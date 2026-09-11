#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = [
#   "steam[client] @ git+https://github.com/detiam/steam_websocket.git@e00f4b547d1339a48195d2518845cccfa71ce669",
#   "requests[socks]>=2.32",
#   "tqdm>=4.67",
#   "pip_system_certs>=5.3",
# ]
# ///

import pip_system_certs.wrapt_requests; pip_system_certs.wrapt_requests.inject_truststore()

import os
import re
import sys
import vdf
import time
import lzma
import json
import shutil
import struct
import logging
import argparse
from tqdm import tqdm
from io import BytesIO
from pathlib import Path
from hashlib import file_digest
from binascii import crc32, unhexlify
from zipfile import ZipFile
from collections import deque
from collections.abc import Iterable
from threading import RLock as Lock
from urllib3.util import parse_url
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from compression.zstd import decompress as ZSTD_uncompress

from steam.utils.web import make_requests_session, APIHost, DEFAULT_PARAMS

parser = argparse.ArgumentParser(
    add_help=True,
    description='Depot Downloader, write in Python.',
    epilog=f"Use Ctrl+C to cancel the download, double-tap to cancel all downloads. GIL: {sys._is_gil_enabled()}")

parser.add_argument('-r', '--retry', type=int, default=5,
    help='how many retries for downloading a chunk, default 5')
parser.add_argument('-t', '--thread', type=int, default=32,
    help='how many chunk downloading in parallel, default 32')
parser.add_argument('-i', '--integrity', action='store_true', dest='verify_integrity',
    help='verify the integrity of downloaded files')
parser.add_argument('-o', '--output', type=str,
    help='output directory to save the downloaded files')
parser.add_argument('-d', '--delete', action='store_true', dest='delete_unmatched',
    help='delete files that are in the output directory but not in the manifest')
parser.add_argument('-p', '--pattern', type=str, dest='regex_pattern', default='',
    help='regex pattern to match the file path, only matched files will be downloaded')
parser.add_argument('-log', '--level', type=str, default='INFO',
    help=f'available: {list(logging._levelToName.values())}')

auth_group = parser.add_argument_group('authentication options')
auth_group.add_argument('-l', '--login-anonymously', action='store_true',
    help='required for request cdn auth token')
auth_group.add_argument('-a', '--app-id', type=int, default=0,
    help='optional for request cdn auth token, generate default output directory path')
auth_group.add_argument('-c', '--cell-id', type=int, default=0,
    help='the overridden CellID of the content server to download from')

conn_group = parser.add_argument_group('connection options')
conn_group.add_argument('-u', '--api-host', type=str, default='Public',
    help=f'available: {APIHost._member_names_} or a custom string')
conn_group.add_argument('-s', '--server', type=str, dest='server_list', action='append', nargs='?',
    help='custom content server(cdn) list, can be set multiple times or separated by commas(,)')
conn_group.add_argument('-m', '--max-servers', type=int, default=20,
    help='how many content server can be obtained and used at most')
conn_group.add_argument('--use-http', action='store_true',
    help='use HTTP for connection')
conn_group.add_argument('--use-websocket', action='store_true',
    help='use WEBSOCKET for connection')

subparsers = parser.add_subparsers(dest='command', required=True,
    help='command')

app_parser = subparsers.add_parser('app')
app_parser.add_argument('-p', '--app-path', type=str, required=True)

depot_parser = subparsers.add_parser('depot')
depot_parser.add_argument('-m', '--manifest-path', type=str, dest='manifest_path_list', action='extend', nargs='+', required=True)
depot_parser.add_argument('-k', '--depot-key', type=str, dest='depot_key_list', action='extend', nargs='+', required=True)

args = parser.parse_args()

DEFAULT_PARAMS['https'] = not args.use_http

try:
    DEFAULT_PARAMS['apihost'] = APIHost[args.api_host].value
except:
    DEFAULT_PARAMS['apihost'] = args.api_host

# China apihost only support websocket
if DEFAULT_PARAMS['apihost'] == APIHost.China.value:
    args.use_websocket = True

from steam.enums import EResult
from steam.exceptions import SteamError
from steam.webapi import get as webapi_get
from steam.client import SteamClient
from steam.client.cdn import CDNClient
from steam.core.connection import WebsocketConnection
from steam.core.manifest import DepotManifest, DepotFile
from steam.core.crypto import symmetric_decrypt

if sys.platform == 'win32':
    from signal import signal, SIGINT, SIGTERM, SIGBREAK

    def _interrupt_handler(signum, frame):
        raise KeyboardInterrupt

    for sig in (
        SIGINT,
        SIGTERM,
        SIGBREAK,
    ):
        signal(sig, _interrupt_handler)
else:
    import atexit
    import termios

    fd = sys.stdin.fileno()
    original_settings = termios.tcgetattr(fd)
    new_settings = termios.tcgetattr(fd)
    new_settings[3] &= ~termios.ECHOCTL
    termios.tcsetattr(fd, termios.TCSANOW, new_settings)
    def restore_terminal():
        termios.tcsetattr(fd, termios.TCSANOW, original_settings)
    atexit.register(restore_terminal)

class FileDownload:
    def __init__(self, depot_downloader:DepotDownloader, depot_file:DepotFile, save_path=None):
        self.depot_downloader = depot_downloader
        verify_integrity = self.depot_downloader.verify_integrity
        chunk_dict = self.depot_downloader.chunk_dict
        self.log = self.depot_downloader.log
        self.depot_file = depot_file
        self.depot_id = self.depot_file.manifest.depot_id
        filename = Path(depot_file.filename)
        self.file_path:Path = (save_path or self.depot_downloader.save_path) / filename
        self.lock = Lock()

        if depot_file.is_file:
            if self.file_path.exists():
                if verify_integrity:
                    self.log.debug(f"Verifying integrity of {filename}...")
                    if depot_file.size and file_digest(self.file_path.open('rb'), 'sha1').digest() != depot_file.sha_content:
                        self.log.warning(f"File '{self.file_path}' exists but integrity check failed, redownloading.")
                        chunk_dict[filename.as_posix()] = []

                if self.file_path.stat().st_size != depot_file.size:
                    with self.file_path.open("rb+") as file:
                        file.truncate(depot_file.size)
            else:
                chunk_dict[filename.as_posix()] = []

                if not self.file_path.parent.exists():
                    self.file_path.parent.mkdir(parents=True, exist_ok=True)

                with self.file_path.open("wb") as file:
                    if hasattr(os, 'posix_fallocate') and depot_file.size >= 1024 ** 3:
                        os.posix_fallocate(file.fileno(), 0, depot_file.size)
                    else:
                        file.truncate(depot_file.size)

        elif depot_file.is_directory:
            self.file_path.mkdir(parents=True, exist_ok=True)

        elif depot_file.is_symlink:
            if self.file_path.exists():
                self.file_path.unlink()

            linktarget = Path(depot_file.linktarget)
            self.file_path.symlink_to(
                linktarget.as_posix(),
                target_is_directory=True if linktarget.is_dir() else False)

        if depot_file.is_executable:
            self.file_path.chmod(self.file_path.stat().st_mode | 0o111)  # Add execute permissions

        if filename.as_posix() not in chunk_dict:
            chunk_dict[filename.as_posix()] = []

    def download_file_and_save(self):
        for chunk in self.depot_file.chunks:
            self.download_chunk_and_save(chunk, self.depot_downloader.retry_num)

    def download_chunk_and_save(self, chunk, max_attempts=5):
        chunk_id = chunk.sha.hex()
        self.depot_downloader.tqdm.set_postfix_str(
            self.file_path.as_posix()[-(shutil.get_terminal_size().columns // 4):])
        data = self.get_chunk(chunk_id, max_attempts)
        with self.lock, self.file_path.open('rb+') as file:
            file.seek(chunk.offset, 0)
            file.write(data)

    def get_chunk(self, chunk_id, max_attempts=5):
        server, token = self.depot_downloader.get_content_server()

        for attempt in range(max_attempts):
            url = f'{server}/depot/{self.depot_id}/chunk/{chunk_id}{token}'
            try:
                resp = self.depot_downloader.web.get(url, timeout=10)

                if resp.ok:
                    data = symmetric_decrypt(resp.content, self.depot_downloader.depot_key)

                    if data[:2] == b'VZ':
                        if data[-2:] != b'zv':
                            raise SteamError("%s %s VZ: Invalid footer: %s" % (self.file_path, chunk_id, repr(data[-2:])))
                        if data[2:3] != b'a':
                            raise SteamError("%s %s VZ: Invalid version: %s" % (self.file_path, chunk_id, repr(data[2:3])))

                        vzfilter = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[7:12])
                        vzdec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[vzfilter])
                        checksum, decompressed_size = struct.unpack('<II', data[-10:-2])
                        # decompress_size is needed since lzma will sometime produce longer output
                        # [12:-9] is need as sometimes lzma will produce shorter output
                        # together they get us the right data
                        data = vzdec.decompress(data[12:-9])[:decompressed_size]
                        if crc32(data) != checksum:
                            raise SteamError("%s %s VZ: CRC32 checksum doesn't match for decompressed data" % (self.file_path, chunk_id))
                    elif data[:3] == b'VSZ':
                        if data[-3:] != b'zsv':
                            raise SteamError("%s %s VSZ: Invalid footer: %s" % (self.file_path, chunk_id, repr(data[-2:])))
                        if data[3:4] != b'a':
                            raise SteamError("%s %s VSZ: Invalid version: %s" % (self.file_path, chunk_id, repr(data[2:3])))

                        crc32_header = struct.unpack_from('<I', data, 4)[0]
                        crc32_footer = struct.unpack_from('<I', data, -15)[0]
                        size_decompressed = struct.unpack_from('<I', data, -11)[0]
                        data = ZSTD_uncompress(data[8 : -15])[:size_decompressed]
                        if crc32(data) != crc32_header != crc32_footer:
                            raise SteamError("%s %s VSZ: CRC32 checksum doesn't match for decompressed data" % (self.file_path, chunk_id))
                    else:
                        with ZipFile(BytesIO(data)) as zf:
                            data = zf.read(zf.filelist[0])

                    return data
                elif resp.status_code == 403:
                    # token missing maybe?
                    raise SteamError(f'{server}: {resp}')
                elif 400 <= resp.status_code < 500:
                    raise SteamError("%s %s HTTP Error %s" % (self.file_path, chunk_id, resp.status_code))
            except Exception as exp:
                self.log.debug("%s %s Request error (attempt %d/%d): %s",
                             self.file_path, chunk_id, attempt+1, max_attempts, exp)

                if attempt == max_attempts - 1:
                    self.log.error(f"Failed to download chunk {chunk_id} after {max_attempts} attempts, {exp}")
                    raise

            # Get a new server for the next attempt
            time.sleep(1)  # Add a delay before retrying
            server, token = self.depot_downloader.get_content_server(rotate=True)


class SingletonDeque(deque):
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, *args, **kwargs):
        if not self._initialized:
            self._initialized = True
            self._lock = Lock()
            super().__init__(*args, **kwargs)

    def append(self, item):
        with self._lock:
            super().append(item)

    def appendleft(self, item):
        with self._lock:
            super().appendleft(item)

    def pop(self):
        with self._lock:
            return super().pop()

    def popleft(self):
        with self._lock:
            return super().popleft()

    def remove(self):
        with self._lock:
            return super().remove()

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __contains__(self, item):
        with self._lock:
            return super().__contains__(item)

    def __getitem__(self, index):
        with self._lock:
            return super().__getitem__(index)

    def __setitem__(self, index, value):
        with self._lock:
            super().__setitem__(index, value)

    def __delitem__(self, index):
        with self._lock:
            super().__delitem__(index)

    def __iter__(self):
        with self._lock:
            return super().__iter__()

    def __reversed__(self):
        with self._lock:
            return super().__reversed__()

class TqdmLoggingHandler(logging.Handler):
    def __init__(self, format_str=None):
        super().__init__()
        if format_str:
            self.setFormatter(logging.Formatter(format_str))

    def emit(self, record):
        msg = self.format(record)
        tqdm.write(msg)

class DepotDownloader:
    def __init__(self, manifest: DepotManifest, depot_key: bytes, *,
                 app_id=0,
                 cell_id=0,
                 thread_num=32,
                 retry_num=5,
                 max_servers=20,
                 cdn_client:CDNClient=None,
                 custom_servers:Iterable[str]=[],
                 save_path:os.PathLike=None,
                 verify_integrity=False,
                 level=logging.INFO):

        self.lock = Lock()
        self.manifest = manifest
        self.depot_id = self.manifest.depot_id
        self.depot_key = depot_key
        self.manifest.decrypt_filenames(self.depot_key)
        self.verify_integrity = verify_integrity
        self.cdn = cdn_client
        self.app_id = app_id
        self.cell_id = cell_id
        self.retry_num = retry_num
        self.thread_num = int(thread_num)
        self.max_servers = int(max_servers)
        self.log = logging.getLogger(self.__class__.__name__)
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=level,
                            handlers=[TqdmLoggingHandler()])
        self.chunk_dict_path = self._get_chunk_saves()
        self.save_path = Path(save_path) if save_path else Path(str(self.depot_id))
        try:
            with self.lock, self.chunk_dict_path.open(encoding='utf-8') as f:
                self.chunk_dict:dict = json.load(f)
        except json.decoder.JSONDecodeError:
            self.chunk_dict = dict()
        self.web = make_requests_session()
        self.web.headers['Cache-Control'] = 'no-cache'
        adapters = HTTPAdapter(self.max_servers, self.thread_num, 0, True)
        self.web.mount('http://', adapters)
        self.web.mount('https://', adapters)
        self.servers = SingletonDeque()
        self.num_entries_in_client_list = 0 # num of how many cdn auth token server can be used, unused for now
        self.get_content_server(fetch_all_cdn_token=True, custom_servers=custom_servers)
        self.tqdm = tqdm(
            total=self.manifest.size_original,
            desc=f'Depot {self.depot_id}',
            unit='B', unit_scale=True, leave=False)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        self.tqdm.close()
        self.web.close()

    def _get_chunk_saves(self):
        matching_files = [p for p in Path.cwd().glob(f'{self.depot_id} - *%.json') if p.is_file()]
        matching_files.sort(key=lambda x: x.stat().st_mtime)
        chunk_saves = None
        if matching_files:
            chunk_saves = matching_files.pop()
            for file in matching_files:
                file.unlink()

        if not chunk_saves:
            chunk_saves = Path(f'{self.depot_id} - 0%.json')
            chunk_saves.touch()

        return chunk_saves

    def get_content_server(self, rotate=False, fetch_all_cdn_token=False, cell_id=0, custom_servers:Iterable[str]=[]):
        if custom_servers:
            for server_str in map(str, custom_servers):
                if server_str not in self.servers:
                    self.servers.append(server_str)

        if not self.servers:
            try:
                resp = webapi_get('IContentServerDirectoryService', 'GetServersForSteamPipe',
                                  params={'cell_id': cell_id or self.cell_id, 'max_servers': self.max_servers})
                content_servers = resp['response']['servers']
                content_servers.sort(key=lambda x: (x['type'] != 'CDN', x['priority_class']))
            except Exception:
                raise

            for server in filter(lambda x: not (
                x['type'] == 'OpenCache' or x.get('steam_china_only', False)
            ), content_servers):
                server_str = f"{'https' if server['https_support'] == 'mandatory' else 'http'}://{server['host']}"
                if not self.num_entries_in_client_list:
                    self.num_entries_in_client_list = server.get('num_entries_in_client_list', 0)
                if server_str not in self.servers:
                    self.servers.append(server_str)
                    self.log.debug('Appended server: ' + server_str)

        if not self.servers:
            raise SteamError("Failed to fetch content servers")

        if rotate:
            self.servers.rotate(-1)

        server_str, token = self.servers[0], ''
        if self.cdn is not None:
            if fetch_all_cdn_token:
                for server in self.servers:
                    self.cdn.get_cdn_auth_token(self.app_id, self.depot_id, parse_url(server).host)
            while True:
                result:dict = self.cdn.get_cdn_auth_token(self.app_id, self.depot_id, parse_url(server_str).host)
                if result['eresult'] in (EResult.OK, EResult.Fail): # Fail means token unneeded seems
                    token = result['token']
                    break
                else:
                    self.servers.remove(server_str)
                    self.log.warning(f'Removed server: {server_str}\nBecause error code {result['eresult']} when try to get cdn auth token.')
                    server_str = self.servers[0]

        return server_str, token

    def discard_paths_in_manifest(self, paths_in_dir:set[str]=set()):
        for depot_file in self.manifest:
            posix_filename = Path(depot_file.filename).as_posix()
            paths_in_dir.discard(posix_filename)

    def download(self, pattern:str='', paths_in_dir:set[str]=set()):
        executor = ThreadPoolExecutor(max_workers=self.thread_num)
        try:
            compiled_pattern = re.compile(pattern)
            futures:list[Future] = []

            for depot_file in self.manifest:
                #depot_file.chunks.sort(key=lambda x: x.offset)
                posix_filename = Path(depot_file.filename).as_posix()
                paths_in_dir.discard(posix_filename)
                if pattern and not compiled_pattern.search(posix_filename): continue

                if posix_filename in self.chunk_dict:
                    self.tqdm.set_postfix_str(
                        posix_filename[-(shutil.get_terminal_size().columns // 4):])

                file_downloader = FileDownload(self, depot_file)

                for chunk in depot_file.chunks:
                    chunk_key = f'{chunk.offset}_{chunk.sha.hex()}'

                    if chunk_key in self.chunk_dict.get(posix_filename, {}):
                        self.tqdm.update(chunk.cb_original)
                    else:
                        future = executor.submit(
                            file_downloader.download_chunk_and_save,
                            chunk,
                            self.retry_num
                        )

                        future.add_done_callback(
                            lambda f, ck=chunk_key, cb=chunk.cb_original, path=posix_filename:
                                self._handle_chunk_result(f, ck, cb, path)
                        )

                        futures.append(future)

            for f in as_completed(futures):
                _ = f.result()
        except KeyboardInterrupt:
            tqdm.write(f'Depot {self.depot_id}: cancelled')
            self.discard_paths_in_manifest(paths_in_dir)
        except Exception:
            tqdm.write(f'Depot {self.depot_id}: failed')
            raise
        else:
            elapsed = self.tqdm.format_dict["elapsed"]
            tqdm.write(f'Depot {self.depot_id}: completed in {elapsed:.2f}s')
        finally:
            try:
                executor.shutdown(cancel_futures=True)
                self.tqdm.clear()
                with self.lock:
                    self.save_chunk_dict()
            except KeyboardInterrupt:
                pass
            #time.sleep(1) # wait for another KeyboardInterrupt to cancell all download

    def _handle_chunk_result(self, future:Future, chunk_key, chunk_size, path:str):
        if future.cancelled():
            return
        self.tqdm.update(chunk_size)
        with self.lock:
            self.chunk_dict[path].append(chunk_key)
            percentage = int(round(self.tqdm.n / self.tqdm.total * 100))
            new_name = f"{self.depot_id} - {percentage}%.json"
            if self.chunk_dict_path.name != new_name:
                self.save_chunk_dict()
                self.chunk_dict_path = self.chunk_dict_path.replace(
                    self.chunk_dict_path.with_name(new_name))

    def save_chunk_dict(self):
        try:
            chunk_dict_for_save = self.chunk_dict.copy()
            with self.chunk_dict_path.open('r+', encoding='utf-8') as f:
                json.dump(chunk_dict_for_save, f)
                f.truncate()
        except KeyboardInterrupt:
            pass

def app_path_parser(app_path:os.PathLike) -> tuple[list[DepotManifest], dict[int,bytes]]:
    path = Path(app_path)
    if not path.is_dir():
        raise NotADirectoryError(path)
    manifests:list[DepotManifest] = []
    depot_keys:dict[int,bytes] = {}
    for file in path.iterdir():
        if file.is_file():
            if file.suffix == '.manifest':
                manifests.append(DepotManifest(file.read_bytes()))
            elif file.suffix == '.vdf':
                with file.open() as f:
                    d = vdf.load(f)
                depots = d['depots']
                for depot_id in depots:
                    depot_key = depots[depot_id]['DecryptionKey']
                    depot_keys[int(depot_id)] = unhexlify(depot_key)

    return manifests,depot_keys


def main(new_args=None):
    global args
    if new_args:
        args = parser.parse_args(new_args)
    paths_in_dir:set[str] = None
    manifests:list[DepotManifest] = []
    depot_keys:dict[int,bytes] = {}
    save_path = Path(args.output) if args.output else None
    server_set = set()
    if args.server_list:
        for server in args.server_list:
            server_set.update(server.split(','))

    if args.command == 'app':
        manifests, depot_keys = app_path_parser(args.app_path)
        if not save_path:
            save_path = Path() / (str(args.app_id) if args.app_id else Path(args.app_path).name)
    elif args.command == 'depot':
        for manifest_path, depot_key in zip(args.manifest_path_list, args.depot_key_list):
            manifest = DepotManifest(Path(manifest_path).read_bytes())
            manifests.append(manifest)
            depot_keys[manifest.depot_id] = unhexlify(depot_key)

    try:
        cdn = None
        if args.login_anonymously:
            client = SteamClient()
            if args.use_websocket:
                client.connection = WebsocketConnection()
            result = client.anonymous_login()
            if result != EResult.OK:
                raise SteamError(f'Login failure reason: {result.__repr__()}')
            cdn = CDNClient(client)

        for manifest in manifests:
            depot_key = depot_keys[manifest.depot_id]
            if not save_path:
                save_path = Path(str(manifest.depot_id))
            if not paths_in_dir:
                paths_in_dir = {
                    f.relative_to(save_path).as_posix()
                    for f in save_path.rglob('*')
                }
            with DepotDownloader(
                manifest, depot_key,
                cdn_client=cdn,
                thread_num=args.thread,
                save_path=save_path,
                custom_servers=server_set,
                level=args.level,
                retry_num=args.retry,
                max_servers=args.max_servers,
                app_id=args.app_id,
                cell_id=args.cell_id,
                verify_integrity=args.verify_integrity) as d:
                d.download(args.regex_pattern, paths_in_dir)
    except KeyboardInterrupt:
        tqdm.write('All downloads cancelled')
    else:
        # show extra files that are not in the manifest
        end = ''
        if not args.regex_pattern and len(paths_in_dir) != 0:
            tqdm.write('') # for \n
            for path in sorted(paths_in_dir, key=lambda p: len(Path(p).parts), reverse=True):
                if args.delete_unmatched:
                    path = save_path / path
                    if path.is_symlink() or path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                else:
                    tqdm.write(path, end=" ")

            if not args.delete_unmatched:
                tqdm.write('\n') # for \n
                end = (f", Found {len(paths_in_dir)} entries above in the output directory that are not in the manifest!\n")

        tqdm.write(f'All downloads completed', end=(end or "\n"))
        return

if __name__ == '__main__':
    main()
