#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = [
#   "steam[client] @ git+https://github.com/detiam/steam_websocket.git@e00f4b547d1339a48195d2518845cccfa71ce669",
#   "requests>=2.32",
#   "tqdm>=4.67",
#   "zstandard>=0.25",
#   "pywin32>=311; sys_platform == 'win32'",
# ]
# ///

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
from binascii import crc32, unhexlify
from zipfile import ZipFile
from collections import deque
from threading import RLock as Lock
from urllib3.util import parse_url
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, Future, wait
from compression.zstd import decompress as ZSTD_uncompress

from steam.utils.web import make_requests_session, APIHost, DEFAULT_PARAMS

parser = argparse.ArgumentParser(
    add_help=True,
    description='Depot Downloader, write in Python.',
    epilog='Use Ctrl+C to cancel the download, double-tap to cancel all downloads.')

parser.add_argument('-r', '--retry', type=int, default=5,
    help='how many retries for downloading a chunk, default 5')
parser.add_argument('-t', '--thread', type=int, default=32,
    help='how many chunk downloading in parallel, default 32')
parser.add_argument('-o', '--output', type=str,
    help='where to save files, default is a folder named after the depot id or app name in the current directory')
parser.add_argument('-p', '--pattern', type=str, dest='regex_pattern',
    help='regex pattern to match the file path, only matched files will be downloaded')
parser.add_argument('-log', '--level', type=str, default='INFO',
    help=f'available: {list(logging._levelToName.values())}')

auth_group = parser.add_argument_group('authentication options')
auth_group.add_argument('-l', '--login-anonymously', action='store_true',
    help='required for request cdn auth token')
auth_group.add_argument('-a', '--app-id', type=int, default=0,
    help='optional for request cdn auth token')
auth_group.add_argument('-c', '--cell-id', type=int, default=0,
    help='the overridden CellID of the content server to download from')

conn_group = parser.add_argument_group('connection options')
conn_group.add_argument('-u', '--api-host', type=str, default='Public',
    help=f'available: {APIHost._member_names_} or a custom string')
conn_group.add_argument('-s', '--server', type=str, dest='server_list', action='append', nargs='?',
    help='content server list')
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

_win_exit_flag=False
if sys.platform == 'win32':
    from win32api import SetConsoleCtrlHandler
    from win32con import CTRL_BREAK_EVENT
    def _win_interrupt_handler(dwCtrlType):
        global _win_exit_flag
        if dwCtrlType != CTRL_BREAK_EVENT:
            _unregister()
            _win_exit_flag = True
            return 1
        return 0
    def _unregister():
        SetConsoleCtrlHandler(_win_interrupt_handler, 0)
    SetConsoleCtrlHandler(_win_interrupt_handler, 1)

if sys.platform != "win32":
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
        chunk_dict = self.depot_downloader.chunk_dict
        self.depot_key = self.depot_downloader.depot_key
        self.log = self.depot_downloader.log
        self.depot_file = depot_file
        self.depot_id = self.depot_file.manifest.depot_id
        filepath = Path(depot_file.filename)
        self.path:Path = (save_path or self.depot_downloader.save_path) / filepath
        self.lock = Lock()

        if not depot_file.is_directory:
            if not self.path.exists():
                if filepath.as_posix() in chunk_dict:
                    chunk_dict[filepath.as_posix()] = []
                if not self.path.parent.exists():
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists():
                    with self.path.open("rb+") as file:
                        file.truncate(depot_file.size)
                else:
                    with self.path.open("wb") as file:
                        if hasattr(os, 'posix_fallocate') and depot_file.size > 3:
                            os.posix_fallocate(file.fileno(), 0, depot_file.size)
                        else:
                            file.truncate(depot_file.size)
        if filepath.as_posix() not in chunk_dict:
            chunk_dict[filepath.as_posix()] = []

    def download_file_and_save(self):
        for chunk in self.depot_file.chunks:
            self.download_chunk_and_save(chunk, self.depot_downloader.retry_num)

    def download_chunk_and_save(self, chunk, max_attempts=5):
        chunk_id = chunk.sha.hex()
        data = self.get_chunk(chunk_id, max_attempts)
        with self.lock, self.path.open('rb+') as file:
            file.seek(chunk.offset, 0)
            file.write(data)

    def get_chunk(self, chunk_id, max_attempts=5):
        server, token = self.depot_downloader.get_content_server()

        for attempt in range(max_attempts):
            url = f'{server}/depot/{self.depot_id}/chunk/{chunk_id}{token}'
            try:
                resp = self.depot_downloader.web.get(url, timeout=10)

                if resp.ok:
                    data = symmetric_decrypt(resp.content, self.depot_key)

                    if data[:2] == b'VZ':
                        if data[-2:] != b'zv':
                            raise SteamError("%s %s VZ: Invalid footer: %s" % (self.path, chunk_id, repr(data[-2:])))
                        if data[2:3] != b'a':
                            raise SteamError("%s %s VZ: Invalid version: %s" % (self.path, chunk_id, repr(data[2:3])))

                        vzfilter = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[7:12])
                        vzdec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[vzfilter])
                        checksum, decompressed_size = struct.unpack('<II', data[-10:-2])
                        # decompress_size is needed since lzma will sometime produce longer output
                        # [12:-9] is need as sometimes lzma will produce shorter output
                        # together they get us the right data
                        data = vzdec.decompress(data[12:-9])[:decompressed_size]
                        if crc32(data) != checksum:
                            raise SteamError("%s %s VZ: CRC32 checksum doesn't match for decompressed data" % (self.path, chunk_id))
                    elif data[:3] == b'VSZ':
                        if data[-3:] != b'zsv':
                            raise SteamError("%s %s VSZ: Invalid footer: %s" % (self.path, chunk_id, repr(data[-2:])))
                        if data[3:4] != b'a':
                            raise SteamError("%s %s VSZ: Invalid version: %s" % (self.path, chunk_id, repr(data[2:3])))

                        crc32_header = struct.unpack_from('<I', data, 4)[0]
                        crc32_footer = struct.unpack_from('<I', data, -15)[0]
                        size_decompressed = struct.unpack_from('<I', data, -11)[0]
                        data = ZSTD_uncompress(data[8 : -15])[:size_decompressed]
                        if crc32(data) != crc32_header != crc32_footer:
                            raise SteamError("%s %s VSZ: CRC32 checksum doesn't match for decompressed data" % (self.path, chunk_id))
                    else:
                        with ZipFile(BytesIO(data)) as zf:
                            data = zf.read(zf.filelist[0])

                    return data
                elif resp.status_code == 403:
                    # token missing maybe?
                    raise SteamError(f'{server}: {resp}')
                elif 400 <= resp.status_code < 500:
                    raise SteamError("%s %s HTTP Error %s" % (self.path, chunk_id, resp.status_code))
            except Exception as exp:
                self.log.debug("%s %s Request error (attempt %d/%d): %s",
                             self.path, chunk_id, attempt+1, max_attempts, exp)

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


class DepotDownloader:
    def __init__(self, manifest_path, depot_key, thread_num=32, save_path=None, servers=None,
                 level=logging.INFO, retry_num=5, expect_logged_in=False, max_servers=20, appid=0, use_websocket=False, cellid=0):
        self._win_exit_flag = False
        self.lock = Lock()
        self.expect_logged_in = expect_logged_in
        if expect_logged_in:
            self.client = SteamClient()
            if use_websocket:
                self.client.connection = WebsocketConnection()
            result = self.client.anonymous_login()
            if result != EResult.OK:
                raise SteamError(f'Login failure reason: {result.__repr__()}')
            self.cdn = CDNClient(self.client)
        self.manifest_path = manifest_path
        self.depot_key = unhexlify(depot_key)
        self.appid = appid
        self.cellid = cellid
        self.retry_num = retry_num
        self.thread_num = int(thread_num)
        self.max_servers = int(max_servers)
        self.log = logging.getLogger(self.__class__.__name__)
        logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                            level=level)
        with open(self.manifest_path, 'rb') as f:
            content = f.read()
        self.manifest = DepotManifest(content)
        self.manifest.decrypt_filenames(self.depot_key)
        self.depot_id = self.manifest.depot_id
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
        self.num_entries_in_client_list = 0 # num of how many cdn auth token server can be used
        self.get_content_server(servers, fetch_all_cdn_token=True)
        self.tqdm = tqdm(
            total=self.manifest.size_original,
            desc=f'Depot {self.depot_id}',
            unit='B', unit_scale=True, leave=False)

    def _get_chunk_saves(self):
        matching_files = [p for p in Path.cwd().glob(f'*% - {self.depot_id}.json') if p.is_file()]
        matching_files.sort(key=lambda x: x.stat().st_mtime)
        chunk_saves = None
        if matching_files:
            chunk_saves = matching_files.pop()
            for file in matching_files:
                file.unlink()

        if not chunk_saves:
            chunk_saves = Path(f'0% - {self.depot_id}.json')
            chunk_saves.touch()

        return chunk_saves

    def get_content_server(self, servers=None, rotate=False, cell_id=0, fetch_all_cdn_token=False):
        if servers:
            for server_str in map(str, servers):
                if server_str not in self.servers:
                    self.servers.append(server_str)

        if not self.servers:
            try:
                resp = webapi_get('IContentServerDirectoryService', 'GetServersForSteamPipe',
                                  params={'cell_id': cell_id or self.cellid, 'max_servers': self.max_servers})
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
        if self.expect_logged_in:
            if fetch_all_cdn_token:
                for server in self.servers:
                    self.cdn.get_cdn_auth_token(self.appid, self.depot_id, parse_url(server).host)
            while True:
                result:dict = self.cdn.get_cdn_auth_token(self.appid, self.depot_id, parse_url(server_str).host)
                if result['eresult'] in (EResult.OK, EResult.Fail): # Fail means token unneeded seems
                    token = result['token']
                    break
                else:
                    self.servers.remove(server_str)
                    self.log.warning(f'Removed server: {server_str}\nBecause error code {result['eresult']} when try to get cdn auth token.')
                    server_str = self.servers[0]

        return server_str, token

    def download(self, pattern:str=''):
        compiled_pattern = re.compile(pattern) if pattern else None
        with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
            futures:list[Future] = []
            try:
                for depot_file in self.manifest:
                    #depot_file.chunks.sort(key=lambda x: x.offset)
                    posix_filename = Path(depot_file.filename).as_posix()

                    if compiled_pattern and not compiled_pattern.search(posix_filename):
                        continue

                    file_downloader = FileDownload(self, depot_file)

                    for chunk in depot_file.chunks:
                        chunk_key = f'{chunk.offset}_{chunk.sha.hex()}'

                        if chunk_key not in self.chunk_dict.get(posix_filename, {}):
                            future = executor.submit(
                                file_downloader.download_chunk_and_save,
                                chunk,
                                self.retry_num
                            )
                            future.add_done_callback(
                                lambda f, ck=chunk_key, cb=chunk.cb_original, path=posix_filename: self._handle_chunk_result(f, ck, cb, path)
                            )
                            futures.append(future)
                        else:
                            self.tqdm.update(chunk.cb_original)

                if sys.platform == 'win32':
                    from win32api import SetConsoleCtrlHandler
                    from win32con import CTRL_BREAK_EVENT
                    def _win_interrupt_handler(dwCtrlType):
                        if dwCtrlType != CTRL_BREAK_EVENT:
                            _unregister()
                            for f in futures:
                                f.cancel()
                            self._win_exit_flag = True
                            return 1
                        return 0
                    def _unregister():
                        SetConsoleCtrlHandler(_win_interrupt_handler, 0)
                    SetConsoleCtrlHandler(_win_interrupt_handler, 1)

                _, not_done = wait(futures, return_when='FIRST_EXCEPTION')
                if self._win_exit_flag:
                    raise KeyboardInterrupt
                if not_done:
                    executor.shutdown(wait=True, cancel_futures=True)
                    self.tqdm.close()
                    os._exit(1)
                else:
                    with self.lock:
                        self.save_chunk_dict()
                    self.tqdm.close()
                    elapsed = self.tqdm.format_dict["elapsed"]
                    print(f'Depot {self.depot_id}:	completed in {elapsed:.2f}s')
            except KeyboardInterrupt:
                executor.shutdown(wait=True, cancel_futures=True)
                self.tqdm.close()
                print(f'Depot {self.depot_id}:	cancelled')

    def _handle_chunk_result(self, future:Future, chunk_key, chunk_size, path:str):
        if future.cancelled():
            return
        #future.result()
        self.tqdm.set_postfix_str(path[-(shutil.get_terminal_size().columns // 4):], False)
        self.tqdm.update(chunk_size)
        with self.lock:
            self.chunk_dict[path].append(chunk_key)
            percentage = int(round(self.tqdm.n / self.tqdm.total * 100))
            new_name = f'{percentage}% - {self.depot_id}.json'
            if self.chunk_dict_path.name != new_name:
                self.save_chunk_dict()
                self.chunk_dict_path = self.chunk_dict_path.replace(self.chunk_dict_path.with_name(new_name))


    def save_chunk_dict(self):
        chunk_dict_for_save = self.chunk_dict.copy()
        with self.chunk_dict_path.open('r+', encoding='utf-8') as f:
            json.dump(chunk_dict_for_save, f)

def get_manifest_path_depot_key_dict(path):
    path = Path(path)
    if not path.is_dir():
        raise NotADirectoryError(path)
    manifest_path_list = []
    depot_dict = {}
    for file in path.iterdir():
        if file.is_file():
            if file.suffix == '.manifest':
                manifest_path_list.append(file)
            elif file.suffix == '.vdf':
                with file.open() as f:
                    d = vdf.load(f)
                depots = d.get('depots')
                if not depots:
                    return {}
                for depot_id in depots:
                    depot_key = depots[depot_id].get('DecryptionKey')
                    if not depot_key:
                        continue
                    depot_dict[int(depot_id)] = depot_key
    manifest_path_depot_key_dict = {}
    for manifest_path in manifest_path_list:
        with manifest_path.open('rb') as f:
            content = f.read()
        manifest = DepotManifest(content)
        if manifest.depot_id not in depot_dict:
            continue
        depot_key = depot_dict[manifest.depot_id]
        manifest_path_depot_key_dict[manifest_path] = depot_key
    return manifest_path_depot_key_dict


def main(new_args=None):
    global args
    if new_args:
        args = parser.parse_args(new_args)
    manifest_path_depot_key_dict = {}
    save_path = args.output
    if args.command == 'app':
        manifest_path_depot_key_dict = get_manifest_path_depot_key_dict(args.app_path)
        if manifest_path_depot_key_dict and args.app_path and not save_path:
            save_path = Path().absolute() / Path(args.app_path).name
    elif args.command == 'depot':
        manifest_path_depot_key_dict = dict(zip(args.manifest_path_list, args.depot_key_list))
    server_set = set()
    if args.server_list:
        for server in args.server_list:
            if type(server) == str:
                server_set.update(server.split(','))
    if manifest_path_depot_key_dict:
        for manifest_path, depot_key in manifest_path_depot_key_dict.items():
            if manifest_path and depot_key:
                if _win_exit_flag:
                    raise KeyboardInterrupt
                d = DepotDownloader(manifest_path, depot_key, args.thread, save_path, server_set, args.level,
                                    args.retry, args.login_anonymously, args.max_servers, args.app_id,
                                    args.use_websocket, args.cell_id)
                d.download(args.regex_pattern)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('All downloads cancelled')
