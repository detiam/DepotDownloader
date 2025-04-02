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
from binascii import crc32
from zipfile import ZipFile
from collections import deque
from urllib3.util import parse_url
from requests.adapters import HTTPAdapter
from multiprocessing.dummy import Pool, Lock

from steam.utils.web import make_requests_session, APIHost, DEFAULT_PARAMS

parser = argparse.ArgumentParser(add_help=True)
parser.add_argument('-t', '--thread-num', type=int, default=32)
parser.add_argument('-f', '--file-open-num', type=int, default=32,
                    help=f'the number of how many file can be write same time, should smaller than thread-num')
parser.add_argument('-o', '--save-path', type=str)
parser.add_argument('-c', '--login-anonymous', action='store_true',
                    help=f'login anonymously and enable request cdn auth token')
parser.add_argument('-s', '--server', type=str, dest='server_list', action='append', nargs='?')
parser.add_argument('-a', '--apihost', type=str, default='Public',
                    help=f'available: {APIHost._member_names_} or a custom string')
parser.add_argument('-i', '--appid', type=int, default=0)
parser.add_argument('-l', '--level', type=str, default='INFO')
parser.add_argument('-r', '--retry-num', type=int, default=5)
parser.add_argument('--use-http', action='store_true')
parser.add_argument('--use-websocket', action='store_true')

subparsers = parser.add_subparsers(dest='command', required=True)

app_parser = subparsers.add_parser('app')
app_parser.add_argument('-p', '--app-path', type=str, required=True)

depot_parser = subparsers.add_parser('depot')
depot_parser.add_argument('-m', '--manifest-path', type=str, dest='manifest_path_list', action='extend', nargs='+', required=True)
depot_parser.add_argument('-k', '--depot-key', type=str, dest='depot_key_list', action='extend', nargs='+', required=True)

args = parser.parse_args()

DEFAULT_PARAMS['https'] = not args.use_http

try:
    DEFAULT_PARAMS['apihost'] = APIHost[args.apihost].value
except:
    DEFAULT_PARAMS['apihost'] = args.apihost

# China apihost only support websocket
if DEFAULT_PARAMS['apihost'] == APIHost.China.value:
    args.use_websocket = True

from steam.enums import EResult
from steam.exceptions import SteamError
from steam.webapi import get as webapi_get
from steam.client import SteamClient
from steam.client.cdn import CDNClient
from steam.core.connection import WebsocketConnection
from steam.core.manifest import DepotManifest
from steam.core.crypto import symmetric_decrypt


class FileDownload:
    def __init__(self, depot_downloader, filemapping):
        self.depot_downloader = depot_downloader
        self.tqdm: tqdm = self.depot_downloader.tqdm
        self.manifest = self.depot_downloader.manifest
        self.filemapping = filemapping
        self.chunk_dict = self.depot_downloader.chunk_dict
        self.depot_id = self.depot_downloader.depot_id
        self.depot_key = self.depot_downloader.depot_key
        self.log = self.depot_downloader.log
        self.filepath = self.filemapping.filename.replace('\\', '/')
        self.path = self.depot_downloader.save_path / self.filepath
        self.lock = Lock()

        if filemapping.flags != 64:
            if not self.path.exists():
                if self.filepath in self.chunk_dict:
                    self.chunk_dict[self.filepath] = []
                if not self.path.parent.exists():
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                if not self.path.exists():
                    self.path.touch(exist_ok=True)
            self.path_f = self.path.open('rb+')
        if self.filepath not in self.chunk_dict:
            self.chunk_dict[self.filepath] = []

    #def download_file():

    def download_chunk_and_save(self, chunk, max_attempts=5):
        chunk_id = chunk.sha.hex()
        data = self.get_chunk(chunk_id, max_attempts)
        while True:
            try:
                with self.lock:
                    self.path_f.seek(chunk.offset, 0)
                    self.path_f.write(data)
                break
            except Exception:
                self.log.warning(f'Save chunk {chunk_id} to {self.filepath} failed, retry...')
                pass
        self.chunk_dict[self.filepath].append(f'{chunk.offset}_{chunk.sha.hex()}')
        self.tqdm.set_postfix(filename=self.filepath[-(shutil.get_terminal_size().columns // 4):])
        self.tqdm.update(chunk.cb_original)

    def get_chunk(self, chunk_id, max_attempts=5):
        server, token = self.depot_downloader.get_content_server()

        for attempt in range(max_attempts):
            url = f'{server}/depot/{self.depot_id}/chunk/{chunk_id}{token}'
            try:
                resp = self.depot_downloader.web.get(url, timeout=10)

                if resp.ok:
                    data = symmetric_decrypt(resp.content, bytes.fromhex(self.depot_key))

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
                    else:
                        with ZipFile(BytesIO(data)) as zf:
                            data = zf.read(zf.filelist[0])

                    return data
                elif 400 <= resp.status_code < 500:
                    raise SteamError("%s %s HTTP Error %s" % (self.path, chunk_id, resp.status_code))
            except Exception as exp:
                self.log.debug("%s %s Request error (attempt %d/%d): %s",
                             self.path, chunk_id, attempt+1, max_attempts, exp)

                if attempt == max_attempts - 1:
                    self.log.error(f"Failed to download chunk {chunk_id} after {max_attempts} attempts")
                    raise

            # Get a new server for the next attempt
            time.sleep(1)  # Add a delay before retrying
            server, token = self.depot_downloader.get_content_server(rotate=True)


class SingletonSteamClient(SteamClient):
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self._lock = Lock()
            super().__init__()
            if args.use_websocket:
                self.connection = WebsocketConnection()
            result = self.anonymous_login()
            if result != EResult.OK:
                raise SteamError(f'Login failure reason: {result.__repr__()}')


class SingletonDict(dict):
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

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key, value):
        with self._lock:
            return super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            return super().__delitem__(key)

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __contains__(self, key):
        with self._lock:
            return super().__contains__(key)


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


class ExitController:
    def __init__(self):
        self.exit_flag = False
        def _handle_interrupt(signum=None, frame=None):
            self.exit_flag = True

        if sys.platform == 'win32':
            from win32api import SetConsoleCtrlHandler
            from win32con import CTRL_BREAK_EVENT
            def _win_interrupt_handler(dwCtrlType):
                if dwCtrlType != CTRL_BREAK_EVENT:
                    _register()
                    _handle_interrupt()
                    return 1
                return 0
            def _register():
                SetConsoleCtrlHandler(_win_interrupt_handler, 0)

            SetConsoleCtrlHandler(_win_interrupt_handler, 1)
        else:
            import signal
            signal.signal(signal.SIGINT, _handle_interrupt)
            signal.signal(signal.SIGHUP, _handle_interrupt)
            signal.signal(signal.SIGTERM, _handle_interrupt)


class DepotDownloader:
    def __init__(self, manifest_path, depot_key, thread_num=32, save_path=None, servers=None,
                 level=logging.INFO, retry_num=5, expect_logged_in=False, max_servers=20, appid=0,
                 file_open_num=32):
        self.lock = Lock()
        self.expect_logged_in = expect_logged_in
        if expect_logged_in:
            self.client = SingletonSteamClient()
            self.cdn = CDNClient(self.client)
        self.manifest_path = manifest_path
        self.depot_key = depot_key
        self.appid = appid
        self.retry_num = retry_num
        self.thread_num = int(thread_num)
        self.file_open_num = int(file_open_num)
        self.max_servers = int(max_servers)
        self.log = logging.getLogger(self.__class__.__name__)
        logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                            level=level)
        with open(self.manifest_path, 'rb') as f:
            content = f.read()
        self.manifest = DepotManifest(content)
        self.depot_id = self.manifest.depot_id
        self.servers = SingletonDeque()
        self.get_content_server(servers)
        self.chunk_dict_path = self._get_chunk_saves()
        self.save_path = Path(save_path) if save_path else Path(str(self.depot_id))
        self.chunk_dict_f = self.chunk_dict_path.open('r+', encoding='utf-8')
        try:
            self.chunk_dict = SingletonDict(json.load(self.chunk_dict_f))
        except json.decoder.JSONDecodeError:
            self.chunk_dict = SingletonDict()
        self.controller = ExitController()
        self.web = make_requests_session()
        adapters = HTTPAdapter(self.max_servers, self.thread_num, 0, True)
        self.web.mount('http://', adapters)
        self.web.mount('https://', adapters)
        self.tqdm = tqdm(total=self.manifest.metadata.cb_disk_original, unit='B', unit_scale=True)
        self.tqdm.set_description_str(f'Depot {self.depot_id}')

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

    def get_content_server(self, servers=None, rotate=False, cell_id=0):
        if servers:
            for server_str in map(str, servers):
                if server_str not in self.servers:
                    self.servers.append(server_str)

        if not self.servers:
            try:
                resp = webapi_get('IContentServerDirectoryService', 'GetServersForSteamPipe',
                                  params={'cell_id': cell_id, 'max_servers': self.max_servers})
                content_servers = resp['response']['servers']
                content_servers.sort(key=lambda x: (x['type'] != 'CDN', x['priority_class']))
            except Exception:
                raise

            for server in filter(lambda x: not (
                x['type'] == 'OpenCache' or x.get('steam_china_only', False)
            ), content_servers):
                server_str = f"{'https' if server['https_support'] == 'mandatory' else 'http'}://{server['host']}"
                if server_str not in self.servers:
                    self.servers.append(server_str)
                    self.log.info('Appended server: ' + server_str)

        if not self.servers:
            raise SteamError("Failed to fetch content servers")

        if rotate:
            self.servers.rotate(-1)

        server_str = str(self.servers[0])
        if self.expect_logged_in:
            return server_str, self.cdn.get_cdn_auth_token(self.appid, self.depot_id, parse_url(server_str).host)
        else:
            return server_str, ''

    def download_file(self, filemapping, pool):
        filemapping.chunks.sort(key=lambda x: x.offset)
        d = FileDownload(self, filemapping)
        result_list = []
        for chunk in filemapping.chunks:
            if f'{chunk.offset}_{chunk.sha.hex()}' not in self.chunk_dict[d.filepath]:
                result_list.append(
                    pool.apply_async(
                        d.download_chunk_and_save,
                        (chunk, self.retry_num,),
                        callback=self.save_chunk_dict))
            else:
                self.tqdm.update(chunk.cb_original)
        try:
            for result in result_list:
                result.get()
                if self.controller.exit_flag:
                    break
        except KeyboardInterrupt:
            pass

    def download(self):
        with Pool(self.thread_num) as connection_pool:
            with Pool(self.file_open_num) as file_pool:
                result_list = []
                for mapping in self.manifest.payload.mappings:
                    result_list.append(
                        file_pool.apply_async(
                            self.download_file,
                            (mapping, connection_pool,)))
                try:
                    for result in result_list:
                        result.get()
                        if self.controller.exit_flag:
                            break
                except KeyboardInterrupt:
                    pass

    def save_chunk_dict(self, r=None):
        with self.lock:
            self.chunk_dict_f.seek(0)
            json.dump(dict(self.chunk_dict), self.chunk_dict_f)
            #self.chunk_dict_f.truncate()

            percentage = int(self.tqdm.n / self.tqdm.total * 100)
            name = self.chunk_dict_path.with_name(f'{percentage}% - {self.depot_id}.json')
            if self.chunk_dict_path != name:
                self.chunk_dict_path = self.chunk_dict_path.rename(name)
                self.chunk_dict_f.close()
                self.chunk_dict_f = self.chunk_dict_path.open('r+', encoding='utf-8')
            else:
                self.chunk_dict_f.flush()
                

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
    if args.level:
        level = logging.getLevelName(args.level.upper())
    else:
        level = logging.INFO
    manifest_path_depot_key_dict = {}
    save_path = args.save_path
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
                d = DepotDownloader(manifest_path, depot_key, args.thread_num, save_path, server_set, level,
                                    args.retry_num, args.login_anonymous, 20, args.appid, args.file_open_num)
                d.download()

if __name__ == '__main__':
    main()
