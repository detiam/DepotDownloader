import os
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
from concurrent.futures import ThreadPoolExecutor

from steam.utils.web import make_requests_session, APIHost, DEFAULT_PARAMS

parser = argparse.ArgumentParser(add_help=True)
parser.add_argument('-t', '--thread-num', type=int, default=32)
parser.add_argument('-o', '--save-path', type=str)
parser.add_argument('-c', '--login-anonymous', action='store_true',
                    help=f'login anonymously and enable request cdn auth token')
parser.add_argument('-s', '--server', type=str, dest='server_list', action='append', nargs='?')
parser.add_argument('-a', '--apihost', type=str, default='Public',
                    help=f'available: {APIHost._member_names_} or a custom string')
parser.add_argument('-i', '--appid', type=int, default=0)
parser.add_argument('-e', '--cellid', type=int, default=0)
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
from steam.core.manifest import DepotManifest, DepotFile
from steam.core.crypto import symmetric_decrypt

class FileDownload:
    def __init__(self, depot_downloader, depot_file:DepotFile):
        self.depot_downloader = depot_downloader
        chunk_dict = self.depot_downloader.chunk_dict
        self.depot_id = self.depot_downloader.depot_id
        self.depot_key = self.depot_downloader.depot_key
        self.log = self.depot_downloader.log
        filepath = Path(depot_file.filename)
        self.path:Path = self.depot_downloader.save_path / filepath
        self.lock = Lock()

        if not depot_file.is_directory:
            if not self.path.exists():
                if filepath.as_posix() in chunk_dict:
                    chunk_dict[filepath.as_posix()] = []
                if not self.path.parent.exists():
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                if not self.path.exists():
                    with self.path.open("wb") as file:
                        if hasattr(os, 'posix_fallocate') and depot_file.size > 3:
                            os.posix_fallocate(file.fileno(), 0, depot_file.size)
                        else:
                            file.truncate(depot_file.size)
        if filepath.as_posix() not in chunk_dict:
            chunk_dict[filepath.as_posix()] = []

    #def download_file():

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
                    self.log.error(f"Failed to download chunk {chunk_id} after {max_attempts} attempts")
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
            total=self.manifest.metadata.cb_disk_original,
            desc=f'Depot {self.depot_id}',
            unit='B', unit_scale=True, leave=True)

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
                    self.log.info('Appended server: ' + server_str)

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
                    self.log.info(f'Removed server: {server_str} because error code {result['eresult']} when try to get cdn auth token.')
                    server_str = self.servers[0]

        return server_str, token

    def download(self):
        with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
            for file_mapping in self.manifest.payload.mappings:
                file_mapping.chunks.sort(key=lambda x: x.offset)
                depot_file = DepotFile(self.manifest, file_mapping)
                file_downloader = FileDownload(self, depot_file)

                for chunk in file_mapping.chunks:
                    chunk_key = f'{chunk.offset}_{chunk.sha.hex()}'

                    if chunk_key not in self.chunk_dict.get(depot_file.filename, {}):
                        # 提交下载任务到线程池
                        future = executor.submit(
                            file_downloader.download_chunk_and_save,
                            chunk,
                            self.retry_num
                        )
                        # 添加回调以处理结果和进度更新
                        future.add_done_callback(
                            lambda f, c=chunk, path=depot_file.filename: self._handle_chunk_result(f, c, path)
                        )
                    else:
                        # 已存在的块直接更新进度
                        self.tqdm.update(chunk.cb_original)

    def _handle_chunk_result(self, future, chunk, path):
        """线程完成后的回调函数"""
        try:
            future.result()  # 显式获取结果以捕获异常
            self.tqdm.set_postfix(filename=str(path)[-(shutil.get_terminal_size().columns // 4):])
            self.tqdm.update(chunk.cb_original)
            with self.lock:
                self.chunk_dict[path].append(f'{chunk.offset}_{chunk.sha.hex()}')
                self.save_chunk_dict()
        except Exception as e:
            print(f"Chunk {chunk.offset} download failed: {str(e)}")
            # 这里可以添加重试逻辑


    def save_chunk_dict(self):
        #if self.lock.acquire(blocking=False):
            percentage = int(round(self.tqdm.n / self.tqdm.total * 100))
            new_name = f'{percentage}% - {self.depot_id}.json'
            if self.chunk_dict_path.name != new_name:
                with self.chunk_dict_path.open('r+', encoding='utf-8') as f:
                    json.dump(self.chunk_dict, f)
                self.chunk_dict_path = self.chunk_dict_path.replace(self.chunk_dict_path.with_name(new_name))
            #self.lock.release()

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
                                    args.retry_num, args.login_anonymous, 20, args.appid,
                                    args.use_websocket, args.cellid)
                d.download()

if __name__ == '__main__':
    main()
