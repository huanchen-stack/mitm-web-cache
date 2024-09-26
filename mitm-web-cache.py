import io
import select
import socket
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import os
import threading
import gzip
from io import BytesIO
from hashlib import sha256
from pymongo import MongoClient
from OpenSSL import crypto
import time
from concurrent.futures import ThreadPoolExecutor
import random
from warcio.warcwriter import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders
import brotli  # MUST IMPORT: IMPLICITELY USED BY WARCIO LIBRARY

# MongoDB setup
MONGO_URI = 'localhost:27017'
DB_NAME = 'mitm-web-cache'
COLLECTION_NAME = 'web_archive_org'
R_CACHE = True
W_CACHE = True

# Proxy server config
CA_CERT_FILE = "mitmproxy-ca.pem"
CA_KEY_FILE = "mitmproxy-ca.pem"
CERT_DIR = "./certs"
MAX_WORKERS = 10000
MAX_SESSIONS_PER_HOST = 3
CONNECTION_IDLE_TIMEOUT = 30


def create_certificate(hostname):
    """Generate a certificate and key for the given hostname."""
    with open(CA_CERT_FILE, "rt") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(CA_KEY_FILE, "rt") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "MyOrganization"
    cert.get_subject().CN = hostname[:64]

    unique_serial = int(time.time() * 1000) + random.SystemRandom().randint(1, 100000)
    cert.set_serial_number(unique_serial)

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)

    san_list = [f"DNS:{hostname}"]
    san_extension = crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode())
    cert.add_extensions([san_extension])

    cert.sign(ca_key, 'sha256')

    cert_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_bytes = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    return cert_bytes, key_bytes

def hash_string(s):
    return sha256(s.encode('utf-8')).hexdigest()[:32]

class MITMWebCache:

    db_collection = MongoClient(MONGO_URI, maxPoolSize=1000)[DB_NAME][COLLECTION_NAME]
    r_cache = R_CACHE
    w_cache = W_CACHE

    @staticmethod
    def find_warc_record(cache_key):
        if MITMWebCache.r_cache:
            warc_record = MITMWebCache.db_collection.find_one({"_id": cache_key})
            if warc_record:
                return warc_record["warc_record"]
        return None

    @staticmethod
    def serve_warc_record(wfile, cache_warc):
        # warc_stream = io.BytesIO(cache_warc)
        # for record in ArchiveIterator(warc_stream):
        #     payload = record.content_stream().read()
        #     for i in range(0, len(payload), 4096):
        #         wfile.write(payload[i:i + 4096])
        #         wfile.flush()
        #     wfile.flush()
        warc_stream = io.BytesIO(cache_warc)  # Create a byte stream for the cached response
        
        # Read and serve the entire payload (which includes status line, headers, and body)
        while True:
            chunk = warc_stream.read(4096)  # Read in 4096-byte chunks
            if not chunk:
                break
            wfile.write(chunk)  # Write the chunk to the browser
            wfile.flush() 

    class WfileWARCHook(io.BufferedWriter):
        def __init__(self, wfile, cache_key):
            super().__init__(wfile)

            self.cache_key = cache_key
            self.buff = io.BytesIO()

            self._closed = False

        def write(self, data):
            if MITMWebCache.w_cache:
                self.buff.write(data)
            return super().write(data)

        def flush(self):
            if not self.closed:
                try:
                    super().flush()
                except Exception as _:
                    pass  # TODO: Handle any flush errors

        def close(self):
            if not self.closed:
                if MITMWebCache.w_cache:
                    self.buff.seek(0)
                    # warc_writer = WARCWriter(self.buff)
                    # status_and_headers = StatusAndHeaders(
                    #     statusline="HTTP/1.1 200 OK",
                    #     headers=[('Content-Type', 'text/html')],
                    #     protocol="HTTP/1.1"
                    # )
                    # warc_record = warc_writer.create_warc_record(
                    #     uri=self.cache_key,
                    #     record_type='response',
                    #     payload=self.buff,
                    #     http_headers=status_and_headers
                    # )
                    

                    MITMWebCache.db_collection.update_one(
                        {"_id": self.cache_key},
                        {
                            "$set": {
                                "url": self.cache_key,  # Placeholder for the URL
                                "warc_record": self.buff.read()
                            }
                        },
                        upsert=True
                    )

                try:
                    super().close()
                except Exception as _:
                    pass
                self._closed = True

        @property
        def closed(self):
            return self._closed

MITMWEBCACHE = MITMWebCache()

class ThreadedHTTPServer(HTTPServer):
    """Handle requests in a separate thread."""
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception as e:
            # pass
            try:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            except Exception as e:
                print(e, flush=True)
                #TODO: shutdown_request sometimes gives me error due to closed sockets 
                pass

class SocketPool:
    def __init__(self, max_connections_per_host=6, idle_timeout=30):
        self.max_connections_per_host = max_connections_per_host
        self.idle_timeout = idle_timeout
        self.pool = {}
        self.connections_per_host = {}
        self.condition = threading.Condition()

    @staticmethod
    def is_socket_alive(sock):
        try:
            ready_to_read, _, _ = select.select([sock], [], [], 0)
            if ready_to_read:
                data = sock.recv(1, socket.MSG_PEEK)
                if data:
                    return True
                else:
                    return False
            else:
                return True
        except Exception:
            return False

    def get_socket(self, host):
        with self.condition:
            if host in self.pool:
                self._cleanup_stale_sockets(host)
            else:
                self.pool[host] = []
                self.connections_per_host[host] = 0
            
            if not self.pool[host] and self.connections_per_host[host] < self.max_connections_per_host:
                try:
                    sock = socket.create_connection((host, 443))
                    ssl_context = ssl.create_default_context()
                    sock = ssl_context.wrap_socket(sock, server_hostname=host)
                    print(f"=-=-=-=-= New connection to {host}", flush=True)
                    
                    self.connections_per_host[host] += 1
                    return sock
                except Exception as e:
                    return None

            while not self.pool[host]:
                self.condition.wait()
            sock, _ = self.pool[host].pop()
            return sock
        
    def release_socket(self, host, sock):
        if SocketPool.is_socket_alive(sock):
            with self.condition:
                self.pool[host].append((sock, time.time()))
                self.condition.notify()
        else:
            self._cleanup_stale_sockets(host, force=True)

    def _cleanup_stale_sockets(self, host, force=False):
        current_time = time.time()
        if not force:
            clean_all = False
            for i in range(len(self.pool[host])):
                sock, last_used = self.pool[host][i]
                if current_time - last_used > self.idle_timeout or not SocketPool.is_socket_alive(sock):
                    clean_all = True
                    break
        else:
            clean_all = True
        
        if clean_all:
            print(f"=======c-l-e-a-n-i-n-g=======(host: {host})", flush=True)
            for sock in self.pool[host]:
                try:
                    sock[0].close()
                except Exception as e:
                    pass
            self.connections_per_host[host] -= len(self.pool[host])
            self.pool[host] = []

        # cur_num_host = len(self.pool[host])
        # self.pool[host] = [
        #     (sock, last_used) for sock, last_used in self.pool[host]
        #     if current_time - last_used <= self.idle_timeout and SocketPool.is_socket_alive(sock)
        # ]
        # self.connections_per_host[host] -= cur_num_host - len(self.pool[host])

SOCKETPOOL = SocketPool(max_connections_per_host=MAX_SESSIONS_PER_HOST, idle_timeout=CONNECTION_IDLE_TIMEOUT)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Handling GET request for path", self.path, flush=True)
        self.handle_https_request()

    def do_POST(self):
        print("Handling POST request for path", self.path, flush=True)
        self.handle_https_request()

    def do_HEAD(self):
        self.handle_https_request()

    def do_PUT(self): 
        self.handle_https_request()

    def do_DELETE(self):
        self.handle_https_request()

    def do_OPTIONS(self):
        self.handle_https_request()

    def do_CONNECT(self):

        port = "443"
        l_ = self.path.split(':')
        if len(l_) > 1:
            port = l_[1]
        self.hostname = l_[0]

        try:
            # get a proxy-server sock before browser-proxy connection
            start = time.time()

            if port == '443':
                self.establish_tls_connection()
                connection_negotiate_time = time.time() - start
                self.handle_https_request()
            else:
                print(f"!! HTTP IS NOT SUPPORTED !!", flush=True)
                self.send_error(400, "Only HTTPS connections are handled in CONNECT method.")
                return        
        except Exception as e:
            print("?????", e, flush=True)
        finally:
            try:
                self.connection.close()
            except Exception as e:
                print("!!!!!!!!", e, flush=True)

    def establish_tls_connection(self):
        cert_bytes, key_bytes = create_certificate(self.hostname)

        with tempfile.NamedTemporaryFile(delete=False) as cert_file:
            cert_file.write(cert_bytes)
            cert_file_path = cert_file.name

        with tempfile.NamedTemporaryFile(delete=False) as key_file:
            key_file.write(key_bytes)
            key_file_path = key_file.name

        try:
            self.send_response(200, "Connection Established")
            # self.send_header("Connection", "close")
            self.end_headers()

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

            if not self.connection or self.connection.fileno() == -1:
                return
            try:
                self.connection = context.wrap_socket(self.connection, server_side=True)
            except ssl.SSLError as e:
                print(e, flush=True)
                self.send_error(502, "Bad Gateway")
            except OSError as e:
                print(e, flush=True)
                self.send_error(502, "Bad Gateway")

            self.rfile = self.connection.makefile('rb', buffering=0)
            self.wfile = self.connection.makefile('wb', buffering=0)

        finally:
            os.remove(cert_file_path)
            os.remove(key_file_path)

    def forward_request(self):
        request_headers = b""
        while True:
            line = self.rfile.readline()
            if not line or line == b"\r\n":
                break
            request_headers += line
    
        content_length = 0
        self.sec_fetch_dest = ""
        for header in request_headers.decode().split("\r\n"):
            if header.lower().startswith("content-length"):
                content_length = int(header.split(":")[1].strip())
            if header.lower().startswith("sec-fetch-dest"):
                self.sec_fetch_dest = header.split(":")[1].strip().lower()
    
        request_data = request_headers + b"\r\n"    
        request_data_list = request_data.split(b'\r\n')
        request_identifier = request_data_list[0].decode('utf-8')[:80] + request_data_list[1].decode('utf-8')
        cache_key = hash_string(request_identifier)
        # print(request_identifier)

        cache_warc = MITMWebCache.find_warc_record(cache_key)
        if cache_warc:
            # print("CACHE FOUND", flush=True)
            return cache_warc, cache_key
        else:
            print("PROX FROM WEB", flush=True)
            print(f"{self.ts}\tREQUEST: {request_data_list[0].decode('utf-8')}\t{request_data_list[1].decode('utf-8')}", flush=True)

        self.sock = SOCKETPOOL.get_socket(self.hostname)
        # print(f"{self.ts}\tREQUEST: {request_data_list[0].decode('utf-8')}\t{request_data_list[1].decode('utf-8')}", flush=True)

        self.sock.sendall(request_data)
        if content_length > 0:  # request payload
            remaining = content_length
            while remaining > 0:
                chunk_size = min(4096, remaining)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                self.sock.sendall(chunk)
                remaining -= len(chunk)

        return None, cache_key

    def handle_chunked_response(self, body):
        def read_from_body_or_sock(num_bytes):
            nonlocal body
            if body:
                chunk_data = body[:num_bytes]
                body = body[len(chunk_data):]  # Remove the chunk from the body
                return chunk_data
            else:
                return self.sock.recv(num_bytes)

        while True:
            chunk_size_str = b""
            while b"\r\n" not in chunk_size_str:
                data = read_from_body_or_sock(1)
                if not data:
                    raise Exception("Connection closed unexpectedly while reading chunk size")
                chunk_size_str += data

            chunk_size = int(chunk_size_str.split(b"\r\n")[0], 16)
            try:
                self.wfile.write(chunk_size_str)
                self.wfile.flush()
            except Exception as e:
                if not self.err_rsc_opt:
                    raise e

            if chunk_size == 0:
                try:
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                except Exception as e:
                    if not self.err_rsc_opt:
                        raise e
                break

            bytes_received = 0
            while bytes_received < chunk_size:
                to_read = min(4096, chunk_size - bytes_received)
                chunk_data = read_from_body_or_sock(to_read)
                if not chunk_data:
                    raise Exception("Connection closed unexpectedly while reading chunk data")
                try:
                    self.wfile.write(chunk_data)
                    self.wfile.flush()
                except Exception as e:
                    if not self.err_rsc_opt:
                        raise e
                bytes_received += len(chunk_data)

            trailing_chars = read_from_body_or_sock(2)  # The trailing CRLF after the chunk data
            try:
                self.wfile.write(trailing_chars)
                self.wfile.flush()
            except Exception as e:
                if not self.err_rsc_opt:
                    raise e

    def handle_content_sized_response(self, body, content_length):
        total_read = len(body)
        if total_read > 0:
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except Exception as e:
                if not self.err_rsc_opt:
                    raise e

        while total_read < content_length:
            to_read = min(4096, content_length - total_read)
            data = self.sock.recv(to_read)
            total_read += len(data)
            try:    
                self.wfile.write(data)
                self.wfile.flush()
            except Exception as e:
                if not self.err_rsc_opt:
                    raise e

    def forward_response(self):
        response = b""
        while True:
            data = self.sock.recv(4096)
            response += data
            if b"\r\n\r\n" in response:
                break

        headers, body = response.split(b"\r\n\r\n", 1)
        header_lines = headers.decode("utf-8").strip("\r\n").split("\r\n")   # add strip to sanitize

        self.err_rsc_opt = False
        if self.sec_fetch_dest not in ["", "empty", "none"]:
            status_line = header_lines[0].split()
            if len(status_line) >= 3 and len(status_line[1]) == 3 and status_line[1].isdigit():
                self.err_rsc_opt = int(status_line[1][0]) > 2
        
        # self.err_rsc_opt = False
        # if self.err_rsc_opt:
        #     updated_headers = []
        
        is_chunked = False
        content_length = 0
        for header in header_lines:
            if header.lower().startswith("transfer-encoding") and "chunked" in header.lower():
                is_chunked = True
                break
            elif header.lower().startswith("content-length"):
                content_length = int(header.split(":")[1].strip())
                break

        self.wfile.write(headers + b"\r\n\r\n")
        self.wfile.flush()

        if is_chunked:
            self.handle_chunked_response(body)
        elif content_length > 0:
            self.handle_content_sized_response(body, content_length)

    def handle_https_request(self):
    
        try:
            self.ts = time.time()

            cache_warc, cache_key = self.forward_request()
            if cache_warc:
                # print("Serve from cache", flush=True)
                MITMWEBCACHE.serve_warc_record(wfile=self.wfile, cache_warc=cache_warc)
            else:
                self.wfile = MITMWebCache.WfileWARCHook(wfile=self.wfile, cache_key=cache_key)
                self.forward_response()
                SOCKETPOOL.release_socket(self.hostname, self.sock)
        except Exception as e: 
            print(f"\t{e}\n\tMAYBE SOCK CLOSED ON BROWSER SIDE/POOL MANAGEMENT\n", flush=True)

def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    print("Serving at", server_address, flush=True)
    httpd.serve_forever()

if __name__ == "__main__":
    run()
