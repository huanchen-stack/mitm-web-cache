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

# from warcio.warcwriter import WARCWriter
# from warcio.archiveiterator import ArchiveIterator
# from warcio.statusandheaders import StatusAndHeaders
# import brotli  # MUST IMPORT: IMPLICITELY USED BY WARCIO LIBRARY

# MongoDB setup
MONGO_URI = 'fable.eecs.umich.edu:27017'
DB_NAME = 'mitm-web-cache'
COLLECTION_NAME = 'web_archive_org'
R_CACHE = True
W_CACHE = R_CACHE

# Proxy server config
CA_CERT_FILE = "mitmproxy-ca.pem"
CA_KEY_FILE = "mitmproxy-ca.pem"
MAX_WORKERS = 100000
MAX_SESSIONS_PER_HOST = 6
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
        while True:
            chunk = warc_stream.read(4096)  # Read in 4096-byte chunks
            if not chunk:
                break
            try:
                wfile.write(chunk)  # Write the chunk to the browser
                wfile.flush() 
            except Exception as e:
                return False
        return True

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
            
            if self.connections_per_host[host] < self.max_connections_per_host:
                try:
                    sock = socket.create_connection((host, 443))
                    ssl_context = ssl.create_default_context()
                    sock = ssl_context.wrap_socket(sock, server_hostname=host)
                    
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
            self.connections_per_host[host] -= 1
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
            for sock in self.pool[host]:
                try:
                    sock[0].close()
                except Exception as e:
                    pass
            self.connections_per_host[host] -= len(self.pool[host])
            self.pool[host] = []

SOCKETPOOL = SocketPool(max_connections_per_host=MAX_SESSIONS_PER_HOST, idle_timeout=CONNECTION_IDLE_TIMEOUT)

class ConnectionPool:

    max_connections_per_host = MAX_SESSIONS_PER_HOST
    max_connection_timeout = CONNECTION_IDLE_TIMEOUT
    
    def __init__(self):
        self.hosts = {}
    
    def get_socket(self, host):
        if host not in self.hosts:
            self.hosts[host] = ConnectionPool.HostPool(host)
        return self.hosts[host].get_socket()
    
    def release_socket(self, host, sock):
        self.hosts[host].release_socket(sock)

    @staticmethod
    def _create_socket(host, port=443):
        try:
            sock = socket.create_connection((host, port))
            ssl_context = ssl.create_default_context()
            sock = ssl_context.wrap_socket(sock, server_hostname=host)
        except Exception as e:
            print("Socket creation failed:", e, flush=True)
            return None
        return sock
    
    @staticmethod
    def _destroy_socket(sock):
        try:
            sock.close()
        except Exception as e:
            print("Socket destruction failed:", e, flush=True)
            return False
        return True
    
    @staticmethod
    def _is_socket_alive(sock):
        try:
            ready_to_read, _, in_error = select.select([sock], [], [], 0)
            if in_error:
                return False
            if ready_to_read:
                data = sock.recv(1, socket.MSG_PEEK)
                if not data:
                    return False
            return True
        except Exception:
            return False

    class HostPool:
        def __init__(self, host):
            self.host = host
            self.pool = []
            self.condition = threading.Condition()
            self.max_retries = 3

        def get_socket(self):
            with self.condition:
                while True:
                    self.cleanup()

                    if len(self.pool) < ConnectionPool.max_connections_per_host:
                        for _ in range(self.max_retries):
                            sock = ConnectionPool._create_socket(self.host)
                            if sock:
                                self.pool.append({"sock": sock, "status": "busy"})
                                return sock

                    for sock_item in self.pool:
                        if sock_item["status"] == "idle":
                            sock_item["status"] = "busy"
                            return sock_item["sock"]

                    self.condition.wait(timeout=10)

        def release_socket(self, sock):
            with self.condition:
                to_be_removed = []
                for sock_item in self.pool:
                    if sock_item["sock"] == sock:
                        if ConnectionPool._is_socket_alive(sock):
                            sock_item["status"] = "idle"
                        else:
                            ConnectionPool._destroy_socket(sock)
                            to_be_removed.append(sock_item)
                        self.condition.notify()
                        break
                for sock_item in to_be_removed:
                    self.pool.remove(sock_item)

        def cleanup(self):
            return
            with self.condition:
                to_be_removed = []
                for sock_item in self.pool:
                    if not ConnectionPool._is_socket_alive(sock_item["sock"]):
                        ConnectionPool._destroy_socket(sock_item["sock"])
                        to_be_removed.append(sock_item)
                for sock_item in to_be_removed:
                    self.pool.remove(sock_item)

SOCKETPOOL = ConnectionPool()

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
        self.ts = time.time()

        port = "443"
        l_ = self.path.split(':')
        if len(l_) > 1:
            port = l_[1]
        self.hostname = l_[0]

        if "archive.org" not in self.hostname:
            self.send_error(400, "Only archive.org is supported.")
            return

        try:
            # get a proxy-server sock before browser-proxy connection
            # self.sock = SOCKETPOOL.get_socket(self.hostname)
            if port == '443':
                self.establish_tls_connection()
                self.handle_https_request()
            else:
                print(f"!! HTTP IS NOT SUPPORTED !!", flush=True)
                self.send_error(400, "Only HTTPS connections are handled in CONNECT method.")
                return        
        except Exception as e:
            print("?????", e, flush=True)
        finally:
            try:
                # SOCKETPOOL.release_socket(self.hostname, self.sock)
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
            self.end_headers()

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

            if not self.connection or self.connection.fileno() == -1:
                return
            try:
                self.connection = context.wrap_socket(self.connection, server_side=True)

                remote_ip, remote_port = self.connection.getpeername()
                print(f"{self.ts} TLS connection established with {remote_ip}:{remote_port}", flush=True)

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
        request_data_list = request_data.strip().split(b'\r\n')
        request_identifier = request_data_list[0].decode('utf-8') + request_data_list[1].decode('utf-8')
        cache_key = hash_string(request_identifier)

        self.method = request_data_list[0].decode('utf-8').split(' ')[0]

        # print(f"{self.ts}\tREQUEST: {request_data_list[0].decode('utf-8')}\t{request_data_list[1].decode('utf-8')}", flush=True)
        cache_warc = MITMWebCache.find_warc_record(cache_key)
        if cache_warc:
            return cache_warc, cache_key

        if self.sock is None:
            self.sock = SOCKETPOOL.get_socket(self.hostname)
        if not SocketPool.is_socket_alive(self.sock):  # sanity check?
            print("SOCKET NOT ALIVE", flush=True)
            self.sock = SOCKETPOOL.get_socket(self.hostname)
        # print(f"{self.ts} PROX FROM WEB with sock {id(self.sock)}", flush=True)

        self.sock.settimeout(30)
        try:
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
        except socket.timeout:
            print(f"{self.ts} Request timeout", flush=True)
            return None, None
        except Exception as e:
            print(f"{self.ts} Request failed: {e}", flush=True)
            return None, None
        finally:
            self.sock.settimeout(None)
        # print(f"{self.ts} Request forwarded", flush=True)

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
        self.sock.settimeout(30)
        response = b""
        try:
            while True:
                data = self.sock.recv(4096)
                if data:
                    pass
                    # print(f"{self.ts} Receiving {len(data)} bytes", flush=True)
                else:
                    raise socket.timeout
                response += data
                if b"\r\n\r\n" in response:
                    break
        except socket.timeout:
            print(f"{self.ts} Response timeout", flush=True)
            return
        finally:
            self.sock.settimeout(None)
        
        # print(response.decode("utf-8").split("\r\n")[0], flush=True)
        headers, body = response.split(b"\r\n\r\n", 1)
        header_lines = headers.decode("utf-8").strip("\r\n").split("\r\n")   # add strip to sanitize

        # Modify the Connection header to be 'close'
        modified_headers = []
        for line in header_lines:
            if not line.lower().startswith("connection:"):
                modified_headers.append(line)
        modified_headers.append("Connection: close")
        modified_headers = "\r\n".join(modified_headers).encode("utf-8")

        self.wfile.write(modified_headers + b"\r\n\r\n")
        self.wfile.flush()

        if self.method == "HEAD":
            return
        
        status_line = header_lines[0].split()
        self.err_rsc_opt = False
        if self.sec_fetch_dest not in ["", "empty", "none"]:
            if len(status_line) >= 3 and len(status_line[1]) == 3 and status_line[1].isdigit():
                self.err_rsc_opt = int(status_line[1][0]) > 2

        is_chunked = False
        content_length = 0
        for header in header_lines:
            if header.lower().startswith("transfer-encoding") and "chunked" in header.lower():
                is_chunked = True
                break
            elif header.lower().startswith("content-length"):
                content_length = int(header.split(":")[1].strip())
                break

        if is_chunked:
            self.handle_chunked_response(body)
        elif content_length > 0:
            self.handle_content_sized_response(body, content_length)

    def handle_https_request(self):
        try:
            self.sock = None

            cache_warc, cache_key = self.forward_request()
            if cache_warc:
                print(f"{self.ts} Serve from cache", flush=True)
                succeed = MITMWEBCACHE.serve_warc_record(wfile=self.wfile, cache_warc=cache_warc)
                if not succeed:
                    print(f"{self.ts} EXCEPTING CACHE WRITE ERR!!!", flush=True)
                # cache_warc, cache_key = self.forward_request()
            elif cache_key:
                self.wfile = MITMWebCache.WfileWARCHook(wfile=self.wfile, cache_key=cache_key)
                self.forward_response()
        except Exception as e: 
            print(f"\t{self.ts}{e}\n\tMAYBE SOCK CLOSED ON BROWSER SIDE/POOL MANAGEMENT\n", flush=True)
        finally:
            if self.sock:
                SOCKETPOOL.release_socket(self.hostname, self.sock)


def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('0.0.0.0', 8090)
    httpd = server_class(server_address, handler_class)
    print("Serving at", server_address, flush=True)
    httpd.serve_forever()

if __name__ == "__main__":
    run()
