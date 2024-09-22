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
MAX_SESSIONS_PER_HOST = 6
CONNECTION_IDLE_TIMEOUT = 300000


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
        self.lock = threading.Lock()

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
        with self.lock:
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

            while not len(self.pool[host]):
                time.sleep(0.01)
            sock, _ = self.pool[host].pop()
            return sock
        
    def release_socket(self, host, sock):
        with self.lock:
            self.pool[host].append((sock, time.time()))

    def _cleanup_stale_sockets(self, host):
        current_time = time.time()
        self.pool[host] = [
            (sock, last_used) for sock, last_used in self.pool[host]
            if current_time - last_used <= self.idle_timeout and SocketPool.is_socket_alive(sock)
        ]
        self.connections_per_host[host] = len(self.pool[host])

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

        # get a proxy-server sock before browser-proxy connection
        self.sock = SOCKETPOOL.get_socket(self.hostname)

        if port == '443':
            self.establish_tls_connection()
            self.handle_https_request()
        else:
            print(f"!! HTTP IS NOT SUPPORTED !!", flush=True)
            self.send_error(400, "Only HTTPS connections are handled in CONNECT method.")
            SOCKETPOOL.release_socket(self.hostname, self.sock)
            return        

        SOCKETPOOL.release_socket(self.hostname, self.sock)

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

    @staticmethod
    def forward_request(rfile, sock, ts):
        request_headers = b""
        while True:
            line = rfile.readline()
            if not line or line == b"\r\n":
                break
            request_headers += line
    
        content_length = 0
        for header in request_headers.decode().split("\r\n"):
            if header.lower().startswith("content-length"):
                content_length = int(header.split(":")[1].strip())
                break
    
        request_data = request_headers + b"\r\n"    
        request_data_list = request_data.split(b'\r\n')
        request_identifier = request_data_list[0].decode('utf-8') + request_data_list[1].decode('utf-8')
        cache_key = hash_string(request_identifier)

        print(f"{ts}\tREQUEST: {request_data_list[0].decode('utf-8')}\t{request_data_list[1].decode('utf-8')}", flush=True)

        sock.sendall(request_data)
        if content_length > 0:  # request payload
            remaining = content_length
            while remaining > 0:
                chunk_size = min(4096, remaining)
                chunk = rfile.read(chunk_size)
                if not chunk:
                    break
                sock.sendall(chunk)
                remaining -= len(chunk)

    @staticmethod
    def forward_request_forever(conn, sock):
        try:
            while True:
                data = conn.read(4096)
                # if not data:
                #     break
                # with lock:
                #     buff.write(data)
                sock.sendall(data)
        except Exception as e:
            print(f"Error forwarding data from client to target: {e}", flush=True)

    @staticmethod
    def handle_chunked_response(sock, wfile, body):
        def read_from_body_or_sock(num_bytes):
            nonlocal body
            if body:
                chunk_data = body[:num_bytes]
                body = body[len(chunk_data):]  # Remove the chunk from the body
                return chunk_data
            else:
                return sock.recv(num_bytes)

        while True:
            chunk_size_str = b""
            while b"\r\n" not in chunk_size_str:
                data = read_from_body_or_sock(1)
                if not data:
                    raise Exception("Connection closed unexpectedly while reading chunk size")
                chunk_size_str += data

            chunk_size = int(chunk_size_str.split(b"\r\n")[0], 16)
            wfile.write(chunk_size_str)
            wfile.flush()

            if chunk_size == 0:
                wfile.write(b"\r\n")
                wfile.flush()
                break

            bytes_received = 0
            while bytes_received < chunk_size:
                to_read = min(4096, chunk_size - bytes_received)
                chunk_data = read_from_body_or_sock(to_read)
                if not chunk_data:
                    raise Exception("Connection closed unexpectedly while reading chunk data")
                wfile.write(chunk_data)
                wfile.flush()
                bytes_received += len(chunk_data)

            trailing_chars = read_from_body_or_sock(2)  # The trailing CRLF after the chunk data
            wfile.write(trailing_chars)
            wfile.flush()

    @staticmethod
    def handle_content_sized_response(sock, wfile, body, content_length):
        total_read = len(body)
        if total_read > 0:
            wfile.write(body)
            wfile.flush()

        while total_read < content_length:
            to_read = min(4096, content_length - total_read)
            data = sock.recv(to_read)
            total_read += len(data)
            wfile.write(data)
            wfile.flush()

    @staticmethod
    def forward_response(sock, wfile, ts):
        response = b""
        while True:
            data = sock.recv(4096)
            response += data
            if b"\r\n\r\n" in response:
                break

        headers, body = response.split(b"\r\n\r\n", 1)
        header_lines = headers.decode("utf-8").split("\r\n")

        eof_exempt = False
        status_line = header_lines[0].split()
        if len(status_line) >= 3 and len(status_line[1]) == 3 and status_line[1].isdigit():
            eof_exempt = int(status_line[1][0]) > 2

        is_chunked = False
        content_length = 0
        for header in header_lines:
            if header.lower().startswith("transfer-encoding") and "chunked" in header.lower():
                is_chunked = True
                break
            elif header.lower().startswith("content-length"):
                content_length = int(header.split(":")[1].strip())
                break

        wfile.write(headers + b"\r\n\r\n")
        wfile.flush()

        try:
            if is_chunked:
                ProxyRequestHandler.handle_chunked_response(sock, wfile, body)
            elif content_length > 0:
                ProxyRequestHandler.handle_content_sized_response(sock, wfile, body, content_length)
        except Exception as e:
            if not eof_exempt:
                print(header_lines, flush=True)
                print(f"{ts}\tError handling response: {e}", flush=True)

    @staticmethod
    def forward_response_forever(sock, conn):
        # try:
        while True:
            try:
                data = sock.recv(4096)
            except Exception as e:
                print("Error receiving data from target:", e, flush=True)
            # if not data:
            #     break
            # with lock:
            #     buff.write(data)
            try:
                conn.sendall(data)
            except Exception as e:
                print("Error sending data to client:", e, flush=True)

        # except Exception as e:
        #     print(f"Error forwarding data from target to client: {e}", flush=True)


    def handle_https_request(self):
        
        # cache_warc = MITMWebCache.find_warc_record(cache_key)
        # if False and cache_warc:
            # MITMWebCache.serve_warc_record(wfile=self.wfile, cache_warc=cache_warc)
            # return
        # self.wfile = MITMWebCache.WfileWARCHook(wfile=self.wfile, cache_key=cache_key)

        # host = request_data_list[1].decode('utf-8')[5:].strip()
    
        # # Validate and sanitize hostname
        # if not host or len(host) > 255 or not all(c.isalnum() or c in '-.' for c in host):
        #     self.send_error(400, f"Invalid hostname {host}")
        #     self.wfile.close()
        #     return
    
        try:
            # sock = SOCKETPOOL.get_socket(self.hostname)
            # sock = socket.create_connection((self.hostname, 443))
            # ssl_context = ssl.create_default_context()
            # sock = ssl_context.wrap_socket(sock, server_hostname=self.hostname)

            sock = self.sock

            ts = time.time()

            th_request = threading.Thread(target=ProxyRequestHandler.forward_request, args=(self.rfile, sock, ts))
            th_response = threading.Thread(target=ProxyRequestHandler.forward_response, args=(sock, self.wfile, ts))
            th_request.start()
            th_response.start()
            th_request.join()
            th_response.join()

            # SOCKETPOOL.release_socket(self.hostname, sock)
    
        except Exception as e: 
            print(f"\tMAYBE SOCK CLOSED ON BROWSER SIDE/POOL MANAGEMENT\n", flush=True)


def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    print("Serving at", server_address, flush=True)
    httpd.serve_forever()

if __name__ == "__main__":
    run()
