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
# client = MongoClient('localhost', 27017, maxPoolSize=1000)
# db = client['mitm-web-cache']
# collection = db['web_archive_org']

R_CACHE = False
W_CACHE = False

# Proxy server config
CA_CERT_FILE = "mitmproxy-ca.pem"
CA_KEY_FILE = "mitmproxy-ca.pem"
CERT_DIR = "./certs"
MAX_WORKERS = 100
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
    cert.get_subject().CN = hostname

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
    """Create a hash for the full URL to use as the cache key."""
    return sha256(s.encode('utf-8')).hexdigest()[:32]


class MITMWebCache:
    
    @staticmethod
    def find_warc_record(cache_key):
        if not R_CACHE:
            return None
        pass

    @staticmethod
    def serve_warc_record(wfile, cache_warc):
        pass

    class WfileWARCHook(io.BufferedWriter):
        def __init__(self, wfile, cache_key):
            super().__init__(wfile)
            self.cache_key = cache_key
            # self.buffer = 
            self._closed = False

        def write(self, data):
            if W_CACHE:
                # self.buffer.extend(data)
                pass
            return super().write(data)

        def flush(self):
            if not self.closed:
                super().flush()

        def close(self):
            if not self.closed:
                if W_CACHE:
                    # MITMWebCache.cache[self.cache_key] = bytes(self.buffer)
                    pass
                try:
                    super().close()
                except Exception as _:
                    pass
                self._closed = True

        @property
        def closed(self):
            return self._closed



# store response_heaader and response_body in warcs_body
def create_warc_record(response, request_url) -> bytes:
    """Create a WARC record for the given response."""
    headers_list = [(k, v) for k, v in response.headers.items()]
    status_and_headers = StatusAndHeaders(
        statusline=str(response.status_code),
        headers=headers_list,
        protocol="HTTP/2.0"
    )

    # Write WARC record to a byte stream
    warc_bytes = BytesIO()
    warc_writer = WARCWriter(warc_bytes)
    record = warc_writer.create_warc_record(
        uri=request_url,
        record_type='response',
        payload=BytesIO(response.content),
        http_headers=status_and_headers
    )
    warc_writer.write_record(record)
    warc_bytes.seek(0)
    return warc_bytes.read()


def parse_warc_record(warc_record_bytes: bytes):
    """Parse WARC record to extract status code, headers, and body."""
    with BytesIO(warc_record_bytes) as f:
        for record in ArchiveIterator(f):
            if record.rec_type == 'response':
                status_code = int(record.http_headers.statusline.split()[-1])
                headers = {k: v for k, v in record.http_headers.headers}
                headers["Server"] = "mitm-cache"
                body = record.content_stream().read()
                return status_code, headers, body
    return None, None, None


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
                #TODO: shutdown_request sometimes gives me error due to closed sockets 
                pass

class SocketPool:
    def __init__(self, max_connections_per_host=6, idle_timeout=30):
        self.max_connections_per_host = max_connections_per_host
        self.idle_timeout = idle_timeout
        self.pool = {}
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

            if self.pool[host]:
                sock, _ = self.pool[host].pop()
                return sock

            if len(self.pool[host]) < self.max_connections_per_host:
                try:
                    sock = socket.create_connection((host, 443))
                    ssl_context = ssl.create_default_context()
                    sock = ssl_context.wrap_socket(sock, server_hostname=host)
                    return sock
                except Exception as e:
                    return None

            print("WARNING: This line should not be reached!", flush=True)
            return None
        
    def release_socket(self, host, sock):
        with self.lock:
            self.pool[host].append((sock, time.time()))

    def _cleanup_stale_sockets(self, host):
        current_time = time.time()
        self.pool[host] = [
            (sock, last_used) for sock, last_used in self.pool[host]
            if current_time - last_used <= self.idle_timeout and SocketPool.is_socket_alive(sock)
        ]

SOCKETPOOL = SocketPool(max_connections_per_host=MAX_SESSIONS_PER_HOST)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_https_request()

    def do_POST(self):
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
        hostname = l_[0]
        if port == '443':
            self.establish_tls_connection(hostname)
        else:
            self.send_error(400, "Only HTTPS connections are handled in CONNECT method.")
            return

        self.handle_https_request()

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
            # print("chunk_size:", chunk_size_str, chunk_size, flush=True)
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
                # print(f"Received {bytes_received} of {chunk_size} bytes", flush=True)

            trailing_chars = read_from_body_or_sock(2)  # The trailing CRLF after the chunk data
            wfile.write(trailing_chars)
            wfile.flush()

    @staticmethod
    def handle_content_sized_response(sock, wfile, body, content_length):
        total_read = len(body)
        wfile.write(body)
        wfile.flush()

        while total_read < content_length:
            to_read = min(4096, content_length - total_read)
            data = sock.recv(to_read)
            total_read += len(data)
            wfile.write(data)
            wfile.flush()

    @staticmethod
    def get_and_forward_http_response(sock, wfile):
        response = b""
        
        while True:
            data = sock.recv(65536)
            response += data
            if b"\r\n\r\n" in response:
                break

        headers, body = response.split(b"\r\n\r\n", 1)

        header_lines = headers.decode("utf-8").split("\r\n")
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

        if is_chunked:
            ProxyRequestHandler.handle_chunked_response(sock, wfile, body)
        elif content_length > 0:
            ProxyRequestHandler.handle_content_sized_response(sock, wfile, body, content_length)

    def establish_tls_connection(self, hostname):
        cert_bytes, key_bytes = create_certificate(hostname)

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
                # self.send_error(502, "Bad Gateway")
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

    def handle_https_request(self):
        request_headers = b""
        while True:
            line = self.rfile.readline()
            if not line or line == b"\r\n":
                break
            request_headers += line
    
        content_length = 0
        for header in request_headers.decode().split("\r\n"):
            if header.lower().startswith("content-length"):
                content_length = int(header.split(":")[1].strip())
                break
    
        request_data = request_headers + b"\r\n"
        if not request_data:
            self.send_error(400, "Bad Request")
            return
    
        # print(request_data.decode('utf-8'), flush=True)
    
        request_data_list = request_data.split(b'\r\n')
        
        request_identifier = request_data_list[0].decode('utf-8') + request_data_list[1].decode('utf-8')
        cache_key = hash_string(request_identifier)
        cache_warc = MITMWebCache.find_warc_record(cache_key)
        if cache_warc:
            MITMWebCache.serve_warc_record(wfile=self.wfile, cache_warc=cache_warc)
            return
        self.wfile = MITMWebCache.WfileWARCHook(wfile=self.wfile, cache_key=cache_key)

        host = request_data_list[1].decode('utf-8')[5:].strip()
    
        # Validate and sanitize hostname
        if not host or len(host) > 255 or not all(c.isalnum() or c in '-.' for c in host):
            self.send_error(400, f"Invalid hostname {host}")
            self.wfile.close()
            return
    
        try:
            sock = SOCKETPOOL.get_socket(host)

            sock.sendall(request_data)
            if content_length > 0:  # request payload
                remaining = content_length
                while remaining > 0:
                    chunk_size = min(4096, remaining)
                    chunk = self.rfile.read(chunk_size)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    remaining -= len(chunk)
    
            ProxyRequestHandler.get_and_forward_http_response(sock, self.wfile)

            SOCKETPOOL.release_socket(host, sock)
    
        except Exception as e:
            print(e, flush=True)
            self.send_error(503, "Bad Gateway")
        finally:
            self.wfile.close()
    
    def cache_response(self, response, url):
        """Cache the response as a WARC record."""
        url_hash = hash_string(url)
        warc_record_bytes = create_warc_record(response, url)
        collection.update_one(
            {"_id": url_hash},
            {
                "$set": {
                    "url": url,
                    "warc_record": warc_record_bytes
                }
            },
            upsert=True
        )


def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    run()
