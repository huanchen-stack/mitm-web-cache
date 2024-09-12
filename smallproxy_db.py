import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import os
import threading
import gzip
from io import BytesIO
from hashlib import sha256
from pymongo import MongoClient
import requests
from OpenSSL import crypto
import time
from concurrent.futures import ThreadPoolExecutor
import random
from warcio.warcwriter import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders
import brotli

# MongoDB setup
client = MongoClient('localhost', 27017, maxPoolSize=1000)
db = client['mitm-web-cache']
collection = db['web_archive_org']

# Proxy server config
CA_CERT_FILE = "mitmproxy-ca.pem"
CA_KEY_FILE = "mitmproxy-ca.pem"
CERT_DIR = "./certs"
MAX_WORKERS = 50
MAX_SESSIONS_PER_HOST = 6
CONNECTION_IDLE_TIMEOUT = 30

session_lock = threading.Lock()
session_pool = {}
# session_pool = defaultdict(lambda: {'session': None, 'last_used': 0})

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


def hash_url(url):
    """Create a hash for the full URL to use as the cache key."""
    return sha256(url.encode('utf-8')).hexdigest()


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

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
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

        # self.do_GET()
        self.handle_https_request()

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
                print(e)
                self.send_error(502, "Bad Gateway")
            except OSError as e:
                print(e)
                self.send_error(502, "Bad Gateway")

            self.rfile = self.connection.makefile('rb', buffering=0)
            self.wfile = self.connection.makefile('wb', buffering=0)

        finally:
            os.remove(cert_file_path)
            os.remove(key_file_path)

    def handle_https_request(self):
        try:
            request_data = self.rfile.read(65536)
            if not request_data:
                return

            # Parse request data to get the host and path
            request_line = request_data.split(b'\r\n', 1)[0].decode('utf-8')
            method, path, version = request_line.split()
            #   (get host)
            headers_start = request_data.split(b'\r\n\r\n', 1)[0].decode('utf-8', errors='replace')
            host = None
            original_headers = {}
            for line in headers_start.split('\r\n'):
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()  # Get the host from the headers
                elif ': ' in line:
                    key, value = line.split(': ', 1)
                    original_headers[key] = value  # Store the rest of the headers in a dictionary

            if not host:
                self.send_error(400, "Bad Request")
                return

            full_url = f"https://{host}{path}"
            url_hash = hash_url(full_url)

            skip_headers = ["Transfer-Encoding", "Content-Encoding", "Connection", "Keep-Alive", "Proxy-Connection", 
                            "Set-Cookie"]
            
            # Look up the request in the cache
            cached = collection.find_one({"_id": url_hash})
            cached = False 
            if cached:
                # Cache HIT: return the cached response
                status_code, headers, body = parse_warc_record(cached['warc_record'])
                if status_code:
                    self.send_response(status_code)

                    for key, value in headers.items():
                        if key not in skip_headers:
                            self.send_header(key, value)
                    self.end_headers()

                    self.wfile.write(body)
                    return

            # Cache MISS: forward the request and cache the response
            response_status, response_headers, response_body = self.forward_request(request_data, host, path, method, original_headers)

            self.send_response(response_status)
            # TODO: header??
            for key, value in response_headers:
                if key not in skip_headers:
                    self.send_header(key, value)
            self.end_headers()

            if response_body:
                self.wfile.write(response_body)
                self.wfile.flush()

            # Cache the response asynchronously
            response_obj = requests.Response()
            response_obj.status_code = response_status
            response_obj.headers = {k: v for k, v in response_headers}
            response_obj._content = response_body
            threading.Thread(target=self.cache_response, args=(response_obj, full_url)).start()

        except Exception as e:
            print(e, host, path)
            self.send_error(500)
            self.wfile.flush()

    def forward_request(self, request_data, host, path, method, original_headers):
        try:
            session_info = self.get_or_create_session(host, 443)
            full_url = f"https://{host}{path}"

            headers = original_headers.copy()
            headers.pop("Connection", None)
            headers["Host"] = host

            if method == "GET":
                response = session_info['session'].get(full_url, headers=headers, stream=True)
            elif method == "POST":
                body = request_data.split(b'\r\n\r\n', 1)[1]
                response = session_info['session'].post(full_url, data=body, headers=headers, stream=True)
            elif method == "OPTIONS":
                response = session_info['session'].options(full_url, headers=headers)
            else:
                self.send_error(405, "Method Not Allowed")
                return 405, [], b'Method Not Allowed'

            response_status = response.status_code
            response_headers = [(k, v) for k, v in response.headers.items()]
            response_body = response.content

            session_info['last_used'] = time.time()

            return response_status, response_headers, response_body

        except Exception as e:
            print(e, host, path)
            return 500, {'Content-Type': 'text/plain'}, b'Internal Server Error'

    def cache_response(self, response, url):
        """Cache the response as a WARC record."""
        url_hash = hash_url(url)
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

    def get_or_create_session(self, host, port):
        global session_pool

        with session_lock:
            # self.cleanup_expired_sessions()
            session_key = (host, port)

            if session_key not in session_pool:
                session_pool[session_key] = []            
            if len(session_pool[session_key]) < MAX_SESSIONS_PER_HOST:
                session_info = {"session": requests.Session(), "last_used": time.time()}
                session_pool[session_key].append(session_info)
            else:
                session_info = session_pool[session_key].pop(0)
                session_pool[session_key].append(session_info)
    
            return session_info

    def cleanup_expired_sessions(self):
        # TODO: don't need this func
        # lock acquired in caller
        for key, session_info_s in session_pool.items():
            for session_info in session_info_s:
                if time.time() - session_info['last_used'] > CONNECTION_IDLE_TIMEOUT:
                    session_info['session'].close()
                    session_pool[key]


def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    run()
