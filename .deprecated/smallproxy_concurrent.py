from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import os
import requests
from OpenSSL import crypto
import time
import http.client
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor
import tempfile
import random

CA_CERT_FILE = "mitmproxy-ca.pem"
CA_KEY_FILE = "mitmproxy-ca.pem"
CERT_DIR = "./certs"

MAX_WORKERS = 20
MAX_SESSIONS_PER_HOST = 6
CONNECTION_IDLE_TIMEOUT = 30

session_pool = defaultdict(lambda: {'session': None, 'last_used': 0})

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
    san_extension = crypto.X509Extension(
        b"subjectAltName", False, ", ".join(san_list).encode())
    cert.add_extensions([san_extension])

    cert.sign(ca_key, 'sha256')

    cert_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_bytes = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    print(f"Generated certificate for {hostname} with serial number {unique_serial}")

    return cert_bytes, key_bytes


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
            self.shutdown_request(request)
        except Exception as e:
            print(f"Exception occurred while processing request: {e}")
            self.handle_error(request, client_address)
            self.shutdown_request(request)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        self.handle_tcp_connect()

    def handle_tcp_connect(self):
        hostname, port = self.path.split(':')
        print(f"Received CONNECT request for {hostname}:{port}")

        if port == '443':
            self.establish_tls_connection(hostname)
        else:
            self.send_error(400, "Only HTTPS connections are handled in CONNECT method.")
            return

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

            try:
                self.connection = context.wrap_socket(self.connection, server_side=True)
            except ssl.SSLError as ssl_error:
                print(f"SSL Error: {ssl_error} for hostname: {hostname}")
                self.send_error(502, "Bad Gateway")
                return

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
            print(f"Intercepted HTTPS request data: {request_data.decode('utf-8', errors='replace')[:100]}... [truncated]")

            response_status, response_headers, response_body = self.forward_request(request_data, True)

            self.send_response(response_status)
            print(response_status, response_headers)

            self.end_headers()

            if response_body:
                self.wfile.write(response_body)
                self.wfile.flush()

            self.wfile.flush()

        except Exception as e:
            print(f"Error handling HTTPS request: {e}")
            self.send_error(500)
            self.wfile.flush()

    def forward_request(self, request_data, is_https):
        try:
            request_line = request_data.split(b'\r\n', 1)[0].decode('utf-8')
            method, path, version = request_line.split()
            headers_start = request_data.split(b'\r\n\r\n', 1)[0].decode('utf-8', errors='replace')

            host = None
            for line in headers_start.split('\r\n'):
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break

            if not host:
                self.send_error(400, "Bad Request")
                return 400, [], b'Bad Request'

            port = 443 if is_https else 80
            url_scheme = "https" if is_https else "http"
            target_url = f"{url_scheme}://{host}{path}"

            session_info = self.get_or_create_session(host, port)

            headers = {
                "Host": host,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Priority": "u=0, i",
                "Sec-CH-UA": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"macOS"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
            }

            if method == "GET":
                response = session_info['session'].get(target_url, headers=headers, stream=True)
            elif method == "POST":
                body = request_data.split(b'\r\n\r\n', 1)[1]
                response = session_info['session'].post(target_url, data=body, headers=headers, stream=True)
            else:
                self.send_error(405, "Method Not Allowed")
                return 405, [], b'Method Not Allowed'

            response_status = response.status_code
            response_headers = [(k, v) for k, v in response.headers.items()]
            response_body = response.content

            session_info['last_used'] = time.time()

            return response_status, response_headers, response_body

        except Exception as e:
            print(f"Error forwarding request: {e}")
            return 500, {'Content-Type': 'text/plain'}, b'Internal Server Error'

    def get_or_create_session(self, host, port):
        global session_pool

        self.cleanup_expired_sessions()

        session_key = (host, port)
        session_info = session_pool[session_key]

        # Count only sessions for the current host:port pair
        if session_info['session'] is None or count_sessions_for_host(host, port) >= MAX_SESSIONS_PER_HOST:
            session_info['session'] = requests.Session()
            session_info['last_used'] = time.time()

        return session_info

    def cleanup_expired_sessions(self):
        current_time = time.time()

        for key, session_info in list(session_pool.items()):
            if current_time - session_info['last_used'] > CONNECTION_IDLE_TIMEOUT:
                print(f"Closing idle session for {key}")
                session_info['session'].close()
                del session_pool[key]

def count_sessions_for_host(host, port):
    """Count the number of active sessions for a specific host and port."""
    return sum(1 for (h, p), session_info in session_pool.items() if h == host and p == port)


def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    print("Starting proxy server on port 8080...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()
