from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import os
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

# Set the number of concurrent threads (requests) you want to handle
MAX_WORKERS = 5


def create_certificate(hostname):
    """Generate a certificate and key for the given hostname."""
    # Load CA certificate and key
    with open(CA_CERT_FILE, "rt") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(CA_KEY_FILE, "rt") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Create a new key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a new certificate
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "MyOrganization"
    cert.get_subject().CN = hostname  # Set the hostname

    # Generate a unique serial number using the current time and a random number
    unique_serial = int(time.time() * 1000) + \
        random.SystemRandom().randint(1, 100000)
    cert.set_serial_number(unique_serial)

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year validity
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)

    # Add the Subject Alternative Name (SAN) extension
    san_list = [f"DNS:{hostname}"]
    san_extension = crypto.X509Extension(
        b"subjectAltName", False, ", ".join(san_list).encode())
    cert.add_extensions([san_extension])

    cert.sign(ca_key, 'sha256')

    # Dump the certificate and key to strings
    cert_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_bytes = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    # Log certificate details
    print(f"Generated certificate for {hostname} with serial number {unique_serial}")

    return cert_bytes, key_bytes


class ThreadedHTTPServer(HTTPServer):
    """Handle requests in a separate thread."""

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def process_request(self, request, client_address):
        """Start a new thread to process the request."""
        self.pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        """Process the request in a new thread."""
        try:
            self.finish_request(request, client_address)
            self.shutdown_request(request)
        except Exception as e:
            print(f"Exception occurred while processing request: {e}")
            self.handle_error(request, client_address)
            self.shutdown_request(request)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        """Handle HTTPS connections."""
        self.handle_tcp_connect()

    def handle_tcp_connect(self):
        """Intercept HTTPS connections and establish a TLS tunnel."""
        hostname, port = self.path.split(':')

        # Log detailed request information
        print(f"Received CONNECT request for {hostname}:{port}")

        if port == '443':
            self.establish_tls_connection(hostname)
        else:
            self.send_error(
                400, "Only HTTPS connections are handled in CONNECT method.")
            return

        self.handle_https_request()

    def establish_tls_connection(self, hostname):
        """Wrap the connection with TLS to intercept HTTPS traffic."""
        cert_bytes, key_bytes = create_certificate(hostname)

        # Use temporary files to store certificate and key for SSLContext
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
            context.load_cert_chain(
                certfile=cert_file_path, keyfile=key_file_path)

            try:
                self.connection = context.wrap_socket(
                    self.connection, server_side=True)
            except ssl.SSLError as ssl_error:
                print(f"SSL Error: {ssl_error} for hostname: {hostname}")
                self.send_error(502, "Bad Gateway")
                return

            self.rfile = self.connection.makefile('rb', buffering=0)
            self.wfile = self.connection.makefile('wb', buffering=0)

        finally:
            # Clean up temporary files
            os.remove(cert_file_path)
            os.remove(key_file_path)

    def do_GET(self):
        """Handle HTTP GET requests."""
        self.handle_http_request()

    def do_POST(self):
        """Handle HTTP POST requests."""
        self.handle_http_request()

    def handle_https_request(self):
        """Handle HTTPS requests after SSL connection setup."""
        try:
            request_data = self.rfile.read(65536)
            if not request_data:
                return
            print(f"Intercepted HTTPS request data: {request_data.decode('utf-8', errors='replace')[:100]}... [truncated]")

            # Forward the HTTPS request to the actual server
            response_status, response_headers, response_body = self.forward_request(request_data, True)

            # Send the server's response back to the client
            self.send_response(response_status)
            print(response_status, response_headers)

            # Safeguard unpacking of response headers
            for header_tuple in response_headers:
                if len(header_tuple) == 2:  # Check if the tuple has exactly two elements
                    header, value = header_tuple
                    if header.lower() not in ('content-length', 'transfer-encoding', 'connection'):
                        self.send_header(header, value)
                else:
                    print(f"Unexpected header format: {header_tuple}")  # Debug output

            self.end_headers()
            self.wfile.write(response_body)
            self.wfile.flush()  # Ensure all data is sent
        except Exception as e:
            print(f"Error handling HTTPS request: {e}")
            self.send_error(500)
            self.wfile.flush()

    def handle_http_request(self):
        """Handle HTTP requests."""
        try:
            request_data = self.rfile.read(65536)
            print(f"Intercepted HTTP request data: {request_data.decode('utf-8', errors='replace')[:50]}... [truncated]")

            # Forward the HTTP request to the actual server
            response_status, response_headers, response_body = self.forward_request(request_data, False)

            # Send the server's response back to the client
            self.send_response(response_status)
            for header, value in response_headers:
                if header.lower() not in ('content-length', 'transfer-encoding', 'connection'):
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response_body)
            self.wfile.flush()  # Ensure all data is sent
        except Exception as e:
            print(f"Error handling HTTP request: {e}")
            self.send_error(500)
            self.wfile.flush()

    def forward_request(self, request_data, is_https):
        """Forward the HTTP/HTTPS request to the actual server and return the response."""
        try:
            request_line = request_data.split(b'\r\n', 1)[0].decode('utf-8')
            print(
                "----------------------------------------------------------------", request_line)
            method, path, version = request_line.split()
            headers_start = request_data.split(b'\r\n\r\n', 1)[
                0].decode('utf-8', errors='replace')
            print(f"Forwarding request with headers:\n{headers_start}")

            # Extract host from headers
            host = None
            for line in headers_start.split('\r\n'):
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break

            if not host:
                print("Could not determine host from headers.")
                self.send_error(400, "Bad Request")
                return 400, [], b'Bad Request'

            port = 443 if is_https else 80

            conn_class = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
            conn = conn_class(host, port)

            # Create headers including Host and User-Agent
            headers = {
                "Host": host,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "en-US,en;q=0.9",
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

            # Print debug information
            print(f"Forwarding request: {method} {path}, Host: {host}, Port: {port}")

            # Forward the request to the actual server
            conn.request(method, path, headers=headers)

            # Get the response from the server
            response = conn.getresponse()
            response_status = response.status
            response_headers = response.getheaders()
            response_body = response.read()
            print(response_status, response_headers)

            conn.close()

            return response_status, response_headers, response_body

        except Exception as e:
            print(f"Error forwarding request: {e}")
            return 500, {'Content-Type': 'text/plain'}, b'Internal Server Error'




def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    print("Starting proxy server on port 8080...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()