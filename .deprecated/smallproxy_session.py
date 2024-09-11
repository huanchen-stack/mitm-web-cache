import os
import random
import ssl
import tempfile
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer

from OpenSSL import crypto
from concurrent.futures import ThreadPoolExecutor

CA_CERT_FILE = "mitmproxy-ca.pem"
CA_KEY_FILE = "mitmproxy-ca.pem"

MAX_WORKERS = 1  # between browser and proxy
CONNECTION_IDLE_TIMEOUT = 60  # between browser and proxy

def create_certificate(hostname):

    with open(CA_CERT_FILE, 'rt') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(CA_CERT_FILE, 'rt') as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "California"
    cert.get_subject().L = "Los Angeles"
    cert.get_subject().O = "NSL USC"
    cert.get_subject().CN = hostname

    unique_serial = int(time.time()) + random.randint(1, 100000)  # add rand to avoid same serial
    cert.set_serial_number(unique_serial)

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(100000)
    cert.set_issuer(ca_cert.get_subject())  # trusted proxy be the issuer
    cert.set_pubkey(key)

    san_list = [f"DNS:{hostname}"]
    san_extension = crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode())
    cert.add_extensions([san_extension])

    cert.sign(ca_key, 'sha256')  # same trusted proxy sign the key

    cert_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)  # avoid creating files
    key_bytes = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    print(f"Generated certificate for {hostname} with serial number {unique_serial}")

    return cert_bytes, key_bytes


class SessionManagingHTTPServer(HTTPServer):

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.connection_pool = defaultdict(lambda: {
            "connection": None,
            "last_used": time.time()
        })
        self.lock = threading.Lock()
        self.cleanup_thread = threading.Thread(target=self.cleanup_idle_sessions, daemon=True)
        self.cleanup_thread.start()

    def get_or_create_session(self, host, port, connection):
        key = (host, port)
        with self.lock:
            session = self.connection_pool[key]

            if session["connection"] is None or self.is_session_idle(session):
                session["connection"] = connection  # Store the actual socket connection
                session["last_used"] = time.time()
                print(f"Created or refreshed session for {host}:{port}.")

            return session["connection"]

    def is_session_idle(self, session):
        return (time.time() - session["last_used"]) > CONNECTION_IDLE_TIMEOUT

    def cleanup_idle_sessions(self):
        while True:
            time.sleep(CONNECTION_IDLE_TIMEOUT)
            with self.lock:
                for key, session in list(self.connection_pool.items()):
                    if self.is_session_idle(session):
                        print(f"Closing idle session for {key}")
                        session["connection"].close()  # Close the connection
                        del self.connection_pool[key]

    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception as e:
            self.handle_error(request, client_address)
            try:
                self.shutdown_request(request)
            except Exception as e:
                print(f"ERROR SHUTTING DOWN REQUEST: {e}")

class ProxyRequestHandler(BaseHTTPRequestHandler):

    def do_CONNECT(self):
        hostname, port = self.path.split(':')

        if port == "443":
            self.establish_tls_connection(hostname)
        else:
            self.send_error(500, "NOW ONLY SUPPORT HTTPS")
            return

        print("tranport layer connected!")

    def establish_tls_connection(self, hostname):
        cert_bytes, key_bytes = create_certificate(hostname)

        with tempfile.NamedTemporaryFile(delete=False) as cert_file:
            cert_file.write(cert_bytes)
            cert_file_path = cert_file.name

        with tempfile.NamedTemporaryFile(delete=False) as key_file:
            key_file.write(key_bytes)
            key_file_path = key_file.name

        self.send_response(200, "Connection Established")
        self.end_headers()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

        try:
            self.connection = context.wrap_socket(self.connection, server_side=True)

            self.rfile = self.connection.makefile('rb', buffering=0)
            self.wfile = self.connection.makefile('wb', buffering=0)
        except ssl.SSLError as e:
            print("SSL ERROR", e)
        except OSError as e:
            print("OS ERROR", e)

        finally:
            os.remove(cert_file_path)
            os.remove(key_file_path)

    def do_GET(self):
        self.handle_intercepted_request("GET")

    def do_POST(self):
        self.handle_intercepted_request("POST")

    def handle_intercepted_request(self, method):
        host = self.headers["HOST"]
        session = self.server.get_or_create_session(host, 443)  # Reuse session

        # For now, just printing that we're handling the request
        print(f"Intercepted {method} request to {host} using session {session}")

        # Here, you could send a forged response or print out the request for now
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"This is a forged response.\n")


def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ("localhost", 8080)
    httpd = server_class(server_address, handler_class)
    print("Starting smallproxy_session server on port 8080...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
