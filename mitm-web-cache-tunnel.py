import os
import ssl
import socket
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import io
from hashlib import sha256
from pymongo import MongoClient
from OpenSSL import crypto
import time
import random
from concurrent.futures import ThreadPoolExecutor

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
MAX_WORKERS = 100

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
            try:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            except Exception as e:
                print(e, flush=True)
                #TODO: shutdown_request sometimes gives me error due to closed sockets 
                pass

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.handle_https_request()

    def do_CONNECT(self):
        self.port = "443"
        l_ = self.path.split(':')
        if len(l_) > 1:
            port = l_[1]
        self.hostname = l_[0]
        if self.port == '443':
            self.establish_tls_connection()
        else:
            self.send_error(400, "Only HTTPS connections are handled in CONNECT method.")
            return
        
        while True:
            self.handle_https_request()
            break

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

            # self.rfile = self.connection.makefile('rb', buffering=0)
            # self.wfile = self.connection.makefile('wb', buffering=0)

        finally:
            os.remove(cert_file_path)
            os.remove(key_file_path)

    def handle_https_request(self):
        try:
            sock = socket.create_connection((self.hostname, 443))
            ssl_context = ssl.create_default_context()
            sock = ssl_context.wrap_socket(sock, server_hostname=self.hostname)

            # Start threads to forward data in both directions
            request_url = []
            response_bytes = io.BytesIO()
            client_to_target = threading.Thread(target=self.forward_client_to_target, args=(self.connection, sock, request_url))
            target_to_client = threading.Thread(target=self.forward_target_to_client, args=(sock, self.connection, response_bytes))
            client_to_target.start()
            target_to_client.start()
            client_to_target.join()
            target_to_client.join()

        except Exception as e:
            print(f"Error handling HTTPS request: {e}", flush=True)
            self.send_error(502, "Bad Gateway")

    @staticmethod
    def forward_client_to_target(client_sock, target_sock, request_url):
        print("Started forwarding client to target", flush=True)
        try:
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                target_sock.sendall(data)
                request_url.append(data)

        except Exception as e:
            print(f"Error forwarding data from client to target: {e}", flush=True)
        finally:
            client_sock.close()
            target_sock.close()

    @staticmethod
    def forward_target_to_client(target_sock, client_sock, response_bytes):
        print("Started forwarding target to client", flush=True)
        try:
            while True:
                data = target_sock.recv(4096)
                if not data:
                    break
                client_sock.sendall(data)
                response_bytes.write(data)

        except Exception as e:
            print(f"Error forwarding data from target to client: {e}", flush=True)
        finally:
            target_sock.close()
            client_sock.close()

def run(server_class=ThreadedHTTPServer, handler_class=ProxyRequestHandler):
    server_address = ('localhost', 8080)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == "__main__":
    run()