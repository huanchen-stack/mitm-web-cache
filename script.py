import threading
import gzip
from io import BytesIO
from warcio.statusandheaders import StatusAndHeaders
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter
from hashlib import sha256
from pymongo import MongoClient
from mitmproxy import http
import time


# Initialize a MongoDB client
client = MongoClient('localhost', 27017, maxPoolSize=1000)
db = client['mitm-web-cache']
collection = db['web_archive_org']


def hash_url(url):
    """Generate a hashed version of the URL using SHA256."""
    return sha256(url.encode('utf-8')[:min(len(url), 100)]).hexdigest()


def create_warc_record(flow: http.HTTPFlow) -> bytes:
    """Create a WARC record for the given response flow and return it as bytes."""
    
    headers_list = [(k, v) for k, v in flow.response.headers.items()]
    status_and_headers = StatusAndHeaders(
        statusline=str(flow.response.status_code),
        headers=headers_list,
        protocol="HTTP/2.0"
    )

    warc_bytes = BytesIO()
    warc_writer = WARCWriter(warc_bytes, gzip=True)

    record = warc_writer.create_warc_record(
        uri=flow.request.url,
        record_type='response',
        payload=BytesIO(flow.response.content),
        http_headers=status_and_headers
    )
    warc_writer.write_record(record)
    warc_bytes.seek(0)  # rewind to start

    return warc_bytes.read()


def parse_warc_record(warc_record_bytes: bytes):
    """Parse WARC record to extract headers and body."""
    
    with gzip.open(BytesIO(warc_record_bytes), 'rb') as f:
        for record in ArchiveIterator(f):
            if record.rec_type == 'response':
                status_code = int(record.http_headers.statusline.split()[-1])
                headers = {k: v for k, v in record.http_headers.headers}
                body = record.content_stream().read()
                return status_code, headers, body
    return None, None, None


def request(flow: http.HTTPFlow):
    """Check if the request has a cached response and return it if available."""
    
    url_hash = hash_url(flow.request.pretty_url)
    
    cached = collection.find_one({"_id": url_hash})
    if cached:
        status_code, headers, body = parse_warc_record(cached['warc_record'])
        if status_code:
            flow.response = http.Response.make(
                status_code,
                body,
                headers
            )
            return  # Response has been served from cache


def write_cache_sync(flow: http.HTTPFlow):
    """Cache the response in MongoDB."""
    
    url_hash = hash_url(flow.request.pretty_url)
    
    # Create and save WARC record
    warc_record_bytes = create_warc_record(flow)
    
    # Save WARC bytes and response metadata to MongoDB
    collection.update_one(
        {"_id": url_hash},  # Query filter: match document by _id
        {
            "$set": {
                "url": flow.request.pretty_url,
                "warc_record": warc_record_bytes  # Store the WARC record as binary data
            }
        },
        upsert=True  # Insert new document if not found
    )


def response(flow: http.HTTPFlow):
    """Handle the response and trigger caching asynchronously."""
    
    # Check if the response is served from cache, avoid caching it again
    if "mitm-cache" in flow.response.headers.get('server', ''):
        return

    # Write the response to cache in a separate thread
    threading.Thread(target=write_cache_sync, args=(flow,)).start()


# Addons array for mitmproxy
addons = [
    request,
    response,
]
