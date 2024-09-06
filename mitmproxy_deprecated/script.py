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
import random
import os
from mitmproxy import ctx, http


TMAP = {}
CSSMAP = {}

# change collection name if need to
client = MongoClient('localhost', 27017, maxPoolSize=1000)
db = client['mitm-web-cache']
collection = db['web_archive_org']


def hash_url(url):
    return sha256(url.encode('utf-8')[:min(len(url), 100)]).hexdigest()


def create_warc_record(flow: http.HTTPFlow) -> bytes:
    """Create a WARC record for the given response flow and return it as bytes."""

    # copy headers
    headers_list = [(k, v) for k, v in flow.response.headers.items()]
    status_and_headers = StatusAndHeaders(
        statusline=str(flow.response.status_code),
        headers=headers_list,
        protocol="HTTP/2.0"
    )

    # create byte stream
    warc_bytes = BytesIO()
    warc_writer = WARCWriter(warc_bytes, gzip=True)

    # create warc = headers + body
    record = warc_writer.create_warc_record(
        uri=flow.request.url,
        record_type='response',
        payload=BytesIO(flow.response.content),
        http_headers=status_and_headers
    )
    warc_writer.write_record(record)
    warc_bytes.seek(0)  # rewind to start

    return warc_bytes.read()


def parse_warc_record(warc_record_bytes: bytes, url_hash):
    """Parse WARC record to extract headers and body."""

    with gzip.open(BytesIO(warc_record_bytes), 'rb') as f:
        for record in ArchiveIterator(f):
            if record.rec_type == 'response':
                status_code = int(
                    record.http_headers.statusline.split()[-1])
                headers = {k: v for k, v in record.http_headers.headers}
                headers['server'] = 'mitm-cache ' + \
                    str(time.time()-TMAP[url_hash])[:5]
                body = record.content_stream().read()
                return status_code, headers, body
    return None, None, None


def request(flow: http.HTTPFlow):
    """Look into database cache first, return cached content if HIT."""

    # now we only cache web.archive.org
    # if True or "web.archive.org" in flow.request.pretty_url:
    url_hash = hash_url(flow.request.pretty_url)

    TMAP[url_hash] = time.time()

    # return
    cached = collection.find_one({"_id": url_hash})
    if cached:
        status_code, headers, body = parse_warc_record(
            cached['warc_record'], url_hash)
        if status_code == 200 and "https://fonts.googleapis.com/css2" in cached['url']:
            CSSMAP[url_hash] = 1
            # body = os.urandom(len(body)*2)
            body = caesar_cipher_encrypt(
                body.decode('utf-8'), 10).encode('utf-8')
        flow.response = http.Response.make(
            status_code,
            body,
            headers
        )
        # time.sleep(random.random * 0.1)
        return  # now that flow has been changed, mitmproxy will not outbound the request


def write_cache_sync(flow: http.HTTPFlow):
    # no need to check cache first because if cache hit, won't be bypass cache
    # if True or "web.archive.org" in flow.request.pretty_url:
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
        upsert=True  # If no document matches the filter, insert a new one
    )


CSSSTR = CSSSTR.encode('utf-8')


def response(flow: http.HTTPFlow):

    if "mitm-cache" in flow.response.headers.get('server'):
        url_hash = hash_url(flow.request.pretty_url)
        if url_hash in CSSMAP:
            # body = caesar_cipher_decrypt(
            #     body.decode('utf-8'), 10).encode('utf-8')
            # flow.response.content = CSSSTR
            # flow.response.content = os.urandom(len(flow.response.content))
            pass
        return

    threading.Thread(target=write_cache_sync, args=(flow,)).start()


addons = [
    request,
    response,
]
