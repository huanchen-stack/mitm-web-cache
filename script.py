from mitmproxy import http
from pymongo import MongoClient
from hashlib import sha256

from warcio.warcwriter import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders
from io import BytesIO
import gzip


# change collection name if need to
client = MongoClient('localhost', 27017)
db = client['mitm-web-cache']
collection = db['web_archive_org']


def hash_url(url):
    return sha256(url.encode('utf-8')).hexdigest()


def create_warc_record(flow: http.HTTPFlow) -> bytes:
    """Create a WARC record for the given response flow and return it as bytes."""

    # copy headers
    headers_list = [(k, v) for k, v in flow.response.headers.items()]
    status_and_headers = StatusAndHeaders(
        statusline=str(flow.response.status_code),
        headers=headers_list,
        protocol="HTTP/1.1"
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


def parse_warc_record(warc_record_bytes: bytes):
    """Parse WARC record to extract headers and body."""

    with gzip.open(BytesIO(warc_record_bytes), 'rb') as f:
        for record in ArchiveIterator(f):
            if record.rec_type == 'response':
                status_code = int(
                    record.http_headers.statusline.split()[-1])
                headers = {k: v for k, v in record.http_headers.headers}
                headers['server'] = 'mitm-cache'
                body = record.content_stream().read()
                return status_code, headers, body
    return None, None, None


def request(flow: http.HTTPFlow):
    """Look into database cache first, return cached content if HIT."""

    # now we only cache web.archive.org
    if True or "web.archive.org" in flow.request.pretty_url:
        url_hash = hash_url(flow.request.pretty_url)

        cached = collection.find_one({"_id": url_hash})
        if cached:
            status_code, headers, body = parse_warc_record(
                cached['warc_record'])
            flow.response = http.Response.make(
                status_code,
                body,
                headers
            )
            return  # now that flow has been changed, mitmproxy will not outbound the request


def response(flow: http.HTTPFlow):

    # no need to check cache first because if cache hit, won't be bypass cache
    if True or "web.archive.org" in flow.request.pretty_url:
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


addons = [
    request,
    response
]
