import re
import base64
from attrs import define, field


@define(slots=True, kw_only=True, order=True)
class ProxyInfo:

    host: str = field()
    port: int = field()
    username: str = field(default=None)
    password: str = field(default=None)


def parse_proxy_info(request_headers: str) -> ProxyInfo:
    # for CONNECT
    if request_headers.lower().startswith('connect'):  # https proxy
        match = re.search(r'CONNECT\s+([\w\.-]+):(\d+)\s+HTTP/.+\r\n', request_headers, re.IGNORECASE)
        if not match:
            raise ValueError("Invalid CONNECT request format")
        host, port = match.groups()
        port = int(port)
    else:                       # http proxy
        uri = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+http://([\w\.-]+)(:\d+)?/', request_headers, re.IGNORECASE | re.MULTILINE)
        if not uri:
            raise ValueError("Invalid HTTP request format")
        host = uri.group(2)
        port = int(uri.group(3)[1:]) if uri.group(3) else 80

    # for Proxy-Authorization
    auth_match = re.search(r'Proxy-Authorization:\s+Basic\s+([\w=+/]+)', request_headers, re.IGNORECASE)
    username, password = None, None
    if auth_match:
        try:
            auth_decoded = base64.b64decode(auth_match.group(1)).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid Proxy-Authorization format: {e}")
        username, password = auth_decoded.split(':', 1)

    return ProxyInfo(host=host, port=port, username=username, password=password)


def trim_proxy_info(request_headers_bytes: bytes) -> bytes:
    if not request_headers_bytes:
        return request_headers_bytes
    # trimmed = re.sub(b'Proxy-Connection: keep-alive\r\n', b'', request_headers_bytes, flags=re.IGNORECASE)
    # trimmed = re.sub(b'Proxy-Authorization: Basic [a-zA-Z0-9+/=]+\r\n', b'', trimmed, flags=re.IGNORECASE)
    trimmed = request_headers_bytes
    trimmed = re.sub(b'Proxy-.*\r\n', b'', trimmed, flags=re.IGNORECASE)
    # remove host in url line
    trimmed = re.sub(br'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+http://[\w\.-]+(:\d+)?/',
                     lambda m: m.group(1) + b' /', trimmed, flags=re.IGNORECASE | re.MULTILINE)
    return trimmed
