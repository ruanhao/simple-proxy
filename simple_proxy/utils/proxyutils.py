import re
import base64
from attrs import define, field


@define(slots=True, kw_only=True, order=True)
class ProxyInfo():

    host: str = field()
    port: int = field()
    username: str = field(default=None)
    password: str = field(default=None)


def parse_proxy_info(request_headers: str) -> ProxyInfo:
    # for CONNECT
    if request_headers.startswith('CONNECT'):  # https proxy
        match = re.search(r'CONNECT\s+([\w\.-]+):(\d+)\s+HTTP/.+\r\n', request_headers, re.IGNORECASE)
        if not match:
            raise ValueError("Invalid CONNECT request format")
        host, port = match.groups()
        port = int(port)
    else:                       # http proxy
        match_with_port = re.search(r'Host:\s+([\w\.-]+):(\d+)\r\n', request_headers, re.IGNORECASE)
        match_without_port = re.search(r'Host:\s+([\w\.-]+)\r\n', request_headers, re.IGNORECASE)
        if match_with_port:
            host, port = match_with_port.groups()
            port = int(port)
        elif match_without_port:
            host = match_without_port.group(1)
            port = 80
        else:
            raise ValueError("Invalid Host header format")

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
    return trimmed
