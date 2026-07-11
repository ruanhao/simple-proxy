import re
import base64
from urllib.parse import urlsplit
from attrs import define, field


@define(slots=True, kw_only=True, order=True)
class ProxyInfo:

    host: str = field()
    port: int = field()
    username: str = field(default=None)
    password: str = field(default=None)


def _parse_authority(authority: str, default_port: int | None = None) -> tuple[str, int]:
    if authority.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::(\d+))?', authority)
        if not match:
            raise ValueError("Invalid authority format")
        host, port = match.groups()
    else:
        if authority.count(':') > 1:
            raise ValueError("IPv6 address must be enclosed in brackets")
        if ':' in authority:
            host, port = authority.rsplit(':', 1)
        else:
            host, port = authority, None
    if not host:
        raise ValueError("Invalid authority host")
    if port is None:
        if default_port is None:
            raise ValueError("Missing authority port")
        return host, default_port
    return host, int(port)


def parse_proxy_info(request_headers: str) -> ProxyInfo:
    # for CONNECT
    if request_headers.lower().startswith('connect'):  # https proxy
        match = re.search(r'^CONNECT\s+(\S+)\s+HTTP/.+\r\n', request_headers, re.IGNORECASE)
        if not match:
            raise ValueError("Invalid CONNECT request format")
        try:
            host, port = _parse_authority(match.group(1))
        except Exception as e:
            raise ValueError("Invalid CONNECT request format") from e
    else:                       # http proxy
        match = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+(\S+)\s+HTTP/.+\r\n', request_headers, re.IGNORECASE | re.MULTILINE)
        if not match:
            raise ValueError("Invalid HTTP request format")
        try:
            uri = urlsplit(match.group(2))
            if uri.scheme.lower() != 'http' or not uri.netloc or not uri.hostname:
                raise ValueError("Invalid HTTP request URI")
            host = uri.hostname
            port = uri.port or 80
        except Exception as e:
            raise ValueError("Invalid HTTP request format") from e

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
    lines = trimmed.split(b'\r\n', 1)
    parts = lines[0].split(maxsplit=2)
    if len(parts) == 3 and parts[1].lower().startswith(b'http://'):
        try:
            uri = urlsplit(parts[1].decode('ascii'))
            path = uri.path or '/'
            if uri.query:
                path += '?' + uri.query
            parts[1] = path.encode('ascii')
            lines[0] = b' '.join(parts)
            trimmed = b'\r\n'.join(lines)
        except Exception:
            pass
    return trimmed
