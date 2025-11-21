import pytest
from simple_proxy.utils import parse_proxy_info, trim_proxy_info

def test_parse_proxy_info_case_no_auth():
    proxy_info = parse_proxy_info("""CONNECT dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert proxy_info.host == "dev.finditnm.com"
    assert proxy_info.port == 443
    assert not proxy_info.username
    assert not proxy_info.password

def test_parse_proxy_info_case_common():
    proxy_info = parse_proxy_info("""CONNECT dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert proxy_info.host == "dev.finditnm.com"
    assert proxy_info.port == 443
    assert proxy_info.username == "qiangwa3"
    assert proxy_info.password == "lallaa"

    proxy_info = parse_proxy_info("""CONNECT dev-abc.finditnm-abc.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert proxy_info.host == "dev-abc.finditnm-abc.com"
    assert proxy_info.port == 443
    assert proxy_info.username == "qiangwa3"
    assert proxy_info.password == "lallaa"


def test_parse_proxy_info_case_lowercase():
    proxy_info = parse_proxy_info("""connect dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
proxy-authorization: basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert proxy_info.host == "dev.finditnm.com"
    assert proxy_info.port == 443
    assert proxy_info.username == "qiangwa3"
    assert proxy_info.password == "lallaa"


def test_parse_proxy_info_case_no_connect():
    with pytest.raises(ValueError, match="Invalid HTTP request format"):
        parse_proxy_info("""connec dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
proxy-authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")


def test_parse_proxy_info_case_wrong_base64():
    with pytest.raises(Exception) as e:
        parse_proxy_info("""connect dev.finditnm.com:443 HTTP/1.1\r\nHost: dev.finditnm.com:443\r\nproxy-authorization: Basic wrong\r\nUser-Agent: curl/8.7.1\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
    print(e)
    assert 'Invalid Proxy-Authorization' in str(e.value)


def test_parse_proxy_info_case_http_proxy():
    parse_info = parse_proxy_info("""GET http://dev.finditnm.com/ HTTP/1.1\r\nHost: dev.cbd-aws.com:443\r\nProxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
    assert parse_info.host == "dev.finditnm.com"
    assert parse_info.port == 80
    assert parse_info.username == "qiangwa3"
    assert parse_info.password == "lallaa"


def test_parse_proxy_info_case_http_proxy_with_port():
    parse_info = parse_proxy_info("""GET http://dev.finditnm.com:8080/ HTTP/1.1\r\nHost: dev.cbd-aws.com:8081\r\nProxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
    assert parse_info.host == "dev.finditnm.com"
    assert parse_info.port == 8080
    assert parse_info.username == "qiangwa3"
    assert parse_info.password == "lallaa"


def test_trim_proxy_info_case_uri():
    for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']:
        raw = f"""{method} http://dev.finditnm.com:8080/a/b/c HTTP/1.1\r
Host: dev.finditnm.com:8080\r
User-Agent: curl/8.7.1\r
Accept: */*\r
Proxy-Connection: Keep-Alive\r\n\r\n""".encode('utf-8')
        trimmed = trim_proxy_info(raw)
        trimmed_str = trimmed.decode('utf-8')
        assert f"{method} /a/b/c HTTP/1.1" in trimmed_str

    raw = b"""GET http://10.74.107.166/api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Proxy-Connection: keep-alive\r
Pragma: no-cache\r
Cache-Control: no-cache\r\n\r\n"""
    trimmed = trim_proxy_info(raw)
    trimmed_str = trimmed.decode('utf-8')
    assert "GET /api/auth HTTP/1.1" in trimmed_str
    assert "Proxy-Connection" not in trimmed_str



def test_trim_proxy_info_case_proxy_authentication():
    assert not trim_proxy_info(b'')
    raw = b"""GET http://dev.finditnm.com:8080/ HTTP/1.1\r
Host: dev.finditnm.com:8080\r
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r
User-Agent: curl/8.7.1\r
Accept: */*\r
Proxy-Connection: Keep-Alive\r\n\r\n"""
    trimmed = trim_proxy_info(raw)
    trimmed_str = trimmed.decode('utf-8')
    assert 'Proxy-' not in trimmed_str
    assert 'Host' in trimmed_str
    assert 'User-Agent' in trimmed_str
    assert 'Accept' in trimmed_str
    assert 'GET' in trimmed_str
    assert 'HTTP/1.1' in trimmed_str


def test_parse_proxy_info_case_connect_not_match():
    with pytest.raises(ValueError, match="Invalid CONNECT request format"):
        parse_proxy_info("""CONNECT dev.finditnm.com:443 KTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")


def test_parse_proxy_info_case_invalid_host_header():
    with pytest.raises(ValueError, match="Invalid HTTP request format"):
        parse_proxy_info("""GET http://dev.finditnm.com:https/ HTTP/1.1\r\nHost: dev.finditnm.com:8080\r\nProxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
