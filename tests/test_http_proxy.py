import pytest
from simple_proxy.utils import parse_proxy_info, trim_proxy_info


def test_parse_headers_case_common():
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


def test_parse_headers_case_lowercase():
    proxy_info = parse_proxy_info("""connect dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
proxy-authorization: basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert proxy_info.host == "dev.finditnm.com"
    assert proxy_info.port == 443
    assert proxy_info.username == "qiangwa3"
    assert proxy_info.password == "lallaa"


def test_parse_headers_case_no_connect():
    proxy_info = parse_proxy_info("""connec dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
proxy-authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert proxy_info.host == "dev.finditnm.com"
    assert proxy_info.port == 443


def test_parse_headers_case_wrong_base64():
    with pytest.raises(Exception) as e:
        parse_proxy_info("""connect dev.finditnm.com:443 HTTP/1.1\r\nHost: dev.finditnm.com:443\r\nproxy-authorization: Basic wrong\r\nUser-Agent: curl/8.7.1\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
    print(e)
    assert 'Invalid Proxy-Authorization' in str(e.value)


def test_parse_headers_case_http_proxy():
    parse_info = parse_proxy_info("""GET http://dev.finditnm.com/ HTTP/1.1\r\nHost: dev.finditnm.com\r\nProxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
    assert parse_info.host == "dev.finditnm.com"
    assert parse_info.port == 80
    assert parse_info.username == "qiangwa3"
    assert parse_info.password == "lallaa"


def test_parse_headers_case_http_proxy_with_port():
    parse_info = parse_proxy_info("""GET http://dev.finditnm.com:8080/ HTTP/1.1\r\nHost: dev.finditnm.com:8080\r\nProxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n""")
    assert parse_info.host == "dev.finditnm.com"
    assert parse_info.port == 8080
    assert parse_info.username == "qiangwa3"
    assert parse_info.password == "lallaa"


def test_trim_proxy_info():
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


if __name__ == "__main__":
    pytest.main()
