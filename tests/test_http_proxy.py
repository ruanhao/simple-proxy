import pytest
from simple_proxy.utils import parse_proxy_info


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
        parse_proxy_info("""connect dev.finditnm.com:443 HTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
proxy-authorization: Basic wrong\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    print(e)
    assert 'Invalid Proxy-Authorization' in str(e.value)


def test_parse_headers_case_http_proxy():
    parse_info = parse_proxy_info("""GET http://dev.finditnm.com/ HTTP/1.1\r\n
Host: dev.finditnm.com\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Accept: */*\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert parse_info.host == "dev.finditnm.com"
    assert parse_info.port == 80
    assert parse_info.username == "qiangwa3"
    assert parse_info.password == "lallaa"


def test_parse_headers_case_http_proxy_with_port():
    parse_info = parse_proxy_info("""GET http://dev.finditnm.com:8080/ HTTP/1.1\r\n
Host: dev.finditnm.com:8080\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Accept: */*\r\n
Proxy-Connection: Keep-Alive\r\n\r\n""")
    assert parse_info.host == "dev.finditnm.com"
    assert parse_info.port == 8080
    assert parse_info.username == "qiangwa3"
    assert parse_info.password == "lallaa"


if __name__ == "__main__":
    pytest.main()
