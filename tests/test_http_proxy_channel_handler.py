from simple_proxy.handler.http_proxy_channel_handler import HttpProxyChannelHandler, get_local_peer_to_target_mapping
from py_netty import EventLoopGroup
from simple_proxy.clients import get_clients
from simple_proxy.utils.proxyutils import ProxyInfo
import pytest

raddr = ('127.0.0.1', 8080)

def test_exception_caught(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    handler.exception_caught(ctx_mocker, Exception("test exception"))
    ctx_mocker.close.assert_called_once()


def test_channel_active(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    local_socket_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value = local_socket_mocker
    local_socket_mocker.getpeername.return_value = raddr
    get_clients().clear()
    handler.channel_active(ctx_mocker)
    assert raddr in get_clients()

    # verify debug log
    mocker.patch('simple_proxy.handler.http_proxy_channel_handler.logger.isEnabledFor', return_value=True)
    handler.channel_active(ctx_mocker)


def test_transform_host_port():
    assert HttpProxyChannelHandler(EventLoopGroup())._transform_host_port("example.com", 80) == ("example.com", 80)
    transform = (
        ('127.0.0.1', 8080, '127.0.0.2', 9090),
        ('www.baidu.com', 443, 'www.google.com', 443),
        ('www.baidu.com', 8080, '8.8.8.8', 9090),
    )
    handler = HttpProxyChannelHandler(EventLoopGroup(), transform=transform)
    assert handler._transform_host_port("127.0.0.1", 8080) == ("127.0.0.2", 9090)
    assert handler._transform_host_port("www.baidu.com", 443) == ("www.google.com", 443)
    assert handler._transform_host_port("www.baidu.com", 8080) == ("8.8.8.8", 9090)
    assert handler._transform_host_port("example.com", 80) == ("example.com", 80)


def test_channel_inactive(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.logger.isEnabledFor', return_value=True)
    handler = HttpProxyChannelHandler(EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    client_mocker = mocker.MagicMock()
    local_socket_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value = local_socket_mocker
    local_socket_mocker.getpeername.return_value = raddr
    handler._client = client_mocker
    ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr

    handler.channel_active(ctx_mocker)
    assert raddr in get_clients()
    handler.channel_inactive(ctx_mocker)
    client_mocker.close.assert_called_once()
    assert raddr not in get_clients()

def test_channel_read_case_negotiated(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup())
    ctx = mocker.MagicMock()
    client = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    client.channelinfo.return_value.peername = ('8.8.8.8', 53)
    handler._client = client
    handler._negotiated = True

    bytebuf = b'test data'
    handler.channel_read(ctx, bytebuf)
    client.write.assert_called_once_with(bytebuf)
    assert not handler._buffer

    # http case
    handler._http = True
    bytebuf = b"""GET http://10.74.107.166/api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Proxy-Connection: keep-alive\r
Cache-Control: no-cache\r\n\r\n"""
    expected_bytebuf = b"""GET /api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Cache-Control: no-cache\r\n\r\n"""
    handler.channel_read(ctx, bytebuf)
    client.write.assert_called_with(expected_bytebuf)
    assert not handler._buffer

def test_channel_read_case_parsing_proxy_info_failed(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup())
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ctx.channel.return_value.id.return_value.peername = "channel-1"
    mocker.patch('simple_proxy.handler.http_proxy_channel_handler.parse_proxy_info', side_effect=Exception("parsing failed"))
    with pytest.raises(ValueError, match="Parse proxy info failed"):
        handler.channel_read(ctx, b'test\r\n\r\n')
    ctx.write.assert_called_once_with(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')

def test_channel_read_case_credential_failed(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ctx.channel.return_value.id.return_value.peername = "channel-1"
    mocker.patch(
        'simple_proxy.handler.http_proxy_channel_handler.parse_proxy_info',
        return_value=ProxyInfo(
            host="10.74.107.166",
            port=80,
            username="wronguser",
            password="wrongpass"
        )
    )
    with pytest.raises(ValueError, match="Username or password error"):
        handler.channel_read(ctx, b'test\r\n\r\n')
    ctx.write.assert_called_once_with(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')


def test_channel_read_case_http_proxy(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ctx.channel.return_value.id.return_value.peername = "channel-1"
    mocker.patch(
        'simple_proxy.handler.http_proxy_channel_handler.parse_proxy_info',
        return_value=ProxyInfo(
            host="10.74.107.166",
            port=80,
            username="cisco",
            password="juniper"
        )
    )
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.http_proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker
    bytebuf = b"""GET http://10.74.107.166/api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Proxy-Connection: keep-alive\r
Pragma: no-cache\r
Cache-Control: no-cache\r\n\r\n"""
    expected_bytebuf = b"""GET /api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Pragma: no-cache\r
Cache-Control: no-cache\r\n\r\n"""
    assert not handler._http
    handler.channel_read(ctx, bytebuf)
    assert handler._http
    client_mocker.write.assert_called_once_with(expected_bytebuf)

def test_channel_read_case_https_proxy(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ctx.channel.return_value.id.return_value.peername = "channel-1"
    mocker.patch(
        'simple_proxy.handler.http_proxy_channel_handler.parse_proxy_info',
        return_value=ProxyInfo(
            host="dev.finditnm.com",
            port=443,
            username="cisco",
            password="juniper"
        )
    )
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.http_proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker
    bytebuf = b"""CONNECT dev.finditnm.com:443 KTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n"""
    handler.channel_read(ctx, bytebuf)
    assert not handler._http
    ctx.write.assert_called_once_with(b'HTTP/1.1 200 Connection Established\r\n\r\n')


def test_channel_read_case_https_proxy_with_transform(mocker):
    handler = HttpProxyChannelHandler(
        EventLoopGroup(), proxy_username="cisco", proxy_password="juniper",
        transform=(('dev.finditnm.com', 443, 'www.google.com', 8443),)
    )
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ctx.channel.return_value.id.return_value.peername = "channel-1"
    mocker.patch(
        'simple_proxy.handler.http_proxy_channel_handler.parse_proxy_info',
        return_value=ProxyInfo(
            host="dev.finditnm.com",
            port=443,
            username="cisco",
            password="juniper"
        )
    )
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.http_proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker
    bytebuf = b"""CONNECT dev.finditnm.com:443 KTTP/1.1\r\n
Host: dev.finditnm.com:443\r\n
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r\n
User-Agent: curl/8.7.1\r\n
Proxy-Connection: Keep-Alive\r\n\r\n"""
    handler.channel_read(ctx, bytebuf)
    assert not handler._http
    ctx.write.assert_called_once_with(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    assert get_local_peer_to_target_mapping()['127.0.0.1:8080'] == "www.google.com:8443"


def test_channel_read_case_not_enough_data():
    handler = HttpProxyChannelHandler(EventLoopGroup())
    handler.channel_read(None, b'\r\n')  # no exception
    assert handler._buffer == b'\r\n'


def test_channel_read_case_no_auth_required_but_providing(mocker):
    handler = HttpProxyChannelHandler(EventLoopGroup())
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ctx.channel.return_value.id.return_value.peername = "channel-1"
    mocker.patch(
        'simple_proxy.handler.http_proxy_channel_handler.parse_proxy_info',
        return_value=ProxyInfo(
            host="10.74.107.166",
            port=80,
            username="cisco",
            password="juniper"
        )
    )
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.http_proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker
    bytebuf = b"""GET http://10.74.107.166/api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Proxy-Connection: keep-alive\r
Proxy-Authorization: Basic cWlhbmd3YTM6bGFsbGFh\r
Pragma: no-cache\r
Cache-Control: no-cache\r\n\r\n"""
    expected_bytebuf = b"""GET /api/auth HTTP/1.1\r
Host: 10.74.107.166\r
Pragma: no-cache\r
Cache-Control: no-cache\r\n\r\n"""
    assert not handler._http
    handler.channel_read(ctx, bytebuf)
    assert handler._http
    client_mocker.write.assert_called_once_with(expected_bytebuf)