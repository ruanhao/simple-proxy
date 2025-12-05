from simple_proxy.handler.socks5_proxy_channel_handler import (
    Socks5ProxyChannelHandler, get_local_peer_to_target_mapping, Socks5State,
)
from py_netty import EventLoopGroup
from simple_proxy.clients import get_clients
import pytest
# from unittest.mock import call

raddr = ('127.0.0.1', 8080)

def test_exception_caught(mocker):
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    handler.exception_caught(ctx_mocker, Exception("test exception"))
    ctx_mocker.write.assert_called_with(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
    ctx_mocker.close.assert_called_once()

def test_channel_active(mocker):
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    local_socket_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value = local_socket_mocker
    local_socket_mocker.getpeername.return_value = raddr
    get_clients().clear()
    handler.channel_active(ctx_mocker)
    assert raddr in get_clients()


def test_channel_inactive(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.logger.isEnabledFor', return_value=True)
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
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


def test_transform_host_port():
    assert Socks5ProxyChannelHandler(EventLoopGroup())._transform_host_port("example.com", 80) == ("example.com", 80)
    transform = (
        ('127.0.0.1', 8080, '127.0.0.2', 9090),
        ('www.baidu.com', 443, 'www.google.com', 443),
        ('www.baidu.com', 8080, '8.8.8.8', 9090),
    )
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), transform=transform)
    assert handler._transform_host_port("127.0.0.1", 8080) == ("127.0.0.2", 9090)
    assert handler._transform_host_port("www.baidu.com", 443) == ("www.google.com", 443)
    assert handler._transform_host_port("www.baidu.com", 8080) == ("8.8.8.8", 9090)
    assert handler._transform_host_port("example.com", 80) == ("example.com", 80)


def test_channel_read_case_unsupported_version(mocker):
    ctx = mocker.MagicMock()
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    with pytest.raises(ValueError, match=r"\[SOCKS5 Proxy\|Handshake\] Unsupported SOCKS version: 4"):
        handler.channel_read(ctx, b'\x04\x01\x00\x01')  # SOCKS version 4 is unsupported

def test_channel_read_case_handshake_without_auth(mocker):
    ctx = mocker.MagicMock()
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    assert handler._socks5_state == Socks5State.HANDSHAKE
    handler.channel_read(ctx, b'\x05')
    handler.channel_read(ctx, b'\x01')
    handler.channel_read(ctx, b'\x00')
    ctx.write.assert_called_with(b'\x05\x00')  # No authentication
    assert handler._socks5_state == Socks5State.REQUEST

def test_channel_read_case_request_with_wrong_version(mocker):
    ctx = mocker.MagicMock()
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=4"):
        handler.channel_read(ctx, b'\x04\x01\x00\x01')  # Wrong version

def test_channel_read_case_request_with_wrong_cmd(mocker):
    ctx = mocker.MagicMock()
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=5, CMD=2"):
        handler.channel_read(ctx, b'\x05\x02\x00\x01')  # Wrong cmd


def test_channel_read_case_request_with_ipv6(mocker):
    ctx = mocker.MagicMock()
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    with pytest.raises(ValueError, match=r"Unsupported address type: IPv6"):
        handler.channel_read(ctx, b'\x05\x01\x00\x04')


def test_channel_read_case_request_with_ipv4(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    assert not handler._negotiated
    handler.channel_read(ctx, b'\x05\x01')
    handler.channel_read(ctx, b'\x00\x01')
    handler.channel_read(ctx, b'\x7f\x00\x00\x02')  # 127.0.0.2
    handler.channel_read(ctx, b'\x1f\x90')  # port 8080
    ctx.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
    assert handler._negotiated
    assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "127.0.0.2:8080"


def test_channel_read_case_request_with_ipv4_and_transform(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ##
    handler = Socks5ProxyChannelHandler(
        EventLoopGroup(),
        transform=(('127.0.0.2', 8080, 'www.google.com', 9090),)
    )
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    assert not handler._negotiated
    handler.channel_read(ctx, b'\x05\x01')
    handler.channel_read(ctx, b'\x00\x01')
    handler.channel_read(ctx, b'\x7f\x00\x00\x02')  # 127.0.0.2
    handler.channel_read(ctx, b'\x1f\x90')  # port 8080
    ctx.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
    assert handler._negotiated
    assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "www.google.com:9090"


def test_channel_read_case_request_with_domain(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    assert not handler._negotiated
    handler.channel_read(ctx, b'\x05\x01')
    handler.channel_read(ctx, b'\x00\x03')  # Domain type
    handler.channel_read(ctx, b'\x0a')  # Domain length 10
    handler.channel_read(ctx, b'ruanhao.cc')  # Domain
    handler.channel_read(ctx, b'\x1f\x90')  # port 8080
    ctx.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
    assert handler._negotiated
    assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "ruanhao.cc:8080"


def test_channel_read_case_request_with_unsupported_addr_type(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    handler.channel_read(ctx, b'\x05\x01\x00')
    ##
    handler.channel_read(ctx, b'\x05\x01')
    with pytest.raises(ValueError, match=r"Unsupported address type: 5"):
        handler.channel_read(ctx, b'\x00\x05')



def test_channel_read_case_without_providing_credential(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    with pytest.raises(ValueError, match="USERNAME/PASSWORD authentication required but not set by client"):
        handler.channel_read(ctx, b'\x05\x01\x00')

def test_channel_read_case_unsupported_auth_method(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup())
    with pytest.raises(ValueError, match="No acceptable authentication methods:"):
        handler.channel_read(ctx, b'\x05\x01\x05')


def test_channel_read_case_authentication(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication
    assert handler._socks5_state == Socks5State.AUTHENTICATION


def test_channel_read_case_authenticate_with_wrong_version(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication
    ##
    with pytest.raises(ValueError, match=r"Unsupported Auth version: 5"):
        handler.channel_read(ctx, b'\x05\x00\x00')


def test_channel_read_case_authenticate_with_wrong_password(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    with pytest.raises(ValueError, match=r"Authentication failed: cisco/\*\*\*\*\*\*\*\*"):
        handler.channel_read(ctx, b'\x01\x05') # Version 1
        handler.channel_read(ctx, b'cis')
        handler.channel_read(ctx, b'co')
        handler.channel_read(ctx, b'\x08') # Password length
        handler.channel_read(ctx, b'wrongpwd')


def test_channel_read_case_authenticate_with_correct_password(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01') # Version 1
    handler.channel_read(ctx, b'\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')
    assert handler._socks5_state == Socks5State.REQUEST


def test_channel_read_case_authenticate_with_unnecessary_password(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup())  # No username/password set
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01') # Version 1
    handler.channel_read(ctx, b'\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')
    assert handler._socks5_state == Socks5State.REQUEST


def test_channel_read_case_authenticate_wrong_version_while_request(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')

    with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=4"):
        handler.channel_read(ctx, b'\x04\x01\x00\x01')  # Wrong version

def test_channel_read_case_authenticate_wrong_cmd_while_request(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')

    with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=5, CMD=2"):
        handler.channel_read(ctx, b'\x05\x02\x00\x01')  # Wrong CMD


def test_channel_read_case_authenticate_while_request_ipv6(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')

    with pytest.raises(ValueError, match=r"Unsupported address type: IPv6"):
        handler.channel_read(ctx, b'\x05')
        handler.channel_read(ctx, b'\x01\x00\x04')  # IPv6 address type

def test_channel_read_case_authenticate_while_request_unsupported_addr_type(mocker):
    ctx = mocker.MagicMock()
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication
    handler.channel_read(ctx, b'\x01\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')

    with pytest.raises(ValueError, match=r"Unsupported address type: 5"):
        handler.channel_read(ctx, b'\x05')
        handler.channel_read(ctx, b'\x01\x00\x05')

def test_channel_read_case_authenticate_while_request_ipv4(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')

    handler.channel_read(ctx, b'\x05')
    handler.channel_read(ctx, b'\x01\x00\x01')  # IPv4 address type
    handler.channel_read(ctx, b'\x7f\x00\x00\x02')  # 127.0.0.2
    handler.channel_read(ctx, b'\x1f\x91')  # port 8081
    ctx.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "127.0.0.2:8081"
    assert handler._negotiated


def test_channel_read_case_authenticate_while_request_domain(mocker):
    mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler.channel_read(ctx, b'\x05\x01\x02')
    ctx.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

    handler.channel_read(ctx, b'\x01\x05') # Version 1
    handler.channel_read(ctx, b'cis')
    handler.channel_read(ctx, b'co')
    handler.channel_read(ctx, b'\x07') # Password length
    handler.channel_read(ctx, b'juniper')
    ctx.write.assert_called_with(b'\x01\x00')
    assert not handler._negotiated

    handler.channel_read(ctx, b'\x05')
    handler.channel_read(ctx, b'\x01\x00\x03')  # domain address type
    handler.channel_read(ctx, b'\x0a')  # domain length 9
    handler.channel_read(ctx, b'ruanhao.cc')  # domain
    handler.channel_read(ctx, b'\x1f\x92')  # port 8082
    ctx.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "ruanhao.cc:8082"
    assert handler._negotiated


def test_channel_read_case_negotiated(mocker):
    client = mocker.MagicMock()
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = raddr
    client.channelinfo.return_value.peername = ('8.8.8.8', 53)
    ##
    handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
    handler._negotiated = True
    handler._client = client
    handler.channel_read(ctx, b'\x05\x01\x02')
    client.write.assert_called_with(b'\x05\x01\x02')
    assert not handler._buffer

