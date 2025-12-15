from simple_proxy.handler.socks5_proxy_channel_handler import (
    Socks5ProxyChannelHandler, get_local_peer_to_target_mapping, Socks5State,
)
from py_netty import EventLoopGroup
from simple_proxy.clients import get_clients
import pytest
# from unittest.mock import call

raddr = ('127.0.0.1', 8080)


@pytest.fixture(scope='function', autouse=False)
def ctx_mocker(mocker):
    return mocker.MagicMock()


class TestExceptionCaught:

    def test_exception_caught(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.exception_caught(ctx_mocker, Exception("test exception"))
        ctx_mocker.write.assert_called_with(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
        ctx_mocker.close.assert_called_once()


class TestChannelActive:

    def test_channel_active(self, mocker, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        local_socket_mocker = mocker.MagicMock()
        ctx_mocker.channel.return_value.socket.return_value = local_socket_mocker
        local_socket_mocker.getpeername.return_value = raddr
        get_clients().clear()
        handler.channel_active(ctx_mocker)
        assert raddr in get_clients()


class TestChannelInactive:

    def test_channel_inactive(self, mocker, ctx_mocker):
        mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.logger.isEnabledFor', return_value=True)
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
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


class TestTransformHostPort:

    def test_transform_host_port(self):
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


class TestChannelRead:

    def test_unsupported_version(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        with pytest.raises(ValueError, match=r"\[SOCKS5 Proxy\|Handshake\] Unsupported SOCKS version: 4"):
            handler.channel_read(ctx_mocker, b'\x04\x01\x00\x01')  # SOCKS version 4 is unsupported

    def test_handshake_without_auth(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        assert handler._socks5_state == Socks5State.HANDSHAKE
        handler.channel_read(ctx_mocker, b'\x05')
        handler.channel_read(ctx_mocker, b'\x01')
        handler.channel_read(ctx_mocker, b'\x00')
        ctx_mocker.write.assert_called_with(b'\x05\x00')  # No authentication
        assert handler._socks5_state == Socks5State.REQUEST

    def test_request_with_wrong_version(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=4"):
            handler.channel_read(ctx_mocker, b'\x04\x01\x00\x01')  # Wrong version

    def test_request_with_wrong_cmd(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=5, CMD=2"):
            handler.channel_read(ctx_mocker, b'\x05\x02\x00\x01')  # Wrong cmd

    def test_request_with_ipv6(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        with pytest.raises(ValueError, match=r"Unsupported address type: IPv6"):
            handler.channel_read(ctx_mocker, b'\x05\x01\x00\x04')

    def test_request_with_ipv4(self, mocker, ctx_mocker):
        mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        assert not handler._negotiated
        handler.channel_read(ctx_mocker, b'\x05\x01')
        handler.channel_read(ctx_mocker, b'\x00\x01')
        handler.channel_read(ctx_mocker, b'\x7f\x00\x00\x02')  # 127.0.0.2
        handler.channel_read(ctx_mocker, b'\x1f\x90')  # port 8080
        ctx_mocker.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
        assert handler._negotiated
        assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "127.0.0.2:8080"

    def test_request_with_ipv4_and_transform(self, mocker, ctx_mocker):
        mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ##
        handler = Socks5ProxyChannelHandler(
            EventLoopGroup(),
            transform=(('127.0.0.2', 8080, 'www.google.com', 9090),)
        )
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        assert not handler._negotiated
        handler.channel_read(ctx_mocker, b'\x05\x01')
        handler.channel_read(ctx_mocker, b'\x00\x01')
        handler.channel_read(ctx_mocker, b'\x7f\x00\x00\x02')  # 127.0.0.2
        handler.channel_read(ctx_mocker, b'\x1f\x90')  # port 8080
        ctx_mocker.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
        assert handler._negotiated
        assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "www.google.com:9090"

    def test_request_with_domain(self, mocker, ctx_mocker):
        mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        assert not handler._negotiated
        handler.channel_read(ctx_mocker, b'\x05\x01')
        handler.channel_read(ctx_mocker, b'\x00\x03')  # Domain type
        handler.channel_read(ctx_mocker, b'\x0a')  # Domain length 10
        handler.channel_read(ctx_mocker, b'ruanhao.cc')  # Domain
        handler.channel_read(ctx_mocker, b'\x1f\x90')  # port 8080
        ctx_mocker.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
        assert handler._negotiated
        assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "ruanhao.cc:8080"

    def test_request_with_unsupported_addr_type(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        handler.channel_read(ctx_mocker, b'\x05\x01\x00')
        ##
        handler.channel_read(ctx_mocker, b'\x05\x01')
        with pytest.raises(ValueError, match=r"Unsupported address type: 5"):
            handler.channel_read(ctx_mocker, b'\x00\x05')

    def test_without_providing_credential(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        with pytest.raises(ValueError, match="USERNAME/PASSWORD authentication required but not set by client"):
            handler.channel_read(ctx_mocker, b'\x05\x01\x00')

    def test_unsupported_auth_method(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup())
        with pytest.raises(ValueError, match="No acceptable authentication methods:"):
            handler.channel_read(ctx_mocker, b'\x05\x01\x05')

    def test_authentication(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication
        assert handler._socks5_state == Socks5State.AUTHENTICATION

    def test_authenticate_with_wrong_version(self, ctx_mocker):
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication
        ##
        with pytest.raises(ValueError, match=r"Unsupported Auth version: 5"):
            handler.channel_read(ctx_mocker, b'\x05\x00\x00')

    def test_authenticate_with_wrong_password(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        with pytest.raises(ValueError, match=r"Authentication failed: cisco/\*\*\*\*\*\*\*\*"):
            handler.channel_read(ctx_mocker, b'\x01\x05')  # Version 1
            handler.channel_read(ctx_mocker, b'cis')
            handler.channel_read(ctx_mocker, b'co')
            handler.channel_read(ctx_mocker, b'\x08')  # Password length
            handler.channel_read(ctx_mocker, b'wrongpwd')

    def test_authenticate_with_correct_password(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01')  # Version 1
        handler.channel_read(ctx_mocker, b'\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')
        assert handler._socks5_state == Socks5State.REQUEST

    def test_authenticate_with_unnecessary_password(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup())  # No username/password set
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01')  # Version 1
        handler.channel_read(ctx_mocker, b'\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')
        assert handler._socks5_state == Socks5State.REQUEST

    def test_authenticate_wrong_version_while_request(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')

        with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=4"):
            handler.channel_read(ctx_mocker, b'\x04\x01\x00\x01')  # Wrong version

    def test_authenticate_wrong_cmd_while_request(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')

        with pytest.raises(ValueError, match=r"Unsupported SOCKS5 request: VER=5, CMD=2"):
            handler.channel_read(ctx_mocker, b'\x05\x02\x00\x01')  # Wrong CMD

    def test_authenticate_while_request_ipv6(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')

        with pytest.raises(ValueError, match=r"Unsupported address type: IPv6"):
            handler.channel_read(ctx_mocker, b'\x05')
            handler.channel_read(ctx_mocker, b'\x01\x00\x04')  # IPv6 address type

    def test_authenticate_while_request_unsupported_addr_type(self, ctx_mocker):
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication
        handler.channel_read(ctx_mocker, b'\x01\x05')     # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')

        with pytest.raises(ValueError, match=r"Unsupported address type: 5"):
            handler.channel_read(ctx_mocker, b'\x05')
            handler.channel_read(ctx_mocker, b'\x01\x00\x05')

    def test_authenticate_while_request_ipv4(self, mocker, ctx_mocker):
        mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')

        handler.channel_read(ctx_mocker, b'\x05')
        handler.channel_read(ctx_mocker, b'\x01\x00\x01')  # IPv4 address type
        handler.channel_read(ctx_mocker, b'\x7f\x00\x00\x02')  # 127.0.0.2
        handler.channel_read(ctx_mocker, b'\x1f\x91')  # port 8081
        ctx_mocker.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "127.0.0.2:8081"
        assert handler._negotiated

    def test_authenticate_while_request_domain(self, mocker, ctx_mocker):
        mocker.patch('simple_proxy.handler.socks5_proxy_channel_handler.Bootstrap')
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        ctx_mocker.write.assert_called_with(b'\x05\x02')  # USERNAME/PASSWORD authentication

        handler.channel_read(ctx_mocker, b'\x01\x05')  # Version 1
        handler.channel_read(ctx_mocker, b'cis')
        handler.channel_read(ctx_mocker, b'co')
        handler.channel_read(ctx_mocker, b'\x07')  # Password length
        handler.channel_read(ctx_mocker, b'juniper')
        ctx_mocker.write.assert_called_with(b'\x01\x00')
        assert not handler._negotiated

        handler.channel_read(ctx_mocker, b'\x05')
        handler.channel_read(ctx_mocker, b'\x01\x00\x03')  # domain address type
        handler.channel_read(ctx_mocker, b'\x0a')  # domain length 9
        handler.channel_read(ctx_mocker, b'ruanhao.cc')  # domain
        handler.channel_read(ctx_mocker, b'\x1f\x92')  # port 8082
        ctx_mocker.write.assert_called_with(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        assert get_local_peer_to_target_mapping()["127.0.0.1:8080"] == "ruanhao.cc:8082"
        assert handler._negotiated

    def test_negotiated(self, mocker, ctx_mocker):
        client = mocker.MagicMock()
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        client.channelinfo.return_value.peername = ('8.8.8.8', 53)
        ##
        handler = Socks5ProxyChannelHandler(EventLoopGroup(), proxy_username="cisco", proxy_password="juniper")
        handler._negotiated = True
        handler._client = client
        handler.channel_read(ctx_mocker, b'\x05\x01\x02')
        client.write.assert_called_with(b'\x05\x01\x02')
        assert not handler._buffer
