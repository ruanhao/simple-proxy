from simple_proxy.handler.echo_channel_handler import EchoChannelHandler
from py_netty import EventLoopGroup
from simple_proxy.clients import get_clients
import pytest


@pytest.fixture(scope='function', autouse=False)
def ctx_mocker(mocker):
    return mocker.MagicMock()


class TestChannelRead:

    def test_with_client(self, mocker, ctx_mocker):
        raddr = ('127.0.0.1', 8080)
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        handler = EchoChannelHandler(EventLoopGroup(), tls=False)

        client_mocker = mocker.MagicMock()
        get_clients()[raddr] = client_mocker
        handler.channel_read(ctx_mocker, b'123')
        ctx_mocker.channel().write.assert_called_once_with(b'123')
        client_mocker.read.assert_called_once_with(3)
        client_mocker.write.assert_called_once_with(3)

    def test_without_client(self, ctx_mocker):
        raddr = ('127.0.0.1', 8080)
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        handler = EchoChannelHandler(EventLoopGroup(), tls=False)

        get_clients().clear()
        handler.channel_read(ctx_mocker, b'123')
        assert ctx_mocker.channel.called
        ctx_mocker.channel().write.assert_called_once_with(b'123')

    def test_empty(self, ctx_mocker):
        raddr = ('127.0.0.1', 8080)
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr

        handler = EchoChannelHandler(EventLoopGroup(), tls=False)
        handler.channel_read(ctx_mocker, b'')
        assert not ctx_mocker.channel.called
