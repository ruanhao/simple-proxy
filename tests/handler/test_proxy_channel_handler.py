import time
import pytest
from simple_proxy.handler.proxy_channel_handler import ProxyChannelHandler
from py_netty import EventLoopGroup
from simple_proxy.clients import get_clients


raddr = ('127.0.0.1', 8080)


@pytest.fixture(scope='function', autouse=False)
def ctx_mocker(mocker):
    return mocker.MagicMock()


class TestExceptionCaught:

    def test_exception_caught(self, ctx_mocker):
        handler = ProxyChannelHandler("1.2.3.4", 9090, EventLoopGroup())
        handler.exception_caught(ctx_mocker, Exception("test exception"))
        ctx_mocker.close.assert_called_once()


class TestChannelActive:

    def test_channel_active(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1"
        )
        local_socket_mocker = mocker.MagicMock()
        ctx_mocker.channel.return_value.socket.return_value = local_socket_mocker
        local_socket_mocker.getpeername.return_value = raddr
        get_clients().clear()
        handler.channel_active(ctx_mocker)
        assert raddr in get_clients()


class TestCreateClient:

    def test_already_exists(self, mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
        )
        handler._client = mocker.MagicMock()
        handler._create_client(None, None)  # no exception should be raised

    def test_disguise_and_wait_for_traffic(self, mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1",
        )
        handler._client = mocker.MagicMock()
        handler._create_client(None, None)  # no exception should be raised

    def test_non_whitelist_with_disguise(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1",
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        client_mocker = mocker.MagicMock()
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
        BoostrapMocker = mocker.patch(  # noqa
            'simple_proxy.handler.proxy_channel_handler.Bootstrap'
        )
        BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

        handler._create_client(ctx_mocker, b'\x16\x03\x01')
        assert BoostrapMocker().connect.call_args[0] == ("4.3.2.1", 443, True, None)
        assert handler._client is client_mocker

    def test_non_whitelist_with_disguise_but_not_tls(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1",
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        client_mocker = mocker.MagicMock()
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
        BoostrapMocker = mocker.patch(  # noqa
            'simple_proxy.handler.proxy_channel_handler.Bootstrap'
        )
        BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

        handler._create_client(ctx_mocker, b'\x15\x03\x01')
        assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True, None)
        assert handler._client is client_mocker

    def test_not_allowed_with_disguise(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1", white_list=["10.0.0.*"],
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        client_mocker = mocker.MagicMock()
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
        BoostrapMocker = mocker.patch(  # noqa
            'simple_proxy.handler.proxy_channel_handler.Bootstrap'
        )
        BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

        handler._create_client(ctx_mocker, b'\x16\x03\x01')
        assert BoostrapMocker().connect.call_args[0] == ("4.3.2.1", 443, True, None)
        assert handler._client is client_mocker

    def test_not_allowed(self, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            white_list=["10.0.0.*"],
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        handler._create_client(ctx_mocker, b'\x16\x03\x01')
        ctx_mocker.close.assert_called_once()
        assert handler._abort

    def test_allowed(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1", white_list=["10.1.0.*"],
            sni="www.google.com"
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        client_mocker = mocker.MagicMock()
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
        BoostrapMocker = mocker.patch(  # noqa
            'simple_proxy.handler.proxy_channel_handler.Bootstrap'
        )
        BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

        handler._create_client(ctx_mocker, b'\x16\x03\x01')
        assert handler._client is client_mocker
        assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True, "www.google.com")

    def test_allowed_while_need_disguise_but_not_tls(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
            disguise_tls_ip="4.3.2.1", white_list=["10.1.0.*"],
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        client_mocker = mocker.MagicMock()
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
        BoostrapMocker = mocker.patch(  # noqa
            'simple_proxy.handler.proxy_channel_handler.Bootstrap'
        )
        BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

        handler._create_client(ctx_mocker, b'\x15\x03\x01')
        assert handler._client is client_mocker
        assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True, None)

    def test_no_wl_and_disguise_configured(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 9090, EventLoopGroup(),
        )
        ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        client_mocker = mocker.MagicMock()
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
        BoostrapMocker = mocker.patch(  # noqa
            'simple_proxy.handler.proxy_channel_handler.Bootstrap'
        )
        BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

        handler._create_client(ctx_mocker, None)  # channel active
        assert handler._client is client_mocker
        assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True, None)


class TestChannelInactive:

    def test_channel_inactive(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler("1.2.3.4", 8080, EventLoopGroup())
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


class TestChannelWritabilityChanged:

    def test_channel_writability_changed(self, mocker, ctx_mocker):
        client_mocker = mocker.MagicMock()
        handler = ProxyChannelHandler("1.2.3.4", 8080, EventLoopGroup())
        handler._client = client_mocker

        ctx_mocker.channel.return_value.is_writable.return_value = False
        handler.channel_writability_changed(ctx_mocker)
        client_mocker.set_auto_read.assert_called_with(False)

        ctx_mocker.channel.return_value.is_writable.return_value = True
        handler.channel_writability_changed(ctx_mocker)
        client_mocker.set_auto_read.assert_called_with(True)


class TestChannelRead:

    def test_no_delay(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler("1.2.3.4", 8080, EventLoopGroup())
        client_mocker = mocker.MagicMock()
        handler._client = client_mocker
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = ("10.1.0.1", 12345)
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)

        now = time.time()
        handler.channel_read(ctx_mocker, b'test data')
        assert time.time() - now < 0.5  # no delay
        client_mocker.write.assert_called_once_with(b'test data')

    def test_channel_read_case_write_delay(self, mocker, ctx_mocker):
        handler = ProxyChannelHandler(
            "1.2.3.4", 8080, EventLoopGroup(),
            write_delay_millis=1000,
        )
        client_mocker = mocker.MagicMock()
        handler._client = client_mocker
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = ("10.1.0.1", 12345)
        client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)

        now = time.time()
        handler.channel_read(ctx_mocker, b'test data')
        assert time.time() - now >= 1
        client_mocker.write.assert_called_once_with(b'test data')


def _get_client_channel_handler(mocker, ctx0_mocker, read_delay_millis=0):
    handler = ProxyChannelHandler(
        "1.2.3.4", 8080, EventLoopGroup(),
        read_delay_millis=read_delay_millis,
    )

    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker
    handler._client_channel(ctx0_mocker, "1.2.3.4", 8080)  # noqa

    assert handler._client is client_mocker # noqa
    return BoostrapMocker.call_args[1]['handler_initializer']


class TestClientChannelInactive:

    def test_client_channel_inactive(self, mocker, ctx_mocker):
        ctx0_mocker = mocker.MagicMock()
        ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        handler_cls = _get_client_channel_handler(mocker, ctx0_mocker)
        handler_cls().channel_inactive(ctx_mocker)
        ctx0_mocker.close.assert_called_once()


class TestClientChannelWritabilityChanged:

    def test_client_channel_writability_changed(self, mocker, ctx_mocker):
        ctx0_mocker = mocker.MagicMock()
        ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        handler_cls = _get_client_channel_handler(mocker, ctx0_mocker)

        handler = handler_cls()
        # Test unwritable
        ctx_mocker.channel.return_value.is_writable.return_value = False
        handler.channel_writability_changed(ctx_mocker)
        ctx0_mocker.channel.return_value.set_auto_read.assert_called_with(False)

        # Test writable
        ctx_mocker.channel.return_value.is_writable.return_value = True
        handler.channel_writability_changed(ctx_mocker)
        ctx0_mocker.channel.return_value.set_auto_read.assert_called_with(True)


class TestClientChannelRead:

    def test_no_delay(self, mocker, ctx_mocker):
        ctx0_mocker = mocker.MagicMock()
        ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        handler_cls = _get_client_channel_handler(mocker, ctx0_mocker)
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ctx0_mocker.channel.return_value.channelinfo.return_value.peername = raddr

        now = time.time()
        handler = handler_cls()
        handler.channel_read(ctx_mocker, b'test data')
        assert time.time() - now < 0.5  # no delay
        ctx0_mocker.write.assert_called_once_with(b'test data')

    def test_delay(self, mocker, ctx_mocker):
        ctx0_mocker = mocker.MagicMock()
        ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
        handler_cls = _get_client_channel_handler(mocker, ctx0_mocker, 1000)
        ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
        ctx0_mocker.channel.return_value.channelinfo.return_value.peername = raddr

        now = time.time()
        handler = handler_cls()
        handler.channel_read(ctx_mocker, b'test data')
        assert time.time() - now >= 1
        ctx0_mocker.write.assert_called_once_with(b'test data')
