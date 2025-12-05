import time
from simple_proxy.handler.proxy_channel_handler import ProxyChannelHandler
from py_netty import EventLoopGroup
from simple_proxy.clients import get_clients


raddr = ('127.0.0.1', 8080)


def test_exception_caught(mocker):
    handler = ProxyChannelHandler("1.2.3.4", 9090, EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    handler.exception_caught(ctx_mocker, Exception("test exception"))
    ctx_mocker.close.assert_called_once()


def test_channel_active(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1"
    )
    ctx_mocker = mocker.MagicMock()
    local_socket_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value = local_socket_mocker
    local_socket_mocker.getpeername.return_value = raddr
    get_clients().clear()
    handler.channel_active(ctx_mocker)
    assert raddr in get_clients()


def test_create_client_case_already_exists(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
    )
    handler._client = mocker.MagicMock()
    handler._create_client(None, None)  # no exception should be raised


def test_create_client_case_disguise_and_wait_for_traffic(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1",
    )
    handler._client = mocker.MagicMock()
    handler._create_client(None, None)  # no exception should be raised


def test_create_client_case_non_whitelist_with_disguise(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1",
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

    handler._create_client(ctx_mocker, b'\x16\x03\x01')
    assert BoostrapMocker().connect.call_args[0] == ("4.3.2.1", 443, True)
    assert handler._client is client_mocker


def test_create_client_case_non_whitelist_with_disguise_but_not_tls(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1",
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

    handler._create_client(ctx_mocker, b'\x15\x03\x01')
    assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True)
    assert handler._client is client_mocker


def test_create_client_case_not_allowed_with_disguise(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1", white_list=["10.0.0.*"],
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

    handler._create_client(ctx_mocker, b'\x16\x03\x01')
    assert BoostrapMocker().connect.call_args[0] == ("4.3.2.1", 443, True)
    assert handler._client is client_mocker


def test_create_client_case_not_allowed(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        white_list=["10.0.0.*"],
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    handler._create_client(ctx_mocker, b'\x16\x03\x01')
    ctx_mocker.close.assert_called_once()
    assert handler._abort


def test_create_client_case_allowed(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1", white_list=["10.1.0.*"],
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

    handler._create_client(ctx_mocker, b'\x16\x03\x01')
    assert handler._client is client_mocker
    assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True)


def test_create_client_case_allowed_while_need_disguise_but_not_tls(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
        disguise_tls_ip="4.3.2.1", white_list=["10.1.0.*"],
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

    handler._create_client(ctx_mocker, b'\x15\x03\x01')
    assert handler._client is client_mocker
    assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True)


def test_create_client_case_no_wl_and_disguise_configured(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 9090, EventLoopGroup(),
    )
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    client_mocker = mocker.MagicMock()
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)
    BoostrapMocker = mocker.patch(  # noqa
        'simple_proxy.handler.proxy_channel_handler.Bootstrap'
    )
    BoostrapMocker.return_value.connect.return_value.sync.return_value.channel.return_value = client_mocker

    handler._create_client(ctx_mocker, None)  # channel active
    assert handler._client is client_mocker
    assert BoostrapMocker().connect.call_args[0] == ("1.2.3.4", 9090, True)


def test_channel_inactive(mocker):
    handler = ProxyChannelHandler("1.2.3.4", 8080, EventLoopGroup())
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


def test_channel_writability_changed(mocker):
    ctx_mocker = mocker.MagicMock()
    client_mocker = mocker.MagicMock()
    handler = ProxyChannelHandler("1.2.3.4", 8080, EventLoopGroup())
    handler._client = client_mocker

    ctx_mocker.channel.return_value.is_writable.return_value = False
    handler.channel_writability_changed(ctx_mocker)
    client_mocker.set_auto_read.assert_called_with(False)

    ctx_mocker.channel.return_value.is_writable.return_value = True
    handler.channel_writability_changed(ctx_mocker)
    client_mocker.set_auto_read.assert_called_with(True)


def test_channel_read_case_no_delay(mocker):
    handler = ProxyChannelHandler("1.2.3.4", 8080, EventLoopGroup())
    ctx_mocker = mocker.MagicMock()
    client_mocker = mocker.MagicMock()
    handler._client = client_mocker
    ctx_mocker.channel.return_value.channelinfo.return_value.peername = ("10.1.0.1", 12345)
    client_mocker.channelinfo.return_value.peername = ('8.8.8.8', 53)

    now = time.time()
    handler.channel_read(ctx_mocker, b'test data')
    assert time.time() - now < 0.5  # no delay
    client_mocker.write.assert_called_once_with(b'test data')


def test_channel_read_case_write_delay(mocker):
    handler = ProxyChannelHandler(
        "1.2.3.4", 8080, EventLoopGroup(),
        write_delay_millis=1000,
    )
    ctx_mocker = mocker.MagicMock()
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


def test_client_channel_inactive(mocker):
    ctx0_mocker = mocker.MagicMock()
    ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    handler_cls = _get_client_channel_handler(mocker, ctx0_mocker)
    ctx_mocker = mocker.MagicMock()
    handler_cls().channel_inactive(ctx_mocker)
    ctx0_mocker.close.assert_called_once()


def test_client_channel_writability_changed(mocker):
    ctx0_mocker = mocker.MagicMock()
    ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    handler_cls = _get_client_channel_handler(mocker, ctx0_mocker)
    ctx_mocker = mocker.MagicMock()

    handler = handler_cls()
    # Test unwritable
    ctx_mocker.channel.return_value.is_writable.return_value = False
    handler.channel_writability_changed(ctx_mocker)
    ctx0_mocker.channel.return_value.set_auto_read.assert_called_with(False)

    # Test writable
    ctx_mocker.channel.return_value.is_writable.return_value = True
    handler.channel_writability_changed(ctx_mocker)
    ctx0_mocker.channel.return_value.set_auto_read.assert_called_with(True)


def test_client_channel_read_case_no_delay(mocker):
    ctx0_mocker = mocker.MagicMock()
    ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    handler_cls = _get_client_channel_handler(mocker, ctx0_mocker)
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
    ctx0_mocker.channel.return_value.channelinfo.return_value.peername = raddr

    now = time.time()
    handler = handler_cls()
    handler.channel_read(ctx_mocker, b'test data')
    assert time.time() - now < 0.5  # no delay
    ctx0_mocker.write.assert_called_once_with(b'test data')


def test_client_channel_read_case_delay(mocker):
    ctx0_mocker = mocker.MagicMock()
    ctx0_mocker.channel.return_value.socket.return_value.getpeername.return_value = ("10.1.0.1", 12345)
    handler_cls = _get_client_channel_handler(mocker, ctx0_mocker, 1000)
    ctx_mocker = mocker.MagicMock()
    ctx_mocker.channel.return_value.channelinfo.return_value.peername = raddr
    ctx0_mocker.channel.return_value.channelinfo.return_value.peername = raddr

    now = time.time()
    handler = handler_cls()
    handler.channel_read(ctx_mocker, b'test data')
    assert time.time() - now >= 1
    ctx0_mocker.write.assert_called_once_with(b'test data')
