from simple_proxy.clients import *
from simple_proxy.clients import _print_http_proxy_info, _print_socks5_proxy_info
import time


def test_print_proxy_info():
    # case empty
    _print_socks5_proxy_info()
    _print_http_proxy_info()
    # case with data
    from simple_proxy.handler.http_proxy_channel_handler import get_local_peer_to_target_mapping as get_http_mapings
    from simple_proxy.handler.socks5_proxy_channel_handler import get_local_peer_to_target_mapping as get_socks5_mapings
    get_http_mapings()["a"] = "b"
    get_socks5_mapings()["c"] = "d"
    _print_socks5_proxy_info()
    _print_http_proxy_info()

def test_get_client_or_none():
    client = TcpProxyClient()
    raddr = ('127.0.0.1', int(time.time()))
    assert get_client_or_none(raddr) is None
    get_clients()[raddr] = client
    assert get_client_or_none(raddr) is client


def test_get_client_or_create():
    raddr = ('127.0.0.1', int(time.time()))
    assert get_client_or_create(raddr)
    assert get_client_or_create(raddr) is get_client_or_create(raddr)
    origin_client = get_client_or_create(raddr)
    pop_client(raddr)
    assert get_client_or_create(raddr) is not origin_client

def test_spawn_clients_monitor():
    client = TcpProxyClient()
    get_clients()[('127.0.0.1', 8080)] = client
    t = spawn_clients_monitor(1)
    time.sleep(0.5)
    assert t.is_alive()
    time.sleep(1)
    assert t.is_alive()
    stop_clients_monitor()
    time.sleep(1)
    assert not t.is_alive()

def test_stop_clients_monitor():
    from simple_proxy import clients
    clients._monitor = True
    stop_clients_monitor()
    assert not clients._monitor

def test_handle_data_case_no_data(mocker):
    src = mocker.MagicMock()
    dst = mocker.MagicMock()
    src.channelinfo.return_value.peername = ('127.0.0.1', 12345)
    dst.channelinfo.return_value.peername = ('8.8.8.8', 54321)
    assert not handle_data(b'', True, src, dst, False, False)

def test_handle_data_case_no_client(mocker):
    src = mocker.MagicMock()
    dst = mocker.MagicMock()
    src.channelinfo.return_value.peername = ('127.0.0.1', 12345)
    dst.channelinfo.return_value.peername = ('8.8.8.8', 54321)
    get_clients().clear()
    buffer = b'123'
    assert handle_data(buffer, True, src, dst, False, False) == buffer

def test_handle_data_case_client_rw(mocker):
    src = mocker.MagicMock()
    dst = mocker.MagicMock()
    src.channelinfo.return_value.peername = ('127.0.0.1', 12345)
    dst.channelinfo.return_value.peername = ('8.8.8.8', 54321)
    buffer = b'123'

    # read case
    client_mocker = mocker.MagicMock()
    get_clients()[('127.0.0.1', 12345)] = client_mocker
    assert handle_data(buffer, True, src, dst, False, False) == buffer
    client_mocker.read.assert_called_once_with(len(buffer))
    assert not client_mocker.write.called

    # write case
    client_mocker = mocker.MagicMock()
    get_clients()[('8.8.8.8', 54321)] = client_mocker
    assert handle_data(buffer, False, src, dst, False, False) == buffer
    client_mocker.write.assert_called_once_with(len(buffer))
    assert not client_mocker.read.called

def test_handle_data_case_log_data(mocker):
    src = mocker.MagicMock()
    dst = mocker.MagicMock()
    src.channelinfo.return_value.peername = ('127.0.0.1', 12345)
    dst.channelinfo.return_value.peername = ('8.8.8.8', 54321)
    get_clients().clear()
    buffer = b'123'
    assert handle_data(buffer, True, src, dst, True, False) == buffer
    assert handle_data(buffer, True, src, dst, False, False) == buffer
    assert handle_data(buffer, True, src, dst, True, True) == buffer
    assert handle_data(buffer, True, src, dst, False, True) == buffer

    assert handle_data(buffer, False, src, dst, True, False) == buffer
    assert handle_data(buffer, False, src, dst, False, False) == buffer
    assert handle_data(buffer, False, src, dst, True, True) == buffer
    assert handle_data(buffer, False, src, dst, False, True) == buffer

def test_tcp_proxy_client():
    c1 = TcpProxyClient()
    c2 = TcpProxyClient()
    c1.read(100)
    c1.write(101)
    assert TcpProxyClient.global_rx == 100
    assert TcpProxyClient.global_tx == 101
    c2.read(200)
    c2.write(201)
    assert TcpProxyClient.global_rx == 300
    assert TcpProxyClient.global_tx == 302

    assert c1.pretty_born_time()
    assert c1.pretty_rx_speed()
    assert c1.pretty_tx_speed()
    assert c1.pretty_rx_total()
    assert c1.pretty_tx_total()

    time.sleep(1.1)
    c1.read(1100)
    c1.write(1200)
    assert c1.rbps >= 900
    assert c1.wbps >= 900
    assert TcpProxyClient.max_rx >= 900
    assert TcpProxyClient.max_tx >= 900
    assert c1.cumulative_read_time == 0
    assert c1.cumulative_read_bytes == 0
    assert c1.cumulative_write_time == 0
    assert c1.cumulative_write_bytes == 0

    c1.check()
    time.sleep(3.1)
    c1.check()
