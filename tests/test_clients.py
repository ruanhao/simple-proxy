from simple_proxy.clients import TcpProxyClient
import time


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
    assert c1.rbps >= 1000
    assert c1.wbps >= 1000
    assert TcpProxyClient.max_rx >= 1000
    assert TcpProxyClient.max_tx >= 1000
    assert c1.cumulative_read_time == 0
    assert c1.cumulative_read_bytes == 0
    assert c1.cumulative_write_time == 0
    assert c1.cumulative_write_bytes == 0

    c1.check()
    time.sleep(3.1)
    c1.check()
