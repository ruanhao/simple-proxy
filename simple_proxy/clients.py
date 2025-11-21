import socket
import time
from attrs import define, field
from .utils import pretty_duration, pretty_speed, pretty_bytes
from collections import defaultdict
import click
from .utils.logutils import sneaky, pstderr
from .utils.osutils import from_cwd, submit_daemon_thread
from .utils.netutils import getpeername, getsockname
from py_netty.channel import NioSocketChannel
from datetime import datetime
from threading import Thread

_monitor = True


@define(slots=True, kw_only=True, order=True)
class TcpProxyClient:

    global_rx = 0
    global_tx = 0
    max_rx = 0
    max_tx = 0

    last_read_time: float = field(factory=time.perf_counter)
    total_read_bytes: int = field(default=0)
    cumulative_read_bytes: int = field(default=0)  # bytes
    cumulative_read_time: float = field(default=0.0)  # seconds
    rbps: float = field(default=0.0)
    born_time: float = field(factory=time.perf_counter)

    last_write_time: float = field(factory=time.perf_counter)
    total_write_bytes: int = field(default=0)
    cumulative_write_bytes: int = field(default=0)  # bytes
    cumulative_write_time: float = field(default=0.0)  # seconds
    wbps: float = field(default=0.0)

    local_socket: socket.socket = field(default=None)
    proxy_socket: socket.socket = field(default=None)

    def pretty_born_time(self):
        return pretty_duration(time.perf_counter() - self.born_time)

    def pretty_rx_speed(self):
        return pretty_speed(self.rbps)

    def pretty_tx_speed(self):
        return pretty_speed(self.wbps)

    def pretty_rx_total(self):
        return pretty_bytes(self.total_read_bytes)

    def pretty_tx_total(self):
        return pretty_bytes(self.total_write_bytes)

    def read(self, size):
        self.__class__.global_rx += size
        current_time = time.perf_counter()
        self.cumulative_read_time += (current_time - self.last_read_time)
        self.last_read_time = current_time
        self.total_read_bytes += size
        self.cumulative_read_bytes += size
        if self.cumulative_read_time > 1:
            self.rbps = int(self.cumulative_read_bytes / self.cumulative_read_time)  # bytes per second
            self.__class__.max_rx = max(self.__class__.max_rx, self.rbps)  # noqa
            self.cumulative_read_time = 0
            self.cumulative_read_bytes = 0

    def write(self, size):
        self.__class__.global_tx += size
        current_time = time.perf_counter()
        self.cumulative_write_time += (current_time - self.last_write_time)
        self.last_write_time = current_time
        self.total_write_bytes += size
        self.cumulative_write_bytes += size
        if self.cumulative_write_time > 1:
            self.wbps = int(self.cumulative_write_bytes / self.cumulative_write_time)  # bytes per second
            self.__class__.max_tx = max(self.__class__.max_tx, self.wbps)  # noqa
            self.cumulative_write_time = 0
            self.cumulative_write_bytes = 0

    def check(self):
        if time.perf_counter() - self.last_read_time > 3:
            self.rbps = 0
            self.cumulative_read_time = 0
            self.cumulative_read_bytes = 0
            self.wbps = 0
            self.cumulative_write_time = 0
            self.cumulative_write_bytes = 0


_clients = defaultdict(TcpProxyClient)


@sneaky()
def handle_data(
        buffer: bytes,
        direction: bool,
        src: NioSocketChannel, dst: NioSocketChannel,
        print_content: bool, to_file: bool
) -> bytes:
    src_ip, src_port = src.channelinfo().peername
    dst_ip, dst_port = dst.channelinfo().peername

    raddr = (src_ip, src_port) if direction else (dst_ip, dst_port)

    if buffer:
        client = _clients.get(raddr)
        if client:
            if direction:
                client.read(len(buffer))
            else:
                client.write(len(buffer))
    else:                       # EOF
        return buffer

    if not print_content and not to_file:
        return buffer
    content = buffer.decode('ascii', errors='using_dot')
    src_ip = src_ip.replace(':', '_')
    dst_ip = dst_ip.replace(':', '_')
    filename = ('L' if direction else 'R') + f'_{src_ip}_{src_port}_{dst_ip}_{dst_port}.log'
    if to_file:
        with from_cwd('__tcpflow__', filename).open('a') as f:
            f.write(content)
    if print_content:
        click.secho(content, fg='green' if direction else 'yellow')
    return buffer


def get_clients() -> dict[tuple[str, int], TcpProxyClient]:
    return _clients


def get_client_or_none(raddr: tuple[str, int]) -> TcpProxyClient | None:
    return _clients.get(raddr)


def get_client_or_create(raddr: tuple[str, int]) -> TcpProxyClient:
    return _clients[raddr]


def pop_client(raddr: tuple[str, int]) -> TcpProxyClient | None:
    return _clients.pop(raddr, None)


def _print_http_proxy_info():
    from .handler.http_proxy_channel_handler import get_local_peer_to_target_mapping
    mapping = get_local_peer_to_target_mapping()
    if not mapping:
        return
    pstderr("HTTP Proxy Mappings".center(100, '-'))
    count = 1
    for peer, target in mapping.items():
        pstderr(f"[{count:3}] | {peer:21} --> {target}")
        count += 1


def _print_socks5_proxy_info():
    from .handler.socks5_proxy_channel_handler import get_local_peer_to_target_mapping
    mapping = get_local_peer_to_target_mapping()
    if not mapping:
        return
    pstderr("SOCKS5 Proxy Mappings".center(100, '-'))
    count = 1
    for peer, target in mapping.items():
        pstderr(f"[{count:3}] | {peer:21} --> {target}")
        count += 1


def _clients_check(interval: int = 5):
    ever = False
    zzz = 0
    rounds = 0
    while True and _monitor:
        clients_snapshot = _clients.copy()
        items = list(clients_snapshot.items())
        items.sort(key=lambda x: x[1].born_time)
        total = len(clients_snapshot)
        if total:
            rounds += 1
            pstderr(f'{datetime.now()} (total:{total}, rounds:{rounds})'.center(100, '-'))
            ever = True
            zzz = 0
        else:
            if zzz % 60 == 0 and ever:
                rounds += 1
                pstderr(f"{datetime.now()} No client connected (rounds:{rounds})".center(100, '-'))
            zzz += 1

        count = 1
        for address, client in items:
            client.check()
            # ip, port = address
            pspeed = client.pretty_rx_speed()
            ptotal = client.pretty_rx_total()
            pwspeed = client.pretty_tx_speed()
            pwtotal = client.pretty_tx_total()
            duration = client.pretty_born_time().lower()
            local_socket = client.local_socket
            proxy_socket = client.proxy_socket
            from_ = getpeername(local_socket)
            proxy = getsockname(proxy_socket)
            pstderr(f"[{count:3}] | {from_:21} | {proxy:21} | rx:{pspeed:10} tx:{pwspeed:10} | cum(rx):{ptotal:10} cum(tx):{pwtotal:10} | {duration}")
            count += 1
        if total:
            average_speed = round(sum([c.rbps for c in clients_snapshot.values()]) / total, 2)
            average_wspeed = round(sum([c.wbps for c in clients_snapshot.values()]) / total, 2)
            r = pretty_bytes(TcpProxyClient.global_rx)
            t = pretty_bytes(TcpProxyClient.global_tx)
            max_rx = pretty_speed(TcpProxyClient.max_rx)
            max_tx = pretty_speed(TcpProxyClient.max_tx)
            pstderr(f"Average Rx:{average_speed} bytes/s, Average Tx:{average_wspeed} bytes/s, Ever max Rx:{max_rx}, Ever max Tx:{max_tx}, Total Rx:{r}, Total Tx:{t}")
        _print_http_proxy_info()
        _print_socks5_proxy_info()
        time.sleep(interval)


def spawn_clients_monitor(interval: int = 5) -> Thread:
    return submit_daemon_thread(_clients_check, interval)


def stop_clients_monitor():
    global _monitor
    _monitor = False
