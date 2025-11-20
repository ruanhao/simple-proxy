import socket
import time
from attrs import define, field
from .utils import pretty_duration, pretty_speed, pretty_bytes


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
