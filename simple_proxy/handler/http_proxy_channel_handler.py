import logging

from py_netty import Bootstrap
from py_netty.handler import LoggingChannelHandler
from ..clients import handle_data, get_client_or_create, pop_client
from ..utils.logutils import pstderr
from ..utils.netutils import set_keepalive
from ..utils.proxyutils import parse_proxy_info, trim_proxy_info
# from collections import OrderedDict


# class LimitedDict(OrderedDict):
#     def __init__(self, maxlen, *args, **kwargs):
#         self.maxlen = maxlen
#         super().__init__(*args, **kwargs)
#     def __setitem__(self, key, value):
#         # if key already exists, delete it first
#         if key in self:
#             del self[key]
#         elif len(self) >= self.maxlen:
#             # delete earliest key（FIFO）
#             oldest = next(iter(self))
#             del self[oldest]
#         super().__setitem__(key, value)

logger = logging.getLogger(__name__)

# _local_peer_to_target_mapping = LimitedDict(1024)
_local_peer_to_target_mapping: dict[str, str] = dict()


def get_local_peer_to_target_mapping() -> dict[str, str]:
    return _local_peer_to_target_mapping


class HttpProxyChannelHandler(LoggingChannelHandler):
    def __init__(
            self,
            client_eventloop_group,
            content=False, to_file=False,
            transform: tuple[tuple[str, int, str, int], ...] = None,
            proxy_username=None, proxy_password=None,
    ):
        self._client_eventloop_group = client_eventloop_group
        self._client = None
        self._negotiated = False
        self._buffer = b''
        self._content = content
        self._to_file = to_file
        self._transform = transform
        self._proxy_username = proxy_username
        self._proxy_password = proxy_password
        self.raddr = None
        self._http = False

    def _client_channel(self, ctx0, ip, port):

        class _ChannelHandler(LoggingChannelHandler):

            def channel_read(this, ctx, bytebuf):  # noqa
                handle_data(bytebuf, False, ctx.channel(), ctx0.channel(), self._content, self._to_file)
                ctx0.write(bytebuf)

            def channel_inactive(this, ctx):  # noqa
                ctx0.close()

        if self._client is None:
            self._client = Bootstrap(
                eventloop_group=self._client_eventloop_group,
                handler_initializer=_ChannelHandler
            ).connect(ip, port, True).sync().channel()
        return self._client

    def exception_caught(self, ctx, exception):
        super().exception_caught(ctx, exception)
        ctx.close()

    def channel_active(self, ctx):
        local_socket = ctx.channel().socket()
        set_keepalive(local_socket)
        self.raddr = local_socket.getpeername()
        get_client_or_create(self.raddr).local_socket = local_socket
        if logger.isEnabledFor(logging.DEBUG):
            pstderr(f"[HTTP PROXY] Connection opened   : {ctx.channel()}")

    def _transform_host_port(self, origin_host: str, origin_port: int) -> tuple[str, int]:
        if self._transform:
            for h0, p0, h, p in self._transform:
                if h0 == origin_host and p0 == origin_port:
                    return h, p
        return origin_host, origin_port

    @staticmethod
    def _print_record(channel_id: str, https: bool, peer: str, host0: str, port0: int, host: str, port: int):
        proto = 'HTTPS' if https else 'HTTP '
        if host0 == host and port0 == port:
            pstderr(f"[HTTP Proxy] Connection requests : {proto} | {channel_id} | {peer} | {host0}:{port0}")
        else:
            pstderr(f"[HTTP Proxy] Connection requests : {proto} | {channel_id} | {peer} | {host0}:{port0} > {host}:{port}")

    def channel_read(self, ctx, bytebuf):  # noqa
        if self._negotiated:
            if self._http:
                bytebuf = trim_proxy_info(bytebuf)
            self._client.write(bytebuf)
            handle_data(bytebuf, True, ctx.channel(), self._client, self._content, self._to_file)
            return
        self._buffer += bytebuf
        if b'\r\n\r\n' in self._buffer:
            self._negotiated = True
            content = self._buffer.decode('ascii', errors='using_dot')
            peer_name, peer_port = ctx.channel().channelinfo().peername
            peer = f"{peer_name}:{peer_port}"
            channel_id = ctx.channel().id()
            try:
                proxy_info = parse_proxy_info(content)
            except Exception as e:
                pstderr(f"[HTTP Proxy] Parse proxy info failed: {e}")
                ctx.write(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                raise ValueError(f"Parse proxy info failed: {content}") from e
            if self._proxy_username and self._proxy_password:
                if self._proxy_username != proxy_info.username or self._proxy_password != proxy_info.password:
                    pstderr(f"[HTTP Proxy] Username or password error: {proxy_info.username} {proxy_info.password}")
                    ctx.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
                    masked_password = '*' * len(proxy_info.password) if proxy_info.password else ''
                    raise ValueError(f"Username or password error: {proxy_info.username}/{masked_password}")

            host, port = self._transform_host_port(proxy_info.host, proxy_info.port)
            get_local_peer_to_target_mapping()[peer] = f"{host}:{port}"
            get_client_or_create(self.raddr).proxy_socket = self._client_channel(ctx, host, int(port)).socket()
            if 'CONNECT' in content:  # https proxy
                self._print_record(channel_id, True, peer, proxy_info.host, proxy_info.port, host, port)
                ctx.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:           # http proxy
                self._http = True
                self._print_record(channel_id, False, peer, proxy_info.host, proxy_info.port, host, port)
                trimmed = trim_proxy_info(self._buffer)
                self._client.write(trimmed)
                handle_data(trimmed, True, ctx.channel(), self._client, self._content, self._to_file)

            self._buffer = b''  # _buffer is no longer needed

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)
        if hasattr(self, 'raddr'):
            c = pop_client(self.raddr)
            if logger.isEnabledFor(logging.DEBUG):
                if c:
                    pstderr(f"[HTTP Proxy] Connection closed   : {ctx.channel()}, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")
                else:
                    pstderr(f"[HTTP Proxy] Connection closed   : {ctx.channel()}")
        if self._client:
            self._client.close()
        peer_name, peer_port = ctx.channel().channelinfo().peername
        peer = f"{peer_name}:{peer_port}"
        get_local_peer_to_target_mapping().pop(peer, None)
