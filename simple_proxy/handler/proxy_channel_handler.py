import time
from typing import Optional
from py_netty import Bootstrap
from py_netty.handler import LoggingChannelHandler
from ..utils.tlsutils import alpn_ssl_context_cb
from ..clients import handle_data, get_client_or_create, pop_client
from ..utils.netutils import set_keepalive
from ..utils.logutils import pstderr
from ..utils.stringutils import check_ip_patterns
import logging
from py_netty import EventLoopGroup

logger = logging.getLogger(__name__)


class ProxyChannelHandler(LoggingChannelHandler):
    def __init__(
            self,
            remote_host: str, remote_port: int,
            client_eventloop_group: EventLoopGroup,
            tls: bool = False, content: bool = False, to_file: bool = False,
            disguise_tls_ip: str = None, disguise_tls_port: int = 443,
            white_list: list[str] = None,
            alpn: bool = False,
            read_delay_millis: int = 0,
            write_delay_millis: int = 0,
    ):
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._client_eventloop_group = client_eventloop_group
        self._tls = tls
        self._client = None
        self._abort: bool = False
        self._content = content
        self._to_file = to_file

        self._disguise_tls_ip = disguise_tls_ip
        self._disguise_tls_port = disguise_tls_port
        self._white_list = white_list
        self._alpn = alpn
        self._read_delay_millis = read_delay_millis
        self._write_delay_millis = write_delay_millis
        self._unwritable_seconds: float = None  # noqa
        self.raddr: tuple[str, int] = None  # noqa

    def _client_channel(self, ctx0, ip, port):

        class _ChannelHandler(LoggingChannelHandler):

            def __init__(self):
                self._unwritable_seconds: float = None  # noqa

            def channel_read(this, ctx, bytebuf):  # noqa
                handle_data(bytebuf, False, ctx.channel(), ctx0.channel(), self._content, self._to_file)
                if self._read_delay_millis > 0:
                    time.sleep(self._read_delay_millis / 1000)
                ctx0.write(bytebuf)

            def channel_writability_changed(this, ctx) -> None:  # noqa
                writable = ctx.channel().is_writable()
                if not writable:
                    this._unwritable_seconds = time.perf_counter()
                    logger.warning(f"{ctx0.channel()} client(proxy) writability changed: {writable}")
                else:
                    recovery_time_seconds = time.perf_counter() - this._unwritable_seconds
                    logger.warning(f"{ctx0.channel()} client(proxy) writability changed: {writable} ({recovery_time_seconds:.2f}s)")
                ctx0.channel().set_auto_read(ctx.channel().is_writable())

            def channel_inactive(this, ctx):  # noqa
                super().channel_inactive(ctx)
                ctx0.close()

        if self._client is None:
            self._client = Bootstrap(
                eventloop_group=self._client_eventloop_group,
                handler_initializer=_ChannelHandler,
                tls=self._tls,
                verify=False,
                ssl_context_cb=alpn_ssl_context_cb if self._alpn else None,
            ).connect(ip, port, True).sync().channel()
            set_keepalive(self._client.socket())
        return self._client

    def channel_writability_changed(self, ctx) -> None:
        writable = ctx.channel().is_writable()
        if not writable:
            self._unwritable_seconds = time.perf_counter()
            logger.warning(f"{ctx.channel()} channel writability changed: {writable}")
        else:
            recovery_time_seconds = time.perf_counter() - self._unwritable_seconds
            logger.warning(f"{ctx.channel()} channel writability changed: {writable} ({recovery_time_seconds:.2f}s)")
        self._client.set_auto_read(ctx.channel().is_writable())

    def exception_caught(self, ctx, exception):
        super().exception_caught(ctx, exception)
        ctx.close()

    def channel_active(self, ctx):
        super().channel_active(ctx)
        local_socket = ctx.channel().socket()
        set_keepalive(local_socket)
        self.raddr = local_socket.getpeername()
        get_client_or_create(self.raddr).local_socket = local_socket
        pstderr(f"Connection opened: {ctx.channel()}")
        self._create_client(ctx, None)

    def _create_client(self, ctx, bytebuf: Optional[bytes]):
        if self._client:
            return

        need_disguise: bool = bool(self._disguise_tls_ip and self._disguise_tls_port)

        # case 1:
        # no white list
        # need disguise, only for TLS probe traffic, this means proxied traffic should not be https
        if not self._white_list and need_disguise:
            if bytebuf is None:
                # need to wait for first packets (if it is TLS) to decide disguise
                return
            if bytebuf[0:2] == b'\x16\x03':
                logger.debug("Disguise for TLS visitor: %s", ctx.channel())
                self._client_channel(ctx, self._disguise_tls_ip, self._disguise_tls_port)
                get_client_or_create(self.raddr).proxy_socket = self._client.socket()
                return

        # case 2:
        # has white list and not allowed
        # close
        if self._white_list and not check_ip_patterns(self._white_list, ctx.channel().socket().getpeername()[0]):
            if need_disguise:
                self._client_channel(ctx, self._disguise_tls_ip, self._disguise_tls_port)
                get_client_or_create(self.raddr).proxy_socket = self._client.socket()
                return
            pstderr(f"Kick out not-allowed visitor: {ctx.channel()}")
            ctx.close()
            self._abort = True
            return

        # case 3: (others)
        # just do proxy
        self._client_channel(ctx, self._remote_host, self._remote_port)
        get_client_or_create(self.raddr).proxy_socket = self._client.socket()

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        if self._abort:
            return
        self._create_client(ctx, bytebuf)
        handle_data(bytebuf, True, ctx.channel(), self._client, self._content, self._to_file)
        if self._write_delay_millis > 0:
            time.sleep(self._write_delay_millis / 1000)
        self._client.write(bytebuf)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)
        if hasattr(self, 'raddr'):
            c = pop_client(self.raddr)
            if c:
                pstderr(f"Connection closed: {ctx.channel()}, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")
            else:
                pstderr(f"Connection closed: {ctx.channel()}")
        if self._client:
            self._client.close()
