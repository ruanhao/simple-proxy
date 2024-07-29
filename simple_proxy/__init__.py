import socket
import http.server
import ssl
from functools import wraps
from py_netty.handler import LoggingChannelHandler
from py_netty import Bootstrap, ServerBootstrap, EventLoopGroup
from py_netty.channel import NioSocketChannel
import traceback
import sys
import os
import click
from datetime import datetime
import logging
import re
import codecs
from collections import defaultdict
import time
from attrs import define, field
import urllib
import subprocess
import shutil
from typing import Optional
from simple_proxy.utils import (
    submit_daemon_thread,
    random_sentence,
    pretty_duration,
    format_bytes,
    pretty_bytes,
    pretty_speed,
    from_cwd,
    getpeername,
    getsockname,
    create_temp_key_cert,
    free_port,
    set_keepalive
)
from simple_proxy.version import __version__

logger = logging.getLogger(__name__)


def _alpn_ssl_context_cb(ssl_ctx):
    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])


def _setup_logging(log_file, level=logging.INFO):
    handler = logging.StreamHandler()
    if log_file:
        from logging.handlers import RotatingFileHandler
        pstderr(f"Save log at {log_file}")
        handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=10 * 1024 * 1024,  # 10M
            backupCount=5
        )
    logging.basicConfig(
        handlers=[handler],
        level=level,
        format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


__ALL__ = ['run_proxy']


_speed_monitor = True
_stderr = False


def pstderr(msg):
    logger.debug(msg)
    if _stderr:
        click.echo(msg, err=True)


def pfatal(msg):
    logger.critical(msg)
    exit(1)


@define(slots=True, kw_only=True, order=True)
class _Client():

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
            self.__class__.max_rx = max(self.__class__.max_rx, self.rbps)
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
            self.__class__.max_tx = max(self.__class__.max_tx, self.wbps)
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


_clients = defaultdict(_Client)


def _check_patterns(patterns, s):
    for pattern in patterns:
        if re.search(pattern, s):
            logger.debug(f"pattern {pattern} matched {s}")
            return True
    logger.warning(f"no pattern matched {s}")
    return False


def _pattern_to_regex(pattern: str) -> str:
    regex_pattern = re.escape(pattern)
    regex_pattern = regex_pattern.replace(r'\*', r'.*')
    return regex_pattern


def _repr(obj):
    if isinstance(obj, (bytes, bytearray)):
        return f"<<{len(obj)} bytes>>"
    return repr(obj)


def _all_args_repr(args, kw):
    try:
        args_repr = [f"<{len(arg)} bytes>" if isinstance(arg, (bytes, bytearray)) else repr(arg) for arg in args]
        kws = []
        for k, v in kw.items():
            if isinstance(v, (bytes, bytearray)):
                kws.append(f"{k}=<{len(v)} bytes>")
            else:
                kws.append(f"{k}={repr(v)}")
        return ', '.join(args_repr + kws)
    except (Exception,):
        return "(?)"


def sneaky():

    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kw):
            all_args = _all_args_repr(args, kw)
            try:
                return func(*args, **kw)
            except Exception as e:
                emsg = f"[{e}] sneaky call: {func.__name__}({all_args})"
                if logger:
                    logger.exception(emsg)
                print(emsg, traceback.format_exc(), file=sys.stderr, sep=os.linesep, flush=True)
        return wrapper
    return decorate


@sneaky()
def _handle(buffer: bytes, direction: bool, src: NioSocketChannel, dst: NioSocketChannel, print_content: bool, to_file: bool):
    # try:
    #     src_ip, src_port = src.getpeername()[:2]
    #     dst_ip, dst_port = dst.getpeername()[:2]
    # except OSError:
    #     return buffer

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


def _clients_check(interval):
    ever = False
    zzz = 0
    rounds = 0
    while True and _speed_monitor:
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
            ever_rx, unit_r = format_bytes(_Client.global_rx)
            ever_tx, unit_t = format_bytes(_Client.global_tx)
            r = f"{ever_rx}{unit_r or 'B'}"
            t = f"{ever_tx}{unit_t or 'B'}"
            max_rx = pretty_speed(_Client.max_rx)
            max_tx = pretty_speed(_Client.max_tx)
            pstderr(f"Average Rx:{average_speed} bytes/s, Average Tx:{average_wspeed} bytes/s, Ever max Rx:{max_rx}, Ever max Tx:{max_tx}, Total Rx:{r}, Total Tx:{t}")
        time.sleep(interval)


class ShellChannelHandler(LoggingChannelHandler):

    def handle_read_output(self, ctx, fd):
        pstderr(f"{ctx.channel()} Start reading output from fd {fd} ...")
        while True:
            try:
                data = os.read(fd, 1024)
                if not data:
                    pstderr(f"{ctx.channel()} EOF reached on fd {fd}")
                    ctx.close()
                    return
                logger.debug(f"{ctx.channel()} Read {len(data)} bytes from fd {fd}")
                ctx.write(data)
                c = _clients.get(self.raddr)
                if c:
                    c.write(len(data))
            except Exception as e:
                pstderr(f"{ctx.channel()} Exception reading output from fd {fd}: {e}")
                ctx.close()
                return

    def _windows_shell_args(self):
        if shutil.which('cmd'):
            return [shutil.which('cmd'), '/Q', '/K']
        else:
            raise Exception("No shell found")

    def _setup_windows_shell(self, ctx):
        my_env = os.environ.copy()
        args = self._windows_shell_args()
        pstderr(f"{ctx.channel()} Starting shell with args: {args}")
        self._process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=-1,
            env=my_env
        )
        submit_daemon_thread(self.handle_read_output, ctx, self._process.stdout.fileno())
        submit_daemon_thread(self.handle_read_output, ctx, self._process.stderr.fileno())
        self._shell_stdin_fd = self._process.stdin.fileno()

    def _setup_linux_shell(self, ctx):
        bash = shutil.which('bash')
        master_fd, slave_fd = os.openpty()
        my_env = os.environ.copy()
        args = [bash, '-li']
        pstderr(f"{ctx.channel()} Starting shell with args: {args}")
        self._process = subprocess.Popen(
            args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            bufsize=-1,
            start_new_session=True,
            env=my_env
        )
        os.close(slave_fd)
        self._shell_stdin_fd = master_fd
        submit_daemon_thread(self.handle_read_output, ctx, master_fd)

    def _setup_linux_shell0(self, ctx):
        my_env = os.environ.copy()
        i_r, i_w = os.pipe()
        o_r, o_w = os.pipe()
        self._process = subprocess.Popen(
            [shutil.which('bash'), '-li'],
            stdin=i_r,
            stdout=o_w,
            stderr=o_w,
            bufsize=-1,
            start_new_session=True,
            env=my_env
        )
        self._shell_stdin_fd = i_w
        submit_daemon_thread(self.handle_read_output, ctx, o_r)

    def channel_active(self, ctx):
        super().channel_active(ctx)
        local_socket = ctx.channel().socket()
        self.raddr = local_socket.getpeername()
        _clients[self.raddr].local_socket = local_socket

        if os.name == 'nt':
            self._setup_windows_shell(ctx)
        else:
            self._setup_linux_shell(ctx)

        pstderr(f"{ctx.channel()} Shell started: {self._process.pid}")

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        if hasattr(self, 'raddr'):
            _clients[self.raddr].read(len(bytebuf))
        os.write(self._shell_stdin_fd, bytebuf)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)

        c = _clients.pop(self.raddr)
        pstderr(f"{ctx.channel()} Connection closed, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")

        self._process.kill()
        os.close(self._shell_stdin_fd)
        pstderr(f"{ctx.channel()} Shell terminated: {self._process.pid}")


class ProxyChannelHandler(LoggingChannelHandler):
    def __init__(
            self,
            remote_host, remote_port,
            client_eventloop_group,
            tls=False, content=False, to_file=False,
            disguise_tls_ip=None, disguise_tls_port=None,
            white_list=None,
            shadow=False,
            alpn=False,
            read_delay_millis=0,
            write_delay_millis=0,
    ):
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._client_eventloop_group = client_eventloop_group
        self._tls = tls
        self._client = None
        self._content = content
        self._to_file = to_file

        self._disguise_tls_ip = disguise_tls_ip
        self._disguise_tls_port = disguise_tls_port
        self._white_list = white_list
        self._shadow = shadow
        self._alpn = alpn
        self._read_delay_millis = read_delay_millis
        self._write_delay_millis = write_delay_millis

    def _client_channel(self, ctx0, ip, port):

        class _ChannelHandler(LoggingChannelHandler):

            def channel_read(this, ctx, bytebuf):
                _handle(bytebuf, False, ctx.channel(), ctx0.channel(), self._content, self._to_file)
                if self._read_delay_millis > 0:
                    time.sleep(self._read_delay_millis / 1000)
                ctx0.write(bytebuf)

            def channel_writability_changed(this, ctx) -> None:
                writable = ctx.channel().is_writable()
                if not writable:
                    this._unwritable_seconds = time.perf_counter()
                    logger.warning(f"{ctx0.channel()} client(proxy) writability changed: {writable}")
                else:
                    recovery_time_seconds = time.perf_counter() - this._unwritable_seconds
                    logger.warning(f"{ctx0.channel()} client(proxy) writability changed: {writable} ({recovery_time_seconds:.2f}s)")
                ctx0.channel().set_auto_read(ctx.channel().is_writable())

            def channel_inactive(this, ctx):
                super().channel_inactive(ctx)
                ctx0.close()

        if self._client is None:
            self._client = Bootstrap(
                eventloop_group=self._client_eventloop_group,
                handler_initializer=_ChannelHandler,
                tls=self._tls,
                verify=False,
                ssl_context_cb=_alpn_ssl_context_cb if self._alpn else None,
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
        _clients[self.raddr].local_socket = local_socket
        pstderr(f"Connection opened: {ctx.channel()}")
        self._create_client(ctx, None)

    def _create_client(self, ctx, bytebuf: Optional[bytes]):
        if self._client:
            return

        if self._shadow and self._disguise_tls_ip and bytebuf is None:
            # wait for the first packet
            return

        if self._shadow and self._disguise_tls_ip and bytebuf[0:2] == b'\x16\x03':
            pstderr(f"Malicious TLS visitor: {ctx.channel()}")
            self._client_channel(ctx, self._disguise_tls_ip, self._disguise_tls_port)
        elif self._white_list and not _check_patterns(self._white_list, ctx.channel().socket().getpeername()[0]):
            pstderr(f"Malicious visitor: {ctx.channel()}")
            if self._disguise_tls_ip and self._disguise_tls_port:
                self._client_channel(ctx, self._disguise_tls_ip, self._disguise_tls_port)
            else:
                ctx.close()
                return
        else:
            self._client_channel(ctx, self._remote_host, self._remote_port)
        _clients[self.raddr].proxy_socket = self._client.socket()

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        self._create_client(ctx, bytebuf)
        _handle(bytebuf, True, ctx.channel(), self._client, self._content, self._to_file)
        if self._write_delay_millis > 0:
            time.sleep(self._write_delay_millis / 1000)
        self._client.write(bytebuf)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)
        if hasattr(self, 'raddr'):
            c = _clients.pop(self.raddr)
            if c:
                pstderr(f"Connection closed: {ctx.channel()}, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")
            else:
                pstderr(f"Connection closed: {ctx.channel()}")
        if self._client:
            self._client.close()


class MyHttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # no log
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(random_sentence().encode('utf-8'))


class HttpProxyChannelHandler(LoggingChannelHandler):
    def __init__(self, client_eventloop_group, content=False, to_file=False):
        self._client_eventloop_group = client_eventloop_group
        self._client = None
        self._negociated = False
        self._buffer = b''
        self._content = content
        self._to_file = to_file

    def _client_channel(self, ctx0, ip, port):

        class _ChannelHandler(LoggingChannelHandler):

            def channel_read(this, ctx, bytebuf):
                _handle(bytebuf, False, ctx.channel(), ctx0.channel(), self._content, self._to_file)
                ctx0.write(bytebuf)

            def channel_inactive(this, ctx):
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
        _clients[self.raddr].local_socket = local_socket
        pstderr(f"[HTTP PROXY] Connection opened   : {ctx.channel()}")

    def channel_read(self, ctx, bytebuf):
        if self._negociated:
            self._client.write(bytebuf)
        else:
            self._buffer += bytebuf
            if b'\r\n\r\n' in self._buffer:
                self._negociated = True
                content = self._buffer.decode('ascii', errors='using_dot')

                idx = content.index('HTTP')
                peer = ctx.channel().channelinfo().peername[0]
                if 'CONNECT' in content:  # https proxy
                    host_and_port = content[:idx].strip().split(' ')[1]
                    pstderr(f"[HTPT Proxy] Connection requests : {peer} | HTTPS | {host_and_port} | {ctx.channel().id()}")
                    host, port = host_and_port.split(':')
                    _clients[self.raddr].proxy_socket = self._client_channel(ctx, host, int(port)).socket()
                    ctx.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                else:           # http proxy
                    url = content[:idx].strip().split(' ')[1]
                    parsed = urllib.parse.urlparse(url)
                    host, port = parsed.hostname, parsed.port or 80
                    pstderr(f"[HTTP Proxy] Connection requests : {peer} | HTTP  | {host}:{port} | {ctx.channel().id()}")
                    _clients[self.raddr].proxy_socket = self._client_channel(ctx, host, port).socket()
                    self._client.write(self._buffer)

                self._buffer = b''

        if self._client:
            _handle(bytebuf, True, ctx.channel(), self._client, self._content, self._to_file)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)
        if hasattr(self, 'raddr'):
            c = _clients.pop(self.raddr)
            if c:
                pstderr(f"[HTTP Proxy] Connection closed   : {ctx.channel()}, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")
            else:
                pstderr(f"[HTTP Proxy] Connection closed   : {ctx.channel()}")
        if self._client:
            self._client.close()


@click.command(short_help="Simple proxy", context_settings=dict(
    help_option_names=['-h', '--help'],
    max_content_width=shutil.get_terminal_size().columns - 10,
))
@click.option('--local-server', '-l', default='localhost', help='Local server address', show_default=True)
@click.option('--local-port', '-lp', type=int, default=8080, help='Local port', show_default=True)
@click.option('--remote-server', '-r', default='localhost', help='Remote server address', show_default=True)
@click.option('--remote-port', '-rp', type=int, default=80, help='Remote port', show_default=True)
@click.option('--global', '-g', 'using_global', is_flag=True, help='Listen on 0.0.0.0')
@click.option('--workers', type=int, default=1, help='Number of worker threads', show_default=True)
@click.option('--proxy-workers', type=int, default=1, help='Number of proxy threads', show_default=True)
@click.option('--tcp-flow', '-c', 'content', is_flag=True, help='Dump tcp flow on to console')
@click.option('--save-tcp-flow', '-f', 'to_file', is_flag=True, help='Save tcp flow to file')
@click.option('--tls', '-s', is_flag=True, help='Denote remote server listening on secure port')
@click.option('-ss', is_flag=True, help='Denote local sever listening on secure port')
@click.option('--key-file', '-kf', help='Key file for local server', type=click.Path(exists=True))
@click.option('--cert-file', '-cf', help='Certificate file for local server', type=click.Path(exists=True))
@click.option('--speed-monitor', '-sm', is_flag=True, help='Print speed info to console for established connection')
@click.option('--speed-monitor-interval', '-smi', type=int, default=3, help='Speed monitor interval', show_default=True)
@click.option('--disguise-tls-ip', '-dti', help='Disguise TLS IP')
@click.option('--disguise-tls-port', '-dtp', type=int, help='Disguise TLS port', default=443, show_default=True)
@click.option('--white-list', '-wl', help='IP White list for incoming connections (comma separated)')
@click.option('--run-mock-tls-server', is_flag=True, help='Run mock TLS server')
@click.option('--shadow', is_flag=True, help='Disguise if incoming connection is TLS client request')
@click.option('--alpn', is_flag=True, help='Set ALPN protocol as [h2, http/1.1]')
@click.option('--http-proxy', is_flag=True, help='HTTP proxy mode')
@click.option('--shell-proxy', is_flag=True, help='Shell proxy mode')
@click.option('-v', '--verbose', count=True)
@click.option('--read-delay-millis', type=int, help='Read delay in milliseconds (only apply to TCP proxy mode)', default=0, show_default=True)
@click.option('--write-delay-millis', type=int, help='Write delay in milliseconds (only apply to TCP proxy mode)', default=0, show_default=True)
@click.option('--log-file', help='Log file', type=click.Path())
@click.version_option(prog_name='Simple Proxy', version=__version__)
def _cli(verbose, log_file: click.Path, **kwargs):
    _setup_logging(log_file, logging.INFO if verbose == 0 else logging.DEBUG)
    if verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger('simple_proxy.utils').setLevel(logging.DEBUG)
    run_proxy(**kwargs)


def run_proxy(
        local_server="localhost", local_port=8080,
        remote_server="localhost", remote_port=80,
        using_global=False,
        content=False, to_file=False,
        tls=False, ss=False,
        key_file=None, cert_file=None,
        speed_monitor=False, speed_monitor_interval=3,
        disguise_tls_ip=None, disguise_tls_port=443,
        white_list=None,
        run_mock_tls_server=False,
        shadow=False,
        alpn=False,
        http_proxy=False,
        shell_proxy=False,
        read_delay_millis=0, write_delay_millis=0,
        workers=1, proxy_workers=1,
):
    if shadow and not (disguise_tls_ip or run_mock_tls_server):
        pfatal("'--shadow' is not applicable if '--disguise-tls-ip/-dti' or '--run-mock-tls-server' is not specified!")
    if tls and (disguise_tls_ip or run_mock_tls_server):
        pfatal("'--tls/-s' is not applicable if disguise is used!")

    if white_list and not (disguise_tls_ip or run_mock_tls_server):
        pstderr("[WARN] Malicious connection will be dropped immediately when neither '--disguise-tls-ip/-dti' nor '--run-mock-tls-server' is specified!")
    if (disguise_tls_ip or run_mock_tls_server) and not white_list and not shadow:
        pstderr("[WARN] Disguise will not take effect when neither '--shadow' nor '--white-list/-wl' is specified")

    white_list0 = white_list or ''
    if white_list:
        white_list = white_list.split(',')
        white_list = [_pattern_to_regex(x) for x in white_list]

    if using_global:
        local_server = '0.0.0.0'

    codecs.register_error('using_dot', lambda e: ('.', e.start + 1))

    cf = None
    kf = None
    if ss:
        assert (key_file and cert_file) or (not key_file and not cert_file), "Both key and cert files are required"
        if key_file and cert_file:
            kf = key_file
            cf = cert_file
        else:
            kf, cf = create_temp_key_cert()

    if run_mock_tls_server:
        disguise_tls_ip = 'localhost'
        disguise_tls_port = free_port()
        server_address = (disguise_tls_ip, disguise_tls_port)
        kf_mock, cf_mock = create_temp_key_cert(True)
        httpd = http.server.HTTPServer(server_address, MyHttpHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                       server_side=True,
                                       certfile=cf_mock,
                                       keyfile=kf_mock,
                                       ssl_version=ssl.PROTOCOL_TLS)
        submit_daemon_thread(httpd.serve_forever)

    client_eventloop_group = EventLoopGroup(proxy_workers, 'Client')
    if http_proxy:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=lambda: HttpProxyChannelHandler(
                client_eventloop_group,
                content=content,
                to_file=to_file,
            ),
        )
        pstderr(f"HTTP Proxy server started listening: {local_server}:{local_port} [console:{content}, file:{to_file}] ... ")
    elif shell_proxy:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=ShellChannelHandler,
            certfile=cf,
            keyfile=kf,
        )
        pstderr(f"Shell proxy server started listening: {local_server}:{local_port}{'(TLS)' if ss else ''} ...")
    else:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=lambda: ProxyChannelHandler(
                remote_server, remote_port,
                client_eventloop_group,
                tls=tls,
                content=content, to_file=to_file,
                disguise_tls_ip=disguise_tls_ip, disguise_tls_port=disguise_tls_port,
                white_list=white_list,
                shadow=shadow,
                alpn=alpn,
                read_delay_millis=read_delay_millis,
                write_delay_millis=write_delay_millis,
            ),
            certfile=cf,
            keyfile=kf,
            ssl_context_cb=_alpn_ssl_context_cb if alpn else None,
        )
        disguise = f"https://{disguise_tls_ip}:{disguise_tls_port}" if disguise_tls_ip else 'n/a'
        pstderr(f"Proxy server started listening: {local_server}:{local_port}{'(TLS)' if ss else ''} => {remote_server}:{remote_port}{'(TLS)' if tls else ''} ...")
        pstderr(f"console:{content}, file:{to_file}, disguise:{disguise}, whitelist:{white_list0 or '*'}, shadow:{shadow}")

    if speed_monitor:
        import signal
        submit_daemon_thread(_clients_check, speed_monitor_interval)

        def _signal_handler(sig, frame):
            global _speed_monitor
            _speed_monitor = False
            signal.default_int_handler(sig, frame)
            signal.signal(signal.SIGINT, signal.default_int_handler)

        signal.signal(signal.SIGINT, _signal_handler)
    sb.bind(address=local_server, port=local_port).close_future().sync()


def _run():
    global _stderr
    _stderr = True
    _cli()


def _test_pattern_to_regex():
    assert _pattern_to_regex('*.example.com') == r'.*\.example\.com'
    assert _pattern_to_regex('example.com') == r'example\.com'
    assert _pattern_to_regex('example.*.com') == r'example\..*\.com'
    assert _pattern_to_regex('example.com.*') == r'example\.com\..*'


def _test_Client():
    c1 = _Client()
    c2 = _Client()
    c1.read(100)
    c1.write(101)
    assert _Client.global_rx == 100
    assert _Client.global_tx == 101
    c2.read(200)
    c2.write(201)
    assert _Client.global_rx == 300
    assert _Client.global_tx == 302


def _test_format_bytes():
    v, u = format_bytes(1)
    assert v == 1
    assert u == 'B'
    v, u = format_bytes(1025)
    assert v == 1, v
    assert u == 'K', u
    v, u = format_bytes(1025 * 1024)
    assert v == 1, v
    assert u == 'M', u
    v, u = format_bytes(60 * 1024 * 1024)
    assert v == 60, v
    assert u == 'M', u


if __name__ == '__main__':
    _test_pattern_to_regex()
    _test_Client()
    _test_format_bytes()
    _stderr = True
    # run_proxy(
    #     local_server='localhost', local_port=8080,
    #     remote_server='www.google.com', remote_port=80,
    #     tls=False, ss=False,
    #     content=False, to_file=False,
    #     key_file='', cert_file='',
    #     speed_monitor=False, speed_monitor_interval=5,
    #     disguise_tls_ip='', disguise_tls_port=0,
    #     white_list=None,
    #     using_global=False,
    # )
