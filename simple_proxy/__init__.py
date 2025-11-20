import http.server
import ssl
from py_netty.handler import LoggingChannelHandler
from py_netty import Bootstrap, ServerBootstrap, EventLoopGroup
import os
import click
import logging
import codecs
import subprocess
import shutil
from typing import Optional, Tuple

from simple_proxy.handler.proxy_channel_handler import ProxyChannelHandler

from .clients import (
    TcpProxyClient,
    get_client_or_none, get_client_or_create, pop_client, handle_data,
    spawn_clients_monitor, stop_clients_monitor,
)

from simple_proxy.utils import (
    submit_daemon_thread,
    pretty_duration,
    from_cwd,
    getpeername,
    getsockname,
    create_temp_key_cert,
    free_port,
    set_keepalive,
    enable_stderr,
    alpn_ssl_context_cb,
)
from simple_proxy.utils.proxyutils import (
    parse_proxy_info,
    trim_proxy_info,
)

from simple_proxy.utils.stringutils import (
    random_sentence, pretty_speed,
    pretty_bytes,
    pattern_to_regex,
)
from simple_proxy.utils.logutils import pstderr, pfatal, setup_logging
from simple_proxy.version import __version__

logger = logging.getLogger(__name__)

__ALL__ = ['run_proxy']

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
                c = get_client_or_none(self.raddr)
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
        get_client_or_create(self.raddr).local_socket = local_socket

        if os.name == 'nt':
            self._setup_windows_shell(ctx)
        else:
            self._setup_linux_shell(ctx)

        pstderr(f"{ctx.channel()} Shell started: {self._process.pid}")

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        if hasattr(self, 'raddr'):
            get_client_or_create(self.raddr).read(len(bytebuf))
        os.write(self._shell_stdin_fd, bytebuf)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)

        c = pop_client(self.raddr)
        pstderr(f"{ctx.channel()} Connection closed, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")

        self._process.kill()
        os.close(self._shell_stdin_fd)
        pstderr(f"{ctx.channel()} Shell terminated: {self._process.pid}")


class EchoChannelHandler(ProxyChannelHandler):

    def __init(
            self,
            client_eventloop_group,
            tls,
    ):
        super().__init__(None, None, client_eventloop_group, tls=tls)

    def channel_read(self, ctx, bytebuf):
        if not bytebuf:
            return
        src_ip, src_port = ctx.channel().channelinfo().peername
        raddr = (src_ip, src_port)
        client = get_client_or_none(raddr)
        if client:
            client.read(len(bytebuf))

        ctx.channel().write(bytebuf)
        if client:
            client.write(len(bytebuf))

    def _create_client(self, ctx, bytebuf: Optional[bytes]):
        pass


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
    def __init__(
            self,
            client_eventloop_group,
            content=False, to_file=False,
            transform: Tuple[Tuple[str, int, str, int]] = None,
            http_proxy_username=None, http_proxy_password=None,
    ):
        self._client_eventloop_group = client_eventloop_group
        self._client = None
        self._negotiated = False
        self._buffer = b''
        self._content = content
        self._to_file = to_file
        self._transform = transform
        self._http_proxy_username = http_proxy_username
        self._http_proxy_password = http_proxy_password
        self.raddr = None

    def _client_channel(self, ctx0, ip, port):

        class _ChannelHandler(LoggingChannelHandler):

            def channel_read(this, ctx, bytebuf):
                handle_data(bytebuf, False, ctx.channel(), ctx0.channel(), self._content, self._to_file)
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
        get_client_or_create(self.raddr).local_socket = local_socket
        if logger.isEnabledFor(logging.DEBUG):
            pstderr(f"[HTTP PROXY] Connection opened   : {ctx.channel()}")

    def _transform_host_port(self, origin_host: str, origin_port: int) -> Tuple[str, int]:
        if self._transform:
            for h0, p0, h, p in self._transform:
                if h0 == origin_host and p0 == origin_port:
                    return h, p
        return origin_host, origin_port

    def _print_record(self, channel_id: str, https: bool, peer: str, host0: str, port0: int, host: str, port: int):
        proto = 'HTTPS' if https else 'HTTP '
        if host0 == host and port0 == port:
            pstderr(f"[HTTP Proxy] Connection requests : {proto} | {channel_id} | {peer} | {host0}:{port0}")
        else:
            pstderr(f"[HTTP Proxy] Connection requests : {proto} | {channel_id} | {peer} | {host0}:{port0} > {host}:{port}")

    def channel_read(self, ctx, bytebuf):
        if self._negotiated:
            self._client.write(bytebuf)
        else:
            self._buffer += bytebuf
            if b'\r\n\r\n' in self._buffer:
                self._negotiated = True
                content = self._buffer.decode('ascii', errors='using_dot')
                peer = ctx.channel().channelinfo().peername[0]
                channel_id = ctx.channel().id()
                try:
                    proxy_info = parse_proxy_info(content)
                except Exception as e:
                    pstderr(f"[HTTP Proxy] Parse proxy info failed: {e}")
                    ctx.write(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                    ctx.close()
                    return
                if self._http_proxy_username and self._http_proxy_password:
                    if self._http_proxy_username != proxy_info.username or self._http_proxy_password != proxy_info.password:
                        pstderr(f"[HTTP Proxy] Username or password error: {proxy_info.username} {proxy_info.password}")
                        ctx.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
                        ctx.close()
                        return
                host, port = self._transform_host_port(proxy_info.host, proxy_info.port)
                get_client_or_create(self.raddr).proxy_socket = self._client_channel(ctx, host, int(port)).socket()
                if 'CONNECT' in content:  # https proxy
                    self._print_record(channel_id, True, peer, proxy_info.host, proxy_info.port, host, port)
                    ctx.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                else:           # http proxy
                    self._print_record(channel_id, False, peer, proxy_info.host, proxy_info.port, host, port)
                    self._client.write(trim_proxy_info(self._buffer))

                self._buffer = b''

        if self._client:
            handle_data(bytebuf, True, ctx.channel(), self._client, self._content, self._to_file)

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
@click.option('--as-echo-server', '-e', is_flag=True, help='Run as Echo Server')
@click.option('--shadow', is_flag=True, help='Disguise if incoming connection is TLS client request')
@click.option('--alpn', is_flag=True, help='Set ALPN protocol as [h2, http/1.1]')
@click.option('--http-proxy', is_flag=True, help='HTTP proxy mode')
@click.option('--http-proxy-username', help='HTTP proxy username')
@click.option('--http-proxy-password', help='HTTP proxy password')
@click.option('--http-proxy-transform', '-t', type=(str, int, str, int), multiple=True, help='HTTP proxy transform(host, port, transformed_host, transformed_port)')
@click.option('--shell-proxy', is_flag=True, help='Shell proxy mode')
@click.option('-v', '--verbose', count=True)
@click.option('--read-delay-millis', type=int, help='Read delay in milliseconds (only apply to TCP proxy mode)', default=0, show_default=True)
@click.option('--write-delay-millis', type=int, help='Write delay in milliseconds (only apply to TCP proxy mode)', default=0, show_default=True)
@click.option('--log-file', help='Log file', type=click.Path())
@click.version_option(prog_name='Simple Proxy', version=__version__)
def _cli(verbose, log_file: click.Path, **kwargs):
    setup_logging(log_file, logging.INFO if verbose == 0 else logging.DEBUG)
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
        http_proxy_transform: Tuple[Tuple[str, int, str, int]] = None,
        http_proxy_username=None, http_proxy_password=None,
        shell_proxy=False,
        read_delay_millis=0, write_delay_millis=0,
        workers=1, proxy_workers=1,
        as_echo_server=False,
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
        white_list = [pattern_to_regex(x) for x in white_list]

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
        kf_mock, cf_mock = create_temp_key_cert()
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
                transform=http_proxy_transform,
                http_proxy_username=http_proxy_username,
                http_proxy_password=http_proxy_password,
            ),
        )
        pstderr(f"HTTP Proxy server started listening: {local_server}:{local_port} [console:{content}, file:{to_file}] ... ")
        if http_proxy_transform:
            pstderr("HTTP Proxy transforms:")
            for h0, p0, h, p in http_proxy_transform:
                pstderr(f"  {h0}:{p0} -> {h}:{p}")
    elif shell_proxy:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=ShellChannelHandler,
            certfile=cf,
            keyfile=kf,
        )
        pstderr(f"Shell proxy server started listening: {local_server}:{local_port}{'(TLS)' if ss else ''} ...")
    elif as_echo_server:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=lambda: EchoChannelHandler(
                None, None,
                client_eventloop_group,
                tls=tls,
            ),
            certfile=cf,
            keyfile=kf,
        )
        pstderr(f"Echo server started listening: {local_server}:{local_port}{'(TLS)' if ss else ''} ...")
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
            ssl_context_cb=alpn_ssl_context_cb if alpn else None,
        )
        disguise = f"https://{disguise_tls_ip}:{disguise_tls_port}" if disguise_tls_ip else 'n/a'
        pstderr(f"Proxy server started listening: {local_server}:{local_port}{'(TLS)' if ss else ''} => {remote_server}:{remote_port}{'(TLS)' if tls else ''} ...")
        pstderr(f"console:{content}, file:{to_file}, disguise:{disguise}, whitelist:{white_list0 or '*'}, shadow:{shadow}")

    if speed_monitor:
        import signal
        spawn_clients_monitor(speed_monitor_interval)

        def _signal_handler(sig, frame):
            stop_clients_monitor()
            signal.default_int_handler(sig, frame)


        signal.signal(signal.SIGINT, _signal_handler)
    sb.bind(address=local_server, port=local_port).close_future().sync()

# for setup.py entry point
def _run():
    enable_stderr()
    _cli()