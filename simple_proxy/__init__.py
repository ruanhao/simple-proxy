import http.server
import ssl
from py_netty import ServerBootstrap, EventLoopGroup
import click
import logging
import codecs
import shutil
from .clients import (
    TcpProxyClient,
    get_client_or_none, get_client_or_create, pop_client, handle_data,
    spawn_clients_monitor, stop_clients_monitor,
)
from .handler.http_proxy_channel_handler import HttpProxyChannelHandler
from .handler.socks5_proxy_channel_handler import Socks5ProxyChannelHandler
from .utils.osutils import (
    submit_daemon_thread,
    from_cwd,
)
from .utils.netutils import (
    getpeername,
    getsockname,
    free_port,
    set_keepalive,
)
from .utils.certutils import create_temp_key_cert
from .utils.tlsutils import alpn_ssl_context_cb
from .utils.proxyutils import (
    parse_proxy_info,
    trim_proxy_info,
)
from .utils.stringutils import (
    random_sentence, pretty_speed,
    pretty_bytes,
    pretty_duration,
    pattern_to_regex,
)
from .utils.logutils import pstderr, pfatal, setup_logging, enable_stderr
from .version import __version__
from .handler.echo_channel_handler import EchoChannelHandler
from .handler.shell_channel_handler import ShellChannelHandler
from simple_proxy.handler.proxy_channel_handler import ProxyChannelHandler

logger = logging.getLogger(__name__)

__ALL__ = ['run_proxy']


class MyHttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format_, *args):
        # no log
        pass

    def do_GET(self):  # noqa
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(random_sentence().encode('utf-8'))


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
@click.option('--socks5-proxy', is_flag=True, help='HTTP proxy mode')
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
        socks5_proxy=False,
        http_proxy_transform: tuple[tuple[str, int, str, int]] = None,
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
        pstderr(f"Mock TLS server started listening(https://localhost:{disguise_tls_port}) ...")
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
    elif socks5_proxy:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=lambda: Socks5ProxyChannelHandler(
                client_eventloop_group,
                content=content,
                to_file=to_file,
                transform=http_proxy_transform,
                http_proxy_username=http_proxy_username,
                http_proxy_password=http_proxy_password,
            ),
        )
        pstderr(f"Socks5 Proxy server started listening: {local_server}:{local_port} [console:{content}, file:{to_file}] ... ")
        if http_proxy_transform:
            pstderr("Proxy transforms:")
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