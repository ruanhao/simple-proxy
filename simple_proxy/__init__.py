import http.server
import ssl
import signal
from py_netty import ServerBootstrap, EventLoopGroup
import click
from click_option_group import optgroup
import logging
import codecs
import shutil
from .clients import (
    spawn_clients_monitor, stop_clients_monitor,
)
from .handler.http_proxy_channel_handler import HttpProxyChannelHandler
from .handler.socks5_proxy_channel_handler import Socks5ProxyChannelHandler
from .utils.osutils import submit_daemon_thread
from .utils.netutils import free_port
from .utils.certutils import create_temp_key_cert
from .utils.tlsutils import alpn_ssl_context_cb
from .utils.stringutils import (
    random_sentence,
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
@optgroup.group('Common configuration', help='Configuration for local/remote endpoints')
@optgroup.option('--local-server', '-l', default='localhost', help='Local server address', show_default=True)
@optgroup.option('--local-port', '-lp', type=int, default=8080, help='Local port', show_default=True)
@optgroup.option('--global', '-g', 'using_global', is_flag=True, help='Local port listening on all interfaces')
@optgroup.option('--remote-server', '-r', default='localhost', help='Remote server address', show_default=True)
@optgroup.option('--remote-port', '-rp', type=int, default=80, help='Remote port', show_default=True)
@optgroup.option('--tls', '-s', is_flag=True, help='Denote remote is listening on secure port')
@optgroup.option('-ss', is_flag=True, help='Make local listen on secure port')
@optgroup.group('TCP proxy configuration', help='Configuration for TCP proxy mode')
@optgroup.option('--read-delay-millis', type=int, help='Read delay in milliseconds', default=0, show_default=True)
@optgroup.option('--write-delay-millis', type=int, help='Write delay in milliseconds', default=0, show_default=True)
#
@optgroup.group('Thread configuration', help='Configuration for thread pool')
@optgroup.option('--workers', type=int, default=1, help='Number of worker threads', show_default=True)
@optgroup.option('--proxy-workers', type=int, default=1, help='Number of proxy threads', show_default=True)
#
@optgroup.group('Traffic dump configuration', help='Configuration for traffic dump')
@optgroup.option('--tcp-flow', '-c', 'content', is_flag=True, help='Dump tcp flow on to console')
@optgroup.option('--save-tcp-flow', '-f', 'to_file', is_flag=True, help='Save tcp flow to file')
#
@optgroup.group('TLS certificate configuration', help='Configuration for TLS certificate')
@optgroup.option('--key-file', '-kf', help='Key file for local server', type=click.Path(exists=True))
@optgroup.option('--cert-file', '-cf', help='Certificate file for local server', type=click.Path(exists=True))
@optgroup.option('--alpn', is_flag=True, help='Set ALPN protocol as [h2, http/1.1]')
#
@optgroup.group('Traffic monitor configuration', help='Configuration for traffic monitor')
@optgroup.option('--monitor', '-m', is_flag=True, help='Print speed info to console for established connection')
@optgroup.option('--monitor-interval', '-mi', type=int, default=3, help='Speed monitor interval', show_default=True)
#
@optgroup.group('TLS Disguise configuration', help='Configuration for protection against unwanted inspection')
@optgroup.option('--disguise-tls-ip', '-dti', help='Disguised upstream TLS IP')
@optgroup.option('--disguise-tls-port', '-dtp', type=int, help='Disguised upstream TLS port', default=443, show_default=True)
@optgroup.option('--run-disguise-tls-server', is_flag=True, help='Run builtin disguise TLS server without specifying external one')
@optgroup.option('--white-list', '-wl', help='IP White list for legal incoming TLS connections (comma separated)')
#
@optgroup.group('Proxy configuration', help='Configuration for proxy')
@optgroup.option('--as-echo-server', '-e', is_flag=True, help='Run as Echo server')
@optgroup.option('--shell-proxy', is_flag=True, help='Run as shell proxy server')
@optgroup.option('--http-proxy', is_flag=True, help='Run as HTTP proxy server')
@optgroup.option('--socks5-proxy', is_flag=True, help='Run as SOCKS5 proxy server')
@optgroup.option('--proxy-username', help='Proxy username')
@optgroup.option('--proxy-password', help='Proxy password')
@optgroup.option('--proxy-transform', '-t', type=(str, int, str, int), multiple=True, help='List of target transformations(origin_host, origin_port, transformed_host, transformed_port)')
#
@optgroup.group('Misc configuration')
@optgroup.option('-v', '--verbose', count=True)
@optgroup.option('--log-file', help='Log file', type=click.Path())
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
        monitor=False, monitor_interval=3,
        disguise_tls_ip=None, disguise_tls_port=443,
        white_list=None,
        run_disguise_tls_server=False,
        alpn=False,
        http_proxy=False,
        socks5_proxy=False,
        proxy_transform: tuple[tuple[str, int, str, int]] = None,
        proxy_username=None, proxy_password=None,
        shell_proxy=False,
        read_delay_millis=0, write_delay_millis=0,
        workers=1, proxy_workers=1,
        as_echo_server=False,
):
    if tls and (disguise_tls_ip or run_disguise_tls_server):
        pfatal("'--tls/-s' is not applicable if disguise mode is used!")

    if white_list and not (disguise_tls_ip or run_disguise_tls_server):
        pstderr("[WARN] Malicious connection will be dropped immediately when neither '--disguise-tls-ip/-dti' nor '--run-disguise-tls-server' is specified!")

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

    if run_disguise_tls_server:
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
        pstderr(f"Builin disguise TLS server started listening(https://localhost:{disguise_tls_port}) ...")
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
                transform=proxy_transform,
                proxy_username=proxy_username,
                proxy_password=proxy_password,
            ),
        )
        pstderr(f"HTTP Proxy server started listening: {local_server}:{local_port} [console:{content}, file:{to_file}] ... ")
        if proxy_transform:
            pstderr("HTTP Proxy transforms:")
            for h0, p0, h, p in proxy_transform:
                pstderr(f"  {h0}:{p0} -> {h}:{p}")
    elif socks5_proxy:
        sb = ServerBootstrap(
            parant_group=EventLoopGroup(1, 'Boss'),
            child_group=EventLoopGroup(workers, 'Worker'),
            child_handler_initializer=lambda: Socks5ProxyChannelHandler(
                client_eventloop_group,
                content=content,
                to_file=to_file,
                transform=proxy_transform,
                proxy_username=proxy_username,
                proxy_password=proxy_password,
            ),
        )
        pstderr(f"Socks5 Proxy server started listening: {local_server}:{local_port} [console:{content}, file:{to_file}] ... ")
        if proxy_transform:
            pstderr("Proxy transforms:")
            for h0, p0, h, p in proxy_transform:
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
        pstderr(f"console:{content}, file:{to_file}, disguise:{disguise}, whitelist:{white_list0 or '*'}")

    if monitor:
        spawn_clients_monitor(monitor_interval)

        def _signal_handler(sig, frame):
            stop_clients_monitor()
            signal.default_int_handler(sig, frame)

        signal.signal(signal.SIGINT, _signal_handler)
    sb.bind(address=local_server, port=local_port).close_future().sync()


# for setup.py entry point
def _run():
    enable_stderr()
    _cli()
