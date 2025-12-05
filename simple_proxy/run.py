import codecs
import http.server
import signal
import ssl

from py_netty import EventLoopGroup, ServerBootstrap

from .clients import spawn_clients_monitor, stop_clients_monitor
from .handler.echo_channel_handler import EchoChannelHandler
from .handler.http_proxy_channel_handler import HttpProxyChannelHandler
from .handler.proxy_channel_handler import ProxyChannelHandler
from .handler.shell_channel_handler import ShellChannelHandler
from .handler.socks5_proxy_channel_handler import Socks5ProxyChannelHandler
from .utils import (
    pfatal, pstderr,
    pattern_to_regex,
    create_temp_key_cert,
    free_port,
    submit_daemon_thread,
    alpn_ssl_context_cb,
    random_sentence,
)


class MyHttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format_, *args):
        # no log
        pass

    def do_GET(self):  # noqa
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(random_sentence().encode('utf-8'))


def run_proxy(
        local_server="localhost", local_port=8080,
        remote_server="localhost", remote_port=80,
        using_global=False,
        content=False, to_file=False,
        tls=False, ss=False,
        key_file=None, cert_file=None,
        monitor=False, monitor_interval=3,
        disguise_tls_ip=None, disguise_tls_port=443,
        white_list: str = None,
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

    if ss and (disguise_tls_ip or run_disguise_tls_server):
        pfatal("'-ss' is not applicable if disguise mode is used!")

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
        httpd = http.server.HTTPServer(server_address, MyHttpHandler)  # noqa
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cf_mock, keyfile=kf_mock)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        pstderr(f"Builtin disguise TLS server started listening(https://localhost:{disguise_tls_port}) ...")
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
