import socket
import random
import http.server
import ssl
from functools import wraps, partial
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from py_netty.handler import LoggingChannelHandler
from py_netty import Bootstrap, ServerBootstrap, EventLoopGroup
import inspect
from pathlib import Path
import traceback
import sys
import tempfile
import os
import click
from datetime import datetime, timedelta
import logging
import re
import codecs
from collections import defaultdict
import time
from attrs import define, field
import threading
import itertools


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


def _setup_logging(level=logging.INFO):
    logging.basicConfig(
        handlers=[
            logging.StreamHandler(),  # default to stderr
        ],
        level=level,
        format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


__ALL__ = ['run_proxy']


_speed_monitor = True
_counter = itertools.count()
_stderr = False


def _submit_daemon_thread(func, *args, **kwargs) -> threading.Thread:
    if isinstance(func, partial):
        func_name = func.func.__name__
    else:
        func_name = func.__name__

    def _worker():
        func(*args, **kwargs)

    t = threading.Thread(target=_worker, name=f'{func_name}-daemon-{next(_counter)}', daemon=True)
    t.start()
    return t


def _random_sentence():
    nouns = ("puppy", "car", "rabbit", "girl", "monkey")
    verbs = ("runs", "hits", "jumps", "drives", "barfs")
    adv = ("crazily.", "dutifully.", "foolishly.", "merrily.", "occasionally.")
    return nouns[random.randrange(0, 5)] + ' ' + \
        verbs[random.randrange(0, 5)] + ' ' + \
        adv[random.randrange(0, 5)] + '\n'


def pstderr(msg):
    logger.debug(msg)
    if _stderr:
        click.echo(msg, err=True)


def pfatal(msg):
    logger.critical(msg)
    exit(1)


def _pretty_duration(seconds: int) -> str:
    TIME_DURATION_UNITS = (
        ('W', 60 * 60 * 24 * 7),
        ('D', 60 * 60 * 24),
        ('H', 60 * 60),
        ('M', 60),
        ('S', 1)
    )
    if seconds == 0:
        return '0S'
    parts = []
    for unit, div in TIME_DURATION_UNITS:
        amount, seconds = divmod(int(seconds), div)
        if amount > 0:
            parts.append('{}{}'.format(amount, unit))
    return ', '.join(parts)


def _format_bytes(size, scale=1):
    # 2**10 = 1024
    size = int(size)
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        size = round(size, scale)
        n += 1
    return size, power_labels[n]


@define(slots=True, kw_only=True, order=True)
class _Client():
    last_read_time: float = field(factory=time.time)
    total_read_bytes: int = field(default=0)
    cumulative_read_bytes: int = field(default=0)  # bytes
    cumulative_read_time: float = field(default=0.0)  # seconds
    rbps: float = field(default=0.0)
    born_time: float = field(factory=time.time)

    last_write_time: float = field(factory=time.time)
    total_write_bytes: int = field(default=0)
    cumulative_write_bytes: int = field(default=0)  # bytes
    cumulative_write_time: float = field(default=0.0)  # seconds
    wbps: float = field(default=0.0)

    def pretty_born_time(self):
        return _pretty_duration(time.time() - self.born_time)

    def pretty_speed(self):
        v, unit = _format_bytes(self.rbps)
        return f"{v:.2f} {unit}/s"

    def pretty_wspeed(self):
        v, unit = _format_bytes(self.wbps)
        return f"{v:.2f} {unit}/s"

    def pretty_total(self):
        v, unit = _format_bytes(self.total_read_bytes)
        if unit:
            return f"{v:.2f} {unit}"
        else:
            return f"{v} B"

    def pretty_wtotal(self):
        v, unit = _format_bytes(self.total_write_bytes)
        if unit:
            return f"{v:.2f} {unit}"
        else:
            return f"{v} B"

    def read(self, size):
        current_time = time.time()
        self.cumulative_read_time += (current_time - self.last_read_time)
        self.last_read_time = current_time
        self.total_read_bytes += size
        self.cumulative_read_bytes += size
        if self.cumulative_read_time > 1:
            self.rbps = int(self.cumulative_read_bytes / self.cumulative_read_time)  # bytes per second
            self.cumulative_read_time = 0
            self.cumulative_read_bytes = 0

    def write(self, size):
        current_time = time.time()
        self.cumulative_write_time += (current_time - self.last_write_time)
        self.last_write_time = current_time
        self.total_write_bytes += size
        self.cumulative_write_bytes += size
        if self.cumulative_write_time > 1:
            self.wbps = int(self.cumulative_write_bytes / self.cumulative_write_time)  # bytes per second
            self.cumulative_write_time = 0
            self.cumulative_write_bytes = 0

    def check(self):
        if time.time() - self.last_read_time > 2:
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


def _all_args_repr(args, kw):
    try:
        args_repr = [repr(arg) for arg in args]
        kws = [f"{k}={repr(v)}" for k, v in kw.items()]
        return ', '.join(args_repr + kws)
    except Exception:
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


def _from_cwd(*args):
    absolute = Path(os.path.join(os.getcwd(), *args))
    absolute.parent.mkdir(parents=True, exist_ok=True)
    return absolute


def _module_path(mod=None):
    if not mod:
        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])
    return os.path.dirname(mod.__file__)


def _from_module(filename=None):
    frm = inspect.stack()[1]
    mod = inspect.getmodule(frm[0])
    if not filename:
        return _module_path(mod)
    return os.path.join(_module_path(mod), filename)


@sneaky()
def _handle(buffer, direction, src, dst, print_content, to_file):
    src_ip, src_port = src.getpeername()
    dst_ip, dst_port = dst.getpeername()

    raddr = (src_ip, src_port) if direction else (dst_ip, dst_port)
    client = _clients[raddr]
    if buffer:
        if direction:
            client.read(len(buffer))
        else:
            client.write(len(buffer))
    else:                       # EOF
        del _clients[raddr]
        return buffer

    if not print_content and not to_file:
        return buffer
    content = buffer.decode('ascii', errors='using_dot')
    src_ip = src_ip.replace(':', '_')
    dst_ip = dst_ip.replace(':', '_')
    filename = ('L' if direction else 'R') + f'_{src_ip}_{src_port}_{dst_ip}_{dst_port}.log'
    if to_file:
        with _from_cwd('__tcpflow__', filename).open('a') as f:
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
            ip, port = address
            ipport = f"{ip}:{port}"
            pspeed = client.pretty_speed()
            ptotal = client.pretty_total()
            pwspeed = client.pretty_wspeed()
            pwtotal = client.pretty_wtotal()
            duration = client.pretty_born_time().lower()
            pstderr(f"[{count:3}] | {ipport:21} | Speed Rx:{pspeed:10} Tx:{pwspeed:10} | Total Rx:{ptotal:10} Tx:{pwtotal:10} | duration: {duration}")
            count += 1
        if total:
            average_speed = round(sum([c.rbps for c in clients_snapshot.values()]) / total, 2)
            average_wspeed = round(sum([c.wbps for c in clients_snapshot.values()]) / total, 2)
            pstderr(f"{'Average Read Speed:':<20} {average_speed} bytes/s, {'Average Write Speed:':<20} {average_wspeed} bytes/s")

        time.sleep(interval)


class ProxyChannelHandler(LoggingChannelHandler):
    def __init__(
            self,
            remote_host, remote_port,
            client_eventloop_group,
            tls=False, content=False, to_file=False,
            disguise_tls_ip=None, disguise_tls_port=None,
            white_list=None,
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

    def _client_channel(self, ctx0, ip, port):

        class _ChannelHandler(LoggingChannelHandler):

            def channel_read(this, ctx, bytebuf):
                _handle(bytebuf, False, ctx.channel().socket(), ctx0.channel().socket(), self._content, self._to_file)
                ctx0.write(bytebuf)

            def channel_inactive(this, ctx):
                super().channel_inactive(ctx)
                ctx0.close()

        if self._client is None:
            self._client = Bootstrap(
                eventloop_group=self._client_eventloop_group,
                handler_initializer=_ChannelHandler,
                tls=self._tls,
                verify=False
            ).connect(ip, port, True).sync().channel()
        return self._client

    def exception_caught(self, ctx, exception):
        super().exception_caught(ctx, exception)
        ctx.close()

    def channel_active(self, ctx):
        super().channel_active(ctx)
        self.raddr = ctx.channel().socket().getpeername()
        pstderr(f"Connection opened: {self.raddr}")
        _clients[self.raddr]

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        if self._client is None:
            if self._white_list and not _check_patterns(self._white_list, ctx.channel().socket().getpeername()[0]):
                pstderr(f"malicious visitor: {ctx.channel().socket().getpeername()}")
                self._client_channel(ctx, self._disguise_tls_ip, self._disguise_tls_port)
            else:
                self._client_channel(ctx, self._remote_host, self._remote_port)

        _handle(bytebuf, True, ctx.channel().socket(), self._client.socket(), self._content, self._to_file)
        self._client.write(bytebuf)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)
        if hasattr(self, 'raddr'):
            pstderr(f"Connection closed: {self.raddr}")
            del _clients[self.raddr]
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
        self.wfile.write(_random_sentence().encode('utf-8'))


@click.command(short_help="Simple proxy", context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--local-server', '-l', default='localhost', help='Local server address', show_default=True)
@click.option('--local-port', '-lp', type=int, default=8080, help='Local port', show_default=True)
@click.option('--remote-server', '-r', default='localhost', help='Remote server address', show_default=True)
@click.option('--remote-port', '-rp', type=int, default=80, help='Remote port', show_default=True)
@click.option('--global', '-g', 'using_global', is_flag=True, help='Listen on 0.0.0.0')
@click.option('--tcp-flow', '-c', 'content', is_flag=True, help='Dump tcp flow on to console')
@click.option('--save-tcp-flow', '-f', 'to_file', is_flag=True, help='Save tcp flow to file')
@click.option('--tls', '-s', is_flag=True, help='Denote remote server listening on secure port')
@click.option('-ss', is_flag=True, help='Denote local sever listening on secure port')
@click.option('--key-file', '-kf', help='Key file for local server', type=click.Path(exists=True))
@click.option('--cert-file', '-cf', help='Certificate file for local server', type=click.Path(exists=True))
@click.option('--speed-monitor', is_flag=True, help='Print speed info to console for established connection')
@click.option('--speed-monitor-interval', type=int, default=5, help='Speed monitor interval', show_default=True)
@click.option('--disguise-tls-ip', '-dti', help='Disguise TLS IP')
@click.option('--disguise-tls-port', '-dtp', type=int, help='Disguise TLS port', default=443, show_default=True)
@click.option('--white-list', '-wl', help='IP White list for incoming connections (comma separated)')
@click.option('--run-mock-tls-server', is_flag=True, help='Run mock TLS server')
@click.option('--verbose', '-v', is_flag=True, help='Verbose mode')
def _cli(verbose, **kwargs):
    if verbose:
        _setup_logging(logging.INFO)
        logger.setLevel(logging.DEBUG)
    run_proxy(**kwargs)


def run_proxy(
        local_server, local_port,
        remote_server, remote_port,
        using_global,
        content, to_file,
        tls, ss,
        key_file, cert_file,
        speed_monitor, speed_monitor_interval,
        disguise_tls_ip, disguise_tls_port,
        white_list,
        run_mock_tls_server
):
    if tls and (disguise_tls_ip or run_mock_tls_server):
        pfatal("'--tls/-s' is not applicable if disguise is used!")
    if not white_list and (disguise_tls_ip or run_mock_tls_server):
        pstderr("[WARN] disguise is not took effect if '--white-list/-wl' is not specified")

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
        disguise_tls_port = _free_port()
        server_address = (disguise_tls_ip, disguise_tls_port)
        kf_mock, cf_mock = create_temp_key_cert(True)
        httpd = http.server.HTTPServer(server_address, MyHttpHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                       server_side=True,
                                       certfile=cf_mock,
                                       keyfile=kf_mock,
                                       ssl_version=ssl.PROTOCOL_TLS)
        _submit_daemon_thread(httpd.serve_forever)

    client_eventloop_group = EventLoopGroup(1, 'Client')
    sb = ServerBootstrap(
        parant_group=EventLoopGroup(1, 'Boss'),
        child_group=EventLoopGroup(1, 'Worker'),
        child_handler_initializer=lambda: ProxyChannelHandler(
            remote_server, remote_port,
            client_eventloop_group,
            tls=tls,
            content=content, to_file=to_file,
            disguise_tls_ip=disguise_tls_ip, disguise_tls_port=disguise_tls_port,
            white_list=white_list
        ),
        certfile=cf,
        keyfile=kf,
    )
    disguise = f"https://{disguise_tls_ip}:{disguise_tls_port}" if disguise_tls_ip else 'n/a'
    pstderr(f"Proxy server started listening: {local_server}:{local_port}{'(TLS)' if ss else ''} => {remote_server}:{remote_port}{'(TLS)' if tls else ''} ...")
    pstderr(f"console:{content}, file:{to_file}, disguise:{disguise}, whitelist:{white_list0 or '*'}")

    if speed_monitor:
        import signal
        _submit_daemon_thread(_clients_check, speed_monitor_interval)

        def _signal_handler(sig, frame):
            global _speed_monitor
            _speed_monitor = False
            signal.default_int_handler(sig, frame)
            signal.signal(signal.SIGINT, signal.default_int_handler)

        signal.signal(signal.SIGINT, _signal_handler)
    sb.bind(address=local_server, port=local_port).close_future().sync()


def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def generate_self_signed_cert(private_key, subject_name, valid_days=365):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Simple Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    issuer = subject

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=valid_days)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(subject_name),
        ]),
        critical=False,
    ).sign(
        private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return cert


def save_key_and_cert(private_key, cert, key_file_path, cert_file_path):
    # Save private key
    with open(key_file_path, 'wb') as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save certificate
    with open(cert_file_path, 'wb') as cert_file:
        cert_file.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )


def create_temp_file(filename):
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, filename)
    with open(file_path, 'w'):
        pass
    return file_path


def create_temp_key_cert(is_for_mock=False):
    kf_obj = generate_private_key()
    cf_obj = generate_self_signed_cert(kf_obj, 'localhost')
    kf = create_temp_file('key.pem')
    cf = create_temp_file('cert.pem')
    if is_for_mock:
        logger.debug(f"[Mock] Generated key and cert: {kf}, {cf}")
    else:
        logger.debug(f"Generated key and cert: {kf}, {cf}")
    save_key_and_cert(kf_obj, cf_obj, kf, cf)
    return kf, cf


def _free_port():
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_socket.bind(('localhost', 0))
    _, port = temp_socket.getsockname()
    temp_socket.close()
    return port


def _run():
    global _stderr
    _stderr = True
    _cli()


def _test_pattern_to_regex():
    assert _pattern_to_regex('*.example.com') == r'.*\.example\.com'
    assert _pattern_to_regex('example.com') == r'example\.com'
    assert _pattern_to_regex('example.*.com') == r'example\..*\.com'
    assert _pattern_to_regex('example.com.*') == r'example\.com\..*'


if __name__ == '__main__':
    _test_pattern_to_regex()
    _stderr = True
    run_proxy(
        local_server='localhost', local_port=8080,
        remote_server='www.google.com', remote_port=80,
        tls=False, ss=False,
        content=False, to_file=False,
        key_file='', cert_file='',
        speed_monitor=False, speed_monitor_interval=5,
        disguise_tls_ip='', disguise_tls_port=0,
        white_list=None,
        using_global=False,
    )
