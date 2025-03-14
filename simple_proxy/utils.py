import inspect
import os
import base64
import platform
import random
import socket
import tempfile
import threading
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
import logging
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from attrs import define, field
import re
import itertools

logger = logging.getLogger(__name__)
_counter = itertools.count()


@define(slots=True, kw_only=True, order=True)
class ProxyInfo():

    host: str = field()
    port: int = field()
    username: str = field(default=None)
    password: str = field(default=None)


def submit_daemon_thread(func, *args, **kwargs) -> threading.Thread:
    if isinstance(func, partial):
        func_name = func.func.__name__
    else:
        func_name = func.__name__

    def _worker():
        func(*args, **kwargs)

    t = threading.Thread(target=_worker, name=f'{func_name}-daemon-{next(_counter)}', daemon=True)
    t.start()
    return t


def random_sentence():
    nouns = ("puppy", "car", "rabbit", "girl", "monkey")
    verbs = ("runs", "hits", "jumps", "drives", "barfs")
    adv = ("crazily.", "dutifully.", "foolishly.", "merrily.", "occasionally.")
    return nouns[random.randrange(0, 5)] + ' ' + \
        verbs[random.randrange(0, 5)] + ' ' + \
        adv[random.randrange(0, 5)] + '\n'


def pretty_duration(seconds: float) -> str:
    TIME_DURATION_UNITS = (
        ('W', 60 * 60 * 24 * 7 * 1000),
        ('D', 60 * 60 * 24 * 1000),
        ('H', 60 * 60 * 1000),
        ('M', 60 * 1000),
        ('S', 1 * 1000),
        ('MS', 1)
    )
    if seconds == 0:
        return '0S'
    parts = []
    milliseconds = int(seconds * 1000)
    for unit, div in TIME_DURATION_UNITS:
        amount, milliseconds = divmod(int(milliseconds), div)
        if amount > 0:
            parts.append('{}{}'.format(amount, unit))
    return ','.join(parts)


def format_bytes(size, scale=1):
    size = int(size)
    power = 2**10
    n = 0
    power_labels = {0 : 'B', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        size = round(size, scale)
        n += 1
    if size == int(size):
        size = int(size)
    return size, power_labels[n]


def pretty_bytes(size: int) -> str:
    v, unit = format_bytes(size)
    return f"{v}{unit}"


def pretty_speed(speed: int) -> str:
    return pretty_bytes(speed) + '/s'


def from_cwd(*args):
    absolute = Path(os.path.join(os.getcwd(), *args))
    absolute.parent.mkdir(parents=True, exist_ok=True)
    return absolute


def module_path(mod=None):
    if not mod:
        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])
    return os.path.dirname(mod.__file__)


def from_module(filename=None):
    frm = inspect.stack()[1]
    mod = inspect.getmodule(frm[0])
    if not filename:
        return module_path(mod)
    return os.path.join(module_path(mod), filename)


def _get_address_str(sock: socket.socket, peer: bool = False) -> str:
    if not sock:
        return '?'
    try:
        addr_tuple = sock.getpeername() if peer else sock.getsockname()
        return ':'.join(map(str, addr_tuple[:2]))
    except OSError:
        return '!'


def getpeername(sock: socket.socket) -> str:
    return _get_address_str(sock, peer=True)


def getsockname(sock: socket.socket) -> str:
    return _get_address_str(sock, peer=False)


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


def free_port():
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_socket.bind(('localhost', 0))
    _, port = temp_socket.getsockname()
    temp_socket.close()
    return port


def set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails):
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails):
    """Set TCP keepalive on an open socket.

    sends a keepalive ping once every 3 seconds (interval_sec)
    """
    # scraped from /usr/include, not exported by python's socket module
    TCP_KEEPALIVE = 0x10
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval_sec)


def set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails):
    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec * 1000, interval_sec * 1000))


def set_keepalive(sock, after_idle_sec=60, interval_sec=60, max_fails=5):
    plat = platform.system()
    if plat == 'Linux':
        set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    if plat == 'Darwin':
        set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails)
    if plat == 'Windows':
        set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails)


def trim_proxy_info(request_headers_bytes: bytes) -> bytes:
    if not request_headers_bytes:
        return request_headers_bytes
    # trimmed = re.sub(b'Proxy-Connection: keep-alive\r\n', b'', request_headers_bytes, flags=re.IGNORECASE)
    # trimmed = re.sub(b'Proxy-Authorization: Basic [a-zA-Z0-9+/=]+\r\n', b'', trimmed, flags=re.IGNORECASE)
    trimmed = request_headers_bytes
    trimmed = re.sub(b'Proxy-.*\r\n', b'', trimmed, flags=re.IGNORECASE)
    return trimmed


def parse_proxy_info(request_headers: str) -> ProxyInfo:
    # for CONNECT
    if request_headers.startswith('CONNECT'):  # https proxy
        match = re.search(r'CONNECT\s+([\w\.-]+):(\d+)\s+HTTP/.+\r\n', request_headers, re.IGNORECASE)
        if not match:
            raise ValueError("Invalid CONNECT request format")
        host, port = match.groups()
        port = int(port)
    else:                       # http proxy
        match_with_port = re.search(r'Host:\s+([\w\.-]+):(\d+)\r\n', request_headers, re.IGNORECASE)
        match_without_port = re.search(r'Host:\s+([\w\.-]+)\r\n', request_headers, re.IGNORECASE)
        if match_with_port:
            host, port = match_with_port.groups()
            port = int(port)
        elif match_without_port:
            host = match_without_port.group(1)
            port = 80
        else:
            raise ValueError("Invalid Host header format")

    # for Proxy-Authorization
    auth_match = re.search(r'Proxy-Authorization:\s+Basic\s+([\w=+/]+)', request_headers, re.IGNORECASE)
    username, password = None, None
    if auth_match:
        try:
            auth_decoded = base64.b64decode(auth_match.group(1)).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid Proxy-Authorization format: {e}")
        username, password = auth_decoded.split(':', 1)

    return ProxyInfo(host=host, port=port, username=username, password=password)
