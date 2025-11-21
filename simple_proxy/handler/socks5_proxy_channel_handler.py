import logging
import socket
from py_netty import Bootstrap
from py_netty.handler import LoggingChannelHandler
from ..clients import handle_data, get_client_or_create, pop_client
from ..utils.logutils import pstderr
from ..utils.netutils import set_keepalive
from enum import Enum

logger = logging.getLogger(__name__)

_local_peer_to_target_mapping: dict[str, str] = dict()


class Socks5State(str, Enum):
    HANDSHAKE = 'HANDSHAKE'
    AUTHENTICATION = 'AUTHENTICATION'
    REQUEST = 'REQUEST'

def get_local_peer_to_target_mapping() -> dict[str, str]:
    return _local_peer_to_target_mapping

# https://www.trickster.dev/post/understanding-socks-protocol/
class Socks5ProxyChannelHandler(LoggingChannelHandler):
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
        self._socks5_state = Socks5State.HANDSHAKE

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
        if not self._negotiated:
            ctx.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')  # General SOCKS server failure
        ctx.close()

    def channel_active(self, ctx):
        local_socket = ctx.channel().socket()
        set_keepalive(local_socket)
        self.raddr = local_socket.getpeername()
        get_client_or_create(self.raddr).local_socket = local_socket
        if logger.isEnabledFor(logging.DEBUG):
            pstderr(f"[SOCKS5 Proxy] Connection opened   : {ctx.channel()}")

    def _transform_host_port(self, origin_host: str, origin_port: int) -> tuple[str, int]:
        if self._transform:
            for h0, p0, h, p in self._transform:
                if h0 == origin_host and p0 == origin_port:
                    return h, p
        return origin_host, origin_port

    @staticmethod
    def _print_record(channel_id: str, peer: str, host0: str, port0: int, host: str, port: int):
        if host0 == host and port0 == port:
            pstderr(f"[SOCKS5 Proxy] Connection requests : {channel_id} | {peer} | {host0}:{port0}")
        else:
            pstderr(f"[SOCKS5 Proxy] Connection requests : {channel_id} | {peer} | {host0}:{port0} > {host}:{port}")


    def channel_read(self, ctx, bytebuf):  # noqa
        if self._negotiated:
            self._client.write(bytebuf)
            handle_data(bytebuf, True, ctx.channel(), self._client, self._content, self._to_file)
            return
        self._buffer += bytebuf
        while True:
            # print("=== SOCKS5 STATE:", self._socks5_state, "BUFFER LEN:", len(self._buffer))
            if self._socks5_state == Socks5State.HANDSHAKE:
                if len(self._buffer) < 2:  # VER, NMETHODS
                    return
                if self._buffer[0] != 0x05:
                    raise ValueError(f"[SOCKS5 Proxy|Handshake] Unsupported SOCKS version: {self._buffer[0]}")
                nmethods = self._buffer[1]
                if len(self._buffer) < 2 + nmethods:
                    return
                methods = self._buffer[2:2 + nmethods]
                self._buffer = self._buffer[2 + nmethods:]
                # Send METHOD SELECTION MESSAGE
                if self._proxy_username and self._proxy_password and 0x02 not in methods:
                    raise ValueError("[SOCKS5 Proxy|Handshake] USERNAME/PASSWORD authentication required but not set by client")
                if 0x02 in methods:
                    ctx.write(bytes([0x05, 0x02]))  # VER, METHOD (USERNAME/PASSWORD)
                    self._socks5_state = Socks5State.AUTHENTICATION

                elif 0x00 in methods:
                    ctx.write(bytes([0x05, 0x00]))  # VER, METHOD (NO AUTHENTICATION)
                    self._socks5_state = Socks5State.REQUEST
                else:
                    raise ValueError(f"[SOCKS5 Proxy|Handshake] No acceptable authentication methods: {methods}")
                if not self._buffer:
                    return
            elif self._socks5_state == Socks5State.REQUEST:
                if len(self._buffer) < 4:
                    return
                if self._buffer[0] != 0x05 or self._buffer[1] != 0x01:
                    raise ValueError(f"[SOCKS5 Proxy|Request] Unsupported SOCKS5 request: VER={self._buffer[0]}, CMD={self._buffer[1]}, RSV={self._buffer[2]}")
                addr_type = self._buffer[3]
                if addr_type == 0x01:  # IPv4
                    if len(self._buffer) < 10:  # VER, CMD, RSV, ATYP, ADDR(4), PORT(2)
                        return
                    dst_addr = socket.inet_ntoa(self._buffer[4:8])
                    dst_port = int.from_bytes(self._buffer[8:10], 'big')
                elif addr_type == 0x03:  # DOMAINNAME
                    if len(self._buffer) < 5:
                        return
                    domain_length = self._buffer[4]
                    if len(self._buffer) < 5 + domain_length + 2:  # VER, CMD, RSV, ATYP, DOMAIN LEN, ADDR(dlen), PORT(2)
                        return
                    dst_addr = self._buffer[5:5 + domain_length].decode('utf-8')
                    dst_port = int.from_bytes(self._buffer[5 + domain_length:5 + domain_length + 2], 'big')
                elif addr_type == 0x04:  # IPv6
                    raise ValueError("[SOCKS5 Proxy|Request] Unsupported address type: IPv6")
                else:
                    raise ValueError(f"[SOCKS5 Proxy|Request] Unsupported address type: {addr_type}")
                # Create connection to target
                host, port = self._transform_host_port(dst_addr, dst_port)
                get_client_or_create(self.raddr).proxy_socket = self._client_channel(ctx, host, int(port)).socket()
                ctx.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
                # Record the mapping
                peer_name, peer_port = ctx.channel().channelinfo().peername
                peer = f"{peer_name}:{peer_port}"
                get_local_peer_to_target_mapping()[peer] = f"{host}:{port}"
                self._print_record(ctx.channel().id(), peer, dst_addr, dst_port, host, port)
                self._buffer = b''
                self._negotiated = True
                return
            else:  # Socks5State.AUTHENTICATION:
                if len(self._buffer) < 2:
                    return
                if self._buffer[0] != 0x01:
                    raise ValueError(f"[SOCKS5 Proxy|Auth] Unsupported Auth version: {self._buffer[0]}")
                ulen = self._buffer[1]
                if len(self._buffer) < 3 + ulen:  # VER, ULEN, UNAME(ulen), PLEN
                    return
                username = self._buffer[2:2 + ulen].decode('utf-8')
                plen = self._buffer[2 + ulen]
                if len(self._buffer) < 2 + ulen + 1 + plen:  # VER, ULEN, UNAME(ulen), PLEN, PASSWD(plen)
                    return
                password = self._buffer[3 + ulen:3 + ulen + plen].decode('utf-8')
                if self._proxy_username and self._proxy_password:
                    if (username != self._proxy_username) or (password != self._proxy_password):
                        masked_password = '*' * len(password) if password else ''
                        # ctx.write(bytes([0x01, 0x01]))  # VER, STATUS(FAILURE)
                        raise ValueError(f"[SOCKS5 Proxy|Auth] Authentication failed: {username}/{masked_password}")
                ctx.write(bytes([0x01, 0x00]))  # VER, STATUS(SUCCESS)
                self._socks5_state = Socks5State.REQUEST
                self._buffer = self._buffer[3 + ulen + plen:]
                if not self._buffer:
                    return

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)
        if hasattr(self, 'raddr'):
            c = pop_client(self.raddr)
            if logger.isEnabledFor(logging.DEBUG):
                if c:
                    pstderr(f"[SOCKS5 Proxy] Connection closed   : {ctx.channel()}, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")
                else:
                    pstderr(f"[SOCKS5 Proxy] Connection closed   : {ctx.channel()}")
        if self._client:
            self._client.close()
        peer_name, peer_port = ctx.channel().channelinfo().peername
        peer = f"{peer_name}:{peer_port}"
        get_local_peer_to_target_mapping().pop(peer, None)
