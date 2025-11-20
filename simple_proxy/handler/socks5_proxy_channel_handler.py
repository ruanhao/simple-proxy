import logging
import socket
from py_netty import Bootstrap
from py_netty.handler import LoggingChannelHandler
from ..clients import handle_data, get_client_or_create, pop_client
from ..utils.logutils import pstderr
from ..utils.netutils import set_keepalive

logger = logging.getLogger(__name__)

_local_peer_to_target_mapping: dict[str, str] = dict()


def get_local_peer_to_target_mapping() -> dict[str, str]:
    return _local_peer_to_target_mapping


class Socks5ProxyChannelHandler(LoggingChannelHandler):
    def __init__(
            self,
            client_eventloop_group,
            content=False, to_file=False,
            transform: tuple[tuple[str, int, str, int]] = None,
            http_proxy_username=None, http_proxy_password=None,
    ):
        self._client_eventloop_group = client_eventloop_group
        self._client = None
        self._negotiated = False
        self._authenticated = True
        self._after_authenticated = False
        self._handshake_done = False
        self._buffer = b''
        self._content = content
        self._to_file = to_file
        self._transform = transform
        self._http_proxy_username = http_proxy_username
        self._http_proxy_password = http_proxy_password
        self.raddr = None

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
        if self._after_authenticated:
            if len(self._buffer) < 10:
                return
            if self._buffer[0] != 0x05:
                pstderr(f"[SOCKS5 Proxy|PostAuth] Unsupported SOCKS version: {self._buffer[0]}")
                ctx.close()
                return
            if self._buffer[1] != 0x01:
                pstderr(f"[SOCKS5 Proxy|PostAuth] Unsupported CMD: {self._buffer[1]}")
                ctx.close()
                return
            addr_type = self._buffer[3]
            if addr_type == 0x01:  # IPv4
                if len(self._buffer) < 10:
                    return
                addr = socket.inet_ntoa(self._buffer[4:8])
                port = int.from_bytes(self._buffer[8:10], 'big')
            elif addr_type == 0x03:  # Domain name
                domain_length = self._buffer[4]
                if len(self._buffer) < 5 + domain_length + 2:
                    return
                addr = self._buffer[5:5 + domain_length].decode('utf-8')
                port = int.from_bytes(self._buffer[5 + domain_length:5 + domain_length + 2], 'big')
            elif addr_type == 0x04:  # IPv6
                pstderr("[SOCKS5 Proxy|PostAuth] IPv6 not supported")
                ctx.close()
                return
            else:
                pstderr(f"[SOCKS5 Proxy|PostAuth] Unsupported ADDR TYPE: {addr_type}")
                ctx.close()
                return
            origin_addr, origin_port = addr, port
            host, port = self._transform_host_port(origin_addr, origin_port)
            get_client_or_create(self.raddr).proxy_socket = self._client_channel(ctx, host, int(port)).socket()
            ctx.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
            peer_name, peer_port = ctx.channel().channelinfo().peername
            peer = f"{peer_name}:{peer_port}"
            get_local_peer_to_target_mapping()[peer] = f"{host}:{port}"
            self._print_record(ctx.channel().id(), peer, origin_addr, origin_port, host, port)
            self._buffer = b''
            self._negotiated = True
        elif not self._authenticated:
            if len(self._buffer) < 3:
                return
            if self._buffer[0] != 0x01:
                pstderr(f"[SOCKS5 Proxy|Auth] Unsupported SOCKS version: {self._buffer[0]}")
                ctx.close()
                return
            ulen = self._buffer[1]
            if len(self._buffer) < 3 + ulen:
                return
            username = self._buffer[2:2 + ulen].decode('utf-8')
            plen = self._buffer[2 + ulen]
            if len(self._buffer) < 3 + ulen + plen:
                return
            password = self._buffer[3 + ulen:3 + ulen + plen].decode('utf-8')
            if (username != self._http_proxy_username) or (password != self._http_proxy_password):
                pstderr(f"[SOCKS5 Proxy|Auth] Authentication failed for user: {username}")
                ctx.close()
                return
            ctx.write(bytes([0x01, 0x00]))  # VER, STATUS (SUCCESS)
            self._authenticated = True
            self._after_authenticated = True
            self._buffer = b''
        elif not self._handshake_done:
            if len(self._buffer) < 2:  # VER, NMETHODS
                return
            if self._buffer[0] != 0x05:
                pstderr(f"[SOCKS5 Proxy|Handshake] Unsupported SOCKS version: {self._buffer[0]}")
                ctx.close()
                return
            nmethods = self._buffer[1]
            if len(self._buffer) < 2 + nmethods:
                return
            methods = self._buffer[2:2 + nmethods]
            self._buffer = b''
            # Send METHOD SELECTION MESSAGE
            # pstderr(f"[SOCKS5 Proxy] Selecting authentication method: {methods}")
            if self._http_proxy_username and self._http_proxy_password and 0x02 not in methods:
                pstderr("[SOCKS5 Proxy] USERNAME/PASSWORD authentication required but not supported by client")
                ctx.close()
                return
            if 0x02 in methods:
                # pstderr("[SOCKS5 Proxy] Using USERNAME/PASSWORD authentication")
                ctx.write(bytes([0x05, 0x02]))  # VER, METHOD (USERNAME/PASSWORD)
                self._authenticated = False
            elif 0x00 in methods:
                ctx.write(bytes([0x05, 0x00]))  # VER, METHOD (NO AUTHENTICATION)
                self._handshake_done = True
                return
            else:
                pstderr("[SOCKS5 Proxy] No acceptable authentication methods")
                ctx.close()
                return
        else:               # Handshake done
            if len(self._buffer) < 4:
                return
            if self._buffer[0] != 0x05 or self._buffer[1] != 0x01 or self._buffer[2] != 0x00:
                pstderr(f"[SOCKS5 Proxy] Unsupported SOCKS5 request: VER={self._buffer[0]}, CMD={self._buffer[1]}, RSV={self._buffer[2]}")
                ctx.close()
                return
            addr_type = self._buffer[3]
            if addr_type == 0x01:  # IPv4
                addr_len = 4
            elif addr_type == 0x03:  # DOMAINNAME
                if len(self._buffer) < 5:
                    return
                addr_len = self._buffer[4] + 1
            elif addr_type == 0x04:  # IPv6
                # addr_len = 16
                pstderr("[SOCKS5 Proxy] Unsupported address type: IPv6")
                ctx.close()
                return
            else:
                pstderr(f"[SOCKS5 Proxy] Unsupported address type: {addr_type}")
                ctx.close()
                return
            if len(self._buffer) < 4 + addr_len + 2:
                return
            # Parse DST.ADDR and DST.PORT
            if addr_type == 0x01:  # IPv4
                dst_addr = socket.inet_ntoa(self._buffer[4:8])
                dst_port = int.from_bytes(self._buffer[8:10], 'big')
            elif addr_type == 0x03:  # DOMAINNAME
                dst_addr = self._buffer[5:5 + addr_len - 1].decode()
                dst_port = int.from_bytes(self._buffer[5 + addr_len - 1:5 + addr_len + 1], 'big')
            else:           # impossible
                pstderr(f"[SOCKS5 Proxy] Unsupported address type during parsing: {addr_type}")
                ctx.close()
                return

            # Create connection to target
            host, port = self._transform_host_port(dst_addr, dst_port)
            get_client_or_create(self.raddr).proxy_socket = self._client_channel(ctx, host, int(port)).socket()

            # Send SERVER RESPONSE
            # resp = bytearray()
            # resp.append(0x05)  # VER
            # resp.append(0x00)  # REP (SUCCEEDED)
            # resp.append(0x00)  # RSV
            # resp.append(0x01)  # ATYP (IPv4)
            # ctx.write(resp + b'\x00\x00\x00\x00' + b'\x00\x00')  # BND.ADDR and BND.PORT
            ctx.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Success response
            # Print record
            peer_name, peer_port = ctx.channel().channelinfo().peername
            peer = f"{peer_name}:{peer_port}"
            get_local_peer_to_target_mapping()[peer] = f"{host}:{port}"
            self._print_record(ctx.channel().id(), peer, dst_addr, dst_port, host, port)
            self._negotiated = True
            self._buffer = b''

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
