from ..handler.proxy_channel_handler import ProxyChannelHandler
from ..clients import get_client_or_none


class EchoChannelHandler(ProxyChannelHandler):

    def __init__(
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

    def _create_client(self, ctx, bytebuf: bytes | None):
        # no need to create a client
        pass
