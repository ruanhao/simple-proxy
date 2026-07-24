import os
from datetime import datetime

from py_netty.handler import LoggingChannelHandler

from ..utils.logutils import pstderr
from ..utils.netutils import format_sockaddr


class HttpStubChannelHandler(LoggingChannelHandler):

    MAX_HEADER_SIZE = 64 * 1024
    BODY_PREVIEW_SIZE = 1024

    def __init__(self, content=False):
        self._content = content
        self._buffer = b''
        self._request = None
        self._remaining_body = 0
        self._body_preview = bytearray()

    @staticmethod
    def _parse_request(header_block):
        text = header_block.decode('iso-8859-1')
        lines = text.split('\r\n')
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) != 3:
            raise ValueError("Invalid HTTP request line")

        method, target, version = parts
        if version not in ('HTTP/1.0', 'HTTP/1.1'):
            raise ValueError(f"Unsupported HTTP version: {version}")

        headers = []
        header_values = {}
        for line in lines[1:]:
            if not line or ':' not in line:
                raise ValueError("Invalid HTTP header")
            name, value = line.split(':', 1)
            name = name.strip()
            value = value.strip()
            if not name:
                raise ValueError("Invalid HTTP header name")
            headers.append((name, value))
            header_values.setdefault(name.lower(), []).append(value)

        content_lengths = header_values.get('content-length', [])
        if content_lengths:
            if len(set(content_lengths)) != 1 or not content_lengths[0].isdigit():
                raise ValueError("Invalid Content-Length")
            content_length = int(content_lengths[0])
        else:
            content_length = 0

        transfer_encoding = ','.join(header_values.get('transfer-encoding', []))
        unsupported_transfer_encoding = bool(
            transfer_encoding and transfer_encoding.lower() != 'identity'
        )

        connection_tokens = {
            token.strip().lower()
            for value in header_values.get('connection', [])
            for token in value.split(',')
        }
        expect_tokens = {
            token.strip().lower()
            for value in header_values.get('expect', [])
            for token in value.split(',')
        }
        close_connection = (
            method.upper() == 'CONNECT'
            or unsupported_transfer_encoding
            or 'close' in connection_tokens
            or (version == 'HTTP/1.0' and 'keep-alive' not in connection_tokens)
        )

        return {
            'method': method,
            'target': target,
            'version': version,
            'request_line': request_line,
            'headers': headers,
            'content_length': content_length,
            'unsupported_transfer_encoding': unsupported_transfer_encoding,
            'expects_continue': (
                version == 'HTTP/1.1'
                and content_length > 0
                and '100-continue' in expect_tokens
            ),
            'close_connection': close_connection,
        }

    @staticmethod
    def _peer(ctx):
        return format_sockaddr(ctx.channel().channelinfo().peername)

    def _print_request(self, ctx):
        peer = self._peer(ctx)
        request = self._request
        timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
        pstderr(f"{timestamp} [{peer}] {request['request_line']}")

        if not self._content:
            return

        lines = [f"[{peer}] {request['request_line']}"]
        lines.extend(f"[{peer}] {name}: {value}" for name, value in request['headers'])
        if self._body_preview:
            body = bytes(self._body_preview).decode('utf-8', errors='replace')
            lines.append(f"[{peer}]")
            lines.extend(f"[{peer}] {line}" for line in body.splitlines())
            if request['content_length'] > len(self._body_preview):
                lines.append(
                    f"[{peer}] ... [body truncated at {len(self._body_preview)} "
                    f"of {request['content_length']} bytes]"
                )
        pstderr(os.linesep.join(lines))

    @staticmethod
    def _response(version, close_connection):
        connection = 'close' if close_connection else 'keep-alive'
        return (
            f"{version} 200 OK\r\n"
            "Content-Length: 0\r\n"
            f"Connection: {connection}\r\n"
            "\r\n"
        ).encode('ascii')

    def _write_response(self, ctx, version, close_connection):
        ctx.write(self._response(version, close_connection))
        if close_connection:
            ctx.close()

    def _finish_request(self, ctx):
        request = self._request
        self._print_request(ctx)
        self._write_response(
            ctx,
            request['version'],
            request['close_connection'],
        )
        close_connection = request['close_connection']
        self._request = None
        self._remaining_body = 0
        self._body_preview = bytearray()
        return close_connection

    def _handle_invalid_request(self, ctx, reason):
        peer = self._peer(ctx)
        pstderr(f"[HTTP Stub] Invalid request from {peer}: {reason}")
        self._buffer = b''
        self._request = None
        self._remaining_body = 0
        self._body_preview = bytearray()
        self._write_response(ctx, 'HTTP/1.1', True)

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        if not bytebuf:
            return

        self._buffer += bytebuf
        while True:
            if self._request is None:
                header_end = self._buffer.find(b'\r\n\r\n')
                if header_end < 0:
                    if len(self._buffer) > self.MAX_HEADER_SIZE:
                        self._handle_invalid_request(ctx, "request headers are too large")
                    return
                if header_end > self.MAX_HEADER_SIZE:
                    self._handle_invalid_request(ctx, "request headers are too large")
                    return

                header_block = self._buffer[:header_end]
                self._buffer = self._buffer[header_end + 4:]
                try:
                    self._request = self._parse_request(header_block)
                except ValueError as e:
                    self._handle_invalid_request(ctx, str(e))
                    return

                self._remaining_body = self._request['content_length']
                if self._request['unsupported_transfer_encoding']:
                    self._finish_request(ctx)
                    self._buffer = b''
                    return
                if self._request['expects_continue'] and self._remaining_body:
                    ctx.write(b'HTTP/1.1 100 Continue\r\n\r\n')

            if self._remaining_body:
                consumed = min(self._remaining_body, len(self._buffer))
                preview_remaining = self.BODY_PREVIEW_SIZE - len(self._body_preview)
                if preview_remaining:
                    preview_size = min(consumed, preview_remaining)
                    self._body_preview.extend(self._buffer[:preview_size])
                self._buffer = self._buffer[consumed:]
                self._remaining_body -= consumed
                if self._remaining_body:
                    return

            if self._finish_request(ctx):
                self._buffer = b''
                return
            if not self._buffer:
                return

    def exception_caught(self, ctx, exception):
        super().exception_caught(ctx, exception)
        ctx.close()
