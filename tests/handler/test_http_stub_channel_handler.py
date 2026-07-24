from unittest.mock import call

import pytest

from simple_proxy.handler.http_stub_channel_handler import HttpStubChannelHandler


@pytest.fixture
def ctx_mocker(mocker):
    ctx = mocker.MagicMock()
    ctx.channel.return_value.channelinfo.return_value.peername = ('127.0.0.1', 12345)
    return ctx


def test_fragmented_request_with_body(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.channel_read(ctx_mocker, b'POST /items HTTP/1.1\r\nHost: local')
    ctx_mocker.write.assert_not_called()

    handler.channel_read(ctx_mocker, b'host\r\nContent-Length: 5\r\n\r\nhe')
    ctx_mocker.write.assert_not_called()

    handler.channel_read(ctx_mocker, b'llo')
    ctx_mocker.write.assert_called_once_with(
        b'HTTP/1.1 200 OK\r\n'
        b'Content-Length: 0\r\n'
        b'Connection: keep-alive\r\n'
        b'\r\n'
    )
    ctx_mocker.close.assert_not_called()


def test_keep_alive_and_pipelined_requests(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.channel_read(
        ctx_mocker,
        b'GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n'
        b'PATCH /two HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx',
    )

    response = (
        b'HTTP/1.1 200 OK\r\n'
        b'Content-Length: 0\r\n'
        b'Connection: keep-alive\r\n'
        b'\r\n'
    )
    assert ctx_mocker.write.call_args_list == [call(response), call(response)]
    ctx_mocker.close.assert_not_called()


@pytest.mark.parametrize(
    ('raw_request', 'version'),
    [
        (b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n', b'HTTP/1.0'),
        (
            b'DELETE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n',
            b'HTTP/1.1',
        ),
        (
            b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n',
            b'HTTP/1.1',
        ),
    ],
)
def test_requests_that_close_connection(ctx_mocker, raw_request, version):
    handler = HttpStubChannelHandler()

    handler.channel_read(ctx_mocker, raw_request)

    response = ctx_mocker.write.call_args.args[0]
    assert response.startswith(version + b' 200 OK\r\n')
    assert b'Connection: close\r\n' in response
    ctx_mocker.close.assert_called_once()


def test_http_1_0_keep_alive(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.channel_read(
        ctx_mocker,
        b'OPTIONS * HTTP/1.0\r\nConnection: keep-alive\r\n\r\n',
    )

    assert b'Connection: keep-alive\r\n' in ctx_mocker.write.call_args.args[0]
    ctx_mocker.close.assert_not_called()


def test_expect_100_continue_before_body(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.channel_read(
        ctx_mocker,
        b'POST /upload HTTP/1.1\r\n'
        b'Host: localhost\r\n'
        b'Content-Length: 5\r\n'
        b'Expect: 100-continue\r\n\r\n',
    )

    ctx_mocker.write.assert_called_once_with(b'HTTP/1.1 100 Continue\r\n\r\n')

    handler.channel_read(ctx_mocker, b'hello')

    assert ctx_mocker.write.call_count == 2
    assert ctx_mocker.write.call_args.args[0].startswith(b'HTTP/1.1 200 OK\r\n')


def test_chunked_request_returns_200_and_closes(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.channel_read(
        ctx_mocker,
        b'POST / HTTP/1.1\r\n'
        b'Host: localhost\r\n'
        b'Transfer-Encoding: chunked\r\n\r\n'
        b'5\r\nhello\r\n0\r\n\r\n',
    )

    assert ctx_mocker.write.call_args.args[0].startswith(b'HTTP/1.1 200 OK\r\n')
    ctx_mocker.close.assert_called_once()
    assert handler._buffer == b''


@pytest.mark.parametrize(
    'raw_request',
    [
        b'BROKEN\r\n\r\n',
        b'POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n',
        b'GET / HTTP/2\r\nHost: localhost\r\n\r\n',
    ],
)
def test_invalid_request_returns_200_and_closes(ctx_mocker, raw_request):
    handler = HttpStubChannelHandler()

    handler.channel_read(ctx_mocker, raw_request)

    assert ctx_mocker.write.call_args.args[0].startswith(b'HTTP/1.1 200 OK\r\n')
    assert b'Connection: close\r\n' in ctx_mocker.write.call_args.args[0]
    ctx_mocker.close.assert_called_once()


def test_oversized_headers_return_200_and_close(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.channel_read(ctx_mocker, b'GET / HTTP/1.1\r\nX-Large: ' + b'x' * 65536)

    assert ctx_mocker.write.call_args.args[0].startswith(b'HTTP/1.1 200 OK\r\n')
    ctx_mocker.close.assert_called_once()
    assert handler._buffer == b''


def test_default_output_is_request_summary(mocker, ctx_mocker):
    output = mocker.patch(
        'simple_proxy.handler.http_stub_channel_handler.pstderr'
    )
    handler = HttpStubChannelHandler()

    handler.channel_read(
        ctx_mocker,
        b'GET /summary HTTP/1.1\r\nHost: localhost\r\n\r\n',
    )

    output.assert_called_once()
    message = output.call_args.args[0]
    assert '[127.0.0.1:12345] GET /summary HTTP/1.1' in message
    assert 'Host: localhost' not in message


def test_detailed_output_includes_headers_and_truncated_body(mocker, ctx_mocker):
    output = mocker.patch(
        'simple_proxy.handler.http_stub_channel_handler.pstderr'
    )
    handler = HttpStubChannelHandler(content=True)
    body = b'x' * 1500

    handler.channel_read(
        ctx_mocker,
        (
            b'PUT /details HTTP/1.1\r\n'
            b'Host: localhost\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'Content-Length: 1500\r\n\r\n'
            + body
        ),
    )

    assert output.call_count == 2
    details = output.call_args.args[0]
    assert '[127.0.0.1:12345] Host: localhost' in details
    assert '[127.0.0.1:12345] Content-Type: application/octet-stream' in details
    assert details.count('x') == 1024
    assert 'body truncated at 1024 of 1500 bytes' in details


def test_exception_closes_connection(ctx_mocker):
    handler = HttpStubChannelHandler()

    handler.exception_caught(ctx_mocker, RuntimeError("broken"))

    ctx_mocker.close.assert_called_once()
