import http.client
import json
import os
import threading
from functools import partial

import pytest

from simple_proxy.file_server import (
    FileServerRequestHandler,
    WorkerPoolHTTPServer,
    run_file_server,
)


@pytest.fixture
def file_server(tmp_path):
    handler = partial(FileServerRequestHandler, directory=tmp_path)
    server = WorkerPoolHTTPServer(('127.0.0.1', 0), handler, workers=2)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, tmp_path
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def request(server, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection(
        '127.0.0.1',
        server.server_port,
        timeout=3,
    )
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_headers = {
            name.lower(): value
            for name, value in response.headers.items()
        }
        return response.status, response_headers, response.read()
    finally:
        connection.close()


def multipart_body(parts, boundary='simple-proxy-boundary'):
    chunks = []
    for part in parts:
        chunks.append(f'--{boundary}\r\n'.encode())
        disposition = f'Content-Disposition: form-data; name="{part["name"]}"'
        if 'filename' in part:
            disposition += f'; filename="{part["filename"]}"'
        chunks.append((disposition + '\r\n').encode())
        if 'filename' in part:
            chunks.append(b'Content-Type: application/octet-stream\r\n')
        chunks.append(b'\r\n')
        chunks.append(part.get('content', b''))
        chunks.append(b'\r\n')
    chunks.append(f'--{boundary}--\r\n'.encode())
    body = b''.join(chunks)
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Content-Length': str(len(body)),
    }
    return body, headers


def test_download_file_and_head(file_server):
    server, root = file_server
    (root / 'hello.txt').write_bytes(b'hello\n')

    status, headers, body = request(server, 'GET', '/hello.txt')

    assert status == 200
    assert headers['content-length'] == '6'
    assert headers['content-type'].startswith('text/plain')
    assert 'last-modified' in headers
    assert body == b'hello\n'

    status, headers, body = request(server, 'HEAD', '/hello.txt')

    assert status == 200
    assert headers['content-length'] == '6'
    assert body == b''


def test_missing_file_returns_not_found(file_server):
    server, _ = file_server

    status, _, _ = request(server, 'GET', '/missing.txt')

    assert status == 404


def test_directory_listing_has_details_sorting_and_escaping(file_server):
    server, root = file_server
    nested = root / 'nested'
    nested.mkdir()
    (nested / 'z.txt').write_bytes(b'z')
    (nested / 'A&b.txt').write_bytes(b'content')
    (nested / 'subdir').mkdir()

    status, headers, body = request(server, 'GET', '/nested/')
    text = body.decode()

    assert status == 200
    assert headers['content-type'] == 'text/html; charset=utf-8'
    assert 'Index of /nested/' in text
    assert 'Name' in text
    assert 'Last Modified' in text
    assert 'Size' in text
    assert 'Parent Directory' in text
    assert 'A&amp;b.txt' in text
    assert 'A%26b.txt' in text
    assert 'subdir/' in text
    assert '<td align="right">7</td>' in text
    assert text.index('A&amp;b.txt') < text.index('z.txt')


def test_directory_redirect_preserves_query(file_server):
    server, root = file_server
    (root / 'nested').mkdir()

    status, headers, body = request(server, 'GET', '/nested?download=1')

    assert status == 301
    assert headers['location'] == '/nested/?download=1'
    assert body == b''


@pytest.mark.parametrize('index_name', ['index.html', 'index.htm'])
def test_directory_serves_index_file(file_server, index_name):
    server, root = file_server
    nested = root / 'nested'
    nested.mkdir()
    (nested / index_name).write_text('index content', encoding='utf-8')

    status, _, body = request(server, 'GET', '/nested/')

    assert status == 200
    assert body == b'index content'


def test_index_html_takes_precedence(file_server):
    server, root = file_server
    (root / 'index.html').write_text('html', encoding='utf-8')
    (root / 'index.htm').write_text('htm', encoding='utf-8')

    _, _, body = request(server, 'GET', '/')

    assert body == b'html'


def test_index_symlink_cannot_escape_served_root(file_server, tmp_path):
    server, root = file_server
    outside = tmp_path.parent / f'{tmp_path.name}-index.html'
    outside.write_bytes(b'secret index')
    link = root / 'index.html'
    try:
        link.symlink_to(outside)
    except OSError as e:
        pytest.skip(f'symlinks unavailable: {e}')

    status, _, body = request(server, 'GET', '/')

    assert status == 404
    assert b'secret index' not in body


def test_favicon_behavior(file_server):
    server, _ = file_server

    status, _, body = request(server, 'GET', '/favicon.ico')
    assert status == 204
    assert body == b''

    status, headers, _ = request(server, 'POST', '/favicon.ico')
    assert status == 405
    assert headers['allow'] == 'GET, HEAD'


def test_upload_page_contains_form_and_progress_script(file_server):
    server, _ = file_server

    status, headers, body = request(server, 'GET', '/upload')
    text = body.decode()

    assert status == 200
    assert headers['content-type'] == 'text/html; charset=utf-8'
    assert 'enctype="multipart/form-data"' in text
    assert 'name="file"' in text
    assert '<progress id="upload-progress"' in text
    assert 'xhr.upload.onprogress' in text
    assert 'xhr.setRequestHeader("Accept", "application/json")' in text


def test_upload_returns_html_and_overwrites_existing_file(file_server):
    server, root = file_server
    (root / 'hello.txt').write_bytes(b'old')
    body, headers = multipart_body([
        {'name': 'file', 'filename': 'hello.txt', 'content': b'new content'},
    ])

    status, response_headers, response_body = request(
        server,
        'POST',
        '/upload',
        body,
        headers,
    )

    assert status == 200
    assert response_headers['content-type'] == 'text/html; charset=utf-8'
    assert b'Upload Complete' in response_body
    assert b'hello.txt' in response_body
    assert b'11 bytes' in response_body
    assert (root / 'hello.txt').read_bytes() == b'new content'


def test_upload_streams_binary_file_and_returns_json(file_server):
    server, root = file_server
    content = os.urandom(FileServerRequestHandler.READ_CHUNK_SIZE * 2 + 19)
    body, headers = multipart_body([
        {'name': 'description', 'content': b'test'},
        {'name': 'file', 'filename': 'data.bin', 'content': content},
        {'name': 'after', 'content': b'value'},
    ])
    headers['Accept'] = 'text/html, application/json'

    status, response_headers, response_body = request(
        server,
        'POST',
        '/upload',
        body,
        headers,
    )

    assert status == 200
    assert response_headers['content-type'] == 'application/json'
    assert json.loads(response_body) == {
        'name': 'data.bin',
        'size': len(content),
        'url': '/data.bin',
    }
    assert (root / 'data.bin').read_bytes() == content

    status, _, downloaded = request(server, 'GET', '/data.bin')
    assert status == 200
    assert downloaded == content


@pytest.mark.parametrize('filename', ['', '.', '..', '../escape.txt', 'a/b.txt', r'a\b.txt'])
def test_upload_rejects_unsafe_filename(file_server, filename):
    server, root = file_server
    body, headers = multipart_body([
        {'name': 'file', 'filename': filename, 'content': b'escape'},
    ])

    status, _, _ = request(server, 'POST', '/upload', body, headers)

    assert status == 400
    assert list(root.iterdir()) == []


def test_upload_rejects_missing_file_and_malformed_body(file_server):
    server, root = file_server
    body, headers = multipart_body([
        {'name': 'description', 'content': b'no file'},
    ])

    status, _, _ = request(server, 'POST', '/upload', body, headers)
    assert status == 400

    truncated, headers = multipart_body([
        {'name': 'file', 'filename': 'partial.txt', 'content': b'partial'},
    ])
    truncated = truncated[:-10]
    headers['Content-Length'] = str(len(truncated))
    status, _, _ = request(server, 'POST', '/upload', truncated, headers)

    assert status == 400
    assert not (root / 'partial.txt').exists()
    assert not list(root.glob('.simple-proxy-upload-*'))


def test_upload_rejects_invalid_request_metadata(file_server):
    server, _ = file_server

    status, _, _ = request(
        server,
        'POST',
        '/upload',
        b'not multipart',
        {'Content-Length': '13', 'Content-Type': 'text/plain'},
    )
    assert status == 400

    status, _, _ = request(
        server,
        'POST',
        '/upload',
        b'',
        {'Transfer-Encoding': 'chunked'},
    )
    assert status == 501


@pytest.mark.parametrize('method', ['PUT', 'DELETE', 'PATCH'])
def test_upload_rejects_unsupported_method(file_server, method):
    server, _ = file_server

    status, headers, _ = request(server, method, '/upload')

    assert status == 405
    assert headers['allow'] == 'GET, POST'


def test_symlink_cannot_escape_served_root(file_server, tmp_path):
    server, root = file_server
    outside = tmp_path.parent / f'{tmp_path.name}-outside.txt'
    outside.write_bytes(b'secret')
    link = root / 'outside.txt'
    try:
        link.symlink_to(outside)
    except OSError as e:
        pytest.skip(f'symlinks unavailable: {e}')

    status, _, body = request(server, 'GET', '/outside.txt')

    assert status == 404
    assert b'secret' not in body


def test_worker_pool_validates_worker_count(tmp_path):
    handler = partial(FileServerRequestHandler, directory=tmp_path)

    with pytest.raises(ValueError, match='at least 1'):
        WorkerPoolHTTPServer(('127.0.0.1', 0), handler, workers=0)


def test_run_file_server_configures_tls_and_closes(mocker, tmp_path):
    server = mocker.patch(
        'simple_proxy.file_server.WorkerPoolHTTPServer'
    ).return_value
    server.server_port = 8443
    original_socket = server.socket
    context = mocker.patch('simple_proxy.file_server.ssl.SSLContext').return_value

    run_file_server(
        local_server='127.0.0.1',
        local_port=8443,
        directory=tmp_path,
        workers=3,
        certfile='/tmp/cert.pem',
        keyfile='/tmp/key.pem',
    )

    context.load_cert_chain.assert_called_once_with(
        certfile='/tmp/cert.pem',
        keyfile='/tmp/key.pem',
    )
    context.wrap_socket.assert_called_once_with(
        original_socket,
        server_side=True,
    )
    server.serve_forever.assert_called_once_with()
    server.server_close.assert_called_once_with()


@pytest.mark.parametrize(
    ('kwargs', 'message'),
    [
        ({'directory': '/missing'}, 'Invalid file server directory'),
        ({'workers': 0}, 'workers must be at least 1'),
        ({'certfile': 'cert.pem'}, 'Both key and cert files are required'),
    ],
)
def test_run_file_server_validates_configuration(tmp_path, kwargs, message):
    options = {
        'local_server': '127.0.0.1',
        'local_port': 0,
        'directory': tmp_path,
    }
    options.update(kwargs)

    with pytest.raises(ValueError, match=message):
        run_file_server(**options)
