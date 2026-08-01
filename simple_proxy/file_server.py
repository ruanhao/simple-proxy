import html
import io
import json
import os
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email import policy
from email.parser import BytesHeaderParser
from functools import partial
from http import HTTPStatus
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from .utils import format_host_port, pstderr


class _PathOutsideRootError(ValueError):
    pass


class _MultipartError(ValueError):
    pass


class _LimitedReader:

    def __init__(self, reader, length):
        self._reader = reader
        self.remaining = length

    def read(self, size=-1):
        if self.remaining <= 0:
            return b''
        if size < 0 or size > self.remaining:
            size = self.remaining
        data = self._reader.read(size)
        self.remaining -= len(data)
        return data

    def readline(self, size=-1):
        if self.remaining <= 0:
            return b''
        if size < 0 or size > self.remaining:
            size = self.remaining
        data = self._reader.readline(size)
        self.remaining -= len(data)
        return data


class WorkerPoolHTTPServer(HTTPServer):

    def __init__(self, server_address, request_handler_class, workers=1):
        if workers < 1:
            raise ValueError("workers must be at least 1")

        host, port = server_address[:2]
        self.address_family = socket.getaddrinfo(
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            0,
            socket.AI_PASSIVE,
        )[0][0]
        self._executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix='FileServer',
        )
        try:
            super().__init__(server_address, request_handler_class)
        except Exception:
            self._executor.shutdown(wait=True, cancel_futures=True)
            raise

    def process_request(self, request, client_address):
        try:
            self._executor.submit(
                self._process_request,
                request,
                client_address,
            )
        except RuntimeError:
            self.shutdown_request(request)

    def _process_request(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def server_close(self):
        super().server_close()
        self._executor.shutdown(wait=True, cancel_futures=True)


class FileServerRequestHandler(SimpleHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    server_version = 'simple-proxy-file-server'
    sys_version = ''
    index_pages = ('index.html', 'index.htm')

    MAX_PART_HEADER_SIZE = 64 * 1024
    READ_CHUNK_SIZE = 64 * 1024

    def __init__(self, *args, directory=None, **kwargs):
        self._root = Path(directory or '.').resolve()
        super().__init__(*args, directory=str(self._root), **kwargs)

    @property
    def _request_path(self):
        return urlsplit(self.path).path

    def translate_path(self, path):
        translated = Path(super().translate_path(path)).resolve()
        try:
            translated.relative_to(self._root)
        except ValueError as e:
            raise _PathOutsideRootError from e
        return str(translated)

    def send_head(self):
        try:
            translated = Path(self.translate_path(self.path))
            if translated.is_dir():
                for index_name in self.index_pages:
                    index_path = (translated / index_name).resolve()
                    if index_path.is_file():
                        index_path.relative_to(self._root)
                        break
            return super().send_head()
        except (_PathOutsideRootError, OSError, RuntimeError, ValueError):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

    def do_GET(self):  # noqa
        self.close_connection = True
        if self._request_path == '/favicon.ico':
            self._send_empty(HTTPStatus.NO_CONTENT)
        elif self._request_path == '/upload':
            self._send_html(self._upload_form())
        else:
            super().do_GET()

    def do_HEAD(self):  # noqa
        self.close_connection = True
        if self._request_path == '/favicon.ico':
            self._send_empty(HTTPStatus.NO_CONTENT)
        elif self._request_path == '/upload':
            self._method_not_allowed('GET, POST', head=True)
        else:
            super().do_HEAD()

    def do_POST(self):  # noqa
        self.close_connection = True
        if self._request_path == '/favicon.ico':
            self._method_not_allowed('GET, HEAD')
        elif self._request_path != '/upload':
            self._method_not_allowed('GET, HEAD')
        else:
            self._handle_upload()

    def do_PUT(self):  # noqa
        self.close_connection = True
        if self._request_path == '/upload':
            self._method_not_allowed('GET, POST')
        elif self._request_path == '/favicon.ico':
            self._method_not_allowed('GET, HEAD')
        else:
            self._method_not_allowed('GET, HEAD')

    def log_message(self, format_, *args):
        # Request summaries are emitted by log_request in the Go-compatible
        # format. Suppress BaseHTTPRequestHandler's second log line.
        pass

    def send_error(self, code, message=None, explain=None):
        if (
            code == HTTPStatus.NOT_IMPLEMENTED
            and message
            and message.startswith('Unsupported method')
        ):
            if self._request_path == '/upload':
                self._method_not_allowed('GET, POST')
                return
            if self._request_path == '/favicon.ico':
                self._method_not_allowed('GET, HEAD')
                return
            self._method_not_allowed('GET, HEAD')
            return
        super().send_error(code, message, explain)

    def end_headers(self):
        if self.close_connection:
            self.send_header('Connection', 'close')
        super().end_headers()

    def log_request(self, code='-', size='-'):
        visitor = self.client_address[0] if self.client_address else '-'
        timestamp = datetime.now().astimezone().isoformat(timespec='seconds')
        pstderr(
            f"{visitor} [{timestamp}] {self.command} {self.path} {code}"
        )

    def list_directory(self, path):
        try:
            with os.scandir(path) as iterator:
                entries = sorted(
                    iterator,
                    key=lambda entry: entry.name.casefold(),
                )
        except OSError:
            self.send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "Error reading directory",
            )
            return None

        request_path = unquote(self._request_path, errors='replace')
        title = f"Index of {request_path}"
        rows = []
        if request_path != '/':
            rows.append(
                '<tr><td><a href="../">Parent Directory</a></td>'
                '<td></td><td align="right"></td></tr>'
            )

        for entry in entries:
            try:
                stat_result = entry.stat(follow_symlinks=False)
            except OSError:
                continue

            display_name = entry.name
            href = quote(entry.name, safe='', errors='surrogatepass')
            size = str(stat_result.st_size)
            if entry.is_dir(follow_symlinks=False):
                display_name += '/'
                href += '/'
                size = '-'

            modified = datetime.fromtimestamp(
                stat_result.st_mtime,
            ).astimezone()
            modified_text = (
                modified.strftime('%a %b ')
                + f"{modified.day:2d}"
                + modified.strftime(' %H:%M:%S %Z %Y')
            )
            rows.append(
                '<tr><td><a href="{href}">{name}</a></td>'
                '<td>{modified}</td><td align="right">{size}</td></tr>'.format(
                    href=html.escape(href, quote=True),
                    name=html.escape(display_name),
                    modified=html.escape(modified_text),
                    size=html.escape(size),
                )
            )

        body = (
            '<!doctype html>\n'
            '<html>\n'
            '<head><meta charset="utf-8"><title>{title}</title>'
            '<style>table{{border-collapse:collapse}}th,td{{padding:0 2.5em .35em 0;text-align:left;white-space:nowrap}}th:last-child,td:last-child{{padding-right:0;text-align:right}}</style>'
            '</head>\n<body>\n'
            '<h1>{title}</h1>\n'
            '<table>\n'
            '<thead><tr><th align="left">Name</th><th align="left">Last Modified</th><th align="right">Size</th></tr></thead>\n'
            '<tbody>\n{rows}\n</tbody>\n</table>\n</body>\n</html>\n'
        ).format(
            title=html.escape(title),
            rows='\n'.join(rows),
        ).encode('utf-8', errors='surrogateescape')

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        return io.BytesIO(body)

    def _handle_upload(self):
        transfer_encoding = self.headers.get('Transfer-Encoding', '')
        if transfer_encoding and transfer_encoding.lower() != 'identity':
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED,
                "Chunked uploads are not supported",
            )
            return

        length_header = self.headers.get('Content-Length')
        if length_header is None:
            self.send_error(HTTPStatus.LENGTH_REQUIRED)
            return
        try:
            content_length = int(length_header)
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return
        if content_length < 0:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return

        boundary = self._multipart_boundary()
        if boundary is None:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        reader = _LimitedReader(self.rfile, content_length)
        temporary_path = None
        upload = None
        try:
            first_boundary = reader.readline(self.MAX_PART_HEADER_SIZE + 1)
            if first_boundary != b'--' + boundary + b'\r\n':
                raise _MultipartError("invalid initial multipart boundary")

            final_boundary = False
            while not final_boundary:
                headers = self._read_part_headers(reader)
                disposition = headers.get_content_disposition()
                disposition_header = next(
                    (
                        value
                        for name, value in headers.raw_items()
                        if name.lower() == 'content-disposition'
                    ),
                    '',
                )
                field_name = headers.get_param(
                    'name',
                    header='content-disposition',
                )
                filename = headers.get_filename()

                destination = None
                if (
                    upload is None
                    and disposition == 'form-data'
                    and field_name == 'file'
                ):
                    filename = self._clean_upload_filename(
                        filename,
                        disposition_header,
                    )
                    temporary = tempfile.NamedTemporaryFile(
                        mode='wb',
                        dir=self._root,
                        prefix='.simple-proxy-upload-',
                        delete=False,
                    )
                    temporary_path = Path(temporary.name)
                    destination = temporary

                try:
                    size, final_boundary = self._copy_part(
                        reader,
                        boundary,
                        destination,
                    )
                finally:
                    if destination is not None:
                        destination.close()

                if destination is not None:
                    upload = (filename, size)

            while reader.remaining:
                if not reader.read(min(self.READ_CHUNK_SIZE, reader.remaining)):
                    raise _MultipartError("truncated multipart body")

            if upload is None:
                raise _MultipartError("missing file field")

            filename, size = upload
            os.replace(temporary_path, self._root / filename)
            temporary_path = None
        except _MultipartError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        except OSError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

        if 'application/json' in self.headers.get('Accept', '').lower():
            body = json.dumps(
                {
                    'name': filename,
                    'size': size,
                    'url': '/' + quote(filename, safe=''),
                },
                separators=(',', ':'),
            ).encode('utf-8') + b'\n'
            self._send_bytes(
                HTTPStatus.OK,
                'application/json',
                body,
            )
        else:
            self._send_html(self._upload_success(filename, size))

    def _multipart_boundary(self):
        content_type = self.headers.get('Content-Type', '')
        header = BytesHeaderParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\n\r\n".encode('iso-8859-1')
        )
        if header.get_content_type() != 'multipart/form-data':
            return None
        boundary = header.get_param('boundary', header='content-type')
        if not boundary or len(boundary) > 70:
            return None
        try:
            encoded = boundary.encode('ascii')
        except UnicodeEncodeError:
            return None
        if b'\r' in encoded or b'\n' in encoded:
            return None
        return encoded

    def _read_part_headers(self, reader):
        chunks = []
        size = 0
        while True:
            line = reader.readline(self.MAX_PART_HEADER_SIZE + 1)
            if not line:
                raise _MultipartError("truncated multipart headers")
            size += len(line)
            if size > self.MAX_PART_HEADER_SIZE:
                raise _MultipartError("multipart headers are too large")
            if line == b'\r\n':
                break
            chunks.append(line)
        try:
            return BytesHeaderParser(policy=policy.default).parsebytes(
                b''.join(chunks) + b'\r\n'
            )
        except ValueError as e:
            raise _MultipartError("invalid multipart headers") from e

    def _copy_part(self, reader, boundary, destination):
        normal_boundary = b'--' + boundary + b'\r\n'
        final_boundary = b'--' + boundary + b'--\r\n'
        final_boundary_without_crlf = b'--' + boundary + b'--'
        pending = b''
        size = 0

        while True:
            line = reader.readline(self.READ_CHUNK_SIZE)
            if not line:
                raise _MultipartError("truncated multipart body")
            if line in (
                normal_boundary,
                final_boundary,
                final_boundary_without_crlf,
            ):
                if pending.endswith(b'\r\n'):
                    pending = pending[:-2]
                else:
                    raise _MultipartError("invalid multipart delimiter")
                if destination is not None:
                    destination.write(pending)
                size += len(pending)
                return size, line != normal_boundary

            if pending:
                if destination is not None:
                    destination.write(pending)
                size += len(pending)
            pending = line

    @staticmethod
    def _clean_upload_filename(filename, disposition_header=''):
        if (
            not filename
            or filename in ('.', '..')
            or '/' in filename
            or '\\' in filename
            or '\\' in disposition_header
            or '\x00' in filename
            or Path(filename).name != filename
        ):
            raise _MultipartError("invalid filename")
        return filename

    def _method_not_allowed(self, allow, head=False):
        body = b'405 Method Not Allowed\n'
        self._send_bytes(
            HTTPStatus.METHOD_NOT_ALLOWED,
            'text/plain; charset=utf-8',
            body,
            headers={'Allow': allow},
            head=head,
        )

    def _send_empty(self, status):
        self._send_bytes(status, None, b'')

    def _send_html(self, text):
        self._send_bytes(
            HTTPStatus.OK,
            'text/html; charset=utf-8',
            text.encode('utf-8'),
        )

    def _send_bytes(self, status, content_type, body, headers=None, head=False):
        self.send_response(status)
        if content_type:
            self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body and not head:
            self.wfile.write(body)

    @staticmethod
    def _upload_form():
        return '''<!doctype html>
<html>
<head><meta charset="utf-8"><title>Upload File</title><style>body{font-family:sans-serif;margin:2em;max-width:42em}form{margin:1.5em 0}.file-input{position:absolute;left:-9999px}.button{display:inline-block;box-sizing:border-box;border:1px solid #777;border-radius:3px;background:#f5f5f5;color:#111;padding:.35em .75em;font-size:13px;line-height:normal;cursor:pointer}.button:hover{background:#eee}.actions{margin-top:.75em}.selected-file{overflow-wrap:anywhere}.upload-result{white-space:nowrap;overflow-x:auto}progress{display:block;width:100%;height:1.25em;margin:.75em 0}.hidden{display:none}.error{color:#b00020}.success{color:#0b6b2b}</style></head>
<body>
<h1>Upload File</h1>
<p>Select a file to upload into the served directory.</p>
<form id="upload-form" method="post" action="/upload" enctype="multipart/form-data">
<input id="file-input" class="file-input" type="file" name="file" required>
<label class="button" for="file-input">Choose File</label>
<p id="selected-file" class="selected-file">No file selected</p>
<div class="actions"><button id="upload-button" class="button" type="submit">Upload</button></div>
</form>
<progress id="upload-progress" class="hidden" max="100" value="0"></progress>
<p id="upload-status" aria-live="polite"></p>
<p id="upload-result" class="upload-result hidden"></p>
<p><a href="/">Back to files</a></p>
<script>
(function () {
  var form = document.getElementById("upload-form");
  var fileInput = document.getElementById("file-input");
  var button = document.getElementById("upload-button");
  var selectedFile = document.getElementById("selected-file");
  var progress = document.getElementById("upload-progress");
  var status = document.getElementById("upload-status");
  var result = document.getElementById("upload-result");

  fileInput.addEventListener("change", function () {
    selectedFile.textContent = fileInput.files.length ? fileInput.files[0].name : "No file selected";
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.setRequestHeader("Accept", "application/json");
    button.disabled = true;
    progress.classList.remove("hidden");
    progress.value = 0;
    status.className = "";
    status.textContent = "Uploading...";
    result.className = "hidden";
    result.textContent = "";
    xhr.upload.onprogress = function (event) {
      if (!event.lengthComputable) { return; }
      var percent = Math.round((event.loaded / event.total) * 100);
      progress.value = percent;
      status.textContent = "Uploading... " + percent + "%";
    };
    xhr.onload = function () {
      button.disabled = false;
      if (xhr.status < 200 || xhr.status >= 300) {
        status.className = "error";
        status.textContent = "Upload failed.";
        return;
      }
      var data = JSON.parse(xhr.responseText);
      progress.value = 100;
      status.className = "success";
      status.textContent = "Upload complete.";
      result.className = "upload-result";
      result.innerHTML = "Uploaded <a></a> (" + data.size + " bytes).";
      var link = result.querySelector("a");
      link.href = data.url;
      link.textContent = data.name;
    };
    xhr.onerror = function () {
      button.disabled = false;
      status.className = "error";
      status.textContent = "Upload failed.";
    };
    xhr.send(new FormData(form));
  });
}());
</script>
</body>
</html>
'''

    @staticmethod
    def _upload_success(filename, size):
        escaped_name = html.escape(filename)
        escaped_href = html.escape(quote(filename, safe=''), quote=True)
        return f'''<!doctype html>
<html>
<head><meta charset="utf-8"><title>Upload Complete</title><style>body{{font-family:sans-serif;margin:2em;max-width:42em}}.upload-result{{white-space:nowrap;overflow-x:auto}}</style></head>
<body>
<h1>Upload Complete</h1>
<p class="upload-result">Uploaded <a href="/{escaped_href}">{escaped_name}</a> ({size} bytes).</p>
<p><a href="/upload">Upload another file</a> | <a href="/">Back to files</a></p>
</body>
</html>
'''


def run_file_server(
        local_server,
        local_port,
        directory='.',
        workers=1,
        certfile=None,
        keyfile=None,
):
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"Invalid file server directory: {directory}")
    if workers < 1:
        raise ValueError("workers must be at least 1")
    if bool(certfile) != bool(keyfile):
        raise ValueError("Both key and cert files are required")

    handler = partial(FileServerRequestHandler, directory=str(root))
    server = WorkerPoolHTTPServer(
        (local_server, local_port),
        handler,
        workers=workers,
    )
    if certfile and keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    scheme = 'https' if certfile else 'http'
    address = format_host_port(local_server, server.server_port)
    pstderr(
        f"File server started listening: {scheme}://{address}/ "
        f"[directory:{root}, workers:{workers}] ..."
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
