"""The local dashboard server (standard library only).

Design rules:

* It listens on 127.0.0.1 only. There is no host option.
* Only three fixed assets are served, loaded with ``importlib.resources``. The
  request path is compared with a fixed table and is never used to build a file
  name, so there is no path traversal and no arbitrary file access.
* Every request must carry a loopback ``Host`` header (DNS rebinding). The one
  API call, ``POST /api/scan``, also needs the per-launch token, a matching
  ``Origin``, a JSON content type and a bounded body.
* A POST that is refused before its body is read has that body discarded, within
  fixed limits, before the connection is closed (see ``_discard_unread_body``).
  Closing a socket that still holds unread data can reset the connection on
  Windows and destroy the response the client has not read yet.
* One scan runs at a time.
* Errors are JSON ``{"error": {"kind": ..., "message": ...}}`` with kind
  ``http`` (the request itself was refused), ``input`` (the content was
  invalid) or ``internal`` (unexpected failure). Problems found by the scanner
  are not errors here: they are part of a normal 200 result (status and issues).
"""

import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import urlsplit

from vulnsight.engine import ScanEngine
from vulnsight.scanner.policy import ParameterMode
from vulnsight.ui.view import build_view

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 16 * 1024
# Cleanup of a refused POST: the whole discard must finish within this time, and
# it reads in pieces of this size. Both are small because the body is at most
# MAX_BODY_BYTES and only a slow or hostile client can make cleanup take long.
CLEANUP_TIMEOUT_SECONDS = 1.0
CLEANUP_CHUNK_BYTES = 4096
# Longest Content-Length text that cleanup will convert to a number.
MAX_LENGTH_DIGITS = 20
MAX_PATH_CHARS = 4096
TOKEN_HEADER = "X-VulnSight-Token"
TOKEN_PLACEHOLDER = "__VULNSIGHT_TOKEN__"

# The only things this server serves: request path -> (asset name, media type).
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

KIND_HTTP = "http"
KIND_INPUT = "input"
KIND_INTERNAL = "internal"


class _Refusal(Exception):
    """An error response: HTTP status, error kind and a short message."""

    def __init__(self, status, kind, message, headers=None):
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.message = message
        self.headers = headers or {}


def load_asset(name):
    """Read one packaged frontend asset. ``name`` must come from ``ASSETS``."""

    if name not in {asset for asset, _ in ASSETS.values()}:
        raise ValueError("unknown asset")

    return resources.files("vulnsight.ui").joinpath("static", name).read_bytes()


class DashboardServer(ThreadingHTTPServer):
    """A loopback-only HTTP server that carries the per-launch state."""

    daemon_threads = True
    # On POSIX, address reuse lets a restart skip TIME_WAIT and never allows a
    # second listener. On Windows it would allow one, so it is off there and
    # the socket is bound exclusively instead.
    allow_reuse_address = not sys.platform.startswith("win")

    def __init__(self, port, token):
        self.token = token
        self.scan_lock = threading.Lock()
        super().__init__((HOST, port), DashboardHandler)

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)

        if exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)

        super().server_bind()

    @property
    def port(self):
        return self.server_address[1]

    @property
    def url(self):
        return f"http://{HOST}:{self.port}/"


def create_server(port=DEFAULT_PORT, *, token=None):
    """Create the server, bound to 127.0.0.1. Port 0 picks a free port.

    There is deliberately no ``host`` argument. ``token`` is for tests; by
    default a random one is made for this launch.
    """

    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 to 65535")

    if token is None:
        token = secrets.token_urlsafe(32)

    return DashboardServer(port, token)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "VulnSightUI"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = 15
    # True once the request body has been read (or cleanup has dealt with it),
    # so that a body is never consumed twice.
    _body_consumed = False

    # -- plumbing --------------------------------------------------

    def version_string(self):
        return self.server_version

    def log_message(self, format, *args):
        """Stay quiet: nothing about requests (or scanned paths) is logged."""

    def __getattr__(self, name):
        # Any other HTTP method (HEAD, PUT, OPTIONS, even a made-up one) is
        # refused the same way instead of the library's 501 page.
        if name.startswith("do_"):
            return self._method_not_allowed

        raise AttributeError(name)

    def _method_not_allowed(self):
        self._respond(self._guard(self._refuse_method))

    def _refuse_method(self):
        raise _Refusal(
            HTTPStatus.METHOD_NOT_ALLOWED,
            KIND_HTTP,
            "method not allowed",
            {"Allow": "GET, POST"},
        )

    def do_GET(self):
        self._respond(self._guard(self._get))

    def do_POST(self):
        self._body_read_started = False
        self._body_consumed = False
        self._respond(self._guard(self._post))
        self._discard_unread_body()

    def _guard(self, action):
        """Run ``action`` and return ``(status, headers, body)``."""

        try:
            self._check_host()

            return action()
        except _Refusal as refusal:
            return self._error(refusal)
        except TimeoutError:
            return self._error(
                _Refusal(HTTPStatus.REQUEST_TIMEOUT, KIND_HTTP, "request timed out")
            )
        except Exception as error:  # never leak details to the client
            print(
                f"vulnsight ui: internal error ({type(error).__name__}): {error}",
                file=sys.stderr,
            )

            return self._error(
                _Refusal(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    KIND_INTERNAL,
                    "internal error; see the server console",
                )
            )

    def send_error(self, code, message=None, explain=None):
        """Answer protocol-level errors in the same JSON form, with headers."""

        try:
            status = HTTPStatus(code)
        except ValueError:
            status = HTTPStatus.BAD_REQUEST

        self.close_connection = True

        if self.request_version == "HTTP/0.9":
            # A one-word request line is read as HTTP/0.9, and the library then
            # sends no status line and no headers. Answer it as HTTP/1.0 so the
            # security headers are on every response.
            self.request_version = "HTTP/1.0"

        self._respond(self._error(_Refusal(status, KIND_HTTP, status.phrase.lower())))

    def _respond(self, response):
        status, headers, body = response

        try:
            self.send_response(status)

            for name, value in {**SECURITY_HEADERS, **headers}.items():
                self.send_header(name, value)

            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # the browser went away

    @staticmethod
    def _error(refusal):
        body = json.dumps(
            {"error": {"kind": refusal.kind, "message": refusal.message}},
            ensure_ascii=True,
        ).encode("ascii")
        headers = {"Content-Type": "application/json", **refusal.headers}

        return int(refusal.status), headers, body

    # -- request checks ---------------------------------------------

    def _allowed_hosts(self):
        port = self.server.port

        return {f"{HOST}:{port}", f"localhost:{port}"}

    def _check_host(self):
        host = (self.headers.get("Host") or "").lower()

        if host not in self._allowed_hosts():
            raise _Refusal(HTTPStatus.FORBIDDEN, KIND_HTTP, "forbidden host")

    def _check_origin(self):
        origin = (self.headers.get("Origin") or "").lower()
        allowed = {f"http://{host}" for host in self._allowed_hosts()}

        if origin not in allowed:
            raise _Refusal(HTTPStatus.FORBIDDEN, KIND_HTTP, "forbidden origin")

    def _check_token(self):
        supplied = self.headers.get(TOKEN_HEADER) or ""

        if not hmac.compare_digest(
            supplied.encode("utf-8", "replace"), self.server.token.encode("ascii")
        ):
            raise _Refusal(HTTPStatus.FORBIDDEN, KIND_HTTP, "missing or wrong token")

    # -- GET ---------------------------------------------------------

    def _get(self):
        route = urlsplit(self.path).path

        if route == "/api/scan":
            raise _Refusal(
                HTTPStatus.METHOD_NOT_ALLOWED,
                KIND_HTTP,
                "method not allowed",
                {"Allow": "POST"},
            )

        asset = ASSETS.get(route)

        if asset is None:
            raise _Refusal(HTTPStatus.NOT_FOUND, KIND_HTTP, "not found")

        name, media_type = asset
        body = load_asset(name)

        if name == "index.html":
            body = body.replace(
                TOKEN_PLACEHOLDER.encode("ascii"), self.server.token.encode("ascii")
            )

        return HTTPStatus.OK, {"Content-Type": media_type}, body

    # -- POST --------------------------------------------------------

    def _post(self):
        route = urlsplit(self.path).path

        if route != "/api/scan":
            if route in ASSETS:
                raise _Refusal(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    KIND_HTTP,
                    "method not allowed",
                    {"Allow": "GET"},
                )

            raise _Refusal(HTTPStatus.NOT_FOUND, KIND_HTTP, "not found")

        self._check_origin()
        self._check_token()

        media_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()

        if media_type.lower() != "application/json":
            raise _Refusal(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                KIND_HTTP,
                "Content-Type must be application/json",
            )

        request = self._read_request()
        path, mode = self._validate(request)

        return self._scan(path, mode)

    def _read_request(self):
        if self.headers.get("Transfer-Encoding") is not None:
            raise _Refusal(
                HTTPStatus.LENGTH_REQUIRED, KIND_HTTP, "chunked bodies are not accepted"
            )

        lengths = self.headers.get_all("Content-Length") or []

        if not lengths:
            raise _Refusal(HTTPStatus.LENGTH_REQUIRED, KIND_HTTP, "length required")

        if len(lengths) != 1:
            raise _Refusal(
                HTTPStatus.BAD_REQUEST, KIND_HTTP, "duplicate Content-Length"
            )

        length = lengths[0]

        # Bound the decimal text before int() so hostile headers cannot trigger
        # Python's integer-string conversion limit or consume needless work.
        if (
            not length.isascii()
            or not length.isdigit()
            or len(length) > MAX_LENGTH_DIGITS
        ):
            raise _Refusal(HTTPStatus.BAD_REQUEST, KIND_HTTP, "bad Content-Length")

        size = int(length)

        if size > MAX_BODY_BYTES:
            raise _Refusal(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, KIND_HTTP, "request body too large"
            )

        # Once a read starts, its outcome may be partial if the socket times
        # out. In that case we must close the connection, not retry the full
        # Content-Length during refused-body cleanup.
        self._body_read_started = True
        data = self.rfile.read(size)

        if len(data) != size:
            self.close_connection = True
            raise _Refusal(HTTPStatus.BAD_REQUEST, KIND_HTTP, "incomplete request body")

        self._body_consumed = True

        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _Refusal(
                HTTPStatus.BAD_REQUEST, KIND_INPUT, "the request is not valid JSON"
            ) from None

    # -- cleanup of refused POSTs ------------------------------------

    def _discardable_body_size(self):
        """Return the size of the unread body if it is safe to discard, else None.

        Only a body framed by exactly one plain decimal ``Content-Length`` that
        is at most ``MAX_BODY_BYTES`` qualifies, and never one sent with
        ``Transfer-Encoding``. The text is checked before it is converted, and
        nothing about the body itself is looked at.
        """

        if self.headers.get("Transfer-Encoding") is not None:
            return None

        lengths = self.headers.get_all("Content-Length") or []

        if len(lengths) != 1:
            return None

        text = lengths[0]

        if not text.isascii() or not text.isdigit() or len(text) > MAX_LENGTH_DIGITS:
            return None

        size = int(text)

        return size if size <= MAX_BODY_BYTES else None

    def _discard_unread_body(self):
        """Read and throw away the body of a POST that was refused unread.

        The response has already been sent. Closing a socket that still holds
        unread request data can reset the connection on Windows, and the reset
        can destroy a response the client has not read yet. So a body that is
        safe to discard (see ``_discardable_body_size``) is read here, within
        ``CLEANUP_TIMEOUT_SECONDS``, and its content is never parsed or used.
        Anything else, and any failure, closes the connection instead.
        """

        if self._body_consumed:
            return

        # _read_request may have consumed some bytes before raising (for
        # example, on a socket timeout). The remaining body length is then
        # unknown, so never attempt a second read using the original length.
        if self._body_read_started:
            self.close_connection = True

            return

        size = self._discardable_body_size()

        if size is None:
            self.close_connection = True

            return

        if size == 0:
            self._body_consumed = True

            return

        self._body_read_started = True

        try:
            discarded = self._drain_body(size)
        except (OSError, ValueError):
            discarded = False

        if not discarded:
            self.close_connection = True
            return

        self._body_consumed = True

    def _drain_body(self, size):
        """Read ``size`` bytes and drop them. Return False if that did not work.

        The time limit covers the whole read, so a client that sends one byte at
        a time cannot hold the connection open for longer than the limit.
        """

        deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        remaining = size

        while remaining > 0:
            left = deadline - time.monotonic()

            if left <= 0:
                return False

            try:
                self.connection.settimeout(left)
                chunk = self.rfile.read1(min(remaining, CLEANUP_CHUNK_BYTES))
            except (OSError, ValueError):
                return False

            if not chunk:
                return True  # the client closed its side: nothing is left unread

            remaining -= len(chunk)

        return True

    @staticmethod
    def _validate(request):
        def invalid(message):
            return _Refusal(HTTPStatus.BAD_REQUEST, KIND_INPUT, message)

        if not isinstance(request, dict):
            raise invalid("the request must be a JSON object")

        if set(request) != {"path", "parameter_mode"}:
            raise invalid('the request must have exactly "path" and "parameter_mode"')

        path = request["path"]
        mode = request["parameter_mode"]

        if not isinstance(path, str) or not path.strip():
            raise invalid("path must be a non-empty string")

        if "\x00" in path:
            raise invalid("path must not contain a null character")

        if len(path) > MAX_PATH_CHARS:
            raise invalid(f"path is longer than {MAX_PATH_CHARS} characters")

        if not isinstance(mode, str) or mode not in {m.value for m in ParameterMode}:
            raise invalid("parameter_mode must be 'strict' or 'recall'")

        return path, ParameterMode(mode)

    def _scan(self, path, mode):
        if not self.server.scan_lock.acquire(blocking=False):
            raise _Refusal(
                HTTPStatus.CONFLICT, KIND_HTTP, "another scan is already running"
            )

        try:
            try:
                result = ScanEngine(parameter_mode=mode).scan_path(path)
            except ValueError as error:  # invalid argument, as the engine defines it
                raise _Refusal(HTTPStatus.BAD_REQUEST, KIND_INPUT, str(error)) from None
        finally:
            self.server.scan_lock.release()

        view = build_view(result, resolved_target=_absolute(path))
        # The export is exactly ScanResult.to_json() plus one final newline, the
        # same bytes as `vulnsight scan --format json`. The page saves it as is.
        body = json.dumps(
            {"view": view, "export": result.to_json() + "\n"}, ensure_ascii=True
        ).encode("ascii")

        return HTTPStatus.OK, {"Content-Type": "application/json"}, body


def _absolute(path):
    """The absolute form of ``path`` for display. Nothing is resolved or opened."""

    try:
        return os.path.abspath(path).replace("\\", "/")
    except (OSError, ValueError):
        return None
