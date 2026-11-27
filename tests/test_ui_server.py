"""Tests for the dashboard server: routes, request checks and error kinds."""

import http.client
import inspect
import json
import socket
import threading
import time

import pytest

import vulnsight.ui.server as server_module
from vulnsight.cli import main as cli_main
from vulnsight.ui.server import (
    ASSETS,
    MAX_BODY_BYTES,
    MAX_PATH_CHARS,
    SECURITY_HEADERS,
    TOKEN_HEADER,
    create_server,
    load_asset,
)

TOKEN = "test-token-123"
VULNERABLE = "import os\n\n\ndef run():\n    os.system(input())\n"


@pytest.fixture
def dashboard():
    server = create_server(0, token=TOKEN)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()

    yield server

    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE, encoding="utf-8")

    return tmp_path


def call(server, method, path, body=None, headers=None):
    """Send one request. ``headers`` replaces or (with None) removes defaults."""

    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    sent = dict(headers or {})
    connection.request(method, path, body=body, headers=sent)
    response = connection.getresponse()
    data = response.read()
    connection.close()

    return response, data


def scan_headers(server, **changes):
    headers = {
        "Content-Type": "application/json",
        "Origin": f"http://127.0.0.1:{server.port}",
        TOKEN_HEADER: TOKEN,
    }

    for name, value in changes.items():
        key = name.replace("_", "-")

        if value is None:
            headers.pop(key, None)
        else:
            headers[key] = value

    return headers


def scan(server, payload, *, raw=None, **changes):
    body = raw if raw is not None else json.dumps(payload)
    headers = scan_headers(server, **changes)

    return call(server, "POST", "/api/scan", body, headers)


def valid(path, mode="strict"):
    return {"path": str(path), "parameter_mode": mode}


def error_of(data):
    return json.loads(data)["error"]


# -- binding and construction ----------------------------------------------


def test_server_binds_to_loopback_only(dashboard):
    assert dashboard.server_address[0] == "127.0.0.1"
    assert dashboard.url == f"http://127.0.0.1:{dashboard.port}/"


def test_there_is_no_host_option():
    assert list(inspect.signature(create_server).parameters) == ["port", "token"]

    with pytest.raises(TypeError):
        create_server(0, host="0.0.0.0")


@pytest.mark.parametrize("bad", [-1, 65536, True, "80", 1.5, None])
def test_invalid_ports_are_rejected(bad):
    with pytest.raises(ValueError, match="port"):
        create_server(bad)


def test_each_launch_gets_a_different_random_token():
    first, second = create_server(0), create_server(0)

    try:
        assert first.token != second.token
        assert len(first.token) >= 32
    finally:
        first.server_close()
        second.server_close()


def test_a_second_server_cannot_take_a_listening_port(dashboard):
    with pytest.raises(OSError):
        create_server(dashboard.port)


def test_exclusive_bind_option_is_applied_when_the_platform_has_one(monkeypatch):
    # SO_EXCLUSIVEADDRUSE exists only on Windows. SO_KEEPALIVE stands in for it
    # so that this branch of server_bind runs (and is observable) on every OS.
    monkeypatch.setattr(
        socket, "SO_EXCLUSIVEADDRUSE", socket.SO_KEEPALIVE, raising=False
    )
    server = create_server(0, token=TOKEN)

    try:
        option = server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)

        assert option != 0
    finally:
        server.server_close()


@pytest.mark.skipif(
    not hasattr(socket, "SO_EXCLUSIVEADDRUSE"),
    reason="SO_EXCLUSIVEADDRUSE exists only on Windows",
)
def test_real_exclusive_bind_option_is_set_on_the_listening_socket(dashboard):
    option = dashboard.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE)

    assert option != 0


def test_a_listening_port_cannot_be_shared_even_with_address_reuse(dashboard):
    other = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        with pytest.raises(OSError):
            other.bind(("127.0.0.1", dashboard.port))
    finally:
        other.close()


def test_a_stopped_servers_port_can_be_bound_again():
    server = create_server(0, token=TOKEN)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    port = server.port

    # One finished request, so the closed connection leaves TIME_WAIT behind.
    response, _ = call(server, "GET", "/")

    server.shutdown()
    server.server_close()
    thread.join(timeout=5)

    assert response.status == 200

    restarted = create_server(port, token=TOKEN)

    try:
        assert restarted.port == port
    finally:
        restarted.server_close()


# -- assets --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "media"),
    [
        ("/", "text/html; charset=utf-8"),
        ("/static/app.js", "text/javascript; charset=utf-8"),
        ("/static/style.css", "text/css; charset=utf-8"),
    ],
)
def test_the_three_assets_are_served(dashboard, path, media):
    response, data = call(dashboard, "GET", path)

    assert response.status == 200
    assert response.getheader("Content-Type") == media
    assert data


def test_the_token_is_inserted_into_the_page_only(dashboard):
    _, page = call(dashboard, "GET", "/")
    _, script = call(dashboard, "GET", "/static/app.js")

    assert f'content="{TOKEN}"'.encode() in page
    assert b"__VULNSIGHT_TOKEN__" not in page
    assert TOKEN.encode() not in script


def test_assets_are_the_packaged_files(dashboard):
    _, script = call(dashboard, "GET", "/static/app.js")

    assert script == load_asset("app.js")


def test_load_asset_refuses_unknown_names():
    for name in ("../server.py", "server.py", "", "index.html/", "static/app.js"):
        with pytest.raises(ValueError):
            load_asset(name)


@pytest.mark.parametrize(
    "path",
    [
        "/index.html",
        "/static/",
        "/static",
        "/static/index.html",
        "/static/app.js/",
        "/static/../server.py",
        "/static/%2e%2e/server.py",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/static/..%2fserver.py",
        "/static/app.js%00.txt",
        "/static/..\\server.py",
        "/etc/passwd",
        "//etc/passwd",
        "/api",
        "/api/",
        "/api/other",
        "/favicon.ico",
        "/.git/config",
    ],
)
def test_unexpected_paths_are_not_found(dashboard, path):
    response, data = call(dashboard, "GET", path)

    assert response.status == 404
    assert error_of(data)["kind"] == "http"


def test_query_strings_do_not_change_routing(dashboard):
    response, _ = call(dashboard, "GET", "/static/app.js?x=../../etc/passwd")

    assert response.status == 200


# -- methods -----------------------------------------------------------------------


@pytest.mark.parametrize("method", ["HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "FOO"])
def test_unsupported_methods_are_rejected(dashboard, method):
    response, data = call(dashboard, method, "/")

    assert response.status == 405
    assert response.getheader("Allow") == "GET, POST"
    if method != "HEAD":
        assert error_of(data)["kind"] == "http"


def test_wrong_method_for_a_known_route(dashboard):
    response, data = call(dashboard, "GET", "/api/scan")

    assert response.status == 405
    assert response.getheader("Allow") == "POST"
    assert error_of(data)["kind"] == "http"

    response, _ = call(dashboard, "POST", "/", "{}", scan_headers(dashboard))

    assert response.status == 405
    assert response.getheader("Allow") == "GET"


def test_post_to_an_unexpected_route_is_not_found(dashboard):
    response, _ = call(dashboard, "POST", "/api/other", "{}", scan_headers(dashboard))

    assert response.status == 404


# -- headers ---------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/static/app.js", "/static/style.css", "/nope"])
def test_security_headers_are_on_every_response(dashboard, path):
    response, _ = call(dashboard, "GET", path)

    for name, value in SECURITY_HEADERS.items():
        assert response.getheader(name) == value


def test_security_headers_are_on_error_and_scan_responses(dashboard, project):
    for response, _ in (
        call(dashboard, "PUT", "/"),
        scan(dashboard, valid(project)),
        scan(dashboard, valid(project), raw="not json"),
    ):
        for name, value in SECURITY_HEADERS.items():
            assert response.getheader(name) == value


def test_policy_blocks_inline_script_and_external_sources(dashboard):
    response, _ = call(dashboard, "GET", "/")
    policy = response.getheader("Content-Security-Policy")

    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "'unsafe-inline'" not in policy
    assert "'unsafe-eval'" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response.getheader("Cache-Control") == "no-store"
    assert response.getheader("X-Content-Type-Options") == "nosniff"


def test_no_cors_headers_are_sent(dashboard, project):
    response, _ = scan(dashboard, valid(project))

    assert response.getheader("Access-Control-Allow-Origin") is None


def test_server_does_not_reveal_the_python_version(dashboard):
    response, _ = call(dashboard, "GET", "/")

    assert response.getheader("Server") == "VulnSightUI"


# -- host, origin, token -------------------------------------------------------------


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:80", "127.0.0.1", "localhost", "[::1]:1", ""]
)
def test_wrong_host_is_refused_for_every_route(dashboard, host):
    for method, path in (("GET", "/"), ("GET", "/static/app.js"), ("PUT", "/")):
        response, data = call(dashboard, method, path, headers={"Host": host})

        assert response.status == 403
        assert error_of(data)["kind"] == "http"


def test_wrong_host_is_refused_on_scan(dashboard, project):
    response, _ = scan(dashboard, valid(project), Host="evil.example")

    assert response.status == 403


def test_localhost_with_the_right_port_is_accepted(dashboard, project):
    port = dashboard.port
    response, _ = call(dashboard, "GET", "/", headers={"Host": f"LocalHost:{port}"})
    scanned, _ = scan(
        dashboard,
        valid(project),
        Host=f"localhost:{port}",
        Origin=f"http://localhost:{port}",
    )

    assert response.status == 200
    assert scanned.status == 200


@pytest.mark.parametrize(
    "origin",
    [None, "null", "http://evil.example", "https://127.0.0.1:1", "http://127.0.0.1"],
)
def test_bad_or_missing_origin_is_refused(dashboard, project, origin):
    response, data = scan(dashboard, valid(project), Origin=origin)

    assert response.status == 403
    assert error_of(data)["kind"] == "http"


@pytest.mark.parametrize("token", [None, "", "wrong", TOKEN + "x", TOKEN[:-1]])
def test_missing_or_wrong_token_is_refused(dashboard, project, token):
    response, data = scan(dashboard, valid(project), X_VulnSight_Token=token)

    assert response.status == 403
    assert error_of(data)["kind"] == "http"


def test_a_refused_request_never_scans(dashboard, project, monkeypatch):
    calls = []
    monkeypatch.setattr(
        server_module,
        "ScanEngine",
        lambda **kw: calls.append(kw) or pytest.fail("scan started"),
    )
    scan(dashboard, valid(project), X_VulnSight_Token="wrong")
    scan(dashboard, valid(project), Origin="http://evil.example")

    assert calls == []


# -- request body ----------------------------------------------------------------------


def test_wrong_content_type_is_refused(dashboard, project):
    for media in ("text/plain", "application/x-www-form-urlencoded", None):
        response, data = scan(dashboard, valid(project), Content_Type=media)

        assert response.status == 415
        assert error_of(data)["kind"] == "http"


def test_content_type_parameters_are_allowed(dashboard, project):
    response, _ = scan(
        dashboard, valid(project), Content_Type="application/json; charset=utf-8"
    )

    assert response.status == 200


def test_oversized_body_is_refused(dashboard):
    body = json.dumps({"path": "x" * (MAX_BODY_BYTES + 10), "parameter_mode": "strict"})
    response, data = scan(dashboard, None, raw=body)

    assert response.status == 413
    assert error_of(data)["kind"] == "http"


def test_missing_or_bad_content_length(dashboard):
    def raw_post(extra):
        client = socket.create_connection(("127.0.0.1", dashboard.port), timeout=10)
        request = (
            "POST /api/scan HTTP/1.0\r\n"
            f"Host: 127.0.0.1:{dashboard.port}\r\n"
            f"Origin: http://127.0.0.1:{dashboard.port}\r\n"
            f"{TOKEN_HEADER}: {TOKEN}\r\n"
            "Content-Type: application/json\r\n"
            f"{extra}\r\n"
        )
        client.sendall(request.encode("ascii") + b"{}")
        data = b""
        while chunk := client.recv(65536):
            data += chunk
        client.close()

        return int(data.split(b" ", 2)[1])

    assert raw_post("") == 411
    assert raw_post("Transfer-Encoding: chunked\r\n") == 411
    assert raw_post("Content-Length: abc\r\n") == 400
    assert raw_post("Content-Length: -5\r\n") == 400
    assert raw_post(f"Content-Length: {MAX_BODY_BYTES + 1}\r\n") == 413


# -- refused POSTs with an unread body ------------------------------------------------
#
# A POST refused before its body is read must not leave that body unread when the
# server closes the connection (on Windows that can reset the connection and lose
# the response). These tests look at what the server did with the body through
# two spies, and they send requests by hand so the framing is exactly as written.


@pytest.fixture
def drains(monkeypatch):
    """Record every cleanup read as ``(size, succeeded)``."""

    calls = []
    original = server_module.DashboardHandler._drain_body

    def spy(self, size):
        succeeded = original(self, size)
        calls.append((size, succeeded))

        return succeeded

    monkeypatch.setattr(server_module.DashboardHandler, "_drain_body", spy)

    return calls


@pytest.fixture
def scans(monkeypatch):
    """Record any use of ScanEngine; a refused request must leave this empty."""

    calls = []

    class Spy:
        def __init__(self, **kwargs):
            calls.append(("created", kwargs))

        def scan_path(self, path):
            calls.append(("scan_path", path))

            raise AssertionError("a refused request reached the scanner")

    monkeypatch.setattr(server_module, "ScanEngine", Spy)

    return calls


def post_headers(server, length, **changes):
    """Headers of a valid scan request, as a list so that tests may repeat one."""

    headers = {
        "Host": f"127.0.0.1:{server.port}",
        "Origin": f"http://127.0.0.1:{server.port}",
        TOKEN_HEADER: TOKEN,
        "Content-Type": "application/json",
    }

    if length is not None:
        headers["Content-Length"] = str(length)

    for name, value in changes.items():
        headers[name.replace("_", "-")] = value

    return list(headers.items())


def raw_post(server, headers, body=b"", path="/api/scan"):
    """Send one POST by hand and read until the server closes the connection.

    Returns ``(status, response_bytes)``. The server closes only after it has
    finished with the request, so anything the spies recorded is complete.
    """

    head = f"POST {path} HTTP/1.0\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in headers)
    client = socket.create_connection(("127.0.0.1", server.port), timeout=10)

    try:
        client.sendall(head.encode("latin-1") + b"\r\n" + body)
        data = b""

        while chunk := client.recv(65536):
            data += chunk
    finally:
        client.close()

    return int(data.split(b" ", 2)[1]), data


def json_body(padding):
    payload = {"path": "/somewhere", "parameter_mode": "strict", "pad": "x" * padding}

    return json.dumps(payload).encode("ascii")


REFUSALS = {
    "host": ({"Host": "evil.example"}, 403),
    "origin": ({"Origin": "http://evil.example"}, 403),
    "token": ({"X_VulnSight_Token": "wrong"}, 403),
    "content-type": ({"Content_Type": "text/plain"}, 415),
}


@pytest.mark.parametrize("padding", [0, 12_000], ids=["small", "twelve-kb"])
@pytest.mark.parametrize("reason", sorted(REFUSALS))
def test_refused_post_has_its_body_discarded_before_the_connection_closes(
    dashboard, drains, scans, reason, padding
):
    changes, expected = REFUSALS[reason]
    body = json_body(padding)
    headers = post_headers(dashboard, len(body), **changes)
    status, data = raw_post(dashboard, headers, body)

    assert status == expected
    assert b'"kind": "http"' in data
    assert b"Content-Security-Policy" in data
    assert drains == [(len(body), True)]
    assert scans == []


def test_refused_post_to_an_unknown_route_has_its_body_discarded(
    dashboard, drains, scans
):
    body = json_body(100)
    headers = post_headers(dashboard, len(body))
    status, _ = raw_post(dashboard, headers, body, path="/api/other")

    assert status == 404
    assert drains == [(len(body), True)]
    assert scans == []


def test_refused_post_with_an_empty_body_needs_no_cleanup(dashboard, drains, scans):
    headers = post_headers(dashboard, 0, X_VulnSight_Token="wrong")
    status, data = raw_post(dashboard, headers)

    assert status == 403
    assert b'"kind": "http"' in data
    assert drains == []
    assert scans == []


def test_refused_post_with_an_incomplete_body_gives_up_and_closes(
    dashboard, drains, scans, monkeypatch
):
    monkeypatch.setattr(server_module, "CLEANUP_TIMEOUT_SECONDS", 0.3)
    headers = post_headers(dashboard, 100, X_VulnSight_Token="wrong")

    # 10 of the promised 100 bytes, and the client then waits. The helper only
    # returns once the server closes the connection, so a return proves it did.
    status, data = raw_post(dashboard, headers, b"x" * 10)

    assert status == 403
    assert b"Content-Security-Policy" in data
    assert drains == [(100, False)]
    assert scans == []


def test_cleanup_has_a_total_time_limit_for_a_client_that_drips_bytes(
    dashboard, drains, scans, monkeypatch
):
    monkeypatch.setattr(server_module, "CLEANUP_TIMEOUT_SECONDS", 0.3)
    headers = post_headers(dashboard, 1000, X_VulnSight_Token="wrong")
    head = "POST /api/scan HTTP/1.0\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in headers)
    stop = threading.Event()
    client = socket.create_connection(("127.0.0.1", dashboard.port), timeout=10)

    def drip():
        while not stop.is_set():
            try:
                client.send(b"x")
            except OSError:
                return

            stop.wait(0.05)  # each byte arrives well inside the socket timeout

    started = time.monotonic()

    try:
        client.sendall(head.encode("latin-1") + b"\r\n")
        feeder = threading.Thread(target=drip, daemon=True)
        feeder.start()

        try:
            while client.recv(65536):
                pass
        except OSError:
            pass  # a reset after the server gave up is acceptable here

        elapsed = time.monotonic() - started
    finally:
        stop.set()
        client.close()

    # 1000 bytes at 20 per second would take 50 seconds to arrive.
    assert elapsed < 5
    assert drains == [(1000, False)]
    assert scans == []


@pytest.mark.parametrize("refusal", ["wrong-token", "oversized"])
def test_a_body_over_the_limit_is_never_read_for_cleanup(
    dashboard, drains, scans, refusal
):
    # Only the declared length is sent. Nothing is sent after the headers, so
    # nothing is left unread and the result does not depend on the platform.
    changes = {"X_VulnSight_Token": "wrong"} if refusal == "wrong-token" else {}
    headers = post_headers(dashboard, MAX_BODY_BYTES + 1, **changes)
    status, _ = raw_post(dashboard, headers)

    assert status == (403 if refusal == "wrong-token" else 413)
    assert drains == []
    assert scans == []


@pytest.mark.parametrize(
    "content_lengths",
    [
        [("Content-Length", "5"), ("Content-Length", "5")],
        [("Content-Length", "5"), ("Content-Length", "6")],
        [("Content-Length", "9" * 5000)],
    ],
    ids=["duplicate-same", "duplicate-different", "excessively-long"],
)
def test_duplicate_or_excessively_long_content_length_is_rejected(
    dashboard, scans, content_lengths
):
    headers = post_headers(dashboard, None) + content_lengths
    status, data = raw_post(dashboard, headers)

    assert status == 400
    assert b'"kind": "http"' in data
    assert scans == []


UNSAFE_FRAMING = {
    "transfer-encoding": [("Content-Length", "5"), ("Transfer-Encoding", "chunked")],
    "transfer-encoding-only": [("Transfer-Encoding", "chunked")],
    "duplicate-same": [("Content-Length", "5"), ("Content-Length", "5")],
    "duplicate-different": [("Content-Length", "5"), ("Content-Length", "6")],
    "missing": [],
    "not-a-number": [("Content-Length", "abc")],
    "negative": [("Content-Length", "-5")],
    "plus-sign": [("Content-Length", "+5")],
    "underscore": [("Content-Length", "1_0")],
    "non-ascii-digit": [("Content-Length", "\u00b2")],
    "huge": [("Content-Length", "9" * 5000)],
}


@pytest.mark.parametrize("framing", sorted(UNSAFE_FRAMING))
def test_unsafe_framing_is_never_discarded_and_still_refused(
    dashboard, drains, scans, framing
):
    headers = post_headers(dashboard, None, X_VulnSight_Token="wrong")
    headers += UNSAFE_FRAMING[framing]
    status, data = raw_post(dashboard, headers)

    assert status == 403
    assert b'"kind": "http"' in data
    assert drains == []
    assert scans == []


def test_a_body_that_was_read_is_not_read_again(dashboard, drains, project):
    ok, _ = scan(dashboard, valid(project))
    bad_json, _ = scan(dashboard, None, raw="{")
    bad_fields, _ = scan(dashboard, {"path": "x"})

    assert (ok.status, bad_json.status, bad_fields.status) == (200, 400, 400)
    assert drains == []


def test_interrupted_body_read_closes_without_a_second_read(
    dashboard, drains, scans, monkeypatch
):
    # The authenticated request enters _read_request, consumes some bytes, then
    # times out. Cleanup must not retry the original Content-Length because the
    # number of bytes already consumed is no longer known.
    monkeypatch.setattr(server_module.DashboardHandler, "timeout", 0.2)
    body = b'{"path":'
    headers = post_headers(dashboard, 100)
    status, data = raw_post(dashboard, headers, body)

    assert status == 408
    assert b"Content-Security-Policy" in data
    assert drains == []
    assert scans == []


def test_a_busy_scan_refusal_does_not_read_the_body_again(dashboard, drains, project):
    assert dashboard.scan_lock.acquire(blocking=False)

    try:
        response, _ = scan(dashboard, valid(project))
    finally:
        dashboard.scan_lock.release()

    assert response.status == 409
    assert drains == []


def test_every_refusal_still_has_its_status_and_security_headers(dashboard):
    body = json_body(12_000)

    for changes, expected in REFUSALS.values():
        headers = post_headers(dashboard, len(body), **changes)
        status, data = raw_post(dashboard, headers, body)
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")

        assert status == expected
        assert "Content-Type: application/json" in head

        for name, value in SECURITY_HEADERS.items():
            assert f"{name}: {value}" in head


def test_repeated_refused_posts_with_a_body_always_get_their_response(dashboard, scans):
    # The failing pattern seen on Windows: many refused POSTs, each with a body.
    payload = {"path": "/somewhere", "parameter_mode": "strict", "pad": "x" * 12_000}
    headers = scan_headers(dashboard)
    headers[TOKEN_HEADER] = "wrong"
    body = json.dumps(payload)

    for _ in range(200):
        response, data = call(dashboard, "POST", "/api/scan", body, headers)

        assert response.status == 403
        assert error_of(data)["kind"] == "http"

    assert scans == []


def test_malformed_request_line_gets_a_json_error(dashboard):
    client = socket.create_connection(("127.0.0.1", dashboard.port), timeout=10)
    client.sendall(b"GARBAGE\r\n\r\n")
    data = b""
    while chunk := client.recv(65536):
        data += chunk
    client.close()

    assert data.startswith(b"HTTP/1.0 400 ")
    assert b"Content-Security-Policy" in data
    assert b'"kind": "http"' in data


@pytest.mark.parametrize(
    "raw",
    ["", "not json", "{", "[1]", "null", '"x"', "3", b"\xff\xfe".decode("latin-1")],
)
def test_invalid_json_is_an_input_error(dashboard, raw):
    response, data = scan(dashboard, None, raw=raw)

    assert response.status == 400
    assert error_of(data)["kind"] == "input"


def test_non_utf8_body_is_an_input_error(dashboard):
    response, data = call(
        dashboard, "POST", "/api/scan", b"\xff\xfe\x00", scan_headers(dashboard)
    )

    assert response.status == 400
    assert error_of(data)["kind"] == "input"


def test_deeply_nested_json_is_an_input_error(dashboard):
    response, data = scan(dashboard, None, raw="[" * 5000)

    assert response.status == 400
    assert error_of(data)["kind"] == "input"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"path": "x"},
        {"parameter_mode": "strict"},
        {"path": "x", "parameter_mode": "strict", "extra": 1},
        {"path": 5, "parameter_mode": "strict"},
        {"path": None, "parameter_mode": "strict"},
        {"path": "", "parameter_mode": "strict"},
        {"path": "   ", "parameter_mode": "strict"},
        {"path": "a\x00b", "parameter_mode": "strict"},
        {"path": "x" * (MAX_PATH_CHARS + 1), "parameter_mode": "strict"},
        {"path": "x", "parameter_mode": "fast"},
        {"path": "x", "parameter_mode": "STRICT"},
        {"path": "x", "parameter_mode": None},
        {"path": "x", "parameter_mode": 1},
        {"path": "x", "parameter_mode": ["strict"]},
        {"path": "x", "parameter_mode": {"a": 1}},
    ],
)
def test_invalid_fields_are_input_errors(dashboard, payload):
    response, data = scan(dashboard, payload)

    assert response.status == 400
    assert error_of(data)["kind"] == "input"


# -- scanning --------------------------------------------------------------


def test_successful_scan_returns_view_and_export(dashboard, project):
    response, data = scan(dashboard, valid(project))
    payload = json.loads(data)

    assert response.status == 200
    assert response.getheader("Content-Type") == "application/json"
    assert set(payload) == {"view", "export"}
    assert payload["view"]["status"] == "complete"
    assert payload["view"]["findings_total"] == 1
    assert payload["view"]["findings"][0]["cwe"] == "CWE-78"
    assert payload["view"]["resolved_target"].endswith(project.name)


def test_export_equals_the_cli_json_output_exactly(dashboard, project, capsys):
    _, data = scan(dashboard, valid(project))
    export = json.loads(data)["export"]

    cli_main(["scan", str(project), "--format", "json"])
    cli_output = capsys.readouterr().out

    assert export == cli_output
    assert export.endswith("}\n") and not export.endswith("\n\n")
    assert json.loads(export)["schema_version"] == "2.1"


def test_export_for_recall_mode_equals_the_cli_output(dashboard, project, capsys):
    (project / "m.py").write_text("import os\ndef f(x):\n    os.system(x)\n")
    _, data = scan(dashboard, valid(project, "recall"))
    cli_main(["scan", str(project), "--format", "json", "--parameter-mode", "recall"])

    assert json.loads(data)["export"] == capsys.readouterr().out
    assert json.loads(json.loads(data)["export"])["metadata"]["settings"] == {
        "parameter_mode": "recall"
    }


def test_export_contains_every_finding_when_the_view_is_truncated(dashboard, tmp_path):
    lines = ["import os"] + ["os.system(input())"] * 1100
    (tmp_path / "big.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _, data = scan(dashboard, valid(tmp_path))
    payload = json.loads(data)

    assert payload["view"]["findings_total"] == 1100
    assert payload["view"]["findings_shown"] == 1000
    assert payload["view"]["truncated"] is True
    assert len(payload["view"]["findings"]) == 1000
    assert len(json.loads(payload["export"])["findings"]) == 1100


def test_response_is_ascii_json(dashboard, tmp_path):
    (tmp_path / "café.py").write_text(VULNERABLE, encoding="utf-8")
    response, data = scan(dashboard, valid(tmp_path))

    assert response.status == 200
    assert data.isascii()
    assert "café.py" in json.loads(data)["view"]["findings"][0]["file"]


def test_scanner_reported_errors_are_a_normal_200_result(dashboard, tmp_path):
    missing = tmp_path / "does-not-exist"
    response, data = scan(dashboard, valid(missing))
    view = json.loads(data)["view"]

    assert response.status == 200
    assert view["status"] == "failed"
    assert view["issues"][0]["code"] == "target-not-found"
    assert "error" not in json.loads(data)


def test_partial_scan_is_a_200_result_with_issues(dashboard, project):
    (project / "bad.py").write_text("def (:\n", encoding="utf-8")
    response, data = scan(dashboard, valid(project))
    view = json.loads(data)["view"]

    assert response.status == 200
    assert view["status"] == "partial"
    assert view["findings_total"] == 1
    assert [i["code"] for i in view["issues"]] == ["syntax-error"]


def test_a_single_file_can_be_scanned(dashboard, project):
    response, data = scan(dashboard, valid(project / "app.py"))

    assert response.status == 200
    assert json.loads(data)["view"]["findings_total"] == 1


def test_scanned_code_is_never_executed(dashboard, tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system(input())\n"
    (tmp_path / "evil.py").write_text(code, encoding="utf-8")
    scan(dashboard, valid(tmp_path))

    assert not marker.exists()


def test_scanning_writes_nothing_to_the_project(dashboard, project):
    before = sorted(p.name for p in project.rglob("*"))
    scan(dashboard, valid(project))

    assert sorted(p.name for p in project.rglob("*")) == before


def test_engine_value_error_is_an_input_error(dashboard, monkeypatch):
    class Refusing:
        def __init__(self, **kwargs):
            pass

        def scan_path(self, path):
            raise ValueError("path is not acceptable")

    monkeypatch.setattr(server_module, "ScanEngine", Refusing)
    response, data = scan(dashboard, valid("x"))

    assert response.status == 400
    assert error_of(data) == {"kind": "input", "message": "path is not acceptable"}


def test_unexpected_exception_is_a_generic_internal_error(
    dashboard, project, monkeypatch, capsys
):
    class Crashing:
        def __init__(self, **kwargs):
            pass

        def scan_path(self, path):
            raise RuntimeError("secret-detail /private/path")

    monkeypatch.setattr(server_module, "ScanEngine", Crashing)
    response, data = scan(dashboard, valid(project))

    assert response.status == 500
    assert error_of(data)["kind"] == "internal"
    assert b"secret-detail" not in data
    assert b"/private/path" not in data
    assert "secret-detail" in capsys.readouterr().err  # kept on the server console


def test_server_keeps_working_after_an_internal_error(dashboard, project, monkeypatch):
    real = server_module.ScanEngine

    class Crashing:
        def __init__(self, **kwargs):
            pass

        def scan_path(self, path):
            raise RuntimeError("boom")

    monkeypatch.setattr(server_module, "ScanEngine", Crashing)
    assert scan(dashboard, valid(project))[0].status == 500

    monkeypatch.setattr(server_module, "ScanEngine", real)
    assert scan(dashboard, valid(project))[0].status == 200


def test_only_one_scan_runs_at_a_time(dashboard, project, monkeypatch):
    real = server_module.ScanEngine
    started, release = threading.Event(), threading.Event()

    class Slow:
        def __init__(self, **kwargs):
            self._engine = real(**kwargs)

        def scan_path(self, path):
            started.set()
            assert release.wait(timeout=10)

            return self._engine.scan_path(path)

    monkeypatch.setattr(server_module, "ScanEngine", Slow)
    first = {}

    def run_first():
        first["status"] = scan(dashboard, valid(project))[0].status

    thread = threading.Thread(target=run_first)
    thread.start()
    assert started.wait(timeout=10)

    response, data = scan(dashboard, valid(project))

    assert response.status == 409
    assert error_of(data)["kind"] == "http"

    release.set()
    thread.join(timeout=10)

    assert first["status"] == 200
    assert scan(dashboard, valid(project))[0].status == 200


def test_the_scan_lock_is_released_after_an_input_error(dashboard, project):
    assert scan(dashboard, valid("x"), raw="nope")[0].status == 400
    assert scan(dashboard, valid(project))[0].status == 200
    assert not dashboard.scan_lock.locked()


def test_error_kinds_are_distinct_for_http_input_and_internal(
    dashboard, project, monkeypatch
):
    http_kind = error_of(scan(dashboard, valid(project), X_VulnSight_Token="x")[1])
    input_kind = error_of(scan(dashboard, valid(project), raw="[]")[1])

    class Crashing:
        def __init__(self, **kwargs):
            pass

        def scan_path(self, path):
            raise RuntimeError("x")

    monkeypatch.setattr(server_module, "ScanEngine", Crashing)
    internal_kind = error_of(scan(dashboard, valid(project))[1])

    assert {http_kind["kind"], input_kind["kind"], internal_kind["kind"]} == {
        "http",
        "input",
        "internal",
    }


def test_assets_table_is_exactly_the_three_expected_routes():
    assert set(ASSETS) == {"/", "/static/app.js", "/static/style.css"}
