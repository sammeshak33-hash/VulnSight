# Local dashboard (M2.1a)

A small browser dashboard for demonstrating VulnSight. It scans a directory (or a single file) on **your own computer** with the existing `ScanEngine` and shows the `ScanResult`. It adds no scanning logic, no dependencies and no changes to the finding schema (2.1).

## Start it

```
python -m vulnsight.ui
python -m vulnsight.ui --port 9000 --no-browser
```

| Option | Meaning |
|---|---|
| `--port N` | TCP port on `127.0.0.1`. Default 8765. `0` picks a free port. |
| `--no-browser` | Do not open the page in a browser. The URL is printed either way. |

There is **no host option**. The server listens on `127.0.0.1` only, so other computers cannot reach it. Press Ctrl+C to stop. Exit codes: 0 stopped normally, 1 could not listen (for example the port is in use), 2 usage error. `vulnsight scan` and the rest of the command line are unchanged.

## Using the page

1. Type the path of a directory or file on this computer and choose the parameter mode (`strict` is the default; `recall` is experimental and gives low-confidence findings).
2. Click **Scan**. The scan runs on the server, one at a time, and a large project can take a while. There is no time limit and no cancel button, as with the command line.
3. The page shows a summary (status, target, resolved path, files scanned, findings, errors, warnings), the findings table (CWE, confidence, file, line, sink), a detail panel for the selected finding (message, rule, taint effect, location, sink, taint evidence with trace steps and neutralizations) and the scan errors and warnings.
4. **Download JSON** saves the result.

Notes:

- Columns are shown **1-based**, like the command-line text report. The JSON keeps the schema's 0-based columns.
- Severity and ML verification are not produced yet. The page says "Not assessed" for a missing severity and "Not run" for a missing ML verification. Nothing is made up. There are no precision or recall numbers (that is M2.2).
- A taint trace that was shortened by the trace-length limit shows one line, "... intermediate trace steps omitted ...", where the steps were left out. That line marks the gap; it is not a taint operation and has no line number.
- A `partial` or `failed` scan is marked clearly. Its findings are incomplete. Scanner problems (syntax errors, unreadable files, a missing path, links) are part of a normal result and appear under "Scan errors and warnings".
- The page shows at most **1,000 findings** and says so when it cuts the list. The JSON download always contains **every** finding. Issues are never cut.

## The downloaded file

The download is exactly what `vulnsight scan PATH --format json` prints: `ScanResult.to_json()` plus one final newline, saved without any change. The server builds that text and the page only saves it. `ScanResult.target` is the path as you typed it; the resolved absolute path is shown beside it for convenience and is not part of the JSON.

## How it works

```
browser page  --POST /api/scan-->  server  -->  ScanEngine.scan_path  -->  ScanResult
   (static HTML, CSS, JS)       (checks)          (existing, unchanged)        |
        ^                                                                       v
        +------------------ {"view": ..., "export": ...} <---- build_view + to_json()
```

- `vulnsight/ui/view.py` turns a `ScanResult` into plain display data. It is pure: no files, no server.
- `vulnsight/ui/server.py` is the HTTP server (standard library only).
- `vulnsight/ui/static/` holds the page, script and style sheet, loaded with `importlib.resources`.
- The server keeps no state between requests. The page holds the last result in memory, so reloading it clears the result.

## Security

The dashboard can scan any directory the user running it can read, so it must only be reachable by that user.

- **Loopback only.** It binds to `127.0.0.1`. On Windows the socket is bound exclusively so no other program can share the port; elsewhere address reuse only speeds up restarts.
- **Host check.** Every request must carry `Host: 127.0.0.1:<port>` or `localhost:<port>`. This stops DNS rebinding, where a web page tries to reach a local server through a name that resolves to 127.0.0.1.
- **Token and origin.** Each launch makes a random token that is placed in the page. `POST /api/scan` needs that token, an `Origin` that matches the server, `Content-Type: application/json` and a body of at most 16 KiB. Another web page open in your browser cannot read the token, so it cannot start scans.
- **Fixed routes.** Only `/`, `/static/app.js` and `/static/style.css` are served, from a fixed table. The request path is never used to build a file name, so path traversal is not possible and no other file is readable. Other paths give 404 and other methods give 405.
- **One scan at a time.** A second request while a scan runs gets 409.
- **Security headers.** A strict Content-Security-Policy (no inline script, no other origins, no framing), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` and cross-origin isolation headers. No CORS headers are sent.
- **Untrusted text.** Messages, callee names, origin names and file names come from scanned code. The page adds every one of them with `textContent`. It never uses `innerHTML`, `eval` or `document.write`, and a test scans the script for such calls.
- **No execution.** Scanned code is only parsed, never imported or run. The server writes nothing to the project or anywhere else, and makes no outbound requests.
- **Quiet logs.** Requests are not logged. Unexpected errors are printed to the server console only; the browser gets a generic message.

Not covered: the server has no login. Anyone who can run programs as you on this computer, or reach `127.0.0.1` as you, can use it. Do not expose the port through a tunnel or proxy.

## Errors

Error responses are JSON `{"error": {"kind": ..., "message": ...}}` and the page shows each kind differently:

| Kind | HTTP status | Meaning |
|---|---|---|
| `http` | 403, 404, 405, 408, 409, 411, 413, 415 and other protocol errors | The server refused the request itself (wrong host, token or origin, wrong route or method, too large, a scan already running). |
| `input` | 400 | The content was invalid: bad JSON, wrong or missing fields, an empty path, a null character, an unknown mode. |
| `internal` | 500 | An unexpected failure. Details are on the server console only. |
| (network) | none | The page could not reach the server. Shown by the page only. |

Problems found by the scanner are **not** errors of this kind. A missing directory, a syntax error or a symbolic-link target gives a normal 200 response whose status is `partial` or `failed` and whose issues describe the problem.

## Limits

- Local use only: one user, one machine, no authentication.
- Only Python source is scanned, and only the CWE-78 detector exists, so the findings list is short.
- No scan history, no source-code view, no cancellation, no progress bar.
- Large results: the page lists 1,000 findings; use the JSON for the rest.
- The Windows-only socket option (`SO_EXCLUSIVEADDRUSE`) is exercised by the Windows test suite. In local Windows validation, refused-POST cleanup also passed 1,000-request stress runs with both small bodies and 12,012-byte bodies (2,000 requests total, no connection failures). These runs cover those tested conditions; they are not an exhaustive guarantee for every client disconnect or malformed request. Browser rendering is checked by the optional browser tests (`tests/test_ui_browser.py`, which need Playwright and a browser) where those are installed.

## Tests

`tests/test_ui_view.py` (display model), `tests/test_ui_server.py` (routes, checks, errors, export equality with the CLI), `tests/test_ui_static.py` (no dangerous APIs, packaged files), `tests/test_ui_launcher.py` (`python -m vulnsight.ui`) and the optional `tests/test_ui_browser.py`. All except the last need only the standard library and run in the normal CI.
