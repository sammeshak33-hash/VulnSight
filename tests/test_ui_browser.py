"""Optional browser checks of the real page.

These run only where Playwright and a browser are installed (they are not part
of the normal CI install) and are skipped everywhere else.
"""

import json
import threading

import pytest

import vulnsight.ui.server as server_module
from tests.finding_builders import make_finding, make_label
from vulnsight.findings import Location, assign_occurrences
from vulnsight.scan_result import (
    IssueLevel,
    ScanIssue,
    ScanResult,
    ScanStatus,
)
from vulnsight.scanner.taint_model import TraceKind
from vulnsight.ui.server import create_server

sync_api = pytest.importorskip("playwright.sync_api")

HOSTILE = '<img src=x onerror="window.__pwned=1"> <b>bold</b>'


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Exception as error:  # no browser installed
            pytest.skip(f"no usable browser: {error}")

        yield instance
        instance.close()


@pytest.fixture
def dashboard():
    server = create_server(0)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()

    yield server

    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def page(browser, dashboard):
    context = browser.new_context(accept_downloads=True)
    opened = context.new_page()
    opened.goto(dashboard.url)

    yield opened

    context.close()


def scan(page, path, mode="strict"):
    page.fill("#path", str(path))
    page.select_option("#mode", mode)
    page.click("#scan-button")


def test_hostile_text_is_shown_as_text_and_never_runs(page, monkeypatch):
    finding = make_finding(
        message=HOSTILE,
        location=Location("<b>x</b>.py", 3, 0),
        enclosing_function="<i>fn</i>",
    )
    issue = ScanIssue(IssueLevel.WARNING, "code", HOSTILE, file="<u>f</u>.py", line=2)

    class Fake:
        def __init__(self, **kwargs):
            pass

        def scan_path(self, path):
            return ScanResult(
                status=ScanStatus.COMPLETE,
                target="<h1>t</h1>",
                findings=assign_occurrences([finding]),
                issues=(issue,),
            )

    monkeypatch.setattr(server_module, "ScanEngine", Fake)
    scan(page, "anything")
    page.wait_for_selector("#findings-body tr")
    page.click("#findings-body button")
    page.wait_for_selector("#detail-card:not([hidden])")

    assert page.evaluate("window.__pwned") is None
    assert page.locator("#findings-body td.mono").first.inner_text() == "<b>x</b>.py"
    assert HOSTILE in page.locator("#detail .message").inner_text()
    assert HOSTILE in page.locator("#issues-body").inner_text()
    assert "<h1>t</h1>" in page.locator("#summary").inner_text()
    assert page.locator("#detail b, #issues-body u, #summary h1, img").count() == 0


def test_scan_shows_summary_findings_details_and_issues(page, tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n\n\ndef run():\n    os.system(input())\n", encoding="utf-8"
    )
    (tmp_path / "bad.py").write_text("def (:\n", encoding="utf-8")
    scan(page, tmp_path)
    page.wait_for_selector("#findings-body tr")

    summary = page.locator("#summary").inner_text()

    assert "partial" in summary
    assert page.locator("#findings-body tr").count() == 1
    assert "CWE-78" in page.locator("#findings-body").inner_text()
    assert "syntax-error" in page.locator("#issues-body").inner_text()

    page.click("#findings-body button")
    detail = page.locator("#detail").inner_text()

    assert "os.system" in detail
    assert "input()" in detail
    assert "Not assessed" in detail
    assert "Not run" in detail


def test_missing_severity_and_verification_are_labelled_differently(page, tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n\n\ndef run():\n    os.system(input())\n", encoding="utf-8"
    )
    scan(page, tmp_path)
    page.wait_for_selector("#findings-body tr")
    page.click("#findings-body button")

    severity = page.locator('#detail dt:text-is("Severity") + dd')
    verification = page.locator('#detail dt:text-is("ML verification") + dd')

    assert severity.inner_text() == "Not assessed"
    assert verification.inner_text() == "Not run"


def test_elided_trace_marker_is_shown_as_a_gap(page, monkeypatch):
    label = make_label(steps=(TraceKind.ASSIGN,) * 20)
    finding = make_finding(evidence=(label,))

    class Fake:
        def __init__(self, **kwargs):
            pass

        def scan_path(self, path):
            return ScanResult(
                status=ScanStatus.COMPLETE, findings=assign_occurrences([finding])
            )

    monkeypatch.setattr(server_module, "ScanEngine", Fake)
    scan(page, "anything")
    page.wait_for_selector("#findings-body tr")
    page.click("#findings-body button")
    page.wait_for_selector("#detail-card:not([hidden])")

    items = page.locator("#detail .trace li")
    texts = [items.nth(i).inner_text() for i in range(items.count())]
    marker = [t for t in texts if "omitted" in t]

    assert marker == ["... intermediate trace steps omitted ..."]
    assert texts.index(marker[0]) == len(texts) // 2
    assert not any(t.startswith("elided") for t in texts)
    assert len(texts) == 12


def test_at_most_one_thousand_rows_and_the_export_has_everything(page, tmp_path):
    lines = ["import os"] + ["os.system(input())"] * 1100
    (tmp_path / "big.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    scan(page, tmp_path)
    page.wait_for_selector("#findings-body tr")

    assert page.locator("#findings-body tr").count() == 1000
    assert "first 1000 of 1100" in page.locator("#truncation").inner_text()

    with page.expect_download() as download:
        page.click("#export-button")

    saved = open(download.value.path(), "rb").read()
    document = json.loads(saved)

    assert download.value.suggested_filename == "vulnsight-scan.json"
    assert len(document["findings"]) == 1100
    assert saved.endswith(b"}\n") and not saved.endswith(b"\n\n")


def test_input_http_and_scanner_errors_are_shown_differently(page, tmp_path):
    scan(page, tmp_path / "missing")
    page.wait_for_selector("#results:not([hidden])")

    assert "failed" in page.locator("#status-note").inner_text()
    assert page.locator("#banner").is_hidden()

    page.fill("#path", "   ")
    page.evaluate("document.getElementById('path').removeAttribute('required')")
    page.click("#scan-button")
    page.wait_for_selector("#banner:not([hidden])")

    assert "Invalid input" in page.locator("#banner").inner_text()


def test_a_wrong_token_is_reported_as_a_refused_request(browser, dashboard, tmp_path):
    context = browser.new_context()
    page = context.new_page()
    page.goto(dashboard.url)
    page.evaluate(
        "document.querySelector('meta[name=vulnsight-token]')"
        ".setAttribute('content', 'wrong')"
    )
    # the script read the token at load time, so reload it with a bad one
    page.route(
        "**/api/scan",
        lambda route: route.continue_(
            headers={**route.request.headers, "x-vulnsight-token": "wrong"}
        ),
    )
    scan(page, tmp_path)
    page.wait_for_selector("#banner:not([hidden])")

    text = page.locator("#banner").inner_text()

    assert "refused the request" in text
    assert "HTTP 403" in text
    context.close()


def test_recall_mode_shows_its_experimental_note(page):
    assert page.locator("#mode-note").is_hidden()

    page.select_option("#mode", "recall")

    assert page.locator("#mode-note").is_visible()


def test_page_makes_no_requests_to_other_hosts(browser, dashboard, tmp_path):
    context = browser.new_context()
    page = context.new_page()
    hosts = set()
    page.on("request", lambda request: hosts.add(request.url.split("/")[2]))
    page.goto(dashboard.url)
    (tmp_path / "a.py").write_text("x = 1\n")
    scan(page, tmp_path)
    page.wait_for_selector("#results:not([hidden])")

    assert hosts == {f"127.0.0.1:{dashboard.port}"}
    context.close()
