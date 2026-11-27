"""Static checks of the packaged frontend files."""

import re
import sys
from importlib import resources
from pathlib import Path

import pytest

from vulnsight.ui.server import ASSETS, load_asset

ASSET_NAMES = sorted(name for name, _ in ASSETS.values())
STATIC_DIR = Path(__file__).resolve().parent.parent / "vulnsight" / "ui" / "static"


def text(name):
    return load_asset(name).decode("utf-8")


def test_every_served_asset_is_packaged():
    for name in ASSET_NAMES:
        assert resources.files("vulnsight.ui").joinpath("static", name).is_file()


def test_static_directory_holds_only_the_served_assets():
    assert sorted(p.name for p in STATIC_DIR.iterdir()) == ASSET_NAMES


def test_pyproject_packages_the_static_files():
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()

    assert '"vulnsight.ui" = ["static/*"]' in pyproject


def test_dependencies_stay_empty():
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()

    assert "dependencies = []" in pyproject
    assert "streamlit" not in pyproject.lower()


def test_ui_modules_import_only_the_standard_library_and_vulnsight():
    allowed_third_party = set()
    root = Path(__file__).resolve().parent.parent / "vulnsight" / "ui"

    for source in root.glob("*.py"):
        for line in source.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*(?:from|import)\s+([A-Za-z_][\w]*)", line)

            if match:
                module = match.group(1)

                assert (
                    module in sys.stdlib_module_names
                    or module == "vulnsight"
                    or module in allowed_third_party
                ), f"{source.name} imports {module}"


FORBIDDEN_IN_SCRIPT = [
    r"\.innerHTML",
    r"\.outerHTML",
    r"insertAdjacentHTML",
    r"document\.write",
    r"\beval\s*\(",
    r"new\s+Function",
    r"setTimeout\s*\(\s*[\"'`]",
    r"setInterval\s*\(\s*[\"'`]",
    r"\bimport\s*\(",
    r"\bXMLHttpRequest\b",
    r"WebSocket",
    r"localStorage|sessionStorage|document\.cookie",
    r"srcdoc",
    r"createContextualFragment",
    r"DOMParser",
    r"\.src\s*=",
]


@pytest.mark.parametrize("pattern", FORBIDDEN_IN_SCRIPT)
def test_script_avoids_dangerous_apis(pattern):
    assert re.search(pattern, text("app.js")) is None, pattern


def test_only_the_blob_download_link_sets_an_href():
    assert re.findall(r"\.href\s*=\s*([^;]+);", text("app.js")) == ["url"]


def test_script_builds_text_with_textcontent():
    script = text("app.js")

    assert "textContent" in script
    assert "createElement" in script


def test_page_has_no_inline_script_style_or_event_handlers():
    page = text("index.html")

    assert re.search(r"<script(?![^>]*\bsrc=)[^>]*>", page) is None
    assert all(
        not body.strip()
        for body in re.findall(r"<script\b[^>]*>(.*?)</script>", page, re.S)
    )
    assert re.search(r"\son[a-z]+\s*=", page, re.I) is None
    assert re.search(r"\sstyle\s*=", page, re.I) is None
    assert "<style" not in page.lower()
    assert "javascript:" not in page.lower()


def test_assets_load_nothing_from_other_origins():
    for name in ASSET_NAMES:
        content = text(name)

        assert re.search(r"https?://", content) is None, name
        assert "//cdn" not in content
        assert "@import" not in content
        assert "url(" not in content


def test_page_references_only_its_own_assets():
    page = text("index.html")
    references = re.findall(r'(?:src|href)="([^"]+)"', page)

    assert sorted(references) == ["/static/app.js", "/static/style.css"]


def test_page_has_a_single_token_placeholder_in_a_meta_tag():
    page = text("index.html")

    assert page.count("__VULNSIGHT_TOKEN__") == 1
    assert '<meta name="vulnsight-token" content="__VULNSIGHT_TOKEN__">' in page
    assert "__VULNSIGHT_TOKEN__" not in text("app.js")


def test_page_never_requests_other_routes():
    script = text("app.js")

    assert re.findall(r'fetch\(\s*"([^"]+)"', script) == ["/api/scan"]


def test_script_sends_the_token_header_and_json():
    script = text("app.js")

    assert '"X-VulnSight-Token"' in script
    assert '"Content-Type": "application/json"' in script


def test_export_is_saved_as_received():
    script = text("app.js")

    assert "new Blob([exportText]" in script
    assert "exportText +" not in script
    assert '+ "\\n"' not in script


def test_script_shows_the_four_error_kinds_and_truncation():
    script = text("app.js")

    for kind in ("http:", "input:", "internal:", "network:"):
        assert kind in script
    assert "findings_total" in script
    assert "JSON download contains all" in script


def test_script_labels_missing_severity_and_verification_differently():
    script = text("app.js")

    assert 'optional(finding.severity, "Not assessed")' in script
    assert 'optional(finding.verification, "Not run")' in script
    assert script.count('"Not assessed"') == 1
    assert script.count('"Not run"') == 1


def test_script_marks_elided_trace_steps_as_a_gap_not_an_operation():
    script = text("app.js")
    branch = script.split('step.kind === "elided"', 1)[1].split("return;", 1)[0]

    assert "... intermediate trace steps omitted ..." in branch
    assert "step.line" not in branch
    assert "step.column" not in branch
    assert ".elided" in text("style.css")


def test_page_footer_names_both_missing_value_labels():
    page = text("index.html")

    assert "Not assessed" in page
    assert "Not run" in page
