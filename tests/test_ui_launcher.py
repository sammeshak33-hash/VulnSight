"""Tests for ``python -m vulnsight.ui``."""

import socket
import subprocess
import sys

import pytest

import vulnsight.ui
import vulnsight.ui.__main__ as launcher
from vulnsight.ui.server import DEFAULT_PORT, DashboardServer


def test_importing_the_package_starts_nothing():
    assert vulnsight.ui.__doc__
    assert not hasattr(vulnsight.ui, "serve_forever")


def test_default_port_and_flags():
    arguments = launcher.build_parser().parse_args([])

    assert arguments.port == DEFAULT_PORT == 8765
    assert arguments.no_browser is False


@pytest.mark.parametrize(
    "argv",
    [["--host", "0.0.0.0"], ["--host=0.0.0.0"], ["--bind", "0.0.0.0"], ["0.0.0.0"]],
)
def test_there_is_no_host_or_remote_option(argv, capsys):
    with pytest.raises(SystemExit) as stop:
        launcher.build_parser().parse_args(argv)

    assert stop.value.code == 2


def test_main_returns_the_usage_code_for_bad_arguments(capsys):
    assert launcher.main(["--host", "0.0.0.0"]) == 2
    assert launcher.main(["--port", "abc"]) == 2
    assert launcher.main(["--port", "70000", "--no-browser"]) == 2
    assert "port" in capsys.readouterr().err


def test_help_exits_cleanly(capsys):
    assert launcher.main(["--help"]) == 0
    assert "127.0.0.1" in capsys.readouterr().out


def stop_immediately(monkeypatch):
    def interrupted(self, *args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(DashboardServer, "serve_forever", interrupted)


def test_main_prints_the_loopback_url_and_stops_on_ctrl_c(monkeypatch, capsys):
    stop_immediately(monkeypatch)
    monkeypatch.setattr(launcher.webbrowser, "open", lambda url: True)

    assert launcher.main(["--port", "0"]) == 0
    out = capsys.readouterr().out

    assert "http://127.0.0.1:" in out
    assert "Ctrl+C" in out


def test_browser_opens_by_default_and_not_with_the_flag(monkeypatch, capsys):
    stop_immediately(monkeypatch)
    opened = []
    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)

    launcher.main(["--port", "0"])
    assert len(opened) == 1 and opened[0].startswith("http://127.0.0.1:")

    opened.clear()
    launcher.main(["--port", "0", "--no-browser"])
    assert opened == []


def test_a_failing_browser_does_not_stop_the_server(monkeypatch, capsys):
    stop_immediately(monkeypatch)

    def broken(url):
        raise RuntimeError("no browser")

    monkeypatch.setattr(launcher.webbrowser, "open", broken)

    assert launcher.main(["--port", "0"]) == 0


def test_the_token_is_not_part_of_the_printed_url(monkeypatch, capsys):
    stop_immediately(monkeypatch)
    created = []
    original = launcher.create_server

    def spy(port):
        server = original(port)
        created.append(server)

        return server

    monkeypatch.setattr(launcher, "create_server", spy)
    launcher.main(["--port", "0", "--no-browser"])

    assert created[0].token not in capsys.readouterr().out


def test_busy_port_gives_a_clear_error_and_exit_code_one(capsys):
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()

    try:
        port = holder.getsockname()[1]

        assert launcher.main(["--port", str(port), "--no-browser"]) == 1
        assert f"cannot listen on 127.0.0.1:{port}" in capsys.readouterr().err
    finally:
        holder.close()


def test_server_socket_is_closed_after_stopping(monkeypatch):
    stop_immediately(monkeypatch)
    sockets = []
    original = launcher.create_server

    def spy(port):
        server = original(port)
        sockets.append(server)

        return server

    monkeypatch.setattr(launcher, "create_server", spy)
    launcher.main(["--port", "0", "--no-browser"])

    assert sockets[0].socket.fileno() == -1


def test_module_runs_with_python_dash_m_and_rejects_a_host_option():
    completed = subprocess.run(
        [sys.executable, "-m", "vulnsight.ui", "--host", "0.0.0.0"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 2
    assert "unrecognized arguments" in completed.stderr
