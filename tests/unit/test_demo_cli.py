"""The demo starts only Streamlit; its gateway lives inside each local session."""

import os
import socket
import subprocess
import sys
from contextlib import ExitStack
from http.client import HTTPConnection
from pathlib import Path
from time import monotonic, sleep

import pytest
from typer.testing import CliRunner

from corridor.cli import app


def test_demo_bootstraps_local_streamlit_in_current_process(monkeypatch):
    from streamlit import config
    from streamlit.web import bootstrap

    monkeypatch.setattr(config, "_config_options", None)
    calls = []
    monkeypatch.setattr(bootstrap, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    result = CliRunner().invoke(app, ["demo", "--port", "8510"])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0].replace("\\", "/").endswith("corridor/ui/app.py")
    assert kwargs["flag_options"]["server.address"] == "127.0.0.1"
    assert kwargs["flag_options"]["server.port"] == 8510
    assert kwargs["flag_options"]["browser.gatherUsageStats"] is False


@pytest.mark.parametrize("headless", [False, True])
def test_demo_applies_requested_options_before_server_creation(monkeypatch, headless):
    from streamlit import config
    from streamlit.web import bootstrap

    monkeypatch.setattr(config, "_config_options", None)
    bootstrap.load_config_options({
        "server.address": "0.0.0.0",
        "server.port": 8501,
        "server.headless": not headless,
        "browser.gatherUsageStats": True,
    })
    observed = []
    expected = {
        "server.address": "127.0.0.1",
        "server.port": 8517,
        "server.headless": headless,
        "browser.gatherUsageStats": False,
    }

    def inspect_startup(*args, **kwargs):
        observed.append({key: config.get_option(key) for key in expected})

    monkeypatch.setattr(bootstrap, "run", inspect_startup)
    result = CliRunner().invoke(
        app, ["demo", "--port", "8517", "--headless" if headless else "--no-headless"]
    )
    assert result.exit_code == 0, result.output
    assert observed == [expected]


def test_two_demo_processes_listen_on_cli_ports_despite_conflicting_environment(tmp_path):
    """Exercise startup sockets, not just the flags forwarded to bootstrap.run."""
    processes = []
    with ExitStack() as stack:
        conflicting = stack.enter_context(socket.socket())
        conflicting.bind(("127.0.0.1", 0))
        conflicting.listen()
        environment_port = conflicting.getsockname()[1]
        reserved = [stack.enter_context(socket.socket()) for _ in range(2)]
        for listener in reserved:
            listener.bind(("127.0.0.1", 0))
        ports = [listener.getsockname()[1] for listener in reserved]
        for listener in reserved:
            listener.close()
        environment = {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "STREAMLIT_SERVER_PORT": str(environment_port),
        }
        try:
            for port in ports:
                log = tmp_path / f"demo-{port}.log"
                output = stack.enter_context(log.open("wb"))
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "from corridor.cli import app; app()",
                        "demo",
                        "--port",
                        str(port),
                        "--headless",
                    ],
                    cwd=Path(__file__).resolve().parents[2],
                    env=environment,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                processes.append((process, port, log))
            for process, port, log in processes:
                deadline = monotonic() + 25
                healthy = False
                while monotonic() < deadline:
                    assert process.poll() is None, log.read_text(encoding="utf-8")
                    connection = HTTPConnection("127.0.0.1", port, timeout=0.2)
                    try:
                        connection.request("GET", "/_stcore/health")
                        response = connection.getresponse()
                        healthy = response.status == 200 and response.read() == b"ok"
                    except OSError:
                        pass
                    finally:
                        connection.close()
                    if healthy:
                        break
                    sleep(0.1)
                assert healthy, log.read_text(encoding="utf-8")
                assert f"URL: http://127.0.0.1:{port}" in log.read_text(encoding="utf-8")
                print(f"CLI port {port}: HTTP 200 ok; process {process.pid}; log {log}")
            assert all(process.poll() is None for process, _, _ in processes)
            print(
                "Both CLI ports listened concurrently; "
                f"conflicting environment port {environment_port}."
            )
        finally:
            for process, _, _ in processes:
                if process.poll() is None:
                    process.terminate()
            for process, _, _ in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
