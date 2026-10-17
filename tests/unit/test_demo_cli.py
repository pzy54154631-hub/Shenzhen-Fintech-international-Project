"""The demo starts only Streamlit; its gateway lives inside each local session."""

from typer.testing import CliRunner

from corridor.cli import app


def test_demo_bootstraps_local_streamlit_in_current_process(monkeypatch):
    from streamlit.web import bootstrap

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
