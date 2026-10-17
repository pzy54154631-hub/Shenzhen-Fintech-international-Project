"""Start the local Streamlit app with an in-process synthetic gateway."""

from pathlib import Path

import typer


def run(
    port: int = typer.Option(8501, min=1024, max=65535), headless: bool = typer.Option(True)
) -> None:
    from streamlit.web import bootstrap

    entry = Path(__file__).resolve().parents[1] / "ui" / "app.py"
    flag_options = {
        "server.address": "127.0.0.1",
        "server.port": port,
        "server.headless": headless,
        "browser.gatherUsageStats": False,
    }
    # bootstrap.run only retains flags for config watchers; startup reads the
    # loaded configuration, just as Streamlit's own CLI initializes it first.
    bootstrap.load_config_options(flag_options=flag_options)
    typer.echo(f"Synthetic bank demo: http://127.0.0.1:{port}; planner=scripted")
    bootstrap.run(
        str(entry),
        is_hello=False,
        args=[],
        flag_options=flag_options,
    )


def register(app: typer.Typer) -> None:
    app.command("demo")(run)
