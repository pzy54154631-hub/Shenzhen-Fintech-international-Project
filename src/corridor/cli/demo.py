"""Start the local Streamlit app with an in-process synthetic gateway."""

from pathlib import Path

import typer


def run(
    port: int = typer.Option(8501, min=1024, max=65535), headless: bool = typer.Option(True)
) -> None:
    from streamlit.web import bootstrap

    entry = Path(__file__).resolve().parents[1] / "ui" / "app.py"
    typer.echo(f"Synthetic bank demo: http://127.0.0.1:{port}; planner=scripted")
    bootstrap.run(
        str(entry),
        is_hello=False,
        args=[],
        flag_options={
            "server.address": "127.0.0.1",
            "server.port": port,
            "server.headless": headless,
            "browser.gatherUsageStats": False,
        },
    )


def register(app: typer.Typer) -> None:
    app.command("demo")(run)
