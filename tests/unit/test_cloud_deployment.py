"""The hosted entrypoint and pinned runtime dependencies remain deployable."""

import re
import runpy
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_cloud_entrypoint_delegates_to_the_real_app(monkeypatch):
    from corridor.ui import app

    calls = []
    monkeypatch.setattr(app, "main", lambda: calls.append("started"))
    runpy.run_path(str(ROOT / "streamlit_app.py"), run_name="__main__")
    assert calls == ["started"]


def test_cloud_config_uses_the_platform_bind_address_and_safe_secrets_example():
    config = tomllib.loads((ROOT / ".streamlit/config.toml").read_text(encoding="utf-8"))
    assert "address" not in config.get("server", {})
    example = tomllib.loads((ROOT / ".streamlit/secrets.toml.example").read_text(encoding="utf-8"))
    assert example["LLM_API_KEY"] == example["LIVE_ACCESS_CODE"] == ""
    assert example["LLM_MODEL"] == "gpt-6.1-sol"
    assert example["LLM_API"] == "responses"
    assert str(example["LIVE_DAILY_USD"]) == "5"
    assert example["LIVE_SESSION_CALLS"] == 40
    assert ".streamlit/secrets.toml" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_requirements_pin_the_locked_runtime_graph_without_development_tools():
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = {item["name"]: item for item in lock["package"]}
    runtime = set()
    visited = set()
    pending = list(packages["corridor"]["dependencies"])
    while pending:
        dependency = pending.pop()
        name = dependency["name"]
        identity = (name, tuple(dependency.get("extra", [])))
        if identity in visited:
            continue
        visited.add(identity)
        runtime.add(name)
        pending.extend(packages[name].get("dependencies", []))
        for extra in dependency.get("extra", []):
            pending.extend(packages[name]["optional-dependencies"][extra])
    lines = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    requirements = [line for line in lines if line and not line.startswith("#")]
    assert "-e ." in requirements  # Install the src-layout application as well.
    pins = {}
    for line in requirements:
        if line == "-e .":
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([^ ;]+)(?: ; .+)?", line)
        assert match is not None, f"Dependency is not exactly pinned: {line}"
        name, version = match.groups()
        assert version == packages[name]["version"]
        pins[name] = version
    assert set(pins) == runtime
    assert not {"pytest", "hypothesis", "ruff", "mypy", "import-linter"} & pins.keys()
