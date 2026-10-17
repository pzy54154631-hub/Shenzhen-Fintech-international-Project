"""Regenerate deterministic synthetic bank fixtures; no network or real accounts."""

from pathlib import Path

from corridor.sim.fixtures import write_fixtures

if __name__ == "__main__":
    write_fixtures(Path("data/bank"))
