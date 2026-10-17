"""Run only J01 and the W04 dialogue with a shared, at-most-30-call live budget."""

import argparse
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from typing import Any

from corridor.agent.llm import BudgetExceeded, LLMClient, LLMConfigurationError
from corridor.bench.transfer_runner import run_j01
from corridor.bench.wealth_smoke import run_w04
from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.money import fraction_string


def _tokens(calls: list[dict[str, Any]], name: str) -> int:
    return sum(row.get(name, 0) for row in calls if type(row.get(name, 0)) is int)


def run_smokes(client: LLMClient, evidence_dir: Path) -> dict[str, Any]:
    """Retain failures and stop on budget exhaustion; never replace an earlier run."""
    if not 1 <= client.max_calls <= 30:
        raise LLMConfigurationError("Combined smoke requires at most 30 calls")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    source_root = Path(__file__).resolve().parents[1] / "src/corridor"
    code_hash = H({
        path.relative_to(source_root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(source_root.rglob("*.py"))
    })
    (evidence_dir / "started.json").write_bytes(
        jcs_bytes({
            "model": client.model,
            "api": client.api,
            "max_calls": client.max_calls,
            "max_usd": fraction_string(client.max_usd),
            "tasks": ["J01", "W04"],
            "mode": "live",
            "code_hash": code_hash,
        })
    )
    runs: dict[str, dict[str, Any]] = {}
    budget_stopped = False
    for task_id, run in (("J01", run_j01), ("W04", run_w04)):
        if budget_stopped:
            runs[task_id] = {"passed": False, "status": "not_run_budget"}
            continue
        call_start, trace_start = client.api_calls, len(client.calls)
        spent_start = client.spent_usd
        passed, error_type = False, None
        try:
            result = run(client, evidence_dir=evidence_dir / task_id)
            passed = result.get("passed") is True
        except BudgetExceeded:
            budget_stopped, error_type = True, "BudgetExceeded"
        except Exception as error:
            # Exception messages may contain remote request details or credentials.
            error_type = type(error).__name__
        calls = client.calls[trace_start:]
        sources = [row["source"] for row in calls]
        passed = passed and bool(sources) and all(source == "live" for source in sources)
        runs[task_id] = {
            "passed": passed,
            "status": "passed" if passed else "failed",
            "error_type": error_type,
            "api_calls": client.api_calls - call_start,
            "sources": sources,
            "input_tokens": _tokens(calls, "input_tokens"),
            "output_tokens": _tokens(calls, "output_tokens"),
            "reasoning_tokens": _tokens(calls, "reasoning_tokens"),
            "estimated_cost_usd": fraction_string(client.spent_usd - spent_start),
        }
    summary = {
        "passed": all(row["passed"] for row in runs.values()),
        "model": client.model,
        "api": client.api,
        "reasoning_effort": client.reasoning_effort,
        "api_calls": client.api_calls,
        "call_cap": client.max_calls,
        "input_tokens": _tokens(client.calls, "input_tokens"),
        "output_tokens": _tokens(client.calls, "output_tokens"),
        "reasoning_tokens": _tokens(client.calls, "reasoning_tokens"),
        "estimated_cost_usd": fraction_string(client.spent_usd),
        "pricing_notice": "Assumed prices; actual billing is not measured.",
        "runs": runs,
    }
    (evidence_dir / "calls.json").write_bytes(jcs_bytes(client.calls))
    (evidence_dir / "summary.json").write_bytes(jcs_bytes(summary))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=Path("evidence/wealth/w6/live"))
    args = parser.parse_args()
    try:
        client = LLMClient(
            mode="live",
            max_calls=30,
            max_usd=Fraction(15),
            max_output_tokens=2048,
        )
        if (
            client.model.removeprefix("openai/") != "gpt-6.1-sol"
            or client.api != "responses"
            or client.reasoning_effort != "low"
        ):
            raise LLMConfigurationError("Smoke requires the adopted main Responses/low profile")
        result = run_smokes(client, args.evidence_dir)
    except Exception as error:
        print(f"Live smoke stopped before completion: {type(error).__name__}")
        return 1
    print(jcs_bytes(result).decode("utf-8"))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
