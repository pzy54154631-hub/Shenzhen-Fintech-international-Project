# Corridor Wealth Execution Evidence

This document indexes final integrated evidence for International AI Track Topic B. [FINAL-RESULTS](../../results/FINAL-RESULTS.md) records the authoritative outcomes, denominators, mode labels, failures and paths. A command or storyboard is not evidence that an experiment or filmed demonstration occurred.

## 01 Evidence Summary

<!-- FINAL_RESULTS_BEGIN -->

### Final measured results

The values below are copied from [FINAL-RESULTS](../../results/FINAL-RESULTS.md) and its [compact summary](../../evidence/final-summary/summary.json). For completion rows the 95% upper bound concerns failures; for attack rows it concerns forbidden effects. Bounds are descriptive for related cases. Replay is reproducibility evidence, not a second independent sample.

| Mode | Observation | Adverse proportion upper 95% | Evidence |
|---|---|---|---|
| scripted | J bank tasks: 24/24 | failure: approximately min(1, 3/24) = 12.5000% | [source](../../evidence/final-f5/judge/scripted/judge.json) |
| scripted | W mechanism tasks: 12/12; 74/74 formal subcases | failure: approximately min(1, 3/12) = 25.0000% | [source](../../evidence/final-f5/judge/wealth/scripted) |
| scripted | Byzantine forbidden effects: 0/40 | effect: approximately min(1, 3/40) = 7.5000% | [source](../../evidence/final-f5/adversary/result.json) |
| live-recorded | J bank tasks: 24/24; Recorded tasks 24/24; strict replay identical 24/24 | failure: approximately min(1, 3/24) = 12.5000% | [source](../../evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| live-recorded | W advisory tasks: 12/12; 30/30 workflows; Recorded tasks 12/12; strict replay identical 12/12 | failure: approximately min(1, 3/12) = 25.0000% | [source](../../evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| live-recorded | M2 fixed dialogue cases and smokes: 26/26; Recorded cases 26/26; strict replay PASS | failure: approximately min(1, 3/26) = 11.5385% | [source](../../evidence/final-f5/dialogue/dialogue-recording.json) |
| live-recorded | M4 rendered-output guard checks: 10/10; Recorded cases 10/10; strict replay PASS | failure: approximately min(1, 3/10) = 30.0000% | [source](../../evidence/final-f5/dialogue/dialogue-recording.json) |
| live-recorded | Frozen blind forbidden effects: 0/16; Forbidden-predicate rate; independent evidence failures reported separately | effect: approximately min(1, 3/16) = 18.7500% | [source](../../evidence/final-f5/blind/live-recorded/summary.json) |
| strict-replay | Frozen blind forbidden effects: 0/16; Forbidden-predicate rate; independent evidence failures reported separately | effect: approximately min(1, 3/16) = 18.7500% | [source](../../evidence/final-f5/blind/strict-replay/summary.json) |
| live-recorded | M7 forbidden effects: 0/24; Measured attack effects; incomplete effects and evidence diagnostics separate | effect: approximately min(1, 3/24) = 12.5000% | [source](../../evidence/final-f5/redteam/live-recorded/summary.json) |
| strict-replay | M7 forbidden effects: 0/24; Measured attack effects; incomplete effects and evidence diagnostics separate | effect: approximately min(1, 3/24) = 12.5000% | [source](../../evidence/final-f5/redteam/strict-replay/summary.json) |

Final quality gates: rules: 248 passed, 2646 deselected in 17.83s; uncovered rules: none; ruff: PASS; format: PASS; mypy: PASS; imports: PASS; test-rules-verified: 2895 passed, 1 warning in 754.45s (0:12:34); uncovered rules: none. See the [source-linked gate logs](../../results/FINAL-RESULTS.md).

Retained earlier attempts: test: FAIL; 1 failed, 2862 passed, 1 warning in 769.22s (0:12:49); test-rules-final: INTERRUPTED; no complete pytest summary or rules coverage result. These earlier failed or interrupted checks remain disclosed in [FINAL-RESULTS](../../results/FINAL-RESULTS.md); the final gates do not erase their logs or failures.

The gpt-5.4-mini W04 contrast completed 0/1 tasks and 4/5 workflows (live-recorded). Recorded tasks 1/1; strict replay identical 1/1. Its failed workflow remains a completion failure; replay equality does not turn it into a pass. See [FINAL-RESULTS](../../results/FINAL-RESULTS.md).

Conservative actual live attempts: 484/1,500 task cap; the shared journal enforces the stricter 1,200 ceiling. [Budget evidence](../../evidence/final/live-budget.json). All recorded failures remain in the accounting.

Formal W mutation/constraint subcases remain scripted; live W rows cover the disclosed task-specific advisory workflows. Main and model-contrast recordings include transport-disabled strict checks, with exact equality and failure details in FINAL-RESULTS. M7 benign completion and each attack family, all D0/D3/CCA cells, model comparisons and missing measurements remain in that same report with evidence paths. Per-call token counts and assumed-price cost estimates remain in the linked recording evidence, including the [M2/M4 recording](../../evidence/final-f5/dialogue/record/summary.json). These estimates are not provider invoices.

<!-- FINAL_RESULTS_END -->

### Evidence modes and denominators

**Scripted** means deterministic mechanism evaluation with synthetic inputs and a deterministic planner. **Live-recorded** means an actual model response passed through the guarded LLM entry point and was saved. **Strict-replay** means the matching saved response was used with network/provider transport disabled; missing cache is fatal. **Not_run** means no measurement exists and contributes neither zero violations nor a success.

J01–J24 bank tasks and W01–W12 wealth tasks remain separate. Full W task acceptance includes all defined subcases and independent assertions; a passing default W04 conversation does not establish the full W04 task or W11 live coverage. The final report preserves adapter coverage explicitly.

The blind corpus retains its isolated-author provenance and original bytes. Earlier development reruns exposed it to adapter corrections, so the final rerun is not an untouched first-pass holdout. M7 pairs malicious inputs with authorized benign twins. A settled but incorrectly narrated benign transfer is a completion failure until fixed and measured again. F4 removes the model-authored expected literal from reference generation: integer 1000 mismatched the authenticated exact value 1000/1. The fact validator remains unchanged.

### Artifact custody

| Artifact | Purpose |
|---|---|
| [results/FINAL-RESULTS.md](../../results/FINAL-RESULTS.md) | English release measurements, coverage, failures and confidence interpretation |
| [evidence/final-f5/](../../evidence/final-f5/) | Local raw final-run logs, live responses, replay and execution bundles; excluded from Git |
| [evidence/final-summary/](../../evidence/final-summary/) | Compact release inventory and selected verified summaries/screenshots suitable for source control |
| [F5 record](../status/F5.md) | Fourth-round repairs, completed F4 work, exact final commands, validation and remaining limits |
| [artifact-manifest.json](artifact-manifest.json) | Hashes of generated documents, deck and their sources |
| [rule-matrix.md](rule-matrix.md) | Current registered rules, execution sites, tests and TCB inventory |

The evidence CLI packages local artifacts with a file manifest. It does not create a genuine live run from a scripted result or certify the independence of an author. Hashes bind bytes against the retained inventory; they are not external notarization.

The final local archive is `dist/corridor-evidence-f5.zip`. Its exact byte size, SHA-256, inventory checksum, file count and zero-finding credential-pattern scan are recorded in [evidence-package.json](evidence-package.json). The archive includes historical attempts as well as the final measured runs, with their original paths and modes preserved. The raw archive and complete inventory stay outside Git; the compact index is committed with the submission sources.

Selected UI screenshots from F3 remain labelled historical **scripted** UI evidence, with their original run/source metadata. They do not depict a new final live-model UI run.

## 02 Logs or Transactions

### What a wealth trace contains

A trace connects the device-signed request, current policy/catalogue/risk hashes, complete BIAC, immutable parent plan and child intents to exact action/certificate/card hashes. Each red purchase has its own scoped MFA grant and approval token. Signed bank receipts and final holdings/balance establish the actual effect. The parent summary distinguishes completed, partial, cancelled/failed and unknown.

Canonical financial fields originate in trusted state or signed receipts. Every displayed benchmark is labelled performance benchmark (not guaranteed). Analysis and fact references preserve their origin; raw assistant prose does not become verified execution evidence.

Audit records append canonical JSON bytes and a newline. Retained heads/checkpoints support chain verification, including rejected decisions. Unknown outcomes retain reservations and require receipt lookup; no second order is sent to manufacture certainty. Partial prior effects remain in the denominator/accounting.

### Security evidence

The generated rule matrix contains the six allocation checks, approval budget, retake limit and upgrade-review rules. Full execution coverage is reported separately from static marker presence. F1/F2 reproducers, third-round F3 fixes, English J01 matching and the M7 generated-fact correction remain regression evidence. Fourth-round review confirmed ten findings (one high severity), now repaired; all four rejected findings retain specification-aligned regressions. The matrix reports accepted forged proposals and separates baseline MFA protocol gaps from business harm.

Zero prohibited effects are written as `0/n (95% upper approximately 3/n)`, capped at one. The rule-of-three interpretation is descriptive for related attack cases. A nonzero result remains visible, with affected case IDs and exact paths. Benign failures, constructor failures, legal preceding effects and projection differences are not hidden inside a safety score.

### Exclusions and unavailable artifacts

Final-run raw replay, large archives and full generated run trees are not committed. Previously tracked regression fixtures remain separate. The final recordings' absence in a clean clone is intentional and does not imply that strict replay can work without the matching cache. The README gives regeneration instructions. No recorded final video, timed rehearsal, publicly accessible release URL or competition submission receipt was produced: each remains `not_run` or unavailable as appropriate.

## 03 Reproduction Guide

Use Python 3.11 and uv. Install frozen dependencies once with network access or provide a populated package cache. Offline application execution is distinct from first-time dependency installation.

```powershell
uv sync --frozen --python 3.11
uv run --frozen corridor setup
uv run --frozen corridor test
uv run --frozen corridor test --rules-coverage
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen lint-imports
uv run --frozen corridor judge --planner scripted --suite all
uv run --frozen corridor judge --planner scripted --suite wealth
uv run --frozen corridor adversary
uv run --frozen corridor bench --suite wealth
uv run --frozen corridor evidence
```

The final evaluation driver and exact commands are recorded in [FINAL-RESULTS](../../results/FINAL-RESULTS.md). To regenerate raw live data, configure credentials privately and run its recording stages under the shared budget journal. Never print or commit the local environment configuration. Keep failed attempts and their budget reservations. Freeze model, API, reasoning effort, output limit, inputs and source for comparison.

The dedicated offline rerun uses the exact saved model/API profile and a fresh output directory:

```powershell
uv run --frozen python scripts/replay_final.py --source evidence/final-f5 --output evidence/final-offline-check --cases data/blind
```

Its `replay-summary.json` reports observation equality separately from task success and actual API calls. Missing source records or a reused output directory are errors. No API key is required.

Strict evaluation disables transport and loads no credential file. Replaying a different profile or absent cache must fail rather than fall back. Compare normalized case observations and actual receipt effects; the existence of replay files alone is insufficient.

Use `corridor verify-log --help` for the exact path/head/checkpoint options for a selected exported audit. Compare all bundle files with the retained manifest and scan the actual archive before release. An operator must preserve the exported archive and submission receipt when external upload is eventually performed.

The wealth workflow export retains approval token identifiers/hashes rather than the nonce-bearing complete token. Runtime gateway checks verify actual device signatures, but the compact export alone cannot independently reconstruct the approval-token signature check. M4 measures guard regressions and observed rendered-output checks using the same guard, not an independent unsafe-output oracle.
