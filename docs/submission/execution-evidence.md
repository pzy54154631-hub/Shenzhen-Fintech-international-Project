# Corridor Wealth Execution Evidence

## 01 Evidence Summary

### What this evidence demonstrates

This document connects the Topic B advisory workflow to recorded decisions, approvals, synthetic-bank effects and reproduction commands. The central claim is inspectability: a permitted purchase can be traced from signed client goals through the BIAC and current approval card to the bank receipt and audit chain.

The accompanying documents use **synthetic data**, **simulated MFA** and a **policy-checked heuristic**. All displayed return estimates are **performance benchmark (not guaranteed)**. The prototype is **not investment advice** and does not connect a real financial account.

| Evidence mode | Meaning | What it cannot establish |
|---|---|---|
| Scripted | Deterministic mechanism or UI execution with synthetic input | Live-model competence |
| Live-recorded | A model response passed through the guarded entry point and was saved | Generalization beyond the disclosed tasks |
| Strict-replay | Matching saved response used with provider transport disabled | A second independent model sample |
| Not run or unavailable | No applicable measurement or required artifact in the package | Success, zero risk or a completed demonstration |

[FINAL-RESULTS](../../results/FINAL-RESULTS.md) records the original F5 measurements, backed by the complete [recorded evidence bundle](../../evidence/final-f5/). Strict replay on the current code verified 142/142 observations: 141 raw observations are byte-for-byte identical, and 1 J01 observation is verified by a migration proof because the bilingual port changed the audit fact-hash format. Network transport was disabled and no API calls occurred. P2's historical **142/142** byte-for-byte equality used code before I1. Replay equality preserves recorded failures and is not a new independent model sample. The reproduction section links the measured result.

The retained I1 screenshots were captured in scripted mode before W1 and retain synthetic/simulated labels. They are separate from historical F3 screenshots and from the retained live-recorded results. A screenshot or command is not proof that a filmed demonstration or external competition submission occurred.

<!-- pagebreak -->

### Reported completion with explicit denominators

F5 reported live-recorded completion and strict-replay agreement. The chart cites the original results report and retained recording bundle. (not included in public checkout: `docs/submission/figures/completion.png`)

| Suite | Live-recorded completion | Failure upper 95% | Strict-replay status in F5 report |
|---|---|---|---|
| J bank tasks | 24/24 | 12.5000% approximate | Identical for 24/24 tasks |
| W advisory tasks | 12/12 | 25.0000% approximate | Identical for 12/12 tasks |
| W advisory workflows | 30/30 | 10.0000% approximate | Task-level equality above |
| M2 dialogue | 26/26 | 11.5385% approximate | PASS observation equality |
| M4 output guard | 10/10 | 30.0000% approximate | PASS observation equality |

The primary recorded model is gpt-6.1-sol. These bounds concern completion failures and are descriptive for related cases. Replay checks reproducibility, not an independent repeated trial. Formal W constraint probes remain scripted and are not counted as live workflows.

The report preserves failed/interrupted test attempts and weaker-model failures. The gpt-5.4-mini live-recorded W contrast completed **0/1** tasks and **4/5** workflows. Strict-replay equality does not make that failure pass. Full observations remain in [FINAL-RESULTS](../../results/FINAL-RESULTS.md).

<!-- pagebreak -->

## 02 Logs or Transactions

### A trace joins client intent to actual bank effects

Receipts from the retained I1 scripted UI capture. The signed result, parent plan and holdings remain inspectable; this run uses synthetic data and simulated authentication. (not included in public checkout: `docs/submission/figures/screens/10-receipts-doc.png`)

| Trace element | Reviewer question | Expected linkage |
|---|---|---|
| Signed goals and questionnaire | Did the device supply the economic request? | Principal, scope, signature and current input reference |
| Policy, catalogue and BIAC | Were alternatives and constraints recomputed? | Current input hashes, eligible set, exclusions, costs and allocation |
| Parent plan and child operation | Which exact purchase was authorized? | Immutable parent/BIAC binding and derived child intent |
| Current card, MFA and approval | Did the device authorize these facts? | Action, certificate and card hashes; separate per-leg scope |
| Signed bank receipt and audit | What actually happened? | Operation identity, exact effect, final state and retained chain head |

The parent summary distinguishes completed, partial, cancelled/failed and unknown. A legal settled purchase before Stop remains an actual effect. Unknown outcomes retain reservations and require receipt lookup; they do not justify resending an order. Performance benchmarks are not realized cash gains or losses.

<!-- pagebreak -->

### Audit checkpoint retention is part of verification

Retained I1 scripted audit screen. The audit exposes decisions and commitments; it does not display raw private utterances or real personal information. (not included in public checkout: `docs/submission/figures/screens/11-audit-doc.png`)

Audit appends canonical JSON bytes plus newline and checks sequence and previous hash against retained state. Rejections remain part of the trace. Write failure blocks protected execution. A chain can reveal modification relative to a trusted head; it cannot establish integrity if every local log and trusted checkpoint is replaced together.

| Supplied artifact | Purpose and availability |
|---|---|
| FINAL-RESULTS and original evidence | F5 measurements linked to original raw outputs and manifest hashes |
| Retained I1 screenshots and capture manifest | I1 scripted interaction states, captions and hashes |
| Rule matrix and regulatory mapping | Source-level controls, tests, official-source scope and gaps |
| Source code and regression tests | Rerunnable deterministic mechanisms and review reproducers |
| Original final-run raw recordings | Complete evidence/final-f5 bundle retained; P2 verification used code before I1 |

The artifact manifest (not included in public checkout: `docs/submission/artifact-manifest.json`) binds generated deliverables to their source bytes. Hashes are integrity aids against the retained inventory, not external notarization. The original archived evidence described by F5 is not represented as a newly produced archive here.

Selected historical UI evidence remains historical scripted material. The retained I1 captures have their own manifest in screenshots (not included in public checkout: `docs/submission/figures/screens`). Neither set demonstrates a new live-model UI run, a filmed final video, a timed rehearsal, a public release URL or a competition submission receipt.

<!-- pagebreak -->

## 03 Reproduction Guide

### Start with the key free mechanism path

The application uses Python 3.11 and the frozen uv lockfile. Install dependencies with network access once or use a populated cache. This installation requirement is distinct from offline application behavior. The following commands exercise deterministic mechanisms without a model key.

```powershell
uv sync --frozen --python 3.11
uv run --frozen corridor setup
uv run --frozen corridor test --rules-coverage
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen lint-imports
uv run --frozen corridor judge --planner scripted --suite all
uv run --frozen corridor judge --planner scripted --suite wealth
uv run --frozen corridor adversary
uv run --frozen corridor bench --suite wealth
```

The wealth matrix keeps configuration and user policy explicit. Compare prohibited outcomes against their full execution-projection denominator, and benign completion against its separate denominator. Do not combine the scripted matrix with live advisory task counts. A protected refusal is not automatically a successful benign task.

### Strict offline replay of the original recorded bundle

Run the command below against the original F5 evidence and repository frozen corpus. Preserve the source manifest and model/API profile. The output directory must be new; use a different output path when repeating this run.

```powershell
uv run --offline --frozen python scripts/replay_final.py --source evidence/final-f5 --output evidence/reproduced --cases data/blind
```

The current replay summary (not included in public checkout: `docs/submission/provenance/current-replay-summary.json`) records the I1 verification retained for the current code. Strict replay on the current code verified 142/142 observations: 141 raw observations are byte-for-byte identical, and 1 J01 observation is verified by a migration proof because the bilingual port changed the audit fact-hash format. Network transport was disabled and no API calls occurred. The P2 replay summary (not included in public checkout: `evidence/p2-replay/replay-summary.json`) records historical **142/142** byte-for-byte equality on code before I1. It covers main, contrast, dialogue, blind and redteam stages. The driver exited successfully. Equality reproduces the recorded gpt-5.4-mini W04 failure as well as successful observations; it does not turn failed tasks into completed tasks or supply another independent sample.

A cache miss or mismatched profile must fail without network transport or fallback. The original measurements and the P2 replay output remain separate, so reviewers can inspect both the source records and the reproduced observations.

The current driver reports raw equality separately from verified reproduction. ADR-014 permits only the named J01 fact-hash migration, requiring both valid audit chains, authenticated facts reproducing both formats, and unchanged remaining observations. A migrated result remains `identical=false`. Missing proof or additional differences fail; frozen evidence is never rewritten.

<!-- pagebreak -->

### Verify actual effects rather than persuasive output

F5 reported security observations and upper bounds. Modes and denominators remain separate; no zero result is generalized to all attacks. (not included in public checkout: `docs/submission/figures/security-results.png`)

The retained F5 report gives live-recorded M7 forbidden effects of **0/24**, with **0/6** in each named attack family, and frozen blind effects of **0/16**. It separately reports scripted Byzantine effects of **0/40** and differential disagreements of **0/1000**. Descriptive approximate 95% upper bounds are **12.5000%**, **50.0000%** per M7 family, **18.7500%**, **7.5000%** and **0.3000%**, respectively. The security assessment explains exposure and independence limits.

For an individual trace, compare the signed request and canonical card with the exact bank receipt and final holdings. Verify parent/child binding, per-leg authority and current trusted inputs. Check rejection and unknown-state records as well as successful purchases. A narrative claim of completion is not a receipt.

Runtime checks verify approval signatures, but compact wealth exports retain only token identifiers and hashes. Independent reconstruction of the complete token signature check requires the appropriate full authorized export.

Use `corridor verify-log --help` for the path, head and checkpoint options. Compare exported files against their retained manifest, and inspect the actual archive for sensitive material before any external release. Keep failures and prior legal effects visible; do not zero-fill missing evidence or relabel protocol gaps as monetary loss.

Current validation and document page counts are recorded in artifact validation (not included in public checkout: `docs/submission/validation.md`). Full source-level rules remain in [rule-matrix.md](rule-matrix.md). Repository: [Corridor Wealth source](https://github.com/pzy54154631-hub/Shenzhen-Fintech-international-Project). This synthetic prototype is **not investment advice**.
