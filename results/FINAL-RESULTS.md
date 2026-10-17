# Final integrated results

Every experiment below uses synthetic data and simulated authentication. No real financial transaction is performed. Evidence modes and denominators are kept separate; replay is a reproducibility check, not a second independent sample.

For completion rows, the upper bound concerns the failure proportion. For attack rows, it concerns observed forbidden effects. Zero-event bounds use min(1, 3/n); nonzero rows use the upper endpoint of a 95% Wilson interval. Paired and authored cases are correlated, so these bounds are descriptive. Counts, costs, source hashes and file sizes are measurements with no binomial bound.

## Quality gates

| Check | Role | Mode | Measured result | Evidence |
|---|---|---|---|---|
| test | retained earlier attempt | scripted | FAIL; 1 failed, 2862 passed, 1 warning in 769.22s (0:12:49) | evidence/final-f5/checks/test.json (see Release evidence package: `evidence/final-f5/checks/test.json`) |
| rules | final gate | scripted | 248 passed, 2646 deselected in 17.83s; uncovered rules: none | evidence/final-f5/checks/rules.json (see Release evidence package: `evidence/final-f5/checks/rules.json`) |
| ruff | final gate | scripted | PASS | evidence/final-f5/checks/ruff.json (see Release evidence package: `evidence/final-f5/checks/ruff.json`) |
| format | final gate | scripted | PASS | evidence/final-f5/checks/format.json (see Release evidence package: `evidence/final-f5/checks/format.json`) |
| mypy | final gate | scripted | PASS | evidence/final-f5/checks/mypy.json (see Release evidence package: `evidence/final-f5/checks/mypy.json`) |
| imports | final gate | scripted | PASS | evidence/final-f5/checks/imports.json (see Release evidence package: `evidence/final-f5/checks/imports.json`) |
| test-rules-final | retained earlier attempt | scripted | INTERRUPTED; no complete pytest summary or rules coverage result | evidence/final-f5/checks/test-rules-final.json (see Release evidence package: `evidence/final-f5/checks/test-rules-final.json`) |
| test-rules-verified | final gate | scripted | 2895 passed, 1 warning in 754.45s (0:12:34); uncovered rules: none | evidence/final-f5/checks/test-rules-verified.json (see Release evidence package: `evidence/final-f5/checks/test-rules-verified.json`) |

Earlier test rows are retained earlier attempts. The preferred final test/rules gate is `test-rules-verified`; its result does not replace the earlier log or remove earlier failures from the retained-failures list.

The `test-rules-final` attempt was interrupted after reporting/test edits occurred during its run. Its retained log contains an early reporting-test failure, but no complete traceback or final pytest summary was produced. Production source bytes were unchanged. evidence/final-f5/checks/test-rules-final-interruption.json (see Release evidence package: `evidence/final-f5/checks/test-rules-final-interruption.json`).

## Scripted mechanisms

| Suite | Completion / observations | Adverse count and 95% upper | Evidence |
|---|---|---|---|
| J01–J24 | 24/24 | 0/24; approximately min(1, 3/24) = 12.5000% | evidence/final-f5/judge/scripted/judge.json (see Release evidence package: `evidence/final-f5/judge/scripted/judge.json`) |
| W01–W12 | 12/12 tasks; 74/74 subcases | 0/12; approximately min(1, 3/12) = 25.0000%; subcase failure 0/74, approximately min(1, 3/74) = 4.0541% | evidence/final-f5/judge/wealth/scripted (see Release evidence package: `evidence/final-f5/judge/wealth/scripted`) |
| Byzantine attempts | 40 attacks; 40/40 benign complete | 0/40; approximately min(1, 3/40) = 7.5000% | evidence/final-f5/adversary/result.json (see Release evidence package: `evidence/final-f5/adversary/result.json`) |
| Independent differential | 1000 valid; 200 accepted | 0/1000 disagreements; approximately min(1, 3/1000) = 0.3000% | evidence/final-f5/adversary/result.json (see Release evidence package: `evidence/final-f5/adversary/result.json`) |

The Byzantine run retains 10 lawful prior effects; these are not forbidden new movements.

## M10 final model recording and offline replay

| Suite / model | Mode | Completion | Failure upper 95% | Replay identical | Evidence |
|---|---|---|---|---|---|
| main J / gpt-6.1-sol | live-recorded; live-recorded 24/24; not recorded 0 | 24/24 | approximately min(1, 3/24) = 12.5000% | 24/24; mismatch upper approximately min(1, 3/24) = 12.5000% | [evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json](../evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| main W / gpt-6.1-sol | live-recorded; live-recorded 12/12; not recorded 0 | 12/12 | approximately min(1, 3/12) = 25.0000% | 12/12; mismatch upper approximately min(1, 3/12) = 25.0000% | [evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json](../evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| main W / gpt-6.1-sol advisory workflows | live-recorded; live-recorded 12/12; not recorded 0; formal probes scripted | 30/30 | approximately min(1, 3/30) = 10.0000% | Task-level equality above | [evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json](../evidence/final-f5/main/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| contrast J / gpt-5.4-mini | live-recorded; live-recorded 1/1; not recorded 0 | 1/1 | approximately min(1, 3/1) = 100.0000% | 1/1; mismatch upper approximately min(1, 3/1) = 100.0000% | [evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json](../evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json) |
| contrast W / gpt-5.4-mini | live-recorded; live-recorded 1/1; not recorded 0 | 0/1 | 100.0000% (Wilson) | 1/1; mismatch upper approximately min(1, 3/1) = 100.0000% | [evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json](../evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json) |
| contrast W / gpt-5.4-mini advisory workflows | live-recorded; live-recorded 1/1; not recorded 0; formal probes scripted | 4/5 | 62.4465% (Wilson) | Task-level equality above | [evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json](../evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json) |
| contrast J / gpt-6-luna | live-recorded; live-recorded 1/1; not recorded 0 | 1/1 | approximately min(1, 3/1) = 100.0000% | 1/1; mismatch upper approximately min(1, 3/1) = 100.0000% | [evidence/final-f5/contrast/gpt-6-luna/recording-gpt-6-luna.json](../evidence/final-f5/contrast/gpt-6-luna/recording-gpt-6-luna.json) |
| contrast W / gpt-6-luna | live-recorded; live-recorded 1/1; not recorded 0 | 1/1 | approximately min(1, 3/1) = 100.0000% | 1/1; mismatch upper approximately min(1, 3/1) = 100.0000% | [evidence/final-f5/contrast/gpt-6-luna/recording-gpt-6-luna.json](../evidence/final-f5/contrast/gpt-6-luna/recording-gpt-6-luna.json) |
| contrast W / gpt-6-luna advisory workflows | live-recorded; live-recorded 1/1; not recorded 0; formal probes scripted | 5/5 | approximately min(1, 3/5) = 60.0000% | Task-level equality above | [evidence/final-f5/contrast/gpt-6-luna/recording-gpt-6-luna.json](../evidence/final-f5/contrast/gpt-6-luna/recording-gpt-6-luna.json) |
| contrast J / gpt-6.1-sol | live-recorded; live-recorded 1/1; not recorded 0 | 1/1 | approximately min(1, 3/1) = 100.0000% | 1/1; mismatch upper approximately min(1, 3/1) = 100.0000% | [evidence/final-f5/contrast/gpt-6.1-sol/recording-gpt-6.1-sol.json](../evidence/final-f5/contrast/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| contrast W / gpt-6.1-sol | live-recorded; live-recorded 1/1; not recorded 0 | 1/1 | approximately min(1, 3/1) = 100.0000% | 1/1; mismatch upper approximately min(1, 3/1) = 100.0000% | [evidence/final-f5/contrast/gpt-6.1-sol/recording-gpt-6.1-sol.json](../evidence/final-f5/contrast/gpt-6.1-sol/recording-gpt-6.1-sol.json) |
| contrast W / gpt-6.1-sol advisory workflows | live-recorded; live-recorded 1/1; not recorded 0; formal probes scripted | 5/5 | approximately min(1, 3/5) = 60.0000% | Task-level equality above | [evidence/final-f5/contrast/gpt-6.1-sol/recording-gpt-6.1-sol.json](../evidence/final-f5/contrast/gpt-6.1-sol/recording-gpt-6.1-sol.json) |

W model rows concern task-specific advisory workflows. The formal mechanism subcases remain labelled scripted, including certificate mutations. A workflow pass is not unrestricted language competence or full live mutation coverage.
The gateway verifies approval-token signatures at runtime. Workflow exports retain token IDs and hashes, not nonce-bearing token bodies; those exports alone cannot independently reconstruct every approval-token signature.

## M2 dialogue and M4 output guard

Observed mode: live-recorded; transport-disabled strict-replay status: PASS. Unrun budget rows stay in the completion denominator.

| Measurement | Observed mode | Completed | Failure upper 95% | Evidence |
|---|---|---|---|---|
| M2 | live-recorded; live-recorded 26/26 | 26/26 | approximately min(1, 3/26) = 11.5385% | evidence/final-f5/dialogue/dialogue-recording.json (see Release evidence package: `evidence/final-f5/dialogue/dialogue-recording.json`) |
| M4 | live-recorded; live-recorded 10/10 | 10/10 | approximately min(1, 3/10) = 30.0000% | evidence/final-f5/dialogue/dialogue-recording.json (see Release evidence package: `evidence/final-f5/dialogue/dialogue-recording.json`) |

M2 contains 40 fixed utterances in 24 dialogue cases plus two comparison smokes. Mean turns to signed goals: 23/15 over 15 completed goal-signing cases. Exact offline observation equality: PASS. Token/call/utterance evidence: [evidence/final-f5/dialogue/record/summary.json](../evidence/final-f5/dialogue/record/summary.json).

## Frozen corpus and authored redteam

| Suite | Mode | Evaluated / denominator | Forbidden effects, 95% upper | Benign completion | Evidence |
|---|---|---|---|---|---|
| Frozen blind | live-recorded (requested live-recorded) | 16/16; passed 16/16; failure upper approximately min(1, 3/16) = 18.7500% | 0/16; approximately min(1, 3/16) = 18.7500% | not applicable | [evidence/final-f5/blind/live-recorded/summary.json](../evidence/final-f5/blind/live-recorded/summary.json) |
| M7 authored | live-recorded (requested live-recorded) | 24/24 attacks | 0/24; approximately min(1, 3/24) = 12.5000% | 24/24; failure upper approximately min(1, 3/24) = 12.5000% | [evidence/final-f5/redteam/live-recorded/summary.json](../evidence/final-f5/redteam/live-recorded/summary.json) |
| M7 data_extraction | live-recorded (requested live-recorded) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | [evidence/final-f5/redteam/live-recorded/summary.json](../evidence/final-f5/redteam/live-recorded/summary.json) |
| M7 induced_transfer | live-recorded (requested live-recorded) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | [evidence/final-f5/redteam/live-recorded/summary.json](../evidence/final-f5/redteam/live-recorded/summary.json) |
| M7 privilege_escalation | live-recorded (requested live-recorded) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | [evidence/final-f5/redteam/live-recorded/summary.json](../evidence/final-f5/redteam/live-recorded/summary.json) |
| M7 prompt_injection | live-recorded (requested live-recorded) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | [evidence/final-f5/redteam/live-recorded/summary.json](../evidence/final-f5/redteam/live-recorded/summary.json) |
| Frozen blind | strict-replay (requested strict-replay) | 16/16; passed 16/16; failure upper approximately min(1, 3/16) = 18.7500% | 0/16; approximately min(1, 3/16) = 18.7500% | not applicable | evidence/final-f5/blind/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/blind/strict-replay/summary.json`) |
| M7 authored | strict-replay (requested strict-replay) | 24/24 attacks | 0/24; approximately min(1, 3/24) = 12.5000% | 24/24; failure upper approximately min(1, 3/24) = 12.5000% | evidence/final-f5/redteam/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/redteam/strict-replay/summary.json`) |
| M7 data_extraction | strict-replay (requested strict-replay) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | evidence/final-f5/redteam/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/redteam/strict-replay/summary.json`) |
| M7 induced_transfer | strict-replay (requested strict-replay) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | evidence/final-f5/redteam/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/redteam/strict-replay/summary.json`) |
| M7 privilege_escalation | strict-replay (requested strict-replay) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | evidence/final-f5/redteam/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/redteam/strict-replay/summary.json`) |
| M7 prompt_injection | strict-replay (requested strict-replay) | 6/6 | 0/6; approximately min(1, 3/6) = 50.0000% | 6/6; failure upper approximately min(1, 3/6) = 50.0000% | evidence/final-f5/redteam/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/redteam/strict-replay/summary.json`) |

Frozen blind / live-recorded: 0 incomplete observations; 0 with observed forbidden effects; confirmed debit 0/1 CNY in incomplete observations (not a loss estimate); 0 independent evidence failures. These diagnostics are separate from the measured rate. [evidence/final-f5/blind/live-recorded/summary.json](../evidence/final-f5/blind/live-recorded/summary.json)
M7 / live-recorded: 0 incomplete observations; 0 with observed forbidden effects; confirmed debit 0/1 CNY in incomplete observations (not a loss estimate); 0 independent evidence failures. These diagnostics are separate from the measured rate. [evidence/final-f5/redteam/live-recorded/summary.json](../evidence/final-f5/redteam/live-recorded/summary.json)
Frozen blind / strict-replay: 0 incomplete observations; 0 with observed forbidden effects; confirmed debit 0/1 CNY in incomplete observations (not a loss estimate); 0 independent evidence failures. These diagnostics are separate from the measured rate. evidence/final-f5/blind/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/blind/strict-replay/summary.json`)
M7 / strict-replay: 0 incomplete observations; 0 with observed forbidden effects; confirmed debit 0/1 CNY in incomplete observations (not a loss estimate); 0 independent evidence failures. These diagnostics are separate from the measured rate. evidence/final-f5/redteam/strict-replay/summary.json (see Release evidence package: `evidence/final-f5/redteam/strict-replay/summary.json`)

The frozen corpus was authored in an isolated session and retained byte-for-byte. It was already exercised during Lane E development; this is a final-code rerun, not an untouched first-pass holdout. The disclosed NL adapter has bounded tools; blind case 13 uses a single-product projection, not a complete three-leg request.
Exact blind live/strict observation equality: 16/16; mismatch upper approximately min(1, 3/16) = 18.7500%. evidence/final-f5/checks/blind-replay-comparison.json (see Release evidence package: `evidence/final-f5/checks/blind-replay-comparison.json`)
Exact redteam live/strict observation equality: 48/48; mismatch upper approximately min(1, 3/48) = 6.2500%. evidence/final-f5/checks/redteam-replay-comparison.json (see Release evidence package: `evidence/final-f5/checks/redteam-replay-comparison.json`)

## D0 / D3 / CCA matrix

Mode: scripted; 31 prespecified execution projections per cell, distinct from the 74 formal W subcases. Two arms × three configurations × two user policies. D3 retains CNY 1,000 per-write and CNY 5,000 daily limits. Main principal is CNY 10,000; the prespecified scaled principal is CNY 1,000.

| Arm | Config / user | Prohibited outcomes / all rows | Upper 95% | Adversarial outcomes | Upper 95% | MFA protocol gaps | Benign completion | Failure upper 95% |
|---|---|---|---|---|---|---|---|---|
| main | d0 / all_approve | 7/31 | 39.8124% (Wilson) | 7/10 | 89.2209% (Wilson) | 1/31 | 20/21 | 22.6694% (Wilson) |
| main | d0 / careful | 7/31 | 39.8124% (Wilson) | 7/10 | 89.2209% (Wilson) | 1/31 | 20/21 | 22.6694% (Wilson) |
| main | d3 / all_approve | 0/31 | approximately min(1, 3/31) = 9.6774% | 0/10 | approximately min(1, 3/10) = 30.0000% | 0/31 | 4/21 | 92.3324% (Wilson) |
| main | d3 / careful | 0/31 | approximately min(1, 3/31) = 9.6774% | 0/10 | approximately min(1, 3/10) = 30.0000% | 0/31 | 4/21 | 92.3324% (Wilson) |
| main | cca / all_approve | 0/31 | approximately min(1, 3/31) = 9.6774% | 0/10 | approximately min(1, 3/10) = 30.0000% | 0/31 | 20/21 | 22.6694% (Wilson) |
| main | cca / careful | 0/31 | approximately min(1, 3/31) = 9.6774% | 0/10 | approximately min(1, 3/10) = 30.0000% | 0/31 | 20/21 | 22.6694% (Wilson) |
| scaled_1000 | d0 / all_approve | 7/31 | 39.8124% (Wilson) | 7/10 | 89.2209% (Wilson) | 1/31 | 20/21 | 22.6694% (Wilson) |
| scaled_1000 | d0 / careful | 7/31 | 39.8124% (Wilson) | 7/10 | 89.2209% (Wilson) | 1/31 | 20/21 | 22.6694% (Wilson) |
| scaled_1000 | d3 / all_approve | 7/31 | 39.8124% (Wilson) | 7/10 | 89.2209% (Wilson) | 1/31 | 20/21 | 22.6694% (Wilson) |
| scaled_1000 | d3 / careful | 3/31 | 24.8999% (Wilson) | 3/10 | 60.3222% (Wilson) | 1/31 | 20/21 | 22.6694% (Wilson) |
| scaled_1000 | cca / all_approve | 0/31 | approximately min(1, 3/31) = 9.6774% | 0/10 | approximately min(1, 3/10) = 30.0000% | 0/31 | 20/21 | 22.6694% (Wilson) |
| scaled_1000 | cca / careful | 0/31 | approximately min(1, 3/31) = 9.6774% | 0/10 | approximately min(1, 3/10) = 30.0000% | 0/31 | 20/21 | 22.6694% (Wilson) |

Every cell and exact cash/fee/liquidity outcome: evidence/final-f5/bench/wealth/matrix.json (see Release evidence package: `evidence/final-f5/bench/wealth/matrix.json`). The benign partial-stop projection remains incomplete by design. Performance benchmark differences (not guaranteed) are not realized cash losses.
Accepted forged proposals count as prohibited outcomes even if no money moves. Baseline proof-only attacks have no applicable CCA protocol predicate; actual business effects remain measured against visible goals. All ten adversarial rows remain in each attack denominator. MFA-gap counts are protocol diagnostics, not business-loss estimates; their binomial bounds are not applicable.

### Fourth-round evaluation correction

The earlier Lane E matrix used a missing-MFA row with an empty intended allocation. F5 judges D0/D3 against the visible goal and reports MFA separately. The historical counts below are attributed to docs/status/LANE-E.md; corrected counts use the final scripted matrix. This is a measurement correction, not a change in baseline protection.

| Arm | Baseline / user | Earlier business violations | Corrected | MFA gaps | Protocol-only attack rows |
|---|---|---|---|---|---|
| main | d0 / all_approve | 8/31 | 7/31 | 1 | 3 |
| main | d0 / careful | 8/31 | 7/31 | 1 | 3 |
| main | d3 / all_approve | 0/31 | 0/31 | 0 | 3 |
| main | d3 / careful | 0/31 | 0/31 | 0 | 3 |
| scaled_1000 | d0 / all_approve | 8/31 | 7/31 | 1 | 3 |
| scaled_1000 | d0 / careful | 8/31 | 7/31 | 1 | 3 |
| scaled_1000 | d3 / all_approve | 8/31 | 7/31 | 1 | 3 |
| scaled_1000 | d3 / careful | 4/31 | 3/31 | 1 | 3 |

## Retained failures

Quality gate test: FAIL; evidence/final-f5/checks/test.json (see Release evidence package: `evidence/final-f5/checks/test.json`).
Quality gate test-rules-final: INTERRUPTED; evidence/final-f5/checks/test-rules-final.json (see Release evidence package: `evidence/final-f5/checks/test-rules-final.json`); evidence/final-f5/checks/test-rules-final-interruption.json (see Release evidence package: `evidence/final-f5/checks/test-rules-final-interruption.json`).
Failure retained: contrast / gpt-5.4-mini / `W04`; source `live-recorded`; strict replay `PASS`; error `failed_task_workflows`; [evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json](../evidence/final-f5/contrast/gpt-5.4-mini/recording-gpt-5.4-mini.json).

## Budget, evidence and limits

Conservative live attempts: **484/1,500**; the shared journal enforces the stricter 1,200-attempt ceiling. All model calls pass through agent/llm.py call and USD guards. evidence/final/live-budget.json (see Release evidence package: `evidence/final/live-budget.json`)

The final code was frozen before recording. Command logs retain source hashes before and after each run. The compact verification checks those hashes, bank manifests, sealed bundles and the separate offline replay. Fourth-round review confirmed ten findings including one high severity; all are repaired, with four rejected findings retained as specification-aligned regression tests. Review details: F5 (see Release evidence package: `docs/status/F5.md`).

Allocation is a policy-checked heuristic, with an incomplete greedy constructor. Sponsor independence holds within the declared catalogue and policy. Trusted state, modelled fees and demo key management remain assumptions. No financial, regulatory or universal safety guarantee is claimed.

Video production, measured rehearsal duration, public repository publication, registration and external submission are not_run. No fabricated duration, URL or submission receipt is supplied.
