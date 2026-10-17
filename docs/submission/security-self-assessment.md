# Corridor Wealth Security Self Assessment

This assessment describes the integrated synthetic Topic B application. It is not production-security certification or permission to offer investment advice. The model is untrusted; the kernel, gateway, device/key issuers, signed data and host remain assumptions. Current measurements come only from [FINAL-RESULTS](../../results/FINAL-RESULTS.md).

## 01 Permission Model

The model proposes references. The device signs explicit goals and authority. The pure kernel validates provenance and financial obligations. The gateway renders current facts, verifies approval/MFA and rechecks dispatch. The independent synthetic bank returns signed effects; its evaluation oracle does not import the production kernel or stores.

| Tier | Prototype behavior | Authority |
|---|---|---|
| Green | Permitted reads, comparison, analysis and risk scoring | Signed scope; scoring changes suitability and is blocked by safety lock |
| Yellow | Listed lower-risk operations and within-limit existing-recipient transfers | Device approval bound to the current canonical card |
| Red | Purchases and listed sensitive changes | Device approval plus distinct scoped simulated MFA |
| Prohibited or unsupported | Invalid provenance, blacklisted action or absent capability | Reject; approval cannot override hard rules |

The [generated inventory](rule-matrix.md) includes every registered rule and exact TCB sizes, imports, enforcement references and test markers. The TCB comprises schemas, crypto, kernel, stores and gateway. Import-linter and AST contracts constrain layering; packages within one process do not create OS isolation.

### Single use authority and execution

Immediate idempotency binds principal, signed intent and operation kind, excluding planner-chosen node/plan IDs. `AUTH-CONSUMED` rejects reused authority with reserved, unknown or settled effects. A failed attempt can release a reservation, but its approval nonce remains consumed. Scheduled authority retains fixed scope and run identity.

Allocation execution binds an immutable parent BIAC to child intents, inputs, authorizations and receipts. Selecting a partial subset cannot start the full allocation. Each purchase needs a fresh card, its own MFA and approval. Full-vector checks include settled and remaining items; only this parent's verified settled debit is added back to reconstruct its original budget.

The gateway checks token signature, scope, expiry and nonce, then reruns `kernel.check(phase="dispatch")`. Material card drift still rejects. Stop/handoff/failure blocks successors; holdings remain. Unknown effects require signed lookup, not resend. There is no automatic rollback, redemption or resume.

### Approval and suitability controls

| Control | Enforcement and benign counterpart | Regression source |
|---|---|---|
| `APR-BUDGET` | Gateway Reject before first leg when approvals cannot cover remaining plan; unchanged propose/MFA shares one count; distinct requests retain lock | `test_approval_budget.py`, `test_ui_wealth_f3.py` |
| `RISK-RETAKE-LIMIT` | Kernel Reject beyond daily/calendar limits, counting bootstrap and unresolved events; policy only tightens | `test_risk_answer_lifecycle.py`, `test_suitability_integrity.py` |
| `RISK-UPGRADE-REVIEW` | Kernel Escalate for post-refusal same-session upgrade; no automatic approval | Suitability integrity/signals tests |
| `RISK-ANSWERS-CONSUMED/STALE` | Reject reused, stale or improperly ordered submissions; fresh device answers supported | Risk answer lifecycle tests |
| Effective suitability | Preserve raw grade, apply no-loss, short-horizon and session caps; old cards cannot bypass downgrade | Suitability signals and F3 dialogue tests |
| Six `ALLOC-*` rules | Recompute policy, candidates, cents, bands, concentration, fees and liquidity; explicit modes retain all checks | Allocation goldens/properties and W oracle |

The retake ceilings are two per UTC+8 simulated business day and eight per rolling twelve calendar months. These controls do not make the synthetic questionnaire professionally adequate. A higher raw grade cannot erase a tighter effective cap. Unsigned alternatives carry no authority and require device reconfirmation.

### Fact gate and output guard

`RCPT-MISMATCH` and `BANK-RECEIPT` validate original signatures, owner, time, ledger relation and exact supported fields. Output diagnostics such as unsupported promise, unverified number, private content and unsupported prose rewrite text into approved English templates. These are display diagnostics, not new kernel rules. Verified projections preserve original FactRef paths. Exploratory analysis cannot supply executable provenance.

The sandbox uses an AST allowlist with bounded input/output, arithmetic and worker lifetime. Arbitrary imports, files and networking are unavailable. It is not an OS security sandbox. Stolen signing roots or hostile local code with memory access remain outside the demonstrated boundary.

## 02 Security Tests

### Registry and runtime coverage

`python scripts/gen_rule_matrix.py` generates the rule, execution-point and test inventory. Its `--check` detects stale output. The pytest plugin requires a successful executed assertion of each marked rule; static markers do not replace `uv run corridor test --rules-coverage`. Current gates and logs appear in [FINAL-RESULTS](../../results/FINAL-RESULTS.md).

### Four engineering review rounds

Reviewers shared implementation/specification context. These reviews are neither isolated blind tests nor an external security audit. Confirmed and rejected findings remain in the original review JSON; findings may overlap in root cause. No inferred count substitutes for the original adjudications.

| Finding or integration issue | Repair and evidence |
|---|---|
| F1 `KPROV-1` and related authority reuse | Intent identity excludes planner node/plan IDs; one-use authority. [F1](../status/F1.md), first-round reproducers |
| F2 `BIC-1` questionnaire reuse | Signed-answer identity consumption and freshness accompany scoring atomically. [F2](../status/F2.md), second-round reproducers |
| F2 recovery and disclosure | Terminal Stop, refund matching, redemption proceeds, lock-time scoring and sandbox errors retain original regressions |
| F3 `RT3-AX-1` | Only relevant principal/parent plans enter dependency hash; MFA consumed after validation. Unrelated plans no longer invalidate cards; drift still rejects |
| F3 `RT3-BIAC-02` | Canonical allowed types and actual context comparison admit legitimate reordered adjustment; duplicate inputs still reject |
| F3 `RT3-LLMDLG-01` | Secret check precedes tokenization/model calls in both wealth entry points; audit only commitment |
| F3 `RT3-LLMDLG-02` | Normalize Unicode decimal digits before tokenization/privacy checks |
| F3 replay reliability | Deterministic session/turn identity distinguishes repeated utterances; same request remains idempotent |
| F4 English matcher | Preserve rule, count, amount, privacy and receipt conditions while matching canonical English; hostile attack text unchanged |
| F4 benign receipt reference | The model supplied integer 1000 as an expected value while the signed receipt used exact 1000/1. Closed reference-only generation now passes receipt/field handles; the strict fact gate still rejects a mismatched expected literal. J01 uses the same reference-only discipline |

See [F3](../status/F3.md), [F5](../status/F5.md) and `tests/redteam_claude3/`. F5 completes the retained F4 checkpoint. A rejected third-round fixture omitted a device supersedes field; the fixture was corrected while retaining its security assertion. No skipped check is described as a fix.

The fourth round used separate F3/TCB, end-to-end integration and evaluation-integrity review lenses, executable reproducers and specification-based adjudication. It confirmed **10 findings, including one high-severity finding**, and rejected four. All ten confirmed findings are repaired in the final implementation; the original cases and stronger regression variants remain in `tests/redteam_claude4/`. This is engineering review with implementation context, not a new isolated blind experiment. The [adjudication](../review/claude-review-4.json) retains the verifier's reasoning.

| Fourth-round findings | Repair and regression evidence |
|---|---|
| RT4-E2E-1 (high) | Read-only recommendation/explanation during execution or reconciliation reports the actual plan; it cannot re-evaluate against a balance already reduced by its own purchases |
| RT4-E2E-2/3/4 | Stop precedes optional model work; partial holdings, cash and remaining legs stay visible, including guided-mode withdrawal and strict replay failure |
| RT4-F3TCB-01 | Shared privacy and secret projection covers Unicode digit values, ordinary/financial Chinese digits and enclosed-zero variants; golden rejects have safe twins |
| RT4-F3TCB-03/04/05 | Every completed turn is recorded once; recomparison has a fresh deterministic revision; questionnaire/answer terms combined with target-rating terms trigger refusal and audit |
| RT4-EVALINT-01 | An accepted forged BIAC proposal counts as a prohibited outcome even before purchase dispatch; adversarial and all-subcase denominators are both reported |
| RT4-EVALINT-05 | D0/D3 missing-MFA rows are judged against the visible economic goal; missing MFA is a separate protocol gap, not business harm |

The four rejected reproducers remain as specification checks: invalid stored policies fail closed, unauthenticated approval evidence remains incomplete while signed effects are retained, absent device answers cannot be invented by the blind adapter, and output privacy is tested through the actual observed model-output path. They are not counted among the ten repairs.

EVALINT changes the baseline interpretation. The previous matrix reported D0 8/31 in both arms and policies, D3 main 0/31, and D3 scaled 8/31 (all approve) or 4/31 (careful). The final matrix separates protocol gaps and lists corrected counts and exact per-cell changes in [FINAL-RESULTS](../../results/FINAL-RESULTS.md). This reduction in baseline business violations is an accounting correction, not a newly safer baseline. No CCA-only authentication mechanism is imposed as an economic-goal requirement on D0/D3.

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

### Interpretation

Evidence is labelled scripted, live-recorded, strict-replay or not_run. J and W totals stay separate. Partial W dialogue coverage does not establish full live W completion. Every zero count has a nonempty denominator and descriptive upper bound; correlated cases are not an independent statistical sample.

Benign refusals and constructor failures remain completion failures even when funds are safe. Legal purchases before Stop are separate from prohibited new effects. The blind rerun retains frozen isolated-author cases but follows development exposure. Small model contrasts do not establish a general capability/safety law.

## 03 Data and Privacy

All identity and financial data are synthetic. The gateway separates raw-to-token mappings from model state, gives role-filtered handles and scans boundaries. It rejects secrets before model calls and normalizes Unicode digit values, Chinese digit glyphs and formatting variants through one projection. Finite checks do not guarantee recognition of all private encodings or meanings.

Every model call passes through `agent/llm.py`. Credentials remain in ignored local configuration and never belong in replay or submissions. Budget guards reserve worst-case configured cost before each request and count failures conservatively. Configured-price accounting is not an invoice.

Audit appends canonical JSON bytes plus newline and verifies sequence, previous hash and retained checkpoint. Rejections retain rule IDs and commitments rather than PII. Write failure blocks protected execution. Replacing all local logs and trusted heads defeats the local custody assumption.

Demo keys derive from a deterministic labelled seed. Authentication is simulated. Tokenization is not encryption or anonymization. There is no production retention service, secure erasure, legal consent workflow or real identity verification. The final package includes an inventory and actual credential-pattern scan. Final-run raw replay and large generated evidence stay outside source control.

## 04 Known Risks

| Risk | Practical consequence |
|---|---|
| Greedy incompleteness | Feasible goals can fail construction; refusal remains a completion cost |
| Trusted catalogue/policy/grades | Signed information can be poor or incomplete; sponsor independence remains bounded |
| Synthetic suitability | Five answers and caps do not assess a real household or certify suitability |
| Nonatomic purchases | Earlier holdings remain after failure; no whole-plan funds/capacity reservation |
| Bounded language/adapters | Partial live coverage cannot establish unrestricted advisor competence |
| Host, demo keys and sandbox | Logical checks do not resist hostile memory access or stolen signing roots |
| Local audit custody | Hashes detect changes against retained manifests, not replacement of every copy |
| Finite privacy/output guards | Unknown encodings and semantics may escape recognition |
| Regulatory scope | Engineering correspondence is not licensing or comprehensive compliance |
| Release operations | Registration, public URL, filmed video, timed rehearsal and upload remain external work |

The [regulatory mapping](regulatory-mapping.md) preserves official sources, jurisdiction/product scope and gaps. No article is satisfied merely because a rule exists. Returns are a **performance benchmark (not guaranteed)**; allocation is a **policy-checked heuristic**.

The wealth workflow export retains approval token identifiers/hashes rather than the nonce-bearing complete token. Runtime gateway checks verify actual device signatures, but the compact export alone cannot independently reconstruct the approval-token signature check. M4 measures guard regressions and observed rendered-output checks using the same guard, not an independent unsafe-output oracle.
