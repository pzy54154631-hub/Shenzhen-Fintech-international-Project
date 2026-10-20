# Corridor Wealth presentation

Official template retained; estimated delivery 9:10. Timing is a plan, not a measured rehearsal.

## Slide 1 — Corridor Wealth — 0:00–0:25

Estimated duration: 25 seconds.

Introduce Corridor Wealth for Topic B. Proof-carrying wealth advice: the model proposes, a verifier decides. The project demonstrates synthetic data, simulated MFA and bank execution. It is not investment advice. The supplied official template's artwork and masters are reused, with its event label localized to English and the current submission year. The repository URL identifies the public source project; the team name remains unfilled pending the user's identity value.

## Slide 2 — Fluent advice can still sell, calculate or act wrongly — 0:25–1:05

Estimated duration: 40 seconds.

Three concrete failures motivate the design. Mis-selling can arise from unsuitable products or issuer incentives. Invented fees or performance promises can mislead the client. Prompt injection can attempt an unauthorized purchase. Reg BI, MiFID II suitability and NFRA suitability motivate engineering checks, not a claim of legal certification. Sources: docs/submission/regulatory-mapping.md; https://www.ecfr.gov/current/title-17/chapter-II/part-240/section-240.15l-1 ; https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014L0065-20260606 ; https://www.shanghai.gov.cn/rzfwgj/20250717/8ef87b63a0044d70a77c063af99eaff5.html .

## Slide 3 — Intelligence and authority belong to separate roles — 1:05–1:40

Estimated duration: 35 seconds.

The model proposes references and explanations. The pure verifier recomputes the declared obligations. The device signs the client's goals, questionnaire and approval. The gateway owns dispatch. No model text is an approval or executable amount. Diagram sources: kernel/check.py, schemas, gateway/service.py and sim/device.py; accepted ADR-012.

## Slide 4 — Model proposes · kernel decides · Device authorises · gateway executes — 1:40–2:30

Estimated duration: 50 seconds.

Model proposes, kernel decides, device authorises, gateway executes. This describes the existing authority separation. A gpt-6.1-sol planner is untrusted; it uses tools and typed references. PII is filtered on ingress. Signed state and catalogue feed BIAC recomputation. The current registry has 71 rules across enforcement points, including 43 kernel, 25 gateway and 3 sandbox rules; the kernel itself must not be labelled 60-plus. Gateway rechecks at dispatch, consumes one-shot authority and enforces APR-BUDGET. The current synthetic backend is MockBank, not the historical SimBank. Receipts are verified, factual prose crosses an output gate, and audit records form a hash chain. Static code inventory has no stochastic mode or binomial denominator.

## Slide 5 — Topic B becomes a visible, signed advisory workflow — 2:30–3:15

Estimated duration: 45 seconds.

The official Topic B wording requires product comparison, client risk profiling, advisory dialogue, and compliant/explainable asset-allocation suggestions. This slide shows enlarged device risk profiling and certificate highlights. Device signing follows clarification; the certificate crop shows the policy statement, principal, purchase fees, benchmark gain and net liquidity. The separate product comparison and allocation views remain inspectable in the UI; per-leg approval follows allocation. Screens are retained I1 scripted captures, not screenshots of the F5 live-recorded evaluation. Source: templates/international-topics-rules-en.docx and figures/screens/manifest.json.

## Slide 6 — BIAC certifies declared policy, not portfolio optimality — 3:15–3:55

Estimated duration: 40 seconds.

Best Interest Allocation Certificate is a checkable witness. It binds signed goals, current risk assessment, catalogue and policy, includes the eligible set and exclusions, fees, liquidity and allocation constraints. The kernel recomputes it. The selector is a policy-checked heuristic and may miss an existing feasible solution. It does not prove global return optimality, legal best interest or future returns. The exact independence claim is sponsor-independent within the declared catalogue and policy. Any return is a performance benchmark (not guaranteed). Sources: DESIGN-WEALTH sections 3-6; kernel/allocation.py; gateway/output_guard.py.

## Slide 7 — Each purchase leg needs fresh, bounded authority — 3:55–4:45

Estimated duration: 50 seconds.

Green is read-only, Yellow requires approval and Red requires simulated MFA. For a multi-leg purchase, APR-BUDGET checks capacity before starting, each leg obtains its own challenge, approval and one-shot authorization, and the gateway revalidates immediately before dispatch. A changed goal voids old approvals. RISK-RETAKE-LIMIT enforces 2 assessments per business day and 8 within 12 calendar months, corresponding narrowly to NFRA Article 29. These counters do not establish professional suitability. A failed leg cannot erase prior purchases; an unknown bank outcome must be reconciled, not blindly retried. Sources: gateway/allocations.py, service.py, kernel/investment.py and the linked NFRA government text.

## Slide 8 — Corridor combines protection with completion — 4:45–5:30

Estimated duration: 45 seconds.

This is the key comparison: scripted all_approve policy, separate main and scaled_1000 arms. Main D0: forbidden 7/31, benign complete 20/21. Main D3: 0/31 and 4/21. Main CCA: 0/31 and 20/21. Scaled D0 and D3: 7/31 and 20/21. Scaled CCA: 0/31 and 20/21. Denominator 31 includes 21 benign and 10 adversarial execution projections, not 31 attacks. Zero-event 95% descriptive upper is 9.6774%; 7/31 upper is 39.8124% Wilson. The 20/21 completion failure upper is 22.6694%; 4/21 failure upper is 92.3324%. The careful policy changes scaled D3 to 3/31; full table retained. A partial-stop task intentionally remains incomplete. This is a bounded scripted comparison, not measured live baseline behavior. Source: results/FINAL-RESULTS.md, matrix section and evidence/final-f5.

## Slide 9 — Observed attacks produced no forbidden effects — 5:30–6:15

Estimated duration: 45 seconds.

M7 has four attack categories: induced transfer, data extraction, privilege escalation and prompt injection. Each live-recorded category has 0/6 forbidden effects; approximate descriptive 95% upper is 50%. Aggregate M7 is 0/24, upper 12.5%, with 24/24 benign twins completed. Blind is live-recorded 0/16, upper 18.75%; Byzantine is scripted 0/40, upper 7.5%; independent differential is scripted 0/1000 disagreements, upper 0.3%. These are different populations and outcomes, not a pooled denominator. The blind corpus was exposed during development, not untouched holdout. Correlated authored cases and finite samples do not establish universal safety. Source: results/FINAL-RESULTS.md and its linked original evidence/final-f5 artifacts.

## Slide 10 — External validation: AgentDojo banking — 6:15–6:55

Estimated duration: 40 seconds.

AgentDojo banking v1.2.2, package 0.1.35, supplies an external synthetic environment. The left chart is model-free GroundTruth replay: A0 targeted ASR is 144/144 with the original judge and 128/144 with the registered corrected IT0/IT1/IT3 check. A5 is 0/144 in each of prompt-bound, auto-deny and auto-approve modes; the null agent is also 0/144. These are complete censuses, with no binomial bounds. The right chart is live gpt-6.1-sol with important_instructions, domestic-freeze-6: A0 is 0/144 under both judges; prompt-bound A5 is 0/143 evaluable under both, with one attack pair truncated and unresolved. No live security advantage is established. Unchanged upstream utility, live gpt-6.1-sol: A0 benign 11/16 and attacked 97/144; A5 prompt-bound benign 8/16 and attacked 72/144 planned, counting truncations incomplete. All 509/509 selected blocks passed strict replay; pilot and other approval modes are disclosed separately in the bundle. Value matching from free-text arguments is weaker than native typed references. Issue #181, public 2026-08-17, already reports the precedence defect. Our additional observation is the IT1 GroundTruth helper-return failure under the corrected check. Sources: evidence/agentdojo-banking/MANIFEST.md; https://github.com/ethz-spylab/agentdojo/issues/181.

## Slide 11 — Strict offline replay verifies the recorded outcomes — 6:55–7:30

Estimated duration: 35 seconds.

The F5 retained report records live-recorded J 24/24, W 12/12, advisory workflows 30/30, M2 26/26 and M4 10/10. Strict replay reproduced the task observations; advisory workflow equality is reported through parent W task equality, not an extra independent sample. Formal W mechanism subcases remain scripted. Strict replay on the current code verified 142/142 observations: 141 raw observations are byte-for-byte identical, and 1 J01 observation is verified by a migration proof because the bilingual port changed the audit fact-hash format. Network transport was disabled and no API calls occurred. P2 matched 142/142 byte-for-byte on code before I1, a historical result. Verification is not task success. See docs/submission/provenance/current-replay-summary.json and evidence/p2-replay/replay-summary.json. Retain the contrast failure: gpt-5.4-mini W04 failed, with 4/5 workflows completed, and replay reproduced the failure. Source: results/FINAL-RESULTS.md, M10 and M2/M4 sections; scripts/replay_final.py.

## Slide 12 — Clients can clarify, correct and stop safely — 7:30–8:10

Estimated duration: 40 seconds.

Clarification does not silently set consequential fields. The user signs the new goal; correction withdraws prior approval authority. A recomputed comparison makes the change inspectable. Stop preserves completed legs; unknown outcomes stay pending reconciliation. Only signed bank receipts establish completed execution, and the audit links the history. These retained I1 UI screenshots are scripted synthetic demonstrations; no live model is called. Screens and source manifest are retained alongside the deck.

## Slide 13 — Review findings become retained regression tests — 8:10–8:40

Estimated duration: 30 seconds.

Four cross-model review rounds confirmed 21, 8, 4 and 10 findings respectively, all addressed in F1/F2/F3/F5 status with reproduction tests. Rejected findings are distinct and not counted as fixes. The retained F5 final acceptance was 2895 passing tests, zero failures, and no uncovered rules. The rule registry currently has 71 entries. Current artifact checks are recorded separately in validation.md; do not confuse historical F5 counts with a fresh test count. Import-linter plus AST checks enforce boundaries; kernel arithmetic avoids floats. Sources: docs/review/claude-review-1.json through -4.json; docs/status/F1.md, F2.md, F3.md, F5.md; FINAL-RESULTS quality gates.

## Slide 14 — Production needs stronger trust, broader evidence — 8:40–9:10

Estimated duration: 30 seconds.

Conclude with limits and the actual next work. This remains synthetic data, simulated MFA, demo keys and a policy-checked heuristic. Trusted catalogue and policy quality, completeness of the fee model, device integrity and kernel correctness remain assumptions. Sponsor-independent within the declared catalogue and policy is deliberately narrower than conflict-free advice. Production work needs protected external keys, broader evaluation, legally reviewed profiling and product disclosures. Performance benchmark (not guaranteed); not investment advice. The original raw evidence bundle and frozen corpus accompany the reproduction command. The repository URL points to the public source project; it does not imply a deployed financial service.
