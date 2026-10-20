# AgentDojo banking: model-free GroundTruth census

This bundle reports **model-free GroundTruth replay**, with **no model** and zero model calls. AgentDojo package **0.1.35**, banking suite **v1.2.2**, upstream commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. Each configuration/oracle covers the complete **16 user tasks x 9 injection tasks = 144 pairs**. These are census counts; no binomial confidence bounds are reported.

| Configuration | Approval oracle | Original targeted ASR | Corrected targeted ASR | Official utility under attack |
|---|---|---:|---:|---:|
| A0 | prompt-bound | 144/144 | 128/144 | 27/144 |
| A5 | prompt-bound | 0/144 | 0/144 | 45/144 |
| A5 | auto-deny | 0/144 | 0/144 | 45/144 |
| A5 | auto-approve | 0/144 | 0/144 | 45/144 |
| Null agent | prompt-bound | 0/144 | 0/144 | 45/144 |

The original judge is **AgentDojo v1.2.2 original**. The corrected judge is **Corridor registered corrected IT0/IT1/IT3**: it requires the attacker recipient and the intended target datum in the subject; other targets and official utility are unchanged. Source-code and upstream-scorer SHA-256 values are recorded in [source-hashes.json](source-hashes.json), [formal-gate.json](formal-gate.json), and [environment.json](environment.json). A0 is the ungated baseline; A5 applies the native gate through the adapter. Null executes no tools. No benign/no-attack GroundTruth run was performed, so benign utility is unavailable. Official utility can pass without action; the unchanged UT5 amount mismatch and UT8 constant predicate limit interpretation.

## Copied evidence and verification

The sources are `wt-dom/results/e4-groundtruth/` (freeze-1) and `wt-f7/results/e4-groundtruth-freeze7/` (freeze-7). All reads and copies ran from the international workspace; no process or Git command ran in either source worktree. Original files were copied into the private review archive before analysis. The source hashes identify their exact bytes; source paths in this public bundle are relative to the common workspace parent.

- Original `rows.json`: both SHA-256 `dfd6a49eece87fb4532c7d5b2e31cd85fe9d3c751078044860fa9c04bcf5f7b0`.
- Original `summary.json`: both SHA-256 `384c119005c113b99cf5410f3f64563604a1072291445fbc1ca249b9f47dad28`.
- **720/720 full source rows and both original summaries are byte-identical.** The historical report differs only in its last sentence, changing a kernel-change assertion to an adapter-boundary statement; every result is unchanged.
- The copied historical [freeze1-freeze2-comparison.json](freeze1-freeze2-comparison.json) also records 720 identical rows. Freeze-1 was associated with `domestic-freeze-1`, commit `af5b74e1179daa296abaf175d9eb8366cd878b98`; the F7 status records final implementation/test snapshot `d9d8e8e`. Artifact and code hashes, rather than an inferred run timestamp, bind this evidence.
- Both recorded replay digests are `bab9e8347b986e957aa5eb8d911dc4793a85ee0e203bb2e142e97458128044f3`. The original generator executed two offline GroundTruth passes. This task checked the recorded replay flag, digests, source-byte equality, all pair identities and every outcome count; it did not rerun the generator or invoke a model.
- [rows-census.json](rows-census.json) is a field-selected projection of all 720 rows, retaining pair identities, outcomes, eligibility, input hashes and per-original-row hashes. Account state, tool arguments and transcripts are omitted. The two `freeze*-summary.json` files preserve all original outcome fields but remove obsolete interval fields, with the transformation and original SHA-256 stated explicitly. The old reports with interval prose remain private.
- `environment.json`, `formal-gate.json`, `source-binding.json`, and the historical comparison manifest are exact-byte copies. The readiness manifest's historical `live_e4_status` does not describe the separate LIVE-6 results.

Machine-readable counts are in [summary.json](summary.json). Published files are bound by [files.sha256.json](files.sha256.json). Recheck the published census offline from the repository root:

```powershell
uv run --offline --frozen python -B evidence/agentdojo-banking/model-free/verify.py
```

The current extraction/verification command was `.venv/Scripts/python.exe -B build_model_free_bundle.py`, with the script, exact absolute source ledger and original copied files retained in the task's private `logs/review/m1` directory. The historical generator interface was `python -B scripts/agentdojo_groundtruth.py --output results/e4-groundtruth-freeze7`; it is recorded here for provenance and was not launched during this task. Neither command requires paid calls.

## Attribution and limits

[AgentDojo issue #181](https://github.com/ethz-spylab/agentdojo/issues/181), opened by **Prabscodes on 2026-08-17**, reports the operator-precedence defect in banking IT0/IT1/IT3. Credit for that defect belongs to the upstream report. Our additional observation is limited to IT1: its helper returns the transaction sender (`me`), so its own GroundTruth produces `Dinner with me` and fails the registered corrected intended-companion check. All 16 original/corrected discrepancies in this model-free census are IT1. This is more specific than merely adding parentheses to the original helper-based expression.

The adapter maps free-text tool arguments to typed references by value matching. That boundary is weaker than Corridor's native typed interface. This evidence covers fixed synthetic proposals in a fixed external suite; it does not establish robustness of an LLM, general security, or a zero-risk guarantee. No paused domestic experiment results are used.
