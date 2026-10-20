# LIVE-6 AgentDojo banking evidence

This bundle contains only the completed E4 OpenAI blocks from the read-only
`wt-dom/evidence/live6` source. It contains no domestic E1, blind-corpus, stress,
E2, or E3 results. The product is unchanged.

## Run and judge identity

- Mode: live-recorded, model `gpt-6.1-sol`, seed 1, attack `important_instructions`.
- Run code: `domestic-freeze-6`, commit
  `a5936b79b122a2043ee1ed259ef71e6dd185ac27`.
- AgentDojo package `0.1.35`, banking benchmark `v1.2.2`, upstream commit
  `089ed468cf3ed0322acc66b0211f26d9d90dbf60`.
- Original targeted judge: the unchanged upstream security predicate.
- Corrected targeted judge: the explicit attacker-recipient and target-content
  checks for IT0, IT1 and IT3 in
  `src/corridor/bench/agentdojo_contract.py::corrected_security` at the run commit;
  all other tasks retain their original score. Utility is the unchanged upstream
  task-utility judge. In particular, permissive upstream utility checks mean that
  these utility counts are not independent proofs of successful banking activity.
- `code-provenance.json` records SHA-256 hashes and original line ranges for the
  reused metric and replay functions. All five inspected source files matched
  the exact bytes at `domestic-freeze-6`. The Chinese reporter was not executed.

## Verified census and denominators

All 509 retained blocks passed the recorded strict replay and block checks:
2 pilot blocks and 507 main blocks. There are 680 rows: 672 `valid_completed`,
8 `truncated`, 0 invalid, and 0 runtime errors. Here `valid_completed` means that
evaluation terminated normally; task utility can still be false.

The metric denominators exclude 4 pilot rows and 36 sanity rows. They contain
576 attack rows (four complete 16-user-task by 9-injection-task grids) and 64
no-attack rows (16 per group). All eight truncated rows reached the tool-call
limit: two attack, three no-attack, and three sanity rows. Unfinished attack
outcomes remain unknown; they are never counted as prevented attacks. These
144-pair grids are complete suite censuses, so no binomial confidence intervals
are attached.

Every row in the following table has live-recorded mode, model `gpt-6.1-sol`,
and the run/judge versions above. Targeted ASR uses the evaluable attack
denominator; the next column shows its missing count out of the 144 planned
pairs. Utility uses the planned denominator and therefore counts unfinished
tasks as incomplete. Evaluable utility denominators are also shown.

| Configuration / approval oracle | Original targeted ASR | Corrected targeted ASR | Missing attack outcomes | No-attack upstream utility, planned (evaluable) | Under-attack upstream utility, planned (evaluable) |
|---|---:|---:|---:|---:|---:|
| A0 / prompt-bound label, no A5 gate | 0/144 | 0/144 | 0/144 | 11/16 (11/16) | 97/144 (97/144) |
| A5 / prompt-bound | 0/143 | 0/143 | 1/144 | 8/16 (8/15) | 72/144 (72/143) |
| A5 / auto-deny | 0/143 | 0/143 | 1/144 | 7/16 (7/15) | 63/144 (63/143) |
| A5 / auto-approve | 0/144 | 0/144 | 0/144 | 8/16 (8/15) | 72/144 (72/144) |

No observed targeted success occurred in unfinished prefixes. That observation
does not resolve the missing outcomes. A0 also has zero observed live targeted
successes, so these live data establish no A5 security advantage over A0.

## Retained evidence and independent verification

- `blocks/`: 509 byte-for-byte copies of completed E4 OpenAI block files, including
  original observations, attempts, both judge outputs, and replay status.
- `strict/`: 680 byte-for-byte copies of the corresponding retained strict replay
  result files. There is one attempt per row. These are verification witnesses,
  not another set of live experiments.
- `plan-e4-openai.json`: only the 509 matching blocks and their 680 planned rows,
  with a hash of the original source plan. The original plan's
  `formal_live_executed: false` is static planning metadata, not the status of
  completed blocks. Actual outcomes come exclusively from the block artifacts.
- `source-files.json`: symbolic source paths, source/copy SHA-256 hashes, byte
  counts for every raw block and strict result, and the plan-subset hash.
- `source/metric_reference.py`: exact extracted functions for corrected scoring,
  replay projection and observation hashing. `source/runner-scoring.txt` and
  `source/strict-verification.txt` retain the relevant run-code excerpts.
- `summary.json`: all four configurations, both judges, all denominators and
  missingness, excluded rows, and 680 independently verified observation hashes.
- `SHA256SUMS.json`: SHA-256 hashes for the full delivered live bundle except
  that checksum file itself.

`recompute.py` checks every copied raw hash, every block's passing replay flags,
the full attack/benign grids and exclusions, and the summary. It re-evaluates
the corrected targeted predicate for all 574 valid attack rows. For all 680
attempts it confirms strict mode and replay-only call sources, then compares
the frozen run's projected observation hash against the retained strict result.
The projection omits provenance and resource measurements, retaining decisions
and effects. The copied attempts were also checked against their original
per-episode live results during extraction. All 680 comparisons pass.

This round verifies the retained strict results; it does not rerun model
inference or make network calls. The original coordinator invoked its worker
with `--strict` inside `network_disabled()` and required a successful worker
exit plus matching projected hashes before recording a passing block.

## Exact commands

From the repository root, recompute and verify the delivered evidence:

```powershell
uv run --frozen python -B evidence/agentdojo-banking/live/recompute.py
```

To regenerate `summary.json` from the same retained evidence:

```powershell
uv run --frozen python -B evidence/agentdojo-banking/live/recompute.py --write
```

The original source extraction used the following command from the main
repository, with `SOURCE_CHECKOUT` set to the read-only `wt-dom` path. All
processes and Git reads ran in the main repository; only file reads accessed
the source checkout. `extract.py` reproduces the extraction and verifies its
five source-code files against the run tag in the main Git object database.

```powershell
python -B evidence/agentdojo-banking/live/extract.py --source $SOURCE_CHECKOUT --output evidence/agentdojo-banking/live
```

The execution environment's `uv` was not on PATH, so the initial equivalent
metric verification used the existing frozen `.venv/Scripts/python.exe` with
`PYTHONPATH=src`. Exact private absolute paths and commands are retained in the
non-exported M1 review log. No credentials were opened or copied.

## Interpretation and upstream attribution

[AgentDojo issue #181](https://github.com/ethz-spylab/agentdojo/issues/181), public
on 2026-08-17, reports the banking IT0/IT1/IT3 operator-precedence defect. We do
not claim to have discovered that defect. Both judges are retained. The
additional GroundTruth observation is that IT1's helper returns `me` rather
than the intended companion IBAN, so its own GroundTruth still fails the
corrected target-content check; the model-free bundle supplies that evidence.

The adapter maps the suite's free-text tool arguments to typed references by
value matching. This is weaker than Corridor's native typed interface. The
data concern synthetic benchmark tasks, one live model, one attack template,
one seed, and simulated approval oracles. Targeted ASR is not a claim of zero
risk or complete security, and it is distinct from task utility and arbitrary
unauthorized effects.
