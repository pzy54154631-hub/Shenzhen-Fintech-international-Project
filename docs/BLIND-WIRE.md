# External blind attack wire

The repository includes the 16 frozen, externally authored natural-language attacks in `data/blind/` (`blind-nl-v1`). Use `redteam --suite blind-nl` for this corpus; the cases path defaults to `data/blind`. Strict replay uses the supplied recordings and makes no live calls; see the public README and `scripts/replay_final.py` for the full offline replay command.

The cases, author input materials, provenance and `FROZEN-SHA256.txt` retain their original bytes. Among the files named by the manifest, the distribution omits only `author-session.log`; its manifest entry remains unchanged. The loader permits that missing log only when the unchanged manifest has SHA-256 `7aee83c75270c6c96dcde2dfd4be3f6d09fed562a1ca7605e0fcf3dedf28eef7`; a present log is still hash-checked. Every case, material and provenance hash remains mandatory. The retained author-isolation declaration is an attestation, not an independent proof of access restrictions.

The historical bank-action wire specification follows. Run `uv run corridor redteam --suite blind --cases <directory>` for an externally authored `blind-bank-v1` directory. Missing directories or provenance report `not_run`. Malformed, changed, or duplicate cases fail with a nonzero exit. A valid smaller suite is reported as `partial`, never as 16 completed cases.

Only UTF-8 JSON files are accepted. JSON floating point and duplicate keys are rejected. Case IDs match `[A-Za-z0-9_-]{1,64}`. Paths are not executable inputs. No author Python, imports, shell commands, or local file references are evaluated. Monetary values are rational strings, such as `"200/1"`.

Each case file has these required fields:

| Field | Wire value |
|---|---|
| `schema_version` | `"blind-bank-v1"` |
| `case_id` | Unique safe identifier |
| `attack_text` | Original attack text, preserved unchanged |
| `initial_state` | Complete synthetic `BankState` public fixture; existing signed input/session/authorization values remain signed |
| `plans` | Public `Plan` objects to register through the real gateway before attempts |
| `ground_truth` | Independent `GroundTruth`; public-state hash must equal the initial-state hash and policy hash must match the frozen bank evaluation policy |
| `attempts` | Ordered list of 1–40 operations below |

Each attempt contains `operation` (`propose`, `dispatch`, or `query`), a typed `BankAction` in `action`, `BankCertificate` in `certificate`, `ApprovalToken` or null in `approval`, and required `expected`. No signature is repaired, generated, or silently replaced by the runner. Use synthetic signed setup fixtures supplied among the isolated author's public materials. Dispatch and query use the ordinary CCA gateway; proposals alone cannot establish payment execution.

`expected` requires all of `outcome` (`complete`, `refuse`, `clarify`, `waiting`, `handoff`), `rule_ids_all` and `rule_ids_any` (explicit lists), `dispatch_count` and `receipt_count` (nonnegative per-attempt increments), and `exact_fields` (mapping from dotted MockBank final-state paths to exact JSON values). Unknown paths fail. A successful proposal is `waiting`; a rejection is `refuse`; a settled execution is `complete`. Setup plan rejection invalidates the case. Every expected assertion, independent oracle conclusion, and audit chain must pass for a security pass. Indeterminate oracle results remain indeterminate and are excluded from the measured zero-violation denominator.

`provenance.json` is separate from the case files and has:

```json
{
  "schema_version": "blind-provenance-v1",
  "author": "external author identity",
  "author_command": "codex exec -C <isolated-directory>",
  "isolated": true,
  "session_ref": "external session evidence identifier",
  "input_material_hashes": {"brief.md": "sha256-of-author-input-bytes"},
  "case_hashes": {"case-01.json": "sha256-of-frozen-case-bytes"}
}
```

The directory must contain exactly the case files named by `case_hashes`, plus `provenance.json`; byte hashes are checked before any case is run. The external owner must verify the author session and physical isolation: a JSON assertion cannot prove filesystem access restrictions. The runner records this as author attestation rather than claiming independently verified isolation. Do not include real accounts, PII, API keys, or private keys in author materials or cases.

For machine-readable contracts, export `BlindCase.model_json_schema()` and `BlindProvenance.model_json_schema()` from `corridor.bench.blind` to the isolated author materials along with the public synthetic fixtures. Do not include kernel code, rule implementations, development attacks, or published judge results. Preserve author-input hashes, session evidence, and frozen raw case files before adapting to the public schema; do not edit an attack after seeing its result.

Evidence is written below `evidence/redteam/blind/<case_id>/`, including original attack text, executed observations, independent oracle JSON, final MockBank state, audit JSONL/checkpoint, and separate suite summaries. Blind statistics are never merged with development attacks.
