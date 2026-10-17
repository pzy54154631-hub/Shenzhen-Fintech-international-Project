# Synthetic wealth fixtures

This namespace belongs to the international Topic B wealth extension. It is
separate from the existing bank fixtures and does not change J01-J24 inputs.
All fixtures describe fictional products, customers and CNY balances.

`allocation-policy-v1.json` is the frozen **unsigned public payload** for the
W0 contract. It has explicit signed-model target values, five profiles and five
sleeves per profile. W1 validates and deterministically signs that payload in
memory with the existing demo bank key. A raw unsigned fixture is never accepted
as a trusted state policy. No key or signature placeholder is stored here.

Catalog binding uses `CATALOG`, version 1. Times match the existing simulator:
2026-10-16T02:00:00Z through 2027-10-16T02:00:00Z, with the end exclusive.
The policy alone does not replace the old bank product catalog; W1 supplies the
separate wealth hand-check products described in
[the public contract](../../docs/wealth-contracts.md#frozen-public-example).

Amounts, rates and weights use exact reduced fraction strings. Freeze new
fixtures as UTF-8; signed/hash inputs use binary reads and canonical JCS bytes.
No API keys, PII, passwords, OTPs or private demo keys belong in this namespace.
Current fixture presence establishes a public input, not a passing wealth run.
