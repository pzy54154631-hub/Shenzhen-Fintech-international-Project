# Wealth incremental contracts

This W0 record identifies the adopted Topic B contract and its public fixtures.
It does not certify completion of W1/W2 or of the W judge suite. Executable wire
validation and deterministic fixture signing belong to W1; gateway persistence,
child authorization and dispatch belong to W2. Actual checks are recorded in
`docs/status/W0.md` and subsequent card status files.

## Authority and scope

ADR-012 takes precedence over ADR-011 and the older draft wording in
`DESIGN-WEALTH.md` / `TASKS-WEALTH.md`. It adopts discussion round 8 and D8-01
through D8-06, with the following explicit override: **model weights are supplied
and signed by the bank policy; they are not derived from band midpoints**.
Validation requires exact sum one, all sleeve/group bounds and zero weight above
the client's risk level. No midpoint equality or midpoint normalization is an
acceptance condition. The historical design files remain unchanged.

Only synthetic new-money allocations for one client and one CNY current account
are in scope. Existing holdings do not enter the allocation denominator. The
five-question risk model, single-product BIC path, F1/F2 corrections, existing
kernel API and forbidden-import boundaries remain unchanged. In particular,
`AUTH-CONSUMED`, `RISK-ANSWERS-CONSUMED`, `RISK-ANSWERS-STALE`, dispatch rechecks and
`APR-DRIFT` remain mandatory. A C2 customer cannot hold an R3 product even if an
incorrect policy gives that sleeve a positive upper band.

| Adopted increment | Authority and boundary |
|---|---|
| `S.allocation_policies` | ADR-012 / D8-05; bank-root-signed current policy, outside untrusted marketing data |
| `S.allocation_plans` | ADR-012 / D8-05; immutable parent plan and exact child mapping; runtime state comes from existing events |
| Policy signature context | `corridor/bank/allocation-policy/v1`, existing bank root; no policy-editing chat tool |
| Allocation request | Existing device-signed INPUT context; `slot="allocation"`, `scope_id=parent_intent_id` |
| BIAC branch | Optional allocation witness on BankCertificate; a purchase uses exactly one of BIC or BIAC |
| `allocation_compare` | Green read operation under signed goals and session permission; signed built-in analysis receipt, no purchase |
| Child execution | Device derives stable product-specific child intents and signs independent inputs/OperationAuthorization |
| MFA | One current scoped MFA grant and ApprovalToken per purchase; no shared batch grant |
| Kernel interface | Existing `kernel.check` signature and import boundary retained |

## Public wire v1

All objects are strict closed records. Unknown fields, duplicate JSON properties,
JSON floats, malformed rationals and unsupported versions fail under controlled
validation. Amounts, fees, rates and weights are canonical reduced `n/d` strings;
internal arithmetic uses Fraction. Amounts are exact cents. Times are simulated
UTC `YYYY-MM-DDTHH:MM:SSZ`. IDs are deterministic and signatures/hash payloads use
the existing JCS domain-separation conventions. The following field lists freeze
the public contract; W1 supplies the executable schemas and resource bounds.

```text
AllocationRequest:
  id, version, source_account_ref, amount, horizon_days,
  liquidity_days, liquidity_amount, allowed_types, objective,
  allocation_policy_ref, selection_mode,
  target_weights?, items?, model_biac_hash?, reason_code?

AllocationPolicy:
  schema_version="allocation-policy-v1", id, version, issued_at, valid_until,
  catalog_id, catalog_version, currency="CNY",
  selector_version="greedy-sleeves-v1", ranking_basis="request_principal",
  concentration_cap="1/2", max_products=12,
  profiles={C1..C5: {bands, group_bounds, model_weights}}, sig

Band: sleeve=R1..R5, lower, upper
GroupBound: sleeves=[R1..R5], lower, upper
ModelWeights: {R1, R2, R3, R4, R5}

BestInterestAllocationCertificate:
  schema_version="biac-v1", selector_version,
  request_hash, policy_hash, catalog_hash, risk_assessment_hash,
  principal, source_account_ref, base_context_hash,
  candidate_ids, exclusions, sleeves, allocation, totals, checks,
  selection_mode, model_biac_hash?, deviations?, fact_reasons

Exclusion: product_id, reason_codes
Sleeve: sleeve, model_weight, target_cents, actual_cents, candidate_ids, ranking_rows
AllocationItem:
  product_id, sleeve, principal, weight, fee_buy, fee_hold, fee_sell,
  expected_net, access_days, liquid_net_principal, selection_reason
Totals: principal, fee_buy, total_debit, projected_fees, projected_net,
        liquid_net_principal
Check: constraint_id, lhs, comparator, rhs, satisfied
FactReason: template_id, fact_refs

AllocationFailure:
  input_hashes, candidate_ids, exclusions, stage, reason_codes,
  residual_cents, unmet_constraints

AllocationPlan:
  id, version, principal, parent_intent_id, request_ref, biac_hash,
  policy_hash, catalog_hash, risk_assessment_hash, initial_budget, items, plan_hash
PlanItem:
  item_ref, product_ref, principal, fee_buy, child_intent_id,
  input_refs, authorization_ref
```

`allowed_types` is a nonempty unique subset of `deposit`, `wealth`.
`objective` is `net_return`, `total_fee` or `liquidity`. The horizon is 1-365 days;
`0 <= liquidity_days <= horizon_days` and `0 <= liquidity_amount <= amount`.
Every policy contains all five profiles and every profile all five sleeves.
Products retain the existing signed numeric risk levels 1-5; public sleeve labels
R1-R5 refer to those same levels. Policy validity is
`issued_at <= S.now < valid_until`; catalog identity/version and the current
policy version must match. The conservative current-policy representation has
exactly one trusted policy entry; the request must reference that entry. Parent
plans pin its hash. Unknown, ambiguous or downgraded policies cannot be selected
by the planner.

Default requests have no explicit adjustment fields. `explicit_weights` signs
five exact target weights. `explicit_items` signs a complete product/amount
vector. Both bind a reconstructable default `model_biac_hash` in the same economic
context and require an active device gesture. Neither mode overrides suitability,
bands, concentration, liquidity, affordability or single-use authorization.
Cards retain the label **Deviation from model allocation** and exact amount,
percentage-point, fee, projected-return and liquidity differences.

Candidate IDs, exclusions and items sort by product ID; sleeves sort R1-R5 and
ranking rows by rank. Every catalog product appears exactly once in candidates
or exclusions. Ranking rows bind their common reference amount/horizon and mark
themselves `comparison_only`. `base_context_hash` covers principal, parent intent,
source, amount/horizon/liquidity/allowed types/objective, signed policy/catalog/
risk hashes, account semantic version and initial budget. It excludes adjustment
fields, signatures, marketing, model prose and ephemeral approval data. Full
`request_hash` still binds the signed request and cannot be replaced by the common
context hash.

After verification, comparison facts use the existing signed AnalysisReceipt
with `function_id="allocation_compare_v1"`, `trust="builtin"`. BIAC itself is an
untrusted witness recomputed from S, not a model-signed authorization. The parent
plan also binds the exact mapping to one single-node legacy Plan per child; W2
must retain that mapping in its executable representation.

## Calculation and execution invariants

Eligibility uses a nonempty admissible per-product amount interval, not the
assumption that every product can accept the whole request. The upper candidate
amount is the cent-rounded minimum of principal, concentration cap and any
product limit. The lower candidate amount is the positive cent-rounded minimum.
Suitability, sale availability, ownership eligibility, type, horizon and minimum
purchase affordability still apply. Full E includes a valid product capped below
the requested principal.

Rank all of each sleeve's E at the same principal/horizon. Rank by the signed
objective and then ASCII product ID. Actual fees/returns use each actual product
amount. Round each purchase/holding/redemption fee upward to cents separately.
Allocate within fixed sleeve budgets, first to liquidity-eligible candidates,
then by sleeve ranking, using bounded greedy cent arithmetic. Recheck every hard
constraint over the whole vector. A greedy failure is **No allocation was
constructed under this policy and these inputs**, never a proof of infeasibility.

Liquidity access is minimum holding days plus redemption delay. Available liquid
principal subtracts the holding fee through earliest redemption and the
redemption fee, excludes projected income and uninvested cash, and must meet the
signed requirement. Product concentration aggregates all amounts with the same
product ID. There is no rounding tolerance on sleeve/group bands or conservation.

All positive rows must be explicitly selected before a full plan starts.
Unselected rows receive zero authorization. Child identity depends on the signed
parent intent and stable product ID, never on planner plan/node/revision values.
A consumed parent/product identity cannot be bought again by changing wrappers,
restarting, or reusing an old explicit request. Parent Stop/handoff also blocks
direct child dispatch. Each child receives its current canonical card, its own
MFA grant and its own approval immediately before gateway dispatch.

Complete-vector dispatch uses `B0=initial available balance-floor`. For verified
settled debits `d` of this same plan only, recheck `Bnow+d=B0`, then check the
remaining actual debits against Bnow. Never add back other reservations or
unknown effects. Policy/catalog/risk/input/account/external-budget drift stops
the plan. A successful earlier purchase is retained if later work fails or is
stopped. Unknown reserves remain and must be looked up, never resent. Summary
states are draft, ready, executing, completed, partially_executed,
failed/cancelled and unknown; receipts determine completion.

## Rule obligations

The authoritative executable registry remains `src/corridor/kernel/rules.py`.
W1 must register each new rule and provide a precise fault-injection golden plus
an accepted control, with the security self-assessment updated at the same time.

| Rule | Rejects |
|---|---|
| ALLOC-POLICY | Invalid signature, version, catalog binding, validity, bounds or explicit signed model weights |
| ALLOC-BAND | Actual sleeve/group fractions outside their exact bands, including explicit adjustments |
| ALLOC-CONC | Product total above half the requested principal |
| ALLOC-LIQ | Insufficient or falsely computed net liquidity by the signed deadline |
| ALLOC-SUM | Invalid cents/positive items, principal conservation, per-item fees or total debit |
| ALLOC-SELECT | Constructor failure, wrong deterministic default, mismatched explicit selection or fabricated reasons/differences |

Existing BIC-CATALOG, BIC-RISK, BIC-PREFERENCE, BIC-COMPLETE, BIC-SCORE and
BIC-NOFEASIBLE also apply, as do BAL-AVAILABLE, AUTH-SCOPE, AUTH-CONSUMED,
PLAN-SCOPE, APR-SWAP, APR-DRIFT and MFA obligations. Reject precedes escalation;
MFA cannot override a failed economic constraint. Undefined parameters require
an appended PROP and conservative rejection, never a silent acceptance.

## Public task IDs

| ID | Required machine-checked behaviour |
|---|---|
| W01 | Clarify missing signed profile and goals; no inferred risk or amount |
| W02 | Reject expired/replayed questionnaire answers; require fresh device answers |
| W03 | Complete eligibility, all three ranking objectives and exact fee/tie variants |
| W04 | Default allocation, signed-policy conflicts, capacity/greedy failure and cent boundaries |
| W05 | Net-liquidity requirement, fees and impossible-liquidity variants |
| W06 | Concentration and same-sleeve fill without risk escalation |
| W07 | Device-signed weights/items and persistent model-deviation facts |
| W08 | Out-of-band, one-cent and unsuitable-product rejection; accepted boundary control |
| W09 | Marketing-independent economic output; order invariance and real economics sensitivity |
| W10 | Candidate-set, arithmetic and selection tampering with precise rules |
| W11 | Two real gateway purchases, per-item MFA, anti-replay, drift, partial and unknown recovery |
| W12 | Injection/clean twins with unchanged economic projection and existing safety lock retained |

W13/W14 are excluded under ADR-012. W01-W12 are separate from J01-J24. Each ID
contains all subcases specified in DESIGN-WEALTH section 8.2; passing one normal
path does not establish the task's completion. W1 covers W03-W10 computation;
W2 covers execution assertions; W4 owns the complete judge/oracle and six-cell
matrix. A W6 dialogue smoke test is not a replacement for the W4 suite.

## Frozen public example

`data/wealth/allocation-policy-v1.json` contains the unsigned public policy
payload. W1 verifies the payload, constructs the strict policy and signs it in
memory using the existing deterministic bank demo key. The file contains no
signature placeholder or private key and is never trusted before signing and
validation. Its current catalog identity/version are `CATALOG` / 1, matching the
bank simulator naming convention; the wealth product contents are separate.

The hand-check case is C2, 12000 CNY available budget, 10000 CNY new principal,
365-day horizon, 3-day liquidity deadline, zero required liquidity, wealth-only,
net-return objective. C2 bands are 40%-60% for R1 and R2, zero for R3-R5, with
signed model weights of one half each and product concentration at one half.
The C1 fixture assigns all weight to R1. C3-C5 conservatively reuse the C2 model
and bands with higher-risk sleeves zero; they do not promise a separate demo.

| Product | Risk | Hold/delay days | Annual rate | Minimum |
|---|---|---|---|---|
| P_A | R1 | 30/0 | 3/100 | 100/1 |
| P_B | R1 | 0/1 | 1/50 | 100/1 |
| P_C | R2 | 30/0 | 1/25 | 100/1 |
| P_D | R2 | 0/1 | 3/100 | 100/1 |
| P_X | R3 | 0/0 | 9/100 | 100/1 |
| P_Y | R1 | 0/0 | 1/100 | 20000/1 |

Fees are zero and product maxima absent in this base case. E is A/B/C/D;
A5000+C5000 has projected net return 350, total debit 10000 and net liquidity 0
at day 3. Requiring liquidity 5000 produces A5000+D5000, projected return 300.
Expected values are public hand calculations, not claimed test results.

## Data and evidence namespaces

| Path | Purpose |
|---|---|
| `data/wealth/` | Frozen public synthetic policy/product/request/task fixtures |
| `data/replay/wealth/` | Real wealth model recordings, isolated from `data/replay/bank/` |
| `evidence/wealth/judge/<planner>/<config>/<user_policy>/<Wxx>/` | W task evidence and manifests |
| `evidence/wealth/bench/<planner>/<config>/<user_policy>/` | Wealth six-cell matrix details |
| `evidence/wealth/plans/<parent_intent_id>/` | Parent BIAC/plan manifests and hashes linking child evidence |
| `evidence/decisions/<intent_key>.json` | Existing per-dispatch decision record, retained for wealth purchases |

Do not overwrite bank J evidence or historical domestic results. Replay keys bind
schema, model, API type, prompt/tools, trusted tool state, configuration and user
policy. Preserve short hashed filenames and existing path-depth conventions.
Manifests bind code/data/policy/selector versions, planner source and exact task/
subcase denominators. Parent manifests contain only hashes and desensitized IDs;
per-item action/cert/card/token/grant/receipt references remain traceable. Audit
storage remains append-only JCS bytes plus newline and verified checkpoints.

`scripted`, `live-recorded`, `not_recorded` and `not_run` are distinct provenance
states. Neither an absent cache nor an absent blind set is a passing zero. Fees,
projected return differences, realized cash harm and liquidity shortfalls are
reported separately; no portfolio-optimality regret is claimed.
