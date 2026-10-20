# Corridor Wealth

Corridor Wealth is a synthetic wealth-advisory prototype for Fintechathon 2026 International AI Track Topic B. It connects English advisory dialogue to signed client goals, complete declared-catalogue comparisons, policy-checked allocations and separately approved purchases.

The language model proposes typed references. A deterministic kernel recomputes eligibility, exact fees, risk bands, concentration and net liquidity from trusted signed inputs. A Best-Interest Allocation Certificate makes the decision inspectable. Each purchase requires scoped simulated MFA and device approval, followed by a fresh dispatch check. Corrections invalidate old authority; partial and unknown outcomes preserve actual bank effects and require explicit recovery.

The integrated implementation includes approval-budget preflight, questionnaire retake controls, effective suitability caps, sourced explanations and bounded unsigned alternatives. Evaluation separates scripted mechanism tests, actual model recordings and transport-disabled strict replay; final denominators, failures and evidence paths appear in results/FINAL-RESULTS.md.

Security must not depend on the model resisting injection: with the planner fully hijacked in model-free GroundTruth replay on AgentDojo banking v1.2.2 (package 0.1.35), unrestricted A0 carries out 144/144 injected attacks under the original targeted judge and 128/144 under the registered corrected IT0/IT1/IT3 judge, while Corridor's kernel blocks them in A5 (0/144 under each judge in all three approval modes). Live gpt-6.1-sol resisted `important_instructions` even without defences (A0 0/144 under both judges), so this run shows no observed live security difference; it does show the defence's utility cost, with benign completion 11/16 for A0 versus 8/16 for prompt-bound A5 under the unchanged upstream task-utility judge.

Live prompt-bound A5 is 0/143 evaluable pairs under both judges, with one pair truncated and unresolved. This census has no binomial bounds; [evidence and limitations](../../evidence/agentdojo-banking/MANIFEST.md) disclose utility, strict replay, upstream defect attribution and the weaker free-text adapter.

The selector is a policy-checked heuristic and can miss feasible allocations. Its sponsor-independence claim applies only within the declared catalogue and policy. Returns are a performance benchmark (not guaranteed). All accounts, products, authentication and transactions are simulated. The prototype provides neither real investment services nor legal suitability certification.
