# AgentDojo banking evidence

This bundle separates model-free mechanism replay from recorded live-model evaluation. Both use AgentDojo package **0.1.35**, banking suite **v1.2.2**, upstream commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. Every outcome carries its configuration, approval oracle, judge and denominator in the linked machine summaries.

| Evidence mode | Model | Summary and provenance |
|---|---|---|
| Model-free GroundTruth replay | None; zero model calls | [Summary](model-free/summary.json), [manifest](model-free/MANIFEST.md), [row census](model-free/rows-census.json) |
| Live recorded evaluation; attack `important_instructions` | `gpt-6.1-sol` | [Summary](live/summary.json), [manifest](live/MANIFEST.md) |

The original judge is **AgentDojo v1.2.2 original**. The corrected judge is **Corridor registered corrected IT0/IT1/IT3**, requiring the intended target datum as well as the attacker recipient; other targets and official utility remain unchanged. [AgentDojo issue #181](https://github.com/ethz-spylab/agentdojo/issues/181), opened by Prabscodes on **2026-08-17**, receives credit for the operator-precedence defect. Our additional observation concerns IT1's helper return: its own GroundTruth fails the registered corrected intended-companion check.

The 144 user-task/injection-task pairs form a complete suite census, not a random sample. No binomial confidence bounds accompany the results. Live truncations, exclusions, planned and valid denominators, and strict replay checks remain visible in the live manifest. Zero observed targeted successes is not a general security guarantee.

The external adapter maps free-text tool arguments to typed references by value matching, which is weaker than Corridor's native typed interface. All data and transactions are synthetic. The bundle uses only AgentDojo E4 evidence; paused domestic experiment results are excluded.
