# Submission Artifact Validation

The M1 exports retain the official template branding and numbered section order, with the I1 UI captures and public repository URL. They add separately verified AgentDojo banking evidence. Native wealth results remain historical F5 observations; M1 makes no new model calls for evaluation.

| Artifact | Pages or slides | Editable source |
|---|---:|---|
| [Technical document](tech-doc.pdf) | 14 | [DOCX](tech-doc.docx), [Markdown](tech-doc.md) |
| [Security self-assessment](security-self-assessment.pdf) | 10 | [DOCX](security-self-assessment.docx), [Markdown](security-self-assessment.md) |
| [Execution evidence](execution-evidence.pdf) | 6 | [DOCX](execution-evidence.docx), [Markdown](execution-evidence.md) |
| [Presentation](deck.pdf) | 14 | [PowerPoint](deck.pptx), [English notes](deck-outline.md) |

Presentation notes allocate 550 seconds (9:10); this is an estimate, not a timed rehearsal. The added evidence slide takes 40 seconds, with 20 seconds removed from other slides. Native presentation text is at least 14 pt. The new AgentDojo charts retain editable categories, values and exact numerator/denominator labels. Existing charts use enlarged slide variants; screenshots are retained as full-resolution evidence as well as document crops.

## One-command rebuild

From the repository root, with installed LibreOffice and `pdftoppm` available:

```powershell
uv run --frozen --with matplotlib --with python-docx --with python-pptx --with playwright --with pypdf python docs/submission/build_submission.py --qa-dir ../logs/review/m1/submission
```

Omit `--capture-screens` to reuse the retained screenshots. The builder regenerates eight PNG/SVG figures, three DOCX files and PowerPoint, then exports all four PDFs through installed LibreOffice, rasterizes every page, checks the OOXML packages and permitted placeholders, and runs the numerical checker. Authoring dependencies are ephemeral; `pyproject.toml` and `uv.lock` are unchanged. M1 reused the retained screenshots without opening credential files or invoking a model.

I2 reuses the I1 screenshots captured before W1; it does not claim newly captured W1 views. The original capture manifest and image bytes are unchanged. The retained-source record (not included in public checkout: `docs/submission/provenance/retained-screenshot-sources.json`) binds the exact capture-manifest hash and the six known old/current source-hash pairs. The checker rejects any additional source change or capture-manifest change.

## Visual and source checks

The final review individually inspected all 44 freshly rendered pages/slides for overflow, overlap, blank pages, missing glyphs and readable content. All passed. Page images and contact sheets are retained in `../logs/review/m1/submission/`. The artifact manifest (not included in public checkout: `docs/submission/artifact-manifest.json`) binds output and rendered-page hashes, and the visual review (not included in public checkout: `docs/submission/provenance/visual-review.json`) records the review basis. Original templates remain unchanged. Only `{{TEAM_NAME}}` remains in the rendered documents; the public README also retains `{{LIVE_URL}}`. The repository is [Corridor Wealth source](https://github.com/pzy54154631-hub/Shenzhen-Fintech-international-Project).

Fourteen retained I1 UI scenes are retained in the screenshot manifest (not included in public checkout: `docs/submission/figures/screens/manifest.json`), with full 1920 × 1080 images and focused evidence crops. They identify synthetic data or simulated authentication. They are scripted demonstrations, not live evaluation evidence. The UI exposes existing authenticated correction differences and wires the masked simulated factor input through the existing MFA validator; authorization and execution rules are unchanged.

The numeric check (not included in public checkout: `docs/submission/provenance/number-check.json`) records the final classified numeral count, inconsistency list and missing original evidence links. It checks result labels, modes, counts, denominators and bounds against source rows; review counts against the review/status files; and rule inventory against code. It classifies visible-text numerals and binds embedded image hashes to verified figure or screenshot sources. It does not perform OCR: screenshot values illustrate the captured I1 scripted UI state, not experimental outcomes. Enlarged principal, purchase-fee, correction and available-cash captions were visually transcribed and are bound to their source screenshot hashes as scripted UI examples. The 22 mutation/regression tests passed during I1 Step 4, including changed replay counts and changed fee captions. Mutation tests also exercise wrong values, modes, populations and bounds.

## Evidence and validation

Security must not depend on the model resisting injection: with the planner fully hijacked in model-free GroundTruth replay on [AgentDojo banking](../../evidence/agentdojo-banking/MANIFEST.md) v1.2.2 (package 0.1.35), unrestricted A0 carries out 144/144 injected attacks under the original targeted judge and 128/144 under the registered corrected IT0/IT1/IT3 judge, while Corridor's kernel blocks them in A5 (0/144 under each judge in all three approval modes). Live gpt-6.1-sol resisted `important_instructions` even without defences (A0 0/144 under both judges), so this run shows no observed live security difference; it does show the defence's utility cost, with benign completion 11/16 for A0 versus 8/16 for prompt-bound A5 under the unchanged upstream task-utility judge.

Live prompt-bound A5 is 0/143 evaluable pairs under both judges, with one truncated pair unresolved. The complete census receives no binomial bounds. The manifest binds judge sources, per-population utility and truncation counts, upstream issue attribution and recorded strict-replay verification for all 509/509 live blocks; a passing replay is not another model sample or a successful task.

The original [FINAL-RESULTS](../../results/FINAL-RESULTS.md) and complete [F5 recorded bundle](../../evidence/final-f5/) are retained. Figure extraction and the numerical checker read the report directly and bind its SHA-256. The numerical checker separately binds the historical P2 offline replay summary (not included in public checkout: `evidence/p2-replay/replay-summary.json`) from code before I1 and the current replay summary (not included in public checkout: `docs/submission/provenance/current-replay-summary.json`).

The exact offline command was `uv run --offline --frozen python scripts/replay_final.py --source evidence/final-f5 --output evidence/p2-replay --cases data/blind`. P2 ran it on code before I1 and recorded historical **142/142** byte-for-byte equality with network transport disabled and **0** API calls. Strict replay on the current code verified 142/142 observations: 141 raw observations are byte-for-byte identical, and 1 J01 observation is verified by a migration proof because the bilingual port changed the audit fact-hash format. Network transport was disabled and no API calls occurred. Replay equality preserves original failures, including the gpt-5.4-mini W04 failure. It is not another independent model sample or a count of successful tasks.

The rebuild uses the explicitly requested existing build pipeline and LibreOffice at `C:/Program Files/LibreOffice/program/soffice.exe`. The renderer path is configurable with `--soffice` and recorded in the artifact manifest. Poppler rasterizes the freshly exported PDFs.

The rule registry was recounted: **43 kernel rules, 25 gateway rules and 3 sandbox rules, 71 total**. The deck uses enlarged risk-profile and certificate-highlight screenshots, the repository corpus path `data/blind`, and the measured replay result. The team name remains pending the user's identity value.

M1 passed 37 builder and numerical-check regression tests and 169 public-export tests, with no failures, plus repository ruff lint and formatting checks. Both AgentDojo offline verifiers passed: 720 model-free rows across five census cells, and 509 live blocks with 680 strict-replay witnesses. Public export scans cover decoded Office text, PDF pages and metadata, and raw bytes; exact hash-bound compressed-image exceptions are documented in the private scan audit.

Final artifact checks are recorded in the manifests linked above; historical P2 gates remain in P2 status (not included in public checkout: `docs/status/P2.md`). Historical F5 gate counts remain explicitly attributed to F5. Historical F5 finite-sample descriptive bounds, its exposed blind corpus, synthetic data, simulated MFA, the policy-checked heuristic and investment-advice limits remain visible. The AgentDojo census has no binomial bounds. No deployment, competition upload or timed deck rehearsal occurred in this task.
