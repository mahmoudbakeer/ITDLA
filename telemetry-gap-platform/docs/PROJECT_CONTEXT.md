# PROJECT CONTEXT — read this first

Everything needed to continue work on this project without re-reading the chat history.
Companion file: `docs/TODO.md` (live task list with status).

## 1. Identity

- **Title:** Intelligent Threat Detection and Log Analysis Platform — Reasoning Over Incomplete Security Telemetry
- **Type:** B.Tech final-year project, academic cybersecurity research (provenance-based intrusion detection)
- **Team:** Mahmoud Bakir (system ID 2023855493), Jaffar Jned (system ID 2023855498)
- **Mentor/Guide:** Dr. Deepthi P S
- **Institution:** Dept. of Computer Science and Engineering, School of Computer Science and Engineering, Sharda University, Greater Noida, India
- **Evaluation context:** "Evaluation 3" deck (design specification, rubric R2). Sections 9 (Implementation Overview) and 10 (Results and Discussion) of the deck are intentionally placeholders until this application produces real results.
- **Tagline:** "Reasoning about what your security telemetry isn't telling you."

## 2. The idea in one paragraph

Provenance-based intrusion detection systems (PIDSes) assume the host telemetry they get is a complete record.
Real deployments lose telemetry (agent crashes, buffer overflow, sampling, misconfiguration), not only through attacker tampering.
Nobody measures how detection and attack-chain reconstruction degrade under that loss, or tells the analyst where the evidence is incomplete.
This project builds: (a) a pipeline normalization -> context-aware detection -> correlation/chain reconstruction (reusing published methodology),
(b) a reproducible **loss-injection (ablation) harness**, and (c) a **statistical gap-localization** method that flags *where* evidence is likely missing
**without fabricating what the missing evidence was**, and (d) an analyst-facing evidence view where every claim traces to a concrete evidence object.

## 3. Research questions

- **RQ1** — Degradation characterization: how do detection and chain reconstruction degrade as telemetry loss rises, per loss mechanism?
- **RQ2** — Gap localization: can a statistical method flag chain locations where evidence is likely missing, beating naive baselines?
- **RQ3** (stretch) — Learned (e.g. link-prediction) gap localization, only after the statistical baseline is validated.
- RQ1 must be fully resolved before RQ2 is attempted (so a safe result exists if time runs short).

## 4. Scope

- **In scope:** one telemetry source/OS family, offline/batch analysis, reused detection+correlation methodology, original loss-injection and gap-localization work, minimal evidence view.
- **Out of scope:** real-time streaming, multi-tenancy/auth, SOAR/response actions, cloud integrations, novel detection algorithms, LLM-based reasoning, dashboards, databases.

## 5. Requirements

| ID | Functional requirement | Component (module) |
|----|------------------------|--------------------|
| FR1 | Parse raw dataset records into the internal event/entity schema | Normalization (`tgap/normalize.py`) |
| FR2 | Assign anomaly scores to entities/windows using a reused detector | Detection (`tgap/detect.py`) |
| FR3 | Build candidate attack-chain graphs from scored events | Correlation (`tgap/correlate.py`) |
| FR4 | Remove known events from ground-truth chains under a defined loss mechanism and rate | Loss-Injection Harness (`tgap/ablate.py`) |
| FR5 | Flag chain locations where observed continuity is statistically implausible, with confidence C(u,v) | Gap-Localization (`tgap/gaps.py`) |
| FR6 | Display chain + evidence + gaps; every displayed claim traceable to a concrete evidence object | Evidence view (`tgap/report.py`) |

Non-functional: **Reproducibility** (every run re-derivable from fixed seed + config), **Explainability** (no unsupported claims in output),
**Maintainability** (whole pipeline runnable from one entry point: `python -m tgap all`), **Feasibility** (runs on a laptop).

Quantification targets: detection reproduced within a stated tolerance of the published baseline on unablated data; gap-localization precision/recall
measured against baselines **never-predict, random, fixed-threshold heuristic**.

## 6. Architecture (modular monolith, Python)

```
Telemetry (dataset) -> Normalization -> Detection + Correlation/Chain-building   [reused methodology]
   -> Loss-Injection Harness (offline, eval-only) -> Ablation Manifest
   -> Gap-Localization [original contribution] -> Evidence/Investigation View
```
Data flow: raw records -> typed Events/Entities -> scored chains -> ablated chains (manifest held separately) -> gap objects -> rendered evidence output.

**Hard rule — strict data isolation:** the ablation manifest is NEVER visible to detection, correlation, gap-localization or the report.
Only `tgap/evaluate.py` reads it. Enforced by an AST-based test (`tests/test_isolation.py`).
No relational DB: events/entities/chains are plain structured objects; graphs use NetworkX in memory. Config is JSON (no YAML dependency).
SDLC: iterative/incremental; each stage validated on a small slice before scaling.

## 7. Implementation decisions and honest caveats (do not hide these in reports)

1. **No DARPA TC E3 data in the dev sandbox** (huge, restricted network). Development uses a **seeded synthetic provenance generator**
   (`tgap/synthetic.py`) with benign sessions + injected multi-step attack chains + ground truth. Synthetic numbers must **never** be presented as DARPA results.
2. **`tgap/darpa_cdm.py`** is a CDM-JSON reader skeleton validated only on a tiny hand-written sample. It must be validated on real DARPA TC E3 data (TODO).
3. **The "reused detector" is a stand-in:** a context-aware rarity/surprisal model (behavior, process lineage, identity, time-of-day) behind a small `Detector`
   interface. PIDSMaker (planned reuse of published PIDSes: Kairos, UNICORN, etc.) is NOT integrated yet. Swapping it in must not touch gap-localization.
4. **Ablation placement (interpretation to confirm with mentor):** the harness removes events of ground-truth chains from the event stream; the
   ablated stream is re-run through detection+correlation (needed for RQ1) and the resulting chains feed gap-localization.
5. **Gap-localization method (v1, statistical, interpretable):** for each pair of consecutive events (u,v) in a detected chain:
   `s_time` = empirical CDF of the inter-event gap under complete-data chains; `s_struct` = 1 if v's acting process appears with no recorded creation
   (orphan-process continuity break); `C(u,v) = 1 - (1 - s_time) * (1 - w * s_struct)` (noisy-OR, w configurable, default 0.7).
   Flag if `C >= gap_tau`; `gap_tau` is chosen on a separate calibration dataset, never on the test data. A gap object contains only location, confidence and
   the signals used — it never states what the missing event was.
6. **Gap evaluation definition:** a flagged gap (u,v) is correct if at least one removed event lies in time between u and v. Precision = correct flagged / flagged.
   Recall is reported two ways: over *interior* removals (inside a detected chain's time span — localizable at all) and over *all* removals.
   Precision with zero predictions is reported as 0.0 (never-predict baseline).
7. **Known limitations:** losses at chain head/tail cannot be localized; fragmented chains (loss larger than `link_window`) are not bridged in v1; gap timing stats are global, not per transition type.

## 8. Evaluation protocol

Three synthetic datasets from separate derived seeds: `train` (benign only; fits detector), `calib` (benign + attacks; fits gap-timing distribution and selects `gap_tau`),
`test` (benign + attacks; ablated, reported). Experiment grid: mechanisms {uniform, burst, sampling, crash} x rates {0.1,0.2,0.3,0.5} x seeds {1..5}.
Methods compared: ours, never-predict, random (same number of flags as ours), fixed-threshold (gap > `fixed_gap_seconds`).
Outputs: `results/metrics.csv` (per run), `results/summary.md`, `results/degradation.png`.

## 9. Repository layout

```
telemetry-gap-platform/
  README.md                 how to run
  docs/PROJECT_CONTEXT.md   this file
  docs/TODO.md              plan + status
  configs/default.json      all tunables
  tgap/                     package (config, schema, synthetic, darpa_cdm, normalize, detect, correlate, ablate, gaps, evaluate, report, pipeline, cli)
  tests/                    pytest suite
  results/                  generated outputs
```
Run: `python -m tgap all --config configs/default.json` (also `run`, `experiment`, `generate`). Tests: `python -m pytest -q`.

## 10. Conventions

- No global RNG: every random source is a `random.Random` seeded via `config.derive_seed(seed, *labels)` (hash-based, not Python's salted `hash`).
- Event IDs are the raw record sequence numbers and stay stable through ablation (evidence ids look like `E123`).
- Raw records never carry labels; ground truth lives in a separate `Truth` object used only by evaluation/ablation.
- Keep modules independent and swappable; no stage imports a later stage.

## 11. Related deliverables (outside this repo)

- Workload matrix PDF — done (delivered earlier in chat).
- Evaluation PPT deck built from the user's template `Eval-3_PPT_Format.pptx` (4:3, Calibri theme, Title/Content layouts). A build script
  (`build_deck.py`, python-pptx) was written but NOT yet run/QA'd; slides 9/10 stay "Content pending" until results exist. Deck content spec is the user's
  14-section outline (sections numbered 1-8, 9/10 placeholders, 11, 13, 14; no section 12; reference [4] intentionally absent).
