# TODO — live plan (update checkboxes as work completes)

Read `docs/PROJECT_CONTEXT.md` first. Status legend: `[x]` done and tested, `[~]` done but needs validation, `[ ]` not started.

## Phase 0 — Setup
- [x] Project skeleton, docs, deps check (networkx, numpy, matplotlib, pytest)

## Phase 1 — Foundations (FR1)
- [x] `config.py`: dataclass Config, JSON loader, `derive_seed`
- [x] `schema.py`: Entity, Event, Telemetry, Chain, Gap, Truth
- [x] `synthetic.py`: benign sessions + attack chains + truth (seeded)
- [x] `normalize.py`: raw records -> Telemetry (skip + count malformed)
- [x] `darpa_cdm.py`: CDM JSON skeleton -> raw record dicts
- [x] tests: normalize, synthetic determinism / no labels in raw records, cdm sample

## Phase 2 — Reused pipeline (FR2, FR3)
- [x] `detect.py`: context-aware surprisal detector (behavior, lineage, identity, time) with explanations
- [x] `correlate.py`: anomalous events -> chains (entity + time-window linking), NetworkX chain graph
- [x] tests: attack scores > benign, chain recovery on complete data

## Phase 3 — Loss injection (FR4, RQ1)
- [x] `ablate.py`: uniform, burst, sampling, crash mechanisms + separate manifest
- [x] tests: only chain events removed, reproducible, rate sanity

## Phase 4 — Gap localization (FR5, RQ2, RQ3)
- [x] `gaps.py`: fit timing ECDF, orphan-process structural signal, noisy-OR confidence C(u,v), threshold calibration
- [x] `deep_gaps.py`: PyTorch Bilinear / Dual-Tower GNN link predictor for learned gap localization
- [x] `deep_detect.py`: PyTorch Provenance Graph Autoencoder (GNN) threat detector behind Detector interface
- [x] `cadets_loader.py`: Real DARPA TC E3 CADETS dataset loader & IoC annotator
- [x] tests: statistical noisy-OR, bounded confidence, deep link predictor, deep GNN PIDS, CADETS real data slice

## Phase 5 — Evaluation (RQ1, RQ2, RQ3)
- [x] `evaluate.py`: degradation metrics, gap precision/recall (interior + all), baselines (never, random, fixed-threshold)
- [x] `pipeline.py`: train -> calib -> test -> ablate -> detect -> localize -> evaluate
- [x] experiment grid -> `results/metrics.csv`, `summary.md`, `degradation.png`

## Phase 6 — Evidence view (FR6)
- [x] `report.py`: claims registry (claim without evidence id is rejected), interactive SOC HTML + JSON output
- [x] test: unsupported claim raises

## Phase 7 — Entry point and hygiene (NFR)
- [x] `cli.py` + `__main__.py`: `generate | run | experiment | all`
- [x] `tests/test_isolation.py`: manifest never imported by detect/correlate/gaps/report
- [x] `tests/test_pipeline.py`: end-to-end small config, same seed -> identical output
- [x] README with run instructions

## Phase 8 — Open items & Final Presentation Deliverables
- [x] Validate `darpa_cdm.py` on real DARPA TC E3 data (`data/cadets_e3/cadets_sample.parquet`)
- [x] RQ3 stretch: learned link-prediction component (`tgap/deep_gaps.py` & `tgap/deep_detect.py`)
- [ ] Integrate external PIDSMaker detector behind the `Detector` interface (optional extension)
- [ ] Confirm with mentor: ablation applied to telemetry stream then re-detected (see CONTEXT 7.4)
- [ ] Per-transition-type timing stats; chain-fragment bridging (v2 of gap-localization)
- [ ] Feed real measured numbers into deck slide 3 (Quantification) and slides 9/10
- [ ] Run + QA the PPT build script (`build_deck.py`) — not yet executed

## Phase 9 — Professional Enterprise UI/UX Redesign (Frontend Engineering)
- [x] **9.1 Design System & Color Palette Overhaul**:
  - Replace clashing multi-color neon theme with a disciplined monochromatic **Zinc/Carbon palette** (`#09090B` background, `#121215` surface, `#27272A` 1px hairline borders, `#FAFAFA` primary text, `#A1A1AA` muted text) inspired by Linear, Vercel, and Palantir Foundry.
  - Restrict accent colors strictly to semantic meaning: Neutral Zinc for observed telemetry, subtle Cobalt (`#3B82F6`) for active selection, and refined Amber (`#F59E0B`) exclusively for localized telemetry gaps.
  - Remove all emojis (`🛡️`, `🚀`, `⚡`, `🎛️`) and replace with crisp inline SVG vector icons.
- [x] **9.2 Typography & Human-Readable Taxonomy**:
  - Use `Inter` / system sans-serif for UI labels and `JetBrains Mono` / monospace strictly for IDs, PIDs, paths, and timestamps.
  - Replace raw internal variable names (`s_time`, `s_struct`, `process_create`, `chain_1`) with clean analyst terminology (`Timing Deviation`, `Lineage Break: Orphan Process`, `Process Spawn`, `Incident Chain #01`).
- [x] **9.3 Master-Detail Workbench Layout (UX Architecture)**:
  - **Top App Bar + Segmented Tabs**: Clean navigation switching between *Investigation Workbench*, *Degradation & Benchmarks*, and *Verified Claims Audit*.
  - **Vertical Trace Waterfall (Left 65%)**: Replace awkward horizontal-scrolling boxes with a vertical top-to-bottom provenance timeline (like Datadog traces / GitHub commit graphs) where localized gaps appear as inset dotted-connector callouts between $(u, v)$.
  - **Sticky Evidence Inspector Panel (Right 35%)**: Clicking any event node or gap immediately populates the right-hand inspector drawer with full system call metadata, anomaly score decomposition, and linked claims without scrolling the page.
- [x] **9.4 Cohesive Matplotlib Chart Styling (`pipeline.py`)**:
  - Restyle `degradation.png` to match the exact Zinc `#121215` surface, subtle gridlines, and refined typography of the web application.
