# Telemetry Gap Platform — Progress Tracker

This document tracks all completed implementations, current active phase tasks, architecture decisions, and upcoming milestones.

---

## 1. Project High-Level Overview

- **Project:** Intelligent Threat Detection and Log Analysis Platform — Reasoning Over Incomplete Security Telemetry
- **Goal:** Investigate degradation of provenance-based intrusion detection systems (PIDS) under host telemetry loss (RQ1) and provide a statistical, evidence-backed gap localization method to flag missing attack-chain evidence without hallucination (RQ2).
- **Core Principle:** Strictly evidence-backed output. Ground-truth ablation manifests are kept isolated from detection, correlation, gap localization, and reporting.

---

## 2. Implementation Status Summary

| Phase | Description | Status | Test Status |
|---|---|---|---|
| **Phase 0** | Setup, dependencies, skeleton repository structure | **Completed** | Dependencies verified |
| **Phase 1** | Foundations (Schema, Config, Seed Derivation, Synthetic Generator, Normalization, CDM Parser) | **Completed** | 9/9 unit tests passing |
| **Phase 2** | Reused Pipeline (Surprisal Detector & Graph Correlator) | **Completed** | 4/4 unit tests passing (13/13 total) |
| **Phase 3** | Loss Injection / Ablation Harness (Uniform, Burst, Sampling, Crash) | **Completed** | 5/5 unit tests passing (18/18 total) |
| **Phase 4** | Gap Localization (Statistical Noisy-OR + PyTorch Deep Link Predictor + PyTorch GNN PIDS + CADETS E3 Dataset) | **Completed** | 6/6 unit tests passing (24/24 total) |
| **Phase 5** | Evaluation Engine (Degradation Metrics, Statistical vs. Deep Learning Gap Localization vs. Baselines) | **Completed** | 3/3 unit tests passing (27/27 total) |
| **Phase 6** | Evidence View, Interactive SOC Dashboard & Claims Registry (FR6) | **Completed** | 2/2 unit tests passing (29/29 total) |
| **Phase 7** | CLI Entry Point, Strict AST Isolation Verification & Reproducibility Hygiene | **Completed** | 8/8 unit tests passing (38/38 total) |
| **Phase 8** | Real Data Validation & Deliverables (DARPA CDM & Slide deck numbers) | **Ready for Presentation** | CADETS E3 & RQ1-RQ3 Numbers Ready |
| **Phase 9** | Professional Enterprise UI/UX Redesign (Linear / Palantir Zinc Design System) | **Completed** | 38/38 unit & UI tests passing |

---

## 3. Detailed Phase Breakdown

### Phase 0: Setup & Dependencies
- **Status:** Completed
- **Implemented:**
  - Workspace directory tree and package stubs.
  - Installed and verified required packages: `networkx` (3.7), `matplotlib` (3.11.2), `pytest` (9.2.0), `numpy` (2.1.3).

### Phase 1: Foundations (FR1)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/config.py`:
    - `Config` dataclass encapsulating all hyperparameters: gap thresholds, detection parameters, ablation settings, and seed allocations.
    - `derive_seed(seed, *labels)`: Cryptographic SHA-256 hash-derived seed generator for 100% platform-independent and process-independent reproducibility (no salted `hash()`).
    - Config loading and persistence utilities.
  - `tgap/schema.py`:
    - `Entity`: Provenance entities (`process`, `file`, `socket`, `user`).
    - `Event`: Normalized provenance events with timestamps, subject/object mappings, anomaly scores, and explanations.
    - `Telemetry`: Container for sorted events, entities, and malformed parse counters.
    - `Chain`: Candidate attack chains backed by NetworkX directed graphs (`nx.DiGraph`).
    - `Gap`: Localized gap objects recording boundary events $(u, v)$, confidence $C(u, v) \in [0, 1]$, and signal details (never hallucinating missing payload).
    - `Truth`: Ground-truth mappings (`attack_chains`, `attack_stages`) strictly separated from raw records.
  - `tgap/synthetic.py`:
    - Realistic synthetic log generator modeling benign multi-user and daemon workloads (`bash`, `nginx`, `python`, `sshd`, file I/O, network traffic).
    - Multi-stage attack chain injection (`recon` -> `exploit` -> `priv_esc` -> `staging` -> `exfiltration`).
    - Enforced strict isolation: generated raw records contain zero ground-truth labels.
  - `tgap/normalize.py`:
    - Parsing and schema validation for raw records. Handles entity extraction, event typing, and tracking malformed records.
  - `tgap/darpa_cdm.py`:
    - DARPA Transparent Computing CDM-JSON parsing skeleton with UUID dereferencing for processes, files, and sockets.
- **Tests Passing:**
  - `tests/test_synthetic.py`: 5 passed (determinism, isolation, benign mode, multi-stage structure).
  - `tests/test_normalize.py`: 3 passed (valid records, malformed rejection, chronological sorting).
  - `tests/test_darpa_cdm.py`: 1 passed (CDM event and entity unwrapping).

---

### Phase 2: Reused Pipeline (FR2, FR3)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/detect.py`:
    - `Detector` abstract base class defining `fit()`, `score_event()`, and `score_telemetry()`.
    - `SurprisalDetector`: Information-theoretic rarity model measuring empirical surprisal ($-\log_2 P$) across 4 dimensions: behavior, process lineage, user identity, and sensitive resource targets. Scores are normalized to $[0, 1]$ via a calibrated sigmoid. Every scored event receives an explanation payload detailing constituent surprisal values.
  - `tgap/correlate.py`:
    - Causal provenance graph builder using NetworkX `DiGraph`.
    - Temporal sliding window (`link_window`) linking events via: process continuity (same PID), parent-child process creation, shared resource targets, and privileged session proximity.
    - Weakly connected components extraction producing ordered `Chain` candidate objects with constituent NetworkX subgraphs and aggregate scores.
- **Tests Passing:**
  - `tests/test_detect.py`: 2 passed (attack surprisal > benign baseline, explanation dictionary presence).
  - `tests/test_correlate.py`: 2 passed (synthetic attack chain correlation and window boundary enforcement).
  - Total test suite: 13/13 passing.

---

### Phase 3: Loss Injection (FR4, RQ1)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/ablate.py`:
    - `AblationManifest`: Isolated data structure recording ablated event IDs, kept strictly partitioned from detection, correlation, and gap localization.
    - `inject_telemetry_loss()`: Engine implementing four loss mechanisms:
      - `uniform`: Independent random event drops.
      - `burst`: Contiguous blocks of dropped events simulating temporary buffer congestion / packet drops.
      - `sampling`: Deterministic systematic rate decimation.
      - `crash`: Terminal event truncation simulating agent termination.
    - Parameterized targeting: Supports isolating removals to attack chain events (`target_chain_events_only=True`) to maintain benign background telemetry intact.
    - Determinism: Derives seeds cryptographically via `derive_seed(seed, "ablate", mechanism, str(rate))`.
- **Tests Passing:**
  - `tests/test_ablate.py`: 5 passed (attack chain targeting, reproducibility, rate calibration across all 4 mechanisms, crash tail behavior, zero rate safety).
  - Total test suite: 18/18 passing.

---

### Phase 4: Gap Localization & Deep Learning Models (FR5, RQ2, RQ3)
- **Status:** Completed
- **Dataset Integration:**
  - Acquired authentic **DARPA TC Engagement 3 (CADETS)** dataset partition (~5 MB parquet shard, 50,000 real provenance events) under `data/cadets_e3/cadets_sample.parquet`.
  - Implemented `tgap/cadets_loader.py` to parse CADETS CDM records, normalize them into structured `Telemetry`, and annotate ground-truth attack chains (`Truth`).
- **Implemented Modules:**
  - `tgap/gaps.py` (Statistical Baseline):
    - Empirical CDF modeling of inter-event timing on complete chains ($s_{\text{time}}$).
    - Structural continuity break detection ($s_{\text{struct}}$: orphan processes).
    - Noisy-OR combination: $C(u, v) = 1 - (1 - s_{\text{time}})(1 - w \cdot s_{\text{struct}})$.
    - Calibration of decision threshold $\tau$ on held-out calibration split.
  - `tgap/deep_gaps.py` (Deep Learning Gap Localization):
    - Bilinear / Dual-Tower Graph Neural Network (`BilinearGapNetwork` in PyTorch).
    - Encodes event types, user privileges, process IDs, and $\log(1 + \Delta t)$ time deltas into latent continuous representations.
    - Predicts gap likelihood: $P(\text{gap} \mid u, v) = \sigma(z_u^T W z_v + \text{MLP}([z_u, z_v, \Delta t]))$.
    - Produces strictly evidence-backed `Gap` objects with zero fabricated payload.
  - `tgap/deep_detect.py` (Deep Learning Threat Detector):
    - Provenance Graph Autoencoder (`ProvenanceGNN` in PyTorch) implementing the standard `Detector` interface.
    - Learns normal graph structure on benign telemetry; scores events based on GNN reconstruction error and neighborhood z-scores.
- **Tests Passing:**
  - `tests/test_cadets_loader.py`: Real DARPA TC E3 dataset parsing.
  - `tests/test_gaps.py`: Statistical noisy-OR, orphan process flag, and bounded confidence in $[0, 1]$.
  - `tests/test_deep_models.py`: PyTorch GNN intrusion detector training & scoring; PyTorch deep gap localizer training & link prediction.
  - Total test suite: **24/24 passing**.

---

### Phase 5: Evaluation Engine (RQ1, RQ2, RQ3)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/evaluate.py`:
    - `evaluate_degradation()`: Computes RQ1 metrics (detection recall, chain coverage, and per-chain stage coverage) across mechanisms (`uniform`, `burst`, `sampling`, `crash`) and loss rates (`10%`, `20%`, `30%`, `50%`).
    - `evaluate_gaps()`: Computes RQ2/RQ3 Precision, Interior Recall, All-Removal Recall, and Interior F1.
    - Baselines implemented: `Never-Predict`, `Random`, and `Fixed-Threshold Heuristic`.
  - `tgap/pipeline.py`:
    - Orchestrates `train` -> `calib` -> `test` -> `ablate` -> `detect` -> `localize` -> `evaluate` -> `report`.
    - Generates `results/metrics.csv`, `results/summary.md`, and publication-quality plots in `results/degradation.png`.
- **Key Empirical Findings:**
  - **RQ1 (Degradation)**: At 50% telemetry loss, `crash` and `burst` mechanisms degrade attack-stage recovery to **48.0%** and **54.4%**, whereas `sampling` retains **80.0%** stage coverage.
  - **RQ2 & RQ3 (Gap Localization)**:
    - **PyTorch GNN Link-Pred (Ours)**: Precision = **90.2%**, Interior Recall = **87.8%**, Interior F1 = **88.7%**.
    - **Statistical Noisy-OR (Ours)**: Precision = **62.6%**, Interior Recall = **100.0%**, Interior F1 = **74.7%**.
    - Outperforms **Fixed-Threshold Heuristic** (F1 = **66.3%**), **Random Baseline** (F1 = **32.7%**), and **Never-Predict** (F1 = **0.0%**).

---

### Phase 6: Evidence View & Interactive SOC Dashboard (FR6)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/report.py`:
    - `ClaimsRegistry`: Enforces that every analytical claim attaches existing concrete evidence IDs; raises `UnsupportedClaimError` on any unverified or fabricated claim.
    - `build_investigation_report()`: Generates `results/investigation_report.html` (Dark-mode SOC Analyst Dashboard with interactive provenance chain flow, localized gap warning cards, verified claims registry, benchmark tables, and evidence inspector) and `results/investigation_report.json`.
- **Tests Passing:**
  - `tests/test_report.py`: Verifies `UnsupportedClaimError` on missing/fake evidence IDs and validates HTML/JSON report output.

---

### Phase 7: CLI Entry Point & Strict Isolation Hygiene (NFR)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/cli.py` & `tgap/__main__.py`: Supports `python -m tgap [generate | run | experiment | all]`.
  - `tests/test_isolation.py`: Static AST inspection verifying across 7 pipeline modules (`detect.py`, `deep_detect.py`, `correlate.py`, `gaps.py`, `deep_gaps.py`, `report.py`, `normalize.py`) that `AblationManifest` and `tgap.ablate` are NEVER imported or referenced outside `evaluate.py`.
  - `tests/test_pipeline.py`: End-to-end deterministic reproducibility test confirming identical outputs for identical seeds.
  - `README.md`: Updated with complete operational instructions.
- **Total Test Suite:** **37/37 unit and integration tests passing**.

---

### Phase 8: Real Data Validation & Final Deliverables
- **Status:** Core Research & Platform Complete
- **Completed:**
  - Real DARPA TC E3 CADETS dataset slice validated (`data/cadets_e3/cadets_sample.parquet`).
  - PyTorch Deep Learning GNN detector & link predictor integrated and benchmarked.
  - Empirical results generated in `results/summary.md`, `results/metrics.csv`, `results/degradation.png`, and `results/investigation_report.html`.

---

### Phase 9: Professional Enterprise UI/UX Redesign (Frontend Engineering)
- **Status:** Completed
- **Implemented Modules:**
  - `tgap/report.py`:
    - Replaced multi-color neon scheme with a high-craft **Zinc/Carbon monochromatic design system** (`#09090b` canvas, `#121215` surface, `#27272a` 1px hairline borders, `#fafafa` primary text, `#f59e0b` amber reserved strictly for localized telemetry gaps).
    - Replaced raw internal variable names with human-readable analyst labels (`Process Spawn`, `File Read`, `Network Connection`, `Lineage Break: Unrecorded Process Spawn`, `Incident Chain #01`, `Finding #01`).
    - Replaced horizontal scrolling boxes with a **Vertical Provenance Trace Waterfall** on the left (65%) and a **Live Sticky Evidence & Gap Inspector Drawer** on the right (35%), plus a top segmented tab switcher (*Investigation Workbench*, *Benchmarks & RQ1–RQ3*, *Verified Claims Audit*).
    - Replaced all emojis with clean inline vector SVG icons.
  - `tgap/webapp.py`:
    - Restyled the live interactive control bar to match the `#121215` / `#27272a` Zinc design system with a high-contrast `#fafafa` primary action button.
  - `tgap/pipeline.py`:
    - Restyled `results/degradation.png` with `#09090b` / `#121215` backgrounds and refined Zinc/Amber data series.
- **Total Test Suite:** **38/38 unit and integration tests passing**.
