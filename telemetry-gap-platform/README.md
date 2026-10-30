# Telemetry Gap Platform (`tgap`)

> **Intelligent Threat Detection and Log Analysis Platform: Reasoning Over Incomplete Security Telemetry**  
> **B.Tech Final-Year Capstone Project**  
> **Authors:** Mahmoud Bakir (`2023855493`) & Jaffar Jned (`2023855498`)  
> **Mentor:** Dr. Deepthi P S (Dept. of Computer Science & Engineering, Sharda University)

---

## Table of Contents

1. [Project Summary](#1-project-summary)
2. [Core Architecture & Modules](#2-core-architecture--modules)
3. [System Requirements & Dependencies](#3-system-requirements--dependencies)
4. [Step-by-Step Installation Guide](#4-step-by-step-installation-guide)
5. [How to Run the Platform](#5-how-to-run-the-platform)
6. [How to Run the Automated Test Suite](#6-how-to-run-the-automated-test-suite)
7. [Empirical Evaluation Summary](#7-empirical-evaluation-summary)

---

## 1. Project Summary

### The Problem
Provenance-based Intrusion Detection Systems (PIDS) reconstruct multi-stage Advanced Persistent Threat (APT) attacks by connecting host audit events (`process_create`, `file_read`, `file_write`, `net_connect`, `auth_login`) into a directed causal provenance graph. However, existing PIDS assume **100% complete telemetry**. In real enterprise networks, host audit streams regularly lose events due to:

- **Burst Overflow (`burst`)**: Kernel ring-buffer saturation during high I/O spikes.
- **Uniform Drop (`uniform`)**: Independent packet drops during UDP/syslog forwarding.
- **Systematic Sampling (`sampling`)**: Rate-limiting decimation on high-throughput servers.
- **Agent Crash (`crash`)**: Endpoint sensor termination or reboot mid-incident.

When intermediate events are lost, attack chains break into disconnected fragments and security analysts are never informed *where* evidence is missing.

### Our Solution
The **Telemetry Gap Platform (`tgap`)** is a provenance-based threat detection, controlled telemetry ablation, and evidence-backed **gap-localization** platform. Rather than fabricating or guessing dropped log payloads, the platform:

1. **Quantifies Detection & Chain Degradation (`RQ1`)**: Measures how event recall and multi-stage attack-chain reconstruction degrade across the 4 loss mechanisms (`uniform`, `burst`, `sampling`, `crash`) and drop rates (`10%`, `20%`, `30%`, `50%`).
2. **Localizes Missing Telemetry via Statistical Noisy-OR (`RQ2`)**: Flags consecutive chain events `(u, v)` where telemetry continuity is broken by combining an empirical inter-event timing CDF score (`s_time`) with an orphan-process lineage break indicator (`s_struct`):
   $$C(u, v) = 1 - (1 - s_{\text{time}}(u, v)) \cdot (1 - w \cdot s_{\text{struct}}(u, v))$$
3. **Localizes Gaps & Detects Threats via Deep Learning GNNs (`RQ3`)**:
   - **PyTorch Provenance Graph Autoencoder (`DeepProvenanceDetector`)**: Learns normal graph topology on benign host telemetry and scores structurally anomalous subgraphs.
   - **PyTorch Bilinear GNN Link Predictor (`DeepGapLocalizer`)**: Learns dual-tower node and temporal embeddings to predict the likelihood of missing telemetry hops between `(u, v)`.
4. **Enforces Zero-Hallucination & 100% Evidence-Backed Claims (`FR6`)**:
   - `Gap` objects strictly report the bounding observed event IDs `(u, v)`, bounded confidence $C(u, v) \in [0, 1]$, and observed structural/timing signals, without ever inventing missing system call payloads.
   - Every analytical statement in the investigation workbench is validated by `ClaimsRegistry` against concrete observed event IDs (`E...`) or localized gap IDs (`GAP-...`).

---

## 2. Core Architecture & Modules

| Module Path | Responsibility |
| :--- | :--- |
| [`tgap/config.py`](tgap/config.py) | Configuration dataclass, JSON loader, and SHA-256 deterministic seed derivation (`derive_seed`). |
| [`tgap/schema.py`](tgap/schema.py) | Core dataclasses: `Entity`, `Event`, `Telemetry`, `Chain`, `Gap`, and `Truth`. |
| [`tgap/synthetic.py`](tgap/synthetic.py) | Seeded generator for benign background sessions and 5-stage APT attack chains (`recon` -> `exploit` -> `priv_esc` -> `staging` -> `exfiltration`). |
| [`tgap/darpa_cdm.py`](tgap/darpa_cdm.py) | Parser for DARPA Transparent Computing Common Data Model (CDM-18) provenance records. |
| [`tgap/cadets_loader.py`](tgap/cadets_loader.py) | Loader for the authentic **DARPA TC E3 CADETS** dataset shard (`data/cadets_e3/cadets_sample.parquet`, 50,000 FreeBSD records). |
| [`tgap/normalize.py`](tgap/normalize.py) | Validates raw log dictionaries into chronologically ordered `Telemetry` streams and counts malformed records. |
| [`tgap/detect.py`](tgap/detect.py) | `Detector` interface and `SurprisalDetector` (context-aware information-theoretic rarity across behavior, lineage, user, and target). |
| [`tgap/deep_detect.py`](tgap/deep_detect.py) | `DeepProvenanceDetector`: PyTorch Provenance Graph Autoencoder (GNN) for anomaly detection. |
| [`tgap/correlate.py`](tgap/correlate.py) | Builds directed `NetworkX` provenance graphs (`nx.DiGraph`) linking anomalous events into candidate `Chain` objects. |
| [`tgap/ablate.py`](tgap/ablate.py) | Controlled loss injection (`uniform`, `burst`, `sampling`, `crash`) and strictly isolated `AblationManifest`. |
| [`tgap/gaps.py`](tgap/gaps.py) | `StatisticalGapLocalizer`: Empirical timing ECDF (`s_time`) + orphan-process continuity break (`s_struct`) fused via calibrated Noisy-OR. |
| [`tgap/deep_gaps.py`](tgap/deep_gaps.py) | `DeepGapLocalizer`: PyTorch Bilinear GNN Link Predictor for learned gap localization. |
| [`tgap/evaluate.py`](tgap/evaluate.py) | Computes RQ1 degradation metrics and RQ2/RQ3 Precision, Interior Recall, All-Removal Recall, and F1 vs. baselines. |
| [`tgap/pipeline.py`](tgap/pipeline.py) | Orchestrates `train -> calib -> test -> ablate -> detect -> localize -> evaluate -> report` and renders Matplotlib charts. |
| [`tgap/report.py`](tgap/report.py) | Enforces `ClaimsRegistry` and builds the standalone HTML & JSON SOC Investigation Workbench. |
| [`tgap/webapp.py`](tgap/webapp.py) | Live interactive Flask web application (`python -m tgap ui`). |
| [`tgap/cli.py`](tgap/cli.py) | Command-line interface supporting `ui`, `all`, `experiment`, `run`, and `generate`. |

---

## 3. System Requirements & Dependencies

### System Requirements
- **Operating System:** Windows 10/11, macOS, or Linux
- **Python:** Python `3.10` or higher (tested with Python `3.13`)
- **Hardware:** Standard CPU (4 GB+ RAM); no dedicated GPU is required.

### Python Dependencies ([`requirements.txt`](requirements.txt))

| Library | Version | Purpose |
| :--- | :--- | :--- |
| `numpy` | `>=1.24.0` | Empirical CDF computation, vector math, and threshold calibration |
| `networkx` | `>=3.0` | Provenance directed graph (`nx.DiGraph`) construction and chain extraction |
| `matplotlib` | `>=3.7.0` | Generates `results/degradation.png` evaluation plots |
| `torch` | `>=2.0.0` | PyTorch Provenance GNN Autoencoder and Bilinear GNN Link Predictor |
| `pyarrow` | `>=12.0.0` | Reads the DARPA TC E3 CADETS Parquet dataset (`data/cadets_e3/cadets_sample.parquet`) |
| `flask` | `>=2.3.0` | Serves the live interactive web workbench (`http://127.0.0.1:5000`) |
| `pytest` | `>=7.0.0` | Runs the 38 unit, integration, and AST data-isolation tests |

---

## 4. Step-by-Step Installation Guide

### Step 1: Navigate to the Project Directory
Open **PowerShell** (Windows) or **Terminal** (macOS/Linux):

```powershell
cd c:\Users\mahmo\dir\Capstone\telemetry-gap-platform
```

### Step 2: Create and Activate a Virtual Environment (Recommended)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

Install all required packages using [`requirements.txt`](requirements.txt):

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> **Note:** If you want to install individual packages manually or use the lightweight CPU-only PyTorch wheel, run:
> ```powershell
> python -m pip install numpy networkx matplotlib pyarrow flask pytest
> python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
> ```

---

## 5. How to Run the Platform

### Option 1: Launch the Live Interactive Web Workbench (Recommended)

Start the local Flask server:

```powershell
python -m tgap ui
```

Then open **`http://127.0.0.1:5000`** in your browser.

- **Top Parameter Bar**: Select the **Dataset Source** (*DARPA TC E3 CADETS* or *Synthetic Multi-Stage APT*), **Loss Mechanism** (*Burst*, *Uniform*, *Sampling*, *Crash*), **Drop Rate** (`0%` to `50%`), and **Detection & Gap Engine** (*PyTorch Deep GNN* or *Statistical Noisy-OR*), then click **Run Analysis**.
- **Investigation Workbench Tab**: Browse reconstructed incident chains on the left **Vertical Provenance Trace Waterfall** and click any observed event (`E...`) or amber **Telemetry Gap Localized** card (`GAP-...`) to inspect its full system call metadata, confidence breakdown, and non-hallucination verification in the right-hand **Evidence & Gap Inspector**.
- **Benchmarks & RQ1-RQ3 Tab**: Inspect the model comparison table and empirical degradation plot.
- **Verified Claims Audit Tab**: Review all analytical findings verified by `ClaimsRegistry` with clickable evidence badges.

---

### Option 2: Run the Full Automated Pipeline via CLI

To run the complete experiment grid (`4 mechanisms x 4 loss rates`), train and evaluate both Statistical and PyTorch GNN models, and generate all reports and plots:

```powershell
python -m tgap all --config configs/default.json
```

*(For a fast single-seed run, add `--quick`: `python -m tgap all --quick`)*

#### Generated Artifacts in `results/`:
- [`results/investigation_report.html`](results/investigation_report.html) - Standalone interactive HTML workbench (double-click to open in any browser).
- [`results/investigation_report.json`](results/investigation_report.json) - Machine-readable JSON export of chains, localized gaps, and verified claims.
- [`results/degradation.png`](results/degradation.png) - High-resolution RQ1 degradation curves and RQ2/RQ3 benchmark chart.
- [`results/summary.md`](results/summary.md) - Markdown benchmark tables ready for reports and slides.
- [`results/metrics.csv`](results/metrics.csv) - Full experiment grid metrics in CSV format.

---

### Option 3: Run Individual CLI Subcommands

```powershell
# 1. Generate synthetic telemetry and ground-truth JSON
python -m tgap generate --config configs/default.json --out results/synthetic_sample.json

# 2. Run single-pass detection, correlation, gap localization, and HTML report
python -m tgap run --config configs/default.json

# 3. Run the multi-mechanism experiment grid and generate CSV/Markdown/PNG outputs
python -m tgap experiment --config configs/default.json
```

---

## 6. How to Run the Automated Test Suite

Run all **38 unit, integration, and AST isolation tests** with `pytest`:

```powershell
python -m pytest -v
```

You can also run specific verification suites individually:

```powershell
# Verify strict AST isolation (proves AblationManifest is never leaked to detectors/localizers)
python -m pytest tests/test_isolation.py -v

# Verify PyTorch Deep Learning models (Provenance GNN Autoencoder & Bilinear Link Predictor)
python -m pytest tests/test_deep_models.py -v

# Verify real DARPA TC E3 CADETS dataset loading & CDM-18 parsing
python -m pytest tests/test_cadets_loader.py tests/test_darpa_cdm.py -v

# Verify Statistical Noisy-OR gap localization & orphan-process detection
python -m pytest tests/test_gaps.py -v

# Verify ClaimsRegistry rejects unsupported/unbacked claims
python -m pytest tests/test_report.py -v
```

---

## 7. Empirical Evaluation Summary

### RQ2 & RQ3: Gap Localization Benchmark (`burst` loss, $p = 0.30$)

| Method | Gap Precision | Interior Gap Recall | All-Removal Recall | Interior F1 Score |
| :--- | :---: | :---: | :---: | :---: |
| **PyTorch GNN Link-Pred (Ours)** | **0.902** | 0.878 | 0.692 | **0.887** |
| **Statistical Noisy-OR (Ours)** | 0.626 | **1.000** | **0.769** | 0.747 |
| **Fixed-Threshold Heuristic** | 0.562 | 0.833 | 0.641 | 0.663 |
| **Random Baseline** | 0.300 | 0.361 | 0.282 | 0.327 |
| **Never-Predict Baseline** | 0.000 | 0.000 | 0.000 | 0.000 |
