# Telemetry Gap Platform (`tgap`)

**Intelligent Threat Detection and Log Analysis Platform — Reasoning Over Incomplete Security Telemetry**  
*B.Tech Final-Year Capstone Project*  
**Authors:** Mahmoud Bakir (`2023855493`) & Jaffar Jned (`2023855498`)  
**Mentor:** Dr. Deepthi P S — *Sharda University*

---

## 1. Project Summary

### The Problem
Provenance-based Intrusion Detection Systems (PIDS) reconstruct multi-stage cyber attacks by connecting host system events (process spawns, file reads/writes, network connections, privilege escalations) into a causal provenance graph. However, existing PIDS assume **100% complete telemetry**. In real enterprise networks, host audit logs regularly suffer from **telemetry loss** caused by kernel ring-buffer overflows (`burst`), endpoint agent crashes (`crash`), rate-limiting (`sampling`), or random packet drops (`uniform`). When key intermediate events are dropped, attack chains break into disconnected fragments and analysts lose visibility into how an attacker moved laterally.

### What This Platform Does
The **Telemetry Gap Platform (`tgap`)** is an end-to-end threat detection, telemetry ablation, and evidence-backed **gap-localization** platform. Instead of hallucinating or guessing missing log payloads, the platform:

1. **Ingests & Normalizes Provenance Logs (`FR1`)**: Supports both multi-stage synthetic APT scenarios and real-world **DARPA Transparent Computing Engagement 3 (CADETS)** FreeBSD provenance telemetry (`50,000` CDM-18 records included in `data/cadets_e3/cadets_sample.parquet`).
2. **Detects Anomalous Host Activity (`FR2`)**: Implements two interchangeable threat detectors behind a unified `Detector` interface:
   - **Statistical Context-Aware Surprisal Detector** (`tgap/detect.py`): Scores events using information-theoretic rarity ($-\log_2 P$) across behavior, parent-child lineage, user identity, and resource sensitivity.
   - **Deep Learning Provenance Graph Autoencoder (GNN)** (`tgap/deep_detect.py`): A PyTorch message-passing Graph Neural Network trained on benign provenance graphs to flag structurally anomalous subgraphs.
3. **Correlates Multi-Stage Attack Chains (`FR3`)**: Links high-scoring events across shared process IDs, parent-child forks, files, and temporal windows into directed `NetworkX` causal graphs (`tgap/correlate.py`).
4. **Simulates Controlled Telemetry Loss (`FR4` / `RQ1`)**: Removes events under four realistic failure modes (`uniform`, `burst`, `sampling`, `crash`) at configurable drop rates (`10%`, `20%`, `30%`, `50%`). Ground-truth dropped event IDs are quarantined inside an isolated `AblationManifest` (`tgap/ablate.py`) that is **never** accessible to the detector, correlator, gap localizer, or report generator (enforced by static AST analysis).
5. **Localizes Missing Telemetry Gaps (`FR5` / `RQ2` / `RQ3`)**: Identifies *where* evidence is missing between consecutive observed chain events $(u, v)$ and outputs a bounded confidence score $C(u, v) \in [0, 1]$ without fabricating missing event contents:
   - **Statistical Noisy-OR Localizer** (`tgap/gaps.py`): Combines an empirical inter-event timing CDF score ($s_{\text{time}}$) with a structural orphan-process lineage break signal ($s_{\text{struct}}$) via calibrated Noisy-OR fusion:
     $$C(u, v) = 1 - (1 - s_{\text{time}}(u, v)) \cdot (1 - w \cdot s_{\text{struct}}(u, v))$$
   - **PyTorch Bilinear GNN Link Predictor** (`tgap/deep_gaps.py`): A dual-tower neural link-prediction model that learns latent event representations and temporal transitions to predict missing provenance links.
6. **Enforces 100% Evidence-Backed Reporting & Interactive Workbench (`FR6`)**:
   - **Strict Claims Registry** (`tgap/report.py`): Rejects any analytical finding (`UnsupportedClaimError`) that does not cite concrete observed event IDs (`E...`) or localized gap IDs (`GAP-...`).
   - **Enterprise Investigation Workbench**: Provides both a standalone HTML investigation report (`results/investigation_report.html`) and a live interactive Flask web application (`python -m tgap ui`).

---

## 2. System Requirements & Dependencies

### Prerequisites
- **Operating System:** Windows 10/11, macOS, or Linux
- **Python Version:** Python **3.10 or newer** (tested on Python 3.13)
- **RAM / Disk:** Minimum 4 GB RAM and ~500 MB free disk space (runs entirely on CPU; no dedicated GPU required)

### Required Python Dependencies
All dependencies are listed in [`requirements.txt`](file:///c:/Users/mahmo/dir/Capstone/telemetry-gap-platform/requirements.txt):

| Package | Version | Purpose in the Platform |
|---|---|---|
| `numpy` | `>=1.24.0` | Empirical CDF calculation, vector math, and statistical threshold calibration |
| `networkx` | `>=3.0` | Directed provenance graph (`nx.DiGraph`) construction and connected-component chain extraction |
| `matplotlib` | `>=3.7.0` | High-resolution RQ1 degradation curves and RQ2/RQ3 benchmark charts (`results/degradation.png`) |
| `torch` | `>=2.0.0` | Deep Learning Provenance GNN Autoencoder (`deep_detect.py`) and Bilinear GNN Link Predictor (`deep_gaps.py`) |
| `pyarrow` | `>=12.0.0` | High-speed columnar reader for the real DARPA TC E3 CADETS Parquet dataset (`data/cadets_e3/cadets_sample.parquet`) |
| `flask` | `>=2.3.0` | Local web server powering the live interactive SOC Investigation Workbench (`tgap/webapp.py`) |
| `pytest` | `>=7.0.0` | Automated unit, integration, and AST ground-truth isolation test suite (`tests/`) |

---

## 3. Step-by-Step Installation Guide

Follow these steps to install and set up the project on any machine:

### Step 1: Open a Terminal in the Project Folder
Open **PowerShell** (Windows) or **Terminal** (macOS/Linux) and navigate to the project directory:
```powershell
cd c:\Users\mahmo\dir\Capstone\telemetry-gap-platform
```

### Step 2: (Optional but Recommended) Create a Virtual Environment
Creating a virtual environment keeps project dependencies isolated from your global Python installation:

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**On macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install All Dependencies
You can install all required packages in one command using `requirements.txt`:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

*(Note: If you want to install the smaller CPU-only version of PyTorch explicitly on Windows/Linux, you can also run:)*
```powershell
python -m pip install numpy networkx matplotlib pyarrow flask pytest
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
```

### Step 4: Verify the Installation
Run the automated test suite to verify that all dependencies, deep learning models, dataset loaders, and security isolation checks are working properly:
```powershell
python -m pytest -v
```
You should see **`38 passed`** in ~7 seconds.

---

## 4. How to Run the Platform

You can use the platform in **three ways**: via the **Live Interactive Web Application**, the **Automated End-to-End CLI Pipeline**, or **Individual Modular CLI Commands**.

---

### Mode A: Live Interactive Web Application (Recommended for Demos)
Launch the local Flask web server to interact with the platform in your browser:

```powershell
python -m tgap ui
```
*(Optional: specify a custom port with `python -m tgap ui --port 8080`)*

1. Open your browser and go to: **`http://127.0.0.1:5000`**
2. Use the top control bar to configure and run experiments in real time:
   - **Dataset Source**: Switch between *DARPA TC E3 (CADETS Real Logs)* and *Synthetic Multi-Stage APT*.
   - **Loss Mechanism**: Choose *Burst Overflow*, *Uniform Random Drop*, *Systematic Sampling*, or *Agent Crash Truncation*.
   - **Drop Rate ($p$)**: Select `0%`, `10%`, `20%`, `30%`, or `50%` telemetry loss.
   - **Detection & Gap Engine**: Switch between **PyTorch Deep GNN (Autoencoder + Link Pred)** and **Statistical (Surprisal + Noisy-OR)**.
   - **Orphan Weight ($w$) & Seed**: Adjust structural confidence weight and random seed, then click **Run Analysis**.
3. Explore the **3 Workspace Views** using the top tab switcher:
   - **Investigation Workbench**: Inspect reconstructed incident chains on the left **Vertical Provenance Trace Waterfall** and click any observed event (`E...`) or amber **Telemetry Gap Localized** card (`GAP-...`) to inspect its full metadata, timing delta $\Delta t$, score breakdown, and non-hallucination audit status in the sticky right-hand **Evidence & Gap Inspector**.
   - **Benchmarks & RQ1–RQ3**: View the empirical benchmark comparison table and degradation chart.
   - **Verified Claims Audit**: Inspect every analytical finding registered in the `ClaimsRegistry` along with its clickable supporting evidence badges.

---

### Mode B: Full End-to-End Automated Pipeline (CLI)
To run the complete training, calibration, 16-condition degradation experiment grid (`4 mechanisms × 4 rates`), statistical vs. PyTorch GNN benchmark comparison, plot generation, and standalone HTML report build in one command:

```powershell
python -m tgap all --config configs/default.json
```

This command populates the `results/` folder with:
- **`results/investigation_report.html`** — Standalone interactive SOC Investigation Workbench (double-click to open in any browser without needing a server).
- **`results/investigation_report.json`** — Machine-readable JSON export of all chains, localized gaps, and verified claims.
- **`results/degradation.png`** — High-resolution chart showing RQ1 stage coverage degradation and RQ2/RQ3 Precision/Recall/F1 benchmarks.
- **`results/summary.md`** — Formatted Markdown tables ready for your project report or presentation slides.
- **`results/metrics.csv`** — Raw CSV metrics across all mechanisms, drop rates, and baseline comparisons.

---

### Mode C: Individual CLI Subcommands
You can also run individual stages of the pipeline via `python -m tgap <subcommand>`:

1. **Generate Synthetic Telemetry Only:**
   ```powershell
   python -m tgap generate --config configs/default.json --out results/synthetic_preview.json
   ```
2. **Run Single-Pass Detection & Gap Localization Report:**
   ```powershell
   python -m tgap run --config configs/default.json
   ```
3. **Run Full Experiment Grid & Benchmark Evaluation:**
   ```powershell
   python -m tgap experiment --config configs/default.json
   ```

---

## 5. Project Structure

```text
telemetry-gap-platform/
├── configs/
│   └── default.json                 # Default hyperparameters, loss rates, and experiment settings
├── data/
│   └── cadets_e3/
│       └── cadets_sample.parquet    # Real DARPA TC E3 (CADETS) dataset shard (50,000 CDM-18 records)
├── docs/
│   ├── PROJECT_CONTEXT.md           # Research architecture, mathematical formulation, and design rules
│   └── TODO.md                      # Phase-by-phase engineering checklist (Phases 0–9)
├── results/                         # Generated reports, plots, CSV metrics, and JSON audits
│   ├── investigation_report.html    # Standalone interactive SOC Investigation Workbench
│   ├── investigation_report.json    # Machine-readable verified claims & evidence export
│   ├── degradation.png              # RQ1 degradation & RQ2/RQ3 model comparison plots
│   ├── summary.md                   # Markdown benchmark summary tables
│   └── metrics.csv                  # Full experimental evaluation grid
├── tests/                           # 38 automated unit, integration, and AST isolation tests
│   ├── test_ablate.py               # Telemetry loss mechanisms & reproducibility tests
│   ├── test_cadets_loader.py        # Real DARPA TC E3 CADETS loader tests
│   ├── test_correlate.py            # Provenance graph correlation tests
│   ├── test_darpa_cdm.py            # CDM-18 JSON parser tests
│   ├── test_deep_models.py          # PyTorch GNN detector & Bilinear Link Predictor tests
│   ├── test_detect.py               # Context-aware surprisal detector tests
│   ├── test_evaluate.py             # RQ1–RQ3 evaluation metric & baseline tests
│   ├── test_gaps.py                 # Statistical Noisy-OR gap localization tests
│   ├── test_isolation.py            # AST check ensuring AblationManifest is never leaked
│   ├── test_normalize.py            # Schema normalization & malformed record handling tests
│   ├── test_pipeline.py             # End-to-end deterministic reproducibility test
│   ├── test_report.py               # ClaimsRegistry UnsupportedClaimError & HTML report tests
│   ├── test_synthetic.py            # Seeded multi-stage APT generator tests
│   └── test_webapp.py               # Interactive Flask UI route & parameter tests
├── tgap/                            # Core Python package
│   ├── __init__.py
│   ├── __main__.py                  # Entry point for `python -m tgap`
│   ├── config.py                    # Configuration dataclass & cryptographic seed derivation
│   ├── schema.py                    # Core dataclasses: Entity, Event, Telemetry, Chain, Gap, Truth
│   ├── synthetic.py                 # Deterministic benign & multi-stage APT log generator
│   ├── normalize.py                 # Raw dictionary -> sorted Telemetry normalizer
│   ├── darpa_cdm.py                 # DARPA CDM-18 record parser
│   ├── cadets_loader.py             # DARPA TC E3 CADETS Parquet loader & ground-truth builder
│   ├── detect.py                    # Statistical SurprisalDetector implementation
│   ├── deep_detect.py               # PyTorch Provenance Graph Autoencoder (GNN) detector
│   ├── correlate.py                 # NetworkX causal provenance chain correlator
│   ├── ablate.py                    # Controlled loss injection (uniform, burst, sampling, crash)
│   ├── gaps.py                      # Statistical Noisy-OR gap localizer (s_time + s_struct)
│   ├── deep_gaps.py                 # PyTorch Bilinear GNN Link Predictor for gap localization
│   ├── evaluate.py                  # RQ1 degradation & RQ2/RQ3 gap localization evaluator
│   ├── pipeline.py                  # End-to-end experimental orchestrator & chart generator
│   ├── report.py                    # ClaimsRegistry & Enterprise SOC HTML Workbench generator
│   ├── webapp.py                    # Live interactive Flask web server (`python -m tgap ui`)
│   └── cli.py                       # Command-line interface parser
├── requirements.txt                 # Python package dependencies
├── USER_GUIDE.md                    # Detailed walkthrough & testing guide
└── README.md                        # Project overview, setup, and execution instructions
```

---

## 6. Key Experimental Results Summary

| Model / Method | Gap Precision | Interior Gap Recall | All-Removal Recall | Interior F1 Score |
| :--- | :---: | :---: | :---: | :---: |
| **PyTorch GNN Link-Pred (Ours)** | **0.902** | 0.878 | 0.692 | **0.887** |
| **Statistical Noisy-OR (Ours)** | 0.626 | **1.000** | **0.769** | 0.747 |
| **Fixed-Threshold Heuristic** | 0.562 | 0.833 | 0.641 | 0.663 |
| **Random Baseline** | 0.300 | 0.361 | 0.282 | 0.327 |
| **Never-Predict Baseline** | 0.000 | 0.000 | 0.000 | 0.000 |
#   I T D L A  
 