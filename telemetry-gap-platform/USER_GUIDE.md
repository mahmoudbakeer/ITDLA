# Telemetry Gap Platform — Complete Project & User Guide

**Title:** Intelligent Threat Detection and Log Analysis Platform — Reasoning Over Incomplete Security Telemetry  
**Authors:** Mahmoud Bakir (2023855493) & Jaffar Jned (2023855498)  
**Mentor:** Dr. Deepthi P S — Dept. of Computer Science & Engineering, Sharda University  

---

## 1. What Is This Project? (The Core Idea)

### The Problem
Provenance-based Intrusion Detection Systems (PIDSes) analyze host system calls (processes spawning children, reading/writing files, opening network sockets) to detect multi-stage cyber attacks (APTs). However, **all existing PIDSes assume the telemetry they receive is 100% complete**.

In real-world enterprise deployments, telemetry is frequently lost due to:
1. **Burst drops** (audit buffer congestion during high I/O spikes)
2. **Uniform random drops** (UDP packet loss in log forwarding)
3. **Sampling / Decimation** (rate-limiting on busy hosts)
4. **Agent crashes** (endpoint sensor crash or service restart mid-attack)

When telemetry is lost, attack chains break into fragments, stages disappear, and security analysts are never told *where* evidence is missing.

### Our Solution & Novelty
This platform solves that problem in three ways:
1. **RQ1 — Degradation Characterization**: Quantifies how threat detection and attack-stage reconstruction degrade as telemetry loss increases from `10%` to `50%` across the 4 loss mechanisms.
2. **RQ2 — Statistical Gap Localization**: Introduces an interpretable statistical method combining empirical inter-event timing distributions ($s_{\text{time}}$) and structural continuity breaks ($s_{\text{struct}}$: orphan processes appearing without a recorded `process_create` event) via a calibrated Noisy-OR model:
   $$C(u, v) = 1 - (1 - s_{\text{time}}) \times (1 - w \cdot s_{\text{struct}})$$
3. **RQ3 — Deep Learning Gap Localization & Detection (PyTorch GNNs)**:
   - **PyTorch Provenance Graph Autoencoder (`DeepProvenanceDetector`)**: Learns normal graph topology on benign host logs to score anomalous events.
   - **PyTorch Bilinear GNN Link Predictor (`DeepGapLocalizer`)**: Learns topological and temporal embeddings of consecutive events $(u, v)$ to predict the probability that an intermediate evidence hop was dropped.
4. **Zero-Hallucination Guarantee & Strict Claims Registry**:
   - A `Gap` object strictly reports **where** evidence is missing $(u, v)$, **confidence** $C(u,v)$, and **observed signals** — it **never fabricates or guesses** what the dropped system call was.
   - Every analytical statement in the UI is validated by `ClaimsRegistry` against concrete evidence IDs (`E12`, `CDM_45`, etc.).

---

## 2. How the Project Works (Module-by-Module Architecture)

```
Raw Logs (DARPA TC E3 CADETS / Synthetic APT)
   │
   ▼
[1. Normalization] (tgap/normalize.py, tgap/darpa_cdm.py, tgap/cadets_loader.py)
   │  Parses raw logs into typed Entities (Process, File, Socket) & chronological Events
   ▼
[2. Loss-Injection Harness] (tgap/ablate.py)
   │  Drops attack chain events under {uniform, burst, sampling, crash} at rate r
   │  Quarantines dropped events inside AblationManifest (strictly hidden from downstream stages!)
   ▼
[3. Threat Detection] (tgap/detect.py & tgap/deep_detect.py)
   │  Scores events using Context-Aware Surprisal OR PyTorch Provenance GNN Autoencoder
   ▼
[4. Attack-Chain Correlation] (tgap/correlate.py)
   │  Builds NetworkX directed provenance graphs (nx.DiGraph) linking related anomalous events
   ▼
[5. Gap Localization] (tgap/gaps.py & tgap/deep_gaps.py)
   │  Flags consecutive chain pairs (u, v) where telemetry continuity is implausible
   ▼
[6. Evaluation & Interactive SOC Frontend] (tgap/evaluate.py, tgap/report.py, tgap/webapp.py)
      Computes Precision/Recall/F1 vs. Baselines & serves the live Web UI
```

### Key Files in `tgap/`
| File | Role |
|---|---|
| `tgap/config.py` | Configuration dataclass and SHA-256 deterministic seed derivation (`derive_seed`). |
| `tgap/schema.py` | Data structures: `Entity`, `Event`, `Telemetry`, `Chain`, `Gap`, and `Truth`. |
| `tgap/synthetic.py` | Deterministic generator producing benign user/service sessions + 5-stage APT attacks (`recon` $\to$ `exploit` $\to$ `priv_esc` $\to$ `staging` $\to$ `exfiltration`). |
| `tgap/darpa_cdm.py` | Parser for official DARPA Transparent Computing Common Data Model (CDM-18) Avro/JSON records. |
| `tgap/cadets_loader.py` | Loader for the downloaded **DARPA TC E3 CADETS** dataset (`data/cadets_e3/cadets_sample.parquet`, 50,000 real FreeBSD provenance records). |
| `tgap/normalize.py` | Converts raw records into validated `Telemetry`, skipping and counting malformed logs. |
| `tgap/detect.py` | `Detector` interface + `SurprisalDetector` (behavior, lineage, identity, and target rarity). |
| `tgap/deep_detect.py` | `DeepProvenanceDetector`: PyTorch Graph Autoencoder neural network for anomaly detection. |
| `tgap/correlate.py` | Links anomalous events via PID, parent-child fork (`ppid == pid`), shared lineage, and shared targets into `Chain` graphs. |
| `tgap/ablate.py` | Controlled loss-injection harness (`uniform`, `burst`, `sampling`, `crash`) + quarantined `AblationManifest`. |
| `tgap/gaps.py` | `StatisticalGapLocalizer`: Empirical timing ECDF ($s_{\text{time}}$) + orphan-process continuity break ($s_{\text{struct}}$) combined via Noisy-OR. |
| `tgap/deep_gaps.py` | `DeepGapLocalizer`: PyTorch Bilinear Neural Network predicting missing link probability between $(u, v)$. |
| `tgap/evaluate.py` | Computes RQ1 degradation metrics and RQ2/RQ3 gap localization Precision, Interior Recall, All Recall, and F1 against `Fixed-Threshold`, `Random`, and `Never-Predict` baselines. |
| `tgap/report.py` | Enforces `ClaimsRegistry` (rejects unbacked claims) and builds the standalone HTML/JSON dashboard. |
| `tgap/webapp.py` | **Live Interactive Flask Web Frontend** allowing real-time parameter tuning and inspection in the browser. |

---

## 3. How to Run & Interact With the Platform on Your Computer

Open **PowerShell** or **Command Prompt** in the project folder:
```powershell
cd C:\Users\mahmo\dir\Capstone\telemetry-gap-platform
```

### Mode A: Launch the Live Interactive Web Frontend (Recommended!)
Run this command to start the interactive web application on your computer:
```powershell
python -m tgap ui
```
Then open your web browser (Chrome / Edge / Firefox) and go to:
👉 **`http://127.0.0.1:5000`**

#### How to Interact with the Web Frontend:
1. **Top Interactive Control Panel**:
   - **Dataset Source**: Switch between **Synthetic Multi-Stage APT** and **DARPA TC E3 (CADETS)**.
   - **Loss Mechanism (RQ1)**: Switch between **Burst (Buffer Overflow)**, **Uniform (Random Drops)**, **Sampling (Rate Decimation)**, and **Crash (Agent Failure)**.
   - **Telemetry Loss Rate**: Choose `0% (Complete Data)`, `10%`, `20%`, `30%`, or `50%` loss.
   - **Intrusion Detector (FR2)**: Switch between **Context-Aware Surprisal** and **PyTorch Provenance GNN**.
   - **Structural Weight ($w$)** & **Random Seed**: Adjust the Noisy-OR weight or seed.
   - Click **"🚀 Run Live Analysis"** — the platform re-runs ablation, detection, correlation, PyTorch GNN & Statistical gap localization in real time and updates the entire dashboard!
2. **Interactive Attack Chain & Gap Graph**:
   - Scroll horizontally across each reconstructed attack chain.
   - **Solid Cards**: Observed system call events (`E8`, `E22`, etc.) with PID, user, target, and anomaly score.
   - **Dashed Amber Warning Cards (`⚡ TELEMETRY GAP LOCALIZED`)**: Placed at the exact hop where telemetry was lost, showing both the **Stat Noisy-OR** and **PyTorch GNN** confidence percentages and whether an **Orphan Process Break** was detected.
3. **Click-to-Inspect Evidence**:
   - **Click any Event Card** in the graph or **any blue Evidence Badge** in the Claims Registry table — the page highlights that event and smoothly scrolls the **Concrete Host Evidence Inspector** table at the bottom to the exact raw audit record!

---

### Mode B: Run the Full Batch Experiment Grid (CLI)
To run the full multi-seed scientific experiment grid (`4 mechanisms x 4 loss rates x 5 seeds = 80 runs`) and regenerate all tables, plots, and static reports:
```powershell
python -m tgap all --config configs/default.json
```
*(Tip: Add `--quick` for a fast 5-second run: `python -m tgap all --quick`)*

This generates 5 files in the `results/` folder:
1. `results/investigation_report.html` — Standalone interactive HTML dashboard (can be opened directly by double-clicking it, even without the web server running).
2. `results/degradation.png` — High-resolution 2-panel chart showing (Left) RQ1 Attack Stage Recovery vs. Loss Rate, and (Right) RQ2/RQ3 Gap Localization Precision/Recall/F1 across all 5 methods.
3. `results/summary.md` — Clean Markdown tables ready to copy into your report or presentation slides.
4. `results/metrics.csv` — Raw per-run CSV data across all seeds, mechanisms, and loss rates.
5. `results/investigation_report.json` — Machine-readable JSON of chains, localized gaps, and verified claims.

---

## 4. How to Test the Project on Your Computer

We have built a comprehensive **38-test automated verification suite** using `pytest`.

### 1. Run All 38 Tests at Once
```powershell
python -m pytest -v
```
You will see all 38 tests pass in ~7 seconds.

### 2. Run Specific Test Suites Individually (Great for Live Demonstrations to Evaluators)

* **Test Strict Data Isolation (Proves the Ablation Manifest is never leaked to the detector or gap localizer):**
  ```powershell
  python -m pytest tests/test_isolation.py -v
  ```
* **Test PyTorch Deep Learning Models (GNN Intrusion Detector & Bilinear Link Predictor):**
  ```powershell
  python -m pytest tests/test_deep_models.py -v
  ```
* **Test Real DARPA TC E3 CADETS Dataset Loading:**
  ```powershell
  python -m pytest tests/test_cadets_loader.py tests/test_darpa_cdm.py -v
  ```
* **Test Statistical Gap Localization & Orphan Process Detection:**
  ```powershell
  python -m pytest tests/test_gaps.py -v
  ```
* **Test Claims Registry (Proves unsupported/hallucinated claims are rejected):**
  ```powershell
  python -m pytest tests/test_report.py -v
  ```
* **Test Live Interactive Web Frontend:**
  ```powershell
  python -m pytest tests/test_webapp.py -v
  ```
* **Test End-to-End Deterministic Reproducibility (Same seed = identical CSV output):**
  ```powershell
  python -m pytest tests/test_pipeline.py -v
  ```
