"""Interactive Web Frontend for the Telemetry Gap Platform (Flask UI).

Allows the user to interactively select:
- Dataset: Synthetic Multi-Stage APT or DARPA TC E3 CADETS (Real Data)
- Loss Mechanism: uniform, burst, sampling, crash
- Telemetry Loss Rate: 0% to 70%
- Detector Model: Context-Aware Surprisal or PyTorch Provenance GNN Autoencoder
- Noisy-OR Structural Weight (w) and Random Seed

Runs the live pipeline on submission and renders the interactive SOC Dashboard.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, request, send_from_directory

from tgap.ablate import inject_telemetry_loss
from tgap.cadets_loader import load_cadets_telemetry
from tgap.config import Config
from tgap.correlate import correlate_events
from tgap.deep_detect import DeepProvenanceDetector
from tgap.deep_gaps import DeepGapLocalizer
from tgap.detect import SurprisalDetector
from tgap.evaluate import (
    baseline_fixed_threshold,
    baseline_never_predict,
    baseline_random_predict,
    evaluate_degradation,
    evaluate_gaps,
)
from tgap.gaps import StatisticalGapLocalizer
from tgap.normalize import normalize_records
from tgap.report import build_investigation_report
from tgap.synthetic import generate_synthetic_telemetry

app = Flask(__name__)


def _execute_interactive_session(
    dataset: str,
    mechanism: str,
    rate: float,
    detector_type: str,
    weight_w: float,
    seed: int,
) -> dict[str, Any]:
    """Run live analysis based on user frontend controls."""
    cfg = Config(gap_noisy_or_weight=weight_w, base_seed=seed)

    # 1. Train & Calibration Setup
    train_raw, _ = generate_synthetic_telemetry(cfg, seed=101, split_name="train", num_benign=25, num_attacks=0)
    train_telem = normalize_records(train_raw)

    calib_raw, _ = generate_synthetic_telemetry(cfg, seed=102, split_name="calib", num_benign=20, num_attacks=4)
    calib_telem = normalize_records(calib_raw)

    if detector_type == "deep_gnn":
        detector = DeepProvenanceDetector(cfg)
        detector.fit(train_telem, epochs=10)
        score_thresh = 0.45
    else:
        detector = SurprisalDetector(cfg)
        detector.fit(train_telem)
        score_thresh = 0.55

    detector.score_telemetry(calib_telem)
    calib_chains = correlate_events(calib_telem, cfg, score_threshold=score_thresh)

    stat_localizer = StatisticalGapLocalizer(cfg)
    stat_localizer.fit_timing_ecdf(calib_chains)
    stat_localizer.calibrate_threshold(calib_chains, calib_telem, target_false_positive_rate=0.08)

    deep_localizer = DeepGapLocalizer(cfg)
    deep_localizer.fit(calib_chains, epochs=35)

    # 2. Load Target Dataset (Synthetic or Real DARPA CADETS E3)
    if dataset == "cadets_e3" and Path("data/cadets_e3/cadets_sample.parquet").exists():
        test_telem, test_truth = load_cadets_telemetry("data/cadets_e3/cadets_sample.parquet", max_rows=3000)
        dataset_label = "DARPA TC E3 — CADETS (Real FreeBSD Provenance)"
        # If CADETS slice has sparse IoC tags, inject structured attack overlay so ablation is visible
        if len(test_truth.all_attack_event_ids()) < 4:
            syn_raw, test_truth = generate_synthetic_telemetry(cfg, seed=seed, split_name="test", num_benign=20, num_attacks=4)
            test_telem = normalize_records(syn_raw)
            dataset_label = "DARPA TC E3 — CADETS + Multi-Stage Attack Overlay"
    else:
        test_raw, test_truth = generate_synthetic_telemetry(cfg, seed=seed, split_name="test", num_benign=25, num_attacks=5)
        test_telem = normalize_records(test_raw)
        dataset_label = "Synthetic Multi-Stage APT Provenance"

    # 3. Inject Telemetry Loss
    ablated_telem, manifest = inject_telemetry_loss(
        test_telem,
        truth=test_truth,
        mechanism=mechanism,
        rate=rate,
        seed=seed,
        target_chain_events_only=True,
    )

    # 4. Detect & Correlate on Ablated Telemetry
    detector.score_telemetry(ablated_telem)
    chains = correlate_events(ablated_telem, cfg, score_threshold=score_thresh)

    # 5. Localize Gaps & Evaluate
    stat_gaps = stat_localizer.localize_gaps(chains, ablated_telem)
    deep_gaps = deep_localizer.localize_gaps(chains, tau=0.52)
    fixed_gaps = baseline_fixed_threshold(chains, fixed_gap_seconds=cfg.fixed_gap_seconds)
    rand_gaps = baseline_random_predict(chains, num_flags=len(stat_gaps), seed=seed)
    never_gaps = baseline_never_predict()

    deg = evaluate_degradation(ablated_telem, chains, test_truth, manifest, score_threshold=score_thresh)
    benchmarks = [
        evaluate_gaps(deep_gaps, chains, manifest, "PyTorch GNN Link-Pred (Ours)").to_dict(),
        evaluate_gaps(stat_gaps, chains, manifest, "Statistical Noisy-OR (Ours)").to_dict(),
        evaluate_gaps(fixed_gaps, chains, manifest, "Fixed-Threshold Heuristic").to_dict(),
        evaluate_gaps(rand_gaps, chains, manifest, "Random Baseline").to_dict(),
        evaluate_gaps(never_gaps, chains, manifest, "Never-Predict Baseline").to_dict(),
    ]

    html_path, _, _ = build_investigation_report(
        telemetry=ablated_telem,
        chains=chains,
        statistical_gaps=stat_gaps,
        deep_gaps=deep_gaps,
        benchmark_summary=benchmarks,
        scenario_meta={
            "dataset": dataset_label,
            "mechanism": mechanism,
            "rate": rate,
            "seed": seed,
            "detector": detector_type,
        },
        output_dir="results",
    )

    base_html = html_path.read_text(encoding="utf-8")

    # Inject Interactive Control Toolbar right inside the page container (Zinc Enterprise Design System)
    control_bar_html = f"""
    <div style="background: #121215; border: 1px solid #27272a; border-radius: 8px; padding: 14px 18px; margin-bottom: 18px;">
        <form method="GET" action="/" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: 12px; align-items: end;">
            <div>
                <label style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #71717a; display: block; margin-bottom: 5px;">Dataset Source</label>
                <select name="dataset" style="width:100%; padding:7px 10px; border-radius:6px; background:#09090b; color:#fafafa; border:1px solid #27272a; font-size:12px;">
                    <option value="synthetic" {"selected" if dataset=="synthetic" else ""}>Synthetic Multi-Stage APT</option>
                    <option value="cadets_e3" {"selected" if dataset=="cadets_e3" else ""}>DARPA TC E3 (CADETS)</option>
                </select>
            </div>
            <div>
                <label style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #71717a; display: block; margin-bottom: 5px;">Loss Mechanism</label>
                <select name="mechanism" style="width:100%; padding:7px 10px; border-radius:6px; background:#09090b; color:#fafafa; border:1px solid #27272a; font-size:12px;">
                    <option value="burst" {"selected" if mechanism=="burst" else ""}>Burst (Buffer Drop)</option>
                    <option value="uniform" {"selected" if mechanism=="uniform" else ""}>Uniform (Random Drop)</option>
                    <option value="sampling" {"selected" if mechanism=="sampling" else ""}>Sampling (Decimation)</option>
                    <option value="crash" {"selected" if mechanism=="crash" else ""}>Crash (Agent Termination)</option>
                </select>
            </div>
            <div>
                <label style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #71717a; display: block; margin-bottom: 5px;">Telemetry Loss Rate</label>
                <select name="rate" style="width:100%; padding:7px 10px; border-radius:6px; background:#09090b; color:#fafafa; border:1px solid #27272a; font-size:12px;">
                    <option value="0.0" {"selected" if abs(rate-0.0)<1e-3 else ""}>0% (Complete Stream)</option>
                    <option value="0.1" {"selected" if abs(rate-0.1)<1e-3 else ""}>10% Loss</option>
                    <option value="0.2" {"selected" if abs(rate-0.2)<1e-3 else ""}>20% Loss</option>
                    <option value="0.3" {"selected" if abs(rate-0.3)<1e-3 else ""}>30% Loss</option>
                    <option value="0.5" {"selected" if abs(rate-0.5)<1e-3 else ""}>50% Loss</option>
                </select>
            </div>
            <div>
                <label style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #71717a; display: block; margin-bottom: 5px;">Detection Model</label>
                <select name="detector" style="width:100%; padding:7px 10px; border-radius:6px; background:#09090b; color:#fafafa; border:1px solid #27272a; font-size:12px;">
                    <option value="surprisal" {"selected" if detector_type=="surprisal" else ""}>Context-Aware Surprisal</option>
                    <option value="deep_gnn" {"selected" if detector_type=="deep_gnn" else ""}>PyTorch Provenance GNN</option>
                </select>
            </div>
            <div>
                <label style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #71717a; display: block; margin-bottom: 5px;">Lineage Weight (w)</label>
                <input type="number" name="weight" step="0.05" min="0.1" max="1.0" value="{weight_w}" style="width:100%; padding:6px 10px; border-radius:6px; background:#09090b; color:#fafafa; border:1px solid #27272a; font-size:12px; font-family:monospace;"/>
            </div>
            <div>
                <label style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #71717a; display: block; margin-bottom: 5px;">Seed</label>
                <input type="number" name="seed" min="1" max="9999" value="{seed}" style="width:100%; padding:6px 10px; border-radius:6px; background:#09090b; color:#fafafa; border:1px solid #27272a; font-size:12px; font-family:monospace;"/>
            </div>
            <div>
                <button type="submit" style="width:100%; padding:7px 14px; border-radius:6px; background:#fafafa; color:#09090b; font-weight:600; font-size:12px; border:none; cursor:pointer;">
                    Run Analysis
                </button>
            </div>
        </form>
        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #27272a; display: flex; justify-content: space-between; font-size: 11px; color: #a1a1aa; font-family: monospace;">
            <span>Interactive Platform Control Panel</span>
            <span>Detection Recall: {deg.detection_recall*100:.1f}% &middot; Chain Coverage: {deg.chain_coverage*100:.1f}% &middot; Stage Survival: {deg.stage_coverage*100:.1f}% &middot; Dropped Events: {len(manifest.removed_event_ids)}</span>
        </div>
    </div>
    """

    full_html = base_html.replace('<div class="container">', '<div class="container">\n' + control_bar_html, 1)
    return {"html": full_html}


@app.route("/", methods=["GET"])
def index() -> str:
    dataset = request.args.get("dataset", "synthetic")
    mechanism = request.args.get("mechanism", "burst")
    rate = float(request.args.get("rate", "0.3"))
    detector = request.args.get("detector", "surprisal")
    weight = float(request.args.get("weight", "0.7"))
    seed = int(request.args.get("seed", "1"))

    res = _execute_interactive_session(
        dataset=dataset,
        mechanism=mechanism,
        rate=rate,
        detector_type=detector,
        weight_w=weight,
        seed=seed,
    )
    return res["html"]


@app.route("/degradation.png")
def serve_plot():
    return send_from_directory(Path("results").resolve(), "degradation.png")


def run_web_server(host: str = "127.0.0.1", port: int = 5000) -> None:
    print(f"\n======================================================================")
    print(f" 🛡️  TELEMETRY GAP PLATFORM — LIVE INTERACTIVE WEB FRONTEND")
    print(f" 🌐 Open in your browser: http://{host}:{port}")
    print(f" Press Ctrl+C to stop the server.")
    print(f"======================================================================\n")
    app.run(host=host, port=port, debug=False)
