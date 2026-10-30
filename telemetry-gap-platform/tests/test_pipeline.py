"""End-to-end integration and reproducibility tests for pipeline (Phase 7)."""

from pathlib import Path
from tgap.config import Config
from tgap.pipeline import run_full_pipeline


def test_end_to_end_pipeline_reproducibility(tmp_path: Path):
    cfg = Config(
        synthetic_benign_sessions=8,
        synthetic_attacks=2,
        mechanisms=["uniform", "burst"],
        rates=[0.2, 0.4],
        seeds=[1],
        base_seed=42,
    )

    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"

    res1 = run_full_pipeline(cfg, output_dir=out1, quick_mode=True)
    res2 = run_full_pipeline(cfg, output_dir=out2, quick_mode=True)

    # Verify all artifacts created
    assert Path(res1["metrics_csv"]).exists()
    assert Path(res1["summary_md"]).exists()
    assert Path(res1["degradation_png"]).exists()
    assert Path(res1["report_html"]).exists()
    assert Path(res1["report_json"]).exists()

    # Verify CSV determinism across identical seed runs
    csv1 = Path(res1["metrics_csv"]).read_text(encoding="utf-8")
    csv2 = Path(res2["metrics_csv"]).read_text(encoding="utf-8")
    assert csv1 == csv2
