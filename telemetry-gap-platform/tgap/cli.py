"""Command-line interface for the Telemetry Gap Platform."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tgap.config import load_config
from tgap.pipeline import run_full_pipeline
from tgap.synthetic import generate_synthetic_telemetry


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tgap",
        description="Intelligent Threat Detection & Log Analysis Platform — Reasoning Over Incomplete Security Telemetry",
    )
    parser.add_argument(
        "command",
        choices=["generate", "run", "experiment", "all", "ui", "serve"],
        help="Execution stage to run ('ui' launches the interactive web frontend; 'all' runs full batch pipeline).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port for the interactive web UI (default: 5000).",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/default.json",
        help="Path to JSON configuration file.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results",
        help="Directory for generated artifacts and reports.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run a faster experiment grid for quick verification.",
    )

    args = parser.parse_args(argv)
    cfg = load_config(args.config if Path(args.config).exists() else None)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.command == "generate":
        records, truth = generate_synthetic_telemetry(cfg)
        out_file = out_dir / "synthetic_sample.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({"records_count": len(records), "sample": records[:20]}, f, indent=2)
        print(f"[tgap] Generated {len(records)} synthetic records -> {out_file}")
        return 0

    if args.command in ("ui", "serve"):
        from tgap.webapp import run_web_server
        run_web_server(port=args.port)
        return 0

    if args.command in ("run", "experiment", "all"):
        print("[tgap] Running end-to-end evaluation & gap localization pipeline...")
        result = run_full_pipeline(cfg, output_dir=out_dir, quick_mode=args.quick)
        print(f"[tgap] Metrics CSV:       {result['metrics_csv']}")
        print(f"[tgap] Summary Markdown:  {result['summary_md']}")
        print(f"[tgap] Degradation Plot:  {result['degradation_png']}")
        print(f"[tgap] SOC HTML Report:   {result['report_html']}")
        print(f"[tgap] Verified Claims:   {result['num_verified_claims']} (0 unsupported)")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
