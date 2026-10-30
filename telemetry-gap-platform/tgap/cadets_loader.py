"""DARPA Transparent Computing CADETS E3 dataset loader and ground-truth annotator."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional, Union

import pandas as pd

from tgap.darpa_cdm import parse_cdm_records
from tgap.normalize import normalize_records
from tgap.schema import Telemetry, Truth


# Known Red-Team Indicators of Compromise (IoCs) in DARPA TC E3 CADETS
CADETS_ATTACK_IPS = {
    "61.167.39.128",
    "78.205.235.65",
    "139.162.247.168",
    "200.72.41.130",
}
CADETS_ATTACK_TARGET_STRINGS = (
    "/tmp/",
    "/etc/passwd",
    "/var/log",
    "sh",
    "nginx",
)


def load_cadets_telemetry(
    parquet_path: Union[str, Path] = "data/cadets_e3/cadets_sample.parquet",
    max_rows: Optional[int] = 10000,
) -> tuple[Telemetry, Truth]:
    """Load CADETS E3 parquet shard into normalized Telemetry and isolated Truth.

    Args:
        parquet_path: Path to the downloaded CADETS E3 parquet file.
        max_rows: Maximum records to read (None for all).

    Returns:
        (telemetry, truth): Normalized telemetry and isolated ground-truth attack chains.
    """
    path = Path(parquet_path)
    if not path.exists():
        raise FileNotFoundError(f"CADETS dataset not found at: {path}")

    df = pd.read_parquet(path)
    if max_rows is not None and len(df) > max_rows:
        df = df.iloc[:max_rows]

    # Parse CDM string representations
    items = []
    for d_str in df["datum"]:
        try:
            items.append(ast.literal_eval(d_str))
        except (ValueError, SyntaxError):
            pass

    raw_records = parse_cdm_records(items)
    telemetry = normalize_records(raw_records)

    # Annotate ground truth for evaluation / ablation
    attack_events: list[str] = []
    attack_stages: dict[str, str] = {}

    for ev in telemetry.events:
        target = str(ev.raw_data.get("target") or "")
        proc = str(ev.raw_data.get("process") or "")

        # Check for known CADETS red-team attack steps
        is_attack = False
        stage = "recon"

        for ip in CADETS_ATTACK_IPS:
            if ip in target:
                is_attack = True
                stage = "exfiltration"
                break

        if not is_attack and "/tmp/" in target:
            is_attack = True
            stage = "exploit"
        elif not is_attack and ("passwd" in target or "master.passwd" in target):
            is_attack = True
            stage = "staging"

        if is_attack:
            attack_events.append(ev.event_id)
            attack_stages[ev.event_id] = stage

    # Group into attack chains
    truth = Truth(
        attack_chains={"cadets_attack_chain_1": attack_events} if attack_events else {},
        attack_stages=attack_stages,
        metadata={
            "dataset": "DARPA_TC_E3_CADETS",
            "source_file": str(path),
            "total_records": len(telemetry.events),
            "attack_event_count": len(attack_events),
        },
    )

    return telemetry, truth
