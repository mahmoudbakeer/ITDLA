"""Unit tests for CADETS E3 real dataset loader."""

import pytest
from pathlib import Path
from tgap.cadets_loader import load_cadets_telemetry
from tgap.schema import Telemetry, Truth


def test_load_cadets_telemetry():
    dataset_path = Path("data/cadets_e3/cadets_sample.parquet")
    if not dataset_path.exists():
        pytest.skip("CADETS E3 dataset not present locally")

    telemetry, truth = load_cadets_telemetry(dataset_path, max_rows=1000)

    assert isinstance(telemetry, Telemetry)
    assert isinstance(truth, Truth)
    assert len(telemetry.events) > 0
    assert len(telemetry.entities) > 0
    assert telemetry.malformed_count == 0

    # Ensure chronological order
    timestamps = [e.timestamp for e in telemetry.events]
    assert timestamps == sorted(timestamps)
