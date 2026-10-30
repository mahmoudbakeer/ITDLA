"""Unit tests for attack-chain correlation (Phase 2)."""

import pytest
from tgap.config import Config
from tgap.correlate import correlate_events
from tgap.detect import SurprisalDetector
from tgap.normalize import normalize_records
from tgap.schema import Event, Telemetry
from tgap.synthetic import generate_synthetic_telemetry


def test_correlate_synthetic_attack_chains():
    cfg = Config(synthetic_benign_sessions=20, synthetic_attacks=2, rarity_threshold=0.35)

    # Train baseline
    train_recs, _ = generate_synthetic_telemetry(cfg, seed=101, num_benign=20, num_attacks=0)
    train_telem = normalize_records(train_recs)
    detector = SurprisalDetector(cfg)
    detector.fit(train_telem)

    # Test stream
    test_recs, truth = generate_synthetic_telemetry(cfg, seed=102, num_benign=15, num_attacks=2)
    test_telem = normalize_records(test_recs)
    detector.score_telemetry(test_telem)

    # Correlate
    chains = correlate_events(test_telem, cfg)

    assert len(chains) >= 1
    for chain in chains:
        assert len(chain.events) >= 2
        assert chain.graph.number_of_nodes() == len(chain.events)
        assert chain.graph.number_of_edges() >= 1

        # Check timestamp monotonically increasing
        timestamps = [e.timestamp for e in chain.events]
        assert timestamps == sorted(timestamps)


def test_correlate_window_boundary():
    """Ensure events exceeding link_window are not linked."""
    cfg = Config(link_window=10.0, rarity_threshold=0.3)

    events = [
        Event(
            event_id="E1",
            timestamp=100.0,
            event_type="process_create",
            subject_id="proc_1",
            score=0.9,
            raw_data={"pid": 100, "ppid": 1, "process": "sh"},
        ),
        Event(
            event_id="E2",
            timestamp=105.0,  # within 10s window
            event_type="file_write",
            subject_id="proc_1",
            score=0.9,
            raw_data={"pid": 100, "ppid": 1, "process": "sh"},
        ),
        Event(
            event_id="E3",
            timestamp=150.0,  # 45s later -> outside window
            event_type="socket_connect",
            subject_id="proc_1",
            score=0.9,
            raw_data={"pid": 100, "ppid": 1, "process": "sh"},
        ),
    ]

    telemetry = Telemetry(events=events)
    chains = correlate_events(telemetry, cfg)

    # E1 and E2 should form a chain; E3 is an isolated singleton beyond link_window
    assert len(chains) == 1
    assert chains[0].event_ids == ["E1", "E2"]
