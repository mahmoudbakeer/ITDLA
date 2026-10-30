"""Unit tests for statistical gap localization (Phase 4)."""

import pytest
from tgap.config import Config
from tgap.correlate import correlate_events
from tgap.detect import SurprisalDetector
from tgap.gaps import StatisticalGapLocalizer
from tgap.normalize import normalize_records
from tgap.schema import Event, Telemetry
from tgap.synthetic import generate_synthetic_telemetry


def test_handcrafted_dropped_fork_case():
    """Verify that an orphan process appearing without a fork event is flagged."""
    cfg = Config()
    localizer = StatisticalGapLocalizer(cfg)
    localizer.empirical_delays = [0.5, 1.0, 1.5, 2.0]

    # Telemetry has process 500 doing work, but NO process_create for pid 500
    events = [
        Event(
            event_id="E1",
            timestamp=100.0,
            event_type="file_read",
            subject_id="proc_100",
            raw_data={"pid": 100, "ppid": 1, "process": "nginx"},
        ),
        # Here, pid 500 appears out of nowhere (dropped fork / process_create)
        Event(
            event_id="E2",
            timestamp=105.0,
            event_type="file_write",
            subject_id="proc_500",
            raw_data={"pid": 500, "ppid": 100, "process": "sh", "target": "/tmp/payload"},
        ),
    ]
    telemetry = Telemetry(events=events)

    gap = localizer.score_gap(events[0], events[1], "test_chain", telemetry)

    assert gap.confidence >= 0.7
    assert gap.signals["s_struct"] == 1.0  # detected orphan process
    assert 0.0 <= gap.confidence <= 1.0


def test_confidence_bounded():
    cfg = Config()
    localizer = StatisticalGapLocalizer(cfg)
    localizer.empirical_delays = [1.0, 2.0, 3.0]

    e1 = Event(event_id="E1", timestamp=10.0, event_type="file_read", subject_id="p1", raw_data={"pid": 10})
    e2 = Event(event_id="E2", timestamp=12.0, event_type="file_write", subject_id="p1", raw_data={"pid": 10})
    telem = Telemetry(events=[e1, e2])

    gap = localizer.score_gap(e1, e2, "c1", telem)
    assert 0.0 <= gap.confidence <= 1.0
    assert "s_time" in gap.signals
    assert "s_struct" in gap.signals


def test_gap_calibration_and_localization():
    cfg = Config(synthetic_benign_sessions=15, synthetic_attacks=2)
    train_recs, _ = generate_synthetic_telemetry(cfg, seed=101, num_benign=15, num_attacks=0)
    calib_recs, _ = generate_synthetic_telemetry(cfg, seed=102, num_benign=10, num_attacks=2)

    detector = SurprisalDetector(cfg)
    detector.fit(normalize_records(train_recs))

    calib_telem = normalize_records(calib_recs)
    detector.score_telemetry(calib_telem)
    calib_chains = correlate_events(calib_telem, cfg)

    localizer = StatisticalGapLocalizer(cfg)
    localizer.fit_timing_ecdf(calib_chains)
    tau = localizer.calibrate_threshold(calib_chains, calib_telem, target_false_positive_rate=0.1)

    assert 0.0 <= tau <= 1.0
    assert len(localizer.empirical_delays) > 0
