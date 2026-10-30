"""Unit tests for evaluation engine and baselines (Phase 5)."""

import pytest
from tgap.ablate import AblationManifest
from tgap.evaluate import (
    baseline_fixed_threshold,
    baseline_never_predict,
    baseline_random_predict,
    evaluate_degradation,
    evaluate_gaps,
)
from tgap.schema import Chain, Event, Gap, Telemetry, Truth


def test_never_predict_baseline_zero_precision_and_recall():
    e1 = Event(event_id="E1", timestamp=10.0, event_type="file_read", subject_id="p1", score=0.9)
    e2 = Event(event_id="E2", timestamp=20.0, event_type="file_write", subject_id="p1", score=0.9)
    rem = Event(event_id="E_DROP", timestamp=15.0, event_type="process_create", subject_id="p1")

    chain = Chain(chain_id="c1", events=[e1, e2])
    manifest = AblationManifest(
        mechanism="uniform",
        rate=0.33,
        seed=1,
        removed_event_ids=["E_DROP"],
        removed_events=[rem],
        original_event_count=3,
        ablated_event_count=2,
        candidate_event_count=3,
    )

    gaps = baseline_never_predict()
    metrics = evaluate_gaps(gaps, [chain], manifest, "never_predict")

    assert metrics.num_flagged == 0
    assert metrics.precision == 0.0
    assert metrics.recall_interior == 0.0
    assert metrics.recall_all == 0.0


def test_correct_interior_gap_evaluation():
    e1 = Event(event_id="E1", timestamp=10.0, event_type="file_read", subject_id="p1", score=0.9)
    e3 = Event(event_id="E3", timestamp=25.0, event_type="file_write", subject_id="p1", score=0.9)
    e_dropped = Event(event_id="E2", timestamp=16.0, event_type="process_create", subject_id="p1")

    chain = Chain(chain_id="c1", events=[e1, e3])
    manifest = AblationManifest(
        mechanism="burst",
        rate=0.33,
        seed=1,
        removed_event_ids=["E2"],
        removed_events=[e_dropped],
        original_event_count=3,
        ablated_event_count=2,
        candidate_event_count=3,
    )

    flagged = [
        Gap(
            gap_id="g1",
            chain_id="c1",
            u_event_id="E1",
            v_event_id="E3",
            u_timestamp=10.0,
            v_timestamp=25.0,
            confidence=0.88,
        )
    ]

    metrics = evaluate_gaps(flagged, [chain], manifest, "ours")
    assert metrics.precision == 1.0
    assert metrics.recall_interior == 1.0
    assert metrics.recall_all == 1.0
    assert metrics.f1_interior == 1.0


def test_degradation_metrics():
    e1 = Event(event_id="E1", timestamp=10.0, event_type="file_read", subject_id="p1", score=0.9)
    e3 = Event(event_id="E3", timestamp=25.0, event_type="file_write", subject_id="p1", score=0.9)
    e2 = Event(event_id="E2", timestamp=16.0, event_type="process_create", subject_id="p1")

    truth = Truth(
        attack_chains={"a1": ["E1", "E2", "E3"]},
        attack_stages={"E1": "recon", "E2": "exploit", "E3": "exfiltration"},
    )
    manifest = AblationManifest(
        mechanism="uniform",
        rate=0.33,
        seed=1,
        removed_event_ids=["E2"],
        removed_events=[e2],
        original_event_count=3,
        ablated_event_count=2,
        candidate_event_count=3,
    )
    telem = Telemetry(events=[e1, e3])
    chain = Chain(chain_id="c1", events=[e1, e3])

    deg = evaluate_degradation(telem, [chain], truth, manifest, score_threshold=0.5)
    assert deg.remaining_attack_events == 2
    assert deg.detection_recall == 1.0
    assert round(deg.chain_coverage, 2) == 0.67
    assert round(deg.stage_coverage, 2) == 0.67
