"""Unit tests for PyTorch Deep Learning models: PIDS and Gap Localizer."""

import pytest
import torch
from tgap.config import Config
from tgap.correlate import correlate_events
from tgap.deep_detect import DeepProvenanceDetector
from tgap.deep_gaps import DeepGapLocalizer
from tgap.normalize import normalize_records
from tgap.synthetic import generate_synthetic_telemetry


def test_deep_provenance_detector_train_and_score():
    cfg = Config(synthetic_benign_sessions=15, synthetic_attacks=2)

    # Benign training
    train_recs, _ = generate_synthetic_telemetry(cfg, seed=101, num_benign=15, num_attacks=0)
    train_telem = normalize_records(train_recs)

    detector = DeepProvenanceDetector(cfg)
    detector.fit(train_telem, epochs=5)
    assert detector.is_fitted

    # Test scoring
    test_recs, truth = generate_synthetic_telemetry(cfg, seed=102, num_benign=10, num_attacks=2)
    test_telem = normalize_records(test_recs)
    detector.score_telemetry(test_telem)

    attack_ids = truth.all_attack_event_ids()
    attack_scores = [e.score for e in test_telem.events if e.event_id in attack_ids]
    benign_scores = [e.score for e in test_telem.events if e.event_id not in attack_ids]

    assert len(attack_scores) > 0
    assert len(benign_scores) > 0
    for e in test_telem.events:
        assert 0.0 <= e.score <= 1.0
        assert "gnn_reconstruction_loss" in e.explanation


def test_deep_gap_localizer_fit_and_score():
    cfg = Config(synthetic_benign_sessions=15, synthetic_attacks=2)
    recs, _ = generate_synthetic_telemetry(cfg, seed=101, num_benign=15, num_attacks=2)
    telem = normalize_records(recs)

    # Assign synthetic scores to correlate chains
    for e in telem.events:
        e.score = 0.8
    chains = correlate_events(telem, cfg)
    assert len(chains) > 0

    deep_localizer = DeepGapLocalizer(cfg)
    deep_localizer.fit(chains, epochs=5)

    chain = chains[0]
    u = chain.events[0]
    v = chain.events[1]

    gap = deep_localizer.score_gap(u, v, chain.chain_id)
    assert 0.0 <= gap.confidence <= 1.0
    assert "deep_gap_prob" in gap.signals
    assert gap.u_event_id == u.event_id
    assert gap.v_event_id == v.event_id
