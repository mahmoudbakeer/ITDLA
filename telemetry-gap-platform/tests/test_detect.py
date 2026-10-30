"""Unit tests for context-aware surprisal detector (Phase 2)."""

import pytest
from tgap.config import Config
from tgap.detect import SurprisalDetector
from tgap.normalize import normalize_records
from tgap.synthetic import generate_synthetic_telemetry


def test_detector_attack_scores_higher_than_benign():
    cfg = Config(synthetic_benign_sessions=30, synthetic_attacks=3, base_seed=42)

    # 1. Generate benign-only training split
    train_records, _ = generate_synthetic_telemetry(
        cfg, seed=101, split_name="train", num_benign=30, num_attacks=0
    )
    train_telemetry = normalize_records(train_records)

    detector = SurprisalDetector(cfg)
    detector.fit(train_telemetry)

    # 2. Generate test split with benign + attacks
    test_records, truth = generate_synthetic_telemetry(
        cfg, seed=102, split_name="test", num_benign=20, num_attacks=3
    )
    test_telemetry = normalize_records(test_records)
    detector.score_telemetry(test_telemetry)

    attack_event_ids = truth.all_attack_event_ids()

    attack_scores = [
        ev.score for ev in test_telemetry.events if ev.event_id in attack_event_ids
    ]
    benign_scores = [
        ev.score for ev in test_telemetry.events if ev.event_id not in attack_event_ids
    ]

    assert len(attack_scores) > 0
    assert len(benign_scores) > 0

    avg_attack_score = sum(attack_scores) / len(attack_scores)
    avg_benign_score = sum(benign_scores) / len(benign_scores)

    # Attack events should exhibit markedly higher surprisal
    assert avg_attack_score > avg_benign_score
    assert avg_attack_score > 0.45


def test_detector_explanation_populated():
    cfg = Config(synthetic_benign_sessions=10, synthetic_attacks=1)
    train_recs, _ = generate_synthetic_telemetry(cfg, num_benign=10, num_attacks=0)
    train_telem = normalize_records(train_recs)

    detector = SurprisalDetector(cfg)
    detector.fit(train_telem)

    test_recs, _ = generate_synthetic_telemetry(cfg, num_benign=5, num_attacks=1)
    test_telem = normalize_records(test_recs)
    detector.score_telemetry(test_telem)

    for ev in test_telem.events:
        assert isinstance(ev.explanation, dict)
        assert "surprisal_behavior" in ev.explanation
        assert "surprisal_lineage" in ev.explanation
        assert "raw_surprisal" in ev.explanation
