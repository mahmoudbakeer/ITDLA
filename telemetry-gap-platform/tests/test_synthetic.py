"""Unit tests for synthetic provenance generator (Phase 1)."""

import pytest
from tgap.config import Config, derive_seed
from tgap.synthetic import generate_synthetic_telemetry


def test_derive_seed_reproducibility():
    s1 = derive_seed(42, "synthetic", "test")
    s2 = derive_seed(42, "synthetic", "test")
    assert s1 == s2
    assert isinstance(s1, int)
    assert s1 >= 0

    s3 = derive_seed(42, "synthetic", "train")
    assert s1 != s3  # different domain label yields different seed


def test_synthetic_determinism():
    cfg = Config(base_seed=123, synthetic_benign_sessions=10, synthetic_attacks=2)
    records1, truth1 = generate_synthetic_telemetry(cfg, seed=123, split_name="test")
    records2, truth2 = generate_synthetic_telemetry(cfg, seed=123, split_name="test")

    assert len(records1) == len(records2)
    assert records1 == records2
    assert truth1.attack_chains == truth2.attack_chains
    assert truth1.attack_stages == truth2.attack_stages


def test_raw_records_contain_no_attack_labels():
    """Ensure strict isolation: raw records must NEVER leak ground-truth attack labels."""
    cfg = Config(synthetic_benign_sessions=5, synthetic_attacks=2)
    records, truth = generate_synthetic_telemetry(cfg, split_name="test")

    forbidden_keys = {"label", "is_attack", "attack_stage", "chain_id", "attack"}
    for rec in records:
        for key in forbidden_keys:
            assert key not in rec, f"Raw record leaked ground truth key: {key}"


def test_pure_benign_generation():
    cfg = Config(synthetic_benign_sessions=5, synthetic_attacks=0)
    records, truth = generate_synthetic_telemetry(cfg, num_attacks=0)

    assert len(records) > 0
    assert len(truth.attack_chains) == 0
    assert len(truth.attack_stages) == 0


def test_attack_chains_validity():
    cfg = Config(synthetic_benign_sessions=10, synthetic_attacks=3)
    records, truth = generate_synthetic_telemetry(cfg, num_attacks=3)

    assert len(truth.attack_chains) == 3
    all_record_ids = {r["event_id"] for r in records}

    for chain_id, event_ids in truth.attack_chains.items():
        assert len(event_ids) >= 5  # all stages present
        for eid in event_ids:
            assert eid in all_record_ids
            assert eid in truth.attack_stages
