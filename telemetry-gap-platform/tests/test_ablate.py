"""Unit tests for loss-injection (ablation) harness (Phase 3)."""

import pytest
from tgap.ablate import AblationManifest, inject_telemetry_loss
from tgap.config import Config
from tgap.normalize import normalize_records
from tgap.synthetic import generate_synthetic_telemetry


def test_ablation_only_chain_events_removed():
    cfg = Config(synthetic_benign_sessions=15, synthetic_attacks=3, base_seed=42)
    records, truth = generate_synthetic_telemetry(cfg, num_benign=15, num_attacks=3)
    telemetry = normalize_records(records)

    attack_ids = truth.all_attack_event_ids()
    benign_ids = {e.event_id for e in telemetry.events if e.event_id not in attack_ids}

    ablated_telem, manifest = inject_telemetry_loss(
        telemetry,
        truth=truth,
        mechanism="uniform",
        rate=0.3,
        seed=42,
        target_chain_events_only=True,
    )

    assert isinstance(manifest, AblationManifest)
    assert len(manifest.removed_event_ids) > 0

    # Ensure EVERY removed event belonged to an attack chain
    for eid in manifest.removed_event_ids:
        assert eid in attack_ids
        assert eid not in benign_ids

    # Ensure all benign events remain intact in the ablated stream
    ablated_event_ids = {e.event_id for e in ablated_telem.events}
    for b_id in benign_ids:
        assert b_id in ablated_event_ids


def test_ablation_reproducibility():
    cfg = Config(synthetic_benign_sessions=10, synthetic_attacks=2)
    records, truth = generate_synthetic_telemetry(cfg)
    telemetry = normalize_records(records)

    _, m1 = inject_telemetry_loss(telemetry, truth, mechanism="burst", rate=0.25, seed=99)
    _, m2 = inject_telemetry_loss(telemetry, truth, mechanism="burst", rate=0.25, seed=99)

    assert m1.removed_event_ids == m2.removed_event_ids
    assert m1.ablated_event_count == m2.ablated_event_count


def test_ablation_rate_sanity_across_all_mechanisms():
    cfg = Config(synthetic_benign_sessions=15, synthetic_attacks=4)
    records, truth = generate_synthetic_telemetry(cfg)
    telemetry = normalize_records(records)
    total_candidates = len(truth.all_attack_event_ids())

    mechanisms = ["uniform", "burst", "sampling", "crash"]
    rates = [0.1, 0.25, 0.5]

    for mech in mechanisms:
        for rate in rates:
            _, manifest = inject_telemetry_loss(
                telemetry, truth, mechanism=mech, rate=rate, seed=123
            )
            expected_count = int(round(total_candidates * rate))
            assert len(manifest.removed_event_ids) == expected_count, (
                f"Mechanism {mech} at rate {rate} removed {len(manifest.removed_event_ids)}, "
                f"expected {expected_count}"
            )


def test_ablation_crash_tail_behavior():
    cfg = Config(synthetic_benign_sessions=10, synthetic_attacks=2)
    records, truth = generate_synthetic_telemetry(cfg)
    telemetry = normalize_records(records)

    attack_events = [e for e in telemetry.events if e.event_id in truth.all_attack_event_ids()]
    attack_events.sort(key=lambda e: e.timestamp)

    rate = 0.3
    _, manifest = inject_telemetry_loss(
        telemetry, truth, mechanism="crash", rate=rate, seed=42
    )

    k = int(round(len(attack_events) * rate))
    expected_tail_ids = [e.event_id for e in attack_events[-k:]]
    assert manifest.removed_event_ids == expected_tail_ids


def test_ablation_zero_rate():
    cfg = Config(synthetic_benign_sessions=5, synthetic_attacks=1)
    records, truth = generate_synthetic_telemetry(cfg)
    telemetry = normalize_records(records)

    ablated_telem, manifest = inject_telemetry_loss(
        telemetry, truth, mechanism="uniform", rate=0.0
    )
    assert len(manifest.removed_event_ids) == 0
    assert len(ablated_telem.events) == len(telemetry.events)
