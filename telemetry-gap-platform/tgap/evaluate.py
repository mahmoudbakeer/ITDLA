"""Evaluation engine for RQ1 (Degradation) and RQ2/RQ3 (Gap Localization vs. Baselines).

NOTE: This is the ONLY module permitted to inspect AblationManifest.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Sequence

from tgap.ablate import AblationManifest
from tgap.config import Config, derive_seed
from tgap.schema import Chain, Event, Gap, Telemetry, Truth


@dataclass
class DegradationMetrics:
    """RQ1 metrics measuring how detection and chain reconstruction degrade under loss."""
    mechanism: str
    rate: float
    seed: int
    remaining_attack_events: int
    detected_attack_events: int
    detection_recall: float
    chain_coverage: float
    stage_coverage: float
    num_detected_chains: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GapEvalMetrics:
    """RQ2/RQ3 metrics evaluating gap localization precision and recall."""
    method: str
    mechanism: str
    rate: float
    seed: int
    num_flagged: int
    num_correct_flagged: int
    total_removed: int
    interior_removed: int
    precision: float
    recall_interior: float
    recall_all: float
    f1_interior: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_degradation(
    ablated_telemetry: Telemetry,
    chains: Sequence[Chain],
    truth: Truth,
    manifest: AblationManifest,
    score_threshold: float = 0.05,
) -> DegradationMetrics:
    """Compute RQ1 detection and correlation degradation metrics on ablated stream."""
    all_truth_ids = truth.all_attack_event_ids()
    removed_ids = set(manifest.removed_event_ids)
    remaining_attack_ids = all_truth_ids - removed_ids

    n_remaining = len(remaining_attack_ids)
    if n_remaining == 0:
        return DegradationMetrics(
            mechanism=manifest.mechanism,
            rate=manifest.rate,
            seed=manifest.seed,
            remaining_attack_events=0,
            detected_attack_events=0,
            detection_recall=0.0,
            chain_coverage=0.0,
            stage_coverage=0.0,
            num_detected_chains=len(chains),
        )

    # Events scoring above threshold
    detected_ids = {
        e.event_id
        for e in ablated_telemetry.events
        if e.event_id in remaining_attack_ids and e.score >= score_threshold
    }
    det_recall = len(detected_ids) / float(n_remaining)

    # Events recovered inside candidate attack chains
    chained_ids: set[str] = set()
    for ch in chains:
        for ev in ch.events:
            if ev.event_id in remaining_attack_ids:
                chained_ids.add(ev.event_id)

    # Stage coverage: average fraction of the 5 stages recovered per ground-truth attack chain
    total_truth_events = max(1, len(all_truth_ids))
    chain_cov = len(chained_ids) / float(total_truth_events)

    per_chain_stage_covs: list[float] = []
    for cid, gt_eids in truth.attack_chains.items():
        gt_stages = {truth.attack_stages[eid] for eid in gt_eids if eid in truth.attack_stages}
        rec_stages = {
            truth.attack_stages[eid]
            for eid in gt_eids
            if eid in chained_ids and eid in truth.attack_stages
        }
        if gt_stages:
            per_chain_stage_covs.append(len(rec_stages) / float(len(gt_stages)))

    stage_cov = (
        sum(per_chain_stage_covs) / len(per_chain_stage_covs)
        if per_chain_stage_covs
        else 0.0
    )

    return DegradationMetrics(
        mechanism=manifest.mechanism,
        rate=manifest.rate,
        seed=manifest.seed,
        remaining_attack_events=n_remaining,
        detected_attack_events=len(detected_ids),
        detection_recall=round(det_recall, 4),
        chain_coverage=round(chain_cov, 4),
        stage_coverage=round(stage_cov, 4),
        num_detected_chains=len(chains),
    )


def evaluate_gaps(
    flagged_gaps: Sequence[Gap],
    chains: Sequence[Chain],
    manifest: AblationManifest,
    method_name: str = "statistical_noisy_or",
) -> GapEvalMetrics:
    """Evaluate gap localization precision and recall (interior and all).

    Definition from PROJECT_CONTEXT.md:
    - A flagged gap (u, v) is correct if at least one removed event lies in time
      strictly or inclusively between u.timestamp and v.timestamp.
    - Precision = correct_flagged / flagged (0.0 if flagged == 0).
    - Interior removals = removed events whose timestamp falls within [chain.start_time, chain.end_time]
      of any detected chain.
    """
    removed_events = manifest.removed_events
    total_removed = len(removed_events)

    # Determine which removed events are interior (localizable within detected chain spans)
    interior_events: list[Event] = []
    for rem_ev in removed_events:
        is_interior = False
        for ch in chains:
            if len(ch.events) >= 2 and ch.start_time <= rem_ev.timestamp <= ch.end_time:
                is_interior = True
                break
        if is_interior:
            interior_events.append(rem_ev)

    n_interior = len(interior_events)
    n_flagged = len(flagged_gaps)

    if n_flagged == 0:
        return GapEvalMetrics(
            method=method_name,
            mechanism=manifest.mechanism,
            rate=manifest.rate,
            seed=manifest.seed,
            num_flagged=0,
            num_correct_flagged=0,
            total_removed=total_removed,
            interior_removed=n_interior,
            precision=0.0,
            recall_interior=0.0,
            recall_all=0.0,
            f1_interior=0.0,
        )

    correct_flagged = 0
    localized_removed_ids: set[str] = set()
    localized_interior_ids: set[str] = set()
    interior_id_set = {e.event_id for e in interior_events}

    for gap in flagged_gaps:
        hit = False
        for rem_ev in removed_events:
            if gap.u_timestamp <= rem_ev.timestamp <= gap.v_timestamp:
                hit = True
                localized_removed_ids.add(rem_ev.event_id)
                if rem_ev.event_id in interior_id_set:
                    localized_interior_ids.add(rem_ev.event_id)
        if hit:
            correct_flagged += 1

    precision = correct_flagged / float(n_flagged)
    recall_interior = len(localized_interior_ids) / float(n_interior) if n_interior > 0 else 0.0
    recall_all = len(localized_removed_ids) / float(total_removed) if total_removed > 0 else 0.0

    if (precision + recall_interior) > 0:
        f1_int = 2.0 * precision * recall_interior / (precision + recall_interior)
    else:
        f1_int = 0.0

    return GapEvalMetrics(
        method=method_name,
        mechanism=manifest.mechanism,
        rate=manifest.rate,
        seed=manifest.seed,
        num_flagged=n_flagged,
        num_correct_flagged=correct_flagged,
        total_removed=total_removed,
        interior_removed=n_interior,
        precision=round(precision, 4),
        recall_interior=round(recall_interior, 4),
        recall_all=round(recall_all, 4),
        f1_interior=round(f1_int, 4),
    )


# --- Baselines for RQ2 Comparison ---


def baseline_never_predict() -> list[Gap]:
    """Never-predict baseline: returns zero gap flags."""
    return []


def baseline_fixed_threshold(
    chains: Sequence[Chain],
    fixed_gap_seconds: float = 4.0,
) -> list[Gap]:
    """Fixed-threshold baseline: flags any consecutive pair with dt > fixed_gap_seconds."""
    gaps: list[Gap] = []
    for ch in chains:
        evs = ch.events
        for i in range(len(evs) - 1):
            u, v = evs[i], evs[i + 1]
            dt = v.timestamp - u.timestamp
            if dt > fixed_gap_seconds:
                gaps.append(
                    Gap(
                        gap_id=f"fixed_{ch.chain_id}_{u.event_id}_{v.event_id}",
                        chain_id=ch.chain_id,
                        u_event_id=u.event_id,
                        v_event_id=v.event_id,
                        u_timestamp=u.timestamp,
                        v_timestamp=v.timestamp,
                        confidence=1.0,
                        signals={"dt_seconds": round(dt, 4)},
                    )
                )
    return gaps


def baseline_random_predict(
    chains: Sequence[Chain],
    num_flags: int,
    seed: int = 42,
) -> list[Gap]:
    """Random baseline: flags the exact same number of gaps as the evaluated method."""
    all_pairs: list[tuple[str, Event, Event]] = []
    for ch in chains:
        evs = ch.events
        for i in range(len(evs) - 1):
            all_pairs.append((ch.chain_id, evs[i], evs[i + 1]))

    if not all_pairs or num_flags <= 0:
        return []

    rng = random.Random(derive_seed(seed, "random_baseline", num_flags))
    k = min(len(all_pairs), num_flags)
    chosen = rng.sample(all_pairs, k)

    return [
        Gap(
            gap_id=f"rand_{cid}_{u.event_id}_{v.event_id}",
            chain_id=cid,
            u_event_id=u.event_id,
            v_event_id=v.event_id,
            u_timestamp=u.timestamp,
            v_timestamp=v.timestamp,
            confidence=0.5,
            signals={"random": 1.0},
        )
        for cid, u, v in chosen
    ]
