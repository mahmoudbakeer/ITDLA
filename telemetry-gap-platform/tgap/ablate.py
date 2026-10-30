"""Loss-injection (ablation) harness for security telemetry.

Simulates controlled telemetry loss across four empirical mechanisms:
- uniform: random independent event drops
- burst: contiguous blocks of dropped events (buffer overflow)
- sampling: periodic / systematic decimation
- crash: terminal event drops after agent failure

STRICT DATA ISOLATION: The AblationManifest returned by this harness must
NEVER be imported or accessed by detect, correlate, gaps, or report.
Only evaluate.py may inspect the manifest.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Optional

from tgap.config import Config, derive_seed
from tgap.schema import Event, Telemetry, Truth


@dataclass
class AblationManifest:
    """Isolated record of events removed during loss injection."""
    mechanism: str
    rate: float
    seed: int
    removed_event_ids: list[str]
    removed_events: list[Event]
    original_event_count: int
    ablated_event_count: int
    candidate_event_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_removed(self, event_id: str) -> bool:
        return event_id in set(self.removed_event_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "rate": self.rate,
            "seed": self.seed,
            "num_removed": len(self.removed_event_ids),
            "removed_event_ids": self.removed_event_ids,
            "original_event_count": self.original_event_count,
            "ablated_event_count": self.ablated_event_count,
            "candidate_event_count": self.candidate_event_count,
            "metadata": self.metadata,
        }


def inject_telemetry_loss(
    telemetry: Telemetry,
    truth: Optional[Truth] = None,
    mechanism: str = "uniform",
    rate: float = 0.2,
    seed: int = 42,
    target_chain_events_only: bool = True,
) -> tuple[Telemetry, AblationManifest]:
    """Inject loss into a telemetry stream under a specified mechanism and rate.

    Args:
        telemetry: Input complete Telemetry.
        truth: Ground-truth metadata. If target_chain_events_only is True,
               only events belonging to attack chains are candidates for loss.
        mechanism: One of {"uniform", "burst", "sampling", "crash"}.
        rate: Desired fraction of candidate events to drop (0.0 to 1.0).
        seed: Base seed for deterministic ablation.
        target_chain_events_only: Whether to restrict ablation to ground-truth chain events.

    Returns:
        (ablated_telemetry, manifest): New Telemetry with events removed, and
        the isolated AblationManifest tracking dropped events.
    """
    if rate <= 0.0:
        manifest = AblationManifest(
            mechanism=mechanism,
            rate=0.0,
            seed=seed,
            removed_event_ids=[],
            removed_events=[],
            original_event_count=len(telemetry.events),
            ablated_event_count=len(telemetry.events),
            candidate_event_count=0,
        )
        return Telemetry(events=list(telemetry.events), entities=dict(telemetry.entities)), manifest

    rng_seed = derive_seed(seed, "ablate", mechanism, str(rate))
    rng = random.Random(rng_seed)

    # Determine candidate events for ablation
    all_events = list(telemetry.events)
    all_events.sort(key=lambda e: e.timestamp)

    if target_chain_events_only and truth is not None:
        target_ids = truth.all_attack_event_ids()
        candidates = [e for e in all_events if e.event_id in target_ids]
    else:
        candidates = list(all_events)

    n_candidates = len(candidates)
    if n_candidates == 0:
        manifest = AblationManifest(
            mechanism=mechanism,
            rate=rate,
            seed=seed,
            removed_event_ids=[],
            removed_events=[],
            original_event_count=len(all_events),
            ablated_event_count=len(all_events),
            candidate_event_count=0,
        )
        return Telemetry(events=all_events, entities=dict(telemetry.entities)), manifest

    target_drop_count = min(n_candidates, max(1, int(round(n_candidates * rate))))
    removed_ids_set: set[str] = set()

    # Apply specific loss mechanism
    if mechanism == "uniform":
        # Random independent removal
        selected = rng.sample(candidates, target_drop_count)
        removed_ids_set = {e.event_id for e in selected}

    elif mechanism == "burst":
        # Contiguous drops simulating buffer congestion / burst drop
        burst_size = min(3, max(1, n_candidates // 4)) if n_candidates >= 4 else 1
        cand_indices = list(range(n_candidates))
        dropped_indices: set[int] = set()

        # Pick random start indices and drop burst_size consecutive candidates
        attempts = 0
        while len(dropped_indices) < target_drop_count and attempts < 100:
            attempts += 1
            available_starts = [i for i in cand_indices if i not in dropped_indices]
            if not available_starts:
                break
            start = rng.choice(available_starts)
            for offset in range(burst_size):
                idx = start + offset
                if idx < n_candidates:
                    dropped_indices.add(idx)
                    if len(dropped_indices) >= target_drop_count:
                        break

        # If any remaining count needed, fill randomly
        if len(dropped_indices) < target_drop_count:
            remaining = [i for i in cand_indices if i not in dropped_indices]
            for idx in rng.sample(remaining, min(len(remaining), target_drop_count - len(dropped_indices))):
                dropped_indices.add(idx)

        removed_ids_set = {candidates[i].event_id for i in dropped_indices}

    elif mechanism == "sampling":
        # Systematic periodic sampling / decimation
        # Compute stride = 1 / rate
        stride = max(1.0, 1.0 / rate)
        offset = rng.uniform(0.0, stride - 1.0) if stride > 1.0 else 0.0
        dropped_indices = set()
        pos = offset
        while int(pos) < n_candidates and len(dropped_indices) < target_drop_count:
            dropped_indices.add(int(pos))
            pos += stride

        # Ensure exact target count
        cand_indices = list(range(n_candidates))
        if len(dropped_indices) < target_drop_count:
            remaining = [i for i in cand_indices if i not in dropped_indices]
            for idx in rng.sample(remaining, min(len(remaining), target_drop_count - len(dropped_indices))):
                dropped_indices.add(idx)
        elif len(dropped_indices) > target_drop_count:
            excess = len(dropped_indices) - target_drop_count
            to_remove = rng.sample(list(dropped_indices), excess)
            dropped_indices.difference_update(to_remove)

        removed_ids_set = {candidates[i].event_id for i in dropped_indices}

    elif mechanism == "crash":
        # Terminal drops: drop the tail events up to target_drop_count
        # Simulates host audit agent crashing mid-chain
        dropped_candidates = candidates[-target_drop_count:]
        removed_ids_set = {e.event_id for e in dropped_candidates}

    else:
        raise ValueError(f"Unknown loss mechanism: {mechanism}. Expected one of: uniform, burst, sampling, crash.")

    # Construct ablated telemetry stream
    kept_events: list[Event] = []
    removed_events: list[Event] = []

    for ev in all_events:
        if ev.event_id in removed_ids_set:
            removed_events.append(ev)
        else:
            kept_events.append(ev)

    manifest = AblationManifest(
        mechanism=mechanism,
        rate=rate,
        seed=seed,
        removed_event_ids=[e.event_id for e in removed_events],
        removed_events=removed_events,
        original_event_count=len(all_events),
        ablated_event_count=len(kept_events),
        candidate_event_count=n_candidates,
        metadata={"target_chain_events_only": target_chain_events_only},
    )

    ablated_telemetry = Telemetry(
        events=kept_events,
        entities=dict(telemetry.entities),
        malformed_count=telemetry.malformed_count,
    )

    return ablated_telemetry, manifest
