"""Context-aware anomaly and surprisal detector.

Implements an extensible Detector interface with a context-aware surprisal model
measuring behavior, lineage, identity, and target rarity against a benign baseline.
"""

from __future__ import annotations

import abc
import math
from collections import Counter
from typing import Any, Optional

from tgap.config import Config
from tgap.schema import Event, Telemetry


class Detector(abc.ABC):
    """Abstract interface for intrusion and anomaly detection models."""

    @abc.abstractmethod
    def fit(self, telemetry: Telemetry) -> None:
        """Fit baseline normal model on benign telemetry."""
        pass

    @abc.abstractmethod
    def score_event(self, event: Event, telemetry: Telemetry) -> tuple[float, dict[str, Any]]:
        """Compute anomaly score and explanation dictionary for a single event."""
        pass

    def score_telemetry(self, telemetry: Telemetry) -> Telemetry:
        """Score all events in the telemetry stream in-place and return telemetry."""
        for event in telemetry.events:
            score, explanation = self.score_event(event, telemetry)
            event.score = score
            event.explanation = explanation
        return telemetry


class SurprisalDetector(Detector):
    """Context-aware surprisal detector based on empirical n-gram frequencies.

    Measures information-theoretic surprisal (-log2 P) across 4 dimensions:
    1. Behavior: (process, event_type) pairing.
    2. Lineage: (process, parent_process).
    3. Identity: (process, user).
    4. Target / Resource: access to high-risk files, unexpected sockets, or rare scripts.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.total_benign_events: int = 0

        # Frequency tables
        self.freq_behavior: Counter[tuple[str, str]] = Counter()
        self.freq_process: Counter[str] = Counter()
        self.freq_lineage: Counter[tuple[str, str]] = Counter()
        self.freq_identity: Counter[tuple[str, str]] = Counter()
        self.freq_targets: Counter[str] = Counter()

        # Sensitive paths commonly abused in privilege escalation or exfiltration
        self.suspicious_prefixes = (
            "/etc/shadow",
            "/etc/passwd",
            "/tmp/",
            "/root",
            "/etc/ssl",
            "198.51.",
            ":4444",
        )

    def fit(self, telemetry: Telemetry) -> None:
        """Learn frequency distributions from benign telemetry."""
        self.total_benign_events = len(telemetry.events)
        if self.total_benign_events == 0:
            return

        for ev in telemetry.events:
            proc = ev.raw_data.get("process", "unknown")
            ev_type = ev.event_type
            user = ev.raw_data.get("user", "unknown")
            target = ev.raw_data.get("target") or "none"
            parent = ev.raw_data.get("ppid", 0)
            parent_proc = f"ppid_{parent}"

            self.freq_process[proc] += 1
            self.freq_behavior[(proc, ev_type)] += 1
            self.freq_lineage[(proc, parent_proc)] += 1
            self.freq_identity[(proc, user)] += 1
            self.freq_targets[str(target)] += 1

    def _calc_surprisal(self, count: int, total: int, smoothing: float = 0.5) -> float:
        """Calculate smoothed surprisal: -log2((count + smoothing) / (total + 1))."""
        prob = (count + smoothing) / (total + 1.0)
        return -math.log2(max(prob, 1e-6))

    def score_event(self, event: Event, telemetry: Telemetry) -> tuple[float, dict[str, Any]]:
        """Score an event against the benign baseline."""
        if self.total_benign_events == 0:
            return 0.0, {"reason": "unfitted_baseline"}

        proc = event.raw_data.get("process", "unknown")
        ev_type = event.event_type
        user = str(event.raw_data.get("user", "unknown"))
        target = str(event.raw_data.get("target") or "none")
        parent = event.raw_data.get("ppid", 0)
        parent_proc = f"ppid_{parent}"

        # 1. Behavior surprisal
        proc_total = max(self.freq_process.get(proc, 0), 1)
        behav_count = self.freq_behavior.get((proc, ev_type), 0)
        s_behav = self._calc_surprisal(behav_count, proc_total)

        # 2. Lineage surprisal
        lineage_count = self.freq_lineage.get((proc, parent_proc), 0)
        s_lineage = self._calc_surprisal(lineage_count, proc_total)

        # 3. Identity surprisal
        ident_count = self.freq_identity.get((proc, user), 0)
        s_ident = self._calc_surprisal(ident_count, proc_total)

        # 4. Target context check
        s_target = 0.0
        target_reasons: list[str] = []
        for prefix in self.suspicious_prefixes:
            if prefix in target:
                s_target += 4.0
                target_reasons.append(f"sensitive_target:{prefix}")

        # Check if process itself is rare or absent in benign
        if proc not in self.freq_process:
            s_behav += 4.0

        # Weighted aggregate surprisal
        raw_score = 0.25 * s_behav + 0.20 * s_lineage + 0.15 * s_ident + 0.45 * s_target

        # Normalize via sigmoid so score is cleanly bounded in [0, 1]
        # Baseline normal score is ~1.5-2.5; attack events exceed 4.0
        normalized_score = 1.0 / (1.0 + math.exp(-0.9 * (raw_score - 3.2)))

        explanation: dict[str, Any] = {
            "surprisal_behavior": round(s_behav, 3),
            "surprisal_lineage": round(s_lineage, 3),
            "surprisal_identity": round(s_ident, 3),
            "surprisal_target": round(s_target, 3),
            "target_flags": target_reasons,
            "raw_surprisal": round(raw_score, 3),
            "normalized_score": round(normalized_score, 4),
        }

        return normalized_score, explanation
