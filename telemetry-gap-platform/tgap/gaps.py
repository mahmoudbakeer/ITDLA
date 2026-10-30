"""Statistical gap-localization method over candidate attack chains.

Combines empirical inter-event timing distributions (s_time) with structural
continuity breaks (s_struct: orphan processes) via noisy-OR:
    C(u, v) = 1 - (1 - s_time) * (1 - w * s_struct)

A Gap object strictly records boundary events, timestamps, confidence,
and observed signals — it NEVER fabricates or guesses missing event content.
"""

from __future__ import annotations

import bisect
from typing import Optional, Sequence

from tgap.config import Config
from tgap.schema import Chain, Event, Gap, Telemetry


class StatisticalGapLocalizer:
    """Interpretable statistical gap localizer with empirical timing CDF and structural signals."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.empirical_delays: list[float] = []
        self.calibrated_tau: float = self.config.gap_tau
        self.noisy_or_weight: float = self.config.gap_noisy_or_weight

    def fit_timing_ecdf(self, chains: Sequence[Chain]) -> None:
        """Fit empirical CDF of consecutive event delays on complete-data calibration chains."""
        delays: list[float] = []
        for chain in chains:
            evs = chain.events
            for i in range(len(evs) - 1):
                dt = evs[i + 1].timestamp - evs[i].timestamp
                if dt >= 0:
                    delays.append(dt)

        delays.sort()
        self.empirical_delays = delays if delays else [1.0]

    def _compute_s_time(self, dt: float) -> float:
        """Compute empirical CDF score on complete baseline, highlighting tail anomalies."""
        if not self.empirical_delays or dt <= 0:
            return 0.0
        max_normal = self.empirical_delays[-1]
        if dt > max_normal:
            # Delay exceeds maximum consecutive step observed in complete calibration chains
            return min(1.0, 0.90 + 0.05 * (dt - max_normal))
        idx = bisect.bisect_right(self.empirical_delays, dt)
        # Within normal complete-chain support, scale ECDF to [0.0, 0.65]
        return 0.65 * (idx / float(len(self.empirical_delays)))

    def _compute_s_struct(self, u: Event, v: Event, telemetry: Telemetry) -> float:
        """Structural continuity break signal: 1.0 if v exhibits an orphan process or broken lineage.

        An orphan process is an acting process whose process_create / fork
        was never observed in the telemetry stream prior to v.
        """
        v_data = v.raw_data
        v_pid = v_data.get("pid", 0)
        v_ppid = v_data.get("ppid", 0)
        u_pid = u.raw_data.get("pid", 0)

        # Case 1: v is a child creation event, check if its parent (v_ppid) is disconnected from u
        if v.event_type in ("process_create", "fork", "exec"):
            if u_pid > 100 and v_ppid > 100 and v_ppid != u_pid:
                return 1.0
            return 0.0

        # Case 2: v is a normal action (read/write/socket); check if v_pid creation was observed
        has_creation = False
        for ev in telemetry.events:
            if ev.timestamp > v.timestamp:
                break
            if ev.event_type in ("process_create", "fork") and ev.raw_data.get("pid") == v_pid:
                has_creation = True
                break

        if not has_creation and v_pid > 100:
            return 1.0

        return 0.0

    def score_gap(self, u: Event, v: Event, chain_id: str, telemetry: Telemetry) -> Gap:
        """Compute confidence C(u, v) and return a Gap object."""
        dt = max(0.0, v.timestamp - u.timestamp)
        s_time = self._compute_s_time(dt)
        s_struct = self._compute_s_struct(u, v, telemetry)

        # Noisy-OR combination
        w = self.noisy_or_weight
        confidence = 1.0 - (1.0 - s_time) * (1.0 - w * s_struct)
        confidence = min(1.0, max(0.0, confidence))

        gap_id = f"gap_{chain_id}_{u.event_id}_{v.event_id}"
        return Gap(
            gap_id=gap_id,
            chain_id=chain_id,
            u_event_id=u.event_id,
            v_event_id=v.event_id,
            u_timestamp=u.timestamp,
            v_timestamp=v.timestamp,
            confidence=round(confidence, 4),
            signals={
                "dt_seconds": round(dt, 4),
                "s_time": round(s_time, 4),
                "s_struct": round(s_struct, 4),
            },
        )

    def localize_gaps(
        self,
        chains: Sequence[Chain],
        telemetry: Telemetry,
        tau: Optional[float] = None,
    ) -> list[Gap]:
        """Detect and flag gaps across all chains where confidence >= tau."""
        threshold = tau if tau is not None else self.calibrated_tau
        flagged_gaps: list[Gap] = []

        for chain in chains:
            evs = chain.events
            for i in range(len(evs) - 1):
                u = evs[i]
                v = evs[i + 1]
                gap = self.score_gap(u, v, chain.chain_id, telemetry)
                if gap.confidence >= threshold:
                    flagged_gaps.append(gap)

        return flagged_gaps

    def calibrate_threshold(
        self,
        calib_chains: Sequence[Chain],
        telemetry: Telemetry,
        target_false_positive_rate: float = 0.05,
    ) -> float:
        """Calibrate tau on complete calibration data to limit false gap flags."""
        scores: list[float] = []
        for chain in calib_chains:
            evs = chain.events
            for i in range(len(evs) - 1):
                gap = self.score_gap(evs[i], evs[i + 1], chain.chain_id, telemetry)
                scores.append(gap.confidence)

        if not scores:
            self.calibrated_tau = self.config.gap_tau
            return self.calibrated_tau

        scores.sort()
        cutoff_idx = int(round((1.0 - target_false_positive_rate) * len(scores)))
        cutoff_idx = min(len(scores) - 1, max(0, cutoff_idx))
        self.calibrated_tau = min(0.85, max(0.68, scores[cutoff_idx] + 0.03))
        return self.calibrated_tau
