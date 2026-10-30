"""Deep learning gap-localization model using PyTorch neural link prediction.

Learns topological and temporal embeddings of consecutive events (u, v) to predict
the probability that an intermediate provenance event was dropped:
    P(gap | u, v) = sigmoid(z_u^T W z_v + MLP([z_u, z_v, log(1 + dt)]))

Maintains strict output schema compatibility with Gap objects: states only
boundary events, timestamps, confidence, and signal metadata without hallucination.
"""

from __future__ import annotations

import math
from typing import Optional, Sequence

import torch
import torch.nn as nn
import torch.optim as optim

from tgap.config import Config, derive_seed
from tgap.schema import Chain, Event, Gap, Telemetry


EVENT_TYPE_INDEX = {
    "process_create": 0,
    "fork": 0,
    "exec": 1,
    "file_read": 2,
    "file_write": 3,
    "file_open": 4,
    "file_close": 5,
    "socket_connect": 6,
    "process_terminate": 7,
}


class BilinearGapNetwork(nn.Module):
    """Neural network computing missing link / gap probability between events."""

    def __init__(self, embed_dim: int = 16, hidden_dim: int = 32) -> None:
        super().__init__()
        self.type_embed = nn.Embedding(len(EVENT_TYPE_INDEX) + 1, embed_dim)
        self.encoder = nn.Sequential(
            nn.Linear(embed_dim + 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, embed_dim),
        )
        self.bilinear = nn.Bilinear(embed_dim, embed_dim, 1)
        self.time_weight = nn.Linear(1, 1)
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim * 2 + 1, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, u_feats: torch.Tensor, v_feats: torch.Tensor, dt: torch.Tensor) -> torch.Tensor:
        # u_feats, v_feats: [batch_size, 3] -> (type_idx, pid_hash, is_root)
        u_type = self.type_embed(u_feats[:, 0].long())
        v_type = self.type_embed(v_feats[:, 0].long())

        u_vec = self.encoder(torch.cat([u_type, u_feats[:, 1:]], dim=-1))
        v_vec = self.encoder(torch.cat([v_type, v_feats[:, 1:]], dim=-1))

        bilin = self.bilinear(u_vec, v_vec)
        time_term = self.time_weight(torch.log1p(dt.unsqueeze(-1)))
        mlp_term = self.classifier(torch.cat([u_vec, v_vec, torch.log1p(dt.unsqueeze(-1))], dim=-1))

        logits = bilin + time_term + mlp_term
        return torch.sigmoid(logits).squeeze(-1)


class DeepGapLocalizer:
    """Deep learning gap localizer using a trained neural link predictor."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        torch.manual_seed(derive_seed(self.config.base_seed, "deep_gaps_init"))
        self.model = BilinearGapNetwork()
        self.calibrated_tau: float = self.config.gap_tau

    def _extract_event_features(self, ev: Event) -> torch.Tensor:
        """Extract continuous feature vector for an event."""
        type_idx = EVENT_TYPE_INDEX.get(ev.event_type, len(EVENT_TYPE_INDEX))
        pid = ev.raw_data.get("pid", 0)
        ppid = ev.raw_data.get("ppid", 0)
        norm_pid = (pid % 1000) / 1000.0
        norm_ppid = (ppid % 1000) / 1000.0
        return torch.tensor([float(type_idx), float(norm_pid), float(norm_ppid)], dtype=torch.float32)

    def fit(
        self,
        complete_chains: Sequence[Chain],
        epochs: int = 40,
        lr: float = 0.03,
    ) -> None:
        """Train neural link predictor on complete and synthetic ablation pairs."""
        samples: list[tuple[torch.Tensor, torch.Tensor, float, float]] = []

        # 1. Negative samples: consecutive events in complete chains (no missing gap)
        for chain in complete_chains:
            evs = chain.events
            for i in range(len(evs) - 1):
                u_feat = self._extract_event_features(evs[i])
                v_feat = self._extract_event_features(evs[i + 1])
                dt = max(0.0, evs[i + 1].timestamp - evs[i].timestamp)
                samples.append((u_feat, v_feat, dt, 0.0))

            # 2. Positive samples: simulate a dropped middle event (i to i+2 has a gap)
            for i in range(len(evs) - 2):
                u_feat = self._extract_event_features(evs[i])
                v_feat = self._extract_event_features(evs[i + 2])
                dt = max(0.0, evs[i + 2].timestamp - evs[i].timestamp)
                samples.append((u_feat, v_feat, dt, 1.0))

        if not samples:
            return

        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.BCELoss()

        u_batch = torch.stack([s[0] for s in samples])
        v_batch = torch.stack([s[1] for s in samples])
        dt_batch = torch.tensor([s[2] for s in samples], dtype=torch.float32)
        y_batch = torch.tensor([s[3] for s in samples], dtype=torch.float32)

        self.model.train()
        for _ in range(epochs):
            optimizer.zero_grad()
            preds = self.model(u_batch, v_batch, dt_batch)
            loss = criterion(preds, y_batch)
            loss.backward()
            optimizer.step()

        self.model.eval()

    def score_gap(self, u: Event, v: Event, chain_id: str) -> Gap:
        """Score missing evidence probability between u and v."""
        u_feat = self._extract_event_features(u).unsqueeze(0)
        v_feat = self._extract_event_features(v).unsqueeze(0)
        dt = max(0.0, v.timestamp - u.timestamp)
        dt_t = torch.tensor([dt], dtype=torch.float32)

        self.model.eval()
        with torch.no_grad():
            prob = self.model(u_feat, v_feat, dt_t).item()

        confidence = min(1.0, max(0.0, float(prob)))
        gap_id = f"deep_gap_{chain_id}_{u.event_id}_{v.event_id}"

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
                "deep_gap_prob": round(confidence, 4),
                "model": "BilinearGapNetwork_PyTorch",
            },
        )

    def localize_gaps(
        self,
        chains: Sequence[Chain],
        tau: Optional[float] = None,
    ) -> list[Gap]:
        """Detect and flag gaps across chains where deep model confidence >= tau."""
        threshold = tau if tau is not None else self.calibrated_tau
        flagged_gaps: list[Gap] = []

        for chain in chains:
            evs = chain.events
            for i in range(len(evs) - 1):
                gap = self.score_gap(evs[i], evs[i + 1], chain.chain_id)
                if gap.confidence >= threshold:
                    flagged_gaps.append(gap)

        return flagged_gaps
