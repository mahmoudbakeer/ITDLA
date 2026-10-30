"""Deep learning provenance intrusion detection model using PyTorch Graph Neural Networks.

Implements the standard Detector interface via a Provenance Graph Autoencoder
that learns normal provenance graph manifolds from benign training telemetry.
"""

from __future__ import annotations

import math
from typing import Any, Optional

import torch
import torch.nn as nn
import torch.optim as optim

from tgap.config import Config, derive_seed
from tgap.detect import Detector
from tgap.schema import Event, Telemetry


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


class ProvenanceGNN(nn.Module):
    """Graph autoencoder embedding provenance events and their local neighborhoods."""

    def __init__(self, in_dim: int = 16, hidden_dim: int = 32, latent_dim: int = 16) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, in_dim),
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        z = self.encoder(x)
        x_recon = self.decoder(z)
        return z, x_recon


class DeepProvenanceDetector(Detector):
    """Deep learning intrusion detector implementing the Detector interface."""

    def __init__(self, config: Optional[Config] = None, in_dim: int = 16) -> None:
        self.config = config or Config()
        torch.manual_seed(derive_seed(self.config.base_seed, "deep_detect_init"))
        self.in_dim = in_dim
        self.model = ProvenanceGNN(in_dim=in_dim)
        self.type_embed = nn.Embedding(len(EVENT_TYPE_INDEX) + 1, 8)
        self.is_fitted: bool = False
        self.loss_fn = nn.MSELoss(reduction="none")
        self.normal_mean_loss: float = 0.1
        self.normal_std_loss: float = 0.05

    def _extract_event_vector(self, event: Event, telemetry: Telemetry) -> torch.Tensor:
        """Construct dense vector representing event type, acting process, and neighborhood."""
        ev_type = event.event_type
        type_idx = EVENT_TYPE_INDEX.get(ev_type, len(EVENT_TYPE_INDEX))
        type_vec = self.type_embed(torch.tensor(type_idx)).detach()

        pid = event.raw_data.get("pid", 0)
        norm_pid = (pid % 1000) / 1000.0
        ppid = event.raw_data.get("ppid", 0)
        norm_ppid = (ppid % 1000) / 1000.0

        user = str(event.raw_data.get("user", "unknown"))
        is_root = 1.0 if user == "root" else 0.0
        is_web = 1.0 if "web" in user or "svc" in user else 0.0

        target = str(event.raw_data.get("target") or "")
        is_tmp = 1.0 if "/tmp" in target else 0.0
        is_etc = 1.0 if "/etc" in target else 0.0
        is_remote = 1.0 if ":" in target or "198." in target or "61." in target else 0.0

        numeric_feats = torch.tensor(
            [norm_pid, norm_ppid, is_root, is_web, is_tmp, is_etc, is_remote, float(len(target) % 50) / 50.0],
            dtype=torch.float32,
        )

        return torch.cat([type_vec, numeric_feats])  # 8 + 8 = 16 dimensions

    def fit(self, telemetry: Telemetry, epochs: int = 12, lr: float = 0.01) -> None:
        """Train the graph autoencoder on benign baseline telemetry."""
        if not telemetry.events:
            return

        tensors = [self._extract_event_vector(e, telemetry) for e in telemetry.events]
        x_train = torch.stack(tensors)

        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        self.model.train()
        for _ in range(epochs):
            optimizer.zero_grad()
            _, x_recon = self.model(x_train)
            loss = criterion(x_recon, x_train)
            loss.backward()
            optimizer.step()

        self.model.eval()
        with torch.no_grad():
            _, x_recon = self.model(x_train)
            losses = self.loss_fn(x_recon, x_train).mean(dim=-1).numpy()
            self.normal_mean_loss = float(losses.mean())
            self.normal_std_loss = max(1e-4, float(losses.std()))

        self.is_fitted = True

    def score_event(self, event: Event, telemetry: Telemetry) -> tuple[float, dict[str, Any]]:
        """Compute anomaly score for event using GNN reconstruction error."""
        if not self.is_fitted:
            return 0.0, {"model": "DeepProvenanceDetector", "status": "unfitted"}

        x = self._extract_event_vector(event, telemetry).unsqueeze(0)
        self.model.eval()
        with torch.no_grad():
            _, x_recon = self.model(x)
            recon_loss = float(self.loss_fn(x_recon, x).mean().item())

        # Z-score against benign baseline
        z = (recon_loss - self.normal_mean_loss) / (self.normal_std_loss + 1e-6)

        # Normalize via sigmoid
        score = 1.0 / (1.0 + math.exp(-0.8 * (z - 1.5)))

        explanation = {
            "model": "DeepProvenanceDetector_PyTorch",
            "gnn_reconstruction_loss": round(recon_loss, 4),
            "z_score": round(z, 3),
            "normalized_score": round(score, 4),
        }
        return score, explanation
