"""Configuration dataclass, JSON loader, and deterministic seed derivation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence


def derive_seed(seed: int, *labels: Any) -> int:
    """Derive a deterministic 31-bit seed from a base seed and string labels.

    Uses SHA-256 rather than Python's salted hash() to guarantee identical
    sequences across Python processes, platforms, and runs.
    """
    key = f"{seed}:" + ":".join(str(lbl) for lbl in labels)
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big") & 0x7FFFFFFF


@dataclass
class Config:
    # Gap localization tunables
    gap_noisy_or_weight: float = 0.7
    gap_tau: float = 0.5
    fixed_gap_seconds: float = 10.0

    # Detection & Correlation tunables
    rarity_threshold: float = 0.05
    link_window: float = 30.0

    # Evaluation & Ablation grid
    mechanisms: list[str] = field(
        default_factory=lambda: ["uniform", "burst", "sampling", "crash"]
    )
    rates: list[float] = field(default_factory=lambda: [0.1, 0.2, 0.3, 0.5])
    seeds: list[int] = field(default_factory=lambda: [1, 2, 3, 4, 5])

    # Synthetic generator tunables
    synthetic_benign_sessions: int = 25
    synthetic_attacks: int = 5
    synthetic_noise_rate: float = 0.02
    base_seed: int = 42

    # Experiment run settings
    dataset_split: dict[str, int] = field(
        default_factory=lambda: {"train": 101, "calib": 102, "test": 103}
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create Config from dictionary, ignoring unknown keys."""
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def to_dict(self) -> dict[str, Any]:
        """Convert Config to standard dict."""
        return asdict(self)


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from a JSON file, or return default config."""
    if path is None:
        default_path = Path("configs/default.json")
        if default_path.exists():
            path = default_path
        else:
            return Config()

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return Config.from_dict(data)


def save_config(config: Config, path: str | Path) -> None:
    """Save configuration to a JSON file."""
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config.to_dict(), f, indent=2)
