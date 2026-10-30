"""Data models and schemas for provenance telemetry, attack chains, gaps, and ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
import networkx as nx


@dataclass
class Entity:
    """Represents a system entity (Process, File, Socket, User)."""
    id: str
    type: str  # 'process', 'file', 'socket', 'user'
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "attributes": self.attributes,
        }


@dataclass
class Event:
    """Represents a normalized security event."""
    event_id: str
    timestamp: float
    event_type: str  # 'process_create', 'exec', 'file_read', 'file_write', 'socket_connect', 'process_terminate'
    subject_id: str
    object_id: Optional[str] = None
    score: float = 0.0
    explanation: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "object_id": self.object_id,
            "score": self.score,
            "explanation": self.explanation,
            "raw_data": self.raw_data,
        }


@dataclass
class Telemetry:
    """A collection of normalized events and entities with parsing statistics."""
    events: list[Event] = field(default_factory=list)
    entities: dict[str, Entity] = field(default_factory=dict)
    malformed_count: int = 0

    def __post_init__(self) -> None:
        # Keep events sorted chronologically
        self.events.sort(key=lambda e: e.timestamp)

    def get_event(self, event_id: str) -> Optional[Event]:
        for ev in self.events:
            if ev.event_id == event_id:
                return ev
        return None

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        return self.entities.get(entity_id)


@dataclass
class Chain:
    """A candidate attack chain or correlated provenance subgraph."""
    chain_id: str
    events: list[Event] = field(default_factory=list)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.events.sort(key=lambda e: e.timestamp)

    @property
    def event_ids(self) -> list[str]:
        return [e.event_id for e in self.events]

    @property
    def start_time(self) -> float:
        return self.events[0].timestamp if self.events else 0.0

    @property
    def end_time(self) -> float:
        return self.events[-1].timestamp if self.events else 0.0

    @property
    def duration(self) -> float:
        if not self.events:
            return 0.0
        return self.end_time - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "event_ids": self.event_ids,
            "score": self.score,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "num_nodes": self.graph.number_of_nodes(),
            "num_edges": self.graph.number_of_edges(),
            "metadata": self.metadata,
        }


@dataclass
class Gap:
    """Represents a localized missing telemetry gap between consecutive events in a chain.

    Design requirement: A Gap object contains only location, confidence,
    and observed signals — it NEVER states or hallucinates what the missing event was.
    """
    gap_id: str
    chain_id: str
    u_event_id: str
    v_event_id: str
    u_timestamp: float
    v_timestamp: float
    confidence: float
    signals: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "chain_id": self.chain_id,
            "u_event_id": self.u_event_id,
            "v_event_id": self.v_event_id,
            "u_timestamp": self.u_timestamp,
            "v_timestamp": self.v_timestamp,
            "gap_duration": self.v_timestamp - self.u_timestamp,
            "confidence": self.confidence,
            "signals": self.signals,
        }


@dataclass
class Truth:
    """Ground truth metadata, strictly isolated from raw telemetry and detection.

    Raw records never carry labels; Truth is kept in this separate structure
    and consumed strictly by evaluation and the ablation harness.
    """
    attack_chains: dict[str, list[str]] = field(default_factory=dict)  # chain_id -> list[event_id]
    attack_stages: dict[str, str] = field(default_factory=dict)        # event_id -> stage_name
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_attack_event(self, event_id: str) -> bool:
        return event_id in self.attack_stages

    def get_chain_for_event(self, event_id: str) -> Optional[str]:
        for cid, ev_ids in self.attack_chains.items():
            if event_id in ev_ids:
                return cid
        return None

    def all_attack_event_ids(self) -> set[str]:
        return set(self.attack_stages.keys())

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_chains": self.attack_chains,
            "attack_stages": self.attack_stages,
            "num_attack_events": len(self.attack_stages),
            "metadata": self.metadata,
        }
