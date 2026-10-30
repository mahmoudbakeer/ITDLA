"""Attack-chain correlation and provenance graph construction."""

from __future__ import annotations

from typing import Optional
import networkx as nx

from tgap.config import Config
from tgap.schema import Chain, Event, Telemetry


def correlate_events(
    telemetry: Telemetry,
    config: Optional[Config] = None,
    score_threshold: Optional[float] = None,
) -> list[Chain]:
    """Correlate anomalous events into candidate attack-chain graphs.

    Uses entity relationships (same PID, parent-child process lineage, shared
    files, network targets) constrained by a temporal sliding window.
    """
    cfg = config or Config()
    threshold = score_threshold if score_threshold is not None else cfg.rarity_threshold
    link_window = cfg.link_window

    # 1. Filter events that exceed the anomaly threshold
    anomalous_events = [e for e in telemetry.events if e.score >= threshold]
    if not anomalous_events:
        return []

    # Ensure chronological order
    anomalous_events.sort(key=lambda e: e.timestamp)

    # 2. Build Candidate Directed Provenance Graph
    G = nx.DiGraph()

    # Add nodes with metadata
    for ev in anomalous_events:
        G.add_node(
            ev.event_id,
            timestamp=ev.timestamp,
            event_type=ev.event_type,
            score=ev.score,
            process=ev.raw_data.get("process", ""),
            pid=ev.raw_data.get("pid", 0),
            ppid=ev.raw_data.get("ppid", 0),
            user=ev.raw_data.get("user", ""),
            target=str(ev.raw_data.get("target") or ""),
            event_obj=ev,
        )

    # Add edges based on causal and entity correlation within link_window
    n = len(anomalous_events)
    for i in range(n):
        u = anomalous_events[i]
        u_data = u.raw_data
        u_pid = u_data.get("pid", 0)
        u_target = str(u_data.get("target") or "")

        for j in range(i + 1, n):
            v = anomalous_events[j]
            dt = v.timestamp - u.timestamp

            # Break if beyond link window (since events are sorted chronologically)
            if dt > link_window:
                break
            if dt < 0:
                continue

            v_data = v.raw_data
            v_pid = v_data.get("pid", 0)
            v_ppid = v_data.get("ppid", 0)
            u_ppid = u_data.get("ppid", 0)
            v_target = str(v_data.get("target") or "")

            is_linked = False
            link_relation = ""

            # Check 1: Process continuity (same PID)
            if u_pid != 0 and u_pid == v_pid:
                is_linked = True
                link_relation = "same_process"
            # Check 2: Parent-Child fork/exec relationship
            elif u_pid != 0 and v_ppid == u_pid:
                is_linked = True
                link_relation = "parent_child"
            # Check 3: Shared lineage when an intermediate process_create was dropped
            elif u_ppid > 100 and (v_pid == u_ppid or v_ppid == u_ppid or abs(v_pid - u_pid) <= 2):
                is_linked = True
                link_relation = "shared_lineage"
            # Check 4: Shared target resource (excluding generic system files across unrelated sessions)
            elif u_target and u_target == v_target and u_target not in ("none", "", "/bin/bash", "/etc/passwd"):
                is_linked = True
                link_relation = "shared_target"

            if is_linked:
                G.add_edge(u.event_id, v.event_id, dt=dt, relation=link_relation)

    # 3. Extract weakly connected components as candidate attack chains
    components = list(nx.weakly_connected_components(G))
    chains: list[Chain] = []
    chain_idx = 1

    # Map event_id back to Event object
    ev_map = {e.event_id: e for e in anomalous_events}

    for comp in components:
        # Require at least 2 connected events to form a meaningful attack chain
        if len(comp) < 2:
            continue

        comp_events = [ev_map[eid] for eid in comp]
        comp_events.sort(key=lambda e: e.timestamp)

        subgraph = G.subgraph(comp).copy()
        avg_score = sum(e.score for e in comp_events) / len(comp_events)

        chain = Chain(
            chain_id=f"chain_{chain_idx}",
            events=comp_events,
            graph=subgraph,
            score=round(avg_score, 4),
            metadata={
                "event_count": len(comp_events),
                "num_edges": subgraph.number_of_edges(),
                "time_span": round(comp_events[-1].timestamp - comp_events[0].timestamp, 4),
            },
        )
        chains.append(chain)
        chain_idx += 1

    # Sort chains by score descending
    chains.sort(key=lambda c: c.score, reverse=True)
    return chains
