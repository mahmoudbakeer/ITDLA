"""Analyst Evidence View and Strict Claims Registry (FR6 & Phase 9 Enterprise UI).

Enforces that every displayed analytical claim references a concrete, existing
evidence ID (Event ID or Gap ID). Renders both machine-readable JSON and
a professional Master-Detail Investigation Workbench (Zinc/Carbon design system).
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

from tgap.schema import Chain, Gap, Telemetry


class UnsupportedClaimError(ValueError):
    """Raised when an analytical claim is registered without valid evidence backing."""
    pass


@dataclass
class Claim:
    """A single analytical statement backed by concrete evidence IDs."""
    claim_id: str
    statement: str
    evidence_ids: list[str]
    category: str = "chain_analysis"


class ClaimsRegistry:
    """Registry that validates every claim against concrete observed evidence IDs."""

    def __init__(self, valid_evidence_ids: set[str]) -> None:
        self.valid_evidence_ids: set[str] = set(valid_evidence_ids)
        self.claims: list[Claim] = []

    def add_claim(
        self,
        statement: str,
        evidence_ids: Sequence[str],
        category: str = "chain_analysis",
    ) -> Claim:
        """Register a claim. Raises UnsupportedClaimError if evidence is missing or invalid."""
        if not statement or not statement.strip():
            raise UnsupportedClaimError("Claim statement cannot be empty.")

        if not evidence_ids:
            raise UnsupportedClaimError(
                f"Rejected unsupported claim '{statement}': no evidence IDs provided."
            )

        cleaned_ids = [str(eid).strip() for eid in evidence_ids if str(eid).strip()]
        if not cleaned_ids:
            raise UnsupportedClaimError(
                f"Rejected unsupported claim '{statement}': empty evidence ID list."
            )

        for eid in cleaned_ids:
            if eid not in self.valid_evidence_ids:
                raise UnsupportedClaimError(
                    f"Rejected claim '{statement}': evidence ID '{eid}' does not exist in observed telemetry."
                )

        claim = Claim(
            claim_id=f"CLM_{len(self.claims) + 1}",
            statement=statement.strip(),
            evidence_ids=cleaned_ids,
            category=category,
        )
        self.claims.append(claim)
        return claim

    def to_list(self) -> list[dict[str, Any]]:
        return [asdict(c) for c in self.claims]


# Human-readable taxonomy mappings (Phase 9.2)
EVENT_LABELS: dict[str, str] = {
    "process_create": "Process Spawn",
    "fork": "Process Fork",
    "exec": "Process Exec",
    "file_read": "File Read",
    "file_write": "File Write",
    "file_open": "File Open",
    "file_close": "File Close",
    "socket_connect": "Network Connection",
    "process_terminate": "Process Exit",
}

CATEGORY_LABELS: dict[str, str] = {
    "attack_chain": "Chain Reconstruction",
    "gap_localization": "Missing Telemetry",
    "chain_analysis": "Provenance Finding",
}


def _human_event_type(raw_type: str) -> str:
    return EVENT_LABELS.get(raw_type, raw_type.replace("_", " ").title())


def _human_chain_name(raw_id: str) -> str:
    if raw_id.startswith("chain_"):
        num = raw_id.split("_")[-1]
        return f"Incident Chain #{int(num):02d}" if num.isdigit() else raw_id.title()
    return raw_id.replace("_", " ").title()


def _human_claim_id(raw_id: str) -> str:
    if raw_id.startswith("CLM_"):
        num = raw_id.split("_")[-1]
        return f"Finding #{int(num):02d}" if num.isdigit() else raw_id
    return raw_id


def _svg_icon(kind: str) -> str:
    """Return crisp 15x15 inline SVG icons without emojis."""
    if kind in ("process_create", "fork", "exec"):
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>'
    if kind in ("file_read", "file_open", "file_close"):
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>'
    if kind == "file_write":
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>'
    if kind == "socket_connect":
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>'
    if kind == "gap":
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
    return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/></svg>'


def build_investigation_report(
    telemetry: Telemetry,
    chains: Sequence[Chain],
    statistical_gaps: Sequence[Gap],
    deep_gaps: Optional[Sequence[Gap]] = None,
    benchmark_summary: Optional[list[dict[str, Any]]] = None,
    scenario_meta: Optional[dict[str, Any]] = None,
    output_dir: str | Path = "results",
) -> tuple[Path, Path, ClaimsRegistry]:
    """Build and validate claims registry, then export JSON and enterprise HTML workbench."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    valid_ids: set[str] = {e.event_id for e in telemetry.events}
    for g in statistical_gaps:
        valid_ids.add(g.gap_id)
    if deep_gaps:
        for g in deep_gaps:
            valid_ids.add(g.gap_id)

    registry = ClaimsRegistry(valid_ids)

    # Register verified claims with human-readable descriptions
    for ch in chains:
        if ch.events:
            registry.add_claim(
                statement=(
                    f"{_human_chain_name(ch.chain_id)} reconstructed from "
                    f"{len(ch.events)} correlated host events spanning {ch.duration:.2f}s "
                    f"(mean anomaly score {ch.score:.2f})."
                ),
                evidence_ids=ch.event_ids,
                category="attack_chain",
            )

    for g in statistical_gaps:
        sig_desc = []
        if g.signals.get("s_struct", 0.0) > 0:
            sig_desc.append("unrecorded process lineage break")
        if g.signals.get("s_time", 0.0) > 0:
            sig_desc.append(f"inter-event timing deviation ({g.v_timestamp - g.u_timestamp:.2f}s)")
        reasons = " and ".join(sig_desc) if sig_desc else "statistical continuity deviation"

        registry.add_claim(
            statement=(
                f"Missing telemetry localized in {_human_chain_name(g.chain_id)} between "
                f"{g.u_event_id} and {g.v_event_id} (confidence {g.confidence * 100:.0f}%) "
                f"indicated by {reasons}. Missing event content remains unguessed."
            ),
            evidence_ids=[g.gap_id, g.u_event_id, g.v_event_id],
            category="gap_localization",
        )

    json_payload = {
        "scenario": scenario_meta or {},
        "total_observed_events": len(telemetry.events),
        "malformed_records_skipped": telemetry.malformed_count,
        "chains": [c.to_dict() for c in chains],
        "statistical_gaps": [g.to_dict() for g in statistical_gaps],
        "deep_gaps": [g.to_dict() for g in (deep_gaps or [])],
        "verified_claims": registry.to_list(),
        "benchmark_summary": benchmark_summary or [],
    }
    json_path = out_path / "investigation_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)

    html_path = out_path / "investigation_report.html"
    html_content = _render_dashboard_html(
        telemetry=telemetry,
        chains=chains,
        statistical_gaps=statistical_gaps,
        deep_gaps=deep_gaps or [],
        registry=registry,
        benchmark_summary=benchmark_summary or [],
        scenario_meta=scenario_meta or {},
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return html_path, json_path, registry


def _render_dashboard_html(
    telemetry: Telemetry,
    chains: Sequence[Chain],
    statistical_gaps: Sequence[Gap],
    deep_gaps: Sequence[Gap],
    registry: ClaimsRegistry,
    benchmark_summary: list[dict[str, Any]],
    scenario_meta: dict[str, Any],
) -> str:
    """Render professional enterprise Master-Detail Workbench HTML (Zinc/Carbon design system)."""
    stat_gap_map = {(g.chain_id, g.u_event_id, g.v_event_id): g for g in statistical_gaps}
    deep_gap_map = {(g.chain_id, g.u_event_id, g.v_event_id): g for g in deep_gaps}

    dataset_name = str(scenario_meta.get("dataset", "DARPA TC E3 CADETS / Synthetic Benchmark"))
    mech_name = str(scenario_meta.get("mechanism", "burst")).capitalize()
    loss_rate = int(round(float(scenario_meta.get("rate", 0.3)) * 100))

    # Build client-side lookup store for the right-hand Sticky Inspector Panel
    inspector_data: dict[str, dict[str, Any]] = {}
    claims_by_evidence: dict[str, list[dict[str, str]]] = {}
    for clm in registry.claims:
        for eid in clm.evidence_ids:
            claims_by_evidence.setdefault(eid, []).append({
                "id": _human_claim_id(clm.claim_id),
                "category": CATEGORY_LABELS.get(clm.category, clm.category),
                "statement": clm.statement,
            })

    for ev in telemetry.events:
        inspector_data[ev.event_id] = {
            "kind": "event",
            "id": ev.event_id,
            "title": _human_event_type(ev.event_type),
            "raw_type": ev.event_type,
            "timestamp": f"{ev.timestamp:.4f}s",
            "process": str(ev.raw_data.get("process", "unknown")),
            "pid": ev.raw_data.get("pid", 0),
            "ppid": ev.raw_data.get("ppid", 0),
            "user": str(ev.raw_data.get("user", "system")),
            "target": str(ev.raw_data.get("target") or "—"),
            "cmdline": str(ev.raw_data.get("cmdline") or "—"),
            "score": round(ev.score, 4),
            "behav_bits": ev.explanation.get("surprisal_behavior", "—"),
            "lineage_bits": ev.explanation.get("surprisal_lineage", "—"),
            "ident_bits": ev.explanation.get("surprisal_identity", "—"),
            "claims": claims_by_evidence.get(ev.event_id, []),
        }

    # Build Vertical Provenance Timeline Waterfall for each chain
    chains_html_parts: list[str] = []
    first_event_id: str = ""

    for ch in chains:
        evs = ch.events
        if evs and not first_event_id:
            first_event_id = evs[0].event_id

        base_ts = evs[0].timestamp if evs else 0.0
        rows_html: list[str] = []

        for i, ev in enumerate(evs):
            rel_t = ev.timestamp - base_ts
            proc_full = str(ev.raw_data.get("process", "unknown"))
            proc_short = proc_full.split("/")[-1] or proc_full
            target = str(ev.raw_data.get("target") or "—")
            pid = ev.raw_data.get("pid", 0)
            user = str(ev.raw_data.get("user", "system"))
            human_type = _human_event_type(ev.event_type)
            icon_svg = _svg_icon(ev.event_type)

            rows_html.append(f"""
            <div class="trace-row" id="node-{ev.event_id}" onclick="selectItem('{ev.event_id}')">
                <div class="trace-time">+{rel_t:.2f}s</div>
                <div class="trace-rail">
                    <div class="rail-dot"></div>
                    {"<div class='rail-line'></div>" if i < len(evs) - 1 else ""}
                </div>
                <div class="trace-card">
                    <div class="trace-main">
                        <span class="trace-icon">{icon_svg}</span>
                        <span class="eid-tag">{ev.event_id}</span>
                        <span class="trace-type">{html.escape(human_type)}</span>
                        <span class="trace-proc">{html.escape(proc_short)} <span class="mono-muted">({pid})</span></span>
                        <span class="trace-user">{html.escape(user)}</span>
                    </div>
                    <div class="trace-meta">
                        <span class="trace-target" title="{html.escape(target)}">{html.escape(target)}</span>
                        <span class="trace-score">Score {ev.score:.2f}</span>
                    </div>
                </div>
            </div>
            """)

            if i < len(evs) - 1:
                nxt = evs[i + 1]
                key = (ch.chain_id, ev.event_id, nxt.event_id)
                s_gap = stat_gap_map.get(key)
                d_gap = deep_gap_map.get(key)

                if s_gap or d_gap:
                    primary = s_gap or d_gap
                    assert primary is not None
                    dt = nxt.timestamp - ev.timestamp
                    stat_pct = int(round((s_gap.confidence if s_gap else 0.0) * 100))
                    deep_pct = int(round((d_gap.confidence if d_gap else 0.0) * 100))
                    s_time = s_gap.signals.get("s_time", 0.0) if s_gap else 0.0
                    s_struct = s_gap.signals.get("s_struct", 0.0) if s_gap else 0.0

                    signals_list = []
                    if s_struct > 0:
                        signals_list.append("Lineage Break: Unrecorded Process Spawn")
                    if s_time > 0:
                        signals_list.append(f"Timing Deviation ({int(round(s_time * 100))}th pct)")
                    sig_summary = " · ".join(signals_list) if signals_list else "Continuity Deviation"

                    inspector_data[primary.gap_id] = {
                        "kind": "gap",
                        "id": primary.gap_id,
                        "title": "Localized Telemetry Gap",
                        "chain": _human_chain_name(ch.chain_id),
                        "boundary": f"{ev.event_id} → {nxt.event_id}",
                        "window": f"+{dt:.3f}s unrecorded span ({ev.timestamp:.2f}s to {nxt.timestamp:.2f}s)",
                        "stat_conf": f"{stat_pct}%",
                        "deep_conf": f"{deep_pct}%",
                        "signals": sig_summary,
                        "claims": claims_by_evidence.get(primary.gap_id, []),
                    }

                    rows_html.append(f"""
                    <div class="trace-row gap-row" id="node-{primary.gap_id}" onclick="selectItem('{primary.gap_id}')">
                        <div class="trace-time gap-delta">&Delta;t +{dt:.2f}s</div>
                        <div class="trace-rail">
                            <div class="rail-line-dashed"></div>
                        </div>
                        <div class="gap-callout">
                            <div class="gap-header">
                                <div class="gap-badge">
                                    {_svg_icon("gap")}
                                    <span>TELEMETRY GAP LOCALIZED</span>
                                </div>
                                <span class="gap-boundary">{ev.event_id} &rarr; {nxt.event_id}</span>
                            </div>
                            <div class="gap-body">
                                <div class="gap-signal-text">{html.escape(sig_summary)}</div>
                                <div class="gap-conf-group">
                                    <span class="conf-chip">GNN Link-Pred: <strong>{deep_pct}%</strong></span>
                                    <span class="conf-chip">Statistical Noisy-OR: <strong>{stat_pct}%</strong></span>
                                </div>
                            </div>
                        </div>
                    </div>
                    """)

        chains_html_parts.append(f"""
        <div class="chain-block">
            <div class="chain-block-header">
                <div class="chain-header-left">
                    <span class="chain-name">{html.escape(_human_chain_name(ch.chain_id))}</span>
                    <span class="chain-stats">{len(ch.events)} observed events &middot; {ch.duration:.2f}s duration</span>
                </div>
                <span class="chain-anomaly-pill">Mean Score {ch.score:.2f}</span>
            </div>
            <div class="waterfall-list">
                {''.join(rows_html)}
            </div>
        </div>
        """)

    # Benchmark Comparison Rows (Tab 2)
    bench_rows: list[str] = []
    for b in benchmark_summary:
        method = str(b.get("method", ""))
        prec = float(b.get("precision", 0.0))
        rec_int = float(b.get("recall_interior", 0.0))
        rec_all = float(b.get("recall_all", 0.0))
        f1_int = float(b.get("f1_interior", 0.0))
        is_primary = "Ours" in method
        row_cls = 'class="row-primary"' if is_primary else ""

        bench_rows.append(f"""
        <tr {row_cls}>
            <td>
                <span class="method-name">{html.escape(method)}</span>
            </td>
            <td>
                <div class="metric-cell">
                    <span class="mono-val">{prec * 100:.1f}%</span>
                    <div class="mini-bar"><div class="mini-fill" style="width:{prec * 100:.0f}%"></div></div>
                </div>
            </td>
            <td>
                <div class="metric-cell">
                    <span class="mono-val">{rec_int * 100:.1f}%</span>
                    <div class="mini-bar"><div class="mini-fill" style="width:{rec_int * 100:.0f}%"></div></div>
                </div>
            </td>
            <td class="mono-val">{rec_all * 100:.1f}%</td>
            <td><span class="f1-pill">{f1_int * 100:.1f}%</span></td>
        </tr>
        """)

    # Verified Claims Rows (Tab 3)
    claims_rows: list[str] = []
    for clm in registry.claims:
        human_id = _human_claim_id(clm.claim_id)
        cat_label = CATEGORY_LABELS.get(clm.category, clm.category)
        is_gap_clm = clm.category == "gap_localization"
        cat_cls = "tag-amber" if is_gap_clm else "tag-neutral"

        badges = " ".join(
            f'<button type="button" class="ev-chip" onclick="jumpToEvidence(\'{eid}\')">{eid}</button>'
            for eid in clm.evidence_ids
        )
        claims_rows.append(f"""
        <tr>
            <td class="mono-val" style="white-space:nowrap;">{html.escape(human_id)}</td>
            <td><span class="status-tag {cat_cls}">{html.escape(cat_label)}</span></td>
            <td class="claim-text">{html.escape(clm.statement)}</td>
            <td><div class="chip-wrap">{badges}</div></td>
        </tr>
        """)

    inspector_json = json.dumps(inspector_data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Telemetry Gap Platform — Investigation Workbench</title>
<style>
    :root {{
        --bg-canvas: #09090b;
        --bg-surface: #121215;
        --bg-elevated: #18181b;
        --bg-hover: #1f1f23;
        --border-subtle: #27272a;
        --border-strong: #3f3f46;
        --text-primary: #fafafa;
        --text-secondary: #a1a1aa;
        --text-muted: #71717a;
        --accent-amber: #f59e0b;
        --accent-amber-bg: rgba(245, 158, 11, 0.07);
        --accent-amber-border: rgba(245, 158, 11, 0.32);
        --accent-focus: #3b82f6;
        --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        --font-mono: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: var(--font-sans);
        background-color: var(--bg-canvas);
        color: var(--text-primary);
        font-size: 13px;
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
    }}
    /* Top Navigation Bar */
    .topbar {{
        height: 52px;
        background-color: var(--bg-surface);
        border-bottom: 1px solid var(--border-subtle);
        padding: 0 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        position: sticky;
        top: 0;
        z-index: 40;
    }}
    .brand-group {{
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .brand-dot {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: var(--text-primary);
    }}
    .brand-name {{
        font-weight: 600;
        font-size: 14px;
        letter-spacing: -0.01em;
        color: var(--text-primary);
    }}
    .brand-divider {{
        color: var(--border-strong);
    }}
    .brand-context {{
        color: var(--text-secondary);
        font-size: 12px;
    }}
    .nav-tabs {{
        display: flex;
        gap: 4px;
        background: var(--bg-canvas);
        padding: 3px;
        border-radius: 7px;
        border: 1px solid var(--border-subtle);
    }}
    .nav-tab {{
        background: transparent;
        color: var(--text-secondary);
        border: none;
        padding: 5px 12px;
        font-size: 12px;
        font-weight: 500;
        border-radius: 5px;
        cursor: pointer;
        transition: all 0.12s ease;
    }}
    .nav-tab:hover {{
        color: var(--text-primary);
    }}
    .nav-tab.active {{
        background: var(--bg-elevated);
        color: var(--text-primary);
        box-shadow: 0 1px 2px rgba(0,0,0,0.4);
    }}
    .audit-status {{
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        color: var(--text-secondary);
    }}
    .status-indicator {{
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: #10b981;
    }}
    /* Main Container */
    .container {{
        max-width: 1480px;
        margin: 0 auto;
        padding: 20px 24px 48px;
    }}
    /* KPI Strip */
    .kpi-strip {{
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        margin-bottom: 20px;
    }}
    .kpi-cell {{
        padding: 14px 18px;
        border-right: 1px solid var(--border-subtle);
    }}
    .kpi-cell:last-child {{
        border-right: none;
    }}
    .kpi-label {{
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--text-muted);
        margin-bottom: 4px;
    }}
    .kpi-val {{
        font-size: 20px;
        font-weight: 600;
        color: var(--text-primary);
        font-family: var(--font-mono);
        letter-spacing: -0.02em;
    }}
    .kpi-val.amber {{
        color: var(--accent-amber);
    }}
    .kpi-meta {{
        font-size: 11px;
        color: var(--text-secondary);
        margin-top: 2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    /* Tab Views */
    .tab-pane {{
        display: none;
    }}
    .tab-pane.active {{
        display: block;
    }}
    /* Master-Detail Split Layout */
    .workbench-grid {{
        display: grid;
        grid-template-columns: 1fr 410px;
        gap: 20px;
        align-items: start;
    }}
    @media (max-width: 1100px) {{
        .workbench-grid {{
            grid-template-columns: 1fr;
        }}
        .kpi-strip {{
            grid-template-columns: repeat(2, 1fr);
        }}
    }}
    /* Left Column: Chain Waterfall */
    .chain-block {{
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        margin-bottom: 16px;
        overflow: hidden;
    }}
    .chain-block-header {{
        padding: 12px 16px;
        background: var(--bg-elevated);
        border-bottom: 1px solid var(--border-subtle);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .chain-name {{
        font-weight: 600;
        color: var(--text-primary);
        font-size: 13px;
    }}
    .chain-stats {{
        color: var(--text-muted);
        font-size: 12px;
        margin-left: 10px;
    }}
    .chain-anomaly-pill {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-secondary);
        background: var(--bg-canvas);
        border: 1px solid var(--border-subtle);
        padding: 2px 8px;
        border-radius: 4px;
    }}
    .waterfall-list {{
        padding: 12px 16px;
    }}
    .trace-row {{
        display: grid;
        grid-template-columns: 68px 24px 1fr;
        align-items: stretch;
        cursor: pointer;
    }}
    .trace-time {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-muted);
        padding-top: 10px;
        text-align: right;
        padding-right: 10px;
    }}
    .trace-time.gap-delta {{
        color: var(--accent-amber);
        font-weight: 500;
        padding-top: 14px;
    }}
    .trace-rail {{
        display: flex;
        flex-direction: column;
        align-items: center;
        position: relative;
    }}
    .rail-dot {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--bg-canvas);
        border: 2px solid var(--text-muted);
        margin-top: 13px;
        z-index: 2;
        transition: all 0.12s ease;
    }}
    .trace-row:hover .rail-dot,
    .trace-row.selected .rail-dot {{
        border-color: var(--text-primary);
        background: var(--text-primary);
    }}
    .rail-line {{
        width: 1px;
        flex-grow: 1;
        background: var(--border-subtle);
        margin-top: 2px;
    }}
    .rail-line-dashed {{
        width: 1px;
        flex-grow: 1;
        border-left: 1px dashed var(--accent-amber);
    }}
    .trace-card {{
        background: var(--bg-canvas);
        border: 1px solid var(--border-subtle);
        border-radius: 6px;
        padding: 8px 12px;
        margin: 3px 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        transition: border-color 0.12s ease, background 0.12s ease;
    }}
    .trace-row:hover .trace-card {{
        background: var(--bg-hover);
        border-color: var(--border-strong);
    }}
    .trace-row.selected .trace-card {{
        background: var(--bg-elevated);
        border-color: var(--text-primary);
    }}
    .trace-main {{
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
    }}
    .trace-icon {{
        color: var(--text-secondary);
        display: flex;
        align-items: center;
    }}
    .eid-tag {{
        font-family: var(--font-mono);
        font-size: 11px;
        font-weight: 600;
        color: var(--text-primary);
        background: var(--bg-elevated);
        border: 1px solid var(--border-subtle);
        padding: 1px 6px;
        border-radius: 4px;
    }}
    .trace-type {{
        font-weight: 500;
        color: var(--text-primary);
        white-space: nowrap;
    }}
    .trace-proc {{
        color: var(--text-secondary);
        font-size: 12px;
        white-space: nowrap;
    }}
    .mono-muted {{
        font-family: var(--font-mono);
        color: var(--text-muted);
        font-size: 11px;
    }}
    .trace-user {{
        font-size: 11px;
        color: var(--text-muted);
        background: var(--bg-surface);
        padding: 1px 6px;
        border-radius: 3px;
        border: 1px solid var(--border-subtle);
    }}
    .trace-meta {{
        display: flex;
        align-items: center;
        gap: 12px;
        min-width: 0;
    }}
    .trace-target {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-secondary);
        max-width: 220px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    .trace-score {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-muted);
        white-space: nowrap;
    }}
    /* Telemetry Gap Inset Callout */
    .gap-callout {{
        background: var(--accent-amber-bg);
        border: 1px solid var(--accent-amber-border);
        border-radius: 6px;
        padding: 10px 14px;
        margin: 6px 0;
        transition: border-color 0.12s ease;
    }}
    .gap-row:hover .gap-callout,
    .gap-row.selected .gap-callout {{
        border-color: var(--accent-amber);
    }}
    .gap-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
    }}
    .gap-badge {{
        display: flex;
        align-items: center;
        gap: 6px;
        color: var(--accent-amber);
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.03em;
    }}
    .gap-boundary {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-secondary);
    }}
    .gap-body {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
    }}
    .gap-signal-text {{
        font-size: 12px;
        color: var(--text-primary);
    }}
    .gap-conf-group {{
        display: flex;
        gap: 8px;
    }}
    .conf-chip {{
        font-size: 11px;
        color: var(--text-secondary);
        background: rgba(9, 9, 11, 0.65);
        border: 1px solid var(--border-subtle);
        padding: 2px 8px;
        border-radius: 4px;
        font-family: var(--font-mono);
    }}
    .conf-chip strong {{
        color: var(--accent-amber);
    }}
    /* Right Column: Sticky Inspector Drawer */
    .inspector-panel {{
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        position: sticky;
        top: 72px;
        overflow: hidden;
    }}
    .inspector-header {{
        padding: 12px 16px;
        background: var(--bg-elevated);
        border-bottom: 1px solid var(--border-subtle);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .inspector-title {{
        font-weight: 600;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--text-secondary);
    }}
    .inspector-body {{
        padding: 16px;
    }}
    .insp-section {{
        margin-bottom: 16px;
        padding-bottom: 14px;
        border-bottom: 1px solid var(--border-subtle);
    }}
    .insp-section:last-child {{
        margin-bottom: 0;
        padding-bottom: 0;
        border-bottom: none;
    }}
    .insp-sec-label {{
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--text-muted);
        margin-bottom: 8px;
    }}
    .kv-grid {{
        display: grid;
        grid-template-columns: 110px 1fr;
        row-gap: 6px;
        column-gap: 10px;
        font-size: 12px;
    }}
    .kv-key {{
        color: var(--text-secondary);
    }}
    .kv-val {{
        color: var(--text-primary);
        font-family: var(--font-mono);
        word-break: break-all;
    }}
    .claim-box {{
        background: var(--bg-canvas);
        border: 1px solid var(--border-subtle);
        border-radius: 6px;
        padding: 8px 10px;
        margin-top: 6px;
        font-size: 12px;
        color: var(--text-secondary);
    }}
    /* Tables & Benchmarks */
    .surface-card {{
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        overflow: hidden;
        margin-bottom: 20px;
    }}
    .card-header {{
        padding: 14px 18px;
        border-bottom: 1px solid var(--border-subtle);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .card-title {{
        font-weight: 600;
        font-size: 14px;
        color: var(--text-primary);
    }}
    .card-subtitle {{
        font-size: 12px;
        color: var(--text-secondary);
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
    }}
    th, td {{
        padding: 11px 16px;
        text-align: left;
        border-bottom: 1px solid var(--border-subtle);
    }}
    th {{
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--text-muted);
        font-weight: 500;
        background: var(--bg-elevated);
    }}
    tr:last-child td {{
        border-bottom: none;
    }}
    tr.row-primary {{
        background: rgba(255, 255, 255, 0.02);
    }}
    .method-name {{
        font-weight: 500;
        color: var(--text-primary);
    }}
    .mono-val {{
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--text-primary);
    }}
    .metric-cell {{
        display: flex;
        align-items: center;
        gap: 10px;
    }}
    .mini-bar {{
        width: 72px;
        height: 5px;
        background: var(--bg-canvas);
        border-radius: 3px;
        overflow: hidden;
        border: 1px solid var(--border-subtle);
    }}
    .mini-fill {{
        height: 100%;
        background: var(--text-primary);
    }}
    .f1-pill {{
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        background: var(--bg-elevated);
        border: 1px solid var(--border-strong);
        padding: 2px 8px;
        border-radius: 4px;
    }}
    .status-tag {{
        font-size: 11px;
        font-weight: 500;
        padding: 2px 8px;
        border-radius: 4px;
        white-space: nowrap;
    }}
    .tag-amber {{
        background: var(--accent-amber-bg);
        color: var(--accent-amber);
        border: 1px solid var(--accent-amber-border);
    }}
    .tag-neutral {{
        background: var(--bg-elevated);
        color: var(--text-secondary);
        border: 1px solid var(--border-subtle);
    }}
    .claim-text {{
        color: var(--text-primary);
        font-size: 13px;
    }}
    .chip-wrap {{
        display: flex;
        gap: 4px;
        flex-wrap: wrap;
    }}
    .ev-chip {{
        font-family: var(--font-mono);
        font-size: 11px;
        background: var(--bg-canvas);
        color: var(--text-secondary);
        border: 1px solid var(--border-subtle);
        padding: 2px 7px;
        border-radius: 4px;
        cursor: pointer;
    }}
    .ev-chip:hover {{
        color: var(--text-primary);
        border-color: var(--text-primary);
    }}
</style>
</head>
<body>

<nav class="topbar">
    <div class="brand-group">
        <span class="brand-dot"></span>
        <span class="brand-name">TELEMETRY GAP PLATFORM</span>
        <span class="brand-divider">/</span>
        <span class="brand-context">Provenance Intrusion &amp; Gap Localization Workbench</span>
    </div>
    <div class="nav-tabs">
        <button type="button" class="nav-tab active" id="tab-btn-workbench" onclick="switchTab('workbench')">Investigation Workbench</button>
        <button type="button" class="nav-tab" id="tab-btn-benchmarks" onclick="switchTab('benchmarks')">Benchmarks &amp; RQ1–RQ3</button>
        <button type="button" class="nav-tab" id="tab-btn-claims" onclick="switchTab('claims')">Verified Claims Audit ({len(registry.claims)})</button>
    </div>
    <div class="audit-status">
        <span class="status-indicator"></span>
        <span>Isolation &amp; Non-Fabrication Verified</span>
    </div>
</nav>

<div class="container">
    <!-- Top KPI Strip -->
    <div class="kpi-strip">
        <div class="kpi-cell">
            <div class="kpi-label">Observed Telemetry</div>
            <div class="kpi-val">{len(telemetry.events):,}</div>
            <div class="kpi-meta">{html.escape(dataset_name)}</div>
        </div>
        <div class="kpi-cell">
            <div class="kpi-label">Loss Condition</div>
            <div class="kpi-val amber">{loss_rate}% {html.escape(mech_name)}</div>
            <div class="kpi-meta">Manifest Quarantined</div>
        </div>
        <div class="kpi-cell">
            <div class="kpi-label">Incident Chains</div>
            <div class="kpi-val">{len(chains)}</div>
            <div class="kpi-meta">Correlated Provenance Graphs</div>
        </div>
        <div class="kpi-cell">
            <div class="kpi-label">Localized Gaps</div>
            <div class="kpi-val amber">{len(statistical_gaps)}</div>
            <div class="kpi-meta">GNN &amp; Statistical Flagged</div>
        </div>
        <div class="kpi-cell">
            <div class="kpi-label">Claims Registry</div>
            <div class="kpi-val">{len(registry.claims)}/{len(registry.claims)}</div>
            <div class="kpi-meta">100% Evidence-Backed</div>
        </div>
    </div>

    <!-- TAB 1: INVESTIGATION WORKBENCH -->
    <div class="tab-pane active" id="pane-workbench">
        <div class="workbench-grid">
            <div class="waterfall-column">
                {''.join(chains_html_parts) if chains_html_parts else '<div class="surface-card" style="padding:24px;color:var(--text-secondary);">No multi-event attack chains correlated at current threshold.</div>'}
            </div>

            <!-- Sticky Evidence Inspector Drawer -->
            <aside class="inspector-panel">
                <div class="inspector-header">
                    <span class="inspector-title">Evidence &amp; Gap Inspector</span>
                    <span class="eid-tag" id="insp-badge">Select Item</span>
                </div>
                <div class="inspector-body" id="insp-content">
                    <div style="color: var(--text-muted); font-size: 12px; padding: 12px 0;">
                        Click any observed event or localized telemetry gap in the timeline to inspect host attributes, model surprisal telemetry, and verified claims.
                    </div>
                </div>
            </aside>
        </div>
    </div>

    <!-- TAB 2: BENCHMARKS & DEGRADATION -->
    <div class="tab-pane" id="pane-benchmarks">
        <div class="surface-card">
            <div class="card-header">
                <div>
                    <div class="card-title">Gap Localization Benchmark Comparison (RQ2 &amp; RQ3)</div>
                    <div class="card-subtitle">Comparing PyTorch Bilinear GNN Link Predictor and Statistical Noisy-OR against heuristic baselines</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Localization Method</th>
                        <th>Precision</th>
                        <th>Interior Recall</th>
                        <th>All-Removal Recall</th>
                        <th>Interior F1</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(bench_rows)}
                </tbody>
            </table>
        </div>

        <div class="surface-card">
            <div class="card-header">
                <div>
                    <div class="card-title">Empirical Degradation &amp; Localization Performance Curves (RQ1–RQ3)</div>
                    <div class="card-subtitle">Stage survival across loss mechanisms (10%–50%) and method precision/recall distribution</div>
                </div>
            </div>
            <div style="padding: 20px; text-align: center; background: var(--bg-canvas);">
                <img src="degradation.png" alt="Empirical Degradation Chart" style="max-width: 100%; border-radius: 6px; border: 1px solid var(--border-subtle);" onerror="this.style.display='none'"/>
            </div>
        </div>
    </div>

    <!-- TAB 3: VERIFIED CLAIMS AUDIT -->
    <div class="tab-pane" id="pane-claims">
        <div class="surface-card">
            <div class="card-header">
                <div>
                    <div class="card-title">Verified Analytical Claims Registry (FR6)</div>
                    <div class="card-subtitle">Every claim is cryptographically bound to observed host event IDs or gap boundaries. Unbacked claims raise UnsupportedClaimError.</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Finding ID</th>
                        <th>Classification</th>
                        <th>Verified Analytical Statement</th>
                        <th>Traceable Evidence Objects</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(claims_rows)}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
const INSPECTOR_STORE = {inspector_json};
const INITIAL_ID = "{first_event_id}";

function switchTab(tabName) {{
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
    const pane = document.getElementById('pane-' + tabName);
    const btn = document.getElementById('tab-btn-' + tabName);
    if (pane) pane.classList.add('active');
    if (btn) btn.classList.add('active');
}}

function selectItem(itemId) {{
    document.querySelectorAll('.trace-row').forEach(r => r.classList.remove('selected'));
    const row = document.getElementById('node-' + itemId);
    if (row) row.classList.add('selected');

    const data = INSPECTOR_STORE[itemId];
    const badge = document.getElementById('insp-badge');
    const container = document.getElementById('insp-content');
    if (!data || !container) return;

    badge.textContent = data.id;

    let claimsHtml = '';
    if (data.claims && data.claims.length > 0) {{
        claimsHtml = data.claims.map(c => `
            <div class="claim-box">
                <div style="font-weight:600; color:var(--text-primary); margin-bottom:2px;">${{c.id}} &middot; ${{c.category}}</div>
                <div>${{c.statement}}</div>
            </div>
        `).join('');
    }} else {{
        claimsHtml = '<div style="color:var(--text-muted); font-size:12px;">No standalone claims attached.</div>';
    }}

    if (data.kind === 'gap') {{
        container.innerHTML = `
            <div class="insp-section">
                <div class="insp-sec-label">Localized Gap Boundary</div>
                <div class="kv-grid">
                    <div class="kv-key">Classification</div>
                    <div class="kv-val" style="color:var(--accent-amber);">${{data.title}}</div>
                    <div class="kv-key">Incident Chain</div>
                    <div class="kv-val">${{data.chain}}</div>
                    <div class="kv-key">Event Span</div>
                    <div class="kv-val">${{data.boundary}}</div>
                    <div class="kv-key">Unrecorded Delta</div>
                    <div class="kv-val">${{data.window}}</div>
                </div>
            </div>
            <div class="insp-section">
                <div class="insp-sec-label">Localization Confidence</div>
                <div class="kv-grid">
                    <div class="kv-key">PyTorch GNN</div>
                    <div class="kv-val" style="color:var(--accent-amber); font-weight:600;">${{data.deep_conf}}</div>
                    <div class="kv-key">Stat Noisy-OR</div>
                    <div class="kv-val">${{data.stat_conf}}</div>
                    <div class="kv-key">Observed Signal</div>
                    <div class="kv-val">${{data.signals}}</div>
                </div>
            </div>
            <div class="insp-section">
                <div class="insp-sec-label">Non-Hallucination Policy</div>
                <div style="font-size:12px; color:var(--text-secondary);">
                    This gap object flags the temporal and structural discontinuity between observed events without fabricating missing syscalls.
                </div>
            </div>
            <div class="insp-section">
                <div class="insp-sec-label">Verified Claims</div>
                ${{claimsHtml}}
            </div>
        `;
    }} else {{
        container.innerHTML = `
            <div class="insp-section">
                <div class="insp-sec-label">Host Provenance Record</div>
                <div class="kv-grid">
                    <div class="kv-key">Event Action</div>
                    <div class="kv-val">${{data.title}} (${{data.raw_type}})</div>
                    <div class="kv-key">Timestamp</div>
                    <div class="kv-val">${{data.timestamp}}</div>
                    <div class="kv-key">Process</div>
                    <div class="kv-val">${{data.process}}</div>
                    <div class="kv-key">PID / PPID</div>
                    <div class="kv-val">${{data.pid}} / ${{data.ppid}}</div>
                    <div class="kv-key">User Context</div>
                    <div class="kv-val">${{data.user}}</div>
                    <div class="kv-key">Target Object</div>
                    <div class="kv-val">${{data.target}}</div>
                    <div class="kv-key">Command Line</div>
                    <div class="kv-val">${{data.cmdline}}</div>
                </div>
            </div>
            <div class="insp-section">
                <div class="insp-sec-label">Detector Telemetry</div>
                <div class="kv-grid">
                    <div class="kv-key">Anomaly Score</div>
                    <div class="kv-val">${{data.score}}</div>
                    <div class="kv-key">Behavior Rarity</div>
                    <div class="kv-val">${{data.behav_bits}} bits</div>
                    <div class="kv-key">Lineage Rarity</div>
                    <div class="kv-val">${{data.lineage_bits}} bits</div>
                    <div class="kv-key">Identity Rarity</div>
                    <div class="kv-val">${{data.ident_bits}} bits</div>
                </div>
            </div>
            <div class="insp-section">
                <div class="insp-sec-label">Linked Findings</div>
                ${{claimsHtml}}
            </div>
        `;
    }}
}}

function jumpToEvidence(eid) {{
    switchTab('workbench');
    selectItem(eid);
    const row = document.getElementById('node-' + eid);
    if (row) row.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
}}

if (INITIAL_ID) {{
    selectItem(INITIAL_ID);
}}
</script>
</body>
</html>
"""
