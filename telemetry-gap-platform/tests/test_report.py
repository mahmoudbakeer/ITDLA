"""Unit tests for claims registry and evidence report generation (Phase 6)."""

import pytest
from pathlib import Path
from tgap.report import ClaimsRegistry, UnsupportedClaimError, build_investigation_report
from tgap.schema import Chain, Event, Gap, Telemetry


def test_unsupported_claim_raises():
    registry = ClaimsRegistry(valid_evidence_ids={"E1", "E2", "gap_1"})

    # Valid claim succeeds
    clm = registry.add_claim("Observed process execution", evidence_ids=["E1"])
    assert clm.claim_id == "CLM_1"

    # Claim with empty evidence list MUST raise UnsupportedClaimError
    with pytest.raises(UnsupportedClaimError):
        registry.add_claim("Unverified speculation about attacker", evidence_ids=[])

    # Claim referencing non-existent evidence ID MUST raise UnsupportedClaimError
    with pytest.raises(UnsupportedClaimError):
        registry.add_claim("Hallucinated event reference", evidence_ids=["E999_FAKE"])


def test_build_investigation_report_outputs(tmp_path: Path):
    e1 = Event(
        event_id="E1",
        timestamp=100.0,
        event_type="process_create",
        subject_id="p1",
        score=0.92,
        raw_data={"process": "/bin/sh", "pid": 200, "ppid": 100, "user": "svc_web"},
    )
    e2 = Event(
        event_id="E2",
        timestamp=108.5,
        event_type="socket_connect",
        subject_id="p1",
        score=0.95,
        raw_data={"process": "/bin/sh", "pid": 200, "ppid": 100, "user": "root", "target": "198.51.100.1:4444"},
    )
    telem = Telemetry(events=[e1, e2])
    chain = Chain(chain_id="chain_1", events=[e1, e2], score=0.935)
    gap = Gap(
        gap_id="gap_chain_1_E1_E2",
        chain_id="chain_1",
        u_event_id="E1",
        v_event_id="E2",
        u_timestamp=100.0,
        v_timestamp=108.5,
        confidence=0.89,
        signals={"s_time": 0.85, "s_struct": 1.0},
    )

    html_path, json_path, registry = build_investigation_report(
        telemetry=telem,
        chains=[chain],
        statistical_gaps=[gap],
        output_dir=tmp_path,
    )

    assert html_path.exists()
    assert json_path.exists()
    assert len(registry.claims) == 2

    html_text = html_path.read_text(encoding="utf-8")
    assert "TELEMETRY GAP PLATFORM" in html_text
    assert "TELEMETRY GAP LOCALIZED" in html_text
    assert "E1" in html_text
    assert "E2" in html_text
