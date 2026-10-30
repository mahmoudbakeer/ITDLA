"""Unit tests for normalize (Phase 1)."""

import pytest
from tgap.normalize import normalize_records
from tgap.schema import Telemetry


def test_normalize_valid_records():
    raw_records = [
        {
            "event_id": "E1",
            "timestamp": 100.5,
            "event_type": "process_create",
            "process": "/bin/bash",
            "pid": 1001,
            "ppid": 1000,
            "user": "alice",
            "target": "/bin/bash",
            "cmdline": "bash",
        },
        {
            "event_id": "E2",
            "timestamp": 102.0,
            "event_type": "file_write",
            "process": "/bin/bash",
            "pid": 1001,
            "ppid": 1000,
            "user": "alice",
            "target": "/tmp/output.txt",
            "cmdline": "echo hi > /tmp/output.txt",
        },
        {
            "event_id": "E3",
            "timestamp": 105.0,
            "event_type": "socket_connect",
            "process": "/bin/bash",
            "pid": 1001,
            "ppid": 1000,
            "user": "alice",
            "target": "10.0.0.1:80",
            "cmdline": "curl 10.0.0.1",
        },
    ]

    telemetry = normalize_records(raw_records)
    assert isinstance(telemetry, Telemetry)
    assert len(telemetry.events) == 3
    assert telemetry.malformed_count == 0

    # Check entities
    assert "proc_1001_bash" in telemetry.entities
    assert "file_/tmp/output.txt" in telemetry.entities
    assert "sock_10.0.0.1:80" in telemetry.entities

    e1 = telemetry.get_event("E1")
    assert e1 is not None
    assert e1.timestamp == 100.5
    assert e1.subject_id == "proc_1001_bash"


def test_normalize_malformed_records():
    raw_records = [
        # Valid
        {
            "event_id": "E1",
            "timestamp": 10.0,
            "event_type": "file_read",
            "process": "/bin/cat",
        },
        # Missing timestamp
        {
            "event_id": "E2",
            "event_type": "file_read",
            "process": "/bin/cat",
        },
        # Negative timestamp
        {
            "event_id": "E3",
            "timestamp": -5.0,
            "event_type": "file_read",
            "process": "/bin/cat",
        },
        # Missing event_type
        {
            "event_id": "E4",
            "timestamp": 12.0,
            "process": "/bin/cat",
        },
        # Missing process
        {
            "event_id": "E5",
            "timestamp": 14.0,
            "event_type": "file_read",
        },
        # Non-dict record
        "invalid string record",
    ]

    telemetry = normalize_records(raw_records)
    assert len(telemetry.events) == 1
    assert telemetry.malformed_count == 5
    assert telemetry.events[0].event_id == "E1"


def test_normalize_sorting():
    raw_records = [
        {"event_id": "E2", "timestamp": 200.0, "event_type": "file_read", "process": "p1"},
        {"event_id": "E1", "timestamp": 100.0, "event_type": "file_read", "process": "p1"},
    ]
    telemetry = normalize_records(raw_records)
    assert telemetry.events[0].event_id == "E1"
    assert telemetry.events[1].event_id == "E2"
