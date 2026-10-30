"""Unit tests for darpa_cdm parser skeleton (Phase 1)."""

import pytest
from tgap.darpa_cdm import parse_cdm_records


def test_parse_cdm_sample():
    sample_cdm = [
        {
            "datum": {
                "com.bbn.tc.schema.avro.cdm18.Subject": {
                    "uuid": "subj-uuid-1",
                    "cmdLine": {"string": "/usr/bin/python3 script.py"},
                    "properties": {"map": {"name": "/usr/bin/python3", "pid": 4321}},
                }
            }
        },
        {
            "datum": {
                "com.bbn.tc.schema.avro.cdm18.FileObject": {
                    "uuid": "file-uuid-1",
                    "properties": {"map": {"filename": "/etc/hosts"}},
                }
            }
        },
        {
            "datum": {
                "com.bbn.tc.schema.avro.cdm18.Event": {
                    "uuid": "event-uuid-1",
                    "type": "EVENT_READ",
                    "timestampNanos": 1600000000000000000,
                    "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "subj-uuid-1"},
                    "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "file-uuid-1"},
                }
            }
        },
    ]

    records = parse_cdm_records(sample_cdm)
    assert len(records) == 1
    ev = records[0]
    assert ev["event_id"] == "CDM_1"
    assert ev["timestamp"] == 1600000000.0
    assert ev["event_type"] == "file_read"
    assert ev["process"] == "/usr/bin/python3"
    assert ev["pid"] == 4321
    assert ev["target"] == "/etc/hosts"
