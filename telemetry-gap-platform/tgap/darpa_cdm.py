"""DARPA Transparent Computing CDM (Common Data Model) JSON parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Union


# Standard CDM event type mapping to tgap normalized event types
CDM_EVENT_MAP = {
    "EVENT_FORK": "process_create",
    "EVENT_CLONE": "process_create",
    "EVENT_EXECUTE": "process_create",
    "EVENT_READ": "file_read",
    "EVENT_WRITE": "file_write",
    "EVENT_OPEN": "file_open",
    "EVENT_CLOSE": "file_close",
    "EVENT_MMAP": "file_read",
    "EVENT_MPROTECT": "file_write",
    "EVENT_CONNECT": "socket_connect",
    "EVENT_ACCEPT": "socket_connect",
    "EVENT_SENDTO": "socket_connect",
    "EVENT_RECVFROM": "file_read",
    "EVENT_EXIT": "process_terminate",
    "EVENT_MODIFY_FILE_ATTRIBUTES": "file_write",
}


def _extract_uuid(val: Any) -> str:
    """Helper to unwrap UUID from nested Avro structures."""
    if isinstance(val, dict):
        for k, v in val.items():
            if "UUID" in k or k == "string":
                return str(v)
    return str(val) if val is not None else ""


def _extract_prop(obj: dict[str, Any], key: str) -> str | None:
    """Helper to extract properties from CDM map structure."""
    if not isinstance(obj, dict):
        return None
    props = obj.get("properties", {}).get("map", {}) if isinstance(obj.get("properties"), dict) else {}
    if isinstance(props, dict) and key in props:
        return str(props[key])
    base_props = obj.get("baseObject", {}).get("properties", {}).get("map", {}) if isinstance(obj.get("baseObject"), dict) else {}
    if isinstance(base_props, dict) and key in base_props:
        return str(base_props[key])
    return None


def _extract_string(val: Any) -> str:
    """Extract string value whether stored directly or as an Avro union dict."""
    if isinstance(val, dict):
        return str(val.get("string", ""))
    return str(val) if val is not None else ""


def parse_cdm_records(cdm_data: Union[str, Path, Iterable[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Parse DARPA TC CDM records into raw record dictionaries.

    Accepts a filepath, raw JSON string, or iterable of dicts.
    Extracts Subjects, FileObjects, NetFlowObjects, and Events,
    resolving UUID references into process/file/network names.
    """
    records: list[dict[str, Any]] = []

    if isinstance(cdm_data, (str, Path)):
        p = Path(cdm_data)
        if p.exists() and p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                parsed_items = []
                for line in lines:
                    try:
                        parsed_items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        else:
            try:
                loaded = json.loads(str(cdm_data))
                parsed_items = loaded if isinstance(loaded, list) else [loaded]
            except json.JSONDecodeError:
                parsed_items = []
    else:
        parsed_items = list(cdm_data)

    # UUID symbol lookup tables
    subjects: dict[str, dict[str, Any]] = {}
    objects: dict[str, str] = {}
    raw_events: list[dict[str, Any]] = []

    for item in parsed_items:
        if not isinstance(item, dict):
            continue
        datum = item.get("datum", item)
        if not isinstance(datum, dict):
            continue

        for k, v in datum.items():
            if not isinstance(v, dict):
                continue

            if "Subject" in k:
                uuid = _extract_uuid(v.get("uuid"))
                cmdline = _extract_string(v.get("cmdLine"))
                pid = v.get("cid", 0) or _extract_prop(v, "pid") or 0
                try:
                    pid = int(pid)
                except (ValueError, TypeError):
                    pid = 0
                name = _extract_prop(v, "name") or (cmdline.split()[0] if cmdline else f"proc_{pid}")
                subjects[uuid] = {
                    "name": name,
                    "cmdline": cmdline or name,
                    "pid": pid,
                    "parent_uuid": _extract_uuid(v.get("parentSubject")),
                }
            elif "FileObject" in k:
                uuid = _extract_uuid(v.get("uuid"))
                filename = (
                    _extract_prop(v, "filename")
                    or _extract_prop(v, "path")
                    or _extract_string(v.get("filename"))
                    or v.get("type", "file")
                )
                objects[uuid] = str(filename)
            elif "NetFlowObject" in k:
                uuid = _extract_uuid(v.get("uuid"))
                ip = _extract_string(v.get("remoteAddress")) or "remote_ip"
                port = v.get("remotePort", {}).get("int") if isinstance(v.get("remotePort"), dict) else v.get("remotePort", 0)
                objects[uuid] = f"{ip}:{port}"
            elif "SrcSinkObject" in k or "UnnamedPipeObject" in k:
                uuid = _extract_uuid(v.get("uuid"))
                objects[uuid] = f"pipe_{uuid[:8]}"
            elif "Event" in k:
                raw_events.append(v)

    # Process events
    for idx, ev in enumerate(raw_events, start=1):
        cdm_type = ev.get("type", "EVENT_UNKNOWN")
        mapped_type = CDM_EVENT_MAP.get(cdm_type, cdm_type.lower())

        ts_nanos = ev.get("timestampNanos", 0)
        try:
            ts_num = float(ts_nanos)
            timestamp = ts_num / 1_000_000_000.0 if ts_num > 1_000_000_000 else ts_num
        except (ValueError, TypeError):
            timestamp = float(idx)

        subj_uuid = _extract_uuid(ev.get("subject"))
        subj_info = subjects.get(subj_uuid, {"name": "cadets_process", "cmdline": "cadets_process", "pid": 1000})

        pred_uuid = _extract_uuid(ev.get("predicateObject"))
        target = objects.get(pred_uuid) or (f"obj_{pred_uuid[:8]}" if pred_uuid else None)

        records.append({
            "event_id": f"CDM_{idx}",
            "timestamp": round(timestamp, 4),
            "event_type": mapped_type,
            "process": subj_info["name"],
            "pid": subj_info["pid"],
            "ppid": 0,
            "user": "system",
            "target": target,
            "cmdline": subj_info["cmdline"],
        })

    return records
