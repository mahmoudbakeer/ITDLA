"""Normalization of raw telemetry records into strongly-typed Telemetry objects."""

from __future__ import annotations

from typing import Any, Mapping
from tgap.schema import Entity, Event, Telemetry


def normalize_records(raw_records: list[dict[str, Any]]) -> Telemetry:
    """Normalize raw log records into structured Telemetry.

    Skips and counts malformed records that lack essential provenance
    information (timestamp, event_type, process).
    """
    events: list[Event] = []
    entities: dict[str, Entity] = {}
    malformed_count = 0

    for idx, rec in enumerate(raw_records):
        if not isinstance(rec, Mapping):
            malformed_count += 1
            continue

        timestamp = rec.get("timestamp")
        event_type = rec.get("event_type")
        process = rec.get("process")
        event_id = str(rec.get("event_id", f"E{idx + 1}"))

        # Validation: timestamp must be a valid float/int >= 0
        try:
            ts_float = float(timestamp)  # type: ignore
            if ts_float < 0:
                malformed_count += 1
                continue
        except (ValueError, TypeError):
            malformed_count += 1
            continue

        # Validation: essential fields must not be empty
        if not event_type or not isinstance(event_type, str):
            malformed_count += 1
            continue
        if not process or not isinstance(process, str):
            malformed_count += 1
            continue

        pid = rec.get("pid", 0)
        ppid = rec.get("ppid", 0)
        user = str(rec.get("user", "unknown"))
        target = rec.get("target")
        cmdline = str(rec.get("cmdline", ""))

        # Create or update Subject Entity (the acting process)
        subject_id = f"proc_{pid}_{process.split('/')[-1]}"
        if subject_id not in entities:
            entities[subject_id] = Entity(
                id=subject_id,
                type="process",
                attributes={
                    "pid": pid,
                    "ppid": ppid,
                    "name": process,
                    "user": user,
                    "cmdline": cmdline,
                },
            )

        # Create Object Entity if target is present
        object_id: str | None = None
        if target:
            target_str = str(target)
            if event_type in ("file_read", "file_write", "file_open", "file_delete"):
                object_id = f"file_{target_str}"
                if object_id not in entities:
                    entities[object_id] = Entity(
                        id=object_id,
                        type="file",
                        attributes={"path": target_str},
                    )
            elif event_type in ("socket_connect", "socket_bind", "socket_listen"):
                object_id = f"sock_{target_str}"
                if object_id not in entities:
                    entities[object_id] = Entity(
                        id=object_id,
                        type="socket",
                        attributes={"address": target_str},
                    )
            elif event_type in ("process_create", "fork", "exec"):
                object_id = f"proc_child_{target_str.split('/')[-1]}"
                if object_id not in entities:
                    entities[object_id] = Entity(
                        id=object_id,
                        type="process",
                        attributes={"name": target_str},
                    )
            else:
                object_id = f"entity_{target_str}"
                if object_id not in entities:
                    entities[object_id] = Entity(
                        id=object_id,
                        type="generic",
                        attributes={"value": target_str},
                    )

        event = Event(
            event_id=event_id,
            timestamp=ts_float,
            event_type=event_type,
            subject_id=subject_id,
            object_id=object_id,
            raw_data=dict(rec),
        )
        events.append(event)

    return Telemetry(events=events, entities=entities, malformed_count=malformed_count)
