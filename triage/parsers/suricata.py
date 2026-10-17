"""Parses Suricata eve.json (one JSON object per line) into Event objects."""

import json
from datetime import datetime
from pathlib import Path

from triage.models import Event

DEFAULT_PORT_SCAN_SIDS = {86601, 1000001}


def parse_record(record: dict, raw_line: str, port_scan_sids=DEFAULT_PORT_SCAN_SIDS) -> Event | None:
    """Turn one eve.json record into an Event. Only alerts are kept; telemetry (flow, stats, ...) is skipped."""
    if record.get("event_type") != "alert":
        return None
    sid = record.get("alert", {}).get("signature_id")
    return Event(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        source="suricata",
        event_type="port_scan" if sid in port_scan_sids else "other",
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"),
        user=None,
        raw_line=raw_line,
    )


def parse(path: str | Path, config: dict | None = None) -> list[Event]:
    """Parse an eve.json file, skipping truncated or non-JSON lines."""
    sids = set((config or {}).get("parsers", {}).get("port_scan_sids", DEFAULT_PORT_SCAN_SIDS))
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip("\x00").strip()
            if not line:
                continue
            try:
                event = parse_record(json.loads(line), line, sids)
            except (ValueError, KeyError, AttributeError):
                continue
            if event is not None:
                events.append(event)
    return events
