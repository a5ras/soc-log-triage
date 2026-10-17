"""Parses Wazuh alerts.json (one JSON object per line) into Event objects."""

import json
from datetime import datetime
from pathlib import Path

from triage.models import Event

# Wazuh rule.id -> normalized event_type. Extend here for new lab rules.
RULE_MAP = {
    "5710": "login_failed",
    "5760": "login_failed",
    "5712": "brute_force",
    "5763": "brute_force",
    "5715": "login_success",
    "5402": "sudo_root",
}


def parse_record(record: dict, raw_line: str) -> Event:
    """Turn one alerts.json record into an Event."""
    data = record.get("data", {})
    return Event(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        source="wazuh",
        event_type=RULE_MAP.get(str(record.get("rule", {}).get("id")), "other"),
        src_ip=data.get("srcip"),
        dst_ip=record.get("agent", {}).get("ip"),
        user=data.get("dstuser") or data.get("srcuser"),
        raw_line=raw_line,
    )


def parse(path: str | Path, config: dict | None = None) -> list[Event]:
    """Parse a Wazuh alerts.json file, skipping truncated or non-JSON lines."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip("\x00").strip()
            if not line:
                continue
            try:
                events.append(parse_record(json.loads(line), line))
            except (ValueError, KeyError, AttributeError):
                continue
    return events
