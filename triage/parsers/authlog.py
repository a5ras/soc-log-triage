"""Parses Linux auth.log (regex) into Event objects."""

import re
from datetime import datetime, timezone
from pathlib import Path

from triage.models import Event

# Header: "<timestamp> <host> <process>[pid]: <message>".
# Timestamp is either ISO-8601 (rsyslog high precision) or classic "Oct 13 22:00:01".
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<proc>[^:\[\s]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
CLASSIC_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^:\[\s]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)

ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
SUDO_COMMAND = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=")
ROOT_SESSION = re.compile(r"session opened for user root\(uid=0\) by (?P<user>[^(\s]*)")
ANY_IP = re.compile(r"(?:from|rhost=)\s?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

# Processes whose root sessions mean privilege elevation (not e.g. CRON).
ELEVATION_PROCS = {"sudo", "su"}


def _parse_timestamp(raw: str, year: int) -> datetime:
    if raw[0].isdigit():
        return datetime.fromisoformat(raw)
    # Classic syslog has no year and no zone: use `year`, assume UTC.
    ts = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
    return ts.replace(tzinfo=timezone.utc)


def _classify(proc: str, msg: str) -> tuple[str, str | None, str | None]:
    """Return (event_type, src_ip, user) for one log message."""
    if m := ACCEPTED.search(msg):
        return "login_success", m["ip"], m["user"]
    if m := FAILED.search(msg):
        return "login_failed", m["ip"], m["user"]
    if proc in ELEVATION_PROCS:
        if m := SUDO_COMMAND.search(msg):
            return "sudo_root", None, m["user"]
        if m := ROOT_SESSION.search(msg):
            return "sudo_root", None, m["user"] or None
    m = ANY_IP.search(msg)
    return "other", m["ip"] if m else None, None


def parse_line(line: str, year: int) -> Event | None:
    """Parse one auth.log line; return None for lines that are not syslog records."""
    line = line.strip("\x00").strip()
    match = ISO_LINE.match(line) or CLASSIC_LINE.match(line)
    if not match:
        return None
    try:
        timestamp = _parse_timestamp(match["ts"], year)
    except ValueError:
        return None
    event_type, src_ip, user = _classify(match["proc"], match["msg"])
    return Event(
        timestamp=timestamp,
        source="authlog",
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=None,
        user=user,
        raw_line=line,
    )


def parse(path: str | Path, config: dict | None = None, year: int | None = None) -> list[Event]:
    """Parse an auth.log file. Classic timestamps take their year from the file mtime unless `year` is given."""
    path = Path(path)
    if year is None:
        year = datetime.fromtimestamp(path.stat().st_mtime).year
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_line(line, year)
            if event is not None:
                events.append(event)
    return events
