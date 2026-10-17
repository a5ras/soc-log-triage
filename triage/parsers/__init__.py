"""Parsers: one module per log format, each turning a file into a list of Event.

Adding a format = one new module with `parse(path, config) -> list[Event]`,
registered in PARSERS and (optionally) KNOWN_FILES / `detect_format`.
"""

import json
from pathlib import Path

from triage.models import Event
from triage.parsers import authlog, suricata, wazuh

PARSERS = {
    "authlog": authlog.parse,
    "suricata": suricata.parse,
    "wazuh": wazuh.parse,
}

# Files read when --input is a directory.
KNOWN_FILES = {"auth.log": "authlog", "eve.json": "suricata", "alerts.json": "wazuh"}


def detect_format(path: Path) -> str:
    """Pick a parser by file name, else by sniffing the first JSON record."""
    if path.name in KNOWN_FILES:
        return KNOWN_FILES[path.name]
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip("\x00").strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return "authlog"
            if "rule" in record:
                return "wazuh"
            if "event_type" in record:
                return "suricata"
            break
    raise ValueError(f"unrecognized log format: {path}")


def collect_files(inputs: list[str]) -> list[Path]:
    """Expand --input values: files as given, directories to their known files."""
    files = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            files.extend(path / name for name in KNOWN_FILES if (path / name).is_file())
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(item)
    return files


def parse_file(path: str | Path, config: dict | None = None) -> list[Event]:
    path = Path(path)
    return PARSERS[detect_format(path)](path, config)
