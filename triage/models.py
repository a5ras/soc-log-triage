"""Data model shared by every pipeline stage: Event and Incident."""

from dataclasses import dataclass, field
from datetime import datetime

EVENT_TYPES = (
    "login_success",
    "login_failed",
    "port_scan",
    "brute_force",
    "sudo_root",
    "arp_spoof",
    "other",
)

INCIDENT_TYPES = ("BREACH", "ATTACK", "RECON", "isolated")


@dataclass
class Event:
    """One normalized log record, from any source."""

    timestamp: datetime
    source: str  # "authlog" | "suricata" | "wazuh"
    event_type: str  # one of EVENT_TYPES
    src_ip: str | None
    dst_ip: str | None
    user: str | None
    raw_line: str
    severity: int = 0  # 0-100, filled by score.py
    is_internal: bool = False  # filled by enrich.py
    in_blocklist: bool = False  # filled by enrich.py
    geo: str | None = None  # filled by enrich.py
    abuse_score: int | None = None  # filled by enrich.py (optional)
    mitre: str | None = None  # technique id, filled by mitre.py


@dataclass
class Incident:
    """All events from one source IP, classified and scored as a whole."""

    src_ip: str
    events: list[Event]  # sorted by timestamp
    incident_type: str  # one of INCIDENT_TYPES
    score: int  # 0-100
    slow_attack_suspected: bool
    first_seen: datetime
    last_seen: datetime
    mitre_techniques: list[str] = field(default_factory=list)
