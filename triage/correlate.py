"""Groups events by source IP into incidents, classifies them and flags slow attacks."""

from collections import defaultdict

from triage import mitre
from triage.models import Event, Incident

LOCAL = "local"  # incident key for events without a source IP (sudo, host alerts)


def classify(events: list[Event], brute_force_threshold: int) -> str:
    """BREACH / ATTACK / RECON / isolated, decided in that order."""
    types = [e.event_type for e in events]
    has_scan = "port_scan" in types
    has_brute = "brute_force" in types or types.count("login_failed") >= brute_force_threshold
    has_success = "login_success" in types
    if has_success and (has_scan or has_brute):
        return "BREACH"
    if has_brute:
        return "ATTACK"
    if has_scan:
        return "RECON"
    return "isolated"


def incident_score(incident_type: str, events: list[Event], config: dict) -> int:
    """Fixed score by type (not a sum); isolated = highest event severity."""
    if incident_type == "isolated":
        return max((e.severity for e in events), default=0)
    return config["incident_score"][incident_type.lower()]


def build_incident(src_ip: str, events: list[Event], config: dict) -> Incident:
    corr = config["correlation"]
    events = sorted(events, key=lambda e: e.timestamp)
    incident_type = classify(events, corr["brute_force_threshold"])
    if incident_type == "BREACH":
        mitre.map_breach(events)
    first_seen, last_seen = events[0].timestamp, events[-1].timestamp
    span = (last_seen - first_seen).total_seconds()
    return Incident(
        src_ip=src_ip,
        events=events,
        incident_type=incident_type,
        score=incident_score(incident_type, events, config),
        slow_attack_suspected=incident_type in ("BREACH", "ATTACK") and span > corr["window_seconds"],
        first_seen=first_seen,
        last_seen=last_seen,
        mitre_techniques=mitre.techniques_of(events),
    )


def correlate(events: list[Event], config: dict) -> list[Incident]:
    """One source IP = one incident. Returned highest score first."""
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        groups[event.src_ip or LOCAL].append(event)
    incidents = [build_incident(ip, evs, config) for ip, evs in groups.items()]
    return sorted(incidents, key=lambda i: (-i.score, i.first_seen))
