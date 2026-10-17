"""Maps normalized event types to MITRE ATT&CK technique IDs."""

from triage.models import Event

TECHNIQUES = {
    "T1046": "Network Service Discovery",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1557": "Adversary-in-the-Middle",
    "T1548": "Abuse Elevation Control Mechanism",
}

EVENT_TECHNIQUE = {
    "port_scan": "T1046",
    "brute_force": "T1110",
    "login_failed": "T1110",
    "arp_spoof": "T1557",
    "sudo_root": "T1548",
}

# login_success only means T1078 once correlation has classified the incident as a BREACH.
BREACH_TECHNIQUE = {"login_success": "T1078"}


def map_events(events: list[Event]) -> list[Event]:
    """Fill Event.mitre from the event type alone."""
    for event in events:
        event.mitre = EVENT_TECHNIQUE.get(event.event_type)
    return events


def map_breach(events: list[Event]) -> None:
    """Add the techniques that only apply inside a BREACH incident."""
    for event in events:
        event.mitre = BREACH_TECHNIQUE.get(event.event_type, event.mitre)


def techniques_of(events: list[Event]) -> list[str]:
    """Sorted set of technique ids across events."""
    return sorted({e.mitre for e in events if e.mitre})
