"""Per-event severity scoring (base by event type + bonuses, capped at 100)."""

from collections import Counter

from triage.models import Event


def severity_class(severity: int, thresholds: dict) -> str:
    """Low (0-29), Medium (30-69) or Critical (70-100) with the default thresholds."""
    if severity <= thresholds["low_max"]:
        return "Low"
    if severity <= thresholds["medium_max"]:
        return "Medium"
    return "Critical"


def score_event(event: Event, prior_failures: int, config: dict) -> int:
    """severity = base + bonuses, capped at 100."""
    scoring = config["scoring"]
    bonus = scoring["bonus"]
    severity = scoring.get(event.event_type, 0)
    if event.in_blocklist:
        severity += bonus["in_blocklist"]
    if not event.is_internal:
        severity += bonus["external_ip"]
    if (
        event.event_type == "login_success"
        and prior_failures >= config["correlation"]["brute_force_threshold"]
    ):
        severity += bonus["success_after_failures"]
    return min(severity, 100)


def score(events: list[Event], config: dict) -> list[Event]:
    """Fill Event.severity; events are walked in time order to count prior failed logins per IP."""
    failures: Counter[str] = Counter()
    for event in sorted(events, key=lambda e: e.timestamp):
        event.severity = score_event(event, failures[event.src_ip], config)
        if event.event_type == "login_failed" and event.src_ip:
            failures[event.src_ip] += 1
    return events
