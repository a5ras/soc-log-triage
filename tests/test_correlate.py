"""Correlation (BUILD_SPEC §9): the four incident types, the real BREACH, the slow-attack flag."""

from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import SAMPLES
from triage.correlate import correlate
from triage.enrich import enrich
from triage.mitre import map_events
from triage.models import Event
from triage.parsers import collect_files, parse_file
from triage.score import score

T0 = datetime(2026, 10, 13, 20, 0, tzinfo=timezone.utc)


def ev(event_type, seconds=0, src_ip="10.10.10.40", severity=0):
    return Event(T0 + timedelta(seconds=seconds), "authlog", event_type, src_ip, None, None, "", severity=severity)


def run(events, config):
    return correlate(map_events(events), config)


def only(incidents):
    assert len(incidents) == 1
    return incidents[0]


@pytest.mark.parametrize(
    "types, expected, expected_score",
    [
        (["port_scan", "login_failed", "login_success"], "BREACH", 90),
        (["brute_force", "login_success"], "BREACH", 90),
        (["login_failed"] * 5 + ["login_success"], "BREACH", 90),
        (["login_failed"] * 5, "ATTACK", 65),
        (["brute_force"], "ATTACK", 65),
        (["port_scan", "port_scan"], "RECON", 35),
        (["port_scan", "login_failed"], "RECON", 35),
        (["login_failed"] * 4 + ["login_success"], "isolated", None),
    ],
)
def test_incident_types(config, types, expected, expected_score):
    events = [ev(t, seconds=i) for i, t in enumerate(types)]
    incident = only(run(events, config))
    assert incident.incident_type == expected
    if expected_score is not None:
        assert incident.score == expected_score


def test_scan_then_success_is_breach(config):
    incident = only(run([ev("port_scan"), ev("login_success", 60)], config))
    assert incident.incident_type == "BREACH"


def test_isolated_score_is_max_event_severity(config):
    events = [ev("login_success", 0, severity=5), ev("sudo_root", 1, severity=30), ev("other", 2, severity=0)]
    incident = only(run(events, config))
    assert (incident.incident_type, incident.score) == ("isolated", 30)


def test_score_is_by_type_not_a_sum(config):
    events = [ev("login_failed", i, severity=100) for i in range(10)]
    assert only(run(events, config)).score == 65


def test_one_source_ip_one_incident_sorted_by_score(config):
    events = [ev("port_scan", 0, "10.10.10.41"), ev("brute_force", 0, "10.10.10.42"), ev("sudo_root", 0, None, severity=30)]
    incidents = run(events, config)
    assert [(i.src_ip, i.incident_type) for i in incidents] == [
        ("10.10.10.42", "ATTACK"), ("10.10.10.41", "RECON"), ("local", "isolated")]


def test_mitre_valid_accounts_only_in_breach(config):
    breach = only(run([ev("brute_force"), ev("login_success", 1)], config))
    assert breach.mitre_techniques == ["T1078", "T1110"]
    lone = only(run([ev("login_success")], config))
    assert lone.mitre_techniques == []


def test_slow_attack_flag_beyond_window(config):
    events = [ev("login_failed", i) for i in range(5)] + [ev("login_success", 3601)]
    incident = only(run(events, config))
    assert incident.incident_type == "BREACH"
    assert incident.slow_attack_suspected is True
    assert incident.score == 90  # flagged, not scored down


def test_no_slow_flag_within_window(config):
    events = [ev("login_failed", i) for i in range(5)] + [ev("login_success", 3600)]
    assert only(run(events, config)).slow_attack_suspected is False


def test_slow_flag_applies_to_attack(config):
    events = [ev("login_failed", i * 1000) for i in range(5)]
    incident = only(run(events, config))
    assert (incident.incident_type, incident.slow_attack_suspected) == ("ATTACK", True)


def test_slow_flag_never_on_recon(config):
    incident = only(run([ev("port_scan", 0), ev("port_scan", 10_000)], config))
    assert (incident.incident_type, incident.slow_attack_suspected) == ("RECON", False)


def test_real_lab_breach(config):
    """samples/: Nmap scan (Oct 12) + Hydra brute force + login (Oct 13) from the Kali VM."""
    events = [e for f in collect_files([str(SAMPLES)]) for e in parse_file(f, config)]
    map_events(score(enrich(events, config), config))
    incidents = correlate(events, config)

    top = incidents[0]
    assert top.src_ip == "10.10.10.40"
    assert top.incident_type == "BREACH"
    assert top.score == 90
    assert top.slow_attack_suspected is True
    assert top.mitre_techniques == ["T1046", "T1078", "T1110"]
    assert top.first_seen == datetime(2026, 10, 12, 22, 8, 4, 591359, tzinfo=timezone.utc)
    assert top.events == sorted(top.events, key=lambda e: e.timestamp)

    rest = {i.src_ip: (i.incident_type, i.score) for i in incidents[1:]}
    assert rest == {"local": ("isolated", 30), "10.0.2.2": ("isolated", 5), "10.10.10.20": ("isolated", 0)}
