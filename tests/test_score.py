"""Per-event scoring (BUILD_SPEC §8): base scores, each bonus, the +25 case, the cap."""

from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import SAMPLES
from triage.enrich import enrich
from triage.models import Event
from triage.parsers import collect_files, parse_file
from triage.score import score, score_event, severity_class

T0 = datetime(2026, 10, 13, 20, 0, tzinfo=timezone.utc)


def ev(event_type, src_ip="10.10.10.40", minutes=0, internal=True, blocklisted=False):
    return Event(T0 + timedelta(minutes=minutes), "authlog", event_type, src_ip, None, None, "",
                 is_internal=internal, in_blocklist=blocklisted)


@pytest.mark.parametrize(
    "event_type, base",
    [("login_success", 5), ("login_failed", 10), ("port_scan", 40), ("brute_force", 70),
     ("sudo_root", 30), ("arp_spoof", 60), ("other", 0)],
)
def test_base_scores(config, event_type, base):
    assert score_event(ev(event_type), 0, config) == base


def test_blocklist_bonus(config):
    assert score_event(ev("port_scan", blocklisted=True), 0, config) == 40 + 20


def test_external_ip_bonus(config):
    assert score_event(ev("port_scan", internal=False), 0, config) == 40 + 10


def test_bonuses_are_additive(config):
    assert score_event(ev("login_failed", internal=False, blocklisted=True), 0, config) == 10 + 20 + 10


def test_cap_at_100(config):
    config["scoring"]["brute_force"] = 95
    assert score_event(ev("brute_force", internal=False, blocklisted=True), 0, config) == 100


def test_success_after_threshold_failures_gets_25(config):
    events = [ev("login_failed", minutes=i) for i in range(5)] + [ev("login_success", minutes=10)]
    score(events, config)
    assert events[-1].severity == 5 + 25


def test_success_below_threshold_gets_no_bonus(config):
    events = [ev("login_failed", minutes=i) for i in range(4)] + [ev("login_success", minutes=10)]
    score(events, config)
    assert events[-1].severity == 5


def test_only_prior_failures_count(config):
    events = [ev("login_success", minutes=0)] + [ev("login_failed", minutes=i + 1) for i in range(5)]
    score(events, config)
    assert events[0].severity == 5


def test_failures_from_another_ip_do_not_count(config):
    events = [ev("login_failed", "10.10.10.99", minutes=i) for i in range(5)] + [ev("login_success", minutes=10)]
    score(events, config)
    assert events[-1].severity == 5


@pytest.mark.parametrize("severity, label", [(0, "Low"), (29, "Low"), (30, "Medium"), (69, "Medium"), (70, "Critical"), (100, "Critical")])
def test_severity_classes(config, severity, label):
    assert severity_class(severity, config["thresholds"]) == label


def test_real_lab_logins(config):
    """The Hydra success at 20:52 follows 72 failures (+25); the 19:10 login came before any."""
    events = [e for f in collect_files([str(SAMPLES)]) for e in parse_file(f, config)]
    score(enrich(events, config), config)
    logins = {e.timestamp.strftime("%H:%M"): e.severity for e in events
              if e.event_type == "login_success" and e.src_ip == "10.10.10.40"}
    assert logins == {"19:10": 5, "20:52": 30}
