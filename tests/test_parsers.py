"""Each parser turns a known line from the real lab samples into the expected Event."""

import json
from datetime import datetime, timezone

import pytest

from tests.conftest import SAMPLES
from triage.parsers import authlog, collect_files, detect_format, suricata, wazuh

# --- auth.log (real lines from samples/auth.log) --------------------------

FAILED = (
    "2026-10-13T20:27:19.623474+00:00 soc-defender sshd-session[2069]: "
    "Failed password for invalid user admin from 10.10.10.40 port 36054 ssh2"
)
ACCEPTED = (
    "2026-10-13T20:52:38.550459+00:00 soc-defender sshd-session[2439]: "
    "Accepted password for a5rasx from 10.10.10.40 port 32882 ssh2"
)
SUDO_COMMAND = (
    "2026-10-07T16:40:36.049534+00:00 soc-defender sudo: a5rasx : TTY=/dev/pts/0 ; "
    "PWD=/home/a5rasx ; USER=root ; COMMAND=/usr/sbin/nft list ruleset"
)
SUDO_SESSION = (
    "2026-10-07T16:40:36.046562+00:00 soc-defender sudo: pam_unix(sudo:session): "
    "session opened for user root(uid=0) by a5rasx(uid=1000)"
)
CRON_SESSION = (
    "2026-10-07T03:17:01.529764+00:00 soc-defender CRON[2718]: pam_unix(cron:session): "
    "session opened for user root(uid=0) by root(uid=0)"
)
PAM_FAILURE = (
    "2026-10-13T20:27:17.828898+00:00 soc-defender sshd-session[2069]: pam_unix(sshd:auth): "
    "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.10.10.40"
)


def test_authlog_failed_password():
    event = authlog.parse_line(FAILED, 2026)
    assert event.event_type == "login_failed"
    assert event.source == "authlog"
    assert event.src_ip == "10.10.10.40"
    assert event.user == "admin"
    assert event.timestamp == datetime(2026, 10, 13, 20, 27, 19, 623474, tzinfo=timezone.utc)
    assert event.raw_line == FAILED


def test_authlog_accepted_password():
    event = authlog.parse_line(ACCEPTED, 2026)
    assert (event.event_type, event.src_ip, event.user) == ("login_success", "10.10.10.40", "a5rasx")


@pytest.mark.parametrize("line", [SUDO_COMMAND, SUDO_SESSION])
def test_authlog_sudo_root(line):
    event = authlog.parse_line(line, 2026)
    assert (event.event_type, event.src_ip, event.user) == ("sudo_root", None, "a5rasx")


def test_authlog_cron_root_session_is_not_elevation():
    assert authlog.parse_line(CRON_SESSION, 2026).event_type == "other"


def test_authlog_other_keeps_source_ip():
    event = authlog.parse_line(PAM_FAILURE, 2026)
    assert (event.event_type, event.src_ip) == ("other", "10.10.10.40")


def test_authlog_classic_timestamp_uses_given_year():
    line = "Oct 13 22:00:01 soc-defender sshd[812]: Failed password for root from 10.10.10.40 port 4242 ssh2"
    event = authlog.parse_line(line, 2025)
    assert event.timestamp == datetime(2025, 10, 13, 22, 0, 1, tzinfo=timezone.utc)
    assert event.timestamp.tzinfo is not None
    assert (event.event_type, event.user) == ("login_failed", "root")


def test_authlog_nul_padded_line_is_parsed():
    event = authlog.parse_line("\x00" * 50 + FAILED, 2026)
    assert event.event_type == "login_failed"


def test_authlog_real_file():
    events = authlog.parse(SAMPLES / "auth.log")
    failed = [e for e in events if e.event_type == "login_failed"]
    success = [e for e in events if e.event_type == "login_success" and e.src_ip == "10.10.10.40"]
    assert len(failed) == 72
    assert all(e.src_ip == "10.10.10.40" for e in failed)
    assert len(success) == 2


# --- Suricata eve.json (real records from samples/eve.json) ---------------


def _eve_alerts():
    with open(SAMPLES / "eve.json", encoding="utf-8", errors="replace") as fh:
        return [line.strip() for line in fh if '"event_type":"alert"' in line]


def test_suricata_port_scan_alert():
    line = next(l for l in _eve_alerts() if '"signature_id":1000001' in l)
    event = suricata.parse_record(json.loads(line), line)
    assert event.event_type == "port_scan"
    assert event.source == "suricata"
    assert (event.src_ip, event.dst_ip) == ("10.10.10.40", "10.10.10.20")
    assert event.timestamp == datetime(2026, 10, 12, 22, 8, 4, 591359, tzinfo=timezone.utc)
    assert "LOCAL Nmap TCP scan detected" in event.raw_line


def test_suricata_other_alert_keeps_signature():
    line = next(l for l in _eve_alerts() if '"signature_id":2210016' in l)
    event = suricata.parse_record(json.loads(line), line)
    assert event.event_type == "other"
    assert "SURICATA STREAM CLOSEWAIT FIN out of window" in event.raw_line


def test_suricata_spec_sid_86601_is_port_scan():
    record = {"timestamp": "2026-10-12T22:08:04+0000", "event_type": "alert",
              "src_ip": "10.10.10.40", "dest_ip": "10.10.10.20", "alert": {"signature_id": 86601}}
    assert suricata.parse_record(record, "").event_type == "port_scan"


def test_suricata_skips_non_alert_records():
    assert suricata.parse_record({"timestamp": "2026-10-07T23:02:14+0000", "event_type": "flow"}, "") is None


def test_suricata_real_file(config):
    events = suricata.parse(SAMPLES / "eve.json", config)
    assert [e.event_type for e in events].count("port_scan") == 4
    assert len(events) == 5  # alerts only; truncated / NUL lines skipped


def test_suricata_port_scan_sids_come_from_config(config):
    config["parsers"]["port_scan_sids"] = [86601]
    events = suricata.parse(SAMPLES / "eve.json", config)
    assert all(e.event_type == "other" for e in events)


# --- Wazuh alerts.json -----------------------------------------------------


def test_wazuh_real_record_is_other():
    line = (SAMPLES / "alerts.json").read_text().splitlines()[0]
    event = wazuh.parse_record(json.loads(line), line)
    assert event.event_type == "other"
    assert event.source == "wazuh"
    assert event.src_ip is None
    assert event.timestamp == datetime(2026, 10, 17, 16, 13, 30, 437000, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "rule_id, expected",
    [("5710", "login_failed"), ("5760", "login_failed"), ("5712", "brute_force"),
     ("5763", "brute_force"), ("5715", "login_success"), ("5402", "sudo_root"), ("510", "other")],
)
def test_wazuh_rule_mapping(rule_id, expected):
    # The lab's alerts.json has no SSH rules yet, so this record is built in the same shape.
    record = {"timestamp": "2026-10-13T20:27:19.623+0000", "rule": {"id": rule_id},
              "agent": {"id": "001", "name": "soc-defender", "ip": "10.10.10.20"},
              "data": {"srcip": "10.10.10.40", "dstuser": "admin"}}
    event = wazuh.parse_record(record, json.dumps(record))
    assert event.event_type == expected
    assert (event.src_ip, event.dst_ip, event.user) == ("10.10.10.40", "10.10.10.20", "admin")


def test_wazuh_real_file():
    assert len(wazuh.parse(SAMPLES / "alerts.json")) == 4


# --- dispatch --------------------------------------------------------------


def test_directory_input_reads_the_known_files():
    names = sorted(p.name for p in collect_files([str(SAMPLES)]))
    assert names == ["alerts.json", "auth.log", "eve.json"]


def test_format_is_sniffed_for_unknown_names():
    assert detect_format(SAMPLES / "public_sample.json") == "suricata"
