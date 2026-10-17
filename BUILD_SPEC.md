# soc-log-triage — BUILD SPEC (final, reconciled)

A standalone Python tool that ingests raw SOC logs from three sources, normalizes
them into unified events, enriches / scores / maps them to MITRE ATT&CK, correlates
them into incidents, and produces a prioritized triage report.

This document is the single source of truth. Numbers and thresholds here are
deliberate design decisions — implement them exactly, do not change without asking.

> NOTE TO CLAUDE CODE: a repo and an older README already exist. The older README
> describes a slightly different plan (2 sources, AbuseIPDB only). **Rewrite the
> README to match THIS spec** (3 sources; enrichment = blocklist + GeoIP + optional
> AbuseIPDB; keep MITRE; add the scoring/correlation/config sections). Keep the
> existing package name `triage/` and entry point `main.py`.

---

## 1. Purpose
In a real SOC an analyst drowns in thousands of raw alerts per shift, most of them
noise. **Triage** turns that flood into a short, ordered list of what matters. This
tool automates the first pass: read raw logs, group related activity into incidents,
map to MITRE, and surface the few critical incidents above the noise.

Sample data is **real** — produced by hand-run lab attacks (port scan, ARP spoofing,
Hydra SSH brute-force), not downloaded synthetic data.

---

## 2. Scope (v1)
**In scope:** read 3 sources (auth.log, Suricata eve.json, Wazuh alerts.json) →
normalize → enrich → score → MITRE map → correlate into incidents → prioritized
report (terminal / JSON / Markdown). CLI (argparse), TOML config, tests, README,
sample data.

**Out of scope (list under README "Future work"):** real-time/tailing; any database;
web UI/GUI; machine learning; writing back to Wazuh/SIEM; any log format beyond the 3;
splitting one source IP into multiple time-separated incidents.

The `parsers/` folder is designed for extensibility: a 4th format = one new parser
file, nothing else changes.

---

## 3. Project structure (keep existing names)
```
soc-log-triage/
  README.md            # rewrite to match this spec
  requirements.txt
  config.toml
  .gitignore
  LICENSE              # MIT, already present
  main.py              # CLI entry point (argparse); wiring only, no logic
  triage/
    __init__.py
    models.py          # Event, Incident dataclasses
    parsers/
      __init__.py
      authlog.py       # regex parser for auth.log
      suricata.py      # eve.json parser
      wazuh.py         # alerts.json parser
    enrich.py          # internal/external, blocklist, geoip, optional abuseipdb
    score.py           # per-event severity scoring
    mitre.py           # event_type -> ATT&CK technique mapping
    correlate.py       # group into incidents, classify, slow-attack flag
    report.py          # terminal / json / markdown renderers
  tests/
    test_parsers.py
    test_score.py
    test_correlate.py
  samples/
    auth.log           # real lab logs
    eve.json
    alerts.json
    public_sample.json # small public-IP sample, for the GeoIP/AbuseIPDB demo only
  data/
    blocklist.txt      # one malicious IP per line
    GeoLite2-City.mmdb # gitignored; README documents how to download it
```
Do NOT create a separate `detections/` package — detection logic lives inside
`correlate.py` (brute-force threshold, scan presence, success-after-failure).

---

## 4. Data model (`triage/models.py`)

### Event (dataclass)
| field | type | notes |
|---|---|---|
| `timestamp` | `datetime` | timezone-aware |
| `source` | `str` | `"authlog"` \| `"suricata"` \| `"wazuh"` |
| `event_type` | `str` | normalized, see §6 |
| `src_ip` | `str \| None` | |
| `dst_ip` | `str \| None` | |
| `user` | `str \| None` | |
| `raw_line` | `str` | original line/record |
| `severity` | `int` | 0–100, filled by score.py |
| `is_internal` | `bool` | filled by enrich.py |
| `in_blocklist` | `bool` | filled by enrich.py |
| `geo` | `str \| None` | filled by enrich.py |
| `abuse_score` | `int \| None` | filled by enrich.py (optional) |
| `mitre` | `str \| None` | technique id, filled by mitre.py |

### Incident (dataclass)
| field | type | notes |
|---|---|---|
| `src_ip` | `str` | |
| `events` | `list[Event]` | sorted by timestamp |
| `incident_type` | `str` | `"BREACH"` \| `"ATTACK"` \| `"RECON"` \| `"isolated"` |
| `score` | `int` | 0–100, see §9 |
| `slow_attack_suspected` | `bool` | see §9 |
| `mitre_techniques` | `list[str]` | union of its events' techniques |
| `first_seen` / `last_seen` | `datetime` | |

---

## 5. Pipeline
```
files → parse → [Event...] → enrich → score → mitre-map → correlate → [Incident...] → report
```
`main.py` wires the stages together.

---

## 6. Normalized event types & source mapping
Fixed set of `event_type`: `login_success`, `login_failed`, `port_scan`,
`brute_force`, `sudo_root`, `arp_spoof`, `other`.

**auth.log (regex):**
- `Accepted password for <user> from <ip>` → `login_success`
- `Failed password for <user> from <ip>` → `login_failed`
- `session opened for user root` / `sudo: ... COMMAND=` → `sudo_root`
- else → `other`
- Classic lines have no year (`Oct 13 22:00:01`): take year from file mtime,
  overridable; produce timezone-aware datetime.

**Suricata eve.json (one JSON object per line):**
- `event_type == "alert"` and `alert.signature_id == 86601` → `port_scan`
- other alerts → `other` (keep signature in raw_line); `src_ip` from `src_ip`.

**Wazuh alerts.json (one JSON object per line):**
- `rule.id` 5710/5760 → `login_failed`; 5712/5763 → `brute_force`;
  5715 → `login_success`; 5402 → `sudo_root`; else → `other`.
- src from `data.srcip`.

IDs come from the lab and must be easy to extend.

---

## 7. Enrichment (`triage/enrich.py`)
Core (offline, deterministic, tested):
- `is_internal` = src_ip starts with `internal_prefix` (default `10.10.10.`) or is RFC1918-private.
- `in_blocklist` = src_ip in `data/blocklist.txt` (one IP per line).

Optional (online / file-based, degrade gracefully if unavailable):
- `geo` = country/city from GeoLite2 via `geoip2`. Private IPs → `None`.
- `abuse_score` = AbuseIPDB confidence score via their API (`requests`), only if an
  API key is set in the environment; skip silently if not.

**Both GeoIP and AbuseIPDB only return data for PUBLIC IPs.** All lab IPs are private,
so these are demonstrated on `samples/public_sample.json` and this is stated honestly
in the README.

---

## 8. Scoring — per event (`triage/score.py`) — LOCKED
`severity = base + bonuses`, capped at 100.

Base by event_type: `login_success` 5, `login_failed` 10, `port_scan` 40,
`brute_force` 70, `sudo_root` 30, `arp_spoof` 60, `other` 0.

Bonuses (additive): `in_blocklist` +20; external IP +10;
`login_success` from an IP with ≥ `brute_force_threshold` prior failed logins +25.

Event classification (display inside incidents): 0–29 Low, 30–69 Medium, 70–100 Critical.

---

## 9. Correlation — into incidents (`triage/correlate.py`) — LOCKED
Group all events by `src_ip`. **One source IP = one incident** in v1.

Per-IP flags:
- `has_scan` = any `port_scan`
- `has_brute` = any `brute_force` OR (count of `login_failed` ≥ `brute_force_threshold`, default 5)
- `has_success` = any `login_success`
- `span` = last_seen − first_seen

Incident type (in order):
```
if has_success and (has_scan or has_brute): BREACH
elif has_brute:                             ATTACK
elif has_scan:                              RECON
else:                                       isolated
```

Incident score by type (NOT a sum): BREACH 90, ATTACK 65, RECON 35,
isolated = max event severity in it.
Rationale: scoring by type keeps a real breach above a failed attempt, and stops a
pile of harmless events summing past a real compromise.

Slow-attack detection:
```
slow_attack_suspected = incident_type in (BREACH, ATTACK) and span > window_seconds
```
Default window 3600s. A slow breach is still a breach — flagged, not scored down.

---

## 10. MITRE ATT&CK mapping (`triage/mitre.py`)
A dict `event_type -> technique`:
- `port_scan`  → T1046  Network Service Discovery
- `brute_force`/`login_failed` → T1110  Brute Force
- `login_success` (in a BREACH) → T1078  Valid Accounts
- `arp_spoof`   → T1557  Adversary-in-the-Middle
- `sudo_root`   → T1548  Abuse Elevation Control Mechanism

Fill `Event.mitre`; an incident's `mitre_techniques` = the set across its events.
Show technique ids in the report. (Mapping reference lives in the home-lab
`mitre-attack-mapping.md`.)

---

## 11. Config (`config.toml`, stdlib `tomllib`)
```toml
[scoring]
login_success = 5
login_failed  = 10
port_scan     = 40
brute_force   = 70
sudo_root     = 30
arp_spoof     = 60

[scoring.bonus]
in_blocklist           = 20
external_ip            = 10
success_after_failures = 25

[thresholds]
low_max    = 29
medium_max = 69

[correlation]
window_seconds        = 3600
brute_force_threshold = 5

[incident_score]
breach = 90
attack = 65
recon  = 35

[enrichment]
internal_prefix = "10.10.10."
blocklist_path  = "data/blocklist.txt"
geoip_path      = "data/GeoLite2-City.mmdb"
# AbuseIPDB key read from env var ABUSEIPDB_KEY if present
```

---

## 12. CLI (`main.py`, argparse)
```
python main.py --input <files-or-dir> [--format terminal|json|markdown]
               [--output PATH] [--config config.toml] [--min-severity N]
```
- `--input` accepts one or more files or a directory (reads the known files in it).
- `--format` default `terminal`.
- `--output` writes to a file instead of stdout.
- `--min-severity` hides incidents below score N.

Examples:
```
python main.py --input samples/ --format terminal
python main.py --input samples/ --format markdown --output report.md --min-severity 60
```

---

## 13. Reporting (`triage/report.py`)
Three renderers, incidents sorted highest score first. Each incident shows: type,
score, src_ip, slow-attack flag, MITRE techniques, first/last seen, ordered events.
- terminal — `rich` table, colored by severity (one dependency; stdlib fallback OK).
- json — stdlib.
- markdown — stdlib.

---

## 14. Dependencies (`requirements.txt`)
`geoip2` (GeoLite2), `requests` (AbuseIPDB, optional), `rich` (terminal table).
TOML via stdlib `tomllib` (Python 3.11+).

---

## 15. Tests (pytest)
- `test_parsers.py` — each parser turns a known sample line into the expected Event.
- `test_score.py` — base scores, each bonus, the +25 success-after-failures case.
- `test_correlate.py` — the four incident types, the BREACH scenario, the slow-attack
  flag (events spread beyond the window).

---

## 16. README (rewrite to match)
Plain-language purpose (triage / alert fatigue); the real-lab-data point; 3 sources;
enrichment set (blocklist core + GeoIP + optional AbuseIPDB) with the honest private-IP
note; MITRE mapping; install + run example with a terminal screenshot; link to the
SOC Home Lab repo; "Future work" = the §2 out-of-scope list.

---

## 17. Build notes for Claude Code
- Rewrite the README to this spec, then build the whole project from it.
- Scoring (§8) and correlation (§9) numbers are the author's own — implement exactly.
- Keep modules small and single-purpose; no logic in `main.py` beyond wiring.
- Commit in logical steps (README+skeleton+model, parsers, enrich, score+mitre,
  correlate, report+cli, tests) and **stop for the author's "yes" before each push.**
