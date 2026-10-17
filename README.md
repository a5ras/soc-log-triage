# SOC Log Triage

A standalone Python tool that turns a flood of raw SOC logs into a **short, prioritised list of incidents**.

It reads three log sources, normalises them into one event format, enriches and scores every event, maps it to MITRE ATT&CK, correlates related activity into incidents, and prints a triage report sorted so the most serious incident comes first.

## Why this project: alert fatigue

In a real SOC an analyst faces thousands of raw alerts per shift, and most of them are noise. The hard part is rarely *collecting* alerts. It is *deciding which ones matter*. **Triage** is that first pass: what happened, is it one attacker doing several things, is the IP known-bad, and what should I look at first?

This tool automates that first pass. In the run below, 2,600 log lines become four incidents, and the one real breach sits at the top.

## Real lab data

The sample logs in [`samples/`](samples/) are **real**. They come from attacks I ran by hand in my [SOC Home Lab](https://github.com/a5ras/soc-home-lab): an Nmap port scan and a Hydra SSH brute force from the Kali attacker (`10.10.10.40`) against the defender VM (`10.10.10.20`), ending in a successful login. They are not downloaded synthetic data. The files are kept as captured, including a few truncated / NUL-padded lines, which the parsers skip.

| File | Source | What it contains |
|------|--------|------------------|
| `samples/auth.log` | Linux `auth.log` on the defender | SSH failures and successes, sudo usage |
| `samples/eve.json` | Suricata `eve.json` | Nmap scan alerts (local rule SID `1000001`), flow / stats / ARP telemetry |
| `samples/alerts.json` | Wazuh `alerts.json` | Wazuh manager alerts (rootcheck, manager start) |
| `samples/public_sample.json` | **Demo only, not lab data** | Four hand-written Suricata alerts from public IPs, used to demonstrate GeoIP / blocklist enrichment (see below) |

## Sources

| Source | Format | Normalised event types |
|--------|--------|------------------------|
| `auth.log` | syslog text, parsed with regex | `Accepted password` → `login_success`; `Failed password` → `login_failed`; `sudo: … COMMAND=` / sudo `session opened for user root` → `sudo_root`; anything else → `other` |
| Suricata `eve.json` | one JSON object per line | alert with a port-scan SID (`86601`, `1000001`, configurable) → `port_scan`; other alerts → `other`. Non-alert records (flow, stats, …) are ignored. |
| Wazuh `alerts.json` | one JSON object per line | `rule.id` 5710/5760 → `login_failed`; 5712/5763 → `brute_force`; 5715 → `login_success`; 5402 → `sudo_root`; anything else → `other` |

All events share one model (`triage/models.py`): timestamp (timezone-aware), source, event type, source/destination IP, user, raw line, plus the fields that later stages fill in. Both auth.log timestamp styles are supported: ISO-8601 (`2026-10-13T20:27:19.62+00:00`) and classic (`Oct 13 22:00:01`). For the classic style, the year comes from the file's modification time.

Adding a fourth format means adding one parser file in `triage/parsers/` and nothing else.

## Pipeline

```
files → parse → [Event…] → enrich → score → MITRE map → correlate → [Incident…] → report
```

| Stage | Module |
|-------|--------|
| parse | `triage/parsers/` (`authlog.py`, `suricata.py`, `wazuh.py`) |
| enrich | `triage/enrich.py` |
| score | `triage/score.py` |
| MITRE map | `triage/mitre.py` |
| correlate | `triage/correlate.py` |
| report | `triage/report.py` |

`main.py` only wires the stages together.

## Enrichment

**Core (offline, deterministic, tested):**
- `is_internal`: the source IP starts with `internal_prefix` (default `10.10.10.`) or is RFC 1918 private.
- `in_blocklist`: the source IP is listed in `data/blocklist.txt` (one IP per line, `#` for comments).

**Optional (degrades gracefully when not available):**
- `geo`: country / city from a MaxMind **GeoLite2-City** database through `geoip2`. Private IPs return nothing.
- `abuse_score`: AbuseIPDB confidence score, looked up only when the `ABUSEIPDB_KEY` environment variable is set. Otherwise the lookup is skipped silently.

> **An honest note:** GeoIP and AbuseIPDB only return data for **public** IPs. Every IP in the lab is private (`10.10.10.0/24`, `10.0.2.0/24`), so on the real lab data these two fields are always empty. That is why `samples/public_sample.json` exists: it is a small, clearly-labelled **demo** file with public source IPs. It uses `45.33.32.156` (`scanme.nmap.org`) and two documentation-range IPs that are also in the demo blocklist. It is not lab data.

To enable GeoIP, create a free MaxMind account, download **GeoLite2-City** (`.mmdb`), and save it as `data/GeoLite2-City.mmdb`. The file is gitignored because its licence does not allow redistribution.

```bash
export ABUSEIPDB_KEY=your_key_here      # optional
python main.py --input samples/public_sample.json
```

## Scoring (per event)

`severity = base + bonuses`, capped at 100.

| Event type | Base |
|------------|-----:|
| `login_success` | 5 |
| `login_failed` | 10 |
| `port_scan` | 40 |
| `brute_force` | 70 |
| `sudo_root` | 30 |
| `arp_spoof` | 60 |
| `other` | 0 |

| Bonus (additive) | Points |
|------------------|-------:|
| source IP is in the blocklist | +20 |
| source IP is external | +10 |
| `login_success` from an IP with ≥ `brute_force_threshold` (5) earlier failed logins | +25 |

Event classes: **0–29 Low**, **30–69 Medium**, **70–100 Critical**.

## Correlation (into incidents)

All events are grouped by source IP: **one source IP = one incident**. Events without a source IP (for example local sudo usage and Wazuh host alerts) go into a single `local` incident.

Flags for each IP:
- `has_scan`: any `port_scan`
- `has_brute`: any `brute_force`, **or** at least `brute_force_threshold` (5) `login_failed`
- `has_success`: any `login_success`
- `span`: last seen − first seen

The incident type is decided in this order:

```
if has_success and (has_scan or has_brute): BREACH
elif has_brute:                             ATTACK
elif has_scan:                              RECON
else:                                       isolated
```

The incident score comes from the type and is **not** a sum of event scores:

| Type | Score |
|------|------:|
| BREACH | 90 |
| ATTACK | 65 |
| RECON | 35 |
| isolated | highest event severity in the incident |

Scoring by type keeps a real breach above a failed attempt, and stops a pile of harmless events from adding up to more than a real compromise.

**Slow-attack detection:** `slow_attack_suspected = type in (BREACH, ATTACK) and span > window_seconds` (default 3600 s). A slow breach is still a breach: it is flagged, not scored lower.

## MITRE ATT&CK mapping

| Event type | Technique |
|------------|-----------|
| `port_scan` | T1046 Network Service Discovery |
| `brute_force`, `login_failed` | T1110 Brute Force |
| `login_success` (only inside a BREACH) | T1078 Valid Accounts |
| `arp_spoof` | T1557 Adversary-in-the-Middle |
| `sudo_root` | T1548 Abuse Elevation Control Mechanism |

Each event gets its technique ID, and each incident lists the set of techniques across its events. The mapping follows the `mitre-attack-mapping.md` reference in the [SOC Home Lab](https://github.com/a5ras/soc-home-lab).

## Configuration

Every number above lives in [`config.toml`](config.toml) and is read with the standard-library `tomllib`:

```toml
[scoring]            # base score per event type
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

[thresholds]         # Low ≤ 29 < Medium ≤ 69 < Critical
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

[parsers]
port_scan_sids = [86601, 1000001]   # Suricata SIDs treated as port_scan
```

## Install

Python 3.11+ is required (for `tomllib`).

```bash
git clone https://github.com/a5ras/soc-log-triage.git
cd soc-log-triage
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python main.py --input <files-or-dir> [--format terminal|json|markdown]
               [--output PATH] [--config config.toml] [--min-severity N]
```

- `--input`: one or more files, or a directory. For a directory, the tool reads the known files in it: `auth.log`, `eve.json`, `alerts.json`.
- `--format`: `terminal` (default, a `rich` table coloured by severity), `json`, or `markdown`.
- `--output`: write to a file instead of stdout.
- `--min-severity`: hide incidents scored below N.

```bash
python main.py --input samples/ --format terminal
python main.py --input samples/ --format markdown --output report.md --min-severity 60
```

## Terminal output

Running `python main.py --input samples/` on the real lab logs:

```
TERMINAL_OUTPUT_PLACEHOLDER
```

## Tests

```bash
python -m pytest
```

- `tests/test_parsers.py`: each parser turns real lines from `samples/` into the expected Event.
- `tests/test_score.py`: base scores, each bonus, and the +25 success-after-failures case.
- `tests/test_correlate.py`: the four incident types, the BREACH scenario from the real lab logs, and the slow-attack flag.

## Project structure

```
soc-log-triage/
├── main.py                 # CLI entry point (argparse), wiring only
├── config.toml
├── requirements.txt
├── triage/
│   ├── models.py           # Event, Incident dataclasses
│   ├── config.py           # loads config.toml over built-in defaults
│   ├── parsers/
│   │   ├── authlog.py      # auth.log (regex)
│   │   ├── suricata.py     # eve.json
│   │   └── wazuh.py        # alerts.json
│   ├── enrich.py           # internal/external, blocklist, GeoIP, AbuseIPDB
│   ├── score.py            # per-event severity
│   ├── mitre.py            # event type → ATT&CK technique
│   ├── correlate.py        # incidents, classification, slow-attack flag
│   └── report.py           # terminal / JSON / Markdown
├── tests/
├── samples/                # real lab logs + public demo sample
└── data/
    ├── blocklist.txt
    └── GeoLite2-City.mmdb  # not committed, see Enrichment
```

## Future work

These are out of scope for v1:

- Real-time processing / tailing live logs
- Storing results in a database
- A web UI or GUI
- Machine learning
- Writing results back to Wazuh or a SIEM
- Log formats beyond the three above (one new parser file each)
- Splitting one source IP into several incidents separated in time
- Producing `arp_spoof` events. The type, score and MITRE mapping exist, but none of the three v1 parsers emits it yet. The lab's Suricata ARP records show no IP/MAC conflict to detect.

## License

MIT (see [LICENSE](LICENSE)).
