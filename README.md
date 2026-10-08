# SOC Log Triage

> 🚧 **Status: in progress** — this project is under active development. The design below is the plan; each part is checked off as it is built and tested.

A Python tool that helps a SOC analyst go from **thousands of raw log lines** to **a short, prioritised triage report**.

It reads Suricata alerts and Linux authentication logs, groups related events into attack stories, enriches suspicious IP addresses, maps each finding to MITRE ATT&CK, and outputs a report sorted by severity.

## Why this project

In a SOC, the hard part is rarely *collecting* alerts — it is *deciding which ones matter*. Analysts face a flood of alerts, many of them noise. This tool automates the first triage steps a Tier 1 analyst does by hand:

1. What happened?
2. Is it the same attacker doing several things?
3. Is this IP already known to be malicious?
4. How serious is it, and what should I look at first?

It complements my [SOC Home Lab](https://github.com/a5ras/soc-home-lab), where I build the detection side (Suricata IDS/IPS, custom rules, Wazuh). The lab is one data source for this tool, but the tool is standalone and works on any `eve.json` / `auth.log` file.

## Planned features

- [ ] **Parsers** — read Suricata `eve.json` (JSON lines) and Linux `auth.log` into one common event format
- [ ] **Detections**
  - [ ] SSH brute force (many failed logins from one IP in a short time)
  - [ ] Port scan (many destination ports from one IP)
  - [ ] Successful login after repeated failures (possible compromise)
- [ ] **Correlation** — link events from the same source IP into one timeline (e.g. scan → brute force → successful login)
- [ ] **Enrichment** — look up IP reputation with the AbuseIPDB API (optional, needs a free API key)
- [ ] **MITRE ATT&CK mapping** — tag each finding with its technique ID (e.g. T1110 Brute Force, T1046 Network Service Discovery)
- [ ] **Severity scoring** — rank findings so the most serious appear first
- [ ] **Report** — Markdown triage report + JSON output for other tools
- [ ] **Tests** — sample log files and unit tests for each detection

## Planned structure

```
soc-log-triage/
├── triage/
│   ├── parsers/        # eve.json and auth.log readers
│   ├── detections/     # one module per detection
│   ├── correlate.py    # groups events by source IP into timelines
│   ├── enrich.py       # AbuseIPDB lookups
│   ├── mitre.py        # technique mapping
│   └── report.py       # Markdown / JSON output
├── samples/            # sample logs for testing (lab + public datasets)
├── tests/
└── main.py             # command-line entry point
```

## Planned usage

```bash
python main.py --suricata samples/eve.json --auth samples/auth.log --out report.md
```

## Roadmap

| Step | Goal |
|------|------|
| 1 | Parsers + common event format |
| 2 | SSH brute force and port scan detections |
| 3 | Correlation by source IP |
| 4 | MITRE mapping + severity scoring |
| 5 | Markdown report |
| 6 | AbuseIPDB enrichment |
| 7 | Tests on lab data and public datasets |

## Tech

Python 3 · standard library first (`json`, `re`, `collections`, `argparse`) · `requests` for enrichment

## License

MIT
