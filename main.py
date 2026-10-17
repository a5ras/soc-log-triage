"""Command-line entry point for SOC Log Triage (wiring only)."""

import argparse
import sys
from pathlib import Path

from triage.config import load_config
from triage.correlate import correlate
from triage.enrich import enrich
from triage.mitre import map_events
from triage.parsers import collect_files, parse_file
from triage.report import RENDERERS, render
from triage.score import score


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Turn raw auth.log, Suricata eve.json and Wazuh alerts.json into a prioritised triage report."
    )
    parser.add_argument("--input", nargs="+", required=True, metavar="PATH",
                        help="log files, or a directory containing auth.log / eve.json / alerts.json")
    parser.add_argument("--format", choices=list(RENDERERS), default="terminal", help="output format (default: terminal)")
    parser.add_argument("--output", metavar="PATH", help="write the report to a file instead of stdout")
    parser.add_argument("--config", default="config.toml", metavar="PATH", help="TOML config (default: config.toml)")
    parser.add_argument("--min-severity", type=int, default=0, metavar="N", help="hide incidents scored below N")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    config = load_config(args.config)

    try:
        files = collect_files(args.input)
    except FileNotFoundError as missing:
        sys.exit(f"error: input not found: {missing}")
    events = [event for path in files for event in parse_file(path, config)]
    enrich(events, config)
    score(events, config)
    map_events(events)
    incidents = correlate(events, config)

    summary = f"{len(events)} events from {len(files)} file(s) → {len(incidents)} incidents"
    if args.min_severity:
        summary += f" (showing score ≥ {args.min_severity})"
    color = args.output is None and sys.stdout.isatty()
    text = render(incidents, args.format, config, summary, args.min_severity, color)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
