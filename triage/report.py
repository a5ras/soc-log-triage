"""Renders incidents as a terminal table, JSON or Markdown."""

import io
import json
from dataclasses import asdict
from datetime import datetime, timezone

from triage.mitre import TECHNIQUES
from triage.models import Event, Incident
from triage.score import severity_class

COLORS = {"Low": "green", "Medium": "yellow", "Critical": "bold red"}


def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _technique(tid: str) -> str:
    return f"{tid} {TECHNIQUES.get(tid, '')}".strip()


def timeline(incident: Incident) -> tuple[list[dict], int]:
    """Notable events in order, consecutive repeats folded into one row; plus the count of `other` events."""
    rows: list[dict] = []
    others = 0
    for event in incident.events:
        if event.event_type == "other":
            others += 1
            continue
        key = (event.event_type, event.user, event.source, event.severity)
        if rows and rows[-1]["key"] == key:
            rows[-1]["count"] += 1
            rows[-1]["last"] = event.timestamp
            continue
        rows.append(
            {
                "key": key,
                "first": event.timestamp,
                "last": event.timestamp,
                "count": 1,
                "event_type": event.event_type,
                "user": event.user,
                "source": event.source,
                "severity": event.severity,
                "mitre": event.mitre,
            }
        )
    return rows, others


def _when(row: dict) -> str:
    if row["count"] == 1:
        return _ts(row["first"])
    first, last = _ts(row["first"]), _ts(row["last"])
    return f"{first} → {last[11:] if first[:10] == last[:10] else last}"


def _what(row: dict) -> str:
    text = row["event_type"] + (f" ×{row['count']}" if row["count"] > 1 else "")
    return text + (f" (user {row['user']})" if row["user"] else "")


def _enrichment(incident: Incident) -> str:
    """Short enrichment summary for an incident, taken from its first event."""
    e = incident.events[0]
    parts = ["internal" if e.is_internal else "external"]
    if e.in_blocklist:
        parts.append("BLOCKLISTED")
    if e.geo:
        parts.append(e.geo)
    if e.abuse_score is not None:
        parts.append(f"AbuseIPDB {e.abuse_score}%")
    return ", ".join(parts)


# --- terminal -------------------------------------------------------------


def render_terminal(incidents: list[Incident], config: dict, summary: str, color: bool = True) -> str:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return _render_plain(incidents, config, summary)

    thresholds = config["thresholds"]
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=color, no_color=not color, width=120)
    console.print(f"[bold]SOC Log Triage[/bold] — {summary}\n")

    overview = Table(title="Incidents (highest score first)", title_justify="left")
    for col in ("#", "Type", "Score", "Source IP", "Slow", "MITRE", "First seen", "Last seen", "Events"):
        overview.add_column(col, no_wrap=col not in ("MITRE",))
    for n, inc in enumerate(incidents, 1):
        color = COLORS[severity_class(inc.score, thresholds)]
        overview.add_row(
            str(n),
            f"[{color}]{inc.incident_type}[/{color}]",
            f"[{color}]{inc.score}[/{color}]",
            inc.src_ip,
            "[bold magenta]YES[/bold magenta]" if inc.slow_attack_suspected else "-",
            ", ".join(inc.mitre_techniques) or "-",
            _ts(inc.first_seen),
            _ts(inc.last_seen),
            str(len(inc.events)),
        )
    console.print(overview)

    for n, inc in enumerate(incidents, 1):
        rows, others = timeline(inc)
        color = COLORS[severity_class(inc.score, thresholds)]
        title = f"#{n} [{color}]{inc.incident_type} {inc.score}[/{color}]  {inc.src_ip}  ({_enrichment(inc)})"
        if inc.slow_attack_suspected:
            title += "  [bold magenta]slow attack suspected[/bold magenta]"
        detail = Table(title=title, title_justify="left", show_header=True)
        for col in ("When (UTC)", "Event", "Source", "Sev", "MITRE"):
            detail.add_column(col)
        for row in rows:
            sev_color = COLORS[severity_class(row["severity"], thresholds)]
            detail.add_row(
                _when(row),
                _what(row),
                row["source"],
                f"[{sev_color}]{row['severity']}[/{sev_color}]",
                row["mitre"] or "-",
            )
        if others:
            detail.add_row("", f"[dim]+ {others} other events[/dim]", "", "", "")
        console.print()
        console.print(detail)
    return buffer.getvalue()


def _render_plain(incidents: list[Incident], config: dict, summary: str) -> str:
    """Stdlib fallback when `rich` is not installed."""
    lines = [f"SOC Log Triage — {summary}", ""]
    for n, inc in enumerate(incidents, 1):
        cls = severity_class(inc.score, config["thresholds"])
        slow = "  SLOW ATTACK SUSPECTED" if inc.slow_attack_suspected else ""
        lines.append(f"#{n} {inc.incident_type} {inc.score} ({cls})  {inc.src_ip}  ({_enrichment(inc)}){slow}")
        lines.append(f"   MITRE: {', '.join(inc.mitre_techniques) or '-'}")
        lines.append(f"   {_ts(inc.first_seen)} → {_ts(inc.last_seen)}  ({len(inc.events)} events)")
        rows, others = timeline(inc)
        for row in rows:
            lines.append(f"     {_when(row):<42} {_what(row):<40} sev {row['severity']:>3}  {row['mitre'] or ''}")
        if others:
            lines.append(f"     + {others} other events")
        lines.append("")
    return "\n".join(lines)


# --- json -----------------------------------------------------------------


def _event_dict(event: Event) -> dict:
    data = asdict(event)
    data["timestamp"] = event.timestamp.isoformat()
    return data


def render_json(incidents: list[Incident], config: dict, summary: str) -> str:
    out = {
        "summary": summary,
        "incidents": [
            {
                "src_ip": inc.src_ip,
                "incident_type": inc.incident_type,
                "score": inc.score,
                "severity_class": severity_class(inc.score, config["thresholds"]),
                "slow_attack_suspected": inc.slow_attack_suspected,
                "mitre_techniques": inc.mitre_techniques,
                "first_seen": inc.first_seen.isoformat(),
                "last_seen": inc.last_seen.isoformat(),
                "events": [_event_dict(e) for e in inc.events],
            }
            for inc in incidents
        ],
    }
    return json.dumps(out, indent=2) + "\n"


# --- markdown -------------------------------------------------------------


def render_markdown(incidents: list[Incident], config: dict, summary: str) -> str:
    thresholds = config["thresholds"]
    lines = ["# SOC Triage Report", "", summary, "", "## Incidents", ""]
    lines += [
        "| # | Type | Score | Source IP | Slow attack | MITRE | First seen (UTC) | Last seen (UTC) | Events |",
        "|---|------|------:|-----------|-------------|-------|------------------|-----------------|-------:|",
    ]
    for n, inc in enumerate(incidents, 1):
        lines.append(
            f"| {n} | **{inc.incident_type}** | {inc.score} ({severity_class(inc.score, thresholds)}) "
            f"| `{inc.src_ip}` | {'⚠️ yes' if inc.slow_attack_suspected else 'no'} "
            f"| {', '.join(inc.mitre_techniques) or '-'} | {_ts(inc.first_seen)} | {_ts(inc.last_seen)} "
            f"| {len(inc.events)} |"
        )
    for n, inc in enumerate(incidents, 1):
        lines += ["", f"### #{n} {inc.incident_type} — `{inc.src_ip}` (score {inc.score})", ""]
        lines.append(f"- Enrichment: {_enrichment(inc)}")
        if inc.slow_attack_suspected:
            lines.append(f"- ⚠️ Slow attack suspected: activity spans more than {config['correlation']['window_seconds']} s")
        if inc.mitre_techniques:
            lines.append("- MITRE ATT&CK: " + "; ".join(_technique(t) for t in inc.mitre_techniques))
        rows, others = timeline(inc)
        if rows:
            lines += ["", "| When (UTC) | Event | Source | Severity | MITRE |", "|---|---|---|---:|---|"]
            for row in rows:
                lines.append(
                    f"| {_when(row)} | {_what(row)} | {row['source']} "
                    f"| {row['severity']} ({severity_class(row['severity'], thresholds)}) | {row['mitre'] or '-'} |"
                )
        if others:
            lines += ["", f"_+ {others} other events (no security meaning on their own)._"]
    return "\n".join(lines) + "\n"


RENDERERS = {"terminal": render_terminal, "json": render_json, "markdown": render_markdown}


def render(
    incidents: list[Incident], fmt: str, config: dict, summary: str, min_severity: int = 0, color: bool = True
) -> str:
    """Render incidents scoring >= min_severity, highest score first. `color` only affects the terminal format."""
    shown = sorted((i for i in incidents if i.score >= min_severity), key=lambda i: (-i.score, i.first_seen))
    if fmt == "terminal":
        return render_terminal(shown, config, summary, color)
    return RENDERERS[fmt](shown, config, summary)
