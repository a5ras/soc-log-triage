"""Enrichment: internal/external, blocklist, GeoIP (optional), AbuseIPDB (optional)."""

import ipaddress
import os
from pathlib import Path

from triage.models import Event

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip: str | None, internal_prefix: str = "10.10.10.") -> bool:
    """True for the lab prefix, RFC1918-private addresses, or events with no source IP (local)."""
    if ip is None:
        return True
    if ip.startswith(internal_prefix):
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in RFC1918)


def load_blocklist(path: str | Path) -> set[str]:
    """Read one IP per line; blank lines and '#' comments are ignored. Missing file = empty list."""
    path = Path(path)
    if not path.is_file():
        return set()
    with open(path, encoding="utf-8") as fh:
        return {line.split("#")[0].strip() for line in fh} - {""}


def _open_geoip(path: str | Path):
    """Return a geoip2 Reader, or None if the library or the database is missing."""
    try:
        import geoip2.database

        return geoip2.database.Reader(str(path))
    except Exception:
        return None


def geo_lookup(reader, ip: str) -> str | None:
    """'City, Country' for a public IP; None when not in the database or unavailable."""
    if reader is None:
        return None
    try:
        response = reader.city(ip)
    except Exception:
        return None
    parts = [response.city.name, response.country.name]
    return ", ".join(p for p in parts if p) or None


def abuse_lookup(ip: str, api_key: str | None) -> int | None:
    """AbuseIPDB confidence score for a public IP; None without a key or on any error."""
    if not api_key:
        return None
    try:
        import requests

        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        resp.raise_for_status()
        return int(resp.json()["data"]["abuseConfidenceScore"])
    except Exception:
        return None


def enrich(events: list[Event], config: dict) -> list[Event]:
    """Fill is_internal, in_blocklist and, when available, geo and abuse_score on each event."""
    cfg = config["enrichment"]
    blocklist = load_blocklist(cfg["blocklist_path"])
    reader = _open_geoip(cfg["geoip_path"])
    api_key = os.environ.get("ABUSEIPDB_KEY")
    geo_cache: dict[str, str | None] = {}
    abuse_cache: dict[str, int | None] = {}

    for event in events:
        ip = event.src_ip
        event.is_internal = is_internal(ip, cfg["internal_prefix"])
        event.in_blocklist = ip in blocklist
        if ip is None or event.is_internal:
            continue
        if ip not in geo_cache:
            geo_cache[ip] = geo_lookup(reader, ip)
        if ip not in abuse_cache:
            abuse_cache[ip] = abuse_lookup(ip, api_key)
        event.geo = geo_cache[ip]
        event.abuse_score = abuse_cache[ip]

    if reader is not None:
        reader.close()
    return events
