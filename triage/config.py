"""Loads config.toml (stdlib tomllib) on top of the built-in defaults."""

import tomllib
from pathlib import Path

DEFAULTS = {
    "scoring": {
        "login_success": 5,
        "login_failed": 10,
        "port_scan": 40,
        "brute_force": 70,
        "sudo_root": 30,
        "arp_spoof": 60,
        "bonus": {
            "in_blocklist": 20,
            "external_ip": 10,
            "success_after_failures": 25,
        },
    },
    "thresholds": {"low_max": 29, "medium_max": 69},
    "correlation": {"window_seconds": 3600, "brute_force_threshold": 5},
    "incident_score": {"breach": 90, "attack": 65, "recon": 35},
    "enrichment": {
        "internal_prefix": "10.10.10.",
        "blocklist_path": "data/blocklist.txt",
        "geoip_path": "data/GeoLite2-City.mmdb",
    },
    "parsers": {"port_scan_sids": [86601, 1000001]},
}


def _merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path | None = None) -> dict:
    """Return the defaults, overridden by the TOML file at `path` if it exists."""
    if path is None or not Path(path).is_file():
        return _merge(DEFAULTS, {})
    with open(path, "rb") as fh:
        return _merge(DEFAULTS, tomllib.load(fh))
