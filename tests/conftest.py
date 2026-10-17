"""Shared fixtures: repo paths and the project config."""

from pathlib import Path

import pytest

from triage.config import load_config

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture
def config():
    cfg = load_config(ROOT / "config.toml")
    cfg["enrichment"]["blocklist_path"] = str(ROOT / cfg["enrichment"]["blocklist_path"])
    cfg["enrichment"]["geoip_path"] = str(ROOT / cfg["enrichment"]["geoip_path"])
    return cfg
