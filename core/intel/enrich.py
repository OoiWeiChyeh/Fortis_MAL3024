"""
Offline enrichment of extracted IOCs against vendored catalogues
(ATT&CK Enterprise, CISA KEV; rebuilt by `python -m core.intel.sync`).

The lookups double as a hallucination check: an ATT&CK id that the model
emits but the catalogue does not contain is fabricated, and a revoked id
is stale. The eval harness uses `technique_status` for exactly that.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

from .ioc import IOC, extract_iocs

DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def attack_catalogue() -> dict:
    return json.loads((DATA_DIR / "attack_enterprise.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def kev_catalogue() -> dict:
    return json.loads((DATA_DIR / "cisa_kev.json").read_text(encoding="utf-8"))


def technique_status(tid: str) -> str:
    """'valid' | 'revoked' | 'deprecated' | 'unknown' (not in ATT&CK at all)."""
    t = attack_catalogue()["techniques"].get(tid.upper())
    if t is None:
        return "unknown"
    if t["revoked"]:
        return "revoked"
    if t["deprecated"]:
        return "deprecated"
    return "valid"


def lookup_technique(tid: str) -> Optional[dict]:
    t = attack_catalogue()["techniques"].get(tid.upper())
    return dict(t, id=tid.upper(), status=technique_status(tid)) if t else None


def lookup_kev(cve: str) -> Optional[dict]:
    v = kev_catalogue()["vulnerabilities"].get(cve.upper())
    return dict(v, cve=cve.upper()) if v else None


def enrich_ioc(ioc: IOC) -> Dict:
    d = ioc.to_dict()
    if ioc.type == "attack_technique":
        t = lookup_technique(ioc.value)
        d["status"] = t["status"] if t else "unknown"
        if t:
            d["name"], d["tactics"], d["url"] = t["name"], t["tactics"], t["url"]
    elif ioc.type == "cve":
        kev = lookup_kev(ioc.value)
        d["kev"] = kev is not None
        if kev:
            d.update({k: kev[k] for k in ("vendor", "product", "name", "date_added", "due_date", "ransomware")})
    return d


def enrich_text(text: str) -> List[Dict]:
    return [enrich_ioc(i) for i in extract_iocs(text)]


def catalogue_versions() -> Dict[str, str]:
    kev = kev_catalogue()
    return {
        "attack": str(attack_catalogue().get("attack_version")),
        "kev": str(kev.get("catalog_version")),
        "kev_released": str(kev.get("date_released")),
    }
