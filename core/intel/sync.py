"""
Builds the offline threat-intel catalogues under core/intel/data/.

    python -m core.intel.sync            # download feeds and rebuild
    python -m core.intel.sync --from-dir <dir>   # rebuild from saved feeds

Sources (public, no API key):
- MITRE ATT&CK Enterprise STIX 2.1 bundle (mitre-attack/attack-stix-data)
- CISA Known Exploited Vulnerabilities (KEV) catalogue

Why vendored snapshots instead of live lookups: Fortis is an offline-first
desktop tool, evaluation runs must be reproducible, and the raw ATT&CK
bundle is ~45 MB. The compact catalogues are a few hundred KB, carry the
source version/date, and are refreshed by re-running this module.

Feeds are parsed as untrusted data: only expected fields are copied out,
string fields are length-capped, and ids are validated by pattern.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTACK_OUT = DATA_DIR / "attack_enterprise.json"
KEV_OUT = DATA_DIR / "cisa_kev.json"

_TECH_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _cap(value, limit: int = 600) -> str:
    return str(value or "")[:limit]


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Fortis-intel-sync/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def build_attack(bundle: dict) -> dict:
    techniques = {}
    tactics = {}
    version = None
    for obj in bundle.get("objects", []):
        otype = obj.get("type")
        if otype == "x-mitre-collection":
            version = obj.get("x_mitre_version") or version
        if otype not in ("attack-pattern", "x-mitre-tactic"):
            continue
        ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        ext_id = str(ext.get("external_id", ""))
        if otype == "x-mitre-tactic":
            tactics[obj.get("x_mitre_shortname", "")] = {"id": ext_id, "name": _cap(obj.get("name"), 80)}
            continue
        if not _TECH_ID.match(ext_id):
            continue
        techniques[ext_id] = {
            "name": _cap(obj.get("name"), 160),
            "tactics": sorted(p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])
                              if p.get("kill_chain_name") == "mitre-attack"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "platforms": sorted(_cap(p, 40) for p in obj.get("x_mitre_platforms", []))[:12],
            "description": _cap(" ".join(str(obj.get("description", "")).split()), 400),
            "url": _cap(ext.get("url"), 200),
        }
    return {
        "source": ATTACK_URL,
        "attack_version": version,
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def build_kev(feed: dict) -> dict:
    entries = {}
    for v in feed.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).strip().upper()
        if not _CVE_ID.match(cve):
            continue
        added = str(v.get("dateAdded", ""))
        due = str(v.get("dueDate", ""))
        entries[cve] = {
            "vendor": _cap(v.get("vendorProject"), 80),
            "product": _cap(v.get("product"), 120),
            "name": _cap(v.get("vulnerabilityName"), 200),
            "date_added": added if _DATE.match(added) else "",
            "due_date": due if _DATE.match(due) else "",
            "ransomware": _cap(v.get("knownRansomwareCampaignUse"), 20),
            "description": _cap(" ".join(str(v.get("shortDescription", "")).split()), 500),
            "cwes": [c for c in v.get("cwes", []) if isinstance(c, str) and re.match(r"^CWE-\d+$", c)][:5],
        }
    return {
        "source": KEV_URL,
        "catalog_version": _cap(feed.get("catalogVersion"), 40),
        "date_released": _cap(feed.get("dateReleased"), 40),
        "count": len(entries),
        "vulnerabilities": dict(sorted(entries.items())),
    }


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=0, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from-dir", help="directory holding enterprise-attack.json and known_exploited_vulnerabilities.json")
    args = ap.parse_args(argv)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if args.from_dir:
        src = Path(args.from_dir)
        attack_raw = (src / "enterprise-attack.json").read_bytes()
        kev_raw = (src / "known_exploited_vulnerabilities.json").read_bytes()
    else:
        attack_raw, kev_raw = _download(ATTACK_URL), _download(KEV_URL)
    attack = build_attack(json.loads(attack_raw))
    kev = build_kev(json.loads(kev_raw))
    _write(ATTACK_OUT, attack)
    _write(KEV_OUT, kev)
    print(f"ATT&CK {attack['attack_version']}: {len(attack['techniques'])} techniques -> {ATTACK_OUT}")
    print(f"CISA KEV {kev['catalog_version']}: {kev['count']} CVEs -> {KEV_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
