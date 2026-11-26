"""
Threat-intel endpoints: deterministic IOC extraction and the advisory
triage agent (core/agents/triage.py).

    POST /intel/iocs    {"text": "..."}                     -> enriched indicators
    POST /intel/triage  {"engagement_id": "...", "text": "..." | "filename": "..."}

Triage uses the engagement's uploaded asset inventory (any uploaded CSV with
a product column) for exposure, and writes four artefacts to the reports
folder, served by the existing /report/download route: the brief (.md), a
STIX 2.1 bundle, Sigma rules and an ATT&CK Navigator layer.
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import store, vectorstore
from ..config import settings
from ..intel import exports
from ..intel.enrich import catalogue_versions, enrich_text
from ..intel.inventory import Asset, parse_inventory

router = APIRouter(prefix="/intel", tags=["intel"])

MAX_ADVISORY_CHARS = 60_000


class IocRequest(BaseModel):
    text: str


class TriageRequest(BaseModel):
    engagement_id: str
    text: Optional[str] = None
    filename: Optional[str] = None


def _raw_upload(filename: str) -> Optional[str]:
    """Uploads are stored as <8 hex>_<name>; newest wins."""
    safe = os.path.basename(filename)
    hits = glob.glob(os.path.join(glob.escape(settings.upload_dir), "*_" + glob.escape(safe)))
    hits = [h for h in hits if re.match(r"^[0-9a-f]{8}_", os.path.basename(h))]
    return max(hits, key=os.path.getmtime) if hits else None


def engagement_inventory(engagement_id: str) -> List[Asset]:
    assets: List[Asset] = []
    for name in vectorstore.list_engagement_files(engagement_id):
        if not name.lower().endswith(".csv"):
            continue
        path = _raw_upload(name)
        if not path:
            continue
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                assets += parse_inventory(fh.read())
        except OSError:
            continue
    return assets


def _advisory_text(engagement_id: str, text: Optional[str], filename: Optional[str]) -> str:
    if filename:
        if filename not in vectorstore.list_engagement_files(engagement_id):
            raise HTTPException(404, f"'{store.clean(filename)}' is not uploaded to this engagement.")
        path = _raw_upload(filename)
        if not path:
            raise HTTPException(404, "The original upload is no longer on disk; upload it again.")
        from ..ingestion import extract_text
        text = extract_text(path)
    text = store.clean(text or "").strip()
    if len(text) < 40:
        raise HTTPException(400, "Paste the advisory text (or name an uploaded advisory file) to triage.")
    return text[:MAX_ADVISORY_CHARS]


def _write_artefacts(result, text: str) -> Dict[str, str]:
    slug = re.sub(r"[^a-z0-9]+", "-", result.title.lower()).strip("-")[:40] or "advisory"
    base = f"triage-{slug}-{hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()[:8]}"
    tech = [t["id"] for t in result.techniques]
    cves = [c["cve"] for c in result.cves]
    files = {
        "STIX 2.1 bundle": (f"{base}.stix.json", exports.dumps(exports.stix_bundle(result.title, result.iocs, tech, cves, result.narrative))),
        "Sigma rules": (f"{base}.sigma.yml", "---\n".join(exports.sigma_rules(result.title, result.iocs, tech, result.priority)) or "# no indicators\n"),
        "ATT&CK Navigator layer": (f"{base}.layer.json", exports.dumps(exports.navigator_layer(
            result.title, tech, {t["id"]: t.get("evidence") or "named in advisory" for t in result.techniques}))),
    }
    links = {}
    for label, (name, content) in files.items():
        with open(os.path.join(settings.report_dir, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        links[label] = f"/report/download/{name}"
    from ..agents.triage import render_markdown
    result.markdown = render_markdown(result, links)
    with open(os.path.join(settings.report_dir, f"{base}.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(result.markdown)
    links["Triage brief (.md)"] = f"/report/download/{base}.md"
    return links


async def run_triage(engagement_id: str, text: Optional[str] = None, filename: Optional[str] = None) -> Dict:
    eng = store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, f"Engagement '{store.clean(engagement_id)}' not found.")
    advisory = _advisory_text(engagement_id, text, filename)
    from ..agents.triage import triage

    client = (dict(eng).get("client_name") or "the client")
    result = await triage(advisory, inventory=engagement_inventory(engagement_id), client=client)
    links = _write_artefacts(result, advisory)
    return {**result.to_dict(), "links": links}


@router.post("/iocs")
async def iocs(req: IocRequest):
    text = store.clean(req.text or "")[:MAX_ADVISORY_CHARS]
    return {"catalogues": catalogue_versions(), "iocs": enrich_text(text)}


@router.post("/triage")
async def triage_endpoint(req: TriageRequest):
    from ..report_intent import is_stub_backend

    if is_stub_backend():
        raise HTTPException(409, "Triage needs a loaded model (the stub backend would write placeholder narrative).")
    return await run_triage(req.engagement_id, req.text, req.filename)
