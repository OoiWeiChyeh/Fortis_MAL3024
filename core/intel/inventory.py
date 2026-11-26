"""
Asset-inventory exposure matching for advisory triage.

"Is this advisory about something we run?" is the question that decides
whether a SOC drops everything or files the advisory. A small local model
answering it from memory is unreliable, so it is answered by code: an
inventory row is exposed when its product name appears in the advisory
text or in the CISA KEV product field of a CVE the advisory cites.

Deliberately conservative:
- product, not vendor: "Microsoft" in an advisory must not light up every
  Windows asset;
- no version-range evaluation: advisories express affected ranges in prose
  ("7.2.0-7.2.6", "before 6.23") that cannot be parsed reliably, so a match
  means "runs the product, confirm the version", and the version is shown
  next to the match for the analyst.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional

from .enrich import lookup_kev

_PRODUCT_KEYS = ("product", "software", "application", "platform")
_VENDOR_KEYS = ("vendor", "manufacturer", "publisher")
_NAME_KEYS = ("hostname", "asset", "name", "asset_id", "id")
# Generic product words that would match everywhere.
_TOO_GENERIC = {"server", "client", "agent", "gateway", "firewall", "router", "switch", "saas", "cloud", "portal"}


@dataclass
class Asset:
    name: str
    vendor: str
    product: str
    version: str = ""
    role: str = ""
    internet_facing: Optional[bool] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Exposure:
    asset: Asset
    matched_on: str       # the product string that matched
    via: str              # "advisory text" | "KEV CVE-xxxx"

    def to_dict(self) -> Dict:
        return {**self.asset.to_dict(), "matched_on": self.matched_on, "via": self.via}


def _pick(row: Dict[str, str], keys: Iterable[str]) -> str:
    low = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
    for k in keys:
        if low.get(k):
            return low[k]
    return ""


def parse_inventory(text: str) -> List[Asset]:
    """Parses a CSV asset register. Needs a product-like column; everything
    else is optional. Returns [] for text that is not such a CSV."""
    try:
        rows = list(csv.DictReader(io.StringIO(text.strip())))
    except csv.Error:
        return []
    if not rows or not any(k and k.strip().lower() in _PRODUCT_KEYS for k in rows[0].keys()):
        return []
    out = []
    for r in rows:
        product = _pick(r, _PRODUCT_KEYS)
        if not product:
            continue
        facing = _pick(r, ("internet_facing", "external", "exposed")).lower()
        out.append(Asset(
            name=_pick(r, _NAME_KEYS) or product,
            vendor=_pick(r, _VENDOR_KEYS),
            product=product,
            version=_pick(r, ("version", "release", "build")),
            role=_pick(r, ("role", "description", "purpose")),
            internet_facing=True if facing in ("yes", "y", "true", "1") else False if facing in ("no", "n", "false", "0") else None,
        ))
    return out


def _mentions(haystack: str, product: str) -> bool:
    p = product.strip()
    if len(p) < 3 or p.lower() in _TOO_GENERIC:
        return False
    return re.search(r"(?<![\w-])" + re.escape(p) + r"(?![\w-])", haystack, re.I) is not None


def match_exposure(advisory_text: str, cves: Iterable[str], assets: List[Asset]) -> List[Exposure]:
    kev_products = []
    for cve in cves:
        k = lookup_kev(cve)
        if k:
            kev_products.append((f"KEV {cve}", f"{k['vendor']} {k['product']}"))
    out = []
    for a in assets:
        if _mentions(advisory_text, a.product):
            out.append(Exposure(a, a.product, "advisory text"))
            continue
        for via, kp in kev_products:
            if _mentions(kp, a.product):
                out.append(Exposure(a, a.product, via))
                break
    return out
