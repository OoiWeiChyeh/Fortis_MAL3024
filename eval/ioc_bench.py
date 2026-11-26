"""
IOC extraction: deterministic extractor (core/intel/ioc.py) vs the local LLM
asked to extract the same indicators, on the 12 gold-labelled advisories.

Beyond precision/recall, the key safety metric is the *invented-indicator
rate*: predicted values that do not occur anywhere in the advisory (even
after refanging). A false positive that exists in the text (a version
string read as an IP) is an extraction error; an invented hash or domain is
a hallucination that would go straight into a blocklist.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict, List

from .metrics import prf

ADV = Path(__file__).parent / "datasets" / "advisories"
TYPES = ("ipv4", "domain", "url", "email", "md5", "sha1", "sha256")

PROMPT = """Extract every indicator of compromise from the threat advisory below. Refang defanged values
(hxxp -> http, [.] -> ., [@] -> @). Do not include private/internal addresses, version numbers or file names
that are not network indicators. Reply with JSON only, exactly this shape:
{"ipv4": [], "domain": [], "url": [], "email": [], "md5": [], "sha1": [], "sha256": [], "cve": []}

<<<ADVISORY>>>
%s
<<<END ADVISORY>>>"""


def gold() -> List[Dict]:
    return json.loads((ADV / "advisories_gold.json").read_text(encoding="utf-8"))


def _norm(kind: str, v: str) -> str:
    v = str(v).strip().strip("`'\"<>").rstrip(".,;")
    if kind in ("domain", "email", "md5", "sha1", "sha256"):
        v = v.lower()
    if kind == "cve":
        v = v.upper()
    return v


def deterministic(text: str) -> Dict[str, List[str]]:
    from core.intel.ioc import extract_iocs, iocs_by_type
    return iocs_by_type(extract_iocs(text))


async def llm_extract(text: str) -> Dict[str, List[str]]:
    from engine import chat
    raw = await chat([{"role": "user", "content": PROMPT % text}], temperature=0.0, json_mode=True, max_tokens=900)
    try:
        s, e = raw.find("{"), raw.rfind("}")
        data = json.loads(raw[s:e + 1])
    except (ValueError, TypeError):
        data = {}
    out = {}
    for k in TYPES + ("cve",):
        vals = data.get(k, []) if isinstance(data, dict) else []
        out[k] = [_norm(k, v) for v in vals if isinstance(v, (str, int))] if isinstance(vals, list) else []
    return out


def _in_text(value: str, text_refanged: str) -> bool:
    return value.lower() in text_refanged.lower()


def score(pred: Dict[str, List[str]], g: Dict, text: str) -> Dict:
    from core.intel.ioc import refang, normalise_dashes
    flat = refang(normalise_dashes(text))
    P = {(k, _norm(k, v)) for k in TYPES for v in pred.get(k, [])}
    G = {(k, _norm(k, v)) for k in TYPES for v in g["iocs"].get(k, [])}
    invented = sorted(f"{k}:{v}" for k, v in P if not _in_text(v, flat))
    s = prf(P, G)
    s["invented"] = invented
    s["false_positives"] = sorted(f"{k}:{v}" for k, v in P - G)
    s["missed"] = sorted(f"{k}:{v}" for k, v in G - P)
    s["cve"] = prf({_norm("cve", c) for c in pred.get("cve", [])}, set(g["cves"]))
    return s


def run(out_dir: Path, *, meta: Dict = None) -> Path:
    import engine
    out = out_dir / "results.jsonl"
    rows = []
    started = time.time()
    use_llm = engine.get_backend() != "stub" and meta and meta.get("model_file")
    for g in gold():
        text = (ADV / f"{g['id']}.md").read_text(encoding="utf-8")
        t0 = time.perf_counter()
        det = score(deterministic(text), g, text)
        det_s = time.perf_counter() - t0
        row = {"id": g["id"], "deterministic": det, "deterministic_s": round(det_s, 4)}
        if use_llm:
            t0 = time.perf_counter()
            pred = asyncio.run(llm_extract(text))
            row["llm"] = score(pred, g, text)
            row["llm_s"] = round(time.perf_counter() - t0, 2)
            row["llm_pred"] = pred
        rows.append(row)
        print(f"{g['id']} det F1={det['f1']:.2f} inv={len(det['invented'])}"
              + (f" | llm F1={row['llm']['f1']:.2f} inv={len(row['llm']['invented'])} {row['llm_s']}s" if use_llm else ""), flush=True)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    (out_dir / "run.json").write_text(json.dumps({**(meta or {}), "suite": "ioc", "items": len(rows),
                                                  "wall_s": round(time.time() - started, 1)}, indent=1), encoding="utf-8")
    return out
