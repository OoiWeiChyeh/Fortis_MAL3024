"""
Triage agent vs a single prompt, on the 12 gold advisories.

The single-prompt baseline is deliberately strong, not a strawman: the same
model gets the same advisory, the client's full asset inventory, the client
sector and the exact P1-P4 rubric the agent uses, and is asked for the same
structured answer. The difference measured is therefore the architecture
(decomposition + deterministic tools + verification), not extra information.

Metrics per advisory: priority accuracy; exposure P/R (asset names); ATT&CK
technique P/R with parent/sub-technique credit; fabricated technique ids
(not in ATT&CK at all); CVE recall; wall-clock latency. For the agent, the
number of identifier issues left in the narrative after verification.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict

from .ioc_bench import ADV, gold
from .metrics import prf, technique_match

INVENTORY = Path(__file__).parent / "datasets" / "docs" / "bayu-capital-asset-inventory.csv"
CLIENT = "Bayu Capital Berhad, a Malaysian financial services firm (investment banking and stock brokerage)"

BASELINE = """You are Fortis, a senior SOC analyst. Triage the threat advisory for the client.

Client: {client}
Client asset inventory (CSV):
{inventory}

Priority rubric:
{rubric}

<<<ADVISORY>>>
{advisory}
<<<END ADVISORY>>>

Reply with JSON only:
{{"priority": "P1|P2|P3|P4", "exposed_assets": ["hostname", ...], "techniques": ["T1234.001", ...],
 "cves": ["CVE-..."], "summary": "2-3 sentences", "actions": ["...", "..."]}}"""


def _parse(raw: str) -> Dict:
    try:
        s, e = raw.find("{"), raw.rfind("}")
        d = json.loads(raw[s:e + 1])
        return d if isinstance(d, dict) else {}
    except (ValueError, TypeError):
        return {}


def _fabricated(ids) -> list:
    from core.intel.enrich import technique_status
    return sorted(t for t in ids if technique_status(t) == "unknown")


def _score(pred_priority, pred_assets, pred_tech, pred_cves, g) -> Dict:
    return {
        "priority": pred_priority, "priority_ok": pred_priority == g["priority"],
        "exposure": prf(set(pred_assets), set(g["exposed_assets"])),
        "techniques": technique_match(pred_tech, g["techniques"]),
        "fabricated_techniques": _fabricated(pred_tech),
        "cve_recall": prf(set(pred_cves), set(g["cves"]))["recall"],
    }


async def _baseline(text: str, inventory: str) -> Dict:
    from engine import chat
    from core.agents.triage import PRIORITY_RUBRIC
    raw = await chat([{"role": "user", "content": BASELINE.format(client=CLIENT, inventory=inventory, rubric=PRIORITY_RUBRIC,
                                                                 advisory=text)}],
                     temperature=0.0, json_mode=True, max_tokens=700)
    d = _parse(raw)
    tech = [str(t).strip().upper() for t in d.get("techniques", []) if re.fullmatch(r"T\d{4}(\.\d{3})?", str(t).strip().upper())]
    return {"raw": raw, "priority": str(d.get("priority", "")).strip().upper()[:2],
            "assets": [str(a).strip() for a in d.get("exposed_assets", []) if isinstance(a, (str, int))],
            "techniques": tech, "cves": [str(c).upper() for c in d.get("cves", []) if isinstance(c, str)]}


def run(out_dir: Path, *, meta: Dict = None) -> Path:
    from core.agents.triage import triage
    from core.intel.inventory import parse_inventory

    inv_text = INVENTORY.read_text(encoding="utf-8")
    assets = parse_inventory(inv_text)
    out = out_dir / "results.jsonl"
    done = {json.loads(l)["id"] for l in out.read_text(encoding="utf-8").splitlines()} if out.exists() else set()
    started = time.time()
    with out.open("a", encoding="utf-8") as fh:
        for g in gold():
            if g["id"] in done:
                continue
            text = (ADV / f"{g['id']}.md").read_text(encoding="utf-8")
            t0 = time.perf_counter()
            r = asyncio.run(triage(text, inventory=assets, client=CLIENT))
            agent_s = time.perf_counter() - t0
            agent = _score(r.priority, [e["name"] for e in r.exposures], [t["id"] for t in r.techniques],
                           [c["cve"] for c in r.cves], g)
            agent.update({"latency_s": round(agent_s, 1), "repaired": r.repaired,
                          "narrative_issues": r.verification.get("issues_after", []),
                          "rejected_techniques": r.dropped_techniques, "narrative": r.narrative,
                          "steps": [s.__dict__ for s in r.steps]})
            t0 = time.perf_counter()
            b = asyncio.run(_baseline(text, inv_text))
            base_s = time.perf_counter() - t0
            base = _score(b["priority"], b["assets"], b["techniques"], b["cves"], g)
            base.update({"latency_s": round(base_s, 1), "raw": b["raw"]})
            rec = {"id": g["id"], "gold_priority": g["priority"], "agent": agent, "single_prompt": base}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            print(f"{g['id']} gold={g['priority']} agent={r.priority} ({agent_s:.0f}s, tech F1 {agent['techniques']['f1']:.2f}) "
                  f"| single={b['priority']} ({base_s:.0f}s, tech F1 {base['techniques']['f1']:.2f}, "
                  f"exp F1 {base['exposure']['f1']:.2f}, fab {base['fabricated_techniques']})", flush=True)
    (out_dir / "run.json").write_text(json.dumps({**(meta or {}), "suite": "triage", "client": CLIENT,
                                                  "wall_s": round(time.time() - started, 1)}, indent=1), encoding="utf-8")
    return out
