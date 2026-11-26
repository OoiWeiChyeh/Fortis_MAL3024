"""
SOC knowledge / grounding / injection benchmark (eval/datasets/soc_qa.jsonl),
driven black-box through the real FastAPI app: create engagement -> upload
documents -> POST /chat. What is measured is what an analyst would get.

Generation is greedy (temperature 0) so a run is repeatable; the shipped UI
uses 0.2. Answers are capped at --max-tokens to bound CPU run time; key
facts are expected early in a consultant answer, and truncation is recorded.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

from .metrics import score_item, strip_verification

DATASET = Path(__file__).parent / "datasets" / "soc_qa.jsonl"


def load_items(only: List[str] = None) -> List[Dict]:
    items = [json.loads(l) for l in DATASET.read_text(encoding="utf-8").splitlines() if l.strip()]
    if only:
        items = [i for i in items if i["id"] in only or i["category"] in only]
    return items


def _done_ids(path: Path) -> set:
    if not path.exists():
        return set()
    return {json.loads(l)["id"] for l in path.read_text(encoding="utf-8").splitlines() if l.strip()}


def run(out_dir: Path, *, max_tokens: int = 640, only: List[str] = None, meta: Dict = None) -> Path:
    from fastapi.testclient import TestClient

    import engine
    from core.main import app
    from core.routers import chat as chat_router
    from eval.sandbox import REPO

    # greedy decoding + a token cap, applied at the router's call site so the
    # rest of the pipeline (condense, structured intents, footer) is untouched
    _orig = chat_router.chat

    async def _chat(messages, temperature=0.2, json_mode=False, **_):
        return await _orig(messages, temperature=0.0, json_mode=json_mode, max_tokens=max_tokens)

    chat_router.chat = _chat

    items = load_items(only)
    out = out_dir / "answers.jsonl"
    done = _done_ids(out)
    started = time.time()
    with TestClient(app) as client:
        engagements: Dict[tuple, str] = {}
        for item in items:
            key = tuple(item.get("docs", []))
            if key in engagements:
                continue
            r = client.post("/engagements", json={"client_name": "Eval Harness",
                                                   "engagement_name": f"set {len(engagements):02d}", "notes": ""})
            r.raise_for_status()
            eid = r.json()["id"]
            for doc in key:
                p = REPO / doc
                with open(p, "rb") as fh:
                    up = client.post("/upload", files={"file": (p.name, fh)}, data={"engagement_id": eid})
                up.raise_for_status()
            engagements[key] = eid

        tokenizer = None
        with out.open("a", encoding="utf-8") as fh:
            for n, item in enumerate(items, 1):
                if item["id"] in done:
                    continue
                eid = engagements[tuple(item.get("docs", []))]
                t0 = time.perf_counter()
                r = client.post("/chat", json={"engagement_id": eid, "message": item["question"], "history": []})
                dt = time.perf_counter() - t0
                if r.status_code != 200:
                    rec = {"id": item["id"], "category": item["category"], "error": f"HTTP {r.status_code}: {r.text[:300]}",
                           "latency_s": dt, "passed": False}
                else:
                    reply = r.json()["reply"]
                    answer = strip_verification(reply)
                    if tokenizer is None and engine.get_backend() == "llama":
                        from engine.llama_engine import _STATE
                        tokenizer = _STATE.get("model")
                    toks = len(tokenizer.tokenize(answer.encode("utf-8"), add_bos=False)) if tokenizer else None
                    rec = score_item(item, answer)
                    rec.update({
                        "latency_s": round(dt, 2),
                        "completion_tokens": toks,
                        "tokens_per_s": round(toks / dt, 2) if toks else None,
                        "truncated": bool(toks and toks >= max_tokens - 2),
                        "footer": reply[len(answer):].strip() or None,
                        "answer": answer,
                    })
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                print(f"[{n}/{len(items)}] {item['id']:6s} pass={rec.get('passed')!s:5s} "
                      f"recall={rec.get('fact_recall')} bad_ids={rec.get('ids_bad')} {dt:5.1f}s", flush=True)
    (out_dir / "run.json").write_text(json.dumps({**(meta or {}), "suite": "qa", "max_tokens": max_tokens,
                                                  "items": len(items), "wall_s": round(time.time() - started, 1)},
                                                 indent=1), encoding="utf-8")
    return out
