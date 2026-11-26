"""
Aggregates eval/results/** into docs/evaluation/results.md, summary.json and
figures. Every QA answer is RE-SCORED from its stored text with the current
eval/metrics.py, so a scorer fix applies to all runs uniformly and the
numbers in the report always match the code in the repo.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from .metrics import mcnemar_exact, percentile, score_item, wilson

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "eval" / "results"
OUT = ROOT / "docs" / "evaluation"
ITEMS = {json.loads(l)["id"]: json.loads(l) for l in (ROOT / "eval/datasets/soc_qa.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}

BASE, HARD = "#f47230", "#257de0"   # categorical slots 2 and 1 (validated reference palette)
INK, INK2, GRID = "#191919", "#666666", "#e6e6e6"


def _jsonl(p: Path) -> List[Dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def _pct(x):
    return "–" if x is None else f"{100 * x:.0f}%"


def _ci(k, n):
    w = wilson(k, n)
    return f"{k}/{n} = {100 * w['p']:.0f}% [{100 * w['lo']:.0f}–{100 * w['hi']:.0f}]" if n else "–"


# ---------------------------------------------------------------------------
# QA
# ---------------------------------------------------------------------------

def qa_runs() -> Dict[str, Dict]:
    runs = {}
    for d in sorted((RES / "qa").glob("*")):
        rows = _jsonl(d / "answers.jsonl")
        if not rows:
            continue
        meta = json.loads((d / "run.json").read_text(encoding="utf-8")) if (d / "run.json").exists() else {}
        scored = []
        for r in rows:
            if "answer" not in r:
                scored.append({**r, "passed": False})
                continue
            s = score_item(ITEMS[r["id"]], r["answer"])
            s.update({k: r.get(k) for k in ("latency_s", "completion_tokens", "tokens_per_s", "truncated", "footer", "answer")})
            scored.append(s)
        runs[d.name] = {"meta": meta, "rows": scored, "complete": bool(meta)}
    return runs


def qa_aggregate(rows: List[Dict]) -> Dict:
    n = len(rows)
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    emitted = sum(r.get("ids_emitted", 0) for r in rows)
    bad = sum(r.get("ids_bad", 0) for r in rows)
    fp = by_cat.get("false_premise", [])
    os_ = by_cat.get("out_of_scope", [])
    inj = [r for r in rows if r.get("injected") is not None]
    non_os = [r for r in rows if r["category"] != "out_of_scope"]
    lat = [r["latency_s"] for r in rows if r.get("latency_s")]
    return {
        "n": n,
        "pass": sum(r["passed"] for r in rows),
        "fact_recall_mean": statistics.mean([r["fact_recall"] for r in rows if r.get("fact_recall") is not None] or [0]),
        "by_category": {c: {"n": len(v), "pass": sum(x["passed"] for x in v)} for c, v in sorted(by_cat.items())},
        "ids_emitted": emitted, "ids_bad": bad, "ids_stale": sum(r.get("ids_stale", 0) for r in rows),
        "answers_with_bad_id": sum(1 for r in rows if r.get("ids_bad")),
        "bad_id_examples": [dict(item=r["id"], **b) for r in rows for b in r.get("bad_ids", [])],
        "false_premise_rejected": sum(r["passed"] for r in fp), "false_premise_n": len(fp),
        "refusal_correct": sum(r["refused"] for r in os_), "refusal_n": len(os_),
        "over_refusals": sum(r.get("over_refusal", False) for r in non_os), "over_refusal_n": len(non_os),
        "injection_success": sum(bool(r["injected"]) for r in inj), "injection_n": len(inj),
        "injection_flagged": sum(bool(r.get("injection_flagged")) for r in inj),
        "latency_p50": percentile(lat, 0.5), "latency_p90": percentile(lat, 0.9),
        "tok_s_mean": statistics.mean([r["tokens_per_s"] for r in rows if r.get("tokens_per_s")] or [0]),
        "truncated": sum(1 for r in rows if r.get("truncated")),
    }


def paired(a: List[Dict], b: List[Dict], key) -> Dict:
    A = {r["id"]: key(r) for r in a}
    B = {r["id"]: key(r) for r in b}
    ids = sorted(set(A) & set(B))
    b_only = sum(1 for i in ids if A[i] and not B[i])
    c_only = sum(1 for i in ids if B[i] and not A[i])
    return {"n": len(ids), "a_only": b_only, "b_only": c_only, "p": mcnemar_exact(b_only, c_only)}


# ---------------------------------------------------------------------------
# other suites
# ---------------------------------------------------------------------------

def redteam() -> Dict:
    out = {}
    for d in sorted((RES / "redteam").glob("*")):
        rows = _jsonl(d / "answers.jsonl")
        if rows:
            out[d.name] = rows
    return out


def triage() -> List[Dict]:
    for d in sorted((RES / "triage").glob("*")):
        rows = _jsonl(d / "results.jsonl")
        if rows:
            return rows
    return []


def ioc() -> Dict[str, List[Dict]]:
    out = {}
    for d in sorted((RES / "ioc").glob("*")):
        rows = _jsonl(d / "results.jsonl")
        if rows:
            out[d.name] = rows
    return out


def _micro(rows, key):
    rs = [r[key] for r in rows if key in r]
    tp, fp, fn = (sum(r[k] for r in rs) for k in ("tp", "fp", "fn"))
    p = tp / (tp + fp) if tp + fp else 0
    rc = tp / (tp + fn) if tp + fn else 0
    return {"n": len(rs), "precision": p, "recall": rc, "f1": 2 * p * rc / (p + rc) if p + rc else 0,
            "invented": sum(len(r["invented"]) for r in rs), "fp": fp, "fn": fn,
            "cve_recall": statistics.mean([r["cve"]["recall"] for r in rs]) if rs else 0}


# ---------------------------------------------------------------------------
# figures
# ---------------------------------------------------------------------------

def _style(ax):
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK2, length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _grouped_h(path, labels, series, title, xlabel, xmax=1.0, fmt="{:.0%}"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    n = len(labels)
    fig, ax = plt.subplots(figsize=(7.2, 0.42 * n * len(series) + 1.3), dpi=160)
    h = 0.8 / len(series)
    for k, (name, color, vals) in enumerate(series):
        ys = [i + (k - (len(series) - 1) / 2) * h for i in range(n)]
        ax.barh(ys, vals, height=h - 0.04, color=color, label=name, edgecolor="white", linewidth=1)
        for y, v in zip(ys, vals):
            if v is not None:
                ax.text(v + xmax * 0.01, y, fmt.format(v), va="center", fontsize=7.5, color=INK)
    ax.set_yticks(range(n), labels, fontsize=8.5, color=INK)
    ax.invert_yaxis()
    ax.set_xlim(0, xmax * 1.12)
    ax.set_xlabel(xlabel, fontsize=8, color=INK2)
    ax.set_title(title, fontsize=10, color=INK, loc="left", pad=10)
    _style(ax)
    ax.legend(frameon=False, fontsize=8, loc="lower right", bbox_to_anchor=(1, 1.0), ncol=len(series))
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# Evaluation results", "",
          "_Generated by `python -m eval summarize` from `eval/results/`. Every QA answer is re-scored with the "
          "current `eval/metrics.py`. Intervals are 95% Wilson; paired tests are exact McNemar._", ""]
    summary: Dict = {}

    runs = qa_runs()
    agg = {k: qa_aggregate(v["rows"]) for k, v in runs.items()}
    summary["qa"] = agg
    if agg:
        md += ["## 1. SOC knowledge, grounding and injection benchmark (53 items)", "",
               "| Run | Items | Pass (95% CI) | Mean fact recall | Ids emitted | Hallucinated ids | Answers with ≥1 | Stale ids | "
               "False premise rejected | Out-of-scope refused | Over-refusals | Injection succeeded | p50 latency |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for k, a in agg.items():
            md.append(f"| `{k}` | {a['n']} | {_ci(a['pass'], a['n'])} | {a['fact_recall_mean']:.2f} | {a['ids_emitted']} | "
                      f"{a['ids_bad']} ({_pct(a['ids_bad'] / a['ids_emitted'] if a['ids_emitted'] else None)}) | "
                      f"{a['answers_with_bad_id']} | {a['ids_stale']} | {a['false_premise_rejected']}/{a['false_premise_n']} | "
                      f"{a['refusal_correct']}/{a['refusal_n']} | {a['over_refusals']} | {a['injection_success']}/{a['injection_n']} | "
                      f"{a['latency_p50']:.0f}s |" if a['latency_p50'] else "| – |")
        md.append("")
        # per category, paired
        for model in sorted({k.split("__")[0] for k in runs}):
            b, h = f"{model}__baseline", f"{model}__hardened"
            if b in runs and h in runs:
                ab, ah = agg[b], agg[h]
                cats = sorted(set(ab["by_category"]) & set(ah["by_category"]))
                md += [f"### {model}: baseline vs hardened by category", "",
                       "| Category | Baseline pass | Hardened pass |", "|---|---|---|"]
                for c in cats:
                    x, y = ab["by_category"][c], ah["by_category"][c]
                    md.append(f"| {c} | {x['pass']}/{x['n']} | {y['pass']}/{y['n']} |")
                pp = paired(runs[b]["rows"], runs[h]["rows"], lambda r: r["passed"])
                pb = paired(runs[b]["rows"], runs[h]["rows"], lambda r: not r.get("ids_bad"))
                md += ["", f"Paired on {pp['n']} items: pass flips baseline-only {pp['a_only']}, hardened-only {pp['b_only']} "
                           f"(McNemar p = {pp['p']:.3f}); answers free of hallucinated ids flips baseline-only {pb['a_only']}, "
                           f"hardened-only {pb['b_only']} (p = {pb['p']:.3f}).", ""]
                summary.setdefault("paired", {})[model] = {"pass": pp, "no_bad_ids": pb}
                _grouped_h(OUT / f"fig-qa-{model}.png", cats,
                           [("baseline", BASE, [ab["by_category"][c]["pass"] / ab["by_category"][c]["n"] for c in cats]),
                            ("hardened", HARD, [ah["by_category"][c]["pass"] / ah["by_category"][c]["n"] for c in cats])],
                           f"{model}: pass rate by category", "share of items passed")
                md += [f"![{model} pass rate by category](fig-qa-{model}.png)", ""]
        ex = [e for a in agg.values() for e in a["bad_id_examples"]]
        if ex:
            md += ["### Hallucinated identifiers found (all runs)", "", "| Run | Item | Id | Class | Detail |", "|---|---|---|---|---|"]
            for k, a in agg.items():
                for e in a["bad_id_examples"]:
                    md.append(f"| `{k}` | {e['item']} | {e['id']} | {e['status']} | {e['detail']} |")
            md.append("")

    rt = redteam()
    if rt:
        ops = list(dict.fromkeys(r["operator"] for rows in rt.values() for r in rows))
        md += ["## 2. Mutation red team: indirect prompt injection (21 cases per config)", "",
               "| Run | Model complied | Reached the user | Leak guard fired | Model flagged the injection |", "|---|---|---|---|---|"]
        for k, rows in rt.items():
            n = len(rows)
            md.append(f"| `{k}` | {_ci(sum(r['complied'] for r in rows), n)} | {_ci(sum(r['exposed_to_user'] for r in rows), n)} | "
                      f"{sum(r['guard_fired'] for r in rows)} | {sum(r['flagged_injection'] for r in rows)}/{n} |")
        md += ["", "Attack success (reached the user) by operator:", "", "| Operator | " + " | ".join(f"`{k}`" for k in rt) + " |",
               "|---|" + "---|" * len(rt)]
        for op in ops:
            md.append(f"| {op} | " + " | ".join(
                f"{sum(r['exposed_to_user'] for r in rows if r['operator'] == op)}/{sum(1 for r in rows if r['operator'] == op)}"
                for rows in rt.values()) + " |")
        md.append("")
        summary["redteam"] = {k: {"n": len(v), "complied": sum(r["complied"] for r in v),
                                  "exposed": sum(r["exposed_to_user"] for r in v)} for k, v in rt.items()}
        keys = list(rt)
        if len(keys) >= 2:
            series = []
            for k in keys:
                col = BASE if "baseline" in k else HARD
                series.append((k.split("__")[-1], col, [sum(r["exposed_to_user"] for r in rt[k] if r["operator"] == op) /
                                                        max(1, sum(1 for r in rt[k] if r["operator"] == op)) for op in ops]))
            _grouped_h(OUT / "fig-redteam.png", ops, series, "Injection attack success by mutation operator",
                       "share of attacks whose payload reached the user")
            md += ["![red team](fig-redteam.png)", ""]

    tr = triage()
    if tr:
        def mean(f):
            return statistics.mean(f(r) for r in tr)
        rows = {}
        for side in ("agent", "single_prompt"):
            rows[side] = {
                "priority accuracy": mean(lambda r: r[side]["priority_ok"]),
                "exposure F1": mean(lambda r: r[side]["exposure"]["f1"]),
                "technique precision": mean(lambda r: r[side]["techniques"]["precision"]),
                "technique recall": mean(lambda r: r[side]["techniques"]["recall"]),
                "CVE recall": mean(lambda r: r[side]["cve_recall"]),
            }
        fab = {s: sum(len(r[s]["fabricated_techniques"]) for r in tr) for s in ("agent", "single_prompt")}
        lat = {s: statistics.mean(r[s]["latency_s"] for r in tr) for s in ("agent", "single_prompt")}
        pa = paired([{"id": r["id"], "v": r["single_prompt"]["priority_ok"]} for r in tr],
                    [{"id": r["id"], "v": r["agent"]["priority_ok"]} for r in tr], lambda r: r["v"])
        md += [f"## 3. Advisory triage: agent vs single prompt ({len(tr)} advisories, same model, same inputs)", "",
               "| Metric | Single prompt | Agent |", "|---|---|---|"]
        for m in rows["agent"]:
            md.append(f"| {m} | {rows['single_prompt'][m]:.2f} | {rows['agent'][m]:.2f} |")
        md += [f"| fabricated technique ids | {fab['single_prompt']} | {fab['agent']} |",
               f"| mean latency | {lat['single_prompt']:.0f}s | {lat['agent']:.0f}s |",
               f"| narratives repaired | – | {sum(r['agent']['repaired'] for r in tr)} |",
               f"| identifier issues left after repair | – | {sum(len(r['agent']['narrative_issues']) for r in tr)} |", "",
               f"Priority correct: single-prompt-only {pa['a_only']}, agent-only {pa['b_only']} (McNemar p = {pa['p']:.3f}).", "",
               "| Advisory | Gold | Single prompt | Agent |", "|---|---|---|---|"]
        md += [f"| {r['id']} | {r['gold_priority']} | {r['single_prompt']['priority'] or '–'} | {r['agent']['priority']} |" for r in tr]
        md.append("")
        summary["triage"] = {"metrics": rows, "fabricated": fab, "latency": lat, "priority_paired": pa}
        mets = list(rows["agent"])
        _grouped_h(OUT / "fig-triage.png", mets, [("single prompt", BASE, [rows["single_prompt"][m] for m in mets]),
                                                  ("agent", HARD, [rows["agent"][m] for m in mets])],
                   "Advisory triage: agent vs single prompt", "mean over advisories", fmt="{:.2f}")
        md += ["![triage](fig-triage.png)", ""]

    io = ioc()
    if io:
        md += ["## 4. IOC extraction (12 advisories, 52 gold indicators)", "",
               "| Extractor | Precision | Recall | F1 | False positives | Invented (not in text) | CVE recall |", "|---|---|---|---|---|---|---|"]
        seen = set()
        for k, rows in io.items():
            for key, name in (("deterministic", "deterministic (core/intel/ioc.py)"), ("llm", f"LLM ({k})")):
                if key == "deterministic" and key in seen:
                    continue
                m = _micro(rows, key)
                if not m["n"]:
                    continue
                seen.add(key)
                md.append(f"| {name} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['fp']} | {m['invented']} | {m['cve_recall']:.2f} |")
                summary.setdefault("ioc", {})[name] = m
        inv = [(r["id"], x) for rows in io.values() for r in rows if "llm" in r for x in r["llm"]["invented"]]
        if inv:
            md += ["", "Invented by the LLM: " + ", ".join(f"{i} `{x}`" for i, x in inv[:20])]
        md.append("")

    (OUT / "results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1, default=str), encoding="utf-8")
    print(f"wrote {OUT / 'results.md'}")
    return 0
