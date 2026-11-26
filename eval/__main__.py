"""
Fortis evaluation harness.

    python -m eval qa --model qwen3.5-4b --config hardened
    python -m eval qa --model qwen3.5-4b --config baseline --only attack_id,false_premise
    python -m eval redteam --model qwen3.5-4b     # mutation-based injection red-team
    python -m eval ioc --model qwen3.5-4b         # deterministic vs LLM extraction
    python -m eval triage --model qwen3.5-4b      # triage agent vs single prompt
    python -m eval summarize                      # tables + charts -> docs/evaluation/

Every run writes eval/results/<suite>/<label>/ with the raw answers, the
per-item scores and run.json (commit, model file, config, platform), and is
resumable: re-running the same command skips items already answered.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RESULTS = Path(__file__).parent / "results"


def _label(args) -> str:
    model = (args.model or "stub").lower().replace(".gguf", "").replace("-q4_k_m", "")
    return f"{model}__{args.config}" + (f"__{args.rag}" if args.rag != "standard" else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval", description=__doc__.split("\n\n")[0])
    ap.add_argument("suite", choices=["qa", "redteam", "ioc", "triage", "summarize"])
    ap.add_argument("--model", help="GGUF path or name fragment in the Fortis models folder")
    ap.add_argument("--config", default="hardened", help="baseline | hardened | grounding-only | spotlight-only")
    ap.add_argument("--rag", default="standard", help="RAG_LEVEL for the run")
    ap.add_argument("--only", help="comma list of item ids or categories")
    ap.add_argument("--max-tokens", type=int, default=640)
    ap.add_argument("--embeddings", default="sentence-transformers", help="hash-stub for offline CI")
    ap.add_argument("--stub", action="store_true", help="use the stub LLM backend (pipeline smoke test)")
    ap.add_argument("--out", help="override the results directory")
    args = ap.parse_args(argv)

    if args.suite == "summarize":
        from .summarize import main as summarize
        return summarize()

    from . import sandbox

    if args.stub:
        args.model = None
    label = _label(args)
    out = Path(args.out or RESULTS / args.suite / label)
    env = sandbox.prepare(out, config=args.config, model=args.model, rag_level=args.rag,
                          embeddings=args.embeddings, backend="stub" if args.stub else None)
    meta = {**sandbox.provenance(), "label": label, "config": args.config, "rag_level": args.rag,
            "model_file": env.get("model_file"), "embeddings": args.embeddings}
    only = args.only.split(",") if args.only else None
    if args.suite == "qa":
        from .qa import run
        run(out, max_tokens=args.max_tokens, only=only, meta=meta)
    elif args.suite == "ioc":
        from .ioc_bench import run
        run(out, meta=meta)
    elif args.suite == "redteam":
        from .redteam import run
        run(out, max_tokens=args.max_tokens, meta=meta)
    elif args.suite == "triage":
        from .triage_bench import run
        run(out, meta=meta)
    print(f"results -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
