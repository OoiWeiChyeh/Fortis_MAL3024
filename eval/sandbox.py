"""
Isolates an evaluation run from the analyst's real Fortis data.

core/config.py reads its environment at import time, so `prepare()` must
run before anything imports `core` or `engine`. Every persistent path
(Chroma, SQLite, uploads, reports, model selection state) goes to the run
directory; the GGUF weights are read from the real models folder through
FORTIS_MODEL_PATH, which never writes active_model.json. This is the same
isolation the test suite needed after it clobbered the user's model choice
(commit 01d7d3a).
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

REPO = Path(__file__).resolve().parent.parent

CONFIGS: Dict[str, Dict[str, str]] = {
    # the platform as shipped upstream: no grounding, no fencing, no checks
    "baseline": {"FORTIS_INTEL_GROUNDING": "0", "FORTIS_SPOTLIGHT": "0", "FORTIS_VERIFY_IDS": "0", "FORTIS_LEAK_GUARD": "0"},
    # this fork's trust hardening
    "hardened": {"FORTIS_INTEL_GROUNDING": "1", "FORTIS_SPOTLIGHT": "1", "FORTIS_VERIFY_IDS": "1", "FORTIS_LEAK_GUARD": "1"},
    # ablations: one mechanism at a time
    "grounding-only": {"FORTIS_INTEL_GROUNDING": "1", "FORTIS_SPOTLIGHT": "0", "FORTIS_VERIFY_IDS": "1", "FORTIS_LEAK_GUARD": "0"},
    "spotlight-only": {"FORTIS_INTEL_GROUNDING": "0", "FORTIS_SPOTLIGHT": "1", "FORTIS_VERIFY_IDS": "1", "FORTIS_LEAK_GUARD": "1"},
}


def real_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home()) / "Fortis"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "Fortis"


def resolve_model(name: Optional[str]) -> Optional[Path]:
    """`name` may be a path or a case-insensitive substring of a GGUF in the
    real models folder (e.g. 'qwen3.5-4b', 'llama-3.2-3b')."""
    if not name:
        return None
    p = Path(name)
    if p.is_file():
        return p
    models = real_data_dir() / "models"
    hits = sorted(m for m in models.glob("*.gguf") if name.lower() in m.name.lower())
    if not hits:
        raise SystemExit(f"No GGUF matching '{name}' in {models}")
    return hits[0]


def prepare(run_dir: Path, *, config: str = "hardened", model: Optional[str] = None,
            rag_level: str = "standard", embeddings: str = "sentence-transformers",
            backend: Optional[str] = None) -> Dict[str, str]:
    if "core" in sys.modules or "core.config" in sys.modules:
        raise RuntimeError("eval.sandbox.prepare() must run before core is imported")
    run_dir.mkdir(parents=True, exist_ok=True)
    data = run_dir / "data"
    env = {
        "FORTIS_DATA_DIR": str(data),
        "FORTIS_MODELS_DIR": str(data / "models"),
        "CHROMA_PERSIST_DIR": str(data / "chroma"),
        "DB_PATH": str(data / "engagements.sqlite3"),
        "UPLOAD_DIR": str(data / "uploads"),
        "REPORT_DIR": str(data / "reports"),
        "RAG_LEVEL": rag_level,
        "EMBEDDING_BACKEND": embeddings,
        "FORTIS_ALLOWED_HOSTS": "127.0.0.1,localhost,::1,testserver",
        "ANONYMIZED_TELEMETRY": "False",
        "HF_HUB_OFFLINE": os.environ.get("HF_HUB_OFFLINE", "1"),  # weights must already be cached
    }
    if rag_level != "full":
        env["RERANK_BACKEND"] = "none"
    env.update(CONFIGS[config])
    path = resolve_model(model)
    if path:
        env["FORTIS_MODEL_PATH"] = str(path)
        env["FORTIS_LLM_BACKEND"] = "llama"
    if backend:
        env["FORTIS_LLM_BACKEND"] = backend
    os.environ.update(env)
    return {**env, "model_file": path.name if path else None}


def provenance() -> Dict[str, str]:
    """What produced a result: commit, dirty flag, platform, versions."""
    def git(*a):
        try:
            return subprocess.run(["git", *a], cwd=REPO, capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            return ""
    out = {
        "commit": git("rev-parse", "--short", "HEAD"),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
    }
    try:
        import llama_cpp
        out["llama_cpp"] = llama_cpp.__version__
        out["gpu_offload"] = bool(llama_cpp.llama_supports_gpu_offload())
    except Exception:
        out["llama_cpp"] = None
    return out
