"""
Fortis Desktop server: the core FastAPI app (engagements, upload, chat,
report) plus a small /api layer for the UI (slash commands, model
management, report saving), and the static chat UI itself.

Run headless with:  python -m server.app --port 8757
(the desktop launcher in desktop/app.py imports create_server instead).
"""
import argparse
import os
import urllib.parse
import subprocess
import sys
import threading
import webbrowser

from fastapi import APIRouter, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from core.config import settings
from core.main import app as core_app  # FastAPI app with all core routers
import engine
import engine.llama_engine
import engine.model_manager as model_manager
from engine.hardware import detect, suggest_tier, can_use_cuda, suggest_tiers
from server.orchestration import Orchestrator

PORT = int(os.getenv("FORTIS_PORT", "8757"))

orch = Orchestrator()

api = APIRouter(prefix="/api")


# ---- UI helpers --------------------------------------------------------------

class CommandRequest(BaseModel):
    text: str


@api.post("/command")
async def command(req: CommandRequest):
    """Slash-command passthrough from the UI (also usable headless)."""
    reply = orch.handle_command(req.text)
    if reply is None:
        raise HTTPException(400, "Not a recognized command. Try /engagements, /new-engagement, /use, /whoami, /close-engagement, /report, /triage, /iocs.")
    return {"text": reply}


# ---- model management ---------------------------------------------------------

def model_fit(size_gb: float, min_vram_gb: float, hw, gpu: bool) -> dict:
    """How a model of `size_gb` will run on this machine. Nothing is blocked
    on VRAM: the engine offloads partially and runs on CPU without CUDA, so
    on a CPU build RAM is the real limit (model + ~1.5 GB working memory)."""
    size = float(size_gb or 0)
    if gpu and hw.vram_gb >= max(min_vram_gb or 0, size + 0.8):
        return {"fit": "gpu", "note": "runs on the GPU"}
    if gpu and hw.vram_gb > 0:
        return {"fit": "partial", "note": "part GPU, part CPU (slower)"}
    if hw.ram_gb and size + 1.5 > hw.ram_gb:
        return {"fit": "too-large", "note": f"needs about {size + 1.5:.0f} GB RAM; this machine has {hw.ram_gb:.0f} GB"}
    return {"fit": "cpu", "note": "runs on the CPU"}


def _loaded_path():
    st = engine.llama_engine._STATE
    return st["path"] if st["model"] is not None else None


@api.get("/model/status")
async def model_status():
    hw = detect()
    warning = await engine.check_model_available()
    hardware_info = engine.llama_engine.hardware_status(hw)
    gpu = can_use_cuda()
    hardware_info["can_cuda"] = gpu
    tiers = model_manager.tier_status()
    for t in tiers.values():
        t.update(model_fit(t["size_gb"], t["min_vram_gb"], hw, gpu))
    local = model_manager.local_model_status()
    loaded = _loaded_path()
    for m in local:
        info = model_manager.TIERS.get(m["tier"] or "", {})
        m.update(model_fit(m["size_gb"], info.get("min_vram_gb", 0), hw, gpu))
        m["loaded"] = bool(loaded and os.path.abspath(loaded) == os.path.abspath(m["path"]))
    return {
        "hardware": hardware_info,
        "suggested_tier": suggest_tier(hw),
        "suggested_tiers": suggest_tiers(hw),
        "tiers": tiers,
        "local_models": local,
        "active_model": model_manager.current_selection(),
        "loaded": engine.llama_engine._STATE["model"] is not None,
        "loaded_model": os.path.basename(loaded) if loaded else None,
        "loading": bool(engine.llama_engine._STATE.get("loading")),
        "downloading": not model_manager.download_progress()["done"],
        "load_error": engine.llama_engine._STATE["error"],
        "warning": warning,
    }


class TierRequest(BaseModel):
    tier: str


@api.post("/model/download/{tier}")
async def model_download(tier: str):
    if tier not in model_manager.TIERS:
        raise HTTPException(400, f"Unknown tier '{tier}'")
    # already downloaded? just select it. (The old check compared "-4b-"
    # case-sensitively with "Qwen3.5-4B-...", so every click re-contacted
    # Hugging Face and logged a fresh "Downloaded" line.)
    existing = model_manager.local_path_for_tier(tier)
    if existing:
        _select_path(existing)
        return {"status": "already_downloaded", "path": existing}
    prog = model_manager.download_progress()
    if not prog["done"] and prog["tier"] == tier:
        return {"status": "in_progress"}
    threading.Thread(target=_download_worker, args=(tier,), daemon=True).start()
    return {"status": "started"}


def _download_worker(tier: str):
    try:
        model_manager.download_tier(tier)
    except Exception as e:
        print(f"[model download] failed: {e}", file=sys.stderr)


@api.get("/model/download/progress")
async def model_download_progress():
    return model_manager.download_progress()


@api.get("/report/progress")
async def report_progress():
    from core import progress
    return progress.snapshot()


class SelectRequest(BaseModel):
    tier: str = ""
    path: str = ""


def _models_root() -> str:
    return os.path.realpath(settings.models_dir)


def _resolve_request_path(req: "SelectRequest") -> str:
    if req.tier:
        path = model_manager.local_path_for_tier(req.tier)
        if not path:
            raise HTTPException(404, f"Tier '{req.tier}' is not downloaded yet.")
        return path
    if not req.path or not req.path.lower().endswith(".gguf") or not os.path.isfile(req.path):
        raise HTTPException(404, "Model file not found.")
    # only files Fortis manages: the UI sends paths it was given, but this is
    # still an HTTP input and must not name arbitrary files on disk
    real = os.path.realpath(req.path)
    if os.path.commonpath([real, _models_root()]) != _models_root():
        raise HTTPException(400, "Only models in the Fortis models folder can be selected.")
    return real


def _select_path(path: str) -> None:
    tier = model_manager.tier_for_file(path)
    if tier and "n_ctx" in model_manager.TIERS[tier]:
        settings.n_ctx = model_manager.TIERS[tier]["n_ctx"]
    model_manager.set_selection(path)
    # an earlier explicit load pins FORTIS_MODEL_PATH, which outranks the
    # selection file; keep it in step so a switch is never silently ignored
    if os.environ.get("FORTIS_MODEL_PATH"):
        os.environ["FORTIS_MODEL_PATH"] = path
    engine.llama_engine.unload()


@api.post("/model/select")
async def model_select(req: SelectRequest):
    """Selects a model; it loads on the next message (or via /model/load)."""
    path = _resolve_request_path(req)
    _select_path(path)
    return {"status": "selected", "path": path, "n_ctx": settings.n_ctx}


@api.post("/model/load")
async def model_load(req: SelectRequest):
    """One-click use: select the model and load it now, so the next message
    answers immediately instead of absorbing the load time."""
    import asyncio
    import time

    path = _resolve_request_path(req)
    if _loaded_path() and os.path.abspath(_loaded_path()) == os.path.abspath(path):
        return {"status": "ready", "path": path, "seconds": 0.0, "already_loaded": True,
                "hardware": engine.llama_engine.hardware_status()}
    _select_path(path)
    t0 = time.perf_counter()
    engine.llama_engine._STATE["loading"] = True
    try:
        await asyncio.get_running_loop().run_in_executor(None, engine.llama_engine.load_model, path, settings.n_ctx)
    except Exception as e:
        raise HTTPException(500, f"Could not load {os.path.basename(path)}: {e}")
    finally:
        engine.llama_engine._STATE["loading"] = False
    return {"status": "ready", "path": path, "seconds": round(time.perf_counter() - t0, 1),
            "hardware": engine.llama_engine.hardware_status()}


# ---- reports -------------------------------------------------------------------

@api.post("/report/save")
async def report_save(req: dict):
    engagement_id = req.get("engagement_id", "")
    fmt = req.get("format", "docx")
    focus = req.get("focus_instructions", "")
    allow_stub = bool(req.get("allow_stub", False))
    result = orch.generate_report_download(
        engagement_id, fmt, focus, allow_stub=allow_stub, enforce_stub_gate=True
    )
    if "error" in result:
        raise HTTPException(result.get("status", 400), result["error"])
    return result


class OpenExternalRequest(BaseModel):
    url: str


@api.post("/open-external")
async def open_external(req: OpenExternalRequest):
    url = req.url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "URL must be a valid http:// or https:// URL")
    threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    return {"status": "opened", "url": url}


@api.post("/open-path")
async def open_path(req: dict):
    path = req.get("path", "")
    if not path or not os.path.exists(path):
        raise HTTPException(404, "Path not found")
    try:
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return {"status": "opened"}
    except Exception as e:
        raise HTTPException(500, str(e))


@api.post("/reports/open-folder")
async def open_reports_folder():
    try:
        if sys.platform == "win32":
            os.startfile(os.path.normpath(settings.report_dir))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", settings.report_dir])
        else:
            subprocess.Popen(["xdg-open", settings.report_dir])
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"path": settings.report_dir}


# ---- wiring ---------------------------------------------------------------------

app = core_app
app.include_router(api)

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/ui", StaticFiles(directory=_STATIC_DIR, html=True), name="ui")


@app.get("/")
async def index():
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))


def create_server(host: str = "127.0.0.1", port: int = PORT):
    import uvicorn
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    return uvicorn.Server(config)


def main():
    parser = argparse.ArgumentParser(description="Fortis desktop server (headless)")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
