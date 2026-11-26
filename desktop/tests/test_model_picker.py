"""Model picker: downloaded-model detection, one-click load, fit notes and
path safety. Field reports behind these tests (2026-11-26, RTX 3050 laptop,
CPU llama.cpp build):
- Qwen3.5 4B/2B files on disk were shown as "will download from Hugging Face";
- each click re-contacted Hugging Face and logged a new "Downloaded" line;
- the Chat & analysis group was always empty;
- tiers were greyed out for VRAM although the engine runs on CPU.
"""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def models(monkeypatch):
    from core.config import settings
    from engine import model_manager
    d = tempfile.mkdtemp(prefix="fortis-picker-")
    monkeypatch.setattr(settings, "models_dir", d)
    monkeypatch.setattr(model_manager, "_STATE_FILE", os.path.join(d, "active_model.json"))
    paths = {}
    for name in ("Qwen3.5-4B-Q4_K_M.gguf", "Qwen3.5-2B-Q4_K_M.gguf", "Llama-3.2-3B-Instruct-Q4_K_M.gguf",
                 "Qwen2.5-Coder-3B-Instruct-Q4_K_M.gguf", "my-custom-finetune.gguf"):
        p = os.path.join(d, name)
        with open(p, "wb") as f:
            f.write(b"gguf")
        paths[name] = p
    return d, paths


def test_tier_for_file_is_case_insensitive_and_any_pattern():
    from engine.model_manager import tier_for_file
    assert tier_for_file("Qwen3.5-4B-Q4_K_M.gguf") == "4b"
    assert tier_for_file("qwen3.5_2b.gguf") == "2b"
    assert tier_for_file("Qwen2.5-Coder-3B-Instruct-Q4_K_M.gguf") == "3b-coder"
    assert tier_for_file("Llama-3.2-3B-Instruct-Q4_K_M.gguf") == "3b-llama"
    assert tier_for_file("my-custom-finetune.gguf") is None


def test_downloaded_qwen_tiers_are_recognised(models):
    from engine.model_manager import tier_status
    st = tier_status()
    assert st["4b"]["downloaded"] and st["2b"]["downloaded"]
    assert st["4b"]["path"].endswith("Qwen3.5-4B-Q4_K_M.gguf")
    assert not st["0.8b"]["downloaded"]


def test_local_models_include_uncatalogued_files(models):
    from engine.model_manager import local_model_status, set_selection
    d, paths = models
    set_selection(paths["my-custom-finetune.gguf"])
    local = {m["name"]: m for m in local_model_status()}
    assert set(local) == set(paths)
    assert local["my-custom-finetune.gguf"]["active"] and local["my-custom-finetune.gguf"]["tier"] is None
    assert local["Qwen3.5-4B-Q4_K_M.gguf"]["roles"]


@pytest.fixture
def client(models, monkeypatch):
    import engine.llama_engine as le
    from server.app import app
    loads = []

    def fake_load(path=None, n_ctx=None):
        loads.append(path)
        le._STATE.update(model=object(), path=path, error=None, offload_level=0)

    monkeypatch.setattr(le, "load_model", fake_load)
    monkeypatch.setattr(le, "unload", lambda: le._STATE.update(model=None, path=None))
    with TestClient(app) as c:
        yield c, models, loads
    le._STATE.update(model=None, path=None, error=None, offload_level=None, loading=False)


def test_status_lists_local_models_with_fit_and_never_blocks_on_vram(client, monkeypatch):
    from engine.hardware import Hardware
    monkeypatch.setattr("server.app.detect", lambda: Hardware(ram_gb=15.2, vram_gb=4.0, has_nvidia=True))
    monkeypatch.setattr("server.app.can_use_cuda", lambda: False)   # CPU build
    c, _, _ = client
    st = c.get("/api/model/status").json()
    assert {m["name"] for m in st["local_models"]} >= {"Qwen3.5-4B-Q4_K_M.gguf", "my-custom-finetune.gguf"}
    # 8B on a CPU build with 15 GB RAM runs on CPU; it is not greyed out for VRAM
    assert st["tiers"]["8b-llama"]["fit"] == "cpu"
    assert all(t["fit"] != "too-large" for t in st["tiers"].values())
    assert "downloading" in st and "loaded_model" in st


def test_fit_rules():
    from engine.hardware import Hardware
    from server.app import model_fit
    gpu = Hardware(ram_gb=16, vram_gb=8, has_nvidia=True)
    assert model_fit(3.4, 3.5, gpu, True)["fit"] == "gpu"
    assert model_fit(6.6, 8, Hardware(16, 4, True), True)["fit"] == "partial"
    assert model_fit(6.6, 8, Hardware(16, 4, True), False)["fit"] == "cpu"
    assert model_fit(6.6, 8, Hardware(6, 0, False), False)["fit"] == "too-large"


def test_one_click_load_selects_and_loads(client):
    from engine.model_manager import current_selection
    c, (d, paths), loads = client
    r = c.post("/api/model/load", json={"path": paths["Qwen3.5-2B-Q4_K_M.gguf"]})
    assert r.status_code == 200 and r.json()["status"] == "ready"
    assert loads == [os.path.realpath(paths["Qwen3.5-2B-Q4_K_M.gguf"])]
    assert os.path.realpath(current_selection()) == os.path.realpath(paths["Qwen3.5-2B-Q4_K_M.gguf"])
    st = c.get("/api/model/status").json()
    row = next(m for m in st["local_models"] if m["name"] == "Qwen3.5-2B-Q4_K_M.gguf")
    assert row["active"] and row["loaded"]
    # clicking the loaded model again is a no-op, not a reload
    again = c.post("/api/model/load", json={"path": paths["Qwen3.5-2B-Q4_K_M.gguf"]}).json()
    assert again.get("already_loaded") and len(loads) == 1


def test_load_by_tier_and_switch_keeps_pinned_path_in_step(client, monkeypatch):
    c, (d, paths), loads = client
    monkeypatch.setenv("FORTIS_MODEL_PATH", paths["Llama-3.2-3B-Instruct-Q4_K_M.gguf"])  # pinned by an earlier load
    assert c.post("/api/model/select", json={"tier": "4b"}).status_code == 200
    assert os.environ["FORTIS_MODEL_PATH"].endswith("Qwen3.5-4B-Q4_K_M.gguf")


def test_download_of_present_tier_does_not_touch_the_network(client, monkeypatch):
    from engine import model_manager
    monkeypatch.setattr(model_manager, "download_tier", lambda *a, **k: pytest.fail("network download attempted"))
    c, _, _ = client
    r = c.post("/api/model/download/4b").json()
    assert r["status"] == "already_downloaded" and r["path"].endswith("Qwen3.5-4B-Q4_K_M.gguf")


def test_select_rejects_paths_outside_the_models_folder(client):
    c, _, _ = client
    outside = os.path.join(tempfile.mkdtemp(), "evil.gguf")
    with open(outside, "wb") as f:
        f.write(b"x")
    assert c.post("/api/model/load", json={"path": outside}).status_code == 400
    assert c.post("/api/model/select", json={"path": "C:/Windows/win.ini"}).status_code == 404
    assert c.post("/api/model/select", json={"tier": "0.8b"}).status_code == 404  # not downloaded
