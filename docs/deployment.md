# Deployment and troubleshooting (Stage 1)

## Environment

| | |
|---|---|
| Machine | Laptop, AMD Ryzen 5 6600H (6 cores / 12 threads), 15.2 GB RAM, NVIDIA RTX 3050 Laptop 4 GB |
| OS / shell | Windows 11 Home, Windows PowerShell 5.1.26100 (the shell `setup.ps1` is launched with) |
| Python | 3.12.0 (python.org installer) |
| Inference | llama-cpp-python 0.3.36, **CPU build** (`llama_supports_gpu_offload() == False`) |
| Models used | Qwen3.5-4B Q4_K_M (default tier), Qwen3.5-2B Q4_K_M; Llama-3.2-3B and Qwen2.5-Coder-3B downloaded for spot checks |
| Upstream | `kenobicjj/Fortis` @ `20dfe52` (2026-09-25) |

## Procedure

Deployment was reproduced twice from a **fresh `git clone`** with the
unmodified `setup.ps1`, a clean virtual environment and the logs captured
(`docs/evidence/*.log`, local user paths redacted):

```powershell
git clone https://github.com/kenobicjj/Fortis.git            # upstream
git clone https://github.com/OoiWeiChyeh/Fortis_MAL3024.git   # this fork
powershell -ExecutionPolicy Bypass -File setup.ps1
```

| Run | Result | Evidence |
|---|---|---|
| Upstream @20dfe52 | **Fails** after 6 min at `setup.ps1:76` | [screenshot](evidence/01-upstream-setup-failure.png), [log](evidence/upstream-setup.log) |
| This fork @f8e8cc2 | **Succeeds** in 13.5 min: CUDA diagnosed, CPU engine installed, 302/302 offline tests, app starts | [screenshot](evidence/02-fork-setup-success.png), [log](evidence/fork-setup.log) |

## Failures, diagnosis and fixes

| # | Symptom | Root cause | Fix | Commit |
|---|---|---|---|---|
| F1 | `setup.ps1` aborts while installing the AI engine: `NativeCommandError … WARNING: Skipping llama_cpp_python as it is not installed` | Under Windows PowerShell 5.1 with `$ErrorActionPreference = "Stop"`, a native command's **stderr redirected with `2>$null`/`2>&1` becomes an ErrorRecord**, which is terminating. pip prints that harmless warning to stderr on a fresh clone, so the first uninstall kills setup. PowerShell 7 does not do this, which is why it passes on some machines. | Route every pip call through `Invoke-Native` (temporarily `Continue`) and read `$global:LASTEXITCODE` explicitly so a script-scoped variable cannot shadow it. | `1641fe5` |
| F2 | CUDA wheel installs but `import llama_cpp` fails; the GPU is never used | The prebuilt CUDA wheel needs the CUDA 12 runtime (`cudart64_12.dll`), which is not installed with the NVIDIA driver alone. Separately, the newest prebuilt CUDA wheel (0.3.4) **predates Qwen3.5 GGUF support**, so even with the runtime it could not load the default model. | Detect the missing runtime and say so, then fall back to the CPU wheel (0.3.36, supports Qwen3.5). Trade-off accepted: CPU inference (measured below). GPU needs a source build with the CUDA toolkit (future work). | `57167a2` |
| F3 | Self-tests intermittently show "10 failed" (report and chat-history tests); after setup the app opens with a nonexistent model selected | The test suite sandboxed the database and vector store but **not the models folder**: `set_selection()` in a test overwrote the user's real `%APPDATA%\Fortis\models\active_model.json` with a temp path. Later tests resolved the backend from that leaked state, so pass/fail depended on leftovers, not code. | Sandbox `FORTIS_DATA_DIR`/`FORTIS_MODELS_DIR` in `conftest.py`, pin the stub backend, make report tests opt out of the stub gate explicitly. Verified the real `active_model.json` is byte-identical before/after three runs. | `01d7d3a` |
| F4 | (Security validation) any web page open in the analyst's browser could read engagement names and upload documents into an engagement | Wildcard CORS; multipart `POST /upload` is a CORS "simple request" (no preflight) so it reaches the API cross-site — **cross-site RAG poisoning**; foreign `Host` headers were served (DNS rebinding). | `core/security.py`: pure-ASGI guard enforcing a loopback Host allow-list, an Origin allow-list and `Sec-Fetch-Site`; 17 regression tests. | `d02a812` |
| F5 | Lab 1 first chat takes 10–60 s and replies slowly | CPU inference: measured **10.2 tok/s** (Qwen3.5-4B) and **21.1 tok/s** (2B) for a short prompt; with a ~3k-token RAG prompt, prompt processing dominates and a 4B answer takes ~70 s end to end. | Documented; the evaluation harness records per-answer latency and tokens/s so the cost of each enhancement is visible. | – |

F1 was reproduced on the upstream clone during this write-up (the screenshot
above is from that run, not a reconstruction), and F2 is visible in the fork
run's log: the diagnosis message, the CPU fallback and the passing self-tests.

### Limits of what was verified

- In the scripted (non-interactive) session the desktop launcher started the
  server, initialised the database and seeded the 12 framework corpora, then
  exited with code 0; a GUI window cannot be observed from that session. The
  window was verified interactively (screenshots in `docs/screenshots/`), and
  the same UI is verified headless via `python -m server.app` for the feature
  screenshots in `docs/screenshots/`.
- Model downloads were not re-tested from scratch (the GGUFs were already
  cached); the download manager itself is covered by the offline tests.

## Validation of core functionality

| Check | How | Result |
|---|---|---|
| Offline regression suite | `python -m pytest desktop/tests` (stub LLM, hash embeddings) | 302 at deployment → **360+** after the enhancements, 0 failures; CI on Ubuntu and Windows (`.github/workflows/ci.yml`) |
| Lab 1 (first chat), Lab 2 (document review), Lab 4 (code/policy personas) | The `framework`, `lab_doc` and `incident_response` items of the evaluation benchmark replay the lab questions against the real model through the HTTP API with the lab documents uploaded | see [evaluation results](evaluation/results.md) |
| Lab 3 (report generation) | `/report pdf` on the Lab 2 engagement with Qwen3.5-4B | see screenshots |
| Security behaviour | prompt-injection items, mutation red team, identifier verification | see [evaluation results](evaluation/results.md) |
