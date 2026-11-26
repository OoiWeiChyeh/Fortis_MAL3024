"""
Seeds a demo engagement through the real API of a running Fortis server and
captures UI screenshots with headless Edge/Chrome.

    # terminal 1: a sandboxed server on the real model
    $env:FORTIS_DATA_DIR="$env:TEMP\\fortis-demo"; $env:FORTIS_LLM_BACKEND="llama"
    $env:FORTIS_MODEL_PATH="$env:APPDATA\\Fortis\\models\\Qwen3.5-4B-Q4_K_M.gguf"
    python -m server.app --port 8799
    # terminal 2
    python docs/screenshots/capture_demo.py --port 8799

Each step is a separate engagement so each screenshot shows one feature.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "screenshots"
DS = ROOT / "eval" / "datasets"


def call(base, path, body=None, files=None, timeout=900):
    if files:
        boundary = "----fortisdemo"
        parts = []
        for k, v in (body or {}).items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        for k, (name, data) in files.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{name}"\r\n'
                         f"Content-Type: application/octet-stream\r\n\r\n".encode() + data + b"\r\n")
        data = b"".join(parts) + f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    else:
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def browser():
    for c in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Google\Chrome\Application\chrome.exe"):
        if Path(c).exists():
            return c
    sys.exit("no Edge/Chrome")


def shot(base, name, h=1500):
    subprocess.run([browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars", "--virtual-time-budget=15000",
                    f"--window-size=1440,{h}", f"--screenshot={OUT / name}", base + "/"], capture_output=True, timeout=120)
    print("captured", name)


def new_eng(base, name):
    r = call(base, "/api/command", {"text": f"/new-engagement Bayu Capital Berhad :: {name}"})
    return call(base, "/engagements")[0]["id"], r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--only", default="triage,grounding,injection")
    a = ap.parse_args()
    base = f"http://127.0.0.1:{a.port}"
    steps = a.only.split(",")

    if "grounding" in steps:
        eid, _ = new_eng(base, "Grounded ATT&CK answers")
        t = time.time()
        call(base, "/chat", {"engagement_id": eid, "message": "What is MITRE ATT&CK technique T1003.001 and how can defenders detect it?"})
        print(f"grounding answer {time.time() - t:.0f}s")
        shot(base, "feature-verified-ids.png")

    if "injection" in steps:
        eid, _ = new_eng(base, "Prompt-injection document")
        call(base, "/upload", {"engagement_id": eid},
             files={"file": ("meeting-notes-exfil.txt", (DS / "docs" / "meeting-notes-exfil.txt").read_bytes())})
        call(base, "/chat", {"engagement_id": eid, "message": "Summarise the action items from these meeting notes."})
        shot(base, "feature-injection-defence.png")

    if "triage" in steps:
        eid, _ = new_eng(base, "Advisory triage")
        call(base, "/upload", {"engagement_id": eid},
             files={"file": ("bayu-capital-asset-inventory.csv", (DS / "docs" / "bayu-capital-asset-inventory.csv").read_bytes())})
        t = time.time()
        r = call(base, "/api/command", {"text": "/triage " + (DS / "advisories" / "ADV-05.md").read_text(encoding="utf-8")})
        print(f"triage {time.time() - t:.0f}s")
        (OUT / "demo-triage-ADV-05.md").write_text(r["text"], encoding="utf-8")
        shot(base, "feature-triage-agent.png", h=2600)


if __name__ == "__main__":
    main()
