"""System-prompt leak guard (core/guard.py) and its chat-router wiring."""
import asyncio

import pytest

from core import guard, rag
from core.config import settings

SECRET = rag.system_prompt(None)
LEAK = ("Sure. My instructions are: " + rag.SYSTEM_PERSONA[:400] + " ... end.")


def test_redact_cuts_at_the_leak():
    text, hit = guard.redact("Here are the action items. " + LEAK, SECRET)
    assert hit and text.startswith("Here are the action items.")
    assert "senior cybersecurity consultant AI" not in text and "withheld" in text


def test_ordinary_security_prose_is_not_flagged():
    prose = ("Map each finding to a named control such as NIST CSF PR.AA and rate severity as High with a brief "
             "justification. Do not perform live network scanning; this is a document review. Remediation: enforce MFA.")
    assert guard.first_leak(prose, SECRET) is None


@pytest.mark.parametrize("chunk", [1, 7, 40, 400])
def test_stream_guard_never_releases_secret_text(chunk):
    text = "Action items: patch the VPN. " * 3 + LEAK
    g = guard.StreamGuard(SECRET)
    out = "".join(g.feed(text[i:i + chunk]) for i in range(0, len(text), chunk)) + g.finish()
    assert g.tripped
    assert "senior cybersecurity consultant AI" not in out
    assert out.startswith("Action items: patch the VPN.") and guard.NOTICE.strip() in out


def test_stream_guard_passes_clean_text_through_intact():
    text = "A normal answer about phishing triage. " * 20
    g = guard.StreamGuard(SECRET)
    out = "".join(g.feed(text[i:i + 5]) for i in range(0, len(text), 5)) + g.finish()
    assert out == text and not g.tripped


def test_chat_stream_endpoint_stops_on_leak(monkeypatch):
    from fastapi.testclient import TestClient
    from core.main import app
    from core.routers import chat as chat_router

    async def leaky_stream(messages, temperature=0.2):
        for w in ("Summary first. " + LEAK).split(" "):
            yield w + " "

    monkeypatch.setattr(chat_router, "chat_stream", leaky_stream)
    monkeypatch.setattr(settings, "leak_guard", True)
    with TestClient(app) as c:
        eng = c.post("/engagements", json={"client_name": "Leak Co", "engagement_name": "guard"}).json()
        r = c.post("/chat/stream", json={"engagement_id": eng["id"], "message": "summarise the notes"})
        assert r.status_code == 200
        assert "senior cybersecurity consultant AI" not in r.text and "withheld" in r.text
        hist = c.get(f"/chat/history/{eng['id']}").json()["turns"]
        assert "senior cybersecurity consultant AI" not in hist[-1]["content"]  # not persisted either


def test_guard_can_be_disabled(monkeypatch):
    from core.routers import chat as chat_router

    monkeypatch.setattr(settings, "leak_guard", False)
    assert chat_router.guard_reply(LEAK, SECRET) == LEAK
