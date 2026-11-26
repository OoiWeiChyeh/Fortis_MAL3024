"""
Local-API request guard.

Fortis serves its API and UI from one origin on 127.0.0.1, so the browser's
same-origin policy should be the only thing standing between a hostile web
page and the analyst's engagement data. Two gaps defeated that:

1. A wildcard CORS policy let any page *read* API responses
   (e.g. GET /engagements, which leaks the guessable engagement slugs).
2. Even without CORS, a multipart POST is a CORS "simple request": the
   browser sends it without a preflight, so a hostile page could *write*
   a document into an engagement (cross-site RAG poisoning), and a
   DNS-rebinding page could talk to the server under its own hostname.

This ASGI middleware closes both, without breaking same-origin use or
non-browser clients (curl, tests, the eval harness):

- Host allow-list: the Host header must name an allowed local host
  (DNS-rebinding defence).
- Origin allow-list: if the request carries an Origin header (browsers
  always send one on cross-origin and on non-GET same-origin requests),
  it must be http(s)://<allowed host>[:port]. "null" origins are refused.
- Fetch metadata: Sec-Fetch-Site: cross-site is refused outright.

Allowed hosts come from FORTIS_ALLOWED_HOSTS (comma-separated); the
default covers loopback only.
"""
import json
import os
from typing import Iterable, Optional
from urllib.parse import urlsplit

DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")


def allowed_hosts_from_env() -> frozenset:
    raw = os.getenv("FORTIS_ALLOWED_HOSTS", "")
    hosts = [h.strip().lower() for h in raw.split(",") if h.strip()]
    return frozenset(hosts or DEFAULT_ALLOWED_HOSTS)


def _strip_port(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):  # [::1]:8757
        end = host.find("]")
        return host[1:end] if end != -1 else host
    if host.count(":") == 1:  # name:port (a bare IPv6 literal has several colons)
        return host.split(":", 1)[0]
    return host


def origin_host(origin: str) -> Optional[str]:
    """Hostname of an Origin header value, or None if it is not http(s)."""
    try:
        parts = urlsplit(origin.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts.hostname.lower()


def check_request(headers: dict, allowed: Iterable[str]) -> Optional[str]:
    """Returns a refusal reason, or None if the request may proceed.

    `headers` maps lower-case header names to values.
    """
    allowed = frozenset(allowed)
    host = headers.get("host")
    if host is not None and _strip_port(host) not in allowed:
        return "Host header not allowed"
    if headers.get("sec-fetch-site", "").lower() == "cross-site":
        return "Cross-site request refused"
    origin = headers.get("origin")
    if origin is not None:
        o_host = origin_host(origin)
        if o_host is None or o_host not in allowed:
            return "Cross-origin request refused"
    return None


class LocalOriginGuard:
    """Pure ASGI middleware (streaming responses pass through untouched)."""

    def __init__(self, app, allowed_hosts: Optional[Iterable[str]] = None):
        self.app = app
        self.allowed = frozenset(allowed_hosts) if allowed_hosts else allowed_hosts_from_env()

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        reason = check_request(headers, self.allowed)
        if reason is None:
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": reason}).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})
