"""
Deterministic indicator-of-compromise (IOC) extraction.

Why deterministic instead of asking the LLM: an IOC list feeds block-lists
and hunts, so a single invented hash or IP is worse than a missed one.
Regexes plus validation never invent an indicator; the eval harness
(eval/) measures how often the local LLM does.

Handles what real advisories (MyCERT, CISA, vendor blogs) actually contain:
- defanged indicators: hxxp://, evil[.]com, 1.2.3[.]4, user[at]x[.]com
- unicode dashes in CVE ids (CVE‑2024‑3400 written with U+2011)
- the file-extension/TLD collision: .zip .mov .py .sh .md ... are real
  TLDs, so "invoice.zip" is only treated as a domain when the source
  signals it is one (defanged, inside a URL, or in an email address)
- version strings that look like IPv4 ("v1.2.3.4", "version 10.0.0.1")
- hex runs: a hash must not be a slice of a longer hex string

Every IOC is returned once, normalised (lower-case domains/hashes,
upper-case CVE/technique ids), with the type, whether it appeared
defanged, and a short context snippet.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

IOC_TYPES = ("url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256", "cve", "attack_technique")

# TLDs that are also everyday file extensions. Seen bare ("setup.sh"),
# they are far more likely a filename than a host.
AMBIGUOUS_TLDS = frozenset({
    "ai", "app", "bz", "md", "ml", "mov", "pl", "pm", "ps", "pub", "py", "rs", "sh", "so", "zip",
})
# Country codes that collide with code attribute names (user.id, obj.to).
# Accepted bare only with 3+ labels (malware.co.id, portal.gov.in).
CODE_LIKE_CCTLDS = frozenset({"id", "in", "is", "it", "me", "to", "do", "go"})
# gTLDs accepted *bare*: legacy ones plus those that dominate abuse
# rankings (Spamhaus/Interisle). Any other new gTLD (.name, .host, .email,
# .bar ...) collides with code like `self.name`, so it needs a strong
# signal (defanged, in a URL, or in an email address).
BARE_OK_GTLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io",
    "xyz", "top", "online", "site", "shop", "club", "live", "icu", "cyou", "buzz",
    "sbs", "cfd", "click", "link", "store", "tech", "website", "space", "fun", "vip",
    "work", "life", "today", "rest", "bond", "lol", "monster", "quest", "support", "cloud",
})

_DASHES = "‐‑‒–—―−"

# order matters: longer / more specific tokens first
_REFANG = [
    (re.compile(r"\bhxxp(s?)(?=\[?:|://)", re.I), r"http\1"),
    (re.compile(r"\bh\[tt\]p(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp(?=\[?:|://)", re.I), "ftp"),
    (re.compile(r"\[:\]//|\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\}", re.I), "@"),
]

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.I)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.I)
_DOMAIN_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}(?![\w-])", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
# loose candidate shape; ipaddress.IPv6Address does the real validation
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
_HASH_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])", re.I)
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
_TECH_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")
# "v1.2.3.4", "version 10.0.0.1", and the phrased forms advisories use:
# "version string is 4.2.0.1", "build number: 6.1.0.3", "firmware 7.2.6.1"
# (the phrased form was found by eval/ioc_bench.py on advisory ADV-03)
_VERSION_PREFIX_RE = re.compile(
    r"(?:\bv|\bver\.?|\bversion|\brelease|\bbuild|\bfirmware)"
    r"(?:\s+(?:string|number|no\.?|id))?(?:\s*(?:is|was|=|:))?\s*$", re.I)
_TRAILING_PUNCT = ".,;:!?)]}>'\""
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


@dataclass
class IOC:
    type: str
    value: str
    defanged: bool = False
    context: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@lru_cache(maxsize=1)
def valid_tlds() -> frozenset:
    path = Path(__file__).parent / "data" / "iana_tlds.txt"
    lines = path.read_text(encoding="ascii").splitlines()
    return frozenset(l.strip().lower() for l in lines if l.strip() and not l.startswith("#"))


def normalise_dashes(text: str) -> str:
    return text.translate({ord(d): "-" for d in _DASHES})


def refang(text: str) -> str:
    text = normalise_dashes(text)
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, ioc_type: str) -> str:
    """Safe-to-display form for reports and chat (never a live link)."""
    if ioc_type == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.I)
        scheme, sep, rest = value.partition("://")
        host, slash, path = rest.partition("/")
        return f"{scheme}{sep}{host.replace('.', '[.]')}{slash}{path}"
    if ioc_type in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if ioc_type == "email":
        local, _, host = value.partition("@")
        return f"{local}[@]{host.replace('.', '[.]')}"
    return value


def _context(text: str, start: int, end: int, width: int = 50) -> str:
    snippet = text[max(0, start - width): min(len(text), end + width)]
    return " ".join(snippet.split())


def _strip_url(url: str) -> str:
    while url and url[-1] in _TRAILING_PUNCT:
        # keep a closing bracket that has its opener inside the URL
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def _is_mask(ip: ipaddress.IPv4Address) -> bool:
    """Netmask (255.255.255.0) or Cisco wildcard/host mask (0.0.0.255):
    configuration values, not indicators."""
    n = int(ip)
    if n in (0, 0xFFFFFFFF):
        return True
    first = n >> 24
    inverted = ~n & 0xFFFFFFFF
    if first == 255 and inverted & (inverted + 1) == 0:  # 1...10...0
        return True
    if first == 0 and n & (n + 1) == 0:  # 0...01...1
        return True
    return False


def _valid_domain(host: str, strong_signal: bool) -> bool:
    host = host.lower().rstrip(".")
    if "." not in host or len(host) > 253:
        return False
    labels = host.split(".")
    tld = labels[-1]
    if tld not in valid_tlds():
        return False
    if strong_signal:
        return True
    if tld in AMBIGUOUS_TLDS:
        return False
    if len(tld) == 2:
        return tld not in CODE_LIKE_CCTLDS or len(labels) >= 3
    return tld in BARE_OK_GTLDS


class _Collector:
    def __init__(self, original: str):
        self.original_lower = normalise_dashes(original).lower()
        self.items: Dict[tuple, IOC] = {}

    def add(self, ioc_type: str, value: str, text: str, start: int, end: int, notes=None) -> None:
        key = (ioc_type, value)
        if key in self.items:
            return
        defanged = ioc_type in ("url", "domain", "ipv4", "email") and value.lower() not in self.original_lower
        self.items[key] = IOC(ioc_type, value, defanged, _context(text, start, end), list(notes or []))


def extract_iocs(text: str, today: Optional[date] = None) -> List[IOC]:
    """All IOCs in `text`, de-duplicated, in a stable type/value order."""
    if not text:
        return []
    max_year = (today or date.today()).year + 1
    work = refang(text)
    out = _Collector(text)
    consumed = []  # spans already claimed by URLs / emails

    for m in _URL_RE.finditer(work):
        url = _strip_url(m.group(0))
        host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/", 1)[0].split("?", 1)[0]
        host = host.rsplit("@", 1)[-1]
        hostname = host.split(":", 1)[0] if host.count(":") <= 1 else host
        out.add("url", url, work, m.start(), m.start() + len(url))
        consumed.append((m.start(), m.start() + len(url)))
        try:
            ipaddress.IPv4Address(hostname)
            out.add("ipv4", hostname, work, m.start(), m.end(), ["from url"])
        except ValueError:
            if _valid_domain(hostname, strong_signal=True):
                out.add("domain", hostname.lower(), work, m.start(), m.end(), ["from url"])

    for m in _EMAIL_RE.finditer(work):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        email = m.group(0).lower()
        domain = email.rsplit("@", 1)[1]
        if not _valid_domain(domain, strong_signal=True):
            continue
        out.add("email", email, work, m.start(), m.end())
        out.add("domain", domain, work, m.start(), m.end(), ["from email"])
        consumed.append((m.start(), m.end()))

    for m in _DOMAIN_RE.finditer(work):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        host = m.group(0).lower()
        try:  # dotted quads match the domain pattern's shape too
            ipaddress.IPv4Address(host)
            continue
        except ValueError:
            pass
        raw_defanged = host not in out.original_lower
        if _valid_domain(host, strong_signal=raw_defanged):
            out.add("domain", host, work, m.start(), m.end())

    for m in _IPV4_RE.finditer(work):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        if _VERSION_PREFIX_RE.search(work[max(0, m.start() - 28): m.start()]):
            continue
        try:
            ip = ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        if _is_mask(ip):
            continue
        if any(ip in n for n in _DOC_NETS):
            # Python counts RFC 5737 as "private", but advisories use these
            # ranges for real-world indicators in examples; calling them
            # internal misled the triage brief (docs/evidence/18)
            notes = ["documentation range (RFC 5737)"]
        elif ip.is_private or ip.is_reserved or ip.is_loopback:
            notes = ["private/reserved"]
        else:
            notes = []
        out.add("ipv4", str(ip), work, m.start(), m.end(), notes)

    for m in _IPV6_RE.finditer(work):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        try:
            ip = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        if ip.is_unspecified:
            continue
        out.add("ipv6", ip.compressed, work, m.start(), m.end())

    for m in _HASH_RE.finditer(work):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        kind = _HASH_LENGTHS.get(len(m.group(0)))
        if kind:
            out.add(kind, m.group(0).lower(), work, m.start(), m.end())

    for m in _CVE_RE.finditer(work):
        year = int(m.group(1))
        if 1999 <= year <= max_year:
            out.add("cve", f"CVE-{m.group(1)}-{m.group(2)}", work, m.start(), m.end())

    for m in _TECH_RE.finditer(work):
        tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        out.add("attack_technique", tid, work, m.start(), m.end())

    order = {t: i for i, t in enumerate(IOC_TYPES)}
    return sorted(out.items.values(), key=lambda i: (order[i.type], i.value))


def iocs_by_type(iocs: List[IOC]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {t: [] for t in IOC_TYPES}
    for i in iocs:
        grouped[i.type].append(i.value)
    return {t: v for t, v in grouped.items() if v}
