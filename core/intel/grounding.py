"""
Catalogue grounding for ATT&CK technique and CVE identifiers.

Validation (eval/, Stage 2) showed the local models bind real-looking ids to
the wrong thing: Qwen3.5-2B answered "T1566 is the Network File Transfer
technique" (T1566 is Phishing). The built-in ATT&CK seed corpus has 39
paraphrased entries, so most ids a user mentions retrieve nothing to ground
on. Prompting harder cannot fix a fact the model does not have.

Two halves, both deterministic and offline:

- ``intel_context(texts)``: BEFORE generation, every ATT&CK id / CVE the user
  (or a retrieved excerpt) mentions is looked up in the vendored catalogues
  and the authoritative facts are put in the prompt. Ids that do not exist
  are stated as non-existent, so a false-premise question ("explain
  T1999.123") is not answered with an invented technique.
- ``verify_text(answer)``: AFTER generation, every id the model emitted is
  classified ``valid`` / ``stale`` (revoked or deprecated in the current
  ATT&CK release) / ``fabricated`` (not in ATT&CK at all, or an impossible
  CVE) / ``misbound`` (real id, but the model attached another technique's
  name or another vendor's product to it). The chat layer appends a short
  verification note, and the eval harness counts the same classes as the
  identifier-hallucination metric.

The verifier only judges names it can see bound to an id (parentheses,
quotes, table cells, "T1234 - Name"); free prose is not scored, so it
under-reports rather than flags correct answers. Its precision is measured
against hand-labelled answers in eval/ (see docs/evaluation.md).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from datetime import date
from functools import lru_cache
from typing import Dict, Iterable, List, Optional

from .enrich import attack_catalogue, kev_catalogue, catalogue_versions, technique_status
from .ioc import normalise_dashes

_TECH_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)

# Words that carry no identity when comparing a technique name.
_STOP = frozenset(
    "a an the of and or to for in on via with from by as at is are this that these those "
    "technique techniques sub subtechnique sub-technique tactic tactics mitre att&ck attack "
    "id ids enterprise matrix use used uses using t".split()
)
# Title-case words that start a sentence rather than name a technique.
_SENTENCE_STARTERS = frozenset(
    "adversaries adversary attackers attacker threat actors this the it used use "
    "description example mitigation detection note see also".split()
)

_MAX_FACTS = 8


# --------------------------------------------------------------------------
# catalogue helpers
# --------------------------------------------------------------------------

def _stem(w: str) -> str:
    # plural only: "Enumerate Accounts" vs "Account Discovery" was a false
    # misbinding found in manual review of the first baseline run
    return w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w


def _tokens(text: str) -> set:
    words = re.findall(r"[a-z0-9]+", text.lower().replace("&", " and "))
    return {_stem(w) for w in words if w not in _STOP and len(w) > 1}


@lru_cache(maxsize=1)
def _tactic_names() -> frozenset:
    names = set()
    for short, t in attack_catalogue().get("tactics", {}).items():
        names.add(short.replace("-", " "))
        names.add(t["name"].lower())
    # pre-v16 tactic names models still use (Defense Evasion became Stealth)
    names.update({"defense evasion", "defence evasion"})
    return frozenset(names)


@lru_cache(maxsize=1)
def _kev_vendors() -> Dict[str, str]:
    """normalised vendor name -> canonical vendor, for misbinding checks."""
    out = {}
    for v in kev_catalogue()["vulnerabilities"].values():
        name = v["vendor"].strip()
        key = name.lower()
        if len(key) >= 3:
            out[key] = name
    return out


@lru_cache(maxsize=1)
def _name_index() -> Dict[str, str]:
    """lower-case technique name -> id, for name-mention grounding. Single
    word names only for top-level techniques ('Phishing'), since one-word
    sub-technique names ('Python', 'Cron') collide with ordinary prose."""
    out = {}
    for tid, t in attack_catalogue()["techniques"].items():
        if t["revoked"] or t["deprecated"]:
            continue
        name = t["name"].lower()
        if " " not in name and (t["is_subtechnique"] or len(name) < 7):
            continue
        out.setdefault(name, tid)
    return out


def technique_names(tid: str) -> List[str]:
    """Names a correct answer may bind to `tid`: its own, its parent's (for a
    sub-technique), and its tactics."""
    cat = attack_catalogue()["techniques"]
    t = cat.get(tid)
    if not t:
        return []
    names = [t["name"]]
    if "." in tid and tid.split(".")[0] in cat:
        names.append(cat[tid.split(".")[0]]["name"])
    names.extend(x.replace("-", " ") for x in t["tactics"])
    return names


# pre-v16 tactic names models still use -> the v20.1 tactics that replaced them
_TACTIC_ALIASES = {"defense evasion": {"stealth", "defense impairment"},
                   "defence evasion": {"stealth", "defense impairment"}}


def _name_matches(candidate: str, tid: str) -> bool:
    cand = _tokens(candidate)
    if not cand:
        return True  # nothing identifying to compare
    label = " ".join(candidate.strip().lower().replace("-", " ").split())
    if label in _tactic_names():
        # A tactic is a valid label only if it is one of THIS technique's
        # tactics. "T1550.001 (Credential Access)" from a real answer passed
        # before (any tactic was accepted), and would still pass the word
        # overlap below via "Access" in "Application Access Token".
        own = {t.replace("-", " ") for t in attack_catalogue()["techniques"][tid]["tactics"]}
        own |= {attack_catalogue()["tactics"].get(t.replace(" ", "-"), {}).get("name", "").lower() for t in own}
        return label in own or bool(_TACTIC_ALIASES.get(label, set()) & own)
    for name in technique_names(tid):
        ref = _tokens(name)
        if not ref:
            continue
        overlap = len(cand & ref) / min(len(cand), len(ref))
        if overlap >= 0.5:
            return True
    return False


# --------------------------------------------------------------------------
# name-binding extraction
# --------------------------------------------------------------------------

_TITLE_PHRASE = r"((?:[A-Z][\w'&\-]*)(?:[ /]+(?:[A-Z][\w'&\-]*|of|and|or|for|the|to|from|via|in|with))*)"
_AFTER_PATTERNS = [
    re.compile(r"^\s*\**\s*\(\s*([^()\n]{3,70})\)"),                     # T1566 (Phishing)
    # T1566 - Phishing. The name must end there: "T1059.001**: Explicitly
    # identifies ..." is a sentence, not a name (false misbinding in review).
    re.compile(r"^\s*\**\s*[:\-–—]\s*\**\s*[\"“]?" + _TITLE_PHRASE + r"\b(?![ \t]+[a-z])"),
    re.compile(r"^\s*\**\s*\|\s*\**([^|\n]{3,70}?)\**\s*\|"),             # | T1566 | Phishing |
    re.compile(r"^[^.\n\"“]{0,40}?[\"“]([^\"”\n]{3,70})[\"”]"),           # T1566 is the "X" technique
]
_BEFORE_PATTERNS = [
    re.compile(_TITLE_PHRASE + r"\**\s*\(\s*(?:MITRE\s+)?(?:ATT&CK\s+)?(?:ID[:\s]*)?$"),  # Phishing (T1566
    re.compile(r"\|\s*\**([^|\n]{3,70}?)\**\s*\|\s*\**\s*$"),                             # | Phishing | T1566
]


def _clean_candidate(c: str) -> Optional[str]:
    c = c.strip().strip("*_`\"“”' ").strip()
    c = re.split(r"\s+(?:technique|sub-technique|subtechnique|tactic)\b", c, flags=re.I)[0].strip()
    if not c or _TECH_RE.search(c) or _CVE_RE.search(c):
        return None
    # technique names are title case; "(the parent technique)", "(e.g. via
    # macros)" are asides (false misbinding found in manual review)
    if c[0].islower():
        return None
    words = c.split()
    if len(words) == 1 and (c.lower() in _SENTENCE_STARTERS or len(c) < 4):
        return None
    if len(words) > 9:  # a sentence, not a name
        return None
    return c


def _bound_name(text: str, start: int, end: int) -> Optional[str]:
    after = text[end:end + 90]
    for pat in _AFTER_PATTERNS:
        m = pat.match(after)
        if m:
            c = _clean_candidate(m.group(1))
            if c:
                return c
    before = text[max(0, start - 90):start]
    for pat in _BEFORE_PATTERNS:
        m = pat.search(before)
        if m:
            c = _clean_candidate(m.group(1))
            if c:
                return c
    return None


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------

@dataclass
class IdCheck:
    id: str
    kind: str            # "attack" | "cve"
    status: str          # valid | stale | fabricated | misbound | unverified
    detail: str = ""
    bound_name: Optional[str] = None
    catalogue_name: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Verification:
    checks: List[IdCheck] = field(default_factory=list)

    def by_status(self, status: str) -> List[IdCheck]:
        return [c for c in self.checks if c.status == status]

    @property
    def problems(self) -> List[IdCheck]:
        return [c for c in self.checks if c.status in ("fabricated", "misbound", "stale")]

    def counts(self) -> Dict[str, int]:
        out = {"total": len(self.checks)}
        for s in ("valid", "stale", "fabricated", "misbound", "unverified"):
            out[s] = len(self.by_status(s))
        return out

    def to_dict(self) -> Dict:
        return {"counts": self.counts(), "checks": [c.to_dict() for c in self.checks]}


def _check_technique(tid: str, text: str, start: int, end: int) -> IdCheck:
    status = technique_status(tid)
    t = attack_catalogue()["techniques"].get(tid)
    if status == "unknown":
        return IdCheck(tid, "attack", "fabricated", "not an ATT&CK technique id")
    bound = _bound_name(text, start, end)
    if status in ("revoked", "deprecated"):
        return IdCheck(tid, "attack", "stale", f"{status} in ATT&CK v{catalogue_versions()['attack']}",
                       bound, t["name"])
    if bound and not _name_matches(bound, tid):
        return IdCheck(tid, "attack", "misbound", f"named '{bound}', catalogue says '{t['name']}'",
                       bound, t["name"])
    return IdCheck(tid, "attack", "valid", "", bound, t["name"])


_SENT_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z*|#-])|\n")
_NEGATION = re.compile(r"\b(not|never|no longer|isn't|doesn't|unrelated|rather than|instead of|confused with|mistaken)\b", re.I)


def _sentence_start(text: str, start: int) -> int:
    s = 0
    for m in _SENT_BREAK.finditer(text, 0, start):
        s = m.end()
    return s


def _sentence_around(text: str, start: int, end: int) -> str:
    """The sentence (or table row / line) holding the id: vendor names in
    the next sentence usually belong to the next id."""
    m = _SENT_BREAK.search(text, end)
    return text[_sentence_start(text, start):m.start() if m else len(text)]


def _check_cve(cve: str, year: int, text: str, start: int, end: int, today: date) -> IdCheck:
    if not (1999 <= year <= today.year + 1):
        return IdCheck(cve, "cve", "fabricated", f"impossible CVE year {year}")
    kev = kev_catalogue()["vulnerabilities"].get(cve)
    if not kev:
        return IdCheck(cve, "cve", "unverified", "not in the CISA KEV snapshot (cannot confirm offline)")
    sentence = _sentence_around(text, start, end)
    window = sentence.lower()
    pos = start - _sentence_start(text, start)
    vendor = kev["vendor"].lower()
    product_tokens = {w for w in re.findall(r"[a-z0-9]{4,}", kev["product"].lower())}
    named = {}
    for v, canonical in _kev_vendors().items():
        # A WRONG vendor must appear as the proper noun KEV spells (case-
        # sensitive): KEV lists vendors called "Daemon", "Zoom", "Linux", and
        # "the SSL-VPN daemon" in a real triage note was read as a
        # misattribution (docs/evidence/18).
        m = re.search(r"\b" + re.escape(canonical) + r"\b", sentence)
        if m:
            named[v] = abs(m.start() - pos)
    right = vendor in window or any(re.search(r"\b" + re.escape(p) + r"\b", window) for p in product_tokens)
    # nicknames built on the product name: "Log4Shell" for Log4j2
    right = right or any(re.search(r"\b" + re.escape(p[:4]), window) for p in product_tokens if len(p) >= 5)
    # A negated mention is not an attribution: "Log4Shell (CVE-2021-44228)
    # does not affect ... Microsoft Exchange" is a correct answer that was
    # flagged in the audit of the baseline run (docs/evaluation.md).
    if _NEGATION.search(window):
        return IdCheck(cve, "cve", "valid", "in CISA KEV (negated mention not judged)", None,
                       f"{kev['vendor']} {kev['product']}")
    # Only call it misbound when the sentence names some *other* KEV vendor
    # next to the id and never the right vendor or product.
    if named and not right and not any(vendor in n or n in vendor for n in named):
        wrong = min(named, key=named.get)
        return IdCheck(cve, "cve", "misbound",
                       f"attributed to {_kev_vendors()[wrong]}, KEV says {kev['vendor']} {kev['product']}",
                       _kev_vendors()[wrong], f"{kev['vendor']} {kev['product']}")
    return IdCheck(cve, "cve", "valid", "in CISA KEV", None, f"{kev['vendor']} {kev['product']}")


def verify_text(text: str, today: Optional[date] = None) -> Verification:
    """Classifies every ATT&CK technique id and CVE id in `text`. Each id is
    judged once, by its worst occurrence (a misbound mention anywhere in the
    answer is a misbinding even if another mention is right)."""
    today = today or date.today()
    text = normalise_dashes(text or "")
    rank = {"fabricated": 4, "misbound": 3, "stale": 2, "unverified": 1, "valid": 0}
    seen: Dict[str, IdCheck] = {}
    for m in _TECH_RE.finditer(text):
        tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        c = _check_technique(tid, text, m.start(), m.end())
        if tid not in seen or rank[c.status] > rank[seen[tid].status]:
            seen[tid] = c
    for m in _CVE_RE.finditer(text):
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        c = _check_cve(cve, int(m.group(1)), text, m.start(), m.end(), today)
        if cve not in seen or rank[c.status] > rank[seen[cve].status]:
            seen[cve] = c
    return Verification(list(seen.values()))


def verification_note(v: Verification) -> str:
    """Markdown footnote for the chat reply. Empty when there is nothing to
    say (no ids, or all ids check out and are not worth a line)."""
    if not v.checks:
        return ""
    versions = catalogue_versions()
    src = f"ATT&CK v{versions['attack']}, CISA KEV {versions['kev']}"
    problems = v.problems
    if not problems:
        n = len(v.checks)
        return f"\n\n---\n✅ *Fortis verified {n} identifier{'s' if n != 1 else ''} against the offline catalogue ({src}).*"
    lines = ["", "", "---", f"⚠️ **Identifier check** ({src}) — treat the following with care:"]
    for c in problems:
        if c.status == "fabricated":
            lines.append(f"- `{c.id}` — **does not exist** ({c.detail}).")
        elif c.status == "misbound":
            lines.append(f"- `{c.id}` — **wrong name**: {c.detail}.")
        else:
            lines.append(f"- `{c.id}` ({c.catalogue_name}) — **{c.detail}**; check the current replacement.")
    ok = len(v.checks) - len(problems)
    if ok:
        lines.append(f"- {ok} other identifier{'s' if ok != 1 else ''} verified.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# pre-generation grounding
# --------------------------------------------------------------------------

_ATTACK_HINT = re.compile(r"att&ck|attack|mitre|technique|ttp|tactic|adversar|threat actor", re.I)


def _mentioned_ids(texts: Iterable[str]) -> Dict[str, List[str]]:
    techs, cves = [], []
    for t in texts:
        t = normalise_dashes(t or "")
        for m in _TECH_RE.finditer(t):
            tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
            if tid not in techs:
                techs.append(tid)
        for m in _CVE_RE.finditer(t):
            cve = f"CVE-{m.group(1)}-{m.group(2)}".upper()
            if cve not in cves:
                cves.append(cve)
    return {"attack": techs, "cve": cves}


def _named_techniques(query: str) -> List[str]:
    if not _ATTACK_HINT.search(query or ""):
        return []
    low = query.lower()
    found = []
    for name, tid in _name_index().items():
        if re.search(r"\b" + re.escape(name) + r"\b", low):
            found.append((len(name), tid))
    # longest names first: "spearphishing attachment" beats "phishing"
    return [tid for _, tid in sorted(found, reverse=True)]


def _tech_fact(tid: str) -> str:
    cat = attack_catalogue()["techniques"]
    status = technique_status(tid)
    if status == "unknown":
        return f"- {tid} — NOT a MITRE ATT&CK technique id (absent from the catalogue). Say it does not exist; do not describe it."
    t = cat[tid]
    parent = ""
    if "." in tid and tid.split(".")[0] in cat:
        parent = f" (sub-technique of {tid.split('.')[0]} {cat[tid.split('.')[0]]['name']})"
    flag = ""
    if status != "valid":
        flag = f" [{status.upper()} in the current ATT&CK release — say so and do not recommend mapping to it]"
    desc = t["description"][:220].rstrip()
    return f"- {tid} = {t['name']}{parent}; tactics: {', '.join(t['tactics']) or 'n/a'}{flag}. {desc}"


def _cve_fact(cve: str, today: date) -> str:
    year = int(cve.split("-")[1])
    if not (1999 <= year <= today.year + 1):
        return f"- {cve} — impossible CVE id (year {year}). Say it does not exist."
    k = kev_catalogue()["vulnerabilities"].get(cve)
    if not k:
        return (f"- {cve} — not in the CISA KEV snapshot (no known in-the-wild exploitation recorded offline). "
                "Do not invent its vendor, product or CVSS; say you cannot confirm details offline unless you are certain.")
    ransom = "known ransomware use" if k["ransomware"].lower() == "known" else "ransomware use not known"
    return (f"- {cve} = {k['vendor']} {k['product']}: {k['name']}. In CISA KEV (actively exploited) since "
            f"{k['date_added']}; federal remediation due {k['due_date']}; {ransom}. {k['description'][:200]}")


def intel_context(texts: Iterable[str], query: str = "", today: Optional[date] = None) -> str:
    """Authoritative facts for the ids in `texts` (query + retrieved excerpts)
    and, for ATT&CK-flavoured questions, techniques named in `query`.
    Returns '' when there is nothing to ground."""
    today = today or date.today()
    ids = _mentioned_ids(list(texts) + [query])
    techs = ids["attack"] + [t for t in _named_techniques(query) if t not in ids["attack"]]
    facts = [_tech_fact(t) for t in techs] + [_cve_fact(c, today) for c in ids["cve"]]
    if not facts:
        return ""
    v = catalogue_versions()
    head = (f"=== Verified threat-intel facts (offline catalogue: MITRE ATT&CK v{v['attack']}, "
            f"CISA KEV {v['kev']}) ===\n"
            "These are authoritative. Use these exact ids and names; never attach a different name to an id.")
    return head + "\n" + "\n".join(facts[:_MAX_FACTS])
