"""
Output-side guard against system-prompt exfiltration.

Spotlighting (core/rag.py) asks the model not to obey instructions inside
uploaded documents; this guard does not trust that request. If a reply
starts reproducing Fortis's own system prompt, the reproduced text never
reaches the user.

Detection is n-gram overlap: any run of NGRAM consecutive words of the
system prompt appearing in the reply. Eight words is long enough that
ordinary security prose does not collide with the persona by accident
(checked against every answer in the eval runs) and short enough to catch
a partial or lightly reformatted dump.

Streaming cannot recall tokens already shown, so `StreamGuard` holds back a
short tail (HOLD characters) and only releases text that has passed the
check; on a hit it stops the stream and emits a notice instead.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import List, Optional, Tuple

NGRAM = 8
HOLD = 160
NOTICE = ("\n\n> 🛡️ *Fortis withheld the rest of this reply: it began reproducing Fortis's own "
          "system instructions, which usually means an uploaded document contains a prompt-injection "
          "attempt asking for them. Review the document.*")


def _words(text: str) -> List[Tuple[str, int, int]]:
    return [(m.group(0).lower(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z0-9']+", text or "")]


@lru_cache(maxsize=8)
def _shingles(secret: str) -> frozenset:
    w = [x[0] for x in _words(secret)]
    return frozenset(tuple(w[i:i + NGRAM]) for i in range(len(w) - NGRAM + 1))


def first_leak(text: str, secret: str) -> Optional[int]:
    """Character offset where reproduced secret text starts, or None."""
    sh = _shingles(secret)
    w = _words(text)
    for i in range(len(w) - NGRAM + 1):
        if tuple(x[0] for x in w[i:i + NGRAM]) in sh:
            return w[i][1]
    return None


def redact(text: str, secret: str) -> Tuple[str, bool]:
    pos = first_leak(text, secret)
    if pos is None:
        return text, False
    return text[:pos].rstrip() + NOTICE, True


class StreamGuard:
    def __init__(self, secret: str):
        self.secret = secret
        self.buf = ""
        self.sent = 0
        self.tripped = False

    def feed(self, token: str) -> str:
        """Returns the text that is now safe to send (possibly empty)."""
        if self.tripped:
            return ""
        self.buf += token
        # re-check a window reaching back past the last released text, so a
        # leak that straddles the release boundary is still found
        start = max(0, self.sent - HOLD)
        pos = first_leak(self.buf[start:], self.secret)
        if pos is not None:
            self.tripped = True
            cut = max(self.sent, start + pos)
            out = self.buf[self.sent:cut].rstrip() + NOTICE
            self.sent = len(self.buf)
            return out
        safe = max(self.sent, len(self.buf) - HOLD)
        out = self.buf[self.sent:safe]
        self.sent = safe
        return out

    def finish(self) -> str:
        if self.tripped:
            return ""
        out = self.feed("")
        if self.tripped:
            return out
        rest = self.buf[self.sent:]
        self.sent = len(self.buf)
        return out + rest
