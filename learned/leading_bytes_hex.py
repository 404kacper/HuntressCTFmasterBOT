# learned-module: leading_bytes_hex
"""Questions asking for the first N bytes (magic / prefix / header) of an
artifact as hexadecimal. N comes from the question text (digits or number
words) or from the hex length named in the answer syntax; the bytes come
from the member the question's artifact field names. Case and separators
follow the answer format (default: lowercase, no prefix, no spaces)."""
import re

from hunt.learn.kit import answer, data, target
from hunt.solvers import handler

_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20, "twenty-four": 24, "thirty-two": 32,
    "sixty-four": 64,
}
_NUM = r"(\d+|" + "|".join(sorted((re.escape(w) for w in _WORDS), key=len, reverse=True)) + r")"
_FIRST_RE = re.compile(r"(?:first|leading|initial)\s+" + _NUM + r"\s+bytes?")
_ID_RE = re.compile(r"(?:hex|bytes?|prefix)[-_](\d+)\b")
_SYN_HEX = re.compile(r"(\d+)\s+(?:lowercase\s+|uppercase\s+)?hex(?:adecimal)?\s+(?:characters|chars|digits)")
_SYN_BYTES = re.compile(r"first\s+" + _NUM + r"\s+bytes?")


def _num(tok):
    tok = tok.lower()
    if tok.isdigit():
        return int(tok)
    return _WORDS.get(tok)


def _count(q):
    txt = (q.text or "").lower()
    syn = (q.syntax or "").lower()
    m = _FIRST_RE.search(txt) or _SYN_BYTES.search(syn)
    if m:
        return _num(m.group(1))
    m = _SYN_HEX.search(syn)
    if m and int(m.group(1)) % 2 == 0:
        return int(m.group(1)) // 2
    m = _ID_RE.search((q.id or "").lower())
    if m and ("first" in txt or "magic" in txt or "prefix" in txt):
        return int(m.group(1))
    return None


@handler()
def leading_bytes_hex(q, ctx):
    hay = q.haystack
    if "hex" not in hay and "hex" not in (q.syntax or "").lower():
        return None
    if not (re.search(r"\b(first|leading|initial)\b", hay) and "byte" in hay):
        return None
    n = _count(q)
    if not n or n <= 0 or n > 4096:
        return None
    m = target(q, ctx)
    if m is None:
        return None
    raw = data(m)
    if raw is None:
        return None
    if len(raw) < n:
        print(f"{m.path}: only {len(raw)} bytes, wanted {n}")
        return None
    chunk = raw[:n]
    syn = (q.syntax or "").lower() + " " + (q.text or "").lower()
    low = chunk.hex()
    up = low.upper()
    spaced = " ".join(f"{b:02x}" for b in chunk)
    if "uppercase" in syn and "lowercase" not in syn:
        best, alts = up, [low]
    else:
        best, alts = low, [up]
    if re.search(r"space[- ]separated|separated by spaces", syn) and "no spaces" not in syn:
        best, alts = spaced, [low]
    return answer(best, f"first {n} bytes of {m.path} ({len(raw)} bytes total) hex-encoded",
                  0.97, subject=m, alternatives=alts)
