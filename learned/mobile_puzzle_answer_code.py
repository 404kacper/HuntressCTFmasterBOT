# learned-module: mobile_puzzle_answer_code
"""Return the backend answer/evidence code for Huntress mobile APK challenges.

The APK ships an assets/*puzzle*.json fixture carrying the answer under a
"data" field, optionally encoded (codec: plain | base64 | hex). The answer
matches the declared pattern (e.g. ANS- + 16 uppercase hex). We read the
fixture, decode per its codec, and return the matching token. Falls back to
scanning every member's bytes for a token matching the answer pattern."""
import base64
import binascii
import json
import re

from hunt.learn.kit import answer, files, data, text
from hunt.solvers import handler


def _pattern_from_format(q):
    """Build a regex from the answer_format syntax when it names a prefix+hex."""
    syn = (q.syntax or "")
    m = re.search(r"([A-Za-z]+-)\s*followed by\s*(?:exactly\s*)?(\d+)\s*uppercase hex", syn, re.I)
    if m:
        prefix = re.escape(m.group(1))
        n = int(m.group(2))
        return re.compile(prefix + "[0-9A-F]{" + str(n) + "}")
    m = re.search(r"([A-Za-z]+-)\s*followed by\s*(?:exactly\s*)?(\d+)\s*hex", syn, re.I)
    if m:
        prefix = re.escape(m.group(1))
        n = int(m.group(2))
        return re.compile(prefix + "[0-9A-Fa-f]{" + str(n) + "}")
    # generic: PREFIX- followed by run of hex/alnum
    return re.compile(r"[A-Z]{2,5}-[0-9A-F]{8,}")


def _decode(value, codec):
    codec = (codec or "plain").lower()
    if codec in ("plain", "none", "", "utf-8", "utf8", "text"):
        return value
    if codec in ("base64", "b64"):
        try:
            return base64.b64decode(value + "===").decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return value
    if codec in ("hex", "base16"):
        try:
            return bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
    if codec in ("rot13",):
        import codecs as _c
        return _c.encode(value, "rot13")
    return value


@handler(lanes=("mobile-android",))
def puzzle_answer(q, ctx):
    pat = _pattern_from_format(q)

    # 1) Prefer a puzzle/fixture JSON that explicitly carries the answer.
    for m in files(ctx):
        name = (m.basename or "").lower()
        if not name.endswith(".json"):
            continue
        body = text(m)
        if not body:
            continue
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        codec = obj.get("codec")
        for key in ("data", "answer", "flag", "code", "payload"):
            val = obj.get(key)
            if isinstance(val, str) and val:
                dec = _decode(val, codec)
                hit = pat.search(dec)
                if hit:
                    v = hit.group(0)
                    v = v[:-16] + v[-16:].upper() if False else v  # noop guard
                    return answer(v, f"'{key}' field (codec={codec or 'plain'}) of {m.path}", 0.96, subject=m)

    # 2) Fall back: scan every member's bytes/strings for a matching token.
    for m in files(ctx):
        raw = data(m)
        if not raw:
            continue
        try:
            blob = raw.decode("latin-1")
        except (UnicodeDecodeError, AttributeError):
            continue
        hits = pat.findall(blob)
        # de-dup preserving order
        uniq = []
        for h in hits:
            if h not in uniq:
                uniq.append(h)
        if len(uniq) == 1:
            return answer(uniq[0], f"token matching answer pattern in {m.path}", 0.9, subject=m)

    return None
