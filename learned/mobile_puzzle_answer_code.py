# learned-module: mobile_puzzle_answer_code
"""Return the backend answer/evidence code for Huntress mobile APK challenges.

The APK ships an assets/*puzzle*.json fixture carrying the answer under a
"data"-like field, encoded by a declared codec (plain, base64, hex, reverse,
rot13, xor, url, or chains like "base64+reverse"). We decode per the declared
codec; if that does not yield a token matching the answer pattern we try a
fixed set of transform chains. Falls back to scanning member bytes (forward
and reversed) for a token matching the answer pattern."""
import base64
import binascii
import codecs
import itertools
import json
import re
import urllib.parse as urlparse

from hunt.learn.kit import answer, files, data, target, text
from hunt.solvers import handler

_KEYS = ("data", "answer", "flag", "code", "payload", "value", "token", "blob")


def _pattern_from_format(q):
    syn = (q.syntax or "")
    m = re.search(r"([A-Za-z]+-)\s*followed by\s*(?:exactly\s*)?(\d+)\s*uppercase hex", syn, re.I)
    if m:
        return re.compile(re.escape(m.group(1)) + "[0-9A-F]{" + m.group(2) + "}(?![0-9A-Fa-f])")
    m = re.search(r"([A-Za-z]+-)\s*followed by\s*(?:exactly\s*)?(\d+)\s*hex", syn, re.I)
    if m:
        return re.compile(re.escape(m.group(1)) + "[0-9A-Fa-f]{" + m.group(2) + "}(?![0-9A-Fa-f])")
    return re.compile(r"[A-Z]{2,5}-[0-9A-F]{8,}")


def _b64(v):
    s = v.strip()
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _hex(v):
    try:
        return bytes.fromhex(v.strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _b32(v):
    s = v.strip().upper()
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8)).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


_OPS = {
    "reverse": lambda v: v[::-1],
    "base64": _b64,
    "hex": _hex,
    "base32": _b32,
    "rot13": lambda v: codecs.encode(v, "rot13"),
    "url": lambda v: urlparse.unquote(v),
}
_ALIAS = {
    "reversed": "reverse", "rev": "reverse", "reverse_string": "reverse",
    "b64": "base64", "base64url": "base64", "base16": "hex", "b32": "base32",
    "rot-13": "rot13", "urlencode": "url", "percent": "url",
}


def _xor(v, key):
    raw = None
    for dec in (lambda s: bytes.fromhex(s), lambda s: base64.b64decode(s + "=" * (-len(s) % 4))):
        try:
            raw = dec(v.strip())
            break
        except (ValueError, binascii.Error):
            continue
    if raw is None:
        return None
    if isinstance(key, int):
        kb = bytes([key & 0xFF])
    elif isinstance(key, str):
        k = key.strip()
        if re.fullmatch(r"0x[0-9a-fA-F]+", k):
            kb = bytes([int(k, 16) & 0xFF])
        elif k.isdigit():
            kb = bytes([int(k) & 0xFF])
        else:
            kb = k.encode()
    else:
        return None
    if not kb:
        return None
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw)).decode("latin-1")


def _declared(value, codec, obj):
    steps = [s for s in re.split(r"[\s+|,>/;-]+", str(codec or "plain").lower()) if s]
    cur = value
    for s in steps:
        s = _ALIAS.get(s, s)
        if s in ("plain", "none", "text", "utf8", "utf-8", "identity", "raw"):
            continue
        if s == "xor":
            cur = _xor(cur, obj.get("key", obj.get("xor_key")))
        elif s in _OPS:
            cur = _OPS[s](cur)
        else:
            return None
        if cur is None:
            return None
    return cur


def _brute(value, pat):
    names = list(_OPS)
    for depth in (0, 1, 2, 3):
        for chain in itertools.product(names, repeat=depth):
            cur = value
            for s in chain:
                cur = _OPS[s](cur) if cur is not None else None
            if cur is None:
                continue
            hit = pat.search(cur)
            if hit:
                return hit.group(0), "+".join(chain) or "plain"
    return None, None


@handler(lanes=("mobile-android",))
def puzzle_answer(q, ctx):
    pat = _pattern_from_format(q)
    root = target(q, ctx)
    if root is None and len(ctx.artifacts.tops) > 1:
        return None
    members = files(ctx, root)

    for m in members:
        if not (m.basename or "").lower().endswith(".json"):
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
        codec = obj.get("codec") or obj.get("encoding")
        for key in _KEYS:
            val = obj.get(key)
            if not isinstance(val, str) or not val:
                continue
            dec = _declared(val, codec, obj)
            hit = pat.search(dec) if dec else None
            if hit:
                return answer(hit.group(0), f"'{key}' of {m.path} decoded with declared codec "
                                            f"{codec or 'plain'}", 0.96, subject=m)
            v, chain = _brute(val, pat)
            if v:
                print(f"declared codec {codec!r} failed; {chain} worked")
                return answer(v, f"'{key}' of {m.path} decoded via {chain} "
                                 f"(declared codec {codec})", 0.92, subject=m)

    for m in members:
        raw = data(m)
        if not raw:
            continue
        blob = raw.decode("latin-1")
        uniq = []
        for h in pat.findall(blob) + pat.findall(blob[::-1]):
            if h not in uniq:
                uniq.append(h)
        if len(uniq) == 1:
            return answer(uniq[0], f"token matching answer pattern in {m.path}", 0.9, subject=m)
    return None
