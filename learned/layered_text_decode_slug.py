# learned-module: layered_text_decode_slug
"""Questions asking to fully decode a text blob (Caesar/ROT-N, Atbash,
Base64/32/85, hex, reversal, URL-encoding, compressed payloads, stacked in
any order) and report the answer slug its final non-empty decoded line tells
you to submit. A breadth-first search over decodings stops at the first text
whose last line reads as an English instruction and carries a slug that
matches the answer syntax."""
import base64
import binascii
import bz2
import gzip
import re
import urllib.parse as urlparse
import zlib

from hunt.learn.kit import answer, data, target, text
from hunt.solvers import handler

_SLUG = re.compile(r"(?<![a-z0-9-])([a-z]+-[a-z]+-[a-z]+-\d{2})(?![a-z0-9-])")
_INSTR = re.compile(r"\b(submit|answer|enter|send|reply|flag)\b", re.I)
_WORDS = set("""the to and you your this that submit answer exact game master
solve decoding decode decoded nice work good job great is of for with it in on
be are was flag warmup enter send reply here final line done well thanks
congratulations please use only text message""".split())
_B64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_B32 = re.compile(r"[A-Z2-7]+=*")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")


def _score(t):
    toks = re.findall(r"[a-z]+", t.lower())
    if not toks:
        return 0.0
    return sum(1 for w in toks if w in _WORDS) / len(toks)


def _printable(t):
    if not t:
        return False
    good = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return good / len(t) > 0.95


def _bytes_to_text(b):
    if not b:
        return None
    for magic, fn in ((b"\x1f\x8b", gzip.decompress), (b"BZh", bz2.decompress)):
        if b.startswith(magic):
            try:
                b = fn(b)
            except Exception:
                return None
            break
    else:
        if b[:1] == b"\x78":
            try:
                b = zlib.decompress(b)
            except Exception:
                pass
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return t if _printable(t) else None


def _caesar(t, k):
    out = []
    for c in t:
        o = ord(c)
        if 97 <= o <= 122:
            out.append(chr((o - 97 + k) % 26 + 97))
        elif 65 <= o <= 90:
            out.append(chr((o - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def _atbash(t):
    out = []
    for c in t:
        o = ord(c)
        if 97 <= o <= 122:
            out.append(chr(219 - o))
        elif 65 <= o <= 90:
            out.append(chr(155 - o))
        else:
            out.append(c)
    return "".join(out)


def _steps(t):
    res = []
    compact = re.sub(r"\s+", "", t)
    if len(compact) >= 8:
        if _B64.fullmatch(compact):
            pad = compact + "=" * (-len(compact) % 4)
            for fn in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    r = _bytes_to_text(fn(pad))
                except (binascii.Error, ValueError):
                    r = None
                if r:
                    res.append(("base64", r))
                    break
        if _B32.fullmatch(compact.upper()) and compact.upper() == compact:
            try:
                r = _bytes_to_text(base64.b32decode(compact + "=" * (-len(compact) % 8)))
                if r:
                    res.append(("base32", r))
            except (binascii.Error, ValueError):
                pass
        if _HEX.fullmatch(compact):
            try:
                r = _bytes_to_text(bytes.fromhex(compact))
                if r:
                    res.append(("hex", r))
            except ValueError:
                pass
        try:
            r = _bytes_to_text(base64.b85decode(compact))
            if r:
                res.append(("base85", r))
        except (ValueError, binascii.Error):
            pass
    if "%" in t:
        u = urlparse.unquote(t)
        if u != t:
            res.append(("url", u))
    if re.search(r"[A-Za-z]", t):
        shifts = sorted(((_score(_caesar(t, k)), k) for k in range(1, 26)), reverse=True)
        for s, k in shifts[:2]:
            if s > 0:
                res.append((f"rot{k}", _caesar(t, k)))
        a = _atbash(t)
        if _score(a) > 0:
            res.append(("atbash", a))
    res.append(("reverse", t[::-1]))
    return res


def _final(t):
    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _check(t):
    last = _final(t)
    if not _INSTR.search(last):
        return None
    found = _SLUG.findall(last)
    if not found:
        return None
    return found[-1]


@handler(lanes=("warmups",))
def decoded_slug(q, ctx):
    hay = q.haystack
    if not ("decod" in hay and ("slug" in hay or "submit" in hay)):
        return None
    m = target(q, ctx)
    if m is None or data(m) is None:
        return None
    start = (text(m) or "").strip()
    if not start:
        return None
    frontier = [(start, [])]
    seen = {start}
    best = None
    for _depth in range(8):
        nxt = []
        for t, path in frontier:
            slug = _check(t)
            if slug and path:
                cand = (_score(_final(t)), -len(path), slug, path)
                if best is None or cand > best:
                    best = cand
            if best is not None:
                continue
            for name, r in _steps(t):
                r2 = r.strip()
                if r2 and r2 not in seen and len(seen) < 3000:
                    seen.add(r2)
                    nxt.append((r2, path + [name]))
        if best is not None or not nxt:
            break
        frontier = nxt
    if best is None:
        print(f"no decoded instruction found in {m.path}; tried {len(seen)} states")
        return None
    sc, _n, slug, path = best
    conf = 0.95 if sc >= 0.2 else 0.85
    return answer(slug, f"decoded {m.path} via {' -> '.join(path)}; final line names the slug",
                  conf, subject=m)
