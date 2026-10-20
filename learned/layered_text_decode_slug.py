# learned-module: layered_text_decode_slug
"""Questions asking to fully decode a text blob (Caesar/ROT-N, Atbash,
Base64/32/85, hex, reversal, URL-encoding, compressed payloads, stacked in
any order) and report the answer slug its final non-empty decoded line tells
you to submit. A breadth-first search over decodings stops at the first text
whose last line reads as an English instruction and carries a slug that
matches the answer syntax. A blob of numbered lines ('01<TAB>...') whose
lines are each encoded their own way (Mastery) is decoded line by line and
joined in order."""
import base64
import binascii
import bz2
import gzip
import math
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
# Words the Game Master's answer slugs were made of so far (adjective-noun-noun-NN): a decoded
# slug then reads as English too, which is what tells it from its ROT-N or Atbash.
_WORDS |= set("""brave clever crisp dapper dashing eager funky gentle handy jazzy jovial kind lucky
nimble peppy plucky quick quiet snappy tidy witty zesty anchor banner candle chimney clock cloud
garden harbor island meadow piano river scooter sparrow squirrel summit tent valley birch blossom
boulder brook cider copper dune fern flint glade lagoon maple marble ridge ripple trail turtle
whale""".split())
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


def _search(start):
    """Breadth-first over stacked decodings of the whole text: (score, -layers, slug, path) or None."""
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
    return best


_SEGMENT = re.compile(r"^\s*(\d{1,3})(?:\t|[:|.)] ?)(.*)$")  # the payload keeps its own leading spaces


def _segments(t):
    """Numbered lines ('01<TAB>payload', ...) in number order, or None when the text is not like that."""
    rows = [ln.rstrip("\r") for ln in t.splitlines() if ln.strip()]
    if len(rows) < 2:
        return None
    out = []
    for ln in rows:
        m = _SEGMENT.match(ln)
        if m is None:
            return None
        out.append((int(m.group(1)), m.group(2)))
    out.sort(key=lambda x: x[0])
    return [p for _n, p in out]


# English letter frequencies (percent): a fragment too short to hold a whole word, or a slug,
# still reads as English letters once its ROT-N / Atbash is undone.
_FREQ = dict(zip("abcdefghijklmnopqrstuvwxyz", (
    8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4,
    6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074)))
_LOGF = {c: math.log(p / 100.0) for c, p in _FREQ.items()}


def _english(t):
    """How much t reads like English text: whole known words first, then letter frequencies,
    less for digits and symbols and for case flipping inside words (encoded text)."""
    letters = [c for c in t.lower() if "a" <= c <= "z"]
    if not letters:
        return -10.0
    fit = sum(_LOGF[c] for c in letters) / len(letters)  # English about -2.9, shuffled about -3.6
    odd = sum(1 for c in t if not (c.isalpha() or c in " .,!?:;'\"-")) / len(t)
    flips = len(re.findall(r"[a-z][A-Z]", t)) / len(letters)
    return 3.0 * _score(t) + fit - 2.0 * odd - 4.0 * flips


def _letter_variants(s):
    """Every ROT-N and Atbash of s, whatever its words: fragments are too short to judge by words."""
    if not re.search(r"[A-Za-z]", s):
        return []
    return [(f"rot{k}", _caesar(s, k)) for k in range(1, 26)] + [("atbash", _atbash(s))]


def _looks_encoded(s):
    compact = re.sub(r"\s+", "", s)
    return len(compact) >= 8 and any(name in ("base64", "base32", "hex", "base85") for name, _r in _steps(s))


def _layers(t, depth=3):
    """t and every decoding reachable from it in up to `depth` steps, most English first.
    Unstripped: a segment's leading or trailing space is part of the sentence it joins."""
    found = [(t, [])]
    seen = {t}
    frontier = [(t, [])]
    for _ in range(depth):
        nxt = []
        for s, path in frontier:
            for name, r in _steps(s) + _letter_variants(s):
                if r.strip() and r not in seen and len(seen) < 2000:
                    seen.add(r)
                    found.append((r, path + [name]))
                    # a letter shift only leads somewhere when it uncovers another encoding
                    if not (name.startswith("rot") or name == "atbash") or _looks_encoded(r):
                        nxt.append((r, path + [name]))
        frontier = nxt
    return sorted(found, key=lambda x: (-(_english(x[0]) - _LAYER * len(x[1])), len(x[1])))


_LAYER = 0.3  # English-likeness one more decoding layer has to buy
_SURE = 0.25  # how much better the chosen slug must read than any other slug


def _assemble(options):
    """Every way to join one decoding per line: slug -> (English-likeness less layers, layers,
    text, path) for the best-reading text that ends in an instruction with that slug."""
    combos = [("", [], [])]
    for opts in options:
        if not opts:
            return {}
        combos = [(text + t, path + ["+".join(p) or "plain"], lens + [len(t)])
                  for text, path, lens in combos for t, p in opts]
        if len(combos) > 20000:
            return {}
    per_slug = {}
    for text, path, lens in combos:
        slug = _check(text)
        if not slug or all(p == "plain" for p in path):
            continue
        layers = sum(p.count("+") + 1 for p in path if p != "plain")
        value = _english(_final(text)) - _LAYER * layers
        if slug not in per_slug or value > per_slug[slug][0]:
            per_slug[slug] = (value, layers, text, path, lens)
    return per_slug


def _shift_decides(slug, text, path, lens):
    """A ROT-N or Atbash on a line holding part of the slug, while one of its words is new to
    the bot: nothing then tells that shift from the other 25, so the slug is a guess."""
    if all(w in _WORDS for w in re.findall(r"[a-z]+", slug)):
        return False
    start = text.rfind(slug)
    end, pos = start + len(slug), 0
    for p, n in zip(path, lens):
        if pos < end and pos + n > start and re.search(r"rot\d|atbash", p):
            return True
        pos += n
    return False


def _segmented(start):
    """Mastery blobs: each numbered line is encoded on its own (one base64, the next ROT13, the
    next hex, ...); decode each, then join them in order. Only when that finds nothing, the raw
    lines joined, in case one encoding was merely wrapped across lines. (score, -layers, slug,
    path) or None, with score 0 when the slug is in doubt, so the gate holds the answer."""
    parts = _segments(start)
    if parts is None:
        return None
    keep = max(2, int(5000 ** (1.0 / len(parts))))
    decoded = [_layers(p) for p in parts]
    # Every line is encoded ("decode the blob completely"); a line left as it is comes last.
    per_slug = _assemble([[x for x in d if x[1]][:keep] for d in decoded]) \
        or _assemble([d[:keep] for d in decoded])
    if not per_slug:
        return _search("".join(p.strip() for p in parts))
    ranked = sorted(per_slug.items(), key=lambda kv: -kv[1][0])
    slug, (value, layers, text, path, lens) = ranked[0]
    lines = [f"line {i + 1}: {p}" for i, p in enumerate(path)]
    score = _score(_final(text))
    if len(ranked) > 1 and value - ranked[1][1][0] < _SURE:
        score = 0.0
        lines.append(f"(but {ranked[1][0]} reads almost as well)")
    elif _shift_decides(slug, text, path, lens):
        score = 0.0
        lines.append("(a letter shift decided a slug word this bot has not seen)")
    return score, -layers, slug, lines


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
    best = _search(start) or _segmented(start)
    if best is None:
        print(f"no decoded instruction found in {m.path}")
        return None
    sc, _n, slug, path = best
    conf = 0.95 if sc >= 0.2 else 0.85
    return answer(slug, f"decoded {m.path} via {' -> '.join(path)}; final line names the slug",
                  conf, subject=m)
