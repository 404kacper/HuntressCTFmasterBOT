# learned-module: text_encoding_facts
"""Encoding-landmine facts about a text artifact, usually asked as
`text.<property>` (utf8_bom_present, bom type/hex/count/interior, encoding,
utf8 validity, line endings / CRLF / CR / LF presence or counts, mixed line
endings, trailing newline, line count, NUL, zero-width, bidi, homoglyph,
control, non-ASCII, tabs, trailing whitespace, NBSP, smart quotes, Unicode
normalization, replacement chars, sizes). Every fact is computed from the
member's raw bytes at run time. Enum answers are mapped onto the declared
accepted values."""
import re
import unicodedata

from hunt.gate import format_problem
from hunt.learn.kit import answer, data, leaves, target
from hunt.solvers import handler

_BOMS = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)
_ZW = "\u200b\u200c\u200d\u2060\u180e\ufeff"
_BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c"
_SMART = "\u2018\u2019\u201c\u201d\u201a\u201e"
_TRUE = ("true", "yes", "y", "1", "present", "on", "t")
_FALSE = ("false", "no", "n", "0", "absent", "off", "f")
_NEG = {"absent", "missing", "lacks", "lacking", "without"}
_CNT = {"count", "number", "num", "occurrences", "occurrence", "total", "how", "many", "qty"}
_INNER = {"interior", "embedded", "mid", "middle", "inner", "internal", "stray", "extra",
          "nonleading", "inline", "additional", "second", "later", "hidden", "inside"}
_MULTI = {"multiple", "double", "duplicate", "duplicated", "doubled", "repeated"}
_TRAIL = {"trailing", "final", "ends", "terminal", "eof", "last", "terminated", "terminating"}

_KEY_RE = re.compile(r"\b(?:text|encoding|unicode|charset)\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)")
_HINT_RE = re.compile(r"\bbom\b|byte[ -]order[ -]mark|line[ -]ending|newline|\bcrlf\b|encoding|"
                      r"zero[ -]width|utf-?(?:8|16|32)|homoglyph|bidi|\bnul\b|null byte")
_BOM_RE = re.compile(r"(?:^|_|utf(?:8|16|32)(?:le|be)?)boms?(?:_|$)")
_FAM_RE = re.compile(r"utf(?:8|16|32)(?:le|be)?")

_STYLE = {
    "crlf": ["crlf", "CRLF", "windows", "dos", "\\r\\n"],
    "lf": ["lf", "LF", "unix", "\\n"],
    "cr": ["cr", "CR", "mac", "\\r"],
    "mixed": ["mixed", "MIXED"],
    "none": ["none", "no line endings", "n/a"],
}


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def _canon(s):
    s = str(s).lower()
    s = re.sub(r"utf[\W_]*(8|16|32)", r"utf\1", s)
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


def _facts(raw):
    bom, sig = None, b""
    for s, name in _BOMS:
        if raw.startswith(s):
            if name.startswith("utf-32"):
                if len(raw) % 4:
                    continue
                try:
                    raw.decode(name)
                except UnicodeDecodeError:
                    continue
            bom, sig = name, s
            break
    try:
        raw.decode("utf-8")
        valid8 = True
    except UnicodeDecodeError:
        valid8 = False
    codec = enc = None
    if bom:
        codec = enc = bom
    else:
        n = len(raw)
        if n >= 4 and n % 2 == 0:
            half = n // 2
            ev = raw[0::2].count(0)
            od = raw[1::2].count(0)
            if od >= 0.3 * half and ev <= 0.05 * half:
                codec = enc = "utf-16-le"
            elif ev >= 0.3 * half and od <= 0.05 * half:
                codec = enc = "utf-16-be"
        if codec is None:
            if valid8:
                codec = "utf-8"
                enc = "ascii" if raw.isascii() else "utf-8"
            else:
                codec, enc = "latin-1", "windows-1252"
    full = raw.decode(codec, "replace")
    body = full[1:] if bom and full.startswith("\ufeff") else full
    crlf = body.count("\r\n")
    return {
        "raw": raw, "full": full, "body": body, "bom": bom, "sig": sig,
        "codec": codec, "enc": enc, "valid8": valid8, "crlf": crlf,
        "cr": body.count("\r") - crlf, "lf": body.count("\n") - crlf,
    }


def _enc_names(f):
    e, bom = f["enc"], f["bom"]
    if bom == "utf-8":
        return ["utf-8-sig", "utf-8-bom", "UTF-8 with BOM", "utf-8 bom", "utf8bom", "utf-8"]
    if e == "ascii":
        return ["ascii", "us-ascii", "utf-8"]
    if e == "utf-8":
        return ["utf-8", "UTF-8", "utf8"]
    if e.startswith("utf-16") or e.startswith("utf-32"):
        base, end = e[:6], e[7:]
        return [e, base + end, f"{base} {end}", f"{base.upper()} {end.upper()}",
                f"{base.upper()}{end.upper()}", base, base.upper()]
    return ["windows-1252", "cp1252", "latin-1", "iso-8859-1", "ansi"]


def _bom_names(lead):
    if lead == "utf-8":
        return ["utf-8", "UTF-8", "utf8", "utf-8-sig", "utf-8-bom"]
    base, end = lead[:6], lead[7:]
    return [lead, base + end, f"{base.upper()} {end.upper()}", f"{base.upper()}{end.upper()}", base]


def _is_family(f, want):
    enc = _norm(f["enc"])
    if want == "utf8":
        return enc in ("utf8", "ascii")
    return enc.startswith(want)


def _resolve(p, f, mode, syn, strict):
    toks = set(t for t in p.split("_") if t)
    raw, full, body = f["raw"], f["full"], f["body"]
    flat = p.replace("_", "")
    inv = bool(toks & _NEG) or p.startswith("no_")
    cnt = mode == "int" or bool(toks & _CNT)

    def B(v, why, conf=0.97, alt=False):
        return ("bool", (not v) if inv else bool(v), why, conf, alt)

    def I(n, why, conf=0.95, alts=()):
        return ("int", int(n), why, conf, tuple(alts))

    def S(cands, why, conf=0.93):
        return ("str", list(cands), why, conf, ())

    def CB(n, why, conf=0.97, alt=False):
        if cnt:
            return I(n, f"{why}: {n}", conf)
        return B(n > 0, f"{why}: {n}", conf, alt)

    # ---- byte order marks
    if _BOM_RE.search(p) or "byteordermark" in flat:
        m32 = re.search(r"utf32_?(le|be)", p)
        m16 = re.search(r"utf16_?(le|be)", p)
        fam = None
        if "utf8" in p:
            fam = "utf-8"
        elif m32:
            fam = "utf-32-" + m32.group(1)
        elif "utf32" in p:
            fam = "utf-32"
        elif m16:
            fam = "utf-16-" + m16.group(1)
        elif "utf16" in p:
            fam = "utf-16"
        lead = f["bom"]
        match = lead is not None and (fam is None or lead.startswith(fam))
        if fam == "utf-8" or (fam is None and f["codec"] == "utf-8"):
            occ = raw.count(b"\xef\xbb\xbf")
            lead_here = raw.startswith(b"\xef\xbb\xbf")
        else:
            occ = full.count("\ufeff")
            lead_here = full.startswith("\ufeff")
        inner = occ - (1 if lead_here else 0)
        label = fam or "any"
        if toks & {"length", "len", "size"}:
            return I(len(f["sig"]) if match else 0, f"leading {label} BOM length")
        if toks & _MULTI:
            if cnt:
                return I(occ, f"{occ} {label} BOM sequence(s) in the bytes")
            return B(occ >= 2, f"{occ} {label} BOM sequence(s) in the bytes")
        if toks & _INNER:
            return CB(inner, f"{label} BOM sequences after offset 0")
        if cnt:
            return I(occ, f"{occ} {label} BOM sequence(s) in the bytes")
        if mode != "bool" and (mode == "str" or toks & {"hex", "bytes", "signature", "type", "kind",
                                                          "name", "encoding", "family", "variant", "which"}):
            if toks & {"hex", "bytes", "signature"} or "hex" in syn:
                if not match:
                    return S(["none"], f"no {label} BOM at offset 0")
                hx = f["sig"].hex()
                return S([hx, hx.upper(), " ".join(f"{b:02x}" for b in f["sig"]), "0x" + hx],
                         f"leading BOM bytes {hx}", 0.95)
            if not match:
                return S(["none", "no bom", "absent", "false"], f"no {label} BOM at offset 0", 0.9)
            return S(_bom_names(lead), f"leading bytes {f['sig'].hex()} are the {lead} BOM", 0.93)
        head = raw[:4].hex() or "empty"
        state = "present" if match else "absent"
        return B(match, f"leading bytes {head} -> {label} BOM {state} at offset 0 "
                        f"({inner} more BOM sequence(s) later)", 0.97, inner > 0 and not match)

    # ---- encoding name / family
    if toks & {"encoding", "charset", "codec", "codepage"}:
        if mode == "bool":
            mf = _FAM_RE.search(flat)
            if not mf:
                return None
            return B(_is_family(f, mf.group(0)), f"detected encoding {f['enc']}")
        if mode == "int":
            return None
        return S(_enc_names(f), f"detected encoding {f['enc']} (bom={f['bom'] or 'none'}, "
                                f"valid utf-8={f['valid8']})", 0.92)
    if "utf8" in flat and toks & {"valid", "invalid", "decodes", "decodable", "decode", "decoding",
                                  "clean", "strict", "malformed", "wellformed", "well"}:
        v = f["valid8"]
        if toks & {"invalid", "malformed"}:
            v = not v
        return B(v, f"strict UTF-8 decode {'succeeds' if f['valid8'] else 'fails'}")
    mf = _FAM_RE.search(flat)
    if mode == "bool" and mf and toks & {"is", "encoded", "uses", "detected", "likely"}:
        return B(_is_family(f, mf.group(0)), f"detected encoding {f['enc']}")

    # ---- line endings
    le = (bool(toks & {"crlf", "lf", "cr", "eol", "eols", "newline", "newlines", "linebreak",
                       "linebreaks", "crs", "lfs", "crlfs"})
          or "lineending" in flat or "linebreak" in flat or "lineterminator" in flat
          or "newline" in flat)
    if le:
        kinds = [k for k in ("crlf", "lf", "cr") if f[k]]
        counts = f"crlf={f['crlf']} lone_lf={f['lf']} lone_cr={f['cr']}"
        if toks & _TRAIL or ("end" in toks and "file" in toks):
            ends = body.endswith(("\n", "\r"))
            return B(ends, f"decoded text {'ends' if ends else 'does not end'} with a line break")
        if toks & {"mixed", "inconsistent", "consistent"}:
            v = len(kinds) > 1
            if "consistent" in toks and "inconsistent" not in toks:
                v = not v
            return B(v, f"line-ending kinds {kinds} ({counts})")
        for k in ("crlf", "cr", "lf", "crlfs", "crs", "lfs"):
            if k not in toks:
                continue
            k = k.rstrip("s") if k != "crs" else "cr"
            if cnt:
                alts = []
                if k == "lf" and not toks & {"bare", "lone", "only", "solo", "unix"}:
                    alts = [f["lf"] + f["crlf"]]
                return I(f[k], f"{k} count ({counts})", 0.95 if not alts else 0.9, alts)
            v = kinds == [k] if "only" in toks else f[k] > 0
            return B(v, f"line endings {counts}")
        if cnt:
            return I(f["crlf"] + f["cr"] + f["lf"], f"line breaks ({counts})")
        if mode == "bool":
            return None
        style = kinds[0] if len(kinds) == 1 else ("mixed" if kinds else "none")
        return S(_STYLE[style], f"line endings {counts}", 0.95)

    # ---- landmine characters
    if toks & {"nul", "null", "nuls", "nulls"}:
        nraw, nbody = raw.count(0), body.count("\x00")
        use_raw = bool(toks & {"byte", "bytes"}) and not toks & {"char", "chars", "character", "characters"}
        n = nraw if use_raw else nbody
        amb = (nraw > 0) != (nbody > 0)
        where = "raw bytes" if use_raw else "decoded text"
        return CB(n, f"NULs in {where}", 0.9 if amb else 0.97, amb)
    if "zerowidth" in flat or toks & {"zwsp", "zwj", "zwnj", "invisible"}:
        pool = _ZW + (_BIDI if "invisible" in toks else "")
        return CB(sum(body.count(c) for c in pool), "zero-width characters in decoded text (leading BOM excluded)")
    if toks & {"bidi", "rtl", "rlo", "override", "overrides", "trojan", "directional"}:
        return CB(sum(body.count(c) for c in _BIDI), "bidi control characters in decoded text")
    if toks & {"homoglyph", "homoglyphs", "confusable", "confusables", "cyrillic", "greek", "lookalike",
               "lookalikes"} or "mixedscript" in flat:
        cyr = sum(1 for c in body if "\u0400" <= c <= "\u052f")
        grk = sum(1 for c in body if "\u0370" <= c <= "\u03ff")
        n = cyr if "cyrillic" in toks else (grk if "greek" in toks else cyr + grk)
        return CB(n, f"Cyrillic={cyr} Greek={grk} letters in decoded text", 0.93)
    if toks & {"control", "controls", "ctrl"}:
        n = sum(1 for c in body if (ord(c) < 32 and c not in "\t\n\r") or 0x7F <= ord(c) <= 0x9F)
        return CB(n, "control characters (excluding tab/CR/LF) in decoded text")
    if "nonascii" in flat or "ascii" in toks:
        hi = sum(1 for c in body if ord(c) > 127)
        raw_hi = sum(1 for b in raw if b > 127)
        amb = (hi > 0) != (raw_hi > 0)
        conf = 0.9 if amb else 0.97
        if "nonascii" in flat:
            if cnt:
                return I(hi, f"non-ASCII characters in decoded text: {hi} (raw bytes >127: {raw_hi})",
                         conf, [raw_hi] if raw_hi != hi else [])
            return B(hi > 0, f"non-ASCII characters in decoded text: {hi} (raw bytes >127: {raw_hi})", conf, amb)
        return B(hi == 0, f"non-ASCII characters in decoded text: {hi} (raw bytes >127: {raw_hi})", conf, amb)
    if toks & {"tab", "tabs"}:
        return CB(body.count("\t"), "tab characters in decoded text")
    if "trailing" in toks and toks & {"whitespace", "space", "spaces", "blank", "blanks"}:
        lines = re.split(r"\r\n|\r|\n", body)
        n = sum(1 for ln in lines if ln != ln.rstrip(" \t"))
        return CB(n, "lines with trailing whitespace")
    if "nbsp" in toks or "nonbreaking" in flat:
        return CB(body.count("\u00a0") + body.count("\u202f"), "no-break spaces in decoded text")
    if toks & {"smart", "curly", "typographic"}:
        return CB(sum(body.count(c) for c in _SMART), "typographic quotes in decoded text")
    for form in ("nfc", "nfd", "nfkc", "nfkd"):
        if form in toks:
            ok = unicodedata.normalize(form.upper(), body) == body
            return B(ok, f"decoded text {'is' if ok else 'is not'} {form.upper()}-normalized")
    if "replacement" in toks or "fffd" in flat:
        n = raw.count(b"\xef\xbf\xbd") if f["codec"] == "utf-8" else body.count("\ufffd")
        return CB(n, "U+FFFD replacement characters")

    # ---- structure / sizes (only for explicit text.<key> questions)
    if strict and "first" in toks and "line" in toks:
        first = re.split(r"\r\n|\r|\n", body)[0].strip()
        if not first:
            return None
        return S([first], "first line of decoded text (BOM stripped)", 0.92)
    if toks & {"line", "lines"} and (cnt or "lines" in toks):
        n = len(re.findall(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$", body))
        breaks = f["crlf"] + f["cr"] + f["lf"]
        return I(n, f"{n} lines ({breaks} line breaks)", 0.92, [breaks] if breaks != n else [])
    if strict and toks & {"char", "chars", "character", "characters"}:
        return I(len(body), f"{len(body)} decoded characters (BOM excluded)", 0.9,
                 [len(full)] if len(full) != len(body) else [])
    if strict and toks & {"byte", "bytes", "size"} and (cnt or toks & {"size", "length", "len"}):
        return I(len(raw), f"{len(raw)} raw bytes", 0.97)
    return None


def _mode(q):
    rawq = q.raw if isinstance(q.raw, dict) else {}
    af = rawq.get("answer_format")
    acc = []
    if isinstance(af, dict):
        acc = [str(a).strip() for a in (af.get("accepted_values") or []) if str(a).strip()]
    low = [a.lower() for a in acc]
    kind = (q.kind or "").lower()
    if acc and all(a in _TRUE + _FALSE for a in low):
        return "bool", acc
    if kind in ("integer", "int", "number"):
        return "int", acc
    if kind in ("boolean", "bool"):
        return "bool", acc
    if acc:
        return "str", acc
    syn = (q.syntax or "").lower()
    if re.search(r"\btrue\b", syn) and re.search(r"\bfalse\b", syn):
        return "bool", acc
    return None, acc


def _bool_word(v, acc):
    pool = _TRUE if v else _FALSE
    for a in acc:
        if a.lower() in pool:
            return a
    return "true" if v else "false"


def _choose(cands, acc, refused):
    out = []
    for c in cands:
        if c not in out:
            out.append(c)
    if acc:
        amap = {}
        for a in acc:
            amap.setdefault(_norm(a), a)
        hits = []
        for c in out:
            a = amap.get(_norm(c))
            if a is not None and a not in hits:
                hits.append(a)
        if not hits:
            return None, []
        return hits[0], hits[1:]
    keep = [c for c in out if c not in refused] or out
    return keep[0], keep[1:]


def _member(q, ctx):
    m = target(q, ctx)
    if m is None:
        return None
    try:
        inner = [k for k in leaves(ctx, m) if k.path != m.path]
    except Exception:
        inner = []
    if not inner:
        return m
    if len(inner) == 1:
        return inner[0]
    txt = q.text or ""
    named = [k for k in inner if k.basename and k.basename in txt]
    if not named:
        return None
    named.sort(key=lambda k: (k.name in txt, len(k.basename)), reverse=True)
    return named[0]


@handler()
def text_encoding_fact(q, ctx):
    txt = q.text or ""
    mk = _KEY_RE.search(txt)
    strict = mk is not None
    if not strict:
        try:
            lane = ctx.attempt.lane or ""
        except Exception:
            lane = ""
        if not lane.startswith("metadata-forensics"):
            return None
        if not _HINT_RE.search(q.haystack):
            return None
    m = _member(q, ctx)
    if m is None:
        return None
    raw = data(m)
    if raw is None:
        return None

    props = []
    if strict:
        props.append(_canon(mk.group(1)))
    else:
        stem = _canon((m.basename or "").rsplit(".", 1)[0])
        qid = re.sub(r"^set\d+\.", "", (q.id or "").lower())
        i = qid.find("text-")
        pid = _canon(qid[i + 5:] if i >= 0 else qid)
        ptx = _canon(txt.replace(m.basename, " ") if m.basename else txt)
        for p in (pid, ptx):
            if stem:
                p = re.sub(r"_+", "_", p.replace(stem, "_")).strip("_")
            props.append(p)

    f = _facts(raw)
    mode, acc = _mode(q)
    syn = (q.syntax or "").lower()
    res = None
    for p in props:
        if p:
            res = _resolve(p, f, mode, syn, strict)
            if res is not None:
                break
    if res is None:
        print(f"text_encoding_fact: no rule for {props} (mode={mode})")
        return None

    typ, val, why, conf, extra = res
    rawq = q.raw if isinstance(q.raw, dict) else {}
    refused = [str(r) for r in (rawq.get("refused_by_game_master") or [])]
    if typ == "bool":
        if mode in ("int", "str"):
            return None
        value = _bool_word(val, acc)
        alts = []
        if extra:
            alts.append(_bool_word(not val, acc))
            conf = min(conf, 0.9)
        if not acc:
            alts += ["yes", "True"] if val else ["no", "False"]
    elif typ == "int":
        if mode == "bool":
            return None
        value = str(val)
        alts = [str(a) for a in extra if str(a) != value]
        if mode == "str" and acc and value not in acc:
            return None
    else:
        if mode in ("bool", "int"):
            return None
        value, alts = _choose(val, acc, refused)
        if value is None:
            print(f"text_encoding_fact: candidates {val} not in accepted {acc}")
            return None

    opts = [value] + [a for a in alts if a != value]
    good = [o for o in opts if format_problem(q, o) is None]
    if not good:
        print(f"text_encoding_fact: gate objects to {value!r}: {format_problem(q, value)}")
        return None
    bom = f["bom"] or "none"
    ev = f"{why}; {m.path}: {len(raw)} bytes, detected {f['enc']}, leading BOM {bom}"
    return answer(good[0], ev, conf, subject=m, alternatives=good[1:])
