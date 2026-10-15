# learned-module: powershell_fixture_indicators
"""Triage inert PowerShell fixtures: decode the embedded indicator blob
(base64 / hex / byte-array, optionally reversed, XOR'd or gzip/deflate'd,
usually JSON), then answer scenario classification, primary ATT&CK
technique, and exact indicators (URL, wallet, mutex, user-agent, filename,
ransom extension, recovery note) from the decoded values."""
import base64
import binascii
import gzip
import hashlib
import json
import re
import zlib

from hunt.learn.kit import answer, data, target
from hunt.solvers import handler

_CACHE = {}

_QUOTED = re.compile(r"'([^'\r\n]*)'|\"([^\"\r\n]*)\"")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")
_INTS = re.compile(r"(?:(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*,\s*){7,}(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})")
_XORK = re.compile(r"-bxor\s*(?:0x([0-9A-Fa-f]+)|(\d+))", re.I)
_URL = re.compile(r"https?://[^\s'\"<>|]+", re.I)
_MUTEX = re.compile(r"^(?:Global|Local|Session)\\\S+$")
_EXT = re.compile(r"^\.[A-Za-z0-9_-]{1,24}$")
_FNAME = re.compile(r"^[\w .()\[\]-]+\.[A-Za-z0-9]{1,6}$")
_BROWSER_FILES = {"login data", "cookies", "web data", "local state", "key4.db",
                  "logins.json", "cookies.sqlite", "history", "places.sqlite"}
_WALLET_RE = re.compile(
    r"^(?:wallet[_-]\S+|bc1[02-9ac-hj-np-z]{20,80}|[13][1-9A-HJ-NP-Za-km-z]{25,34}"
    r"|0x[0-9a-fA-F]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$")
_NOTE_HINT = re.compile(r"recover|readme|read_me|decrypt|restore|how[_-]?to|ransom|instructions|note", re.I)


def _xor(b, k):
    n = len(k)
    return bytes(x ^ k[i % n] for i, x in enumerate(b))


def _decompress(b):
    out = [b]
    for fn in (gzip.decompress, zlib.decompress):
        try:
            out.append(fn(b))
        except Exception:
            pass
    try:
        out.append(zlib.decompress(b, -15))
    except Exception:
        pass
    return out


def _as_json(b):
    for enc in ("utf-8-sig", "utf-16-le"):
        try:
            t = b.decode(enc).strip()
        except UnicodeDecodeError:
            continue
        if not t or t[0] not in "{[":
            continue
        try:
            o = json.loads(t)
        except ValueError:
            continue
        if isinstance(o, (dict, list)):
            return o
    return None


def _raw_blobs(src):
    out = []
    lits = []
    for a, b in _QUOTED.findall(src):
        s = (a or b).strip()
        lits.append(s)
        if _HEX.fullmatch(s):
            try:
                out.append(bytes.fromhex(s))
            except ValueError:
                pass
        if _B64.fullmatch(s):
            for alt in (s, s.replace("-", "+").replace("_", "/")):
                try:
                    out.append(base64.b64decode(alt + "=" * (-len(alt) % 4)))
                    break
                except (binascii.Error, ValueError):
                    continue
    for run in _INTS.findall(src):
        vals = [int(x, 16) if x.lower().startswith("0x") else int(x)
                for x in re.split(r"\s*,\s*", run.strip())]
        if all(0 <= v < 256 for v in vals):
            out.append(bytes(vals))
    return out, lits


def _decode_obj(blob, keys):
    stage1 = [blob, blob[::-1]]
    for k in keys:
        stage1.append(_xor(blob, k))
        stage1.append(_xor(blob[::-1], k))
    for cand in stage1:
        for d in _decompress(cand):
            o = _as_json(d)
            if o is not None:
                return o
    for kb in range(1, 256):
        x = _xor(blob, bytes([kb]))
        for d in _decompress(x):
            o = _as_json(d)
            if o is not None:
                return o
    return None


def _flat(o, vals, lists):
    if isinstance(o, dict):
        for v in o.values():
            _flat(v, vals, lists)
    elif isinstance(o, list):
        strs = [x.strip() for x in o if isinstance(x, str) and x.strip()]
        if strs:
            lists.append(strs)
        for v in o:
            _flat(v, vals, lists)
    elif isinstance(o, str):
        s = o.strip()
        if s and "\n" not in s:
            vals.append(s)


def _analyse(m):
    raw = data(m)
    if not raw:
        return None
    key = hashlib.sha256(raw).hexdigest()
    if key in _CACHE:
        return _CACHE[key]
    try:
        src = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        src = raw.decode("latin-1")
    blobs, lits = _raw_blobs(src)
    keys = []
    for h, d in _XORK.findall(src):
        try:
            v = int(h, 16) if h else int(d)
        except ValueError:
            continue
        if 0 < v < 256:
            keys.append(bytes([v]))
    for s in lits:
        if 1 <= len(s) <= 64:
            keys.append(s.encode("utf-8"))
    vals, lists, decoded = [], [], []
    for b in blobs:
        o = _decode_obj(b, keys)
        if o is not None:
            _flat(o, vals, lists)
            decoded.append(json.dumps(o))
    from_json = bool(vals)
    for s in lits:
        if s and s not in vals and not _B64.fullmatch(s) and not _HEX.fullmatch(s):
            vals.append(s)
    full = src + "\n" + "\n".join(decoded) + "\n" + "\n".join(vals)
    res = {"vals": vals, "lists": lists, "full": full, "json": from_json}
    _CACHE[key] = res
    return res


def _classify(info):
    full = info["full"].lower()
    vals = info["vals"]
    sc = {"resource": 0, "collection": 0, "impact": 0}
    if any(_WALLET_RE.match(v) or "wallet" in v.lower() for v in vals):
        sc["resource"] += 3
    for w, n in (("stratum", 3), ("xmrig", 3), ("hashrate", 2), ("monero", 2),
                 ("[diagnostics.process]", 1), ("mining", 2), ("miner", 2)):
        if w in full:
            sc["resource"] += n
    if any(_EXT.match(v) for v in vals):
        sc["impact"] += 3
    if any(_FNAME.match(v) and _NOTE_HINT.search(v) for v in vals):
        sc["impact"] += 3
    for w, n in (("cryptography.aes", 2), ("[security.cryptography", 2), ("directoryinfo", 1),
                 ("vssadmin", 2), ("shadowcopy", 2), (".locked", 1), ("encrypt", 1)):
        if w in full:
            sc["impact"] += n
    low = [v.lower() for v in vals]
    for w, n in (("login data", 1), ("cookies", 1), ("web data", 1), ("key4.db", 1)):
        if w in low:
            sc["collection"] += n
    if any(v.lower().endswith(".zip") for v in vals):
        sc["collection"] += 2
    for w, n in (("compression.zipfile", 2), ("compress-archive", 2),
                 ("httpwebrequest", 1), ("uploadfile", 1)):
        if w in full:
            sc["collection"] += n
    ranked = sorted(sc.items(), key=lambda kv: -kv[1])
    best, top = ranked[0]
    margin = top - ranked[1][1]
    return best, top, margin, sc


def _enum_value(q, cls):
    fmt = q.raw.get("answer_format") if isinstance(q.raw, dict) else None
    acc = (fmt or {}).get("accepted_values") or []
    words = {"resource": ("resource", "hijack", "mining", "miner"),
             "collection": ("collection", "steal", "exfil"),
             "impact": ("impact", "ransom", "encrypt")}[cls]
    for a in acc:
        if any(w in str(a).lower() for w in words):
            return str(a)
    return {"resource": "resource_hijacking", "collection": "synthetic_collection",
            "impact": "synthetic_impact"}[cls]


def _pick(cands, what, m):
    uniq = []
    for c in cands:
        if c not in uniq:
            uniq.append(c)
    if not uniq:
        return None
    conf = 0.95 if len(uniq) == 1 else 0.9
    return answer(uniq[0], f"{what} decoded from embedded material in {m.path}", conf,
                  subject=m, alternatives=uniq[1:])


@handler(lanes=("script-analysis",))
def powershell_fixture(q, ctx):
    m = target(q, ctx)
    if m is None:
        m = ctx.subject
    if m is None:
        return None
    name = (m.basename or "").lower()
    if not (name.endswith((".ps1", ".psm1", ".psd1", ".ps", ".txt")) or "powershell" in q.haystack):
        return None
    info = _analyse(m)
    if info is None:
        return None
    hay = q.haystack
    vals = info["vals"]

    if "scenario" in hay or "classif" in hay:
        cls, top, margin, sc = _classify(info)
        if top == 0:
            return None
        conf = 0.95 if margin >= 2 else 0.8
        return answer(_enum_value(q, cls), f"behaviour scores {sc} for {m.path}", conf, subject=m)

    if "att&ck" in hay or "technique" in hay or (q.kind or "") == "mitre_attack_id" or "-attack" in (q.id or ""):
        cls, top, margin, sc = _classify(info)
        if top == 0:
            return None
        conf = 0.95 if margin >= 2 else 0.8
        if cls == "resource":
            vs = ["T1496", "T1496.001"]
        elif cls == "impact":
            vs = ["T1486"]
        else:
            if "credential" in hay or "browser" in hay:
                vs = ["T1555.003", "T1005", "T1555"]
            else:
                vs = ["T1005", "T1555.003"]
        return answer(vs[0], f"{cls} behaviour ({sc}) in {m.path}", conf, subject=m,
                      alternatives=vs[1:])

    if "user-agent" in hay or "user agent" in hay or "useragent" in hay:
        c = [v for v in vals if v.startswith("Mozilla/")]
        if not c:
            c = [v for v in vals if re.match(r"^[A-Za-z][\w.-]*/\d[\w.]*(?: |$)", v) and "://" not in v]
        return _pick(c, "user-agent", m)

    if "wallet" in hay:
        c = [v for v in vals if _WALLET_RE.match(v)]
        if not c:
            c = [v for v in vals if "wallet" in v.lower()]
        return _pick(c, "wallet indicator", m)

    if "mutex" in hay:
        c = [v for v in vals if _MUTEX.match(v)]
        return _pick(c, "mutex", m)

    if "recovery" in hay or "note" in hay or "ransom" in hay:
        c = [v for v in vals if _FNAME.match(v) and _NOTE_HINT.search(v) and "\\" not in v]
        if not c:
            c = [v for v in vals if re.match(r"^[\w.-]+\.(?:txt|html?|hta|rtf)$", v, re.I)]
        return _pick(c, "recovery note filename", m)

    if "extension" in hay:
        c = [v for v in vals if _EXT.match(v)]
        return _pick(c, "extension indicator", m)

    if re.search(r"\burl\b", hay) or "-url" in hay:
        c = [v for v in vals if _URL.fullmatch(v)]
        if not c:
            c = _URL.findall(info["full"])
        return _pick(c, "URL", m)

    if "filename" in hay or "file name" in hay or re.search(r"\bfile\b", hay):
        def is_file(v):
            if "\\" in v or "/" in v or ":" in v:
                return False
            return bool(_FNAME.match(v)) or v.lower() in _BROWSER_FILES
        c = []
        for lst in info["lists"]:
            fl = [v for v in lst if is_file(v)]
            if len(fl) >= 2:
                c.extend(fl)
                break
        c.extend(v for v in vals if is_file(v))
        return _pick(c, "filename indicator", m)

    return None
