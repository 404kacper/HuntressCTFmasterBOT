# learned-module: jscript_descriptor_plan
"""WSH JScript triage fixtures: an inspect_* function eval()s the JSON text
returned by recover_*, which rebuilds it from packed material (numeric
arrays, Base64, separated decimal/hex, percent-encoding) via a decode_*
transform (reverse, single-byte or repeating-key XOR, add/sub).  The
descriptor holds steps/adapter/values/stageCount.  Answers role and ATT&CK
(from the ordered step graph per the stated rubric), descriptor fields
(adapter, campaign, url, path, next stage, extension, note, host, ...), and
the source-style questions (inspect function style, recover invocation
style, descriptor property-access style).  Everything is derived from the
bytes at run time; file names are never trusted."""
import base64
import binascii
import hashlib
import json
import re

from hunt.learn.kit import answer, data, target, text
from hunt.solvers import handler

_CACHE = {}
_STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
_ARR = re.compile(r"\[\s*(\d{1,5}(?:\s*,\s*\d{1,5})*)\s*,?\s*\]")
_ESC = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|.)", re.S)
_PROPS = "steps|adapter|values|stageCount"


def _unescape(body):
    def rep(mt):
        s = mt.group(1)
        if s[0] in "xu" and len(s) > 1:
            return chr(int(s[1:], 16))
        return {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(s, s)
    return _ESC.sub(rep, body)


def _block(src, i):
    j = src.find("{", i)
    if j < 0:
        return ""
    depth, k, n = 0, j, len(src)
    while k < n:
        c = src[k]
        if c in "\"'":
            qc = c
            k += 1
            while k < n and src[k] != qc:
                if src[k] == "\\":
                    k += 1
                k += 1
        elif c == "/" and src[k + 1:k + 2] == "/":
            nl = src.find("\n", k)
            k = n if nl < 0 else nl
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[j:k + 1]
        k += 1
    return src[j:]


def _funcs(src, prefix):
    out = []
    pat_decl = re.compile(r"\bfunction\s+(" + prefix + r"_[\w$]*)\s*\(")
    pat_expr = re.compile(r"\b(" + prefix + r"_[\w$]*)\s*=\s*function\b\s*([A-Za-z_$][\w$]*)?\s*\(")
    for mt in pat_expr.finditer(src):
        style = "named_expression" if mt.group(2) else "anonymous_expression"
        out.append((mt.start(), mt.group(1), style, _block(src, mt.end())))
    for mt in pat_decl.finditer(src):
        before = src[:mt.start()].rstrip()
        if before and before[-1] in "=(,:?!&|[":
            continue
        out.append((mt.start(), mt.group(1), "declaration", _block(src, mt.end())))
    out.sort(key=lambda x: x[0])
    return out


def _str_groups(src):
    groups, cur, last_end = [], [], None
    for mt in _STR.finditer(src):
        if cur and last_end is not None and re.fullmatch(r"\s*\+\s*", src[last_end:mt.start()]):
            cur.append(_unescape(mt.group(0)[1:-1]))
        else:
            if cur:
                groups.append("".join(cur))
            cur = [_unescape(mt.group(0)[1:-1])]
        last_end = mt.end()
    if cur:
        groups.append("".join(cur))
    return [g for g in groups if len(g) >= 16]


def _str_cands(s):
    out = []
    t = s.strip()
    if not t:
        return out
    if re.fullmatch(r"(?:%[0-9A-Fa-f]{2})+", t):
        out.append([int(t[i + 1:i + 3], 16) for i in range(0, len(t), 3)])
    mt = re.fullmatch(r"[0-9A-Fa-f]+([^0-9A-Za-z])[0-9A-Fa-f]+(?:\1[0-9A-Fa-f]+)*", t)
    if mt:
        parts = t.split(mt.group(1))
        if all(p.isdigit() for p in parts):
            out.append([int(p) for p in parts])
        out.append([int(p, 16) for p in parts])
    compact = re.sub(r"\s+", "", t)
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        pad = compact.replace("-", "+").replace("_", "/")
        pad = pad + "=" * (-len(pad) % 4)
        try:
            out.append(list(base64.b64decode(pad, validate=True)))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", compact):
        out.append(list(bytes.fromhex(compact)))
    out.append([ord(c) for c in t])
    return out


def _arrays(src):
    return [[int(x) for x in re.split(r"\s*,\s*", mt.group(1))] for mt in _ARR.finditer(src)]


def _parse(seq):
    if not seq or seq[0] != 0x7B:
        return None
    texts = []
    if all(0 <= x < 256 for x in seq):
        try:
            texts.append(bytes(seq).decode("utf-8"))
        except UnicodeDecodeError:
            pass
    try:
        texts.append("".join(chr(x) for x in seq))
    except (ValueError, OverflowError):
        pass
    for t in texts:
        try:
            obj = json.loads(t)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("steps"), list):
            return obj
    return None


def _attempts(b, keys):
    for seq in (b, b[::-1]):
        if not seq:
            continue
        yield seq
        k = seq[0] ^ 0x7B
        yield [x ^ k for x in seq]
        d = seq[0] - 0x7B
        yield [(x - d) & 255 for x in seq]
        for key in keys:
            yield [x ^ key[i % len(key)] for i, x in enumerate(seq)]
    for key in keys:
        x = [v ^ key[i % len(key)] for i, v in enumerate(b)]
        yield x[::-1]


def _decode(src):
    recs = _funcs(src, "recover")
    scopes = [r[3] for r in recs if r[3]] + [src]
    keys = []
    for a in _arrays(src):
        if 1 < len(a) <= 64 and all(0 <= x < 256 for x in a) and a not in keys:
            keys.append(a)
    for scope in scopes:
        bases = []
        big = [a for a in _arrays(scope) if len(a) >= 16]
        if big:
            cat = [x for a in big for x in a]
            bases.append(cat)
            bases.extend(big)
        for g in _str_groups(scope):
            bases.extend(_str_cands(g))
        for b in bases:
            if len(b) < 8:
                continue
            for seq in _attempts(b, keys):
                obj = _parse(seq)
                if obj is not None:
                    return obj
    return None


def _lang(src, m):
    head = src[:300].lower()
    if "vbscript" in head or (m.ext or "").lower() in (".vbs", ".vbe"):
        return "T1059.005"
    if "powershell" in head or (m.ext or "").lower() == ".ps1":
        return "T1059.001"
    return "T1059.007"


def _analyse(m):
    raw = data(m)
    if not raw:
        return None
    key = hashlib.sha1(raw).hexdigest()
    if key in _CACHE:
        return _CACHE[key]
    src = text(m) or ""
    info = None
    if "recover" in src or "inspect" in src or "eval" in src:
        desc = _decode(src)
        insp = None
        for f in _funcs(src, "inspect"):
            if "eval" in f[3]:
                insp = f
                break
        if insp is None:
            fs = _funcs(src, "inspect")
            insp = fs[0] if fs else None
        info = {"desc": desc, "inspect": insp, "lang": _lang(src, m), "src": src}
    _CACHE[key] = info
    return info


def _role(steps):
    s = [str(x).lower() for x in steps]
    while s:
        last = s[-1]
        if last in ("upload_remote", "transmit_remote"):
            return "uploader"
        if last == "handoff_script":
            return "staged_chain"
        if last == "dispatch_next_stage":
            return "relay"
        if last == "write_recovery_note":
            return "impact"
        if last == "register_descriptor":
            return "persistence_descriptor"
        if last == "return_configuration":
            return "benign_utility"
        if last.startswith("dispatch") and any(w in last for w in ("memory", "pipe", "reflect")):
            return "stager"
        if last == "dispatch_process":
            pre = s[:-1]
            if "write_file" in pre and any(x == "acquire_remote" or x.startswith("profile") for x in pre):
                return "staged_chain"
            return "launcher"
        if last == "write_file":
            for x in reversed(s[:-1]):
                if x == "acquire_remote":
                    return "downloader"
                if x == "decode_embedded":
                    return "dropper"
            return None
        s = s[:-1]
    return None


def _attack(role, steps, lang):
    s = [str(x).lower() for x in steps]
    acq = ["T1105"] if "acquire_remote" in s else []
    if role in ("staged_chain", "launcher"):
        return lang, ["T1059"] + acq
    if role == "relay":
        return lang, ["T1059"] + acq + ["none"]
    table = {
        "benign_utility": ("none", []),
        "stager": ("T1105", ["T1620"]),
        "downloader": ("T1105", []),
        "dropper": ("T1140", []),
        "uploader": ("T1041", []),
        "persistence_descriptor": ("T1053.005", ["T1053"]),
        "impact": ("T1486", []),
    }
    return table.get(role, (None, []))


def _flat(d):
    out = []
    for k, v in d.items():
        if isinstance(v, dict):
            out.extend(_flat(v))
        else:
            out.append((str(k), v))
    return out


def _concept(t):
    if "adapter" in t or "lolbin" in t:
        return "adapter"
    if "campaign" in t:
        return "campaign"
    if "host" in t and "identifier" in t:
        return "host"
    if "next-stage" in t or "next stage" in t:
        return "next"
    if "extension" in t:
        return "extension"
    if "note" in t:
        return "note"
    if "user-agent" in t or "user agent" in t:
        return "agent"
    if "registry" in t:
        return "registry"
    if "mutex" in t:
        return "mutex"
    if "url" in t or "destination" in t or "uri" in t or "endpoint" in t:
        return "url"
    if "path" in t:
        return "path"
    return None


_KEYS = {
    "campaign": ("campaign",), "host": ("host",), "next": ("next",),
    "extension": ("extension", "ext"), "note": ("note",), "agent": ("agent",),
    "registry": ("registry",), "mutex": ("mutex",),
    "url": ("url", "uri", "destination", "endpoint", "upload"),
}


def _pick(concept, desc, t):
    pairs = [(k, v) for k, v in _flat(desc) if k not in ("steps", "stageCount")]
    if concept == "adapter":
        if desc.get("adapter") not in (None, ""):
            return "adapter", desc["adapter"]
        for k, v in pairs:
            if "adapter" in k.lower() or "lolbin" in k.lower():
                return k, v
        return None
    if concept == "path":
        cands = [(k, v) for k, v in pairs if "path" in k.lower() and "registry" not in k.lower()]
        for k, v in cands:
            kl = k.lower()
            if any(w in t and w in kl for w in ("output", "local", "target", "file")):
                return k, v
        return cands[0] if cands else None
    for k, v in pairs:
        if any(w in k.lower() for w in _KEYS.get(concept, ())):
            return k, v
    shape = {"url": lambda v: v.lower().startswith(("http://", "https://")),
             "extension": lambda v: v.startswith(".") and "\\" not in v,
             "next": lambda v: re.search(r"\.(js|ps1|vbs|jse|wsf|hta|bat|cmd)$", v, re.I) is not None}
    f = shape.get(concept)
    if f:
        for k, v in pairs:
            if isinstance(v, str) and f(v):
                return k, v
    return None


def _style_answer(kind, info, m):
    insp = info["inspect"]
    if insp is None:
        return None
    name, fstyle, body = insp[1], insp[2], insp[3]
    if kind == "fstyle":
        return answer(fstyle, f"{name} in {m.path} is emitted as {fstyle}", 0.93, subject=m)
    if kind == "istyle":
        mt = re.search(r"\brecover_[\w$]*\s*(?:\.\s*(call|apply)\s*)?\(", body)
        if not mt:
            mt = re.search(r"\brecover_[\w$]*\s*\[\s*[\"'](call|apply)[\"']\s*\]\s*\(", body)
        if not mt:
            return None
        style = mt.group(1) or "direct"
        return answer(style, f"{name} invokes {mt.group(0).strip()} in {m.path}", 0.93, subject=m)
    mv = re.search(r"\b(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*eval\s*\(\s*[^;]*recover_", body)
    if not mv:
        return None
    v = re.escape(mv.group(1))
    dot = re.findall(r"(?<![\w$.])" + v + r"\s*\.\s*(?:" + _PROPS + r")\b", body)
    br = re.findall(r"(?<![\w$.])" + v + r"\s*\[\s*([\"'])(?:" + _PROPS + r")\1\s*\]", body)
    if not dot and not br:
        return None
    style = "mixed" if dot and br else ("dot" if dot else "bracket_literal")
    return answer(style, f"{mv.group(1)} in {name}: {len(dot)} dot / {len(br)} bracket accesses ({m.path})",
                  0.93, subject=m)


@handler(lanes=("script-analysis",))
def jscript_descriptor_plan(q, ctx):
    pid = re.sub(r"^set\d+\.", "", q.id or "").lower()
    t = (q.text or "").lower()
    kind = None
    for suf, k in (("-function-style", "fstyle"), ("-invocation-style", "istyle"),
                   ("-property-style", "pstyle"), ("-role", "role"), ("-attack", "attack")):
        if pid.endswith(suf):
            kind = k
            break
    if kind is None:
        if "inspect function" in t and "declaration" in t:
            kind = "fstyle"
        elif "direct, call, or apply" in t:
            kind = "istyle"
        elif "bracket_literal" in t or ("dot" in t and "eval(recover" in t):
            kind = "pstyle"
        elif "terminal intent" in t or "behavior graph" in t and "classify" in t:
            kind = "role"
        elif "att&ck" in t:
            kind = "attack"
        else:
            kind = _concept(t)
    if kind is None:
        return None
    m = target(q, ctx)
    if m is None:
        return None
    info = _analyse(m)
    if not info:
        return None
    if kind in ("fstyle", "istyle", "pstyle"):
        return _style_answer(kind, info, m)
    desc = info["desc"]
    if not desc:
        return None
    steps = desc.get("steps") or []
    if kind == "role":
        role = _role(steps)
        if not role:
            return None
        return answer(role, f"decoded steps {steps} in {m.path}", 0.93, subject=m)
    if kind == "attack":
        role = _role(steps)
        tid, alts = _attack(role, steps, info["lang"])
        if not tid:
            return None
        return answer(tid, f"{role} graph {steps} in {m.path}", 0.92, subject=m,
                      alternatives=[a for a in alts if a != tid])
    got = _pick(kind, desc, t)
    if not got:
        return None
    k, v = got
    alts = []
    if isinstance(v, list):
        vals = [str(x) for x in v if str(x).strip()]
        if not vals:
            return None
        v, alts = vals[0], vals[1:]
    if isinstance(v, bool) or v is None:
        return None
    v = str(v).strip()
    if not v or "\n" in v:
        return None
    if "\\" in v:
        alts.append(v.replace("\\", "\\\\"))
    return answer(v, f"decoded recover_* descriptor of {m.path}: {k}", 0.95, subject=m,
                  alternatives=alts)
