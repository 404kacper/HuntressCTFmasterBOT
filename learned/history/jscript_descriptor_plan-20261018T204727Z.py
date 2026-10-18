# learned-module: jscript_descriptor_plan
"""WSH JScript specimens whose inspect_* function eval()s a descriptor rebuilt by
recover_*(): decode the descriptor (steps/adapter/values/stageCount), classify the
ordered behaviour graph (role + ATT&CK), pull reconstructed indicators, and report
the syntactic style of the inspect function, the recover invocation and the
property accesses on the recovered descriptor variable."""
import base64
import binascii
import codecs
import collections
import hashlib
import itertools
import re
import urllib.parse as urlparse

from hunt.learn.kit import answer, data, target, text
from hunt.solvers import handler

_JS_EXTS = (".js", ".jse", ".wsf", ".jscript")
_STR = re.compile(r'"(?:[^"\\\r\n]|\\.)*"|\'(?:[^\'\\\r\n]|\\.)*\'', re.S)
_ESC = re.compile(r'\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|\r\n|.)', re.S)
_IDK = re.compile(r'[A-Za-z_$][\w$]*|\d+')
_NUM = re.compile(r'-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)')
_INT = r'(?:0[xX][0-9a-fA-F]+|\d+)'
_ID = r'[A-Za-z_$][\w$]*'
_KW = set("var let const function return if else for while do new this typeof in of null true "
          "false undefined break continue switch case default try catch finally throw delete "
          "void instanceof with eval String Math Array Object WScript ActiveXObject".split())
_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
           "\n": "", "\r\n": "", "\r": ""}
_CACHE = {}
_PROPS = ("steps", "adapter", "values", "stageCount")


# ---------------------------------------------------------------- lexing helpers
def _unesc(body):
    def rep(mo):
        e = mo.group(1)
        try:
            if e[0] == "u" and len(e) > 1:
                h = e[2:-1] if e[1] == "{" else e[1:]
                return chr(int(h, 16))
            if e[0] == "x" and len(e) == 3:
                return chr(int(e[1:], 16))
            if e[0] in "01234567":
                return chr(int(e, 8))
        except ValueError:
            return e
        return _SIMPLE.get(e, e)
    return _ESC.sub(rep, body)


def _skip_str(src, i):
    q = src[i]
    j = i + 1
    n = len(src)
    while j < n and src[j] != q:
        if src[j] == "\\":
            j += 1
        elif src[j] == "\n":
            break
        j += 1
    return j + 1


def _strip_comments(src):
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in "\"'":
            j = _skip_str(src, i)
            out.append(src[i:j])
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            if j < 0:
                break
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                break
            out.append(" ")
            i = j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match(src, i, opener, closer):
    depth = 0
    j = i
    n = len(src)
    while j < n:
        c = src[j]
        if c in "\"'":
            j = _skip_str(src, j)
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
        j += 1
    return src[i:]


def _block(src, start):
    i = src.find("{", start)
    return "" if i < 0 else _match(src, i, "{", "}")


def _stmt(src, start, limit=20000):
    depth = 0
    i = start
    n = min(len(src), start + limit)
    while i < n:
        c = src[i]
        if c in "\"'":
            i = _skip_str(src, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return src[start:i]
        elif c == ";" and depth == 0:
            return src[start:i]
        i += 1
    return src[start:n]


# ---------------------------------------------------------------- JS literal parser
def _ws(s, i):
    n = len(s)
    while i < n:
        if s[i].isspace():
            i += 1
        elif s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j < 0 else j
        elif s.startswith("/*", i):
            j = s.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            break
    return i


def _pstr(s, i):
    j = _skip_str(s, i)
    return _unesc(s[i + 1:j - 1]), j


def _pval(s, i, depth=0):
    if depth > 40:
        raise ValueError("deep")
    i = _ws(s, i)
    if i >= len(s):
        raise ValueError("eof")
    c = s[i]
    if c == "(":
        v, i = _pval(s, i + 1, depth + 1)
        i = _ws(s, i)
        if i < len(s) and s[i] == ")":
            i += 1
        return v, i
    if c == "{":
        obj = {}
        i += 1
        while True:
            i = _ws(s, i)
            if i >= len(s):
                raise ValueError("eof")
            if s[i] == "}":
                return obj, i + 1
            if s[i] in "\"'":
                k, i = _pstr(s, i)
            else:
                mo = _IDK.match(s, i)
                if not mo:
                    raise ValueError("key")
                k, i = mo.group(0), mo.end()
            i = _ws(s, i)
            if i >= len(s) or s[i] != ":":
                raise ValueError("colon")
            v, i = _pval(s, i + 1, depth + 1)
            obj[k] = v
            i = _ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "}":
                return obj, i + 1
            raise ValueError("obj")
    if c == "[":
        arr = []
        i += 1
        while True:
            i = _ws(s, i)
            if i >= len(s):
                raise ValueError("eof")
            if s[i] == "]":
                return arr, i + 1
            v, i = _pval(s, i, depth + 1)
            arr.append(v)
            i = _ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "]":
                return arr, i + 1
            raise ValueError("arr")
    if c in "\"'":
        v, i = _pstr(s, i)
        while True:
            j = _ws(s, i)
            if j < len(s) and s[j] == "+":
                k = _ws(s, j + 1)
                if k < len(s) and s[k] in "\"'":
                    w, i = _pstr(s, k)
                    v += w
                    continue
            return v, i
    mo = _NUM.match(s, i)
    if mo:
        t = mo.group(0)
        if "x" in t.lower():
            return int(t, 16), mo.end()
        try:
            return int(t), mo.end()
        except ValueError:
            return float(t), mo.end()
    mo = _IDK.match(s, i)
    if mo:
        w = mo.group(0)
        return {"true": True, "false": False, "null": None, "undefined": None}.get(w, w), mo.end()
    raise ValueError("value")


def _parse_desc(t):
    texts = [t]
    try:
        u = t.encode("latin-1").decode("utf-8")
        if u != t:
            texts.insert(0, u)
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    for s in texts:
        pos = s.find("steps")
        if pos < 0:
            continue
        tries = 0
        for mo in re.finditer(r"\{", s[:pos]):
            tries += 1
            if tries > 60:
                break
            try:
                v, _ = _pval(s, mo.start())
            except (ValueError, IndexError, RecursionError):
                continue
            if isinstance(v, dict) and "steps" in v:
                return v
    return None


# ---------------------------------------------------------------- decoders
def _printable(s):
    if not s:
        return False
    good = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    return good >= 0.9 * len(s)


def _bytewise(s):
    return all(ord(c) < 256 for c in s)


def _b64(s):
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", t):
        return None
    t = t.rstrip("=")
    t += "=" * (-len(t) % 4)
    for alt in (None, "-_"):
        try:
            if alt:
                raw = base64.urlsafe_b64decode(t)
            else:
                raw = base64.b64decode(t, validate=True)
            return raw.decode("latin-1")
        except (binascii.Error, ValueError):
            continue
    return None


def _hex(s):
    t = re.sub(r"[\s:]+", "", s)
    if len(t) < 8 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    try:
        return binascii.unhexlify(t).decode("latin-1")
    except (binascii.Error, ValueError):
        return None


def _tokens_to_chars(tokens, radix):
    try:
        vals = [int(t, radix) for t in tokens]
    except ValueError:
        return None
    if not vals or any(v < 0 or v >= 0x110000 for v in vals):
        return None
    return "".join(chr(v) for v in vals)


def _split_ints(s, radices):
    t = s.strip()
    if not re.fullmatch(r"[0-9A-Za-z]{1,6}(?:[^0-9A-Za-z]+[0-9A-Za-z]{1,6})+", t):
        return []
    tokens = re.split(r"[^0-9A-Za-z]+", t)
    out = []
    for r in radices:
        v = _tokens_to_chars(tokens, r)
        if v is not None:
            out.append(v)
    return out


def _apply_rep(s, rep):
    kind, a, b = rep
    try:
        if kind == "re":
            return a.sub(lambda mo: b, s)
        if kind == "srj":
            parts = list(s) if a == "" else s.split(a)
            return b.join(reversed(parts))
    except (re.error, ValueError):
        return None
    return None


def _plain_ops(s, reps, radices):
    """Key-free text decoders, applied to printable strings only."""
    out = [s[::-1]]
    for v in (_b64(s), _hex(s)):
        if v is not None:
            out.append(v)
    out.extend(_split_ints(s, radices))
    if re.search(r"[A-Za-z]", s):
        out.append(codecs.encode(s, "rot_13"))
    if "%" in s:
        v = re.sub(r"%u([0-9a-fA-F]{4})", lambda mo: chr(int(mo.group(1), 16)), s)
        out.append(urlparse.unquote(v, encoding="latin-1"))
    for rep in reps:
        v = _apply_rep(s, rep)
        if v is not None and v != s:
            out.append(v)
    return out


def _chained(bs, iv):
    a = []
    b = []
    c = []
    d = []
    pa = pb = pc = pd = iv & 0xFF
    for x in bs:
        y = x ^ pa
        a.append(chr(y))
        pa = x
        y = x ^ pb
        b.append(chr(y))
        pb = y
        y = (x - pc) & 0xFF
        c.append(chr(y))
        pc = x
        y = (x - pd) & 0xFF
        d.append(chr(y))
        pd = y
    return ["".join(a), "".join(b), "".join(c), "".join(d)]


def _keyed_ops(s, keys, skeys):
    """Key-dependent byte decoders (XOR/shift/feedback/repeating key)."""
    if not _bytewise(s):
        return []
    bs = [ord(c) for c in s]
    out = []
    for k in keys:
        kk = k & 0xFF
        out.append("".join(chr(x ^ kk) for x in bs))
        out.extend(_chained(bs, kk))
    for k in keys:
        kk = k & 0xFF
        out.append("".join(chr((x - kk) & 0xFF) for x in bs))
        out.append("".join(chr((x + kk) & 0xFF) for x in bs))
        out.append("".join(chr(x ^ ((kk + i) & 0xFF)) for i, x in enumerate(bs)))
        out.append("".join(chr((x - kk - i) & 0xFF) for i, x in enumerate(bs)))
        out.append("".join(chr(x ^ ((kk * i) & 0xFF)) for i, x in enumerate(bs)))
    out.extend(_chained(bs, 0))
    out.append("".join(chr(x ^ (i & 0xFF)) for i, x in enumerate(bs)))
    out.append("".join(chr((x - i) & 0xFF) for i, x in enumerate(bs)))
    out.append("".join(chr((x + i) & 0xFF) for i, x in enumerate(bs)))
    for sk in skeys:
        kb = [ord(c) & 0xFF for c in sk]
        n = len(kb)
        out.append("".join(chr(x ^ kb[i % n]) for i, x in enumerate(bs)))
        out.append("".join(chr((x - kb[i % n]) & 0xFF) for i, x in enumerate(bs)))
    return out


def _byteops(s):
    if not s or not _bytewise(s):
        return []
    bs = [ord(c) for c in s]
    out = ["".join(chr(255 - x) for x in bs),
           "".join(chr(((x << 4) | (x >> 4)) & 0xFF) for x in bs)]
    for r in range(1, 8):
        out.append("".join(chr(((x << r) | (x >> (8 - r))) & 0xFF) for x in bs))
    return out


def _ints(txt):
    return [int(x, 16) if x.lower().startswith("0x") else int(x)
            for x in re.findall(r"0[xX][0-9a-fA-F]+|\d+", txt)]


def _chars(arr):
    if arr and all(0 <= x < 0x110000 for x in arr):
        return "".join(chr(x) for x in arr)
    return None


# ---------------------------------------------------------------- search
def _material(chunk, src):
    lits = [(mo.start(), mo.end(), _unesc(mo.group(0)[1:-1])) for mo in _STR.finditer(chunk)]
    groups = []
    cur = []
    pe = 0
    for s, e, v in lits:
        if cur and re.fullmatch(r"[\s+,]*", chunk[pe:s]):
            cur.append(v)
        else:
            if cur:
                groups.append(cur)
            cur = [v]
        pe = e
    if cur:
        groups.append(cur)

    code = _STR.sub('""', chunk)  # code only: never harvest numbers from inside strings

    radices = [10]
    for mo in re.finditer(r"parseInt\s*\([^()]*?,\s*(\d+)\s*\)", code):
        r = int(mo.group(1))
        if 2 <= r <= 36 and r not in radices:
            radices.insert(0, r)
    if 16 not in radices:
        radices.append(16)

    nums = []
    for mo in re.finditer(r"\[\s*(" + _INT + r"(?:\s*,\s*" + _INT + r")+)\s*,?\s*\]", code):
        nums.append(_ints(mo.group(1)))
    for mo in re.finditer(r"fromCharCode\s*\(\s*(" + _INT + r"(?:\s*,\s*" + _INT + r")+)\s*\)", code):
        nums.append(_ints(mo.group(1)))
    for g in groups:
        if len(g) >= 2 and all(re.fullmatch(r"[0-9A-Za-z]{1,6}", x or "") for x in g):
            for r in radices:
                try:
                    nums.append([int(x, r) for x in g])
                    break
                except ValueError:
                    continue

    seeds = []
    named_arr = collections.OrderedDict()
    for mo in re.finditer(r"(" + _ID + r")\s*=\s*\[\s*(" + _INT + r"(?:\s*,\s*" + _INT + r")*)\s*,?\s*\]", code):
        named_arr[mo.group(1)] = _ints(mo.group(2))
    named_str = collections.OrderedDict()
    for mo in re.finditer(r"(" + _ID + r")\s*=\s*(\"(?:[^\"\\\r\n]|\\.)*\"|'(?:[^'\\\r\n]|\\.)*')\s*[;,\n]", chunk):
        named_str[mo.group(1)] = _unesc(mo.group(2)[1:-1])
    orders = []
    for mo in re.finditer(r"(" + _ID + r"|\[\s*\])\s*\.\s*concat\s*\(([^()]*)\)", code):
        head = mo.group(1)
        names = ([] if head.startswith("[") else [head]) + re.findall(_ID, mo.group(2))
        if names and all(n in named_arr for n in names):
            orders.append(names)
    keys_arr = list(named_arr.keys())
    if 2 <= len(keys_arr) <= 4:
        for p in itertools.permutations(keys_arr):
            orders.append(list(p))
    for names in orders:
        arr = []
        for n in names:
            arr.extend(named_arr[n])
        v = _chars(arr)
        if v:
            seeds.append(v)
    for mo in re.finditer(r"(" + _ID + r"(?:\s*\+\s*" + _ID + r")+)", code):
        names = re.findall(_ID, mo.group(1))
        if len(names) >= 2 and all(n in named_str for n in names):
            seeds.append("".join(named_str[n] for n in names))
    sk_str = list(named_str.keys())
    if 2 <= len(sk_str) <= 4:
        for p in itertools.permutations(sk_str):
            seeds.append("".join(named_str[n] for n in p))
    if len(nums) >= 2:
        allarr = []
        for arr in nums:
            allarr.extend(arr)
        v = _chars(allarr)
        if v:
            seeds.append(v)
    for arr in nums:
        if len(arr) >= 8:
            v = _chars(arr)
            if v:
                seeds.append(v)
    for g in sorted(groups, key=lambda g: -sum(len(x) for x in g)):
        seeds.append("".join(g))
        if len(g) > 1:
            seeds.append("".join(reversed(g)))
            n = len(g)
            for perm in nums:
                for base in (0, 1):
                    p = [x - base for x in perm]
                    if len(p) == n and sorted(p) == list(range(n)):
                        seeds.append("".join(g[i] for i in p))
                        inv = [""] * n
                        for pos, i in enumerate(p):
                            inv[i] = g[pos]
                        seeds.append("".join(inv))
    for g in groups:
        for v in g:
            if len(v) >= 16:
                seeds.append(v)
    seeds.append("".join(v for _, _, v in lits))

    keys = []
    for mo in re.finditer(r"(?<![=!<>])=\s*(" + _INT + r")\s*[;,\n)]", code):
        v = _ints(mo.group(1))[0]
        if 1 <= v <= 0xFF and v not in keys:
            keys.append(v)
    for mo in re.finditer(r"(?:\^|-|\+|%|&|\|)\s*(" + _INT + r")\b", code):
        v = _ints(mo.group(1))[0]
        if 1 <= v <= 0xFF and v not in keys:
            keys.append(v)
    keys = keys[:24]
    skeys = []
    for _, _, v in lits:
        if 2 <= len(v) <= 32 and _printable(v) and v not in skeys:
            skeys.append(v)
    for arr in nums:
        if 2 <= len(arr) <= 32 and all(0 < x < 256 for x in arr):
            k = "".join(chr(x) for x in arr)
            if k not in skeys:
                skeys.append(k)
    skeys = skeys[:12]

    reps = []
    for mo in re.finditer(r"\.replace\s*\(\s*/((?:[^/\\\n]|\\.)+)/([gimsuy]*)\s*,\s*([\"'])((?:[^\\]|\\.)*?)\3\s*\)", src):
        try:
            rx = re.compile(mo.group(1), re.I if "i" in mo.group(2) else 0)
        except re.error:
            continue
        reps.append(("re", rx, _unesc(mo.group(4))))
    for mo in re.finditer(r"\.split\s*\(\s*([\"'])((?:[^\\]|\\.)*?)\1\s*\)\s*(\.reverse\s*\(\s*\)\s*)?\.join\s*\(\s*([\"'])((?:[^\\]|\\.)*?)\4\s*\)", src):
        a = _unesc(mo.group(2))
        b = _unesc(mo.group(5))
        if mo.group(3):
            reps.append(("srj", a, b))
        elif a:
            reps.append(("re", re.compile(re.escape(a)), b))
    reps = reps[:8]

    uniq = []
    seen_seed = set()
    for s in seeds:
        if s and s not in seen_seed:
            seen_seed.add(s)
            uniq.append(s)
    return uniq[:200], keys, skeys, reps, radices


def _check(v, reps, radices):
    if "steps" in v:
        d = _parse_desc(v)
        if d is not None:
            return d
    if _printable(v):
        for w in _plain_ops(v, reps, radices):
            if "steps" in w:
                d = _parse_desc(w)
                if d is not None:
                    return d
    return None


def _search(chunk, src, deep):
    seeds, keys, skeys, reps, radices = _material(chunk, src)
    # pass 1: key-free text decoders
    pool = []
    seen = set()
    queue = collections.deque((s, 0) for s in seeds)
    b1 = 6000
    while queue:
        s, d = queue.popleft()
        if s in seen:
            continue
        seen.add(s)
        pool.append(s)
        if "steps" in s:
            desc = _parse_desc(s)
            if desc is not None:
                return desc
        if d >= 4 or b1 <= 0 or not _printable(s):
            continue
        for child in _plain_ops(s, reps, radices):
            b1 -= 1
            if child and child not in seen:
                queue.append((child, d + 1))
    if not deep:
        return None
    # pass 2: one keyed op and/or one byte op over byte-string candidates
    cands = [s for s in pool if 16 <= len(s) <= 20000 and _bytewise(s)]
    cands.sort(key=lambda s: (_printable(s), -len(s)))
    budget = 9000
    for c in cands[:12]:
        first = [(v, "k") for v in _keyed_ops(c, keys, skeys)] + [(v, "b") for v in _byteops(c)]
        for v, _kind in first:
            budget -= 1
            r = _check(v, reps, radices)
            if r is not None:
                return r
        if budget <= 0:
            break
        for v, kind in first:
            if budget <= 0:
                break
            if _printable(v):
                continue
            second = _byteops(v) if kind == "k" else _keyed_ops(v, keys, skeys)
            for w in second:
                budget -= 1
                r = _check(w, reps, radices)
                if r is not None:
                    return r
                if budget <= 0:
                    break
        if budget <= 0:
            break
    return None


# ---------------------------------------------------------------- structure
def _inspect_defs(src):
    out = []
    for mo in re.finditer(r"(?<![\w$])(inspect_[\w$]*)\s*=\s*function\b\s*([\w$]*)\s*\(", src):
        style = "named_expression" if mo.group(2) else "anonymous_expression"
        out.append((mo.start(), style, mo.group(1), _block(src, mo.end())))
    for mo in re.finditer(r"\bfunction\s+(inspect_[\w$]*)\s*\(", src):
        k = mo.start() - 1
        while k >= 0 and src[k].isspace():
            k -= 1
        prev = src[k] if k >= 0 else ";"
        before = src[max(0, k - 5):k + 1]
        if prev in "=(:,!?&|[+-~" or before.endswith("return"):
            style = "named_expression"
        else:
            style = "declaration"
        out.append((mo.start(), style, mo.group(1), _block(src, mo.end())))
    out.sort(key=lambda t: (0 if re.search(r"\beval\s*\(", t[3]) else 1, t[0]))
    return out


def _defs_of(src, name):
    out = []
    n = re.escape(name)
    for mo in re.finditer(f"\\bfunction\\s+{n}\\s*\\(", src):
        out.append(src[mo.start():mo.end()] + _block(src, mo.end()))
    for mo in re.finditer(f"(?<![\\w$.]){n}\\s*=(?!=)", src):
        st = _stmt(src, mo.end())
        if st.strip().startswith("function"):
            st = st + _block(src, mo.end())
        out.append(st)
    return out


def _scope(src, names):
    seen = set()
    parts = []
    frontier = list(names)
    for _level in range(3):
        nxt = []
        for nm in frontier:
            if nm in seen or nm in _KW:
                continue
            seen.add(nm)
            for t in _defs_of(src, nm):
                parts.append(t)
                idents = re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)", _STR.sub('""', t))
                nxt.extend(idents[:200])
        frontier = nxt
    return "\n".join(parts)


def _eval_args(body):
    out = []
    for mo in re.finditer(r"\beval\s*\(", body):
        out.append((mo.start(), _match(body, mo.end() - 1, "(", ")")))
    return out


def _invocation(body):
    evals = [a for _, a in _eval_args(body) if "recover_" in a]
    for scope in evals + [body]:
        if re.search(r"recover_[\w$]*\s*\.\s*apply\s*\(", scope) or \
                re.search(r"recover_[\w$]*\s*\[\s*[\"']apply[\"']\s*\]\s*\(", scope):
            return "apply"
        if re.search(r"recover_[\w$]*\s*\.\s*call\s*\(", scope) or \
                re.search(r"recover_[\w$]*\s*\[\s*[\"']call[\"']\s*\]\s*\(", scope):
            return "call"
        if re.search(r"recover_[\w$]*\s*\(", scope):
            return "direct"
    return None


def _property_style(body):
    var = None
    for mo in re.finditer(r"([A-Za-z_$][\w$]*)\s*=\s*eval\s*\(", body):
        arg = _match(body, mo.end() - 1, "(", ")")
        if "recover_" in arg:
            var = mo.group(1)
            break
    if var is None:
        return None, None
    v = re.escape(var)
    props = "|".join(_PROPS)
    dot = re.findall(f"(?<![\\w$.]){v}\\s*\\.\\s*({props})\\b", body)
    br = re.findall(f"(?<![\\w$.]){v}\\s*\\[\\s*([\"'])({props})\\1\\s*\\]", body)
    if dot and br:
        return "mixed", var
    if dot:
        return "dot", var
    if br:
        return "bracket_literal", var
    return None, var


def _compact(s):
    s = re.sub(r"\s+", " ", s)
    s = _STR.sub(lambda mo: mo.group(0) if len(mo.group(0)) <= 60 else mo.group(0)[:50] + "..." + mo.group(0)[-6:], s)
    s = re.sub(r"\[\s*(\d+\s*,\s*){12,}\d+\s*\]", lambda mo: mo.group(0)[:60] + "...]", s)
    return s


def _analyse(m):
    raw = data(m)
    if not raw:
        return None
    key = (m.path, hashlib.sha256(raw).hexdigest())
    if key in _CACHE:
        return _CACHE[key]
    src = _strip_comments(text(m) or "")
    res = {"style": None, "inv": None, "prop": None, "var": None, "desc": None, "scope": None}
    defs = _inspect_defs(src)
    body = defs[0][3] if defs else src
    if defs:
        res["style"] = defs[0][1]
    res["inv"] = _invocation(body)
    res["prop"], res["var"] = _property_style(body)
    names = sorted(set(re.findall(r"recover_[\w$]*", body))) or sorted(set(re.findall(r"recover_[\w$]*", src)))
    rec_scope = _scope(src, names) if names else ""
    if rec_scope:
        res["desc"] = _search(rec_scope, src, True)
        res["scope"] = "recover"
    if res["desc"] is None:
        res["desc"] = _search(src, src, not rec_scope)
        res["scope"] = "file"
    if res["desc"] is None:
        decs = []
        for mo in re.finditer(r"\bfunction\s+(decode_[\w$]*)\s*\(([^)]*)\)", src):
            decs.append(f"function {mo.group(1)}({mo.group(2)})" + _block(src, mo.end()))
        print(f"[jsdp FAIL] {m.basename} DECODERS: {_compact(' | '.join(decs))[:700]}")
        print(f"[jsdp FAIL] {m.basename} SCOPE: {_compact(rec_scope or src)[:700]}")
    else:
        print(f"[jsdp ok] {m.basename}: steps={res['desc'].get('steps')}")
    _CACHE[key] = res
    return res


# ---------------------------------------------------------------- semantics
def _steps(desc):
    st = desc.get("steps")
    if isinstance(st, str):
        st = [x for x in re.split(r"\s*(?:->|=>|>|\||,|;|\s)\s*", st) if x]
    if not isinstance(st, list):
        return []
    out = []
    for e in st:
        if isinstance(e, str):
            out.append(e)
        elif isinstance(e, dict):
            pick = None
            for k in ("op", "action", "step", "name", "kind", "type", "verb", "id"):
                if isinstance(e.get(k), str):
                    pick = e.get(k)
                    break
            if pick is None:
                for v in e.values():
                    if isinstance(v, str) and re.fullmatch(r"[a-z]+(?:_[a-z]+)+", v):
                        pick = v
                        break
            if pick:
                out.append(pick)
    return [x.strip().lower().replace("-", "_") for x in out if x and x.strip()]


def _role(steps):
    if not steps:
        return None
    last = steps[-1]
    has = set(steps)
    if last == "handoff_script":
        return "staged_chain"
    if last == "dispatch_next_stage":
        return "relay"
    if last in ("upload_remote", "transmit_remote"):
        return "uploader"
    if last == "write_recovery_note":
        return "impact"
    if last == "register_descriptor":
        return "persistence_descriptor"
    if last == "return_configuration":
        return "benign_utility"
    if last.startswith("dispatch") and ("memory" in last or "pipe" in last or "reflect" in last):
        return "stager"
    if last == "dispatch_process":
        if "acquire_remote" in has or "write_file" in has or any(s.startswith("profile") for s in steps):
            return "staged_chain"
        return "launcher"
    if last == "write_file":
        if "acquire_remote" in has:
            return "downloader"
        if "decode_embedded" in has:
            return "dropper"
    return None


def _attack(role, steps):
    if role in ("staged_chain", "relay") and steps and steps[-1] in ("handoff_script", "dispatch_next_stage"):
        alts = ["T1059", "T1105"] + (["none"] if role == "relay" else [])
        return "T1059.007", alts
    if role == "benign_utility":
        return "none", []
    if role == "uploader":
        return "T1041", []
    if role == "impact":
        return "T1486", []
    if role == "persistence_descriptor":
        return "T1053.005", ["T1053"]
    if role in ("launcher", "staged_chain"):
        return "T1059.007", ["T1059", "T1105"] if role == "staged_chain" else ["T1059"]
    if role == "stager":
        return "T1105", ["T1620"]
    if role == "downloader":
        return "T1105", []
    if role == "dropper":
        return "T1140", []
    return None, []


def _pairs(obj, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _pairs(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _pairs(v, key)
    elif isinstance(obj, str):
        yield key, obj


_RULES = {
    "campaign": (r"campaign|camp|cmp", r"(?i)campaign|^camp|^cmp"),
    "host": (r"host|machine|computer|workstation|device", r"(?i)host|^ws-|^desktop-|^wks|^lab-"),
    "url": (r"url|uri|endpoint|dest|remote|server|upload|target", r"^[A-Za-z][A-Za-z0-9+.-]*://"),
    "path": (r"path|dir|file|out|local|target|dest|drop", r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?:[A-Za-z]:[\\/]|%[^%]+%|\\\\|.*[\\/])"),
    "extension": (r"ext", r"^\.[A-Za-z0-9_-]{1,40}$"),
    "note": (r"note|ransom|readme|recover|message", r"(?i)(recover|readme|note|restore|decrypt|instruction).*\.[A-Za-z0-9]{1,5}$"),
}


def _uniq(xs):
    out = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def _resolve(desc, krx, vrx):
    pairs = list(_pairs({k: v for k, v in desc.items() if k != "steps"}))
    both = _uniq([v for k, v in pairs if re.search(krx, k, re.I) and re.search(vrx, v)])
    if both:
        return both[0], (0.95 if len(both) == 1 else 0.85), both[1:]
    vonly = _uniq([v for k, v in pairs if re.search(vrx, v)])
    if vonly:
        return vonly[0], (0.92 if len(vonly) == 1 else 0.8), vonly[1:]
    konly = _uniq([v for k, v in pairs if re.search(krx, k, re.I)])
    if konly:
        return konly[0], (0.85 if len(konly) == 1 else 0.75), konly[1:]
    return None, 0, []


def _field(q):
    mo = re.search(r"jscript-[a-z0-9]+-([a-z][a-z-]*)$", q.id or "")
    if mo:
        return mo.group(1)
    t = q.haystack
    if "declaration" in t and "named_expression" in t:
        return "function-style"
    if "direct, call, or apply" in t:
        return "invocation-style"
    if "bracket_literal" in t:
        return "property-style"
    if "behavior graph" in t and "classify" in t:
        return "role"
    if "mitre" in t:
        return "attack"
    for w, f in (("next-stage", "next-stage"), ("adapter", "adapter"), ("campaign", "campaign"),
                 ("host", "host"), ("url", "url"), ("destination", "url"), ("extension", "extension"),
                 ("note", "note"), ("path", "path")):
        if w in t:
            return f
    return None


@handler(lanes=("script-analysis",))
def jscript_descriptor_plan(q, ctx):
    m = target(q, ctx)
    if m is None:
        return None
    if not m.basename.lower().endswith(_JS_EXTS):
        return None
    field = _field(q)
    if field is None:
        return None
    try:
        res = _analyse(m)
    except Exception as exc:  # keep the bot alive; show why on the next round
        print(f"[jsdp] analysis failed for {m.path}: {exc!r}")
        return None
    if res is None:
        return None

    if field == "function-style":
        if res["style"]:
            return answer(res["style"], f"inspect_* function form in {m.path}", 0.95, subject=m)
        return None
    if field == "invocation-style":
        if res["inv"]:
            return answer(res["inv"], f"recover_* invocation inside eval() in {m.path}", 0.95, subject=m)
        return None
    if field == "property-style":
        if res["prop"]:
            return answer(res["prop"], f"accesses on eval'd variable {res['var']} in {m.path}", 0.95, subject=m)
        return None

    desc = res["desc"]
    if not desc:
        return None
    conf_scope = 0.95 if res["scope"] == "recover" else 0.92
    steps = _steps(desc)
    role = _role(steps)
    if field == "role":
        if role:
            return answer(role, f"decoded steps {steps} in {m.path}", conf_scope, subject=m)
        return None
    if field == "attack":
        tech, alts = _attack(role, steps)
        if tech:
            return answer(tech, f"role {role} from steps {steps} in {m.path}", conf_scope,
                          subject=m, alternatives=alts)
        return None
    if field == "adapter":
        ad = desc.get("adapter")
        if isinstance(ad, list):
            ad = next((x for x in ad if isinstance(x, str)), None)
        elif isinstance(ad, dict):
            ad = next((v for _, v in _pairs(ad)), None)
        if isinstance(ad, str) and ad.strip():
            return answer(ad.strip(), f"descriptor.adapter decoded from {m.path}", conf_scope, subject=m)
        v, c, alts = _resolve(desc, r"adapter|progid|object|lolbin|tool", r".")
        if v:
            return answer(v.strip(), f"adapter-like field in decoded descriptor of {m.path}", min(c, 0.85),
                          subject=m, alternatives=alts)
        return None
    if field == "next-stage":
        t = q.haystack
        if "powershell" in t:
            vrx = r"(?i)\.ps1$"
        elif "jscript" in t or "javascript" in t:
            vrx = r"(?i)\.(?:js|jse)$"
        else:
            vrx = r"(?i)\.(?:ps1|js|jse|vbs|wsf|bat|cmd|hta)$"
        v, c, alts = _resolve(desc, r"next|stage|script|handoff|child|file", vrx)
        if not v:
            return None
        base = re.split(r"[\\/]", v.strip())[-1]
        extra = [v.strip()] if base != v.strip() else []
        return answer(base, f"next-stage script name in decoded descriptor of {m.path}", min(c, conf_scope),
                      subject=m, alternatives=extra + alts)
    if field in _RULES:
        krx, vrx = _RULES[field]
        v, c, alts = _resolve(desc, krx, vrx)
        if not v or not v.strip():
            return None
        return answer(v.strip(), f"{field} field in decoded descriptor of {m.path}", min(c, conf_scope),
                      subject=m, alternatives=[a.strip() for a in alts if a.strip()])
    return None
