# learned-module: elf_function_return_constant
"""Recover the constant returned by a function in an ELF (x86/x86-64 and
AArch64). The question names a function (e.g. "constant returned by
recover_code"); when the binary has no such symbol (variants rename the
designated analysis function) fall back to the binary's designated
non-runtime global function and decode the immediate it leaves in the
return register."""
import re
import struct

from hunt.learn.kit import answer, data, files, target
from hunt.solvers import handler

_STD = {
    "main", "deregister_tm_clones", "register_tm_clones", "frame_dummy",
    "completed.0", "data_start",
}
_FN_RE = re.compile(r"return(?:ed|s)?\s+by\s+(?:the\s+)?(?:function\s+)?`?([A-Za-z_][A-Za-z0-9_]*)")


def _cstr(blob, off):
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("latin-1")


def _parse(raw):
    if not raw or len(raw) < 52 or raw[:4] != b"\x7fELF":
        return None
    cls = raw[4]
    if cls not in (1, 2) or raw[5] not in (1, 2):
        return None
    e = "<" if raw[5] == 1 else ">"
    try:
        if cls == 2:
            t = struct.unpack_from(e + "HHIQQQIHHHHHH", raw, 16)
        else:
            t = struct.unpack_from(e + "HHIIIIIHHHHHH", raw, 16)
    except struct.error:
        return None
    mach, shoff, shes, shn, shstr = t[1], t[5], t[10], t[11], t[12]
    secs = []
    if shoff and shn and shes:
        for i in range(shn):
            try:
                if cls == 2:
                    s = struct.unpack_from(e + "IIQQQQIIQQ", raw, shoff + i * shes)
                else:
                    s = struct.unpack_from(e + "IIIIIIIIII", raw, shoff + i * shes)
            except struct.error:
                break
            secs.append({"no": s[0], "type": s[1], "addr": s[3], "offset": s[4],
                         "size": s[5], "link": s[6], "entsize": s[9], "name": ""})
        if 0 <= shstr < len(secs):
            st = secs[shstr]
            tab = raw[st["offset"]:st["offset"] + st["size"]]
            for s in secs:
                s["name"] = _cstr(tab, s["no"])
    syms = []
    for s in secs:
        if s["type"] not in (2, 11) or not (0 <= s["link"] < len(secs)):
            continue
        strs = secs[s["link"]]
        stab = raw[strs["offset"]:strs["offset"] + strs["size"]]
        esz = s["entsize"] or (24 if cls == 2 else 16)
        for i in range(s["size"] // esz if esz else 0):
            off = s["offset"] + i * esz
            try:
                if cls == 2:
                    nm, info, _o, shndx, val, size = struct.unpack_from(e + "IBBHQQ", raw, off)
                else:
                    nm, val, size, info, _o, shndx = struct.unpack_from(e + "IIIBBH", raw, off)
            except struct.error:
                break
            name = _cstr(stab, nm)
            if name:
                syms.append({"name": name, "value": val, "size": size, "bind": info >> 4,
                             "stype": info & 0xF, "shndx": shndx,
                             "dyn": s["type"] == 11})
    return {"cls": cls, "e": e, "machine": mach, "secs": secs, "syms": syms, "raw": raw}


def _v2o(elf, va):
    for s in elf["secs"]:
        if s["type"] == 8 or not s["addr"]:
            continue
        if s["addr"] <= va < s["addr"] + s["size"]:
            return s["offset"] + (va - s["addr"])
    return None


def _x86(code):
    vals = []
    locs = {}
    i, n = 0, len(code)
    while i < n:
        c = code[i:i + 4]
        b = code[i]
        if c in (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb"):
            i += 4
            continue
        if b == 0xC3 or code[i:i + 2] == b"\xf3\xc3":
            break
        if b == 0xB8 and i + 5 <= n:
            vals.append(struct.unpack_from("<i", code, i + 1)[0])
            i += 5
            continue
        if code[i:i + 3] == b"\x48\xc7\xc0" and i + 7 <= n:
            vals.append(struct.unpack_from("<i", code, i + 3)[0])
            i += 7
            continue
        if code[i:i + 2] == b"\x48\xb8" and i + 10 <= n:
            v = struct.unpack_from("<Q", code, i + 2)[0]
            vals.append(v - (1 << 64) if v >= 1 << 63 else v)
            i += 10
            continue
        if code[i:i + 2] in (b"\x31\xc0", b"\x33\xc0"):
            vals.append(0)
            i += 2
            continue
        if code[i:i + 3] == b"\x83\xc8\xff":
            vals.append(-1)
            i += 3
            continue
        if code[i:i + 2] == b"\xc7\x45" and i + 7 <= n:
            locs[("bp", code[i + 2])] = struct.unpack_from("<i", code, i + 3)[0]
            i += 7
            continue
        if code[i:i + 3] == b"\xc7\x44\x24" and i + 8 <= n:
            locs[("sp", code[i + 3])] = struct.unpack_from("<i", code, i + 4)[0]
            i += 8
            continue
        if code[i:i + 2] == b"\x8b\x45" and i + 3 <= n:
            k = ("bp", code[i + 2])
            if k in locs:
                vals.append(locs[k])
            i += 3
            continue
        if code[i:i + 3] == b"\x8b\x44\x24" and i + 4 <= n:
            k = ("sp", code[i + 3])
            if k in locs:
                vals.append(locs[k])
            i += 4
            continue
        if b in (0x55, 0x5D, 0xC9, 0x90):
            i += 1
            continue
        if code[i:i + 3] == b"\x48\x89\xe5":
            i += 3
            continue
        i += 1
    return vals[-1] if vals else None


def _a64(code, e):
    val = None
    for i in range(0, len(code) - 3, 4):
        w = struct.unpack_from(e + "I", code, i)[0]
        if w == 0xD65F03C0:
            break
        if w & 0x1F:
            continue
        imm = (w >> 5) & 0xFFFF
        hw = (w >> 21) & 3
        top = w & 0x7F800000
        if top == 0x52800000:
            val = imm << (16 * hw)
        elif top == 0x12800000:
            val = ~(imm << (16 * hw))
        elif top == 0x72800000 and val is not None:
            mask = 0xFFFF << (16 * hw)
            val = (val & ~mask) | (imm << (16 * hw))
        elif w in (0x2A1F03E0, 0xAA1F03E0):
            val = 0
    if val is not None and val >= 0:
        val &= 0xFFFFFFFF
        if val & 0x80000000:
            val -= 1 << 32
    return val


def _func_const(elf, sym):
    va = sym["value"]
    off = _v2o(elf, va)
    if off is None:
        return None
    size = sym["size"]
    if not size:
        nxt = [s["value"] for s in elf["syms"] if s["value"] > va]
        size = min(min(nxt) - va, 512) if nxt else 256
    code = elf["raw"][off:off + size]
    if elf["machine"] in (62, 3):
        return _x86(code)
    if elf["machine"] == 183:
        return _a64(code, elf["e"])
    return None


def _defined_funcs(elf, name=None):
    out = []
    for s in elf["syms"]:
        if s["shndx"] == 0 or s["stype"] not in (0, 2):
            continue
        if name is not None:
            if s["name"] == name:
                out.append(s)
            continue
        n = s["name"]
        if (s["stype"] == 2 and s["bind"] in (1, 2) and not n.startswith("_")
                and n not in _STD and "@" not in n and "." not in n):
            out.append(s)
    return out


def _pick(q, ctx):
    m = target(q, ctx)
    pool = []
    if m is not None:
        pool = [m] + list(files(ctx, m))
    if not pool:
        pool = list(files(ctx))
    cands = []
    seen = set()
    for mem in pool:
        if mem.path in seen:
            continue
        seen.add(mem.path)
        raw = data(mem)
        elf = _parse(raw) if raw else None
        if elf is not None:
            cands.append((mem, elf))
    if not cands:
        return None, None, 0
    hunt = [c for c in cands if any(s["name"] == ".huntress" for s in c[1]["secs"])]
    use = hunt if len(hunt) == 1 else cands
    return use[-1][0], use[-1][1], len(use)


def _fmt(v, mem, why, conf):
    alts = [f"0x{v:x}"] if v >= 0 else [f"0x{v & 0xFFFFFFFF:x}"]
    return answer(str(v), f"{why} in {mem.path}", conf, subject=mem, alternatives=alts)


@handler(lanes=("binary-reverse-engineering",))
def elf_return_constant(q, ctx):
    hay = q.haystack
    if not ((q.id or "").lower() == "recover_code"
            or ("return" in hay and ("constant" in hay or "value" in hay))):
        return None
    mem, elf, ncand = _pick(q, ctx)
    if elf is None:
        return None
    base = 0.95 if ncand == 1 else 0.8
    mm = _FN_RE.search(q.text or "")
    fname = mm.group(1) if mm else None

    if fname:
        named = _defined_funcs(elf, fname)
        named.sort(key=lambda s: s["stype"] != 2)
        for s in named:
            v = _func_const(elf, s)
            if v is not None:
                return _fmt(v, mem, f"immediate returned by {fname}", base)
        if named:
            return None

    # Named function absent: variants rename the designated analysis function.
    funcs = _defined_funcs(elf)
    names = []
    for s in sorted(funcs, key=lambda s: not s["dyn"]):
        if s["name"] not in names:
            names.append(s["name"])
    results = []
    for n in names:
        s = next(x for x in funcs if x["name"] == n)
        v = _func_const(elf, s)
        if v is not None:
            results.append((n, v))
    if len(results) == 1 or (results and len(names) == 1):
        n, v = results[0]
        return _fmt(v, mem, f"{fname or 'named function'} absent; immediate returned by "
                            f"designated function {n}", min(base, 0.9))
    if results:
        n, v = results[0]
        return _fmt(v, mem, f"immediate returned by first candidate function {n} (ambiguous)", 0.7)
    print(f"no return constant found; candidate funcs={names}")
    return answer("none", f"no function returning a constant in {mem.path}", 0.6, subject=mem)
