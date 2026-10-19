# learned-module: cpp_c_specimen_config_facts
"""Day-2 style RE evidence sets holding a C specimen and a C++ specimen
(ELF or PE). Answers per-specimen fields (c_*/cpp_*: sha256, marker,
has_symtab, recover_code, machine, format, xor_key, config_crc32) and the
C++ facts (vtable/typeinfo presence, mangled symbols) plus indicators
(campaign, domain, url, mutex) from the single-byte-XOR'd JSON config blob.
Everything is derived from the bytes; the C++ specimen is identified by
content (libstdc++ / Itanium or MSVC mangling), not by file name.

Mangled-symbol questions read the real symbol tables (ELF .symtab/.dynsym,
PE COFF symbol table and export table) plus ASCII/UTF-16 strings, keep GCC
clone suffixes (.constprop.0, .isra.0), recognise MSVC member decorations
(?m@Class@@...), rank symbol-table definitions first and skip spellings the
Game Master already refused. Unproven spellings are only offered at low
confidence."""
import json
import re
import struct
import urllib.parse as urlparse
import zlib

from hunt.forensics.identity import digest
from hunt.learn.kit import answer, data, files, target
from hunt.solvers import handler

_TABLES = [bytes(i ^ k for i in range(256)) for k in range(256)]
_DEC = json.JSONDecoder()
_CACHE = {}

_MACH = {
    62: ["x86-64", "x86_64", "Advanced Micro Devices X86-64", "AMD x86-64", "EM_X86_64", "amd64"],
    3: ["x86", "Intel 80386", "i386", "EM_386"],
    183: ["AArch64", "aarch64", "EM_AARCH64", "arm64"],
    40: ["ARM", "EM_ARM", "arm"],
    243: ["RISC-V", "EM_RISCV", "riscv"],
    8: ["MIPS", "EM_MIPS"],
}
_PEMACH = {
    0x8664: ["x86-64", "AMD64", "x64", "IMAGE_FILE_MACHINE_AMD64"],
    0x14C: ["x86", "i386", "IMAGE_FILE_MACHINE_I386"],
    0xAA64: ["AArch64", "ARM64", "IMAGE_FILE_MACHINE_ARM64"],
}
_STD = {"main", "deregister_tm_clones", "register_tm_clones", "frame_dummy",
        "completed.0", "data_start"}
_CPP_FIELDS = {"has_cpp_vtable", "has_cpp_typeinfo", "vtable_symbol", "format",
               "xor_key", "config_crc32"}
_CFG_FIELDS = {"campaign", "domain", "url", "mutex"}

_ITA = re.compile(rb"_Z[A-Za-z0-9_]{3,}(?:\.[A-Za-z0-9_]+)*")
_MSV = re.compile(rb"\?\??[A-Za-z0-9_$][A-Za-z0-9_@?$]{2,}")
_U16 = re.compile(rb"(?:[\x21-\x7e]\x00){6,}")
_BUILTIN = {
    "v": ("void", "X"), "b": ("bool", "_N"), "c": ("char", "D"), "a": ("signed char", "C"),
    "h": ("unsigned char", "E"), "s": ("short", "F"), "t": ("unsigned short", "G"),
    "i": ("int", "H"), "j": ("unsigned int", "I"), "l": ("long", "J"),
    "m": ("unsigned long", "K"), "x": ("long long", "_J"), "y": ("unsigned long long", "_K"),
    "f": ("float", "M"), "d": ("double", "N"), "w": ("wchar_t", "_W"),
}


def _cstr(blob, off):
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("latin-1")


def _elf(raw):
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
                             "stype": info & 0xF, "shndx": shndx, "dyn": s["type"] == 11})
    return {"cls": cls, "e": e, "machine": mach, "secs": secs, "syms": syms, "raw": raw}


def _rva2off(pe, rva):
    for s in pe["secs"]:
        span = max(s["vsize"], s["rsize"])
        if s["va"] <= rva < s["va"] + span:
            d = rva - s["va"]
            if d < s["rsize"]:
                return s["rptr"] + d
            return None
    return None


def _coff(raw, symptr, nsyms):
    out = []
    if not symptr or not nsyms or nsyms > 500000 or symptr + nsyms * 18 > len(raw):
        return out
    strbase = symptr + nsyms * 18
    i = 0
    while i < nsyms:
        off = symptr + i * 18
        try:
            val, secn, typ, scl, naux = struct.unpack_from("<IhHBB", raw, off + 8)
        except struct.error:
            break
        if raw[off:off + 4] == b"\x00\x00\x00\x00":
            so = struct.unpack_from("<I", raw, off + 4)[0]
            name = _cstr(raw, strbase + so) if so >= 4 else ""
        else:
            name = raw[off:off + 8].split(b"\x00", 1)[0].decode("latin-1")
        if name:
            out.append({"name": name, "value": val, "secn": secn, "type": typ, "scl": scl})
        i += 1 + naux
    return out


def _pe_exports(raw, pe, opt, optsz, magic):
    if magic == 0x20B:
        dd = opt + 112
    elif magic == 0x10B:
        dd = opt + 96
    else:
        return []
    if dd + 8 > opt + optsz:
        return []
    out = []
    try:
        rva, size = struct.unpack_from("<II", raw, dd)
        if not rva or not size:
            return []
        off = _rva2off(pe, rva)
        if off is None:
            return []
        nnames, _afun, anames = struct.unpack_from("<III", raw, off + 24)
        noff = _rva2off(pe, anames)
        if noff is None:
            return []
        for i in range(min(nnames, 20000)):
            nrva = struct.unpack_from("<I", raw, noff + 4 * i)[0]
            so = _rva2off(pe, nrva)
            if so is not None:
                s = _cstr(raw, so)
                if s:
                    out.append(s)
    except struct.error:
        return out
    return out


def _pe(raw):
    if not raw or len(raw) < 0x40 or raw[:2] != b"MZ":
        return None
    try:
        lfa = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[lfa:lfa + 4] != b"PE\x00\x00":
            return None
        mach, nsec, _ts, symptr, nsyms, optsz = struct.unpack_from("<HHIIIH", raw, lfa + 4)
        opt = lfa + 24
        magic = struct.unpack_from("<H", raw, opt)[0] if optsz else 0
    except struct.error:
        return None
    pe = {"machine": mach, "symptr": symptr, "nsyms": nsyms, "magic": magic,
          "secs": [], "coff": [], "exports": []}
    strbase = symptr + nsyms * 18 if (symptr and nsyms) else None
    base = opt + optsz
    for i in range(min(nsec, 96)):
        o = base + i * 40
        try:
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", raw, o + 8)
        except struct.error:
            break
        nm = raw[o:o + 8].split(b"\x00", 1)[0].decode("latin-1")
        if nm.startswith("/") and nm[1:].isdigit() and strbase is not None:
            nm = _cstr(raw, strbase + int(nm[1:])) or nm
        pe["secs"].append({"name": nm, "va": va, "vsize": vsize, "rsize": rsize, "rptr": rptr})
    pe["coff"] = _coff(raw, symptr, nsyms)
    pe["exports"] = _pe_exports(raw, pe, opt, optsz, magic)
    return pe


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
        b = code[i]
        if code[i:i + 4] in (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb"):
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


def _json_at(dec):
    s = dec.decode("latin-1")
    i = s.find("{")
    if i < 0 or i > 4:
        return None
    try:
        obj, end = _DEC.raw_decode(s, i)
    except ValueError:
        return None
    if not isinstance(obj, dict) or len(obj) < 2:
        return None
    try:
        obj = json.loads(dec[i:end].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        pass
    return obj, i, end


def _find_config(elf, raw):
    hits = []
    if elf is not None:
        for s in elf["syms"]:
            if "config" not in s["name"].lower() or s["size"] < 4 or s["shndx"] == 0:
                continue
            off = _v2o(elf, s["value"])
            if off is None:
                continue
            blob = raw[off:off + s["size"]]
            for k in range(1, 256):
                r = _json_at(blob.translate(_TABLES[k]))
                if r:
                    obj, i, end = r
                    hits.append({"key": k, "obj": obj, "enc": blob[i:end],
                                 "plain": blob[i:end].translate(_TABLES[k]),
                                 "full_enc": blob, "sym": s["name"]})
                    break
    if hits:
        return hits[0]
    best = None
    for k in range(1, 256):
        t = _TABLES[k]
        needle = b'{"'.translate(t)
        pos = raw.find(needle)
        count = 0
        while pos >= 0 and count < 40:
            count += 1
            seg = raw[pos:pos + 16384].translate(t)
            r = _json_at(seg)
            if r:
                obj, i, end = r
                cand = {"key": k, "obj": obj, "enc": raw[pos + i:pos + end],
                        "plain": seg[i:end], "full_enc": None, "sym": None}
                if best is None or len(obj) > len(best["obj"]):
                    best = cand
                break
            pos = raw.find(needle, pos + 1)
    return best


def _is_cpp(raw):
    if b"libstdc++" in raw or b".?AV" in raw or b"msvcp" in raw.lower():
        return True
    return re.search(rb"_Z(?:N\d|T[VIS]|L\d|Zd|dl)", raw) is not None


def _spec_info(m):
    raw = data(m)
    if not raw:
        return None
    key = digest("sha256", raw)
    if key in _CACHE:
        return _CACHE[key]
    elf = _elf(raw)
    pe = _pe(raw) if elf is None else None
    if elf is None and pe is None:
        _CACHE[key] = None
        return None
    info = {"m": m, "raw": raw, "sha": key, "elf": elf, "pe": pe,
            "cpp": _is_cpp(raw), "cfg": None, "cfg_done": False,
            "names": None, "sets": None}
    _CACHE[key] = info
    return info


def _config(info):
    if not info["cfg_done"]:
        info["cfg"] = _find_config(info["elf"], info["raw"])
        info["cfg_done"] = True
    return info["cfg"]


def _specimens(q, ctx):
    root = target(q, ctx)
    pool = []
    if root is not None:
        pool.append(root)
        pool.extend(files(ctx, root))
    if not pool:
        pool = list(files(ctx))
    out, seen = [], set()
    for m in pool:
        if m.path in seen:
            continue
        seen.add(m.path)
        info = _spec_info(m)
        if info is not None and info["sha"] not in [o["sha"] for o in out]:
            out.append(info)
    return out


def _choose(specs, want_cpp):
    group = [s for s in specs if s["cpp"] == want_cpp]
    if not group:
        return None, 0
    if len(group) == 1:
        return group[0], 1
    hint = ("cpp", "cxx", "++") if want_cpp else ("-c.", "_c.", ".c")
    named = [s for s in group if any(h in (s["m"].basename or "").lower() for h in hint)]
    if len(named) == 1:
        return named[0], 1
    return group[0], len(group)


def _refused(q):
    r = q.raw.get("refused_by_game_master") if isinstance(q.raw, dict) else None
    return [str(x) for x in (r or [])]


def _multi(q, opts, why, conf, mem):
    bad = _refused(q)
    seen = []
    for o in opts:
        if o and o not in seen and o not in bad:
            seen.append(o)
    if not seen:
        return None
    return answer(seen[0], why, conf, subject=mem, alternatives=seen[1:])


def _lookup(obj, f):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == f and isinstance(v, (str, int, float)) and not isinstance(v, bool):
                return v
        for v in obj.values():
            r = _lookup(v, f)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _lookup(v, f)
            if r is not None:
                return r
    return None


def _values(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            _values(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _values(v, out)
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _all_names(info):
    if info.get("names") is not None:
        return info["names"]
    names = []
    if info["elf"] is not None:
        for s in info["elf"]["syms"]:
            names.append(s["name"])
    if info["pe"] is not None:
        for s in info["pe"]["coff"]:
            names.append(s["name"])
        names.extend(info["pe"]["exports"])
    raw = info["raw"]
    blobs = [raw]
    for mm in _U16.finditer(raw):
        try:
            blobs.append(mm.group(0).decode("utf-16le").encode("latin-1"))
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
    for blob in blobs:
        for mm in _ITA.finditer(blob):
            names.append(mm.group(0).decode("latin-1"))
        for mm in _MSV.finditer(blob):
            n = mm.group(0).decode("latin-1")
            if "@@" in n or n.startswith("??_7"):
                names.append(n)
    out, seen = [], set()
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    info["names"] = out
    return out


def _symsets(info):
    if info.get("sets") is None:
        fn, df, und = set(), set(), set()
        if info["elf"] is not None:
            for s in info["elf"]["syms"]:
                if s["shndx"] == 0:
                    und.add(s["name"])
                else:
                    df.add(s["name"])
                    if s["stype"] == 2:
                        fn.add(s["name"])
        if info["pe"] is not None:
            for s in info["pe"]["coff"]:
                if s["secn"] > 0:
                    df.add(s["name"])
                    if (s["type"] >> 4) == 2:
                        fn.add(s["name"])
                elif s["secn"] == 0:
                    und.add(s["name"])
            for n in info["pe"]["exports"]:
                df.add(n)
        info["sets"] = (fn, df, und)
    return info["sets"]


def _defined(info, name):
    return name in _symsets(info)[1]


def _cls_of(name):
    mm = re.match(r"_ZNK?(\d+)", name)
    if mm:
        n = int(mm.group(1))
        return name[mm.end():mm.end() + n]
    mm = re.match(r"_ZT[VIS](\d+)", name)
    if mm:
        n = int(mm.group(1))
        return name[mm.end():mm.end() + n]
    mm = re.match(r"\?\?_7([A-Za-z0-9_]+)@@", name) or re.match(r"\?[A-Za-z0-9_]+@([A-Za-z0-9_]+)@@", name)
    return mm.group(1) if mm else None


def _sym_kind(n):
    b = n[1:] if n.startswith("__Z") else n
    if b.startswith("_Z"):
        if b.startswith(("_ZTh", "_ZTv", "_ZTc")):
            return "thunk"
        if b.startswith(("_ZT", "_ZGV", "_ZZ", "_ZGR")):
            return None
        return "ita"
    if n.startswith("?"):
        if "@@" not in n or n.startswith(("??_", "?AV", "?AU", "?AW", "?AT")):
            return None
        return "msvc"
    return None


def _mangled(info, word):
    fn, df, und = _symsets(info)
    is_pe = info["pe"] is not None
    cands = []
    for idx, n in enumerate(_all_names(info)):
        kind = _sym_kind(n)
        if kind is None or word not in n.lower():
            continue
        if kind == "msvc" and is_pe:
            rank = -1
        elif n in fn:
            rank = 0
        elif n in df:
            rank = 1
        elif n in und:
            rank = 3
        else:
            rank = 2
        if kind == "thunk":
            rank += 4
        if ".cold" in n:
            sub = 2
        elif "." in n:
            sub = 0 if is_pe else 1
        else:
            sub = 1 if is_pe else 0
        cands.append(((rank, sub, idx), n))
    cands.sort()
    return [n for _k, n in cands]


def _vtables(info, prefer_cls):
    vt = [n for n in _all_names(info)
          if (n.startswith("_ZTV") and "cxxabiv1" not in n) or n.startswith("??_7")]
    vt.sort(key=lambda n: (_cls_of(n) != prefer_cls if prefer_cls else False,
                           not _defined(info, n)))
    return vt


def _ident(s, i):
    mm = re.match(r"\d+", s[i:])
    if not mm:
        return None, i
    k = int(mm.group(0))
    j = i + len(mm.group(0))
    if k <= 0 or j + k > len(s):
        return None, i
    return s[j:j + k], j + k


def _itanium(name):
    s = name[1:] if name.startswith("__Z") else name
    s = s.split(".", 1)[0]
    if not s.startswith("_Z"):
        return None
    i, n = 2, len(s)
    const = False
    comps = []
    if s[i:i + 1] == "N":
        i += 1
        while s[i:i + 1] in ("K", "V", "r"):
            if s[i] == "K":
                const = True
            i += 1
        while i < n and s[i] != "E":
            part, i2 = _ident(s, i)
            if part is None:
                return None
            comps.append(part)
            i = i2
        if i >= n:
            return None
        i += 1
    else:
        part, i2 = _ident(s, i)
        if part is None:
            return None
        comps.append(part)
        i = i2
    params = []
    while i < n:
        j = i
        while j < n and s[j] in "PKR":
            j += 1
        if j >= n or s[j] not in _BUILTIN:
            return None
        params.append((s[i:j], s[j]))
        i = j + 1
    if not comps or not params:
        return None
    return comps, const, params


def _ms_param(mods, code, wide):
    out = ""
    i = 0
    while i < len(mods):
        c = mods[i]
        if c in ("P", "R"):
            cst = i + 1 < len(mods) and mods[i + 1] == "K"
            out += ("P" if c == "P" else "A") + ("E" if wide else "") + ("B" if cst else "A")
            i += 2 if cst else 1
        else:
            i += 1
    return out + _BUILTIN[code][1]


def _dm_param(mods, code):
    s = _BUILTIN[code][0]
    for c in reversed(mods):
        s += {"K": " const", "P": "*", "R": "&"}[c]
    return s


def _synth(info, found):
    """Other spellings of the found Itanium symbol: (msvc, underscored, demangled)."""
    ita = [n for n in found if _sym_kind(n) == "ita"]
    if not ita:
        return [], [], []
    plain = [n for n in ita if "." not in n]
    base = plain[0] if plain else ita[0].split(".", 1)[0]
    under = [base[1:]] if base.startswith("__Z") else ["_" + base]
    parts = _itanium(base)
    if parts is None:
        return [], under, []
    comps, const, params = parts
    pe, elf = info["pe"], info["elf"]
    wide = True
    if pe is not None and pe["machine"] == 0x14C:
        wide = False
    if elf is not None and elf["cls"] == 1:
        wide = False
    if params == [("", "v")]:
        plist_ms, plist_dm = "XZ", ""
    else:
        plist_ms = "".join(_ms_param(md, c, wide) for md, c in params) + "@Z"
        plist_dm = ", ".join(_dm_param(md, c) for md, c in params)
    dem = ["::".join(comps) + "(" + plist_dm + ")" + (" const" if const else "")]
    msvc = []
    if len(comps) >= 2:
        cls = comps[-2]
        virt = any(n.startswith("_ZTV") and _cls_of(n) == cls for n in _all_names(info))
        head = "?" + comps[-1] + "@" + "@".join(reversed(comps[:-1])) + "@@"
        thisq = ("E" if wide else "") + ("B" if const else "A")
        cc = "A" if wide else "E"
        for acc in (("U", "Q") if virt else ("Q", "U")):
            for ret in ("H", "N"):
                msvc.append(head + acc + thisq + cc + ret + plist_ms)
    else:
        for ret in ("H", "N"):
            msvc.append("?" + comps[0] + "@@YA" + ret + plist_ms)
    return msvc, under, dem


def _siblings(info, found):
    """Defined methods of the same class (same signature first)."""
    ita = [n for n in found if _sym_kind(n) == "ita"]
    if not ita:
        return []
    p = _itanium(ita[0])
    if not p or len(p[0]) < 2:
        return []
    cls = p[0][-2]
    _fn, df, _und = _symsets(info)
    same, other = [], []
    for n in _all_names(info):
        if n in found or n not in df or _sym_kind(n) != "ita":
            continue
        q2 = _itanium(n)
        if not q2 or len(q2[0]) < 2 or q2[0][-2] != cls:
            continue
        if q2[1] == p[1] and q2[2] == p[2]:
            same.append(n)
        else:
            other.append(n)
    return same + other


def _where(info, off):
    pe, elf = info["pe"], info["elf"]
    if pe is not None:
        if pe["symptr"] and off >= pe["symptr"]:
            return "coff-symtab" if off < pe["symptr"] + pe["nsyms"] * 18 else "coff-strtab"
        for s in pe["secs"]:
            if s["rptr"] <= off < s["rptr"] + s["rsize"]:
                return s["name"]
    if elf is not None:
        for s in elf["secs"]:
            if s["type"] != 8 and s["offset"] <= off < s["offset"] + s["size"]:
                return s["name"]
    return "?"


def _src(info, n):
    fn, df, _und = _symsets(info)
    kind = "COFF" if info["pe"] is not None else "ELF"
    if info["pe"] is not None and n in info["pe"]["exports"]:
        return "PE export table"
    if n in fn:
        return f"{kind} symbol table (defined function)"
    if n in df:
        return f"{kind} symbol table (defined)"
    pos = info["raw"].find(n.encode("latin-1"))
    if pos >= 0:
        return f"string in {_where(info, pos)}"
    return "UTF-16 string"


def _diag(info, word, found, bad):
    raw, pe, m = info["raw"], info["pe"], info["m"]
    print(f"[mangled-diag] {m.path} found={found} refused={sorted(bad)}")
    if pe is not None:
        secnames = [s["name"] for s in pe["secs"]]
        print(f"[mangled-diag] PE machine=0x{pe['machine']:x} magic=0x{pe['magic']:x} "
              f"coff_syms={len(pe['coff'])} exports={len(pe['exports'])} sections={secnames}")
        cls = set()
        for n in found:
            c = _cls_of(n)
            if c:
                cls.add(c.lower())
        shown = 0
        for s in pe["coff"]:
            nl = s["name"].lower()
            if word in nl or any(c in nl for c in cls):
                print(f"  coff {s['name']} sec={s['secn']} type=0x{s['type']:x} "
                      f"scl={s['scl']} val=0x{s['value']:x}")
                shown += 1
                if shown >= 30:
                    break
        if pe["exports"]:
            print(f"  exports: {pe['exports'][:20]}")
    low = raw.lower()
    w = word.encode("latin-1")
    pos = low.find(w)
    k = 0
    while pos >= 0 and k < 20:
        a = pos
        while a > 0 and 0x20 < raw[a - 1] < 0x7F and pos - a < 120:
            a -= 1
        b = pos
        while b < len(raw) and 0x20 < raw[b] < 0x7F and b - pos < 120:
            b += 1
        print(f"  raw @0x{pos:x} [{_where(info, pos)}] {repr(raw[a:b].decode('latin-1'))}")
        k += 1
        pos = low.find(w, max(b, pos + 1))
    pu = low.find(word.encode("utf-16le"))
    if pu >= 0:
        print(f"  utf16 hit @0x{pu:x} [{_where(info, pu)}]")
    ms = [n for n in _all_names(info) if n.startswith("?")][:15]
    if ms:
        print(f"  msvc-like names: {ms}")


@handler(lanes=("binary-reverse-engineering",))
def specimen_field(q, ctx):
    qid = re.sub(r"^set\d+\.", "", (q.id or "").lower())
    if qid.startswith("cpp_"):
        want, field = True, qid[4:]
    elif qid.startswith("c_"):
        want, field = False, qid[2:]
    else:
        want, field = None, qid
    known = {"sha256", "marker", "has_symtab", "recover_code", "machine", "format",
             "xor_key", "config_crc32"} | _CPP_FIELDS | _CFG_FIELDS
    mang = re.match(r"mangled_(\w+?)_symbol$", field)
    if field not in known and not mang:
        if want is None:
            return None
    specs = _specimens(q, ctx)
    if not specs:
        return None
    if want is None and (field in _CPP_FIELDS or mang):
        want = True

    if want is None:
        order = [s for s in specs if s["cpp"]] + [s for s in specs if not s["cpp"]]
        for info in order:
            cfg = _config(info)
            if cfg is None:
                continue
            m = info["m"]
            v = _lookup(cfg["obj"], field)
            vals = _values(cfg["obj"], [])
            alts = []
            if v is None and field == "url":
                c = [x for x in vals if re.match(r"https?://", x, re.I)]
                v = c[0] if c else None
            if v is None and field == "domain":
                for x in vals:
                    if re.match(r"https?://", x, re.I):
                        v = urlparse.urlsplit(x).hostname
                        break
            if v is None and field == "mutex":
                c = [x for x in vals if re.match(r"(?:Global|Local|Session)\\", x)]
                v = c[0] if c else None
            if field == "campaign":
                for mm in re.finditer(rb'"campaign"\s*:\s*"([^"%]+)"', info["raw"]):
                    other = mm.group(1).decode("latin-1")
                    if v is None:
                        v = other
                    elif other != str(v):
                        alts.append(other)
            if v is None:
                if field in _CFG_FIELDS:
                    return answer("none", f"field {field} absent from decoded config in {m.path}",
                                  0.85, subject=m)
                return None
            v = str(v)
            if field == "mutex" and "\\" in v:
                alts.append(v.replace("\\", "\\\\"))
            if "\n" in v or v != v.strip():
                return None
            return answer(v, f"'{field}' in XOR-0x{cfg['key']:02x} decoded JSON config of {m.path}",
                          0.95, subject=m, alternatives=alts)
        return None

    info, n = _choose(specs, want)
    if info is None:
        return None
    m, raw, elf, pe = info["m"], info["raw"], info["elf"], info["pe"]
    conf = 0.95 if n == 1 else 0.8
    where = m.path

    if field == "sha256":
        return answer(info["sha"], f"sha256 of {where}", conf, subject=m)

    if field == "format":
        if elf is not None:
            return _multi(q, ["ELF", "ELF64" if elf["cls"] == 2 else "ELF32"],
                          f"\\x7fELF magic of {where}", conf, m)
        return _multi(q, ["PE", "PE32+" if pe["magic"] == 0x20B else "PE32"],
                      f"MZ/PE signature of {where}", conf, m)

    if field == "machine":
        if elf is not None:
            opts = _MACH.get(elf["machine"], [f"EM_{elf['machine']}"])
            return _multi(q, opts, f"e_machine={elf['machine']} in {where}", conf, m)
        opts = _PEMACH.get(pe["machine"], [f"0x{pe['machine']:x}"])
        return _multi(q, opts, f"COFF machine 0x{pe['machine']:x} in {where}", conf, m)

    if field == "has_symtab":
        if elf is not None:
            has = any(s["type"] == 2 or s["name"] == ".symtab" for s in elf["secs"])
        else:
            has = bool(pe["symptr"] and pe["nsyms"])
        return answer("true" if has else "false", f"section/symbol table of {where}", conf, subject=m)

    if field == "marker":
        if elf is None:
            return None
        sec = next((s for s in elf["secs"] if s["name"] == ".huntress"), None)
        if sec is None:
            return answer("none", f"no .huntress section in {where}", 0.85, subject=m)
        blob = raw[sec["offset"]:sec["offset"] + sec["size"]]
        parts = [p.decode("utf-8", "replace").strip() for p in blob.split(b"\x00")]
        parts = [p for p in parts if p and "\n" not in p]
        if not parts:
            return None
        return answer(parts[0], f"string in .huntress of {where}",
                      conf if len(parts) == 1 else min(conf, 0.85), subject=m)

    if field == "recover_code":
        if elf is None:
            return None
        syms = [s for s in elf["syms"] if s["name"] == "recover_code" and s["shndx"] != 0]
        if not syms:
            syms = [s for s in elf["syms"] if s["shndx"] != 0 and s["stype"] == 2
                    and s["bind"] in (1, 2) and not s["name"].startswith("_")
                    and s["name"] not in _STD and "@" not in s["name"] and "." not in s["name"]]
            conf = min(conf, 0.9) if len({s["name"] for s in syms}) == 1 else 0.7
        for s in syms:
            v = _func_const(elf, s)
            if v is not None:
                alt = f"0x{v:x}" if v >= 0 else f"0x{v & 0xFFFFFFFF:x}"
                return answer(str(v), f"immediate returned by {s['name']} in {where}", conf,
                              subject=m, alternatives=[alt])
        return None

    if field in ("xor_key", "config_crc32"):
        cfg = _config(info)
        if cfg is None:
            return None
        if field == "xor_key":
            k = cfg["key"]
            return _multi(q, [f"0x{k:02x}", f"0x{k:x}"],
                          f"single-byte XOR key decoding the JSON config in {where}", conf, m)
        cands = [cfg["plain"]]
        if cfg["full_enc"] is not None:
            fp = cfg["full_enc"].translate(_TABLES[cfg["key"]])
            cands.append(fp.rstrip(b"\x00"))
            cands.append(fp)
        cands.append(cfg["enc"])
        if cfg["full_enc"] is not None:
            cands.append(cfg["full_enc"])
        crcs = []
        for c in cands:
            v = zlib.crc32(c) & 0xFFFFFFFF
            if v not in crcs:
                crcs.append(v)
        stored = [v for v in crcs if struct.pack("<I", v) in raw]
        ordered = stored + [v for v in crcs if v not in stored]
        opts = []
        for v in ordered:
            opts += [f"0x{v:08x}", f"0x{v:x}"]
        why = "CRC32 of decoded JSON config" + (" (value also stored in binary)" if stored else "")
        return _multi(q, opts, f"{why} in {where}", conf if stored or len(crcs) == 1 else 0.9, m)

    if field == "has_cpp_vtable":
        has = (b"_ZTV" in raw or b"??_7" in raw)
        return answer("true" if has else "false", f"vtable symbols in {where}", conf, subject=m)

    if field == "has_cpp_typeinfo":
        has = (b"_ZTI" in raw or b"_ZTS" in raw or b"class_type_info" in raw
               or b".?AV" in raw or b"??_R0" in raw)
        return answer("true" if has else "false", f"RTTI/typeinfo symbols in {where}", conf, subject=m)

    if mang:
        word = mang.group(1).lower()
        found = _mangled(info, word)
        bad = set(_refused(q))
        if pe is not None or (found and all(x in bad for x in found)):
            _diag(info, word, found, bad)
        if not found:
            if "none" in bad:
                return None
            return answer("none", f"no mangled {word} symbol in {where}", 0.85, subject=m)
        msvc, under, dem = _synth(info, found)
        live = [x for x in found if x not in bad]
        if live:
            alts = list(live[1:])
            for x in msvc + under + dem:
                if x not in bad and x not in alts and x != live[0]:
                    alts.append(x)
            c2 = conf if (len(found) == 1 and not bad) else min(conf, 0.9)
            return answer(live[0], f"mangled symbol containing '{word}' from "
                                   f"{_src(info, live[0])} in {where}",
                          c2, subject=m, alternatives=alts)
        _fn, df, _und = _symsets(info)
        sib = _siblings(info, found)
        listed = any(x in df for x in found)
        if df and not listed:
            order = sib + msvc[:1] + ["none"] + under + msvc[1:] + dem
        else:
            order = msvc[:1] + ["none"] + under + sib + msvc[1:] + dem
        opts = []
        for x in order:
            if x and x not in bad and x not in opts:
                opts.append(x)
        if not opts:
            return None
        print(f"[mangled-diag] fallback order: {opts}")
        return answer(opts[0], f"every {word} symbol found in {where} was refused "
                               f"({', '.join(found)}); remaining spellings are unproven guesses",
                      0.6, subject=m, alternatives=opts[1:])

    if field == "vtable_symbol":
        sc = _mangled(info, "score")
        prefer = _cls_of(sc[0]) if sc else None
        vt = _vtables(info, prefer)
        if not vt:
            return answer("none", f"no vtable symbol in {where}", 0.85, subject=m)
        alts = vt[1:]
        cl = _cls_of(vt[0])
        if cl:
            alts.append(f"vtable for {cl}")
        return answer(vt[0], f"vtable symbol in {where}", conf if len(vt) == 1 else 0.9,
                      subject=m, alternatives=alts)

    cfg = _config(info)
    if cfg is not None:
        v = _lookup(cfg["obj"], field)
        if v is not None and "\n" not in str(v):
            return answer(str(v), f"'{field}' in decoded config of {where}", conf, subject=m)
    return None
