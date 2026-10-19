# learned-module: cpp_c_specimen_config_facts
"""Day-2 style RE evidence sets holding a C specimen and a C++ specimen
(ELF or PE). Answers per-specimen fields (c_*/cpp_*: sha256, marker,
has_symtab, recover_code, machine, format, xor_key, config_crc32) and the
C++ facts (vtable/typeinfo presence, mangled symbols) plus indicators
(campaign, domain, url, mutex) from the single-byte-XOR'd JSON config blob.
Everything is derived from the bytes; the C++ specimen is identified by
content (libstdc++ / Itanium or MSVC mangling), not by file name."""
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


def _pe(raw):
    if not raw or len(raw) < 0x40 or raw[:2] != b"MZ":
        return None
    try:
        lfa = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[lfa:lfa + 4] != b"PE\x00\x00":
            return None
        mach, nsec, _ts, symptr, nsyms, optsz = struct.unpack_from("<HHIIIH", raw, lfa + 4)
        magic = struct.unpack_from("<H", raw, lfa + 24)[0] if optsz else 0
    except struct.error:
        return None
    return {"machine": mach, "symptr": symptr, "nsyms": nsyms, "magic": magic}


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
            "cpp": _is_cpp(raw), "cfg": None, "cfg_done": False}
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
    names = []
    if info["elf"] is not None:
        for s in info["elf"]["syms"]:
            names.append(s["name"])
    for mm in re.finditer(rb"_Z[A-Za-z0-9_]{3,}|\?\?_7[A-Za-z0-9_@?$]+|\?[A-Za-z_][A-Za-z0-9_@?$]+@@[A-Za-z0-9_@?$]*",
                          info["raw"]):
        names.append(mm.group(0).decode("latin-1"))
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def _defined(info, name):
    if info["elf"] is None:
        return False
    return any(s["name"] == name and s["shndx"] != 0 for s in info["elf"]["syms"])


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


def _mangled(info, word):
    cands = [n for n in _all_names(info)
             if word in n.lower() and (n.startswith("_Z") or n.startswith("?"))
             and not n.startswith("_ZT") and not n.startswith("??_")]
    cands.sort(key=lambda n: (not _defined(info, n), "@" in n and n.startswith("_Z")))
    return cands


def _vtables(info, prefer_cls):
    vt = [n for n in _all_names(info)
          if (n.startswith("_ZTV") and "cxxabiv1" not in n) or n.startswith("??_7")]
    vt.sort(key=lambda n: (_cls_of(n) != prefer_cls if prefer_cls else False,
                           not _defined(info, n)))
    return vt


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
        c = _mangled(info, mang.group(1))
        if not c:
            return answer("none", f"no mangled {mang.group(1)} symbol in {where}", 0.85, subject=m)
        return answer(c[0], f"mangled symbol containing '{mang.group(1)}' in {where}",
                      conf if len(c) == 1 else 0.9, subject=m, alternatives=c[1:])

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
