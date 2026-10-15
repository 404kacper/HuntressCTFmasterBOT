# learned-module: elf_header_section_symbol_facts
"""Answer ELF orientation questions (class, byte order, machine, type, entry,
custom section contents, .symtab presence, designated/exported symbol, and the
constant returned by a named function) by parsing the ELF bytes directly."""
import re
import struct

from hunt.learn.kit import answer, asks, data, files, target
from hunt.solvers import handler

_MACHINES = {
    0: "none", 2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    22: "S390", 40: "ARM", 42: "SuperH", 43: "SPARCV9", 50: "IA-64",
    62: "x86-64", 183: "AArch64", 243: "RISC-V", 258: "LoongArch",
}
_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}

_STD_SYMS = {
    "main", "deregister_tm_clones", "register_tm_clones", "frame_dummy",
    "completed.0", "data_start", "crtstuff.c", "crt1.o", "challenge.c",
}


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
            (etype, mach, _ver, entry, phoff, shoff, flags, _ehs, phes, phn,
             shes, shn, shstr) = struct.unpack_from(e + "HHIQQQIHHHHHH", raw, 16)
        else:
            (etype, mach, _ver, entry, phoff, shoff, flags, _ehs, phes, phn,
             shes, shn, shstr) = struct.unpack_from(e + "HHIIIIIHHHHHH", raw, 16)
    except struct.error:
        return None
    elf = {"class": cls, "endian": e, "type": etype, "machine": mach,
           "entry": entry, "sections": [], "symbols": [], "raw": raw}
    secs = []
    if shoff and shn and shes:
        for i in range(shn):
            off = shoff + i * shes
            try:
                if cls == 2:
                    t = struct.unpack_from(e + "IIQQQQIIQQ", raw, off)
                else:
                    t = struct.unpack_from(e + "IIIIIIIIII", raw, off)
            except struct.error:
                break
            secs.append({"name_off": t[0], "type": t[1], "flags": t[2],
                         "addr": t[3], "offset": t[4], "size": t[5],
                         "link": t[6], "info": t[7], "entsize": t[9],
                         "name": ""})
        if 0 <= shstr < len(secs):
            st = secs[shstr]
            tab = raw[st["offset"]:st["offset"] + st["size"]]
            for s in secs:
                s["name"] = _cstr(tab, s["name_off"])
    elf["sections"] = secs
    syms = []
    for s in secs:
        if s["type"] not in (2, 11):  # SYMTAB, DYNSYM
            continue
        if not (0 <= s["link"] < len(secs)):
            continue
        strs = secs[s["link"]]
        stab = raw[strs["offset"]:strs["offset"] + strs["size"]]
        esz = s["entsize"] or (24 if cls == 2 else 16)
        n = s["size"] // esz if esz else 0
        for i in range(n):
            off = s["offset"] + i * esz
            try:
                if cls == 2:
                    nm, info, other, shndx, val, size = struct.unpack_from(
                        e + "IBBHQQ", raw, off)
                else:
                    nm, val, size, info, other, shndx = struct.unpack_from(
                        e + "IIIBBH", raw, off)
            except struct.error:
                break
            name = _cstr(stab, nm)
            if not name:
                continue
            syms.append({"name": name, "value": val, "size": size,
                         "bind": info >> 4, "stype": info & 0xF,
                         "shndx": shndx, "table": "dynsym" if s["type"] == 11 else "symtab"})
    elf["symbols"] = syms
    return elf


def _section(elf, name):
    for s in elf["sections"]:
        if s["name"] == name:
            return s
    return None


def _v2o(elf, va):
    for s in elf["sections"]:
        if s["type"] == 8 or not s["addr"]:
            continue
        if s["addr"] <= va < s["addr"] + s["size"]:
            return s["offset"] + (va - s["addr"])
    return None


def _pick_elf(q, ctx):
    m = target(q, ctx)
    pool = []
    if m is not None:
        try:
            kids = list(ctx.artifacts.files(m))
        except Exception:
            kids = []
        pool = [m] + kids
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
        for mem in files(ctx):
            raw = data(mem)
            elf = _parse(raw) if raw else None
            if elf is not None:
                cands.append((mem, elf))
    if not cands:
        return None, None, 0
    if len(cands) == 1:
        return cands[0][0], cands[0][1], 1
    custom = [c for c in cands if _section(c[1], ".huntress") is not None]
    if len(custom) == 1:
        return custom[0][0], custom[0][1], 1
    exe = [c for c in (custom or cands) if c[1]["type"] in (2, 3)]
    pick = (exe or custom or cands)[-1]
    return pick[0], pick[1], len(exe or custom or cands)


def _ret_const_x86(code, is64):
    vals = []
    locs = {}
    i = 0
    n = len(code)
    while i < n:
        b = code[i]
        if code[i:i + 4] == b"\xf3\x0f\x1e\xfa" or code[i:i + 4] == b"\xf3\x0f\x1e\xfb":
            i += 4
            continue
        if b == 0xC3:
            break
        if b == 0xB8 and i + 5 <= n:
            vals.append(struct.unpack_from("<I", code, i + 1)[0])
            i += 5
            continue
        if b == 0x48 and code[i + 1:i + 3] == b"\xc7\xc0" and i + 7 <= n:
            vals.append(struct.unpack_from("<i", code, i + 3)[0])
            i += 7
            continue
        if b == 0x48 and i + 1 < n and code[i + 1] == 0xB8 and i + 10 <= n:
            vals.append(struct.unpack_from("<Q", code, i + 2)[0])
            i += 10
            continue
        if b in (0x31, 0x33) and i + 1 < n and code[i + 1] == 0xC0:
            vals.append(0)
            i += 2
            continue
        if b == 0xC7 and i + 1 < n and code[i + 1] == 0x45 and i + 7 <= n:
            locs[code[i + 2]] = struct.unpack_from("<I", code, i + 3)[0]
            i += 7
            continue
        if b == 0x8B and i + 1 < n and code[i + 1] == 0x45 and i + 3 <= n:
            if code[i + 2] in locs:
                vals.append(locs[code[i + 2]])
            i += 3
            continue
        i += 1
    if not vals:
        return None
    v = vals[-1]
    if v >= 1 << 63:
        v -= 1 << 64
    return v


def _ret_const_a64(code, e):
    val = None
    for i in range(0, len(code) - 3, 4):
        w = struct.unpack_from(e + "I", code, i)[0]
        if w == 0xD65F03C0:
            break
        rd = w & 0x1F
        imm = (w >> 5) & 0xFFFF
        hw = (w >> 21) & 3
        top = w & 0x7F800000
        if rd != 0:
            continue
        if top == 0x52800000:  # MOVZ
            val = imm << (16 * hw)
        elif top == 0x12800000:  # MOVN
            v = ~(imm << (16 * hw))
            val = v if (w >> 31) else ((v & 0xFFFFFFFF) - (1 << 32) if v & 0x80000000 else v & 0xFFFFFFFF)
        elif top == 0x72800000 and val is not None:  # MOVK
            mask = 0xFFFF << (16 * hw)
            val = (val & ~mask) | (imm << (16 * hw))
        elif w in (0x2A1F03E0, 0xAA1F03E0):  # mov w0, wzr
            val = 0
    if val is not None and 0x80000000 <= val < 0x100000000:
        val -= 1 << 32
    return val


def _func_const(elf, fname):
    sym = None
    for s in elf["symbols"]:
        if s["name"] == fname and s["shndx"] != 0:
            if sym is None or s["stype"] == 2:
                sym = s
    if sym is None:
        return None
    va = sym["value"]
    if elf["machine"] == 40:
        va &= ~1
    off = _v2o(elf, va)
    if off is None:
        return None
    size = sym["size"] or 256
    code = elf["raw"][off:off + size]
    if elf["machine"] in (62, 3):
        return _ret_const_x86(code, elf["machine"] == 62)
    if elf["machine"] == 183:
        return _ret_const_a64(code, elf["endian"])
    return None


def _designated_symbol(elf):
    def ok(s):
        n = s["name"]
        return (s["shndx"] != 0 and s["stype"] in (1, 2) and not n.startswith("_")
                and n not in _STD_SYMS and "@" not in n and "." not in n)
    dyn = [s for s in elf["symbols"] if s["table"] == "dynsym" and ok(s) and s["bind"] in (1, 2)]
    names = []
    for s in dyn:
        if s["name"] not in names:
            names.append(s["name"])
    if len(names) == 1:
        return names[0], "exported in .dynsym"
    glob = [s for s in elf["symbols"] if ok(s) and s["bind"] in (1, 2)]
    gnames = []
    for s in glob:
        if s["name"] not in gnames:
            gnames.append(s["name"])
    if len(gnames) == 1:
        return gnames[0], "only non-runtime global symbol"
    funcs = [n for n in gnames if any(s["name"] == n and s["stype"] == 2 for s in glob)]
    if len(funcs) == 1:
        return funcs[0], "only non-runtime global function"
    if names:
        return names[0], "first exported .dynsym symbol (ambiguous)"
    if gnames:
        return gnames[0], "first non-runtime global symbol (ambiguous)"
    return None, ""


_SEC_RE = re.compile(r"(\.[A-Za-z0-9_.\-]+)\s+section")
_FN_RE = re.compile(r"return(?:ed)?\s+by\s+`?([A-Za-z_][A-Za-z0-9_]*)")


@handler()
def elf_facts(q, ctx):
    qid = (q.id or "").lower()
    hay = q.haystack
    if "elf" not in hay and qid not in (
            "elf_class", "endianness", "machine", "elf_type", "marker",
            "has_symtab", "exported_symbol", "recover_code", "entry_point"):
        return None
    mem, elf, ncand = _pick_elf(q, ctx)
    if elf is None:
        return None
    conf = 0.95 if ncand == 1 else 0.8
    where = mem.path

    if qid == "elf_class" or ("class" in hay and "elf" in hay):
        v = "ELF64" if elf["class"] == 2 else "ELF32"
        return answer(v, f"e_ident[EI_CLASS]={elf['class']} in {where}", conf, subject=mem)

    if qid == "endianness" or asks(q, "byte", "order") or "endian" in hay:
        v = "little" if elf["endian"] == "<" else "big"
        return answer(v, f"e_ident[EI_DATA] in {where}", conf, subject=mem)

    if qid == "entry_point" or asks(q, "entry", "point"):
        return answer(f"0x{elf['entry']:x}", f"e_entry of {where}", conf, subject=mem)

    if qid == "machine" or "machine" in hay or "architecture" in hay:
        v = _MACHINES.get(elf["machine"], f"EM_{elf['machine']}")
        return answer(v, f"e_machine={elf['machine']} in {where}", conf, subject=mem)

    if qid == "elf_type" or asks(q, "object", "type"):
        v = _TYPES.get(elf["type"], str(elf["type"]))
        return answer(v, f"e_type={elf['type']} in {where}", conf, subject=mem)

    if qid == "has_symtab" or ("symtab" in hay and ("true" in hay or "retain" in hay)):
        has = any(s["type"] == 2 or s["name"] == ".symtab" for s in elf["sections"])
        return answer("true" if has else "false", f"section table of {where}", conf, subject=mem)

    if qid == "marker" or ("section" in hay and ("string" in hay or "marker" in hay)):
        mm = _SEC_RE.search(q.text or "")
        sname = mm.group(1) if mm else ".huntress"
        sec = _section(elf, sname)
        if sec is None:
            return answer("none", f"no {sname} section in {where}", conf, subject=mem)
        if sec["type"] == 8:
            return None
        blob = elf["raw"][sec["offset"]:sec["offset"] + sec["size"]]
        parts = [p.decode("utf-8", "replace").strip() for p in blob.split(b"\x00")]
        parts = [p for p in parts if p]
        if not parts:
            return None
        v = parts[0]
        if "\n" in v:
            return None
        c = conf if len(parts) == 1 else min(conf, 0.85)
        return answer(v, f"NUL-terminated string in {sname} of {where}", c, subject=mem)

    if qid == "recover_code" or ("return" in hay and "constant" in hay):
        mm = _FN_RE.search(q.text or "")
        fname = mm.group(1) if mm else "recover_code"
        v = _func_const(elf, fname)
        if v is None:
            return None
        return answer(str(v), f"immediate loaded into return register in {fname} of {where}",
                      conf, subject=mem)

    if qid == "exported_symbol" or ("symbol" in hay and ("designated" in hay or "export" in hay)):
        name, why = _designated_symbol(elf)
        if not name:
            return None
        c = conf if "ambiguous" not in why else 0.7
        return answer(name, f"{why} in {where}", c, subject=mem)

    return None
