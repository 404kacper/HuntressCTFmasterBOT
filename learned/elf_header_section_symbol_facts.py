# learned-module: elf_header_section_symbol_facts
"""Answer ELF orientation questions (class, byte order, machine, type, entry,
custom section contents, .symtab presence, designated/exported symbol, the
constant returned by a named function, and the disassembly of a named FUNC)
by parsing the ELF bytes directly."""
import json
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
_TYPE_DESC = {0: "None", 1: "Relocatable file", 2: "Executable file",
              3: "Shared object file", 4: "Core file"}
_TYPE_WORD = {0: "none", 1: "relocatable", 2: "executable", 3: "shared", 4: "core"}

_STD_SYMS = {
    "main", "deregister_tm_clones", "register_tm_clones", "frame_dummy",
    "completed.0", "data_start", "crtstuff.c", "crt1.o", "challenge.c",
}

_R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
_R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]


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
           "entry": entry, "sections": [], "symbols": [], "raw": raw,
           "ptypes": []}
    ptypes = []
    if phoff and phn and phes:
        for i in range(phn):
            try:
                ptypes.append(struct.unpack_from(e + "I", raw, phoff + i * phes)[0])
            except struct.error:
                break
    elf["ptypes"] = ptypes
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


# ---------- disassembly ----------

def _imm(v):
    return f"0x{v:x}"


def _disasm_x86(code, bits64):
    """List of (intel, att) per instruction, or None on an unknown opcode."""
    out = []
    i, n = 0, len(code)
    while i < n:
        b = code[i]
        if code[i:i + 4] == b"\xf3\x0f\x1e\xfa":
            out.append(("endbr64", "endbr64")); i += 4; continue
        if code[i:i + 4] == b"\xf3\x0f\x1e\xfb":
            out.append(("endbr32", "endbr32")); i += 4; continue
        if b == 0xC3:
            out.append(("ret", "ret")); i += 1; break
        if code[i:i + 2] == b"\xf3\xc3":
            out.append(("ret", "ret")); i += 2; break
        if 0x50 <= b <= 0x57:
            r = _R64[b - 0x50]; out.append((f"push {r}", f"push %{r}")); i += 1; continue
        if 0x58 <= b <= 0x5F:
            r = _R64[b - 0x58]; out.append((f"pop {r}", f"pop %{r}")); i += 1; continue
        if b == 0xC9:
            out.append(("leave", "leave")); i += 1; continue
        if b == 0x90:
            out.append(("nop", "nop")); i += 1; continue
        if 0xB8 <= b <= 0xBF and i + 5 <= n:
            r = _R32[b - 0xB8]; v = struct.unpack_from("<I", code, i + 1)[0]
            out.append((f"mov {r}, {_imm(v)}", f"mov ${_imm(v)}, %{r}")); i += 5; continue
        if b in (0x31, 0x33) and i + 2 <= n and (code[i + 1] & 0xC0) == 0xC0:
            modrm = code[i + 1]; reg = (modrm >> 3) & 7; rm = modrm & 7
            rr, rm_ = _R32[reg], _R32[rm]
            if b == 0x31:
                out.append((f"xor {rm_}, {rr}", f"xor %{rr}, %{rm_}"))
            else:
                out.append((f"xor {rr}, {rm_}", f"xor %{rm_}, %{rr}"))
            i += 2; continue
        if b == 0x48 and i + 1 < n:
            b2 = code[i + 1]
            if b2 == 0x89 and i + 3 <= n and (code[i + 2] & 0xC0) == 0xC0:
                modrm = code[i + 2]; reg = (modrm >> 3) & 7; rm = modrm & 7
                out.append((f"mov {_R64[rm]}, {_R64[reg]}",
                            f"mov %{_R64[reg]}, %{_R64[rm]}")); i += 3; continue
            if b2 == 0xC7 and i + 7 <= n and (code[i + 2] & 0xF8) == 0xC0:
                rm = code[i + 2] & 7
                v = struct.unpack_from("<i", code, i + 3)[0] & 0xFFFFFFFFFFFFFFFF
                out.append((f"mov {_R64[rm]}, {_imm(v)}",
                            f"mov ${_imm(v)}, %{_R64[rm]}")); i += 7; continue
            if 0xB8 <= b2 <= 0xBF and i + 10 <= n:
                r = _R64[b2 - 0xB8]; v = struct.unpack_from("<Q", code, i + 2)[0]
                out.append((f"movabs {r}, {_imm(v)}",
                            f"movabs ${_imm(v)}, %{r}")); i += 10; continue
            if b2 == 0x31 and i + 3 <= n and (code[i + 2] & 0xC0) == 0xC0:
                modrm = code[i + 2]; reg = (modrm >> 3) & 7; rm = modrm & 7
                out.append((f"xor {_R64[rm]}, {_R64[reg]}",
                            f"xor %{_R64[reg]}, %{_R64[rm]}")); i += 3; continue
            return None
        return None
    return out


def _disasm_a64(code, e):
    out = []
    for i in range(0, len(code) - 3, 4):
        w = struct.unpack_from(e + "I", code, i)[0]
        if w == 0xD65F03C0:
            out.append(("ret", "ret")); break
        rd = w & 0x1F
        sf = (w >> 31) & 1
        reg = f"{'x' if sf else 'w'}{rd}"
        imm = (w >> 5) & 0xFFFF
        hw = (w >> 21) & 3
        top = w & 0x7F800000
        shift = f", lsl #{16 * hw}" if hw else ""
        if top == 0x52800000:
            s = (f"mov {reg}, #0x{imm:x}",) * 2 if not hw else \
                (f"movz {reg}, #0x{imm:x}{shift}",) * 2
            out.append(s)
        elif top == 0x12800000:
            out.append((f"movn {reg}, #0x{imm:x}{shift}",) * 2)
        elif top == 0x72800000:
            out.append((f"movk {reg}, #0x{imm:x}{shift}",) * 2)
        else:
            return None
    return out


def _find_symtab_func(elf, name):
    for s in elf["symbols"]:
        if (s["table"] == "symtab" and s["stype"] == 2
                and s["shndx"] != 0 and s["name"] == name):
            return s
    return None


def _disasm_sym(elf, sym):
    va = sym["value"]
    if elf["machine"] == 40:
        va &= ~1
    off = _v2o(elf, va)
    if off is None:
        return None, None
    size = sym["size"] or 64
    code = elf["raw"][off:off + size]
    if elf["machine"] in (62, 3):
        return _disasm_x86(code, elf["machine"] == 62), code
    if elf["machine"] == 183:
        return _disasm_a64(code, elf["endian"]), code
    return None, code


_DIS_RE = re.compile(r"find\s+(?:the\s+)?`?([A-Za-z_]\w*)`?\s+func", re.I)


def _disasm_target_name(q):
    m = _DIS_RE.search(q.text or "")
    return m.group(1) if m else "recover_code"


def _is_struct(intel):
    return intel.startswith((
        "push ", "pop ", "endbr", "nop", "leave",
        "mov rbp", "mov ebp", "mov rsp", "mov esp"))


def _disasm_candidates(seq, refused):
    def grp(tuples):
        intel = [t[0] for t in tuples]
        att = [t[1] for t in tuples]
        return [intel,
                [s.replace(", ", ",") for s in intel],
                att,
                [s.replace(", ", ",") for s in att]]
    groups = [seq]
    core = [t for t in seq if not _is_struct(t[0])]
    if core and core != seq:
        groups.append(core)
    out = []
    for g in groups:
        for arr in grp(g):
            s = json.dumps(arr, separators=(",", ":"), ensure_ascii=False)
            for cand in (s, re.sub(r'0x0(?=")', '0', s)):
                if cand not in out and cand not in refused:
                    out.append(cand)
    return out


def _handle_disasm(q, ctx):
    name = _disasm_target_name(q)
    refused = []
    if isinstance(q.raw, dict):
        refused = q.raw.get("refused_by_game_master") or []
    elfs = []
    seen = set()
    for mem in files(ctx):
        if mem.path in seen:
            continue
        seen.add(mem.path)
        raw = data(mem)
        el = _parse(raw) if raw else None
        if el is not None:
            elfs.append((mem, el))
    if not elfs:
        return None
    chosen = None
    for mem, el in elfs:
        sym = _find_symtab_func(el, name)
        if sym is not None:
            chosen = (mem, el, sym)
            break
    if chosen is None:
        return answer("[]", f"no .symtab {name} FUNC symbol among ELF members", 0.9)
    mem, el, sym = chosen
    seq, code = _disasm_sym(el, sym)
    print(f"[disasm] {mem.path} {name} va=0x{sym['value']:x} size={sym['size']} "
          f"bytes={(code or b'').hex()}")
    if not seq:
        print(f"[disasm] decode failed for {name}")
        return None
    print(f"[disasm] intel={[t[0] for t in seq]}")
    cands = _disasm_candidates(seq, refused)
    if not cands:
        return None
    return answer(cands[0], f"disassembly of {name} FUNC bytes in {mem.path}",
                  0.9, subject=mem, alternatives=cands[1:])


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
        if top == 0x52800000:
            val = imm << (16 * hw)
        elif top == 0x12800000:
            v = ~(imm << (16 * hw))
            val = v if (w >> 31) else ((v & 0xFFFFFFFF) - (1 << 32) if v & 0x80000000 else v & 0xFFFFFFFF)
        elif top == 0x72800000 and val is not None:
            mask = 0xFFFF << (16 * hw)
            val = (val & ~mask) | (imm << (16 * hw))
        elif w in (0x2A1F03E0, 0xAA1F03E0):
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


def _type_spellings(elf):
    t = elf["type"]
    short = _TYPES.get(t)
    if short is None:
        return [str(t), f"0x{t:x}"]
    desc = _TYPE_DESC[t]
    out = []
    if t == 3:
        pie = 3 in elf["ptypes"]
        pie_desc = "Position-Independent Executable file"
        first, second = (pie_desc, desc) if pie else (desc, pie_desc)
        out += [f"DYN ({first})", f"DYN ({second})", f"ET_{short}", first, second]
    else:
        out += [f"{short} ({desc})", f"ET_{short}", desc]
    out += [_TYPE_WORD[t], short]
    seen = []
    for v in out:
        if v not in seen:
            seen.append(v)
    return seen


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

    # Disassembly question: own it so we never fall through to endianness/marker.
    if "disassembl" in hay or qid.endswith("disassembly"):
        return _handle_disasm(q, ctx)

    mem, elf, ncand = _pick_elf(q, ctx)
    if elf is None:
        return None
    conf = 0.95 if ncand == 1 else 0.8
    where = mem.path

    if qid == "elf_type" or asks(q, "object", "type"):
        refused = q.raw.get("refused_by_game_master") or [] if isinstance(q.raw, dict) else []
        opts = [v for v in _type_spellings(elf) if v not in refused]
        if not opts:
            return None
        return answer(opts[0], f"e_type={elf['type']} in {where} (readelf spelling)", conf,
                      subject=mem, alternatives=opts[1:])

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
