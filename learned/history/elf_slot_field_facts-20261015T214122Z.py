# learned-module: elf_slot_field_facts
"""Multi-binary ELF orientation sets: questions named slotN_<field> ask for a
field (elf_class, endianness, machine, elf_type, marker, has_symtab,
exported_symbol, recover_code, entry_point) of the Nth binary (slot-N.elf).
Each answer is parsed from that binary's own bytes. A recover_code question
whose function is absent from the binary is answered with the literal none
when the format allows it (also for the single-binary recover_code question).
A stripped binary with no non-runtime global symbol in .dynsym or .symtab
answers exported_symbol with the literal none when the format allows it."""
import re
import struct

from hunt.learn.kit import answer, data, files, target
from hunt.solvers import handler

_MACHINES = {
    0: "none", 2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    22: "S390", 40: "ARM", 42: "SuperH", 43: "SPARCV9", 50: "IA-64",
    62: "x86-64", 183: "AArch64", 243: "RISC-V", 258: "LoongArch",
}
_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_TYPE_DESC = {0: "None", 1: "Relocatable file", 2: "Executable file",
              3: "Shared object file", 4: "Core file"}
_STD = {"main", "deregister_tm_clones", "register_tm_clones", "frame_dummy",
        "completed.0", "data_start"}
_FIELDS = ("elf_class", "endianness", "machine", "elf_type", "marker",
           "has_symtab", "exported_symbol", "recover_code", "entry_point")
_SLOT_RE = re.compile(r"^slot[_-]?(\d+)_(.+)$")


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
    etype, mach, entry, phoff, shoff = t[0], t[1], t[3], t[4], t[5]
    phes, phn, shes, shn, shstr = t[8], t[9], t[10], t[11], t[12]
    ptypes = []
    if phoff and phn and phes:
        for i in range(phn):
            try:
                ptypes.append(struct.unpack_from(e + "I", raw, phoff + i * phes)[0])
            except struct.error:
                break
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
    return {"cls": cls, "e": e, "type": etype, "machine": mach, "entry": entry,
            "ptypes": ptypes, "secs": secs, "syms": syms, "raw": raw}


def _section(elf, name):
    for s in elf["secs"]:
        if s["name"] == name:
            return s
    return None


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


def _named_funcs(elf, name):
    out = [s for s in elf["syms"] if s["name"] == name and s["shndx"] != 0
           and s["stype"] in (0, 2)]
    out.sort(key=lambda s: s["stype"] != 2)
    return out


def _sym_const(elf, sym):
    va = sym["value"]
    if elf["machine"] == 40:
        va &= ~1
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


def _designated(elf):
    def ok(s):
        n = s["name"]
        return (s["shndx"] != 0 and s["stype"] in (1, 2) and s["bind"] in (1, 2)
                and not n.startswith("_") and n not in _STD and "@" not in n and "." not in n)
    for pool in ([s for s in elf["syms"] if s["dyn"] and ok(s)],
                 [s for s in elf["syms"] if ok(s)],
                 [s for s in elf["syms"] if ok(s) and s["stype"] == 2]):
        names = []
        for s in pool:
            if s["name"] not in names:
                names.append(s["name"])
        if len(names) == 1:
            return names[0], True
    pool = [s["name"] for s in elf["syms"] if ok(s)]
    return (pool[0], False) if pool else (None, False)


def _type_spellings(elf):
    t = elf["type"]
    short = _TYPES.get(t)
    if short is None:
        return [str(t)]
    desc = _TYPE_DESC[t]
    out = [f"ET_{short}", f"{short} ({desc})"]
    if t == 3:
        out.append("DYN (Position-Independent Executable file)")
    out += [short, desc]
    seen = []
    for v in out:
        if v not in seen:
            seen.append(v)
    return seen


def _collect(pool):
    out = []
    seen = set()
    for m in pool:
        if m is None or m.path in seen:
            continue
        seen.add(m.path)
        raw = data(m)
        elf = _parse(raw) if raw else None
        if elf is not None:
            out.append((m, elf))
    return out


def _elves(q, ctx):
    root = None
    try:
        root = target(q, ctx)
    except Exception:
        root = None
    pool = []
    if root is not None:
        pool.append(root)
        try:
            pool += list(files(ctx, root))
        except Exception:
            pass
        try:
            pool += list(ctx.artifacts.files(root))
        except Exception:
            pass
    out = _collect(pool)
    if not out:
        out = _collect(list(files(ctx)))
    return out


def _slot_member(elves, n):
    named = []
    for m, elf in elves:
        stem = (m.basename or "").rsplit(".", 1)[0]
        nums = re.findall(r"\d+", stem)
        if nums and int(nums[-1]) == n:
            named.append((m, elf))
    if len(named) == 1:
        return named[0][0], named[0][1], 0.95
    ordered = sorted(elves, key=lambda c: (c[0].order, c[0].path))
    if 0 <= n < len(ordered):
        return ordered[n][0], ordered[n][1], 0.9
    return None, None, 0


def _none_ok(q):
    return "none" in (q.syntax or "").lower() and (q.kind or "") != "integer"


def _field(q, field, mem, elf, conf):
    where = mem.path
    if field == "elf_class":
        return answer("ELF64" if elf["cls"] == 2 else "ELF32",
                      f"e_ident[EI_CLASS]={elf['cls']} in {where}", conf, subject=mem,
                      alternatives=["64-bit" if elf["cls"] == 2 else "32-bit"])
    if field == "endianness":
        v = "little" if elf["e"] == "<" else "big"
        return answer(v, f"e_ident[EI_DATA] in {where}", conf, subject=mem,
                      alternatives=[f"{v}-endian", f"{v} endian"])
    if field == "machine":
        v = _MACHINES.get(elf["machine"], f"EM_{elf['machine']}")
        alts = ["Advanced Micro Devices X86-64", "x86_64", "EM_X86_64"] if elf["machine"] == 62 else []
        return answer(v, f"e_machine={elf['machine']} in {where}", conf, subject=mem,
                      alternatives=alts)
    if field == "elf_type":
        refused = (q.raw.get("refused_by_game_master") or []) if isinstance(q.raw, dict) else []
        opts = [v for v in _type_spellings(elf) if v not in refused]
        if not opts:
            return None
        return answer(opts[0], f"e_type={elf['type']} in {where}", conf, subject=mem,
                      alternatives=opts[1:])
    if field == "entry_point":
        return answer(f"0x{elf['entry']:x}", f"e_entry of {where}", conf, subject=mem)
    if field == "has_symtab":
        has = any(s["type"] == 2 or s["name"] == ".symtab" for s in elf["secs"])
        return answer("true" if has else "false", f"section table of {where}", conf, subject=mem)
    if field == "marker":
        sec = _section(elf, ".huntress")
        if sec is None:
            return answer("none", f"no .huntress section in {where}", conf, subject=mem)
        if sec["type"] == 8:
            return None
        blob = elf["raw"][sec["offset"]:sec["offset"] + sec["size"]]
        parts = [p.decode("utf-8", "replace").strip() for p in blob.split(b"\x00")]
        parts = [p for p in parts if p and "\n" not in p]
        if not parts:
            return None
        return answer(parts[0], f"string in .huntress of {where}",
                      conf if len(parts) == 1 else min(conf, 0.85), subject=mem)
    if field == "exported_symbol":
        name, sure = _designated(elf)
        if not name:
            if not _none_ok(q):
                return None
            has_symtab = any(s["type"] == 2 for s in elf["secs"])
            why = "stripped (no .symtab)" if not has_symtab else "symbol tables checked"
            return answer("none", f"{why}; no non-runtime global symbol in .dynsym/.symtab "
                                  f"of {where}", conf, subject=mem)
        return answer(name, f"designated non-runtime global symbol in {where}",
                      conf if sure else 0.7, subject=mem)
    if field == "recover_code":
        funcs = _named_funcs(elf, "recover_code")
        for s in funcs:
            v = _sym_const(elf, s)
            if v is not None:
                return answer(str(v), f"immediate returned by recover_code in {where}",
                              conf, subject=mem)
        if funcs:
            return None
        if (q.kind or "") == "integer":
            name, sure = _designated(elf)
            for s in (_named_funcs(elf, name) if name else []):
                v = _sym_const(elf, s)
                if v is not None:
                    return answer(str(v), f"recover_code absent; constant returned by {name} "
                                          f"in {where}", 0.8, subject=mem)
            return None
        return answer("none", f"no recover_code symbol in {where}", conf, subject=mem)
    return None


@handler(priority=90, challenges=(r".*elf-orientation.*",))
def elf_slot_field(q, ctx):
    qid = (q.id or "").lower()
    mm = _SLOT_RE.match(qid)
    if not mm and qid != "recover_code":
        return None
    elves = _elves(q, ctx)
    if not elves:
        print(f"elf_slot_field: no ELF found for {qid}")
        return None
    if mm:
        field = mm.group(2)
        if field not in _FIELDS:
            return None
        mem, elf, conf = _slot_member(elves, int(mm.group(1)))
        if elf is None:
            print(f"elf_slot_field: no slot member for {qid} among {[m.path for m, _ in elves]}")
            return None
        return _field(q, field, mem, elf, conf)
    if len(elves) == 1:
        return _field(q, "recover_code", elves[0][0], elves[0][1], 0.95)
    return None
