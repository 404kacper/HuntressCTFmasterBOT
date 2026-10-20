# learned-module: bre_managed_config_facts
"""Day-03 'managed configuration' bundle: one evidence.zip with a Day-1 C ELF,
a Day-2 C++ ELF, and a Day-3 .NET managed PE (+runtimeconfig.json). Answers
per-day sha256, ELF/PE machine, container+runtime format, ELF type, CLI
metadata version, the SHT_SYMTAB symbol-name list, and the embedded config.

The config is an HCFG-style blob: magic(4) version(1) xorkey(1) len(2 LE)
crc32(4 LE) then the single-byte-XOR'd JSON payload. We find it structurally
(a key byte whose payload XORs to '{' and parses as a JSON object), so renamed
or re-valued variants still resolve. Gated by the dNN_(artifact|analysis)_ id
scheme unique to this bundle."""
import json
import re
import struct
import zlib

from hunt.learn.kit import answer, data, leaves
from hunt.forensics.identity import digest
from hunt.solvers import handler

_ELF_MACH = {
    62: ("x86-64", ["x86_64", "AMD64", "Advanced Micro Devices X86-64", "EM_X86_64", "0x3e", "62"]),
    183: ("AArch64", ["ARM64", "EM_AARCH64", "0xb7", "183"]),
    3: ("x86", ["Intel 80386", "i386", "EM_386", "0x3", "3"]),
    40: ("ARM", ["EM_ARM", "0x28", "40"]),
    243: ("RISC-V", ["EM_RISCV", "0xf3", "243"]),
}
_PE_MACH = {
    0x14c: ("i386", ["x86", "Intel 386", "I386", "IMAGE_FILE_MACHINE_I386", "0x14c", "332"]),
    0x8664: ("x86-64", ["AMD64", "x86_64", "IMAGE_FILE_MACHINE_AMD64", "0x8664", "34404"]),
    0xaa64: ("ARM64", ["AArch64", "IMAGE_FILE_MACHINE_ARM64", "0xaa64", "43620"]),
    0x1c0: ("ARM", ["IMAGE_FILE_MACHINE_ARM", "0x1c0", "448"]),
}
_ETYPE = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_EDESC = {0: "None", 1: "Relocatable file", 2: "Executable file",
          3: "Shared object file", 4: "Core file"}


def _cstr(blob, off):
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    raw = blob[off:(end if end >= 0 else len(blob))]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _parse_elf(raw):
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
    etype, mach, _v, entry, _ph, shoff, _fl, _eh, _phe, _phn, shes, shn, shstr = t
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
    for si, s in enumerate(secs):
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
            syms.append({"name": name, "value": val, "size": size, "bind": info >> 4,
                         "stype": info & 0xF, "shndx": shndx, "idx": len(syms),
                         "tab": s["type"], "sec": si, "entry": i})
    return {"class": cls, "endian": e, "type": etype, "machine": mach, "entry": entry,
            "secs": secs, "syms": syms, "raw": raw}


def _parse_pe(raw):
    if not raw or raw[:2] != b"MZ" or len(raw) < 0x40:
        return None
    try:
        lf = struct.unpack_from("<I", raw, 0x3c)[0]
        if raw[lf:lf + 4] != b"PE\x00\x00":
            return None
        machine = struct.unpack_from("<H", raw, lf + 4)[0]
        magic = struct.unpack_from("<H", raw, lf + 24)[0]
        ndd_off = lf + 24 + (92 if magic == 0x10b else 108)
        numdd = struct.unpack_from("<I", raw, ndd_off)[0]
        clr = struct.unpack_from("<I", raw, ndd_off + 4 + 14 * 8)[0] if numdd > 14 else 0
    except struct.error:
        return None
    return {"machine": machine, "magic": magic, "dotnet": clr != 0}


def _parse_cli(raw):
    i = raw.find(b"BSJB")
    if i < 0:
        return None
    try:
        _maj, _min, _res, vlen = struct.unpack_from("<HHII", raw, i + 4)
        ver = raw[i + 16:i + 16 + vlen].split(b"\x00")[0].decode("latin-1")
    except (struct.error, UnicodeDecodeError):
        return None
    return {"version": ver}


def _json_obj(payload):
    s = payload.decode("utf-8", "ignore")
    start = s.find("{")
    if start < 0:
        return None, None
    try:
        obj, end = json.JSONDecoder().raw_decode(s[start:])
    except ValueError:
        return None, None
    if not isinstance(obj, dict):
        return None, None
    return obj, s[start:start + end]


def _find_config_hcfg(raw):
    n = len(raw)
    for i in range(0, n - 13):
        key = raw[i + 5]
        try:
            plen = struct.unpack_from("<H", raw, i + 6)[0]
        except struct.error:
            continue
        if plen < 4 or i + 12 + plen > n:
            continue
        if raw[i + 12] ^ key != 0x7b:
            continue
        enc = raw[i + 12:i + 12 + plen]
        payload = bytes(b ^ key for b in enc)
        obj, jtxt = _json_obj(payload)
        if obj:
            crc = struct.unpack_from("<I", raw, i + 8)[0]
            return {"cfg": obj, "key": key, "crc": crc, "payload": payload,
                    "enc": enc, "jtxt": jtxt}
    return None


def _find_config_brute(raw):
    for key in range(1, 256):
        dec = bytes(b ^ key for b in raw)
        for m in re.finditer(rb'\{"', dec):
            s = m.start()
            obj, jtxt = _json_obj(dec[s:s + 8192])
            if obj:
                jb = jtxt.encode("utf-8") if jtxt else b""
                return {"cfg": obj, "key": key, "crc": None, "payload": jb,
                        "enc": None, "jtxt": jtxt}
    return None


def _get_config(raw):
    if not raw:
        return None
    return _find_config_hcfg(raw) or _find_config_brute(raw)


def _cfg_get(cfg, name):
    for k in cfg:
        if str(k).lower() == name:
            return cfg[k]
    return None


def _day_members(ctx, day):
    out = [m for m in leaves(ctx)
           if re.match(r"d0*%d(\D|$)" % day, (m.basename or "").lower())]
    out.sort(key=lambda x: x.order)
    if out:
        return out
    pe = celf = cppelf = None
    jsons = []
    for m in leaves(ctx):
        raw = data(m)
        if not raw:
            continue
        if raw[:2] == b"MZ":
            pe = m
        elif raw[:4] == b"\x7fELF":
            if b"config_blob" in raw or b"_ZN" in raw or b"_ZL" in raw:
                cppelf = m
            else:
                celf = m
        elif raw[:1] in (b"{", b"[") or (m.basename or "").lower().endswith(".json"):
            jsons.append(m)
    if day == 1 and celf:
        return [celf]
    if day == 2 and cppelf:
        return [cppelf]
    if day == 3 and pe:
        return [pe] + sorted(jsons, key=lambda x: x.order)
    return []


def _primary(members):
    for m in members:
        raw = data(m)
        if raw and (raw[:2] == b"MZ" or raw[:4] == b"\x7fELF"):
            return m
    return members[0] if members else None


def _uniq(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def _js(x):
    return json.dumps(x, separators=(",", ":"), ensure_ascii=False)


def _refused(q):
    if isinstance(q.raw, dict):
        return q.raw.get("refused_by_game_master") or []
    return []


def _symbol_names(q, elf, prim, day):
    hay = q.haystack or ""
    want = 11 if ("dynsym" in hay and "symtab" not in hay) else 2
    tabname = ".dynsym" if want == 11 else ".symtab"
    rows = [s for s in elf["syms"] if s["tab"] == want]
    rows.sort(key=lambda s: (s["sec"], s["entry"]))
    names = [s["name"] for s in rows if s["name"]]
    print(f"[mcf] day{day} {tabname} nonempty names ({len(names)}): {names}")
    if not rows:
        has_tab = any(s["type"] == want for s in elf["secs"])
        if not has_tab:
            return answer("[]", f"no {tabname} section in {prim.path}", 0.9, subject=prim)
        return None
    cands = [_js(names)]
    stripped = [n.split("@")[0] for n in names]
    if stripped != names:
        cands.append(_js(stripped))
    # raw string-table walk as a cross-check spelling (same table, entry order)
    cands.append(json.dumps(names, ensure_ascii=False))
    refused = _refused(q)
    opts = [c for c in _uniq(cands) if c not in refused]
    if not opts:
        return None
    return answer(opts[0], f"all {len(names)} nonempty {tabname} names in entry order of "
                  f"{prim.path}", 0.95, subject=prim, alternatives=opts[1:])


@handler(priority=90, lanes=("binary-reverse-engineering",))
def managed_config_facts(q, ctx):
    qid = (q.id or "").lower()
    mm = re.search(r"d0*(\d+)_(artifact|analysis)_(.+)", qid)
    if not mm:
        return None
    day, field = int(mm.group(1)), mm.group(3)
    members = _day_members(ctx, day)
    if not members:
        print(f"[mcf] no members for day {day}")
        return None
    prim = _primary(members)
    raw = data(prim) if prim else None

    sm = re.match(r"sha256_(\d+)$", field)
    if sm:
        k = int(sm.group(1))
        if 1 <= k <= len(members):
            mem = members[k - 1]
            mr = data(mem)
            if mr is None:
                return None
            return answer(digest("sha256", mr), f"sha256 of {mem.path}", 0.97, subject=mem)
        return answer("none", f"day {day} has {len(members)} artifacts; #{k} absent", 0.9)

    elf = _parse_elf(raw) if raw else None
    pe = _parse_pe(raw) if raw else None

    if field == "machine":
        if elf:
            v, alts = _ELF_MACH.get(elf["machine"], (f"EM_{elf['machine']}", [str(elf['machine'])]))
            return answer(v, f"ELF e_machine={elf['machine']} in {prim.path}", 0.95,
                          subject=prim, alternatives=alts)
        if pe:
            v, alts = _PE_MACH.get(pe["machine"], (f"0x{pe['machine']:x}", [str(pe['machine'])]))
            return answer(v, f"PE Machine=0x{pe['machine']:x} in {prim.path}", 0.95,
                          subject=prim, alternatives=alts)
        return None

    if field == "format":
        if elf:
            v = "ELF64" if elf["class"] == 2 else "ELF32"
            return answer(v, f"ELF class {elf['class']} in {prim.path}", 0.95,
                          subject=prim, alternatives=["ELF", v.replace("ELF", "ELF ") + "-bit"])
        if pe:
            cont = "PE32" if pe["magic"] == 0x10b else "PE32+"
            if pe["dotnet"]:
                alts = [f"{cont}/CLR", f"{cont}-CLR", f"{cont} CLR", f"{cont}_CLI",
                        f"{cont}_.NET", f"{cont}/.NET", "PE_CLR", "PE/CLI", "PE_.NET"]
                return answer(f"{cont}_CLR", f"PE magic 0x{pe['magic']:x} + CLR directory in "
                              f"{prim.path}", 0.92, subject=prim, alternatives=alts)
            return answer(cont, f"PE magic 0x{pe['magic']:x} in {prim.path}", 0.9,
                          subject=prim, alternatives=["PE", "Portable Executable"])
        return None

    if field == "elf_type" and elf:
        t = elf["type"]
        short = _ETYPE.get(t, str(t))
        desc = _EDESC.get(t, "")
        alts = [f"ET_{short}", short, desc, str(t), f"0x{t:x}"] if desc else [str(t), f"0x{t:x}"]
        primary = f"{short} ({desc})" if desc else str(t)
        return answer(primary, f"ELF e_type={t} in {prim.path}", 0.95, subject=prim,
                      alternatives=[a for a in alts if a])

    if field == "metadata_version" and pe:
        cli = _parse_cli(raw)
        if cli:
            return answer(cli["version"], f"CLI metadata root version in {prim.path}",
                          0.95, subject=prim)
        return None

    if field == "symbols" and elf:
        return _symbol_names(q, elf, prim, day)

    if field == "xor_key_hex" or field.startswith("config_"):
        info = _get_config(raw)
        if not info:
            print(f"[mcf] no config blob in {prim.path if prim else '?'}")
            return None
        if field == "xor_key_hex":
            return answer(f"0x{info['key']:02x}",
                          f"single-byte XOR key from config header in {prim.path}",
                          0.95, subject=prim)
        sub = field[len("config_"):]
        if sub == "crc32_hex":
            cands = []
            if info.get("crc") is not None:
                cands.append(info["crc"])
            cands.append(zlib.crc32(info["payload"]) & 0xffffffff)
            if info.get("jtxt"):
                cands.append(zlib.crc32(info["jtxt"].encode("utf-8")) & 0xffffffff)
            if info.get("enc"):
                cands.append(zlib.crc32(info["enc"]) & 0xffffffff)
            vals = _uniq([f"0x{c:08x}" for c in cands])
            print(f"[mcf] day{day} crc candidates {vals}")
            return answer(vals[0], f"crc32 from config header in {prim.path}", 0.9,
                          subject=prim, alternatives=vals[1:])
        val = _cfg_get(info["cfg"], sub)
        if val is None:
            return answer("none", f"config has no '{sub}' in {prim.path}", 0.9, subject=prim)
        val = str(val)
        if not val or "\n" in val:
            return None
        return answer(val, f"config '{sub}' from decoded blob in {prim.path}", 0.95, subject=prim)
    return None
