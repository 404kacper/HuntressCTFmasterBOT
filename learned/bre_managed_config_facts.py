# learned-module: bre_managed_config_facts
"""BRE delivery-archive facts about the dNN-- specimens (ELF, PE, managed PE).

Every answer is scoped to the delivery the question names: the archive is
target(q, ctx), cross-checked against ctx.artifacts.tops when the label says
"delivery N"; the members are that archive's own dNN-- entries in ZIP
central-directory order (all of them, binaries and support files alike).
Covers: member digests, ELF/PE machine, ELF e_type, SHT_SYMTAB names,
container / container+managed-runtime format, CLR metadata-root version, and
HCFG config records (byte-5 XOR key, CRC32-checked UTF-8 JSON) found at the
start of a section named .hcfg (ELF or PE) or by scanning for HCFG magic.
"""
import hashlib
import io
import json
import re
import struct
import zipfile
import zlib

from hunt.forensics.identity import digest
from hunt.learn.kit import answer, data, files, target
from hunt.solvers import handler

_ID = re.compile(r"^(?:set\d+\.)?d(\d{1,3})_(artifact|analysis)_([a-z0-9_]+)$", re.I)
_DELIVERY = re.compile(r"delivery\s*#?\s*(\d+)", re.I)
_MEMBER_N = re.compile(r"\bmember\s+(\d+)\b", re.I)
_PROP = re.compile(r"top-level\s+[`'\"]?([A-Za-z0-9_.\-]+)[`'\"]?\s+(?:property|key|field)", re.I)

_ELF_MACH = {
    2: ["SPARC", "Sparc", "EM_SPARC"],
    3: ["i386", "Intel 80386", "x86", "EM_386"],
    8: ["MIPS", "MIPS R3000", "EM_MIPS"],
    20: ["PowerPC", "ppc", "EM_PPC"],
    21: ["PowerPC64", "ppc64", "EM_PPC64"],
    22: ["S390", "IBM S/390", "EM_S390"],
    40: ["ARM", "arm", "EM_ARM"],
    43: ["SPARC V9", "sparcv9", "EM_SPARCV9"],
    50: ["IA-64", "Intel IA-64", "EM_IA_64"],
    62: ["x86-64", "x86_64", "AMD64", "Advanced Micro Devices X86-64", "EM_X86_64"],
    183: ["AArch64", "aarch64", "ARM64", "EM_AARCH64"],
    243: ["RISC-V", "riscv", "EM_RISCV"],
    258: ["LoongArch", "loongarch", "EM_LOONGARCH"],
}
_PE_MACH = {
    0x14C: ["i386", "x86", "Intel 386", "I386", "IMAGE_FILE_MACHINE_I386"],
    0x8664: ["x86-64", "AMD64", "x86_64", "IMAGE_FILE_MACHINE_AMD64"],
    0xAA64: ["ARM64", "AArch64", "aarch64", "IMAGE_FILE_MACHINE_ARM64"],
    0x1C0: ["ARM", "IMAGE_FILE_MACHINE_ARM"],
    0x1C4: ["ARMNT", "ARM Thumb-2", "IMAGE_FILE_MACHINE_ARMNT"],
    0x200: ["IA64", "Intel Itanium", "IMAGE_FILE_MACHINE_IA64"],
}
_ELF_TYPE = {
    0: ["ET_NONE", "NONE (None)", "NONE"],
    1: ["ET_REL", "REL (Relocatable file)", "REL"],
    2: ["EXEC (Executable file)", "ET_EXEC", "EXEC", "Executable file"],
    3: ["ET_DYN", "DYN (Position-Independent Executable file)", "DYN (Shared object file)", "DYN"],
    4: ["ET_CORE", "CORE (Core file)", "CORE"],
}


def _uniq(seq, exclude=None):
    out = []
    for s in seq:
        if s and s != exclude and s not in out:
            out.append(s)
    return out


def _cstr(b, off, end=None):
    stop = len(b) if end is None else min(end, len(b))
    if off < 0 or off >= stop:
        return ""
    z = b.find(b"\x00", off, stop)
    raw = b[off:(z if z >= 0 else stop)]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ---------------------------------------------------------------- delivery scoping

def _inside(ctx, m, top):
    if m is top:
        return True
    for x in files(ctx, top):
        if x is m:
            return True
    return False


def _relocate(ctx, m, top):
    if m is None or list(m.chain)[:1] == [] or m.path == top.path:
        return top
    for x in files(ctx, top):
        if x.path == m.path:
            return x
    return top


def _root(q, ctx):
    try:
        tops = list(ctx.artifacts.tops or [])
    except Exception:
        tops = []
    try:
        m = target(q, ctx)
    except Exception:
        m = None
    raw = q.raw if isinstance(q.raw, dict) else {}
    n = None
    dm = _DELIVERY.search(q.artifact or "")
    if dm:
        n = int(dm.group(1))
    elif isinstance(raw.get("set"), int) and len(tops) > 1:
        n = int(raw.get("set"))
    if n is not None and len(tops) > 1 and 1 <= n <= len(tops):
        want = tops[n - 1]
        if m is None or not _inside(ctx, m, want):
            m = _relocate(ctx, m, want)
    if m is None and len(tops) == 1:
        m = tops[0]
    return m


def _children(ctx, root):
    try:
        kids = list(ctx.artifacts.children(root) or [])
    except Exception:
        kids = []
    if not kids:
        rc = list(root.chain)
        for m in files(ctx, root):
            ch = list(m.chain)
            if len(ch) == len(rc) + 1 and ch[:len(rc)] == rc:
                kids.append(m)
    return kids


def _cd_order(root, sel):
    idx = {}
    raw = data(root)
    if raw and raw[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            for i, info in enumerate(z.infolist()):
                if info.filename not in idx:
                    idx[info.filename] = i
            z.close()
        except Exception:
            idx = {}

    def key(m):
        o = m.order if isinstance(m.order, int) else 0
        n = m.name or ""
        pos = idx.get(n, idx.get(n.replace("\\", "/")))
        return (pos if pos is not None else 1000000 + o, o)

    return sorted(sel, key=key)


def _day_members(ctx, root, day):
    prefix = f"d{day}--"
    sel = [m for m in _children(ctx, root) if (m.basename or "").lower().startswith(prefix)]
    if sel:
        return _cd_order(root, sel)
    rc = list(root.chain)
    deep = [m for m in files(ctx, root)
            if list(m.chain) != rc and (m.basename or "").lower().startswith(prefix)]
    if deep:
        return deep
    if (root.basename or "").lower().startswith(prefix):
        return [root]
    return []


# ---------------------------------------------------------------- ELF / PE parsing

def _elf(b):
    if not b or len(b) < 52 or b[:4] != b"\x7fELF":
        return None
    cls, enc = b[4], b[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return None
    e = "<" if enc == 1 else ">"
    hfmt = e + ("HHIIIIIHHHHHH" if cls == 1 else "HHIQQQIHHHHHH")
    if 16 + struct.calcsize(hfmt) > len(b):
        return None
    hdr = struct.unpack_from(hfmt, b, 16)
    etype, mach, phoff, shoff = hdr[0], hdr[1], hdr[4], hdr[5]
    phent, phnum, shent, shnum, shstrndx = hdr[8], hdr[9], hdr[10], hdr[11], hdr[12]
    sfmt = e + ("IIIIIIIIII" if cls == 1 else "IIQQQQIIQQ")
    ssz = struct.calcsize(sfmt)
    secs = []
    if shoff and shent >= ssz and shoff + ssz <= len(b):
        first = struct.unpack_from(sfmt, b, shoff)
        if shnum == 0:
            shnum = first[5]
        if shstrndx == 0xFFFF:
            shstrndx = first[6]
        for i in range(min(shnum, 65536)):
            o = shoff + i * shent
            if o + ssz > len(b):
                break
            s = struct.unpack_from(sfmt, b, o)
            secs.append({"name_off": s[0], "type": s[1], "offset": s[4], "size": s[5],
                         "link": s[6], "entsize": s[9], "name": ""})
        if 0 <= shstrndx < len(secs):
            st = secs[shstrndx]
            for s in secs:
                s["name"] = _cstr(b, st["offset"] + s["name_off"], st["offset"] + st["size"])
    interp = False
    if phoff and phent >= 4:
        for i in range(min(phnum, 4096)):
            o = phoff + i * phent
            if o + 4 > len(b):
                break
            if struct.unpack_from(e + "I", b, o)[0] == 3:
                interp = True
    return {"cls": cls, "enc": enc, "e": e, "type": etype, "machine": mach,
            "secs": secs, "interp": interp}


def _elf_symbols(b, info):
    e, cls, secs = info["e"], info["cls"], info["secs"]
    minent = 16 if cls == 1 else 24
    names = []
    found = False
    for s in secs:
        if s["type"] != 2:
            continue
        found = True
        ent = s["entsize"] if s["entsize"] >= minent else minent
        link = s["link"]
        if not 0 <= link < len(secs):
            continue
        st = secs[link]
        stoff, stend = st["offset"], st["offset"] + st["size"]
        for i in range(s["size"] // ent):
            o = s["offset"] + i * ent
            if o + 4 > len(b):
                break
            nm = struct.unpack_from(e + "I", b, o)[0]
            if nm == 0:
                continue
            name = _cstr(b, stoff + nm, stend)
            if name:
                names.append(name)
    return names, found


def _pe(b):
    if not b or len(b) < 0x40 or b[:2] != b"MZ":
        return None
    lfa = struct.unpack_from("<I", b, 0x3C)[0]
    if lfa + 24 > len(b) or b[lfa:lfa + 4] != b"PE\x00\x00":
        return None
    mach, nsec, _ts, symptr, nsyms, optsz, chars = struct.unpack_from("<HHIIIHH", b, lfa + 4)
    opt = lfa + 24
    magic = struct.unpack_from("<H", b, opt)[0] if opt + 2 <= len(b) else 0
    dirs = []
    nd_off = opt + 92 if magic == 0x10B else (opt + 108 if magic == 0x20B else None)
    if nd_off is not None and nd_off + 4 <= min(len(b), opt + optsz):
        nd = struct.unpack_from("<I", b, nd_off)[0]
        for i in range(min(nd, 16)):
            o = nd_off + 4 + 8 * i
            if o + 8 > opt + optsz or o + 8 > len(b):
                break
            dirs.append(struct.unpack_from("<II", b, o))
    strtab = symptr + nsyms * 18 if symptr else None
    secs = []
    so = opt + optsz
    for i in range(min(nsec, 96)):
        o = so + 40 * i
        if o + 40 > len(b):
            break
        name = b[o:o + 8].split(b"\x00", 1)[0].decode("latin-1")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", b, o + 8)
        if name.startswith("/") and name[1:].isdigit() and strtab is not None:
            name = _cstr(b, strtab + int(name[1:])) or name
        secs.append({"name": name, "vsize": vsize, "va": va, "rsize": rsize, "rptr": rptr})
    return {"machine": mach, "magic": magic, "dirs": dirs, "secs": secs, "chars": chars}


def _rva(pe, rva):
    for s in pe["secs"]:
        span = max(s["vsize"], s["rsize"])
        if s["va"] <= rva < s["va"] + span:
            d = rva - s["va"]
            if d < s["rsize"]:
                return s["rptr"] + d
    return None


def _clr_dir(pe):
    if pe and len(pe["dirs"]) > 14:
        rva, size = pe["dirs"][14]
        if rva and size:
            return rva, size
    return None


def _kind(b):
    if b and b[:4] == b"\x7fELF":
        return "elf"
    if _pe(b) is not None:
        return "pe"
    return None


def _primary(ctx, members, day, managed):
    pool = []
    for m in members:
        b = data(m)
        k = _kind(b) if b else None
        if k:
            pool.append((m, b, k))
    if not pool:
        for m in members:
            mc = list(m.chain)
            for x in files(ctx, m):
                if list(x.chain) == mc:
                    continue
                b = data(x)
                k = _kind(b) if b else None
                if k:
                    pool.append((x, b, k))
    if not pool:
        return None
    vre = re.compile(rf"d{day}--variant-[^.]+(\.(dll|exe|elf|so|bin|out))?")

    def score(t):
        m, b, k = t
        bn = (m.basename or "").lower()
        s = 0
        if bn.startswith(f"d{day}--variant-"):
            s += 4
        if vre.fullmatch(bn):
            s += 2
        if managed:
            if k == "pe" and (_clr_dir(_pe(b)) or b.find(b"BSJB") >= 0):
                s += 3
            if bn.endswith(".dll"):
                s += 1
        return s

    ranked = sorted(pool, key=lambda t: -score(t))
    ambiguous = len(ranked) > 1 and score(ranked[0]) == score(ranked[1])
    m, b, k = ranked[0]
    return m, b, k, ambiguous


# ---------------------------------------------------------------- HCFG records

def _hcfg_at(b, off, limit=None):
    end = len(b) if limit is None else min(limit, len(b))
    if off < 0 or off + 12 > end or b[off:off + 4] != b"HCFG":
        return None
    ver, key = b[off + 4], b[off + 5]
    ln = struct.unpack_from("<H", b, off + 6)[0]
    crc = struct.unpack_from("<I", b, off + 8)[0]
    rec = {"off": off, "ver": ver, "key": key, "len": ln, "crc": crc,
           "calc": None, "obj": None, "valid": False}
    if off + 12 + ln > end:
        return rec
    dec = bytes(x ^ key for x in b[off + 12:off + 12 + ln])
    rec["calc"] = zlib.crc32(dec) & 0xFFFFFFFF
    try:
        rec["obj"] = json.loads(dec.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        rec["obj"] = None
    rec["valid"] = rec["calc"] == crc and isinstance(rec["obj"], dict)
    return rec


def _section_bounds(b, name):
    out = []
    e = _elf(b)
    if e:
        for s in e["secs"]:
            if s["name"] == name and s["type"] != 8:
                out.append((s["offset"], s["offset"] + s["size"]))
        return out
    p = _pe(b)
    if p:
        for s in p["secs"]:
            if s["name"] == name and s["rsize"]:
                out.append((s["rptr"], s["rptr"] + s["rsize"]))
    return out


def _pick_record(b, prefer_section):
    secs = _section_bounds(b, ".hcfg")
    srecs = [r for r in (_hcfg_at(b, lo, hi) for lo, hi in secs) if r]
    if prefer_section:
        good = [r for r in srecs if r["valid"]]
        if good:
            return good[0], (0.95 if len(good) == 1 else 0.85), "start of section .hcfg"
    valid = []
    pos = b.find(b"HCFG")
    while pos >= 0:
        r = _hcfg_at(b, pos)
        if r and r["valid"]:
            valid.append(r)
        pos = b.find(b"HCFG", pos + 1)
    if len(valid) == 1:
        return valid[0], 0.95, "unique CRC32-valid HCFG record"
    if valid:
        inside = [r for r in valid if any(lo <= r["off"] < hi for lo, hi in secs)]
        if len(inside) == 1:
            return inside[0], 0.9, "CRC32-valid HCFG record inside .hcfg"
        return valid[0], 0.8, f"first of {len(valid)} CRC32-valid HCFG records"
    for r in srecs:
        if isinstance(r["obj"], dict):
            return r, 0.8, "HCFG at .hcfg start (CRC32 mismatch)"
    return None, 0.0, ""


# ---------------------------------------------------------------- CLR metadata

def _md_version(b, pe):
    off, how = -1, "CLI header"
    clr = _clr_dir(pe)
    if clr:
        cli = _rva(pe, clr[0])
        if cli is not None and cli + 16 <= len(b):
            md = _rva(pe, struct.unpack_from("<I", b, cli + 8)[0])
            if md is not None and b[md:md + 4] == b"BSJB":
                off = md
    if off < 0:
        off, how = b.find(b"BSJB"), "BSJB scan"
    if off < 0 or off + 16 > len(b):
        return None
    ln = struct.unpack_from("<I", b, off + 12)[0]
    if ln == 0 or ln > 255 or off + 16 + ln > len(b):
        return None
    raw = b[off + 16:off + 16 + ln].rstrip(b"\x00")
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1")
    return s, how, off


# ---------------------------------------------------------------- answers

def _hash(algo, b):
    try:
        h = digest(algo, b)
        if h:
            return str(h).lower()
    except Exception:
        pass
    return hashlib.new(algo, b).hexdigest()


def _artifact_answer(q, day, rest, members):
    am = re.fullmatch(r"(md5|sha1|sha224|sha256|sha384|sha512|size|name|basename)_(\d+)", rest)
    if not am:
        return None
    what, k = am.group(1), int(am.group(2))
    tm = _MEMBER_N.search(q.text or "")
    if tm:
        k = int(tm.group(1))
    print(f"[bre_managed_config_facts] {q.id}: d{day}-- members={[m.path for m in members]}")
    if not 1 <= k <= len(members):
        return None
    mem = members[k - 1]
    b = data(mem)
    if b is None:
        return None
    if what == "size":
        value = str(len(b))
    elif what in ("name", "basename"):
        value = mem.basename
    else:
        value = _hash(what, b)
    return answer(value, f"{what} of {mem.path}, member {k} of {len(members)} d{day}-- "
                         f"members in central-directory order", 0.97, subject=mem)


def _analysis_answer(q, ctx, day, rest, members):
    hay = q.haystack or ""
    text = q.text or ""
    managed = any(w in hay for w in ("managed", "clr", ".net", "bsjb"))
    pick = _primary(ctx, members, day, managed)
    if pick is None:
        return None
    mem, b, kind, ambiguous = pick
    conf = 0.85 if ambiguous else 0.95
    elf = _elf(b) if kind == "elf" else None
    pe = _pe(b) if kind == "pe" else None

    if rest.endswith("machine"):
        if elf:
            code = elf["machine"]
            labels = _ELF_MACH.get(code, [])
            codes = [f"0x{code:x}", str(code)]
            how = f"ELF e_machine={code}"
        elif pe:
            code = pe["machine"]
            labels = _PE_MACH.get(code, [])
            codes = [f"0x{code:x}", str(code), f"0x{code:04x}"]
            how = f"PE Machine=0x{code:x}"
        else:
            return None
        allv = _uniq(labels + codes)
        return answer(allv[0], f"{how} in {mem.path}", conf, subject=mem, alternatives=allv[1:])

    if rest in ("elf_type", "type", "e_type"):
        if not elf:
            return None
        t = elf["type"]
        labels = list(_ELF_TYPE.get(t, []))
        if t == 3 and not elf["interp"]:
            labels = ["ET_DYN", "DYN (Shared object file)",
                      "DYN (Position-Independent Executable file)", "DYN"]
        allv = _uniq(labels + [str(t), f"0x{t:x}"])
        return answer(allv[0], f"ELF e_type={t} in {mem.path}", conf, subject=mem,
                      alternatives=allv[1:])

    if rest.endswith("symbols"):
        if not elf:
            return None
        names, found = _elf_symbols(b, elf)
        value = json.dumps(names, separators=(",", ":"), ensure_ascii=False)
        alts = []
        if any("@" in n for n in names):
            alts.append(json.dumps([n.split("@", 1)[0] for n in names],
                                   separators=(",", ":"), ensure_ascii=False))
        alts.append(json.dumps(names, ensure_ascii=False))
        why = (f"all {len(names)} nonempty SHT_SYMTAB names in entry order of {mem.path}"
               if found else f"no SHT_SYMTAB section in {mem.path}")
        return answer(value, why, min(conf, 0.95 if found else 0.9), subject=mem,
                      alternatives=_uniq(alts, value))

    if rest.endswith("format"):
        compound = any(w in hay for w in ("managed", "runtime", "compound"))
        if elf:
            if compound:
                return None
            base = "ELF32" if elf["cls"] == 1 else "ELF64"
            allv = _uniq([base, "ELF", f"ELF {32 if elf['cls'] == 1 else 64}-bit"])
            return answer(allv[0], f"ELF class {elf['cls']} in {mem.path}", conf,
                          subject=mem, alternatives=allv[1:])
        if not pe:
            return None
        base = "PE32+" if pe["magic"] == 0x20B else "PE32"
        if not compound:
            allv = _uniq([base, "PE", "Portable Executable"])
            return answer(allv[0], f"PE optional-header magic 0x{pe['magic']:x} in {mem.path}",
                          conf, subject=mem, alternatives=allv[1:])
        clr = _clr_dir(pe)
        if not clr and b.find(b"BSJB") < 0:
            return None
        allv = _uniq([f"{base}_CLR", f"{base}/CLR", f"{base}-CLR", f"{base} CLR",
                      f"{base}_CLI", f"{base}_.NET", f"{base}/.NET", "PE_CLR", "PE/CLI"])
        why = "CLR directory" if clr else "BSJB metadata"
        return answer(allv[0], f"PE magic 0x{pe['magic']:x} + {why} in {mem.path}",
                      min(conf, 0.92), subject=mem, alternatives=allv[1:])

    if "metadata_version" in rest or rest in ("clr_version", "runtime_version"):
        if not pe:
            return None
        got = _md_version(b, pe)
        if not got:
            return None
        s, how, off = got
        parts = s.split("\x00")
        value = parts[0]
        if not value or value != value.strip():
            return None
        return answer(value, f"CLI metadata root version at BSJB 0x{off:x}+16 ({how}) "
                             f"in {mem.path}", conf, subject=mem,
                      alternatives=_uniq([s], value) if "\x00" not in s else [])

    if "crc32" in rest or "xor_key" in rest or rest.startswith("config_") or "hcfg" in rest:
        prefer = ".hcfg" in text or "section table" in hay
        rec, rconf, how = _pick_record(b, prefer)
        if rec is None:
            return None
        c = min(conf, rconf)
        where = f"HCFG at 0x{rec['off']:x} ({how}) in {mem.path}"
        if "crc32" in rest:
            value = f"0x{rec['crc']:08x}"
            alts = []
            if rec["calc"] is not None and rec["calc"] != rec["crc"]:
                alts.append(f"0x{rec['calc']:08x}")
            return answer(value, f"header bytes 8..11 of {where}", c, subject=mem,
                          alternatives=alts)
        if "xor_key" in rest:
            return answer(f"0x{rec['key']:02x}", f"header byte 5 of {where}", c, subject=mem)
        pm = _PROP.search(text)
        if pm is None and "version" in rest and "byte 4" in text:
            v = rec["ver"]
            value = f"0x{v:02x}" if "0x" in text else str(v)
            return answer(value, f"header byte 4 of {where}", c, subject=mem)
        if pm is None and ("length" in rest or rest.endswith("_len")) and "6..7" in text:
            return answer(str(rec["len"]), f"header bytes 6..7 of {where}", c, subject=mem)
        prop = pm.group(1) if pm else (rest[len("config_"):] if rest.startswith("config_") else None)
        obj = rec["obj"]
        if not prop or not isinstance(obj, dict) or prop not in obj:
            return None
        v = obj[prop]
        if isinstance(v, str):
            value = v
        elif v is None:
            return None
        elif isinstance(v, (bool, int, float)):
            value = json.dumps(v)
        else:
            value = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
        if not value:
            return None
        return answer(value, f"config '{prop}' from decoded {where}", c, subject=mem)

    return None


@handler(lanes=("binary-reverse-engineering",))
def managed_config_facts(q, ctx):
    mid = _ID.match((q.id or "").strip())
    if not mid:
        return None
    day, area, rest = mid.group(1), mid.group(2).lower(), mid.group(3).lower()
    root = _root(q, ctx)
    if root is None:
        return None
    members = _day_members(ctx, root, day)
    if not members:
        return None
    if area == "artifact":
        return _artifact_answer(q, day, rest, members)
    return _analysis_answer(q, ctx, day, rest, members)
