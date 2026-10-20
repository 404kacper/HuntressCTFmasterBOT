# learned-module: elf_section_name_list
"""ELF section names in section-header-table order, as a JSON array.

Parses e_shoff / e_shentsize / e_shnum / e_shstrndx (with the SHN_XINDEX and
e_shnum==0 extended-numbering escapes), reads every section header's sh_name
and resolves it in the section-name string table. The ELF is chosen from the
question's artifact; in multi-day bundles the day number from the question id
(dNN_...) or text ("Day N") selects the dNN-- member. The value includes the
empty name of section index 0; the variant without it is an alternative."""
import json
import re
import struct

from hunt.learn.kit import answer, data, leaves, target
from hunt.solvers import handler


def _cstr(blob, off):
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    raw = blob[off:(end if end >= 0 else len(blob))]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _section_names(raw):
    """None if not a parseable ELF; [] if it has no section header table."""
    if not raw or len(raw) < 52 or raw[:4] != b"\x7fELF":
        return None
    cls, ed = raw[4], raw[5]
    if cls not in (1, 2) or ed not in (1, 2):
        return None
    e = "<" if ed == 1 else ">"
    try:
        if cls == 2:
            shoff = struct.unpack_from(e + "Q", raw, 0x28)[0]
            shes, shn, shstr = struct.unpack_from(e + "HHH", raw, 0x3a)
        else:
            shoff = struct.unpack_from(e + "I", raw, 0x20)[0]
            shes, shn, shstr = struct.unpack_from(e + "HHH", raw, 0x2e)
    except struct.error:
        return None
    if not shoff:
        return []
    if shes < (0x40 if cls == 2 else 0x28):
        return None

    def hdr(i):
        off = shoff + i * shes
        if cls == 2:
            nm = struct.unpack_from(e + "I", raw, off)[0]
            so, ss = struct.unpack_from(e + "QQ", raw, off + 0x18)
            link = struct.unpack_from(e + "I", raw, off + 0x28)[0]
        else:
            nm = struct.unpack_from(e + "I", raw, off)[0]
            so, ss, link = struct.unpack_from(e + "III", raw, off + 0x10)
        return nm, so, ss, link

    try:
        first = hdr(0)
    except struct.error:
        return None
    if shn == 0:
        shn = first[2]          # extended numbering: count in section 0 sh_size
    if shstr == 0xFFFF:
        shstr = first[3]        # SHN_XINDEX: index in section 0 sh_link
    if shn <= 0 or shn > 100000:
        return None
    hdrs = []
    for i in range(shn):
        try:
            hdrs.append(hdr(i))
        except struct.error:
            return None
    tab = b""
    if 0 <= shstr < len(hdrs):
        so, ss = hdrs[shstr][1], hdrs[shstr][2]
        tab = raw[so:so + ss]
    return [_cstr(tab, h[0]) for h in hdrs]


def _day(q):
    m = re.search(r"(?:^|\.)d0*(\d+)_", (q.id or "").lower())
    if m:
        return int(m.group(1))
    low = (q.text or "").lower()
    m = re.search(r"\bd0*(\d+)--", low)
    if m:
        return int(m.group(1))
    m = re.search(r"\bday\s*0*(\d+)\b", low)
    if m:
        return int(m.group(1))
    return None


def _pool(q, ctx):
    root = target(q, ctx)
    out, seen = [], set()
    cands = ([root] + list(leaves(ctx, root))) if root is not None else list(leaves(ctx))
    for m in cands:
        if m is None or m.path in seen:
            continue
        seen.add(m.path)
        out.append(m)
    return out


def _elfs(members):
    found = []
    for m in members:
        raw = data(m)
        if not raw or raw[:4] != b"\x7fELF":
            continue
        names = _section_names(raw)
        if names is not None:
            found.append((m, names))
    found.sort(key=lambda c: c[0].order)
    return found


@handler(priority=80, lanes=("binary-reverse-engineering",),
         challenges=(r"binary-reverse-engineering.*",))
def elf_section_names(q, ctx):
    hay = q.haystack or ""
    if "section" in hay:
        print(f"[secnames] called for {q.id} kind={q.kind}")
    if not re.search(r"section[\s_-]*names", hay):
        return None
    if not ("json" in (q.kind or "").lower() or "array" in hay or "list" in hay):
        return None
    elfs = _elfs(_pool(q, ctx))
    if not elfs:
        elfs = _elfs(list(leaves(ctx)))
    if not elfs:
        print("[secnames] no ELF found")
        return None
    day = _day(q)
    if day is not None and len(elfs) > 1:
        pref = [c for c in elfs
                if re.match(rf"d0*{day}(?!\d)", (c[0].basename or "").lower())]
        if pref:
            elfs = pref
    mem, names = elfs[0]
    conf = 0.95 if len(elfs) == 1 else 0.75
    if not names:
        conf = min(conf, 0.85)
    print(f"[secnames] {mem.path}: {names}")

    with_null = list(names)
    without = names[1:] if names and names[0] == "" else list(names)
    cands = []
    for arr in (with_null, without):
        cands.append(json.dumps(arr, separators=(",", ":"), ensure_ascii=False))
    for arr in (with_null, without):
        cands.append(json.dumps(arr, ensure_ascii=False))
    refused = []
    if isinstance(q.raw, dict):
        refused = q.raw.get("refused_by_game_master") or []
    opts = []
    for c in cands:
        if c not in opts and c not in refused:
            opts.append(c)
    if not opts:
        return None
    return answer(opts[0], f"{len(names)} section headers of {mem.path} resolved via e_shstrndx",
                  conf, subject=mem, alternatives=opts[1:])
