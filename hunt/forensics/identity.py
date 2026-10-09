"""File identity: digests, true type from magic bytes, and label checks.

`inventory()` is the "deep analysis" pass: it runs on every artifact we touch
(off the clock) and is saved to the archive, so when a question nobody has a
handler for shows up, the answer is usually already sitting in inventory.json.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import zlib

from .artifacts import ArtifactSet, Member


def _h(name):
    return lambda b: hashlib.new(name, b, usedforsecurity=False).hexdigest()


DIGESTS = {
    "md5": (_h("md5"), 32),
    "sha1": (_h("sha1"), 40),
    "sha224": (_h("sha224"), 56),
    "sha256": (_h("sha256"), 64),
    "sha384": (_h("sha384"), 96),
    "sha512": (_h("sha512"), 128),
    "sha3_224": (_h("sha3_224"), 56),
    "sha3_256": (_h("sha3_256"), 64),
    "sha3_384": (_h("sha3_384"), 96),
    "sha3_512": (_h("sha3_512"), 128),
    "blake2b": (_h("blake2b"), 128),
    "blake2s": (_h("blake2s"), 64),
    "crc32": (lambda b: f"{zlib.crc32(b) & 0xFFFFFFFF:08x}", 8),
}

_BY_LENGTH = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512", 8: "crc32"}


def digest(algo: str, data: bytes) -> str:
    return DIGESTS[algo][0](data)


# (offset, magic, type label, extensions that honestly carry it)
MAGIC: list[tuple[int, bytes, str, frozenset[str]]] = [
    (0, b"\x89PNG\r\n\x1a\n", "png", frozenset({"png"})),
    (0, b"\xff\xd8\xff", "jpeg", frozenset({"jpg", "jpeg", "jfif", "jpe"})),
    (0, b"GIF87a", "gif", frozenset({"gif"})),
    (0, b"GIF89a", "gif", frozenset({"gif"})),
    (0, b"%PDF-", "pdf", frozenset({"pdf"})),
    (0, b"PK\x03\x04", "zip", frozenset({"zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods",
                                          "odp", "epub", "xpi", "aab", "ipa", "whl", "nupkg", "vsix"})),
    (0, b"PK\x05\x06", "zip", frozenset({"zip"})),
    (0, b"\x1f\x8b", "gzip", frozenset({"gz", "tgz", "gzip"})),
    (0, b"BZh", "bzip2", frozenset({"bz2", "tbz2"})),
    (0, b"\xfd7zXZ\x00", "xz", frozenset({"xz", "txz"})),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", frozenset({"7z"})),
    (0, b"Rar!\x1a\x07", "rar", frozenset({"rar"})),
    (0, b"MSCF", "cab", frozenset({"cab"})),
    (0, b"\x7fELF", "elf", frozenset({"", "elf", "so", "o", "bin", "out", "ko"})),
    (0, b"MZ", "pe", frozenset({"exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "com", "drv"})),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", frozenset({"doc", "xls", "ppt", "msi", "msg", "dot", "xlt"})),
    (0, b"dex\n", "dex", frozenset({"dex"})),
    (0, b"\xca\xfe\xba\xbe", "java-class/mach-o-fat", frozenset({"class", "dylib", ""})),
    (0, b"\xcf\xfa\xed\xfe", "mach-o", frozenset({"", "dylib", "bundle", "o"})),
    (0, b"\xce\xfa\xed\xfe", "mach-o", frozenset({"", "dylib", "bundle", "o"})),
    (0, b"SQLite format 3\x00", "sqlite", frozenset({"sqlite", "sqlite3", "db", "db3"})),
    (0, b"regf", "registry-hive", frozenset({"dat", "hiv", "hive", ""})),
    (0, b"ElfFile\x00", "evtx", frozenset({"evtx"})),
    (0, b"\xd4\xc3\xb2\xa1", "pcap", frozenset({"pcap", "cap"})),
    (0, b"\xa1\xb2\xc3\xd4", "pcap", frozenset({"pcap", "cap"})),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng", frozenset({"pcapng"})),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", frozenset({"lnk"})),
    (0, b"{\\rtf", "rtf", frozenset({"rtf", "doc"})),
    (0, b"%!PS", "postscript", frozenset({"ps", "eps"})),
    (0, b"OggS", "ogg", frozenset({"ogg", "oga", "ogv", "opus"})),
    (0, b"ID3", "mp3", frozenset({"mp3"})),
    (0, b"fLaC", "flac", frozenset({"flac"})),
    (0, b"II*\x00", "tiff", frozenset({"tif", "tiff", "dng", "cr2", "nef"})),
    (0, b"MM\x00*", "tiff", frozenset({"tif", "tiff"})),
    (0, b"BM", "bmp", frozenset({"bmp", "dib"})),
    (0, b"\x00\x00\x01\x00", "ico", frozenset({"ico"})),
    (0, b"wOFF", "woff", frozenset({"woff"})),
    (0, b"wOF2", "woff2", frozenset({"woff2"})),
]
_RIFF = {b"WAVE": ("wav", {"wav"}), b"WEBP": ("webp", {"webp"}), b"AVI ": ("avi", {"avi"})}
TEXT_EXTS = frozenset({"txt", "log", "csv", "tsv", "md", "json", "xml", "html", "htm", "ini", "cfg", "conf",
                       "yaml", "yml", "ps1", "psm1", "py", "js", "vbs", "bat", "cmd", "sh", "c", "h",
                       "cpp", "java", "php", "rb", "go", "rs", "sql", "eml", "svg", "rtf", "sha256",
                       "md5", "sha1", "sum", "sums", "manifest", "toml", "properties", "smali", "pem",
                       "key", "crt", "hta", "reg", "inf", "url", ""})


def true_type(data: bytes) -> tuple[str, frozenset[str]]:
    for off, sig, label, exts in MAGIC:
        if data[off:off + len(sig)] == sig:
            return label, exts
    if data[:4] == b"RIFF" and data[8:12] in _RIFF:
        label, exts = _RIFF[data[8:12]]
        return label, frozenset(exts)
    if data[4:8] == b"ftyp":
        return "iso-bmff(mp4/mov/heic)", frozenset({"mp4", "m4a", "m4v", "mov", "heic", "heif", "3gp", "avif"})
    if _looks_text(data):
        return "text", TEXT_EXTS
    return "data", frozenset()


def _looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return True
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if sample.startswith(bom):
            sample = sample[len(bom):].decode(enc, "ignore").encode()
            break
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError as e:
        if e.start < len(sample) - 3:  # not just a multibyte char cut at the 4 KiB boundary
            return False
        text = sample[:e.start].decode("utf-8")
    bad = sum(1 for c in text if ord(c) < 32 and c not in "\t\r\n\f")
    return bad <= max(1, len(text) // 100)


# ---- claimed labels inside the artifact (manifests, sum files) -----------
_SUM = re.compile(r"^\s*([0-9a-fA-F]{8,128})\s+[ *]?(.+?)\s*$")  # sha256sum / md5sum
_BSD = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*\((.+)\)\s*=\s*([0-9a-fA-F]{8,128})\s*$")  # SHA256 (f) = x
_KV = re.compile(r"^\s*(.+?)\s*[:=]\s*([0-9a-fA-F]{32,128})\s*$")  # f: x
_ALGO_KEYS = {k.replace("_", ""): k for k in DIGESTS} | {"sha-1": "sha1", "sha-256": "sha256", "sha-512": "sha512"}


def _algo_from(key: str | None, value: str) -> str | None:
    if key:
        k = key.lower().replace("_", "").replace(" ", "")
        if k in _ALGO_KEYS:
            return _ALGO_KEYS[k]
        k = k.replace("-", "")
        if k in _ALGO_KEYS:
            return _ALGO_KEYS[k]
    return _BY_LENGTH.get(len(value))


def claims_in(m: Member) -> list[dict]:
    """Labels one file makes about other files: {target, attribute, value}."""
    if true_type(m.data)[0] != "text" or len(m.data) > 2_000_000:
        return []
    text = m.data.decode("utf-8", "replace")
    out: list[dict] = []
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            out += _claims_json(json.loads(text))
        except ValueError:
            pass
    lines = text.splitlines()
    if not out and lines and "," in lines[0]:
        out += _claims_csv(text)
    if not out:
        for line in lines:
            if mb := _BSD.match(line):
                algo = _algo_from(mb.group(1), mb.group(3))
                if algo:
                    out.append({"target": mb.group(2).strip(), "attribute": algo, "value": mb.group(3).lower()})
            elif ms := _SUM.match(line):
                algo = _algo_from(None, ms.group(1))
                if algo:
                    out.append({"target": ms.group(2).strip(), "attribute": algo, "value": ms.group(1).lower()})
            elif mk := _KV.match(line):
                algo = _algo_from(None, mk.group(2))
                if algo:
                    out.append({"target": mk.group(1).strip(), "attribute": algo, "value": mk.group(2).lower()})
    for c in out:
        c["source"] = m.path
    return out


_NAME_KEYS = ("name", "filename", "file", "path", "file_name")


def _claims_records(rows) -> list[dict]:
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        lower = {str(k).lower().strip(): v for k, v in row.items()}
        target = next((str(lower[k]) for k in _NAME_KEYS if lower.get(k)), None)
        if not target:
            continue
        for k, v in lower.items():
            if k in _NAME_KEYS or v in (None, ""):
                continue
            v = str(v).strip()
            if k in ("size", "bytes", "length", "size_bytes", "filesize") and v.isdigit():
                out.append({"target": target, "attribute": "size", "value": v})
            elif re.fullmatch(r"[0-9a-fA-F]{8,128}", v) and (
                    _algo_from(k, "") or any(w in k for w in ("hash", "digest", "checksum"))):
                algo = _algo_from(k, v)
                if algo:
                    out.append({"target": target, "attribute": algo, "value": v.lower()})
            elif k in ("type", "mime", "filetype", "file_type", "extension", "ext"):
                out.append({"target": target, "attribute": "type", "value": v})
    return out


def _claims_json(obj) -> list[dict]:
    if isinstance(obj, dict):
        rows = obj.get("files") or obj.get("items") or obj.get("entries")
        if isinstance(rows, list):
            return _claims_records(rows)
        if all(isinstance(v, dict) for v in obj.values()):
            return _claims_records([{"name": k, **v} for k, v in obj.items()])
        return []
    return _claims_records(obj) if isinstance(obj, list) else []


def _claims_csv(text: str) -> list[dict]:
    try:
        return _claims_records(csv.DictReader(io.StringIO(text)))
    except csv.Error:
        return []


# ---- inventory -------------------------------------------------------------
def describe(m: Member, algos=("md5", "sha1", "sha256")) -> dict:
    label, exts = true_type(m.data)
    d = {
        "path": m.path,
        "name": m.name,
        "basename": m.basename,
        "order": m.order,
        "size": len(m.data),
        **{a: digest(a, m.data) for a in algos},
        "true_type": label,
        "extension": m.ext,
        "extension_matches_content": (m.ext in exts) if label not in ("data",) else None,
    }
    if m.mtime:
        d["mtime"] = m.mtime.isoformat()
    if m.stored_crc is not None:
        d["stored_crc32"] = f"{m.stored_crc:08x}"
        d["stored_crc32_matches"] = d["stored_crc32"] == digest("crc32", m.data)
    if m.notes:
        d["notes"] = list(m.notes)
    return d


def inventory(arts: ArtifactSet) -> dict:
    members = arts.files()
    files = [describe(m) for m in members]
    claims = [c for m in members for c in claims_in(m)]
    checks = []
    for c in claims:
        want = c["target"].replace("\\", "/")
        targets = [m for m in members if m.name == want or m.basename == want.rsplit("/", 1)[-1]]
        if not targets:
            checks.append({**c, "verdict": "target-missing"})
            continue
        t = targets[0]
        if c["attribute"] == "size":
            actual = str(len(t.data))
        elif c["attribute"] in DIGESTS:
            actual = digest(c["attribute"], t.data)
        else:
            actual = true_type(t.data)[0]
        ok = actual.lower() == str(c["value"]).lower()
        checks.append({**c, "actual": actual, "verdict": "trusted" if ok else "LIES"})
    for m, f in zip(members, files):
        if f["extension_matches_content"] is False:
            checks.append({"source": "filename extension", "target": f["path"], "attribute": "type",
                           "value": f["extension"], "actual": f["true_type"], "verdict": "LIES"})
        if f.get("stored_crc32_matches") is False:
            checks.append({"source": "zip central directory", "target": f["path"], "attribute": "crc32",
                           "value": f["stored_crc32"], "actual": digest("crc32", m.data), "verdict": "LIES"})
    return {"files": files, "label_checks": checks}
