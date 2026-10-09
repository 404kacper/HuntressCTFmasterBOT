"""In-memory view of downloaded artifacts, with lazy expansion of containers.

Nothing is ever extracted to disk or executed. Listing a container reads only
its directory; a member's bytes are decompressed (or decrypted) the first
time something actually reads `member.data`, so the timed path pays only for
the files the questions are about. The size budget is charged when bytes are
actually produced, so a huge member is still listed (and still counts when a
question asks "which file") but reading it fails cleanly.

A member that cannot be read raises UnreadableMember instead of handing out
garbage; the solver turns that into a held answer. A container that cannot
be listed is marked `expand_failed`, so nobody mistakes it for a plain file.
"""
from __future__ import annotations

import io
import posixpath
import struct
import tarfile
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable

MAX_DEPTH = 4
MAX_TOTAL_BYTES = 512 * 1024 * 1024
ZIP_PASSWORDS = (b"infected", b"malware", b"virus")


class UnreadableMember(Exception):
    pass


Loader = Callable[[list], "bytes | None"]


class Member:
    def __init__(self, name: str, chain: tuple[str, ...], order: int, depth: int, *,
                 data: bytes | None = None, loader: Loader | None = None,
                 mtime: datetime | None = None, stored_crc: int | None = None,
                 notes: list[str] | None = None, name_is_guess: bool = False):
        self.name = name  # path inside its container (or the top-level artifact name)
        self.chain = chain  # names from the top-level artifact down to this member
        self.order = order  # position inside its container (archive order)
        self.depth = depth
        self.mtime = mtime
        self.stored_crc = stored_crc
        self.notes: list[str] = notes if notes is not None else []
        # True when the name was decoded with a guessed encoding or made up
        # (a gzip without a stored name): never report it as a fact.
        self.name_is_guess = name_is_guess
        self.container: str | None = None  # zip | tar | gzip, once children() looked
        self.expand_failed = False  # looks like a container but could not be listed
        self._data = data
        self._loader = loader
        self._failed = data is None and loader is None

    def __repr__(self) -> str:
        return f"Member({self.path!r})"

    @property
    def data(self) -> bytes:
        if self._data is None and not self._failed:
            loader, self._loader = self._loader, None
            try:
                self._data = loader(self.notes) if loader else None
            except Exception as e:  # corrupt deflate, truncated tar, MemoryError, ...
                self.notes.append(f"unreadable: {type(e).__name__}: {e}")
            self._failed = self._data is None
        if self._failed:
            raise UnreadableMember(f"{self.path}: " + ("; ".join(self.notes) or "no data"))
        return self._data  # type: ignore[return-value]

    @property
    def key(self) -> str:
        return norm_name(self.name)

    @property
    def basename(self) -> str:
        return posixpath.basename(self.key)

    @property
    def path(self) -> str:
        return " -> ".join(self.chain)

    @property
    def ext(self) -> str:
        b = self.basename
        return b.rsplit(".", 1)[-1].lower() if "." in b.lstrip(".") else ""


def norm_name(name: str) -> str:
    """'./a//b\\c' -> 'a/b/c': names extractors treat as the same path compare equal."""
    n = posixpath.normpath(name.replace("\\", "/")).lstrip("/")
    while n.startswith("./"):
        n = n[2:]
    return "" if n == "." else n


def container_kind(data: bytes) -> str | None:
    # Only a container if it *starts* like one: a JPEG or EXE with a zip
    # appended is still a JPEG/EXE, and a tar whose last member is a .docx is
    # still a tar (zipfile.is_zipfile would say "zip" to both).
    if _is_tar(data):
        return "tar"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    return None


class ArtifactSet:
    def __init__(self, tops: list[tuple[str, bytes]]):
        self.tops = [Member(name or f"artifact{i}", (name or f"artifact{i}",), i, 0, data=data,
                            name_is_guess=not name)
                     for i, (name, data) in enumerate(tops)]
        self._kids: dict[int, list[Member]] = {}
        self._budget = MAX_TOTAL_BYTES

    # ---- expansion -------------------------------------------------------
    def children(self, m: Member) -> list[Member]:
        key = id(m)
        if key not in self._kids:
            try:
                self._kids[key] = self._expand(m) if m.depth < MAX_DEPTH else []
            except UnreadableMember:
                self._kids[key] = []
            except Exception as e:  # MemoryError and anything else a hostile archive finds
                m.notes.append(f"could not list: {type(e).__name__}: {e}")
                m.expand_failed = True
                self._kids[key] = []
        return self._kids[key]

    def _expand(self, m: Member) -> list[Member]:
        data = m.data
        m.container = container_kind(data)
        if m.container == "zip":
            return self._expand_zip(m)
        if m.container == "gzip":
            return self._expand_gzip(m, data)
        if m.container == "tar":
            return self._expand_tar(m, data, charge=True)
        return []

    def _budgeted(self, size_hint: int, loader: Loader, charge: bool = True) -> Loader:
        def load(notes: list) -> bytes | None:
            if size_hint > self._budget:
                notes.append(f"not read: declares {size_hint} bytes, over the size budget")
                return None
            data = loader(notes)
            if data is not None and charge:
                self._budget -= len(data)
            return data
        return load

    def _expand_zip(self, m: Member) -> list[Member]:
        out: list[Member] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(m.data))
            infos = zf.infolist()
        except Exception as e:  # BadZipFile, odd name encodings, ...
            m.notes.append(f"bad zip: {type(e).__name__}: {e}")
            m.expand_failed = True
            return out
        named = [(info, *_zip_name(info)) for info in infos]
        dupes = Counter(norm_name(n) for _, n, _, _ in named)
        for i, (info, name, guess, note) in enumerate(named):
            if info.is_dir():
                continue
            kid = Member(name, m.chain + (name,), i, m.depth + 1,
                         loader=self._budgeted(info.file_size,
                                               lambda notes, info=info: _read_zip_member(zf, info, notes)),
                         mtime=_zip_time(info.date_time), stored_crc=info.CRC, name_is_guess=guess)
            if note:
                kid.notes.append(note)
            if dupes[norm_name(name)] > 1:
                kid.notes.append("duplicate entry name in this container")
            out.append(kid)
        return out

    def _expand_gzip(self, m: Member, data: bytes) -> list[Member]:
        stored = _gzip_fname(data)
        d = zlib.decompressobj(31)
        try:
            inner = d.decompress(data, self._budget + 1)
        except zlib.error as e:
            m.notes.append(f"bad gzip: {e}")
            m.expand_failed = True
            return []
        if len(inner) > self._budget:
            m.notes.append("gzip not expanded: decompresses past the size budget")
            m.expand_failed = True
            return []
        if not d.eof:
            m.notes.append("gzip stream is truncated")
        self._budget -= len(inner)
        if stored:
            child_name, guess = stored, False
        else:  # no name in the header: whatever we call it is made up
            child_name = m.basename[:-3] if m.basename.lower().endswith(".gz") else m.basename + ".out"
            guess = True
        if _is_tar(inner):  # .tar.gz: list the tar's members directly under the .gz
            return self._expand_tar(m, inner, charge=False)
        return [Member(child_name, m.chain + (child_name,), 0, m.depth + 1, data=inner, name_is_guess=guess)]

    def _expand_tar(self, m: Member, data: bytes, charge: bool) -> list[Member]:
        out: list[Member] = []
        errors = (tarfile.TarError, OSError, EOFError, zlib.error)
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except errors as e:
            m.notes.append(f"bad tar: {e}")
            m.expand_failed = True
            return out
        infos = []
        try:
            for ti in tf:  # iterate so a truncated tail keeps what came before
                infos.append(ti)
        except errors as e:
            m.notes.append(f"tar stopped early: {e}")
        dupes = Counter(norm_name(ti.name) for ti in infos)
        for i, ti in enumerate(infos):
            if not ti.isfile():
                continue

            def load(notes, ti=ti):
                f = tf.extractfile(ti)
                return f.read() if f is not None else None
            guess = any(0xDC80 <= ord(c) <= 0xDCFF for c in ti.name)  # undecodable bytes in the name
            kid = Member(ti.name, m.chain + (ti.name,), i, m.depth + 1,
                         loader=self._budgeted(ti.size, load, charge), mtime=_unix_time(ti.mtime),
                         name_is_guess=guess)
            if dupes[norm_name(ti.name)] > 1:
                kid.notes.append("duplicate entry name in this container")
            out.append(kid)
        return out

    # ---- lookup ----------------------------------------------------------
    def files(self, root: Member | None = None) -> list[Member]:
        """Every member, depth first, in archive order (expands everything)."""
        out: list[Member] = []

        def walk(m: Member):
            out.append(m)
            for k in self.children(m):
                walk(k)

        for t in [root] if root else self.tops:
            walk(t)
        return out

    def top(self, name: str | None) -> Member | None:
        if len(self.tops) == 1:
            return self.tops[0]  # the download name often differs from the label
        if not name:
            return None
        return _match(self.tops, name)

    def resolve(self, chain: list[str] | tuple[str, ...]) -> Member | None:
        if not chain:
            return None
        cur = self.top(chain[0])
        if cur is None:
            return None
        hit = self._walk(cur, chain[1:])
        if hit is None and len(self.tops) == 1:
            # The question may name the inner file without naming the container.
            hit = self._walk(cur, chain)
        return hit

    def _walk(self, cur: Member, parts) -> Member | None:
        for part in parts:
            cur = _match(self.children(cur), part)
            if cur is None:
                return None
        return cur


def _match(members: list[Member], name: str) -> Member | None:
    """Normalised path, then case-insensitive, then basename. Every step needs
    a unique hit: duplicate names are ambiguous, so they resolve to nothing."""
    want = norm_name(name)
    for key, target in ((lambda m: m.key, want),
                        (lambda m: m.key.casefold(), want.casefold()),
                        (lambda m: m.basename.casefold(), posixpath.basename(want).casefold())):
        hits = [m for m in members if key(m) == target]
        if hits:
            return hits[0] if len(hits) == 1 else None
    return None


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def _zip_name(info: zipfile.ZipInfo) -> tuple[str, bool, str | None]:
    """(name, is_guess, note). Without the UTF-8 flag Python decodes names as
    cp437; Info-ZIP on a UTF-8 locale stores UTF-8 without setting the flag."""
    name = info.filename
    if info.flag_bits & 0x800 or name.isascii():
        return name, False, None
    try:
        utf8 = info.filename.encode("cp437").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return name, True, "non-ASCII name without the UTF-8 flag; cp437 reading may be wrong"
    return utf8, True, f"name stored without the UTF-8 flag; read as UTF-8 (cp437 would give {name!r})"


def _gzip_fname(data: bytes) -> str | None:
    """The original filename stored in a gzip header (FNAME), if any."""
    try:
        flags = data[3]
        pos = 10
        if flags & 0x04:  # FEXTRA
            (xlen,) = struct.unpack_from("<H", data, pos)
            pos += 2 + xlen
        if flags & 0x08:  # FNAME, zero-terminated latin-1
            end = data.index(b"\0", pos)
            return norm_name(data[pos:end].decode("latin-1")) or None
    except (IndexError, ValueError, struct.error):
        return None
    return None


def _zip_time(dt) -> datetime | None:
    try:
        return datetime(*dt)
    except (TypeError, ValueError):
        return None


def _unix_time(ts) -> datetime | None:
    if not ts:
        return None
    try:  # fromtimestamp() rejects negatives on Windows; this does not
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ts)
    except (OverflowError, ValueError, OSError, TypeError):
        return None


def _read_zip_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, notes: list[str]) -> bytes | None:
    encrypted = bool(info.flag_bits & 0x1)
    for pwd in ((None,) + ZIP_PASSWORDS) if encrypted else (None,):
        try:
            data = zf.read(info, pwd=pwd)
        except RuntimeError:  # password required / rejected
            continue
        except Exception as e:
            if encrypted:
                # ZipCrypto's password check is one byte: 1 in 256 wrong
                # passwords pass it and decrypt to garbage that then fails
                # CRC/inflate/bzip2/lzma. Never treat that as data.
                continue
            if isinstance(e, zipfile.BadZipFile) and "CRC" in str(e):
                # The stored CRC is itself a label that can lie; read the bytes anyway.
                with zf.open(info) as f:
                    f._expected_crc = None  # type: ignore[attr-defined]
                    data = f.read()
                notes.append("stored CRC-32 does not match the bytes")
                return data
            raise
        if pwd:
            notes.append(f"decrypted with password {pwd.decode()!r}")
        return data
    notes.append("encrypted; no known password produced valid data")
    return None
