"""In-memory view of downloaded artifacts, with lazy expansion of containers.

Nothing is ever extracted to disk or executed. Listing a container reads only
its directory; a member's bytes are decompressed (or decrypted) the first
time something actually reads `member.data`, so the timed path pays only for
the files the questions are about. Size and depth limits stop zip bombs.
A member that cannot be read raises UnreadableMember instead of handing out
garbage, which the solver engine turns into a held answer.
"""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from posixpath import basename
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
                 notes: list[str] | None = None):
        self.name = name  # path inside its container (or the top-level artifact name)
        self.chain = chain  # names from the top-level artifact down to this member
        self.order = order  # position inside its container (archive order)
        self.depth = depth
        self.mtime = mtime
        self.stored_crc = stored_crc
        self.notes: list[str] = notes if notes is not None else []
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
            except Exception as e:  # corrupt deflate, truncated tar, ...
                self.notes.append(f"unreadable: {type(e).__name__}: {e}")
            self._failed = self._data is None
        if self._failed:
            raise UnreadableMember(f"{self.path}: " + ("; ".join(self.notes) or "no data"))
        return self._data  # type: ignore[return-value]

    @property
    def basename(self) -> str:
        return basename(self.name.rstrip("/"))

    @property
    def path(self) -> str:
        return " -> ".join(self.chain)

    @property
    def ext(self) -> str:
        b = self.basename
        return b.rsplit(".", 1)[-1].lower() if "." in b.lstrip(".") else ""


class ArtifactSet:
    def __init__(self, tops: list[tuple[str, bytes]]):
        self.tops = [Member(name or f"artifact{i}", (name or f"artifact{i}",), i, 0, data=data)
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
        return self._kids[key]

    def _expand(self, m: Member) -> list[Member]:
        data = m.data
        if zipfile.is_zipfile(io.BytesIO(data)):
            return self._expand_zip(m)
        if data[:2] == b"\x1f\x8b":
            try:
                inner = gzip.decompress(data)
            except (OSError, EOFError, zlib.error) as e:
                m.notes.append(f"bad gzip: {e}")
                return []
            if not self._spend(len(inner), m):
                return []
            child_name = m.basename[:-3] if m.basename.endswith(".gz") else m.basename + ".out"
            kid = Member(child_name, m.chain + (child_name,), 0, m.depth + 1, data=inner)
            return self._expand_tar(kid, inner) if _is_tar(inner) else [kid]
        if _is_tar(data):
            return self._expand_tar(m, data)
        return []

    def _spend(self, n: int, m: Member) -> bool:
        if n > self._budget:
            m.notes.append("member skipped: size budget exceeded")
            return False
        self._budget -= n
        return True

    def _expand_zip(self, m: Member) -> list[Member]:
        out: list[Member] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(m.data))
            infos = zf.infolist()
        except Exception as e:  # BadZipFile, odd name encodings, ...
            m.notes.append(f"bad zip: {type(e).__name__}: {e}")
            return out
        dupes = Counter(i.filename for i in infos)
        for i, info in enumerate(infos):
            if info.is_dir() or not self._spend(info.file_size, m):
                continue
            kid = Member(info.filename, m.chain + (info.filename,), i, m.depth + 1,
                         loader=lambda notes, info=info: _read_zip_member(zf, info, notes),
                         mtime=_zip_time(info.date_time), stored_crc=info.CRC)
            if dupes[info.filename] > 1:
                kid.notes.append("duplicate entry name in this container")
            out.append(kid)
        return out

    def _expand_tar(self, m: Member, data: bytes) -> list[Member]:
        out: list[Member] = []
        errors = (tarfile.TarError, OSError, EOFError, zlib.error)
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except errors as e:
            m.notes.append(f"bad tar: {e}")
            return out
        infos = []
        try:
            for ti in tf:  # iterate so a truncated tail keeps what came before
                infos.append(ti)
        except errors as e:
            m.notes.append(f"tar stopped early: {e}")
        dupes = Counter(ti.name for ti in infos)
        for i, ti in enumerate(infos):
            if not ti.isfile() or not self._spend(ti.size, m):
                continue

            def load(notes, ti=ti):
                f = tf.extractfile(ti)
                return f.read() if f is not None else None
            kid = Member(ti.name, m.chain + (ti.name,), i, m.depth + 1, loader=load, mtime=_unix_time(ti.mtime))
            if dupes[ti.name] > 1:
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
    """Exact name, then case-insensitive, then basename. Every step needs a
    unique hit: duplicate names are ambiguous, so they resolve to nothing."""
    want = name.strip("/")
    for key, target in ((lambda m: m.name, name),
                        (lambda m: m.name.strip("/").casefold(), want.casefold()),
                        (lambda m: m.basename.casefold(), basename(want).casefold())):
        hits = [m for m in members if key(m) == target]
        if hits:
            return hits[0] if len(hits) == 1 else None
    return None


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


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
        except (zipfile.BadZipFile, zlib.error, EOFError) as e:
            if encrypted:
                # ZipCrypto's password check is one byte: 1 in 256 wrong
                # passwords pass it and decrypt to garbage that then fails
                # CRC/inflate. Never treat that as data.
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
