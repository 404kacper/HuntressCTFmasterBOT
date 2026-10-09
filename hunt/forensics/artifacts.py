"""In-memory view of downloaded artifacts, with lazy expansion of containers.

Nothing is ever extracted to disk or executed. Containers (zip/apk/jar, tar,
gzip) are opened only when a question walks into them, so the timed path
pays only for what it reads. Size and depth limits stop zip bombs.
"""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from posixpath import basename

MAX_DEPTH = 4
MAX_TOTAL_BYTES = 512 * 1024 * 1024
ZIP_PASSWORDS = (b"infected", b"malware", b"virus")


@dataclass(eq=False)
class Member:
    name: str  # path inside its container (or the top-level artifact name)
    data: bytes
    chain: tuple[str, ...]  # names from the top-level artifact down to this member
    order: int  # position inside its container (archive order)
    depth: int
    mtime: datetime | None = None
    stored_crc: int | None = None
    notes: list[str] = field(default_factory=list)

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
        self.tops = [Member(name or f"artifact{i}", data, (name or f"artifact{i}",), i, 0)
                     for i, (name, data) in enumerate(tops)]
        self._kids: dict[int, list[Member]] = {}
        self._budget = MAX_TOTAL_BYTES

    # ---- expansion -------------------------------------------------------
    def children(self, m: Member) -> list[Member]:
        key = id(m)
        if key not in self._kids:
            self._kids[key] = self._expand(m) if m.depth < MAX_DEPTH else []
        return self._kids[key]

    def _expand(self, m: Member) -> list[Member]:
        data = m.data
        if zipfile.is_zipfile(io.BytesIO(data)):
            return self._expand_zip(m)
        if data[:2] == b"\x1f\x8b":
            try:
                inner = gzip.decompress(data)
            except (OSError, EOFError):
                return []
            if self._spend(len(inner), m):
                child_name = m.basename[:-3] if m.basename.endswith(".gz") else m.basename + ".out"
                kid = Member(child_name, inner, m.chain + (child_name,), 0, m.depth + 1)
                return self._expand(kid) if _is_tar(inner) else [kid]
            return []
        if _is_tar(data):
            return self._expand_tar(m, data)
        return []

    def _spend(self, n: int, m: Member) -> bool:
        if n > self._budget:
            m.notes.append("container not expanded: size budget exceeded")
            return False
        self._budget -= n
        return True

    def _expand_zip(self, m: Member) -> list[Member]:
        out: list[Member] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(m.data))
        except zipfile.BadZipFile as e:
            m.notes.append(f"bad zip: {e}")
            return out
        for i, info in enumerate(zf.infolist()):
            if info.is_dir() or not self._spend(info.file_size, m):
                continue
            notes: list[str] = []
            data = _read_zip_member(zf, info, notes)
            if data is None:
                continue
            try:
                mtime = datetime(*info.date_time)
            except ValueError:
                mtime = None
            out.append(Member(info.filename, data, m.chain + (info.filename,), i, m.depth + 1,
                              mtime, info.CRC, notes))
        return out

    def _expand_tar(self, m: Member, data: bytes) -> list[Member]:
        out: list[Member] = []
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except (tarfile.TarError, OSError):
            return out
        for i, ti in enumerate(tf.getmembers()):
            if not ti.isfile() or not self._spend(ti.size, m):
                continue
            f = tf.extractfile(ti)
            if f is None:
                continue
            out.append(Member(ti.name, f.read(), m.chain + (ti.name,), i, m.depth + 1,
                              datetime.fromtimestamp(ti.mtime) if ti.mtime else None))
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
    for m in members:
        if m.name == name:
            return m
    want = name.strip("/").casefold()
    for key in (lambda m: m.name.strip("/").casefold(), lambda m: m.basename.casefold()):
        hits = [m for m in members if key(m) == want]
        if len(hits) == 1:
            return hits[0]
    hits = [m for m in members if m.basename.casefold() == basename(want)]
    return hits[0] if len(hits) == 1 else None


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def _read_zip_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, notes: list[str]) -> bytes | None:
    pwds = (None,) + ZIP_PASSWORDS if info.flag_bits & 0x1 else (None,)
    for pwd in pwds:
        try:
            data = zf.read(info, pwd=pwd)
            if pwd:
                notes.append(f"decrypted with password {pwd.decode()!r}")
            return data
        except RuntimeError:  # wrong / missing password
            continue
        except zipfile.BadZipFile as e:
            if "CRC" not in str(e):
                notes.append(f"unreadable: {e}")
                return None
            # The stored CRC is itself a label that can lie; read the bytes anyway.
            with zf.open(info, pwd=pwd) as f:
                f._expected_crc = None  # type: ignore[attr-defined]
                data = f.read()
            notes.append("stored CRC-32 does not match the bytes")
            return data
        except (NotImplementedError, ValueError, OSError) as e:
            notes.append(f"unreadable: {e}")
            return None
    notes.append("encrypted; no known password worked")
    return None
