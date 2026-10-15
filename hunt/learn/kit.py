"""Small helpers for learned handlers, so each one can stay short.

Everything here is pure computation on what the handler was handed; learned
modules import from this file with `from hunt.learn.kit import ...`.
"""
from __future__ import annotations

import re

from ..forensics.artifacts import Member, UnreadableMember
from ..model import Question
from ..solvers import Answer, Context
from ..solvers.file_identity import located


def target(q: Question, ctx: Context) -> Member | None:
    """The file the question's `artifact` field names ('x.zip -> dir/y.txt'),
    understanding 'delivery N' labels; the only download when the field is empty."""
    chain, hint = located(q, ctx)
    if chain:
        return ctx.artifacts.resolve(chain, hint)
    tops = ctx.artifacts.tops
    return tops[0] if len(tops) == 1 else None


def files(ctx: Context, root: Member | None = None) -> list[Member]:
    """Every file, archives expanded (zip, tar, gzip; nested), depth first."""
    return ctx.artifacts.files(root)


def leaves(ctx: Context, root: Member | None = None) -> list[Member]:
    """Files that are not themselves archives that could be opened."""
    return [m for m in files(ctx, root) if not ctx.artifacts.children(m)]


def data(m: Member | bytes) -> bytes | None:
    if isinstance(m, (bytes, bytearray)):
        return bytes(m)
    try:
        return m.data
    except UnreadableMember:
        return None


def text(m: Member | bytes, limit: int | None = None) -> str | None:
    """Decode bytes as text: BOM-marked UTF-8/16, else UTF-8, else Latin-1."""
    raw = data(m)
    if raw is None:
        return None
    if limit is not None:
        raw = raw[:limit]
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def strings(raw: bytes, min_len: int = 4) -> list[str]:
    """ASCII runs of at least min_len printable characters (like `strings`)."""
    rx = re.compile(rb"[\x20-\x7e\t]{" + str(int(min_len)).encode() + rb",}")
    return [s.decode("ascii") for s in rx.findall(raw)]


def asks(q: Question, *words: str) -> bool:
    """True when the question text (or id) mentions every word (case-insensitive)."""
    hay = q.haystack
    return all(w.lower() in hay for w in words)


def wants(q: Question, *words: str) -> bool:
    """True when the answer format / syntax mentions every word."""
    hay = f"{q.kind} {q.syntax} {q.normalization or ''}".lower()
    return all(w.lower() in hay for w in words)


def answer(value, evidence: str, confidence: float = 0.95, subject: Member | None = None,
           alternatives=()) -> Answer:
    """An answer as the gate expects it: a string, with the reason it is right. `alternatives`
    are other spellings of the same fact, best first, for when the Game Master refuses `value`."""
    main = str(value).strip()
    alts = []
    for a in alternatives or ():
        a = str(a).strip()
        if a and a != main and a not in alts:
            alts.append(a)
    return Answer(main, confidence, evidence, subject=subject, alternatives=alts)
