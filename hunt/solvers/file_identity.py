"""Generic file-identity answers: filename, size, digests.

Works for any challenge whose questions ask about a file's identity, not just
"You Must Be This Hash to Ride". Which file a question is about is taken, in
order of trust, from:
  1. the question's own artifact path ("x.zip -> evidence-note.txt"),
  2. the file the other questions name / the only file in the container,
  3. an ordinal phrase ("the first evidence note") matched against names in
     archive order.
Each step carries its own confidence so the gate knows when to stop and ask.
"""
from __future__ import annotations

import re
from os.path import commonprefix

from ..forensics.artifacts import Member
from ..forensics.identity import DIGESTS, digest
from ..model import Question
from . import Answer, Context, handler

_DIGEST_RX = [
    ("sha3_512", r"sha-?3[-_ ]?512"), ("sha3_384", r"sha-?3[-_ ]?384"),
    ("sha3_256", r"sha-?3[-_ ]?256"), ("sha3_224", r"sha-?3[-_ ]?224"),
    ("sha512", r"sha[-_ ]?512"), ("sha384", r"sha[-_ ]?384"),
    ("sha256", r"sha[-_ ]?256"), ("sha224", r"sha[-_ ]?224"),
    ("sha1", r"sha[-_ ]?1(?!\d)"), ("md5", r"\bmd[-_ ]?5\b"), ("crc32", r"crc[-_ ]?32"),
    ("blake2b", r"blake2b"), ("blake2s", r"blake2s"),
]
_PRONOUN = re.compile(r"\b(its|it|this file|that file|the same file)\b", re.I)
_ORDINALS = {"first": 0, "1st": 0, "second": 1, "2nd": 1, "third": 2, "3rd": 2,
             "fourth": 3, "4th": 3, "fifth": 4, "5th": 4, "last": -1, "final": -1}
_ORDINAL_RX = re.compile(r"\b(" + "|".join(_ORDINALS) + r")\s+((?:[a-z0-9]+[\s_-]?){1,3})", re.I)
_STOP = {"the", "a", "an", "of", "in", "file", "files", "inside", "within", "from", "archive", "zip"}
_CONTAINER_SELF = re.compile(r"\b(?:the|this|that|downloaded|whole|entire)\s+(?:archive|zip|zip file|bundle|"
                             r"download|container|artifact)\b", re.I)
_CONTAINER_INNER = re.compile(r"\b(?:in|inside|within|from|of files in)\s+(?:the|this|that)\s+"
                              r"(?:archive|zip|zip file|bundle|download|container|artifact)\b", re.I)


# ---- which file? -----------------------------------------------------------
def subject(q: Question, ctx: Context) -> tuple[Member | None, float, str]:
    arts = ctx.artifacts
    chain = q.artifact_chain
    if len(chain) >= 2:
        m = arts.resolve(chain)
        if m is not None:
            return m, 0.99, f"question names {q.artifact!r}"
        return None, 0.0, f"question names {q.artifact!r} but no such file is in the artifact"

    top = arts.top(chain[0] if chain else None)
    if top is None:
        if len(chain) == 1:  # maybe the question names an inner file directly
            m = arts.resolve(chain)
            if m is not None:
                return m, 0.95, f"question names {chain[0]!r}"
        return None, 0.0, "cannot tell which downloaded artifact the question is about"
    kids = arts.children(top)
    if not kids:
        return top, 0.97, f"{top.name} is a single plain file"
    if _CONTAINER_SELF.search(q.text) and not _CONTAINER_INNER.search(q.text) \
            and not _ORDINAL_RX.search(q.text):
        return top, 0.8, "question seems to ask about the container itself"
    if _PRONOUN.search(q.text) and ctx.subject is not None:
        return ctx.subject, ctx.subject_confidence, "same file as the previous question"

    named = _named_by_other_questions(q, top, ctx)
    pick, pconf, pwhy = _by_ordinal(q, kids)
    if len(named) == 1:
        m = named[0]
        if pick is None or pick is m:
            agree = "; ordinal phrase agrees" if pick is m else ""
            return m, 0.97, f"the file the other questions name ({m.name}){agree}"
        return m, 0.6, f"other questions name {m.name} but '{pwhy}' points at {pick.name}"
    if len(kids) == 1:
        return kids[0], 0.97, "the container holds exactly one file"
    if pick is not None:
        return pick, pconf, pwhy
    return None, 0.0, f"{len(kids)} files in {top.name} and nothing says which one is meant"


def _named_by_other_questions(q: Question, top: Member, ctx: Context) -> list[Member]:
    """Files named by sibling questions. Siblings whose id shares the longest
    prefix with this one win, so 'task-2-note-filename' follows
    'task-2-note-md5' rather than 'task-1-note-md5'."""
    by_prefix: dict[int, dict[int, Member]] = {}
    for other in ctx.attempt.questions:
        oc = other.artifact_chain
        if other is q or len(oc) < 2 or ctx.artifacts.top(oc[0]) is not top:
            continue
        m = ctx.artifacts.resolve(oc)
        if m is not None:
            n = len(commonprefix([q.id, other.id]))
            by_prefix.setdefault(n, {})[id(m)] = m
    return list(by_prefix[max(by_prefix)].values()) if by_prefix else []


def _words(s: str) -> list[str]:
    return [w.rstrip("s") for w in re.split(r"[^a-z0-9]+", s.lower()) if len(w) > 2 and w not in _STOP]


def _by_ordinal(q: Question, kids: list[Member]) -> tuple[Member | None, float, str]:
    m = _ORDINAL_RX.search(q.text)
    if not m:
        return None, 0.0, ""
    idx = _ORDINALS[m.group(1).lower()]
    keywords = _words(m.group(2))
    named = [k for k in kids if keywords and all(w in _words(k.basename) or w in k.basename.lower()
                                                 for w in keywords)]
    some = [k for k in kids if any(w in k.basename.lower() for w in keywords)]
    for cands, base, tier in ((named, 0.85, "all"), (some, 0.7, "some"), (kids, 0.5, "none")):
        if not cands:
            continue
        ordered = sorted(cands, key=lambda k: k.order)
        if not -len(ordered) <= idx < len(ordered):
            continue
        pick = ordered[idx]
        if len(ordered) == 1 and tier == "all":
            conf = 0.9  # exactly one file fits the description
        else:  # "first" is ambiguous if name order disagrees with archive order
            conf = base if sorted(cands, key=lambda k: k.name)[idx] is pick else base - 0.15
        return pick, conf, f"'{m.group(0).strip()}' -> {pick.name} (archive order, keyword match: {tier})"
    return None, 0.0, f"'{m.group(0).strip()}' matched nothing"


# ---- answer formatting helpers -------------------------------------------
def _hex_len(syntax: str) -> int | None:
    m = re.search(r"(\d+)[- ]character[^.;]*hex", syntax, re.I)
    return int(m.group(1)) if m else None


def _wants_upper(syntax: str) -> bool:
    return bool(re.search(r"\bupper[- ]?case\b", syntax, re.I)) and "ignored" not in syntax.lower()


def _which_digest(q: Question) -> str | None:
    for hay in (q.id.lower(), q.text.lower()):
        found = [algo for algo, rx in _DIGEST_RX if re.search(rx, hay)]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            return None
    return None


def _unresolved(why: str) -> Answer:
    return Answer("", 0.0, why)


# ---- handlers --------------------------------------------------------------
@handler(priority=200)
def file_digest(q: Question, ctx: Context) -> Answer | None:
    algo = _which_digest(q)
    looks_hex = q.kind == "pattern" or re.search(r"hex|digest|hash", q.syntax, re.I)
    if not algo or not looks_hex:
        return None
    m, conf, why = subject(q, ctx)
    if m is None:
        return _unresolved(why)
    value = digest(algo, m.data)
    want = _hex_len(q.syntax)
    if want and want != DIGESTS[algo][1]:
        conf = min(conf, 0.3)
        why += f"; syntax expects {want} hex chars but {algo} has {DIGESTS[algo][1]}"
    if _wants_upper(q.syntax):
        value = value.upper()
    return Answer(value, conf, f"{algo} of {m.path} ({why})", subject=m)


_SIZE_YES = re.compile(r"\bsize\b|\blength\b|how many bytes|byte count|\bbytes\b")
_SIZE_NO = re.compile(r"kilo|mega|giga|\bki?b\b|\bmi?b\b|\bbits?\b|\blines?\b|\bwords?\b|"
                      r"\bcharacters?\b|\bentries\b|\bhow many files\b|\bcount of files\b")


@handler(priority=200)
def file_size(q: Question, ctx: Context) -> Answer | None:
    hay = q.haystack
    if q.kind not in ("integer", "") or not _SIZE_YES.search(hay) or _SIZE_NO.search(hay):
        return None
    m, conf, why = subject(q, ctx)
    if m is None:
        return _unresolved(why)
    return Answer(str(len(m.data)), conf, f"len({m.path}) ({why})", subject=m)


_NAME_YES = re.compile(r"file ?name|name of the|what is the name|\bnamed\b")


@handler(priority=200)
def file_name(q: Question, ctx: Context) -> Answer | None:
    if q.kind not in ("exact_text", "text", "") or not _NAME_YES.search(q.haystack):
        return None
    if re.search(r"which file|whose|that (?:has|matches|does not)", q.text, re.I):
        return None  # a search question, not "what is this file called"
    m, conf, why = subject(q, ctx)
    if m is None:
        return _unresolved(why)
    syn = q.syntax.lower()
    if "full path" in syn or re.search(r"including (?:its|the) director", syn):
        value = m.name
    elif "without" in syn and "extension" in syn:
        value = m.basename.rsplit(".", 1)[0]
    else:
        value = m.basename
    return Answer(value, conf, f"name of {m.path} ({why})", subject=m)
