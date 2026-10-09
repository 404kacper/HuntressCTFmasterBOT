"""Generic file-identity answers: filename, size, digests.

Works for any challenge whose questions ask about a file's identity, not just
"You Must Be This Hash to Ride". Which file a question is about is taken, in
order of trust, from:
  1. the question's own artifact path ("x.zip -> evidence-note.txt"),
  2. a member the question text names outright ("... of scan.png"),
  3. the file the sibling questions name, when the wording agrees with it,
  4. an ordinal phrase ("the first evidence note") matched against names in
     archive order.
Each step carries its own confidence so the gate knows when to stop and ask.

These handlers deliberately refuse questions about what a label, manifest or
header *claims* ("which file", "whose", "listed", "stored", ...): those need a
dedicated handler, and the gate holds them until one exists.
"""
from __future__ import annotations

import re
from os.path import commonprefix

from ..forensics.artifacts import Member, UnreadableMember
from ..forensics.identity import DIGESTS, digest
from ..model import Question
from . import Answer, Context, handler

_DIGEST_RX = [(algo, re.compile(rx)) for algo, rx in (
    ("sha3_512", r"sha-?3[-_ ]?512"), ("sha3_384", r"sha-?3[-_ ]?384"),
    ("sha3_256", r"sha-?3[-_ ]?256"), ("sha3_224", r"sha-?3[-_ ]?224"),
    ("sha512", r"sha[-_ ]?512"), ("sha384", r"sha[-_ ]?384"),
    ("sha256", r"sha[-_ ]?256"), ("sha224", r"sha[-_ ]?224"),
    ("sha1", r"sha[-_ ]?1(?!\d)"), ("md5", r"\bmd[-_ ]?5\b"), ("crc32", r"crc[-_ ]?32"),
    ("blake2b", r"blake2b"), ("blake2s", r"blake2s"),
)]
# "What is its size?" refers back to the previous question's file; "the file
# whose name ... its" does not.
_INHERIT = re.compile(r"^\s*what(?:'s| is| are)\s+(?:its|this file's|that file's)\b|\bthe same file\b", re.I)
# Questions about claims/labels or searches over files: not identity lookups.
_NOT_IDENTITY = re.compile(
    r"\b(?:which|whose|what)\s+(?:file|member|entry|one)s?\b|\bwhose\b|\bfiles?\s+(?:that|which|where)\b|"
    r"\blist(?:s|ed|ing)?\b|\bclaim(?:s|ed)?\b|\brecord(?:s|ed)?\b|\bstor(?:e|es|ed)\b|\bmanifest\b|"
    r"\bcentral directory\b|\bheader\b|\baccording to\b|\blabel(?:s|ed|led)?\b|\bdeclared\b|\breported\b|"
    r"\bexpected\b|\bwrong\b|\bmismatch|\bdoes not match\b|\blies\b|\bspoof", re.I)
_ORDINALS = {"first": 0, "1st": 0, "second": 1, "2nd": 1, "third": 2, "3rd": 2,
             "fourth": 3, "4th": 3, "fifth": 4, "5th": 4, "last": -1, "final": -1}
_ORDINAL_RX = re.compile(r"\b(" + "|".join(_ORDINALS) + r")\s+((?:[a-z0-9]+[\s_-]?){1,3})", re.I)
_STOP = {"the", "and", "of", "in", "file", "files", "inside", "within", "from", "archive", "zip", "what",
         "exact", "its", "this", "that", "name", "filename", "size", "byte", "bytes", "digest", "hash",
         "value", "is", "for", "with", "md5", "sha", "sha1", "sha256", "sha512", "crc32", "base", "extension"}
_CONTAINER_WORD = re.compile(r"\b(?:zip|archive|bundle|downloaded|download|container|tarball)\b", re.I)
_CONTAINER_INNER = re.compile(r"\b(?:in|inside|within|from|of files in|contained in)\s+(?:the|this|that|your)\s+"
                              r"(?:[\w-]+\s+)?(?:archive|zip|zip file|bundle|download|container|artifact)\b", re.I)
_NEGATED = re.compile(r"\b(?:not|no|never|without|excluding)\b(?:\s+\S+){0,3}\s*$")
_HEX_LEN = re.compile(r"(\d+)[- ]character[^.;]*hex", re.I)
_UPPER = re.compile(r"\bupper[- ]?case\b")
_FULL_PATH = re.compile(r"full path|including (?:its|the) director")
_STRIP_EXT = re.compile(r"\b(?:without|no|excluding|minus)\s+(?:the\s+|its\s+|any\s+)?(?:file\s+)?extension")
_KEEP_EXT = re.compile(r"including (?:its|the) extension")


# ---- which file? -----------------------------------------------------------
def subject(q: Question, ctx: Context) -> tuple[Member | None, float, str]:
    arts = ctx.artifacts
    chain = q.artifact_chain
    if len(chain) >= 2:
        m = arts.resolve(chain)
        if m is not None:
            return m, 0.99, f"question names {q.artifact!r}"
        return None, 0.0, f"question names {q.artifact!r} but no single such file is in the artifact"

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

    text = q.text
    mentioned = [k for k in kids if _mentions(text, k.basename)]
    if len(mentioned) == 1:
        return mentioned[0], 0.97, f"question text names {mentioned[0].name}"
    if len(mentioned) > 1:
        return None, 0.0, "question text names several files: " + ", ".join(k.name for k in mentioned)
    ordinal = _ORDINAL_RX.search(text)
    if not ordinal and (_mentions(text, top.basename) or _CONTAINER_WORD.search(_CONTAINER_INNER.sub(" ", text))):
        return top, 0.8, "question seems to ask about the container itself"
    if _INHERIT.search(text) and ctx.subject is not None:
        return ctx.subject, min(ctx.subject_confidence, 0.97), "same file as the previous question"

    named = _named_by_siblings(q, top, ctx)
    pick, pconf, pwhy = _by_ordinal(q, kids)
    if len(named) == 1:
        m = named[0]
        if pick is m:
            return m, 0.97, f"the file the sibling questions name ({m.name}); '{ordinal.group(0).strip()}' agrees"
        if pick is not None:
            return m, 0.6, f"sibling questions name {m.name} but {pwhy}"
        if not ordinal and set(_words(text)) & set(_words(m.basename)):
            return m, 0.95, f"the file the sibling questions name ({m.name}); wording agrees"
        return m, 0.85, f"the file the sibling questions name ({m.name}); wording does not confirm it"
    if len(kids) == 1 and not ordinal:
        return kids[0], 0.97, "the container holds exactly one file"
    if pick is not None:
        return pick, pconf, pwhy
    return None, 0.0, f"{len(kids)} files in {top.name} and nothing says which one is meant"


def _mentions(text: str, name: str) -> bool:
    return bool(name) and re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-]|\.\w)", text, re.I) is not None


def _stem_len(a: str, b: str) -> int:
    """Length of the shared id prefix up to a separator, so 'q1' and 'q10'
    share nothing but 'task-2-note-md5' and 'task-2-note-size' share 'task-2-note-'."""
    cp = commonprefix([a, b])
    cut = max(cp.rfind("-"), cp.rfind("_"), cp.rfind("."), cp.rfind("/"))
    return cut + 1


def _named_by_siblings(q: Question, top: Member, ctx: Context) -> list[Member]:
    by_stem: dict[int, dict[int, Member]] = {}
    for other in ctx.attempt.questions:
        oc = other.artifact_chain
        if other is q or len(oc) < 2 or ctx.artifacts.top(oc[0]) is not top:
            continue
        m = ctx.artifacts.resolve(oc)
        if m is not None:
            by_stem.setdefault(_stem_len(q.id, other.id), {})[id(m)] = m
    return list(by_stem[max(by_stem)].values()) if by_stem else []


def _words(s: str) -> list[str]:
    out = []
    for w in re.split(r"[^a-z0-9]+", s.lower()):
        if len(w) > 2 and w not in _STOP:
            out.append(w[:-1] if w.endswith("s") and len(w) > 3 else w)
    return out


def _by_ordinal(q: Question, kids: list[Member]) -> tuple[Member | None, float, str]:
    m = _ORDINAL_RX.search(q.text)
    if not m:
        return None, 0.0, ""
    idx = _ORDINALS[m.group(1).lower()]
    phrase = m.group(0).strip()
    keywords = _words(m.group(2))
    named = [k for k in kids if keywords and all(w in k.basename.lower() for w in keywords)]
    some = [k for k in kids if any(w in k.basename.lower() for w in keywords)]
    for cands, base, tier in ((named, 0.85, "all"), (some, 0.7, "some"), (kids, 0.5, "none")):
        if not cands:
            continue
        ordered = sorted(cands, key=lambda k: k.order)
        if not -len(ordered) <= idx < len(ordered):
            continue
        pick = ordered[idx]
        if len(ordered) == 1 and tier == "all" and idx in (0, -1):
            conf = 0.9  # exactly one file fits the description
        else:  # "first" is ambiguous if name order disagrees with archive order
            conf = base if sorted(cands, key=lambda k: k.name)[idx] is pick else base - 0.15
        return pick, conf, f"'{phrase}' -> {pick.name} (archive order, keyword match: {tier})"
    return None, 0.0, f"'{phrase}' matched nothing"


# ---- answer formatting helpers -------------------------------------------
def _says(syntax: str, rx: re.Pattern) -> bool:
    """rx occurs in syntax and is not negated ('not the full path')."""
    return any(not _NEGATED.search(syntax[max(0, m.start() - 40):m.start()]) for m in rx.finditer(syntax))


def _hex_len(syntax: str) -> int | None:
    m = _HEX_LEN.search(syntax)
    return int(m.group(1)) if m else None


def _wants_upper(syntax: str) -> bool:
    s = syntax.lower()
    return _says(s, _UPPER) and "lowercase" not in s and "lower-case" not in s and "ignored" not in s


def _which_digest(q: Question) -> str | None:
    for hay in (q.id.lower(), q.text.lower()):
        found = [algo for algo, rx in _DIGEST_RX if rx.search(hay)]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            return None
    return None


def _unresolved(why: str) -> Answer:
    return Answer("", 0.0, why)


def _target(q: Question, ctx: Context):
    """(member, data, confidence, why) or an unresolved Answer."""
    m, conf, why = subject(q, ctx)
    if m is None:
        return _unresolved(why)
    try:
        data = m.data
    except UnreadableMember as e:
        return _unresolved(f"cannot read {m.path}: {e}")
    if any("CRC-32 does not match" in n or "duplicate entry" in n for n in m.notes):
        conf = min(conf, 0.5)
        why += "; " + "; ".join(m.notes)
    return m, data, conf, why


# ---- handlers --------------------------------------------------------------
@handler(priority=200)
def file_digest(q: Question, ctx: Context) -> Answer | None:
    algo = _which_digest(q)
    looks_hex = q.kind == "pattern" or re.search(r"hex|digest|hash", q.syntax, re.I)
    if not algo or not looks_hex or _NOT_IDENTITY.search(q.text):
        return None
    t = _target(q, ctx)
    if isinstance(t, Answer):
        return t
    m, data, conf, why = t
    value = digest(algo, data)
    want = _hex_len(q.syntax)
    if want and want != DIGESTS[algo][1]:
        conf = min(conf, 0.3)
        why += f"; syntax expects {want} hex chars but {algo} has {DIGESTS[algo][1]}"
    if _wants_upper(q.syntax):
        value = value.upper()
    return Answer(value, conf, f"{algo} of {m.path} ({why})", subject=m)


_SIZE_YES = re.compile(r"\bsize\b[^?]*\bbytes?\b|\bbytes?\b[^?]*\bsize\b|\bhow many bytes\b|"
                       r"\bbyte (?:count|length|size)\b|\blength in bytes\b|\bfile ?size\b|"
                       r"\bits (?:exact |total |file )?size\b")
_SIZE_NO = re.compile(r"kilo|mega|giga|\bki?b\b|\bmi?b\b|\bbits?\b|\blines?\b|\bwords?\b|"
                      r"\bcharacters?\b|\bentries\b|\bhow many files\b|\bcount of files\b|\bcompressed\b")


@handler(priority=200)
def file_size(q: Question, ctx: Context) -> Answer | None:
    hay = q.haystack
    if (q.kind not in ("integer", "") or not _SIZE_YES.search(hay) or _SIZE_NO.search(hay)
            or _NOT_IDENTITY.search(q.text)):
        return None
    t = _target(q, ctx)
    if isinstance(t, Answer):
        return t
    m, data, conf, why = t
    return Answer(str(len(data)), conf, f"len({m.path}) ({why})", subject=m)


_NAME_YES = re.compile(r"\bfile ?names?\b|\bname of (?:the|this|that|its)\s+(?:[\w-]+\s+){0,3}?"
                       r"(?:file|note|document|member|entry|artifact|archive|zip|sample|log|attachment)s?\b")


@handler(priority=200)
def file_name(q: Question, ctx: Context) -> Answer | None:
    if q.kind not in ("exact_text", "text", "") or not _NAME_YES.search(q.haystack) \
            or _NOT_IDENTITY.search(q.text):
        return None
    m, conf, why = subject(q, ctx)
    if m is None:
        return _unresolved(why)
    if any("duplicate entry" in n for n in m.notes):
        conf = min(conf, 0.5)
    syn = q.syntax.lower()
    if _says(syn, _FULL_PATH):
        value = m.name
    elif _STRIP_EXT.search(syn) and not _KEEP_EXT.search(syn):
        value = m.basename.rsplit(".", 1)[0]
    else:
        value = m.basename
    return Answer(value, conf, f"name of {m.path} ({why})", subject=m)
