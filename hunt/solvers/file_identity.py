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
# Asides that name things the question is NOT about ("regardless of what the
# label claims", "unlike scan.png", "(not the expected value)").
_ASIDE = re.compile(r"\((?:not|ignoring|excluding|unlike)\b[^)]*\)|\b(?:regardless of|rather than|instead of|ignoring|"
                    r"unlike|except for|other than|not the|not any)\b[^,;:?()]*", re.I)
# Questions about claims/labels or searches over files: not identity lookups.
_NOT_IDENTITY = re.compile(
    r"\b(?:which|whose|what)\s+(?:file|member|entry|one)s?\b|\bwhose\b|\bfiles?\s+(?:that|which|where)\b|"
    r"\blist(?:s|ed|ing)?\b|\bclaim(?:s|ed)?\b|\brecord(?:s|ed)?\b|\bstor(?:e|es|ed)\b|\bmanifest\b|"
    r"\bcentral directory\b|\bheader\b|\baccording to\b|\blabel(?:s|ed|led)?\b|\bdeclared\b|\breported\b|"
    r"\bexpected\b|\bwrong\b|\bmismatch|\bdoes(?:n't| not) match\b|\blies\b|\bspoof|\bdescrib|\breferenc|"
    r"\bmention", re.I)
_SEARCH = re.compile(r"\bwhich (?:file|member|entry)|\bwhose\b|\bfiles?\s+(?:that|which|where)\b|"
                     r"\bdoes(?:n't| not) match\b|\bmismatch", re.I)
# Things *inside* a file: "the name of the analyst", "bytes in the sequence number".
_CONTENT_OBJECT = re.compile(
    r"\b(?:analyst|host ?name|host|user ?name|user|author|owner|field|line|string|payload|sequence|marker|"
    r"chunk|section|embedded|original|password|url|domain|address|e-?mail|endpoint|signature|certificate|"
    r"process|command|variable|function|token|key|word|number|offset|portion|substring|version info|"
    r"entry point)s?\b|\b(?:first|last)\s+\d+\s+bytes?\b", re.I)
_ORDINALS = {"first": 0, "1st": 0, "second": 1, "2nd": 1, "third": 2, "3rd": 2,
             "fourth": 3, "4th": 3, "fifth": 4, "5th": 4, "last": -1, "final": -1}
_ORDINAL_RX = re.compile(r"\b(" + "|".join(_ORDINALS) + r")\s+((?:[a-z0-9]+[\s_-]?){1,3})", re.I)
_STOP = {"the", "and", "of", "in", "file", "files", "inside", "within", "from", "archive", "zip", "what",
         "exact", "its", "this", "that", "name", "filename", "size", "byte", "bytes", "digest", "hash",
         "value", "is", "for", "with", "md5", "sha", "sha1", "sha256", "sha512", "crc32", "base", "extension",
         "you", "your", "downloaded", "download", "give", "true", "actual", "real", "computed"}
_CONTAINER_WORD = re.compile(r"\b(?:zip|archive|bundle|downloaded|download|container|tarball)\b", re.I)
_CONTAINER_INNER = re.compile(r"\b(?:(?:listed|stored|contained|found|packed|included)\s+)?(?:in|inside|within|from|"
                              r"of files in|contained in)\s+(?:the|this|that|your)\s+(?:[\w-]+\s+)?(?:archive|zip|"
                              r"zip file|bundle|download|container|artifact)\b|\b(?:you|we)\s+downloaded\b", re.I)
_NEG_BEFORE = re.compile(r"\b(?:not|no|never|without|excluding|omit|omitting|rather than|instead of)\b(?:\s+\S+){0,3}\s*$")
_NEG_AFTER = re.compile(r"^\S*(?:\s+\S+){0,4}?\s*(?:is|are)?\s*(?:not accepted|not allowed|rejected|forbidden|"
                        r"disallowed|invalid)\b")
_HEX_LEN = re.compile(r"(\d+)[- ]character[^.;]*hex", re.I)
_UPPER = re.compile(r"\bupper[- ]?case\b")
_FULL_PATH = re.compile(r"full path|including (?:its|the) (?:director|folder)|with (?:its|the) (?:director|folder)")
_BASE_ONLY = re.compile(r"base ?name|bare file ?name|file ?name only|\bno (?:directory|folder|path)\b|without (?:any |the |"
                        r"a )?(?:directory|folder|path)|omit (?:the )?(?:full )?path|rather than the full path")
_STRIP_EXT = re.compile(r"\b(?:without|no|excluding|minus|omit)\s+(?:the\s+|its\s+|any\s+)?(?:file\s+)?extension"
                        r"(?!\s+(?:removal|stripp|change))|\bstem\b")
_KEEP_EXT = re.compile(r"including (?:its|the) extension|extension included|keep (?:the |its )?extension|"
                       r"with (?:its|the) extension")


# ---- which file? -----------------------------------------------------------
def subject(q: Question, ctx: Context) -> tuple[Member | None, float, str]:
    arts = ctx.artifacts
    chain = q.artifact_chain
    if len(chain) >= 2:
        m = arts.resolve(chain)
        if m is not None:
            return m, 0.99, f"question names {q.artifact!r}"
        return None, 0.0, f"question names {q.artifact!r} but no single such file is in the artifact"

    # The container the question is about: the download itself, or a member
    # inside it that the question names (Mastery ships a zip of zips).
    top = arts.resolve(chain) if chain else arts.top(None)
    if top is None:
        return None, 0.0, "cannot tell which downloaded artifact the question is about"
    kids = arts.children(top)
    if not kids:
        if top.container or top.expand_failed:
            return None, 0.0, f"{top.name} looks like a {top.container or 'container'} but could not be listed"
        return top, 0.97, f"{top.name} is a single plain file"

    text = _ASIDE.sub(" ", q.text)
    ordinal = _ORDINAL_RX.search(text)
    named, stem = _named_by_siblings(q, top, ctx)
    pick, pconf, pwhy = _by_ordinal(q, kids, text)
    # Siblings only vouch for a file when their ids describe the same subject
    # ('set2.evidence-note-size-bytes' -> 'set2.evidence-note-filename'); 'q1'/'q2' prove nothing.
    sibling = named[0] if len(named) == 1 and stem > 0 else None

    mentioned = [k for k in kids if "." in k.basename and _mentions(text, k.basename)]
    if len(mentioned) > 1:
        return None, 0.0, "question text names several files: " + ", ".join(k.name for k in mentioned)
    if mentioned:
        m = mentioned[0]
        if (sibling is not None and sibling is not m) or (pick is not None and pick is not m):
            return m, 0.6, f"question text names {m.name} but other evidence points elsewhere"
        return m, 0.97, f"question text names {m.name}"
    if not ordinal and (_mentions(text, top.basename) or _CONTAINER_WORD.search(_CONTAINER_INNER.sub(" ", text))):
        return top, 0.8, "question seems to ask about the container itself"
    if _INHERIT.search(text) and ctx.subject is not None:
        if sibling is not None and sibling is not ctx.subject:
            return ctx.subject, 0.6, f"'its' points at {ctx.subject.name} but sibling questions name {sibling.name}"
        return ctx.subject, min(ctx.subject_confidence, 0.97), "same file as the previous question"

    if sibling is not None:
        m = sibling
        if pick is m:
            return m, 0.97, f"the file the sibling questions name ({m.name}); '{ordinal.group(0).strip()}' agrees"
        if pick is not None:
            return m, 0.6, f"sibling questions name {m.name} but {pwhy}"
        scores = {id(k): len(set(_words(text)) & set(_words(k.basename))) for k in kids}
        best, mine = max(scores.values()), scores.get(id(m), 0)
        if mine >= 1 and mine == best and sum(v == best for v in scores.values()) == 1:
            return m, 0.95, f"the file the sibling questions name ({m.name}); wording fits it best"
        if mine < best:
            return m, 0.6, f"sibling questions name {m.name} but the wording fits another file better"
        return m, 0.85, f"the file the sibling questions name ({m.name}); wording does not confirm it"
    if len(kids) == 1 and not ordinal:
        return kids[0], 0.97, "the container holds exactly one file"
    if pick is not None:
        return pick, pconf, pwhy
    if len(named) == 1:
        return named[0], 0.85, f"the only file other questions name ({named[0].name}), but their ids are unrelated"
    return None, 0.0, f"{len(kids)} files in {top.name} and nothing says which one is meant"


def _mentions(text: str, name: str) -> bool:
    if not name or name.casefold() not in text.casefold():  # cheap prefilter: no regex per member
        return False
    return re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-]|\.\w)", text, re.I) is not None


def _stem_len(a: str, b: str) -> int:
    """Length of the shared id prefix up to a separator, so 'q1' and 'q10'
    share nothing but 'task-2-note-md5' and 'task-2-note-size' share 'task-2-note-'."""
    cp = commonprefix([a, b])
    cut = max(cp.rfind("-"), cp.rfind("_"), cp.rfind("."), cp.rfind("/"))
    return cut + 1


_ATTR_SUFFIX = re.compile(r"[-_.](?:file-?name|name|size(?:[-_]bytes)?|bytes|length|md5|sha-?1|sha-?224|sha-?256|"
                          r"sha-?384|sha-?512|sha3[-_]?\d+|crc-?32|blake2[bs]|digest|hash|type|path|mtime|extension)$",
                          re.I)


def _subject_key(qid: str) -> str:
    """'set2.evidence-note-size-bytes' -> 'set2.evidence-note': the id minus the
    attribute it asks for, i.e. which file the question is about."""
    key = qid
    while (m := _ATTR_SUFFIX.search(key)) and m.start() > 0:
        key = key[:m.start()]
    return key


def _named_by_siblings(q: Question, top: Member, ctx: Context) -> tuple[list[Member], int]:
    """Files inside `top` that other questions name by artifact path, and how
    strongly they vouch: 2 = same subject key, 1 = shared id stem, 0 = unrelated."""
    key = _subject_key(q.id)
    same_key: dict[int, Member] = {}
    by_stem: dict[int, dict[int, Member]] = {}
    for other in ctx.attempt.questions:
        oc = other.artifact_chain
        if other is q or len(oc) < 2:
            continue
        m = ctx.artifacts.resolve(oc)
        if m is None or m.chain[:-1] != top.chain:
            continue
        if key != q.id and _subject_key(other.id) == key:
            same_key[id(m)] = m
        by_stem.setdefault(_stem_len(q.id, other.id), {})[id(m)] = m
    if same_key:
        return list(same_key.values()), 2
    if not by_stem:
        return [], 0
    best = max(by_stem)
    return list(by_stem[best].values()), 1 if best > 0 else 0


def _words(s: str) -> list[str]:
    out = []
    for w in re.split(r"[^a-z0-9]+", s.lower()):
        if len(w) > 2 and w not in _STOP:
            out.append(w[:-1] if w.endswith("s") and len(w) > 3 else w)
    return out


def _by_ordinal(q: Question, kids: list[Member], text: str) -> tuple[Member | None, float, str]:
    m = _ORDINAL_RX.search(text)
    if not m:
        return None, 0.0, ""
    idx = _ORDINALS[m.group(1).lower()]
    phrase = m.group(0).strip()
    keywords = _words(m.group(2))
    # "the first evidence note": a file literally called evidence-note beats evidence-note-copy.
    exact = [k for k in kids if keywords and set(_words(k.basename.rsplit(".", 1)[0])) == set(keywords)]
    named = [k for k in kids if keywords and all(w in k.basename.lower() for w in keywords)]
    some = [k for k in kids if any(w in k.basename.lower() for w in keywords)]
    for cands, base, tier in ((exact, 0.85, "exact"), (named, 0.85, "all"), (some, 0.7, "some"), (kids, 0.5, "none")):
        if not cands:
            continue
        ordered = sorted(cands, key=lambda k: k.order)
        if not -len(ordered) <= idx < len(ordered):
            continue
        pick = ordered[idx]
        if len(ordered) == 1 and tier in ("exact", "all") and idx in (0, -1):
            conf = 0.9  # exactly one file fits the description
        else:  # "first" is ambiguous if name order disagrees with archive order
            conf = base if sorted(cands, key=lambda k: k.name)[idx] is pick else base - 0.15
        return pick, conf, f"'{phrase}' -> {pick.name} (archive order, keyword match: {tier})"
    return None, 0.0, f"'{phrase}' matched nothing"


# ---- answer formatting helpers -------------------------------------------
def _says(syntax: str, rx: re.Pattern) -> bool:
    """rx occurs in syntax and is not negated within its own clause
    ('not the full path', 'full path is NOT accepted')."""
    for m in rx.finditer(syntax):
        start = max(syntax.rfind(c, 0, m.start()) for c in ",;:()") + 1
        ends = [i for i in (syntax.find(c, m.end()) for c in ",;:()") if i != -1]
        before, after = syntax[start:m.start()], syntax[m.end():min(ends) if ends else len(syntax)]
        if not _NEG_BEFORE.search(before) and not _NEG_AFTER.search(after):
            return True
    return False


def _hex_len(syntax: str) -> int | None:
    m = _HEX_LEN.search(syntax)
    return int(m.group(1)) if m else None


def _wants_upper(syntax: str) -> bool:
    s = syntax.lower()
    return _says(s, _UPPER) and not _says(s, re.compile(r"\blower[- ]?case\b")) and "ignored" not in s


def _which_digest(q: Question) -> str | None:
    for hay in (q.id.lower(), q.text.lower()):
        found = [algo for algo, rx in _DIGEST_RX if rx.search(hay)]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            return None
    return None


def _about_the_file(q: Question) -> bool:
    """False for searches, claim lookups and questions about content inside a file."""
    text = _ASIDE.sub(" ", q.text)
    return not (_SEARCH.search(q.text) or _NOT_IDENTITY.search(text) or _CONTENT_OBJECT.search(text))


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
    looks_hex = q.kind in ("pattern", "") or re.search(r"hex|digest|hash", q.syntax, re.I)
    if not algo or not looks_hex or not _about_the_file(q):
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
        if _says(q.syntax.lower(), re.compile(r"\blower[- ]?case\b")):
            conf, why = min(conf, 0.5), why + "; syntax asks for both upper and lower case"
    return Answer(value, conf, f"{algo} of {m.path} ({why})", subject=m)


_SIZE_YES = re.compile(r"\bsize\b[^?]*\bbytes?\b|\bbytes?\b[^?]*\bsize\b|\bhow many bytes\b|"
                       r"\bbyte (?:count|length|size)\b|\blength in bytes\b|\bfile ?size\b|"
                       r"\bits (?:exact |total |file )?size\b")
_SIZE_NO = re.compile(r"kilo|mega|giga|\bki?b\b|\bmi?b\b|\bbits?\b|\blines?\b|\bwords?\b|"
                      r"\bcharacters?\b|\bentries\b|\bhow many files\b|\bcount of files\b|\bcompressed\b")


@handler(priority=200)
def file_size(q: Question, ctx: Context) -> Answer | None:
    hay = q.haystack
    if q.kind not in ("integer", "") or not _SIZE_YES.search(hay) or _SIZE_NO.search(hay) \
            or not _about_the_file(q):
        return None
    t = _target(q, ctx)
    if isinstance(t, Answer):
        return t
    m, data, conf, why = t
    return Answer(str(len(data)), conf, f"len({m.path}) ({why})", subject=m)


_FILLER = r"(?:(?!(?:in|of|from|inside|within|for|by|on|at|the|this|that|its)\b)[\w-]+\s+){0,2}?"
_NAME_YES = re.compile(r"\bfile ?names?\b|\bname of (?:the|this|that|its)\s+" + _FILLER +
                       r"(?:file|note|document|member|entry|artifact|archive|zip|sample|log|attachment)s?\b(?!')")


@handler(priority=200)
def file_name(q: Question, ctx: Context) -> Answer | None:
    if q.kind not in ("exact_text", "text", "") or not _NAME_YES.search(q.haystack) or not _about_the_file(q):
        return None
    m, conf, why = subject(q, ctx)
    if m is None:
        return _unresolved(why)
    if any("duplicate entry" in n for n in m.notes):
        conf = min(conf, 0.5)
    if m.name_is_guess:
        conf, why = min(conf, 0.5), why + "; the stored name had to be guessed (" + "; ".join(m.notes) + ")"
    syn = q.syntax.lower()
    full, base_only = _says(syn, _FULL_PATH), bool(_BASE_ONLY.search(syn))
    strip, keep = _says(syn, _STRIP_EXT), bool(_KEEP_EXT.search(syn))
    if (full and base_only) or (strip and keep):
        conf, why = min(conf, 0.5), why + "; answer_format syntax gives conflicting instructions"
    value = m.key if full and not base_only else m.basename
    if strip and not keep:
        value = value.rsplit(".", 1)[0] if "." in value.rsplit("/", 1)[-1] else value
    return Answer(value, conf, f"name of {m.path} ({why})", subject=m)
