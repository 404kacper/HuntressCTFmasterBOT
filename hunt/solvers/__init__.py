"""Question handlers and the engine that runs them.

A handler is a function (question, ctx) -> Answer | None. The engine asks
handlers in priority order and the first non-None answer wins. Handlers can
be scoped to a lane or challenge id, so a challenge-specific module can
override the generic ones without touching them.

Every module in this package is imported automatically: to teach the bot a
new trick, drop a file here that uses @handler.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
from dataclasses import dataclass, field
from typing import Callable

from ..forensics.artifacts import ArtifactSet, Member
from ..model import Attempt, Question


@dataclass
class Answer:
    value: str
    confidence: float  # 0..1; the gate holds anything under its threshold
    evidence: str
    handler: str = ""
    subject: Member | None = field(default=None, repr=False)
    # Other spellings of the same fact, best first ("EXEC (Executable file)", "ET_EXEC"). An untimed
    # attempt tries them in order when the Game Master refuses the value; a timed one never does.
    alternatives: list[str] = field(default_factory=list)


@dataclass
class Solution:
    answers: dict[str, Answer]  # question id -> answer
    unresolved: dict[str, str]  # question id -> why
    notes: list[str]


@dataclass
class Context:
    attempt: Attempt
    artifacts: ArtifactSet
    subject: Member | None = None  # the file the previous question was about ("its size")
    subject_confidence: float = 0.0
    answers: dict[str, Answer] = field(default_factory=dict)


Handler = Callable[[Question, Context], "Answer | None"]


@dataclass
class _Reg:
    priority: int
    name: str
    fn: Handler
    lanes: tuple[str, ...]
    challenges: tuple[str, ...]

    def applies(self, a: Attempt) -> bool:
        if self.challenges and not any(re.fullmatch(c, a.challenge) for c in self.challenges):
            return False
        if self.lanes and not any(lane_matches(lane, a.lane) for lane in self.lanes):
            return False
        return True


def lane_matches(wanted: str, lane: str) -> bool:
    """'binary' also scopes 'binary-reverse-engineering': lane ids are hyphenated phrases, and a
    handler written against the short name must not silently stop applying."""
    return lane == wanted or lane.startswith(wanted + "-")


_HANDLERS: list[_Reg] = []


def handler(*, priority: int = 100, lanes: tuple[str, ...] = (), challenges: tuple[str, ...] = ()):
    """Register a handler. Lower priority runs first; challenge-specific
    handlers should use < 100 so they beat the generic ones."""
    def deco(fn: Handler) -> Handler:
        _HANDLERS.append(_Reg(priority, f"{fn.__module__.rsplit('.', 1)[-1]}.{fn.__name__}",
                              fn, tuple(lanes), tuple(challenges)))
        _HANDLERS.sort(key=lambda r: r.priority)
        return fn
    return deco


def solve(attempt: Attempt, artifacts: ArtifactSet) -> Solution:
    load_handlers()
    sol = _solve(attempt, artifacts)
    # Mastery asks the Time Trial question set once per download ("set2.marker" about download 2).
    # Each set is also solved on its own, prefix off and only its own download in view, so the
    # handlers that answer Time Trial answer Mastery too; the more confident answer wins.
    for n, (sub, arts, back) in _sets(attempt, artifacts).items():
        part = _solve(sub, arts)
        for qid, ans in part.answers.items():
            have = sol.answers.get(back[qid])
            if have is None or ans.confidence > have.confidence:
                ans.evidence = f"{ans.evidence} [set {n}, its own download]"
                sol.answers[back[qid]] = ans
                sol.unresolved.pop(back[qid], None)
        sol.notes += [f"set {n}: {note}" for note in part.notes]
    return sol


SET_ID = re.compile(r"^set[\s#_-]*(\d+)[.:/_-](.+)$", re.I)
_DELIVERY_LABEL = re.compile(r"^(?:delivery|download|bundle|package|set)[\s#_-]*(\d+)\s*(?:[:/|]\s*|$)", re.I)


def _sets(attempt: Attempt, artifacts: ArtifactSet) -> dict[int, tuple[Attempt, ArtifactSet, dict[str, str]]]:
    """set number -> (that set as an attempt of its own, its download alone, its question id ->
    the original id). Empty unless every download is one set: ids 'setN.<id>', one set per download."""
    tops = artifacts.tops
    groups: dict[int, list[tuple[str, dict]]] = {}
    for q in attempt.questions:
        m = SET_ID.match(q.id)
        if not m:
            continue
        n = int(m.group(1))
        if q.raw.get("set") is not None and str(q.raw.get("set")).strip() != str(n):
            continue
        chain = q.artifact_chain
        if chain and (label := _DELIVERY_LABEL.match(chain[0])):
            if int(label.group(1)) != n:
                continue  # about another set's download: leave it to the full view
            rest = chain[0][label.end():].strip()
            chain = ([rest] if rest else []) + chain[1:]
        d = {k: v for k, v in q.raw.items() if k not in ("set", "answer_id")}
        d["id"], d["artifact"] = m.group(2), " -> ".join(chain) or None
        groups.setdefault(n, []).append((q.id, d))
    if len(tops) < 2 or len(groups) != len(tops):
        return {}
    first = 0 if min(groups) == 0 else 1
    shared = {k: v for k, v in attempt.raw.items()
              if k not in ("questions", "tasks", "answer_ids", "download", "downloads", "deliveries", "artifacts")}
    out = {}
    for n, qs in groups.items():
        if not 0 <= n - first < len(tops) or len({d["id"] for _, d in qs}) != len(qs):
            return {}
        top = tops[n - first]
        sub = Attempt.from_response(attempt.challenge, {**shared, "questions": [d for _, d in qs]})
        arts = ArtifactSet([("" if top.name_is_guess else top.name, top.data)])
        out[n] = (sub, arts, {d["id"]: qid for qid, d in qs})
    return out


def _solve(attempt: Attempt, artifacts: ArtifactSet) -> Solution:
    ctx = Context(attempt, artifacts)
    unresolved: dict[str, str] = {}
    notes: list[str] = []
    regs = [r for r in _HANDLERS if r.applies(attempt)]
    for q in attempt.questions:
        for reg in regs:
            try:
                ans = reg.fn(q, ctx)
            except Exception as e:  # one bad handler must not kill a timed run
                notes.append(f"{reg.name} crashed on {q.id}: {e!r}")
                continue
            if ans is not None:
                ans.handler = reg.name  # attribution comes from the registry, never from the handler
                ctx.answers[q.id] = ans
                # "its" in the next question may only refer to a file this one resolved.
                ctx.subject = ans.subject
                ctx.subject_confidence = ans.confidence if ans.subject is not None else 0.0
                break
        else:
            unresolved[q.id] = "no handler recognised this question"
            ctx.subject, ctx.subject_confidence = None, 0.0
    return Solution(ctx.answers, unresolved, notes)


_loaded = False


def load_handlers() -> None:
    """Import every handler module and run one throwaway solve, so imports and
    regex compilation happen before the clock starts, not on it."""
    global _loaded
    if _loaded:
        return
    for mod in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{mod.name}")
    _loaded = True
    _warm_up()


def _warm_up() -> None:
    import io
    import zipfile

    from ..gate import decide

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("warm-note.txt", b"warm")
        zf.writestr("other.bin", b"\0")
    fmt = {"kind": "pattern", "syntax": "exact 64-character hexadecimal SHA-256 value"}
    attempt = Attempt.from_response("warm-up", {"questions": [
        {"id": "w-filename", "question": "What is the exact filename of the first warm note?",
         "artifact": "w.zip", "answer_format": {"kind": "exact_text", "syntax": "base filename"}},
        {"id": "w-size", "question": "What is its exact size in bytes?", "artifact": "w.zip -> warm-note.txt",
         "answer_format": {"kind": "integer", "syntax": "base-10 integer"}},
        {"id": "w-sha256", "question": "What is its SHA-256 digest?", "artifact": "w.zip -> warm-note.txt",
         "answer_format": fmt, "normalization": "case_insensitive"},
        {"id": "w-x", "question": "Which file lies?", "artifact": "w.zip", "answer_format": {"kind": "exact_text"}},
    ]})
    decide(attempt, solve(attempt, ArtifactSet([("w.zip", buf.getvalue())])))
