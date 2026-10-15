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
        if self.lanes and a.lane not in self.lanes:
            return False
        return True


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
