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
                ans.handler = ans.handler or reg.name
                ctx.answers[q.id] = ans
                if ans.subject is not None:
                    ctx.subject, ctx.subject_confidence = ans.subject, ans.confidence
                break
        else:
            unresolved[q.id] = "no handler recognised this question"
    return Solution(ctx.answers, unresolved, notes)


_loaded = False


def load_handlers() -> None:
    """Import every handler module. Call before the clock starts."""
    global _loaded
    if _loaded:
        return
    for mod in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{mod.name}")
    _loaded = True
