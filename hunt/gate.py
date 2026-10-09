"""The check every answer passes before it is allowed anywhere near submit.

There is one submission per attempt, so the gate errs towards holding: an
answer goes out only if it is mapped to a real answer id, matches the
declared answer format, and the handler was confident enough. Everything
held is reported with the reason, so the human (or the next handler you
write) knows exactly what to look at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Attempt, Question
from .solvers import Solution

DEFAULT_MIN_CONFIDENCE = 0.9


@dataclass
class Decision:
    submit: dict[str, str]  # answer_id -> value (ready to send)
    held: dict[str, str]  # question id -> reason
    warnings: list[str] = field(default_factory=list)
    tentative: dict[str, str] = field(default_factory=dict)  # held only for low confidence

    @property
    def complete(self) -> bool:
        return not self.held


_NO_DIR = re.compile(r"base file ?name|no directory|without (?:any |the |a )?director|not the full path|"
                     r"file ?name only|no (?:folder|path)")


def format_problem(q: Question, value: str) -> str | None:
    if value == "":
        return "empty answer"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "value is not valid text (undecodable bytes in a name?)"
    if "\ufffd" in value:
        return "value contains a U+FFFD replacement character"
    if value != value.strip():
        return "leading/trailing whitespace"
    kind = q.kind.lower()
    syn = q.syntax.lower()
    if kind == "integer" and not re.fullmatch(r"-?\d+", value):
        return f"answer_format is integer but value is {value!r}"
    m = re.search(r"(\d+)[- ]character[^.;]*hex", syn)
    if m and not re.fullmatch(r"[0-9a-fA-F]{%d}" % int(m.group(1)), value):
        return f"syntax wants {m.group(1)} hex characters, got {len(value)}: {value[:20]!r}"
    if _NO_DIR.search(syn) and ("/" in value or "\\" in value):
        return "syntax forbids a directory path"
    if "\n" in value:
        return "multi-line answer"
    return None


def decide(attempt: Attempt, solution: Solution,
           min_confidence: float = DEFAULT_MIN_CONFIDENCE, trust_guessed_ids: bool = False) -> Decision:
    ids, warnings, guessed = attempt.answer_id_mapping()
    warnings = list(warnings) + list(solution.notes)
    submit: dict[str, str] = {}
    held: dict[str, str] = {}
    tentative: dict[str, str] = {}
    for q in attempt.questions:
        ans = solution.answers.get(q.id)
        if ans is None:
            held[q.id] = solution.unresolved.get(q.id, "no answer")
            continue
        if q.id not in ids:
            held[q.id] = "no answer_id for this question"
            continue
        problem = format_problem(q, ans.value)
        if problem:
            held[q.id] = f"{problem} ({ans.evidence})"
        elif ans.confidence < min_confidence:
            held[q.id] = f"confidence {ans.confidence:.2f} < {min_confidence:.2f}: {ans.evidence}"
            tentative[ids[q.id]] = ans.value
        elif guessed and not trust_guessed_ids:
            held[q.id] = f"answer id {ids[q.id]!r} was guessed ({'; '.join(warnings)})"
            tentative[ids[q.id]] = ans.value
        else:
            submit[ids[q.id]] = ans.value
    if not attempt.questions:
        warnings.append("reply contained no questions")
    return Decision(submit, held, warnings, tentative)


def normalize(q: Question | None, value: str) -> str:
    v = str(value).strip()
    norm = (q.normalization or "").lower() if q else ""
    if "insensitive" in norm or "ignore" in norm or (q and "case is ignored" in q.syntax.lower()):
        v = v.casefold()
    return v
