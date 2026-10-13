"""Proving a learned module offline before it is trusted with a submission.

A candidate passes when: the policy accepts it, it loads in the sandbox
without errors, the current attempt then comes out complete through the gate
(every question answered, in format, confident), and every archived CORRECT
attempt still reproduces with it loaded. Anything less goes back to the
advisor as feedback.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..archive import Archive, replay
from ..forensics.artifacts import ArtifactSet
from ..gate import DEFAULT_MIN_CONFIDENCE, decide, normalize
from ..model import Attempt
from . import policy
from .library import Library
from .sandbox import Sandbox, SandboxError, to_solution


@dataclass
class TrialReport:
    name: str
    ok: bool = False
    problems: list[str] = field(default_factory=list)  # why it cannot even run
    answers: dict[str, dict] = field(default_factory=dict)  # question id -> value/confidence/evidence/handler
    held: dict[str, str] = field(default_factory=dict)  # question id -> why the gate holds it
    regressions: list[dict] = field(default_factory=list)
    traces: list[str] = field(default_factory=list)  # exceptions from this module's handlers
    other_traces: list[str] = field(default_factory=list)  # from other learned modules (not held against it)
    printed: str = ""
    handlers: list[dict] = field(default_factory=list)

    def feedback(self) -> str:
        """What went wrong, written for the advisor."""
        if self.ok:
            return f"Module {self.name} passed the offline trial."
        out = [f"Module `{self.name}` did not pass the offline trial."]
        if self.problems:
            out.append("It was refused before running:\n" + "\n".join(f"- {p}" for p in self.problems))
        if self.traces:
            out.append("Exceptions raised by your handlers:\n" + "\n\n".join(t[-2500:] for t in self.traces[:6]))
        if self.answers or self.held:
            rows = []
            for qid in sorted(set(self.answers) | set(self.held)):
                a = self.answers.get(qid)
                got = (f"{a['value']!r} (confidence {a['confidence']:.2f}, by {a['handler']})" if a else "no answer")
                rows.append(f"- {qid}: {got}" + (f"\n    HELD: {self.held[qid]}" if qid in self.held else ""))
            out.append("Result on the current attempt:\n" + "\n".join(rows))
        if self.regressions:
            out.append("It breaks answers the Game Master accepted before:\n" + "\n".join(
                f"- {r['run']}: {r['diffs']}" for r in self.regressions[:5]))
        if self.printed.strip():
            out.append("Your print() output:\n" + self.printed.strip()[-3000:])
        return "\n\n".join(out)


def failing_runs(library: Library, archive: Archive, min_confidence: float = DEFAULT_MIN_CONFIDENCE,
                 trust_guessed_ids: bool = False, latest: int = 2, timeout: float = 30.0) -> set[str]:
    """Archived CORRECT runs the current library already fails to reproduce: a
    candidate is only blamed for failures it adds."""
    try:
        with Sandbox(library.modules(), timeout=timeout) as sb:
            rows = replay(archive, None, min_confidence, trust_guessed_ids, solver=sb.solve, latest=latest)
    except SandboxError:
        return set()
    return {r["run"] for r in rows if not r["ok"]}


def run_trial(library: Library, name: str, source: str, attempt: Attempt, artifacts: ArtifactSet,
              archive: Archive | None = None, min_confidence: float = DEFAULT_MIN_CONFIDENCE,
              trust_guessed_ids: bool = False, timeout: float = 30.0, regression_latest: int = 2,
              refused: dict[str, set[str]] | None = None, baseline: set[str] | None = None) -> TrialReport:
    """refused: question id -> values the Game Master already turned down on this
    attempt; a candidate that still gives one of them has not fixed anything.
    baseline: runs that already fail without the candidate (see failing_runs)."""
    report = TrialReport(name)
    report.problems = policy.check(source)
    if report.problems:
        return report
    sandbox = Sandbox(library.modules(exclude=name) + [(name, source)], timeout=timeout)
    try:
        info = sandbox.start()
        if name in (info.get("errors") or {}):
            report.problems.append(f"loading the module raised:\n{info['errors'][name][-2500:]}")
            return report
        report.handlers = [h for h in info.get("handlers") or [] if h["name"].startswith(f"learned/{name}.")]
        if not report.handlers:
            report.problems.append("the module registered no @handler functions")
            return report
        raw = sandbox.raw_solve(attempt, artifacts)
        report.answers = raw.get("answers") or {}
        mine = f"learned/{name}."
        report.traces = [t for t in raw.get("traces") or [] if t.startswith(mine)]
        report.other_traces = [t for t in raw.get("traces") or [] if not t.startswith(mine)]
        report.printed = raw.get("printed") or ""
        decision = decide(attempt, to_solution(raw), min_confidence, trust_guessed_ids)
        report.held = dict(decision.held)
        qs = {q.id: q for q in attempt.questions}
        for qid, values in (refused or {}).items():
            got = report.answers.get(qid, {}).get("value")
            if got is not None and normalize(qs.get(qid), got) in {normalize(qs.get(qid), x) for x in values}:
                report.held[qid] = f"still {got!r}, which the Game Master already refused for this question"
        if archive is not None:
            rows = replay(archive, None, min_confidence, trust_guessed_ids, solver=sandbox.solve,
                          latest=regression_latest)
            report.regressions = [r for r in rows if not r["ok"] and r["run"] not in (baseline or set())]
    except SandboxError as e:
        report.problems.append(str(e))
        return report
    finally:
        sandbox.close()
    report.ok = not (report.held or report.regressions or report.traces)
    return report
