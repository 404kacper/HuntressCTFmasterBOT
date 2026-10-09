"""One attempt, end to end: start/retry -> download -> solve -> gate -> submit.

Everything between the start request and the submit reply is the clock on a
timed attempt, so nothing in that window prints, writes to disk, or computes
anything the answers do not need. Archiving and the inventory happen after.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable

from .archive import Archive, Run
from .forensics.artifacts import ArtifactSet
from .forensics.identity import inventory
from .gate import DEFAULT_MIN_CONFIDENCE, Decision, decide
from .gm import Download, GameMaster, GMError
from .model import Attempt
from .solvers import Solution, load_handlers, solve

# Called when the gate held something and a human is available. Returns
# "y" (send the confident answers), "a" (also send the low-confidence ones) or "n".
Prompt = Callable[[Attempt, Decision, Solution], str]


@dataclass
class Outcome:
    status: str  # submitted | dry-run | held | no-artifact | wrong-artifact | gm-error
    message: str = ""
    attempt: Attempt | None = None
    solution: Solution | None = None
    decision: Decision | None = None
    sent: dict[str, str] | None = None
    reply: dict | None = None
    run: Run | None = None
    timings: dict[str, float] = field(default_factory=dict)


def play(gm: GameMaster, archive: Archive, challenge: str, *, timed: bool, use_retry: bool,
         submit: bool, min_confidence: float = DEFAULT_MIN_CONFIDENCE, partial: bool = False,
         prompt: Prompt | None = None) -> Outcome:
    load_handlers()  # imports happen before the clock, not on it
    clock = time.perf_counter
    t: dict[str, float] = {}
    t0 = clock()
    try:
        rft = True if timed else None
        data = gm.retry(challenge, run_for_time=rft) if use_retry else gm.start(challenge, run_for_time=rft)
    except GMError as e:
        return Outcome("gm-error", f"{'retry' if use_retry else 'start'} refused: {e}", reply=e.data)
    t["start"] = clock() - t0
    attempt = Attempt.from_response(challenge, data)

    if not attempt.downloads and (attempt.result or not attempt.questions):
        run = _archive(archive, attempt, data, [], None, None, None, None)
        return Outcome("no-artifact", _no_artifact_message(attempt), attempt, run=run, timings=t)

    try:
        t1 = clock()
        downloads = gm.artifacts(challenge, attempt.downloads)
        t["download"] = clock() - t1
    except GMError as e:
        run = _archive(archive, attempt, data, [], None, None, None, None)
        return Outcome("gm-error", str(e), attempt, run=run, timings=t)

    if attempt.expected_sha256:
        got = {hashlib.sha256(d.data).hexdigest() for d in downloads}
        if not got <= attempt.expected_sha256:
            run = _archive(archive, attempt, data, downloads, None, None, None, None)
            return Outcome("wrong-artifact", "downloaded bytes do not match the artifact SHA-256 in the "
                           "reply; refusing to answer for the wrong variant", attempt, run=run, timings=t)

    t2 = clock()
    arts = ArtifactSet([(d.filename or "", d.data) for d in downloads])
    solution = solve(attempt, arts)
    decision = decide(attempt, solution, min_confidence)
    t["solve"] = clock() - t2

    sent = None
    if submit:
        if decision.complete:
            sent = decision.submit
        elif prompt is not None:
            choice = prompt(attempt, decision, solution)
            sent = {"y": decision.submit, "a": {**decision.submit, **decision.tentative}}.get(choice)
        elif partial:
            sent = decision.submit
    reply = None
    if sent:
        t3 = clock()
        try:
            reply = gm.submit(challenge, sent)
        except GMError as e:
            reply = {"error": str(e), "data": e.data}
        t["submit"] = clock() - t3
    t["start->submit-reply"] = clock() - t0

    # ---- off the clock ----------------------------------------------------
    run = _archive(archive, attempt, data, downloads, arts, solution, decision, (sent, reply), t)
    if sent:
        status = "submitted"
    elif submit:
        status = "held"
    else:
        status = "dry-run"
    return Outcome(status, "", attempt, solution, decision, sent, reply, run, t)


def _no_artifact_message(a: Attempt) -> str:
    if (a.result or "").upper() == "CORRECT":
        return ("this attempt is already solved (start just reconnects to it). Use --retry for the "
                "next fresh variant, or `race` for a timed one.")
    return f"reply has no download (result={a.result!r}); see start.json in the run folder"


def _archive(archive: Archive, attempt: Attempt, data: dict, downloads: list[Download],
             arts: ArtifactSet | None, solution: Solution | None, decision: Decision | None,
             submitted, timings: dict | None = None) -> Run:
    run = archive.new_run(attempt.challenge, "timed" if attempt.timed else "regular")
    run.write_json("start.json", data)
    if downloads:
        run.write_artifacts([(d.filename, d.data, d.url) for d in downloads])
    if solution is not None and decision is not None:
        run.write_json("solution.json", {
            "answers": {qid: {"value": a.value, "confidence": a.confidence, "evidence": a.evidence,
                              "handler": a.handler} for qid, a in solution.answers.items()},
            "unresolved": solution.unresolved,
            "held": decision.held,
            "warnings": decision.warnings,
            "timings": timings or {},
        })
    if arts is not None:
        try:
            run.write_json("inventory.json", inventory(arts))
        except Exception as e:  # analysis must never lose the archive
            run.write_json("inventory.json", {"error": repr(e)})
    if submitted and submitted[0]:
        run.write_json("submit.json", {"sent": submitted[0], "reply": submitted[1]})
    return run
