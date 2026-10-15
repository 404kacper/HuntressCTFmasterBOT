"""One attempt, end to end: start/retry -> download -> solve -> gate -> submit.

Everything between the start request and the submit reply is the clock on a
timed attempt, so nothing in that window prints, writes to disk, or computes
anything the answers do not need. Archiving and the inventory happen after.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Callable

from . import web
from .archive import Archive, Run
from .forensics.artifacts import ArtifactSet
from .forensics.identity import inventory
from .gate import DEFAULT_MIN_CONFIDENCE, Decision, decide
from .gm import Download, GameMaster, GMError
from .model import TERMINAL_RESULTS, Attempt
from .solvers import Solution, load_handlers, solve

# Called when the gate held something and a human is available. Returns
# "y" (send the confident answers), "a" (also send the low-confidence ones) or "n".
Prompt = Callable[[Attempt, Decision, Solution], str]
# (attempt, artifacts) -> Solution. Default: built-in handlers in this process;
# with learned handlers, the sandbox worker's solve (hunt.learn.sandbox).
Solver = Callable[[Attempt, ArtifactSet], Solution]


@dataclass
class Outcome:
    status: str  # submitted | dry-run | held | no-artifact | wrong-artifact | not-timed | pending | gm-error
    message: str = ""
    attempt: Attempt | None = None
    solution: Solution | None = None
    decision: Decision | None = None
    sent: dict[str, str] | None = None
    reply: dict | None = None
    run: Run | None = None
    timings: dict[str, float] = field(default_factory=dict)
    downloads: list[Download] = field(default_factory=list)


def play(gm: GameMaster, archive: Archive, challenge: str, *, timed: bool, use_retry: bool | None,
         submit: bool, min_confidence: float = DEFAULT_MIN_CONFIDENCE, partial: bool = False,
         prompt: Prompt | None = None, trust_guessed_ids: bool = False,
         refuse: set[str] | None = None, solver: Solver | None = None) -> Outcome:
    """use_retry: True sends op=retry, False sends start. None (auto) sends
    start, and if that only reconnects to a finished attempt, follows with
    retry. Reconnecting starts no clock, so the extra request costs no time.

    refuse: attempt ids / artifact sha256s already solved in this session;
    getting one of them back means retry has not advanced yet ('pending')."""
    load_handlers()  # imports happen before the clock, not on it
    clock = time.perf_counter
    t: dict[str, float] = {}
    rft = True if timed else None
    t0 = clock()
    retried = False
    try:
        if use_retry:
            data = gm.retry(challenge, run_for_time=rft)
            retried = True
        else:
            data = gm.start(challenge, run_for_time=rft)
            if use_retry is None and _finished(challenge, data, gm.server_now()):
                t_start = clock()
                try:
                    data = gm.retry(challenge, run_for_time=rft)
                    retried, t0 = True, t_start
                except GMError as e:
                    if e.transport or e.status != 409:
                        raise
                    if _server_says_finished(data):
                        # Retry refused on a solved attempt: its scoring is not confirmed yet.
                        return Outcome("pending", f"retry refused for now ({e}); the last solve is probably "
                                       "still awaiting confirmation", Attempt.from_response(challenge, data))
                    # Otherwise the server says the attempt is still live, so our deadline
                    # arithmetic was wrong: carry on with the attempt start gave us.
    except GMError as e:
        if e.transport and timed:
            return Outcome("gm-error", f"no reply from the Game Master: {e}. It may still have opened a timed "
                           f"attempt: check with `py -m hunt status {challenge}`; running race again reconnects "
                           "to it if it is still running.", reply=e.data)
        return Outcome("gm-error", f"the Game Master refused: {e}", reply=e.data)
    t["start"] = clock() - t0
    t_ready = clock()  # the server's clock starts about now, once the material is ready
    attempt = Attempt.from_response(challenge, data)

    if retried and _server_says_finished(data):
        return Outcome("pending", "retry handed back the attempt that is already solved; its scoring is "
                       "probably still awaiting confirmation", attempt, timings=t)
    # A new attempt id is a new attempt, even if its artifact repeats an earlier variant;
    # the SHA-256 comparison is only for replies that carry no id at all.
    if refuse and ((attempt.attempt_id in refuse) if attempt.attempt_id else bool(attempt.expected_sha256 & refuse)):
        return Outcome("pending", "the Game Master handed back an attempt this session already solved",
                       attempt, timings=t)

    flag_only = attempt.flag_only and not _server_says_finished(data)
    if not attempt.downloads and not flag_only and (attempt.result or not attempt.questions):
        run = _archive(archive, attempt, data, [], None, None, None, None)
        return Outcome("no-artifact", _no_artifact_message(attempt), attempt, run=run, timings=t)
    if timed and not attempt.timed:
        run = _archive(archive, attempt, data, [], None, None, None, None)
        return Outcome("not-timed", "the reply has no deadline: this reconnected to an existing untimed "
                       "attempt. Finish it with `hunt solve CID --submit` first, then race.",
                       attempt, run=run, timings=t)

    try:
        t1 = clock()
        if flag_only:
            # Nothing to download from the Game Master; a page the prompt links may hold the answer.
            downloads = web.fetch_targets(str(data.get("prompt") or ""), {gm.host.lower()})
        else:
            downloads = gm.artifacts(challenge, attempt.downloads)
        t["download"] = clock() - t1
    except GMError as e:
        run = _archive(archive, attempt, data, getattr(e, "partial", []), None, None, None, None)
        return Outcome("gm-error", str(e), attempt, run=run, timings=t)

    problem, downloads = (None, downloads) if flag_only else _verify_downloads(attempt, downloads)
    if problem:
        run = _archive(archive, attempt, data, downloads, None, None, None, None)
        return Outcome("wrong-artifact", problem, attempt, run=run, timings=t)

    t2 = clock()
    arts = ArtifactSet([(d.filename or "", d.data) for d in downloads])
    solution = (solver or solve)(attempt, arts)
    decision = decide(attempt, solution, min_confidence, trust_guessed_ids)
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
    message = ""
    if sent:
        t3 = clock()
        try:
            reply = gm.submit(challenge, sent)
        except GMError as e:
            reply = {"error": str(e), "data": e.data}
            if e.transport:
                message = ("the submit got no reply, so its outcome is UNKNOWN. Run `hunt status CID` "
                           "before doing anything else; do not resubmit blindly.")
        t["submit"] = clock() - t3
    t["start->submit-reply"] = clock() - t0
    if sent:
        t["on-clock(approx)"] = clock() - t_ready

    # ---- off the clock ----------------------------------------------------
    try:
        run = _archive(archive, attempt, data, downloads, arts, solution, decision, (sent, reply), t)
    except Exception as e:  # never lose the reply because the disk said no
        run = None
        message += f" (archiving failed: {type(e).__name__}: {e})"
    if sent:
        status = "submitted"
    elif submit:
        status = "held"
    else:
        status = "dry-run"
    return Outcome(status, message.strip(), attempt, solution, decision, sent, reply, run, t, downloads)


def _verify_downloads(attempt: Attempt, downloads: list[Download]) -> tuple[str | None, list[Download]]:
    """Check fetched bytes against the SHA-256 values in the reply and put them in
    reply order (download i <-> delivery i). Returns (problem, downloads)."""
    got = [hashlib.sha256(d.data).hexdigest() for d in downloads]
    n = len(downloads)
    if n > 1 and len(set(got)) < n:
        return "several downloads came back identical; refusing to answer for copies of one file", downloads
    per = attempt.download_sha256 if len(attempt.download_sha256) == n else []
    known = [(i, h) for i, h in enumerate(per) if h]
    if known:
        if any(h not in got for _, h in known):
            return ("downloaded bytes do not match the per-download SHA-256 values in the reply; refusing to "
                    "answer for the wrong files"), downloads
        ordered: list[Download | None] = [None] * n
        for i, h in known:  # each file to the slot whose SHA-256 it has
            ordered[i] = downloads[got.index(h)]
        rest = iter(d for d in downloads if all(d is not o for o in ordered))
        return None, [o if o is not None else next(rest) for o in ordered]
    if attempt.expected_sha256 and not set(got) <= attempt.expected_sha256:
        return ("downloaded bytes do not match the artifact SHA-256 in the reply; refusing to answer for "
                "the wrong variant"), downloads
    return None, downloads


def _server_says_finished(data: dict) -> bool:
    return str(data.get("result") or "").upper() in TERMINAL_RESULTS or bool(data.get("solved_by"))


def _finished(challenge: str, data: dict, server_now: datetime | None = None) -> bool:
    """A reconnect to an attempt that can no longer be answered: solved,
    failed or expired (whether or not the reply still carries its download
    link), including a timed attempt whose deadline has passed, e.g. one a
    failed earlier race left behind. The deadline is judged on the server's
    clock with a margin for the Date header's one-second resolution."""
    if _server_says_finished(data):
        return True
    left = Attempt.from_response(challenge, data).seconds_left(server_now)
    return left is not None and left < -2


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
    if submitted and submitted[0]:  # ground truth first, before anything that could fail
        run.write_json("submit.json", {"sent": submitted[0], "reply": submitted[1]})
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
    return run
