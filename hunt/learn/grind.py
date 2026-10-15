"""hunt grind: walk the challenges until each one has scored.

For each challenge, in the order the Game Master unlocks them (Single Solve,
then Time Trial, then Mastery), it takes an untimed attempt, solves what it
can and submits once every answer passes the gate. A CORRECT reply means the
points are in: that challenge is done. When a question has no handler, the
advisor (Claude) is asked to write one; the module is proven offline in the
sandbox, kept in learned/, and the attempt is solved again with it.

Answers from handlers the Game Master has not yet accepted go in one at a
time, after everything else: a refusal then names the exact answer (and the
handler) that was wrong, and that goes back to the advisor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..archive import Archive, Run
from ..gate import DEFAULT_MIN_CONFIDENCE
from ..gm import GameMaster, GMError
from ..model import TERMINAL_RESULTS
from ..runner import Outcome, play
from . import packet
from . import policy
from .advisor import TRUNCATED, Advisor, AdvisorError, Conversation, extract_module
from .library import Library, module_of, valid_name
from .sandbox import Sandbox
from .trial import failing_runs, run_trial

MODE_ORDER = {"": 0, "time_trial": 1, "mastery": 2}


@dataclass
class GrindOptions:
    rounds: int = 4  # advisor replies per learning episode
    episodes: int = 3  # learning episodes per challenge
    fresh_variants: int = 1  # regular variants that may be spent after an attempt is lost
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    trust_guessed_ids: bool = False
    accept_timer: bool = False  # also start routes that do not say their start is untimed
    submit: bool = True  # False: learn and prove, but send nothing
    one_by_one: bool = True  # submit answers singly so a refusal names the wrong one


@dataclass
class Result:
    challenge: str
    name: str
    status: str  # scored | already | ready | skipped | stuck | error
    detail: str = ""
    learned: list[str] = field(default_factory=list)
    pending: bool = False  # the Game Master said scoring is pending: check CourseStack

    @property
    def points(self) -> bool:
        return self.status in ("scored", "already")


def mode(cid: str) -> str:
    return cid.split("/", 1)[1] if "/" in cid else ""


def scored(reply: dict | None) -> bool:
    if not isinstance(reply, dict):
        return False
    return str(reply.get("result") or "").upper() == "CORRECT" or bool(reply.get("solved_by")) or bool(reply.get("flag"))


def pending(reply: dict | None) -> bool:
    return isinstance(reply, dict) and str(reply.get("status") or "").lower() == "pending"


def lost(reply: dict | None) -> bool:
    """The attempt is over without a solve (failed, expired, ...). A refused answer
    alone does not end an untimed attempt ("regular untimed attempts can continue
    until solved"), so 'incorrect' only counts as over on a timed one."""
    r = str((reply or {}).get("result") or "").upper()
    if r in ("INCORRECT", "WRONG"):
        return bool((reply or {}).get("deadline"))
    return r in TERMINAL_RESULTS and r != "CORRECT"


def order(entries: list[dict]) -> list[dict]:
    return sorted(entries, key=lambda e: (e.get("day") if isinstance(e.get("day"), int) else 999,
                                          str(e.get("lane") or ""), packet.base_id(str(e.get("id"))),
                                          MODE_ORDER.get(mode(str(e.get("id"))), 9), str(e.get("id"))))


class SolverBox:
    """The sandbox worker holding the current library, restarted whenever it grows."""

    def __init__(self, library: Library):
        self.library = library
        self.sandbox: Sandbox | None = None

    def get(self):
        mods = self.library.modules()
        if not mods:
            return None  # nothing learned yet: built-in handlers, in process
        if self.sandbox is not None and not self.sandbox.alive:
            self.close()  # killed after a timeout: start a fresh one
        if self.sandbox is None:
            self.sandbox = Sandbox(mods)
            self.sandbox.start()
        return self.sandbox.solve

    def reset(self) -> None:
        self.close()

    def close(self) -> None:
        if self.sandbox is not None:
            self.sandbox.close()
            self.sandbox = None


@dataclass
class Verdict:
    correct: bool = False
    pending: bool = False
    message: str = ""
    culprit: tuple[str, str, str] | None = None  # (question id, value, handler) the Game Master refused
    unknown: bool = False  # transport failure: we do not know what happened
    over: bool = False  # the attempt ended (expired, failed): no answer was judged
    sent: dict[str, str] = field(default_factory=dict)
    steps: list[dict] = field(default_factory=list)


def submit_stepwise(gm: GameMaster, o: Outcome, library: Library, one_by_one: bool = True) -> Verdict:
    """Send the answers one at a time (answers from trusted handlers first), stopping at
    the first refusal, so a refusal names the exact answer that was wrong. The Game
    Master keeps correct partial progress ("accepted", with what remains). With
    one_by_one=False everything goes in a single request."""
    attempt, sol, dec = o.attempt, o.solution, o.decision
    ids = attempt.answer_id_map()[0]
    by_aid = {ids[q.id]: q.id for q in attempt.questions if q.id in ids}

    def handler_of(aid: str) -> str:
        qid = by_aid.get(aid, aid)
        return sol.answers[qid].handler if qid in sol.answers else ""

    items = sorted(dec.submit.items(), key=lambda kv: not library.trusted(handler_of(kv[0])))  # stable
    groups = [{aid: value} for aid, value in items] if one_by_one else ([dict(items)] if items else [])
    v = Verdict()
    for group in groups:
        try:
            reply = gm.submit(attempt.challenge, group)
        except GMError as e:
            v.steps.append({"sent": group, "error": str(e), "data": e.data})
            v.message = f"submit failed: {e}"
            v.unknown = e.transport
            return v
        v.steps.append({"sent": group, "reply": reply})
        v.sent.update(group)
        result = str((reply or {}).get("result") or "")
        if result.upper() == "CORRECT":
            v.correct, v.pending = True, pending(reply)
            return v
        if result.lower() == "accepted":
            continue
        v.message = f"the Game Master answered {result or reply!r}"
        if result.lower() not in ("incorrect", "wrong"):
            v.over = result.upper() in TERMINAL_RESULTS  # expired / failed: not a verdict on the answer
            return v
        if len(group) == 1:
            aid, value = next(iter(group.items()))
            v.culprit = (by_aid.get(aid, aid), value, handler_of(aid))
        else:
            v.message += " to the whole batch"
        return v
    v.message = "every answer was accepted but the Game Master never said CORRECT" if groups else "nothing to send"
    return v


def _record(run: Run | None, o: Outcome, v: Verdict) -> None:
    """submit.json the way replay reads it: everything sent, and the final reply."""
    if run is None or not v.steps:
        return
    last = v.steps[-1]
    run.write_json("submit.json", {"sent": v.sent, "reply": last.get("reply") or {"error": last.get("error")},
                                   "steps": v.steps})


def _modules_used(o: Outcome) -> set[str]:
    if not o.solution:
        return set()
    return {m for a in o.solution.answers.values() if (m := module_of(a.handler))}


def _id_hold(why: str) -> bool:
    """Held because of how answer ids map to questions, which no handler can fix."""
    return why.startswith("no answer_id") or " was guessed (" in why


def learn(convo: Conversation, library: Library, archive: Archive, o: Outcome, entry: dict | None,
          feedback: str | None, opts: GrindOptions, log: Callable[[str], None],
          refused: dict[str, set[str]] | None = None) -> str | None:
    """One learning episode: ask, trial, feed back, until a module passes or rounds run out.
    Returns the installed module's name."""
    arts = o.run.artifact_set() if o.run else None
    if arts is None:
        return None
    message = packet.build(o.attempt, arts, o.solution, o.decision, library, archive, entry)
    if feedback:
        message = f"## What happened last time\n{feedback}\n\n" + message
    baseline = failing_runs(library, archive, opts.min_confidence, opts.trust_guessed_ids)
    for rnd in range(1, opts.rounds + 1):
        log(f"    asking the advisor (round {rnd}/{opts.rounds})...")
        try:
            reply = convo.ask(message)
        except AdvisorError as e:
            log(f"    advisor: {e}")
            return None
        name, source = extract_module(reply)
        if source is None:
            if TRUNCATED in reply:
                message = ("Your reply was cut off at the output limit before the module was complete. Send a "
                           "more compact complete module in one ```python block.")
            else:
                message = ("Your reply had no ```python block. Reply with the complete module in one fenced "
                           "```python block whose first line is `# learned-module: <name>`.")
            continue
        if not valid_name(name):
            name = re.sub(r"[^a-z0-9_]+", "_", f"learned_{packet.base_id(o.attempt.challenge)}".lower())[:47]
        report = run_trial(library, name, source, o.attempt, arts, archive, opts.min_confidence,
                           opts.trust_guessed_ids, refused=refused, baseline=baseline)
        if report.ok:
            try:
                library.install(name, source, challenge=o.attempt.challenge, advisor=convo.advisor.name, rounds=rnd)
            except (ValueError, OSError, policy.PolicyError) as e:
                message = f"The module passed the trial but could not be saved ({e}). Send it again."
                continue
            log(f"    learned/{name}.py passed the offline trial and was installed")
            return name
        first = (report.problems or list(report.held.values()) or [r["run"] for r in report.regressions]
                 or report.traces or ["?"])[0]
        log(f"    {name}: not yet ({str(first).splitlines()[0][:160]})")
        message = report.feedback() + "\n\nSend the complete corrected module."
    return None


def grind_one(gm: GameMaster, archive: Archive, library: Library, advisor: Advisor | None, entry: dict,
              opts: GrindOptions, log: Callable[[str], None] = print) -> Result:
    cid = str(entry["id"])
    res = Result(cid, str(entry.get("name") or cid), "stuck")
    try:
        st = gm.status(cid)
    except GMError:
        st = {}
    if scored(st):
        res.status, res.detail, res.pending = "already", "the Game Master already reports it solved", pending(st)
        return res
    # A plain retry only gives an untimed variant on routes that list run_for_time_supported;
    # on older routes every start/retry may run a clock and spend a ranked attempt.
    untimed_retry = bool(entry.get("run_for_time_supported")) or opts.accept_timer
    box = SolverBox(library)
    convo: Conversation | None = None
    feedback: str | None = None
    use_retry = False
    spent = episodes = 0
    refused: dict[str, set[str]] = {}  # question id -> values the Game Master turned down (this attempt)
    still_open: set[str] = set()  # attempts whose retry got 409: open, whatever their result says
    last_id: str | None = None
    try:
        for _ in range(2 + 2 * opts.episodes + opts.fresh_variants):
            if use_retry:
                if not untimed_retry:
                    res.detail = ("the attempt is over and this route has no untimed retry (no "
                                  "run_for_time_supported): the bot will not start a clock for you. "
                                  "Check `hunt status`; --accept-timer allows it")
                    return res
                if spent >= opts.fresh_variants:
                    res.detail = (f"the attempt was lost and --fresh-variants {opts.fresh_variants} allows no "
                                  "more fresh variants")
                    return res
                try:
                    gm.retry(cid)
                except GMError as e:
                    if e.transport or e.status != 409:
                        res.status, res.detail = "error", f"retry refused: {e}"
                        return res
                    # 409: the attempt is still open after all (an untimed attempt continues
                    # until solved); keep working on it.
                    if last_id:
                        still_open.add(last_id)
                else:
                    spent += 1
                    refused.clear()  # a new variant: earlier refusals say nothing about its answers
                use_retry = False
            o = play(gm, archive, cid, timed=False, use_retry=False, submit=False,
                     min_confidence=opts.min_confidence, trust_guessed_ids=opts.trust_guessed_ids,
                     solver=box.get())
            raw = o.attempt.raw if o.attempt else {}
            last_id = o.attempt.attempt_id if o.attempt else None
            if scored(raw):
                res.status, res.detail, res.pending = "already", "the attempt is already solved", pending(raw)
                return res
            if lost(raw) and not (last_id and last_id in still_open):
                log(f"  the current attempt is over ({raw.get('result')}); asking for a fresh one")
                use_retry = True
                continue
            if o.status not in ("dry-run",):
                res.status, res.detail = "error", f"{o.status}: {o.message}"
                return res
            if o.attempt.timed and not opts.accept_timer:
                # A clock is running (an old timed attempt, or a route that is timed after all).
                # Finish it at once if every answer is ready; never learn or retry on the clock.
                if o.decision.complete and opts.submit and feedback is None:
                    log("  ! this attempt is TIMED: every answer is ready, so it is submitted right away")
                    v = submit_stepwise(gm, o, library, one_by_one=False)
                    _record(o.run, o, v)
                    if v.correct:
                        for m in _modules_used(o):
                            library.mark_proven(m, cid)
                        res.status, res.pending, res.detail = "scored", v.pending, "CORRECT (timed attempt)"
                        return res
                    res.status, res.detail = "error", f"timed attempt: {v.message}"
                    return res
                res.status = "error"
                res.detail = ("this attempt is TIMED (a clock is running) and the bot cannot answer all of it; "
                              "it does not learn on the clock. Let it expire (or finish it by hand), then run "
                              "grind again; --accept-timer allows learning on timed attempts")
                return res
            if o.decision.complete and feedback is None:
                if not opts.submit:
                    res.status, res.detail = "ready", "every answer passes the gate (nothing sent: --no-submit)"
                    return res
                v = submit_stepwise(gm, o, library, opts.one_by_one)
                _record(o.run, o, v)
                if v.correct:
                    for m in _modules_used(o):
                        library.mark_proven(m, cid)
                    res.status, res.pending = "scored", v.pending
                    res.detail = "CORRECT" + (" (scoring pending: check CourseStack)" if v.pending else "")
                    return res
                if v.unknown:
                    res.status, res.detail = "error", f"{v.message}; check `hunt status {cid}` before anything else"
                    return res
                if v.over:
                    log(f"  {v.message}: the attempt is over; asking for a fresh one")
                    use_retry = True
                    continue
                if v.culprit is None:
                    res.status, res.detail = "error", v.message
                    return res
                qid, value, handler = v.culprit
                refused.setdefault(qid, set()).add(value)
                q = next((x for x in o.attempt.questions if x.id == qid), None)
                feedback = (f"The Game Master refused the answer {value!r} to question `{qid}`"
                            + (f" ({q.text})" if q else "") + f", which came from handler `{handler}`. "
                            "Every answer sent before it was accepted. Work out what that handler got wrong.")
                log(f"  refused: {qid} = {value!r} (from {handler})")
                module = module_of(handler)
                if module and module in library.names():
                    if library.status(module) == "proven":
                        # It earned its place elsewhere; keep it. The refused value is recorded, so the
                        # advisor has to write a challenge-specific override that answers differently.
                        log(f"  learned/{module}.py is proven on other challenges: kept, asking for an override")
                    else:
                        library.reject(module, f"{cid}: {qid}={value!r} refused")
                        box.reset()
                continue  # look again: the attempt may still be open, or may need a fresh variant
            # Something is held (or a refused answer needs a better handler): learn.
            if feedback is None and o.decision.held and all(_id_hold(w) for w in o.decision.held.values()):
                res.detail = ("every held answer is held only because the reply's answer_ids could not be matched "
                              "to questions with certainty; no new handler can fix that. Check the reply with "
                              f"`hunt inspect {cid}`; --trust-positional-ids sends them by position")
                return res
            if advisor is None:
                where = _save_packet(o, library, archive, entry)
                res.detail = (f"{len(o.decision.held)} question(s) need a new handler and there is no advisor; "
                              f"packet saved to {where}")
                return res
            if episodes >= opts.episodes:
                res.detail = f"no handler passed after {opts.episodes} learning episode(s)"
                return res
            episodes += 1
            convo = convo or advisor.conversation(cid)
            held = ", ".join(o.decision.held) or "(answers to revise)"
            log(f"  learning: {held}")
            name = learn(convo, library, archive, o, entry, feedback, opts, log, refused)
            feedback = None
            if name is None:
                res.detail = "the advisor's modules never passed the offline trial"
                return res
            res.learned.append(name)
            box.reset()
        res.detail = "gave up: step limit reached"
        return res
    finally:
        box.close()
        if convo is not None:
            convo.close()


def _save_packet(o: Outcome, library: Library, archive: Archive, entry: dict | None) -> str:
    text = packet.build(o.attempt, o.run.artifact_set(), o.solution, o.decision, library, archive, entry)
    path = o.run.path / "packet.md"
    path.write_text(text, encoding="utf-8")
    return str(path)


def grind(gm: GameMaster, archive: Archive, library: Library, advisor: Advisor | None, entries: list[dict],
          opts: GrindOptions, log: Callable[[str], None] = print) -> list[Result]:
    results: list[Result] = []
    blocked: set[str] = set()  # a mode unlocks only after the one before it scored
    for entry in order(entries):
        cid = str(entry.get("id"))
        base = packet.base_id(cid)
        name = str(entry.get("name") or cid)
        if base in blocked:
            results.append(Result(cid, name, "skipped", "an earlier mode of this challenge has not scored yet"))
            continue
        if mode(cid) and not entry.get("run_for_time_supported") and not opts.accept_timer:
            results.append(Result(cid, name, "skipped", "its start may be timed (no run_for_time_supported); "
                                  "pass --accept-timer to include it"))
            blocked.add(base)
            continue
        log(f"\n== {name}  [{cid}]")
        if not mode(cid) and not entry.get("run_for_time_supported"):
            # Single Solve is documented as untimed; if this one turns out to run a clock, grind_one
            # submits only a complete answer set and never learns or retries on it.
            log("  (Single Solve route: documented as untimed)")
        try:
            r = grind_one(gm, archive, library, advisor, entry, opts, log)
        except GMError as e:
            r = Result(cid, name, "error", f"Game Master error: {e}")
        log(f"  -> {r.status}: {r.detail}")
        results.append(r)
        if not r.points:
            blocked.add(base)
    return results
