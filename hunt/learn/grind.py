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
import time
from dataclasses import dataclass, field
from typing import Callable

from ..archive import Archive, Run
from ..forensics.artifacts import ArtifactSet
from ..gate import DEFAULT_MIN_CONFIDENCE, decide, format_problem, normalize
from ..gm import GameMaster, GMError
from ..model import TERMINAL_RESULTS, Attempt, attempts_left
from ..runner import Outcome, play
from ..solvers import SET_ID
from ..solvers import solve as builtin_solve
from . import packet
from . import policy
from .advisor import TRUNCATED, Advisor, AdvisorError, Conversation, extract_module
from .library import Library, module_of, valid_name
from .sandbox import Sandbox
from .trial import failing_runs, run_trial

MODE_ORDER = {"": 0, "time_trial": 1, "mastery": 2}
# A mode with this few attempts left is only started once every layout the bot has seen of the
# challenge comes out fully answered offline (Mastery routes allow two attempts in all).
SCARCE_ATTEMPTS = 2
PREFLIGHT_RUNS = 20  # newest archived runs per mode that the preflight re-solves


@dataclass
class GrindOptions:
    rounds: int = 4  # advisor replies per learning episode
    episodes: int = 3  # learning episodes per challenge
    fresh_variants: int = 1  # regular variants that may be spent after an attempt is lost
    # (a timed attempt whose clock ran out while the bot was learning from it does not count: the
    # retry after it is how the lesson gets used, so timed starts <= 1 + episodes + fresh_variants)
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    trust_guessed_ids: bool = False
    accept_timer: bool = False  # also start routes that do not say their start is untimed
    submit: bool = True  # False: learn and prove, but send nothing
    one_by_one: bool = True  # submit answers singly so a refusal names the wrong one
    alternatives: int = 6  # refused answers retried with a handler's alternative spellings (untimed only)
    preflight: bool = True  # before a new timed attempt, re-solve every archived layout offline (and learn)


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
    batched: int = 0  # answers sent together because the clock left no time to send them singly


# Sending answers singly on a timed attempt costs one round trip each; keep this much in hand.
_CLOCK_MARGIN = 3.0
_RTT_SLACK = 1.5


def submit_stepwise(gm: GameMaster, o: Outcome, library: Library, one_by_one: bool = True) -> Verdict:
    """Send the answers one at a time (answers from trusted handlers first), stopping at
    the first refusal, so a refusal names the exact answer that was wrong. The Game
    Master keeps correct partial progress ("accepted", with what remains). With
    one_by_one=False everything goes in a single request. On a timed attempt, the
    answers still left go in one request as soon as the deadline leaves no room for
    one round trip each: a full answer set beats a refusal that names its culprit."""
    attempt, sol, dec = o.attempt, o.solution, o.decision
    ids = attempt.answer_id_map()[0]
    by_aid = {ids[q.id]: q.id for q in attempt.questions if q.id in ids}

    def handler_of(aid: str) -> str:
        qid = by_aid.get(aid, aid)
        return sol.answers[qid].handler if qid in sol.answers else ""

    items = sorted(dec.submit.items(), key=lambda kv: not library.trusted(handler_of(kv[0])))  # stable
    v = Verdict()
    # A small download is about one round trip: the first estimate, until a submit measures one.
    rtt = min(o.timings.get("download") or 1.0, 1.0)
    while items:
        left = attempt.seconds_left(gm.server_now()) if attempt.timed else None
        if one_by_one and len(items) > 1 and left is not None \
                and left < _CLOCK_MARGIN + len(items) * rtt * _RTT_SLACK:
            v.batched = len(items)
        if one_by_one and not v.batched:
            group, items = dict(items[:1]), items[1:]
        else:
            group, items = dict(items), []
        t = time.perf_counter()
        try:
            reply = gm.submit(attempt.challenge, group)
        except GMError as e:
            v.steps.append({"sent": group, "error": str(e), "data": e.data})
            v.message = f"submit failed: {e}"
            v.unknown = e.transport
            return v
        rtt = max(rtt, time.perf_counter() - t)
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
    v.message = "every answer was accepted but the Game Master never said CORRECT" if v.steps else "nothing to send"
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


def archived_refusals(archive: Archive, attempt) -> dict[str, set[str]]:
    """question id -> values the Game Master refused on this same attempt (same attempt id, or for
    a static Single Solve artifact the same bytes) in earlier runs, so a new run does not send
    them again."""
    out: dict[str, set[str]] = {}
    for run in archive.runs(attempt.challenge):
        sub = run.read_json("submit.json") or {}
        steps = sub.get("steps") or []
        if not steps:
            continue
        try:
            a = run.attempt()
        except Exception:
            continue
        same_id = bool(attempt.attempt_id) and a.attempt_id == attempt.attempt_id
        same_bytes = bool(attempt.expected_sha256) and a.expected_sha256 == attempt.expected_sha256
        if not (same_id or same_bytes):
            continue
        by_aid = {aid: qid for qid, aid in a.answer_id_map()[0].items()}
        for st in steps:
            sent, reply = st.get("sent") or {}, st.get("reply") or {}
            if len(sent) == 1 and str(reply.get("result") or "").lower() in ("incorrect", "wrong"):
                aid, value = next(iter(sent.items()))
                out.setdefault(by_aid.get(aid, aid), set()).add(str(value))
    return out


def untried(ans, q, refused: set[str]) -> list[str]:
    """The answer's value and alternatives that the Game Master has not refused, best first."""
    seen = {normalize(q, x) for x in refused}
    out = []
    for v in [ans.value] + list(ans.alternatives or []):
        n = normalize(q, v)
        if n not in seen and v not in out and format_problem(q, v) is None:
            out.append(v)
    return out


def use_alternatives(o: Outcome, refused: dict[str, set[str]], min_confidence: float,
                     trust_guessed_ids: bool) -> list[str]:
    """Swap every refused answer for its handler's next alternative and re-gate; an answer with
    nothing left to try is held, so it is never sent again. Returns what was swapped."""
    changed = []
    stale = {}
    qs = {q.id: q for q in o.attempt.questions}
    for qid, values in refused.items():
        ans = o.solution.answers.get(qid) if o.solution else None
        if ans is None or qid not in qs:
            continue
        options = untried(ans, qs[qid], values)
        if not options:
            stale[qid] = f"the Game Master already refused {ans.value!r} (and every alternative) for this question"
        elif options[0] != ans.value:
            changed.append(f"{qid}: {ans.value!r} -> {options[0]!r}")
            ans.evidence = f"{ans.evidence} [alternative: {ans.value!r} was refused]"
            ans.value = options[0]
    if changed or stale:
        o.decision = decide(o.attempt, o.solution, min_confidence, trust_guessed_ids)
        ids = o.attempt.answer_id_map()[0]
        for qid, why in stale.items():
            o.decision.submit.pop(ids.get(qid, qid), None)
            o.decision.held[qid] = why
    return changed


def _unanswered(dec) -> list[str]:
    """Questions held for a reason a handler could fix (not how answer ids map)."""
    return [qid for qid, why in dec.held.items() if not _id_hold(why)]


def rehearsal(run: Run, cid: str, sets: int = 2) -> tuple[dict, list[tuple[str, bytes]]] | None:
    """An archived single-download attempt rebuilt the way Mastery asks it: the same questions
    once per set ('set1.<id>', 'set2.<id>'), one copy of the download per set. None when the run
    is not a single-download layout."""
    try:
        attempt, arts = run.attempt(), run.artifact_set()
    except Exception:
        return None
    if len(arts.tops) != 1 or not attempt.questions or attempt.flag_only \
            or any(SET_ID.match(q.id) for q in attempt.questions):
        return None
    keep = {k: v for k, v in attempt.raw.items()
            if k not in ("questions", "tasks", "answer_ids", "download", "downloads", "deliveries", "artifacts",
                         "artifact_sha256", "deadline", "result", "attempt_id", "attempt")}
    qs = [{**{k: v for k, v in q.raw.items() if k != "answer_id"}, "id": f"set{n}.{q.id}", "set": n}
          for n in range(1, sets + 1) for q in attempt.questions]
    top = arts.tops[0]
    return {**keep, "questions": qs, "answer_ids": [d["id"] for d in qs]}, [(top.name, top.data)] * sets


def first_gap(archive: Archive, cid: str, solver, opts: GrindOptions) -> tuple[Outcome, str] | None:
    """The first layout of this challenge the current handlers cannot fully answer, offline:
    every archived run of each of its modes (newest first), then, for Mastery, each archived
    single-download layout rebuilt in Mastery shape. For a rehearsal the outcome has no run yet
    (keep_rehearsal archives it, when the advisor is to be asked about it)."""
    solver = solver or builtin_solve
    base = packet.base_id(cid)
    layouts: dict[tuple, Run] = {}
    for route in (base, f"{base}/time_trial", f"{base}/mastery"):
        runs = [r for r in archive.runs(route) if (r.path / "artifacts.json").exists()]
        for run in reversed(runs[-PREFLIGHT_RUNS:]):
            try:
                attempt, arts = run.attempt(), run.artifact_set()
            except Exception:
                continue
            if not attempt.questions:
                continue
            sol = solver(attempt, arts)
            dec = decide(attempt, sol, opts.min_confidence, opts.trust_guessed_ids)
            gaps = _unanswered(dec)
            if gaps:
                return (Outcome("dry-run", "", attempt, sol, dec, run=run),
                        f"archived {route} attempt {run.path.name} leaves {len(gaps)} question(s) unanswered")
            if route != f"{base}/mastery":
                layouts.setdefault(tuple(sorted(q.id for q in attempt.questions)), run)
    if mode(cid) != "mastery":
        return None
    for run in layouts.values():
        built = rehearsal(run, cid)
        if built is None:
            continue
        raw, tops = built
        attempt = Attempt.from_response(cid, raw)
        sol = solver(attempt, ArtifactSet(tops))
        dec = decide(attempt, sol, opts.min_confidence, opts.trust_guessed_ids)
        gaps = _unanswered(dec)
        if gaps:
            o = Outcome("dry-run", str(run.path), attempt, sol, dec, reply=raw)
            o.downloads = tops
            return o, (f"the {len(raw['questions']) // 2}-question layout of {run.path.parent.name}, asked the "
                       f"Mastery way, leaves {len(gaps)} question(s) unanswered")
    return None


def keep_rehearsal(archive: Archive, cid: str, o: Outcome) -> Outcome:
    """Archive a rehearsal from first_gap (in its own folder, so it is never mistaken for a real
    attempt of the route) and return the outcome pointing at it, ready for learn()."""
    run = archive.new_run(f"{cid}-rehearsal", "rehearsal")
    run.write_json("meta.json", {"challenge": cid, "rehearsal_of": o.message})
    run.write_json("start.json", o.reply)
    run.write_artifacts([(name, data, None) for name, data in o.downloads])
    o.run, o.attempt = run, run.attempt()
    return o


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
    message = packet.build(o.attempt, arts, o.solution, o.decision, library, archive, entry, refused=refused)
    if feedback:
        message = f"## What happened last time\n{feedback}\n\n" + message
    baseline = failing_runs(library, archive, opts.min_confidence, opts.trust_guessed_ids)
    transcript = _Transcript(o.run.path / "advisor")
    for rnd in range(1, opts.rounds + 1):
        log(f"    asking the advisor (round {rnd}/{opts.rounds})...")
        transcript.write("ask", message)
        try:
            reply = convo.ask(message)
        except AdvisorError as e:
            transcript.write("error", str(e))
            log(f"    advisor: {e}")
            return None
        transcript.write(f"reply-{convo.served_by or convo.advisor.name}", reply)
        name, source = extract_module(reply)
        if source is None:
            gist = " ".join(reply.split())[:160] or "(empty reply)"
            if TRUNCATED in reply:
                log("    the reply was cut off at the output limit before the module was complete")
                message = ("Your reply was cut off at the output limit before the module was complete. Send a "
                           "more compact complete module in one ```python block.")
            else:
                log(f"    the reply had no ```python block: {gist}")
                message = ("Your reply had no ```python block. Reply with the complete module in one fenced "
                           "```python block whose first line is `# learned-module: <name>`.")
            continue
        if not valid_name(name):
            name = re.sub(r"[^a-z0-9_]+", "_", f"learned_{packet.base_id(o.attempt.challenge)}".lower())[:47]
        report = run_trial(library, name, source, o.attempt, arts, archive, opts.min_confidence,
                           opts.trust_guessed_ids, refused=refused, baseline=baseline)
        transcript.write("trial", report.feedback())
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


class _Transcript:
    """Every packet, reply and trial verdict of a learning episode, next to the run it is about,
    so a failed episode can be read afterwards (runs/<challenge>/<run>/advisor/)."""

    def __init__(self, path):
        n = 1
        while path.with_name(f"{path.name}-{n}" if n > 1 else path.name).exists():
            n += 1
        self.path = path.with_name(f"{path.name}-{n}" if n > 1 else path.name)
        self.n = 0

    def write(self, kind: str, text: str) -> None:
        self.n += 1
        try:
            self.path.mkdir(exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", kind)[:40]
            (self.path / f"{self.n:02d}-{safe}.md").write_text(text, encoding="utf-8")
        except OSError:
            pass  # a transcript must never stop the learning


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
    seeded: set[str] = set()  # attempts whose earlier refusals were read from the archive
    still_open: set[str] = set()  # attempts whose retry got 409: open, whatever their result says
    announced: set[str] = set()  # timed attempts whose clock was reported
    learned_on_clock = False  # a module was learned from the current timed attempt
    retry_refused = ""  # what the Game Master said when it answered a retry with 409
    last_id: str | None = None
    raw: dict = {}
    # Time Trial / Mastery routes without run_for_time_supported: every new attempt runs a clock
    # and spends one of a few attempts, so the bot only starts one once it is ready.
    timed_route = bool(mode(cid)) and not entry.get("run_for_time_supported")
    offline_episodes = 0

    def preflight() -> list[str]:
        """Offline, before a new timed attempt: learn from every layout of this challenge the
        handlers cannot fully answer yet (no clock, no attempt spent). Returns what is still open."""
        nonlocal convo, offline_episodes
        while True:
            gap = first_gap(archive, cid, box.get(), opts)
            if gap is None:
                return []
            o2, what = gap
            if advisor is None or offline_episodes >= opts.episodes:
                return [what]
            offline_episodes += 1
            if o2.run is None:
                o2 = keep_rehearsal(archive, cid, o2)
            convo = convo or advisor.conversation(cid)
            convo.log = log
            log(f"  preflight: {what}; learning from it offline, before any attempt is spent")
            log(f"  learning: {', '.join(_unanswered(o2.decision))}")
            name = learn(convo, library, archive, o2, entry, None, opts, log)
            if name is None:
                return [what]
            res.learned.append(name)
            box.reset()

    def why_not_start(reply: dict) -> str | None:
        """Why a new timed attempt must not be started now (None: go ahead)."""
        if not timed_route:
            return None
        left = attempts_left(reply)
        if left == 0:
            return f"no attempts left on this mode (unique_attempts_remaining: 0); `hunt status {cid}` shows it"
        gaps = preflight() if opts.preflight else []
        if not gaps:
            return None
        scarce = left <= SCARCE_ATTEMPTS if left is not None else mode(cid) == "mastery"
        if scarce:
            return (f"not starting a new attempt with {left if left is not None else 'an unknown number of'} "
                    f"attempt(s) left on this mode: the bot still cannot answer {'; '.join(gaps)}. Run grind "
                    "again with an advisor (it learns offline first), or pass --no-preflight to start anyway")
        log(f"  preflight: {'; '.join(gaps)}; starting anyway ({left} attempts left on this mode)")
        return None

    try:
        if not Attempt.from_response(cid, st).attempt_id:
            # Nothing started yet on this mode: the first start is a new attempt too.
            stop = why_not_start(st)
            if stop:
                res.detail = stop
                return res
        for _ in range(2 + 2 * opts.episodes + opts.fresh_variants + opts.alternatives):
            if use_retry:
                if not untimed_retry:
                    res.detail = ("the attempt is over and this route has no untimed retry (no "
                                  "run_for_time_supported): the bot will not start a clock for you. "
                                  "Check `hunt status`; --accept-timer allows it")
                    return res
                if spent >= opts.fresh_variants and not learned_on_clock:
                    left = attempts_left(raw)
                    res.detail = (f"the attempt was lost and --fresh-variants {opts.fresh_variants} allows no "
                                  "more fresh variants (each is a new start" + (
                                      f"; {left} attempt(s) left on this mode" if left is not None else "")
                                  + "); run grind again or pass a higher --fresh-variants")
                    return res
                stop = why_not_start(raw if attempts_left(raw) is not None else st)
                if stop:
                    res.detail = stop
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
                    retry_refused = str(e)
                else:
                    if learned_on_clock:
                        log("  (the clock ran out while the bot was learning; this variant is where the new "
                            "handler gets used, so it does not count against --fresh-variants)")
                    else:
                        spent += 1
                    learned_on_clock = False
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
            if lost(raw) and last_id and last_id in still_open \
                    and str(raw.get("result") or "").upper() not in ("INCORRECT", "WRONG"):
                # A 409 said "still open", yet the attempt has expired or failed: the retry was
                # refused for another reason (often: no attempts left on this route).
                res.status = "error"
                res.detail = (f"the attempt is over ({raw.get('result')}) and the Game Master refused a fresh one "
                              f"({retry_refused}); check `hunt status {cid}`: this route may have no attempts left")
                return res
            if lost(raw) and not (last_id and last_id in still_open):
                log(f"  the current attempt is over ({raw.get('result')}); asking for a fresh one")
                use_retry = True
                continue
            if o.status not in ("dry-run",):
                res.status, res.detail = "error", f"{o.status}: {o.message}"
                return res
            if o.attempt.timed and last_id not in announced:
                announced.add(last_id)
                secs, left = o.attempt.seconds_left(gm.server_now()), attempts_left(raw)
                log(f"  timed attempt: {max(secs or 0.0, 0.0):.0f}s left on the clock"
                    + (f", {left} more attempt(s) left on this mode" if left is not None else ""))
            if not o.attempt.timed:
                sig = o.attempt.attempt_id or ",".join(sorted(o.attempt.expected_sha256))
                if sig not in seeded:
                    seeded.add(sig)
                    for qid, values in archived_refusals(archive, o.attempt).items():
                        refused.setdefault(qid, set()).update(values)
                for change in use_alternatives(o, refused, opts.min_confidence, opts.trust_guessed_ids):
                    log(f"  trying an alternative answer: {change}")
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
                if v.batched:
                    log(f"  the clock was short: the last {v.batched} answers went in one request")
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
                log(f"  refused: {qid} = {value!r} (from {handler})")
                ans = o.solution.answers.get(qid) if o.solution else None
                if q is not None and ans is not None and not o.attempt.timed and untried(ans, q, refused[qid]):
                    continue  # the next pass sends the handler's next alternative; no advisor needed yet
                module = module_of(handler)
                feedback = (f"The Game Master refused the answer {value!r} to question `{qid}`"
                            + (f" ({q.text})" if q else "") + f", which came from handler `{handler}`. "
                            f"Every value it has refused for `{qid}` so far: {sorted(refused[qid])!r}. Every "
                            "answer sent before it was accepted. Work out what that handler got wrong. If the fact "
                            "is right and only its spelling is in doubt, return the best spelling as the value "
                            "and the other plausible spellings as alternatives=[...], best first."
                            + (f" Revise learned/{module}.py by sending the whole module under the same name "
                               f"`{module}`." if module and module in library.names() else ""))
                if module and module in library.names():
                    # Kept either way: one refused field is no reason to throw away the answers it got
                    # right. The refused value is recorded, so the trial only passes a revision that
                    # answers differently.
                    log(f"  learned/{module}.py kept; asking the advisor to revise it")
                continue  # look again: the attempt may still be open, or may need a fresh variant
            # Something is held (or a refused answer needs a better handler): learn.
            if feedback is None and o.decision.held and all(_id_hold(w) for w in o.decision.held.values()):
                res.detail = ("every held answer is held only because the reply's answer_ids could not be matched "
                              "to questions with certainty; no new handler can fix that. Check the reply with "
                              f"`hunt inspect {cid}`; --trust-positional-ids sends them by position")
                return res
            if advisor is None:
                where = _save_packet(o, library, archive, entry, refused)
                res.detail = (f"{len(o.decision.held)} question(s) need a new handler and there is no advisor; "
                              f"packet saved to {where}")
                return res
            if episodes >= opts.episodes:
                res.detail = f"no handler passed after {opts.episodes} learning episode(s)"
                return res
            episodes += 1
            convo = convo or advisor.conversation(cid)
            convo.log = log
            held = ", ".join(o.decision.held) or "(answers to revise)"
            log(f"  learning: {held}")
            name = learn(convo, library, archive, o, entry, feedback, opts, log, refused)
            feedback = None
            if name is None:
                res.detail = "the advisor's modules never passed the offline trial"
                return res
            res.learned.append(name)
            learned_on_clock = learned_on_clock or o.attempt.timed
            box.reset()
        res.detail = "gave up: step limit reached"
        return res
    finally:
        box.close()
        if convo is not None:
            convo.close()


def _save_packet(o: Outcome, library: Library, archive: Archive, entry: dict | None,
                 refused: dict[str, set[str]] | None = None) -> str:
    text = packet.build(o.attempt, o.run.artifact_set(), o.solution, o.decision, library, archive, entry,
                        refused=refused)
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
