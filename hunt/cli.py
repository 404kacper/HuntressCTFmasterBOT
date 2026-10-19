"""hunt — command line for the Huntress CTF Game Master.

  hunt list [--day N] [--lane L]     what's out there (and which routes are safe to peek at)
  hunt openapi                       save the live API spec to docs/openapi.json
  hunt status CID
  hunt ping                          network round trip vs server time (compare your PC and Homebase)
  hunt solve CID                     untimed: start/reconnect, download, solve, show; nothing sent
  hunt solve CID --submit            ...and submit if every answer passes the gate
  hunt solve CID --retry             fresh regular variant (after a confirmed solve)
  hunt race CID                      timed Hall-of-Fame run (start, or retry if already finished)
  hunt offline CID                   re-solve the latest archived attempt, no network
  hunt replay [CID]                  regression: re-solve every archived CORRECT attempt
  hunt inspect CID                   what the Game Master sent for archived attempts (no network)
  hunt fetch CID --delivery 0 1      download the current attempt's files and print their SHA-256
  hunt rehearse                      full race against a local fake Game Master

  hunt grind [CHALLENGE...] [--day N]  solve every challenge (all modes) until each one scores;
                                     questions no handler knows are learned with Claude
  hunt optimize CID --target-rank 3  race until you hold that place on the Hall of Fame
  hunt learned                       what the bot has learned (learned/), and its status
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import statistics
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .archive import Archive, replay
from .forensics.identity import inventory
from . import config
from .config import ConfigError
from .gate import DEFAULT_MIN_CONFIDENCE, decide
from .gm import GameMaster, GMError
from .learn.library import Library
from .learn.sandbox import Sandbox, SandboxError
from .model import Attempt, ranked_attempts_left
from .runner import Outcome, play
from .solvers import solve


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # emoji in challenge names vs. cp1252 consoles
        except (AttributeError, ValueError):
            pass


def _gm(args) -> GameMaster:
    gm = _make_gm(args)
    if getattr(args, "wait", None):
        gm.prepare_timeout = args.wait
    return gm


def _make_gm(args) -> GameMaster:
    token = config.load_token()
    if token is None and not (args.url or os.environ.get("HUNTRESS_GM_URL") or os.environ.get("GM")) \
            and sys.stdin.isatty():
        # Hidden prompt: nothing on screen, nothing in shell history.
        token = config.clean_token(getpass.getpass(
            "Game Master token (typing is hidden; press Enter if you are on the Homebase VM): "))
    return GameMaster(base_url=args.url, token=token or "")


@contextmanager
def _solver(args, challenge: str | None = None, lane: str | None = None):
    """The sandbox worker loaded with learned/ (started now, before any clock), or
    None for built-in handlers in process: when nothing has been learned, or when
    `challenge` is given and no learned handler applies to it (the worker decides
    that, so learned patterns are never evaluated in this process)."""
    mods = Library(args.learned).modules()
    if not mods:
        yield None
        return
    sb = Sandbox(mods)
    try:
        info = sb.start()
    except SandboxError as e:
        print(f"warning: learned handlers unavailable ({e}); using built-in handlers only")
        yield None
        return
    try:
        for name, err in (info.get("errors") or {}).items():
            print(f"warning: learned/{name}.py failed to load: {err.strip().splitlines()[-1]}")
        if challenge is not None and not sb.applies(challenge, lane):
            yield None  # nothing learned is relevant here: stay in process, fastest
        else:
            yield sb.solve
    finally:
        sb.close()


# ---- printing --------------------------------------------------------------
def _print_outcome(o: Outcome, verbose: bool = True) -> None:
    a = o.attempt
    if o.run:
        print(f"archived: {o.run.path}")
    if a and verbose:
        name = a.raw.get("name") or a.challenge
        print(f"\n{name}  [{'TIMED, deadline ' + a.deadline.isoformat() if a.timed else 'untimed'}]")
        for w in a.warnings:
            print(f"  ! {w}")
    if o.solution and o.decision and a:
        ids, _ = a.answer_id_map()
        for q in a.questions:
            ans = o.solution.answers.get(q.id)
            mark = "HELD" if q.id in o.decision.held else " ok "
            print(f"\n[{mark}] {q.id}: {q.text}")
            print(f"       format: {q.kind} — {q.syntax}")
            if ans:
                print(f"       answer: {ans.value!r}  (conf {ans.confidence:.2f}, {ans.handler})")
                print(f"       why:    {ans.evidence}")
            if q.id in o.decision.held:
                print(f"       held:   {o.decision.held[q.id]}")
        for w in o.decision.warnings:
            print(f"  ! {w}")
    if o.message:
        print(f"\n{o.status}: {o.message}")
    if o.sent is not None:
        print(f"\nsent {len(o.sent)} answer(s) -> {json.dumps(o.reply, ensure_ascii=False)}")
    elif o.status == "held":
        print("\nnothing submitted: the gate held answers (see above).")
    elif o.status == "dry-run":
        n = len(o.decision.submit) if o.decision else 0
        held = len(o.decision.held) if o.decision else 0
        print(f"\ndry run: {n} answer(s) ready, {held} held. Re-run with --submit to send.")
    if o.timings:
        print("timings: " + "  ".join(f"{k}={v * 1000:.1f}ms" for k, v in o.timings.items()))
    for d in o.downloads:
        if d.redirects:
            print(f"note: the artifact came from {urlsplit(d.url).netloc} after {d.redirects} redirect(s); "
                  "each redirect to another host costs a new connection on the clock")


def _human_prompt(attempt, decision, solution) -> str:
    if not sys.stdin.isatty():
        return "n"
    left = attempt.seconds_left()
    print(f"\n*** gate held {len(decision.held)} answer(s)"
          + (f" — about {left:.0f}s left on the clock" if left is not None else "") + " ***")
    for qid, why in decision.held.items():
        ans = solution.answers.get(qid)
        print(f"  {qid}: {ans.value if ans else '-'!r}  <- {why}")
    print(f"  {len(decision.submit)} answer(s) passed.")
    choice = input("[y] send the passed ones  [a] send all incl. low-confidence  [N] send nothing: ")
    return choice.strip().lower()[:1] or "n"


# ---- commands --------------------------------------------------------------
def cmd_list(args) -> int:
    rows = _gm(args).list(day=args.day, lane=args.lane)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for r in rows:
        rft = r.get("run_for_time_supported")
        safe = "regular start is untimed" if rft else "START IS TIMED (older route)"
        print(f"{r.get('id')}\n    {r.get('name', '')} | day {r.get('day', '?')} | {r.get('lane', '?')} | {safe}")
        extra = {k: v for k, v in r.items() if k not in ("id", "name", "day", "lane", "run_for_time_supported")}
        if extra:
            print(f"    {json.dumps(extra, ensure_ascii=False)[:300]}")
    return 0


def cmd_openapi(args) -> int:
    spec = _gm(args).openapi()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(spec, indent=2, ensure_ascii=False)
    out.write_text(text, encoding="utf-8")
    print(f"saved {out} ({len(text)} characters)")
    if args.grep:
        lines = text.splitlines()
        hits = [i for i, line in enumerate(lines) if any(w.lower() in line.lower() for w in args.grep)]
        shown: set[int] = set()
        for i in hits:
            for j in range(max(0, i - args.context), min(len(lines), i + args.context + 1)):
                if j not in shown:
                    if shown and j - 1 not in shown:
                        print("  ...")
                    print(f"{j + 1:6}: {lines[j]}")
                    shown.add(j)
        print(f"({len(hits)} matching line(s) for {', '.join(args.grep)})")
    return 0


def cmd_fetch(args) -> int:
    """Download the current attempt's artifact(s) and compare them with what the reply
    announced. Read-only: nothing is started, solved or submitted."""
    if any(d < 0 for d in args.delivery or []):
        print("delivery numbers cannot be negative")
        return 2
    gm = _gm(args)
    cid, _ = _resolve(gm, args.challenge)
    if cid is None:
        return 2
    try:
        reply = gm.status(cid)
    except GMError as e:
        print(f"(status unavailable: {e})")
        reply = {}
    a = Attempt.from_response(cid, reply) if isinstance(reply, dict) else None
    per = (a.download_sha256 if a else []) or []
    if a and a.downloads:
        print("the reply lists:")
        for i, link in enumerate(a.downloads):
            print(f"  download {i}: sha256={(per[i] if i < len(per) else None) or '?'}  link={link!r}")
    failures = 0
    for d in args.delivery or [None]:
        label = "-" if d is None else d
        try:
            dl = gm.artifact(cid, delivery=d)
        except GMError as e:
            print(f"delivery={label}: {e}")
            failures += 1
            continue
        h = hashlib.sha256(dl.data).hexdigest()
        where = [i for i, x in enumerate(per) if x == h]
        verdict = (f"matches download {where[0]}" if where else
                   "MATCHES NOTHING the reply announced" if any(per) else "unknown (the reply gives no SHA-256)")
        if any(per) and not where:
            failures += 1
        print(f"delivery={label}  size={len(dl.data)}  sha256={h}  filename={dl.filename!r}  -> {verdict}")
    return 1 if failures else 0


def cmd_inspect(args) -> int:
    """Show what the Game Master actually sent for each archived attempt of a
    challenge: download fields, question artifact labels, and what was fetched.
    Read-only: no network."""
    runs = Archive(args.runs).runs(args.challenge)
    if not runs:
        print("nothing archived for that challenge")
        return 1
    skip = {"guidance", "questions", "prompt", "name"}
    for run in runs[-args.last:]:
        data = run.read_json("start.json") or {}
        print(f"=== {run.path.name}")
        for k, v in data.items():
            if k not in skip:
                print(f"  {k}: {json.dumps(v, ensure_ascii=False)[:400]}")
        for q in data.get("questions") or []:
            if isinstance(q, dict):
                extra = {k: v for k, v in q.items() if k not in ("id", "question", "artifact", "answer_format",
                                                                   "normalization")}
                print(f"  Q {q.get('id')} | artifact={q.get('artifact')!r} | {q.get('question')}"
                      + (f" | {json.dumps(extra, ensure_ascii=False)}" if extra else ""))
        for m in run.read_json("artifacts.json") or []:
            print(f"  fetched: name={m.get('name')!r} size={m.get('size')} sha256={str(m.get('sha256'))[:16]}... "
                  f"url={m.get('url')}")
        sub = run.read_json("submit.json")
        if sub:
            print(f"  submit reply: result={(sub.get('reply') or {}).get('result')!r}")
    return 0


def cmd_status(args) -> int:
    gm = _gm(args)
    cid, _ = _resolve(gm, args.challenge)
    if cid is None:
        return 2
    data = gm.status(cid)
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    a = Attempt.from_response(cid, data) if isinstance(data, dict) else None
    print(f"challenge: {cid}")
    if a is not None:
        left = a.seconds_left()
        print(f"  attempt:   {a.attempt_id or '?'}   result: {a.result or '(open)'}")
        print(f"  timed:     {'yes, deadline ' + a.deadline.isoformat() if a.timed else 'no'}"
              + (f"  ({left:.0f}s left)" if left is not None and left > 0 else "  (deadline passed)" if a.timed else ""))
        for key in ("run_for_time", "hall_of_fame_eligible", "ranked_attempts_remaining",
                    "regular_variants_remaining", "unique_attempts_remaining", "variant_fresh", "status"):
            if key in data:
                print(f"  {key}: {data[key]}")
    print("(full reply: add --json)")
    return 0


def _norm(text) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).strip()


def cmd_ping(args) -> int:
    """Where does the time go? Pure network round trip (TCP handshake, no
    server code involved) versus a full request on a warm connection."""
    gm = _gm(args)
    parts = urlsplit(gm.base)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        print(f"cannot resolve {host}: {e}")
        return 2
    addr = infos[0][4]
    print(f"{gm.base}  ->  {addr[0]}:{port}")
    rtts = []
    for _ in range(args.count):
        t = time.perf_counter()
        try:
            with socket.create_connection(addr[:2], timeout=5):
                rtts.append(time.perf_counter() - t)
        except OSError as e:
            print(f"  tcp connect failed: {e}")
            break
    gm.warm(None)  # TLS + keep-alive set up, like race does
    try:
        r = gm.s.get(gm.base, params={"op": "openapi"}, timeout=gm.timeout)
        hints = {k: v for k, v in r.headers.items() if k.lower() in (
            "server", "via", "cf-ray", "x-vercel-id", "x-amz-cf-pop", "x-served-by", "fly-request-id",
            "x-azure-ref", "x-cache", "x-powered-by", "x-envoy-upstream-service-time")}
        if hints:
            print("  hosting hints: " + "  ".join(f"{k}={v}" for k, v in hints.items()))
    except Exception:
        pass
    reqs = []
    for _ in range(args.count):
        t = time.perf_counter()
        try:
            gm.get(op="openapi")
        except GMError as e:
            print(f"  request failed: {e}")
            break
        reqs.append(time.perf_counter() - t)

    def show(label, xs):
        if xs:
            print(f"  {label:34} min {min(xs) * 1000:7.1f} ms   median {statistics.median(xs) * 1000:7.1f} ms")
    show("network round trip (TCP connect)", rtts)
    show("request on a warm connection", reqs)
    if rtts and reqs:
        rtt, req = min(rtts), min(reqs)
        print(f"\n  ~{rtt * 1000:.0f} ms of every request is distance to the server, ~{max(0.0, req - rtt) * 1000:.0f} ms "
              "is the server itself.")
        print(f"  A timed run needs about two round trips on the clock (download, submit): >= ~{2 * rtt * 1000:.0f} ms "
              "from here, plus server time.\n  Run this on Homebase too: whichever machine has the smaller round "
              "trip should do the race.")
    return 0


def _resolve(gm: GameMaster, wanted: str) -> tuple[str | None, dict | None]:
    """Accept a challenge id or its display name. Returns (id, list entry);
    id is None when the choice is ambiguous or unknown (and says why)."""
    try:
        rows = gm.list()
    except GMError as e:
        print(f"(could not list challenges: {e}; using {wanted!r} as the id)")
        return wanted, None
    for r in rows:
        if r.get("id") == wanted:
            return wanted, r
    key = _norm(wanted)
    hits = [r for r in rows if key and _norm(r.get("name", "")) == key] or \
           [r for r in rows if key and key in _norm(r.get("name", "")) + " " + _norm(r.get("id", ""))]
    if len(hits) == 1:
        print(f"'{wanted}' -> challenge id {hits[0]['id']}")
        return hits[0]["id"], hits[0]
    if hits:
        print(f"'{wanted}' matches several challenges. Pick one id and run the command again with it:")
    else:
        print(f"no challenge called '{wanted}'. Challenge ids look like this (from `py -m hunt list`):")
        hits = rows[:15]
    for r in hits:
        mode = "untimed start" if r.get("run_for_time_supported") else "START IS TIMED"
        print(f"  {r.get('id')}    ({r.get('name', '')}, {mode})")
    return None, None


def cmd_solve(args) -> int:
    gm = _gm(args)
    cid, route = _resolve(gm, args.challenge)
    if cid is None:
        return 2
    args.challenge = cid
    if not args.accept_timer:
        if route is None or not route.get("run_for_time_supported"):
            print(f"refusing to {'retry' if args.retry else 'start'}: this route is not listed with "
                  "run_for_time_supported=true, so it may begin a real countdown. Check `hunt list`, "
                  "then pass --accept-timer if that is what you want.")
            return 3
    with _solver(args, cid, (route or {}).get("lane")) as solver:
        o = play(gm, Archive(args.runs), args.challenge, timed=False, use_retry=args.retry,
                 submit=args.submit, min_confidence=args.min_confidence, partial=args.partial,
                 prompt=None if args.yes else _human_prompt, trust_guessed_ids=args.trust_positional_ids,
                 solver=solver)
    _print_outcome(o)
    return 0 if o.status == "dry-run" else _exit_code(o)


def cmd_race(args) -> int:
    if args.repeat < 1 or args.gap < 0 or args.keep < 0 or args.pending_wait < 0:
        print("--repeat must be at least 1; --gap, --keep and --pending-wait cannot be negative")
        return 2
    if args.start and args.repeat > 1:
        print("--start reconnects to the same attempt every time, so it cannot be combined with --repeat")
        return 2
    gm = _gm(args)
    cid, route = _resolve(gm, args.challenge)
    if cid is None:
        return 2
    args.challenge = cid
    with _solver(args, cid, (route or {}).get("lane")) as solver:
        return _race(args, gm, solver)


def _race(args, gm: GameMaster, solver) -> int:
    archive = Archive(args.runs)
    if not args.force:
        rows = replay(archive, args.challenge, args.min_confidence, args.trust_positional_ids, solver=solver)
        if not rows:
            print("refusing to race: the bot has not yet been proven CORRECT on this challenge.\n"
                  "  Practise without a clock first:\n"
                  "    py -m hunt solve CID            (look at the answers; nothing is sent)\n"
                  "    py -m hunt solve CID --submit   (send them for real, still no clock)\n"
                  "  If solve says 'already solved', get a fresh untimed copy with\n"
                  "    py -m hunt solve CID --retry    and then  py -m hunt solve CID --submit\n"
                  "  Or race anyway, trusting the bot:  py -m hunt race CID --force")
            return 3
        bad = [r for r in rows if not r["ok"]]
        if bad:
            print("refusing to race: the solver no longer reproduces accepted answers "
                  "(or the gate would hold them):")
            for r in bad:
                print(f"  {r['run']}: {json.dumps(r['diffs'])}")
            return 3
        print(f"regression: {len(rows)} archived CORRECT attempt(s) reproduce.")
    gm.warm(args.challenge, tuple(_known_artifact_hosts(archive, args.challenge)))
    if gm.clock_offset is not None and abs(gm.clock_offset) > 5:
        print(f"note: this machine's clock is {abs(gm.clock_offset):.0f}s {'behind' if gm.clock_offset > 0 else 'ahead of'} "
              "the Game Master's; deadlines are judged on the server's clock")
    use_retry = True if args.retry else False if args.start else None  # None: start, or retry if finished
    if args.repeat > 1:
        try:
            left = ranked_attempts_left(gm.status(args.challenge))
        except GMError:
            left = None
        if left is None:
            print("refusing --repeat: cannot read ranked_attempts_remaining, so the reserve (--keep) cannot "
                  "be protected. Run single races instead.")
            return 2
        if left <= args.keep:
            print(f"refusing --repeat: {left} ranked attempt(s) left and --keep is {args.keep}")
            return 2
    refuse: set[str] = set()  # attempts solved in this session; seeing one again means 'not advanced yet'
    best: list[float] = []
    code = 1
    for i in range(args.repeat):
        if i:
            time.sleep(args.gap)
            gm.warm(args.challenge)
        print(f"{f'[{i + 1}/{args.repeat}] ' if args.repeat > 1 else ''}asking for a timed attempt; preparing it "
              f"can take a while (up to {gm.prepare_timeout:.0f}s) and does not count on the clock...", flush=True)
        o = _play_through_pending(gm, archive, args, use_retry, refuse, solver)
        result = str((o.reply or {}).get("result") or "")
        if o.status == "pending":
            print(f"stopping: {o.message}")
            code = 0 if best else 1
            break
        if not (o.status == "submitted" and result.upper() == "CORRECT"):
            _print_outcome(o)
            code = _exit_code(o)
            break  # never keep spending ranked attempts after anything but a clean CORRECT
        code = 0
        if o.attempt:
            if o.attempt.attempt_id:
                refuse.add(o.attempt.attempt_id)
            refuse |= o.attempt.expected_sha256
        t = o.timings
        best.append(t.get("on-clock(approx)", 0.0))
        if args.repeat == 1:
            _print_outcome(o, verbose=False)
            for key in ("hall_of_fame_eligible", "unique_attempts_remaining", "ranked_attempts_remaining"):
                if o.attempt and key in o.attempt.raw:
                    print(f"{key}: {o.attempt.raw[key]}")
            break
        left = ranked_attempts_left(o.attempt.raw if o.attempt else {})
        print(f"  CORRECT  on-clock<= {best[-1] * 1000:.0f} ms  (download {t.get('download', 0) * 1000:.0f}, "
              f"solve {t.get('solve', 0) * 1000:.1f}, submit {t.get('submit', 0) * 1000:.0f} ms)  "
              f"ranked attempts left: {left if left is not None else '?'}   archived: {o.run.path if o.run else '-'}")
        if o.message:
            print(f"  note: {o.message}")
        if o.run is None:
            print("stopping: this run could not be archived, so further runs would not be saved either")
            break
        if o.attempt and o.attempt.raw.get("hall_of_fame_eligible") is False:
            print("stopping: the Game Master says this attempt is not Hall of Fame eligible")
            break
        if left is None:
            print("stopping: cannot read ranked_attempts_remaining, so the reserve (--keep) cannot be protected")
            break
        if left <= args.keep and i + 1 < args.repeat:
            print(f"stopping: {left} ranked attempt(s) left, keeping {args.keep} in reserve (--keep)")
            break
    if len(best) > 1:
        print(f"\n{len(best)} CORRECT timed runs; fastest on-clock<= {min(best) * 1000:.0f} ms "
              "(the leaderboard keeps your best; its clock stops before the submit reply returns, "
              "so it shows less than these numbers)")
    return code


def _play_through_pending(gm: GameMaster, archive: Archive, args, use_retry, refuse: set[str],
                          solver=None) -> Outcome:
    """Run one timed attempt; if the Game Master has not yet advanced past the
    last solve (scoring still being confirmed), wait with backoff and ask again."""
    waited, delay = 0.0, 2.0
    while True:
        o = play(gm, archive, args.challenge, timed=True, use_retry=use_retry, submit=True,
                 min_confidence=args.min_confidence, partial=args.partial,
                 prompt=None if args.no_prompt else _human_prompt, trust_guessed_ids=args.trust_positional_ids,
                 refuse=refuse, solver=solver)
        if o.status != "pending" or waited >= args.pending_wait:
            return o
        print(f"  {o.message}; asking again in {delay:.0f}s", flush=True)
        time.sleep(delay)
        waited += delay
        delay = min(delay * 2, 16.0)


def _exit_code(o: Outcome) -> int:
    if o.status != "submitted":
        return 1
    result = str((o.reply or {}).get("result") or "")
    if result.upper() == "CORRECT":
        return 0
    if result.lower() == "accepted":
        print(f"PARTIAL: accepted, {(o.reply or {}).get('remaining', '?')} answer(s) still outstanding")
        return 5
    print(f"NOT SOLVED: the Game Master answered {result or (o.reply or {}).get('error')!r}")
    return 4


def _known_artifact_hosts(archive: Archive, cid: str) -> list[str]:
    run = archive.latest(cid)
    meta = (run.read_json("artifacts.json") if run else None) or []
    return [m["url"] for m in meta if m.get("url")]


def cmd_offline(args) -> int:
    archive = Archive(args.runs)
    run = archive.latest(args.challenge)
    if run is None:
        print("nothing archived for that challenge")
        return 1
    attempt, arts = run.attempt(), run.artifact_set()
    with _solver(args, attempt.challenge, attempt.lane) as solver:
        sol = (solver or solve)(attempt, arts)
    dec = decide(attempt, sol, args.min_confidence, args.trust_positional_ids)
    _print_outcome(Outcome("dry-run", f"re-solved {run.path} offline", attempt, sol, dec))
    if args.inventory:
        print(json.dumps(inventory(arts), indent=2, ensure_ascii=False))
    return 0


def cmd_replay(args) -> int:
    with _solver(args) as solver:
        rows = replay(Archive(args.runs), args.challenge, args.min_confidence, args.trust_positional_ids,
                      solver=solver)
    if not rows:
        print("no archived CORRECT attempts yet")
        return 1
    for r in rows:
        print(("PASS " if r["ok"] else "FAIL ") + r["run"] + ("" if r["ok"] else f"  {json.dumps(r['diffs'])}"))
    return 0 if all(r["ok"] for r in rows) else 1


def cmd_rehearse(args) -> int:
    from .testing.fake_gm import CID, FakeGM

    fake = FakeGM(mode=args.mode, seed=args.seed, opaque_ids=args.opaque_ids)
    url = fake.start_server()
    ok = 0
    try:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Archive(tmp)
            gm = GameMaster(base_url=url, token=fake.token)
            # The untimed attempt first (like real play), then timed retries.
            first = play(gm, archive, CID, timed=False, use_retry=False, submit=True, partial=False,
                         trust_guessed_ids=args.opaque_ids)
            print(f"regular: {first.status} {first.reply}")
            for i in range(args.variants):
                gm.warm(CID)
                o = play(gm, archive, CID, timed=True, use_retry=None, submit=True,
                         min_confidence=args.min_confidence, trust_guessed_ids=args.opaque_ids)
                res = (o.reply or {}).get("result")
                ok += res == "CORRECT"
                ms = o.timings.get("start->submit-reply", 0) * 1000
                print(f"variant {i + 1}: {o.status:9} {res!s:9} {ms:6.1f}ms  held={list(o.decision.held) if o.decision else '-'}")
                if res != "CORRECT" and o.decision:
                    _print_outcome(o)
    finally:
        fake.stop()
    print(f"\n{ok}/{args.variants} timed variants CORRECT against the fake Game Master")
    return 0 if ok == args.variants else 1

# ---- learning and racing for places ---------------------------------------------
def _pick_entries(rows: list[dict], wanted: list[str]) -> tuple[list[dict], list[str]]:
    """Every challenge (all modes) matching each id or name; and the names that matched nothing."""
    picked: list[dict] = []
    missing = []
    for w in wanted:
        exact = [r for r in rows if r.get("id") == w]
        key = _norm(w)
        hits = exact or [r for r in rows if key and (key == _norm(r.get("name", "")) or
                                                     key in _norm(r.get("name", "")) + " " + _norm(r.get("id", "")))]
        if not hits:
            missing.append(w)
        for r in hits:
            if r not in picked:
                picked.append(r)
    return picked, missing


def _pick_advisor(args):
    from .learn.advisor import pick
    fallbacks = None
    if args.fallback_models is not None:
        fallbacks = [m.strip() for m in args.fallback_models.split(",") if m.strip() and m.strip() != "none"]
    return pick(args.advisor, args.model, Path(args.learned) / "inbox", fallback_models=fallbacks, kimi=args.kimi)


def cmd_grind(args) -> int:
    from .learn.advisor import AdvisorError
    from .learn.grind import GrindOptions, grind

    if args.rounds < 1 or args.episodes < 0 or args.fresh_variants < 0:
        print("--rounds must be at least 1; --episodes and --fresh-variants cannot be negative")
        return 2
    gm = _gm(args)
    rows = gm.list(day=args.day, lane=args.lane)
    if args.challenges:
        rows, missing = _pick_entries(rows, args.challenges)
        for w in missing:
            print(f"no challenge matches {w!r} (see `hunt list`)")
        if missing and not rows:
            return 2
    if not rows:
        print("no challenges to grind")
        return 1
    try:
        advisor, how = _pick_advisor(args)
    except AdvisorError as e:
        print(f"advisor: {e}")
        return 2
    print(f"advisor: {how}")
    if advisor is not None:
        print("  (questions and artifact previews go to the advisor; the Game Master token never does)")
    opts = GrindOptions(rounds=args.rounds, episodes=args.episodes, fresh_variants=args.fresh_variants,
                        min_confidence=args.min_confidence, trust_guessed_ids=args.trust_positional_ids,
                        accept_timer=args.accept_timer, submit=not args.no_submit, one_by_one=not args.batch,
                        alternatives=args.alternatives, preflight=not args.no_preflight)
    results = grind(gm, Archive(args.runs), Library(args.learned), advisor, rows, opts)
    print("\n== summary")
    for r in results:
        print(f"  {'+' if r.points else '-'} {r.status:8} {r.challenge}  {r.detail}"
              + (f"  [learned: {', '.join(r.learned)}]" if r.learned else ""))
    scored = sum(r.points for r in results)
    print(f"\n{scored}/{len(results)} challenge mode(s) have scored.")
    if any(r.pending for r in results):
        print("Some solves say scoring is pending: CourseStack is the official ledger, check the points there.")
    if any(r.learned for r in results):
        print(f"New handlers are in {args.learned}/. Commit them (git add {args.learned}) so Homebase gets them "
              "with `git pull`.")
    return 0 if scored == len(results) else 1


def cmd_optimize(args) -> int:
    from .optimize import Board

    if args.target_rank < 1 or args.max_runs < 1 or args.patience < 1 or args.keep < 0 or args.gap < 0:
        print("--target-rank, --max-runs and --patience must be at least 1; --keep and --gap cannot be negative")
        return 2
    archive = Archive(args.runs)
    gm = _gm(args)
    cid, route = _resolve(gm, args.challenge)
    if cid is None:
        return 2
    args.challenge = cid
    if route is not None and not route.get("run_for_time_supported"):
        print("refusing: this route does not list run_for_time_supported, so there is no opt-in timed race to optimise")
        return 2
    lane = (route or {}).get("lane")
    with _solver(args, cid, lane) as solver:
        rows = replay(archive, cid, args.min_confidence, args.trust_positional_ids, solver=solver)
    if not rows and not args.force:
        if args.no_learn:
            print("refusing: the bot has never been CORRECT on this challenge (run `hunt grind` first)")
            return 3
        print("never CORRECT on this challenge yet: grinding it first (untimed)...")
        from .learn.advisor import AdvisorError
        from .learn.grind import MODE_ORDER, GrindOptions, grind, mode
        from .learn.packet import base_id
        try:
            advisor, how = _pick_advisor(args)
        except AdvisorError as e:
            print(f"advisor: {e}")
            return 2
        print(f"advisor: {how}")
        try:  # the modes before this one unlock it, so they come first
            chain = [r for r in gm.list() if base_id(str(r.get("id"))) == base_id(cid)
                     and MODE_ORDER.get(mode(str(r.get("id"))), 9) <= MODE_ORDER.get(mode(cid), 9)]
        except GMError:
            chain = []
        res = grind(gm, archive, Library(args.learned), advisor, chain or [route or {"id": cid}],
                    GrindOptions(min_confidence=args.min_confidence, trust_guessed_ids=args.trust_positional_ids))
        if not res or res[-1].challenge != cid or not res[-1].points:
            print("stopping: the challenge has not scored, so racing it would only burn ranked attempts")
            return 1
        with _solver(args, cid, lane) as solver:
            rows = replay(archive, cid, args.min_confidence, args.trust_positional_ids, solver=solver)
        if not rows:
            print("refusing: the Game Master already counts this challenge as solved, but this machine has no "
                  f"archived CORRECT attempt of it ({args.runs}/ is not shared between machines), so nothing "
                  "proves the bot solves it. Either earn one untimed (spends a regular variant):\n"
                  f"    py -m hunt solve {cid} --retry   then   py -m hunt solve {cid} --submit\n"
                  "  or race trusting the learned handlers:  add --force")
            return 3
    if rows and not all(r["ok"] for r in rows):
        print("refusing: archived CORRECT attempts no longer reproduce (see `hunt replay`)")
        return 3
    me = args.me
    try:
        st = gm.status(cid)
    except GMError:
        st = {}
    if not me and isinstance(st.get("solved_by"), dict):
        me = st["solved_by"].get("name")
    board = Board(gm, cid, me=me, beat=args.beat)
    ops = board.discover()
    print("standing from: reply rank fields"
          + (f", then op={'/'.join(ops)}" if ops else "")
          + (f", else --beat {args.beat:.3f}s" if args.beat is not None else "")
          + (f"   (you are {me!r})" if me else ""))
    if not ops and args.beat is None:
        print("note: the Game Master lists no leaderboard operation; unless its replies carry a rank, give the "
              "time of the place you want with --beat SECONDS (read it off the Hall of Fame)")
    left = ranked_attempts_left(st)
    if left is None:
        print("refusing: cannot read ranked_attempts_remaining, so the reserve (--keep) cannot be protected")
        return 2
    gm.warm(cid, tuple(_known_artifact_hosts(archive, cid)))
    refuse: set[str] = set()
    times: list[float] = []
    official: list[float] = []  # times the Game Master itself reported
    best_at = 0
    code = 1
    with _solver(args, cid, lane) as solver:
        for i in range(args.max_runs):
            if left is not None and left <= args.keep:
                print(f"stopping: {left} ranked attempt(s) left, keeping {args.keep} in reserve (--keep)")
                break
            if i:
                time.sleep(args.gap)
                gm.warm(cid)
            print(f"[{i + 1}/{args.max_runs}] timed attempt...", flush=True)
            o = _play_through_pending(gm, archive, args, None, refuse, solver)
            result = str((o.reply or {}).get("result") or "")
            if o.status == "pending":
                print(f"stopping: {o.message}")
                break
            if not (o.status == "submitted" and result.upper() == "CORRECT"):
                _print_outcome(o)
                code = _exit_code(o)
                break
            if o.attempt:
                if o.attempt.attempt_id:
                    refuse.add(o.attempt.attempt_id)
                refuse |= o.attempt.expected_sha256
            t = o.timings.get("on-clock(approx)", 0.0)
            times.append(t)
            if t <= min(times):
                best_at = len(times)
            left = ranked_attempts_left(o.attempt.raw if o.attempt else {})
            try:
                after = gm.status(cid) if board.working_op is None else None
            except GMError:
                after = None
            standing = board.standing(o.reply, after)
            if standing.seconds is not None:
                official.append(standing.seconds)
            shown = f", official {standing.seconds:.3f}s" if standing.seconds is not None else ""
            place = (f"place {standing.rank}" + (f"/{standing.total}" if standing.total else "")
                     if standing.rank else "place unknown")
            print(f"  CORRECT on-clock<= {t * 1000:.0f} ms (best {min(times) * 1000:.0f}){shown}  {place} "
                  f"[{standing.source}]  ranked left: {left if left is not None else '?'}")
            if o.attempt and o.attempt.raw.get("hall_of_fame_eligible") is False:
                print("stopping: the Game Master says these attempts are not Hall of Fame eligible")
                break
            if standing.rank is not None and standing.rank <= args.target_rank:
                print(f"done: place {standing.rank} (target {args.target_rank})")
                code = 0
                break
            if args.beat is not None and standing.rank is None:
                # The official time when the Game Master gives one; else the bot's own on-clock
                # time, which over-estimates it (a safe comparison).
                mine = min(official) if official else min(times)
                if mine <= args.beat:
                    print(f"done: {mine:.3f}s beats the {args.beat:.3f}s you set (--beat)")
                    code = 0
                    break
            if len(times) - best_at >= args.patience:
                print(f"stopping: no faster run in the last {args.patience} (plateau). Best on-clock "
                      f"{min(times) * 1000:.0f} ms. The rest is network distance: try the machine `hunt ping` "
                      "shows closest to the Game Master.")
                break
            if left is None:
                print("stopping: cannot read ranked_attempts_remaining any more")
                break
        else:
            print(f"stopping: --max-runs {args.max_runs} reached")
    if board.raw_example is not None and board.working_op is None:
        print("note: a leaderboard reply came back that the bot could not read; its shape: "
              + json.dumps(board.raw_example, ensure_ascii=False)[:600])
    return code


def cmd_learned(args) -> int:
    from .learn import policy

    lib = Library(args.learned)
    if args.reject:
        dest = lib.reject(args.reject, "rejected by hand")
        print(f"moved to {dest}" if dest else f"no learned/{args.reject}.py")
        return 0 if dest else 1
    if args.show:
        p = lib.root / f"{args.show}.py"
        if not p.exists():
            print(f"no {p}")
            return 1
        print(p.read_text(encoding="utf-8"))
        problems = policy.check(p.read_text(encoding="utf-8"))
        if problems:
            print("\nREFUSED by the policy (the sandbox will not load it):\n  " + "\n  ".join(problems))
        return 0
    names = lib.names()
    if not names:
        print(f"nothing learned yet ({lib.root}/ is empty). `hunt grind` fills it.")
        return 0
    man = lib.manifest()["modules"]
    bad = lib.problems()
    for n in names:
        e = man.get(n, {})
        print(f"{n:32} {e.get('status', 'candidate'):9} proven on: {', '.join(e.get('proven_on') or []) or '-'}"
              + (f"   REFUSED: {bad[n][0]}" if n in bad else ""))
    return 0


def main(argv=None) -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(prog="hunt", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default="runs", help="archive directory (default: ./runs)")
    ap.add_argument("--url", help="Game Master URL (default: $HUNTRESS_GM_URL, $GM, or the direct URL)")
    ap.add_argument("--learned", default="learned", help="learned handlers directory (default: ./learned)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list")
    p.add_argument("--day", type=int)
    p.add_argument("--lane")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("openapi")
    p.add_argument("--out", default="docs/openapi.json")
    p.add_argument("--grep", nargs="*", default=[], help="print lines mentioning these words (with context)")
    p.add_argument("--context", type=int, default=6)
    p.set_defaults(fn=cmd_openapi)

    p = sub.add_parser("fetch", help="download the current attempt's artifact(s) and print their SHA-256 (read-only)")
    p.add_argument("challenge")
    p.add_argument("--delivery", type=int, nargs="*", help="delivery numbers to fetch (op=artifact&delivery=N)")
    p.set_defaults(fn=cmd_fetch)

    p = sub.add_parser("inspect", help="show what the Game Master sent for archived attempts (no network)")
    p.add_argument("challenge")
    p.add_argument("--last", type=int, default=3, help="how many of the latest runs to show (default 3)")
    p.set_defaults(fn=cmd_inspect)

    p = sub.add_parser("status")
    p.add_argument("challenge")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("ping", help="measure network round trip vs server time to the Game Master")
    p.add_argument("--count", type=int, default=7)
    p.set_defaults(fn=cmd_ping)

    def gate_opts(p):
        p.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE)
        p.add_argument("--partial", action="store_true",
                       help="when something is held and nobody answers the prompt, still send the rest")
        p.add_argument("--trust-positional-ids", action="store_true",
                       help="send answers even when answer_ids had to be matched to questions by position")

    def advisor_opts(p):
        p.add_argument("--advisor", choices=("auto", "api", "cli", "kimi", "manual", "none"), default="auto",
                       help="who writes new handlers (default auto: API key, else `claude` CLI, else manual)")
        p.add_argument("--model", help="Claude model for the advisor (default claude-opus-5-5 or $HUNT_CLAUDE_MODEL)")
        p.add_argument("--fallback-models", metavar="M1,M2",
                       help="Claude models asked, in order, when the first declines a packet "
                            "(default claude-opus-4-8; 'none' for no fallback)")
        p.add_argument("--kimi", choices=("auto", "on", "off"), default="auto",
                       help="Kimi as the last resort when every Claude model declined (auto: the "
                            "`kimi` CLI on a membership login if on PATH, else the HTTP API when "
                            "MOONSHOT_API_KEY is set; CLI model $HUNT_KIMI_CLI_MODEL)")

    p = sub.add_parser("solve", help="untimed attempt; dry run unless --submit")
    p.add_argument("challenge")
    p.add_argument("--submit", action="store_true")
    p.add_argument("--yes", action="store_true", help="no interactive prompt")
    p.add_argument("--retry", action="store_true", help="op=retry: next fresh regular variant")
    p.add_argument("--accept-timer", action="store_true",
                   help="allow a start on a route that may be timed by default")
    gate_opts(p)
    p.set_defaults(fn=cmd_solve)

    p = sub.add_parser("race", help="timed attempt for the Hall of Fame")
    p.add_argument("challenge")
    how = p.add_mutually_exclusive_group()
    how.add_argument("--start", action="store_true",
                     help="only send start (by default: start, then retry if that attempt is already finished)")
    how.add_argument("--retry", action="store_true", help="only send retry")
    p.add_argument("--force", action="store_true", help="skip the regression requirement")
    p.add_argument("--wait", type=float, default=180.0,
                   help="seconds to wait for the Game Master to prepare the attempt (default 180)")
    p.add_argument("--repeat", type=int, default=1,
                   help="run this many timed attempts back to back (each spends a ranked attempt; "
                        "stops at the first result that is not CORRECT)")
    p.add_argument("--keep", type=int, default=3,
                   help="with --repeat: stop when only this many ranked attempts are left (default 3)")
    p.add_argument("--gap", type=float, default=3.0, help="with --repeat: seconds between runs (default 3)")
    p.add_argument("--pending-wait", type=float, default=60.0,
                   help="how long to keep asking while the last solve is still being confirmed (default 60s)")
    p.add_argument("--no-prompt", action="store_true")
    gate_opts(p)
    p.set_defaults(fn=cmd_race)

    p = sub.add_parser("offline", help="re-solve the latest archived attempt without network")
    p.add_argument("challenge")
    p.add_argument("--inventory", action="store_true")
    p.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE)
    p.add_argument("--trust-positional-ids", action="store_true")
    p.set_defaults(fn=cmd_offline)

    p = sub.add_parser("replay")
    p.add_argument("challenge", nargs="?")
    p.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE)
    p.add_argument("--trust-positional-ids", action="store_true")
    p.set_defaults(fn=cmd_replay)

    p = sub.add_parser("rehearse", help="race a local fake Game Master")
    p.add_argument("--variants", type=int, default=5)
    p.add_argument("--mode", choices=("single", "trio", "mastery"), default="trio")
    p.add_argument("--seed", type=int, default=int(datetime.now(timezone.utc).timestamp()))
    p.add_argument("--opaque-ids", action="store_true")
    p.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE)
    p.set_defaults(fn=cmd_rehearse)

    p = sub.add_parser("grind", help="solve challenges (all modes) until each scores; learn unknown questions")
    p.add_argument("challenges", nargs="*", help="ids or names (default: everything `list` returns)")
    p.add_argument("--day", type=int)
    p.add_argument("--lane")
    advisor_opts(p)
    p.add_argument("--rounds", type=int, default=4, help="advisor replies per learning episode (default 4)")
    p.add_argument("--episodes", type=int, default=3, help="learning episodes per challenge (default 3)")
    p.add_argument("--fresh-variants", type=int, default=1,
                   help="fresh regular variants to spend when an attempt is lost (default 1)")
    p.add_argument("--no-submit", action="store_true", help="learn and prove offline, send nothing")
    p.add_argument("--batch", action="store_true",
                   help="submit all answers in one request (default: one by one, so a refusal names the wrong one)")
    p.add_argument("--alternatives", type=int, default=6,
                   help="refused answers retried with a handler's other spellings, untimed only (default 6)")
    p.add_argument("--no-preflight", action="store_true",
                   help="start timed attempts without first re-solving every archived layout offline "
                        "(and without the guard that keeps the last Mastery attempts)")
    p.add_argument("--accept-timer", action="store_true",
                   help="include Time Trial / Mastery routes that do not say their start is untimed")
    p.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE)
    p.add_argument("--trust-positional-ids", action="store_true")
    p.set_defaults(fn=cmd_grind)

    p = sub.add_parser("optimize", help="race until you hold the target place on the Hall of Fame")
    p.add_argument("challenge")
    p.add_argument("--target-rank", type=int, default=3)
    p.add_argument("--beat", type=float, help="seconds: the time of the place you want (when no rank is readable)")
    p.add_argument("--me", help="your team/player name on the board (default: solved_by from status)")
    p.add_argument("--max-runs", type=int, default=20)
    p.add_argument("--patience", type=int, default=6, help="stop after this many runs without a new best")
    p.add_argument("--keep", type=int, default=3, help="ranked attempts to keep in reserve (default 3)")
    p.add_argument("--gap", type=float, default=3.0)
    p.add_argument("--wait", type=float, default=180.0)
    p.add_argument("--pending-wait", type=float, default=60.0)
    p.add_argument("--no-learn", action="store_true", help="never grind first; refuse if not yet proven")
    p.add_argument("--force", action="store_true",
                   help="race even without an archived CORRECT attempt on this machine (e.g. on Homebase)")
    advisor_opts(p)
    p.add_argument("--no-prompt", action="store_true")
    gate_opts(p)
    p.set_defaults(fn=cmd_optimize)

    p = sub.add_parser("learned", help="list learned handlers (learned/) and their status")
    p.add_argument("--show", metavar="NAME", help="print one module")
    p.add_argument("--reject", metavar="NAME", help="move a module out of use")
    p.set_defaults(fn=cmd_learned)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except GMError as e:
        print(f"Game Master error: {e}", file=sys.stderr)
        return 2
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
