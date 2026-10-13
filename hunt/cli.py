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
  hunt rehearse                      full race against a local fake Game Master
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import socket
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .archive import Archive, replay
from .forensics.identity import inventory
from . import config
from .config import ConfigError
from .gate import DEFAULT_MIN_CONFIDENCE, decide
from .gm import GameMaster, GMError
from .model import Attempt
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
    out.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"saved {out}")
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
    o = play(gm, Archive(args.runs), args.challenge, timed=False, use_retry=args.retry,
             submit=args.submit, min_confidence=args.min_confidence, partial=args.partial,
             prompt=None if args.yes else _human_prompt, trust_guessed_ids=args.trust_positional_ids)
    _print_outcome(o)
    return 0 if o.status == "dry-run" else _exit_code(o)


def cmd_race(args) -> int:
    archive = Archive(args.runs)
    gm = _gm(args)
    cid, _ = _resolve(gm, args.challenge)
    if cid is None:
        return 2
    args.challenge = cid
    if not args.force:
        rows = replay(archive, args.challenge, args.min_confidence, args.trust_positional_ids)
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
    print(f"asking for a timed attempt; preparing it can take a while (up to {gm.prepare_timeout:.0f}s) "
          "and does not count on the clock...", flush=True)
    o = play(gm, archive, args.challenge, timed=True, use_retry=use_retry, submit=True,
             min_confidence=args.min_confidence, partial=args.partial,
             prompt=None if args.no_prompt else _human_prompt, trust_guessed_ids=args.trust_positional_ids)
    _print_outcome(o, verbose=o.status != "submitted")
    for key in ("hall_of_fame_eligible", "unique_attempts_remaining", "ranked_attempts_remaining"):
        if o.attempt and key in o.attempt.raw:
            print(f"{key}: {o.attempt.raw[key]}")
    return _exit_code(o)


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
    sol = solve(attempt, arts)
    dec = decide(attempt, sol, args.min_confidence, args.trust_positional_ids)
    _print_outcome(Outcome("dry-run", f"re-solved {run.path} offline", attempt, sol, dec))
    if args.inventory:
        print(json.dumps(inventory(arts), indent=2, ensure_ascii=False))
    return 0


def cmd_replay(args) -> int:
    rows = replay(Archive(args.runs), args.challenge, args.min_confidence, args.trust_positional_ids)
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


def main(argv=None) -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(prog="hunt", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default="runs", help="archive directory (default: ./runs)")
    ap.add_argument("--url", help="Game Master URL (default: $HUNTRESS_GM_URL, $GM, or the direct URL)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list")
    p.add_argument("--day", type=int)
    p.add_argument("--lane")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("openapi")
    p.add_argument("--out", default="docs/openapi.json")
    p.set_defaults(fn=cmd_openapi)

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
