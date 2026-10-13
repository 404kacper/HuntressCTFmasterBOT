"""Where you stand on the Hall of Fame, for `hunt optimize`.

The leaderboard keeps each team's fastest qualified timed solve. optimize
races until you hold the target place; this module answers "what place am I
now?" from the first source that works:

  1. a rank/place field in the Game Master's submit or status reply
  2. a leaderboard operation listed in the Game Master's OpenAPI document
  3. --beat SECONDS: the time of the place you want, read off the board by you
     (compared with the official time if a reply carries one, else with the
     bot's own on-clock measurement, which over-estimates: a safe comparison)
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .gm import GameMaster, GMError

RANK_KEYS = ("rank", "place", "position", "standing", "leaderboard_rank", "hall_of_fame_rank", "hof_rank",
             "leaderboard_position")
TIME_KEYS = ("best_time_ms", "time_ms", "elapsed_ms", "duration_ms", "best_ms", "best_time", "best_seconds",
             "elapsed_seconds", "time_seconds", "seconds", "elapsed", "duration", "time", "solve_time",
             "hall_of_fame_time")
NAME_KEYS = ("name", "team", "team_name", "player", "user", "username", "display_name", "handle")
ME_KEYS = ("is_me", "me", "you", "is_you", "self", "mine", "current", "is_current", "current_user", "is_team")
_BOARD_WORDS = re.compile(r"leader|hall|fame|board|rank|standing|score", re.I)


@dataclass
class Standing:
    rank: int | None = None
    seconds: float | None = None  # official time, when a source reports one
    source: str = ""
    total: int | None = None  # entries on the board, when known


def _int(v) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and v >= 1:
        return v
    if isinstance(v, str) and v.strip().lstrip("#").isdigit():
        return int(v.strip().lstrip("#")) or None
    return None


def _seconds(key: str, v) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        m = re.fullmatch(r"\s*([0-9]*\.?[0-9]+)\s*(ms|s)?\s*", v)
        if not m:
            return None
        num, unit = float(m.group(1)), m.group(2)
        return num / 1000 if unit == "ms" or (unit is None and "ms" in key) else num
    if isinstance(v, (int, float)) and v >= 0:
        return v / 1000 if "ms" in key else float(v)
    return None


def rank_in(reply, depth: int = 0) -> Standing | None:
    """A rank (and official time) the Game Master put in a submit/status reply."""
    if depth > 3 or not isinstance(reply, dict):
        return None
    found = Standing(source="reply")
    for k, v in reply.items():
        lk = str(k).lower()
        if lk in RANK_KEYS and found.rank is None:
            found.rank = _int(v)
        elif lk in TIME_KEYS and found.seconds is None:
            found.seconds = _seconds(lk, v)
    if found.rank is not None:
        return found
    for k, v in reply.items():
        if str(k).lower() in ("questions", "guidance", "prompt"):
            continue
        if isinstance(v, dict) and (s := rank_in(v, depth + 1)):
            return s
    return None


def leaderboard_ops(spec) -> list[str]:
    """op values in the OpenAPI document that sound like a leaderboard."""
    ops: list[str] = []

    def walk(o, depth=0):
        if depth > 12:
            return
        if isinstance(o, dict):
            if o.get("name") == "op" and isinstance(o.get("schema"), dict):
                for v in o["schema"].get("enum") or []:
                    if isinstance(v, str) and _BOARD_WORDS.search(v) and v not in ops:
                        ops.append(v)
            for k, v in o.items():
                if k == "op" and isinstance(v, dict):
                    for e in v.get("enum") or []:
                        if isinstance(e, str) and _BOARD_WORDS.search(e) and e not in ops:
                            ops.append(e)
                walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, depth + 1)

    walk(spec)
    text = str(spec)
    for m in re.finditer(r"op=([a-z_]+)", text):
        if _BOARD_WORDS.search(m.group(1)) and m.group(1) not in ops:
            ops.append(m.group(1))
    return ops


def _entries(o, depth: int = 0) -> list[dict]:
    """The longest list of dicts that look like leaderboard rows."""
    best: list[dict] = []
    if depth > 5:
        return best
    if isinstance(o, list) and o and all(isinstance(x, dict) for x in o):
        if sum(1 for x in o if any(str(k).lower() in TIME_KEYS or str(k).lower() in RANK_KEYS for k in x)) >= len(o) / 2:
            best = o
    children = o.values() if isinstance(o, dict) else o if isinstance(o, list) else []
    for v in children:
        sub = _entries(v, depth + 1)
        if len(sub) > len(best):
            best = sub
    return best


def _row_time(row: dict) -> float | None:
    for k in TIME_KEYS:
        for rk, v in row.items():
            if str(rk).lower() == k and (s := _seconds(k, v)) is not None:
                return s
    return None


def _row_name(row: dict) -> str | None:
    for k in NAME_KEYS:
        for rk, v in row.items():
            if str(rk).lower() == k:
                if isinstance(v, str):
                    return v
                if isinstance(v, dict) and isinstance(v.get("name"), str):
                    return v["name"]
    return None


def parse_board(data, me: str | None) -> Standing | None:
    rows = _entries(data)
    if not rows:
        return None
    mine = None
    for i, row in enumerate(rows):
        if any(row.get(k) is True for k in ME_KEYS):
            mine = i
            break
    if mine is None and me:
        want = me.strip().casefold()
        hits = [i for i, row in enumerate(rows) if (_row_name(row) or "").strip().casefold() == want]
        mine = hits[0] if len(hits) == 1 else None
    if mine is None:
        return None
    row = rows[mine]
    rank = next((r for k in RANK_KEYS for rk, v in row.items() if str(rk).lower() == k and (r := _int(v))), None)
    t = _row_time(row)
    if rank is None:
        times = [_row_time(r) for r in rows]
        if t is not None and all(x is not None for x in times):
            rank = 1 + sum(1 for x in times if x < t)
        else:
            rank = mine + 1  # boards are listed best first
    return Standing(rank, t, "leaderboard", len(rows))


class Board:
    def __init__(self, gm: GameMaster, challenge: str, me: str | None = None, beat: float | None = None):
        self.gm, self.challenge, self.me, self.beat = gm, challenge, me, beat
        self.ops: list[str] = []
        self.working_op: str | None = None
        self.raw_example = None  # the first leaderboard reply we could not read, for the user

    def discover(self) -> list[str]:
        try:
            self.ops = leaderboard_ops(self.gm.openapi())
        except GMError:
            self.ops = []
        return self.ops

    def standing(self, *replies) -> Standing:
        for reply in replies:
            if (s := rank_in(reply)) is not None:
                return s
        for op in ([self.working_op] if self.working_op else self.ops):
            try:
                data = self.gm.get(op=op, challenge=self.challenge)
            except GMError:
                continue
            s = parse_board(data, self.me)
            if s is not None:
                self.working_op = op
                s.source = f"op={op}"
                return s
            if self.raw_example is None:
                self.raw_example = data
        return Standing(source="beat" if self.beat is not None else "none")
