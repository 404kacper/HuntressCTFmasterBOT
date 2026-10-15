"""Orientation challenges with no files and no questions, only an answer id.

The bot makes their questions itself (model.SYNTHESIZED), so these handlers
touch nothing else: either the reply hands the flag out ("issued_flag"), or
the prompt links a page whose bytes (hunt.web) hide a flag{...} string.
"""
from __future__ import annotations

import re

from ..forensics.artifacts import UnreadableMember
from ..model import SYNTHESIZED, Question
from . import Answer, Context, handler

_FLAG = re.compile(r"flag\{[^{}\s\"'<>]{1,200}\}", re.I)


@handler(priority=50)
def issued_flag(q: Question, ctx: Context) -> Answer | None:
    if not q.raw.get(SYNTHESIZED):
        return None
    v = ctx.attempt.raw.get("issued_flag")
    if isinstance(v, str) and v.strip():
        return Answer(v.strip(), 0.99, "the Game Master's reply issues this flag (issued_flag)")
    return None


@handler(priority=60)
def page_flag(q: Question, ctx: Context) -> Answer | None:
    if not q.raw.get(SYNTHESIZED):
        return None
    found: dict[str, str] = {}  # flag -> where
    for m in ctx.artifacts.files():
        try:
            body = m.data.decode("utf-8", "replace")
        except UnreadableMember:
            continue
        for hit in _FLAG.findall(body):
            found.setdefault(hit, m.path)
    if not found:
        return None
    flag, where = next(iter(found.items()))
    inner = flag[flag.index("{") + 1:-1]
    if len(found) > 1:
        return Answer(flag, 0.5, f"{len(found)} different flag{{...}} strings in the linked page; first in {where}",
                      alternatives=[x for x in found if x != flag])
    # Submitted as found; the bare value inside the braces is the other way to read "the flag value".
    return Answer(flag, 0.95, f"the only flag{{...}} in the page the prompt links ({where})", alternatives=[inner])
