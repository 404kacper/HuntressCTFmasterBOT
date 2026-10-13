"""What the advisor is shown about a challenge the bot cannot fully answer.

The packet holds the challenge text, every question with what the bot already
answered (and why the gate held the rest), an inventory of the downloaded
files, previews of their contents, earlier attempts of the same challenge with
the answers the Game Master accepted, and the handlers learned so far.
Everything that comes from artifact bytes is fenced as untrusted data.
"""
from __future__ import annotations

import json

from ..archive import Archive
from ..forensics.artifacts import ArtifactSet, Member, UnreadableMember
from ..forensics.identity import true_type
from ..gate import Decision
from ..model import Attempt
from ..solvers import Solution
from .library import Library

MAX_PREVIEWS = 24
TEXT_PREVIEW = 3000
HEX_PREVIEW = 256
MAX_PACKET = 100_000
_OPEN, _CLOSE = "<untrusted-artifact-data>", "</untrusted-artifact-data>"
_SKIP_REPLY_KEYS = {"questions", "guidance", "answer_ids", "flag", "solved_by", "token", "download", "downloads"}


def fence(text: str) -> str:
    """Untrusted text, made unable to close its own fence."""
    return f"{_OPEN}\n{text.replace(_CLOSE, '</untrusted-artifact-data_>')}\n{_CLOSE}"


def base_id(cid: str) -> str:
    return cid.split("/", 1)[0]


def build(attempt: Attempt, arts: ArtifactSet, solution: Solution, decision: Decision,
          library: Library | None = None, archive: Archive | None = None, entry: dict | None = None) -> str:
    parts = [_header(attempt, entry), _questions(attempt, solution, decision), _inventory(arts, attempt),
             _previews(arts, attempt)]
    if archive is not None:
        ex = _examples(archive, attempt.challenge)
        if ex:
            parts.append(ex)
    if library is not None:
        parts.append(_library(library))
    held = [q for q in attempt.questions if q.id in decision.held]
    parts.append("## Your task\nWrite one handler module so the bot answers "
                 + (", ".join(f"`{q.id}`" for q in held) or "these questions")
                 + " correctly on this and every future variant of this challenge.")
    text = "\n\n".join(parts)
    if len(text) > MAX_PACKET:
        text = text[:MAX_PACKET] + "\n\n[packet truncated]"
    return text


def _header(attempt: Attempt, entry: dict | None) -> str:
    raw = attempt.raw
    info = {"challenge_id": attempt.challenge, "lane": attempt.lane,
            "mode": attempt.challenge.split("/", 1)[1] if "/" in attempt.challenge else "single_solve"}
    for k in ("name", "day", "lane"):
        if entry and entry.get(k) is not None:
            info[k] = entry[k]
    extra = {k: v for k, v in raw.items() if k not in _SKIP_REPLY_KEYS and not isinstance(v, (dict, list))
             and k not in ("prompt", "_note")}
    out = "## Challenge\n" + json.dumps(info, ensure_ascii=False, indent=1)
    if raw.get("prompt"):
        out += "\n\nChallenge description (from the Game Master):\n" + fence(str(raw["prompt"])[:4000])
    if extra:
        out += "\n\nOther reply fields: " + json.dumps(extra, ensure_ascii=False, default=str)[:1500]
    return out


def _questions(attempt: Attempt, solution: Solution, decision: Decision) -> str:
    rows = []
    for q in attempt.questions:
        d = {k: v for k, v in q.raw.items() if k not in ("answer_id",)}
        a = solution.answers.get(q.id)
        if q.id in decision.held:
            d["bot_status"] = f"HELD: {decision.held[q.id]}"
            if a:
                d["bot_tentative_answer"] = a.value
        elif a:
            d["bot_status"] = f"answered by {a.handler} (confidence {a.confidence:.2f}): {a.evidence}"
            d["bot_answer"] = a.value
        rows.append(d)
    return ("## Questions (as the Game Master sent them, plus what the bot did)\n"
            + fence(json.dumps(rows, ensure_ascii=False, indent=1, default=str)))


def _describe(m: Member) -> dict:
    d = {"path": m.path, "order": m.order}
    if m.name_is_guess:
        d["name_is_guess"] = True
    try:
        raw = m.data
    except UnreadableMember as e:
        d["unreadable"] = str(e)[:200]
        return d
    from hashlib import sha256
    d.update({"size": len(raw), "true_type": true_type(raw)[0], "sha256": sha256(raw).hexdigest()})
    if m.mtime:
        d["mtime"] = m.mtime.isoformat()
    if m.notes:
        d["notes"] = m.notes[:5]
    return d


def _inventory(arts: ArtifactSet, attempt: Attempt) -> str:
    files = arts.files()
    rows = [_describe(m) for m in files[:400]]
    more = f"\n({len(files) - 400} more files not listed)" if len(files) > 400 else ""
    return ("## Downloaded files (archives expanded; `path` is what Member.path returns)\n"
            + fence(json.dumps(rows, ensure_ascii=False, indent=1)) + more)


def _referenced(arts: ArtifactSet, attempt: Attempt) -> list[Member]:
    out = []
    for q in attempt.questions:
        try:
            m = arts.resolve(q.artifact_chain) if q.artifact_chain else None
        except Exception:
            m = None
        if m is not None and m not in out:
            out.append(m)
    return out


def _preview(m: Member) -> str:
    try:
        raw = m.data
    except UnreadableMember as e:
        return f"(unreadable: {e})"
    if not raw:
        return "(empty)"
    sample = raw[:TEXT_PREVIEW * 2]
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in sample)
    if printable >= 0.9 * len(sample):
        text = raw.decode("utf-8", "replace")
        if len(text) > TEXT_PREVIEW:
            text = text[:TEXT_PREVIEW] + f"\n[... {len(text) - TEXT_PREVIEW} more characters; last 300:]\n" + text[-300:]
        return text
    head = raw[:HEX_PREVIEW]
    lines = [f"{i:08x}  {head[i:i + 16].hex(' '):<47}  " + "".join(chr(b) if 32 <= b < 127 else "." for b in head[i:i + 16])
             for i in range(0, len(head), 16)]
    strs = []
    run = bytearray()
    for b in raw[:1 << 20]:
        if 32 <= b < 127:
            run.append(b)
            continue
        if len(run) >= 6:
            strs.append(run.decode())
        run = bytearray()
        if len(strs) >= 60:
            break
    return "\n".join(lines) + ("\nprintable strings: " + json.dumps(strs, ensure_ascii=False) if strs else "")


def _previews(arts: ArtifactSet, attempt: Attempt) -> str:
    ordered = _referenced(arts, attempt)
    for m in arts.files():
        if m not in ordered and not arts.children(m):
            ordered.append(m)
    chunks = []
    for m in ordered[:MAX_PREVIEWS]:
        chunks.append(f"### {m.path}\n" + _preview(m))
    more = f"\n({len(ordered) - MAX_PREVIEWS} more files not previewed)" if len(ordered) > MAX_PREVIEWS else ""
    return "## File contents (previews)\n" + fence("\n\n".join(chunks)) + more


def _examples(archive: Archive, challenge: str) -> str:
    """Earlier attempts of this challenge (or its other modes) and the answers the Game Master accepted."""
    base = base_id(challenge)
    runs = [r for r in archive.runs() if base_id(r.challenge) == base and r.correct_answers()]
    if not runs:
        return ""
    chunks = []
    for run in runs[-2:]:
        a = run.attempt()
        truth = run.correct_answers() or {}
        ids = a.answer_id_map()[0]
        qa = [{"id": q.id, "question": q.text, "artifact": q.artifact,
               "accepted_answer": truth.get(ids.get(q.id, q.id))} for q in a.questions]
        try:
            files = [{"path": m.path, "size": len(m.data)} for m in run.artifact_set().files()[:60]]
        except Exception:
            files = []
        chunks.append(json.dumps({"challenge": run.challenge, "questions": qa, "files": files},
                                 ensure_ascii=False, indent=1))
    return ("## Earlier variants the Game Master accepted (other files, same kind of questions)\n"
            + fence("\n\n".join(chunks)))


def _library(library: Library) -> str:
    names = library.names()
    if not names:
        return "## Handlers learned so far\n(none yet)"
    man = library.manifest()["modules"]
    rows = []
    sources = []
    total = 0
    for n in names:
        e = man.get(n, {})
        rows.append(f"- {n}: {e.get('status', 'candidate')}"
                    + (f", proven on {', '.join(e['proven_on'])}" if e.get("proven_on") else ""))
        src = (library.root / f"{n}.py").read_text(encoding="utf-8")
        if total + len(src) < 40_000:
            sources.append(f"### learned/{n}.py\n```python\n{src}\n```")
            total += len(src)
    return ("## Handlers learned so far (reuse a name to revise one)\n" + "\n".join(rows)
            + ("\n\n" + "\n\n".join(sources) if sources else ""))
