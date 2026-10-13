"""Parse Game Master start/retry/status replies into something solvers can use.

Only `questions`, `answer_ids` and `download` have been seen in a real reply;
everything else is read defensively so an unexpected shape degrades into a
warning (and a held answer) instead of a crash mid-timer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
# Results after which an attempt can no longer be answered.
TERMINAL_RESULTS = frozenset({"CORRECT", "EXPIRED", "INCORRECT", "FAILED", "FAIL", "WRONG"})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Question:
    id: str
    text: str
    artifact: str | None
    kind: str  # answer_format.kind: exact_text | integer | pattern | ...
    syntax: str  # answer_format.syntax, free text
    normalization: str | None
    answer_id: str | None
    raw: dict

    @classmethod
    def from_dict(cls, d: dict, index: int) -> "Question":
        fmt = d.get("answer_format") or {}
        if not isinstance(fmt, dict):
            fmt = {"kind": str(fmt)}
        qid = d.get("id") or d.get("answer_id") or f"q{index}"
        return cls(
            id=str(qid),
            text=str(d.get("question") or d.get("prompt") or d.get("text") or ""),
            artifact=d.get("artifact"),
            kind=str(fmt.get("kind") or ""),
            syntax=str(fmt.get("syntax") or ""),
            normalization=d.get("normalization"),
            answer_id=d.get("answer_id"),
            raw=d,
        )

    @property
    def artifact_chain(self) -> list[str]:
        """'a.zip -> dir/b.txt' -> ['a.zip', 'dir/b.txt']"""
        if not self.artifact or not isinstance(self.artifact, str):
            return []
        return [p.strip() for p in self.artifact.split("->") if p.strip()]

    @property
    def haystack(self) -> str:
        return f"{self.id} {self.text}".lower()


@dataclass
class Attempt:
    challenge: str
    raw: dict
    questions: list[Question]
    answer_ids: list[str]
    downloads: list[str]
    deadline: datetime | None
    attempt_id: str | None
    expected_sha256: set[str]
    warnings: list[str] = field(default_factory=list)
    answer_id_dict: dict[str, str] | None = None  # when the reply gives answer_ids as a mapping
    answer_ids_malformed: bool = False  # entries that are not plain ids (objects, lists, ...)
    download_sha256: list[str | None] = field(default_factory=list)  # per download, when the reply says

    @classmethod
    def from_response(cls, challenge: str, data: dict) -> "Attempt":
        qdicts = list(_iter_question_dicts(data))
        questions = [Question.from_dict(q, i) for i, q in enumerate(qdicts)]
        raw_ids = _answer_ids(data)
        scalar = all(isinstance(a, (str, int)) and not isinstance(a, bool) for a in raw_ids)
        answer_ids = [str(a) for a in raw_ids] if scalar else []
        return cls(
            challenge=challenge,
            raw=data,
            questions=questions,
            answer_ids=answer_ids,
            downloads=[u for u, _ in _download_entries(data)],
            download_sha256=[h for _, h in _download_entries(data)],
            deadline=_parse_time(data.get("deadline")),
            attempt_id=_first(data, ("attempt_id", "attempt")),
            expected_sha256=set(_sha256_values(data)),
            answer_id_dict=({str(k): str(v) for k, v in data["answer_ids"].items()}
                            if isinstance(data.get("answer_ids"), dict) else None),
            answer_ids_malformed=not scalar,
        )

    @property
    def timed(self) -> bool:
        return self.deadline is not None

    @property
    def result(self) -> str | None:
        r = self.raw.get("result")
        return str(r) if r is not None else None

    @property
    def lane(self) -> str:
        lane = self.raw.get("lane")
        if isinstance(lane, str) and lane:
            return lane
        return self.challenge.split("-day-")[0]

    def seconds_left(self, now: datetime | None = None) -> float | None:
        """Seconds to the deadline; pass the server's time (GameMaster.server_now)
        when you have it, because the local clock can be off by minutes."""
        if not self.deadline:
            return None
        return (self.deadline - (now or utcnow())).total_seconds()

    def answer_id_map(self) -> tuple[dict[str, str], list[str]]:
        """question id -> answer id (+ warnings about how it was decided)."""
        ids, warnings, _ = self.answer_id_mapping()
        return ids, warnings

    def answer_id_mapping(self) -> tuple[dict[str, str], list[str], bool]:
        """Like answer_id_map, plus whether the mapping had to be guessed
        (by position, or from question ids when the reply gave none)."""
        qs = self.questions
        qids = [q.id for q in qs]
        if qs and all(q.answer_id for q in qs):
            return {q.id: str(q.answer_id) for q in qs}, [], False
        if self.answer_ids_malformed:
            return {}, ["answer_ids contain entries that are not plain ids; not guessing"], False
        d = self.answer_id_dict
        if d is not None:
            if set(qids) <= set(d):  # {question_id: answer_id}
                return {qid: d[qid] for qid in qids}, [], False
            inverse = {v: k for k, v in d.items()}
            if set(qids) <= set(inverse) and len(inverse) == len(d):  # {answer_id: question_id}
                return {qid: inverse[qid] for qid in qids}, [], False
            return {}, ["answer_ids mapping does not mention the question ids; not guessing"], False
        if not self.answer_ids:
            return {qid: qid for qid in qids}, ["reply had no answer_ids; assuming they equal the question ids"], True
        if set(qids) <= set(self.answer_ids):
            return {qid: qid for qid in qids}, [], False
        if len(self.answer_ids) == len(qs):
            guessed = len(qs) > 1
            return ({q.id: a for q, a in zip(qs, self.answer_ids)},
                    ["answer_ids differ from question ids; mapped by position"] if guessed else [], guessed)
        return {}, [f"cannot map {len(self.answer_ids)} answer_ids onto {len(qs)} questions"], False


def _first(data: dict, keys) -> str | None:
    for k in keys:
        v = data.get(k)
        if isinstance(v, (str, int)) and v != "":
            return str(v)
        if isinstance(v, dict) and v.get("id"):
            return str(v["id"])
    return None


def _iter_question_dicts(data: dict):
    if isinstance(data.get("questions"), list):
        yield from (q for q in data["questions"] if isinstance(q, dict))
        return
    for task in data.get("tasks") or []:  # speculative Mastery shape
        if isinstance(task, dict):
            yield from (q for q in task.get("questions") or [] if isinstance(q, dict))


def _answer_ids(data: dict) -> list:
    ids = data.get("answer_ids")
    if isinstance(ids, list):
        return ids
    if isinstance(ids, dict):  # {question_id: answer_id}
        return list(ids.values())
    out = []
    for task in data.get("tasks") or []:
        if isinstance(task, dict) and isinstance(task.get("answer_ids"), list):
            out.extend(task["answer_ids"])
    return out


def _download_entries(data: dict) -> list[tuple[str, str | None]]:
    """(link, expected sha256 or None) for every download, in reply order."""
    found: list[tuple[str, str | None]] = []

    def take(v, sha=None):
        if isinstance(v, str) and v:
            found.append((v, sha.lower() if isinstance(sha, str) and _HEX64.match(sha) else None))
        elif isinstance(v, dict):
            take(v.get("url") or v.get("download") or v.get("href"), v.get("sha256") or v.get("artifact_sha256"))
        elif isinstance(v, list):
            for x in v:
                take(x)

    take(data.get("download"), data.get("sha256") or data.get("artifact_sha256"))
    for key in ("downloads", "artifacts", "deliveries"):
        take(data.get(key))
    for task in data.get("tasks") or []:
        if isinstance(task, dict):
            take(task.get("download"), task.get("sha256"))
    seen: dict[str, str | None] = {}
    for url, sha in found:
        seen[url] = seen.get(url) or sha
    return list(seen.items())


def _collect_downloads(data: dict) -> list[str]:
    return [u for u, _ in _download_entries(data)]


def _sha256_values(obj, depth: int = 0):
    """Any 64-hex value stored under a key mentioning sha256 (e.g. the
    artifact SHA-256 the docs say identifies a variant)."""
    if depth > 4:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and "sha256" in str(k).lower() and _HEX64.match(v):
                yield v.lower()
            elif isinstance(v, (dict, list)) and k != "questions":
                yield from _sha256_values(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _sha256_values(v, depth + 1)


_ISO_FRACTION = re.compile(r"(T\d{2}:\d{2}:\d{2})\.(\d+)")


def _parse_time(v) -> datetime | None:
    if not isinstance(v, str) or not v:
        return None
    # Python 3.10 only accepts 3- or 6-digit fractions and no "Z" suffix.
    v = v.strip().replace("Z", "+00:00").replace("z", "+00:00")
    v = _ISO_FRACTION.sub(lambda m: f"{m.group(1)}.{(m.group(2) + '000000')[:6]}", v)
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
