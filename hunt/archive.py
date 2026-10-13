"""Every attempt is saved: the reply, the artifact bytes, what we answered,
and what the Game Master said. Attempts that came back CORRECT become the
regression set that must pass before the bot is allowed to race.

Layout:  runs/<challenge>/<utc-stamp>-<label>/
            start.json  artifacts.json  artifacts/<sha256>.bin
            solution.json  inventory.json  submit.json
Artifact bytes are stored as <sha256>.bin so nothing is ever double-click
runnable and no attacker-chosen filename touches the disk.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .forensics.artifacts import ArtifactSet
from .gate import DEFAULT_MIN_CONFIDENCE, decide, normalize
from .model import Attempt
from .solvers import solve

DEFAULT_ROOT = Path("runs")


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80] or "_"


class Run:
    def __init__(self, path: Path):
        self.path = path

    @property
    def challenge(self) -> str:
        # The folder name is sanitised ('a/time_trial' -> 'a_time_trial'); the real id is in meta.json.
        meta = self.read_json("meta.json") or {}
        return meta.get("challenge") or self.path.parent.name

    def write_json(self, name: str, obj) -> None:
        # ensure_ascii: undecodable names (lone surrogates) must not crash the archive
        (self.path / name).write_text(json.dumps(obj, indent=2, ensure_ascii=True, default=str),
                                      encoding="utf-8")

    def read_json(self, name: str):
        p = self.path / name
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def write_artifacts(self, items: list[tuple[str | None, bytes, str | None]]) -> list[dict]:
        """items: (name the server gave, bytes, url)"""
        d = self.path / "artifacts"
        d.mkdir(exist_ok=True)
        meta = []
        for i, (name, data, url) in enumerate(items):
            sha = hashlib.sha256(data).hexdigest()
            (d / f"{sha}.bin").write_bytes(data)
            meta.append({"index": i, "name": name, "sha256": sha, "size": len(data), "url": url})
        self.write_json("artifacts.json", meta)
        return meta

    def artifact_set(self) -> ArtifactSet:
        meta = self.read_json("artifacts.json") or []
        return ArtifactSet([(m.get("name") or f"artifact{m['index']}",
                             (self.path / "artifacts" / f"{m['sha256']}.bin").read_bytes()) for m in meta])

    def attempt(self) -> Attempt:
        return Attempt.from_response(self.challenge, self.read_json("start.json") or {})

    def correct_answers(self) -> dict[str, str] | None:
        sub = self.read_json("submit.json")
        if not sub or str((sub.get("reply") or {}).get("result", "")).upper() != "CORRECT":
            return None
        return sub.get("sent") or None


class Archive:
    def __init__(self, root: Path | str = DEFAULT_ROOT):
        self.root = Path(root)

    def new_run(self, challenge: str, label: str) -> Run:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = self.root / _safe(challenge) / f"{stamp}-{_safe(label)}"
        path.mkdir(parents=True, exist_ok=False)
        run = Run(path)
        run.write_json("meta.json", {"challenge": challenge})
        return run

    def runs(self, challenge: str | None = None) -> list[Run]:
        if not self.root.exists():
            return []
        dirs = [self.root / _safe(challenge)] if challenge else sorted(self.root.iterdir())
        out = []
        for d in dirs:
            if d.is_dir():
                out += [Run(p) for p in sorted(d.iterdir()) if (p / "start.json").exists()]
        return out

    def latest(self, challenge: str) -> Run | None:
        runs = [r for r in self.runs(challenge) if (r.path / "artifacts.json").exists()]
        return runs[-1] if runs else None


def replay(archive: Archive, challenge: str | None = None,
           min_confidence: float = DEFAULT_MIN_CONFIDENCE, trust_guessed_ids: bool = False,
           solver=None, latest: int | None = None) -> list[dict]:
    """Re-solve every archived CORRECT attempt offline and compare with what
    the Game Master accepted, under the same gate settings a race would use:
    an answer the gate would hold counts as a failure. One row per run.
    solver: (attempt, artifacts) -> Solution (default: in process, built-in
    handlers only). latest: only the newest N CORRECT runs of each challenge."""
    rows = []
    picked: list[tuple[Run, dict]] = []
    per: dict[str, int] = {}
    for run in reversed(archive.runs(challenge)):
        truth = run.correct_answers()
        if not truth:
            continue
        key = run.path.parent.name
        if latest is not None and per.get(key, 0) >= latest:
            continue
        per[key] = per.get(key, 0) + 1
        picked.append((run, truth))
    for run, truth in reversed(picked):
        attempt = run.attempt()
        sol = (solver or solve)(attempt, run.artifact_set())
        dec = decide(attempt, sol, min_confidence, trust_guessed_ids)
        ids = attempt.answer_id_map()[0]
        qs = {ids[q.id]: q for q in attempt.questions if q.id in ids}
        diffs = {}
        for aid, want in truth.items():
            got = dec.submit.get(aid)
            q = qs.get(aid)
            if got is None or normalize(q, got) != normalize(q, want):
                diffs[aid] = {"accepted": want, "now": got, "held": dec.held.get(q.id if q else aid)}
        rows.append({"run": str(run.path), "ok": not diffs, "diffs": diffs})
    return rows
