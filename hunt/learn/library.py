"""learned/: the handlers the bot has been taught, and what each has proven.

    learned/<name>.py          one module per technique, loaded only inside the sandbox
    learned/manifest.json      status per module: candidate (passed the offline trial)
                               or proven (the Game Master said CORRECT with its answers)
    learned/history/           earlier versions of modules that were since revised
    learned/rejected/          modules whose answers the Game Master turned down

Commit learned/ to git: it is the bot's memory, and `git pull` on Homebase
gives the racing machine the same knowledge.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import policy

DEFAULT_DIR = Path("learned")
NAME = re.compile(r"^[a-z][a-z0-9_]{1,47}$")
_RESERVED = {"kit", "file_identity", "manifest", "history", "rejected", "inbox", "learned"}


def valid_name(name) -> bool:
    """A module name that can only ever mean learned/<name>.py."""
    return isinstance(name, str) and bool(NAME.match(name)) and name not in _RESERVED


def module_of(handler_name: str) -> str | None:
    """'learned/base64_note.decode' -> 'base64_note'; None for built-in or malformed names."""
    if not isinstance(handler_name, str) or not handler_name.startswith("learned/"):
        return None
    module = handler_name[len("learned/"):].split(".", 1)[0]
    return module if valid_name(module) else None


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class Library:
    def __init__(self, root: Path | str = DEFAULT_DIR):
        self.root = Path(root)

    # ---- reading ---------------------------------------------------------------
    def names(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(p.stem for p in self.root.glob("*.py") if NAME.match(p.stem))

    def modules(self, exclude: str | None = None) -> list[tuple[str, str]]:
        """(name, source) for every learned module, skipping (and saying so) any that fail the policy."""
        out = []
        for name in self.names():
            if name == exclude:
                continue
            src = (self.root / f"{name}.py").read_text(encoding="utf-8")
            if policy.check(src):
                continue  # edited into something the sandbox will not run; `hunt learned` shows why
            out.append((name, src))
        return out

    def problems(self) -> dict[str, list[str]]:
        return {n: p for n in self.names()
                if (p := policy.check((self.root / f"{n}.py").read_text(encoding="utf-8")))}

    def manifest(self) -> dict:
        p = self.root / "manifest.json"
        if not p.exists():
            return {"modules": {}}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return {"modules": {}}
        data.setdefault("modules", {})
        return data

    def entry(self, name: str) -> dict:
        return self.manifest()["modules"].get(name, {}) if valid_name(name) else {}

    def status(self, name: str) -> str:
        if not valid_name(name) or not (self.root / f"{name}.py").is_file():
            return "missing"
        return self.entry(name).get("status", "candidate")

    def trusted(self, handler_name: str) -> bool:
        """Built-in handlers, and learned ones the Game Master has accepted answers from."""
        if not str(handler_name).startswith("learned/"):
            return True
        module = module_of(handler_name)
        return module is not None and self.status(module) == "proven"

    # ---- writing ---------------------------------------------------------------
    def _save(self, data: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / "manifest.json.tmp"
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.root / "manifest.json")

    def install(self, name: str, source: str, **meta) -> Path:
        if not valid_name(name):
            raise ValueError(f"bad module name {name!r}")
        policy.require(source)
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{name}.py"
        data = self.manifest()
        prev = data["modules"].get(name, {})
        replaced = None
        if path.exists():
            old = path.read_text(encoding="utf-8")
            if old == source:
                return path
            (self.root / "history").mkdir(exist_ok=True)
            replaced = self.root / "history" / f"{name}-{_stamp()}.py"
            replaced.write_text(old, encoding="utf-8")
        tmp = path.with_suffix(".py.tmp")
        tmp.write_text(source, encoding="utf-8")
        os.replace(tmp, path)
        data["modules"][name] = {**prev, **meta, "status": "candidate", "updated": _stamp(),
                                 "proven_on": prev.get("proven_on", []), "versions": prev.get("versions", 0) + 1,
                                 "replaced": ({"file": replaced.name, "status": prev.get("status", "candidate")}
                                              if replaced else None)}
        self._save(data)
        return path

    def mark_proven(self, name: str, challenge: str) -> None:
        if self.status(name) == "missing":
            return
        data = self.manifest()
        e = data["modules"].setdefault(name, {})
        e["status"] = "proven"
        if challenge not in e.setdefault("proven_on", []):
            e["proven_on"].append(challenge)
        e["proven"] = _stamp()
        e["replaced"] = None  # this version has earned its place: never roll it back
        self._save(data)

    def reject(self, name: str, why: str) -> Path | None:
        """Move a module whose answer the Game Master refused out of the way. If it
        was a revision of a proven module, the proven version comes back."""
        if self.status(name) == "missing":
            return None
        path = self.root / f"{name}.py"
        (self.root / "rejected").mkdir(exist_ok=True)
        dest = self.root / "rejected" / f"{name}-{_stamp()}.py"
        os.replace(path, dest)
        data = self.manifest()
        e = data["modules"].setdefault(name, {})
        e.update({"rejected": _stamp(), "why": why[:500]})
        old = e.get("replaced") or {}
        backup = self.root / "history" / str(old.get("file") or "")
        if old.get("status") == "proven" and old.get("file") and backup.is_file():
            path.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
            e.update({"status": "proven", "replaced": None, "restored": backup.name})
        else:
            e["status"] = "rejected"
        self._save(data)
        return dest
