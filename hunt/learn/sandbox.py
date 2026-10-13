"""The main process's side of the sandbox worker (worker.py).

Learned handlers never run in the bot's own process: that process holds the
Game Master token. They run in a child Python started with -I -S, an
environment holding nothing but what Windows needs to start Python, an empty
working directory, and an audit hook that refuses network, processes and
files. The worker is started (and warmed up) before any clock starts; a solve
is then one JSON line each way, about a millisecond for small artifacts.
"""
from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from ..forensics.artifacts import ArtifactSet
from ..model import Attempt
from ..solvers import Answer, Solution

ROOT = str(Path(__file__).resolve().parents[2])  # the folder that holds the hunt package
_BOOT = "import sys; sys.path.insert(0, sys.argv[1]); from hunt.learn.worker import main; main()"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_KEEP_ENV = ("SYSTEMROOT", "SystemRoot", "WINDIR")  # Python on Windows cannot start without these


class SandboxError(Exception):
    pass


def clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k in _KEEP_ENV}


class Sandbox:
    def __init__(self, modules: list[tuple[str, str]], timeout: float = 20.0, startup_timeout: float = 60.0):
        self.modules = modules
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self.proc: subprocess.Popen | None = None
        self.info: dict = {}
        self._lines: queue.Queue = queue.Queue()
        self._stderr: list[bytes] = []
        self._dir: tempfile.TemporaryDirectory | None = None
        self._threads: list[threading.Thread] = []
        self._seq = 0

    # ---- lifecycle -----------------------------------------------------------
    def start(self) -> dict:
        """Start the worker and load the modules; returns what loaded and what failed."""
        self._dir = tempfile.TemporaryDirectory(prefix="hunt-sandbox-")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.proc = subprocess.Popen([sys.executable, "-I", "-S", "-c", _BOOT, ROOT], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self._dir.name,
                                     env=clean_env(), creationflags=flags)
        self._threads = [threading.Thread(target=self._pump, args=(self.proc.stdout, self._lines), daemon=True),
                         threading.Thread(target=self._drain, args=(self.proc.stderr,), daemon=True)]
        for t in self._threads:
            t.start()
        self._send({"modules": [{"name": n, "source": s} for n, s in self.modules]})
        self.info = self._receive(self.startup_timeout)
        return self.info

    def close(self) -> None:
        if self.proc is not None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=2)
            except Exception:
                self.proc.kill()
                self.proc.wait()
            for t in self._threads:
                t.join(timeout=1)
            for stream in (self.proc.stdout, self.proc.stderr):
                try:
                    stream.close()
                except Exception:
                    pass
            self.proc = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def __enter__(self) -> "Sandbox":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- requests ------------------------------------------------------------
    def raw_solve(self, attempt: Attempt, artifacts: ArtifactSet | list[tuple[str, bytes]],
                  timeout: float | None = None) -> dict:
        tops = artifacts if isinstance(artifacts, list) else \
            [("" if m.name_is_guess else m.name, m.data) for m in artifacts.tops]
        if sum(len(d) for _, d in tops) > MAX_ARTIFACT_BYTES:
            raise SandboxError("artifacts are too large to hand to the sandbox")
        self._seq += 1
        self._send({"op": "solve", "id": self._seq, "challenge": attempt.challenge, "reply": attempt.raw,
                    "artifacts": [[n, base64.b64encode(d).decode()] for n, d in tops]})
        reply = self._receive(timeout or self.timeout)
        if reply.get("error"):
            raise SandboxError(f"the sandbox worker failed: {reply['error']}")
        return reply

    def solve(self, attempt: Attempt, artifacts: ArtifactSet) -> Solution:
        """A drop-in for hunt.solvers.solve. A dead or stuck worker becomes 'unresolved', never a crash."""
        try:
            r = self.raw_solve(attempt, artifacts)
        except SandboxError as e:
            return Solution({}, {q.id: f"sandbox: {e}" for q in attempt.questions}, [str(e)])
        return to_solution(r)

    def ping(self) -> None:
        self._seq += 1
        self._send({"op": "ping", "id": self._seq})
        self._receive(self.timeout)

    # ---- plumbing ------------------------------------------------------------
    def _send(self, obj) -> None:
        if self.proc is None or self.proc.poll() is not None:
            raise SandboxError("the sandbox worker is not running" + self._stderr_tail())
        try:
            self.proc.stdin.write(json.dumps(obj).encode() + b"\n")
            self.proc.stdin.flush()
        except OSError as e:
            raise SandboxError(f"the sandbox worker went away ({e}){self._stderr_tail()}") from None

    def _receive(self, timeout: float) -> dict:
        try:
            line = self._lines.get(timeout=timeout)
        except queue.Empty:
            self._kill()
            raise SandboxError(f"no answer from the sandbox within {timeout:.0f}s (endless loop?); worker stopped")
        if line is None:
            raise SandboxError("the sandbox worker exited" + self._stderr_tail())
        try:
            return json.loads(line)
        except ValueError:
            raise SandboxError(f"garbled reply from the sandbox: {line[:200]!r}") from None

    def _kill(self) -> None:
        if self.proc is not None:
            self.proc.kill()

    def _stderr_tail(self) -> str:
        tail = b"".join(self._stderr)[-1500:].decode("utf-8", "replace").strip()
        return f": {tail}" if tail else ""

    @staticmethod
    def _pump(stream, q: queue.Queue) -> None:
        for line in iter(stream.readline, b""):
            q.put(line)
        q.put(None)

    def _drain(self, stream) -> None:
        for chunk in iter(lambda: stream.read(4096), b""):
            self._stderr.append(chunk)
            if len(self._stderr) > 64:
                del self._stderr[:32]


def to_solution(r: dict) -> Solution:
    answers = {qid: Answer(a["value"], float(a.get("confidence") or 0.0), a.get("evidence", ""), a.get("handler", ""))
               for qid, a in (r.get("answers") or {}).items()}
    notes = list(r.get("notes") or []) + [t.splitlines()[0] for t in r.get("traces") or []]
    return Solution(answers, dict(r.get("unresolved") or {}), notes)
