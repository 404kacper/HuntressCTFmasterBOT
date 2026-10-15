"""The main process's side of the sandbox worker (worker.py).

Learned handlers never run in the bot's own process: that process holds the
Game Master token. They run in a child Python started with -I -S, an
environment holding nothing but what Windows needs to start Python, an empty
working directory, and an audit hook that refuses network, processes and
files. The worker is started (and warmed up) before any clock starts; a solve
is then one JSON line plus the raw artifact bytes in, one JSON line out.

Nothing that comes back is trusted: values are strings the gate still checks,
and handler names are only ever compared with the library's own names.
"""
from __future__ import annotations

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
from ..solvers import solve as builtin_solve

ROOT = str(Path(__file__).resolve().parents[2])  # the folder that holds the hunt package
_BOOT = "import sys; sys.path.insert(0, sys.argv[1]); from hunt.learn.worker import main; main()"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024  # the same budget ArtifactSet expands archives within
SOLVE_TIMEOUT = 20.0  # one solve on a real attempt
TRIAL_TIMEOUT = 15.0  # stricter in the offline trial, so what passes there never times out for real
_KEEP_ENV = ("SYSTEMROOT", "SystemRoot", "WINDIR")  # Python on Windows cannot start without these


class SandboxError(Exception):
    pass


def clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k in _KEEP_ENV}


def _tops(artifacts: ArtifactSet | list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    if isinstance(artifacts, list):
        return artifacts
    return [("" if m.name_is_guess else m.name, m.data) for m in artifacts.tops]


class Sandbox:
    def __init__(self, modules: list[tuple[str, str]], timeout: float = SOLVE_TIMEOUT,
                 startup_timeout: float = 60.0):
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
        try:
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
        except BaseException:
            self.close()
            raise

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

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
        tops = _tops(artifacts)
        if sum(len(d) for _, d in tops) > MAX_ARTIFACT_BYTES:
            raise SandboxError("artifacts are too large to hand to the sandbox")
        reply = self._request({"op": "solve", "challenge": attempt.challenge, "reply": attempt.raw,
                               "names": [n for n, _ in tops]}, [d for _, d in tops], timeout)
        if reply.get("error"):
            raise SandboxError(f"the sandbox worker failed: {reply['error']}")
        return reply

    def solve(self, attempt: Attempt, artifacts: ArtifactSet) -> Solution:
        """A drop-in for hunt.solvers.solve. If the worker cannot answer (too large,
        stuck, dead), the built-in handlers still do, in this process."""
        try:
            return to_solution(self.raw_solve(attempt, artifacts))
        except SandboxError as e:
            sol = builtin_solve(attempt, artifacts)
            sol.notes.append(f"sandbox unavailable ({e}); built-in handlers only")
            return sol

    def applies(self, challenge: str, lane: str | None) -> bool:
        """Could any learned handler answer questions of this challenge? (Asked of the
        worker: the lanes and patterns are the learned module's, not ours to evaluate.)"""
        try:
            return bool(self._request({"op": "applies", "challenge": challenge, "lane": lane}, []).get("applies"))
        except SandboxError:
            return False

    def ping(self) -> None:
        self._request({"op": "ping"}, [])

    # ---- plumbing ------------------------------------------------------------
    def _request(self, header: dict, blobs: list[bytes], timeout: float | None = None) -> dict:
        self._seq += 1
        header = {**header, "id": self._seq, "sizes": [len(b) for b in blobs]}
        self._send(header, blobs)
        return self._receive(timeout or self.timeout)

    def _send(self, obj, blobs: list[bytes] = ()) -> None:
        if not self.alive:
            raise SandboxError("the sandbox worker is not running" + self._stderr_tail())
        try:
            self.proc.stdin.write(json.dumps(obj).encode() + b"\n")
            for b in blobs:
                self.proc.stdin.write(b)
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
    answers = {qid: Answer(str(a.get("value", "")), float(a.get("confidence") or 0.0), str(a.get("evidence", "")),
                           str(a.get("handler", ""))[:200])
               for qid, a in (r.get("answers") or {}).items() if isinstance(a, dict)}
    notes = list(r.get("notes") or []) + [str(t).splitlines()[0] for t in r.get("traces") or [] if str(t)]
    return Solution(answers, dict(r.get("unresolved") or {}), notes)
