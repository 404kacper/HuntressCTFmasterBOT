"""The sandbox process that runs learned handlers.

sandbox.py starts it as `python -I -S -c <boot> <root>`, with an environment
that holds no Game Master token and no API keys, in an empty directory. It
loads the built-in handlers, then closes the doors with an audit hook (no
network, no processes, no file writes, no file reads outside the Python
installation and this package), and only then executes the learned modules
it was sent. After that it answers solve requests until stdin closes: one
JSON line in, one JSON line out.
"""
from __future__ import annotations

import base64
import importlib
import io
import json
import os
import sys
import sysconfig
import time
import traceback
import types

_BLOCK_PREFIXES = (
    "socket.", "subprocess.", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
    "os.kill", "os.killpg", "os.startfile", "os.add_dll_directory", "os.remove", "os.unlink", "os.rename",
    "os.replace", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.chflags", "os.lchown", "os.link",
    "os.symlink", "os.truncate", "os.putenv", "os.unsetenv", "os.utime", "os.listdir", "os.scandir",
    "os.chdir", "os.setxattr", "os.removexattr", "os.listxattr", "os.getxattr", "os.listdrives",
    "os.listmounts", "os.listvolumes", "shutil.", "ctypes.", "winreg.", "_winapi.", "msvcrt.",
    "urllib.Request", "http.client.", "ftplib.", "smtplib.", "poplib.", "imaplib.", "nntplib.", "telnetlib.",
    "webbrowser.", "sqlite3.", "pty.", "fcntl.", "resource.", "mmap.", "glob.", "tempfile.",
    "pickle.", "sys._getframe", "sys._current_frames", "sys.settrace", "sys.setprofile", "code.__new__",
    "function.__new__", "cpython.run_",
)
_WRITE_FLAGS = sum(getattr(os, f, 0) for f in ("O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"))
MAX_PRINTED = 4000
MAX_VALUE = 10_000


class _Hook:
    def __init__(self, read_roots: list[str]):
        self.read_roots = tuple(os.path.normcase(os.path.abspath(r)).rstrip("\\/") + os.sep
                                for r in read_roots if r)

    def __call__(self, event: str, args) -> None:
        if event == "open":
            path, mode, flags = (tuple(args) + (None, None, None))[:3]
            if self._readable(path, mode, flags):
                return
            raise PermissionError(f"sandbox: opening {path!r} is not allowed")
        if event in ("os.listdir", "os.scandir") and args and self._readable(args[0], None, None):
            return  # the import system lists the standard library's folders
        if event.startswith(_BLOCK_PREFIXES):
            raise PermissionError(f"sandbox: {event} is not allowed")

    def _readable(self, path, mode, flags) -> bool:
        if isinstance(mode, str) and any(c in mode for c in "wax+"):
            return False
        if isinstance(flags, int) and flags & _WRITE_FLAGS:
            return False
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if isinstance(path, os.PathLike):
            path = os.fspath(path)
        if not isinstance(path, str):
            return False  # file descriptors and the like
        full = os.path.normcase(os.path.abspath(path))
        return full.startswith(self.read_roots)


def _read_roots(root: str) -> list[str]:
    roots = {os.path.join(root, "hunt")}
    for key in ("stdlib", "platstdlib"):
        try:
            roots.add(sysconfig.get_paths()[key])
        except KeyError:
            pass
    roots.add(os.path.join(sys.base_prefix, "DLLs"))
    for mod in list(sys.modules.values()):  # extension modules live next to their files (lib-dynload)
        f = getattr(mod, "__file__", None)
        if f and not os.path.abspath(f).startswith(os.path.abspath(root)):
            roots.add(os.path.dirname(f))
    return sorted(roots)


def _preload() -> None:
    from . import policy
    for name in sorted(policy.ALLOWED_MODULES) + sorted(policy.ALLOWED_HUNT):
        try:
            importlib.import_module(name)
        except Exception:
            pass
    from ..solvers import load_handlers
    load_handlers()


def _load(name: str, source: str, traces: list[str]):
    """Execute one learned module; returns its handler registrations."""
    from . import policy
    from ..solvers import _HANDLERS
    problems = policy.check(source)
    if problems:
        raise policy.PolicyError(problems)
    before = set(map(id, _HANDLERS))
    mod = types.ModuleType(f"learned.{name}")
    mod.__dict__["__name__"] = f"learned.{name}"
    exec(compile(source, f"<learned/{name}.py>", "exec"), mod.__dict__)
    regs = [r for r in _HANDLERS if id(r) not in before]
    for reg in regs:
        reg.name = f"learned/{reg.name}"
        reg.fn = _guarded(reg.name, reg.fn, traces)
    return regs


def _guarded(name: str, fn, traces: list[str]):
    from ..solvers import Answer

    def run(q, ctx):
        try:
            out = fn(q, ctx)
        except Exception:
            traces.append(f"{name} raised on question {q.id}:\n{traceback.format_exc(limit=-8)}")
            raise
        if out is not None and not isinstance(out, Answer):
            traces.append(f"{name} returned {type(out).__name__} for {q.id}; return Answer(...) or None")
            return None
        return out
    return run


def _solve(req: dict, traces: list[str], printed: io.StringIO) -> dict:
    from ..forensics.artifacts import ArtifactSet
    from ..model import Attempt
    from ..solvers import solve
    t = time.perf_counter()
    attempt = Attempt.from_response(str(req.get("challenge") or ""), req.get("reply") or {})
    arts = ArtifactSet([(n or "", base64.b64decode(b)) for n, b in req.get("artifacts") or []])
    sol = solve(attempt, arts)
    answers = {}
    for qid, a in sol.answers.items():
        try:
            conf = float(a.confidence)
        except (TypeError, ValueError):
            conf = 0.0
        answers[qid] = {"value": str(a.value)[:MAX_VALUE], "confidence": conf,
                        "evidence": str(a.evidence)[:2000], "handler": str(a.handler)}
    return {"answers": answers, "unresolved": sol.unresolved, "notes": sol.notes,
            "traces": traces[:20], "printed": printed.getvalue()[:MAX_PRINTED],
            "seconds": time.perf_counter() - t}


def main() -> None:
    root = sys.argv[1]
    proto_in, proto_out = sys.stdin.buffer, sys.stdout.buffer
    printed = io.StringIO()
    sys.stdout = printed  # a handler's print() must never reach the protocol stream
    sys.stdin = io.StringIO()

    def send(obj) -> None:
        proto_out.write(json.dumps(obj, ensure_ascii=True).encode() + b"\n")
        proto_out.flush()

    init = json.loads(proto_in.readline() or b"{}")
    _preload()
    sys.addaudithook(_Hook(_read_roots(root)))
    traces: list[str] = []
    loaded, errors, handlers = [], {}, []
    for mod in init.get("modules") or []:
        name = str(mod.get("name"))
        try:
            regs = _load(name, str(mod.get("source") or ""), traces)
        except Exception:
            errors[name] = traceback.format_exc(limit=-6)
            continue
        loaded.append(name)
        handlers += [{"name": r.name, "priority": r.priority, "lanes": list(r.lanes),
                      "challenges": list(r.challenges)} for r in regs]
    send({"ok": True, "loaded": loaded, "errors": errors, "handlers": handlers})
    for line in proto_in:
        if not line.strip():
            continue
        traces.clear()
        printed.seek(0)
        printed.truncate()
        try:
            req = json.loads(line)
            if req.get("op") == "ping":
                send({"id": req.get("id"), "pong": True})
                continue
            send({"id": req.get("id"), **_solve(req, traces, printed)})
        except Exception:
            send({"id": None, "error": traceback.format_exc(limit=-6), "traces": traces[:20]})
