"""The sandbox process that runs learned handlers.

sandbox.py starts it as `python -I -S -c <boot> <root>`, with an environment
that holds no Game Master token and no API keys, in an empty directory. It
loads the built-in handlers, then closes the doors with an audit hook (no
network, no processes, no file writes, no file reads outside the Python
installation and this package), and only then executes the learned modules
it was sent, each with a reduced set of builtins and an import guard.

Protocol on stdin/stdout: the first line is JSON naming the modules to load;
the reply is one JSON line. After that, each request is one JSON line
followed by the raw bytes of its artifacts (their sizes are in the line), and
each reply is one JSON line.

Nothing a learned module produces is trusted: answers are attributed to the
module the parent named, and a handler that rewrites other answers, the
questions, or the handler registry is undone and reported.
"""
from __future__ import annotations

import builtins
import importlib
import io
import json
import os
import re
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
    "pickle.", "sys._current_frames", "sys.settrace", "sys.setprofile", "code.__new__",
    "function.__new__", "cpython.run_",
)
_WRITE_FLAGS = sum(getattr(os, f, 0) for f in ("O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"))
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,47}$")
_DENIED_BUILTINS = ("open", "eval", "exec", "compile", "input", "breakpoint", "globals", "locals", "vars",
                    "getattr", "setattr", "delattr", "help", "exit", "quit", "copyright", "credits", "license")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
MAX_PRINTED = 4000
MAX_VALUE = 10_000
MAX_ALTERNATIVES = 8


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
        # namedtuple, functional Enum and TypeVar ask for their caller's module this way;
        # these are the errors they already expect when frames are unavailable.
        if event == "sys._getframemodulename":
            raise AttributeError("sandbox: frames are not available")
        if event == "sys._getframe":
            raise ValueError("sandbox: frames are not available")
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


class _Integrity:
    """The bot's own classes as they were before any learned code ran. Learned code
    could reach them through an alias the static check cannot follow; anything it
    changed is put back, and the change reported."""

    def __init__(self):
        from ..forensics.artifacts import ArtifactSet, Member, UnreadableMember
        from ..model import Attempt, Question
        from ..solvers import Answer, Context, Solution
        self.saved = {cls: dict(vars(cls)) for cls in (Answer, Context, Solution, Question, Attempt, Member,
                                                        ArtifactSet, UnreadableMember)}

    def repair(self) -> list[str]:
        changed = []
        for cls, saved in self.saved.items():
            now = dict(vars(cls))
            if now == saved:
                continue
            changed.append(cls.__name__)
            for k in set(now) - set(saved):
                type.__delattr__(cls, k)
            for k, v in saved.items():
                if now.get(k, _MISSING) is not v:
                    type.__setattr__(cls, k, v)
        return changed


_MISSING = object()


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    from . import policy
    if level or (name not in policy.ALLOWED_MODULES and name not in policy.ALLOWED_HUNT):
        raise ImportError(f"sandbox: import of {name!r} is not allowed")
    return builtins.__import__(name, globals, locals, fromlist, level)


def _learned_builtins() -> dict:
    b = {k: v for k, v in vars(builtins).items() if k not in _DENIED_BUILTINS}
    b["__import__"] = _guarded_import
    return b


def _load(name: str, source: str, traces: list[str]):
    """Execute one learned module; returns its handler registrations."""
    from . import policy
    from ..solvers import _HANDLERS
    if not _NAME.match(name):
        raise ValueError(f"bad module name {name!r}")
    problems = policy.check(source)
    if problems:
        raise policy.PolicyError(problems)
    before = set(map(id, _HANDLERS))
    modname = f"learned.{name}"
    mod = types.ModuleType(modname)
    mod.__dict__["__builtins__"] = _learned_builtins()
    sys.modules[modname] = mod  # dataclasses and enum look their class's module up here
    try:
        # dont_inherit: this file's `from __future__ import annotations` must not leak into learned code
        exec(compile(source, f"<learned/{name}.py>", "exec", dont_inherit=True), mod.__dict__)
    except BaseException:
        sys.modules.pop(modname, None)
        _HANDLERS[:] = [r for r in _HANDLERS if id(r) in before]
        raise
    regs = [r for r in _HANDLERS if id(r) not in before]
    for reg in regs:
        fn_name = re.sub(r"[^A-Za-z0-9_]", "_", str(getattr(reg.fn, "__name__", "handler")))[:60] or "handler"
        reg.name = f"learned/{name}.{fn_name}"  # from the parent's name, never from the module itself
        reg.fn = _guarded(reg.name, reg.fn, traces)
    return regs


def _snapshot(q, ctx) -> tuple:
    answers = {k: (a, a.value, a.confidence, a.evidence, a.handler, a.subject, tuple(a.alternatives))
               for k, a in ctx.answers.items()}
    question = (q.id, q.text, q.artifact, q.kind, q.syntax, q.normalization, q.answer_id)
    return answers, question, (ctx.subject, ctx.subject_confidence)


def _restore(q, ctx, snap: tuple) -> bool:
    """Undo whatever a handler changed outside its own answer; True if it changed anything."""
    answers, question, subject = snap
    changed = False
    now = {k: (a, a.value, a.confidence, a.evidence, a.handler, a.subject, tuple(a.alternatives))
           for k, a in ctx.answers.items()}
    if now != answers:
        changed = True
        ctx.answers.clear()
        for k, (a, value, conf, ev, handler, subj, alts) in answers.items():
            a.value, a.confidence, a.evidence, a.handler, a.subject = value, conf, ev, handler, subj
            a.alternatives = list(alts)
            ctx.answers[k] = a
    if (q.id, q.text, q.artifact, q.kind, q.syntax, q.normalization, q.answer_id) != question:
        changed = True
        q.id, q.text, q.artifact, q.kind, q.syntax, q.normalization, q.answer_id = question
    if (ctx.subject, ctx.subject_confidence) != subject:
        changed = True
        ctx.subject, ctx.subject_confidence = subject
    return changed


def _guarded(name: str, fn, traces: list[str]):
    from ..solvers import Answer

    def run(q, ctx):
        snap = _snapshot(q, ctx)
        try:
            out = fn(q, ctx)
        except Exception:
            _restore(q, ctx, snap)
            traces.append(f"{name} raised on question {q.id}:\n{traceback.format_exc(limit=-8)}")
            raise
        if _restore(q, ctx, snap):
            traces.append(f"{name} changed other answers, the question or the context on {q.id}; "
                          "that was undone and its answer dropped")
            return None
        if out is not None and not isinstance(out, Answer):
            traces.append(f"{name} returned {type(out).__name__} for {q.id}; return Answer(...) or None")
            return None
        if out is not None:
            out.handler = name  # attribution is ours to give
        return out
    return run


def _clean(text, limit: int) -> str:
    return _CONTROL.sub("?", str(text))[:limit]


def _solve(req: dict, blobs: list[bytes], traces: list[str], printed: io.StringIO, frozen: set[int]) -> dict:
    from ..forensics.artifacts import ArtifactSet
    from ..model import Attempt
    from ..solvers import _HANDLERS, solve
    t = time.perf_counter()
    attempt = Attempt.from_response(str(req.get("challenge") or ""), req.get("reply") or {})
    names = list(req.get("names") or [])
    arts = ArtifactSet([(str(names[i]) if i < len(names) and names[i] else "", b) for i, b in enumerate(blobs)])
    try:
        sol = solve(attempt, arts)
    finally:
        if len(_HANDLERS) != len(frozen) or any(id(r) not in frozen for r in _HANDLERS):
            traces.append("a learned handler registered more handlers while solving; they were removed")
            _HANDLERS[:] = [r for r in _HANDLERS if id(r) in frozen]
    answers = {}
    for qid, a in sol.answers.items():
        try:
            conf = float(a.confidence)
        except (TypeError, ValueError):
            conf = 0.0
        alts = a.alternatives if isinstance(a.alternatives, (list, tuple)) else []
        answers[str(qid)[:200]] = {"value": str(a.value)[:MAX_VALUE], "confidence": conf,
                                   "evidence": _clean(a.evidence, 2000), "handler": _clean(a.handler, 200),
                                   "alternatives": [str(x)[:MAX_VALUE] for x in alts[:MAX_ALTERNATIVES]]}
    return {"answers": answers, "unresolved": {str(k)[:200]: _clean(v, 500) for k, v in sol.unresolved.items()},
            "notes": [_clean(n, 500) for n in sol.notes[:50]], "traces": traces[:20],
            "printed": printed.getvalue()[:MAX_PRINTED], "seconds": time.perf_counter() - t}


def _applies(req: dict) -> dict:
    from ..model import Attempt
    from ..solvers import _HANDLERS
    raw = {"lane": req["lane"]} if req.get("lane") else {}
    attempt = Attempt.from_response(str(req.get("challenge") or ""), raw)
    hits = [r.name for r in _HANDLERS if r.name.startswith("learned/") and r.applies(attempt)]
    return {"applies": bool(hits), "handlers": hits[:50]}


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
    from ..solvers import _HANDLERS
    integrity = _Integrity()
    traces: list[str] = []
    loaded, errors, handlers = [], {}, []
    for mod in init.get("modules") or []:
        name = str(mod.get("name"))
        try:
            regs = _load(name, str(mod.get("source") or ""), traces)
        except Exception:
            integrity.repair()
            errors[name] = traceback.format_exc(limit=-6)
            continue
        tampered = integrity.repair()
        if tampered:
            sys.modules.pop(f"learned.{name}", None)
            _HANDLERS[:] = [r for r in _HANDLERS if r not in regs]
            errors[name] = f"refused: loading it changed the bot's own classes ({', '.join(tampered)})"
            continue
        loaded.append(name)
        handlers += [{"name": r.name, "priority": r.priority, "lanes": list(r.lanes),
                      "challenges": list(r.challenges)} for r in regs]
    frozen = set(map(id, _HANDLERS))
    send({"ok": True, "loaded": loaded, "errors": errors, "handlers": handlers})
    while True:
        line = proto_in.readline()
        if not line:
            break
        if not line.strip():
            continue
        traces.clear()
        printed.seek(0)
        printed.truncate()
        try:
            req = json.loads(line)
            sizes = [int(s) for s in req.get("sizes") or []]
            blobs = [proto_in.read(s) for s in sizes]  # raw artifact bytes follow the line
            if any(len(b) != s for b, s in zip(blobs, sizes)):
                break  # the parent went away mid-request
            op = req.get("op")
            if op == "ping":
                send({"id": req.get("id"), "pong": True})
            elif op == "applies":
                send({"id": req.get("id"), **_applies(req)})
            else:
                reply = _solve(req, blobs, traces, printed, frozen)
                tampered = integrity.repair()
                if tampered:  # nothing computed while the classes were altered can be trusted
                    reply = {"error": f"a learned handler changed the bot's own classes ({', '.join(tampered)}); "
                                      "this solve was discarded", "traces": traces[:20]}
                send({"id": req.get("id"), **reply})
        except Exception:
            integrity.repair()
            send({"id": None, "error": traceback.format_exc(limit=-6), "traces": traces[:20]})
