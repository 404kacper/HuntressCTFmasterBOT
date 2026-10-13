"""A local stand-in for the Game Master, for tests and `hunt rehearse`.

It copies the documented behaviour (start reconnects, retry spends a variant,
run_for_time adds a deadline, partial "accepted", one wrong answer fails the
attempt) and the reply shape seen live for "You Must Be This Hash to Ride".
Its variants are guesses at how a dynamic task might differ: other
filenames, decoy files, subfolders, opaque answer ids. Passing here means the
plumbing and the solver's generality are sound, not that the real server
agrees.
"""
from __future__ import annotations

import hashlib
import io
import json
import random
import secrets
import threading
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CID = "metadata-forensics-day-01-hash-to-ride"
ZIP_NAME = "metadata-day-01-evidence.zip"

_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_SYNTAX = {
    "md5": "exact 32-character hexadecimal MD5 digest; letter case is ignored",
    "sha1": "exact 40-character hexadecimal SHA-1 digest; letter case is ignored",
    "sha256": "exact 64-character hexadecimal SHA-256 value; use no prefix, spaces, or explanatory text",
}
_LABEL = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def _note(rng: random.Random) -> bytes:
    return ("Huntress CTF 2026 — Metadata Forensics\n"
            f"Case marker: CASE-{rng.getrandbits(48):012X}\n"
            f"Endpoint: WS-{rng.getrandbits(32):08X}\n"
            f"Collected sequence: {rng.randrange(10**9, 10**10)}\n"
            f"Analyst: analyst-{rng.getrandbits(32):08x}\n\n"
            "Preserve these bytes exactly. Filename, length, and cryptographic digests are evidence.\n"
            ).encode()


def _questions(note_path: str, prefix: str = "evidence-note", ordinal: str = "first") -> list[dict]:
    chain = f"{ZIP_NAME} -> {note_path}"
    qs = [{"id": f"{prefix}-filename",
           "question": f"What is the exact filename of the {ordinal} evidence note?",
           "artifact": ZIP_NAME,
           "answer_format": {"kind": "exact_text", "syntax": "exact base filename including its extension, "
                                                             "with no directory path, quotes, or explanatory text"},
           "normalization": "trim"},
          {"id": f"{prefix}-size-bytes", "question": "What is its exact size in bytes?", "artifact": chain,
           "answer_format": {"kind": "integer",
                             "syntax": "base-10 integer with no units, separators, or explanatory text"},
           "normalization": "trim"}]
    for algo in ("md5", "sha1", "sha256"):
        qs.append({"id": f"{prefix}-{algo}", "question": f"What is its {_LABEL[algo]} digest?", "artifact": chain,
                   "answer_format": {"kind": "pattern", "syntax": _SYNTAX[algo]},
                   "normalization": "case_insensitive"})
    return qs


def _truth(path: str, data: bytes, prefix: str = "evidence-note") -> dict[str, str]:
    t = {f"{prefix}-filename": path.rsplit("/", 1)[-1], f"{prefix}-size-bytes": str(len(data))}
    for algo in _HEX:
        t[f"{prefix}-{algo}"] = hashlib.new(algo, data).hexdigest()
    return t


@dataclass
class Variant:
    zip_bytes: bytes
    questions: list[dict]
    truth: dict[str, str]  # question id -> answer
    deliveries: list[bytes] = field(default_factory=list)  # several separate downloads (timed Mastery)


def make_variant(rng: random.Random, mode: str = "trio") -> Variant:
    """mode: single (like the live single solve), trio (note + 2 decoys,
    maybe in a folder), mastery (two notes, two question sets)."""
    files: list[tuple[str, bytes]] = []
    folder = rng.choice(["", "", "evidence/", "case-0142/"]) if mode != "single" else ""
    names = ["evidence-note.txt", "evidence_note.txt", "evidence-note-01.txt", "Evidence-Note.log",
             "evidence-note.md"]
    if mode == "mastery":
        a, b = rng.sample(names, 2)
        files = [(folder + a, _note(rng)), (folder + "intake.png", _note(rng)), (folder + b, _note(rng))]
        qs = _questions(files[0][0], "task-1-note", "first") + _questions(files[2][0], "task-2-note", "second")
        truth = {**_truth(*files[0], "task-1-note"), **_truth(*files[2], "task-2-note")}
    else:
        note = (folder + rng.choice(names), _note(rng))
        if mode == "single":
            files = [note]
        else:
            decoys = [(folder + "scan.png", b"not really a png\n"),
                      (folder + "report.pdf", b"\x89PNG\r\n\x1a\n" + rng.randbytes(64)),
                      (folder + "SHA256SUMS", f"{'0' * 64}  {note[0].rsplit('/', 1)[-1]}\n".encode())]
            files = rng.sample(decoys, 2)
            files.insert(rng.randrange(3), note)
        qs = _questions(note[0])
        truth = _truth(*note)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files:
            zf.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
    return Variant(buf.getvalue(), qs, truth)


@dataclass
class _Attempt:
    id: str
    variant: Variant
    timed: bool
    deadline: datetime | None
    answer_ids: dict[str, str]  # question id -> answer id
    accepted: set[str] = field(default_factory=set)
    state: str = "active"  # active | solved | failed | expired
    solved_at: float = 0.0


class FakeGM:
    def __init__(self, token: str = "rehearsal-token", mode: str = "trio", seed: int = 1,
                 opaque_ids: bool = False, timed_by_default: bool = False, time_limit: float = 30.0,
                 prepare_delay: float = 0.0, proxy_prefix: str = "", root_links: bool = False,
                 pending_for: float = 0.0, two_deliveries: bool = False, proxy_passthrough: bool = False):
        self.token, self.mode, self.opaque = token, mode, opaque_ids
        # proxy_prefix: serve the API only under a path, like the Homebase proxy
        # (http://10.0.0.219/huntress-ctf-proxy). root_links: hand out download
        # links like '/artifact/<id>', which only work on the direct host.
        self.proxy_prefix, self.root_links = proxy_prefix.rstrip("/"), root_links
        self.ranked_left = 32  # like ranked_attempts_remaining in live replies
        # Seconds after a solve during which retry hands back the solved attempt
        # ("if scoring is still pending, that attempt stays in place until confirmation").
        self.pending_for = pending_for
        # Like the live timed Mastery variant: two separate downloads (root-relative links)
        # instead of one zip of zips; op=artifact can only return the first.
        self.two_deliveries = two_deliveries
        self.proxy_passthrough = proxy_passthrough  # serve '<prefix>/artifact/...' links through the proxy
        self.reverse_deliveries = False  # op=artifact&delivery=i counts from the other end (order test)
        self.timed_by_default, self.time_limit = timed_by_default, time_limit
        self.prepare_delay = prepare_delay  # the real server can take a while to prepare a variant
        self.rng = random.Random(seed)
        self.attempt: _Attempt | None = None
        self.history: list[_Attempt] = []
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None

    # ---- game logic ---------------------------------------------------------
    def _new(self, timed: bool) -> _Attempt:
        if self.prepare_delay:
            time.sleep(self.prepare_delay)
        v = make_variant(self.rng, self.mode)
        if self.two_deliveries:
            # Like the live timed Mastery variant: two separate downloads with the same file
            # name, questions told apart by a "set" field (1-based).
            parts = [make_variant(self.rng, "trio") for _ in range(2)]
            qs, truth = [], {}
            for n, part in enumerate(parts, 1):
                for q in part.questions:
                    qs.append({**q, "id": f"set{n}.{q['id']}", "set": n})
                truth.update({f"set{n}.{k}": val for k, val in part.truth.items()})
            v = Variant(parts[0].zip_bytes, qs, truth, [p.zip_bytes for p in parts])
        ids = {q["id"]: (secrets.token_hex(6) if self.opaque else q["id"]) for q in v.questions}
        deadline = datetime.now(timezone.utc) + timedelta(seconds=self.time_limit) if timed else None
        if timed:
            self.ranked_left -= 1
        self.attempt = _Attempt(secrets.token_hex(8), v, timed, deadline, ids)
        self.history.append(self.attempt)
        return self.attempt

    def _view(self, a: _Attempt) -> dict:
        if a.state == "solved":
            return {"result": "CORRECT", "solved_by": {"name": "rehearsal"}, "questions": a.variant.questions,
                    "ranked_attempts_remaining": self.ranked_left}
        d = {"challenge": CID, "attempt_id": a.id, "questions": a.variant.questions,
             "answer_ids": list(a.answer_ids.values()),
             "download": f"/artifact/{a.id}" if self.root_links else f"?op=artifact&challenge={CID}",
             "artifact_sha256": hashlib.sha256(a.variant.zip_bytes).hexdigest(),
             "unique_attempts_remaining": 5, "ranked_attempts_remaining": self.ranked_left}
        if a.deadline:
            d["deadline"] = a.deadline.isoformat().replace("+00:00", "Z")
            d["hall_of_fame_eligible"] = True
        if a.state in ("failed", "expired"):
            d["result"] = a.state
        if a.variant.deliveries:
            d.pop("download", None)
            d.pop("artifact_sha256", None)
            d["downloads"] = [{"url": f"/artifact/{a.id}/{n}", "sha256": hashlib.sha256(z).hexdigest()}
                              for n, z in enumerate(a.variant.deliveries, 1)]
        return d

    def _expired(self, a: _Attempt) -> bool:
        if a.deadline and a.state == "active" and datetime.now(timezone.utc) > a.deadline:
            a.state = "expired"
        return a.state == "expired"

    def handle(self, method: str, query: dict, body: dict) -> tuple[int, dict]:
        op = query.get("op") or body.get("op")
        with self.lock:
            if method == "GET" and op == "list":
                return 200, {"challenges": [{"id": CID, "name": "You Must Be This Hash to Ride", "day": 1,
                                             "lane": "metadata-forensics",
                                             "run_for_time_supported": not self.timed_by_default}]}
            if method == "GET" and op == "openapi":
                return 200, {"openapi": "3.1.0", "info": {"title": "fake Game Master"}}
            if method == "GET" and op == "status":
                return 200, (self._view(self.attempt) if self.attempt else
                             {"status": "not_started", "ranked_attempts_remaining": self.ranked_left})
            if method != "POST":
                return 400, {"error": f"unknown op {op!r}"}
            if body.get("challenge") != CID:
                return 404, {"error": "unknown challenge"}
            a = self.attempt
            if "answers" in body:
                return self._submit(body["answers"])
            if op in (None, "start"):
                if a is None:
                    timed = bool(body.get("run_for_time")) or self.timed_by_default
                    a = self._new(timed)
                return 200, self._view(a)
            if op == "retry":
                if a and a.state == "active" and not self._expired(a):
                    return 409, {"error": "finish the current attempt before retrying"}
                if a and a.state == "solved" and time.monotonic() - a.solved_at < self.pending_for:
                    return 200, self._view(a)  # stays in place until scoring is confirmed
                return 200, self._view(self._new(bool(body.get("run_for_time")) or self.timed_by_default))
            return 400, {"error": f"unknown op {op!r}"}

    def _submit(self, answers: dict) -> tuple[int, dict]:
        a = self.attempt
        if a is None:
            return 409, {"error": "no attempt"}
        if self._expired(a):
            return 200, {"result": "expired"}
        if a.state != "active":
            return 200, {"result": "CORRECT" if a.state == "solved" else a.state}
        by_aid = {aid: qid for qid, aid in a.answer_ids.items()}
        qs = {q["id"]: q for q in a.variant.questions}
        for aid, value in answers.items():
            qid = by_aid.get(aid)
            if qid is None or not isinstance(value, str):
                return 400, {"error": f"bad answer id or non-string value for {aid!r}"}
            want = a.variant.truth[qid]
            got, norm = value.strip(), qs[qid].get("normalization")
            if (got.lower() != want.lower()) if norm == "case_insensitive" else got != want:
                a.state = "failed"
                return 200, {"result": "incorrect"}
            a.accepted.add(qid)
        remaining = len(a.answer_ids) - len(a.accepted)
        if remaining:
            return 200, {"result": "accepted", "remaining": remaining}
        a.state = "solved"
        a.solved_at = time.monotonic()
        return 200, {"result": "CORRECT"}

    # ---- HTTP -------------------------------------------------------------
    def start_server(self) -> str:
        gm = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True  # else 40ms delayed-ACK stalls per reply

            def log_message(self, *a):
                pass

            def _send(self, code: int, payload: bytes, ctype: str, extra: dict | None = None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def _auth(self) -> bool:
                if self.headers.get("Authorization") != f"Bearer {gm.token}":
                    self._send(401, b'{"error":"unauthorized"}', "application/json")
                    return False
                return True

            def do_HEAD(self):
                self._send(200, b"", "text/plain")

            def _routed(self) -> bool:
                path = urlsplit(self.path).path.rstrip("/")
                if gm.proxy_prefix and gm.proxy_passthrough and path.startswith(gm.proxy_prefix + "/artifact/"):
                    return True
                if path != gm.proxy_prefix and not (path.startswith("/artifact/") and not gm.proxy_prefix):
                    self._send(404, b'{"error":"not found"}', "application/json")
                    return False
                return True

            def _artifact(self, attempt_id: str | None = None, index: int = 0):
                with gm.lock:
                    a = gm.attempt
                if a is None or (attempt_id and attempt_id != a.id):
                    return self._send(404 if attempt_id else 409, b'{"error":"no such attempt"}', "application/json")
                files = a.variant.deliveries or [a.variant.zip_bytes]
                if not 0 <= index < len(files):
                    return self._send(404, b'{"error":"no such delivery"}', "application/json")
                data = files[index]
                return self._send(200, data, "application/zip",
                                  {"Content-Disposition": f'attachment; filename="{ZIP_NAME}"'})

            def _by_delivery(self, index: int):
                with gm.lock:
                    a = gm.attempt
                n = len(a.variant.deliveries) if a and a.variant.deliveries else 1
                return self._artifact(None, n - 1 - index if gm.reverse_deliveries else index)

            def do_GET(self):
                if not self._auth() or not self._routed():
                    return
                path = urlsplit(self.path).path
                if gm.proxy_prefix and path.startswith(gm.proxy_prefix + "/"):
                    path = path[len(gm.proxy_prefix):]
                if path.startswith("/artifact/"):
                    parts = path.split("/")  # ['', 'artifact', id] or ['', 'artifact', id, n (1-based)]
                    return self._artifact(parts[2], int(parts[3]) - 1 if len(parts) > 3 else 0)
                q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
                if q.get("op") == "artifact":
                    return self._by_delivery(int(q.get("delivery") or 0))
                code, data = gm.handle("GET", q, {})
                self._send(code, json.dumps(data).encode(), "application/json")

            def do_POST(self):
                if not self._auth() or not self._routed():
                    return
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._send(400, b'{"error":"bad json"}', "application/json")
                q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
                code, data = gm.handle("POST", q, body)
                self._send(code, json.dumps(data).encode(), "application/json")

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # clients that time out on purpose (tests) leave broken pipes behind

        self.server = Server(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_address[1]}" + (self.proxy_prefix or "/")

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
