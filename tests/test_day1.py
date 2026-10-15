"""What day 1 needed: WinZip AES evidence, Mastery reply shapes, flag-only
orientation challenges, alternative spellings, and the advisor fallback chain.

Run with:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import random
import struct
import tempfile
import threading
import unittest
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from hunt import web
from hunt.archive import Archive
from hunt.forensics import winzip_aes
from hunt.forensics.artifacts import ArtifactSet
from hunt.gate import decide
from hunt.gm import GameMaster
from hunt.learn import advisor as advisor_mod
from hunt.learn.advisor import (AdvisorError, AdvisorRefusal, Advisor, ChainAdvisor, KimiAdvisor, ScriptedAdvisor,
                                _cli_refused)
from hunt.learn.grind import GrindOptions, archived_refusals, grind, untried, use_alternatives
from hunt.learn.library import Library
from hunt.learn.trial import run_trial
from hunt.model import Attempt
from hunt.runner import Outcome
from hunt.solvers import Answer, Solution, solve
from hunt.solvers.file_identity import file_name
from hunt.testing.fake_gm import Base64Challenge, FakeGM

from test_learn import BASED, GOOD, _arts, _attempt, _block


# ---- WinZip AES --------------------------------------------------------------------
def aes_zip(files: dict[str, bytes], password: bytes, strength: int = 3) -> bytes:
    """A WinZip AE-2 archive (deflate inside), built the way 7-Zip/WinZip write one."""
    klen = {1: 16, 2: 24, 3: 32}[strength]
    out = io.BytesIO()
    central = []
    for name, data in files.items():
        salt = os.urandom(klen // 2)
        keys = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * klen + 2)
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        deflated = c.compress(data) + c.flush()
        cipher = winzip_aes.aes_ctr_le(keys[:klen], deflated)
        mac = hmac.new(keys[klen:2 * klen], cipher, hashlib.sha1).digest()[:10]
        blob = salt + keys[-2:] + cipher + mac
        extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", strength, 8)
        fname = name.encode()
        offset = out.tell()
        out.write(struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 51, 1, 99, 0, 0, 0, len(blob), len(data),
                              len(fname), len(extra)) + fname + extra + blob)
        central.append(struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 51, 51, 1, 99, 0, 0, 0, len(blob),
                                   len(data), len(fname), len(extra), 0, 0, 0, 0, offset) + fname + extra)
    cd_start = out.tell()
    for c in central:
        out.write(c)
    out.write(struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(central), len(central),
                          out.tell() - cd_start, cd_start, 0))
    return out.getvalue()


class WinZipAes(unittest.TestCase):
    def test_fips197_vectors(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        for key, ct in (("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
                        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
                        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                         "8ea2b7ca516745bfeafc49904b496089")):
            self.assertEqual(winzip_aes._encrypt_block(winzip_aes._expand_key(bytes.fromhex(key)), pt).hex(), ct)

    def test_evidence_zip_opens_with_the_usual_password(self):
        script = b"# specimen\n$u = 'https://cdn.example.invalid/a.bin'\n" * 20
        arts = ArtifactSet([("evidence.zip", aes_zip({"resource-sample.ps1": script}, b"infected"))])
        m = arts.resolve(["evidence.zip", "resource-sample.ps1"])
        self.assertEqual(m.data, script)
        self.assertIn("decrypted (WinZip AES) with password 'infected'", m.notes)

    def test_unknown_password_is_unreadable_not_garbage(self):
        arts = ArtifactSet([("e.zip", aes_zip({"a.txt": b"secret text"}, b"not-a-known-one", strength=1))])
        m = arts.resolve(["e.zip", "a.txt"])
        with self.assertRaises(Exception):
            m.data
        self.assertTrue(any("no known password" in n for n in m.notes))


# ---- reply shapes -------------------------------------------------------------------------
MASTERY = {
    "mode": "mastery", "deadline": "2099-01-01T00:00:30Z", "answer_ids": ["set1.answer", "set2.answer"],
    "downloads": ["/?op=download&capability=aa", "/?op=download&capability=bb"],
    "artifacts": [{"download": "/?op=download&capability=aa", "sha256": "1" * 64, "filename": "m_01.apk"},
                  {"download": "/?op=download&capability=bb", "sha256": "2" * 64, "filename": "m_02.apk"}],
    "questions": [{"id": "set1.answer", "question": "q", "artifact": "delivery 1: m_01.apk"},
                  {"id": "set2.answer", "question": "q", "artifact": "delivery 2: m_02.apk"}],
}


class ReplyShapes(unittest.TestCase):
    def test_downloads_and_artifacts_describe_the_same_deliveries(self):
        a = Attempt.from_response("x/mastery", MASTERY)
        self.assertEqual(a.downloads, ["/?op=download&capability=aa", "/?op=download&capability=bb"])
        self.assertEqual(a.download_sha256, ["1" * 64, "2" * 64])

    def test_different_listings_still_add_up(self):
        d = dict(MASTERY, artifacts=[{"download": "/?op=download&capability=cc", "sha256": "3" * 64}])
        self.assertEqual(len(Attempt.from_response("x/mastery", d).downloads), 3)

    def test_issued_flag_is_answered(self):
        a = Attempt.from_response("welcome-robots", {"prompt": "Ask your AI teammate...", "result": "issued",
                                                     "issued_flag": "00052436d82f0cb06d0d282a6f29dfc6",
                                                     "answer_ids": ["flag"]})
        self.assertTrue(a.flag_only)
        sol = solve(a, ArtifactSet([]))
        dec = decide(a, sol)
        self.assertEqual(dec.submit, {"flag": "00052436d82f0cb06d0d282a6f29dfc6"})

    def test_flag_hidden_in_a_linked_page(self):
        a = Attempt.from_response("read-the-rules", {"prompt": "Read the rules at https://x.test/rules",
                                                     "answer_ids": ["flag"], "downloads": [], "artifacts": []})
        self.assertTrue(a.flag_only)
        arts = ArtifactSet([("page1.html", b"<html></html>"),
                            ("page1-assets/c.js", b'x="<span class=\\"hidden\\">flag{0123abcd}</span>"')])
        ans = solve(a, arts).answers["flag"]
        self.assertEqual((ans.value, ans.alternatives), ("flag{0123abcd}", ["0123abcd"]))
        self.assertGreaterEqual(ans.confidence, 0.9)

    def test_ordinary_questions_are_never_flag_only(self):
        self.assertFalse(_attempt().flag_only)
        self.assertFalse(Attempt.from_response("x", {"answer_ids": ["a"], "download": "/a"}).flag_only)

    def test_filename_indicator_inside_a_script_is_not_the_files_name(self):
        a = Attempt.from_response("script-analysis-day-01-x", {"answer_ids": ["collection-file"], "questions": [
            {"id": "collection-file", "question": "What is the first exact filename indicator in the collection "
             "sample?", "artifact": "evidence.zip -> collection-sample.ps1", "answer_format": {"kind": "exact_text"}}]})
        from hunt.solvers import Context
        self.assertIsNone(file_name(a.questions[0], Context(a, ArtifactSet([("evidence.zip", b"PK")]))))

    def test_mastery_sets_are_answered_by_the_time_trial_handler(self):
        from hunt import solvers

        # A Time Trial handler: knows only the plain id and assumes the one download.
        @solvers.handler(lanes=("test-mastery",))
        def first_line(q, ctx):
            if q.id != "first-line":
                return None
            return Answer(ctx.artifacts.tops[0].data.decode().splitlines()[0], 0.95, "first line of the download")

        def q(n, label=""):
            return {"id": f"set{n}.first-line", "set": n, "question": "What is the first line?",
                    "artifact": f"{label}note.txt", "answer_format": {"kind": "exact_text"}}

        try:
            a = Attempt.from_response("test-mastery-day-01/mastery", {
                "lane": "test-mastery", "questions": [q(1), q(2, "delivery 2: ")],
                "answer_ids": ["set1.first-line", "set2.first-line"]})
            sol = solve(a, ArtifactSet([("note.txt", b"alpha\n"), ("note.txt", b"beta\n")]))
            self.assertEqual(sol.answers["set1.first-line"].value, "alpha")
            self.assertEqual(sol.answers["set2.first-line"].value, "beta")
            self.assertIn("set 2, its own download", sol.answers["set2.first-line"].evidence)
            self.assertEqual(sol.unresolved, {})
            # one download for two sets: no per-set view, so nothing is guessed
            one = solve(a, ArtifactSet([("note.txt", b"alpha\n")]))
            self.assertEqual(one.answers, {})
        finally:
            solvers._HANDLERS[:] = [r for r in solvers._HANDLERS if r.fn is not first_line]

    def test_short_lane_names_still_scope(self):
        from hunt.solvers import _Reg
        reg = _Reg(100, "x", lambda q, c: None, ("binary",), ())
        self.assertTrue(reg.applies(Attempt.from_response("binary-reverse-engineering-day-01-c", {})))
        self.assertFalse(reg.applies(Attempt.from_response("warmups-day-01", {})))


# ---- linked pages ------------------------------------------------------------------------------
class _Site(BaseHTTPRequestHandler):
    pages = {
        "/rules": b'<html><script src="/_next/static/app.js"></script><script id="__NEXT_DATA__" '
                  b'type="application/json">{"buildId":"b1","page":"/student/rules"}</script></html>',
        "/_next/static/app.js": b"console.log(1)",
        "/_next/static/b1/_buildManifest.js": b'self.__BUILD_MANIFEST={"/student/rules":["static/chunks/p.js"]}',
        "/_next/static/chunks/p.js": b'__turbopack_load_page_chunks__("/student/rules",["static/chunks/c.js"])',
        "/_next/static/chunks/c.js": b'e("flag{feedfacecafe}")',
    }
    seen_auth: list = []

    def do_GET(self):  # noqa: N802
        _Site.seen_auth.append(self.headers.get("Authorization"))
        body = self.pages.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        self.wfile.write(body or b"")

    def log_message(self, *a):
        pass


class LinkedPages(unittest.TestCase):
    def test_page_and_its_next_chunks_are_fetched_without_credentials(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            got = web.fetch_targets(f"Read the rules at {base}/rules. Thanks!", {"gm.test"})
        finally:
            srv.shutdown()
        names = [d.filename for d in got]
        self.assertEqual(names[0], "page1.html")
        self.assertIn("page1-assets/c.js", names)
        self.assertTrue(any(b"flag{feedfacecafe}" in d.data for d in got))
        self.assertEqual(set(_Site.seen_auth), {None})

    def test_the_game_masters_host_is_never_fetched(self):
        self.assertEqual(web.prompt_urls("see https://gm.test/x and https://ok.test/y.", {"gm.test"}),
                         ["https://ok.test/y"])


# ---- alternatives --------------------------------------------------------------------------
ALT = GOOD.replace('return answer(plain, f"Base64-decoded {m.path}", 0.95, subject=m)',
                   'return answer(plain[::-1], f"Base64-decoded {m.path}", 0.95, subject=m, alternatives=[plain])')


class Alternatives(unittest.TestCase):
    def test_untried_skips_refused_and_malformed(self):
        q = _attempt().questions[0]
        a = Answer("x", 0.95, "e", alternatives=["x", " y", "", "z"])
        self.assertEqual(untried(a, q, {"x"}), ["z"])  # " y" and "" would fail the gate

    def test_refused_value_is_swapped_or_held(self):
        a = _attempt()
        sol = Solution({"decoded-message": Answer("wrong", 0.95, "e", alternatives=["right"])}, {}, [])
        o = Outcome("dry-run", attempt=a, solution=sol, decision=decide(a, sol))
        self.assertEqual(use_alternatives(o, {"decoded-message": {"wrong"}}, 0.9, False),
                         ["decoded-message: 'wrong' -> 'right'"])
        self.assertEqual(o.decision.submit, {"decoded-message": "right"})
        use_alternatives(o, {"decoded-message": {"wrong", "right"}}, 0.9, False)
        self.assertIn("already refused", o.decision.held["decoded-message"])
        self.assertEqual(o.decision.submit, {})

    def test_trial_passes_a_refused_value_that_brings_an_untried_alternative(self):
        with tempfile.TemporaryDirectory() as d:
            r = run_trial(Library(d), "base64_note", ALT, _attempt(), _arts(),
                          refused={"decoded-message": {"}cba{FTCssertnuH"}})
            self.assertTrue(r.ok, r.feedback())

    def test_refusals_are_remembered_across_runs(self):
        with tempfile.TemporaryDirectory() as d:
            archive = Archive(d)
            a = Attempt.from_response(BASED, dict(_attempt().raw, attempt_id="att-1"))
            run = archive.new_run(BASED, "regular")
            run.write_json("start.json", a.raw)
            run.write_json("submit.json", {"sent": {}, "reply": {}, "steps": [
                {"sent": {"decoded-message": "nope"}, "reply": {"result": "incorrect"}}]})
            self.assertEqual(archived_refusals(archive, a), {"decoded-message": {"nope"}})
            other = Attempt.from_response(BASED, dict(_attempt().raw, attempt_id="att-2"))
            self.assertEqual(archived_refusals(archive, other), {})

    def test_grind_tries_the_alternative_before_asking_the_advisor_again(self):
        fake = FakeGM(mode="trio", seed=3)
        based = Base64Challenge(BASED, rng=random.Random(5), with_length=True)
        fake.extras[BASED] = based
        url = fake.start_server()
        log: list[str] = []
        try:
            with tempfile.TemporaryDirectory() as d:
                gm = GameMaster(base_url=url, token=fake.token)
                adv = ScriptedAdvisor([_block(ALT)])
                rows = [r for r in gm.list() if r["id"] == BASED]
                res = grind(gm, Archive(Path(d) / "runs"), Library(Path(d) / "learned"), adv, rows,
                            GrindOptions(), log=log.append)
                self.assertEqual(res[0].status, "scored", log)
                self.assertEqual(len(adv.seen), 1)  # one module; the refusal was fixed without the advisor
                self.assertTrue(any("trying an alternative answer" in line for line in log), log)
                transcripts = list((Path(d) / "runs").rglob("advisor/*"))
                self.assertTrue(any(p.name.endswith("-ask.md") for p in transcripts))
                self.assertTrue(any("-reply-" in p.name for p in transcripts))
        finally:
            fake.stop()


# ---- advisor chain -----------------------------------------------------------------------------
class _Refuses(Advisor):
    name = "claude"

    def __init__(self):
        self.calls = 0

    def reply(self, convo, message):
        self.calls += 1
        raise AdvisorRefusal("claude-opus-5-5 and claude-opus-4-8 declined this packet (category: cyber)")


class _Broken(Advisor):
    name = "claude"

    def reply(self, convo, message):
        raise AdvisorError("cannot reach the Claude API")


class AdvisorChain(unittest.TestCase):
    def test_refusal_hands_the_conversation_on_and_it_stays_there(self):
        first, second = _Refuses(), ScriptedAdvisor(["one", "two"])
        chain = ChainAdvisor([first, second])
        notes: list[str] = []
        convo = chain.conversation("x")
        convo.log = notes.append
        self.assertEqual(convo.ask("packet"), "one")
        self.assertEqual(convo.ask("feedback"), "two")
        self.assertEqual(first.calls, 1)
        self.assertTrue(any("handing this conversation" in n for n in notes))

    def test_other_errors_do_not_escalate(self):
        chain = ChainAdvisor([_Broken(), ScriptedAdvisor(["never"])])
        with self.assertRaises(AdvisorError):
            chain.conversation("x").ask("packet")

    def test_cli_refusal_detection(self):
        self.assertTrue(_cli_refused({"stop_reason": "refusal", "result": ""}))
        self.assertTrue(_cli_refused({"is_error": True, "result": "API Error: Claude Code is unable to respond to "
                                                                  "this request, which appears to violate our Usage Policy"}))
        self.assertFalse(_cli_refused({"result": "```python\n# mentions the usage policy\n```"}))

    def test_cli_falls_back_to_the_next_model_on_refusal(self):
        replies = iter([json.dumps({"is_error": True, "result": "API Error: ... violate our Usage Policy"}),
                        json.dumps({"result": "```python\nx\n```", "session_id": "s2"})])
        seen_models = []

        def run(cmd, **kw):
            seen_models.append(cmd[cmd.index("--model") + 1])
            return mock.Mock(stdout=next(replies).encode(), stderr=b"", returncode=0)

        with mock.patch.object(advisor_mod.shutil, "which", return_value="claude"), \
                mock.patch.object(advisor_mod.subprocess, "run", side_effect=run):
            cli = advisor_mod.CliAdvisor()
            convo = cli.conversation("x")
            self.assertIn("```python", convo.ask("packet"))
            cli.close(convo)
        self.assertEqual(seen_models, ["claude-opus-5-5", "claude-opus-4-8"])
        self.assertEqual(convo.served_by, "claude-opus-4-8")

    def test_kimi_request_shape_and_refusal(self):
        posted = []

        def post(url, **kw):
            posted.append((url, kw))
            return mock.Mock(status_code=200, text="", json=lambda: {
                "model": "kimi-k3", "choices": [{"message": {"content": "```python\nx\n```"}, "finish_reason": "stop"}]})

        with mock.patch.dict(os.environ, {"MOONSHOT_API_KEY": "mk"}):
            kimi = KimiAdvisor()
        kimi.session.post = post
        convo = kimi.conversation("x")
        convo.ask("packet")
        url, kw = posted[0]
        self.assertTrue(url.endswith("/chat/completions"))
        self.assertEqual(kw["json"]["model"], "kimi-k3")
        self.assertEqual(kw["json"]["messages"][0]["role"], "system")
        self.assertEqual(kw["headers"], {"Authorization": "Bearer mk"})
        kimi.session.post = lambda url, **kw: mock.Mock(status_code=200, text="", json=lambda: {
            "choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}]})
        with self.assertRaises(AdvisorRefusal):
            convo.ask("again")

    def test_pick_adds_kimi_only_when_configured(self):
        with mock.patch.object(advisor_mod, "_api_ready", return_value=False), \
                mock.patch.object(advisor_mod.shutil, "which", return_value="claude"):
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MOONSHOT_API_KEY", None)
                os.environ.pop("KIMI_API_KEY", None)
                adv, how = advisor_mod.pick("auto")
                self.assertIsInstance(adv, advisor_mod.CliAdvisor)
                self.assertIn("claude-opus-5-5 -> claude-opus-4-8", how)
            with mock.patch.dict(os.environ, {"MOONSHOT_API_KEY": "mk"}):
                adv, how = advisor_mod.pick("auto")
                self.assertIsInstance(adv, ChainAdvisor)
                self.assertIn("Kimi (kimi-k3", how)
                adv, _ = advisor_mod.pick("auto", kimi="off")
                self.assertIsInstance(adv, advisor_mod.CliAdvisor)


if __name__ == "__main__":
    unittest.main()
