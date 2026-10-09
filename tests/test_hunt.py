"""Run with:  python -m unittest discover -s tests -v"""
from __future__ import annotations

import hashlib
import io
import json
import os
import random
import tarfile
import tempfile
import time
import unittest
import warnings
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from hunt import cli, config
from hunt.forensics import artifacts, identity
from hunt.archive import Archive, replay
from hunt.forensics.artifacts import ArtifactSet
from hunt.forensics.identity import inventory
from hunt.gate import decide
from hunt.gm import GameMaster, GMError
from hunt.model import Attempt
from hunt.runner import play
from hunt.solvers import solve
from hunt.testing import fake_gm
from hunt.testing.fake_gm import CID, FakeGM

FIX = Path(__file__).parent / "fixtures"

# Cross-checked with coreutils md5sum/sha1sum/sha256sum on the extracted file.
EXPECTED = {
    "evidence-note-filename": "evidence-note.txt",
    "evidence-note-size-bytes": "240",
    "evidence-note-md5": "6b5074cd2b741ee5d0f0f9cae5eba7d5",
    "evidence-note-sha1": "11f594f647b3c81bce2527c0d9f6c72a60f492d9",
    "evidence-note-sha256": "a6d2d239a6ba996a16ea585c9dd5874b9a0fcdb1e16e3f10457d5ea79e944dc6",
}


def _zip(files: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files:
            zf.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), data)
    return buf.getvalue()


def _fixture_attempt() -> Attempt:
    data = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))
    return Attempt.from_response(CID, data)


class SingleSolveFixture(unittest.TestCase):
    def test_real_artifact_and_questions(self):
        attempt = _fixture_attempt()
        arts = ArtifactSet([("", (FIX / "you_must_be_this_hash_to_ride.zip").read_bytes())])
        sol = solve(attempt, arts)
        dec = decide(attempt, sol)
        self.assertEqual(dec.held, {})
        self.assertEqual(dec.submit, EXPECTED)
        self.assertTrue(all(isinstance(v, str) for v in dec.submit.values()))

    def test_solved_reply_has_no_download(self):
        data = json.loads((FIX / "hash_to_ride_solved_reply.json").read_text(encoding="utf-8"))
        a = Attempt.from_response(CID, data)
        self.assertEqual(a.downloads, [])
        self.assertEqual(a.result, "CORRECT")
        self.assertFalse(a.timed)


class Solver(unittest.TestCase):
    def _attempt(self, questions, answer_ids=None):
        return Attempt.from_response(CID, {"questions": questions,
                                           "answer_ids": answer_ids or [q["id"] for q in questions]})

    def test_named_member_in_subfolder_among_decoys(self):
        rng = random.Random(5)
        for _ in range(20):
            v = fake_gm.make_variant(rng, "trio")
            a = self._attempt(v.questions)
            dec = decide(a, solve(a, ArtifactSet([("x.zip", v.zip_bytes)])))
            self.assertEqual(dec.held, {})
            self.assertEqual(dec.submit, v.truth)

    def test_ambiguous_first_note_is_held_not_guessed(self):
        z = _zip([("evidence-note-b.txt", b"b\n"), ("evidence-note-a.txt", b"a\n")])
        q = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"][0]
        a = self._attempt([q])
        dec = decide(a, solve(a, ArtifactSet([("x.zip", z)])))
        self.assertIn("evidence-note-filename", dec.held)
        self.assertEqual(dec.tentative, {"evidence-note-filename": "evidence-note-b.txt"})

    def test_missing_named_member_is_held(self):
        qs = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
        z = _zip([("other.txt", b"x"), ("more.txt", b"y")])
        a = self._attempt(qs)
        dec = decide(a, solve(a, ArtifactSet([("x.zip", z)])))
        self.assertEqual(dec.submit, {})
        self.assertEqual(set(dec.held), {q["id"] for q in qs})

    def test_positional_answer_ids_are_held_unless_trusted(self):
        qs = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
        opaque = [f"a{i}" for i in range(len(qs))]
        a = self._attempt(qs, opaque)
        sol = solve(a, ArtifactSet([("", (FIX / "you_must_be_this_hash_to_ride.zip").read_bytes())]))
        held = decide(a, sol)
        self.assertEqual(held.submit, {})
        self.assertEqual(held.tentative, {f"a{i}": EXPECTED[q["id"]] for i, q in enumerate(qs)})
        trusted = decide(a, sol, trust_guessed_ids=True)
        self.assertEqual(trusted.submit, {f"a{i}": EXPECTED[q["id"]] for i, q in enumerate(qs)})
        self.assertTrue(any("by position" in w for w in trusted.warnings))

    def test_dict_answer_ids_map_by_key_not_position(self):
        qs = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
        ids = {q["id"]: f"aid-{q['id']}" for q in sorted(qs, key=lambda q: q["id"])}
        a = Attempt.from_response(CID, {"questions": qs, "answer_ids": ids})
        dec = decide(a, solve(a, ArtifactSet([("", (FIX / "you_must_be_this_hash_to_ride.zip").read_bytes())])))
        self.assertEqual(dec.submit, {f"aid-{k}": v for k, v in EXPECTED.items()})

    def test_unknown_question_is_unresolved(self):
        a = self._attempt([{"id": "which-label-lies", "question": "Which file's extension lies?",
                            "artifact": "x.zip", "answer_format": {"kind": "exact_text", "syntax": "a filename"}}])
        dec = decide(a, solve(a, ArtifactSet([("x.zip", _zip([("a.txt", b"x")]))])))
        self.assertIn("which-label-lies", dec.held)

    def test_container_itself(self):
        z = _zip([("a.txt", b"x"), ("b.txt", b"y")])
        a = self._attempt([{"id": "zip-size", "question": "What is the size of the downloaded archive in bytes?",
                            "artifact": "x.zip", "answer_format": {"kind": "integer", "syntax": "base-10 integer"}}])
        sol = solve(a, ArtifactSet([("x.zip", z)]))
        self.assertEqual(sol.answers["zip-size"].value, str(len(z)))


class NotIdentityQuestions(unittest.TestCase):
    """Review findings: loose triggers must not answer questions that only
    look like identity questions."""

    ZIP = _zip([("evidence-note.txt", b"Endpoint: WS-01\nAnalyst: a-1\n"), ("scan.png", b"text, not png\n"),
                ("SHA256SUMS", f"{'0' * 64}  evidence-note.txt\n".encode())])

    def _solve(self, questions):
        a = Attempt.from_response(CID, {"questions": questions, "answer_ids": [q["id"] for q in questions]})
        return decide(a, solve(a, ArtifactSet([("e.zip", self.ZIP)])))

    def _q(self, qid, text, artifact="e.zip", kind="exact_text", syntax="text"):
        return {"id": qid, "question": text, "artifact": artifact, "answer_format": {"kind": kind, "syntax": syntax}}

    def test_names_that_are_not_filenames(self):
        dec = self._solve([self._q("host", "What is the hostname of the endpoint?", "e.zip -> evidence-note.txt"),
                           self._q("who", "What is the name of the analyst?", "e.zip -> evidence-note.txt")])
        self.assertEqual(dec.submit, {})

    def test_length_that_is_not_file_size(self):
        dec = self._solve([self._q("len", "What is the length of the collected sequence number?",
                                   "e.zip -> evidence-note.txt", "integer", "base-10 integer")])
        self.assertEqual(dec.submit, {})

    def test_claimed_values_are_not_computed_values(self):
        hexfmt = "exact 64-character hexadecimal SHA-256 value"
        dec = self._solve([
            self._q("listed", "What SHA-256 does SHA256SUMS list for the note?", "e.zip -> SHA256SUMS", "pattern", hexfmt),
            self._q("crc", "What CRC-32 does the ZIP central directory store for the note?",
                    "e.zip -> evidence-note.txt", "pattern", "exact 8-character hexadecimal CRC-32"),
            self._q("liar", "What is the SHA-256 of the file whose extension does not match its contents?",
                    "e.zip", "pattern", hexfmt)])
        self.assertEqual(dec.submit, {})

    def test_text_naming_a_member_beats_siblings(self):
        hexfmt = "exact 64-character hexadecimal SHA-256 value"
        qs = [self._q("note-sha256", "What is its SHA-256 digest?", "e.zip -> evidence-note.txt", "pattern", hexfmt),
              self._q("scan-sha256", "What is the SHA-256 digest of scan.png?", "e.zip", "pattern", hexfmt),
              self._q("zip-sha256", "What is the SHA-256 of the downloaded evidence ZIP?", "e.zip", "pattern", hexfmt)]
        a = Attempt.from_response(CID, {"questions": qs, "answer_ids": [q["id"] for q in qs]})
        sol = solve(a, ArtifactSet([("e.zip", self.ZIP)]))
        dec = decide(a, sol)
        self.assertEqual(dec.submit["scan-sha256"], hashlib.sha256(b"text, not png\n").hexdigest())
        self.assertIn("zip-sha256", dec.held)  # container guess stays below the gate
        self.assertEqual(sol.answers["zip-sha256"].value, hashlib.sha256(self.ZIP).hexdigest())

    def test_syntax_negations(self):
        z = _zip([("case/evidence-note.txt", b"x")])
        def name_for(syntax):
            q = self._q("evidence-note-filename", "What is the exact filename of the first evidence note?",
                        "e.zip", "exact_text", syntax)
            a = Attempt.from_response(CID, {"questions": [q], "answer_ids": [q["id"]]})
            return solve(a, ArtifactSet([("e.zip", z)])).answers[q["id"]].value
        self.assertEqual(name_for("exact base filename including its extension, without any directory path"),
                         "evidence-note.txt")
        self.assertEqual(name_for("the file name only (not the full path), including its extension"),
                         "evidence-note.txt")
        self.assertEqual(name_for("the full path inside the archive"), "case/evidence-note.txt")
        self.assertEqual(name_for("filename without the extension"), "evidence-note")
        q = self._q("evidence-note-sha256", "What is its SHA-256 digest?", "e.zip -> case/evidence-note.txt",
                    "pattern", "exact 64-character lowercase hexadecimal SHA-256 value, not uppercase")
        a = Attempt.from_response(CID, {"questions": [q], "answer_ids": [q["id"]]})
        self.assertEqual(solve(a, ArtifactSet([("e.zip", z)])).answers[q["id"]].value, hashlib.sha256(b"x").hexdigest())


class Forensics(unittest.TestCase):
    def test_label_checks(self):
        note = b"hello\n"
        bad_manifest = f"{'0' * 64}  note.txt\n".encode()
        z = _zip([("note.txt", note), ("SHA256SUMS", bad_manifest), ("photo.jpg", b"%PDF-1.7 fake")])
        inv = inventory(ArtifactSet([("x.zip", z)]))
        lies = {(c["source"].split(" -> ")[-1], c["attribute"]) for c in inv["label_checks"] if c["verdict"] == "LIES"}
        self.assertIn(("SHA256SUMS", "sha256"), lies)
        self.assertIn(("filename extension", "type"), lies)

    def test_tampered_zip_crc_is_read_and_flagged(self):
        z = bytearray(_zip([("a.txt", b"payload")]))
        crc = zipfile.ZipFile(io.BytesIO(bytes(z))).infolist()[0].CRC.to_bytes(4, "little")
        z = bytes(z).replace(crc, b"\x00\x00\x00\x00")
        arts = ArtifactSet([("x.zip", z)])
        (member,) = arts.children(arts.tops[0])
        self.assertEqual(member.data, b"payload")
        self.assertTrue(any("CRC" in n for n in member.notes))

    def test_duplicate_member_names_are_not_guessed(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # zipfile warns about the duplicate we are building
            z = _zip([("evidence-note.txt", b"decoy\n"), ("evidence-note.txt", b"real note bytes\n")])
        q = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
        a = Attempt.from_response(CID, {"questions": q, "answer_ids": [x["id"] for x in q]})
        dec = decide(a, solve(a, ArtifactSet([("x.zip", z)])))
        self.assertEqual(dec.submit, {})

    def test_corrupt_decoy_does_not_block_the_note(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(zipfile.ZipInfo("decoy.bin", (2026, 1, 1, 0, 0, 0)), os.urandom(4096) * 4,
                        zipfile.ZIP_DEFLATED)
            zf.writestr(zipfile.ZipInfo("evidence-note.txt", (2026, 1, 1, 0, 0, 0)), b"note\n")
        raw = bytearray(buf.getvalue())
        info = zipfile.ZipFile(io.BytesIO(bytes(raw))).getinfo("decoy.bin")
        start = info.header_offset + 30 + len(info.filename) + 20
        raw[start:start + 64] = b"\xff" * 64
        q = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
        a = Attempt.from_response(CID, {"questions": q, "answer_ids": [x["id"] for x in q]})
        arts = ArtifactSet([("x.zip", bytes(raw))])
        dec = decide(a, solve(a, arts))
        self.assertEqual(dec.held, {})
        self.assertEqual(dec.submit["evidence-note-sha256"], hashlib.sha256(b"note\n").hexdigest())
        inventory(arts)  # must not raise on the corrupt member

    def test_wrong_zipcrypto_password_never_yields_data(self):
        info = zipfile.ZipInfo("s.bin")
        info.flag_bits |= 0x1

        class FakeZip:  # the 1-in-256 case: a wrong password passes the check, then CRC fails
            def read(self, info, pwd=None):
                if pwd is None:
                    raise RuntimeError("password required")
                raise zipfile.BadZipFile("Bad CRC-32 for file 's.bin'")
        notes = []
        self.assertIsNone(artifacts._read_zip_member(FakeZip(), info, notes))
        self.assertTrue(any("no known password" in n for n in notes))

    def test_undecodable_tar_name_is_held(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT, encoding="utf-8",
                          errors="surrogateescape") as tf:
            ti = tarfile.TarInfo("za\udcbf\udcf3.txt")
            ti.size = 4
            tf.addfile(ti, io.BytesIO(b"note"))
        q = {"id": "f", "question": "What is the exact filename of the first note?", "artifact": "t.tar",
             "answer_format": {"kind": "exact_text", "syntax": "exact base filename"}}
        a = Attempt.from_response(CID, {"questions": [q], "answer_ids": ["f"]})
        dec = decide(a, solve(a, ArtifactSet([("t.tar", buf.getvalue())])))
        self.assertIn("f", dec.held)

    def test_whitespace_heavy_text_is_fast(self):
        member = ArtifactSet([("w.txt", ((" \t" * 3000 + "x\n") * 50).encode())]).tops[0]
        t = time.perf_counter()
        identity.claims_in(member)
        self.assertLess(time.perf_counter() - t, 0.5)

    def test_zip_bomb_budget(self):
        z = _zip([("big.bin", b"\0" * 2_000_000)])
        with mock.patch("hunt.forensics.artifacts.MAX_TOTAL_BYTES", 1_000_000):
            arts = ArtifactSet([("x.zip", z)])
            self.assertEqual(arts.children(arts.tops[0]), [])


class Token(unittest.TestCase):
    def test_trailing_newline_is_stripped_and_garbage_rejected(self):
        with mock.patch.dict(os.environ, {"HUNTRESS_GM_TOKEN": "abc123\r\n"}):
            self.assertEqual(config.load_token(), "abc123")
        with mock.patch.dict(os.environ, {"HUNTRESS_GM_TOKEN": "abc 123"}):
            with self.assertRaises(config.ConfigError) as cm:
                config.load_token()
            self.assertNotIn("abc", str(cm.exception))

    def test_powershell_utf16_token_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "tok.txt"
            f.write_bytes("\ufefftok-123\r\n".encode("utf-16-le"))
            with mock.patch.dict(os.environ, {"HUNTRESS_GM_TOKEN": "", "HUNTRESS_GM_TOKEN_FILE": str(f)}):
                self.assertEqual(config.load_token(), "tok-123")

    def test_no_token_over_plain_http_to_remote_hosts(self):
        with redirect_stderr(io.StringIO()):
            gm = GameMaster("http://10.0.0.219/huntress-ctf-proxy", "tok")
        self.assertNotIn("Authorization", gm.s.headers)
        self.assertEqual(GameMaster("https://2026.huntress.ctf.games/", "tok").s.headers["Authorization"],
                         "Bearer tok")


class AgainstFakeGameMaster(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runs = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _fake(self, **kw) -> tuple[FakeGM, str]:
        fake = FakeGM(**kw)
        url = fake.start_server()
        self.addCleanup(fake.stop)
        return fake, url

    def _cli(self, fake, url, *argv) -> tuple[int, str]:
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"HUNTRESS_GM_TOKEN": fake.token}), redirect_stdout(out):
            code = cli.main(["--runs", self.runs, "--url", url, *argv])
        return code, out.getvalue()

    def test_full_cycle_regular_then_race(self):
        fake, url = self._fake(mode="trio", seed=3)
        code, out = self._cli(fake, url, "race", CID)
        self.assertEqual(code, 3, out)  # no proof yet -> refuses before touching the server
        self.assertIsNone(fake.attempt)
        code, out = self._cli(fake, url, "solve", CID)
        self.assertEqual(code, 0, out)  # dry run
        self.assertEqual(fake.attempt.state, "active")
        code, out = self._cli(fake, url, "solve", CID, "--submit", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(fake.attempt.state, "solved")
        code, out = self._cli(fake, url, "solve", CID)  # what crashed solution.py
        self.assertEqual(code, 1)
        self.assertIn("already solved", out)
        code, out = self._cli(fake, url, "race", CID, "--no-prompt")
        self.assertEqual(code, 0, out)
        self.assertTrue(fake.attempt.timed)
        self.assertEqual(fake.attempt.state, "solved")
        code, out = self._cli(fake, url, "replay", CID)
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("PASS"), 2)

    def test_refuses_to_peek_at_timed_by_default_route(self):
        fake, url = self._fake(timed_by_default=True)
        code, out = self._cli(fake, url, "solve", CID)
        self.assertEqual(code, 3, out)
        self.assertIsNone(fake.attempt)

    def test_wrong_artifact_is_not_answered(self):
        fake, url = self._fake(seed=9)
        orig = fake._view
        fake._view = lambda a: {**orig(a), "artifact_sha256": "f" * 64}
        o = play(GameMaster(url, fake.token), Archive(self.runs), CID, timed=False, use_retry=False,
                 submit=True)
        self.assertEqual(o.status, "wrong-artifact")
        self.assertIsNone(o.sent)
        self.assertEqual(fake.attempt.state, "active")

    def test_held_answers_are_not_sent_without_a_human(self):
        # Two notes and no artifact paths: "the first evidence note" is a guess.
        fake, url = self._fake(seed=2, mode="mastery")
        orig = fake._view

        def ambiguous(a):
            v = orig(a)
            v["questions"] = [{**q, "artifact": "metadata-day-01-evidence.zip"} for q in v["questions"]]
            return v
        fake._view = ambiguous
        asked = []
        o = play(GameMaster(url, fake.token), Archive(self.runs), CID, timed=False, use_retry=False,
                 submit=True, prompt=lambda *a: asked.append(1) or "n")
        self.assertEqual(o.status, "held")
        self.assertEqual(asked, [1])
        self.assertIsNone(o.sent)
        self.assertIn("task-1-note-filename", o.decision.held)
        self.assertEqual(fake.attempt.state, "active")

    def test_token_not_sent_to_other_hosts(self):
        fake, url = self._fake()
        gm = GameMaster(url, fake.token)
        gm.start(CID)
        other = url.replace("127.0.0.1", "localhost")
        with self.assertRaises(GMError) as cm:
            gm.artifact(CID, download=other + f"?op=artifact&challenge={CID}")
        self.assertEqual(cm.exception.status, 401)
        self.assertEqual(len(gm.artifact(CID).data) > 0, True)

    def test_network_failure_mid_submit_is_archived_and_flagged(self):
        fake, url = self._fake(seed=6)
        orig = fake._submit

        def slow(answers):
            time.sleep(1.0)
            return orig(answers)
        fake._submit = slow
        o = play(GameMaster(url, fake.token, timeout=0.3), Archive(self.runs), CID, timed=False,
                 use_retry=False, submit=True)
        self.assertEqual(o.status, "submitted")
        self.assertIn("UNKNOWN", o.message)
        (run,) = Archive(self.runs).runs(CID)
        self.assertIsNotNone(run.read_json("submit.json"))
        self.assertIsNotNone(run.read_json("start.json"))

    def test_race_does_not_submit_to_an_untimed_attempt(self):
        fake, url = self._fake(seed=8)
        gm = GameMaster(url, fake.token)
        gm.start(CID)  # an untimed attempt is already open
        o = play(gm, Archive(self.runs), CID, timed=True, use_retry=False, submit=True)
        self.assertEqual(o.status, "not-timed")
        self.assertIsNone(o.sent)
        self.assertEqual(fake.attempt.state, "active")

    def test_solve_retry_is_guarded_on_timed_routes(self):
        fake, url = self._fake(timed_by_default=True)
        code, out = self._cli(fake, url, "solve", CID, "--retry")
        self.assertEqual(code, 3, out)
        self.assertIsNone(fake.attempt)

    def test_replay_catches_a_regression(self):
        fake, url = self._fake(seed=4)
        play(GameMaster(url, fake.token), Archive(self.runs), CID, timed=False, use_retry=False, submit=True)
        (run,) = Archive(self.runs).runs(CID)
        sub = run.read_json("submit.json")
        sub["sent"]["evidence-note-md5"] = "0" * 32
        run.write_json("submit.json", sub)
        rows = replay(Archive(self.runs), CID)
        self.assertFalse(rows[0]["ok"])


if __name__ == "__main__":
    unittest.main()
