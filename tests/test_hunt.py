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
from datetime import datetime, timedelta, timezone
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
            (big,) = arts.children(arts.tops[0])  # still listed, so "which file" logic sees it
            with self.assertRaises(artifacts.UnreadableMember):
                big.data


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

    def test_race_auto_picks_start_or_retry(self):
        # never started: start(run_for_time) opens the timed attempt
        fake, url = self._fake(seed=12)
        code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt")
        self.assertEqual(code, 0, out)
        self.assertEqual((fake.attempt.timed, fake.attempt.state), (True, "solved"))

    def test_race_after_solving_with_another_script(self):
        # solved earlier with solution.py (nothing archived): refusal explains, --force races via retry
        fake2, url2 = self._fake(seed=13)
        gm = GameMaster(url2, fake2.token)
        gm.start(CID)
        gm.submit(CID, fake2.attempt.variant.truth)
        code, out = self._cli(fake2, url2, "race", CID, "--no-prompt")
        self.assertEqual(code, 3, out)
        self.assertIn("--force", out)
        code, out = self._cli(fake2, url2, "race", CID, "--force", "--no-prompt")
        self.assertEqual(code, 0, out)
        self.assertEqual((fake2.attempt.timed, fake2.attempt.state, len(fake2.history)), (True, "solved", 2))

    def test_challenge_name_works_like_the_id(self):
        fake, url = self._fake(seed=15)
        code, out = self._cli(fake, url, "solve", "You Must Be This Hash to Ride")
        self.assertEqual(code, 0, out)
        self.assertIn(CID, out)
        self.assertEqual(fake.attempt.state, "active")  # dry run: started, nothing sent

    def test_ambiguous_or_unknown_name_lists_ids(self):
        rows = [{"id": f"metadata-forensics-day-01-hash-to-ride{sfx}", "name": "\U0001F50E You Must Be This Hash to Ride",
                 "run_for_time_supported": True} for sfx in ("", "-time-trial", "-mastery")]
        gm = mock.Mock(list=mock.Mock(return_value=rows))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli._resolve(gm, "You Must Be This Hash to Ride"), (None, None))
            self.assertEqual(cli._resolve(gm, "hash to ride time trial")[0], rows[1]["id"])
            self.assertEqual(cli._resolve(gm, "nothing like it"), (None, None))
        self.assertEqual(out.getvalue().count("-mastery"), 2)

    def test_finished_attempt_detected_even_with_a_download_link(self):
        from hunt.runner import _finished
        self.assertTrue(_finished(CID, {"result": "CORRECT", "download": "?op=artifact", "questions": LIVE_QS}))
        self.assertTrue(_finished(CID, {"result": "expired", "download": "?op=artifact"}))
        self.assertFalse(_finished(CID, {"download": "?op=artifact", "questions": LIVE_QS}))
        self.assertTrue(_finished(CID, {"download": "/artifact/x", "deadline": "2026-01-01T00:00:00Z"}))
        self.assertFalse(_finished(CID, {"download": "/artifact/x", "deadline": "2999-01-01T00:00:00Z"}))

    def test_archive_keeps_ids_with_slashes(self):
        run = Archive(self.runs).new_run("metadata-forensics-day-01-hash-to-ride/time_trial", "regular")
        run.write_json("start.json", {})
        (again,) = Archive(self.runs).runs("metadata-forensics-day-01-hash-to-ride/time_trial")
        self.assertEqual(again.challenge, "metadata-forensics-day-01-hash-to-ride/time_trial")

    def test_slow_preparation_is_waited_for(self):
        fake, url = self._fake(seed=17, prepare_delay=1.0)
        gm = GameMaster(url, fake.token, timeout=0.3, prepare_timeout=5.0)
        o = play(gm, Archive(self.runs), CID, timed=True, use_retry=None, submit=True)
        self.assertEqual((o.status, (o.reply or {}).get("result")), ("submitted", "CORRECT"))
        self.assertLess(o.timings["on-clock(approx)"], 1.0)  # the preparation wait is not counted
        fake2, url2 = self._fake(seed=18, prepare_delay=1.0)
        gm2 = GameMaster(url2, fake2.token, timeout=0.3, prepare_timeout=0.3)
        o2 = play(gm2, Archive(self.runs), CID, timed=True, use_retry=None, submit=True)
        self.assertEqual(o2.status, "gm-error")
        self.assertIn("hunt status", o2.message)
        self.assertIn("start", o2.message)

    def test_root_relative_links_behind_the_homebase_proxy(self):
        # Live failure: '/artifact/x' resolved outside http://10.0.0.219/huntress-ctf-proxy and 404ed.
        fake, url = self._fake(seed=19, root_links=True, proxy_prefix="/huntress-ctf-proxy")
        self.assertTrue(url.endswith("/huntress-ctf-proxy"))
        o = play(GameMaster(url, fake.token), Archive(self.runs), CID, timed=True, use_retry=None, submit=True)
        self.assertEqual((o.status, (o.reply or {}).get("result")), ("submitted", "CORRECT"))
        self.assertEqual(o.downloads[0].url.split("?")[0], url)  # went straight to op=artifact, no 404 first

    def test_root_relative_links_on_the_direct_host(self):
        fake, url = self._fake(seed=20, root_links=True)
        o = play(GameMaster(url, fake.token), Archive(self.runs), CID, timed=True, use_retry=None, submit=True)
        self.assertEqual((o.reply or {}).get("result"), "CORRECT")
        self.assertIn("/artifact/", o.downloads[0].url)

    def test_dead_download_link_falls_back_to_op_artifact(self):
        fake, url = self._fake(seed=21)
        orig = fake._view
        fake._view = lambda a: {**orig(a), "download": "/artifact/not-this-one"}
        o = play(GameMaster(url, fake.token), Archive(self.runs), CID, timed=True, use_retry=None, submit=True)
        self.assertEqual((o.reply or {}).get("result"), "CORRECT")

    def test_pc_clock_ahead_does_not_abandon_a_live_attempt(self):
        # Review finding: deadlines judged on the local clock made race retry on a live attempt.
        fake, url = self._fake(seed=22, timed_by_default=True, time_limit=60)
        ahead = lambda: datetime.now(timezone.utc) + timedelta(seconds=90)
        with mock.patch("hunt.model.utcnow", ahead), mock.patch("hunt.gm.utcnow", ahead):
            code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt")
        self.assertEqual(code, 0, out)
        self.assertIn("ahead of", out)
        self.assertEqual((len(fake.history), fake.attempt.state), (1, "solved"))

    def test_server_409_keeps_the_live_attempt(self):
        fake, url = self._fake(seed=23, timed_by_default=True, time_limit=60)
        gm = GameMaster(url, fake.token)
        gm.server_now = lambda: datetime.now(timezone.utc) + timedelta(hours=1)  # no usable clock
        o = play(gm, Archive(self.runs), CID, timed=True, use_retry=None, submit=True)
        self.assertEqual((o.reply or {}).get("result"), "CORRECT")
        self.assertEqual(len(fake.history), 1)

    def test_failed_attempt_is_left_for_a_fresh_one(self):
        fake, url = self._fake(seed=24, time_limit=60)
        gm = GameMaster(url, fake.token)
        gm.start(CID, run_for_time=True)
        gm.submit(CID, {"evidence-note-md5": "0" * 32})  # one wrong answer fails the attempt
        self.assertEqual(fake.attempt.state, "failed")
        code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt")
        self.assertEqual(code, 0, out)
        self.assertEqual((len(fake.history), fake.attempt.state), (2, "solved"))

    def test_race_exit_code_reflects_the_verdict(self):
        fake, url = self._fake(seed=25)
        fake._submit = lambda answers: (200, {"result": "incorrect"})
        code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt")
        self.assertEqual(code, 4, out)
        self.assertIn("NOT SOLVED", out)

    def test_race_repeat_runs_fresh_attempts(self):
        fake, url = self._fake(seed=26)
        code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt", "--repeat", "3", "--gap", "0")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("CORRECT  on-clock"), 3)
        self.assertEqual([a.state for a in fake.history], ["solved"] * 3)
        self.assertTrue(all(a.timed for a in fake.history))

    def test_race_repeat_stops_at_the_first_bad_result_and_keeps_a_reserve(self):
        fake, url = self._fake(seed=27)
        orig, calls = fake._submit, []

        def flaky(answers):
            calls.append(1)
            return orig(answers) if len(calls) < 2 else (200, {"result": "incorrect"})
        fake._submit = flaky
        code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt", "--repeat", "5", "--gap", "0")
        self.assertEqual(code, 4, out)
        self.assertEqual(len(fake.history), 2)
        fake2, url2 = self._fake(seed=28)
        fake2.ranked_left = 10
        code, out = self._cli(fake2, url2, "race", CID, "--force", "--no-prompt", "--repeat", "5", "--gap", "0",
                              "--keep", "8")
        self.assertEqual(code, 0, out)
        self.assertEqual(len(fake2.history), 2)
        self.assertIn("keeping 8 in reserve", out)

    def test_ping_reports_round_trip_and_server_time(self):
        fake, url = self._fake(seed=16)
        code, out = self._cli(fake, url, "ping", "--count", "3")
        self.assertEqual(code, 0, out)
        self.assertIn("network round trip", out)
        self.assertIn("warm connection", out)

    def test_race_on_timed_by_default_route(self):
        fake, url = self._fake(seed=14, timed_by_default=True)
        code, out = self._cli(fake, url, "race", CID, "--force", "--no-prompt")
        self.assertEqual(code, 0, out)
        self.assertEqual((fake.attempt.timed, fake.attempt.state), (True, "solved"))

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


LIVE_QS = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
HEX256 = "exact 64-character hexadecimal SHA-256 value"


def _decide(questions, files_or_zip, name="e.zip", **kw):
    a = Attempt.from_response(CID, {"questions": questions, "answer_ids": [q["id"] for q in questions]})
    data = files_or_zip if isinstance(files_or_zip, bytes) else _zip(files_or_zip)
    sol = solve(a, ArtifactSet([(name, data)]))
    return sol, decide(a, sol, **kw)


def _q(qid, text, artifact="e.zip", kind="exact_text", syntax="text"):
    return {"id": qid, "question": text, "artifact": artifact, "answer_format": {"kind": kind, "syntax": syntax}}


class SecondReview(unittest.TestCase):
    """Second adversarial pass: each test is a reproduced claim."""

    NOTE = b"Huntress note\n"

    def test_bare_word_decoy_does_not_count_as_a_mention(self):
        for decoy in ("note", "evidence"):
            _, dec = _decide(LIVE_QS, [(decoy, b"decoy"), ("evidence-note.txt", self.NOTE)])
            self.assertEqual(dec.held, {}, decoy)
            self.assertEqual(dec.submit["evidence-note-filename"], "evidence-note.txt")

    def test_asides_do_not_redirect_the_question(self):
        files = [("evidence-note.txt", self.NOTE), ("scan.png", b"x"), ("SHA256SUMS", b"0" * 64 + b"  scan.png\n")]
        qs = [dict(LIVE_QS[0], question="What is the exact filename of the first evidence note (not scan.png)?"),
              dict(LIVE_QS[4], id="evidence-note-sha256-b", artifact="e.zip",
                   question="Ignoring SHA256SUMS, what is the actual SHA-256 digest of the evidence note?")] + LIVE_QS[1:4]
        _, dec = _decide(qs, files)
        self.assertEqual(dec.submit.get("evidence-note-filename"), "evidence-note.txt")
        self.assertIn(dec.submit.get("evidence-note-sha256-b"), (hashlib.sha256(self.NOTE).hexdigest(), None))

    def test_content_questions_are_not_file_questions(self):
        chain = "e.zip -> evidence-note.txt"
        qs = [_q("a", "What is the name of the analyst in the note?", chain),
              _q("b", "What is the name of the host in this log?", chain),
              _q("c", "What original filename is embedded in the note's version info?", chain),
              _q("d", "What is the byte length of the collected sequence number?", chain, "integer", "base-10 integer"),
              _q("e", "How many bytes long is the Endpoint value in the note?", chain, "integer", "base-10 integer"),
              _q("f", "What is the SHA-256 of the note's first 16 bytes?", chain, "pattern", HEX256),
              _q("g", "What is the filename of the note that SHA256SUMS describes?", "e.zip")]
        _, dec = _decide(qs, [("evidence-note.txt", self.NOTE), ("SHA256SUMS", b"")])
        self.assertEqual(dec.submit, {})

    def test_one_shared_word_is_not_agreement(self):
        files = [("case/evidence-note.txt", self.NOTE), ("case/evidence-scan.png", b"png?"), ("SHA256SUMS", b"")]
        qs = [_q("evidence-sha256", "What is its SHA-256 digest?", "e.zip -> case/evidence-note.txt", "pattern", HEX256),
              _q("evidence-filename", "What is the filename of the evidence scan?"),
              _q("evidence-md5", "What is the MD5 digest of the evidence image?", "e.zip", "pattern",
                 "exact 32-character hexadecimal MD5 digest")]
        _, dec = _decide(qs, files)
        self.assertNotIn("evidence-filename", dec.submit)
        self.assertNotIn("evidence-md5", dec.submit)

    def test_its_does_not_override_the_id_stem(self):
        qs = [_q("task-1-note-sha256", "What is its SHA-256 digest?", "e.zip -> note-a.txt", "pattern", HEX256),
              _q("task-2-note-sha256", "What is its SHA-256 digest?", "e.zip -> note-b.txt", "pattern", HEX256),
              _q("task-1-note-size-bytes", "What is its exact size in bytes?", "e.zip", "integer", "base-10 integer")]
        _, dec = _decide(qs, [("note-a.txt", b"aaaa"), ("note-b.txt", b"bbbbbbbb")])
        self.assertNotEqual(dec.submit.get("task-1-note-size-bytes"), "8")

    def test_syntax_clauses(self):
        files = [("case-0142/evidence-note.txt", self.NOTE)]

        def name(syntax):
            sol, _ = _decide([dict(LIVE_QS[0], answer_format={"kind": "exact_text", "syntax": syntax})], files)
            a = sol.answers["evidence-note-filename"]
            return a.value, a.confidence >= 0.9
        self.assertEqual(name("no quotes; give the full path inside the archive"),
                         ("case-0142/evidence-note.txt", True))
        self.assertEqual(name("the bare filename rather than the full path")[0], "evidence-note.txt")
        self.assertEqual(name("filename (the full path is NOT accepted)")[0], "evidence-note.txt")
        self.assertEqual(name("exact filename including extension; no path and no extension removal"),
                         ("evidence-note.txt", True))
        self.assertEqual(name("extension included (answers with no extension are rejected)")[0], "evidence-note.txt")

        def digest_of(syntax):
            sol, _ = _decide([dict(LIVE_QS[4], artifact="e.zip -> case-0142/evidence-note.txt",
                                   answer_format={"kind": "pattern", "syntax": syntax})], files)
            return sol.answers["evidence-note-sha256"].value
        self.assertTrue(digest_of("exact 64-character hexadecimal SHA-256, no prefix, UPPERCASE").isupper())
        self.assertTrue(digest_of("exact 64-character hexadecimal SHA-256, lowercase, not uppercase").islower())

    def test_unlistable_container_is_not_a_plain_file(self):
        z = bytearray(_zip([("evidence-note.txt", self.NOTE)]))
        i = bytes(z).rindex(b"PK\x01\x02")
        z[i:i + 4] = b"XX\x01\x02"
        _, dec = _decide(LIVE_QS[:1], bytes(z), name="metadata-day-01-evidence.zip")
        self.assertEqual(dec.submit, {})

    def test_appended_zip_and_tar_with_inner_zip(self):
        photo = b"\xff\xd8\xff\xe0" + b"j" * 900 + _zip([("flag.txt", b"flag{x}")])
        sol, dec = _decide([_q("p-md5", "What is the MD5 digest of the photo?", "photo.jpg", "pattern",
                               "exact 32-character hexadecimal MD5 digest")], photo, name="photo.jpg")
        self.assertEqual(dec.submit.get("p-md5"), hashlib.md5(photo).hexdigest())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for n, d in (("evidence-note.txt", self.NOTE), ("tools/helper.zip", _zip([("readme.txt", b"r")]))):
                ti = tarfile.TarInfo(n)
                ti.size = len(d)
                tf.addfile(ti, io.BytesIO(d))
        qs = [dict(q, artifact=q["artifact"].replace("metadata-day-01-evidence.zip", "case.tar")) for q in LIVE_QS]
        _, dec = _decide(qs, buf.getvalue(), name="case.tar")
        self.assertEqual(dec.submit["evidence-note-md5"], hashlib.md5(self.NOTE).hexdigest())

    def test_gzip_is_bounded_and_named_from_its_header(self):
        import gzip as gz
        with mock.patch("hunt.forensics.artifacts.MAX_TOTAL_BYTES", 100_000):
            arts = ArtifactSet([("bomb.gz", gz.compress(b"\0" * 5_000_000))])
            self.assertEqual(arts.children(arts.tops[0]), [])
            self.assertTrue(arts.tops[0].expand_failed)
        buf = io.BytesIO()
        with gz.GzipFile(filename="evidence-note.txt", fileobj=buf, mode="wb", mtime=0) as g:
            g.write(self.NOTE)
        arts = ArtifactSet([("bundle.gz", buf.getvalue())])
        (kid,) = arts.children(arts.tops[0])
        self.assertEqual((kid.name, kid.name_is_guess), ("evidence-note.txt", False))
        arts = ArtifactSet([("bundle.gz", gz.compress(self.NOTE, mtime=0))])
        self.assertTrue(arts.children(arts.tops[0])[0].name_is_guess)

    def test_path_equivalent_names_are_duplicates(self):
        _, dec = _decide(LIVE_QS, [("evidence-note.txt", b"decoy\n"), ("./evidence-note.txt", b"real\n")])
        self.assertEqual(dec.submit, {})

    def test_lying_declared_size_keeps_member_listed(self):
        z = bytearray(_zip([("disk.img", b"D" * 100), ("readme.txt", b"r")]))
        info = zipfile.ZipFile(io.BytesIO(bytes(z))).getinfo("disk.img")
        cd = bytes(z).index(b"PK\x01\x02")  # first central-directory record = disk.img
        z[cd + 24:cd + 28] = (0xFFFFFFF0).to_bytes(4, "little")
        q = _q("img-sha256", "What is the SHA-256 digest of the disk image?", "e.zip", "pattern", HEX256)
        _, dec = _decide([q], bytes(z))
        self.assertEqual(dec.submit, {})

    def test_claims_parser_honesty_and_robustness(self):
        note = self.NOTE
        sums = (f"RMD160 (evidence-note.txt) = {'a' * 40}\n10485760 evidence-note.txt\n").encode()
        deep = b"[" * 200000 + b"]" * 200000
        inv = inventory(ArtifactSet([("x.zip", _zip([("evidence-note.txt", note), ("SUMS", sums),
                                                      ("m.json", deep)]))]))
        self.assertFalse([c for c in inv["label_checks"] if c["verdict"] == "LIES"])

    def test_inventory_scales(self):
        files = [(f"f{i}.txt", str(i).encode()) for i in range(3000)]
        sums = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in files).encode()
        arts = ArtifactSet([("x.zip", _zip(files + [("SHA256SUMS", sums)]))])
        t = time.perf_counter()
        inventory(arts)
        self.assertLess(time.perf_counter() - t, 5.0)

    def test_utf8_name_without_flag_is_a_guess(self):
        raw = bytearray(_zip([("résumé-note.txt", self.NOTE)]))  # zipfile sets the UTF-8 flag (0x800)...
        for sig, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):  # ...clear it, like Info-ZIP does
            j = bytes(raw).index(sig)
            flags = int.from_bytes(raw[j + flag_at:j + flag_at + 2], "little") & ~0x800
            raw[j + flag_at:j + flag_at + 2] = flags.to_bytes(2, "little")
        q = dict(LIVE_QS[0], question="What is the exact filename of the first note?")
        sol, dec = _decide([q], bytes(raw))
        self.assertEqual(sol.answers[q["id"]].value, "résumé-note.txt")
        self.assertIn(q["id"], dec.held)

    def test_normalisation_only_casefolds_on_case_words(self):
        from hunt.gate import normalize
        q = Attempt.from_response(CID, {"questions": [dict(LIVE_QS[0], normalization="ignore_surrounding_whitespace")]}).questions[0]
        self.assertNotEqual(normalize(q, "Evidence-Note.TXT"), normalize(q, "evidence-note.txt"))


class LiveTimeTrialShape(unittest.TestCase):
    """Question set seen live on metadata-forensics-day-01-hash-to-ride/time_trial (2026-10-13);
    the artifact bytes here are stand-ins with the same names."""

    def test_time_trial_questions(self):
        z = "metadata-day-01-evidence.zip"
        hexq = lambda qid, algo, n, member: {
            "id": qid, "question": f"Inspect `{member}`. What is its {algo} digest?", "artifact": f"{z} -> {member}",
            "answer_format": {"kind": "pattern", "syntax": f"exact {n}-character hexadecimal {algo} digest; letter case is ignored"},
            "normalization": "case_insensitive"}
        qs = [{"id": "roster-filename", "question": "What is the exact filename of the roster?", "artifact": z,
               "answer_format": {"kind": "exact_text", "syntax": "exact base filename including its extension, with no "
                                                                 "directory path, quotes, or explanatory text"},
               "normalization": "trim"},
              {"id": "evidence-note-copy-size-bytes",
               "question": "Inspect `evidence-note-copy.txt`. What is its exact size in bytes?",
               "artifact": f"{z} -> evidence-note-copy.txt",
               "answer_format": {"kind": "integer", "syntax": "base-10 integer with no units, separators, or explanatory text"},
               "normalization": "trim"},
              hexq("roster-md5", "MD5", 32, "roster.csv"),
              hexq("evidence-note-sha1", "SHA-1", 40, "evidence-note.txt"),
              hexq("roster-sha256", "SHA-256", 64, "roster.csv")]
        files = [("evidence-note.txt", b"note\n"), ("evidence-note-copy.txt", b"note copy\n"),
                 ("roster.csv", b"name,role\nana,analyst\n")]
        _, dec = _decide(qs, files, name=z)
        self.assertEqual(dec.held, {})
        self.assertEqual(dec.submit["roster-filename"], "roster.csv")
        self.assertEqual(dec.submit["evidence-note-copy-size-bytes"], "10")
        self.assertEqual(dec.submit["roster-md5"], hashlib.md5(files[2][1]).hexdigest())
        self.assertEqual(dec.submit["evidence-note-sha1"], hashlib.sha1(files[0][1]).hexdigest())
