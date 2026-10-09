"""Run with:  python -m unittest discover -s tests -v"""
from __future__ import annotations

import io
import json
import os
import random
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from hunt import cli
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

    def test_positional_answer_ids(self):
        qs = json.loads((FIX / "hash_to_ride_start_reply.json").read_text(encoding="utf-8"))["questions"]
        opaque = [f"a{i}" for i in range(len(qs))]
        a = self._attempt(qs, opaque)
        dec = decide(a, solve(a, ArtifactSet([("", (FIX / "you_must_be_this_hash_to_ride.zip").read_bytes())])))
        self.assertEqual(dec.submit, {f"a{i}": EXPECTED[q["id"]] for i, q in enumerate(qs)})
        self.assertTrue(any("by position" in w for w in dec.warnings))

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

    def test_zip_bomb_budget(self):
        z = _zip([("big.bin", b"\0" * 2_000_000)])
        with mock.patch("hunt.forensics.artifacts.MAX_TOTAL_BYTES", 1_000_000):
            arts = ArtifactSet([("x.zip", z)])
            self.assertEqual(arts.children(arts.tops[0]), [])


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
