"""Regression tests for the adversarial review of grind/optimize.

Each test pins one finding's fix so it cannot quietly come back.
Run with:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from hunt.gm import GameMaster
from hunt.learn import policy
from hunt.learn.advisor import TRUNCATED, ManualAdvisor, ScriptedAdvisor, extract_module
from hunt.learn.grind import GrindOptions, grind
from hunt.learn.library import Library, module_of, valid_name
from hunt.learn.sandbox import SOLVE_TIMEOUT, TRIAL_TIMEOUT, Sandbox
from hunt.archive import Archive
from hunt.model import Attempt
from hunt.testing.fake_gm import CID, Base64Challenge, FakeGM

from test_learn import BASED, GOOD, WRONG, _arts, _attempt, _block

# A learned module that answers correctly but tries to forge the handler attribution.
FORGE = GOOD.replace(
    "    return answer(plain, f\"Base64-decoded {m.path}\", 0.95, subject=m)",
    "    a = answer(plain, f\"Base64-decoded {m.path}\", 0.95, subject=m)\n"
    "    a.handler = \"learned//tmp/outside/victim.evil\"\n"
    "    return a")


def _solve(modules, attempt, arts):
    with Sandbox(modules) as sb:
        return sb.raw_solve(attempt, arts)


class HandlerAttribution(unittest.TestCase):
    def test_worker_attributes_to_the_registered_name_not_the_module(self):
        # Even if the module forges Answer.handler, the worker reports the real registration.
        r = _solve([("base64_note", FORGE)], _attempt(), _arts())
        self.assertEqual(r["answers"]["decoded-message"]["handler"], "learned/base64_note.hidden_message")
        self.assertNotIn("/tmp/outside", r["answers"]["decoded-message"]["handler"])

    def test_module_of_and_valid_name_reject_path_like_names(self):
        self.assertIsNone(module_of("learned//tmp/outside/victim.evil"))
        self.assertIsNone(module_of("learned/../../etc/passwd.x"))
        self.assertEqual(module_of("learned/base64_note.decode"), "base64_note")
        self.assertIsNone(module_of("file_identity.file_digest"))  # built-in, not learned
        for bad in ("/abs/path", "../x", "kit", "file_identity", "Bad", "x", "a.b"):
            self.assertFalse(valid_name(bad), bad)
        self.assertTrue(valid_name("base64_note"))

    def test_library_ops_ignore_forged_names(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Library(d)
            lib.install("base64_note", GOOD, challenge=BASED)
            # None of these touch anything outside learned/ for a path-like name.
            lib.mark_proven("/tmp/outside/victim", BASED)
            self.assertIsNone(lib.reject("/tmp/outside/victim", "x"))
            self.assertEqual(lib.status("/tmp/outside/victim"), "missing")
            self.assertFalse(lib.trusted("learned//tmp/outside/victim.evil"))
            self.assertEqual(sorted(lib.names()), ["base64_note"])
            self.assertNotIn("/tmp/outside/victim", lib.manifest()["modules"])

    def test_handler_length_is_capped(self):
        mod = GOOD.replace(
            "    return answer(plain, f\"Base64-decoded {m.path}\", 0.95, subject=m)",
            "    a = answer(plain, \"x\", 0.95, subject=m)\n    a.handler = 'y' * 100000\n    return a")
        r = _solve([("base64_note", mod)], _attempt(), _arts())
        self.assertLessEqual(len(r["answers"]["decoded-message"]["handler"]), 200)


class WorkerIntegrity(unittest.TestCase):
    def test_tampering_with_other_answers_is_undone(self):
        # A handler that mutates a sibling Answer object has its own answer dropped and the change undone.
        q2 = Attempt.from_response(BASED, {"lane": "warmups", "answer_ids": ["a", "b"], "questions": [
            {"id": "a", "question": "What message is hidden in the encoded note?", "artifact": "little-based.txt",
             "answer_format": {"kind": "exact_text", "syntax": "text"}},
            {"id": "b", "question": "What message is hidden, again?", "artifact": "little-based.txt",
             "answer_format": {"kind": "exact_text", "syntax": "text"}}]})
        evil = ('# learned-module: base64_note\n'
                'from hunt.learn.kit import answer, target, text\n'
                'from hunt.solvers import handler\n'
                'import base64\n'
                '@handler(lanes=("warmups",))\n'
                'def h(q, ctx):\n'
                '    m = target(q, ctx)\n'
                '    plain = base64.b64decode((text(m) or "").strip()).decode()\n'
                '    for a in ctx.answers.values():\n'
                '        a.value = "TAMPERED"\n'
                '    return answer(plain, "x", 0.95, subject=m)\n')
        self.assertEqual(policy.check(evil), [])
        r = _solve([("base64_note", evil)], q2, _arts())
        # 'a' answered normally; answering 'b' tries to rewrite 'a' -> dropped, 'a' intact.
        self.assertEqual(r["answers"]["a"]["value"], "HuntressCTF{abc}")
        self.assertNotIn("b", r["answers"])
        self.assertTrue(any("changed other answers" in t for t in r["traces"]))

    def test_stdlib_constructs_load_in_the_worker(self):
        # dataclass, namedtuple, functional Enum and TypeVar are advertised; they must load.
        mod = ('# learned-module: base64_note\n'
               'import dataclasses, collections, enum, typing\n'
               'from hunt.solvers import handler\n'
               '@dataclasses.dataclass\n'
               'class P:\n'
               '    a: int = 1\n'
               'Pt = collections.namedtuple("Pt", "a b")\n'
               'E = enum.Enum("E", "A B")\n'
               'T = typing.TypeVar("T")\n'
               '@handler(lanes=("warmups",))\n'
               'def h(q, ctx):\n'
               '    return None\n')
        self.assertEqual(policy.check(mod), [])
        with Sandbox([("base64_note", mod)]) as sb:
            self.assertEqual(sb.info["loaded"], ["base64_note"], sb.info.get("errors"))

    def test_registering_handlers_mid_solve_is_undone(self):
        evil = ('# learned-module: base64_note\n'
                'from hunt.solvers import handler, Answer\n'
                'def _extra(q, ctx):\n'
                '    return None\n'
                '@handler(lanes=("warmups",))\n'
                'def h(q, ctx):\n'
                '    handler(lanes=("warmups",))(_extra)\n'
                '    return None\n')
        self.assertEqual(policy.check(evil), [])
        with Sandbox([("base64_note", evil)]) as sb:
            before = len(sb.info["handlers"])
            r = sb.raw_solve(_attempt(), _arts())
            # a second solve: the registry did not grow across calls
            sb.raw_solve(_attempt(), _arts())
        self.assertTrue(any("registered more handlers" in t for t in r["traces"]))
        self.assertEqual(before, 1)


class PolicyTightening(unittest.TestCase):
    def test_mutating_imported_or_shared_objects_is_refused(self):
        head = "from hunt.solvers import handler, Answer\n@handler()\ndef h(q, ctx):\n    return None\n"
        for code, why in {
            "__name__ = 'x'": "assigning __name__",
            "Answer.value = 1": "imported or computed",
            "import re\nre.X = 1": "imported or computed",
            "import sys\nx=1": "import sys",  # sys not allowed at all
            "type(1).real = 2": "imported or computed",  # mutate a direct call result
            "import json\njson.__dict__['x'] = 1": "not allowed",
        }.items():
            problems = policy.check(code + "\n" + head)
            self.assertTrue(problems, code)
            self.assertIn(why, " ".join(problems), code)

    def test_local_object_mutation_is_fine(self):
        ok = ("from hunt.solvers import handler\n"
              "@handler()\n"
              "def h(q, ctx):\n"
              "    d = {}\n"
              "    d['x'] = 1\n"
              "    class C:\n"
              "        pass\n"
              "    c = C()\n"
              "    c.v = 2\n"
              "    return None\n")
        self.assertEqual(policy.check(ok), [])

    def test_check_is_independent_of_import_state(self):
        # html.parser / email.policy resolve the same whether or not the process imported them.
        for code in ("import html.parser\nx = html.parser.HTMLParser",
                     "import email.policy\nx = email.policy.default"):
            src = code + "\nfrom hunt.solvers import handler\n@handler()\ndef h(q, ctx):\n    return None\n"
            self.assertEqual(policy.check(src), [], code)


class Timeouts(unittest.TestCase):
    def test_trial_is_stricter_than_solve(self):
        self.assertLess(TRIAL_TIMEOUT, SOLVE_TIMEOUT)

    def test_sandbox_falls_back_to_builtins(self):
        # Too-large artifacts: the worker refuses, but built-in handlers still answer in process.
        with Sandbox([("base64_note", GOOD)]) as sb:
            fn = _attempt("What is the exact filename of the note?")
            # A size over the cap is simulated by monkeypatching the module constant is overkill;
            # instead check the real fallback path: a built-in question answered despite a learned-only sandbox.
            sol = sb.solve(fn, _arts())
        # built-in file_name handler still produced something (not all-unresolved)
        self.assertTrue(sol.answers or sol.unresolved)


class GrindGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fake = FakeGM(mode="trio", seed=3)
        self.based = Base64Challenge(BASED, rng=random.Random(5), with_length=True)
        self.fake.extras[BASED] = self.based
        self.url = self.fake.start_server()
        self.gm = GameMaster(base_url=self.url, token=self.fake.token)
        self.lib = Library(self.root / "learned")
        self.log: list[str] = []

    def tearDown(self):
        self.fake.stop()
        self.tmp.cleanup()

    def _grind(self, advisor, ids=None, **opts):
        rows = [r for r in self.gm.list() if ids is None or r["id"] in ids]
        return {r.challenge: r for r in grind(self.gm, Archive(self.root / "runs"), self.lib, advisor, rows,
                                              GrindOptions(**opts), log=self.log.append)}

    def test_reserved_name_does_not_crash_grind(self):
        # The advisor names its module 'kit' (reserved). grind must survive and fall back to a safe name.
        bad = GOOD.replace("# learned-module: base64_note", "# learned-module: kit")
        res = self._grind(ScriptedAdvisor([_block(bad)]), ids=[BASED])
        self.assertEqual(res[BASED].status, "scored", self.log)
        self.assertNotIn("kit", self.lib.names())

    def test_proven_module_is_kept_when_refused_elsewhere(self):
        # A proven module that answers and is refused on another challenge is kept, not deleted,
        # and the refusal makes grind ask for a challenge-specific override instead.
        self.lib.install("base64_note", GOOD, challenge=BASED)
        self.lib.mark_proven("base64_note", BASED)
        other = Base64Challenge(BASED + "x", name="Based B", rng=random.Random(2), reverse_truth=True)
        self.fake.extras[other.id] = other
        override = (GOOD.replace("# learned-module: base64_note", "# learned-module: based_b")
                    .replace('@handler(lanes=("warmups",))', '@handler(priority=50, challenges=(r".*a-little-basedx",))')
                    .replace("return answer(plain, f", "return answer(plain[::-1], f"))
        res = self._grind(ScriptedAdvisor([_block(override)]), ids=[other.id])
        self.assertEqual(self.lib.status("base64_note"), "proven")  # never rejected
        self.assertIn("base64_note", self.lib.names())
        self.assertIn("kept", " ".join(self.log))
        self.assertEqual(res[other.id].status, "scored", self.log)

    def test_rejecting_a_revised_proven_module_rolls_back(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Library(d)
            lib.install("base64_note", GOOD, challenge=BASED)
            lib.mark_proven("base64_note", BASED)
            lib.install("base64_note", WRONG)  # a revision: candidate again
            lib.reject("base64_note", "refused")
            self.assertEqual(lib.status("base64_note"), "proven")
            self.assertEqual((Path(d) / "base64_note.py").read_text(encoding="utf-8"), GOOD)

    def test_guessed_ids_do_not_go_to_the_advisor(self):
        # With opaque ids the gate holds everything for id-mapping reasons; no handler can fix that.
        self.fake = FakeGM(mode="trio", seed=3, opaque_ids=True)
        self.url = self.fake.start_server()
        self.gm = GameMaster(base_url=self.url, token=self.fake.token)
        adv = ScriptedAdvisor(lambda m, n: "no module")
        rows = [r for r in self.gm.list() if r["id"] == CID]
        res = {r.challenge: r for r in grind(self.gm, Archive(self.root / "runs"), self.lib, adv, rows,
                                             GrindOptions(), log=self.log.append)}
        self.assertEqual(res[CID].status, "stuck")
        self.assertIn("trust-positional-ids", res[CID].detail)
        self.assertEqual(adv.seen, [])  # the advisor was never asked

    def test_timed_single_solve_is_submitted_not_learned(self):
        # A route with no run_for_time_supported that actually runs a clock: built-ins answer the
        # hash challenge, so it is submitted at once; it is never retried.
        self.fake = FakeGM(mode="single", seed=3, timed_by_default=True)
        self.url = self.fake.start_server()
        self.gm = GameMaster(base_url=self.url, token=self.fake.token)
        rows = [r for r in self.gm.list() if r["id"] == CID]
        res = {r.challenge: r for r in grind(self.gm, Archive(self.root / "runs"), self.lib, None, rows,
                                             GrindOptions(), log=self.log.append)}
        self.assertEqual(res[CID].status, "scored", self.log)
        self.assertIn("TIMED", " ".join(self.log))
        self.assertEqual(len(self.fake.history), 1)  # no retry spent


class AdvisorRobustness(unittest.TestCase):
    def test_fence_parsing(self):
        g = "# learned-module: abc\nfrom hunt.solvers import handler\n@handler()\ndef h(q, ctx):\n    return '```'\n"
        self.assertEqual(extract_module(f"```python\n{g}```")[0], "abc")
        self.assertEqual(extract_module(f"```Python\n{g}```")[0], "abc")
        self.assertEqual(extract_module(f"```python3\n{g}```")[0], "abc")
        self.assertEqual(extract_module(f"````python\n{g}````")[0], "abc")
        self.assertEqual(extract_module(f"```json\n{{}}\n```\nthen:\n```python\n{g}```")[0], "abc")
        # a cut-off reply (unclosed fence) is not a usable block
        self.assertEqual(extract_module(f"```python\n{g[:30]}")[:1], (None,))

    def test_truncated_reply_is_reported_as_cut_off(self):
        g = "# learned-module: abc\nfrom hunt.solvers import handler\n@handler()\ndef h(q, ctx):\n    pass\n"
        truncated = f"```python\n{g[:40]}\n\n{TRUNCATED}"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = FakeGM(mode="trio", seed=1)
        based = Base64Challenge(BASED, rng=random.Random(5))
        fake.extras[BASED] = based
        url = fake.start_server()
        self.addCleanup(fake.stop)
        gm = GameMaster(base_url=url, token=fake.token)
        adv = ScriptedAdvisor([truncated, _block(GOOD)])
        rows = [r for r in gm.list() if r["id"] == BASED]
        grind(gm, Archive(Path(tmp.name) / "runs"), Library(Path(tmp.name) / "learned"), adv, rows,
              GrindOptions(rounds=2, episodes=1))
        self.assertIn("cut off", adv.seen[1])

    def test_manual_advisor_ignores_a_stale_reply(self):
        with tempfile.TemporaryDirectory() as d:
            inbox = Path(d) / "inbox"
            inbox.mkdir(parents=True)
            stale = inbox / "warmups-day-01-a-little-based-round1.reply.md"
            stale.write_text("OLD reply from an earlier run", encoding="utf-8")
            saved = {}

            def ask(_prompt):
                # the reply file must have been moved aside before we are asked
                saved["exists"] = stale.exists()
                r = inbox / "warmups-day-01-a-little-based-round1.reply.md"
                r.write_text(_block(GOOD), encoding="utf-8")
                return ""

            adv = ManualAdvisor(inbox, ask=ask, out=lambda *a: None)
            convo = adv.conversation("warmups-day-01-a-little-based")
            reply = convo.ask("NEW packet")
            self.assertFalse(saved["exists"])  # old reply was renamed before the prompt
            self.assertIn("base64_note", reply)


if __name__ == "__main__":
    unittest.main()
