# HuntressCTFmasterBOT

A deterministic solver for the Huntress CTF 2026 Game Master. The AI's job is
to *write handlers* for this bot while nothing is timed. `hunt grind` does that
on its own, asking Claude whenever it meets a question it cannot answer. The
bot's job is to replay those handlers, with no model calls, when the clock is
running.

```
untimed (learn + prove)                          timed (race)
──────────────────────────────────────           ───────────────────────────────────────
hunt solve CID          dry run: see the         hunt race CID
                        questions, artifact,       regression must pass first
                        proposed answers           warm connection   (off the clock)
   ↓ write/adjust a handler if needed              start/retry (timed) ┐
hunt offline CID        re-solve archive, no net   download artifact   │ on the clock
hunt solve CID --submit the real untimed submit    solve + gate        │ (~ms of compute,
   ↓ CORRECT → archived as ground truth            submit             ─┘  the rest is network)
hunt replay CID         regression check           archive + inventory (off the clock)
```

## Quick start: the timed hash challenge (Windows PowerShell)

```powershell
# once
git clone https://github.com/404kacper/HuntressCTFmasterBOT
cd HuntressCTFmasterBOT
git checkout claude/huntress-ctf-solver-8n8edz
py -m pip install requests

# every time: find the challenge id
py -m hunt list --day 1

# practise with no clock (nothing is sent), then for real (still no clock)
py -m hunt solve <challenge-id>
py -m hunt solve <challenge-id> --submit

# the timed run
py -m hunt race <challenge-id>
```

If `solve` says the challenge is *already solved*, run `py -m hunt solve <challenge-id> --retry`
for a fresh untimed copy, then `py -m hunt solve <challenge-id> --submit`. If `list`
says **START IS TIMED**, there is no untimed copy: go straight to
`py -m hunt race <challenge-id> --force`.

## Autopilot: `grind` (points) and `optimize` (leaderboard)

Two goals, two commands.

**Points: `hunt grind`.** It walks the challenges and stops once every one has scored (a CORRECT
reply from the Game Master = flag + CourseStack points). Modes run in unlock order: Single Solve,
then Time Trial, then Mastery. All attempts are untimed, so no clock and no ranked attempt is spent.

```powershell
py -m hunt grind --day 2                 # every challenge of day 2, all modes
py -m hunt grind "A Little Based"        # one challenge, all of its modes
py -m hunt grind --day 2 --no-submit     # learn and prove offline, send nothing
py -m hunt grind --day 1 --accept-timer  # also Time Trial / Mastery routes that may start a clock
py -m hunt learned                       # what the bot has learned so far
```

Most day-1 Time Trial and Mastery routes don't list `run_for_time_supported`, so grind skips them
unless you pass `--accept-timer`. Each such start can spend one ranked attempt on a 30-second clock.
When a timed attempt has questions no handler answers, grind learns from it anyway. Asking the
advisor takes minutes, so that attempt runs out, and the next start is where the new handler gets
used. That retry doesn't count against `--fresh-variants`. Each start is printed with the seconds on
the clock and the ranked attempts left. A challenge spends at most 1 + `--episodes` +
`--fresh-variants` timed starts in one run. On a timed attempt, answers still go one at a time while
the clock allows, so a refusal names the wrong one. When the deadline gets close, the rest go in one
request.

Challenges without files work too. If the reply only names an answer id, the bot submits an
`issued_flag` the reply hands out. Otherwise it fetches the page the prompt links, plus the scripts
that page loads, and looks for a `flag{...}`. That fetch uses its own HTTP session, with no
Authorization header, and never contacts the Game Master's host. Zips encrypted with WinZip AES are
opened like ZipCrypto ones, using `infected`, `malware` or `virus`.

For each challenge, grind starts (or reconnects to) an untimed attempt and solves it with
everything the bot knows. If every answer passes the gate, it submits. If some question has no
handler, it **asks Claude to write one** and goes back and forth with it:

1. Claude gets a packet: the challenge text, every question with what the bot already answered,
   an inventory of the downloaded files, and previews of their contents. It also gets earlier
   variants with the answers the Game Master accepted, plus the handlers learned so far.
2. Claude replies with one Python module. The bot checks it against a strict policy: allowlisted
   stdlib imports only, and no files, network, processes, `eval`, or dunder tricks. It then runs
   the module in a **sandbox process** started with `-I -S`, an empty environment (no Game Master
   token, no API key), an empty folder, and an audit hook that refuses network, processes and
   file access.
3. The module must answer every held question in the declared format and still reproduce every
   archived CORRECT attempt. If it doesn't, the exact problem goes back to Claude: the policy
   violation, the traceback, the gate's objection, or the broken regression. Claude replies with
   a fixed module, and this repeats for up to `--rounds` replies.
4. Once it passes, the module is saved in `learned/` and the attempt is submitted **one answer at
   a time**, answers from proven handlers first. The Game Master keeps correct partial progress,
   so if it refuses an answer, the bot knows exactly which handler was wrong. A handler can give
   `alternatives=[...]`, other spellings of the same fact such as `EXEC` or `ET_EXEC`. On an
   untimed attempt the bot tries those first. Refused values are kept in the run archive and are
   never sent again for the same attempt. If nothing is left to try, the module is **kept**, and
   the refusal goes back to Claude with a request to revise that module under the same name. One
   wrong field is no reason to throw away the answers the module got right.
5. On CORRECT, the module is marked *proven*. Every later variant, timed race and day reuses it
   with no AI in the loop.

Who plays Claude (`--advisor`, default `auto` picks the first that works):

| advisor | needs | notes |
|---|---|---|
| `api` | `py -m pip install anthropic` plus `ANTHROPIC_API_KEY` (or `ant auth login`) | model `claude-opus-5-5` (`--model` / `HUNT_CLAUDE_MODEL`); server-side fallback to `claude-opus-4-8` when it declines |
| `cli` | Claude Code installed (`claude`) | runs `claude -p` with **all tools off**: it can only read the packet and reply. If Opus 5.5 declines, the same packet goes to `claude-opus-4-8` |
| `kimi` | `MOONSHOT_API_KEY` | Kimi alone (`HUNT_KIMI_MODEL`, default `kimi-k3`; `HUNT_KIMI_BASE_URL`, default `https://api.moonshot.ai/v1`) |
| `manual` | you | writes `learned/inbox/<challenge>-roundN.md`; you paste it into Claude and save the reply next to it |
| `none` | - | known questions only; for the rest, a `packet.md` is saved in the run folder |

**Escalation on refusal.** Opus 5.5 handles the packet first, then Opus 4.8 if 5.5 declines.
Change that list with `--fallback-models`, or pass `none` to turn it off. If both Claude models
decline and `MOONSHOT_API_KEY` is set, the conversation moves to Kimi and stays there. `--kimi on`
requires Kimi, and `--kimi off` never uses it. A network error or a module that fails the trial
never escalates. Only a refusal does. Kimi receives the same packet Claude would: challenge text,
questions and artifact previews. It never receives the Game Master token. The packet goes to
Moonshot's servers, so decide whether that's acceptable for your event data.

Every learning episode leaves a transcript in the run folder (`runs/<challenge>/<run>/advisor/`).
It holds each packet, each reply (named after the model that wrote it) and each trial verdict.

Run grind **on your PC**, not on Homebase: an API key is a credential, and Huntress asks you not to
put credentials into Homebase. Then commit `learned/` (`git add learned; git commit`) and
`git pull` on Homebase so the racing machine knows the same tricks.

**Leaderboard: `hunt optimize`.** It races a challenge until you hold the target place.

```powershell
py -m hunt optimize <challenge-id> --target-rank 3
py -m hunt optimize <challenge-id> --target-rank 3 --beat 0.330   # if no rank can be read: the 3rd place time
```

If the bot has never been CORRECT on the challenge, optimize grinds it first (untimed). Then it
runs timed attempts back to back and reads your place after each CORRECT. The place comes from a
rank field in the Game Master's reply, a leaderboard operation in its OpenAPI document, or, failing
both, your `--beat` time. It stops at the first of these:

- the target place
- `--keep` ranked attempts left
- `--patience` runs with no new best
- `--max-runs`
- any result that is not CORRECT

If the best time stops improving, the remaining time is network distance: run `hunt ping` on each
machine and race from the closer one.

## Token

The bot reads `HUNTRESS_GM_TOKEN` (and `GM` or `HUNTRESS_GM_URL` for the endpoint, as
`solution.py` did). If you set them with `setx`, there is nothing else to do: just
open a new terminal afterwards, because `setx` does not change the window it runs in.
Only if the variable is missing does the bot ask for the token, with hidden typing.
`HUNTRESS_GM_TOKEN_FILE` (a path to a file holding the token) also works.

## The loop for a new challenge

1. `py -m hunt list`: look at `run_for_time_supported`. **If it is false, a
   plain start may begin a real countdown.** `solve` refuses to start such a
   route unless you pass `--accept-timer`.
2. `py -m hunt openapi`: save the live API spec to `docs/openapi.json` and
   commit it, so you and your AI work from the real schema.
3. `py -m hunt solve CID`: start or reconnect to the **untimed** attempt,
   download the artifact, and print each question, its answer format, the
   proposed answer, confidence and evidence. Nothing is sent.
4. If something is `HELD`, add or fix a handler in `hunt/solvers/` and check
   it with `py -m hunt offline CID` (it re-solves the archived artifact without
   touching the network). `runs/<CID>/…/inventory.json` already has sizes,
   hashes, true file types and label checks for every file.
5. `py -m hunt solve CID --submit`: the real untimed submission. When it comes
   back CORRECT, the attempt becomes ground truth in `runs/`.
6. `py -m hunt race CID`: replays every archived CORRECT attempt first and
   refuses to race if the solver no longer reproduces them (`--force` skips
   this). Then it warms the connection and sends `start` with
   `run_for_time:true`. If that only reconnects to a finished attempt, it
   sends `retry` instead (reconnecting costs no clock time). Then it solves,
   submits and prints the timings.

Regular and timed attempts draw from separate artifact pools, but the question
IDs and answer formats are stable by design. Proving a solver on the untimed
variant is therefore the closest thing to testing before you submit.

## The gate (where the robot stops and asks)

An answer is only sent if it:
- maps to an `answer_id` from the reply, by id rather than guessed from position. If the
  ids had to be matched by position, the answers are held unless you pass
  `--trust-positional-ids`,
- matches the declared `answer_format` (integer, N hex characters, no path, …),
- was produced with confidence at or above `--min-confidence` (default 0.9).

The identity handlers deliberately refuse questions about what a label,
manifest or header *claims* ("which file…", "whose…", "listed", "stored",
"central directory"…). Duplicate entry names, encrypted entries no known
password opens, and entries whose stored CRC lies are reported, never
guessed.

When something is held during a race, you get a prompt showing the seconds left
on the clock: send the passed answers, send everything, or send nothing. With
`--no-prompt` (or no terminal) nothing is sent. The bot also refuses to:
- answer if the downloaded bytes don't match an artifact SHA-256 given in the reply,
- answer in a race when the reply has no deadline (start or retry reconnected to an
  untimed attempt),
- start or retry, in `solve`, on a route not listed with `run_for_time_supported`
  (pass `--accept-timer` to override).

If the network drops during submit, the run is still archived and you are
told the outcome is unknown: check `hunt status CID` before doing anything else.

## Adding a handler

```python
# hunt/solvers/my_lane.py  (picked up automatically)
from . import Answer, handler

@handler(priority=50, lanes=("script-analysis",))
def decoded_url(q, ctx):
    if "url" not in q.haystack:
        return None                      # not mine, let the next handler try
    data = ctx.artifacts.tops[0].data
    ...
    return Answer(value, 0.95, "why I believe it")
```

`solvers/file_identity.py` is the worked example: filename, size and every
common digest, for whichever file the question points at.

## Tests

```
py -m unittest discover -s tests -v
py -m hunt rehearse --mode trio --variants 10   # full race against a local fake Game Master
```

The fake Game Master copies the documented behaviour and the live reply shape.
Its variants (renamed files, decoys, subfolders, two-note mastery, opaque
answer ids) are guesses, so a pass shows that the plumbing and the solver's
generality are sound. It does not show that the real server agrees.

## Safety

- The token is read from the environment only. It is never logged or archived.
  It is stripped from requests to any host other than the Game Master, and it is
  never sent over plain HTTP except to localhost. Network errors are reported by
  type only, because some of them embed header values.
- Artifacts are parsed in memory and never executed. Archived copies are stored
  as `<sha256>.bin`. Nested archives are expanded lazily, with depth and size limits.
- `runs/` is git-ignored: it holds untrusted bytes.
- Code Claude writes never runs in the bot's own process (the one holding the token). It must
  first pass `hunt/learn/policy.py`. It then runs only inside the sandbox worker
  (`hunt/learn/worker.py`): a separate Python with no token, no API key and an empty folder,
  whose audit hook refuses network, processes and file access outside the Python installation.
  Packets fence artifact content as untrusted data, because CTF files can carry prompt injection.
  They never contain the token.
- Nothing the worker returns is trusted by the main process: an answer is attributed to the
  handler the bot registered, never to a name the module supplies, and the library validates every
  module name before it touches a file, so a learned module cannot steer a filesystem operation.
  The worker also restores the bot's own classes after each solve and drops any handler a module
  registers mid-solve, so one learned module cannot corrupt another or the built-ins.
