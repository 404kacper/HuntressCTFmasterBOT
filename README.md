# HuntressCTFmasterBOT

A deterministic solver for the Huntress CTF 2026 Game Master. The AI's job is
to *write handlers* for this bot while nothing is timed. The bot's job is to
replay them, with no model calls, when the clock is running.

```
untimed (learn + prove)                          timed (race)
──────────────────────────────────────           ───────────────────────────────────────
hunt solve CID          dry run: see the         hunt race CID
                        questions, artifact,       regression must pass first
                        proposed answers           warm connection   (off the clock)
   ↓ write/adjust a handler if needed              retry run_for_time ─┐
hunt offline CID        re-solve archive, no net   download artifact   │ on the clock
hunt solve CID --submit the real untimed submit    solve + gate        │ (~ms of compute,
   ↓ CORRECT → archived as ground truth            submit             ─┘  the rest is network)
hunt replay CID         regression check           archive + inventory (off the clock)
```

## Setup (Windows PowerShell)

```powershell
py -m pip install requests
cd HuntressCTFmasterBOT
# Read the token without echoing it or saving it to history:
$s = Read-Host -AsSecureString "Game Master token"
$env:HUNTRESS_GM_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
py -m hunt list --day 1
```

Or put the token in a file outside the repo and set `$env:HUNTRESS_GM_TOKEN_FILE`
to its path. `HUNTRESS_GM_URL` (or `GM`, which your old script used) overrides the
endpoint. With no token, the bot uses the Homebase proxy URL.

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
   refuses to race if the solver no longer reproduces them. Then it warms the
   connection, retries with `run_for_time:true`, solves, submits and prints
   the timings.

Regular and timed attempts draw from separate artifact pools, but the question
IDs and answer formats are stable by design. Proving a solver on the untimed
variant is therefore the closest thing to testing before you submit.

## The gate (where the robot stops and asks)

An answer is only sent if it:
- maps to an `answer_id` from the reply,
- matches the declared `answer_format` (integer, N hex characters, no path, …),
- was produced with confidence at or above `--min-confidence` (default 0.9).

When something is held during a race, you get a prompt showing the seconds left
on the clock: send the passed answers, send everything, or send nothing. With
`--no-prompt` (or no terminal) nothing is sent. The bot also refuses to answer
if the downloaded bytes don't match an artifact SHA-256 given in the reply.

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

- The token is read from the environment only. It is never logged or archived,
  and it is stripped from requests to any host other than the Game Master.
- Artifacts are parsed in memory and never executed. Archived copies are stored
  as `<sha256>.bin`. Nested archives are expanded lazily, with depth and size limits.
- `runs/` is git-ignored: it holds untrusted bytes.
