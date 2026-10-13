"""Learning: when no handler knows a question, ask Claude for one, prove it, keep it.

    packet.py   what the advisor is shown (questions, artifact inventory, previews)
    advisor.py  who writes the handler: the Claude API, the `claude` CLI, or a human
    policy.py   the static check learned code must pass before it ever runs
    worker.py   the sandbox process learned code runs in (no token, no network, no files)
    sandbox.py  the parent side of that process
    library.py  learned/ on disk: the handlers kept so far and what they have proven
    grind.py    the loop that walks a day's challenges until each one scores
"""
