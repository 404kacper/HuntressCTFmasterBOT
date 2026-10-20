# learned-module: batch_control_wrapper
"""Control-flow wrapper that makes a batch descriptor reconstruction run.

Answers "Classify only the control-flow wrapper ..." (direct, goto_dispatch,
call_subroutine, for_once, if_guard, errorlevel_guard) for a .bat/.cmd artifact.
It finds the SET that concatenates the fragment variables, discards any FOR
whose loop variable feeds that SET (the FOR-indirect expansion form, not a
wrapper), then classifies what makes the statement run:
  * an inline IF / ERRORLEVEL / && guard or a one-item FOR around it;
  * a conditional jump (IF ... GOTO / || GOTO / IF ... EXIT) that skips past it;
  * the label that leads to it when that label cannot be reached by falling
    through (CALL -> call_subroutine, one-item FOR around CALL -> for_once,
    GOTO -> goto_dispatch);
  * otherwise straight-line flow (direct).
GOTOs into a label that straight-line flow reaches anyway, forward GOTOs that
merely hop over noise, unreferenced labels and the --inspect/--plan host
envelope are ordinary transfers and are ignored.
"""
import re

from hunt.learn.kit import answer, target, text
from hunt.solvers import handler

TAG = "[batch_control_wrapper]"
CHOICES = ("direct", "goto_dispatch", "call_subroutine", "for_once", "if_guard", "errorlevel_guard")
KIND_ANSWER = {"for": "for_once", "errorlevel": "errorlevel_guard", "cond": "errorlevel_guard", "if": "if_guard"}
ENVELOPE = re.compile(r"(?i)--inspect|--plan|%~?[0-9]|%\*")
ESCAPED = {"(": "\x01", ")": "\x02", "&": "\x03", "|": "\x04", "<": "\x05", ">": "\x06"}
UNESCAPED = {"\x01": "^(", "\x02": "^)", "\x03": "^&", "\x04": "^|", "\x05": "^<", "\x06": "^>"}

IF_HEAD = re.compile(r"(?i)if\s+(?:(?:/i|not)\s+){0,2}")
IF_ERR = re.compile(r"(?i)errorlevel\s+[^\s()]+\s*")
IF_DEF = re.compile(r"(?i)(?:defined|cmdextversion)\s+[^\s()]+\s*")
IF_EXIST = re.compile(r'(?i)exist\s+(?:"[^"]*"|[^\s()]+)\s*')
OPND = r'(?:"[^"]*"|[^\s=()"]+)'
IF_CMP = re.compile(r"(?i)(" + OPND + r")(?:\s*==\s*|\s+(?:equ|neq|lss|leq|gtr|geq)\s+)(" + OPND + r")\s*")
FOR_HEAD = re.compile(
    r'(?i)for\s+(?:(/[dlrf])\s+(?:("[^"]*")\s+|(?![%"])(\S+)\s+)?)?'
    r'(%%?[A-Za-z0-9#$])\s+in\s*\(([^()]*)\)\s*do\b\s*'
)
SET_AT = re.compile(r"(?i)(?<![\w.\-])set\s+(/[ap]\s+)?")
REF = re.compile(
    r"%%([A-Za-z_][\w#$.\-]*?)(?::[^%]*)?%%"
    r"|%([A-Za-z_][\w#$.\-]*?)(?::[^%]*)?%"
    r"|!([A-Za-z_][\w#$.\-]*?)(?::[^!]*)?!"
)
JUMP = re.compile(r"(?i)\s*@?\s*(?:goto|exit)(?![\w])")
GOTO_AT = re.compile(r"(?i)\s*@?\s*goto\s*:?\s*([^\s&|<>()]+)")
DYNAMIC = re.compile(r"(?i)(?<![\w])(call|goto)\s*:?\s*([%!][^\s&|<>()]+)")


def clean(s):
    return "".join(UNESCAPED.get(c, c if c >= " " else " ") for c in s)


def dedupe(seq):
    out = []
    for x in seq:
        if x and x not in out:
            out.append(x)
    return out


# ---------------------------------------------------------------- lines

def logical_lines(body):
    phys = body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    i = 0
    while i < len(phys):
        no = i + 1
        line = phys[i]
        while i + 1 < len(phys) and (len(line) - len(line.rstrip("^"))) % 2 == 1:
            line = line[:-1] + phys[i + 1]
            i += 1
        out.append((no, line))
        i += 1
    return out


def decaret(line):
    out = []
    quoted = False
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == '"':
            quoted = not quoted
            out.append(c)
        elif c == "^" and not quoted and i + 1 < n:
            nxt = line[i + 1]
            out.append(ESCAPED.get(nxt, nxt))
            i += 1
        else:
            out.append(c)
        i += 1
    return "".join(out)


def line_kind(txt):
    s = txt.strip()
    if not s:
        return "blank", ""
    if s.startswith("::"):
        return "comment", ""
    if re.match(r"(?i)@?\s*rem(?:[\s.:/,;=]|$)", s):
        return "comment", ""
    if s.startswith(":"):
        m = re.match(r":\s*([^\s:+=,;&|<>()\"]+)", s)
        if m:
            return "label", m.group(1).lower()
        return "comment", ""
    return "cmd", ""


def first_operator(t):
    quoted = False
    i = 0
    while i < len(t):
        c = t[i]
        if c == '"':
            quoted = not quoted
        elif not quoted and c in "&|":
            if t[i:i + 2] in ("&&", "||"):
                return i, t[i:i + 2]
            return i, c
        i += 1
    return None


def for_items(sw, items):
    sw = (sw or "").lower()
    body = items.strip()
    if sw == "/l":
        nums = re.findall(r"-?\d+", body)
        if len(nums) == 3:
            a, b, c = int(nums[0]), int(nums[1]), int(nums[2])
            if b != 0:
                n = max((c - a) // b + 1, 0)
                return n, [str(a + k * b) for k in range(min(n, 64))]
        return None, []
    if sw == "/f":
        if body[:1] in ('"', "'", "`"):
            return 1, [body.strip("\"'`")]
        return None, []
    if "*" in body or "?" in body:
        return None, []
    toks = re.findall(r'"[^"]*"|[^\s,;=]+', body)
    return len(toks), toks


def parse_wrappers(s):
    """Leading IF / FOR / && chains of a command prefix -> (wrappers, rest)."""
    found = []
    rest = s
    for step in range(32):
        t = rest.lstrip(" \t@;,=")
        if not t:
            return found, ""
        m = re.match(r"(?i)(?:\)\s*)?else(?![\w])\s*", t)
        if m:
            rest = t[m.end():]
            continue
        m = IF_HEAD.match(t)
        if m:
            u = t[m.end():]
            kind = "errorlevel"
            m2 = IF_ERR.match(u)
            if m2 is None:
                kind = "if"
                m2 = IF_DEF.match(u) or IF_EXIST.match(u)
            if m2 is None:
                m2 = IF_CMP.match(u)
                if m2 is not None and "errorlevel" in (m2.group(1) + m2.group(2)).lower():
                    kind = "errorlevel"
            if m2 is None:
                found.append(("if", None, t))
                return found, ""
            found.append((kind, None, t[:m.end() + m2.end()]))
            rest = u[m2.end():]
            continue
        m = FOR_HEAD.match(t)
        if m:
            count, items = for_items(m.group(1), m.group(5))
            found.append(("for", (m.group(4), count, items), m.group(0)))
            rest = t[m.end():]
            continue
        m = re.match(r"(?i)call\s*:\s*([^\s&|<>()]+)", t)
        if m:
            found.append(("call", m.group(1).lower(), m.group(0)))
            return found, t[m.end():]
        m = re.match(r"(?i)call\s+", t)
        if m:
            rest = t[m.end():]
            continue
        op = first_operator(t)
        if op is None:
            return found, t
        pos, sym = op
        if sym in ("&&", "||"):
            found.append(("cond", sym, t[:pos + len(sym)]))
        rest = t[pos + len(sym):]
    return found, rest


def opens_block(head):
    h = head.rstrip()
    if not h.strip():
        return True
    if re.search(r"(?i)(?:^|[\s)])(?:do|in|else)$", h):
        return True
    if h.endswith(("&", "|")):
        return True
    found, rest = parse_wrappers(h)
    return bool(found) and not rest.strip()


def scan(txt, stack, idx, stop=None):
    """Paren-scan txt from stack; returns (open blocks, text after the last open paren)."""
    st = list(stack)
    segs = []
    seg = 0
    ignored = 0
    popped = None
    quoted = False
    end = len(txt) if stop is None else min(stop, len(txt))
    for i in range(end):
        c = txt[i]
        if c == '"':
            quoted = not quoted
        elif quoted:
            continue
        elif c == "(":
            head = txt[seg:i]
            if opens_block(head):
                if popped is not None and re.fullmatch(r"(?i)\s*\)?\s*else\s*", head):
                    head = popped[0]
                st.append((head, idx))
                segs.append(seg)
                seg = i + 1
            else:
                ignored += 1
        elif c == ")":
            if ignored:
                ignored -= 1
            elif st:
                popped = st.pop()
                seg = segs.pop() if segs else i + 1
    return st, txt[seg:end]


def build(body):
    rows = []
    stack = []
    for no, raw in logical_lines(body):
        txt = decaret(raw)
        kind, label = line_kind(txt)
        if kind == "label":
            stack = []
        rows.append({"no": no, "txt": txt, "kind": kind, "label": label, "stack": list(stack)})
        if kind == "cmd":
            stack, tail = scan(txt, stack, len(rows) - 1)
    return rows


def context(rows, idx, pos):
    r = rows[idx]
    return scan(r["txt"], r["stack"], idx, pos)


def wrappers_of(st, prefix):
    out = []
    for head, li in st:
        out.extend(parse_wrappers(head)[0])
    out.extend(parse_wrappers(prefix)[0])
    return out


def var_pattern(v):
    pct = "%%" if v.startswith("%%") else "%"
    return re.compile(re.escape(pct) + r"(?:~[A-Za-z$:]*?)?" + re.escape(v[-1]))


def effective(wrappers, value=""):
    out = []
    for kind, info, src in wrappers:
        if kind == "for":
            if info[1] != 1 or (value and var_pattern(info[0]).search(value)):
                continue
        elif kind == "call":
            continue
        elif ENVELOPE.search(src):
            continue
        out.append((kind, info, src))
    return out


# ---------------------------------------------------------------- variables

def refs_in(s):
    return [(mm.group(1) or mm.group(2) or mm.group(3) or "").lower() for mm in REF.finditer(s)]


def assignment(txt, e):
    t = txt[e:]
    if t.startswith('"'):
        m = re.match(r'"([^"=]+)=(.*?)"(?=\s*(?:$|[&|)<>]))', t) or re.match(r'"([^"=]+)=(.*)"', t)
    else:
        m = re.match(r'([^\s="&|<>()]+)=([^&|]*)', t)
    if m is None:
        return None
    return m.group(1).strip(), m.group(2)


def apply_modifier(val, full):
    inner = full.strip("%!")
    if ":" not in inner:
        return val
    mod = inner.split(":", 1)[1]
    if mod.startswith("~"):
        nums = re.findall(r"-?\d+", mod)
        if not nums:
            return val
        n = len(val)
        a = int(nums[0])
        if a < 0:
            a = max(n + a, 0)
        if len(nums) > 1:
            b = int(nums[1])
            return val[a:(n + b if b < 0 else a + b)]
        return val[a:]
    if "=" in mod:
        old, new = mod.split("=", 1)
        if old.startswith("*"):
            key = old[1:]
            pos = val.lower().find(key.lower()) if key else -1
            return val if pos < 0 else new + val[pos + len(key):]
        if not old:
            return val
        return re.sub(re.escape(old), lambda x: new, val, flags=re.I)
    return val


def resolve(tok, values, depth=0):
    def repl(mm):
        name = (mm.group(1) or mm.group(2) or mm.group(3) or "").lower()
        if name not in values:
            return "\x00"
        return apply_modifier(values[name], mm.group(0))
    out = REF.sub(repl, tok)
    if "\x00" in out:
        return None
    if REF.search(out) and depth < 3:
        return resolve(out, values, depth + 1)
    return out


def expand_for(value, used):
    outs = [value]
    for v, items in used[:3]:
        pat = var_pattern(v)
        nxt = []
        for o in outs:
            for it in items[:16]:
                rep = it.strip('"')
                nxt.append(pat.sub(lambda mm, rep=rep: rep, o))
        outs = nxt[:64] or outs
    return outs


def collect(rows):
    sets = []
    assigned = {}
    values = {}
    for i, r in enumerate(rows):
        if r["kind"] != "cmd":
            continue
        t = r["txt"]
        for m in SET_AT.finditer(t):
            asg = assignment(t, m.end())
            if asg is None:
                continue
            st, prefix = context(rows, i, m.start())
            pwr, rest = parse_wrappers(prefix)
            if rest.strip():
                continue
            name, value = asg
            key = name.lower()
            assigned.setdefault(key, set()).add(i)
            if m.group(1):
                continue
            values[key] = value
            sets.append({"idx": i, "pos": m.start(), "name": name, "value": value,
                         "stack": st, "wrappers": wrappers_of(st, prefix)})
    return sets, assigned, values


# ---------------------------------------------------------------- labels

def label_index(rows, name):
    for j, r in enumerate(rows):
        if r["kind"] == "label" and r["label"] == name:
            return j
    return -1


def goto_target(txt, values):
    m = GOTO_AT.match(txt)
    if m is None:
        return None
    tok = m.group(1)
    if "%" in tok or "!" in tok:
        tok = resolve(tok, values) or ""
    tok = tok.strip().lstrip(":").lower()
    return tok or None


def falls_into(rows, label_idx, values):
    """True when straight-line flow reaches the label without any GOTO/CALL."""
    p = label_idx - 1
    while p >= 0 and rows[p]["kind"] != "cmd":
        p -= 1
    if p < 0:
        return True
    r = rows[p]
    if r["stack"] or not JUMP.match(r["txt"]):
        return True
    tgt = goto_target(r["txt"], values)
    if tgt:
        k = label_index(rows, tgt)
        return p < k <= label_idx
    return False


def find_refs(rows, label, values):
    pat = re.compile(r"(?i)(?<![\w])(?:(call)\s*:\s*|(goto)\s*:?\s*)" + re.escape(label) + r"(?![\w#$.\-])")
    out = []
    for j, r in enumerate(rows):
        if r["kind"] != "cmd":
            continue
        t = r["txt"]
        for mm in pat.finditer(t):
            out.append((j, mm.start(), "call" if mm.group(1) else "goto", False))
        for mm in DYNAMIC.finditer(t):
            val = resolve(mm.group(2), values)
            if val and val.strip().lstrip(":").lower() == label:
                out.append((j, mm.start(), mm.group(1).lower(), True))
    return out


def region_end(rows, stmt_idx):
    for j in range(stmt_idx + 1, len(rows)):
        r = rows[j]
        if r["kind"] == "label":
            return j - 1
        if r["kind"] == "cmd" and not r["stack"] and JUMP.match(r["txt"]):
            return j
    return len(rows) - 1


def label_refs(rows, name, label_idx, end, values):
    hits = []
    env = 0
    for j, pos, kind, dyn in find_refs(rows, name, values):
        if label_idx <= j <= end:
            continue
        st, prefix = context(rows, j, pos)
        wr = wrappers_of(st, prefix)
        if any(k != "for" and ENVELOPE.search(src) for k, info, src in wr):
            env += 1
            continue
        eff = effective(wr)
        guards = [w for w in eff if w[0] != "for"]
        guard = KIND_ANSWER[guards[-1][0]] if guards else None
        if any(k == "for" for k, info, src in eff):
            verdict = "for_once"
        elif kind == "call":
            verdict = "call_subroutine"
        else:
            verdict = "goto_dispatch"
        hits.append((j, verdict, kind, dyn, guard))
    hits.sort(key=lambda h: h[0])
    return hits, env


def envelope_section(rows, i, values):
    for k in range(i - 1, -1, -1):
        if rows[k]["kind"] == "label":
            hits, env = label_refs(rows, rows[k]["label"], k, k, values)
            return env > 0 and not hits
    return False


def main_like(rows, label_idx, stmt_idx, known):
    want = set(known)
    seen = set()
    for j in range(label_idx + 1, stmt_idx):
        t = rows[j]["txt"]
        if rows[j]["kind"] != "cmd":
            continue
        for mm in SET_AT.finditer(t):
            asg = assignment(t, mm.end())
            if asg and asg[0].lower() in want:
                seen.add(asg[0].lower())
    return len(seen) >= max(2, (len(want) + 1) // 2)


# ---------------------------------------------------------------- analysis

def find_statement(rows):
    sets, assigned, values = collect(rows)
    best = None
    for s in sets:
        fors = [w[1] for w in s["wrappers"] if w[0] == "for"]
        feeding = [(v, items) for v, count, items in fors if var_pattern(v).search(s["value"])]
        names = set()
        for ev in expand_for(s["value"], [(v, items) for v, items in feeding if items]):
            names.update(refs_in(ev))
        key = s["name"].lower()
        names.discard(key)
        known = sorted(n for n in names if assigned.get(n, set()) - {s["idx"]})
        if len(known) < 2:
            continue
        uses = sum(1 for j, r in enumerate(rows)
                   if j != s["idx"] and r["kind"] == "cmd" and key in refs_in(r["txt"]))
        env = any(ENVELOPE.search(h) for h, li in s["stack"]) or envelope_section(rows, s["idx"], values)
        s["known"] = known
        s["indirect"] = bool(feeding)
        rank = (0 if env else 1, len(known), uses, s["idx"])
        if best is None or rank > best[0]:
            best = (rank, s)
    return (best[1] if best else None), values


def dynamic_fallback(rows, barrier_no):
    kinds = set()
    for r in rows:
        if r["kind"] == "cmd":
            for mm in DYNAMIC.finditer(r["txt"]):
                kinds.add(mm.group(1).lower())
    if "goto" in kinds:
        return (["goto_dispatch", "direct"],
                f"the statement follows the unconditional transfer on line {barrier_no} and is reached by a computed goto", 0.9)
    if "call" in kinds:
        return (["call_subroutine", "direct"],
                f"the statement follows the unconditional transfer on line {barrier_no} and is reached by a computed call", 0.85)
    return (["direct", "goto_dispatch"], f"no static entry found past the transfer on line {barrier_no}", 0.8)


def flow(rows, start, stmt_idx, known, values):
    extras = []
    skipped = []
    j = start - 1
    while j >= 0:
        r = rows[j]
        if r["kind"] == "label" and r["label"] != "eof":
            name = r["label"]
            hits, env = label_refs(rows, name, j, region_end(rows, stmt_idx), values)
            strong = [h for h in hits if h[2] == "call" or h[1] == "for_once"]
            if hits and not strong and falls_into(rows, j, values):
                extras.append("goto_dispatch")
                skipped.append(f":{name}")
                j -= 1
                continue
            if hits:
                hj, verdict, kind, dyn, guard = strong[0] if strong else hits[0]
                via = f"{kind} :{name} on line {rows[hj]['no']}" + (" (computed target)" if dyn else "")
                if verdict == "goto_dispatch" and main_like(rows, j, stmt_idx, known):
                    return (dedupe(["direct", "goto_dispatch"] + extras),
                            f"label :{name} opens the main body that sets the fragments; {via} is an ordinary transfer", 0.9)
                if verdict == "for_once":
                    return (dedupe(["for_once", "call_subroutine"] + extras),
                            f"label :{name} is entered by a one-item FOR around {via}", 0.92)
                if verdict == "goto_dispatch":
                    return (dedupe(["goto_dispatch", guard, "direct"] + extras),
                            f"label :{name} is not reached by fall-through and is entered by {via}", 0.92)
                return (dedupe([verdict, guard] + extras), f"label :{name} is entered by {via}", 0.92)
            if env:
                return dedupe(["direct"] + extras), f"label :{name} is reached only from the host envelope", 0.9
        elif r["kind"] == "cmd" and not r["stack"]:
            t = r["txt"]
            if JUMP.match(t):
                tgt = goto_target(t, values)
                k = label_index(rows, tgt) if tgt else -1
                if j < k < stmt_idx:
                    j -= 1
                    continue
                ranked, why, conf = dynamic_fallback(rows, r["no"])
                return dedupe(ranked + extras), why, conf
            wr, rest = parse_wrappers(t.strip())
            eff = [w for w in effective(wr) if w[0] != "for"]
            gm = re.search(r"(?i)(?<![\w])(?:goto\s*:?\s*([^\s&|<>()]+)|exit(?![\w]))", rest)
            if eff and gm:
                tgt = (gm.group(1) or "eof").lstrip(":").lower()
                if tgt == "eof" or label_index(rows, tgt) > stmt_idx:
                    return (dedupe([KIND_ANSWER[eff[-1][0]]] + extras),
                            f"line {r['no']} conditionally jumps past the statement", 0.9)
        j -= 1
    note = "the statement runs in straight-line flow from the top of the script"
    if skipped:
        note += f" (goto into {', '.join(skipped)} is an ordinary transfer: that label is reached by fall-through)"
    return dedupe(["direct"] + extras), note, 0.93


def classify(rows, stmt, values):
    i = stmt["idx"]
    ranked = []
    why = ""
    conf = 0.0
    eff = effective(stmt["wrappers"], stmt["value"])
    if eff:
        kind, info, src = eff[-1]
        ranked.append(KIND_ANSWER[kind])
        why = f"inline wrapper '{clean(src.strip())}' guards the statement"
        conf = 0.92
    start = stmt["stack"][0][1] if stmt["stack"] else i
    franked, fwhy, fconf = flow(rows, start, i, stmt["known"], values)
    ranked = dedupe(ranked + franked)
    if not why:
        why, conf = fwhy, fconf
    return ranked, why, conf


def control_question(q):
    raw = q.raw if isinstance(q.raw, dict) else {}
    fmt = raw.get("answer_format") or {}
    acc = [str(x) for x in (fmt.get("accepted_values") or [])] if isinstance(fmt, dict) else []
    if acc:
        return acc if ("goto_dispatch" in acc and "for_once" in acc) else None
    hay = q.haystack or ""
    if "control-flow wrapper" in hay and "reconstruction" in hay:
        return list(CHOICES)
    return None


def skeleton(rows):
    shown = 0
    for row in rows:
        t = row["txt"].strip()
        if row["kind"] == "label" or re.search(r"(?i)(?<![\w])(?:goto|call|if|for|exit|ver)(?![\w])|&&|\|\|", t):
            print(f"{TAG}   {row['no']:>4} d{len(row['stack'])} {clean(t)[:150]}")
            shown += 1
            if shown >= 50:
                break


@handler(priority=1, challenges=(r"(?i).*(?:script-analysis|batch|expansion).*",))
def batch_control_wrapper(q, ctx):
    accepted = control_question(q)
    if not accepted:
        return None
    m = target(q, ctx)
    if m is None:
        print(f"{TAG} {q.id}: no target member")
        return None
    try:
        body = text(m) or ""
    except Exception as exc:
        print(f"{TAG} {q.id}: unreadable {m.path}: {exc}")
        return None
    name = (m.basename or "").lower()
    if not (name.endswith((".bat", ".cmd")) or re.search(r"(?im)^\s*@?echo\s+off\b", body)):
        print(f"{TAG} {q.id}: {m.path} is not a batch script")
        return None
    try:
        rows = build(body)
        stmt, values = find_statement(rows)
        if stmt is None:
            print(f"{TAG} {q.id}: no fragment reconstruction statement found in {m.path}")
            return None
        ranked, why, conf = classify(rows, stmt, values)
    except Exception as exc:
        print(f"{TAG} {q.id}: analysis failed on {m.path}: {exc}")
        return None
    raw = q.raw if isinstance(q.raw, dict) else {}
    refused = {str(x).strip() for x in (raw.get("refused_by_game_master") or [])}
    acting = bool(refused) or conf >= 0.9
    srow = rows[stmt["idx"]]
    print(f"{TAG} {q.id} {m.path} line {srow['no']} indirect={stmt['indirect']} ranked={ranked} "
          f"conf={conf} refused={sorted(refused)} acting={acting}: {why}")
    if stmt["indirect"] or refused:
        print(f"{TAG}   statement: {clean(srow['txt'].strip())[:200]}")
        skeleton(rows)
    if not acting:
        return None
    choice = next((x for x in ranked if x in accepted and x not in refused), None)
    if choice is None:
        return None
    if choice != ranked[0]:
        conf = min(conf, 0.8)
        why = f"{ranked[0]} was refused; next structural reading: {why}"
    evidence = f"reconstruction of {stmt['name']} on line {srow['no']} of {m.path}: {why}"
    return answer(choice, evidence, conf, subject=m)
