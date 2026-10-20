# learned-module: batch_descriptor_plan
"""Statically reconstruct the pipe-delimited behavior descriptor in Huntress
batch-expansion specimens, then answer role, ATT&CK, indicator, expansion,
control-flow, and graph questions. The parser never executes the script.
"""
import re

from hunt.learn.kit import answer, target, text
from hunt.solvers import handler


_LABEL = re.compile(r"^\s*:([A-Za-z_][A-Za-z0-9_]*)\b", re.I)
_SET_ANY = re.compile(
    r"\b(?:(call)\s+)?set\s+(?:\"([^\"=]+)=([^\"]*)\"|([A-Za-z_][A-Za-z0-9_]*)=(.*))",
    re.I,
)
_FOR = re.compile(
    r"\bfor\s+(?:/([A-Za-z])\s+)?%%([A-Za-z])\s+in\s*\(([^)]*)\)\s*do\s+(.*)$",
    re.I,
)
_GOTO = re.compile(r"\bgoto\s+:([A-Za-z_][A-Za-z0-9_]*)\b", re.I)
_CALLSUB = re.compile(r"\bcall\s+:([A-Za-z_][A-Za-z0-9_]*)\b", re.I)

_KNOWN = {
    "v", "steps", "adapter", "stage_count", "graph", "next_language",
    "campaign_id", "host_id", "url", "file_path", "source_path",
    "upload_url", "extension", "note_name", "next_stage",
}
_ASPECTS = (
    "upload-url", "next-stage", "file-path", "note-name", "host-id",
    "expansion", "control", "campaign", "adapter", "attack", "graph",
    "role", "url", "path", "note", "host",
)
_FIELDS = {
    "adapter": ("adapter", "tool", "lolbin", "interpreter"),
    "campaign": ("campaign_id", "campaign", "cid"),
    "host-id": ("host_id", "hostid", "host"),
    "host": ("host_id", "hostid", "host"),
    "url": ("url", "uri", "download_url", "fetch_url"),
    "upload-url": ("upload_url", "upload_uri", "exfil_url"),
    "file-path": ("file_path", "filepath", "path", "output_path", "output"),
    "path": ("file_path", "filepath", "path", "output_path", "output"),
    "note-name": ("note_name", "note", "recovery_note", "ransom_note"),
    "note": ("note_name", "note", "recovery_note", "ransom_note"),
    "next-stage": ("next_stage", "nextstage", "next_script", "handoff"),
}


class _Set:
    def __init__(self, line_no, line, name, raw, is_call, wrapper=""):
        self.line_no = line_no
        self.line = line
        self.name = name.lower()
        self.raw = raw
        self.is_call = bool(is_call)
        self.wrapper = wrapper
        self.value = ""


def _lines(src):
    return src.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _inspect_bounds(lines):
    start = 0
    end = len(lines)
    for i, line in enumerate(lines):
        m = _LABEL.match(line)
        if m and m.group(1).lower() == "huntress_inspect":
            start = i + 1
            break
    for i in range(start, len(lines)):
        m = _LABEL.match(lines[i])
        if m and m.group(1).lower() in ("huntress_plan", "huntress_unused"):
            end = i
            break
    return start, end


def _unescape(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == "^" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _strip_inline_rem(s):
    quoted = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "^" and i + 1 < len(s):
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch == "&":
            rest = s[i + 1:].lstrip()
            if rest.lower().startswith("rem") and (
                len(rest) == 3 or rest[3].isspace()
            ):
                return s[:i].rstrip()
        i += 1
    return s.rstrip()


def _set_match(line):
    m = _SET_ANY.search(line)
    if not m:
        return None
    name = m.group(2) if m.group(2) is not None else m.group(4)
    raw = m.group(3) if m.group(3) is not None else m.group(5)
    if raw is None:
        raw = ""
    if m.group(3) is None:
        raw = _strip_inline_rem(raw)
    return name, raw, bool(m.group(1))


def _apply_modifier(value, modifier):
    if not modifier:
        return value
    modifier = modifier.strip()
    if modifier.startswith("~"):
        m = re.match(r"~\(?(-?\d+)(?:,(-?\d+))?\)?", modifier)
        if not m:
            return value
        try:
            start = int(m.group(1))
            if m.group(2) is None:
                return value[start:]
            length = int(m.group(2))
            if length >= 0:
                return value[start:start + length]
            return value[start:length]
        except (ValueError, IndexError):
            return value
    if "=" in modifier:
        old, new = modifier.split("=", 1)
        if old:
            return value.replace(old, new)
    return value


def _lookup(env, name, modifier=None):
    return _apply_modifier(env.get(name.lower(), ""), modifier)


def _expand_percent(expr, env):
    def sub(m):
        return _lookup(env, m.group(1), m.group(2))
    return re.sub(
        r"%([A-Za-z_][A-Za-z0-9_]*)(?::([^%]*))?%",
        sub,
        expr,
    )


def _expand_delayed(expr, env):
    def sub(m):
        inner = m.group(1)
        mm = re.match(r"([A-Za-z_][A-Za-z0-9_]*)(?::(.*))?$", inner)
        if not mm:
            return m.group(0)
        return _lookup(env, mm.group(1), mm.group(2))
    return re.sub(r"!([^!\r\n]+)!", sub, expr)


def _expand_call(expr, env):
    def sub(m):
        return _lookup(env, m.group(1), m.group(2))
    old = None
    out = expr
    for _ in range(3):
        if out == old:
            break
        old = out
        out = re.sub(
            r"%%([A-Za-z_][A-Za-z0-9_]*)(?::([^%]*))?%%",
            sub,
            out,
        )
    return out


def _expand(expr, env, is_call):
    if is_call:
        return _unescape(_expand_call(expr, env))
    return _unescape(_expand_delayed(_expand_percent(expr, env), env))


def _for_tokens(flag, inner):
    if flag and flag.lower() == "l":
        nums = [int(x) for x in re.findall(r"-?\d+", inner)]
        if len(nums) != 3 or nums[1] == 0:
            return []
        start, step, stop = nums
        end = stop + (1 if step > 0 else -1)
        return [str(n) for n in range(start, end, step)][:512]
    if flag:
        return []
    out = []
    for m in re.finditer(r'"([^"]*)"|(\S+)', inner):
        out.append(m.group(1) if m.group(1) is not None else m.group(2))
    return out[:512]


def _self_wrapper(line):
    low = line.lower()
    if _FOR.search(line):
        return "for_once"
    if re.search(r"\bif\b", low):
        if "errorlevel" in low:
            return "errorlevel_guard"
        return "if_guard"
    return ""


def _parse_sets(lines, start, end):
    env = {}
    sets = []
    labels = {}
    for i in range(start, end):
        m = _LABEL.match(lines[i])
        if m:
            labels[m.group(1).lower()] = i
    for i in range(start, end):
        line = lines[i].strip()
        low = line.lower()
        if not line or low.startswith("rem ") or line.startswith("::"):
            continue
        fm = _FOR.search(line)
        if fm:
            body = fm.group(4).strip()
            sub = _set_match(body)
            if sub:
                name, raw, is_call = sub
                wrapper = "for_once"
                var = fm.group(2)
                pat = re.compile(r"%%" + re.escape(var) + r"(?![A-Za-z0-9_])", re.I)
                for token in _for_tokens(fm.group(1), fm.group(3)):
                    item = _Set(i, line, name, pat.sub(token, raw), is_call, wrapper)
                    item.value = _expand(item.raw, env, item.is_call)
                    env[item.name] = item.value
                    sets.append(item)
            continue
        sub = _set_match(line)
        if not sub:
            continue
        name, raw, is_call = sub
        item = _Set(i, line, name, raw, is_call, _self_wrapper(line))
        item.value = _expand(raw, env, is_call)
        env[item.name] = item.value
        sets.append(item)
    return sets, labels


def _descriptor(text_value):
    if not text_value or "|" not in text_value:
        return None
    out = {}
    for part in text_value.split("|"):
        if "=" not in part:
            return None
        key, value = part.split("=", 1)
        key = key.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            return None
        out[key] = value.strip()
    if "steps" not in out or not out["steps"]:
        return None
    if len(set(out) & _KNOWN) < 4:
        return None
    return out


def _score(desc, item):
    keys = set(desc)
    score = len(keys & _KNOWN) * 100 + len(desc.get("steps", ""))
    if "campaign_id" in keys:
        score += 20
    if "adapter" in keys:
        score += 10
    if item.wrapper == "for_once" and desc.get("steps", "").count(",") >= 1:
        score += 1
    return score


def _find_descriptor(sets):
    best = None
    best_desc = None
    best_score = -1
    for item in sets:
        desc = _descriptor(item.value)
        if desc is None:
            continue
        score = _score(desc, item)
        if score > best_score:
            best = item
            best_desc = desc
            best_score = score
    return best_desc, best


def _steps(desc):
    value = desc.get("steps", "")
    return [x.strip().lower() for x in value.split(",") if x.strip()]


def _role(steps):
    terminal = steps[-1] if steps else ""
    if terminal == "return_configuration":
        return "benign_utility"
    if terminal == "handoff_script":
        return "staged_chain"
    if terminal == "dispatch_next_stage":
        return "relay"
    if terminal in ("upload_remote", "transmit_remote"):
        return "uploader"
    if terminal == "write_recovery_note":
        return "impact"
    if terminal == "register_descriptor":
        return "persistence_descriptor"
    if terminal in ("dispatch_memory", "dispatch_pipe"):
        return "stager"
    if terminal == "dispatch_process":
        if any(x in steps for x in (
            "acquire_remote", "profile_host", "write_file", "decode_embedded",
            "change_mode",
        )):
            return "staged_chain"
        return "launcher"
    if terminal == "write_file":
        if "decode_embedded" in steps:
            return "dropper"
        return "downloader"
    if "acquire_remote" in steps:
        return "downloader"
    return "benign_utility"


def _attack(role):
    table = {
        "benign_utility": ("none", []),
        "stager": ("T1105", ["T1620"]),
        "dropper": ("T1140", []),
        "downloader": ("T1105", []),
        "uploader": ("T1041", []),
        "launcher": ("T1059.003", ["T1059"]),
        "impact": ("T1486", []),
        "staged_chain": ("T1059.003", ["T1059", "T1105"]),
        "relay": ("T1059.003", ["T1059", "T1105", "none"]),
        "persistence_descriptor": ("T1053.005", ["T1053"]),
    }
    return table.get(role, ("none", []))


def _expansion(item):
    line = item.line.strip()
    raw = item.raw
    if _FOR.search(line):
        return "for_indirect"
    if re.search(r"![A-Za-z_][A-Za-z0-9_]*(?:[^!]*)!", raw):
        return "delayed"
    if item.is_call and re.search(r"%%[A-Za-z_][A-Za-z0-9_]*(?:[^%]*)%%", raw):
        return "call_double"
    if re.search(r"%[A-Za-z_][A-Za-z0-9_]*(?:[^%]*)%", raw):
        return "percent"
    return "percent"


def _control(item, lines, labels, start, end):
    if item.wrapper in ("for_once", "if_guard", "errorlevel_guard"):
        return item.wrapper
    line_no = item.line_no
    containing = None
    for name, idx in labels.items():
        if idx < line_no:
            containing = (idx, name)
    if containing is not None:
        label_idx, label_name = containing
        for i in range(start, label_idx):
            low = lines[i].lower()
            if _CALLSUB.search(low) and _CALLSUB.search(low).group(1).lower() == label_name:
                if _FOR.search(lines[i]):
                    return "for_once"
                return "call_subroutine"
    best = None
    for i in range(start, line_no):
        m = _GOTO.search(lines[i])
        if not m:
            continue
        target_name = m.group(1).lower()
        if target_name == "huntress_inspect":
            continue
        target_idx = labels.get(target_name)
        if target_idx is not None and i < target_idx <= line_no:
            best = "goto_dispatch"
    if best:
        return best
    low = lines[line_no].lower()
    if "errorlevel" in low:
        return "errorlevel_guard"
    return "direct"


def _aspect(q):
    qid = (q.id or "").lower()
    for suffix in _ASPECTS:
        if qid.endswith("-" + suffix):
            return suffix
    hay = q.haystack
    if "expansion form" in hay:
        return "expansion"
    if "control-flow wrapper" in hay:
        return "control"
    if "stage-graph topology" in hay:
        return "graph"
    if "terminal intent" in hay or "behavior graph" in hay:
        return "role"
    if "mitre" in hay or "att&ck" in hay or "technique" in hay:
        return "attack"
    if "host_id" in hay or "host id" in hay:
        return "host-id"
    if "upload_url" in hay or ("upload" in hay and "url" in hay):
        return "upload-url"
    if "file_path" in hay or "file path" in hay:
        return "file-path"
    if "next_stage" in hay or "next stage" in hay:
        return "next-stage"
    if "note_name" in hay or "note name" in hay:
        return "note-name"
    if "campaign" in hay:
        return "campaign"
    if "adapter" in hay:
        return "adapter"
    if "url" in hay:
        return "url"
    return ""


@handler(priority=50, challenges=(r"script-analysis-day-03-batch-expansion.*",))
def batch_descriptor(q, ctx):
    if not (q.id or "").lower().startswith("batch-"):
        return None
    member = target(q, ctx)
    if member is None or not member.basename.lower().endswith((".cmd", ".bat")):
        return None
    src = text(member)
    if not src:
        return None
    aspect = _aspect(q)
    if not aspect:
        return None

    lines = _lines(src)
    start, end = _inspect_bounds(lines)
    sets, labels = _parse_sets(lines, start, end)
    desc, item = _find_descriptor(sets)
    if desc is None or item is None:
        return None
    steps = _steps(desc)
    role = _role(steps)

    if aspect == "role":
        return answer(
            role,
            "terminal behavior step {} in reconstructed descriptor".format(
                steps[-1] if steps else "<missing>"
            ),
            0.95,
            subject=member,
        )
    if aspect == "attack":
        value, alternatives = _attack(role)
        return answer(
            value,
            "role {} mapped from ordered steps {}".format(role, ",".join(steps)),
            0.95,
            subject=member,
            alternatives=alternatives,
        )
    if aspect == "graph":
        value = desc.get("graph")
        if value:
            return answer(
                value,
                "graph field in reconstructed descriptor",
                0.95,
                subject=member,
            )
        return None
    if aspect == "expansion":
        return answer(
            _expansion(item),
            "descriptor reconstruction statement: {}".format(item.line.strip()[:120]),
            0.95,
            subject=member,
        )
    if aspect == "control":
        return answer(
            _control(item, lines, labels, start, end),
            "control wrapper for descriptor reconstruction on line {}".format(
                item.line_no + 1
            ),
            0.95,
            subject=member,
        )
    for key in _FIELDS.get(aspect, ()):
        value = desc.get(key)
        if value:
            return answer(
                value,
                "descriptor field {} reconstructed from {}".format(key, member.path),
                0.95,
                subject=member,
            )
    return None
