"""The static check every learned (Claude-written) handler passes before it runs.

Learned code is written from untrusted material: challenge artifacts can carry
prompt injection, and the advisor reads them. So a learned module is held to
pure computation on the bytes it is handed. This check is the first fence; the
sandbox worker (no token, no network, no file access: worker.py) is the second.
It is an allowlist: anything not named here is refused.
"""
from __future__ import annotations

import ast
import importlib
import re
import types

MAX_SOURCE = 200_000

# Standard-library modules learned code may import: computation on bytes and text.
ALLOWED_MODULES = frozenset({
    "base64", "binascii", "bisect", "bz2", "calendar", "codecs", "collections", "colorsys", "csv",
    "dataclasses", "datetime", "decimal", "difflib", "email", "email.header", "email.parser",
    "email.policy", "email.utils", "enum", "fractions", "functools", "gzip", "hashlib", "heapq",
    "hmac", "html", "html.parser", "io", "ipaddress", "itertools", "json", "lzma", "math",
    "operator", "plistlib", "quopri", "re", "statistics", "string", "struct", "tarfile",
    "textwrap", "typing", "unicodedata", "urllib.parse", "uuid", "xml.dom.minidom",
    "xml.etree.ElementTree", "zipfile", "zlib",
})

# The bot's own API, name by name (a module object would hand out its imports).
ALLOWED_HUNT = {
    "hunt.solvers": {"handler", "Answer", "Context"},
    "hunt.forensics.artifacts": {"ArtifactSet", "Member", "UnreadableMember", "norm_name", "container_kind"},
    "hunt.forensics.identity": {"digest", "true_type", "describe", "claims_in", "DIGESTS", "TEXT_EXTS"},
    "hunt.gate": {"format_problem", "normalize"},
    "hunt.model": {"Question", "Attempt"},
    "hunt.learn.kit": None,  # every public name
}

BANNED_NAMES = frozenset({
    "__import__", "eval", "exec", "compile", "open", "input", "breakpoint", "globals", "locals", "vars",
    "getattr", "setattr", "delattr", "help", "exit", "quit", "__builtins__", "__loader__", "__spec__",
    "__file__", "__dict__", "__class__",
})
# Attributes that reach frames, code, globals or dynamic attribute lookup.
BANNED_ATTRS = frozenset({
    "format_map", "mro", "attrgetter", "methodcaller", "get_type_hints", "ForwardRef", "Formatter",
    "open_code", "FileIO", "modules", "environ", "environb", "getenv", "system", "popen",
})
BANNED_ATTR_PREFIXES = ("_", "gi_", "cr_", "ag_", "f_", "tb_", "co_", "func_", "im_")
# Module-level functions that open files by name. Reading from bytes (fileobj=, BytesIO) stays fine.
BANNED_MODULE_ATTRS = {"io": {"open"}, "codecs": {"open", "EncodedFile"}}
_DUNDER = re.compile(r"__[A-Za-z_]\w*__")


class PolicyError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def check(source: str) -> list[str]:
    """Every reason this module may not run (empty list: it may)."""
    if len(source) > MAX_SOURCE:
        return [f"module is {len(source)} characters; the limit is {MAX_SOURCE}"]
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [f"syntax error line {e.lineno}: {e.msg}"]
    return _Checker().run(tree)


def require(source: str) -> None:
    problems = check(source)
    if problems:
        raise PolicyError(problems)


def _module(name: str) -> types.ModuleType | None:
    try:
        return importlib.import_module(name)
    except Exception:
        return None


class _Checker(ast.NodeVisitor):
    def __init__(self):
        self.problems: list[str] = []
        self.modules: dict[str, str] = {}  # local name -> module it is bound to
        self.module_uses: set[int] = set()  # ids of Name nodes used as `module.attr`
        self.has_handler = False

    def bad(self, node: ast.AST, why: str) -> None:
        self.problems.append(f"line {getattr(node, 'lineno', '?')}: {why}")

    def run(self, tree: ast.AST) -> list[str]:
        # Imports first, so module names are known wherever they are used.
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._import(node)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id in self.modules:
                self.module_uses.add(id(node.value))
        self.visit(tree)
        if not self.has_handler:
            self.problems.append("no @handler(...) function: the module would never be asked anything")
        return self.problems

    # ---- imports -----------------------------------------------------------
    def _import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in ALLOWED_MODULES:
                    self.bad(node, f"import {a.name} is not allowed (allowed: {', '.join(sorted(ALLOWED_MODULES))})")
                    continue
                if a.asname:
                    self.modules[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    if top not in ALLOWED_MODULES:
                        self.bad(node, f"write `import {a.name} as name` (the bare package {top} is not allowed)")
                    self.modules[top] = top
            return
        if node.level:
            self.bad(node, "relative imports are not allowed")
            return
        mod = node.module or ""
        if mod in ALLOWED_HUNT:
            allowed = ALLOWED_HUNT[mod]
            for a in node.names:
                if a.name == "*" or a.name.startswith("_") or (allowed is not None and a.name not in allowed):
                    self.bad(node, f"from {mod} import {a.name} is not allowed"
                             + (f" (allowed: {', '.join(sorted(allowed))})" if allowed else ""))
                elif allowed is None and isinstance(getattr(_module(mod), a.name, None), types.ModuleType):
                    self.bad(node, f"{mod}.{a.name} is a module")
            return
        if mod not in ALLOWED_MODULES:
            self.bad(node, f"from {mod} import ... is not allowed")
            return
        real = _module(mod)
        for a in node.names:
            if a.name == "*" or a.name.startswith("_"):
                self.bad(node, f"from {mod} import {a.name} is not allowed")
                continue
            if a.name in BANNED_ATTRS or a.name in BANNED_MODULE_ATTRS.get(mod, ()):
                self.bad(node, f"{mod}.{a.name} is not allowed")
                continue
            obj = getattr(real, a.name, None) if real else None
            if isinstance(obj, types.ModuleType):
                full = f"{mod}.{a.name}"
                if full not in ALLOWED_MODULES:
                    self.bad(node, f"{full} is not an allowed module")
                else:
                    self.modules[a.asname or a.name] = full

    # ---- names and attributes ---------------------------------------------
    def visit_Name(self, node: ast.Name) -> None:
        if node.id in BANNED_NAMES or (node.id.startswith("__") and node.id != "__name__"):
            self.bad(node, f"name {node.id!r} is not allowed")
        elif node.id in self.modules and id(node) not in self.module_uses \
                and not isinstance(node.ctx, ast.Store):
            self.bad(node, f"module {self.modules[node.id]} may only be used as `{node.id}.something`")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        attr = node.attr
        if attr.startswith(BANNED_ATTR_PREFIXES) or attr in BANNED_ATTRS:
            self.bad(node, f"attribute .{attr} is not allowed")
        elif attr == "format" and not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            self.bad(node, "only a literal template may call .format(); use an f-string")
        else:
            chain = self._static(node)
            if chain is not None:
                base, obj = chain
                if attr in BANNED_MODULE_ATTRS.get(base, ()):
                    self.bad(node, f"{base}.{attr} is not allowed")
                elif obj is _MISSING:
                    self.bad(node, f"{base} has no attribute {attr!r}")
                elif isinstance(obj, types.ModuleType) and obj.__name__ not in ALLOWED_MODULES:
                    self.bad(node, f"{obj.__name__} is not an allowed module")
        self.generic_visit(node)

    def _static(self, node: ast.Attribute):
        """(module name, object) when `node` is module.a.b... and resolvable."""
        parts = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if not (isinstance(cur, ast.Name) and cur.id in self.modules):
            return None
        base = self.modules[cur.id]
        obj = _module(base)
        if obj is None:
            return None
        for p in reversed(parts):
            if not isinstance(obj, (types.ModuleType, type)):
                return None  # an instance or function: not resolvable statically
            obj = getattr(obj, p, _MISSING)
            if obj is _MISSING:
                return base, _MISSING
        return base, obj

    def visit_Constant(self, node: ast.Constant) -> None:
        v = node.value
        text = v.decode("latin-1") if isinstance(v, bytes) else v if isinstance(v, str) else None
        if text is not None and text != "__main__" and _DUNDER.search(text):
            self.bad(node, "string constants may not name dunder attributes")

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Name) and f.id == "handler" or isinstance(f, ast.Attribute) and f.attr == "handler":
            self.has_handler = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node) -> None:
        for d in node.decorator_list:
            if isinstance(d, ast.Name) and d.id == "handler":
                self.has_handler = True
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Global(self, node) -> None:
        self.bad(node, "global statements are not allowed")


_MISSING = object()
