"""Pages a challenge prompt links to, fetched as artifacts.

Some orientation challenges have no download: the answer sits in a web page
the prompt names ("the flag is hidden in the page itself"). A browser would
load the page and the scripts it runs; this fetches the same bytes, without
running anything, so ordinary handlers can read them.

The session here is not the Game Master's: it carries no Authorization header,
no cookies from the Game Master, and never talks to the Game Master's host.
Fetches are bounded (count, bytes, same origin only), because a prompt is
untrusted text too.
"""
from __future__ import annotations

import json
import posixpath
import re
from urllib.parse import urljoin, urlsplit

import requests

from . import config
from .gm import Download

MAX_PAGES = 3
MAX_ASSETS = 80
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT = 20.0
_URL = re.compile(r"https?://[^\s<>\"'()\[\]{}]+")
_SCRIPT = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_NEXT_DATA = re.compile(r"""<script[^>]*id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>""", re.I | re.S)
_CHUNK = re.compile(r"""["'](static/[A-Za-z0-9_./\-]+\.js)["']""")


def prompt_urls(prompt: str, avoid_hosts: set[str]) -> list[str]:
    out = []
    for u in _URL.findall(prompt or ""):
        u = u.rstrip(".,;:!?")
        if urlsplit(u).netloc.lower() in avoid_hosts or u in out:
            continue
        out.append(u)
    return out[:MAX_PAGES]


class _Budget:
    def __init__(self):
        self.count = 0
        self.bytes = 0

    def allows(self) -> bool:
        return self.count < MAX_ASSETS and self.bytes < MAX_BYTES


def fetch_targets(prompt: str, avoid_hosts: set[str]) -> list[Download]:
    """Each linked page plus the same-origin scripts it loads (Next.js page chunks included)."""
    s = requests.Session()
    s.trust_env = config.proxy_env_present()
    s.headers["User-Agent"] = "Mozilla/5.0 (hunt; Huntress CTF solver)"
    budget = _Budget()
    out: list[Download] = []
    for n, url in enumerate(prompt_urls(prompt, avoid_hosts), start=1):
        page = _get(s, url, budget)
        if page is None:
            continue
        out.append(Download(page.content, page.url, f"page{n}.html", page.elapsed.total_seconds()))
        origin = urlsplit(page.url)
        html = page.text
        # The route's own chunks first: that is where client-rendered page content lives, and the
        # framework scripts every page shares come after, while the budget lasts.
        assets = _next_chunks(s, page.url, html, budget)
        assets += [urljoin(page.url, src) for src in _SCRIPT.findall(html)]
        seen: set[str] = set()
        queue = list(assets)
        while queue and budget.allows():
            a = queue.pop(0)
            if a in seen or urlsplit(a).netloc != origin.netloc:
                continue
            seen.add(a)
            r = _get(s, a, budget)
            if r is None:
                continue
            name = posixpath.basename(urlsplit(a).path) or f"asset{len(seen)}.js"
            out.append(Download(r.content, r.url, f"page{n}-assets/{name}", r.elapsed.total_seconds()))
            if "__turbopack_load_page_chunks__" in r.text or "__BUILD_MANIFEST" in r.text:
                queue += [urljoin(_next_root(page.url), c) for c in _CHUNK.findall(r.text)]
    return out


def _next_root(page_url: str) -> str:
    p = urlsplit(page_url)
    return f"{p.scheme}://{p.netloc}/_next/"


def _next_chunks(s: requests.Session, page_url: str, html: str, budget: _Budget) -> list[str]:
    """A Next.js page's own chunks, from the build manifest its __NEXT_DATA__ points at: the
    scripts a browser loads for this route, where client-rendered page content lives."""
    m = _NEXT_DATA.search(html)
    if not m:
        return []
    try:
        nd = json.loads(m.group(1))
    except ValueError:
        return []
    build, page = nd.get("buildId"), nd.get("page")
    if not isinstance(build, str) or not isinstance(page, str) or not re.fullmatch(r"[\w.\-]+", build):
        return []
    r = _get(s, urljoin(_next_root(page_url), f"static/{build}/_buildManifest.js"), budget)
    if r is None:
        return []
    entry = re.search(re.escape(json.dumps(page)) + r"\s*:\s*\[(.*?)\]", r.text, re.S)
    if not entry:
        return []
    return [urljoin(_next_root(page_url), c) for c in _CHUNK.findall(entry.group(1))]


def _get(s: requests.Session, url: str, budget: _Budget) -> requests.Response | None:
    if not budget.allows() or urlsplit(url).scheme not in ("http", "https"):
        return None
    budget.count += 1
    try:
        r = s.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None
    if r.status_code >= 400:
        return None
    budget.bytes += len(r.content)
    return r if budget.bytes <= MAX_BYTES else None
