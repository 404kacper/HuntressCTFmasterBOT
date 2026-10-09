"""Where the Game Master lives and how we authenticate to it.

The token is only ever read from the environment (or a file the environment
points at). It is never written to disk, logged, or put in the archive.
"""
from __future__ import annotations

import os
from pathlib import Path

DIRECT_URL = "https://2026.huntress.ctf.games/"
PROXY_URL = "http://10.0.0.219/huntress-ctf-proxy"  # only reachable from Homebase / VPN

_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


def load_token() -> str | None:
    tok = os.environ.get("HUNTRESS_GM_TOKEN")
    if not tok:
        path = os.environ.get("HUNTRESS_GM_TOKEN_FILE")
        if path:
            tok = Path(path).expanduser().read_text(encoding="utf-8").strip()
    return tok or None


def base_url(token: str | None) -> str:
    explicit = os.environ.get("HUNTRESS_GM_URL") or os.environ.get("GM")
    if explicit:
        return explicit
    return DIRECT_URL if token else PROXY_URL


def proxy_env_present() -> bool:
    """requests' proxy discovery is slow on Windows (registry lookups on every
    request). Only pay for it when a proxy is actually configured."""
    return any(os.environ.get(v) for v in _PROXY_VARS) or bool(os.environ.get("REQUESTS_CA_BUNDLE"))
