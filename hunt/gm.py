"""Thin Game Master client.

One requests.Session for the whole run so TCP+TLS is negotiated once (warm()
does it before the clock starts). Every documented operation is a method;
nothing here knows about any particular challenge.
"""
from __future__ import annotations

import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from . import config


class GMError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, data=None, transport: bool = False):
        super().__init__(message)
        self.status = status
        self.data = data
        self.transport = transport  # True: we never got an answer (timeout, reset, ...)


def _transport_error(e: Exception) -> GMError:
    # Only the type name: some requests errors embed header values (the token).
    return GMError(f"network error: {type(e).__name__}", transport=True)


@dataclass
class Download:
    data: bytes
    url: str  # final URL after redirects
    filename: str | None  # from Content-Disposition / URL, if the server told us
    seconds: float
    redirects: int = 0  # each one may cost a fresh connection to another host


_CD_FILENAME = re.compile(r"""filename\*?\s*=\s*(?:UTF-8'')?["']?([^"';]+)""", re.I)


def _brief(data) -> str:
    if isinstance(data, dict):
        for key in ("error", "message", "detail", "result", "status"):
            if key in data:
                return f"{key}={data[key]!r}"
    return repr(data)[:300]


class GameMaster:
    def __init__(self, base_url: str | None = None, token: str | None = None,
                 timeout: float = 20.0):
        if token is None:
            token = config.load_token()
        self.base = base_url or config.base_url(token)
        parts = urlsplit(self.base)
        self.scheme, self.host = parts.scheme, parts.netloc
        self.timeout = timeout
        s = requests.Session()
        s.trust_env = config.proxy_env_present()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers["Accept"] = "application/json"
        if token:
            if self.scheme == "https" or parts.hostname in ("127.0.0.1", "localhost", "::1"):
                s.headers["Authorization"] = "Bearer " + token
            else:
                print(f"warning: not sending the token over plain HTTP to {self.host} "
                      "(the Homebase proxy needs no token)", file=sys.stderr)
        self.s = s

    # ---- transport -------------------------------------------------------
    def _decode(self, r: requests.Response):
        try:
            data = r.json()
        except ValueError:
            raise GMError(f"HTTP {r.status_code}: non-JSON reply: {r.text[:300]!r}", r.status_code)
        if r.status_code >= 400:
            raise GMError(f"HTTP {r.status_code}: {_brief(data)}", r.status_code, data)
        return data

    def get(self, **params):
        params = {k: v for k, v in params.items() if v is not None}
        try:
            r = self.s.get(self.base, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise _transport_error(e) from None
        return self._decode(r)

    def post(self, body: dict, **params):
        params = {k: v for k, v in params.items() if v is not None}
        try:
            r = self.s.post(self.base, params=params or None, json=body, timeout=self.timeout)
        except requests.RequestException as e:
            raise _transport_error(e) from None
        return self._decode(r)

    def warm(self, challenge: str | None = None, extra_urls: tuple[str, ...] = ()) -> None:
        """Open (and keep alive) the connections the timed path will use."""
        try:
            self.s.get(self.base, params={"op": "status", "challenge": challenge} if challenge
                       else {"op": "list"}, timeout=self.timeout).content
        except requests.RequestException:
            pass
        for url in extra_urls:
            if urlsplit(url).netloc == self.host or urlsplit(url).scheme not in ("http", "https"):
                continue
            try:
                self.s.head(url, timeout=self.timeout, headers={"Authorization": None})
            except requests.RequestException:
                pass

    # ---- documented operations ------------------------------------------
    def list(self, day: int | None = None, lane: str | None = None) -> list[dict]:
        data = self.get(op="list", day=day, lane=lane)
        return data.get("challenges", []) if isinstance(data, dict) else data

    def openapi(self):
        return self.get(op="openapi")

    def status(self, challenge: str) -> dict:
        return self.get(op="status", challenge=challenge)

    def start(self, challenge: str, run_for_time: bool | None = None) -> dict:
        body: dict = {"challenge": challenge}
        if run_for_time is not None:
            body = {"op": "start", "challenge": challenge, "run_for_time": bool(run_for_time)}
        return self.post(body)

    def retry(self, challenge: str, run_for_time: bool | None = None) -> dict:
        body: dict = {"op": "retry", "challenge": challenge}
        if run_for_time is not None:
            body["run_for_time"] = bool(run_for_time)
        return self.post(body)

    def practice(self, challenge: str) -> dict:
        return self.post({"op": "practice", "challenge": challenge})

    def submit(self, challenge: str, answers: dict[str, str]) -> dict:
        # Every answer goes over the wire as a string ("240", not 240).
        return self.post({"challenge": challenge,
                          "answers": {str(k): str(v) for k, v in answers.items()}})

    def artifact(self, challenge: str, download: str | None = None) -> Download:
        t = time.perf_counter()
        try:
            if download:
                url = urljoin(self.base, download)
                # Never hand our bearer token to anything but the Game Master itself.
                same = (urlsplit(url).scheme, urlsplit(url).netloc) == (self.scheme, self.host)
                r = self.s.get(url, timeout=self.timeout, headers=None if same else {"Authorization": None})
            else:
                r = self.s.get(self.base, params={"op": "artifact", "challenge": challenge},
                               timeout=self.timeout)
        except requests.RequestException as e:
            raise _transport_error(e) from None
        if r.status_code >= 400:
            try:
                data = r.json()
            except ValueError:
                data = r.text[:300]
            raise GMError(f"artifact download HTTP {r.status_code}: {_brief(data)}", r.status_code, data)
        return Download(r.content, r.url, _filename(r), time.perf_counter() - t, len(r.history))

    def artifacts(self, challenge: str, downloads: list[str]) -> list[Download]:
        if len(downloads) <= 1:
            return [self.artifact(challenge, downloads[0] if downloads else None)]
        with ThreadPoolExecutor(max_workers=min(8, len(downloads))) as pool:
            return list(pool.map(lambda d: self.artifact(challenge, d), downloads))


def _filename(r: requests.Response) -> str | None:
    m = _CD_FILENAME.search(r.headers.get("Content-Disposition", ""))
    if m:
        return unquote(m.group(1)).strip()
    last = unquote(urlsplit(r.url).path.rsplit("/", 1)[-1])
    return last if "." in last else None
