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
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from . import config
from .model import utcnow


class GMError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, data=None, transport: bool = False):
        super().__init__(message)
        self.status = status
        self.data = data
        self.transport = transport  # True: we never got an answer (timeout, reset, ...)


def _transport_error(e: Exception, what: str = "", seconds: float | None = None) -> GMError:
    # Only the type name: some requests errors embed header values (the token).
    detail = f" after {seconds:.1f}s" if seconds is not None else ""
    return GMError(f"network error: {type(e).__name__}{detail}{' (' + what + ')' if what else ''}", transport=True)


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
                 timeout: float = 20.0, prepare_timeout: float = 180.0):
        if token is None:
            token = config.load_token()
        self.base = base_url or config.base_url(token)
        parts = urlsplit(self.base)
        self.scheme, self.host = parts.scheme, parts.netloc
        self.prefix = parts.path.rstrip("/")  # '' for the direct host, '/huntress-ctf-proxy' on Homebase
        self.timeout = timeout
        # start/retry can wait while the Game Master prepares a fresh variant;
        # that wait is not on the clock, so give it room instead of giving up.
        self.prepare_timeout = prepare_timeout
        self.clock_offset: float | None = None  # server clock minus ours, seconds (from Date headers)
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
    def _note_server_time(self, r: requests.Response) -> None:
        date = r.headers.get("Date")
        if not date:
            return
        try:
            self.clock_offset = (parsedate_to_datetime(date) - utcnow()).total_seconds()
        except (TypeError, ValueError):
            pass

    def server_now(self) -> datetime:
        """The Game Master's idea of 'now' (local clock + offset from its Date header)."""
        return utcnow() + timedelta(seconds=self.clock_offset or 0.0)

    def _decode(self, r: requests.Response):
        self._note_server_time(r)
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

    def post(self, body: dict, timeout: float | None = None, **params):
        params = {k: v for k, v in params.items() if v is not None}
        what = str(body.get("op") or ("submit" if "answers" in body else "start"))
        t = time.perf_counter()
        try:
            r = self.s.post(self.base, params=params or None, json=body,
                            timeout=(min(10.0, self.timeout), timeout or self.timeout))
        except requests.RequestException as e:
            raise _transport_error(e, what, time.perf_counter() - t) from None
        return self._decode(r)

    def warm(self, challenge: str | None = None, extra_urls: tuple[str, ...] = ()) -> None:
        """Open (and keep alive) the connections the timed path will use."""
        try:
            r = self.s.get(self.base, params={"op": "status", "challenge": challenge} if challenge
                           else {"op": "list"}, timeout=self.timeout)
            r.content
            self._note_server_time(r)
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
        return self.post(body, timeout=self.prepare_timeout)

    def retry(self, challenge: str, run_for_time: bool | None = None) -> dict:
        body: dict = {"op": "retry", "challenge": challenge}
        if run_for_time is not None:
            body["run_for_time"] = bool(run_for_time)
        return self.post(body, timeout=self.prepare_timeout)

    def practice(self, challenge: str) -> dict:
        return self.post({"op": "practice", "challenge": challenge}, timeout=self.prepare_timeout)

    def submit(self, challenge: str, answers: dict[str, str]) -> dict:
        # Every answer goes over the wire as a string ("240", not 240).
        return self.post({"challenge": challenge,
                          "answers": {str(k): str(v) for k, v in answers.items()}})

    def download_url(self, download: str | None) -> str | None:
        """Absolute URL for the reply's download link, or None to use the
        documented op=artifact on the base URL instead. Behind a proxy that
        lives under a path (Homebase: http://10.0.0.219/huntress-ctf-proxy) a
        root-relative link such as '/artifact/x' resolves outside the proxy and
        404s, so there the documented operation is used from the start."""
        if not download:
            return None
        url = urljoin(self.base, download)
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc) == (self.scheme, self.host) and self.prefix \
                and parts.path.rstrip("/") != self.prefix and not parts.path.startswith(self.prefix + "/"):
            return None
        return url

    def _fetch(self, challenge: str, url: str | None) -> requests.Response:
        t = time.perf_counter()
        try:
            if url is None:
                return self.s.get(self.base, params={"op": "artifact", "challenge": challenge},
                                  timeout=self.timeout)
            # Never hand our bearer token to anything but the Game Master itself.
            same = (urlsplit(url).scheme, urlsplit(url).netloc) == (self.scheme, self.host)
            return self.s.get(url, timeout=self.timeout, headers=None if same else {"Authorization": None})
        except requests.RequestException as e:
            raise _transport_error(e, "artifact download", time.perf_counter() - t) from None

    def artifact(self, challenge: str, download: str | None = None) -> Download:
        t = time.perf_counter()
        url = self.download_url(download)
        r = self._fetch(challenge, url)
        if r.status_code == 404 and url is not None:
            # The link does not work from where we are; the documented operation is the fallback.
            r = self._fetch(challenge, None)
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
