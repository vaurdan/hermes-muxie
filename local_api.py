"""The connector's local endpoints, client side (CONTRACT.md §1-§5; health: dist-s2s3 ``connector/CLI.md``).

The connector listens on 127.0.0.1 and writes ``connector-<id>.plugin.json`` (0600: ``{v, connectorId, url, token}``)
in its state dir. Every request goes straight to ``http://127.0.0.1:<port>`` with ``Authorization: Bearer <token>``,
never through a proxy from the environment (the token would go with it), and never with an ``Origin`` header.
A file whose URL is not ``http://127.0.0.1:<port>`` is ignored, so a tampered file cannot send the token elsewhere.
"""

from __future__ import annotations

import http.client
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .layout import Layout, connector_id

# Straight to 127.0.0.1: never through a proxy from the environment.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PLUGIN_VERSION = "0.1.0"
MAX_ANSWER = 1024 * 1024


@dataclass(frozen=True)
class Endpoint:
    url: str
    token: str
    connector_id: str
    file: Path


class LocalApiError(Exception):
    """No answer: refused, timed out, or not JSON. ``kind`` is ``down`` | ``timeout`` | ``bad_answer``."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(detail or kind)
        self.kind = kind


def private_file_ok(path: Path) -> bool:
    """Owned by this user and not readable or writable by group/others (0600 or stricter)."""
    try:
        st = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o077)


def read_endpoint(path: Path) -> Optional[Endpoint]:
    if not private_file_ok(path):
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict) or data.get("v") != 1:
        return None
    url, token = data.get("url"), data.get("token")
    if not isinstance(url, str) or not isinstance(token, str) or not token or len(token) > 512:
        return None
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if u.scheme != "http" or u.hostname != "127.0.0.1" or not port or u.path not in ("", "/"):
        return None
    cid = data.get("connectorId") if isinstance(data.get("connectorId"), str) else ""
    return Endpoint(url=f"http://127.0.0.1:{port}", token=token, connector_id=cid, file=path)


def health_files(layout: Layout) -> list[Path]:
    """The S2/S3 health token files (``connector-<id>.health.json``: ``{"v":1,"url","token","pid","version",
    "startedAt"}``, 0600)."""
    try:
        return sorted(layout.state.glob("connector-*.health.json"))
    except OSError:
        return []


def health_endpoints(layout: Layout) -> list[Endpoint]:
    want = f"connector-{connector_id(layout)}.health.json"
    found = [e for e in (read_endpoint(p) for p in health_files(layout)) if e is not None]
    return sorted(found, key=lambda e: (e.file.name != want, e.file.name))


def endpoints(layout: Layout) -> list[Endpoint]:
    """The token files in the state dir, the configured connector id first."""
    want = connector_id(layout)
    found = [e for e in (read_endpoint(p) for p in layout.endpoint_files()) if e is not None]
    return sorted(found, key=lambda e: (e.connector_id != want, e.connector_id))


def request(endpoint: Endpoint, method: str, path: str, body: Any = None, timeout: float = 2.0,
            profile: str = "") -> tuple[int, Any]:
    """One request; ``(status, parsed JSON or None)``. Raises :class:`LocalApiError` when nothing usable answers."""
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"authorization": f"Bearer {endpoint.token}",
               "x-muxie-plugin": f"muxie/{PLUGIN_VERSION}" + (f" profile={profile}" if profile else "")}
    if data is not None:
        headers["content-type"] = "application/json"
    req = urllib.request.Request(endpoint.url + path, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, _json(r.read(MAX_ANSWER + 1))
    except urllib.error.HTTPError as e:
        with e:
            try:
                return e.code, _json(e.read(MAX_ANSWER + 1))
            except OSError:
                return e.code, None
    except TimeoutError as e:
        raise LocalApiError("timeout", str(e)) from None
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        kind = "timeout" if isinstance(reason, TimeoutError) or "timed out" in str(reason) else "down"
        raise LocalApiError(kind, str(reason)) from None
    except http.client.HTTPException as e:  # something that is not HTTP answers on that port (a stale token file)
        raise LocalApiError("bad_answer", type(e).__name__) from None
    except (OSError, ValueError) as e:
        raise LocalApiError("down", f"{type(e).__name__}: {e}") from None


def _json(raw: bytes) -> Any:
    if len(raw) > MAX_ANSWER:
        return None
    try:
        return json.loads(raw.decode("utf-8") or "null")
    except (ValueError, UnicodeDecodeError):
        return None


@dataclass(frozen=True)
class Health:
    ok: bool
    detail: str
    endpoint: Optional[Endpoint] = None
    info: Optional[dict] = None  # the /v1/health answer (S2/S3)


def probe_health(endpoint: Endpoint, timeout: float = 2.0, profile: str = "") -> Health:
    """S2/S3: ``GET /v1/health`` on a ``.health.json`` endpoint → ``{"ok":true,"pid","version","startedAt",
    "relay":{"linked","since","connects"}}`` (dist-s2s3 ``connector/CLI.md`` «Health endpoint»)."""
    try:
        status, answer = request(endpoint, "GET", "/v1/health", timeout=timeout, profile=profile)
    except LocalApiError as e:
        return Health(False, f"nothing answers on {endpoint.url} ({e.kind}; {endpoint.file.name} is stale)", endpoint)
    if status == 200 and isinstance(answer, dict) and answer.get("ok"):
        relay = answer.get("relay") if isinstance(answer.get("relay"), dict) else {}
        link = "relay linked" if relay.get("linked") else "relay not linked yet"
        return Health(True, f"answers on {endpoint.url} (version {answer.get('version', '?')}, pid {answer.get('pid', '?')}, "
                            f"{link})", endpoint, answer)
    if status == 401:
        return Health(False, f"something on {endpoint.url} refuses the token in {endpoint.file.name} (a stale file?)", endpoint)
    return Health(False, f"something answers on {endpoint.url} (HTTP {status})", endpoint)


def probe(endpoint: Endpoint, timeout: float = 2.0, profile: str = "") -> Health:
    """S1: a connector answers on its plugin endpoint (``.plugin.json``) and accepts the token: ``POST /v1/ops
    {"v":0}``, which the endpoint refuses with 400 *after* checking the token, so nothing runs."""
    try:
        status, _ = request(endpoint, "POST", "/v1/ops", {"v": 0}, timeout=timeout, profile=profile)
    except LocalApiError as e:
        return Health(False, f"nothing answers on {endpoint.url} ({e.kind}; {endpoint.file.name} is stale)", endpoint)
    if status == 400:
        return Health(True, f"answers on {endpoint.url} (plugin endpoint; no health endpoint: an S1 connector)", endpoint)
    if status == 401:
        return Health(False, f"something on {endpoint.url} refuses the token in {endpoint.file.name} (a stale file?)", endpoint)
    return Health(False, f"something answers on {endpoint.url} (HTTP {status})", endpoint)


def health(layout: Layout, timeout: float = 2.0, profile: str = "") -> Health:
    """The first healthy connector of this layout: its health endpoint (S2/S3), else its plugin endpoint (S1); else
    why there is none."""
    candidates = [(e, probe_health) for e in health_endpoints(layout)] + [(e, probe) for e in endpoints(layout)]
    if not candidates:
        return Health(False, f"no connector token file in {layout.state}")
    last = None
    for e, check in candidates:
        h = check(e, timeout=timeout, profile=profile)
        if h.ok:
            return h
        last = h
    return last  # type: ignore[return-value]
