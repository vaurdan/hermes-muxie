"""Lifecycle signals: observer hooks → id-only events → the connector's local endpoint (PLAN §8, §9; CONTRACT.md §5).

Hooks run inside the agent loop. A callback here only builds an id-only event and puts it on a bounded queue
(``put_nowait``; a full queue drops the event and counts it). A daemon thread, started lazily by the first event (never
in ``register()``: it also runs in short-lived CLI processes), posts batches to ``POST /v1/signals`` with a 200 ms
timeout. Nothing here raises into Hermes.

Content never leaves: ``pre_llm_call``, ``post_llm_call`` and the auxiliary hooks carry the user message, history,
the request and the response. Only the keys in :data:`ALLOW` are read, and each value must be an int, a float, a bool,
or a string that matches :data:`ID_RE` (ids, enum words); anything else is dropped, never truncated (turn_id is up to
150 characters). tests/test_signals.py pins this.
"""

from __future__ import annotations

import math
import queue
import re
import threading
import time
from typing import Any, Callable, Optional

from . import local_api
from .layout import Layout

# Strings that may leave: ids (session ``local-<64 hex>`` / ``20261112_112139_04641460`` / ``run_…``, turn_id
# ``<sid>:<task>:<8 hex>``, session_key ``agent:main:webhook:…``) and enum words. No spaces, so no prose.
ID_RE = re.compile(r"^[A-Za-z0-9_.:@/+=-]{0,256}$")
NUM = (int, float)

# hook -> the keys forwarded. Everything else in the payload is ignored.
ALLOW: dict[str, tuple[str, ...]] = {
    "pre_llm_call": ("session_id", "turn_id", "task_id", "parent_session_id", "platform", "model", "is_first_turn"),
    "post_llm_call": ("session_id", "turn_id", "task_id", "platform", "model"),
    "on_session_start": ("session_id", "platform", "model"),
    "on_session_end": ("session_id", "turn_id", "task_id", "platform", "model", "completed", "failed", "interrupted",
                       "turn_exit_reason"),
    "agent_loop_stopped": ("session_key", "platform", "reason", "invalidation_reason"),
    "pre_auxiliary_call": ("session_id", "turn_id", "task_id", "platform", "aux_task", "api_request_id", "started_at"),
    "post_auxiliary_call": ("session_id", "turn_id", "task_id", "platform", "aux_task", "api_request_id", "ended_at",
                            "error_type", "finish_reason"),
    "post_compaction": ("session_id", "old_session_id", "kind", "reason", "before_tokens", "after_tokens",
                        "messages_removed"),
    "subagent_start": ("parent_session_id", "parent_turn_id", "parent_subagent_id", "child_session_id",
                       "child_subagent_id"),
    "subagent_stop": ("parent_session_id", "parent_turn_id", "child_session_id", "child_status", "duration_ms"),
}
HOOKS = tuple(ALLOW)
# Only compaction auxiliary calls are signals (titling, vision, ... are not).
AUX_TASKS = {"compression"}
QUEUE_MAX = 512
BATCH_MAX = 64
POST_TIMEOUT_S = 0.2
BACKOFF_DOWN_S = 5.0
BACKOFF_UNSUPPORTED_S = 300.0


def _clean(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, NUM):
        return value if math.isfinite(value) else None  # NaN and ±inf out (invalid JSON)
    if isinstance(value, str) and ID_RE.fullmatch(value):
        return value
    return _DROP


_DROP = object()


def exit_reason(value: Any) -> Optional[str]:
    """``turn_exit_reason`` is a repr-like string (``…reason=stop)``): only the reason word goes."""
    if not isinstance(value, str):
        return None
    m = re.search(r"reason=([A-Za-z0-9_]{1,40})", value)
    if m:
        return m.group(1)
    return value if re.fullmatch(r"[A-Za-z0-9_]{1,40}", value) else None


def event(hook: str, payload: dict, profile: str, seq: int, now: Optional[float] = None) -> Optional[dict]:
    """The id-only event for one hook call, or None when the hook/aux task is not a signal."""
    keys = ALLOW.get(hook)
    if keys is None:
        return None
    if hook in ("pre_auxiliary_call", "post_auxiliary_call") and payload.get("aux_task") not in AUX_TASKS:
        return None
    data: dict[str, Any] = {}
    for k in keys:
        if k not in payload:
            continue
        v = exit_reason(payload[k]) if k == "turn_exit_reason" else _clean(payload[k])
        if v is not _DROP and v is not None:
            data[k] = v
    return {"hook": hook, "profile": profile, "seq": seq, "ts": round(now if now is not None else time.time(), 3),
            "data": data}


class Signals:
    """One per plugin instance (per profile). ``callback(hook)`` is what ``register_hook`` gets."""

    def __init__(self, layout_fn: Callable[[], Layout], profile: str,
                 post: Optional[Callable[[list], str]] = None, on_first_event: Optional[Callable[[], None]] = None):
        self._layout_fn = layout_fn
        # What this instance registered from tools.json (S7): {"revision", "tools"}; set by register().
        self.catalogue_info: Optional[Callable[[], Optional[dict]]] = None
        self.profile = profile
        self.q: "queue.Queue[dict]" = queue.Queue(maxsize=QUEUE_MAX)
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._start_lock = threading.Lock()
        self._stop = threading.Event()
        self._post = post or self._post_http
        self.sent = 0
        self.dropped = 0
        self.failed = 0
        self.last_error = ""
        self._paused_until = 0.0
        self._on_first_event = on_first_event

    # Hook side: cheap, never raises.
    def callback(self, hook: str) -> Callable[..., None]:
        def on_hook(*_args: Any, **kwargs: Any) -> None:
            try:
                self.enqueue(hook, kwargs)
            except Exception:
                pass
        on_hook.__name__ = f"muxie_signal_{hook}"
        return on_hook

    def enqueue(self, hook: str, payload: dict) -> None:
        if self._stop.is_set():
            return
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        ev = event(hook, payload, self.profile, seq)
        if ev is None:
            return
        self._ensure_thread()
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            self.dropped += 1

    def _ensure_thread(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if self._stop.is_set():
                return
            t = threading.Thread(target=self._loop, name=f"muxie-signals-{self.profile}", daemon=True)
            first = self._thread is None
            self._thread = t
            t.start()
        if first and self._on_first_event is not None:
            try:
                self._on_first_event()  # it only starts its own thread
            except Exception:
                pass

    # Sender side.
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                first = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            batch = [first]
            while len(batch) < BATCH_MAX:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            if time.monotonic() < self._paused_until:
                self.dropped += len(batch)
                continue
            try:
                outcome = self._post(batch)
            except Exception as e:  # pragma: no cover - _post_http catches its own
                outcome, self.last_error = "down", type(e).__name__
            if outcome == "ok":
                self.sent += len(batch)
            else:
                self.failed += len(batch)
                self._paused_until = time.monotonic() + (BACKOFF_UNSUPPORTED_S if outcome == "unsupported" else BACKOFF_DOWN_S)

    def _post_http(self, batch: list) -> str:
        found = local_api.endpoints(self._layout_fn())
        if not found:
            self.last_error = "no connector token file"
            return "down"
        dropped, self.dropped = self.dropped, 0
        body = {"v": 1, "profile": self.profile, "dropped": dropped, "events": batch}
        info = self._catalogue()
        if info is not None:
            body["catalogue"] = info
        try:
            status, _ = local_api.request(found[0], "POST", "/v1/signals", body, timeout=POST_TIMEOUT_S,
                                          profile=self.profile)
        except local_api.LocalApiError as e:
            self.last_error = e.kind
            self.dropped += dropped
            return "down"
        if status in (200, 202, 204):
            return "ok"
        self.last_error = f"HTTP {status}"
        self.dropped += dropped
        return "unsupported" if status in (404, 405) else "down"

    def _catalogue(self) -> Optional[dict]:
        """The tools.json revision and tool count this instance registered (CONTRACT.md §5 «catalogue»): how the connector
        knows the native tools are live here (S7 migration, reload bookkeeping). Ids and a count only."""
        try:
            info = self.catalogue_info() if self.catalogue_info else None
        except Exception:
            return None
        if not isinstance(info, dict):
            return None
        rev, n = info.get("revision"), info.get("tools")
        if not isinstance(rev, str) or not re.fullmatch(r"[A-Za-z0-9]{0,64}", rev) or not isinstance(n, int) or isinstance(n, bool) or n < 0:
            return None
        return {"revision": rev, "tools": n}

    def stop(self, wait: float = 0.3) -> None:
        """``on_unload``: stop the sender; queued events are dropped (the next instance starts its own)."""
        self._stop.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=wait)

    def stats(self) -> str:
        running = bool(self._thread and self._thread.is_alive())
        s = f"sent {self.sent}, dropped {self.dropped}, failed {self.failed}, sender {'running' if running else 'idle'}"
        return s + (f", last error {self.last_error}" if self.last_error else "")
