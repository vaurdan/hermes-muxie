"""Pairing UX (PLAN §6, distribution S4 and S6).

Two flows, both ending in the connector's own passkey check (the plugin never sees more than a code):

**App-initiated** (S4, unchanged): the app makes a 10-minute single-use code, the user sends ``/muxie pair <CODE>`` in
a DM with the agent (or runs ``hermes muxie pair <CODE>``), and the connector's ``pair`` claims it; the app confirms
with a passkey. The code is never echoed back.

**Host-initiated** (S6, ``/muxie pair`` and ``hermes muxie pair`` with no code): the connector opens a pairing slot at
the relay and returns a code + link (:func:`start_host_initiated`, ``POST /v1/pair/start``); the person enters it in
the app; the connector checks the phone's passkey statement and then asks the machine's OWNER before it pins anything.
The plugin follows the slot with a long poll (:func:`wait_state`, ``POST /v1/pair/state``; the endpoint may restart
with a new token file when the connector hands over from unpaired to paired, so a connection error re-reads the
endpoint and polls again) and asks «Allow / Deny» with ``ctx.ask_choice`` (:func:`confirm_device`). When that returns
None (no confirm surface: CLI one-shot, no viewer, maybe some messaging adapters; S0 §4) it posts the fallback text
(:func:`fallback_text`) and keeps waiting: the answer then comes from ``/muxie allow|deny <CODE>`` (another handler) or
from a terminal, and is delivered by the PAIRING CODE itself (:func:`send_decision`, ``POST /v1/pair/decision``).
There is no separate short code. CONTRACT.md §8 has the routes and bodies.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Optional

from .local_api import LocalApiError

CODE_CHARS = re.compile(r"[^A-Za-z0-9]")

# ``endpoint_call(method, path, body, timeout) -> (status, parsed JSON or None)``; raises LocalApiError when nothing
# answers. commands.MuxiePlugin.endpoint_call builds one that re-reads the connector's token files on every call.
EndpointCall = Callable[..., tuple]

START_TIMEOUT_S = 30.0  # the connector's own request timeout (the relay's pair.open takes up to 15 s)
STATE_WAIT_S = 25  # the connector caps one long poll at 25 s
RECONNECT_S = 15.0  # how long one poll may keep re-reading the endpoint after a connection error
RECONNECT_PAUSE_S = 0.5
END_GRACE_S = 30.0  # past the code's expiry the connector has long answered `expired`; this only ends a stuck loop

TOO_OLD_TERMINAL = ("This connector is too old to pair from the machine; update it (hermes muxie update) or use a code "
                    "from the app: hermes muxie pair <CODE>")
TOO_OLD_CHAT = ("This connector is too old to pair from the machine; update it (/muxie update) or use a code from the "
                "app: /muxie pair <CODE>")


def normalize_code(raw: str) -> Optional[str]:
    """``k7qf 9m2t-xr4d-ab12`` → ``K7QF-9M2T-XR4D-AB12``; None unless it is 16 letters/digits (code v2) or 12 (v1, from
    an app or connector not updated yet). The connector checks it again."""
    s = CODE_CHARS.sub("", raw or "").upper()
    if len(s) not in (12, 16):
        return None
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


# The surfaces that dispatch a command with no SessionSource: the classic CLI (``cli.py``) and the local session
# backend (``tui_gateway/methods_tools.py`` ``_run_plugin_command``: ``source=None``, ``platform`` = the session's client).
LOCAL_PLATFORMS = {"", "cli", "tui", "desktop", "acp", "local"}


def is_private_chat(source: Any, platform: str = "") -> bool:
    """Whether a slash command came from a one-to-one place: a local session (no source, a local platform) or a
    messaging DM. Groups, channels, threads, shared sessions, and anything unknown are refused (a code there is
    visible to every member)."""
    if source is None:
        return str(platform or "").lower() in LOCAL_PLATFORMS
    chat_type = getattr(source, "chat_type", None)
    if not isinstance(chat_type, str) or chat_type.lower() != "dm":  # group, channel, thread, unknown
        return False
    return not bool(getattr(source, "shared_session", False))


# ── host-initiated: the connector's routes (CONTRACT.md §8) ───────────────
class HostInitiatedUnavailable(Exception):
    """The pairing could not start or be followed; the message is for the person (the connector's own, or ours)."""


@dataclass(frozen=True)
class PairingSlot:
    slot: str
    code: str  # K7QF-9M2T-XR4D
    link: str  # https://chat.muxie.sh/pair#<code>: the fragment never reaches a server
    fingerprint: str  # this machine's key, the same one the app shows before the passkey
    machine: str
    expires_at: float  # epoch seconds (the connector answers milliseconds)


@dataclass(frozen=True)
class DeviceRequest:
    request_id: str
    device_name: str
    passkey_fingerprint: str  # «AB12…»
    machine: str


FINAL_STATES = ("paired", "denied", "cancelled", "expired", "failed")


@dataclass(frozen=True)
class PairState:
    """One answer of ``/v1/pair/state``. ``state`` is the connector's (open | asking | paired | denied | cancelled |
    expired | failed) or ``unknown`` (404: the slot is not known: it ended long ago, or the connector restarted)."""
    slot: str
    state: str
    version: int = -1
    expires_at: float = 0.0
    request: Optional[DeviceRequest] = None
    error: str = ""
    device: str = ""
    claimed: bool = False
    renewable: bool = False

    @property
    def final(self) -> bool:
        return self.state in FINAL_STATES


def _text(v: Any, limit: int = 200) -> str:
    return v.strip()[:limit] if isinstance(v, str) else ""


def start_host_initiated(endpoint_call: EndpointCall) -> PairingSlot:
    """``POST /v1/pair/start {"v":1}``: the connector opens a pairing slot at the relay and returns the code + link.
    Raises :class:`HostInitiatedUnavailable` (502: the relay is unreachable or too old, the message is the connector's;
    404: a connector without the route)."""
    try:
        status, a = endpoint_call("POST", "/v1/pair/start", {"v": 1}, START_TIMEOUT_S)
    except LocalApiError as e:
        raise HostInitiatedUnavailable(f"the connector did not answer ({e.kind})") from None
    a = a if isinstance(a, dict) else {}
    if status == 200 and a.get("ok"):
        slot, code, link = _text(a.get("slot"), 100), _text(a.get("code"), 40), _text(a.get("link"), 300)
        machine, fingerprint = _text(a.get("machine"), 100), _text(a.get("fingerprint"), 100)
        expires = a.get("expiresAt")
        if slot and code and link and isinstance(expires, (int, float)) and not isinstance(expires, bool):
            return PairingSlot(slot, code, link, fingerprint, machine, float(expires) / 1000.0)
        raise HostInitiatedUnavailable("the connector's answer was incomplete")
    if status == 404:
        raise HostInitiatedUnavailable(TOO_OLD_CHAT)
    if status == 502:
        raise HostInitiatedUnavailable(_text(a.get("message"), 300) or "the relay is not reachable")
    raise HostInitiatedUnavailable(f"the connector answered HTTP {status}")


def _request_of(r: Any) -> Optional[DeviceRequest]:
    if not isinstance(r, dict):
        return None
    rid, name = _text(r.get("requestId"), 100), _text(r.get("deviceName"), 100)
    if not rid or not name:
        return None
    return DeviceRequest(rid, name, _text(r.get("passkeyFingerprint"), 40), _text(r.get("machine"), 100))


def wait_state(endpoint_call: EndpointCall, slot: str, after: int = -1, wait: int = STATE_WAIT_S, *,
               retry_for: float = RECONNECT_S, sleep: Callable[[float], None] = time.sleep,
               clock: Callable[[], float] = time.monotonic) -> PairState:
    """One long poll of ``POST /v1/pair/state {"v":1,"slot","after","wait"}``: returns as soon as the slot's version is
    newer than *after* (``-1`` at first), or after *wait* seconds (the connector caps it at 25).

    When the connector process hands over from unpaired to paired, its plugin endpoint restarts with a new token file
    and port mid-poll. *endpoint_call* re-reads the endpoint files on every call, so a connection error here simply
    polls again, for up to *retry_for* seconds (the slot stays known in the same process). 404 → state ``unknown``."""
    deadline = clock() + retry_for
    body = {"v": 1, "slot": slot, "after": int(after), "wait": int(wait)}
    while True:
        try:
            status, a = endpoint_call("POST", "/v1/pair/state", body, wait + 5.0)
            break
        except LocalApiError:
            if clock() >= deadline:
                raise HostInitiatedUnavailable("the connector stopped answering") from None
            sleep(RECONNECT_PAUSE_S)
    if status == 404:
        return PairState(slot, "unknown")
    if status != 200 or not isinstance(a, dict) or not a.get("ok"):
        raise HostInitiatedUnavailable(f"the connector answered HTTP {status}")
    expires = a.get("expiresAt")
    version = a.get("version")
    return PairState(
        slot, _text(a.get("state"), 20) or "failed",
        version if isinstance(version, int) and not isinstance(version, bool) else after,
        float(expires) / 1000.0 if isinstance(expires, (int, float)) and not isinstance(expires, bool) else 0.0,
        _request_of(a.get("request")), _text(a.get("error"), 300), _text(a.get("device"), 100), bool(a.get("claimed")), a.get("renewable") is True)


@dataclass(frozen=True)
class DecisionResult:
    """``kind``: ``done`` (200) | ``not_waiting`` (404: nothing waits for it) | ``down`` (nothing answers) | ``error``."""
    kind: str
    device: str = ""
    machine: str = ""
    detail: str = ""


def send_decision(endpoint_call: EndpointCall, decision: str, *, request_id: str = "", code: str = "") -> DecisionResult:
    """``POST /v1/pair/decision``: by the request id (the Allow/Deny buttons) or by the pairing code itself
    (``/muxie allow|deny <CODE>``, a terminal: any process with the token; *code* should be normalized, the connector
    takes any spelling). Only ``allow`` pins the device."""
    body: dict = {"v": 1, "decision": decision}
    if request_id:
        body["requestId"] = request_id
    else:
        body["code"] = code
    try:
        status, a = endpoint_call("POST", "/v1/pair/decision", body, 5.0)
    except LocalApiError as e:
        return DecisionResult("down", detail=e.kind)
    a = a if isinstance(a, dict) else {}
    if status == 200:
        return DecisionResult("done", _text(a.get("device"), 100), _text(a.get("machine"), 100))
    if status == 404:
        return DecisionResult("not_waiting")
    return DecisionResult("error", detail=f"HTTP {status}")


NOT_RUNNING = "The connector is not running, so the answer cannot reach it. /muxie status says more."


def decision_reply(decision: str, r: DecisionResult) -> str:
    """The reply to ``/muxie allow|deny <CODE>`` (and ``hermes muxie allow|deny``)."""
    if r.kind == "done":
        if decision == "allow":
            return f"Allowed: {r.device or 'the device'} can now use the agents on {r.machine or 'this machine'}."
        return "Denied: nothing was paired."
    if r.kind == "not_waiting":
        return "No device is waiting for that code (it expired, or was already answered)."
    if r.kind == "down":
        return NOT_RUNNING
    return f"The connector answered {r.detail or 'with an error'}, so the answer was not delivered. Try again."


# ── machine-side confirm ──────────────────────────────────────────────────
def confirm_question(r: DeviceRequest) -> str:
    return f"{r.device_name} (passkey {r.passkey_fingerprint}) wants to use the agents on {r.machine}."


def confirm_device(request: DeviceRequest, ask_choice: Callable[[str, list], Optional[str]]) -> Optional[str]:
    """Ask the machine's owner with ``ctx.ask_choice`` (works only from the handler's own context). Returns
    ``"allow"`` / ``"deny"``, or None when there is no confirm surface (CLI one-shot, no viewer: S0 §4) or the answer
    was anything else."""
    choices = [{"value": "allow", "label": "Allow"}, {"value": "deny", "label": "Deny"}]
    try:
        picked = ask_choice(confirm_question(request), choices)
    except Exception:
        return None
    return picked if picked in ("allow", "deny") else None


# ── copy (frame 5 of mockups-s6 and its error follow-up) ──────────────────
def code_text(s: PairingSlot) -> str:
    """The ONE message the chat shows (approved frame 5); the end state edits it in place."""
    return (f"Pair a phone with {s.machine}\n\n"
            f"Code: {s.code}\n"
            f"On your phone, tap: {s.link}\n"
            "Or in Muxie: Add a machine › Enter code.\n\n"
            f"Machine key: {s.fingerprint}\n"
            "Expires in 10 min. Works once.")


NO_POST_HINT = "When your phone asks, answer here with /muxie allow <CODE> (or /muxie deny <CODE>)."


def no_post_text(s: PairingSlot) -> str:
    """The reply when the surface cannot post and edit a message: the code message, no waiting in the handler."""
    return code_text(s) + "\n\n" + NO_POST_HINT.replace("<CODE>", s.code)


def clock_text(epoch_seconds: float) -> str:
    """HH:MM in the machine's local time."""
    return time.strftime("%H:%M", time.localtime(epoch_seconds))


def fallback_text(r: DeviceRequest, code: str, expires_at: float) -> str:
    """No Allow/Deny buttons here (E6 of mockups-s6/errors): the owner answers with the pairing code."""
    return (f"{confirm_question(r)}\n\n"
            f"To allow it, send /muxie allow {code}\n"
            f"Not you? Send /muxie deny {code}\n"
            f"Until {clock_text(expires_at)}.")


# How the code message ends (it is edited in place): ``paired`` and ``denied`` from frame 5 / E6, ``expired``,
# ``cancelled`` and ``failed`` from X8 (mockups-s6/extra, approved 2026-11-13 07:26).
END_TEXTS = {
    "paired": "Paired with {device}.",
    "denied": "Pairing denied: {device} can't use the agents on {machine}.\n"
              "The code {code} no longer works. Send /muxie pair for a new one.",
    "expired": "The code {code} expired after 10 minutes. Nothing was paired.\nSend /muxie pair for a new one.",
    "cancelled": "Pairing cancelled. The code {code} no longer works. Nothing was paired.\nSend /muxie pair for a new one.",
    "failed": "Pairing failed: {error}. Nothing was paired.\nSend /muxie pair for a new code.",
}


def end_text(state: str, *, device: str = "", machine: str = "", code: str = "", error: str = "") -> str:
    """The text the code message is edited to when the pairing ended in *state* (see END_TEXTS)."""
    template = END_TEXTS.get(state) or END_TEXTS["failed"]
    why = (error or "").strip().rstrip(". ") or "the pairing did not complete"
    return template.format(device=device or "that device", machine=machine or "this machine", code=code, error=why)


# ── following one host-initiated pairing ──────────────────────────────────
def follow_host_pairing(slot: PairingSlot, endpoint_call: EndpointCall,
                        ask_choice: Callable[[str, list], Optional[str]],
                        post_fallback: Callable[[str], Any], *,
                        superseded: Callable[[], bool] = lambda: False,
                        clock: Callable[[], float] = time.time,
                        sleep: Callable[[float], None] = time.sleep) -> PairState:
    """Long-poll the slot until it ends; returns the final :class:`PairState` (``device`` = the best known name).

    Runs in the ``/muxie pair`` handler's own thread, because ``ctx.ask_choice`` works only there. On ``asking`` it asks
    Allow/Deny ONCE per request (owner decision, 2026-11-13: one card); a pick goes to the connector by request id. When
    that card comes back with no answer (no surface; stock's clarify timeout, 90 s by default, also with no viewer
    attached; or a pick that could not be delivered) it is not asked again: *post_fallback* gets :func:`fallback_text`
    once (the handler edits it into the code message) and the wait goes on until the code's 10 minutes: the answer then
    arrives from another ``/muxie allow|deny <CODE>`` handler or a terminal, decided at the connector by the code.
    *superseded* says a newer ``/muxie pair`` of this plugin instance replaced this flow (the connector forgets the old
    slot: ``unknown`` then means «cancelled», not «lost»)."""
    after = -1
    device = ""
    asked: set = set()
    claimed = False
    renewable = False
    while True:
        if clock() > slot.expires_at + END_GRACE_S:
            return PairState(slot.slot, "expired", after, slot.expires_at, device=device, claimed=claimed, renewable=renewable)
        try:
            st = wait_state(endpoint_call, slot.slot, after, sleep=sleep)
        except HostInitiatedUnavailable as e:
            return PairState(slot.slot, "failed", after, slot.expires_at, error=str(e), device=device)
        renewable = st.renewable
        claimed = claimed or st.claimed or st.state == "asking"
        if st.request:
            device = st.request.device_name
        if st.state == "unknown":
            if superseded():
                return PairState(slot.slot, "cancelled", after, slot.expires_at, device=device)
            return PairState(slot.slot, "failed", after, slot.expires_at, device=device,
                             error="the connector no longer knows this pairing (it may have restarted)")
        after = st.version
        if st.final:
            return replace(st, device=st.device or device, claimed=claimed)
        if st.state == "asking" and st.request and st.request.request_id not in asked:
            asked.add(st.request.request_id)  # one card per request, never asked again
            pick = confirm_device(st.request, ask_choice)
            delivered = False
            if pick:
                delivered = send_decision(endpoint_call, pick, request_id=st.request.request_id).kind in ("done", "not_waiting")
            if not delivered:  # no answer on the card (no surface, timed out) or it could not reach the connector
                try:
                    post_fallback(fallback_text(st.request, slot.code, st.expires_at or slot.expires_at))
                except Exception:
                    pass
