"""How the gateway this plugin runs in is supervised, from public OS facts (PLAN §4, S0 finding 4).

Never ppid == 1 and never Hermes' own «under_systemd» log line: in S0 it said yes for a nohup gateway that sat in a
``session-N.scope`` with no ``INVOCATION_ID``. The facts used here:

- ``/proc/self/cgroup``: the unit the process is in (``…/hermes-gateway.service``, ``user@1000.service/…``, or a
  ``session-N.scope`` / no unit at all);
- ``INVOCATION_ID``: systemd sets it for processes it starts as a service (absent in login sessions and scopes);
- ``XPC_SERVICE_NAME`` (macOS launchd job label; ``0`` or absent outside a job);
- the effective uid.

``service install --mode auto --like-pid <gateway pid>`` (connector_adapter.py) lets the connector read the same facts and
pick the unit kind (dist-s2s3 ``connector/CLI.md``); this module's own reading decides the plugin's messages and the
detached fallback while the connector has no ``service`` (S1).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Mapping, Optional

SYSTEMD_SYSTEM = "systemd-system"
SYSTEMD_USER = "systemd-user"
LAUNCHD = "launchd"
DETACHED = "detached"


@dataclass(frozen=True)
class Supervision:
    kind: str  # systemd-system | systemd-user | launchd | detached
    unit: str = ""  # the gateway's unit / launchd label, when there is one
    cgroup: str = ""
    invocation_id: bool = False
    euid: int = -1
    notes: list = field(default_factory=list)
    pid: Optional[int] = None  # the process the facts are about (the gateway); None = no caller facts

    def cli_args(self) -> list[str]:
        """The facts for ``service install --mode auto`` (dist-s2s3 ``connector/CLI.md``): ``--like-pid <gateway pid>``,
        and the connector reads that process' cgroup and INVOCATION_ID itself. No pid (a terminal with no running
        gateway): no flag, the connector applies its terminal rules."""
        return ["--like-pid", str(self.pid)] if self.pid else []

    def describe(self) -> str:
        where = f" ({self.unit})" if self.unit else ""
        return f"{self.kind}{where}"


def cgroup_path(text: str) -> str:
    """The process' cgroup path: the v2 line (``0::/…``), else the v1 ``name=systemd`` line, else the first one."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        if ln.startswith("0::"):
            return ln[3:]
    for ln in lines:
        parts = ln.split(":", 2)
        if len(parts) == 3 and "name=systemd" in parts[1].split(","):
            return parts[2]
    return lines[0].split(":", 2)[-1] if lines else ""


def classify(cgroup_text: str, env: Mapping[str, str], euid: int, platform: str = "linux") -> Supervision:
    if platform == "darwin":
        label = (env.get("XPC_SERVICE_NAME") or "").strip()
        if label and label != "0":
            return Supervision(LAUNCHD, unit=label, euid=euid)
        return Supervision(DETACHED, euid=euid, notes=["no launchd job label (XPC_SERVICE_NAME)"])
    path = cgroup_path(cgroup_text)
    segments = [s for s in path.split("/") if s]
    invocation = bool((env.get("INVOCATION_ID") or "").strip())
    # The innermost .service that is not the per-user manager itself (user@1000.service holds user units below it).
    unit = next((s for s in reversed(segments) if s.endswith(".service") and not s.startswith("user@")), "")
    in_user_manager = any(s.startswith("user@") and s.endswith(".service") for s in segments)
    if unit and invocation:
        kind = SYSTEMD_USER if in_user_manager else SYSTEMD_SYSTEM
        return Supervision(kind, unit=unit, cgroup=path, invocation_id=True, euid=euid)
    notes = []
    if unit and not invocation:
        notes.append(f"in {unit} but no INVOCATION_ID")
    if any(s.startswith("session-") and s.endswith(".scope") for s in segments):
        notes.append("in a login session scope")
    if not path:
        notes.append("no cgroup information")
    return Supervision(DETACHED, cgroup=path, invocation_id=invocation, euid=euid, notes=notes)


def detect(pid: Optional[int] = None) -> Supervision:
    """The supervision of this process (in the gateway), or of process *pid* (``hermes muxie`` in a terminal asks
    about the running gateway, not about the terminal). Reads only ``/proc/<pid>/cgroup`` and ``/proc/<pid>/environ``
    (same user)."""
    target = "self" if pid is None else str(int(pid))
    text, env = "", dict(os.environ) if pid is None else {}
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{target}/cgroup", encoding="utf-8") as f:
                text = f.read(65536)
        except OSError:
            text = ""
        if pid is not None:
            try:
                with open(f"/proc/{target}/environ", "rb") as f:
                    raw = f.read(1 << 20)
                for item in raw.split(b"\0"):
                    k, _, v = item.partition(b"=")
                    if k in (b"INVOCATION_ID", b"XPC_SERVICE_NAME"):
                        env[k.decode()] = v.decode("utf-8", "replace")
            except OSError:
                pass
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    s = classify(text, env, euid, "darwin" if sys.platform == "darwin" else "linux")
    return Supervision(s.kind, s.unit, s.cgroup, s.invocation_id, s.euid, s.notes, os.getpid() if pid is None else pid)


def running_gateway_pid(default_home: Optional[str] = None) -> Optional[int]:
    """The running gateway's PID via stock's public ``gateway.status.get_running_pid`` (read-only:
    ``cleanup_stale=False``): this profile's home first, then the default home (one multiplexed gateway serves every
    profile)."""
    try:
        from pathlib import Path
        from gateway.status import get_running_pid
    except Exception:
        return None
    paths = [None] + ([Path(default_home) / "gateway.pid"] if default_home else [])
    for path in paths:
        try:
            pid = get_running_pid(path, cleanup_stale=False)
        except Exception:
            pid = None
        if pid:
            return int(pid)
    return None


def detect_for_terminal(default_home: Optional[str] = None) -> Supervision:
    """For ``hermes muxie`` in a terminal: the running gateway's facts, else this process' (noted)."""
    pid = running_gateway_pid(default_home)
    if pid is not None:
        s = detect(pid)
        return Supervision(s.kind, s.unit, s.cgroup, s.invocation_id, s.euid, s.notes + [f"gateway pid {pid}"], pid)
    s = detect()
    return Supervision(s.kind, s.unit, s.cgroup, s.invocation_id, s.euid, s.notes + ["no running gateway found"], None)


def describe_for_user(s: Supervision) -> Optional[str]:
    """One line for the chat when the mode needs the user's attention, else None."""
    if s.kind == DETACHED:
        return ("this gateway runs without a service manager, so the connector runs detached: it survives gateway "
                "restarts but not a reboot")
    return None
