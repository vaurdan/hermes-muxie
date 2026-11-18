"""``/muxie …`` in chat and ``hermes muxie …`` in a terminal (PLAN §3, §6).

Chat: ``help``, ``status``, ``pair`` (host-initiated, S6), ``pair <CODE>``, ``start``, ``update``, ``logs [N]``,
``allow|deny <CODE>`` (answer a phone's request by the pairing code).
Terminal: the same plus ``setup [--from SRC] [--relay-url URL]``, ``rollback`` and ``uninstall [--purge]``.

Long work (install, pairing with a code, update) runs on a background thread started by the command; its progress is
ONE chat message posted with ``ctx.post_message`` and edited in place. When the surface cannot post (``ok=False``), the
work runs in the handler instead (S0: a sync handler may block; it runs on the gateway pool) and the reply is the final
text. ``/muxie pair`` with no code blocks in the handler (``ctx.ask_choice`` works only from its own context) and edits
its one message to the outcome (pairing.py).
Everything that can show a secret or change the machine (pair, allow/deny, update, logs, start) is refused outside a
private chat. Settings come from ``ctx.get_config`` (``plugins.entries.muxie.settings.*``), never ``os.environ``.
"""

from __future__ import annotations

import argparse
import os
import socket
import threading
import time
from typing import Any, Callable, Optional

from . import bootstrap, connector_adapter as ca, local_api, pairing, supervision, tools_proxy
from .layout import Layout, configured_relay, muxie_layout, relay_missing_message
from .signals import Signals

SETTINGS = ("channel_url", "bundle_sha256", "relay_url", "muxie_home", "node")
MAX_CHAT_TEXT = 3500

HELP = """Muxie on this machine:
/muxie status          is the connector installed, running, paired
/muxie pair            show a code to pair a phone (scan it or type it in Muxie)
/muxie pair <CODE>     pair with a code the app shows (Add a machine); installs the connector
/muxie allow|deny <CODE>  answer a phone's request when no Allow/Deny buttons show
/muxie start           start the connector again (when /muxie status says it is not running)
/muxie update          update the connector now (it also updates itself)
/muxie logs [N]        the connector's last N log lines
In a terminal: hermes muxie setup|status|pair|allow|deny|update|rollback|logs|uninstall
  hermes muxie pair             show a code (QR) to pair a phone; Allow? is asked right there
  hermes muxie allow|deny <CODE>  answer a phone's request from another terminal"""

PRIVATE_ONLY = {"pair", "start", "update", "logs", "allow", "deny"}
BOOT_CHECK_EVERY_S = 600
_BOOT_CHECKS: dict = {}  # state dir -> monotonic time of the last boot check in this process
_BOOT_LOCK = threading.Lock()


class MuxiePlugin:
    """One per plugin load (per profile). Holds the signal sender and the host-initiated pairing in progress."""

    def __init__(self, ctx: Any):
        self.ctx = ctx
        try:
            self.profile = str(ctx.profile_name or "default")
        except Exception:
            self.profile = "default"
        self._layout_cache: Optional[tuple] = None
        self.signals = Signals(self._signal_layout, self.profile, on_first_event=self.boot_check_soon)
        self._boot_started = False
        self._host_gen = 0  # bumped by every /muxie pair (no code): a newer one replaces the older flow of this instance
        self._host_lock = threading.Lock()
        self.catalogue: Optional[tools_proxy.Catalogue] = None
        self._job: Optional[threading.Thread] = None
        self._job_lock = threading.Lock()

    # ── settings ───────────────────────────────────────────────────────────
    def setting(self, key: str) -> str:
        try:
            v = self.ctx.get_config(key, "")
        except Exception:
            return ""
        return v.strip() if isinstance(v, str) else ""

    def layout(self) -> Layout:
        return muxie_layout(self.setting("muxie_home"))

    def _signal_layout(self) -> Layout:
        """The signal sender's layout, re-read at most every 30 s (not one config read per batch)."""
        now = time.monotonic()
        if self._layout_cache is None or now - self._layout_cache[0] > 30:
            self._layout_cache = (now, self.layout())
        return self._layout_cache[1]

    def options(self, code: str = "", **over: Any) -> bootstrap.Options:
        o = bootstrap.Options(channel_url=self.setting("channel_url") or bootstrap.DEFAULT_CHANNEL_URL,
                              relay_url=self.setting("relay_url"),
                              node=self.setting("node"), code=code, profile=self.profile,
                              bundle_sha256=self.setting("bundle_sha256"))
        for k, v in over.items():
            if v not in (None, ""):
                setattr(o, k, v)
        return o

    def unload(self) -> None:
        self.signals.stop()

    # ── boot trigger (detached mode) ──────────────────────────────────────
    @staticmethod
    def is_gateway_process() -> bool:
        """This process is the running gateway (stock's public ``gateway.status.get_running_pid``, read-only)."""
        pid = supervision.running_gateway_pid()
        return pid == os.getpid()

    def boot_check_soon(self) -> None:
        """Called by the first hook event of this plugin instance (never by ``register()``, which also runs in CLI
        processes): one background check, at most every 10 minutes per state dir and process."""
        if self._boot_started:
            return
        self._boot_started = True
        threading.Thread(target=self.boot_check, name=f"muxie-boot-{self.profile}", daemon=True).start()

    def boot_check(self) -> str:
        """In detached mode nothing restarts the connector after a reboot (dist-s2s3 CLI.md «Detached mode files»), so
        the first agent activity in the gateway does: when the connector is installed and paired but does not answer,
        ``service install --mode auto --like-pid <gateway>`` (idempotent: it starts a supervisor only when none runs;
        on S1, the plugin's own detached start). Returns what it did (for tests and logs); never raises."""
        try:
            if not self.is_gateway_process():
                return "not the gateway process"
            layout = self.layout()
            key = str(layout.state)
            with _BOOT_LOCK:  # several profiles share one gateway process
                now = time.monotonic()
                if now - _BOOT_CHECKS.get(key, -1e9) < BOOT_CHECK_EVERY_S:
                    return "checked recently"
                _BOOT_CHECKS[key] = now
            if ca.installed_bundle(layout) is None:
                return "not installed"
            lock = bootstrap.InstallLock(layout, self.profile)
            if not lock.acquire(wait=0):  # a /muxie pair or setup runs: it starts the connector itself
                return "an install runs"
            with lock:
                return self._boot_locked(layout)
        except Exception as e:  # never into Hermes
            return f"boot check failed: {type(e).__name__}"

    def _boot_locked(self, layout: Layout) -> str:
        try:
            if ca.installed_bundle(layout) is None:
                return "not installed"
            if local_api.health(layout, timeout=1.5, profile=self.profile).ok:
                return "already answers"
            conn, _why = self.connector(layout)
            if conn is None or ca.paired_from_status(conn.status()) is not True:
                return "not paired (or no Node)"
            try:
                r = conn.service_install(supervision.detect().cli_args())
                return "service install: " + ("ok" if r.ok else ca.explain(r))
            except ca.NotAvailable:
                if ca.detached_pid(layout) is None and layout.detached_pid_file.exists():
                    return f"restarted detached (pid {conn.start_detached()})"
                return "no service command and no detached record"
        except Exception as e:  # never into Hermes
            return f"boot check failed: {type(e).__name__}"

    # ── chat ──────────────────────────────────────────────────────────────
    def slash(self, raw_args: str, **context: Any) -> str:
        try:
            return self._slash(raw_args or "", context)
        except Exception as e:  # a command error is a reply, never a traceback in the chat
            return f"/muxie: unexpected error ({type(e).__name__}: {str(e)[:200]})"

    def _slash(self, raw: str, context: dict) -> str:
        words = raw.split()
        sub = (words[0].lower() if words else "help")
        rest = words[1:]
        if sub in ("help", "-h", "--help", "?"):
            return HELP
        if sub in PRIVATE_ONLY and not pairing.is_private_chat(context.get("source"), str(context.get("platform") or "")):
            return f"/muxie {sub} works only in a private chat with the agent (a direct message), not in a group."
        if sub == "status":
            if not pairing.is_private_chat(context.get("source"), str(context.get("platform") or "")):
                return self.status_brief()  # no paths, keys, URLs or host name in a group
            return self.status_text()
        if sub == "pair":
            return self.chat_pair(rest)
        if sub == "start":
            return self.chat_job("Muxie · starting the connector", self.options())
        if sub == "update":
            return self.chat_update()
        if sub == "logs":
            return self.logs_text(rest)
        if sub in ("allow", "deny"):
            return self.decide_by_code(sub, rest)[1]
        return f"unknown /muxie command {sub!r}.\n\n{HELP}"

    def chat_pair(self, rest: list) -> str:
        if not rest:
            return self.chat_pair_host()
        code = pairing.normalize_code(" ".join(rest))
        if code is None:
            return "That is not a pairing code (16 letters/digits, like K7QF-9M2T-XR4D-AB12). Usage: /muxie pair <CODE>"
        return self.chat_job("Muxie · pairing this machine", self.options(code=code), secrets=(code,))

    # ── host-initiated pairing (S6) ───────────────────────────────────────
    def post(self, text: str) -> Any:
        """``ctx.post_message``; the handle when the surface can post and edit, else None."""
        try:
            handle = self.ctx.post_message(_fit(text))
        except Exception:
            return None
        return handle if handle is not None and getattr(handle, "ok", False) else None

    def chat_pair_host(self) -> str:
        """``/muxie pair`` with no code. ONE message: the code (approved frame 5), edited in place to the outcome. The
        handler blocks (long poll) so it can call ``ctx.ask_choice``; a newer ``/muxie pair`` of this instance replaces
        it (the connector cancels the old slot itself; this handler then edits its message to «cancelled»)."""
        layout = self.layout()
        with self._host_lock:
            self._host_gen += 1
            gen = self._host_gen
        call = self.endpoint_call(layout)
        handle = None
        if not local_api.health(layout, timeout=1.5, profile=self.profile).ok:
            # Not installed or not running: the bootstrap path with no code, in this same message. The connector runs
            # unpaired from S7 on, and the slot needs it running.
            title = "Muxie · getting ready to pair a phone"
            handle = self.post(title + "\n… starting")
            progress = bootstrap.Progress(title, _editor(handle) if handle else (lambda _t: None))
            outcome = bootstrap.run(layout, self.options(start_unpaired=True), progress)
            if not outcome.ok or not outcome.running:
                why = _final(outcome) if not outcome.ok else pairing.TOO_OLD_CHAT
                if handle is None:
                    return _fit(progress.text() + "\n\n" + why)
                progress.note("\n" + why)
                return "Muxie could not get ready to pair: see the message above."
        try:
            slot = pairing.start_host_initiated(call)
        except pairing.HostInitiatedUnavailable as e:
            return self._settle(handle, f"Could not start pairing: {e}")
        if handle is not None:
            _edit(handle, pairing.code_text(slot))
        else:
            handle = self.post(pairing.code_text(slot))
        if handle is None:  # this surface cannot edit a message: answer with the code, do not block
            return _fit(pairing.no_post_text(slot))
        shown = pairing.code_text(slot)
        renew_until = time.time() + 3600

        def fallback(text: str) -> None:
            _edit(handle, shown + "\n\n" + text)

        while True:
            final = pairing.follow_host_pairing(slot, call, self.ctx.ask_choice, fallback,
                                                superseded=lambda: self._host_gen != gen)
            if final.state != "expired" or not final.renewable or final.claimed or final.expires_at > time.time() or time.time() >= renew_until or self._host_gen != gen:
                break
            stopped_at = final.expires_at or slot.expires_at
            try:
                slot = pairing.start_host_initiated(call)
            except pairing.HostInitiatedUnavailable as e:
                _edit(handle, f"Could not renew pairing: {e}. Nothing was paired.")
                return "The result is in the message above."
            shown = pairing.code_text(slot) + "\n\nNew code · the last one stopped at " + pairing.clock_text(stopped_at) + "."
            _edit(handle, shown)
        _edit(handle, pairing.end_text(final.state, device=final.device, machine=slot.machine, code=slot.code,
                                       error=final.error))
        return "The result is in the message above."

    @staticmethod
    def _settle(handle: Any, text: str) -> str:
        """Put *text* into the message already posted, or return it as the reply when there is none."""
        if handle is None:
            return _fit(text)
        _edit(handle, text)
        return "The result is in the message above."

    def chat_job(self, title: str, opts: bootstrap.Options, secrets: tuple = ()) -> str:
        """Run bootstrap.run on a background thread, its progress edited into one posted message."""
        with self._job_lock:
            if self._job is not None and self._job.is_alive():
                return "Muxie is already working on this machine: see the progress message above."
            handle = None
            try:
                handle = self.ctx.post_message(title + "\n… starting")
            except Exception:
                handle = None
            if handle is None or not getattr(handle, "ok", False):
                progress = bootstrap.Progress(title, lambda _t: None, secrets)
                outcome = bootstrap.run(self.layout(), opts, progress)
                return _fit(progress.text() + "\n\n" + _final(outcome))
            progress = bootstrap.Progress(title, _editor(handle), secrets)

            def work():
                outcome = bootstrap.run(self.layout(), opts, progress)
                progress.note("\n" + _final(outcome))

            self._job = threading.Thread(target=work, name=f"muxie-bootstrap-{self.profile}", daemon=True)
            self._job.start()
        return "Working on it: progress in the message above."

    def chat_update(self) -> str:
        layout = self.layout()
        conn, why = self.connector(layout)
        if conn is None:
            return why
        try:
            r = conn.update()
        except ca.NotAvailable as e:
            return (f"{e}. The connector will update itself from the signed release channel (slice S3); until then "
                    "a newer bundle is installed with: hermes muxie setup --from <tgz or channel>")
        if not r.ok:
            return _fit("Update not applied: " + ca.explain(r))
        info = r.json or {}
        summary = ", ".join(f"{k} {info[k]}" for k in ("action", "current", "available", "version") if info.get(k))
        return _fit("Update: " + (summary or bootstrap._last(r.out, 8)))

    def logs_text(self, rest: list) -> str:
        try:
            n = max(1, min(100, int(rest[0]))) if rest else 30
        except ValueError:
            return "Usage: /muxie logs [N] (1-100)"
        layout = self.layout()
        conn, _why = self.connector(layout)
        text = conn.logs(n) if conn else ca.tail(layout.detached_log, n)
        if not text.strip():
            return "No connector log here yet."
        return _fit("```\n" + text[-MAX_CHAT_TEXT + 20:] + "\n```")

    def decide_by_code(self, sub: str, rest: list) -> tuple[bool, str]:
        """``/muxie allow|deny <CODE>`` and ``hermes muxie allow|deny <CODE>``: the answer goes to the connector by the
        PAIRING CODE itself (no separate short code). Returns (delivered, text for the person)."""
        if not rest:
            return False, f"Usage: /muxie {sub} <CODE>"
        code = pairing.normalize_code(" ".join(rest))
        if code is None:
            return False, f"That is not a pairing code (16 letters/digits, like K7QF-9M2T-XR4D-AB12). Usage: /muxie {sub} <CODE>"
        layout = self.layout()
        if not local_api.endpoints(layout):
            return False, pairing.NOT_RUNNING
        r = pairing.send_decision(self.endpoint_call(layout), sub, code=code)
        return r.kind == "done", pairing.decision_reply(sub, r)

    # ── shared ────────────────────────────────────────────────────────────
    def connector(self, layout: Layout) -> tuple[Optional[ca.Connector], str]:
        if ca.installed_bundle(layout) is None:
            return None, "The Muxie connector is not installed on this machine. /muxie pair installs it."
        node = ca.find_node(layout, self.setting("node"))
        if isinstance(node, ca.NodeProblem):
            return None, node.message()
        return ca.Connector(layout, node), ""

    def endpoint_call(self, layout: Layout) -> Callable[..., tuple]:
        """``pairing.EndpointCall`` over the connector's local endpoint. The token files are re-read on EVERY call: the
        connector's endpoint restarts with a new token and port when it hands over from unpaired to paired."""
        def call(method: str, path: str, body: Any = None, timeout: float = 5.0) -> tuple:
            last = local_api.LocalApiError("down", "no connector token file")
            for ep in local_api.endpoints(layout):
                try:
                    status, answer = local_api.request(ep, method, path, body, timeout=timeout, profile=self.profile)
                except local_api.LocalApiError as e:
                    last = e
                    continue
                if status == 401:  # a stale token file: the next one, if any
                    last = local_api.LocalApiError("down", f"{ep.file.name} is refused")
                    continue
                return status, answer
            raise last
        return call

    def status_brief(self) -> str:
        layout = self.layout()
        installed = ca.installed_bundle(layout) is not None
        running = local_api.health(layout, timeout=1.5, profile=self.profile).ok
        return (f"Muxie connector: {'installed' if installed else 'not installed'}, "
                f"{'running' if running else 'not running'}. Details: /muxie status in a private chat.")

    def status_text(self) -> str:
        layout = self.layout()
        lines = [f"Muxie on {socket.gethostname()} (profile {self.profile})"]
        bundle = ca.installed_bundle(layout)
        h = local_api.health(layout, timeout=1.5, profile=self.profile)
        paired = None
        if bundle is None:
            lines.append(f"connector  not installed ({layout.connector_dir})")
        else:
            lines.append(f"connector  {ca.bundle_version(bundle)} ({bundle})")
        lines.append(f"running    {'yes, ' + h.detail if h.ok else 'no: ' + h.detail}")
        if bundle is None:  # an installed connector reports its own relay below (status --json)
            setting = self.setting("relay_url")
            relay = configured_relay(layout, setting)
            lines.append(f"relay      {relay} ({'setting' if setting else 'connector.env'})" if relay
                         else f"relay      not set: {relay_missing_message(layout)}")
        pid = ca.detached_pid(layout)
        if pid:
            lines.append(f"detached   pid {pid} (started by this plugin; log {layout.detached_log})")
        if bundle is not None:
            conn, why = self.connector(layout)
            if conn is None:
                lines.append(f"node       {why}")
            else:
                st = conn.status()
                paired = ca.paired_from_status(st)
                lines += status_lines(st)
        sup = supervision.detect()
        lines.append(f"gateway    {sup.describe()}" + (f" ({'; '.join(sup.notes)})" if sup.notes else ""))
        cat = self.catalogue
        if cat is not None:
            names = ", ".join(t.name for t in cat.tools) or "none"
            lines.append(f"tools      {len(cat.tools)} native ({names}); loaded when this profile's plugins loaded")
            for p in cat.problems[:3]:
                lines.append(f"           ! {p}")
        lines.append(f"signals    {self.signals.stats()}")
        channel = self.setting("channel_url").split("?", 1)[0].split("#", 1)[0]  # never a query (tokens)
        if not channel and bootstrap.DEFAULT_CHANNEL_URL:
            channel = bootstrap.DEFAULT_CHANNEL_URL + " (default)"
        lines.append(f"channel    {channel or 'not set (plugins.entries.muxie.settings.channel_url)'}")
        if bundle is not None and not h.ok:
            if paired is False:
                lines.append("Not paired yet: send /muxie pair for a code to scan, or use a code from the app: /muxie pair <CODE>")
            else:
                lines.append("To start it: /muxie start (or in a terminal: hermes muxie setup)")
        return _fit("\n".join(lines))

    # ── terminal ──────────────────────────────────────────────────────────
    def cli_setup(self, parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="muxie_command")
        sub.add_parser("help", help="what this command does")
        sub.add_parser("status", help="is the connector installed, running, paired")
        p = sub.add_parser("setup", help="install the connector (if needed) and start it")
        p.add_argument("--from", dest="source", default="", help="a connector .tgz (with .sha256 beside it) or a "
                                                                    "channel manifest; default: the channel_url setting")
        p.add_argument("--relay-url", default="", help="the relay (default: the relay_url setting)")
        p = sub.add_parser("pair", help="show a code to pair a phone, or pair with a code the Muxie app shows")
        p.add_argument("code", nargs="*", help="a code from the app, like K7QF-9M2T-XR4D (none: this machine shows one)")
        for name, what in (("allow", "let the phone that is asking use the agents"), ("deny", "refuse the phone that is asking")):
            p = sub.add_parser(name, help=what + " (by the pairing code)")
            p.add_argument("code", nargs="*", help="the pairing code this machine shows")
        sub.add_parser("start", help="start the connector again")
        sub.add_parser("update", help="update the connector now")
        sub.add_parser("rollback", help="go back to the previous connector version")
        p = sub.add_parser("logs", help="the connector's last log lines")
        p.add_argument("-n", "--lines", type=int, default=40)
        p = sub.add_parser("uninstall", help="stop and remove the connector (keeps its key and roster)")
        p.add_argument("--purge", action="store_true", help="also remove the key, roster and config")

    def cli_run(self, args: argparse.Namespace) -> int:
        cmd = getattr(args, "muxie_command", None) or "help"
        out = print
        if cmd == "help":
            out(HELP)
            return 0
        if cmd == "status":
            out(self.status_text())
            return 0
        if cmd in ("allow", "deny"):
            if not args.code:
                out(f"Usage: hermes muxie {cmd} <CODE>")
                return 2
            ok, text = self.decide_by_code(cmd, args.code)
            out(text)
            return 0 if ok else 1
        if cmd == "pair" and not args.code:
            return self.cli_pair_host(out)
        if cmd in ("setup", "start", "pair"):
            code = ""
            if cmd == "pair":
                code = pairing.normalize_code(" ".join(args.code)) or ""
                if not code:
                    out("That is not a pairing code (16 letters/digits, like K7QF-9M2T-XR4D-AB12).")
                    return 2
            opts = self.options(code=code)
            if cmd == "setup":
                source = args.source
                if source and "://" not in source:
                    source = os.path.abspath(source)  # a path typed in a terminal is relative to it
                opts = self.options(channel_url=source, relay_url=args.relay_url, reinstall=bool(source))
            progress = bootstrap.Progress("Muxie · " + {"setup": "setting up", "start": "starting",
                                                       "pair": "pairing"}[cmd], _printer(out), (code,))
            root = ca.hermes_root()
            sup = supervision.detect_for_terminal(str(root.parent) if root else None)
            outcome = bootstrap.run(self.layout(), opts, progress, sup)
            out(_final(outcome))
            return 0 if outcome.ok else 1
        if cmd == "logs":
            out(self.logs_text([str(args.lines)]))
            return 0
        layout = self.layout()
        conn, why = self.connector(layout)
        if conn is None:
            out(why)
            return 1
        try:
            if cmd == "update":
                r = conn.update()
            elif cmd == "rollback":
                r = conn.rollback()
            elif cmd == "uninstall":
                return self.cli_uninstall(conn, layout, bool(args.purge), out)
            else:
                out(HELP)
                return 2
        except ca.NotAvailable as e:
            out(str(e))
            return 2
        out(r.text if r.ok else ca.explain(r))
        return 0 if r.ok else (r.code or 1)

    def cli_pair_host(self, out: Callable[[str], None]) -> int:
        """``hermes muxie pair`` with no code: make sure the connector is installed (no code), then its own
        ``pair --host`` runs in the FOREGROUND on this terminal (QR, code, link, key, ``Allow? [y/N]``)."""
        layout = self.layout()
        progress = bootstrap.Progress("Muxie · getting ready to pair a phone", _printer(out))
        root = ca.hermes_root()
        sup = supervision.detect_for_terminal(str(root.parent) if root else None)
        outcome = bootstrap.run(layout, self.options(start_unpaired=True), progress, sup)
        if not outcome.ok:
            out(_final(outcome))
            return 1
        conn, why = self.connector(layout)
        if conn is None:
            out(why)
            return 1
        if not conn.offers("pair --host"):
            out(pairing.TOO_OLD_TERMINAL)
            return 2
        return conn.pair_host_foreground()

    def cli_uninstall(self, conn: ca.Connector, layout: Layout, purge: bool, out: Callable[[str], None]) -> int:
        try:
            r = conn.uninstall(purge=purge)
            out(r.text if r.ok else ca.explain(r))
            if r.ok and "hermes plugins remove" not in r.text:
                out("Then remove the plugin: hermes plugins remove muxie")
            return 0 if r.ok else 1
        except ca.NotAvailable as e:
            if purge:
                out(f"{e}: --purge (key, roster, config) needs the connector's own uninstall; nothing was removed.")
                return 2
        # Fallback until S2/S3: what the plugin itself started and unpacked, nothing else.
        import shutil
        pid = conn.stop_detached()
        out(f"stopped the detached connector (pid {pid})" if pid else "no detached connector started by this plugin runs")
        shutil.rmtree(layout.connector_dir, ignore_errors=True)
        out(f"removed {layout.connector_dir}")
        out(f"kept: the machine's key and roster in {layout.state}, config in {layout.config}")
        out("A connector installed as a service by a newer connector is not touched here.")
        out("Then remove the plugin: hermes plugins remove muxie")
        return 0


def status_lines(st: dict) -> list:
    """The connector's own status: ``status --json`` (dist-s2s3, schema 1) or S1's ``key  value`` text."""
    out = []
    if st.get("schema") == 1:
        p = st.get("paired") or {}
        if p.get("paired"):
            out.append(f"machine    paired, key {p.get('fingerprint') or '?'}, {p.get('devices', 0)} trusted device(s)")
        else:
            out.append("machine    not paired" + (f" ({p['error']})" if p.get("error") else ""))
        relay, conn = st.get("relay") or {}, st.get("connector") or {}
        if relay.get("url"):
            out.append(f"relay      {relay['url']} ({relay.get('source', '?')})")
        else:
            out.append("relay      not set: " + relay_missing_message((st.get("config") or {}).get("path")))
        out.append(f"id         {conn.get('id', '?')} ({conn.get('source', '?')})")
        inst = st.get("install") or {}
        if inst.get("current"):
            out.append(f"install    current {inst['current']}" + (f", previous {inst['previous']}" if inst.get("previous") else "")
                       + (f", bad {', '.join(inst['bad'])}" if inst.get("bad") else ""))
        svc = st.get("service") or {}
        if svc.get("installed"):
            out.append(f"service    {svc.get('mode')} {svc.get('unit') or ''} {svc.get('active') or ''}".rstrip()
                       + (f", pid {svc['pid']}" if svc.get("pid") else ""))
            if svc.get("lingerFix"):
                out.append(f"           stops at logout until, as root: {svc['lingerFix']}")
        upd = st.get("update") or {}
        if upd.get("channel") or upd.get("pin"):
            out.append(f"updates    {'auto' if upd.get('auto') else 'manual'} from {upd.get('channel') or '?'}"
                       + (f", pinned {upd['pin']}" if upd.get("pin") else ""))
        return out
    for key in ("machine", "relay", "id"):
        if st.get(key):
            out.append(f"{key:<10} {st[key]}")
    if st.get("error"):
        out.append(f"status     {str(st['error'])[:200]}")
    return out


def _editor(handle: Any) -> Callable[[str], None]:
    def emit(text: str) -> None:
        handle.edit(_fit(text))
    return emit


def _edit(handle: Any, text: str) -> None:
    """Edit the one message; a failed edit is not worth stopping the pairing for."""
    try:
        handle.edit(_fit(text))
    except Exception:
        pass


def _printer(out: Callable[[str], None]) -> Callable[[str], None]:
    """Terminal progress: print each new or changed last line once."""
    shown: list = []

    def emit(text: str) -> None:
        for i, line in enumerate(text.splitlines()):
            if i < len(shown) and shown[i] == line:
                continue
            if i < len(shown):
                shown[i] = line
            else:
                shown.append(line)
            out(line)
    return emit


def _final(o: bootstrap.Outcome) -> str:
    if not o.ok:
        return f"Not done: {o.summary}"
    if o.paired is False:
        return "Installed. Next: pair it (/muxie pair)."
    return "Done: the connector is paired and running." if o.running else f"Done: {o.summary}."


def _fit(text: str) -> str:
    return text if len(text) <= MAX_CHAT_TEXT else text[: MAX_CHAT_TEXT - 20] + "\n… (cut)"
