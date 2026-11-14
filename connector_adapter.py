"""The ONE place the plugin talks to the ``muxie-connector`` CLI (and to the release-signature check).

PLAN §1: everything the plugin does, the connector CLI can do alone; the plugin is a shell around it. The CLI contract
is ``connector/CLI.md`` on branch ``dist-s2s3`` (S2 service + S3 update). This module detects what the installed
connector offers (its ``help`` text, ``--json`` output, or S1's «not available in this build» exit 2) and falls back:

=====================  ============================================  ===============================================
Plugin needs           Asked of the connector (CLI.md)               Fallback (S1 connector, or not in CLI.md yet)
=====================  ============================================  ===============================================
setup                  ``setup [--relay-url] [--channel] [--node]``   the flags ``help`` does not list are left out;
                       (+ ``--hermes-launcher``, not in CLI.md yet)   ``--hermes-launcher`` reported as skipped
pair                   ``pair <CODE>`` (``--code-stdin`` when listed)  -
status                 ``status --json`` (schema 1)                   S1 ``key  value`` text, parsed
service                ``service install --mode auto --like-pid PID   start ``run`` detached (new session, own log,
                       [--node PATH] --json``                         PID file)
update / rollback      ``update --json`` / ``rollback --json``        «not available in this connector build»
logs                   (no command) ``<logs>/connector.log``           the same file (unit and detached fallback)
uninstall              ``uninstall [--purge] --json``                 stop the detached connector the plugin started,
                                                                      remove the code it unpacked; state/config kept
release signature      ``verify_manifest_signature``: Ed25519 in       -
                       Python, keys of release_keys.py (release key only)
=====================  ============================================  ===============================================

Wiring later pieces = editing this file only. Every command runs the bundle as ``<node> <current>/connector.mjs …``
with a small fixed environment (never the gateway's whole environment), from the layout of layout.py.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from .layout import Layout, ensure_private_dir, read_connector_env

MIN_NODE_MAJOR = 22
NOT_AVAILABLE = re.compile(r"not available in this build")
# What a connector command may see of the gateway's environment (nothing per-profile, no secrets).
KEEP_ENV = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "PATH", "TMPDIR", "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS", "SHELL")


class ConnectorMissing(Exception):
    """No connector bundle is installed in this layout."""


class NotAvailable(Exception):
    """The installed connector does not have this command yet (a later slice)."""


@dataclass
class Result:
    code: Optional[int]
    out: str  # the human lines (stdout + stderr; with --json only stderr)
    timed_out: bool = False
    stdout: str = ""  # with --json: the JSON object (CLI.md «--json: exactly one JSON object on stdout»)

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    @property
    def json(self) -> Optional[dict]:
        """The ``--json`` object, or None (an S1 connector prints text whatever the flag)."""
        for line in reversed(self.stdout.strip().splitlines()):
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                except ValueError:
                    return None
                return data if isinstance(data, dict) else None
        return None

    @property
    def text(self) -> str:
        """Everything the command printed, for messages."""
        return "\n".join(t for t in (self.out, self.stdout if self.json is None else "") if t)


@dataclass
class NodeChoice:
    path: str
    version: str
    source: str


@dataclass
class NodeProblem:
    tried: list = field(default_factory=list)  # [(path, why)]

    def message(self) -> str:
        if not self.tried:
            return (f"no Node.js {MIN_NODE_MAJOR} or newer found (set plugins.entries.muxie.settings.node, or install "
                    "Node with `hermes pm install node`)")
        lines = [f"no usable Node.js {MIN_NODE_MAJOR}+:"] + [f"  {p}: {why}" for p, why in self.tried]
        return "\n".join(lines)


def hermes_root() -> Optional[Path]:
    """The Hermes checkout the gateway runs (the parent of its ``hermes_cli`` package), without importing anything."""
    import sys
    mod = sys.modules.get("hermes_cli")
    f = getattr(mod, "__file__", None)
    return Path(f).resolve().parent.parent if f else None


def hermes_launcher() -> Optional[Path]:
    """``<root>/.hermes/bin/hermes``: the launcher of the install this gateway runs (S0 finding 1: ``sys.executable`` is
    a bare CPython that cannot import Hermes' deps). The same rule as stock's
    ``hermes_cli/gateway_runtime_service_identity.py:64-66``."""
    root = hermes_root()
    if root is None:
        return None
    launcher = root / ".hermes" / "bin" / "hermes"
    return launcher if launcher.is_file() else None


def _node_version(path: str) -> tuple[Optional[int], str]:
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15,
                           env={k: os.environ[k] for k in ("HOME", "PATH", "LANG") if k in os.environ})
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"does not run ({type(e).__name__})"
    text = (p.stdout or "").strip()
    if p.returncode != 0 or not text.startswith("v"):
        err = (p.stderr or "").strip().splitlines()[-1:] or [""]
        m = re.search(r"(lib[\w.+-]+\.so[\w.]*)", p.stderr or "")
        if m and "libatomic" in m.group(1):
            return None, (f"missing {m.group(1)}: the libatomic1 package must be installed (Debian/Ubuntu, as "
                          "root: apt-get install libatomic1), then run the command again")
        if m:
            return None, f"missing shared library {m.group(1)}"
        return None, f"exit {p.returncode}: {err[0][:160]}"
    try:
        return int(text[1:].split(".")[0]), text
    except ValueError:
        return None, f"unexpected version {text[:40]!r}"


def find_node(layout: Layout, configured: str = "", which: Callable[[str], Optional[str]] = shutil.which) -> NodeChoice | NodeProblem:
    """Node for the connector. Order: the ``node`` setting; Muxie's own pinned Node (D3, ``<data>/node/current``,
    slice S3); Hermes' Node (``~/.hermes/tools/node-*/bin/node`` or ``~/.hermes/node/bin/node``); ``node`` on PATH."""
    candidates: list[tuple[str, str]] = []
    if configured.strip():
        candidates.append((configured.strip(), "setting node"))
    candidates.append((str(layout.data / "node" / "current" / "bin" / "node"), "muxie"))
    root = hermes_root()
    hermes_home = root.parent if root else layout.home / ".hermes"
    tools = sorted(hermes_home.glob("tools/node-*/bin/node"), key=lambda p: _version_key(p.parent.parent.name), reverse=True)
    candidates += [(str(p), "hermes tools") for p in tools]
    candidates.append((str(hermes_home / "node" / "bin" / "node"), "hermes node"))
    on_path = which("node")
    if on_path:
        candidates.append((on_path, "PATH"))
    problem = NodeProblem()
    seen = set()
    for path, source in candidates:
        if path in seen or not Path(path).is_file():
            continue
        seen.add(path)
        major, info = _node_version(path)
        if major is None:
            problem.tried.append((path, info))
        elif major < MIN_NODE_MAJOR:
            problem.tried.append((path, f"{info} is older than {MIN_NODE_MAJOR}"))
        else:
            return NodeChoice(path, info, source)
    return problem


def _version_key(name: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", name)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def installed_bundle(layout: Layout) -> Optional[Path]:
    """The bundle dir ``current`` points at, when it holds a connector."""
    cur = layout.current
    try:
        real = cur.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return real if (real / "connector.mjs").is_file() else None


def bundle_version(bundle: Path) -> str:
    try:
        return (bundle / "VERSION").read_text(encoding="utf-8").strip()[:64] or "unknown"
    except OSError:
        return "unknown"


@dataclass
class SignatureCheck:
    ok: Optional[bool]  # True: verified with a trusted key; False: bad, malformed or an untrusted key; None: no signature
    reason: str = ""
    key_id: str = ""
    key_name: str = ""
    test_key: bool = False


def verify_manifest_signature(manifest: bytes, signature: Optional[bytes], keys: Optional[Iterable[dict]] = None) -> SignatureCheck:
    """The release channel's Ed25519 check, in this (trusted) Python process, BEFORE anything from the channel runs.

    ``stable.json.sig`` = ``{"alg":"ed25519","keyId","sig"}``, a raw Ed25519 signature over the manifest's exact bytes
    (dist-s2s3 ``connector/CLI.md`` «Update channel», ``connector/src/release.ts``), checked against the keys embedded in
    the plugin (release_keys.py: the release key muxie-release-2026-11 only). A key the manifest announces is never trusted here."""
    from . import ed25519, release_keys
    if signature is None:
        return SignatureCheck(None, "no signature file (stable.json.sig)")
    try:
        sig = json.loads(signature.decode("utf-8"))
        if not isinstance(sig, dict) or sig.get("alg") != "ed25519":
            raise ValueError("not ed25519")
        kid, b64 = str(sig["keyId"]), str(sig["sig"])
        import base64
        raw_sig = base64.b64decode(b64, validate=True)
    except Exception:
        return SignatureCheck(False, 'the signature file is not {"alg":"ed25519","keyId","sig"}')
    trusted = list(release_keys.RELEASE_KEYS if keys is None else keys)
    entry = next((k for k in trusted if k.get("keyId") == kid), None)
    if entry is None:
        return SignatureCheck(False, f"signed by a key this plugin does not trust ({kid}; trusted: "
                                     f"{', '.join(k['keyId'] for k in trusted) or 'none'})", kid)
    try:
        pub = release_keys.raw_key(entry)
    except (ValueError, KeyError):
        return SignatureCheck(False, f"trusted key {kid} is malformed", kid)
    if not ed25519.verify(pub, manifest, raw_sig):
        return SignatureCheck(False, f"bad signature for key {kid}", kid, entry.get("name", ""), bool(entry.get("test")))
    return SignatureCheck(True, "verified", kid, entry.get("name", ""), bool(entry.get("test")))


class Connector:
    """The installed connector's CLI for one layout."""

    def __init__(self, layout: Layout, node: NodeChoice, bundle: Optional[Path] = None):
        self.layout = layout
        self.node = node
        self.bundle = bundle or installed_bundle(layout)
        if self.bundle is None:
            raise ConnectorMissing(f"no connector installed in {layout.connector_dir}")
        self._help: Optional[str] = None

    # ── running ────────────────────────────────────────────────────────────
    def env(self, extra: Optional[dict] = None) -> dict[str, str]:
        env = {k: os.environ[k] for k in KEEP_ENV if os.environ.get(k)}
        env["HOME"] = str(self.layout.home)
        node_dir = str(Path(self.node.path).parent)
        env["PATH"] = node_dir + os.pathsep + env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        env["MUXIE_NODE"] = self.node.path
        env.update(self.layout.subprocess_env())
        env.update(extra or {})
        return env

    def argv(self, args: Iterable[str]) -> list[str]:
        return [self.node.path, str(self.bundle / "connector.mjs"), *args]

    def cwd(self) -> str:
        return str(self.layout.state) if self.layout.state.is_dir() else "/"

    def run(self, args: list[str], timeout: float = 60.0, stdin: Optional[str] = None,
            on_line: Optional[Callable[[str], None]] = None, extra_env: Optional[dict] = None,
            json_out: bool = False) -> Result:
        """Run one CLI command; the human lines are collected and streamed line by line to *on_line*. With
        *json_out*, stdout (the ``--json`` object) is kept apart from stderr (the human lines)."""
        try:
            p = subprocess.Popen(self.argv(args), cwd=self.cwd(), env=self.env(extra_env), text=True,
                                 stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE if json_out else subprocess.STDOUT,
                                 close_fds=True)
        except OSError as e:
            return Result(None, f"could not start the connector: {e}")
        lines: list[str] = []
        stdout: list[str] = []
        deadline = time.monotonic() + timeout
        if stdin is not None:
            try:
                p.stdin.write(stdin)
                p.stdin.close()
            except OSError:
                pass
        import threading

        def pump(stream, into, stream_lines):
            # The pump closes its own stream: closing it from the caller while a read blocks (a descendant that
            # inherited the pipe) would wait on the reader's lock.
            try:
                for line in stream:
                    line = line.rstrip("\n")
                    into.append(line)
                    if on_line and stream_lines:
                        try:
                            on_line(line)
                        except Exception:
                            pass
            except (OSError, ValueError):
                pass
            finally:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass

        pumps = [threading.Thread(target=pump, args=(p.stdout, stdout if json_out else lines, not json_out),
                                  name="muxie-cli-output", daemon=True)]
        if json_out:
            pumps.append(threading.Thread(target=pump, args=(p.stderr, lines, True), name="muxie-cli-err", daemon=True))
        for t in pumps:
            t.start()
        timed_out = False
        try:
            p.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            p.terminate()  # our own child, by its handle
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for t in pumps:
            t.join(timeout=2)
        return Result(p.returncode, "\n".join(lines), timed_out, "\n".join(stdout))

    def help_text(self) -> str:
        if self._help is None:
            r = self.run(["help"], timeout=30)
            self._help = r.out if r.ok else ""
        return self._help

    def offers(self, needle: str) -> bool:
        return needle in self.help_text()

    def _later(self, r: Result, what: str) -> Result:
        if r.code == 2 and NOT_AVAILABLE.search(r.text):
            raise NotAvailable(f"{what} is not available in this connector build ({bundle_version(self.bundle)})")
        return r

    # ── commands ───────────────────────────────────────────────────────────
    def version(self) -> str:
        return bundle_version(self.bundle)

    def setup(self, relay_url: str = "", launcher: Optional[Path] = None, hermes_home: Optional[Path] = None,
              channel: str = "") -> tuple[Result, list[str]]:
        """``setup``; returns the result and the inputs this connector could not take yet (for the report).
        *channel* (a signed channel manifest URL) becomes the connector's own update channel (S3 ``--channel``)."""
        args, skipped = ["setup"], []
        if relay_url:
            args += ["--relay-url", relay_url]
        if channel:
            if self.offers("--channel"):
                args += ["--channel", channel]
            else:
                skipped.append("--channel")
        if self.node.source != "muxie" and self.offers("--node PATH"):
            args += ["--node", self.node.path]  # the Node this plugin found; the release's pinned Node otherwise
        if launcher:
            if self.offers("--hermes-launcher"):
                args += ["--hermes-launcher", str(launcher)]
            else:
                skipped.append("--hermes-launcher")
        if hermes_home:
            if self.offers("--hermes-home"):
                args += ["--hermes-home", str(hermes_home)]
            else:
                skipped.append("--hermes-home")
        return self.run(args, timeout=60), skipped

    def pair(self, code: str, on_line: Optional[Callable[[str], None]] = None, timeout: float = 12 * 60) -> Result:
        """Today's protocol: the app made *code*; this machine claims it and waits for the app's passkey confirm."""
        if self.offers("--code-stdin"):
            return self.run(["pair", "--code-stdin"], timeout=timeout, stdin=code + "\n", on_line=on_line)
        return self.run(["pair", code], timeout=timeout, on_line=on_line)

    def pair_host_foreground(self) -> int:
        """S6: ``pair --host`` in the FOREGROUND of the caller's terminal: stdin, stdout and stderr are inherited (the
        connector draws the QR and asks ``Allow? [y/N]`` itself), nothing is captured and there is no timeout (the code
        lasts 10 minutes; the connector ends it). The environment follows the reduced rules of :meth:`env`, plus TERM and
        COLORTERM so a terminal keeps its colours. Returns the connector's exit code: 0 paired, 3 denied or cancelled,
        1 failed or expired. Ctrl-C reaches the connector too (same foreground process group), which cancels the slot."""
        extra = {k: os.environ[k] for k in ("TERM", "COLORTERM") if os.environ.get(k)}
        try:
            p = subprocess.Popen(self.argv(["pair", "--host"]), cwd=self.cwd(), env=self.env(extra), close_fds=True)
        except OSError as e:
            print(f"could not start the connector: {e}", file=sys.stderr)
            return 1
        interrupts = 0
        while True:
            try:
                return p.wait()
            except KeyboardInterrupt:  # the child got the same SIGINT and ends the pairing; wait for it
                interrupts += 1
                if interrupts == 3:
                    p.terminate()  # our own child, by its handle

    def status(self) -> dict:
        """``status --json`` (CLI.md «status --json»); an S1 connector ignores the flag and prints ``key  value`` text,
        which is parsed instead. One call either way."""
        r = self.run(["status", "--json"], timeout=30, json_out=True)
        data = r.json
        if data is not None:
            return data
        text = r.stdout or r.out
        return parse_status_text(text) if r.ok else {"error": r.text[-400:] or f"exit {r.code}"}

    def paired(self) -> Optional[bool]:
        """Paired = a key AND at least one trusted device (what ``run`` needs). A failed ``pair`` leaves a key with 0
        devices, which S1 ``status`` prints as «paired, key …, 0 trusted device(s)»."""
        return paired_from_status(self.status())

    def service_install(self, caller_args: list[str]) -> Result:
        """``service install --mode auto`` with the gateway's facts (``--like-pid``, supervision.py) and, when the
        connector would not find it on its own, the Node this plugin found (``--node``). ``.json`` has the mode and a
        ``lingerFix`` line when a user unit stops at logout."""
        args = ["service", "install", "--mode", "auto", *caller_args]
        if self.node.source != "muxie":
            args += ["--node", self.node.path]
        r = self.run([*args, "--json"], timeout=120, json_out=True)
        return self._later(r, "service install")

    def update(self) -> Result:
        return self._later(self.run(["update", "--json"], timeout=15 * 60, json_out=True), "update")

    def rollback(self) -> Result:
        return self._later(self.run(["rollback", "--json"], timeout=5 * 60, json_out=True), "rollback")

    def uninstall(self, purge: bool = False) -> Result:
        r = self.run(["uninstall", *(["--purge"] if purge else []), "--json"], timeout=5 * 60, json_out=True)
        return self._later(r, "uninstall")

    def logs(self, lines: int = 40) -> str:
        """The connector's log: the service writes ``<logs>/connector.log`` (S2 ``service.ts`` LOG_NAME), the same file
        the detached fallback appends to. There is no ``logs`` command in the CLI contract."""
        return tail(self.layout.detached_log, lines)

    # ── the detached fallback (until S2's service installer) ───────────────
    def start_detached(self) -> int:
        """Start ``run`` in its own session, stdin /dev/null, output appended to the plugin's log; returns its PID.

        ``sh -c '… &'`` backgrounds the connector and exits at once, so the connector is reparented away from the
        gateway (no zombie in it) and is not the gateway's child when the gateway restarts. Under a systemd gateway
        unit it would still sit in the unit's cgroup: that case needs S2's unit (see bootstrap.py)."""
        ensure_private_dir(self.layout.logs)
        log = self.layout.detached_log
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        extra = {}
        # The local endpoint the plugin needs is off in an S1 connector unless MUXIE_PLUGIN_PORT is set; 0 = any free
        # port. A port the owner put in connector.env wins (the environment would override it, so leave it unset).
        if "MUXIE_PLUGIN_PORT" not in read_connector_env(self.layout.config_file):
            extra["MUXIE_PLUGIN_PORT"] = "0"
        script = 'log=$1; shift; "$@" </dev/null >>"$log" 2>&1 & echo $!'
        p = subprocess.run(["/bin/sh", "-c", script, "sh", str(log), *self.argv(["run"])], cwd=self.cwd(),
                           env=self.env(extra), capture_output=True, text=True, timeout=30, start_new_session=True,
                           close_fds=True)
        try:
            pid = int((p.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise RuntimeError(f"could not start the connector: {(p.stderr or p.stdout or '').strip()[:300]}")
        record = {"pid": pid, "started": time.time(), "bundle": str(self.bundle), "log": str(log)}
        tmp = self.layout.detached_pid_file.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(record, f)
        os.replace(tmp, self.layout.detached_pid_file)
        return pid

    def detached_pid(self) -> Optional[int]:
        return detached_pid(self.layout)

    def stop_detached(self, wait: float = 10.0) -> Optional[int]:
        """SIGTERM the connector this plugin started (the PID in its record, only if that PID still runs our bundle)."""
        pid = detached_pid(self.layout)
        if pid is None:
            return None
        for sig, grace in ((signal.SIGTERM, wait), (signal.SIGKILL, 5.0)):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                break
            except OSError:
                return None  # not ours to signal: keep the record
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline and _alive(pid):
                time.sleep(0.2)
            if not _alive(pid):
                break
        if _alive(pid):
            return None  # still running: keep the record so nothing starts a second one
        try:
            self.layout.detached_pid_file.unlink()
        except OSError:
            pass
        return pid


def detached_pid(layout: Layout) -> Optional[int]:
    """The recorded detached connector's PID, if that process still runs a connector.mjs of this layout."""
    try:
        record = json.loads(layout.detached_pid_file.read_text(encoding="utf-8"))
        pid = int(record["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    args = _cmdline(pid)
    if args is None:
        return None
    roots = {str(layout.connector_dir), str(layout.connector_dir.resolve())}
    if any(a.endswith("connector.mjs") and any(a.startswith(r + os.sep) for r in roots) for a in args):
        return pid
    return None


def _cmdline(pid: int) -> Optional[list]:
    """A process' argv: /proc on Linux, ``ps`` elsewhere (macOS has no /proc)."""
    try:
        return [a.decode("utf-8", "replace") for a in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if a]
    except FileNotFoundError:
        if sys.platform.startswith("linux"):
            return None  # Linux: that pid is gone
    except OSError:
        return None
    try:
        p = subprocess.run(["ps", "-o", "command=", "-p", str(int(pid))], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout.split() if p.returncode == 0 and p.stdout.strip() else None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:  # a zombie still answers kill 0
        return Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


def paired_from_status(st: dict) -> Optional[bool]:
    p = st.get("paired")
    if isinstance(p, dict):  # status --json (CLI.md): {"paired": bool, "fingerprint", "devices": N, "error"}
        if not isinstance(p.get("paired"), bool):
            return None
        return p["paired"] and int(p.get("devices") or 0) > 0
    machine = str(st.get("machine", ""))
    if machine.startswith("not paired"):
        return False
    if machine.startswith("paired"):
        m = re.search(r"(\d+) trusted device", machine)
        return bool(m and int(m.group(1)) > 0)
    return None


EXIT_MEANING = {1: "failed", 2: "usage or config error", 3: "refused (signature, sha256, downgrade, new key or major, "
                "bad version)", 4: "installed but unhealthy: rolled back", 5: "missing prerequisite"}


def explain(r: Result) -> str:
    """One line for a failed command: the ``--json`` error when there is one, else the last output lines."""
    data = r.json or {}
    if data.get("error"):
        line = str(data["error"])
    else:
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        line = " | ".join(lines[-3:]) or "(no output)"
    meaning = EXIT_MEANING.get(r.code or 0)
    return (f"{meaning}: " if meaning and meaning not in line else "") + line[:500]


def parse_status_text(text: str) -> dict:
    """S1 ``status`` prints ``key  value`` lines (``machine  paired, key …``); nested ``  data  …`` lines are skipped."""
    out: dict = {}
    for line in text.splitlines():
        m = re.match(r"^([a-z]+)\s{2,}(.*)$", line)
        if m and m.group(1) not in out:
            out[m.group(1)] = m.group(2).strip()
        elif line.startswith("muxie-connector ") and "version" not in out:
            out["version"] = line.split(" ", 2)[1]
    return out


def tail(path: Path, lines: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return ""
    return "\n".join(data.splitlines()[-lines:])
