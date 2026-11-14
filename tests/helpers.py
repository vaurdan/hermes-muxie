"""Shared test helpers: load the plugin as a package, a fake PluginContext, a fake connector endpoint, a fake connector
bundle (a Python program behind a fake ``node``), temp HOME dirs under the scratch root."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get("MUXIE_TEST_SCRATCH") or tempfile.gettempdir())
# No relay is built in: tests that run the bootstrap name one (a closed local port: nothing is dialled).
TEST_RELAY = "ws://127.0.0.1:1"


def load_plugin(name: str = "muxie_under_test"):
    """Import hermes-plugin/muxie as a package (the way Hermes' loader and the validator probe do)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "__init__.py",
                                                  submodule_search_locations=[str(PLUGIN_DIR)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    # Unit tests never reach the network: an empty channel_url means no channel here (test_channel.py restores the
    # public default and pins it).
    importlib.import_module(f"{name}.bootstrap").DEFAULT_CHANNEL_URL = ""
    return mod


def sub(name: str):
    load_plugin()
    return importlib.import_module(f"muxie_under_test.{name}")


def temp_dir(prefix: str) -> Path:
    base = SCRATCH if SCRATCH.is_dir() else Path(tempfile.gettempdir())
    return Path(tempfile.mkdtemp(prefix=f"dist-s4-{prefix}-", dir=base))


class FakeHandle:
    def __init__(self, ok=True):
        self.ok = ok
        self.texts = []
        self.lock = threading.Lock()

    def edit(self, text):
        with self.lock:
            self.texts.append(text)
        return {"ok": True, "edited": True}


class FakeCtx:
    """The PluginContext surface the plugin uses."""

    def __init__(self, settings=None, profile="default", post_ok=True, choice=None):
        self.settings = dict(settings or {})
        self.profile_name = profile
        self.commands, self.cli, self.hooks, self.tools, self.unloads = {}, {}, {}, {}, []
        self.posts = []
        self.post_ok = post_ok
        self.choice = choice
        self.asked = []

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_command(self, name, handler, description="", args_hint="", argument_mode=None):
        self.commands[name] = handler

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
        self.cli[name] = (setup_fn, handler_fn)

    def register_hook(self, name, cb, *, hold_stream=False):
        self.hooks[name] = cb

    def register_tool(self, name, toolset, schema, handler, check_fn=None, requires_env=None, is_async=False,
                      description="", emoji="", override=False):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler, "check_fn": check_fn}

    def on_unload(self, cb):
        self.unloads.append(cb)

    def post_message(self, text):
        h = FakeHandle(self.post_ok)
        h.texts.append(text)
        self.posts.append(h)
        return h

    def ask_choice(self, question, choices):
        self.asked.append((question, choices))
        return self.choice(question, choices) if callable(self.choice) else self.choice


class FakeEndpoint:
    """A connector local endpoint: records requests, answers from ``routes[path] -> (status, body)`` or a callable."""

    def __init__(self, token="t0ken", routes=None, delay=0.0):
        self.token = token
        self.routes = dict(routes or {})
        self.delay = delay
        self.got = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def _answer(self):
                n = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(n) if n else b""
                rec = {"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                       "raw": raw, "body": json.loads(raw) if raw else None}
                outer.got.append(rec)
                if outer.delay:
                    time.sleep(outer.delay)
                if rec["headers"].get("authorization") != f"Bearer {outer.token}":
                    status, body = 401, {"ok": False, "error": "bad token"}
                else:
                    r = outer.routes.get(self.path, (404, {"ok": False, "error": "not found"}))
                    status, body = r(rec) if callable(r) else r
                data = json.dumps(body).encode()
                try:
                    self.send_response(status)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass

            do_GET = do_POST = _answer

            def log_message(self, *_a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def write_file(self, state_dir: Path, connector_id="local", mode=0o600, url=None, kind="plugin"):
        """The connector's token file: ``plugin`` (S1 plugin endpoint) or ``health`` (S2/S3 health endpoint)."""
        state_dir.mkdir(parents=True, exist_ok=True)
        f = state_dir / f"connector-{connector_id}.{kind}.json"
        f.write_text(json.dumps({"v": 1, "connectorId": connector_id, "url": url or self.url, "token": self.token}))
        os.chmod(f, mode)
        return f

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ── a fake connector bundle (Python behind a fake `node`) ───────────────────
FAKE_NODE = """#!/bin/sh
{log}if [ "$1" = "--version" ]; then echo v22.99.0; exit 0; fi
exec python3 "$@"
"""

# connector.mjs of the fake bundle: S1's CLI surface, enough for the plugin (help/setup/status/pair/run, and the
# «not available in this build» exit 2 of service/update/rollback/uninstall).
FAKE_CONNECTOR = r'''
import json, os, secrets, signal, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
args = sys.argv[1:]
cmd = args[0] if args else "run"
home = os.environ.get("MUXIE_HOME")
if home:
    state, config = os.path.join(home, "state"), os.path.join(home, "config")
else:
    state = os.path.join(os.environ["HOME"], ".local", "state", "muxie")
    config = os.path.join(os.environ["HOME"], ".config", "muxie")
envfile = os.path.join(config, "connector.env")
log = open(os.path.join(os.environ.get("FAKE_LOG_DIR", "/tmp"), "fake-connector-calls.jsonl"), "a") if os.environ.get("FAKE_LOG_DIR") else None
if log: log.write(json.dumps({"argv": args, "env_keys": sorted(os.environ)}) + "\n"); log.close()
paired = os.path.join(state, "paired")
S2 = os.environ.get("FAKE_S2") == "1"
S7 = os.environ.get("FAKE_S7") == "1"  # S6/S7: `pair --host`, and the connector stays up unpaired
if cmd == "help":
    if S2:  # the dist-s2s3 usage lines the plugin looks at
        host = "  pair --host         this machine makes the code, the phone enters it\n" if S7 else ""
        print("usage: muxie-connector [command]   (connector/CLI.md; --json: one JSON object on stdout)\n  pair <CODE> [--replace]\n{host}  status [--json]\n  setup [--relay-url URL] [--channel URL] [--node PATH | --no-node] [--json]\n  service install|remove|status|restart [--mode auto|system|user|launchd|detached] [--node PATH]\n        [--like-pid PID] [--caller-json JSON] [--no-start] [--json]".replace("{host}", host))
    else:
        print("usage: muxie-connector [command]\n  pair <CODE> [--replace]\n  status\n  setup [--relay-url URL]\n  update | rollback | service | uninstall   not available in this build (slice S2/S3)")
    sys.exit(0)
if S2 and cmd == "service" and args[1:2] == ["install"]:
    if not S7 and not os.path.exists(os.path.join(state, "paired")):
        print(json.dumps({"ok": False, "command": "service install", "error": "not paired", "code": 1})); sys.exit(1)
    import subprocess
    log = os.path.join(state, "connector.log")
    out = subprocess.run(["/bin/sh", "-c", 'log=$1; shift; "$@" </dev/null >>"$log" 2>&1 & echo $!', "sh", log, sys.executable, os.path.abspath(__file__), "run"],
                         capture_output=True, text=True, start_new_session=True)
    open(os.path.join(state, "fake-service.pid"), "w").write(out.stdout.strip())
    print("service: user unit written and started", file=sys.stderr)
    print(json.dumps({"ok": True, "command": "service install", "mode": "user", "unit": "muxie-connector.service", "lingerFix": "sudo loginctl enable-linger tester", "code": 0}))
    sys.exit(0)
if cmd in ("update", "rollback", "service", "uninstall"):
    print(f"muxie-connector {cmd}: not available in this build (slice S2/S3)", file=sys.stderr); sys.exit(2)
if cmd == "setup":
    if any(a.startswith("--hermes") for a in args): print("setup: unknown option", file=sys.stderr); sys.exit(2)
    os.makedirs(state, 0o700, exist_ok=True); os.makedirs(config, 0o700, exist_ok=True)
    if not os.path.exists(envfile):
        fd = os.open(envfile, os.O_WRONLY | os.O_CREAT, 0o600); os.write(fd, b"CONNECTOR_ID=local\n"); os.close(fd)
    print("config  connector.env: created"); sys.exit(0)
if cmd == "status" and S2 and "--json" in args:
    n = 1 if os.path.exists(paired) else 0
    print("reading status", file=sys.stderr)
    print(json.dumps({"ok": True, "command": "status", "schema": 1, "version": "9.9.9-fake",
                      "paired": {"paired": bool(n), "fingerprint": "AB12" if n else None, "devices": n, "error": None},
                      "relay": {"url": "ws://127.0.0.1:1", "source": "default"}, "connector": {"id": "local", "source": "default"},
                      "service": {"installed": False, "mode": None}, "code": 0}))
    sys.exit(0)
if cmd == "status":
    print("muxie-connector 9.9.9-fake (bundle, commit fake)")
    print("machine  " + ("paired, key AB12 CD34, 1 trusted device(s)" if os.path.exists(paired) else "not paired"))
    print("relay    ws://127.0.0.1:1 (default)"); print("id       local (default)"); sys.exit(0)
if cmd == "pair" and args[1:2] == ["--host"]:
    # the S6 terminal flow, reduced to what the plugin must get right: argv, the inherited stdio and the environment
    os.makedirs(state, 0o700, exist_ok=True)
    link = lambda n: os.readlink(f"/proc/self/fd/{n}")
    json.dump({"argv": args, "env_keys": sorted(os.environ), "fds": [link(0), link(1), link(2)], "cwd": os.getcwd()},
              open(os.path.join(state, "pair-host-call.json"), "w"))
    hx = os.path.join(state, "host-exit")
    sys.exit(int(open(hx).read()) if os.path.exists(hx) else 0)
if cmd == "pair":
    code = args[1] if len(args) > 1 else ""
    print(f"Pairing local (fakehost) with the relay. This machine's key: AB12 CD34 EF56")
    print("Confirm in the Muxie app; check that the app shows the same key.")
    if code != os.environ.get("FAKE_GOOD_CODE", "K7QF-9M2T-XR4D"):
        print(f"pairing failed: the relay does not know code {code}", file=sys.stderr); sys.exit(1)
    os.makedirs(state, 0o700, exist_ok=True); open(paired, "w").close()
    print("Paired. 1 device(s) trusted."); sys.exit(0)
if cmd == "run":
    if not S7 and not os.path.exists(paired):
        print("local is not paired yet.", file=sys.stderr); sys.exit(1)
    token = secrets.token_urlsafe(32)
    class H(BaseHTTPRequestHandler):
        # As S1's projects/plugin-endpoint.ts: only POST /v1/ops (400 after the token check for a {"v":0} probe);
        # in S2 mode also GET /v1/health (dist-s2s3 health.ts).
        def do_POST(self):
            if self.path != "/v1/ops": self.send_response(404); self.end_headers(); return
            ok = self.headers.get("authorization") == "Bearer " + token
            self.send_response(400 if ok else 401); self.end_headers()
        def do_GET(self):
            if S2 and self.path == "/v1/health" and self.headers.get("authorization") == "Bearer " + token:
                body = json.dumps({"ok": True, "pid": os.getpid(), "version": "9.9.9-fake", "startedAt": 0,
                                   "relay": {"linked": True, "since": 0, "connects": 1}}).encode()
                self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body); return
            self.send_response(404); self.end_headers()
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MUXIE_PLUGIN_PORT", "0") or 0)), H)
    f = os.path.join(state, "connector-local.plugin.json")
    fd = os.open(f + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, json.dumps({"v": 1, "connectorId": "local", "url": f"http://127.0.0.1:{srv.server_address[1]}", "token": token}).encode()); os.close(fd)
    os.replace(f + ".tmp", f)
    hf = os.path.join(state, "connector-local.health.json")
    if S2:
        fd = os.open(hf + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, json.dumps({"v": 1, "url": f"http://127.0.0.1:{srv.server_address[1]}", "token": token, "pid": os.getpid(), "version": "9.9.9-fake", "startedAt": 0}).encode()); os.close(fd)
        os.replace(hf + ".tmp", hf)
    def bye(*a):
        for x in (f, hf):
            try: os.unlink(x)
            except OSError: pass
        os._exit(0)
    signal.signal(signal.SIGTERM, bye)
    print("connected to relay as local", flush=True)
    srv.serve_forever()
print("unknown command", file=sys.stderr); sys.exit(2)
'''


def make_fake_bundle(where: Path, version="9.9.9-fake", extra_members=None, log_dir=None, s2=False, s7=False) -> tuple[Path, str, Path]:
    """A connector-<version>.tgz (+ .sha256) and the fake node; returns (tgz, sha256, node). With *log_dir* the fake
    connector logs each call's argv and environment keys there (the plugin passes it no such variable itself). With
    *s2* it behaves like the dist-s2s3 CLI (--json, service install, health endpoint); with *s7* also like S6/S7 (`pair
    --host` in its help, runs and installs the service while unpaired)."""
    where.mkdir(parents=True, exist_ok=True)
    node = where / "fake-node"
    extra = (f"export FAKE_LOG_DIR='{log_dir}'\n" if log_dir else "") + ("export FAKE_S2=1\n" if s2 or s7 else "") + ("export FAKE_S7=1\n" if s7 else "")
    node.write_text(FAKE_NODE.format(log=extra))
    os.chmod(node, 0o755)
    tgz = where / f"connector-{version}.tgz"
    top = f"connector-{version}"
    with tarfile.open(tgz, "w:gz") as tar:
        def add(name, data: bytes, mode=0o644):
            info = tarfile.TarInfo(f"{top}/{name}" if name else top)
            info.size, info.mode, info.mtime = len(data), mode, 0
            tar.addfile(info, io.BytesIO(data))
        d = tarfile.TarInfo(top)
        d.type, d.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(d)
        add("VERSION", version.encode())
        add("connector.mjs", FAKE_CONNECTOR.encode())
        add("muxie-connector", b"#!/bin/sh\nexec node connector.mjs \"$@\"\n", 0o755)
        for m in extra_members or []:
            tar.addfile(*m)
    sha = hashlib.sha256(tgz.read_bytes()).hexdigest()
    (where / f"{tgz.name}.sha256").write_text(f"{sha}  {tgz.name}\n")
    return tgz, sha, node


def kill_detached(layout) -> None:
    """Stop the connector a test started: the plugin's detached one and the fake S2 «service» (exact recorded PIDs)."""
    try:
        rec = json.loads(layout.detached_pid_file.read_text())
        os.kill(int(rec["pid"]), 15)
    except (OSError, ValueError, KeyError):
        pass
    try:
        os.kill(int((layout.state / "fake-service.pid").read_text().strip()), 15)
    except (OSError, ValueError):
        pass


def rm(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


# ── Ed25519 signing for tests only (RFC 8032 §5.1.6); the plugin itself only verifies ─────────────────────
def ed_keypair_and_signer(seed: bytes):
    """(raw public key, sign(msg) -> 64-byte signature) for a 32-byte *seed*."""
    ed = sub("ed25519")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = ed._compress(ed._mul(a, ed.G))

    def sign(msg: bytes) -> bytes:
        r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % ed.L
        R = ed._compress(ed._mul(r, ed.G))
        k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % ed.L
        return R + ((r + k * a) % ed.L).to_bytes(32, "little")
    return pub, sign


def signed_channel(where: Path, tgz: Path, sha: str, seed: bytes = b"\x07" * 32, version="9.9.9-fake",
                   channel="stable", min_plugin="0.1.0"):
    """stable.json + stable.json.sig beside *tgz*, signed with a test key; returns (manifest path, trusted key entry)."""
    import base64
    rk = sub("release_keys")
    pub, sign = ed_keypair_and_signer(seed)
    entry = {"keyId": rk.key_id(pub), "publicKey": base64.b64encode(pub).decode(), "name": "unit-test key", "test": True}
    m = where / f"{channel}.json"
    raw = json.dumps({"schema": 1, "channel": channel, "version": version, "minPlugin": min_plugin,
                      "bundle": {"url": tgz.name, "sha256": sha, "size": tgz.stat().st_size}}).encode()
    m.write_bytes(raw)
    (where / f"{channel}.json.sig").write_text(json.dumps({"alg": "ed25519", "keyId": entry["keyId"],
                                                           "sig": base64.b64encode(sign(raw)).decode()}))
    return m, entry
