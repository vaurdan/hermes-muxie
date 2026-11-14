"""First install of the connector from the plugin (PLAN §3 step 3), and getting it running.

Runs on a background thread started by ``/muxie pair`` / ``/muxie setup`` (or in the foreground for ``hermes muxie``),
never from ``register()``. Every step reports to a :class:`Progress`, which the chat command turns into ONE message
edited in place.

1. ``install.lock`` in the state dir (``fcntl.flock``): two gateways (or a gateway and a terminal) never install at once.
2. The release channel (setting ``channel_url``; ``hermes muxie setup --from`` overrides) and WHY its bundle may run:
   a manifest (``stable.json``) whose Ed25519 signature (``stable.json.sig``) verifies here, in Python, against the
   keys embedded in the plugin (release_keys.py, the release key muxie-release-2026-11 only), or a bundle sha256
   pinned in trusted plugin config (setting ``bundle_sha256`` or ``connector.lock.json``). A sha256 that comes from the channel itself never
   suffices; an unsigned network channel is refused (CONTRACT.md §7).
3. sha256 of the tgz, then a checked unpack (one top dir, regular files and dirs only, no ``..``, size caps) into
   ``versions/<VERSION>``; ``current`` flips atomically, the old target becomes ``previous``.
4. Node (connector_adapter.find_node), then ``muxie-connector setup`` (+ ``--hermes-launcher`` when the connector takes
   it).
5. Pairing if a code was given (today's app-initiated protocol). An S1 connector refuses to ``run`` unpaired, so the
   service starts only once the machine is paired, unless ``Options.start_unpaired`` (host-initiated pairing, S6) and
   the connector offers ``pair --host`` (S7: ``run`` stays up unpaired).
6. ``service install --mode auto`` with the gateway's supervision facts; while the connector lacks it (S2), the
   connector starts detached.
7. Wait until the local endpoint answers (local_api.health).
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import connector_adapter as ca
from . import local_api, supervision
from .local_api import PLUGIN_VERSION
from .layout import Layout, configured_relay, ensure_private_dir, relay_missing_message

VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# The public signed channel (PLAN.md D4): the latest GitHub release of the plugin's own repo, the same URL as the
# connector's PUBLIC_CHANNEL_URL (connector/src/release.ts; a connector unit pins that they match). An empty
# ``channel_url`` setting means DEFAULT_CHANNEL_URL (tests clear it: they never reach the network).
PUBLIC_CHANNEL_URL = "https://github.com/vaurdan/hermes-muxie/releases/latest/download/stable.json"
DEFAULT_CHANNEL_URL = PUBLIC_CHANNEL_URL
MAX_DOWNLOAD = 200 * 1024 * 1024
MAX_UNPACKED = 400 * 1024 * 1024
MAX_MEMBERS = 5000
HEALTH_WAIT_S = 45.0


class BootstrapError(Exception):
    pass


class Refusal(BootstrapError):
    """A precondition that is not met (no relay): nothing was started, so it is told once, in the outcome only."""


# ── progress ──────────────────────────────────────────────────────────────
class Progress:
    """Lines of one status message; ``emit`` gets the whole text after every change (the chat edits one message)."""

    def __init__(self, title: str, emit: Callable[[str], None], secrets: tuple = ()):
        self.title = title
        self.lines: list[str] = []
        self._emit = emit
        self._secrets = [s for s in secrets if s]
        self.lock = threading.Lock()

    def add_secret(self, secret: str) -> None:
        if secret and secret not in self._secrets:
            self._secrets.append(secret)

    def redact(self, text: str) -> str:
        for s in self._secrets:
            for form in {s, s.replace("-", ""), s.upper(), s.replace("-", "").upper()}:
                if form:
                    text = text.replace(form, "[code]")
        return text

    def text(self) -> str:
        return "\n".join([self.title, *self.lines])

    def _push(self) -> None:
        try:
            self._emit(self.text())
        except Exception:
            pass

    def step(self, line: str) -> None:
        with self.lock:
            self.lines.append("… " + self.redact(line))
        self._push()

    def ok(self, line: str) -> None:
        self._replace_last("✓ " + self.redact(line))

    def warn(self, line: str) -> None:
        with self.lock:
            self.lines.append("! " + self.redact(line))
        self._push()

    def fail(self, line: str) -> None:
        self._replace_last("✗ " + self.redact(line))

    def note(self, line: str) -> None:
        with self.lock:
            self.lines.append(self.redact(line))
        self._push()

    def _replace_last(self, line: str) -> None:
        with self.lock:
            if self.lines and self.lines[-1].startswith("… "):
                self.lines[-1] = line
            else:
                self.lines.append(line)
        self._push()


# ── settings and outcome ──────────────────────────────────────────────────
@dataclass
class Options:
    channel_url: str = ""
    relay_url: str = ""
    node: str = ""
    bundle_sha256: str = ""  # a pinned bundle sha256 (trusted plugin setting), see Pins
    code: str = ""  # a pairing code from the app (today's protocol); empty = install only
    profile: str = "default"
    reinstall: bool = False  # hermes muxie setup --from: install that source even when a connector is installed
    # Host-initiated pairing (S6): the connector must run BEFORE it is paired (it opens the slot). With S7 `run` stays
    # up unpaired; a connector whose help lacks `pair --host` is older and still refuses, so it stays not started.
    start_unpaired: bool = False


@dataclass
class Outcome:
    ok: bool
    summary: str
    paired: Optional[bool] = None
    running: bool = False
    version: str = ""
    skipped: list = field(default_factory=list)


# ── lock ──────────────────────────────────────────────────────────────────
class InstallLock:
    """``install.lock`` (flock). ``acquire`` waits up to *wait* seconds; the holder's pid/profile is in the file."""

    def __init__(self, layout: Layout, profile: str):
        self.path = layout.install_lock
        self.layout = layout
        self.profile = profile
        self.fd: Optional[int] = None

    def holder(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8").strip()[:200]
        except OSError:
            return ""

    def acquire(self, wait: float = 20.0) -> bool:
        ensure_private_dir(self.layout.state)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    return False
                time.sleep(0.25)
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps({"pid": os.getpid(), "profile": self.profile, "since": time.time()}).encode())
        self.fd = fd
        return True

    def release(self) -> None:
        if self.fd is not None:
            try:
                os.ftruncate(self.fd, 0)
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()


# ── channel ───────────────────────────────────────────────────────────────
@dataclass
class Pins:
    """sha256 values pinned in TRUSTED plugin config: the ``bundle_sha256`` setting (one value, always enforced when
    set) and ``connector.lock.json`` beside this file (installed with the plugin from its git source)."""
    setting: str = ""
    lock: dict = field(default_factory=dict)  # sha256 -> version

    def all(self) -> set:
        return ({self.setting} if self.setting else set()) | set(self.lock)

    def source(self, sha: str) -> str:
        if self.setting and sha == self.setting:
            return "sha256 pinned in plugin settings (bundle_sha256)"
        if sha in self.lock:
            return f"sha256 pinned in connector.lock.json ({self.lock[sha] or 'version ?'})"
        return ""


LOCK_FILE = Path(__file__).resolve().parent / "connector.lock.json"


def load_pins(setting: str = "", lock_file: Path = LOCK_FILE) -> Pins:
    pin = (setting or "").strip().lower()
    if pin and not SHA256_RE.match(pin):
        raise BootstrapError("plugins.entries.muxie.settings.bundle_sha256 is not a sha256 (64 hex characters)")
    lock: dict = {}
    try:
        data = json.loads(lock_file.read_text(encoding="utf-8"))
        for entry in data.get("pins", []) if isinstance(data, dict) and data.get("v") == 1 else []:
            sha = str(entry.get("sha256", "")).lower()
            if SHA256_RE.match(sha):
                lock[sha] = str(entry.get("version") or "")
    except (OSError, ValueError, AttributeError):
        pass
    return Pins(pin, lock)


@dataclass
class Artifact:
    location: str  # a local path or an https URL
    sha256: str  # expected; "" = one of `allowed` (a local tgz checked against the lock pins)
    version_hint: str
    channel: str
    trust: str  # why it may run: «signature …» or «sha256 pinned …»
    allowed: set = field(default_factory=set)
    test_key: bool = False

    @property
    def local(self) -> bool:
        return not self.location.startswith("https://")


def _local_path(url: str) -> Optional[Path]:
    if url.startswith("file://"):
        parts = urllib.parse.urlsplit(url)
        if parts.netloc not in ("", "localhost"):
            raise BootstrapError(f"file:// channel on another host ({parts.netloc}) is not supported")
        return Path(urllib.parse.unquote(parts.path))
    if url.startswith("/"):
        return Path(url)
    return None


def _sidecar_sha(path: Path) -> Optional[str]:
    """The ``.sha256`` beside a tgz, when there is one. It comes from the same place as the tgz, so it is only a
    consistency check, never a reason to trust the tgz."""
    try:
        first = path.read_text(encoding="utf-8").split()
    except OSError:
        return None
    sha = (first[0] if first else "").lower()
    if not SHA256_RE.match(sha):
        raise BootstrapError(f"{path.name} does not hold a sha256")
    return sha


def _fetch_small(url: str, limit: int = 1024 * 1024) -> bytes:
    local = _local_path(url)
    if local is not None:
        data = local.read_bytes()
    elif url.startswith("https://"):
        with urllib.request.urlopen(url, timeout=30) as r:
            data = r.read(limit + 1)
    else:
        raise BootstrapError(f"unsupported channel URL {url!r} (file:// or https:// only)")
    if len(data) > limit:
        raise BootstrapError(f"{url} is larger than {limit} bytes")
    return data


def resolve_channel(channel: str, pins: Optional[Pins] = None) -> Artifact:
    """The connector artifact a channel names, and why it may run (CONTRACT.md §7).

    Nothing from a channel runs unless the plugin trusts it: a manifest whose Ed25519 signature verifies here against
    the plugin's embedded keys (release_keys.py), or a bundle whose sha256 is pinned in trusted plugin config (the
    ``bundle_sha256`` setting or ``connector.lock.json``). A sha256 the channel itself supplies (the manifest of an
    unsigned channel, a ``.sha256`` beside a tgz) proves nothing about who made the bundle. A network channel must be
    signed; a pinned ``bundle_sha256`` is enforced on top of a signature."""
    pins = pins or Pins()
    channel = (channel or "").strip()
    if not channel:
        raise BootstrapError(
            "no release channel is configured. For a local "
            "bundle: hermes config set plugins.entries.muxie.settings.channel_url file:///path/connector-<v>.tgz and "
            "pin its sha256: hermes config set plugins.entries.muxie.settings.bundle_sha256 <sha256>")
    if channel.startswith("http://"):
        raise BootstrapError("plain http channels are refused; use https:// or file://")
    local = _local_path(channel)
    name = (local.name if local else urllib.parse.urlsplit(channel).path.rsplit("/", 1)[-1])
    if name.endswith(".tgz"):
        if local is None:
            raise BootstrapError("a bare tgz over the network is refused: use a signed channel manifest (stable.json)")
        if not local.is_file():
            raise BootstrapError(f"{local} does not exist")
        if not pins.all():
            raise BootstrapError(
                "a local connector tgz is installed only with its sha256 pinned in trusted plugin config: hermes config "
                "set plugins.entries.muxie.settings.bundle_sha256 <sha256> (the .sha256 file beside the tgz comes from "
                "the same place as the tgz and proves nothing)")
        side = _sidecar_sha(local.with_name(local.name + ".sha256"))
        if side and pins.setting and side != pins.setting:
            raise BootstrapError("the .sha256 beside the tgz disagrees with the pinned bundle_sha256")
        m = re.match(r"^connector-(.+)\.tgz$", name)
        if pins.setting:
            return Artifact(str(local), pins.setting, m.group(1) if m else "", channel, pins.source(pins.setting))
        return Artifact(str(local), "", m.group(1) if m else "", channel, "sha256 pinned in connector.lock.json",
                        allowed=set(pins.lock))
    if name.endswith(".json"):
        # The signed channel of dist-s2s3 connector/CLI.md «Update channel»: stable.json + stable.json.sig.
        raw = _fetch_small(channel)
        try:
            sig = _fetch_small(channel + ".sig", 64 * 1024)
        except (OSError, BootstrapError, ValueError):
            sig = None
        check = ca.verify_manifest_signature(raw, sig)
        if check.ok is False:
            raise BootstrapError(f"the channel manifest is refused: {check.reason}")
        try:
            manifest = json.loads(raw.decode("utf-8"))
            art = manifest["bundle"]
            url, sha, version = str(art["url"]), str(art["sha256"]).lower(), str(manifest["version"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise BootstrapError("the channel manifest is not {schema:1, version, bundle:{url, sha256}}") from None
        if manifest.get("schema") != 1 or not SHA256_RE.match(sha) or not VERSION_RE.match(version):
            raise BootstrapError("the channel manifest has a bad schema, sha256 or version")
        stem = name[:-len(".json")]
        if manifest.get("channel") not in (None, stem):
            raise BootstrapError(f"the manifest is for channel {manifest.get('channel')!r}, not {stem!r}")
        need = str(manifest.get("minPlugin") or "")
        if need and _older(PLUGIN_VERSION, need):
            raise BootstrapError(f"this release needs plugin {need} or newer (this is {PLUGIN_VERSION}): "
                                 "run hermes plugins update muxie")
        if pins.setting and sha != pins.setting:
            raise BootstrapError(f"the channel's bundle {sha[:12]}… is not the pinned bundle_sha256 {pins.setting[:12]}…")
        if check.ok:
            trust = (f"signature of key {check.key_id} ({check.key_name})"
                     + (": a TEST key, so this is not a release" if check.test_key else ""))
        elif local is None:
            raise BootstrapError(f"an unsigned network channel is refused ({check.reason})")
        elif pins.source(sha):
            trust = pins.source(sha) + " (the manifest itself is unsigned)"
        else:
            raise BootstrapError(f"the local channel manifest is unsigned ({check.reason}) and its bundle sha256 is "
                                 "not pinned: sign it (stable.json.sig) or pin plugins.entries.muxie.settings."
                                 "bundle_sha256")
        if "://" in url:
            target = url
        else:
            target = urllib.parse.urljoin(channel, url) if "://" in channel else str(local.parent / url)
        if not (target.startswith("file://") or target.startswith("/") or target.startswith("https://")):
            raise BootstrapError(f"the bundle URL {target!r} is neither file:// nor https://")
        return Artifact(target if not target.startswith("file://") else str(_local_path(target)), sha, version,
                        channel, trust, test_key=check.test_key)
    raise BootstrapError(f"channel {channel!r} is neither a connector .tgz nor a manifest .json")


def _older(have: str, need: str) -> bool:
    def key(v: str) -> tuple:
        return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v)[:3])
    return key(have) < key(need)


def fetch(artifact: Artifact, into: Path) -> tuple[Path, int, str]:
    """The tgz in *into* (copied or downloaded), its sha256 checked against the trusted value; returns
    (path, bytes, sha256). Nothing in it has run yet."""
    ensure_private_dir(into)
    fd, tmp = tempfile.mkstemp(prefix="connector-", suffix=".tgz.part", dir=into)
    h, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as out:
            if artifact.local:
                src = open(artifact.location, "rb")
            else:
                src = urllib.request.urlopen(artifact.location, timeout=60)
            with src:
                while True:
                    chunk = src.read(1 << 16)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_DOWNLOAD:
                        raise BootstrapError(f"the artifact is larger than {MAX_DOWNLOAD // (1024 * 1024)} MB")
                    h.update(chunk)
                    out.write(chunk)
        got = h.hexdigest()
        if artifact.sha256 and got != artifact.sha256:
            raise BootstrapError(f"sha256 mismatch: expected {artifact.sha256[:16]}…, got {got[:16]}…")
        if not artifact.sha256 and got not in artifact.allowed:
            raise BootstrapError(f"sha256 {got[:16]}… is not pinned in connector.lock.json")
        return Path(tmp), size, got
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def unpack(tgz: Path, layout: Layout) -> tuple[Path, str]:
    """Checked unpack into ``versions/<VERSION>``; returns (dir, version). An existing complete dir is reused."""
    ensure_private_dir(layout.versions_dir)
    incoming = Path(tempfile.mkdtemp(prefix=".incoming-", dir=layout.versions_dir))
    try:
        with tarfile.open(tgz, "r:gz") as tar:
            members = tar.getmembers()
            if not members or len(members) > MAX_MEMBERS:
                raise BootstrapError("the tgz is empty or has too many entries")
            top = members[0].name.split("/", 1)[0]
            total = 0
            for m in members:
                name = m.name
                parts = name.split("/")
                if name.startswith("/") or ".." in parts or parts[0] != top or not top or top in (".", ".."):
                    raise BootstrapError(f"unsafe path in the tgz: {name!r}")
                if not (m.isreg() or m.isdir()):
                    raise BootstrapError(f"the tgz holds a link or device ({name!r})")
                total += m.size
                if total > MAX_UNPACKED:
                    raise BootstrapError("the tgz unpacks to more than the size cap")
            try:
                tar.extractall(incoming, members=members, filter="data")
            except TypeError:  # Python without extraction filters: members were checked above
                tar.extractall(incoming, members=members)
        src = incoming / top
        if not (src / "connector.mjs").is_file() or not (src / "VERSION").is_file():
            raise BootstrapError("the tgz is not a connector bundle (no connector.mjs or VERSION)")
        version = (src / "VERSION").read_text(encoding="utf-8").strip()
        if not VERSION_RE.match(version):
            raise BootstrapError(f"bad VERSION in the bundle: {version[:40]!r}")
        dest = layout.versions_dir / version
        os.chmod(src, 0o755)
        if dest.exists() or dest.is_symlink():
            # Always the verified tree: an existing dir of the same version may hold other bytes (a rebuilt dev
            # version, a local edit). Swap atomically; the old tree goes once the new one is in place.
            aside = layout.versions_dir / f".old-{version}-{os.getpid()}"
            os.replace(dest, aside)
            os.replace(src, dest)
            if aside.is_symlink() or aside.is_file():
                aside.unlink()
            else:
                shutil.rmtree(aside, ignore_errors=True)
        else:
            os.replace(src, dest)
        return dest, version
    finally:
        shutil.rmtree(incoming, ignore_errors=True)


def make_current(layout: Layout, version: str) -> Optional[str]:
    """Point ``current`` at ``versions/<version>`` atomically; the old target becomes ``previous``. Returns the old one."""
    old = None
    try:
        old = os.readlink(layout.current)
    except OSError:
        pass
    target = f"versions/{version}"
    if old == target:
        return old
    tmp = layout.connector_dir / f".current-{os.getpid()}"
    try:
        os.unlink(tmp)
    except OSError:
        pass
    os.symlink(target, tmp)
    os.replace(tmp, layout.current)
    if old and old.startswith("versions/"):
        ptmp = layout.connector_dir / f".previous-{os.getpid()}"
        try:
            os.unlink(ptmp)
        except OSError:
            pass
        os.symlink(old, ptmp)
        os.replace(ptmp, layout.connector_dir / "previous")
    return old


# ── the whole run ─────────────────────────────────────────────────────────
def wait_healthy(layout: Layout, profile: str, seconds: float = HEALTH_WAIT_S,
                 alive: Callable[[], bool] = lambda: True) -> local_api.Health:
    deadline = time.monotonic() + seconds
    h = local_api.health(layout, timeout=1.5, profile=profile)
    while not h.ok and time.monotonic() < deadline and alive():
        time.sleep(0.5)
        h = local_api.health(layout, timeout=1.5, profile=profile)
    return h


def _pair_lines(progress: Progress) -> Callable[[str], None]:
    """The connector's pairing output, reduced to what the chat needs (the key to compare, the result)."""
    def on_line(line: str) -> None:
        m = re.search(r"This machine's key: ([0-9A-F ]{8,})", line)
        if m:
            progress.note(f"   this machine's key: {m.group(1).strip()}. Confirm in the Muxie app and check it shows "
                          "the same key.")
        elif line.startswith("Paired."):
            progress.note("   " + line[:200])
    return on_line


def run(layout: Layout, opts: Options, progress: Progress,
        sup: Optional[supervision.Supervision] = None) -> Outcome:
    """Install (if needed) → setup → pair (if a code) → service → healthy. Never raises; the outcome says what happened."""
    progress.add_secret(opts.code)
    # No relay is built in: refuse before the lock, the channel or any download (a running connector has one).
    if not configured_relay(layout, opts.relay_url) and not local_api.health(layout, timeout=1.5, profile=opts.profile).ok:
        return Outcome(False, relay_missing_message(layout))
    lock = InstallLock(layout, opts.profile)
    try:
        if not lock.acquire():
            return Outcome(False, f"another Muxie install is running on this machine ({lock.holder() or 'unknown'}); "
                                  "try again in a minute")
        with lock:
            return _run_locked(layout, opts, progress, sup or supervision.detect())
    except Refusal as e:
        return Outcome(False, progress.redact(str(e)))
    except BootstrapError as e:
        progress.fail(str(e))
        return Outcome(False, progress.redact(str(e)))
    except Exception as e:  # never into Hermes
        progress.fail(f"unexpected error: {type(e).__name__}: {e}")
        return Outcome(False, progress.redact(f"unexpected error: {type(e).__name__}: {e}"))


def _run_locked(layout: Layout, opts: Options, progress: Progress, sup: supervision.Supervision) -> Outcome:
    h = local_api.health(layout, timeout=1.5, profile=opts.profile)
    bundle = ca.installed_bundle(layout)
    if h.ok and not opts.code and not opts.reinstall:
        progress.ok(f"a connector already answers ({h.detail})")
        return Outcome(True, "the connector is already installed and running", paired=True, running=True,
                       version=ca.bundle_version(bundle) if bundle else "")

    # Checked again under the lock (run() checked before taking it): never past here without a relay.
    if not configured_relay(layout, opts.relay_url):
        raise Refusal(relay_missing_message(layout))
    skipped: list = []
    replaced = None  # the version a reinstall replaced, when it changed
    if bundle is None or opts.reinstall:
        progress.step("finding the connector release and checking that it may run here")
        art = resolve_channel(opts.channel_url, load_pins(opts.bundle_sha256))
        have = ca.bundle_version(bundle) if bundle is not None else ""
        if have and art.version_hint and _older(art.version_hint, have):
            raise BootstrapError(f"{art.version_hint} is older than the installed {have}: a downgrade goes through the "
                                 f"connector (muxie-connector update --pin {art.version_hint})")
        progress.ok(f"release {art.version_hint or '?'} from {art.channel}; trusted by: {art.trust}")
        if art.test_key:
            progress.warn("signed with the TEST release key: fine for a lab, never a release")
        progress.step("copying and checking sha256")
        tgz, size, got = fetch(art, layout.connector_dir / "downloads")
        try:
            progress.ok(f"sha256 {got[:12]}… matches the trusted value ({size // 1024} KB)")
            progress.step("unpacking")
            dest, version = unpack(tgz, layout)
        finally:
            try:
                os.unlink(tgz)
            except OSError:
                pass
        old = make_current(layout, version)
        if old and old != f"versions/{version}":
            replaced = old.split("/", 1)[-1]
        bundle = dest
        progress.ok(f"connector {version} in {dest}")
    else:
        progress.ok(f"connector {ca.bundle_version(bundle)} already installed ({bundle})")

    progress.step("looking for Node.js")
    node = ca.find_node(layout, opts.node)
    if isinstance(node, ca.NodeProblem):
        raise BootstrapError(node.message())
    progress.ok(f"Node {node.version} ({node.source}: {node.path})")
    conn = ca.Connector(layout, node, bundle)

    progress.step("writing the connector's config (setup)")
    launcher = ca.hermes_launcher()
    # The connector's own update channel (setup --channel takes http(s) only): an https manifest.
    channel = opts.channel_url if opts.channel_url.startswith("https://") and \
        opts.channel_url.split("?")[0].endswith(".json") else ""
    r, skipped = conn.setup(relay_url=opts.relay_url, launcher=launcher, channel=channel)
    if not r.ok:
        raise BootstrapError("setup failed: " + ca.explain(r))
    progress.ok("setup done" + (f" (this connector does not take {', '.join(skipped)} yet)" if skipped else ""))

    paired = conn.paired()
    if opts.code:
        progress.step("pairing: waiting for the Muxie app (the code lasts 10 minutes)")
        r = conn.pair(opts.code, on_line=_pair_lines(progress))
        if r.timed_out:
            raise BootstrapError("pairing timed out")
        if not r.ok:
            raise BootstrapError("pairing failed: " + progress.redact(ca.explain(r)))
        progress.ok("paired")
        paired = True
    unpaired = paired is False
    if unpaired and not (opts.start_unpaired and conn.offers("pair --host")):
        progress.note("Not paired yet. In the Muxie app: Settings › Add a machine, then send /muxie pair <CODE> "
                      "(or run: hermes muxie pair <CODE>).")
        return Outcome(True, "installed; pair it next", paired=False, version=conn.version(), skipped=skipped)

    h = local_api.health(layout, timeout=1.5, profile=opts.profile)
    if h.ok and replaced:
        pid = conn.detached_pid()
        if pid is not None:
            progress.step(f"stopping the detached connector {replaced} (pid {pid}) to start {conn.version()}")
            conn.stop_detached()
            progress.ok(f"stopped {replaced} (pid {pid})")
            h = local_api.health(layout, timeout=1.5, profile=opts.profile)
        else:
            progress.warn(f"a connector still runs (it may be {replaced}); it runs {conn.version()} once its service "
                          "restarts it")
    if h.ok:
        progress.ok(f"connector answers ({h.detail})")
        return Outcome(True, "running, not paired yet" if unpaired else "paired and running", paired=not unpaired,
                       running=True, version=conn.version(), skipped=skipped)

    progress.step(f"starting the connector as a service (gateway: {sup.describe()})")
    started_pid: Optional[int] = None
    try:
        r = conn.service_install(sup.cli_args())
        if not r.ok:
            raise BootstrapError("service install failed: " + ca.explain(r))
        info = r.json or {}
        mode = info.get("mode") or (info.get("service") or {}).get("mode") or "?"
        progress.ok(f"service installed and started (mode {mode})")
        fix = info.get("lingerFix") or (info.get("service") or {}).get("lingerFix")
        if fix:
            progress.warn(f"this user's services stop at logout until linger is on; run once as root: {fix}")
    except ca.NotAvailable:
        pid = conn.detached_pid()
        if pid is None:
            pid = conn.start_detached()
            started_pid = pid
        progress.ok(f"started detached (pid {pid}); service units come with slice S2")
        if sup.kind != supervision.DETACHED:
            progress.warn(f"this gateway runs under {sup.describe()}: a detached connector sits in the gateway's "
                          "cgroup and stops when the gateway's unit restarts, until the S2 service installer lands; "
                          "/muxie status starts it again")
        else:
            progress.note("   " + (supervision.describe_for_user(sup) or ""))

    progress.step("waiting for the connector to answer")
    alive = (lambda: ca._alive(started_pid)) if started_pid else (lambda: True)
    h = wait_healthy(layout, opts.profile, alive=alive)
    if not h.ok:
        logs = ca.tail(layout.detached_log, 6) if started_pid else ""
        raise BootstrapError(f"the connector did not answer: {h.detail}" + (f"\nlast log lines:\n{logs}" if logs else ""))
    progress.ok(f"connector answers ({h.detail})")
    return Outcome(True, "running, not paired yet" if unpaired else "paired and running", paired=not unpaired,
                   running=True, version=conn.version(), skipped=skipped)


def _last(text: str, n: int = 3) -> str:
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    return " | ".join(lines[-n:])[:500] or "(no output)"
