"""Where the Muxie connector lives on this machine, as the plugin sees it (PLAN §3).

The same rules as the connector's own ``connector/src/layout.ts`` (``muxieLayout``), so the plugin and the connector
agree on every path without asking each other:

- Linux: ``~/.local/share/muxie`` (data: bundles, Node), ``~/.local/state/muxie`` (key, roster, token file, tools.json,
  logs), ``~/.config/muxie/connector.env``.
- macOS: ``~/Library/Application Support/Muxie`` (data), ``…/Muxie/state``, ``…/Muxie/config``, ``~/Library/Logs/Muxie``;
  an older ``~/.local/state/muxie`` is kept as the state dir.
- ``MUXIE_HOME=<d>``: ``<d>/share``, ``<d>/state``, ``<d>/config`` (logs in state) on every OS.
- ``MUXIE_STATE_DIR`` moves the state dir alone. The connector reads it from its environment or from connector.env; the
  plugin cannot see the connector's environment, so it reads connector.env (the place ``setup`` writes it).

Where MUXIE_HOME comes from: the plugin setting ``muxie_home`` (per profile) first, then the gateway process'
``MUXIE_HOME``. The latter is a per-OS-user layout switch (one connector per OS user serves every profile), not a
per-profile setting, so reading it from ``os.environ`` is consistent with the multiplexed gateway; every per-profile
setting comes from ``ctx.get_config`` only.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

CONFIG_FILE_NAME = "connector.env"
DEFAULT_CONNECTOR_ID = "local"


@dataclass(frozen=True)
class Layout:
    home: Path
    data: Path
    state: Path
    config: Path
    logs: Path
    config_file: Path
    # Which rule chose the roots: MUXIE_HOME | linux | macos; and where the state dir came from.
    origin: str
    state_from: str
    muxie_home: Optional[str]

    # The connector code the plugin installs (PLAN §3): versions/<X.Y.Z>/ and the `current` symlink.
    @property
    def connector_dir(self) -> Path:
        return self.data / "connector"

    @property
    def versions_dir(self) -> Path:
        return self.connector_dir / "versions"

    @property
    def current(self) -> Path:
        return self.connector_dir / "current"

    @property
    def tools_file(self) -> Path:
        return self.state / "tools.json"

    @property
    def install_lock(self) -> Path:
        return self.state / "install.lock"

    @property
    def detached_pid_file(self) -> Path:
        return self.state / "connector-detached.json"

    @property
    def detached_log(self) -> Path:
        return self.logs / "connector.log"

    def endpoint_files(self) -> list[Path]:
        """The connectors' local endpoint token files (``connector-<id>.plugin.json``, 0600, CONTRACT.md §1)."""
        try:
            return sorted(self.state.glob("connector-*.plugin.json"))
        except OSError:
            return []

    def subprocess_env(self) -> dict[str, str]:
        """What a connector command the plugin runs needs to find the same layout (only MUXIE_HOME; the rest is in
        connector.env, which the connector reads itself)."""
        return {"MUXIE_HOME": self.muxie_home} if self.muxie_home else {}


def parse_env_file(text: str) -> dict[str, str]:
    """A small dotenv reader for connector.env (the connector parses it with Node's ``util.parseEnv``; ``setup`` writes
    plain ``KEY=value`` lines). Handles comments, ``export``, single/double/back quotes and inline `` #`` comments."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key or not all(c.isalnum() or c in "_.-" for c in key):
            continue
        value = value.strip()
        end = value.find(value[0], 1) if value[:1] in ("'", '"', "`") else -1
        if end > 0:  # a quoted value; anything after the closing quote (a comment) is ignored
            inner = value[1:end]
            value = inner.replace("\\n", "\n") if value[0] == '"' else inner
        else:
            value = value.split("#", 1)[0].rstrip()
        values[key] = value
    return values


def read_connector_env(path: Path) -> dict[str, str]:
    try:
        return parse_env_file(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {}


def muxie_layout(muxie_home: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
                 platform: Optional[str] = None) -> Layout:
    """The layout for this OS user. *muxie_home* is the plugin setting; *env* defaults to the process environment and
    is read for HOME and MUXIE_HOME only."""
    env = os.environ if env is None else env
    platform = platform or sys.platform
    home = Path(env.get("HOME") or Path.home())
    mh = (muxie_home or "").strip() or (env.get("MUXIE_HOME") or "").strip() or None
    legacy_state = home / ".local" / "state" / "muxie"
    if mh:
        root = Path(mh).expanduser().resolve()
        origin, data, state, config, logs = "MUXIE_HOME", root / "share", root / "state", root / "config", root / "state"
        mh = str(root)
    elif platform == "darwin":
        base = home / "Library" / "Application Support" / "Muxie"
        origin, data, state, config, logs = "macos", base, base / "state", base / "config", home / "Library" / "Logs" / "Muxie"
    else:
        origin = "linux"
        data, state, config, logs = home / ".local" / "share" / "muxie", legacy_state, home / ".config" / "muxie", legacy_state
    state_from = "layout"
    if origin == "macos" and not state.exists() and legacy_state.exists():
        state, state_from = legacy_state, "legacy"
    config_file = config / CONFIG_FILE_NAME
    moved = read_connector_env(config_file).get("MUXIE_STATE_DIR", "").strip()
    if moved:
        state, state_from = Path(moved).expanduser(), "MUXIE_STATE_DIR"  # logs stay (layout.ts does the same)
    return Layout(home=home, data=data, state=state, config=config, logs=logs, config_file=config_file,
                  origin=origin, state_from=state_from, muxie_home=mh)


# No relay is built in (the connector refuses without one): the ``relay_url`` setting, else RELAY_URL in connector.env.
RELAY_EXAMPLE = "wss://<your relay>"


def configured_relay(layout: Layout, setting: str = "") -> str:
    """The relay the connector will dial: the setting, else connector.env's RELAY_URL; "" when neither is set."""
    return (setting or "").strip() or read_connector_env(layout.config_file).get("RELAY_URL", "").strip()


def relay_missing_message(where: "Layout | str | Path | None" = None) -> str:
    """The one message for «no relay»: the plugin setting and the connector.env line (*where*: a layout or the file's
    path), each with the example."""
    where = str(where.config_file if isinstance(where, Layout) else (where or CONFIG_FILE_NAME))
    return (f"no relay configured: set it with `hermes config set plugins.entries.muxie.settings.relay_url {RELAY_EXAMPLE}` "
            f"(or the line RELAY_URL={RELAY_EXAMPLE} in {where})")


def connector_id(layout: Layout) -> str:
    """The connector id ``setup`` wrote (connector.env ``CONNECTOR_ID``), else the code default."""
    return read_connector_env(layout.config_file).get("CONNECTOR_ID", "").strip() or DEFAULT_CONNECTOR_ID


def ensure_private_dir(path: Path) -> None:
    """Create *path* (and parents) as 0700 when missing; an existing dir is left as it is."""
    if not path.is_dir():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
