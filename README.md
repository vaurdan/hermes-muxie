# hermes-muxie: the Muxie plugin for Hermes

[Muxie](https://chat.muxie.sh) is a phone and web app for talking to your Hermes agents. This plugin connects the Hermes
gateway on your machine to Muxie:

- `/muxie …` in any chat with your agent, and `hermes muxie …` in a terminal, install, pair, check and update the
  **Muxie connector**, the small program that links this machine to the Muxie relay;
- the connector's agent tools become native Hermes tools (`muxie_*`);
- lifecycle hooks send id-only events (turn started/ended, compaction, sub-agents) to the local connector, so the app
  shows live status. Message text never leaves the hook: only ids, counts and flags are forwarded, to `127.0.0.1`.

Requirements: Hermes **0.22.6 or newer**, Linux (systemd or none) or macOS (macOS is not tested yet), `git`, an
account in the Muxie app, and **the URL of a Muxie relay** (there is no default relay: you configure yours). Windows is
not supported.

## Install

```sh
hermes plugins install vaurdan/hermes-muxie
hermes plugins enable muxie
hermes config set plugins.entries.muxie.settings.relay_url wss://<your relay>
```

- Run `enable` as a separate step: it is what adds the `muxie` toolset to your saved platform toolsets
  (`plugins install --enable` does not). The running gateway picks the plugin up without a restart.
- **The relay is required.** Replace `wss://<your relay>` with the relay your Muxie app uses (set it once per profile).
  There is no built-in relay: without one, `/muxie pair` and `hermes muxie setup` stop at once with
  `no relay configured: set it with …` and download nothing, and `/muxie status` shows `relay      not set`.
  A connector installed by hand reads it from `RELAY_URL` in `~/.config/muxie/connector.env`
  (`muxie-connector setup --relay-url wss://<your relay>` writes it).

To install an exact, reviewed revision: `hermes plugins install vaurdan/hermes-muxie --ref <40-character commit sha>`.

**Telegram:** the bot's command menu lists only a limited number of commands, so `/muxie` may not appear there. Type it
by hand; it works the same.

## Pair your phone

In a **private chat** with your agent (pairing is refused in groups, where everyone would see the code):

```
/muxie pair
```

1. The first time, the plugin installs the connector (see below). Progress is shown in one message, edited in place.
2. The message then shows a pairing code and a link. In the Muxie app, choose **Add a machine** and type the code, or
   open the link on the phone. Codes expire after 10 minutes and work once.
3. The app shows this machine's name and key; confirm with your passkey.
4. Back in the chat, answer **Allow** or **Deny**. Nothing is paired until you allow it. Where no buttons show, answer
   with `/muxie allow <CODE>` or `/muxie deny <CODE>`.

In a terminal, `hermes muxie pair` does the same: it prints the code, a QR code and asks `Allow? [y/N]`.
If the app shows you a code instead, use `/muxie pair <CODE>`.

`/muxie status` shows whether the connector is installed, running and paired. `/muxie help` lists every command.

## The connector: a separate, supervised process

The plugin itself stays small. The connector runs as its **own service**, never as a child of the gateway, so it keeps
running across gateway restarts and Hermes upgrades:

| Your gateway runs… | The connector gets… |
|---|---|
| as a systemd user service (`hermes gateway install`) | `~/.config/systemd/user/muxie-connector.service` |
| as root in a systemd system service | `/etc/systemd/system/muxie-connector.service` |
| on macOS (launchd) | `~/Library/LaunchAgents/sh.muxie.connector.plist` |
| anywhere else (nohup, containers, Termux) | a detached supervisor; the plugin starts it again after a reboot, at the first agent turn |

A systemd user service stops when you log out unless lingering is on; the install message and `hermes muxie status`
say so when it is off (`sudo loginctl enable-linger $USER`). The plugin never runs `sudo` itself.

Files (Linux): code in `~/.local/share/muxie/` (the connector and its own pinned Node.js 22), state and logs in
`~/.local/state/muxie/` (this machine's key and the paired devices, 0600), config in `~/.config/muxie/connector.env`.
`/muxie logs [N]` shows the connector's last log lines.

## Signed releases and self-update

Connector releases are the [GitHub releases](https://github.com/vaurdan/hermes-muxie/releases) of this repository. Each
release carries `connector-<version>.tgz` and `stable.json`, a manifest with the sha256 of the bundle and of the official
Node.js builds, signed with the Muxie release key (Ed25519, key id `0641c4073af01b9e`, public key in
[`release_keys.py`](release_keys.py)).

- Nothing from a release runs before its signature verifies against that embedded key, and the bundle's sha256 matches
  the signed manifest. Plain `http` channels and unsigned manifests are refused.
- The connector updates itself: it checks the channel every 6 hours, verifies, runs a self-test, switches over, and
  rolls back on its own if the new version is not healthy within 90 seconds. It never downgrades, changes major
  version or trusts a new key unattended.
- By hand: `/muxie update` or `hermes muxie update`; `hermes muxie rollback` goes back to the previous version.
  `~/.local/share/muxie/connector/current/muxie-connector update --pin X.Y.Z` stays on one version (`--unpin` follows
  the channel again); `MUXIE_AUTO_UPDATE=off` in `connector.env` turns the automatic check off.
- The plugin itself updates with Hermes: `hermes plugins update muxie`, then restart the gateway so it loads the new
  code.

## Settings

`hermes config set plugins.entries.muxie.settings.<key> <value>` (per profile):

| Key | Meaning |
|---|---|
| `relay_url` | **required**: the relay the connector dials, e.g. `wss://<your relay>` (no default) |
| `channel_url` | where releases come from; empty = this repository's latest GitHub release |
| `bundle_sha256` | a connector bundle sha256 you trust: enforced on top of the signature, required for a local `file://` bundle |
| `node` | a Node.js 22+ for the connector; empty = Muxie's pinned Node, then Hermes' Node, then `node` on `PATH` |
| `muxie_home` | moves every Muxie directory (like `MUXIE_HOME`); for tests |

## Uninstall

```sh
hermes muxie uninstall          # stops and removes the service, the connector code and its Node.js
hermes plugins remove muxie
```

`hermes muxie uninstall` keeps this machine's key and paired devices in `~/.local/state/muxie`; add `--purge` to delete
them too (and the config and logs). Removing only the plugin leaves the connector running on purpose, so the app keeps
working until you uninstall it.

## Security notes

- The plugin talks to the connector only on `127.0.0.1`, with a bearer token from a 0600 file, and sends no `Origin`.
- It reads its own settings and that token file. It never reads your `.env`, `auth.json`, sessions or `state.db`.
- It declares no Hermes capabilities (it overrides no tool, makes no model calls and no platform actions).
- Report security issues privately to the repository owner rather than in a public issue.

## Development

```sh
python3 -m unittest discover -s tests -v
```

No Hermes is needed: the tests use a fake plugin context, fake connector endpoints on `127.0.0.1` and a fake connector
bundle. `tests/fixtures/test-release-key.json` and the `stable-1.0.0.json(.sig)` beside it are a **test key** and a
manifest it signed: the plugin never trusts that key, and the tests prove it refuses that manifest.

The connector's source and the plugin ↔ connector contract are not in this repository: comments that point at
`CONTRACT.md`, `connector/…` or `design/…` refer to Muxie's main source tree. The released connector bundle is in each
GitHub release.

## License

MIT, see [LICENSE](LICENSE).
