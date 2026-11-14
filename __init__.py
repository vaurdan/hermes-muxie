"""Muxie for Hermes (design/distribution/PLAN.md, slice S4).

``register(ctx)`` is cheap and side-effect free: it also runs in short-lived CLI processes and in auto-spawned
idle-exit gateways (S0), so it starts no thread and contacts nothing. It registers:

- ``/muxie`` (chat) and ``hermes muxie`` (terminal): commands.py;
- the native Muxie tools listed in the connector's ``tools.json`` (one small file read): tools_proxy.py;
- observer hooks that turn lifecycle events into id-only signals for the connector: signals.py (its sender thread
  starts with the first event and stops in ``on_unload``).

Install: ``hermes plugins install <source> --enable``; settings in ``plugins.entries.muxie.settings`` (README.md).
"""

from __future__ import annotations

from .commands import HELP, MuxiePlugin
from .signals import HOOKS
from .tools_proxy import register_tools


def register(ctx) -> None:
    plugin = MuxiePlugin(ctx)
    ctx.register_command("muxie", plugin.slash, description="Muxie: pair this machine, check or update its connector",
                         args_hint="status | pair [<CODE>] | allow|deny <CODE> | start | update | logs | help")
    ctx.register_cli_command("muxie", help="Muxie connector: setup, pair, status, update, logs, uninstall",
                             setup_fn=plugin.cli_setup, handler_fn=plugin.cli_run, description=HELP)
    for hook in HOOKS:
        ctx.register_hook(hook, plugin.signals.callback(hook))
    try:
        layout = plugin.layout()
    except Exception:  # an odd HOME or muxie_home must not fail the plugin load
        layout = None
    plugin.catalogue = register_tools(ctx, layout, plugin.layout, plugin.profile)
    cat = plugin.catalogue
    plugin.signals.catalogue_info = lambda: {"revision": cat.revision, "tools": len(cat.tools)} if cat else None
    ctx.on_unload(plugin.unload)
