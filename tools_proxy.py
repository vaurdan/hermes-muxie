"""Native agent tools (D5, PLAN §7; CONTRACT.md §3-§4).

The connector writes ``tools.json`` (0600) in its state dir from the same table that feeds its MCP server. The plugin
reads it in ``register()`` (one small file read, nothing else), so the tools exist even when the connector is down at
gateway start, and registers each tool as a proxy: a call is ``POST /v1/tools/call`` to the connector's local endpoint
(127.0.0.1, bearer token, no proxy, timeout). A call while the connector is down, or for a tool the connector no
longer has (a running session keeps its old tool list after a reload), returns a clear tool error.

The catalogue is checked before anything is registered: owner-only file, size cap, ``v: 1``, names ``muxie_*`` (so a
catalogue can never shadow a built-in or another plugin's tool), a JSON-schema object for parameters, short
descriptions. A bad entry is skipped; a bad file registers nothing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import local_api
from .layout import Layout

# One tool is always registered, whatever tools.json says: stock adds a plugin's toolset to the SAVED
# platform_toolsets lists (which the default config.yaml has) only when the plugin has tools registered at
# `plugins install/enable` time (hermes_cli/plugins_cmd.py _toggle_plugin_toolset, _get_plugin_toolset_key). Without a
# fixed tool the `muxie` toolset would stay off on cli/telegram/… when tools.json appears later. It is declared in
# plugin.yaml provides_tools; catalogue tools share its toolset.
STATUS_TOOL = "muxie_status"
STATUS_SCHEMA = {
    "name": STATUS_TOOL,
    "description": ("Check whether this machine's Muxie connector is running and which Muxie tools it offers. "
                    "No arguments."),
    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
}
MAX_FILE = 256 * 1024
MAX_TOOLS = 32
NAME_RE = re.compile(r"^muxie_[a-z0-9_]{1,48}$")
MAX_DESCRIPTION = 1024
DEFAULT_TIMEOUT_S = 20.0
MAX_TIMEOUT_S = 120.0
TOOLSET = "muxie"

try:  # Hermes' public helpers (hermes_cli/data/plugin_api.json: tools.registry)
    from tools.registry import tool_error, tool_result
except Exception:  # outside Hermes (tests, the validator's bare probe)
    def tool_result(data: Any = None, **kwargs: Any) -> str:
        return json.dumps(data if data is not None else kwargs, ensure_ascii=False)

    def tool_error(message: str, **extra: Any) -> str:
        return json.dumps({"error": message, **extra}, ensure_ascii=False)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict
    timeout_s: float
    emoji: str


@dataclass
class Catalogue:
    tools: list
    problems: list
    revision: str = ""


def load_catalogue(layout: Layout, profile: str) -> Catalogue:
    path = layout.tools_file
    if not path.exists():
        return Catalogue([], [])
    if not local_api.private_file_ok(path):
        return Catalogue([], [f"{path} is not a 0600 file of this user: ignored"])
    try:
        if path.stat().st_size > MAX_FILE:
            return Catalogue([], [f"{path} is larger than {MAX_FILE // 1024} KB: ignored"])
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return Catalogue([], [f"{path} unreadable: {type(e).__name__}"])
    if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("tools"), list):
        return Catalogue([], [f"{path} is not {{v:1, tools:[...]}}: ignored"])
    profiles = data.get("profiles")
    if isinstance(profiles, list) and profile not in profiles:
        return Catalogue([], [f"profile {profile} is not in tools.json profiles"], str(data.get("revision") or ""))
    tools, problems, seen = [], [], set()
    for raw in data["tools"][: MAX_TOOLS + 1]:
        spec, why = _spec(raw)
        if spec is None:
            problems.append(why)
        elif spec.name == STATUS_TOOL:
            problems.append(f"{STATUS_TOOL} is the plugin's own tool: the catalogue entry is ignored")
        elif spec.name in seen:
            problems.append(f"{spec.name}: listed twice")
        else:
            seen.add(spec.name)
            tools.append(spec)
    if len(data["tools"]) > MAX_TOOLS:
        problems.append(f"more than {MAX_TOOLS} tools: the rest ignored")
        tools = tools[:MAX_TOOLS]
    return Catalogue(tools, problems, str(data.get("revision") or ""))


def _spec(raw: Any) -> tuple[Optional[ToolSpec], str]:
    if not isinstance(raw, dict):
        return None, "an entry is not an object"
    name = raw.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        return None, f"bad tool name {str(name)[:60]!r} (muxie_[a-z0-9_]+)"
    desc = raw.get("description")
    if not isinstance(desc, str) or not desc.strip() or len(desc) > MAX_DESCRIPTION:
        return None, f"{name}: description missing or over {MAX_DESCRIPTION} characters"
    params = raw.get("parameters")
    if not isinstance(params, dict) or params.get("type") != "object":
        return None, f"{name}: parameters must be a JSON schema with type object"
    try:
        json.dumps(params)
    except (TypeError, ValueError):
        return None, f"{name}: parameters are not JSON"
    t = raw.get("timeoutMs")
    timeout = DEFAULT_TIMEOUT_S
    if isinstance(t, (int, float)) and not isinstance(t, bool) and t > 0:
        timeout = min(MAX_TIMEOUT_S, float(t) / 1000.0)
    emoji = raw.get("emoji") if isinstance(raw.get("emoji"), str) and len(raw.get("emoji")) <= 4 else ""
    return ToolSpec(name, desc.strip(), params, timeout, emoji), ""


def _session_env(name: str) -> str:
    try:  # public: hermes_cli/data/plugin_api.json gateway.session_context:get_session_env
        from gateway.session_context import get_session_env
        return get_session_env(name) or ""
    except Exception:
        return ""


def make_handler(spec: ToolSpec, layout_fn: Callable[[], Layout], profile: str) -> Callable[..., str]:
    def handler(args: dict, **kw: Any) -> str:
        return call(spec, layout_fn(), profile, args if isinstance(args, dict) else {}, kw)
    handler.__name__ = f"muxie_proxy_{spec.name}"
    return handler


def call(spec: ToolSpec, layout: Layout, profile: str, args: dict, kw: dict) -> str:
    """One proxied call. Answers are tool results or tool errors, never exceptions."""
    session_id = str(kw.get("session_id") or _session_env("HERMES_SESSION_ID") or "")
    body = {"v": 1, "tool": spec.name, "args": args, "sessionId": session_id or None, "profile": profile,
            "taskId": str(kw.get("task_id") or "") or None}
    found = local_api.endpoints(layout)
    if not found:
        return tool_error(f"{spec.name}: the Muxie connector is not running on this machine (no local endpoint). "
                          "Ask the user to run /muxie status.")
    last = ""
    for ep in found:
        try:
            status, answer = local_api.request(ep, "POST", "/v1/tools/call", body, timeout=spec.timeout_s,
                                               profile=profile)
        except local_api.LocalApiError as e:
            last = (f"{spec.name}: the Muxie connector did not answer ({e.kind}). Ask the user to run /muxie status.")
            continue
        answer = answer if isinstance(answer, dict) else {}
        if status == 200 and answer.get("ok"):
            return tool_result(answer.get("result"))
        if status == 404 and answer.get("error") == "unknown_tool":
            return tool_error(f"{spec.name}: the connector does not offer this tool any more (its tool list changed); "
                              "a new session has the current tools.")
        if status == 401:
            last = f"{spec.name}: the Muxie connector refused the plugin's token (a stale token file?)"
            continue
        message = answer.get("message") or answer.get("error") or f"HTTP {status}"
        return tool_error(f"{spec.name}: {str(message)[:500]}")
    return tool_error(last or f"{spec.name}: the Muxie connector did not answer")


def status_result(layout: Layout, profile: str, catalogue: Optional[Catalogue]) -> str:
    """``muxie_status``: a local health probe only (1.5 s), never a connector command."""
    from . import connector_adapter as ca
    bundle = ca.installed_bundle(layout)
    h = local_api.health(layout, timeout=1.5, profile=profile)
    return tool_result({
        "installed": bundle is not None,
        "version": ca.bundle_version(bundle) if bundle else None,
        "running": h.ok,
        "detail": h.detail,
        "tools": [t.name for t in (catalogue.tools if catalogue else [])],
        "hint": None if h.ok else "Ask the user to send /muxie status (and /muxie pair <CODE> if it is not installed).",
    })


def register_tools(ctx: Any, layout: Optional[Layout], layout_fn: Callable[[], Layout], profile: str) -> Catalogue:
    try:
        cat = load_catalogue(layout, profile) if layout is not None else Catalogue([], ["no Muxie layout"])
    except Exception as e:  # never fail the plugin load
        cat = Catalogue([], [f"tools.json not read ({type(e).__name__})"])
    ctx.register_tool(name=STATUS_TOOL, toolset=TOOLSET, schema=STATUS_SCHEMA,
                      handler=lambda args, **kw: status_result(layout_fn(), profile, cat),
                      description=STATUS_SCHEMA["description"], emoji="🧩")
    for spec in cat.tools:
        schema = {"name": spec.name, "description": spec.description, "parameters": spec.parameters}
        ctx.register_tool(name=spec.name, toolset=TOOLSET, schema=schema, handler=make_handler(spec, layout_fn, profile),
                          description=spec.description, emoji=spec.emoji or "🧩")
    return cat
