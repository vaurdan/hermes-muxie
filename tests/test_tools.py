"""Native tools: the tools.json catalogue checks and the proxy to the connector's local endpoint."""

import json
import os
import unittest

from helpers import FakeCtx, FakeEndpoint, rm, sub, temp_dir

tools_proxy = sub("tools_proxy")
layout_mod = sub("layout")
local_api = sub("local_api")

SPACE = {"name": "muxie_space", "description": "Read or change a Muxie Space. Ops: read, post.",
         "parameters": {"type": "object", "properties": {"op": {"type": "string"}}, "required": ["op"]}}


class CatalogueTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("tools")
        self.layout = layout_mod.muxie_layout(str(self.dir / "mh"))
        self.layout.state.mkdir(parents=True)

    def tearDown(self):
        rm(self.dir)

    def write(self, data, mode=0o600):
        f = self.layout.tools_file
        f.write_text(json.dumps(data) if not isinstance(data, str) else data)
        os.chmod(f, mode)

    def test_no_file_no_tools(self):
        cat = tools_proxy.load_catalogue(self.layout, "default")
        self.assertEqual((cat.tools, cat.problems), ([], []))

    def test_valid_entries_registered_bad_ones_skipped(self):
        self.write({"v": 1, "revision": "r1", "tools": [
            SPACE,
            {"name": "write_file", "description": "x", "parameters": {"type": "object"}},  # would shadow a built-in
            {"name": "muxie_bad", "description": "", "parameters": {"type": "object"}},
            {"name": "muxie_noschema", "description": "d", "parameters": {"type": "array"}},
            dict(SPACE),  # twice
            {"name": "muxie_slow", "description": "d", "parameters": {"type": "object"}, "timeoutMs": 999999},
        ]})
        cat = tools_proxy.load_catalogue(self.layout, "default")
        self.assertEqual([t.name for t in cat.tools], ["muxie_space", "muxie_slow"])
        self.assertEqual(cat.tools[1].timeout_s, tools_proxy.MAX_TIMEOUT_S)
        self.assertEqual(len(cat.problems), 4, cat.problems)
        self.assertEqual(cat.revision, "r1")
        ctx = FakeCtx()
        tools_proxy.register_tools(ctx, self.layout, lambda: self.layout, "default")
        self.assertEqual(sorted(ctx.tools), ["muxie_slow", "muxie_space", "muxie_status"])
        self.assertEqual({t["toolset"] for t in ctx.tools.values()}, {"muxie"})
        self.assertEqual(ctx.tools["muxie_space"]["toolset"], "muxie")
        self.assertEqual(ctx.tools["muxie_space"]["schema"]["parameters"], SPACE["parameters"])
        self.assertIsNone(ctx.tools["muxie_space"]["check_fn"], "tools exist even while the connector is down")

    def test_loose_mode_or_bad_shape_registers_nothing(self):
        self.write({"v": 1, "tools": [SPACE]}, mode=0o644)
        cat = tools_proxy.load_catalogue(self.layout, "default")
        self.assertEqual(cat.tools, [])
        self.assertIn("not a 0600 file", cat.problems[0])
        for bad in ('{"v": 2, "tools": []}', "[]", "not json", json.dumps({"v": 1, "tools": {}})):
            self.write(bad)
            self.assertEqual(tools_proxy.load_catalogue(self.layout, "default").tools, [])
        self.write("x" * (tools_proxy.MAX_FILE + 1))
        self.assertIn("larger than", tools_proxy.load_catalogue(self.layout, "default").problems[0])

    def test_status_tool_always_there_and_reserved(self):
        self.write({"v": 1, "tools": [{"name": "muxie_status", "description": "fake", "parameters": {"type": "object"}}]})
        cat = tools_proxy.load_catalogue(self.layout, "default")
        self.assertEqual(cat.tools, [])
        self.assertIn("plugin's own tool", cat.problems[0])
        ctx = FakeCtx()
        tools_proxy.register_tools(ctx, self.layout, lambda: self.layout, "default")
        self.assertEqual(list(ctx.tools), ["muxie_status"])
        out = json.loads(ctx.tools["muxie_status"]["handler"]({}, session_id="s"))
        self.assertEqual((out["installed"], out["running"], out["tools"]), (False, False, []))
        self.assertIn("/muxie status", out["hint"])
        ep = FakeEndpoint(routes={"/v1/health": (200, {"ok": True, "pid": 7, "version": "1.0.0",
                                                         "relay": {"linked": True}})})
        try:
            ep.write_file(self.layout.state, kind="health")
            out = json.loads(ctx.tools["muxie_status"]["handler"]({}))
            self.assertTrue(out["running"])
            self.assertIn("version 1.0.0, pid 7, relay linked", out["detail"])
        finally:
            ep.close()

    def test_profiles_filter(self):
        self.write({"v": 1, "profiles": ["default"], "tools": [SPACE]})
        self.assertEqual(len(tools_proxy.load_catalogue(self.layout, "default").tools), 1)
        self.assertEqual(len(tools_proxy.load_catalogue(self.layout, "p2").tools), 0)


class HealthTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("health")
        self.layout = layout_mod.muxie_layout(str(self.dir / "mh"))
        self.eps = []

    def tearDown(self):
        for e in self.eps:
            e.close()
        rm(self.dir)

    def ep(self, **kw):
        e = FakeEndpoint(**kw)
        self.eps.append(e)
        return e

    def test_health_endpoint_first_then_the_s1_probe(self):
        self.assertIn("no connector token file", local_api.health(self.layout).detail)
        s1 = self.ep(routes={"/v1/ops": (400, {"ok": False})})
        s1.write_file(self.layout.state)
        h = local_api.health(self.layout)
        self.assertTrue(h.ok)
        self.assertIn("an S1 connector", h.detail)
        s2 = self.ep(routes={"/v1/health": (200, {"ok": True, "pid": 9, "version": "2.0.0", "relay": {"linked": False}})})
        s2.write_file(self.layout.state, kind="health")
        h = local_api.health(self.layout)
        self.assertEqual((h.ok, h.info["version"]), (True, "2.0.0"))
        self.assertIn("relay not linked yet", h.detail)
        self.assertEqual(s2.got[-1]["path"], "/v1/health")
        self.assertNotIn("origin", s2.got[-1]["headers"])

    def test_a_non_http_service_on_the_port_is_not_an_exception(self):
        import socket, threading
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]

        def banner():
            for _ in range(4):
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
                c.close()
        threading.Thread(target=banner, daemon=True).start()
        try:
            e = self.ep()
            e.write_file(self.layout.state, kind="health", url=f"http://127.0.0.1:{port}")
            h = local_api.health(self.layout, timeout=2)
            self.assertFalse(h.ok)
            self.assertIn("bad_answer", h.detail)
        finally:
            srv.close()

    def test_stale_and_refused(self):
        dead = self.ep()
        dead.write_file(self.layout.state, kind="health")
        dead.close()
        self.eps.remove(dead)
        self.assertIn("is stale", local_api.health(self.layout, timeout=1).detail)
        wrong = self.ep(token="other")
        wrong.write_file(self.layout.state, kind="health")
        wrong.token = "rotated"  # the file names a token the endpoint no longer takes
        self.assertIn("refuses the token", local_api.health(self.layout).detail)


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("proxy")
        self.layout = layout_mod.muxie_layout(str(self.dir / "mh"))
        self.spec = tools_proxy._spec(SPACE)[0]
        self.ep = None

    def tearDown(self):
        if self.ep:
            self.ep.close()
        rm(self.dir)
        for k in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
            os.environ.pop(k, None)

    def handler(self, profile="default"):
        return tools_proxy.make_handler(self.spec, lambda: self.layout, profile)

    def test_call_reaches_the_connector_with_token_and_session(self):
        self.ep = FakeEndpoint(routes={"/v1/tools/call": (200, {"ok": True, "result": {"space": "s1", "posted": True}})})
        self.ep.write_file(self.layout.state)
        # A proxy in the environment must not be used (the token would go with it).
        os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = os.environ["ALL_PROXY"] = "http://127.0.0.1:9"
        out = json.loads(self.handler("p2")({"op": "post"}, session_id="local-abc", task_id="t1", extra="ignored"))
        self.assertEqual(out, {"space": "s1", "posted": True})
        req = self.ep.got[-1]
        self.assertEqual(req["headers"]["authorization"], "Bearer t0ken")
        self.assertNotIn("origin", req["headers"])
        self.assertEqual(req["body"], {"v": 1, "tool": "muxie_space", "args": {"op": "post"}, "sessionId": "local-abc",
                                       "profile": "p2", "taskId": "t1"})

    def test_connector_down_is_a_clear_tool_error(self):
        out = json.loads(self.handler()({"op": "read"}))
        self.assertIn("not running on this machine", out["error"])
        self.ep = FakeEndpoint()
        self.ep.write_file(self.layout.state)
        self.ep.close()
        self.ep = None
        out = json.loads(self.handler()({"op": "read"}))
        self.assertIn("did not answer", out["error"])

    def test_unknown_tool_after_a_list_change(self):
        self.ep = FakeEndpoint(routes={"/v1/tools/call": (404, {"ok": False, "error": "unknown_tool"})})
        self.ep.write_file(self.layout.state)
        out = json.loads(self.handler()({"op": "read"}))
        self.assertIn("does not offer this tool any more", out["error"])

    def test_refusal_message_passed_through_and_bad_files_ignored(self):
        self.ep = FakeEndpoint(routes={"/v1/tools/call": (422, {"ok": False, "error": "refused", "message": "not your Space"})})
        f = self.ep.write_file(self.layout.state)
        self.assertIn("not your Space", json.loads(self.handler()({}))["error"])
        for url in ("http://10.0.0.1:%d" % self.ep.port, "https://127.0.0.1:%d" % self.ep.port, "http://localhost:1"):
            self.ep.write_file(self.layout.state, url=url)
            self.assertEqual(local_api.endpoints(self.layout), [], url)
        self.ep.write_file(self.layout.state, mode=0o644)
        self.assertEqual(local_api.endpoints(self.layout), [], "a token file readable by others is ignored")
        self.assertTrue(f.exists())


if __name__ == "__main__":
    unittest.main()
