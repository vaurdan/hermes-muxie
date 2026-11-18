"""Pairing helpers, S6 host-initiated pairing (chat: ask_choice + /muxie allow|deny <CODE>; terminal: pair --host),
register() and the chat commands."""

import contextlib
import io
import json
import os
import threading
import time
import types
import unittest

from helpers import TEST_RELAY, FakeCtx, FakeEndpoint, kill_detached, load_plugin, make_fake_bundle, rm, sub, temp_dir

pairing = sub("pairing")
bootstrap = sub("bootstrap")
ca = sub("connector_adapter")
commands = sub("commands")
layout_mod = sub("layout")


class PairingTest(unittest.TestCase):
    def test_normalize_code(self):
        self.assertEqual(pairing.normalize_code("k7qf 9m2t-xr4d"), "K7QF-9M2T-XR4D")
        self.assertEqual(pairing.normalize_code("K7QF9M2TXR4D"), "K7QF-9M2T-XR4D")
        # Code v2 (security audit F2): 16 symbols; v1 above is still read from apps and connectors not updated yet.
        self.assertEqual(pairing.normalize_code("k7qf 9m2t-xr4d-ab12"), "K7QF-9M2T-XR4D-AB12")
        self.assertEqual(pairing.normalize_code("K7QF9M2TXR4DAB12"), "K7QF-9M2T-XR4D-AB12")
        for bad in ("", "K7QF-9M2T", "K7QF-9M2T-XR4D-1", "K7QF-9M2T-XR4D-AB1", "K7QF-9M2T-XR4D-AB12-C", "../../etc"):
            self.assertIsNone(pairing.normalize_code(bad), bad)

    def test_private_chat_only(self):
        src = lambda **kw: types.SimpleNamespace(**kw)
        self.assertTrue(pairing.is_private_chat(None))  # classic CLI
        self.assertTrue(pairing.is_private_chat(None, "tui"))  # local session backend: source=None
        self.assertFalse(pairing.is_private_chat(None, "telegram"), "no source from a messaging platform: refused")
        self.assertFalse(pairing.is_private_chat(object(), "telegram"), "no chat_type: refused")
        self.assertFalse(pairing.is_private_chat({"chat_type": "dm"}, "telegram"), "a dict is not a SessionSource")
        self.assertTrue(pairing.is_private_chat(src(chat_type="dm")))
        for t in ("group", "channel", "thread", "forum", "weird"):
            self.assertFalse(pairing.is_private_chat(src(chat_type=t)), t)
        self.assertFalse(pairing.is_private_chat(src(chat_type="dm", shared_session=True)))

    def test_no_short_code_machinery_left(self):
        for gone in ("ALLOW_CODE_ALPHABET", "PendingConfirms", "Pending", "deliver_decision"):
            self.assertFalse(hasattr(pairing, gone), gone)
        self.assertFalse(hasattr(commands.MuxiePlugin(FakeCtx({"muxie_home": "/nonexistent-muxie"})), "pending"))

    def test_confirm_question_and_choices(self):
        req = pairing.DeviceRequest("r1", "Pixel 9", "AB12 CD34", "box")
        for answer in ("allow", "deny"):
            asked = []
            got = pairing.confirm_device(req, lambda q, c: asked.append((q, c)) or answer)
            self.assertEqual(got, answer)
            self.assertEqual(asked[0][0], "Pixel 9 (passkey AB12 CD34) wants to use the agents on box.")
            self.assertEqual([(c["value"], c["label"]) for c in asked[0][1]], [("allow", "Allow"), ("deny", "Deny")])
        for asker in (lambda q, c: None, lambda q, c: "something typed", lambda q, c: 1 / 0):
            self.assertIsNone(pairing.confirm_device(req, asker))

    def test_send_decision_bodies_and_replies(self):
        sent = []

        def ok(method, path, body, timeout):
            sent.append((method, path, body))
            return 200, {"ok": True, "state": "paired", "device": "Pixel", "machine": "box"}

        r = pairing.send_decision(ok, "allow", request_id="r9")
        self.assertEqual(sent[-1], ("POST", "/v1/pair/decision", {"v": 1, "decision": "allow", "requestId": "r9"}))
        self.assertEqual(pairing.decision_reply("allow", r), "Allowed: Pixel can now use the agents on box.")
        r = pairing.send_decision(ok, "deny", code="K7QF-9M2T-XR4D")
        self.assertEqual(sent[-1][2], {"v": 1, "decision": "deny", "code": "K7QF-9M2T-XR4D"})
        self.assertEqual(pairing.decision_reply("deny", r), "Denied: nothing was paired.")
        r = pairing.send_decision(lambda *a: (404, {"ok": False}), "allow", code="X")
        self.assertEqual(pairing.decision_reply("allow", r),
                         "No device is waiting for that code (it expired, or was already answered).")

        def down(*a):
            raise pairing.LocalApiError("down", "refused")

        self.assertEqual(pairing.decision_reply("allow", pairing.send_decision(down, "allow", code="X")), pairing.NOT_RUNNING)
        self.assertEqual(pairing.send_decision(lambda *a: (500, None), "allow", code="X").kind, "error")

    def test_start_host_initiated(self):
        answer = {"ok": True, "v": 1, "slot": "s1", "code": "K7QF-9M2T-XR4D", "link": "https://chat.muxie.sh/pair#K7QF",
                  "fingerprint": "AB12 CD34", "machine": "box", "expiresAt": 1_700_000_600_000}
        seen = []
        s = pairing.start_host_initiated(lambda m, p, b, t: seen.append((m, p, b, t)) or (200, answer))
        self.assertEqual(seen, [("POST", "/v1/pair/start", {"v": 1}, 30.0)])
        self.assertEqual((s.slot, s.code, s.machine, s.fingerprint, s.expires_at), ("s1", "K7QF-9M2T-XR4D", "box", "AB12 CD34", 1_700_000_600.0))
        with self.assertRaises(pairing.HostInitiatedUnavailable) as e:
            pairing.start_host_initiated(lambda *a: (502, {"ok": False, "error": "relay", "message": "The relay is not reachable."}))
        self.assertEqual(str(e.exception), "The relay is not reachable.")
        with self.assertRaises(pairing.HostInitiatedUnavailable) as e:
            pairing.start_host_initiated(lambda *a: (404, None))
        self.assertEqual(str(e.exception), pairing.TOO_OLD_CHAT)
        with self.assertRaises(pairing.HostInitiatedUnavailable):
            pairing.start_host_initiated(lambda *a: (200, {"ok": True, "slot": "s"}))

    def test_wait_state_reads_the_endpoint_again_after_a_connection_error(self):
        calls = []

        def flaky(method, path, body, timeout):
            calls.append((path, body, timeout))
            if len(calls) < 3:  # the hand-over unpaired -> paired: the old port is gone
                raise pairing.LocalApiError("down", "refused")
            return 200, {"ok": True, "slot": "s1", "state": "asking", "version": 4, "expiresAt": 1_700_000_600_000,
                         "request": {"requestId": "r1", "deviceName": "Pixel 9", "passkeyFingerprint": "AB12",
                                     "passkeyFingerprintFull": "AB12 CD34", "machine": "box"}}

        slept = []
        st = pairing.wait_state(flaky, "s1", 3, 25, sleep=slept.append)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0], ("/v1/pair/state", {"v": 1, "slot": "s1", "after": 3, "wait": 25}, 30.0))
        self.assertEqual((st.state, st.version, st.request.request_id, st.request.device_name), ("asking", 4, "r1", "Pixel 9"))
        self.assertEqual(len(slept), 2)
        # It does not retry for ever.
        now = [0.0]

        def never(*a):
            raise pairing.LocalApiError("down", "refused")

        def sleep(n):
            now[0] += 10

        with self.assertRaises(pairing.HostInitiatedUnavailable):
            pairing.wait_state(never, "s1", clock=lambda: now[0], sleep=sleep)
        self.assertEqual(pairing.wait_state(lambda *a: (404, None), "s1").state, "unknown")

    def test_end_texts(self):
        kw = dict(device="Pixel 9", machine="box", code="K7QF-9M2T-XR4D")
        self.assertEqual(pairing.end_text("paired", **kw), "Paired with Pixel 9.")
        self.assertEqual(pairing.end_text("denied", **kw), "Pairing denied: Pixel 9 can't use the agents on box.\n"
                                                         "The code K7QF-9M2T-XR4D no longer works. Send /muxie pair for a new one.")
        # X8 (approved 2026-11-13 07:26): the code message edited in place, one newline before «Send /muxie pair…».
        self.assertEqual(pairing.end_text("expired", **kw),
                         "The code K7QF-9M2T-XR4D expired after 10 minutes. Nothing was paired.\nSend /muxie pair for a new one.")
        self.assertEqual(pairing.end_text("cancelled", **kw),
                         "Pairing cancelled. The code K7QF-9M2T-XR4D no longer works. Nothing was paired.\n"
                         "Send /muxie pair for a new one.")
        self.assertEqual(pairing.end_text("failed", error="the relay didn't answer.", **kw),
                         "Pairing failed: the relay didn't answer. Nothing was paired.\nSend /muxie pair for a new code.")
        self.assertIn("did not complete", pairing.end_text("failed", **kw))
        self.assertEqual(sorted(pairing.END_TEXTS), ["cancelled", "denied", "expired", "failed", "paired"], "one table")


class RegisterAndCommandsTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("cmd")
        self.mh = str(self.dir / "mh")
        self.ep = None

    def tearDown(self):
        if self.ep:
            self.ep.close()
        rm(self.dir)

    def test_register_is_cheap(self):
        mod = load_plugin()
        threads = {t.ident for t in threading.enumerate()}
        ctx = FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY})
        mod.register(ctx)
        self.assertEqual(set(ctx.commands), {"muxie"})
        self.assertEqual(set(ctx.cli), {"muxie"})
        self.assertEqual(set(ctx.hooks), set(sub("signals").HOOKS))
        self.assertEqual(len(ctx.unloads), 1)
        self.assertEqual(list(ctx.tools), ["muxie_status"])
        # The signals say which catalogue the tools came from (S7): none here (no tools.json).
        self.assertEqual(ctx.unloads[0].__self__.signals.catalogue_info(), {"revision": "", "tools": 0})
        self.assertEqual({t.ident for t in threading.enumerate()} - threads, set(), "register() starts no thread")
        self.assertFalse(os.path.exists(self.mh), "register() creates nothing")
        ctx.unloads[0]()

    def test_manifest_declares_every_registered_hook(self):
        with open(os.path.join(os.path.dirname(commands.__file__), "plugin.yaml"), encoding="utf-8") as f:
            text = f.read()
        hooks = [ln.strip()[2:] for ln in text.split("provides_hooks:")[1].split("\n#")[0].splitlines() if ln.strip().startswith("- ")]
        self.assertEqual(sorted(hooks), sorted(sub("signals").HOOKS))
        tools = [ln.strip()[2:] for ln in text.split("provides_tools:")[1].split("\n\n")[0].splitlines() if ln.strip().startswith("- ")]
        # muxie_status first (the toolset key, REPORT-s4 §5.1), then the connector's stable names (S7; the connector's
        # test/dist/plugin-tools.unit.ts pins them to connector/src/agent-tools/catalogue.ts TOOL_GROUPS).
        self.assertEqual(tools[0], "muxie_status")
        self.assertEqual(tools[1:], ["muxie_context", "muxie_space", "muxie_chats", "muxie_app", "muxie_records", "muxie_widget"])
        self.assertTrue(all(sub("tools_proxy").NAME_RE.match(t) for t in tools))

    def test_help_and_status_with_nothing_installed(self):
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY}))
        h = p.slash("")
        self.assertIn("/muxie pair <CODE>", h)
        self.assertIn("/muxie pair            show a code to pair a phone (scan it or type it in Muxie)", h)
        self.assertIn("/muxie allow|deny <CODE>  answer a phone's request when no Allow/Deny buttons show", h)
        self.assertIn("hermes muxie setup|status|pair|allow|deny|update|rollback|logs|uninstall", h)
        self.assertTrue(all(len(line) <= 100 for line in h.splitlines()), "short lines")
        self.assertIn("/muxie status", p.slash("help"))
        st = p.slash("status")
        self.assertIn("connector  not installed", st)
        self.assertIn("running    no:", st)
        self.assertIn("channel    not set", st)
        self.assertIn("unknown /muxie command", p.slash("frobnicate"))

    def test_private_only_commands_refused_in_groups(self):
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY}))
        group = types.SimpleNamespace(chat_type="group")
        for sub_cmd in ("pair", "pair K7QF-9M2T-XR4D", "logs", "update", "start", "allow K7QF-9M2T-XR4D",
                        "deny K7QF-9M2T-XR4D", "allow ABCDEF"):
            self.assertIn("only in a private chat", p.slash(sub_cmd, source=group, platform="telegram"), sub_cmd)
        brief = p.slash("status", source=group)
        self.assertTrue(brief.startswith("Muxie connector: not installed, not running."), brief)
        self.assertNotIn(self.mh, brief)

    def test_pair_bad_code(self):
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY}))
        self.assertIn("not a pairing code", p.slash("pair 1234"))

    def test_pair_without_channel_reports_in_the_progress_message(self):
        ctx = FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY})
        p = commands.MuxiePlugin(ctx)
        reply = p.slash("pair k7qf-9m2t-xr4d", source=None)
        self.assertEqual(reply, "Working on it: progress in the message above.")
        p._job.join(10)
        final = ctx.posts[0].texts[-1]
        self.assertIn("no release channel is configured", final)
        self.assertIn("Not done", final)
        self.assertNotIn("K7QF", "".join(ctx.posts[0].texts), "the code is never echoed")
        self.assertNotIn("9M2T", final)

    def test_pair_runs_inline_when_the_surface_cannot_post(self):
        ctx = FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY}, post_ok=False)
        p = commands.MuxiePlugin(ctx)
        reply = p.slash("pair K7QF-9M2T-XR4D")
        self.assertIn("no release channel is configured", reply)
        self.assertIsNone(p._job)

    def test_register_survives_a_bad_layout(self):
        mod = load_plugin()
        ctx = FakeCtx({"muxie_home": "~no-such-user-xyz/m"})
        mod.register(ctx)  # expanduser raises inside layout(); the load still succeeds
        self.assertEqual(set(ctx.commands), {"muxie"})
        self.assertEqual(list(ctx.tools), ["muxie_status"])

    def test_status_lines_both_shapes(self):
        s2 = {"ok": True, "command": "status", "schema": 1,
              "paired": {"paired": True, "fingerprint": "2CC4 5E41", "devices": 1, "error": None},
              "relay": {"url": "wss://r", "source": "connector.env"}, "connector": {"id": "local", "source": "default"},
              "install": {"current": "1.0.0", "previous": "0.9.0", "bad": {}},
              "service": {"installed": True, "mode": "user", "unit": "muxie-connector.service", "active": "active",
                          "pid": 12, "lingerFix": "sudo loginctl enable-linger u"},
              "update": {"channel": "https://x/stable.json", "auto": True, "pin": None}}
        text = "\n".join(commands.status_lines(s2))
        for want in ("machine    paired, key 2CC4 5E41, 1 trusted device(s)", "relay      wss://r (connector.env)",
                     "install    current 1.0.0, previous 0.9.0", "service    user muxie-connector.service active, pid 12",
                     "as root: sudo loginctl enable-linger u", "updates    auto from https://x/stable.json"):
            self.assertIn(want, text)
        s1 = {"machine": "not paired", "relay": "ws://x (default)", "id": "local (default)"}
        self.assertEqual(commands.status_lines(s1), ["machine    not paired", "relay      ws://x (default)", "id         local (default)"])

    def test_cli_parser(self):
        import argparse
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY}))
        parser = argparse.ArgumentParser()
        p.cli_setup(parser)
        a = parser.parse_args(["setup", "--from", "/x/connector-1.tgz", "--relay-url", "wss://r"])
        self.assertEqual((a.muxie_command, a.source, a.relay_url), ("setup", "/x/connector-1.tgz", "wss://r"))
        self.assertEqual(parser.parse_args(["pair", "K7QF", "9M2T", "XR4D"]).code, ["K7QF", "9M2T", "XR4D"])
        self.assertTrue(parser.parse_args(["uninstall", "--purge"]).purge)
        self.assertEqual(parser.parse_args(["allow", "K7QF-9M2T-XR4D"]).code, ["K7QF-9M2T-XR4D"])
        self.assertEqual(parser.parse_args(["deny"]).code, [])
        self.assertEqual(parser.parse_args(["pair"]).code, [])
        self.assertEqual(p.cli_run(parser.parse_args(["pair", "1234"])), 2)
        self.assertEqual(p.cli_run(parser.parse_args(["allow"])), 2)
        self.assertEqual(p.cli_run(parser.parse_args(["pair"])), 1, "no code, nothing installed, no channel: not done")
        self.assertEqual(p.cli_run(parser.parse_args(["update"])), 1)  # nothing installed


CODE = "K7QF-9M2T-XR4D"
LINK = "https://chat.muxie.sh/pair#K7QF-9M2T-XR4D"
REQUEST = {"requestId": "req-1", "deviceName": "Pixel 9", "passkeyFingerprint": "AB12",
           "passkeyFingerprintFull": "AB12 CD34 EF56 7890", "machine": "box"}
CODE_MESSAGE = ("Pair a phone with box\n\n"
                f"Code: {CODE}\n"
                f"On your phone, tap: {LINK}\n"
                "Or in Muxie: Add a machine › Enter code.\n\n"
                "Machine key: AB12 CD34 EF56\n"
                "Expires in 10 min. Works once.")
QUESTION = "Pixel 9 (passkey AB12) wants to use the agents on box."


def state_answer(state, version, request=None, error=None, device=None, expires_ms=None):
    return 200, {"ok": True, "slot": "s1", "state": state, "version": version,
                 "expiresAt": expires_ms or int((time.time() + 600) * 1000), "request": request, "error": error,
                 "device": device}


class HostPairingChatTest(unittest.TestCase):
    """/muxie pair with no code: the code message, ask_choice, the decision, the edit in place (S6)."""

    def setUp(self):
        self.dir = temp_dir("host")
        self.mh = str(self.dir / "mh")
        self.layout = layout_mod.muxie_layout(self.mh)
        self.expires_ms = int((time.time() + 600) * 1000)
        self.states = []  # answers of /v1/pair/state, in order; the last one repeats
        self.polls = []
        self.ep = FakeEndpoint(routes={
            "/v1/ops": (400, {"ok": False}),
            "/v1/pair/start": (200, {"ok": True, "v": 1, "slot": "s1", "code": CODE, "link": LINK,
                                     "fingerprint": "AB12 CD34 EF56", "machine": "box", "expiresAt": self.expires_ms}),
            "/v1/pair/state": self.state_route,
            "/v1/pair/decision": (200, {"ok": True, "state": "paired", "device": "Pixel 9", "machine": "box"}),
        })
        self.ep.write_file(self.layout.state)

    def tearDown(self):
        self.ep.close()
        rm(self.dir)

    def state_route(self, rec):
        self.polls.append(rec["body"])
        i = min(len(self.polls) - 1, len(self.states) - 1)
        return self.states[i]

    def plugin(self, **kw):
        ctx = FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY}, **kw)
        return ctx, commands.MuxiePlugin(ctx)

    def asking(self, version=2):
        return state_answer("asking", version, REQUEST, expires_ms=self.expires_ms)

    def decisions(self):
        return [r["body"] for r in self.ep.got if r["path"] == "/v1/pair/decision"]

    # (a)
    def test_allow_pick_sends_the_request_id_and_edits_the_message(self):
        self.states = [state_answer("open", 0, expires_ms=self.expires_ms), self.asking(2),
                       state_answer("paired", 3, device="Pixel 9", expires_ms=self.expires_ms)]
        ctx, p = self.plugin(choice="allow")
        ctx.choice = lambda q, c: "allow"
        reply = p.slash("pair", source=None)
        self.assertEqual(len(ctx.posts), 1, "ONE message")
        self.assertEqual(ctx.posts[0].texts, [CODE_MESSAGE, "Paired with Pixel 9."])
        self.assertEqual(len(ctx.asked), 1)
        self.assertEqual(ctx.asked[0][0], QUESTION)
        self.assertEqual([(c["value"], c["label"]) for c in ctx.asked[0][1]], [("allow", "Allow"), ("deny", "Deny")])
        self.assertEqual(self.decisions(), [{"v": 1, "requestId": "req-1", "decision": "allow"}])
        self.assertEqual([x["after"] for x in self.polls], [-1, 0, 2])
        self.assertTrue(all(x["slot"] == "s1" and x["v"] == 1 and x["wait"] == 25 for x in self.polls))
        self.assertEqual(reply, "The result is in the message above.")
        self.assertNotIn(CODE, reply)
        start = [r for r in self.ep.got if r["path"] == "/v1/pair/start"]
        self.assertEqual([r["body"] for r in start], [{"v": 1}])

    # (b)
    def test_deny_pick_sends_deny_and_edits_to_denied(self):
        self.states = [self.asking(1), state_answer("denied", 2, device="Pixel 9", expires_ms=self.expires_ms)]
        ctx, p = self.plugin(choice="deny")
        p.slash("pair")
        self.assertEqual(self.decisions(), [{"v": 1, "requestId": "req-1", "decision": "deny"}])
        self.assertEqual(ctx.posts[0].texts[-1],
                         f"Pairing denied: Pixel 9 can't use the agents on box.\nThe code {CODE} no longer works. "
                         "Send /muxie pair for a new one.")
        self.assertEqual(len(ctx.posts), 1)

    def fallback(self):
        hhmm = time.strftime("%H:%M", time.localtime(self.expires_ms // 1000))
        return f"{QUESTION}\n\nTo allow it, send /muxie allow {CODE}\nNot you? Send /muxie deny {CODE}\nUntil {hhmm}."

    # (c) no surface to ask on (None at once): ONE card asked, the code message edited in place with the fallback, the
    # code stays valid (the wait goes on) and the answer comes from /muxie allow|deny <CODE> elsewhere.
    def test_without_buttons_the_code_message_gets_the_fallback_and_the_wait_goes_on(self):
        self.states = [self.asking(1), self.asking(1), state_answer("paired", 2, device="Pixel 9", expires_ms=self.expires_ms)]
        ctx, p = self.plugin(choice=None)
        p.slash("pair")
        self.assertEqual(len(ctx.posts), 1, "no second message")
        self.assertEqual(ctx.posts[0].texts, [CODE_MESSAGE, f"{CODE_MESSAGE}\n\n{self.fallback()}", "Paired with Pixel 9."])
        self.assertEqual(len(ctx.asked), 1)
        self.assertEqual(self.decisions(), [])

    # (c2) Owner decision 2026-11-13: ONE card per pairing. Stock ends an unanswered ask_choice at agent.clarify_timeout
    # (90 s default) and waits that long with no viewer too (lab run 4): it is NOT asked again; the code message is edited
    # in place to carry the fallback, and the code stays valid until its 10 minutes.
    def test_a_card_that_timed_out_is_not_asked_again_the_code_message_gets_the_fallback(self):
        self.states = [self.asking(1), self.asking(1), self.asking(1), state_answer("paired", 2, device="Pixel 9", expires_ms=self.expires_ms)]
        ctx, p = self.plugin(choice=None)

        def slow(q, c):
            time.sleep(0.06)  # a card shown, then closed by stock's timeout
            return None
        ctx.choice = slow
        p.slash("pair")
        self.assertEqual(len(ctx.asked), 1, "exactly one ask_choice per pairing")
        self.assertEqual(len(ctx.posts), 1, "no second message")
        self.assertEqual(ctx.posts[0].texts, [CODE_MESSAGE, f"{CODE_MESSAGE}\n\n{self.fallback()}", "Paired with Pixel 9."])
        self.assertEqual(self.decisions(), [])

    def test_a_pick_that_cannot_be_delivered_falls_back_too(self):
        self.ep.routes["/v1/pair/decision"] = (500, {"ok": False})
        self.states = [self.asking(1), state_answer("paired", 2, device="Pixel 9", expires_ms=self.expires_ms)]
        ctx, p = self.plugin(choice="allow")
        p.slash("pair")
        self.assertEqual(len(ctx.asked), 1)
        self.assertEqual(len(ctx.posts), 1)
        self.assertEqual(ctx.posts[0].texts[1], f"{CODE_MESSAGE}\n\n{self.fallback()}")

    # (f)
    def test_expired_cancelled_and_failed_use_the_placeholder_texts(self):
        for state, error in (("expired", None), ("cancelled", None), ("failed", "the relay hung up.")):
            with self.subTest(state):
                self.states = [state_answer(state, 1, error=error, expires_ms=self.expires_ms)]
                self.polls.clear()
                ctx, p = self.plugin()
                p.slash("pair")
                self.assertEqual(ctx.posts[0].texts, [CODE_MESSAGE, pairing.end_text(state, device="", machine="box", code=CODE, error=error or "")])
        self.assertIn(f"The code {CODE} expired after 10 minutes", pairing.end_text("expired", code=CODE))

    def test_unclaimed_expiry_renews_the_code_in_the_same_message(self):
        starts = []
        next_code = "ABCD-EFGH-JKLM"

        def start(rec):
            starts.append(rec)
            return 200, {"ok": True, "v": 1, "slot": "s1" if len(starts) == 1 else "s2",
                         "code": CODE if len(starts) == 1 else next_code,
                         "link": LINK if len(starts) == 1 else "https://chat.muxie.sh/pair#" + next_code,
                         "fingerprint": "AB12 CD34 EF56", "machine": "box",
                         "expiresAt": int((time.time() - 1 if len(starts) == 1 else time.time() + 600) * 1000)}

        self.ep.routes["/v1/pair/start"] = start
        expired_status, expired_body = state_answer("expired", 1, expires_ms=int((time.time() - 1) * 1000))
        expired_body["renewable"] = True  # new relay observes claims; old relays must never renew blindly
        self.states = [(expired_status, expired_body), state_answer("paired", 2, device="Pixel 9", expires_ms=self.expires_ms)]
        ctx, p = self.plugin()
        p.slash("pair")
        self.assertEqual(len(starts), 2)
        self.assertEqual(len(ctx.posts), 1)
        self.assertEqual(len(ctx.posts[0].texts), 3)
        self.assertIn(next_code, ctx.posts[0].texts[1])
        self.assertIn("New code · the last one stopped at", ctx.posts[0].texts[1])
        self.assertEqual(ctx.posts[0].texts[-1], "Paired with Pixel 9.")

    def test_claimed_expiry_never_renews(self):
        status, body = state_answer("expired", 1, expires_ms=int((time.time() - 1) * 1000))
        body["claimed"] = True
        self.states = [(status, body)]
        ctx, p = self.plugin()
        p.slash("pair")
        self.assertEqual(len([r for r in self.ep.got if r["path"] == "/v1/pair/start"]), 1)
        self.assertEqual(len(ctx.posts[0].texts), 2)

    def test_old_relay_without_claim_signal_never_renews(self):
        self.states = [state_answer("expired", 1, expires_ms=int((time.time() - 1) * 1000))]
        ctx, p = self.plugin()
        p.slash("pair")
        self.assertEqual(len([r for r in self.ep.got if r["path"] == "/v1/pair/start"]), 1)
        self.assertEqual(len(ctx.posts[0].texts), 2)

    def test_a_newer_pair_replaces_the_older_one(self):
        gate = threading.Event()
        calls = []

        def state(rec):
            calls.append(1)
            if len(calls) == 1:
                return state_answer("open", 0, expires_ms=self.expires_ms)
            if not gate.is_set():
                gate.wait(5)
            return 404, {"ok": False, "error": "unknown"}  # the connector forgot the old slot when the new one started

        self.ep.routes["/v1/pair/state"] = state
        ctx, p = self.plugin()
        out = []
        t = threading.Thread(target=lambda: out.append(p.slash("pair")))
        t.start()
        for _ in range(100):
            if len(calls) >= 2:
                break
            time.sleep(0.05)
        with p._host_lock:
            p._host_gen += 1  # what a second /muxie pair does first
        gate.set()
        t.join(10)
        self.assertEqual(ctx.posts[0].texts[-1], pairing.end_text("cancelled", machine="box", code=CODE))

    def test_unknown_slot_without_a_newer_pair_is_a_failure(self):
        self.states = [(404, {"ok": False, "error": "unknown"})]
        ctx, p = self.plugin()
        p.slash("pair")
        self.assertIn("Pairing failed: the connector no longer knows this pairing", ctx.posts[0].texts[-1])

    def test_no_post_surface_returns_the_code_and_does_not_block(self):
        self.states = [self.asking(1)]
        ctx, p = self.plugin(post_ok=False)
        t0 = time.time()
        reply = p.slash("pair")
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(reply, CODE_MESSAGE + f"\n\nWhen your phone asks, answer here with /muxie allow {CODE} (or /muxie deny {CODE}).")
        self.assertEqual(self.polls, [], "no long poll")
        self.assertEqual(ctx.asked, [])

    def test_relay_trouble_is_reported_in_chat(self):
        self.ep.routes["/v1/pair/start"] = (502, {"ok": False, "error": "relay", "message": "The relay is not reachable."})
        ctx, p = self.plugin()
        reply = p.slash("pair")
        self.assertEqual(reply, "Could not start pairing: The relay is not reachable.")
        self.assertEqual(ctx.posts, [])

    def test_group_chats_are_refused_before_anything_is_asked(self):
        ctx, p = self.plugin()
        self.assertIn("only in a private chat", p.slash("pair", source=types.SimpleNamespace(chat_type="group"), platform="telegram"))
        self.assertEqual([r["path"] for r in self.ep.got], [])

    def test_not_installed_starts_the_bootstrap_in_the_same_message(self):
        ep_files = list(self.layout.endpoint_files())
        for f in ep_files:
            f.unlink()
        ctx, p = self.plugin()  # no channel configured: the bootstrap stops, in the progress message
        reply = p.slash("pair")
        self.assertIn("see the message above", reply)
        self.assertEqual(len(ctx.posts), 1)
        self.assertIn("no release channel is configured", ctx.posts[0].texts[-1])

    # (d)
    def test_allow_and_deny_by_code(self):
        ctx, p = self.plugin()
        self.assertEqual(p.slash("allow k7qf 9m2t xr4d"), "Allowed: Pixel 9 can now use the agents on box.")
        self.assertEqual(self.decisions()[-1], {"v": 1, "code": CODE, "decision": "allow"})
        self.assertEqual(p.slash(f"deny {CODE.lower()}"), "Denied: nothing was paired.")
        self.assertEqual(self.decisions()[-1], {"v": 1, "code": CODE, "decision": "deny"})
        self.assertEqual(p.slash("allow K7QF9M2TXR4D"), "Allowed: Pixel 9 can now use the agents on box.")
        self.assertEqual(self.decisions()[-1]["code"], CODE)

    def test_decision_replies_404_usage_bad_code_and_down(self):
        ctx, p = self.plugin()
        self.ep.routes["/v1/pair/decision"] = (404, {"ok": False, "error": "not_waiting"})
        self.assertEqual(p.slash(f"allow {CODE}"),
                         "No device is waiting for that code (it expired, or was already answered).")
        self.assertEqual(p.slash("deny"), "Usage: /muxie deny <CODE>")
        self.assertIn("not a pairing code", p.slash("allow ABCDEF"))
        self.assertEqual(len(self.decisions()), 1, "a bad code is not sent")
        self.ep.routes["/v1/pair/decision"] = (500, {})
        self.assertIn("answered HTTP 500", p.slash(f"allow {CODE}"))
        for f in self.layout.endpoint_files():
            f.unlink()
        self.assertIn("not running", p.slash(f"allow {CODE}"))

    def test_refused_in_groups(self):
        ctx, p = self.plugin()
        g = types.SimpleNamespace(chat_type="group")
        for c in ("allow", "deny"):
            self.assertIn("only in a private chat", p.slash(f"{c} {CODE}", source=g, platform="telegram"))
        self.assertEqual(self.decisions(), [])

    # (e)
    def test_pair_with_a_code_is_still_the_app_initiated_job(self):
        ctx, p = self.plugin()
        reply = p.slash(f"pair {CODE}")
        self.assertEqual(reply, "Working on it: progress in the message above.")
        p._job.join(10)
        self.assertIn("no release channel is configured", ctx.posts[0].texts[-1])
        self.assertEqual([r["path"] for r in self.ep.got if r["path"].startswith("/v1/pair/")], [], "no host-initiated call")
        self.assertEqual(ctx.asked, [])

    # the CLI
    def test_cli_allow_and_deny(self):
        import argparse
        ctx, p = self.plugin()
        parser = argparse.ArgumentParser()
        p.cli_setup(parser)
        self.assertEqual(p.cli_run(parser.parse_args(["allow", CODE])), 0)
        self.assertEqual(self.decisions()[-1], {"v": 1, "code": CODE, "decision": "allow"})
        self.assertEqual(p.cli_run(parser.parse_args(["deny", CODE])), 0)
        self.ep.routes["/v1/pair/decision"] = (404, {})
        self.assertEqual(p.cli_run(parser.parse_args(["allow", CODE])), 1)


class HostPairingTerminalTest(unittest.TestCase):
    """`hermes muxie pair` with no code: the connector's own `pair --host` in the foreground (S6)."""

    def setUp(self):
        self.dir = temp_dir("term")
        self.mh = str(self.dir / "mh")
        self.layout = layout_mod.muxie_layout(self.mh)

    def tearDown(self):
        rm(self.dir)

    def install(self, s7):
        tgz, sha, node = make_fake_bundle(self.dir / "rel", s2=True, s7=s7)
        ctx = FakeCtx({"muxie_home": self.mh, "relay_url": TEST_RELAY, "channel_url": str(tgz), "bundle_sha256": sha, "node": str(node)})
        return commands.MuxiePlugin(ctx)

    def run_cli(self, p, *argv):
        import argparse
        parser = argparse.ArgumentParser()
        p.cli_setup(parser)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = p.cli_run(parser.parse_args(list(argv)))
        return code, buf.getvalue()

    def marker(self):
        return json.loads((self.layout.state / "pair-host-call.json").read_text())

    # (g)
    def test_pair_host_runs_in_the_foreground_with_inherited_stdio(self):
        p = self.install(s7=True)
        real = bootstrap.run
        seen = {}

        def run(layout, opts, progress, sup=None):
            seen["opts"] = opts
            out = real(layout, opts, progress, sup)
            (layout.state / "host-exit").write_text("3")
            return out

        bootstrap.run = run
        try:
            code, out = self.run_cli(p, "pair")
        finally:
            bootstrap.run = real
        self.assertEqual(code, 3, out)
        self.assertEqual(seen["opts"].code, "")
        self.assertTrue(seen["opts"].start_unpaired)
        m = self.marker()
        self.assertEqual(m["argv"], ["pair", "--host"])
        self.assertEqual(m["fds"], [os.readlink("/proc/self/fd/0"), os.readlink("/proc/self/fd/1"), os.readlink("/proc/self/fd/2")],
                         "stdin, stdout and stderr are the terminal's own, not pipes")
        self.assertLessEqual(set(m["env_keys"]) - {"PWD", "SHLVL", "_", "LC_CTYPE", "TERM", "COLORTERM"},
                             set(ca.KEEP_ENV) | {"MUXIE_HOME", "MUXIE_NODE", "MUXIE_PLUGIN_PORT", "FAKE_S2", "FAKE_S7"}, "reduced environment")
        kill_detached(self.layout)

    def test_pair_host_exit_code_zero(self):
        p = self.install(s7=True)
        code, out = self.run_cli(p, "pair")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.marker()["argv"], ["pair", "--host"])
        kill_detached(self.layout)

    def test_an_old_connector_gets_the_too_old_message_and_exit_2(self):
        p = self.install(s7=False)
        code, out = self.run_cli(p, "pair")
        self.assertEqual(code, 2, out)
        self.assertIn("This connector is too old to pair from the machine; update it (hermes muxie update) or use a code "
                      "from the app: hermes muxie pair <CODE>", out)
        self.assertFalse((self.layout.state / "pair-host-call.json").exists())

    def test_pair_with_a_code_keeps_the_old_flow(self):
        p = self.install(s7=True)
        code, out = self.run_cli(p, "pair", CODE)
        self.assertEqual(code, 0, out)
        self.assertFalse((self.layout.state / "pair-host-call.json").exists(), "no pair --host")
        self.assertIn("Paired. 1 device(s) trusted.", out)
        kill_detached(self.layout)


if __name__ == "__main__":
    unittest.main()
