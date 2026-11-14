"""Signals: the allowlist (no message text ever leaves), the bounded queue, the lazy sender, never raising."""

import json
import threading
import time
import unittest

from helpers import FakeEndpoint, rm, sub, temp_dir

signals = sub("signals")
layout_mod = sub("layout")

SECRET = "SECRET-PROSE do not leak this sentence"
TURN_ID = "local-" + "a" * 64 + ":" + "local-" + "a" * 64 + ":c8101670"  # 150 characters, as in S0

# Every hook's real S0 key set (REPORT-s0 §1, evidence/hooks.jsonl), every value poisoned with SECRET except ids.
PAYLOADS = {
    "pre_llm_call": dict(conversation_history=[{"role": "user", "content": SECRET}], is_first_turn=True, model="m-1",
                         parent_session_id="", platform="tui", sender_id=SECRET, session_id="local-1", task_id="local-1",
                         telemetry_schema_version=SECRET, turn_id=TURN_ID, user_message=SECRET),
    "post_llm_call": dict(assistant_response=SECRET, conversation_history=[SECRET], model="m-1", platform="cli",
                          session_id="local-1", side_question_token=SECRET, task_id="local-1",
                          telemetry_schema_version="1", turn_id=TURN_ID, user_message=SECRET),
    "on_session_start": dict(model="m-1", platform="webhook", session_id="20261112_112139_04641460",
                             telemetry_schema_version=SECRET),
    "on_session_end": dict(completed=True, failed=False, interrupted=False, model="m", platform="api_server",
                           session_id="run_1", task_id="run_1", telemetry_schema_version="x",
                           turn_exit_reason="TurnExit(detail='" + SECRET + "', reason=stop)", turn_id=TURN_ID),
    "agent_loop_stopped": dict(session_key="agent:main:telegram:dm:42", platform="telegram", reason="stop_command",
                               invalidation_reason=SECRET),
    "pre_auxiliary_call": dict(api_call_count=1, api_mode="chat_completions", api_request_id="aux-1625", approx_input_tokens=9,
                               aux_task="compression", base_url=SECRET, max_tokens=1, message_count=3, model="m", platform="cli",
                               provider="anthropic", request={"messages": [SECRET]}, request_char_count=5,
                               request_messages=[SECRET], retry_count=0, session_id="local-1", started_at=1794481595.7,
                               streaming=False, system_prompt=SECRET, task_id="local-1", telemetry_schema_version="1",
                               tool_count=0, turn_id=TURN_ID),
    "post_auxiliary_call": dict(api_request_id="aux-1625", aux_task="compression", assistant_content_chars=5, ended_at=1.5,
                                error=SECRET, error_type="RateLimitError", finish_reason="stop", response=SECRET,
                                usage={"x": SECRET}, session_id="local-1", turn_id=TURN_ID, platform="cli"),
    "post_compaction": dict(after_tokens=1551, before_tokens=15857, kind="summarize", messages_removed=2, old_session_id="",
                            reason="turn_start_threshold", session_id="local-1", telemetry_schema_version="1"),
    "subagent_start": dict(child_goal=SECRET, child_role=SECRET, child_session_id="20261112_1", child_subagent_id="sa-0-1",
                           parent_session_id="local-1", parent_subagent_id="", parent_turn_id=TURN_ID,
                           telemetry_schema_version="1"),
    "subagent_stop": dict(child_role="leaf", child_session_id="20261112_1", child_status="completed", child_summary=SECRET,
                          duration_ms=1234, parent_session_id="local-1", parent_turn_id=TURN_ID,
                          tool_call_history=[{"args": SECRET}], telemetry_schema_version="1"),
}


class AllowlistTest(unittest.TestCase):
    def test_every_hook_is_covered(self):
        self.assertEqual(set(PAYLOADS), set(signals.HOOKS))

    def test_no_content_ever_leaves(self):
        for hook, payload in PAYLOADS.items():
            ev = signals.event(hook, payload, "default", 1, now=1.0)
            text = json.dumps(ev)
            self.assertNotIn("SECRET", text, hook)
            self.assertNotIn("leak", text, hook)
            self.assertLessEqual(set(ev["data"]), set(signals.ALLOW[hook]), hook)

    def test_ids_kept_whole(self):
        ev = signals.event("pre_llm_call", PAYLOADS["pre_llm_call"], "p2", 7, now=1.0)
        self.assertEqual(ev["data"]["turn_id"], TURN_ID)  # 150 characters, not truncated
        self.assertEqual(len(ev["data"]["turn_id"]), 150)
        self.assertEqual((ev["hook"], ev["profile"], ev["seq"]), ("pre_llm_call", "p2", 7))
        self.assertIs(ev["data"]["is_first_turn"], True)

    def test_exit_reason_reduced_to_a_word(self):
        ev = signals.event("on_session_end", PAYLOADS["on_session_end"], "default", 1)
        self.assertEqual(ev["data"]["turn_exit_reason"], "stop")
        self.assertEqual(signals.exit_reason("max_iterations"), "max_iterations")
        self.assertIsNone(signals.exit_reason("some free text here"))

    def test_prose_in_an_allowed_key_is_dropped_not_cut(self):
        ev = signals.event("on_session_start", {"session_id": "hello there " + SECRET, "model": "m"}, "default", 1)
        self.assertNotIn("session_id", ev["data"])
        self.assertEqual(ev["data"]["model"], "m")
        ev = signals.event("on_session_start", {"session_id": "x" * 257}, "default", 1)
        self.assertNotIn("session_id", ev["data"])
        ev = signals.event("post_compaction", {"before_tokens": float("nan"), "after_tokens": [1],
                                               "messages_removed": float("inf")}, "default", 1)
        self.assertEqual(ev["data"], {})
        ev = signals.event("on_session_start", {"session_id": "abc\n", "model": "m\n"}, "default", 1)
        self.assertEqual(ev["data"], {}, "a trailing newline is not an id")
        json.loads(json.dumps(signals.event("post_compaction", {"before_tokens": float("-inf")}, "d", 1)))

    def test_only_compression_aux_calls(self):
        self.assertIsNone(signals.event("pre_auxiliary_call", {"aux_task": "title_generation"}, "d", 1))
        self.assertIsNone(signals.event("post_auxiliary_call", {"aux_task": "vision"}, "d", 1))
        self.assertIsNone(signals.event("pre_tool_call", {"session_id": "x"}, "d", 1))
        ev = signals.event("pre_auxiliary_call", {"aux_task": "compression", "session_id": ""}, "d", 1)
        self.assertEqual(ev["data"], {"aux_task": "compression", "session_id": ""})  # out-of-turn: profile only


class SenderTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("signals")
        self.layout = layout_mod.muxie_layout(str(self.dir / "mh"))
        self.ep = None

    def tearDown(self):
        if self.ep:
            self.ep.close()
        rm(self.dir)

    def wait(self, cond, t=5.0):
        end = time.monotonic() + t
        while time.monotonic() < end and not cond():
            time.sleep(0.02)
        return cond()

    def test_lazy_thread_and_posts_ids_only(self):
        self.ep = FakeEndpoint(routes={"/v1/signals": (202, {"ok": True})})
        self.ep.write_file(self.layout.state)
        before = {t.name for t in threading.enumerate()}
        s = signals.Signals(lambda: self.layout, "default")
        cbs = {h: s.callback(h) for h in signals.HOOKS}
        self.assertEqual({t.name for t in threading.enumerate()} - before, set(), "no thread before the first event")
        for hook, payload in PAYLOADS.items():
            cbs[hook](**payload)
        self.assertTrue(self.wait(lambda: s.sent == len(PAYLOADS)), s.stats())
        raw = b"".join(r["raw"] for r in self.ep.got)
        self.assertNotIn(b"SECRET", raw)
        req = self.ep.got[0]
        self.assertEqual(req["path"], "/v1/signals")
        self.assertEqual(req["headers"]["authorization"], "Bearer t0ken")
        self.assertNotIn("origin", req["headers"])
        body = req["body"]
        self.assertEqual((body["v"], body["profile"]), (1, "default"))
        self.assertEqual([e["seq"] for b in (r["body"] for r in self.ep.got) for e in b["events"]], list(range(1, len(PAYLOADS) + 1)))
        s.stop()
        self.assertTrue(self.wait(lambda: not s._thread.is_alive()))
        cbs["pre_llm_call"](**PAYLOADS["pre_llm_call"])  # after stop: ignored, no new thread
        self.assertFalse(s._thread.is_alive())

    def test_posts_say_which_catalogue_the_tools_came_from(self):
        # S7: the connector learns from the signals that this instance's native tools are live (ids and a count only).
        self.ep = FakeEndpoint(routes={"/v1/signals": (202, {"ok": True})})
        self.ep.write_file(self.layout.state)
        s = signals.Signals(lambda: self.layout, "default")
        s.catalogue_info = lambda: {"revision": "434e7ed83f015949", "tools": 6}
        self.assertEqual(s._post_http([{"hook": "x"}]), "ok")
        self.assertEqual(self.ep.got[-1]["body"]["catalogue"], {"revision": "434e7ed83f015949", "tools": 6})
        for bad in ({"revision": "not an id", "tools": 6}, {"revision": "abc", "tools": True}, {"revision": "abc", "tools": -1},
                    "nope", None):
            s.catalogue_info = lambda bad=bad: bad
            self.assertEqual(s._post_http([{"hook": "x"}]), "ok")
            self.assertNotIn("catalogue", self.ep.got[-1]["body"], bad)
        s.catalogue_info = lambda: 1 / 0  # never raises into the sender
        self.assertEqual(s._post_http([{"hook": "x"}]), "ok")
        self.assertNotIn("catalogue", self.ep.got[-1]["body"])

    def test_full_queue_drops_and_hooks_never_block(self):
        s = signals.Signals(lambda: self.layout, "default", post=lambda b: time.sleep(2) or "ok")
        cb = s.callback("post_compaction")
        t0 = time.monotonic()
        for _ in range(signals.QUEUE_MAX + 200):
            cb(**PAYLOADS["post_compaction"])
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertGreaterEqual(s.dropped, 200 - signals.BATCH_MAX)  # the sender took one batch out
        s.stop(wait=0.05)

    def test_slow_endpoint_times_out_at_200ms_and_backs_off(self):
        self.ep = FakeEndpoint(routes={"/v1/signals": (200, {})}, delay=1.5)
        self.ep.write_file(self.layout.state)
        s = signals.Signals(lambda: self.layout, "default")
        t0 = time.monotonic()
        s._post_http([{"hook": "x"}])
        self.assertLess(time.monotonic() - t0, 0.9)
        self.assertEqual(s.last_error, "timeout")

    def test_no_connector_and_old_connector(self):
        s = signals.Signals(lambda: self.layout, "default")
        self.assertEqual(s._post_http([{}]), "down")  # no token file
        self.ep = FakeEndpoint(routes={})  # an S1 connector: no /v1/signals
        self.ep.write_file(self.layout.state)
        self.assertEqual(s._post_http([{}]), "unsupported")
        s.callback("pre_llm_call")(**PAYLOADS["pre_llm_call"])
        self.assertTrue(self.wait(lambda: s.failed >= 1))
        s.stop()

    def test_callback_never_raises(self):
        s = signals.Signals(lambda: (_ for _ in ()).throw(RuntimeError("boom")), "default")
        s.callback("pre_llm_call")(**PAYLOADS["pre_llm_call"])
        s.callback("pre_llm_call")("positional", object())
        s.stop()


if __name__ == "__main__":
    unittest.main()
