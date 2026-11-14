"""No relay is built in: each operator configures one (the ``relay_url`` setting, or RELAY_URL in connector.env).

Without one, the bootstrap (``/muxie pair``, ``/muxie pair <CODE>``, ``hermes muxie setup|pair``) stops with ONE clear
message naming the setting and an example, before anything is fetched (no channel read, no download), and
``/muxie status`` says the relay is not set instead of showing ``None``.
"""

import argparse
import contextlib
import io
import os
import unittest

from helpers import FakeCtx, rm, sub, temp_dir

bootstrap = sub("bootstrap")
commands = sub("commands")
layout_mod = sub("layout")

SETTING = "hermes config set plugins.entries.muxie.settings.relay_url wss://<your relay>"


class NoDefaultRelayTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("relay")
        self.mh = str(self.dir / "mh")
        self.layout = layout_mod.muxie_layout(self.mh)
        self.fetched = []
        self.real = bootstrap.resolve_channel

        def spy(channel, pins=None):
            self.fetched.append(channel)
            raise bootstrap.BootstrapError("stopped by the test after the relay check")
        bootstrap.resolve_channel = spy

    def tearDown(self):
        bootstrap.resolve_channel = self.real
        rm(self.dir)

    def assert_missing(self, text):
        self.assertEqual(text.count("no relay configured"), 1, text)
        self.assertIn(SETTING, text)
        self.assertIn(f"RELAY_URL=wss://<your relay> in {self.layout.config_file}", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("unexpected error", text)

    def test_message(self):
        self.assert_missing(layout_mod.relay_missing_message(self.layout))
        self.assertEqual(layout_mod.configured_relay(self.layout, ""), "")
        self.assertEqual(layout_mod.configured_relay(self.layout, " wss://r.example "), "wss://r.example")

    def test_pair_without_a_relay_stops_before_any_fetch(self):
        for args in ("pair", "pair K7QF-9M2T-XR4D"):
            ctx = FakeCtx({"muxie_home": self.mh})
            p = commands.MuxiePlugin(ctx)
            p.slash(args, source=None)
            if p._job:
                p._job.join(10)
            final = ctx.posts[0].texts[-1]
            self.assert_missing(final)
            self.assertIn("Not done", final)
        self.assertEqual(self.fetched, [], "no channel was read")
        self.assertFalse(self.layout.connector_dir.exists(), "nothing downloaded or unpacked")

    def test_terminal_setup_without_a_relay(self):
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh}))
        parser = argparse.ArgumentParser()
        p.cli_setup(parser)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = p.cli_run(parser.parse_args(["setup"]))
        out = [buf.getvalue()]
        self.assertNotEqual(rc, 0)
        self.assert_missing("\n".join(out))
        self.assertEqual(self.fetched, [])

    def test_a_relay_from_the_setting_or_connector_env_lets_the_bootstrap_go_on(self):
        ctx = FakeCtx({"muxie_home": self.mh, "relay_url": "wss://r.example"})
        p = commands.MuxiePlugin(ctx)
        p.slash("pair K7QF-9M2T-XR4D", source=None)
        p._job.join(10)
        self.assertEqual(len(self.fetched), 1, "past the relay check: the channel is read")
        self.layout.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.layout.config_file.write_text("RELAY_URL=wss://file.example\n")
        os.chmod(self.layout.config_file, 0o600)
        ctx2 = FakeCtx({"muxie_home": self.mh})
        p2 = commands.MuxiePlugin(ctx2)
        p2.slash("pair K7QF-9M2T-XR4D", source=None)
        p2._job.join(10)
        self.assertEqual(len(self.fetched), 2)

    def test_status_says_the_relay_is_not_set(self):
        st = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh})).slash("status")
        self.assertIn("relay      not set: no relay configured", st)
        self.assert_missing(st)
        st2 = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh, "relay_url": "wss://r.example"})).slash("status")
        self.assertIn("relay      wss://r.example (setting)", st2)
        # The connector's own status --json with no relay (url null): the same words, never «None».
        lines = commands.status_lines({"schema": 1, "relay": {"url": None, "source": "default"}, "connector": {"id": "local", "source": "default"}})
        relay = [l for l in lines if l.startswith("relay")]
        self.assertEqual(len(relay), 1)
        self.assertTrue(relay[0].startswith("relay      not set: no relay configured"), relay)
        self.assertNotIn("None", relay[0])


if __name__ == "__main__":
    unittest.main()
