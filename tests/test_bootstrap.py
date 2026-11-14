"""Bootstrap: channel resolution, sha256, checked unpack, current/previous, the install lock, and a whole run against a
fake connector bundle (install → setup → pair → detached start → healthy), plus the adapter's fallbacks."""

import fcntl
import hashlib
import io
import json
import os
import subprocess
import tarfile
import threading
import time
import unittest
from pathlib import Path

from helpers import TEST_RELAY, FakeCtx, kill_detached, make_fake_bundle, rm, sub, temp_dir

bootstrap = sub("bootstrap")
ca = sub("connector_adapter")
layout_mod = sub("layout")
supervision = sub("supervision")
commands = sub("commands")

DETACHED = supervision.Supervision("detached")


def progress():
    texts = []
    return bootstrap.Progress("T", texts.append, ("K7QF-9M2T-XR4D",)), texts


class ChannelTest(unittest.TestCase):
    """Channel shapes; the trust rules themselves are in test_trust.py."""

    def setUp(self):
        self.dir = temp_dir("chan")
        self.tgz, self.sha, self.node = make_fake_bundle(self.dir / "rel")

    def tearDown(self):
        rm(self.dir)

    def test_refusals(self):
        for ch, why in (("", "no release channel"), ("http://x/stable.json", "plain http"),
                        ("https://x/connector-1.tgz", "bare tgz over the network"),
                        ("file://otherhost/x.tgz", "another host"),
                        (str(self.dir / "nope.tgz"), "does not exist"), (str(self.dir / "x.zip"), "neither")):
            with self.assertRaises(bootstrap.BootstrapError) as e:
                bootstrap.resolve_channel(ch, bootstrap.Pins(setting=self.sha))
            self.assertIn(why, str(e.exception), ch)

    def test_tgz_and_file_url(self):
        for ch in (str(self.tgz), "file://" + str(self.tgz)):
            a = bootstrap.resolve_channel(ch, bootstrap.Pins(setting=self.sha))
            self.assertEqual((a.location, a.sha256, a.version_hint), (str(self.tgz), self.sha, "9.9.9-fake"))

    def test_sha_mismatch(self):
        a = bootstrap.resolve_channel(str(self.tgz), bootstrap.Pins(setting=self.sha))
        a.sha256 = "0" * 64
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.fetch(a, self.dir / "dl")
        self.assertIn("sha256 mismatch", str(e.exception))
        self.assertEqual(list((self.dir / "dl").iterdir()), [], "no partial file left")


class UnpackTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("unpack")
        self.layout = layout_mod.muxie_layout(str(self.dir / "mh"))

    def tearDown(self):
        rm(self.dir)

    def bad_tgz(self, member):
        tgz, _, _ = make_fake_bundle(self.dir / "rel", extra_members=[member])
        return tgz

    def test_unpack_current_previous(self):
        tgz, _, _ = make_fake_bundle(self.dir / "a", version="1.0.0")
        dest, v = bootstrap.unpack(tgz, self.layout)
        self.assertEqual((v, dest), ("1.0.0", self.layout.versions_dir / "1.0.0"))
        self.assertTrue(os.access(dest / "muxie-connector", os.X_OK))
        self.assertIsNone(bootstrap.make_current(self.layout, v))
        self.assertEqual(ca.installed_bundle(self.layout), dest)
        tgz2, _, _ = make_fake_bundle(self.dir / "b", version="1.1.0")
        self.assertEqual(bootstrap.unpack(tgz2, self.layout)[1], "1.1.0")
        self.assertEqual(bootstrap.make_current(self.layout, "1.1.0"), "versions/1.0.0")
        self.assertEqual(os.readlink(self.layout.connector_dir / "previous"), "versions/1.0.0")
        self.assertEqual(ca.bundle_version(ca.installed_bundle(self.layout)), "1.1.0")
        self.assertEqual(bootstrap.unpack(tgz2, self.layout)[1], "1.1.0", "an existing complete version is reused")
        self.assertEqual([p.name for p in self.layout.versions_dir.iterdir() if p.name.startswith(".")], [])

    def test_same_version_other_bytes_are_replaced_by_the_verified_tree(self):
        tgz, _, _ = make_fake_bundle(self.dir / "a", version="1.0.0")
        dest, _ = bootstrap.unpack(tgz, self.layout)
        (dest / "connector.mjs").write_text("# edited locally\n")
        (dest / "stray").write_text("x")
        dest2, _ = bootstrap.unpack(tgz, self.layout)
        self.assertEqual(dest2, dest)
        self.assertNotIn("edited locally", (dest / "connector.mjs").read_text())
        self.assertFalse((dest / "stray").exists())
        self.assertEqual([p.name for p in self.layout.versions_dir.iterdir()], ["1.0.0"])

    def test_rejects_traversal_links_and_foreign_tops(self):
        evil = tarfile.TarInfo("connector-9.9.9-fake/../../escape")
        evil.size = 1
        link = tarfile.TarInfo("connector-9.9.9-fake/lnk")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        other = tarfile.TarInfo("othertop/x")
        other.size = 1
        for member, data in ((evil, io.BytesIO(b"x")), (link, None), (other, io.BytesIO(b"x"))):
            rm(self.dir / "rel")
            tgz = self.bad_tgz((member, data))
            with self.assertRaises(bootstrap.BootstrapError, msg=member.name):
                bootstrap.unpack(tgz, self.layout)
        self.assertFalse((self.dir / "escape").exists())
        self.assertFalse(any(self.layout.versions_dir.glob("9.9.9*")))


class LockTest(unittest.TestCase):
    def test_second_holder_waits_then_gives_up(self):
        d = temp_dir("lock")
        try:
            L = layout_mod.muxie_layout(str(d / "mh"))
            a = bootstrap.InstallLock(L, "default")
            self.assertTrue(a.acquire())
            self.assertEqual(oct(L.install_lock.stat().st_mode & 0o777), "0o600")
            b = bootstrap.InstallLock(L, "p2")
            t0 = time.monotonic()
            self.assertFalse(b.acquire(wait=0.6))
            self.assertGreaterEqual(time.monotonic() - t0, 0.5)
            self.assertIn('"profile": "default"', b.holder())
            a.release()
            self.assertTrue(b.acquire(wait=0.1))
            b.release()
        finally:
            rm(d)


class WholeRunTest(unittest.TestCase):
    """bootstrap.run with the fake connector: real processes, a real detached connector (stopped by its PID)."""

    def setUp(self):
        self.dir = temp_dir("run")
        self.tgz, self.sha, self.node = make_fake_bundle(self.dir / "rel", log_dir=self.dir)
        self.layout = layout_mod.muxie_layout(str(self.dir / "mh"))

    def tearDown(self):
        kill_detached(self.layout)
        rm(self.dir)

    def opts(self, **kw):
        return bootstrap.Options(channel_url=str(self.tgz), node=str(self.node), bundle_sha256=self.sha, relay_url=kw.pop("relay_url", TEST_RELAY), **kw)

    def calls(self):
        f = self.dir / "fake-connector-calls.jsonl"
        return [json.loads(l)["argv"] for l in f.read_text().splitlines()] if f.exists() else []

    def test_install_without_code_stops_at_pairing(self):
        p, texts = progress()
        real = ca.hermes_launcher
        ca.hermes_launcher = lambda: Path("/nonexistent/hermes/.hermes/bin/hermes")
        try:
            out = bootstrap.run(self.layout, self.opts(), p, DETACHED)
        finally:
            ca.hermes_launcher = real
        self.assertTrue(out.ok, p.text())
        self.assertIs(out.paired, False)
        self.assertEqual(out.version, "9.9.9-fake")
        self.assertIn("Not paired yet", p.text())
        # An S1 connector has no --hermes-launcher: it is left out (and reported), setup still runs.
        self.assertEqual(out.skipped, ["--hermes-launcher"])
        self.assertIn("does not take --hermes-launcher yet", p.text())
        self.assertEqual(self.calls()[:3], [["help"], ["setup", "--relay-url", TEST_RELAY], ["status", "--json"]])  # S1 ignores --json
        self.assertIsNone(ca.detached_pid(self.layout), "an unpaired S1 connector is not started")

    def test_pair_then_detached_and_healthy_then_idempotent(self):
        p, texts = progress()
        out = bootstrap.run(self.layout, self.opts(code="K7QF-9M2T-XR4D"), p, DETACHED)
        self.assertTrue(out.ok, p.text())
        self.assertTrue(out.running and out.paired)
        text = p.text()
        for want in ("trusted by: sha256 pinned in plugin settings (bundle_sha256)", "this machine's key: AB12 CD34 EF56", "Paired. 1 device(s) trusted.",
                     "started detached (pid", "connector answers"):
            self.assertIn(want, text)
        self.assertNotIn("K7QF", "".join(texts), "the code never reaches the progress text")
        pid = ca.detached_pid(self.layout)
        self.assertIsNotNone(pid)
        # No caller pid in this Supervision: no --like-pid; the Node the plugin found goes along (--node).
        self.assertIn(["service", "install", "--mode", "auto", "--node", str(self.node), "--json"], self.calls())
        # The detached connector is not our child any more (sh exited), it has its own session, its env is small.
        self.assertNotEqual(os.getpgid(pid), os.getpgid(0))
        env_keys = [json.loads(l)["env_keys"] for l in (self.dir / "fake-connector-calls.jsonl").read_text().splitlines()
                    if json.loads(l)["argv"] == ["run"]][0]
        self.assertIn("MUXIE_PLUGIN_PORT", env_keys)
        self.assertLessEqual(set(env_keys) - {"PWD", "SHLVL", "_", "LC_CTYPE"},
                             set(ca.KEEP_ENV) | {"MUXIE_HOME", "MUXIE_NODE", "MUXIE_PLUGIN_PORT", "FAKE_LOG_DIR"})
        p2, _ = progress()
        again = bootstrap.run(self.layout, self.opts(), p2, DETACHED)
        self.assertTrue(again.ok and again.running)
        self.assertIn("already answers", p2.text())
        self.assertEqual(ca.detached_pid(self.layout), pid, "no second connector")

    def test_reinstall_of_a_new_version_restarts_the_detached_connector(self):
        p, _ = progress()
        self.assertTrue(bootstrap.run(self.layout, self.opts(code="K7QF-9M2T-XR4D"), p, DETACHED).ok, p.text())
        old_pid = ca.detached_pid(self.layout)
        tgz2, _, _ = make_fake_bundle(self.dir / "rel2", version="9.9.10-fake", log_dir=self.dir)
        p2, _ = progress()
        sha2 = (self.dir / "rel2" / f"{tgz2.name}.sha256").read_text().split()[0]
        out = bootstrap.run(self.layout, bootstrap.Options(relay_url=TEST_RELAY, channel_url=str(tgz2), node=str(self.node), reinstall=True,
                                                           bundle_sha256=sha2), p2, DETACHED)
        self.assertTrue(out.ok and out.running, p2.text())
        self.assertEqual(out.version, "9.9.10-fake")
        self.assertIn(f"✓ stopped 9.9.9-fake (pid {old_pid})", p2.text())
        new_pid = ca.detached_pid(self.layout)
        self.assertNotIn(new_pid, (None, old_pid))
        self.assertFalse(ca._alive(old_pid))
        self.assertEqual(os.readlink(self.layout.connector_dir / "previous"), "versions/9.9.9-fake")

    def test_boot_check_restarts_a_stopped_s2_connector_once(self):
        tgz, sha, node = make_fake_bundle(self.dir / "rel-boot", log_dir=self.dir, s2=True)
        settings = {"muxie_home": str(self.dir / "mh"), "channel_url": str(tgz), "node": str(node), "bundle_sha256": sha, "relay_url": TEST_RELAY}
        plugin = commands.MuxiePlugin(FakeCtx(settings))
        self.assertEqual(plugin.boot_check(), "not the gateway process")  # a CLI process never starts anything
        p, _ = progress()
        self.assertTrue(bootstrap.run(self.layout, plugin.options(code="K7QF-9M2T-XR4D"), p, DETACHED).ok, p.text())
        svc_pid = int((self.layout.state / "fake-service.pid").read_text())
        os.kill(svc_pid, 15)  # «reboot»: the detached connector is gone
        for _ in range(50):
            if not ca._alive(svc_pid):
                break
            time.sleep(0.1)
        commands._BOOT_CHECKS.clear()
        plugin.is_gateway_process = lambda: True
        self.assertEqual(plugin.boot_check(), "service install: ok")
        self.assertTrue(bootstrap.wait_healthy(self.layout, "default", 10).ok)
        self.assertEqual(plugin.boot_check(), "checked recently")
        commands._BOOT_CHECKS.clear()
        self.assertEqual(plugin.boot_check(), "already answers")
        # The first hook event of an instance asks for one check; later events do not.
        asked = []
        p2 = commands.MuxiePlugin(FakeCtx(settings))
        p2.boot_check_soon = lambda: asked.append(1)
        p2.signals._on_first_event = p2.boot_check_soon
        for _ in range(3):
            p2.signals.callback("on_session_start")(session_id="s", platform="tui", model="m")
        p2.signals.stop()
        self.assertEqual(asked, [1])

    def test_reinstall_refuses_a_downgrade(self):
        p, _ = progress()
        self.assertTrue(bootstrap.run(self.layout, self.opts(), p, DETACHED).ok, p.text())
        old_tgz, _, _ = make_fake_bundle(self.dir / "rel-old", version="9.9.8-fake")
        sha = (self.dir / "rel-old" / f"{old_tgz.name}.sha256").read_text().split()[0]
        p2, _ = progress()
        out = bootstrap.run(self.layout, bootstrap.Options(relay_url=TEST_RELAY, channel_url=str(old_tgz), node=str(self.node), reinstall=True,
                                                           bundle_sha256=sha), p2, DETACHED)
        self.assertFalse(out.ok)
        self.assertIn("older than the installed 9.9.9-fake", out.summary)
        self.assertEqual(ca.bundle_version(ca.installed_bundle(self.layout)), "9.9.9-fake")

    def test_detached_pid_found_under_a_symlinked_home(self):
        real = self.dir / "realhome"
        real.mkdir()
        link = self.dir / "linkhome"
        link.symlink_to(real)
        layout = layout_mod.muxie_layout(env={"HOME": str(link)}, platform="linux")
        p, _ = progress()
        try:
            out = bootstrap.run(layout, self.opts(code="K7QF-9M2T-XR4D"), p, DETACHED)
            self.assertTrue(out.ok and out.running, p.text())
            pid = ca.detached_pid(layout)
            self.assertIsNotNone(pid, "the bundle path is resolved, the layout is not: both must match")
        finally:
            kill_detached(layout)

    def test_wrong_code_fails_cleanly(self):
        p, _ = progress()
        out = bootstrap.run(self.layout, self.opts(code="AAAA-BBBB-CCCC"), p, DETACHED)
        self.assertFalse(out.ok)
        self.assertIn("pairing failed", out.summary)
        self.assertNotIn("AAAA", out.summary + p.text())
        self.assertIsNone(ca.detached_pid(self.layout))

    def test_systemd_gateway_gets_a_warning_until_s2(self):
        p, _ = progress()
        sup = supervision.Supervision("systemd-user", unit="hermes-gateway.service", pid=4242)
        out = bootstrap.run(self.layout, self.opts(code="K7QF-9M2T-XR4D"), p, sup)
        self.assertTrue(out.ok, p.text())
        self.assertIn("stops when the gateway's unit restarts", p.text())
        self.assertIn(["service", "install", "--mode", "auto", "--like-pid", "4242", "--node", str(self.node), "--json"],
                      self.calls())

    def test_s2_connector_installs_its_service_and_answers_on_health(self):
        tgz, sha, node = make_fake_bundle(self.dir / "rel-s2", log_dir=self.dir, s2=True)
        p, _ = progress()
        sup = supervision.Supervision("systemd-user", unit="hermes-gateway.service", pid=4242)
        out = bootstrap.run(self.layout, bootstrap.Options(relay_url=TEST_RELAY, channel_url=str(tgz), node=str(node), code="K7QF-9M2T-XR4D",
                                                           bundle_sha256=sha), p, sup)
        self.assertTrue(out.ok and out.running, p.text())
        text = p.text()
        self.assertIn("service installed and started (mode user)", text)
        self.assertIn("run once as root: sudo loginctl enable-linger tester", text)
        self.assertIn("version 9.9.9-fake", text)  # from GET /v1/health, not the S1 probe
        self.assertNotIn("detached", text.split("connector answers")[0].split("service installed")[1])
        self.assertIsNone(ca.detached_pid(self.layout), "no plugin-started connector when the service exists")
        self.assertIn(["service", "install", "--mode", "auto", "--like-pid", "4242", "--node", str(node), "--json"],
                      self.calls())
        self.assertIn(["status", "--json"], self.calls())
        setup = [c for c in self.calls() if c[:1] == ["setup"]][0]
        self.assertEqual(setup, ["setup", "--relay-url", TEST_RELAY, "--node", str(node)])  # S2 setup takes --node; a tgz channel is no --channel

    def test_chat_command_end_to_end_with_progress_edits(self):
        ctx = FakeCtx({"relay_url": TEST_RELAY, "muxie_home": str(self.dir / "mh"), "channel_url": "file://" + str(self.tgz), "node": str(self.node),
                       "bundle_sha256": self.sha})
        plugin = commands.MuxiePlugin(ctx)
        self.assertEqual(plugin.slash("pair K7QF-9M2T-XR4D"), "Working on it: progress in the message above.")
        self.assertIn("already working", plugin.slash("pair K7QF-9M2T-XR4D"))
        plugin._job.join(60)
        texts = ctx.posts[0].texts
        self.assertGreater(len(texts), 5, "one message, edited in place")
        self.assertEqual(len(ctx.posts), 1)
        self.assertIn("Done: the connector is paired and running.", texts[-1])
        self.assertNotIn("K7QF", "".join(texts))
        st = plugin.slash("status")
        for want in ("connector  9.9.9-fake", "running    yes", "machine    paired", "detached   pid"):
            self.assertIn(want, st)
        self.assertIn("connected to relay as local", plugin.slash("logs 5"))
        self.assertIn("not available in this connector build", plugin.slash("update"))

    def test_cli_setup_takes_a_relative_path(self):
        ctx = FakeCtx({"relay_url": TEST_RELAY, "muxie_home": str(self.dir / "mh"), "node": str(self.node), "bundle_sha256": self.sha})
        plugin = commands.MuxiePlugin(ctx)
        import argparse
        parser = argparse.ArgumentParser()
        plugin.cli_setup(parser)
        cwd = os.getcwd()
        os.chdir(self.tgz.parent)
        try:
            self.assertEqual(plugin.cli_run(parser.parse_args(["setup", "--from", self.tgz.name])), 0)
        finally:
            os.chdir(cwd)
        self.assertEqual(ca.bundle_version(ca.installed_bundle(self.layout)), "9.9.9-fake")

    def test_cli_uninstall_fallback_stops_only_what_it_started(self):
        ctx = FakeCtx({"relay_url": TEST_RELAY, "muxie_home": str(self.dir / "mh"), "channel_url": str(self.tgz), "node": str(self.node),
                       "bundle_sha256": self.sha})
        plugin = commands.MuxiePlugin(ctx)
        import argparse
        parser = argparse.ArgumentParser()
        plugin.cli_setup(parser)
        lines = []
        import builtins
        real_print = builtins.print
        builtins.print = lambda *a, **k: lines.append(" ".join(str(x) for x in a))
        try:
            self.assertEqual(plugin.cli_run(parser.parse_args(["pair", "K7QF-9M2T-XR4D"])), 0)
            pid = ca.detached_pid(self.layout)
            self.assertIsNotNone(pid)
            self.assertEqual(plugin.cli_run(parser.parse_args(["uninstall", "--purge"])), 2)
            self.assertEqual(plugin.cli_run(parser.parse_args(["uninstall"])), 0)
        finally:
            builtins.print = real_print
        self.assertTrue(any(f"stopped the detached connector (pid {pid})" in l for l in lines), lines)
        self.assertFalse(self.layout.connector_dir.exists())
        self.assertTrue(self.layout.state.exists(), "state (key, roster) kept")
        self.assertFalse(ca._alive(pid))


class NodeTest(unittest.TestCase):
    def test_find_node_reports_why(self):
        d = temp_dir("node")
        try:
            L = layout_mod.muxie_layout(str(d / "mh"), env={"HOME": str(d)})
            old = d / "node18"
            old.write_text("#!/bin/sh\necho v18.1.0\n")
            os.chmod(old, 0o755)
            broken = d / "nodelib"
            broken.write_text("#!/bin/sh\necho 'node: error while loading shared libraries: libatomic.so.1: cannot open' >&2\nexit 127\n")
            os.chmod(broken, 0o755)
            r = ca.find_node(L, str(old), which=lambda n: str(broken))
            self.assertIsInstance(r, ca.NodeProblem)
            msg = r.message()
            self.assertIn("older than 22", msg)
            self.assertIn("apt-get install libatomic1", msg)
            good = d / "node22"
            good.write_text("#!/bin/sh\necho v22.22.2\n")
            os.chmod(good, 0o755)
            r = ca.find_node(L, "", which=lambda n: str(good))
            self.assertEqual((r.path, r.version, r.source), (str(good), "v22.22.2", "PATH"))
        finally:
            rm(d)

    def test_status_text_parser(self):
        text = ("muxie-connector 0.1.0-dev.g7147cb53 (bundle, commit 7147cb53)\nprogram  /x/connector.mjs\nlayout   linux\n"
                "  data   /h/.local/share/muxie\nmachine  not paired\nrunning  unknown: no /x/connector-local.plugin.json\n")
        st = ca.parse_status_text(text)
        self.assertEqual((st["version"], st["machine"], st["layout"]), ("0.1.0-dev.g7147cb53", "not paired", "linux"))
        self.assertNotIn("data", st)
        self.assertIs(ca.paired_from_status({"machine": "paired, key AB, 0 trusted device(s)"}), False)
        self.assertIs(ca.paired_from_status({"machine": "paired, key AB, 2 trusted device(s)"}), True)
        self.assertIs(ca.paired_from_status({"machine": "unreadable key /x: boom"}), None)
        self.assertIs(ca.paired_from_status({"paired": {"paired": True, "devices": 1}}), True)
        self.assertIs(ca.paired_from_status({"paired": {"paired": True, "devices": 0}}), False)
        self.assertIsNone(ca.paired_from_status({"paired": {"paired": None, "error": "unreadable"}}))
        r = ca.Result(3, "refused by the channel", stdout='{"ok":false,"command":"update","error":"unknown signing key","code":3}')
        self.assertEqual(r.json["code"], 3)
        self.assertEqual(ca.explain(r), "refused (signature, sha256, downgrade, new key or major, bad version): unknown signing key")


if __name__ == "__main__":
    unittest.main()
