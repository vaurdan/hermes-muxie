"""The plugin against the REAL S1 and S2/S3 connector bundles and a real Node (skipped when one is missing).

  MUXIE_S1_TGZ   an S1 connector-<v>.tgz with its .sha256 beside it (read-only)
  MUXIE_S2_TGZ   an S2/S3 connector-<v>.tgz (read-only). Only read-only and config commands run here: never `service`
                 or `uninstall`
  MUXIE_TEST_NODE  Node 22+ (default: `node` on PATH)

Nothing is paired (no relay): the relay is ws://127.0.0.1:1, a closed port, so pairing fails fast.
"""

import os
import shutil
import unittest
from pathlib import Path

from helpers import rm, sub, temp_dir

bootstrap = sub("bootstrap")
ca = sub("connector_adapter")
layout_mod = sub("layout")
supervision = sub("supervision")

TGZ = os.environ.get("MUXIE_S1_TGZ") or ""
S2_TGZ = os.environ.get("MUXIE_S2_TGZ") or ""
NODE = os.environ.get("MUXIE_TEST_NODE") or shutil.which("node") or ""
RELAY = "ws://127.0.0.1:1"


@unittest.skipUnless(TGZ and os.path.isfile(TGZ) and os.path.isfile(TGZ + ".sha256") and os.path.isfile(NODE),
                     "no S1 bundle or Node here")
class S1BundleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = temp_dir("s1")
        rel = cls.dir / "rel"
        rel.mkdir()
        cls.tgz = rel / Path(TGZ).name
        shutil.copy(TGZ, cls.tgz)  # a copy: the original stays read-only
        shutil.copy(TGZ + ".sha256", str(cls.tgz) + ".sha256")
        cls.layout = layout_mod.muxie_layout(str(cls.dir / "mh"))
        texts = []
        cls.progress = bootstrap.Progress("T", texts.append)
        real = ca.hermes_launcher
        ca.hermes_launcher = lambda: Path("/nonexistent/hermes/.hermes/bin/hermes")
        try:
            # The operator pins the build it trusts (the .sha256 beside it is only where this test reads it from).
            sha = Path(TGZ + ".sha256").read_text().split()[0]
            cls.out = bootstrap.run(cls.layout, bootstrap.Options(channel_url="file://" + str(cls.tgz), node=NODE,
                                                                  relay_url=RELAY, bundle_sha256=sha), cls.progress,
                                    supervision.Supervision("detached"))
        finally:
            ca.hermes_launcher = real

    @classmethod
    def tearDownClass(cls):
        rm(cls.dir)

    def conn(self):
        node = ca.find_node(self.layout, NODE)
        self.assertIsInstance(node, ca.NodeChoice)
        return ca.Connector(self.layout, node)

    def test_bootstrap_installs_and_stops_at_pairing(self):
        self.assertTrue(self.out.ok, self.progress.text())
        self.assertIs(self.out.paired, False)
        version = Path(TGZ).name[len("connector-"):-len(".tgz")]
        self.assertEqual(self.out.version, version)
        self.assertEqual(self.out.skipped, ["--hermes-launcher"])
        self.assertEqual(os.readlink(self.layout.current), f"versions/{version}")
        env = (self.layout.config / "connector.env")
        self.assertEqual(env.stat().st_mode & 0o777, 0o600)
        self.assertIn(f"RELAY_URL={RELAY}", env.read_text())

    def test_status_and_later_commands(self):
        c = self.conn()
        st = c.status()
        # «not paired», or after a failed pair (test order): a key with 0 trusted devices; neither is paired.
        self.assertRegex(st.get("machine", ""), r"^(not paired|paired, key [0-9A-F ]+, 0 trusted device\(s\))$")
        self.assertIs(ca.paired_from_status(st), False)
        self.assertTrue(st.get("relay", "").startswith(RELAY), st)
        self.assertIn("all 3 present", st.get("assets", ""))
        self.assertTrue(c.offers("pair <CODE>"))
        self.assertFalse(c.offers("--hermes-launcher"))
        for call in (lambda: c.service_install([]), c.update, c.rollback, c.uninstall):
            with self.assertRaises(ca.NotAvailable):
                call()

    def test_pair_against_a_closed_relay_fails_cleanly(self):
        r = self.conn().pair("K7QF-9M2T-XR4D", timeout=60)
        self.assertFalse(r.ok)
        self.assertFalse(r.timed_out, r.out)

    def test_too_old_node_is_refused(self):
        if not os.path.isfile("/usr/bin/node"):
            self.skipTest("no /usr/bin/node")
        major, info = ca._node_version("/usr/bin/node")
        if major is None or major >= 22:
            self.skipTest(f"/usr/bin/node is {info}")
        r = ca.find_node(self.layout, "/usr/bin/node", which=lambda n: None)
        self.assertNotEqual(getattr(r, "path", None), "/usr/bin/node")


@unittest.skipUnless(S2_TGZ and os.path.isfile(S2_TGZ) and os.path.isfile(S2_TGZ + ".sha256") and os.path.isfile(NODE),
                     "no dist-s2s3 bundle or Node here")
class S2BundleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = temp_dir("s2")
        rel = cls.dir / "rel"
        rel.mkdir()
        cls.tgz = rel / Path(S2_TGZ).name
        shutil.copy(S2_TGZ, cls.tgz)
        shutil.copy(S2_TGZ + ".sha256", str(cls.tgz) + ".sha256")
        cls.layout = layout_mod.muxie_layout(str(cls.dir / "mh"))
        cls.progress = bootstrap.Progress("T", lambda t: None)
        sha = Path(S2_TGZ + ".sha256").read_text().split()[0]
        cls.out = bootstrap.run(cls.layout, bootstrap.Options(channel_url="file://" + str(cls.tgz), node=NODE,
                                                              relay_url=RELAY, bundle_sha256=sha), cls.progress,
                                supervision.Supervision("detached"))

    @classmethod
    def tearDownClass(cls):
        rm(cls.dir)

    def test_bootstrap_setup_and_status_json(self):
        self.assertTrue(self.out.ok, self.progress.text())
        self.assertIs(self.out.paired, False)
        node = ca.find_node(self.layout, NODE)
        c = ca.Connector(self.layout, node)
        for flag in ("--channel", "--node PATH", "--like-pid", "status [--json]"):
            self.assertTrue(c.offers(flag), flag)
        self.assertFalse(c.offers("--hermes-launcher"), "dist-s2s3 has no --hermes-launcher yet (report item)")
        st = c.status()
        self.assertEqual((st.get("ok"), st.get("command"), st.get("schema")), (True, "status", 1), st)
        self.assertEqual(st["paired"]["paired"], False)
        self.assertIs(ca.paired_from_status(st), False)
        self.assertTrue(st["relay"]["url"].startswith(RELAY), st["relay"])
        self.assertEqual(st["install"]["current"], self.out.version)  # the plugin's versions/<v> + current read back
        env = (self.layout.config / "connector.env").read_text()
        self.assertIn(f"RELAY_URL={RELAY}", env)


if __name__ == "__main__":
    unittest.main()
