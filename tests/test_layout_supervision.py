"""layout.py mirrors connector/src/layout.ts; supervision.py reads the gateway's supervision from cgroup + INVOCATION_ID."""

import os
import unittest
from pathlib import Path
from unittest import mock

from helpers import rm, sub, temp_dir

layout = sub("layout")
supervision = sub("supervision")


class LayoutTest(unittest.TestCase):
    def setUp(self):
        self.home = temp_dir("layout")

    def tearDown(self):
        rm(self.home)

    def test_linux_default_dirs(self):
        L = layout.muxie_layout(env={"HOME": str(self.home)}, platform="linux")
        self.assertEqual(L.data, self.home / ".local/share/muxie")
        self.assertEqual(L.state, self.home / ".local/state/muxie")
        self.assertEqual(L.config_file, self.home / ".config/muxie/connector.env")
        self.assertEqual(L.tools_file, self.home / ".local/state/muxie/tools.json")
        self.assertEqual(L.current, self.home / ".local/share/muxie/connector/current")
        self.assertEqual(L.subprocess_env(), {})

    def test_muxie_home_from_setting_wins_over_environment(self):
        L = layout.muxie_layout("/x/mine", env={"HOME": str(self.home), "MUXIE_HOME": "/x/env"}, platform="linux")
        self.assertEqual((L.origin, L.data, L.state, L.config), ("MUXIE_HOME", Path("/x/mine/share"), Path("/x/mine/state"), Path("/x/mine/config")))
        self.assertEqual(L.subprocess_env(), {"MUXIE_HOME": "/x/mine"})
        L2 = layout.muxie_layout("", env={"HOME": str(self.home), "MUXIE_HOME": "/x/env"}, platform="linux")
        self.assertEqual(L2.state, Path("/x/env/state"))

    def test_macos_and_legacy_state(self):
        L = layout.muxie_layout(env={"HOME": str(self.home)}, platform="darwin")
        self.assertEqual(L.state, self.home / "Library/Application Support/Muxie/state")
        self.assertEqual(L.logs, self.home / "Library/Logs/Muxie")
        (self.home / ".local/state/muxie").mkdir(parents=True)
        L = layout.muxie_layout(env={"HOME": str(self.home)}, platform="darwin")
        self.assertEqual((L.state, L.state_from), (self.home / ".local/state/muxie", "legacy"))

    def test_state_dir_moved_in_connector_env(self):
        cfg = self.home / ".config/muxie"
        cfg.mkdir(parents=True)
        (cfg / "connector.env").write_text("# mine\nexport CONNECTOR_ID=box1\nMUXIE_STATE_DIR='/srv/muxie state' # moved\n")
        L = layout.muxie_layout(env={"HOME": str(self.home)}, platform="linux")
        self.assertEqual((L.state, L.state_from), (Path("/srv/muxie state"), "MUXIE_STATE_DIR"))
        self.assertEqual(layout.connector_id(L), "box1")

    def test_env_file_parser(self):
        p = layout.parse_env_file('A=1\n# c\n\nB="x\\ny"\nC=plain # comment\nD=`q`\nbad line\nE=\n')
        self.assertEqual(p, {"A": "1", "B": "x\ny", "C": "plain", "D": "q", "E": ""})


class SupervisionTest(unittest.TestCase):
    def test_system_unit_with_invocation_id(self):
        s = supervision.classify("0::/system.slice/hermes-gateway.service\n", {"INVOCATION_ID": "abc"}, 0)
        self.assertEqual((s.kind, s.unit), ("systemd-system", "hermes-gateway.service"))
        self.assertEqual(s.cli_args(), [], "classify() alone has no process: no caller facts to pass")
        self.assertEqual(supervision.Supervision("systemd-system", pid=321).cli_args(), ["--like-pid", "321"])

    def test_user_unit(self):
        cg = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/hermes-gateway.service\n"
        s = supervision.classify(cg, {"INVOCATION_ID": "x"}, 1000)
        self.assertEqual((s.kind, s.unit), ("systemd-user", "hermes-gateway.service"))

    def test_nohup_gateway_in_session_scope_is_detached(self):
        # S0 finding 4: Hermes logged under_systemd=yes for this one; it was a nohup gateway in a login scope.
        s = supervision.classify("0::/user.slice/user-1000.slice/session-7989.scope\n", {}, 1000)
        self.assertEqual(s.kind, "detached")
        self.assertIn("in a login session scope", s.notes)
        self.assertEqual(supervision.detect().cli_args(), ["--like-pid", str(os.getpid())], "in the gateway: its own pid")

    def test_unit_without_invocation_id_is_detached(self):
        s = supervision.classify("0::/system.slice/foo.service\n", {}, 0)
        self.assertEqual(s.kind, "detached")
        self.assertIn("in foo.service but no INVOCATION_ID", s.notes)

    def test_only_the_user_manager_is_not_a_gateway_unit(self):
        s = supervision.classify("0::/user.slice/user-1000.slice/user@1000.service/init.scope\n", {"INVOCATION_ID": "x"}, 1000)
        self.assertEqual(s.kind, "detached")

    def test_cgroup_v1_and_containers(self):
        v1 = "12:pids:/system.slice/x.service\n1:name=systemd:/system.slice/hermes.service\n"
        self.assertEqual(supervision.classify(v1, {"INVOCATION_ID": "1"}, 0).kind, "systemd-system")
        self.assertEqual(supervision.classify("0::/\n", {}, 0).kind, "detached")
        self.assertEqual(supervision.classify("", {}, 0).kind, "detached")

    def test_launchd(self):
        self.assertEqual(supervision.classify("", {"XPC_SERVICE_NAME": "ai.hermes.gateway"}, 501, "darwin").kind, "launchd")
        self.assertEqual(supervision.classify("", {"XPC_SERVICE_NAME": "0"}, 501, "darwin").kind, "detached")

    def test_detect_runs_here(self):
        s = supervision.detect()
        self.assertIn(s.kind, ("systemd-system", "systemd-user", "detached", "launchd"))
        # Another process (here: ourselves by PID) is read from /proc/<pid>/cgroup + environ, with the same result.
        self.assertEqual(supervision.detect(os.getpid()).kind, s.kind)
        self.assertEqual(supervision.detect(os.getpid()).cgroup, s.cgroup)

    def test_terminal_without_hermes_falls_back_to_itself(self):
        # Hermetic: never read the host's real gateway (on a host running one, the lookup finds it).
        with mock.patch.object(supervision, "running_gateway_pid", return_value=None):
            s = supervision.detect_for_terminal("/nonexistent")
        self.assertIn("no running gateway found", s.notes)
        self.assertIsNone(s.pid)

    def test_terminal_with_a_running_gateway_uses_its_facts(self):
        with mock.patch.object(supervision, "running_gateway_pid", return_value=os.getpid()):
            s = supervision.detect_for_terminal("/nonexistent")
        self.assertIn(f"gateway pid {os.getpid()}", s.notes)
        self.assertEqual(s.pid, os.getpid())


if __name__ == "__main__":
    unittest.main()
