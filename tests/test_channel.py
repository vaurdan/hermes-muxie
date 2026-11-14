"""The default release channel: the latest GitHub release of vaurdan/hermes-muxie (stable.json + stable.json.sig).

An empty ``channel_url`` setting means that public channel: the bootstrap reads it, and the connector gets it as its
own update channel (``setup --channel``). The other unit tests run with the default cleared (helpers.py), so they
never reach the network.
"""

import unittest

from helpers import FakeCtx, rm, sub, temp_dir

bootstrap = sub("bootstrap")
commands = sub("commands")

PUBLIC = "https://github.com/vaurdan/hermes-muxie/releases/latest/download/stable.json"


class DefaultChannelTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("channel")
        self.mh = str(self.dir / "mh")
        self.saved = bootstrap.DEFAULT_CHANNEL_URL
        bootstrap.DEFAULT_CHANNEL_URL = bootstrap.PUBLIC_CHANNEL_URL

    def tearDown(self):
        bootstrap.DEFAULT_CHANNEL_URL = self.saved
        rm(self.dir)

    def test_the_public_channel(self):
        self.assertEqual(bootstrap.PUBLIC_CHANNEL_URL, PUBLIC)

    def test_an_empty_setting_means_the_public_channel(self):
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh}))
        self.assertEqual(p.options().channel_url, PUBLIC)
        self.assertIn(f"channel    {PUBLIC} (default)", p.slash("status"))

    def test_a_setting_or_setup_from_wins(self):
        own = "https://muxie.example/channel/stable.json"
        p = commands.MuxiePlugin(FakeCtx({"muxie_home": self.mh, "channel_url": own}))
        self.assertEqual(p.options().channel_url, own)
        self.assertIn(f"channel    {own}\n", p.slash("status") + "\n")
        self.assertEqual(p.options(channel_url="file:///x/connector-1.0.0.tgz").channel_url, "file:///x/connector-1.0.0.tgz")


if __name__ == "__main__":
    unittest.main()
