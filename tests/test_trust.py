"""Release trust (the S2/S3 boundary): nothing from a channel runs unless its manifest's Ed25519 signature verifies in
the plugin's Python against embedded keys, or its bundle sha256 is pinned in trusted plugin config. A sha256 supplied
by the channel itself (an unsigned manifest, a .sha256 beside a tgz) never suffices; unsigned network channels are
refused; the embedded key is the release key muxie-release-2026-11 only (the TEST key of the lab channels is a test
fixture, fixtures/test-release-key.json, injected where a test needs it)."""

import base64
import hashlib
import json
import unittest
from pathlib import Path

from helpers import ed_keypair_and_signer, make_fake_bundle, rm, signed_channel, sub, temp_dir

ed = sub("ed25519")
rk = sub("release_keys")
ca = sub("connector_adapter")
bootstrap = sub("bootstrap")
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TEST_KEY = json.loads((FIXTURES / "test-release-key.json").read_text())
RELEASE_KEY_ID = "0641c4073af01b9e"


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vectors(self):
        vectors = [  # RFC 8032 §7.1 TEST 1-3
            ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ]
        for pk, msg, sig in vectors:
            pk, msg, sig = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
            self.assertTrue(ed.verify(pk, msg, sig))
            self.assertFalse(ed.verify(pk, msg + b"!", sig))
            bad = bytearray(sig)
            bad[5] ^= 1
            self.assertFalse(ed.verify(pk, msg, bytes(bad)))
        # S >= L and malformed sizes are refused, not wrapped around.
        pk, sig = bytes.fromhex(vectors[0][0]), bytes.fromhex(vectors[0][2])
        s_plus_l = (int.from_bytes(sig[32:], "little") + ed.L).to_bytes(32, "little")
        self.assertFalse(ed.verify(pk, b"", sig[:32] + s_plus_l))
        self.assertFalse(ed.verify(pk[:31], b"", sig))
        self.assertFalse(ed.verify(pk, b"", sig[:63]))

    def test_test_signer_matches_rfc(self):
        pub, sign = ed_keypair_and_signer(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        self.assertEqual(pub.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(sign(b"").hex()[:16], "e5564300c360ac72")

    def test_node_signed_test_channel_verifies_here(self):
        # stable-1.0.0.json(.sig): signed by the S2/S3 job with Node's crypto and the TEST key (dist-s2s3 lab channel).
        # The TEST key is injected here: the plugin itself does not trust it (next test).
        raw = (FIXTURES / "stable-1.0.0.json").read_bytes()
        sig = (FIXTURES / "stable-1.0.0.json.sig").read_bytes()
        keys = [TEST_KEY]
        check = ca.verify_manifest_signature(raw, sig, keys)
        self.assertEqual((check.ok, check.key_id, check.test_key), (True, "7d4b06d8cc0d45ab", True))
        self.assertIn("TEST", check.key_name)
        self.assertIs(ca.verify_manifest_signature(raw.replace(b"1.0.0", b"1.0.1", 1), sig, keys).ok, False)
        self.assertIs(ca.verify_manifest_signature(raw, None, keys).ok, None)
        self.assertIs(ca.verify_manifest_signature(raw, b"not json", keys).ok, False)
        other = json.loads(sig)
        other["keyId"] = "0000000000000000"
        c = ca.verify_manifest_signature(raw, json.dumps(other).encode(), keys)
        self.assertIs(c.ok, False)
        self.assertIn("does not trust", c.reason)

    def test_test_signed_channel_is_refused_by_the_embedded_keys(self):
        raw = (FIXTURES / "stable-1.0.0.json").read_bytes()
        sig = (FIXTURES / "stable-1.0.0.json.sig").read_bytes()
        check = ca.verify_manifest_signature(raw, sig)
        self.assertIs(check.ok, False)
        self.assertEqual(check.reason, f"signed by a key this plugin does not trust (7d4b06d8cc0d45ab; trusted: {RELEASE_KEY_ID})")
        d = temp_dir("trust-test-key")
        try:
            (d / "stable.json").write_bytes(raw)
            (d / "stable.json.sig").write_bytes(sig)
            with self.assertRaises(bootstrap.BootstrapError) as e:
                bootstrap.resolve_channel("file://" + str(d / "stable.json"))
            self.assertIn("does not trust (7d4b06d8cc0d45ab", str(e.exception))
        finally:
            rm(d)

    def test_embedded_keys_are_the_release_key_only(self):
        self.assertEqual([k["keyId"] for k in rk.RELEASE_KEYS], [RELEASE_KEY_ID])
        self.assertEqual(rk.RELEASE_KEYS[0]["publicKey"], "7PaERoStM2Oo+iOPS4ZmH/qwHDxAbaP/c6qCOQ2v6aw=")
        self.assertEqual(rk.RELEASE_KEYS[0]["name"], "muxie-release-2026-11")
        self.assertFalse(any(k.get("test") for k in rk.RELEASE_KEYS))
        self.assertNotIn(TEST_KEY["keyId"], [k["keyId"] for k in rk.RELEASE_KEYS])
        self.assertEqual(rk.key_id(rk.raw_key(rk.RELEASE_KEYS[0])), RELEASE_KEY_ID)
        self.assertEqual(rk.key_id(rk.raw_key(TEST_KEY)), TEST_KEY["keyId"], "the fixture is the TEST key it says")


class ChannelTrustTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir("trust")
        self.tgz, self.sha, _ = make_fake_bundle(self.dir / "rel")
        self.keys = rk.RELEASE_KEYS

    def tearDown(self):
        rk.RELEASE_KEYS = self.keys
        rm(self.dir)

    def test_local_tgz_needs_a_pin_never_the_sidecar(self):
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.resolve_channel(str(self.tgz))  # a .sha256 sits beside it: not enough
        self.assertIn("pinned in trusted plugin config", str(e.exception))
        a = bootstrap.resolve_channel("file://" + str(self.tgz), bootstrap.Pins(setting=self.sha))
        self.assertEqual((a.sha256, a.trust), (self.sha, "sha256 pinned in plugin settings (bundle_sha256)"))
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.resolve_channel(str(self.tgz), bootstrap.Pins(setting="0" * 64))
        self.assertIn("disagrees with the pinned", str(e.exception))
        (self.dir / "rel" / f"{self.tgz.name}.sha256").unlink()  # no sidecar: the pin alone decides
        a = bootstrap.resolve_channel(str(self.tgz), bootstrap.Pins(setting="0" * 64))
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.fetch(a, self.dir / "dl")
        self.assertIn("sha256 mismatch", str(e.exception))

    def test_lock_file_pins(self):
        lock = self.dir / "connector.lock.json"
        lock.write_text(json.dumps({"v": 1, "pins": [{"version": "9.9.9-fake", "sha256": self.sha}, {"sha256": "bad"}]}))
        pins = bootstrap.load_pins("", lock)
        self.assertEqual(pins.lock, {self.sha: "9.9.9-fake"})
        a = bootstrap.resolve_channel(str(self.tgz), pins)
        self.assertEqual((a.sha256, a.allowed), ("", {self.sha}))
        path, _size, got = bootstrap.fetch(a, self.dir / "dl")
        self.assertEqual(got, self.sha)
        other, _, _ = make_fake_bundle(self.dir / "rel2", version="9.9.10-fake")
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.fetch(bootstrap.resolve_channel(str(other), pins), self.dir / "dl")
        self.assertIn("not pinned in connector.lock.json", str(e.exception))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_pins("not-a-sha")
        self.assertEqual(json.loads(bootstrap.LOCK_FILE.read_text())["pins"], [], "the shipped lock pins nothing yet")

    def test_signed_manifest_with_a_trusted_key(self):
        m, entry = signed_channel(self.dir / "rel", self.tgz, self.sha)
        with self.assertRaises(bootstrap.BootstrapError) as e:  # the unit-test key is not embedded
            bootstrap.resolve_channel("file://" + str(m))
        self.assertIn("does not trust", str(e.exception))
        rk.RELEASE_KEYS = (entry,)
        a = bootstrap.resolve_channel("file://" + str(m))
        self.assertEqual((a.location, a.sha256, a.test_key), (str(self.tgz), self.sha, True))
        self.assertIn(f"signature of key {entry['keyId']}", a.trust)
        self.assertIn("TEST key", a.trust)
        with self.assertRaises(bootstrap.BootstrapError) as e:  # a pin is enforced on top of a signature
            bootstrap.resolve_channel(str(m), bootstrap.Pins(setting="1" * 64))
        self.assertIn("not the pinned bundle_sha256", str(e.exception))
        raw = bytearray(m.read_bytes())
        raw[raw.index(b"9.9.9-fake")] = ord("8")
        m.write_bytes(bytes(raw))
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.resolve_channel(str(m))
        self.assertIn("bad signature", str(e.exception))

    def test_a_release_key_of_the_real_shape_is_not_labelled_test(self):
        # A throwaway key in the shape of the real entry (16-hex keyId, no "test" flag): verified, parsed, no TEST label.
        m, entry = signed_channel(self.dir / "rel", self.tgz, self.sha, seed=b"\x0b" * 32)
        entry = {"keyId": entry["keyId"], "publicKey": entry["publicKey"], "name": "muxie-release-throwaway"}
        self.assertRegex(entry["keyId"], r"^[0-9a-f]{16}$")
        rk.RELEASE_KEYS = (entry,)
        a = bootstrap.resolve_channel("file://" + str(m))
        self.assertEqual((a.location, a.sha256, a.test_key, a.version_hint), (str(self.tgz), self.sha, False, "9.9.9-fake"))
        self.assertEqual(a.trust, f"signature of key {entry['keyId']} (muxie-release-throwaway)")

    def test_unsigned_manifests(self):
        m, _ = signed_channel(self.dir / "rel", self.tgz, self.sha)
        (self.dir / "rel" / "stable.json.sig").unlink()
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.resolve_channel(str(m))
        self.assertIn("unsigned", str(e.exception))
        a = bootstrap.resolve_channel(str(m), bootstrap.Pins(setting=self.sha))
        self.assertIn("pinned in plugin settings (bundle_sha256) (the manifest itself is unsigned)", a.trust)
        # An unsigned network channel is refused even with a pin.
        real = bootstrap._fetch_small
        bootstrap._fetch_small = lambda url, limit=0: m.read_bytes() if url.endswith(".json") else (_ for _ in ()).throw(OSError("404"))
        try:
            with self.assertRaises(bootstrap.BootstrapError) as e:
                bootstrap.resolve_channel("https://example.invalid/stable.json", bootstrap.Pins(setting=self.sha))
            self.assertIn("unsigned network channel is refused", str(e.exception))
        finally:
            bootstrap._fetch_small = real

    def test_manifest_rules(self):
        m, entry = signed_channel(self.dir / "rel", self.tgz, self.sha, channel="beta")
        rk.RELEASE_KEYS = (entry,)
        self.assertEqual(bootstrap.resolve_channel(str(m)).version_hint, "9.9.9-fake")
        m2 = self.dir / "rel" / "stable.json"  # a beta manifest renamed to stable.json
        m2.write_bytes(m.read_bytes())
        (self.dir / "rel" / "stable.json.sig").write_bytes((self.dir / "rel" / "beta.json.sig").read_bytes())
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.resolve_channel(str(m2))
        self.assertIn("for channel 'beta', not 'stable'", str(e.exception))
        m3, entry3 = signed_channel(self.dir / "rel", self.tgz, self.sha, min_plugin="99.0.0", seed=b"\x09" * 32)
        rk.RELEASE_KEYS = (entry3,)
        with self.assertRaises(bootstrap.BootstrapError) as e:
            bootstrap.resolve_channel(str(m3))
        self.assertIn("needs plugin 99.0.0 or newer", str(e.exception))
        for bad in ("http://x/stable.json", "https://x/connector-1.tgz"):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_channel(bad)


if __name__ == "__main__":
    unittest.main()
