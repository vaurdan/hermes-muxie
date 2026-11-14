"""The Ed25519 keys a release channel manifest must be signed with before the plugin installs anything from it.

The same list as the connector's ``connector/src/release-keys.ts`` (dist-s2s3): keyId = the first 16 hex characters of
sha256(the 32-byte raw public key). The release key ``muxie-release-2026-11`` is the only key the plugin trusts; its
private half never enters the repo. The TEST key of the lab channels (7d4b06d8cc0d45ab) is a test fixture only
(``tests/fixtures/test-release-key.json``; a lab copy of the plugin is rewritten to trust it with
``test/dist/lab/test-key.ts plugin <copy>``). An entry with ``"test": True`` is labelled «not a release» at bootstrap.
The plugin never trusts a key a manifest announces (rotation is the connector's ``update --accept-key``, after install).
"""

from __future__ import annotations

import base64
import hashlib

RELEASE_KEYS: tuple = (
    {"keyId": "0641c4073af01b9e", "publicKey": "7PaERoStM2Oo+iOPS4ZmH/qwHDxAbaP/c6qCOQ2v6aw=",
     "name": "muxie-release-2026-11"},
)


def key_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:16]


def raw_key(entry: dict) -> bytes:
    raw = base64.b64decode(entry["publicKey"])
    if len(raw) != 32 or key_id(raw) != entry["keyId"]:
        raise ValueError(f"release key {entry.get('keyId')} does not match its public key")
    return raw
