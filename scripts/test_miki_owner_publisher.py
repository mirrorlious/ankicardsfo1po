from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import miki_owner_publisher as policy


class OwnerPublisherDiscoveryPolicyTest(unittest.TestCase):
    def make_root(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        return temp, root

    def test_root_auto_discovery_is_scoped_to_current_event(self):
        temp, root = self.make_root()
        self.addCleanup(temp.cleanup)
        for name in ("configured.apkg", "historical.apkg", "new-upload.apkg"):
            (root / name).write_bytes(b"fixture")
        auto = root / ".miki-auto-sources.txt"
        auto.write_text("new-upload.apkg\n", encoding="utf-8")
        config = {"packs": [{"source": "configured.apkg", "packId": "configured"}]}

        with patch.object(policy.engine, "ROOT", root), patch.object(policy, "AUTO_SOURCES_PATH", auto):
            found = policy.discover_sources(config)

        sources = [path.relative_to(root).as_posix() for path, _ in found]
        self.assertEqual(sources, ["configured.apkg", "new-upload.apkg"])
        self.assertNotIn("historical.apkg", sources)

    def test_authorize_persists_new_root_upload_once(self):
        temp, root = self.make_root()
        self.addCleanup(temp.cleanup)
        (root / "新卡包.apkg").write_bytes(b"fixture")
        auto = root / ".miki-auto-sources.txt"
        auto.write_text("新卡包.apkg\n", encoding="utf-8")
        config = {"packs": []}

        with patch.object(policy.engine, "ROOT", root), patch.object(policy, "AUTO_SOURCES_PATH", auto):
            first = policy.authorize_root_uploads(config)
            second = policy.authorize_root_uploads(config)

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(config["packs"][0]["source"], "新卡包.apkg")
        self.assertTrue(config["packs"][0]["packId"].startswith("owner-pack-"))
        self.assertEqual(config["packs"][0]["title"], "新卡包")

    def test_incoming_lane_remains_zero_config_and_persistent(self):
        temp, root = self.make_root()
        self.addCleanup(temp.cleanup)
        incoming = root / "incoming" / "law"
        incoming.mkdir(parents=True)
        (incoming / "pack.apkg").write_bytes(b"fixture")
        auto = root / ".miki-auto-sources.txt"
        config = {"packs": []}

        with patch.object(policy.engine, "ROOT", root), patch.object(policy, "AUTO_SOURCES_PATH", auto):
            found = policy.discover_sources(config)

        self.assertEqual(
            [path.relative_to(root).as_posix() for path, _ in found],
            ["incoming/law/pack.apkg"],
        )


if __name__ == "__main__":
    unittest.main()
