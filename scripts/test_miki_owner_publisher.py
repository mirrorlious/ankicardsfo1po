from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import miki_owner_publisher as policy
import publish_miki_owner_pack as engine
import audit_apkg_identity as identity


class OwnerPublisherDiscoveryPolicyTest(unittest.TestCase):
    def make_root(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        return temp, root

    def write_config(self, root: Path, config: dict) -> Path:
        path = root / "miki-publisher.json"
        path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def test_unbound_root_upload_becomes_pending_and_never_a_pack(self):
        temp, root = self.make_root()
        self.addCleanup(temp.cleanup)
        (root / "新卡包.apkg").write_bytes(b"fixture")
        auto = root / ".miki-auto-sources.txt"
        auto.write_text("新卡包.apkg\n", encoding="utf-8")
        config_path = self.write_config(root, {"schemaVersion": 2, "repository": "mirrorlious/ankicardsfo1po", "publisher": "mirrorlious", "packs": []})

        with patch.object(policy.engine, "ROOT", root), \
             patch.object(policy, "AUTO_SOURCES_PATH", auto), \
             patch.object(policy.engine, "CONFIG_PATH", config_path):
            policy.authorize_command()

        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(config.get("packs"), [])
        pending = config.get("pendingClassification", [])
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["sourcePath"], "新卡包.apkg")
        self.assertEqual(pending[0]["status"], "PENDING_CLASSIFICATION")
        self.assertEqual(pending[0]["reason"], "NEW_ROOT_UPLOAD_UNCLASSIFIED")

        # second authorize run must be idempotent
        with patch.object(policy.engine, "ROOT", root), \
             patch.object(policy, "AUTO_SOURCES_PATH", auto), \
             patch.object(policy.engine, "CONFIG_PATH", config_path):
            policy.authorize_command()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(len(config.get("pendingClassification", [])), 1)

    def test_bound_root_source_is_not_recorded_as_pending(self):
        temp, root = self.make_root()
        self.addCleanup(temp.cleanup)
        (root / "configured.apkg").write_bytes(b"fixture")
        auto = root / ".miki-auto-sources.txt"
        auto.write_text("configured.apkg\n", encoding="utf-8")
        config = {
            "schemaVersion": 2,
            "packs": [{
                "packId": "configured",
                "currentReleaseId": "v1",
                "releases": [{
                    "releaseId": "v1", "displayVersion": "1", "status": "ACTIVE",
                    "defaultVariantId": "original",
                    "variants": [{"variantId": "original", "label": "原版", "sourcePath": "configured.apkg"}],
                }],
            }],
        }
        config_path = self.write_config(root, config)

        with patch.object(policy.engine, "ROOT", root), \
             patch.object(policy, "AUTO_SOURCES_PATH", auto), \
             patch.object(policy.engine, "CONFIG_PATH", config_path):
            policy.authorize_command()

        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(config.get("pendingClassification", []), [])

    def test_incoming_lane_remains_zero_config(self):
        temp, root = self.make_root()
        self.addCleanup(temp.cleanup)
        incoming = root / "incoming" / "law"
        incoming.mkdir(parents=True)
        (incoming / "pack.apkg").write_bytes(b"fixture")
        config = {"schemaVersion": 2, "packs": []}

        with patch.object(policy.engine, "ROOT", root):
            injected = policy.inject_incoming_lane(config)

        self.assertEqual(len(injected["packs"]), 1)
        family = injected["packs"][0]
        self.assertEqual(family["packId"], "pack")
        self.assertEqual(family["releases"][0]["variants"][0]["sourcePath"], "incoming/law/pack.apkg")


class ConfigSchemaValidationTest(unittest.TestCase):
    def family(self, pack_id="family-a", status="ACTIVE"):
        return {
            "packId": pack_id,
            "currentReleaseId": "v1",
            "releases": [{
                "releaseId": "v1", "displayVersion": "1", "status": status,
                "defaultVariantId": "original",
                "variants": [{"variantId": "original", "label": "原版", "sourcePath": f"{pack_id}.apkg"}],
            }],
        }

    def test_duplicate_top_level_pack_id_rejected(self):
        config = {"schemaVersion": 2, "packs": [self.family("dup"), self.family("dup")]}
        with self.assertRaises(SystemExit):
            engine.validate_config(config)

    def test_duplicate_release_id_rejected(self):
        family = self.family()
        family["releases"] = family["releases"] + [dict(family["releases"][0], status="ARCHIVED")]
        with self.assertRaises(SystemExit):
            engine.validate_config({"schemaVersion": 2, "packs": [family]})

    def test_duplicate_variant_id_rejected(self):
        family = self.family()
        family["releases"][0]["variants"] = [
            {"variantId": "dup", "label": "a", "sourcePath": "a.apkg"},
            {"variantId": "dup", "label": "b", "sourcePath": "b.apkg"},
        ]
        with self.assertRaises(SystemExit):
            engine.validate_config({"schemaVersion": 2, "packs": [family]})

    def test_exactly_one_active_release_required(self):
        family = self.family()
        family["releases"] = [
            dict(family["releases"][0], releaseId="v1", status="ARCHIVED"),
            dict(family["releases"][0], releaseId="v2", status="ARCHIVED"),
        ]
        family["currentReleaseId"] = "v2"
        with self.assertRaises(SystemExit):
            engine.validate_config({"schemaVersion": 2, "packs": [family]})

    def test_pending_source_cannot_also_be_bound(self):
        family = self.family("family-a")
        config = {
            "schemaVersion": 2,
            "packs": [family],
            "pendingClassification": [{"sourcePath": "family-a.apkg", "status": "PENDING_CLASSIFICATION", "reason": "x"}],
        }
        with self.assertRaises(SystemExit):
            engine.validate_config(config)

    def test_legacy_schema_version_1_migrates_to_families(self):
        legacy = {
            "schemaVersion": 1,
            "repository": "mirrorlious/ankicardsfo1po",
            "packs": [
                {"source": "OldPack.apkg", "packId": "old-pack", "title": "Old Pack"},
                {"source": "Incoming.apkg"},
            ],
        }
        config = engine.normalize_config(legacy)
        self.assertEqual(config["schemaVersion"], 2)
        self.assertEqual(len(config["packs"]), 2)
        first = config["packs"][0]
        self.assertEqual(first["packId"], "old-pack")
        self.assertEqual(first["currentReleaseId"], "v1")
        self.assertEqual(first["releases"][0]["variants"][0]["sourcePath"], "OldPack.apkg")
        self.assertEqual(config["packs"][1]["packId"], "incoming")


class ClassificationRuleTest(unittest.TestCase):
    def test_same_content_different_template_is_variant(self):
        result = identity.classify_fingerprints("aaa", "t1", "aaa", "t2")
        self.assertIn("VARIANT", result)

    def test_different_content_is_new_release(self):
        result = identity.classify_fingerprints("aaa", "t1", "bbb", "t1")
        self.assertIn("NEW CONTENT RELEASE", result)

    def test_identical_both_is_duplicate_artifact(self):
        result = identity.classify_fingerprints("aaa", "t1", "aaa", "t1")
        self.assertIn("IDENTICAL", result)


class FeedLifecycleTest(unittest.TestCase):
    def make_state(self) -> dict:
        return {
            "schemaVersion": 2,
            "repository": "mirrorlious/ankicardsfo1po",
            "publisher": "mirrorlious",
            "packs": [{
                "packId": "family-a",
                "currentReleaseId": "v2",
                "releases": [
                    {
                        "releaseId": "v1", "displayVersion": "1", "status": "ARCHIVED",
                        "defaultVariantId": "original",
                        "variants": [self.variant("original", "v1")],
                    },
                    {
                        "releaseId": "v2", "displayVersion": "2", "status": "ACTIVE",
                        "defaultVariantId": "shuimo",
                        "variants": [self.variant("shuimo", "v2")],
                    },
                    {
                        "releaseId": "v3", "displayVersion": "3", "status": "WITHDRAWN",
                        "defaultVariantId": "broken",
                        "variants": [self.variant("broken", "v3")],
                    },
                    {
                        "releaseId": "v4", "displayVersion": "4", "status": "REVOKED",
                        "defaultVariantId": "toxic",
                        "variants": [self.variant("toxic", "v4")],
                    },
                ],
            }],
        }

    def variant(self, variant_id: str, release_id: str) -> dict:
        return {
            "packId": "family-a",
            "releaseId": release_id,
            "variantId": variant_id,
            "label": variant_id,
            "title": "Family A",
            "description": "desc",
            "subject": "",
            "license": "仅供个人学习",
            "author": "author",
            "usageHint": "hint",
            "sourcePath": f"{release_id}.apkg",
            "sourceSha256": "a" * 64,
            "manifestPath": f".miki-family-a-{variant_id}.manifest.v2.json",
            "templateReportPath": f".miki-reports/family-a-{variant_id}.json",
            "cardCount": 10, "noteCount": 10, "deckCount": 2,
            "version": "2026.08.14+aaaa", "resourceVersion": "family-a-x",
            "t1CandidateCount": 0, "blockedTemplateCount": 0,
        }

    def test_feed_lifecycle_semantics(self):
        state = self.make_state()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        state_path = root / "state.json"
        feed_path = root / "index.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")

        with patch.object(engine, "STATE_PATH", state_path), patch.object(engine, "FEED_PATH", feed_path):
            engine.feed_command("1dfc64e7fa68755261094c134e30657c3d5136f1")

        feed = json.loads(feed_path.read_text(encoding="utf-8"))
        pack = feed["packs"][0]
        # legacy flattened fields still present for current default variant
        self.assertEqual(pack["packId"], "family-a")
        self.assertEqual(pack["currentReleaseId"], "v2")
        self.assertEqual(pack["currentVariantId"], "shuimo")
        self.assertIn("manifestUrl", pack)
        self.assertEqual(pack["variantId"], "shuimo")

        releases = {item["releaseId"]: item for item in pack["releases"]}
        archived = releases["v1"]["variants"][0]
        active = releases["v2"]["variants"][0]
        withdrawn = releases["v3"]["variants"][0]
        revoked = releases["v4"]["variants"][0]

        self.assertIn("manifestUrl", active)
        self.assertIn("manifestUrl", archived)  # history download allowed
        self.assertNotIn("manifestUrl", withdrawn)  # no public artifact URL
        self.assertNotIn("templateReportUrl", withdrawn)
        self.assertNotIn("manifestUrl", revoked)  # no artifact exposure
        self.assertNotIn("sourceSha256", revoked)
        self.assertEqual(set(revoked.keys()), {"variantId", "label"})

        # top-level packIds are unique families only
        self.assertEqual(len(feed["packs"]), 1)


class ManifestProvenanceTest(unittest.TestCase):
    def test_raw_url_is_commit_pinned(self):
        url = engine.raw_url("mirrorlious/ankicardsfo1po", "a" * 40, ".miki-x.manifest.v2.json")
        self.assertIn(f"mirrorlious/ankicardsfo1po/{'a' * 40}/", url)
        self.assertTrue(url.startswith("https://raw.githubusercontent.com/"))

    def test_clean_variant_id_normalization(self):
        self.assertEqual(engine.clean_variant_id("Shuimo-Qing"), "shuimo-qing")
        self.assertEqual(engine.clean_variant_id("水墨 青"), "variant")
        self.assertTrue(len(engine.clean_variant_id("x" * 100)) <= 40)


if __name__ == "__main__":
    unittest.main()
