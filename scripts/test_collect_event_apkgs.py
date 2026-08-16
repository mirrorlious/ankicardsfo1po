from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import collect_event_apkgs as collector


class EventApkgCollectorTest(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True, encoding="utf-8").strip()

    def test_unicode_root_apkg_survives_git_path_quoting(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.git(root, "init")
        self.git(root, "config", "user.name", "Miki Test")
        self.git(root, "config", "user.email", "miki-test@example.invalid")
        (root / "README.md").write_text("baseline\n", encoding="utf-8")
        self.git(root, "add", "--", "README.md")
        self.git(root, "commit", "-m", "baseline")
        base = self.git(root, "rev-parse", "HEAD")

        filename = "27政治 阶段测_水墨青165题.apkg"
        (root / filename).write_bytes(b"fixture")
        self.git(root, "add", "--", filename)
        self.git(root, "commit", "-m", "add unicode apkg")
        head = self.git(root, "rev-parse", "HEAD")

        names = collector.collect_changed_apkgs(
            event="push",
            before=base,
            head=head,
            cwd=root,
        )
        self.assertEqual(names, [filename])

    def test_only_root_and_incoming_apkgs_are_collected(self):
        payload = (
            "根目录.apkg\0"
            "incoming/政治/资料 包.apkg\0"
            "nested/private.apkg\0"
            "README.md\0"
        ).encode("utf-8")
        paths = collector.decode_paths(payload)
        self.assertEqual(
            collector.filter_apkg_paths(paths),
            ["incoming/政治/资料 包.apkg", "根目录.apkg"],
        )


if __name__ == "__main__":
    unittest.main()
