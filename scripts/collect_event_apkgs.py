#!/usr/bin/env python3
"""Collect root/incoming APKG paths changed by the current GitHub event.

Git path output is NUL-delimited so Unicode, spaces, tabs, and Git's
core.quotePath behavior cannot change the filename seen by the publisher.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

AUTO_SOURCES_PATH = Path(".miki-auto-sources.txt")


def build_command(event: str, before: str, base: str, head: str) -> list[str] | None:
    if event == "pull_request" and base:
        return ["git", "diff", "--name-only", "-z", base, head]
    if event == "push" and before and set(before) != {"0"}:
        return ["git", "diff", "--name-only", "-z", before, head]
    if event == "push":
        return ["git", "show", "--pretty=", "--name-only", "-z", head]
    return None


def decode_paths(payload: bytes) -> list[str]:
    return [chunk.decode("utf-8") for chunk in payload.split(b"\0") if chunk]


def filter_apkg_paths(paths: list[str]) -> list[str]:
    names: list[str] = []
    for raw in paths:
        name = raw.replace("\\", "/")
        if not name.lower().endswith(".apkg"):
            continue
        if "/" not in name or name.startswith("incoming/"):
            names.append(name)
    return sorted(set(names))


def collect_changed_apkgs(
    *,
    event: str,
    before: str = "",
    base: str = "",
    head: str = "HEAD",
    cwd: str | Path | None = None,
) -> list[str]:
    command = build_command(event, before, base, head or "HEAD")
    if not command:
        return []
    payload = subprocess.check_output(command, cwd=cwd)
    return filter_apkg_paths(decode_paths(payload))


def main() -> None:
    names = collect_changed_apkgs(
        event=os.environ.get("EVENT_NAME", ""),
        before=os.environ.get("BEFORE_SHA", ""),
        base=os.environ.get("BASE_SHA", ""),
        head=os.environ.get("HEAD_SHA", "") or "HEAD",
    )
    AUTO_SOURCES_PATH.write_text(
        "".join(f"{name}\n" for name in names),
        encoding="utf-8",
    )
    print(f"event-scoped APKG candidates: {names}")


if __name__ == "__main__":
    main()
