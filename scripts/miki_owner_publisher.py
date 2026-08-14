#!/usr/bin/env python3
"""Safe entrypoint for the Miki owner publisher.

Discovery policy (schemaVersion 2 identity model):
- pack families / releases / variants bound in miki-publisher.json are always
  publishable;
- incoming/**/*.apkg is the explicit zero-config author lane and is always
  auto-discovered as its own pack family;
- repository-root APKG files from the current GitHub event are publishable
  ONLY when they are already bound to a pack family variant;
- a newly uploaded root APKG that is NOT bound to any family is recorded in
  `pendingClassification` (PENDING_CLASSIFICATION) and never enters the
  public feed. Filename no longer implies pack identity.

The GitHub workflow is responsible for creating .miki-auto-sources.txt from the
current push / pull-request diff. Only the repository owner is allowed to execute
the write-capable publish job. The underlying publisher still performs archive,
SQLite, integrity, template and JavaScript capability checks and never approves
raw JavaScript execution by itself.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path, PurePosixPath

import publish_miki_owner_pack as engine

AUTO_SOURCES_PATH = engine.ROOT / ".miki-auto-sources.txt"


def normalize_relative_source(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts:
        return ""
    return path.as_posix()


def is_root_apkg(relative: str) -> bool:
    path = PurePosixPath(relative)
    return len(path.parts) == 1 and path.suffix.lower() == ".apkg"


def read_auto_sources() -> list[str]:
    if not AUTO_SOURCES_PATH.is_file():
        return []
    values = []
    seen = set()
    for line in AUTO_SOURCES_PATH.read_text(encoding="utf-8").splitlines():
        relative = normalize_relative_source(line)
        if not relative or relative in seen:
            continue
        if not (is_root_apkg(relative) or relative.startswith("incoming/") and relative.lower().endswith(".apkg")):
            continue
        values.append(relative)
        seen.add(relative)
    return values


def bound_sources(config: dict) -> set[str]:
    return {
        str(variant.get("sourcePath", "")).replace("\\", "/")
        for pack in config.get("packs", [])
        for release in pack.get("releases", [])
        for variant in release.get("variants", [])
        if variant.get("sourcePath")
    }


def inject_incoming_lane(config: dict) -> dict:
    """Zero-config author lane: each incoming/**/*.apkg becomes its own
    single-release family (ADR-026 lane semantics preserved)."""
    incoming = engine.ROOT / "incoming"
    if not incoming.exists():
        return config
    bound = bound_sources(config)
    packs = list(config.get("packs", []))
    appended = []
    for path in sorted(incoming.rglob("*.apkg")):
        if not path.is_file():
            continue
        relative = path.relative_to(engine.ROOT).as_posix()
        if relative in bound:
            continue
        stem = path.stem
        pack_id = engine.clean_pack_id(stem)
        appended.append(relative)
        packs.append({
            "packId": pack_id,
            "title": stem.replace("_", " ").strip() or stem,
            "currentReleaseId": "v1",
            "releases": [{
                "releaseId": "v1",
                "displayVersion": "1",
                "status": "ACTIVE",
                "defaultVariantId": "original",
                "variants": [{
                    "variantId": "original",
                    "label": "原版",
                    "sourcePath": relative,
                }],
            }],
        })
    if appended:
        print(f"zero-config incoming lane packs: {appended}")
    config["packs"] = packs
    return config


def authorize_command() -> None:
    """PENDING_CLASSIFICATION gate. Root APKG uploads are NEVER auto-bound to a
    pack family. Unbound root sources are recorded as pending and stay out of
    the public feed until the Owner binds them to pack/release/variant."""
    config = engine.load_config()
    config = engine.normalize_config(config)
    bound = bound_sources(config)
    pending = list(config.get("pendingClassification", []))
    pending_sources = {str(item.get("sourcePath", "")).replace("\\", "/") for item in pending}
    added = []
    for relative in read_auto_sources():
        if not is_root_apkg(relative):
            continue
        path = engine.ROOT / relative
        if not path.is_file():
            continue
        if relative in bound or relative in pending_sources:
            continue
        pending.append({
            "sourcePath": relative,
            "status": "PENDING_CLASSIFICATION",
            "reason": "NEW_ROOT_UPLOAD_UNCLASSIFIED",
            "detail": (
                "新上传的 root APKG 未绑定到任何 pack family 的 release/variant。"
                "按 P0 门禁暂停公开，等待 Owner 完成身份审计与 pack/release/variant 绑定。"
            ),
        })
        added.append(relative)

    if added:
        config["pendingClassification"] = pending
        engine.dump_json(engine.CONFIG_PATH, config)
        print(f"Recorded {len(added)} pending unclassified root source(s): {added}")
    else:
        print("No new unclassified root APKG upload.")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "authorize":
        if len(sys.argv) != 2:
            raise SystemExit("authorize does not accept additional arguments")
        authorize_command()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "build":
        config = engine.normalize_config(engine.load_config())
        engine.validate_config(config)
        config = inject_incoming_lane(config)
        engine.validate_config(config)
        engine.build_with_config(config)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "feed":
        commit = None
        if len(sys.argv) == 4 and sys.argv[2] == "--commit":
            commit = sys.argv[3]
        elif len(sys.argv) == 3 and sys.argv[2].startswith("--commit="):
            commit = sys.argv[2].split("=", 1)[1]
        if not commit:
            raise SystemExit("usage: feed --commit=<40-hex-sha>")
        engine.feed_command(commit)
        return

    raise SystemExit("usage: miki_owner_publisher.py authorize|build|feed --commit=<sha>")


if __name__ == "__main__":
    main()
