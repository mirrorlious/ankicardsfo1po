#!/usr/bin/env python3
"""Safe entrypoint for the Miki owner publisher.

Discovery policy:
- configured APKG files are always publishable;
- incoming/**/*.apkg is the low-friction author lane and is always auto-discovered;
- repository-root APKG files are auto-discovered only when they are listed in
  .miki-auto-sources.txt for the current GitHub event;
- `authorize` persists newly uploaded root APKG files into miki-publisher.json so
  later publisher runs keep them in the owner feed.

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


def configured_sources(config: dict) -> dict[str, dict]:
    return {
        normalize_relative_source(item.get("source", "")): item
        for item in config.get("packs", [])
        if normalize_relative_source(item.get("source", ""))
    }


def discover_sources(config: dict) -> list[tuple[Path, dict]]:
    configured = configured_sources(config)
    found: dict[str, Path] = {}
    missing_configured: list[str] = []

    for relative in configured:
        path = engine.ROOT / relative
        if path.is_file():
            found[relative] = path
        else:
            missing_configured.append(relative)

    if missing_configured:
        raise SystemExit(
            "Configured APKG source(s) are missing: " + ", ".join(sorted(missing_configured))
        )

    # incoming/ remains the explicit zero-config lane. Existing incoming packs stay
    # discoverable on every run, so later uploads cannot evict earlier feed entries.
    incoming = engine.ROOT / "incoming"
    if incoming.exists():
        for path in incoming.rglob("*.apkg"):
            if path.is_file():
                relative = path.relative_to(engine.ROOT).as_posix()
                found[relative] = path

    # Root APKG auto-discovery is event-scoped. This prevents old historical files
    # from being swept into the public pool just because the workflow was enabled.
    for relative in read_auto_sources():
        if not is_root_apkg(relative):
            continue
        path = engine.ROOT / relative
        if path.is_file():
            found[relative] = path

    if not found:
        raise SystemExit(
            "No publishable APKG files found. Configure a root pack, upload a new root APKG "
            "through the owner workflow, or place a pack under incoming/."
        )

    return [(found[key], configured.get(key, {})) for key in sorted(found)]


def auto_pack_entry(relative: str) -> dict:
    stem = Path(relative).stem
    title = stem.replace("_", " ").strip() or stem
    return {
        "source": relative,
        "packId": engine.clean_pack_id(stem),
        "title": title,
    }


def authorize_root_uploads(config: dict) -> list[dict]:
    packs = list(config.get("packs", []))
    configured = configured_sources({"packs": packs})
    added = []

    for relative in read_auto_sources():
        if not is_root_apkg(relative) or relative in configured:
            continue
        path = engine.ROOT / relative
        if not path.is_file():
            continue
        entry = auto_pack_entry(relative)
        packs.append(entry)
        configured[relative] = entry
        added.append(entry)

    if added:
        config["packs"] = packs
    return added


def authorize_command() -> None:
    config = engine.load_config()
    added = authorize_root_uploads(config)
    if added:
        engine.dump_json(engine.CONFIG_PATH, config)
        print(f"Authorized {len(added)} new root APKG source(s): {[item['source'] for item in added]}")
    else:
        print("No new root APKG authorization required.")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "authorize":
        if len(sys.argv) != 2:
            raise SystemExit("authorize does not accept additional arguments")
        authorize_command()
        return

    # build_command resolves discover_sources from the engine module at runtime.
    # Replacing only the policy seam keeps the mature APKG parser untouched.
    engine.discover_sources = discover_sources
    engine.main()


if __name__ == "__main__":
    main()
