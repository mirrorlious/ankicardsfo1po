#!/usr/bin/env python3
"""Safe entrypoint for the Miki owner publisher.

Discovery policy is intentionally narrower than the underlying APKG build engine:
- repository-root APKG files are publishable only when explicitly listed in
  miki-publisher.json;
- incoming/**/*.apkg is the only auto-discovery lane.

The underlying publisher still performs archive/SQLite/integrity/template checks
and never approves JavaScript execution by itself.
"""

from __future__ import annotations

from pathlib import Path

import publish_miki_owner_pack as engine


def discover_sources(config: dict) -> list[tuple[Path, dict]]:
    configured = {
        str(item.get("source", "")).replace("\\", "/"): item
        for item in config.get("packs", [])
        if item.get("source")
    }

    found: dict[str, Path] = {}
    missing_configured: list[str] = []

    # Root-level APKG files are never auto-discovered. They must be explicitly
    # registered so historical copies/backups cannot become public by accident.
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

    # incoming/ is the deliberate low-friction author lane. New APKGs placed
    # here may be auto-discovered, but they still pass every publisher gate.
    incoming = engine.ROOT / "incoming"
    if incoming.exists():
        for path in incoming.rglob("*.apkg"):
            if path.is_file():
                relative = path.relative_to(engine.ROOT).as_posix()
                found[relative] = path

    if not found:
        raise SystemExit(
            "No publishable APKG files found. Register root files in miki-publisher.json "
            "or place new files under incoming/."
        )

    return [(found[key], configured.get(key, {})) for key in sorted(found)]


def main() -> None:
    # build_command resolves discover_sources from the engine module at runtime.
    # Replacing only that policy seam keeps the mature APKG parser untouched.
    engine.discover_sources = discover_sources
    engine.main()


if __name__ == "__main__":
    main()
