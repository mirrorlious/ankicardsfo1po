#!/usr/bin/env python3
"""Build Miki owner-publisher manifests and feed metadata from APKG files.

The publisher never executes template JavaScript. It reads Anki SQLite data,
calculates exact APKG integrity, fingerprints template source, and emits a
fail-closed capability report. `collection.anki21b` requires the `zstandard`
package installed by the GitHub Actions workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import quote

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover - exercised by workflow environment contract
    zstd = None

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "miki-publisher.json"
STATE_PATH = ROOT / ".miki-publish-state.json"
FEED_PATH = ROOT / "miki-public" / "index.json"
MAX_ARCHIVE_ENTRIES = 100_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_COLLECTION_BYTES = 512 * 1024 * 1024

SCRIPT_RE = re.compile(r"<script\b[^>]*>([\s\S]*?)</script>", re.I)
HANDLER_RE = re.compile(r"\son[a-z0-9:_-]+\s*=\s*([\"'])([\s\S]*?)\1", re.I)
BLOCK_RULES = (
    ("network", re.compile(r"\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b", re.I)),
    ("navigation", re.compile(r"\b(?:location|history|navigation|window\s*\.\s*open)\b", re.I)),
    ("storage", re.compile(r"\b(?:localStorage|sessionStorage|indexedDB|document\s*\.\s*cookie)\b", re.I)),
    ("host-window", re.compile(r"\b(?:parent|top|opener)\b", re.I)),
    ("dynamic-code", re.compile(r"\b(?:eval|Function)\s*\(|\bimport\s*\(", re.I)),
    ("worker", re.compile(r"\b(?:Worker|SharedWorker|ServiceWorker|WebAssembly)\b", re.I)),
    ("document-write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(", re.I)),
    ("unbounded-loop", re.compile(r"\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)", re.I)),
)


def dump_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_config() -> dict:
    value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if value.get("schemaVersion") != 1:
        raise SystemExit("Unsupported miki-publisher.json schemaVersion")
    return value


def clean_pack_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or f"owner-pack-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}"


def discover_sources(config: dict) -> list[tuple[Path, dict]]:
    configured = {
        str(item.get("source", "")).replace("\\", "/"): item
        for item in config.get("packs", [])
        if item.get("source")
    }
    found: dict[str, Path] = {}
    for pattern in ("*.apkg", "incoming/**/*.apkg"):
        for path in ROOT.glob(pattern):
            if path.is_file():
                found[path.relative_to(ROOT).as_posix()] = path
    for relative in configured:
        path = ROOT / relative
        if path.is_file():
            found[relative] = path
    if not found:
        raise SystemExit("No APKG files found in repository root or incoming/")
    return [(found[key], configured.get(key, {})) for key in sorted(found)]


def validate_archive(zf: zipfile.ZipFile) -> None:
    infos = zf.infolist()
    if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ValueError("APKG archive entry count is invalid")
    total = 0
    for info in infos:
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
            raise ValueError(f"Unsafe APKG archive path: {info.filename}")
        total += int(info.file_size)
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ValueError("APKG archive uncompressed size exceeds publisher limit")
        if info.file_size > 64 * 1024 * 1024 and info.compress_size > 0 and info.file_size > info.compress_size * 1000:
            raise ValueError(f"Suspicious APKG compression ratio: {info.filename}")


def read_collection(zf: zipfile.ZipFile) -> tuple[str, bytes]:
    names = set(zf.namelist())
    for name in ("collection.anki21", "collection.anki2"):
        if name in names:
            info = zf.getinfo(name)
            if info.file_size < 1 or info.file_size > MAX_COLLECTION_BYTES:
                raise ValueError("Anki collection size is invalid")
            return name, zf.read(name)
    if "collection.anki21b" in names:
        if zstd is None:
            raise ValueError("collection.anki21b requires Python package zstandard")
        compressed = zf.read("collection.anki21b")
        try:
            value = zstd.ZstdDecompressor().decompress(compressed, max_output_size=MAX_COLLECTION_BYTES)
        except Exception as error:
            raise ValueError(f"collection.anki21b decompression failed: {error}") from error
        if not value or len(value) > MAX_COLLECTION_BYTES:
            raise ValueError("Decompressed Anki collection size is invalid")
        return "collection.anki21b", value
    raise ValueError("APKG does not contain collection.anki2, collection.anki21, or collection.anki21b")


def open_collection(value: bytes):
    handle = tempfile.NamedTemporaryFile(prefix="miki-owner-", suffix=".sqlite", delete=False)
    try:
        handle.write(value)
        handle.close()
        connection = sqlite3.connect(handle.name)
        connection.execute("PRAGMA query_only = ON")
        return connection, Path(handle.name)
    except Exception:
        Path(handle.name).unlink(missing_ok=True)
        raise


def parse_models(connection: sqlite3.Connection) -> dict:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(col)")}
    if "models" not in columns:
        raise ValueError("Anki collection does not expose col.models")
    row = connection.execute("SELECT models FROM col LIMIT 1").fetchone()
    if not row or not row[0]:
        raise ValueError("Anki collection model metadata is missing")
    models = json.loads(row[0])
    if not isinstance(models, dict):
        raise ValueError("Anki model metadata is invalid")
    return models


def extract_executables(text: str) -> list[str]:
    values = [match.group(1).strip() for match in SCRIPT_RE.finditer(text or "") if match.group(1).strip()]
    values.extend(match.group(2).strip() for match in HANDLER_RE.finditer(text or "") if match.group(2).strip())
    return values


def assess_template(model_id: str, model: dict, template: dict, ordinal: int) -> dict:
    qfmt = str(template.get("qfmt", ""))
    afmt = str(template.get("afmt", ""))
    css = str(model.get("css", ""))
    field_names = [str(field.get("name", "")) for field in model.get("flds", []) if isinstance(field, dict)]
    executables = extract_executables(qfmt) + extract_executables(afmt)
    blockers = {
        code
        for source in executables
        for code, pattern in BLOCK_RULES
        if pattern.search(source)
    }
    canonical = {
        "modelId": str(model_id),
        "modelName": str(model.get("name", "")),
        "cardOrd": int(template.get("ord", ordinal) or 0),
        "templateName": str(template.get("name", "")),
        "fieldNames": field_names,
        "qfmt": qfmt,
        "afmt": afmt,
        "css": css,
    }
    fingerprint = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    interaction = "static" if not executables else ("blocked" if blockers else "t1-candidate")
    return {
        "modelId": canonical["modelId"],
        "modelName": canonical["modelName"],
        "cardOrd": canonical["cardOrd"],
        "templateName": canonical["templateName"],
        "fieldNames": field_names,
        "fingerprint": f"sha256:{fingerprint}",
        "executableSourceCount": len(executables),
        "interactionCandidate": interaction,
        "blockers": sorted(blockers),
        "executionApproved": False,
    }


def inspect_apkg(path: Path) -> dict:
    raw = path.read_bytes()
    with zipfile.ZipFile(path, "r") as zf:
        validate_archive(zf)
        collection_name, collection_bytes = read_collection(zf)
    connection, temp_path = open_collection(collection_bytes)
    try:
        required = {"cards", "notes", "col"}
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required.issubset(tables):
            raise ValueError("Anki collection is missing required tables")
        card_count = int(connection.execute("SELECT COUNT(*) FROM cards").fetchone()[0])
        note_count = int(connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0])
        deck_count = int(connection.execute("SELECT COUNT(DISTINCT did) FROM cards").fetchone()[0])
        if card_count < 1 or note_count < 1 or deck_count < 1:
            raise ValueError("Anki collection counts are invalid")
        templates = []
        for model_id, model in sorted(parse_models(connection).items(), key=lambda item: str(item[0])):
            if not isinstance(model, dict):
                continue
            for ordinal, template in enumerate(model.get("tmpls", []) or []):
                if isinstance(template, dict):
                    templates.append(assess_template(str(model_id), model, template, ordinal))
        if not templates:
            raise ValueError("Anki collection contains no publishable templates")
    finally:
        connection.close()
        temp_path.unlink(missing_ok=True)
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
        "collection": collection_name,
        "cardCount": card_count,
        "noteCount": note_count,
        "deckCount": deck_count,
        "templates": templates,
    }


def merge_metadata(config: dict, source: Path, override: dict) -> dict:
    merged = {**dict(config.get("defaults") or {}), **override}
    relative = source.relative_to(ROOT).as_posix()
    stem = source.stem
    merged.update({
        "source": relative,
        "packId": str(merged.get("packId") or clean_pack_id(stem)),
        "title": str(merged.get("title") or stem),
        "description": str(merged.get("description") or f"由 {stem} 自动发布的 Miki 公共卡包。"),
        "author": str(merged.get("author") or config.get("publisher") or "mirrorlious"),
        "license": str(merged.get("license") or "仅供个人学习"),
        "subject": str(merged.get("subject") or ""),
        "usageHint": str(merged.get("usageHint") or "加入后可在 Miki 公共池中安装。"),
    })
    return merged


def build_release(config: dict, source: Path, override: dict, date_key: str) -> dict:
    metadata = merge_metadata(config, source, override)
    inspection = inspect_apkg(source)
    short_hash = inspection["sha256"][:12]
    version = f"{date_key[:4]}.{date_key[4:6]}.{date_key[6:8]}+{short_hash[:8]}"
    resource_version = f"{metadata['packId']}-{short_hash}-{inspection['sizeBytes']}"
    runtime = metadata.get("runtime") or {"contentFormat": "anki", "renderEngine": "anki-core-v1"}
    manifest = {
        "schemaVersion": 2,
        "packId": metadata["packId"],
        "title": metadata["title"],
        "description": metadata["description"],
        "version": version,
        "resourceVersion": resource_version,
        "payload": {"format": "apkg", "entryResourceIds": ["source-apkg"]},
        "runtime": runtime,
        "counts": {
            "sourceCardCount": inspection["cardCount"],
            "finalCardCount": inspection["cardCount"],
            "deckCount": inspection["deckCount"],
            "duplicateCardCountRemoved": 0,
            "uniqueKnowledgeMapCount": 0,
        },
        "resources": [{
            "id": "source-apkg",
            "role": "apkg",
            "path": metadata["source"],
            "mediaType": "application/octet-stream",
            "sizeBytes": inspection["sizeBytes"],
            "integrity": {"algorithm": "sha256", "digest": inspection["sha256"]},
            "cachePolicy": "immutable",
        }],
    }
    report = {
        "schemaVersion": 1,
        "packId": metadata["packId"],
        "sourcePath": metadata["source"],
        "sourceSha256": inspection["sha256"],
        "sourceSizeBytes": inspection["sizeBytes"],
        "collection": inspection["collection"],
        "templateEditPolicy": "fields-only",
        "javascriptPolicy": "fingerprint-gated-disabled-by-default",
        "templates": inspection["templates"],
        "summary": {
            "templateCount": len(inspection["templates"]),
            "javascriptTemplateCount": sum(item["executableSourceCount"] > 0 for item in inspection["templates"]),
            "t1CandidateCount": sum(item["interactionCandidate"] == "t1-candidate" for item in inspection["templates"]),
            "blockedTemplateCount": sum(item["interactionCandidate"] == "blocked" for item in inspection["templates"]),
            "executionApprovedCount": 0,
        },
    }
    manifest_rel = f".miki-{metadata['packId']}.manifest.v2.json"
    report_rel = f".miki-reports/{metadata['packId']}.json"
    dump_json(ROOT / manifest_rel, manifest)
    dump_json(ROOT / report_rel, report)
    return {
        **metadata,
        "version": version,
        "resourceVersion": resource_version,
        "manifestSchemaVersion": 2,
        "manifestPath": manifest_rel,
        "templateReportPath": report_rel,
        "cardCount": inspection["cardCount"],
        "noteCount": inspection["noteCount"],
        "deckCount": inspection["deckCount"],
        "sourceSha256": inspection["sha256"],
        "sourceSizeBytes": inspection["sizeBytes"],
        "t1CandidateCount": report["summary"]["t1CandidateCount"],
        "blockedTemplateCount": report["summary"]["blockedTemplateCount"],
    }


def build_command() -> None:
    config = load_config()
    date_key = os.environ.get("MIKI_RELEASE_DATE") or datetime.now(timezone.utc).strftime("%Y%m%d")
    if not re.fullmatch(r"\d{8}", date_key):
        raise SystemExit("MIKI_RELEASE_DATE must be YYYYMMDD")
    releases = [build_release(config, source, override, date_key) for source, override in discover_sources(config)]
    dump_json(STATE_PATH, {
        "schemaVersion": 1,
        "repository": str(config.get("repository") or "mirrorlious/ankicardsfo1po"),
        "publisher": str(config.get("publisher") or "mirrorlious"),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "packs": releases,
    })
    print(f"Built {len(releases)} owner pack manifest(s).")


def raw_url(repository: str, commit: str, path: str) -> str:
    encoded = "/".join(quote(part, safe="") for part in PurePosixPath(path).parts)
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{encoded}"


def feed_command(commit: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit or ""):
        raise SystemExit("--commit must be a full Git commit SHA")
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    repository = str(state.get("repository") or "mirrorlious/ankicardsfo1po")
    packs = []
    for item in state.get("packs", []):
        packs.append({
            "id": item["packId"],
            "packId": item["packId"],
            "title": item["title"],
            "description": item["description"],
            "subject": item.get("subject", ""),
            "type": "cards",
            "version": item["version"],
            "resourceVersion": item["resourceVersion"],
            "manifestSchemaVersion": 2,
            "cardCount": item["cardCount"],
            "deckCount": item["deckCount"],
            "noteCount": item["noteCount"],
            "license": item["license"],
            "author": item["author"],
            "usageHint": item["usageHint"],
            "manifestUrl": raw_url(repository, commit, item["manifestPath"]),
            "publisherChannel": "owner",
            "sourceRepository": repository,
            "sourceCommit": commit,
            "sourceApkgPath": item["source"],
            "sourceSha256": item["sourceSha256"],
            "templateEditPolicy": "fields-only",
            "javascriptPolicy": "fingerprint-gated-disabled-by-default",
            "templateReportUrl": raw_url(repository, commit, item["templateReportPath"]),
            "t1CandidateCount": item["t1CandidateCount"],
            "blockedTemplateCount": item["blockedTemplateCount"],
        })
    dump_json(FEED_PATH, {
        "schemaVersion": 1,
        "feedType": "miki-owner-publisher",
        "publisher": state.get("publisher", "mirrorlious"),
        "repository": repository,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "packs": packs,
    })
    print(f"Wrote owner feed with {len(packs)} pack(s) for {commit}.")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("build")
    feed_parser = subparsers.add_parser("feed")
    feed_parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    build_command() if args.command == "build" else feed_command(args.commit)


if __name__ == "__main__":
    main()
