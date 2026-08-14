#!/usr/bin/env python3
"""Build Miki owner-publisher manifests and feed metadata from APKG files.

Identity model (schemaVersion 2):

    pack family → content release → skin/template variant → immutable APKG

The publisher never executes template JavaScript. It reads Anki SQLite data,
calculates exact APKG integrity, fingerprints content (semantic) and template
(variant) independently, and emits fail-closed capability reports.

Lifecycle per release: ACTIVE / ARCHIVED / WITHDRAWN / REVOKED.
  - ACTIVE    install + download
  - ARCHIVED  download only (history)
  - WITHDRAWN no public URLs (audit record stays in registry)
  - REVOKED   minimal audit metadata only, never artifact URLs
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

import audit_apkg_identity as identity

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover - exercised by workflow environment contract
    zstd = None

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "miki-publisher.json"
STATE_PATH = ROOT / ".miki-publish-state.json"
FEED_PATH = ROOT / "miki-public" / "index.json"
REPORTS_DIR = ROOT / ".miki-reports"
MAX_ARCHIVE_ENTRIES = 100_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_COLLECTION_BYTES = 512 * 1024 * 1024

RELEASE_STATUSES = ("ACTIVE", "ARCHIVED", "WITHDRAWN", "REVOKED")

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


def clean_pack_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or f"owner-pack-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}"


def clean_variant_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:40] or "variant"


def normalize_config(raw: dict) -> dict:
    """Accept schemaVersion 1 (legacy flat packs) or 2 (family/release/variant)
    and return a normalized schemaVersion-2 config."""
    version = raw.get("schemaVersion")
    if version == 2:
        return raw
    if version != 1:
        raise SystemExit(f"Unsupported miki-publisher.json schemaVersion: {version!r}")

    packs = []
    for item in raw.get("packs", []):
        source = str(item.get("source", "")).strip()
        if not source:
            continue
        pack = {key: value for key, value in item.items() if key not in ("source", "packId", "version")}
        pack["packId"] = str(item.get("packId") or clean_pack_id(Path(source).stem))
        pack["currentReleaseId"] = "v1"
        pack["releases"] = [{
            "releaseId": "v1",
            "displayVersion": str(item.get("displayVersion") or "1"),
            "status": "ACTIVE",
            "defaultVariantId": "original",
            "variants": [{
                "variantId": "original",
                "label": "原版",
                "sourcePath": source,
            }],
        }]
        packs.append(pack)

    config = {key: value for key, value in raw.items() if key not in ("schemaVersion", "packs")}
    config["schemaVersion"] = 2
    config["packs"] = packs
    return config


def validate_config(config: dict) -> None:
    packs = config.get("packs", [])
    if not isinstance(packs, list) or not packs:
        raise SystemExit("miki-publisher.json must define at least one pack family")

    seen_pack_ids: set[str] = set()
    bound_sources: set[str] = set()
    for pack in packs:
        pack_id = str(pack.get("packId", "")).strip()
        if not pack_id:
            raise SystemExit("pack family is missing packId")
        if pack_id in seen_pack_ids:
            raise SystemExit(f"duplicate top-level packId: {pack_id}")
        seen_pack_ids.add(pack_id)

        releases = pack.get("releases", [])
        if not isinstance(releases, list) or not releases:
            raise SystemExit(f"pack {pack_id} must define at least one release")
        seen_release_ids: set[str] = set()
        active_count = 0
        for release in releases:
            release_id = str(release.get("releaseId", "")).strip()
            if not release_id:
                raise SystemExit(f"pack {pack_id} contains a release without releaseId")
            if release_id in seen_release_ids:
                raise SystemExit(f"pack {pack_id} duplicate releaseId: {release_id}")
            seen_release_ids.add(release_id)
            status = str(release.get("status", "")).upper()
            if status not in RELEASE_STATUSES:
                raise SystemExit(f"pack {pack_id} release {release_id} invalid status: {status!r}")
            if status == "ACTIVE":
                active_count += 1
            variants = release.get("variants", [])
            if not isinstance(variants, list) or not variants:
                raise SystemExit(f"pack {pack_id} release {release_id} must define variants")
            seen_variant_ids: set[str] = set()
            for variant in variants:
                variant_id = str(variant.get("variantId", "")).strip()
                source_path = str(variant.get("sourcePath", "")).replace("\\", "/").strip()
                if not variant_id or not source_path:
                    raise SystemExit(f"pack {pack_id} release {release_id} variant is missing variantId/sourcePath")
                if variant_id in seen_variant_ids:
                    raise SystemExit(f"pack {pack_id} release {release_id} duplicate variantId: {variant_id}")
                seen_variant_ids.add(variant_id)
                bound_sources.add(source_path)
            default_variant = str(release.get("defaultVariantId", "")).strip()
            if default_variant and default_variant not in seen_variant_ids:
                raise SystemExit(f"pack {pack_id} release {release_id} defaultVariantId unknown: {default_variant}")
        if active_count != 1:
            raise SystemExit(f"pack {pack_id} must have exactly one ACTIVE release (found {active_count})")
        current_release = str(pack.get("currentReleaseId", "")).strip()
        if current_release not in seen_release_ids:
            raise SystemExit(f"pack {pack_id} currentReleaseId unknown: {current_release!r}")

    for pending in config.get("pendingClassification", []):
        source_path = str(pending.get("sourcePath", "")).replace("\\", "/").strip()
        if not source_path:
            raise SystemExit("pendingClassification entry is missing sourcePath")
        if source_path in bound_sources:
            raise SystemExit(f"pending source is also bound to a pack variant: {source_path}")


def variant_sources(config: dict) -> list[tuple[Path, dict, dict, dict]]:
    """(path, pack, release, variant) for every bound variant source."""
    sources: list[tuple[Path, dict, dict, dict]] = []
    for pack in config.get("packs", []):
        for release in pack.get("releases", []):
            for variant in release.get("variants", []):
                relative = str(variant.get("sourcePath", "")).replace("\\", "/")
                path = ROOT / relative
                if not path.is_file():
                    raise SystemExit(
                        f"Configured APKG source missing: {relative} "
                        f"(pack {pack['packId']} release {release['releaseId']} variant {variant['variantId']})"
                    )
                sources.append((path, pack, release, variant))
    return sources


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
    """APKG integrity + counts + template security assessment.
    Never executes template JavaScript. Collection parsing is delegated to
    the shared identity audit module (content/template fingerprints)."""
    identity_info = identity.inspect_apkg(path)
    raw = path.read_bytes()
    with zipfile.ZipFile(path, "r") as zf:
        validate_archive(zf)
        collection_name, collection_bytes = read_collection(zf)
    connection, temp_path = open_collection(collection_bytes)
    try:
        templates = []
        models = parse_models(connection)
        for model_id, model in sorted(models.items(), key=lambda item: str(item[0])):
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
        "cardCount": identity_info["cardCount"],
        "noteCount": identity_info["noteCount"],
        "deckCount": identity_info["deckCount"],
        "contentFingerprint": identity_info["contentFingerprint"],
        "templateFingerprint": identity_info["templateFingerprint"],
        "templates": templates,
    }


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
        raise ValueError("Anki collection model metadata is invalid")
    return models


def merge_metadata(config: dict, pack: dict, release: dict, variant: dict) -> dict:
    defaults = dict(config.get("defaults") or {})
    variant_label = str(variant.get("label") or variant.get("variantId") or "variant")
    merged = {
        **defaults,
        **{key: value for key, value in pack.items() if key not in ("releases", "currentReleaseId", "runtime", "packId")},
        "source": str(variant.get("sourcePath", "")).replace("\\", "/"),
        "packId": str(pack["packId"]),
        "releaseId": str(release["releaseId"]),
        "variantId": str(variant["variantId"]),
        "title": str(pack.get("title") or pack["packId"]),
        "description": str(pack.get("description") or f"由 {pack['packId']} 自动发布的 Miki 公共卡包。"),
        "author": str(pack.get("author") or config.get("publisher") or "mirrorlious"),
        "license": str(pack.get("license") or "仅供个人学习"),
        "subject": str(pack.get("subject") or ""),
        "usageHint": str(pack.get("usageHint") or "加入后可在 Miki 公共池中安装。"),
        "runtime": pack.get("runtime") or defaults.get("runtime") or {"contentFormat": "anki", "renderEngine": "anki-core-v1"},
        "variantLabel": variant_label,
    }
    return merged


def build_variant(config: dict, source: Path, pack: dict, release: dict, variant: dict, date_key: str, is_legacy_default: bool) -> dict:
    metadata = merge_metadata(config, pack, release, variant)
    inspection = inspect_apkg(source)
    short_hash = inspection["sha256"][:12]
    version = f"{date_key[:4]}.{date_key[6:8]}.{date_key[4:6]}+{short_hash[:8]}"
    resource_version = f"{metadata['packId']}-{metadata['variantId']}-{short_hash}-{inspection['sizeBytes']}"
    manifest = {
        "schemaVersion": 2,
        "packId": metadata["packId"],
        "releaseId": metadata["releaseId"],
        "variantId": metadata["variantId"],
        "title": metadata["title"],
        "description": metadata["description"],
        "version": version,
        "resourceVersion": resource_version,
        "payload": {"format": "apkg", "entryResourceIds": ["source-apkg"]},
        "runtime": metadata["runtime"],
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
        "releaseId": metadata["releaseId"],
        "variantId": metadata["variantId"],
        "sourcePath": metadata["source"],
        "sourceSha256": inspection["sha256"],
        "sourceSizeBytes": inspection["sizeBytes"],
        "collection": inspection["collection"],
        "contentFingerprint": f"sha256:{inspection['contentFingerprint']}",
        "templateFingerprint": f"sha256:{inspection['templateFingerprint']}",
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

    manifest_rel = f".miki-{metadata['packId']}-{metadata['variantId']}.manifest.v2.json"
    report_rel = f".miki-reports/{metadata['packId']}-{metadata['variantId']}.json"
    dump_json(ROOT / manifest_rel, manifest)
    dump_json(ROOT / report_rel, report)
    if is_legacy_default:
        dump_json(ROOT / f".miki-{metadata['packId']}.manifest.v2.json", manifest)
        dump_json(ROOT / f".miki-reports/{metadata['packId']}.json", report)

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
        "contentFingerprint": inspection["contentFingerprint"],
        "templateFingerprint": inspection["templateFingerprint"],
        "t1CandidateCount": report["summary"]["t1CandidateCount"],
        "blockedTemplateCount": report["summary"]["blockedTemplateCount"],
    }


def remove_stale_generated_artifacts(kept_manifest_paths: set[str], kept_report_paths: set[str]) -> None:
    for path in ROOT.glob(".miki-*.manifest.v2.json"):
        if path.name not in kept_manifest_paths:
            path.unlink(missing_ok=True)
            print(f"removed stale generated manifest: {path.name}")
    REPORTS_DIR.mkdir(exist_ok=True)
    for path in REPORTS_DIR.glob("*.json"):
        if path.name not in kept_report_paths:
            path.unlink(missing_ok=True)
            print(f"removed stale generated report: {path.name}")


def discover_sources(config: dict) -> list[tuple[Path, dict]]:
    """Legacy-shaped discovery (single pack per source). Replaced by the
    entrypoint policy; kept for v1 callers/tests."""
    converted: list[tuple[Path, dict]] = []
    for path, pack, release, variant in variant_sources(config):
        converted.append((path, {**pack, **{"source": variant["sourcePath"], "releaseId": release["releaseId"], "variantId": variant["variantId"]}}))
    return converted


def build_with_config(config: dict) -> None:
    config = normalize_config(config)
    validate_config(config)
    date_key = os.environ.get("MIKI_RELEASE_DATE") or datetime.now(timezone.utc).strftime("%Y%m%d")
    if not re.fullmatch(r"\d{8}", date_key):
        raise SystemExit("MIKI_RELEASE_DATE must be YYYYMMDD")

    families = []
    kept_manifests: set[str] = set()
    kept_reports: set[str] = set()
    for pack in config.get("packs", []):
        current_release_id = str(pack.get("currentReleaseId", ""))
        family = {"packId": pack["packId"], "currentReleaseId": current_release_id, "releases": []}
        for release in pack.get("releases", []):
            release_entry = {
                "releaseId": release["releaseId"],
                "displayVersion": str(release.get("displayVersion") or release["releaseId"]),
                "status": str(release.get("status", "")).upper(),
                "defaultVariantId": str(release.get("defaultVariantId", "") or release["variants"][0]["variantId"]),
                "classificationEvidence": release.get("classificationEvidence"),
                "variants": [],
            }
            for variant in release.get("variants", []):
                source_path = Path(str(variant.get("sourcePath", "")).replace("\\", "/"))
                is_legacy_default = release["releaseId"] == current_release_id and variant["variantId"] == release_entry["defaultVariantId"]
                built = build_variant(config, ROOT / source_path, pack, release, variant, date_key, is_legacy_default)
                kept_manifests.add(Path(built["manifestPath"]).name)
                if is_legacy_default:
                    kept_manifests.add(f".miki-{pack['packId']}.manifest.v2.json")
                kept_reports.add(Path(built["templateReportPath"]).name)
                if is_legacy_default:
                    kept_reports.add(f"{pack['packId']}.json")
                release_entry["variants"].append({
                    "packId": built["packId"],
                    "variantId": built["variantId"],
                    "label": built["variantLabel"],
                    "sourcePath": built["source"],
                    "sourceSha256": built["sourceSha256"],
                    "sourceSizeBytes": built["sourceSizeBytes"],
                    "contentFingerprint": f"sha256:{built['contentFingerprint']}",
                    "templateFingerprint": f"sha256:{built['templateFingerprint']}",
                    "manifestPath": built["manifestPath"],
                    "templateReportPath": built["templateReportPath"],
                    "cardCount": built["cardCount"],
                    "noteCount": built["noteCount"],
                    "deckCount": built["deckCount"],
                    "version": built["version"],
                    "resourceVersion": built["resourceVersion"],
                    "title": built["title"],
                    "description": built["description"],
                    "subject": built["subject"],
                    "license": built["license"],
                    "author": built["author"],
                    "usageHint": built["usageHint"],
                    "t1CandidateCount": built["t1CandidateCount"],
                    "blockedTemplateCount": built["blockedTemplateCount"],
                })
            family["releases"].append(release_entry)
        families.append(family)

    remove_stale_generated_artifacts(kept_manifests, kept_reports)

    dump_json(STATE_PATH, {
        "schemaVersion": 2,
        "repository": str(config.get("repository") or "mirrorlious/ankicardsfo1po"),
        "publisher": str(config.get("publisher") or "mirrorlious"),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "packs": families,
        "pendingClassification": config.get("pendingClassification", []),
    })
    print(f"Built {len(families)} owner pack families.")


def raw_url(repository: str, commit: str, path: str) -> str:
    encoded = "/".join(quote(part, safe="") for part in PurePosixPath(path).parts)
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{encoded}"


def legacy_entry(item: dict, repository: str, commit: str, runtime: dict | None = None) -> dict:
    """Flattened current-release/default-variant fields for existing Miki
    consumers. The legacy manifest/report carry the same content as the
    variant-specific files. Adds releaseId/variantId without changing the
    legacy field set."""
    runtime_value = runtime or {"contentFormat": "anki", "renderEngine": "anki-core-v1"}
    return {
        "id": item["packId"],
        "packId": item["packId"],
        "title": item.get("title", item["packId"]),
        "description": item.get("description", ""),
        "subject": item.get("subject", ""),
        "type": "cards",
        "version": item["version"],
        "resourceVersion": item["resourceVersion"],
        "manifestSchemaVersion": 2,
        "cardCount": item["cardCount"],
        "deckCount": item["deckCount"],
        "noteCount": item["noteCount"],
        "license": item.get("license", "仅供个人学习"),
        "author": item.get("author", "原卡作者"),
        "usageHint": item.get("usageHint", ""),
        "manifestUrl": raw_url(repository, commit, item["manifestPath"]),
        "publisherChannel": "owner",
        "sourceRepository": repository,
        "sourceCommit": commit,
        "sourceApkgPath": item["sourcePath"],
        "sourceSha256": item["sourceSha256"],
        "templateEditPolicy": "fields-only",
        "javascriptPolicy": "fingerprint-gated-disabled-by-default",
        "templateReportUrl": raw_url(repository, commit, item["templateReportPath"]),
        "t1CandidateCount": item.get("t1CandidateCount", 0),
        "blockedTemplateCount": item.get("blockedTemplateCount", 0),
        "releaseId": item.get("releaseId", ""),
        "variantId": item.get("variantId", ""),
    }


def feed_command(commit: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit or ""):
        raise SystemExit("--commit must be a full Git commit SHA")
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    repository = str(state.get("repository") or "mirrorlious/ankicardsfo1po")
    packs = []
    for family in state.get("packs", []):
        current_release_id = str(family.get("currentReleaseId", ""))
        releases_out = []
        legacy = None
        for release in family.get("releases", []):
            status = str(release.get("status", "")).upper()
            default_variant_id = str(release.get("defaultVariantId", ""))
            variants_out = []
            for variant in release.get("variants", []):
                is_default = variant["variantId"] == default_variant_id and release["releaseId"] == current_release_id
                if status == "REVOKED":
                    variants_out.append({
                        "variantId": variant["variantId"],
                        "label": variant.get("label", ""),
                    })
                    continue
                if status == "WITHDRAWN":
                    variants_out.append({
                        "variantId": variant["variantId"],
                        "label": variant.get("label", ""),
                    })
                    continue
                entry = legacy_entry(variant, repository, commit)
                entry["releaseId"] = release["releaseId"]
                entry["variantId"] = variant["variantId"]
                variants_out.append(entry)
                if is_default:
                    legacy = legacy_entry(variant, repository, commit)
            releases_out.append({
                "releaseId": release["releaseId"],
                "displayVersion": release.get("displayVersion", ""),
                "status": status,
                "defaultVariantId": release.get("defaultVariantId", ""),
                "contentFingerprint": release.get("classificationEvidence", {}).get("contentFingerprint", "") if release.get("classificationEvidence") else "",
                "variants": variants_out,
            })
        if legacy is None:
            raise SystemExit(f"pack {family['packId']} has no publishable current default variant")
        current_variant_id = ""
        for release in family.get("releases", []):
            if release["releaseId"] == current_release_id:
                current_variant_id = release.get("defaultVariantId", "")
                break
        legacy["currentReleaseId"] = current_release_id
        legacy["currentVariantId"] = current_variant_id
        legacy["releases"] = releases_out
        packs.append(legacy)

    dump_json(FEED_PATH, {
        "schemaVersion": 1,
        "feedType": "miki-owner-publisher",
        "publisher": state.get("publisher", "mirrorlious"),
        "repository": repository,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "packs": packs,
    })
    print(f"Wrote owner feed with {len(packs)} pack family(s) for {commit}.")


def build_command() -> None:
    build_with_config(load_config())


def load_config() -> dict:
    value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return value


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
