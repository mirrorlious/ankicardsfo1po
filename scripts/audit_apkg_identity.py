#!/usr/bin/env python3
"""APKG pair classification audit.

Static-only: reads Anki SQLite collection data and computes two independent
fingerprints per APKG:

  content fingerprint  - deck hierarchy + field names + field values keyed by
                         stable note GUID + card ord mapping + content-
                         referenced media (skins/wrappers excluded)
  template fingerprint - model identity + qfmt/afmt/css + template-referenced
                         media (safe interaction surface)

Never executes template JavaScript.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import zstandard as zstd

ROOT = Path(__file__).resolve().parents[1]

FIELD_SEP = "\x1f"
MEDIA_REF_RE = re.compile(r'([A-Za-z0-9_\-./()]+\.(?:jpg|jpeg|png|gif|webp|svg|mp3|wav|ogg|m4a|mp4|ttf|woff2?|css))', re.I)
TAG_RE = re.compile(r"<[^>]*>")
ENTITY_MAP = {"&nbsp;": " ", "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"', "&#39;": "'", "&apos;": "'"}
WS_RE = re.compile(r"\s+")


def normalize_field_value(value: str) -> str:
    """Stable semantic normalization: wrapper HTML/whitespace must not change
    the content identity, real text changes must."""
    text = str(value or "")
    for entity, replacement in ENTITY_MAP.items():
        text = text.replace(entity, replacement)
    text = TAG_RE.sub(" ", text)
    return WS_RE.sub(" ", text).strip()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_collection(zf: zipfile.ZipFile) -> tuple[str, bytes]:
    names = set(zf.namelist())
    for name in ("collection.anki21", "collection.anki2"):
        if name in names:
            return name, zf.read(name)
    if "collection.anki21b" in names:
        return "collection.anki21b", zstd.ZstdDecompressor().decompress(zf.read("collection.anki21b"), max_output_size=512 * 1024 * 1024)
    raise ValueError("no collection table found")


def media_inventory(zf: zipfile.ZipFile) -> dict[str, dict]:
    inventory = {}
    for info in zf.infolist():
        name = info.filename
        if name.startswith("collection.") or name == "media":
            continue
        value = zf.read(name)
        inventory[name] = {"sha256": sha256_hex(value), "sizeBytes": len(value)}
    return inventory


def referenced_media(*texts: str) -> set[str]:
    found: set[str] = set()
    for text in texts:
        for match in MEDIA_REF_RE.findall(text or ""):
            found.add(match.strip())
    return found


def inspect_apkg(path: Path) -> dict:
    with zipfile.ZipFile(path, "r") as zf:
        collection_name, collection_bytes = read_collection(zf)
        media = media_inventory(zf)

    handle = tempfile.NamedTemporaryFile(prefix="miki-audit-", suffix=".sqlite", delete=False)
    handle.write(collection_bytes)
    handle.close()
    connection = sqlite3.connect(handle.name)
    connection.execute("PRAGMA query_only = ON")
    try:
        models_raw = connection.execute("SELECT models, decks FROM col LIMIT 1").fetchone()
        models = json.loads(models_raw[0]) if models_raw and models_raw[0] else {}
        decks_json = json.loads(models_raw[1]) if models_raw and len(models_raw) > 1 and models_raw[1] else {}
        decks = {int(key): str(value.get("name", "")) for key, value in decks_json.items() if isinstance(value, dict)}

        model_meta = {}
        for model_id, model in models.items():
            if not isinstance(model, dict):
                continue
            model_meta[str(model_id)] = {
                "name": str(model.get("name", "")),
                "fieldNames": [str(f.get("name", "")) for f in model.get("flds", []) if isinstance(f, dict)],
                "css": str(model.get("css", "")),
                "templates": [
                    {
                        "name": str(t.get("name", "")),
                        "ord": int(t.get("ord", ordinal) or 0),
                        "qfmt": str(t.get("qfmt", "")),
                        "afmt": str(t.get("afmt", "")),
                    }
                    for ordinal, t in enumerate(model.get("tmpls", []) or [])
                    if isinstance(t, dict)
                ],
            }

        notes = []
        for row in connection.execute("SELECT id, guid, mid, flds FROM notes"):
            notes.append({
                "id": int(row[0]),
                "guid": str(row[1]),
                "mid": str(row[2]),
                "fields": [str(v) for v in str(row[3] or "").split(FIELD_SEP)],
            })

        cards = []
        for row in connection.execute("SELECT id, nid, did, ord FROM cards"):
            cards.append({"id": int(row[0]), "nid": int(row[1]), "did": int(row[2]), "ord": int(row[3])})

        card_count = len(cards)
        note_count = len(notes)
        deck_count = len({card["did"] for card in cards})

        # ---- semantic content fingerprint --------------------------------
        deck_names = sorted({name for name in decks.values() if name})

        field_name_sets = sorted({tuple(m["fieldNames"]) for m in model_meta.values()})

        content_referenced: set[str] = set()
        note_records = []
        raw_field_values_by_guid = {}
        for note in notes:
            fields = tuple(note["fields"])
            content_referenced |= referenced_media(*fields)
            raw_field_values_by_guid[note["guid"]] = fields
            note_records.append({
                "guid": note["guid"],
                "fields": tuple(normalize_field_value(field) for field in fields),
            })
        note_records.sort(key=lambda item: item["guid"])

        ord_by_guid = {}
        for card in cards:
            for note in notes:
                if note["id"] == card["nid"]:
                    ord_by_guid.setdefault(note["guid"], set()).add(card["ord"])
                    break
        ord_map = sorted(
            (guid, sorted(ords)) for guid, ords in ord_by_guid.items()
        )

        content_media = {
            name: media[name]["sha256"]
            for name in sorted(content_referenced)
            if name in media
        }

        content_payload = {
            "deckNames": deck_names,
            "fieldNameSets": field_name_sets,
            "notes": note_records,
            "cardOrdByGuid": ord_map,
            "contentMedia": content_media,
        }
        content_fingerprint = hashlib.sha256(
            json.dumps(content_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        # ---- template / variant fingerprint ------------------------------
        template_referenced: set[str] = set()
        template_parts = []
        for model_id, meta in sorted(model_meta.items()):
            qfmt_all = "".join(t["qfmt"] for t in meta["templates"])
            afmt_all = "".join(t["afmt"] for t in meta["templates"])
            template_referenced |= referenced_media(meta["css"], qfmt_all, afmt_all)
            template_parts.append({
                "modelId": model_id,
                "name": meta["name"],
                "fieldNames": meta["fieldNames"],
                "css": meta["css"],
                "templates": meta["templates"],
            })
        template_media = {
            name: media[name]["sha256"]
            for name in sorted(template_referenced)
            if name in media
        }
        template_fingerprint = hashlib.sha256(
            json.dumps({"models": template_parts, "templateMedia": template_media}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    finally:
        connection.close()
        Path(handle.name).unlink(missing_ok=True)

    return {
        "path": path.name,
        "sha256": sha256_hex(path.read_bytes()),
        "sizeBytes": path.stat().st_size,
        "collection": collection_name,
        "cardCount": card_count,
        "noteCount": note_count,
        "deckCount": deck_count,
        "deckNames": deck_names,
        "modelNames": sorted({m["name"] for m in model_meta.values()}),
        "noteGuids": sorted({n["guid"] for n in notes}),
        "fieldValuesByGuid": {n["guid"]: n["fields"] for n in notes},
        "normalizedFieldsByGuid": {
            guid: tuple(normalize_field_value(field) for field in fields)
            for guid, fields in raw_field_values_by_guid.items()
        },
        "contentFingerprint": content_fingerprint,
        "templateFingerprint": template_fingerprint,
        "contentMedia": content_media,
        "templateMedia": template_media,
        "allMedia": sorted(media.keys()),
    }


def first_field_diff(old: dict, v2: dict, guid: str) -> dict:
    old_fields = old["fieldValuesByGuid"].get(guid, ())
    v2_fields = v2["fieldValuesByGuid"].get(guid, ())
    diffs = []
    for index, (left, right) in enumerate(zip(old_fields, v2_fields)):
        if left != right:
            diffs.append({
                "fieldIndex": index,
                "old": left[:120],
                "v2": right[:120],
                "oldNormalized": normalize_field_value(left)[:120],
                "v2Normalized": normalize_field_value(right)[:120],
            })
    return {"guid": guid, "fieldCounts": [len(old_fields), len(v2_fields)], "diffs": diffs[:3]}


def classify_fingerprints(old_content_fp: str, old_template_fp: str, new_content_fp: str, new_template_fp: str) -> str:
    """Pure classification rule on the two independent fingerprints.

    A — same content fingerprint + different template fingerprint → VARIANT
    B — different content fingerprint → NEW CONTENT RELEASE
    Identical both → duplicate artifact. Anything else → AMBIGUOUS (never
    auto-publish)."""
    content_same = old_content_fp == new_content_fp
    template_same = old_template_fp == new_template_fp
    if content_same and not template_same:
        return "VARIANT (same content, different skin/template)"
    if not content_same:
        return "NEW CONTENT RELEASE"
    if content_same and template_same:
        return "IDENTICAL CONTENT + TEMPLATE (duplicate artifact)"
    return "AMBIGUOUS"


def compare_pair(old: dict, v2: dict) -> dict:
    old_guids = set(old["noteGuids"])
    v2_guids = set(v2["noteGuids"])
    shared = sorted(old_guids & v2_guids)
    identical_raw = sum(
        1 for guid in shared
        if old["fieldValuesByGuid"].get(guid) == v2["fieldValuesByGuid"].get(guid)
    )
    identical_normalized = sum(
        1 for guid in shared
        if old["normalizedFieldsByGuid"].get(guid) == v2["normalizedFieldsByGuid"].get(guid)
    )
    content_same = old["contentFingerprint"] == v2["contentFingerprint"]
    template_same = old["templateFingerprint"] == v2["templateFingerprint"]

    sample_diff = None
    for guid in shared:
        if old["normalizedFieldsByGuid"].get(guid) != v2["normalizedFieldsByGuid"].get(guid):
            sample_diff = first_field_diff(old, v2, guid)
            break

    classification = classify_fingerprints(
        old["contentFingerprint"], old["templateFingerprint"],
        v2["contentFingerprint"], v2["templateFingerprint"],
    )

    return {
        "old": {"path": old["path"], "sha256": old["sha256"][:16], "cards": old["cardCount"], "notes": old["noteCount"], "decks": old["deckCount"], "contentFingerprint": old["contentFingerprint"][:16], "templateFingerprint": old["templateFingerprint"][:16]},
        "v2": {"path": v2["path"], "sha256": v2["sha256"][:16], "cards": v2["cardCount"], "notes": v2["noteCount"], "decks": v2["deckCount"], "contentFingerprint": v2["contentFingerprint"][:16], "templateFingerprint": v2["templateFingerprint"][:16]},
        "sharedGuids": len(shared),
        "oldOnlyGuids": len(old_guids - v2_guids),
        "v2OnlyGuids": len(v2_guids - old_guids),
        "sharedGuidsWithIdenticalRawFields": identical_raw,
        "sharedGuidsWithIdenticalNormalizedFields": identical_normalized,
        "deckNamesChanged": sorted(old["deckNames"]) != sorted(v2["deckNames"]),
        "modelNamesOld": old["modelNames"],
        "modelNamesV2": v2["modelNames"],
        "contentSame": content_same,
        "templateSame": template_same,
        "sampleNormalizedDiff": sample_diff,
        "classification": classification,
    }


def main() -> None:
    pairs = [
        ("FaLi_beisong.apkg", "FaLi_beisong-v2.apkg", "lsat-jurisprudence"),
        ("FaZhiShi_beisong.apkg", "FaZhiShi_beisong-v2.apkg", "lsat-legal-history"),
        ("XianFa_beisong_full.apkg", "XianFa_beisong_full-v2.apkg", "lsat-constitutional-law"),
        ("ZH2000_apkg.apkg", "ZH2000_apkg-v2.apkg", "zh2000"),
    ]
    report = {"pairs": []}
    for old_name, v2_name, family in pairs:
        old_path = ROOT / old_name
        v2_path = ROOT / v2_name
        if not old_path.is_file() or not v2_path.is_file():
            print(f"SKIP {old_name} / {v2_name}: file missing", file=sys.stderr)
            continue
        old = inspect_apkg(old_path)
        v2 = inspect_apkg(v2_path)
        comparison = compare_pair(old, v2)
        comparison["family"] = family
        report["pairs"].append(comparison)
        print(json.dumps(comparison, ensure_ascii=False, indent=2))

    out = ROOT / ".miki-audit" / "apkg-pair-audit.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"audit report written to {out}")


if __name__ == "__main__":
    main()
