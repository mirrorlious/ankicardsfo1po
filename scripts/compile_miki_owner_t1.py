#!/usr/bin/env python3
"""Compile redacted owner T1 interaction plans from APKG template source."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

import publish_miki_owner_pack as publisher

POLICY_VERSION = 1
PROFILE = "choice-judge-v1"
ANSWER_FIELD_CANDIDATES = ("正确答案", "标准答案", "参考答案", "正确选项", "答案", "Answer", "answer", "CorrectAnswer", "correctAnswer", "correct_answer")
VALUE_ATTR_CANDIDATES = ("data-letter", "data-value", "data-answer", "data-option", "data-choice", "data-key")
SIMPLE_SELECTOR_RE = re.compile(r"^(?:[.#][A-Za-z_][\w-]*|\[data-[A-Za-z0-9_-]+\])$")
CLASS_TOKEN_RE = re.compile(r"^[A-Za-z_][\w-]{0,63}$")


def _read_templates(source: Path) -> list[dict]:
    with zipfile.ZipFile(source, "r") as zf:
        publisher.validate_archive(zf)
        _name, collection_bytes = publisher.read_collection(zf)
    connection, temp_path = publisher.open_collection(collection_bytes)
    try:
        models = publisher.parse_models(connection)
        return [
            {"modelId": str(model_id), "model": model, "template": template, "cardOrd": int(template.get("ord", ordinal) or 0)}
            for model_id, model in sorted(models.items(), key=lambda item: str(item[0])) if isinstance(model, dict)
            for ordinal, template in enumerate(model.get("tmpls", []) or []) if isinstance(template, dict)
        ]
    finally:
        connection.close()
        temp_path.unlink(missing_ok=True)


def _selectors(js: str) -> list[str]:
    values = []
    for match in re.finditer(r"\bquerySelector(?:All)?\s*\(\s*([\"'])(.{1,128}?)\1\s*\)", js):
        value = match.group(2).strip()
        if SIMPLE_SELECTOR_RE.fullmatch(value) and value not in values:
            values.append(value)
    return values[:16]


def _classes(js: str, css: str) -> list[str]:
    values = []
    for text, pattern in (
        (js, r"classList\s*\.\s*(?:add|remove|toggle|contains)\s*\(\s*([\"'])([A-Za-z_][\w-]{0,63})\1"),
        (css, r"\.([A-Za-z_][\w-]{0,63})\s*(?:[,>{:#.]|\{)"),
    ):
        for match in re.finditer(pattern, text):
            token = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
            if CLASS_TOKEN_RE.fullmatch(token) and token not in values:
                values.append(token)
    return values[:32]


def _pick_class(values: list[str], hints: tuple[str, ...]) -> str:
    for value in values:
        lowered = value.lower()
        if lowered in hints or any(hint in lowered for hint in hints):
            return value
    return ""


def _answer_field(fields: list[str]) -> str:
    for candidate in ANSWER_FIELD_CANDIDATES:
        if candidate in fields:
            return candidate
    return next((name for name in fields if ("正确答案" in name or "正确选项" in name or name.lower().replace("_", "") in {"answer", "correctanswer"}) and "解析" not in name), "")


def _value_attr(js: str, html: str) -> str:
    for attr in VALUE_ATTR_CANDIDATES:
        if re.search(rf"\b{re.escape(attr)}\s*=", html, re.I):
            return attr
    for match in re.finditer(r"\.dataset\.([A-Za-z_][\w]*)", js):
        raw = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", match.group(1)).lower()
        attr = f"data-{raw}"
        if attr in VALUE_ATTR_CANDIDATES:
            return attr
    return ""


def _option_selector(selectors: list[str], html: str, value_attr: str) -> str:
    ranked = sorted(((sum(token in selector.lower() for token in ("option", "choice", "answer", "letter", "data-")), selector) for selector in selectors), key=lambda item: (-item[0], len(item[1])))
    if ranked and ranked[0][0] > 0:
        return ranked[0][1]
    for class_name in ("option", "choice", "answer-option", "zh-option", "anki-option"):
        if re.search(rf"class\s*=\s*([\"'])[^\"']*\b{re.escape(class_name)}\b", html, re.I):
            return f".{class_name}"
    return f"[{value_attr}]" if value_attr else ""


def compile_plan(model: dict, template: dict, report_item: dict) -> tuple[dict | None, dict]:
    qfmt, afmt, css = str(template.get("qfmt", "")), str(template.get("afmt", "")), str(model.get("css", ""))
    html = f"{qfmt}\n{afmt}"
    js = "\n".join(publisher.extract_executables(qfmt) + publisher.extract_executables(afmt))
    fields = [str(item.get("name", "")) for item in model.get("flds", []) if isinstance(item, dict)]
    selectors, classes = _selectors(js), _classes(js, css)
    value_attr, answer_field = _value_attr(js, html), _answer_field(fields)
    option_selector = _option_selector(selectors, html, value_attr)
    correct_class = _pick_class(classes, ("correct", "right", "success"))
    wrong_class = _pick_class(classes, ("wrong", "incorrect", "error"))
    selected_class = _pick_class(classes, ("selected", "active", "chosen", "checked"))
    locked_class = _pick_class(classes, ("locked", "disabled"))
    diagnostics = {"selectorHints": selectors, "classHints": classes, "answerFieldHint": answer_field, "valueAttributeHint": value_attr}
    if report_item.get("interactionCandidate") != "t1-candidate" or report_item.get("blockers"):
        return None, diagnostics
    if not all((answer_field, option_selector, value_attr, correct_class, wrong_class)):
        return None, diagnostics
    plan = {
        "policyVersion": POLICY_VERSION,
        "profile": PROFILE,
        "optionSelector": option_selector,
        "optionValueAttribute": value_attr,
        "answerField": answer_field,
        "selectedClass": selected_class,
        "correctClass": correct_class,
        "wrongClass": wrong_class,
        "lockedClass": locked_class,
        "resetSelector": next((selector for selector in selectors if "reset" in selector.lower()), ""),
        "lockAfterSelection": bool(locked_class or re.search(r"\blocked\b|pointerEvents\s*=\s*[\"']none", js, re.I)),
        "showCorrectOnWrong": True,
    }
    canonical = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    plan["planHash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return plan, diagnostics


def compile_report(source: Path, report_path: Path) -> int:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    by_key = {(str(item.get("modelId", "")), int(item.get("cardOrd", 0))): item for item in report.get("templates", [])}
    approved = 0
    for source_item in _read_templates(source):
        item = by_key.get((source_item["modelId"], source_item["cardOrd"]))
        if not item:
            continue
        plan, diagnostics = compile_plan(source_item["model"], source_item["template"], item)
        item.update({
            "safeInteractionPolicyVersion": POLICY_VERSION,
            "safeInteractionApproved": bool(plan),
            "safeInteractionMode": PROFILE if plan else "none",
            "safeInteractionPlan": plan,
            "safeInteractionDiagnostics": diagnostics,
            "executionApproved": False,
        })
        approved += int(bool(plan))
    report.setdefault("summary", {})["safeInteractionApprovedCount"] = approved
    report["safeInteractionPolicyVersion"] = POLICY_VERSION
    report["rawJavascriptExecutionApproved"] = False
    publisher.dump_json(report_path, report)
    return approved


def main() -> None:
    state = json.loads(publisher.STATE_PATH.read_text(encoding="utf-8"))
    total = 0
    for item in state.get("packs", []):
        approved = compile_report(publisher.ROOT / item["source"], publisher.ROOT / item["templateReportPath"])
        total += approved
        print(f"{item['packId']}: safe-interaction-approved={approved}")
    print(f"Owner T1 compiler approved {total} template(s); raw JavaScript execution remains disabled.")


if __name__ == "__main__":
    main()
