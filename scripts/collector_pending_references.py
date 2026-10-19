"""監視PCの未確定公式配布参照を非通信で検証・保存・明示copyする（ADR 0322）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
独立受入した根拠pinを必須とし、通信・公開索引・端末導入の許可を発行しない。
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import sys
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit

import collector_registry as cr


SCHEMA = "dc-collector-pending-references-v1"
MAP_SCHEMA = "dc-pending-import-map-v2"
BUNDLE_SCHEMA = "dc-portable-pending-references-v1"
MAX_COPY_LEAVES = 64
MAX_COPY_BYTES = 64 * 1024 * 1024
ROOT_KEYS = {"schema", "importedAt", "baselinePin", "manualSourcePin", "researchOnly",
             "defaultRegistryAdopted", "publishable", "installAuthorized", "products", "evidence", "references"}
PRODUCT_KEYS = {"id", "manufacturer", "model", "formalProductTitle", "evidenceId", "modelFact", "mentionKind"}
EVIDENCE_KEYS = {"id", "pageUrl", "officialBasis", "bodySha256", "effectiveBase", "observedAt", "parserVersion", "pagePin", "routePin"}
REFERENCE_KEYS = {"id", "evidenceId", "driverFact", "rawHref", "resolvedUrl", "priorFactCount", "association", "osEvidence", "architectureEvidence", "checks", "pendingReasons"}
ASSOCIATION_KEYS = {"contextProductIds", "explicitDriverModelProductIds", "pageMentionProductIds", "modelScope"}
CHECK_KEYS = {"driverOnly", "utilitySeparation", "firmwareCoupling", "payload", "signature", "infApplicability", "eula"}
CHECK_REASONS = ("DRIVER_ONLY_NOT_CHECKED", "UTILITY_SEPARATION_NOT_CHECKED",
                 "FIRMWARE_COUPLING_NOT_CHECKED", "PAYLOAD_NOT_CHECKED", "SIGNATURE_NOT_CHECKED",
                 "INF_APPLICABILITY_NOT_CHECKED", "EULA_NOT_CHECKED")
PRIVATE_EXTRA = re.compile(r"(?i)(?:\b(?:serial(?:number)?|serial_number|token|cookie|secret|api_key)\s*[:=]|\b(?:PCI|USB|ACPI|HID)[\\#]|\b(?:VID|PID|VEN|DEV)_[0-9a-f]{4})")


@dataclass(frozen=True)
class PendingSummary:
    """許可やURLを含まない保存件数を別々の軸で返す。"""

    products: int
    savedReferences: int
    uniqueUrls: int
    contexts: int
    pendingReasons: dict[str, int]


def _text(value: object, maximum: int = 4096) -> str:
    """正確な公開factを改変せず、秘密・端末path・制御文字を拒否する。"""
    cr.require(type(value) is str and 0 < len(value) <= maximum, "PUBLIC_TEXT")
    cr.require(all(not unicodedata.category(char).startswith("C") for char in value), "TEXT_CONTROL")
    decoded = value
    for _ in range(3):
        cr.require(not cr.PRIVATE_TEXT.search(decoded) and not PRIVATE_EXTRA.search(decoded), "PRIVATE_TEXT")
        decoded = unquote(decoded)
    return value


def _privacy(value: object) -> None:
    """実文字列とserialized表現を別に検査する。"""
    if isinstance(value, str):
        if value:
            _text(value, max(8192, len(value)))
    elif isinstance(value, dict):
        for key, item in value.items():
            _privacy(key)
            _privacy(item)
    elif isinstance(value, list):
        for item in value:
            _privacy(item)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
    cr.require(not cr.PRIVATE_TEXT.search(encoded) and not PRIVATE_EXTRA.search(encoded), "SERIALIZED_PRIVATE_TEXT")


def _url(value: object) -> str:
    """既存の非通信HTTPS規則を維持し、予約名とencoded秘密も拒否する。"""
    _text(value, 8192)
    cr.public_url(value, allow_public_query=True)
    host = urlsplit(value).hostname
    cr.require(not host.endswith((".invalid", ".test", ".example", ".onion", ".home.arpa")), "RESERVED_HOST")
    decoded = value
    for _ in range(3):
        decoded = unquote(decoded)
        _text(decoded, 8192)
    return value


def _leaf(value: object) -> str:
    """相対の明示leafだけを認め、Windowsで曖昧・無効・予約された名前を拒否する。"""
    _text(value, 256)
    parts = value.split("/")
    cr.require(not PurePosixPath(value).is_absolute() and "\\" not in value and ":" not in value
               and all(part not in {"", ".", ".."} for part in parts), "LEAF_PATH")
    # 全segmentをcopy前に検査し、Windowsの正規化・device名解釈による別名を作らせない。
    for part in parts:
        cr.require(not part.endswith((" ", ".")) and not any(char in '<>:"\\|?*' for char in part), "LEAF_PATH")
        basename = part.split(".", 1)[0].rstrip(" ")
        cr.require(re.fullmatch(r"(?i)(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])", basename) is None, "LEAF_PATH")
    return value


def _pin(value: object) -> dict:
    """pinの厳密な型と小文字digestを検査する。"""
    cr.fields(value, {"leaf", "bytes", "sha256"}, "PIN_FIELDS")
    _leaf(value["leaf"])
    cr.require(type(value["bytes"]) is int and 0 <= value["bytes"] <= cr.MAX_JSON_BYTES, "PIN_BYTES")
    cr.sha256(value["sha256"])
    cr.require(value["sha256"] is not None, "PIN_HASH")
    return value


def _time(value: object) -> None:
    """元観測のISO offsetと小数秒を維持して日時を検査する。"""
    _text(value, 64)
    cr.require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value) is not None, "OBSERVED_TIME")
    try:
        cr.require(datetime.fromisoformat(value).tzinfo is not None, "OBSERVED_TIME")
    except ValueError as error:
        raise cr.RegistryError("OBSERVED_TIME") from error


def _fact(value: object, page: dict | None = None) -> dict | None:
    """同bodyのfact indexと正確な公開文字列へ結合する。"""
    if value is None:
        return None
    cr.fields(value, {"index", "text"}, "FACT_FIELDS")
    cr.require(type(value["index"]) is int and value["index"] >= 0, "FACT_INDEX")
    _text(value["text"])
    if page is not None:
        facts = page["publicFacts"]
        cr.require(value["index"] < len(facts) and facts[value["index"]] == value["text"], "FACT_BODY_BINDING")
    return value


def _same(left: object, right: object, code: str) -> None:
    """boolと整数を同一視せず、元入力とのJSON型付き一致を要求する。"""
    cr.require(cr.json_bytes(left) == cr.json_bytes(right), code)


def _raw(path: Path) -> bytes:
    """全parentとleafを検査し、有限読込み中の変更を拒否する。"""
    cr.check_ancestors(path)
    cr.regular_path(path)
    before = path.stat()
    with path.open("rb") as stream:
        raw = stream.read(cr.MAX_JSON_BYTES + 1)
    cr.regular_path(path)
    after = path.stat()
    cr.require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), "INPUT_CHANGED")
    cr.require(len(raw) <= cr.MAX_JSON_BYTES, "JSON_SIZE")
    return raw


def _trusted(root: Path, trust: dict) -> tuple[dict, dict, dict, dict[str, dict], dict[str, bytes]]:
    """独立受入した全leafのbyteを検査後にのみ根拠を解析する。"""
    root = Path(root)
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    cr.require(type(trust) is dict and 3 <= len(trust) < MAX_COPY_LEAVES, "TRUST_INPUT")
    aliases = {}
    # 全名前を先に検査し、leaf・directoryのcase差やfile/directory競合を排他出力前に拒否する。
    for leaf in trust:
        _leaf(leaf)
        parts = leaf.split("/")
        cr.require(parts[0].casefold() not in {"pending-references.json", "manifest.json", "ledger.json"}, "TRUST_RESERVED_LEAF")
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            entry = (prefix, count == len(parts))
            folded = prefix.casefold()
            cr.require(folded not in aliases or aliases[folded] == entry, "TRUST_PATH_ALIAS")
            aliases[folded] = entry
    content = {}
    total = 0
    for leaf, expected in trust.items():
        cr.fields(expected, {"bytes", "sha256"}, "TRUST_PIN_FIELDS")
        _pin({"leaf": leaf, **expected})
        raw = _raw(root / leaf)
        _same({"bytes": len(raw), "sha256": cr.digest(raw)}, expected, "TRUST_BYTE_MISMATCH")
        content[leaf] = raw
        total += len(raw)
    cr.require(total <= MAX_COPY_BYTES, "BUNDLE_SIZE")
    values = {leaf: cr.parse_json(raw) for leaf, raw in content.items()}
    cr.require({"baseline-registry.json", "manual-review-source.json", "approved-import-map.json"} <= set(values), "TRUST_CORE_MISSING")
    baseline = values["baseline-registry.json"]
    review = values["manual-review-source.json"]
    mapping = values["approved-import-map.json"]
    cr.validate_registry(baseline)
    cr.fields(mapping, {"schema", "baselinePin", "sourceManualPin", "productRowIndices", "evidence", "references"}, "MAP_FIELDS")
    cr.require(mapping["schema"] == MAP_SCHEMA, "MAP_SCHEMA")
    for key, leaf in (("baselinePin", "baseline-registry.json"), ("sourceManualPin", "manual-review-source.json")):
        _pin(mapping[key])
        _same(mapping[key], {"leaf": leaf, **trust[leaf]}, "MAP_SOURCE_PIN")
    leaves = {"baseline-registry.json", "manual-review-source.json", "approved-import-map.json"}
    cr.require(type(mapping["evidence"]) is list, "MAP_EVIDENCE")
    for entry in mapping["evidence"]:
        cr.fields(entry, {"id", "pagePin", "routePin", "officialBasis", "parserVersion"}, "MAP_EVIDENCE_FIELDS")
        for key in ("pagePin", "routePin"):
            if entry[key] is not None:
                pointer = _pin(entry[key])
                leaf = pointer["leaf"]
                cr.require(leaf in trust, "MAP_UNKNOWN_LEAF")
                _same(pointer, {"leaf": leaf, **trust[leaf]}, "MAP_EVIDENCE_PIN")
                leaves.add(leaf)
    cr.require(set(trust) == leaves, "TRUST_UNKNOWN_LEAF")
    return baseline, review, mapping, values, content


def _scope(value: object, fact: dict | None, architecture: bool = False) -> dict:
    """approved scopeを同driver factへ限定し、型付きscopeの矛盾を拒否する。"""
    if value is None:
        return {"status": "UNKNOWN", "value": None, "fact": None}
    _text(value, 1024)
    cr.require(fact is not None, "SCOPE_FACT_MISSING")
    text = fact["text"]
    if architecture:
        cr.require(value in {"x64", "x86", "ARM64"}, "ARCHITECTURE_VALUE")
        patterns = {"x64": r"(?i)(?:\bx64\b|\b64[- ]bit\b|\bamd64\b)",
                    "x86": r"(?i)(?:\bx86\b|\b32[- ]bit\b)", "ARM64": r"(?i)\barm64\b"}
        cr.require(re.search(patterns[value], text) is not None, "ARCHITECTURE_FACT")
        cr.require(not any(re.search(pattern, text) for other, pattern in patterns.items() if other != value), "ARCHITECTURE_CONTRADICTION")
    else:
        typed = re.fullmatch(r"WINDOWS_(\d+)", value)
        if typed is not None:
            numbers = re.findall(r"(?i)\bWindows\s+(\d+)\b", text)
            cr.require(numbers == [typed.group(1)], "OS_FACT_CONTRADICTION")
        else:
            cr.require(value.casefold() in text.casefold(), "OS_FACT_LITERAL")
    return {"status": "EXPLICIT", "value": value, "fact": fact}


def _build(baseline: dict, review: dict, mapping: dict, values: dict, imported_at: str) -> dict:
    """信頼済み元情報からのみ正確なpendingを構築し、全許可をfalseへ固定する。"""
    _time(imported_at)
    cr.require(review["researchOnly"] is True and all(review[key] is False for key in ("defaultRegistryAdopted", "publishable", "installAuthorized")), "REVIEW_SAFETY")
    cr.require(type(mapping["productRowIndices"]) is list, "MAP_PRODUCT_ROWS")
    cr.require(all(type(index) is int and 0 <= index < len(review["rows"]) for index in mapping["productRowIndices"]), "MAP_PRODUCT_INDEX")
    cr.require(len(set(mapping["productRowIndices"])) == len(mapping["productRowIndices"]), "MAP_PRODUCT_DUPLICATE")
    evidence = []
    nodes = {}
    for entry in mapping["evidence"]:
        node = cr.identity(entry["id"])
        cr.require(node not in nodes, "EVIDENCE_DUPLICATE")
        page = values[entry["pagePin"]["leaf"]] if entry["pagePin"] is not None else None
        route = values[entry["routePin"]["leaf"]] if entry["routePin"] is not None else None
        official = entry["officialBasis"]
        if official is not None:
            cr.fields(official, {"kind", "reviewPin"}, "OFFICIAL_BASIS_FIELDS")
            cr.require(official["kind"] == "MANUAL_OFFICIAL_PAGE_REVIEW", "OFFICIAL_BASIS_KIND")
            _same(official["reviewPin"], mapping["sourceManualPin"], "OFFICIAL_BASIS_BINDING")
        page_url = page["receipt"]["url"] if page is not None else None
        body = page["receipt"]["bodySha256"] if page is not None else None
        observed = page["receipt"]["checkedAt"] if page is not None else None
        base = route["effectiveBase"] if route is not None else None
        for value in (page_url, base):
            if value is not None:
                _url(value)
        if observed is not None:
            _time(observed)
        cr.sha256(body)
        if page is not None and route is not None:
            cr.require(body == route["bodySha256"] and page_url == route["documentUrl"], "PAGE_ROUTE_BODY")
        if entry["parserVersion"] is not None:
            cr.label(entry["parserVersion"])
        result = dict(id=node, pageUrl=page_url, officialBasis=official, bodySha256=body,
                      effectiveBase=base, observedAt=observed, parserVersion=entry["parserVersion"],
                      pagePin=entry["pagePin"], routePin=entry["routePin"])
        evidence.append(result)
        nodes[node] = (result, page, route)
    products = []
    product_ids = set()
    for index in mapping["productRowIndices"]:
        row = review["rows"][index]
        manufacturer = cr.label(row["manufacturer"])
        model = cr.label(row["model"])
        matches = [product for product in baseline["products"] if (product["manufacturer"], product["model"]) == (manufacturer, model)]
        cr.require(len(matches) == 1, "BASELINE_PRODUCT_MATCH")
        product_id = cr.identity(matches[0]["id"])
        cr.require(product_id not in product_ids, "PRODUCT_DUPLICATE")
        product_ids.add(product_id)
        cr.require(row["recordIds"] == [] and row["conditions"]["scopeReviewPromoted"] is False, "PENDING_PRODUCT_STATE")
        node = row["productNode"]
        cr.require(node in nodes, "PRODUCT_EVIDENCE_UNKNOWN")
        ev, page, _ = nodes[node]
        proof = row["proof"]
        for source, target in (("bodySha256", "bodySha256"), ("observedAt", "observedAt"), ("evidenceUrl", "pageUrl"), ("effectiveBase", "effectiveBase")):
            _same(proof[source], ev[target], "PRODUCT_PROOF_BINDING")
        model_fact = _fact(proof["modelFact"], page)
        cr.require(type(proof["modelIsNavigationListEntry"]) is bool, "PRODUCT_MENTION_TYPE")
        title = cr.label(row["formalProductTitle"])
        if model_fact is not None:
            cr.require(title == model_fact["text"], "PRODUCT_TITLE_FACT")
        products.append(dict(id=product_id, manufacturer=manufacturer, model=model, formalProductTitle=title,
                             evidenceId=node, modelFact=model_fact, mentionKind="NAVIGATION_NAME" if proof["modelIsNavigationListEntry"] else "OFFICIAL_PRODUCT_TITLE"))
    references = []
    ref_ids = set()
    indices = set()
    cr.require(type(mapping["references"]) is list, "MAP_REFERENCES")
    for entry in mapping["references"]:
        cr.fields(entry, {"referenceIndex", "referenceId", "contextProductIds", "explicitDriverModelProductIds", "modelScope", "osValue", "architectureValue"}, "MAP_REFERENCE_FIELDS")
        index = entry["referenceIndex"]
        cr.require(type(index) is int and 0 <= index < len(review["unadoptedDistributionReferences"]) and index not in indices, "REFERENCE_INDEX")
        indices.add(index)
        ref_id = cr.identity(entry["referenceId"])
        cr.require(ref_id not in ref_ids, "REFERENCE_DUPLICATE")
        ref_ids.add(ref_id)
        source = review["unadoptedDistributionReferences"][index]
        cr.require(all(source[key] is False for key in ("adoptedAsRecord", "contentsChecked", "signatureChecked", "installAuthorized")), "REFERENCE_SAFETY")
        node = source["node"]
        cr.require(node in nodes, "REFERENCE_EVIDENCE_UNKNOWN")
        ev, page, route = nodes[node]
        _same(source["bodySha256"], ev["bodySha256"], "REFERENCE_BODY")
        _same(source["effectiveBase"], ev["effectiveBase"], "REFERENCE_BASE")
        fact = _fact(source["driverFact"], page)
        literal = source["literal"]
        raw_href = literal["rawHref"] if literal is not None else None
        resolved = literal["resolvedHref"] if literal is not None else None
        prior = literal["priorFactCount"] if literal is not None else None
        if raw_href is not None:
            _text(raw_href, 8192)
            cr.require("\\" not in raw_href and not any(char.isspace() for char in raw_href), "RAW_HREF")
            parts = urlsplit(raw_href)
            cr.require(parts.scheme in {"", "https"}, "RAW_SCHEME")
            # 欠測によってresolvedUrlをnullにしても、元literalのprivate宛先を保存させない。
            if parts.scheme == "https":
                _url(raw_href)
            elif parts.netloc:
                _url("https:" + raw_href)
            elif ev["effectiveBase"] is not None:
                _url(urljoin(ev["effectiveBase"], raw_href))
        if prior is not None:
            cr.require(type(prior) is int and prior >= 0, "PRIOR_FACT_COUNT")
        complete = all(value is not None for value in (ev["officialBasis"], ev["pagePin"], ev["routePin"], ev["bodySha256"], ev["effectiveBase"], ev["pageUrl"], ev["observedAt"], fact, raw_href, resolved, prior))
        if route is not None and literal is not None:
            _same(source["routeFile"], ev["routePin"]["leaf"], "REFERENCE_ROUTE_LEAF")
            cr.require(literal in route["rows"], "REFERENCE_LITERAL_BINDING")
        if complete:
            _url(resolved)
            _same(urljoin(ev["effectiveBase"], raw_href), resolved, "REFERENCE_RESOLUTION")
        else:
            resolved = None
        contexts = cr.id_list(entry["contextProductIds"])
        cr.require(all(key in product_ids for key in contexts), "CONTEXT_UNKNOWN")
        mentions = [product["id"] for product in products if product["evidenceId"] == node]
        cr.require(all(key in mentions for key in contexts), "CONTEXT_OTHER_MODEL_PAGE")
        cr.require(entry["explicitDriverModelProductIds"] == [] and entry["modelScope"] == "UNKNOWN", "MODEL_SCOPE")
        os_evidence = _scope(entry["osValue"], fact)
        arch_evidence = _scope(entry["architectureValue"], fact, architecture=True)
        reasons = ["MODEL_SCOPE_UNKNOWN", *CHECK_REASONS]
        if os_evidence["status"] == "UNKNOWN":
            reasons.append("OS_SCOPE_UNKNOWN")
        elif re.search(r"(?i)(?:WINDOWS_|Windows\s+)(?:7|8(?:\.1)?|XP|VISTA)\b", entry["osValue"]):
            reasons.append("LEGACY_OS_ONLY")
        if arch_evidence["status"] == "UNKNOWN":
            reasons.append("ARCHITECTURE_UNKNOWN")
        if not complete:
            reasons.append("EVIDENCE_INCOMPLETE")
        references.append(dict(id=ref_id, evidenceId=node, driverFact=fact, rawHref=raw_href,
                               resolvedUrl=resolved, priorFactCount=prior,
                               association=dict(contextProductIds=contexts, explicitDriverModelProductIds=[], pageMentionProductIds=mentions, modelScope="UNKNOWN"),
                               osEvidence=os_evidence, architectureEvidence=arch_evidence,
                               checks={key: "NOT_CHECKED" for key in sorted(CHECK_KEYS)}, pendingReasons=reasons))
    result = dict(schema=SCHEMA, importedAt=imported_at, baselinePin=mapping["baselinePin"],
                  manualSourcePin=mapping["sourceManualPin"], researchOnly=True, defaultRegistryAdopted=False,
                  publishable=False, installAuthorized=False, products=products, evidence=evidence, references=references)
    _privacy(result)
    cr.require(len(cr.json_bytes(result)) <= cr.MAX_JSON_BYTES, "JSON_SIZE")
    return result


def import_reviewed_references(review: dict, import_map: dict, evidence_root: Path, expected_trust: dict) -> dict:
    """独立受入済み原入力に一致する手動調査だけをpendingとして構築する。"""
    baseline, trusted_review, trusted_map, values, _ = _trusted(evidence_root, expected_trust)
    _same(review, trusted_review, "REVIEW_INPUT_MISMATCH")
    _same(import_map, trusted_map, "MAP_INPUT_MISMATCH")
    return _build(baseline, trusted_review, trusted_map, values, datetime.now(timezone.utc).isoformat())


def validate_pending_ledger(value: dict, evidence_root: Path, expected_trust: dict) -> PendingSummary:
    """strict schemaと全原根拠を検査し、独立した件数だけを返す。"""
    cr.fields(value, ROOT_KEYS, "PENDING_ROOT_FIELDS")
    cr.require(value["schema"] == SCHEMA, "PENDING_SCHEMA")
    cr.require(value["researchOnly"] is True and all(value[key] is False for key in ("defaultRegistryAdopted", "publishable", "installAuthorized")), "PENDING_SAFETY")
    _privacy(value)
    for name, fields in (("products", PRODUCT_KEYS), ("evidence", EVIDENCE_KEYS), ("references", REFERENCE_KEYS)):
        cr.require(type(value[name]) is list, "PENDING_ARRAY")
        for entry in value[name]:
            cr.fields(entry, fields, "PENDING_NESTED_FIELDS")
    baseline, review, mapping, values, _ = _trusted(evidence_root, expected_trust)
    expected = _build(baseline, review, mapping, values, value["importedAt"])
    # 順序を含む型付き完全一致によりnested未知field・型違い・自己申告scopeを拒否する。
    _same(value, expected, "PENDING_EVIDENCE_MISMATCH")
    reasons = Counter(reason for reference in value["references"] for reason in reference["pendingReasons"])
    urls = {reference["resolvedUrl"] for reference in value["references"] if reference["resolvedUrl"] is not None}
    contexts = {reference["evidenceId"] for reference in value["references"]}
    return PendingSummary(len(value["products"]), len(value["references"]), len(urls), len(contexts), dict(sorted(reasons.items())))


def read_pending_ledger(path: Path, evidence_root: Path, expected_trust: dict) -> PendingSummary:
    """台帳読込みでも全parent検査と独立した信頼入力を必須にする。"""
    return validate_pending_ledger(cr.parse_json(_raw(Path(path))), evidence_root, expected_trust)


def copy_pending_bundle(ledger: dict, evidence_root: Path, destination: Path, expected_trust: dict) -> PendingSummary:
    """検査済み明示leafを新規出力へ排他copyし、最後だけ完成manifestを置く。"""
    summary = validate_pending_ledger(ledger, evidence_root, expected_trust)
    _, _, _, _, content = _trusted(evidence_root, expected_trust)
    content["pending-references.json"] = cr.json_bytes(ledger)
    cr.require(len(content) + 1 <= MAX_COPY_LEAVES, "COPY_BUDGET")
    destination = Path(destination)
    cr.check_ancestors(destination)
    cr.require(not destination.exists() and not destination.is_symlink(), "OUTPUT_EXISTS")
    manifest = {"schema": BUNDLE_SCHEMA, "ledgerLeaf": "pending-references.json",
                "files": {leaf: {"bytes": len(raw), "sha256": cr.digest(raw)} for leaf, raw in content.items()},
                "researchOnly": True, "publishable": False, "installAuthorized": False}
    manifest_raw = cr.json_bytes(manifest)
    cr.require(sum(map(len, content.values())) + len(manifest_raw) <= MAX_COPY_BYTES, "COPY_BUDGET")
    # partial失敗は既に生成したbyteを保持し、完成manifestを発行しない。
    destination.mkdir(parents=True, exist_ok=False)
    for leaf, raw in content.items():
        target = destination / _leaf(leaf)
        target.parent.mkdir(parents=True, exist_ok=True)
        cr.check_ancestors(target)
        with target.open("xb") as stream:
            stream.write(raw)
        cr.require(_raw(target) == raw, "COPY_BYTE_MISMATCH")
    cr.check_ancestors(destination / "manifest.json")
    with (destination / "manifest.json").open("xb") as stream:
        stream.write(manifest_raw)
    return summary


def verify_pending_bundle(root: Path, expected_trust: dict) -> PendingSummary:
    """manifest本人のhashだけを信用せず、外側trustと全byteを再照合する。"""
    root = Path(root)
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    manifest_raw = _raw(root / "manifest.json")
    manifest = cr.parse_json(manifest_raw)
    cr.fields(manifest, {"schema", "ledgerLeaf", "files", "researchOnly", "publishable", "installAuthorized"}, "BUNDLE_FIELDS")
    cr.require(manifest["schema"] == BUNDLE_SCHEMA and manifest["ledgerLeaf"] == "pending-references.json", "BUNDLE_SCHEMA")
    cr.require(manifest["researchOnly"] is True and manifest["publishable"] is False and manifest["installAuthorized"] is False, "BUNDLE_SAFETY")
    cr.require(type(manifest["files"]) is dict and set(manifest["files"]) == set(expected_trust) | {"pending-references.json"}, "BUNDLE_LEAF_SET")
    # 宣言済みparentのみを走査し、bundleに無関係なfileやdirectoryを持ち込ませない。
    paths = {PurePosixPath(_leaf(leaf)) for leaf in manifest["files"]} | {PurePosixPath("manifest.json")}
    parents = {PurePosixPath(".")}
    for path in paths:
        parents.update(path.parents)
    for parent in parents:
        directory = root / parent
        cr.check_ancestors(directory)
        cr.regular_path(directory, directory=True)
        allowed = {path.name for path in paths | parents if path.parent == parent and path != parent}
        cr.require({path.name for path in directory.iterdir()} == allowed, "BUNDLE_UNKNOWN_LEAF")
    total = 0
    for leaf, expected in manifest["files"].items():
        _pin({"leaf": leaf, **cr.fields(expected, {"bytes", "sha256"}, "BUNDLE_PIN_FIELDS")})
        raw = _raw(root / leaf)
        total += len(raw)
        _same({"bytes": len(raw), "sha256": cr.digest(raw)}, expected, "BUNDLE_BYTE_MISMATCH")
        if leaf in expected_trust:
            _same(expected, expected_trust[leaf], "BUNDLE_TRUST_MISMATCH")
    cr.require(len(manifest["files"]) + 1 <= MAX_COPY_LEAVES and total + len(manifest_raw) <= MAX_COPY_BYTES, "COPY_BUDGET")
    return read_pending_ledger(root / "pending-references.json", root, expected_trust)


def main() -> int:
    """非通信validate／import／copyだけを公開し、入力値を診断へ出さない。

    importの排他的ledger保存に失敗しても、作成済みfileは自動削除しない。残った既存出力は上書きせず拒否する。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("validate", "import", "copy"))
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        trust = cr.parse_json(_raw(args.trust))
        if args.operation == "import":
            cr.require(args.output is not None, "OUTPUT_REQUIRED")
            _, review, mapping, _, _ = _trusted(args.evidence_root, trust)
            ledger = import_reviewed_references(review, mapping, args.evidence_root, trust)
            summary = validate_pending_ledger(ledger, args.evidence_root, trust)
            cr.check_ancestors(args.output)
            with args.output.open("xb") as stream:
                stream.write(cr.json_bytes(ledger))
        else:
            cr.require(args.ledger is not None, "LEDGER_REQUIRED")
            ledger = cr.parse_json(_raw(args.ledger))
            if args.operation == "copy":
                cr.require(args.output is not None, "OUTPUT_REQUIRED")
                summary = copy_pending_bundle(ledger, args.evidence_root, args.output, trust)
            else:
                summary = validate_pending_ledger(ledger, args.evidence_root, trust)
        print(json.dumps(asdict(summary), ensure_ascii=False, sort_keys=True))
        return 0
    except (cr.RegistryError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error) if isinstance(error, cr.RegistryError) else "LOCAL_INPUT_REJECTED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
