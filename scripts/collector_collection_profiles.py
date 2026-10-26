"""収集profileの参照検証・保守・非通信計画（ADR 0395）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
標準libraryだけを使い、通信・process起動・保護state・署名・導入を扱わない。
planのjobは実行許可でも検査成功証拠でもなく、後続nativeが再検証する入力である。
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import collector_public_locators as pl
import collector_registry as cr


SCHEMA = "dc-collector-collection-profiles-v2"
PLAN_SCHEMA = "dc-collector-collection-plan-v1"
EDIT_SCHEMA = "dc-collector-collection-profile-edits-v2"
JOB_SCHEMA = "dc-collector-registry-job-v2"
STATIC_FORMAT = "STATIC_HTML_ANCHOR_V1"
MAX_PROFILES = 100_000  # 一回の検証予算であり、総対応上限ではない。
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
MAX_BATCH = 32
PROFILE_FIELDS = {"id", "revision", "sourceId", "recordId", "pageLocatorId", "payloadLocatorId",
                  "sourceFormat", "href", "container", "maximumBytes", "infSelection", "review"}
BOUND_FIELDS = PROFILE_FIELDS | {"referenceSha256", "reviewState"}
REVIEW_STATES = {
    "official": {"CONFIRMED", "UNKNOWN"},
    "preDownload": {"NO_EXTRA_PROMPT", "CONSENT_REQUIRED", "UNKNOWN"},
    "terms": {"NO_ADDITIONAL_TERMS", "ACCEPTANCE_REQUIRED", "UNKNOWN"},
    "prerequisites": {"NONE_REQUIRED", "REQUIRED", "UNKNOWN"},
}


def page_content_sha256(raw: bytes) -> str:
    """原byteを保持し、ADR0399の厳密末尾診断一件だけを除外した比較値を返す。

    手動保守用の純粋関数であり、実HTTP proofや公式性・同意を発行しない。
    対応外の書式/HTMLは全rawをhashし、汎用のHTML正規化は行わない。
    """
    cr.require(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024, "PAGE_CONTENT_SIZE")
    marker = b"<!-- WP Fastest Cache file was created in "
    start = raw.find(marker)
    if start < 0 or raw.find(marker, start + 1) >= 0:
        return cr.digest(raw)
    value = raw[start + len(marker):]
    if re.fullmatch(rb"0\.[0-9]{14} seconds, on [0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} -->", value) is None:
        return cr.digest(raw)
    stamp = value[29:46]
    try:
        datetime(2000 + int(stamp[6:8]), int(stamp[3:5]), int(stamp[0:2]),
                 int(stamp[9:11]), int(stamp[12:14]), int(stamp[15:17]))
    except ValueError:
        return cr.digest(raw)
    prefix = raw[:start]
    if not prefix.endswith(b"</body>\n</html>") or b"\0" in prefix:
        return cr.digest(raw)
    lower = prefix.lower()  # 走査用だけであり、hash対象の原byteを変更しない。
    offset = count = 0
    terminal = False
    # Nativeと同じ有限tag/comment/引用符/非表示要素走査を使う。
    while (offset := lower.find(b"<", offset)) >= 0:
        count += 1
        if count > 8192:
            return cr.digest(raw)
        if lower.startswith(b"<!--", offset):
            end = lower.find(b"-->", offset + 4)
            if end < 0:
                return cr.digest(raw)
            offset = end + 3
            continue
        end, quote = offset + 1, None
        while end < len(lower) and end - offset <= 4096:
            char = lower[end]
            if quote is not None and char == quote:
                quote = None
            elif quote is None and char in (34, 39):
                quote = char
            elif quote is None and char == 62:
                break
            end += 1
        if end >= len(lower) or end - offset > 4096:
            return cr.digest(raw)
        tag = lower[offset:end + 1]
        suppressed = next((name for name in (b"script", b"style", b"template", b"noscript", b"textarea",
            b"iframe", b"xmp", b"title", b"plaintext", b"noembed", b"noframes", b"svg", b"math")
            if tag.startswith(b"<" + name) and len(tag) > len(name) + 1 and
            tag[len(name) + 1] in b">/ \t\n\r\f"), None)
        if suppressed is not None:
            close = lower.find(b"</" + suppressed + b">", end + 1)
            if close < 0 or suppressed == b"plaintext" or (suppressed in (b"template", b"svg", b"math") and
                    0 <= lower.find(b"<" + suppressed, end + 1) < close):
                return cr.digest(raw)
            offset = close + len(suppressed) + 3
            continue
        if offset + 15 == len(lower) and tag == b"</body>":
            terminal = True
        if offset + 7 == len(lower) and tag == b"</html>":
            return cr.digest(prefix if terminal else raw)
        offset = end + 1
    return cr.digest(raw)


def enum(value: object, allowed: set[str], code: str) -> str:
    """型を混同せず有限の確認状態を検査する。"""
    return pl.enum_value(value, allowed, code)


def read_raw(path: Path) -> bytes:
    """原byteと解析対象を一致させ、有限読取り中の変更を拒否する。"""
    cr.regular_path(path)
    before = path.stat()
    with path.open("rb") as stream:
        raw = stream.read(cr.MAX_JSON_BYTES + 1)
    cr.regular_path(path)
    after = path.stat()
    cr.require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
               "INPUT_CHANGED")
    cr.require(len(raw) <= cr.MAX_JSON_BYTES, "JSON_SIZE")
    return raw


def input_binding(value: dict, raw: bytes) -> dict:
    """元file世代と原bytehashを返し、正規化hashと取り違えない。"""
    return {key: value[key] for key in ("schema", "revision", "asOf")} | {"sha256": cr.digest(raw)}


def load_inputs(registry_raw: bytes, locators_raw: bytes) -> dict:
    """既存の台帳・locator契約を維持して検証し、参照mapを一度だけ構築する。

    戻り値はこのmoduleの各関数へ渡す読取り専用contextであり、通信権限を持たない。
    元入力・既存module・運用stateを書き換えない。
    """
    registry = cr.validate_registry(cr.parse_json(registry_raw))
    locators = pl.validate_locators(cr.parse_json(locators_raw), registry)
    products_by_record = {row["id"]: [] for row in registry["records"]}
    # 対応edgeを一度だけ反転し、profileごとの全製品走査を避ける。
    for product in registry["products"]:
        for record_id in product["recordIds"]:
            products_by_record[record_id].append(product)
    return {"registry": registry, "locators": locators,
            "bindings": {"registry": input_binding(registry, registry_raw),
                         "locators": input_binding(locators, locators_raw)},
            "sources": {row["id"]: row for row in registry["sources"]},
            "products": {row["id"]: row for row in registry["products"]},
            "productsByRecord": products_by_record,
            "records": {row["id"]: row for row in registry["records"]},
            "locatorMap": {row["id"]: row for row in locators["locators"]}}


def reference_data(row: dict, inputs: dict) -> dict:
    """多対多の正本から全製品と公式導線を解決し、別recordの根拠借用を拒否する。"""
    source = inputs["sources"].get(row["sourceId"])
    record = inputs["records"].get(row["recordId"])
    page = inputs["locatorMap"].get(row["pageLocatorId"])
    payload = inputs["locatorMap"].get(row["payloadLocatorId"])
    cr.require(source is not None and record is not None and page is not None and payload is not None,
               "PROFILE_REFERENCE")
    cr.require(record["sourceId"] == source["id"] == page["sourceId"] == payload["sourceId"],
               "PROFILE_SOURCE_BINDING")
    cr.require(page["purpose"] == "PAGE" and payload["purpose"] == "PAYLOAD" and
               page["id"] in payload["parentPageIds"] and
               payload["recordIds"] == [record["id"]] and record["id"] in page["recordIds"],
               "PROFILE_LOCATOR_BINDING")
    products = inputs["productsByRecord"][record["id"]]
    product_ids = {product["id"] for product in products}
    cr.require(product_ids and product_ids <= set(page["productIds"]) and
               product_ids == set(payload["productIds"]), "PROFILE_PRODUCTS_BINDING")
    # 根拠graphの全祖先をfingerprintへ含め、root変更を見落とさない。
    pages = {page["id"]: page}
    current = page
    for _ in range(pl.MAX_PAGE_DEPTH):
        if not current["parentPageIds"]:
            break
        current = inputs["locatorMap"][current["parentPageIds"][0]]
        pages[current["id"]] = current
    return {"source": source, "record": record, "products": products, "page": page,
            "payload": payload, "pages": sorted(pages.values(), key=lambda item: item["id"])}


def reference_digest(row: dict, inputs: dict) -> str:
    """参照先の実質内容をhash化し、世代名だけの変更と配布条件変更を区別する。"""
    return cr.digest(cr.json_bytes(reference_data(row, inputs)))


def validate_inf_selection(value: object) -> dict:
    """全INFまたは有限なarchive内相対INFだけを許容し、実行pathを受け取らない。"""
    value = cr.fields(value, {"mode", "paths"}, "PROFILE_INF_FIELDS")
    enum(value["mode"], {"ALL", "SELECTED"}, "PROFILE_INF_MODE")
    paths = value["paths"]
    cr.require(type(paths) is list and len(paths) <= 128, "PROFILE_INF_COUNT")
    cr.require((value["mode"] == "ALL") == (len(paths) == 0), "PROFILE_INF_SELECTION")
    # Archive相対指定だけを保存し、nativeのmember/閉包/CAT検査を代行しない。
    for path in paths:
        cr.require(type(path) is str and 0 < len(path) <= 240 and
                   re.fullmatch(r"[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*\.inf", path,
                                flags=re.IGNORECASE) is not None and
                   all(part not in {".", ".."} and not part.endswith((".", " "))
                       for part in path.split("\\")), "PROFILE_INF_PATH")
    cr.require(len({path.casefold() for path in paths}) == len(paths), "PROFILE_INF_DUPLICATE")
    return {"mode": value["mode"], "paths": sorted(paths)}


def validate_review(value: object, data: dict, as_of: str, *, historical: bool = False) -> dict:
    """各実手動確認を原PAGEのhashと観測以降・profile世代/実現在以下へ結合する。

    historicalは再bindingで元根拠を失わず保留するためだけに使い、planの許可には使わない。
    """
    value = cr.fields(value, set(REVIEW_STATES), "PROFILE_REVIEW_FIELDS")
    result = {}
    content_bindings = {}
    # 全確認範囲を独立に検査し、一つの成功値で他の条件を満たさない。
    for scope, states in REVIEW_STATES.items():
        fields = {"state", "evidence"} | ({"items"} if scope == "prerequisites" else set())
        item = cr.fields(value[scope], fields, "PROFILE_REVIEW_ITEM_FIELDS")
        state = enum(item["state"], states, "PROFILE_REVIEW_STATE")
        evidence = item["evidence"]
        if state == "UNKNOWN":
            cr.require(evidence is None, "PROFILE_UNKNOWN_EVIDENCE")
        else:
            evidence = cr.fields(evidence, {"locatorId", "bodySha256", "contentSha256", "checkedAt", "scope"},
                                 "PROFILE_EVIDENCE_FIELDS")
            cr.identity(evidence["locatorId"])
            cr.sha256(evidence["bodySha256"])
            cr.sha256(evidence["contentSha256"])
            cr.require(evidence["bodySha256"] is not None and evidence["contentSha256"] is not None and evidence["scope"] == scope,
                       "PROFILE_EVIDENCE_SCOPE")
            binding = evidence["locatorId"], evidence["bodySha256"]
            cr.require(content_bindings.setdefault(binding, evidence["contentSha256"]) ==
                       evidence["contentSha256"], "PROFILE_CONTENT_BINDING")
            reviewed_at = cr.observation_timestamp(evidence["checkedAt"])
            cr.require(reviewed_at <= cr.timestamp(as_of) and
                       reviewed_at <= datetime.now(timezone.utc).replace(tzinfo=None),
                       "PROFILE_EVIDENCE_TIME")
            if not historical:
                page = next((page for page in data["pages"]
                             if page["id"] == evidence["locatorId"]), None)
                cr.require(page is not None and page["publicationCondition"] != "EXCLUDED" and
                           page["pageObservation"]["bodySha256"] == evidence["bodySha256"],
                           "PROFILE_EVIDENCE_BINDING")
                cr.require(cr.observation_timestamp(page["pageObservation"]["checkedAt"]) <=
                           reviewed_at, "PROFILE_EVIDENCE_TIME")
        if scope == "prerequisites":
            items = item["items"]
            cr.require(type(items) is list and len(items) <= 32, "PROFILE_PREREQUISITE_COUNT")
            for prerequisite in items:
                cr.label(prerequisite)
            cr.require(len(set(items)) == len(items) and
                       (bool(items) == (state == "REQUIRED")), "PROFILE_PREREQUISITES")
        result[scope] = copy.deepcopy(item)
    return result


def validate_profile(value: object, inputs: dict, *, as_of: str, bound: bool = True) -> dict:
    """厳密field・有限値・参照・確認根拠を検証し、独立したprofileを返す。"""
    row = cr.fields(value, BOUND_FIELDS if bound else PROFILE_FIELDS, "PROFILE_FIELDS")
    for key in ("id", "revision", "sourceId", "recordId", "pageLocatorId", "payloadLocatorId"):
        cr.identity(row[key])
    cr.require(type(row["sourceFormat"]) is str and
               re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", row["sourceFormat"]), "PROFILE_SOURCE_FORMAT")
    enum(row["container"], {"ZIP", "CAB"}, "PROFILE_CONTAINER")
    cr.require(type(row["maximumBytes"]) is int and 0 < row["maximumBytes"] <= MAX_PAYLOAD_BYTES,
               "PROFILE_MAXIMUM_BYTES")
    cr.require(type(row["href"]) is str and 0 < len(row["href"]) <= 480 and
               not cr.PRIVATE_TEXT.search(row["href"]) and
               not any(ord(char) <= 32 or ord(char) == 127 for char in row["href"]) and
               not any(char in row["href"] for char in "?#@<>&\"'\\") and
               ".." not in row["href"] and not row["href"].startswith("//"), "PROFILE_HREF")
    data = reference_data(row, inputs)
    historical = False
    if bound:
        cr.sha256(row["referenceSha256"])
        cr.require(row["referenceSha256"] is not None, "PROFILE_REFERENCE_HASH")
        enum(row["reviewState"], {"CURRENT", "REVIEW_REQUIRED"}, "PROFILE_BINDING_REVIEW")
        historical = row["reviewState"] == "REVIEW_REQUIRED"
        cr.require(row["referenceSha256"] == reference_digest(row, inputs), "PROFILE_REFERENCE_CHANGED")
    result = copy.deepcopy(row)
    result["infSelection"] = validate_inf_selection(row["infSelection"])
    result["review"] = validate_review(row["review"], data, as_of, historical=historical)
    return result


def document(inputs: dict, revision: str, as_of: str, profiles: list[dict]) -> dict:
    """入力hashを自動結合した新世代を作り、実行・公開・導入権限を付与しない。"""
    return {"schema": SCHEMA, "revision": revision, "asOf": as_of,
            **copy.deepcopy(inputs["bindings"]), "profiles": profiles,
            "networkAuthorized": False, "publishable": False, "installAuthorized": False}


def validate_profiles(value: object, inputs: dict) -> dict:
    """外部profile全分母を検証し、元配列に副作用なくstable ID順に返す。"""
    value = cr.fields(value, {"schema", "revision", "asOf", "registry", "locators", "profiles",
                              "networkAuthorized", "publishable", "installAuthorized"}, "PROFILES_FIELDS")
    cr.require(value["schema"] == SCHEMA, "PROFILES_SCHEMA")
    cr.identity(value["revision"])
    cr.require(cr.timestamp(value["asOf"]) >= cr.timestamp(inputs["locators"]["asOf"]), "PROFILES_TIME")
    cr.require(all(value[key] is False for key in
                   ("networkAuthorized", "publishable", "installAuthorized")), "PROFILES_AUTHORITY")
    for key in ("registry", "locators"):
        cr.fields(value[key], {"schema", "revision", "asOf", "sha256"}, "PROFILES_BINDING_FIELDS")
        cr.require(value[key] == inputs["bindings"][key], "PROFILES_INPUT_BINDING")
    cr.require(type(value["profiles"]) is list and len(value["profiles"]) <= MAX_PROFILES, "PROFILES_COUNT")
    rows = []
    ids = set()
    records = set()
    # 一record一profileを要求し、矛盾する条件で二重取得jobを作らない。
    for raw in value["profiles"]:
        row = validate_profile(raw, inputs, as_of=value["asOf"])
        cr.require(row["id"] not in ids and row["recordId"] not in records, "PROFILE_DUPLICATE")
        ids.add(row["id"])
        records.add(row["recordId"])
        rows.append(row)
    result = {**copy.deepcopy(value), "profiles": sorted(rows, key=lambda row: row["id"])}
    cr.require(len(cr.json_bytes(result)) <= cr.MAX_JSON_BYTES, "PROFILES_JSON_SIZE")
    return result


def static_source(row: dict, data: dict) -> dict | None:
    """既存native exact anchor文法だけを解決し、未知形式やqueryを救済しない。"""
    page = data["page"]["url"]
    payload = data["payload"]["url"]
    href = row["href"]
    values = (page, payload, href)
    if row["sourceFormat"] != STATIC_FORMAT or any(
            any(char in value for char in "?#@<>&\"'\\") or ".." in value for value in values):
        return None
    if href.startswith("//") or data["page"]["parentPageIds"] or page != data["source"]["officialPage"]:
        return None
    root_host = urlsplit(page).hostname
    payload_host = urlsplit(payload).hostname
    # Nativeと同じ絶対/root相対/page相対の三構文を使い、URLを正規化し直さない。
    resolved = href if href.startswith("https://") else (
        "https://" + root_host + href if href.startswith("/") else page.rsplit("/", 1)[0] + "/" + href)
    if resolved != payload or not page.startswith("https://" + root_host + "/") or not payload.startswith(
            "https://" + payload_host + "/"):
        return None
    return {"rootUrl": page, "rootHost": root_host, "payloadUrl": payload,
            "payloadHost": payload_host, "href": href}


def make_static_job(row: dict, inputs: dict) -> dict:
    """検証済みprofileと同じ参照mapから一jobを作る。通信許可は発行しない。"""
    data = reference_data(row, inputs)
    source = static_source(row, data)
    cr.require(source is not None, "UNSUPPORTED_SOURCE_FORMAT")
    return {"schema": JOB_SCHEMA, "jobId": row["id"], "profileRevision": row["revision"],
            "referenceSha256": row["referenceSha256"], **copy.deepcopy(inputs["bindings"]),
            "sourceFormat": row["sourceFormat"], "sourceId": row["sourceId"], "recordId": row["recordId"],
            "source": source, "record": copy.deepcopy(data["record"]), "products": copy.deepcopy(data["products"]),
            "pageObservation": copy.deepcopy(data["page"]["pageObservation"]), "container": row["container"],
            "maximumBytes": row["maximumBytes"], "infSelection": copy.deepcopy(row["infSelection"]),
            "review": copy.deepcopy(row["review"])}


def plan_profiles(value: object, inputs: dict, *, batch_size: int = MAX_BATCH,
                  completed_profile_ids: tuple[str, ...] = ()) -> dict:
    """全profileを分類し、同一recordの全製品を一jobへ束ねる非通信計画を返す。

    completed_profile_idsは次batchの選択用であり成功・待機・実行許可ではない。
    jobは参照から解決したsource/record/productsとreviewを持つJOB_SCHEMAのJSONである。
    後続nativeは入力hash・公式導線・実byte・署名・全INFを再検証する必要がある。
    """
    value = validate_profiles(value, inputs)
    cr.require(type(batch_size) is int and 0 < batch_size <= MAX_BATCH, "PLAN_BATCH")
    completed = set(completed_profile_ids)
    cr.require(len(completed) == len(completed_profile_ids) and completed <=
               {row["id"] for row in value["profiles"]}, "PLAN_COMPLETED_IDS")
    jobs = []
    targets = []
    # 分母をstable ID順に保持し、延期・未知・保留を除外しない。
    for row in value["profiles"]:
        data = reference_data(row, inputs)
        source = static_source(row, data)
        reasons = []
        if source is None:
            reasons.append("UNSUPPORTED_SOURCE_FORMAT")
        if row["reviewState"] != "CURRENT":
            reasons.append("REVIEW_REQUIRED")
        for scope, required in (("official", "CONFIRMED"), ("preDownload", "NO_EXTRA_PROMPT"),
                                ("terms", "NO_ADDITIONAL_TERMS"), ("prerequisites", "NONE_REQUIRED")):
            if row["review"][scope]["state"] != required:
                reasons.append("HOLD_" + scope.upper())
        if data["payload"]["requestCondition"] != "NO_EXTRA_PROMPT_OBSERVED":
            reasons.append("HOLD_LOCATOR_CONDITION")
        if any(item["publicationCondition"] == "EXCLUDED" for item in [data["payload"], *data["pages"]]):
            reasons.append("HOLD_EXCLUDED")
        status = "HOLD" if reasons else "PLANNED"
        if "UNSUPPORTED_SOURCE_FORMAT" in reasons:
            status = "UNSUPPORTED_SOURCE_FORMAT"
        if not reasons and row["id"] in completed:
            status = "ALREADY_SELECTED"
        if status == "PLANNED" and len(jobs) >= batch_size:
            status = "DEFERRED_BATCH"
        if status == "PLANNED":
            jobs.append(make_static_job(row, inputs))
        targets.append({"profileId": row["id"], "recordId": row["recordId"],
                        "productIds": [product["id"] for product in data["products"]],
                        "status": status, "reasons": reasons})
    profiled_records = {row["recordId"] for row in value["profiles"]}
    # 未profileの研究recordも分母として明示し、空集合を全対象の対応完了と表示しない。
    unprofiled = [{"recordId": record["id"], "status": "NO_COLLECTION_PROFILE",
                   "productIds": [product["id"] for product in inputs["productsByRecord"][record["id"]]]}
                  for record in inputs["registry"]["records"] if record["id"] not in profiled_records]
    return {"schema": PLAN_SCHEMA, "profileRevision": value["revision"],
            "profileSha256": cr.digest(cr.json_bytes(value)), **copy.deepcopy(inputs["bindings"]),
            "batchSize": batch_size, "targets": targets, "unprofiledRecords": unprofiled, "jobs": jobs,
            "counts": {"profiles": len(targets), "productReferences": sum(len(row["productIds"]) for row in targets),
                       "registeredRecords": len(inputs["records"]), "unprofiledRecords": len(unprofiled),
                       "jobs": len(jobs), "deferred": sum(row["status"] == "DEFERRED_BATCH" for row in targets),
                       "held": sum(bool(row["reasons"]) for row in targets)},
            "networkAuthorized": False, "publishable": False, "installAuthorized": False}


def upsert_profiles(existing: object | None, inputs: dict, edits: object, *, revision: str,
                    as_of: str, previous_inputs: dict | None = None,
                    reviewed_profile_ids: tuple[str, ...] = ()) -> dict:
    """小さな編集入力から追加・更新・原byte再bindingを行い、新規documentを返す。

    既存は旧inputsでも検証してから移す。実質参照/実行条件変更は必ずREVIEW_REQUIREDとなり、
    同じ呼出しのreview指定では解除しない。次の明示reviewには当該profileの全確認入力が必要である。
    待機・成功・運用stateは一切受け取らず、hash再計算で成功や送信権限を作らない。
    """
    edits = cr.fields(edits, {"schema", "profiles"}, "PROFILE_EDIT_FIELDS")
    cr.require(edits["schema"] == EDIT_SCHEMA and type(edits["profiles"]) is list and
               len(edits["profiles"]) <= MAX_PROFILES, "PROFILE_EDIT_SCHEMA")
    rows = {}
    if existing is not None:
        validated = validate_profiles(existing, previous_inputs or inputs)
        cr.require(cr.timestamp(as_of) >= cr.timestamp(validated["asOf"]), "PROFILE_EDIT_TIME")
        rows = {row["id"]: row for row in validated["profiles"]}
    updates = {}
    for raw in edits["profiles"]:
        row = validate_profile(raw, inputs, as_of=as_of, bound=False)
        cr.require(row["id"] not in updates, "PROFILE_EDIT_DUPLICATE")
        updates[row["id"]] = row
    reviewed = set(reviewed_profile_ids)
    cr.require(len(reviewed) == len(reviewed_profile_ids) and reviewed <= set(updates), "PROFILE_REVIEW_SELECTION")
    # 削除しないupsertとし、未確認の旧対象も新世代の分母へ残す。
    for identifier in sorted(set(rows) | set(updates)):
        old = rows.get(identifier)
        row = copy.deepcopy(updates.get(identifier, old))
        data_hash = reference_digest(row, inputs)
        changed = old is not None and (old["referenceSha256"] != data_hash or any(
            old[key] != row[key] for key in PROFILE_FIELDS - {"revision", "review"}))
        if old is not None and identifier in updates and any(old[key] != row[key] for key in PROFILE_FIELDS):
            cr.require(row["revision"] != old["revision"], "PROFILE_REVISION_UNCHANGED")
        row["referenceSha256"] = data_hash
        row["reviewState"] = ("REVIEW_REQUIRED" if changed else
                              ("CURRENT" if old is None or identifier in reviewed else old["reviewState"]))
        rows[identifier] = row
    result = document(inputs, revision, as_of, list(rows.values()))
    if existing is not None and result != validated:
        cr.require(revision != validated["revision"], "PROFILES_REVISION_UNCHANGED")
    return validate_profiles(result, inputs)


def write_new(output: Path, value: dict, protected: list[Path]) -> None:
    """既存file・入力・linkを上書きせず、明示した新規JSONだけを出力する。"""
    target = output.absolute()
    cr.require(all(target.resolve() != item.resolve() for item in protected), "OUTPUT_IS_INPUT")
    current = target.parent
    # 親directoryのreparseも拒否し、既存管理fileへの迂回を防ぐ。
    while True:
        cr.regular_path(current, directory=True)
        if current.parent == current:
            break
        current = current.parent
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    raw = cr.json_bytes(value)
    cr.require(len(raw) <= cr.MAX_JSON_BYTES, "OUTPUT_SIZE")
    with output.open("xb") as stream:
        stream.write(raw)


def main(argv: list[str] | None = None) -> int:
    """非通信CLI。通常出力は件数/codeだけとし、URLを含むJSONは明示fileに限定する。"""
    parser = argparse.ArgumentParser(description="収集profileの非通信検証・計画・保守。")
    parser.add_argument("command", choices=("validate", "plan", "upsert"))
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--locators", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--edits", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--as-of")
    parser.add_argument("--previous-registry", type=Path)
    parser.add_argument("--previous-locators", type=Path)
    parser.add_argument("--review-profile", action="append", default=[])
    parser.add_argument("--batch-size", type=int, default=MAX_BATCH)
    parser.add_argument("--completed-profile", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command != "upsert":
            cr.require(args.edits is None and args.revision is None and args.as_of is None and
                       args.previous_registry is None and args.previous_locators is None and
                       not args.review_profile, "COMMAND_ARGUMENTS")
        if args.command != "plan":
            cr.require(args.batch_size == MAX_BATCH and not args.completed_profile, "COMMAND_ARGUMENTS")
        if args.command == "validate":
            cr.require(args.output is None, "COMMAND_ARGUMENTS")
        inputs = load_inputs(read_raw(args.registry), read_raw(args.locators))
        profiles = cr.read_json(args.profiles) if args.profiles else None
        protected = [path for path in (args.registry, args.locators, args.profiles, args.edits,
                                      args.previous_registry, args.previous_locators) if path is not None]
        if args.command == "upsert":
            cr.require(args.output is not None and args.edits is not None and
                       args.revision is not None and args.as_of is not None, "UPSERT_ARGUMENTS")
            cr.require((args.previous_registry is None) == (args.previous_locators is None), "PREVIOUS_INPUTS")
            previous = (load_inputs(read_raw(args.previous_registry), read_raw(args.previous_locators))
                        if args.previous_registry is not None else None)
            result = upsert_profiles(profiles, inputs, cr.read_json(args.edits), revision=args.revision,
                                     as_of=args.as_of, previous_inputs=previous,
                                     reviewed_profile_ids=tuple(args.review_profile))
            write_new(args.output, result, protected)
            counts = {"profiles": len(result["profiles"]), "reviewRequired": sum(
                row["reviewState"] == "REVIEW_REQUIRED" for row in result["profiles"])}
        else:
            cr.require(profiles is not None, "PROFILES_REQUIRED")
            result = validate_profiles(profiles, inputs)
            counts = {"profiles": len(result["profiles"])}
            if args.command == "plan":
                cr.require(args.output is not None, "PLAN_OUTPUT_REQUIRED")
                result = plan_profiles(result, inputs, batch_size=args.batch_size,
                                       completed_profile_ids=tuple(args.completed_profile))
                write_new(args.output, result, protected)
                counts = result["counts"]
        print(cr.json_bytes({"status": "VALID", "counts": counts}).decode("utf-8"), end="")
    except cr.RegistryError as error:
        print("REJECTED:" + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("REJECTED:IO_ERROR", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
