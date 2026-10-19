"""原取得byteと保存済み導線を後日結合する純粋研究validator（ADR 0326）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
file・DNS・HTTP・archive解析を行わず、署名、適用性、通信、公開、導入権限を発行しない。
原pin照合済みbyteを呼出側から借用し、入力を変更しない。原proofの自己申告boolは認定に使わない。
"""

from __future__ import annotations

import copy
from datetime import datetime
import math
import re

import collector_registry as cr
import collector_public_locators as pl


SCHEMA = "dc-route-acquisition-bindings-v1"
SCHEMA_V2 = "dc-route-acquisition-bindings-v2"
MAX_BINDINGS = 2  # 初回一検証の有限予算であり、製品収集総数の上限ではない。
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_PROOF_BYTES = 64 * 1024
ROLES = {"landing", "metadata", "app", "chunk10"}
MAIN_FIELDS = {"code", "id", "name", "categoryId", "auth", "redirect", "fullUrl",
               "githubDownloadUrl", "version", "uploadTime", "scope"}


def _time(value: object) -> datetime:
    """元HTTPの小数秒を保持し、明示UTCだけを受理する。"""
    cr.require(type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.[0-9]{1,6})?Z", value) is not None,
        "BINDING_TIME")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise cr.RegistryError("BINDING_TIME") from error


def _pin(raw: object, expected: object, maximum: int) -> bytes:
    """借用byteを有限sizeと非nullの外部固定pinへ照合する。"""
    expected = cr.fields(expected, {"bytes", "sha256"}, "BINDING_PIN_FIELDS")
    cr.require(type(raw) is bytes and 0 < len(raw) <= maximum, "BINDING_BYTE_LIMIT")
    cr.require(type(expected["bytes"]) is int and expected["bytes"] == len(raw), "BINDING_BYTE_SIZE")
    cr.sha256(expected["sha256"])
    cr.require(expected["sha256"] is not None and cr.digest(raw) == expected["sha256"], "BINDING_BYTE_HASH")
    return raw


def _document_binding(document: dict) -> dict:
    """検証後の正規document identityへ結合する。"""
    return {"schema": document["schema"], "revision": document["revision"],
            "asOf": document["asOf"], "sha256": cr.digest(cr.json_bytes(document))}


def _metadata_url(value: object, name: str) -> str:
    """保存済みAPI根拠の単一basenameだけを検査し、GETを許可しない。"""
    cr.require(type(value) is str and len(value) <= 2048, "BINDING_METADATA_URL")
    base, separator, query = value.partition("?")
    cr.public_url(base)
    cr.require(separator == "?" and query == "fileName=" + name.replace(".", "_") + ".html",
               "BINDING_METADATA_QUERY")
    return value


def _receipt(raw: object, expected: object) -> dict:
    """原receipt実byteとpinを検査し、成功200以外を新結合へ使わない。"""
    result = cr.parse_json(_pin(raw, expected, MAX_PROOF_BYTES))
    cr.require(type(result) is dict and type(result.get("status")) is int and result["status"] == 200 and
               type(result.get("exitCode")) is int and result["exitCode"] == 0 and
               result.get("timedOut") is False and result.get("outputLimitStopped") is False,
               "BINDING_ORIGINAL_RECEIPT")
    _time(result.get("completedAtUtc"))
    return result


def _observation(declared: object, original: object, role: str, bound_at: datetime, v2: bool) -> tuple[dict, bytes]:
    """公開する選抜観測値を原HTTP receiptとbodyへ結合する。"""
    expected = {"url", "observedAt", "bytes", "sha256", "originalReceiptSha256"}
    if role in {"app", "chunk10"}:
        expected |= {"role", "checkedAt", "reused"}
        expected |= {"derivedAgeSeconds", "originalRecordedAgeSeconds"} if v2 else {"sourceAgeSeconds"}
    row = cr.fields(declared, expected, "BINDING_OBSERVATION_FIELDS")
    original = cr.fields(original, {"bodyBytes", "receiptBytes", "receiptPin"}, "BINDING_ORIGINAL_FIELDS")
    receipt = _receipt(original["receiptBytes"], original["receiptPin"])
    body = _pin(original["bodyBytes"], receipt.get("bodyPin"), MAX_BODY_BYTES)
    cr.require(row["originalReceiptSha256"] == original["receiptPin"]["sha256"] and
               type(row["bytes"]) is int and
               row["url"] == receipt.get("url") and row["observedAt"] == receipt["completedAtUtc"] and
               {"bytes": row["bytes"], "sha256": row["sha256"]} == receipt["bodyPin"],
               "BINDING_ORIGINAL_OBSERVATION")
    cr.require(_time(row["observedAt"]) <= bound_at, "BINDING_FUTURE_OBSERVATION")
    if role in {"app", "chunk10"}:
        cr.public_url(row["url"])
        age = row["derivedAgeSeconds"] if v2 else row["sourceAgeSeconds"]
        cr.require(row["role"] == role and type(row["reused"]) is bool and type(age) in {int, float}
                   and 0 <= age <= 31_536_000 and math.isfinite(age), "BINDING_SCRIPT_FIELDS")
        actual_age = (_time(row["checkedAt"]) - _time(row["observedAt"])).total_seconds()
        exact_age = actual_age == age if v2 else abs(actual_age - age) <= 0.000001
        cr.require(_time(row["checkedAt"]) <= bound_at and exact_age and
                   (row["reused"] or age == 0), "BINDING_SCRIPT_AGE")
        # v2は原記録値を鮮度の正本にせず、freshでは記録不存在をnullで示す。
        if v2:
            recorded = row["originalRecordedAgeSeconds"]
            cr.require((type(recorded) in {int, float} and 0 <= recorded <= 31_536_000 and
                        math.isfinite(recorded)) if row["reused"] else recorded is None,
                       "BINDING_ORIGINAL_SCRIPT_AGE")
    return receipt, body


def _route_proof(proof: dict, bodies: dict, provenance: dict, v2: bool) -> None:
    """原proofのpinと四静的範囲を実byteへ再結合し、scriptを実行しない。"""
    for role, key in (("landing", "landingPin"), ("metadata", "metadataPin"),
                      ("app", "appPin"), ("chunk10", "chunk10Pin")):
        _pin(bodies[role], proof.get(key), MAX_BODY_BYTES)
    ranges = proof.get("ranges")
    cr.require(type(ranges) is dict, "BINDING_PROOF_RANGES")
    for name, role in (("resourceRoute", "app"), ("webpackPath", "app"),
                       ("relationFilesClient", "chunk10"), ("chineseDownloadAnchor", "chunk10")):
        row = ranges.get(name)
        cr.require(type(row) is dict, "BINDING_PROOF_RANGE")
        start, end = row.get("startByteOffset"), row.get("endByteOffset")
        cr.require(type(start) is int and type(end) is int and 0 <= start < end <= len(bodies[role]),
                   "BINDING_PROOF_OFFSETS")
        _pin(bodies[role][start:end], {"bytes": row.get("bytes"), "sha256": row.get("sha256")}, MAX_BODY_BYTES)
    anchor = ranges["chineseDownloadAnchor"]
    fragment = bodies["chunk10"][anchor["startByteOffset"]:anchor["endByteOffset"]]
    cr.require(provenance["literalCdnPrefix"].encode("ascii") in fragment, "BINDING_CDN_LITERAL")
    # 再使用時は原URLと原日時・ageまで保持し、現在の新script観測へ付け替えない。
    for script in provenance["scripts"]:
        if script["reused"]:
            reuse = proof.get("reuseBinding")
            cr.require(type(reuse) is dict and type(reuse.get("reusedScripts")) is list and
                       all(type(item) is dict for item in reuse["reusedScripts"]),
                       "BINDING_REUSE_PROOF")
            matches = [row for row in reuse["reusedScripts"] if row.get("role") == script["role"]]
            cr.require(len(matches) == 1, "BINDING_REUSE_ROLE")
            old = matches[0]
            # 原proofの値はv2でも書き換えず、数値と原identityを個別に再照合する。
            proof_age = old.get("sourceAgeSeconds")
            cr.require(type(proof_age) in {int, float} and 0 <= proof_age <= 31_536_000 and
                       math.isfinite(proof_age), "BINDING_REUSE_IDENTITY")
            age_matches = proof_age == script["originalRecordedAgeSeconds"] if v2 else (
                abs(proof_age - script["sourceAgeSeconds"]) <= 0.000001)
            cr.require(reuse.get("checkedAtUtc") == script["checkedAt"] and
                       old.get("originalUrl") == script["url"] and
                       old.get("originalObservedAtUtc") == script["observedAt"] and
                       old.get("pin") == {"bytes": script["bytes"], "sha256": script["sha256"]} and
                       age_matches,
                       "BINDING_REUSE_IDENTITY")


def _aliases(value: object, row: dict, registry: dict, provenance: dict, locator: dict) -> None:
    """用途別aliasを保存だけへ限定し、元source／recordの待機identityを残す。"""
    aliases = cr.fields(value, {"familyKey", "requests", "waitState", "hostState", "eulaState"}, "BINDING_ALIAS_FIELDS")
    cr.require(aliases["familyKey"] == row["familyKey"], "BINDING_ALIAS_FAMILY")
    for key in ("waitState", "hostState", "eulaState"):
        pl.enum_value(aliases[key], {"UNKNOWN", "HELD"}, "BINDING_ALIAS_STATE")
    requests = aliases["requests"]
    cr.require(type(requests) is list and len(requests) == 4, "BINDING_ALIAS_COUNT")
    sources = {item["id"]: item for item in registry["sources"]}
    records = {item["id"]: item for item in registry["records"]}
    seen = set()
    for raw in requests:
        request = cr.fields(raw, {"kind", "sourceId", "recordId", "url"}, "BINDING_ALIAS_ROW")
        kind = pl.enum_value(request["kind"], {"LEGACY", "PAGE", "METADATA", "PAYLOAD"}, "BINDING_ALIAS_KIND")
        cr.identity(request["sourceId"])
        cr.require(kind not in seen and request["sourceId"] in sources, "BINDING_ALIAS_REFERENCE")
        seen.add(kind)
        if kind == "LEGACY":
            old_id = request["recordId"]
            cr.require(request["sourceId"] != locator["sourceId"] and
                       any(request["sourceId"] in product["sourceIds"] for product in registry["products"]
                           if product["id"] in row["productIds"]), "BINDING_LEGACY_SOURCE")
            if old_id is None:
                cr.require(request["url"] == sources[request["sourceId"]]["officialPage"], "BINDING_LEGACY_PAGE")
            else:
                cr.require(type(old_id) is str and old_id in records and old_id != row["recordId"] and
                           records[old_id]["sourceId"] == request["sourceId"] and
                           request["url"] == records[old_id]["downloadUrl"], "BINDING_LEGACY_RECORD")
        else:
            expected_url = provenance["landing"]["url"] if kind == "PAGE" else (
                provenance["metadata"]["url"] if kind == "METADATA" else locator["url"])
            cr.require(request["sourceId"] == locator["sourceId"] and request["recordId"] == row["recordId"]
                       and request["url"] == expected_url, "BINDING_ALIAS_IDENTITY")


def validate_bindings(registry: object, locators: object, bindings: object, original_proofs: object) -> dict:
    """固定原byteを照合し、後日の研究結合だけを返す。全入力を変更しない。

    original_proofsは呼出側で原固定pin照合済みの非公開byte bundleである。JSON byte入力の重複keyを
    拒否し、未知・欠損・時刻・型・参照・pinの不一致はRegistryErrorのcodeだけでfail-closedにする。
    """
    registry = cr.validate_registry(registry)
    locators = pl.validate_locators(locators, registry)
    if type(bindings) is bytes:
        bindings = cr.parse_json(bindings)
    document = cr.fields(bindings, {"schema", "revision", "asOf", "registryBinding", "locatorsBinding",
        "researchOnly", "publishable", "installAuthorized", "nativeConnected", "bindings"}, "BINDING_FIELDS")
    cr.require(type(document["schema"]) is str and document["schema"] in {SCHEMA, SCHEMA_V2}, "BINDING_SCHEMA")
    v2 = document["schema"] == SCHEMA_V2
    cr.identity(document["revision"])
    as_of = cr.timestamp(document["asOf"])
    cr.require(as_of >= cr.timestamp(locators["asOf"]), "BINDING_DOCUMENT_TIME")
    cr.require(document["registryBinding"] == _document_binding(registry) and
               document["locatorsBinding"] == _document_binding(locators), "BINDING_DOCUMENT_IDENTITY")
    cr.require(document["researchOnly"] is True and document["publishable"] is False and
               document["installAuthorized"] is False and document["nativeConnected"] is False, "BINDING_SAFETY")
    rows = document["bindings"]
    cr.require(type(rows) is list and 1 <= len(rows) <= MAX_BINDINGS, "BINDING_COUNT")
    cr.require(type(original_proofs) is dict, "BINDING_ORIGINAL_BUNDLE")
    records = {row["id"]: row for row in registry["records"]}
    sources = {row["id"]: row for row in registry["sources"]}
    products = {row["id"]: row for row in registry["products"]}
    locator_map = {row["id"]: row for row in locators["locators"]}
    seen_ids, seen_records, seen_locators, seen_families = set(), set(), set(), set()
    # 初回の有限binding集合を個別に原取得へ結合する。
    for raw in rows:
        row = cr.fields(raw, {"id", "familyKey", "recordId", "recordSha256", "locatorId", "locatorSha256",
            "productIds", "provenance", "acquisition", "infDisplay", "waitAliases", "requestAuthorized"}, "BINDING_ROW_FIELDS")
        for key, seen in (("id", seen_ids), ("recordId", seen_records), ("locatorId", seen_locators), ("familyKey", seen_families)):
            cr.identity(row[key])
            cr.require(row[key] not in seen, "BINDING_DUPLICATE")
            seen.add(row[key])
        cr.require(row["id"] in original_proofs and row["recordId"] in records and row["locatorId"] in locator_map,
                   "BINDING_REFERENCE")
        record, locator = records[row["recordId"]], locator_map[row["locatorId"]]
        cr.require(row["recordSha256"] == cr.digest(cr.json_bytes(record)) and
                   row["locatorSha256"] == cr.digest(cr.json_bytes(locator)), "BINDING_ROW_HASH")
        ids = cr.id_list(row["productIds"])
        expected_ids = sorted(key for key, product in products.items() if row["recordId"] in product["recordIds"])
        cr.require(sorted(ids) == expected_ids and sorted(locator["productIds"]) == expected_ids and
                   locator["recordIds"] == [row["recordId"]] and locator["sourceId"] == record["sourceId"], "BINDING_PRODUCT_GRAPH")
        cr.require(locator["purpose"] == "PAYLOAD" and locator["urlProfile"] == "PUBLIC_NUMERIC_ID" and
                   locator["requestCondition"] == "ACCESS_UNRESOLVED" and locator["publicationCondition"] == "REVIEW_REQUIRED" and
                   row["requestAuthorized"] is False and record["downloadUrl"] is None and record["linkState"] == "MISSING" and
                   record["publishedSha256"] is None, "BINDING_HELD")
        original = cr.fields(original_proofs[row["id"]], {"proofBytes", "proofPin", "receiptBytes", "receiptPin",
            "payloadBytes", "observations"}, "BINDING_BUNDLE_FIELDS")
        proof = cr.parse_json(_pin(original["proofBytes"], original["proofPin"], MAX_PROOF_BYTES))
        cr.require(type(proof) is dict, "BINDING_PROOF_TYPE")
        provenance = cr.fields(row["provenance"], {"boundAt", "originalProofSha256", "landing", "metadata", "scripts",
            "mainRecord", "literalCdnPrefix"}, "BINDING_PROVENANCE_FIELDS")
        bound_at = _time(provenance["boundAt"])
        cr.require(cr.timestamp(locators["asOf"]) <= bound_at <= as_of and
                   provenance["originalProofSha256"] == original["proofPin"]["sha256"], "BINDING_BOUND_AT")
        observations = cr.fields(original["observations"], ROLES, "BINDING_ORIGINAL_ROLES")
        scripts = provenance["scripts"]
        cr.require(type(scripts) is list and len(scripts) == 2 and all(type(item) is dict for item in scripts), "BINDING_SCRIPTS")
        script_map = {item.get("role"): item for item in scripts if type(item.get("role")) is str}
        cr.require(set(script_map) == {"app", "chunk10"}, "BINDING_SCRIPT_ROLES")
        bodies = {}
        for role in ROLES:
            declared = provenance[role] if role in {"landing", "metadata"} else script_map[role]
            _, bodies[role] = _observation(declared, observations[role], role, bound_at, v2)
        main = cr.fields(provenance["mainRecord"], MAIN_FIELDS, "BINDING_MAIN_FIELDS")
        metadata = cr.parse_json(bodies["metadata"])
        cr.require(type(metadata) is dict and type(metadata.get("code")) is int and metadata["code"] == 0 and
                   type(metadata.get("data")) is dict, "BINDING_MAIN_RESPONSE")
        data = metadata["data"]
        selected = {key: metadata["code"] if key == "code" else data.get(key) for key in MAIN_FIELDS}
        cr.require(all(key in data for key in MAIN_FIELDS - {"code"}) and cr.json_bytes(selected) == cr.json_bytes(main), "BINDING_MAIN_IDENTITY")
        cr.require(type(main["id"]) is int and 1 <= main["id"] <= 2147483647 and type(main["code"]) is int and main["code"] == 0 and
                   type(main["categoryId"]) is int and main["categoryId"] == 67 and type(main["auth"]) is str and main["auth"] == "0" and
                   type(main["name"]) is str and re.fullmatch(r"[A-Z0-9_]{1,80}\.ZIP", main["name"]) is not None and
                   main["redirect"] is None and main["fullUrl"] is None and main["githubDownloadUrl"] == "" and
                   type(main["githubDownloadUrl"]) is str, "BINDING_TYPED_MAIN")
        proof_main = proof.get("mainRecordFields")
        cr.require(type(proof_main) is dict and all(cr.json_bytes(proof_main.get(key)) == cr.json_bytes(main[key])
                   for key in ("id", "name", "auth", "categoryId", "version", "uploadTime", "scope")), "BINDING_PROOF_MAIN")
        cr.require(type(main["scope"]) is str and len(main["scope"]) <= 2048, "BINDING_SCOPE_TYPE")
        scope = [part.strip() for part in main["scope"].split(",")]
        cr.require(all(scope) and len(scope) == len(set(scope)) and set(scope) == {products[key]["model"] for key in ids}, "BINDING_SCOPE")
        cr.require(main["version"] == record["packageVersion"] and main["uploadTime"] == record["publishedDate"], "BINDING_RELEASE")
        cr.require(provenance["landing"]["url"] == sources[record["sourceId"]]["officialPage"], "BINDING_LANDING_SOURCE")
        _metadata_url(provenance["metadata"]["url"], main["name"])
        prefix = provenance["literalCdnPrefix"]
        cr.require(type(prefix) is str and prefix.isascii() and prefix.endswith("?id=") and len(prefix) <= 2040, "BINDING_CDN_PREFIX")
        cr.public_url(prefix[:-4])
        cr.require(locator["url"] == prefix + str(main["id"]), "BINDING_CDN_URL")
        _route_proof(proof, bodies, provenance, v2)
        receipt = _receipt(original["receiptBytes"], original["receiptPin"])
        body = _pin(original["payloadBytes"], receipt.get("bodyPin"), MAX_BODY_BYTES)
        acquisition = cr.fields(row["acquisition"], {"originalReceiptSha256", "observedAt", "httpStatus", "bytes", "sha256", "signature", "content"}, "BINDING_ACQUISITION_FIELDS")
        cr.require(acquisition["originalReceiptSha256"] == original["receiptPin"]["sha256"] and acquisition["observedAt"] == receipt["completedAtUtc"] and
                   type(acquisition["httpStatus"]) is int and acquisition["httpStatus"] == 200 and receipt.get("url") == locator["url"] and
                   type(acquisition["bytes"]) is int and acquisition["bytes"] == len(body) and acquisition["sha256"] == cr.digest(body) and
                   acquisition["signature"] == "NOT_CHECKED" and acquisition["content"] == "NOT_CHECKED" and
                   _time(provenance["metadata"]["observedAt"]) <= _time(acquisition["observedAt"]) <= bound_at, "BINDING_ACQUISITION_IDENTITY")
        display = cr.fields(row["infDisplay"], {"driverVersion", "driverDate", "inventoryEntries", "inspection"}, "BINDING_INF_FIELDS")
        cr.label(display["driverVersion"])
        cr.require(display["driverVersion"] == record["driverVersion"] and type(display["inventoryEntries"]) is int and
                   0 <= display["inventoryEntries"] <= 4096 and display["inspection"] == "NOT_CHECKED", "BINDING_INF_DISPLAY")
        cr.require(type(display["driverDate"]) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}", display["driverDate"]) is not None, "BINDING_INF_DATE")
        _time(display["driverDate"] + "T00:00:00Z")
        _aliases(row["waitAliases"], row, registry, provenance, locator)
    cr.require(set(original_proofs) == seen_ids, "BINDING_BUNDLE_SET")
    return copy.deepcopy(document)


def research_binding_report(registry: object, locators: object, bindings: object, original_proofs: object) -> dict:
    """検証を経由し、過去取得と全通信保留・未確認の研究reportを返す。"""
    document = validate_bindings(registry, locators, bindings, original_proofs)
    rows = [{"bindingId": row["id"], "familyKey": row["familyKey"], "recordId": row["recordId"],
             "locatorId": row["locatorId"], "productIds": list(row["productIds"]),
             "status": "HISTORICAL_BODY_OBSERVED", "observedAt": row["acquisition"]["observedAt"],
             "boundAt": row["provenance"]["boundAt"], "requestState": "HELD", "requestAuthorized": False,
             "signature": "NOT_CHECKED", "content": "NOT_CHECKED", "applicability": "NOT_CHECKED"}
            for row in document["bindings"]]
    # v1の生成fieldとbyteを維持し、v2だけに明示した原記録／派生／差を添える。
    if document["schema"] == SCHEMA_V2:
        for row, source in zip(rows, document["bindings"]):
            row["scriptAges"] = [{"role": script["role"], "derivedAgeSeconds": script["derivedAgeSeconds"],
                "originalRecordedAgeSeconds": script["originalRecordedAgeSeconds"],
                "originalMinusDerivedSeconds": None if script["originalRecordedAgeSeconds"] is None else
                    script["originalRecordedAgeSeconds"] - script["derivedAgeSeconds"]}
                for script in source["provenance"]["scripts"]]
    report_schema = "dc-route-acquisition-research-report-v2" if document["schema"] == SCHEMA_V2 else (
        "dc-route-acquisition-research-report-v1")
    return {"schema": report_schema, "revision": document["revision"],
            "asOf": document["asOf"], "registryBinding": copy.deepcopy(document["registryBinding"]),
            "locatorsBinding": copy.deepcopy(document["locatorsBinding"]), "researchOnly": True,
            "publishable": False, "installAuthorized": False, "nativeConnected": False,
            "counts": {"historicalBindings": len(rows), "heldRequests": len(rows), "newAcquisitions": 0}, "bindings": rows}
