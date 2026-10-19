"""公開locatorの用途別・台帳binding・根拠graphの非通信検証（ADR 0235／0237）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
保守用toolであり、公式性、同意、通信、公開、導入の権限を発行しない。
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import re
import sys
from urllib.parse import unquote

import collector_registry as cr


PROFILES = {"QUERYLESS", "PUBLIC_NUMERIC_ID", "PUBLIC_PAGE_ID", "PUBLIC_PRODUCT_PID", "PUBLIC_RESOURCE_PATH", "PUBLIC_DRIVER_SELECTOR",
            "CANON_PUBLIC_FILE_ID", "PUBLIC_DOWNLOAD_FILE_PATH"}
PURPOSES = {"PAGE", "PAYLOAD"}
LOCATOR_SCHEMA = "dc-public-driver-locators-v1"
PAIR_LOCATOR_SCHEMA = "dc-public-driver-locators-v2"
MAX_LOCATORS = 200_000  # 一回の検証予算であり、収集対象総数の上限ではない。
MAX_PRODUCT_RECORD_PAIRS = 200_000  # 明示edgeの一回検証予算である。
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_PAGE_DEPTH = 8
PAYLOAD_CONDITIONS = {"CONSENT_REQUIRED", "ACCESS_UNRESOLVED", "NO_EXTRA_PROMPT_OBSERVED"}
PUBLICATION_CONDITIONS = {"REVIEW_REQUIRED", "EXCLUDED"}


def public_locator_url(value: object, *, profile: str, purpose: str) -> str:
    """明示用途の公開selectorだけを検査し、元URLを変更せず返す。通信は行わない。"""
    cr.require(type(profile) is str and profile in PROFILES, "LOCATOR_URL_PROFILE")
    cr.require(type(purpose) is str and purpose in PURPOSES, "LOCATOR_URL_PURPOSE")
    cr.require(isinstance(value, str) and 0 < len(value) <= 2048, "URL_TYPE_OR_SIZE")
    cr.require("#" not in value, "URL_POLICY")
    base, separator, query = value.partition("?")
    # 既存のHTTPS・host・auth・control境界を再利用し、通信URLは再生成しない。
    cr.public_url(base)
    if profile == "QUERYLESS":
        cr.require(not separator, "LOCATOR_QUERY_POLICY")
    else:
        cr.require(bool(separator), "LOCATOR_QUERY_POLICY")
        if profile == "PUBLIC_NUMERIC_ID":
            cr.require(cr.public_numeric_query(query, purpose=purpose),
                "LOCATOR_QUERY_POLICY")
        elif profile == "PUBLIC_PAGE_ID":
            cr.require(purpose == "PAGE", "LOCATOR_PROFILE_PURPOSE")
            cr.require(re.fullmatch(r"idx=[0-9]{1,20}", query), "LOCATOR_QUERY_POLICY")
        elif profile == "PUBLIC_PRODUCT_PID":
            # 公開製品selectorをPAGEだけへ限定し、旧numeric predicateを変更しない。
            cr.require(purpose == "PAGE", "LOCATOR_PROFILE_PURPOSE")
            cr.require(re.fullmatch(r"pid=[0-9]{1,20}", query), "LOCATOR_QUERY_POLICY")
        elif profile == "PUBLIC_RESOURCE_PATH":
            # 公開slug pathだけをPAGE用途で扱い、decodeした値を通信URLへ書き戻さない。
            cr.require(purpose == "PAGE", "LOCATOR_PROFILE_PURPOSE")
            cr.require(query.startswith("path="), "LOCATOR_QUERY_POLICY")
            raw_path = query[5:]
            cr.require(len(raw_path) <= 1536 and re.fullmatch(r"(?:[a-z0-9_/-]|%2[Ff])+", raw_path),
                       "LOCATOR_QUERY_POLICY")
            decoded = unquote(raw_path)
            cr.require(re.fullmatch(r"/(?:[a-z0-9][a-z0-9_-]{0,63}/){1,8}", decoded),
                       "LOCATOR_QUERY_POLICY")
            cr.require(not decoded.startswith("/dp/"), "LOCATOR_PAGE_PAYLOAD_PATH")
        elif profile == "PUBLIC_DRIVER_SELECTOR":
            cr.require(purpose == "PAYLOAD", "LOCATOR_PROFILE_PURPOSE")
            cr.require(re.fullmatch(
                r"FILE_INFO=driver\|driver_file\|driver_idx\|[0-9]{1,20}\|driver", query),
                "LOCATOR_QUERY_POLICY")
        elif profile == "PUBLIC_DOWNLOAD_FILE_PATH":
            # 公開file pathをPAYLOADだけに扱い、PAGE／任意query・encodingへ拡張しない。
            cr.require(purpose == "PAYLOAD", "LOCATOR_PROFILE_PURPOSE")
            match = re.fullmatch(r"file=driver&file_link=download/driver/[0-9]{4}/"
                r"([A-Za-z0-9][A-Za-z0-9_.-]{0,255}\.(?:zip|rar|7z|cab|exe|msi))", query)
            cr.require(match is not None and ".." not in match[1], "LOCATOR_QUERY_POLICY")
        else:
            # 実観測した公開数字IDだけを許容し、別host・認証queryやPAGE要求へ転用しない。
            cr.require(purpose == "PAYLOAD", "LOCATOR_PROFILE_PURPOSE")
            cr.require(base == "https://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do",
                       "LOCATOR_CANON_ORIGIN")
            match = re.fullmatch(r"id=([A-Za-z0-9+/]{1,40}={0,2})&cmp=ACB&lang=EN", query)
            cr.require(match is not None, "LOCATOR_QUERY_POLICY")
            try:
                decoded = base64.b64decode(match[1], validate=True)
            except ValueError as error:
                raise cr.RegistryError("LOCATOR_CANON_ENCODING") from error
            cr.require(re.fullmatch(rb"[0-9]{1,20}", decoded) is not None and
                       base64.b64encode(decoded).decode("ascii") == match[1],
                       "LOCATOR_CANON_PUBLIC_ID")
    return value


def registry_binding(registry: dict) -> dict:
    """検証済み元台帳の正規byteへsidecarを結合する。署名や公式性は保証しない。"""
    return {"schema": registry["schema"], "revision": registry["revision"],
            "asOf": registry["asOf"], "sha256": cr.digest(cr.json_bytes(registry))}


def enum_value(value: object, allowed: set[str], code: str) -> str:
    """未知文字列とcontainer・bool等の型混同をcodeだけで拒否する。"""
    cr.require(type(value) is str and value in allowed, code)
    return value


def product_record_pairs(value: object, product_ids: list[str], record_ids: list[str],
                         products: dict) -> list[dict]:
    """v2の閉じた明示組を元台帳へ照合し、省略・追加・重複を拒否する。"""
    cr.require(type(value) is list and len(value) <= MAX_PRODUCT_RECORD_PAIRS, "LOCATOR_PAIRS_COUNT")
    product_set, record_set, seen = set(product_ids), set(record_ids), set()
    for raw in value:
        pair = cr.fields(raw, {"productId", "recordId"}, "LOCATOR_PAIR_FIELDS")
        product_id, record_id = cr.identity(pair["productId"]), cr.identity(pair["recordId"])
        cr.require(product_id in product_set and record_id in record_set and
                   record_id in products[product_id]["recordIds"], "LOCATOR_PAIR_BINDING")
        cr.require((product_id, record_id) not in seen, "LOCATOR_PAIR_DUPLICATE")
        seen.add((product_id, record_id))
    expected = set()
    # PAGE_ONLYも残しつつ、掲載を結合した各recordの全明示製品対応を有限列挙する。
    for product_id in product_ids:
        for record_id in products[product_id]["recordIds"]:
            if record_id in record_set:
                expected.add((product_id, record_id))
                cr.require(len(expected) <= MAX_PRODUCT_RECORD_PAIRS, "LOCATOR_PAIRS_COUNT")
    cr.require(seen == expected and {record_id for _, record_id in seen} == record_set,
               "LOCATOR_PAIRS_GRAPH")
    return [{"productId": product_id, "recordId": record_id} for product_id, record_id in sorted(seen)]


def validate_locators(value: object, registry: object) -> dict:
    """元台帳・公開根拠graphと同意待ち条件を検査し、新しい正規形を返す。通信は行わない。"""
    registry = cr.validate_registry(registry)
    document = cr.fields(value, {"schema", "revision", "asOf", "registry", "researchOnly",
                                 "publishable", "installAuthorized", "locators"}, "LOCATOR_FIELDS")
    cr.require(type(document["schema"]) is str and document["schema"] in
               {LOCATOR_SCHEMA, PAIR_LOCATOR_SCHEMA}, "LOCATOR_SCHEMA")
    explicit_pairs = document["schema"] == PAIR_LOCATOR_SCHEMA
    cr.label(document["revision"])
    as_of = cr.timestamp(document["asOf"])
    cr.require(as_of >= cr.timestamp(registry["asOf"]), "LOCATOR_TIME_BINDING")
    cr.fields(document["registry"], {"schema", "revision", "asOf", "sha256"}, "LOCATOR_BINDING_FIELDS")
    cr.require(document["registry"] == registry_binding(registry), "LOCATOR_REGISTRY_BINDING")
    cr.require(document["researchOnly"] is True and document["publishable"] is False and
               document["installAuthorized"] is False, "LOCATOR_SAFETY_FLAGS")
    rows = document["locators"]
    cr.require(isinstance(rows, list) and 0 < len(rows) <= MAX_LOCATORS, "LOCATOR_COUNT")
    sources = {row["id"]: row for row in registry["sources"]}
    products = {row["id"]: row for row in registry["products"]}
    records = {row["id"]: row for row in registry["records"]}
    # 元台帳のroot実観測をURL・日時・hash・製品単位で検査し、deep hashの転用を防ぐ。
    root_evidence = {(row["productId"], row["evidenceUrl"], row["checkedAt"], row["evidenceSha256"])
                     for row in registry["observations"]
                     if row["kind"] in {"OFFICIAL_PAGE", "OFFICIAL_LINK"} and
                     row["method"] == "LOCAL_HTTP" and row["httpStatus"] == 200 and
                     row["evidenceSha256"] is not None}
    by_id = {}
    urls = set()
    pair_count = 0
    # 全rowのfield・型・台帳参照を先に検査し、graph検査中の未知値を排除する。
    for raw in rows:
        row_fields = {"id", "sourceId", "purpose", "url", "urlProfile", "productIds",
                             "recordIds", "parentPageIds", "requestCondition",
                             "publicationCondition", "pageObservation"}
        if explicit_pairs:
            row_fields.add("productRecordPairs")
        row = cr.fields(raw, row_fields, "LOCATOR_ROW_FIELDS")
        identifier = cr.identity(row["id"])
        cr.require(identifier not in by_id, "LOCATOR_DUPLICATE_ID")
        source_id = cr.identity(row["sourceId"])
        cr.require(source_id in sources, "LOCATOR_SOURCE")
        purpose = enum_value(row["purpose"], PURPOSES, "LOCATOR_PURPOSE")
        url = public_locator_url(row["url"], profile=row["urlProfile"], purpose=purpose)
        cr.require((purpose, url) not in urls, "LOCATOR_DUPLICATE_URL")
        urls.add((purpose, url))
        product_ids = cr.id_list(row["productIds"])
        record_ids = cr.id_list(row["recordIds"], allow_empty=True)
        parents = cr.id_list(row["parentPageIds"], allow_empty=True)
        enum_value(row["publicationCondition"], PUBLICATION_CONDITIONS, "LOCATOR_PUBLICATION")
        # 各製品は登録sourceに属し、全recordとの対応が元台帳に明示されている必要がある。
        for product_id in product_ids:
            cr.require(product_id in products and source_id in products[product_id]["sourceIds"],
                       "LOCATOR_PRODUCT_SOURCE")
            # v1の全製品共通record規則を維持し、v2だけは明示組で別途照合する。
            if not explicit_pairs:
                cr.require(set(record_ids) <= set(products[product_id]["recordIds"]), "LOCATOR_PRODUCT_RECORD")
        for record_id in record_ids:
            cr.require(record_id in records and records[record_id]["sourceId"] == source_id,
                       "LOCATOR_RECORD_SOURCE")
        pairs = None
        if explicit_pairs:
            pairs = product_record_pairs(row["productRecordPairs"], product_ids, record_ids, products)
            pair_count += len(pairs)
            cr.require(pair_count <= MAX_PRODUCT_RECORD_PAIRS, "LOCATOR_PAIRS_TOTAL")
        observation = row["pageObservation"]
        if purpose == "PAGE":
            cr.require(row["requestCondition"] == "PUBLIC_METADATA", "LOCATOR_PAGE_CONDITION")
            cr.require(len(parents) <= 1, "LOCATOR_PAGE_PARENTS")
            cr.fields(observation, {"method", "httpStatus", "bodyBytes", "bodySha256", "checkedAt"},
                      "LOCATOR_PAGE_OBSERVATION_FIELDS")
            cr.require(observation["method"] == "LOCAL_HTTP" and
                       type(observation["httpStatus"]) is int and observation["httpStatus"] == 200,
                       "LOCATOR_PAGE_OBSERVATION")
            cr.require(type(observation["bodyBytes"]) is int and
                       0 < observation["bodyBytes"] <= MAX_PAGE_BYTES, "LOCATOR_PAGE_BYTES")
            cr.sha256(observation["bodySha256"])
            cr.require(observation["bodySha256"] is not None, "LOCATOR_PAGE_HASH")
            cr.require(cr.observation_timestamp(observation["checkedAt"]) <= as_of, "LOCATOR_OBSERVATION_TIME")
            if not parents:
                cr.require(url == sources[source_id]["officialPage"], "LOCATOR_ROOT_URL")
                cr.require(all((pid, url, observation["checkedAt"], observation["bodySha256"])
                               in root_evidence for pid in product_ids), "LOCATOR_ROOT_EVIDENCE")
        else:
            enum_value(row["requestCondition"], PAYLOAD_CONDITIONS, "LOCATOR_PAYLOAD_CONDITION")
            cr.require(len(record_ids) == 1 and bool(parents), "LOCATOR_PAYLOAD_REFERENCES")
            if explicit_pairs:
                cr.require({pair["productId"] for pair in pairs} == set(product_ids),
                           "LOCATOR_PAYLOAD_PAIR_PRODUCTS")
            cr.require(observation is None, "LOCATOR_PAYLOAD_OBSERVATION")
            cr.require(records[record_ids[0]]["downloadUrl"] in (None, url), "LOCATOR_EXISTING_URL")
        by_id[identifier] = {**row, "productIds": sorted(product_ids), "recordIds": sorted(record_ids),
                             "parentPageIds": sorted(parents),
                             "pageObservation": dict(observation) if observation is not None else None}
        if explicit_pairs:
            by_id[identifier]["productRecordPairs"] = pairs
    # PAGE参照と各edgeの製品・配布対応を検査し、別sourceの根拠を借用しない。
    for row in by_id.values():
        parent_products = set()
        parent_pairs = set()
        for parent_id in row["parentPageIds"]:
            cr.require(parent_id in by_id, "LOCATOR_PARENT_MISSING")
            parent = by_id[parent_id]
            cr.require(parent["purpose"] == "PAGE" and parent["sourceId"] == row["sourceId"],
                       "LOCATOR_PARENT_SOURCE_OR_PURPOSE")
            parent_products.update(parent["productIds"])
            if row["purpose"] == "PAGE":
                cr.require(set(row["productIds"]) <= set(parent["productIds"]), "LOCATOR_PAGE_PRODUCTS")
            else:
                cr.require(set(row["recordIds"]) <= set(parent["recordIds"]), "LOCATOR_PAYLOAD_EVIDENCE")
                if explicit_pairs:
                    parent_pairs.update((pair["productId"], pair["recordId"])
                        for pair in parent["productRecordPairs"] if pair["recordId"] in row["recordIds"])
        if row["purpose"] == "PAYLOAD":
            if explicit_pairs:
                cr.require(parent_pairs == {(pair["productId"], pair["recordId"])
                    for pair in row["productRecordPairs"]}, "LOCATOR_PAYLOAD_PAIRS")
            else:
                cr.require(parent_products == set(row["productIds"]), "LOCATOR_PAYLOAD_PRODUCTS")
    # 全PAGEを有限深度でrootまで辿り、自己参照・循環・過大graphを拒否する。
    for row in by_id.values():
        if row["purpose"] != "PAGE":
            continue
        current = row
        seen = set()
        for _ in range(MAX_PAGE_DEPTH):
            cr.require(current["id"] not in seen, "LOCATOR_PAGE_CYCLE")
            seen.add(current["id"])
            if not current["parentPageIds"]:
                break
            current = by_id[current["parentPageIds"][0]]
        else:
            raise cr.RegistryError("LOCATOR_PAGE_DEPTH")
    normalized = {**document, "registry": registry_binding(registry),
                  "locators": sorted(by_id.values(), key=lambda row: row["id"])}
    cr.require(len(cr.json_bytes(normalized)) <= cr.MAX_JSON_BYTES, "LOCATOR_JSON_SIZE")
    return normalized


def locator_counts(value: dict) -> dict:
    """検証済みlocatorの保存数だけを集計し、実取得・内容合格へ加算しない。"""
    rows = value["locators"]
    pages = [row for row in rows if row["purpose"] == "PAGE"]
    payloads = [row for row in rows if row["purpose"] == "PAYLOAD"]
    return {"pageLocators": len(pages), "payloadLocators": len(payloads),
            "payloadRecordReferences": len({rid for row in payloads for rid in row["recordIds"]}),
            "payloadProductReferences": len({pid for row in payloads for pid in row["productIds"]}),
            "productRecordEdges": sum(len(row["productIds"]) for row in payloads),
            "consentRequiredPayloads": sum(row["requestCondition"] == "CONSENT_REQUIRED" for row in payloads),
            "payloadRequestsAuthorized": 0, "publishable": False, "installAuthorized": False}


def main() -> int:
    """入力fileを非通信検証し、URL・pathを含まない件数とhashだけを表示する。"""
    parser = argparse.ArgumentParser(description="公開locator sidecarの非通信検証。通信・導入は行わない。")
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--locators", type=Path, required=True)
    options = parser.parse_args()
    try:
        value = validate_locators(cr.read_json(options.locators), cr.read_json(options.registry))
        print(cr.json_bytes({"schema": value["schema"], "revision": value["revision"],
                             "sha256": cr.digest(cr.json_bytes(value)),
                             "counts": locator_counts(value)}).decode("utf-8"), end="")
    except cr.RegistryError as error:
        print("REJECTED:" + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("REJECTED:IO_ERROR", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
