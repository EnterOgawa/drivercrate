"""大型保守planと研究用取得証拠の非通信検証（ADR 0242）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
旧schemaを拡張せず、本体・実端末情報・期限付き署名を出力しない。
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import collector_registry as cr
import collector_payload_evidence as pe


PLAN_SCHEMA = "dc-sample-acquisition-plan-v3"
EVIDENCE_SCHEMA = "dc-large-payload-evidence-v1"
GIB = 1024 ** 3
NATIVE_INPUT_BYTES = 128 * 1024 ** 2


def validate_plan(registry: dict, plan: dict) -> dict:
    """明示予算・登録record・route・非同意claimを有限検査する。通信しない。"""
    registry = cr.validate_registry(registry)
    cr.fields(plan, {"schema", "revision", "maximumTotalBytes", "reserveFreeBytes", "items"}, "PLAN_FIELDS")
    cr.require(plan["schema"] == PLAN_SCHEMA, "PLAN_SCHEMA")
    cr.identity(plan["revision"])
    cr.require(type(plan["maximumTotalBytes"]) is int and 0 < plan["maximumTotalBytes"] <= 4 * GIB,
               "BATCH_BUDGET")
    cr.require(type(plan["reserveFreeBytes"]) is int and 2 * GIB <= plan["reserveFreeBytes"] <= 16 * GIB,
               "RESERVE_BUDGET")
    cr.require(isinstance(plan["items"], list) and 1 <= len(plan["items"]) <= 4, "PLAN_ITEMS")
    records = {r["id"]: r for r in registry["records"]}
    sources = {s["id"]: s for s in registry["sources"]}
    seen = set()
    budget = 0
    for item in plan["items"]:
        cr.fields(item, {"recordId", "maximumBytes", "maximumSeconds", "format", "preDownloadConsent",
                         "route", "publicModel"}, "PLAN_ITEM_FIELDS")
        record_id = item["recordId"]
        cr.require(isinstance(record_id, str) and record_id in records and record_id not in seen, "PLAN_RECORD")
        seen.add(record_id)
        record = records[record_id]
        cr.require(record["downloadUrl"] is not None, "PLAN_LINK")
        cr.require(type(item["maximumBytes"]) is int and 0 < item["maximumBytes"] <= 2 * GIB, "PLAN_BYTES")
        cr.require(type(item["maximumSeconds"]) is int and 1 <= item["maximumSeconds"] <= 1800, "PLAN_SECONDS")
        cr.require(item["format"] in {"ZIP", "EXE"} and
                   item["preDownloadConsent"] == "NO_GATE_OBSERVED", "PLAN_ITEM_POLICY")
        cr.require(item["route"] in {"DIRECT", "ASUS_PUBLIC_CDN_SESSION"}, "PLAN_ROUTE")
        if item["route"] == "DIRECT":
            cr.require(item["publicModel"] is None, "PLAN_MODEL")
        else:
            from urllib.parse import quote, urlsplit
            import re
            model = item["publicModel"]
            source = sources[record["sourceId"]]
            cr.require(isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 -]{0,127}", model)
                       is not None, "ASUS_ROUTE_POLICY")
            url = urlsplit(record["downloadUrl"])
            cr.require(item["format"] == "ZIP" and source["manufacturer"] == "ASUS" and
                       source["collectionMethod"] == "MANUAL_RESEARCH" and
                       record["publishedSha256"] is not None and
                       source["officialPage"] == "https://www.asus.com/jp/supportonly/" +
                       quote(model.lower(), safe="") + "/helpdesk_download/" and
                       url.scheme == "https" and url.netloc == "dlcdnta.asus.com" and
                       not url.query and not url.fragment and
                       re.fullmatch(r"/pub/ASUS/mb/[A-Za-z0-9]+/[A-Za-z0-9_.-]+\.zip", url.path)
                       is not None, "ASUS_ROUTE_POLICY")
        budget += item["maximumBytes"]
    cr.require(budget <= plan["maximumTotalBytes"], "BATCH_BUDGET")
    return plan


def validate_large_evidence(registry: dict, document: dict) -> dict:
    """取得rowをplanの各上限・hash・台帳・未対応区分へ結合し、旧schemaと混同させない。"""
    cr.fields(document, {"schema", "plan", "planSha256", "evidence"}, "LARGE_EVIDENCE_FIELDS")
    cr.require(document["schema"] == EVIDENCE_SCHEMA, "LARGE_EVIDENCE_SCHEMA")
    plan = validate_plan(registry, document["plan"])
    cr.require(document["planSha256"] == cr.digest(cr.json_bytes(plan)), "PLAN_HASH_BINDING")
    evidence = document["evidence"]
    cr.require(evidence.get("schema") == pe.EVIDENCE_SCHEMA and
               evidence.get("revision") == plan["revision"], "LARGE_EVIDENCE_BINDING")
    normalized = pe._validate_evidence(registry, evidence, maximum_payload_bytes=2 * GIB)
    items = {i["recordId"]: i for i in plan["items"]}
    cr.require({r["recordId"] for r in normalized["acquisitions"]} == set(items), "PLAN_RECORD_BINDING")
    total = 0
    for row in normalized["acquisitions"]:
        item = items[row["recordId"]]
        cr.require(row["bytes"] <= item["maximumBytes"], "PLAN_PAYLOAD_BUDGET")
        total += row["bytes"]
        if row["state"] == "DOWNLOADED":
            if item["format"] == "EXE" or row["bytes"] > NATIVE_INPUT_BYTES:
                cr.require(row["inspection"] == "UNSUPPORTED", "NATIVE_INPUT_UNSUPPORTED")
            else:
                cr.require(row["inspection"] in {"PASSED", "PARTIAL", "REJECTED"}, "NATIVE_INSPECTION_MISSING")
        if item["format"] == "ZIP":
            cr.require(row["outerSignature"] == "NOT_CHECKED" and row["publisher"] is None,
                       "ZIP_OUTER_SIGNATURE")
    cr.require(total <= plan["maximumTotalBytes"], "BATCH_PAYLOAD_BUDGET")
    return {**document, "evidence": normalized}


def main() -> int:
    """非通信のCLI。秘密を含む例外全文ではなく既存共通toolの拒否codeだけを返す。"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("plan", "evidence"))
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        registry = cr.read_json(args.registry)
        value = cr.read_json(args.input)
        validated = validate_plan(registry, value) if args.mode == "plan" else validate_large_evidence(registry, value)
        print(cr.digest(cr.json_bytes(validated)))
        return 0
    except cr.RegistryError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
