"""旧ASUS公開metadata実測をread-onlyで共通調査台帳へ投影する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
保護stateは変更せず、許可field以外・端末内path・運用予約を出力しない。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unicodedata

from collector_registry import (RegistryError, digest, fields, json_bytes, parse_json,
                                read_json, regular_path, require, sha256, validate_registry)


def canonical_label(value: str) -> str:
    """旧表示名の連続空白とUnicode表現だけを新台帳の正規形へそろえる。"""
    return unicodedata.normalize("NFC", " ".join(value.split()))


def project(summary: dict, plan: dict, runs: dict[str, dict], revision: str, as_of: str) -> dict:
    """hash確認済みrunと公開計画を報告に結合し、旧実測の分母を保持する。"""
    require(summary["schema"] == "dc-local-feasibility-report-v1" and
            plan["schema"] == "drivercrate-collector-evaluation-plan-v1", "LEGACY_SCHEMA")
    rows = summary["rows"]
    require(isinstance(rows, list) and len(rows) == summary["scopeTargets"], "LEGACY_DENOMINATOR")
    public_products = {entry["id"]: entry for entry in plan["products"] if entry["maker"] == "ASUS"}
    require(len(public_products) == len(rows) and len({entry["id"] for entry in rows}) == len(rows),
            "LEGACY_PRODUCT_SET")
    output = {"schema": "dc-public-driver-registry-v1", "revision": revision, "asOf": as_of,
              "sources": [{"id": "asus-catalog-legacy", "manufacturer": "ASUS",
                           "officialPage": "https://www.asus.com/support/download-center/",
                           "collectionMethod": "LEGACY_ASUS_METADATA"}],
              "products": [], "records": [], "observations": []}
    success_count = 0
    record_count = 0
    # 当時の公開製品と報告のrun hashが結合する項目だけを投影する。
    for row in rows:
        require(row["id"] in public_products and row["runSha256"] in runs, "LEGACY_RUN_OR_PRODUCT")
        public_product = public_products[row["id"]]
        run = runs[row["runSha256"]]
        require(run["schema"] == "dc-collector-run-v4" and run["complete"] is True and
                len(run["targets"]) == 1, "LEGACY_RUN_SCHEMA")
        target = run["targets"][0]
        require(target["source"] == "ASUS_CATALOG" and
                target["publicModel"] == public_product["model"] == row["model"] and
                target["operatingSystem"] == "Windows 11 64-bit" and target["category"] == "LAN" and
                target["state"] == row["state"] and target["lastHttpStatus"] == row["httpStatus"] and
                target["lastAttemptAt"] == row["lastAttemptAt"] and target["error"] == row["error"] and
                target["observedRecordCount"] == row["observedRecords"], "LEGACY_TARGET_BINDING")
        expected_key = digest(f"ASUS_CATALOG\n{row['model']}\nWindows 11 64-bit\nLAN\n".encode("utf-8"))
        require(target["keySha256"] == expected_key, "LEGACY_TARGET_KEY")
        require(len(target["records"]) == row["storedRecords"] and
                [entry["fingerprint"] for entry in target["records"]] == row["recordFingerprints"],
                "LEGACY_RECORD_BINDING")
        product_id = "asus-" + row["id"].lower()
        saved = row["outcome"] == "METADATA_SAVED"
        require(saved == (target["state"] in {"UPDATED", "UNCHANGED"} and
                          target["error"] == 0 and target["lastHttpStatus"] == 200 and
                          len(target["records"]) > 0), "LEGACY_OUTCOME")
        if saved:
            require(row["observedRecords"] == row["storedRecords"], "LEGACY_OBSERVED_COUNT")
            success_count += 1
            reason = "NONE"
        else:
            require(not target["records"] and row["outcome"] in {"HELD", "FAILED"}, "LEGACY_FAILURE")
            reason = "LEGACY_PARSE_EMPTY" if row["outcome"] == "HELD" else "LEGACY_REDIRECT_REJECTED"
        product = {"id": product_id, "manufacturer": "ASUS", "model": canonical_label(public_product["model"]),
                   "driverCategory": "LAN", "sourceIds": ["asus-catalog-legacy"], "recordIds": [],
                   "researchState": "METADATA_SAVED" if saved else "RESEARCH_REQUIRED", "reason": reason}
        observed_at = datetime.fromtimestamp(target["lastAttemptAt"], tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        for position, old_record in enumerate(target["records"]):
            fields(old_record, {"fingerprint", "displayTitle", "driverCategory", "operatingSystem",
                                "packageVersion", "publishedDate"}, "LEGACY_RECORD_FIELDS")
            sha256(old_record["fingerprint"])
            require(old_record["driverCategory"] == "LAN" and
                    old_record["operatingSystem"] == "Windows 11 64-bit", "LEGACY_RECORD_SCOPE")
            record_id = "asus-r-" + old_record["fingerprint"]
            product["recordIds"].append(record_id)
            date = old_record["publishedDate"]
            normalized_date = datetime.strptime(date, "%Y/%m/%d").strftime("%Y-%m-%d") if date else None
            output["records"].append({"id": record_id, "sourceId": "asus-catalog-legacy",
                "title": canonical_label(old_record["displayTitle"]), "driverCategory": "LAN",
                "operatingSystems": ["WINDOWS_11_X64"],
                "packageVersion": canonical_label(old_record["packageVersion"]) or None,
                "driverVersion": None, "publishedDate": normalized_date, "downloadUrl": None,
                "linkState": "MISSING", "publishedSha256": None, "contentState": "NOT_DOWNLOADED"})
            output["observations"].append({"id": f"{product_id}-metadata-{position + 1}",
                "productId": product_id, "recordId": record_id, "checkedAt": observed_at,
                "kind": "LEGACY_METADATA", "method": "LEGACY_PROJECTION", "evidenceUrl": None,
                "httpStatus": 200, "evidenceSha256": row["runSha256"]})
            record_count += 1
        if not saved:
            output["observations"].append({"id": f"{product_id}-failure", "productId": product_id,
                "recordId": None, "checkedAt": observed_at, "kind": "LEGACY_FAILURE",
                "method": "LEGACY_PROJECTION", "evidenceUrl": None, "httpStatus": row["httpStatus"],
                "evidenceSha256": row["runSha256"]})
        output["products"].append(product)
    require(success_count == summary["metadataSavedProducts"] and record_count == summary["currentRecords"],
            "LEGACY_SUMMARY_COUNT")
    return validate_registry(output)


def read_runs(root: Path, wanted: set[str]) -> dict[str, dict]:
    """必要runだけをhashで選び、envelope本文hashを検証して読む。"""
    regular_path(root, directory=True)
    selected = {}
    for file in root.iterdir():
        regular_path(file)
        require(file.suffix == ".json" and file.stat().st_size <= 2 * 1024 * 1024, "LEGACY_RUN_FILE")
        with file.open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        require(len(raw) <= 2 * 1024 * 1024, "LEGACY_RUN_SIZE")
        file_hash = digest(raw)
        if file_hash not in wanted:
            continue
        envelope = parse_json(raw)
        fields(envelope, {"schema", "sha256", "body"}, "LEGACY_ENVELOPE_FIELDS")
        require(envelope["schema"] == "dc-collector-envelope-v1" and isinstance(envelope["body"], str) and
                digest(envelope["body"].encode("utf-8")) == envelope["sha256"], "LEGACY_ENVELOPE_HASH")
        selected[file_hash] = parse_json(envelope["body"].encode("utf-8"))
    require(set(selected) == wanted, "LEGACY_RUN_MISSING")
    return selected


def main() -> int:
    """旧stateを読取り専用で投影し、新規の研究用JSONだけを生成する。

    出力はxbで作成してwithで終了処理を行う。保存失敗も拒否結果へ変換するが、
    作成済み部分fileは削除せず、同じ既存pathを上書きして再試行しない。
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    try:
        summary = read_json(args.summary)
        registry = project(summary, read_json(args.plan),
                           read_runs(args.runs, {entry["runSha256"] for entry in summary["rows"]}),
                           args.revision, args.as_of)
        with args.output.open("xb") as stream:
            stream.write(json_bytes(registry))
        print(json.dumps({"result": "OK", "products": len(registry["products"]),
                          "records": len(registry["records"])}))
        return 0
    except (RegistryError, OSError, ValueError, TypeError, KeyError) as error:
        reason = str(error) if isinstance(error, RegistryError) else type(error).__name__
        print(json.dumps({"result": "REJECTED", "reason": reason}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
