"""外部調査台帳の保守用日次監視・差分・再調査待ち（ADR 0229／0236／0293）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Metadata・索引・driverを変更しない。Native保護store／Task接続は未実装。
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

import collector_registry as cr
import collector_public_locators as pl
from registry_locator_requests import HOLD_REASONS, locator_requests
from registry_page_requests import page_requests
from registry_monitor_http import CurlTransport, MAX_BODY


STATE_SCHEMA = "dc-registry-monitor-state-v1"
DAY = timedelta(days=1)
MAX_REQUESTS = 64
MAX_RUN_BYTES = 32 * 1024 * 1024
MAX_RUN_SECONDS = 600
ERRORS = {"NONE", "DNS_EMPTY", "DNS_FAILED", "PRIVATE_DNS", "HEADER_SIZE", "HTTP_ERROR",
          "TRANSFER_FAILED", "BODY_SIZE", "CONTENT_TYPE", "CONTENT_ENCODING", "TEXT_ENCODING",
          "HTML_STRUCTURE", "TIMEOUT", "TRANSPORT_FAILED", "UNKNOWN_OUTCOME",
          "PROXY_ROUTE_UNSUPPORTED", "PROXY_AUTH_UNSUPPORTED", "PROXY_CONFIG_FAILED",
          "PROXY_RESOLUTION_FAILED", "PROXY_RESOLUTION_TIMEOUT"}
NATIVE_PAGE_HOLDS = {"NATIVE_SHARED_REQUEST_HELD", "NATIVE_SHARED_HOST_HELD"}
HOLD_REASONS = HOLD_REASONS | NATIVE_PAGE_HOLDS


def utc_now() -> datetime:
    """内部時計だけを使用し、CLIから仮想日時を指定させない。"""
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_text(value: str) -> str:
    return cr.digest(value.encode("utf-8"))


def validate_policy(registry: dict, policy: dict) -> dict:
    cr.fields(policy, {"schema", "revision", "heldSourceIds"}, "MONITOR_POLICY_FIELDS")
    cr.require(policy["schema"] == "dc-registry-monitor-policy-v1", "MONITOR_POLICY_SCHEMA")
    cr.identity(policy["revision"])
    held = policy["heldSourceIds"]
    cr.require(isinstance(held, list) and all(isinstance(value, str) for value in held) and
               len(held) == len(set(held)) and set(held) <= {row["id"] for row in registry["sources"]},
               "MONITOR_POLICY_SOURCES")
    return {**policy, "heldSourceIds": sorted(held)}


def make_requests(registry: dict, policy: dict) -> list[dict]:
    """同一method・URLを共有し、登録済み対象だけを監視する。"""
    combined = {}
    products = registry["products"]
    by_record = {row["id"]: row for row in registry["records"]}
    for source in registry["sources"]:
        records = [row for row in registry["records"] if row["sourceId"] == source["id"]]
        page_record_ids = {row["recordId"] for row in registry["observations"]
                           if row["kind"] == "OFFICIAL_LINK" and row["recordId"] is not None and
                           row["evidenceUrl"] == source["officialPage"]}
        page_record_ids.update(row["id"] for row in records)
        observed_links = {hash_text(by_record[row["recordId"]]["downloadUrl"])
                          for row in registry["observations"] if row["kind"] == "OFFICIAL_LINK" and row["recordId"] is not None and
                          row["evidenceUrl"] == source["officialPage"]}
        definitions = [("PAGE", source["officialPage"], sorted(page_record_ids))]
        definitions += [("LINK", row["downloadUrl"], [row["id"]]) for row in records if row["downloadUrl"]]
        for kind, url, record_ids in definitions:
            key = hash_text(kind + "\n" + url)
            item = combined.setdefault(key, {"id": key, "kind": kind, "url": url,
                                            "sourceIds": set(), "recordIds": set(), "productIds": set(),
                                            "held": False, "expectedLinks": set()})
            item["sourceIds"].add(source["id"])
            item["recordIds"].update(record_ids)
            item["productIds"].update(row["id"] for row in products if source["id"] in row["sourceIds"] and
                                      (kind == "PAGE" or set(row["recordIds"]) & set(record_ids)))
            item["held"] |= source["id"] in policy["heldSourceIds"]
            if kind == "PAGE":
                item["expectedLinks"].update(observed_links)
    result = []
    for _, item in sorted(combined.items()):
        for field in ("sourceIds", "recordIds", "productIds", "expectedLinks"):
            item[field] = sorted(item[field])
        result.append(item)
    return result


def validate_state(state: dict) -> dict:
    """日時・待機・旧成功の整合性を確認し、未知stateを修復しない。"""
    cr.fields(state, {"schema", "createdAt", "observedAt", "requests", "hosts"}, "MONITOR_STATE_FIELDS")
    cr.require(state["schema"] == STATE_SCHEMA, "MONITOR_STATE_SCHEMA")
    created = cr.timestamp(state["createdAt"])
    observed = cr.timestamp(state["observedAt"])
    cr.require(created <= observed, "MONITOR_CLOCK")
    cr.require(isinstance(state["requests"], dict) and isinstance(state["hosts"], dict), "MONITOR_MAP")
    for key, row in state["requests"].items():
        cr.sha256(key)
        cr.require(key is not None, "REQUEST_KEY")
        cr.fields(row, {"kind", "locatorSha256", "hostSha256", "attemptedAt", "endedAt", "nextDueAt", "outcome",
                        "httpStatus", "reason", "lastSuccess"}, "REQUEST_FIELDS")
        cr.require(row["kind"] in {"PAGE", "LINK"}, "REQUEST_KIND")
        cr.sha256(row["locatorSha256"])
        cr.sha256(row["hostSha256"])
        cr.require(row["locatorSha256"] is not None and row["hostSha256"] is not None, "REQUEST_LOCATOR")
        attempted = cr.timestamp(row["attemptedAt"])
        ended = cr.timestamp(row["endedAt"]) if row["endedAt"] else attempted
        due = cr.timestamp(row["nextDueAt"])
        cr.require(created <= attempted <= ended <= observed and due >= ended + DAY, "REQUEST_TIME")
        cr.require(row["outcome"] in {"IN_PROGRESS", "SUCCESS", "FAILED", "UNKNOWN_OUTCOME"}, "REQUEST_OUTCOME")
        cr.require((row["outcome"] == "IN_PROGRESS") == (row["endedAt"] is None), "RESERVATION_TIME")
        status = row["httpStatus"]
        cr.require(status is None or (type(status) is int and 100 <= status <= 599), "HTTP_STATUS")
        cr.require(row["reason"] in ERRORS and (row["reason"] == "NONE") ==
                   (row["outcome"] in {"IN_PROGRESS", "SUCCESS"}), "REQUEST_REASON")
        success = row["lastSuccess"]
        if success is not None:
            cr.fields(success, {"checkedAt", "bodySha256", "bodyBytes", "linkHashes"}, "SUCCESS_FIELDS")
            cr.require(created <= cr.timestamp(success["checkedAt"]) <= ended, "SUCCESS_TIME")
            cr.sha256(success["bodySha256"])
            cr.require(type(success["bodyBytes"]) is int and 0 <= success["bodyBytes"] <= MAX_BODY, "SUCCESS_BYTES")
            hashes = success["linkHashes"]
            cr.require(isinstance(hashes, list) and hashes == sorted(set(hashes)), "SUCCESS_LINKS")
            for value in hashes:
                cr.sha256(value)
                cr.require(value is not None, "SUCCESS_LINK_HASH")
            cr.require((row["kind"] == "PAGE" and success["bodySha256"] is not None and success["bodyBytes"] > 0) or
                       (row["kind"] == "LINK" and success["bodySha256"] is None and success["bodyBytes"] == 0 and not hashes),
                       "SUCCESS_KIND")
        if row["outcome"] == "SUCCESS":
            cr.require(status == 200 and success is not None and success["checkedAt"] == row["endedAt"], "SUCCESS_BINDING")
        elif success is not None:
            cr.require(cr.timestamp(success["checkedAt"]) <= attempted, "OLD_SUCCESS_TIME")
        if row["outcome"] == "UNKNOWN_OUTCOME":
            cr.require(row["reason"] == "UNKNOWN_OUTCOME" and status is None, "UNKNOWN_CLAIM")
    for key, row in state["hosts"].items():
        cr.sha256(key)
        cr.require(key is not None, "HOST_KEY")
        cr.fields(row, {"failedAt", "nextDueAt", "held"}, "HOST_FIELDS")
        cr.require(created <= cr.timestamp(row["failedAt"]) <= observed and
                   cr.timestamp(row["nextDueAt"]) >= cr.timestamp(row["failedAt"]) + DAY and
                   type(row["held"]) is bool, "HOST_TIME")
    return state


def envelope(schema: str, payload: dict) -> bytes:
    return cr.json_bytes({"schema": schema, "sha256": cr.digest(cr.json_bytes(payload)), "payload": payload})


def read_envelope(path: Path, schema: str) -> dict:
    document = cr.read_json(path)
    cr.fields(document, {"schema", "sha256", "payload"}, "MONITOR_ENVELOPE_FIELDS")
    cr.require(document["schema"] == schema and document["sha256"] == cr.digest(cr.json_bytes(document["payload"])),
               "MONITOR_ENVELOPE_HASH")
    return document["payload"]


def validate_import_metadata(document: dict) -> dict:
    """移設の申告と元exportの指紋を検証し、通信許可として扱わない。"""
    cr.fields(document, {"schema", "manifestSha256", "sourceObservedAt", "sourceStopAcknowledged"},
              "IMPORT_METADATA_FIELDS")
    cr.require(document["schema"] == "dc-registry-monitor-import-v1", "IMPORT_METADATA_SCHEMA")
    cr.sha256(document["manifestSha256"])
    cr.require(document["manifestSha256"] is not None, "IMPORT_MANIFEST_HASH")
    cr.timestamp(document["sourceObservedAt"])
    cr.require(document["sourceStopAcknowledged"] is True, "IMPORT_SOURCE_STOP_REQUIRED")
    return document


def layout(root: Path, *, allow_import_stage: bool = False) -> None:
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    cr.require(allow_import_stage or ".import-" not in root.name, "IMPORT_NOT_PUBLISHED")
    names = {path.name for path in root.iterdir()}
    expected = {"state.json", "writer.lock", "reports"}
    if "distribution-init-v1.json" in names:
        marker = cr.read_json(root / "distribution-init-v1.json")
        cr.fields(marker, {"schema", "createdAt"}, "DISTRIBUTION_INITIALIZATION_FIELDS")
        cr.require(marker["schema"] == "dc-collector-distribution-initialization-v1", "DISTRIBUTION_INITIALIZATION_SCHEMA")
        cr.timestamp(marker["createdAt"])
        expected.add("distribution-init-v1.json")
    if "distribution" in names:
        import collector_distribution_pipeline as distribution
        if (root / "distribution/journal.json").exists():
            distribution.verify_layout(root / "distribution")
        else:
            cr.require("distribution-init-v1.json" in names and
                       {path.name for path in (root / "distribution").iterdir()} <= {"runs"},
                       "DISTRIBUTION_INITIALIZATION_CHANGED")
            if (root / "distribution/runs").exists():
                cr.regular_path(root / "distribution/runs", directory=True)
                cr.require(not any((root / "distribution/runs").iterdir()), "DISTRIBUTION_INITIALIZATION_CHANGED")
        expected.add("distribution")
    if "import-metadata.json" in names:
        validate_import_metadata(cr.read_json(root / "import-metadata.json"))
        expected.add("import-metadata.json")
    cr.require(names == expected, "MONITOR_FILE_SET")
    cr.regular_path(root / "writer.lock")
    cr.regular_path(root / "reports", directory=True)


def report_counts(items: list[dict], queue: list[dict], recovered: list[str]) -> dict:
    """表示件数を行から再計算し、未試行を成功へ含めない。"""
    attempted = {"BASELINE", "UNCHANGED", "CHANGED", "LINK_ALIVE", "FAILED"}
    return {"targetProducts": len({key for row in items for key in row["productIds"]}),
            "sources": len({key for row in items for key in row["sourceIds"]}),
            "plannedRequests": len(items), "attempted": sum(row["state"] in attempted for row in items),
            "bodyBytes": sum(row["bodyBytes"] for row in items),
            "budgetBytes": sum(MAX_BODY if row["state"] == "FAILED" else row["bodyBytes"] for row in items),
            "recoveredReservations": len(recovered), "reviewItems": len(queue),
            **{name.lower(): sum(row["state"] == name for row in items)
               for name in ("BASELINE", "UNCHANGED", "CHANGED", "LINK_ALIVE", "FAILED", "HELD", "DEFERRED")}}


def validate_report(report: dict) -> dict:
    """公開ID・状態・hash・件数を検証し、本文や未知fieldの混入を拒否する。"""
    cr.require(isinstance(report, dict), "MONITOR_REPORT_FIELDS")
    page_mode = report.get("schema") == "dc-registry-monitor-report-v3"
    locator_mode = report.get("schema") == "dc-registry-monitor-report-v2" or page_mode
    cr.fields(report, {"schema", "id", "registrySha256", "policySha256", "startedAt", "finishedAt",
                       "items", "reviewQueue", "recoveredRequestIds", "counts"} |
              ({"locatorsSha256"} if locator_mode else set()) |
              ({"requestScope"} if page_mode else set()), "MONITOR_REPORT_FIELDS")
    cr.require(type(report["schema"]) is str and report["schema"] in
               {"dc-registry-monitor-report-v1", "dc-registry-monitor-report-v2", "dc-registry-monitor-report-v3"},
               "MONITOR_REPORT_SCHEMA")
    if page_mode:
        cr.require(report["requestScope"] == "REGISTERED_PAGES_ONLY", "REPORT_PAGE_SCOPE")
    if locator_mode:
        cr.sha256(report["locatorsSha256"])
        cr.require(report["locatorsSha256"] is not None, "REPORT_LOCATOR_BINDING")
    cr.identity(report["id"])
    for field in ("registrySha256", "policySha256"):
        cr.sha256(report[field])
        cr.require(report[field] is not None, "REPORT_BINDING")
    finished = cr.timestamp(report["finishedAt"])
    cr.require(cr.timestamp(report["startedAt"]) <= finished, "MONITOR_REPORT_TIME")
    cr.require(isinstance(report["items"], list) and isinstance(report["reviewQueue"], list), "MONITOR_REPORT_TYPES")
    seen = set()
    for row in report["items"]:
        cr.fields(row, {"id", "kind", "sourceIds", "recordIds", "productIds", "state", "reason", "httpStatus",
                        "previousSha256", "observedSha256", "bodyBytes", "checkedAt", "nextDueAt"} |
                  ({"locatorIds"} if locator_mode else set()), "REPORT_ITEM_FIELDS")
        cr.sha256(row["id"])
        cr.require(row["id"] is not None and row["id"] not in seen, "REPORT_ITEM_ID")
        seen.add(row["id"])
        cr.require(row["kind"] in {"PAGE", "LINK"}, "REPORT_ITEM_KIND")
        if page_mode:
            cr.require(row["kind"] == "PAGE", "REPORT_PAGE_SCOPE")
        for field in ("sourceIds", "recordIds", "productIds"):
            values = row[field]
            cr.require(isinstance(values, list) and values == sorted(set(values)), "REPORT_REFERENCES")
            for value in values:
                cr.identity(value)
        cr.require(bool(row["sourceIds"]), "REPORT_SOURCE")
        if locator_mode:
            cr.id_list(row["locatorIds"], allow_empty=page_mode)
            cr.require(row["locatorIds"] == sorted(row["locatorIds"]), "REPORT_LOCATOR_IDS")
        cr.require(type(row["bodyBytes"]) is int and 0 <= row["bodyBytes"] <= MAX_BODY, "REPORT_BYTES")
        for field in ("previousSha256", "observedSha256"):
            cr.sha256(row[field])
        status = row["httpStatus"]
        cr.require(status is None or (type(status) is int and 100 <= status <= 599), "HTTP_STATUS")
        checked = cr.timestamp(row["checkedAt"]) if row["checkedAt"] else None
        if checked:
            cr.require(checked <= finished, "REPORT_CHECKED_TIME")
        if row["nextDueAt"] is not None:
            due = cr.timestamp(row["nextDueAt"])
            cr.require(checked is None or due >= checked + DAY, "REPORT_DUE_TIME")
        outcome = row["state"]
        cr.require(outcome in {"BASELINE", "UNCHANGED", "CHANGED", "LINK_ALIVE", "FAILED", "HELD", "DEFERRED"},
                   "REPORT_OUTCOME")
        if outcome in {"BASELINE", "UNCHANGED", "CHANGED", "LINK_ALIVE"}:
            cr.require(status == 200 and checked is not None and row["reason"] == "NONE", "REPORT_SUCCESS")
            if outcome == "LINK_ALIVE":
                cr.require(row["kind"] == "LINK" and row["bodyBytes"] == 0 and row["observedSha256"] is None,
                           "REPORT_HEAD")
            else:
                cr.require(row["kind"] == "PAGE" and row["bodyBytes"] > 0 and row["observedSha256"] is not None,
                           "REPORT_PAGE")
                cr.require((outcome == "BASELINE" and row["previousSha256"] is None) or
                           (outcome == "UNCHANGED" and row["previousSha256"] == row["observedSha256"]) or
                           (outcome == "CHANGED" and row["previousSha256"] is not None and
                            row["previousSha256"] != row["observedSha256"]), "REPORT_CHANGE")
        elif outcome == "FAILED":
            cr.require(row["reason"] in ERRORS - {"NONE", "UNKNOWN_OUTCOME"} and checked is not None and
                       row["observedSha256"] is None, "REPORT_FAILURE")
        elif outcome == "HELD":
            holds = HOLD_REASONS if locator_mode else {"NATIVE_COORDINATION_PENDING"}
            cr.require(row["reason"] in holds and row["bodyBytes"] == 0, "REPORT_HOLD")
            if row["reason"] in NATIVE_PAGE_HOLDS:
                cr.require(page_mode and row["kind"] == "PAGE", "REPORT_NATIVE_PAGE_HOLD")
            elif row["reason"] != "NATIVE_COORDINATION_PENDING":
                cr.require(row["kind"] == "LINK", "REPORT_PAYLOAD_HOLD")
        else:
            reasons = {"WAIT_24H", "HOST_REVIEW_REQUIRED", "HOST_COOLDOWN", "RUN_BUDGET"} | (
                {"OBSERVATION_WAIT_24H"} if locator_mode else set())
            cr.require(row["reason"] in reasons and
                       row["bodyBytes"] == 0, "REPORT_DEFERRED")
            if row["reason"] == "OBSERVATION_WAIT_24H":
                cr.require(row["kind"] == "PAGE" and checked is not None and row["nextDueAt"] is not None,
                           "REPORT_OBSERVATION_WAIT")
    queue_keys = []
    reasons = ERRORS - {"NONE"} | {"METADATA_PARSER_NOT_CONFIGURED", "PAGE_CHANGED", "NATIVE_COORDINATION_PENDING",
                                  "STATIC_LINK_NOT_OBSERVED", "LINK_HTTP_FAILED", "LINK_UNRESOLVED", "METADATA_UNRESOLVED"}
    if locator_mode:
        reasons |= HOLD_REASONS
    for row in report["reviewQueue"]:
        cr.fields(row, {"kind", "id", "reason"}, "REVIEW_FIELDS")
        cr.require(row["kind"] in {"SOURCE", "RECORD", "PRODUCT"} and row["reason"] in reasons, "REVIEW_KIND")
        cr.identity(row["id"])
        queue_keys.append((row["kind"], row["id"], row["reason"]))
    cr.require(queue_keys == sorted(set(queue_keys)), "REVIEW_DUPLICATE")
    recovered = report["recoveredRequestIds"]
    cr.require(isinstance(recovered, list) and recovered == sorted(set(recovered)), "RECOVERED_IDS")
    for value in recovered:
        cr.sha256(value)
        cr.require(value is not None, "RECOVERED_ID")
    expected_counts = report_counts(report["items"], report["reviewQueue"], recovered)
    cr.fields(report["counts"], set(expected_counts), "REPORT_COUNT_FIELDS")
    cr.require(all(type(value) is int for value in report["counts"].values()) and
               report["counts"] == expected_counts, "REPORT_COUNTS")
    return report


def verify_store(root: Path, *, allow_import_stage: bool = False) -> dict:
    """コピー後もstate hashと最低待機を検証し、余分なfileを拒否する。"""
    layout(root, allow_import_stage=allow_import_stage)
    state = validate_state(read_envelope(root / "state.json", "dc-monitor-state-envelope-v1"))
    if (root / "import-metadata.json").exists():
        metadata = validate_import_metadata(cr.read_json(root / "import-metadata.json"))
        cr.require(cr.timestamp(metadata["sourceObservedAt"]) <= cr.timestamp(state["observedAt"]),
                   "IMPORT_OBSERVATION_LOST")
    for path in (root / "reports").iterdir():
        cr.require(path.suffix == ".json", "MONITOR_REPORT_NAME")
        cr.identity(path.stem)
        report = validate_report(read_envelope(path, "dc-monitor-report-envelope-v1"))
        cr.require(report["id"] == path.stem,
                   "MONITOR_REPORT_SCHEMA")
    layout(root, allow_import_stage=allow_import_stage)
    return state


def export_store(root: Path, output: Path) -> None:
    """停止時の公開state・報告だけを新規snapshotへまとめ、lockを持ち出さない。

    各出力streamはwithで終了処理を行う。書込みや最終検証に失敗した場合も
    作成済みsnapshotを自動削除・復元せず保持する。残った既存出力は上書きせず拒否する。
    """
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(output)
    with writer_lock(root):
        state = verify_store(root)
        distribution_present = (root / "distribution/journal.json").exists()
        cr.require(distribution_present or not (root / "distribution-init-v1.json").exists(),
                   "EXPORT_DISTRIBUTION_INITIALIZATION_INCOMPLETE")
        extra = {}
        if distribution_present:
            import collector_distribution_pipeline as distribution
            state, extra = distribution.portable_content(root, state)
        cr.require(all(row["outcome"] != "IN_PROGRESS" for row in state["requests"].values()),
                   "EXPORT_INCOMPLETE_RESERVATION")
        content = {"state.json": cr.json_bytes(cr.read_json(root / "state.json"))}
        if distribution_present:
            content["state.json"] = envelope("dc-monitor-state-envelope-v1", state)
            content.update(extra)
        for path in sorted((root / "reports").iterdir()):
            content["reports/" + path.name] = cr.json_bytes(cr.read_json(path))
        if distribution_present:
            if (root / "distribution-init-v1.json").exists():
                content["distribution-init-v1.json"] = read_import_bytes(root / "distribution-init-v1.json")
        manifest = {"schema": "dc-registry-monitor-export-v3" if distribution_present else "dc-registry-monitor-export-v1", "asOf": state["observedAt"],
                    "files": [{"path": name, "bytes": len(raw), "sha256": cr.digest(raw)}
                              for name, raw in sorted(content.items())]}
        content["manifest.json"] = cr.json_bytes(manifest)
        cr.require(all(len(raw) <= cr.MAX_JSON_BYTES for raw in content.values()), "EXPORT_SIZE")
        cr.require(len(content) - 1 <= 4096 and sum(map(len, content.values())) <= 64 * 1024 * 1024,
                   "EXPORT_TOTAL_LIMIT")
        output.mkdir(parents=True, exist_ok=False)
        (output / "reports").mkdir()
        if distribution_present:
            (output / "distribution/runs").mkdir(parents=True)
        for name, raw in content.items():
            (output / name).parent.mkdir(parents=True, exist_ok=True)
            with (output / name).open("xb") as stream:
                stream.write(raw)
        verify_export(output)


def verify_export(root: Path) -> dict:
    """Manifestの閉じたfile集合・hash・待機を確認する。通信は開始しない。"""
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    root_names = {path.name for path in root.iterdir()}
    cr.require({"state.json", "reports", "manifest.json"} <= root_names <=
               {"state.json", "reports", "manifest.json", "distribution", "distribution-init-v1.json"}, "EXPORT_FILE_SET")
    cr.regular_path(root / "reports", directory=True)
    manifest = cr.read_json(root / "manifest.json")
    cr.fields(manifest, {"schema", "asOf", "files"}, "EXPORT_MANIFEST_FIELDS")
    cr.require(manifest["schema"] in {"dc-registry-monitor-export-v1", "dc-registry-monitor-export-v3"} and isinstance(manifest["files"], list),
               "EXPORT_MANIFEST_SCHEMA")
    cr.require(len(manifest["files"]) <= 4096, "EXPORT_FILE_LIMIT")
    actual_names = {"state.json"}
    if "distribution" in root_names or "distribution-init-v1.json" in root_names:
        cr.require(manifest["schema"] == "dc-registry-monitor-export-v3", "EXPORT_DISTRIBUTION_VERSION")
        if "distribution" in root_names:
            import collector_distribution_pipeline as distribution
            distribution.verify_layout(root / "distribution")
            cr.require((root / "distribution/portable-history.json").exists() and
                not any((root / "distribution/runs").iterdir()) and
                not (root / "distribution/candidate-head.json").exists(), "EXPORT_PRIVATE_EVIDENCE")
            for path in (root / "distribution").rglob("*"):
                cr.regular_path(path, directory=path.is_dir())
                if path.is_file():
                    actual_names.add(path.relative_to(root).as_posix())
        if "distribution-init-v1.json" in root_names:
            cr.regular_path(root / "distribution-init-v1.json")
            actual_names.add("distribution-init-v1.json")
    for path in (root / "reports").iterdir():
        cr.regular_path(path)
        cr.require(path.suffix == ".json", "EXPORT_REPORT_NAME")
        cr.identity(path.stem)
        actual_names.add("reports/" + path.name)
    names = set()
    total = (root / "manifest.json").stat().st_size
    for row in manifest["files"]:
        cr.fields(row, {"path", "bytes", "sha256"}, "EXPORT_FILE_FIELDS")
        cr.require(isinstance(row["path"], str) and row["path"] in actual_names and row["path"] not in names,
                   "EXPORT_FILE_PATH")
        names.add(row["path"])
        cr.require(type(row["bytes"]) is int and 0 < row["bytes"] <= cr.MAX_JSON_BYTES, "EXPORT_FILE_BYTES")
        total += row["bytes"]
        cr.require(total <= 64 * 1024 * 1024, "EXPORT_TOTAL_LIMIT")
        cr.sha256(row["sha256"])
        path = root / row["path"]
        cr.regular_path(path)
        with path.open("rb") as stream:
            raw = stream.read(cr.MAX_JSON_BYTES + 1)
        cr.regular_path(path)
        cr.require(len(raw) == row["bytes"] and cr.digest(raw) == row["sha256"], "EXPORT_FILE_HASH")
    cr.require(names == actual_names, "EXPORT_FILE_SET")
    state = validate_state(read_envelope(root / "state.json", "dc-monitor-state-envelope-v1"))
    cr.require(manifest["asOf"] == state["observedAt"], "EXPORT_TIME")
    for path in (root / "reports").iterdir():
        report = validate_report(read_envelope(path, "dc-monitor-report-envelope-v1"))
        cr.require(report["id"] == path.stem, "EXPORT_REPORT_BINDING")
    return state


@contextmanager
def exclusive_file_lock(path: Path):
    """同じ通常fileをOSで排他lockし、中断時はOSへ解放を任せる。"""
    cr.regular_path(path)
    with path.open("r+b") as stream:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise cr.RegistryError("MONITOR_BUSY") from error
        try:
            yield stream
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def writer_lock(root: Path):
    """完全な通常実行rootだけをlockし、移設途中からのrunを拒否する。"""
    layout(root)
    with exclusive_file_lock(root / "writer.lock"):
        yield


def export_content(root: Path) -> tuple[dict, dict[str, bytes]]:
    """完全検証したexportの元byteを有限に所有し、読取り中の変更を拒否する。"""
    state = verify_export(root)
    cr.require(all(row["outcome"] != "IN_PROGRESS" for row in state["requests"].values()),
               "IMPORT_INCOMPLETE_RESERVATION")
    manifest_raw = read_import_bytes(root / "manifest.json")
    manifest = cr.parse_json(manifest_raw)
    cr.require(len(manifest["files"]) <= 4096, "IMPORT_FILE_LIMIT")
    content = {"manifest.json": manifest_raw}
    total = len(manifest_raw)
    for row in manifest["files"]:
        path = root / row["path"]
        cr.regular_path(path)
        cr.require(total + row["bytes"] <= 64 * 1024 * 1024, "IMPORT_TOTAL_LIMIT")
        with path.open("rb") as stream:
            raw = stream.read(row["bytes"] + 1)
        cr.regular_path(path)
        cr.require(len(raw) == row["bytes"] and cr.digest(raw) == row["sha256"], "IMPORT_INPUT_CHANGED")
        total += len(raw)
        content[row["path"]] = raw
    cr.require(read_import_bytes(root / "manifest.json") == manifest_raw, "IMPORT_INPUT_CHANGED")
    verify_export(root)
    return state, content


def read_import_bytes(path: Path) -> bytes:
    """通常fileを既存のJSON上限内で読み、reparseと読取り中の長さ変更を拒否する。"""
    cr.regular_path(path)
    size = path.stat().st_size
    cr.require(0 < size <= cr.MAX_JSON_BYTES, "IMPORT_FILE_SIZE")
    with path.open("rb") as stream:
        raw = stream.read(size + 1)
    cr.regular_path(path)
    cr.require(len(raw) == size and path.stat().st_size == size, "IMPORT_INPUT_CHANGED")
    return raw


def write_new_bytes(path: Path, raw: bytes) -> None:
    """新しいfileだけをflushして保存し、既存byteを上書きしない。

    streamはwithで終了処理を行う。write・flush・fsync・終了処理の例外は伝播し、
    作成済み部分fileを自動削除しない。失敗した既存fileを上書きして再試行しない。
    """
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def import_export(source: Path, output: Path, *, source_stop_acknowledged: bool = False,
                  resume: bool = False, clock=utc_now, checkpoint=None) -> Path:
    """停止時exportを同じbyteで新規rootへ移設し、同じsnapshotの中断だけを再開する。"""
    cr.require(source_stop_acknowledged is True, "IMPORT_SOURCE_STOP_REQUIRED")
    cr.require(output.is_absolute() and len(output.name) <= 120 and
               all(part not in {".", ".."} for part in output.parts) and ".import-" not in output.name,
               "IMPORT_OUTPUT_PATH")
    cr.check_ancestors(output)
    cr.regular_path(output.parent, directory=True)
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    source = source.absolute()
    cr.require(source != output and source not in output.parents and output not in source.parents,
               "IMPORT_PATH_OVERLAP")
    state, content = export_content(source)
    cr.require(clock() >= cr.timestamp(state["observedAt"]), "IMPORT_CLOCK")
    manifest_hash = cr.digest(content["manifest.json"])
    metadata_raw = cr.json_bytes({"schema": "dc-registry-monitor-import-v1",
                                 "manifestSha256": manifest_hash,
                                 "sourceObservedAt": state["observedAt"],
                                 "sourceStopAcknowledged": True})
    stage = output.parent / (output.name + ".import-" + manifest_hash[:32])
    cr.check_ancestors(stage)
    if resume:
        cr.regular_path(stage, directory=True)
        cr.require(read_import_bytes(stage / "import-metadata.json") == metadata_raw, "IMPORT_RESUME_BINDING")
    else:
        cr.require(not stage.exists() and not stage.is_symlink(), "IMPORT_STAGE_EXISTS")
        stage.mkdir(exist_ok=False)
        write_new_bytes(stage / "import-metadata.json", metadata_raw)
        if checkpoint:
            checkpoint("METADATA_SAVED", stage)
    names = {path.name for path in stage.iterdir()}
    cr.require(names <= {"import-metadata.json", "reports", "writer.lock", "state.json", "distribution", "distribution-init-v1.json"}, "IMPORT_STAGE_FILES")
    if "reports" not in names:
        (stage / "reports").mkdir(exist_ok=False)
    if "distribution/journal.json" in content:
        (stage / "distribution/runs").mkdir(parents=True, exist_ok=True)
    cr.regular_path(stage / "reports", directory=True)
    if "writer.lock" not in names:
        write_new_bytes(stage / "writer.lock", b"0")
    cr.regular_path(stage / "writer.lock")
    with exclusive_file_lock(stage / "writer.lock") as lock:
        lock.seek(0)
        cr.require(lock.read(2) == b"0", "IMPORT_LOCK_BYTES")
        lock.seek(0)
        allowed_reports = {name[8:] for name in content if name.startswith("reports/")}
        cr.require({path.name for path in (stage / "reports").iterdir()} <= allowed_reports,
                   "IMPORT_STAGE_REPORTS")
        for name, raw in sorted(content.items()):
            if name == "manifest.json":
                continue
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                cr.regular_path(target)
                cr.require(target.stat().st_size == len(raw) and read_import_bytes(target) == raw, "IMPORT_PARTIAL_CHANGED")
            else:
                write_new_bytes(target, raw)
            if checkpoint:
                checkpoint("FILE_SAVED", stage)
        cr.require(verify_store(stage, allow_import_stage=True) == state, "IMPORT_STATE_CHANGED")
        _, current_content = export_content(source)
        cr.require(current_content == content, "IMPORT_INPUT_CHANGED")
        if checkpoint:
            checkpoint("VALIDATED", stage)
    # Windows rename does not replace an existing destination. No cleanup or overwrite fallback.
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    os.rename(stage, output)
    cr.require(verify_store(output) == state, "IMPORT_STATE_CHANGED")
    return output


def save_state(root: Path, state: dict) -> None:
    """有限の新規temporary fileをflushし、正本を原子的に置換する。"""
    raw = envelope("dc-monitor-state-envelope-v1", validate_state(state))
    cr.require(len(raw) <= cr.MAX_JSON_BYTES, "MONITOR_STATE_SIZE")
    descriptor, name = tempfile.mkstemp(prefix="state-", suffix=".pending", dir=root)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        cr.regular_path(root / "state.json")
        os.replace(temporary, root / "state.json")
    finally:
        if temporary.exists():
            cr.regular_path(temporary)
            temporary.unlink()


def initialize(root: Path, clock=utc_now) -> None:
    """新規root/reportsとlock/state fileを作り、収集やHTTPは開始しない。

    writer.lockは初期byteを作る段階で、排他lockを保持する操作ではない。
    streamはwithで閉じ、検証/I/O失敗では部分rootを削除・再利用せず残して伝播する。
    """
    cr.require(not root.exists() and not root.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(root)
    root.mkdir(parents=True, exist_ok=False)
    (root / "reports").mkdir()
    with (root / "writer.lock").open("xb") as stream:
        stream.write(b"0")
    now = stamp(clock())
    state = {"schema": STATE_SCHEMA, "createdAt": now, "observedAt": now, "requests": {}, "hosts": {}}
    with (root / "state.json").open("xb") as stream:
        stream.write(envelope("dc-monitor-state-envelope-v1", state))
    verify_store(root)


def retry_deadline(value: str | None, now: datetime) -> tuple[datetime, bool]:
    """不正Retry-Afterを要確認保留にし、有効な長い期限を短縮しない。"""
    due = now + DAY
    if value is None:
        return due, False
    try:
        if value.isascii() and value.isdigit() and len(value) <= 7:
            seconds = int(value)
            cr.require(seconds <= 30 * 86400, "RETRY_AFTER_RANGE")
            requested = now + timedelta(seconds=seconds)
        else:
            parsed = parsedate_to_datetime(value)
            cr.require(format_datetime(parsed, usegmt=True) == value, "RETRY_AFTER_FORMAT")
            requested = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            cr.require(requested <= now + timedelta(days=30), "RETRY_AFTER_RANGE")
        return max(due, requested), False
    except (ValueError, TypeError, OverflowError, cr.RegistryError):
        return due, True


def validate_response(result: dict, kind: str) -> dict:
    cr.fields(result, {"status", "error", "bodySha256", "bodyBytes", "linkHashes", "retryAfter"}, "TRANSPORT_FIELDS")
    cr.require(result["error"] in ERRORS - {"UNKNOWN_OUTCOME"}, "TRANSPORT_ERROR")
    status = result["status"]
    cr.require(status is None or (type(status) is int and 100 <= status <= 599), "HTTP_STATUS")
    cr.sha256(result["bodySha256"])
    cr.require(type(result["bodyBytes"]) is int and 0 <= result["bodyBytes"] <= MAX_BODY, "TRANSPORT_BYTES")
    links = result["linkHashes"]
    cr.require(isinstance(links, list) and links == sorted(set(links)), "TRANSPORT_LINKS")
    for value in links:
        cr.sha256(value)
        cr.require(value is not None, "TRANSPORT_LINK_HASH")
    if result["error"] == "NONE":
        cr.require(status == 200, "TRANSPORT_SUCCESS")
        cr.require((kind == "PAGE" and result["bodySha256"] is not None and result["bodyBytes"] > 0) or
                   (kind == "LINK" and result["bodySha256"] is None and result["bodyBytes"] == 0 and not links),
                   "TRANSPORT_KIND")
    cr.require(result["retryAfter"] is None or (isinstance(result["retryAfter"], str) and
                                               len(result["retryAfter"]) <= 1024), "RETRY_AFTER_SIZE")
    return result


def run_once(registry: dict, policy: dict, root: Path, transport=None, clock=utc_now,
             monotonic=time.monotonic, checkpoint=None, *, public_locators: dict | None = None,
             pages_only: bool = False, admission=None) -> dict:
    """監視を一回だけ行い、予約・結果を保存して全対象の報告を生成する。"""
    registry = cr.validate_registry(registry)
    policy = validate_policy(registry, policy)
    cr.require(type(pages_only) is bool and (not pages_only or public_locators is not None), "MONITOR_PAGE_MODE")
    requests = make_requests(registry, policy)
    if public_locators is not None:
        public_locators = pl.validate_locators(public_locators, registry)
        requests = (page_requests if pages_only else locator_requests)(registry, public_locators, policy, requests)
    transport = transport or CurlTransport(
        allow_public_query=registry["schema"] == cr.QUERY_REGISTRY_SCHEMA,
        **({"registry": registry, "public_locators": public_locators,
            "held_source_ids": tuple(policy["heldSourceIds"])} if public_locators is not None else {}))
    with writer_lock(root):
        state = verify_store(root)
        started = clock()
        cr.require(started >= cr.timestamp(state["observedAt"]) and started >= cr.timestamp(registry["asOf"]),
                   "MONITOR_CLOCK")
        if public_locators is not None:
            cr.require(started >= cr.timestamp(public_locators["asOf"]), "MONITOR_LOCATOR_CLOCK")
        # Nativeの生きたleaseは同じwriter内で一度消費し、行を削除せず理由付き保留へ射影する。
        if admission is not None:
            cr.require(pages_only, "MONITOR_ADMISSION_SCOPE")
            holds = admission(requests, state)
            cr.require(type(holds) is dict and set(holds) <= {row["id"] for row in requests} and
                       all(value in HOLD_REASONS for value in holds.values()), "MONITOR_ADMISSION_RESULT")
            requests = [{**row, "held":True, "holdReason":holds[row["id"]]} if row["id"] in holds else row
                        for row in requests]
        # 予約後の停止は再送せず、旧成功と元の待機を保持して結果不明へ確定する。
        recovered = []
        for key, row in state["requests"].items():
            if row["outcome"] == "IN_PROGRESS":
                row.update(outcome="UNKNOWN_OUTCOME", reason="UNKNOWN_OUTCOME", endedAt=stamp(started),
                           nextDueAt=stamp(max(cr.timestamp(row["nextDueAt"]), started + DAY)))
                recovered.append(key)
                # 応答後・host待機保存前の停止も区別不能なため、同hostを要確認保留する。
                state["hosts"][row["hostSha256"]] = {"failedAt": stamp(started),
                    "nextDueAt": stamp(max(started + DAY, cr.timestamp(row["nextDueAt"]))), "held": True}
        state["observedAt"] = stamp(started)
        save_state(root, state)
        items = []
        queue = set()
        attempts = 0
        total_bytes = 0
        budget_bytes = 0
        start_timer = monotonic()
        for target in requests:
            now = clock()
            cr.require(now >= cr.timestamp(state["observedAt"]), "MONITOR_CLOCK")
            key = target["id"]
            old = state["requests"].get(key)
            if old:
                cr.require(old["kind"] == target["kind"] and old["locatorSha256"] == hash_text(target["url"]) and
                           old["hostSha256"] == hash_text(urlsplit(target["url"]).hostname),
                           "REQUEST_BINDING")
            success = old["lastSuccess"] if old else None
            previous = success["bodySha256"] if success else None
            item = {field: target[field] for field in ("id", "kind", "sourceIds", "recordIds", "productIds")}
            if public_locators is not None:
                item["locatorIds"] = target["locatorIds"]
            item.update(state="DEFERRED", reason="WAIT_24H", httpStatus=old["httpStatus"] if old else None,
                        previousSha256=previous, observedSha256=previous,
                        bodyBytes=0, checkedAt=old["endedAt"] if old else None,
                        nextDueAt=old["nextDueAt"] if old else None)
            # 研究観測日時を実通信の予約へ補わず、実request/hostの元待機だけを使う。
            host_key = hash_text(urlsplit(target["url"]).hostname)
            host = state["hosts"].get(host_key)
            if target["held"]:
                item.update(state="HELD", reason=target.get("holdReason") or "NATIVE_COORDINATION_PENDING")
            elif host and (host["held"] or now < cr.timestamp(host["nextDueAt"])):
                item.update(reason="HOST_REVIEW_REQUIRED" if host["held"] else "HOST_COOLDOWN",
                            nextDueAt=host["nextDueAt"])
            elif old and now < cr.timestamp(old["nextDueAt"]):
                pass
            elif attempts >= MAX_REQUESTS or budget_bytes + MAX_BODY > MAX_RUN_BYTES or monotonic() - start_timer >= MAX_RUN_SECONDS - 30:
                item.update(reason="RUN_BUDGET")
            else:
                # HTTP開始前の永続予約で、途中停止後の同日再送を防ぐ。
                row = {"kind": target["kind"], "locatorSha256": hash_text(target["url"]), "hostSha256": host_key,
                       "attemptedAt": stamp(now), "endedAt": None, "nextDueAt": stamp(now + DAY),
                       "outcome": "IN_PROGRESS", "httpStatus": None, "reason": "NONE", "lastSuccess": success}
                state["requests"][key] = row
                state["observedAt"] = stamp(now)
                save_state(root, state)
                if checkpoint:
                    checkpoint("RESERVED", key)
                attempts += 1
                try:
                    result = validate_response(transport(target["kind"], target["url"]), target["kind"])
                except Exception:
                    # 外部transport例外や不正結果を成功へ昇格せず、元例外本文を保存しない。
                    result = {"status": None, "error": "TRANSPORT_FAILED", "bodySha256": None,
                              "bodyBytes": 0, "linkHashes": [], "retryAfter": None}
                ended = clock()
                cr.require(ended >= now, "MONITOR_CLOCK")
                total_bytes += result["bodyBytes"]
                # 失敗中の転送量が観測不能でも、一要求の最大量を予算へ課金する。
                budget_bytes += result["bodyBytes"] if result["error"] == "NONE" else MAX_BODY
                row.update(endedAt=stamp(ended), nextDueAt=stamp(ended + DAY), httpStatus=result["status"],
                           outcome="SUCCESS" if result["error"] == "NONE" else "FAILED", reason=result["error"])
                if result["error"] == "NONE":
                    row["lastSuccess"] = {"checkedAt": stamp(ended), "bodySha256": result["bodySha256"],
                                          "bodyBytes": result["bodyBytes"],
                                          "linkHashes": sorted(set(result["linkHashes"]) & set(target["expectedLinks"]))}
                    classification = "LINK_ALIVE" if target["kind"] == "LINK" else (
                        "BASELINE" if previous is None else "UNCHANGED" if previous == result["bodySha256"] else "CHANGED")
                    item.update(state=classification, reason="NONE", observedSha256=result["bodySha256"])
                else:
                    item.update(state="FAILED", reason=result["error"], observedSha256=None)
                if result["status"] in {429, 503}:
                    due, held = retry_deadline(result["retryAfter"], ended)
                    state["hosts"][host_key] = {"failedAt": stamp(ended), "nextDueAt": stamp(due), "held": held}
                    row["nextDueAt"] = stamp(max(cr.timestamp(row["nextDueAt"]), due))
                item.update(httpStatus=result["status"], bodyBytes=result["bodyBytes"], checkedAt=stamp(ended), nextDueAt=row["nextDueAt"])
                state["observedAt"] = stamp(ended)
                save_state(root, state)
                success = row["lastSuccess"]
                if checkpoint:
                    checkpoint("SAVED", key)
            items.append(item)
            if target["kind"] == "PAGE":
                for source_id in target["sourceIds"]:
                    queue.add(("SOURCE", source_id, "METADATA_PARSER_NOT_CONFIGURED"))
                    if item["state"] in {"CHANGED", "FAILED", "HELD"}:
                        queue.add(("SOURCE", source_id, "PAGE_CHANGED" if item["state"] == "CHANGED" else item["reason"]))
                    if success and set(target["expectedLinks"]) - set(success["linkHashes"]):
                        queue.add(("SOURCE", source_id, "STATIC_LINK_NOT_OBSERVED"))
                    if item["state"] == "DEFERRED" and old and old["outcome"] in {"FAILED", "UNKNOWN_OUTCOME"}:
                        queue.add(("SOURCE", source_id, old["reason"]))
            elif item["state"] == "FAILED":
                for record_id in target["recordIds"]:
                    queue.add(("RECORD", record_id, "LINK_HTTP_FAILED"))
            elif item["state"] == "HELD" and public_locators is not None:
                for record_id in target["recordIds"]:
                    queue.add(("RECORD", record_id, item["reason"]))
            elif old and old["outcome"] in {"FAILED", "UNKNOWN_OUTCOME"}:
                for record_id in target["recordIds"]:
                    queue.add(("RECORD", record_id, "LINK_HTTP_FAILED" if old["outcome"] == "FAILED" else "UNKNOWN_OUTCOME"))
        visible_records = {rid for row in requests for rid in row["recordIds"]}
        visible_products = {pid for row in requests for pid in row["productIds"]}
        saved_payload_records = {rid for row in public_locators["locators"] for rid in row["recordIds"]
                                 if row["purpose"] == "PAYLOAD"} if public_locators is not None else set()
        for record in registry["records"]:
            if record["downloadUrl"] is None and record["id"] not in saved_payload_records and (
                    public_locators is None or record["id"] in visible_records):
                queue.add(("RECORD", record["id"], "LINK_UNRESOLVED"))
        for product in registry["products"]:
            if not product["recordIds"] and (public_locators is None or product["id"] in visible_products):
                queue.add(("PRODUCT", product["id"], "METADATA_UNRESOLVED"))
        report_id = "run-" + uuid.uuid4().hex
        review_queue = [{"kind": kind, "id": key, "reason": reason} for kind, key, reason in sorted(queue)]
        counts = report_counts(items, review_queue, recovered)
        finished = clock()
        cr.require(finished >= cr.timestamp(state["observedAt"]), "MONITOR_CLOCK")
        state["observedAt"] = stamp(finished)
        save_state(root, state)
        report = {"schema": "dc-registry-monitor-report-v3" if pages_only else (
                      "dc-registry-monitor-report-v2" if public_locators is not None else (
                      "dc-registry-monitor-report-v1")), "id": report_id,
                  **({"requestScope": "REGISTERED_PAGES_ONLY"} if pages_only else {}),
                  "registrySha256": cr.digest(cr.json_bytes(registry)), "policySha256": cr.digest(cr.json_bytes(policy)),
                  **({"locatorsSha256": cr.digest(cr.json_bytes(public_locators))} if public_locators is not None else {}),
                  "startedAt": stamp(started), "finishedAt": stamp(finished), "items": items,
                  "reviewQueue": review_queue, "recoveredRequestIds": sorted(recovered),
                  "counts": counts}
        raw = envelope("dc-monitor-report-envelope-v1", validate_report(report))
        cr.require(len(raw) <= cr.MAX_JSON_BYTES, "MONITOR_REPORT_SIZE")
        with (root / "reports" / (report_id + ".json")).open("xb") as stream:
            stream.write(raw)
        verify_store(root)
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "verify", "verify-export"):
        commands.add_parser(command).add_argument("store", type=Path)
    sub = commands.add_parser("export")
    sub.add_argument("store", type=Path)
    sub.add_argument("output", type=Path)
    for command in ("run-locators", "run-pages"):
        sub = commands.add_parser(command)
        sub.add_argument("registry", type=Path)
        sub.add_argument("locators", type=Path)
        sub.add_argument("policy", type=Path)
        sub.add_argument("store", type=Path)
    for command in ("import-export", "resume-import"):
        sub = commands.add_parser(command)
        sub.add_argument("snapshot", type=Path)
        sub.add_argument("output", type=Path)
        sub.add_argument("--confirm-source-stopped", action="store_true")
    sub = commands.add_parser("run")
    sub.add_argument("registry", type=Path)
    sub.add_argument("policy", type=Path)
    sub.add_argument("store", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args.store)
        elif args.command == "verify":
            verify_store(args.store)
        elif args.command == "verify-export":
            verify_export(args.store)
        elif args.command == "export":
            export_store(args.store, args.output)
        elif args.command in {"import-export", "resume-import"}:
            import_export(args.snapshot, args.output, source_stop_acknowledged=args.confirm_source_stopped,
                          resume=args.command == "resume-import")
        else:
            cr.check_ancestors(args.registry)
            cr.check_ancestors(args.policy)
            options = {}
            if args.command in {"run-locators", "run-pages"}:
                cr.check_ancestors(args.locators)
                options["public_locators"] = cr.read_json(args.locators)
                options["pages_only"] = args.command == "run-pages"
            report = run_once(cr.read_json(args.registry), cr.read_json(args.policy), args.store, **options)
            print(json.dumps({"result": "SAVED", "counts": report["counts"]}, sort_keys=True))
            return 1 if report["counts"]["failed"] or report["counts"]["held"] else 0
        print(json.dumps({"result": "OK"}))
        return 0
    except (cr.RegistryError, OSError, ValueError, TypeError, KeyError) as error:
        code = str(error) if isinstance(error, cr.RegistryError) else type(error).__name__
        print(json.dumps({"result": "REJECTED", "reason": code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
