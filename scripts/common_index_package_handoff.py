"""研究索引から取得済み原archiveの通常native検査へ接続する（ADR 0262）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
開発・非導入入口。署名索引読取り・network取得・製品worker接続ではない。
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import subprocess

import collector_registry as cr
import common_maintenance_index as mi

SCHEMA = "dc-indexed-package-handoff-v1"
NATIVE_SCHEMA = "dc-indexed-common-package-inspection-v1"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_TOOL_BYTES = 32 * 1024 * 1024
MAX_STDOUT_BYTES = 256 * 1024
HINT_FIELDS = {"schema", "researchOnly", "publishable", "installAuthorized", "recordId",
               "sourceId", "sourceSha256", "indexSha256", "recordSha256", "archiveSha256",
               "archiveBytes", "historicalMaintenanceContentInfs"}
NATIVE_FIELDS = {"schema", "researchOnly", "publishable", "installAuthorized", "applicability",
                 "indexSha256", "recordSha256", "archiveSha256", "archiveBytes", "inputBound",
                 "state", "error", "inventoryFileCount", "infCount", "verifiedInfCount",
                 "closureRejectedInfCount", "signatureRejectedInfCount", "infErrors"}


def file_identity(path: Path, maximum: int) -> tuple[int, str]:
    """通常fileを有限量でhashし、path・byte本体を返さない。"""
    cr.regular_path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            cr.require(size <= maximum, "HANDOFF_FILE_BUDGET")
            digest.update(block)
    cr.regular_path(path)
    cr.require(size > 0, "HANDOFF_FILE_EMPTY")
    return size, digest.hexdigest()


def validate_hint(value: dict) -> dict:
    """非昇格flagと元取得identityを厳密に検証する。"""
    cr.fields(value, HINT_FIELDS, "HANDOFF_FIELDS")
    cr.require(value["schema"] == SCHEMA and value["researchOnly"] is True
               and value["publishable"] is False and value["installAuthorized"] is False,
               "HANDOFF_PURPOSE")
    for field in ("recordId", "sourceId"):
        cr.identity(value[field])
    for field in ("sourceSha256", "indexSha256", "recordSha256", "archiveSha256"):
        mi.required_hash(value[field])
    cr.require(type(value["archiveBytes"]) is int and 0 < value["archiveBytes"] <= MAX_ARCHIVE_BYTES
               and type(value["historicalMaintenanceContentInfs"]) is int
               and 0 <= value["historicalMaintenanceContentInfs"] <= 4096, "HANDOFF_BUDGET")
    return value


def prepare(snapshot: Path, record_id: str) -> dict:
    """全snapshotのmetadataを再検証し、元取得観測を一意に選ぶ。索引署名認証ではない。"""
    cr.identity(record_id)
    registry, evidence, assessments = mi.verify_bundle(snapshot)
    records = [r for r in registry["records"] if r["id"] == record_id]
    acquired = [r for r in evidence["acquisitions"] if r["recordId"] == record_id]
    cr.require(len(records) == 1 and len(acquired) == 1 and acquired[0]["state"] == "DOWNLOADED",
               "HANDOFF_ACQUIRED_RECORD")
    record, acquired = records[0], acquired[0]
    source = next(r for r in registry["sources"] if r["id"] == record["sourceId"])
    _, index_hash = file_identity(snapshot / "index/drivers.json", cr.MAX_JSON_BYTES)
    return validate_hint({"schema": SCHEMA, "researchOnly": True, "publishable": False,
        "installAuthorized": False, "recordId": record_id, "sourceId": source["id"],
        "sourceSha256": cr.digest(cr.json_bytes(source)), "indexSha256": index_hash,
        "recordSha256": cr.digest(cr.json_bytes(record)), "archiveSha256": acquired["sha256"],
        "archiveBytes": acquired["bytes"], "historicalMaintenanceContentInfs":
            sum(r["recordId"] == record_id for r in assessments["infs"])})


def native_result(value: dict, hint: dict, exit_code: int) -> dict:
    """有限native結果を検証し、完了0件・個別拒否・全体失敗を区別する。"""
    validate_hint(hint)
    cr.fields(value, NATIVE_FIELDS, "HANDOFF_NATIVE_FIELDS")
    cr.require(value["schema"] == NATIVE_SCHEMA and value["researchOnly"] is True
               and value["publishable"] is False and value["installAuthorized"] is False
               and value["applicability"] == "NOT_CHECKED", "HANDOFF_NATIVE_PURPOSE")
    for field in ("indexSha256", "recordSha256", "archiveSha256", "archiveBytes"):
        cr.require(type(value[field]) is type(hint[field]) and value[field] == hint[field],
                   "HANDOFF_NATIVE_IDENTITY")
    cr.require(type(value["inputBound"]) is bool and type(value["error"]) is int
               and -(2 ** 31) <= value["error"] < 2 ** 31, "HANDOFF_NATIVE_STATE")
    limits = {"inventoryFileCount": 8192, "infCount": 128, "verifiedInfCount": 128,
              "closureRejectedInfCount": 128, "signatureRejectedInfCount": 128}
    for field, maximum in limits.items():
        cr.require(type(value[field]) is int and 0 <= value[field] <= maximum, "HANDOFF_NATIVE_COUNTS")
    cr.require(value["infCount"] == value["verifiedInfCount"] + value["closureRejectedInfCount"]
               + value["signatureRejectedInfCount"] and type(value["infErrors"]) is list
               and len(value["infErrors"]) == value["infCount"]
               and all(type(e) is int and -(2 ** 31) <= e < 2 ** 31 for e in value["infErrors"])
               and value["infErrors"].count(0) == value["verifiedInfCount"], "HANDOFF_NATIVE_INFS")
    completed = value["state"] == "INSPECTION_COMPLETED"
    cr.require(type(exit_code) is int and exit_code == (0 if completed else 1), "HANDOFF_NATIVE_EXIT")
    if completed:
        cr.require(value["error"] == 0 and value["inputBound"] is True, "HANDOFF_NATIVE_COMPLETED")
    else:
        cr.require(value["state"] in {"INPUT_REJECTED", "CANCELLED", "INSPECTION_FAILED"}
                   and value["error"] != 0 and all(value[f] == 0 for f in limits)
                   and (value["state"] != "INPUT_REJECTED" or value["inputBound"] is False),
                   "HANDOFF_NATIVE_FAILURE")
        cr.require(value["state"] != "CANCELLED" or value["error"] == -2147023673,
                   "HANDOFF_NATIVE_CANCELLED")
    return value


def inspect(hint: dict, payload: Path, tool: Path, expected_tool_sha256: str,
            *, runner=subprocess.run) -> dict:
    """元byteとtoolを固定し、明示local検査を一回だけ呼ぶ。HTTP・導入へ進まない。"""
    validate_hint(hint)
    mi.required_hash(expected_tool_sha256)
    cr.regular_path(payload)
    cr.regular_path(tool)
    cr.check_ancestors(payload)
    cr.check_ancestors(tool)
    payload, tool = payload.resolve(), tool.resolve()
    cr.require(payload.suffix.lower() in {".zip", ".cab"}, "HANDOFF_ARCHIVE_FORMAT")
    expected = hint["archiveBytes"], hint["archiveSha256"]
    cr.require(file_identity(payload, MAX_ARCHIVE_BYTES) == expected, "HANDOFF_PAYLOAD_IDENTITY")
    tool_identity = file_identity(tool, MAX_TOOL_BYTES)
    cr.require(tool_identity[1] == expected_tool_sha256, "HANDOFF_TOOL_IDENTITY")
    try:
        run = runner([str(tool), str(payload), hint["indexSha256"], hint["recordSha256"],
                      hint["archiveSha256"], str(hint["archiveBytes"])],
                     capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise cr.RegistryError("HANDOFF_NATIVE_PROCESS") from error
    cr.require(type(run.stdout) is bytes and 0 < len(run.stdout) <= MAX_STDOUT_BYTES
               and run.stderr == b"", "HANDOFF_NATIVE_OUTPUT")
    value = native_result(cr.parse_json(run.stdout), hint, run.returncode)
    cr.require(file_identity(tool, MAX_TOOL_BYTES) == tool_identity
               and file_identity(payload, MAX_ARCHIVE_BYTES) == expected, "HANDOFF_INPUT_CHANGED")
    return {"schema": "dc-indexed-common-handoff-observation-v1", "researchOnly": True,
        "publishable": False, "installAuthorized": False, "hint": hint.copy(),
        "inspectorSha256": tool_identity[1], "native": value}
