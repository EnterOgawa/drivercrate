"""固定native親と同じwriter下で検査取得を予約・精算する（ADR0396）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
公開resultの再import、HTTP transport、任意commandは提供しない。
native親の生きたduplexだけを使い、署名・公開・導入は行わない。
"""
from __future__ import annotations

from datetime import timedelta, timezone
import base64
import gzip
import json
import os
from pathlib import Path
import struct
import tempfile
import time
from urllib.parse import urlsplit
import uuid
import copy

import collector_collection_profiles as profiles
import collector_distribution_data as data
import collector_registry as cr
import registry_daily_monitor as monitor

PROTOCOL = "dc-collector-distribution-bridge-v1"
SCHEMA = "dc-collector-distribution-journal-v1"
RUN_SCHEMA = "dc-collector-distribution-run-v1"
PAGE_RESERVE = 2 * 1024 * 1024 + 1
MAX_FRAME = 1024 * 1024
JOURNAL_FIELDS = {"schema", "observedAt", "requests", "runs", "cursor", "pendingRun"}
REQUEST_FIELDS = {"kind", "hostSha256", "attemptedAt", "endedAt", "nextDueAt", "phase",
                  "chargedRequests", "chargedBytes", "runId", "ordinal", "lastSuccess"}
RUN_FIELDS = {"schema", "runId", "inputHashes", "planHash", "monitorIdentity", "startedAt",
              "deadline", "phase", "jobs", "targets", "unprofiledRecords", "pendingJob"}
RESERVATION_FIELDS = {"schema", "runId", "planHash", "inputHashes", "monitorIdentity", "ordinal",
                      "jobSha256", "pageKey", "payloadKey", "pageHost", "payloadHost", "attemptedAt",
                      "nextDueAt", "deadline", "pageReused", "pageRequests", "pageBytes",
                      "payloadRequests", "payloadBytes", "effectiveCap"}
JOB_FIELDS = {"reservationSha256", "phase", "chargedRequests", "chargedBytes", "resultMember",
              "resultSha256", "candidateMember", "candidateSha256", "candidateRecords", "status", "reason"}
BUILD_MEMBERS = {"build-plan.json", "index.json", "index.json.gz", "manifest.raw.json",
                 "build-report.json", "provenance.json", "unsigned-validation.json", "build-commit.json"}
DISTRIBUTION_KEY_ID = "distribution-index-0ac4d0ce9873c82b3c7bb7bd3fb3f5d2"


def save_json(path: Path, value: dict, *, replace: bool = False) -> str:
    """flush・原子的保存・原byte読戻しを行い、失敗時も予約を取消さない。"""
    raw = cr.json_bytes(value)
    cr.require(0 < len(raw) <= cr.MAX_JSON_BYTES, "DISTRIBUTION_FILE_LIMIT")
    if not replace:
        monitor.write_new_bytes(path, raw)
    else:
        cr.regular_path(path)
        descriptor, name = tempfile.mkstemp(prefix="journal-", suffix=".pending", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
    cr.require(profiles.read_raw(path) == raw, "DISTRIBUTION_READBACK")
    return cr.digest(raw)


def read_hash(path: Path, expected: str) -> dict:
    """保存済み原byteを有限読取りし、参照hashの一致後だけ解析する。"""
    raw = profiles.read_raw(path)
    cr.require(cr.digest(raw) == expected, "DISTRIBUTION_FILE_HASH")
    return cr.parse_json(raw)


def verify_page_body(directory: Path, ordinal: int, result: dict, job: dict, job_hash: str,
                     *, required: bool = False) -> None:
    """同resultへ結合した診断原byteを検査する。取得proofやgrantを生成しない。

    旧runの不在は補完せず、新応答のpageProof成立時だけ存在を必須にする。
    """
    path = directory / f"page-{ordinal}.body"
    if not path.exists() and not path.is_symlink():
        cr.require(not required, "DISTRIBUTION_PAGE_BODY_MISSING")
        return
    cr.regular_path(path)
    info = path.stat()
    cr.require(info.st_nlink == 1 and 0 < info.st_size < PAGE_RESERVE, "DISTRIBUTION_PAGE_BODY_LIMIT")
    raw = profiles.read_raw(path)
    page = result.get("pageObservation", {})
    transfer = result.get("pageTransfer", {})
    cr.require(result.get("schema") == "dc-collector-registry-native-result-v1" and
               result.get("jobSha256") == job_hash and result.get("job") == job and
               page.get("httpStatus") == 200 and transfer.get("stage") == "PAGE" and
               transfer.get("completion") == "COMPLETE" and transfer.get("terminalStatus") == 200 and
               type(page.get("bodyBytes")) is int and page["bodyBytes"] == len(raw) and
               transfer.get("bodyBytesRead") == len(raw) and cr.digest(raw) == page.get("bodySha256") and
               type(page.get("requestCount")) is int and 1 <= page["requestCount"] <= 3 and
               transfer.get("attemptedRequests") == page["requestCount"] and
               type(page.get("observedUtcSeconds")) is int and page["observedUtcSeconds"] > 0,
               "DISTRIBUTION_PAGE_BODY_BINDING")
    final = urlsplit(page.get("finalUrl", ""))
    cr.require(final.scheme == "https" and final.hostname == job["source"]["rootHost"] and
               final.port in (None, 443) and final.username is None and final.password is None,
               "DISTRIBUTION_PAGE_BODY_SOURCE")


def validate_journal(value: dict) -> dict:
    """待機と課金の閉じたschemaを検査し、未知の保存状態をfreshへ直さない。"""
    cr.fields(value, JOURNAL_FIELDS, "DISTRIBUTION_JOURNAL_FIELDS")
    cr.require(value["schema"] == SCHEMA, "DISTRIBUTION_JOURNAL_SCHEMA")
    observed = cr.timestamp(value["observedAt"])
    cr.require(type(value["cursor"]) is str and len(value["cursor"]) <= 128, "DISTRIBUTION_CURSOR")
    cr.require(type(value["requests"]) is dict and type(value["runs"]) is dict,
               "DISTRIBUTION_JOURNAL_MAP")
    for key, row in value["requests"].items():
        cr.sha256(key)
        cr.fields(row, REQUEST_FIELDS, "DISTRIBUTION_REQUEST_FIELDS")
        cr.sha256(row["hostSha256"])
        attempted = cr.timestamp(row["attemptedAt"])
        ended = cr.timestamp(row["endedAt"]) if row["endedAt"] else attempted
        cr.require(attempted <= ended <= observed and cr.timestamp(row["nextDueAt"]) >= attempted + monitor.DAY,
                   "DISTRIBUTION_REQUEST_TIME")
        cr.require(row["kind"] in {"PAGE", "PAYLOAD"} and row["phase"] in
                   {"RESERVED", "SETTLED_ACTUAL", "SETTLED_MAXIMUM"}, "DISTRIBUTION_REQUEST_PHASE")
        cr.require(type(row["ordinal"]) is int and 0 <= row["ordinal"] < 32 and
                   type(row["chargedRequests"]) is int and 0 <= row["chargedRequests"] <= 3 and
                   type(row["chargedBytes"]) is int and 0 <= row["chargedBytes"] <= monitor.MAX_RUN_BYTES,
                   "DISTRIBUTION_REQUEST_BUDGET")
        if row["lastSuccess"] is not None:
            cr.fields(row["lastSuccess"], {"runId", "ordinal", "checkedAt", "resultSha256"},
                      "DISTRIBUTION_SUCCESS_FIELDS")
            cr.sha256(row["lastSuccess"]["resultSha256"])
            cr.require(cr.timestamp(row["lastSuccess"]["checkedAt"]) <= ended,
                       "DISTRIBUTION_SUCCESS_TIME")
    for run_id, run in value["runs"].items():
        cr.fields(run, RUN_FIELDS, "DISTRIBUTION_RUN_FIELDS")
        cr.require(run["schema"] == RUN_SCHEMA and run_id == run["runId"] and valid_run_id(run_id),
                   "DISTRIBUTION_RUN_ID")
        cr.require(run["phase"] in {"RUNNING", "FINISHED", "UNKNOWN_OUTCOME"} and
                   type(run["jobs"]) is list and len(run["jobs"]) <= 32, "DISTRIBUTION_RUN_PHASE")
        cr.sha256(run["planHash"])
        cr.sha256(run["monitorIdentity"])
        cr.fields(run["inputHashes"], {"registry", "locators", "profiles"}, "DISTRIBUTION_INPUT_FIELDS")
        for digest in run["inputHashes"].values():
            cr.sha256(digest)
        cr.require(cr.timestamp(run["startedAt"]) <= cr.timestamp(run["deadline"]) <=
                   cr.timestamp(run["startedAt"]) + timedelta(seconds=600), "DISTRIBUTION_RUN_TIME")
        for job in run["jobs"]:
            cr.fields(job, JOB_FIELDS, "DISTRIBUTION_JOB_FIELDS")
            cr.sha256(job["reservationSha256"])
            cr.require(job["phase"] in {"RESERVED", "SETTLED_ACTUAL", "SETTLED_MAXIMUM"},
                       "DISTRIBUTION_JOB_PHASE")
    return value


def valid_run_id(value: str) -> bool:
    """固定run memberだけを許し、path componentを受けない。"""
    return (type(value) is str and len(value) == 36 and value.startswith("run-") and
            all(char in "0123456789abcdef" for char in value[4:]))


def verify_layout(root: Path) -> dict:
    """monitor配下の補助journalと固定run fileの閉集合を検査する。"""
    cr.regular_path(root, directory=True)
    names = {path.name for path in root.iterdir()}
    cr.require({"journal.json", "runs"} <= names <=
               {"journal.json", "runs", "candidate-head.json", "portable-history.json", "reference.json", "references"},
               "DISTRIBUTION_FILE_SET")
    if "portable-history.json" in names:
        history = cr.fields(cr.read_json(root / "portable-history.json"), {"schema", "observedAt", "cursor",
            "maximumGeneration", "sourceJournalSha256", "runs", "referenceHashes"}, "DISTRIBUTION_HISTORY_FIELDS")
        cr.require(history["schema"] == "dc-collector-distribution-portable-history-v1" and
            type(history["maximumGeneration"]) is int and 0 <= history["maximumGeneration"] < 9007199254740991 and
            type(history["runs"]) is dict and type(history["cursor"]) is str and len(history["cursor"]) <= 128,
            "DISTRIBUTION_HISTORY_SCHEMA")
        cr.timestamp(history["observedAt"])
        cr.sha256(history["sourceJournalSha256"])
        for run_id, row in history["runs"].items():
            cr.fields(row, {"phase", "planHash", "inputHashes", "startedAt", "deadline", "stateSha256"},
                      "DISTRIBUTION_HISTORY_RUN_FIELDS")
            cr.require(valid_run_id(run_id) and row["phase"] in {"FINISHED", "UNKNOWN_OUTCOME"} and
                cr.timestamp(row["startedAt"]) <= cr.timestamp(row["deadline"]), "DISTRIBUTION_HISTORY_RUN")
            cr.fields(row["inputHashes"], set(data.INPUTS), "DISTRIBUTION_HISTORY_INPUT_FIELDS")
            for digest in [row["planHash"], row["stateSha256"], *row["inputHashes"].values()]:
                cr.sha256(digest)
        actual = {}
        if "reference.json" in names or "references" in names:
            cr.require({"reference.json", "references"} <= names, "DISTRIBUTION_REFERENCE_MISSING")
            content = {member: profiles.read_raw(root / member) for member in data.REFERENCE_FILES}
            data.validate_reference(content)
            cr.require({path.name for path in (root / "references").iterdir()} == data.ARTIFACTS,
                       "DISTRIBUTION_REFERENCE_FILE_SET")
            actual = {name: cr.digest(raw) for name, raw in content.items()}
        cr.require(history["referenceHashes"] == actual, "DISTRIBUTION_REFERENCE_HASH")
    else:
        cr.require(not ({"reference.json", "references"} & names), "DISTRIBUTION_REFERENCE_HISTORY_REQUIRED")
    cr.regular_path(root / "runs", directory=True)
    index = cr.read_json(root / "journal.json")
    cr.fields(index, JOURNAL_FIELDS, "DISTRIBUTION_JOURNAL_FIELDS")
    journal = {**index, "runs": {}}
    for run_id, reference in index["runs"].items():
        cr.fields(reference, {"member", "sha256"}, "DISTRIBUTION_RUN_REFERENCE_FIELDS")
        cr.sha256(reference["sha256"])
        cr.require(valid_run_id(run_id) and reference["member"] == "state-" + reference["sha256"] + ".json",
                   "DISTRIBUTION_RUN_REFERENCE")
        journal["runs"][run_id] = read_hash(root / "runs" / run_id / reference["member"], reference["sha256"])
    validate_journal(journal)
    pending = journal["pendingRun"]
    if pending is not None:
        cr.fields(pending, {"runId", "planHash"}, "DISTRIBUTION_PENDING_RUN_FIELDS")
        cr.require(valid_run_id(pending["runId"]) and pending["runId"] not in journal["runs"],
                   "DISTRIBUTION_PENDING_RUN")
        cr.sha256(pending["planHash"])
    allowed_runs = set(journal["runs"]) | ({pending["runId"]} if pending else set())
    cr.require({path.name for path in (root / "runs").iterdir()} <= allowed_runs,
               "DISTRIBUTION_RUN_FILE_SET")
    for run_id, run in journal["runs"].items():
        directory = root / "runs" / run_id
        cr.regular_path(directory, directory=True)
        allowed = {"plan.json"} | BUILD_MEMBERS
        intent = run["pendingJob"]
        if intent is not None:
            cr.fields(intent, {"job", "reservation"}, "DISTRIBUTION_PENDING_JOB_FIELDS")
            cr.require(intent["reservation"]["ordinal"] == len(run["jobs"]), "DISTRIBUTION_PENDING_JOB")
            allowed.update({f"job-{len(run['jobs'])}.json", f"reservation-{len(run['jobs'])}.json"})
        for ordinal, job in enumerate(run["jobs"]):
            allowed.update({f"job-{ordinal}.json", f"reservation-{ordinal}.json"})
            # 結果保存後・精算保存前の停止窓では固定native結果を残せる。
            allowed.add(f"result-{ordinal}.json")
            allowed.add(f"candidate-{ordinal}.json")
            allowed.add(f"page-{ordinal}.body")
        # content-addressed run snapshotsの保存後・pointer更新前も既知保存窓として保持する。
        for path in directory.iterdir():
            if path.name.startswith("state-") and len(path.name) == 75 and path.name.endswith(".json"):
                digest = path.name[6:-5]
                cr.sha256(digest)
                snapshot = read_hash(path, digest)
                cr.fields(snapshot, RUN_FIELDS, "DISTRIBUTION_RUN_FIELDS")
                cr.require(snapshot["runId"] == run_id, "DISTRIBUTION_RUN_BINDING")
                allowed.add(path.name)
        names = {path.name for path in directory.iterdir()}
        cr.require(names <= allowed and "plan.json" in names, "DISTRIBUTION_RUN_FILE_SET")
        plan = read_hash(directory / "plan.json", run["planHash"])
        identity = lambda row: (row["profileId"], row["recordId"], row["productIds"])
        cr.require(list(map(identity, plan["targets"])) == list(map(identity, run["targets"])) and
                   plan["unprofiledRecords"] == run["unprofiledRecords"],
                   "DISTRIBUTION_DENOMINATOR_CHANGED")
        for ordinal, job in enumerate(run["jobs"]):
            reservation = read_hash(directory / f"reservation-{ordinal}.json", job["reservationSha256"])
            cr.fields(reservation, RESERVATION_FIELDS, "DISTRIBUTION_RESERVATION_FIELDS")
            cr.require(reservation["runId"] == run_id and reservation["ordinal"] == ordinal and
                       reservation["planHash"] == run["planHash"], "DISTRIBUTION_RESERVATION_BINDING")
            if job["phase"] == "RESERVED":
                # 同一atomic journalにあるはずの予約欠損は保存窓ではなく破損として拒否する。
                for kind, key, count in (("PAGE", reservation["pageKey"], reservation["pageRequests"]),
                                         ("PAYLOAD", reservation["payloadKey"], reservation["payloadRequests"])):
                    if not count:
                        continue
                    request = journal["requests"].get(key)
                    cr.require(request is not None and request["kind"] == kind and request["runId"] == run_id and
                               request["ordinal"] == ordinal and request["phase"] == "RESERVED",
                               "DISTRIBUTION_RESERVATION_HISTORY_MISSING")
            original_job = read_hash(directory / f"job-{ordinal}.json", reservation["jobSha256"])
            result_path = directory / f"result-{ordinal}.json"
            if job["resultSha256"] is not None:
                cr.require(job["resultMember"] == f"result-{ordinal}.json", "DISTRIBUTION_RESULT_MEMBER")
                native_result = read_hash(result_path, job["resultSha256"])
            elif result_path.exists():
                # 親の原result保存後・精算前停止も、本文があれば同じ観測へ照合する。
                native_result = cr.parse_json(profiles.read_raw(result_path))
            else:
                native_result = {}
            verify_page_body(directory, ordinal, native_result, original_job, reservation["jobSha256"])
            if job["candidateSha256"] is not None:
                cr.require(job["candidateMember"] == f"candidate-{ordinal}.json", "DISTRIBUTION_CANDIDATE_MEMBER")
                candidate = read_hash(directory / job["candidateMember"], job["candidateSha256"])
                cr.require(candidate["binding"]["runId"] == run_id and
                           candidate["binding"]["ordinal"] == ordinal and
                           candidate["binding"]["monitorIdentity"] == run["monitorIdentity"] and
                           candidate["jobSha256"] == reservation["jobSha256"] and
                           len(candidate["records"]) == job["candidateRecords"], "DISTRIBUTION_CANDIDATE_BINDING")
        for path in directory.iterdir():
            cr.regular_path(path)
    if pending and (root / "runs" / pending["runId"]).exists():
        directory = root / "runs" / pending["runId"]
        cr.regular_path(directory, directory=True)
        cr.require({path.name for path in directory.iterdir()} <= {"plan.json"}, "DISTRIBUTION_PENDING_RUN_FILES")
        if (directory / "plan.json").exists():
            read_hash(directory / "plan.json", pending["planHash"])
    return journal


def initialize_journal(store: Path, now, checkpoint=None) -> dict:
    """同じmonitor writerの内側でだけ空補助stateを作る。履歴は初期化し直さない。"""
    root = store / "distribution"
    if root.exists() and (root / "journal.json").exists():
        return verify_layout(root)
    marker = store / "distribution-init-v1.json"
    if not marker.exists():
        save_json(marker, {"schema": "dc-collector-distribution-initialization-v1", "createdAt": monitor.stamp(now)})
    if checkpoint:
        checkpoint("JOURNAL_INTENT", 0)
    root.mkdir(exist_ok=True)
    (root / "runs").mkdir(exist_ok=True)
    cr.require(not any((root / "runs").iterdir()) and {path.name for path in root.iterdir()} == {"runs"},
               "DISTRIBUTION_INITIALIZATION_CHANGED")
    if checkpoint:
        checkpoint("JOURNAL_DIRECTORY", 0)
    value = {"schema": SCHEMA, "observedAt": monitor.stamp(now), "requests": {}, "runs": {}, "cursor": "",
             "pendingRun": None}
    save_json(root / "journal.json", value)
    return value


def portable_content(store: Path, state: dict) -> tuple[dict, dict[str, bytes]]:
    """停止移設用の待機/最大課金だけを射影し、私有run/permitを持ち出さない。"""
    journal = verify_layout(store / "distribution")
    transferred = copy.deepcopy(state)
    ledger = copy.deepcopy(journal)
    history_path = store / "distribution/portable-history.json"
    previous = cr.read_json(history_path) if history_path.exists() else None
    runs = dict(previous["runs"]) if previous else {}
    for run_id, run in journal["runs"].items():
        runs[run_id] = {"phase": "UNKNOWN_OUTCOME" if run["phase"] == "RUNNING" else run["phase"],
            "planHash": run["planHash"], "inputHashes": run["inputHashes"], "startedAt": run["startedAt"],
            "deadline": run["deadline"], "stateSha256": cr.digest(cr.json_bytes(run))}
    for key, row in ledger["requests"].items():
        if row["phase"] == "RESERVED":
            row.update(phase="SETTLED_MAXIMUM", endedAt=row["attemptedAt"])
    # 保存窓の未確定jobも全予約上限を確定し、同日再送を許しません。
    for run in journal["runs"].values():
        intent = run["pendingJob"]
        if intent:
            reservation = intent["reservation"]
            for kind, prefix in (("PAGE", "page"), ("PAYLOAD", "payload")):
                if reservation[prefix + "Requests"]:
                    key = reservation[prefix + "Key"]
                    old = ledger["requests"].get(key)
                    ledger["requests"][key] = {"kind": kind, "hostSha256": reservation[prefix + "Host"],
                        "attemptedAt": reservation["attemptedAt"], "endedAt": reservation["attemptedAt"],
                        "nextDueAt": reservation["nextDueAt"], "phase": "SETTLED_MAXIMUM",
                        "chargedRequests": reservation[prefix + "Requests"], "chargedBytes": reservation[prefix + "Bytes"],
                        "runId": run["runId"], "ordinal": reservation["ordinal"],
                        "lastSuccess": old["lastSuccess"] if old else None}
    for key, row in transferred["requests"].items():
        if row["outcome"] == "IN_PROGRESS":
            cr.require(key in ledger["requests"], "EXPORT_UNKNOWN_RESERVATION")
            row.update(outcome="FAILED", reason="TRANSPORT_FAILED", endedAt=row["attemptedAt"])
    for row in ledger["requests"].values():
        if row["phase"] == "SETTLED_MAXIMUM":
            previous_host = transferred["hosts"].get(row["hostSha256"])
            due = max(cr.timestamp(row["nextDueAt"]), cr.timestamp(previous_host["nextDueAt"]) if previous_host
                      else cr.timestamp(row["nextDueAt"]))
            transferred["hosts"][row["hostSha256"]] = {"failedAt": row["attemptedAt"],
                "nextDueAt": monitor.stamp(due), "held": True}
    reference = data.reference_content(store)
    if not reference and previous and previous["referenceHashes"]:
        reference = {name: profiles.read_raw(store / "distribution" / name) for name in data.REFERENCE_FILES}
    maximum = cr.read_json(store / "distribution/candidate-head.json")["generation"] if (
        store / "distribution/candidate-head.json").exists() else 0
    history = {"schema": "dc-collector-distribution-portable-history-v1", "observedAt": journal["observedAt"],
        "cursor": journal["cursor"], "maximumGeneration": max(maximum, previous["maximumGeneration"] if previous else 0),
        "sourceJournalSha256": cr.digest(profiles.read_raw(store / "distribution/journal.json")), "runs": runs,
        "referenceHashes": {name: cr.digest(raw) for name, raw in reference.items()}}
    ledger.update(runs={}, pendingRun=None)
    validate_journal(ledger)
    monitor.validate_state(transferred)
    content = {"distribution/journal.json": cr.json_bytes(ledger),
        "distribution/portable-history.json": cr.json_bytes(history),
        **{"distribution/" + name: raw for name, raw in reference.items()}}
    return transferred, content


def save_journal(store: Path, journal: dict) -> None:
    """同writerの確定課金だけを原子的に保存し、読戻しする。"""
    validate_journal(journal)
    references = {}
    for run_id, run in journal["runs"].items():
        digest = cr.digest(cr.json_bytes(run))
        member = "state-" + digest + ".json"
        path = store / "distribution/runs" / run_id / member
        if path.exists():
            cr.require(read_hash(path, digest) == run, "DISTRIBUTION_RUN_STATE_CHANGED")
        else:
            save_json(path, run)
        references[run_id] = {"member": member, "sha256": digest}
    save_json(store / "distribution/journal.json", {**journal, "runs": references}, replace=True)


def recover(store: Path, state: dict, journal: dict, now) -> None:
    """結果欠損・各保存窓停止を最大課金へ確定し、旧成功・元待機を保持する。"""
    pending = journal["pendingRun"]
    if pending is not None:
        # 未BEGINのplan保存窓はHTTP未許可の中断として履歴を残す。
        directory = store / "distribution/runs" / pending["runId"]
        directory.mkdir(exist_ok=True)
        plan_path = directory / "plan.json"
        plan = cr.read_json(plan_path) if plan_path.exists() else None
        # 未保存planは元hashを保った中断記録であり、新規HTTPや成功を発行しない。
        if plan is None:
            plan = {"targets": [], "unprofiledRecords": [], "abandonedPlanSha256": pending["planHash"]}
            save_json(plan_path, plan)
        run = {"schema": RUN_SCHEMA, "runId": pending["runId"], "inputHashes": {name: "0" * 64 for name in
               ("registry", "locators", "profiles")}, "planHash": cr.digest(profiles.read_raw(plan_path)),
               "monitorIdentity": "0" * 64, "startedAt": monitor.stamp(now), "deadline": monitor.stamp(now),
               "phase": "UNKNOWN_OUTCOME", "jobs": [], "targets": plan["targets"],
               "unprofiledRecords": plan["unprofiledRecords"], "pendingJob": None}
        journal["runs"][pending["runId"]] = run
        journal["pendingRun"] = None
    for run_id, run in journal["runs"].items():
        intent = run["pendingJob"]
        if intent is not None:
            reservation = intent["reservation"]
            directory = store / "distribution/runs" / run_id
            ordinal = len(run["jobs"])
            for path, value in ((directory / f"job-{ordinal}.json", intent["job"]),
                                (directory / f"reservation-{ordinal}.json", reservation)):
                if path.exists():
                    cr.require(cr.read_json(path) == value, "DISTRIBUTION_PENDING_FILE_CHANGED")
                else:
                    save_json(path, value)
            for kind, key, host, count, amount in (("PAGE", reservation["pageKey"], reservation["pageHost"],
                    reservation["pageRequests"], reservation["pageBytes"]), ("PAYLOAD", reservation["payloadKey"],
                    reservation["payloadHost"], 3, reservation["payloadBytes"])):
                if not count:
                    continue
                old = journal["requests"].get(key)
                journal["requests"][key] = {"kind": kind, "hostSha256": host, "attemptedAt": reservation["attemptedAt"],
                    "endedAt": None, "nextDueAt": reservation["nextDueAt"], "phase": "RESERVED",
                    "chargedRequests": count, "chargedBytes": amount, "runId": run_id, "ordinal": ordinal,
                    "lastSuccess": old["lastSuccess"] if old else None}
            run["jobs"].append({"reservationSha256": cr.digest(cr.json_bytes(reservation)), "phase": "RESERVED",
                "chargedRequests": reservation["pageRequests"] + 3,
                "chargedBytes": reservation["pageBytes"] + reservation["payloadBytes"], "resultMember": None,
                "resultSha256": None, "candidateMember": None, "candidateSha256": None, "candidateRecords": 0,
                "status": "FAILED", "reason": "UNKNOWN_OUTCOME"})
            run["pendingJob"] = None
    for row in state["requests"].values():
        if row["outcome"] == "IN_PROGRESS":
            row.update(outcome="UNKNOWN_OUTCOME", reason="UNKNOWN_OUTCOME", endedAt=monitor.stamp(now),
                       nextDueAt=monitor.stamp(max(cr.timestamp(row["nextDueAt"]), now + monitor.DAY)))
            state["hosts"][row["hostSha256"]] = {"failedAt": monitor.stamp(now),
                "nextDueAt": row["nextDueAt"], "held": True}
    for row in journal["requests"].values():
        if row["phase"] == "RESERVED":
            row.update(phase="SETTLED_MAXIMUM", endedAt=monitor.stamp(now),
                       nextDueAt=monitor.stamp(max(cr.timestamp(row["nextDueAt"]), now + monitor.DAY)))
            state["hosts"][row["hostSha256"]] = {"failedAt": monitor.stamp(now),
                "nextDueAt": row["nextDueAt"], "held": True}
    for run in journal["runs"].values():
        if run["phase"] == "RUNNING":
            run["phase"] = "UNKNOWN_OUTCOME"
            for job in run["jobs"]:
                if job["phase"] == "RESERVED":
                    job.update(phase="SETTLED_MAXIMUM", status="FAILED", reason="UNKNOWN_OUTCOME")
    state["observedAt"] = journal["observedAt"] = monitor.stamp(now)
    monitor.save_state(store, state)
    cr.require(monitor.read_envelope(store / "state.json", "dc-monitor-state-envelope-v1") == state,
               "DISTRIBUTION_STATE_READBACK")
    save_journal(store, journal)


class NativeBridge:
    """親PID・実setup image確認済みの単一duplex。public receiptを実行能力にしない。"""

    def __init__(self, stream, context: dict, alive, close):
        self.stream, self.context, self.alive, self.close = stream, context, alive, close
        self.sequence = 0
        self._verified_run = None

    @classmethod
    def connect(cls, package: Path, name: str):
        """固定親が作ったlocal pipeだけを接続し、server実imageを再検査する。"""
        import ctypes
        from ctypes import wintypes
        import msvcrt
        import collector_workspace as workspace
        cr.require(name.startswith("\\\\.\\pipe\\DriverCrate-distribution-") and
                   len(name) < 128 and name.rsplit("-", 1)[-1].isalnum(), "DISTRIBUTION_PIPE_NAME")
        stream = open(name, "r+b", buffering=0)
        try:
            alive, close = workspace.native_pipe_parent(package, pipe=msvcrt.get_osfhandle(stream.fileno()))
            context = cls.read_frame(stream)
            cr.require(context.get("protocol") == PROTOCOL and context.get("type") == "CONTEXT",
                       "DISTRIBUTION_CONTEXT")
            result = cls(stream, context, alive, close)
            result._verified_run = context["runId"]
            return result
        except Exception:
            stream.close()
            raise

    @staticmethod
    def read_frame(stream) -> dict:
        """4byte little endian長を先に検査し、EOFや余分な本文を許さない。"""
        def exact(count):
            raw = bytearray()
            while len(raw) < count:
                chunk = stream.read(count - len(raw))
                cr.require(bool(chunk), "DISTRIBUTION_PIPE_EOF")
                raw.extend(chunk)
            return bytes(raw)
        count = struct.unpack("<I", exact(4))[0]
        cr.require(0 < count <= MAX_FRAME, "DISTRIBUTION_FRAME_LIMIT")
        return cr.parse_json(exact(count))

    def exchange(self, kind: str, run_id: str, plan_hash: str, **fields) -> dict:
        """固定順序・同run・連番に結合した一要求一応答だけを行う。"""
        cr.require(self.alive(), "DISTRIBUTION_PARENT_STOPPED")
        self.sequence += 1
        message = {"protocol": PROTOCOL, "type": kind, "sequence": self.sequence,
                   "runId": run_id, "planHash": plan_hash, **fields}
        raw = cr.json_bytes(message)
        cr.require(len(raw) <= MAX_FRAME, "DISTRIBUTION_FRAME_LIMIT")
        packet = struct.pack("<I", len(raw)) + raw
        written = 0
        while written < len(packet):
            amount = self.stream.write(packet[written:])
            cr.require(amount and amount > 0, "DISTRIBUTION_PIPE_WRITE")
            written += amount
        result = self.read_frame(self.stream)
        cr.require(all(result.get(key) == message[key] for key in
                       ("protocol", "type", "sequence", "runId", "planHash")), "DISTRIBUTION_RESPONSE_BINDING")
        return result


def inputs_at(package: Path, root: Path | None = None) -> tuple[dict, dict, dict[str, str]]:
    """active全参照を検証し、存在しない初回だけ初期seedの原byteを使う。"""
    selected = data.active_bundle(root) if root is not None else None
    if selected is None:
        selected = data.verify_bundle(package / "seed/distribution-data")
    return selected["inputs"], selected["profiles"], selected["manifest"]["inputHashes"]


def producer_hashes(package: Path) -> dict[str, str]:
    """親と同じ固定実producer/moduleの原byteを照合し、鍵を参照しない。"""
    return {name: cr.digest(profiles.read_raw(package / member)) for name, member in (
        ("native", "DriverCrateCollectorSetup.exe"), ("pipeline", "scripts/collector_distribution_pipeline.py"),
        ("profiles", "scripts/collector_collection_profiles.py"))}


def candidate_reference(run_id: str, ordinal: int, job: dict) -> dict:
    """journal内の固定candidate memberを参照し、外部pathを受けない。"""
    return {"runId": run_id, "ordinal": ordinal, "member": job["candidateMember"],
            "sha256": job["candidateSha256"]}


def read_candidate(store: Path, reference: dict, journal: dict, context: dict) -> dict:
    """同保護journal/原job/hash/実producerに結合した親生成候補だけを読む。"""
    cr.fields(reference, {"runId", "ordinal", "member", "sha256"}, "CANDIDATE_REFERENCE_FIELDS")
    run_id, ordinal = reference["runId"], reference["ordinal"]
    cr.require(valid_run_id(run_id) and type(ordinal) is int and 0 <= ordinal < 32 and
               reference["member"] == f"candidate-{ordinal}.json", "CANDIDATE_REFERENCE")
    run = journal["runs"][run_id]
    cr.require(run["monitorIdentity"] == context["monitorIdentity"] and run["phase"] == "FINISHED",
               "CANDIDATE_ORIGIN_OR_PHASE")
    job = run["jobs"][ordinal]
    cr.require(job["phase"] != "RESERVED" and candidate_reference(run_id, ordinal, job) == reference,
               "CANDIDATE_JOURNAL_BINDING")
    directory = store / "distribution/runs" / run_id
    candidate = read_hash(directory / reference["member"], reference["sha256"])
    cr.require(candidate["schema"] == "dc-collector-distribution-candidate-v1" and
               candidate["producerVersion"] == "collector-distribution-v1", "CANDIDATE_PRODUCER_VERSION")
    binding = cr.fields(candidate["binding"], {"runId", "ordinal", "planHash", "inputHashes", "monitorIdentity",
        "packageManifestSha256", "seedManifestSha256", "producerHashes"}, "CANDIDATE_BINDING_FIELDS")
    cr.require(binding == {"runId": run_id, "ordinal": ordinal, "planHash": run["planHash"],
        "inputHashes": run["inputHashes"], **{name: context[name] for name in
        ("monitorIdentity", "packageManifestSha256", "seedManifestSha256", "producerHashes")}},
        "CANDIDATE_PRIVATE_BINDING")
    reservation = read_hash(directory / f"reservation-{ordinal}.json", job["reservationSha256"])
    raw_job = read_hash(directory / f"job-{ordinal}.json", reservation["jobSha256"])
    cr.require(candidate["jobSha256"] == reservation["jobSha256"] and candidate["job"] == raw_job and
               len(candidate["records"]) == job["candidateRecords"], "CANDIDATE_ORIGINAL_JOB")
    # 全体FAILEDの先行合格や公開boolを成功recordへ救済しない。
    cr.require(not candidate["records"] or (candidate["jobError"] == 0 and job["status"] in
               {"SUCCESS", "PARTIAL_FAILURE"}), "CANDIDATE_DISCARDED_JOB_FAILURE")
    return candidate


def save_build_bytes(path: Path, raw: bytes) -> str:
    """固定run memberを新規保存・flush/readbackし、同run再buildは同byteだけを許す。"""
    cr.require(0 < len(raw) <= cr.MAX_JSON_BYTES, "CANDIDATE_OUTPUT_LIMIT")
    if path.exists():
        cr.require(profiles.read_raw(path) == raw, "CANDIDATE_REBUILD_CHANGED")
    else:
        monitor.write_new_bytes(path, raw)
        cr.require(profiles.read_raw(path) == raw, "CANDIDATE_OUTPUT_READBACK")
    return cr.digest(raw)


def read_candidate_head(store: Path, context: dict) -> dict | None:
    """未署名headだけを原点へ結合し、端末の署名済high-waterへ変換しない。"""
    path = store / "distribution/candidate-head.json"
    if not path.exists():
        return None
    value = cr.read_json(path)
    cr.fields(value, {"schema", "generation", "runId", "monitorIdentity", "inputHashes", "producerHashes",
        "packageManifestSha256", "seedManifestSha256", "includedCandidates", "outputs", "validationSha256",
        "signingGenerationFinalized"}, "CANDIDATE_HEAD_FIELDS")
    cr.require(value["schema"] == "dc-collector-unsigned-candidate-head-v1" and
               type(value["generation"]) is int and 0 < value["generation"] < 9007199254740991 and
               value["monitorIdentity"] == context["monitorIdentity"] and
               value["signingGenerationFinalized"] is False and valid_run_id(value["runId"]),
               "CANDIDATE_HEAD_BINDING")
    cr.require(set(value["outputs"]) == {"index.json", "index.json.gz", "manifest.raw.json",
               "build-report.json", "provenance.json"}, "CANDIDATE_HEAD_OUTPUT_SET")
    directory = store / "distribution/runs" / value["runId"]
    validation = read_hash(directory / "unsigned-validation.json", value["validationSha256"])
    cr.require(validation["runId"] == value["runId"] and validation["unsigned"] is True and validation["authenticated"] is False and
               validation["outputs"] == value["outputs"], "CANDIDATE_HEAD_VALIDATION")
    for member, digest in value["outputs"].items():
        cr.require(member in BUILD_MEMBERS and cr.digest(profiles.read_raw(directory / member)) == digest,
                   "CANDIDATE_HEAD_OUTPUT_HASH")
    return value


def assert_build_caller(bridge, run_id: str) -> None:
    """実parent image/PIDを検査した同じ生存pipe以外からbuildを開始しない。"""
    cr.require(isinstance(bridge, NativeBridge) and bridge._verified_run == run_id and
               not bridge.stream.closed and bridge.alive() and bridge.context["runId"] == run_id,
               "CANDIDATE_LIVE_CALLER_REQUIRED")


def build_candidate(package: Path, root: Path, run_id: str, bridge, *, clock=monitor.utc_now) -> dict | None:
    """同じ生存private caller/monitor writer内で、親の候補から非通信assembleする。

    公開native-result JSONや任意候補pathを受けない。実出力は親の共通validatorが別途確認する。
    ここでのgenerationは未署名準備値であり、認証済公開headを調べた署名用確定値ではない。
    """
    import collector_workspace as workspace
    assert_build_caller(bridge, run_id)
    context = bridge.context
    workspace.validate_workspace(root, workspace.binding(package))
    _, _, hashes = inputs_at(package, root)
    cr.require(context["inputHashes"] == hashes and context["producerHashes"] == producer_hashes(package),
               "CANDIDATE_CURRENT_INPUT_OR_PRODUCER")
    store = Path(context["monitorRoot"])
    journal = verify_layout(store / "distribution")
    run = journal["runs"][run_id]
    cr.require(run["phase"] == "FINISHED" and run["inputHashes"] == hashes and
               run["monitorIdentity"] == context["monitorIdentity"], "CANDIDATE_RUN_NOT_COMPLETE")
    current = [candidate_reference(run_id, ordinal, job) for ordinal, job in enumerate(run["jobs"])
               if job["candidateSha256"] is not None]
    observations = [(reference, read_candidate(store, reference, journal, context)) for reference in current]
    fresh = [(reference, candidate) for reference, candidate in observations if candidate["records"]]
    # 全失敗/空成功/待機だけのrunでは旧head/assetを更新しない。
    if not fresh:
        save_build_bytes(store / "distribution/runs" / run_id / "build-report.json", cr.json_bytes({
            "schema": "dc-collector-candidate-report-v1", "runId": run_id, "targets": run["targets"],
            "unprofiledRecords": run["unprofiledRecords"], "jobs": run["jobs"],
            "outcomes": [{"reference": reference, "outcomes": candidate["outcomes"], "jobError": candidate["jobError"]}
                         for reference, candidate in observations],
            "freshRecords": 0, "headUpdated": False, "unsigned": True, "authenticated": False,
            "signingGenerationFinalized": False, "networkRequests": 0, "keyOperations": 0}))
        return None
    now = clock().replace(tzinfo=None, microsecond=0)
    cr.require(now >= cr.timestamp(journal["observedAt"]), "CANDIDATE_CLOCK")
    head = read_candidate_head(store, context)
    directory = store / "distribution/runs" / run_id
    plan_path = directory / "build-plan.json"
    plan = cr.read_json(plan_path) if plan_path.exists() else None
    if plan is None:
        prior = [] if head is None else head["includedCandidates"]
        replaced = {(candidate["job"]["sourceId"], candidate["job"]["recordId"]) for _, candidate in fresh}
        retained = []
        for reference in prior:
            candidate = read_candidate(store, reference, journal, context)
            key = (candidate["job"]["sourceId"], candidate["job"]["recordId"])
            if key not in replaced:
                retained.append(reference)
        history_path = store / "distribution/portable-history.json"
        floor = cr.read_json(history_path)["maximumGeneration"] if history_path.exists() else 0
        plan = {"schema": "dc-collector-candidate-build-plan-v1", "runId": run_id,
            "generation": floor + 1 if head is None else max(floor, head["generation"]) + 1, "preparedAtUtc": monitor.stamp(now),
            "priorHeadSha256": cr.digest(profiles.read_raw(store / "distribution/candidate-head.json")) if head else None,
            "includedCandidates": retained + [reference for reference, _ in fresh]}
        save_json(plan_path, plan)
    cr.require(plan["runId"] == run_id and plan["schema"] == "dc-collector-candidate-build-plan-v1",
               "CANDIDATE_BUILD_PLAN")
    prepared = cr.timestamp(plan["preparedAtUtc"])
    cr.require(prepared <= now, "CANDIDATE_BUILD_TIME")
    chosen = []
    expired = []
    for reference in plan["includedCandidates"]:
        candidate = read_candidate(store, reference, journal, context)
        if now >= cr.timestamp(candidate["validUntilUtc"]):
            expired.append({"reference": reference, "reason": "ORIGINAL_EVIDENCE_EXPIRED"})
        else:
            chosen.append((reference, candidate))
    # 元期限が切れた候補を新しい発行時刻で復活させない。
    cr.require(any(reference["runId"] == run_id for reference, _ in chosen), "CANDIDATE_FRESH_EVIDENCE_EXPIRED")
    sources, records = {}, {}
    provenance = []
    for reference, candidate in chosen:
        for source in candidate["sources"]:
            if source["sourceId"] in sources:
                cr.require(sources[source["sourceId"]]["distributionPage"] == source["distributionPage"],
                           "CANDIDATE_SOURCE_CONFLICT")
            sources[source["sourceId"]] = source
        for record in candidate["records"]:
            key = (record["sourceId"], record["recordId"])
            cr.require(key not in records, "CANDIDATE_RECORD_CONFLICT")
            records[key] = record
        provenance.append({"reference": reference, "observation": candidate})
    entries = []
    for key in sorted(records):
        raw = json.dumps(records[key], ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")
        cr.require(len(raw) <= 65536, "CANDIDATE_RECORD_LIMIT")
        entries.append({"recordBytesBase64": base64.b64encode(raw).decode("ascii"), "recordSha256": cr.digest(raw)})
    raw_index = cr.json_bytes({"schema": "driver-index-records-v2", "assetGeneration": plan["generation"],
        "sources": [sources[key] for key in sorted(sources)], "records": entries})
    packed = gzip.compress(raw_index, mtime=0)
    # 固定OS byteへそろえ、mtime/file名をGZip identityへ混入させない。
    packed = packed[:9] + b"\xff" + packed[10:]
    asset_hash = cr.digest(packed)
    expiry = min(cr.timestamp(record["acquisitionDescriptor"]["attestation"]["validUntilUtc"])
                 for record in records.values())
    quality = {"sourceCount": len(sources), "recordCount": len(records), "metadataOnlyCount": 0,
               "contentInspectedCount": len(records), "unconfirmedCount": 0}
    manifest = {"schema": "driver-index-manifest-v1", "repository": "EnterOgawa/drivercrate", "channel": "driver-index",
        "keyId": DISTRIBUTION_KEY_ID, "generation": plan["generation"], "assetGeneration": plan["generation"],
        "publishedAtUtc": monitor.stamp(prepared), "expiresAtUtc": monitor.stamp(expiry),
        "asset": {"tag": f"index-v1-{prepared:%Y%m%d}-{asset_hash}", "name": "index.json.gz", "compression": "gzip",
                  "sizeBytes": len(packed), "sha256": asset_hash}, "quality": quality}
    report = {"schema": "dc-collector-candidate-report-v1", "runId": run_id, "generation": plan["generation"],
        "targets": run["targets"], "unprofiledRecords": run["unprofiledRecords"], "jobs": run["jobs"],
        "outcomes": [{"reference": reference, "outcomes": candidate["outcomes"], "jobError": candidate["jobError"]}
                     for reference, candidate in observations], "expired": expired,
        "freshRecords": sum(len(candidate["records"]) for _, candidate in fresh), "includedRecords": len(records),
        "allTargetsSucceeded": bool(run["targets"]) and all(row["status"] == "SUCCESS" for row in run["targets"])
                               and not run["unprofiledRecords"],
        "unsigned": True, "authenticated": False, "signingGenerationFinalized": False, "networkRequests": 0,
        "tasks": 0, "keyOperations": 0, "installations": 0}
    provenance_document = {"schema": "dc-collector-candidate-provenance-v1", "runId": run_id,
        "inputHashes": run["inputHashes"], "producerHashes": context["producerHashes"],
        "monitorIdentity": context["monitorIdentity"], "observations": provenance}
    output_bytes = {"index.json": raw_index, "index.json.gz": packed, "manifest.raw.json": cr.json_bytes(manifest),
        "build-report.json": cr.json_bytes(report), "provenance.json": cr.json_bytes(provenance_document)}
    outputs = {member: save_build_bytes(directory / member, raw) for member, raw in output_bytes.items()}
    return {"generation": plan["generation"], "outputs": outputs,
        "includedCandidates": [reference for reference, _ in chosen], "priorHeadSha256": plan["priorHeadSha256"]}


def commit_candidate(store: Path, run_id: str, built: dict | None, response: dict) -> None:
    """同じ親の未署名検証receiptへ結合した後だけ候補headを更新する。"""
    if built is None:
        return
    directory = store / "distribution/runs" / run_id
    cr.require(response["validationMember"] == "unsigned-validation.json", "CANDIDATE_VALIDATION_MEMBER")
    validation = read_hash(directory / "unsigned-validation.json", response["validationSha256"])
    cr.require(validation["unsigned"] is True and validation["authenticated"] is False and
               validation["outputs"] == built["outputs"] and validation["runId"] == run_id,
               "CANDIDATE_VALIDATION_BINDING")
    first = cr.read_json(directory / built["includedCandidates"][-1]["member"])["binding"]
    head = {"schema": "dc-collector-unsigned-candidate-head-v1", "generation": built["generation"],
        "runId": run_id, **{name: first[name] for name in ("monitorIdentity", "inputHashes", "producerHashes",
          "packageManifestSha256", "seedManifestSha256")}, "includedCandidates": built["includedCandidates"],
        "outputs": built["outputs"], "validationSha256": response["validationSha256"],
        "signingGenerationFinalized": False}
    head_path = store / "distribution/candidate-head.json"
    old = profiles.read_raw(head_path) if head_path.exists() else None
    cr.require((old is None and built["priorHeadSha256"] is None) or
               (old is not None and (cr.digest(old) == built["priorHeadSha256"] or cr.parse_json(old) == head)),
               "CANDIDATE_HEAD_CHANGED")
    save_build_bytes(directory / "build-commit.json", cr.json_bytes(head))
    if old is None or cr.parse_json(old) != head:
        save_json(head_path, head, replace=old is not None)


def run_once(package: Path, root: Path, bridge, *, confirmed: bool, clock=monitor.utc_now,
             monotonic=time.monotonic, checkpoint=None) -> dict:
    """一回のnative lease→monitor writerで全targetを保持し、各jobを一度実行する。"""
    import collector_workspace as workspace
    cr.require(confirmed is True, "DISTRIBUTION_CONSENT_REQUIRED")
    expected = workspace.binding(package)
    workspace.validate_workspace(root, expected)
    inputs, value, hashes = inputs_at(package, root)
    policy = monitor.validate_policy(inputs["registry"], cr.read_json(package / "config/monitor-policy.json"))
    context = bridge.context
    cr.require(context["inputHashes"] == hashes and context["operation"] == "distribution-run-once",
               "DISTRIBUTION_INPUT_BINDING")
    # 専用admissionだけが空legacy footprintを許し、現在native予約scopeは常に非空で受け取る。
    live = workspace.DistributionAdmission(context, parent_alive=bridge.alive)
    store = live.validate(package, root, expected, policy, clock)
    with monitor.writer_lock(store):
        state = monitor.verify_store(store)
        now = clock()
        cr.require(now >= cr.timestamp(state["observedAt"]) and now >= cr.timestamp(value["asOf"]),
                   "DISTRIBUTION_CLOCK")
        journal = initialize_journal(store, now, checkpoint)
        cr.require(now >= cr.timestamp(journal["observedAt"]), "DISTRIBUTION_CLOCK")
        recover(store, state, journal, now)
        run_id = context["runId"]
        cr.require(valid_run_id(run_id) and run_id not in journal["runs"], "DISTRIBUTION_RUN_REPLAY")
        # 待機済み/先行失敗を同じ先頭batchへ選び直さず、前回cursor以降へ進める。
        all_plan = profiles.plan_profiles(value, inputs)
        ordered = sorted(value["profiles"], key=lambda row: (row["id"] <= journal["cursor"], row["id"]))
        jobs = []
        targets = {row["profileId"]: dict(row) for row in all_plan["targets"]}
        used = []
        page_proofs = set()
        total_requests = total_bytes = 0
        start_timer = monotonic()
        # 選択は予約前の有限planで行う。実待機/hostは実行直前にも照合する。
        for profile in ordered:
            if targets[profile["id"]]["reasons"]:
                continue
            job = profiles.make_static_job(profile, inputs)
            page_key, payload_key = (monitor.hash_text("GET\n" + job["source"][name])
                                     for name in ("rootUrl", "payloadUrl"))
            previous = journal["requests"].get(payload_key)
            if previous and now < cr.timestamp(previous["nextDueAt"]):
                targets[profile["id"]].update(status="DEFERRED", reasons=["WAIT_24H"])
                continue
            native_hosts = set(context["hostHashes"])
            native_requests = set(context["requestHashes"])
            source_held = job["sourceId"] in set(policy["heldSourceIds"]) | {"asus-catalog-legacy", "intel-ethernet-win11"}
            scope_held = source_held or any(monitor.hash_text(job["source"][key]) in native_hosts for key in
                                           ("rootHost", "payloadHost")) or any(
                monitor.hash_text("GET\n" + job["source"][key]) in native_requests for key in ("rootUrl", "payloadUrl"))
            if scope_held:
                targets[profile["id"]].update(status="HOLD", reasons=["NATIVE_SHARED_HOST_HELD"])
                continue
            page_previous = state["requests"].get(page_key) or journal["requests"].get(page_key)
            host_rows = [state["hosts"].get(monitor.hash_text(job["source"][key])) for key in ("rootHost", "payloadHost")]
            if (page_previous and now < cr.timestamp(page_previous["nextDueAt"])) or any(
                    row and (row["held"] or now < cr.timestamp(row["nextDueAt"])) for row in host_rows):
                targets[profile["id"]].update(status="DEFERRED", reasons=["WAIT_OR_HOST_REVIEW"])
                continue
            # 研究観測は根拠の時点であり、実HTTPの待機は上の保護request/hostだけが決める。
            if len(jobs) >= 32:
                targets[profile["id"]].update(status="DEFERRED_BATCH", reasons=[])
                continue
            jobs.append(job)
            targets[profile["id"]].update(status="PLANNED", reasons=[])
        all_plan.update(jobs=jobs, targets=[targets[key] for key in sorted(targets)])
        all_plan["counts"]["jobs"] = len(jobs)
        plan_hash = cr.digest(cr.json_bytes(all_plan))
        directory = store / "distribution/runs" / run_id
        journal["pendingRun"] = {"runId": run_id, "planHash": plan_hash}
        save_journal(store, journal)
        if checkpoint:
            checkpoint("RUN_INTENT", 0)
        directory.mkdir()
        save_json(directory / "plan.json", all_plan)
        if checkpoint:
            checkpoint("PLAN_SAVED", 0)
        run = {"schema": RUN_SCHEMA, "runId": run_id, "inputHashes": hashes, "planHash": plan_hash,
               "monitorIdentity": context["monitorIdentity"], "startedAt": monitor.stamp(now),
               "deadline": monitor.stamp(now + timedelta(seconds=600)), "phase": "RUNNING", "jobs": [],
               "targets": copy.deepcopy(all_plan["targets"]), "unprofiledRecords": all_plan["unprofiledRecords"],
               "pendingJob": None}
        journal["runs"][run_id] = run
        journal["pendingRun"] = None
        save_journal(store, journal)
        bridge.exchange("BEGIN_RUN", run_id, plan_hash)
        # native footprintは全jobのPAGE/payload双方へ適用する。全HOLDも全分母へ残る。
        requests = [{"id": str(index), "url": job["source"][name], "sourceIds": [job["sourceId"]]}
                    for index, job in enumerate(jobs) for name in ("rootUrl", "payloadUrl")]
        holds = live.consume(requests, state, store, inputs["registry"], policy)
        try:
            for index, job in enumerate(jobs):
                now = clock()
                cr.require(now >= cr.timestamp(journal["observedAt"]), "DISTRIBUTION_CLOCK")
                target = next(row for row in run["targets"] if row["profileId"] == job["jobId"])
                keys = [monitor.hash_text("GET\n" + job["source"][name]) for name in ("rootUrl", "payloadUrl")]
                hosts = [monitor.hash_text(job["source"][name]) for name in ("rootHost", "payloadHost")]
                reused = keys[0] in page_proofs
                reason = holds.get(str(index))
                for key, host in zip(keys, hosts):
                    host_state = state["hosts"].get(host)
                    if host_state and (host_state["held"] or now < cr.timestamp(host_state["nextDueAt"])):
                        reason = "HOST_REVIEW_REQUIRED" if host_state["held"] else "HOST_COOLDOWN"
                    old = journal["requests"].get(key)
                    native_page = state["requests"].get(key)
                    if (not (reused and key == keys[0]) and
                            any(row and now < cr.timestamp(row["nextDueAt"]) for row in (old, native_page))):
                        reason = reason or "WAIT_24H"
                if reason:
                    target.update(status="HOLD" if "HELD" in reason or "PENDING" in reason else "DEFERRED",
                                  reasons=[reason])
                    continue
                page_bytes, page_requests = (0, 0) if reused else (PAGE_RESERVE, 3)
                cap = min(job["maximumBytes"], monitor.MAX_RUN_BYTES - total_bytes - page_bytes - 1)
                if (cap < 1 or total_requests + page_requests + 3 > monitor.MAX_REQUESTS or
                        monotonic() - start_timer >= monitor.MAX_RUN_SECONDS - 30):
                    target.update(status="DEFERRED", reasons=["RUN_BUDGET"])
                    continue
                ordinal = len(run["jobs"])
                job_hash = cr.digest(cr.json_bytes(job))
                due = monitor.stamp(now + monitor.DAY)
                reservation = {"schema": "dc-collector-distribution-reservation-v1", "runId": run_id,
                    "planHash": plan_hash, "inputHashes": hashes, "monitorIdentity": context["monitorIdentity"],
                    "ordinal": ordinal, "jobSha256": job_hash, "pageKey": keys[0], "payloadKey": keys[1],
                    "pageHost": hosts[0], "payloadHost": hosts[1], "attemptedAt": monitor.stamp(now),
                    "nextDueAt": due, "deadline": run["deadline"], "pageReused": reused,
                    "pageRequests": page_requests, "pageBytes": page_bytes, "payloadRequests": 3,
                    "payloadBytes": cap + 1, "effectiveCap": cap}
                run["pendingJob"] = {"job": job, "reservation": reservation}
                save_journal(store, journal)
                if checkpoint:
                    checkpoint("JOB_INTENT", ordinal)
                save_json(directory / f"job-{ordinal}.json", job)
                # PAGE保存窓の停止は既存monitor回収へ残す。payloadを後から取消さない。
                if not reused:
                    old = state["requests"].get(keys[0])
                    state["requests"][keys[0]] = {"kind": "PAGE", "locatorSha256": monitor.hash_text(job["source"]["rootUrl"]),
                        "hostSha256": hosts[0], "attemptedAt": monitor.stamp(now), "endedAt": None,
                        "nextDueAt": due, "outcome": "IN_PROGRESS", "httpStatus": None, "reason": "NONE",
                        "lastSuccess": old["lastSuccess"] if old else None}
                    state["observedAt"] = monitor.stamp(now)
                    monitor.save_state(store, state)
                    cr.require(monitor.read_envelope(store / "state.json", "dc-monitor-state-envelope-v1") == state,
                               "DISTRIBUTION_STATE_READBACK")
                if checkpoint:
                    checkpoint("PAGE_RESERVED", ordinal)
                reservation_hash = save_json(directory / f"reservation-{ordinal}.json", reservation)
                for kind, key, host, count, amount in (("PAGE", keys[0], hosts[0], page_requests, page_bytes),
                                                        ("PAYLOAD", keys[1], hosts[1], 3, cap + 1)):
                    if not count:
                        continue
                    old = journal["requests"].get(key)
                    journal["requests"][key] = {"kind": kind, "hostSha256": host, "attemptedAt": monitor.stamp(now),
                        "endedAt": None, "nextDueAt": due, "phase": "RESERVED", "chargedRequests": count,
                        "chargedBytes": amount, "runId": run_id, "ordinal": ordinal,
                        "lastSuccess": old["lastSuccess"] if old else None}
                run["jobs"].append({"reservationSha256": reservation_hash, "phase": "RESERVED",
                    "chargedRequests": page_requests + 3, "chargedBytes": page_bytes + cap + 1,
                    "resultMember": None, "resultSha256": None, "candidateMember": None, "candidateSha256": None,
                    "candidateRecords": 0, "status": "FAILED", "reason": "UNKNOWN_OUTCOME"})
                run["pendingJob"] = None
                journal["cursor"] = job["jobId"]
                journal["observedAt"] = monitor.stamp(now)
                save_journal(store, journal)
                if checkpoint:
                    checkpoint("RESERVED", ordinal)
                # 親は同じ保護予約を読戻し、私有permitを消費して実runnerを一回だけ呼ぶ。
                response = bridge.exchange("EXECUTE_JOB", run_id, plan_hash, ordinal=ordinal,
                                           reservationSha256=reservation_hash)
                if checkpoint:
                    checkpoint("RESULT_RECEIVED", ordinal)
                ended = clock()
                cr.require(ended >= now and response["ordinal"] == ordinal and
                           response["resultMember"] == f"result-{ordinal}.json", "DISTRIBUTION_RESULT_BINDING")
                native_result = read_hash(directory / response["resultMember"], response["resultSha256"])
                verify_page_body(directory, ordinal, native_result, job, job_hash,
                                 required=response["pageProof"])
                if response["pageProof"]:
                    cr.require(response["page"]["complete"] is True and
                               response["pageSha256"] == native_result["pageObservation"]["bodySha256"] and
                               response["page"]["bytes"] == native_result["pageObservation"]["bodyBytes"],
                               "DISTRIBUTION_PAGE_BODY_RESPONSE")
                cr.require(response["candidateMember"] == f"candidate-{ordinal}.json", "DISTRIBUTION_CANDIDATE_MEMBER")
                candidate = read_hash(directory / response["candidateMember"], response["candidateSha256"])
                cr.require(candidate["binding"]["runId"] == run_id and
                           candidate["binding"]["ordinal"] == ordinal and
                           candidate["jobSha256"] == job_hash and len(candidate["records"]) == response["candidateRecords"],
                           "DISTRIBUTION_CANDIDATE_BINDING")
                row = run["jobs"][ordinal]
                cr.require(row["phase"] == "RESERVED", "DISTRIBUTION_DOUBLE_SETTLEMENT")
                charged_requests = charged_bytes = 0
                for stage, key, maximum_requests, maximum_bytes in (
                        ("page", keys[0], page_requests, page_bytes), ("payload", keys[1], 3, cap + 1)):
                    if maximum_requests == 0:
                        continue
                    observation = response[stage]
                    cr.fields(observation, {"complete", "requests", "bytes", "status"}, "DISTRIBUTION_TRANSFER_FIELDS")
                    cr.require(type(observation["complete"]) is bool and type(observation["requests"]) is int and
                               type(observation["bytes"]) is int and 0 <= observation["requests"] <= maximum_requests and
                               0 <= observation["bytes"] <= maximum_bytes, "DISTRIBUTION_TRANSFER_LIMIT")
                    actual = observation["complete"]
                    requests_charge = observation["requests"] if actual else maximum_requests
                    bytes_charge = observation["bytes"] if actual else maximum_bytes
                    item = journal["requests"][key]
                    cr.require(item["phase"] == "RESERVED" and item["runId"] == run_id and
                               item["ordinal"] == ordinal, "DISTRIBUTION_DOUBLE_SETTLEMENT")
                    item.update(phase="SETTLED_ACTUAL" if actual else "SETTLED_MAXIMUM", endedAt=monitor.stamp(ended),
                                chargedRequests=requests_charge, chargedBytes=bytes_charge,
                                nextDueAt=monitor.stamp(max(cr.timestamp(item["nextDueAt"]), ended + monitor.DAY)))
                    charged_requests += requests_charge
                    charged_bytes += bytes_charge
                    if stage == "page":
                        page = state["requests"][key]
                        # 公開PAGE成功本文の再importをせず、typed完全観測のhashだけを保持する。
                        page.update(outcome="FAILED", reason="TRANSPORT_FAILED", endedAt=monitor.stamp(ended),
                                    nextDueAt=item["nextDueAt"], httpStatus=observation["status"] or None)
                        if actual and response["pageProof"]:
                            page_proofs.add(key)
                            page.update(outcome="SUCCESS", reason="NONE", httpStatus=200,
                                lastSuccess={"checkedAt": monitor.stamp(ended), "bodySha256": response["pageSha256"],
                                             "bodyBytes": observation["bytes"], "linkHashes": []})
                    if not actual:
                        state["hosts"][item["hostSha256"]] = {"failedAt": monitor.stamp(ended),
                            "nextDueAt": item["nextDueAt"], "held": True}
                row.update(phase="SETTLED_ACTUAL" if response["page"]["complete"] and response["payload"]["complete"]
                           else "SETTLED_MAXIMUM", chargedRequests=charged_requests, chargedBytes=charged_bytes,
                           resultMember=response["resultMember"], resultSha256=response["resultSha256"],
                           candidateMember=response["candidateMember"], candidateSha256=response["candidateSha256"],
                           candidateRecords=response["candidateRecords"],
                           status=response["status"], reason=response["reason"])
                if response["status"] == "SUCCESS":
                    journal["requests"][keys[1]]["lastSuccess"] = {"runId": run_id, "ordinal": ordinal,
                        "checkedAt": monitor.stamp(ended), "resultSha256": response["resultSha256"]}
                target.update(status=response["status"], reasons=[] if response["status"] == "SUCCESS" else [response["reason"]])
                state["observedAt"] = journal["observedAt"] = monitor.stamp(ended)
                monitor.save_state(store, state)
                save_journal(store, journal)
                total_requests += charged_requests
                total_bytes += charged_bytes
                used.append(ordinal)
                if checkpoint:
                    checkpoint("SETTLED", ordinal)
            run["phase"] = "FINISHED"
            save_journal(store, journal)
            built = build_candidate(package, root, run_id, bridge, clock=clock)
            response = bridge.exchange("FINISH_RUN", run_id, plan_hash, build=built)
            commit_candidate(store, run_id, built, response)
        except BaseException:
            # 予約は抹消せず、次回同writerのrecoverへ最大課金として残す。
            raise
        success_count = sum(row["status"] == "SUCCESS" for row in run["targets"])
        return {"result": "COMPLETE" if run["targets"] and success_count == len(run["targets"]) and
                not run["unprofiledRecords"] else "PARTIAL_OR_HELD",
                "targets": len(run["targets"]), "success": success_count, "executed": len(used),
                "requests": total_requests, "bodyBytes": total_bytes, "unprofiledRecords": len(run["unprofiledRecords"]),
                "producerConnected": True, "candidateRecords": sum(row["candidateRecords"] for row in run["jobs"]),
                "candidatePrepared": built is not None, "signingGenerationFinalized": False, "tasks": 0}
