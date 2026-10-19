"""取得証拠と構造観測へ結合した明示SFX選択を、非実行で両構成検査する。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import subprocess
import time
import zipfile

import collector_registry as cr
import collector_large_payload_evidence as lp
import inspect_large_registry_payloads as ip

PLAN_SCHEMA = "dc-maintenance-sfx-selection-plan-v1"
PROOF_SCHEMA = "dc-maintenance-sfx-selection-evidence-v1"
STRUCTURE_SCHEMA = "dc-maintenance-sfx-structure-observations-v1"
MAX_SELECTED = 2 * lp.GIB
MAX_EXPORT = MAX_SELECTED + 16 * 1024 ** 2
ROOT = Path(__file__).resolve().parents[1]


def exact(value: dict, keys: set[str], code: str) -> None:
    """未知fieldを許可せず、研究専用契約をfail-closedで確認する。"""
    cr.require(isinstance(value, dict) and set(value) == keys, code)


def sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def bounded_integer(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def normalized_hash(document: dict) -> str:
    return cr.digest(cr.json_bytes(document))


def export_hash(path: Path) -> str:
    """出力管理領域込みの2GiB＋16MiB以内を有限hash化する。元入力の上限は変えない。"""
    cr.regular_path(path)
    before = path.stat()
    cr.require(0 < before.st_size <= MAX_EXPORT, "EXPORT_SIZE")
    value = hashlib.sha256()
    consumed = 0
    started = time.monotonic()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 ** 2):
            consumed += len(chunk)
            cr.require(consumed <= MAX_EXPORT and time.monotonic() - started <= 900, "EXPORT_BUDGET")
            value.update(chunk)
    cr.regular_path(path)
    after = path.stat()
    cr.require(consumed == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ino) ==
               (after.st_size, after.st_mtime_ns, after.st_ino), "EXPORT_CHANGED")
    return value.hexdigest()


def validate_metadata(entries: list[dict]) -> dict[int, dict]:
    """旧観測の有限path・index・sizeを再検証し、改変した選択を通さない。"""
    cr.require(isinstance(entries, list) and 0 < len(entries) <= 32768, "METADATA_ENTRIES")
    names = set()
    expanded = 0
    by_index = {}
    for entry in entries:
        exact(entry, {"index", "path", "bytes"}, "METADATA_ENTRY")
        cr.require(bounded_integer(entry["index"], 0, 2 ** 32 - 1) and
                   bounded_integer(entry["bytes"], 0, 4 * lp.GIB) and
                   isinstance(entry["path"], str) and
                   len(entry["path"]) <= 1024 and entry["index"] not in by_index, "METADATA_VALUE")
        name = entry["path"].replace("\\", "/")
        parts = name.split("/")
        cr.require(not name.startswith("/") and all(32 <= ord(c) < 127 and c not in ':<>"|?*' for c in name) and
                   all(part not in {"", ".", ".."} and not part.endswith((" ", ".")) for part in parts), "METADATA_PATH")
        key = name.casefold()
        cr.require(key not in names, "METADATA_DUPLICATE")
        names.add(key)
        expanded += entry["bytes"]
        cr.require(expanded <= 8 * lp.GIB, "METADATA_EXPANSION")
        by_index[entry["index"]] = entry
    cr.require(not any("/".join(name.split("/")[:index]) in names
                       for name in names for index in range(1, len(name.split("/")))), "METADATA_PARENT_COLLISION")
    return by_index


def validate_structure(structure: dict, large: dict) -> dict[str, dict]:
    """旧両構成観測と大型取得証拠の結合を確認する。内容合格は推定しない。"""
    exact(structure, {"schema", "researchOnly", "publishable", "installAuthorized", "largeEvidenceSha256",
                      "toolSha256", "checkedAt", "derivedMembers", "samples"}, "STRUCTURE_SCHEMA")
    cr.require(structure["schema"] == STRUCTURE_SCHEMA and structure["researchOnly"] is True and
               structure["publishable"] is False and structure["installAuthorized"] is False and
               structure["largeEvidenceSha256"] == normalized_hash(large) and sha(structure["toolSha256"]),
               "STRUCTURE_BINDING")
    cr.require(isinstance(structure["samples"], list) and 0 < len(structure["samples"]) <= 16,
               "STRUCTURE_SAMPLES")
    by_name = {}
    for row in structure["samples"]:
        exact(row, {"sample", "sha256", "configurationsEqual", "configurations"}, "STRUCTURE_SAMPLE")
        cr.require(isinstance(row["sample"], str) and row["sample"] not in by_name and sha(row["sha256"])
                   and row["configurationsEqual"] is True and set(row["configurations"]) == {"Debug", "Release"},
                   "STRUCTURE_CONFIGURATIONS")
        results = row["configurations"]
        cr.require(results["Debug"]["observation"] == results["Release"]["observation"], "STRUCTURE_MISMATCH")
        observed = results["Release"]["observation"]
        if observed["state"] != "METADATA_VALID":
            continue
        cr.require(all(result["exitCode"] == 0 and sha(result["toolSha256"]) for result in results.values()) and
                   observed["inputSha256"] == row["sha256"] and observed["payloadDecoded"] is False and
                   observed["contentSignatureVerified"] is False, "STRUCTURE_OBSERVATION")
        validate_metadata(observed["entries"])
        by_name[row["sample"]] = row
    return by_name


def validate_plan(plan: dict, registry: dict, large: dict, structure: dict) -> dict:
    """一回16選択以下のplanを、元構造の完全一致entryだけへ制限する。"""
    exact(plan, {"schema", "revision", "registrySha256", "largeEvidenceSha256", "structureSha256", "selections"},
          "PLAN_SCHEMA")
    cr.require(plan["schema"] == PLAN_SCHEMA and isinstance(plan["revision"], str) and
               re.fullmatch(r"[a-z0-9-]{1,80}", plan["revision"]) is not None and
               plan["registrySha256"] == normalized_hash(registry) and
               plan["largeEvidenceSha256"] == normalized_hash(large) and
               plan["structureSha256"] == normalized_hash(structure), "PLAN_BINDING")
    samples = validate_structure(structure, large)
    acquired = {row["recordId"]: row for row in large["evidence"]["acquisitions"]}
    cr.require(isinstance(plan["selections"], list) and 0 < len(plan["selections"]) <= 16, "PLAN_COUNT")
    names = set()
    for selection in plan["selections"]:
        exact(selection, {"name", "recordId", "sample", "vendor", "purpose", "inputSha256", "entries"},
              "SELECTION_SCHEMA")
        name = selection["name"]
        cr.require(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]{1,80}", name) is not None and name not in names,
                   "SELECTION_NAME")
        names.add(name)
        sample = samples.get(selection["sample"])
        acquisition = acquired.get(selection["recordId"])
        cr.require(sample is not None and acquisition is not None and acquisition["state"] == "DOWNLOADED" and
                   selection["inputSha256"] == sample["sha256"] and selection["vendor"] in {"AMD", "NVIDIA"} and
                   selection["purpose"] in {"INF_CATALOG", "DISPLAY_CLOSURE"}, "SELECTION_BINDING")
        # 元EXE自体か、CRCと全byteを確認した元ZIP memberであることを要求する。
        if selection["inputSha256"] != acquisition["sha256"]:
            matched = [row for row in structure["derivedMembers"] if row["localFile"] == selection["sample"] and
                       row["recordId"] == selection["recordId"] and row["sourceSha256"] == acquisition["sha256"] and
                       row["memberSha256"] == selection["inputSha256"]]
            cr.require(len(matched) == 1, "DERIVED_BINDING")
        metadata = validate_metadata(sample["configurations"]["Release"]["observation"]["entries"])
        selected = selection["entries"]
        cr.require(isinstance(selected, list) and 0 < len(selected) <= 1024, "SELECTION_COUNT")
        indices = set()
        for entry in selected:
            exact(entry, {"index", "path", "bytes"}, "SELECTED_ENTRY")
            cr.require(type(entry["index"]) is int and entry["index"] not in indices and
                       metadata.get(entry["index"]) == entry, "SELECTED_ENTRY_BINDING")
            indices.add(entry["index"])
        cr.require(sum(row["bytes"] for row in selected) <= MAX_SELECTED, "SELECTION_BYTES")
        infs = [row for row in selected if row["path"].lower().endswith(".inf")]
        cr.require(0 < len(infs) <= 512 and sum(row["bytes"] for row in infs) <= 64 * 1024 ** 2 and
                   all(0 < row["bytes"] <= 4 * 1024 ** 2 for row in infs), "INF_BUDGET")
        if selection["purpose"] == "INF_CATALOG":
            cr.require(all(row["path"].lower().endswith((".inf", ".cat")) for row in selected), "METADATA_PURPOSE")
        else:
            cr.require(len(infs) == 1, "CLOSURE_INF_COUNT")
    return plan


def verify_export(target: Path, observation: dict, selection: dict) -> None:
    """研究ZIP全byteと全memberを再読し、元index証拠を破棄せず結合する。"""
    keys = {"state", "inputSha256", "selectedBytes", "requiredDecodeBytes", "exportSha256", "exportBytes",
            "entries", "contentInspections", "payloadDecoded", "installAuthorized", "publishable"}
    # 旧先行取得の証拠は参照計画を持たない。存在しない参照合格を推定しない。
    if "referenceInspections" in observation:
        keys.add("referenceInspections")
    if "maintenanceReferences" in observation:
        keys.add("maintenanceReferences")
    exact(observation, keys,
          "NATIVE_SCHEMA")
    cr.require(observation["state"] == "SELECTED_EXPORTED" and observation["inputSha256"] == selection["inputSha256"]
               and observation["payloadDecoded"] is True and observation["installAuthorized"] is False and
               observation["publishable"] is False and sha(observation["exportSha256"]) and
               bounded_integer(observation["exportBytes"], 1, MAX_EXPORT), "NATIVE_BINDING")
    expected = {row["index"]: row for row in selection["entries"]}
    observed = {}
    for row in observation["entries"]:
        exact(row, {"index", "path", "bytes", "sha256"}, "NATIVE_MEMBER")
        cr.require(type(row["index"]) is int and row["index"] not in observed and sha(row["sha256"]) and
                   expected.get(row["index"]) == {key: row[key] for key in ("index", "path", "bytes")}, "NATIVE_ENTRY_BINDING")
        observed[row["index"]] = row
    cr.require(set(observed) == set(expected) and observation["selectedBytes"] == sum(r["bytes"] for r in expected.values()),
               "NATIVE_ENTRIES")
    cr.require(bounded_integer(observation["requiredDecodeBytes"], 1, 8 * lp.GIB) and
               isinstance(observation["contentInspections"], list), "NATIVE_CONTENT")
    inspections = observation["contentInspections"]
    cr.require(len(inspections) == 1 if selection["purpose"] == "DISPLAY_CLOSURE" else len(inspections) <= 1, "CONTENT_COUNT")
    for inspection in inspections:
        exact(inspection, {"infPath", "infSha256", "stage", "error", "verified", "externalDependencies"}, "CONTENT_SCHEMA")
        infs = [row for row in observed.values() if row["path"].lower().endswith(".inf")]
        cr.require(len(infs) == 1 and inspection["infPath"] == infs[0]["path"] and
                   inspection["infSha256"] == infs[0]["sha256"] and
                   inspection["stage"] in {"INF_STRUCTURE", "CATALOG_INTEGRITY"} and
                   bounded_integer(inspection["error"], 0, 2 ** 32 - 1) and type(inspection["verified"]) is bool and
                   type(inspection["externalDependencies"]) is bool and
                   inspection["verified"] == (inspection["stage"] == "CATALOG_INTEGRITY" and inspection["error"] == 0),
                   "CONTENT_BINDING")
    if "referenceInspections" in observation:
        refs = observation["referenceInspections"]
        infs = {row["path"]: row for row in observed.values() if row["path"].lower().endswith(".inf")}
        cr.require(isinstance(refs, list) and len(refs) == len(infs), "REFERENCE_COUNT")
        seen = set()
        for ref in refs:
            exact(ref, {"infPath", "infSha256", "error", "closureEntries", "contentSignatureVerified"}, "REFERENCE_SCHEMA")
            cr.require(isinstance(ref["infPath"], str) and ref["infPath"] in infs and ref["infPath"] not in seen and
                       ref["infSha256"] == infs[ref["infPath"]]["sha256"] and ref["contentSignatureVerified"] is False and
                       bounded_integer(ref["error"], 0, 2 ** 32 - 1) and isinstance(ref["closureEntries"], list), "REFERENCE_BINDING")
            seen.add(ref["infPath"])
            if ref["error"] == 0:
                cr.require(0 < len(ref["closureEntries"]) <= 1024, "REFERENCE_BUDGET")
                validate_metadata(ref["closureEntries"])
                cr.require(sum(row["bytes"] for row in ref["closureEntries"]) <= MAX_SELECTED and
                           [r for r in ref["closureEntries"] if r["path"].lower().endswith(".inf")] ==
                           [{key: infs[ref["infPath"]][key] for key in ("index", "path", "bytes")}], "REFERENCE_INF")
            else:
                cr.require(not ref["closureEntries"], "PARTIAL_REFERENCE")
    if "maintenanceReferences" in observation:
        validate_maintenance_references(observation)
    cr.require(export_hash(target) == observation["exportSha256"] and target.stat().st_size == observation["exportBytes"],
               "EXPORT_HASH")
    started = time.monotonic()
    members = {row["path"].replace("\\", "/"): row for row in observed.values()}
    with zipfile.ZipFile(target) as archive:
        infos = archive.infolist()
        ip.validate_entries(infos)
        cr.require(len(infos) == len(members) and {row.filename for row in infos} == set(members), "EXPORT_MEMBERS")
        for info in infos:
            expected_member = members[info.filename]
            cr.require(info.file_size == expected_member["bytes"], "EXPORT_MEMBER_SIZE")
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                while chunk := stream.read(1024 ** 2):
                    cr.require(time.monotonic() - started <= 900, "EXPORT_TIME")
                    digest.update(chunk)
            cr.require(digest.hexdigest() == expected_member["sha256"], "EXPORT_MEMBER_HASH")
    cr.require(export_hash(target) == observation["exportSha256"], "EXPORT_CHANGED")


def validate_maintenance_references(observation: dict) -> dict[str, dict]:
    """実取得INFのhashに棚卸しを結合する。成功を内容合格へ変換しない。"""
    infs = {r["path"].replace("\\", "/").casefold(): r for r in observation["entries"]
            if r["path"].lower().endswith(".inf")}
    rows = observation["maintenanceReferences"]
    cr.require(isinstance(rows, list) and len(rows) == len(infs), "MAINTENANCE_COUNT")
    bound = {}
    for row in rows:
        exact(row, {"infPath", "infSha256", "error", "stage", "class", "catalogPath", "directEntries",
                    "copyInfPaths", "externalDependencies", "installActionsError", "contentSignatureVerified"},
              "MAINTENANCE_SCHEMA")
        cr.require(isinstance(row["infPath"], str), "MAINTENANCE_INF")
        key = row["infPath"].replace("\\", "/").casefold()
        cr.require(key in infs and key not in bound and row["infSha256"] == infs[key]["sha256"] and
                   bounded_integer(row["error"], 0, 2 ** 32 - 1) and bounded_integer(row["stage"], 0, 4) and
                   bounded_integer(row["installActionsError"], 0, 2 ** 32 - 1) and
                   type(row["externalDependencies"]) is bool and row["contentSignatureVerified"] is False and
                   isinstance(row["class"], str) and isinstance(row["catalogPath"], str) and
                   isinstance(row["directEntries"], list) and isinstance(row["copyInfPaths"], list), "MAINTENANCE_BINDING")
        if row["error"]:
            cr.require(row["stage"] != 4 and not row["class"] and not row["catalogPath"] and
                       not row["directEntries"] and not row["copyInfPaths"] and not row["externalDependencies"] and
                       row["installActionsError"] == 0, "MAINTENANCE_PARTIAL")
        else:
            cr.require(row["stage"] == 4 and isinstance(row["class"], str) and 0 < len(row["class"]) <= 128 and
                       all(32 <= ord(c) < 127 for c in row["class"]) and isinstance(row["catalogPath"], str) and
                       row["catalogPath"].lower().endswith(".cat") and len(row["directEntries"]) <= 8194 and
                       len(row["copyInfPaths"]) <= 1024, "MAINTENANCE_COMPLETE")
            direct = validate_metadata(row["directEntries"])
            cr.require(infs[key]["index"] in direct and direct[infs[key]["index"]] ==
                       {k: infs[key][k] for k in ("index", "path", "bytes")}, "MAINTENANCE_ORIGINAL_INF")
            names = {r["path"].replace("\\", "/").casefold() for r in direct.values()}
            cr.require(row["catalogPath"].replace("\\", "/").casefold() in names, "MAINTENANCE_CAT")
            if row["copyInfPaths"]:
                validate_metadata([{"index": n, "path": p, "bytes": 0} for n, p in enumerate(row["copyInfPaths"])])
                parent = key.rsplit("/", 1)[0] + "/" if "/" in key else ""
                cr.require(all("%" not in p and p.lower().endswith(".inf") and p.replace("\\", "/").casefold().startswith(parent)
                               for p in row["copyInfPaths"]), "MAINTENANCE_COPY_INF")
        bound[key] = row
    return bound


def build_reference_closures(observation: dict, original_entries: list[dict], *,
                             maximum_bytes: int = MAX_SELECTED) -> list[dict]:
    """CopyINFを有限一意graphとして展開する。未取得・欠落・外部依存は完全閉包にしない。"""
    cr.require(bounded_integer(maximum_bytes, 1, 8 * lp.GIB), "LOGICAL_CLOSURE_BUDGET")
    inventory = validate_metadata(original_entries)
    by_path = {r["path"].replace("\\", "/").casefold(): r for r in inventory.values()}
    rows = validate_maintenance_references(observation)
    for row in rows.values():
        for entry in row["directEntries"]:
            cr.require(inventory.get(entry["index"]) == entry, "MAINTENANCE_ORIGINAL_MEMBER")
    plans = []
    for root, initial in rows.items():
        pending = [root]
        queued = {root}
        seen = set()
        selected = {}
        problems = set()
        total = 0
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            if len(seen) > 1024:
                problems.add("DEPENDENCY_CAPACITY")
                break
            if key not in by_path:
                problems.add("COPY_INF_MISSING")
                continue
            if key not in rows:
                problems.add("CHILD_INF_UNACQUIRED")
                continue
            row = rows[key]
            if row["error"]:
                problems.add("CHILD_REFERENCE_REJECTED" if key != root else "ROOT_REFERENCE_REJECTED")
                continue
            if row["externalDependencies"]:
                problems.add("EXTERNAL_DEPENDENCY_UNRESOLVED")
            for entry in row["directEntries"]:
                if entry["index"] in selected:
                    continue
                total += entry["bytes"]
                selected[entry["index"]] = entry
                if total > maximum_bytes or len(selected) > 1024:
                    problems.add("CLOSURE_CAPACITY")
                    break
            if "CLOSURE_CAPACITY" in problems:
                break
            for path in row["copyInfPaths"]:
                child = path.replace("\\", "/").casefold()
                if child not in queued:
                    queued.add(child)
                    if len(queued) > 1024:
                        problems.add("DEPENDENCY_CAPACITY")
                        break
                    pending.append(child)
            if "DEPENDENCY_CAPACITY" in problems:
                break
        plans.append({"infPath": initial["infPath"], "infSha256": initial["infSha256"],
                      "state": "UNRESOLVED" if problems else "REFERENCE_COMPLETE",
                      "reasons": sorted(problems), "visitedInfCount": len(seen),
                      "closureEntries": [] if problems else sorted(selected.values(), key=lambda r: r["index"]),
                      "contentSignatureVerified": False, "installAuthorized": False, "publishable": False})
    return plans


def source_path(selection: dict, structure: dict, acquired: dict, payloads: Path, members: Path) -> Path:
    """元EXEまたは元ZIP内memberの実byteを確認し、任意入力への差替えを拒否する。"""
    source = acquired[selection["recordId"]]
    if selection["inputSha256"] == source["sha256"]:
        path = payloads / (selection["recordId"] + ".exe")
    else:
        row = next(row for row in structure["derivedMembers"] if row["localFile"] == selection["sample"])
        cr.require(re.fullmatch(r"[a-z0-9-]+\.exe", row["localFile"]) is not None, "MEMBER_FILE")
        original = payloads / (selection["recordId"] + ".zip")
        cr.require(ip.file_hash(original) == source["sha256"], "ORIGINAL_HASH")
        with zipfile.ZipFile(original) as archive:
            ip.validate_entries(archive.infolist())
            info = archive.getinfo(row["member"])
            cr.require(info.file_size == row["memberBytes"], "ORIGINAL_MEMBER_SIZE")
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                while chunk := stream.read(1024 ** 2):
                    digest.update(chunk)
            cr.require(digest.hexdigest() == selection["inputSha256"], "ORIGINAL_MEMBER_HASH")
        cr.require(ip.file_hash(original) == source["sha256"], "ORIGINAL_CHANGED")
        path = members / row["localFile"]
    cr.require(ip.file_hash(path) == selection["inputSha256"], "INPUT_HASH")
    return path.resolve()


def run_selection(tool: Path, payload: Path, selection: dict, target: Path) -> dict:
    """自作子検査器だけを900秒で制限する。installerを実行しない。"""
    cr.require(not target.exists(), "OUTPUT_EXISTS")
    csv = ",".join(str(row["index"]) for row in selection["entries"])
    tool_hash = ip.file_hash(tool)
    started = time.monotonic()
    result = subprocess.run([str(tool), "--select", str(payload), selection["inputSha256"], selection["vendor"],
                             str(target), csv], capture_output=True, timeout=900, check=False)
    cr.require(len(result.stdout) <= 16 * 1024 ** 2 and len(result.stderr) <= 1024 ** 2, "NATIVE_OUTPUT")
    import json
    observed = json.loads(result.stdout)
    cr.require(result.returncode == (0 if observed.get("state") == "SELECTED_EXPORTED" else 2), "NATIVE_EXIT")
    if result.returncode == 0:
        verify_export(target, observed, selection)
    else:
        exact(observed, {"state", "stage", "error"}, "NATIVE_REJECTION")
        cr.require(observed["state"] == "REJECTED" and not target.exists(), "PARTIAL_EXPORT")
    cr.require(ip.file_hash(payload) == selection["inputSha256"], "INPUT_CHANGED")
    cr.require(ip.file_hash(tool) == tool_hash, "TOOL_CHANGED")
    return {"toolSha256": tool_hash, "durationSeconds": round(time.monotonic() - started, 3),
            "exitCode": result.returncode, "exportFile": target.name if result.returncode == 0 else None,
            "observation": observed}


def comparable(result: dict) -> dict:
    """observationから生成ZIP全体のexportSha256とexportBytesだけを除いた比較用写像を返す。
    その他のmember・内容検査項目は保持する。
    """
    return {key: value for key, value in result["observation"].items() if key not in {"exportSha256", "exportBytes"}}


def main() -> int:
    """検証した入力/toolを借用し、payloadを実行せず両構成のnative検査を進める。

    新規output内へ結果/proofを逐次保存する。保存後の不一致やnative拒否、I/O例外でも
    証拠と部分出力を残し、自動削除/rollbackしない。導入/公開許可は発行しない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--large-evidence", type=Path, required=True)
    parser.add_argument("--structure", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--payload-directory", type=Path, required=True)
    parser.add_argument("--member-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    registry = cr.validate_registry(cr.read_json(args.registry))
    large = lp.validate_large_evidence(registry, cr.read_json(args.large_evidence))
    structure = cr.read_json(args.structure)
    plan = validate_plan(cr.read_json(args.plan), registry, large, structure)
    destination = args.output_directory.resolve()
    cr.check_ancestors(destination)
    cr.require(not destination.exists(), "OUTPUT_EXISTS")
    tools = {config: ROOT / "build" / config / "drivercrate_official_sfx_structure_smoke.exe"
             for config in ("Debug", "Release")}
    for tool in tools.values():
        cr.regular_path(tool)
    acquired = {row["recordId"]: row for row in large["evidence"]["acquisitions"]}
    inputs = {row["name"]: source_path(row, structure, acquired, args.payload_directory.resolve(),
                                      args.member_directory.resolve()) for row in plan["selections"]}
    proof = {"schema": PROOF_SCHEMA, "researchOnly": True, "publishable": False, "installAuthorized": False,
             "registrySha256": normalized_hash(registry), "largeEvidenceSha256": normalized_hash(large),
             "structureSha256": normalized_hash(structure), "planSha256": normalized_hash(plan),
             "toolSha256": ip.file_hash(Path(__file__)), "checkedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "selections": []}
    destination.mkdir()
    for row in plan["selections"]:
        results = {}
        for config, tool in tools.items():
            results[config] = run_selection(tool, inputs[row["name"]], row, destination / (row["name"] + "-" + config.lower() + ".zip"))
            print(row["name"], config, results[config]["observation"]["state"], flush=True)
        equal = comparable(results["Debug"]) == comparable(results["Release"])
        proof["selections"].append({"selection": row, "configurationsEqual": equal, "configurations": results})
        reference_plans = {}
        original = next(s for s in structure["samples"] if s["sample"] == row["sample"])
        for config, result in results.items():
            if "maintenanceReferences" in result["observation"]:
                reference_plans[config] = build_reference_closures(
                    result["observation"], original["configurations"][config]["observation"]["entries"])
        cr.require(not reference_plans or reference_plans["Debug"] == reference_plans["Release"], "REFERENCE_PLAN_MISMATCH")
        with (destination / ("selection-evidence-" + str(len(proof["selections"])) + ".json")).open("xb") as stream:
            stream.write(cr.json_bytes(proof))
        if reference_plans:
            reference_proof = {"schema": "dc-maintenance-inf-reference-plan-v1", "researchOnly": True,
                               "publishable": False, "installAuthorized": False,
                               "selectionEvidenceSha256": normalized_hash(proof), "structureSha256": normalized_hash(structure),
                               "plans": reference_plans["Release"]}
            with (destination / ("reference-plan-" + str(len(proof["selections"])) + ".json")).open("xb") as stream:
                stream.write(cr.json_bytes(reference_proof))
        cr.require(equal, "CONFIGURATION_MISMATCH")
        cr.require(all(result["exitCode"] == 0 for result in results.values()), "SELECTION_REJECTED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, zipfile.BadZipFile, UnicodeError):
        # Package中のIDやabsolute pathを例外本文へ出さない。
        print("SFX selection failed; no install or publication authorized.")
        raise SystemExit(2)
