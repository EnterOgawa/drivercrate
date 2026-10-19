"""元取得証拠へ結合したGPU参照を有限分割取得し、CAT/member内容検査を保存する。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time

import collector_registry as cr
import collector_large_payload_evidence as lp
import inspect_large_registry_payloads as ip
import select_registry_sfx_members as sm

PLAN_SCHEMA = "dc-maintenance-batched-closure-plan-v1"
PROOF_SCHEMA = "dc-maintenance-batched-closure-evidence-v1"
DIRECT_PLAN_SCHEMA = "dc-maintenance-direct-content-plan-v1"
DIRECT_PROOF_SCHEMA = "dc-maintenance-direct-content-evidence-v1"
ROOT = Path(__file__).resolve().parents[1]


def path_key(path: str) -> str:
    return path.replace("\\", "/").casefold()


def batch_count(entries: list[dict]) -> int:
    """一file2GiB・論理8GiB以下を2GiBの有限batchへ分割する。"""
    sm.validate_metadata(entries)
    cr.require(0 < len(entries) <= 1024 and sum(r["bytes"] for r in entries) <= 8 * lp.GIB and
               all(r["bytes"] <= 2 * lp.GIB for r in entries), "BATCH_BUDGET")
    infs = [r for r in entries if r["path"].lower().endswith(".inf")]
    cr.require(0 < len(infs) <= 512 and all(0 < r["bytes"] <= 4 * 1024 ** 2 for r in infs) and
               sum(r["bytes"] for r in infs) <= 64 * 1024 ** 2, "BATCH_INF_BUDGET")
    count, total = 1, 0
    for row in entries:
        if total + row["bytes"] > 2 * lp.GIB:
            count += 1
            total = 0
        total += row["bytes"]
    return count


def root_closure(observation: dict, original: list[dict], root_index: int) -> dict:
    """明示rootの全参照だけを解決する。未取得CopyINFと外部依存を省略しない。"""
    cr.require(sm.bounded_integer(root_index, 0, 2 ** 32 - 1), "ROOT_INDEX")
    metadata = sm.validate_metadata(original)
    root = metadata.get(root_index)
    cr.require(root is not None and root["path"].lower().endswith(".inf"), "ROOT_INF")
    plans = sm.build_reference_closures(observation, original, maximum_bytes=8 * lp.GIB)
    found = [r for r in plans if path_key(r["infPath"]) == path_key(root["path"])]
    cr.require(len(found) == 1 and found[0]["state"] == "REFERENCE_COMPLETE", "ROOT_UNRESOLVED")
    batch_count(found[0]["closureEntries"])
    return found[0]


def root_direct(observation: dict, original: list[dict], root_index: int) -> dict:
    """直接sourceを全件解決し、CopyINFと外部依存の完成は推定しない。"""
    cr.require(sm.bounded_integer(root_index, 0, 2 ** 32 - 1), "ROOT_INDEX")
    metadata = sm.validate_metadata(original)
    root = metadata.get(root_index)
    cr.require(root is not None and root["path"].lower().endswith(".inf"), "ROOT_INF")
    refs = sm.validate_maintenance_references(observation)
    row = refs.get(path_key(root["path"]))
    cr.require(row is not None and row["error"] == 0, "DIRECT_ROOT_REJECTED")
    cr.require(all(metadata.get(r["index"]) == r for r in row["directEntries"]), "DIRECT_ORIGINAL_MEMBER")
    batch_count(row["directEntries"])
    return row


def make_plan(selection: dict, previous: dict, original: list[dict], root_index: int,
              bindings: dict, *, scope: str = "closure") -> dict:
    """旧2GiB計画を変更せず、明示8GiB modeの別planを発行する。"""
    cr.require(scope in {"closure", "direct"}, "CONTENT_SCOPE")
    if scope == "direct":
        direct = root_direct(previous, original, root_index)
        return {"schema": DIRECT_PLAN_SCHEMA, **bindings, "rootIndex": root_index,
                "dependencyClosureVerified": False,
                "selection": {**selection, "purpose": "DIRECT_CONTENT",
                              "entries": sorted(direct["directEntries"], key=lambda r: r["index"])}}
    closure = root_closure(previous, original, root_index)
    return {"schema": PLAN_SCHEMA, **bindings, "rootIndex": root_index,
            "selection": {**selection, "purpose": "REFERENCE_CONTENT", "entries": closure["closureEntries"]}}


def validate_plan(plan: dict, previous: dict, original: list[dict], bindings: dict,
                  source_selection: dict) -> dict:
    cr.require(isinstance(plan, dict) and plan.get("schema") in {PLAN_SCHEMA, DIRECT_PLAN_SCHEMA}, "CONTENT_PLAN_SCHEMA")
    direct = plan["schema"] == DIRECT_PLAN_SCHEMA
    keys = {"schema", "rootIndex", "selection", *bindings}
    if direct:
        keys.add("dependencyClosureVerified")
        cr.require(plan.get("dependencyClosureVerified") is False, "DIRECT_PLAN_DEPENDENCY")
    sm.exact(plan, keys, "CLOSURE_PLAN_SCHEMA")
    cr.require(all(plan[k] == v for k, v in bindings.items()),
               "CLOSURE_PLAN_BINDING")
    expected = make_plan(source_selection, previous, original, plan["rootIndex"], bindings,
                         scope="direct" if direct else "closure")
    cr.require(plan == expected, "CLOSURE_PLAN_MEMBERS")
    return plan


def validate_observation(observed: dict, plan: dict, previous: dict, original: list[dict]) -> bool:
    """全取得member・全INF内容結果を元byteと結合し、偽の部分合格を拒否する。"""
    direct = plan["schema"] == DIRECT_PLAN_SCHEMA
    cr.require(plan["schema"] in {PLAN_SCHEMA, DIRECT_PLAN_SCHEMA} and
               plan["selection"]["purpose"] == ("DIRECT_CONTENT" if direct else "REFERENCE_CONTENT"), "CONTENT_SCOPE")
    keys = {"state", "inputSha256", "rootIndex", "selectedBytes", "batches", "entries",
            "maintenanceReferences", "contentInspections", "payloadDecoded", "installAuthorized", "publishable"}
    if direct:
        keys.add("dependencyClosureVerified")
        cr.require(observed.get("dependencyClosureVerified") is False and
                   plan.get("dependencyClosureVerified") is False, "DIRECT_NATIVE_DEPENDENCY")
    sm.exact(observed, keys, "CLOSURE_NATIVE_SCHEMA")
    selection = plan["selection"]
    cr.require(observed["state"] == ("DIRECT_CONTENT_OBSERVED" if direct else "REFERENCE_CONTENT_OBSERVED") and
               observed["inputSha256"] == selection["inputSha256"] and
               type(observed["rootIndex"]) is int and observed["rootIndex"] == plan["rootIndex"] and
               observed["payloadDecoded"] is True and observed["installAuthorized"] is False and
               observed["publishable"] is False and
               type(observed["selectedBytes"]) is int and
               observed["selectedBytes"] == sum(r["bytes"] for r in selection["entries"]) and
               type(observed["batches"]) is int and observed["batches"] == batch_count(selection["entries"]),
               "CLOSURE_NATIVE_BINDING")
    cr.require(isinstance(observed["entries"], list), "CLOSURE_NATIVE_ENTRIES")
    rows = {}
    for row in observed["entries"]:
        sm.exact(row, {"index", "path", "bytes", "sha256"}, "CLOSURE_NATIVE_MEMBER")
        cr.require(type(row["index"]) is int and row["index"] not in rows and sm.sha(row["sha256"]),
                   "CLOSURE_NATIVE_HASH")
        rows[row["index"]] = row
    cr.require([{k: r[k] for k in ("index", "path", "bytes")} for r in rows.values()] == selection["entries"],
               "CLOSURE_NATIVE_MEMBERS")
    refs = sm.validate_maintenance_references(observed)
    old_refs = sm.validate_maintenance_references(previous)
    cr.require(all(key in old_refs and ref == old_refs[key] for key, ref in refs.items()), "CLOSURE_REFERENCE_CHANGED")
    if direct:
        rederived = root_direct(observed, original, plan["rootIndex"])
        expected = sorted(rederived["directEntries"], key=lambda r: r["index"])
    else:
        rederived = root_closure(observed, original, plan["rootIndex"])
        expected = rederived["closureEntries"]
    cr.require(expected == selection["entries"], "CLOSURE_REFERENCE_OMISSION")
    infs = {path_key(r["path"]): r for r in rows.values() if r["path"].lower().endswith(".inf")}
    if direct:
        infs = {key: r for key, r in infs.items() if r["index"] == plan["rootIndex"]}
    checks = observed["contentInspections"]
    cr.require(isinstance(checks, list) and len(checks) == len(infs), "CLOSURE_CONTENT_COUNT")
    seen = set()
    for check in checks:
        acquired_key = "directReferencesAcquired" if direct else "referencesAcquired"
        sm.exact(check, {"infPath", "infSha256", "referenceError", acquired_key, "integrityError",
                         "contentSignatureVerified"}, "CLOSURE_CONTENT_SCHEMA")
        cr.require(isinstance(check["infPath"], str), "CLOSURE_CONTENT_INF")
        key = path_key(check["infPath"])
        cr.require(key in infs and key not in seen and check["infSha256"] == infs[key]["sha256"] and
                   sm.bounded_integer(check["referenceError"], 0, 2 ** 32 - 1) and check["referenceError"] == 0 and
                   check[acquired_key] is True and
                   sm.bounded_integer(check["integrityError"], 0, 2 ** 32 - 1) and
                   type(check["contentSignatureVerified"]) is bool and
                   check["contentSignatureVerified"] == (check["integrityError"] == 0), "CLOSURE_CONTENT_BINDING")
        seen.add(key)
    return all(c["contentSignatureVerified"] for c in checks)


def verify_previous(proof: dict, old_plan: dict, directory: Path, bindings: dict) -> None:
    """旧両構成証拠と全INF/CAT ZIPの実byteを再検証する。"""
    sm.exact(proof, {"schema", "researchOnly", "publishable", "installAuthorized", "registrySha256",
                     "largeEvidenceSha256", "structureSha256", "planSha256", "toolSha256", "checkedAt",
                     "selections"}, "SOURCE_SELECTION_SCHEMA")
    cr.require(proof["schema"] == sm.PROOF_SCHEMA and proof["researchOnly"] is True and
               proof["publishable"] is False and proof["installAuthorized"] is False and
               sm.sha(proof["toolSha256"]) and proof["planSha256"] == sm.normalized_hash(old_plan) and
               all(proof[k] == bindings[k] for k in ("registrySha256", "largeEvidenceSha256", "structureSha256")) and
               len(proof["selections"]) == len(old_plan["selections"]), "SOURCE_SELECTION_BINDING")
    for row, expected in zip(proof["selections"], old_plan["selections"], strict=True):
        sm.exact(row, {"selection", "configurationsEqual", "configurations"}, "SOURCE_SELECTION_ROW")
        cr.require(row["selection"] == expected and row["configurationsEqual"] is True and
                   set(row["configurations"]) == {"Debug", "Release"}, "SOURCE_SELECTION_CONFIGURATIONS")
        for result in row["configurations"].values():
            sm.exact(result, {"toolSha256", "durationSeconds", "exitCode", "exportFile", "observation"},
                     "SOURCE_SELECTION_RESULT")
            cr.require(result["exitCode"] == 0 and sm.sha(result["toolSha256"]) and
                       isinstance(result["exportFile"], str) and Path(result["exportFile"]).name == result["exportFile"],
                       "SOURCE_SELECTION_EXPORT")
            sm.verify_export(directory / result["exportFile"], result["observation"], expected)
        cr.require(sm.comparable(row["configurations"]["Debug"]) == sm.comparable(row["configurations"]["Release"]),
                   "SOURCE_SELECTION_MISMATCH")


def run_native(tool: Path, payload: Path, plan: dict, previous: dict, original: list[dict]) -> dict:
    """自作検査器だけを900秒に制限し、installerを実行しない。"""
    selection = plan["selection"]
    tool_hash = ip.file_hash(tool)
    cr.require(ip.file_hash(payload) == selection["inputSha256"], "CLOSURE_INPUT_HASH")
    started = time.monotonic()
    mode = "--verify-direct" if plan["schema"] == DIRECT_PLAN_SCHEMA else "--verify-closure"
    result = subprocess.run([str(tool), mode, str(payload), selection["inputSha256"],
                             selection["vendor"], str(plan["rootIndex"]),
                             ",".join(str(r["index"]) for r in selection["entries"])],
                            capture_output=True, timeout=900, check=False)
    cr.require(len(result.stdout) <= 16 * 1024 ** 2 and len(result.stderr) <= 1024 ** 2, "CLOSURE_OUTPUT_BUDGET")
    observation = json.loads(result.stdout)
    if observation.get("state") == "REJECTED":
        sm.exact(observation, {"state", "stage", "error"}, "CLOSURE_NATIVE_REJECTION")
        cr.require(result.returncode == 2 and sm.bounded_integer(observation["error"], 1, 2 ** 32 - 1) and
                   isinstance(observation["stage"], str), "CLOSURE_NATIVE_REJECTED")
        verified = False
    else:
        cr.require(result.returncode == 0, "CLOSURE_NATIVE_EXIT")
        verified = validate_observation(observation, plan, previous, original)
    cr.require(ip.file_hash(tool) == tool_hash and ip.file_hash(payload) == selection["inputSha256"], "CLOSURE_CHANGED")
    return {"toolSha256": tool_hash, "durationSeconds": round(time.monotonic() - started, 3),
            "exitCode": result.returncode, "contentSignatureVerified": verified, "observation": observation}


def main() -> int:
    """検証した入力/toolを借用し、payloadを実行せずnativeの分割内容検査を進める。

    新規output内へplan・両構成の結果・evidenceを逐次保存する。不一致やnative拒否、
    I/O失敗では証拠と部分出力を残し、自動削除/rollbackしない。導入/公開許可は発行しない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("registry", "large-evidence", "structure", "selection-plan", "selection-evidence",
                 "payload-directory", "member-directory", "output-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--root-sample", required=True)
    parser.add_argument("--root-inf", required=True)
    parser.add_argument("--scope", choices=("closure", "direct"), default="closure")
    args = parser.parse_args()
    registry = cr.validate_registry(cr.read_json(args.registry))
    large = lp.validate_large_evidence(registry, cr.read_json(args.large_evidence))
    structure = cr.read_json(args.structure)
    old_plan = sm.validate_plan(cr.read_json(args.selection_plan), registry, large, structure)
    source = cr.read_json(args.selection_evidence)
    bindings = {"registrySha256": sm.normalized_hash(registry), "largeEvidenceSha256": sm.normalized_hash(large),
                "structureSha256": sm.normalized_hash(structure), "selectionEvidenceSha256": sm.normalized_hash(source)}
    verify_previous(source, old_plan, args.selection_evidence.resolve().parent, bindings)
    found = [r for r in source["selections"] if r["selection"]["sample"] == args.root_sample]
    cr.require(len(found) == 1, "CLOSURE_SOURCE_SAMPLE")
    previous = found[0]["configurations"]["Release"]["observation"]
    original = sm.validate_structure(structure, large)[args.root_sample]["configurations"]["Release"]["observation"]["entries"]
    roots = [r for r in original if path_key(r["path"]) == path_key(args.root_inf)]
    cr.require(len(roots) == 1, "CLOSURE_ROOT_PATH")
    plan = make_plan(found[0]["selection"], previous, original, roots[0]["index"], bindings, scope=args.scope)
    validate_plan(plan, previous, original, bindings, found[0]["selection"])
    destination = args.output_directory.resolve()
    cr.check_ancestors(destination)
    cr.require(not destination.exists(), "OUTPUT_EXISTS")
    acquired = {r["recordId"]: r for r in large["evidence"]["acquisitions"]}
    payload = sm.source_path(plan["selection"], structure, acquired, args.payload_directory.resolve(),
                             args.member_directory.resolve())
    tools = {config: ROOT / "build" / config / "drivercrate_official_sfx_structure_smoke.exe"
             for config in ("Debug", "Release")}
    for tool in tools.values():
        cr.regular_path(tool)
    destination.mkdir()
    prefix = "direct" if args.scope == "direct" else "closure"
    with (destination / (prefix + "-plan.json")).open("xb") as stream:
        stream.write(cr.json_bytes(plan))
    results = {}
    for config, tool in tools.items():
        results[config] = run_native(tool, payload, plan, previous, original)
        with (destination / (prefix + "-" + config.lower() + ".json")).open("xb") as stream:
            stream.write(cr.json_bytes(results[config]))
        print(config, results[config]["observation"]["state"],
              "contentVerified=" + str(results[config]["contentSignatureVerified"]), flush=True)
    equal = results["Debug"]["observation"] == results["Release"]["observation"]
    proof = {"schema": DIRECT_PROOF_SCHEMA if args.scope == "direct" else PROOF_SCHEMA,
             "researchOnly": True, "publishable": False, "installAuthorized": False,
             **bindings, "planSha256": sm.normalized_hash(plan), "toolSha256": ip.file_hash(Path(__file__)),
             "checkedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "plan": plan,
             "configurationsEqual": equal, "configurations": results,
             "contentSignatureVerified": equal and all(r["contentSignatureVerified"] for r in results.values())}
    if args.scope == "direct":
        proof["dependencyClosureVerified"] = False
    with (destination / (prefix + "-evidence.json")).open("xb") as stream:
        stream.write(cr.json_bytes(proof))
    cr.require(equal, "CLOSURE_CONFIGURATION_MISMATCH")
    return 0 if all(r["exitCode"] == 0 for r in results.values()) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        print("Closure verification failed; no install or publication authorized.")
        raise SystemExit(2)
