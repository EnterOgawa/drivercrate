"""保守四軸をmetadata-onlyの共通研究索引へ投影する（ADR 0261）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
非通信・非実行。metadataの整合性は署名認証や原byte検査を代替しない。
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys

import collector_registry as cr
import collector_payload_evidence as pe

SCHEMA = "dc-maintenance-index-assessments-v1"
INDEX_SCHEMA = "dc-local-research-index-v4"
MANIFEST_SCHEMA = "dc-portable-maintenance-index-v1"
FILES = pe.BUNDLE_FILES | {"maintenance-assessments.json"}
KINDS = {"PACKAGE_ASSESSMENT", "PE_FLAT_TABLE"}
AXES = ("parser", "integrity", "applicability", "installRoute")
ROW_FIELDS = {"recordId", "recordSha256", "sourceSha256", "archiveSha256", "infSha256",
              "archiveDepth", "sourceKind", "proofSha256", "sourceMemberSha256",
              "derivedArchiveSha256", "dependencyState", *AXES}


def required_hash(value) -> None:
    """nullではないSHA-256だけを識別根拠に使用する。"""
    cr.sha256(value)
    cr.require(value is not None, "MAINTENANCE_HASH_MISSING")


def finding(value, allowed: set[str]) -> None:
    """独立findingのstateと符号付きHRESULTを厳密に検証する。"""
    cr.fields(value, {"state", "error"}, "MAINTENANCE_FINDING_FIELDS")
    cr.require(type(value["state"]) is str and value["state"] in allowed
               and type(value["error"]) is int and -(2 ** 31) <= value["error"] < 2 ** 31,
               "MAINTENANCE_FINDING_VALUE")
    cr.require((value["error"] == 0) == (value["state"] in {"NOT_CHECKED", "PASSED"}),
               "MAINTENANCE_FINDING_ERROR")


def row_key(row: dict) -> tuple:
    """同一配布・INF・深さ・原形式を重複判定と安定順へ使用する。"""
    return row["recordId"], row["infSha256"], row["archiveDepth"], row["sourceKind"]


def validate_assessments(registry: dict, evidence: dict, value: dict) -> dict:
    """観測metadataの内部整合性を検査する。原byte・WinTrustの再検証は行わない。"""
    registry = cr.validate_registry(registry)
    evidence = pe.validate_evidence(registry, evidence)
    cr.fields(value, {"schema", "researchOnly", "publishable", "installAuthorized", "registrySha256",
                      "payloadEvidenceSha256", "asOf", "proofs", "infs"}, "MAINTENANCE_FIELDS")
    cr.require(value["schema"] == SCHEMA and value["researchOnly"] is True
               and value["publishable"] is False and value["installAuthorized"] is False,
               "MAINTENANCE_PURPOSE")
    cr.require(value["registrySha256"] == cr.digest(cr.json_bytes(registry))
               and value["payloadEvidenceSha256"] == cr.digest(cr.json_bytes(evidence)),
               "MAINTENANCE_GENERATION")
    end = cr.timestamp(value["asOf"])
    cr.require(end >= cr.timestamp(evidence["asOf"]), "MAINTENANCE_TIME")
    cr.require(isinstance(value["proofs"], list) and 1 <= len(value["proofs"]) <= 32
               and isinstance(value["infs"], list) and 1 <= len(value["infs"]) <= 4096,
               "MAINTENANCE_BATCH_BUDGET")
    proofs = {}
    for proof in value["proofs"]:
        cr.fields(proof, {"kind", "sha256", "checkedAt"}, "MAINTENANCE_PROOF_FIELDS")
        required_hash(proof["sha256"])
        cr.require(type(proof["kind"]) is str and proof["kind"] in KINDS
                   and proof["sha256"] not in proofs
                   and cr.timestamp(evidence["asOf"]) <= cr.timestamp(proof["checkedAt"]) <= end,
                   "MAINTENANCE_PROOF")
        proofs[proof["sha256"]] = proof
    records = {row["id"]: row for row in registry["records"]}
    sources = {row["id"]: row for row in registry["sources"]}
    acquisitions = {row["recordId"]: row for row in evidence["acquisitions"]}
    seen = set()
    used = set()
    for row in value["infs"]:
        cr.fields(row, ROW_FIELDS, "MAINTENANCE_INF_FIELDS")
        key = cr.identity(row["recordId"])
        cr.require(key in records and key in acquisitions, "MAINTENANCE_RECORD")
        for name in ("recordSha256", "sourceSha256", "archiveSha256", "infSha256", "proofSha256"):
            required_hash(row[name])
        cr.require(type(row["archiveDepth"]) is int and row["archiveDepth"] in {0, 1}
                   and type(row["sourceKind"]) is str and row["sourceKind"] in KINDS,
                   "MAINTENANCE_INF_ORIGIN")
        record = records[key]
        acquired = acquisitions[key]
        cr.require(row["recordSha256"] == cr.digest(cr.json_bytes(record))
                   and row["sourceSha256"] == cr.digest(cr.json_bytes(sources[record["sourceId"]]))
                   and acquired["state"] == "DOWNLOADED" and row["archiveSha256"] == acquired["sha256"],
                   "MAINTENANCE_SOURCE_BINDING")
        proof = proofs.get(row["proofSha256"])
        cr.require(proof is not None and proof["kind"] == row["sourceKind"]
                   and cr.timestamp(acquired["checkedAt"]) <= cr.timestamp(proof["checkedAt"]),
                   "MAINTENANCE_PROOF_BINDING")
        used.add(row["proofSha256"])
        if row["sourceKind"] == "PE_FLAT_TABLE":
            required_hash(row["sourceMemberSha256"])
            required_hash(row["derivedArchiveSha256"])
            cr.require(row["archiveDepth"] == 0, "MAINTENANCE_PE_DEPTH")
        else:
            cr.require(row["sourceMemberSha256"] is None and row["derivedArchiveSha256"] is None,
                       "MAINTENANCE_ARCHIVE_ORIGIN")
        finding(row["parser"], {"PASSED"})
        finding(row["integrity"], {"PASSED"})
        finding(row["applicability"], {"NOT_CHECKED"})
        finding(row["installRoute"], {"NOT_CHECKED", "FAILED", "UNSUPPORTED"})
        cr.require(type(row["dependencyState"]) is str
                   and row["dependencyState"] in {"NONE_REFERENCED", "EXTERNAL_PRESENT"},
                   "MAINTENANCE_CONTENT_DEPENDENCY")
        # 原形式やproofだけの付替えで同じ配布・INF・深さを二重計上しない。
        identity = row_key(row)[:3]
        cr.require(identity not in seen, "MAINTENANCE_DUPLICATE_INF")
        seen.add(identity)
    cr.require(used == set(proofs), "MAINTENANCE_UNUSED_PROOF")
    normalized = copy.deepcopy(value)
    normalized["proofs"].sort(key=lambda row: row["sha256"])
    normalized["infs"].sort(key=row_key)
    cr.require(len(cr.json_bytes(normalized)) <= cr.MAX_JSON_BYTES, "OUTPUT_SIZE")
    return normalized


def assessment_counts(value: dict) -> dict:
    """部分INF内容と未検査端末・導入方式を、配布全体合格とは別に数える。"""
    rows = value["infs"]
    return {"recordsWithMaintenanceContent": len({row["recordId"] for row in rows}),
            "maintenanceContentVerifiedInfs": len(rows),
            "maintenanceExternalDependencyInfs": sum(row["dependencyState"] == "EXTERNAL_PRESENT" for row in rows),
            "maintenanceApplicabilityUncheckedInfs": len(rows),
            "maintenanceInstallRoutePassedInfs": 0}


def bundle_content(registry: dict, evidence: dict, assessments: dict) -> dict[str, bytes]:
    """旧metadataを保持し、八fileの研究用snapshotを決定的に生成する。"""
    registry = cr.validate_registry(registry)
    evidence = pe.validate_evidence(registry, evidence)
    assessments = validate_assessments(registry, evidence, assessments)
    content = pe.bundle_content(registry, evidence)
    index = cr.parse_json(content["index/drivers.json"])
    index.update(schema=INDEX_SCHEMA, asOf=assessments["asOf"],
                 maintenanceScope="PARTIAL_INF_CONTENT", maintenanceAssessments=assessments)
    index["counts"].update(assessment_counts(assessments))
    content["index/drivers.json"] = cr.json_bytes(index)
    content["maintenance-assessments.json"] = cr.json_bytes(assessments)
    del content["manifest.json"]
    cr.require(all(len(raw) <= cr.MAX_JSON_BYTES for raw in content.values()), "OUTPUT_SIZE")
    manifest = {"schema": MANIFEST_SCHEMA, "registrySchema": registry["schema"],
                "revision": registry["revision"], "asOf": assessments["asOf"],
                "registrySha256": cr.digest(cr.json_bytes(registry)),
                "files": [{"path": name, "bytes": len(raw), "sha256": cr.digest(raw)}
                          for name, raw in sorted(content.items())]}
    content["manifest.json"] = cr.json_bytes(manifest)
    return content


def tree_files(root: Path) -> None:
    """本文や未知file・reparseを含まない、閉じた八fileだけを受理する。"""
    cr.regular_path(root, directory=True)
    found = set()
    for item in root.iterdir():
        if item.name == "index":
            cr.regular_path(item, directory=True)
            for child in item.iterdir():
                cr.regular_path(child)
                found.add("index/" + child.name)
        else:
            cr.regular_path(item)
            found.add(item.name)
    cr.require(found == FILES, "MAINTENANCE_FILE_SET")


def verify_bundle(root: Path) -> tuple[dict, dict, dict]:
    """copy先のmetadataを全再構築する。署名・本体内容検査の成功を発行しない。"""
    cr.check_ancestors(root)
    tree_files(root)
    manifest = cr.read_json(root / "manifest.json")
    cr.fields(manifest, {"schema", "registrySchema", "revision", "asOf", "registrySha256", "files"},
              "MAINTENANCE_MANIFEST_FIELDS")
    cr.require(manifest["schema"] == MANIFEST_SCHEMA and type(manifest["registrySchema"]) is str
               and manifest["registrySchema"] in {cr.REGISTRY_SCHEMA, cr.QUERY_REGISTRY_SCHEMA},
               "MAINTENANCE_MANIFEST_SCHEMA")
    registry = {"schema": manifest["registrySchema"], "revision": manifest["revision"]}
    # 台帳時刻と内容観測時刻を混同せず、collection側を台帳時刻の正本にする。
    for name in cr.COLLECTIONS:
        document = cr.read_json(root / (name + ".json"))
        cr.fields(document, {"schema", "revision", "asOf", "items"}, "COLLECTION_FIELDS")
        if "asOf" not in registry:
            registry["asOf"] = document["asOf"]
        cr.require(document["schema"] == cr.collection_schema(registry["schema"], name)
                   and document["revision"] == registry["revision"] and document["asOf"] == registry["asOf"],
                   "COLLECTION_BINDING")
        registry[name] = document["items"]
    registry = cr.validate_registry(registry)
    evidence = pe.validate_evidence(registry, cr.read_json(root / "payload-evidence.json"))
    assessments = validate_assessments(registry, evidence, cr.read_json(root / "maintenance-assessments.json"))
    for name, expected in bundle_content(registry, evidence, assessments).items():
        path = root / name
        cr.regular_path(path)
        with path.open("rb") as stream:
            actual = stream.read(cr.MAX_JSON_BYTES + 1)
        cr.regular_path(path)
        cr.require(actual == expected, "MAINTENANCE_CONTENT_OR_HASH")
    tree_files(root)
    return registry, evidence, assessments


def write_bundle(registry: dict, evidence: dict, assessments: dict, output: Path) -> None:
    """新しいdirectoryへだけ保存し、既存世代を上書きしない。

    各fileのstreamはwithで終了処理を行う。書込みや最後の検証の失敗は伝播し、
    作成済みdirectoryと部分fileを自動削除・復元しない。残った既存出力は上書きせず拒否する。
    """
    content = bundle_content(registry, evidence, assessments)
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "index").mkdir()
    for name, raw in content.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    verify_bundle(output)


def main() -> int:
    """明示入力だけを投影する。原proofの検証は先行する保守runnerの責務とする。"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    for name in ("registry", "payload-evidence", "assessments", "output"):
        build.add_argument("--" + name, type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            write_bundle(cr.read_json(args.registry), cr.read_json(args.payload_evidence),
                         cr.read_json(args.assessments), args.output)
            _, _, value = verify_bundle(args.output)
        else:
            _, _, value = verify_bundle(args.snapshot)
        print(cr.json_bytes({"metadataConsistencyVerified": True, "contentReverified": False,
                             "installAuthorized": False, **assessment_counts(value)}).decode("utf-8"), end="")
        return 0
    except cr.RegistryError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
