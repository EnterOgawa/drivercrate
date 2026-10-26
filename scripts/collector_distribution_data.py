"""配布収集の可搬dataを検証し、保護workspaceのactive世代を非通信で切り替える。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
package/通信許可/私有run証拠とは独立した公開dataだけを扱う。
"""
from __future__ import annotations

import argparse
import base64
import gzip
import io
import os
from pathlib import Path
import re
import stat
import tempfile

import collector_collection_profiles as profiles
import collector_registry as cr
import registry_daily_monitor as monitor

SCHEMA = "dc-collector-distribution-data-v1"
ACTIVE_SCHEMA = "dc-collector-distribution-active-v1"
INPUTS = {"registry": "registry.json", "locators": "locators.json", "profiles": "collection-profiles.json"}
BASE = {*INPUTS.values(), "research-index.json"}
ARTIFACTS = {"index.json", "index.json.gz", "manifest.raw.json", "build-report.json", "provenance.json"}
REFERENCE_FILES = {"reference.json", *("references/" + name for name in ARTIFACTS)}
MAX_TOTAL = 64 * 1024 * 1024
# 保持rootの全履歴と新規保存のピークだけへ適用する。可搬inputのMAX_TOTALを変えない。
MAX_WORKSPACE_TOTAL = 256 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 8192


def public_json(value: object) -> None:
    """公開dataへcredential、端末path、鍵または実行指示を混入させない。"""
    if isinstance(value, dict):
        for key, child in value.items():
            cr.require(key.casefold() not in {"password", "credential", "token", "cookie", "privatekey",
                "serialnumber", "instanceid", "nativeRoot".casefold(), "monitorroot", "workspaceroot",
                "command", "script", "permit", "executionpermit"}, "DATA_SECRET_OR_COMMAND")
            public_json(child)
    elif isinstance(value, list):
        for child in value:
            public_json(child)
    elif isinstance(value, str):
        cr.require("PRIVATE KEY" not in value and not re.search(r"(?i)(?:bearer\s+|[?&](?:token|key|auth|sig)=)", value)
                   and not re.match(r"^[A-Za-z]:[\\/]", value), "DATA_SECRET_OR_PATH")


def reference_content(store: Path) -> dict[str, bytes]:
    """検証済みheadの公開出力だけを元hash/原点/producer付き参照として取り出す。"""
    import collector_distribution_pipeline as pipeline
    head_path = store / "distribution/candidate-head.json"
    if not head_path.exists():
        return {}
    head = cr.read_json(head_path)
    pipeline.verify_layout(store / "distribution")
    cr.require(set(head["outputs"]) == ARTIFACTS, "DATA_REFERENCE_OUTPUTS")
    result = {}
    for name, digest in head["outputs"].items():
        raw = profiles.read_raw(store / "distribution/runs" / head["runId"] / name)
        cr.require(cr.digest(raw) == digest, "DATA_REFERENCE_HASH")
        result["references/" + name] = raw
    provenance = cr.parse_json(result["references/provenance.json"])
    observations = []
    for row in provenance["observations"]:
        candidate = row["observation"]
        observations.append({"sha256": row["reference"]["sha256"], "runId": row["reference"]["runId"],
            "ordinal": row["reference"]["ordinal"], "jobSha256": candidate["jobSha256"],
            "checkedAtUtc": candidate["checkedAtUtc"], "validUntilUtc": candidate["validUntilUtc"],
            "inputHashes": candidate["binding"]["inputHashes"],
            "producerHashes": candidate["binding"]["producerHashes"],
            "originSha256": candidate["binding"]["monitorIdentity"]})
    result["references/provenance.json"] = cr.json_bytes({**provenance,
        "schema": "dc-collector-public-provenance-v1", "observations": observations})
    reference = {"schema": "dc-collector-public-reference-v1", "generation": head["generation"],
        "runId": head["runId"], "originSha256": head["monitorIdentity"],
        "inputHashes": head["inputHashes"], "producerHashes": head["producerHashes"],
        "originalOutputs": head["outputs"], "outputs": {name: cr.digest(result["references/" + name])
        for name in ARTIFACTS}, "privateEvidence": False, "communicationAuthorized": False}
    result["reference.json"] = cr.json_bytes(reference)
    return result


def validate_reference(content: dict[str, bytes]) -> None:
    """参照成果物の閉集合と全hash/元時刻を検査し、私有観測へ昇格させない。"""
    if "reference.json" not in content:
        return
    ref = cr.fields(cr.parse_json(content["reference.json"]), {"schema", "generation", "runId",
        "originSha256", "inputHashes", "producerHashes", "originalOutputs", "outputs", "privateEvidence", "communicationAuthorized"},
        "DATA_REFERENCE_FIELDS")
    cr.require(ref["schema"] == "dc-collector-public-reference-v1" and ref["privateEvidence"] is False and
        ref["communicationAuthorized"] is False and type(ref["generation"]) is int and ref["generation"] > 0,
        "DATA_REFERENCE_SCHEMA")
    cr.sha256(ref["originSha256"])
    cr.fields(ref["inputHashes"], set(INPUTS), "DATA_REFERENCE_INPUTS")
    cr.fields(ref["producerHashes"], {"native", "pipeline", "profiles"}, "DATA_REFERENCE_PRODUCER")
    for digest in [*ref["inputHashes"].values(), *ref["producerHashes"].values()]:
        cr.sha256(digest)
    cr.require(set(ref["outputs"]) == ARTIFACTS, "DATA_REFERENCE_OUTPUTS")
    cr.require(set(ref["originalOutputs"]) == ARTIFACTS and all(
        ref["outputs"][name] == digest for name, digest in ref["originalOutputs"].items() if name != "provenance.json"),
        "DATA_REFERENCE_ORIGINAL_HASH")
    for digest in ref["originalOutputs"].values():
        cr.sha256(digest)
    for name, digest in ref["outputs"].items():
        cr.require(cr.digest(content["references/" + name]) == digest, "DATA_REFERENCE_HASH")
        if name != "index.json.gz":
            public_json(cr.parse_json(content["references/" + name]))
    manifest = cr.parse_json(content["references/manifest.raw.json"])
    cr.require(manifest["schema"] == "driver-index-manifest-v1" and manifest["generation"] == ref["generation"],
               "DATA_REFERENCE_MANIFEST")
    cr.timestamp(manifest["publishedAtUtc"])
    cr.timestamp(manifest["expiresAtUtc"])
    packed = content["references/index.json.gz"]
    cr.require(manifest["asset"]["sha256"] == cr.digest(packed) and manifest["asset"]["sizeBytes"] == len(packed),
               "DATA_REFERENCE_ASSET_HASH")
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        expanded = stream.read(cr.MAX_JSON_BYTES + 1)
        cr.require(len(expanded) <= cr.MAX_JSON_BYTES and stream.read(1) == b"", "DATA_REFERENCE_EXPANSION_LIMIT")
    cr.require(expanded == content["references/index.json"], "DATA_REFERENCE_GZIP_BYTES")
    index = cr.fields(cr.parse_json(expanded), {"schema", "assetGeneration", "sources", "records"}, "DATA_REFERENCE_INDEX_FIELDS")
    cr.require(index["schema"] == "driver-index-records-v2" and index["assetGeneration"] == ref["generation"],
               "DATA_REFERENCE_INDEX_SCHEMA")
    for row in index["records"]:
        cr.fields(row, {"recordBytesBase64", "recordSha256"}, "DATA_REFERENCE_RECORD_FIELDS")
        record = base64.b64decode(row["recordBytesBase64"], validate=True)
        cr.require(len(record) <= 65536 and cr.digest(record) == row["recordSha256"], "DATA_REFERENCE_RECORD_HASH")
        public_json(cr.parse_json(record))
    provenance = cr.parse_json(content["references/provenance.json"])
    cr.fields(provenance, {"schema", "runId", "inputHashes", "producerHashes", "monitorIdentity", "observations"},
              "DATA_REFERENCE_PROVENANCE")
    cr.require(provenance["schema"] == "dc-collector-public-provenance-v1" and
               provenance["runId"] == ref["runId"] and provenance["inputHashes"] == ref["inputHashes"] and
               provenance["producerHashes"] == ref["producerHashes"] and
               provenance["monitorIdentity"] == ref["originSha256"], "DATA_REFERENCE_PROVENANCE_BINDING")
    for row in provenance["observations"]:
        cr.fields(row, {"sha256", "runId", "ordinal", "jobSha256", "checkedAtUtc", "validUntilUtc", "inputHashes",
                       "producerHashes", "originSha256"}, "DATA_REFERENCE_OBSERVATION_FIELDS")
        cr.require(cr.timestamp(row["checkedAtUtc"]) < cr.timestamp(row["validUntilUtc"]), "DATA_REFERENCE_TIME")


def bundle_content(raw: dict[str, bytes], references: dict[str, bytes] | None = None,
                   *, retained: bool = False) -> dict[str, bytes]:
    """元三入力から全参照/hashと研究索引を自動計算し、確認時刻を書き換えない。"""
    cr.require(set(raw) == set(INPUTS), "DATA_INPUT_SET")
    inputs = profiles.load_inputs(raw["registry"], raw["locators"])
    profile_value = cr.parse_json(raw["profiles"])
    if retained and profile_value.get("schema") == "dc-collector-collection-profiles-v1":
        # 保存dataの原byte/参照/世代だけを監査し、現行実行入力へ変換しない。
        cr.fields(profile_value, {"schema", "revision", "asOf", "registry", "locators", "profiles",
                                  "networkAuthorized", "publishable", "installAuthorized"}, "PROFILES_FIELDS")
        cr.identity(profile_value["revision"])
        cr.require(cr.timestamp(profile_value["asOf"]) >= cr.timestamp(inputs["locators"]["asOf"]), "PROFILES_TIME")
        cr.require(profile_value["registry"] == inputs["bindings"]["registry"] and
                   profile_value["locators"] == inputs["bindings"]["locators"] and
                   profile_value["networkAuthorized"] is False and profile_value["publishable"] is False and
                   profile_value["installAuthorized"] is False, "DATA_RETAINED_BINDING")
        cr.require(type(profile_value["profiles"]) is list and len(profile_value["profiles"]) <= profiles.MAX_PROFILES,
                   "DATA_RETAINED_PROFILES")
        ids = set()
        for row in profile_value["profiles"]:
            cr.fields(row, profiles.BOUND_FIELDS, "PROFILE_FIELDS")
            cr.identity(row["id"])
            cr.require(row["id"] not in ids, "DATA_RETAINED_DUPLICATE")
            ids.add(row["id"])
            cr.require(row["referenceSha256"] == profiles.reference_digest(row, inputs), "PROFILE_REFERENCE_CHANGED")
    else:
        profiles.validate_profiles(profile_value, inputs)
    result = {INPUTS[name]: value for name, value in raw.items()}
    result["research-index.json"] = cr.json_bytes(cr.research_index(inputs["registry"]))
    if references:
        cr.require(set(references) == REFERENCE_FILES, "DATA_REFERENCE_FILE_SET")
        result.update(references)
    for name, value in result.items():
        cr.require(0 < len(value) <= cr.MAX_JSON_BYTES, "DATA_FILE_LIMIT")
        if name != "references/index.json.gz":
            public_json(cr.parse_json(value))
    validate_reference(result)
    manifest = {"schema": SCHEMA, "inputHashes": {name: cr.digest(value) for name, value in raw.items()},
        "includesReference": bool(references), "files": [{"path": name, "bytes": len(value),
        "sha256": cr.digest(value)} for name, value in sorted(result.items())]}
    result["manifest.json"] = cr.json_bytes(manifest)
    cr.require(sum(map(len, result.values())) <= MAX_TOTAL, "DATA_TOTAL_LIMIT")
    return result


def verify_bundle(root: Path, *, retained: bool = False) -> dict:
    """全file/原byte/hashとsemantic参照を有限検証し、未知file/schemaを拒否する。"""
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    manifest_raw = profiles.read_raw(root / "manifest.json")
    manifest = cr.fields(cr.parse_json(manifest_raw), {"schema", "inputHashes", "includesReference", "files"},
                         "DATA_MANIFEST_FIELDS")
    cr.require(manifest["schema"] == SCHEMA and type(manifest["includesReference"]) is bool, "DATA_SCHEMA")
    expected = BASE | {"manifest.json"} | (REFERENCE_FILES if manifest["includesReference"] else set())
    found = set()
    for path in root.rglob("*"):
        cr.regular_path(path, directory=path.is_dir())
        if path.is_dir():
            cr.require(path == root / "references" and manifest["includesReference"], "DATA_DIRECTORY_SET")
        else:
            found.add(path.relative_to(root).as_posix())
        cr.require(len(found) <= 12, "DATA_FILE_COUNT")
    cr.require(found == expected, "DATA_FILE_SET")
    raw = {name: profiles.read_raw(root / member) for name, member in INPUTS.items()}
    references = {member: profiles.read_raw(root / member) for member in REFERENCE_FILES} if manifest["includesReference"] else None
    content = bundle_content(raw, references, retained=retained)
    cr.require(content["manifest.json"] == manifest_raw, "DATA_MANIFEST_HASH_OR_CANONICAL")
    for member, value in content.items():
        cr.require(profiles.read_raw(root / member) == value, "DATA_FILE_HASH")
    inputs = profiles.load_inputs(raw["registry"], raw["locators"])
    return {"raw": raw, "inputs": inputs, "profiles": cr.parse_json(raw["profiles"]),
            "content": content, "sha256": cr.digest(manifest_raw), "manifest": manifest}


def write_bundle(output: Path, content: dict[str, bytes]) -> None:
    """新規集合へflush/readbackし、途中保存はactiveへ昇格しない。"""
    cr.require(not output.exists(), "DATA_OUTPUT_EXISTS")
    output.mkdir()
    for member, raw in sorted(content.items()):
        (output / member).parent.mkdir(exist_ok=True)
        monitor.write_new_bytes(output / member, raw)
    verify_bundle(output)


def active_bundle(root: Path, *, retained: bool = False) -> dict | None:
    """存在するactiveが壊れていればseedへ戻さず拒否する。"""
    directory = root / "data"
    if not directory.exists():
        return None
    cr.regular_path(directory, directory=True)
    cr.require({path.name for path in directory.iterdir()} == {"writer.lock", "generations", "active.json"}, "DATA_STORE_SET")
    cr.regular_path(directory / "generations", directory=True)
    pointer = cr.fields(cr.read_json(directory / "active.json"), {"schema", "sha256"}, "DATA_ACTIVE_FIELDS")
    cr.require(pointer["schema"] == ACTIVE_SCHEMA, "DATA_ACTIVE_SCHEMA")
    cr.sha256(pointer["sha256"])
    for path in (directory / "generations").iterdir():
        cr.sha256(path.name)
        cr.regular_path(path, directory=True)
    value = verify_bundle(directory / "generations" / pointer["sha256"], retained=retained)
    cr.require(value["sha256"] == pointer["sha256"], "DATA_ACTIVE_HASH")
    return value


def require_import_capacity(root: Path, value: dict, pointer: bytes) -> None:
    """全保持treeと新世代/active pendingのピークを保存前に有限検査する。

    呼出し元のdata writer lock内で使用し、新規storeだけはscaffolding作成前にも呼ぶ。
    旧activeはpendingと共存するため差し引かない。既存世代は増分0だがpendingは数える。
    ACL/実identity/競合の境界はnativeが維持し、同一userの任意書換えへの新保証は加えない。
    """
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    entries = 0
    total = 0
    pending = [root]
    # 検査済み通常directoryだけを展開し、全entry上限で列挙を終了する。
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                cr.require(entries <= MAX_WORKSPACE_ENTRIES, "WORKSPACE_ENTRY_LIMIT")
                path = Path(child.path)
                info = path.lstat()
                directory = stat.S_ISDIR(info.st_mode)
                cr.regular_path(path, directory=directory)
                if directory:
                    pending.append(path)
                else:
                    cr.require(info.st_nlink == 1, "WORKSPACE_OBJECT")
                    size = info.st_size
                    cr.require(0 <= size <= cr.MAX_JSON_BYTES and size <= MAX_WORKSPACE_TOTAL and
                               total <= MAX_WORKSPACE_TOTAL - size, "WORKSPACE_BYTE_LIMIT")
                    total += size
    directory = root / "data"
    target = directory / "generations" / value["sha256"]
    additions = {}
    if not directory.exists():
        additions.update({directory: 0, directory / "generations": 0, directory / "writer.lock": 1})
    if not target.exists():
        additions[target] = 0
        for member, raw in value["content"].items():
            path = target / member
            additions[path] = len(raw)
            # 必要な子directoryを一度だけ数え、data世代rootで停止する。
            for parent in path.parents:
                if parent == target:
                    break
                additions[parent] = 0
    # 既存activeと同時に存在する新規pendingを含め、置換前ピークのentry数を確定する。
    cr.require(entries + len(additions) + 1 <= MAX_WORKSPACE_ENTRIES, "WORKSPACE_ENTRY_LIMIT")
    for size in [*additions.values(), len(pointer)]:
        cr.require(0 <= size <= cr.MAX_JSON_BYTES and size <= MAX_WORKSPACE_TOTAL and
                   total <= MAX_WORKSPACE_TOTAL - size, "WORKSPACE_BYTE_LIMIT")
        total += size


def import_data(root: Path, source: Path) -> dict:
    """全保持量の保存前判定で非通信importし、旧世代と運用待機/予算/同意を保持する。"""
    value = verify_bundle(source)
    directory = root / "data"
    raw = cr.json_bytes({"schema": ACTIVE_SCHEMA, "sha256": value["sha256"]})
    if not directory.exists():
        require_import_capacity(root, value, raw)
        directory.mkdir()
        (directory / "generations").mkdir()
        monitor.write_new_bytes(directory / "writer.lock", b"0")
    with monitor.exclusive_file_lock(directory / "writer.lock"):
        old = active_bundle(root, retained=True) if (directory / "active.json").exists() else None
        if old:
            previous = {row["id"]: row for row in old["profiles"]["profiles"]}
            current = {row["id"]: row for row in value["profiles"]["profiles"]}
            cr.require(previous.keys() <= current.keys(), "DATA_PROFILE_HISTORY_LOST")
            for key, row in previous.items():
                changed = row["referenceSha256"] != current[key]["referenceSha256"] or any(
                    row[name] != current[key][name] for name in profiles.PROFILE_FIELDS - {"revision", "review"})
                cr.require(not changed or current[key]["reviewState"] == "REVIEW_REQUIRED", "DATA_B1_REVIEW_REQUIRED")
            cr.require(cr.timestamp(value["profiles"]["asOf"]) >= cr.timestamp(old["profiles"]["asOf"]), "DATA_GENERATION_ROLLBACK")
        target = directory / "generations" / value["sha256"]
        if target.exists():
            cr.require(verify_bundle(target)["content"] == value["content"], "DATA_GENERATION_CHANGED")
        require_import_capacity(root, value, raw)
        if not target.exists():
            write_bundle(target, value["content"])
        descriptor, name = tempfile.mkstemp(prefix="active-", suffix=".pending", dir=directory)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            cr.require(profiles.read_raw(temporary) == raw, "DATA_POINTER_READBACK")
            os.replace(temporary, directory / "active.json")
        finally:
            if temporary.exists():
                temporary.unlink()
        cr.require(active_bundle(root)["sha256"] == value["sha256"], "DATA_ACTIVE_READBACK")
    return {"result": "DATA_IMPORTED_OFFLINE", "dataSha256": value["sha256"], "network": 0, "tasks": 0,
            "communicationAuthorized": False}


def main() -> int:
    """固定build/verifyだけを公開し、Task/HTTPや任意実行を提供しない。"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser("build")
    for name in ("registry", "locators", "profiles", "output"):
        build.add_argument(name, type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    export = sub.add_parser("export-active")
    export.add_argument("workspace", type=Path)
    export.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "build":
            raw = {name: profiles.read_raw(getattr(args, name)) for name in INPUTS}
            write_bundle(args.output, bundle_content(raw))
        elif args.action == "export-active":
            active = active_bundle(args.workspace)
            cr.require(active is not None, "DATA_ACTIVE_REQUIRED")
            reference = None
            if (args.workspace / "origin.json").exists():
                origin = cr.read_json(args.workspace / "origin.json")
                store = Path(origin["monitorRoot"])
                with monitor.writer_lock(store):
                    monitor.verify_store(store)
                    reference = reference_content(store)
            write_bundle(args.output, bundle_content(active["raw"], reference))
        else:
            verify_bundle(args.bundle)
        print('DATA_VERIFIED network=0 tasks=0 authority=0')
        return 0
    except (OSError, ValueError, KeyError, cr.RegistryError) as error:
        print("DATA_REJECTED", str(error) if isinstance(error, cr.RegistryError) else type(error).__name__)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
