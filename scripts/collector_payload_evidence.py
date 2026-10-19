"""取得観測を台帳へ結合し、本文を含まない研究用snapshotを生成する（ADR 0228／0233／0234）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
非通信の開発・保守tool。署名認証・実機適合・導入権限を発行しない。
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import json
import zipfile

import collector_registry as cr


EVIDENCE_SCHEMA = "dc-public-payload-evidence-v1"
CARRIED_EVIDENCE_SCHEMA = "dc-public-payload-evidence-v2"
BUNDLE_SCHEMA = "dc-portable-research-snapshot-v2"
BUNDLE_FILES = {*cr.SNAPSHOT_FILES, "manifest.json", "payload-evidence.json"}
ROW_FIELDS = {"id", "recordId", "checkedAt", "state", "httpStatus", "bytes", "sha256",
              "outerSignature", "publisher", "inspection", "inspectorSha256", "inspectionExitCode",
              "verifiedInfs", "rejectedInfs", "inventoryFiles", "reason"}


def validate_evidence(registry: dict, evidence: dict) -> dict:
    """台帳hash・参照・日時・状態の整合性を検証し、証拠を正規化する。"""
    return _validate_evidence(registry, evidence, maximum_payload_bytes=64 * 1024 * 1024)


def _validate_evidence(registry: dict, evidence: dict, *, maximum_payload_bytes: int) -> dict:
    """共通row検証。大型保守形式だけが別の明示予算で呼び、旧公開契約は64MiBを維持する。"""
    registry = cr.validate_registry(registry)
    carried = evidence.get("schema") == CARRIED_EVIDENCE_SCHEMA
    root_fields = {"schema", "revision", "registryRevision", "registrySha256", "asOf", "acquisitions"}
    cr.fields(evidence, root_fields | ({"originRegistry"} if carried else set()), "PAYLOAD_EVIDENCE_FIELDS")
    cr.require(evidence["schema"] in {EVIDENCE_SCHEMA, CARRIED_EVIDENCE_SCHEMA}, "PAYLOAD_EVIDENCE_SCHEMA")
    cr.identity(evidence["revision"])
    cr.require(evidence["registryRevision"] == registry["revision"] and
               evidence["registrySha256"] == cr.digest(cr.json_bytes(registry)), "EVIDENCE_REGISTRY_BINDING")
    as_of = cr.timestamp(evidence["asOf"])
    cr.require(as_of >= cr.timestamp(registry["asOf"]), "EVIDENCE_TIME")
    earliest = cr.timestamp(registry["asOf"])
    if carried:
        origin = evidence["originRegistry"]
        cr.fields(origin, {"revision", "sha256", "asOf"}, "ORIGIN_REGISTRY_FIELDS")
        cr.identity(origin["revision"])
        cr.sha256(origin["sha256"])
        cr.require(origin["sha256"] is not None and origin["revision"] != registry["revision"],
                   "ORIGIN_REGISTRY_BINDING")
        earliest = cr.timestamp(origin["asOf"])
        cr.require(earliest <= cr.timestamp(registry["asOf"]), "ORIGIN_REGISTRY_TIME")
    rows = evidence["acquisitions"]
    cr.require(isinstance(rows, list) and rows, "EVIDENCE_ROWS")
    records = {row["id"]: row for row in registry["records"]}
    seen_ids = set()
    seen_records = set()
    hashes = {}
    for row in rows:
        cr.fields(row, ROW_FIELDS | ({"recordSha256"} if carried else set()), "ACQUISITION_FIELDS")
        key = cr.identity(row["id"])
        cr.require(key not in seen_ids, "DUPLICATE_ACQUISITION")
        seen_ids.add(key)
        record_id = row["recordId"]
        cr.require(isinstance(record_id, str) and record_id in records and
                   record_id not in seen_records, "ACQUISITION_RECORD")
        seen_records.add(record_id)
        cr.require(earliest <= cr.timestamp(row["checkedAt"]) <= as_of,
                   "ACQUISITION_TIME")
        if carried:
            cr.require(row["recordSha256"] == cr.digest(cr.json_bytes(records[record_id])),
                       "ACQUISITION_RECORD_BINDING")
        cr.require(records[record_id]["downloadUrl"] is not None, "ACQUISITION_LINK")
        for field in ("bytes", "verifiedInfs", "rejectedInfs", "inventoryFiles"):
            cr.require(type(row[field]) is int and 0 <= row[field] <= 2**40, "ACQUISITION_INTEGER")
        status = row["httpStatus"]
        cr.require(status is None or (type(status) is int and 100 <= status <= 599), "HTTP_STATUS")
        cr.sha256(row["sha256"])
        cr.sha256(row["inspectorSha256"])
        cr.require(row["state"] in {"DOWNLOADED", "FAILED", "CONSENT_REQUIRED", "NOT_ATTEMPTED"},
                   "ACQUISITION_STATE")
        cr.require(row["reason"] in {"NONE", "TRANSFER_FAILED", "PAYLOAD_SIZE", "PAYLOAD_TYPE",
                                     "PUBLISHED_HASH_MISMATCH", "INPUT_CHANGED", "PRIVATE_DNS", "DNS_EMPTY",
                                     "DNS_FAMILY", "URL_POLICY", "OBSERVATION_FAILED", "CONSENT_REQUIRED",
                                     "NOT_ATTEMPTED"}, "ACQUISITION_REASON")
        downloaded = row["state"] == "DOWNLOADED"
        cr.require((row["reason"] == "NONE") == downloaded, "ACQUISITION_REASON_STATE")
        if row["state"] in {"CONSENT_REQUIRED", "NOT_ATTEMPTED"}:
            cr.require(row["reason"] == row["state"] and status is None, "UNATTEMPTED_EVIDENCE")
        if row["state"] == "FAILED":
            cr.require(row["reason"] not in {"CONSENT_REQUIRED", "NOT_ATTEMPTED"}, "FAILURE_REASON")
        if downloaded:
            cr.require(status == 200 and 0 < row["bytes"] <= maximum_payload_bytes and
                       row["sha256"] is not None, "DOWNLOADED_EVIDENCE")
            published = records[record_id]["publishedSha256"]
            cr.require(published is None or published == row["sha256"], "PUBLISHED_HASH_MISMATCH")
            cr.require(row["sha256"] not in hashes or hashes[row["sha256"]] == row["bytes"],
                       "HASH_BYTE_CONFLICT")
            hashes[row["sha256"]] = row["bytes"]
        else:
            cr.require(row["bytes"] == 0 and row["sha256"] is None, "FAILED_PAYLOAD_CLAIM")
        cr.require(row["outerSignature"] in {"NOT_CHECKED", "VALID", "UNSIGNED", "INVALID"},
                   "OUTER_SIGNATURE")
        if row["publisher"] is not None:
            cr.label(row["publisher"])
        cr.require(row["outerSignature"] != "VALID" or row["publisher"] is not None, "SIGNER_MISSING")
        cr.require(row["outerSignature"] != "NOT_CHECKED" or row["publisher"] is None, "UNCHECKED_SIGNER")
        state = row["inspection"]
        cr.require(state in {"NOT_CHECKED", "UNSUPPORTED", "PASSED", "PARTIAL", "REJECTED"},
                   "INSPECTION_STATE")
        inspected = state in {"PASSED", "PARTIAL", "REJECTED"}
        if inspected:
            cr.require(downloaded and row["inspectorSha256"] is not None and
                       type(row["inspectionExitCode"]) is int and 0 <= row["inspectionExitCode"] <= 2**32-1,
                       "INSPECTOR_EVIDENCE")
            cr.require(row["inventoryFiles"] >= row["verifiedInfs"] + row["rejectedInfs"],
                       "INSPECTION_COUNTS")
            if state == "PASSED":
                cr.require(row["inspectionExitCode"] == 0 and row["verifiedInfs"] > 0 and
                           row["rejectedInfs"] == 0, "PASSED_INSPECTION")
            elif state == "PARTIAL":
                cr.require(row["verifiedInfs"] > 0 and row["rejectedInfs"] > 0, "PARTIAL_INSPECTION")
            else:
                cr.require(row["inspectionExitCode"] != 0 and row["verifiedInfs"] == 0, "REJECTED_INSPECTION")
        else:
            cr.require(row["inspectorSha256"] is None and row["inspectionExitCode"] is None and
                       all(row[field] == 0 for field in ("verifiedInfs", "rejectedInfs", "inventoryFiles")),
                       "UNINSPECTED_CLAIM")
        cr.require(state != "UNSUPPORTED" or downloaded, "UNSUPPORTED_WITHOUT_PAYLOAD")
        cr.require(downloaded or (state == "NOT_CHECKED" and row["outerSignature"] == "NOT_CHECKED"),
                   "FAILED_INSPECTION_CLAIM")
    return {**evidence, "acquisitions": sorted(rows, key=lambda row: row["id"])}


def validate_product_enrichment(old: dict, candidate: dict, fresh: list[dict],
                                sources: dict, records: dict) -> None:
    """旧PAGE_ONLYの識別と参照を保持し、新しい製品別配布根拠だけを受理する（ADR 0234）。"""
    cr.require(old["researchState"] == "PAGE_ONLY" and not old["recordIds"] and
               old["reason"] == "DOWNLOAD_TABLE_UNAVAILABLE" and
               candidate["researchState"] == "METADATA_SAVED" and candidate["reason"] == "NONE" and
               bool(candidate["recordIds"]) and
               set(old["sourceIds"]) <= set(candidate["sourceIds"]) and candidate == {
                   **old, "sourceIds": candidate["sourceIds"], "recordIds": candidate["recordIds"],
                   "researchState": "METADATA_SAVED", "reason": "NONE"},
               "PRODUCT_ENRICHMENT_SCOPE")
    proof = [row for row in fresh if row["productId"] == old["id"] and
             row["kind"] in {"OFFICIAL_PAGE", "OFFICIAL_LINK"} and row["httpStatus"] in (None, 200) and
             row["method"] in {"WEB_REVIEW", "LOCAL_HTTP"}]
    # 製品への追加配布ごとに、その取得元pageと結合した新しい根拠を要求する。
    for record_id in candidate["recordIds"]:
        source_url = sources[records[record_id]["sourceId"]]["officialPage"]
        cr.require(any(row["recordId"] == record_id and row["evidenceUrl"] == source_url
                       for row in proof), "PRODUCT_ENRICHMENT_RECORD_EVIDENCE")
    # 新しい取得元への参照も観測なしでは追加せず、旧参照は削除しない。
    for source_id in set(candidate["sourceIds"]) - set(old["sourceIds"]):
        cr.require(any(row["evidenceUrl"] == sources[source_id]["officialPage"] for row in proof),
                   "PRODUCT_ENRICHMENT_SOURCE_EVIDENCE")


def carry_forward(old_registry: dict, old_evidence: dict, new_registry: dict, *,
                  allow_link_enrichment: bool = False, allow_product_enrichment: bool = False,
                  allow_metadata_enrichment: bool = False) -> dict:
    """追加専用または独立した明示補完へ旧観測を結合する（ADR 0232／0233／0234／0308）。"""
    cr.require(type(allow_link_enrichment) is bool, "ENRICHMENT_MODE")
    cr.require(type(allow_product_enrichment) is bool, "PRODUCT_ENRICHMENT_MODE")
    cr.require(type(allow_metadata_enrichment) is bool, "METADATA_ENRICHMENT_MODE")
    old_registry = cr.validate_registry(old_registry)
    old_evidence = validate_evidence(old_registry, old_evidence)
    new_registry = cr.validate_registry(new_registry)
    cr.require(new_registry["revision"] != old_registry["revision"] and
               cr.timestamp(new_registry["asOf"]) >= cr.timestamp(old_registry["asOf"]),
               "CARRY_FORWARD_GENERATION")
    protected_records = {row["recordId"] for row in old_evidence["acquisitions"]}
    old_observations = {row["id"] for row in old_registry["observations"]}
    fresh = [row for row in new_registry["observations"] if row["id"] not in old_observations and
             cr.observation_timestamp(row["checkedAt"]) >= cr.timestamp(old_registry["asOf"])]
    sources = {row["id"]: row for row in new_registry["sources"]}
    records = {row["id"]: row for row in new_registry["records"]}
    # 旧取得元・製品・観測は保持する。既定では未取得recordの補完も拒否する。
    for name in cr.COLLECTIONS:
        current = {row["id"]: row for row in new_registry[name]}
        for row in old_registry[name]:
            candidate = current.get(row["id"])
            if candidate == row:
                continue
            # 登録済み配布の参照追記は独立して明示され、識別と旧参照を変更しない。
            if allow_metadata_enrichment and name == "products" and candidate is not None and \
                    row["researchState"] == "METADATA_SAVED":
                validate_metadata_enrichment(row, candidate, fresh, sources, records)
                continue
            # 未確定製品の限定補完はURL補完とは別に明示され、他の旧製品変更を許可しない。
            if allow_product_enrichment and name == "products" and candidate is not None:
                validate_product_enrichment(row, candidate, fresh, sources, records)
                continue
            cr.require(allow_link_enrichment and name == "records" and candidate is not None and
                       row["id"] not in protected_records and row["downloadUrl"] is None and
                       row["linkState"] == "MISSING" and candidate["downloadUrl"] is not None and
                       candidate["linkState"] in {"OFFICIAL_LINK", "HEAD_OK"} and
                       candidate == {**row, "downloadUrl": candidate["downloadUrl"],
                                     "linkState": candidate["linkState"]},
                       "CARRY_FORWARD_NOT_APPEND_ONLY")
            kinds = {item["kind"] for item in fresh if item["recordId"] == row["id"]}
            cr.require("OFFICIAL_LINK" in kinds and
                       (candidate["linkState"] != "HEAD_OK" or "HEAD" in kinds),
                       "ENRICHMENT_FRESH_EVIDENCE")
    result = {**old_evidence, "schema": CARRIED_EVIDENCE_SCHEMA,
              "revision": new_registry["revision"] + "-carried",
              "registryRevision": new_registry["revision"],
              "registrySha256": cr.digest(cr.json_bytes(new_registry)),
              "asOf": max(old_evidence["asOf"], new_registry["asOf"]),
              "originRegistry": old_evidence.get("originRegistry", {
                  "revision": old_registry["revision"], "asOf": old_registry["asOf"],
                  "sha256": cr.digest(cr.json_bytes(old_registry))}),
              "acquisitions": [{**row, "recordSha256": cr.digest(cr.json_bytes(records[row["recordId"]]))}
                               for row in old_evidence["acquisitions"]]}
    return validate_evidence(new_registry, result)


def validate_metadata_enrichment(old: dict, candidate: dict, fresh: list[dict],
                                 sources: dict, records: dict) -> None:
    """旧metadata対象へ新しい公式source／record参照だけを追記する（ADR 0308）。"""
    cr.require(old["researchState"] == "METADATA_SAVED" and old["reason"] == "NONE" and bool(old["recordIds"])
               and candidate == {**old, "sourceIds": candidate["sourceIds"], "recordIds": candidate["recordIds"]}
               and set(old["sourceIds"]) <= set(candidate["sourceIds"])
               and set(old["recordIds"]) <= set(candidate["recordIds"]), "METADATA_ENRICHMENT_SCOPE")
    added_sources = set(candidate["sourceIds"]) - set(old["sourceIds"])
    added_records = set(candidate["recordIds"]) - set(old["recordIds"])
    cr.require(bool(added_sources or added_records), "METADATA_ENRICHMENT_EMPTY")
    proof = [row for row in fresh if row["productId"] == old["id"]
             and row["recordId"] in candidate["recordIds"] and row["kind"] in {"OFFICIAL_PAGE", "OFFICIAL_LINK"}
             and row["httpStatus"] in (None, 200) and row["method"] in {"WEB_REVIEW", "LOCAL_HTTP"}]
    # 追加配布は当該配布の取得元pageの成功観測に結合する。
    for record_id in added_records:
        source_url = sources[records[record_id]["sourceId"]]["officialPage"]
        cr.require(any(row["recordId"] == record_id and row["evidenceUrl"] == source_url for row in proof),
                   "METADATA_ENRICHMENT_RECORD_EVIDENCE")
    # sourceだけの補完では既存recordのliteralリンク観測を要求する。
    for source_id in added_sources:
        source_url = sources[source_id]["officialPage"]
        cr.require(any(row["evidenceUrl"] == source_url and (added_records or row["kind"] == "OFFICIAL_LINK")
                       for row in proof), "METADATA_ENRICHMENT_SOURCE_EVIDENCE")


def evidence_counts(registry: dict, evidence: dict) -> dict:
    """観測byteを一意化し、製品・recordと全内容合格数を分けて集計する。"""
    rows = validate_evidence(registry, evidence)["acquisitions"]
    acquired = [row for row in rows if row["state"] == "DOWNLOADED"]
    record_ids = {row["recordId"] for row in acquired}
    result = cr.counts(registry)
    result.update(payloadsDownloaded=len({row["sha256"] for row in acquired}),
                  contentsVerified=len({row["sha256"] for row in acquired if row["inspection"] == "PASSED"}),
                  acquisitionTargets=len(rows), recordsWithDownloadedPayloads=len(record_ids),
                  productsWithDownloadedPayloads=sum(bool(set(row["recordIds"]) & record_ids)
                                                    for row in registry["products"]))
    return result


def bundle_content(registry: dict, evidence: dict) -> dict[str, bytes]:
    """旧台帳を保持し、証拠と結合した導入不可の7 file snapshotを生成する。"""
    registry = cr.validate_registry(registry)
    evidence = validate_evidence(registry, evidence)
    content = cr.snapshot_content(registry)
    index = cr.research_index(registry)
    index.update(schema="dc-local-research-index-v3" if registry["schema"] == cr.QUERY_REGISTRY_SCHEMA
                        else "dc-local-research-index-v2", asOf=evidence["asOf"],
                 counts=evidence_counts(registry, evidence), payloadEvidence=evidence)
    observations = {row["recordId"]: row for row in evidence["acquisitions"]}
    index["records"] = []
    for record in registry["records"]:
        copied = dict(record)
        observed = observations.get(record["id"])
        if observed and observed["state"] == "DOWNLOADED":
            copied["contentState"] = {"PASSED": "CONTENT_VERIFIED", "PARTIAL": "INSPECTION_PARTIAL",
                                      "REJECTED": "INSPECTION_REJECTED", "UNSUPPORTED": "INSPECTION_UNSUPPORTED",
                                      "NOT_CHECKED": "DOWNLOADED"}[observed["inspection"]]
        index["records"].append(copied)
    content["index/drivers.json"] = cr.json_bytes(index)
    content["payload-evidence.json"] = cr.json_bytes(evidence)
    del content["manifest.json"]
    cr.require(all(len(raw) <= cr.MAX_JSON_BYTES for raw in content.values()), "OUTPUT_SIZE")
    content["manifest.json"] = cr.json_bytes(cr.snapshot_manifest(registry, content, payload=True))
    return content


def write_bundle(registry: dict, evidence: dict, output: Path) -> None:
    """新規のsnapshotだけを保存し、保存後に再計算する。

    保存・再検証の途中で失敗しても、作成済みdirectoryとfileを保持する。自動削除・上書き・修復はしない。
    """
    content = bundle_content(registry, evidence)
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "index").mkdir()
    for name, raw in content.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    verify_bundle(output)


def tree_files(root: Path) -> None:
    """既知の7 file以外とreparseを拒否する。"""
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
    cr.require(found == BUNDLE_FILES, "SNAPSHOT_FILE_SET")


def verify_bundle(root: Path) -> tuple[dict, dict]:
    """全構成・証拠・索引・manifestを有限読取りで再計算する。"""
    cr.check_ancestors(root)
    tree_files(root)
    manifest = cr.read_json(root / "manifest.json")
    registry = {"schema": cr.manifest_registry_schema(manifest, payload=True),
                "revision": manifest["revision"], "asOf": manifest["asOf"]}
    for name in cr.COLLECTIONS:
        document = cr.read_json(root / f"{name}.json")
        cr.fields(document, {"schema", "revision", "asOf", "items"}, "COLLECTION_FIELDS")
        cr.require(document["schema"] == cr.collection_schema(registry["schema"], name) and
                   document["revision"] == registry["revision"] and document["asOf"] == registry["asOf"],
                   "COLLECTION_BINDING")
        registry[name] = document["items"]
    registry = cr.validate_registry(registry)
    evidence = validate_evidence(registry, cr.read_json(root / "payload-evidence.json"))
    for name, raw in bundle_content(registry, evidence).items():
        path = root / name
        cr.regular_path(path)
        with path.open("rb") as stream:
            actual = stream.read(cr.MAX_JSON_BYTES + 1)
        cr.regular_path(path)
        cr.require(actual == raw, "SNAPSHOT_CONTENT_OR_HASH")
    tree_files(root)
    return registry, evidence


def write_zip(root: Path, output: Path) -> None:
    """検証済みの研究用fileだけを決定的ZIPへ格納する。

    archiveの終了処理を本関数で行う。I/O例外は伝播し、作成途中のZIPは自動削除せず、既存ZIPを上書きしない。
    """
    registry, evidence = verify_bundle(root)
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(output)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(bundle_content(registry, evidence).items()):
            info = zipfile.ZipInfo("collector-data/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)


def main() -> int:
    """明示した証拠を検証・結合し、台帳のみのsnapshotと混同しない。"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "build"):
        sub = commands.add_parser(command)
        sub.add_argument("registry", type=Path)
        sub.add_argument("evidence", type=Path)
        if command == "build":
            sub.add_argument("output", type=Path)
    sub = commands.add_parser("verify")
    sub.add_argument("snapshot", type=Path)
    sub = commands.add_parser("zip")
    sub.add_argument("snapshot", type=Path)
    sub.add_argument("output", type=Path)
    sub = commands.add_parser("carry-forward")
    sub.add_argument("snapshot", type=Path)
    sub.add_argument("registry", type=Path)
    sub.add_argument("output", type=Path)
    sub.add_argument("--allow-link-enrichment", action="store_true")
    sub.add_argument("--allow-product-enrichment", action="store_true")
    sub.add_argument("--allow-metadata-enrichment", action="store_true")
    args = parser.parse_args()
    try:
        if args.command in {"validate", "build"}:
            cr.check_ancestors(args.registry)
            cr.check_ancestors(args.evidence)
            registry = cr.validate_registry(cr.read_json(args.registry))
            evidence = validate_evidence(registry, cr.read_json(args.evidence))
            if args.command == "build":
                write_bundle(registry, evidence, args.output)
        elif args.command == "carry-forward":
            old_registry, old_evidence = verify_bundle(args.snapshot)
            cr.check_ancestors(args.registry)
            registry = cr.validate_registry(cr.read_json(args.registry))
            evidence = carry_forward(old_registry, old_evidence, registry,
                                     allow_link_enrichment=args.allow_link_enrichment,
                                     allow_product_enrichment=args.allow_product_enrichment,
                                     allow_metadata_enrichment=args.allow_metadata_enrichment)
            write_bundle(registry, evidence, args.output)
        else:
            registry, evidence = verify_bundle(args.snapshot)
            if args.command == "zip":
                write_zip(args.snapshot, args.output)
        print(json.dumps({"result": "OK", "counts": evidence_counts(registry, evidence)}, sort_keys=True))
        return 0
    except (cr.RegistryError, OSError, ValueError, TypeError, KeyError) as error:
        code = str(error) if isinstance(error, cr.RegistryError) else type(error).__name__
        print(json.dumps({"result": "REJECTED", "reason": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
