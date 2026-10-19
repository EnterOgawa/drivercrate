"""公開locatorを含む可搬snapshot v4の非通信生成・検証・世代引継ぎ（ADR 0235／0237）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
閉じたJSON集合のみを新規出力へ保存する。明示補完でも旧PAYLOAD参照recordを変更しない。
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import zipfile

import collector_registry as cr
import collector_payload_evidence as pe
import collector_public_locators as pl


SNAPSHOT_SCHEMA = "dc-portable-research-snapshot-v4"
BASE_FILES = {*cr.SNAPSHOT_FILES, "manifest.json", "locators.json"}


def snapshot_content(registry: dict, locators: dict, evidence: dict | None = None) -> dict[str, bytes]:
    """既存集合・索引・証拠byteを保持し、locatorとv4 manifestだけを追加する。"""
    registry = cr.validate_registry(registry)
    locators = pl.validate_locators(locators, registry)
    content = cr.snapshot_content(registry) if evidence is None else pe.bundle_content(registry, evidence)
    del content["manifest.json"]
    content["locators.json"] = cr.json_bytes(locators)
    cr.require(all(len(raw) <= cr.MAX_JSON_BYTES for raw in content.values()), "OUTPUT_SIZE")
    manifest = {"schema": SNAPSHOT_SCHEMA, "registrySchema": registry["schema"],
                "revision": registry["revision"], "asOf": registry["asOf"],
                "registrySha256": cr.digest(cr.json_bytes(registry)),
                "includesPayloadEvidence": evidence is not None, "includesPublicLocators": True,
                "files": [{"path": name, "bytes": len(raw), "sha256": cr.digest(raw)}
                          for name, raw in sorted(content.items())]}
    content["manifest.json"] = cr.json_bytes(manifest)
    return content


def tree_files(root: Path, *, payload: bool) -> None:
    """7／8 fileの閉じた構成だけを有限列挙し、未知directory・reparseを拒否する。"""
    cr.require(type(payload) is bool, "SNAPSHOT_PAYLOAD_MODE")
    cr.regular_path(root, directory=True)
    allowed = BASE_FILES | ({"payload-evidence.json"} if payload else set())
    found = set()
    for item in root.iterdir():
        if item.name == "index":
            cr.regular_path(item, directory=True)
            for child in item.iterdir():
                cr.require(child.name == "drivers.json", "SNAPSHOT_FILE_SET")
                cr.regular_path(child)
                found.add("index/drivers.json")
        else:
            cr.require(item.name in allowed, "SNAPSHOT_FILE_SET")
            cr.regular_path(item)
            found.add(item.name)
    cr.require(found == allowed, "SNAPSHOT_FILE_SET")


def verify_snapshot(root: Path) -> tuple[dict, dict, dict | None]:
    """全構成・元台帳・locator・証拠・manifestを有限読込みで再生成して照合する。"""
    cr.check_ancestors(root)
    cr.regular_path(root, directory=True)
    manifest = cr.read_json(root / "manifest.json")
    cr.fields(manifest, {"schema", "registrySchema", "revision", "asOf", "registrySha256",
                         "includesPayloadEvidence", "includesPublicLocators", "files"}, "MANIFEST_FIELDS")
    cr.require(manifest["schema"] == SNAPSHOT_SCHEMA and manifest["includesPublicLocators"] is True and
               type(manifest["includesPayloadEvidence"]) is bool, "MANIFEST_LOCATOR_SCHEMA")
    cr.require(type(manifest["registrySchema"]) is str and manifest["registrySchema"] in
               {cr.REGISTRY_SCHEMA, cr.QUERY_REGISTRY_SCHEMA}, "MANIFEST_REGISTRY_BINDING")
    payload = manifest["includesPayloadEvidence"]
    tree_files(root, payload=payload)
    registry = {"schema": manifest["registrySchema"], "revision": manifest["revision"], "asOf": manifest["asOf"]}
    for name in cr.COLLECTIONS:
        document = cr.read_json(root / f"{name}.json")
        cr.fields(document, {"schema", "revision", "asOf", "items"}, "COLLECTION_FIELDS")
        cr.require(document["schema"] == cr.collection_schema(registry["schema"], name) and
                   document["revision"] == registry["revision"] and document["asOf"] == registry["asOf"],
                   "COLLECTION_BINDING")
        registry[name] = document["items"]
    registry = cr.validate_registry(registry)
    locators = pl.validate_locators(cr.read_json(root / "locators.json"), registry)
    evidence = pe.validate_evidence(registry, cr.read_json(root / "payload-evidence.json")) if payload else None
    expected = snapshot_content(registry, locators, evidence)
    for name, raw in expected.items():
        actual = cr.json_bytes(cr.read_json(root / name))
        # JSONの意味だけでなく、空白・順序を含む正規byteも要求する。
        with (root / name).open("rb") as stream:
            stored = stream.read(cr.MAX_JSON_BYTES + 1)
        cr.regular_path(root / name)
        cr.require(actual == raw and stored == raw, "SNAPSHOT_CONTENT_OR_HASH")
    tree_files(root, payload=payload)
    return registry, locators, evidence


def write_snapshot(registry: dict, locators: dict, output: Path, evidence: dict | None = None) -> None:
    """新規directoryだけへ保存し、再検証する。途中失敗の出力を上書き・自動削除しない。"""
    content = snapshot_content(registry, locators, evidence)
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "index").mkdir()
    for name, raw in content.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    verify_snapshot(output)


def write_zip(root: Path, output: Path) -> None:
    """検証済みJSONを新しい決定的ZIPへ格納し、payloadやcredentialを同梱しない。

    archiveの終了処理を本関数で行う。I/O例外は伝播し、作成途中のZIPは自動削除せず、既存ZIPを上書きしない。
    """
    registry, locators, evidence = verify_snapshot(root)
    content = snapshot_content(registry, locators, evidence)
    cr.require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    cr.check_ancestors(output)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(content.items()):
            info = zipfile.ZipInfo("collector-data/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)


def carry_forward_locators(old_registry: dict, old_locators: dict, new_registry: dict, *,
                           revision: str, as_of: str, allow_link_enrichment: bool = False,
                           allow_product_enrichment: bool = False, allow_metadata_enrichment: bool = False,
                           old_evidence: dict | None = None) -> dict:
    """独立した三補完modeを共通検証へ渡し、全旧locatorとPAYLOAD参照recordを保持する。"""
    cr.require(type(allow_link_enrichment) is bool, "LOCATOR_ENRICHMENT_MODE")
    cr.require(type(allow_product_enrichment) is bool, "LOCATOR_PRODUCT_ENRICHMENT_MODE")
    cr.require(type(allow_metadata_enrichment) is bool, "LOCATOR_METADATA_ENRICHMENT_MODE")
    old_registry = cr.validate_registry(old_registry)
    old_locators = pl.validate_locators(old_locators, old_registry)
    new_registry = cr.validate_registry(new_registry)
    cr.label(revision)
    cr.require(new_registry["revision"] != old_registry["revision"] and revision != old_locators["revision"] and
               cr.timestamp(new_registry["asOf"]) >= cr.timestamp(old_registry["asOf"]) and
               cr.timestamp(as_of) >= max(cr.timestamp(old_locators["asOf"]), cr.timestamp(new_registry["asOf"])),
               "LOCATOR_CARRY_GENERATION")
    cr.require(new_registry["schema"] == old_registry["schema"] or
               (old_registry["schema"] == cr.REGISTRY_SCHEMA and new_registry["schema"] == cr.QUERY_REGISTRY_SCHEMA),
               "LOCATOR_CARRY_SCHEMA")
    if allow_link_enrichment or allow_product_enrichment or allow_metadata_enrichment:
        cr.require(old_evidence is not None, "LOCATOR_ENRICHMENT_EVIDENCE_REQUIRED")
        # 旧取得証拠と各明示補完の根拠検証を再利用し、既存規則の順序と条件を維持する。
        pe.carry_forward(old_registry, old_evidence, new_registry,
                         allow_link_enrichment=allow_link_enrichment,
                         allow_product_enrichment=allow_product_enrichment,
                         allow_metadata_enrichment=allow_metadata_enrichment)
        protected = {identity for row in old_locators["locators"] if row["purpose"] == "PAYLOAD"
                     for identity in row["recordIds"]}
        current = {row["id"]: row for row in new_registry["records"]}
        cr.require(all(current.get(row["id"]) == row for row in old_registry["records"]
                       if row["id"] in protected), "LOCATOR_ENRICHMENT_HELD_RECORD")
    else:
        for name in cr.COLLECTIONS:
            current = {row["id"]: row for row in new_registry[name]}
            cr.require(all(current.get(row["id"]) == row for row in old_registry[name]),
                       "LOCATOR_CARRY_NOT_APPEND_ONLY")
    updated = {**old_locators, "revision": revision, "asOf": as_of, "registry": pl.registry_binding(new_registry)}
    return pl.validate_locators(updated, new_registry)


def main() -> int:
    """明示fileだけをbuild／verify／zip／carryし、通信・Task・公開・導入は行わない。"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("registry", type=Path)
    build.add_argument("locators", type=Path)
    build.add_argument("output", type=Path)
    build.add_argument("--evidence", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("snapshot", type=Path)
    zipper = commands.add_parser("zip")
    zipper.add_argument("snapshot", type=Path)
    zipper.add_argument("output", type=Path)
    carry = commands.add_parser("carry-forward")
    carry.add_argument("snapshot", type=Path)
    carry.add_argument("registry", type=Path)
    carry.add_argument("output", type=Path)
    carry.add_argument("--locator-revision", required=True)
    carry.add_argument("--allow-link-enrichment", action="store_true")
    carry.add_argument("--allow-product-enrichment", action="store_true")
    carry.add_argument("--allow-metadata-enrichment", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "build":
            cr.check_ancestors(args.registry)
            cr.check_ancestors(args.locators)
            registry = cr.validate_registry(cr.read_json(args.registry))
            locators = pl.validate_locators(cr.read_json(args.locators), registry)
            evidence = None
            if args.evidence is not None:
                cr.check_ancestors(args.evidence)
                evidence = pe.validate_evidence(registry, cr.read_json(args.evidence))
            write_snapshot(registry, locators, args.output, evidence)
        elif args.command == "carry-forward":
            old_registry, old_locators, old_evidence = verify_snapshot(args.snapshot)
            cr.check_ancestors(args.registry)
            registry = cr.validate_registry(cr.read_json(args.registry))
            locators = carry_forward_locators(old_registry, old_locators, registry,
                                              revision=args.locator_revision,
                                              as_of=max(registry["asOf"], old_locators["asOf"]),
                                              allow_link_enrichment=args.allow_link_enrichment,
                                              allow_product_enrichment=args.allow_product_enrichment,
                                              allow_metadata_enrichment=args.allow_metadata_enrichment,
                                              old_evidence=old_evidence)
            evidence = pe.carry_forward(old_registry, old_evidence, registry,
                                       allow_link_enrichment=args.allow_link_enrichment,
                                       allow_product_enrichment=args.allow_product_enrichment,
                                       allow_metadata_enrichment=args.allow_metadata_enrichment) \
                if old_evidence is not None else None
            write_snapshot(registry, locators, args.output, evidence)
        else:
            registry, locators, evidence = verify_snapshot(args.snapshot)
            if args.command == "zip":
                write_zip(args.snapshot, args.output)
        counts = cr.counts(registry) if evidence is None else pe.evidence_counts(registry, evidence)
        print(cr.json_bytes({"result": "OK", "counts": counts,
                             "locatorCounts": pl.locator_counts(locators)}).decode("utf-8"), end="")
    except cr.RegistryError as error:
        print("REJECTED:" + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("REJECTED:IO_ERROR", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
