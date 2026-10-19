"""Locator付きsnapshot v4・旧byte・追加専用引継ぎの非通信回帰試験。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公開台帳・取得証拠とtemporary directoryだけを使用する。
"""

import contextlib
import copy
import io
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import collector_registry as cr
import collector_payload_evidence as pe
import collector_public_locators as pl
import collector_locator_snapshot as ls
from test_collector_public_locators import locator_fixture
from test_collector_payload_evidence import evidence
from test_collector_registry import RESPONSE_HEADER_URL


def snapshot_fixture() -> tuple[dict, dict, dict]:
    """既存URLと取得証拠を持つ架空台帳へ、用途を分けたlocatorを結合する。"""
    registry, locators = locator_fixture()
    url = "https://cdn.example.org/driver.zip"
    registry["records"][0].update(downloadUrl=url, linkState="OFFICIAL_LINK")
    registry["observations"][0]["kind"] = "OFFICIAL_LINK"
    registry = cr.validate_registry(registry)
    locators["registry"] = pl.registry_binding(registry)
    locators["locators"][2].update(url=url, urlProfile="QUERYLESS")
    return registry, pl.validate_locators(locators, registry), evidence(registry)


def next_registry(registry: dict) -> dict:
    """旧全rowを保った架空新世代を返す。実データの更新は行わない。"""
    value = copy.deepcopy(registry)
    value.update(revision="test-02", asOf="2026-10-03T02:00:00Z")
    return cr.validate_registry(value)


def enrichment_fixture(*, product=False, metadata=False, metadata_count=1) -> tuple[dict, dict, dict, dict]:
    """旧locatorを保持し、架空PAGE_ONLY補完と共有metadata参照追記を独立して作る。"""
    old, locators, _ = snapshot_fixture()
    if metadata:
        for number in range(1, metadata_count):
            identifier = f"metadata-{number}"
            old["products"].append({**copy.deepcopy(old["products"][0]), "id": identifier,
                                    "model": f"Metadata Device {number}"})
            old["observations"].append({**old["observations"][0], "id": f"old-{identifier}",
                                        "productId": identifier})
    if product:
        old["products"].append({**copy.deepcopy(old["products"][0]), "id": "unknown-one",
                                "model": "Unknown Device", "recordIds": [],
                                "researchState": "PAGE_ONLY", "reason": "DOWNLOAD_TABLE_UNAVAILABLE"})
        old["observations"].append({**old["observations"][0], "id": "old-unknown",
                                    "productId": "unknown-one", "recordId": None, "kind": "OFFICIAL_PAGE"})
    old = cr.validate_registry(old)
    locators["registry"] = pl.registry_binding(old)
    locators = pl.validate_locators(locators, old)
    observed = evidence(old)
    current = next_registry(old)
    current["sources"].append({**old["sources"][0], "id": "source-two",
                                "officialPage": "https://vendor.example.org/new-drivers"})
    current["records"].append({**old["records"][0], "id": "record-two", "sourceId": "source-two",
                                "downloadUrl": None, "linkState": "MISSING"})
    for row in current["products"]:
        if (product and row["id"] == "unknown-one") or (metadata and row["researchState"] == "METADATA_SAVED"):
            row["sourceIds"].append("source-two")
            row["recordIds"].append("record-two")
            row.update(researchState="METADATA_SAVED", reason="NONE")
            current["observations"].append({**old["observations"][0], "id": "fresh-" + row["id"],
                                            "productId": row["id"], "recordId": "record-two",
                                            "checkedAt": current["asOf"], "kind": "OFFICIAL_PAGE",
                                            "method": "WEB_REVIEW", "httpStatus": None,
                                            "evidenceSha256": None,
                                            "evidenceUrl": current["sources"][-1]["officialPage"]})
    return old, locators, observed, cr.validate_registry(current)


class LocatorSnapshotTests(unittest.TestCase):
    """新しい閉じたJSON形式を検査し、旧形式・本体取得権限を変更しない。"""

    def test_plain_and_evidence_file_sets(self):
        """証拠なし7 fileと証拠あり8 fileを明示的に分ける。"""
        registry, locators, observed = snapshot_fixture()
        for payload in (None, observed):
            with self.subTest(payload=payload is not None):
                content = ls.snapshot_content(registry, locators, payload)
                self.assertEqual(set(content), ls.BASE_FILES | ({"payload-evidence.json"} if payload else set()))
                manifest = cr.parse_json(content["manifest.json"])
                self.assertEqual(manifest["schema"], ls.SNAPSHOT_SCHEMA)
                self.assertIs(manifest["includesPayloadEvidence"], payload is not None)
                self.assertIs(manifest["includesPublicLocators"], True)
                index = cr.parse_json(content["index/drivers.json"])
                self.assertFalse(index["installAuthorized"])
                self.assertFalse(index["publishable"])
                self.assertNotIn("locators", index)

    def test_old_file_bytes_and_generators_are_unchanged(self):
        """旧schemaと既存集合・索引・証拠byteを、新形式へ混ぜて再解釈しない。"""
        registry, locators, observed = snapshot_fixture()
        for payload in (None, observed):
            old = cr.snapshot_content(registry) if payload is None else pe.bundle_content(registry, payload)
            before = copy.deepcopy(old)
            current = ls.snapshot_content(registry, locators, payload)
            for name, raw in old.items():
                if name != "manifest.json":
                    self.assertEqual(current[name], raw)
            self.assertEqual(old, before)
            self.assertNotEqual(old["manifest.json"], current["manifest.json"])

    def test_response_header_missing_link_enrichment_preserves_old_evidence(self):
        """明示MISSING補完だけへ原URLを保存し、旧全rowとlocator・取得証拠を保つ。"""
        from test_registry_file_query import carry_fixture
        old, locators, observed, new = carry_fixture()
        new["records"][1]["downloadUrl"] = RESPONSE_HEADER_URL
        new = cr.validate_registry(new)
        with self.assertRaises(cr.RegistryError):
            pe.carry_forward(old, observed, new)
        with self.assertRaises(cr.RegistryError):
            ls.carry_forward_locators(old, locators, new, revision="locators-header",
                as_of=new["asOf"], old_evidence=observed)
        carried = pe.carry_forward(old, observed, new, allow_link_enrichment=True)
        after = ls.carry_forward_locators(old, locators, new, revision="locators-header",
            as_of=new["asOf"], allow_link_enrichment=True, old_evidence=observed)
        self.assertEqual(after["locators"], locators["locators"])
        self.assertEqual([{k: v for k, v in row.items() if k != "recordSha256"}
                          for row in carried["acquisitions"]], observed["acquisitions"])
        for name in ("sources", "products", "observations"):
            rows = {row["id"]: row for row in new[name]}
            self.assertTrue(all(rows[row["id"]] == row for row in old[name]))
        self.assertEqual(new["records"][0], old["records"][0])
        changed = {key for key in old["records"][1]
                   if old["records"][1][key] != new["records"][1][key]}
        self.assertEqual(changed, {"downloadUrl", "linkState"})
        without_fresh = copy.deepcopy(new)
        without_fresh["observations"] = copy.deepcopy(old["observations"])
        with self.assertRaises(cr.RegistryError):
            pe.carry_forward(old, observed, without_fresh, allow_link_enrichment=True)
        content = ls.snapshot_content(new, after, carried)
        index = cr.parse_json(content["index/drivers.json"])
        self.assertTrue(index["researchOnly"])
        self.assertFalse(index["publishable"])
        self.assertFalse(index["installAuthorized"])
        self.assertEqual(index["applicability"], "NOT_CHECKED")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            ls.write_snapshot(new, after, root, carried)
            self.assertEqual(ls.snapshot_content(*ls.verify_snapshot(root)), content)

    def test_copy_verify_and_deterministic_zip(self):
        """新形式をcopy・再生成・ZIP展開しても全byteと参照を保持する。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original"
            copied = root / "copied"
            ls.write_snapshot(registry, locators, original, observed)
            shutil.copytree(original, copied)
            rebuilt = ls.snapshot_content(*ls.verify_snapshot(copied))
            for name, raw in rebuilt.items():
                self.assertEqual((copied / name).read_bytes(), raw)
            for name in ("one.zip", "two.zip"):
                ls.write_zip(original, root / name)
            self.assertEqual((root / "one.zip").read_bytes(), (root / "two.zip").read_bytes())
            with zipfile.ZipFile(root / "one.zip") as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(set(archive.namelist()), {"collector-data/" + name for name in rebuilt})
                archive.extractall(root / "expanded")
            ls.verify_snapshot(root / "expanded" / "collector-data")

    def test_manifest_unknown_missing_schema_and_flag_types(self):
        """未知manifest・証拠有無の偽装・真偽型混同を拒否する。"""
        registry, locators, observed = snapshot_fixture()
        cases = (("extra", True), ("schema", "dc-portable-research-snapshot-v3"),
                 ("includesPublicLocators", False), ("includesPublicLocators", 1),
                 ("includesPayloadEvidence", 1), ("registrySchema", "future"),
                 ("registrySha256", "0" * 64), ("files", []))
        with tempfile.TemporaryDirectory() as directory:
            for number, (key, replacement) in enumerate(cases):
                root = Path(directory) / str(number)
                ls.write_snapshot(registry, locators, root, observed)
                manifest = cr.read_json(root / "manifest.json")
                manifest[key] = replacement
                (root / "manifest.json").write_bytes(cr.json_bytes(manifest))
                with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                    ls.verify_snapshot(root)

    def test_extra_files_directories_and_missing_locators(self):
        """任意payload・秘密file・不明directoryを移設ZIPへ同梱しない。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            for number, mode in enumerate(("extra-file", "extra-dir", "nested-file", "missing")):
                root = Path(directory) / str(number)
                ls.write_snapshot(registry, locators, root, observed)
                if mode == "extra-file":
                    (root / "driver.zip").write_bytes(b"not a driver")
                elif mode == "extra-dir":
                    (root / "private").mkdir()
                elif mode == "nested-file":
                    (root / "index" / "unexpected.json").write_bytes(b"{}")
                else:
                    (root / "locators.json").unlink()
                with self.subTest(mode=mode), self.assertRaises(cr.RegistryError):
                    ls.verify_snapshot(root)

    def test_each_json_mutation_and_noncanonical_bytes_are_rejected(self):
        """各構成JSONの先頭へ空白を追加し、正規byteとの差による拒否を確認する。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            content = ls.snapshot_content(registry, locators, observed)
            for number, name in enumerate(content):
                root = Path(directory) / str(number)
                ls.write_snapshot(registry, locators, root, observed)
                path = root / name
                path.write_bytes(b" " + path.read_bytes())
                with self.subTest(name=name), self.assertRaises(cr.RegistryError):
                    ls.verify_snapshot(root)

    def test_locators_cannot_bind_different_product_bytes(self):
        """元台帳のrevisionだけを合わせた別製品へのsidecar転用を拒否する。"""
        registry, locators, observed = snapshot_fixture()
        registry["products"][0]["model"] = "Other Model"
        with self.assertRaises(cr.RegistryError) as result:
            ls.snapshot_content(registry, locators)
        self.assertEqual(str(result.exception), "LOCATOR_REGISTRY_BINDING")

    def test_old_readers_do_not_accept_v4(self):
        """旧readerが新形式を旧snapshotと誤認しない。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            ls.write_snapshot(registry, locators, root, observed)
            for reader in (cr.verify_snapshot, pe.verify_bundle):
                with self.subTest(reader=reader.__name__), self.assertRaises(cr.RegistryError):
                    reader(root)

    def test_existing_output_is_never_overwritten(self):
        """既存snapshotとZIPを上書きせず、失敗後も元byteを保持する。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            ls.write_snapshot(registry, locators, root, observed)
            before = (root / "manifest.json").read_bytes()
            with self.assertRaises(cr.RegistryError):
                ls.write_snapshot(registry, locators, root, observed)
            self.assertEqual((root / "manifest.json").read_bytes(), before)
            archive = Path(directory) / "existing.zip"
            archive.write_bytes(b"original")
            with self.assertRaises(cr.RegistryError):
                ls.write_zip(root, archive)
            self.assertEqual(archive.read_bytes(), b"original")

    def test_reparse_input_is_rejected(self):
        """共通file種別検査の拒否を迂回せずreaderを中止する。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            ls.write_snapshot(registry, locators, root, observed)
            with patch.object(cr, "regular_path", side_effect=cr.RegistryError("REPARSE_PATH")), \
                    self.assertRaises(cr.RegistryError):
                ls.verify_snapshot(root)

    def test_carry_forward_preserves_all_locator_rows_and_originals(self):
        """新世代のbindingだけを更新し、旧観測・同意保留・元objectを保持する。"""
        registry, locators, observed = snapshot_fixture()
        current = next_registry(registry)
        before = copy.deepcopy(locators)
        carried = ls.carry_forward_locators(registry, locators, current,
                                            revision="locators-02", as_of=current["asOf"])
        self.assertEqual(carried["locators"], locators["locators"])
        self.assertEqual(locators, before)
        self.assertEqual(carried["registry"], pl.registry_binding(current))
        self.assertEqual(carried["revision"], "locators-02")
        observed_carried = pe.carry_forward(registry, observed, current)
        self.assertEqual([{key: row[key] for key in observed["acquisitions"][0]}
                          for row in observed_carried["acquisitions"]], observed["acquisitions"])
        self.assertEqual(observed_carried["acquisitions"][0]["recordSha256"],
                         cr.digest(cr.json_bytes(registry["records"][0])))

    def test_append_only_rejects_old_row_changes(self):
        """Source・製品・配布・観測の改変をlocatorの世代引継ぎへ混ぜない。"""
        registry, locators, observed = snapshot_fixture()
        changes = (("sources", "collectionMethod", "LEGACY_ASUS_METADATA"),
                   ("products", "model", "Changed"), ("records", "title", "Changed"),
                   ("observations", "id", "changed-observation"))
        for name, key, replacement in changes:
            current = next_registry(registry)
            current[name][0][key] = replacement
            with self.subTest(collection=name), self.assertRaises(cr.RegistryError) as result:
                ls.carry_forward_locators(registry, locators, current,
                                           revision="locators-02", as_of=current["asOf"])
            self.assertEqual(str(result.exception), "LOCATOR_CARRY_NOT_APPEND_ONLY")

    def test_carry_generation_and_schema_downgrade_rejection(self):
        """同revision・逆行日時・schema降格をcopyによる新世代として認めない。"""
        registry, locators, observed = snapshot_fixture()
        cases = ((registry, "locators-02", registry["asOf"]),
                 (next_registry(registry), locators["revision"], "2026-10-03T02:00:00Z"),
                 (next_registry(registry), "locators-02", "2026-10-01T00:00:00Z"))
        for current, revision, as_of in cases:
            with self.subTest(revision=revision, as_of=as_of), self.assertRaises(cr.RegistryError):
                ls.carry_forward_locators(registry, locators, current, revision=revision, as_of=as_of)
        registry["schema"] = cr.QUERY_REGISTRY_SCHEMA
        locators["registry"] = pl.registry_binding(cr.validate_registry(registry))
        current = next_registry(registry)
        current["schema"] = cr.REGISTRY_SCHEMA
        with self.assertRaises(cr.RegistryError) as result:
            ls.carry_forward_locators(registry, locators, current,
                                       revision="locators-02", as_of=current["asOf"])
        self.assertEqual(str(result.exception), "LOCATOR_CARRY_SCHEMA")

    def test_carry_allows_v1_to_v2_and_new_product(self):
        """旧rowを保ったschema昇格と新しい製品の追加を受理する。"""
        registry, locators, observed = snapshot_fixture()
        current = next_registry(registry)
        current["schema"] = cr.QUERY_REGISTRY_SCHEMA
        current["products"].append({**current["products"][0], "id": "product-two", "model": "Device Two"})
        current["observations"].append({**current["observations"][0], "id": "product-two-observation",
                                        "productId": "product-two"})
        carried = ls.carry_forward_locators(registry, locators, current,
                                            revision="locators-02", as_of=current["asOf"])
        self.assertEqual(carried["locators"], locators["locators"])

    def test_cli_build_verify_zip_carry_and_redacted_errors(self):
        """CLIの実入口を非通信で通し、原証拠とlocator保留を新しい出力へ保持する。"""
        registry, locators, observed = snapshot_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (("registry.json", registry), ("locators.json", locators),
                                ("evidence.json", observed), ("next.json", next_registry(registry))):
                (root / name).write_bytes(cr.json_bytes(value))
            commands = [
                ["build", str(root / "registry.json"), str(root / "locators.json"), str(root / "snapshot"),
                 "--evidence", str(root / "evidence.json")],
                ["verify", str(root / "snapshot")],
                ["zip", str(root / "snapshot"), str(root / "snapshot.zip")],
                ["carry-forward", str(root / "snapshot"), str(root / "next.json"), str(root / "next"),
                 "--locator-revision", "locators-02"]]
            for command in commands:
                output = io.StringIO()
                with self.subTest(command=command[0]), patch("sys.argv", ["snapshot", *command]), \
                        contextlib.redirect_stdout(output), patch("subprocess.run") as network:
                    self.assertEqual(ls.main(), 0)
                    network.assert_not_called()
                    self.assertNotIn("https://", output.getvalue())
                    self.assertNotIn(str(root), output.getvalue())
            current, carried, proof = ls.verify_snapshot(root / "next")
            self.assertEqual(carried["locators"], locators["locators"])
            self.assertEqual([{key: row[key] for key in observed["acquisitions"][0]}
                              for row in proof["acquisitions"]], observed["acquisitions"])
            self.assertEqual(proof["acquisitions"][0]["recordSha256"],
                             cr.digest(cr.json_bytes(registry["records"][0])))
            error = io.StringIO()
            with patch("sys.argv", ["snapshot", "verify", str(root / "missing")]), \
                    contextlib.redirect_stderr(error):
                self.assertEqual(ls.main(), 2)
            self.assertEqual(error.getvalue(), "REJECTED:IO_ERROR\n")


class LocatorEnrichmentTests(unittest.TestCase):
    """独立した明示補完を既存検証へ接続し、旧locatorの保留境界を維持する。"""

    def carry(self, fixture, **options):
        """架空の新台帳へ旧全locatorを引き継ぎ、元objectへ書き込まない。"""
        old, locators, observed, current = fixture
        return ls.carry_forward_locators(old, locators, current, revision="locators-02",
                                         as_of=current["asOf"], old_evidence=observed, **options)

    def test_product_mode_is_independent_and_preserves_original_objects(self):
        """PAGE_ONLY一件は明示製品modeだけで補完し、全旧入力・locatorを保持する。"""
        values = enrichment_fixture(product=True)
        before = copy.deepcopy(values)
        for options in ({}, {"allow_link_enrichment": True}, {"allow_metadata_enrichment": True}):
            with self.subTest(options=options), self.assertRaises(cr.RegistryError):
                self.carry(values, **options)
        carried = self.carry(values, allow_product_enrichment=True)
        self.assertEqual(carried["locators"], values[1]["locators"])
        self.assertEqual(carried["registry"], pl.registry_binding(values[3]))
        self.assertEqual(values, before)

    def test_thirteen_metadata_references_and_combined_modes(self):
        """共有配布13製品の参照追記と未知一件の補完を、必要な独立modeで受理する。"""
        values = enrichment_fixture(metadata=True, metadata_count=13)
        before = copy.deepcopy(values)
        self.assertEqual(len(values[0]["products"]), 13)
        for options in ({}, {"allow_link_enrichment": True}, {"allow_product_enrichment": True}):
            with self.subTest(options=options), self.assertRaises(cr.RegistryError):
                self.carry(values, **options)
        self.assertEqual(self.carry(values, allow_metadata_enrichment=True)["locators"], values[1]["locators"])
        self.assertEqual(values, before)
        combined = enrichment_fixture(product=True, metadata=True, metadata_count=13)
        for options in ({"allow_product_enrichment": True}, {"allow_metadata_enrichment": True}):
            with self.subTest(options=options), self.assertRaises(cr.RegistryError):
                self.carry(combined, **options)
        for link in (False, True):
            carried = self.carry(combined, allow_product_enrichment=True, allow_metadata_enrichment=True,
                                 allow_link_enrichment=link)
            self.assertEqual(carried["locators"], combined[1]["locators"])

    def test_each_mode_requires_exact_boolean(self):
        """三boolを個別に検査し、整数・null・文字列を許可として扱わない。"""
        values = enrichment_fixture(product=True, metadata=True)
        cases = (("allow_link_enrichment", "LOCATOR_ENRICHMENT_MODE"),
                 ("allow_product_enrichment", "LOCATOR_PRODUCT_ENRICHMENT_MODE"),
                 ("allow_metadata_enrichment", "LOCATOR_METADATA_ENRICHMENT_MODE"))
        for name, code in cases:
            for value in (1, None, "true"):
                with self.subTest(name=name, value=value), self.assertRaisesRegex(cr.RegistryError, "^" + code + "$"):
                    self.carry(values, **{name: value})

    def test_any_enabled_mode_requires_original_evidence(self):
        """一つでも明示補完が有効なら、証拠なしの引継ぎを生成前に拒否する。"""
        old, locators, _ = snapshot_fixture()
        current = next_registry(old)
        for name in ("allow_link_enrichment", "allow_product_enrichment", "allow_metadata_enrichment"):
            with self.subTest(name=name), self.assertRaisesRegex(cr.RegistryError,
                    "^LOCATOR_ENRICHMENT_EVIDENCE_REQUIRED$"):
                ls.carry_forward_locators(old, locators, current, revision="locators-02",
                                          as_of=current["asOf"], old_evidence=None, **{name: True})

    def test_fresh_product_record_source_time_and_http_evidence_is_required(self):
        """欠落・別製品／配布／取得元・古い／未来の日時・HTTP失敗を根拠へ流用しない。"""
        mutations = (None, {"productId": "product-one"}, {"recordId": "record-one"},
                     {"evidenceUrl": "https://vendor.example.org/drivers"},
                     {"checkedAt": "2026-10-02T23:59:59Z"}, {"checkedAt": "2026-10-03T02:00:01Z"},
                     {"httpStatus": 403}, {"httpStatus": 302}, {"method": "LEGACY_PROJECTION"})
        for mode in ("allow_product_enrichment", "allow_metadata_enrichment"):
            for change in mutations:
                values = enrichment_fixture(product=mode == "allow_product_enrichment",
                                             metadata=mode == "allow_metadata_enrichment")
                current = values[3]
                identifier = "fresh-unknown-one" if mode == "allow_product_enrichment" else "fresh-product-one"
                fresh = next(row for row in current["observations"] if row["id"] == identifier)
                if change is None:
                    current["observations"].remove(fresh)
                elif mode == "allow_metadata_enrichment" and change == {"productId": "product-one"}:
                    fresh["productId"] = "missing-product"
                else:
                    fresh.update(change)
                before = copy.deepcopy(values)
                with self.subTest(mode=mode, change=change), self.assertRaises(cr.RegistryError):
                    self.carry(values, **{mode: True})
                self.assertEqual(values, before)

    def test_old_identity_and_reference_deletion_are_rejected(self):
        """旧stable identity・名称・source参照・metadata record参照を置換しない。"""
        for mode in ("allow_product_enrichment", "allow_metadata_enrichment"):
            for field, replacement in (("id", "renamed"), ("model", "Renamed Device"),
                                       ("sourceIds", ["source-two"]), ("recordIds", ["record-two"])):
                if mode == "allow_product_enrichment" and field == "recordIds":
                    continue
                values = enrichment_fixture(product=mode == "allow_product_enrichment",
                                             metadata=mode == "allow_metadata_enrichment")
                identifier = "unknown-one" if mode == "allow_product_enrichment" else "product-one"
                row = next(row for row in values[3]["products"] if row["id"] == identifier)
                row[field] = replacement
                with self.subTest(mode=mode, field=field), self.assertRaises(cr.RegistryError):
                    self.carry(values, **{mode: True})

    def test_unacquired_old_payload_record_is_protected_under_all_enabled_modes(self):
        """peが許す未取得URL補完でも、旧PAYLOAD locator参照recordは全属性を保持する。"""
        old, locators = locator_fixture()
        payload = next(row for row in locators["locators"] if row["purpose"] == "PAYLOAD")
        payload.update(url="https://cdn.example.org/held.zip", urlProfile="QUERYLESS")
        old["records"].append({**old["records"][0], "id": "acquired-record",
                                "downloadUrl": "https://cdn.example.org/acquired.zip", "linkState": "OFFICIAL_LINK"})
        old["products"][0]["recordIds"].append("acquired-record")
        old["observations"].append({**old["observations"][0], "id": "old-acquired-page",
                                    "recordId": "acquired-record", "kind": "OFFICIAL_LINK"})
        old = cr.validate_registry(old)
        locators["registry"] = pl.registry_binding(old)
        locators = pl.validate_locators(locators, old)
        observed = evidence(old)
        observed["acquisitions"][0]["recordId"] = "acquired-record"
        current = next_registry(old)
        next(row for row in current["records"] if row["id"] == "record-one").update(
            downloadUrl=payload["url"], linkState="OFFICIAL_LINK")
        current["observations"].append({**old["observations"][0], "id": "fresh-held-link",
                                        "recordId": "record-one", "productId": "product-one",
                                        "kind": "OFFICIAL_LINK", "checkedAt": current["asOf"]})
        options_list = ({"allow_link_enrichment": True},
                        {"allow_link_enrichment": True, "allow_product_enrichment": True},
                        {"allow_link_enrichment": True, "allow_metadata_enrichment": True},
                        {"allow_link_enrichment": True, "allow_product_enrichment": True,
                         "allow_metadata_enrichment": True})
        for options in options_list:
            pe.carry_forward(old, observed, current, **options)
            with self.subTest(options=options), self.assertRaisesRegex(cr.RegistryError,
                    "^LOCATOR_ENRICHMENT_HELD_RECORD$"):
                self.carry((old, locators, observed, current), **options)

    def test_new_modes_do_not_authorize_record_metadata_or_nonnull_url_changes(self):
        """旧recordの版・title・既存URLは新製品modeを併用しても変更できない。"""
        for field, replacement in (("packageVersion", "99.0"), ("title", "Changed"),
                                   ("downloadUrl", "https://cdn.example.org/changed.zip")):
            values = enrichment_fixture(product=True, metadata=True)
            values[3]["records"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(cr.RegistryError):
                self.carry(values, allow_link_enrichment=True, allow_product_enrichment=True,
                           allow_metadata_enrichment=True)

    def test_unheld_missing_link_requires_its_own_mode_with_both_product_modes(self):
        """旧PAYLOAD参照外のMISSING補完はリンクmodeも必要とし、三mode併用時だけ受理する。"""
        old, locators, _, current = enrichment_fixture(product=True, metadata=True)
        missing = {**old["records"][0], "id": "missing-record", "downloadUrl": None, "linkState": "MISSING"}
        old["records"].append(missing)
        old["products"][0]["recordIds"].append(missing["id"])
        page = {**old["observations"][0], "id": "old-missing-page", "productId": "product-one",
                "recordId": missing["id"],
                "kind": "OFFICIAL_PAGE"}
        old["observations"].append(page)
        old = cr.validate_registry(old)
        locators["registry"] = pl.registry_binding(old)
        current["records"].append({**missing, "downloadUrl": "https://cdn.example.org/missing.zip",
                                   "linkState": "OFFICIAL_LINK"})
        next(row for row in current["products"] if row["id"] == "product-one")["recordIds"].append(missing["id"])
        current["observations"].extend([page, {**page, "id": "fresh-missing-link", "kind": "OFFICIAL_LINK",
                                              "checkedAt": current["asOf"]}])
        values = old, pl.validate_locators(locators, old), evidence(old), cr.validate_registry(current)
        with self.assertRaises(cr.RegistryError):
            self.carry(values, allow_product_enrichment=True, allow_metadata_enrichment=True)
        carried = self.carry(values, allow_link_enrichment=True, allow_product_enrichment=True,
                             allow_metadata_enrichment=True)
        self.assertEqual(carried["locators"], values[1]["locators"])

    def test_cli_transfers_all_modes_to_locator_and_evidence_carry(self):
        """実CLI入口から二つの引継ぎへ全flagを渡し、旧証拠と保留rowを保存する。"""
        cases = ((True, False, False), (False, True, False), (True, True, False), (True, True, True))
        for product, metadata, link in cases:
            old, locators, observed, current = enrichment_fixture(product=product, metadata=metadata)
            with self.subTest(product=product, metadata=metadata, link=link), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                ls.write_snapshot(old, locators, root / "old", observed)
                (root / "registry.json").write_bytes(cr.json_bytes(current))
                options = {"allow_link_enrichment": link, "allow_product_enrichment": product,
                           "allow_metadata_enrichment": metadata}
                args = ["snapshot", "carry-forward", str(root / "old"), str(root / "registry.json"),
                        str(root / "new"), "--locator-revision", "locators-02"]
                args.extend("--" + name.replace("_", "-") for name, enabled in options.items() if enabled)
                output = io.StringIO()
                with patch("sys.argv", args), patch.object(pe, "carry_forward", wraps=pe.carry_forward) as carry, \
                        contextlib.redirect_stdout(output), patch("socket.getaddrinfo") as dns:
                    self.assertEqual(ls.main(), 0)
                    dns.assert_not_called()
                    self.assertEqual(carry.call_count, 2)
                    for call in carry.call_args_list:
                        self.assertEqual(call.kwargs, options)
                self.assertNotIn("https://", output.getvalue())
                self.assertNotIn(str(root), output.getvalue())
                rebuilt, carried, proof = ls.verify_snapshot(root / "new")
                self.assertEqual(rebuilt, current)
                self.assertEqual(carried["locators"], locators["locators"])
                self.assertEqual([{key: row[key] for key in observed["acquisitions"][0]}
                                  for row in proof["acquisitions"]], observed["acquisitions"])
                self.assertEqual(proof["originRegistry"], {"revision": old["revision"], "asOf": old["asOf"],
                                                           "sha256": cr.digest(cr.json_bytes(old))})

    def test_cli_rejects_evidence_less_snapshot_and_bad_proof_before_output(self):
        """明示補完の証拠欠落・誤根拠は出力directory作成前にcodeだけで拒否する。"""
        for mode in ("allow_link_enrichment", "allow_product_enrichment", "allow_metadata_enrichment"):
            for proof_missing in (False, True):
                old, locators, observed, current = enrichment_fixture(product=True, metadata=True)
                if proof_missing:
                    next(row for row in current["observations"] if row["id"] == "fresh-unknown-one")["httpStatus"] = 403
                with self.subTest(mode=mode, proof_missing=proof_missing), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    ls.write_snapshot(old, locators, root / "old", observed if proof_missing else None)
                    (root / "registry.json").write_bytes(cr.json_bytes(current))
                    args = ["snapshot", "carry-forward", str(root / "old"), str(root / "registry.json"),
                            str(root / "new"), "--locator-revision", "locators-02",
                            "--" + mode.replace("_", "-")]
                    output, error = io.StringIO(), io.StringIO()
                    with patch("sys.argv", args), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                        self.assertEqual(ls.main(), 2)
                    self.assertFalse((root / "new").exists())
                    self.assertEqual(output.getvalue(), "")
                    self.assertNotIn("https://", error.getvalue())
                    self.assertNotIn(str(root), error.getvalue())
                    if not proof_missing:
                        self.assertEqual(error.getvalue(), "REJECTED:LOCATOR_ENRICHMENT_EVIDENCE_REQUIRED\n")


if __name__ == "__main__":
    unittest.main()
