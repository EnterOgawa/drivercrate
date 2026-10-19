"""可搬取得証拠・非実行検査とsnapshot v2の非通信回帰試験。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の証拠とtemporary directoryのみを使用する。
"""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import collector_registry as cr
import collector_payload_evidence as pe
from test_collector_registry import fixture


def evidence(registry: dict) -> dict:
    """実取得と区別される架空の一件証拠を返す。"""
    return {"schema": pe.EVIDENCE_SCHEMA, "revision": "sample-test-01",
            "registryRevision": registry["revision"],
            "registrySha256": cr.digest(cr.json_bytes(cr.validate_registry(registry))),
            "asOf": "2026-10-03T01:00:00Z", "acquisitions": [{
                "id": "acquisition-one", "recordId": "record-one",
                "checkedAt": "2026-10-03T01:00:00Z", "state": "DOWNLOADED",
                "httpStatus": 200, "bytes": 100, "sha256": "a" * 64,
                "outerSignature": "NOT_CHECKED", "publisher": None,
                "inspection": "PASSED", "inspectorSha256": "b" * 64,
                "inspectionExitCode": 0, "verifiedInfs": 1, "rejectedInfs": 0,
                "inventoryFiles": 3, "reason": "NONE"}]}


class EvidenceTests(unittest.TestCase):
    """観測整合性と本文・実機適合・導入権限の非混同を確認する。"""

    def setUp(self):
        self.registry = fixture()
        self.evidence = evidence(self.registry)

    def reject_row(self, **changes):
        """一件の不整合が必ず例外になることを確認する。"""
        row = self.evidence["acquisitions"][0]
        row.update(changes)
        with self.assertRaises(cr.RegistryError):
            pe.validate_evidence(self.registry, self.evidence)

    def test_valid_counts_and_flags(self):
        index = cr.parse_json(pe.bundle_content(self.registry, self.evidence)["index/drivers.json"])
        self.assertTrue(index["researchOnly"])
        self.assertFalse(index["publishable"])
        self.assertFalse(index["installAuthorized"])
        self.assertEqual(index["applicability"], "NOT_CHECKED")
        self.assertEqual(index["counts"]["payloadsDownloaded"], 1)
        self.assertEqual(index["counts"]["contentsVerified"], 1)
        self.assertEqual(index["counts"]["deviceApplicabilityMeasured"], 0)
        self.assertIsNone(index["counts"]["uniquePayloads"])
        self.assertEqual(index["records"][0]["contentState"], "CONTENT_VERIFIED")
        self.assertEqual(self.registry["records"][0]["contentState"], "NOT_DOWNLOADED")

    def test_unknown_root_and_row_fields(self):
        for target in (self.evidence, self.evidence["acquisitions"][0]):
            target["extra"] = "unknown"
            with self.assertRaises(cr.RegistryError):
                pe.validate_evidence(self.registry, self.evidence)
            del target["extra"]

    def test_wrong_schema_binding_or_revision(self):
        for key, value in (("schema", "future"), ("registryRevision", "wrong"),
                           ("registrySha256", "c" * 64), ("revision", "C:/private")):
            original = self.evidence[key]
            self.evidence[key] = value
            with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                pe.validate_evidence(self.registry, self.evidence)
            self.evidence[key] = original

    def test_duplicate_and_unknown_records(self):
        original = copy.deepcopy(self.evidence)
        for changes in ({}, {"id": "acquisition-other"}, {"id": "acquisition-other", "recordId": "absent"}):
            second = {**original["acquisitions"][0], **changes}
            self.evidence = {**original, "acquisitions": [original["acquisitions"][0], second]}
            with self.subTest(changes=changes), self.assertRaises(cr.RegistryError):
                pe.validate_evidence(self.registry, self.evidence)

    def test_missing_download_link(self):
        self.registry["records"][0].update(downloadUrl=None, linkState="MISSING")
        self.registry["observations"] = [{**self.registry["observations"][0], "kind": "OFFICIAL_PAGE"}]
        self.evidence["registrySha256"] = cr.digest(cr.json_bytes(cr.validate_registry(self.registry)))
        self.reject_row()

    def test_download_requires_positive_bounded_bytes_status_hash(self):
        for changes in ({"bytes": 0}, {"bytes": 64 * 1024 * 1024 + 1}, {"httpStatus": 302},
                        {"sha256": None}, {"sha256": "a" * 63}, {"reason": "TRANSFER_FAILED"}):
            self.evidence = evidence(self.registry)
            with self.subTest(changes=changes):
                self.reject_row(**changes)

    def test_boolean_and_negative_counts(self):
        for key in ("bytes", "verifiedInfs", "rejectedInfs", "inventoryFiles", "httpStatus", "inspectionExitCode"):
            for value in (True, -1):
                self.evidence = evidence(self.registry)
                with self.subTest(key=key, value=value):
                    self.reject_row(**{key: value})

    def test_time_binding(self):
        for value in ("2026-10-02T01:00:00Z", "2026-10-03T02:00:00Z", "2026-10-03T01:00:00+00:00"):
            with self.subTest(value=value):
                self.reject_row(checkedAt=value)

    def test_published_hash_mismatch(self):
        self.registry["records"][0]["publishedSha256"] = "c" * 64
        self.evidence = evidence(self.registry)
        self.reject_row()

    def test_failure_cannot_claim_content_or_signature(self):
        self.reject_row(state="FAILED", reason="TRANSFER_FAILED", bytes=0, sha256=None)
        self.evidence = evidence(self.registry)
        self.reject_row(state="FAILED", reason="TRANSFER_FAILED")

    def test_unattempted_reason_and_valid_failed_row(self):
        for state, reason in (("FAILED", "TRANSFER_FAILED"), ("CONSENT_REQUIRED", "CONSENT_REQUIRED"),
                              ("NOT_ATTEMPTED", "NOT_ATTEMPTED")):
            self.evidence = evidence(self.registry)
            row = self.evidence["acquisitions"][0]
            row.update(state=state, reason=reason, httpStatus=None, bytes=0, sha256=None,
                       inspection="NOT_CHECKED", inspectorSha256=None, inspectionExitCode=None,
                       verifiedInfs=0, inventoryFiles=0)
            self.assertEqual(pe.evidence_counts(self.registry, self.evidence)["payloadsDownloaded"], 0)
            row["reason"] = "NOT_ATTEMPTED" if state == "FAILED" else "TRANSFER_FAILED"
            with self.subTest(state=state), self.assertRaises(cr.RegistryError):
                pe.validate_evidence(self.registry, self.evidence)

    def test_signer_identity_and_private_text(self):
        for changes in ({"outerSignature": "VALID"}, {"publisher": "Example"},
                        {"outerSignature": "VALID", "publisher": "C:/private"}):
            self.evidence = evidence(self.registry)
            with self.subTest(changes=changes):
                self.reject_row(**changes)

    def test_partial_rejected_and_unsupported_are_not_content_passes(self):
        for state, values in (("PARTIAL", {"rejectedInfs": 1}),
                              ("REJECTED", {"verifiedInfs": 0, "rejectedInfs": 1, "inspectionExitCode": 1}),
                              ("UNSUPPORTED", {"verifiedInfs": 0, "inventoryFiles": 0,
                                               "inspectionExitCode": None, "inspectorSha256": None})):
            self.evidence = evidence(self.registry)
            self.evidence["acquisitions"][0].update(inspection=state, **values)
            with self.subTest(state=state):
                self.assertEqual(pe.evidence_counts(self.registry, self.evidence)["contentsVerified"], 0)
                self.assertEqual(pe.evidence_counts(self.registry, self.evidence)["payloadsDownloaded"], 1)

    def test_inconsistent_inspection_counts(self):
        for changes in ({"inspectionExitCode": 1}, {"rejectedInfs": 1}, {"inventoryFiles": 0},
                        {"inspection": "PARTIAL"}, {"inspection": "REJECTED"}, {"inspectorSha256": None}):
            self.evidence = evidence(self.registry)
            with self.subTest(changes=changes):
                self.reject_row(**changes)

    def test_hash_dedup_and_byte_conflict(self):
        second = copy.deepcopy(self.registry["records"][0])
        second["id"] = "record-two"
        self.registry["records"].append(second)
        self.registry["products"][0]["recordIds"].append("record-two")
        for original in list(self.registry["observations"]):
            row = {**original, "id": original["id"] + "-two", "recordId": "record-two"}
            self.registry["observations"].append(row)
        self.evidence = evidence(self.registry)
        row = {**self.evidence["acquisitions"][0], "id": "acquisition-two", "recordId": "record-two"}
        self.evidence["acquisitions"].append(row)
        counts = pe.evidence_counts(self.registry, self.evidence)
        self.assertEqual(counts["payloadsDownloaded"], 1)
        self.assertEqual(counts["contentsVerified"], 1)
        self.assertEqual(counts["recordsWithDownloadedPayloads"], 2)
        self.assertEqual(counts["productsWithDownloadedPayloads"], 1)
        row["bytes"] = 101
        with self.assertRaisesRegex(cr.RegistryError, "HASH_BYTE_CONFLICT"):
            pe.validate_evidence(self.registry, self.evidence)


class CarryForwardTests(unittest.TestCase):
    """追加専用拡大で過去日時を保ち、別配布への証拠転用を拒否する。"""

    def setUp(self):
        self.old_registry = fixture()
        self.old_evidence = evidence(self.old_registry)
        self.new_registry = copy.deepcopy(self.old_registry)
        self.new_registry.update(revision="test-02", asOf="2026-10-03T02:00:00Z")
        product = {**copy.deepcopy(self.new_registry["products"][0]),
                   "id": "product-two", "model": "Device Two"}
        self.new_registry["products"].append(product)
        self.new_registry["observations"].append({**self.new_registry["observations"][0],
            "id": "page-two", "productId": "product-two", "checkedAt": "2026-10-03T02:00:00Z"})

    def test_preserves_old_rows_time_origin_and_counts(self):
        carried = pe.carry_forward(self.old_registry, self.old_evidence, self.new_registry)
        self.assertEqual(carried["schema"], pe.CARRIED_EVIDENCE_SCHEMA)
        self.assertEqual(carried["originRegistry"]["revision"], "test-01")
        row = dict(carried["acquisitions"][0])
        row.pop("recordSha256")
        self.assertEqual(row, self.old_evidence["acquisitions"][0])
        self.assertEqual(pe.evidence_counts(self.new_registry, carried)["payloadsDownloaded"], 1)
        self.assertEqual(pe.evidence_counts(self.new_registry, carried)["productsWithDownloadedPayloads"], 2)

    def test_old_evidence_binding_must_be_valid(self):
        self.old_evidence["registrySha256"] = "c" * 64
        with self.assertRaisesRegex(cr.RegistryError, "EVIDENCE_REGISTRY_BINDING"):
            pe.carry_forward(self.old_registry, self.old_evidence, self.new_registry)

    def test_all_old_collections_must_be_unchanged(self):
        for name, field, value in (("sources", "officialPage", "https://vendor.example.org/other"),
                                   ("products", "model", "Other Device"),
                                   ("records", "title", "Other driver"),
                                   ("observations", "checkedAt", "2026-10-02T01:00:00Z")):
            changed = copy.deepcopy(self.new_registry)
            changed[name][0][field] = value
            if name == "sources":
                for observation in changed["observations"]:
                    if observation["kind"] == "OFFICIAL_LINK":
                        observation["evidenceUrl"] = value
            with self.subTest(collection=name), self.assertRaisesRegex(
                    cr.RegistryError, "CARRY_FORWARD_NOT_APPEND_ONLY"):
                pe.carry_forward(self.old_registry, self.old_evidence, changed)

    def test_removed_product_or_acquired_record_is_rejected(self):
        for name in ("products", "records"):
            changed = copy.deepcopy(self.new_registry)
            changed[name] = changed[name][1:]
            with self.subTest(collection=name), self.assertRaises(cr.RegistryError):
                pe.carry_forward(self.old_registry, self.old_evidence, changed)

    def test_same_generation_and_time_regression_are_rejected(self):
        for changes in ({"revision": "test-01"}, {"asOf": "2026-10-02T23:00:00Z"}):
            changed = {**self.new_registry, **changes}
            with self.subTest(changes=changes), self.assertRaises(cr.RegistryError):
                pe.carry_forward(self.old_registry, self.old_evidence, changed)

    def test_v2_record_digest_origin_time_and_extra_fields_are_checked(self):
        carried = pe.carry_forward(self.old_registry, self.old_evidence, self.new_registry)
        for target, key, value in (("row", "recordSha256", "c" * 64),
                                    ("row", "checkedAt", "2026-10-02T23:59:59Z"),
                                    ("origin", "asOf", "2026-10-03T03:00:00Z"),
                                    ("origin", "sha256", None), ("origin", "extra", "unknown")):
            changed = copy.deepcopy(carried)
            item = changed["acquisitions"][0] if target == "row" else changed["originRegistry"]
            item[key] = value
            with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                pe.validate_evidence(self.new_registry, changed)

    def test_repeat_carry_keeps_first_origin_and_original_rows(self):
        carried = pe.carry_forward(self.old_registry, self.old_evidence, self.new_registry)
        newest = {**copy.deepcopy(self.new_registry), "revision": "test-03",
                  "asOf": "2026-10-03T03:00:00Z"}
        repeated = pe.carry_forward(self.new_registry, carried, newest)
        self.assertEqual(repeated["originRegistry"], carried["originRegistry"])
        self.assertEqual(repeated["acquisitions"], carried["acquisitions"])

    def test_copy_bundle_is_deterministic_and_no_permission_is_added(self):
        carried = pe.carry_forward(self.old_registry, self.old_evidence, self.new_registry)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pe.write_bundle(self.new_registry, carried, root / "snapshot")
            shutil.copytree(root / "snapshot", root / "copied")
            registry, observed = pe.verify_bundle(root / "copied")
            self.assertEqual(observed["acquisitions"], carried["acquisitions"])
            index = cr.read_json(root / "copied/index/drivers.json")
            self.assertFalse(index["installAuthorized"])
            self.assertFalse(index["publishable"])
            self.assertEqual(index["applicability"], "NOT_CHECKED")
            self.assertEqual(pe.bundle_content(registry, observed),
                             pe.bundle_content(self.new_registry, carried))


class BundleTests(unittest.TestCase):
    """7 fileのcopy再読込み・再生成と拒否境界を確認する。"""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.registry = fixture()
        self.evidence = evidence(self.registry)
        self.snapshot = self.root / "snapshot"
        pe.write_bundle(self.registry, self.evidence, self.snapshot)

    def test_copy_rebuild_zip_determinism(self):
        copied = self.root / "copied"
        shutil.copytree(self.snapshot, copied)
        registry, observed = pe.verify_bundle(copied)
        rebuilt = self.root / "rebuilt"
        pe.write_bundle(registry, observed, rebuilt)
        for name in pe.BUNDLE_FILES:
            self.assertEqual((self.snapshot / name).read_bytes(), (rebuilt / name).read_bytes())
        first, second = self.root / "first.zip", self.root / "second.zip"
        pe.write_zip(copied, first)
        pe.write_zip(rebuilt, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(set(archive.namelist()), {"collector-data/" + name for name in pe.BUNDLE_FILES})

    def test_no_overwrite(self):
        with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
            pe.write_bundle(self.registry, self.evidence, self.snapshot)
        archive = self.root / "one.zip"
        pe.write_zip(self.snapshot, archive)
        with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
            pe.write_zip(self.snapshot, archive)

    def test_rehashed_forged_index_claim(self):
        index_path = self.snapshot / "index/drivers.json"
        index = cr.read_json(index_path)
        index["installAuthorized"] = True
        index_path.write_bytes(cr.json_bytes(index))
        manifest_path = self.snapshot / "manifest.json"
        manifest = cr.read_json(manifest_path)
        for row in manifest["files"]:
            if row["path"] == "index/drivers.json":
                raw = index_path.read_bytes()
                row.update(bytes=len(raw), sha256=cr.digest(raw))
        manifest_path.write_bytes(cr.json_bytes(manifest))
        with self.assertRaises(cr.RegistryError):
            pe.verify_bundle(self.snapshot)

    def test_extra_payload_and_missing_evidence(self):
        extra = self.snapshot / "payload.exe"
        extra.write_bytes(b"MZ-fake")
        with self.assertRaisesRegex(cr.RegistryError, "SNAPSHOT_FILE_SET"):
            pe.verify_bundle(self.snapshot)
        extra.unlink()
        (self.snapshot / "payload-evidence.json").unlink()
        with self.assertRaisesRegex(cr.RegistryError, "SNAPSHOT_FILE_SET"):
            pe.verify_bundle(self.snapshot)

    def test_evidence_tamper_and_oversize(self):
        path = self.snapshot / "payload-evidence.json"
        value = cr.read_json(path)
        value["registrySha256"] = "c" * 64
        path.write_bytes(cr.json_bytes(value))
        with self.assertRaises(cr.RegistryError):
            pe.verify_bundle(self.snapshot)
        with patch.object(cr, "MAX_JSON_BYTES", 10):
            with self.assertRaisesRegex(cr.RegistryError, "JSON_SIZE"):
                pe.verify_bundle(self.snapshot)

    def test_reparse_and_second_tree_check(self):
        """file種別検査の拒否と、二回目のtree列挙前に増えたfileの拒否を個別に確認する。

        changed_tree.callsはこのtestだけの呼出し回数であり、最初の列挙後だけlate.exeを追加する。
        patch解除後のfile後始末はBundleTestsのtemporary所有者へ任せる。
        """
        with patch.object(cr, "regular_path", side_effect=cr.RegistryError("REPARSE_PATH")):
            with self.assertRaisesRegex(cr.RegistryError, "REPARSE_PATH"):
                pe.verify_bundle(self.snapshot)
        actual_tree = pe.tree_files
        def changed_tree(root):
            if changed_tree.calls:
                (root / "late.exe").write_bytes(b"MZ")
            changed_tree.calls += 1
            return actual_tree(root)
        changed_tree.calls = 0
        with patch.object(pe, "tree_files", side_effect=changed_tree):
            with self.assertRaisesRegex(cr.RegistryError, "SNAPSHOT_FILE_SET"):
                pe.verify_bundle(self.snapshot)

    def test_v1_and_v2_are_not_interchangeable(self):
        original = self.root / "v1"
        cr.write_snapshot(self.registry, original)
        self.assertEqual(cr.verify_snapshot(original), cr.validate_registry(self.registry))
        with self.assertRaises(cr.RegistryError):
            pe.verify_bundle(original)
        with self.assertRaises(cr.RegistryError):
            cr.verify_snapshot(self.snapshot)


if __name__ == "__main__":
    unittest.main()
