"""共通四軸索引の非昇格・互換性・可搬metadataを架空値で検査する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
ネットワーク・installer・実端末ID・導入を使用しない。
"""

import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_payload_evidence as pe
import common_maintenance_index as mi
from test_collector_registry import fixture
from test_collector_payload_evidence import evidence


def assessments(registry, payload):
    """架空の保守内容だけが合格した、未適合・導入未対応の一INFを作る。"""
    return {"schema": mi.SCHEMA, "researchOnly": True, "publishable": False,
        "installAuthorized": False, "registrySha256": cr.digest(cr.json_bytes(cr.validate_registry(registry))),
        "payloadEvidenceSha256": cr.digest(cr.json_bytes(pe.validate_evidence(registry, payload))),
        "asOf": "2026-10-03T02:00:00Z", "proofs": [{"kind": "PACKAGE_ASSESSMENT",
            "sha256": "d" * 64, "checkedAt": "2026-10-03T02:00:00Z"}],
        "infs": [{"recordId": "record-one", "recordSha256": cr.digest(cr.json_bytes(registry["records"][0])),
            "sourceSha256": cr.digest(cr.json_bytes(registry["sources"][0])), "archiveSha256": "a" * 64,
            "infSha256": "e" * 64, "archiveDepth": 0, "sourceKind": "PACKAGE_ASSESSMENT",
            "proofSha256": "d" * 64, "sourceMemberSha256": None, "derivedArchiveSha256": None,
            "parser": {"state": "PASSED", "error": 0}, "integrity": {"state": "PASSED", "error": 0},
            "applicability": {"state": "NOT_CHECKED", "error": 0},
            "installRoute": {"state": "UNSUPPORTED", "error": -2147024846},
            "dependencyState": "EXTERNAL_PRESENT"}]}


class MaintenanceIndexTests(unittest.TestCase):
    """研究観測の整合性と、内容合格を導入許可へ変えないことを検査する。"""

    def setUp(self):
        self.registry = cr.validate_registry(fixture())
        self.evidence = pe.validate_evidence(self.registry, evidence(self.registry))
        self.value = assessments(self.registry, self.evidence)

    def reject(self, value):
        """不正metadataを正規化で救済しない。"""
        with self.assertRaises(cr.RegistryError):
            mi.validate_assessments(self.registry, self.evidence, value)

    def test_content_is_not_device_or_install_permission(self):
        result = cr.parse_json(mi.bundle_content(self.registry, self.evidence, self.value)["index/drivers.json"])
        self.assertEqual(result["schema"], mi.INDEX_SCHEMA)
        self.assertTrue(result["researchOnly"])
        self.assertFalse(result["publishable"])
        self.assertFalse(result["installAuthorized"])
        self.assertEqual(result["applicability"], "NOT_CHECKED")
        self.assertEqual(result["maintenanceScope"], "PARTIAL_INF_CONTENT")
        self.assertEqual(result["counts"]["maintenanceContentVerifiedInfs"], 1)
        self.assertEqual(result["counts"]["maintenanceExternalDependencyInfs"], 1)
        self.assertEqual(result["counts"]["maintenanceInstallRoutePassedInfs"], 0)
        self.assertEqual(result["counts"]["deviceApplicabilityMeasured"], 0)

    def test_old_bytes_fields_and_arguments_unchanged(self):
        old = pe.bundle_content(self.registry, self.evidence)
        inputs = copy.deepcopy((self.registry, self.evidence, self.value))
        new = mi.bundle_content(self.registry, self.evidence, self.value)
        self.assertEqual((self.registry, self.evidence, self.value), inputs)
        for name in old.keys() - {"index/drivers.json", "manifest.json"}:
            self.assertEqual(old[name], new[name])
        before, after = [cr.parse_json(c["index/drivers.json"]) for c in (old, new)]
        for name in ("sources", "products", "records", "payloadEvidence"):
            self.assertEqual(before[name], after[name])
        self.assertEqual(old, pe.bundle_content(self.registry, self.evidence))

    def test_no_whole_package_promotion(self):
        self.evidence["acquisitions"][0].update(inspection="UNSUPPORTED", inspectorSha256=None,
            inspectionExitCode=None, verifiedInfs=0, rejectedInfs=0, inventoryFiles=0)
        self.value = assessments(self.registry, self.evidence)
        index = cr.parse_json(mi.bundle_content(self.registry, self.evidence, self.value)["index/drivers.json"])
        self.assertEqual(index["records"][0]["contentState"], "INSPECTION_UNSUPPORTED")
        self.assertEqual(index["counts"]["contentsVerified"], 0)
        self.assertEqual(index["counts"]["maintenanceContentVerifiedInfs"], 1)

    def test_schema_and_permission_flags(self):
        for field, replacement in (("schema", "future"), ("researchOnly", False),
                ("researchOnly", 1), ("publishable", True), ("publishable", 0),
                ("installAuthorized", True), ("installAuthorized", 0)):
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field, replacement=replacement):
                self.reject(value)

    def test_unknown_fields_and_private_data(self):
        for field in ("hardwareId", "instanceId", "path", "downloadGrant", "rank", "token", "extra"):
            for target in ("root", "inf", "proof", "finding"):
                value = copy.deepcopy(self.value)
                row = {"root": value, "inf": value["infs"][0], "proof": value["proofs"][0],
                       "finding": value["infs"][0]["parser"]}[target]
                row[field] = "private-fixture"
                with self.subTest(field=field, target=target):
                    self.reject(value)

    def test_generation_and_source_hash_bindings(self):
        for target, fields in (("root", ("registrySha256", "payloadEvidenceSha256")),
                ("inf", ("recordSha256", "sourceSha256", "archiveSha256", "proofSha256"))):
            for field in fields:
                value = copy.deepcopy(self.value)
                (value if target == "root" else value["infs"][0])[field] = "f" * 64
                with self.subTest(target=target, field=field):
                    self.reject(value)

    def test_missing_or_malformed_hash(self):
        for field in ("recordSha256", "sourceSha256", "archiveSha256", "infSha256", "proofSha256"):
            for replacement in (None, "A" * 64, "e" * 63, True, [], "C:/private"):
                value = copy.deepcopy(self.value)
                value["infs"][0][field] = replacement
                with self.subTest(field=field, replacement=replacement):
                    self.reject(value)

    def test_unknown_unacquired_record(self):
        value = copy.deepcopy(self.value)
        value["infs"][0]["recordId"] = "absent"
        self.reject(value)
        self.evidence["acquisitions"][0].update(state="NOT_ATTEMPTED", reason="NOT_ATTEMPTED",
            httpStatus=None, bytes=0, sha256=None, outerSignature="NOT_CHECKED", publisher=None,
            inspection="NOT_CHECKED", inspectorSha256=None, inspectionExitCode=None,
            verifiedInfs=0, rejectedInfs=0, inventoryFiles=0)
        value = assessments(self.registry, self.evidence)
        self.reject(value)

    def test_inf_identity_depth_and_duplicates(self):
        for depth in (True, -1, 2, "0"):
            value = copy.deepcopy(self.value)
            value["infs"][0]["archiveDepth"] = depth
            with self.subTest(depth=depth):
                self.reject(value)
        value = copy.deepcopy(self.value)
        value["infs"].append(copy.deepcopy(value["infs"][0]))
        self.reject(value)

    def test_all_findings_keep_error_and_state(self):
        for axis in mi.AXES:
            for replacement in ({"state": "FUTURE", "error": 0}, {"state": [], "error": 0},
                    {"state": "PASSED", "error": True}, {"state": "PASSED", "error": -(2 ** 31) - 1},
                    {"state": "PASSED", "error": 2 ** 31}, {"state": "PASSED", "error": -1}):
                value = copy.deepcopy(self.value)
                value["infs"][0][axis] = replacement
                with self.subTest(axis=axis, replacement=replacement):
                    self.reject(value)

    def test_device_and_route_pass_cannot_be_claimed(self):
        for axis in ("applicability", "installRoute"):
            value = copy.deepcopy(self.value)
            value["infs"][0][axis] = {"state": "PASSED", "error": 0}
            self.reject(value)

    def test_unparsed_unsigned_or_unknown_dependency_not_content_pass(self):
        for axis in ("parser", "integrity"):
            for state, error in (("NOT_CHECKED", 0), ("UNSUPPORTED", -1), ("FAILED", -1)):
                value = copy.deepcopy(self.value)
                value["infs"][0][axis] = {"state": state, "error": error}
                with self.subTest(axis=axis, state=state):
                    self.reject(value)
        for state in ("NOT_CHECKED", "SATISFIED", True, []):
            value = copy.deepcopy(self.value)
            value["infs"][0]["dependencyState"] = state
            self.reject(value)

    def test_no_external_reference_is_not_installed(self):
        self.value["infs"][0]["dependencyState"] = "NONE_REFERENCED"
        result = mi.validate_assessments(self.registry, self.evidence, self.value)
        self.assertEqual(mi.assessment_counts(result)["maintenanceExternalDependencyInfs"], 0)
        self.assertEqual(result["infs"][0]["installRoute"]["state"], "UNSUPPORTED")

    def test_unchecked_and_failed_routes_are_distinct(self):
        for state, error in (("NOT_CHECKED", 0), ("FAILED", -1)):
            self.value["infs"][0]["installRoute"] = {"state": state, "error": error}
            result = mi.validate_assessments(self.registry, self.evidence, self.value)
            self.assertEqual(result["infs"][0]["installRoute"], {"state": state, "error": error})

    def test_pe_origin_requires_both_hashes_and_zero_depth(self):
        self.value["proofs"][0]["kind"] = "PE_FLAT_TABLE"
        self.value["infs"][0].update(sourceKind="PE_FLAT_TABLE", sourceMemberSha256="1" * 64,
            derivedArchiveSha256="2" * 64)
        self.assertEqual(mi.validate_assessments(self.registry, self.evidence, self.value), self.value)
        for field, replacement in (("sourceMemberSha256", None), ("derivedArchiveSha256", None),
                                   ("archiveDepth", 1)):
            value = copy.deepcopy(self.value)
            value["infs"][0][field] = replacement
            self.reject(value)

    def test_package_cannot_pretend_to_be_pe(self):
        for field in ("sourceMemberSha256", "derivedArchiveSha256"):
            value = copy.deepcopy(self.value)
            value["infs"][0][field] = "1" * 64
            self.reject(value)
        value = copy.deepcopy(self.value)
        value["infs"][0]["sourceKind"] = "PE_FLAT_TABLE"
        self.reject(value)

    def test_same_inf_cannot_be_recounted_by_other_proof_kind(self):
        value = copy.deepcopy(self.value)
        value["proofs"].append({"kind": "PE_FLAT_TABLE", "sha256": "1" * 64,
            "checkedAt": value["asOf"]})
        value["infs"].append({**copy.deepcopy(value["infs"][0]), "sourceKind": "PE_FLAT_TABLE",
            "proofSha256": "1" * 64, "sourceMemberSha256": "2" * 64, "derivedArchiveSha256": "3" * 64})
        self.reject(value)

    def test_proof_kinds_unused_and_duplicate_rejected(self):
        for kind in ("FUTURE", [], None):
            value = copy.deepcopy(self.value)
            value["proofs"][0]["kind"] = kind
            self.reject(value)
        for digest in ("d" * 64, "f" * 64):
            value = copy.deepcopy(self.value)
            value["proofs"].append({**value["proofs"][0], "sha256": digest})
            self.reject(value)

    def test_proof_and_generation_times(self):
        for target, field, replacement in (("root", "asOf", "2026-10-03T00:59:59Z"),
                ("proof", "checkedAt", "2026-10-03T00:59:59Z"),
                ("proof", "checkedAt", "2026-10-03T02:00:01Z"),
                ("root", "asOf", "invalid")):
            value = copy.deepcopy(self.value)
            (value if target == "root" else value["proofs"][0])[field] = replacement
            self.reject(value)

    def test_empty_oversized_batches_and_file_budget(self):
        for name, rows in (("proofs", []), ("proofs", [{}] * 33), ("infs", []), ("infs", [{}] * 4097)):
            value = copy.deepcopy(self.value)
            value[name] = rows
            self.reject(value)
        with patch.object(cr, "MAX_JSON_BYTES", 50):
            self.reject(self.value)

    def test_normalized_order_and_many_products_one_distribution(self):
        self.value["infs"].append({**copy.deepcopy(self.value["infs"][0]), "infSha256": "1" * 64})
        second = {**self.registry["products"][0], "id": "product-two", "model": "Device Two"}
        self.registry["products"].append(second)
        self.registry["observations"].append({**self.registry["observations"][0],
            "id": "page-two", "productId": "product-two"})
        self.value["registrySha256"] = cr.digest(cr.json_bytes(cr.validate_registry(self.registry)))
        self.evidence = evidence(self.registry)
        self.value["payloadEvidenceSha256"] = cr.digest(cr.json_bytes(pe.validate_evidence(self.registry, self.evidence)))
        first = mi.bundle_content(self.registry, self.evidence, self.value)
        self.value["infs"].reverse()
        self.assertEqual(first, mi.bundle_content(self.registry, self.evidence, self.value))
        index = cr.parse_json(first["index/drivers.json"])
        self.assertEqual(index["counts"]["recordsWithMaintenanceContent"], 1)
        self.assertEqual(index["counts"]["maintenanceContentVerifiedInfs"], 2)
        self.assertEqual(index["counts"]["targetProducts"], 2)

    def test_old_and_query_registry_generations(self):
        for schema in (cr.REGISTRY_SCHEMA, cr.QUERY_REGISTRY_SCHEMA):
            self.registry["schema"] = schema
            self.evidence = evidence(self.registry)
            self.value = assessments(self.registry, self.evidence)
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "snapshot"
                mi.write_bundle(self.registry, self.evidence, self.value, root)
                registry, payload, value = mi.verify_bundle(root)
                self.assertEqual(registry["schema"], schema)
                self.assertEqual(value, self.value)
                self.assertEqual(payload, self.evidence)
                with self.assertRaises(cr.RegistryError):
                    pe.verify_bundle(root)

    def test_copy_has_exactly_eight_metadata_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "original"
            mi.write_bundle(self.registry, self.evidence, self.value, root)
            copied = Path(folder) / "copy"
            shutil.copytree(root, copied)
            self.assertEqual(mi.verify_bundle(root), mi.verify_bundle(copied))
            names = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
            self.assertEqual(names, mi.FILES)
            for name in names:
                self.assertEqual((root / name).read_bytes(), (copied / name).read_bytes())
            with self.assertRaises(cr.RegistryError):
                mi.write_bundle(self.registry, self.evidence, self.value, root)

    def test_each_file_tamper_and_missing_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "snapshot"
            mi.write_bundle(self.registry, self.evidence, self.value, root)
            for name in mi.FILES:
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.subTest(name=name), self.assertRaises(cr.RegistryError):
                    mi.verify_bundle(root)
                path.write_bytes(original)
                path.unlink()
                with self.subTest(missing=name), self.assertRaises(cr.RegistryError):
                    mi.verify_bundle(root)
                path.write_bytes(original)

    def test_manifest_flag_and_generation_changes_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "snapshot"
            mi.write_bundle(self.registry, self.evidence, self.value, root)
            path = root / "manifest.json"
            original = path.read_bytes()
            for field, replacement in (("schema", "future"), ("revision", "wrong"),
                    ("asOf", "2026-10-03T03:00:00Z"), ("registrySha256", "f" * 64),
                    ("registrySchema", []), ("files", []), ("installAuthorized", True)):
                value = cr.parse_json(original)
                value[field] = replacement
                path.write_bytes(cr.json_bytes(value))
                with self.subTest(field=field), self.assertRaises(cr.RegistryError):
                    mi.verify_bundle(root)
                path.write_bytes(original)

    def test_no_payload_or_unknown_directory_permitted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "snapshot"
            mi.write_bundle(self.registry, self.evidence, self.value, root)
            extra = root / "driver.zip"
            extra.write_bytes(b"fixture")
            with self.assertRaises(cr.RegistryError):
                mi.verify_bundle(root)
            extra.unlink()
            (root / "private").mkdir()
            with self.assertRaises(cr.RegistryError):
                mi.verify_bundle(root)

    def test_json_duplicate_keys_and_boolean_error_rejected(self):
        with self.assertRaises(cr.RegistryError):
            cr.parse_json(b'{"installAuthorized":false,"installAuthorized":true}')
        value = copy.deepcopy(self.value)
        value["infs"][0]["applicability"]["error"] = False
        self.reject(value)


if __name__ == "__main__":
    unittest.main()
