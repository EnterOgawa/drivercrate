"""大型plan・研究証拠・旧上限維持の非通信試験（ADR 0242）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の台帳・byte数だけを使用し、HTTP・本体・installerを扱わない。
"""
import copy
import unittest

import collector_registry as cr
import collector_payload_evidence as pe
import collector_large_payload_evidence as lp
from test_collector_registry import fixture
from test_collector_payload_evidence import evidence


def plan_fixture() -> dict:
    """一件の架空大型ZIP用明示planを生成する。"""
    return {"schema": lp.PLAN_SCHEMA, "revision": "large-test-01", "maximumTotalBytes": lp.GIB,
            "reserveFreeBytes": 2 * lp.GIB, "items": [{"recordId": "record-one",
                "maximumBytes": lp.GIB, "maximumSeconds": 900, "format": "ZIP",
                "preDownloadConsent": "NO_GATE_OBSERVED", "route": "DIRECT", "publicModel": None}]}


class LargeEvidenceTests(unittest.TestCase):
    """予算・世代・未対応claimと従来契約を独立に検査する。"""

    def setUp(self):
        self.registry = fixture()
        plan = plan_fixture()
        inner = evidence(self.registry)
        inner["revision"] = plan["revision"]
        inner["acquisitions"][0].update(bytes=256 * 1024 ** 2, inspection="UNSUPPORTED",
            inspectorSha256=None, inspectionExitCode=None, verifiedInfs=0, rejectedInfs=0, inventoryFiles=0)
        self.document = {"schema": lp.EVIDENCE_SCHEMA, "plan": plan,
                         "planSha256": cr.digest(cr.json_bytes(plan)), "evidence": inner}

    def test_valid_large_but_legacy_rejected(self):
        lp.validate_large_evidence(self.registry, self.document)
        with self.assertRaisesRegex(cr.RegistryError, "DOWNLOADED_EVIDENCE"):
            pe.validate_evidence(self.registry, self.document["evidence"])

    def test_batch_budget(self):
        plan = copy.deepcopy(self.document["plan"])
        plan["maximumTotalBytes"] = plan["items"][0]["maximumBytes"] - 1
        with self.assertRaisesRegex(cr.RegistryError, "BATCH_BUDGET"):
            lp.validate_plan(self.registry, plan)

    def test_plan_root_rejections(self):
        for changes in ({"schema": "future"}, {"revision": "C:/secret"}, {"extra": "unknown"},
                        {"maximumTotalBytes": True}, {"maximumTotalBytes": 0},
                        {"maximumTotalBytes": 4 * lp.GIB + 1}, {"reserveFreeBytes": True},
                        {"reserveFreeBytes": 2 * lp.GIB - 1}, {"reserveFreeBytes": 16 * lp.GIB + 1},
                        {"items": []}, {"items": self.document["plan"]["items"] * 5}):
            with self.subTest(changes=changes):
                plan = {**self.document["plan"], **changes}
                with self.assertRaises(cr.RegistryError):
                    lp.validate_plan(self.registry, plan)

    def test_plan_item_rejections(self):
        for changes in ({"recordId": "missing"}, {"maximumBytes": True}, {"maximumBytes": 0},
                        {"maximumBytes": 2 * lp.GIB + 1}, {"maximumSeconds": True},
                        {"maximumSeconds": 0}, {"maximumSeconds": 1801}, {"format": "MSI"},
                        {"preDownloadConsent": "ACCEPTED"}, {"route": "UNKNOWN"},
                        {"publicModel": "secret"}, {"extra": True}):
            with self.subTest(changes=changes):
                plan = copy.deepcopy(self.document["plan"])
                plan["items"][0].update(changes)
                with self.assertRaises(cr.RegistryError):
                    lp.validate_plan(self.registry, plan)

    def test_duplicate_record_rejected(self):
        plan = copy.deepcopy(self.document["plan"])
        plan["items"].append(copy.deepcopy(plan["items"][0]))
        with self.assertRaisesRegex(cr.RegistryError, "PLAN_RECORD"):
            lp.validate_plan(self.registry, plan)

    def test_asus_source_binding(self):
        plan = copy.deepcopy(self.document["plan"])
        plan["items"][0].update(route="ASUS_PUBLIC_CDN_SESSION", publicModel="Test Model")
        with self.assertRaisesRegex(cr.RegistryError, "ASUS_ROUTE_POLICY"):
            lp.validate_plan(self.registry, plan)

    def test_missing_link_rejected(self):
        self.registry["records"][0].update(downloadUrl=None, linkState="MISSING")
        # fixture内の配布根拠を壊さないため、元の台帳検証より先に欠落claimで拒否されてもよい。
        with self.assertRaises(cr.RegistryError):
            lp.validate_plan(self.registry, self.document["plan"])

    def test_wrong_plan_hash(self):
        self.document["planSha256"] = "0" * 64
        with self.assertRaisesRegex(cr.RegistryError, "PLAN_HASH_BINDING"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_wrong_registry_binding(self):
        self.document["evidence"]["registrySha256"] = "0" * 64
        with self.assertRaisesRegex(cr.RegistryError, "EVIDENCE_REGISTRY_BINDING"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_wrong_revision(self):
        self.document["evidence"]["revision"] = "other"
        with self.assertRaisesRegex(cr.RegistryError, "LARGE_EVIDENCE_BINDING"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_record_set_binding(self):
        self.document["evidence"]["acquisitions"][0]["recordId"] = "record-two"
        with self.assertRaises(cr.RegistryError):
            lp.validate_large_evidence(self.registry, self.document)

    def test_payload_exceeds_item(self):
        self.document["evidence"]["acquisitions"][0]["bytes"] = lp.GIB + 1
        with self.assertRaisesRegex(cr.RegistryError, "PLAN_PAYLOAD_BUDGET"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_larger_than_native_cannot_pass(self):
        row = self.document["evidence"]["acquisitions"][0]
        row.update(inspection="PASSED", inspectorSha256="b" * 64,
                   inspectionExitCode=0, verifiedInfs=1, inventoryFiles=3)
        with self.assertRaisesRegex(cr.RegistryError, "NATIVE_INPUT_UNSUPPORTED"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_smaller_zip_requires_native_observation(self):
        self.document["evidence"]["acquisitions"][0]["bytes"] = lp.NATIVE_INPUT_BYTES
        with self.assertRaisesRegex(cr.RegistryError, "NATIVE_INSPECTION_MISSING"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_smaller_zip_can_pass_but_not_legacy(self):
        row = self.document["evidence"]["acquisitions"][0]
        row.update(bytes=lp.NATIVE_INPUT_BYTES, inspection="PASSED", inspectorSha256="b" * 64,
                   inspectionExitCode=0, verifiedInfs=1, inventoryFiles=3)
        lp.validate_large_evidence(self.registry, self.document)
        with self.assertRaises(cr.RegistryError):
            pe.validate_evidence(self.registry, self.document["evidence"])

    def test_exe_outer_does_not_prove_inner(self):
        self.document["plan"]["items"][0]["format"] = "EXE"
        self.document["planSha256"] = cr.digest(cr.json_bytes(self.document["plan"]))
        self.document["evidence"]["acquisitions"][0].update(outerSignature="VALID", publisher="Fixture")
        lp.validate_large_evidence(self.registry, self.document)

    def test_zip_cannot_claim_authenticode(self):
        self.document["evidence"]["acquisitions"][0].update(outerSignature="VALID", publisher="Fixture")
        with self.assertRaisesRegex(cr.RegistryError, "ZIP_OUTER_SIGNATURE"):
            lp.validate_large_evidence(self.registry, self.document)

    def test_old_evidence_byte_contract(self):
        ordinary = evidence(self.registry)
        self.assertEqual(pe.validate_evidence(self.registry, ordinary), ordinary)


if __name__ == "__main__":
    unittest.main()
