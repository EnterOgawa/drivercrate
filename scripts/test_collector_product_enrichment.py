"""旧PAGE_ONLY製品の明示補完と取得証拠保持の非通信回帰試験。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公開情報とtemporary directoryのみを使用する（ADR 0234）。
"""
import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_payload_evidence as pe
from test_collector_registry import fixture
from test_collector_payload_evidence import evidence


def product_fixture(query=False):
    """旧未確定製品へ新しい公式取得元・配布根拠を付ける架空の世代を返す。"""
    old = fixture()
    if query:
        old["schema"] = cr.QUERY_REGISTRY_SCHEMA
    held = {**copy.deepcopy(old["products"][0]), "id": "product-two", "model": "Device Two",
            "recordIds": [], "researchState": "PAGE_ONLY", "reason": "DOWNLOAD_TABLE_UNAVAILABLE"}
    old["products"].append(held)
    old["observations"].append({**old["observations"][0], "id": "page-two-old",
                                "productId": "product-two", "recordId": None, "kind": "OFFICIAL_PAGE"})
    observed = evidence(old)
    new = copy.deepcopy(old)
    new.update(revision="test-02", asOf="2026-10-03T02:00:00Z")
    source = {**new["sources"][0], "id": "source-two", "officialPage":
              "https://vendor.example.org/download/?id=12" if query else "https://vendor.example.org/other"}
    new["sources"].append(source)
    record = {**new["records"][0], "id": "record-two", "sourceId": "source-two",
              "downloadUrl": "https://cdn.example.org/other.zip", "linkState": "OFFICIAL_LINK"}
    new["records"].append(record)
    new["products"][1].update(sourceIds=["source-one", "source-two"], recordIds=["record-two"],
                               researchState="METADATA_SAVED", reason="NONE")
    new["observations"].append({**new["observations"][0], "id": "fresh-link",
                                "productId": "product-two", "recordId": "record-two",
                                "checkedAt": new["asOf"], "evidenceUrl": source["officialPage"],
                                "httpStatus": 200})
    return old, observed, new


class ProductEnrichmentTests(unittest.TestCase):
    """製品補完の独立した承認・新しい根拠・旧取得との非混同を検査する。"""

    def test_default_and_link_option_do_not_allow_product_changes(self):
        """既定とURL補完の承認だけでは製品参照を変更できない。"""
        old, observed, new = product_fixture()
        for options in ({}, {"allow_link_enrichment": True}):
            with self.subTest(options=options), self.assertRaises(cr.RegistryError):
                pe.carry_forward(old, observed, new, **options)

    def test_explicit_mode_preserves_acquisitions_and_origin_on_repeat(self):
        """限定補完は旧観測日時・結果・record hashを変えず次世代にも保持する。"""
        old, observed, new = product_fixture()
        carried = pe.carry_forward(old, observed, new, allow_product_enrichment=True)
        acquisition = dict(carried["acquisitions"][0])
        acquisition.pop("recordSha256")
        self.assertEqual(acquisition, observed["acquisitions"][0])
        self.assertEqual(carried["originRegistry"]["revision"], old["revision"])
        counts = pe.evidence_counts(new, carried)
        self.assertEqual(counts["productsWithMetadata"], 2)
        self.assertEqual(counts["recordsWithHead200"], 1)
        self.assertEqual(counts["payloadsDownloaded"], 1)
        self.assertEqual(counts["productsWithDownloadedPayloads"], 1)
        newest = {**new, "revision": "test-03", "asOf": "2026-10-03T03:00:00Z"}
        repeated = pe.carry_forward(new, carried, newest)
        self.assertEqual(repeated["acquisitions"], carried["acquisitions"])
        self.assertEqual(repeated["originRegistry"], carried["originRegistry"])

    def test_product_identity_and_old_source_references_are_immutable(self):
        """名称の変更・旧参照の削除は補完として受理しない。"""
        for changes in ({"model": "Renamed"}, {"id": "renamed-product"},
                        {"sourceIds": ["source-two"]}):
            old, observed, new = product_fixture()
            new["products"][1].update(changes)
            with self.subTest(changes=changes), self.assertRaises(cr.RegistryError):
                pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_failure_states_and_legacy_reasons_are_not_resolved(self):
        """HTTP失敗・legacy失敗を配布表未解析と同じ補完対象にしない。"""
        for state, reason in (("PAGE_ONLY", "HTTP_403"), ("RESEARCH_REQUIRED", "DOWNLOAD_TABLE_UNAVAILABLE"),
                              ("PAGE_ONLY", "LEGACY_PARSE_EMPTY"), ("PAGE_ONLY", "LEGACY_REDIRECT_REJECTED")):
            old, observed, new = product_fixture()
            old["products"][1].update(researchState=state, reason=reason)
            observed = evidence(old)
            with self.subTest(reason=reason, state=state), self.assertRaisesRegex(
                    cr.RegistryError, "PRODUCT_ENRICHMENT_SCOPE"):
                pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_existing_metadata_product_cannot_change(self):
        """既存のmetadata製品へ別recordを付ける権限は付与しない。"""
        old, observed, new = product_fixture()
        new["products"][0]["sourceIds"].append("source-two")
        new["products"][0]["recordIds"].append("record-two")
        with self.assertRaisesRegex(cr.RegistryError, "PRODUCT_ENRICHMENT_SCOPE"):
            pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_old_source_record_observation_changes_and_removal_rejected(self):
        """補完modeでも旧取得元・配布・観測を不変とする。"""
        for collection, key, value in (("sources", "officialPage", "https://vendor.example.org/changed"),
                                       ("records", "packageVersion", "2.0"),
                                       ("observations", "httpStatus", 200)):
            old, observed, new = product_fixture()
            new[collection][0][key] = value
            with self.subTest(collection=collection), self.assertRaises(cr.RegistryError):
                pe.carry_forward(old, observed, new, allow_product_enrichment=True)
        old, observed, new = product_fixture()
        del new["observations"][2]
        with self.assertRaises(cr.RegistryError):
            pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_each_added_record_requires_its_own_fresh_source_page_proof(self):
        """別recordや別取得元の根拠だけでは製品へ配布を追加しない。"""
        old, observed, new = product_fixture()
        new["records"].append({**new["records"][1], "id": "record-three"})
        new["products"][1]["recordIds"].append("record-three")
        with self.assertRaisesRegex(cr.RegistryError, "UNOBSERVED_RECORD"):
            pe.carry_forward(old, observed, new, allow_product_enrichment=True)
        new["observations"].append({**new["observations"][-1], "id": "fresh-three", "recordId": "record-three"})
        pe.carry_forward(old, observed, new, allow_product_enrichment=True)
        new["observations"][-1]["evidenceUrl"] = old["sources"][0]["officialPage"]
        with self.assertRaisesRegex(cr.RegistryError, "PRODUCT_ENRICHMENT_RECORD_EVIDENCE"):
            pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_new_source_reference_requires_product_bound_proof(self):
        """recordに使わない新取得元も同じ製品の新規観測で確認する。"""
        old, observed, new = product_fixture()
        source = {**new["sources"][0], "id": "source-three", "officialPage": "https://vendor.example.org/models"}
        new["sources"].append(source)
        new["products"][1]["sourceIds"].append(source["id"])
        with self.assertRaisesRegex(cr.RegistryError, "PRODUCT_ENRICHMENT_SOURCE_EVIDENCE"):
            pe.carry_forward(old, observed, new, allow_product_enrichment=True)
        new["observations"].append({**new["observations"][-1], "id": "fresh-model", "kind": "OFFICIAL_PAGE",
                                    "recordId": None, "evidenceUrl": source["officialPage"]})
        pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_old_and_future_observation_dates_do_not_authorize_enrichment(self):
        """新しいIDだけでは足りず、旧asOfから新asOfの範囲を要求する。"""
        for stamp in ("2026-10-02T23:59:59Z", "2026-10-03T02:00:01Z"):
            old, observed, new = product_fixture()
            new["observations"][-1]["checkedAt"] = stamp
            with self.subTest(stamp=stamp), self.assertRaises(cr.RegistryError):
                pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_http_failures_and_legacy_methods_cannot_authorize_enrichment(self):
        """失敗応答とlegacy投影を新しい公式page確認に数えない。"""
        for changes in ({"httpStatus": 403}, {"httpStatus": 302}, {"method": "LEGACY_PROJECTION"}):
            old, observed, new = product_fixture()
            new["observations"][-1].update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    cr.RegistryError, "PRODUCT_ENRICHMENT_RECORD_EVIDENCE"):
                pe.carry_forward(old, observed, new, allow_product_enrichment=True)

    def test_mode_requires_exact_boolean(self):
        """整数や文字列を承認のboolとして扱わない。"""
        old, observed, new = product_fixture()
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaisesRegex(cr.RegistryError, "PRODUCT_ENRICHMENT_MODE"):
                pe.carry_forward(old, observed, new, allow_product_enrichment=value)

    def test_product_option_does_not_authorize_old_missing_record_link_changes(self):
        """URL補完の承認は独立とし、両方必要なら両方を明示する。"""
        old, observed, new = product_fixture()
        missing = {**old["records"][0], "id": "missing-record", "downloadUrl": None, "linkState": "MISSING"}
        old["records"].append(missing)
        old["products"][0]["recordIds"].append(missing["id"])
        old["observations"].append({**old["observations"][0], "id": "missing-page", "kind": "OFFICIAL_PAGE",
                                    "recordId": missing["id"]})
        observed = evidence(old)
        new["products"][0] = copy.deepcopy(old["products"][0])
        new["records"].append({**missing, "downloadUrl": "https://cdn.example.org/missing.zip",
                                "linkState": "OFFICIAL_LINK"})
        new["observations"].append(copy.deepcopy(old["observations"][-1]))
        new["observations"].append({**new["observations"][0], "id": "fresh-missing-link",
                                    "recordId": missing["id"], "checkedAt": new["asOf"]})
        with self.assertRaisesRegex(cr.RegistryError, "CARRY_FORWARD_NOT_APPEND_ONLY"):
            pe.carry_forward(old, observed, new, allow_product_enrichment=True)
        pe.carry_forward(old, observed, new, allow_product_enrichment=True, allow_link_enrichment=True)

    def test_snapshot_copy_and_cli_preserve_flags_for_both_schemas(self):
        """CLI承認・新旧snapshot・copy再読込みと導入不可flagを非通信で試す。"""
        for query in (False, True):
            old, observed, new = product_fixture(query)
            with self.subTest(query=query), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                pe.write_bundle(old, observed, base / "old")
                (base / "registry.json").write_bytes(cr.json_bytes(new))
                args = ["collector_payload_evidence.py", "carry-forward", str(base / "old"),
                        str(base / "registry.json"), str(base / "new"), "--allow-product-enrichment"]
                with patch("sys.argv", args), patch("builtins.print"):
                    self.assertEqual(pe.main(), 0)
                shutil.copytree(base / "new", base / "copy")
                registry, carried = pe.verify_bundle(base / "copy")
                self.assertEqual(registry, cr.validate_registry(new))
                self.assertEqual(carried["acquisitions"][0]["checkedAt"], observed["acquisitions"][0]["checkedAt"])
                index = cr.read_json(base / "copy" / "index/drivers.json")
                self.assertTrue(index["researchOnly"])
                self.assertFalse(index["publishable"])
                self.assertFalse(index["installAuthorized"])
                self.assertEqual(index["applicability"], "NOT_CHECKED")


if __name__ == "__main__":
    unittest.main()
