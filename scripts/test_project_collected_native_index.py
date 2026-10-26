"""実収集投影契約の人工正負を決定的に検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
人工入力を実収集／driver候補へ数えない。
"""
import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock

import project_collected_native_index as projection


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 13, 13, tzinfo=timezone.utc)
        self.scope = {"schema": "dc-fixed-collector-native-index-scope-v1", "targetCount": 1,
                      "source": projection.SOURCE, "distributionPage": projection.PAGE,
                      "sourceId": "intel-ethernet-win11", "recordId": "intel-wired-31-2-2-win11",
                      "collectorManifestSha256": "1"*64, "keyId": "artificial-public-key"}
        self.body = b"\n<html>Artificial collected metadata\r\n</html>"
        self.evidence = {"schema": "dc-collector-evidence-v1", "manifestSha256": "1"*64,
                         "contractSha256": "2"*64, "source": projection.SOURCE, "httpStatus": 200,
                         "lastSuccessfulValidationAt": int(self.now.timestamp())-30,
                         "bodySha256": hashlib.sha256(self.body).hexdigest(),
                         "bodyBytesBase64": base64.b64encode(self.body).decode("ascii"),
                         "records": [{"fingerprint": "3"*64, "displayTitle": "Artificial metadata",
                                      "driverCategory": "Ethernet", "operatingSystem": "Windows 11",
                                      "packageVersion": "1.2.3", "publishedDate": "2026-10-12"}]}

    def test_exact_observation_and_unknown_boundaries(self):
        raw, packed, manifest, report = projection.project(self.scope, self.evidence, 1, self.now)
        self.assertEqual(gzip.decompress(packed), raw)
        index = json.loads(raw)
        record = json.loads(base64.b64decode(index["records"][0]["recordBytesBase64"]))
        self.assertEqual(record["version"]["value"], "1.2.3")
        self.assertEqual(record["publishedIdentityEvidence"]["state"], "UNKNOWN")
        self.assertEqual(record["acquisitionDescriptor"]["state"], "UNKNOWN")
        self.assertIsNone(record["acquisitionDescriptor"]["attestation"])
        self.assertEqual(report["realContentInspected"], 0)
        self.assertTrue(manifest.startswith(b"\n{"))
        self.assertEqual(json.loads(manifest)["asset"]["sha256"], hashlib.sha256(packed).hexdigest())

    def test_fixed_denominator_rejections(self):
        for field, value in (("source", "OTHER"), ("targetCount", 0), ("distributionPage", "https://vendor.example/")):
            scope = deepcopy(self.scope)
            scope[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                projection.project(scope, self.evidence, 1, self.now)

    def test_failed_revalidation_unknown_and_corruption_rejected(self):
        for field, value in (("httpStatus", 304), ("httpStatus", True), ("manifestSha256", "0"*64),
                             ("bodySha256", "0"*64), ("bodyBytesBase64", "?"), ("records", []),
                             ("lastSuccessfulValidationAt", self.now.timestamp()+1),
                             ("lastSuccessfulValidationAt", True)):
            evidence = deepcopy(self.evidence)
            evidence[field] = value
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, TypeError)):
                projection.project(self.scope, evidence, 1, self.now)

    def test_same_observation_new_asset_generation(self):
        first = projection.project(self.scope, self.evidence, 1, self.now)
        second = projection.project(self.scope, self.evidence, 2, self.now)
        self.assertEqual(first[3]["recordSha256"], second[3]["recordSha256"])
        self.assertEqual(first[3]["observationUtc"], second[3]["observationUtc"])
        self.assertNotEqual(first[3]["assetSha256"], second[3]["assetSha256"])

    def test_exact_native_intel_projection(self):
        # 人工値でnativeの固定tupleを再現し、実収集成功数へ加算しない。
        evidence = deepcopy(self.evidence)
        evidence["records"][0].update(displayTitle="Intel Ethernet Network Adapters",
                                      driverCategory="", operatingSystem="Microsoft Windows 11",
                                      publishedDate="")
        raw, _, _, _ = projection.project(self.scope, evidence, 1, self.now)
        record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
        self.assertEqual(record["targetOs"]["value"], "WINDOWS_11")
        self.assertEqual(record["architecture"]["value"], "X64")
        self.assertEqual(record["publishedDate"]["state"], "UNKNOWN")
        self.assertEqual(record["publishedIdentityEvidence"]["state"], "UNKNOWN")
        self.assertEqual(record["acquisitionDescriptor"]["state"], "UNKNOWN")
        self.assertIsNone(record["acquisitionDescriptor"]["attestation"])

    def test_native_tuple_and_source_changes_rejected(self):
        for field, value in (("operatingSystem", "Microsoft Windows 10"),
                             ("operatingSystem", "Windows 11"),
                             ("displayTitle", "Intel Ethernet Network Adapters Firmware"),
                             ("displayTitle", "Other Network Adapters"),
                             ("driverCategory", "Firmware"),
                             ("driverCategory", "Ethernet"),
                             ("kind", "FIRMWARE"), ("architecture", "X86")):
            evidence = deepcopy(self.evidence)
            evidence["records"][0].update(displayTitle="Intel Ethernet Network Adapters",
                                          driverCategory="", operatingSystem="Microsoft Windows 11")
            evidence["records"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                projection.project(self.scope, evidence, 1, self.now)
        evidence = deepcopy(self.evidence)
        evidence["source"] = "OTHER"
        with self.assertRaises(ValueError):
            projection.project(self.scope, evidence, 1, self.now)

    def daily_receipt(self, status=200, generation=4):
        """各caseのevidenceを複写し、元投影byteとhashを持つ人工日次receiptを作る。

        200は新規取得側、その他のstatusは再検証側の時刻形を作るだけで、
        status・世代・前hashの受理は呼出先の検査へ任せる。
        """
        receipt = deepcopy(self.evidence)
        validated = receipt["lastSuccessfulValidationAt"]
        receipt.update(schema="dc-collector-daily-receipt-v1",
                       outcome="NEW_200" if status == 200 else "REVALIDATED_304",
                       generation=generation, previousReceiptSha256="" if generation == 4 else "9"*64,
                       day="20261013", httpStatus=status,
                       lastFetchedAt=validated if status == 200 else validated-86400,
                       lastAttemptAt=validated-1, notBefore=validated+86400,
                       requestBindingSha256="4"*64, error=0, stateError=0)
        raw = projection.bytes_json({field: receipt[field] for field in
                                     ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")})
        receipt.update(projectionBytesBase64=base64.b64encode(raw).decode("ascii"),
                       projectionSha256=hashlib.sha256(raw).hexdigest())
        return receipt

    def test_daily_200_304_preserve_fetch_and_unknown_acquisition(self):
        for status in (200, 304):
            receipt = self.daily_receipt(status)
            raw, _, manifest, report = projection.project_daily(self.scope, receipt, self.now)
            record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
            self.assertEqual(report["httpStatus"], status)
            self.assertEqual(report["originalFetchedAt"], receipt["lastFetchedAt"])
            self.assertEqual(report["newHttp200Count"], int(status == 200))
            self.assertEqual(report["revalidatedHttp304Count"], int(status == 304))
            self.assertEqual(record["inspectionStage"], "METADATA_ONLY")
            self.assertIsNone(record["acquisitionDescriptor"]["attestation"])
            self.assertEqual(record["acquisitionDescriptor"]["state"], "UNKNOWN")
            self.assertEqual(json.loads(manifest)["generation"], 4)
            self.assertEqual(json.loads(manifest)["expiresAtUtc"], "2026-10-14T12:59:30Z")

    def test_daily_hold_cache_missing_tampered_and_forged_times_rejected(self):
        changes = (("outcome", "HOLD"), ("outcome", "NO_NETWORK"), ("httpStatus", 0),
                   ("httpStatus", True), ("error", True), ("stateError", 13),
                   ("bodyBytesBase64", ""), ("bodySha256", "0"*64),
                   ("projectionBytesBase64", "AA=="), ("projectionSha256", "0"*64),
                   ("lastFetchedAt", True), ("lastFetchedAt", self.now.timestamp()+1),
                   ("lastAttemptAt", self.now.timestamp()+1), ("notBefore", 1),
                   ("requestBindingSha256", "0"*64), ("records", []))
        for field, value in changes:
            receipt = self.daily_receipt(304)
            receipt[field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, TypeError)):
                projection.project_daily(self.scope, receipt, self.now)
        receipt = self.daily_receipt(304)
        receipt.pop("bodyBytesBase64")
        with self.assertRaises(ValueError):
            projection.project_daily(self.scope, receipt, self.now)
        with self.assertRaises(ValueError):
            projection.project_daily(self.scope, self.daily_receipt(304),
                                      datetime(2026, 10, 14, 13, tzinfo=timezone.utc))

    def test_daily_generation_separate_from_acceptance_limits(self):
        for generation in (4, 9, 1000, 9007199254740991):
            result = projection.project_daily(self.scope, self.daily_receipt(304, generation), self.now)
            self.assertEqual(json.loads(result[2])["generation"], generation)
        for generation in (0, 3, True, 4.5, 9007199254740992):
            with self.subTest(generation=generation), self.assertRaises(ValueError):
                projection.project_daily(self.scope, self.daily_receipt(304, generation), self.now)
        receipt = self.daily_receipt(304, 5)
        receipt["previousReceiptSha256"] = ""
        with self.assertRaises(ValueError):
            projection.project_daily(self.scope, receipt, self.now)
        with self.assertRaises(ValueError):
            projection.project(self.scope, self.evidence, 4, self.now)

    def test_daily_projection_hash_does_not_replace_binding(self):
        receipt = self.daily_receipt(304)
        changed = {field: receipt[field] for field in
                   ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")}
        changed["lastFetchedAt"] -= 1
        raw = projection.bytes_json(changed)
        receipt.update(projectionSha256=hashlib.sha256(raw).hexdigest(),
                       projectionBytesBase64=base64.b64encode(raw).decode("ascii"))
        with self.assertRaises(ValueError):
            projection.project_daily(self.scope, receipt, self.now)


class DistributionProjectionTests(unittest.TestCase):
    """P1-01〜07の人工束だけを検査し、通信/native childをdenyする。"""

    def setUp(self):
        """外部開始境界を先に拒否し、実観測ではない完全人工入力を作る。"""
        targets = ["socket.socket", "socket.create_connection", "socket.getaddrinfo",
                   "subprocess.Popen", "os.system", "os.startfile"]
        targets += ["os."+name for name in dir(os) if name.startswith(("spawn", "exec"))]
        for target in targets:
            patcher = mock.patch(target, side_effect=AssertionError("EXTERNAL_ACTION_DENIED"))
            patcher.start()
            self.addCleanup(patcher.stop)
        ProjectionTests.setUp(self)
        self.legacy_scope = deepcopy(self.scope)
        self.scope.update(schema="dc-fixed-distribution-acquisition-scope-v1",
                          keyId=projection.DISTRIBUTION_KEY_ID,
                          publicFingerprint=projection.DISTRIBUTION_PUBLIC_FINGERPRINT,
                          projectionPolicyRevision=projection.DISTRIBUTION_PROJECTION_POLICY_REVISION)
        payload = "https://downloadmirror.intel.com/923981/Wired_driver_31.2.2_x64.zip"
        terms = "Artificial complete terms; no real consent or official observation."
        self.body = (f'<button data-modal-id="1" data-href="{payload}" class="available-download-button__cta"></button>'
                     '<div id="licenseModal" class="license-modal__dialog">'
                     f'<textarea id="content-raw" class="license-modal-content_body_license-text-raw">{terms}</textarea></div>'
                     '<div class="license-modal-big-bag-container"></div>'
                     '<button class="license-modal-content-license__btn--btn-accept"></button>'
                     '<a class="license-modal-content-footer-download__restart-link"></a>').encode("utf-8")
        self.evidence.update(bodySha256=hashlib.sha256(self.body).hexdigest(),
                             bodyBytesBase64=base64.b64encode(self.body).decode("ascii"))
        self.evidence["records"][0]["packageVersion"] = "31.2.2"
        observed = self.evidence["lastSuccessfulValidationAt"]
        terms_hash = hashlib.sha256(terms.encode("utf-8")).hexdigest()
        self.release = {"schema": "dc-saved-release-analysis-v1", "source": projection.SOURCE,
                        "bodySha256": self.evidence["bodySha256"], "bodyBytes": len(self.body),
                        "observedUtcSeconds": str(observed), "distributionPage": projection.PAGE,
                        "freshNetworkEvidence": False, "acquisitionAuthority": False,
                        "termsDocumentState": "HTML_EXTRACTED_BINDING_UNCONFIRMED", "payloadUrl": payload,
                        "fileName": "Wired_driver_31.2.2_x64.zip", "packageVersion": "31.2.2",
                        "publishedSha256": "2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5",
                        "termsText": terms, "termsTextUtf8Bytes": len(terms.encode("utf-8")),
                        "termsTextSha256": terms_hash, "termsRevision": "artificial-revision-1",
                        "htmlExtraction": {"profile": "TEXTAREA_HTML_DOCUMENT_V1",
                            "selector": {"tagName": "textarea", "attributeName": "id", "attributeValue": "content-raw"},
                            "containerSelector": {"tagName": "div", "attributeName": "id", "attributeValue": "licenseModal"},
                            "documentUrl": projection.PAGE, "documentSha256": self.evidence["bodySha256"],
                            "documentSizeBytes": len(self.body), "textSha256": terms_hash,
                            "textSizeBytes": len(terms.encode("utf-8"))}}
        roles = ("DOWNLOAD_CLASS_HANDLER", "DATASET_PAYLOAD_TO_BOUND_LINK", "NONEMPTY_RAW_TO_DIALOG",
                 "RAW_DOCUMENT_PRESENTATION", "EXACT_CONTAINER_ACCEPT", "ACCEPT_BOUND_LINK")
        raw_script = ("// ARTIFICIAL NONEXECUTED WITNESSES\n" + "\n".join(roles)).encode("utf-8")
        script_hash = hashlib.sha256(raw_script).hexdigest()
        script_url = "https://www.intel.com/artificial-terms-binding.js"
        self.review = {"schema": "dc-static-terms-binding-review-v1",
                       "reviewMethod": "MANUAL_NONEXECUTED_STATIC_LINK_REVIEW", "source": projection.SOURCE,
                       "pageSha256": self.evidence["bodySha256"], "payloadUrl": payload,
                       "termsRevision": self.release["termsRevision"], "numericModalMappingClaimed": False,
                       "scriptSha256": script_hash, "scriptUrl": script_url,
                       "checkedAtUtcSeconds": observed+20,
                       "scriptWitnesses": [{"role": role, "literal": role} for role in roles]}
        self.script = {"schema": "dc-collected-terms-script-v1", "source": projection.SOURCE,
                       "pageUrl": projection.PAGE, "pageSha256": self.evidence["bodySha256"],
                       "pageObservedUtcSeconds": str(observed), "httpStatus": 200, "scriptExecuted": False,
                       "scriptFreshNetworkEvidence": True, "pageFreshNetworkEvidence": False, "payloadGet": 0,
                       "scriptBytesBase64": base64.b64encode(raw_script).decode("ascii"),
                       "scriptSizeBytes": len(raw_script), "scriptSha256": script_hash, "scriptUrl": script_url,
                       "scriptObservedUtcSeconds": str(observed+10)}
        model = {"modelSection": "Intel.NTamd64.10.0.1..22000",
                 "pnpIds": [{"kind": "HARDWARE", "value": r"PCI\VEN_8086&DEV_0001"}]}
        inf = {"state": 2, "contentError": 0, "identityError": 0, "publishedIdentityKnown": True,
               "infIdentity": "PRO2500/Winx64/W11/e2fn.inf",
               "infSha256": "a93fa3c2b8725aed2081e0d239766474fac205f75ddbe16849502af6acba2417",
               "driverVersion": "2.1.5.7", "driverDate": "09/15/2026", "verifiedPublisher": "Artificial Intel signer",
               "classGuid": "{4d36e972-e325-11ce-bfc1-08002be10318}",
               "models": [model, {"modelSection": "UNPROJECTED_ARTIFICIAL_SECTION", "pnpIds": []}]}
        self.inspection = {"schema": "dc-inspected-public-identities-v2",
                           "archiveSha256": self.release["publishedSha256"], "archiveBytes": 40477087,
                           "inspectionError": 0, "officialAuthority": False, "actualApplicabilityChecked": False,
                           "selectedOnly": True, "selectedInf": "PRO2500\\Winx64\\W11\\e2fn.inf",
                           "verifiedIdentityInfs": 1, "infs": [inf], "contentCheckedUtcSeconds": str(observed+15)}

    def project(self, **changes):
        """変更指定以外は同じ人工束を純粋入口へ渡す。"""
        args = dict(scope=self.scope, evidence=self.evidence, release=self.release, inspection=self.inspection,
                    review=self.review, script=self.script, generation=9, now=self.now)
        args.update(changes)
        return projection.project_distribution_acquisition(**args)

    def test_p1_01_complete_unsigned_projection_and_deny_guard(self):
        """完全人工束の原byte/hash/qualityと非権限出力、外部開始拒否を確認する。"""
        before = deepcopy((self.scope, self.evidence, self.release, self.inspection, self.review, self.script))
        with self.subTest(case="P1-01-positive"):
            raw, packed, manifest_raw, report = self.project()
            index, manifest = json.loads(raw), json.loads(manifest_raw)
            entry = index["records"][0]
            record_raw = base64.b64decode(entry["recordBytesBase64"])
            record = json.loads(record_raw)
            self.assertEqual(gzip.decompress(packed), raw)
            self.assertEqual(entry["recordSha256"], hashlib.sha256(record_raw).hexdigest())
            self.assertEqual(manifest["asset"]["sha256"], hashlib.sha256(packed).hexdigest())
            self.assertEqual(manifest["asset"]["sizeBytes"], len(packed))
            self.assertEqual(manifest["quality"], dict(sourceCount=1, recordCount=1, metadataOnlyCount=0,
                                                      contentInspectedCount=1, unconfirmedCount=0))
            self.assertEqual(record["acquisitionDescriptor"]["state"], "KNOWN")
            self.assertEqual(manifest["keyId"], projection.DISTRIBUTION_KEY_ID)
            self.assertNotIn("signatureBase64", manifest)
            self.assertTrue(report["unsigned"])
            self.assertFalse(report["authorityIssued"])
            self.assertEqual(before, (self.scope, self.evidence, self.release, self.inspection, self.review, self.script))
        for case, call in (("P1-01-deny-native", lambda: subprocess.Popen(["must-not-start"])),
                           ("P1-01-deny-network", lambda: socket.create_connection(("127.0.0.1", 1)))):
            with self.subTest(case=case), self.assertRaisesRegex(AssertionError, "EXTERNAL_ACTION_DENIED"):
                call()

    def test_p1_02_generation_and_legacy_boundaries(self):
        """新世代のexact int境界と旧用途の世代/原期限を維持する。"""
        for generation in (1, 3, 4, 8, 9, 1000, 9007199254740991):
            with self.subTest(case="P1-02-generation", value=generation):
                self.assertEqual(json.loads(self.project(generation=generation)[2])["generation"], generation)
        for generation in (0, -1, True, False, 1.0, 4.5, "9", None, 9007199254740992):
            with self.subTest(case="P1-02-reject", value=generation), self.assertRaises(ValueError):
                self.project(generation=generation)
        for generation in (4, 8):
            with self.subTest(case="P1-02-legacy-acquisition", value=generation):
                result = projection.project_acquisition(self.legacy_scope, self.evidence, self.release,
                    self.inspection, self.review, self.script, generation, self.now)
                self.assertEqual(json.loads(result[2])["expiresAtUtc"], "2026-10-14T12:59:30Z")
        for generation in (3, 9):
            with self.subTest(case="P1-02-legacy-reject", value=generation), self.assertRaises(ValueError):
                projection.project_acquisition(self.legacy_scope, self.evidence, self.release,
                    self.inspection, self.review, self.script, generation, self.now)
        with self.subTest(case="P1-02-metadata-expiry"):
            self.assertEqual(json.loads(projection.project(self.legacy_scope, self.evidence, 1, self.now)[2])[
                "expiresAtUtc"], "2026-10-14T13:00:00Z")

    def test_p1_03_scope_and_explicit_cli(self):
        """全scope field/型/固定pinとCLI用途・入力集合を正負で確認する。"""
        changes = [(key, None) for key in self.scope]
        changes += [("schema", "dc-fixed-collector-native-index-scope-v1"), ("targetCount", True),
                    ("targetCount", 1.0), ("projectionPolicyRevision", True), ("projectionPolicyRevision", 1),
                    ("source", "OTHER"), ("sourceId", "other"), ("recordId", "other"),
                    ("distributionPage", "https://invalid.example/"), ("collectorManifestSha256", "F"*64),
                    ("publicFingerprint", "0"*64), ("keyId", "local-index-artificial"),
                    ("keyId", projection.DISTRIBUTION_KEY_ID+"-other")]
        for field, value in changes:
            changed = deepcopy(self.scope)
            changed[field] = value
            with self.subTest(case="P1-03-scope", field=field, value=value), self.assertRaises(ValueError):
                self.project(scope=changed)
        for field in self.scope:
            changed = deepcopy(self.scope)
            changed.pop(field)
            with self.subTest(case="P1-03-missing", field=field), self.assertRaises(ValueError):
                self.project(scope=changed)
        for changed in ({**self.scope, "unrecognized": 1}, self.legacy_scope, [], None):
            with self.subTest(case="P1-03-extra-type"), self.assertRaises(ValueError):
                self.project(scope=changed)
        base = ["projection", "--scope", "scope", "--evidence", "evidence", "--output-prefix", "out"]
        acq = ["--parsed-release", "release", "--inspected-package", "inspection",
               "--terms-review", "review", "--terms-script", "script"]
        supplied = dict(scope=self.scope, evidence=self.evidence, release=self.release, inspection=self.inspection,
                        review=self.review, script=self.script)
        saved = {}
        expected_raw = self.project()[0]
        @contextmanager
        def output(path, mode):
            """CLI出力をRAMだけへ保存し、実fileや外部処理へ到達させない。"""
            self.assertEqual(mode, "xb")
            with io.BytesIO() as stream:
                yield stream
                saved[str(path)] = stream.getvalue()
        fixed_now = self.now
        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                """外部時計を読まず、同じ人工UTCを指定timezoneで返す。"""
                return cls.fromtimestamp(fixed_now.timestamp(), tz)
        with mock.patch.object(projection, "raw_json", side_effect=lambda path, _: deepcopy(supplied[str(path)])), \
             mock.patch.object(Path, "open", autospec=True, side_effect=output), \
             mock.patch.object(Path, "exists", return_value=False), \
             mock.patch.object(projection, "datetime", FixedDateTime), redirect_stdout(io.StringIO()):
            with self.subTest(case="P1-03-cli-positive"), mock.patch.object(sys, "argv", base+[
                    "--distribution-acquisition", "--generation", "9"]+acq):
                self.assertEqual(projection.main(), 0)
                self.assertEqual(saved["out.index.json"], expected_raw)
                self.assertEqual(len(saved), 4)
            variants = [("P1-03-cli-daily", ["--daily", "--distribution-acquisition"]+acq, SystemExit)]
            variants += [("P1-03-cli-missing-generation", ["--distribution-acquisition"]+acq, ValueError)]
            variants += [(f"P1-03-cli-missing-input-{i}", ["--distribution-acquisition", "--generation", "9"]+
                          acq[:2*i]+acq[2*i+2:], ValueError) for i in range(4)]
            for case, args, error in variants:
                with self.subTest(case=case), mock.patch.object(sys, "argv", base+args), \
                     redirect_stderr(io.StringIO()), self.assertRaises(error):
                    projection.main()

    def test_p1_04_provenance_tamper(self):
        """原page/package/INF/terms/scriptの有限な独立改変を拒否する。"""
        cases = [("evidence", ("manifestSha256",), "0"*64), ("evidence", ("bodySha256",), "0"*64),
                 ("release", ("bodySha256",), "0"*64), ("release", ("bodyBytes",), 1),
                 ("release", ("observedUtcSeconds",), "1"), ("release", ("payloadUrl",), "https://invalid.example/a.zip"),
                 ("release", ("publishedSha256",), "0"*64), ("release", ("termsTextSha256",), "0"*64),
                 ("release", ("termsText",), "changed"), ("script", ("scriptSha256",), "0"*64),
                 ("script", ("scriptBytesBase64",), "AA=="), ("script", ("scriptUrl",), "https://invalid.example/a.js"),
                 ("review", ("pageSha256",), "0"*64), ("review", ("scriptWitnesses", 0, "literal"), "absent"),
                 ("inspection", ("archiveSha256",), "0"*64), ("inspection", ("archiveBytes",), 1),
                 ("inspection", ("infs", 0, "infSha256"), "0"*64),
                 ("inspection", ("infs", 0, "infIdentity"), "different.inf"),
                 ("inspection", ("infs", 0, "models", 0, "modelSection"), "different"),
                 ("inspection", ("infs", 0, "models", 0, "pnpIds", 0, "kind"), "UNKNOWN"),
                 ("inspection", ("infs", 0, "verifiedPublisher"), "")]
        for target, path, value in cases:
            changed = deepcopy(getattr(self, target))
            node = changed
            for field in path[:-1]:
                node = node[field]
            node[path[-1]] = value
            with self.subTest(case="P1-04", target=target, path=path), self.assertRaises(ValueError):
                self.project(**{target: changed})

    def test_p1_05_time_missing_and_uninspected(self):
        """時刻/欠測/内容未検査を成功や延長済み観測へしない。"""
        for label, value in (("expired", self.now+timedelta(days=1)),
                             ("before-observation", self.now-timedelta(minutes=1)),
                             ("naive", self.now.replace(tzinfo=None)),
                             ("subsecond", self.now.replace(microsecond=1))):
            with self.subTest(case="P1-05-now", variant=label), self.assertRaises(ValueError):
                self.project(now=value)
        for target, field, value in (("inspection", "inspectionError", 1),
                                     ("inspection", "contentCheckedUtcSeconds", "1"),
                                     ("review", "checkedAtUtcSeconds", int(self.now.timestamp())+1),
                                     ("script", "scriptExecuted", True),
                                     ("evidence", "lastSuccessfulValidationAt", self.now.timestamp()+1)):
            changed = deepcopy(getattr(self, target))
            changed[field] = value
            with self.subTest(case="P1-05-evidence", target=target, field=field), self.assertRaises(ValueError):
                self.project(**{target: changed})
        for field, value in (("publishedIdentityKnown", False), ("state", 0), ("contentError", 1),
                             ("identityError", 1), ("models", [])):
            changed = deepcopy(self.inspection)
            changed["infs"][0][field] = value
            with self.subTest(case="P1-05-inf", field=field), self.assertRaises(ValueError):
                self.project(inspection=changed)
        for name in ("release", "inspection", "review", "script"):
            with self.subTest(case="P1-05-missing", name=name), self.assertRaises((ValueError, KeyError)):
                self.project(**{name: {}})

    def test_p1_06_package_version_and_public_identity(self):
        """package版/INF版と実端末ではない公開INF由来IDを分離する。"""
        with self.subTest(case="P1-06-positive"):
            raw, _, _, report = self.project()
            record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
            self.assertEqual(record["version"]["value"], "2.1.5.7")
            self.assertEqual(report["packageVersion"], "31.2.2")
            self.assertEqual(record["publishedIdentityEvidence"]["pnpIds"], self.inspection["infs"][0]["models"][0]["pnpIds"])
            self.assertEqual(record["publishedIdentityEvidence"]["evidenceSha256"], self.inspection["infs"][0]["infSha256"])
            self.assertNotIn(b"instanceId", raw)
            self.assertIsNone(report["actualDeviceCandidates"])
        changed = deepcopy(self.inspection)
        changed["infs"][0]["driverVersion"] = "31.2.2"
        with self.subTest(case="P1-06-release-as-driver"), self.assertRaises(ValueError):
            self.project(inspection=changed)
        changed = deepcopy(self.evidence)
        changed["records"][0]["packageVersion"] = "different"
        with self.subTest(case="P1-06-conflicting-page-release"), self.assertRaises(ValueError):
            self.project(evidence=changed)

    def test_p1_07_fixed_denominators(self):
        """一件/一INF/一節と未投影分母を保持し、追加入力を成功へ落とさない。"""
        with self.subTest(case="P1-07-positive"):
            raw, _, _, report = self.project()
            index = json.loads(raw)
            record = json.loads(base64.b64decode(index["records"][0]["recordBytesBase64"]))
            self.assertEqual((len(index["sources"]), len(index["records"])), (1, 1))
            self.assertEqual(report["unprojectedModelSections"], 1)
            self.assertNotIn("UNPROJECTED_ARTIFICIAL_SECTION", json.dumps(record))
        for target, field, value in (("evidence", "records", self.evidence["records"]*2),
                                     ("inspection", "infs", self.inspection["infs"]*2),
                                     ("inspection", "verifiedIdentityInfs", 2),
                                     ("inspection", "selectedOnly", False)):
            changed = deepcopy(getattr(self, target))
            changed[field] = value
            with self.subTest(case="P1-07-reject", target=target, field=field), self.assertRaises(ValueError):
                self.project(**{target: changed})


class DailyDistributionProjectionTests(unittest.TestCase):
    """ADR0364のD01〜04/D07〜24を固定人工入力で検査する。"""

    def setUp(self):
        """旧fixtureだけを借用し、旧methodの再発見を増やさない。

        helperのdoCleanupsを先に登録してpatchの寿命をこのcaseへ結合する。
        各文書はdeepcopyして所有し、変更をhelperや別caseへ共有しない。
        """
        fixture = DistributionProjectionTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        for name in ("scope", "legacy_scope", "evidence", "release", "inspection", "review", "script"):
            setattr(self, name, deepcopy(getattr(fixture, name)))
        self.now = fixture.now
        self.receipt = self.make_receipt()

    def make_receipt(self, status=200, generation=4):
        """元evidenceから人工日次receiptを構成し、実観測とは区別する。"""
        return ProjectionTests.daily_receipt(self, status, generation)

    @staticmethod
    def rebind(receipt, projected=None):
        """negative所有copyの投影hashだけを揃え、個別結合検査へ到達させる。"""
        if projected is None:
            projected = {field: receipt[field] for field in
                         ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")}
        raw = projection.bytes_json(projected)
        receipt.update(projectionBytesBase64=base64.b64encode(raw).decode("ascii"),
                       projectionSha256=hashlib.sha256(raw).hexdigest())
        return receipt

    def project(self, **changes):
        """世代overrideを追加せず、固定した原文書を明示入口へ渡す。"""
        args = dict(scope=self.scope, receipt=self.receipt, release=self.release,
                    inspection=self.inspection, review=self.review, script=self.script, now=self.now)
        args.update(changes)
        return projection.project_daily_distribution_acquisition(**args)

    def reject(self, label, code, **changes):
        """固定reasonを完全一致で照合し、失敗を分母から除かない。"""
        with self.subTest(variant=label, expected=code):
            with self.assertRaises(ValueError) as caught:
                self.project(**changes)
            self.assertEqual(str(caught.exception), code)

    def test_d01_original_200(self):
        """D01。元200のbody/観測/世代/前hashを変更せず取得索引へ接続する。"""
        for generation in (4, 9, 9007199254740991):
            receipt = self.make_receipt(200, generation)
            original = deepcopy(receipt)
            with self.subTest(generation=generation):
                raw, packed, manifest, report = self.project(receipt=receipt)
                record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
                self.assertEqual(gzip.decompress(packed), raw)
                self.assertEqual(receipt, original)
                self.assertEqual(json.loads(manifest)["generation"], generation)
                self.assertEqual(record["inspectionStage"], "CONTENT_INSPECTED")
                self.assertEqual(report["observationUtc"], "2026-10-13T12:59:30Z")
                self.assertEqual(report["bodySha256"], receipt["bodySha256"])
                self.assertEqual(report["originalFetchedAt"], receipt["lastFetchedAt"])
                self.assertEqual(report["previousReceiptSha256"], receipt["previousReceiptSha256"])
                self.assertEqual((report["newHttp200Count"], report["revalidatedHttp304Count"]), (1, 0))
                self.assertEqual(json.loads(manifest)["expiresAtUtc"], "2026-10-21T12:59:30Z")

    def test_d02_original_304(self):
        """D02。旧fetchedと今回validatedを分け、304を200に換算しない。"""
        for generation in (4, 5, 9007199254740991):
            receipt = self.make_receipt(304, generation)
            original = deepcopy(receipt)
            with self.subTest(generation=generation):
                _, _, manifest, report = self.project(receipt=receipt)
                self.assertEqual(receipt, original)
                self.assertEqual(report["httpStatus"], 304)
                self.assertEqual(report["observationKind"], "REVALIDATED_304")
                self.assertEqual((report["newHttp200Count"], report["revalidatedHttp304Count"]), (0, 1))
                self.assertEqual(report["originalFetchedAt"], receipt["lastFetchedAt"])
                self.assertLess(receipt["lastFetchedAt"], receipt["lastAttemptAt"])
                self.assertEqual(report["previousReceiptSha256"], receipt["previousReceiptSha256"])
                self.assertEqual(json.loads(manifest)["generation"], generation)
                self.assertEqual(json.loads(manifest)["expiresAtUtc"], "2026-10-21T12:59:30Z")

    def test_d03_original_three_paths(self):
        """D03。旧三入口の用途を保持し、別guard内でbefore原byteとも比較する。"""
        calls = (("project", lambda: projection.project(self.legacy_scope, self.evidence, 1, self.now),
                  "METADATA_ONLY", 1),
                 ("project_daily", lambda: projection.project_daily(
                     self.legacy_scope, self.receipt, self.now), "METADATA_ONLY", 4),
                 ("P1", lambda: projection.project_distribution_acquisition(
                     self.scope, self.evidence, self.release, self.inspection,
                     self.review, self.script, 4, self.now), "CONTENT_INSPECTED", 4))
        for name, call, stage, generation in calls:
            with self.subTest(path=name):
                raw, packed, manifest, report = call()
                record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
                self.assertEqual(gzip.decompress(packed), raw)
                self.assertEqual(record["inspectionStage"], stage)
                self.assertEqual(json.loads(manifest)["generation"], generation)
                self.assertEqual(report["realInstall"], 0)
                if name == "P1":
                    self.assertEqual((raw, packed, manifest), self.project()[:3])

    def test_d04_inputs_and_nonissuance(self):
        """D04。借用文書を不変に保ち、未署名整合性を権限へ変換しない。"""
        for status in (200, 304):
            receipt = self.make_receipt(status)
            values = (self.scope, receipt, self.release, self.inspection, self.review, self.script)
            original = deepcopy(values)
            with self.subTest(status=status):
                report = self.project(receipt=receipt)[3]
                self.assertEqual(values, original)
                self.assertTrue(report["unsigned"])
                self.assertFalse(report["authorityIssued"])
                self.assertFalse(report["termsConsent"])
                self.assertEqual((report["realPayloads"], report["realInstall"], report["publication"]), (0, 0, 0))
                self.assertIsNone(report["actualDeviceCandidates"])

    def test_d07_receipt_fields(self):
        """D07。日次receiptの全fieldと明示schema/sourceを要求する。"""
        missing = deepcopy(self.receipt)
        missing.pop("bodyBytesBase64")
        self.reject("missing", "DAILY_RECEIPT_FIELDS", receipt=missing)
        self.reject("extra", "DAILY_RECEIPT_FIELDS", receipt=dict(self.receipt, extra=1))
        for field in ("schema", "source"):
            self.reject(field, "DAILY_RECEIPT_BINDING", receipt=dict(self.receipt, **{field: "OTHER"}))

    def test_d08_nonobservations(self):
        """D08。待機/失敗/無通信を新観測へ昇格しない。"""
        for outcome in ("HOLD", "FAILED", "NO_NETWORK"):
            self.reject(outcome, "DAILY_NOT_A_NEW_OBSERVATION", receipt=dict(self.receipt, outcome=outcome))

    def test_d09_status_outcome_and_errors(self):
        """D09。status/outcome不整合とerrorの型違い・非零を拒否する。"""
        changes = [("httpStatus", value) for value in (0, True, 201)]
        changes += [("outcome", "REVALIDATED_304")]
        changes += [(field, value) for field in ("error", "stateError") for value in (True, 1, "0")]
        for ordinal, (field, value) in enumerate(changes):
            self.reject(str(ordinal), "DAILY_NOT_A_NEW_OBSERVATION", receipt=dict(self.receipt, **{field: value}))

    def test_d10_generation(self):
        """D10。日次世代の型と有限整数範囲を保つ。"""
        for value in (0, 3, True, 4.5, 9007199254740992, "4"):
            self.reject(repr(value), "DAILY_GENERATION", receipt=dict(self.receipt, generation=value))

    def test_d11_previous_receipt(self):
        """D11。初代と後続の前receipt結合を区別する。"""
        self.reject("first-nonempty", "DAILY_PREVIOUS_RECEIPT", receipt=dict(self.receipt, previousReceiptSha256="9"*64))
        for value in ("", "short", "A"*64, None):
            self.reject(repr(value), "DAILY_PREVIOUS_RECEIPT",
                        receipt=dict(self.make_receipt(generation=5), previousReceiptSha256=value))

    def test_d12_time_types_and_ranges(self):
        """D12。四時刻のbool/非正数/端数/上限超過を拒否する。"""
        for field in ("lastFetchedAt", "lastSuccessfulValidationAt", "lastAttemptAt", "notBefore"):
            for value in (True, 0, -1, 1.5, 253402300800):
                self.reject(field+":"+repr(value), "DAILY_TIME", receipt=dict(self.receipt, **{field: value}))

    def test_d13_observation_order_and_wait(self):
        """D13。観測順序と元24時間待機・期限を保持する。"""
        observed = self.receipt["lastSuccessfulValidationAt"]
        changes = (("lastSuccessfulValidationAt", int(self.now.timestamp())+1),
                   ("lastAttemptAt", observed+1), ("lastFetchedAt", observed+1), ("notBefore", observed+1))
        for field, value in changes:
            self.reject(field, "DAILY_OBSERVATION_TIME", receipt=dict(self.receipt, **{field: value}))
        self.reject("expiry", "DAILY_OBSERVATION_TIME", now=datetime.fromtimestamp(observed+86400, timezone.utc))

    def test_d14_fetch_rules(self):
        """D14。200の元取得時刻と304の再検証前取得を厳密に分ける。"""
        self.reject("200-old", "DAILY_FETCH_TIME", receipt=dict(self.receipt, lastFetchedAt=self.receipt["lastFetchedAt"]-1))
        receipt = self.make_receipt(304)
        receipt["lastFetchedAt"] = receipt["lastAttemptAt"]
        self.reject("304-new", "DAILY_FETCH_TIME", receipt=receipt)

    def test_d15_day(self):
        """D15。日付の型と固定桁の表記を要求する。"""
        for value in (True, 20261013, "2026-10-13"):
            self.reject(repr(value), "DAILY_DAY", receipt=dict(self.receipt, day=value))

    def test_d16_daily_digests(self):
        """D16。request/projection digestの小文字全64桁を保持する。"""
        for field in ("requestBindingSha256", "projectionSha256"):
            for value, code in (("A"*64, "DAILY_DIGEST"), ("invalid", "NATIVE_PUBLIC_DIGEST"),
                                (None, "NATIVE_PUBLIC_DIGEST")):
                self.reject(field+":"+repr(value), code, receipt=dict(self.receipt, **{field: value}))

    def test_d17_original_body(self):
        """D17。投影pinを揃えても原bodyの型・digest不整合を拒否する。"""
        for field, value, code in (("bodyBytesBase64", "", "BODY_DIGEST"),
                                   ("bodyBytesBase64", None, "BODY_TYPE"),
                                   ("bodySha256", "0"*64, "BODY_DIGEST"),
                                   ("bodySha256", "invalid", "COLLECTED_DIGEST")):
            receipt = self.rebind(dict(self.receipt, **{field: value}))
            self.reject(field+":"+repr(value), code, receipt=receipt)

    def test_d18_projection_bytes_and_binding(self):
        """D18。元投影の型・byte・field・receipt結合を別々に検査する。"""
        self.reject("type", "DAILY_PROJECTION_TYPE", receipt=dict(self.receipt, projectionBytesBase64=None))
        for value in ("", "AA=="):
            self.reject("bytes-"+value, "DAILY_PROJECTION_DIGEST", receipt=dict(self.receipt, projectionBytesBase64=value))
        projected = json.loads(base64.b64decode(self.receipt["projectionBytesBase64"]))
        projected["lastFetchedAt"] -= 1
        self.reject("binding", "DAILY_PROJECTION_BINDING", receipt=self.rebind(dict(self.receipt), projected))
        projected.pop("lastFetchedAt")
        self.reject("fields", "DAILY_PROJECTION_FIELDS", receipt=self.rebind(dict(self.receipt), projected))

    def test_d19_scope_and_full_pin(self):
        """D19。配布専用scopeと完全pinを旧schemaへの偽装なしで検査する。"""
        missing = dict(self.scope)
        missing.pop("keyId")
        self.reject("missing", "DISTRIBUTION_SCOPE_FIELDS", scope=missing)
        self.reject("extra", "DISTRIBUTION_SCOPE_FIELDS", scope=dict(self.scope, extra=1))
        for field, value, code in (("targetCount", True, "DISTRIBUTION_SCOPE_TYPE"),
                                   ("source", "OTHER", "DISTRIBUTION_SCOPE_BINDING"),
                                   ("publicFingerprint", "f"*64, "DISTRIBUTION_PUBLIC_PIN"),
                                   ("keyId", "other", "DISTRIBUTION_PUBLIC_PIN"),
                                   ("collectorManifestSha256", "invalid", "DISTRIBUTION_SCOPE_BINDING"),
                                   ("schema", self.legacy_scope["schema"], "DISTRIBUTION_SCOPE_BINDING")):
            self.reject(field, code, scope=dict(self.scope, **{field: value}))

    def test_d20_package_and_inf_binding(self):
        """D20。page/package版と実内容・選択INF・model節を結合する。"""
        self.reject("payload", "FIXED_PACKAGE", release=dict(self.release, payloadUrl="https://www.intel.com/other.zip"))
        self.reject("release", "NATIVE_RELEASE_BINDING", release=dict(self.release, bodySha256="0"*64))
        receipt = deepcopy(self.receipt)
        receipt["records"][0]["packageVersion"] = "other"
        self.reject("package-version", "DISTRIBUTION_PACKAGE_VERSION", receipt=self.rebind(receipt))
        self.reject("archive", "NATIVE_PACKAGE_BINDING", inspection=dict(self.inspection, archiveSha256="0"*64))
        self.reject("selected-inf", "NATIVE_PACKAGE_BINDING", inspection=dict(self.inspection, selectedInf="other.inf"))
        inspection = deepcopy(self.inspection)
        inspection["infs"][0]["infIdentity"] = "other.inf"
        self.reject("inf", "NATIVE_INF_BINDING", inspection=inspection)
        inspection = deepcopy(self.inspection)
        inspection["infs"][0]["models"][0]["modelSection"] = "OTHER"
        self.reject("section", "NATIVE_MODEL_SECTION", inspection=inspection)

    def test_d21_content_terms_script(self):
        """D21。原内容・terms・非実行scriptの検査を省略しない。"""
        observed = self.receipt["lastSuccessfulValidationAt"]
        self.reject("inspection", "NATIVE_PACKAGE_BINDING", inspection=dict(self.inspection, inspectionError=1))
        for label, value in (("old", observed-1), ("future", int(self.now.timestamp())+1)):
            self.reject(label, "NATIVE_CONTENT_TIME", inspection=dict(self.inspection, contentCheckedUtcSeconds=str(value)))
        self.reject("terms", "NATIVE_TERMS_DIGEST", release=dict(self.release, termsTextSha256="0"*64))
        self.reject("review", "TERMS_REVIEW_BINDING", review=dict(self.review, payloadUrl="other"))
        self.reject("executed", "TERMS_SCRIPT_RECEIPT", script=dict(self.script, scriptExecuted=True))
        self.reject("script-hash", "TERMS_SCRIPT_DIGEST", script=dict(self.script, scriptSha256="0"*64))
        self.reject("review-time", "TERMS_REVIEW_TIME", review=dict(self.review, checkedAtUtcSeconds=int(self.now.timestamp())+1))
        self.reject("roles", "TERMS_WITNESS_ROLES", review=dict(self.review, scriptWitnesses=[]))

    def test_d22_utc_and_expiry(self):
        """D22。明示UTC秒と元観測期限だけを使用する。"""
        for value in (self.now.replace(tzinfo=None), self.now.astimezone(timezone(timedelta(hours=1))),
                      self.now.replace(microsecond=1)):
            self.reject(repr(value), "DISTRIBUTION_UTC_SECONDS", now=value)
        self.reject("expired", "DAILY_OBSERVATION_TIME", now=self.now+timedelta(days=1))

    def test_d23_explicit_entry_separation(self):
        """D23。旧evidence/日次/P1の用途を推測せず、任意新世代指定を拒否する。"""
        self.reject("old-evidence", "DAILY_RECEIPT_FIELDS", receipt=self.evidence)
        for label, call, code in (
                ("old-daily", lambda: projection.project_daily(self.scope, self.receipt, self.now), "FIXED_SCOPE"),
                ("P1", lambda: projection.project_distribution_acquisition(self.scope, self.receipt,
                    self.release, self.inspection, self.review, self.script, 4, self.now), "COLLECTED_FIELDS")):
            with self.subTest(variant=label, expected=code):
                with self.assertRaises(ValueError) as caught:
                    call()
                self.assertEqual(str(caught.exception), code)
        code = "project_daily_distribution_acquisition() got an unexpected keyword argument 'generation'"
        with self.subTest(variant="override", expected=code):
            with self.assertRaises(TypeError) as caught:
                self.project(generation=5)
            self.assertEqual(str(caught.exception), code)

    def test_d24_stale_304_not_refreshed(self):
        """D24。304を口実に古いrelease/内容/scriptの時刻を書き換えない。"""
        receipt = self.make_receipt(304)
        old = receipt["lastFetchedAt"]
        changes = (("release", "observedUtcSeconds", str(old), "NATIVE_RELEASE_BINDING"),
                   ("inspection", "contentCheckedUtcSeconds", str(old), "NATIVE_CONTENT_TIME"),
                   ("script", "scriptObservedUtcSeconds", str(old), "TERMS_REVIEW_TIME"))
        for name, field, value, code in changes:
            document = dict(getattr(self, name), **{field: value})
            original = deepcopy(document)
            self.reject(name, code, receipt=receipt, **{name: document})
            self.assertEqual(document, original)


class PinnedStaticRevalidationTests(unittest.TestCase):
    """C01/C02/C06〜C10の全人工variant。旧manualと新機械時刻を分離する。"""

    def setUp(self):
        """元fixtureの承認済み原三文書を固定してから、二日後のfresh artifactを作る。

        helperのsetUp成功後に登録したdoCleanupsが、このcase終了時にpatchを解除する。
        文書はdeepcopyし、originalsのbyteとoriginal_pinsは保持する。
        fresh release／scriptの観測時刻を別に更新する。
        """
        fixture = DistributionProjectionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for name in ("scope", "evidence", "release", "inspection", "review", "script", "body"):
            setattr(self, name, deepcopy(getattr(fixture, name)))
        # 新modeは実nativeの明示profile/field集合を要求する。旧fixture/入口は変更しない。
        self.release["parserRevision"] = 1
        self.release["htmlExtraction"] = {
            "profile": "TEXTAREA_HTML_DOCUMENT_V1",
            "selector": {"tag": "textarea", "attribute": "id", "value": "content-raw"},
            "containerSelector": {"tag": "div", "attribute": "id", "value": "licenseModal"},
            "linkSelector": {"tag": "button", "attribute": "data-modal-id", "value": "1"},
            "payloadAttribute": "data-href", "documentSha256": self.evidence["bodySha256"],
            "documentSizeBytes": len(self.body), "textSha256": self.release["termsTextSha256"],
            "textSizeBytes": self.release["termsTextUtf8Bytes"], "bindingEvidenceUrl": "", "bindingEvidenceSha256": ""}
        self.originals = {key: projection.bytes_json(getattr(self, key)) for key in ("release", "review", "script")}
        self.original_pins = {key: hashlib.sha256(raw).hexdigest() for key, raw in self.originals.items()}
        self.original_checked = self.review["checkedAtUtcSeconds"]
        self.now = fixture.now + timedelta(days=2)
        observed = int(self.now.timestamp()) - 30
        self.evidence["lastSuccessfulValidationAt"] = observed
        self.release["observedUtcSeconds"] = str(observed)
        self.script.update(pageObservedUtcSeconds=str(observed), scriptObservedUtcSeconds=str(observed+10))
        self.inspection["contentCheckedUtcSeconds"] = str(observed+15)
        self.receipt = ProjectionTests.daily_receipt(self, 200, 9)
        self.review = self.wrapper()

    def wrapper(self, release=None, script=None):
        """原pinを保持して、明示した新二文書だけを機械receiptへ包む。"""
        return json.loads(projection.make_pinned_static_terms_revalidation(self.body, self.originals,
            self.original_pins, projection.bytes_json(release or self.release),
            projection.bytes_json(script or self.script), int(self.now.timestamp())-5, self.now))

    def project(self, **changes):
        """明示modeを必ず渡し、旧入口やschemaによるfallbackを使わない。"""
        args = dict(scope=self.scope, receipt=self.receipt, release=self.release, inspection=self.inspection,
                    review=self.review, script=self.script, now=self.now,
                    terms_review_mode=projection.PINNED_STATIC_REVALIDATION_V1)
        args.update(changes)
        return projection.project_daily_distribution_acquisition(**args)

    def reject(self, label, reason, **changes):
        """期待する最初の拒否理由を完全一致で固定する。"""
        with self.subTest(variant=label, expected=reason), self.assertRaises(ValueError) as caught:
            self.project(**changes)
        self.assertEqual(str(caught.exception), reason)

    def test_c01_c02_fresh_200_304_and_original_manual_bytes(self):
        """200/304を変換せず、旧manualより後の機械確認から一件を投影する。"""
        originals = deepcopy(self.originals)
        for status in (200, 304):
            with self.subTest(case="C01" if status == 200 else "C02", status=status):
                receipt = ProjectionTests.daily_receipt(self, status, 9)
                raw, packed, manifest, report = self.project(receipt=receipt)
                self.assertEqual(gzip.decompress(packed), raw)
                self.assertEqual(report["httpStatus"], status)
                self.assertEqual((report["newHttp200Count"], report["revalidatedHttp304Count"]),
                                 (int(status == 200), int(status == 304)))
                self.assertEqual(self.review["originalManualCheckedAtUtcSeconds"], self.original_checked)
                self.assertLess(self.original_checked, receipt["lastSuccessfulValidationAt"])
                self.assertEqual(self.originals, originals)
                self.assertFalse(report["termsConsent"])
                self.assertFalse(report["authorityIssued"])
                record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
                self.assertEqual(record["acquisitionDescriptor"]["terms"]["state"], "ACCEPTANCE_REQUIRED")
                self.assertEqual(json.loads(manifest)["generation"], 9)

    def test_c06_old_artifacts_and_time_order(self):
        """旧release/content/script、未来・失効を原stamp更新なしで拒否する。"""
        old_release = json.loads(self.originals["release"])
        self.reject("old-release", "NATIVE_RELEASE_BINDING", release=old_release)
        old_content = deepcopy(self.inspection)
        old_content["contentCheckedUtcSeconds"] = str(self.original_checked)
        self.reject("old-content", "NATIVE_CONTENT_TIME", inspection=old_content)
        old_script = json.loads(self.originals["script"])
        self.reject("old-script", "TERMS_REVALIDATION_PIN", script=old_script)
        for value in (self.original_checked, int(self.now.timestamp())+1):
            wrapper = dict(self.review, revalidatedCheckedAtUtcSeconds=value)
            self.reject(str(value), "TERMS_REVIEW_TIME", review=wrapper)
        self.reject("expiry", "DAILY_OBSERVATION_TIME", now=self.now + timedelta(days=1))

    def test_c07_template_script_and_full_terms_changes(self):
        """全byteや規約全文の差は意味同等と推測しない。"""
        for key, value in (("termsRevision", "changed"), ("payloadUrl", "https://www.intel.com/changed")):
            release = dict(self.release, **{key: value})
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED"):
                self.wrapper(release=release)
        script = deepcopy(self.script)
        script["scriptSha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED"):
            self.wrapper(script=script)
        self.reject("script-altered-outside-wrapper", "TERMS_REVALIDATION_PIN", script=script)

    def test_c08_original_pins_mode_manual_time_and_witness(self):
        """旧manual原pin、元時刻、明示modeと非manual表示を保持する。"""
        for key in ("originalRelease", "originalReview", "originalScript", "freshRelease", "freshScript"):
            wrapper = deepcopy(self.review)
            wrapper[key]["sha256"] = "0"*64
            self.reject(key, "TERMS_REVALIDATION_PIN", review=wrapper)
        self.reject("manual-time", "TERMS_REVIEW_TIME",
                    review=dict(self.review, originalManualCheckedAtUtcSeconds=self.original_checked+1))
        self.reject("false-manual", "TERMS_REVIEW_MODE",
                    review=dict(self.review, reviewMethod="MANUAL_NONEXECUTED_STATIC_LINK_REVIEW"))
        self.reject("nonexplicit", "TERMS_REVIEW_BINDING", terms_review_mode=None)
        self.reject("unknown-mode", "TERMS_REVIEW_MODE", terms_review_mode="AUTO")
        for key, reason in (("scriptWitnesses", "TERMS_WITNESS_ROLES"), ("pageSha256", "TERMS_REVIEW_BINDING")):
            old = json.loads(self.originals["review"])
            old[key] = [] if key == "scriptWitnesses" else "0"*64
            raw = projection.bytes_json(old)
            wrapper = deepcopy(self.review)
            wrapper["originalReview"] = {"bytesBase64": base64.b64encode(raw).decode(),
                                          "sha256": hashlib.sha256(raw).hexdigest()}
            self.reject(key, reason, review=wrapper)

    def test_c09_wrapper_fields_types_capacity_and_duplicate_raw(self):
        """明示v2の1MiB、旧review64KiB、nested原manual64KiBを混同しない。"""
        self.reject("unknown", "TERMS_REVALIDATION_FIELDS", review=dict(self.review, extra=True))
        self.reject("bool-time", "TERMS_REVALIDATION_TYPE",
                    review=dict(self.review, revalidatedCheckedAtUtcSeconds=True))
        wrapper = deepcopy(self.review)
        wrapper["originalReview"]["bytesBase64"] = "A"*(90000)
        self.reject("nested-manual-cap", "TERMS_REVALIDATION_SIZE", review=wrapper)
        wrapper = deepcopy(self.review)
        wrapper["freshRelease"]["bytesBase64"] = "A"*(1048576)
        self.reject("v2-cap", "TERMS_REVALIDATION_SIZE", review=wrapper)
        for raw in (b'{"schema":"one","schema":"two"}', b'\xff'):
            wrapper = deepcopy(self.review)
            wrapper["originalReview"] = {"bytesBase64": base64.b64encode(raw).decode(),
                                          "sha256": hashlib.sha256(raw).hexdigest()}
            with self.subTest(rawKind="duplicate" if raw.startswith(b"{") else "utf8"), self.assertRaises((ValueError, UnicodeError)):
                self.project(review=wrapper)

    def test_c10_package_inf_models_and_content_failures(self):
        """別archive・INF・Models・CAT/publisher失敗を新対応へ数えない。"""
        for key, value in (("archiveSha256", "0"*64), ("archiveBytes", 1), ("inspectionError", 13),
                           ("selectedInf", "other.inf")):
            self.reject(key, "NATIVE_PACKAGE_BINDING", inspection=dict(self.inspection, **{key: value}))
        for key, value in (("contentError", 13), ("identityError", 13), ("driverVersion", "0.0"),
                           ("infIdentity", "other.inf")):
            inspection = deepcopy(self.inspection)
            inspection["infs"][0][key] = value
            self.reject(key, "NATIVE_INF_BINDING", inspection=inspection)
        inspection = deepcopy(self.inspection)
        inspection["infs"][0]["models"][0]["modelSection"] = "other"
        self.reject("models", "NATIVE_MODEL_SECTION", inspection=inspection)


class FiniteProjectionResult(unittest.TextTestResult):
    """成功を含む全subcaseと実method数を原streamへ報告する。"""
    def __init__(self, *args, **kwargs):
        """標準resultを初期化し、実行method/subcaseの台帳を所有する。"""
        super().__init__(*args, **kwargs)
        self.subcases = []
        self.method_ids = []

    def startTest(self, test):
        """分母へ実際に開始したmethodだけを標準通知とともに記録する。"""
        super().startTest(test)
        self.method_ids.append(test.id())

    def addSubTest(self, test, subtest, err):
        """標準成否を保ち、成功も含めて個別subcaseを保持する。"""
        super().addSubTest(test, subtest, err)
        self.subcases.append({"test": test.id(), "subcase": str(subtest), "passed": err is None})

    def stopTestRun(self):
        """原streamへ実件数と全subcaseを出し、失敗やskipを除かない。"""
        super().stopTestRun()
        self.stream.writeln("PROJECTION_FINITE_RECEIPT " + json.dumps({
            "testsRun": self.testsRun, "methodIds": self.method_ids,
            "failures": len(self.failures), "errors": len(self.errors),
            "skipped": len(self.skipped), "subcases": self.subcases,
            "actualNetworkOrNativeChildStarts": 0, "guardScope": "all seven new P1 test methods"}, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(resultclass=FiniteProjectionResult))
