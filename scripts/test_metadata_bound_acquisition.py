"""架空metadata/実byteから六入力と既存索引投影までの閉じた回帰。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実通信・実索引署名・実端末・実CATの成功を生成しない。
"""
from __future__ import annotations

import base64
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import daily_index_pipeline as pipeline
import project_collected_native_index as projection
import test_project_collected_native_index as fixtures


def artifact(raw: bytes) -> dict:
    """人工原byteを全byte/hash対へ固定する。"""
    return {"bytesBase64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}


class MetadataBoundFixture:
    """既存manual原byteと、異なる版/file/INF/sizeの人工取得結果を分離する。"""

    def __init__(self, algorithm="sha512", *, exact=None, payload=b"ARTIFICIAL_ARCHIVE_BYTES_V99"):
        self.original = fixtures.PinnedStaticRevalidationTests()
        self.original.setUp()
        self.now = self.original.now
        self.originals = deepcopy(self.original.originals)
        self.originals["body"] = self.original.body
        self.payload = payload
        self.release = deepcopy(self.original.release)
        self.release.update(packageVersion="99.7.4", fileName="Wired_driver_99.7.4_x64.zip",
                            payloadUrl="https://downloadmirror.intel.com/999999/Wired_driver_99.7.4_x64.zip",
                            publishedSha256=hashlib.sha256(payload).hexdigest() if algorithm != "sha512" else "")
        if algorithm != "sha256":
            self.release.update(schema="dc-saved-release-analysis-v2", publishedSha512=hashlib.sha512(payload).hexdigest())
        if exact is not None:
            self.release["publishedSizeBytes"] = exact
        old_url = self.original.release["payloadUrl"]
        self.body = self.original.body.replace(old_url.encode(), self.release["payloadUrl"].encode()) + b"<!-- artificial new metadata -->"
        body_hash = hashlib.sha256(self.body).hexdigest()
        self.release.update(bodySha256=body_hash, bodyBytes=len(self.body))
        self.script = deepcopy(self.original.script)
        self.script["pageSha256"] = body_hash
        self.evidence = deepcopy(self.original.evidence)
        self.evidence.update(bodySha256=body_hash, bodyBytesBase64=base64.b64encode(self.body).decode())
        self.evidence["records"][0]["packageVersion"] = self.release["packageVersion"]
        self.receipt = fixtures.ProjectionTests.daily_receipt(self, 200, 12)
        self.scope = dict(self.original.scope, schema=projection.METADATA_BOUND_SCOPE, recordId="artificial-wired-99-7-4")
        self.scope["acquisitionBinding"] = {"expectedRelease": artifact(projection.bytes_json(self.release)),
            "selectedInf": "NEW/Winx64/W11/fake99.inf", "modelSection": "Fixture.NTamd64.10.0.1..22000", "maximumBytes": 4096}
        self.inspection = deepcopy(self.original.inspection)
        self.inspection.update(schema="dc-inspected-public-identities-v3", archiveSha256=hashlib.sha256(payload).hexdigest(),
                               archiveSha512=hashlib.sha512(payload).hexdigest(), archiveBytes=len(payload),
                               selectedInf=self.scope["acquisitionBinding"]["selectedInf"].replace("/", "\\"))
        inf = self.inspection["infs"][0]
        inf.update(infIdentity=self.scope["acquisitionBinding"]["selectedInf"], infSha256=hashlib.sha256(b"ARTIFICIAL_INF").hexdigest(),
                   driverVersion="9.8.7.6", verifiedPublisher="Artificial fixture publisher")
        inf["models"] = [{"modelSection": self.scope["acquisitionBinding"]["modelSection"],
                          "pnpIds": [{"kind": "HARDWARE", "value": r"PCI\VEN_FFFE&DEV_0001"}]}]
        self.refresh_review()

    def refresh_review(self):
        """旧manual原byte/原stampを保持し、新metadata/scriptへ機械bindingする。"""
        self.pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in self.originals.items()}
        self.review = json.loads(projection.make_pinned_static_terms_revalidation(self.body, self.originals, self.pins,
            projection.bytes_json(self.release), projection.bytes_json(self.script), int(self.now.timestamp())-5,
            self.now, mode=projection.PINNED_STATIC_REVALIDATION_V2))

    def project(self, **changes):
        """人工原receiptだけから未署名索引を生成する。"""
        args = dict(scope=self.scope, receipt=self.receipt, release=self.release, inspection=self.inspection,
                    review=self.review, script=self.script, now=self.now,
                    terms_review_mode=projection.PINNED_STATIC_REVALIDATION_V2)
        args.update(changes)
        return projection.project_daily_distribution_acquisition(**args)

    def close(self):
        """既存fixtureの外部開始禁止patchを解放する。"""
        self.original.doCleanups()


class MetadataBoundAcquisitionTests(unittest.TestCase):
    """新版metadata・全algorithm・任意exact・明示selectorの安全な回帰集合。"""

    def fixture(self, algorithm="sha512", **kwargs):
        value = MetadataBoundFixture(algorithm, **kwargs)
        self.addCleanup(value.close)
        return value

    def test_all_algorithms_new_file_selector_and_optional_size(self):
        for algorithm in ("sha256", "sha512", "both"):
            for exact in (False, True):
                with self.subTest(algorithm=algorithm, exact=exact):
                    payload = b"ARTIFICIAL_CHANGED_SIZE_" + algorithm.encode()
                    fixture = self.fixture(algorithm, payload=payload, exact=len(payload) if exact else None)
                    raw, packed, manifest, report = fixture.project()
                    record = json.loads(base64.b64decode(json.loads(raw)["records"][0]["recordBytesBase64"]))
                    self.assertEqual(record["version"]["value"], "9.8.7.6")
                    self.assertEqual(record["publishedIdentityEvidence"]["infIdentity"], "NEW/Winx64/W11/fake99.inf")
                    self.assertEqual(record["packageEvidence"]["calculatedHash"]["sha256"], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(record["packageEvidence"]["publishedHash"]["state"], "UNKNOWN" if algorithm == "sha512" else "KNOWN")
                    self.assertEqual(record["packageEvidence"]["size"]["valueBytes"], len(payload))
                    self.assertEqual(pipeline.parse_time(json.loads(manifest)["expiresAtUtc"]),
                                     fixture.now-timedelta(seconds=30)+timedelta(days=8))
                    self.assertFalse(report["authorityIssued"])
                    self.assertEqual(fixture.review["originalManualCheckedAtUtcSeconds"], fixture.original.original_checked)

    def test_only_contained_content_raw_is_the_terms_document(self):
        """補助textareaは許諾へ混ぜず、対象の欠損/重複/container外/本文変更は拒否する。"""
        for variant in ("unrelated", "missing", "duplicate", "outside", "changed"):
            fixture = self.fixture()
            body = fixture.body
            start = body.index(b'<textarea id="content-raw"')
            end = body.index(b"</textarea>", start)+len(b"</textarea>")
            target = body[start:end]
            if variant == "unrelated":
                body += b'<textarea id="helper-one">unrelated new text</textarea><textarea id="helper-two">other</textarea>'
            elif variant == "missing":
                body = body[:start]+body[end:]
            elif variant == "duplicate":
                body = body[:end]+target+body[end:]
            elif variant == "outside":
                body = body[:start]+body[end:]+target
            else:
                body = body[:start]+target.replace(b"Artificial complete terms", b"Changed complete terms")+body[end:]
            fixture.body = body
            digest = pipeline.sha(body)
            fixture.release.update(bodySha256=digest, bodyBytes=len(body))
            fixture.script["pageSha256"] = digest
            fixture.evidence.update(bodySha256=digest, bodyBytesBase64=base64.b64encode(body).decode())
            fixture.receipt = fixtures.ProjectionTests.daily_receipt(fixture, 200, 12)
            if variant == "unrelated":
                fixture.refresh_review()
                self.assertEqual(len(projection.TermsDom(body.decode()).raw_documents), 1)
                self.assertEqual(fixture.project()[3]["realContentInspected"], 1)
            else:
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    fixture.refresh_review()

    def test_all_hashes_malformed_missing_wrong_and_legacy_bundle(self):
        fixture = self.fixture("both")
        for field in ("publishedSha256", "publishedSha512"):
            for value in ("g", "", "0"*(64 if field.endswith("256") else 128), None, True):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    fixture.project(release=dict(fixture.release, **{field: value}))
        for field, value in (("archiveSha256", "0"*64), ("archiveSha512", "0"*128),
                             ("archiveBytes", 0), ("archiveBytes", 4097), ("archiveBytes", True),
                             ("schema", "dc-inspected-public-identities-v2")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.project(inspection=dict(fixture.inspection, **{field: value}))
        for field in ("receipt", "release", "inspection", "script", "review"):
            with self.subTest(legacy=field), self.assertRaises(ValueError):
                fixture.project(**{field: getattr(fixture.original, field)})

    def test_old_expected_stamp_is_preserved_and_fresh_window_uses_new_receipt(self):
        """翌日待機24h+1秒のexpectedは宣言のまま保ち、新実観測だけをfresh/期限へ使う。"""
        fixture = self.fixture("sha512")
        expected = deepcopy(fixture.release)
        observed = int(fixture.receipt["lastSuccessfulValidationAt"])
        expected["observedUtcSeconds"] = str(observed-86401)
        raw = projection.bytes_json(expected)
        scope = deepcopy(fixture.scope)
        scope["acquisitionBinding"]["expectedRelease"] = artifact(raw)
        before = deepcopy(scope)
        _, _, manifest_raw, report = fixture.project(scope=scope)
        manifest = json.loads(manifest_raw)
        self.assertEqual(scope, before)
        self.assertEqual(projection._revalidation_artifact(scope["acquisitionBinding"]["expectedRelease"], 65536)[0], raw)
        self.assertEqual(expected["observedUtcSeconds"], str(observed-86401))
        self.assertEqual(report["originalManualCheckedAtUtcSeconds"], fixture.original.original_checked)
        self.assertEqual(pipeline.parse_time(manifest["expiresAtUtc"]),
                         datetime.fromtimestamp(observed, timezone.utc)+timedelta(days=8))
        self.assertNotEqual(pipeline.parse_time(manifest["expiresAtUtc"]),
                            datetime.fromtimestamp(observed-86401, timezone.utc)+timedelta(days=8))
        with self.assertRaises(ValueError):
            fixture.project(scope=scope, now=datetime.fromtimestamp(observed+86400, timezone.utc))
        for value in (None, True, "0", " 1792970375", "1792970375.0"):
            invalid = dict(expected, observedUtcSeconds=value)
            with self.subTest(expectedTimestamp=value), self.assertRaises(ValueError):
                projection.release_binding(invalid)

    def test_selector_metadata_terms_signature_and_expiry(self):
        fixture = self.fixture()
        for field, value in (("payloadUrl", "https://www.intel.com/other.zip"), ("fileName", "other.zip"),
                             ("packageVersion", "99.7.5"), ("bodySha256", "0"*64),
                             ("termsRevision", "changed"), ("termsText", "changed")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.project(release=dict(fixture.release, **{field: value}))
        for field, value in (("state", 0), ("contentError", 13), ("identityError", 13),
                             ("publishedIdentityKnown", False), ("verifiedPublisher", ""),
                             ("infIdentity", "other.inf"), ("classGuid", "wrong"),
                             ("driverVersion", ""), ("models", [])):
            inspection = deepcopy(fixture.inspection)
            inspection["infs"][0][field] = value
            with self.subTest(inf=field), self.assertRaises(ValueError):
                fixture.project(inspection=inspection)
        for path in ("../other.inf", "C:/other.inf", "/other.inf", "NEW\\other.inf", "NEW//other.inf"):
            scope = deepcopy(fixture.scope)
            scope["acquisitionBinding"]["selectedInf"] = path
            with self.subTest(selector=path), self.assertRaises(ValueError):
                fixture.project(scope=scope)
        for value in (0, -1, True, 1.5, 134217729):
            release = dict(fixture.release, publishedSizeBytes=value)
            with self.subTest(exact=value), self.assertRaises(ValueError):
                projection.release_binding(release)
        for observed in ("1", str(int(fixture.now.timestamp())+1)):
            inspection = dict(fixture.inspection, contentCheckedUtcSeconds=observed)
            with self.subTest(time=observed), self.assertRaises(ValueError):
                fixture.project(inspection=inspection)
        with self.assertRaises(ValueError):
            fixture.project(now=fixture.now+timedelta(days=1))

    def test_changed_script_requires_complete_external_technical_review(self):
        fixture = self.fixture()
        source = base64.b64decode(fixture.script["scriptBytesBase64"]) + b"\n// Artificial reviewed update"
        fixture.script.update(scriptBytesBase64=base64.b64encode(source).decode(), scriptSizeBytes=len(source),
                              scriptSha256=hashlib.sha256(source).hexdigest())
        with self.assertRaisesRegex(ValueError, "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED"):
            fixture.refresh_review()
        technical_review = json.loads(fixture.originals["review"])
        # 技術reviewは新body/metadata/scriptの明示入力。元の許諾同意とは別に保持する。
        technical_review.update(pageSha256=fixture.release["bodySha256"], payloadUrl=fixture.release["payloadUrl"],
                                scriptSha256=fixture.script["scriptSha256"], checkedAtUtcSeconds=int(fixture.now.timestamp())-10)
        fixture.originals.update(bindingBody=fixture.body, bindingRelease=projection.bytes_json(fixture.release),
                                bindingScript=projection.bytes_json(fixture.script), bindingReview=projection.bytes_json(technical_review))
        fixture.refresh_review()
        self.assertEqual(fixture.project()[3]["realContentInspected"], 1)
        self.assertEqual(fixture.review["originalManualCheckedAtUtcSeconds"], fixture.original.original_checked)
        technical_review["checkedAtUtcSeconds"] = int(fixture.now.timestamp())-1
        fixture.originals["bindingReview"] = projection.bytes_json(technical_review)
        with self.assertRaisesRegex(ValueError, "TERMS_REVIEW_TIME"):
            fixture.refresh_review()
        fixture.originals.pop("bindingReview")
        with self.assertRaises(ValueError):
            fixture.refresh_review()

    def test_real_byte_identity_inspection_fake_six_inputs_and_audit(self):
        for algorithm in ("sha256", "sha512", "both"):
            with self.subTest(algorithm=algorithm), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(algorithm)
                root = Path(temporary)
                archive, receipt_path = root/"artificial.zip", root/"artificial.json"
                archive.write_bytes(fixture.payload)
                receipt_path.write_bytes(pipeline.canonical(fixture.receipt))
                commands = []
                class FakeBudget:
                    """実byte/hash引数を検査してから、内容検査結果だけをfakeする。"""
                    def run(inner, argv, **kwargs):
                        commands.append(argv)
                        command = argv[1]
                        if command == "--verify-daily-reservation":
                            return 0, (f"COLLECTOR_RESERVATION error=0 mode=FRESH_INPUT generation=12 receipt_sha256={pipeline.sha(receipt_path.read_bytes())}").encode(), b""
                        if command == "--inspect-collected-package":
                            self.assertEqual(argv[3], hashlib.sha256(fixture.payload).hexdigest())
                            self.assertEqual(argv[5], "NEW\\Winx64\\W11\\fake99.inf")
                            Path(argv[4]).write_bytes(pipeline.canonical(fixture.inspection))
                        else:
                            document = fixture.release if command == "--parse-collected-release" else fixture.script
                            self.assertIn(command, {"--parse-collected-release", "--collect-terms-link-script"})
                            Path(argv[-1]).write_bytes(pipeline.canonical(document))
                        return 0, b"ARTIFICIAL_ONLY", b""
                with patch.object(pipeline, "operation_root", side_effect=lambda path: path), \
                     patch.object(pipeline, "protected_tree"), patch.object(pipeline, "protected_path"), \
                     patch.object(pipeline, "utc", return_value=fixture.now):
                    result = pipeline.prepare_daily_acquisition_inputs({"collectorExe": "FAKE", "signerExe": "FAKE",
                        "manifestFile": "FAKE", "stateRoot": "FAKE"}, pipeline.canonical(fixture.scope), receipt_path,
                        fixture.originals, fixture.pins, archive, fixture.scope["acquisitionBinding"]["selectedInf"],
                        FakeBudget(), terms_review_mode=projection.PINNED_STATIC_REVALIDATION_V2)
                self.assertEqual(len(commands), 4)
                _, packed, manifest, _ = result["projection"]
                envelope = pipeline.canonical({"schema": "driver-index-envelope-v1", "keyId": fixture.scope["keyId"],
                    "manifestBytesBase64": base64.b64encode(manifest).decode(), "signatureBase64": base64.b64encode(bytes(384)).decode()})
                audited = pipeline.audit_daily_distribution_acquisition_bundle({"manifest.json": envelope, "index.json.gz": packed},
                    result["inputs"], result["inputPins"], generation=12, published_at=fixture.now, now=fixture.now,
                    terms_review_mode=projection.PINNED_STATIC_REVALIDATION_V2)
                self.assertEqual(audited["generation"], 12)
                self.assertEqual(set(result["inputs"]), {"scope", "evidence", "release", "inspection", "review", "script"})

    def test_fresh_wrapper_uses_new_expected_and_writes_complete_six_file_bundle(self):
        """fresh入口の承認/実byte/六fileを新metadataへ閉じ、旧archive pinを代用しない。"""
        fixture = self.fixture("sha512")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = {"schema": "dc-private-daily-index-config-v2", "purpose": pipeline.ACQUISITION_PURPOSE,
                      "outputRoot": str(directory), "stateRoot": "ARTIFICIAL_STATE",
                      "selectedInf": fixture.scope["acquisitionBinding"]["selectedInf"],
                      "termsReviewMode": projection.PINNED_STATIC_REVALIDATION_V2}
            for name, digest_field, content in (("collectorExe", "collectorSha256", b"ARTIFICIAL_COLLECTOR"),
                    ("signerExe", "signerSha256", b"ARTIFICIAL_SIGNER"),
                    ("manifestFile", "manifestSha256", b"ARTIFICIAL_MANIFEST"),
                    ("scopeFile", "scopeSha256", pipeline.canonical(fixture.scope))):
                path = directory/name
                path.write_bytes(content)
                config[name], config[digest_field] = str(path), pipeline.sha(content)
            receipt_path = directory/"fresh-artificial.json"
            calls = []
            class FakeBudget:
                """実processを呼ばず、nativeの明示承認argvと保存byteを有限確認する。"""
                def remaining(inner, maximum):
                    """人工runの残予算だけを返し、実待機やdeadline延長を行わない。"""
                    return maximum

                def run(inner, argv, **kwargs):
                    calls.append(argv)
                    command = argv[1]
                    if command == "--daily-acquire":
                        approved = Path(argv[5]).read_bytes()
                        self.assertEqual(pipeline.sha(approved), argv[6])
                        self.assertEqual(approved, projection._revalidation_artifact(
                            fixture.scope["acquisitionBinding"]["expectedRelease"], 65536)[0])
                        self.assertNotEqual(approved, fixture.originals["release"])
                        self.assertEqual(json.loads(approved)["publishedSha256"], "")
                        Path(argv[4]).write_bytes(pipeline.canonical(fixture.receipt))
                        Path(argv[4]).with_suffix(".payload.zip").write_bytes(fixture.payload)
                        return 0, b"COLLECTOR_PAYLOAD save_error=0 held=0 not_before=123 stage=0 acquired=1 installed=0\n", b""
                    if command == "--verify-daily-reservation":
                        return 0, (f"COLLECTOR_RESERVATION error=0 mode=FRESH_INPUT generation=12 receipt_sha256={pipeline.sha(receipt_path.read_bytes())}").encode(), b""
                    if command == "--inspect-collected-package":
                        self.assertEqual(argv[3], hashlib.sha256(fixture.payload).hexdigest())
                        Path(argv[4]).write_bytes(pipeline.canonical(fixture.inspection))
                    else:
                        self.assertIn(command, {"--parse-collected-release", "--collect-terms-link-script"})
                        Path(argv[-1]).write_bytes(pipeline.canonical(fixture.release if command == "--parse-collected-release" else fixture.script))
                    return 0, b"ARTIFICIAL_ONLY", b""
            with patch.object(pipeline, "operation_root", side_effect=lambda path: path), \
                 patch.object(pipeline, "protected_tree"), patch.object(pipeline, "protected_path"), \
                 patch.object(pipeline, "utc", return_value=fixture.now), patch.object(pipeline, "exclusive", return_value=nullcontext()), \
                 patch.object(pipeline, "require_config_workspace"), patch.object(pipeline, "validate_v2_code"), \
                 patch.object(pipeline, "acquisition_originals", return_value=(fixture.originals, fixture.pins)):
                result = pipeline.prepare_fresh_daily_acquisition_inputs(config, receipt_path, maximum_bytes=4096,
                    consent_not_after=int(fixture.now.timestamp())+3600, accept_pinned_terms=True, budget=FakeBudget())
            self.assertEqual(result["status"], "PREPARED_UNSIGNED")
            self.assertEqual(len(calls), 5)
            raw = Path(result["nativeInputsFile"]).read_bytes()
            self.assertEqual(pipeline.sha(raw), result["nativeInputsSha256"])
            inputs = json.loads(raw)["inputs"]
            self.assertEqual(set(inputs), {"scope", "evidence", "release", "inspection", "review", "script"})
            for item in inputs.values():
                self.assertEqual(pipeline.sha(Path(item["file"]).read_bytes()), item["sha256"])


if __name__ == "__main__":
    unittest.main()
