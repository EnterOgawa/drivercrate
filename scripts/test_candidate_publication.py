"""汎用候補の手動prepare/signを自己所有file・fake native/Publicだけで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実鍵照会・署名・HTTP・Task・運用storeを操作しない。暗号の実検査はnative RAM試験で別確認する。
"""
from __future__ import annotations

import base64
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import daily_index_pipeline as pipeline
from test_daily_index_pipeline import PublicIdentityRemote


def fake_envelope(raw: bytes) -> bytes:
    """暗号成功とは異なる決定的な署名代役で、原manifest差替えを検出する。"""
    return pipeline.canonical({"schema": "driver-index-envelope-v1", "keyId": pipeline.projection.DISTRIBUTION_KEY_ID,
        "manifestBytesBase64": base64.b64encode(raw).decode(),
        "signatureBase64": base64.b64encode(hashlib.sha256(raw).digest() * 12).decode()})


class CandidateWorld:
    """保護ACLとnative/remote作用だけをfake化し、製品のprepare/sign制御をそのまま通す。"""

    def __init__(self, directory: Path, *, nested=False):
        self.stack = ExitStack()
        self.base = directory
        self.out = directory / "publication"
        self.out.mkdir()
        self.now = datetime(2026, 10, 24, 6, 0, tzinfo=timezone.utc)
        self.generation = 8
        self.calls = []
        self.fail_modes = {}
        self.sign_hook = None
        self.stack.enter_context(patch.object(pipeline, "protected_path"))
        self.stack.enter_context(patch.object(pipeline, "protected_tree"))
        self.stack.enter_context(patch.object(pipeline, "operation_root", side_effect=lambda value, **unused: value))
        self.stack.enter_context(patch.object(pipeline, "utc", side_effect=lambda: self.now))
        approval = pipeline.public_publisher_approval(pipeline.canonical(dict(pipeline.PUBLIC_APPROVAL_VALUES)))
        self.stack.enter_context(patch.object(pipeline, "validate_public_config", return_value=({}, approval)))
        self.config = {"schema": pipeline.PUBLIC_CONFIG_SCHEMA, "purpose": pipeline.ACQUISITION_PURPOSE,
            "outputRoot": str(self.out), "stateRoot": str(directory / "state"),
            "fingerprint": pipeline.projection.DISTRIBUTION_PUBLIC_FINGERPRINT, "ghExe": str(directory / "fake-gh.exe")}
        for name, filename, body, pin in (("signerExe", "DriverCrateLocalIndexSigner.exe", b"FAKE SIGNER", "signerSha256"),
                ("collectorExe", "DriverCrateCollector.exe", b"FAKE COLLECTOR", "collectorSha256"),
                ("manifestFile", "collector-manifest.json", b"FAKE MANIFEST", "manifestSha256")):
            path = directory / filename
            path.write_bytes(body)
            self.config[name], self.config[pin] = str(path), pipeline.sha(body)
        # sourceに固定された公開blobだけを読み、KSP/実永続鍵は照会しない。
        trust = (Path(__file__).resolve().parents[1] / "src/platform/index_distribution_trust.h").read_text(encoding="utf-8")
        public_blob = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})U", trust))
        assert len(public_blob) == 411 and pipeline.sha(public_blob) == self.config["fingerprint"]
        public_path = directory / "distribution.public.blob"
        public_path.write_bytes(public_blob)
        self.config["publicKeyFile"] = str(public_path)
        self.config_hash = pipeline.sha(pipeline.canonical(self.config))
        self.receipt_path = self.out / "current.collection.json"
        self.receipt_path.write_bytes(pipeline.canonical({"generation": self.generation, "original": "FAKE_NATIVE_RECEIPT"}))
        self.receipt_hash = pipeline.sha(self.receipt_path.read_bytes())
        self.native_receipt = self.receipt_path.read_bytes()
        self.head_path = directory / "monitor/distribution/candidate-head.json"
        self.source = self.head_path.parent / "runs" / ("run-" + "a" * 32)
        self.source.mkdir(parents=True)
        entries = []
        for ordinal in range(3):
            checked = self.now - timedelta(hours=3-ordinal)
            body = pipeline.canonical({"recordId": f"fixture-{ordinal}", "sourceId": "fixture-source",
                "publishedIdentityEvidence": {"nestedArchiveIdentity": "Drivers/Inner.zip" if nested else "",
                    "infIdentity": f"amd64/driver-{ordinal}.inf"},
                "acquisitionDescriptor": {"state": "KNOWN", "attestation": {
                    "checkedAtUtc": checked.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "validUntilUtc": (checked + timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")}}})
            entries.append({"recordBytesBase64": base64.b64encode(body).decode(), "recordSha256": pipeline.sha(body)})
        expanded = pipeline.cr.json_bytes({"schema": "driver-index-records-v2", "assetGeneration": 1,
            "sources": [{"sourceId": "fixture-source", "original": "UNSIGNED_SOURCE"}], "records": entries})
        packed = pipeline.candidate_publication_gzip(expanded)
        self.manifest = {"schema": "driver-index-manifest-v1", "repository": pipeline.REPOSITORY,
            "channel": "driver-index", "keyId": pipeline.projection.DISTRIBUTION_KEY_ID, "generation": 1, "assetGeneration": 1,
            "publishedAtUtc": "2026-10-24T05:30:00Z", "expiresAtUtc": "2026-11-01T03:00:00Z",
            "asset": {"tag": "index-v1-20261024-" + pipeline.sha(packed), "name": "index.json.gz", "compression": "gzip",
                "sizeBytes": len(packed), "sha256": pipeline.sha(packed)},
            "quality": {"sourceCount": 1, "recordCount": 3, "metadataOnlyCount": 0, "contentInspectedCount": 3, "unconfirmedCount": 0}}
        self.source_raw = {"index.json": expanded, "index.json.gz": packed,
            "manifest.raw.json": pipeline.cr.json_bytes(self.manifest),
            "build-report.json": pipeline.cr.json_bytes({"allTargetsSucceeded": False, "originalFailureCount": 1}),
            "provenance.json": pipeline.cr.json_bytes({"unsigned": True, "fixture": "not-private-authority"})}
        self.save_candidate()
        self.remote = PublicIdentityRemote()
        historical = deepcopy(self.manifest)
        historical.update(generation=5, assetGeneration=5, publishedAtUtc="2026-10-18T16:32:04Z",
            expiresAtUtc="2026-10-19T13:24:11Z")
        historical["asset"]["tag"] = "index-v1-20261018-" + pipeline.sha(packed)
        self.set_public(fake_envelope(pipeline.cr.json_bytes(historical)), packed)

    def close(self):
        """試験patchだけを解除し、保存原失敗は呼出し側が確認する。"""
        self.stack.close()

    def save_candidate(self):
        """公開dataの整合fixtureを生成し、実private観測やpermitは作らない。"""
        hashes = {name: pipeline.sha(body) for name, body in self.source_raw.items()}
        for name, body in self.source_raw.items():
            (self.source / name).write_bytes(body)
        validation = pipeline.canonical({"schema": "dc-collector-unsigned-validation-v1", "runId": self.source.name,
            "outputs": hashes, "unsigned": True, "authenticated": False, "recordCount": 3})
        (self.source / "unsigned-validation.json").write_bytes(validation)
        head = {"schema": "dc-collector-unsigned-candidate-head-v1", "generation": 1, "runId": self.source.name,
            "monitorIdentity": "a" * 64, "inputHashes": {"registry": "b" * 64, "locators": "c" * 64, "profiles": "d" * 64},
            "producerHashes": {"native": "e" * 64}, "packageManifestSha256": "f" * 64, "seedManifestSha256": "1" * 64,
            "includedCandidates": [], "outputs": hashes, "validationSha256": pipeline.sha(validation),
            "signingGenerationFinalized": False}
        self.head_raw = pipeline.cr.json_bytes(head)
        self.head_path.write_bytes(self.head_raw)
        (self.source / "build-commit.json").write_bytes(self.head_raw)
        self.head_hash = pipeline.sha(self.head_raw)

    def set_public(self, envelope: bytes, packed: bytes):
        """固定Public fakeのread-only branch/releaseをRAMへ直接配置する。remote writeは呼ばない。"""
        manifest, _ = pipeline.unpack_envelope(envelope)
        tag = manifest["asset"]["tag"]
        self.remote.head = "a" * 40
        self.remote.commits[self.remote.head] = {"tree": "b" * 40}
        self.remote.trees["b" * 40] = [{"path": "index/current.json", "mode": "100644", "type": "blob", "sha": "c" * 40}]
        self.remote.blobs["c" * 40] = envelope
        self.remote.assets = {1: envelope, 2: packed}
        self.remote.releases = {tag: {"tag_name": tag, "draft": False, "prerelease": True, "assets": [
            {"id": 1, "name": "manifest.json", "state": "uploaded", "size": len(envelope)},
            {"id": 2, "name": "index.json.gz", "state": "uploaded", "size": len(packed)}]}}

    def run(self, argv, **unused):
        """実行argvと元byteを検査するnative代役。暗号の実成功へ換算しない。"""
        self.calls.append(list(argv))
        mode = argv[1]
        if mode in self.fail_modes:
            return self.fail_modes[mode], b"FAKE_NATIVE_REJECTED", b""
        if mode == "--verify-daily-reservation":
            body = Path(argv[4]).read_bytes()
            if body != self.native_receipt or pipeline.cr.parse_json(body)["generation"] != self.generation:
                return 2, b"FAKE_NATIVE_HEAD_MISMATCH", b""
            assert argv[5] == "LEGACY_FENCE"
            return 0, (f"COLLECTOR_RESERVATION error=0 mode=LEGACY_FENCE generation={self.generation} "
                f"receipt_sha256={pipeline.sha(body)}").encode(), b""
        if mode == "--validate-unsigned-index-candidate":
            assert Path(argv[2]).is_file() and Path(argv[3]).is_file()
            return 0, b"UNSIGNED_FAKE", b""
        if mode == "--distribution-acquisition-sign":
            body = Path(argv[2]).read_bytes()
            if self.sign_hook:
                return self.sign_hook(argv, body)
            Path(argv[4]).write_bytes(fake_envelope(body))
            return 0, b"FAKE_SIGNER_EXIT_ZERO", b""
        if mode in {"--distribution-verify-history", "--distribution-acquisition-verify-history",
                    "--distribution-acquisition-verify"}:
            body = Path(argv[2]).read_bytes()
            manifest, raw = pipeline.unpack_envelope(body)
            if body != fake_envelope(raw):
                return 2, b"FAKE_SIGNATURE_MISMATCH", b""
            if mode.endswith("history"):
                assert len(argv) == 7 and int(argv[6]) == int(pipeline.parse_time(manifest["publishedAtUtc"]).timestamp())
            elif self.now >= pipeline.parse_time(manifest["expiresAtUtc"]):
                return 2, b"FAKE_EXPIRED", b""
            return 0, b"FAKE_NATIVE_VERIFIED", b""
        raise AssertionError(argv)

    def prepare(self, **kwargs):
        """製品入口を同じconfigと人工native/remoteへ接続する。"""
        return pipeline.prepare_candidate_publication(self.config, self.config_hash, self.head_path, self.head_hash,
            self.receipt_path, self.receipt_hash, head_profile=kwargs.pop("head_profile", "METADATA_ONLY"),
            budget=self, remote=self.remote, **kwargs)

    def sign(self, prepared, **kwargs):
        """明示claim/pinの製品署名入口をfake nativeだけで実行する。"""
        return pipeline.sign_candidate_publication(self.config, self.config_hash, self.head_path, self.head_hash,
            self.receipt_path, self.receipt_hash, self.out / prepared["claimName"], prepared["claimSha256"],
            self.config["fingerprint"], budget=self, remote=self.remote, **kwargs)

    def add_old_claim(self, generation: int, *, raw_hash="4" * 64):
        """現役固定scopeの未確定claimを生成し、署名/公開済みとは表示しない。"""
        pins = {name: "2" * 64 for name in ("scope", "evidence", "release", "inspection", "review", "script")}
        claim = {"schema": "dc-distribution-issuance-claim-v1", "state": "SIGNING_INTENT", "purpose": pipeline.ACQUISITION_PURPOSE,
            "generation": generation, "assetGeneration": generation, "inputPins": pins,
            "termsReviewMode": pipeline.projection.PINNED_STATIC_REVALIDATION_V1,
            "reservation": {"mode": "FRESH_INPUT", "generation": generation, "receiptSha256": pins["evidence"]},
            "previousReceiptSha256": "3" * 64, "publishedAtUtc": "2026-10-18T16:32:04Z", "expiresAtUtc": "2026-10-19T13:24:11Z",
            "rawManifestSha256": raw_hash, "gzipSha256": "5" * 64, "scopeSha256": pins["scope"],
            "keyId": pipeline.projection.DISTRIBUTION_KEY_ID, "fingerprint": self.config["fingerprint"],
            "legacyConfigSha256": "6" * 64, "legacyReservationFence": {"generation": 4, "receiptSha256": "7" * 64}}
        path = self.out / f"issuance-v1-{generation:016d}.claim.json"
        path.write_bytes(pipeline.canonical(claim))
        return path


class CandidatePublicationTests(unittest.TestCase):
    """原期限・世代・一回署名・停止窓の有限な意味を確認する。"""

    def world(self, **kwargs):
        """variantごとのfileとpatchの所有をtest終了へ結ぶ。"""
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="dc-publication-")))
        world = CandidateWorld(directory, **kwargs)
        self.addCleanup(world.close)
        return world

    def test_prepare_flat_nested_multiple_records_keep_original_bytes_and_report(self):
        for nested in (False, True):
            world = self.world(nested=nested)
            original = dict(world.source_raw)
            result = world.prepare()
            self.assertEqual((result["status"], result["generation"], result["signed"], result["published"]),
                ("PREPARED_UNSIGNED", 9, False, False))
            paths = pipeline.candidate_publication_paths(world.out, 9)
            before = pipeline.cr.parse_json(original["index.json"])
            after = pipeline.cr.parse_json(paths["index.json"].read_bytes())
            self.assertEqual((before["records"], before["sources"]), (after["records"], after["sources"]))
            self.assertEqual(after["assetGeneration"], 9)
            manifest = pipeline.cr.parse_json(paths["manifest.raw.json"].read_bytes())
            self.assertEqual(manifest["expiresAtUtc"], "2026-11-01T03:00:00Z")
            self.assertEqual(manifest["publishedAtUtc"], "2026-10-24T06:00:00Z")
            self.assertEqual((manifest["generation"], manifest["assetGeneration"]), (9, 9))
            self.assertEqual(manifest["asset"]["sha256"], pipeline.sha(paths["index.json.gz"].read_bytes()))
            self.assertEqual(world.source_raw, original)
            self.assertEqual({name: (world.source / name).read_bytes() for name in original}, original)
            self.assertFalse(any(call[1].endswith("-sign") for call in world.calls))
            self.assertTrue(all(event[0] == "GET" for event in world.remote.events))
            self.assertFalse(paths["manifest.json"].exists())

    def test_prepare_reuses_same_generation_and_time_without_extending_expiry(self):
        world = self.world()
        first = world.prepare()
        before = {path.name: path.read_bytes() for path in world.out.glob("candidate-publication-*.*")}
        world.now += timedelta(minutes=1)
        self.assertEqual(world.prepare(), first)
        self.assertEqual({path.name: path.read_bytes() for path in world.out.glob("candidate-publication-*.*")}, before)

    def test_prepare_all_four_save_windows_resume_exactly(self):
        for stop in ("CLAIM_RESERVED", "index.json", "index.json.gz", "manifest.raw.json"):
            world = self.world()
            def interrupt(stage):
                if stage == stop:
                    raise ValueError("ARTIFICIAL_PREPARE_STOP")
            with self.assertRaisesRegex(ValueError, "ARTIFICIAL_PREPARE_STOP"):
                world.prepare(checkpoint=interrupt)
            claim_path = next(world.out.glob("issuance-v1-*.claim.json"))
            original = claim_path.read_bytes()
            world.now += timedelta(minutes=1)
            resumed = world.prepare()
            self.assertEqual(resumed["generation"], 9)
            self.assertEqual(claim_path.read_bytes(), original)
            self.assertEqual(len(list(world.out.glob("issuance-v1-*.claim.json"))), 1)

    def test_existing_unpublished_and_unknown_reservations_are_never_reused(self):
        world = self.world()
        prior = world.add_old_claim(12)
        original = prior.read_bytes()
        self.assertEqual(world.prepare()["generation"], 13)
        self.assertEqual(prior.read_bytes(), original)

    def test_public_generation_above_native_and_local_is_the_floor(self):
        world = self.world()
        old = world.remote.blobs["c" * 40]
        manifest, _ = pipeline.unpack_envelope(old)
        manifest.update(generation=30, assetGeneration=30)
        world.set_public(fake_envelope(pipeline.cr.json_bytes(manifest)), world.remote.assets[2])
        self.assertEqual(world.prepare()["generation"], 31)

    def test_overflow_and_same_generation_different_body_refuse(self):
        world = self.world()
        world.add_old_claim(pipeline.PUBLICATION_MAX_GENERATION)
        with self.assertRaisesRegex(ValueError, "CANDIDATE_GENERATION_OVERFLOW"):
            world.prepare()
        other = self.world()
        other.add_old_claim(5)
        with self.assertRaisesRegex(ValueError, "CANDIDATE_SAME_GENERATION_CONFLICT"):
            other.prepare()

    def test_unknown_missing_corrupt_and_wrong_purpose_head_refuse_without_reset(self):
        for variant in ("missing", "signature", "unknown-profile", "native-purpose", "foreign-content"):
            world = self.world()
            if variant == "missing":
                world.remote.head = None
            elif variant == "signature":
                value = pipeline.cr.parse_json(world.remote.assets[1])
                value["signatureBase64"] = base64.b64encode(b"Q" * 384).decode()
                world.set_public(pipeline.canonical(value), world.remote.assets[2])
            elif variant == "native-purpose":
                world.fail_modes["--distribution-verify-history"] = 2
            elif variant == "foreign-content":
                world.remote.foreign = True
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                world.prepare(head_profile="UNKNOWN" if variant == "unknown-profile" else "METADATA_ONLY")
            self.assertEqual(list(world.out.glob("issuance-v1-*.claim.json")), [])
            self.assertFalse(any(call[1].endswith("-sign") for call in world.calls))

    def test_corrupt_unknown_or_orphan_local_history_refuses(self):
        for variant in ("partial", "unknown", "name", "float", "orphan"):
            world = self.world()
            path = world.add_old_claim(12)
            if variant == "partial":
                path.write_bytes(b"{")
            elif variant == "orphan":
                (world.out / "candidate-publication-0000000000000013.manifest.json").write_bytes(b"orphan")
            else:
                claim = pipeline.cr.parse_json(path.read_bytes())
                if variant == "unknown":
                    claim["schema"] = "UNKNOWN"
                elif variant == "name":
                    claim.update(generation=13, assetGeneration=13)
                    claim["reservation"]["generation"] = 13
                else:
                    claim["generation"] = 12.0
                path.write_bytes(pipeline.canonical(claim))
            original = path.read_bytes()
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                world.prepare()
            self.assertEqual(path.read_bytes(), original)

    def test_original_expiry_minimum_future_and_unknown_clock_refuse(self):
        for variant in ("expired", "future", "minimum", "clock", "naive-clock"):
            world = self.world()
            if variant == "expired":
                world.now = pipeline.parse_time(pipeline.cr.parse_json(world.source_raw["manifest.raw.json"])["expiresAtUtc"])
            elif variant in {"future", "minimum"}:
                manifest = pipeline.cr.parse_json(world.source_raw["manifest.raw.json"])
                manifest["publishedAtUtc" if variant == "future" else "expiresAtUtc"] = "2026-10-26T06:00:00Z"
                world.source_raw["manifest.raw.json"] = pipeline.cr.json_bytes(manifest)
                world.save_candidate()
            elif variant == "clock":
                world.now = None
            else:
                world.now = world.now.replace(tzinfo=None)
            with self.subTest(variant=variant), self.assertRaises((ValueError, AttributeError)):
                world.prepare()
            self.assertFalse(any(call[1].endswith("-sign") for call in world.calls))

    def test_input_hash_record_base64_source_commit_and_runtime_tamper_refuse(self):
        for variant in ("head", "record", "base64", "source-output", "commit", "runtime", "key", "native-head"):
            world = self.world()
            if variant == "head":
                world.head_path.write_bytes(world.head_raw + b" ")
            elif variant in {"record", "base64"}:
                index = pipeline.cr.parse_json(world.source_raw["index.json"])
                index["records"][0]["recordSha256" if variant == "record" else "recordBytesBase64"] = "0" * 64 if variant == "record" else "%%%"
                world.source_raw["index.json"] = pipeline.cr.json_bytes(index)
                world.source_raw["index.json.gz"] = pipeline.candidate_publication_gzip(world.source_raw["index.json"])
                world.save_candidate()
            elif variant == "source-output":
                (world.source / "provenance.json").write_bytes(b"changed")
            elif variant == "commit":
                (world.source / "build-commit.json").write_bytes(b"changed")
            elif variant in {"runtime", "key"}:
                Path(world.config["signerExe" if variant == "runtime" else "publicKeyFile"]).write_bytes(b"changed")
            else:
                world.generation += 1
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                world.prepare()
            self.assertFalse(any(call[1].endswith("-sign") for call in world.calls))

    def test_native_unsigned_rejection_is_not_turned_into_signing_permission(self):
        world = self.world()
        world.fail_modes["--validate-unsigned-index-candidate"] = 2
        with self.assertRaisesRegex(ValueError, "CANDIDATE_UNSIGNED_REJECTED"):
            world.prepare()
        self.assertEqual(world.remote.events, [])
        self.assertEqual(list(world.out.glob("issuance-v1-*.claim.json")), [])

    def test_explicit_sign_and_verified_resume_call_native_sign_once_and_never_publish(self):
        world = self.world(nested=True)
        prepared = world.prepare()
        first = world.sign(prepared)
        self.assertEqual((first["status"], first["resumed"], first["published"]), ("SIGNED_NOT_PUBLISHED", False, False))
        world.now += timedelta(minutes=1)
        second = world.sign(prepared)
        self.assertTrue(second["resumed"])
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)
        self.assertTrue(all(event[0] == "GET" for event in world.remote.events))
        paths = pipeline.candidate_publication_paths(world.out, 9)
        self.assertEqual(pipeline.unpack_envelope(paths["manifest.json"].read_bytes())[1], paths["manifest.raw.json"].read_bytes())

    def test_sign_intent_missing_envelope_refuses_and_returned_valid_envelope_resumes_without_resign(self):
        for stop in ("SIGNING_INTENT", "SIGNER_RETURNED"):
            world = self.world()
            prepared = world.prepare()
            def interrupt(stage):
                if stage == stop:
                    raise ValueError("ARTIFICIAL_SIGN_STOP")
            with self.assertRaisesRegex(ValueError, "ARTIFICIAL_SIGN_STOP|CANDIDATE_SIGNING_OUTCOME_UNKNOWN"):
                world.sign(prepared, checkpoint=interrupt)
            count = sum(call[1] == "--distribution-acquisition-sign" for call in world.calls)
            if stop == "SIGNING_INTENT":
                with self.assertRaisesRegex(ValueError, "CANDIDATE_SIGNING_OUTCOME_UNKNOWN"):
                    world.sign(prepared)
            else:
                original = pipeline.candidate_publication_paths(world.out, 9)["signing-result.json"].read_bytes()
                recovered = world.sign(prepared)
                self.assertEqual(recovered["status"], "SIGNED_NOT_PUBLISHED")
                self.assertFalse(recovered["originalSigningOutcomeKnown"])
                self.assertEqual(pipeline.candidate_publication_paths(world.out, 9)["signing-result.json"].read_bytes(), original)
            self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), count)

    def test_partial_nonzero_or_exception_keeps_failure_and_never_resigns(self):
        for variant in ("nonzero", "partial", "exception"):
            world = self.world()
            prepared = world.prepare()
            def fail(argv, raw):
                if variant == "partial":
                    Path(argv[4]).write_bytes(b"{")
                if variant == "exception":
                    raise OSError("ARTIFICIAL_NATIVE_EXCEPTION")
                return 2, b"ARTIFICIAL_NONZERO", b""
            world.sign_hook = fail
            with self.assertRaises(ValueError):
                world.sign(prepared)
            path = pipeline.candidate_publication_paths(world.out, 9)["signing-result.json"]
            original = path.read_bytes()
            self.assertEqual(pipeline.cr.parse_json(original)["status"], "UNKNOWN_NO_RE_SIGN")
            self.assertEqual(pipeline.cr.parse_json(original)["childExitCode"], None if variant == "exception" else 2)
            with self.assertRaises(ValueError):
                world.sign(prepared)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_sign_rechecks_public_local_floor_expiry_and_all_pins(self):
        for variant in ("public", "native", "later-claim", "expiry", "runtime", "candidate", "output", "ready", "claim"):
            world = self.world()
            prepared = world.prepare()
            paths = pipeline.candidate_publication_paths(world.out, 9)
            if variant == "public":
                manifest, _ = pipeline.unpack_envelope(world.remote.assets[1])
                manifest.update(generation=6, assetGeneration=6)
                world.set_public(fake_envelope(pipeline.cr.json_bytes(manifest)), world.remote.assets[2])
            elif variant == "native":
                world.generation += 1
            elif variant == "later-claim":
                world.add_old_claim(12)
            elif variant == "expiry":
                world.now = pipeline.parse_time(pipeline.cr.parse_json(world.source_raw["manifest.raw.json"])["expiresAtUtc"])
            elif variant == "runtime":
                Path(world.config["signerExe"]).write_bytes(b"changed")
            elif variant == "candidate":
                (world.source / "index.json").write_bytes(b"changed")
            elif variant == "claim":
                (world.out / prepared["claimName"]).write_bytes(b"changed")
            else:
                paths["ready.json" if variant == "ready" else "index.json.gz"].write_bytes(b"changed")
            with self.subTest(variant=variant), self.assertRaises((ValueError, KeyError)):
                world.sign(prepared)
            self.assertFalse(any(call[1].endswith("-sign") for call in world.calls))

    def test_claim_and_fingerprint_cannot_grant_permission_and_signed_body_must_match(self):
        world = self.world()
        prepared = world.prepare()
        with self.assertRaisesRegex(ValueError, "CANDIDATE_SIGN_FINGERPRINT"):
            pipeline.sign_candidate_publication(world.config, world.config_hash, world.head_path, world.head_hash,
                world.receipt_path, world.receipt_hash, world.out / prepared["claimName"], prepared["claimSha256"],
                "0" * 64, budget=world, remote=world.remote)
        self.assertFalse(any(call[1].endswith("-sign") for call in world.calls))
        def wrong_body(argv, raw):
            value = pipeline.cr.parse_json(raw)
            value["generation"] += 1
            Path(argv[4]).write_bytes(fake_envelope(pipeline.cr.json_bytes(value)))
            return 0, b"ARTIFICIAL_WRONG_BODY", b""
        world.sign_hook = wrong_body
        with self.assertRaisesRegex(ValueError, "CANDIDATE_SIGNED_MANIFEST_PIN"):
            world.sign(prepared)
        self.assertFalse(pipeline.candidate_publication_paths(world.out, 9)["signing-result.json"].exists())

    def test_post_sign_native_current_verification_is_required_before_success(self):
        world = self.world()
        prepared = world.prepare()
        world.fail_modes["--distribution-acquisition-verify"] = 2
        with self.assertRaisesRegex(ValueError, "CANDIDATE_NATIVE_VERIFY"):
            world.sign(prepared)
        del world.fail_modes["--distribution-acquisition-verify"]
        recovered = world.sign(prepared)
        self.assertFalse(recovered["originalSigningOutcomeKnown"])
        self.assertIsNone(recovered["originalChildExitCode"])
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_nonzero_with_complete_valid_envelope_recovers_artifact_and_keeps_original_failure(self):
        world = self.world()
        prepared = world.prepare()
        def nonzero(argv, raw):
            Path(argv[4]).write_bytes(fake_envelope(raw))
            return 2, b"ARTIFICIAL_EXIT_TWO_WITH_COMPLETE_OUTPUT", b""
        world.sign_hook = nonzero
        with self.assertRaisesRegex(ValueError, "CANDIDATE_SIGNING_OUTCOME_UNKNOWN"):
            world.sign(prepared)
        path = pipeline.candidate_publication_paths(world.out, 9)["signing-result.json"]
        original = path.read_bytes()
        result = world.sign(prepared)
        self.assertFalse(result["originalSigningOutcomeKnown"])
        self.assertEqual(result["originalChildExitCode"], 2)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_success_label_without_native_signature_does_not_resume(self):
        world = self.world()
        prepared = world.prepare()
        world.sign(prepared)
        paths = pipeline.candidate_publication_paths(world.out, 9)
        value = pipeline.cr.parse_json(paths["manifest.json"].read_bytes())
        value["signatureBase64"] = base64.b64encode(b"Q" * 384).decode()
        paths["manifest.json"].write_bytes(pipeline.canonical(value))
        result = pipeline.cr.parse_json(paths["signing-result.json"].read_bytes())
        result["envelopeSha256"] = pipeline.sha(paths["manifest.json"].read_bytes())
        paths["signing-result.json"].write_bytes(pipeline.canonical(result))
        with self.assertRaisesRegex(ValueError, "CANDIDATE_NATIVE_VERIFY"):
            world.sign(prepared)
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_cli_modes_are_explicit_and_mixed_old_run_arguments_refuse(self):
        base = ["prepare-candidate", "config.json", "--candidate-head", "head.json", "--candidate-head-sha256", "a" * 64,
            "--reservation-receipt", "receipt.json", "--reservation-receipt-sha256", "b" * 64,
            "--head-profile", "METADATA_ONLY"]
        self.assertEqual(pipeline.pipeline_arguments(base).mode, "prepare-candidate")
        sign = base[:]
        sign[0], sign[-2:] = "sign-candidate", ["--claim", "claim.json", "--claim-sha256", "c" * 64, "--fingerprint", "d" * 64]
        self.assertEqual(pipeline.pipeline_arguments(sign).mode, "sign-candidate")
        for argv in (base + ["--smoke"], base + ["--output", "out.json"], base + ["--claim", "claim.json"],
                     ["run", *base[1:]], sign + ["--head-profile", "METADATA_ONLY"]):
            with self.assertRaises(ValueError):
                pipeline.pipeline_arguments(argv)

    def test_incomplete_or_empty_producer_selection_rejects_before_main_load_or_phase_io(self):
        """全三phaseの欠損対/未指定を、config読取・root/lock/外部作用より前に拒否する。"""
        head = ["--candidate-head", "head", "--candidate-head-sha256", "a" * 64]
        native = ["--native-inputs", "native", "--native-inputs-sha256", "b" * 64]
        pairs = ([], head[:2], head[2:], native[:2], native[2:], head + native[:2], native + head[2:],
            head[:3] + ["invalid"], native[:3] + ["invalid"])
        for mode in ("prepare-candidate", "sign-candidate", "publish-candidate"):
            extra = (["--head-profile", pipeline.HISTORY_FLOOR] if mode == "prepare-candidate" else
                ["--claim", "claim", "--claim-sha256", "c" * 64, "--fingerprint", "d" * 64])
            if mode == "publish-candidate":
                extra += ["--envelope-sha256", "e" * 64]
            for selection in pairs:
                argv = ["pipeline", mode, "absent-config", "--reservation-receipt", "receipt",
                    "--reservation-receipt-sha256", "f" * 64, *extra, *selection]
                with self.subTest(mode=mode, selection=selection), \
                        patch.object(pipeline.sys, "argv", argv), \
                        patch.object(pipeline, "load_config", side_effect=AssertionError("IO_NOT_ALLOWED")) as load:
                    with self.assertRaisesRegex(ValueError, "CANDIDATE_CLI_ARGUMENTS"):
                        pipeline.main()
                    load.assert_not_called()
        for generic_path, generic_hash, native in ((None, None, None), (Path("head"), None, None),
                (None, "a" * 64, None), (None, None, (Path("native"), None)),
                (Path("head"), "a" * 64, (None, "b" * 64))):
            common = ({}, "f" * 64, generic_path, generic_hash, Path("receipt"), "e" * 64)
            for mode in ("prepare", "sign", "publish"):
                with self.subTest(mode=mode, path=generic_path, native=native), \
                        patch.object(pipeline, "operation_root", side_effect=AssertionError("ROOT_NOT_ALLOWED")) as root:
                    with self.assertRaisesRegex(ValueError, "CANDIDATE_INPUT_SELECTION"):
                        if mode == "prepare":
                            pipeline.prepare_candidate_publication(*common, head_profile=pipeline.HISTORY_FLOOR,
                                native_inputs=native)
                        elif mode == "sign":
                            pipeline.sign_candidate_publication(*common, Path("claim"), "c" * 64, "d" * 64,
                                native_inputs=native)
                        else:
                            pipeline.publish_candidate_publication(*common, Path("claim"), "c" * 64, "d" * 64,
                                "e" * 64, native_inputs=native)
                    root.assert_not_called()

    def test_nullable_generic_claim_is_closed_and_requires_a_native_pin(self):
        """旧generic claimの閉fieldを維持し、片側nullや両系統欠如を履歴へ入れない。"""
        world = self.world()
        prepared = world.prepare()
        original = pipeline.cr.parse_json((world.out / prepared["claimName"]).read_bytes())
        native = dict(original, candidateHeadSha256=None, candidateOutputs=None, nativeInputsSha256="a" * 64)
        pipeline.validate_candidate_publication_claim(native)
        for changed in (dict(native, nativeInputsSha256=None), dict(native, candidateOutputs={}),
                dict(original, candidateOutputs=None), dict(native, candidateHeadSha256="a" * 64),
                dict(native, nativeInputsSha256="invalid"), dict(native, unknown=True)):
            with self.subTest(fields=changed), self.assertRaises(ValueError):
                pipeline.validate_candidate_publication_claim(changed)

    def test_main_dispatches_prepare_and_sign_without_daily_or_publisher_write(self):
        world = self.world()
        class FakeBudgetFactory:
            """isinstanceのtype契約を維持し、mainの全native作用を同じfakeへ結ぶ。"""
            def __new__(cls):
                return world
        base = ["prepare-candidate", str(world.base / "config.json"), "--candidate-head", str(world.head_path),
            "--candidate-head-sha256", world.head_hash, "--reservation-receipt", str(world.receipt_path),
            "--reservation-receipt-sha256", world.receipt_hash, "--head-profile", "METADATA_ONLY"]
        with patch.object(pipeline, "load_config", return_value=(world.config, {}, world.config_hash)), \
                patch.object(pipeline, "Budget", FakeBudgetFactory), \
                patch.object(pipeline, "GitHub", return_value=world.remote), \
                patch.object(pipeline, "run_pipeline", side_effect=AssertionError("DAILY_NOT_ALLOWED")), \
                patch.object(pipeline.Publisher, "publish", side_effect=AssertionError("WRITE_NOT_ALLOWED")), \
                patch.object(pipeline.sys, "argv", ["pipeline", *base]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(pipeline.main(), 0, output.getvalue())
        prepared = json.loads(output.getvalue())
        sign = base[:]
        sign[0], sign[-2:] = "sign-candidate", ["--claim", str(world.out / prepared["claimName"]),
            "--claim-sha256", prepared["claimSha256"], "--fingerprint", world.config["fingerprint"]]
        with patch.object(pipeline, "load_config", return_value=(world.config, {}, world.config_hash)), \
                patch.object(pipeline, "Budget", FakeBudgetFactory), \
                patch.object(pipeline, "GitHub", return_value=world.remote), \
                patch.object(pipeline.sys, "argv", ["pipeline", *sign]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(pipeline.main(), 0, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "SIGNED_NOT_PUBLISHED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
