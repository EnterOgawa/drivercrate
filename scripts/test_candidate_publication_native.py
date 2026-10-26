"""現producer原byte→手動prepare→製品共通codec→RAM認証通常appを有限確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
nativeはunsigned検査と既存RAM fixtureだけを起動する。永続鍵/production署名/実HTTPは呼ばない。
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_project_collected_native_index as native_fixture

import daily_index_pipeline as pipeline
from test_candidate_publication import CandidateWorld
from test_candidate_publish_path import PublicationWorld
from test_daily_index_pipeline import anonymous_stdout_fixture
from unittest.mock import patch

NATIVE = None
UNSIGNED = None
APPLICATION = None
SOURCE = None
OUTPUT = None


def native_run(label: str, argv: list[str]) -> tuple[int, str]:
    """自己所有logへ原argv/exitを残し、許可した二つの非永続native入口だけを呼ぶ。"""
    allowed = {"--validate-unsigned-index-candidate", "--validate-unsigned-fixture", "--distribution-application-fixture",
        "--distribution-application-native-merge-fixture"}
    assert argv[1] in allowed
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, creationflags=subprocess.CREATE_NO_WINDOW)
    log = OUTPUT / (label + "-" + str(native_run.ordinal))
    native_run.ordinal += 1
    log.with_suffix(".stdout.bin").write_bytes(result.stdout)
    log.with_suffix(".stderr.bin").write_bytes(result.stderr)
    log.with_suffix(".json").write_bytes(pipeline.cr.json_bytes({"argv": argv, "exitCode": result.returncode,
        "productionSigning": False, "realNetwork": 0, "stdoutEof": True, "stderrEof": True}))
    return result.returncode, result.stdout.decode("utf-8", errors="strict")


native_run.ordinal = 0


class NativeCandidateWorld(CandidateWorld):
    """元head/recordを公開dataとしてcopyし、unsigned validatorだけを実nativeへ接続する。"""

    def __init__(self, directory: Path):
        super().__init__(directory)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.native_selection = None
        self.anonymous_behavior = "success"
        self.stack.enter_context(patch.object(pipeline, "validate_v2_code"))
        for release in self.remote.releases.values():
            release["id"] = 1
        origin = SOURCE / "workspace/monitor/distribution"
        head_raw = (origin / "candidate-head.json").read_bytes()
        head = pipeline.cr.parse_json(head_raw)
        self.source = self.head_path.parent / "runs" / head["runId"]
        self.source.mkdir()
        self.source_raw = {name: (origin / "runs" / head["runId"] / name).read_bytes() for name in head["outputs"]}
        for name, raw in self.source_raw.items():
            (self.source / name).write_bytes(raw)
        for name in ("build-commit.json", "unsigned-validation.json"):
            (self.source / name).write_bytes((origin / "runs" / head["runId"] / name).read_bytes())
        self.head_raw = head_raw
        self.head_path.write_bytes(head_raw)
        self.head_hash = pipeline.sha(head_raw)

    def run(self, argv, *args, **kwargs):
        if argv[1] == "--distribution-verify-floor-history":
            proxy = list(argv)
            proxy[1] = "--distribution-acquisition-verify-history"
            return super().run(proxy, **kwargs)
        if argv[1] == "--validate-unsigned-index-candidate":
            self.calls.append(list(argv))
            code, output = native_run("production-unsigned", [str(UNSIGNED), *argv[1:]])
            return code, output.encode(), b""
        if argv[1] == "--public-index-readback":
            self.calls.append(list(argv))
            bundle = {"manifest.json": Path(argv[2]).read_bytes(), "index.json.gz": Path(argv[3]).read_bytes()}
            return 0, anonymous_stdout_fixture(bundle, self.now), b""
        return super().run(argv, **kwargs)

    def remaining(self, maximum=600):
        """実通信のない同PublicOperationBudgetへ有限枠だけを返す。"""
        return min(maximum, 1800)

    def publish(self, prepared, signed):
        """既存Publisherと匿名wire検査へ原署名束を渡す。実remoteはRAM fakeだけ。"""
        return PublicationWorld.publish(self, prepared, signed)


class NativePublicationTests(unittest.TestCase):
    """flat/nestedとも同じ三原recordと二sourceを新世代へ接続する。"""

    def world(self):
        path = Path(tempfile.mkdtemp(prefix="publication-native-", dir=OUTPUT))
        world = NativeCandidateWorld(path)
        self.addCleanup(world.close)
        return world

    def test_producer_original_bytes_prepared_header_real_codec_and_ram_application(self):
        world = self.world()
        before = deepcopy(world.source_raw)
        result = world.prepare()
        self.assertEqual((result["generation"], result["status"]), (9, "PREPARED_UNSIGNED"))
        paths = pipeline.candidate_publication_paths(world.out, 9)
        original = pipeline.cr.parse_json(before["index.json"])
        rebased = pipeline.cr.parse_json(paths["index.json"].read_bytes())
        self.assertEqual(len(original["records"]), 3)
        self.assertEqual(len(original["sources"]), 2)
        self.assertEqual((rebased["records"], rebased["sources"]), (original["records"], original["sources"]))
        times = [pipeline.cr.parse_json(base64.b64decode(row["recordBytesBase64"], validate=True))[
            "acquisitionDescriptor"]["attestation"]["validUntilUtc"] for row in rebased["records"]]
        self.assertGreater(len(set(times)), 1)
        manifest = pipeline.cr.parse_json(paths["manifest.raw.json"].read_bytes())
        self.assertEqual(manifest["expiresAtUtc"], min(times))
        self.assertEqual(manifest["expiresAtUtc"], pipeline.cr.parse_json(before["manifest.raw.json"])["expiresAtUtc"])
        signed = world.sign(result)
        published = world.publish(result, signed)
        self.assertEqual(published["status"], "PUBLISHED")
        self.assertEqual(published["publicAnonymousReadback"]["status"], "VERIFIED")
        release = world.remote.releases[manifest["asset"]["tag"]]
        returned = {
            entry["name"]: world.remote.assets[entry["id"]] for entry in release["assets"]}
        self.assertEqual(returned["index.json.gz"], paths["index.json.gz"].read_bytes())
        self.assertEqual(pipeline.unpack_envelope(returned["manifest.json"])[1], paths["manifest.raw.json"].read_bytes())
        returned_manifest, returned_gzip = world.base / "returned.manifest.raw.json", world.base / "returned.index.json.gz"
        returned_manifest.write_bytes(pipeline.unpack_envelope(returned["manifest.json"])[1])
        returned_gzip.write_bytes(returned["index.json.gz"])
        code, output = native_run("published-application", [str(APPLICATION), "--distribution-application-fixture",
            str(returned_manifest), str(returned_gzip), str(SOURCE / "package")])
        self.assertEqual(code, 0, output)
        self.assertIn("DISTRIBUTION_AUTHENTICATION assertions=153 ", output)
        self.assertIn("DISTRIBUTION_WEEKLY_APPLICATION days=7 originalExpiryUnchanged=1", output)
        self.assertIn("failures: 0", output)
        self.assertEqual(world.source_raw, before)
        self.assertEqual({name: (world.source / name).read_bytes() for name in before}, before)
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)
        self.assertEqual(world.remote.ref_updates, 1)
        (OUTPUT / "prepared.json").write_bytes(pipeline.cr.json_bytes({"source": str(SOURCE),
            "publicationRoot": str(world.out), "result": result, "originalRecordBytesUnchanged": True,
            "individualExpiries": times, "normalApplicationAssertions": 153, "ramKeysOnly": True,
            "productionIndexSigning": 0, "realNetwork": 0, "signatureSurrogateCalls": 1,
            "fakePublication": published, "originalRecordIds": [pipeline.cr.parse_json(base64.b64decode(
                row["recordBytesBase64"]))["recordId"] for row in original["records"]]}))

    def test_native_six_input_merge_fake_publication_and_same_four_record_ram_app(self):
        """追加Intel一recordを同集合へ保持し、既存三架空deviceへの不適切な照合をしない。"""
        world = self.world()
        fixture = native_fixture.PinnedStaticRevalidationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.now = world.now
        observed = int(world.now.timestamp()) - 30
        fixture.evidence["lastSuccessfulValidationAt"] = observed
        fixture.release["observedUtcSeconds"] = str(observed)
        fixture.script.update(pageObservedUtcSeconds=str(observed), scriptObservedUtcSeconds=str(observed + 10))
        fixture.inspection["contentCheckedUtcSeconds"] = str(observed + 15)
        fixture.receipt = native_fixture.ProjectionTests.daily_receipt(fixture, 200, world.generation)
        fixture.review = fixture.wrapper()
        documents = {name: pipeline.canonical(fixture.receipt if name == "evidence" else getattr(fixture, name))
            for name in ("scope", "evidence", "release", "inspection", "review", "script")}
        fixture.doCleanups()
        native_inputs = {"schema": "dc-candidate-native-inputs-v1", "inputs": {}}
        for name, body in documents.items():
            path = world.base / ("native-" + name + ".json")
            path.write_bytes(body)
            native_inputs["inputs"][name] = {"file": str(path), "sha256": pipeline.sha(body)}
        selected_path = world.base / "native-inputs.json"
        selected_path.write_bytes(pipeline.canonical(native_inputs))
        selected = (selected_path, pipeline.sha(selected_path.read_bytes()))
        world.native_selection = selected
        world.native_receipt = documents["evidence"]
        world.receipt_path.write_bytes(world.native_receipt)
        world.receipt_hash = pipeline.sha(world.native_receipt)
        world.config.update(scopeFile=native_inputs["inputs"]["scope"]["file"],
            scopeSha256=native_inputs["inputs"]["scope"]["sha256"],
            termsReviewMode=pipeline.projection.PINNED_STATIC_REVALIDATION_V1)
        world.config_hash = pipeline.sha(pipeline.canonical(world.config))
        original = pipeline.cr.parse_json(world.source_raw["index.json"])
        projected = pipeline.candidate_publication_native_inputs(world.config, selected,
            world.receipt_path, world.receipt_hash, world.now)
        native = pipeline.cr.parse_json(projected["index.json"])
        prepared = world.prepare(native_inputs=selected)
        signed = world.sign(prepared, native_inputs=selected)
        published = world.publish(prepared, signed)
        self.assertEqual(published["status"], "PUBLISHED")
        self.assertEqual(published["publicAnonymousReadback"]["status"], "VERIFIED")
        paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
        final = pipeline.cr.parse_json(paths["index.json"].read_bytes())
        self.assertEqual(final["records"], original["records"] + native["records"])
        self.assertEqual(final["sources"], original["sources"] + native["sources"])
        self.assertEqual((len(final["records"]), len(final["sources"])), (4, 3))
        release = world.remote.releases[published["tag"]]
        returned = {entry["name"]: world.remote.assets[entry["id"]] for entry in release["assets"]}
        self.assertEqual(returned["index.json.gz"], paths["index.json.gz"].read_bytes())
        returned_manifest, returned_gzip = world.base / "merged-returned.manifest.raw.json", world.base / "merged-returned.index.json.gz"
        returned_manifest.write_bytes(pipeline.unpack_envelope(returned["manifest.json"])[1])
        returned_gzip.write_bytes(returned["index.json.gz"])
        code, output = native_run("merged-published-application", [str(APPLICATION),
            "--distribution-application-native-merge-fixture", str(returned_manifest), str(returned_gzip), str(SOURCE / "package")])
        self.assertEqual(code, 0, output)
        self.assertIn("DISTRIBUTION_AUTHENTICATION assertions=154 ", output)
        self.assertIn("DISTRIBUTION_WEEKLY_APPLICATION days=7 originalExpiryUnchanged=1", output)
        self.assertIn("failures: 0", output)
        (OUTPUT / "merged-prepared.json").write_bytes(pipeline.cr.json_bytes({"publicationRoot": str(world.out),
            "source": str(SOURCE), "result": prepared, "fakePublication": published,
            "originalRecordWrappersUnchanged": True, "nativeOriginalInputs": native_inputs,
            "records": 4, "sources": 3, "unmatchedFixedNativeRecords": 1,
            "normalApplicationAssertions": 154, "realDeviceApplicability": None,
            "nativeRowLookupAcquisitionBindingPositiveProven": False,
            "ramKeyOnly": True, "productionSigning": 0, "externalHttp": 0}))

    def test_rebased_expiry_and_all_record_purpose_use_real_native_codec(self):
        world = self.world()
        result = world.prepare()
        paths = pipeline.candidate_publication_paths(world.out, result["generation"])
        manifest = pipeline.cr.parse_json(paths["manifest.raw.json"].read_bytes())
        expiry = pipeline.parse_time(manifest["expiresAtUtc"])
        code, _ = native_run("expired", [str(NATIVE), "--validate-unsigned-fixture", str(paths["manifest.raw.json"]),
            str(paths["index.json.gz"]), str(int(expiry.timestamp()))])
        self.assertEqual(code, 2)
        index = pipeline.cr.parse_json(paths["index.json"].read_bytes())
        for ordinal in range(len(index["records"])):
            changed = deepcopy(index)
            row = changed["records"][ordinal]
            record = pipeline.cr.parse_json(base64.b64decode(row["recordBytesBase64"], validate=True))
            record["acquisitionDescriptor"]["state"] = "UNKNOWN"
            body = pipeline.canonical(record)
            row.update(recordBytesBase64=base64.b64encode(body).decode(), recordSha256=pipeline.sha(body))
            packed = pipeline.candidate_publication_gzip(pipeline.cr.json_bytes(changed))
            mutated_manifest = deepcopy(manifest)
            mutated_manifest["asset"].update(sizeBytes=len(packed), sha256=pipeline.sha(packed),
                tag=f"index-v1-{world.now:%Y%m%d}-{pipeline.sha(packed)}")
            target = world.base / f"purpose-{ordinal}"
            target.mkdir()
            (target / "manifest.raw.json").write_bytes(pipeline.cr.json_bytes(mutated_manifest))
            (target / "index.json.gz").write_bytes(packed)
            code, _ = native_run("wrong-purpose", [str(UNSIGNED), "--validate-unsigned-index-candidate",
                str(target / "manifest.raw.json"), str(target / "index.json.gz")])
            self.assertEqual(code, 2)


def main():
    """明示native/元producer fixtureだけを借用し、実鍵や通信入口は起動しない。"""
    global NATIVE, UNSIGNED, APPLICATION, SOURCE, OUTPUT
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--unsigned", type=Path, required=True)
    parser.add_argument("--application", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    NATIVE, UNSIGNED, APPLICATION, SOURCE = (path.resolve(strict=True) for path in
        (args.native, args.unsigned, args.application, args.fixture))
    assert NATIVE.name == "drivercrate_collector_distribution_pipeline_tests.exe"
    assert UNSIGNED.name == "DriverCrateLocalIndexSigner.exe" and APPLICATION.name == "drivercrate_index_binding_tests.exe"
    OUTPUT = args.output.resolve()
    OUTPUT.mkdir()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativePublicationTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
