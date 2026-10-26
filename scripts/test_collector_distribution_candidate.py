"""実native producer出力と、非通信assembleの有限世代/期限fixtureを検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
親/pipeの正常・部分・全失敗は別の実native fixtureで確認する。本fileのassembly bridgeは
試験専用であり、公開receiptを製品のprivate観測や通信許可へ復元する入口ではない。
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import collector_distribution_pipeline as pipeline
import collector_registry as cr
import collector_workspace as workspace
import registry_daily_monitor as monitor
from test_collector_distribution_pipeline import Fixture, Bridge

NATIVE = None
SOURCE = None
OUTPUT = None


def artifacts(base: Path):
    """同じ実parentの候補headが参照した原byteだけを読む。"""
    store = base / "workspace/monitor"
    head = cr.read_json(store / "distribution/candidate-head.json")
    directory = store / "distribution/runs" / head["runId"]
    raw = {member: pipeline.profiles.read_raw(directory / member) for member in head["outputs"]}
    candidates = [cr.read_json(store / "distribution/runs" / reference["runId"] / reference["member"])
                  for reference in head["includedCandidates"]]
    return head, raw, candidates


def native_check(manifest: bytes, packed: bytes, now: datetime, *, shared=False):
    """実producer由来byteを製品の同じnative validator/内部codecへ渡す。"""
    directory = Path(tempfile.mkdtemp(prefix="codec-", dir=OUTPUT))
    (directory / "manifest.json").write_bytes(manifest)
    (directory / "index.json.gz").write_bytes(packed)
    command = [str(NATIVE), "--decode-index-fixture" if shared else "--validate-unsigned-fixture",
               str(directory / "manifest.json"), str(directory / "index.json.gz"),
               str(int(now.replace(tzinfo=timezone.utc).timestamp()))]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    (directory / "native-raw.txt").write_bytes(result.stdout)
    (directory / "command.json").write_text(json.dumps({"mode": command[1], "now": command[-1],
        "exit": result.returncode}, indent=2) + "\n", encoding="utf-8")
    return result.returncode, result.stdout.decode("utf-8", errors="strict")


def mutated(raw: dict[str, bytes], mutate):
    """実producerのrecordを一条件だけ変更し、実hash/GZip/qualityを保って負例を作る。"""
    manifest = cr.parse_json(raw["manifest.raw.json"])
    index = cr.parse_json(raw["index.json"])
    records = [cr.parse_json(base64.b64decode(row["recordBytesBase64"], validate=True)) for row in index["records"]]
    mutate(manifest, records)
    index["records"] = []
    for record in records:
        body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        index["records"].append({"recordBytesBase64": base64.b64encode(body).decode(), "recordSha256": cr.digest(body)})
    packed = gzip.compress(cr.json_bytes(index), mtime=0)
    digest = cr.digest(packed)
    manifest["asset"].update(sizeBytes=len(packed), sha256=digest)
    manifest["asset"]["tag"] = manifest["asset"]["tag"][:18] + digest
    return cr.json_bytes(manifest), packed


class AssemblyBridge(Bridge):
    """同じnative出力を値codec試験へ借用する試験seam。実parent能力ではない。"""

    def __init__(self, fixture, *, failures=(), empty=False):
        super().__init__(fixture)
        self.failures = set(failures)
        self.empty = empty
        self.rebuilds = 0

    def exchange(self, kind, run_id, plan_hash, **fields):
        if kind == "EXECUTE_JOB":
            result = super().exchange(kind, run_id, plan_hash, **fields)
            ordinal = fields["ordinal"]
            directory = self.fixture.store / "distribution/runs" / run_id
            job = cr.read_json(directory / f"job-{ordinal}.json")
            template = next(row for row in artifacts(SOURCE)[2] if row["job"]["recordId"] == job["recordId"])
            candidate = copy.deepcopy(template)
            candidate.update(job=job, jobSha256=cr.digest(cr.json_bytes(job)), binding={"runId": run_id,
                "ordinal": ordinal, "planHash": plan_hash, "inputHashes": self.context["inputHashes"],
                **{name: self.context[name] for name in ("monitorIdentity", "packageManifestSha256",
                                                       "seedManifestSha256", "producerHashes")}})
            if job["sourceId"] in self.failures or self.empty:
                candidate["records"] = []
                candidate["sources"] = []
                candidate["jobError"] = -2147467259 if not self.empty else 0
                result.update(status="FAILED" if not self.empty else "SUCCESS", reason="TEST_ONLY_FAILURE")
            result["candidateRecords"] = len(candidate["records"])
            result["candidateSha256"] = pipeline.save_json(directory / result["candidateMember"], candidate, replace=True)
            return result
        if kind != "FINISH_RUN" or fields["build"] is None:
            return super().exchange(kind, run_id, plan_hash, **fields)
        built = fields["build"]
        repeated = pipeline.build_candidate(self.fixture.package, self.fixture.root, run_id, self,
                                             clock=lambda: self.fixture.now)
        cr.require(repeated == built, "TEST_REBUILD_CHANGED")
        self.rebuilds += 1
        directory = self.fixture.store / "distribution/runs" / run_id
        code, text = native_check((directory / "manifest.raw.json").read_bytes(),
            (directory / "index.json.gz").read_bytes(), self.fixture.now)
        cr.require(code == 0 and "receipt=1 authenticated=0 keyOperations=0" in text,
                   "TEST_NATIVE_ASSEMBLY_VALIDATOR")
        member = "unsigned-validation.json"
        digest = pipeline.save_json(directory / member, {"schema": "dc-collector-unsigned-validation-v1",
            "runId": run_id, "outputs": built["outputs"], "unsigned": True, "authenticated": False})
        return {"validationMember": member, "validationSha256": digest}


def assembly_fixture():
    """世代/期限の検査だけへ自己所有fake monitorと同じ実producerデータを用意する。"""
    fixture = Fixture()
    for name in ("seed/distribution-data/manifest.json", "seed/distribution-data/registry.json",
                 "seed/distribution-data/collection-profiles.json", "seed/distribution-data/locators.json",
                 "seed/distribution-data/research-index.json",
                 "DriverCrateCollectorSetup.exe", "scripts/collector_distribution_pipeline.py",
                 "scripts/collector_collection_profiles.py"):
        shutil.copyfile(SOURCE / "package" / name, fixture.package / name)
    fixture.inputs, fixture.value, _ = pipeline.inputs_at(fixture.package)
    fixture.now = cr.timestamp(max(row["checkedAtUtc"] for row in artifacts(SOURCE)[2])) + timedelta(minutes=1)
    return fixture


class CandidateTests(unittest.TestCase):
    """実native byteと非通信assembleの世代・元期限・拒否を区別する。"""

    @classmethod
    def setUpClass(cls):
        if NATIVE is None or SOURCE is None or OUTPUT is None:
            raise unittest.SkipTest("explicit native fixture and output directory required")

    def test_actual_three_products_two_makers_new_inf_shared_descriptor(self):
        head, raw, candidates = artifacts(SOURCE)
        self.assertEqual(gzip.decompress(raw["index.json.gz"]), raw["index.json"])
        manifest = cr.parse_json(raw["manifest.raw.json"])
        self.assertEqual(manifest["quality"], {"sourceCount": 2, "recordCount": 3, "metadataOnlyCount": 0,
            "contentInspectedCount": 3, "unconfirmedCount": 0})
        products = [product for row in candidates for product in row["job"]["products"]]
        self.assertEqual((len(products), len({row["manufacturer"] for row in products})), (3, 2))
        a, b = candidates
        self.assertEqual(a["records"][0]["acquisitionDescriptor"], a["records"][1]["acquisitionDescriptor"])
        self.assertNotEqual(a["records"][0]["publishedIdentityEvidence"]["infIdentity"],
                            a["records"][1]["publishedIdentityEvidence"]["infIdentity"])
        self.assertNotEqual(a["records"][0]["packageEvidence"]["calculatedHash"]["sha256"],
                            b["records"][0]["packageEvidence"]["calculatedHash"]["sha256"])
        self.assertEqual(b["job"]["record"]["driverVersion"], "0.9.0.0")
        self.assertEqual(b["records"][0]["version"]["value"], "3.4.5.6")
        self.assertEqual(manifest["expiresAtUtc"], min(row["validUntilUtc"] for row in candidates))
        self.assertLess(a["validUntilUtc"], b["validUntilUtc"])
        self.assertFalse(head["signingGenerationFinalized"])
        now = cr.timestamp(manifest["publishedAtUtc"])
        code, checked = native_check(raw["manifest.raw.json"], raw["index.json.gz"], now)
        self.assertEqual(code, 0)
        self.assertIn("manifestFailure=NONE", checked)
        self.assertNotIn("manifest=0", checked)

    def test_common_codec_accepts_both_expiry_orders_candidate_requires_minimum(self):
        _, raw, _ = artifacts(SOURCE)
        manifest = cr.parse_json(raw["manifest.raw.json"])
        now = cr.timestamp(manifest["publishedAtUtc"])
        self.assertEqual(native_check(raw["manifest.raw.json"], raw["index.json.gz"], now, shared=True)[0], 0)
        manifest["expiresAtUtc"] = monitor.stamp(cr.timestamp(manifest["expiresAtUtc"]) + timedelta(hours=1))
        long_manifest = cr.json_bytes(manifest)
        self.assertEqual(native_check(long_manifest, raw["index.json.gz"], now, shared=True)[0], 0)
        code, result = native_check(long_manifest, raw["index.json.gz"], now)
        self.assertEqual(code, 2)
        self.assertIn("status=5 ", result)

    def test_current_member_identity_survives_original_candidate_and_strict_codec(self):
        """現producerの10fieldを原candidate/assetへ保持し、欠損やunsafe selectorを拒否する。"""
        _, raw, candidates = artifacts(SOURCE)
        manifest = cr.parse_json(raw["manifest.raw.json"])
        now = cr.timestamp(manifest["publishedAtUtc"])
        expected_fields = {"state", "kind", "pnpIds", "classGuid", "nestedArchiveIdentity",
                           "infIdentity", "modelSection", "evidenceUrl", "evidenceSha256", "reason"}
        for candidate in candidates:
            for record in candidate["records"]:
                identity = record["publishedIdentityEvidence"]
                self.assertEqual(set(identity), expected_fields)
                self.assertEqual(identity["kind"], "INF")
                matching = [inf for inf in candidate["infs"] if
                    inf["infIdentity"].replace("\\", "/") == identity["infIdentity"] and
                    inf["nestedArchiveIdentity"].replace("\\", "/") == identity["nestedArchiveIdentity"] and
                    inf["infSha256"] == identity["evidenceSha256"] and
                    inf["classGuid"] == identity["classGuid"] and
                    any(model["modelSection"] == identity["modelSection"] and
                        model["pnpIds"] == identity["pnpIds"] for model in inf["models"])]
                self.assertEqual(len(matching), 1)
        changes = (
            lambda identity: identity.pop("nestedArchiveIdentity"),
            lambda identity: identity.update(nestedArchiveIdentity=None),
            lambda identity: identity.update(nestedArchiveIdentity="../inner.zip"),
            lambda identity: identity.update(nestedArchiveIdentity="a/CON.zip"),
            lambda identity: identity.update(nestedSelector="inner.zip"))
        for change in changes:
            with self.subTest(mutation=changes.index(change)):
                body, packed = mutated(raw, lambda _, records: change(records[0]["publishedIdentityEvidence"]))
                self.assertEqual(native_check(body, packed, now)[0], 2)

    def test_manifest_expired_and_individual_expired(self):
        _, raw, _ = artifacts(SOURCE)
        manifest = cr.parse_json(raw["manifest.raw.json"])
        now = cr.timestamp(manifest["publishedAtUtc"])
        self.assertEqual(native_check(raw["manifest.raw.json"], raw["index.json.gz"],
                                      cr.timestamp(manifest["expiresAtUtc"]))[0], 2)
        def expire_one(value, records):
            records[0]["acquisitionDescriptor"]["attestation"]["validUntilUtc"] = monitor.stamp(now + timedelta(seconds=1))
        body, packed = mutated(raw, expire_one)
        code, result = native_check(body, packed, now + timedelta(seconds=2))
        self.assertEqual(code, 2)
        self.assertIn("status=4 ", result)

    def test_beyond_eight_days_and_future_checked_rejected(self):
        _, raw, _ = artifacts(SOURCE)
        now = cr.timestamp(cr.parse_json(raw["manifest.raw.json"])["publishedAtUtc"])
        for field, value in (("validUntilUtc", monitor.stamp(now + timedelta(days=9))),
                             ("checkedAtUtc", monitor.stamp(now + timedelta(seconds=1)))):
            with self.subTest(field=field):
                body, packed = mutated(raw, lambda _, records: records[0]["acquisitionDescriptor"]["attestation"].update({field: value}))
                code, result = native_check(body, packed, now)
                self.assertEqual(code, 2)
                self.assertIn("status=3 ", result)

    def test_hash_quality_and_unknown_wire_rejected(self):
        _, raw, _ = artifacts(SOURCE)
        manifest = cr.parse_json(raw["manifest.raw.json"])
        now = cr.timestamp(manifest["publishedAtUtc"])
        broken = bytearray(raw["index.json.gz"])
        broken[-1] ^= 1
        self.assertEqual(native_check(raw["manifest.raw.json"], bytes(broken), now)[0], 2)
        manifest["quality"]["recordCount"] += 1
        manifest["quality"]["contentInspectedCount"] += 1
        self.assertEqual(native_check(cr.json_bytes(manifest), raw["index.json.gz"], now)[0], 2)
        body, packed = mutated(raw, lambda _, records: records[0].update(unregisteredWireField=True))
        self.assertEqual(native_check(body, packed, now)[0], 2)

    def test_copied_public_receipt_cannot_start_private_build(self):
        head, _, candidates = artifacts(SOURCE)
        for receipt in (None, candidates[0], SimpleNamespace(alive=lambda: True,
                context={"runId": head["runId"], **candidates[0]["binding"]})):
            with self.subTest(kind=type(receipt).__name__):
                with self.assertRaisesRegex(cr.RegistryError, "CANDIDATE_LIVE_CALLER_REQUIRED"):
                    pipeline.build_candidate(SOURCE / "package", SOURCE / "workspace", head["runId"], receipt)

    def test_assemble_old_a_new_b_original_expiry_monotonic_and_same_run_bytes(self):
        fixture = assembly_fixture()
        policy = fixture.package / "config/monitor-policy.json"
        source_a, source_b = [row["job"]["sourceId"] for row in artifacts(SOURCE)[2]]
        pipeline.save_json(policy, {"schema": "dc-registry-monitor-policy-v1", "revision": "hold-b",
            "heldSourceIds": [source_b]}, replace=True)
        first = AssemblyBridge(fixture)
        fixture.run(first)
        head_a = cr.read_json(fixture.store / "distribution/candidate-head.json")
        a_directory = fixture.store / "distribution/runs" / head_a["runId"]
        old_a = (a_directory / "index.json.gz").read_bytes()
        a_expiry = cr.read_json(a_directory / "manifest.raw.json")["expiresAtUtc"]
        pipeline.save_json(policy, {"schema": "dc-registry-monitor-policy-v1", "revision": "unhold-b",
            "heldSourceIds": []}, replace=True)
        second = AssemblyBridge(fixture)
        result = fixture.run(second)
        head_b = cr.read_json(fixture.store / "distribution/candidate-head.json")
        b_directory = fixture.store / "distribution/runs" / head_b["runId"]
        manifest = cr.read_json(b_directory / "manifest.raw.json")
        self.assertEqual((head_a["generation"], head_b["generation"]), (1, 2))
        self.assertEqual((result["executed"], result["requests"], result["candidateRecords"]), (1, 2, 1))
        self.assertEqual(manifest["expiresAtUtc"], a_expiry)
        self.assertEqual(manifest["quality"]["recordCount"], 3)
        self.assertEqual((a_directory / "index.json.gz").read_bytes(), old_a)
        self.assertEqual((first.rebuilds, second.rebuilds), (1, 1))
        head_raw = (fixture.store / "distribution/candidate-head.json").read_bytes()
        fixture.now += timedelta(days=2)
        failed = fixture.run(AssemblyBridge(fixture, failures=(source_a, source_b)))
        self.assertFalse(failed["candidatePrepared"])
        self.assertEqual((fixture.store / "distribution/candidate-head.json").read_bytes(), head_raw)
        fixture.now = cr.timestamp(a_expiry) + timedelta(seconds=1)
        fixture.run(AssemblyBridge(fixture, failures=(source_a,)))
        last = cr.read_json(fixture.store / "distribution/candidate-head.json")
        last_directory = fixture.store / "distribution/runs" / last["runId"]
        self.assertEqual(last["generation"], 3)
        self.assertEqual(cr.read_json(last_directory / "manifest.raw.json")["quality"]["recordCount"], 1)
        self.assertTrue(cr.read_json(last_directory / "build-report.json")["expired"])

    def test_empty_success_keeps_no_head_or_asset(self):
        fixture = assembly_fixture()
        result = fixture.run(AssemblyBridge(fixture, empty=True))
        self.assertFalse(result["candidatePrepared"])
        self.assertFalse((fixture.store / "distribution/candidate-head.json").exists())
        journal = pipeline.verify_layout(fixture.store / "distribution")
        for run_id in journal["runs"]:
            self.assertFalse((fixture.store / "distribution/runs" / run_id / "index.json.gz").exists())


def main():
    """明示した自己所有native fixtureだけを使い、全原logを出力directoryへ残す。"""
    global NATIVE, SOURCE, OUTPUT
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    NATIVE, SOURCE, OUTPUT = args.native.resolve(strict=True), args.fixture.resolve(strict=True), args.output.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(OUTPUT)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CandidateTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
