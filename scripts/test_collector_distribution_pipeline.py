"""配布補助journal・先払い・停止窓を自己所有fixtureと完全fake bridgeで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
本fileのbridgeは試験内だけにあり、製品CLI/envにfake設定を公開しない。
"""
import base64
import copy
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collector_collection_profiles as cp
import collector_distribution_data as data
import collector_distribution_pipeline as pipeline
import collector_public_locators as pl
import collector_registry as cr
import collector_workspace as workspace
import registry_daily_monitor as monitor
from test_collector_collection_profiles import fixture_inputs, AS_OF


class Bridge:
    """同じ予約と固定結果memberを扱う試験専用のparent transportである。"""

    def __init__(self, fixture, *, complete=True, status="SUCCESS", page_proof=True, retain_body=True):
        self.fixture = fixture
        self.complete = complete
        self.status = status
        self.page_proof = page_proof
        self.retain_body = retain_body
        self.calls = []
        self.alive = lambda: True
        self.context = fixture.context()

    def exchange(self, kind, run_id, plan_hash, **fields):
        self.calls.append(kind)
        if kind != "EXECUTE_JOB":
            return {}
        ordinal = fields["ordinal"]
        root = self.fixture.store / "distribution/runs" / run_id
        reservation = pipeline.read_hash(root / f"reservation-{ordinal}.json", fields["reservationSha256"])
        self.fixture.reservations.append(reservation)
        member = f"result-{ordinal}.json"
        candidate_member = f"candidate-{ordinal}.json"
        job = cr.read_json(root / f"job-{ordinal}.json")
        body = b"x" * 1200
        page = {"httpStatus": 200, "bodyBytes": len(body), "bodySha256": cr.digest(body),
                "finalUrl": job["source"]["rootUrl"], "requestCount": 1, "observedUtcSeconds": 1792717200}
        transfer = {"stage": "PAGE", "completion": "COMPLETE" if self.complete else "UNKNOWN",
                    "bodyBytesRead": len(body), "terminalStatus": 200, "attemptedRequests": 1}
        digest = pipeline.save_json(root / member, {"schema": "dc-collector-registry-native-result-v1",
            "job": job, "jobSha256": reservation["jobSha256"], "pageObservation": page, "pageTransfer": transfer})
        if self.complete and self.page_proof and self.retain_body:
            monitor.write_new_bytes(root / f"page-{ordinal}.body", body)
        candidate = {"schema": "dc-collector-distribution-candidate-v1", "producerVersion": "collector-distribution-v1",
            "job": job, "jobSha256": reservation["jobSha256"], "records": [], "sources": [], "outcomes": [], "jobError": 0,
            "binding": {"runId": run_id, "ordinal": ordinal, "planHash": plan_hash,
            "inputHashes": self.context["inputHashes"], **{name: self.context[name] for name in
            ("monitorIdentity", "packageManifestSha256", "seedManifestSha256", "producerHashes")}}}
        candidate_hash = pipeline.save_json(root / candidate_member, candidate)
        return {"ordinal": ordinal, "resultMember": member, "resultSha256": digest,
                "candidateMember": candidate_member, "candidateSha256": candidate_hash, "candidateRecords": 0,
                "status": self.status, "reason": "NONE" if self.status == "SUCCESS" else "INDIVIDUAL_INF_REJECTED",
                "page": {"complete": self.complete, "requests": 1, "bytes": 1200, "status": 200},
                "payload": {"complete": self.complete, "requests": 1, "bytes": 4096, "status": 200},
                "pageProof": self.complete and self.page_proof, "pageSha256": cr.digest(body)}


class Fixture:
    """実運用rootを使わず架空データと日付を固定する。"""

    def __init__(self, count=2, *, same_page=False, fresh_research=False):
        self.base = Path(tempfile.mkdtemp(prefix="dc-distribution-"))
        self.package = self.base / "package"
        self.root = self.base / "workspace"
        self.store = self.root / "monitor"
        self.root.mkdir()
        (self.package / "seed/collector-data").mkdir(parents=True)
        (self.package / "config").mkdir()
        (self.package / "DriverCrateCollectorSetup.exe").write_bytes(b"fixture-not-executable")
        (self.package / "scripts").mkdir()
        for member in ("collector_distribution_pipeline.py", "collector_collection_profiles.py"):
            (self.package / "scripts" / member).write_bytes((Path(__file__).parent / member).read_bytes())
        inputs, value, _ = fixture_inputs(count)
        if same_page:
            registry = copy.deepcopy(inputs["registry"])
            locators = copy.deepcopy(inputs["locators"])
            edits = {"schema": cp.EDIT_SCHEMA, "profiles": []}
            for index in range(count):
                page_url = "https://shared.example.org/download/"
                payload_url = page_url + f"driver-{index}.zip"
                registry["sources"][index]["officialPage"] = page_url
                registry["records"][index]["downloadUrl"] = payload_url
                for observation in registry["observations"]:
                    if observation["recordId"] == registry["records"][index]["id"]:
                        observation["evidenceUrl"] = page_url
                        observation["evidenceSha256"] = "e" * 64
                for locator in locators["locators"]:
                    if locator["sourceId"] == registry["sources"][index]["id"]:
                        locator["url"] = page_url if locator["purpose"] == "PAGE" else payload_url
                        if locator["pageObservation"]:
                            locator["pageObservation"]["bodySha256"] = "e" * 64
                profile = {key: copy.deepcopy(value["profiles"][index][key]) for key in cp.PROFILE_FIELDS}
                profile["href"] = f"driver-{index}.zip"
                for review in profile["review"].values():
                    review["evidence"]["bodySha256"] = "e" * 64
                edits["profiles"].append(profile)
            import collector_public_locators as locators_module
            common_source = registry["sources"][0]["id"]
            common_page = locators["locators"][0]
            registry["sources"] = registry["sources"][:1]
            for record in registry["records"]:
                record["sourceId"] = common_source
            for product in registry["products"]:
                product["sourceIds"] = [common_source]
                product["manufacturer"] = registry["sources"][0]["manufacturer"]
                product["recordIds"] = [row["id"] for row in registry["records"]]
            common_page["recordIds"] = [row["id"] for row in registry["records"]]
            common_page["productIds"] = [row["id"] for row in registry["products"]]
            locators["locators"] = [row for row in locators["locators"] if row["purpose"] != "PAGE" or row is common_page]
            for locator in locators["locators"]:
                locator["sourceId"] = common_source
                if locator["purpose"] == "PAYLOAD":
                    locator["parentPageIds"] = [common_page["id"]]
                    locator["productIds"] = common_page["productIds"]
            for profile in edits["profiles"]:
                profile["sourceId"] = common_source
                profile["pageLocatorId"] = common_page["id"]
                for review in profile["review"].values():
                    review["evidence"]["locatorId"] = common_page["id"]
            locators["registry"] = locators_module.registry_binding(registry)
            inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
            value = cp.upsert_profiles(None, inputs, edits, revision="shared-01", as_of=AS_OF)
        if fresh_research:
            registry = copy.deepcopy(inputs["registry"])
            locators = copy.deepcopy(inputs["locators"])
            for observation in registry["observations"]:
                observation["checkedAt"] = AS_OF
            for locator in locators["locators"]:
                if locator["pageObservation"]:
                    locator["pageObservation"]["checkedAt"] = AS_OF
            locators["registry"] = pl.registry_binding(registry)
            edits = {"schema": cp.EDIT_SCHEMA, "profiles": []}
            for row in value["profiles"]:
                profile = {key: copy.deepcopy(row[key]) for key in cp.PROFILE_FIELDS}
                for review in profile["review"].values():
                    review["evidence"]["checkedAt"] = AS_OF
                edits["profiles"].append(profile)
            inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
            value = cp.upsert_profiles(None, inputs, edits, revision="fresh-01", as_of=AS_OF)
        self.inputs, self.value = inputs, value
        self.reservations = []
        self.now = datetime(2026, 10, 23, 1)
        self.sequence = 0
        data.write_bundle(self.package / "seed/distribution-data", data.bundle_content({
            "registry": cr.json_bytes(inputs["registry"]), "locators": cr.json_bytes(inputs["locators"]),
            "profiles": cr.json_bytes(value)}))
        policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "fixture", "heldSourceIds": []}
        pipeline.save_json(self.package / "config/monitor-policy.json", policy)
        self.expected = {"schema": "dc-collector-explicit-workspace-v1", "packageManifestSha256": "1" * 64,
                         "seedManifestSha256": "2" * 64, "communicationAuthorized": False,
                         "nativeConstraints": "UNKNOWN", "originalDayBudget": "UNVERIFIED"}
        pipeline.save_json(self.root / "workspace.json", self.expected)
        monitor.initialize(self.store, clock=lambda: self.now)

    def context(self):
        self.sequence += 1
        _, _, hashes = pipeline.inputs_at(self.package)
        return {"schema": "dc-collector-live-admission-v1", "protocol": pipeline.PROTOCOL,
                "operation": "distribution-run-once", "nativeMode": "VERIFIED_PRISTINE_V1",
                "originInitializationComplete": True, "legacyHistoryEverObserved": False,
                "nativeFileCount": 0, "nativeDigest": "3" * 64,
                "workspaceIdentity": "4" * 64, "monitorIdentity": "4" * 64,
                "monitorRoot": str(self.store), "packageManifestSha256": "1" * 64,
                "seedManifestSha256": "2" * 64,
                "policySha256": cr.digest((self.package / "config/monitor-policy.json").read_bytes()),
                "issuedAtUtcMillis": int(self.now.replace(tzinfo=timezone.utc).timestamp() * 1000),
                "requestHashes": ["8" * 64], "hostHashes": ["9" * 64],
                "runId": "run-" + f"{self.sequence:032x}", "inputHashes": hashes,
                "producerHashes": pipeline.producer_hashes(self.package)}

    def run(self, bridge=None, **options):
        original = workspace.DistributionAdmission
        def admission(document, *, parent_alive):
            return original(document, parent_alive=parent_alive, identity=lambda path: "4" * 64)
        with patch.object(workspace, "binding", return_value=self.expected), patch.object(
                workspace, "DistributionAdmission", side_effect=admission), patch.object(
                pipeline, "assert_build_caller", return_value=None):
            return pipeline.run_once(self.package, self.root, bridge or Bridge(self), confirmed=True,
                                     clock=lambda: self.now, monotonic=lambda: 1, **options)


class CandidateBridge(Bridge):
    """assemblyの部分失敗/原期限だけを検査するfake。native内容/署名の成功を証明しない。"""

    def __init__(self, fixture, *, failures=(), validity=None):
        super().__init__(fixture)
        self.failures = set(failures)
        self.validity = validity or {}

    def exchange(self, kind, run_id, plan_hash, **fields):
        result = super().exchange(kind, run_id, plan_hash, **fields)
        directory = self.fixture.store / "distribution/runs" / run_id
        if kind == "EXECUTE_JOB":
            path = directory / result["candidateMember"]
            candidate = cr.read_json(path)
            source = candidate["job"]["sourceId"]
            failed = source in self.failures
            expiry = monitor.stamp(self.fixture.now + self.validity.get(source, timedelta(days=8)))
            candidate.update(checkedAtUtc=monitor.stamp(self.fixture.now), validUntilUtc=expiry,
                jobError=-2147467259 if failed else 0,
                outcomes=[{"status": "FAILED" if failed else "CONTENT_INSPECTED",
                           "reason": "TEST_FAILURE" if failed else "NONE", "error": -2147467259 if failed else 0}])
            if not failed:
                candidate["sources"] = [{"sourceId": source, "distributionPage": candidate["job"]["source"]["rootUrl"]}]
                candidate["records"] = [{"sourceId": source, "recordId": candidate["job"]["recordId"],
                    "acquisitionDescriptor": {"attestation": {"checkedAtUtc": monitor.stamp(self.fixture.now),
                                                               "validUntilUtc": expiry}}}]
            result.update(candidateSha256=pipeline.save_json(path, candidate, replace=True),
                candidateRecords=len(candidate["records"]), status="FAILED" if failed else "SUCCESS",
                reason="TEST_FAILURE" if failed else "NONE")
        elif kind == "FINISH_RUN" and fields["build"] is not None:
            member = "unsigned-validation.json"
            digest = pipeline.save_json(directory / member, {"schema": "dc-collector-unsigned-validation-v1",
                "runId": run_id, "outputs": fields["build"]["outputs"], "unsigned": True, "authenticated": False})
            result = {"validationMember": member, "validationSha256": digest}
        return result


class PipelineTests(unittest.TestCase):
    """成功・待機・停止回収と未知履歴の拒否を別分母で確認する。"""

    def test_success_with_failed_or_held_target_keeps_denominator_and_diagnostics(self):
        for mode in ("FAILED", "HOLD"):
            fixture = Fixture()
            source_a, source_b = [row["id"] for row in fixture.inputs["registry"]["sources"]]
            if mode == "HOLD":
                pipeline.save_json(fixture.package / "config/monitor-policy.json", {
                    "schema": "dc-registry-monitor-policy-v1", "revision": "hold-b",
                    "heldSourceIds": [source_b]}, replace=True)
            result = fixture.run(CandidateBridge(fixture, failures=(source_b,) if mode == "FAILED" else ()))
            head = cr.read_json(fixture.store / "distribution/candidate-head.json")
            directory = fixture.store / "distribution/runs" / head["runId"]
            report = cr.read_json(directory / "build-report.json")
            index = cr.read_json(directory / "index.json")
            records = [cr.parse_json(base64.b64decode(row["recordBytesBase64"])) for row in index["records"]]
            with self.subTest(mode=mode):
                self.assertEqual((result["result"], result["targets"], result["success"]), ("PARTIAL_OR_HELD", 2, 1))
                self.assertEqual([row["sourceId"] for row in records], [source_a])
                self.assertFalse(report["allTargetsSucceeded"])
                self.assertIn(mode, [row["status"] for row in report["targets"]])
                self.assertTrue(next(row for row in report["targets"] if row["status"] == mode)["reasons"])
                if mode == "FAILED":
                    self.assertIn(-2147467259, [row["jobError"] for row in report["outcomes"]])
                self.assertNotIn("https://", cr.json_bytes(result).decode())
                journal = pipeline.verify_layout(fixture.store / "distribution")
                self.assertEqual(journal["runs"][head["runId"]]["startedAt"], monitor.stamp(fixture.now))
                for request in journal["requests"].values():
                    self.assertLessEqual(cr.timestamp(request["attemptedAt"]), cr.timestamp(request["endedAt"]))
                    self.assertGreaterEqual(cr.timestamp(request["nextDueAt"]), cr.timestamp(request["endedAt"]) + monitor.DAY)

    def test_old_success_new_success_all_failure_and_expired_record_preserve_originals(self):
        fixture = Fixture()
        source_a, source_b = [row["id"] for row in fixture.inputs["registry"]["sources"]]
        policy = fixture.package / "config/monitor-policy.json"
        pipeline.save_json(policy, {"schema": "dc-registry-monitor-policy-v1", "revision": "hold-b",
                                   "heldSourceIds": [source_b]}, replace=True)
        fixture.run(CandidateBridge(fixture, validity={source_a: timedelta(days=2)}))
        head_a = cr.read_json(fixture.store / "distribution/candidate-head.json")
        directory_a = fixture.store / "distribution/runs" / head_a["runId"]
        assets_a = {name: (directory_a / name).read_bytes() for name in head_a["outputs"]}
        original_a = cr.parse_json(assets_a["index.json"])["records"][0]
        expiry_a = cr.parse_json(assets_a["manifest.raw.json"])["expiresAtUtc"]
        pipeline.save_json(policy, {"schema": "dc-registry-monitor-policy-v1", "revision": "enable-b",
                                   "heldSourceIds": []}, replace=True)
        fixture.run(CandidateBridge(fixture))
        head_path = fixture.store / "distribution/candidate-head.json"
        head_b_raw = head_path.read_bytes()
        head_b = cr.parse_json(head_b_raw)
        directory_b = fixture.store / "distribution/runs" / head_b["runId"]
        assets_b = {name: (directory_b / name).read_bytes() for name in head_b["outputs"]}
        self.assertEqual((head_a["generation"], head_b["generation"]), (1, 2))
        self.assertIn(original_a, cr.parse_json(assets_b["index.json"])["records"])
        self.assertEqual(cr.parse_json(assets_b["manifest.raw.json"])["expiresAtUtc"], expiry_a)
        fixture.now += timedelta(days=1)
        failed = fixture.run(CandidateBridge(fixture, failures=(source_a, source_b)))
        self.assertFalse(failed["candidatePrepared"])
        self.assertEqual(head_path.read_bytes(), head_b_raw)
        journal = pipeline.verify_layout(fixture.store / "distribution")
        failed_run = next(run for run in journal["runs"].values() if all(row["status"] == "FAILED" for row in run["targets"]))
        report = cr.read_json(fixture.store / "distribution/runs" / failed_run["runId"] / "build-report.json")
        self.assertEqual((report["freshRecords"], report["headUpdated"]), (0, False))
        self.assertTrue(all(row["lastSuccess"] is not None for row in journal["requests"].values() if row["kind"] == "PAYLOAD"))
        fixture.now = cr.timestamp(expiry_a) + timedelta(seconds=1)
        fixture.run(CandidateBridge(fixture, failures=(source_a,)))
        head_c = cr.read_json(head_path)
        directory_c = fixture.store / "distribution/runs" / head_c["runId"]
        report_c = cr.read_json(directory_c / "build-report.json")
        self.assertEqual(head_c["generation"], 3)
        self.assertEqual(cr.read_json(directory_c / "manifest.raw.json")["quality"]["recordCount"], 1)
        self.assertEqual([row["reason"] for row in report_c["expired"]], ["ORIGINAL_EVIDENCE_EXPIRED"])
        self.assertEqual({name: (directory_a / name).read_bytes() for name in assets_a}, assets_a)
        self.assertEqual({name: (directory_b / name).read_bytes() for name in assets_b}, assets_b)

    def test_page_body_same_scope_keeps_original_bytes_and_budget(self):
        fixture = Fixture(same_page=True)
        result = fixture.run()
        journal = pipeline.verify_layout(fixture.store / "distribution")
        directory = fixture.store / "distribution/runs" / next(iter(journal["runs"]))
        self.assertEqual(result["requests"], 3)
        self.assertEqual((directory / "page-0.body").read_bytes(), b"x" * 1200)
        self.assertEqual((directory / "page-1.body").read_bytes(), (directory / "page-0.body").read_bytes())
        for ordinal in range(2):
            native = cr.read_json(directory / f"result-{ordinal}.json")
            self.assertEqual(native["pageObservation"]["bodySha256"], cr.digest(b"x" * 1200))

    def test_missing_new_page_body_preserves_original_result_and_maximum_reservation(self):
        fixture = Fixture(1)
        with self.assertRaisesRegex(cr.RegistryError, "DISTRIBUTION_PAGE_BODY_MISSING"):
            fixture.run(Bridge(fixture, retain_body=False))
        journal = pipeline.verify_layout(fixture.store / "distribution")
        run_id, run = next(iter(journal["runs"].items()))
        self.assertEqual(run["jobs"][0]["phase"], "RESERVED")
        self.assertTrue((fixture.store / "distribution/runs" / run_id / "result-0.json").exists())
        self.assertTrue(all(row["phase"] == "RESERVED" for row in journal["requests"].values()))
        self.assertEqual(sum(row["chargedRequests"] for row in journal["requests"].values()), 6)

    def test_old_run_missing_body_is_read_without_reconstruction(self):
        fixture = Fixture(1)
        fixture.run()
        journal = pipeline.verify_layout(fixture.store / "distribution")
        directory = fixture.store / "distribution/runs" / next(iter(journal["runs"]))
        (directory / "page-0.body").unlink()
        self.assertEqual(pipeline.verify_layout(fixture.store / "distribution"), journal)
        self.assertFalse((directory / "page-0.body").exists())

    def test_page_body_corruption_and_unknown_ordinal_are_rejected(self):
        for mutation in ("changed", "empty", "oversize", "unknown", "hardlink"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(1)
                fixture.run()
                journal = pipeline.verify_layout(fixture.store / "distribution")
                directory = fixture.store / "distribution/runs" / next(iter(journal["runs"]))
                path = directory / "page-0.body"
                if mutation == "unknown":
                    (directory / "page-99.body").write_bytes(b"unknown")
                elif mutation == "hardlink":
                    os.link(path, fixture.base / "body-link")
                else:
                    path.write_bytes({"changed": b"y" * 1200, "empty": b"", "oversize": b"x" * pipeline.PAGE_RESERVE}[mutation])
                with self.assertRaises(cr.RegistryError):
                    pipeline.verify_layout(fixture.store / "distribution")

    def test_page_body_observation_source_and_incomplete_binding_are_rejected(self):
        fixture = Fixture(1)
        fixture.run()
        journal = pipeline.verify_layout(fixture.store / "distribution")
        directory = fixture.store / "distribution/runs" / next(iter(journal["runs"]))
        original = cr.read_json(directory / "result-0.json")
        for group, key, value in (("pageTransfer", "completion", "UNKNOWN"),
                ("pageTransfer", "stage", "PAYLOAD"), ("pageTransfer", "terminalStatus", 500),
                ("pageTransfer", "attemptedRequests", 2), ("pageObservation", "bodyBytes", 1199),
                ("pageObservation", "bodySha256", "0" * 64), ("pageObservation", "observedUtcSeconds", 0),
                ("pageObservation", "finalUrl", "https://other.example.org/")):
            with self.subTest(group=group, key=key):
                changed = copy.deepcopy(original)
                changed[group][key] = value
                with self.assertRaises(cr.RegistryError):
                    pipeline.verify_page_body(directory, 0, changed, original["job"], original["jobSha256"], required=True)

    def test_page_body_stays_out_of_portable_history_and_reports(self):
        fixture = Fixture(1)
        fixture.run()
        state = monitor.verify_store(fixture.store)
        _, portable = pipeline.portable_content(fixture.store, state)
        self.assertFalse(any(name.endswith(".body") for name in portable))
        self.assertFalse(any(b"x" * 1200 in raw for raw in portable.values()))
        journal = pipeline.verify_layout(fixture.store / "distribution")
        directory = fixture.store / "distribution/runs" / next(iter(journal["runs"]))
        report = (directory / "build-report.json").read_bytes()
        self.assertNotIn(b"x" * 1200, report)
        self.assertNotIn(b"page-0.body", report)

    def test_fresh_research_first_attempt_then_actual_ledger_wait(self):
        fixture = Fixture(1, fresh_research=True)
        first = fixture.run()
        self.assertEqual((first["executed"], first["success"], first["requests"]), (1, 1, 2))
        before = copy.deepcopy(pipeline.verify_layout(fixture.store / "distribution")["requests"])
        second = fixture.run()
        self.assertEqual(second["executed"], 0)
        self.assertEqual(len(fixture.reservations), 1)
        self.assertEqual(pipeline.verify_layout(fixture.store / "distribution")["requests"], before)
        self.assertTrue(all(cr.timestamp(row["nextDueAt"]) >= fixture.now + monitor.DAY for row in before.values()))

    def test_fresh_research_does_not_override_host_hold(self):
        fixture = Fixture(1, fresh_research=True)
        state = monitor.verify_store(fixture.store)
        source = cp.make_static_job(fixture.value["profiles"][0], fixture.inputs)["source"]
        state["hosts"][monitor.hash_text(source["rootHost"])] = {
            "failedAt": monitor.stamp(fixture.now), "nextDueAt": monitor.stamp(fixture.now + monitor.DAY), "held": True}
        monitor.save_state(fixture.store, state)
        bridge = Bridge(fixture)
        result = fixture.run(bridge)
        self.assertEqual(result["executed"], 0)
        self.assertNotIn("EXECUTE_JOB", bridge.calls)
        self.assertEqual(monitor.verify_store(fixture.store)["hosts"], state["hosts"])

    def test_fresh_research_unknown_clock_rejects_before_request(self):
        fixture = Fixture(1, fresh_research=True)
        fixture.now -= timedelta(seconds=1)
        bridge = Bridge(fixture)
        with self.assertRaisesRegex(cr.RegistryError, "DISTRIBUTION_CLOCK"):
            fixture.run(bridge)
        self.assertEqual(bridge.calls, [])
        self.assertFalse((fixture.store / "distribution").exists())

    def test_fresh_research_incomplete_attempt_keeps_maximum_charge(self):
        fixture = Fixture(1, fresh_research=True)
        first = fixture.run(Bridge(fixture, complete=False, status="FAILED"))
        before = copy.deepcopy(pipeline.verify_layout(fixture.store / "distribution")["requests"])
        self.assertEqual(first["bodyBytes"], monitor.MAX_RUN_BYTES)
        self.assertTrue(all(row["phase"] == "SETTLED_MAXIMUM" for row in before.values()))
        self.assertEqual(fixture.run()["executed"], 0)
        self.assertEqual(pipeline.verify_layout(fixture.store / "distribution")["requests"], before)

    def test_missing_or_unknown_job_fields_reject_without_changing_history(self):
        fixture = Fixture(1)
        fixture.run()
        journal = pipeline.verify_layout(fixture.store / "distribution")
        run_id = next(iter(journal["runs"]))
        job = journal["runs"][run_id]["jobs"][0]
        original = copy.deepcopy(job)
        for name in ("candidateMember", "candidateSha256", "candidateRecords", "unknownField"):
            with self.subTest(field=name):
                job.clear()
                job.update(original)
                if name == "unknownField":
                    job[name] = None
                else:
                    del job[name]
                run = journal["runs"][run_id]
                digest = cr.digest(cr.json_bytes(run))
                member = "state-" + digest + ".json"
                pipeline.save_json(fixture.store / "distribution/runs" / run_id / member, run)
                index = cr.read_json(fixture.store / "distribution/journal.json")
                index["runs"][run_id] = {"member": member, "sha256": digest}
                pipeline.save_json(fixture.store / "distribution/journal.json", index, replace=True)
                before = {path: path.read_bytes() for path in fixture.store.rglob("*") if path.is_file()}
                with self.assertRaisesRegex(cr.RegistryError, "DISTRIBUTION_JOB_FIELDS"):
                    fixture.run()
                self.assertEqual(before, {path: path.read_bytes() for path in fixture.store.rglob("*") if path.is_file()})
        self.assertEqual(len(fixture.reservations), 1)
        self.assertFalse((fixture.store / "distribution/candidate-head.json").exists())

    def test_same_page_two_payload_actual_and_next_run_wait(self):
        fixture = Fixture(same_page=True)
        first = fixture.run()
        self.assertEqual((first["success"], first["requests"]), (2, 3))
        self.assertEqual(fixture.reservations[0]["effectiveCap"], 30 * 1024 * 1024 - 2)
        self.assertEqual(fixture.reservations[1]["pageBytes"], 0)
        before = copy.deepcopy(pipeline.verify_layout(fixture.store / "distribution"))
        second = fixture.run()
        self.assertEqual(second["executed"], 0)
        self.assertEqual(len(fixture.reservations), 2)
        after = pipeline.verify_layout(fixture.store / "distribution")
        self.assertEqual(before["requests"], after["requests"])
        self.assertTrue(all(row["lastSuccess"] for row in after["requests"].values() if row["kind"] == "PAYLOAD"))

    def test_33_continues_after_first_batch_and_first_failure(self):
        fixture = Fixture(33)
        fixture.run(Bridge(fixture, status="FAILED"))
        fixture.now += timedelta(days=2)
        fixture.run()
        self.assertEqual(fixture.reservations[32]["jobSha256"], cr.digest(cr.json_bytes(
            cp.make_static_job(fixture.value["profiles"][-1], fixture.inputs))))

    def test_each_saved_window_recovers_without_resend(self):
        for stage in ("JOURNAL_INTENT", "JOURNAL_DIRECTORY", "RUN_INTENT", "PLAN_SAVED", "JOB_INTENT", "PAGE_RESERVED", "RESERVED", "RESULT_RECEIVED"):
            with self.subTest(stage=stage):
                fixture = Fixture(1)
                bridge = Bridge(fixture)
                def stop(observed, ordinal):
                    if observed == stage:
                        raise InterruptedError("fixture stop")
                with self.assertRaises(InterruptedError):
                    fixture.run(bridge, checkpoint=stop)
                monitor.verify_store(fixture.store)
                fixture.run()
                journal = pipeline.verify_layout(fixture.store / "distribution")
                if stage not in {"JOURNAL_INTENT", "JOURNAL_DIRECTORY", "RUN_INTENT", "PLAN_SAVED"}:
                    self.assertEqual(len(fixture.reservations), int(stage == "RESULT_RECEIVED"))
                    self.assertTrue(all(row["phase"] == "SETTLED_MAXIMUM" for row in journal["requests"].values()))

    def test_unknown_maximum_and_old_success_kept(self):
        fixture = Fixture(1)
        fixture.run()
        old = pipeline.verify_layout(fixture.store / "distribution")["requests"]
        fixture.now += timedelta(days=2)
        result = fixture.run(Bridge(fixture, complete=False, status="FAILED"))
        journal = pipeline.verify_layout(fixture.store / "distribution")
        payload = next(row for row in journal["requests"].values() if row["kind"] == "PAYLOAD")
        self.assertEqual(result["bodyBytes"], monitor.MAX_RUN_BYTES)
        self.assertEqual(payload["lastSuccess"], next(row["lastSuccess"] for row in old.values() if row["kind"] == "PAYLOAD"))
        self.assertEqual(payload["phase"], "SETTLED_MAXIMUM")

    def test_unconfirmed_and_input_change_zero_execute(self):
        fixture = Fixture(1)
        bridge = Bridge(fixture)
        with self.assertRaises(cr.RegistryError):
            pipeline.run_once(fixture.package, fixture.root, bridge, confirmed=False)
        self.assertEqual(bridge.calls, [])
        bridge.context["inputHashes"]["profiles"] = "a" * 64
        with self.assertRaises(cr.RegistryError):
            fixture.run(bridge)
        self.assertEqual(bridge.calls, [])

    def test_unknown_files_and_changed_reservation_rejected(self):
        fixture = Fixture(1)
        fixture.run()
        directory = fixture.store / "distribution"
        pipeline.save_json(directory / "unexpected.json", {"unexpected": True})
        with self.assertRaises(cr.RegistryError):
            monitor.verify_store(fixture.store)

    def test_export_import_preserves_waits_without_private_run_authority(self):
        fixture = Fixture(2)
        fixture.run()
        before = pipeline.verify_layout(fixture.store / "distribution")
        monitor.export_store(fixture.store, fixture.base / "export")
        monitor.import_export(fixture.base / "export", fixture.base / "imported", source_stop_acknowledged=True,
                              clock=lambda: fixture.now)
        after = pipeline.verify_layout(fixture.base / "imported/distribution")
        self.assertEqual(before["requests"], after["requests"])
        self.assertEqual(before["cursor"], after["cursor"])
        self.assertEqual(after["runs"], {})
        history = cr.read_json(fixture.base / "imported/distribution/portable-history.json")
        self.assertEqual(set(history["runs"]), set(before["runs"]))
        self.assertEqual(cr.read_json(fixture.base / "export/manifest.json")["schema"], "dc-registry-monitor-export-v3")

    def test_stopped_export_keeps_maximum_charge_hosts_and_no_private_results(self):
        fixture = Fixture(1)
        def stop(stage, ordinal):
            if stage == "RESERVED":
                raise InterruptedError("fixture stop")
        with self.assertRaises(InterruptedError):
            fixture.run(checkpoint=stop)
        before = pipeline.verify_layout(fixture.store / "distribution")
        monitor.export_store(fixture.store, fixture.base / "export")
        monitor.import_export(fixture.base / "export", fixture.base / "imported", source_stop_acknowledged=True,
                              clock=lambda: fixture.now)
        after = pipeline.verify_layout(fixture.base / "imported/distribution")
        self.assertEqual(sum(row["chargedBytes"] for row in before["requests"].values()),
                         sum(row["chargedBytes"] for row in after["requests"].values()))
        self.assertTrue(all(row["phase"] == "SETTLED_MAXIMUM" for row in after["requests"].values()))
        self.assertTrue(monitor.verify_store(fixture.base / "imported")["hosts"])
        self.assertEqual(list((fixture.base / "imported/distribution/runs").iterdir()), [])
        self.assertEqual(before, pipeline.verify_layout(fixture.store / "distribution"))

    def test_partial_result_is_not_complete_or_global_failed(self):
        fixture = Fixture(1)
        result = fixture.run(Bridge(fixture, status="PARTIAL_FAILURE"))
        journal = pipeline.verify_layout(fixture.store / "distribution")
        target = next(iter(journal["runs"].values()))["targets"][0]
        self.assertEqual(target["status"], "PARTIAL_FAILURE")
        self.assertEqual(result["success"], 0)
        self.assertEqual(result["requests"], 2)

    def test_reserved_history_missing_is_corruption_not_fresh(self):
        fixture = Fixture(1)
        def stop(stage, ordinal):
            if stage == "RESERVED":
                raise InterruptedError("fixture stop")
        with self.assertRaises(InterruptedError):
            fixture.run(checkpoint=stop)
        path = fixture.store / "distribution/journal.json"
        raw = cr.read_json(path)
        key = next(key for key, row in raw["requests"].items() if row["kind"] == "PAYLOAD")
        del raw["requests"][key]
        pipeline.save_json(path, raw, replace=True)
        with self.assertRaisesRegex(cr.RegistryError, "DISTRIBUTION_RESERVATION_HISTORY_MISSING"):
            monitor.verify_store(fixture.store)


if __name__ == "__main__":
    unittest.main()
