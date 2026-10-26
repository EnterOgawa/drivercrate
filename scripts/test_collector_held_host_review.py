"""一host明示baseline reviewを自己所有workspaceと非通信fakeで検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実HOLD、Task、HTTP、署名、driver導入には接続しない。
"""
import copy
from datetime import timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import collector_collection_profiles as profiles
import collector_distribution_data as data
import collector_distribution_pipeline as pipeline
import collector_public_locators as locators
import collector_registry as cr
import collector_workspace as workspace
import registry_daily_monitor as monitor
from test_collector_distribution_pipeline import Fixture


class RejectedPageBridge:
    """実native結果の失敗形だけを固定memberへ保存する試験専用bridge。"""

    def __init__(self, fixture):
        self.fixture = fixture
        self.context = fixture.context()
        self.alive = lambda: True

    def exchange(self, kind, run_id, plan_hash, **fields):
        if kind != "EXECUTE_JOB":
            return {}
        directory = self.fixture.store / "distribution/runs" / run_id
        job = cr.read_json(directory / "job-0.json")
        reservation = pipeline.read_hash(directory / "reservation-0.json", fields["reservationSha256"])
        raw = b'<html><body>unreviewed changed page</body></html>'
        value = {"schema": "dc-collector-registry-native-result-v1", "job": job,
                 "jobSha256": reservation["jobSha256"], "status": "FAILED", "reason": "ACQUISITION_REJECTED",
                 "error": -2147023590, "sourceVerified": False, "archiveBytes": 0, "verifiedInfs": 0,
                 "pageTransfer": {"stage": "PAGE", "completion": "COMPLETE", "terminalStatus": 200,
                                  "attemptedRequests": 1, "bodyBytesRead": len(raw)},
                 "payloadTransfer": {"stage": "UNSTARTED", "completion": "UNKNOWN", "attemptedRequests": 0,
                                     "bodyBytesRead": 0, "terminalStatus": 0},
                 "pageObservation": {"httpStatus": 200, "bodyBytes": len(raw), "bodySha256": cr.digest(raw),
                                     "finalUrl": job["source"]["rootUrl"], "requestCount": 1,
                                     "observedUtcSeconds": int(self.fixture.now.replace(tzinfo=timezone.utc).timestamp())}}
        digest = pipeline.save_json(directory / "result-0.json", value)
        monitor.write_new_bytes(directory / "page-0.body", raw)
        candidate = {"schema": "dc-collector-distribution-candidate-v1", "producerVersion": "collector-distribution-v1",
                     "job": job, "jobSha256": reservation["jobSha256"], "records": [], "sources": [],
                     "outcomes": [], "jobError": -2147023590,
                     "binding": {"runId": run_id, "ordinal": 0, "planHash": plan_hash,
                                 "inputHashes": self.context["inputHashes"], **{name: self.context[name] for name in
                                 ("monitorIdentity", "packageManifestSha256", "seedManifestSha256", "producerHashes")}}}
        candidate_hash = pipeline.save_json(directory / "candidate-0.json", candidate)
        return {"ordinal": 0, "resultMember": "result-0.json", "resultSha256": digest,
                "candidateMember": "candidate-0.json", "candidateSha256": candidate_hash, "candidateRecords": 0,
                "status": "FAILED", "reason": "ACQUISITION_REJECTED",
                "page": {"complete": True, "requests": 1, "bytes": len(raw), "status": 200},
                "payload": {"complete": False, "requests": 0, "bytes": 0, "status": 0},
                "pageProof": True, "pageSha256": cr.digest(raw)}


class ReviewFixture(Fixture):
    """既存run_onceで最大課金とHOLDを作り、正規review入力を用意する。"""

    def __init__(self):
        super().__init__(count=1)
        self.baseline = (b'<html><body><a href="driver.zip">driver terms unchanged</a></body>\n</html>' +
                         b'<!-- WP Fastest Cache file was created in 0.51081204414368 seconds, on 22-10-26 00:00:00 -->')
        self.current_raw = self.baseline.replace(b'0.51081204414368', b'0.59633994102478')
        registry = copy.deepcopy(self.inputs["registry"])
        locator_value = copy.deepcopy(self.inputs["locators"])
        for item in registry["observations"]:
            item["evidenceSha256"] = cr.digest(self.baseline)
        for item in locator_value["locators"]:
            if item["pageObservation"]:
                item["pageObservation"].update(bodyBytes=len(self.baseline), bodySha256=cr.digest(self.baseline))
        locator_value["registry"] = locators.registry_binding(registry)
        edits = {"schema": profiles.EDIT_SCHEMA, "profiles": []}
        for item in self.value["profiles"]:
            row = {key: copy.deepcopy(item[key]) for key in profiles.PROFILE_FIELDS}
            for scope in row["review"].values():
                scope["evidence"].update(bodySha256=cr.digest(self.baseline),
                                         contentSha256=profiles.page_content_sha256(self.baseline))
            edits["profiles"].append(row)
        self.inputs = profiles.load_inputs(cr.json_bytes(registry), cr.json_bytes(locator_value))
        self.value = profiles.upsert_profiles(None, self.inputs, edits, revision="review-fixture", as_of=self.value["asOf"])
        content = data.bundle_content({"registry": cr.json_bytes(registry), "locators": cr.json_bytes(locator_value),
                                       "profiles": cr.json_bytes(self.value)})
        for name, raw in content.items():
            (self.package / "seed/distribution-data" / name).write_bytes(raw)
        self.bridge = RejectedPageBridge(self)
        self.run(self.bridge)
        # 保存機能追加前の原raw欠測を、自己所有の固定一fileだけで明示再現する。
        run_id = self.bridge.context["runId"]
        (self.store / "distribution/runs" / run_id / "page-0.body").unlink()
        self.now += timedelta(days=1, seconds=1)
        self.review_directory = self.base / "operator-review"
        self.review_directory.mkdir()
        (self.review_directory / "baseline.raw.html").write_bytes(self.baseline)
        (self.review_directory / "current.raw.html").write_bytes(self.current_raw)
        self.path = self.review_directory / "review-request.json"
        self.request = self.make_request()
        self.save_request()

    def make_request(self):
        state = monitor.verify_store(self.store)
        journal = pipeline.verify_layout(self.store / "distribution")
        run_id = next(iter(journal["runs"]))
        row = self.value["profiles"][0]
        return {"schema": "dc-collector-held-host-review-v1", "reviewId": "review-fixture-01",
                "hostSha256": next(iter(state["hosts"])), "profileId": row["id"], "recordId": row["recordId"],
                "workspaceSha256": cr.digest((self.root / "workspace.json").read_bytes()),
                "stateSha256": cr.digest((self.store / "state.json").read_bytes()),
                "journalSha256": cr.digest((self.store / "distribution/journal.json").read_bytes()),
                "inputHashes": pipeline.inputs_at(self.package, self.root)[2],
                "cause": {"kind": "PAGE_CONTENT_CHANGED_REVALIDATE_BASELINE", "runId": run_id, "ordinal": 0,
                          "resultSha256": journal["runs"][run_id]["jobs"][0]["resultSha256"], "originalRawMissing": True},
                "currentPage": {"bodySha256": cr.digest(self.current_raw), "bodyBytes": len(self.current_raw),
                                "observedAt": monitor.stamp(self.now)}, "review": copy.deepcopy(row["review"]),
                "baselineRevalidationOnly": True, "preserveChargesAndWaits": True}

    def save_request(self):
        self.path.write_bytes(cr.json_bytes(self.request))

    def admission(self):
        context = self.context()
        context.update(operation="review-held-host", reviewRequestSha256=cr.digest(self.path.read_bytes()),
                       nativeIdentity="7" * 64)
        return workspace.DistributionAdmission(context, parent_alive=lambda: True, identity=lambda path: "4" * 64)

    def review(self, *, checkpoint=None, admission=None):
        with patch.object(workspace, "binding", return_value=self.expected):
            return workspace.review_held_host(self.package, self.root, self.path, admission or self.admission(),
                                               checkpoint=checkpoint, clock=lambda: self.now)

    def fingerprints(self):
        return {str(path.relative_to(self.store)): cr.digest(path.read_bytes())
                for path in self.store.rglob("*") if path.is_file() and path.name != "writer.lock"}


class HeldHostReviewTests(unittest.TestCase):
    """一hostだけの許可差分と失敗時の原state/監査保持を確認する。"""

    def fixture(self):
        return ReviewFixture()

    def reject(self, fixture, code, **options):
        before = (fixture.store / "state.json").read_bytes()
        with self.assertRaisesRegex(cr.RegistryError, code):
            fixture.review(**options)
        self.assertEqual((fixture.store / "state.json").read_bytes(), before)

    def test_success_preserves_history_charges_waits_and_original_reviews(self):
        f = self.fixture()
        before = monitor.verify_store(f.store)
        pins = f.fingerprints()
        result = f.review()
        after = monitor.verify_store(f.store)
        expected = copy.deepcopy(before)
        expected["hosts"][f.request["hostSha256"]]["held"] = False
        expected["observedAt"] = monitor.stamp(f.now)
        self.assertEqual(after, expected)
        self.assertEqual(result["result"], "REVIEWED_BASELINE_OFFLINE")
        self.assertFalse(result["communicationAuthorized"])
        self.assertFalse(result["freshSuccess"])
        now_pins = f.fingerprints()
        self.assertEqual({key: value for key, value in pins.items() if key != "state.json"},
                         {key: value for key, value in now_pins.items() if key != "state.json"})
        audit = f.root / "host-reviews" / f.request["reviewId"]
        self.assertEqual(cr.read_json(audit / "request.json")["review"], f.request["review"])
        self.assertEqual(len(list(audit.iterdir())), 8)
        final = (f.store / "state.json").read_bytes()
        self.assertEqual(f.review()["result"], "ALREADY_REVIEWED")
        self.assertEqual((f.store / "state.json").read_bytes(), final)

    def test_state_and_journal_cas(self):
        for field in ("stateSha256", "journalSha256", "workspaceSha256"):
            with self.subTest(field=field):
                f = self.fixture()
                f.request[field] = "0" * 64
                f.save_request()
                self.reject(f, "HOST_REVIEW_CAS")

    def test_other_host_unknown_profile_and_other_cause(self):
        for field, value, code in (("hostSha256", "0" * 64, "HOST_REVIEW_HOST_MISSING"),
                                   ("profileId", "unknown-profile", "HOST_REVIEW_PROFILE")):
            with self.subTest(field=field):
                f = self.fixture()
                f.request[field] = value
                f.save_request()
                self.reject(f, code)
        f = self.fixture()
        f.request["cause"]["kind"] = "IGNORE_SIGNATURE"
        f.save_request()
        self.reject(f, "HOST_REVIEW_CAUSE")

    def test_result_security_rejection_is_not_releaseable(self):
        for field, value in (("error", -2147024891), ("reason", "SIGNATURE_REJECTED"), ("sourceVerified", True)):
            with self.subTest(field=field):
                f = self.fixture()
                journal = pipeline.verify_layout(f.store / "distribution")
                run_id = f.request["cause"]["runId"]
                path = f.store / "distribution/runs" / run_id / "result-0.json"
                result = cr.read_json(path)
                result[field] = value
                path.write_bytes(cr.json_bytes(result))
                digest = cr.digest(path.read_bytes())
                journal["runs"][run_id]["jobs"][0]["resultSha256"] = digest
                pipeline.save_journal(f.store, journal)
                f.request["cause"]["resultSha256"] = digest
                f.request["journalSha256"] = cr.digest((f.store / "distribution/journal.json").read_bytes())
                f.save_request()
                self.reject(f, "HOST_REVIEW_UNSUPPORTED_CAUSE")

    def test_unsettled_run_and_pending_intent(self):
        for mutation in ("phase", "pendingRun"):
            f = self.fixture()
            journal = pipeline.verify_layout(f.store / "distribution")
            if mutation == "phase":
                next(iter(journal["runs"].values()))["phase"] = "RUNNING"
            else:
                journal["pendingRun"] = {"runId": "run-" + "a" * 32, "planHash": "1" * 64}
            pipeline.save_journal(f.store, journal)
            f.request["journalSha256"] = cr.digest((f.store / "distribution/journal.json").read_bytes())
            f.save_request()
            self.reject(f, "HOST_REVIEW_NOT_SETTLED")

    def test_wait_clock_and_stale_page(self):
        f = self.fixture()
        f.now -= timedelta(seconds=2)
        self.reject(f, "HOST_REVIEW_WAIT")
        f = self.fixture()
        f.request["currentPage"]["observedAt"] = monitor.stamp(f.now - timedelta(days=1, seconds=1))
        f.save_request()
        self.reject(f, "HOST_REVIEW_PAGE_STALE")
        f = self.fixture()
        f.now += timedelta(days=8)
        f.request["currentPage"]["observedAt"] = monitor.stamp(f.now)
        f.save_request()
        self.reject(f, "HOST_REVIEW_SCOPE_STALE")

    def test_changed_body_href_terms_raw_and_scope(self):
        for token in (b'driver.zip', b'terms'):
            f = self.fixture()
            current = f.current_raw.replace(token, b'changed')
            (f.review_directory / "current.raw.html").write_bytes(current)
            f.request["currentPage"].update(bodyBytes=len(current), bodySha256=cr.digest(current))
            f.save_request()
            self.reject(f, "HOST_REVIEW_CONTENT_CHANGED")
        f = self.fixture()
        f.request["review"]["terms"]["state"] = "UNKNOWN"
        f.save_request()
        self.reject(f, "HOST_REVIEW_SCOPE_CHANGED")
        f = self.fixture()
        (f.review_directory / "baseline.raw.html").write_bytes(f.baseline + b'changed')
        self.reject(f, "HOST_REVIEW_CONTENT_CHANGED")

    def test_wrong_data_and_missing_raw_ack(self):
        f = self.fixture()
        f.request["inputHashes"]["profiles"] = "0" * 64
        f.save_request()
        self.reject(f, "HOST_REVIEW_INPUT_CHANGED")
        f = self.fixture()
        f.request["cause"]["originalRawMissing"] = False
        f.save_request()
        self.reject(f, "HOST_REVIEW_MISSING_RAW_ACK")

    def test_parent_identity_context_and_monitor_lock(self):
        for kind, code in (("parent", "NATIVE_CONTEXT_RELEASED"), ("identity", "NATIVE_CONTEXT_BINDING"),
                           ("operation", "NATIVE_CONTEXT_OPERATION"), ("request", "NATIVE_CONTEXT_OPERATION")):
            f = self.fixture()
            admission = f.admission()
            if kind == "parent":
                admission.parent_alive = lambda: False
            elif kind == "identity":
                admission.identity = lambda path: "0" * 64
            elif kind == "operation":
                admission.document["operation"] = "verify"
            else:
                admission.document["reviewRequestSha256"] = "0" * 64
            self.reject(f, code, admission=admission)
        f = self.fixture()
        with monitor.writer_lock(f.store):
            self.reject(f, "MONITOR_BUSY")

    def test_cas_and_parent_change_after_durable_intent(self):
        for kind in ("state", "journal", "parent"):
            f = self.fixture()
            admission = f.admission()
            original = (f.store / "state.json").read_bytes()
            def interrupt(stage, audit):
                if stage == "INTENT_SAVED":
                    if kind == "state":
                        state = monitor.verify_store(f.store)
                        state["observedAt"] = monitor.stamp(f.now)
                        monitor.save_state(f.store, state)
                    elif kind == "journal":
                        journal = pipeline.verify_layout(f.store / "distribution")
                        journal["cursor"] = "concurrent-writer"
                        pipeline.save_journal(f.store, journal)
                    else:
                        admission.parent_alive = lambda: False
            with self.assertRaisesRegex(cr.RegistryError, "HOST_REVIEW_CAS|NATIVE_CONTEXT_RELEASED"):
                f.review(checkpoint=interrupt, admission=admission)
            self.assertTrue(monitor.verify_store(f.store)["hosts"][f.request["hostSha256"]]["held"])
            self.assertTrue((f.root / "host-reviews" / f.request["reviewId"] / "intent.json").exists())
            if kind != "state":
                self.assertEqual((f.store / "state.json").read_bytes(), original)

    def test_interrupted_snapshots_intent_and_replace_keep_originals(self):
        for point in ("ORIGINAL_SAVED", "INTENT_SAVED", "REPLACED"):
            with self.subTest(point=point):
                f = self.fixture()
                before = (f.store / "state.json").read_bytes()
                def interrupt(stage, audit):
                    if stage == point:
                        raise OSError("injected-stop")
                with self.assertRaisesRegex(OSError, "injected-stop"):
                    f.review(checkpoint=interrupt)
                audit = f.root / "host-reviews" / f.request["reviewId"]
                self.assertEqual((audit / "state-before.json").read_bytes(), before)
                self.assertFalse((audit / "receipt.json").exists())
                if point == "ORIGINAL_SAVED":
                    self.reject(f, "HOST_REVIEW_AUDIT_INCOMPLETE")
                else:
                    self.assertEqual(f.review()["result"], "REVIEWED_BASELINE_OFFLINE")
                    self.assertFalse(monitor.verify_store(f.store)["hosts"][f.request["hostSha256"]]["held"])

    def test_new_hold_after_review_and_tampered_audit_are_rejected(self):
        f = self.fixture()
        f.review()
        state = monitor.verify_store(f.store)
        state["hosts"][f.request["hostSha256"]]["held"] = True
        state["observedAt"] = monitor.stamp(f.now + timedelta(seconds=1))
        monitor.save_state(f.store, state)
        f.now += timedelta(seconds=1)
        self.reject(f, "HOST_REVIEW_CAS")
        f = self.fixture()
        f.review()
        audit = f.root / "host-reviews" / f.request["reviewId"]
        (audit / "intent.json").write_bytes(b'{}')
        self.reject(f, "HOST_REVIEW_AUDIT_CHANGED")

    def test_retained_original_raw_is_verified_separately(self):
        f = self.fixture()
        directory = f.store / "distribution/runs" / f.request["cause"]["runId"]
        raw = b'<html><body>unreviewed changed page</body></html>'
        monitor.write_new_bytes(directory / "page-0.body", raw)
        f.request["cause"]["originalRawMissing"] = False
        f.save_request()
        self.assertEqual(f.review()["result"], "REVIEWED_BASELINE_OFFLINE")
        self.assertEqual((directory / "page-0.body").read_bytes(), raw)

    def test_native_shared_host_and_policy_hold_are_not_overridden(self):
        f = self.fixture()
        admission = f.admission()
        admission.document["hostHashes"] = [f.request["hostSha256"]]
        self.reject(f, "HOST_REVIEW_SCOPE_HELD", admission=admission)
        f = self.fixture()
        policy = cr.read_json(f.package / "config/monitor-policy.json")
        policy["heldSourceIds"] = [f.value["profiles"][0]["sourceId"]]
        (f.package / "config/monitor-policy.json").write_bytes(cr.json_bytes(policy))
        self.reject(f, "HOST_REVIEW_SCOPE_HELD")

    def test_monitor_in_progress_and_reserved_request_are_not_reviewed(self):
        f = self.fixture()
        state = monitor.verify_store(f.store)
        row = next(iter(state["requests"].values()))
        row.update(outcome="IN_PROGRESS", endedAt=None, reason="NONE", httpStatus=None, lastSuccess=None)
        monitor.save_state(f.store, state)
        f.request["stateSha256"] = cr.digest((f.store / "state.json").read_bytes())
        f.save_request()
        self.reject(f, "HOST_REVIEW_NOT_SETTLED")
        f = self.fixture()
        journal = pipeline.verify_layout(f.store / "distribution")
        row = next(iter(journal["requests"].values()))
        row.update(phase="RESERVED", endedAt=None)
        pipeline.save_journal(f.store, journal)
        f.request["journalSha256"] = cr.digest((f.store / "distribution/journal.json").read_bytes())
        f.save_request()
        self.reject(f, "HOST_REVIEW_NOT_SETTLED")

    def test_commit_clock_identity_and_data_are_rechecked(self):
        for kind in ("clock", "identity", "data"):
            f = self.fixture()
            admission = f.admission()
            def interrupt(stage, audit):
                if stage == "INTENT_SAVED":
                    if kind == "clock":
                        f.now -= timedelta(seconds=1)
                    elif kind == "identity":
                        admission.identity = lambda path: "0" * 64
                    else:
                        path = f.package / "seed/distribution-data/collection-profiles.json"
                        path.write_bytes(path.read_bytes() + b' ')
            self.reject(f, "HOST_REVIEW_CLOCK|NATIVE_CONTEXT_RELEASED|DATA_", checkpoint=interrupt, admission=admission)

    def test_snapshot_replace_and_receipt_failures_keep_original_audit(self):
        for member in ("state-before.json", "intent.json", "receipt.json", "replace"):
            with self.subTest(member=member):
                f = self.fixture()
                before = (f.store / "state.json").read_bytes()
                write = monitor.write_new_bytes
                replace = workspace.os.replace
                def failing_write(path, raw):
                    if path.name == member:
                        raise OSError("injected-save-failure")
                    return write(path, raw)
                def failing_replace(source, target):
                    if member == "replace" and Path(target) == f.store / "state.json":
                        raise OSError("injected-replace-failure")
                    return replace(source, target)
                with patch.object(monitor, "write_new_bytes", side_effect=failing_write), patch.object(
                        workspace.os, "replace", side_effect=failing_replace):
                    with self.assertRaisesRegex(OSError, "injected-"):
                        f.review()
                audit = f.root / "host-reviews" / f.request["reviewId"]
                self.assertTrue((audit / "request.json").exists())
                if member == "receipt.json":
                    self.assertFalse(monitor.verify_store(f.store)["hosts"][f.request["hostSha256"]]["held"])
                    self.assertEqual(f.review()["result"], "REVIEWED_BASELINE_OFFLINE")
                else:
                    self.assertEqual((f.store / "state.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
