"""非通信workspace adapterのbyte保持・中断再開・拒否を人工fixtureで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Native ACLと同梱runtimeの実試験は別の有限fixtureで実施する。
"""
from datetime import datetime, timedelta
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_workspace as workspace
import registry_daily_monitor as monitor
import registry_monitor_http as http
from test_collector_registry import fixture


def historical_store(root: Path) -> dict:
    """旧成功、翌日失敗、host hold、有限予算reportを人工transportだけで作る。"""
    registry = fixture()
    policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
    first = datetime(2026, 10, 3, 1)
    if root.exists():
        monitor.verify_store(root)
        monitor.save_state(root, {"schema": monitor.STATE_SCHEMA, "createdAt": monitor.stamp(first),
                                 "observedAt": monitor.stamp(first), "requests": {}, "hosts": {}})
    else:
        monitor.initialize(root, clock=lambda: first)
    monitor.run_once(registry, policy, root, clock=lambda: first,
                     transport=lambda kind, url: http.response(200, body=b"<html>fixture</html>")
                     if kind == "PAGE" else http.response(200))
    monitor.run_once(registry, policy, root, clock=lambda: first + timedelta(days=1),
                     transport=lambda kind, url: http.response(error="TIMEOUT"))
    state = monitor.verify_store(root)
    assert len(state["requests"]) == 2 and all(row["lastSuccess"] for row in state["requests"].values())
    assert all(row["outcome"] == "FAILED" for row in state["requests"].values())
    assert all(row["held"] for row in state["hosts"].values())
    assert any(monitor.read_envelope(path, "dc-monitor-report-envelope-v1")["counts"]["budgetBytes"] > 0
               for path in (root / "reports").iterdir())
    return state


class WorkspaceTests(unittest.TestCase):
    """既存monitorへ委譲した非通信成功と負例を別々に確認する。"""

    def setUp(self):
        """各testで別の人工rootと同じbindingを使用する。

        DRIVERCRATE_WORKSPACE_TEST_ROOT指定時はその値をmkdtempの親dirへ渡し、
        未指定時はOS既定のtempを使う。addCleanupはbinding差替えのpatcher.stopだけを
        登録し、人工rootとそのbyteは成功・失敗とも削除せず保持する。
        """
        fixture_parent = os.environ.get("DRIVERCRATE_WORKSPACE_TEST_ROOT")
        self.base = Path(tempfile.mkdtemp(prefix="workspace-unit-", dir=fixture_parent))
        self.expected = {"schema": workspace.SCHEMA, "packageManifestSha256": "1" * 64,
                         "seedManifestSha256": "2" * 64, "communicationAuthorized": False,
                         "nativeConstraints": "UNKNOWN", "originalDayBudget": "UNVERIFIED"}
        patcher = patch.object(workspace, "binding", return_value=self.expected)
        patcher.start()
        self.addCleanup(patcher.stop)

    def create_root(self, name: str) -> Path:
        """Nativeが先に作成する空rootをunit fixtureで代用する。"""
        root = self.base / name
        root.mkdir()
        return root

    def source(self) -> tuple[Path, dict]:
        """履歴を持つ停止snapshotを作り、移設対象のstateを返す。"""
        state = historical_store(self.base / "history")
        monitor.export_store(self.base / "history", self.base / "snapshot")
        return self.base / "snapshot", state

    def assert_source_bytes(self, source: Path, store: Path) -> None:
        """移設されたstateと全reportを元snapshotの実byteへ照合する。"""
        for row in cr.read_json(source / "manifest.json")["files"]:
            self.assertEqual((source / row["path"]).read_bytes(), (store / row["path"]).read_bytes())

    def test_fresh_initialize_is_offline(self):
        """正常初期化でも通信許可と未知制約を別fieldへ残す。"""
        root = self.create_root("fresh")
        result = workspace.operate(self.base, "initialize", root, None)
        self.assertEqual(result["result"], "VERIFIED_OFFLINE")
        self.assertIs(result["communicationAuthorized"], False)
        self.assertEqual((result["nativeConstraints"], result["originalDayBudget"]), ("UNKNOWN", "UNVERIFIED"))
        self.assertEqual(set(path.name for path in root.iterdir()), {"workspace.json", "monitor"})

    def test_origin_requires_current_native_context(self):
        """現行の原点を持つworkspaceはnative contextなしで検査を通さない。"""
        root = self.create_root("with-origin")
        workspace.operate(self.base, "initialize", root, None)
        (root / "origin.json").write_bytes(b"not a v5 binding")
        before = (root / "monitor/state.json").read_bytes()
        with self.assertRaisesRegex(cr.RegistryError, "NATIVE_LIVE_CONTEXT_REQUIRED"):
            workspace.operate(self.base, "verify", root, None)
        self.assertEqual((root / "monitor/state.json").read_bytes(), before)

    def test_export_with_origin_rejects_missing_context_and_keeps_history(self):
        """原点名だけを権限へ変換せず、停止export拒否でも全履歴byteを保持する。"""
        source, state = self.source()
        root = self.create_root("v4-export-with-origin")
        workspace.operate(self.base, "import", root, source)
        (root / "origin.json").write_bytes(b"not a v5 binding")
        output = self.create_root("v4-export-result")
        with self.assertRaisesRegex(cr.RegistryError, "NATIVE_LIVE_CONTEXT_REQUIRED"):
            workspace.operate(self.base, "export", root, output)
        self.assertEqual(monitor.verify_store(root / "monitor"), state)
        self.assert_source_bytes(source, root / "monitor")
        self.assertEqual(list(output.iterdir()), [])

    def test_normal_import_preserves_history_bytes(self):
        """HOLD拒否ではなく十分な履歴の正常importと元byte一致を確認する。"""
        source, state = self.source()
        root = self.create_root("imported")
        result = workspace.operate(self.base, "import", root, source)
        self.assertEqual(monitor.verify_store(root / "monitor"), state)
        self.assertEqual(result["reports"], 2)
        self.assert_source_bytes(source, root / "monitor")

    def test_same_snapshot_interrupted_resume_preserves_bytes(self):
        """最初のfile保存で中断した同snapshotだけを正常再開する。"""
        source, state = self.source()
        root = self.create_root("resumed")

        def interrupt(stage, path):
            """人工中断でstagingを残す。"""
            if stage == "FILE_SAVED":
                raise RuntimeError("fixture-interruption")

        with self.assertRaisesRegex(RuntimeError, "fixture-interruption"):
            workspace.operate(self.base, "import", root, source, checkpoint=interrupt)
        self.assertTrue(any(".import-" in path.name for path in root.iterdir()))
        workspace.operate(self.base, "resume", root, source)
        self.assertEqual(monitor.verify_store(root / "monitor"), state)
        self.assert_source_bytes(source, root / "monitor")

    def test_changed_partial_bytes_rejected_and_preserved(self):
        """同名staging内の改変を修復せず拒否する。"""
        source, _ = self.source()
        root = self.create_root("partial")

        def interrupt(stage, path):
            """Metadata保存直後に中断する。"""
            if stage == "METADATA_SAVED":
                raise RuntimeError("fixture-interruption")

        with self.assertRaises(RuntimeError):
            workspace.operate(self.base, "import", root, source, checkpoint=interrupt)
        stage = next(path for path in root.iterdir() if ".import-" in path.name)
        (stage / "state.json").write_bytes(b"changed partial")
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_PARTIAL_CHANGED"):
            workspace.operate(self.base, "resume", root, source)
        self.assertEqual((stage / "state.json").read_bytes(), b"changed partial")

    def test_different_snapshot_resume_rejected(self):
        """別snapshotへ変更した再開は新規stageも作らず拒否する。"""
        source, _ = self.source()
        root = self.create_root("different")

        def interrupt(stage, path):
            """Metadataを保存した同snapshotを保持する。"""
            if stage == "METADATA_SAVED":
                raise RuntimeError("fixture-interruption")

        with self.assertRaises(RuntimeError):
            workspace.operate(self.base, "import", root, source, checkpoint=interrupt)
        state = monitor.verify_store(self.base / "history")
        state["observedAt"] = "2026-10-05T01:00:00Z"
        monitor.save_state(self.base / "history", state)
        monitor.export_store(self.base / "history", self.base / "other")
        with self.assertRaises((cr.RegistryError, OSError)):
            workspace.operate(self.base, "resume", root, self.base / "other")

    def test_future_clock_import_is_rejected(self):
        """移設側時計が元観測より古い場合は拒否しrootを保持する。"""
        source, _ = self.source()
        root = self.create_root("future")
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_CLOCK"):
            workspace.operate(self.base, "import", root, source, clock=lambda: datetime(2026, 10, 1))
        self.assertTrue((root / "workspace.json").exists())

    def test_incomplete_reservation_export_rejected(self):
        """未完了予約を消去せずexportを拒否する。"""
        historical_store(self.base / "pending")
        state = monitor.verify_store(self.base / "pending")
        row = next(iter(state["requests"].values()))
        row.update(outcome="IN_PROGRESS", endedAt=None, reason="NONE", httpStatus=None)
        monitor.save_state(self.base / "pending", state)
        before = (self.base / "pending" / "state.json").read_bytes()
        with self.assertRaisesRegex(cr.RegistryError, "EXPORT_INCOMPLETE_RESERVATION"):
            monitor.export_store(self.base / "pending", self.base / "blocked")
        self.assertEqual((self.base / "pending" / "state.json").read_bytes(), before)

    def test_network_and_process_audit_rejected(self):
        """固定adapterの逸脱防止hookをevent入力で決定的に確認する。"""
        for event in ("socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.exec"):
            with self.subTest(event=event), self.assertRaisesRegex(cr.RegistryError, "FORBIDDEN"):
                workspace.reject_external_execution(event, ())
        workspace.reject_external_execution("open", ())

    def test_existing_or_unknown_content_is_not_reused(self):
        """既存のbyteや任意moduleをworkspaceへ混入させない。"""
        root = self.create_root("existing")
        (root / "sentinel").write_bytes(b"keep")
        with self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_NOT_EMPTY"):
            workspace.operate(self.base, "initialize", root, None)
        self.assertEqual((root / "sentinel").read_bytes(), b"keep")


class PackageSwitchTests(unittest.TestCase):
    """現形式の原hash reviewと既存admissionを、本物journal/byte保存へ接続する。"""

    def test_retained_v1_data_and_run_survive_switch_then_current_import(self):
        """保存v1の非通信切替と新v2 importを、元run/hash/待機を保った人工rootへ接続する。"""
        import collector_collection_profiles as cp
        import collector_distribution_data as data
        import collector_distribution_pipeline as pipeline
        original_make = cp.make_static_job

        def old_job(*args):
            job = original_make(*args)
            job['schema'] = 'dc-collector-registry-job-v1'
            for item in job['review'].values():
                item['evidence'].pop('contentSha256')
            return job

        with patch.object(cp, 'make_static_job', side_effect=old_job):
            self.prepare()
        current = data.active_bundle(self.root)
        old = copy.deepcopy(current['profiles'])
        old['schema'] = 'dc-collector-collection-profiles-v1'
        for row in old['profiles']:
            for item in row['review'].values():
                item['evidence'].pop('contentSha256')
        content = data.bundle_content({**current['raw'], 'profiles': cr.json_bytes(old)}, retained=True)
        digest = cr.digest(content['manifest.json'])
        directory = self.root / 'data/generations' / digest
        directory.mkdir()
        for name, raw in content.items():
            (directory / name).write_bytes(raw)
        (self.root / 'data/active.json').write_bytes(cr.json_bytes({'schema': data.ACTIVE_SCHEMA, 'sha256': digest}))
        before = self.retained()
        with self.assertRaises(cr.RegistryError):
            pipeline.inputs_at(self.package, self.root)
        self.assertEqual(self.switch()['result'], 'VERIFIED_OFFLINE')
        self.assertEqual(self.retained(), before)
        data.import_data(self.root, self.package / 'seed/distribution-data')
        _, value, _ = pipeline.inputs_at(self.package, self.root)
        self.assertEqual(value['schema'], cp.SCHEMA)
        after = self.retained()
        self.assertTrue(all(after[name] == raw for name, raw in before.items() if name != 'data/active.json'))
        journal = pipeline.verify_layout(self.root / 'monitor/distribution')
        self.assertIsNone(journal['pendingRun'])
        self.assertTrue(all(row['phase'] == 'FINISHED' for row in journal['runs'].values()))
        original_jobs = list((self.root / 'monitor/distribution/runs').glob('*/job-0.json'))
        self.assertEqual(len(original_jobs), 1)
        self.assertEqual(cr.read_json(original_jobs[0])['schema'], 'dc-collector-registry-job-v1')

    def setUp(self):
        """完全fake配布の確定runと、実snapshot/receiptを持つ次packageを作る。"""
        self.prepare()

    def prepare(self):
        """新しい所有fixtureを作り、原履歴を実validatorで確定する。"""
        from test_collector_distribution_pipeline import Fixture
        import collector_distribution_data as data
        self.fixture = Fixture(count=1)
        self.assertEqual(self.fixture.run()["result"], "COMPLETE")
        self.package, self.root = self.fixture.package, self.fixture.root
        self.now = self.fixture.now + timedelta(hours=1)
        for member, raw in workspace.snapshot.snapshot_content(
                self.fixture.inputs["registry"], self.fixture.inputs["locators"]).items():
            target = self.package / "seed/collector-data" / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (self.package / "package-manifest.json").write_bytes(cr.json_bytes({
            "schema": "dc-collector-package-v7", "mode": "EXPLICIT_DISTRIBUTION_DATA_DAILY"}))
        (self.package / "install-receipt.json").write_bytes(cr.json_bytes({
            "schema": "dc-collector-install-receipt-v3", "installedUtc": "2026-10-23T00:00:00Z",
            "packageManifestSha256": cr.digest((self.package / "package-manifest.json").read_bytes())}))
        self.expected = workspace.binding(self.package)
        self.original = (self.root / "workspace.json").read_bytes()
        self.reviewed = cr.digest(self.original)
        for member in ("origin.json", "distribution-origin-init-v1.json", "distribution-initial-plan-v1.json"):
            (self.root / member).write_bytes(b'{"unitFixtureNativeChecksAreSeparate":true}\n')
        data.import_data(self.root, self.package / "seed/distribution-data")

    def live(self, **overrides):
        """nativeの内部seamだけで人工leaseを作り、同じ実identity validatorを通す。"""
        document = {"schema": "dc-collector-live-admission-v1", "operation": "switch-package",
            "nativeMode": "VERIFIED_PRISTINE_V1", "nativeDigest": "a" * 64, "nativeFileCount": 0,
            "originInitializationComplete": True, "legacyHistoryEverObserved": False,
            "workspaceIdentity": workspace.directory_identity(self.root),
            "monitorIdentity": workspace.directory_identity(self.root / "monitor"),
            "monitorRoot": str(self.root / "monitor"), "reviewedWorkspaceSha256": self.reviewed,
            "issuedAtUtcMillis": int(self.now.replace(tzinfo=monitor.timezone.utc).timestamp() * 1000),
            "packageManifestSha256": self.expected["packageManifestSha256"],
            "seedManifestSha256": self.expected["seedManifestSha256"],
            "policySha256": cr.digest((self.package / "config/monitor-policy.json").read_bytes()),
            "requestHashes": ["b" * 64], "hostHashes": ["c" * 64]}
        document.update(overrides)
        return workspace.DistributionAdmission(document, parent_alive=lambda: True)

    def retained(self):
        """workspace bindingと今回のarchive以外の全履歴/active/原点byteを比較する。"""
        return {path.relative_to(self.root).as_posix(): path.read_bytes() for path in self.root.rglob("*")
                if path.is_file() and path != self.root / "workspace.json" and
                "package-switches" not in path.relative_to(self.root).parts}

    def switch(self, **options):
        """製品の同じ切替関数へ内部人工leaseを渡す。"""
        live = options.pop("admission", self.live())
        return workspace.switch_package(self.package, self.root, self.reviewed, live,
                                        clock=lambda: self.now, **options)

    def test_switch_preserves_raw_origin_ledger_wait_budget_and_active(self):
        """確定runを保持した正例で、現在bindingと原archive/通常validateを確認する。"""
        self.original = b" \n" + self.original + b"\n"
        (self.root / "workspace.json").write_bytes(self.original)
        self.reviewed = cr.digest(self.original)
        before = self.retained()
        result = self.switch()
        self.assertEqual(result["result"], "VERIFIED_OFFLINE")
        self.assertEqual(result["previousWorkspaceSha256"], self.reviewed)
        self.assertFalse(result["communicationAuthorized"])
        self.assertEqual((result["nativeConstraints"], result["originalDayBudget"], result["tasks"]),
                         ("UNKNOWN", "UNVERIFIED", 0))
        self.assertEqual(self.retained(), before)
        self.assertEqual((self.root / "package-switches" / (self.reviewed + ".json")).read_bytes(), self.original)
        self.assertEqual({key for key in self.expected if self.expected[key] != cr.parse_json(self.original)[key]},
                         {"packageManifestSha256", "seedManifestSha256"})
        workspace.validate_workspace(self.root, self.expected)
        with self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_BINDING"):
            workspace.validate_workspace(self.root, cr.parse_json(self.original))

    def test_current_package_seed_receipt_are_required_before_any_write(self):
        """誤package/seed/receiptを受理せず原bindingと全履歴を残す。"""
        changes = [("package-manifest.json", "schema", "dc-collector-package-v6"),
                   ("package-manifest.json", "mode", "UNKNOWN"),
                   ("install-receipt.json", "schema", "dc-collector-install-receipt-v2"),
                   ("install-receipt.json", "packageManifestSha256", "0" * 64),
                   ("seed/collector-data/manifest.json", "schema", "unknown")]
        before = self.retained()
        for member, field, value in changes:
            with self.subTest(member=member, field=field):
                path = self.package / member
                raw = path.read_bytes()
                changed = cr.parse_json(raw)
                changed[field] = value
                path.write_bytes(cr.json_bytes(changed))
                with self.assertRaises(cr.RegistryError):
                    self.switch()
                path.write_bytes(raw)
                self.assertEqual((self.root / "workspace.json").read_bytes(), self.original)
                self.assertFalse((self.root / "package-switches").exists())
        receipt = self.package / "install-receipt.json"
        raw = receipt.read_bytes()
        receipt.unlink()
        with self.assertRaises(OSError):
            self.switch()
        receipt.write_bytes(raw)
        self.assertEqual(self.retained(), before)

    def test_review_hash_schema_unknown_fields_and_identity_are_closed(self):
        """reviewしたhashでも旧schema/未知fieldを補正せず、原fieldを保持する。"""
        for change in ({"schema": "dc-collector-explicit-workspace-v0"}, {"unknown": 1},
                       {"communicationAuthorized": True}, {"packageManifestSha256": None},
                       {"seedManifestSha256": "BAD"}):
            with self.subTest(change=tuple(change)):
                raw = cr.json_bytes({**cr.parse_json(self.original), **change})
                (self.root / "workspace.json").write_bytes(raw)
                with self.assertRaises(cr.RegistryError):
                    workspace.switch_package(self.package, self.root, cr.digest(raw), self.live(), clock=lambda: self.now)
                self.assertEqual((self.root / "workspace.json").read_bytes(), raw)
        (self.root / "workspace.json").write_bytes(self.original)
        with self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_SWITCH_REVIEW_HASH"):
            workspace.switch_package(self.package, self.root, "0" * 64, self.live(), clock=lambda: self.now)
        self.assertFalse((self.root / "package-switches").exists())

    def test_native_context_operation_review_epoch_and_all_root_identities_are_required(self):
        """通信context/別原hash/stale/別実体/解放済みleaseを切替へ転用しない。"""
        before = self.retained()
        for change in ({"operation": "distribution-run-once"}, {"reviewedWorkspaceSha256": "d" * 64},
                       {"issuedAtUtcMillis": 0}, {"workspaceIdentity": "e" * 64},
                       {"monitorIdentity": "f" * 64}, {"packageManifestSha256": "e" * 64},
                       {"seedManifestSha256": "f" * 64}, {"originInitializationComplete": False}):
            with self.subTest(change=tuple(change)), self.assertRaises(cr.RegistryError):
                self.switch(admission=self.live(**change))
        for mode in ("used", "dead", "missing"):
            live = self.live()
            if mode == "used":
                live.used = True
            elif mode == "dead":
                live.parent_alive = lambda: False
            else:
                live = None
            with self.subTest(mode=mode), self.assertRaises(cr.RegistryError):
                self.switch(admission=live)
        self.assertEqual(self.retained(), before)
        self.assertFalse((self.root / "package-switches").exists())

    def test_metadata_unfinished_or_unknown_is_rejected_without_settlement(self):
        """切替のために未確定metadataを回収/再課金せず、その全byteを残す。"""
        store = self.root / "monitor"
        state = monitor.verify_store(store)
        for outcome in ("IN_PROGRESS", "UNKNOWN_OUTCOME"):
            changed = copy.deepcopy(state)
            row = next(iter(changed["requests"].values()))
            row.update(outcome=outcome, endedAt=None if outcome == "IN_PROGRESS" else changed["observedAt"],
                       reason="NONE" if outcome == "IN_PROGRESS" else "UNKNOWN_OUTCOME", httpStatus=None)
            monitor.save_state(store, changed)
            before = self.retained()
            with self.subTest(outcome=outcome), self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_SWITCH_NOT_STOPPED"):
                self.switch()
            self.assertEqual(self.retained(), before)
        self.assertFalse((self.root / "package-switches").exists())

    def test_distribution_unfinished_unknown_and_pending_are_not_recovered(self):
        """原distribution run/予約を確定停止へ偽装しない。"""
        import collector_distribution_pipeline as distribution
        for mode in ("running", "unknown", "pending-run", "reserved"):
            self.prepare()
            store = self.root / "monitor"
            journal = distribution.verify_layout(store / "distribution")
            if mode in {"running", "unknown"}:
                next(iter(journal["runs"].values()))["phase"] = "RUNNING" if mode == "running" else "UNKNOWN_OUTCOME"
            elif mode == "pending-run":
                journal["pendingRun"] = {"runId": "run-" + "d" * 32, "planHash": "e" * 64}
            else:
                next(iter(journal["requests"].values()))["phase"] = "RESERVED"
            distribution.save_journal(store, journal)
            before = self.retained()
            with self.subTest(mode=mode), self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_SWITCH_NOT_STOPPED"):
                self.switch()
            self.assertEqual(self.retained(), before)
            self.assertFalse((self.root / "package-switches").exists())

    def test_monitor_lock_and_second_apply_are_rejected(self):
        """元writer競合ではarchiveを作らず、成功後の再適用も上書きしない。"""
        before = self.retained()
        with monitor.writer_lock(self.root / "monitor"):
            with self.assertRaisesRegex(cr.RegistryError, "MONITOR_BUSY"):
                self.switch()
        self.assertEqual(self.retained(), before)
        self.assertFalse((self.root / "package-switches").exists())
        self.switch()
        archive = (self.root / "package-switches" / (self.reviewed + ".json")).read_bytes()
        with self.assertRaises(cr.RegistryError):
            self.switch()
        self.assertEqual((self.root / "package-switches" / (self.reviewed + ".json")).read_bytes(), archive)

    def test_interrupted_windows_keep_original_and_do_not_auto_resume(self):
        """三保存窓の中断で原byteを保持し、二回適用やpendingの通常利用を拒否する。"""
        for stage in ("ORIGINAL_SAVED", "REPLACEMENT_SAVED", "REPLACED"):
            self.prepare()
            before = self.retained()
            def stop(actual, path):
                """所有fixtureだけへ保存後例外を注入する。"""
                if actual == stage:
                    raise RuntimeError("fixture-interrupted")
            with self.subTest(stage=stage), self.assertRaisesRegex(RuntimeError, "fixture-interrupted"):
                self.switch(checkpoint=stop)
            self.assertEqual(self.retained(), before)
            self.assertEqual((self.root / "package-switches" / (self.reviewed + ".json")).read_bytes(), self.original)
            current = (self.root / "workspace.json").read_bytes()
            self.assertEqual(current, cr.json_bytes(self.expected) if stage == "REPLACED" else self.original)
            with self.assertRaises(cr.RegistryError):
                self.switch()
            if stage == "REPLACEMENT_SAVED":
                with self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_SWITCH_INCOMPLETE"):
                    workspace.validate_workspace(self.root, cr.parse_json(self.original))

    def test_concurrent_byte_change_and_unknown_archive_are_preserved(self):
        """最終原hash再照合とarchive閉集合を確認し、競合byteを修復しない。"""
        def change(stage, path):
            """新pendingのflush後に自己所有の原fileだけを競合変更する。"""
            if stage == "REPLACEMENT_SAVED":
                (self.root / "workspace.json").write_bytes(self.original + b" ")
        before = self.retained()
        with self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_SWITCH_INPUT_CHANGED"):
            self.switch(checkpoint=change)
        self.assertEqual(self.retained(), before)
        self.assertEqual((self.root / "workspace.json").read_bytes(), self.original + b" ")
        self.prepare()
        history = self.root / "package-switches"
        history.mkdir()
        (history / "unexpected.json").write_bytes(b"keep")
        with self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_SWITCH_FILE_SET"):
            self.switch()
        self.assertEqual((history / "unexpected.json").read_bytes(), b"keep")

    def test_old_binding_never_enters_normal_operations_and_switch_context_cannot_run(self):
        """原binding例外を切替へ閉じ、同じcontextを通信許可へ変換しない。"""
        before = self.retained()
        for action in ("verify", "export", "resume", "run-once"):
            with self.subTest(action=action), self.assertRaisesRegex(cr.RegistryError, "WORKSPACE_BINDING"):
                if action == "run-once":
                    workspace.run_monitor_once(self.package, self.root, confirmed=True, curl="unused",
                        admission=self.live(), transport=lambda *args: self.fail("network"), clock=lambda: self.now)
                else:
                    workspace.operate(self.package, action, self.root, None, admission=self.live(), clock=lambda: self.now)
        self.assertEqual(self.retained(), before)
        self.switch()
        with self.assertRaisesRegex(cr.RegistryError, "NATIVE_CONTEXT_OPERATION"):
            workspace.run_monitor_once(self.package, self.root, confirmed=True, curl="unused",
                admission=self.live(), transport=lambda *args: self.fail("network"), clock=lambda: self.now)
        import collector_distribution_pipeline as distribution
        class WrongBridge:
            """転用contextだけを渡し、交換開始を失敗へする。"""
            context = {**self.live().document, "inputHashes": self.fixture.context()["inputHashes"]}
            alive = staticmethod(lambda: True)
            def exchange(self, *args, **kwargs):
                raise AssertionError("bridge must not execute")
        with self.assertRaisesRegex(cr.RegistryError, "DISTRIBUTION_INPUT_BINDING"):
            distribution.run_once(self.package, self.root, WrongBridge(), confirmed=True, clock=lambda: self.now)


if __name__ == "__main__":
    unittest.main()
