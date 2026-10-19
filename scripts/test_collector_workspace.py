"""非通信workspace adapterのbyte保持・中断再開・拒否を人工fixtureで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Native ACLと同梱runtimeの実試験は別の有限fixtureで実施する。
"""
from datetime import datetime, timedelta
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

    def test_v4_origin_name_does_not_enable_v5_context(self):
        """旧v4で許されたorigin名だけをv5の原点bindingへ読み替えない。"""
        root = self.create_root("v4-with-origin")
        workspace.operate(self.base, "initialize", root, None)
        (root / "origin.json").write_bytes(b"not a v5 binding")
        before = (root / "monitor/state.json").read_bytes()
        result = workspace.operate(self.base, "verify", root, None)
        self.assertEqual((result["requests"], result["reports"]), (0, 0))
        self.assertFalse(result["communicationAuthorized"])
        self.assertEqual((root / "monitor/state.json").read_bytes(), before)

    def test_v4_export_with_origin_keeps_legacy_history(self):
        """旧v4のexportもorigin名だけで新contextを要求せず、全履歴byteを保持する。"""
        source, state = self.source()
        root = self.create_root("v4-export-with-origin")
        workspace.operate(self.base, "import", root, source)
        (root / "origin.json").write_bytes(b"not a v5 binding")
        output = self.create_root("v4-export-result")
        result = workspace.operate(self.base, "export", root, output)
        self.assertEqual((result["requests"], result["reports"]), (len(state["requests"]), 2))
        self.assertFalse(result["communicationAuthorized"])
        for row in cr.read_json(source / "manifest.json")["files"]:
            self.assertEqual((source / row["path"]).read_bytes(),
                             (output / "snapshot" / row["path"]).read_bytes())

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


if __name__ == "__main__":
    unittest.main()
