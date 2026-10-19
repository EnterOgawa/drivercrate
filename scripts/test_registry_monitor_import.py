"""監視exportの非通信import・保持・中断再開・拒否境界を検証する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空データと自作temporary directoryだけを使用し、実通信・Task・driver導入を行わない。
"""
import copy
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import unittest

import collector_registry as cr
import registry_daily_monitor as dm
import registry_monitor_http as http
from test_collector_registry import fixture


class ImportTests(unittest.TestCase):
    """移設で元の待機・結果・byteを失わず、途中rootから通信させない。"""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.export = self.base / "snapshot"
        self.output = self.base / "別host & data"
        self.now = datetime(2026, 10, 3, 1)
        self.registry = fixture()
        self.policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
        self.calls = []
        dm.initialize(self.root, clock=lambda: self.now)
        dm.run_once(self.registry, self.policy, self.root, clock=lambda: self.now, transport=self.transport)
        dm.export_store(self.root, self.export)

    def transport(self, kind, url):
        self.calls.append((kind, url))
        return http.response(200, body=b"<html>sample</html>") if kind == "PAGE" else http.response(200)

    def import_snapshot(self, **options):
        return dm.import_export(self.export, self.output, source_stop_acknowledged=True,
                                clock=lambda: self.now, **options)

    def snapshot_bytes(self):
        return {path.relative_to(self.export).as_posix(): path.read_bytes()
                for path in self.export.rglob("*") if path.is_file()}

    def interrupted_stage(self, at="FILE_SAVED"):
        """指定checkpointで同期的に中断し、再開検査用のstage pathを返す。

        callbackは観測したpathをsavedへ保持してから例外を出し、完成outputがないことを確認する。
        残したstageはこのhelperでは削除せず、case全体のTemporaryDirectoryに所有させる。
        """
        saved = []
        def stop(stage, path):
            saved.append(path)
            if stage == at:
                raise RuntimeError("fixture-stop")
        with self.assertRaisesRegex(RuntimeError, "fixture-stop"):
            self.import_snapshot(checkpoint=stop)
        self.assertFalse(self.output.exists())
        return saved[-1]

    def test_import_preserves_all_state_and_report_bytes(self):
        before = self.snapshot_bytes()
        state = dm.verify_export(self.export)
        self.import_snapshot()
        self.assertEqual(dm.verify_store(self.output), state)
        for name, raw in before.items():
            if name != "manifest.json":
                self.assertEqual((self.output / name).read_bytes(), raw)
        self.assertEqual(self.snapshot_bytes(), before)
        self.assertEqual((self.output / "writer.lock").read_bytes(), b"0")
        self.assertTrue((self.output / "import-metadata.json").exists())

    def test_import_same_day_has_no_http_and_next_day_preserves_baseline(self):
        self.import_snapshot()
        count = len(self.calls)
        report = dm.run_once(self.registry, self.policy, self.output, clock=lambda: self.now, transport=self.transport)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(len(self.calls), count)
        self.now += timedelta(days=1)
        report = dm.run_once(self.registry, self.policy, self.output, clock=lambda: self.now, transport=self.transport)
        self.assertEqual(report["counts"]["unchanged"], 1)
        self.assertEqual(report["counts"]["link_alive"], 1)

    def test_source_stop_acknowledgement_is_required_and_strict(self):
        for flag in (False, None, "true", 1):
            with self.subTest(flag=flag), self.assertRaisesRegex(cr.RegistryError, "IMPORT_SOURCE_STOP_REQUIRED"):
                dm.import_export(self.export, self.output, source_stop_acknowledged=flag)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.base.glob("*.import-*")), [])

    def test_existing_empty_destination_is_not_overwritten(self):
        self.output.mkdir()
        with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
            self.import_snapshot()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_future_clock_is_rejected_before_creation(self):
        self.now -= timedelta(seconds=1)
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_CLOCK"):
            self.import_snapshot()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.base.glob("*.import-*")), [])

    def test_all_import_checkpoints_resume_only_same_snapshot(self):
        for index, stage in enumerate(("METADATA_SAVED", "FILE_SAVED", "VALIDATED")):
            self.output = self.base / ("destination-" + str(index))
            interrupted = self.interrupted_stage(stage)
            with self.assertRaises(cr.RegistryError):
                dm.run_once(self.registry, self.policy, interrupted, transport=self.transport, clock=lambda: self.now)
            with self.assertRaisesRegex(cr.RegistryError, "IMPORT_STAGE_EXISTS"):
                self.import_snapshot()
            self.import_snapshot(resume=True)
            self.assertFalse(interrupted.exists())
            self.assertEqual(dm.verify_store(self.output), dm.verify_export(self.export))

    def test_partial_file_is_not_repaired_or_deleted(self):
        stage = self.interrupted_stage()
        report = next((stage / "reports").iterdir())
        report.write_bytes(b"partial")
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_PARTIAL_CHANGED"):
            self.import_snapshot(resume=True)
        self.assertEqual(report.read_bytes(), b"partial")
        self.assertTrue(stage.exists())
        self.assertFalse(self.output.exists())

    def test_unknown_stage_file_is_preserved_and_rejected(self):
        stage = self.interrupted_stage()
        unknown = stage / "unknown.txt"
        unknown.write_bytes(b"retained")
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_STAGE_FILES"):
            self.import_snapshot(resume=True)
        self.assertEqual(unknown.read_bytes(), b"retained")

    def test_resume_does_not_accept_changed_export(self):
        stage = self.interrupted_stage()
        previous = {path.relative_to(stage).as_posix(): path.read_bytes()
                    for path in stage.rglob("*") if path.is_file()}
        manifest = cr.read_json(self.export / "manifest.json")
        (self.export / "manifest.json").write_bytes(cr.json_bytes(manifest) + b" ")
        with self.assertRaises((OSError, cr.RegistryError)):
            self.import_snapshot(resume=True)
        self.assertEqual({path.relative_to(stage).as_posix(): path.read_bytes()
                          for path in stage.rglob("*") if path.is_file()}, previous)

    def test_import_lock_contention_is_rejected(self):
        stage = self.interrupted_stage()
        with dm.exclusive_file_lock(stage / "writer.lock"):
            with self.assertRaisesRegex(cr.RegistryError, "MONITOR_BUSY"):
                self.import_snapshot(resume=True)
        self.assertFalse(self.output.exists())

    def test_modified_snapshot_file_is_rejected_before_stage_creation(self):
        path = self.export / "state.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(cr.RegistryError, "EXPORT_FILE_HASH"):
            self.import_snapshot()
        self.assertEqual(list(self.base.glob("*.import-*")), [])

    def test_excessive_export_manifest_is_rejected_before_stage_creation(self):
        manifest = cr.read_json(self.export / "manifest.json")
        manifest["files"] = [manifest["files"][0]] * 4097
        (self.export / "manifest.json").write_bytes(cr.json_bytes(manifest))
        with self.assertRaisesRegex(cr.RegistryError, "EXPORT_FILE_LIMIT"):
            self.import_snapshot()
        self.assertEqual(list(self.base.glob("*.import-*")), [])

    def test_unfinished_reservation_is_not_imported_even_after_rehash(self):
        state = copy.deepcopy(dm.verify_export(self.export))
        row = next(iter(state["requests"].values()))
        row.update(outcome="IN_PROGRESS", endedAt=None, httpStatus=None, reason="NONE")
        path = self.export / "state.json"
        raw = dm.envelope("dc-monitor-state-envelope-v1", dm.validate_state(state))
        path.write_bytes(raw)
        manifest = cr.read_json(self.export / "manifest.json")
        entry = next(item for item in manifest["files"] if item["path"] == "state.json")
        entry.update(bytes=len(raw), sha256=cr.digest(raw))
        (self.export / "manifest.json").write_bytes(cr.json_bytes(manifest))
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_INCOMPLETE_RESERVATION"):
            self.import_snapshot()
        self.assertFalse(self.output.exists())

    def test_host_hold_and_long_deadline_survive_import(self):
        state = dm.verify_store(self.root)
        row = next(iter(state["requests"].values()))
        row["nextDueAt"] = dm.stamp(self.now + timedelta(days=5))
        for request in state["requests"].values():
            state["hosts"][request["hostSha256"]] = {"failedAt": dm.stamp(self.now),
                "nextDueAt": dm.stamp(self.now + timedelta(days=7)), "held": True}
        dm.save_state(self.root, state)
        second = self.base / "long-wait-export"
        dm.export_store(self.root, second)
        self.export = second
        self.import_snapshot()
        self.now += timedelta(days=2)
        count = len(self.calls)
        report = dm.run_once(self.registry, self.policy, self.output, clock=lambda: self.now, transport=self.transport)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(len(self.calls), count)
        self.assertEqual(dm.verify_store(self.output)["hosts"], state["hosts"])

    def test_unknown_outcome_preserves_previous_success_and_wait(self):
        state = dm.verify_store(self.root)
        row = next(iter(state["requests"].values()))
        previous = copy.deepcopy(row["lastSuccess"])
        row.update(outcome="UNKNOWN_OUTCOME", reason="UNKNOWN_OUTCOME", httpStatus=None)
        dm.save_state(self.root, state)
        second = self.base / "unknown-export"
        dm.export_store(self.root, second)
        self.export = second
        self.import_snapshot()
        imported = dm.verify_store(self.output)
        unknown = next(item for item in imported["requests"].values() if item["outcome"] == "UNKNOWN_OUTCOME")
        self.assertEqual(unknown["lastSuccess"], previous)
        self.assertEqual(unknown["nextDueAt"], row["nextDueAt"])
        count = len(self.calls)
        report = dm.run_once(self.registry, self.policy, self.output, clock=lambda: self.now, transport=self.transport)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(len(self.calls), count)

    def test_imported_store_exports_without_machine_import_metadata(self):
        self.import_snapshot()
        exported = self.base / "after-import"
        dm.export_store(self.output, exported)
        self.assertEqual(dm.verify_export(exported), dm.verify_export(self.export))
        self.assertFalse((exported / "writer.lock").exists())
        self.assertFalse((exported / "import-metadata.json").exists())


if __name__ == "__main__":
    unittest.main()
