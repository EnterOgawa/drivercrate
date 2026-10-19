"""索引hintから通常native検査への接続を架空byte・偽processで試験する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実driver・実process・network・導入を開始しない。
"""

import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import common_maintenance_index as mi
import common_index_package_handoff as handoff
from test_collector_registry import fixture
from test_collector_payload_evidence import evidence
from test_common_maintenance_index import assessments


def result(hint):
    """通常検査完了・全INF拒否の架空観測を返す。"""
    return {"schema": handoff.NATIVE_SCHEMA, "researchOnly": True, "publishable": False,
        "installAuthorized": False, "applicability": "NOT_CHECKED",
        **{k: hint[k] for k in ("indexSha256", "recordSha256", "archiveSha256", "archiveBytes")},
        "inputBound": True, "state": "INSPECTION_COMPLETED", "error": 0,
        "inventoryFileCount": 3, "infCount": 1, "verifiedInfCount": 0,
        "closureRejectedInfCount": 1, "signatureRejectedInfCount": 0, "infErrors": [-2147024846]}


class HandoffTests(unittest.TestCase):
    """取得観測・元byte・tool・native結果の非昇格と差替え拒否を検査する。"""

    def setUp(self):
        """原archiveと偽toolのbyteを専用temporary directoryへ置き、各caseの観測を作る。

        root配下は登録したtemp.cleanupが後始末する。nativeはresultの架空結果であり、
        callsはrunnerの呼出し回数だけを数え、toolを実行した回数ではない。
        """
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "snapshot"
        self.payload = self.root / "original.zip"
        self.tool = self.root / "fixture.exe"
        self.payload.write_bytes(b"abc")
        self.tool.write_bytes(b"fake-tool-not-executed")
        self.tool_hash = cr.digest(self.tool.read_bytes())
        self.registry = cr.validate_registry(fixture())
        self.evidence = evidence(self.registry)
        row = self.evidence["acquisitions"][0]
        row["sha256"] = cr.digest(b"abc")
        row["bytes"] = 3
        self.assessments = assessments(self.registry, self.evidence)
        self.assessments["infs"][0]["archiveSha256"] = row["sha256"]
        mi.write_bundle(self.registry, self.evidence, self.assessments, self.snapshot)
        self.hint = handoff.prepare(self.snapshot, "record-one")
        self.native = result(self.hint)
        self.calls = 0

    def runner(self, argv, **kwargs):
        """引数を検査し、nativeを起動しない固定processを返す。"""
        self.calls += 1
        self.assertEqual(argv[2:], [self.hint[k] for k in ("indexSha256", "recordSha256", "archiveSha256")] + ["3"])
        self.assertEqual(kwargs, {"capture_output": True, "timeout": 180, "check": False})
        return subprocess.CompletedProcess(argv, 0, cr.json_bytes(self.native), b"")

    def inspect(self, runner=None):
        """実file identityだけを使い、偽processで接続する。"""
        return handoff.inspect(self.hint, self.payload, self.tool, self.tool_hash,
                               runner=runner or self.runner)

    def reject_native(self, **changes):
        """native結果の一項目を破損させて拒否する。"""
        value = copy.deepcopy(self.native)
        value.update(changes)
        with self.assertRaises(cr.RegistryError):
            handoff.native_result(value, self.hint, 0)

    def test_prepare_binds_original_acquired_archive_not_derived(self):
        self.assertEqual(self.hint["archiveSha256"], cr.digest(b"abc"))
        self.assertEqual(self.hint["recordSha256"], cr.digest(cr.json_bytes(self.registry["records"][0])))
        self.assertEqual(self.hint["sourceSha256"], cr.digest(cr.json_bytes(self.registry["sources"][0])))
        self.assertEqual(self.hint["historicalMaintenanceContentInfs"], 1)
        self.assertFalse(self.hint["installAuthorized"])

    def test_no_metadata_promoted_when_all_native_infs_rejected(self):
        value = self.inspect()
        self.assertEqual(self.calls, 1)
        self.assertEqual(value["native"]["verifiedInfCount"], 0)
        self.assertEqual(value["hint"]["historicalMaintenanceContentInfs"], 1)
        self.assertFalse(value["installAuthorized"])
        self.assertNotIn(str(self.root), cr.json_bytes(value).decode())

    def test_zero_inf_completed_is_not_content_success(self):
        self.native.update(infCount=0, closureRejectedInfCount=0, infErrors=[])
        self.assertEqual(self.inspect()["native"]["verifiedInfCount"], 0)

    def test_verified_inf_counts_and_error_are_consistent(self):
        self.native.update(verifiedInfCount=1, closureRejectedInfCount=0, infErrors=[0])
        self.assertEqual(self.inspect()["native"]["verifiedInfCount"], 1)

    def test_unknown_record_is_rejected(self):
        with self.assertRaises(cr.RegistryError):
            handoff.prepare(self.snapshot, "record-absent")

    def test_stale_snapshot_is_rejected(self):
        path = self.snapshot / "index/drivers.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(cr.RegistryError):
            handoff.prepare(self.snapshot, "record-one")

    def test_without_acquisition_does_not_start_native(self):
        with patch.object(mi, "verify_bundle", return_value=(self.registry, {"acquisitions": []}, self.assessments)):
            with self.assertRaises(cr.RegistryError):
                handoff.prepare(self.snapshot, "record-one")
        self.assertEqual(self.calls, 0)

    def test_unsupported_local_format_is_rejected(self):
        unsupported = self.root / "original.exe"
        unsupported.write_bytes(b"abc")
        with self.assertRaises(cr.RegistryError):
            handoff.inspect(self.hint, unsupported, self.tool, self.tool_hash, runner=self.runner)
        self.assertEqual(self.calls, 0)

    def test_wrong_payload_hash_does_not_start_native(self):
        self.payload.write_bytes(b"abd")
        with self.assertRaises(cr.RegistryError):
            self.inspect()
        self.assertEqual(self.calls, 0)

    def test_wrong_payload_size_does_not_start_native(self):
        self.payload.write_bytes(b"abcd")
        with self.assertRaises(cr.RegistryError):
            self.inspect()
        self.assertEqual(self.calls, 0)

    def test_wrong_tool_hash_does_not_start_native(self):
        self.tool.write_bytes(b"other-tool")
        with self.assertRaises(cr.RegistryError):
            self.inspect()
        self.assertEqual(self.calls, 0)

    def test_payload_change_during_native_is_rejected(self):
        def runner(argv, **kwargs):
            value = self.runner(argv, **kwargs)
            self.payload.write_bytes(b"abd")
            return value
        with self.assertRaises(cr.RegistryError):
            self.inspect(runner)

    def test_tool_change_during_native_is_rejected(self):
        def runner(argv, **kwargs):
            value = self.runner(argv, **kwargs)
            self.tool.write_bytes(b"other-tool")
            return value
        with self.assertRaises(cr.RegistryError):
            self.inspect(runner)

    def test_hint_fields_flags_types_and_budgets(self):
        for key, value in (("extra", True), ("installAuthorized", True), ("researchOnly", False),
                           ("publishable", True), ("archiveBytes", True), ("archiveBytes", 0),
                           ("archiveBytes", handoff.MAX_ARCHIVE_BYTES + 1), ("indexSha256", "A" * 64),
                           ("historicalMaintenanceContentInfs", True), ("historicalMaintenanceContentInfs", -1)):
            with self.subTest(key=key, value=value):
                hint = copy.deepcopy(self.hint)
                hint[key] = value
                with self.assertRaises(cr.RegistryError):
                    handoff.validate_hint(hint)

    def test_native_flags_and_unknown_fields_rejected(self):
        for key, value in (("extra", 1), ("installAuthorized", True), ("publishable", True),
                           ("researchOnly", False), ("applicability", "PASSED")):
            with self.subTest(key=key):
                self.reject_native(**{key: value})

    def test_native_wrong_identity_rejected(self):
        for key, value in (("indexSha256", "1" * 64), ("recordSha256", "2" * 64),
                           ("archiveSha256", "3" * 64), ("archiveBytes", 4), ("archiveBytes", True)):
            with self.subTest(key=key):
                self.reject_native(**{key: value})

    def test_native_count_mismatch_and_bool_rejected(self):
        for key, value in (("infCount", 2), ("infCount", True), ("verifiedInfCount", 1),
                           ("signatureRejectedInfCount", -1), ("inventoryFileCount", 8193),
                           ("infErrors", [0]), ("infErrors", [True]), ("infErrors", [])):
            with self.subTest(key=key):
                self.reject_native(**{key: value})

    def test_native_completed_needs_input_binding_and_zero_error(self):
        self.reject_native(inputBound=False)
        self.reject_native(inputBound=1)
        self.reject_native(error=-1)
        self.reject_native(error=True)

    def test_native_exit_code_matches_state(self):
        for exit_code in (1, 2, True, -1):
            with self.assertRaises(cr.RegistryError):
                handoff.native_result(self.native, self.hint, exit_code)

    def test_native_failure_and_cancel_have_no_partial_infs(self):
        for state, error, bound in (("INPUT_REJECTED", -1, False),
                                    ("INSPECTION_FAILED", -1, True), ("CANCELLED", -2147023673, False)):
            value = result(self.hint)
            value.update(state=state, error=error, inputBound=bound, inventoryFileCount=0,
                         infCount=0, closureRejectedInfCount=0, infErrors=[])
            self.assertEqual(handoff.native_result(value, self.hint, 1), value)
            value["verifiedInfCount"] = 1
            with self.assertRaises(cr.RegistryError):
                handoff.native_result(value, self.hint, 1)

    def test_process_errors_and_timeout_are_sanitized(self):
        for error in (OSError("private-path"), subprocess.TimeoutExpired("private-path", 180)):
            def runner(*args, **kwargs):
                raise error
            with self.assertRaises(cr.RegistryError) as caught:
                self.inspect(runner)
            self.assertEqual(str(caught.exception), "HANDOFF_NATIVE_PROCESS")

    def test_native_output_budget_stderr_and_bad_json_rejected(self):
        for out, err in ((b"", b""), (b"x" * (handoff.MAX_STDOUT_BYTES + 1), b""),
                         (b"{}", b"private-path"), (b"{invalid}", b""),
                         ("not-bytes", b""), (b'{"schema":1,"schema":2}', b"")):
            def runner(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, out, err)
            with self.assertRaises(cr.RegistryError):
                self.inspect(runner)

    def test_file_budget_empty_directory_are_rejected(self):
        with self.assertRaises(cr.RegistryError):
            handoff.file_identity(self.payload, 2)
        self.payload.write_bytes(b"")
        with self.assertRaises(cr.RegistryError):
            handoff.file_identity(self.payload, 3)
        with self.assertRaises(cr.RegistryError):
            handoff.file_identity(self.root, 3)


if __name__ == "__main__":
    unittest.main()
