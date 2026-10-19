"""ADR0369の固定stage/exit診断とADR0370の入口拒否を非通信fakeだけで検査する六case。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
"""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import daily_index_pipeline as pipeline


class NativeReceiptDiagnosticTests(unittest.TestCase):
    """実native/Task/networkを呼ばず、原失敗と任意診断の保存境界を検査する。"""

    def test_d01_safe_finite_exit(self):
        """Windows終了値と負の終了値を有限整数として保持する。"""
        for code in (0, 7, -(1 << 31), (1 << 32) - 1):
            path = Mock()
            path.exists.return_value = False
            with self.assertRaisesRegex(ValueError, "^NATIVE_RECEIPT_MISSING$") as caught:
                pipeline.require_native_receipt(path, code)
            self.assertEqual(caught.exception.native_failure, {
                "schema": "dc-native-stage-failure-v1", "stage": "DAILY_EVIDENCE_RECEIPT", "childExitCode": code})

    def test_d02_invalid_diagnostic_omitted(self):
        """不正型・範囲外・余分なfieldを保存せず、元の失敗理由を保つ。"""
        good = {"schema": "dc-native-stage-failure-v1", "stage": "DAILY_EVIDENCE_RECEIPT", "childExitCode": 2}
        bad = [None, {}, {**good, "raw": "artificial-secret"}, {**good, "stage": "OTHER"}]
        bad += [{**good, "childExitCode": value} for value in (True, "2", None, -(1 << 31) - 1, 1 << 32)]
        for detail in bad:
            result = pipeline.result_with_safe_github_failure({"status": "FAILED", "reason": "NATIVE_RECEIPT_MISSING", "nativeFailure": detail})
            self.assertEqual(result, {"status": "FAILED", "reason": "NATIVE_RECEIPT_MISSING"})

    def test_d03_acquisition_missing_no_retry(self):
        """取得子processがreceiptを残さない場合に一回で失敗し、raw出力を保持しない。"""
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / "20261018"
            budget = Mock()
            budget.run.return_value = (7, b"artificial-url", b"artificial-credential")
            config = {"collectorExe": "artificial.exe", "manifestFile": "artificial.json", "stateRoot": "artificial-state"}
            with patch.object(pipeline, "operation_root", side_effect=lambda value: value), patch.object(pipeline, "protected_tree"):
                with self.assertRaisesRegex(ValueError, "^NATIVE_RECEIPT_MISSING$") as caught:
                    pipeline.collect_daily_acquisition_receipt(config, prefix, budget)
            self.assertEqual(budget.run.call_count, 1)
            self.assertEqual(caught.exception.native_failure["childExitCode"], 7)
            self.assertNotIn("artificial-url", json.dumps(caught.exception.native_failure))

    def test_d04_terminal_diagnostic(self):
        """既存mainの終了2・UNKNOWN_NO_RE_SIGNを保ち、最小診断だけをterminalへ渡す。"""
        now = datetime(2026, 10, 18, 6, tzinfo=timezone.utc)
        path = Mock()
        path.exists.return_value = False
        try:
            pipeline.require_native_receipt(path, 9)
        except ValueError as error:
            failure = error
        config = {"firstDailyLocal": "2026-10-16T15:00:00+09:00", "outputRoot": "C:/artificial/operations", "purpose": pipeline.ACQUISITION_PURPOSE}
        output = io.StringIO()
        with patch.object(pipeline, "load_config", return_value=(config, {}, "a" * 64)), \
                patch.object(pipeline, "run_pipeline", side_effect=failure), patch.object(pipeline, "utc", return_value=now), \
                patch.object(pipeline, "write_new") as save, \
                patch("sys.argv", ["daily_index_pipeline.py", "run", "C:/artificial/config.json"]), redirect_stdout(output):
            self.assertEqual(pipeline.main(), 2)
        result = json.loads(save.call_args.args[1])
        self.assertEqual(result["reason"], "NATIVE_RECEIPT_MISSING")
        self.assertEqual(result["signingOutcome"], "UNKNOWN_NO_RE_SIGN")
        self.assertEqual(result["nativeFailure"], failure.native_failure)
        self.assertEqual(json.loads(output.getvalue()), result)

    def test_d05_historical_report_unchanged(self):
        """診断のない過去の失敗へ終了値や原因を補完しない。"""
        historical = {"status": "FAILED", "reason": "NATIVE_RECEIPT_MISSING", "configSha256": "a" * 64}
        self.assertEqual(pipeline.result_with_safe_github_failure(historical), historical)
        self.assertNotIn("nativeFailure", historical)
        good = {"schema": "dc-native-stage-failure-v1", "stage": "DAILY_EVIDENCE_RECEIPT", "childExitCode": 2}
        result = pipeline.result_with_safe_github_failure({**historical, "nativeFailure": good})
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["nativeFailure"], good)

    def test_d06_missing_approval_precedes_native_and_terminal(self):
        """人工configに承認recordがなければmainはnativeとterminal保存へ進まない。"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control = root / "control/artificial"
            control.mkdir(parents=True)
            path = control / "config.json"
            config = {name: "ARTIFICIAL_UNTRUSTED_CONFIG" for name in pipeline.CONFIG_FIELDS}
            config["schema"] = "dc-private-daily-index-config-v1"
            path.write_bytes(pipeline.canonical(config))
            with patch.object(pipeline, "protected_root", return_value=root), \
                    patch.object(pipeline, "protected_path"), patch.object(pipeline, "_APPROVED_WORKSPACE", None), \
                    patch.object(pipeline, "run_pipeline") as native, patch.object(pipeline, "write_new") as terminal, \
                    patch("sys.argv", ["daily_index_pipeline.py", "run", str(path)]):
                with self.assertRaisesRegex(ValueError, "^WORKSPACE_APPROVAL_REQUIRED$"):
                    pipeline.main()
                native.assert_not_called()
                terminal.assert_not_called()


if __name__ == "__main__":
    unittest.main()
