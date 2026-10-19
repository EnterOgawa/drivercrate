"""明示v5一回実行の人工既知制約、保存、process閉集合を非通信で確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
同じproduction admission／transport／run_once／保存へ完全fakeを通す。
実DNS・実HTTP・実collectorを実行しない。
"""
from datetime import datetime, timedelta
import copy
import os
from pathlib import Path
import subprocess
import json
import tempfile
import shutil
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_workspace as workspace
import registry_daily_monitor as monitor
import registry_monitor_http as http
from test_collector_public_locators import locator_fixture
from test_collector_workspace import historical_store


class ExplicitRunTests(unittest.TestCase):
    """人工authorityを内部引数だけへ結合し、本物のstate/report保存を確認する。"""

    def setUp(self):
        """各caseの試験用baseとworkspace／人工binding／時計を初期化する。

        baseはmkdtempで作り、登録するcleanupはpatcher.stopだけである。
        このsetUpにはbase配下の試験fileを削除するcleanup登録がない。
        """
        self.base = Path(tempfile.mkdtemp(prefix="explicit-unit-", dir=os.environ.get("DRIVERCRATE_WORKSPACE_TEST_ROOT")))
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.registry, self.locators = locator_fixture()
        self.policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
        self.now = datetime(2026, 10, 4, 1)
        self.expected = {"schema": "dc-collector-explicit-workspace-v1", "packageManifestSha256": "1"*64,
                         "seedManifestSha256": "2"*64, "communicationAuthorized": False,
                         "nativeConstraints": "UNKNOWN", "originalDayBudget": "UNVERIFIED"}
        self.known = {"schema":"dc-collector-live-admission-v1", "nativeMode":"VERIFIED_LEGACY_V4",
                      "nativeDigest":"a"*64, "nativeFileCount":2,
                      "requestHashes":[monitor.hash_text("GET\nhttps://native.example.org/page")],
                      "hostHashes":[monitor.hash_text("native.example.org")]}
        (self.base/"config").mkdir()
        original_read = cr.read_json
        for patcher in (patch.object(workspace, "binding", return_value=self.expected),
                        patch.object(workspace.snapshot, "verify_snapshot", return_value=(self.registry,self.locators,None)),
                        patch.object(cr, "read_json", side_effect=lambda path: self.policy if path.name == "monitor-policy.json" else original_read(path))):
            patcher.start()
            self.addCleanup(patcher.stop)
        workspace.operate(self.base, "initialize", self.root, None, clock=lambda:self.now)
        self.calls = []

    def fake(self, kind, url):
        """本文と登録link hashだけを返す架空PAGEでdriver成功を生成しない。"""
        self.calls.append((kind,url))
        return http.response(200, body=b"<html>artificial</html>")

    def make_admission(self, **overrides):
        """同じproduction validatorへ渡す内部の完全fake親contextを作る。"""
        policy_raw=cr.json_bytes(self.policy)
        (self.base/"config/monitor-policy.json").write_bytes(policy_raw)
        document={**self.known, "operation":"run-once", "workspaceIdentity":workspace.directory_identity(self.root),
            "monitorIdentity":workspace.directory_identity(self.root/"monitor"), "monitorRoot":str(self.root/"monitor"),
            "issuedAtUtcMillis":int(self.now.replace(tzinfo=monitor.timezone.utc).timestamp()*1000),
            "packageManifestSha256":self.expected["packageManifestSha256"],
            "seedManifestSha256":self.expected["seedManifestSha256"], "policySha256":cr.digest(policy_raw)}
        document.update(overrides)
        return workspace.NativeAdmission(document,parent_alive=lambda:True)

    def run_known(self, **options):
        """実原点identityと同じcontext validatorから既存monitorへ委譲する。"""
        live=options.pop("admission",self.make_admission())
        return workspace.run_monitor_once(self.base,self.root,confirmed=True,curl="unused-artificial",
            admission=live,transport=options.pop("transport",self.fake),
            clock=lambda:self.now,**options)

    def test_original_reader_holds_without_mutation(self):
        before = (self.root/"monitor/state.json").read_bytes()
        result = workspace.run_monitor_once(self.base,self.root,confirmed=True,curl="unused",transport=self.fake,
                                             clock=lambda:self.now)
        self.assertEqual(result["result"],"HOLD")
        self.assertEqual(result["nativeConstraints"],"UNKNOWN")
        self.assertEqual((self.root/"monitor/state.json").read_bytes(),before)
        self.assertEqual(self.calls,[])

    def test_bound_offline_verify_export_import_rebind_uses_active_history(self):
        """I03/I04: 空の初期monitorと区別し、外部正本の全byteと停止移設を維持する。"""
        active = self.base / "active-original"
        original = historical_store(active)
        self.now = datetime(2026, 10, 8, 1)
        (self.root / "origin.json").write_bytes(cr.json_bytes({"artificialNativeAnchor": True}))
        before = workspace.history_fingerprint(active)
        decoy = workspace.history_fingerprint(self.root / "monitor")

        def context(action):
            """実childと同じvalidatorを使う内部人工leaseだけを作る。"""
            return self.make_admission(operation=action, monitorRoot=str(active),
                                       monitorIdentity=workspace.directory_identity(active))

        result = workspace.operate(self.base, "verify", self.root, None,
                                   admission=context("verify"), clock=lambda: self.now)
        self.assertEqual((result["requests"], result["reports"]), (2, 2))
        self.assertFalse(result["communicationAuthorized"])
        transfer = self.base / "active-export"
        transfer.mkdir()
        result = workspace.operate(self.base, "export", self.root, transfer,
                                   admission=context("export"), clock=lambda: self.now)
        self.assertEqual((result["requests"], result["reports"]), (2, 2))
        manifest = cr.read_json(transfer / "snapshot/manifest.json")
        self.assertEqual({row["path"]: row["sha256"] for row in manifest["files"]}, before)
        for row in manifest["files"]:
            self.assertEqual((active / row["path"]).read_bytes(),
                             (transfer / "snapshot" / row["path"]).read_bytes())
        self.assertEqual(workspace.history_fingerprint(active), before)
        self.assertEqual(workspace.history_fingerprint(self.root / "monitor"), decoy)
        self.root = self.base / "migrated-workspace"
        self.root.mkdir()
        workspace.operate(self.base, "import", self.root, transfer / "snapshot", clock=lambda: self.now)
        live = self.make_admission(operation="bind-origins", previousMonitorRoot=str(active),
                                   previousMonitorIdentity=workspace.directory_identity(active))
        bound = workspace.bind_origins(self.base, self.root, live, clock=lambda: self.now)
        self.assertEqual((bound["requests"], bound["reports"]), (2, 2))
        self.assertEqual(monitor.verify_store(self.root / "monitor"), original)
        self.assertEqual(workspace.history_fingerprint(self.root / "monitor"), before)
        self.assertEqual(self.calls, [])

    def test_bound_offline_rejects_missing_stale_foreign_and_wrong_operation(self):
        """I05: bound操作の欠損・stale・foreign contextを空monitorへ逃がさない。"""
        (self.root / "origin.json").write_bytes(b"{}")
        before = workspace.history_fingerprint(self.root / "monitor")
        with self.assertRaisesRegex(cr.RegistryError, "NATIVE_LIVE_CONTEXT_REQUIRED"):
            workspace.operate(self.base, "verify", self.root, None, clock=lambda: self.now)
        for change in ({"issuedAtUtcMillis": 0}, {"workspaceIdentity": "f" * 64},
                       {"monitorIdentity": "e" * 64}, {"operation": "run-once"}):
            with self.subTest(change=tuple(change)), self.assertRaises(cr.RegistryError):
                live = self.make_admission(operation="verify")
                live.document.update(change)
                workspace.operate(self.base, "verify", self.root, None,
                                  admission=live, clock=lambda: self.now)
        self.assertEqual(workspace.history_fingerprint(self.root / "monitor"), before)
        self.assertEqual(self.calls, [])

    def test_copied_and_renamed_monitor_context_is_rejected_before_run_once(self):
        """I06: copyまたはrenameで発行済み実identityを差し替えず、同じrun_once入口で拒否する。"""
        live = self.make_admission()
        original = self.root / "monitor"
        before = workspace.history_fingerprint(original)
        copied = self.base / "monitor-copy"
        shutil.copytree(original, copied)
        live.document["monitorRoot"] = str(copied)
        with self.assertRaisesRegex(cr.RegistryError, "MONITOR_ORIGIN_CHANGED"):
            self.run_known(admission=live)
        self.assertEqual(workspace.history_fingerprint(original), before)
        live = self.make_admission()
        renamed = self.base / "monitor-renamed"
        original.rename(renamed)
        try:
            with self.assertRaises(cr.RegistryError):
                self.run_known(admission=live)
            self.assertEqual(workspace.history_fingerprint(renamed), before)
        finally:
            renamed.rename(original)
        self.assertEqual(workspace.history_fingerprint(original), before)
        self.assertEqual(self.calls, [])

    def test_small_batch_uses_actual_per_run_budget(self):
        with patch.object(monitor,"MAX_REQUESTS",1), patch.object(monitor,"MAX_RUN_BYTES",http.MAX_BODY):
            result=self.run_known()
        self.assertEqual(result["counts"]["attempted"],1)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(result["originalDayBudget"],"NOT_APPLICABLE_TO_PROVEN_NONSHARING_PAGES")

    def test_native_validated_v4_and_stopped_monitor_import_save_one_page(self):
        """B01/B04/B07/B08: 別target生成のscope fixtureを読み、停止importと架空transportの保存を確認する。

        DRIVERCRATE_NATIVE_SCOPE_FIXTUREが未指定ならskipする。
        本test自身はnative validatorを起動せず、読み込んだscopeを人工admissionへ渡す。
        """
        source=os.environ.get("DRIVERCRATE_NATIVE_SCOPE_FIXTURE")
        if not source:
            self.skipTest("native fixture producer is a separate affected target")
        scope=json.loads(Path(source).read_text(encoding="utf-8"))
        self.known.update(scope)
        original=self.base/"original-monitor"
        monitor.initialize(original,clock=lambda:self.now)
        monitor.run_once(self.registry,self.policy,original,transport=self.fake,clock=lambda:self.now,
                         public_locators=self.locators,pages_only=True)
        monitor.export_store(original,self.base/"stopped-export")
        self.now+=timedelta(days=2)
        self.root=self.base/"imported-workspace"
        self.root.mkdir()
        workspace.operate(self.base,"import",self.root,self.base/"stopped-export",clock=lambda:self.now)
        before=workspace.history_fingerprint(self.root/"monitor")
        selected=self.make_admission(operation="bind-origins",previousMonitorRoot=str(original),
            previousMonitorIdentity=workspace.directory_identity(original))
        bound=workspace.bind_origins(self.base,self.root,selected,clock=lambda:self.now)
        self.assertFalse(bound["communicationAuthorized"])
        self.assertEqual(before,workspace.history_fingerprint(original))
        self.calls.clear()
        curl=r"C:\Windows\System32\curl.exe"
        rows=monitor.page_requests(self.registry,self.locators,self.policy,monitor.make_requests(self.registry,self.policy))
        gate=workspace.ProcessGate(self.base,curl,tuple(row["url"] for row in rows if not row["held"]))
        transport=http.CurlTransport(registry=self.registry,public_locators=self.locators,package=self.base,
            curl_path=curl,process_gate=gate.prepare,route_gate=gate.bind_route)
        def child(arguments,**options):
            """HTTP/DNS子だけをfakeにし、admissionから本番curl/parser/保存まで接続する。"""
            gate.audit("subprocess.Popen",(options["executable"],subprocess.list2cmdline(arguments),None,None))
            if arguments[0]!=curl:
                route=http.resolve_route(arguments[-1],environment={"HTTPS_PROXY":"http://proxy.example.org:8080"})
                return subprocess.CompletedProcess(arguments,0,json.dumps({"route":route,"addresses":["93.184.216.34"]}).encode())
            self.assertEqual(arguments[arguments.index("--proxy")+1],"http://proxy.example.org:8080")
            self.assertTrue(arguments[arguments.index("--connect-to")+1].endswith(":443:93.184.216.34:443"))
            self.calls.append(("PAGE",arguments[-1]))
            Path(arguments[arguments.index("--dump-header")+1]).write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            Path(arguments[arguments.index("--output")+1]).write_bytes(b"<html>artificial</html>")
            return subprocess.CompletedProcess(arguments,0,b"200")
        with patch.object(monitor,"MAX_REQUESTS",1),patch.object(monitor,"MAX_RUN_BYTES",http.MAX_BODY), \
             patch.object(http,"system_curl_path",return_value=curl),patch.object(http.subprocess,"run",side_effect=child):
            report=self.run_known(transport=transport)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(report["counts"]["attempted"],1)
        self.assertGreater(report["counts"]["plannedRequests"],1)
        self.assertEqual(len(list((self.root/"monitor/reports").iterdir())),2)
        self.assertTrue(monitor.verify_store(self.root/"monitor")["requests"])

    def test_both_fixed_sources_alias_and_same_native_host_are_held(self):
        """B02: 二held sourceと同URL別名、同host大小文字を行のまま保持する。"""
        live=self.make_admission()
        sources=[{**self.registry["sources"][0],"id":value} for value in
                 ("asus-catalog-legacy","intel-ethernet-win11")]
        registry={**self.registry,"sources":[*self.registry["sources"],*sources]}
        rows=monitor.page_requests(self.registry,self.locators,self.policy,monitor.make_requests(self.registry,self.policy))
        rows += [{**rows[0],"id":"c"*64,"url":"https://NATIVE.example.org/another","sourceIds":["renamed-source"]}]
        holds=live.consume(rows,{},self.root/"monitor",registry,self.policy)
        self.assertEqual(holds[rows[0]["id"]],"NATIVE_COORDINATION_PENDING")
        self.assertEqual(holds["c"*64],"NATIVE_SHARED_HOST_HELD")
        self.assertEqual(self.calls,[])
        self.known["hostHashes"]=[monitor.hash_text("vendor.example.org")]
        result=self.run_known()
        self.assertEqual(result["counts"]["attempted"],0)
        self.assertEqual(result["counts"]["held"],result["counts"]["plannedRequests"])
        self.assertEqual(self.calls,[])

    def test_unknown_mode_and_scope_are_rejected_before_mutation(self):
        """B03/B05: 未対応modeと欠損scopeを未知のまま拒否する。"""
        for field,value in (("nativeMode","CAMPAIGN_UNKNOWN"),("requestHashes",[]),("hostHashes",[])):
            with self.subTest(field=field):
                before=(self.root/"monitor/state.json").read_bytes()
                with self.assertRaises(cr.RegistryError):
                    self.run_known(admission=self.make_admission(**{field:value}))
                self.assertEqual(before,(self.root/"monitor/state.json").read_bytes())
        self.assertEqual(self.calls,[])

    def test_stale_released_foreign_and_consumed_context_rejected(self):
        """B05/B09: 時刻・原点・親生存・一回消費をHTTP前に検査する。"""
        for change in ({"issuedAtUtcMillis":0},{"issuedAtUtcMillis":9999999999999},
                       {"workspaceIdentity":"e"*64},{"monitorIdentity":"f"*64}):
            with self.subTest(change=tuple(change)),self.assertRaises(cr.RegistryError):
                self.run_known(admission=self.make_admission(**change))
        live=self.make_admission()
        live.parent_alive=lambda:False
        with self.assertRaisesRegex(cr.RegistryError,"RELEASED"):
            self.run_known(admission=live)
        live=self.make_admission()
        self.run_known(admission=live)
        self.calls.clear()
        with self.assertRaisesRegex(cr.RegistryError,"RELEASED"):
            self.run_known(admission=live)
        self.assertEqual(self.calls,[])

    def test_fresh_origin_and_changed_import_cannot_reset_history(self):
        """B07: 履歴なし採用と元正本に一致しない停止importを拒否する。"""
        with self.assertRaisesRegex(cr.RegistryError,"HISTORY_REQUIRED"):
            workspace.bind_origins(self.base,self.root,self.make_admission(operation="bind-origins"),clock=lambda:self.now)
        self.run_known()
        original=self.base/"origin"
        monitor.export_store(self.root/"monitor",self.base/"origin-export")
        monitor.import_export(self.base/"origin-export",original,source_stop_acknowledged=True,clock=lambda:self.now)
        state=monitor.verify_store(original)
        state["observedAt"]=monitor.stamp(self.now+timedelta(seconds=1))
        monitor.save_state(original,state)
        live=self.make_admission(operation="bind-origins",previousMonitorRoot=str(original),
            previousMonitorIdentity=workspace.directory_identity(original))
        with self.assertRaises((cr.RegistryError,OSError)):
            workspace.bind_origins(self.base,self.root,live,clock=lambda:self.now)

    def test_normal_known_fake_saves_report_and_state(self):
        result = self.run_known()
        state = monitor.verify_store(self.root/"monitor")
        self.assertEqual(result["result"],"MONITOR_REPORT_SAVED")
        self.assertTrue(state["requests"])
        self.assertTrue(all(row["outcome"]=="SUCCESS" for row in state["requests"].values()))
        self.assertEqual(len(list((self.root/"monitor/reports").iterdir())),1)
        self.assertFalse(result["publishableIndex"])
        self.assertFalse(result["driverContentVerified"])
        self.assertTrue(all(kind=="PAGE" for kind,url in self.calls))

    def test_partial_failure_retains_individual_result(self):
        def partial(kind,url):
            self.calls.append((kind,url))
            return http.response(200,body=b"<html>artificial</html>") if len(self.calls)==1 else http.response(error="TIMEOUT")
        self.run_known(transport=partial)
        rows = list(monitor.verify_store(self.root/"monitor")["requests"].values())
        self.assertGreater(len(rows),1)
        self.assertIn("SUCCESS",[row["outcome"] for row in rows])
        self.assertIn("FAILED",[row["outcome"] for row in rows])

    def test_24h_and_held_sources_do_not_call_transport(self):
        self.run_known()
        self.calls.clear()
        self.run_known()
        self.assertEqual(self.calls,[])
        self.policy["heldSourceIds"] = [row["id"] for row in self.registry["sources"]]
        self.run_known()
        self.assertEqual(self.calls,[])

    def test_incomplete_reservations_recover_without_resend(self):
        self.run_known()
        self.calls.clear()
        state = monitor.verify_store(self.root/"monitor")
        successes = [copy.deepcopy(row["lastSuccess"]) for row in state["requests"].values()]
        for row in state["requests"].values():
            row.update(outcome="IN_PROGRESS",endedAt=None,reason="NONE",httpStatus=None)
        monitor.save_state(self.root/"monitor",state)
        self.run_known()
        recovered = monitor.verify_store(self.root/"monitor")
        self.assertEqual(self.calls,[])
        self.assertTrue(all(row["outcome"]=="UNKNOWN_OUTCOME" for row in recovered["requests"].values()))
        self.assertEqual([row["lastSuccess"] for row in recovered["requests"].values()],successes)

    def test_consent_and_old_v4_rejected_before_http(self):
        with self.assertRaisesRegex(cr.RegistryError,"CONSENT"):
            workspace.run_monitor_once(self.base,self.root,confirmed=False,curl="unused",transport=self.fake)
        self.expected["schema"] = workspace.SCHEMA
        with self.assertRaisesRegex(cr.RegistryError,"RUN_VERSION"):
            self.run_known()
        self.assertEqual(self.calls,[])

    def test_fake_dns_child_timeout_saves_failure_and_report(self):
        curl=r"C:\Windows\System32\curl.exe"
        targets=monitor.page_requests(self.registry,self.locators,self.policy,monitor.make_requests(self.registry,self.policy))
        gate=workspace.ProcessGate(self.base,curl,tuple(row["url"] for row in targets if not row["held"]))
        transport=http.CurlTransport(package=self.base,curl_path=curl,process_gate=gate.prepare)
        with patch.object(http,"system_curl_path",return_value=curl), \
             patch.object(http.subprocess,"run",side_effect=subprocess.TimeoutExpired("fake-dns",5)) as child:
            self.run_known(transport=transport)
        rows=monitor.verify_store(self.root/"monitor")["requests"].values()
        self.assertTrue(rows)
        self.assertTrue(all(row["outcome"]=="FAILED" for row in rows))
        self.assertTrue(any(row["reason"]=="TIMEOUT" for row in monitor.verify_store(self.root/"monitor")["requests"].values()))
        self.assertGreater(child.call_count,0)
        self.assertEqual(len(list((self.root/"monitor/reports").iterdir())),1)


class ProcessBoundaryTests(unittest.TestCase):
    """実processを起動せず固定argvとWindows auditの文字列化を確認する。"""

    def setUp(self):
        self.package = Path(r"D:\ArtificialPackage")
        self.curl = r"C:\Windows\System32\curl.exe"
        self.gate = workspace.ProcessGate(self.package,self.curl,("https://vendor.example.org/page",))

    def test_dns_exact_and_windows_audit_one_use(self):
        args = http.dns_command(self.package,"vendor.example.org")
        self.assertEqual(args[1:5],["-I","-B","-S","-c"])
        self.gate.prepare(args)
        self.gate.audit("subprocess.Popen",(args[0],subprocess.list2cmdline(args),None,None))
        with self.assertRaises(cr.RegistryError):
            self.gate.audit("subprocess.Popen",(args[0],args,None,None))

    def test_alternate_python_script_shell_and_argv_rejected(self):
        args = http.dns_command(self.package,"vendor.example.org")
        for index,value in ((0,"python.exe"),(0,r"D:\other\python.exe"),(5,"arbitrary-script"),(6,r"D:\other-package")):
            modified = args.copy()
            modified[index] = value
            with self.assertRaises(cr.RegistryError):
                self.gate.prepare(modified)
        for event in ("socket.getaddrinfo","socket.connect","os.system","os.spawn","os.exec"):
            with self.assertRaises(cr.RegistryError):
                self.gate.audit(event,())

    def test_fixed_curl_and_path_shadow_do_not_change_executable(self):
        captured=[]
        def fake(args,**options):
            captured.append(args)
            self.gate.audit("subprocess.Popen",(options["executable"],subprocess.list2cmdline(args),None,None))
            if args[0] != self.curl:
                return subprocess.CompletedProcess(args,0,b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["93.184.216.34"]}')
            Path(args[args.index("--dump-header")+1]).write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            Path(args[args.index("--output")+1]).write_bytes(b"<html>artificial</html>")
            return subprocess.CompletedProcess(args,0,b"200")
        with patch.object(http,"system_curl_path",return_value=self.curl), patch.object(http.subprocess,"run",side_effect=fake), \
             patch.dict(os.environ,{"PATH":r"D:\Shadow","PYTHONPATH":r"D:\Shadow"}):
            result = http.CurlTransport(package=self.package,curl_path=self.curl,process_gate=self.gate.prepare)("PAGE","https://vendor.example.org/page")
        self.assertEqual(result["error"],"NONE")
        self.assertEqual(captured[1][0],self.curl)
        for value in ("curl.exe",r"D:\Shadow\curl.exe"):
            bad = captured[1].copy()
            bad[0]=value
            with self.assertRaises(cr.RegistryError):
                self.gate.prepare(bad)
        bad = captured[1].copy()
        bad[26:] = ["--config","arbitrary"]
        with self.assertRaises(cr.RegistryError):
            self.gate.prepare(bad)

    def test_timeout_is_projected_without_retry(self):
        with patch.object(http,"system_curl_path",return_value=self.curl), \
             patch.object(http.subprocess,"run",side_effect=subprocess.TimeoutExpired("fake",5)) as child:
            result=http.CurlTransport(package=self.package,curl_path=self.curl,process_gate=self.gate.prepare)("PAGE","https://vendor.example.org/page")
        self.assertEqual(result["error"],"TIMEOUT")
        self.assertEqual(child.call_count,1)


if __name__ == "__main__":
    unittest.main()
