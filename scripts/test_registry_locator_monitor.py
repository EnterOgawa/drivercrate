"""公開locatorの用途保留・共通HTTP・共有待機と移設の非通信試験（ADR 0236）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空URL・時計・HTTPとtemporary directoryを使い、実DNS・実取得・導入は行わない。
"""

import contextlib
import copy
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_public_locators as pl
import registry_daily_monitor as dm
import registry_locator_requests as lr
import registry_monitor_http as http
from test_collector_public_locators import BASE, PAGE, PAYLOAD, locator_fixture
from test_collector_registry import RESPONSE_HEADER_URL
from test_collector_registry import fixture


class LocatorMonitorTests(unittest.TestCase):
    """架空台帳と旧storeを共有し、同意保留・24時間待機を確認する。"""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "monitor"
        self.registry, self.locators = locator_fixture()
        self.policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
        self.now = datetime(2026, 10, 3, 1)
        self.calls = []
        self.body = b"<html>sample</html>"
        self.failure = None
        dm.initialize(self.root, clock=lambda: self.now)

    def transport(self, kind, url):
        """呼出を記録し、架空の本文hashと登録URLhashだけを返す。"""
        self.calls.append((kind, url))
        if self.failure:
            return self.failure
        return http.response(200, body=self.body, links=sorted({dm.hash_text(row["url"])
                             for row in self.locators["locators"]}))

    def run_monitor(self, **options):
        """同じ台帳・時計・保護storeでlocator限定監視を一回行う。"""
        return dm.run_once(self.registry, self.policy, self.root, transport=self.transport,
                           clock=lambda: self.now, public_locators=self.locators, **options)

    def requests(self):
        """旧要求集合とlocatorを非通信で結合する。"""
        return lr.locator_requests(self.registry, self.locators, self.policy,
                                   dm.make_requests(self.registry, self.policy))

    def recent_observations(self):
        """元観測と結合を整合させ、24時間未満の架空観測にする。"""
        for observation in self.registry["observations"]:
            observation["checkedAt"] = self.registry["asOf"]
        self.locators["registry"] = pl.registry_binding(self.registry)
        for row in self.locators["locators"]:
            if row["purpose"] == "PAGE":
                row["pageObservation"]["checkedAt"] = self.registry["asOf"]

    def test_request_binding_references_and_input_immutability(self):
        """用途と元URLの共有IDを保ち、結合入力を変更しない。"""
        before = copy.deepcopy((self.registry, self.locators, self.policy))
        rows = self.requests()
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row["id"], dm.hash_text(row["kind"] + "\n" + row["url"]))
            self.assertEqual(row["sourceIds"], ["source-one"])
            self.assertEqual(row["productIds"], ["product-one"])
            self.assertEqual(len(row["locatorIds"]), 1)
        root = next(row for row in rows if row["locatorIds"] == ["root-one"])
        child = next(row for row in rows if row["locatorIds"] == ["page-one"])
        self.assertIn(dm.hash_text(PAGE), root["expectedLinks"])
        self.assertIn(dm.hash_text(PAYLOAD), child["expectedLinks"])
        self.assertEqual(before, (self.registry, self.locators, self.policy))

    def test_input_order_and_revision_do_not_reset_request_identity(self):
        """Parentと子の順序・台帳版の変更で要求IDや待機を変えない。"""
        original = self.requests()
        self.locators["locators"].reverse()
        self.locators["revision"] = "locators-02"
        self.assertEqual(self.requests(), original)

    def test_every_payload_condition_is_held_without_approval(self):
        """プロンプト未観測も取得許可ではなく、全PAYLOADを保留する。"""
        for condition, reason in (("CONSENT_REQUIRED", "CONSENT_REQUIRED"),
                                  ("ACCESS_UNRESOLVED", "ACCESS_UNRESOLVED"),
                                  ("NO_EXTRA_PROMPT_OBSERVED", "PAYLOAD_APPROVAL_REQUIRED")):
            with self.subTest(condition=condition):
                self.locators["locators"][2]["requestCondition"] = condition
                row = next(row for row in self.requests() if row["kind"] == "LINK")
                self.assertTrue(row["held"])
                self.assertEqual(row["holdReason"], reason)

    def test_native_hold_precedes_consent_and_never_calls_http(self):
        """旧native調整待ちのsource保留を全用途で維持する。"""
        self.policy["heldSourceIds"] = ["source-one"]
        report = self.run_monitor()
        self.assertEqual(report["counts"]["held"], 3)
        self.assertTrue(all(row["reason"] == "NATIVE_COORDINATION_PENDING" for row in report["items"]))
        self.assertEqual(self.calls, [])
        self.assertEqual(dm.verify_store(self.root)["requests"], {})

    def test_known_observation_wait_then_exact_due_get(self):
        """初回storeも既知観測から24時間待ち、満了時だけPAGEをGETする。"""
        self.recent_observations()
        report = self.run_monitor()
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(report["counts"]["deferred"], 2)
        self.assertEqual(report["counts"]["held"], 1)
        for row in report["items"]:
            if row["kind"] == "PAGE":
                self.assertEqual(row["reason"], "OBSERVATION_WAIT_24H")
                self.assertEqual(row["checkedAt"], "2026-10-03T00:00:00Z")
                self.assertEqual(row["nextDueAt"], "2026-10-04T00:00:00Z")
                self.assertIsNone(row["httpStatus"])
        self.assertEqual(dm.verify_store(self.root)["requests"], {})
        self.now = datetime(2026, 10, 4)
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 2)
        self.assertTrue(all(kind == "PAGE" for kind, _ in self.calls))
        self.assertNotIn(PAYLOAD, {url for _, url in self.calls})

    def test_first_baseline_next_day_change_and_same_day_no_retry(self):
        """新旧本文をhashだけで比較し、同日の再実行はHTTPを呼ばない。"""
        first = self.run_monitor()
        self.assertEqual(first["counts"]["baseline"], 2)
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)
        self.now += timedelta(days=1)
        self.assertEqual(self.run_monitor()["counts"]["unchanged"], 2)
        self.now += timedelta(days=1)
        self.body = b"<html>changed</html>"
        self.assertEqual(self.run_monitor()["counts"]["changed"], 2)
        self.assertEqual(len(self.calls), 6)
        self.assertTrue(all(kind == "PAGE" for kind, _ in self.calls))

    def test_legacy_to_locator_shared_wait_and_last_success(self):
        """旧runのroot待機と成功を新しい入口でも共有する。"""
        old = dm.run_once(self.registry, self.policy, self.root, transport=self.transport, clock=lambda: self.now)
        before = dm.verify_store(self.root)
        report = self.run_monitor()
        self.assertEqual(old["schema"], "dc-registry-monitor-report-v1")
        self.assertEqual(report["counts"]["attempted"], 1)
        root_id = dm.hash_text("PAGE\n" + self.registry["sources"][0]["officialPage"])
        self.assertEqual(dm.verify_store(self.root)["requests"][root_id], before["requests"][root_id])
        self.assertEqual(next(row for row in report["items"] if row["id"] == root_id)["reason"], "WAIT_24H")

    def test_locator_to_legacy_keeps_wait_and_v1_closed_fields(self):
        """Locator監視後も旧runが共有待機と旧報告schemaを維持する。"""
        self.run_monitor()
        before = dm.verify_store(self.root)
        report = dm.run_once(self.registry, self.policy, self.root, transport=self.transport, clock=lambda: self.now)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(report["schema"], "dc-registry-monitor-report-v1")
        self.assertNotIn("locatorsSha256", report)
        self.assertTrue(all("locatorIds" not in row for row in report["items"]))
        self.assertEqual(dm.verify_store(self.root), before)

    def test_legacy_report_canonical_bytes_match_closed_v1_oracle(self):
        """固定時計・IDの旧V1報告を独立したfield／件数の期待byteへ照合する。"""
        registry = cr.validate_registry(fixture())
        page_url = registry["sources"][0]["officialPage"]
        payload_url = registry["records"][0]["downloadUrl"]
        def legacy_http(kind, url):
            """従来のPAGE本文とLINK HEADを用途別に模擬する。"""
            return http.response(200, body=self.body, links=[dm.hash_text(payload_url)]) if kind == "PAGE" else (
                http.response(200))
        with patch.object(dm.uuid, "uuid4") as identity:
            identity.return_value.hex = "0" * 32
            report = dm.run_once(registry, self.policy, self.root, transport=legacy_http, clock=lambda: self.now)
        expected = {"schema": "dc-registry-monitor-report-v1", "id": "run-" + "0" * 32,
            "registrySha256": cr.digest(cr.json_bytes(registry)), "policySha256": cr.digest(cr.json_bytes(self.policy)),
            "startedAt": "2026-10-03T01:00:00Z", "finishedAt": "2026-10-03T01:00:00Z",
            "items": [], "reviewQueue": [{"kind": "SOURCE", "id": "source-one", "reason": "METADATA_PARSER_NOT_CONFIGURED"}],
            "recoveredRequestIds": [], "counts": {"sources": 1, "targetProducts": 1, "plannedRequests": 2,
                "attempted": 2, "bodyBytes": len(self.body), "budgetBytes": len(self.body), "recoveredReservations": 0,
                "reviewItems": 1, "baseline": 1, "unchanged": 0, "changed": 0, "link_alive": 1,
                "failed": 0, "held": 0, "deferred": 0}}
        for kind, url in (("PAGE", page_url), ("LINK", payload_url)):
            expected["items"].append({"id": dm.hash_text(kind + "\n" + url), "kind": kind,
                "sourceIds": ["source-one"], "recordIds": ["record-one"], "productIds": ["product-one"],
                "state": "BASELINE" if kind == "PAGE" else "LINK_ALIVE", "reason": "NONE", "httpStatus": 200,
                "previousSha256": None, "observedSha256": cr.digest(self.body) if kind == "PAGE" else None,
                "bodyBytes": len(self.body) if kind == "PAGE" else 0, "checkedAt": "2026-10-03T01:00:00Z",
                "nextDueAt": "2026-10-04T01:00:00Z"})
        expected["items"].sort(key=lambda row: row["id"])
        self.assertEqual(cr.json_bytes(report), cr.json_bytes(expected))
        path = self.root / "reports" / (expected["id"] + ".json")
        self.assertEqual(path.read_bytes(), dm.envelope("dc-monitor-report-envelope-v1", expected))

    def test_retry_after_and_invalid_host_hold_are_shared(self):
        """429の長い期限と不正Retry-Afterのhost保留を別URLにも適用する。"""
        self.failure = http.response(429, "HTTP_ERROR", retry_after="172800")
        first = self.run_monitor()
        self.assertEqual(first["counts"]["attempted"], 1)
        self.now += timedelta(days=1)
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)
        self.now += timedelta(days=1)
        self.failure = http.response(503, "HTTP_ERROR", retry_after="invalid")
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 1)
        self.now += timedelta(days=40)
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)
        self.assertTrue(all(row["held"] for row in dm.verify_store(self.root)["hosts"].values()))

    def test_reservation_crash_keeps_unknown_and_host_hold(self):
        """通信前の停止も再送せず、旧成功と最低待機を失わない。"""
        def stop(stage, key):
            """永続予約直後に架空の中断を発生させる。"""
            if stage == "RESERVED":
                raise RuntimeError("test-stop")
        with self.assertRaises(RuntimeError):
            self.run_monitor(checkpoint=stop)
        self.assertEqual(self.calls, [])
        report = self.run_monitor()
        self.assertEqual(report["counts"]["recoveredReservations"], 1)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertTrue(all(row["outcome"] == "UNKNOWN_OUTCOME" for row in dm.verify_store(self.root)["requests"].values()))

    def test_finite_budgets_do_not_reserve_or_spend_held_requests(self):
        """件数・時間・byteの有限予算を維持し、保留は予約へ入れない。"""
        for name in ("MAX_REQUESTS", "MAX_RUN_BYTES", "MAX_RUN_SECONDS"):
            with self.subTest(name=name), patch.object(dm, name, 0):
                report = self.run_monitor()
                self.assertEqual(report["counts"]["attempted"], 0)
                self.assertEqual(report["counts"]["held"], 1)
                self.assertEqual(report["counts"]["deferred"], 2)
                self.assertEqual(dm.verify_store(self.root)["requests"], {})

    def test_invalid_binding_rejected_before_store_or_http(self):
        """結合hash・用途不正を保存や通信より先に拒否する。"""
        before = (self.root / "state.json").read_bytes()
        self.locators["registry"]["sha256"] = "0" * 64
        with self.assertRaises(cr.RegistryError):
            self.run_monitor()
        self.assertEqual(self.calls, [])
        self.assertEqual((self.root / "state.json").read_bytes(), before)
        self.assertEqual(list((self.root / "reports").iterdir()), [])

    def test_page_payload_url_collision_rejected_before_store(self):
        """同じURLをPAGEとPAYLOADへ併用して取得保留を回避しない。"""
        self.locators["locators"][2].update(url=self.registry["sources"][0]["officialPage"], urlProfile="QUERYLESS")
        before = (self.root / "state.json").read_bytes()
        with self.assertRaisesRegex(cr.RegistryError, "PURPOSE_COLLISION"):
            self.run_monitor()
        self.assertEqual((self.root / "state.json").read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_held_url_already_in_core_does_not_get_head(self):
        """元台帳にも本体URLがある場合にHEAD経路を再有効化しない。"""
        url = BASE + "/driver.zip"
        self.registry["records"][0].update(downloadUrl=url, linkState="OFFICIAL_LINK")
        self.registry["observations"].append({**self.registry["observations"][0],
                                             "id": "link-one", "kind": "OFFICIAL_LINK"})
        self.registry = cr.validate_registry(self.registry)
        self.locators["registry"] = pl.registry_binding(self.registry)
        self.locators["locators"][2].update(url=url, urlProfile="QUERYLESS")
        report = self.run_monitor()
        self.assertEqual(report["counts"]["attempted"], 2)
        self.assertEqual(report["counts"]["held"], 1)
        self.assertTrue(all(kind == "PAGE" for kind, _ in self.calls))

    def test_payload_condition_is_not_link_unresolved(self):
        """保存済み本体URLの同意未了をURL不明と混同しない。"""
        report = self.run_monitor()
        self.assertIn({"kind": "RECORD", "id": "record-one", "reason": "CONSENT_REQUIRED"}, report["reviewQueue"])
        self.assertFalse(any(row["reason"] == "LINK_UNRESOLVED" for row in report["reviewQueue"]))
        self.assertIsNone(self.registry["records"][0]["downloadUrl"])

    def test_shared_alias_source_hold_is_not_lost_by_locator_filter(self):
        """同じroot URLを共有する別sourceの保留を結合時と通信層で維持する。"""
        self.registry["sources"].append({**self.registry["sources"][0], "id": "source-alias"})
        self.registry["products"][0]["sourceIds"].append("source-alias")
        self.registry = cr.validate_registry(self.registry)
        self.locators["registry"] = pl.registry_binding(self.registry)
        self.policy["heldSourceIds"] = ["source-alias"]
        root_url = self.registry["sources"][0]["officialPage"]
        root = next(row for row in self.requests() if row["url"] == root_url)
        self.assertEqual(root["holdReason"], "NATIVE_COORDINATION_PENDING")
        transport = http.CurlTransport(registry=self.registry, public_locators=self.locators,
                                       held_source_ids=("source-alias",))
        with patch.object(http.subprocess, "run") as process:
            with self.assertRaisesRegex(cr.RegistryError, "LOCATOR_REQUEST_HELD"):
                transport("PAGE", root_url)
            process.assert_not_called()

    def test_failed_page_preserves_previous_success_and_wait(self):
        """新入口での取得失敗も既存の成功hashを消さず、同日再送しない。"""
        self.run_monitor()
        before = dm.verify_store(self.root)
        self.now += timedelta(days=1)
        self.failure = http.response(403, "HTTP_ERROR")
        self.assertEqual(self.run_monitor()["counts"]["failed"], 2)
        after = dm.verify_store(self.root)
        for key, row in before["requests"].items():
            self.assertEqual(after["requests"][key]["lastSuccess"], row["lastSuccess"])
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)

    def test_missing_static_link_is_review_only_not_payload_call(self):
        """登録hrefを観測できなくても本体を追跡せず、source再調査へ残す。"""
        def missing(kind, url):
            """リンクのない正常HTMLを返し、本体通信を検出する。"""
            self.calls.append((kind, url))
            return http.response(200, body=self.body)
        report = dm.run_once(self.registry, self.policy, self.root, public_locators=self.locators,
                             transport=missing, clock=lambda: self.now)
        self.assertIn({"kind": "SOURCE", "id": "source-one", "reason": "STATIC_LINK_NOT_OBSERVED"},
                      report["reviewQueue"])
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all(kind == "PAGE" for kind, _ in self.calls))

    def test_future_locator_generation_rejected_before_state_change(self):
        """未来世代のlocatorを実時計より前に通信・保存しない。"""
        before = (self.root / "state.json").read_bytes()
        self.locators["asOf"] = "2026-10-04T00:00:00Z"
        with self.assertRaisesRegex(cr.RegistryError, "MONITOR_LOCATOR_CLOCK"):
            self.run_monitor()
        self.assertEqual((self.root / "state.json").read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_report_payload_hold_cannot_masquerade_as_page(self):
        """同意保留のLINKをPAGEへ読み替えるV2報告を拒否する。"""
        report = self.run_monitor()
        next(row for row in report["items"] if row["kind"] == "LINK")["kind"] = "PAGE"
        with self.assertRaisesRegex(cr.RegistryError, "REPORT_PAYLOAD_HOLD"):
            dm.validate_report(report)

    def test_observation_wait_survives_export_and_import_without_reservation(self):
        """まだ通信していない実観測待機も移設後に消さず、予約を偽造しない。"""
        self.recent_observations()
        self.run_monitor()
        exported = self.root.parent / "known-export"
        dm.export_store(self.root, exported)
        imported = self.root.parent / "known-import"
        dm.import_export(exported, imported, source_stop_acknowledged=True, clock=lambda: self.now)
        report = dm.run_once(self.registry, self.policy, imported, public_locators=self.locators,
                             transport=self.transport, clock=lambda: self.now)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(dm.verify_store(imported)["requests"], {})
        self.assertEqual(self.calls, [])

    def test_report_and_store_do_not_persist_urls_or_body(self):
        """URL・HTML本文を報告や共有stateへ保存せず、hashと公開IDだけを残す。"""
        self.run_monitor()
        for path in self.root.rglob("*.json"):
            raw = path.read_bytes()
            self.assertNotIn(b"https://", raw)
            self.assertNotIn(self.body, raw)
            self.assertNotIn(b"FILE_INFO", raw)

    def test_v2_report_binding_ids_and_closed_schema(self):
        """V2の結合とIDを必須にし、未知fieldやV1への誤読を拒否する。"""
        report = self.run_monitor()
        self.assertEqual(report["locatorsSha256"], cr.digest(cr.json_bytes(pl.validate_locators(self.locators, self.registry))))
        for mutate in (lambda row: row.update(locatorsSha256=None),
                       lambda row: row.update(cookie="fixture"),
                       lambda row: row["items"][0].update(locatorIds=[]),
                       lambda row: row.update(schema="dc-registry-monitor-report-v1")):
            with self.subTest(mutate=mutate):
                damaged = copy.deepcopy(report)
                mutate(damaged)
                with self.assertRaises(cr.RegistryError):
                    dm.validate_report(damaged)

    def test_v1_does_not_accept_locator_only_hold_reason(self):
        """旧V1報告へ新しい同意保留理由を紛れ込ませない。"""
        report = self.run_monitor()
        report["schema"] = "dc-registry-monitor-report-v1"
        del report["locatorsSha256"]
        for row in report["items"]:
            del row["locatorIds"]
        with self.assertRaisesRegex(cr.RegistryError, "REPORT_HOLD"):
            dm.validate_report(report)

    def test_copy_export_import_mixed_reports_preserve_wait(self):
        """V1／V2混在exportをcopy・importし、報告byteと待機を引き継ぐ。"""
        dm.run_once(self.registry, self.policy, self.root, transport=self.transport, clock=lambda: self.now)
        self.run_monitor()
        exported = self.root.parent / "export"
        dm.export_store(self.root, exported)
        copied = self.root.parent / "copy"
        shutil.copytree(exported, copied)
        self.assertEqual(dm.verify_export(copied), dm.verify_store(self.root))
        imported = self.root.parent / "imported"
        with self.assertRaisesRegex(cr.RegistryError, "IMPORT_SOURCE_STOP_REQUIRED"):
            dm.import_export(copied, imported, clock=lambda: self.now)
        dm.import_export(copied, imported, source_stop_acknowledged=True, clock=lambda: self.now)
        for path in (exported / "reports").iterdir():
            self.assertEqual((imported / "reports" / path.name).read_bytes(), path.read_bytes())
        calls = len(self.calls)
        report = dm.run_once(self.registry, self.policy, imported, public_locators=self.locators,
                             transport=self.transport, clock=lambda: self.now)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(len(self.calls), calls)

    def test_cli_run_locators_and_old_export_arguments(self):
        """新入口は四引数だけとし、既存exportの引数を変更しない。"""
        paths = []
        for name, value in (("registry", self.registry), ("locators", self.locators), ("policy", self.policy)):
            path = self.root.parent / (name + ".json")
            path.write_bytes(cr.json_bytes(value))
            paths.append(str(path))
        with patch("sys.argv", ["monitor", "run-locators", *paths, str(self.root)]), \
             patch.object(dm, "run_once", wraps=dm.run_once) as run, \
             patch.object(dm, "CurlTransport", return_value=self.transport), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(dm.main(), 1)
            self.assertIsNotNone(run.call_args.kwargs["public_locators"])
        self.assertEqual(json.loads(output.getvalue())["result"], "SAVED")
        self.assertNotIn("https://", output.getvalue())
        exported = self.root.parent / "cli-export"
        with patch("sys.argv", ["monitor", "export", str(self.root), str(exported)]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(dm.main(), 0)
        dm.verify_export(exported)


class LocatorHttpTests(unittest.TestCase):
    """Transportの登録限定profileとDNS前拒否を架空subprocessで試験する。"""

    def setUp(self):
        self.registry, self.locators = locator_fixture()

    def transport(self, **options):
        """結合済みlocator専用transportを作り、通信はまだ行わない。"""
        return http.CurlTransport(registry=self.registry, public_locators=self.locators, **options)

    def test_payload_page_and_head_both_rejected_before_dns(self):
        """SelectorのPAYLOADはGETとHEADの両方をDNS前に拒否する。"""
        transport = self.transport()
        with patch.object(http.subprocess, "run") as process:
            for kind in ("PAGE", "LINK"):
                with self.subTest(kind=kind), self.assertRaisesRegex(cr.RegistryError, "LOCATOR_REQUEST_HELD"):
                    transport(kind, PAYLOAD)
            process.assert_not_called()

    def test_response_header_has_no_locator_profile_and_bound_requests_stay_held(self):
        """全既存profileを維持し、新URLの登録recordもDNS前保留のままにする。"""
        url = RESPONSE_HEADER_URL
        self.registry["schema"] = cr.QUERY_REGISTRY_SCHEMA
        self.registry["records"][0].update(downloadUrl=url, linkState="OFFICIAL_LINK")
        self.registry["observations"][0]["kind"] = "OFFICIAL_LINK"
        self.registry = cr.validate_registry(self.registry)
        self.locators["registry"] = pl.registry_binding(self.registry)
        # 新URLへ既存PAYLOAD profileを偽装せず、架空PAGE locatorだけを結合する。
        self.locators["locators"] = [row for row in self.locators["locators"] if row["purpose"] == "PAGE"]
        transport = self.transport()
        with patch.object(http.subprocess, "run") as process:
            for kind in ("PAGE", "LINK"):
                with self.subTest(kind=kind), self.assertRaisesRegex(cr.RegistryError, "LOCATOR_REQUEST_HELD"):
                    transport(kind, url)
            process.assert_not_called()
        for profile in pl.PROFILES:
            for purpose in ("PAGE", "PAYLOAD"):
                with self.subTest(profile=profile, purpose=purpose), self.assertRaises(cr.RegistryError):
                    pl.public_locator_url(url, profile=profile, purpose=purpose)

    def test_queryless_payload_also_rejected_before_dns(self):
        """従来文法を通る本体URLでも用途保留は省略しない。"""
        self.locators["locators"][2].update(url=BASE + "/driver.zip", urlProfile="QUERYLESS")
        transport = self.transport()
        with patch.object(http.subprocess, "run") as process:
            for kind in ("PAGE", "LINK"):
                with self.assertRaises(cr.RegistryError):
                    transport(kind, BASE + "/driver.zip")
            process.assert_not_called()

    def test_native_source_hold_is_enforced_at_transport(self):
        """呼出元が誤って渡してもnative保留sourceを通信しない。"""
        transport = self.transport(held_source_ids=("source-one",))
        with patch.object(http.subprocess, "run") as process:
            with self.assertRaises(cr.RegistryError):
                transport("PAGE", PAGE)
            process.assert_not_called()

    def test_unknown_selectors_wrong_kind_and_default_mode_reject(self):
        """登録外selector・誤用途と既定経路は新queryを許可しない。"""
        transport = self.transport()
        with patch.object(http.subprocess, "run") as process:
            for kind, url in (("PAGE", PAGE.replace("00012", "99999")),
                              ("LINK", PAGE), ("PAGE", PAYLOAD.replace("0012", "9999")),
                              ("HEAD", PAGE), ([], PAGE)):
                with self.subTest(kind=kind), self.assertRaises(cr.RegistryError):
                    transport(kind, url)
            with self.assertRaises(cr.RegistryError):
                http.CurlTransport()("PAGE", PAGE)
            process.assert_not_called()

    def test_transport_invalid_binding_and_held_ids_reject(self):
        """不整合な結合・未登録source・型を初期化時に拒否する。"""
        with self.assertRaises(cr.RegistryError):
            self.transport(held_source_ids=("not-registered",))
        with self.assertRaises(cr.RegistryError):
            self.transport(held_source_ids=["source-one"])
        with self.assertRaises(cr.RegistryError):
            http.CurlTransport(registry=self.registry)
        self.locators["registry"]["sha256"] = "0" * 64
        with self.assertRaises(cr.RegistryError):
            self.transport()

    def test_registered_raw_selector_get_with_finite_curl_policy(self):
        """元のidx URLを有限GETへ渡し、curl設定・redirect・HEADを混ぜない。"""
        captured = []
        def fake_run(args, **options):
            """DNSとcurlを模擬し、test用temporary本文だけを書き込む。"""
            captured.append((args, options))
            if Path(args[0]).name != "curl.exe":
                return subprocess.CompletedProcess(args, 0, b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["93.184.216.34"]}')
            Path(args[args.index("--dump-header") + 1]).write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            Path(args[args.index("--output") + 1]).write_bytes(
                ('<html><a data-href="' + PAYLOAD + '">driver</a></html>').encode("utf-8"))
            return subprocess.CompletedProcess(args, 0, b"200")
        with patch.object(http.subprocess, "run", side_effect=fake_run):
            result = self.transport()("PAGE", PAGE)
        self.assertEqual(result["error"], "NONE")
        self.assertEqual(result["linkHashes"], [dm.hash_text(PAYLOAD)])
        args, options = captured[1]
        self.assertEqual(args[:2], [http.system_curl_path(), "-q"])
        self.assertEqual(args[-1], PAGE)
        self.assertNotIn("--head", args)
        self.assertNotIn("-L", args)
        self.assertEqual(args[args.index("--max-redirs") + 1], "0")
        self.assertEqual(args[args.index("--max-filesize") + 1], str(http.MAX_BODY))
        self.assertEqual(options["timeout"], 22)

    def test_parser_observes_registered_urls_without_following_or_decoding(self):
        """登録URLだけのselector hashを観測し、baseやscriptを実行しない。"""
        transport = self.transport()
        parser = http.PageLinks(BASE, registered_links=transport.registered_links)
        parser.feed('<html><base href="https://other.example.org/"><a href="?idx=00012">page</a>'
                    '<a data-href="' + PAYLOAD + '">file</a><a href="?idx=99999">unknown</a>'
                    '<a href="' + PAYLOAD.replace("|", "%7C") + '">encoded</a>'
                    '<script>location="' + PAGE.replace("00012", "333") + '"</script></html>')
        self.assertEqual(parser.links, {dm.hash_text(PAGE), dm.hash_text(PAYLOAD)})

    def test_parser_invalid_profile_and_mode_reject(self):
        """Parserのprofile mappingも型・用途を閉じて検査する。"""
        for mapping in ({PAGE: ["PUBLIC_PAGE_ID", "PAGE"]},
                        {PAGE: ("PUBLIC_PAGE_ID", "PAYLOAD")}, {PAGE: ("AUTO", "PAGE")}, []):
            with self.subTest(mapping=mapping), self.assertRaises(cr.RegistryError):
                http.PageLinks(BASE, registered_links=mapping)


if __name__ == "__main__":
    unittest.main()
