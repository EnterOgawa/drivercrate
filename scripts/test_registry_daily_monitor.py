"""台帳日次監視の非通信時計・中断・待機・差分・拒否試験。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公開製品・URLとtemporary directoryだけを使う。
"""
import copy
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import registry_daily_monitor as dm
import registry_monitor_http as http
from test_collector_registry import fixture
from test_collector_registry import RESPONSE_HEADER_URL


class MonitorTests(unittest.TestCase):
    """実driver・実HTTP・端末状態を触れずに保存境界を検証する。"""

    def setUp(self):
        """case専用storeと手動時計・本文・失敗応答・呼出し記録を作る。

        storeは登録したtemporary.cleanupが後始末する。nowの変更だけで試験時刻を進め、
        failureがtruthyでない間はtransportの通常の架空応答を使う。
        """
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "monitor"
        self.registry = fixture()
        self.policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
        self.now = datetime(2026, 10, 3, 1)
        self.calls = []
        self.body = b"<html>sample</html>"
        self.failure = None
        dm.initialize(self.root, clock=lambda: self.now)

    def transport(self, kind, url):
        """同期呼出し中のkindとURLを記録し、truthyなfailureを優先して返す。

        通常のPAGEは本文とリンクhash、LINKは本文なしの架空200を返す。
        実HTTPへ接続せず、このcaseが所有するbody・registry・failureを参照する。
        """
        self.calls.append((kind, url))
        if self.failure:
            return self.failure
        if kind == "PAGE":
            return http.response(200, body=self.body, links=[dm.hash_text(self.registry["records"][0]["downloadUrl"])])
        return http.response(200)

    def run_monitor(self, **options):
        return dm.run_once(self.registry, self.policy, self.root, transport=self.transport,
                           clock=lambda: self.now, **options)

    def test_first_baseline_and_same_day_no_http(self):
        original = copy.deepcopy(self.registry)
        first = self.run_monitor()
        second = self.run_monitor()
        self.assertEqual(first["counts"]["attempted"], 2)
        self.assertEqual(first["counts"]["baseline"], 1)
        self.assertEqual(first["counts"]["link_alive"], 1)
        self.assertEqual(second["counts"]["attempted"], 0)
        self.assertEqual(second["counts"]["deferred"], 2)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.registry, original)
        self.assertEqual(cr.counts(self.registry)["payloadsDownloaded"], 0)
        self.assertTrue(any(row["reason"] == "METADATA_PARSER_NOT_CONFIGURED" for row in first["reviewQueue"]))

    def test_next_day_unchanged_then_changed(self):
        self.run_monitor()
        self.now += timedelta(days=1)
        self.assertEqual(self.run_monitor()["counts"]["unchanged"], 1)
        self.now += timedelta(days=1)
        self.body = b"<html>changed</html>"
        report = self.run_monitor()
        self.assertEqual(report["counts"]["changed"], 1)
        item = next(row for row in report["items"] if row["kind"] == "PAGE")
        self.assertNotEqual(item["previousSha256"], item["observedSha256"])
        self.assertTrue(any(row["reason"] == "PAGE_CHANGED" for row in report["reviewQueue"]))

    def test_failure_preserves_previous_success_and_wait(self):
        self.run_monitor()
        before = dm.verify_store(self.root)
        self.now += timedelta(days=1)
        self.failure = http.response(403, "HTTP_ERROR")
        report = self.run_monitor()
        self.assertEqual(report["counts"]["failed"], 2)
        after = dm.verify_store(self.root)
        for key, row in before["requests"].items():
            self.assertEqual(row["lastSuccess"], after["requests"][key]["lastSuccess"])
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)

    def test_no_response_does_not_claim_success(self):
        self.failure = http.response(error="TIMEOUT")
        report = self.run_monitor()
        self.assertEqual(report["counts"]["failed"], 2)
        self.assertEqual(report["counts"]["budgetBytes"], 2 * http.MAX_BODY)
        self.assertTrue(all(row["lastSuccess"] is None for row in dm.verify_store(self.root)["requests"].values()))

    def test_reservation_crash_is_recovered_without_same_day_retry(self):
        def stop(stage, key):
            if stage == "RESERVED":
                raise RuntimeError("test-stop")
        with self.assertRaises(RuntimeError):
            self.run_monitor(checkpoint=stop)
        self.assertEqual(len(self.calls), 0)
        self.policy["heldSourceIds"] = ["source-one"]
        report = self.run_monitor()
        self.assertEqual(report["counts"]["recoveredReservations"], 1)
        self.assertEqual(len(self.calls), 0)
        self.assertTrue(any(row["outcome"] == "UNKNOWN_OUTCOME" for row in dm.verify_store(self.root)["requests"].values()))

    def test_saved_result_crash_does_not_repeat_saved_target(self):
        def stop(stage, key):
            if stage == "SAVED":
                raise RuntimeError("test-stop")
        with self.assertRaises(RuntimeError):
            self.run_monitor(checkpoint=stop)
        self.assertEqual(len(self.calls), 1)
        report = self.run_monitor()
        self.assertEqual(report["counts"]["attempted"], 1)
        self.assertEqual(len(self.calls), 2)

    def test_added_product_shared_link_does_not_reset_wait(self):
        self.run_monitor()
        product = {**self.registry["products"][0], "id": "product-two", "model": "Device Two"}
        self.registry["products"].append(product)
        self.registry["observations"].append({**self.registry["observations"][0], "id": "page-two", "productId": "product-two"})
        self.registry["revision"] = "test-02"
        report = self.run_monitor()
        self.assertEqual(report["counts"]["targetProducts"], 2)
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertEqual(report["counts"]["plannedRequests"], 2)

    def test_source_rename_keeps_url_wait(self):
        self.run_monitor()
        self.registry["sources"][0]["id"] = "renamed-source"
        self.registry["products"][0]["sourceIds"] = ["renamed-source"]
        self.registry["records"][0]["sourceId"] = "renamed-source"
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)

    def test_alias_page_uses_official_observation_without_duplicate_head(self):
        self.registry["sources"].append({**self.registry["sources"][0], "id": "source-alias",
                                         "officialPage": "https://vendor.example.org/another-page"})
        self.registry["products"][0]["sourceIds"].append("source-alias")
        self.registry["observations"].append({**self.registry["observations"][0], "id": "alias-link",
                                              "evidenceUrl": "https://vendor.example.org/another-page"})
        requests = dm.make_requests(cr.validate_registry(self.registry), self.policy)
        self.assertEqual(len(requests), 3)
        page = next(row for row in requests if row["sourceIds"] == ["source-alias"])
        self.assertEqual(page["expectedLinks"], [dm.hash_text(self.registry["records"][0]["downloadUrl"])])
        self.assertEqual(page["recordIds"], ["record-one"])
        self.assertEqual(sum(row["kind"] == "LINK" for row in requests), 1)

    def test_legacy_hold_never_contacts_http(self):
        self.policy["heldSourceIds"] = ["source-one"]
        report = self.run_monitor()
        self.assertEqual(report["counts"]["held"], 2)
        self.assertEqual(len(self.calls), 0)

    def test_retry_after_long_delay_blocks_other_url_same_host(self):
        self.registry["records"][0]["downloadUrl"] = "https://vendor.example.org/driver.zip"
        self.registry["observations"][1]["evidenceUrl"] = "https://vendor.example.org/driver.zip"
        self.failure = http.response(429, "HTTP_ERROR", retry_after="172800")
        report = self.run_monitor()
        self.assertEqual(report["counts"]["attempted"], 1)
        self.assertEqual(report["counts"]["deferred"], 1)
        self.now += timedelta(days=1)
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)
        self.now += timedelta(days=1)
        self.failure = None
        self.assertGreater(self.run_monitor()["counts"]["attempted"], 0)

    def test_invalid_retry_after_requires_review_forever(self):
        self.failure = http.response(503, "HTTP_ERROR", retry_after="invalid")
        self.run_monitor()
        self.now += timedelta(days=40)
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)
        self.assertTrue(all(row["held"] for row in dm.verify_store(self.root)["hosts"].values()))

    def test_clock_reversal_rejected_before_http(self):
        self.run_monitor()
        self.calls.clear()
        self.now -= timedelta(seconds=1)
        with self.assertRaisesRegex(cr.RegistryError, "MONITOR_CLOCK"):
            self.run_monitor()
        self.assertEqual(self.calls, [])

    def test_state_corruption_and_rehashed_shortened_wait(self):
        self.run_monitor()
        self.calls.clear()
        path = self.root / "state.json"
        original = path.read_bytes()
        value = cr.read_json(path)
        value["sha256"] = "0" * 64
        path.write_bytes(cr.json_bytes(value))
        with self.assertRaises(cr.RegistryError):
            self.run_monitor()
        path.write_bytes(original)
        state = dm.verify_store(self.root)
        next(iter(state["requests"].values()))["nextDueAt"] = dm.stamp(self.now)
        path.write_bytes(dm.envelope("dc-monitor-state-envelope-v1", state))
        with self.assertRaisesRegex(cr.RegistryError, "REQUEST_TIME"):
            self.run_monitor()
        self.assertEqual(self.calls, [])

    def test_unknown_fields_and_damaged_report(self):
        self.run_monitor()
        self.calls.clear()
        report_path = next((self.root / "reports").iterdir())
        report_path.write_bytes(b"not-json")
        with self.assertRaises(cr.RegistryError):
            self.run_monitor()
        self.assertEqual(self.calls, [])

    def test_rehashed_report_counts_and_private_fields_rejected(self):
        report = self.run_monitor()
        for mutate in (lambda value: value["counts"].update(attempted=99),
                       lambda value: value["counts"].update(baseline=True),
                       lambda value: value["items"][0].update(cookie="private"),
                       lambda value: value["reviewQueue"][0].update(id="C:/private")):
            value = copy.deepcopy(report)
            mutate(value)
            with self.assertRaises(cr.RegistryError):
                dm.validate_report(value)

    def test_unknown_state_fields_and_success_time_rejected(self):
        self.run_monitor()
        state = dm.verify_store(self.root)
        row = next(iter(state["requests"].values()))
        row["cookie"] = "private"
        with self.assertRaises(cr.RegistryError):
            dm.validate_state(state)
        del row["cookie"]
        row["lastSuccess"]["checkedAt"] = dm.stamp(self.now + timedelta(days=1))
        with self.assertRaises(cr.RegistryError):
            dm.validate_state(state)

    def test_old_http_failure_remains_in_review_on_deferred_run(self):
        self.failure = http.response(404, "HTTP_ERROR")
        self.run_monitor()
        report = self.run_monitor()
        self.assertEqual(report["counts"]["attempted"], 0)
        self.assertTrue(any(row["reason"] == "LINK_HTTP_FAILED" for row in report["reviewQueue"]))
        self.assertTrue(any(row["reason"] == "HTTP_ERROR" for row in report["reviewQueue"]))

    def test_changed_url_uses_new_binding_without_resetting_old(self):
        self.run_monitor()
        old_keys = set(dm.verify_store(self.root)["requests"])
        new_url = "https://cdn.example.org/new-driver.zip"
        self.registry["records"][0]["downloadUrl"] = new_url
        self.registry["observations"][1]["evidenceUrl"] = new_url
        self.assertEqual(self.run_monitor()["counts"]["attempted"], 1)
        self.assertTrue(old_keys < set(dm.verify_store(self.root)["requests"]))

    def test_request_end_time_also_governs_wait(self):
        def slow(kind, url):
            self.now += timedelta(minutes=2)
            return self.transport(kind, url)
        dm.run_once(self.registry, self.policy, self.root, transport=slow, clock=lambda: self.now)
        state = dm.verify_store(self.root)
        self.assertTrue(all(cr.timestamp(row["nextDueAt"]) >= cr.timestamp(row["endedAt"]) + timedelta(days=1)
                            for row in state["requests"].values()))

    def test_deadline_and_reparse_refuse_requests(self):
        with patch.object(dm, "MAX_RUN_SECONDS", 0):
            self.assertEqual(self.run_monitor()["counts"]["attempted"], 0)
        with patch.object(cr, "regular_path", side_effect=cr.RegistryError("REPARSE_PATH")):
            with self.assertRaisesRegex(cr.RegistryError, "REPARSE_PATH"):
                self.run_monitor()
        self.assertEqual(self.calls, [])

    def test_copy_preserves_wait_and_state(self):
        self.run_monitor()
        copied = self.root.parent / "copy"
        shutil.copytree(self.root, copied)
        original = dm.verify_store(self.root)
        self.assertEqual(dm.verify_store(copied), original)
        report = dm.run_once(self.registry, self.policy, copied, transport=self.transport, clock=lambda: self.now)
        self.assertEqual(report["counts"]["attempted"], 0)

    def test_export_excludes_lock_and_preserves_wait(self):
        self.run_monitor()
        exported = self.root.parent / "exported"
        dm.export_store(self.root, exported)
        self.assertEqual(dm.verify_export(exported), dm.verify_store(self.root))
        self.assertFalse((exported / "writer.lock").exists())
        copied = self.root.parent / "copied-export"
        shutil.copytree(exported, copied)
        self.assertEqual(dm.verify_export(copied), dm.verify_store(self.root))
        with self.assertRaisesRegex(cr.RegistryError, "MONITOR_FILE_SET"):
            dm.run_once(self.registry, self.policy, copied, transport=self.transport, clock=lambda: self.now)
        self.assertEqual(len(self.calls), 2)

    def test_export_manifest_tamper_missing_extra_and_overwrite(self):
        self.run_monitor()
        exported = self.root.parent / "exported"
        dm.export_store(self.root, exported)
        with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
            dm.export_store(self.root, exported)
        report_path = next((exported / "reports").iterdir())
        raw = report_path.read_bytes()
        report_path.unlink()
        with self.assertRaises(cr.RegistryError):
            dm.verify_export(exported)
        report_path.write_bytes(raw)
        (exported / "writer.lock").write_bytes(b"0")
        with self.assertRaisesRegex(cr.RegistryError, "EXPORT_FILE_SET"):
            dm.verify_export(exported)

    def test_export_detects_byte_change_even_with_equivalent_json(self):
        self.run_monitor()
        exported = self.root.parent / "exported"
        dm.export_store(self.root, exported)
        path = exported / "state.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(cr.RegistryError, "EXPORT_FILE_HASH"):
            dm.verify_export(exported)

    def test_export_does_not_take_in_progress_reservation(self):
        def stop(stage, key):
            raise RuntimeError("test-stop")
        with self.assertRaises(RuntimeError):
            self.run_monitor(checkpoint=stop)
        output = self.root.parent / "exported"
        with self.assertRaisesRegex(cr.RegistryError, "EXPORT_INCOMPLETE_RESERVATION"):
            dm.export_store(self.root, output)
        self.assertFalse(output.exists())

    def test_concurrent_writer_refused(self):
        with dm.writer_lock(self.root):
            with self.assertRaisesRegex(cr.RegistryError, "MONITOR_BUSY"):
                self.run_monitor()
        self.assertEqual(len(self.calls), 0)

    def test_preexisting_root_and_extra_file_refused(self):
        with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
            dm.initialize(self.root, clock=lambda: self.now)
        (self.root / "unexpected.exe").write_bytes(b"MZ-fake")
        with self.assertRaisesRegex(cr.RegistryError, "MONITOR_FILE_SET"):
            self.run_monitor()
        self.assertEqual(len(self.calls), 0)

    def test_invalid_transport_and_exception_are_failed(self):
        for result in ({}, http.response(200)):
            with self.subTest(result=result):
                self.failure = result or {"extra": "unknown"}
                self.assertGreater(self.run_monitor()["counts"]["failed"], 0)
                self.now += timedelta(days=1)
        def raised(kind, url):
            raise RuntimeError("private text must not persist")
        report = dm.run_once(self.registry, self.policy, self.root, transport=raised, clock=lambda: self.now)
        self.assertEqual(report["counts"]["failed"], 2)
        self.assertNotIn("private text", cr.json_bytes(report).decode())

    def test_finite_budget_defers_without_reservation(self):
        with patch.object(dm, "MAX_REQUESTS", 1):
            report = self.run_monitor()
        self.assertEqual(report["counts"]["attempted"], 1)
        self.assertEqual(report["counts"]["deferred"], 1)
        self.assertEqual(len(dm.verify_store(self.root)["requests"]), 1)

    def test_failed_bytes_budget_charged_conservatively(self):
        self.failure = http.response(error="TIMEOUT")
        with patch.object(dm, "MAX_RUN_BYTES", http.MAX_BODY):
            self.assertEqual(self.run_monitor()["counts"]["attempted"], 1)

    def test_missing_links_and_metadata_stay_in_review(self):
        self.registry["records"][0].update(downloadUrl=None, linkState="MISSING")
        self.registry["observations"] = [{**self.registry["observations"][0], "kind": "OFFICIAL_PAGE"}]
        def page(kind, url):
            return http.response(200, body=self.body)
        report = dm.run_once(self.registry, self.policy, self.root, transport=page, clock=lambda: self.now)
        self.assertEqual(report["counts"]["plannedRequests"], 1)
        self.assertTrue(any(row["reason"] == "LINK_UNRESOLVED" for row in report["reviewQueue"]))


class HttpProjectionTests(unittest.TestCase):
    """本文非保存のリンク観測、宛先拒否とRetry-After規則を確認する。"""

    def test_response_header_href_retains_original_hash_without_request(self):
        """二keyの順序とpercent tripletをそのままhash化し、HTMLから通信しない。"""
        raw = RESPONSE_HEADER_URL
        reverse = raw.partition("?")[0] + "?" + "&".join(reversed(raw.partition("?")[2].split("&")))
        lowercase = raw.replace("%3B", "%3b").replace("%2A", "%2a").replace("%2F", "%2f")
        body = "<html>" + "".join('<a data-href="' + url.replace("&", "&amp;") + '">x</a>'
                                   for url in (raw, reverse, lowercase)) + "</html>"
        with patch.object(http.subprocess, "run") as process:
            parser = http.PageLinks("https://vendor.example.org/page", allow_public_query=True)
            parser.feed(body)
            self.assertEqual(parser.links, {dm.hash_text(url) for url in (raw, reverse, lowercase)})
            self.assertEqual(parser.derived_links, set())
            old = http.PageLinks("https://vendor.example.org/page")
            old.feed(body)
            self.assertEqual(old.links, set())
            process.assert_not_called()

    def test_response_header_transport_refuses_before_dns(self):
        """保存可能なqueryもPAGE／LINKの既定・明示modeでDNSとcurlを呼ばない。"""
        # Suffixの早期拒否だけに依存せず、第二数値gateへ届くLINKも検査する。
        urls = (RESPONSE_HEADER_URL, "https://cdn.example.org/files/package?" +
                RESPONSE_HEADER_URL.partition("?")[2])
        for url in urls:
            self.assertEqual(cr.public_url(url, allow_public_query=True, purpose="PAYLOAD"), url)
            for kind in ("PAGE", "LINK"):
                for mode in (False, True):
                    with self.subTest(url=url, kind=kind, mode=mode), \
                            patch.object(http.subprocess, "run") as process:
                        with self.assertRaises(cr.RegistryError):
                            http.CurlTransport(allow_public_query=mode)(kind, url)
                        process.assert_not_called()

    def test_response_header_link_plan_is_not_transport_authorization(self):
        """非null recordからのLINK計画が旧第二数値gateのDNS前拒否を回避しない。"""
        value = fixture()
        value["schema"] = cr.QUERY_REGISTRY_SCHEMA
        value["records"][0].update(downloadUrl=RESPONSE_HEADER_URL, linkState="OFFICIAL_LINK")
        value["observations"] = value["observations"][:1]
        value = cr.validate_registry(value)
        policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
        request = next(row for row in dm.make_requests(value, policy) if row["kind"] == "LINK")
        self.assertEqual(request["url"], RESPONSE_HEADER_URL)
        self.assertEqual(request["recordIds"], ["record-one"])
        with patch.object(http.subprocess, "run") as process:
            with self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_POLICY"):
                http.CurlTransport(allow_public_query=True)(request["kind"], request["url"])
            process.assert_not_called()

    def test_static_html_links_never_execute_or_follow(self):
        parser = http.PageLinks("https://vendor.example.org/page")
        parser.feed('<html><base href="https://other.example.org/"><a data-href="/driver.zip">x</a>'
                    '<script>location="https://unrelated.example.org/run"</script>'
                    '<a href="http://127.0.0.1/private">x</a></html>')
        self.assertTrue(parser.html)
        self.assertEqual(parser.links, {dm.hash_text("https://vendor.example.org/driver.zip")})

    def test_html_fragment_is_not_required_to_have_html_root(self):
        parser = http.PageLinks("https://vendor.example.org/page")
        parser.feed('<div><a href="/driver.zip">Driver</a></div>')
        self.assertTrue(parser.html)
        self.assertIn(dm.hash_text("https://vendor.example.org/driver.zip"), parser.links)

    def test_head_large_payload_is_not_limited_as_body_download(self):
        calls = []
        def fake_run(args, **options):
            calls.append(args)
            if Path(args[0]).name != "curl.exe":
                return subprocess.CompletedProcess(args, 0, stdout=b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')
            self.assertIn("-q", args)
            self.assertIn("--head", args)
            self.assertNotIn("--max-filesize", args)
            self.assertNotIn("--location", args)
            headers = Path(args[args.index("--dump-header") + 1])
            headers.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 56245504\r\n\r\n")
            return subprocess.CompletedProcess(args, 0, stdout=b"200")
        with patch.object(http.subprocess, "run", side_effect=fake_run):
            result = http.CurlTransport()("LINK", "https://vendor.example.org/driver.exe")
        self.assertEqual(result["error"], "NONE")
        self.assertEqual(result["bodyBytes"], 0)
        self.assertEqual(len(calls), 2)

    def test_get_limit_curl_size_error_and_duplicate_retry_header(self):
        def fake_run(args, **options):
            if Path(args[0]).name != "curl.exe":
                return subprocess.CompletedProcess(args, 0, stdout=b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')
            self.assertIn("--max-filesize", args)
            self.assertNotIn("--head", args)
            headers = Path(args[args.index("--dump-header") + 1])
            headers.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            return subprocess.CompletedProcess(args, 63, stdout=b"200")
        with patch.object(http.subprocess, "run", side_effect=fake_run):
            self.assertEqual(http.CurlTransport()("PAGE", "https://vendor.example.org/page")["error"], "BODY_SIZE")

    def test_http_timeout_and_dns_timeout_do_not_retry(self):
        def timed_out(args, **options):
            raise subprocess.TimeoutExpired(args, 5)
        with patch.object(http.subprocess, "run", side_effect=timed_out) as mocked:
            self.assertEqual(http.CurlTransport()("PAGE", "https://vendor.example.org/page")["error"], "TIMEOUT")
            self.assertEqual(mocked.call_count, 1)

    def test_dns_private_mixed_and_embedded_addresses(self):
        for addresses in (("127.0.0.1",), ("8.8.8.8", "192.168.1.1"), ("2001:db8::1",), ("::ffff:8.8.8.8",)):
            answers = [(2, 1, 6, "", (address, 443)) for address in addresses]
            with self.subTest(addresses=addresses), patch.object(http.socket, "getaddrinfo", return_value=answers):
                with self.assertRaises(cr.RegistryError):
                    http.public_addresses("vendor.example.org")

    def test_dns_public_and_empty(self):
        with patch.object(http.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 443))]):
            self.assertEqual(http.public_addresses("vendor.example.org"), ["8.8.8.8"])
        with patch.object(http.socket, "getaddrinfo", return_value=[]):
            with self.assertRaisesRegex(cr.RegistryError, "DNS_EMPTY"):
                http.public_addresses("vendor.example.org")

    def test_retry_after_exact_http_date_and_bad_values(self):
        now = datetime(2026, 10, 3)
        desired = now + timedelta(days=3)
        value = format_datetime(desired.replace(tzinfo=timezone.utc), usegmt=True)
        self.assertEqual(dm.retry_deadline(value, now), (desired, False))
        for value in ("-1", "99999999", "1,2", "tomorrow", "2592001"):
            self.assertEqual(dm.retry_deadline(value, now), (now + timedelta(days=1), True))
        self.assertEqual(dm.retry_deadline("0", now), (now + timedelta(days=1), False))


if __name__ == "__main__":
    unittest.main()
