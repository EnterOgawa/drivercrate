"""公開数値配布ID query・旧形式・限定リンク補完の非通信回帰試験（ADR 0233）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公開URL・clock・HTTP・temporary directoryだけを使い、実導入は行わない。
"""
import copy
from datetime import datetime
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_payload_evidence as pe
import registry_daily_monitor as dm
import registry_monitor_http as http
from test_collector_registry import fixture
from test_collector_payload_evidence import evidence
from test_common_page_routes import FIXTURE_CURL, assert_http_process


PUBLIC_URL = "https://vendor.example.org/download/?drid=126"


def query_fixture() -> dict:
    """台帳v2の正当な架空queryリンクを同じ観測へ結合する。"""
    value = fixture()
    value["schema"] = cr.QUERY_REGISTRY_SCHEMA
    value["records"][0]["downloadUrl"] = PUBLIC_URL
    value["observations"][1]["evidenceUrl"] = PUBLIC_URL
    return value


def enrichment_fixture() -> tuple[dict, dict, dict]:
    """旧未取得recordだけを新しいlink根拠で補完する世代組を返す。"""
    old = fixture()
    old["records"].append({**old["records"][0], "id": "record-two",
                           "downloadUrl": None, "linkState": "MISSING"})
    old["products"][0]["recordIds"].append("record-two")
    old["observations"].append({**old["observations"][0], "id": "unknown-page",
                               "recordId": "record-two", "kind": "OFFICIAL_PAGE"})
    observed = evidence(old)
    new = copy.deepcopy(old)
    new.update(schema=cr.QUERY_REGISTRY_SCHEMA, revision="test-02", asOf="2026-10-03T02:00:00Z")
    new["records"][1].update(downloadUrl=PUBLIC_URL, linkState="HEAD_OK")
    new["observations"] += [
        {**old["observations"][0], "id": "fresh-link", "recordId": "record-two",
         "checkedAt": new["asOf"]},
        {**old["observations"][1], "id": "fresh-head", "recordId": "record-two",
         "evidenceUrl": PUBLIC_URL, "checkedAt": new["asOf"]},
    ]
    return old, observed, new


class PublicQueryTests(unittest.TestCase):
    """Queryはv2の明示modeだけで受理し、秘密や曖昧な表現を拒否する。"""

    def test_numeric_selectors_keep_original_url_and_v1_refuses(self):
        """全selectorの元表現を維持し、旧modeへ許可を漏らさない。"""
        for key in ("id", "drid", "download_id", "file_id", "product_id"):
            for number in ("0", "00012", "12345678901234567890"):
                url = "https://vendor.example.org/file?" + key + "=" + number
                with self.subTest(key=key, number=number):
                    self.assertEqual(cr.public_url(url, allow_public_query=True), url)
                    with self.assertRaises(cr.RegistryError):
                        cr.public_url(url)

    def test_unsafe_unknown_encoded_or_multiple_query_is_rejected(self):
        """Token・転送・曖昧なkey/valueを数値selectorへ読み替えない。"""
        queries = ("", "token=fixture", "signature=fixture", "expires=123", "utm_source=1",
                   "path=/support/resource/", "redirect=https://example.org/", "unknown=1",
                   "id=", "id=-1", "id=+1", "id=1.0", "id=１２", "ID=1",
                   "%69d=1", "id=%31", "id=%250a", "id=1%26token=fixture",
                   "id=1&id=2", "id=1&drid=2", "id=1;token=fixture",
                   "id=123456789012345678901", "id=1#fragment")
        for query in queries:
            with self.subTest(query=query), self.assertRaises(cr.RegistryError):
                cr.public_url("https://vendor.example.org/file?" + query, allow_public_query=True)

    def test_private_host_auth_and_control_stay_rejected_in_v2(self):
        """Query対応で既存HTTPS・私的宛先・escape境界を緩めない。"""
        for base in ("http://vendor.example.org/file", "https://127.0.0.1/file",
                     "https://[::1]/file", "https://server.local/file",
                     "https://user:fixture@vendor.example.org/file",
                     "https://vendor.example.org:444/file", "https://vendor.example.org/%250a",
                     "https://vendor.example.org/%5cfile"):
            with self.subTest(base=base), self.assertRaises(cr.RegistryError):
                cr.public_url(base + "?id=1", allow_public_query=True)
        for mode in (None, 1, "true"):
            with self.subTest(mode=mode), self.assertRaises(cr.RegistryError):
                cr.public_url(PUBLIC_URL, allow_public_query=mode)

    def test_registry_schema_gates_all_url_channels(self):
        """Source・record・観測に同じ世代のURL契約を適用する。"""
        value = query_fixture()
        source = "https://vendor.example.org/page?download_id=12"
        value["sources"][0]["officialPage"] = source
        value["observations"][0]["evidenceUrl"] = source
        self.assertEqual(cr.validate_registry(value)["schema"], cr.QUERY_REGISTRY_SCHEMA)
        value["schema"] = cr.REGISTRY_SCHEMA
        with self.assertRaises(cr.RegistryError):
            cr.validate_registry(value)
        for channel in ("source", "record"):
            changed = query_fixture()
            bad = "https://vendor.example.org/file?unknown=1"
            if channel == "source":
                changed["sources"][0]["officialPage"] = bad
                changed["observations"][0]["evidenceUrl"] = bad
            else:
                changed["records"][0]["downloadUrl"] = bad
                changed["observations"][1]["evidenceUrl"] = bad
            with self.subTest(channel=channel), self.assertRaises(cr.RegistryError):
                cr.validate_registry(changed)

    def test_page_link_hash_observes_public_query_without_normalizing(self):
        """公開selectorだけを観測し、query削除・JS実行・未知query追跡を行わない。"""
        body = ('<html><a href="/download/?drid=126">driver</a>'
                '<a data-href="/download/?drid=000126">other</a>'
                '<a href="/download/?drid=126&amp;token=fixture">private</a>'
                '<script>location="/download/?id=9"</script></html>')
        parser = http.PageLinks("https://vendor.example.org/page", allow_public_query=True)
        parser.feed(body)
        self.assertEqual(parser.links, {dm.hash_text(PUBLIC_URL),
                         dm.hash_text("https://vendor.example.org/download/?drid=000126")})
        old = http.PageLinks("https://vendor.example.org/page")
        old.feed(body)
        self.assertEqual(old.links, set())

    def test_http_refuses_bad_query_and_kind_before_dns(self):
        """不許可queryと誤kindはDNS・GETへ到達しない。"""
        for kind, url, mode in (("LINK", PUBLIC_URL, False),
                                ("LINK", PUBLIC_URL + "&token=fixture", True),
                                ("HEAD", PUBLIC_URL, True)):
            with self.subTest(kind=kind, mode=mode), patch.object(http.subprocess, "run") as called:
                with self.assertRaises(cr.RegistryError):
                    http.CurlTransport(allow_public_query=mode)(kind, url)
                called.assert_not_called()

    def test_query_head_keeps_original_url_no_redirect_and_no_body(self):
        """Query付きLINKでもHEADとHTTPS・上限を維持する。"""
        calls = []
        def fake(args, **options):
            """既定routeと正確なHEADだけへ架空の公開headerを返す。"""
            calls.append(args)
            if assert_http_process(self, args, options, kind='LINK', url=PUBLIC_URL):
                return subprocess.CompletedProcess(args, 0,
                    stdout=b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')
            self.assertEqual(args[-1], PUBLIC_URL)
            self.assertIn("--head", args)
            self.assertIn("-q", args)
            self.assertNotIn("--location", args)
            self.assertEqual(args[args.index("--max-redirs") + 1], "0")
            Path(args[args.index("--dump-header") + 1]).write_bytes(b"HTTP/1.1 200 OK\r\n\r\n")
            return subprocess.CompletedProcess(args, 0, stdout=b"200")
        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                patch.object(http.subprocess, "run", side_effect=fake):
            result = http.CurlTransport(allow_public_query=True)("LINK", PUBLIC_URL)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["bodyBytes"], 0)
        self.assertIsNone(result["bodySha256"])
        self.assertEqual(len(calls), 2)

    def test_query_page_get_projects_public_link_hash(self):
        """PAGEの有限GETにも同じquery modeを適用し、本文を観測値だけへ射影する。"""
        body = b'<html><a href="/download/?drid=126">driver</a></html>'
        def fake(args, **options):
            """既定routeと正確なPAGE GETだけへ架空HTMLを返す。"""
            if assert_http_process(self, args, options, kind='PAGE', url=PUBLIC_URL):
                return subprocess.CompletedProcess(args, 0,
                    stdout=b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')
            self.assertNotIn("--head", args)
            self.assertIn("--max-filesize", args)
            self.assertNotIn("--location", args)
            Path(args[args.index("--dump-header") + 1]).write_bytes(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n")
            Path(args[args.index("--output") + 1]).write_bytes(body)
            return subprocess.CompletedProcess(args, 0, stdout=b"200")
        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                patch.object(http.subprocess, "run", side_effect=fake):
            result = http.CurlTransport(allow_public_query=True)("PAGE", PUBLIC_URL)
        self.assertEqual(result["error"], "NONE")
        self.assertEqual(result["linkHashes"], [dm.hash_text(PUBLIC_URL)])
        self.assertEqual(result["bodySha256"], cr.digest(body))

    def test_daily_registry_mode_and_same_day_wait(self):
        """明示v2のURLを監視へ結合し、同日再実行の待機を維持する。"""
        registry = query_fixture()
        policy = {"schema": "dc-registry-monitor-policy-v1", "revision": "test", "heldSourceIds": []}
        now = datetime(2026, 10, 3, 2)
        calls = []
        body = b'<html><a href="/download/?drid=126">driver</a></html>'
        def fake(kind, url):
            calls.append((kind, url))
            return http.response(200) if kind == "LINK" else http.response(
                200, body=body, links=[dm.hash_text(PUBLIC_URL)])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "monitor"
            dm.initialize(root, clock=lambda: now)
            with patch.object(dm, "CurlTransport", return_value=fake) as factory:
                first = dm.run_once(registry, policy, root, clock=lambda: now)
                second = dm.run_once(registry, policy, root, clock=lambda: now)
                self.assertEqual(factory.call_args.kwargs, {"allow_public_query": True})
            self.assertEqual(first["counts"]["attempted"], 2)
            self.assertEqual(second["counts"]["attempted"], 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(first["reviewQueue"], [{"kind": "SOURCE", "id": "source-one",
                             "reason": "METADATA_PARSER_NOT_CONFIGURED"}])

    def test_v3_snapshot_roundtrip_and_manifest_downgrade_rejected(self):
        """6 fileのquery世代とfield・台帳schema・証拠有無を検査する。"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "snapshot"
            cr.write_snapshot(query_fixture(), root)
            self.assertEqual(cr.verify_snapshot(root), cr.validate_registry(query_fixture()))
            path = root / "manifest.json"
            original = cr.read_json(path)
            self.assertEqual(original["schema"], cr.QUERY_SNAPSHOT_SCHEMA)
            for key, value in (("schema", "dc-portable-research-snapshot-v1"),
                               ("registrySchema", cr.REGISTRY_SCHEMA),
                               ("includesPayloadEvidence", True)):
                path.write_bytes(cr.json_bytes({**original, key: value}))
                with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                    cr.verify_snapshot(root)


class LinkEnrichmentTests(unittest.TestCase):
    """既定の追加専用を維持し、未取得URL以外の変更へ証拠を転用しない。"""

    def test_default_rejects_but_explicit_enrichment_preserves_old_evidence(self):
        """明示補完だけを受理し、旧取得観測とoriginを保持する。"""
        old, observed, new = enrichment_fixture()
        with self.assertRaisesRegex(cr.RegistryError, "CARRY_FORWARD_NOT_APPEND_ONLY"):
            pe.carry_forward(old, observed, new)
        carried = pe.carry_forward(old, observed, new, allow_link_enrichment=True)
        row = dict(carried["acquisitions"][0])
        row.pop("recordSha256")
        self.assertEqual(row, observed["acquisitions"][0])
        self.assertEqual(carried["originRegistry"]["revision"], old["revision"])
        self.assertEqual(pe.evidence_counts(new, carried)["payloadsDownloaded"], 1)
        newest = {**new, "revision": "test-03", "asOf": "2026-10-03T03:00:00Z"}
        repeated = pe.carry_forward(new, carried, newest)
        self.assertEqual(carried["originRegistry"], repeated["originRegistry"])
        self.assertEqual(carried["acquisitions"], repeated["acquisitions"])

    def test_official_link_without_head_is_not_promoted_to_head_success(self):
        """HEAD未実施の正当な補完を許すが、HEAD合格や本体取得へ数えない。"""
        old, observed, new = enrichment_fixture()
        new["records"][1]["linkState"] = "OFFICIAL_LINK"
        new["observations"] = [row for row in new["observations"] if row["id"] != "fresh-head"]
        carried = pe.carry_forward(old, observed, new, allow_link_enrichment=True)
        counts = pe.evidence_counts(new, carried)
        self.assertEqual(counts["recordsWithOfficialLinks"], 2)
        self.assertEqual(counts["recordsWithHead200"], 1)
        self.assertEqual(counts["payloadsDownloaded"], 1)

    def test_other_record_metadata_and_old_acquired_url_changes_rejected(self):
        """補完modeでも版・title・hash・OSと旧取得URLの変更を拒否する。"""
        old, observed, new = enrichment_fixture()
        for index, key, value in ((1, "title", "Other title"), (1, "packageVersion", "2.0"),
                                  (1, "publishedSha256", "c" * 64),
                                  (1, "operatingSystems", ["WINDOWS_10_X64"]),
                                  (0, "downloadUrl", "https://cdn.example.org/other.zip")):
            changed = copy.deepcopy(new)
            changed["records"][index][key] = value
            if index == 0:
                changed["observations"][1]["evidenceUrl"] = value
            with self.subTest(key=key, index=index), self.assertRaises(cr.RegistryError):
                pe.carry_forward(old, observed, changed, allow_link_enrichment=True)

    def test_old_products_sources_observations_remain_immutable(self):
        """未取得recordの補完を製品対応・元根拠の変更へ拡大しない。"""
        old, observed, new = enrichment_fixture()
        for name, key, value in (("products", "model", "Different Model"),
                                 ("sources", "collectionMethod", "LEGACY_ASUS_METADATA"),
                                 ("observations", "checkedAt", "2026-10-02T01:00:00Z")):
            changed = copy.deepcopy(new)
            changed[name][0][key] = value
            with self.subTest(name=name), self.assertRaises(cr.RegistryError):
                pe.carry_forward(old, observed, changed, allow_link_enrichment=True)

    def test_fresh_link_and_head_proof_is_required(self):
        """古い日時の観測を新しいリンクの確認へ流用しない。"""
        old, observed, new = enrichment_fixture()
        for kind in ("OFFICIAL_LINK", "HEAD"):
            changed = copy.deepcopy(new)
            for row in changed["observations"]:
                if row["id"].startswith("fresh-") and row["kind"] == kind:
                    row["checkedAt"] = "2026-10-02T00:00:00Z"
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    cr.RegistryError, "ENRICHMENT_FRESH_EVIDENCE"):
                pe.carry_forward(old, observed, changed, allow_link_enrichment=True)

    def test_query_evidence_bundle_roundtrip_and_plain_reader_refuses(self):
        """7 fileのv3をcopy可能に保ち、証拠なしreaderへの偽装を拒否する。"""
        old, observed, new = enrichment_fixture()
        carried = pe.carry_forward(old, observed, new, allow_link_enrichment=True)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "bundle"
            pe.write_bundle(new, carried, root)
            actual, proof = pe.verify_bundle(root)
            self.assertEqual(actual, cr.validate_registry(new))
            self.assertEqual(proof, carried)
            manifest = cr.read_json(root / "manifest.json")
            self.assertEqual(manifest["schema"], cr.QUERY_SNAPSHOT_SCHEMA)
            self.assertTrue(manifest["includesPayloadEvidence"])
            with self.assertRaises(cr.RegistryError):
                cr.verify_snapshot(root)
            manifest["includesPayloadEvidence"] = False
            (root / "manifest.json").write_bytes(cr.json_bytes(manifest))
            with self.assertRaises(cr.RegistryError):
                pe.verify_bundle(root)

    def test_carry_forward_cli_enrichment_option_is_connected(self):
        """CLIの明示optionを補完処理へ渡し、未知optionの黙認をしない。"""
        old, observed, new = enrichment_fixture()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            pe.write_bundle(old, observed, base / "old")
            (base / "new.json").write_bytes(cr.json_bytes(new))
            args = ["collector_payload_evidence.py", "carry-forward", str(base / "old"),
                    str(base / "new.json"), str(base / "new"), "--allow-link-enrichment"]
            with patch.object(pe.sys, "argv", args):
                self.assertEqual(pe.main(), 0)
            self.assertEqual(pe.verify_bundle(base / "new")[0], cr.validate_registry(new))


if __name__ == "__main__":
    unittest.main()
