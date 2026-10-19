"""公開数値fileの用途境界・明示補完・旧同意保持の非通信試験（ADR 0237）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空URL・偽HTTP・temporary directoryだけを使用し、実通信や導入は行わない。
"""

import contextlib
import copy
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_public_locators as pl
import collector_locator_snapshot as ls
import collector_payload_evidence as pe
import registry_monitor_http as http
from test_collector_registry import fixture
from test_collector_public_locators import locator_fixture
from test_collector_locator_snapshot import snapshot_fixture
from test_collector_payload_evidence import evidence
from test_common_page_routes import FIXTURE_CURL, assert_http_process


URL = "https://vendor.example.org/media/file?file=000123"
NEW_TIME = "2026-10-03T02:00:00Z"


def file_fixture() -> dict:
    """架空v2の本体URLとHEAD根拠を同じfile selectorへ結合する。"""
    value = fixture()
    value["schema"] = cr.QUERY_REGISTRY_SCHEMA
    value["records"][0]["downloadUrl"] = URL
    value["observations"][1]["evidenceUrl"] = URL
    return value


def carry_fixture() -> tuple[dict, dict, dict, dict]:
    """Locatorと旧取得証拠が参照しない未取得recordだけを補完する。"""
    old, locators, _ = snapshot_fixture()
    old["records"].append({**old["records"][0], "id": "record-two",
                           "downloadUrl": None, "linkState": "MISSING"})
    old["products"][0]["recordIds"].append("record-two")
    old["observations"].append({**old["observations"][0], "id": "missing-page",
                               "recordId": "record-two", "kind": "OFFICIAL_PAGE"})
    old = cr.validate_registry(old)
    locators["registry"] = pl.registry_binding(old)
    observed = evidence(old)
    new = copy.deepcopy(old)
    new.update(schema=cr.QUERY_REGISTRY_SCHEMA, revision="test-02", asOf=NEW_TIME)
    new["records"][1].update(downloadUrl=URL, linkState="OFFICIAL_LINK")
    new["observations"].append({**old["observations"][0], "id": "fresh-link",
                                "recordId": "record-two", "kind": "OFFICIAL_LINK", "checkedAt": NEW_TIME})
    return old, locators, observed, new


class FilePurposeTests(unittest.TestCase):
    """保存可能なfileをPAGE GET・任意query・自動同意へ拡張しない。"""

    def test_file_only_in_explicit_payload_mode(self):
        """ASCII数値と先頭ゼロは元表現のまま、PAYLOADでだけ受理する。"""
        for number in ("0", "000123", "12345678901234567890"):
            url = URL.rsplit("=", 1)[0] + "=" + number
            self.assertEqual(cr.public_url(url, allow_public_query=True, purpose="PAYLOAD"), url)
            self.assertEqual(pl.public_locator_url(url, profile="PUBLIC_NUMERIC_ID", purpose="PAYLOAD"), url)
            for mode, purpose in ((False, "PAYLOAD"), (True, "PAGE"), (False, "PAGE")):
                with self.subTest(number=number, mode=mode, purpose=purpose), self.assertRaises(cr.RegistryError):
                    cr.public_url(url, allow_public_query=mode, purpose=purpose)
            with self.assertRaisesRegex(cr.RegistryError, "LOCATOR_QUERY_POLICY"):
                pl.public_locator_url(url, profile="PUBLIC_NUMERIC_ID", purpose="PAGE")

    def test_file_query_is_not_a_generic_escape(self):
        """複数値・encoding・path・token・桁超過・未知keyを拒否する。"""
        for query in ("file=", "file=-1", "file=+1", "file=1.0", "file=１２", "File=1",
                      "%66ile=1", "file=%31", "file=1&file=2", "file=1&id=2",
                      "file=1;token=fixture", "file=/driver.zip", "file=123456789012345678901",
                      "file=1#fragment", "redirect=1", "token=1"):
            with self.subTest(query=query), self.assertRaises(cr.RegistryError):
                cr.public_url(URL.partition("?")[0] + "?" + query,
                              allow_public_query=True, purpose="PAYLOAD")

    def test_purpose_and_query_types_are_closed(self):
        """Bool・container・未知用途を黙って受理しない。"""
        for purpose in (None, True, 1, [], "LINK", "payload"):
            with self.subTest(purpose=purpose), self.assertRaisesRegex(cr.RegistryError, "URL_PURPOSE"):
                cr.public_url(URL, allow_public_query=True, purpose=purpose)
        for query in (None, 1, True, []):
            with self.subTest(query=query), self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_TYPE"):
                cr.public_numeric_query(query, purpose="PAYLOAD")

    def test_registry_file_download_and_head_only(self):
        """Source・非HEAD観測・v1へ本体selectorを混入させない。"""
        self.assertEqual(cr.validate_registry(file_fixture())["records"][0]["downloadUrl"], URL)
        for target in ("source", "observation", "v1"):
            value = file_fixture()
            if target == "source":
                value["sources"][0]["officialPage"] = URL
                value["observations"][0]["evidenceUrl"] = URL
            elif target == "observation":
                value["observations"][0]["evidenceUrl"] = URL
            else:
                value["schema"] = cr.REGISTRY_SCHEMA
            with self.subTest(target=target), self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_POLICY"):
                cr.validate_registry(value)

    def test_payload_still_rejects_private_host_auth_and_controls(self):
        """新keyでも元HTTPS・host・auth・escape検証を使う。"""
        for base in ("http://vendor.example.org/file", "https://127.0.0.1/file",
                     "https://server.local/file", "https://user:fixture@vendor.example.org/file",
                     "https://vendor.example.org/%250a", "https://vendor.example.org/%5cfile"):
            with self.subTest(base=base), self.assertRaises(cr.RegistryError):
                cr.public_url(base + "?file=1", allow_public_query=True, purpose="PAYLOAD")

    def test_file_href_is_observed_without_following(self):
        """Hrefだけをhash化し、script・base・追加queryを使わない。"""
        body = ('<html><base href="https://other.example.org/">'
                '<a href="/media/file?file=000123">driver</a>'
                '<a data-href="/media/file?file=000123&amp;token=fixture">private</a>'
                '<script>location="/media/file?file=999"</script></html>')
        parser = http.PageLinks("https://vendor.example.org/page", allow_public_query=True)
        with patch.object(http.subprocess, "run") as called:
            parser.feed(body)
            called.assert_not_called()
        self.assertEqual(parser.links, {cr.digest(URL.encode("utf-8"))})
        old = http.PageLinks("https://vendor.example.org/page")
        old.feed(body)
        self.assertEqual(old.links, set())

    def test_page_and_old_mode_refuse_before_dns(self):
        """FILEのPAGE・旧LINKはDNS・curl前に拒否する。"""
        for kind, mode in (("PAGE", True), ("PAGE", False), ("LINK", False)):
            with self.subTest(kind=kind, mode=mode), patch.object(http.subprocess, "run") as called:
                with self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_POLICY"):
                    http.CurlTransport(allow_public_query=mode)(kind, URL)
                called.assert_not_called()

    def test_head_keeps_selector_and_does_not_follow_redirect(self):
        """200だけを成功とし、302は本文0のHTTP_ERRORとして返す。"""
        for status in (200, 302):
            calls = []
            def fake(args, **options):
                """既定routeと正確なHEADだけへ指定statusの架空headerを返す。"""
                calls.append(args)
                if assert_http_process(self, args, options, kind='LINK', url=URL):
                    return subprocess.CompletedProcess(args, 0,
                        stdout=b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')
                self.assertEqual(args[-1], URL)
                self.assertIn("--head", args)
                self.assertIn("-q", args)
                self.assertNotIn("--location", args)
                self.assertEqual(args[args.index("--max-redirs") + 1], "0")
                Path(args[args.index("--dump-header") + 1]).write_bytes(
                    f"HTTP/1.1 {status} response\r\n\r\n".encode("ascii"))
                return subprocess.CompletedProcess(args, 0, stdout=str(status).encode("ascii"))
            with self.subTest(status=status), patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                    patch.object(http.subprocess, "run", side_effect=fake):
                result = http.CurlTransport(allow_public_query=True)("LINK", URL)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["error"], "NONE" if status == 200 else "HTTP_ERROR")
            self.assertEqual(result["bodyBytes"], 0)
            self.assertIsNone(result["bodySha256"])
            self.assertEqual(len(calls), 2)

    def test_registered_payload_all_conditions_stay_held(self):
        """FILEを登録しても追加promptなしを含む全PAYLOADはDNS前に保留する。"""
        old, locators = locator_fixture()
        for condition in pl.PAYLOAD_CONDITIONS:
            value = copy.deepcopy(locators)
            value["locators"][2].update(url=URL, urlProfile="PUBLIC_NUMERIC_ID", requestCondition=condition)
            transport = http.CurlTransport(allow_public_query=True, registry=old, public_locators=value)
            for kind in ("PAGE", "LINK"):
                with self.subTest(condition=condition, kind=kind), patch.object(http.subprocess, "run") as called:
                    with self.assertRaisesRegex(cr.RegistryError, "LOCATOR_REQUEST_HELD"):
                        transport(kind, URL)
                    called.assert_not_called()


class FileCarryTests(unittest.TestCase):
    """明示補完は未取得・非保留recordへ限定し、旧集合・証拠を保持する。"""

    def carry(self, old, locators, new, **options):
        """架空世代へ共通引継ぎを行い、通信しない。"""
        return ls.carry_forward_locators(old, locators, new, revision="locators-02", as_of=NEW_TIME, **options)

    def test_default_stays_append_only_and_explicit_requires_evidence(self):
        """旧APIの拒否を維持し、optionだけで根拠を省略できない。"""
        old, locators, observed, new = carry_fixture()
        with self.assertRaisesRegex(cr.RegistryError, "LOCATOR_CARRY_NOT_APPEND_ONLY"):
            self.carry(old, locators, new)
        with self.assertRaisesRegex(cr.RegistryError, "LOCATOR_ENRICHMENT_EVIDENCE_REQUIRED"):
            self.carry(old, locators, new, allow_link_enrichment=True)
        for mode in (None, 1, "true"):
            with self.subTest(mode=mode), self.assertRaisesRegex(cr.RegistryError, "LOCATOR_ENRICHMENT_MODE"):
                self.carry(old, locators, new, allow_link_enrichment=mode, old_evidence=observed)

    def test_explicit_carry_preserves_all_locator_rows_and_old_acquisition(self):
        """変更は結合世代だけ、旧locator・originと実取得件数は不変とする。"""
        old, locators, observed, new = carry_fixture()
        carried = self.carry(old, locators, new, allow_link_enrichment=True, old_evidence=observed)
        self.assertEqual(carried["locators"], pl.validate_locators(locators, old)["locators"])
        proof = pe.carry_forward(old, observed, new, allow_link_enrichment=True)
        self.assertEqual(pe.evidence_counts(new, proof)["payloadsDownloaded"], 1)
        self.assertEqual(pe.evidence_counts(new, proof)["recordsWithOfficialLinks"], 2)

    def test_payload_locator_record_cannot_be_enriched(self):
        """旧未取得recordでも同意保留の参照があれば補完を拒否する。"""
        old, locators, observed, new = carry_fixture()
        parent = next(row for row in locators["locators"] if row["id"] == "page-one")
        parent["recordIds"].append("record-two")
        payload = next(row for row in locators["locators"] if row["purpose"] == "PAYLOAD")
        held = {**copy.deepcopy(payload), "id": "payload-two", "recordIds": ["record-two"],
                "url": URL, "urlProfile": "PUBLIC_NUMERIC_ID"}
        locators["locators"].append(held)
        for condition in pl.PAYLOAD_CONDITIONS:
            held["requestCondition"] = condition
            with self.subTest(condition=condition), self.assertRaisesRegex(
                    cr.RegistryError, "LOCATOR_ENRICHMENT_HELD_RECORD"):
                self.carry(old, locators, new, allow_link_enrichment=True, old_evidence=observed)

    def test_missing_fresh_link_and_metadata_change_are_rejected(self):
        """新根拠のない補完とURL以外の変更を許可しない。"""
        old, locators, observed, new = carry_fixture()
        for target in ("time", "title", "product", "old-acquisition"):
            changed = copy.deepcopy(new)
            if target == "time":
                changed["observations"][-1]["checkedAt"] = "2026-10-02T01:00:00Z"
            elif target == "title":
                changed["records"][1]["title"] = "Other driver"
            elif target == "product":
                changed["products"][0]["model"] = "Other Device"
            else:
                changed["records"][0]["packageVersion"] = "2.0"
            with self.subTest(target=target), self.assertRaises(cr.RegistryError):
                self.carry(old, locators, changed, allow_link_enrichment=True, old_evidence=observed)

    def test_cli_option_roundtrip_and_old_input_bytes(self):
        """CLIの明示補完・8 file再検証と旧出力の非変更を確認する。"""
        old, locators, observed, new = carry_fixture()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            ls.write_snapshot(old, locators, base / "old", observed)
            before = {name: (base / "old" / name).read_bytes()
                      for name in ls.snapshot_content(old, locators, observed)}
            (base / "new.json").write_bytes(cr.json_bytes(new))
            args = ["collector_locator_snapshot.py", "carry-forward", str(base / "old"),
                    str(base / "new.json"), str(base / "new"), "--locator-revision", "locators-02",
                    "--allow-link-enrichment"]
            with patch.object(ls.sys, "argv", args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ls.main(), 0)
            actual, carried, proof = ls.verify_snapshot(base / "new")
            self.assertEqual(actual, cr.validate_registry(new))
            self.assertEqual(carried["locators"], pl.validate_locators(locators, old)["locators"])
            self.assertEqual(pe.evidence_counts(actual, proof)["payloadsDownloaded"], 1)
            self.assertEqual(before, {name: (base / "old" / name).read_bytes() for name in before})


if __name__ == "__main__":
    unittest.main()
