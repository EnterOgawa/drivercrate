"""公開locatorの文法・用途と旧経路の拒否境界を検証する（ADR 0235）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空URLのみを使用し、DNS・HTTP・driver取得・導入は行わない。
"""

import contextlib
import copy
import io
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_public_locators as pl
import registry_monitor_http as http
from test_collector_registry import fixture


BASE = "https://vendor.example.org/download/file"
PAGE = BASE + "?idx=00012"
PAYLOAD = BASE + "?FILE_INFO=driver|driver_file|driver_idx|0012|driver"


def locator_fixture() -> tuple[dict, dict]:
    """元台帳の実観測へrootを結合した架空三locatorを返す。"""
    registry = fixture()
    registry["records"][0].update(downloadUrl=None, linkState="MISSING")
    registry["observations"] = [
        {**registry["observations"][0], "kind": "OFFICIAL_PAGE", "method": "LOCAL_HTTP",
         "httpStatus": 200, "evidenceSha256": "a" * 64}]
    registry = cr.validate_registry(registry)
    observation = {"method": "LOCAL_HTTP", "httpStatus": 200, "bodyBytes": 1200,
                   "bodySha256": "a" * 64, "checkedAt": "2026-10-02T00:00:00Z"}
    root = {"id": "root-one", "sourceId": "source-one", "purpose": "PAGE",
            "url": registry["sources"][0]["officialPage"], "urlProfile": "QUERYLESS",
            "productIds": ["product-one"], "recordIds": [], "parentPageIds": [],
            "requestCondition": "PUBLIC_METADATA", "publicationCondition": "REVIEW_REQUIRED",
            "pageObservation": observation}
    child = {**copy.deepcopy(root), "id": "page-one", "url": PAGE, "urlProfile": "PUBLIC_PAGE_ID",
             "recordIds": ["record-one"], "parentPageIds": ["root-one"],
             "pageObservation": {**observation, "bodySha256": "b" * 64}}
    payload = {**copy.deepcopy(child), "id": "payload-one", "purpose": "PAYLOAD", "url": PAYLOAD,
               "urlProfile": "PUBLIC_DRIVER_SELECTOR", "parentPageIds": ["page-one"],
               "requestCondition": "CONSENT_REQUIRED", "pageObservation": None}
    value = {"schema": pl.LOCATOR_SCHEMA, "revision": "locators-01", "asOf": registry["asOf"],
             "registry": pl.registry_binding(registry), "researchOnly": True, "publishable": False,
             "installAuthorized": False, "locators": [root, child, payload]}
    return registry, value


class PublicLocatorUrlTests(unittest.TestCase):
    """公開selectorの保存許可を、通信や公式性の許可へ拡張しない。"""

    def test_queryless_both_purposes_keep_exact_url(self):
        """Queryなしの元表現をPAGEとPAYLOADで保持する。"""
        for purpose in pl.PURPOSES:
            for url in (BASE, BASE + "/", "https://vendor.example.org:443/File%20Name"):
                with self.subTest(purpose=purpose, url=url):
                    self.assertEqual(pl.public_locator_url(
                        url, profile="QUERYLESS", purpose=purpose), url)

    def test_numeric_profile_keeps_existing_public_ids(self):
        """既存の五つのselectorと先頭ゼロを変更しない。"""
        for key in ("id", "drid", "download_id", "file_id", "product_id"):
            for number in ("0", "00012", "12345678901234567890"):
                for purpose in pl.PURPOSES:
                    url = BASE + "?" + key + "=" + number
                    with self.subTest(key=key, number=number, purpose=purpose):
                        self.assertEqual(pl.public_locator_url(
                            url, profile="PUBLIC_NUMERIC_ID", purpose=purpose), url)

    def test_page_id_and_selector_have_separate_purposes(self):
        """PAGE IDと配布tupleの元表現を、その用途だけで保存できる。"""
        for number in ("0", "00012", "12345678901234567890"):
            page = BASE + "?idx=" + number
            payload = BASE + "?FILE_INFO=driver|driver_file|driver_idx|" + number + "|driver"
            with self.subTest(number=number):
                self.assertEqual(pl.public_locator_url(
                    page, profile="PUBLIC_PAGE_ID", purpose="PAGE"), page)
                self.assertEqual(pl.public_locator_url(
                    payload, profile="PUBLIC_DRIVER_SELECTOR", purpose="PAYLOAD"), payload)

    def test_profile_purpose_cannot_be_crossed(self):
        """配布URLをHTMLとしてGETする用途へ読み替えない。"""
        for url, profile, purpose in ((PAGE, "PUBLIC_PAGE_ID", "PAYLOAD"),
                                     (PAYLOAD, "PUBLIC_DRIVER_SELECTOR", "PAGE")):
            with self.subTest(profile=profile), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(url, profile=profile, purpose=purpose)

    def test_profile_and_purpose_types_are_closed(self):
        """Boolや未知値・containerをmodeに読み替えない。"""
        for value in (None, True, 1, [], {}, "", "AUTO", "page"):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE, profile=value, purpose="PAGE")
            with self.subTest(purpose=value), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE, profile="QUERYLESS", purpose=value)
        for purpose in ("HEAD", "GET", "LINK", "INSTALL"):
            with self.subTest(purpose=purpose), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE, profile="QUERYLESS", purpose=purpose)

    def test_url_type_and_total_size_are_bounded(self):
        """巨大queryも含めて元URLの上限を検査する。"""
        for value in (None, False, 1, [], b"https://vendor.example.org/file", "", BASE + "a" * 2048):
            with self.subTest(value=type(value)), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(value, profile="QUERYLESS", purpose="PAGE")
        url = "https://vendor.example.org/" + "a" * (2048 - len("https://vendor.example.org/"))
        self.assertEqual(pl.public_locator_url(url, profile="QUERYLESS", purpose="PAGE"), url)
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(url + "?idx=1", profile="PUBLIC_PAGE_ID", purpose="PAGE")

    def test_queryless_and_missing_query_never_fallback(self):
        """不一致profileを自動選択したりqueryを削除したりしない。"""
        for url in (PAGE, PAYLOAD, BASE + "?", BASE + "?id=1"):
            with self.subTest(url=url), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(url, profile="QUERYLESS", purpose="PAGE")
        for profile, purpose in (("PUBLIC_NUMERIC_ID", "PAGE"),
                                 ("PUBLIC_PAGE_ID", "PAGE"),
                                 ("PUBLIC_DRIVER_SELECTOR", "PAYLOAD")):
            for url in (BASE, BASE + "?"):
                with self.subTest(profile=profile, url=url), self.assertRaises(cr.RegistryError):
                    pl.public_locator_url(url, profile=profile, purpose=purpose)

    def test_page_id_rejects_ambiguous_and_encoded_queries(self):
        """複数key、大小文字、escape、token、ASCII以外の数値を拒否する。"""
        queries = ("IDX=1", "id=1", "idx=", "idx=-1", "idx=+1", "idx=１２",
                   "idx=1.0", "idx=123456789012345678901", "idx=%31", "%69dx=1",
                   "idx=1&idx=2", "idx=1&token=fixture", "idx=1;extra=1",
                   "idx=1?extra=1", "idx=1#", "idx=1%250a", "idx=1\n", "idx=1 ",
                   "path=/support", "url=https://example.org/", "authorization=fixture")
        for query in queries:
            with self.subTest(query=query), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE + "?" + query, profile="PUBLIC_PAGE_ID", purpose="PAGE")

    def test_selector_only_accepts_exact_driver_tuple(self):
        """Firmware・任意path・URL・encoded tupleをdriver配布へ読み替えない。"""
        queries = ("FILE_INFO=driver|driver_file|driver_idx|1|firmware",
                   "FILE_INFO=firmware|driver_file|driver_idx|1|driver",
                   "FILE_INFO=driver|other|driver_idx|1|driver",
                   "FILE_INFO=driver|driver_file|id|1|driver",
                   "FILE_INFO=driver|driver_file|driver_idx|1|Driver",
                   "file_info=driver|driver_file|driver_idx|1|driver",
                   "FILE_INFO=driver|driver_file|driver_idx|-1|driver",
                   "FILE_INFO=driver|driver_file|driver_idx|１２|driver",
                   "FILE_INFO=driver|driver_file|driver_idx||driver",
                   "FILE_INFO=driver|driver_file|driver_idx|123456789012345678901|driver",
                   "FILE_INFO=driver%7Cdriver_file%7Cdriver_idx%7C1%7Cdriver",
                   "FILE_INFO=driver|driver_file|driver_idx|1|driver&token=fixture",
                   "FILE_INFO=driver|driver_file|driver_idx|1|driver|other",
                   "FILE_INFO=/path/to/file", "FILE_INFO=https://example.org/",
                   "FILE_INFO=driver|driver_file|driver_idx|1|driver#fragment")
        for query in queries:
            with self.subTest(query=query), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE + "?" + query,
                                      profile="PUBLIC_DRIVER_SELECTOR", purpose="PAYLOAD")

    def test_existing_url_security_checks_remain(self):
        """既存のscheme・auth・private host・port・control拒否を再利用する。"""
        bases = ("http://vendor.example.org/file", "https://127.0.0.1/file", "https://[::1]/file",
                 "https://server.local/file", "https://server.internal/file",
                 "https://localhost.example.org/file", "https://vendor.example.org:444/file",
                 "https://user:fixture@vendor.example.org/file", "https://vendor.example.org/%250a",
                 "https://vendor.example.org/%5cfile", "https://vendor.example.org/file\n",
                 "https://vendor.example.org/file#fragment", "https://vendor.example.org./file")
        for base in bases:
            for profile, query, purpose in (("QUERYLESS", "", "PAGE"),
                                            ("PUBLIC_PAGE_ID", "?idx=1", "PAGE"),
                                            ("PUBLIC_DRIVER_SELECTOR",
                                             "?FILE_INFO=driver|driver_file|driver_idx|1|driver",
                                             "PAYLOAD")):
                with self.subTest(base=base, profile=profile), self.assertRaises(cr.RegistryError):
                    pl.public_locator_url(base + query, profile=profile, purpose=purpose)

    def test_selector_validation_does_not_authorize_old_url_contract(self):
        """新しい保存用検査の成功で旧台帳・既定URL検査を緩めない。"""
        for url in (PAGE, PAYLOAD):
            for mode in (False, True):
                with self.subTest(url=url, mode=mode), self.assertRaises(cr.RegistryError):
                    cr.public_url(url, allow_public_query=mode)

    def test_old_transport_rejects_new_selectors_before_dns(self):
        """既存HTTPへ新しいselectorを渡してもDNS前に拒否する。"""
        for url in (PAGE, PAYLOAD):
            for mode in (False, True):
                for kind in ("PAGE", "LINK"):
                    with self.subTest(url=url, mode=mode, kind=kind), \
                            patch.object(http.subprocess, "run") as run:
                        with self.assertRaises(cr.RegistryError):
                            http.CurlTransport(allow_public_query=mode)(kind, url)
                        run.assert_not_called()

    def test_no_dns_http_or_file_side_effects(self):
        """純粋URL検査は受理・拒否のどちらでも通信・file書込みを呼ばない。"""
        with patch("socket.getaddrinfo") as dns, patch("subprocess.run") as process, \
                patch("builtins.open") as opened:
            self.assertEqual(pl.public_locator_url(
                PAGE, profile="PUBLIC_PAGE_ID", purpose="PAGE"), PAGE)
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(PAYLOAD, profile="PUBLIC_DRIVER_SELECTOR", purpose="PAGE")
            dns.assert_not_called()
            process.assert_not_called()
            opened.assert_not_called()

    def test_error_code_does_not_echo_url(self):
        """拒否codeへURLやquery値を含めない。"""
        with self.assertRaises(cr.RegistryError) as result:
            pl.public_locator_url(BASE + "?idx=1&token=fixture", profile="PUBLIC_PAGE_ID", purpose="PAGE")
        self.assertEqual(str(result.exception), "LOCATOR_QUERY_POLICY")


class LocatorRegistryTests(unittest.TestCase):
    """Sidecarは公開観測の整合性だけを検査し、旧台帳・証拠を変更しない。"""

    def test_valid_safety_counts_and_input_immutability(self):
        """同意待ちURLを保存できるが、取得許可・本体取得件数へ加算しない。"""
        registry, value = locator_fixture()
        before_registry = copy.deepcopy(registry)
        before_value = copy.deepcopy(value)
        normalized = pl.validate_locators(value, registry)
        self.assertEqual(pl.locator_counts(normalized), {
            "pageLocators": 2, "payloadLocators": 1, "payloadRecordReferences": 1,
            "payloadProductReferences": 1, "productRecordEdges": 1, "consentRequiredPayloads": 1,
            "payloadRequestsAuthorized": 0, "publishable": False, "installAuthorized": False})
        self.assertEqual(registry, before_registry)
        self.assertEqual(value, before_value)
        self.assertEqual(cr.research_index(registry)["counts"]["productsWithOfficialLinks"], 0)

    def test_unknown_missing_fields_and_accepted_consent_are_rejected(self):
        """同意済み・credentialをsidecarに混入させず、閉じたfield集合を維持する。"""
        for channel in ("root", "binding", "row", "observation"):
            for action in ("extra", "missing"):
                registry, value = locator_fixture()
                target = {"root": value, "binding": value["registry"], "row": value["locators"][1],
                          "observation": value["locators"][1]["pageObservation"]}[channel]
                if action == "extra":
                    target["accepted"] = True
                else:
                    del target[next(iter(target))]
                with self.subTest(channel=channel, action=action), self.assertRaises(cr.RegistryError):
                    pl.validate_locators(value, registry)

    def test_registry_binding_requires_exact_canonical_content(self):
        """同じrevisionでもsource／製品／配布／観測byteの差替えを拒否する。"""
        for channel in ("schema", "revision", "asOf", "sha256"):
            registry, value = locator_fixture()
            value["registry"][channel] = "different"
            with self.subTest(channel=channel), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)
        registry, value = locator_fixture()
        registry["products"][0]["model"] = "Changed Model"
        with self.assertRaises(cr.RegistryError):
            pl.validate_locators(value, registry)

    def test_safety_flags_are_strict_boolean(self):
        """真偽値の数値代用・公開／導入許可への昇格を拒否する。"""
        for key in ("researchOnly", "publishable", "installAuthorized"):
            for replacement in (0, 1, None, "false", not (key == "researchOnly")):
                registry, value = locator_fixture()
                value[key] = replacement
                with self.subTest(key=key, value=replacement), self.assertRaises(cr.RegistryError):
                    pl.validate_locators(value, registry)

    def test_duplicate_ids_urls_and_references(self):
        """Dedupや上書きで不正な重複を隠さない。"""
        for channel in ("id", "url", "productIds", "recordIds", "parentPageIds"):
            registry, value = locator_fixture()
            if channel in {"id", "url"}:
                duplicate = copy.deepcopy(value["locators"][1])
                if channel == "url":
                    duplicate["id"] = "duplicate-page"
                value["locators"].append(duplicate)
            else:
                value["locators"][2][channel] *= 2
            with self.subTest(channel=channel), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)

    def test_locator_schema_container_and_budget(self):
        """未知schema・不正集合・一回の行数予算超過を拒否する。"""
        for key, replacement in (("schema", "future"), ("revision", ""), ("locators", []),
                                  ("locators", None), ("locators", {})):
            registry, value = locator_fixture()
            value[key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)
        registry, value = locator_fixture()
        with patch.object(pl, "MAX_LOCATORS", 2), self.assertRaises(cr.RegistryError):
            pl.validate_locators(value, registry)

    def test_missing_and_mismatched_registry_references(self):
        """未知source・製品・record、製品にない配布を別対象へ流用しない。"""
        for key in ("sourceId", "productIds", "recordIds"):
            registry, value = locator_fixture()
            value["locators"][1][key] = "missing" if key == "sourceId" else ["missing"]
            with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)

    def test_page_observation_types_status_hash_bytes_and_time(self):
        """未取得・失敗・過大本文・偽hash・未来日時を200実観測へ読み替えない。"""
        cases = (("method", "WEB_REVIEW"), ("httpStatus", True), ("httpStatus", 403),
                 ("bodyBytes", True), ("bodyBytes", 0), ("bodyBytes", pl.MAX_PAGE_BYTES + 1),
                 ("bodySha256", None), ("bodySha256", "invalid"),
                 ("checkedAt", "2026-10-04T00:00:00Z"), ("checkedAt", "invalid"))
        for key, replacement in cases:
            registry, value = locator_fixture()
            value["locators"][1]["pageObservation"][key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)

    def test_root_url_and_original_observation_binding(self):
        """Deepのhashや未登録URLを公式起点の実観測へ転用しない。"""
        for key, replacement in (("url", BASE), ("bodySha256", "c" * 64),
                                  ("checkedAt", "2026-10-01T00:00:00Z")):
            registry, value = locator_fixture()
            target = value["locators"][0] if key == "url" else value["locators"][0]["pageObservation"]
            target[key] = replacement
            with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)

    def test_missing_parent_wrong_purpose_and_self_reference(self):
        """欠損・PAYLOAD親・自己参照をPAGEの根拠へ採用しない。"""
        for parent in ("missing", "payload-one", "page-one"):
            registry, value = locator_fixture()
            value["locators"][1]["parentPageIds"] = [parent]
            with self.subTest(parent=parent), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)

    def test_page_cycles_and_depth_are_bounded(self):
        """相互循環と8段階を超えるpage chainを有限に拒否する。"""
        registry, value = locator_fixture()
        sibling = {**copy.deepcopy(value["locators"][1]), "id": "page-two", "url": BASE + "?idx=2",
                   "parentPageIds": ["page-one"]}
        value["locators"][1]["parentPageIds"] = ["page-two"]
        value["locators"].append(sibling)
        with self.assertRaises(cr.RegistryError) as cycle:
            pl.validate_locators(value, registry)
        self.assertEqual(str(cycle.exception), "LOCATOR_PAGE_CYCLE")
        registry, value = locator_fixture()
        parent = "page-one"
        for number in range(2, pl.MAX_PAGE_DEPTH + 1):
            page = {**copy.deepcopy(value["locators"][1]), "id": f"page-{number}",
                    "url": BASE + f"?idx={number}", "parentPageIds": [parent]}
            value["locators"].append(page)
            parent = page["id"]
        with self.assertRaises(cr.RegistryError) as depth:
            pl.validate_locators(value, registry)
        self.assertEqual(str(depth.exception), "LOCATOR_PAGE_DEPTH")

    def test_foreign_source_page_and_record_cannot_supply_evidence(self):
        """複数sourceへ属する製品でも、別sourceのpage・record根拠を借用しない。"""
        for channel in ("page", "payload"):
            registry, value = locator_fixture()
            source = {**registry["sources"][0], "id": "source-two",
                      "officialPage": "https://other.example.org/drivers"}
            registry["sources"].append(source)
            registry["products"][0]["sourceIds"].append(source["id"])
            registry["observations"].append({**registry["observations"][0], "id": "other-observation",
                                             "recordId": None, "evidenceUrl": source["officialPage"]})
            value["registry"] = pl.registry_binding(cr.validate_registry(registry))
            if channel == "page":
                other_root = {**copy.deepcopy(value["locators"][0]), "id": "root-two",
                              "sourceId": source["id"], "url": source["officialPage"]}
                value["locators"].append(other_root)
                value["locators"][1]["parentPageIds"] = [other_root["id"]]
            else:
                value["locators"][2]["sourceId"] = source["id"]
            with self.subTest(channel=channel), self.assertRaises(cr.RegistryError) as result:
                pl.validate_locators(value, registry)
            self.assertEqual(str(result.exception), "LOCATOR_PARENT_SOURCE_OR_PURPOSE"
                             if channel == "page" else "LOCATOR_RECORD_SOURCE")

    def test_page_parent_count_and_payload_record_count_are_closed(self):
        """複数親のPAGEや複数recordのPAYLOADを暗黙に一つへまとめない。"""
        registry, value = locator_fixture()
        value["locators"][1]["parentPageIds"] = ["root-one", "page-other"]
        with self.assertRaises(cr.RegistryError) as page:
            pl.validate_locators(value, registry)
        self.assertEqual(str(page.exception), "LOCATOR_PAGE_PARENTS")
        registry, value = locator_fixture()
        second_record = {**registry["records"][0], "id": "record-two"}
        registry["records"].append(second_record)
        registry["products"][0]["recordIds"].append(second_record["id"])
        registry["observations"].append({**registry["observations"][0], "id": "record-two-observation",
                                         "recordId": second_record["id"]})
        value["registry"] = pl.registry_binding(cr.validate_registry(registry))
        value["locators"][2]["recordIds"].append(second_record["id"])
        with self.assertRaises(cr.RegistryError) as payload:
            pl.validate_locators(value, registry)
        self.assertEqual(str(payload.exception), "LOCATOR_PAYLOAD_REFERENCES")

    def test_payload_needs_exact_record_and_real_page_references(self):
        """同意待ち配布にも対応record・掲載pageが必要であり、root一覧だけを借用しない。"""
        for key, replacement in (("recordIds", []), ("parentPageIds", []),
                                  ("parentPageIds", ["root-one"]),
                                  ("pageObservation", {"bodySha256": "a" * 64})):
            registry, value = locator_fixture()
            value["locators"][2][key] = replacement
            with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)

    def test_page_product_scope_and_payload_union(self):
        """親にない製品を子pageへ増やしたり、配布の一部製品根拠を省略したりしない。"""
        registry, value = locator_fixture()
        registry["products"].append({**registry["products"][0], "id": "product-two", "model": "Device Two"})
        registry["observations"].append({**registry["observations"][0], "id": "page-two-observation",
                                         "productId": "product-two"})
        value["registry"] = pl.registry_binding(cr.validate_registry(registry))
        value["locators"][1]["productIds"].append("product-two")
        with self.assertRaises(cr.RegistryError) as page:
            pl.validate_locators(value, registry)
        self.assertEqual(str(page.exception), "LOCATOR_PAGE_PRODUCTS")
        registry, value = locator_fixture()
        registry["products"].append({**registry["products"][0], "id": "product-two", "model": "Device Two"})
        registry["observations"].append({**registry["observations"][0], "id": "page-two-observation",
                                         "productId": "product-two"})
        value["registry"] = pl.registry_binding(cr.validate_registry(registry))
        value["locators"][2]["productIds"].append("product-two")
        with self.assertRaises(cr.RegistryError) as payload:
            pl.validate_locators(value, registry)
        self.assertEqual(str(payload.exception), "LOCATOR_PAYLOAD_PRODUCTS")

    def test_condition_enums_never_store_accepted_permission(self):
        """同意済みや未知条件を研究用sidecarへ保存しない。"""
        for row_index, key, replacement in ((1, "requestCondition", "CONSENT_REQUIRED"),
                                            (2, "requestCondition", "ACCEPTED"),
                                            (2, "requestCondition", None),
                                            (2, "requestCondition", []),
                                            (2, "publicationCondition", "APPROVED"),
                                            (2, "publicationCondition", {})):
            registry, value = locator_fixture()
            value["locators"][row_index][key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(cr.RegistryError):
                pl.validate_locators(value, registry)
        for condition in pl.PAYLOAD_CONDITIONS:
            registry, value = locator_fixture()
            value["locators"][2]["requestCondition"] = condition
            self.assertEqual(pl.locator_counts(pl.validate_locators(value, registry))["payloadRequestsAuthorized"], 0)

    def test_existing_record_url_cannot_be_retargeted(self):
        """既存の非null URLをsidecar経由で別配布へ差し替えない。"""
        registry, value = locator_fixture()
        registry["records"][0].update(downloadUrl="https://cdn.example.org/driver.zip", linkState="OFFICIAL_LINK")
        registry["observations"][0]["kind"] = "OFFICIAL_LINK"
        value["registry"] = pl.registry_binding(cr.validate_registry(registry))
        with self.assertRaises(cr.RegistryError) as changed:
            pl.validate_locators(value, registry)
        self.assertEqual(str(changed.exception), "LOCATOR_EXISTING_URL")

    def test_canonical_sorting_and_file_copy_revalidation(self):
        """順序を正規化し、file copy後も元台帳binding付きで同じbyteを検証できる。"""
        registry, value = locator_fixture()
        expected = cr.json_bytes(pl.validate_locators(value, registry))
        value["locators"].reverse()
        self.assertEqual(cr.json_bytes(pl.validate_locators(value, registry)), expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "registry.json").write_bytes(cr.json_bytes(registry))
            (root / "locators.json").write_bytes(expected)
            copied = root / "copied"
            copied.mkdir()
            shutil.copy2(root / "registry.json", copied / "registry.json")
            shutil.copy2(root / "locators.json", copied / "locators.json")
            observed = pl.validate_locators(cr.read_json(copied / "locators.json"),
                                            cr.read_json(copied / "registry.json"))
            self.assertEqual(cr.json_bytes(observed), expected)

    def test_sidecar_cli_summary_and_redacted_rejection(self):
        """CLIはURL・pathを出さず、非通信の件数とhashまたは拒否codeを返す。"""
        registry, value = locator_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            locators_path = root / "locators.json"
            registry_path.write_bytes(cr.json_bytes(registry))
            locators_path.write_bytes(cr.json_bytes(value))
            argv = ["collector_public_locators", "--registry", str(registry_path),
                    "--locators", str(locators_path)]
            output = io.StringIO()
            with patch("sys.argv", argv), contextlib.redirect_stdout(output), \
                    patch("subprocess.run") as network:
                self.assertEqual(pl.main(), 0)
                network.assert_not_called()
            summary = cr.parse_json(output.getvalue().encode("utf-8"))
            self.assertEqual(summary["counts"]["payloadLocators"], 1)
            self.assertNotIn("https://", output.getvalue())
            self.assertNotIn(str(root), output.getvalue())
            value["locators"][2]["url"] += "&token=fixture"
            locators_path.write_bytes(cr.json_bytes(value))
            error = io.StringIO()
            with patch("sys.argv", argv), contextlib.redirect_stderr(error):
                self.assertEqual(pl.main(), 2)
            self.assertEqual(error.getvalue(), "REJECTED:LOCATOR_QUERY_POLICY\n")

    def test_bounded_json_and_side_effect_free_registry_validation(self):
        """正規出力にもbyte上限を適用し、検証関数は通信・file I/Oを行わない。"""
        registry, value = locator_fixture()
        with patch.object(cr, "MAX_JSON_BYTES", 10), self.assertRaises(cr.RegistryError):
            pl.validate_locators(value, registry)
        with patch("socket.getaddrinfo") as dns, patch("subprocess.run") as network, \
                patch("builtins.open") as opened:
            pl.validate_locators(value, registry)
            dns.assert_not_called()
            network.assert_not_called()
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
