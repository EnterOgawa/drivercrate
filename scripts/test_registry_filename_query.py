"""公開本体basenameの保存と自動通信拒否を検証する（ADR 0324）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空URLと偽processだけを使用し、network・installer・導入を実行しない。
"""
import copy
import unittest
from unittest.mock import patch
import collector_registry as cr
import collector_public_locators as pl
import collector_payload_evidence as pe
import collector_locator_snapshot as ls
import registry_monitor_http as http
from test_registry_file_query import carry_fixture, NEW_TIME
from test_collector_registry import fixture

URL = "https://vendor.example.org/api/downloadFile?fileName=DRIVER_1-2.ZIP"


class FilenameQueryTests(unittest.TestCase):
    """許可用途と旧APIを閉じ、公式根拠や同意を構文から推定しない。"""

    def test_explicit_payload_only(self):
        """ASCII basenameだけを明示PAYLOADへ保存できる。"""
        for name in ("D.ZIP", "DRIVER_1-2.ZIP", "a" * 100 + ".zip", "a.12345678"):
            url = URL.rsplit("=", 1)[0] + "=" + name
            self.assertEqual(cr.public_url(url, allow_public_query=True, purpose="PAYLOAD"), url)
            for mode, purpose in ((False, "PAYLOAD"), (True, "PAGE"), (False, "PAGE")):
                with self.subTest(name=name, mode=mode, purpose=purpose), self.assertRaises(cr.RegistryError):
                    cr.public_url(url, allow_public_query=mode, purpose=purpose)

    def test_query_boundaries(self):
        """Path・encoding・複数key・認証名とbasename上限を拒否する。"""
        for query in ("fileName=", "filename=A.ZIP", "fileName=.ZIP", "fileName=A",
                      "fileName=A..ZIP", "fileName=A.B.ZIP", "fileName=../A.ZIP",
                      "fileName=/A.ZIP", "fileName=A\\B.ZIP", "fileName=A+X.ZIP",
                      "fileName=A%2eZIP", "%66ileName=A.ZIP", "fileName=A.ZIP&fileName=B.ZIP",
                      "fileName=A.ZIP&id=1", "fileName=A.ZIP;token=1", "token=A.ZIP",
                      "fileName=Ａ.ZIP", "fileName=" + "a" * 101 + ".ZIP",
                      "fileName=A.123456789", "fileName=A.ZIP#fragment"):
            with self.subTest(query=query), self.assertRaises(cr.RegistryError):
                cr.public_url(URL.partition("?")[0] + "?" + query,
                              allow_public_query=True, purpose="PAYLOAD")

    def test_numeric_api_and_locator_stay_numeric(self):
        """数値profileをfilenameへ流用できない。"""
        self.assertFalse(cr.public_numeric_query("fileName=A.ZIP", purpose="PAYLOAD"))
        self.assertTrue(cr.public_numeric_query("file=0005", purpose="PAYLOAD"))
        with self.assertRaisesRegex(cr.RegistryError, "LOCATOR_QUERY_POLICY"):
            pl.public_locator_url(URL, profile="PUBLIC_NUMERIC_ID", purpose="PAYLOAD")

    def test_old_transport_refuses_filename_before_dns(self):
        """新しく保存可能なURLを旧自動HEAD／PAGEで要求しない。"""
        for kind in ("PAGE", "LINK"):
            for mode in (False, True):
                with self.subTest(kind=kind, mode=mode), patch.object(http.subprocess, "run") as called:
                    with self.assertRaises(cr.RegistryError):
                        http.CurlTransport(allow_public_query=mode)(kind, URL)
                    called.assert_not_called()

    def test_url_security_and_types(self):
        """HTTPS・host・認証・制御文字と用途型の元境界を保持する。"""
        for base in ("http://vendor.example.org/file", "https://127.0.0.1/file",
                     "https://server.local/file", "https://user:fixture@vendor.example.org/file",
                     "https://vendor.example.org/%250a", "https://vendor.example.org/%5cfile"):
            with self.subTest(base=base), self.assertRaises(cr.RegistryError):
                cr.public_url(base + "?fileName=A.ZIP", allow_public_query=True, purpose="PAYLOAD")
        for purpose in (None, True, 1, [], "LINK", "payload"):
            with self.subTest(purpose=purpose), self.assertRaisesRegex(cr.RegistryError, "URL_PURPOSE"):
                cr.public_payload_basename_query("fileName=A.ZIP", purpose=purpose)
        for query in (None, 1, True, []):
            with self.subTest(query=query), self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_TYPE"):
                cr.public_payload_basename_query(query, purpose="PAYLOAD")

    def test_registry_and_explicit_missing_enrichment(self):
        """MISSINGのURLだけを補完し、既定拒否と全旧証拠を保持する。"""
        old, locators, observed, new = carry_fixture()
        new["records"][1]["downloadUrl"] = URL
        self.assertEqual(cr.validate_registry(new)["records"][1]["downloadUrl"], URL)
        with self.assertRaises(cr.RegistryError):
            pe.carry_forward(old, observed, new)
        carried = pe.carry_forward(old, observed, new, allow_link_enrichment=True)
        self.assertEqual([{k: v for k, v in row.items() if k != "recordSha256"}
                          for row in carried["acquisitions"]], observed["acquisitions"])
        self.assertEqual(carried["acquisitions"][0]["recordSha256"],
                         cr.digest(cr.json_bytes(old["records"][0])))
        after = ls.carry_forward_locators(old, locators, new, revision="locators-filename",
            as_of=NEW_TIME, allow_link_enrichment=True, old_evidence=observed)
        self.assertEqual(after["locators"], locators["locators"])
        for target in ("source", "v1"):
            invalid = copy.deepcopy(new)
            if target == "source":
                invalid["sources"][0]["officialPage"] = URL
            else:
                invalid["schema"] = cr.REGISTRY_SCHEMA
            with self.subTest(target=target), self.assertRaises(cr.RegistryError):
                cr.validate_registry(invalid)


if __name__ == "__main__":
    unittest.main()
