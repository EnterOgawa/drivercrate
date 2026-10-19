"""公開数字selector・リンク観測・接続情報の非通信試験（ADR 0292）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公開ID・HTTP・時計を使い、本体取得・同意・導入は実行しない。
"""
import base64
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_public_locators as pl
import collector_locator_connections as cc
import collector_locator_snapshot as cs
import registry_daily_monitor as dm
import registry_locator_requests as lr
import registry_monitor_http as http
from test_collector_public_locators import locator_fixture


PREFIX = 'https://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do?'
URL = PREFIX + 'id=' + base64.b64encode(b'00012').decode('ascii') + '&cmp=ACB&lang=EN'


def fixture():
    """既存の架空graphのPAYLOADを公開数字selectorへ置き換える。"""
    registry, locators = locator_fixture()
    payload = next(row for row in locators['locators'] if row['purpose'] == 'PAYLOAD')
    payload.update(url=URL, urlProfile='CANON_PUBLIC_FILE_ID')
    return registry, pl.validate_locators(locators, registry)


class LocatorConnectionTests(unittest.TestCase):
    """新profileも既存graph・待機・用途・非許可境界へ従うことを検査する。"""

    def setUp(self):
        """各試験を独立した架空世代へ結合する。"""
        self.registry, self.locators = fixture()

    def rejected_url(self, url, purpose='PAYLOAD'):
        """不正URLまたは用途が通信前に拒否されることを確認する。"""
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(url, profile='CANON_PUBLIC_FILE_ID', purpose=purpose)

    def test_01_exact_public_encoding(self):
        """公開数字の先頭ゼロと元URLを保持する。"""
        self.assertEqual(pl.public_locator_url(URL, profile='CANON_PUBLIC_FILE_ID', purpose='PAYLOAD'), URL)

    def test_02_page_purpose(self):
        """本体selectorをPAGE GETへ読み替えない。"""
        self.rejected_url(URL, 'PAGE')

    def test_03_host(self):
        """任意hostへ公開selectorを委譲しない。"""
        self.rejected_url(URL.replace('pdisp01.c-wss.com', 'vendor.example.org'))

    def test_04_path(self):
        """別pathへ同じquery規則を適用しない。"""
        self.rejected_url(URL.replace('WWUFORedirectTarget.do', 'other.do'))

    def test_05_extra_query(self):
        """余分な認証queryを拒否する。"""
        self.rejected_url(URL + '&token=DO_NOT_SAVE')

    def test_06_duplicate_query(self):
        """重複keyを正規化して受理しない。"""
        self.rejected_url(URL + '&lang=EN')

    def test_07_different_region(self):
        """固定地域・言語を別値へ変換しない。"""
        self.rejected_url(URL.replace('cmp=ACB', 'cmp=OTHER'))
        self.rejected_url(URL.replace('lang=EN', 'lang=JA'))

    def test_08_non_numeric_base64(self):
        """認証文字列に見える値は数字公開IDへ昇格しない。"""
        self.rejected_url(PREFIX + 'id=dG9rZW4=&cmp=ACB&lang=EN')

    def test_09_oversized_id(self):
        """一回の公開ID長を制限する。"""
        self.rejected_url(PREFIX + 'id=' + base64.b64encode(b'1' * 21).decode() + '&cmp=ACB&lang=EN')

    def test_10_malformed_base64(self):
        """不完全なbase64を補完して受理しない。"""
        self.rejected_url(PREFIX + 'id=MDE&cmp=ACB&lang=EN')

    def test_11_reordered_keys(self):
        """Queryを並べ替えて受理しない。"""
        self.rejected_url(PREFIX + 'cmp=ACB&id=MDEy&lang=EN')

    def test_12_fragment(self):
        """Fragmentを除去して保存しない。"""
        self.rejected_url(URL + '#file')

    def test_13_common_registry_still_rejects(self):
        """共通台帳URLの一般query許可を広げない。"""
        with self.assertRaises(cr.RegistryError):
            cr.public_url(URL, allow_public_query=True, purpose='PAYLOAD')

    def test_14_old_graph_unchanged(self):
        """既存四profileのgraphが同じ正規byteへ戻る。"""
        registry, locators = locator_fixture()
        self.assertEqual(pl.validate_locators(locators, registry)['locators'],
            sorted(locators['locators'], key=lambda row: row['id']))

    def test_15_data_url(self):
        """登録されたdata-urlからURL hashだけを観測する。"""
        parser = http.PageLinks('https://vendor.example.org/', registered_links={URL: ('CANON_PUBLIC_FILE_ID', 'PAYLOAD')})
        parser.feed('<button data-url="' + URL.replace('&', '&amp;') + '">Download</button>')
        self.assertEqual(parser.links, {cr.digest(URL.encode())})

    def test_16_unregistered_selector_ignored(self):
        """未登録queryのdata-urlを許可しない。"""
        parser = http.PageLinks('https://vendor.example.org/')
        parser.feed('<div data-url="' + URL + '"></div>')
        self.assertEqual(parser.links, set())

    def test_17_literal_onclick(self):
        """定数onclickは実行せずURLを読み取る。"""
        value = "window.location='https://vendor.example.org/file.zip'; return false;"
        self.assertEqual(http.literal_navigation_url(value), 'https://vendor.example.org/file.zip')

    def test_18_dynamic_handler_rejected(self):
        """変数・連結・余分なstatementを評価しない。"""
        for value in ("window.location=url; return false;", "window.location='https://vendor.example.org/' + name; return false;",
            "window.location='https://vendor.example.org/'; accept(); return false;", "fetch('https://vendor.example.org/')"):
            self.assertIsNone(http.literal_navigation_url(value))

    def test_19_onclick_observation(self):
        """単純なpublic URLだけを共通link hashへ接続する。"""
        parser = http.PageLinks('https://vendor.example.org/')
        parser.feed('<a onclick="window.location=\'https://vendor.example.org/file.zip\'; return false;">Download</a>')
        self.assertEqual(parser.links, {cr.digest(b'https://vendor.example.org/file.zip')})

    def test_20_payload_requests_blocked(self):
        """同意待ちのPAGE／LINK要求は子process起動前に拒否する。"""
        transport = http.CurlTransport(registry=self.registry, public_locators=self.locators)
        with patch('registry_monitor_http.subprocess.run') as process:
            for kind in ('PAGE', 'LINK'):
                with self.assertRaises(cr.RegistryError):
                    transport(kind, URL)
            process.assert_not_called()

    def test_21_request_hold(self):
        """要求生成に接続しても同意待ちを維持する。"""
        policy = dict(schema='dc-registry-monitor-policy-v1', revision='fixture', heldSourceIds=[])
        requests = lr.locator_requests(self.registry, self.locators, policy, dm.make_requests(self.registry, policy))
        payload = next(row for row in requests if row['url'] == URL)
        self.assertTrue(payload['held'])
        self.assertEqual(payload['holdReason'], 'CONSENT_REQUIRED')

    def test_22_connections(self):
        """所在と取得／端末適合を別状態へ結合する。"""
        value = cc.connection_index(self.registry, self.locators)
        self.assertEqual(value['counts']['recordsWithAnyPublicReference'], 1)
        self.assertEqual(value['counts']['recordsWithDirectUrls'], 0)
        self.assertFalse(value['records'][0]['contentVerified'])
        self.assertFalse(value['installAuthorized'])

    def test_23_multiple_variants(self):
        """同recordの複数variantを勝手に一つへ選ばない。"""
        payload = deepcopy(next(row for row in self.locators['locators'] if row['purpose'] == 'PAYLOAD'))
        payload.update(id='second-choice', url='https://vendor.example.org/other.zip', urlProfile='QUERYLESS')
        self.locators['locators'].append(payload)
        value = cc.connection_index(self.registry, self.locators)
        self.assertEqual(len(value['records'][0]['publicLocatorChoices']), 2)
        self.assertEqual(value['counts']['recordsWithMultipleLocatorChoices'], 1)

    def test_24_stale_connection(self):
        """元世代hashの不一致を拒否する。"""
        value = cc.connection_index(self.registry, self.locators)
        value['registrySha256'] = '0' * 64
        with self.assertRaises(cr.RegistryError):
            cc.validate_connections(value, self.registry, self.locators)

    def test_25_unauthorized_connection(self):
        """接続情報から導入許可を発行しない。"""
        value = cc.connection_index(self.registry, self.locators)
        value['records'][0]['installAuthorized'] = True
        with self.assertRaises(cr.RegistryError):
            cc.validate_connections(value, self.registry, self.locators)

    def test_26_unknown_connection_field(self):
        """未知fieldを含む接続情報を拒否する。"""
        value = cc.connection_index(self.registry, self.locators)
        value['extra'] = True
        with self.assertRaises(cr.RegistryError):
            cc.validate_connections(value, self.registry, self.locators)

    def test_27_input_immutable(self):
        """入力台帳・locatorを変更しない。"""
        before = deepcopy((self.registry, self.locators))
        cc.connection_index(self.registry, self.locators)
        self.assertEqual(before, (self.registry, self.locators))

    def test_28_snapshot_copy(self):
        """新profileを共通snapshot v4へ結合し、再読込みで同じ値へ戻す。"""
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'snapshot'
            cs.write_snapshot(self.registry, self.locators, output)
            registry, locators, evidence = cs.verify_snapshot(output)
            self.assertEqual((registry, locators, evidence), (cr.validate_registry(self.registry), self.locators, None))

    def test_29_finite_monitor_no_payload(self):
        """架空日次監視が保留selectorへ通信しない。"""
        calls = []
        def fake(kind, url):
            """架空pageの観測だけを返す。"""
            calls.append((kind, url))
            return http.response(200, body=b'<html>fixture</html>', links=[cr.digest(URL.encode())])
        policy = dict(schema='dc-registry-monitor-policy-v1', revision='fixture', heldSourceIds=[])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'monitor'
            now = datetime(2026, 10, 4)
            dm.initialize(root, clock=lambda: now)
            dm.run_once(self.registry, policy, root, transport=fake, clock=lambda: now,
                public_locators=self.locators)
        self.assertTrue(calls)
        self.assertTrue(all(kind == 'PAGE' and url != URL for kind, url in calls))


if __name__ == '__main__':
    unittest.main()
