"""公開pidのPAGE専用profile・初回mapと共通HTTP拒否境界（ADR 0300）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空URL／偽応答だけを使い、実network・保護store・導入を呼ばない。
"""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import collector_public_locators as pl
import collector_registry as cr
import registry_monitor_http as http
from test_collector_public_locators import locator_fixture
from test_common_page_routes import FIXTURE_CURL, assert_http_process

ROOT = 'https://vendor.example.org/'
PAGE = ROOT + 'product.php?pid=000483'


def mapped(url=PAGE, root=ROOT):
    """同一rootの明示PAGEだけを初回mapへ登録する。"""
    return http.CurlTransport(research_page_profiles={url: ('PUBLIC_PRODUCT_PID', root)})


class ProductPidTests(unittest.TestCase):
    """新profileを旧URLやPAYLOADの全般許可へ拡張しない。"""

    def test_exact_pid_keeps_zeros(self):
        for number in ('0', '000483', '9' * 20):
            value = ROOT + 'product.php?pid=' + number
            self.assertEqual(pl.public_locator_url(value, profile='PUBLIC_PRODUCT_PID', purpose='PAGE'), value)

    def test_payload_purpose_rejected(self):
        with self.assertRaisesRegex(cr.RegistryError, 'LOCATOR_PROFILE_PURPOSE'):
            pl.public_locator_url(PAGE, profile='PUBLIC_PRODUCT_PID', purpose='PAYLOAD')

    def test_old_numeric_predicate_not_changed(self):
        self.assertFalse(cr.public_numeric_query('pid=483', purpose='PAGE'))
        with self.assertRaises(cr.RegistryError):
            cr.public_url(PAGE, allow_public_query=True)
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(PAGE, profile='PUBLIC_NUMERIC_ID', purpose='PAGE')

    def test_query_and_key_variations_rejected(self):
        for value in ('pid=', 'pid=-1', 'pid=+1', 'pid=1.0', 'pid=１２', 'PID=1', 'pid=1&cid=2',
                'pid=1&pid=2', 'pid=1;pid=2', 'pid=1 2', 'pid=' + '1' * 21, '%70id=1', 'pid=%31'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(ROOT + 'product.php?' + value, profile='PUBLIC_PRODUCT_PID', purpose='PAGE')

    def test_fragment_private_and_control_rejected(self):
        for value in (PAGE + '#', PAGE + '#x', PAGE + '\n', PAGE.replace('pid=000483', 'pid=1&access_token=x'),
                'https://127.0.0.1/product.php?pid=1', 'https://user@vendor.example.org/product.php?pid=1'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(value, profile='PUBLIC_PRODUCT_PID', purpose='PAGE')

    def test_unknown_profile_rejected(self):
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(PAGE, profile='PUBLIC_PID_UNCHECKED', purpose='PAGE')

    def test_common_parser_observes_registered_only(self):
        parser = http.PageLinks(ROOT, registered_links={PAGE: ('PUBLIC_PRODUCT_PID', 'PAGE')})
        parser.feed('<html><a href="' + PAGE + '">one</a><a href="product.php?pid=999">unknown</a></html>')
        self.assertEqual(parser.links, {cr.digest(PAGE.encode())})
        self.assertFalse(parser.derived_links)

    def test_map_does_not_create_observation(self):
        transport = mapped()
        self.assertEqual(transport.registered_links, {PAGE: ('PUBLIC_PRODUCT_PID', 'PAGE')})
        self.assertFalse(transport.last_finished)
        self.assertFalse(transport.registry_bound)

    def test_map_size_and_type_rejected(self):
        for value in ({}, [], False, {ROOT + f'product.php?pid={i}': ('PUBLIC_PRODUCT_PID', ROOT)
                for i in range(17)}):
            with self.assertRaises(cr.RegistryError):
                http.CurlTransport(research_page_profiles=value)

    def test_map_spec_and_profile_rejected(self):
        for spec in (('PUBLIC_NUMERIC_ID', ROOT), ['PUBLIC_PRODUCT_PID', ROOT], ('PUBLIC_PRODUCT_PID',),
                ('PUBLIC_PRODUCT_PID', ROOT, 'unused')):
            with self.assertRaises(cr.RegistryError):
                http.CurlTransport(research_page_profiles={PAGE: spec})

    def test_map_cross_origin_rejected(self):
        for root in ('https://other.example.org/', ROOT + '?id=1', 'http://vendor.example.org/',
                'https://vendor.local/'):
            with self.assertRaises(cr.RegistryError):
                mapped(root=root)

    def test_map_registry_modes_not_mixed(self):
        registry, locators = locator_fixture()
        for options in (dict(registry=registry), dict(registry=registry, public_locators=locators),
                dict(held_source_ids=('source-one',))):
            with self.assertRaises(cr.RegistryError):
                http.CurlTransport(research_page_profiles={PAGE: ('PUBLIC_PRODUCT_PID', ROOT)}, **options)

    def test_payload_suffix_map_rejected(self):
        for suffix in ('zip', 'rar', 'inf', 'sys', 'cat', 'dll', '%72%61%72', '%69nf'):
            with self.assertRaisesRegex(cr.RegistryError, 'PAGE_PAYLOAD_ENDPOINT'):
                mapped(ROOT + 'driver.' + suffix + '?pid=1')

    def test_payload_root_rejected(self):
        for suffix in ('rar', 'inf', 'sys'):
            with self.assertRaisesRegex(cr.RegistryError, 'PAGE_PAYLOAD_ENDPOINT'):
                mapped(root=ROOT + 'driver.' + suffix)

    def test_map_link_head_rejected_before_network(self):
        with patch('subprocess.run') as run:
            with self.assertRaisesRegex(cr.RegistryError, 'LOCATOR_REQUEST_PURPOSE'):
                mapped()('LINK', PAGE)
            run.assert_not_called()

    def test_unmapped_pid_rejected_before_network(self):
        with patch('subprocess.run') as run:
            with self.assertRaises(cr.RegistryError):
                mapped()('PAGE', ROOT + 'product.php?pid=999')
            run.assert_not_called()

    def test_initial_page_uses_common_html_and_limits(self):
        calls = []

        def fake(args, **options):
            """正確なroute/curl呼出しだけへ架空結果を返し、subprocessを実行しない。"""
            calls.append(args)
            if assert_http_process(self, args, options, kind='PAGE', url=PAGE):
                return subprocess.CompletedProcess(args, 0,
                    json.dumps({'route': {'source': 'SYSTEM', 'proxy': ''}, 'addresses': ['8.8.8.8']}).encode(), b'')
            Path(args[args.index('--output') + 1]).write_bytes(b'<html>public product</html>')
            Path(args[args.index('--dump-header') + 1]).write_bytes(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n')
            return subprocess.CompletedProcess(args, 0, b'200', b'')

        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                patch('subprocess.run', side_effect=fake):
            response = mapped()('PAGE', PAGE)
        self.assertEqual(response['status'], 200)
        self.assertEqual(response['error'], 'NONE')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][-1], PAGE)
        self.assertIn('--max-filesize', calls[1])
        self.assertNotIn('--head', calls[1])

    def test_dns_failure_does_not_retry_or_claim_success(self):
        def fake(args, **options):
            """正確なroute呼出しへ明示PRIVATE_DNSを返し、curlへ進ませない。"""
            self.assertTrue(assert_http_process(self, args, options, kind='PAGE', url=PAGE))
            return subprocess.CompletedProcess(args, 2, b'{"error":"PRIVATE_DNS"}', b'')
        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                patch('subprocess.run', side_effect=fake) as run:
            result = mapped()('PAGE', PAGE)
        self.assertEqual(result['error'], 'PRIVATE_DNS')
        self.assertEqual(run.call_count, 1)
        self.assertIsNone(result['bodySha256'])

    def test_empty_nonzero_dns_stdout_reports_dns_failed(self):
        """空の失敗応答はDNS_FAILEDとし、一回のrouteだけで本文hashを残さない。"""
        def fake(args, **options):
            """正確なroute呼出しへ空の失敗応答だけを返す。"""
            self.assertTrue(assert_http_process(self, args, options, kind='PAGE', url=PAGE))
            return subprocess.CompletedProcess(args, 2, b'', b'')
        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                patch('subprocess.run', side_effect=fake) as run:
            result = mapped()('PAGE', PAGE)
        self.assertEqual(result['error'], 'DNS_FAILED')
        self.assertEqual(run.call_count, 1)
        self.assertIsNone(result['bodySha256'])


if __name__ == '__main__':
    unittest.main()
