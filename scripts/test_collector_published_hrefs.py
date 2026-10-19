"""掲載pathの空白導出・共通parserと日次偽transportの非通信回帰（ADR 0299）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公開URLとtemporary directoryだけを使い、network／導入を呼ばない。
"""
from datetime import datetime
from html import escape
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collector_published_hrefs as h
import collector_public_locators as pl
import collector_registry as cr
import registry_daily_monitor as dm
import registry_monitor_http as http
from test_collector_public_locators import locator_fixture

BASE = 'https://vendor.example.org/downloads/'
RAW = BASE + 'driver Windows 10 x64.zip'
WIRE = RAW.replace(' ', '%20')


class PublishedHrefTests(unittest.TestCase):
    """path以外の変更・権限昇格とurljoinのcontrol除去を許可しない。"""

    def test_absolute_path_space(self):
        self.assertEqual(h.path_space_url(RAW), WIRE)
        self.assertEqual(cr.public_url(WIRE), WIRE)
        with self.assertRaises(cr.RegistryError):
            cr.public_url(RAW)

    def test_relative_resolution(self):
        self.assertEqual(h.resolve_published_href(BASE, 'driver Windows 10 x64.zip'), (RAW, WIRE))

    def test_existing_percent20_idempotent(self):
        self.assertEqual(h.path_space_url(WIRE), WIRE)
        self.assertEqual(h.resolve_published_href(BASE, WIRE), (WIRE, WIRE))

    def test_percent_triplets_not_reencoded(self):
        value = BASE + 'already%20encoded and%2Bplus.zip'
        self.assertEqual(h.path_space_url(value), BASE + 'already%20encoded%20and%2Bplus.zip')

    def test_authority_space_rejected(self):
        for value in ('https://vendor .example.org/a b.zip', 'https:// vendor.example.org/a b.zip'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(value)

    def test_any_query_with_space_path_rejected(self):
        for tail in ('?id=123', '?id=1 23', '?', '?access_token=sample'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(RAW + tail)

    def test_fragment_with_space_path_rejected(self):
        for tail in ('#', '#info'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(RAW + tail)

    def test_controls_and_non_ascii_whitespace_rejected(self):
        for char in ('\r', '\n', '\t', '\x00', '\x1f', '\x7f', '\u00a0', '\u3000'):
            with self.assertRaises(cr.RegistryError):
                h.resolve_published_href(BASE, 'a' + char + 'b.zip')

    def test_leading_space_not_trimmed(self):
        for value in (' ' + RAW, '\t' + RAW, '\n' + RAW):
            with self.assertRaises(cr.RegistryError):
                h.resolve_published_href(BASE, value)

    def test_non_public_hosts_and_userinfo_rejected(self):
        for value in ('https://127.0.0.1/a b.zip', 'https://vendor.local/a b.zip',
                'https://localhost.example.org/a b.zip', 'https://user@vendor.example.org/a b.zip',
                'https://vendor.example.org:444/a b.zip'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(value)

    def test_encoded_control_and_backslash_rejected(self):
        for tail in ('a%0Ab c.zip', 'a%09b c.zip', 'a%5Cb c.zip', 'a\\b c.zip'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(BASE + tail)

    def test_invalid_percent_rejected(self):
        for tail in ('a%b c.zip', 'a%2b c%.zip', 'a%ggb c.zip'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(BASE + tail)

    def test_nested_percent_rejected(self):
        for tail in ('a%2520b c.zip', 'a%2509b c.zip', 'a%252Fb c.zip'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(BASE + tail)

    def test_scheme_and_size_rejected(self):
        for value in ('http://vendor.example.org/a b.zip', 'file:///a b.zip', BASE + 'a' * 2048 + ' b.zip'):
            with self.assertRaises(cr.RegistryError):
                h.path_space_url(value)

    def test_common_parser_keeps_relation_in_ram(self):
        parser = http.PageLinks(BASE)
        parser.feed('<html><a href="' + escape(RAW, quote=True) + '">file</a></html>')
        self.assertEqual(parser.links, {cr.digest(WIRE.encode())})
        self.assertEqual(parser.derived_links, {(RAW, RAW, WIRE)})
        self.assertNotIn(cr.digest(RAW.encode()), parser.links)

    def test_base_script_and_other_attributes_not_executed(self):
        parser = http.PageLinks(BASE)
        parser.feed('<html><base href="https://else.example.org/"><script>fetch("other.zip")</script>'
            '<a href="a b.zip">a</a><img src="other.zip"><a onclick="fetch(1)">b</a></html>')
        self.assertEqual(parser.links, {cr.digest((BASE + 'a%20b.zip').encode())})
        self.assertEqual(parser.derived_links, {('a b.zip', BASE + 'a b.zip', BASE + 'a%20b.zip')})

    def test_existing_registered_query_profile(self):
        page = BASE + '?path=%2Fpublic%2F'
        parser = http.PageLinks(BASE, registered_links={page: ('PUBLIC_RESOURCE_PATH', 'PAGE')})
        parser.feed('<html><a href="' + escape(page, quote=True) + '">page</a></html>')
        self.assertEqual(parser.links, {cr.digest(page.encode())})
        self.assertFalse(parser.derived_links)

    def test_private_dns_still_fail_closed(self):
        results = [(2, 1, 6, '', ('8.8.8.8', 443)), (2, 1, 6, '', ('127.0.0.1', 443))]
        with patch('socket.getaddrinfo', return_value=results):
            with self.assertRaises(cr.RegistryError):
                http.public_addresses('vendor.example.org')

    def test_payload_not_page_or_automatic_followup(self):
        transport = http.CurlTransport()
        with patch('subprocess.run') as run:
            with self.assertRaisesRegex(cr.RegistryError, 'PAGE_PAYLOAD_ENDPOINT'):
                transport('PAGE', WIRE)
            run.assert_not_called()

    def test_fake_daily_monitor_hash_and_same_day_zero(self):
        registry, locators = locator_fixture()
        registry['records'][0]['downloadUrl'] = WIRE
        registry['records'][0]['linkState'] = 'OFFICIAL_LINK'
        registry['observations'][0]['kind'] = 'OFFICIAL_LINK'
        registry = cr.validate_registry(registry)
        locators['registry'] = pl.registry_binding(registry)
        locators['locators'] = locators['locators'][:1]
        policy = dict(schema='dc-registry-monitor-policy-v1', revision='test', heldSourceIds=[])
        now = datetime(2026, 10, 6, 14)
        body = ('<html><a href="' + escape(RAW, quote=True) + '">file</a></html>').encode()
        calls = []

        def fake(kind, url):
            """架空pageだけを再生し、LINKやhref先を通信しない。"""
            self.assertEqual(kind, 'PAGE')
            calls.append((kind, url))
            parser = http.PageLinks(url)
            parser.feed(body.decode())
            return http.response(200, body=body, links=sorted(parser.links))

        with tempfile.TemporaryDirectory() as folder:
            store = Path(folder) / 'store'
            dm.initialize(store, clock=lambda: now)
            first = dm.run_once(registry, policy, store, transport=fake, clock=lambda: now,
                pages_only=True, public_locators=locators)
            second = dm.run_once(registry, policy, store, transport=fake, clock=lambda: now,
                pages_only=True, public_locators=locators)
            self.assertEqual(first['counts']['attempted'], 1)
            self.assertEqual(second['counts']['attempted'], 0)
            self.assertEqual(len(calls), 1)
            success = next(iter(dm.verify_store(store)['requests'].values()))['lastSuccess']
            self.assertEqual(success['linkHashes'], [cr.digest(WIRE.encode())])


if __name__ == '__main__':
    unittest.main()
