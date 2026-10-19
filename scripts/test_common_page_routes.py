"""公開path・address familyとmetadata用途の共通拒否を非通信で検証する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空PAGE・DNS・時計だけを使い、実DNS／HTTP・本体・導入を実行しない。
"""
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch

import collector_registry as cr
import collector_public_locators as pl
import registry_daily_monitor as dm
import registry_monitor_http as http
from registry_page_requests import page_requests
from test_collector_public_locators import locator_fixture

BASE = 'https://vendor.example.org/download/file'
PATH = BASE + '?path=/support/driver-pages/current/'
FIXTURE_CURL = r'C:\DriverCrateFixture\System32\curl.exe'


def assert_http_process(case, args, options, *, kind, url):
    """独立した固定argvとoptionsを照合し、routeならTrue、curlならFalseを返す。

    架空System32 path以外や未知optionを成功へ読み替えず、AssertionErrorで拒否する。
    header/bodyだけは呼出しごとの新規temporary directory内の二つの名前を受ける。
    """
    route_args = [sys.executable, '-I', '-B', '-S', '-c',
                  'import sys;sys.path.insert(0,sys.argv[1]);import registry_monitor_http as h;'
                  'sys.exit(h.route_main(sys.argv[2:]))', str(Path(__file__).resolve().parent), url]
    if args == route_args:
        case.assertEqual(options, dict(executable=sys.executable, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, timeout=5, check=False))
        return True
    # 固定位置も含めた全argvを照合し、許可していないoptionの追加を拒否する。
    case.assertEqual(len(args), 28 if kind == 'LINK' else 29)
    headers = Path(args[19])
    body = Path(args[21])
    case.assertEqual((headers.name, body.name), ('headers', 'body'))
    case.assertEqual(headers.parent, body.parent)
    case.assertTrue(headers.is_absolute() and headers.parent.is_dir())
    case.assertTrue(headers.parent.name.startswith('drivercrate-monitor-http-'))
    case.assertEqual(args, [FIXTURE_CURL, '-q', '--silent', '--fail', '--proto', '=https',
        '--max-redirs', '0', '--connect-timeout', '5', '--max-time', '20', '--proxy', '',
        '--noproxy', '', '--connect-to', 'vendor.example.org:443:8.8.8.8:443',
        '--dump-header', str(headers), '--output', str(body), '--write-out', '%{http_code}',
        '--user-agent', 'DriverCrate-maintenance-monitor/1'] +
        (['--head'] if kind == 'LINK' else ['--max-filesize', '2097152']) + [url])
    case.assertEqual(options, dict(executable=FIXTURE_CURL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=22, check=False))
    return False


def path_fixture():
    """登録親PAGEへ一つの架空childを結合する。"""
    registry, original = locator_fixture()
    value = deepcopy(original)
    child = value['locators'][1]
    child.update(url=PATH, urlProfile='PUBLIC_RESOURCE_PATH')
    value = pl.validate_locators(value, registry)
    return registry, value


class PublicPathTests(TestCase):
    """URLの元表現とPAGE限定・一回decodeの文法を検証する。"""

    def test_literal_path_keeps_url(self):
        self.assertEqual(pl.public_locator_url(PATH, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE'), PATH)

    def test_encoded_slash_keeps_url(self):
        for separator in ('%2F', '%2f'):
            value = PATH.replace('/support/driver-pages/current/', separator + 'support' + separator + 'driver-pages' + separator + 'current' + separator)
            self.assertEqual(pl.public_locator_url(value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE'), value)

    def test_mixed_slash_representation(self):
        value = BASE + '?path=%2Fsupport/driver-pages%2Fcurrent/'
        self.assertEqual(pl.public_locator_url(value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE'), value)

    def test_payload_purpose_rejected(self):
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(PATH, profile='PUBLIC_RESOURCE_PATH', purpose='PAYLOAD')

    def test_private_or_extra_query_rejected(self):
        for suffix in ('&token=synthetic', '&path=/second/', '#fragment', ';token=synthetic', '?other=value'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(PATH + suffix, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE')

    def test_nested_and_control_escape_rejected(self):
        for value in ('%252Fsupport%252F', '%2Fsupport%00/', '%2Fsupport%2E%2E/', '/support/%2F/', '/support%5Cdriver/'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE + '?path=' + value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE')

    def test_dot_empty_relative_and_url_rejected(self):
        for value in ('/support/../', '/support//', 'support/current/', '//support/', 'https://other.example.org/', '/support/driver.exe/'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE + '?path=' + value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE')

    def test_segment_and_depth_limits(self):
        for value in ('/' + 'a' * 65 + '/', '/a/' + 'b/' * 8):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE + '?path=' + value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE')
        value = BASE + '?path=/' + 'a' * 64 + '/'
        self.assertEqual(pl.public_locator_url(value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE'), value)

    def test_dp_inside_selector_rejected(self):
        for value in ('/dp/synthetic/', '%2Fdp%2Fsynthetic%2F'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(BASE + '?path=' + value, profile='PUBLIC_RESOURCE_PATH', purpose='PAGE')

    def test_queryless_and_numeric_defaults_still_reject_path(self):
        for profile in ('QUERYLESS', 'PUBLIC_NUMERIC_ID', 'PUBLIC_PAGE_ID'):
            with self.assertRaises(cr.RegistryError):
                pl.public_locator_url(PATH, profile=profile, purpose='PAGE')

    def test_fixture_graph_and_page_plan(self):
        registry, locators = path_fixture()
        policy = dict(schema='dc-registry-monitor-policy-v1', revision='synthetic-path', heldSourceIds=[])
        pages = page_requests(registry, locators, policy, dm.make_requests(registry, policy))
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(row['kind'] == 'PAGE' for row in pages))
        self.assertEqual(next(row for row in pages if row['url'] == PATH)['observationDueAt'], datetime(2026, 10, 3))

    def test_fake_daily_wait_and_no_payload_requests(self):
        registry, locators = path_fixture()
        policy = dict(schema='dc-registry-monitor-policy-v1', revision='synthetic-path', heldSourceIds=[])
        calls = []
        def transport(kind, url):
            calls.append((kind, url))
            return http.response(200, body=b'<html></html>')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'monitor'
            clock = lambda: datetime(2026, 10, 4)
            dm.initialize(root, clock=clock)
            first = dm.run_once(registry, policy, root, transport=transport, clock=clock, public_locators=locators, pages_only=True)
            second = dm.run_once(registry, policy, root, transport=transport, clock=clock, public_locators=locators, pages_only=True)
        self.assertEqual((first['counts']['attempted'], second['counts']['attempted']), (2, 0))
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(kind == 'PAGE' for kind, _ in calls))


class AddressFamilyTests(TestCase):
    """全DNS公開性を保ったIPv4優先とIPv6単独を検証する。"""

    def resolve(self, values):
        """指定addressをgetaddrinfoの偽応答にし、共通の公開address検査へ渡す。

        patchはpublic_addressesの同期呼出し中だけ有効で、実DNSへ問い合わせない。
        """
        answers = [(2, 1, 6, '', (value, 443)) for value in values]
        with patch.object(http.socket, 'getaddrinfo', return_value=answers):
            return http.public_addresses('vendor.example.org')

    def test_ipv4_before_ipv6(self):
        self.assertEqual(self.resolve(['2606:4700:4700::1111', '8.8.8.8']), ['8.8.8.8', '2606:4700:4700::1111'])

    def test_ipv6_only_preserved(self):
        self.assertEqual(self.resolve(['2606:4700:4700::1111']), ['2606:4700:4700::1111'])

    def test_numeric_ipv4_order(self):
        self.assertEqual(self.resolve(['8.8.8.10', '8.8.8.2', '8.8.8.10']), ['8.8.8.2', '8.8.8.10'])

    def test_mixed_private_ipv4_rejected(self):
        with self.assertRaises(cr.RegistryError):
            self.resolve(['2606:4700:4700::1111', '192.168.1.1'])

    def test_mixed_reserved_ipv6_rejected(self):
        with self.assertRaises(cr.RegistryError):
            self.resolve(['8.8.8.8', '2001:db8::1'])

    def test_embedded_addresses_not_filtered_away(self):
        for value in ('::ffff:8.8.8.8', '2002:0808:0808::'):
            with self.assertRaises(cr.RegistryError):
                self.resolve(['8.8.8.8', value])


class MetadataTransportTests(TestCase):
    """本体・未知PAGEを通信前に拒否し、登録pathを既存有限curlへ渡す。"""

    def test_dp_and_encoded_suffix_blocked_before_dns(self):
        for suffix in ('/dp/path=/support/asset/synthetic/', '/%64%70/synthetic/', '/driver.EXE', '/driver%2Eexe', '/driver%252Eexe'):
            with patch.object(http.subprocess, 'run') as process:
                with self.assertRaises(cr.RegistryError):
                    http.CurlTransport()('PAGE', 'https://vendor.example.org' + suffix)
                process.assert_not_called()

    def test_bound_direct_payload_blocked_without_locator(self):
        registry, locators = path_fixture()
        registry['records'][0].update(downloadUrl='https://vendor.example.org/opaque-download', linkState='OFFICIAL_LINK')
        registry['observations'][0]['kind'] = 'OFFICIAL_LINK'
        registry = cr.validate_registry(registry)
        locators['locators'] = [row for row in locators['locators'] if row['purpose'] == 'PAGE']
        locators['registry'] = pl.registry_binding(registry)
        transport = http.CurlTransport(registry=registry, public_locators=locators)
        with patch.object(http.subprocess, 'run') as process:
            for kind in ('PAGE', 'LINK'):
                with self.assertRaises(cr.RegistryError):
                    transport(kind, registry['records'][0]['downloadUrl'])
            process.assert_not_called()

    def test_unknown_page_is_not_automatically_followed(self):
        registry, locators = path_fixture()
        transport = http.CurlTransport(registry=registry, public_locators=locators)
        with patch.object(http.subprocess, 'run') as process:
            with self.assertRaises(cr.RegistryError):
                transport('PAGE', 'https://vendor.example.org/new-public-page')
            process.assert_not_called()

    def test_unregistered_path_is_not_enabled_by_mode(self):
        with patch.object(http.subprocess, 'run') as process:
            for mode in (False, True):
                with self.assertRaises(cr.RegistryError):
                    http.CurlTransport(allow_public_query=mode)('PAGE', PATH)
            process.assert_not_called()

    def test_parser_observes_registered_path_without_following(self):
        parser = http.PageLinks(BASE, registered_links={PATH: ('PUBLIC_RESOURCE_PATH', 'PAGE')})
        parser.feed('<html><a href="?path=/support/driver-pages/current/">page</a><a href="?path=/unregistered/">x</a></html>')
        self.assertEqual(parser.links, {dm.hash_text(PATH)})

    def test_registered_path_curl_keeps_url_and_one_pinned_request(self):
        registry, locators = path_fixture()
        calls = []
        def fake(args, **options):
            """正確なroute/curl呼出しだけへ架空のtyped DNSとHTMLを返す。"""
            calls.append(args)
            if assert_http_process(self, args, options, kind='PAGE', url=PATH):
                return subprocess.CompletedProcess(args, 0,
                    b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')
            Path(args[args.index('--dump-header') + 1]).write_bytes(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n')
            Path(args[args.index('--output') + 1]).write_bytes(b'<html></html>')
            return subprocess.CompletedProcess(args, 0, b'200')
        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
                patch.object(http.subprocess, 'run', side_effect=fake):
            result = http.CurlTransport(registry=registry, public_locators=locators)('PAGE', PATH)
        self.assertEqual(result['error'], 'NONE')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][-1], PATH)
        self.assertEqual(calls[1][calls[1].index('--connect-to') + 1], 'vendor.example.org:443:8.8.8.8:443')
        self.assertNotIn('--head', calls[1])
        self.assertNotIn('--retry', calls[1])
        self.assertNotIn('--insecure', calls[1])
