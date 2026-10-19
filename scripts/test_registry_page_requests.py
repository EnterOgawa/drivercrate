"""全登録PAGE監視の非通信・保存・待機・互換性を検証する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空台帳とtemporary directoryだけを使い、実HTTPや本体取得を行わない。
"""
import copy
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import unittest

import collector_registry as cr
import collector_public_locators as pl
import registry_daily_monitor as dm
import registry_monitor_http as http
from registry_locator_requests import locator_requests
from registry_page_requests import page_requests
from test_collector_public_locators import locator_fixture


def full_fixture():
    """locatorのない取得元と直接本体URLを含む架空台帳を返す。"""
    registry, locators = locator_fixture()
    registry['sources'].append({**registry['sources'][0], 'id': 'source-two',
        'officialPage': 'https://another.example.org/support'})
    registry['records'].append({**registry['records'][0], 'id': 'record-two', 'sourceId': 'source-two',
        'downloadUrl': 'https://another.example.org/driver.zip', 'linkState': 'OFFICIAL_LINK'})
    registry['products'].append({**registry['products'][0], 'id': 'product-two',
        'model': 'Device Two', 'sourceIds': ['source-two'], 'recordIds': ['record-two']})
    registry['observations'].append({**registry['observations'][0], 'id': 'link-two',
        'productId': 'product-two', 'recordId': 'record-two', 'kind': 'OFFICIAL_LINK',
        'evidenceUrl': registry['sources'][1]['officialPage']})
    registry = cr.validate_registry(registry)
    locators['registry'] = pl.registry_binding(registry)
    return registry, pl.validate_locators(locators, registry)


class PageMonitorTests(unittest.TestCase):
    """既存限定モードを維持し、全ページと待機を独立に検証する。"""

    def setUp(self):
        self.registry, self.locators = full_fixture()
        self.policy = {'schema': 'dc-registry-monitor-policy-v1', 'revision': 'test', 'heldSourceIds': []}
        self.now = datetime(2026, 10, 3, 1)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'store'
        dm.initialize(self.root, clock=lambda: self.now)
        self.calls = []

    def response(self, kind, url):
        self.assertEqual(kind, 'PAGE')
        self.calls.append((kind, url))
        return http.response(200, body=b'<html>fixture</html>')

    def run_pages(self, **options):
        return dm.run_once(self.registry, self.policy, self.root, public_locators=self.locators,
            pages_only=True, transport=self.response, clock=lambda: self.now, **options)

    def test_full_fixture_includes_both_sources_no_payload(self):
        rows = page_requests(self.registry, self.locators, self.policy, dm.make_requests(self.registry, self.policy))
        self.assertEqual(len(rows), 3)
        self.assertEqual({sid for row in rows for sid in row['sourceIds']}, {'source-one', 'source-two'})
        self.assertTrue(all(row['kind'] == 'PAGE' for row in rows))
        self.assertTrue(any(row['locatorIds'] == [] for row in rows))

    def test_limited_mode_does_not_expand(self):
        rows = locator_requests(self.registry, self.locators, self.policy, dm.make_requests(self.registry, self.policy))
        self.assertEqual({sid for row in rows for sid in row['sourceIds']}, {'source-one'})
        self.assertEqual(sum(row['kind'] == 'LINK' for row in rows), 1)

    def test_registry_and_locators_remain_immutable(self):
        before = copy.deepcopy((self.registry, self.locators))
        self.run_pages()
        self.assertEqual((self.registry, self.locators), before)

    def test_report_v3_and_same_day_zero(self):
        first = self.run_pages()
        second = self.run_pages()
        self.assertEqual(first['schema'], 'dc-registry-monitor-report-v3')
        self.assertEqual(first['requestScope'], 'REGISTERED_PAGES_ONLY')
        self.assertEqual(first['counts']['attempted'], 3)
        self.assertEqual(second['counts']['attempted'], 0)
        self.assertEqual(len(self.calls), 3)
        dm.verify_store(self.root)

    def test_source_hold_preserved(self):
        self.policy['heldSourceIds'] = ['source-two']
        report = self.run_pages()
        self.assertEqual(report['counts']['held'], 1)
        self.assertEqual(report['counts']['attempted'], 2)
        self.assertTrue(all('another.' not in url for _, url in self.calls))

    def test_v2_rejects_empty_locator_list(self):
        report = self.run_pages()
        report['schema'] = 'dc-registry-monitor-report-v2'
        del report['requestScope']
        with self.assertRaises(cr.RegistryError):
            dm.validate_report(report)

    def test_v3_rejects_link_kind(self):
        report = self.run_pages()
        report['items'][0]['kind'] = 'LINK'
        with self.assertRaises(cr.RegistryError):
            dm.validate_report(report)

    def test_v3_rejects_unknown_scope(self):
        report = self.run_pages()
        report['requestScope'] = 'ALL_PAYLOADS'
        with self.assertRaises(cr.RegistryError):
            dm.validate_report(report)

    def test_requires_locators_and_bool(self):
        for options in ({'pages_only': True}, {'pages_only': 1, 'public_locators': self.locators}):
            with self.assertRaises(cr.RegistryError):
                dm.run_once(self.registry, self.policy, self.root, **options)

    def test_purpose_collision_rejected_before_http(self):
        self.registry['sources'][1]['officialPage'] = self.registry['records'][1]['downloadUrl']
        self.locators['registry'] = pl.registry_binding(self.registry)
        with self.assertRaises(cr.RegistryError):
            self.run_pages()
        self.assertEqual(self.calls, [])

    def test_duplicate_official_page_combines_sources(self):
        self.registry['sources'][1]['officialPage'] = self.registry['sources'][0]['officialPage']
        for row in self.registry['observations']:
            if row['productId'] == 'product-two':
                row['evidenceUrl'] = self.registry['sources'][1]['officialPage']
        self.locators['registry'] = pl.registry_binding(self.registry)
        report = self.run_pages()
        self.assertEqual(report['counts']['plannedRequests'], 2)
        self.assertEqual(report['counts']['sources'], 2)

    def test_next_day_shared_id_wait_and_prior_success(self):
        self.run_pages()
        before = dm.verify_store(self.root)
        self.now += timedelta(hours=23)
        limited = dm.run_once(self.registry, self.policy, self.root, public_locators=self.locators,
            transport=self.response, clock=lambda: self.now)
        self.assertEqual(limited['counts']['attempted'], 0)
        after = dm.verify_store(self.root)
        self.assertEqual(before['requests'], after['requests'])

    def test_export_copy_preserves_v3_and_wait(self):
        self.run_pages()
        exported = Path(self.temp.name) / 'export'
        dm.export_store(self.root, exported)
        dm.verify_export(exported)
        target = Path(self.temp.name) / 'imported'
        dm.import_export(exported, target, source_stop_acknowledged=True, clock=lambda: self.now)
        self.root = target
        self.assertEqual(self.run_pages()['counts']['attempted'], 0)
        self.assertEqual(len(self.calls), 3)


if __name__ == '__main__':
    unittest.main()
