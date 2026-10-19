"""多配布PAGEの明示edge v2と旧v1拒否境界の決定的試験（ADR 0303）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の製品・配布のみを使用し、通信・同意・実driver導入を行わない。
"""
import copy
import unittest
from unittest.mock import patch
import collector_public_locators as pl
import collector_registry as cr
import collector_locator_snapshot as snapshot
import registry_monitor_http as http
from test_collector_public_locators import locator_fixture


def fixture():
    """異なる二配布・shared製品・PAGE_ONLYを含む架空の一PAGEを返す。"""
    registry, value = locator_fixture()
    registry['records'].append({**registry['records'][0], 'id':'record-two'})
    for identifier, records in (('product-two',['record-two']),('product-shared',['record-one']),('product-page-only',[])):
        registry['products'].append({**registry['products'][0], 'id':identifier,'model':identifier,
            'recordIds':records,'researchState':'METADATA_SAVED' if records else 'PAGE_ONLY',
            'reason':'NONE' if records else 'DOWNLOAD_TABLE_UNAVAILABLE'})
        registry['observations'].append({**registry['observations'][0], 'id':identifier+'-observation',
            'productId':identifier,'recordId':records[0] if records else None})
    registry = cr.validate_registry(registry)
    value['schema'] = pl.PAIR_LOCATOR_SCHEMA
    value['registry'] = pl.registry_binding(registry)
    root, page, payload = value['locators']
    root['productIds'] = [row['id'] for row in registry['products']]
    page['productIds'] = root['productIds'][:]
    page['recordIds'] = ['record-one','record-two']
    payload['productIds'] = ['product-one','product-shared']
    second = {**copy.deepcopy(payload),'id':'payload-two','url':payload['url'].replace('0012','0013'),
        'productIds':['product-two'],'recordIds':['record-two']}
    value['locators'].append(second)
    products = {row['id']:row for row in registry['products']}
    for row in value['locators']:
        row['productRecordPairs'] = [dict(productId=pid,recordId=rid) for pid in sorted(row['productIds'])
            for rid in sorted(row['recordIds']) if rid in products[pid]['recordIds']]
    return registry, value


class ProductRecordPairTests(unittest.TestCase):
    """新schemaだけで正当な部分scopeを扱い、未知・省略と許可昇格を拒否する。"""

    def reject(self, value, registry, code=None):
        with self.assertRaises(cr.RegistryError) as raised:
            pl.validate_locators(value,registry)
        if code:
            self.assertEqual(str(raised.exception),code)

    def test_heterogeneous_page_shared_driver_and_page_only(self):
        registry, value = fixture()
        valid = pl.validate_locators(value,registry)
        self.assertEqual(pl.locator_counts(valid)['productRecordEdges'],3)
        self.assertEqual(pl.locator_counts(valid)['payloadRequestsAuthorized'],0)
        self.assertEqual(len(valid['locators']),4)

    def test_v1_original_byte_contract_and_heterogeneous_rejection(self):
        registry, value = locator_fixture()
        normalized = pl.validate_locators(value,registry)
        self.assertEqual(normalized['schema'],pl.LOCATOR_SCHEMA)
        self.assertTrue(all('productRecordPairs' not in row for row in normalized['locators']))
        registry, value = fixture()
        value['schema'] = pl.LOCATOR_SCHEMA
        for row in value['locators']:
            row.pop('productRecordPairs')
        self.reject(value,registry,'LOCATOR_PRODUCT_RECORD')

    def test_missing_v2_field_and_v1_extra_field(self):
        registry, value = fixture()
        value['locators'][1].pop('productRecordPairs')
        self.reject(value,registry,'LOCATOR_ROW_FIELDS')
        registry, value = locator_fixture()
        value['locators'][0]['productRecordPairs'] = []
        self.reject(value,registry,'LOCATOR_ROW_FIELDS')

    def test_unknown_schema_or_type(self):
        for schema in ('dc-public-driver-locators-v3',None,[],True):
            registry, value = fixture()
            value['schema'] = schema
            self.reject(value,registry,'LOCATOR_SCHEMA')

    def test_missing_shared_product_pair_rejected(self):
        registry, value = fixture()
        value['locators'][1]['productRecordPairs'].pop()
        self.reject(value,registry,'LOCATOR_PAIRS_GRAPH')

    def test_extra_or_unknown_pair_cannot_borrow_same_page(self):
        for pair in (dict(productId='product-two',recordId='record-one'),
                     dict(productId='unknown',recordId='record-one'),
                     dict(productId='product-one',recordId='unknown')):
            registry, value = fixture()
            value['locators'][1]['productRecordPairs'].append(pair)
            self.reject(value,registry,'LOCATOR_PAIR_BINDING')

    def test_duplicate_and_unclosed_pair_fields(self):
        registry, value = fixture()
        value['locators'][1]['productRecordPairs'].append(value['locators'][1]['productRecordPairs'][0].copy())
        self.reject(value,registry,'LOCATOR_PAIR_DUPLICATE')
        registry, value = fixture()
        value['locators'][1]['productRecordPairs'][0]['approved'] = True
        self.reject(value,registry,'LOCATOR_PAIR_FIELDS')

    def test_empty_or_invalid_pair_container(self):
        for pairs in ([],None,{},True):
            registry, value = fixture()
            value['locators'][1]['productRecordPairs'] = pairs
            self.reject(value,registry,'LOCATOR_PAIRS_GRAPH' if pairs==[] else 'LOCATOR_PAIRS_COUNT')

    def test_record_without_any_product_cannot_be_advertised(self):
        registry, value = fixture()
        registry['records'].append({**registry['records'][0],'id':'record-unused'})
        next(row for row in registry['products'] if row['id']=='product-two')['recordIds'].append('record-unused')
        registry['observations'].append({**registry['observations'][0],'id':'record-unused-observation',
            'productId':'product-two','recordId':'record-unused'})
        registry = cr.validate_registry(registry)
        value['registry'] = pl.registry_binding(registry)
        value['locators'][0]['recordIds'].append('record-unused')
        self.reject(value,registry,'LOCATOR_PAIRS_GRAPH')

    def test_payload_cannot_omit_shared_scope(self):
        registry, value = fixture()
        value['locators'][2]['productIds'] = ['product-one']
        value['locators'][2]['productRecordPairs'] = [dict(productId='product-one',recordId='record-one')]
        self.reject(value,registry,'LOCATOR_PAYLOAD_PAIRS')

    def test_payload_cannot_include_unrelated_product(self):
        registry, value = fixture()
        value['locators'][2]['productIds'].append('product-two')
        value['locators'][2]['productRecordPairs'].append(dict(productId='product-two',recordId='record-one'))
        self.reject(value,registry,'LOCATOR_PAIR_BINDING')

    def test_payload_unrelated_product_without_pair_rejected(self):
        registry, value = fixture()
        value['locators'][2]['productIds'].append('product-page-only')
        self.reject(value,registry,'LOCATOR_PAYLOAD_PAIR_PRODUCTS')

    def test_payload_needs_record_in_each_parent(self):
        registry, value = fixture()
        value['locators'][2]['parentPageIds'] = ['root-one']
        self.reject(value,registry,'LOCATOR_PAYLOAD_EVIDENCE')

    def test_two_pages_union_only_explicit_shared_record_scope(self):
        registry, value = fixture()
        page = value['locators'][1]
        second = {**copy.deepcopy(page),'id':'page-two','url':page['url'].replace('00012','00013'),
            'productIds':['product-shared'],'recordIds':['record-one'],
            'productRecordPairs':[dict(productId='product-shared',recordId='record-one')]}
        page['productIds'].remove('product-shared')
        page['productRecordPairs'] = [pair for pair in page['productRecordPairs'] if pair['productId']!='product-shared']
        value['locators'][2]['parentPageIds'].append('page-two')
        value['locators'].append(second)
        valid = pl.validate_locators(value,registry)
        self.assertEqual(pl.locator_counts(valid)['payloadProductReferences'],3)

    def test_foreign_record_source_and_registry_binding(self):
        registry, value = fixture()
        value['registry']['sha256'] = '0'*64
        self.reject(value,registry,'LOCATOR_REGISTRY_BINDING')
        registry, value = fixture()
        registry['sources'].append({**registry['sources'][0], 'id':'foreign',
            'officialPage':'https://foreign.example.org/drivers'})
        for product in registry['products']:
            if 'record-one' in product['recordIds']:
                product['sourceIds'].append('foreign')
        registry['records'][0]['sourceId'] = 'foreign'
        registry = cr.validate_registry(registry)
        value['registry'] = pl.registry_binding(registry)
        self.reject(value,registry,'LOCATOR_RECORD_SOURCE')

    def test_pair_budgets_are_finite_per_document(self):
        registry, value = fixture()
        with patch.object(pl,'MAX_PRODUCT_RECORD_PAIRS',4):
            self.reject(value,registry,'LOCATOR_PAIRS_TOTAL')

    def test_normalization_reordering_and_snapshot_content(self):
        registry, value = fixture()
        expected = pl.validate_locators(value,registry)
        value['locators'].reverse()
        for row in value['locators']:
            row['productRecordPairs'].reverse()
            row['productIds'].reverse()
        self.assertEqual(pl.validate_locators(value,registry),expected)
        content = snapshot.snapshot_content(registry,value)
        self.assertEqual(cr.parse_json(content['locators.json']),expected)

    def test_transport_blocks_payload_before_dns_even_new_schema(self):
        registry, value = fixture()
        transport = http.CurlTransport(registry=registry,public_locators=value)
        with patch('subprocess.run') as run:
            with self.assertRaisesRegex(cr.RegistryError,'LOCATOR_REQUEST_HELD'):
                transport('PAGE',value['locators'][2]['url'])
            run.assert_not_called()

    def test_no_side_effects_or_permission_promotion(self):
        registry, value = fixture()
        with patch('socket.getaddrinfo') as dns, patch('subprocess.run') as run, patch('builtins.open') as opened:
            valid = pl.validate_locators(value,registry)
            dns.assert_not_called()
            run.assert_not_called()
            opened.assert_not_called()
        self.assertFalse(valid['publishable'])
        self.assertFalse(valid['installAuthorized'])
        value['installAuthorized'] = True
        self.reject(value,registry,'LOCATOR_SAFETY_FLAGS')


if __name__ == '__main__':
    unittest.main()
