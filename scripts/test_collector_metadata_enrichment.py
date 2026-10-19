"""登録済みmetadata参照の明示追記と旧取得証拠保持を非通信で試験する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の公式source・製品・取得証拠だけを使い、実通信・導入を行わない。
"""
from copy import deepcopy
from contextlib import redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch
import collector_registry as cr
import collector_payload_evidence as pe
from test_collector_registry import fixture
from test_collector_payload_evidence import evidence


def enriched():
    """旧識別を保持した新source・recordと新公式観測を返す。"""
    prior = fixture()
    value = deepcopy(prior)
    value.update(revision='test-enriched', asOf='2026-10-04T01:00:00Z')
    value['sources'].append(dict(id='source-two', manufacturer='Example',
        officialPage='https://vendor.example.org/new-drivers', collectionMethod='MANUAL_RESEARCH'))
    value['records'].append({**value['records'][0], 'id': 'record-two', 'sourceId': 'source-two',
        'packageVersion': '2.0', 'downloadUrl': 'https://cdn.example.org/new-driver.zip', 'linkState': 'OFFICIAL_LINK'})
    value['products'][0]['sourceIds'].append('source-two')
    value['products'][0]['recordIds'].append('record-two')
    value['observations'].append(dict(id='fresh-page', productId='product-one', recordId='record-two',
        checkedAt=value['asOf'], kind='OFFICIAL_LINK', method='WEB_REVIEW',
        evidenceUrl=value['sources'][-1]['officialPage'], httpStatus=None, evidenceSha256=None))
    return prior, value


class MetadataEnrichmentTests(unittest.TestCase):
    """optionの独立性と根拠・識別・取得recordの保持を確認する。"""

    def setUp(self):
        """各caseに独立した架空の台帳を用意する。"""
        self.prior, self.current = enriched()
        self.observed = evidence(self.prior)

    def carry(self, **options):
        """架空の証拠だけで非通信の引継ぎを行う。"""
        return pe.carry_forward(self.prior, self.observed, self.current, **options)

    def validate(self):
        """通常validatorとは別に追記差分の契約を確認する。"""
        pe.validate_metadata_enrichment(self.prior['products'][0], self.current['products'][0],
            self.current['observations'][2:], {row['id']: row for row in self.current['sources']},
            {row['id']: row for row in self.current['records']})

    def test_default_refuses(self):
        """既定の追加専用規則は変えない。"""
        with self.assertRaises(cr.RegistryError):
            self.carry()

    def test_explicit_preserves_acquisition(self):
        """参照追記は元取得時刻・hash・検査を保持する。"""
        result = self.carry(allow_metadata_enrichment=True)
        self.assertEqual({key: value for key, value in result['acquisitions'][0].items() if key != 'recordSha256'},
            self.observed['acquisitions'][0])
        self.assertEqual(pe.evidence_counts(self.current, result)['payloadsDownloaded'], 1)

    def test_non_boolean_mode_refuses(self):
        """truthyな任意値を明示許可として扱わない。"""
        with self.assertRaises(cr.RegistryError):
            self.carry(allow_metadata_enrichment=1)

    def test_old_identity_refuses(self):
        """名前やIDの付替えを補完にしない。"""
        for key, value in (('id', 'other-product'), ('model', 'Other Device'), ('manufacturer', 'Other'), ('driverCategory', 'USB')):
            with self.subTest(key=key):
                original = self.current['products'][0][key]
                self.current['products'][0][key] = value
                with self.assertRaises(cr.RegistryError):
                    self.validate()
                self.current['products'][0][key] = original

    def test_source_removal_refuses(self):
        """旧公式sourceを消さない。"""
        self.current['products'][0]['sourceIds'] = ['source-two']
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_record_removal_refuses(self):
        """旧配布を新しい配布へ置換しない。"""
        self.current['products'][0]['recordIds'] = ['record-two']
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_state_change_refuses(self):
        """既存metadataを別状態へ変更しない。"""
        self.current['products'][0]['researchState'] = 'PAGE_ONLY'
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_reason_change_refuses(self):
        """拒否理由の付替えを参照追記にしない。"""
        self.current['products'][0]['reason'] = 'HTTP_403'
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_source_only_literal_link_passes(self):
        """既存recordの別公式配布根拠だけを追記できる。"""
        self.current['records'].pop()
        self.current['products'][0]['recordIds'] = ['record-one']
        self.current['observations'][-1]['recordId'] = 'record-one'
        result = self.carry(allow_metadata_enrichment=True)
        self.assertEqual(result['acquisitions'][0]['recordSha256'], cr.digest(cr.json_bytes(self.prior['records'][0])))

    def test_source_only_page_without_link_refuses(self):
        """sourceだけの追加には明示リンク根拠を要求する。"""
        self.current['products'][0]['recordIds'] = ['record-one']
        self.current['observations'][-1].update(recordId='record-one', kind='OFFICIAL_PAGE')
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_wrong_record_source_refuses(self):
        """別sourceのpageで追加recordを証明しない。"""
        self.current['observations'][-1]['evidenceUrl'] = self.prior['sources'][0]['officialPage']
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_wrong_added_source_refuses(self):
        """新sourceの成功根拠を省略しない。"""
        self.current['sources'][-1]['officialPage'] = 'https://vendor.example.org/another-page'
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_stale_observation_refuses(self):
        """旧asOf以前の観測を新規根拠に流用しない。"""
        self.current['observations'][-1]['checkedAt'] = '2026-10-02T23:59:59Z'
        with self.assertRaises(cr.RegistryError):
            self.carry(allow_metadata_enrichment=True)

    def test_failure_observation_refuses(self):
        """HTTP失敗を成功根拠にしない。"""
        self.current['observations'][-1]['httpStatus'] = 403
        with self.assertRaises(cr.RegistryError):
            self.carry(allow_metadata_enrichment=True)

    def test_other_product_observation_refuses(self):
        """他製品の根拠を借りない。"""
        self.current['observations'][-1]['productId'] = 'other-product'
        with self.assertRaises(cr.RegistryError):
            self.validate()

    def test_protected_record_mutation_refuses(self):
        """取得済みrecordの属性を改変しない。"""
        self.current['records'][0]['packageVersion'] = '99.0'
        with self.assertRaises(cr.RegistryError):
            self.carry(allow_metadata_enrichment=True, allow_link_enrichment=True)

    def test_options_remain_independent(self):
        """旧PAGE_ONLY optionだけでは既存metadataを追記できない。"""
        with self.assertRaises(cr.RegistryError):
            self.carry(allow_product_enrichment=True)
        self.assertEqual(self.carry(allow_product_enrichment=True, allow_metadata_enrichment=True)['acquisitions'][0]['bytes'], 100)

    def test_cli_explicit_option(self):
        """非通信CLIだけへ独立optionを接続する。"""
        with patch('sys.argv', ['tool', 'carry-forward', 'old', 'new', 'output', '--allow-metadata-enrichment']), \
                patch.object(pe, 'verify_bundle', return_value=(self.prior, self.observed)), \
                patch.object(cr, 'check_ancestors'), patch.object(cr, 'read_json', return_value=self.current), \
                patch.object(pe, 'write_bundle') as write, redirect_stdout(StringIO()):
            self.assertEqual(pe.main(), 0)
            self.assertEqual(write.call_count, 1)


if __name__ == '__main__':
    unittest.main()
