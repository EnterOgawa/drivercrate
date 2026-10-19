"""配布系列文書条件の世代・scope・版不明と非昇格を検証する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の一配布／一製品だけを使用し、通信・本体取得・導入を実行しない。
"""
from copy import deepcopy
import unittest

import collector_family_conditions as family
from test_collector_public_locators import locator_fixture

cr = family.cr


def fixture():
    """版不明の架空配布と観測済み文書の条件を作る。"""
    registry, _ = locator_fixture()
    registry['records'][0]['packageVersion'] = None
    registry['records'][0]['driverVersion'] = None
    registry = cr.validate_registry(registry)
    row = dict(recordId='record-one', recordSha256=cr.digest(cr.json_bytes(registry['records'][0])),
        productIds=['product-one'], scopeBinding='DISTRIBUTION_FAMILY_DOCUMENTATION', versionBinding='NOT_ESTABLISHED',
        documents=[dict(url='https://example.org/readme.txt', method='LOCAL_HTTP', httpStatus=200,
            checkedAt=registry['asOf'], bodyBytes=100, bodySha256='a' * 64, documentRevisionMonth='2026-09',
            revisionIsPackageReleaseDate=False)], declaredOs=['WINDOWS_11_X64'], architectures=['X64'],
        serverVersions=[], optionalDependencies=[dict(name='Example runtime', minimum='4.0',
            use='DOCUMENTATION_ONLY', requiredForCoreDriverProven=False)], excludedHardwareGroups=['EXAMPLE_LEGACY_CLASS'],
        firmwareCoupling='NOT_CHECKED', accessConditionsConfirmed=False, contentVerified=False,
        deviceApplicable=False, installAuthorized=False)
    value = dict(schema='dc-collector-family-conditions-v1', reviewDate='2026-10-06',
        registrySha256=cr.digest(cr.json_bytes(registry)), researchOnly=True, publishable=False,
        installAuthorized=False, records=[row])
    return registry, value


class FamilyConditionTests(unittest.TestCase):
    """文書条件を特定配布版・端末適合・導入許可へ変更しない。"""

    def setUp(self):
        self.registry, self.value = fixture()
        self.row = self.value['records'][0]

    def evaluate(self):
        return family.evaluate_family_conditions(self.registry, self.value)

    def rejects(self, key, value):
        self.row[key] = value
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_unknown_version_allowed_without_content_claim(self):
        result = self.evaluate()
        self.assertEqual(result['familyDocumentedRecords'], 1)
        self.assertEqual(result['linkedResearchProducts'], 1)
        self.assertEqual(result['releaseVersionsConfirmed'], 0)
        self.assertFalse(result['installAuthorized'])

    def test_inputs_immutable(self):
        before = deepcopy((self.registry, self.value))
        self.evaluate()
        self.assertEqual((self.registry, self.value), before)

    def test_wrong_generation_rejected(self):
        self.value['registrySha256'] = 'b' * 64
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_wrong_record_hash_rejected(self):
        self.rejects('recordSha256', 'b' * 64)

    def test_duplicate_record_rejected(self):
        self.value['records'].append(deepcopy(self.row))
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_missing_product_rejected(self):
        self.rejects('productIds', [])

    def test_foreign_product_rejected(self):
        self.rejects('productIds', ['product-other'])

    def test_unknown_field_rejected(self):
        self.rejects('unreviewed', True)

    def test_scope_beyond_record_rejected(self):
        self.rejects('declaredOs', ['WINDOWS_10_X64'])

    def test_server_version_required(self):
        self.rejects('serverVersions', ['2022'])

    def test_explicit_server_documentation_allowed(self):
        self.registry['records'][0]['operatingSystems'] = ['WINDOWS_SERVER_X64']
        self.registry = cr.validate_registry(self.registry)
        self.value['registrySha256'] = cr.digest(cr.json_bytes(self.registry))
        self.row['recordSha256'] = cr.digest(cr.json_bytes(self.registry['records'][0]))
        self.row.update(declaredOs=['WINDOWS_SERVER_X64'], serverVersions=['2022'])
        self.assertEqual(self.evaluate()['familyDocumentedRecords'], 1)

    def test_x86_not_target(self):
        self.rejects('architectures', ['X86'])

    def test_version_binding_not_inferred(self):
        self.rejects('versionBinding', 'CONFIRMED')

    def test_known_version_not_reclassified_as_unknown(self):
        self.registry['records'][0]['packageVersion'] = '1.0'
        self.registry = cr.validate_registry(self.registry)
        self.value['registrySha256'] = cr.digest(cr.json_bytes(self.registry))
        self.row['recordSha256'] = cr.digest(cr.json_bytes(self.registry['records'][0]))
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_document_missing_hash_rejected(self):
        self.row['documents'][0]['bodySha256'] = None
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_document_revision_not_release_date(self):
        self.row['documents'][0]['revisionIsPackageReleaseDate'] = True
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_document_invalid_calendar_rejected(self):
        self.row['documents'][0]['documentRevisionMonth'] = '2026-99'
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_document_failed_http_rejected(self):
        self.row['documents'][0]['httpStatus'] = 403
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_optional_runtime_not_core_dependency(self):
        self.row['optionalDependencies'][0]['requiredForCoreDriverProven'] = True
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_optional_runtime_use_must_be_explicit(self):
        self.row['optionalDependencies'][0]['use'] = 'MANDATORY_CORE_DRIVER'
        with self.assertRaises(cr.RegistryError):
            self.evaluate()

    def test_firmware_not_verified(self):
        self.rejects('firmwareCoupling', 'NONE')

    def test_content_claim_rejected(self):
        self.rejects('contentVerified', True)

    def test_applicability_claim_rejected(self):
        self.rejects('deviceApplicable', True)

    def test_install_claim_rejected(self):
        self.rejects('installAuthorized', True)


if __name__ == '__main__':
    unittest.main()
