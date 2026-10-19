"""版不明の配布系列に対する公式文書条件を検証する（ADR 0296）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
監視PC側のmetadataだけを扱う。版一致・内容・端末適合・導入許可へ昇格しない。
"""
from datetime import date
import re

import collector_registry as cr


def evaluate_family_conditions(registry, value):
    """同世代のrecordと公開文書を結合し、版不明を保持した条件集計を返す。"""
    registry = cr.validate_registry(registry)
    cr.fields(value, {'schema', 'reviewDate', 'registrySha256', 'researchOnly', 'publishable', 'installAuthorized',
        'records'}, 'FAMILY_CONDITION_FIELDS')
    cr.require(value['schema'] == 'dc-collector-family-conditions-v1' and value['researchOnly'] is True and
        value['publishable'] is False and value['installAuthorized'] is False, 'FAMILY_CONDITION_PURPOSE')
    try:
        date.fromisoformat(value['reviewDate'])
    except (ValueError, TypeError) as error:
        raise cr.RegistryError('FAMILY_CONDITION_DATE') from error
    cr.require(value['registrySha256'] == cr.digest(cr.json_bytes(registry)), 'FAMILY_CONDITION_GENERATION')
    cr.require(type(value['records']) is list and 0 < len(value['records']) <= 256, 'FAMILY_CONDITION_BUDGET')
    records = {row['id']: row for row in registry['records']}
    seen = set()
    products = set()
    for row in value['records']:
        cr.fields(row, {'recordId', 'recordSha256', 'productIds', 'scopeBinding', 'versionBinding', 'documents',
            'declaredOs', 'architectures', 'serverVersions', 'optionalDependencies', 'excludedHardwareGroups',
            'firmwareCoupling', 'accessConditionsConfirmed', 'contentVerified', 'deviceApplicable',
            'installAuthorized'}, 'FAMILY_CONDITION_ROW')
        identifier = cr.identity(row['recordId'])
        record = records.get(identifier)
        cr.require(record is not None and identifier not in seen and record['packageVersion'] is None and
            record['driverVersion'] is None and row['recordSha256'] == cr.digest(cr.json_bytes(record)),
            'FAMILY_CONDITION_RECORD')
        expected = sorted(item['id'] for item in registry['products'] if identifier in item['recordIds'])
        cr.require(cr.id_list(row['productIds']) == expected and expected, 'FAMILY_CONDITION_PRODUCTS')
        cr.require(row['scopeBinding'] == 'DISTRIBUTION_FAMILY_DOCUMENTATION' and
            row['versionBinding'] == 'NOT_ESTABLISHED' and row['firmwareCoupling'] == 'NOT_CHECKED',
            'FAMILY_CONDITION_BINDING')
        cr.require(all(row[key] is False for key in ('accessConditionsConfirmed', 'contentVerified',
            'deviceApplicable', 'installAuthorized')), 'FAMILY_CONDITION_NO_AUTHORITY')
        cr.require(type(row['declaredOs']) is list and row['declaredOs'] and
            len(set(row['declaredOs'])) == len(row['declaredOs']) and
            set(row['declaredOs']) <= set(record['operatingSystems']) and
            set(row['declaredOs']) <= cr.SCOPES and row['architectures'] == ['X64'], 'FAMILY_CONDITION_OS')
        cr.require(type(row['serverVersions']) is list and len(set(row['serverVersions'])) == len(row['serverVersions']) and
            all(version in {'2016', '2019', '2022', '2025'} for version in row['serverVersions']) and
            bool(row['serverVersions']) == ('WINDOWS_SERVER_X64' in row['declaredOs']), 'FAMILY_CONDITION_SERVER')
        cr.require(type(row['documents']) is list and 0 < len(row['documents']) <= 8, 'FAMILY_CONDITION_DOCUMENTS')
        urls = set()
        for doc in row['documents']:
            cr.fields(doc, {'url', 'method', 'httpStatus', 'checkedAt', 'bodyBytes', 'bodySha256',
                'documentRevisionMonth', 'revisionIsPackageReleaseDate'}, 'FAMILY_CONDITION_DOCUMENT_FIELDS')
            cr.public_url(doc['url'])
            cr.require(doc['url'] not in urls and doc['method'] == 'LOCAL_HTTP' and type(doc['httpStatus']) is int and
                doc['httpStatus'] == 200 and type(doc['bodyBytes']) is int and 0 < doc['bodyBytes'] <= 2 * 1024**2,
                'FAMILY_CONDITION_DOCUMENT_OBSERVATION')
            cr.require(cr.timestamp(doc['checkedAt']) <= cr.timestamp(registry['asOf']) and
                type(doc['documentRevisionMonth']) is str and re.fullmatch(r'\d{4}-\d{2}', doc['documentRevisionMonth']) and
                doc['revisionIsPackageReleaseDate'] is False, 'FAMILY_CONDITION_DOCUMENT_TIME')
            try:
                date.fromisoformat(doc['documentRevisionMonth'] + '-01')
            except ValueError as error:
                raise cr.RegistryError('FAMILY_CONDITION_DOCUMENT_CALENDAR') from error
            cr.sha256(doc['bodySha256'])
            cr.require(doc['bodySha256'] is not None, 'FAMILY_CONDITION_DOCUMENT_HASH')
            urls.add(doc['url'])
        cr.require(type(row['optionalDependencies']) is list and len(row['optionalDependencies']) <= 16,
            'FAMILY_CONDITION_DEPENDENCIES')
        dependencies = set()
        for dep in row['optionalDependencies']:
            cr.fields(dep, {'name', 'minimum', 'use', 'requiredForCoreDriverProven'}, 'FAMILY_CONDITION_DEPENDENCY_FIELDS')
            cr.label(dep['name'])
            cr.label(dep['minimum'])
            key = (dep['name'], dep['minimum'], dep['use'])
            cr.require(dep['use'] in {'DOCUMENTATION_ONLY', 'OPTIONAL_PROGRAMMING_INTERFACE_ONLY'} and
                dep['requiredForCoreDriverProven'] is False and key not in dependencies,
                'FAMILY_CONDITION_OPTIONAL_DEPENDENCY')
            dependencies.add(key)
        cr.require(type(row['excludedHardwareGroups']) is list and len(row['excludedHardwareGroups']) <= 32 and
            len(set(row['excludedHardwareGroups'])) == len(row['excludedHardwareGroups']), 'FAMILY_CONDITION_EXCLUSIONS')
        for group in row['excludedHardwareGroups']:
            cr.label(group)
        seen.add(identifier)
        products.update(expected)
    return dict(schema='dc-collector-family-condition-evaluation-v1', registrySha256=cr.digest(cr.json_bytes(registry)),
        familyConditionsSha256=cr.digest(cr.json_bytes(value)), researchOnly=True, publishable=False,
        installAuthorized=False, scope='DISTRIBUTION_FAMILY_DOCUMENTATION_NOT_RELEASE_VERIFICATION',
        familyDocumentedRecords=len(seen), linkedResearchProducts=len(products), releaseVersionsConfirmed=0,
        accessConditionsConfirmed=0, contentsVerified=0, deviceApplicable=0, nativeConnected=False)
