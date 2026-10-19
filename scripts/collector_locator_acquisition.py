"""台帳／公開locator／導出根拠を代表二GET planと独立取得証拠へ結合する（ADR 0302）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
非通信validatorであり、任意query・POST・同意・install・公開を許可しない。
"""
import argparse
from pathlib import Path
from urllib.parse import urlsplit

import collector_registry as cr
import collector_public_locators as pl
import collector_literal_downloads as literal
import collector_payload_evidence as pe

PLAN_SCHEMA = 'dc-locator-sample-acquisition-plan-v4'
EVIDENCE_SCHEMA = 'dc-locator-payload-evidence-v1'


def validate_plan(registry, locators, proof, plan):
    """選択recordと全page／action根拠・予算を照合し、限定URL集合を返す。"""
    registry = cr.validate_registry(registry)
    locators = pl.validate_locators(locators, registry)
    cr.fields(plan, {'schema', 'revision', 'registrySha256', 'locatorsSha256', 'derivationsSha256',
        'maximumTotalBytes', 'maximumRequests', 'items'}, 'LOCATOR_PLAN_FIELDS')
    cr.require(plan['schema'] == PLAN_SCHEMA and plan['registrySha256'] == cr.digest(cr.json_bytes(registry)) and
        plan['locatorsSha256'] == cr.digest(cr.json_bytes(locators)) and
        plan['derivationsSha256'] == cr.digest(cr.json_bytes(proof)), 'LOCATOR_PLAN_BINDING')
    cr.identity(plan['revision'])
    cr.require(type(plan['maximumTotalBytes']) is int and 0 < plan['maximumTotalBytes'] <= 32 * 1024**2 and
        type(plan['maximumRequests']) is int and 0 < plan['maximumRequests'] <= 2 and
        type(plan['items']) is list and 0 < len(plan['items']) <= plan['maximumRequests'], 'LOCATOR_PLAN_BUDGET')
    cr.require(proof['schema'] == 'dc-literal-download-derivations-v1' and proof['researchOnly'] is True and
        all(proof[key] is False for key in ('publishable', 'installAuthorized', 'nativeConnected')) and
        proof['method'] == literal.METHOD and proof['payloadRequests'] == proof['postRequests'] == 0,
        'LOCATOR_DERIVATION_AUTHORITY')
    records, products, sources = ({row['id']: row for row in registry[name]} for name in ('records', 'products', 'sources'))
    by_id = {row['id']: row for row in locators['locators']}
    seen, budget, urls = set(), 0, []
    for item in plan['items']:
        cr.fields(item, {'recordId', 'locatorId', 'format', 'maximumBytes', 'preDownloadConsent'}, 'LOCATOR_PLAN_ITEM')
        record_id = cr.identity(item['recordId'])
        cr.require(record_id not in seen and record_id in records and item['format'] in {'ZIP', 'EXE'} and
            item['preDownloadConsent'] == 'NO_GATE_OBSERVED_IN_PAGE_FUNCTION' and type(item['maximumBytes']) is int and
            0 < item['maximumBytes'] <= (16 if item['format'] == 'ZIP' else 8) * 1024**2, 'LOCATOR_PLAN_ITEM_POLICY')
        seen.add(record_id)
        budget += item['maximumBytes']
        locator = by_id.get(item['locatorId'])
        cr.require(locator is not None and locator['purpose'] == 'PAYLOAD' and locator['recordIds'] == [record_id] and
            locator['urlProfile'] == 'PUBLIC_DOWNLOAD_FILE_PATH' and locator['requestCondition'] == 'ACCESS_UNRESOLVED' and
            locator['publicationCondition'] == 'REVIEW_REQUIRED', 'LOCATOR_PLAN_PURPOSE')
        record = records[record_id]
        entries = [row for row in proof['entries'] if row['recordId'] == record_id]
        cr.require(len(entries) == 1, 'LOCATOR_PROOF_RECORD')
        entry = entries[0]
        cr.require(entry['url'] == locator['url'] and entry['urlProfile'] == locator['urlProfile'] and
            entry['productIds'] == locator['productIds'] and entry['operatingSystems'] == record['operatingSystems'] and
            all(entry[key] is False for key in ('requestAuthorized', 'httpObserved', 'payloadDownloaded',
                'preNavigationPostExecuted')), 'LOCATOR_PROOF_BINDING')
        suffix = '.zip' if item['format'] == 'ZIP' else '.exe'
        cr.require(locator['url'].endswith(suffix), 'LOCATOR_PAYLOAD_FORMAT')
        evidence_products, evidence_pages = set(), set()
        for evidence in entry['evidence']:
            product = products.get(evidence['productId'])
            parents = [by_id[key] for key in locator['parentPageIds'] if by_id[key]['url'] == evidence['page']]
            cr.require(product is not None and len(parents) == 1 and record_id in product['recordIds'] and
                evidence['productId'] in parents[0]['productIds'] and record_id in parents[0]['recordIds'] and
                evidence['reviewMethod'] == 'MANUAL_FUNCTION_REVIEW' and evidence['originalBodyReparsed'] is False and
                evidence['automaticInlineBlockParseMatched'] is False, 'LOCATOR_PROOF_PAGE')
            page_observation = parents[0]['pageObservation']
            cr.require(page_observation['bodySha256'] == evidence['bodySha256'] and
                page_observation['checkedAt'] == evidence['observedAt'], 'LOCATOR_PROOF_OBSERVATION')
            cr.sha256(evidence['receiptSha256'])
            cr.require(evidence['receiptSha256'] is not None and
                evidence['transfer']['model'] == product['model'] and
                literal.derive_url(evidence['page'], evidence['action'], evidence['transfer']) == locator['url'],
                'LOCATOR_PROOF_TRANSFER')
            source = sources[record['sourceId']]
            cr.require(urlsplit(source['officialPage']).netloc == urlsplit(evidence['page']).netloc,
                'LOCATOR_PLAN_ORIGIN')
            evidence_products.add(evidence['productId'])
            evidence_pages.add(parents[0]['id'])
        cr.require(evidence_products == set(locator['productIds']) and evidence_pages == set(locator['parentPageIds']),
            'LOCATOR_PROOF_CLOSED_GRAPH')
        urls.append(dict(recordId=record_id, locatorId=locator['id'], url=locator['url']))
    cr.require(budget <= plan['maximumTotalBytes'], 'LOCATOR_PLAN_TOTAL_BUDGET')
    return dict(planSha256=cr.digest(cr.json_bytes(plan)), payloadUrls=urls)


def validate_evidence(registry, locators, proof, plan, evidence):
    """有限取得の独立証拠を旧row規則へ結合し、台帳metadataを変更しない。"""
    validated = validate_plan(registry, locators, proof, plan)
    cr.fields(evidence, {'schema', 'planSha256', 'registrySha256', 'asOf', 'acquisitions'}, 'LOCATOR_EVIDENCE_FIELDS')
    cr.require(evidence['schema'] == EVIDENCE_SCHEMA and evidence['planSha256'] == validated['planSha256'] and
        evidence['registrySha256'] == plan['registrySha256'], 'LOCATOR_EVIDENCE_BINDING')
    rows = evidence['acquisitions']
    cr.require(type(rows) is list and len(rows) == len(plan['items']) and
        {row['recordId'] for row in rows} == {item['recordId'] for item in plan['items']}, 'LOCATOR_EVIDENCE_SET')
    for row in rows:
        cr.fields(row, pe.ROW_FIELDS, 'LOCATOR_ACQUISITION_FIELDS')
        item = next(item for item in plan['items'] if item['recordId'] == row['recordId'])
        cr.require(row['bytes'] <= item['maximumBytes'], 'LOCATOR_ACQUISITION_BUDGET')
        # 旧rowのfield集合を再利用するが、URL必須の旧台帳や観測を捏造して通さない。
        if row['state'] == 'DOWNLOADED':
            cr.require(row['httpStatus'] == 200 and type(row['bytes']) is int and row['bytes'] > 0 and
                row['sha256'] is not None and row['reason'] == 'NONE', 'LOCATOR_DOWNLOAD_STATE')
        else:
            cr.require(row['bytes'] == 0 and row['sha256'] is None and row['reason'] != 'NONE' and
                row['inspection'] == 'NOT_CHECKED' and row['outerSignature'] == 'NOT_CHECKED', 'LOCATOR_FAILURE_STATE')
        cr.sha256(row['sha256'])
        cr.sha256(row['inspectorSha256'])
        cr.require(cr.timestamp(registry['asOf']) <= cr.timestamp(row['checkedAt']) <= cr.timestamp(evidence['asOf']),
            'LOCATOR_ACQUISITION_TIME')
        cr.require(row['state'] in {'DOWNLOADED', 'FAILED'} and row['outerSignature'] in
            {'NOT_CHECKED', 'VALID', 'UNSIGNED', 'INVALID'} and row['inspection'] in
            {'NOT_CHECKED', 'UNSUPPORTED', 'PASSED', 'PARTIAL', 'REJECTED'}, 'LOCATOR_RESULT_STATE')
        cr.require(row['outerSignature'] != 'VALID' or row['publisher'] is not None, 'LOCATOR_SIGNER')
        cr.require(row['outerSignature'] != 'NOT_CHECKED' or row['publisher'] is None, 'LOCATOR_UNCHECKED_SIGNER')
        if row['publisher'] is not None:
            cr.label(row['publisher'])
        cr.require(row['reason'] in {'NONE', 'TRANSFER_FAILED', 'PAYLOAD_SIZE', 'PAYLOAD_TYPE',
            'PUBLISHED_HASH_MISMATCH', 'INPUT_CHANGED', 'PRIVATE_DNS', 'DNS_EMPTY', 'DNS_FAMILY',
            'URL_POLICY', 'OBSERVATION_FAILED'}, 'LOCATOR_RESULT_REASON')
        for key in ('verifiedInfs', 'rejectedInfs', 'inventoryFiles'):
            cr.require(type(row[key]) is int and row[key] >= 0, 'LOCATOR_INSPECTION_COUNTS')
        if row['inspection'] in {'PASSED', 'PARTIAL', 'REJECTED'}:
            cr.require(row['state'] == 'DOWNLOADED' and row['inspectorSha256'] is not None and
                type(row['inspectionExitCode']) is int, 'LOCATOR_INSPECTION_BINDING')
        if row['inspection'] == 'PASSED':
            cr.require(row['inspectionExitCode'] == 0 and row['verifiedInfs'] > 0 and row['rejectedInfs'] == 0,
                'LOCATOR_INSPECTION_PASSED')
        elif row['inspection'] == 'PARTIAL':
            cr.require(row['verifiedInfs'] > 0 and row['rejectedInfs'] > 0, 'LOCATOR_INSPECTION_PARTIAL')
        elif row['inspection'] == 'REJECTED':
            cr.require(row['verifiedInfs'] == 0 and row['inspectionExitCode'] != 0, 'LOCATOR_INSPECTION_REJECTED')
        else:
            cr.require(row['inspectorSha256'] is None and row['inspectionExitCode'] is None and
                row['verifiedInfs'] == row['rejectedInfs'] == row['inventoryFiles'] == 0, 'LOCATOR_UNINSPECTED')
        cr.require(row['inventoryFiles'] >= row['verifiedInfs'] + row['rejectedInfs'], 'LOCATOR_INVENTORY_COUNTS')
    return evidence


def main():
    """共通PSへ非通信の限定URL集合またはevidence検証結果だけを返す。"""
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('plan', 'evidence'))
    for name in ('registry', 'locators', 'derivations', 'input'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    values = [cr.read_json(getattr(args, name)) for name in ('registry', 'locators', 'derivations', 'input')]
    if args.mode == 'plan':
        print(cr.json_bytes(validate_plan(*values)).decode(), end='')
    else:
        cr.require(args.evidence is not None, 'LOCATOR_EVIDENCE_REQUIRED')
        validate_evidence(*values, cr.read_json(args.evidence))
        print('VALID')


if __name__ == '__main__':
    main()
