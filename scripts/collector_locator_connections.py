"""共通台帳と公開locatorの研究用接続情報を非通信で再構築する（ADR 0292）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
通信・同意・本体取得・端末適合・導入許可は発行しない。
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import collector_registry as cr
import collector_public_locators as pl


def connection_index(registry: dict, locators: dict) -> dict:
    """全recordへ直接URLと0個以上の公開locatorを結合し、未確認も残す。"""
    registry = cr.validate_registry(registry)
    locators = pl.validate_locators(locators, registry)
    products = {}
    for product in registry['products']:
        for record_id in product['recordIds']:
            products.setdefault(record_id, []).append(product['id'])
    payloads = {}
    for locator in locators['locators']:
        if locator['purpose'] == 'PAYLOAD':
            record_id = locator['recordIds'][0]
            payloads.setdefault(record_id, []).append({key: locator[key] for key in
                ('id', 'url', 'urlProfile', 'requestCondition', 'publicationCondition')})
    rows = []
    known_records = set()
    for record in registry['records']:
        choices = sorted(payloads.get(record['id'], []), key=lambda row: row['id'])
        direct = record['downloadUrl']
        if direct is not None or choices:
            known_records.add(record['id'])
        rows.append(dict(recordId=record['id'], recordSha256=cr.digest(cr.json_bytes(record)),
            sourceId=record['sourceId'], productIds=sorted(products[record['id']]),
            directUrl=direct, publicLocatorChoices=choices,
            referenceState='LOCATED' if record['id'] in known_records else 'NOT_LOCATED',
            contentVerified=False, deviceApplicability='NOT_CHECKED', installAuthorized=False))
    return dict(schema='dc-research-locator-connections-v1', revision=registry['revision'],
        asOf=locators['asOf'], registrySha256=cr.digest(cr.json_bytes(registry)),
        locatorsSha256=cr.digest(cr.json_bytes(locators)), researchOnly=True,
        publishable=False, installAuthorized=False, productConnected=False,
        counts=dict(distributionRecords=len(rows),
            recordsWithDirectUrls=sum(row['directUrl'] is not None for row in rows),
            recordsWithLocatorOnly=sum(row['directUrl'] is None and bool(row['publicLocatorChoices']) for row in rows),
            recordsWithAnyPublicReference=len(known_records),
            recordsWithoutPublicReference=len(rows) - len(known_records),
            productsWithAnyPublicReference=sum(bool(set(product['recordIds']) & known_records)
                for product in registry['products']),
            payloadLocatorChoices=sum(len(row['publicLocatorChoices']) for row in rows),
            recordsWithMultipleLocatorChoices=sum(len(row['publicLocatorChoices']) > 1 for row in rows),
            payloadRequestsAuthorized=0, contentsVerified=0, deviceApplicabilityMeasured=0),
        records=rows)


def validate_connections(value: object, registry: dict, locators: dict) -> dict:
    """元世代と用途条件からの再生成に完全一致する接続情報だけを受理する。"""
    expected = connection_index(registry, locators)
    cr.require(type(value) is dict and value == expected and
        cr.json_bytes(value) == cr.json_bytes(expected), 'LOCATOR_CONNECTION_BINDING')
    cr.require(len(cr.json_bytes(expected)) <= cr.MAX_JSON_BYTES, 'LOCATOR_CONNECTION_SIZE')
    return expected


def main() -> int:
    """新規fileへ研究用接続情報を保存し、通常logへ公開URLを出力しない。

    排他的な保存に失敗しても、作成済みfileは自動削除しない。残った既存出力は上書きせず拒否する。
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--locators', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        registry = cr.read_json(args.registry)
        locators = cr.read_json(args.locators)
        value = connection_index(registry, locators)
        validate_connections(value, registry, locators)
        cr.require(not args.output.exists(), 'OUTPUT_EXISTS')
        cr.check_ancestors(args.output)
        with args.output.open('xb') as stream:
            stream.write(cr.json_bytes(value))
        print(cr.json_bytes(value['counts']).decode('utf-8'), end='')
        return 0
    except (cr.RegistryError, OSError) as error:
        print('REJECTED:' + (str(error) if isinstance(error, cr.RegistryError) else 'IO_ERROR'), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
