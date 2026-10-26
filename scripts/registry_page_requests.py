"""全登録公式PAGEの要求を生成する（ADR 0293）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
共通台帳・locatorの検証と待機を維持し、PAYLOAD要求は一つも返さない。
"""
from __future__ import annotations

import collector_registry as cr
import collector_public_locators as pl
from registry_locator_requests import locator_requests


def page_requests(registry: dict, locators: dict, policy: dict, base_requests: list[dict]) -> list[dict]:
    """全取得元の公式PAGEと登録PAGE locatorを、URL単位で重複なく返す。"""
    registry = cr.validate_registry(registry)
    locators = pl.validate_locators(locators, registry)
    # 限定経路の衝突・graph検証を共用し、旧モードの範囲を変更しない。
    limited = locator_requests(registry, locators, policy, base_requests)
    combined = {row['id']: {**row, 'locatorIds': [],
        'holdReason': 'NATIVE_COORDINATION_PENDING' if row['held'] else None}
        for row in base_requests if row['kind'] == 'PAGE'}
    for row in limited:
        if row['kind'] == 'PAGE':
            combined[row['id']] = row
    payloads = {row['downloadUrl'] for row in registry['records'] if row['downloadUrl'] is not None}
    payloads.update(row['url'] for row in locators['locators'] if row['purpose'] == 'PAYLOAD')
    cr.require(not {row['url'] for row in combined.values()} & payloads, 'PAGE_MONITOR_PURPOSE_COLLISION')
    result = [combined[key] for key in sorted(combined)]
    cr.require({sid for row in result for sid in row['sourceIds']} ==
        {row['id'] for row in registry['sources']}, 'PAGE_MONITOR_SOURCE_COVERAGE')
    cr.require(all(row['kind'] == 'PAGE' for row in result), 'PAGE_MONITOR_PAYLOAD')
    return result
