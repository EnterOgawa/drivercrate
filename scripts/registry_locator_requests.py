"""公開locator限定監視の要求結合・用途保留を非通信で生成する（ADR 0236）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
基底要求は検証済み台帳のmake_requests出力。通信・同意・公開権限を発行しない。
"""

from __future__ import annotations

import collector_registry as cr
import collector_public_locators as pl


HOLD_REASONS = {"NATIVE_COORDINATION_PENDING", "CONSENT_REQUIRED", "ACCESS_UNRESOLVED",
                "PAYLOAD_APPROVAL_REQUIRED"}
HOLD_PRIORITY = {None: 0, "PAYLOAD_APPROVAL_REQUIRED": 1, "CONSENT_REQUIRED": 2,
                 "ACCESS_UNRESOLVED": 3, "NATIVE_COORDINATION_PENDING": 4}


def locator_requests(registry: dict, locators: dict, policy: dict, base_requests: list[dict]) -> list[dict]:
    """検証済み基底要求へlocatorを結合し、locator限定の保留付き要求を返す。"""
    locators = pl.validate_locators(locators, registry)
    held_sources = set(policy["heldSourceIds"])
    combined = {}
    for row in base_requests:
        cr.require(row["id"] == cr.digest((row["kind"] + "\n" + row["url"]).encode("utf-8")),
                   "LOCATOR_REQUEST_ID")
        item = {**row, "sourceIds": set(row["sourceIds"]), "recordIds": set(row["recordIds"]),
                "productIds": set(row["productIds"]), "expectedLinks": set(row["expectedLinks"]),
                "locatorIds": set(), "holdReason": "NATIVE_COORDINATION_PENDING" if row["held"] else None}
        combined[row["id"]] = item
    by_locator = {row["id"]: row for row in locators["locators"]}
    for locator in locators["locators"]:
        kind = "PAGE" if locator["purpose"] == "PAGE" else "LINK"
        key = cr.digest((kind + "\n" + locator["url"]).encode("utf-8"))
        item = combined.setdefault(key, {"id": key, "kind": kind, "url": locator["url"],
            "sourceIds": set(), "recordIds": set(), "productIds": set(), "expectedLinks": set(),
            "held": False, "locatorIds": set(), "holdReason": None})
        item["sourceIds"].add(locator["sourceId"])
        item["recordIds"].update(locator["recordIds"])
        item["productIds"].update(locator["productIds"])
        item["locatorIds"].add(locator["id"])
        reason = None
        if locator["sourceId"] in held_sources:
            reason = "NATIVE_COORDINATION_PENDING"
        elif kind == "LINK":
            reason = locator["requestCondition"] if locator["requestCondition"] != "NO_EXTRA_PROMPT_OBSERVED" else (
                "PAYLOAD_APPROVAL_REQUIRED")
        if HOLD_PRIORITY[reason] > HOLD_PRIORITY[item["holdReason"]]:
            item["holdReason"] = reason
        item["held"] |= reason is not None
        # 登録された子URLを観測hashへ結合するだけで、自動追従しない。
        for parent_id in locator["parentPageIds"]:
            parent = by_locator[parent_id]
            parent_key = cr.digest(("PAGE\n" + parent["url"]).encode("utf-8"))
            # 入力順によらず全parentの存在を確保し、後のrow結合へ引き継ぐ。
            parent_item = combined.setdefault(parent_key, {"id": parent_key, "kind": "PAGE", "url": parent["url"],
                "sourceIds": set(), "recordIds": set(), "productIds": set(), "expectedLinks": set(),
                "held": False, "locatorIds": set(), "holdReason": None})
            parent_item["expectedLinks"].add(cr.digest(locator["url"].encode("utf-8")))
    result = []
    for _, item in sorted(combined.items()):
        if not item["locatorIds"]:
            continue
        for name in ("sourceIds", "recordIds", "productIds", "expectedLinks", "locatorIds"):
            item[name] = sorted(item[name])
        result.append(item)
    pages = {row["url"] for row in result if row["kind"] == "PAGE"}
    payloads = {row["url"] for row in base_requests if row["kind"] == "LINK"}
    payloads.update(row["url"] for row in result if row["kind"] == "LINK")
    cr.require(not pages & payloads, "LOCATOR_MONITOR_PURPOSE_COLLISION")
    return result
