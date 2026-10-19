"""過去取得bindingの登録済み有限matrixを架空byteだけで検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実台帳、network、archive／INF解析、署名認定、導入を行わない。
"""

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_public_locators as pl
import collector_route_acquisition_bindings as rb


STATS = {"positiveCases": 0, "rejectionCases": 0, "assertionChecks": 0, "copyRoundTrips": 0}
NOW = "2026-10-11T00:00:00Z"
OBSERVED = "2026-10-10T00:00:00.123456Z"
ACQUIRED = "2026-10-10T00:00:01.123456Z"
PREFIX = "https://cdn.example.org/download/file?id="


def pin(raw):
    """架空byteの固定size／hashを返す。"""
    return {"bytes": len(raw), "sha256": cr.digest(raw)}


def identity(document):
    """正規化済み架空documentの世代参照を返す。"""
    return {key: document[key] for key in ("schema", "revision", "asOf")} | {"sha256": cr.digest(cr.json_bytes(document))}


def receipt(raw, url, observed=OBSERVED):
    """実通信を伴わない原receipt byteを作る。"""
    return cr.json_bytes({"status": 200, "exitCode": 0, "timedOut": False, "outputLimitStopped": False,
                          "completedAtUtc": observed, "url": url, "bodyPin": pin(raw)})


def fixture(count=1, legacy_record=False, reused_roles=()):
    """一／二familyの独立した架空registry／locator／bindingと原byteを返す。"""
    registry = {"schema": cr.REGISTRY_SCHEMA, "revision": "fictional-registry-01", "asOf": NOW,
                "sources": [], "products": [], "records": [], "observations": []}
    locators = {"schema": pl.LOCATOR_SCHEMA, "revision": "fictional-locators-01", "asOf": NOW,
                "researchOnly": True, "publishable": False, "installAuthorized": False, "locators": []}
    rows = []
    originals = {}
    for number in range(1, count + 1):
        suffix = str(number)
        sid, oldsid, rid, pid = [value + suffix for value in ("source-new-", "source-old-", "record-", "product-")]
        page = "https://vendor.example.org/downloads/EXAMPLE" + suffix + "SER_ZIP.html"
        oldpage = "https://vendor.example.org/downloads/EXAMPLE" + suffix + "CDC_ZIP.html"
        metadata_url = "https://api.example.org/relationFiles?fileName=EXAMPLE" + suffix + "SER_ZIP.html"
        main = {"code": 0, "id": 40 + number, "name": "EXAMPLE" + suffix + "SER.ZIP", "categoryId": 67,
                "auth": "0", "redirect": None, "fullUrl": None, "githubDownloadUrl": "", "version": "2.0",
                "uploadTime": "2026-09-01", "scope": "ExampleModel" + suffix}
        bodies = {"landing": b"fictional landing", "app": b"fictional resource route webpack",
                  "chunk10": b"relationFiles anchor " + PREFIX.encode("ascii"),
                  "metadata": cr.json_bytes({"code": 0, "data": {key: value for key, value in main.items() if key != "code"}})}
        urls = {"landing": page, "metadata": metadata_url, "app": "https://vendor.example.org/js/app.js",
                "chunk10": "https://vendor.example.org/js/10.chunk.js"}
        observations = {}
        declared = {}
        for role, body in bodies.items():
            raw = receipt(body, urls[role])
            observations[role] = {"bodyBytes": body, "receiptBytes": raw, "receiptPin": pin(raw)}
            declared[role] = {"url": urls[role], "observedAt": OBSERVED, **pin(body), "originalReceiptSha256": pin(raw)["sha256"]}
            if role in {"app", "chunk10"}:
                reused = role in reused_roles
                declared[role].update(role=role, checkedAt=ACQUIRED if reused else OBSERVED,
                                      reused=reused, sourceAgeSeconds=1 if reused else 0)
        ranges = {}
        for name, role in (("resourceRoute", "app"), ("webpackPath", "app"),
                           ("relationFilesClient", "chunk10"), ("chineseDownloadAnchor", "chunk10")):
            ranges[name] = {"startByteOffset": 0, "endByteOffset": len(bodies[role]), **pin(bodies[role])}
        proof = {role + "Pin": pin(body) for role, body in bodies.items()}
        proof.update(ranges=ranges, mainRecordFields={key: main[key] for key in
                     ("id", "name", "auth", "categoryId", "version", "uploadTime", "scope")}, currentRouteChecked=False)
        if reused_roles:
            proof["reuseBinding"] = {"checkedAtUtc": ACQUIRED, "reusedScripts": [
                {"role": role, "originalUrl": urls[role], "originalObservedAtUtc": OBSERVED,
                 "pin": pin(bodies[role]), "sourceAgeSeconds": 1} for role in reused_roles]}
        proof_raw = cr.json_bytes(proof)
        payload = b"fictional historical body " + suffix.encode("ascii")
        acquired = receipt(payload, PREFIX + str(main["id"]), ACQUIRED)
        record = {"id": rid, "sourceId": sid, "title": "Example serial driver " + suffix, "driverCategory": "SERIAL",
                  "operatingSystems": ["WINDOWS_11_X64"], "packageVersion": "2.0", "driverVersion": "2.0.2026.01",
                  "publishedDate": "2026-09-01", "downloadUrl": None, "linkState": "MISSING",
                  "publishedSha256": None, "contentState": "NOT_DOWNLOADED"}
        registry["sources"].extend([{"id": source, "manufacturer": "Example", "officialPage": url,
                                     "collectionMethod": "MANUAL_RESEARCH"} for source, url in ((sid, page), (oldsid, oldpage))])
        registry["records"].append(record)
        product = {"id": pid, "manufacturer": "Example", "model": main["scope"], "driverCategory": "SERIAL",
                   "sourceIds": [sid, oldsid], "recordIds": [rid], "researchState": "METADATA_SAVED", "reason": "NONE"}
        registry["products"].append(product)
        observation = {"id": "observation-" + suffix, "productId": pid, "recordId": rid,
                       "checkedAt": "2026-10-10T00:00:00Z", "kind": "OFFICIAL_PAGE", "method": "LOCAL_HTTP",
                       "evidenceUrl": page, "httpStatus": 200, "evidenceSha256": pin(bodies["landing"])["sha256"]}
        registry["observations"].append(observation)
        oldrid = None
        oldurl = oldpage
        if legacy_record:
            oldrid = "legacy-record-" + suffix
            oldurl = "https://vendor.example.org/files/LEGACY" + suffix + ".ZIP"
            registry["records"].append(record | {"id": oldrid, "sourceId": oldsid, "downloadUrl": oldurl, "linkState": "OFFICIAL_LINK"})
            product["recordIds"].append(oldrid)
            registry["observations"].append(observation | {"id": "legacy-observation-" + suffix,
                "recordId": oldrid, "kind": "OFFICIAL_LINK", "evidenceUrl": oldpage})
        root = {"id": "page-" + suffix, "sourceId": sid, "purpose": "PAGE", "url": page, "urlProfile": "QUERYLESS",
                "productIds": [pid], "recordIds": [rid], "parentPageIds": [], "requestCondition": "PUBLIC_METADATA",
                "publicationCondition": "REVIEW_REQUIRED", "pageObservation": {"method": "LOCAL_HTTP", "httpStatus": 200,
                "bodyBytes": len(bodies["landing"]), "bodySha256": pin(bodies["landing"])["sha256"], "checkedAt": "2026-10-10T00:00:00Z"}}
        locator = root | {"id": "payload-" + suffix, "purpose": "PAYLOAD", "url": PREFIX + str(main["id"]),
                          "urlProfile": "PUBLIC_NUMERIC_ID", "parentPageIds": [root["id"]],
                          "requestCondition": "ACCESS_UNRESOLVED", "pageObservation": None}
        locators["locators"].extend([root, locator])
        binding_id = "binding-" + suffix
        family = "example-family-" + suffix
        row = {"id": binding_id, "familyKey": family, "recordId": rid, "recordSha256": cr.digest(cr.json_bytes(record)),
               "locatorId": locator["id"], "locatorSha256": cr.digest(cr.json_bytes(locator)), "productIds": [pid],
               "provenance": {"boundAt": NOW, "originalProofSha256": pin(proof_raw)["sha256"], "landing": declared["landing"],
               "metadata": declared["metadata"], "scripts": [declared["app"], declared["chunk10"]], "mainRecord": main, "literalCdnPrefix": PREFIX},
               "acquisition": {"originalReceiptSha256": pin(acquired)["sha256"], "observedAt": ACQUIRED, "httpStatus": 200,
                               **pin(payload), "signature": "NOT_CHECKED", "content": "NOT_CHECKED"},
               "infDisplay": {"driverVersion": "2.0.2026.01", "driverDate": "2026-01-01", "inventoryEntries": 3, "inspection": "NOT_CHECKED"},
               "waitAliases": {"familyKey": family, "waitState": "UNKNOWN", "hostState": "HELD", "eulaState": "UNKNOWN",
               "requests": [{"kind": "LEGACY", "sourceId": oldsid, "recordId": oldrid, "url": oldurl},
                 *[{"kind": kind, "sourceId": sid, "recordId": rid, "url": url} for kind, url in
                   (("PAGE", page), ("METADATA", metadata_url), ("PAYLOAD", locator["url"]))]]}, "requestAuthorized": False}
        rows.append(row)
        originals[binding_id] = {"proofBytes": proof_raw, "proofPin": pin(proof_raw), "receiptBytes": acquired,
                                "receiptPin": pin(acquired), "payloadBytes": payload, "observations": observations}
    registry = cr.validate_registry(registry)
    locators["registry"] = pl.registry_binding(registry)
    locators = pl.validate_locators(locators, registry)
    for row in rows:
        row["recordSha256"] = cr.digest(cr.json_bytes(next(item for item in registry["records"] if item["id"] == row["recordId"])))
        row["locatorSha256"] = cr.digest(cr.json_bytes(next(item for item in locators["locators"] if item["id"] == row["locatorId"])))
    bindings = {"schema": rb.SCHEMA, "revision": "fictional-bindings-01", "asOf": NOW,
                "registryBinding": identity(registry), "locatorsBinding": identity(locators), "researchOnly": True,
                "publishable": False, "installAuthorized": False, "nativeConnected": False, "bindings": rows}
    return registry, locators, bindings, originals


def set_path(args, path, value):
    """独立fixtureの指定値だけを変更する。"""
    selected = args
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = value


def update_proof(args, change):
    """変更した架空proofを外側pinにも再結合して内側検査へ到達させる。"""
    original = args[3]["binding-1"]
    proof = cr.parse_json(original["proofBytes"])
    change(proof)
    # 非有限constantの拒否例を原raw JSONへ渡し、公開JSON生成の成功とは扱わない。
    original["proofBytes"] = (json.dumps(proof, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=True) + "\n").encode("utf-8")
    original["proofPin"] = pin(original["proofBytes"])
    args[2]["bindings"][0]["provenance"]["originalProofSha256"] = original["proofPin"]["sha256"]


def update_receipt(args, role, change):
    """変更した架空原receiptの外側pinと選抜観測pinを再結合する。"""
    original = args[3]["binding-1"]
    target = original if role == "payload" else original["observations"][role]
    parsed = cr.parse_json(target["receiptBytes"])
    change(parsed)
    target["receiptBytes"] = cr.json_bytes(parsed)
    target["receiptPin"] = pin(target["receiptBytes"])
    provenance = args[2]["bindings"][0]["provenance"]
    declared = args[2]["bindings"][0]["acquisition"] if role == "payload" else (
        provenance[role] if role in {"landing", "metadata"} else next(item for item in provenance["scripts"] if item["role"] == role))
    declared["originalReceiptSha256"] = target["receiptPin"]["sha256"]


def update_main(args, key, value, related_only=False):
    """主rawと選抜値・proofを共に変更し、型／scope検査を直接試験する。"""
    row = args[2]["bindings"][0]
    target = args[3]["binding-1"]["observations"]["metadata"]
    parsed = cr.parse_json(target["bodyBytes"])
    if related_only:
        parsed["data"]["relationFileList"] = [copy.deepcopy(parsed["data"])]
        parsed["data"][key] = value
    else:
        row["provenance"]["mainRecord"][key] = value
        parsed["code" if key == "code" else "data"] = value if key == "code" else parsed["data"]
        if key != "code":
            parsed["data"][key] = value
    target["bodyBytes"] = cr.json_bytes(parsed)
    update_receipt(args, "metadata", lambda raw: raw.update(bodyPin=pin(target["bodyBytes"])))
    row["provenance"]["metadata"].update(pin(target["bodyBytes"]))
    def change(proof):
        proof["metadataPin"] = pin(target["bodyBytes"])
        if key in proof["mainRecordFields"] and not related_only:
            proof["mainRecordFields"][key] = value
    update_proof(args, change)


class BindingMatrixTests(unittest.TestCase):
    """登録済みカテゴリの有限subTestと明示assertionだけを実行する。"""

    def setUp(self):
        self.network_guards = [patch(name, side_effect=AssertionError("NETWORK_FORBIDDEN")) for name in
            ("socket.getaddrinfo", "socket.create_connection", "http.client.HTTPSConnection.connect")]
        for guard in self.network_guards:
            guard.start()
            self.addCleanup(guard.stop)

    def check(self, condition):
        STATS["assertionChecks"] += 1
        self.assertTrue(condition)

    def accepted(self, args, byte_input=False):
        before = copy.deepcopy(args)
        result = rb.validate_bindings(args[0], args[1], cr.json_bytes(args[2]) if byte_input else args[2], args[3])
        STATS["positiveCases"] += 1
        self.check(result == args[2] and result is not args[2])
        self.check(args == before)
        result["bindings"][0]["productIds"].append("output-only")
        self.check(args == before)

    def rejected(self, args, byte_input=False):
        before = copy.deepcopy(args)
        with self.assertRaises(cr.RegistryError) as captured:
            rb.validate_bindings(args[0], args[1], cr.json_bytes(args[2]) if byte_input else args[2], args[3])
        STATS["assertionChecks"] += 1
        STATS["rejectionCases"] += 1
        self.check(str(captured.exception).replace("_", "").isalnum() and "https" not in str(captured.exception))
        self.check(args == before)

    def test_positive_defined_combinations(self):
        for count in (1, 2):
            for legacy in (False, True):
                for reused in ((), ("app",), ("chunk10",), ("app", "chunk10")):
                    for byte_input in (False, True):
                        with self.subTest(count=count, legacy=legacy, reused=reused, byte_input=byte_input):
                            self.accepted(fixture(count, legacy, reused), byte_input)

    def test_closed_fields(self):
        paths = [(2,), (2, "bindings", 0), (2, "bindings", 0, "provenance"),
                 (2, "bindings", 0, "provenance", "landing"), (2, "bindings", 0, "provenance", "metadata"),
                 (2, "bindings", 0, "provenance", "scripts", 0), (2, "bindings", 0, "provenance", "mainRecord"),
                 (2, "bindings", 0, "acquisition"), (2, "bindings", 0, "infDisplay"),
                 (2, "bindings", 0, "waitAliases"), (2, "bindings", 0, "waitAliases", "requests", 0),
                 (3, "binding-1"), (3, "binding-1", "observations"), (3, "binding-1", "observations", "landing"),
                 (3, "binding-1", "proofPin"), (3, "binding-1", "receiptPin")]
        for path in paths:
            for change in ("extra", "missing", "wrong_type"):
                with self.subTest(path=path, change=change):
                    args = list(fixture())
                    target = args
                    for key in path:
                        target = target[key]
                    if change == "extra":
                        target["unknownField"] = True
                    elif change == "missing":
                        del target[next(iter(target))]
                    else:
                        set_path(args, path, [])
                    self.rejected(args)

    def test_document_identity_safety_and_counts(self):
        changes = [("schema", "wrong"), ("revision", ""), ("asOf", "2026-10-09T00:00:00Z"),
                   ("registryBinding", {}), ("locatorsBinding", {}), ("researchOnly", 1),
                   ("publishable", True), ("installAuthorized", True), ("nativeConnected", True),
                   ("bindings", []), ("bindings", None)]
        for key, value in changes:
            with self.subTest(key=key):
                args = fixture()
                args[2][key] = value
                self.rejected(args)
        args = fixture(2)
        args[2]["bindings"].append(copy.deepcopy(args[2]["bindings"][0]))
        self.rejected(args)
        for key in ("schema", "revision", "asOf", "sha256"):
            for kind in ("registryBinding", "locatorsBinding"):
                args = fixture()
                args[2][kind][key] = "changed"
                self.rejected(args)
        args = fixture()
        for raw in (b'{"schema":"one","schema":"two"}', b'{', b'[]'):
            with self.subTest(raw=raw):
                with self.assertRaises(cr.RegistryError):
                    rb.validate_bindings(args[0], args[1], raw, args[3])
                STATS["assertionChecks"] += 1
                STATS["rejectionCases"] += 1

    def test_references_duplicates_and_bundle_exact_set(self):
        for key in ("id", "familyKey", "recordId", "locatorId"):
            with self.subTest(duplicate=key):
                args = fixture(2)
                args[2]["bindings"][1][key] = args[2]["bindings"][0][key]
                self.rejected(args)
        for key, value in (("id", "absent-binding"), ("recordId", "absent-record"), ("locatorId", "absent-locator"),
                           ("recordSha256", "a"*64), ("locatorSha256", None), ("productIds", []),
                           ("productIds", ["absent-product"]), ("productIds", ["product-1", "product-1"]),
                           ("requestAuthorized", 0), ("requestAuthorized", True)):
            args = fixture()
            args[2]["bindings"][0][key] = value
            self.rejected(args)
        for mutation in ("extra", "missing", "wrong_type"):
            args = list(fixture())
            if mutation == "extra":
                args[3]["unreferenced"] = copy.deepcopy(args[3]["binding-1"])
            elif mutation == "missing":
                del args[3]["binding-1"]
            else:
                args[3] = []
            self.rejected(args)

    def test_times_fractional_z_and_ordering(self):
        for value in ("2026-10-11T00:00:00+00:00", "2026-10-11T00:00:00.1234567Z", "2026-02-30T00:00:00Z",
                      "2026-10-11T00:00:00", None, 0, "2026-10-09T00:00:00Z", "2026-10-12T00:00:00Z"):
            args = fixture()
            args[2]["bindings"][0]["provenance"]["boundAt"] = value
            self.rejected(args)
        for fraction in ("1", "12", "123", "1234", "12345", "123456"):
            args = fixture()
            value = "2026-10-10T00:00:01." + fraction + "Z"
            args[2]["bindings"][0]["acquisition"]["observedAt"] = value
            update_receipt(args, "payload", lambda raw: raw.update(completedAtUtc=value))
            self.accepted(args)
        for value in ("2026-10-10T00:00:00Z", "2026-10-12T00:00:00Z"):
            args = fixture()
            args[2]["bindings"][0]["acquisition"]["observedAt"] = value
            update_receipt(args, "payload", lambda raw: raw.update(completedAtUtc=value))
            self.rejected(args)

    def test_original_byte_pins_and_receipt_types(self):
        for role in ("payload", "landing", "metadata", "app", "chunk10"):
            for key, value in (("status", True), ("status", "200"), ("status", 403), ("exitCode", False),
                               ("exitCode", 1), ("timedOut", True), ("timedOut", 0),
                               ("outputLimitStopped", True), ("outputLimitStopped", 0),
                               ("completedAtUtc", "bad"), ("bodyPin", {"bytes": 1, "sha256": "a"*64})):
                with self.subTest(role=role, key=key, value=value):
                    args = fixture()
                    update_receipt(args, role, lambda raw: raw.update({key: value}))
                    self.rejected(args)
            for field in ("bytes", "sha256"):
                args = fixture()
                target = args[3]["binding-1"] if role == "payload" else args[3]["binding-1"]["observations"][role]
                target["receiptPin"][field] = True if field == "bytes" else None
                self.rejected(args)
            for raw in (b"", b"changed", bytearray(b"nonbytes"), b"x"*(rb.MAX_BODY_BYTES+1)):
                args = fixture()
                target = args[3]["binding-1"] if role == "payload" else args[3]["binding-1"]["observations"][role]
                target["payloadBytes" if role == "payload" else "bodyBytes"] = raw
                self.rejected(args)

    def test_raw_main_exact_selection_and_types(self):
        values = {"code": [True, "0", 1], "id": [True, 0, -1, 2147483648, "41", 41.0],
                  "categoryId": [True, "67", 68], "auth": [0, False, "1"],
                  "name": ["EXAMPLE1SER.exe", "example1ser.zip", "../EXAMPLE1SER.ZIP", "EXAMPLE1SER.ZIP?x=1"],
                  "redirect": ["https://other.example.org/file"], "fullUrl": ["https://other.example.org/file"],
                  "githubDownloadUrl": [None, "https://other.example.org/file"], "scope": ["WrongModel", "ExampleModel1,ExampleModel1", "", True],
                  "version": ["3.0"], "uploadTime": ["2026-09-02"]}
        for key, invalid in values.items():
            for value in invalid:
                with self.subTest(key=key, value=value):
                    args = fixture()
                    update_main(args, key, value)
                    self.rejected(args)
        args = fixture()
        update_main(args, "id", 99, related_only=True)
        self.rejected(args)
        args = fixture()
        args[2]["bindings"][0]["provenance"]["mainRecord"]["id"] = 99
        self.rejected(args)
        args = fixture()
        update_proof(args, lambda proof: proof["mainRecordFields"].update(id=99))
        self.rejected(args)

    def test_proof_ranges_offsets_pins_and_literal(self):
        for name in ("resourceRoute", "webpackPath", "relationFilesClient", "chineseDownloadAnchor"):
            for key, value in (("startByteOffset", True), ("startByteOffset", -1), ("endByteOffset", 0),
                               ("endByteOffset", 10000), ("endByteOffset", "3"), ("bytes", True), ("sha256", "a"*64)):
                args = fixture()
                update_proof(args, lambda proof: proof["ranges"][name].update({key: value}))
                self.rejected(args)
        for role in ("landing", "metadata", "app", "chunk10"):
            args = fixture()
            update_proof(args, lambda proof: proof[role+"Pin"].update(sha256="a"*64))
            self.rejected(args)
        args = fixture()
        fragment = args[3]["binding-1"]["observations"]["chunk10"]["bodyBytes"][:3]
        update_proof(args, lambda proof: proof["ranges"]["chineseDownloadAnchor"].update(endByteOffset=3, **pin(fragment)))
        self.rejected(args)
        for prefix in ("https://different.example.org/file?id=", "https://cdn.example.org/download/file?x=", "invalid", 1):
            args = fixture()
            args[2]["bindings"][0]["provenance"]["literalCdnPrefix"] = prefix
            self.rejected(args)

    def test_script_reuse_age_finite_and_identity(self):
        for age in (True, "0", -1, 31536001, float("nan"), float("inf"), -float("inf"), 10**1000):
            for reused in (False, True):
                with self.subTest(age=age, reused=reused):
                    args = fixture(reused_roles=("app", "chunk10") if reused else ())
                    args[2]["bindings"][0]["provenance"]["scripts"][0]["sourceAgeSeconds"] = age
                    self.rejected(args)
        for key, value in (("checkedAt", OBSERVED), ("checkedAt", "2026-10-12T00:00:00Z"), ("reused", 1),
                           ("role", "chunk10"), ("sourceAgeSeconds", 2)):
            args = fixture(reused_roles=("app", "chunk10"))
            args[2]["bindings"][0]["provenance"]["scripts"][0][key] = value
            self.rejected(args)
        for key, value in (("originalUrl", "https://other.example.org/app.js"), ("originalObservedAtUtc", ACQUIRED),
                           ("pin", {"bytes": 1, "sha256": "a"*64}), ("sourceAgeSeconds", float("inf")),
                           ("sourceAgeSeconds", float("nan")), ("sourceAgeSeconds", -float("inf")),
                           ("sourceAgeSeconds", 10**1000), ("sourceAgeSeconds", True)):
            args = fixture(reused_roles=("app",))
            update_proof(args, lambda proof: proof["reuseBinding"]["reusedScripts"][0].update({key: value}))
            self.rejected(args)
        for mutation in ("absent", "duplicate", "checkedAt"):
            args = fixture(reused_roles=("app",))
            def change(proof):
                if mutation == "absent":
                    del proof["reuseBinding"]
                elif mutation == "duplicate":
                    proof["reuseBinding"]["reusedScripts"] *= 2
                else:
                    proof["reuseBinding"]["checkedAtUtc"] = OBSERVED
            update_proof(args, change)
            self.rejected(args)

    def test_observation_selectors_script_roles_and_held_graph(self):
        for key, value in (("url", "https://other.example.org/page"), ("bytes", True),
                           ("sha256", "a"*64), ("originalReceiptSha256", None), ("observedAt", ACQUIRED)):
            args = fixture()
            args[2]["bindings"][0]["provenance"]["landing"][key] = value
            self.rejected(args)
        for value in ([], [None], [{"role": "app"}], [{"role": "app"}, {"role": "app"}]):
            args = fixture()
            args[2]["bindings"][0]["provenance"]["scripts"] = value
            self.rejected(args)
        for value in ("https://api.example.org/relationFiles?fileName=OTHER_ZIP.html",
                      "https://api.example.org/relationFiles?fileName=EXAMPLE1SER_ZIP.html&extra=1",
                      "https://api.example.org/relationFiles"):
            args = fixture()
            args[2]["bindings"][0]["provenance"]["metadata"]["url"] = value
            update_receipt(args, "metadata", lambda raw: raw.update(url=value))
            args[2]["bindings"][0]["waitAliases"]["requests"][2]["url"] = value
            self.rejected(args)
        for key, value in (("requestCondition", "PUBLIC_PAYLOAD"), ("publicationCondition", "ELIGIBLE"),
                           ("recordIds", []), ("productIds", []), ("sourceId", "source-old-1")):
            args = fixture()
            payload = next(item for item in args[1]["locators"] if item["id"] == "payload-1")
            payload[key] = value
            args[2]["locatorsBinding"] = identity(args[1])
            args[2]["bindings"][0]["locatorSha256"] = cr.digest(cr.json_bytes(payload))
            self.rejected(args)
        args = fixture()
        args[0]["records"][0]["publishedSha256"] = "a"*64
        args[1]["registry"] = pl.registry_binding(args[0])
        args[2]["registryBinding"] = identity(args[0])
        args[2]["locatorsBinding"] = identity(args[1])
        args[2]["bindings"][0]["recordSha256"] = cr.digest(cr.json_bytes(args[0]["records"][0]))
        self.rejected(args)

    def test_alias_purpose_identity_state_and_legacy(self):
        for state in ("waitState", "hostState", "eulaState"):
            for value in ("ACCEPTED", "READY", 1, None):
                args = fixture()
                args[2]["bindings"][0]["waitAliases"][state] = value
                self.rejected(args)
        for number in range(4):
            for key, value in (("kind", "UNKNOWN"), ("sourceId", "absent-source"),
                               ("recordId", "absent-record"), ("url", "https://other.example.org/file")):
                args = fixture(legacy_record=True)
                args[2]["bindings"][0]["waitAliases"]["requests"][number][key] = value
                self.rejected(args)
        for mutation in ("duplicate", "missing", "family"):
            args = fixture()
            aliases = args[2]["bindings"][0]["waitAliases"]
            if mutation == "duplicate":
                aliases["requests"][1] = copy.deepcopy(aliases["requests"][0])
            elif mutation == "missing":
                aliases["requests"].pop()
            else:
                aliases["familyKey"] = "different-family"
            self.rejected(args)

    def test_acquisition_inf_and_report_safety(self):
        for key, value in (("httpStatus", True), ("httpStatus", 403), ("bytes", True), ("sha256", "a"*64),
                           ("signature", "PASSED"), ("content", "PASSED"), ("originalReceiptSha256", "a"*64)):
            args = fixture()
            args[2]["bindings"][0]["acquisition"][key] = value
            self.rejected(args)
        for key, value in (("driverVersion", "3.0"), ("driverDate", "2026-02-30"), ("driverDate", "2026-1-1"),
                           ("inventoryEntries", True), ("inventoryEntries", -1), ("inventoryEntries", 4097), ("inspection", "PASSED")):
            args = fixture()
            args[2]["bindings"][0]["infDisplay"][key] = value
            self.rejected(args)
        args = fixture(2, True, ("app", "chunk10"))
        before = copy.deepcopy(args)
        report = rb.research_binding_report(*args)
        self.check(report["counts"] == {"historicalBindings": 2, "heldRequests": 2, "newAcquisitions": 0})
        self.check(report["researchOnly"] is True and all(report[key] is False for key in ("publishable", "installAuthorized", "nativeConnected")))
        self.check("https://" not in cr.json_bytes(report).decode() and "proofBytes" not in report and "receiptBytes" not in report)
        self.check(all(row["requestState"] == "HELD" and row["requestAuthorized"] is False and
                       all(row[key] == "NOT_CHECKED" for key in ("signature", "content", "applicability")) and
                       row["status"] == "HISTORICAL_BODY_OBSERVED" and row["observedAt"] == ACQUIRED for row in report["bindings"]))
        report["bindings"][0]["productIds"].clear()
        report["registryBinding"]["sha256"] = "changed"
        self.check(args == before)
        args[2]["publishable"] = True
        with self.assertRaises(cr.RegistryError):
            rb.research_binding_report(*args)
        STATS["assertionChecks"] += 1
        STATS["rejectionCases"] += 1

    def test_fictional_file_copy_round_trip_revalidates_bytes(self):
        args = fixture(2, True, ("app", "chunk10"))
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source, destination = base / "source", base / "copied"
            source.mkdir()
            for number, document in enumerate(args[:3]):
                (source / (str(number)+".json")).write_bytes(cr.json_bytes(document))
            for binding_id, original in args[3].items():
                folder = source / binding_id
                folder.mkdir()
                for key in ("proofBytes", "receiptBytes", "payloadBytes"):
                    (folder / key).write_bytes(original[key])
                for role, observation in original["observations"].items():
                    for key in ("bodyBytes", "receiptBytes"):
                        (folder / (role+"-"+key)).write_bytes(observation[key])
            shutil.copytree(source, destination)
            copied = [cr.parse_json((destination / (str(number)+".json")).read_bytes()) for number in range(3)]
            originals = copy.deepcopy(args[3])
            for binding_id, original in originals.items():
                for key in ("proofBytes", "receiptBytes", "payloadBytes"):
                    original[key] = (destination / binding_id / key).read_bytes()
                for role, observation in original["observations"].items():
                    for key in ("bodyBytes", "receiptBytes"):
                        observation[key] = (destination / binding_id / (role+"-"+key)).read_bytes()
            copied.append(originals)
            self.accepted(copied, True)
            STATS["copyRoundTrips"] += 1
            originals["binding-1"]["payloadBytes"] += b"tampered-copy"
            self.rejected(copied)


V2_STATS = {"positiveCases": 0, "rejectionCases": 0, "assertionChecks": 0}


def fixture_v2(count=1, legacy_record=False, reused_roles=()):
    """原記録差を保持し、鮮度値だけを日時から算出する架空v2を返す。"""
    args = fixture(count, legacy_record, reused_roles)
    args[2]["schema"] = rb.SCHEMA_V2
    for row in args[2]["bindings"]:
        original = args[3][row["id"]]
        proof = cr.parse_json(original["proofBytes"])
        for script in row["provenance"]["scripts"]:
            script["derivedAgeSeconds"] = script.pop("sourceAgeSeconds")
            script["originalRecordedAgeSeconds"] = 0.99917 if script["reused"] else None
            if script["reused"]:
                old = next(item for item in proof["reuseBinding"]["reusedScripts"] if item["role"] == script["role"])
                old["sourceAgeSeconds"] = script["originalRecordedAgeSeconds"]
        original["proofBytes"] = cr.json_bytes(proof)
        original["proofPin"] = pin(original["proofBytes"])
        row["provenance"]["originalProofSha256"] = original["proofPin"]["sha256"]
    return args


class BindingV2Tests(unittest.TestCase):
    """v1のmatrixと分け、版本・厳密二age・原proofを有限に検査する。"""

    setUp = BindingMatrixTests.setUp

    def check(self, condition):
        V2_STATS["assertionChecks"] += 1
        self.assertTrue(condition)

    def accepted(self, args, byte_input=False):
        before = copy.deepcopy(args)
        result = rb.validate_bindings(args[0], args[1], cr.json_bytes(args[2]) if byte_input else args[2], args[3])
        V2_STATS["positiveCases"] += 1
        self.check(result == args[2] and result is not args[2])
        self.check(args == before)
        result["bindings"][0]["productIds"].clear()
        self.check(args == before)

    def rejected(self, args):
        before = copy.deepcopy(args)
        with self.assertRaises(cr.RegistryError) as captured:
            rb.validate_bindings(*args)
        V2_STATS["rejectionCases"] += 1
        V2_STATS["assertionChecks"] += 1
        self.check(str(captured.exception).replace("_", "").isalnum() and "https" not in str(captured.exception))
        self.check(args == before)

    def test_v2_positive_combinations_and_original_delta(self):
        for count in (1, 2):
            for legacy in (False, True):
                for reused in ((), ("app",), ("chunk10",), ("app", "chunk10")):
                    for byte_input in (False, True):
                        self.accepted(fixture_v2(count, legacy, reused), byte_input)
        args = fixture_v2(2, True, ("app", "chunk10"))
        report = rb.research_binding_report(*args)
        self.check(report["schema"] == "dc-route-acquisition-research-report-v2")
        self.check(report["counts"] == {"historicalBindings": 2, "heldRequests": 2, "newAcquisitions": 0})
        self.check("https://" not in cr.json_bytes(report).decode())
        self.check(all(row["requestAuthorized"] is False and row["requestState"] == "HELD" and
                       all(row[key] == "NOT_CHECKED" for key in ("signature", "content", "applicability"))
                       for row in report["bindings"]))
        self.check(all(age["derivedAgeSeconds"] == 1 and age["originalRecordedAgeSeconds"] == 0.99917 and
                       age["originalMinusDerivedSeconds"] == 0.99917 - 1
                       for row in report["bindings"] for age in row["scriptAges"]))
        self.check(all(report[key] is False for key in ("publishable", "installAuthorized", "nativeConnected")))
        fresh_report = rb.research_binding_report(*fixture_v2())
        self.check(all(age["originalRecordedAgeSeconds"] is None and age["originalMinusDerivedSeconds"] is None
                       for age in fresh_report["bindings"][0]["scriptAges"]))

    def test_version_and_closed_script_fields(self):
        for schema in ("dc-route-acquisition-bindings-v3", True, None, [], {}):
            args = fixture_v2()
            args[2]["schema"] = schema
            self.rejected(args)
        for schema in (rb.SCHEMA, rb.SCHEMA_V2):
            args = fixture_v2() if schema == rb.SCHEMA else fixture()
            args[2]["schema"] = schema
            self.rejected(args)
        for number in (0, 1):
            for mutation in ("old", "extra", "missing-derived", "missing-original", "fresh-numeric", "reused-null"):
                args = fixture_v2(reused_roles=("app", "chunk10") if mutation == "reused-null" else ())
                script = args[2]["bindings"][0]["provenance"]["scripts"][number]
                if mutation == "old":
                    script["sourceAgeSeconds"] = 0
                elif mutation == "extra":
                    script["unknownField"] = 0
                elif mutation.startswith("missing"):
                    del script["derivedAgeSeconds" if mutation == "missing-derived" else "originalRecordedAgeSeconds"]
                else:
                    script["originalRecordedAgeSeconds"] = None if mutation == "reused-null" else 0
                self.rejected(args)

    def test_both_age_types_bounds_and_exactness(self):
        for field in ("derivedAgeSeconds", "originalRecordedAgeSeconds"):
            for number in (0, 1):
                for value in (True, False, "1", None, -1, 31536001, 10**1000, float("nan"), float("inf"), -float("inf"), [], {}):
                    args = fixture_v2(reused_roles=("app", "chunk10"))
                    args[2]["bindings"][0]["provenance"]["scripts"][number][field] = value
                    self.rejected(args)
                args = fixture_v2(reused_roles=("app", "chunk10"))
                args[2]["bindings"][0]["provenance"]["scripts"][number][field] += 0.0000005
                self.rejected(args)

    def test_future_and_original_receipt_dates(self):
        for value in ("2026-10-12T00:00:00Z", "2026-10-09T00:00:00Z", OBSERVED,
                      "2026-10-10T00:00:01.123457Z", "2026-10-10T00:00:01.1234567Z"):
            args = fixture_v2(reused_roles=("app", "chunk10"))
            args[2]["bindings"][0]["provenance"]["scripts"][0]["checkedAt"] = value
            self.rejected(args)
        args = fixture_v2(reused_roles=("app",))
        args[2]["bindings"][0]["provenance"]["scripts"][0]["observedAt"] = ACQUIRED
        self.rejected(args)

    def test_original_proof_exact_age_and_pin(self):
        for value in (True, -1, 31536001, 10**1000, float("nan"), float("inf"), 0.9991705):
            args = fixture_v2(reused_roles=("app",))
            update_proof(args, lambda proof: proof["reuseBinding"]["reusedScripts"][0].update(sourceAgeSeconds=value))
            self.rejected(args)
        for key, value in (("originalUrl", "https://other.example.org/app.js"), ("originalObservedAtUtc", ACQUIRED),
                           ("pin", {"bytes": 1, "sha256": "a"*64})):
            args = fixture_v2(reused_roles=("app",))
            update_proof(args, lambda proof: proof["reuseBinding"]["reusedScripts"][0].update({key: value}))
            self.rejected(args)
        for mutation in ("raw", "outer-pin", "declared-pin", "range", "checkedAt"):
            args = fixture_v2(reused_roles=("app",))
            original = args[3]["binding-1"]
            if mutation == "raw":
                original["proofBytes"] += b" "
            elif mutation == "outer-pin":
                original["proofPin"]["sha256"] = "a"*64
            elif mutation == "declared-pin":
                args[2]["bindings"][0]["provenance"]["originalProofSha256"] = "a"*64
            elif mutation == "range":
                update_proof(args, lambda proof: proof["ranges"]["resourceRoute"].update(sha256="a"*64))
            else:
                update_proof(args, lambda proof: proof["reuseBinding"].update(checkedAtUtc=OBSERVED))
            self.rejected(args)

    def test_v1_original_discrepancy_remains_rejected(self):
        args = fixture(reused_roles=("app",))
        args[2]["bindings"][0]["provenance"]["scripts"][0]["sourceAgeSeconds"] = 0.99917
        update_proof(args, lambda proof: proof["reuseBinding"]["reusedScripts"][0].update(sourceAgeSeconds=0.99917))
        self.rejected(args)


if __name__ == "__main__":
    unittest.main()
