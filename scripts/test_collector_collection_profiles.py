"""外部collection profileの非通信・データ更新・分母保持の固定回帰。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空の三製品・二メーカーから検査し、通信・native実行・運用state変更を行わない。
"""

import ast
import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collector_collection_profiles as cp
import collector_public_locators as pl
import collector_registry as cr


AS_OF = "2026-10-23T00:00:00Z"
CHECKED = "2026-10-22T00:00:00Z"


def collection_fixture(count: int = 2) -> tuple[dict, dict, dict]:
    """A社二製品の共通recordとB社別recordを持つ再利用可能なnative入力fixtureを返す。"""
    registry = {"schema": cr.REGISTRY_SCHEMA, "revision": "fixture-01", "asOf": AS_OF,
                "sources": [], "products": [], "records": [], "observations": []}
    locators = []
    profiles = []
    for index in range(count):
        key = f"{index:03d}"
        maker = "a" if index % 2 == 0 else "b"
        source_id = "source-" + key
        record_id = "record-" + key
        page_id = "page-" + key
        product_ids = ["product-" + key] + (["product-shared"] if index == 0 else [])
        page_url = f"https://maker-{maker}.example.org/download/{key}/"
        payload_url = page_url + "driver.zip"
        body_hash = cr.digest(key.encode("ascii"))
        registry["sources"].append({"id": source_id, "manufacturer": "Maker " + maker.upper(),
                                    "officialPage": page_url, "collectionMethod": "MANUAL_RESEARCH"})
        registry["records"].append({"id": record_id, "sourceId": source_id,
                                    "title": "Network driver " + key, "driverCategory": "LAN",
                                    "operatingSystems": ["WINDOWS_11_X64"], "packageVersion": "1.0",
                                    "driverVersion": None, "publishedDate": None,
                                    "downloadUrl": payload_url, "linkState": "OFFICIAL_LINK",
                                    "publishedSha256": "f" * 64, "contentState": "NOT_DOWNLOADED"})
        for product_id in product_ids:
            registry["products"].append({"id": product_id, "manufacturer": "Maker " + maker.upper(),
                                         "model": "Device " + product_id, "driverCategory": "LAN",
                                         "sourceIds": [source_id], "recordIds": [record_id],
                                         "researchState": "METADATA_SAVED", "reason": "NONE"})
            registry["observations"].append({"id": "observation-" + product_id, "productId": product_id,
                                             "recordId": record_id, "checkedAt": CHECKED,
                                             "kind": "OFFICIAL_LINK", "method": "LOCAL_HTTP",
                                             "evidenceUrl": page_url, "httpStatus": 200,
                                             "evidenceSha256": body_hash})
        root = {"id": page_id, "sourceId": source_id, "purpose": "PAGE", "url": page_url,
                "urlProfile": "QUERYLESS", "productIds": product_ids, "recordIds": [record_id],
                "parentPageIds": [], "requestCondition": "PUBLIC_METADATA",
                "publicationCondition": "REVIEW_REQUIRED",
                "pageObservation": {"method": "LOCAL_HTTP", "httpStatus": 200, "bodyBytes": 1200,
                                    "bodySha256": body_hash, "checkedAt": CHECKED}}
        locators.extend([root, {**root, "id": "payload-" + key, "purpose": "PAYLOAD", "url": payload_url,
                                "parentPageIds": [page_id], "requestCondition": "NO_EXTRA_PROMPT_OBSERVED",
                                "pageObservation": None}])
        review = {}
        for scope, state in (("official", "CONFIRMED"), ("preDownload", "NO_EXTRA_PROMPT"),
                             ("terms", "NO_ADDITIONAL_TERMS"), ("prerequisites", "NONE_REQUIRED")):
            review[scope] = {"state": state, "evidence": {"locatorId": page_id, "bodySha256": body_hash, "contentSha256": body_hash,
                                                           "checkedAt": CHECKED, "scope": scope}}
        review["prerequisites"]["items"] = []
        profiles.append({"id": "profile-" + key, "revision": "profile-01", "sourceId": source_id,
                         "recordId": record_id, "pageLocatorId": page_id, "payloadLocatorId": "payload-" + key,
                         "sourceFormat": cp.STATIC_FORMAT, "href": "driver.zip", "container": "ZIP",
                         "maximumBytes": cp.MAX_PAYLOAD_BYTES, "infSelection": {"mode": "ALL", "paths": []},
                         "review": review})
    registry = cr.validate_registry(registry)
    locator_document = {"schema": pl.LOCATOR_SCHEMA, "revision": "locators-01", "asOf": AS_OF,
                        "registry": pl.registry_binding(registry), "researchOnly": True,
                        "publishable": False, "installAuthorized": False, "locators": locators}
    return registry, pl.validate_locators(locator_document, registry), {"schema": cp.EDIT_SCHEMA, "profiles": profiles}


def fixture_inputs(count: int = 2) -> tuple[dict, dict, dict]:
    """共通API経由でfixtureをbindingし、検証済みcontext・profile・小編集を返す。"""
    registry, locators, edits = collection_fixture(count)
    inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
    profiles = cp.upsert_profiles(None, inputs, edits, revision="profiles-01", as_of=AS_OF)
    return inputs, profiles, edits


class CollectionProfileTests(unittest.TestCase):
    """非通信参照・保守・計画の権限境界を固定する。"""

    def test_terminal_comment_content_comparison_is_exact(self):
        """既知EOF commentだけを区別し、本文や偽終端・書式の変更を許容しない。"""
        prefix = b'<html><body><a href="driver.zip">terms/prerequisites</a></body>\n</html>'
        old = b'<!-- WP Fastest Cache file was created in 0.51081204414368 seconds, on 24-10-26 10:12:44 -->'
        new = b'<!-- WP Fastest Cache file was created in 0.59633994102478 seconds, on 25-10-26 11:22:05 -->'
        expected = cr.digest(prefix)
        self.assertEqual(cp.page_content_sha256(prefix + old), expected)
        self.assertEqual(cp.page_content_sha256(prefix + new), expected)
        for raw in (prefix.replace(b'terms', b'changed') + new,
                    prefix.replace(b'driver.zip', b'other.zip') + new):
            self.assertNotEqual(cp.page_content_sha256(raw), expected)
        for raw in (prefix + old + new, prefix + new + b'\n', prefix + new + b'<p>visible</p>',
                    prefix + new.replace(b'0.59', b'1.59'), prefix + new.replace(b'25-10', b'32-10'),
                    b'<html><script>"' + prefix + new,
                    b'<html><div title="' + prefix + new,
                    b'<html><!--' + prefix + new,
                    b'<html><template>' + prefix + new,
                    b'<html><svg>' + prefix + new,
                    prefix + new.replace(b' -->', b' --!>')):
            with self.subTest(raw=raw):
                self.assertEqual(cp.page_content_sha256(raw), cr.digest(raw))
                self.assertNotEqual(cp.page_content_sha256(raw), expected)

    def test_current_v2_requires_content_bound_to_each_raw_scope(self):
        """旧版・欠損・scope間比較差を実行入力へ補完しない。"""
        inputs, value, _ = fixture_inputs(1)
        for change in ('v1', 'missing', 'different', 'null'):
            bad = copy.deepcopy(value)
            evidence = bad['profiles'][0]['review']['terms']['evidence']
            if change == 'v1':
                bad['schema'] = 'dc-collector-collection-profiles-v1'
            elif change == 'missing':
                del evidence['contentSha256']
            elif change == 'different':
                evidence['contentSha256'] = '0' * 64
            else:
                evidence['contentSha256'] = None
            with self.subTest(change=change), self.assertRaises(cr.RegistryError):
                cp.plan_profiles(bad, inputs)

    def test_later_manual_review_preserves_original_page_and_each_scope(self):
        """旧PAGE/locator世代を保持し、各範囲の実手動時刻をupsert/read/planへ渡す。"""
        inputs, profiles, edits = fixture_inputs(1)
        before = copy.deepcopy(inputs)
        update = edits["profiles"][0]
        update["revision"] = "manual-02"
        for index, item in enumerate(update["review"].values()):
            item["evidence"]["checkedAt"] = f"2026-10-24T00:00:0{index}Z"
        value = cp.upsert_profiles(profiles, inputs, edits, revision="profiles-02",
                                   as_of="2026-10-24T00:00:04Z",
                                   reviewed_profile_ids=("profile-000",))
        self.assertEqual(cp.validate_profiles(cr.parse_json(cr.json_bytes(value)), inputs), value)
        job = cp.plan_profiles(value, inputs)["jobs"][0]
        self.assertEqual(job["review"], update["review"])
        self.assertEqual(job["pageObservation"]["checkedAt"], CHECKED)
        self.assertEqual(inputs, before)
        self.assertEqual(cp.plan_profiles(value, inputs)["jobs"][0]["review"], update["review"])

    def test_each_manual_review_time_is_bounded_by_page_profile_and_real_now(self):
        """各scopeの観測以前・profile上限外・未来をvalidate/upsertで拒否する。"""
        inputs, profiles, edits = fixture_inputs(1)
        for scope in cp.REVIEW_STATES:
            for checked, as_of in (("2026-10-21T23:59:59Z", AS_OF),
                                    ("2026-10-23T00:00:01Z", AS_OF),
                                    ("9999-12-31T00:00:00Z", "9999-12-31T00:00:00Z")):
                value = copy.deepcopy(profiles)
                value["asOf"] = as_of
                value["profiles"][0]["review"][scope]["evidence"]["checkedAt"] = checked
                update = copy.deepcopy(edits)
                update["profiles"][0]["review"][scope]["evidence"]["checkedAt"] = checked
                with self.subTest(scope=scope, checked=checked):
                    with self.assertRaisesRegex(cr.RegistryError, "PROFILE_EVIDENCE_TIME"):
                        cp.validate_profiles(value, inputs)
                    with self.assertRaisesRegex(cr.RegistryError, "PROFILE_EVIDENCE_TIME"):
                        cp.upsert_profiles(None, inputs, update, revision="invalid", as_of=as_of)

    def test_later_review_keeps_hash_locator_and_scope_binding(self):
        """後刻確認でも異hash・別locator・別scopeの根拠を借用しない。"""
        inputs, profiles, _ = fixture_inputs()
        for scope in cp.REVIEW_STATES:
            for field, replacement in (("bodySha256", "0" * 64), ("locatorId", "page-001"),
                                       ("scope", "unrelated")):
                value = copy.deepcopy(profiles)
                evidence = value["profiles"][0]["review"][scope]["evidence"]
                evidence.update(checkedAt=AS_OF)
                evidence[field] = replacement
                with self.subTest(scope=scope, field=field), self.assertRaises(cr.RegistryError):
                    cp.validate_profiles(value, inputs)

    def test_three_products_two_manufacturers_shared_record(self):
        """A1の二メーカー三製品を二jobへ束ね、研究台帳を変更しない。"""
        inputs, profiles, _ = fixture_inputs()
        before = copy.deepcopy(inputs)
        plan = cp.plan_profiles(profiles, inputs)
        self.assertEqual(plan["counts"], {"profiles": 2, "productReferences": 3, "registeredRecords": 2,
                                          "unprofiledRecords": 0, "jobs": 2, "deferred": 0, "held": 0})
        self.assertEqual(len(plan["jobs"][0]["products"]), 2)
        self.assertEqual(len({row["manufacturer"] for job in plan["jobs"] for row in job["products"]}), 2)
        self.assertEqual(plan["jobs"][0]["record"]["publishedSha256"], "f" * 64)
        self.assertEqual(plan["jobs"][0]["source"]["href"], "driver.zip")
        self.assertFalse(plan["networkAuthorized"])
        self.assertEqual(inputs, before)

    def test_empty_initial_set_and_original_byte_binding(self):
        """空集合は実行jobを作らず、意味が同じでも原bytehash変更を検出する。"""
        inputs, _, _ = fixture_inputs()
        value = cp.document(inputs, "empty-01", AS_OF, [])
        plan = cp.plan_profiles(value, inputs)
        self.assertEqual(plan["counts"]["jobs"], 0)
        self.assertEqual(plan["counts"]["unprofiledRecords"], 2)
        self.assertEqual({row["status"] for row in plan["unprofiledRecords"]}, {"NO_COLLECTION_PROFILE"})
        other = cp.load_inputs(cr.json_bytes(inputs["registry"]) + b" ", cr.json_bytes(inputs["locators"]))
        self.assertNotEqual(inputs["bindings"]["registry"], other["bindings"]["registry"])
        with self.assertRaisesRegex(cr.RegistryError, "PROFILES_INPUT_BINDING"):
            cp.validate_profiles(value, other)

    def test_data_only_add_and_nonmaterial_rebind(self):
        """既存対象を維持してデータだけで別メーカーを追加し、世代hashを自動計算する。"""
        old_inputs, old_profiles, _ = fixture_inputs(1)
        new_inputs, _, edits = fixture_inputs(2)
        added = cp.upsert_profiles(old_profiles, new_inputs,
                                  {"schema": cp.EDIT_SCHEMA, "profiles": [edits["profiles"][1]]},
                                  revision="profiles-02", as_of=AS_OF, previous_inputs=old_inputs)
        self.assertEqual(cp.plan_profiles(added, new_inputs)["counts"]["jobs"], 2)
        self.assertEqual(added["profiles"][0], old_profiles["profiles"][0])

    def test_version_update_requires_review_even_with_same_call_confirmation(self):
        """新版へ旧確認を自動付替えせず、二段階の明示再確認まで保留する。"""
        old_inputs, old_profiles, edits = fixture_inputs()
        registry = copy.deepcopy(old_inputs["registry"])
        registry["revision"] = "fixture-02"
        registry["records"][1]["packageVersion"] = "2.0"
        locators = copy.deepcopy(old_inputs["locators"])
        locators["registry"] = pl.registry_binding(cr.validate_registry(registry))
        inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
        value = cp.upsert_profiles(old_profiles, inputs, {"schema": cp.EDIT_SCHEMA, "profiles": []},
                                   revision="profiles-02", as_of=AS_OF, previous_inputs=old_inputs)
        self.assertEqual(value["profiles"][0]["reviewState"], "CURRENT")
        self.assertEqual(value["profiles"][1]["reviewState"], "REVIEW_REQUIRED")
        self.assertEqual(cp.plan_profiles(value, inputs)["counts"]["jobs"], 1)
        update = copy.deepcopy(edits["profiles"][1])
        update["revision"] = "profile-02"
        confirmed = cp.upsert_profiles(value, inputs, {"schema": cp.EDIT_SCHEMA, "profiles": [update]},
                                       revision="profiles-03", as_of=AS_OF,
                                       reviewed_profile_ids=(update["id"],))
        self.assertEqual(cp.plan_profiles(confirmed, inputs)["counts"]["jobs"], 2)

    def test_changed_execution_reference_and_review_evidence_are_not_silently_reused(self):
        """取得条件変更は確認指定と同時でも保留し、根拠hash不一致を拒否する。"""
        inputs, profiles, edits = fixture_inputs()
        update = copy.deepcopy(edits["profiles"][0])
        update.update(revision="profile-02", maximumBytes=1024)
        changed = cp.upsert_profiles(profiles, inputs, {"schema": cp.EDIT_SCHEMA, "profiles": [update]},
                                     revision="profiles-02", as_of=AS_OF,
                                     reviewed_profile_ids=(update["id"],))
        self.assertEqual(changed["profiles"][0]["reviewState"], "REVIEW_REQUIRED")
        update["review"]["terms"]["evidence"]["bodySha256"] = "0" * 64
        with self.assertRaisesRegex(cr.RegistryError, "PROFILE_EVIDENCE_BINDING"):
            cp.upsert_profiles(None, inputs, {"schema": cp.EDIT_SCHEMA, "profiles": [update]},
                               revision="profiles-02", as_of=AS_OF)

    def test_unknown_terms_conditions_and_source_format_stay_in_denominator(self):
        """未知形式と規約不明を消さず、検査可能jobと成功に数えない。"""
        inputs, profiles, _ = fixture_inputs()
        profiles["profiles"][0]["sourceFormat"] = "DYNAMIC_FUTURE_V1"
        profiles["profiles"][1]["review"]["terms"] = {"state": "UNKNOWN", "evidence": None}
        plan = cp.plan_profiles(profiles, inputs)
        self.assertEqual(plan["counts"]["profiles"], 2)
        self.assertEqual(plan["counts"]["jobs"], 0)
        self.assertEqual([row["status"] for row in plan["targets"]], ["UNSUPPORTED_SOURCE_FORMAT", "HOLD"])
        self.assertIn("HOLD_TERMS", plan["targets"][1]["reasons"])
        self.assertFalse(plan["publishable"])

    def test_thirty_three_batch_continuation_and_stable_order(self):
        """33番目を延期して次batchで選び、batch予算を総対応上限にしない。"""
        inputs, profiles, _ = fixture_inputs(33)
        profiles["profiles"].reverse()
        first = cp.plan_profiles(profiles, inputs)
        self.assertEqual(first["counts"]["jobs"], 32)
        self.assertEqual(first["counts"]["deferred"], 1)
        completed = tuple(job["jobId"] for job in first["jobs"])
        second = cp.plan_profiles(profiles, inputs, completed_profile_ids=completed)
        self.assertEqual(second["counts"]["profiles"], 33)
        self.assertEqual([job["jobId"] for job in second["jobs"]], ["profile-032"])
        self.assertEqual(first, cp.plan_profiles(profiles, inputs))

    def test_strict_fields_schema_duplicates_and_references(self):
        """任意実行・runtime成功値・ID登録・重複・不正参照を入力権限にしない。"""
        inputs, profiles, _ = fixture_inputs()
        for field in ("command", "script", "runtimeSuccess", "hardwareIds", "privateKey", "path"):
            value = copy.deepcopy(profiles)
            value["profiles"][0][field] = "fixture"
            with self.subTest(field=field), self.assertRaisesRegex(cr.RegistryError, "PROFILE_FIELDS"):
                cp.validate_profiles(value, inputs)
        for field, replacement in (("recordId", "missing"), ("sourceId", "source-001"),
                                   ("payloadLocatorId", "page-000"), ("maximumBytes", True),
                                   ("maximumBytes", cp.MAX_PAYLOAD_BYTES + 1), ("container", "EXE")):
            value = copy.deepcopy(profiles)
            value["profiles"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(cr.RegistryError):
                cp.validate_profiles(value, inputs)
        for kind in ("schema", "duplicate", "extra", "binding"):
            value = copy.deepcopy(profiles)
            if kind == "schema":
                value["schema"] = "future"
            elif kind == "duplicate":
                value["profiles"].append(copy.deepcopy(value["profiles"][0]))
            elif kind == "extra":
                value["extra"] = False
            else:
                value["registry"]["sha256"] = "0" * 64
            with self.subTest(kind=kind), self.assertRaises(cr.RegistryError):
                cp.validate_profiles(value, inputs)
        with self.assertRaises(cr.RegistryError):
            cr.parse_json(b'{"schema":1,"schema":2}')

    def test_inf_selection_paths_and_no_id_allowlist(self):
        """新INF名を列挙表なしで受け取り、絶対path・traversal・重複を拒否する。"""
        selected = {"mode": "SELECTED", "paths": [r"drivers\fresh_name.inf"]}
        self.assertEqual(cp.validate_inf_selection(selected), selected)
        for paths in (["C:\\private.inf"], ["..\\x.inf"], ["/root/x.inf"], ["a.inf", "A.inf"],
                      ["a.exe"], [], [r"folder.\a.inf"], ["a.inf"] * 129):
            with self.subTest(paths=paths), self.assertRaises(cr.RegistryError):
                cp.validate_inf_selection({"mode": "SELECTED", "paths": paths})

    def test_unsafe_urls_and_private_evidence(self):
        """既存URL拒否と秘密文字列検査を保守入口でも維持する。"""
        for url in ("http://vendor.example.org/x", "https://127.0.0.1/x", "https://server.local/x",
                    "https://user:secret@vendor.example.org/x", "https://vendor.example.org/x?token=secret"):
            registry, locators, _ = collection_fixture()
            registry["sources"][0]["officialPage"] = url
            with self.subTest(url=url), self.assertRaises(cr.RegistryError):
                cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
        inputs, profiles, _ = fixture_inputs()
        profiles["profiles"][0]["href"] = "password=secret"
        with self.assertRaisesRegex(cr.RegistryError, "PROFILE_HREF"):
            cp.validate_profiles(profiles, inputs)

    def test_unknown_states_no_implicit_permission(self):
        """規約・前条件・必須条件の欠損や未知型を既定許可へ置換しない。"""
        inputs, profiles, _ = fixture_inputs()
        for scope in cp.REVIEW_STATES:
            value = copy.deepcopy(profiles)
            value["profiles"][0]["review"][scope]["state"] = "UNKNOWN"
            value["profiles"][0]["review"][scope]["evidence"] = None
            self.assertEqual(cp.plan_profiles(value, inputs)["counts"]["held"], 1)
            del value["profiles"][0]["review"][scope]
            with self.assertRaises(cr.RegistryError):
                cp.validate_profiles(value, inputs)

    def test_source_module_has_no_network_or_process_imports(self):
        """実装を非通信標準library集合へ限定し、subprocessやsocketの依存を作らない。"""
        tree = ast.parse(Path(cp.__file__).read_text(encoding="utf-8"))
        imports = {name.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for name in node.names}
        imports.update(node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
        self.assertEqual(imports, {"__future__", "argparse", "copy", "datetime", "pathlib", "re", "sys", "urllib.parse",
                                  "collector_public_locators", "collector_registry"})


class ProfileCliTests(unittest.TestCase):
    """通常logの非開示・明示出力・失敗時不変をCLI境界で確認する。"""

    def test_validate_plan_upsert_determinism_and_failures(self):
        """三入口を直接呼び、通信processなしで同一出力・上書き拒否・原入力保持を確認する。"""
        registry, locators, edits = collection_fixture()
        inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
        profiles = cp.upsert_profiles(None, inputs, edits, revision="profiles-01", as_of=AS_OF)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"registry": registry, "locators": locators, "profiles": profiles, "edits": edits}
            for name, value in files.items():
                (root / (name + ".json")).write_bytes(cr.json_bytes(value))
            baseline = {path.name: path.read_bytes() for path in root.iterdir()}
            common = ["--registry", str(root / "registry.json"), "--locators", str(root / "locators.json")]
            profile_arg = ["--profiles", str(root / "profiles.json")]
            results = []
            with patch("socket.socket", side_effect=AssertionError("NETWORK_FORBIDDEN")), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                results.append(cp.main(["validate", *common, *profile_arg]))
                for name in ("plan1.json", "plan2.json"):
                    results.append(cp.main(["plan", *common, *profile_arg, "--output", str(root / name)]))
                for name in ("upsert1.json", "upsert2.json"):
                    results.append(cp.main(["upsert", *common, "--edits", str(root / "edits.json"),
                                            "--revision", "profiles-01", "--as-of", AS_OF,
                                            "--output", str(root / name)]))
                self.assertEqual(results, [0] * 5)
                self.assertEqual(cp.main(["plan", *common, *profile_arg, "--output", str(root / "plan1.json")]), 2)
                self.assertEqual(cp.main(["plan", *common, *profile_arg]), 2)
                self.assertEqual(cp.main(["plan", *common, *profile_arg, "--output", str(root / "registry.json")]), 2)
                self.assertEqual(cp.main(["upsert", *common]), 2)
            self.assertEqual((root / "plan1.json").read_bytes(), (root / "plan2.json").read_bytes())
            self.assertEqual((root / "upsert1.json").read_bytes(), (root / "upsert2.json").read_bytes())
            for name, raw in baseline.items():
                self.assertEqual((root / name).read_bytes(), raw)
            self.assertNotIn("https://", stdout.getvalue() + stderr.getvalue())
            self.assertNotIn(str(root), stdout.getvalue() + stderr.getvalue())
            self.assertIn("REJECTED:OUTPUT_EXISTS", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
