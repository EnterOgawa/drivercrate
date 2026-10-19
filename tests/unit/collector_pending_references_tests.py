"""未確定参照の原根拠・許可境界・可搬copyを標準unittestで検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
拒否用の秘密・private宛先はruntimeで組み立て、監査成果物へ保存しない。
"""

import copy
from dataclasses import asdict
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import collector_registry as cr
import collector_pending_references as pending
import test_collector_registry as registry_tests


def fixture(root: Path, *, driver="Windows Driver", os_value=None, architecture=None, missing=False,
            page_leaf="page.json", route_leaf="route.json"):
    """メーカー別codeを用いず、独立したbaseline・manual・map・pageを作る。"""
    baseline = registry_tests.fixture()
    node = "evidence-one"
    body = "a" * 64
    observed = "2020-01-01T00:00:00+09:00"
    page_url = "https://vendor.example.org/drivers"
    base = "https://vendor.example.org/files/"
    title = "Device One"
    model_fact = {"index": 0, "text": title}
    fact = {"index": 1, "text": driver}
    literal = {"rawHref": "driver.zip", "resolvedHref": base + "driver.zip", "priorFactCount": 1}
    page = {"receipt": {"url": page_url, "bodySha256": body, "checkedAt": observed}, "publicFacts": [title, driver]}
    route = {"documentUrl": page_url, "bodySha256": body, "effectiveBase": base, "rows": [literal]}
    manual = {"researchOnly": True, "defaultRegistryAdopted": False, "publishable": False, "installAuthorized": False,
              "rows": [{"manufacturer": "Example", "model": title, "formalProductTitle": title,
                        "productNode": node, "recordIds": [], "conditions": {"scopeReviewPromoted": False},
                        "proof": {"bodySha256": None if missing else body,
                                  "observedAt": None if missing else observed,
                                  "evidenceUrl": None if missing else page_url,
                                  "effectiveBase": None if missing else base,
                                  "modelFact": None if missing else model_fact,
                                  "modelIsNavigationListEntry": False}}],
              "unadoptedDistributionReferences": [{"node": node, "routeFile": None if missing else route_leaf,
                  "bodySha256": None if missing else body, "effectiveBase": None if missing else base,
                  "driverFact": None if missing else fact, "literal": None if missing else literal,
                  "adoptedAsRecord": False, "contentsChecked": False, "signatureChecked": False, "installAuthorized": False}]}
    content = {"baseline-registry.json": baseline, "manual-review-source.json": manual}
    if not missing:
        content.update({page_leaf: page, route_leaf: route})
    trust = {}
    for leaf, value in content.items():
        raw = cr.json_bytes(value)
        (root / leaf).parent.mkdir(parents=True, exist_ok=True)
        (root / leaf).write_bytes(raw)
        trust[leaf] = {"bytes": len(raw), "sha256": cr.digest(raw)}
    pointer = lambda leaf: {"leaf": leaf, **trust[leaf]}
    mapping = {"schema": pending.MAP_SCHEMA, "baselinePin": pointer("baseline-registry.json"),
               "sourceManualPin": pointer("manual-review-source.json"), "productRowIndices": [0],
               "evidence": [{"id": node, "pagePin": None if missing else pointer(page_leaf),
                             "routePin": None if missing else pointer(route_leaf),
                             "officialBasis": None if missing else {"kind": "MANUAL_OFFICIAL_PAGE_REVIEW", "reviewPin": pointer("manual-review-source.json")},
                             "parserVersion": None}],
               "references": [{"referenceIndex": 0, "referenceId": "reference-one", "contextProductIds": ["product-one"],
                               "explicitDriverModelProductIds": [], "modelScope": "UNKNOWN", "osValue": os_value, "architectureValue": architecture}]}
    raw = cr.json_bytes(mapping)
    (root / "approved-import-map.json").write_bytes(raw)
    trust["approved-import-map.json"] = {"bytes": len(raw), "sha256": cr.digest(raw)}
    ledger = pending.import_reviewed_references(manual, mapping, root, trust)
    return ledger, trust, manual, mapping


class PendingReferenceTests(unittest.TestCase):
    """非通信の汎用fixtureで未知保存と原根拠からの逸脱拒否を確認する。"""

    def setUp(self):
        """試験専用directoryを作り、実端末storeから分離する。"""
        self.temporary = tempfile.TemporaryDirectory(prefix="dc-pending92-")
        self.root = Path(self.temporary.name)
        self.ledger, self.trust, self.review, self.mapping = fixture(self.root)

    def tearDown(self):
        """所有する試験専用temporaryだけを解放する。"""
        self.temporary.cleanup()

    def reject(self, mutate):
        """独立trustを維持して台帳改変だけを拒否する。"""
        value = copy.deepcopy(self.ledger)
        mutate(value)
        with self.assertRaises((cr.RegistryError, ValueError, TypeError, KeyError)):
            pending.validate_pending_ledger(value, self.root, self.trust)

    def test_summary_has_only_count_axes(self):
        """summaryにURL・許可・導入identityを返さない。"""
        result = pending.validate_pending_ledger(self.ledger, self.root, self.trust)
        self.assertEqual(set(asdict(result)), {"products", "savedReferences", "uniqueUrls", "contexts", "pendingReasons"})
        self.assertEqual((result.products, result.savedReferences, result.uniqueUrls, result.contexts), (1, 1, 1, 1))
        self.assertEqual(result.pendingReasons["ARCHITECTURE_UNKNOWN"], 1)

    def test_exact_boolean_flags(self):
        """true許可・0/1・文字列を厳密booleanとして受け付けない。"""
        for key in ("defaultRegistryAdopted", "publishable", "installAuthorized"):
            for bad in (True, 0, 1, "false"):
                with self.subTest(key=key, kind=type(bad).__name__):
                    self.reject(lambda value: value.__setitem__(key, bad))
        for bad in (False, 1, "true"):
            self.reject(lambda value: value.__setitem__("researchOnly", bad))

    def test_root_unknown_fields_and_version(self):
        """未知field・版・導入commandを拒否する。"""
        self.reject(lambda value: value.__setitem__("schema", "future"))
        for key in ("extra", "grant", "installCommand"):
            self.reject(lambda value: value.__setitem__(key, True))

    def test_nested_unknown_fields(self):
        """nested exact-keyを省略せず全層で検査する。"""
        locations = [lambda v: v["products"][0], lambda v: v["products"][0]["modelFact"],
                     lambda v: v["evidence"][0], lambda v: v["evidence"][0]["officialBasis"],
                     lambda v: v["references"][0], lambda v: v["references"][0]["association"],
                     lambda v: v["references"][0]["osEvidence"], lambda v: v["references"][0]["checks"],
                     lambda v: v["baselinePin"]]
        for locate in locations:
            self.reject(lambda value: locate(value).__setitem__("extra", True))

    def test_duplicate_json_and_constants(self):
        """duplicate keys／NaN／Infinityを標準共通parserで拒否する。"""
        for raw in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(cr.RegistryError):
                cr.parse_json(raw)

    def test_duplicate_ids(self):
        """各台帳arrayの重複IDを暗黙dedupしない。"""
        for key in ("products", "evidence", "references"):
            self.reject(lambda value: value[key].append(copy.deepcopy(value[key][0])))

    def test_undefined_ids(self):
        """存在しないproduct／evidence参照を拒否する。"""
        self.reject(lambda v: v["references"][0]["association"].__setitem__("contextProductIds", ["unknown"]))
        self.reject(lambda v: v["references"][0].__setitem__("evidenceId", "unknown"))

    def test_wrong_product_id(self):
        """文字列から組み立てたIDをbaseline正式IDへ代用しない。"""
        self.reject(lambda v: v["products"][0].__setitem__("id", "guessed-product"))

    def test_product_model_and_title(self):
        """メーカー・型番・正式titleを元factへ固定する。"""
        for key in ("manufacturer", "model", "formalProductTitle"):
            self.reject(lambda v: v["products"][0].__setitem__(key, "Changed"))

    def test_other_model_scope(self):
        """page掲載とdriver model scopeの借用を拒否する。"""
        self.reject(lambda v: v["references"][0]["association"].__setitem__("modelScope", "EXPLICIT"))
        self.reject(lambda v: v["references"][0]["association"].__setitem__("explicitDriverModelProductIds", ["product-one"]))
        self.reject(lambda v: v["references"][0]["association"].__setitem__("pageMentionProductIds", []))

    def test_fake_checks(self):
        """内容・署名・INF・EULA等の偽確認状態を拒否する。"""
        for key in pending.CHECK_KEYS:
            for bad in (True, "CHECKED", "VERIFIED"):
                self.reject(lambda v: v["references"][0]["checks"].__setitem__(key, bad))

    def test_missing_or_fake_reasons(self):
        """未知理由の欠損・重複・旧reasonへの丸めを拒否する。"""
        for reasons in ([], ["DOWNLOAD_TABLE_UNAVAILABLE"], ["MODEL_SCOPE_UNKNOWN"] * 2):
            self.reject(lambda v: v["references"][0].__setitem__("pendingReasons", reasons))

    def test_body_base_fact_and_href_binding(self):
        """同body・個別base・Driver fact・元hrefの全結合を要求する。"""
        for key, bad in (("bodySha256", "b" * 64), ("effectiveBase", "https://vendor.example.org/other/")):
            self.reject(lambda v: v["evidence"][0].__setitem__(key, bad))
        self.reject(lambda v: v["references"][0]["driverFact"].__setitem__("text", "Different fact"))
        self.reject(lambda v: v["references"][0]["driverFact"].__setitem__("index", True))
        self.reject(lambda v: v["references"][0].__setitem__("rawHref", "other.zip"))
        self.reject(lambda v: v["references"][0].__setitem__("priorFactCount", 2))

    def test_arbitrary_url(self):
        """HTTPSだけで任意のpayload URLを受理しない。"""
        self.reject(lambda v: v["references"][0].__setitem__("resolvedUrl", "https://other.example.org/arbitrary.zip"))

    def test_private_and_credential_urls(self):
        """runtimeのprivate／credential宛先を非通信拒否する。"""
        private_host = ".".join(str(number) for number in (127, 0, 0, 1))
        for url in ("https://" + private_host + "/driver.zip", "https://user" + ":secret@vendor.example.org/driver.zip", "https://vendor.example.org/driver.zip?" + "token" + "=secret"):
            self.reject(lambda v: v["references"][0].__setitem__("resolvedUrl", url))
            with self.assertRaises(cr.RegistryError):
                pending._url(url)

    def test_raw_private_text(self):
        """rawHrefやfactの端末path・生ID・serialをruntime拒否する。"""
        texts = ["USB" + chr(92) + "VID_" + "1234", "serial" + "=private", "C" + ":" + chr(92) + "device"]
        for text in texts:
            self.reject(lambda v: v["references"][0].__setitem__("rawHref", text))

    def test_missing_and_tampered_input(self):
        """欠損・改変byteを台帳自己申告hashで救済しない。"""
        (self.root / "page.json").write_bytes(b"{}")
        with self.assertRaises(cr.RegistryError):
            pending.validate_pending_ledger(self.ledger, self.root, self.trust)
        (self.root / "page.json").unlink()
        with self.assertRaises(OSError):
            pending.validate_pending_ledger(self.ledger, self.root, self.trust)

    def test_approved_map_tampering(self):
        """approved map本人の改変と引数差を拒否する。"""
        forged = copy.deepcopy(self.mapping)
        forged["references"][0]["contextProductIds"] = ["other-product"]
        with self.assertRaises(cr.RegistryError):
            pending.import_reviewed_references(self.review, forged, self.root, self.trust)
        (self.root / "approved-import-map.json").write_bytes(cr.json_bytes(forged))
        with self.assertRaises(cr.RegistryError):
            pending.validate_pending_ledger(self.ledger, self.root, self.trust)

    def test_baseline_id_tampering(self):
        """baseline IDの変造を独立trustで拒否する。"""
        value = cr.read_json(self.root / "baseline-registry.json")
        value["products"][0]["id"] = "forged-id"
        (self.root / "baseline-registry.json").write_bytes(cr.json_bytes(value))
        with self.assertRaises(cr.RegistryError):
            pending.validate_pending_ledger(self.ledger, self.root, self.trust)

    def test_trust_not_derived_from_ledger(self):
        """ledger本人のpin集合ではtrust coreを供給できない。"""
        fake = {pin["leaf"]: {key: pin[key] for key in ("bytes", "sha256")} for pin in (self.ledger["baselinePin"], self.ledger["manualSourcePin"])}
        with self.assertRaises(cr.RegistryError):
            pending.validate_pending_ledger(self.ledger, self.root, fake)

    def test_review_argument_type_difference(self):
        """falseを0へ差し替えたreview引数も一致扱いしない。"""
        value = copy.deepcopy(self.review)
        value["publishable"] = 0
        with self.assertRaises(cr.RegistryError):
            pending.import_reviewed_references(value, self.mapping, self.root, self.trust)

    def test_traversal_absolute_and_unknown_leaves(self):
        """明示trustにtraversal・絶対path・未知leafを入れさせない。"""
        for leaf in ("../page.json", "/page.json", "unknown.json"):
            trust = copy.deepcopy(self.trust)
            trust[leaf] = trust.pop("page.json")
            with self.assertRaises((cr.RegistryError, OSError)):
                pending.validate_pending_ledger(self.ledger, self.root, trust)

    def test_reparse_leaf_parent_and_root(self):
        """共通reparse属性判定をleaf・親・rootの検査で維持する。"""
        info = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        with patch.object(Path, "lstat", return_value=info), self.assertRaises(cr.RegistryError):
            pending.validate_pending_ledger(self.ledger, self.root, self.trust)

    def test_filename_architecture_not_inferred(self):
        """filenameのx64をscopeへ借用しない。"""
        self.reject(lambda v: v["references"][0].__setitem__("architectureEvidence", {"status": "EXPLICIT", "value": "x64", "fact": v["references"][0]["driverFact"]}))

    def test_old_observation_retained(self):
        """copy／再import時刻で旧観測を最新化しない。"""
        self.assertEqual(self.ledger["evidence"][0]["observedAt"], "2020-01-01T00:00:00+09:00")
        self.assertNotEqual(self.ledger["evidence"][0]["observedAt"], self.ledger["importedAt"])
        self.reject(lambda v: v["evidence"][0].__setitem__("observedAt", v["importedAt"]))

    def test_pending_rejected_by_confirmed_registry(self):
        """既存confirmed入力にpendingが混入すると実validatorで拒否する。"""
        with self.assertRaisesRegex(cr.RegistryError, "REGISTRY_FIELDS"):
            cr.validate_registry(self.ledger)

    def test_byte_copy_and_reimport(self):
        """別二folderの明示copy後もbyte一致と全根拠の再読込みを確認する。"""
        target = self.root / "portable"
        pending.copy_pending_bundle(self.ledger, self.root, target, self.trust)
        self.assertEqual((target / "pending-references.json").read_bytes(), cr.json_bytes(self.ledger))
        result = pending.verify_pending_bundle(target, self.trust)
        self.assertEqual(result.savedReferences, 1)
        reconstructed = pending.import_reviewed_references(self.review, self.mapping, target, self.trust)
        reconstructed["importedAt"] = self.ledger["importedAt"]
        self.assertEqual(cr.json_bytes(reconstructed), cr.json_bytes(self.ledger))

    def test_existing_output_refused(self):
        """先在出力を上書き・自動修復しない。"""
        target = self.root / "portable"
        target.mkdir()
        with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
            pending.copy_pending_bundle(self.ledger, self.root, target, self.trust)

    def test_partial_copy_has_no_complete_manifest(self):
        """copy途中の失敗では完成manifestを生成しない。"""
        target = self.root / "portable"
        original = Path.open
        def fail(path, *args, **kwargs):
            if path.parent == target and path.name == "manual-review-source.json":
                raise OSError("test interruption")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", fail), self.assertRaises(OSError):
            pending.copy_pending_bundle(self.ledger, self.root, target, self.trust)
        self.assertTrue(target.exists())
        self.assertFalse((target / "manifest.json").exists())

    def test_bundle_unknown_manifest_leaf(self):
        """完成manifestの未知leafや自己申告pin差を拒否する。"""
        target = self.root / "portable"
        pending.copy_pending_bundle(self.ledger, self.root, target, self.trust)
        manifest = cr.read_json(target / "manifest.json")
        manifest["files"]["unknown.json"] = {"bytes": 0, "sha256": "a" * 64}
        (target / "manifest.json").write_bytes(cr.json_bytes(manifest))
        with self.assertRaises(cr.RegistryError):
            pending.verify_pending_bundle(target, self.trust)

    def test_bundle_unknown_actual_leaf(self):
        """manifest外の実fileも完成bundleへ含めさせない。"""
        target = self.root / "portable"
        pending.copy_pending_bundle(self.ledger, self.root, target, self.trust)
        (target / "unlisted.json").write_bytes(b"{}")
        with self.assertRaises(cr.RegistryError):
            pending.verify_pending_bundle(target, self.trust)

    def test_bundle_tampered_leaf(self):
        """copy後の改変byteを拒否する。"""
        target = self.root / "portable"
        pending.copy_pending_bundle(self.ledger, self.root, target, self.trust)
        (target / "page.json").write_bytes(b"{}")
        with self.assertRaises(cr.RegistryError):
            pending.verify_pending_bundle(target, self.trust)


class WindowsLeafBoundaryTests(unittest.TestCase):
    """Windows名の拒否を出力前に固定し、通常spaceを含む明示leafを通す。"""

    def setUp(self):
        """試験所有のsourceと新規copy先を正式dataから分離する。"""
        self.temporary = tempfile.TemporaryDirectory(prefix="dc-leaf92-")
        self.root = Path(self.temporary.name)
        self.ledger, self.trust, self.review, self.mapping = fixture(self.root)
        self.destination = self.root / "portable"

    def tearDown(self):
        """所有する試験専用temporaryだけを解放する。"""
        self.temporary.cleanup()

    def reject_names(self, page_leaf, route_leaf="route.json", code="LEAF_PATH"):
        """全trust名を原入力読込みと最初の出力directory生成より前に拒否する。"""
        trust = copy.deepcopy(self.trust)
        page_pin = trust.pop("page.json")
        route_pin = trust.pop("route.json")
        trust[page_leaf] = page_pin
        trust[route_leaf] = route_pin
        with patch.object(pending, "_raw", side_effect=AssertionError("name preflight required")), patch.object(Path, "mkdir") as create:
            with self.assertRaisesRegex(cr.RegistryError, code):
                pending.import_reviewed_references(self.review, self.mapping, self.root, trust)
            with self.assertRaisesRegex(cr.RegistryError, code):
                pending.copy_pending_bundle(self.ledger, self.root, self.destination, trust)
            create.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_trailing_space_dot_before_output(self):
        """末尾space/dotのleaf・directoryをWindows alias生成前に拒否する。"""
        for leaf in ("page.json ", "page.json.", "Folder /page.json", "Folder./page.json"):
            with self.subTest(leaf=leaf):
                self.reject_names(leaf)

    def test_invalid_windows_and_reserved_names_before_output(self):
        """Windows無効字符と大文字小文字・拡張子付きDOS予約basenameを拒否する。"""
        names = ["page" + char + ".json" for char in '<>:"\\|?*']
        names.extend(("con", "PrN.json", "aUx.txt", "NUL.json", "com1.json", "COM9", "lpt1.txt", "LPT9",
                      "COM¹.json", "LPT².txt", "CONIN$.json", "conout$", "CON .json", "NUL/page.json"))
        for leaf in names:
            with self.subTest(leaf=leaf):
                self.reject_names(leaf)

    def test_casefold_leaf_directory_and_file_conflicts_before_output(self):
        """leafのcasefold重複と共有directoryのcase差・file競合を先行拒否する。"""
        for page_leaf, route_leaf in (("Page.json", "page.json"), ("A/page.json", "a/route.json"),
                                     ("A", "A/route.json")):
            with self.subTest(page_leaf=page_leaf, route_leaf=route_leaf):
                self.reject_names(page_leaf, route_leaf, "TRUST_PATH_ALIAS")

    def test_generated_leaf_names_casefold_before_output(self):
        """生成用root名をcase違いやdirectoryへの転用で占有させない。"""
        for leaf in ("MANIFEST.JSON", "Pending-References.JSON", "Ledger.Json", "MANIFEST.JSON/page.json"):
            with self.subTest(leaf=leaf):
                self.reject_names(leaf, code="TRUST_RESERVED_LEAF")

    def test_normal_leaf_space_and_shared_directory_copy(self):
        """通常の名前内spaceと一貫した共有directory表記をcopy・再検証でも保持する。"""
        for leaf in ("page.json", "Driver Files/page one.json", "COM10.json", "console.json"):
            self.assertEqual(pending._leaf(leaf), leaf)
        ledger, trust, _, _ = fixture(self.root, page_leaf="Driver Files/page one.json",
                                      route_leaf="Driver Files/route two.json")
        pending.copy_pending_bundle(ledger, self.root, self.destination, trust)
        self.assertEqual(pending.verify_pending_bundle(self.destination, trust).savedReferences, 1)
        self.assertEqual((self.destination / "Driver Files/page one.json").read_bytes(),
                         (self.root / "Driver Files/page one.json").read_bytes())


class ScopeFixtureTests(unittest.TestCase):
    """独立scope根拠・nullable欠測を別fixtureで検査する。"""

    def test_legacy_os_and_explicit_architecture(self):
        """同Driver factだけのWin7 64-bitを正確に保存する。"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger, trust, _, _ = fixture(root, driver="v2.02 for Windows 7 (64-bit)", os_value="WINDOWS_7", architecture="x64")
            summary = pending.validate_pending_ledger(ledger, root, trust)
            self.assertEqual(summary.pendingReasons["LEGACY_OS_ONLY"], 1)
            self.assertNotIn("ARCHITECTURE_UNKNOWN", summary.pendingReasons)

    def test_general_explicit_os_literal(self):
        """二OS固定にせず、同factの自由な明示OS literalを保存する。"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger, trust, _, _ = fixture(root, driver="Driver for Windows Server 2022", os_value="Windows Server 2022")
            self.assertEqual(pending.validate_pending_ledger(ledger, root, trust).savedReferences, 1)

    def test_os_and_architecture_contradictions(self):
        """typed OS番号差・別architecture借用を拒否する。"""
        for os_value, arch in (("WINDOWS_11", None), ("WINDOWS_7", "x86")):
            with tempfile.TemporaryDirectory() as folder, self.assertRaises(cr.RegistryError):
                fixture(Path(folder), driver="v2.02 for Windows 7 (64-bit)", os_value=os_value, architecture=arch)

    def test_nullable_incomplete_evidence(self):
        """独立根拠にも欠測がある時だけnullと正しい理由で保存する。"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger, trust, _, _ = fixture(root, missing=True)
            summary = pending.validate_pending_ledger(ledger, root, trust)
            self.assertEqual(summary.uniqueUrls, 0)
            self.assertEqual(summary.pendingReasons["EVIDENCE_INCOMPLETE"], 1)
            self.assertIsNone(ledger["references"][0]["resolvedUrl"])
            ledger["references"][0]["resolvedUrl"] = "https://vendor.example.org/arbitrary.zip"
            with self.assertRaises(cr.RegistryError):
                pending.validate_pending_ledger(ledger, root, trust)


class LateBoundaryTests(unittest.TestCase):
    """最初suite後の局所補正だけを独立epochで検査する。"""

    def test_incomplete_evidence_still_rejects_absolute_private_href(self):
        """公式性欠測時もabsolute rawHrefのprivate宛先を保存させない。"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            _, trust, review, mapping = fixture(root)
            private = "https://" + ".".join(map(str, (127, 0, 0, 1))) + "/driver.zip"
            review["unadoptedDistributionReferences"][0]["literal"]["rawHref"] = private
            review["unadoptedDistributionReferences"][0]["literal"]["resolvedHref"] = private
            mapping["evidence"][0]["officialBasis"] = None
            raw = cr.json_bytes(review)
            (root / "manual-review-source.json").write_bytes(raw)
            trust["manual-review-source.json"] = {"bytes": len(raw), "sha256": cr.digest(raw)}
            mapping["sourceManualPin"] = {"leaf": "manual-review-source.json", **trust["manual-review-source.json"]}
            route = cr.read_json(root / "route.json")
            route["rows"] = [review["unadoptedDistributionReferences"][0]["literal"]]
            raw = cr.json_bytes(route)
            (root / "route.json").write_bytes(raw)
            trust["route.json"] = {"bytes": len(raw), "sha256": cr.digest(raw)}
            mapping["evidence"][0]["routePin"] = {"leaf": "route.json", **trust["route.json"]}
            raw = cr.json_bytes(mapping)
            (root / "approved-import-map.json").write_bytes(raw)
            trust["approved-import-map.json"] = {"bytes": len(raw), "sha256": cr.digest(raw)}
            with self.assertRaisesRegex(cr.RegistryError, "URL_IP_LITERAL"):
                pending.import_reviewed_references(review, mapping, root, trust)

    def test_copy_budget_includes_manifest_leaf(self):
        """63根拠＋ledger＋manifestの65leafを生成前に拒否する。"""
        content = {"evidence-" + str(index) + ".json": b"{}" for index in range(63)}
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "portable"
            with patch.object(pending, "validate_pending_ledger", return_value=None), patch.object(pending, "_trusted", return_value=(None, None, None, None, content)):
                with self.assertRaisesRegex(cr.RegistryError, "COPY_BUDGET"):
                    pending.copy_pending_bundle({}, Path(folder), target, {})
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
