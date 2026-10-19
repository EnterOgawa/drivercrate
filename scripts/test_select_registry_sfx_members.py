"""明示SFX planと選択ZIPの差替え・過大・部分証拠拒否を検証する。"""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

import collector_registry as cr
import select_registry_sfx_members as sm


class SelectionTests(unittest.TestCase):
    def setUp(self):
        """同じ架空recordへ結合した構造観測と選択planを各caseへ作る。

        planはself.selectionと同じdictを保持し、negative変更をvalidateへ渡す。
        選択entriesとDebug／Release観測はdeepcopyし、構造との差替えを別に検査する。
        登録hashは、明示して再結合するcase以外では更新しない。
        """
        self.registry = {"fixture": True}
        self.large = {"evidence": {"acquisitions": [{"recordId": "fixture-record", "state": "DOWNLOADED", "sha256": "a" * 64}]}}
        self.entries = [{"index": 7, "path": "Display.Driver\\driver.inf", "bytes": 16},
                        {"index": 8, "path": "Display.Driver\\driver.cat", "bytes": 8}]
        observation = {"state": "METADATA_VALID", "inputSha256": "a" * 64,
                       "payloadDecoded": False, "contentSignatureVerified": False, "entries": self.entries}
        result = {"exitCode": 0, "toolSha256": "b" * 64, "observation": observation}
        self.structure = {"schema": sm.STRUCTURE_SCHEMA, "researchOnly": True, "publishable": False,
                          "installAuthorized": False, "largeEvidenceSha256": sm.normalized_hash(self.large),
                          "toolSha256": "c" * 64, "checkedAt": "2026-10-04T00:00:00Z", "derivedMembers": [],
                          "samples": [{"sample": "fixture-record", "sha256": "a" * 64, "configurationsEqual": True,
                                       "configurations": {"Debug": copy.deepcopy(result), "Release": copy.deepcopy(result)}}]}
        self.selection = {"name": "fixture-inf", "recordId": "fixture-record", "sample": "fixture-record", "vendor": "NVIDIA",
                          "purpose": "INF_CATALOG", "inputSha256": "a" * 64, "entries": copy.deepcopy(self.entries)}
        self.plan = {"schema": sm.PLAN_SCHEMA, "revision": "fixture-01", "registrySha256": sm.normalized_hash(self.registry),
                     "largeEvidenceSha256": sm.normalized_hash(self.large), "structureSha256": sm.normalized_hash(self.structure),
                     "selections": [self.selection]}

    def validate(self):
        return sm.validate_plan(self.plan, self.registry, self.large, self.structure)

    def rejects(self, change):
        """changeをその場で一度呼び、続くvalidateの拒否だけを確認する。

        callback自身の例外はassertRaisesの外へ伝わり、検証側の拒否として扱わない。
        """
        change()
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.validate()

    def test_valid(self):
        self.assertEqual(self.validate(), self.plan)

    def test_unknown_field(self):
        self.rejects(lambda: self.plan.update(unknown=True))

    def test_changed_registry(self):
        self.rejects(lambda: self.registry.update(changed=True))

    def test_changed_acquisition(self):
        self.rejects(lambda: self.large["evidence"]["acquisitions"][0].update(sha256="d" * 64))

    def test_changed_structure(self):
        self.rejects(lambda: self.structure.update(toolSha256="e" * 64))

    def test_empty_selection(self):
        self.rejects(lambda: self.selection.update(entries=[]))

    def test_duplicate_index(self):
        self.rejects(lambda: self.selection["entries"].append(self.selection["entries"][0]))

    def test_unknown_index(self):
        self.rejects(lambda: self.selection["entries"][0].update(index=99))

    def test_boolean_index(self):
        self.rejects(lambda: self.selection["entries"][0].update(index=True))

    def test_changed_path(self):
        self.rejects(lambda: self.selection["entries"][0].update(path="other.inf"))

    def test_changed_size(self):
        self.rejects(lambda: self.selection["entries"][0].update(bytes=18))

    def test_unknown_vendor(self):
        self.rejects(lambda: self.selection.update(vendor="ASUS"))

    def test_invented_source(self):
        self.rejects(lambda: self.selection.update(inputSha256="d" * 64))

    def test_no_source_record(self):
        self.rejects(lambda: self.selection.update(recordId="other-record"))

    def test_unknown_purpose(self):
        self.rejects(lambda: self.selection.update(purpose="INSTALL"))

    def test_duplicate_name(self):
        self.rejects(lambda: self.plan["selections"].append(copy.deepcopy(self.selection)))

    def test_unbounded_count(self):
        self.rejects(lambda: self.plan.update(selections=[self.selection] * 17))

    def test_rebound_structure_disagreement(self):
        self.structure["samples"][0]["configurations"]["Debug"]["observation"]["entries"][0]["bytes"] = 18
        self.plan["structureSha256"] = sm.normalized_hash(self.structure)
        with self.assertRaises(ValueError):
            self.validate()

    def test_metadata_paths(self):
        for path in ("../driver.inf", "C:/driver.inf", "driver.inf/../other", "foo//driver.inf", "foo./driver.inf"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                sm.validate_metadata([{"index": 1, "path": path, "bytes": 1}])

    def test_metadata_collision(self):
        with self.assertRaises(ValueError):
            sm.validate_metadata([{"index": 1, "path": "file", "bytes": 1},
                                  {"index": 2, "path": "file/child", "bytes": 1}])

    def test_large_metadata_not_automatically_selected(self):
        self.assertEqual(sm.validate_metadata([{"index": 1, "path": "driver.inf", "bytes": 5 * 1024 ** 2}])[1]["bytes"],
                         5 * 1024 ** 2)

    def export_fixture(self, root):
        target = root / "selection.zip"
        raw = {"Display.Driver/driver.inf": b"i" * 16, "Display.Driver/driver.cat": b"c" * 8}
        with zipfile.ZipFile(target, "x", zipfile.ZIP_STORED) as archive:
            for name, data in raw.items():
                archive.writestr(name, data)
        rows = [dict(entry, sha256=hashlib.sha256(raw[entry["path"].replace("\\", "/")]).hexdigest()) for entry in self.entries]
        observed = {"state": "SELECTED_EXPORTED", "inputSha256": "a" * 64, "selectedBytes": 24,
                    "requiredDecodeBytes": 100, "exportSha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "exportBytes": target.stat().st_size, "entries": rows, "contentInspections": [],
                    "payloadDecoded": True, "installAuthorized": False, "publishable": False}
        return target, observed

    def test_export_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, observed = self.export_fixture(Path(tmp))
            sm.verify_export(path, observed, self.selection)

    def test_export_changed_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, observed = self.export_fixture(Path(tmp))
            observed["entries"][0]["sha256"] = "d" * 64
            with self.assertRaises(ValueError):
                sm.verify_export(path, observed, self.selection)

    def test_export_missing_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, observed = self.export_fixture(Path(tmp))
            observed["entries"].pop()
            with self.assertRaises(ValueError):
                sm.verify_export(path, observed, self.selection)

    def test_export_invented_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, observed = self.export_fixture(Path(tmp))
            observed["contentInspections"] = [{"verified": True}]
            with self.assertRaises(ValueError):
                sm.verify_export(path, observed, self.selection)

    def test_export_publishable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, observed = self.export_fixture(Path(tmp))
            observed["publishable"] = True
            with self.assertRaises(ValueError):
                sm.verify_export(path, observed, self.selection)


class ReferenceClosureTests(unittest.TestCase):
    def setUp(self):
        """rootとchildの人工参照rowを作り、同じrowをobservationへ保持する。

        self.root／self.childの変更はmaintenanceReferencesへ反映する。
        各rowのdirectEntriesは複写したmetadataで、内容署名や導入許可を表さない。
        """
        self.entries = [{"index": 1, "path": "gpu\\root.inf", "bytes": 10},
                        {"index": 2, "path": "gpu\\root.cat", "bytes": 10},
                        {"index": 3, "path": "gpu\\service.exe", "bytes": 10},
                        {"index": 4, "path": "gpu\\child.inf", "bytes": 10},
                        {"index": 5, "path": "gpu\\child.cat", "bytes": 10},
                        {"index": 6, "path": "gpu\\data.bin", "bytes": 10}]
        self.root = self.row("root", self.entries[:3], ["gpu\\child.inf"])
        self.child = self.row("child", self.entries[3:], [])
        self.observation = {"entries": [dict(r, sha256="a" * 64) for r in self.entries],
                            "maintenanceReferences": [self.root, self.child]}

    def row(self, name, entries, children):
        """entriesを複写し、childrenのlistをそのまま保持する人工INF参照rowを返す。

        署名は未確認で、installActionsErrorも未対応を示す固定値のままにする。
        """
        return {"infPath": "gpu\\" + name + ".inf", "infSha256": "a" * 64, "error": 0, "stage": 4,
                "class": "Display", "catalogPath": "gpu\\" + name + ".cat", "directEntries": copy.deepcopy(entries),
                "copyInfPaths": children, "externalDependencies": False, "installActionsError": 0x80070032,
                "contentSignatureVerified": False}

    def plans(self):
        return sm.build_reference_closures(self.observation, self.entries)

    def rejects(self):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.plans()

    def test_transitive_members_and_no_authority(self):
        root = self.plans()[0]
        self.assertEqual(root["state"], "REFERENCE_COMPLETE")
        self.assertEqual(root["closureEntries"], self.entries)
        self.assertFalse(root["contentSignatureVerified"])
        self.assertFalse(root["installAuthorized"])
        self.assertFalse(root["publishable"])

    def test_cycle_is_finite(self):
        self.child["copyInfPaths"] = ["gpu\\ROOT.inf"]
        self.assertEqual(self.plans()[0]["visitedInfCount"], 2)

    def test_shared_member_unique(self):
        self.child["directEntries"].append(copy.deepcopy(self.entries[2]))
        self.assertEqual(len(self.plans()[0]["closureEntries"]), 6)

    def test_unacquired_child_is_not_complete(self):
        self.observation["entries"] = self.observation["entries"][:3]
        self.observation["maintenanceReferences"] = [self.root]
        self.assertEqual(self.plans()[0]["reasons"], ["CHILD_INF_UNACQUIRED"])
        self.assertEqual(self.plans()[0]["closureEntries"], [])

    def test_missing_child_is_not_complete(self):
        self.root["copyInfPaths"] = ["gpu\\missing.inf"]
        self.assertEqual(self.plans()[0]["reasons"], ["COPY_INF_MISSING"])

    def test_external_dependency_is_not_complete(self):
        self.child["externalDependencies"] = True
        self.assertEqual(self.plans()[0]["reasons"], ["EXTERNAL_DEPENDENCY_UNRESOLVED"])

    def test_capacity_is_not_complete(self):
        self.entries[2]["bytes"] = sm.MAX_SELECTED + 1
        self.root["directEntries"][2]["bytes"] = sm.MAX_SELECTED + 1
        self.assertEqual(self.plans()[0]["reasons"], ["CLOSURE_CAPACITY"])

    def test_changed_metadata(self):
        self.root["directEntries"][2]["bytes"] += 1
        self.rejects()

    def test_changed_inf_hash(self):
        self.root["infSha256"] = "b" * 64
        self.rejects()

    def test_fake_content_pass(self):
        self.root["contentSignatureVerified"] = True
        self.rejects()

    def test_copy_traversal(self):
        self.root["copyInfPaths"] = ["gpu\\..\\child.inf"]
        self.rejects()

    def test_copy_outside_parent(self):
        self.root["copyInfPaths"] = ["other\\child.inf"]
        self.rejects()

    def test_copy_executable(self):
        self.root["copyInfPaths"] = ["gpu\\service.exe"]
        self.rejects()

    def test_duplicate_reference_row(self):
        self.observation["maintenanceReferences"][1] = copy.deepcopy(self.root)
        self.rejects()

    def test_unknown_field(self):
        self.root["installAuthorized"] = True
        self.rejects()

    def test_partial_failure(self):
        self.child["error"] = 0x80070002
        self.child["stage"] = 2
        self.rejects()

    def test_rejected_child_is_not_complete(self):
        self.child.update(error=0x80070002, stage=2, **{"class": ""}, catalogPath="", directEntries=[],
                          copyInfPaths=[], installActionsError=0)
        self.assertEqual(self.plans()[0]["reasons"], ["CHILD_REFERENCE_REJECTED"])

    def test_missing_catalog(self):
        self.root["directEntries"].pop(1)
        self.rejects()

    def test_unresolved_string_token(self):
        self.root["copyInfPaths"] = ["gpu\\%Child%.inf"]
        self.rejects()

    def test_boolean_error(self):
        self.root["error"] = False
        self.rejects()

    def test_unknown_stage(self):
        self.root["stage"] = 5
        self.rejects()

    def test_duplicate_copy_dependency(self):
        self.root["copyInfPaths"] *= 2
        self.rejects()

    def test_bounded_dependency_frontier(self):
        self.root["copyInfPaths"] = ["gpu\\missing-" + str(i) + ".inf" for i in range(1024)]
        self.assertEqual(self.plans()[0]["reasons"], ["DEPENDENCY_CAPACITY"])
        self.assertEqual(self.plans()[0]["closureEntries"], [])

    def test_source_traversal(self):
        self.root["directEntries"][2]["path"] = "gpu\\..\\service.exe"
        self.rejects()


if __name__ == "__main__":
    unittest.main()
