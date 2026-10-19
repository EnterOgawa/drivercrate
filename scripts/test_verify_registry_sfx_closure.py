"""分割取得の元member拘束・全参照・偽内容合格の拒否を検証する。"""

import copy
import unittest

import collector_large_payload_evidence as lp
import verify_registry_sfx_closure as vc


class ClosureTests(unittest.TestCase):
    def setUp(self):
        """複数GiBの宣言sizeを持つ人工metadataを作り、本体byteは確保しない。

        previousはself.refと同じrowを参照し、observed側のmaintenanceReferencesは複写する。
        contentInspectionsの合格値も架空観測であり、実署名を検証した結果ではない。
        """
        self.entries = [{"index": 7, "path": "Display.Driver\\driver.inf", "bytes": 16},
                        {"index": 8, "path": "Display.Driver\\driver.cat", "bytes": 8},
                        {"index": 9, "path": "Display.Driver\\driver.sys", "bytes": 2 * lp.GIB - 24},
                        {"index": 10, "path": "Display.Driver\\data.bin", "bytes": 600 * 1024 ** 2}]
        self.ref = {"infPath": self.entries[0]["path"], "infSha256": "d" * 64, "error": 0, "stage": 4,
                    "class": "Display", "catalogPath": self.entries[1]["path"],
                    "directEntries": copy.deepcopy(self.entries), "copyInfPaths": [],
                    "externalDependencies": False, "installActionsError": 0, "contentSignatureVerified": False}
        self.previous = {"entries": [{**r, "sha256": "d" * 64} for r in self.entries[:2]],
                         "maintenanceReferences": [self.ref]}
        self.source = {"name": "fixture-inf", "recordId": "fixture-record", "sample": "fixture-record",
                       "vendor": "NVIDIA", "purpose": "INF_CATALOG", "inputSha256": "a" * 64,
                       "entries": copy.deepcopy(self.entries[:2])}
        self.bindings = {k: "b" * 64 for k in ("registrySha256", "largeEvidenceSha256", "structureSha256",
                                              "selectionEvidenceSha256")}
        self.plan = vc.make_plan(self.source, self.previous, self.entries, 7, self.bindings)
        self.observed = {"state": "REFERENCE_CONTENT_OBSERVED", "inputSha256": "a" * 64, "rootIndex": 7,
                         "selectedBytes": sum(r["bytes"] for r in self.entries), "batches": 2,
                         "entries": [{**r, "sha256": "d" * 64} for r in self.entries],
                         "maintenanceReferences": [copy.deepcopy(self.ref)], "contentInspections": [
                             {"infPath": self.ref["infPath"], "infSha256": "d" * 64, "referenceError": 0,
                              "referencesAcquired": True, "integrityError": 0, "contentSignatureVerified": True}],
                         "payloadDecoded": True, "installAuthorized": False, "publishable": False}

    def validate(self):
        return vc.validate_observation(self.observed, self.plan, self.previous, self.entries)

    def rejects(self, change):
        """changeを同期適用してから、validateだけを期待例外の範囲へ置く。

        変更callbackが失敗した場合は、その例外を検証成功へ数えない。
        """
        change()
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.validate()

    def test_complete_large_selection(self):
        self.assertTrue(self.validate())

    def test_old_two_gib_plan_stays_incomplete(self):
        import select_registry_sfx_members as sm
        self.assertEqual(sm.build_reference_closures(self.previous, self.entries)[0]["state"], "UNRESOLVED")

    def test_catalog_rejection_is_not_content_success(self):
        self.observed["contentInspections"][0].update(integrityError=0x80096010, contentSignatureVerified=False)
        self.assertFalse(self.validate())

    def test_fake_catalog_success(self):
        self.rejects(lambda: self.observed["contentInspections"][0].update(integrityError=0x80096010))

    def test_missing_source(self):
        self.rejects(lambda: self.observed["entries"].pop())

    def test_source_changed(self):
        self.rejects(lambda: self.observed["entries"][-1].update(bytes=2))

    def test_source_hash_not_hex(self):
        self.rejects(lambda: self.observed["entries"][-1].update(sha256="x" * 64))

    def test_original_inf_hash_changed(self):
        self.rejects(lambda: self.observed["entries"][0].update(sha256="c" * 64))

    def test_duplicate_source(self):
        self.rejects(lambda: self.observed["entries"].append(self.observed["entries"][-1]))

    def test_root_changed(self):
        self.rejects(lambda: self.observed.update(rootIndex=8))

    def test_boolean_root(self):
        self.rejects(lambda: self.observed.update(rootIndex=True))

    def test_input_changed(self):
        self.rejects(lambda: self.observed.update(inputSha256="e" * 64))

    def test_install_authorized(self):
        self.rejects(lambda: self.observed.update(installAuthorized=True))

    def test_publishable(self):
        self.rejects(lambda: self.observed.update(publishable=True))

    def test_wrong_batch_count(self):
        self.rejects(lambda: self.observed.update(batches=1))

    def test_wrong_total(self):
        self.rejects(lambda: self.observed.update(selectedBytes=1))

    def test_unacquired_reference(self):
        self.rejects(lambda: self.observed["contentInspections"][0].update(referencesAcquired=False))

    def test_reference_error(self):
        self.rejects(lambda: self.observed["contentInspections"][0].update(referenceError=2))

    def test_unknown_native_field(self):
        self.rejects(lambda: self.observed.update(untrusted=True))

    def test_changed_reference(self):
        self.rejects(lambda: self.observed["maintenanceReferences"][0].update(className="Display"))

    def test_missing_content_check(self):
        self.rejects(lambda: self.observed.update(contentInspections=[]))

    def test_duplicate_content_check(self):
        self.rejects(lambda: self.observed["contentInspections"].append(self.observed["contentInspections"][0]))

    def test_unknown_root(self):
        with self.assertRaises(ValueError):
            vc.root_closure(self.previous, self.entries, 99)

    def test_non_inf_root(self):
        with self.assertRaises(ValueError):
            vc.root_closure(self.previous, self.entries, 8)

    def test_missing_copy_inf(self):
        self.ref["copyInfPaths"] = ["Display.Driver\\child.inf"]
        with self.assertRaises(ValueError):
            vc.root_closure(self.previous, self.entries, 7)

    def test_external_dependency(self):
        self.ref["externalDependencies"] = True
        with self.assertRaises(ValueError):
            vc.root_closure(self.previous, self.entries, 7)

    def test_single_file_budget(self):
        self.entries[-1]["bytes"] = 2 * lp.GIB + 1
        with self.assertRaises(ValueError):
            vc.batch_count(self.entries)

    def test_inf_budget(self):
        self.entries[0]["bytes"] = 4 * 1024 ** 2 + 1
        with self.assertRaises(ValueError):
            vc.batch_count(self.entries)

    def test_total_budget(self):
        extra = [{"index": 20 + i, "path": f"Display.Driver\\extra{i}.bin", "bytes": 2 * lp.GIB} for i in range(4)]
        with self.assertRaises(ValueError):
            vc.batch_count(self.entries + extra)

    def test_unknown_plan_field(self):
        self.plan["extra"] = 1
        with self.assertRaises(ValueError):
            vc.validate_plan(self.plan, self.previous, self.entries, self.bindings, self.source)

    def test_omitted_plan_member(self):
        self.plan["selection"]["entries"].pop()
        with self.assertRaises(ValueError):
            vc.validate_plan(self.plan, self.previous, self.entries, self.bindings, self.source)

    def test_changed_plan_binding(self):
        self.plan["selectionEvidenceSha256"] = "f" * 64
        with self.assertRaises(ValueError):
            vc.validate_plan(self.plan, self.previous, self.entries, self.bindings, self.source)


class DirectContentTests(ClosureTests):
    def setUp(self):
        """親の人工fixtureをdirect用途へ切り替え、未取得の外部依存を残す。

        依存閉包合格はfalseのまま、観測rowを複写してdirect参照の検査だけに限定する。
        """
        super().setUp()
        self.ref["copyInfPaths"] = ["Display.Driver\\child.inf"]
        self.ref["externalDependencies"] = True
        self.ref["installActionsError"] = 0x80070032
        self.plan = vc.make_plan(self.source, self.previous, self.entries, 7, self.bindings, scope="direct")
        self.observed.update(state="DIRECT_CONTENT_OBSERVED", dependencyClosureVerified=False,
                             maintenanceReferences=[copy.deepcopy(self.ref)])
        check = self.observed["contentInspections"][0]
        check["directReferencesAcquired"] = check.pop("referencesAcquired")

    def test_direct_success_keeps_dependencies_unverified(self):
        self.assertTrue(self.validate())
        self.assertFalse(self.observed["dependencyClosureVerified"])
        self.assertTrue(self.observed["maintenanceReferences"][0]["externalDependencies"])
        self.assertEqual(len(self.observed["maintenanceReferences"][0]["copyInfPaths"]), 1)

    def test_fake_dependency_complete(self):
        self.rejects(lambda: self.observed.update(dependencyClosureVerified=True))

    def test_missing_dependency_field(self):
        self.rejects(lambda: self.observed.pop("dependencyClosureVerified"))

    def test_non_boolean_dependency_field(self):
        self.rejects(lambda: self.observed.update(dependencyClosureVerified=0))

    def test_old_observation_state(self):
        self.rejects(lambda: self.observed.update(state="REFERENCE_CONTENT_OBSERVED"))

    def test_erased_copy_inf(self):
        self.rejects(lambda: self.observed["maintenanceReferences"][0].update(copyInfPaths=[]))

    def test_erased_external_dependency(self):
        self.rejects(lambda: self.observed["maintenanceReferences"][0].update(externalDependencies=False))

    def test_old_purpose(self):
        self.rejects(lambda: self.plan["selection"].update(purpose="REFERENCE_CONTENT"))

    def test_old_schema(self):
        self.rejects(lambda: self.plan.update(schema=vc.PLAN_SCHEMA))

    def test_false_direct_acquisition(self):
        self.rejects(lambda: self.observed["contentInspections"][0].update(directReferencesAcquired=False))

    def test_plan_fake_dependency(self):
        self.plan["dependencyClosureVerified"] = True
        with self.assertRaises(ValueError):
            vc.validate_plan(self.plan, self.previous, self.entries, self.bindings, self.source)

    def test_unknown_scope(self):
        with self.assertRaises(ValueError):
            vc.make_plan(self.source, self.previous, self.entries, 7, self.bindings, scope="automatic")


if __name__ == "__main__":
    unittest.main()
