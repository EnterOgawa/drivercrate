"""Literal閉包・元member binding・改変拒否の非通信試験。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空ZIPだけを使用する。CATは署名済みと偽らず、実端末・導入を扱わない。
"""
import copy
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import collector_registry as cr
import derive_registry_inf_closures as dc
import inspect_large_registry_payloads as ip


INF = b"[Version]\nClass=MEDIA\nCatalogFile=test.cat\n[SourceDisksNames]\n1=Description\n[SourceDisksFiles]\ntest.sys=1\n"


class DerivationTests(unittest.TestCase):
    """限定literal解釈と原物拘束を検査し、未知形式の黙認を防ぐ。"""

    def test_literal_reference(self):
        self.assertEqual(dc.references(INF), {"test.cat", "test.sys"})

    def test_selection_policy_rejections(self):
        large = {"evidence": {"acquisitions": [{"recordId": "record-one", "state": "DOWNLOADED"}]},
                 "plan": {"items": [{"recordId": "record-one", "format": "ZIP"}]}}
        selection = {"schema": dc.PLAN_SCHEMA, "revision": "test", "selections": [
            {"id": "closure-one", "recordId": "record-one", "infMember": "folder/test.inf"}]}
        dc.validate_selection(large, selection)
        for change in ({"recordId": "other"}, {"infMember": "../test.inf"}, {"infMember": "/test.inf"},
                       {"infMember": "folder//test.inf"}, {"infMember": "test.exe"}, {"extra": True}):
            invalid = copy.deepcopy(selection)
            invalid["selections"][0].update(change)
            with self.subTest(change=change), self.assertRaises(cr.RegistryError):
                dc.validate_selection(large, invalid)
        invalid = copy.deepcopy(selection)
        invalid["selections"] *= 2
        with self.assertRaises(cr.RegistryError):
            dc.validate_selection(large, invalid)
        for mode in ("EXE",):
            large["plan"]["items"][0]["format"] = mode
            with self.assertRaises(cr.RegistryError):
                dc.validate_selection(large, selection)
        large["plan"]["items"][0]["format"] = "ZIP"
        large["evidence"]["acquisitions"][0]["state"] = "FAILED"
        with self.assertRaises(cr.RegistryError):
            dc.validate_selection(large, selection)

    def test_nonliteral_references(self):
        for modified in (INF.replace(b"test.cat", b"%Catalog%"), INF.replace(b"test.sys=1", b"test.sys=1,sub"),
                         INF.replace(b"1=Description", b"1=Description,cab"),
                         INF.replace(b"test.sys=1", b"test.sys=2"),
                         INF.replace(b"test.sys=1", b"test.sys=%Disk%"),
                         INF.replace(b"test.sys=1", b"../test.sys=1"),
                         INF.replace(b"test.sys=1", b"test.sys=1\nTEST.SYS=1")):
            with self.subTest(modified=modified), self.assertRaises(cr.RegistryError):
                dc.references(modified)

    def make_source(self, root, *, missing=False):
        """呼出元のrootへ未署名の人工ZIPを作り、missing時だけSYSを省く。

        CATとSYSは検査用byteであり、署名合格を表さない。setup.exeも格納するだけで、
        rootの後始末は呼出元のTemporaryDirectoryへ任せる。
        """
        source = root / "source.zip"
        with zipfile.ZipFile(source, "x") as archive:
            archive.writestr("folder/test.inf", INF)
            archive.writestr("folder/test.cat", b"not-a-signed-catalog")
            if not missing:
                archive.writestr("folder/test.sys", b"not-a-driver")
            archive.writestr("setup.exe", b"MZ-not-executed")
        return source

    def test_copy_preserves_byte_and_omits_unrelated_exe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_source(root)
            derived = root / "derived.zip"
            proof = dc.create_closure(source, ip.file_hash(source), "folder/test.inf", derived)
            dc.verify_closure(source, derived, proof)
            self.assertEqual(len(proof["members"]), 3)
            self.assertNotEqual(proof["sourceArchiveSha256"], proof["derivedArchiveSha256"])
            with zipfile.ZipFile(derived) as archive:
                self.assertNotIn("setup.exe", archive.namelist())

    def test_missing_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory), missing=True)
            with zipfile.ZipFile(source) as archive, self.assertRaisesRegex(cr.RegistryError, "REFERENCE_MISSING"):
                dc.select_members(archive, "folder/test.inf")

    def test_inf_case_must_be_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            with zipfile.ZipFile(source) as archive, self.assertRaisesRegex(cr.RegistryError, "SELECTED_INF"):
                dc.select_members(archive, "folder/TEST.inf")

    def test_wrong_source_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_source(root)
            with self.assertRaisesRegex(cr.RegistryError, "SOURCE_HASH_BINDING"):
                dc.create_closure(source, "0" * 64, "folder/test.inf", root / "derived.zip")
            self.assertFalse((root / "derived.zip").exists())

    def test_modified_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_source(root)
            derived = root / "derived.zip"
            proof = dc.create_closure(source, ip.file_hash(source), "folder/test.inf", derived)
            for key in ("sourceArchiveSha256", "derivedArchiveSha256", "sourceInfSha256"):
                invalid = {**proof, key: "0" * 64}
                with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                    dc.verify_closure(source, derived, invalid)

    def test_member_hash_and_set_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_source(root)
            derived = root / "derived.zip"
            proof = dc.create_closure(source, ip.file_hash(source), "folder/test.inf", derived)
            invalid = copy.deepcopy(proof)
            invalid["members"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(cr.RegistryError, "CLOSURE_MEMBER_HASH"):
                dc.verify_closure(source, derived, invalid)
            invalid = copy.deepcopy(proof)
            invalid["members"].pop()
            with self.assertRaisesRegex(cr.RegistryError, "CLOSURE_MEMBER_SET"):
                dc.verify_closure(source, derived, invalid)

    def test_existing_output_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_source(root)
            with self.assertRaisesRegex(cr.RegistryError, "OUTPUT_EXISTS"):
                dc.create_closure(source, ip.file_hash(source), "folder/test.inf", source)

    def test_derivation_root_binding(self):
        large = {"evidence": {"registrySha256": "a" * 64, "asOf": "2026-10-04T01:00:00Z",
            "acquisitions": [{"recordId": "record-one", "state": "DOWNLOADED", "sha256": "b" * 64}]},
            "plan": {"items": [{"recordId": "record-one", "format": "ZIP"}]}}
        plan = {"schema": dc.PLAN_SCHEMA, "revision": "test", "selections": [
            {"id": "closure-one", "recordId": "record-one", "infMember": "folder/test.inf"}]}
        proof = {"schema": dc.PROOF_SCHEMA, "researchOnly": True, "publishable": False, "installAuthorized": False,
            "registrySha256": "a" * 64, "largePayloadEvidenceSha256": cr.digest(cr.json_bytes(large)),
            "plan": plan, "planSha256": cr.digest(cr.json_bytes(plan)), "toolSha256": "c" * 64,
            "checkedAt": "2026-10-04T01:01:00Z", "closures": [{"id": "closure-one", "recordId": "record-one",
                "sourceArchiveSha256": "b" * 64, "sourceInfMember": "folder/test.inf", "sourceInfSha256": "d" * 64,
                "derivedArchiveSha256": "e" * 64, "derivedArchiveBytes": 100,
                "members": [{"sourcePath": "folder/test.inf", "bytes": 100, "sha256": "d" * 64}]}]}
        with patch.object(dc, "verify_closure"):
            dc.verify_derivation(large, proof, Path("sources"), Path("closures"))
        for changes in ({"registrySha256": "0" * 64}, {"largePayloadEvidenceSha256": "0" * 64},
                        {"planSha256": "0" * 64}, {"publishable": True}, {"installAuthorized": True},
                        {"checkedAt": "2026-10-04T00:00:00Z"}, {"closures": []}, {"extra": True}):
            invalid = {**proof, **changes}
            with self.subTest(changes=changes), self.assertRaises(cr.RegistryError):
                dc.verify_derivation(large, invalid, Path("sources"), Path("closures"))
        for changes in ({"recordId": "other"}, {"sourceArchiveSha256": "0" * 64},
                        {"sourceInfMember": "other.inf"}, {"derivedArchiveBytes": True}, {"members": []}):
            invalid = copy.deepcopy(proof)
            invalid["closures"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(cr.RegistryError):
                dc.verify_derivation(large, invalid, Path("sources"), Path("closures"))


if __name__ == "__main__":
    unittest.main()
