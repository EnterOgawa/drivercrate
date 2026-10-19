"""大型ZIPの非実行・有限読込み・危険path拒否を架空データで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
本体download・HTTP・署名合格・実端末情報を使用しない。
"""
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

import collector_registry as cr
import inspect_large_registry_payloads as ip


def entry(name="test.inf", size=100, compressed=100):
    """展開せずmetadataだけを持つ架空entryを返す。"""
    value = zipfile.ZipInfo(name)
    value.file_size = size
    value.compress_size = compressed
    return value


class StaticZipTests(unittest.TestCase):
    """宣言制限と実読込み結果を分けて検査する。"""

    def test_regular_inventory(self):
        result = ip.validate_entries([entry(), entry("test.cat"), entry("nested.exe")])
        self.assertEqual(result["infs"], 1)
        self.assertEqual(result["extensions"][".exe"], 1)

    def test_path_rejections(self):
        for name in ("../a.inf", "/a.inf", "C:/a.inf", "a\\b.inf", "a//b.inf", "a/./b.inf",
                     "a./b.inf", "a /b.inf", "a\x01b.inf"):
            with self.subTest(name=name), self.assertRaisesRegex(cr.RegistryError, "MEMBER_PATH"):
                ip.validate_entries([entry(name)])

    def test_case_duplicate(self):
        with self.assertRaisesRegex(cr.RegistryError, "DUPLICATE_MEMBER"):
            ip.validate_entries([entry("A.inf"), entry("a.inf")])

    def test_symlink(self):
        value = entry()
        value.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(cr.RegistryError, "MEMBER_SPECIAL"):
            ip.validate_entries([value])

    def test_encryption_and_codec(self):
        for flags, codec in ((1, 0), (0, zipfile.ZIP_LZMA)):
            value = entry()
            value.flag_bits = flags
            value.compress_type = codec
            with self.assertRaisesRegex(cr.RegistryError, "MEMBER_ENCODING"):
                ip.validate_entries([value])

    def test_ratio(self):
        with self.assertRaisesRegex(cr.RegistryError, "COMPRESSION_RATIO"):
            ip.validate_entries([entry(size=201, compressed=1)])

    def test_inf_size(self):
        with self.assertRaisesRegex(cr.RegistryError, "INF_BUDGET"):
            ip.validate_entries([entry(size=ip.MAX_INF + 1, compressed=ip.MAX_INF + 1)])

    def test_total_inf_budget(self):
        with self.assertRaisesRegex(cr.RegistryError, "INF_BUDGET"):
            ip.validate_entries([entry(f"{i}.inf", ip.MAX_INF, ip.MAX_INF) for i in range(17)])

    def test_declared_expansion_budget(self):
        with self.assertRaisesRegex(cr.RegistryError, "EXPANSION_BUDGET"):
            ip.validate_entries([entry(f"{i}.sys", 2 * ip.lp.GIB, ip.lp.GIB) for i in range(5)])

    def test_inf_count(self):
        with self.assertRaisesRegex(cr.RegistryError, "INF_BUDGET"):
            ip.validate_entries([entry(f"{i}.inf", 1, 1) for i in range(ip.MAX_INFS + 1)])

    def test_entry_count(self):
        with self.assertRaisesRegex(cr.RegistryError, "ENTRY_BUDGET"):
            ip.validate_entries([entry()] * (ip.MAX_ENTRIES + 1))

    def test_static_inf_omits_identifiers(self):
        raw = b"[Version]\nClass=System\nDriverVer=01/01/2026,1.2.3.4\n[Models]\nDevice=Install,PCI\\VEN_DEAD&DEV_BEEF\n"
        result = ip.inf_facts(raw, 1)
        self.assertEqual(result["declarations"]["class"], "System")
        self.assertNotIn("VEN_", str(result))
        self.assertFalse(result["hasExecutionDirective"])

    def test_execution_and_dependency_flags(self):
        result = ip.inf_facts(b"[Install]\nInclude=test.inf\nRegisterDlls=Test\nFirmwareVersion=1\n", 1)
        self.assertTrue(result["hasExecutionDirective"])
        self.assertTrue(result["hasExternalDependencyDirective"])
        self.assertEqual(result["firmwareDirectiveMarkers"], ["firmwareversion"])

    def test_real_zip_hash_and_no_signature_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test.zip"
            with zipfile.ZipFile(path, "x") as archive:
                archive.writestr("test.inf", b"[Version]\nClass=Net\n")
            result = ip.inspect_zip(path, ip.file_hash(path))
            self.assertEqual(result["inventory"]["infs"], 1)
            self.assertFalse(result["contentSignatureVerified"])
            self.assertFalse(result["allMemberCrcChecked"])
            with self.assertRaisesRegex(cr.RegistryError, "PAYLOAD_HASH_BINDING"):
                ip.inspect_zip(path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
