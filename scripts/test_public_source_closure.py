"""公開候補の静的閉包を、workも製品実行も不要な合成file集合で検証する。

作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0。repository rootのLICENSEを参照する。
sourceを動作させず、必要input欠落・除外work参照・import・生成template・package境界を検査する。
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_public_source_closure as closure


class SourceClosureTests(unittest.TestCase):
    """実機情報を使わず、所有権とhashを記録した小さな通常fileだけを扱う。"""

    def setUp(self):
        """caseごとに新規tempを所有し、正常な最小source閉包を作成する。"""
        self.root = Path(tempfile.mkdtemp(prefix="drivercrate-source-closure-"))
        self.owned = {}
        self.put("CMakeLists.txt", 'include(cmake/options.cmake)\nadd_library(example src/a.cpp)\n')
        self.put("cmake/options.cmake", 'configure_file(cmake/version.h.in generated/version.h)\n')
        self.put("cmake/version.h.in", '#pragma once\n#define VALUE @VALUE@\n')
        self.put("src/a.cpp", '#include "a.h"\n#include "version.h"\n')
        self.put("src/a.h", '#pragma once\n#include "core/b.h"\n')
        self.put("src/core/b.h", '#pragma once\n')
        self.put("scripts/entry.py", 'import json\nimport helper\n')
        self.put("scripts/helper.py", 'VALUE = 1\n')
        self.put("scripts/package.ps1", ". (Join-Path $PSScriptRoot 'profile.ps1')\n")
        self.put("scripts/profile.ps1", '# synthetic source\n')
        self.put("src/app/app.rc", '1 ICON "assets\\\\example.ico"\n')
        self.put("src/app/assets/example.ico", b"synthetic icon bytes")
        self.put("LICENSE", 'synthetic source license\n')
        self.manifest = {"schema": closure.SCHEMA, "finalAllowlist": False,
                         "files": sorted([*self.owned, "scripts/public_source_export_manifest.json"]),
                         "excluded": [{"path": "scripts/old.ps1", "reason": "historical only"}],
                         "generatedHeaders": {"version.h": "cmake/version.h.in"},
                         "requiredEdges": [{"owner": "scripts/package.ps1", "input": "LICENSE", "kind": "license"}],
                         "externalInputs": [], "limitations": ["not a native build"]}
        self.save_manifest()

    def put(self, name, value):
        """合成fileだけを書込み、cleanup時のexact byte pinを更新する。"""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value.encode("utf-8") if isinstance(value, str) else value
        path.write_bytes(raw)
        self.owned[name] = hashlib.sha256(raw).hexdigest()

    def remove(self, name):
        """意図的な欠損caseの通常fileをpin確認後に一件だけ削除する。"""
        path = self.root / name
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), self.owned[name])
        self.assertFalse(path.is_symlink())
        path.unlink()
        del self.owned[name]

    def save_manifest(self):
        """caseが指定した候補契約を合成treeへ保存する。"""
        self.put("scripts/public_source_export_manifest.json", json.dumps(self.manifest) + "\n")

    def reject(self, expected):
        """実際のcheckerが指定した不一致理由を返すことを確認する。"""
        with self.assertRaisesRegex(closure.ClosureError, expected):
            closure.check(self.root)

    def tearDown(self):
        """entry集合・reparse・hashを検証し、所有fileと空dirだけを非再帰削除する。"""
        actual = set()
        directories = []
        for directory, children, leaves in os.walk(self.root, followlinks=False):
            current = Path(directory)
            info = current.lstat()
            self.assertFalse(stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400)
            directories.append(current)
            for child in children:
                child_info = (current / child).lstat()
                self.assertFalse(stat.S_ISLNK(child_info.st_mode) or getattr(child_info, "st_file_attributes", 0) & 0x400)
            for leaf in leaves:
                path = current / leaf
                name = path.relative_to(self.root).as_posix()
                info = path.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertFalse(getattr(info, "st_file_attributes", 0) & 0x400)
                actual.add(name)
                self.assertIn(name, self.owned)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), self.owned[name])
        self.assertEqual(actual, set(self.owned))
        for name in sorted(actual):
            (self.root / name).unlink()
        for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
            directory.rmdir()
        self.assertFalse(self.root.exists())

    def test_positive_without_work(self):
        """workのない所有fixtureを読み、importとresourceを含む静的閉包の成功区分を確認する。"""
        self.assertFalse((self.root / "work").exists())
        result = closure.check(self.root)
        self.assertEqual(result["fileCount"], len(self.manifest["files"]))
        self.assertFalse(result["finalAllowlist"])
        self.assertEqual(result["status"], "STATIC_REFERENCES_CLOSED_NOT_FRESH_BUILD")
        self.assertTrue(any(row["kind"] == "python-import" for row in result["edges"]))
        self.assertTrue(any(row["kind"] == "resource" for row in result["edges"]))

    def test_repeat_is_byte_deterministic(self):
        """同じ所有fileを二回読む結果構造が一致し、観測順でpinやedgeが揺れないことを確認する。"""
        self.assertEqual(closure.check(self.root), closure.check(self.root))

    def test_missing_transitive_header(self):
        """pin確認済みの合成headerを削除し、推移includeの実file欠損を成功にしないことを確認する。"""
        self.remove("src/core/b.h")
        self.reject("MISSING_INPUT")

    def test_existing_header_omitted_from_manifest(self):
        """合成headerを残したまま候補集合から外し、存在だけで閉包内と扱わないことを確認する。"""
        self.manifest["files"].remove("src/core/b.h")
        self.save_manifest()
        self.reject("MISSING_LOCAL_INCLUDE")

    def test_missing_generated_template(self):
        """所有templateを削除し、生成headerの宣言だけでは入力欠損を補えないことを確認する。"""
        self.remove("cmake/version.h.in")
        self.reject("MISSING_INPUT")

    def test_missing_icon(self):
        """合成iconをpin確認後に削除し、resourceから参照する実入力の欠損を拒否させる。"""
        self.remove("src/app/assets/example.ico")
        self.reject("MISSING_INPUT")

    def test_unlisted_python_import(self):
        """合成moduleを候補集合だけから外し、local import先の無登録を拒否させる。"""
        self.manifest["files"].remove("scripts/helper.py")
        self.save_manifest()
        self.reject("MISSING_PYTHON_IMPORT")

    def test_unlisted_powershell_module(self):
        """dot-source先を候補集合だけから外し、存在する所有fileも境界外なら拒否させる。"""
        self.manifest["files"].remove("scripts/profile.ps1")
        self.save_manifest()
        self.reject("INPUT_OUTSIDE_MANIFEST")

    def test_work_dot_source_rejected_without_read(self):
        """合成scriptのwork参照を拒否し、限定patch中の通常file照会にworkが渡らないことを確認する。"""
        self.put("scripts/package.ps1", ". (Join-Path $PSScriptRoot '../work/analysis/hidden.ps1')\n")
        visited = []
        original = closure.normal_file

        def tracked(root, name):
            """借用rootと相対名を元の検証へ渡し、照会名だけをcase所有listへ記録して結果を返す。"""
            visited.append(name)
            return original(root, name)

        with patch.object(closure, "normal_file", tracked):
            self.reject("EXCLUDED_DEPENDENCY")
        self.assertFalse(any(name.startswith("work/") for name in visited))

    def test_excluded_work_candidate_rejected(self):
        """manifestへwork候補名だけを追加し、実file作成なしで除外rootの契約違反を拒否させる。"""
        self.manifest["files"].append("work/analysis/hidden.ps1")
        self.manifest["files"].sort()
        self.save_manifest()
        self.reject("EXCLUDED_ROOT")

    def test_required_license_edge_preserved(self):
        """所有LICENSEを候補集合から外し、必須license edgeを黙って欠落させないことを確認する。"""
        self.manifest["files"].remove("LICENSE")
        self.save_manifest()
        self.reject("INPUT_OUTSIDE_MANIFEST")

    def test_cmake_missing_reference(self):
        """合成CMakeを未登録source参照へ置換し、buildを実行せず入力境界の欠落を拒否させる。"""
        self.put("CMakeLists.txt", "add_library(example src/missing.cpp)\n")
        self.reject("INPUT_OUTSIDE_MANIFEST")

    def test_case_duplicate_rejected(self):
        """大小文字だけ異なる候補名を追加し、Windowsで衝突するpathを別file扱いしないことを確認する。"""
        self.manifest["files"].append("src/A.cpp")
        self.manifest["files"].sort()
        self.save_manifest()
        self.reject("UNSORTED_OR_DUPLICATE_PATH")

    def test_parent_escape_rejected(self):
        """path正規化へ親逸脱名を渡し、対象fileを開く前の字句境界で拒否されることを確認する。"""
        with self.assertRaises(closure.ClosureError):
            closure.relative_name("../outside.json")

    def test_absolute_and_backslash_rejected(self):
        """絶対名・区切り違反・特殊名・payload名の固定集合を、実I/Oなしのpath検証で拒否させる。"""
        for path in ("/outside.json", "C:/outside.json", "src\\a.h", "src/a.h.", "src/a?.h", "src/NUL.h", "src/a\n.h", "data/driver.sys"):
            with self.subTest(path=path), self.assertRaises(closure.ClosureError):
                closure.relative_name(path)

    def test_reparse_input_rejected(self):
        """所有headerのlstat応答だけを一時差替えし、実reparse作成なしで属性による拒否を確認する。"""
        original = Path.lstat

        def marked(path):
            """借用pathを実lstatし、指定fixtureだけreparse属性の代替応答を返し、他は元の情報を返す。"""
            info = original(path)
            if path == self.root / "src/a.h":
                return type("ReparseInfo", (), {"st_mode": info.st_mode, "st_file_attributes": 0x400})()
            return info

        with patch.object(Path, "lstat", marked):
            self.reject("REPARSE_INPUT")

    def test_read_budget_rejected(self):
        """patch期間だけ総読取予算を縮め、所有fixtureが上限超過のまま成功しないことを確認する。"""
        with patch.object(closure, "MAX_TOTAL_BYTES", 16):
            self.reject("READ_BUDGET")

    def test_duplicate_json_key_rejected(self):
        """所有manifestを重複keyの合成byteへ置換し、JSONの後勝ち解釈で受理しないことを確認する。"""
        self.put("scripts/public_source_export_manifest.json", '{"schema":1,"schema":2}')
        self.reject("DUPLICATE_JSON_KEY")

    def test_final_allowlist_cannot_be_claimed(self):
        """候補manifestの最終承認flagを変え、静的検査だけで公開allowlistを確定できないことを確認する。"""
        self.manifest["finalAllowlist"] = True
        self.save_manifest()
        self.reject("MANIFEST_CONTRACT")

    def test_historical_tool_not_required(self):
        """未作成の履歴専用scriptが必要file集合へ復活せず、所有fixtureの閉包が成立することを確認する。"""
        result = closure.check(self.root)
        self.assertNotIn("scripts/old.ps1", {row["path"] for row in result["files"]})
        self.assertFalse((self.root / "scripts/old.ps1").exists())

    def test_collector_payload_modules(self):
        """メモリ上の固定PowerShell式からpayload module名を抽出し、scriptや製品を実行せず結果を照合する。"""
        text = "@('alpha', 'beta') | ForEach-Object { 'scripts/' + $_ + '.py' }\n'scripts/workspace.py'"
        self.assertEqual(closure.collector_payload_edges(text), ["scripts/alpha.py", "scripts/beta.py", "scripts/workspace.py"])

    def test_unknown_collector_payload_expression_rejected(self):
        """未対応のpayload構築式をメモリ上で渡し、未知を空の依存集合へ置き換えず拒否させる。"""
        with self.assertRaisesRegex(closure.ClosureError, "COLLECTOR_PAYLOAD_EXPRESSION_UNKNOWN"):
            closure.collector_payload_edges("Get-ArbitraryModuleList | ForEach-Object { $_ }")

    def test_relative_python_import_is_unknown(self):
        """所有entryを相対importへ置換し、解決未対応の依存を成功へ数えず未知として拒否させる。"""
        self.put("scripts/entry.py", "from . import helper\n")
        self.reject("RELATIVE_PYTHON_IMPORT_UNKNOWN")

    def test_missing_fixed_repository_input(self):
        """合成Pythonへ固定repository入力の欠損を記載し、scriptを実行せず候補外参照を拒否させる。"""
        self.put("scripts/entry.py", 'from pathlib import Path\nPLAN = Path(__file__).parent / "docs/evaluation/missing.json"\n')
        self.reject("INPUT_OUTSIDE_MANIFEST")

    def test_missing_native_runtime_fixture(self):
        """合成C++へ未登録runtime fixture名を記載し、native実行なしで固定入力の欠落を拒否させる。"""
        self.put("src/a.cpp", 'const auto file = L"tests/fixtures/missing.json";\n')
        self.reject("INPUT_OUTSIDE_MANIFEST")

    def test_main_preserves_failure_exit(self):
        """所有source欠損をCLI入口へ渡し、argvとstderrを限定patchして終了値1と拒否理由の保持を確認する。"""
        self.remove("src/a.cpp")
        with patch.object(sys, "argv", ["checker", "--root", str(self.root)]), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(closure.main(), 1)
        self.assertIn("MISSING_INPUT", output.getvalue())

    def test_bootstrap_generated_and_resource_inputs(self):
        """生成tableとresourceの元templateを含む場合だけ、bootstrap閉包を受理する。"""
        self.put("src/bootstrap.cpp", '#include "bootstrap_table.h"\n')
        self.put("src/bootstrap_table.h.in", '#pragma once\n')
        self.put("src/bootstrap.rc.in", '1 RT_MANIFEST "@MANIFEST@"\n')
        self.manifest["files"] = sorted(set(self.manifest["files"]) | {
            "src/bootstrap.cpp", "src/bootstrap_table.h.in", "src/bootstrap.rc.in"})
        self.manifest["generatedHeaders"]["bootstrap_table.h"] = "src/bootstrap_table.h.in"
        self.manifest["requiredEdges"].append({"owner": "scripts/package.ps1", "input": "src/bootstrap.rc.in", "kind": "resource-template"})
        self.save_manifest()
        closure.check(self.root)
        self.manifest["files"].remove("src/bootstrap.rc.in")
        self.save_manifest()
        self.reject("INPUT_OUTSIDE_MANIFEST")
        self.manifest["files"].append("src/bootstrap.rc.in")
        self.manifest["files"].sort()
        self.manifest["files"].remove("src/bootstrap_table.h.in")
        self.save_manifest()
        self.reject("GENERATED_HEADER_CONTRACT")

    def test_v6_explicit_required_edge(self):
        """別式で構成するv6 moduleも明示edgeで閉じ、存在だけの未採用を拒否する。"""
        self.put("scripts/local_entry.py", 'import helper\n')
        self.manifest["files"].append("scripts/local_entry.py")
        self.manifest["files"].sort()
        self.manifest["requiredEdges"].append({"owner": "scripts/package.ps1", "input": "scripts/local_entry.py", "kind": "collector-v6-module"})
        self.save_manifest()
        closure.check(self.root)
        self.manifest["files"].remove("scripts/local_entry.py")
        self.save_manifest()
        self.reject("INPUT_OUTSIDE_MANIFEST")


class CmakeScratchTests(unittest.TestCase):
    """h8d1の新しい静的四caseだけを実行可能にし、既済26caseの反復を要求しない。"""

    VALID = '''set(drivercrate_integrity_test_scratch
        "${CMAKE_CURRENT_BINARY_DIR}/test-scratch/maintenance-inf-integrity")
    file(MAKE_DIRECTORY "${drivercrate_integrity_test_scratch}")
    target_compile_definitions(drivercrate_maintenance_inf_integrity_tests PRIVATE
        DRIVERCRATE_REACHED_WORKSPACE=L"${drivercrate_integrity_test_scratch}/reached-$<CONFIG>"
        DRIVERCRATE_RESIDUAL_WORKSPACE=L"${drivercrate_integrity_test_scratch}/residual-$<CONFIG>")'''

    def test_declared_binary_parent_positive(self):
        """固定CMake文字列のbuild内祖先宣言を受理させ、CMake実行やdirectory作成なしで契約を確認する。"""
        closure.verify_integrity_test_scratch(self.VALID)

    def test_old_work_root_rejected(self):
        """メモリ上のscratch定義一件を旧work rootへ戻し、unit出力先の分離違反を拒否させる。"""
        old = self.VALID.replace("${drivercrate_integrity_test_scratch}/reached-$<CONFIG>",
                                 "${CMAKE_CURRENT_SOURCE_DIR}/work/analysis/old/writer-$<CONFIG>")
        with self.assertRaisesRegex(closure.ClosureError, "UNIT_SCRATCH_ROOT_NOT_ISOLATED"):
            closure.verify_integrity_test_scratch(old)

    def test_missing_ancestor_creation_rejected(self):
        """固定CMake文字列から祖先生成宣言だけを外し、writer leafの親が未宣言なら拒否させる。"""
        missing = self.VALID.replace('file(MAKE_DIRECTORY "${drivercrate_integrity_test_scratch}")', "")
        with self.assertRaisesRegex(closure.ClosureError, "UNIT_SCRATCH_ANCESTOR_NOT_DECLARED"):
            closure.verify_integrity_test_scratch(missing)

    def test_source_parent_substitution_rejected(self):
        """メモリ上の祖先をsource側へ差替えし、build専用scratchという前提の逸脱を拒否させる。"""
        escaped = self.VALID.replace("${CMAKE_CURRENT_BINARY_DIR}", "${CMAKE_CURRENT_SOURCE_DIR}")
        with self.assertRaisesRegex(closure.ClosureError, "UNIT_SCRATCH_ANCESTOR_NOT_DECLARED"):
            closure.verify_integrity_test_scratch(escaped)


if __name__ == "__main__":
    unittest.main()
