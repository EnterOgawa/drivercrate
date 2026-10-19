"""Doxygen member集合監査のpositive／negative統合fixture。"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from audit_doxygen_members import (
    audit_members, find_doxygen, neutralize_raw_literal_contents, report_error_count,
)
from source_comments import MemberCommentTarget, convert_member_comments
from source_style import hidden_process


POSITIVE_FIXTURE = r"""
namespace fixture {

/** @brief 公開・非公開fieldを持つ型。 */
struct Fields {
    /// 二行で説明する
    /// 公開field。
    int value;

private:
    /// classが所有する上限。
    static constexpr int LIMIT = 3;
};

/** @brief unionの選択値。 */
union Choice {
    /// 数値として保持する場合の値。
    int number;

    /// 真偽として保持する場合の値。
    bool enabled;
};

/** @brief 状態区分。 */
enum class State {
    /// 処理を開始できる。
    READY,

    /// 処理に失敗した。
    FAILED,
};

namespace {

/** @brief このtranslation unit内だけで使用する型。 */
struct Local {
    /// file内だけで使用する値。
    int current;
};

} // namespace

/** @brief 非通信raw HTMLのparser回帰です。
 * @return 架空HTMLです。
 */
[[nodiscard]] std::string dailyIntelPage()
{
    return R"(<html><h1>Intel® Network Adapter Driver for Microsoft Windows 11*</h1>
<p>Intel requires an accepted license agreement in order to download this file.</p>
<textarea id="content-raw" class="license-modal-content_body_license-text-raw" tabindex="0"><html lang="en"><head><title>Intel Fixture License Agreement [v2030.01.02]</title></head><body><p>Artificial fixture terms.</p></body></html></textarea>
<h2>Available Downloads</h2>
<button data-modal-id="1" data-href="https://downloadmirror.intel.com/900011/Wired_driver_31.2.2_x64.zip">Wired_driver_31.2.2_x64.zip</button>
<li>Windows 11 Family*</li><li>Size: 38.6 MB</li>
<li>SHA256: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</li>
<h2>Detailed Description</h2><p><strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip</p>
<h2>This download is valid for the product(s) listed below.</h2>
<a>Intel® Ethernet Network Adapter E610-XT2</a></html>)";
}

} // namespace fixture
"""


NEGATIVE_FIXTURE = r"""
namespace fixture {

/** @brief 不正なfieldコメントを持つ型。 */
struct Fields {
    // 通常コメントはfield文書にしない。
    int ordinary;

    int trailing; ///< 行末形式は採用しない。

    /// 空行で切り離された説明。

    int detached;
};

/** @brief 不正な列挙値コメントを持つ型。 */
enum class State {
    // 通常コメントは列挙値文書にしない。
    ORDINARY,

    TRAILING, ///< 行末形式は採用しない。
};

} // namespace fixture
"""


class DoxygenRawLiteralFilterTests(unittest.TestCase):
    def test_plain_strings_comments_and_raw_lookalikes_remain_byte_exact(self):
        source = ('/// 宣言の説明。\r\nint field;\n'
                  'const char *normal = "R\\\"(quoted)\\\"";\n'
                  '// R"(line comment)"\n/* LR"tag(block)tag" */\n')
        filtered, count = neutralize_raw_literal_contents(source)
        self.assertEqual(count, 0)
        self.assertEqual(filtered.encode("utf-8"), source.encode("utf-8"))

    def test_prefixes_empty_and_max_delimiters_preserve_every_non_body_byte(self):
        for prefix in ("", "u8", "u", "U", "L"):
            for delimiter in ("", "abcdefghijklmnop"):
                for body in ("", '日本語®"///*\\\r\nsecond\n'):
                    with self.subTest(prefix=prefix, delimiter=delimiter, body=body):
                        before = "/// 元の説明。\nconst auto value = " + prefix + 'R"' + delimiter + "("
                        after = ")" + delimiter + '";\n/// 次の説明。\nint next;\n'
                        source = before + body + after
                        expected_body = b"".join(bytes([value]) if value in (10, 13) else b" "
                                                 for value in body.encode("utf-8"))
                        filtered, count = neutralize_raw_literal_contents(source)
                        self.assertEqual(count, 1)
                        self.assertEqual(filtered.encode("utf-8"),
                                         before.encode("utf-8") + expected_body + after.encode("utf-8"))

    def test_multiple_literals_keep_unrelated_normal_literal_and_member_comments(self):
        source = '/// Field.\nconst auto a=R"(x)"; const auto b=LR"d(y\nz)d"; "unchanged";\n'
        filtered, count = neutralize_raw_literal_contents(source)
        self.assertEqual(count, 2)
        self.assertEqual(filtered, '/// Field.\nconst auto a=R"( )"; const auto b=LR"d( \n )d"; "unchanged";\n')

    def test_invalid_literals_fail_before_filtered_output_is_returned(self):
        for source in ('R"tag(unclosed', 'R"tag(body)wrong"',
                       'R"abcdefghijklmnopq(body)abcdefghijklmnopq"', '"unterminated'):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    neutralize_raw_literal_contents(source)


class DoxygenMemberIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doxygen = find_doxygen()

    def audit_fixture(self, source: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="drivercrate-member-fixture-") as directory:
            root = Path(directory)
            path = root / "fixture.cpp"
            path.write_text(source.lstrip(), encoding="utf-8", newline="\n")
            return audit_members(root, [path], self.doxygen)

    def test_positive_fixture_extracts_private_static_union_local_and_enum(self):
        report = self.audit_fixture(POSITIVE_FIXTURE)
        self.assertEqual(report["inventory_count"], 7)
        self.assertEqual(report["documented_count"], 7)
        self.assertEqual(report_error_count(report), 0)

    def test_same_named_qualified_types_and_fields_are_extracted_without_ambiguity(self):
        source = """namespace fixture {
struct State {
    /// 相互排他の役割。
    std::mutex mutex;
    /// 保存先の役割。
    std::filesystem::path path;
};
struct Other {
    /// 初期化された相互排他の役割。
    std::mutex mutex{};
    /// 初期化された保存先の役割。
    std::filesystem::path path{};
    /// 別instanceの相互排他の役割。
    std::mutex mutexCopy;
    /// 別型の同意fieldを参照するpointer。
    bool Options::*consent;
    /// 別型のmethodを参照するpointer。
    void (Options::*callback)(int);
};
}
"""
        report = self.audit_fixture(source)
        self.assertEqual(report["inventory_count"], 7)
        self.assertEqual(report["documented_count"], 7)
        self.assertEqual(report_error_count(report), 0)

    def test_multiple_declarators_cannot_share_one_preceding_comment(self):
        source = ("namespace fixture {\nstruct Fields {\n"
                  "/// 一つの説明を二つのfieldへ流用しない。\n"
                  "int first, second;\n};\n}\n")
        report = self.audit_fixture(source)
        self.assertEqual(report["inventory_count"], 2)
        self.assertEqual(len(report["invalid_preceding_comment"]), 2)
        self.assertGreater(report_error_count(report), 0)

    def test_negative_fixture_rejects_normal_trailing_and_detached_comments(self):
        report = self.audit_fixture(NEGATIVE_FIXTURE)
        self.assertEqual(report["inventory_count"], 5)
        self.assertEqual(len(report["invalid_preceding_comment"]), 5)
        self.assertEqual(
            len(report["empty_documentation"])
            + len(report["missing_from_documented_xml"]),
            2,
        )
        self.assertGreater(report_error_count(report), 0)

    def test_converted_comments_are_extracted_as_preceding_member_documentation(self):
        source = "\n".join([
            "namespace fixture {",
            "struct Fields {",
            "    // 二行の前置説明。",
            "    // 内容を保持する。",
            "    int first;",
            "    LongType second{",
            "        DefaultValue}; // 複数行宣言の説明。",
            "    enum class State {",
            "        READY, // 列挙値の説明。",
            "    };",
            "};",
            "}",
            "",
        ])
        targets = [
            MemberCommentTarget("field", "first", 5),
            MemberCommentTarget("field", "second", 6),
            MemberCommentTarget("enumvalue", "READY", 9),
        ]
        converted, count = convert_member_comments(source, targets)
        report = self.audit_fixture(converted)
        self.assertEqual(count, 3)
        self.assertEqual(report["inventory_count"], 3)
        self.assertEqual(report["documented_count"], 3)
        self.assertEqual(report_error_count(report), 0)

    def test_multiline_function_field_comment_belongs_to_complete_declaration(self):
        source = """namespace fixture {
struct Services {
    /// 型を含む全宣言の契約。
    std::function<void(
        int, const std::wstring &)>
        fixture;
};
}
"""
        report = self.audit_fixture(source)
        self.assertEqual(report["inventory_count"], 1)
        self.assertEqual(report["documented_count"], 1)
        self.assertEqual(report_error_count(report), 0)

    def test_conditional_multiline_field_prefix_is_accepted(self):
        source = ("namespace fixture {\nstruct Services {\n#if 1\n"
                  "/// 条件内の完全な宣言直前です。\n"
                  "std::function<void(\n int)>\n fixture;\n#endif\n};\n}\n")
        report = self.audit_fixture(source)
        self.assertEqual(report["inventory_count"], 1)
        self.assertEqual(report_error_count(report), 0)

    def test_multiline_function_field_missing_and_wrong_position_comments_are_rejected(self):
        variants = [
            "std::function<void(\n int)>\n fixture;",
            "std::function<void(\n int)>\n /// 宣言内の誤位置。\n fixture;",
            "/// 離れた説明。\n\nstd::function<void(\n int)>\n fixture;",
        ]
        for declaration in variants:
            report = self.audit_fixture("namespace fixture {\nstruct Services {\n" + declaration
                                        + "\n};\n}\n")
            self.assertEqual(report["inventory_count"], 1)
            self.assertEqual(len(report["invalid_preceding_comment"]), 1)
            self.assertGreater(report_error_count(report), 0)

    def test_conditional_split_declaration_rejects_comment_between_type_and_name(self):
        source = ("namespace fixture {\nstruct Example {\nint\n#if 1\n"
                  "/// 型と名称の間の誤位置。\nvalue;\n#endif\n};\n}\n")
        report = self.audit_fixture(source)
        self.assertEqual(report["inventory_count"], 1)
        self.assertEqual(len(report["invalid_preceding_comment"]), 1)
        self.assertGreater(report_error_count(report), 0)

    def test_conditional_split_declaration_accepts_comment_before_complete_declaration(self):
        source = ("namespace fixture {\nstruct Example {\n"
                  "/// 完全宣言前。\nint\n#if 1\nvalue;\n#endif\n};\n}\n")
        report = self.audit_fixture(source)
        self.assertEqual(report["inventory_count"], 1)
        self.assertEqual(report["documented_count"], 1)
        self.assertEqual(report_error_count(report), 0)

    def test_formal_strict_configuration_parses_contracts_and_keeps_negative_warnings(self):
        """正式設定の出力処理が完全契約を警告せず、欠落と誤引数を検出する。"""
        configuration = Path(__file__).with_name("source-audit.doxyfile").read_text(
            encoding="utf-8"
        )
        for key in ("GENERATE_HTML", "GENERATE_XML", "WARNINGS", "WARN_IF_UNDOCUMENTED",
                    "WARN_IF_DOC_ERROR", "WARN_NO_PARAMDOC"):
            self.assertRegex(configuration, rf"(?m)^{key}\s*=\s*YES\s*$")
        self.assertRegex(configuration, r"(?m)^EXTRACT_ALL\s*=\s*NO\s*$")

        with tempfile.TemporaryDirectory(prefix="drivercrate-strict-fixture-") as directory:
            root = Path(directory)
            header = root / "fixture.h"
            source = root / "fixture.cpp"
            header.write_text("""/** @file fixture.h */
/**
 * @brief 宣言を正本とする完全契約。
 * @param[in] declaredValue 値で受け取る入力。
 * @return 入力値。
 */
int canonical(int declaredValue);
""", encoding="utf-8", newline="\n")
            source.write_text("""/** @file fixture.cpp */
#include "fixture.h"
/**
 * @brief 引数と戻り値を持つ完全契約。
 * @param[in] value 値で受け取る入力。
 * @return 入力値。
 */
int complete(int value) { return value; }
/**
 * @brief 引数のない完全契約。
 * @return 固定値。
 */
int noParameters() { return 1; }
/**
 * @brief 戻り値を持たない完全契約。
 * @param[in] value 値で受け取る入力。
 */
void voidComplete(int value) { (void)value; }
/**
 * @brief 戻り値説明を欠く負例。
 * @param[in] value 値で受け取る入力。
 */
int missingReturn(int value) { return value; }
/**
 * @brief 引数説明を欠く負例。
 * @return 入力値。
 */
int missingParam(int value) { return value; }
/**
 * @brief 誤った引数名の負例。
 * @param[in] other 実在しない引数。
 * @return 入力値。
 */
int wrongParam(int value) { return value; }
int canonical(int runtimeValue) { return runtimeValue; }
""", encoding="utf-8", newline="\n")

            # 正式設定の入力と出力先だけをfixtureへ結合し、WARN等は変更しない。
            replacements = {
                "INPUT": f'"{header.as_posix()}" "{source.as_posix()}"',
                "OUTPUT_DIRECTORY": f'"{(root / "output").as_posix()}"',
                "WARN_LOGFILE": f'"{(root / "warnings.log").as_posix()}"',
            }
            for key, value in replacements.items():
                configuration, count = re.subn(
                    rf"(?m)^{key}\s*=.*$", f"{key} = {value}", configuration
                )
                self.assertEqual(count, 1)
            result = subprocess.run(
                [str(self.doxygen), "-"], input=configuration.encode("utf-8"), cwd=root,
                capture_output=True, check=False, timeout=30, **hidden_process(),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "output/xml/index.xml").is_file())
            warnings = (root / "warnings.log").read_bytes().decode("utf-8", errors="replace")
            for name in ("complete", "noParameters", "voidComplete", "canonical"):
                self.assertNotRegex(warnings, rf"\b{re.escape(name)}\b")
            self.assertIn("return type of member missingReturn is not documented", warnings)
            self.assertIn("parameters of member missingParam are not documented", warnings)
            self.assertIn("argument 'other' of command @param is not found", warnings)
            self.assertIn("parameter 'value'", warnings)


if __name__ == "__main__":
    unittest.main()
