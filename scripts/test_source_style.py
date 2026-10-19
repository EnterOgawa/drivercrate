"""ネットワーク・製品・実デバイスを使わないsource formatterの決定的test。"""

from __future__ import annotations

import unittest
from pathlib import Path

from source_style import (
    add_standard_spacing, align_trailing_comments, apply_edits, ensure_same_tokens,
    find_clang_format, format_non_cpp, format_source, literal_signature, token_signature, tokenize,
    hoist_processing_comments,
)
from source_comments import (
    MemberCommentTarget,
    convert_comments,
    convert_file_header,
    convert_function_blocks,
    convert_member_comments,
    merge_adjacent_contracts,
    normalize_doxygen_markup,
    rename_parameter_comments,
    synchronize_parameter_contracts,
)
from audit_source_comments import case_nodes, control_nodes
from prepare_control_comment_patterns import describe_control
from source_structure import add_simple_braces, add_vertical_spacing, brace_insertions
from audit_source_contracts import cleanup_contracts, merge_contracts, preceding_contract
from audit_source_declarations import declaration_description, local_declaration_nodes
from audit_doxygen_members import (
    MemberIdentity,
    MemberRecord,
    compare_members,
    enum_value_lines,
    field_declaration_line,
    preceding_triple_slash,
)
from check_source_standard import file_metadata_errors


def metadata_fixture(filename="fixture.h", version="01.00.01", history_rows=None,
                     migrated_history=""):
    """C++ file headerの検査用文字列を返し、実sourceを作成・更新しない。

    history_rowsが空なら既定二行を使い、migrated_historyは移行前履歴として別に挿入する。
    返すlicense・日付・版数の記述は検査入力であり、このPython fileのmetadataではない。
    """
    rows = history_rows or [
        " * Ver.01.00.00  Shunji Ogawa  2026/09/01  新規作成。",
        " * Ver.01.00.01  Shunji Ogawa  2026/09/11  説明を明確化。",
    ]
    migrated = (migrated_history + "\n") if migrated_history else ""
    return "\n".join([
        "//------------------------------------------------------------------------------",
        "/**",
        f" * @file {filename}",
        " * @brief 検査用のfile headerです。",
        f" * @version {version}",
        " * @date 2026/09/01",
        " * @author Shunji Ogawa",
        " * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.",
        " *",
        " * @par ライセンス",
        " * SPDX-License-Identifier: Apache-2.0",
        " * 本ファイルには Apache License, Version 2.0 が適用されます。",
        " * ライセンス全文はプロジェクトルートの LICENSE を参照してください。",
        " * https://www.apache.org/licenses/LICENSE-2.0",
        " *",
        " * @par 会社名",
        " * EnterSystem",
        " *",
        migrated.rstrip("\n"),
        " * @par 更新履歴",
        " * <pre>",
        " * VerNo.       author        update      comment",
        *rows,
        " * </pre>",
        " */",
        "//------------------------------------------------------------------------------",
        "",
        "#pragma once",
        "",
    ]).replace("\n\n * @par 更新履歴", "\n * @par 更新履歴")


class MetadataTests(unittest.TestCase):
    def test_metadata_check_accepts_approved_header_and_independent_version(self):
        source = metadata_fixture()
        self.assertEqual(file_metadata_errors(source, Path("fixture.h"), "0.1.0"), [])

    def test_metadata_check_rejects_renamed_file_tag(self):
        source = metadata_fixture(filename="wrong_name.h")
        self.assertIn(
            '@file must match the actual source filename',
            file_metadata_errors(source, Path('right_name.h')),
        )

    def test_metadata_check_rejects_legacy_and_duplicate_license_text(self):
        source = metadata_fixture().replace(" */", " * MIT License\n */")
        source = source.replace(
            " * SPDX-License-Identifier: Apache-2.0",
            " * SPDX-License-Identifier: Apache-2.0\n"
            " * SPDX-License-Identifier: Apache-2.0",
        )
        errors = file_metadata_errors(source, Path("fixture.h"))
        self.assertTrue(any("exactly one SPDX" in error for error in errors))
        self.assertTrue(any("forbidden legacy text: MIT License" in error for error in errors))

    def test_metadata_check_requires_file_version_and_latest_history_match(self):
        source = metadata_fixture(version="0.1.0")
        errors = file_metadata_errors(source, Path("fixture.h"))
        self.assertIn('@version must use the independent XX.YY.ZZ file version', errors)
        self.assertIn('@version must match the last current history version', errors)

    def test_metadata_check_rejects_reused_or_decreasing_current_versions(self):
        rows = [
            " * Ver.01.00.01  Shunji Ogawa  2026/09/01  最初の変更。",
            " * Ver.01.00.01  Shunji Ogawa  2026/09/11  版数を再利用。",
        ]
        errors = file_metadata_errors(
            metadata_fixture(history_rows=rows), Path("fixture.h")
        )
        self.assertIn('current history versions must be unique', errors)
        self.assertIn('current history versions must increase monotonically', errors)

    def test_metadata_check_rejects_product_version_in_current_history(self):
        rows = [
            " * Ver.0.1.0    Shunji Ogawa  2026/09/01  誤った旧履歴。",
            " * Ver.01.00.01  Shunji Ogawa  2026/09/11  現行履歴。",
        ]
        errors = file_metadata_errors(
            metadata_fixture(history_rows=rows), Path("fixture.h")
        )
        self.assertIn(
            'current history rows must use Ver.XX.YY.ZZ and the approved columns',
            errors,
        )

    def test_metadata_check_preserves_repeated_migrated_product_versions(self):
        migrated = "\n".join([
            " * @par 移行前更新履歴（製品版）",
            " * <pre>",
            " * VerNo.       author        update      comment",
            " * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。",
            " * Ver.0.1.0    Shunji Ogawa  2026/09/02  契約を追加。",
            " * </pre>",
            " *",
        ])
        self.assertEqual(
            file_metadata_errors(
                metadata_fixture(migrated_history=migrated), Path("fixture.h")
            ),
            [],
        )

    def test_metadata_check_rejects_new_version_in_migrated_product_history(self):
        migrated = "\n".join([
            " * @par 移行前更新履歴（製品版）",
            " * <pre>",
            " * VerNo.       author        update      comment",
            " * Ver.01.00.00 Shunji Ogawa  2026/09/01  誤った追記。",
            " * </pre>",
            " *",
        ])
        errors = file_metadata_errors(
            metadata_fixture(migrated_history=migrated), Path("fixture.h")
        )
        self.assertIn(
            'independent file versions must not be added to migrated product history',
            errors,
        )


class DoxygenMemberTests(unittest.TestCase):
    def test_field_declarator_resolves_qualified_type_with_same_member_name(self):
        for declaration, name in (
            ("std::mutex mutex ;", "mutex"),
            ("std::filesystem::path path ;", "path"),
            ("std::mutex mutex{} ;", "mutex"),
            ("std::filesystem::path path{std::filesystem::path{}} ;", "path"),
        ):
            with self.subTest(declaration=declaration):
                source = "struct Example {\n/// fieldの説明。\n" + declaration + "\n};\n"
                self.assertEqual(field_declaration_line(source, 3, name), 3)

    def test_field_declarator_preserves_multiline_nested_template_and_pointer(self):
        declarations = [
            "std::filesystem::path\npath ;",
            "std::vector<std::vector<value>>\nvalue ;",
            "std::function<void(\n const value &)>\nvalue ;",
            "void (*value)(const value &) ;",
            "const value *value[2] ;",
        ]
        for declaration in declarations:
            name = "path" if "path" in declaration else "value"
            source = "struct Example {\n/// 完全宣言の説明。\n" + declaration + "\n};\n"
            # Doxygenが返す宣言名の行を固定し、型内の同名tokenへ関連付けない。
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if "value ;" in text or "path ;" in text
                        or "(*value)" in text or "*value[" in text)
            with self.subTest(declaration=declaration):
                self.assertEqual(field_declaration_line(source, line, name), 3)

    def test_field_declarator_preserves_pointer_to_member_types(self):
        for declaration, name in (
            ("bool Options::*consent ;", "consent"),
            ("void (Options::*callback)(int) ;", "callback"),
        ):
            with self.subTest(declaration=declaration):
                source = "struct Example {\n/// member pointerの役割。\n" + declaration + "\n};\n"
                self.assertEqual(field_declaration_line(source, 3, name), 3)

    def test_field_declarator_ignores_initializer_references(self):
        for declaration in (
            "Item value = choose(value) ;",
            "Item value{value} ;",
            "Item value{make<value>()} ;",
            "std::array<int, 2> value{value[0], value[1]} ;",
        ):
            with self.subTest(declaration=declaration):
                source = "struct Example {\n/// fieldの説明。\n" + declaration + "\n};\n"
                self.assertEqual(field_declaration_line(source, 3, "value"), 3)

    def test_field_declarator_rejects_type_reference_and_initializer_only_matches(self):
        for declaration in (
            "std::mutex actual ;",
            "std::vector<std::vector<mutex>> actual ;",
            "void (*actual)(const mutex &) ;",
            "Item actual = mutex ;",
            "Item actual{mutex} ;",
        ):
            with self.subTest(declaration=declaration):
                self.assertIsNone(field_declaration_line(declaration, 1, "mutex"))

    def test_field_declarator_rejects_multiple_declarators_and_real_ambiguity(self):
        for declaration in (
            "int value, other ;",
            "int other, value ;",
            "int value = 1, other = 2 ;",
            "void (*value)(int), (*other)(int) ;",
            "struct A { int value; }; struct B { int value; };",
            "int value other ;",
        ):
            with self.subTest(declaration=declaration):
                self.assertIsNone(field_declaration_line(declaration, 1, "value"))

    def test_same_named_type_field_still_requires_comment_before_complete_declaration(self):
        identity = MemberIdentity("field", "Example", "path", "fixture.h")
        variants = [
            "struct Example {\nstd::filesystem::path path ; ///< 行末。\n};\n",
            "struct Example {\n/// 離れた説明。\n\nstd::filesystem::path path ;\n};\n",
            "struct Example {\nstd::filesystem::path\n/// 型と宣言名の途中。\npath ;\n};\n",
            "struct Example {\n/// 別fieldの説明。\nint previous ;\nstd::filesystem::path path ;\n};\n",
        ]
        for source in variants:
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if "path ;" in text)
            record = MemberRecord(identity, line, "XMLの説明だけでは合格しない。")
            with self.subTest(source=source):
                report = compare_members({identity: record}, {identity: record}, {"fixture.h": source})
                self.assertEqual(len(report["invalid_preceding_comment"]), 1)

    def test_preceding_triple_slash_accepts_contiguous_multiline_description(self):
        source = "/// 一行目。\n/// 二行目。\nint value ;\n"
        self.assertEqual(preceding_triple_slash(source, 3), "一行目。 二行目。")

    def test_preceding_triple_slash_rejects_other_or_detached_comments(self):
        self.assertEqual(preceding_triple_slash("// 通常。\nint value ;\n", 2), "")
        self.assertEqual(preceding_triple_slash("int value ; ///< 行末。\n", 1), "")
        self.assertEqual(preceding_triple_slash("/// 説明。\n\nint value ;\n", 3), "")

    def test_member_comparison_accepts_comment_before_multiline_declaration_start(self):
        identity = MemberIdentity("field", "Services", "fixture", "fixture.h")
        source = "struct Services {\n/// 全宣言への説明。\nstd::function<void(\n    int)>\n    fixture ;\n};\n"
        record = MemberRecord(identity, 5, "全宣言への説明。")
        report = compare_members({identity: record}, {identity: record}, {"fixture.h": source})
        self.assertEqual(report["invalid_preceding_comment"], [])

    def test_member_comparison_rejects_missing_internal_detached_or_previous_comment(self):
        identity = MemberIdentity("field", "Services", "fixture", "fixture.h")
        variants = [
            "struct Services {\nstd::function<void(\n int)>\n fixture ;\n};\n",
            "struct Services {\nstd::function<void(\n int)>\n /// 型内の誤位置。\n fixture ;\n};\n",
            "struct Services {\n/// 離れた説明。\n\nstd::function<void(\n int)>\n fixture ;\n};\n",
            "struct Services {\n/// 前fieldの説明。\nint previous ;\nstd::function<void(\n int)>\n fixture ;\n};\n",
        ]
        for source in variants:
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if "fixture ;" in text)
            record = MemberRecord(identity, line, "XMLが本文を拾っても境界は必須。")
            report = compare_members({identity: record}, {identity: record}, {"fixture.h": source})
            self.assertEqual(len(report["invalid_preceding_comment"]), 1)

    def test_enum_value_lines_uses_tokens_in_the_selected_enum(self):
        source = "\n".join([
            "enum class First { OTHER };",
            "enum class Target : int {",
            "    // VALUE_IN_COMMENT",
            "    VALUE_A = 1,",
            "    VALUE_B",
            "};",
            "",
        ])
        self.assertEqual(
            enum_value_lines(source, 2, ["VALUE_A", "VALUE_B"]),
            {"VALUE_A": 4, "VALUE_B": 5},
        )

    def test_member_comparison_requires_xml_text_and_preceding_triple_slash(self):
        documented_identity = MemberIdentity("field", "Example", "documented", "fixture.h")
        empty_identity = MemberIdentity("field", "Example", "empty", "fixture.h")
        missing_identity = MemberIdentity("enumvalue", "Example::Kind", "MISSING", "fixture.h")
        sources = {
            "fixture.h": "/// 抽出する説明。\nint documented ;\n"
                         "// Doxygen対象外。\nint empty ;\n"
                         "/// XMLにない説明。\nMISSING,\n"
        }
        inventory = {
            documented_identity: MemberRecord(documented_identity, 2, ""),
            empty_identity: MemberRecord(empty_identity, 4, ""),
            missing_identity: MemberRecord(missing_identity, 6, ""),
        }
        documented = {
            documented_identity: MemberRecord(documented_identity, 2, "抽出する説明。"),
            empty_identity: MemberRecord(empty_identity, 4, ""),
        }
        report = compare_members(inventory, documented, sources)
        self.assertEqual(report["missing_from_documented_xml"][0]["name"], "MISSING")
        self.assertEqual(report["empty_documentation"][0]["name"], "empty")
        self.assertEqual(report["invalid_preceding_comment"][0]["name"], "empty")

    def test_member_comments_move_before_one_line_and_multiline_declarations(self):
        source = "\n".join([
            "struct Example {",
            "\tint value ;\t// 一行fieldの説明。",
            "\tLongType configured{",
            "\t\tDefaultValue} ;\t// 複数行fieldの説明。",
            "\tenum class Kind {",
            "\t\tREADY,\t// 列挙値の説明。",
            "\t} ;",
            "} ;",
            "",
        ])
        targets = [
            MemberCommentTarget("field", "value", 2),
            MemberCommentTarget("field", "configured", 3),
            MemberCommentTarget("enumvalue", "READY", 6),
        ]
        result, count = convert_member_comments(source, targets)
        self.assertEqual(count, 3)
        self.assertIn("\t/// 一行fieldの説明。\n\tint value ;", result)
        self.assertIn("\t/// 複数行fieldの説明。\n\tLongType configured{", result)
        self.assertIn("\t\t/// 列挙値の説明。\n\t\tREADY,", result)
        self.assertNotIn(";\t//", result)
        ensure_same_tokens(source, result)

    def test_member_comment_conversion_preserves_wrapped_preceding_text(self):
        source = "\n".join([
            "struct Example {",
            "\t// 一行目の説明。",
            "\t// 二行目の説明。",
            "\tbool enabled{} ;",
            "} ;",
            "",
        ])
        result, count = convert_member_comments(
            source, [MemberCommentTarget("field", "enabled", 4)]
        )
        self.assertEqual(count, 1)
        self.assertIn("\t/// 一行目の説明。\n\t/// 二行目の説明。", result)
        ensure_same_tokens(source, result)

    def test_member_comment_conversion_rejects_ambiguous_or_invalid_targets(self):
        both = "// 前置説明。\nint value ; // 行末説明。\n"
        result, count = convert_member_comments(
            both, [MemberCommentTarget("field", "value", 2)]
        )
        self.assertEqual(count, 1)
        self.assertIn("// 前置説明。\n/// 行末説明。\nint value ;", result)
        with self.assertRaisesRegex(ValueError, "duplicated member comment target"):
            target = MemberCommentTarget("field", "value", 1)
            convert_member_comments("int value ; // 説明。\n", [target, target])
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            convert_member_comments(
                "int value ;\n", [MemberCommentTarget("field", "value", 1)]
            )
        with self.assertRaisesRegex(ValueError, "unsupported member kind"):
            convert_member_comments(
                "int value ; // 説明。\n",
                [MemberCommentTarget("function", "value", 1)],
            )

    def test_non_target_comment_and_literal_remain_exact(self):
        source = "\n".join([
            "struct Example {",
            "\tconst char *url{\"https://example.invalid/a//b\"} ;",
            "\tint selected ; // 対象の説明。",
            "\tint untouched ; // 対象外の説明。",
            "} ;",
            "",
        ])
        result, count = convert_member_comments(
            source, [MemberCommentTarget("field", "selected", 3)]
        )
        self.assertEqual(count, 1)
        self.assertIn("int untouched ; // 対象外の説明。", result)
        self.assertIn('"https://example.invalid/a//b"', result)
        self.assertEqual(literal_signature(source), literal_signature(result))


class CommentTests(unittest.TestCase):
    def test_assignment_operator_uses_parameter_inner_space(self):
        source = 'A &operator=(const A &) = delete;'
        self.assertIn('operator=( const A &)', add_standard_spacing(source))

    def test_multiple_tags_in_single_line_contract_remain_separate(self):
        entries = merge_contracts('/** @brief 状態を返す。 @return 現在状態。 */', '/** @note 借用する。 */')
        self.assertIn(('@brief ', '状態を返す。'), entries)
        self.assertIn(('@return ', '現在状態。'), entries)

    def test_processing_comments_move_without_changing_declaration_comments(self):
        source = 'void run() {\n int value = 1; // 入力。\n value += 2; // 補正。\n return; // 終了。\n}\n'
        result = hoist_processing_comments(source)
        self.assertIn('value = 1; // 入力。', result)
        self.assertIn('// 補正。\n value += 2;', result)
        self.assertIn('// 終了。\n return;', result)
        self.assertEqual(result, hoist_processing_comments(result))
        ensure_same_tokens(source, result)

    def test_control_closing_comment_moves_to_its_own_header(self):
        source = 'void run() {\n if(ok) {\n call();\n } // 成功した場合だけ。\n}\n'
        result = hoist_processing_comments(source)
        self.assertIn('// 成功した場合だけ。\n if(ok)', result)
        ensure_same_tokens(source, result)

    def test_processing_comment_hoisting_preserves_macro_and_namespace(self):
        source = '#define APPLY(x) \\\n call(x); // macro\nnamespace demo {\n} // namespace demo\n'
        self.assertEqual(source, hoist_processing_comments(source))

    def test_local_audit_skips_function_and_parameter_but_checks_direct_init(self):
        source = '/** 契約。 */\nint run(\n int input)\n{\n int result(input);\n return result;\n}\n'
        nodes = local_declaration_nodes(source)
        self.assertEqual([node['name'] for node in nodes], ['result'])

    def test_single_line_doxygen_contract_is_not_lost_when_merging(self):
        entries = merge_contracts('/** @brief 元の目的。 */', '/**\n * @note 所有権の説明。\n */')
        self.assertIn(('@brief ', '元の目的。'), entries)
        self.assertIn(('@note ', '所有権の説明。'), entries)

    def test_declaration_audit_does_not_reuse_previous_trailing_comment(self):
        source = 'int first; // firstの目的。\nint second;\n'
        self.assertTrue(declaration_description(source, 1, 'first', 'variable')[0])
        self.assertFalse(declaration_description(source, 2, 'second', 'variable')[0])

    def test_declaration_audit_accepts_multiline_initializer_comment(self):
        source = 'const auto values = Array{\n  1, 2\n}; // 対応表。\n'
        self.assertTrue(declaration_description(source, 1, 'values', 'variable')[0])

    def test_contract_cleanup_preserves_file_name_and_joined_parameter(self):
        source = '/**\n * @file localCoverage.h\n */\n/**\n * @param[in] left 保存値。(i) right : 現在値。\n */\nbool same(int left, int right);\n'
        result = cleanup_contracts(source, Path('local_coverage.h'))
        self.assertIn('@file local_coverage.h', result)
        self.assertIn('@param[in] right 現在値。', result)
        self.assertEqual(result, cleanup_contracts(result, Path('local_coverage.h')))
        ensure_same_tokens(source, result)

    def test_void_contract_cleanup_retains_error_handling_note(self):
        source = '/**\n * @brief 結果を更新する。\n * @return なし。拒否はreportへ残す。\n */\nvoid run();\n'
        self.assertIn('@note 拒否はreportへ残す。', cleanup_contracts(source, Path('a.cpp')))

    def test_contract_merge_retains_both_descriptions_without_duplicate_tag(self):
        declaration = '/**\n * @brief 入力を検証する。\n * @param[in] input 借用入力。\n */'
        definition = '/**\n * @brief 不正な状態を拒否する。\n * @param[in] input 有限の入力。\n * @return 正常時true。\n */'
        entries = merge_contracts(declaration, definition)
        self.assertEqual(sum(key == '@param[in] input ' for key, _ in entries), 1)
        self.assertIn(('@param[in] input ', '借用入力。 有限の入力。'), entries)
        self.assertIn(('', '不正な状態を拒否する。'), entries)

    def test_preceding_contract_does_not_cross_another_declaration(self):
        source = '/**\n * @brief 対象。\n */\nvoid first();\nvoid second();\n'
        self.assertIsNotNone(preceding_contract(source, 4))
        self.assertIsNone(preceding_contract(source, 5))

    def test_parameter_direction_merge_retains_input_and_output_roles(self):
        first = '/**\n * @param[in,out] result 初期値を検査する。\n */'
        second = '/**\n * @param[out] result 完了結果を保持する。\n */'
        entries = merge_contracts(first, second)
        self.assertEqual(entries, [('@param[in,out] result ', '初期値を検査する。 完了結果を保持する。')])

    def test_case_audit_ignores_defaulted_member_and_nested_switch(self):
        source = 'A() = default; switch(a) { case A: switch(b) { /* 内側。 */ case B: break; } break; /* その他。 */ default: break; }'
        nodes = case_nodes(source)
        self.assertEqual(len(nodes), 3)
        self.assertIn('switch(b)', nodes[0]['body'])

    def test_simple_braces_preserve_else_binding_and_literals(self):
        source = 'if(a) value = "x"; else if(b) return false; else value = "y";'
        plan = brace_insertions(source)
        self.assertEqual(len(plan), 3)
        converted = add_simple_braces(source, plan)
        self.assertEqual(brace_insertions(converted), [])
        self.assertEqual(literal_signature(source), literal_signature(converted))

    def test_braces_refuse_unreviewed_nested_control(self):
        with self.assertRaisesRegex(ValueError, 'non-simple'):
            brace_insertions('if(a) if(b) call(); else other();')

    def test_braces_refuse_declaration_lifetime_change(self):
        with self.assertRaisesRegex(ValueError, 'declaration'):
            brace_insertions('if(a) Widget object;')

    def test_vertical_spacing_excludes_else_and_nested_close(self):
        source = 'if(a) {\n if(b) {\n call();\n }\n}\nelse {\n other();\n}\n// 次の独立処理。\nnext();\n'
        converted = add_vertical_spacing(source)
        self.assertIn('}\n}\nelse', converted)
        self.assertIn('}\n\n// 次の独立処理。', converted)
        self.assertEqual(converted, add_vertical_spacing(converted))
        ensure_same_tokens(source, converted)

    def test_blank_line_after_case_break(self):
        source = 'switch(x) {\ncase A: break;\ncase B: break;\n}\n'
        self.assertIn('break;\n\ncase B', add_vertical_spacing(source))

    def test_preprocessor_else_does_not_own_next_runtime_if(self):
        source = '#if !defined(_WIN64)\nreturn;\n#else\nif(value) { return; }\n#endif\n'
        node = control_nodes(source)[0]
        self.assertEqual(source[node['start']:node['start'] + 2], 'if')

    def test_splitting_a_preprocessor_directive_is_not_formatting(self):
        with self.assertRaisesRegex(ValueError, 'preprocessor'):
            ensure_same_tokens('#else\nif(value) {}', '#\n// 誤った挿入。\nelse\nif(value) {}')

    def test_preprocessor_continuation_can_be_reindented(self):
        ensure_same_tokens('#define FLAG \\\n  (1 + 2)\n', '#define FLAG \\\n\t(1 + 2)\n')

    def test_test_result_guard_is_not_applied_to_product(self):
        node = {'condition': 'if(items.size() != 1U)', 'body': '{ return; }'}
        self.assertEqual(describe_control('tests/unit/example.cpp', node)[0], 'test_missing_result')
        self.assertIsNone(describe_control('src/example.cpp', node))

    def test_test_detail_guard_requires_assertion(self):
        node = {'condition': 'if(items.size() == 1U)', 'body': '{ DRIVERCRATE_EXPECT(context, items.front().ready); }'}
        self.assertEqual(describe_control('tests/unit/example.cpp', node)[0], 'test_result_details')
        node['body'] = '{ publish(items.front()); }'
        self.assertIsNone(describe_control('tests/unit/example.cpp', node))

    def test_fixture_mutation_requires_matching_guarded_position(self):
        node = {'condition': 'if(position != std::wstring::npos)', 'body': '{ fixture.replace(position, 2, L"x"); DRIVERCRATE_EXPECT(context, check(fixture)); }'}
        self.assertEqual(describe_control('tests/unit/example.cpp', node)[0], 'test_fixture_mutation')
        node['body'] = node['body'].replace('replace(position', 'replace(otherPosition')
        self.assertIsNone(describe_control('tests/unit/example.cpp', node))

    def test_failure_pattern_preserves_same_error(self):
        node = control_nodes('if(error != 0) { return error; }')[0]
        self.assertEqual(describe_control('src/test.cpp', node)[0], 'propagate_error')

    def test_failure_pattern_does_not_guess_different_return(self):
        node = control_nodes('if(error != 0) { return unrelated; }')[0]
        self.assertIsNone(describe_control('src/test.cpp', node))

    def test_success_pattern_requires_next_call_and_same_result_slot(self):
        node = control_nodes('if(error == 0) { error = readNext(); }')[0]
        self.assertEqual(describe_control('src/test.cpp', node)[0], 'preserve_first_error')
        other = control_nodes('if(error == 0) { state = 1; }')[0]
        self.assertIsNone(describe_control('src/test.cpp', other))

    def test_trailing_variable_comment_does_not_explain_following_condition(self):
        nodes = control_nodes('int value = 0; // 作業値。\nif(value) { return; }')
        self.assertFalse(nodes[0]['commented'])

    def test_standalone_condition_comment_is_recognized(self):
        nodes = control_nodes('// 未処理の値を反映しない。\nif(value) { return; }')
        self.assertTrue(nodes[0]['commented'])

    def test_else_if_and_do_while_are_separate_control_entries(self):
        nodes = control_nodes('if(a) {} else if(b) {} do { call(); } while(c);')
        self.assertEqual([node['kind'] for node in nodes], ['if', 'if', 'do'])

    def old_header(self, metadata=None):
        return "\n".join([
            "//******************************************************************************//",
            "// プログラム名 : fixture.cpp //",
            metadata or "// プログラム名称 : 上限と失敗時状態を検査する。 //\n// 作成日 : 2026/09/01 //",
            "// バージョン : 0.1.0 //",
            "// 会社名 : EnterSystem //",
            "// 作成者 : Shunji Ogawa //",
            "// 0.1.0 Shunji Ogawa 2026/09/01 新規作成。 //",
            "// 備考 //",
            "// 借用中は入力を書き換えない。 //",
            "//******************************************************************************//",
            "", "int value = 1;", "",
        ])

    def test_file_header_preserves_dates_history_and_constraints(self):
        source = self.old_header()
        result = convert_file_header(
            source, Path("fixture.cpp"), "01.00.00", "2026/09/11"
        )
        for text in (
            "@file fixture.cpp", "@version 01.00.00", "@date 2026/09/01",
            "@copyright Copyright (c) 2026 EnterSystem CO.,LTD.",
            "@par ライセンス", "SPDX-License-Identifier: Apache-2.0",
            "@par 移行前更新履歴（製品版）", "@par 更新履歴", "Ver.01.00.00",
            "新規作成。", "借用中は入力を書き換えない。", "Shunji Ogawa",
            "EnterSystem",
        ):
            self.assertIn(text, result)
        ensure_same_tokens(source, result)

    def test_joined_old_metadata_is_recovered(self):
        metadata = "// プログラム名称 : 境界検査。 // バージョン : 0.1.0 // 作成日 :\n// 2026/09/05 // 会社名 : EnterSystem //"
        result = convert_file_header(
            self.old_header(metadata), Path("fixture.cpp"), "01.00.00", "2026/09/11"
        )
        self.assertIn("@brief 境界検査。", result)
        self.assertIn("@date 2026/09/05", result)

    def test_doxygen_header_migration_preserves_legacy_history_order(self):
        source = metadata_fixture(version="01.00.01")
        source = source.replace(
            " * @version 01.00.01", " * @version 0.1.0"
        ).replace(
            " * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.\n"
            " *\n"
            " * @par ライセンス\n"
            " * SPDX-License-Identifier: Apache-2.0\n"
            " * 本ファイルには Apache License, Version 2.0 が適用されます。\n"
            " * ライセンス全文はプロジェクトルートの LICENSE を参照してください。\n"
            " * https://www.apache.org/licenses/LICENSE-2.0",
            " * @copyright Copyright (c) 2026 EnterOgawa and DriverCrate contributors. MIT License.",
        ).replace("Ver.01.00.00", "Ver.0.1.0   ").replace(
            "Ver.01.00.01", "Ver.0.1.0   "
        )
        result = convert_file_header(source, Path("fixture.h"))
        first_history = result.index("Ver.0.1.0")
        second_history = result.index("Ver.0.1.0", first_history + 1)
        current_history = result.index("Ver.01.00.00")
        self.assertLess(first_history, second_history)
        self.assertLess(second_history, current_history)
        self.assertIn("@par 移行前更新履歴（製品版）", result)
        self.assertIn("@version 01.00.00", result)
        self.assertEqual(result, convert_file_header(result, Path("fixture.h")))
        ensure_same_tokens(source, result)

    def test_unrecognized_metadata_is_rejected(self):
        with self.assertRaises(ValueError):
            convert_file_header("int value;", Path("fixture.cpp"), "0.1.0", "2026/09/10")

    def test_function_preserves_directions_and_template_parameter(self):
        source = "\n".join([
            "//------------------------------------------------------------------------------//",
            "// 関数名 : 出力を検証する //",
            "// 呼出形式 : bool check(Getter getter, Result& output) //",
            "// パラメータ : (t) Getter : 入力を参照する呼出し型。 //",
            "// : (i) getter : 呼出し中だけ借用する。 //",
            "// : (io) output : 成功時だけ更新する。 //",
            "// 戻り値 : 全項目が有効ならtrue。 //",
            "// 説明 : 部分的な結果は公開しない。 //",
            "//------------------------------------------------------------------------------//",
            "bool check(Getter getter, Result& output) { return true; }",
        ])
        result, count = convert_function_blocks(source)
        self.assertEqual(count, 1)
        for text in ("@tparam Getter", "@param[in] getter", "@param[in,out] output", "@return 全項目", "部分的な結果は公開しない。"):
            self.assertIn(text, result)
        self.assertNotIn("呼出形式", result)
        ensure_same_tokens(source, result)

    def test_adjacent_contracts_keep_distinct_information(self):
        source = "/**\n * @brief 入力を検査する。\n * @param[in] value 借用入力。\n */\n//------------------------------------------------------------------------------\n/**\n * @brief 入力を検査する。\n * @param[in] value null不可。\n * @return 成功時true。\n */\nbool check(int value);"
        result, count = merge_adjacent_contracts(source)
        self.assertEqual(count, 1)
        self.assertEqual(result.count("@brief"), 1)
        self.assertIn("借用入力。 null不可。", result)
        self.assertIn("@return 成功時true。", result)
        ensure_same_tokens(source, result)

    def test_parameter_comment_rename_does_not_touch_literal(self):
        source = '/** @param[in] old_name 入力。 */\nconst auto text = "@param[in] old_name";'
        result = rename_parameter_comments(source, {"old_name": "oldName"})
        self.assertIn('@param[in] oldName 入力。', result)
        self.assertEqual(literal_signature(source), literal_signature(result))

    def test_parameter_name_uses_adjacent_signature_not_same_named_constant(self):
        source = '/**\n * @param[in] TARGET 借用対象。\n * @param[in] compatible_ids 照合入力。\n */\nvoid check(const Target& target, Ids compatibleIds);'
        result, unresolved = synchronize_parameter_contracts(source)
        self.assertEqual(unresolved, [])
        self.assertIn('@param[in] target ', result)
        self.assertIn('@param[in] compatibleIds ', result)
        ensure_same_tokens(source, result)

    def test_parameter_scan_crosses_braced_default_before_later_output(self):
        source = "\n".join([
            "/**",
            " * @param[in] options 入力option。",
            " * @param[out] measurement_evidence 成功時の根拠。",
            " */",
            "void scan(Options options = {}, Evidence *measurementEvidence = nullptr);",
        ])
        result, unresolved = synchronize_parameter_contracts(source)
        self.assertEqual(unresolved, [])
        self.assertIn("@param[out] measurementEvidence", result)
        ensure_same_tokens(source, result)

    def test_japanese_punctuation_is_not_part_of_a_doxygen_std_link(self):
        source = "/** @return 失敗時はstd::nullopt。 */\nint parse();\n"
        result = normalize_doxygen_markup(source)
        self.assertIn("<tt>std::nullopt</tt>。", result)
        self.assertEqual(result, normalize_doxygen_markup(result))
        ensure_same_tokens(source, result)


class TokenTests(unittest.TestCase):
    def test_url_is_not_a_comment(self):
        source = 'const char *url = "https://example.invalid/a//b"; // actual comment\n'
        self.assertEqual(len(literal_signature(source)), 1)
        self.assertEqual(sum(token.kind == "line_comment" for token in tokenize(source)), 1)

    def test_raw_strings_keep_every_byte(self):
        source = 'auto data = LR"payload(\n\t{ "text": "/* // ( x);" }\n)payload";'
        self.assertEqual(literal_signature(source), [("raw", source[source.index('LR"'):-1])])

    def test_prefixes_and_escaped_quotes(self):
        source = r'''auto a = u8"日本語\\\""; auto b = L'\''; auto c = U"text";'''
        self.assertEqual(len(literal_signature(source)), 3)

    def test_digit_separators_are_not_character_literals(self):
        source = "auto count = 1'000'000ULL; auto value = 0xFFFF'FFFFU;"
        self.assertEqual(literal_signature(source), [])
        numbers = [token.text for token in tokenize(source) if token.kind == "number"]
        self.assertEqual(numbers, ["1'000'000ULL", "0xFFFF'FFFFU"])

    def test_exponent_sign_stays_in_number(self):
        numbers = [token.text for token in tokenize("1e-10 0x1.fp+3 .25f") if token.kind == "number"]
        self.assertEqual(numbers, ["1e-10", "0x1.fp+3", ".25f"])

    def test_unterminated_string_is_rejected(self):
        with self.assertRaises(ValueError):
            tokenize('auto text = "unterminated;')

    def test_unterminated_block_comment_is_rejected(self):
        with self.assertRaises(ValueError):
            tokenize("/* unterminated")

    def test_unterminated_raw_literal_is_rejected(self):
        with self.assertRaises(ValueError):
            tokenize('auto text = R"tag(unfinished";')

    def test_line_comment_continuation_is_not_code(self):
        source = "// continued \\\ncall(value);\nreturn 0;\n"
        identifiers = [token.text for token in tokenize(source) if token.kind == "identifier"]
        self.assertEqual(identifiers, ["return"])

    def test_whitespace_and_comments_do_not_change_signature(self):
        ensure_same_tokens("int value=1;", "int /* reason */ value = 1 ;\n")

    def test_changed_literal_is_rejected(self):
        with self.assertRaises(ValueError):
            ensure_same_tokens('auto value="a b";', 'auto value="ab";')

    def test_changed_operator_is_rejected(self):
        with self.assertRaises(ValueError):
            ensure_same_tokens("value <= maximum;", "value < maximum;")

    def test_changed_name_is_rejected_by_formatting(self):
        with self.assertRaises(ValueError):
            ensure_same_tokens("oldName();", "newName();")

    def test_overlapping_edits_are_rejected(self):
        with self.assertRaises(ValueError):
            apply_edits("abcdef", [(0, 3, "a"), (2, 4, "b")])

    def test_conflicting_edits_are_rejected(self):
        with self.assertRaises(ValueError):
            apply_edits("abcdef", [(0, 3, "a"), (0, 3, "b")])

    def test_duplicate_edits_are_applied_once(self):
        self.assertEqual(apply_edits("abcdef", [(0, 3, "x"), (0, 3, "x")]), "xdef")


class SpacingTests(unittest.TestCase):
    def test_call_and_statement_spacing(self):
        self.assertEqual(add_standard_spacing("call(value);"), "call( value) ;")

    def test_empty_call_remains_empty(self):
        self.assertEqual(add_standard_spacing("initialize();"), "initialize() ;")

    def test_for_separators_remain_unchanged(self):
        self.assertEqual(add_standard_spacing("for(int i=0;i<2;++i){call(i);}"), "for( int i=0;i<2;++i){call( i) ;}")

    def test_for_lambda_body_is_a_statement(self):
        actual = add_standard_spacing("for(auto i=[](){return 0;}();i<2;++i){}")
        self.assertIn("return 0 ;", actual)
        self.assertIn("();i<2;++i)", actual)

    def test_literals_and_comments_are_preserved(self):
        source = 'call("no( change);"); // call(unchanged);\n'
        result = add_standard_spacing(source)
        self.assertEqual(literal_signature(source), literal_signature(result))
        self.assertIn("// call(unchanged);", result)
        ensure_same_tokens(source, result)

    def test_multiline_opening_has_no_trailing_space(self):
        self.assertEqual(add_standard_spacing("call(\n value);"), "call(\n value) ;")

    def test_comment_between_arguments_is_not_erased(self):
        self.assertIn("/* reason */", add_standard_spacing("call(/* reason */ value);"))

    def test_grouping_is_not_a_function_call(self):
        self.assertEqual(add_standard_spacing("return (value + 1);"), "return (value + 1) ;")

    def test_grouping_after_greater_than_is_not_a_template_call(self):
        source = "if(value > (maximum - offset)) {}"
        self.assertEqual(
            add_standard_spacing(source), "if( value > (maximum - offset)) {}"
        )

    def test_compact_template_invocation_keeps_parameter_inner_space(self):
        source = "make<std::vector<int>>(value);"
        self.assertEqual(
            add_standard_spacing(source), "make<std::vector<int>>( value) ;"
        )

    def test_comment_columns_match_tab_stops(self):
        source = "\tint a ; // first\n\tlong second ; // second\n"
        result = align_trailing_comments(source)
        columns = [line.expandtabs(4).index("//") for line in result.splitlines()]
        self.assertEqual(columns[0], columns[1])
        self.assertEqual(columns[0] % 4, 0)
        ensure_same_tokens(source, result)

    def test_alignment_does_not_find_comment_in_url(self):
        source = '\tconst auto url = "https://example.invalid" ;\n'
        self.assertEqual(align_trailing_comments(source), source)

    def test_long_trailing_comment_moves_before_declaration(self):
        source = '\tconst int result = 1 ; // ' + '検査済みの確定値。' * 14 + '\n'
        formatted = align_trailing_comments(source)
        self.assertTrue(formatted.startswith('\t// '))
        ensure_same_tokens(source, formatted)

    def test_resource_literal_is_unchanged(self):
        source = '    VALUE "Name", "value ; ( )"\n'
        result = format_non_cpp(source)
        self.assertTrue(result.startswith("\t"))
        ensure_same_tokens(source, result)

    def test_template_markers_remain_unchanged(self):
        source = '#define VERSION @PROJECT_VERSION_MAJOR@, @PROJECT_VERSION_MINOR@\n'
        ensure_same_tokens(source, format_non_cpp(source))


class FormatterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """実clang-formatを解決し、C++書式判定用の論理pathをclassで共有する。

        pathはformat_sourceのassume-filename用で、このmethodはそのfileを作成しない。
        各testは文字列をstdinへ渡してformatterを呼ぶため、純粋な偽process試験ではない。
        """
        cls.root = Path(__file__).resolve().parents[1]
        cls.formatter = find_clang_format()
        cls.path = cls.root / "src/core/format_fixture.cpp"

    def test_full_format_is_idempotent(self):
        source = 'namespace example { int value(int input) { if(input>0){return input;} return 0; } }\n'
        first = format_source(source, self.path, self.formatter, self.root)
        second = format_source(first, self.path, self.formatter, self.root)
        self.assertEqual(first, second)
        ensure_same_tokens(source, first)
        self.assertIn("if( input > 0) {", first)
        self.assertIn("\t", first)

    def test_raw_fixture_is_not_reindented_inside_literal(self):
        source = 'const auto data=R"fixture(\n    { "mode": "x; // unchanged" }\n)fixture";\n'
        result = format_source(source, self.path, self.formatter, self.root)
        self.assertEqual(literal_signature(source), literal_signature(result))

    def test_preprocessor_stringification_tokens_are_preserved(self):
        source = '#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)\n'
        result = format_source(source, self.path, self.formatter, self.root)
        self.assertEqual(token_signature(source), token_signature(result))

    def test_declaration_comment_alignment_is_idempotent(self):
        source = 'struct Fields { int shortName; // first\nlong longerName; // second\n};\n'
        first = format_source(source, self.path, self.formatter, self.root)
        self.assertEqual(first, format_source(first, self.path, self.formatter, self.root))

    def test_preceding_field_comments_and_blank_lines_keep_member_alignment(self):
        source = "\n".join([
            "struct Fields {",
            "/// Short field.",
            "std::string_view input;",
            "",
            "/// Longer type field.",
            "std::uint32_t expectedValue;",
            "};",
            "",
        ])
        result = format_source(source, self.path, self.formatter, self.root)
        declaration_lines = [line for line in result.splitlines() if ";" in line]
        name_columns = [
            line.expandtabs(4).index(name)
            for line, name in zip(declaration_lines, ("input", "expectedValue"))
        ]
        self.assertEqual(name_columns[0], name_columns[1])
        self.assertEqual(result, format_source(result, self.path, self.formatter, self.root))

    def test_lambda_end_comment_alignment_converges(self):
        source = 'void check() { const auto reader = [](int input) { return input; }; // borrowed input\nint value{}; // result\n}\n'
        first = format_source(source, self.path, self.formatter, self.root)
        self.assertEqual(first, format_source(first, self.path, self.formatter, self.root))
        ensure_same_tokens(source, first)


if __name__ == "__main__":
    unittest.main()
