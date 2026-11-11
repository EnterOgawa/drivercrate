"""宣言・定義の独立契約と、有限parserの除外/拒否境界を確認する。"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import audit_source_contracts
from audit_source_contracts import pair_contract_errors
from source_comments import SEPARATOR, doxy_entries, render_doxygen
from source_method_contracts import (
    method_contract_nodes, meaningless_reference_summary, rename_parameter_text, signature,
)


def documented(code, *entries, framed=True):
    block = render_doxygen(list(entries))
    return ((SEPARATOR + '\n' + block + '\n' + SEPARATOR if framed else block)
            + '\n' + code + '\n')


def errors(source):
    return [error for node in method_contract_nodes(source) for error in node['errors']]


class MethodContractTests(unittest.TestCase):
    def test_complete_global_and_supplementary_see(self):
        source = documented('int read(int value);',
                            ('@brief ', '有限入力を検査して個数を返します。'),
                            ('@param[in] value ', '今回だけ借用する入力です。'),
                            ('@return ', '確認した個数です。'),
                            ('@see ', 'src/core/source.h'))
        self.assertEqual(errors(source), [])

    def test_class_constructor_destructor_and_inline_need_no_frames(self):
        source = 'class Owner {\npublic:\n'
        source += documented('Owner() = default;', ('@brief ', '空の所有物を作ります。'), framed=False)
        source += documented('~Owner() = default;', ('@brief ', '所有物を解放します。'), framed=False)
        source += documented('void clear() {}', ('@brief ', '所有物を空にします。'), framed=False)
        source += '};\n'
        self.assertEqual(errors(source), [])

    def test_inline_and_closing_line_shorthand_are_rejected(self):
        for comment in ('/** @brief 空にします。 */', '/**\n * @brief 空にします。 */'):
            with self.subTest(comment=comment):
                self.assertTrue(errors(comment + '\nvoid clear();\n'))

    def test_formatted_reference_only_is_rejected(self):
        source = documented('void clear();', ('@see ', 'src/app/main_window.h 宣言側の契約を正本とする。'))
        self.assertTrue(any('independent @brief' in e for e in errors(source)))

    def test_copy_and_inheritance_variants_cannot_supply_the_contract(self):
        for leader in ('@', '\\'):
            for tag in ('copydoc', 'copybrief', 'copydetails', 'inheritdoc'):
                with self.subTest(leader=leader, tag=tag):
                    source = documented('void clear();', (leader + tag + ' ', 'Base::clear'))
                    self.assertTrue(errors(source))

    def test_reference_redirects_and_real_reference_target(self):
        for summary in ('宣言側の契約を正本とする。', '詳細は参照先を見るだけ。',
                        '参照先の契約を参照してください。',
                        '契約はsrc/app/main_window.hを参照してください。', '@see source.h'):
            with self.subTest(summary=summary):
                self.assertTrue(meaningless_reference_summary(summary))
                self.assertTrue(errors(documented('void read();', ('@brief ', summary))))
        summary = '参照先のファイルの署名を検証します。'
        self.assertFalse(meaningless_reference_summary(summary))
        self.assertEqual(errors(documented('void read();', ('@brief ', summary))), [])

    def test_empty_brief_and_parameter_are_rejected(self):
        self.assertTrue(errors(documented('void use(int value);', ('@brief ', ''),
                                         ('@param[in] value ', ''))))

    def test_nonvoid_requires_return_even_if_other_side_is_documented(self):
        source = documented('int read();', ('@brief ', '個数を読みます。'))
        self.assertTrue(any('non-void' in e for e in errors(source)))

    def test_void_return_placeholder_is_rejected(self):
        source = documented('void clear();', ('@brief ', '所有物を空にします。'), ('@return ', 'なし。'))
        self.assertTrue(any('void/' in e for e in errors(source)))

    def test_every_overload_uses_its_real_parameter_names(self):
        source = documented('int use(int count);', ('@brief ', '件数を検査します。'),
                            ('@param[in] count ', '件数です。'), ('@return ', '確認件数です。'))
        source += documented('int use(double ratio);', ('@brief ', '比率を検査します。'),
                             ('@param[in] ratio ', '比率です。'), ('@return ', '判定値です。'))
        self.assertEqual(errors(source), [])
        self.assertTrue(errors(source.replace('@param[in] ratio ', '@param[in] count ')))

    def test_parameter_direction_order_and_spelling_are_checked(self):
        for entries in ([('@param value ', '入力です。')],
                        [('@param[in] second ', '後です。'), ('@param[in] first ', '先です。')]):
            source = documented('void use(int first, int second);',
                                ('@brief ', '二値を検査します。'), *entries)
            self.assertTrue(errors(source))

    def test_declaration_definition_name_difference_is_independent(self):
        declaration = documented('int use(int source);', ('@brief ', '入力を検査します。'),
                                 ('@param[in] source ', '検査入力です。'), ('@return ', '判定です。'))
        definition = documented('int use(int xml) { return xml; }', ('@brief ', '入力を検査します。'),
                                ('@param[in] xml ', '検査入力です。'), ('@return ', '判定です。'))
        self.assertEqual(pair_contract_errors(declaration, len(declaration.splitlines()),
                                             definition, len(definition.splitlines())), [])
        bad_definition = definition.replace('@param[in] xml ', '@param[in] source ')
        self.assertTrue(pair_contract_errors(declaration, len(declaration.splitlines()),
                                             bad_definition, len(bad_definition.splitlines())))

    def test_contract_on_only_one_side_does_not_pass(self):
        declaration = documented('void use();', ('@brief ', '入力を使用します。'))
        self.assertTrue(pair_contract_errors(declaration, len(declaration.splitlines()),
                                             'void use() {}\n', 1))
        definition = documented('void use() {}', ('@see ', 'source.h'))
        self.assertTrue(pair_contract_errors(declaration, len(declaration.splitlines()),
                                             definition, len(definition.splitlines())))

    def test_missing_comment_is_found_in_namespace_and_class(self):
        source = 'namespace a { int one(); class A { public: void two() {} }; }'
        self.assertEqual(sum('no independent' in e for e in errors(source)), 2)

    def test_unnamed_parameter_keeps_ordinal_type_direction_and_role(self):
        source = documented('void ignore(const Frame &) noexcept;', ('@brief ', '入力を使用しません。'),
                            ('@note ', '第1引数（const Frame&、in）は無名で未使用です。'))
        self.assertEqual(errors(source), [])
        self.assertTrue(errors(source.replace('、in', '、方向不明')))
        self.assertTrue(errors(source.replace('const Frame&', 'Other')))

    def test_deleted_members_have_prohibition_without_runtime_values(self):
        member = documented('A &operator=(const A &) = delete;',
                            ('@brief ', '単独所有の複写代入を禁止します。'), framed=False)
        self.assertEqual(errors('class A {\n' + member + '};'), [])
        bad = member.replace(' */', ' * @return 呼出し不能です。\n */')
        self.assertTrue(errors('class A {\n' + bad + '};'))

    def test_defaulted_comparison_is_callable_and_needs_return(self):
        member = documented('bool operator==(const A &other) const = default;',
                            ('@brief ', '各値が一致するか確認します。'),
                            ('@param[in] other ', '比較する値です。'),
                            ('@return ', '全値一致でtrueです。'), framed=False)
        self.assertEqual(errors('class A {\n' + member + '};'), [])

    def test_literal_field_type_and_lambda_contents_are_excluded(self):
        source = ('const char *s = R"tag(/** @see fake.h */\nvoid fake();\n#define FAKE \\\n)tag";\n'
                  'struct State {\n/// 値です。\nint value;\n};\n'
                  '/** @brief 格納用の型です。 */\nusing Callback = void (*)(int);\n'
                  '// lambdaの役割です。\nauto action = [] { return 1; };\n')
        self.assertEqual(errors(source), [])

    def test_multiline_macro_body_is_not_a_source_function(self):
        source = '#define RUN_THING(x) \\\n    int unexpanded(int x); \\\n    void not_a_source_function();\n'
        self.assertEqual(method_contract_nodes(source), [])

    def test_conditional_branches_and_conditional_parameters_are_checked(self):
        source = '#if A\n' + documented('void use();', ('@brief ', '入力を使用します。'))
        source += '#else\nvoid missing();\n#endif\n'
        self.assertTrue(any('no independent' in e for e in errors(source)))
        code = 'void use(int first,\n#if OPTIONAL\n int second,\n#endif\n int last);'
        source = documented(code, ('@brief ', '有効な引数を使用します。'),
                            ('@param[in] first ', '先頭です。'), ('@param[in] second ', '条件付きです。'),
                            ('@param[in] last ', '末尾です。'))
        self.assertEqual(errors(source), [])

    def test_template_function_and_template_type_are_distinguished(self):
        source = documented('template<class T> T copy(T value) { return value; }',
                            ('@brief ', '値を複写します。'), ('@tparam T ', '複写する型です。'),
                            ('@param[in] value ', '複写元です。'), ('@return ', '複写した値です。'))
        source += '/** @brief 値型です。\n * @tparam T 格納する型です。\n */\ntemplate<class T> struct Value { T field; };'
        self.assertEqual(errors(source), [])

    def test_function_pointer_parameter_is_not_an_unnamed_type(self):
        source = documented('void use(void (*callback)(int));', ('@brief ', '通知関数を呼びます。'),
                            ('@param[in] callback ', '同期呼出し中に借用する通知先です。'))
        self.assertEqual(errors(source), [])

    def test_unsupported_signature_and_unbalanced_input_fail_explicitly(self):
        self.assertTrue(errors('int specialized<T>(int value);\n'))
        with self.assertRaises(ValueError):
            method_contract_nodes('void broken( ;')

    def test_variable_initializers_and_function_try_catch_are_excluded(self):
        source = 'constexpr int VALUE = std::bit_cast<int>(1U);\nconst std::wstring HASH(64U, L\'a\');\n'
        source += documented('A::A() try {} catch(...) {}', ('@brief ', '所有物を初期化します。'))
        self.assertEqual(errors(source), [])

    def test_immediate_lambda_call_is_one_initializer_but_next_function_needs_comment(self):
        source = 'constexpr auto POLICY = [] { return 1; }();\n'
        self.assertEqual(errors(source), [])
        self.assertTrue(any('no independent' in e for e in errors(source + 'int missing();\n')))

    def test_parameter_rename_preserves_links_qualified_names_and_urls(self):
        original = 'sourceを検査しsrc/source.h、source.h、std::source::path、https://example.invalid/sourceへ保存する。'
        expected = 'xmlを検査しsrc/source.h、source.h、std::source::path、https://example.invalid/sourceへ保存する。'
        self.assertEqual(rename_parameter_text(original, 'source', 'xml'), expected)

    def test_same_spelling_type_and_parameter_remove_only_the_parameter_token(self):
        parsed = signature('void read(const std::filesystem::path &path);', 0)
        self.assertEqual(parsed['params'][0]['name'], 'path')
        self.assertEqual(parsed['params'][0]['type'], 'const std :: filesystem :: path &')

    def test_punctuation_adjacent_inline_tags_and_backslash_tags_are_parsed(self):
        entries = doxy_entries('/** @brief 入力を検査します。@param[in] value 入力です。@return 判定です。 */')
        self.assertEqual([k for k, _ in entries], ['@brief ', '@param[in] value ', '@return '])
        self.assertEqual(doxy_entries('/** \\copydoc Base::use */'), [('@copydoc ', 'Base::use')])

    def run_audit_fixture(self, definition, *, xml_mode='valid'):
        """実main/--writeをtemp sourceへ向け、source二件の原byteを呼出し後に比較する。"""
        with tempfile.TemporaryDirectory(prefix='drivercrate-contract-cli-') as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            declaration = documented('void use();', ('@brief ', '入力を使用します。'))
            header = root / 'src/contract.h'
            implementation = root / 'src/contract.cpp'
            header.write_text(declaration, encoding='utf-8')
            implementation.write_text(definition, encoding='utf-8')
            before = (header.read_bytes(), implementation.read_bytes())
            xml = root / 'xml'
            xml.mkdir()
            if xml_mode != 'missing':
                (xml / 'index.xml').write_text('<doxygenindex/>', encoding='utf-8')
            if xml_mode == 'valid':
                location = (f'<location file="src/contract.h" line="{len(declaration.splitlines())}" '
                            f'bodyfile="src/contract.cpp" bodystart="{len(definition.splitlines())}"/>')
                (xml / 'contract.xml').write_text(
                    '<doxygen><compounddef><memberdef kind="function"><qualifiedname>use</qualifiedname>'
                    + location + '</memberdef></compounddef></doxygen>', encoding='utf-8')
            stdout = io.StringIO()
            with (mock.patch.object(audit_source_contracts, '__file__', str(root / 'scripts/audit.py')),
                  mock.patch.object(audit_source_contracts, 'source_paths', return_value=[header, implementation]),
                  mock.patch('sys.argv', ['audit', '--xml', str(xml), '--write']),
                  contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO())):
                try:
                    result = audit_source_contracts.main()
                except SystemExit as error:
                    result = error.code
            self.assertEqual(before, (header.read_bytes(), implementation.read_bytes()))
            return result, stdout.getvalue()

    def test_actual_audit_write_mode_preserves_both_complete_contracts(self):
        definition = documented('void use() {}', ('@brief ', '入力を使用します。'))
        result, output = self.run_audit_fixture(definition)
        self.assertEqual(result, 0)
        report = json.loads(output)
        self.assertEqual(report['checkedPairs'], 1)
        self.assertEqual(report['files'], 0)

    def test_actual_audit_write_mode_refuses_omission_without_mutating_sources(self):
        definition = documented('void use() {}', ('@see ', 'src/contract.h'))
        result, output = self.run_audit_fixture(definition)
        self.assertEqual(result, 1)
        self.assertTrue(json.loads(output)['unresolved'])

    def test_actual_audit_refuses_missing_or_empty_xml(self):
        for xml_mode in ('missing', 'empty'):
            with self.subTest(xml_mode=xml_mode):
                result, _ = self.run_audit_fixture('void use() {}\n', xml_mode=xml_mode)
                self.assertEqual(result, 2)


if __name__ == '__main__':
    unittest.main()
