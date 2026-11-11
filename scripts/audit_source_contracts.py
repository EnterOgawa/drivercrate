"""Doxygenの位置を手掛かりに宣言・定義のraw独立契約を確認する。省略は生成しない。"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from source_comments import doxy_entries
from source_style import IGNORED_KINDS, apply_edits, ensure_same_tokens, source_paths, tokenize
from source_method_contracts import contract_errors, method_contract_nodes


def preceding_contract(source: str, line: int):
    offset = sum(len(part) for part in source.splitlines(keepends=True)[:line - 1])
    tokens = tokenize(source)
    candidates = [token for token in tokens if token.start < offset
                  and token.kind == 'block_comment' and token.text.startswith('/**')]
    if not candidates:
        return None
    candidate = candidates[-1]
    if '@file' in candidate.text:
        return None
    # 直後の属性・signature以外のcodeをまたいで、別関数の契約へ結び付けない。
    between = [token for token in tokens if candidate.end <= token.start < offset
               and token.kind not in IGNORED_KINDS]
    if any(token.text in {';', '{', '}'} for token in between):
        return None
    return candidate


def merge_contracts(declaration: str, definition: str) -> list[tuple[str, str]]:
    entries = doxy_entries(declaration)
    # overrideの実装が具体的な契約を持つ場合は、copydocと重複するparamを生成しない。
    entries = [('@see ' if prefix == '@copydoc ' else prefix, content)
               for prefix, content in entries]
    for prefix, content in doxy_entries(definition):
        if prefix in {'@copydoc ', '@see '}:
            entry = ('@see ', content)
            if entry not in entries:
                entries.append(entry)
            continue
        parameter = re.match(r'@param\[([^]]+)\]\s+(\w+) ', prefix)
        position = next((index for index, (key, _) in enumerate(entries) if prefix and (
            key == prefix or (parameter and re.fullmatch(r'@param\[[^]]+\]\s+' + re.escape(parameter.group(2)) + ' ', key))
        )), None)
        if position is None:
            if (prefix, content) not in entries:
                entries.append((prefix, content))
            continue
        previous = entries[position][1]
        if parameter and entries[position][0] != prefix:
            directions = set(parameter.group(1).split(','))
            directions.update(re.search(r'\[([^]]+)\]', entries[position][0]).group(1).split(','))
            prefix = '@param[' + ('in,out' if directions == {'in', 'out'} else ','.join(sorted(directions))) + '] ' + parameter.group(2) + ' '
            entries[position] = (prefix, previous)
        if previous == content or content.rstrip('。') in previous:
            continue
        if previous.rstrip('。') in content:
            entries[position] = (prefix, content)
        elif prefix == '@brief ':
            if ('', content) not in entries:
                entries.append(('', content))
        else:
            entries[position] = (prefix, previous + ' ' + content)
    # 契約の原文と各引数の順序を維持し、タグ区分だけを採用順に並べる。
    order = {'@brief': 0, '@tparam': 2, '@param': 3, '@return': 4, '@retval': 4,
             '@throws': 5, '@pre': 6, '@post': 7, '@note': 8, '@warning': 9, '@see': 10}
    return sorted((entry for entry in entries if entry != ('', '')),
                  key=lambda entry: order.get(re.split(r'[ \[]', entry[0])[0], 1))


def cleanup_contracts(source: str, path: Path) -> str:
    edits = []
    for token in tokenize(source):
        if token.kind != 'block_comment' or not token.text.startswith('/**'):
            continue
        replacement = token.text
        if '@file' in replacement:
            replacement = re.sub(r'(@file\s+)\S+', lambda match: match.group(1) + path.name, replacement)
        replacement = re.sub(
            r'\((i|o|io)\)\s+(\w+)\s*:\s*',
            lambda match: '\n * @param[' + {'i': 'in', 'o': 'out', 'io': 'in,out'}[match.group(1)]
            + '] ' + match.group(2) + ' ', replacement)
        replacement = re.sub(r'(?m)^\s*\* @return なし。\s*\n', '', replacement)
        replacement = replacement.replace('@return なし。', '@note ')
        replacement = re.sub(r'(@copydoc\s+)(IOfficialAcquisitionTransport|IOfficialNetworkCostReader)::',
                             r'\1drivercrate::\2::', replacement)
        # Doxygenが拡張子をfile linkと誤解する曖昧なbacktick表現だけを明示markupにする。
        replacement = re.sub(r'`(\.[A-Za-z0-9_-]+)`', r'「\1」', replacement)
        replacement = re.sub(r'<tt>(\.[A-Za-z0-9_-]+)</tt>', r'「\1」', replacement)
        if replacement != token.text:
            edits.append((token.start, token.end, replacement))
    converted = apply_edits(source, edits)
    ensure_same_tokens(source, converted)
    return converted


def pair_contract_errors(declaration_source, declaration_line, definition_source, definition_line):
    """双方を独立に検査する。本文の集約・移動・参照による置換は行わない。"""
    errors = []
    for role, source, line in (('declaration', declaration_source, declaration_line),
                               ('definition', definition_source, definition_line)):
        token = preceding_contract(source, line)
        if token is None:
            errors.append(role + ': independent Doxygen contract is missing')
        else:
            errors.extend(role + ': ' + error for error in contract_errors(source, token))
    return errors


def main() -> int:
    """通常は双方のraw契約を監査し、cleanup明示時だけ整形差分を計画する。

    --writeでも通常監査は契約を移動・省略しない。cleanupは全件検証と元sourceの
    再読後に逐次保存する。I/O例外と途中変更は伝播し、複数fileのrollbackはしない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xml', default='work/tmp/source-style-analysis/doxygen/xml')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--cleanup', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sources = {path.relative_to(root).as_posix(): path.read_text(encoding='utf-8') for path in source_paths(root)}
    edits = {}
    seen = set()
    checked = []
    unresolved = []
    owned_function_locations = 0
    if args.cleanup:
        for relative, source in sources.items():
            converted = cleanup_contracts(source, Path(relative))
            if source != converted:
                edits[relative] = [(0, len(source), converted)]
    else:
        xml_directory = Path(args.xml)
        if not (xml_directory / 'index.xml').is_file():
            parser.error('Doxygen XML index is missing; an absent analysis is not a successful audit')
        for path in sorted(xml_directory.glob('*.xml')):
            for member in ET.parse(path).findall('.//memberdef[@kind="function"]'):
                location = member.find('location')
                if location is None or not location.get('bodyfile'):
                    continue
                declaration_file = location.get('declfile', location.get('file', '')).replace('\\', '/')
                definition_file = location.get('bodyfile').replace('\\', '/')
                declaration_line = int(location.get('declline', location.get('line', '0')))
                definition_line = int(location.get('bodystart', '0'))
                key = (declaration_file, declaration_line, definition_file, definition_line)
                if key in seen or declaration_file not in sources or definition_file not in sources:
                    continue
                seen.add(key)
                owned_function_locations += 1
                if declaration_file == definition_file and declaration_line == definition_line:
                    continue
                problems = pair_contract_errors(sources[declaration_file], declaration_line,
                                                sources[definition_file], definition_line)
                checked.append((key, member.findtext('qualifiedname')))
                if problems:
                    unresolved.append((key, member.findtext('qualifiedname'), problems))
        if not owned_function_locations:
            parser.error('Doxygen XML contains no owned function locations')
    pending = []
    for relative, changes in edits.items():
        converted = apply_edits(sources[relative], changes)
        ensure_same_tokens(sources[relative], converted)
        problems = [node for node in method_contract_nodes(converted) if node['errors']]
        if problems:
            unresolved.append((relative, problems))
        pending.append((root / relative, converted))
    print(json.dumps({'files': len(pending), 'checkedPairs': len(checked), 'unresolved': unresolved}, ensure_ascii=False))
    if unresolved:
        return 1
    if args.write:
        for path, _ in pending:
            if path.read_text(encoding='utf-8') != sources[path.relative_to(root).as_posix()]:
                raise ValueError('source changed during contract planning')
        for path, converted in pending:
            path.write_bytes(converted.encode('utf-8'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
