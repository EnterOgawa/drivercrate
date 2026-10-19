"""Doxygenの宣言位置を利用し、既存の契約を宣言側へ集約する移行補助。"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from source_comments import doxy_entries, render_doxygen
from source_style import IGNORED_KINDS, apply_edits, ensure_same_tokens, source_paths, tokenize


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


def main() -> int:
    """契約整理を計画し、--write時だけ元sourceの再読確認後に逐次上書きする。

    入力/整合拒否とI/O例外は伝播する。全件を検証しても複数fileのcommitは
    原子的ではなく、書込み途中の失敗では先行変更を残して自動復元しない。
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
    consolidated = []
    unresolved = []
    if args.cleanup:
        for relative, source in sources.items():
            converted = cleanup_contracts(source, Path(relative))
            if source != converted:
                edits[relative] = [(0, len(source), converted)]
    else:
        for path in sorted(Path(args.xml).glob('*.xml')):
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
                if declaration_file == definition_file and declaration_line == definition_line:
                    continue
                declaration = preceding_contract(sources[declaration_file], declaration_line)
                definition = preceding_contract(sources[definition_file], definition_line)
                if declaration is None or definition is None:
                    unresolved.append((key, member.findtext('qualifiedname')))
                    continue
                # 既に宣言参照だけの定義は再処理しない。
                if not any(tag in definition.text for tag in ('@brief', '@param', '@return', '@note')):
                    continue
                entries = merge_contracts(declaration.text, definition.text)
                indentation = re.match(r'[ \t]*', sources[declaration_file].splitlines()[declaration_line - 1]).group()
                text = render_doxygen(entries, indentation)[len(indentation):]
                edits.setdefault(declaration_file, []).append((declaration.start, declaration.end, text))
                indentation = re.match(r'[ \t]*', sources[definition_file].splitlines()[definition_line - 1]).group()
                reference = render_doxygen([('@see ', declaration_file + ' 宣言側の契約を正本とする。')], indentation)[len(indentation):]
                edits.setdefault(definition_file, []).append((definition.start, definition.end, reference))
                consolidated.append((key, member.findtext('qualifiedname')))
    pending = []
    for relative, changes in edits.items():
        converted = apply_edits(sources[relative], changes)
        ensure_same_tokens(sources[relative], converted)
        pending.append((root / relative, converted))
    print(json.dumps({'files': len(pending), 'consolidated': len(consolidated), 'unresolved': unresolved}, ensure_ascii=False))
    if args.write:
        for path, _ in pending:
            if path.read_text(encoding='utf-8') != sources[path.relative_to(root).as_posix()]:
                raise ValueError('source changed during contract planning')
        for path, converted in pending:
            path.write_bytes(converted.encode('utf-8'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
