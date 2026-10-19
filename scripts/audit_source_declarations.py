"""文書解析で得た自作宣言位置について、通常コメントも含む説明の不足を確認する。"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

from source_structure import bracket_pairs
from source_style import IGNORED_KINDS, apply_edits, ensure_same_tokens, source_paths, tokenize


@lru_cache(maxsize=16)
def declaration_tokens(source: str):
    tokens = tokenize(source)
    code = [token for token in tokens if token.kind not in IGNORED_KINDS]
    pairs = bracket_pairs(code)
    return tokens, code, pairs


def declaration_description(source: str, line: int, name: str, kind: str):
    tokens, code, pairs = declaration_tokens(source)
    offset = sum(len(part) for part in source.splitlines(keepends=True)[:line - 1])
    newline = source.find('\n', offset)
    endline = len(source) if newline < 0 else newline
    index = next((index for index, token in enumerate(code) if offset <= token.start < endline), None)
    if index is None:
        return False, ''
    previous = code[index - 1].end if index else 0
    start = code[index].start
    end = index
    if kind == 'define':
        stop = endline
    else:
        while end < len(code) and code[end].text != ';':
            if code[end].text in {'(', '[', '{'}:
                end = pairs[end]
            end += 1
        if end == len(code):
            raise ValueError('unterminated declaration: ' + name)
        stop = code[end].end
        tail = source.find('\n', stop)
        stop = len(source) if tail < 0 else tail
    comments = [token for token in tokens if token.kind.endswith('comment')]
    explanation = [token for token in comments if
                   (previous <= token.start < start
                    and not source[source.rfind('\n', 0, token.start) + 1:token.start].strip())
                   or start <= token.start < stop]
    return bool(explanation), source[start:stop].strip()


def local_declaration_nodes(source: str):
    """行頭から始まる型付き宣言を確認する。式やparameter継続行の誤検出は原文で確認する。"""
    tokens, code, pairs = declaration_tokens(source)
    starts = {}
    for index, token in enumerate(code):
        line_start = source.rfind('\n', 0, token.start) + 1
        if not source[line_start:token.start].strip():
            starts[line_start] = index
    # 任意のidentifierを型と仮定せず、C++組み込み・標準型・project型の形に限定する。
    pattern = re.compile(r'(?m)^[ \t]*(?:(?:const|constexpr|static|inline|volatile|mutable|thread_local)\s+)*'
                         r'(?:auto|bool|char|wchar_t|int|long|short|unsigned|signed|float|double|size_t|'
                         r'std::\w+|Microsoft::\w+(?:::\w+)*|[A-Z][A-Za-z0-9_]*(?:::\w+)*)'
                         r'(?:\s*<[^;{}\n]*>)?(?:[ \t]+|[ \t]*[&*]+[ \t]*)'
                         r'(?P<name>[a-z_][A-Za-z0-9_]*|[A-Z][A-Z0-9_]*|\[[^\]\n]+\])'
                         r'(?=[ \t]*[={;(\[])')
    result = []
    for match in pattern.finditer(source):
        if match.group('name') == 'operator':
            continue
        line_start = source.rfind('\n', 0, match.start()) + 1
        index = starts.get(line_start)
        if index is None:
            continue
        # signatureのparameter、argument、initializer内は独立したlocal宣言ではない。
        enclosing = [opening for opening, closing in pairs.items()
                     if opening < index < closing and code[opening].text in {'(', '['}]
        if enclosing:
            continue
        name_index = next((position for position in range(index, len(code))
                           if code[position].start == match.start('name')), None)
        if name_index is not None and name_index + 1 < len(code) and code[name_index + 1].text == '(':
            following = pairs[name_index + 1] + 1
            if following < len(code) and code[following].text in {'{', 'const', 'noexcept', 'override', 'final', '->'}:
                continue
        line = source.count('\n', 0, code[index].start) + 1
        documented, declaration = declaration_description(source, line, match.group('name'), 'variable')
        if not documented:
            result.append({'line': line, 'name': match.group('name'), 'token_index': index,
                           'kind': 'local', 'declaration': declaration})
    return result


def main() -> int:
    """宣言監査のreportを上書きし、明示apply時だけ検証済み説明をsourceへ保存する。

    reportは適用より先に保存する。sourceは逐次更新のため、途中のI/O失敗では
    reportと先行変更が残る。例外を伝播し、複数fileのrollbackは行わない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xml', default='work/tmp/source-style-analysis/doxygen/xml')
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--report', default='work/tmp/source-style-analysis/declarations-current.json')
    parser.add_argument('--apply', help='file→宣言名→レビュー済み説明のJSON')
    parser.add_argument('--locals', action='store_true', help='行頭の型付きlocal宣言も確認する')
    parser.add_argument('--check', action='store_true', help='説明の不足があれば非0で終了する')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sources = {path.relative_to(root).as_posix(): path.read_text(encoding='utf-8') for path in source_paths(root)}
    missing = []
    checked = set()
    if args.locals:
        for relative, source in sources.items():
            if Path(relative).suffix in {'.rc', '.in'}:
                continue
            for node in local_declaration_nodes(source):
                missing.append({'path': relative, **node})
                checked.add((relative, node['line'], node['name']))
    for path in sorted(Path(args.xml).glob('*.xml')):
        if args.locals:
            break
        for member in ET.parse(path).findall('.//memberdef'):
            kind = member.get('kind')
            if kind not in {'variable', 'define'}:
                continue
            location = member.find('location')
            if location is None:
                continue
            relative = location.get('file', '').replace('\\', '/')
            line = int(location.get('line', '0'))
            name = member.findtext('name')
            if relative not in sources or (relative, line, name) in checked:
                continue
            checked.add((relative, line, name))
            documented, declaration = declaration_description(sources[relative], line, name, kind)
            if not documented:
                missing.append({'path': relative, 'line': line, 'name': name, 'kind': kind, 'declaration': declaration})
    missing.sort(key=lambda node: (node['path'], node['line']))
    for node in missing[:args.limit]:
        print(f"{node['path']}:{node['line']} [{node.get('token_index', node['name'])}] {node['declaration'][:300]}")
    print(f'Missing typed declarations: {len(missing)}.' if args.locals
          else f'Checked {len(checked)} declarations; missing {len(missing)}.')
    Path(args.report).write_text(json.dumps(missing, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.apply:
        authored = json.loads(Path(args.apply).read_text(encoding='utf-8'))
        pending = []
        count = 0
        for relative, entries in authored.items():
            source = sources[relative]
            edits = []
            for name, comment in entries.items():
                matches = [node for node in missing if node['path'] == relative and
                           (str(node.get('token_index')) == name if args.locals else node['name'] == name)]
                if len(matches) != 1 or not comment.endswith('。') or '\n' in comment:
                    raise ValueError('declaration comment plan is invalid or ambiguous')
                offset = sum(len(part) for part in source.splitlines(keepends=True)[:matches[0]['line'] - 1])
                indentation = re.match(r'[ \t]*', source[offset:]).group()
                edits.append((offset, offset, indentation + '// ' + comment + '\n'))
                count += 1
            converted = apply_edits(source, edits)
            ensure_same_tokens(source, converted)
            pending.append((root / relative, converted))
        for path, converted in pending:
            path.write_bytes(converted.encode('utf-8'))
        print(f'Added {count} reviewed declaration comments.')
    return 1 if args.check and missing else 0


if __name__ == '__main__':
    raise SystemExit(main())
