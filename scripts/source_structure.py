"""書式移行用の限定的な構造処理。自明な単文だけをbraceで囲み、挿入位置を監査する。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from source_style import apply_edits, preprocessor_signature, significant_tokens, source_paths, token_signature


def bracket_pairs(tokens):
    pairs = {}
    stack = []
    for index, token in enumerate(tokens):
        if token.text in {'(', '[', '{'}:
            stack.append((index, token.text))
        elif token.text in {')', ']', '}'}:
            if not stack or stack[-1][1] != {')': '(', ']': '[', '}': '{'}[token.text]:
                raise ValueError('unbalanced delimiters')
            opening, _ = stack.pop()
            pairs[opening] = index
            pairs[index] = opening
    if stack:
        raise ValueError('unclosed delimiters')
    return pairs


def brace_insertions(source: str) -> list[dict]:
    """宣言・入れ子制御・macroを除く、return、更新式、call文に限定してbraceを追加する。"""
    tokens = significant_tokens(source)
    pairs = bracket_pairs(tokens)
    result = []
    for index, token in enumerate(tokens):
        if token.text not in {'if', 'for', 'while', 'else', 'do'}:
            continue
        if index and tokens[index - 1].text == '#':
            continue
        if token.text == 'while' and index and tokens[index - 1].text == '}':
            opening = pairs[index - 1]
            if opening and tokens[opening - 1].text == 'do':
                continue
        if token.text in {'else', 'do'}:
            body = index + 1
            if token.text == 'else' and tokens[body].text == 'if':
                continue
        else:
            opening = index + 1 + int(tokens[index + 1].text == 'constexpr')
            if tokens[opening].text != '(':
                raise ValueError('unsupported control header')
            body = pairs[opening] + 1
        if tokens[body].text == '{':
            continue
        end = body
        while end < len(tokens) and tokens[end].text != ';':
            if tokens[end].text in {'(', '['}:
                end = pairs[end]
            elif tokens[end].text in {'{', '}', '#', 'if', 'for', 'while', 'else', 'do', 'switch'}:
                raise ValueError('non-simple or preprocessor-spanning statement requires review')
            end += 1
        if end >= len(tokens):
            raise ValueError('unterminated control body')
        statement = tokens[body:end]
        words = [entry.text for entry in statement]
        # 同じ暗黙blockの中で単文だけを囲み、宣言のlifetimeやdangling elseを変えない。
        safe = (words and (words[0] in {'return', 'throw', 'break', 'continue', '++', '--'}
                or (len(statement) > 1 and statement[0].kind == 'identifier'
                    and words[1] in {'=', '+=', '-=', '++', '--', '.', '->', '('})))
        if not safe:
            raise ValueError('declaration or unreviewed statement requires manual braces')
        result.append({'before': body, 'after': end, 'control': token.text,
                       'statement': [(entry.kind, entry.text) for entry in tokens[body:end + 1]]})
    return result


def insert_brace_signature(signature, insertions):
    before = {entry['before'] for entry in insertions}
    after = {entry['after'] for entry in insertions}
    if len(before) != len(insertions) or len(after) != len(insertions):
        raise ValueError('overlapping brace insertions')
    result = []
    for index, token in enumerate(signature):
        if index in before:
            result.append(('operator', '{'))
        result.append(tuple(token))
        if index in after:
            result.append(('operator', '}'))
    return result


def add_simple_braces(source: str, insertions: list[dict]) -> str:
    if insertions != brace_insertions(source):
        raise ValueError('brace plan no longer matches source')
    tokens = significant_tokens(source)
    edits = []
    for entry in insertions:
        edits.extend(((tokens[entry['before']].start, tokens[entry['before']].start, '{\n'),
                      (tokens[entry['after']].end, tokens[entry['after']].end, '\n}')))
    converted = apply_edits(source, edits)
    if token_signature(converted) != insert_brace_signature(token_signature(source), insertions):
        raise ValueError('non-brace code change')
    if preprocessor_signature(source) != preprocessor_signature(converted):
        raise ValueError('brace insertion changed directive')
    return converted


def add_vertical_spacing(source: str) -> str:
    """制御block後の独立処理と、breakから次caseの間だけに空行を入れる。"""
    tokens = significant_tokens(source)
    pairs = bracket_pairs(tokens)
    ends = {}
    for index, token in enumerate(tokens):
        if token.text not in {'if', 'for', 'while', 'switch', 'else', 'do', 'try', 'catch'}:
            continue
        if index and tokens[index - 1].text == '#':
            continue
        if token.text in {'else', 'do', 'try'}:
            body = index + 1
        else:
            opening = index + 1 + int(tokens[index + 1].text == 'constexpr')
            if tokens[opening].text != '(':
                continue
            body = pairs[opening] + 1
        if body < len(tokens) and tokens[body].text == '{':
            ends[pairs[body]] = token.text
    for index, token in enumerate(tokens[:-2]):
        if token.text == 'break' and tokens[index + 1].text == ';' and tokens[index + 2].text in {'case', 'default'}:
            ends[index + 1] = 'break'
    edits = []
    for end in sorted(ends):
        if end + 1 >= len(tokens) or tokens[end + 1].text in {'}', 'else', 'catch', ';', ',', ')', ']', '#'}:
            continue
        if ends[end] == 'do' and tokens[end + 1].text == 'while':
            continue
        gap = source[tokens[end].end:tokens[end + 1].start]
        lines = gap.split('\n')
        if len(lines) < 2 or any(not line.strip() for line in lines[1:-1]):
            continue
        newline = source.find('\n', tokens[end].end)
        edits.append((newline, newline, '\n'))
    return apply_edits(source, edits)


def main() -> int:
    """既存planを拒否し、--write時だけplanを先に保存してsourceを逐次更新する。

    元sourceの再読後も複数fileのcommitは原子的ではない。検証/I/O失敗は伝播し、
    先に保存したplanやsourceを自動復元しない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='work/tmp/source-style-analysis/index-complete/brace-plan.json')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    plan = {'files': {}}
    pending = []
    for path in source_paths(root):
        if path.suffix in {'.rc', '.in'}:
            continue
        before = path.read_bytes()
        source = before.decode('utf-8')
        insertions = brace_insertions(source)
        if not insertions:
            continue
        converted = add_simple_braces(source, insertions)
        plan['files'][path.relative_to(root).as_posix()] = {
            'source_sha256': hashlib.sha256(before).hexdigest(), 'insertions': insertions}
        pending.append((path, before, converted))
    print(f"Simple braced statements: {sum(len(entry['insertions']) for entry in plan['files'].values())} in {len(pending)} files")
    destination = Path(args.output)
    if destination.exists():
        raise ValueError('refusing to overwrite the audited brace plan')
    if args.write:
        for path, before, _ in pending:
            if path.read_bytes() != before:
                raise ValueError('source changed while planning braces')
        destination.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        for path, _, converted in pending:
            path.write_bytes(converted.encode('utf-8'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
