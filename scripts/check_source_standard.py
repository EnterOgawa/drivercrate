"""採用規約のfile metadata・制御文説明・単文brace・宣言説明を有限の字句検査で確認する。"""

from __future__ import annotations

import json
import re
from pathlib import Path

from audit_source_comments import case_nodes, control_nodes
from audit_source_declarations import local_declaration_nodes
from source_structure import brace_insertions
from source_style import read_source, source_paths


COPYRIGHT_LINE = '@copyright Copyright (c) 2026 EnterSystem CO.,LTD.'
LICENSE_SECTION_LINES = (
    '@par ライセンス',
    'SPDX-License-Identifier: Apache-2.0',
    '本ファイルには Apache License, Version 2.0 が適用されます。',
    'ライセンス全文はプロジェクトルートの LICENSE を参照してください。',
    'https://www.apache.org/licenses/LICENSE-2.0',
)
FILE_VERSION_PATTERN = re.compile(r'^\d{2}\.\d{2}\.\d{2}$')
HISTORY_ROW_PATTERN = re.compile(
    r'^\s*\*\s+Ver\.(?P<version>\d{2}\.\d{2}\.\d{2})\s+'
    r'(?P<author>\S+(?:\s+\S+)?)\s+(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<reason>\S.*)$'
)


def metadata_line_count(prefix: str, value: str) -> int:
    return len(re.findall(r'(?m)^\s*\*\s+' + re.escape(value) + r'\s*$', prefix))


def version_tuple(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split('.'))


def history_section(prefix: str, name: str) -> str | None:
    pattern = re.compile(
        r'(?ms)^\s*\*\s+@par\s+' + re.escape(name)
        + r'\s*$\n^\s*\*\s+<pre>\s*$\n(?P<body>.*?)^\s*\*\s+</pre>\s*$'
    )
    matches = list(pattern.finditer(prefix))
    return matches[0].group('body') if len(matches) == 1 else None


def file_metadata_errors(source: str, path: Path, _product_version: str | None = None) -> list[str]:
    prefix = source.split('#', 1)[0]
    errors = []

    file_tags = re.findall(r'(?m)^\s*\*\s+@file\s+(\S+)\s*$', prefix)
    if file_tags != [path.name]:
        errors.append('@file must match the actual source filename')

    version_tags = re.findall(r'(?m)^\s*\*\s+@version\s+(\S+)\s*$', prefix)
    file_version = version_tags[0] if len(version_tags) == 1 else ''
    if len(version_tags) != 1 or FILE_VERSION_PATTERN.fullmatch(file_version) is None:
        errors.append('@version must use the independent XX.YY.ZZ file version')

    required_lines = (
        '@brief',
        '@author Shunji Ogawa',
        COPYRIGHT_LINE,
        *LICENSE_SECTION_LINES,
        '@par 会社名',
        'EnterSystem',
        '@par 更新履歴',
    )
    for value in required_lines:
        count = (len(re.findall(r'(?m)^\s*\*\s+@brief\s+\S.*$', prefix))
                 if value == '@brief' else metadata_line_count(prefix, value))
        if count != 1:
            errors.append(f'file header must contain exactly one {value}')

    dates = re.findall(r'(?m)^\s*\*\s+@date\s+(\S+)\s*$', prefix)
    if len(dates) != 1 or re.fullmatch(r'\d{4}/\d{2}/\d{2}', dates[0]) is None:
        errors.append('creation date must use YYYY/MM/DD')

    exact_license_block = '\n'.join((
        ' * ' + COPYRIGHT_LINE,
        ' *',
        ' * ' + LICENSE_SECTION_LINES[0],
        *((' * ' + line) for line in LICENSE_SECTION_LINES[1:]),
        ' *',
        ' * @par 会社名',
        ' * EnterSystem',
    ))
    if prefix.count(exact_license_block) != 1:
        errors.append('copyright, license, and company sections must match the approved order')

    if re.search(r'(?m)^\s*\*\s+Copyright \(c\)', prefix):
        errors.append('tagless Copyright line is not allowed in an owned file header')
    for forbidden in ('All Rights Reserved.', 'MIT License',
                      'EnterOgawa and DriverCrate contributors'):
        if forbidden in prefix:
            errors.append('owned file header contains forbidden legacy text: ' + forbidden)

    current_history = history_section(prefix, '更新履歴')
    if current_history is None:
        errors.append('current history must have one @par section with one pre block')
    else:
        version_lines = [line for line in current_history.splitlines()
                         if re.match(r'^\s*\*\s+Ver\.', line)]
        rows = [match.groupdict() for line in current_history.splitlines()
                if (match := HISTORY_ROW_PATTERN.fullmatch(line)) is not None]
        if len(rows) != len(version_lines):
            errors.append('current history rows must use Ver.XX.YY.ZZ and the approved columns')
        if not rows:
            errors.append('current history must contain at least one Ver.XX.YY.ZZ row')
        else:
            versions = [row['version'] for row in rows]
            if any(row['author'] != 'Shunji Ogawa' for row in rows):
                errors.append('current history author must be Shunji Ogawa')
            if len(set(versions)) != len(versions):
                errors.append('current history versions must be unique')
            if any(version_tuple(left) >= version_tuple(right)
                   for left, right in zip(versions, versions[1:])):
                errors.append('current history versions must increase monotonically')
            if file_version and versions[-1] != file_version:
                errors.append('@version must match the last current history version')

    migrated_history = history_section(prefix, '移行前更新履歴（製品版）')
    if '@par 移行前更新履歴（製品版）' in prefix:
        if migrated_history is None:
            errors.append('migrated product history must have one pre block')
        elif re.search(r'(?m)^\s*\*\s+Ver\.\d{2}\.\d{2}\.\d{2}\b', migrated_history):
            errors.append('independent file versions must not be added to migrated product history')
        if prefix.find('@par 移行前更新履歴（製品版）') > prefix.find('@par 更新履歴'):
            errors.append('migrated product history must precede current history')

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    counts = {'files': 0, 'controls': 0, 'cases': 0}
    errors = []
    for path in source_paths(root):
        relative = path.relative_to(root).as_posix()
        source = read_source(path)
        raw = path.read_bytes()
        if raw.startswith(b'\xef\xbb\xbf') or b'\r' in raw:
            errors.append(relative + ': UTF-8 without BOM and LF are required')
        errors.extend(relative + ': ' + error for error in file_metadata_errors(source, path))
        counts['files'] += 1
        if path.suffix in {'.rc', '.in'}:
            continue
        for key, nodes in (('controls', control_nodes(source)), ('cases', case_nodes(source))):
            counts[key] += len(nodes)
            errors.extend(f"{relative}:{node['line']}: {node['kind']} explanation is missing"
                          for node in nodes if not node['commented'])
        if brace_insertions(source):
            errors.append(relative + ': control statement braces are missing')
        errors.extend(f"{relative}:{node['line']}: declaration explanation is missing ({node['name']})"
                      for node in local_declaration_nodes(source))
    for error in errors:
        print(error)
    print('Source standard: ' + json.dumps({**counts, 'errors': len(errors)}))
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
