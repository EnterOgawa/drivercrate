"""旧source commentの情報を保持してDoxygenへ移す、一括移行用の変換。"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from source_style import (
    IGNORED_KINDS,
    apply_edits,
    ensure_same_tokens,
    significant_tokens,
    tokenize,
)


SEPARATOR = "//" + "-" * 78
MIGRATION_REASON = "独立ファイル版と改訂コメント規約へ移行。"
APPROVED_COPYRIGHT = "Copyright (c) 2026 EnterSystem CO.,LTD."
LEGACY_COPYRIGHT = "Copyright (c) 2026 EnterOgawa and DriverCrate contributors. MIT License."
LICENSE_LINES = (
    "SPDX-License-Identifier: Apache-2.0",
    "本ファイルには Apache License, Version 2.0 が適用されます。",
    "ライセンス全文はプロジェクトルートの LICENSE を参照してください。",
    "https://www.apache.org/licenses/LICENSE-2.0",
)
FUNCTION_BLOCK = re.compile(
    r"(?m)^(?P<indent>[ \t]*)//-{10,}//[ \t]*\n"
    r"(?P<body>(?:(?P=indent)//[^\n]*\n)+?)"
    r"(?P=indent)//-{10,}//[ \t]*(?=\n|$)"
)
FIELD_NAMES = {"関数名": "brief", "呼出形式": "signature", "パラメータ": "parameters", "戻り値": "returns", "説明": "description"}


@dataclass(frozen=True)
class MemberCommentTarget:
    """Doxygenのmember identityから得た、現在source上の宣言位置。"""

    kind: str
    name: str
    line: int


def unwrap_line(line: str) -> str:
    text = re.sub(r"^[ \t]*//[ \t]?", "", line)
    text = re.sub(r"[ \t]*//[ \t]*$", "", text)
    return text.strip()


def sentence(text: str) -> str:
    text = text.strip()
    return text if not text or text.endswith(("。", ".", ":", "：", "！", "？")) else text + "。"


def combine(lines: list[str]) -> str:
    """旧枠の折返しを戻す。文章とASCII語の境界を落とさない。"""
    output = ""
    for text in (line.strip() for line in lines if line.strip()):
        if output and output[-1].isascii() and text[0].isascii():
            output += " "
        output += text
    return output


def wrap_payload(text: str, width: int) -> list[str]:
    """日本語は文字間で、identifierとURLは分断せずに折り返す。"""
    words = re.findall(r"`[^`]*`|https?://\S+|[A-Za-z0-9_][A-Za-z0-9_:/.,+<>*&=()\[\]-]*|[ \t]+|.", text)
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) > width and current.strip():
            lines.append(current.rstrip())
            current = ""
            if word.isspace():
                continue
        current += word
    if current.strip():
        lines.append(current.rstrip())
    return lines or [""]


def render_doxygen(entries: list[tuple[str, str]], indent: str = "") -> str:
    """tagと説明を出力する。旧line comment中の終端記号はDoxygen entityとして保持する。"""
    output = [indent + "/**"]
    width = max(40, 100 - len(indent.expandtabs(4)) - 3)
    for prefix, content in entries:
        if not prefix and not content:
            output.append(indent + " *")
            continue
        payload = (prefix + content).replace("*/", "*&#47;")
        wrapped = wrap_payload(payload, width)
        output.append(indent + " * " + wrapped[0])
        continuation = " " * min(len(prefix), 18) if prefix.startswith("@") else ""
        for line in wrapped[1:]:
            output.append(indent + " * " + continuation + line)
    output.append(indent + " */")
    return "\n".join(output)


def approved_license_entries() -> list[tuple[str, str]]:
    return [
        ("@copyright ", APPROVED_COPYRIGHT),
        ("", ""),
        ("@par ", "ライセンス"),
        *(("", line) for line in LICENSE_LINES),
        ("", ""),
        ("@par ", "会社名"),
        ("", "EnterSystem"),
        ("", ""),
    ]


def migrate_doxygen_header(prefix: str, path: Path, version: str, date: str) -> str:
    file_tags = re.findall(r"(?m)^\s*\*\s+@file\s+(\S+)\s*$", prefix)
    if file_tags != [path.name]:
        raise ValueError(f"file header name is invalid: {path}")
    versions = re.findall(r"(?m)^\s*\*\s+@version\s+(\S+)\s*$", prefix)
    if len(versions) != 1:
        raise ValueError(f"file version is missing or duplicated: {path}")

    if re.fullmatch(r"\d{2}\.\d{2}\.\d{2}", versions[0]):
        required = (
            "@copyright " + APPROVED_COPYRIGHT,
            "@par ライセンス",
            *LICENSE_LINES,
            "@par 会社名",
            "@par 更新履歴",
        )
        if all(prefix.count(value) == 1 for value in required):
            return prefix
        raise ValueError(f"independent file header does not match the approved license form: {path}")

    if versions[0] != "0.1.0":
        raise ValueError(f"unsupported legacy file version: {path}: {versions[0]}")
    if prefix.count("@copyright " + LEGACY_COPYRIGHT) != 1:
        raise ValueError(f"legacy copyright is missing or ambiguous: {path}")
    if prefix.count("@par 更新履歴") != 1:
        raise ValueError(f"legacy current history is missing or ambiguous: {path}")

    converted = re.sub(
        r"(?m)^(?P<leader>\s*\*\s+)@version\s+0\.1\.0\s*$",
        lambda match: match.group("leader") + "@version " + version,
        prefix,
        count=1,
    )
    license_block = "\n".join((
        " * @copyright " + APPROVED_COPYRIGHT,
        " *",
        " * @par ライセンス",
        *(" * " + line for line in LICENSE_LINES),
    ))
    converted = converted.replace(" * @copyright " + LEGACY_COPYRIGHT, license_block, 1)
    history_start = converted.index(" * @par 更新履歴")
    converted = (converted[:history_start]
                 + converted[history_start:].replace(
                     " * @par 更新履歴", " * @par 移行前更新履歴（製品版）", 1
                 ))
    history_end = converted.index(" * </pre>", history_start) + len(" * </pre>")
    current_history = "\n".join((
        " *",
        " * @par 更新履歴",
        " * <pre>",
        " * VerNo.       author        update      comment",
        f" * Ver.{version:<8} Shunji Ogawa  {date}  {MIGRATION_REASON}",
        " * </pre>",
    ))
    return converted[:history_end] + "\n" + current_history + converted[history_end:]


def convert_file_header(source: str, path: Path, version: str = "01.00.00",
                        date: str = "2026/09/11") -> str:
    if re.fullmatch(r"\d{2}\.\d{2}\.\d{2}", version) is None:
        raise ValueError(f"new file version must use XX.YY.ZZ: {path}")
    tokens = tokenize(source)
    first_code = next((token.start for token in tokens if token.kind not in IGNORED_KINDS), len(source))
    prefix = source[:first_code]
    if "プログラム名" not in prefix and "@file" not in prefix:
        raise ValueError(f"file header metadata is missing: {path}")
    if "@file" in prefix and "プログラム名" not in prefix:
        converted = migrate_doxygen_header(prefix, path, version, date)
        result = converted + source[first_code:]
        ensure_same_tokens(source, result)
        return result
    original_lines = prefix.splitlines()
    old_style = "プログラム名" in prefix
    if old_style:
        lines = [unwrap_line(line) for line in original_lines]
        # 旧formatterが同一行へ連結した項目を分離し、折り返された作成日を復元する。
        metadata = "\n".join(lines)
        metadata = re.sub(r"\s*//\s*(?=(?:バージョン|作成日|会社名|作成者)\s*[:：])", "\n", metadata)
        metadata = re.sub(r"(作成日\s*[:：])\s*\n\s*(\d{4}/\d{2}/\d{2})", r"\1 \2", metadata)
        lines = metadata.splitlines()
        brief = next((re.split(r"[:：]", line, maxsplit=1)[1].strip() for line in lines if re.match(r"プログラム名称\s*[:：]", line)), "")
        created = next((re.split(r"[:：]", line, maxsplit=1)[1].strip() for line in lines if re.match(r"作成日\s*[:：]", line)), "")
    else:
        lines = [re.sub(r"^\s*\* ?", "", line).strip() for line in original_lines]
        brief = next((line[len("@brief "):] for line in lines if line.startswith("@brief ")), "")
        created = next((line[len("@date "):] for line in lines if line.startswith("@date ")), "")
    if not brief or not re.fullmatch(r"\d{4}/\d{2}/\d{2}", created):
        raise ValueError(f"file brief or creation date is invalid: {path}")
    history = []
    notes = []
    references = []
    in_notes = False
    for line in lines:
        entry = re.match(r"(?:Ver\.)?(\d+\.\d+\.\d+)\s+(Shunji Ogawa)\s+(\d{4}/\d{2}/\d{2})\s+(.*)", line)
        bullet = re.match(r"- (\d+\.\d+\.\d+)\s*\|\s*(Shunji Ogawa)\s*\|\s*(\d{4}/\d{2}/\d{2})\s*\|\s*(.*)", line)
        if entry or bullet:
            history.append(tuple((entry or bullet).groups()))
        if old_style and line == "備考":
            in_notes = True
            continue
        if line.startswith("@note "):
            in_notes = True
            notes.append(line[len("@note "):])
            continue
        if line.startswith("@see "):
            references.append(line[len("@see "):])
            in_notes = False
            continue
        if in_notes and line and not re.fullmatch(r"[/*-]+", line):
            if line.startswith("@") or line in {"<pre>", "</pre>"}:
                in_notes = False
            else:
                notes.append(line)
    if not history:
        raise ValueError(f"file history is missing: {path}")
    entries = [
        ("@file ", path.name), ("@brief ", sentence(brief)), ("@version ", version),
        ("@date ", created), ("@author ", "Shunji Ogawa"),
        *approved_license_entries(),
    ]
    first = render_doxygen(entries).splitlines()[:-1]
    first.extend((" * @par 移行前更新履歴（製品版）", " * <pre>",
                  " * VerNo.       author        update      comment"))
    for item_version, author, item_date, reason in history:
        row_prefix = f"Ver.{item_version:<8} {author:<13} {item_date}  "
        reason_lines = wrap_payload(sentence(reason), 96 - len(row_prefix))
        first.append(" * " + row_prefix + reason_lines[0])
        first.extend(" * " + " " * len(row_prefix) + continuation for continuation in reason_lines[1:])
    first.append(" * </pre>")
    first.extend((
        " *",
        " * @par 更新履歴",
        " * <pre>",
        " * VerNo.       author        update      comment",
        f" * Ver.{version:<8} Shunji Ogawa  {date}  {MIGRATION_REASON}",
        " * </pre>",
    ))
    suffix_entries = []
    if notes:
        suffix_entries.extend((("", ""), ("@note ", combine(notes))))
    suffix_entries.extend(("@see ", reference) for reference in references)
    suffix = render_doxygen(suffix_entries).splitlines()[1:]
    header = SEPARATOR + "\n" + "\n".join(first + suffix) + "\n" + SEPARATOR + "\n\n"
    result = header + source[first_code:]
    ensure_same_tokens(source, result)
    return result


def parse_function_fields(body: str) -> dict[str, list[str]]:
    fields = {name: [] for name in FIELD_NAMES.values()}
    current = None
    for raw_line in body.splitlines():
        line = unwrap_line(raw_line)
        field = re.match(r"^(関数名|呼出形式|パラメータ|戻り値|説明)\s*[:：]\s*(.*)", line)
        if field:
            current = FIELD_NAMES[field.group(1)]
            if field.group(2):
                fields[current].append(field.group(2))
        elif current and line:
            fields[current].append(re.sub(r"^[:：]\s*", "", line))
    return fields


def convert_function_blocks(source: str) -> tuple[str, int]:
    converted = 0

    def replace(match):
        nonlocal converted
        if "関数名" not in match.group("body") or "呼出形式" not in match.group("body"):
            return match.group()
        fields = parse_function_fields(match.group("body"))
        brief = sentence(combine(fields["brief"]))
        if not brief:
            raise ValueError("named function header has no purpose")
        entries = [("@brief ", brief)]
        description = sentence(combine(fields["description"]))
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:~]*。?", brief) and description:
            # 名前の手書き複製ではなく、既存説明の目的を概要へ移す。
            brief = description
            entries = [("@brief ", brief)]
        if description and description != brief:
            entries.extend((("", ""), ("", description)))
        parameters = []
        for line in fields["parameters"]:
            parameter = re.match(r"^\((i|o|io|t)\)\s+([A-Za-z_]\w*)\s*[:：]\s*(.*)", line)
            if parameter:
                parameters.append([parameter.group(1), parameter.group(2), [parameter.group(3)]])
            elif line not in {"なし。", "なし", "None", "None。"}:
                if not parameters:
                    raise ValueError(f"unrecognized function parameter description: {line}")
                parameters[-1][2].append(line)
        if parameters:
            entries.append(("", ""))
        for direction, name, lines in parameters:
            if direction == "t":
                entries.append((f"@tparam {name} ", sentence(combine(lines))))
                continue
            tag = {"i": "in", "o": "out", "io": "in,out"}[direction]
            entries.append((f"@param[{tag}] {name} ", sentence(combine(lines))))
        returns = combine(fields["returns"])
        if returns and returns not in {"なし。", "なし", "None", "None。"}:
            entries.append(("@return ", sentence(returns)))
        indentation = match.group("indent")
        converted += 1
        return indentation + SEPARATOR + "\n" + render_doxygen(entries, indentation) + "\n" + indentation + SEPARATOR

    return FUNCTION_BLOCK.sub(replace, source), converted


def convert_member_comments(source: str,
                            targets: list[MemberCommentTarget]) -> tuple[str, int]:
    """監査済みfield／enum値の既存説明を、宣言直前の`///`へ移す。"""
    if not targets:
        return source, 0

    lines = source.splitlines(keepends=True)
    line_starts = []
    offset = 0
    for line in lines:
        line_starts.append(offset)
        offset += len(line)

    tokens = tokenize(source)
    code = significant_tokens(source)
    code_depths = []
    depth = [0, 0, 0]
    opening = {"(": 0, "[": 1, "{": 2}
    closing = {")": 0, "]": 1, "}": 2}
    for token in code:
        code_depths.append(tuple(depth))
        if token.text in opening:
            depth[opening[token.text]] += 1
        elif token.text in closing:
            depth[closing[token.text]] -= 1

    def token_line(token) -> int:
        return bisect_right(line_starts, token.start)

    edits = []
    converted = 0
    seen = set()
    for target in sorted(targets, key=lambda item: (item.line, item.kind, item.name)):
        identity = (target.line, target.kind, target.name)
        if identity in seen:
            raise ValueError(f"duplicated member comment target: {target}")
        seen.add(identity)
        if target.kind not in {"field", "enumvalue"}:
            raise ValueError(f"unsupported member kind: {target.kind}")
        if target.line <= 0 or target.line > len(lines):
            raise ValueError(f"member line lies outside source: {target}")

        matching = [
            (index, token)
            for index, token in enumerate(code)
            if token.kind == "identifier"
            and token.text == target.name
            and token_line(token) == target.line
        ]
        if len(matching) != 1:
            raise ValueError(f"member identifier is missing or ambiguous: {target}")
        code_index, identifier = matching[0]

        target_index = target.line - 1
        previous_matches = []
        previous_index = target_index - 1
        while previous_index >= 0:
            match = re.fullmatch(
                r"(?P<indent>[ \t]*)(?P<marker>//)(?P<body>[ \t]+\S.*?)"
                r"(?P<ending>\r?\n)?",
                lines[previous_index],
            )
            if match is None:
                break
            previous_matches.append((previous_index, match))
            previous_index -= 1
        previous_matches.reverse()

        trailing = [
            token
            for token in tokens
            if token.kind == "line_comment"
            and token.start > identifier.end
            and token_line(token) == target.line
        ]
        if not trailing and target.kind == "field":
            declaration_depth = code_depths[code_index]
            terminator = next(
                (
                    token
                    for index, token in enumerate(code[code_index + 1:], code_index + 1)
                    if token.text == ";" and code_depths[index] == declaration_depth
                ),
                None,
            )
            if terminator is not None:
                trailing = [
                    token
                    for token in tokens
                    if token.kind == "line_comment"
                    and token.start > terminator.end
                    and token_line(token) == token_line(terminator)
                ]

        if previous_matches and not trailing:
            for line_index, match in previous_matches:
                marker_start = line_starts[line_index] + match.start("marker")
                edits.append((marker_start, marker_start + 2, "///"))
            converted += 1
            continue
        if len(trailing) != 1 or "\n" in trailing[0].text or "\r" in trailing[0].text:
            raise ValueError(f"member description is missing or ambiguous: {target}")

        comment = trailing[0]
        if re.fullmatch(r"//[ \t]+\S.*", comment.text) is None:
            raise ValueError(f"member description is not a plain nonempty line comment: {target}")
        comment_line = token_line(comment) - 1
        comment_line_start = line_starts[comment_line]
        gap_start = comment.start
        while gap_start > comment_line_start and source[gap_start - 1] in " \t":
            gap_start -= 1
        if source[gap_start:comment.start].strip():
            raise ValueError(f"member comment gap contains non-whitespace: {target}")

        declaration = lines[target_index]
        indentation = re.match(r"[ \t]*", declaration).group()
        newline = "\r\n" if declaration.endswith("\r\n") else "\n"
        replacement = indentation + "/" + comment.text + newline
        edits.append((line_starts[target_index], line_starts[target_index], replacement))
        edits.append((gap_start, comment.end, ""))
        converted += 1

    result = apply_edits(source, edits)
    ensure_same_tokens(source, result)
    return result, converted


def doxy_entries(text: str) -> list[tuple[str, str]]:
    entries = []
    current_prefix = ""
    current_lines = []
    payload = re.sub(r'^/\*\*\s*', '', text)
    payload = re.sub(r'\s*\*/$', '', payload)
    payload = re.sub(r'(?<=\S)[ \t]+(?=@(?:brief|param|tparam|return|retval|note|pre|post|throws|see)\b)', '\n', payload)
    for raw_line in payload.splitlines():
        line = re.sub(r"^\s*\* ?", "", raw_line).strip()
        tag = re.match(r"^(@param\[[^\]]+\]\s+\w+|@\w+(?:\[[^\]]+\])?)\s*(.*)", line)
        if tag or not line:
            if current_prefix or current_lines:
                entries.append((current_prefix, combine(current_lines)))
            current_prefix = tag.group(1) + " " if tag else ""
            current_lines = [tag.group(2)] if tag and tag.group(2) else []
        elif line:
            current_lines.append(line)
    if current_prefix or current_lines:
        entries.append((current_prefix, combine(current_lines)))
    return entries


def merge_adjacent_contracts(source: str) -> tuple[str, int]:
    """既存Doxygenと旧枠からの変換結果が隣接する場合、同じ項目を一つへ集約する。"""
    comments = [token for token in tokenize(source) if token.kind == "block_comment" and token.text.startswith("/**")]
    edits = []
    merged = 0
    index = 0
    while index + 1 < len(comments):
        first, second = comments[index:index + 2]
        middle = source[first.end:second.start]
        if "@file" in first.text or any(token.kind not in IGNORED_KINDS for token in tokenize(middle)):
            index += 1
            continue
        # 区切り線以外の中間commentは移動せず、個別確認の対象に残す。
        middle_lines = [line.strip() for line in middle.splitlines() if line.strip()]
        if any(not re.fullmatch(r"//-+", line) for line in middle_lines):
            index += 1
            continue
        entries = doxy_entries(first.text)
        for prefix, content in doxy_entries(second.text):
            same = next((position for position, (old_prefix, _) in enumerate(entries) if prefix and old_prefix == prefix), None)
            if same is None:
                if (prefix, content) not in entries:
                    entries.append((prefix, content))
                continue
            previous = entries[same][1]
            if previous == content or content.rstrip("。") in previous:
                continue
            if previous.rstrip("。") in content:
                entries[same] = (prefix, content)
            elif prefix == "@brief ":
                entries.append(("", content))
            else:
                entries[same] = (prefix, previous + " " + content)
        line_start = source.rfind("\n", 0, first.start) + 1
        indentation = source[line_start:first.start]
        if indentation.strip():
            raise ValueError("Doxygen contract does not begin on its own line")
        rendered = render_doxygen(entries, indentation)
        edits.append((first.start, second.end, rendered[len(indentation):]))
        merged += 1
        index += 2
    return apply_edits(source, edits), merged


def normalize_doxygen_markup(source: str) -> str:
    """日本語句読点まで自動link名へ含めるDoxygen解釈を、明示的な等幅表記へ直す。"""
    edits = []
    for token in tokenize(source):
        if token.kind != "block_comment" or not token.text.startswith("/**"):
            continue
        replacement = re.sub(
            r"(?<!<tt>)(std::[A-Za-z_][A-Za-z0-9_:]*)(?=[。、])",
            r"<tt>\1</tt>",
            token.text,
        )
        if replacement != token.text:
            edits.append((token.start, token.end, replacement))
    converted = apply_edits(source, edits)
    ensure_same_tokens(source, converted)
    return converted


def rename_parameter_comments(source: str, renames: dict[str, str]) -> str:
    edits = []
    for token in tokenize(source):
        if token.kind not in {"line_comment", "block_comment"}:
            continue
        replacement = re.sub(
            r"(@param(?:\[[^\]]+\])?\s+)([A-Za-z_]\w*)",
            lambda match: match.group(1) + renames.get(match.group(2), match.group(2)),
            token.text,
        )
        # 識別子を明示した説明もコードへ追随する。英語の一般語や外部schemaは変えない。
        replacement = re.sub(
            r"(?<![A-Za-z0-9_])(?:[A-Za-z_]\w*_[A-Za-z0-9_]+|k[A-Z]\w*)(?![A-Za-z0-9_])",
            lambda match: renames.get(match.group(), match.group()), replacement,
        )
        replacement = re.sub(
            r"`([A-Za-z_]\w*)`",
            lambda match: "`" + (renames.get(match.group(1), match.group(1)) if not match.group(1).islower() else match.group(1)) + "`", replacement,
        )
        if replacement != token.text:
            edits.append((token.start, token.end, replacement))
    return apply_edits(source, edits)


def synchronize_parameter_contracts(source: str) -> tuple[str, list[str]]:
    """直後の宣言とtagを照合し、同名定数とは区別して引数名の書式だけを追随させる。"""
    tokens = tokenize(source)
    edits = []
    unresolved = []
    normalize = lambda name: name.replace("_", "").casefold()
    for index, token in enumerate(tokens):
        if token.kind != "block_comment" or "@param" not in token.text:
            continue
        signature = set()
        parameter_depth = 0
        parameter_list_started = False
        for following in tokens[index + 1:]:
            if following.kind in IGNORED_KINDS:
                continue
            if not parameter_list_started:
                if following.text == "(":
                    parameter_list_started = True
                    parameter_depth = 1
                elif following.text in {"{", ";"}:
                    break
                continue
            if following.text == "(":
                parameter_depth += 1
            elif following.text == ")":
                parameter_depth -= 1
                if parameter_depth == 0:
                    break
            elif following.kind == "identifier":
                signature.add(following.text)
            if parameter_depth < 0:
                break

        def resolve(match):
            prefix, name = match.groups()
            if name in signature:
                return match.group()
            matching = [candidate for candidate in signature if normalize(candidate) == normalize(name)]
            if len(matching) > 1:
                matching = [candidate for candidate in matching if candidate[0].islower()]
            if len(matching) == 1:
                return prefix + matching[0]
            unresolved.append(f"line {source.count(chr(10), 0, token.start) + 1}: {name}")
            return match.group()

        text = re.sub(r"(@param(?:\[[^\]]+\])?\s+)([A-Za-z_]\w*)", resolve, token.text)
        if text != token.text:
            edits.append((token.start, token.end, text))
    return apply_edits(source, edits), unresolved


def convert_comments(source: str, path: Path, renames: dict[str, str],
                     version="01.00.00", date="2026/09/11",
                     member_targets: list[MemberCommentTarget] | None = None) -> tuple[str, dict]:
    converted, members = convert_member_comments(source, member_targets or [])
    converted = convert_file_header(converted, path, version, date)
    converted, functions = convert_function_blocks(converted)
    converted = re.sub(r"(?m)^(\s*)//[-*]{10,}//[ \t]*$", lambda match: match.group(1) + SEPARATOR, converted)
    converted, merged = merge_adjacent_contracts(converted)
    converted = normalize_doxygen_markup(converted)
    converted = rename_parameter_comments(converted, renames)
    converted, unresolved = synchronize_parameter_contracts(converted)
    if unresolved:
        raise ValueError(f"unresolved parameter contracts in {path}: {unresolved}")
    ensure_same_tokens(source, converted)
    return converted, {
        "function_headers": functions,
        "member_comments": members,
        "merged_contracts": merged,
    }
