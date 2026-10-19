"""DriverCrateの開発用C/C++字句処理と承認済み書式。外部packageには依存しない。"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


SOURCE_DIRECTORIES = ("src", "tests", "cmake", "docs/examples")
SOURCE_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".c", ".cpp", ".cc", ".cxx", ".rc", ".inl", ".ipp"}
EXCLUDED_DIRECTORIES = {"third_party", "_deps", "generated"}
PROTECTED_KINDS = {"raw", "string", "character"}
IGNORED_KINDS = {"space", "splice", "line_comment", "block_comment"}

# Raw stringのdelimiter、escape、数字の桁区切りを先に認識し、本文をcodeとして扱わない。
TOKEN_PATTERN = re.compile(
    r'(?P<raw>(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\v\f\r\n]{0,16})\(.*?\)(?P=delimiter)")'
    r'|(?P<string>(?:u8|u|U|L)?"(?:\\[\s\S]|[^"\\\r\n])*")'
    r"|(?P<number>(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[\w.'])*)"
    r"|(?P<character>(?:u8|u|U|L)?'(?:\\[\s\S]|[^'\\\r\n])*')"
    r'|(?P<line_comment>//(?:\\\r?\n|[^\r\n])*)'
    r'|(?P<block_comment>/\*.*?\*/)'
    r'|(?P<splice>\\\r?\n)'
    r'|(?P<space>\s+)'
    r'|(?P<identifier>[A-Za-z_]\w*)'
    r'|(?P<operator><=>|>>=|<<=|->\*|\.\.\.|::|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\|'
    r'|\+=|-=|\*=|/=|%=|&=|\|=|\^=|##|<:|:>|<%|%>|%:|.)',
    re.DOTALL,
)


@dataclass(frozen=True)
class Token:
    """元の文字列内の半開区間と字句を保持する。byte offsetとは混同しない。"""

    kind: str
    text: str
    start: int
    end: int


def tokenize(source: str) -> list[Token]:
    """Literalを一単位として読む。不完全な引用符は書換え前に拒否する。"""
    tokens = []
    position = 0
    for match in TOKEN_PATTERN.finditer(source):
        if match.start() != position:
            raise ValueError(f"unrecognized input at character {position}")
        kind = match.lastgroup
        if kind == "operator" and match.group() in {'"', "'"}:
            raise ValueError(f"unterminated literal at character {position}")
        if kind == "operator" and source.startswith("/*", position):
            raise ValueError(f"unterminated block comment at character {position}")
        if kind == "identifier" and match.group() in {"R", "u8R", "uR", "UR", "LR"} and source[match.end():].startswith('"'):
            raise ValueError(f"unterminated raw literal at character {position}")
        tokens.append(Token(kind, match.group(), match.start(), match.end()))
        position = match.end()
    if position != len(source):
        raise ValueError(f"unrecognized input at character {position}")
    return tokens


def significant_tokens(source: str) -> list[Token]:
    """空白・comment・継続改行を除く字句を返す。Literal内部の空白は保持する。"""
    return [token for token in tokenize(source) if token.kind not in IGNORED_KINDS]


def token_signature(source: str) -> list[tuple[str, str]]:
    return [(token.kind, token.text) for token in significant_tokens(source)]


def literal_signature(source: str) -> list[tuple[str, str]]:
    return [(token.kind, token.text) for token in tokenize(source) if token.kind in PROTECTED_KINDS]


def preprocessor_signature(source: str) -> list[list[tuple[str, str]]]:
    """Directiveの論理行を保護し、同じtokenでも改行による意味変更を拒否する。"""
    tokens = significant_tokens(source)
    directives = []
    for index, token in enumerate(tokens):
        if token.text != "#" or source[source.rfind("\n", 0, token.start) + 1:token.start].strip():
            continue
        end = source.find("\n", token.end)
        while end >= 0 and source[:end].endswith("\\"):
            end = source.find("\n", end + 1)
        if end < 0:
            end = len(source)
        directives.append([(entry.kind, entry.text) for entry in tokens[index:] if entry.start < end])
    return directives


def ensure_same_tokens(before: str, after: str) -> None:
    """単なる書式変更が数値・演算子・literal・識別子を変更していないことを要求する。"""
    if token_signature(before) != token_signature(after):
        raise ValueError("formatting changed significant C/C++ tokens")
    if literal_signature(before) != literal_signature(after):
        raise ValueError("formatting changed a literal")
    if preprocessor_signature(before) != preprocessor_signature(after):
        raise ValueError("formatting changed a preprocessor logical line")


def source_paths(root: Path) -> list[Path]:
    """明示された自作source directoryだけを列挙する。生成元.inは含める。"""
    paths = set()
    for directory in SOURCE_DIRECTORIES:
        folder = root / directory
        if not folder.is_dir():
            continue
        for path in folder.rglob("*"):
            relative = path.relative_to(root)
            if not path.is_file() or EXCLUDED_DIRECTORIES.intersection(relative.parts):
                continue
            suffix = path.with_suffix("").suffix if path.suffix == ".in" else path.suffix
            if suffix in SOURCE_EXTENSIONS:
                paths.add(path.resolve())
    return sorted(paths, key=lambda path: path.as_posix().lower())


def read_source(path: Path) -> str:
    """BOM有無を読取り時だけ許容する。置換出力はUTF-8 BOMなしへ統一する。"""
    return path.read_bytes().decode("utf-8-sig")


def find_clang_format(explicit: str | None = None) -> Path:
    """local toolを探索し、explicit指定時も存在するvswhereの同期探索を先に行う。

    vswhereの起動にはtimeout/出力量上限を設けず、非0はCalledProcessErrorが伝播する。
    未発見はFileNotFoundError。softwareのinstallや環境変数の恒久変更は行わない。
    """
    candidates = [explicit, os.environ.get("CLANG_FORMAT"), shutil.which("clang-format")]
    for environment in ("ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(environment):
            candidates.append(str(Path(os.environ[environment]) / "LLVM/bin/clang-format.exe"))
    if os.environ.get("VSINSTALLDIR"):
        candidates.append(str(Path(os.environ["VSINSTALLDIR"]) / "VC/Tools/Llvm/x64/bin/clang-format.exe"))
    installer = Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if installer.is_file():
        result = subprocess.run(
            [str(installer), "-all", "-products", "*", "-property", "installationPath"],
            capture_output=True, text=True, check=True, **hidden_process(),
        )
        for installation in result.stdout.splitlines():
            if installation.strip():
                candidates.append(
                    str(Path(installation.strip()) / "VC/Tools/Llvm/x64/bin/clang-format.exe")
                )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise FileNotFoundError("clang-format was not found; specify --clang-format or CLANG_FORMAT")


def hidden_process() -> dict:
    """Windowsで補助processのconsole windowを新規表示しない。"""
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def apply_edits(source: str, edits: list[tuple[int, int, str]]) -> str:
    """元offsetへ非重複の編集だけを適用する。同一位置の異なる提案は拒否する。"""
    unique = {}
    for start, end, replacement in edits:
        if not 0 <= start <= end <= len(source):
            raise ValueError("edit lies outside the source")
        key = (start, end)
        if key in unique and unique[key] != replacement:
            raise ValueError("conflicting edits")
        unique[key] = replacement
    ordered = sorted((start, end, value) for (start, end), value in unique.items())
    previous_end = 0
    result = []
    for start, end, replacement in ordered:
        if start < previous_end:
            raise ValueError("overlapping edits")
        result.extend((source[previous_end:start], replacement))
        previous_end = end
    result.append(source[previous_end:])
    return "".join(result)


def add_standard_spacing(source: str) -> str:
    """Literal/commentを避け、call括弧の片側空白とfor区切り以外のセミコロン空白を付ける。"""
    tokens = significant_tokens(source)
    parentheses = []
    brace_depth = 0
    edits = []
    non_call_words = {"return", "throw", "case", "delete", "co_return", "co_yield"}
    for index, token in enumerate(tokens):
        previous = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.text == "{":
            brace_depth += 1
        elif token.text == "}":
            brace_depth -= 1
        elif token.text == "(":
            parentheses.append((bool(previous and previous.text == "for"), brace_depth))
            compact_template_call = (
                previous
                and previous.text in {">", ">>"}
                and not source[previous.end:token.start]
            )
            looks_like_call = previous and (
                (previous.kind == "identifier" and previous.text not in non_call_words)
                or compact_template_call
                or previous.text in {")", "]"}
                or (index > 1 and tokens[index - 2].text == 'operator')
            )
            if looks_like_call and following and following.text != ")":
                gap = source[token.end:following.start]
                if not gap.strip() and "\n" not in gap and "\r" not in gap:
                    edits.append((token.end, following.start, " "))
        elif token.text == ")":
            if parentheses:
                parentheses.pop()
        elif token.text == ";" and previous:
            if any(is_for and depth == brace_depth for is_for, depth in parentheses):
                continue
            gap = source[previous.end:token.start]
            if not gap.strip() and "\n" not in gap and "\r" not in gap:
                edits.append((previous.end, token.start, " "))
            elif token.start and not source[token.start - 1].isspace():
                edits.append((token.start, token.start, " "))
    return apply_edits(source, edits)


def align_trailing_comments(source: str) -> str:
    """連続した一行宣言・列挙値のコメントをタブstopへそろえる。Literal内の//は無視する。"""
    lines = source.splitlines(keepends=True)
    line_starts = []
    offset = 0
    for line in lines:
        line_starts.append(offset)
        offset += len(line)
    positions = {}
    line_index = 0
    for token in tokenize(source):
        if token.kind != "line_comment" or "\n" in token.text:
            continue
        while line_index + 1 < len(line_starts) and line_starts[line_index + 1] <= token.start:
            line_index += 1
        prefix = source[line_starts[line_index]:token.start].rstrip(" \t")
        if prefix.strip() and not prefix.strip().startswith("}"):
            positions[line_index] = (prefix, token.text)
    groups = []
    for index in sorted(positions):
        if not groups or groups[-1][-1] != index - 1:
            groups.append([])
        groups[-1].append(index)
    for group in groups:
        maximum = max(len(positions[index][0].expandtabs(4)) for index in group)
        target = (maximum // 4 + 1) * 4
        for index in group:
            prefix, comment = positions[index]
            column = len(prefix.expandtabs(4))
            padding = ""
            while column < target:
                padding += "\t"
                column += 4 - column % 4
            ending = "\r\n" if lines[index].endswith("\r\n") else "\n" if lines[index].endswith("\n") else ""
            if (
                target + len(comment) > 120
                and not prefix.lstrip().startswith("#")
                and not (index and lines[index - 1].rstrip().endswith("\\"))
            ):
                indentation = re.match(r"[ \t]*", prefix).group()
                lines[index] = indentation + comment + ending + prefix + ending
            else:
                lines[index] = prefix + padding + comment + ending
    return "".join(lines)


def hoist_processing_comments(source: str) -> str:
    """単独の処理文・制御終端に付いた説明を直前へ移す。宣言や固定対応表は維持する。"""
    from bisect import bisect_right
    from source_structure import bracket_pairs
    tokens = tokenize(source)
    code = [token for token in tokens if token.kind not in IGNORED_KINDS]
    pairs = bracket_pairs(code)
    ends = [token.end for token in code]
    edits = []
    for token in tokens:
        if token.kind != 'line_comment' or '\n' in token.text:
            continue
        line_start = source.rfind('\n', 0, token.start) + 1
        prefix = source[line_start:token.start]
        statement = prefix.strip()
        if not statement or statement.startswith('#'):
            continue
        previous_line = source[source.rfind('\n', 0, max(0, line_start - 1)) + 1:line_start]
        if previous_line.rstrip().endswith('\\'):
            continue
        indentation = re.match(r'[ \t]*', prefix).group()
        target = line_start
        simple = (statement.endswith(';') and (
            re.match(r'^(?:return|throw|break|continue)\b', statement)
            or re.match(r'^(?:\+\+|--|static_cast\s*<)', statement)
            or re.match(r'^\w+(?:::\w+)*(?:(?:\.|->)\w+)*(?:\[[^]]+\])*\s*(?:\(|(?:[+*/%&|^-]|<<|>>)?=|\+\+|--)', statement)
        ))
        if statement == '}':
            end = bisect_right(ends, token.start) - 1
            opening = pairs.get(end)
            if opening is None or code[end].text != '}' or opening == 0:
                continue
            header = opening - 1
            if code[header].text == ')':
                header = pairs[header] - 1
                if header >= 0 and code[header].text == 'constexpr':
                    header -= 1
            if header < 0 or code[header].text not in {'if', 'else', 'for', 'while', 'do', 'switch', 'try', 'catch'}:
                continue
            target = code[header].start
            target_line = source.rfind('\n', 0, target) + 1
            # else/catchが前の閉じbraceと同じ行の場合は、formatter後の再評価に残す。
            if source[target_line:target].strip():
                continue
            target = target_line
            indentation = source[target_line:code[header].start]
            simple = True
        if not simple:
            continue
        edits.append((target, target, indentation + token.text + '\n'))
        edits.append((line_start + len(prefix.rstrip(' \t')), token.end, ''))
    converted = apply_edits(source, edits)
    ensure_same_tokens(source, converted)
    return converted


def format_non_cpp(source: str) -> str:
    """Resourceと生成元templateはtokenを維持したまま行頭indentをタブ化する。"""
    protected = [token for token in tokenize(source) if token.kind in PROTECTED_KINDS]
    protected_index = 0
    offset = 0
    lines = []
    for line in source.splitlines(keepends=True):
        while protected_index < len(protected) and protected[protected_index].end <= offset:
            protected_index += 1
        inside = protected_index < len(protected) and protected[protected_index].start < offset < protected[protected_index].end
        if inside:
            lines.append(line)
        else:
            content = line.rstrip("\r\n")
            indentation = re.match(r"[ \t]*", content).group()
            columns = len(indentation.expandtabs(4))
            lines.append("\t" * (columns // 4) + " " * (columns % 4) + content[len(indentation):].rstrip() + "\n")
        offset += len(line)
    return "".join(lines)


def format_pass(source: str, path: Path, clang_format: Path, root: Path) -> str:
    """基本formatterと後処理を一回実行し、token不変を確認する。"""
    if path.suffix in {".rc", ".in"}:
        formatted = format_non_cpp(source)
    else:
        result = subprocess.run(
            [str(clang_format), "--style=file", f"--assume-filename={path}"],
            input=source.encode("utf-8"), capture_output=True, cwd=root, check=True, **hidden_process(),
        )
        formatted = result.stdout.decode("utf-8")
        from source_structure import add_vertical_spacing
        formatted = add_vertical_spacing(align_trailing_comments(
            hoist_processing_comments(add_standard_spacing(formatted))))
    ensure_same_tokens(source, formatted)
    return formatted


def format_source(source: str, path: Path, clang_format: Path, root: Path) -> str:
    """有限回で安定した書式だけを返す。Clangと後処理の整列境界を再評価する。"""
    current = source
    seen = {current}
    for _ in range(5):
        formatted = format_pass(current, path, clang_format, root)
        if formatted == current:
            return formatted
        if formatted in seen:
            raise ValueError(f"formatter entered a cycle: {path.relative_to(root)}")
        seen.add(formatted)
        current = formatted
    raise ValueError(f"formatter did not converge: {path.relative_to(root)}")
