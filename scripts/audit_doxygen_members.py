"""自作data member・列挙値の前置///とDoxygen XML抽出を集合で照合する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

from source_structure import bracket_pairs
from source_style import hidden_process, significant_tokens, source_paths, tokenize


DOXYGEN_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
                           ".inl", ".ipp"}
COMPOUND_KINDS_WITH_FIELDS = {"class", "struct", "union"}


@dataclass(frozen=True, order=True)
class MemberIdentity:
    kind: str
    owner: str
    name: str
    path: str


@dataclass
class MemberRecord:
    identity: MemberIdentity
    line: int
    documentation: str


def find_doxygen(explicit: str | None = None) -> Path:
    candidates = (
        explicit,
        os.environ.get("DOXYGEN"),
        shutil.which("doxygen"),
        r"C:\Strawberry\c\bin\doxygen.exe",
        r"C:\Program Files\doxygen\bin\doxygen.exe",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise FileNotFoundError("doxygen was not found; specify --doxygen or DOXYGEN")


def source_digest(paths: list[Path], root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def neutralize_raw_literal_contents(source: str) -> tuple[str, int]:
    """raw本文だけの非改行UTF-8 byteをspaceへ置換し、生成入力と個数を返す。

    Doxygen 1.10.0のparser入力に限る。本文外のbyte・delimiter・prefix・コメント・
    宣言とCR/LF位置は保持する。不完全literalは共有lexerのValueErrorで拒否する。
    原sourceと通常文字列を変更せず、本文の値はmember文書化の判定に使わない。
    """
    parts = []
    cursor = 0
    count = 0
    for token in tokenize(source):
        if token.kind != "raw":
            continue
        opening = token.start + token.text.index("(") + 1
        closing = token.start + token.text.rfind(")")
        parts.append(source[cursor:opening].encode("utf-8"))
        body = source[opening:closing].encode("utf-8")
        parts.append(bytes(value if value in (10, 13) else 32 for value in body))
        cursor = closing
        count += 1
    parts.append(source[cursor:].encode("utf-8"))
    return b"".join(parts).decode("utf-8"), count


def doxygen_configuration(paths: list[Path], output: Path, extract_all: bool,
                          *, strict_parameter_docs: bool = False) -> str:
    """集合監査と、引数・戻り値のstrict診断用設定を生成する。

    Doxygen 1.10.0のXML-only経路は契約のparseより前に引数欠落を警告する。
    strict診断ではHTML生成も有効にし、実際の説明欠落の警告を保持する。
    """
    quoted_inputs = " ".join('"' + path.as_posix() + '"' for path in paths)
    warning_setting = "YES" if strict_parameter_docs else "NO"
    # 原fileを入力の正本に保ち、raw本文を含む集合だけに標準の入力filterを結合する。
    has_raw_literals = any(
        token.kind == "raw" for path in paths
        for token in tokenize(path.read_bytes().decode("utf-8"))
    )
    filter_configuration = []
    if has_raw_literals:
        command = [Path(sys.executable).as_posix(), "-X", "utf8", "-B",
                   Path(__file__).resolve().as_posix(), "--filter-raw-literals"]
        quoted_command = (subprocess.list2cmdline(command) if os.name == "nt"
                          else shlex.join(command))
        filter_configuration.append("INPUT_FILTER = " + json.dumps(quoted_command, ensure_ascii=False))
    return "\n".join((
        "PROJECT_NAME = DriverCrate_member_audit",
        "OUTPUT_DIRECTORY = " + output.as_posix(),
        "INPUT = " + quoted_inputs,
        "INPUT_ENCODING = UTF-8",
        "FILE_PATTERNS = *.h *.hpp *.hh *.hxx *.c *.cpp *.cc *.cxx *.inl *.ipp",
        "RECURSIVE = NO",
        "EXTRACT_ALL = " + ("YES" if extract_all else "NO"),
        "EXTRACT_PRIVATE = YES",
        "EXTRACT_STATIC = YES",
        "EXTRACT_LOCAL_CLASSES = YES",
        "EXTRACT_LOCAL_METHODS = YES",
        "EXTRACT_ANON_NSPACES = YES",
        "HIDE_UNDOC_MEMBERS = NO",
        "GENERATE_HTML = " + warning_setting,
        "GENERATE_LATEX = NO",
        "GENERATE_XML = YES",
        "XML_PROGRAMLISTING = NO",
        "QUIET = YES",
        "WARNINGS = " + warning_setting,
        "WARN_IF_UNDOCUMENTED = " + warning_setting,
        "WARN_IF_DOC_ERROR = " + warning_setting,
        "WARN_NO_PARAMDOC = " + warning_setting,
        "ENABLE_PREPROCESSING = YES",
        "MACRO_EXPANSION = NO",
        "SEARCH_INCLUDES = NO",
        *filter_configuration,
        "",
    ))


def generate_xml(doxygen: Path, paths: list[Path], output: Path, extract_all: bool,
                 root: Path) -> str:
    """借用したtool・入力・rootでDoxygenを同期起動し、stderr文字列を返す。

    output配下の生成物と失敗時の部分出力は呼出し側が所有し、後始末する。
    非0終了とXML index欠損はValueError、起動/I/O例外は伝播する。本関数には
    timeoutや出力量上限がないため、有限な実行制御は呼出し側が担う。
    """
    result = subprocess.run(
        [str(doxygen), "-"],
        cwd=root,
        input=doxygen_configuration(paths, output, extract_all),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        **hidden_process(),
    )
    if result.returncode != 0:
        raise ValueError(
            f"doxygen failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    xml = output / "xml" / "index.xml"
    if not xml.is_file():
        raise ValueError("doxygen did not produce XML index")
    return result.stderr.strip()


def relative_location(value: str, root: Path) -> str | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            return None
    return Path(value.replace("\\", "/")).as_posix()


def description_text(node: ET.Element) -> str:
    parts = []
    for name in ("briefdescription", "detaileddescription"):
        child = node.find(name)
        if child is not None:
            parts.extend(child.itertext())
    return " ".join(" ".join(parts).split())


def enum_value_lines(source: str, enum_line: int, value_names: list[str]) -> dict[str, int]:
    tokens = significant_tokens(source)
    pairs = bracket_pairs(tokens)
    candidates = [index for index, token in enumerate(tokens)
                  if token.text == "enum"
                  and source.count("\n", 0, token.start) + 1 == enum_line]
    for enum_index in candidates:
        opening = next((index for index in range(enum_index + 1, len(tokens))
                        if tokens[index].text == "{"), None)
        if opening is None or opening not in pairs:
            continue
        closing = pairs[opening]
        found = {}
        for index in range(opening + 1, closing):
            token = tokens[index]
            if token.kind == "identifier" and token.text in value_names:
                found[token.text] = source.count("\n", 0, token.start) + 1
        if set(found) == set(value_names):
            return found
    return {}


def collect_members(xml_directory: Path, sources: dict[str, str], root: Path
                    ) -> tuple[dict[MemberIdentity, MemberRecord], list[dict]]:
    records = {}
    unresolved = []
    for xml_path in sorted(xml_directory.glob("*.xml")):
        document = ET.parse(xml_path)
        for compound in document.findall(".//compounddef"):
            compound_kind = compound.get("kind", "")
            owner = compound.findtext("compoundname", default="")
            if compound_kind in COMPOUND_KINDS_WITH_FIELDS:
                for member in compound.findall('./sectiondef/memberdef[@kind="variable"]'):
                    location = member.find("location")
                    relative = relative_location(
                        "" if location is None else location.get("file", ""), root
                    )
                    name = member.findtext("name", default="")
                    line = int("0" if location is None else location.get("line", "0"))
                    if relative not in sources or not name or line <= 0:
                        unresolved.append({
                            "kind": "field", "owner": owner, "name": name,
                            "path": relative or "", "line": line,
                        })
                        continue
                    identity = MemberIdentity("field", owner, name, relative)
                    records[identity] = MemberRecord(identity, line, description_text(member))

            for enum in compound.findall('.//memberdef[@kind="enum"]'):
                location = enum.find("location")
                relative = relative_location(
                    "" if location is None else location.get("file", ""), root
                )
                enum_line = int("0" if location is None else location.get("line", "0"))
                enum_owner = enum.findtext("qualifiedname", default="")
                values = enum.findall("enumvalue")
                names = [value.findtext("name", default="") for value in values]
                lines = (enum_value_lines(sources[relative], enum_line, names)
                         if relative in sources and enum_line > 0 and all(names) else {})
                for value in values:
                    name = value.findtext("name", default="")
                    line = lines.get(name, 0)
                    if relative not in sources or not enum_owner or not name or line <= 0:
                        unresolved.append({
                            "kind": "enumvalue", "owner": enum_owner, "name": name,
                            "path": relative or "", "line": line,
                        })
                        continue
                    identity = MemberIdentity("enumvalue", enum_owner, name, relative)
                    records[identity] = MemberRecord(identity, line, description_text(value))
    return records, unresolved


def field_declarator_index(tokens, pairs, start: int) -> int | None:
    """単一field宣言の型・declarator・初期値を分離し、宣言名のtoken位置を返す。

    型内・引数内・初期値内の参照は宣言名にしない。扱えない構文と複数declaratorは
    Noneで保留し、Doxygenが返した名称との文字列一致だけでは受理しない。
    """
    qualifiers = {"const", "volatile", "static", "constexpr", "constinit", "inline",
                  "mutable", "thread_local", "extern", "register"}
    builtins = {"void", "bool", "char", "wchar_t", "char8_t", "char16_t", "char32_t",
                "short", "int", "long", "signed", "unsigned", "float", "double", "auto"}

    def attributes(index):
        # 属性とalignmentは型・名称の一部にせず、対応する括弧全体を読み飛ばす。
        while index < len(tokens):
            if (tokens[index].text == "[" and index + 1 < len(tokens)
                    and tokens[index + 1].text == "[" and index in pairs):
                index = pairs[index] + 1
            elif (tokens[index].text == "alignas" and index + 1 < len(tokens)
                  and tokens[index + 1].text == "(" and index + 1 in pairs):
                index = pairs[index + 1] + 1
            else:
                break
        return index

    def template_end(index):
        # 型引数の入れ子を追い、括弧内の比較式やcommaを宣言区切りへ流用しない。
        depth = 0
        while index < len(tokens):
            text = tokens[index].text
            if text in ("(", "[", "{") and index in pairs:
                index = pairs[index] + 1
                continue
            if text == "<":
                depth += 1
            elif text in (">", ">>"):
                depth -= len(text)
                if depth <= 0:
                    return index + 1 if depth == 0 else None
            elif text in (";", "}"):
                return None
            index += 1
        return None

    index = attributes(start)
    # storage/cv指定を除いた型の先頭から、一つのtype-specifierを解決する。
    while index < len(tokens) and tokens[index].text in qualifiers:
        index = attributes(index + 1)
    if index >= len(tokens):
        return None
    if tokens[index].text in builtins:
        while index < len(tokens) and tokens[index].text in builtins | qualifiers:
            index += 1
    elif tokens[index].text == "decltype":
        if index + 1 not in pairs or tokens[index + 1].text != "(":
            return None
        index = pairs[index + 1] + 1
    else:
        if tokens[index].text in ("typename", "struct", "class", "union", "enum"):
            index += 1
        if index < len(tokens) and tokens[index].text == "::":
            index += 1
        # qualified typeの各構成要素とtemplate引数をdeclaratorから分離する。
        while index < len(tokens):
            if tokens[index].kind != "identifier":
                return None
            index += 1
            if index < len(tokens) and tokens[index].text == "<":
                index = template_end(index)
                if index is None:
                    return None
            if index < len(tokens) and tokens[index].text == "::":
                index += 1
                if index < len(tokens) and tokens[index].text == "template":
                    index += 1
            else:
                break
    while index < len(tokens) and tokens[index].text in qualifiers:
        index += 1

    def declarator(index):
        index = attributes(index)
        # pointer-to-memberのowner限定子を、field名や通常のqualified typeへ取り違えない。
        owner = index + int(index < len(tokens) and tokens[index].text == "::")
        while owner < len(tokens) and tokens[owner].kind == "identifier":
            owner += 1
            if owner < len(tokens) and tokens[owner].text == "<":
                owner = template_end(owner)
                if owner is None:
                    return None
            if owner >= len(tokens) or tokens[owner].text != "::":
                break
            owner += 1
            if owner < len(tokens) and tokens[owner].text == "*":
                index = owner
                break
        # pointer/referenceの修飾を読み、括弧付きpointer declaratorにも同じ規則を適用する。
        while index < len(tokens) and tokens[index].text in ("*", "&", "&&"):
            index = attributes(index + 1)
            while index < len(tokens) and tokens[index].text in ("const", "volatile"):
                index = attributes(index + 1)
        if index >= len(tokens):
            return None
        if tokens[index].text == "(" and index in pairs:
            closing = pairs[index]
            nested = declarator(index + 1)
            if nested is None or nested[1] != closing:
                return None
            name_index = nested[0]
            index = closing + 1
        elif tokens[index].kind == "identifier":
            name_index = index
            index += 1
        else:
            return None
        # 配列の境界式とfunction pointerの引数型は宣言名の候補にしない。
        while index < len(tokens):
            index = attributes(index)
            if index < len(tokens) and tokens[index].text in ("(", "[") and index in pairs:
                index = pairs[index] + 1
            elif index < len(tokens) and tokens[index].text == "noexcept":
                index += 1
                if index < len(tokens) and tokens[index].text == "(" and index in pairs:
                    index = pairs[index] + 1
            else:
                break
        return name_index, index

    parsed = declarator(index)
    if parsed is None:
        return None
    name_index, index = parsed
    if index >= len(tokens):
        return None
    if tokens[index].text == "{":
        if index not in pairs:
            return None
        index = pairs[index] + 1
    elif tokens[index].text in ("=", ":"):
        index += 1
        # 初期化式・bit幅は参照のみとして読み、同一宣言の外側commaは必ず拒否する。
        while index < len(tokens) and tokens[index].text not in (";", ",", "}"):
            if tokens[index].text in ("(", "[", "{") and index in pairs:
                index = pairs[index] + 1
            elif tokens[index].text == "<" and template_end(index) is not None:
                index = template_end(index)
            else:
                index += 1
    return name_index if index < len(tokens) and tokens[index].text == ";" else None


def field_declaration_line(source: str, line: int, name: str) -> int | None:
    """完全宣言の型と実declaratorを照合し、前置コメントを要求する開始行を返す。"""
    tokens = significant_tokens(source)
    directive_ranges = []
    for token in tokens:
        if token.text != "#" or source[source.rfind("\n", 0, token.start) + 1:token.start].strip():
            continue
        end = source.find("\n", token.end)
        while end >= 0 and source[:end].endswith("\\"):
            end = source.find("\n", end + 1)
        directive_ranges.append((token.start, end + 1 if end >= 0 else len(source)))
    # 条件指令が型と名称を分けても、指令自身を完全宣言の開始境界にしない。
    tokens = [token for token in tokens
              if not any(begin <= token.start < end for begin, end in directive_ranges)]
    pairs = bracket_pairs(tokens)
    candidates = [index for index, token in enumerate(tokens)
                  if token.kind == "identifier" and token.text == name
                  and source.count("\n", 0, token.start) + 1 == line]
    declarations = []
    # 同じ文字列が型や初期値にも現れてよいが、実declaratorは一意でなければならない。
    for candidate in candidates:
        start = candidate
        index = start - 1
        while index >= 0:
            token = tokens[index]
            if token.text in (")", "]") and index in pairs:
                index = pairs[index]
            elif token.text in (";", "{", "}") or token.kind == "preprocessor":
                break
            elif (token.text == ":" and index > 0
                  and tokens[index - 1].text in ("public", "private", "protected")):
                break
            start = index
            index -= 1
        if field_declarator_index(tokens, pairs, start) == candidate:
            declarations.append(start)
    if len(declarations) != 1:
        return None
    return source.count("\n", 0, tokens[declarations[0]].start) + 1


def preceding_triple_slash(source: str, line: int) -> str:
    lines = source.splitlines()
    index = line - 2
    if index < 0 or re.fullmatch(r'[ \t]*///[ \t]+\S.*', lines[index]) is None:
        return ""
    descriptions = []
    while index >= 0:
        match = re.fullmatch(r'[ \t]*///[ \t]+(?P<text>\S.*)', lines[index])
        if match is None:
            break
        descriptions.append(match.group("text"))
        index -= 1
    descriptions.reverse()
    return " ".join(descriptions)


def compare_members(inventory: dict[MemberIdentity, MemberRecord],
                    documented: dict[MemberIdentity, MemberRecord],
                    sources: dict[str, str]) -> dict:
    missing = []
    empty = []
    invalid_prefix = []
    line_mismatch = []
    for identity, expected in sorted(inventory.items()):
        actual = documented.get(identity)
        payload = {**asdict(identity), "line": expected.line}
        if actual is None:
            missing.append(payload)
        elif not actual.documentation:
            empty.append(payload)
        elif actual.line != expected.line:
            line_mismatch.append({**payload, "documented_line": actual.line})
        comment_line = (field_declaration_line(sources[identity.path], expected.line, identity.name)
                        if identity.kind == "field" else expected.line)
        if comment_line is None or not preceding_triple_slash(sources[identity.path], comment_line):
            invalid_prefix.append(payload)
    unexpected = [asdict(identity) for identity in sorted(set(documented) - set(inventory))]
    return {
        "inventory_count": len(inventory),
        "documented_count": len(documented),
        "missing_from_documented_xml": missing,
        "empty_documentation": empty,
        "invalid_preceding_comment": invalid_prefix,
        "line_mismatch": line_mismatch,
        "unexpected_documented_members": unexpected,
    }


# 対象C/C++ suffixだけを二passでXML抽出し、inventoryと文書付き集合の比較reportを返す。
# 原sourceは変更せず、抽出前後のpin差を拒否する。両pass共通の脱落を独立検出する保証ではない。
# 一時XMLはこの入口が所有し、例外時もTemporaryDirectoryでcleanupする。native起動・I/O・
# XML解析等の例外は伝播し、失敗時reportは返さない。自前のtimeout/出力上限はなく、
# generate_xmlと同じく有限な実行制御は外側の呼出し側が担う。
def audit_members(root: Path, paths: list[Path], doxygen: Path) -> dict:
    eligible = [path for path in paths if path.suffix.lower() in DOXYGEN_SOURCE_SUFFIXES]
    before_hashes = source_digest(eligible, root)
    sources = {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
               for path in eligible}
    with tempfile.TemporaryDirectory(prefix="drivercrate-doxygen-members-") as directory:
        temporary = Path(directory)
        inventory_output = temporary / "inventory"
        documented_output = temporary / "documented"
        inventory_stderr = generate_xml(doxygen, eligible, inventory_output, True, root)
        documented_stderr = generate_xml(doxygen, eligible, documented_output, False, root)
        inventory, inventory_unresolved = collect_members(
            inventory_output / "xml", sources, root
        )
        documented, documented_unresolved = collect_members(
            documented_output / "xml", sources, root
        )
    after_hashes = source_digest(eligible, root)
    changed = sorted(path for path in before_hashes if before_hashes[path] != after_hashes[path])
    if changed:
        raise ValueError("source changed during Doxygen audit: " + ", ".join(changed))
    comparison = compare_members(inventory, documented, sources)
    diagnostics = {}
    for name, value in (
        ("inventory", inventory_stderr), ("documented", documented_stderr)
    ):
        diagnostics[name] = {
            "line_count": len(value.splitlines()),
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "first_lines": value.splitlines()[:10],
        }
    return {
        "schema": 1,
        "doxygen": str(doxygen),
        "source_count": len(eligible),
        "source_hashes": before_hashes,
        "inventory_unresolved": inventory_unresolved,
        "documented_unresolved": documented_unresolved,
        "doxygen_diagnostics": diagnostics,
        **comparison,
    }


def report_error_count(report: dict) -> int:
    return sum(len(report[name]) for name in (
        "inventory_unresolved",
        "documented_unresolved",
        "missing_from_documented_xml",
        "empty_documentation",
        "invalid_preceding_comment",
        "line_mismatch",
        "unexpected_documented_members",
    ))


def main() -> int:
    """全対象を監査後、reportの親directoryを作ってJSONを上書きする。

    sourceは変更しない。reportのI/O失敗は伝播し、部分reportのrollbackは行わない。
    --check時の監査errorは非0へ変換し、native起動の契約はgenerate_xmlへ従う。
    """
    # Doxygenが付加する一fileだけを読み、診断文を生成sourceへ混在させず出力する。
    if len(sys.argv) == 3 and sys.argv[1] == "--filter-raw-literals":
        source = Path(sys.argv[2]).read_bytes().decode("utf-8")
        filtered, _ = neutralize_raw_literal_contents(source)
        sys.stdout.buffer.write(filtered.encode("utf-8"))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--doxygen", help="使用するdoxygen executableのpath")
    parser.add_argument(
        "--report", default="work/tmp/source-style-analysis/doxygen-members.json"
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = audit_members(root, source_paths(root), find_doxygen(arguments.doxygen))
    destination = Path(arguments.report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        newline="\n",
    )
    errors = report_error_count(report)
    print(json.dumps({
        "sources": report["source_count"],
        "inventory": report["inventory_count"],
        "documented": report["documented_count"],
        "errors": errors,
    }))
    if errors:
        shown = 0
        for category in (
            "inventory_unresolved", "documented_unresolved",
            "missing_from_documented_xml", "empty_documentation",
            "invalid_preceding_comment", "line_mismatch",
            "unexpected_documented_members",
        ):
            for item in report[category]:
                if shown >= arguments.limit:
                    break
                print(category + ": " + json.dumps(item, ensure_ascii=False))
                shown += 1
    return int(arguments.check and bool(errors))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"Doxygen member audit failed: {error}")
        raise SystemExit(2) from error
