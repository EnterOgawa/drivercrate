"""明示した公開候補の静的入力閉包を検査する。公開承認・fresh buildの代用にはしない。

作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0。repository rootのLICENSEを参照する。
manifestに列挙した通常fileだけを読む。export・network・build・製品module importは行わない。
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import posixpath
import re
import stat
import sys
from pathlib import Path, PurePosixPath

SCHEMA = "dc-public-source-candidate-v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 2048
FORBIDDEN_ROOTS = {"work", "build", "out", ".git", "Testing", "$out"}
FORBIDDEN_SUFFIXES = {".exe", ".dll", ".pdb", ".obj", ".lib", ".pyd", ".sys", ".cat", ".zip", ".7z", ".gz", ".msi", ".cab"}
TEXT_SUFFIXES = {".cpp", ".h", ".c", ".rc", ".in", ".cmake", ".py", ".ps1", ".psm1", ".cmd", ".yml"}
NATIVE_SUFFIXES = {".cpp", ".h", ".c", ".rc", ".in"}


class ClosureError(ValueError):
    """候補契約・file境界・必要入力の不一致を表す。"""


def unique_object(pairs):
    """重複JSON keyを拒否し、後勝ちで設定を隠さない。"""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClosureError("DUPLICATE_JSON_KEY:" + key)
        result[key] = value
    return result


def relative_name(value: str) -> str:
    """portableなexact相対file名だけを受理し、隔離対象とpath逸脱を拒否する。"""
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ClosureError("PATH_FORMAT")
    parts = value.split("/")
    if re.search(r'[\x00-\x1f<>"|?*]', value) or PurePosixPath(value).suffix.casefold() in FORBIDDEN_SUFFIXES:
        raise ClosureError("PAYLOAD_OR_PATH_FORMAT")
    if any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts):
        raise ClosureError("PATH_COMPONENT")
    if parts[0].casefold() in {part.casefold() for part in FORBIDDEN_ROOTS}:
        raise ClosureError("EXCLUDED_ROOT:" + parts[0])
    if PurePosixPath(value).is_absolute():
        raise ClosureError("ABSOLUTE_PATH")
    if any(re.fullmatch(r'(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part, re.I) for part in parts):
        raise ClosureError("DEVICE_PATH")
    return value


def normal_file(root: Path, name: str) -> Path:
    """rootからleafまでreparse/symlinkを拒否する。sourceを変更しない。"""
    relative_name(name)
    current = root
    for component in (None, *PurePosixPath(name).parts):
        if component is not None:
            current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise ClosureError("MISSING_INPUT:" + name) from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ClosureError("REPARSE_INPUT:" + name)
    if not stat.S_ISREG(info.st_mode):
        raise ClosureError("NOT_REGULAR_INPUT:" + name)
    if info.st_size > MAX_FILE_BYTES:
        raise ClosureError("INPUT_SIZE_LIMIT:" + name)
    return current


def read_limited(root: Path, name: str, accounting: dict) -> bytes:
    """宣言上限と実byteを照合し、全候補の有限read予算を累積する。"""
    path = normal_file(root, name)
    before = path.stat()
    if accounting["files"] >= MAX_FILES or accounting["bytes"] + before.st_size > MAX_TOTAL_BYTES:
        raise ClosureError("READ_BUDGET")
    with path.open("rb") as stream:
        value = stream.read(MAX_FILE_BYTES + 1)
    after = path.stat()
    if len(value) > MAX_FILE_BYTES or len(value) != before.st_size or (
        before.st_size, before.st_mtime_ns
    ) != (after.st_size, after.st_mtime_ns):
        raise ClosureError("INPUT_CHANGED_OR_LIMIT:" + name)
    accounting["files"] += 1
    accounting["bytes"] += len(value)
    return value


def load_manifest(root: Path, name: str, accounting: dict) -> dict:
    """source候補だけのversioned契約を読み、未知fieldや重複pathも拒否する。"""
    value = json.loads(read_limited(root, name, accounting).decode("utf-8"), object_pairs_hook=unique_object)
    fields = {"schema", "finalAllowlist", "files", "excluded", "generatedHeaders", "requiredEdges", "externalInputs", "limitations"}
    if set(value) != fields or value["schema"] != SCHEMA or value["finalAllowlist"] is not False:
        raise ClosureError("MANIFEST_CONTRACT")
    files = value["files"]
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise ClosureError("MANIFEST_FILES")
    names = [relative_name(name) for name in files]
    if names != sorted(names) or len({name.casefold() for name in names}) != len(names):
        raise ClosureError("UNSORTED_OR_DUPLICATE_PATH")
    if name not in names:
        raise ClosureError("MANIFEST_NOT_INCLUDED")
    for header, template in value["generatedHeaders"].items():
        if "/" in header or not header.endswith(".h") or template not in names:
            raise ClosureError("GENERATED_HEADER_CONTRACT")
    for row in value["excluded"]:
        if set(row) != {"path", "reason"} or not row["reason"] or row["path"] in names:
            raise ClosureError("EXCLUSION_CONTRACT")
    return value


def normalize_reference(owner: str, reference: str, base: str = "") -> str:
    """参照をrepository内の相対名へ解決し、workや親逸脱を読取前に拒否する。"""
    result = posixpath.normpath(posixpath.join(base, reference.replace("\\", "/")))
    try:
        return relative_name(result)
    except ClosureError as error:
        raise ClosureError("EXCLUDED_DEPENDENCY:" + owner + ":" + reference) from error


def verify_integrity_test_scratch(text: str) -> None:
    """必須unitのscratch祖先生成と二rootを固定し、旧work依存の復帰を拒否する。

    CMakeを実行しない静的検査である。native writerの固定root・reparse・CreateNew判定や
    合成assertionを変更せず、任意live研究targetの別rootもこのunitへ流用しない。
    """
    declaration = re.search(
        r'set\(\s*drivercrate_integrity_test_scratch\s+"\$\{CMAKE_CURRENT_BINARY_DIR\}/test-scratch/maintenance-inf-integrity"\s*\)', text)
    creation = re.search(r'file\(\s*MAKE_DIRECTORY\s+"\$\{drivercrate_integrity_test_scratch\}"\s*\)', text)
    definitions = re.search(
        r'target_compile_definitions\(\s*drivercrate_maintenance_inf_integrity_tests\s+PRIVATE(?P<body>.*?)\)', text, re.S)
    if declaration is None or creation is None or definitions is None or not (
        declaration.end() < creation.start() < creation.end() < definitions.start()
    ):
        raise ClosureError("UNIT_SCRATCH_ANCESTOR_NOT_DECLARED")
    for macro, leaf in (("REACHED", "reached"), ("RESIDUAL", "residual")):
        expected = f'DRIVERCRATE_{macro}_WORKSPACE=L"${{drivercrate_integrity_test_scratch}}/{leaf}-$<CONFIG>"'
        if definitions["body"].count(expected) != 1:
            raise ClosureError("UNIT_SCRATCH_ROOT_NOT_ISOLATED:" + macro)


def references(owner: str, text: str, files: set[str], generated: dict) -> list[tuple[str, str]]:
    """native include、CMake literal、Python import、PSローカルimportの静的edgeを返す。

    動的なruntime pathを実行して推定しない。非literalのpackage mappingはrequiredEdgesと
    固定payload式の別検査で扱う。全言語の一般的な到達可能性証明ではない。
    """
    edges = []
    suffix = PurePosixPath(owner).suffix
    parent = posixpath.dirname(owner)
    if suffix in NATIVE_SUFFIXES:
        for match in re.finditer(r'^\s*#\s*include\s*"([^"\r\n]+)"', text, re.M):
            target = match[1]
            if target in generated:
                edges.append((generated[target], "generated-template"))
                continue
            # tests/liveはCMakeのDRIVERCRATE_REACHED_REFERENCE_RESEARCH用明示include rootである。
            candidates = [normalize_reference(owner, target, base) for base in (parent, "src", "tests", "tests/unit", "tests/live")]
            found = [candidate for candidate in candidates if candidate in files]
            if not found:
                raise ClosureError("MISSING_LOCAL_INCLUDE:" + owner + ":" + target)
            edges.append((found[0], "native-include"))
        if suffix == ".rc":
            for match in re.finditer(r'\b(?:ICON|RT_MANIFEST)\s+"([^"\r\n]+)"', text):
                edges.append((normalize_reference(owner, match[1], parent), "resource"))
        for match in re.finditer(r'(?:L)?"((?:tests/fixtures|data/collector-registry)/[^"\r\n]+\.(?:json|txt))"', text):
            edges.append((normalize_reference(owner, match[1]), "native-runtime-fixture"))
    if suffix == ".py":
        tree = ast.parse(text, filename=owner)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                raise ClosureError("RELATIVE_PYTHON_IMPORT_UNKNOWN:" + owner)
            modules = [item.name for item in node.names] if isinstance(node, ast.Import) else (
                [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for module in modules:
                top = module.split(".")[0]
                candidates = [base + "/" + top + ".py" for base in (parent, "scripts")]
                found = [candidate for candidate in candidates if candidate in files]
                if found:
                    edges.append((found[0], "python-import"))
                elif top not in sys.stdlib_module_names and top not in {"__future__"}:
                    raise ClosureError("MISSING_PYTHON_IMPORT:" + owner + ":" + top)
            # 製品toolの固定repository入力もimportとは別に確認する。test中の架空pathは実入力にしない。
            if not owner.startswith(("scripts/test", "tests/")) and isinstance(node, ast.Constant) and isinstance(node.value, str):
                if re.fullmatch(r'(?:docs|data|tests/fixtures|cmake|scripts|packaging)/[^\s]+\.(?:json|md|txt|py|ps1|psm1|in|ico)', node.value):
                    edges.append((normalize_reference(owner, node.value), "python-fixed-repository-input"))
    if suffix in {".ps1", ".psm1"}:
        for match in re.finditer(r"Join-Path\s+\$PSScriptRoot\s+'([^']+\.(?:ps1|psm1|py))'", text):
            edges.append((normalize_reference(owner, match[1], parent), "powershell-local-path"))
    if owner == "CMakeLists.txt" or suffix == ".cmake":
        if owner == "CMakeLists.txt" and "drivercrate_maintenance_inf_integrity_tests" in text:
            verify_integrity_test_scratch(text)
        for match in re.finditer(r'(?<![\w/])((?:src|tests|cmake|scripts|packaging|data)/[\w./-]+\.(?:cpp|h|c|rc|in|cmake|ps1|py|ico|manifest|json))\b', text):
            edges.append((normalize_reference(owner, match[1]), "cmake-input"))
        for match in re.finditer(r'\$\{CMAKE_CURRENT_LIST_DIR\}/([^"\s)]+\.(?:cmake|in|py|h))', text):
            edges.append((normalize_reference(owner, match[1], parent), "cmake-list-input"))
    if suffix == ".yml":
        for match in re.finditer(r'\bscripts/[\w-]+\.py\b', text):
            edges.append((normalize_reference(owner, match[0]), "ci-python-entry"))
    return edges


def collector_payload_edges(text: str) -> list[str]:
    """現packageの固定script配列式を検査し、未理解の式へ変更された場合は拒否する。"""
    pattern = r"@\(([^)]*)\)\s*\|\s*ForEach-Object\s*\{\s*'scripts/'\s*\+\s*\$_\s*\+\s*'\.py'\s*\}"
    matches = list(re.finditer(pattern, text, re.S))
    if len(matches) != 1:
        raise ClosureError("COLLECTOR_PAYLOAD_EXPRESSION_UNKNOWN")
    names = re.findall(r"'([a-z_]+)'", matches[0][1])
    if not names or len(names) != len(set(names)):
        raise ClosureError("COLLECTOR_PAYLOAD_MODULES")
    explicit = re.findall(r"'(scripts/[a-z_]+\.py)'", text)
    return ["scripts/" + name + ".py" for name in names] + explicit


def check(root: Path, manifest_name="scripts/public_source_export_manifest.json") -> dict:
    """候補fileと既知の静的edgeだけを検証し、再現可能なpin/edge集合を返す。"""
    accounting = {"files": 0, "bytes": 0}
    manifest = load_manifest(root, manifest_name, accounting)
    files = set(manifest["files"])
    pins = []
    edges = set()
    generated = manifest["generatedHeaders"]
    for name in manifest["files"]:
        raw = read_limited(root, name, accounting)
        pins.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        if PurePosixPath(name).suffix not in TEXT_SUFFIXES and name != "CMakeLists.txt":
            continue
        text = raw.decode("utf-8-sig")
        for target, kind in references(name, text, files, generated):
            edges.add((name, target, kind))
        if name == "packaging/collector/collector-setup.psm1":
            for target in collector_payload_edges(text):
                edges.add((name, target, "collector-package-module"))
    for row in manifest["requiredEdges"]:
        if set(row) != {"owner", "input", "kind"} or not row["kind"]:
            raise ClosureError("REQUIRED_EDGE_CONTRACT")
        edges.add((relative_name(row["owner"]), relative_name(row["input"]), row["kind"]))
    for owner, target, kind in sorted(edges):
        if owner not in files or target not in files:
            raise ClosureError("INPUT_OUTSIDE_MANIFEST:" + owner + ":" + target)
    canonical = json.dumps(pins, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"schema": "dc-public-source-closure-result-v1", "status": "STATIC_REFERENCES_CLOSED_NOT_FRESH_BUILD",
            "finalAllowlist": False, "files": pins,
            "edges": [{"owner": owner, "input": target, "kind": kind} for owner, target, kind in sorted(edges)],
            "fileCount": len(pins), "edgeCount": len(edges), "inputBytes": sum(row["bytes"] for row in pins),
            "sourceSetSha256": hashlib.sha256(canonical).hexdigest(), "readAccounting": accounting,
            "externalInputs": manifest["externalInputs"], "limitations": manifest["limitations"]}


def main() -> int:
    """明示rootで検査し、指定時だけ未存在reportを保存する。入力fileは変更しない。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).absolute().parents[1])
    parser.add_argument("--manifest", default="scripts/public_source_export_manifest.json")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = check(args.root.absolute(), args.manifest)
        if args.report:
            with args.report.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(result, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        print(f"PASS static candidate files={result['fileCount']} edges={result['edgeCount']} freshBuild=NOT_RUN finalAllowlist=false")
        return 0
    except (ClosureError, OSError, UnicodeError, SyntaxError, json.JSONDecodeError) as error:
        print("FAIL " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
