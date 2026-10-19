"""承認済みC/C++書式を検査・適用する開発用entry point。製品には組み込まない。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from source_style import find_clang_format, format_source, read_source, source_paths


def main() -> int:
    """checkでもlocal toolを同期起動し、全対象の検証後にだけ明示writeを適用する。

    checkの差分は終了値1とする。処理/I/O例外は伝播し、逐次書込みの途中失敗では
    先行sourceを巻き戻さない。複数fileを原子的に更新する入口ではない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="書式差分があれば非0で終了する")
    mode.add_argument("--write", action="store_true", help="検証済みの書式差分を適用する")
    parser.add_argument("--clang-format", help="使用するclang-formatのpath")
    parser.add_argument("paths", nargs="*", help="省略時は全自作sourceを対象とする")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    owned = source_paths(root)
    owned_set = set(owned)
    targets = [Path(path).resolve() for path in arguments.paths] if arguments.paths else owned
    if not targets or any(path not in owned_set for path in targets):
        parser.error("targets must be existing files inside the owned source directories")
    clang_format = find_clang_format(arguments.clang_format)
    pending = []
    for path in targets:
        source = read_source(path)
        formatted = format_source(source, path, clang_format, root)
        if format_source(formatted, path, clang_format, root) != formatted:
            raise ValueError(f"formatter is not idempotent: {path.relative_to(root)}")
        output = formatted.encode("utf-8")
        if path.read_bytes() != output:
            pending.append((path, output))
    # 全対象の検査後にだけ書き込む。途中の検査失敗で一部だけ適用しない。
    for path, output in pending:
        if arguments.write:
            path.write_bytes(output)
        print(f"{'formatted' if arguments.write else 'needs format'}: {path.relative_to(root).as_posix()}")
    print(f"Checked {len(targets)} files; {len(pending)} {'updated' if arguments.write else 'differences'}.")
    return 1 if pending and arguments.check else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"source format failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
