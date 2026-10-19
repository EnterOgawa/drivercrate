"""自作C/C++の制御文コメントを列挙し、レビュー済み説明だけをtoken不変で挿入する。"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from source_style import IGNORED_KINDS, apply_edits, ensure_same_tokens, source_paths, tokenize


def control_nodes(source: str) -> list[dict]:
    """C/C++の制御語を限定字句処理で列挙し、直前の独立commentの有無を返す。

    直前が#の制御語と、閉じ波括弧の対応先の直前がdoとなるwhileを除く。
    括弧対応または単文終端までをbodyとし、直近briefは表示補助だけに使う。
    完全なC++構文解析や実関数ownerの特定は保証せず、sourceは変更しない。
    不完全なtoken配置等による解析例外は呼出し元へ伝播する。
    """
    tokens = tokenize(source)
    significant = [token for token in tokens if token.kind not in IGNORED_KINDS]
    pairs = {}
    stack = []
    for index, token in enumerate(significant):
        if token.text in {"(", "{"}:
            stack.append((index, token.text))
        elif token.text in {")", "}"}:
            if not stack:
                continue
            opening, _ = stack.pop()
            pairs[opening] = index
            pairs[index] = opening
    comments = [token for token in tokens if token.kind.endswith("comment")]
    nodes = []
    for index, token in enumerate(significant):
        if token.text not in {"if", "for", "while", "do", "switch"}:
            continue
        if index and significant[index - 1].text == "#":
            continue
        if token.text == "while" and index and significant[index - 1].text == "}":
            opening = pairs.get(index - 1, 0)
            if opening and significant[opening - 1].text == "do":
                continue
        preceding_else = (index and significant[index - 1].text == "else"
                          and not (index > 1 and significant[index - 2].text == "#"))
        start_index = index - 1 if preceding_else else index
        previous_end = significant[start_index - 1].end if start_index else 0
        start = significant[start_index].start
        gap_comments = [
            comment for comment in comments
            if previous_end <= comment.start < start
            and not source[source.rfind("\n", 0, comment.start) + 1:comment.start].strip()
        ]
        condition_end = index
        if token.text != "do":
            opening = index + (2 if significant[index + 1].text == "constexpr" else 1)
            if opening >= len(significant) or significant[opening].text != "(":
                continue
            condition_end = pairs[opening]
        body_start = condition_end + 1
        body_end = pairs.get(body_start, body_start)
        if significant[body_start].text != "{":
            while body_end + 1 < len(significant) and significant[body_end].text != ";":
                body_end += 1
        nearest_contract = next((comment for comment in reversed(comments) if comment.end <= start and "@brief" in comment.text), None)
        brief = re.search(r"@brief\s+([^\n]+)", nearest_contract.text).group(1) if nearest_contract else ""
        body = source[significant[body_start].start:significant[body_end].end]
        nodes.append({
            "token_index": index, "kind": token.text, "line": source.count("\n", 0, token.start) + 1,
            "start": start, "commented": bool(gap_comments), "function": brief,
            "condition": source[token.start:significant[condition_end].end], "body": body,
            "body_start": significant[body_start].start,
        })
    return nodes


def case_nodes(source: str) -> list[dict]:
    """Caseの直前または直後にある説明を確認し、literal中のcaseは無視する。"""
    from source_structure import bracket_pairs
    tokens = tokenize(source)
    significant = [token for token in tokens if token.kind not in IGNORED_KINDS]
    pairs = bracket_pairs(significant)
    comments = [token for token in tokens if token.kind.endswith('comment')]
    nodes = []
    for index, token in enumerate(significant):
        if token.text not in {'case', 'default'}:
            continue
        end = index + 1
        while end < len(significant) and significant[end].text != ':':
            if significant[end].text in {';', '='}:
                break
            end += 1
        if end == len(significant) or significant[end].text != ':':
            continue
        previous_end = significant[index - 1].end if index else 0
        following = end + 1
        gap_comments = [comment for comment in comments if
                        (previous_end <= comment.start < token.start
                         and not source[source.rfind('\n', 0, comment.start) + 1:comment.start].strip())
                        or significant[end].end <= comment.start < significant[following].start]
        body_end = following
        while body_end < len(significant) and significant[body_end].text not in {'case', 'default', '}'}:
            if significant[body_end].text in {'(', '[', '{'}:
                body_end = pairs[body_end]
            body_end += 1
        nearest = next((comment for comment in reversed(comments) if comment.end <= token.start and '@brief' in comment.text), None)
        brief = re.search(r'@brief\s+([^\n]+)', nearest.text).group(1) if nearest else ''
        nodes.append({'token_index': index, 'kind': token.text,
                      'line': source.count('\n', 0, token.start) + 1, 'start': token.start,
                      'commented': bool(gap_comments), 'function': brief,
                      'condition': source[token.start:significant[end].end],
                      'body': source[significant[following].start:significant[body_end].start],
                      'body_start': significant[following].start})
    return nodes


def main() -> int:
    """明示された説明の適用/移動だけを、検証と元source再読後に逐次保存する。

    reportはsource保存後に作成/上書きする。複数fileの更新は原子的ではなく、
    途中のI/O失敗は先行sourceや部分reportを残して伝播する。自動復元はしない。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", help="file名→token index→説明のレビュー済みJSON")
    parser.add_argument("--report", help="不足箇所を保存するJSON")
    parser.add_argument("--path", help="対象の相対path prefix")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--cases", action="store_true", help="switchのcase/default説明を確認する")
    parser.add_argument("--hoist", action="store_true", help="単一の早期終了文に付いた既存理由を条件の直前へ移す")
    parser.add_argument("--limit", type=int, default=100)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    authored = json.loads(Path(arguments.apply).read_text(encoding="utf-8")) if arguments.apply else {}
    report = {}
    pending = []
    hoisted = 0
    for path in source_paths(root):
        relative = path.relative_to(root).as_posix()
        if path.suffix in {".rc", ".in"} or (arguments.path and not relative.startswith(arguments.path)):
            continue
        source = path.read_text(encoding="utf-8")
        nodes = case_nodes(source) if arguments.cases else control_nodes(source)
        missing = [node for node in nodes if not node["commented"]]
        if missing:
            report[relative] = missing
        if arguments.hoist:
            edits = []
            for node in missing:
                if node["kind"] != "if":
                    continue
                body_tokens = tokenize(node["body"])
                body_code = [token for token in body_tokens if token.kind not in IGNORED_KINDS]
                body_comments = [token for token in body_tokens if token.kind.endswith("comment")]
                if (len(body_code) < 4 or body_code[0].text != "{" or body_code[1].text not in {"return", "throw", "continue", "break"}
                    or sum(token.text == ";" for token in body_code) != 1 or len(body_comments) != 1):
                    continue
                reason = body_comments[0]
                if reason.kind != "line_comment" or not (
                    reason.start >= body_code[-2].end or reason.end <= body_code[1].start
                ):
                    continue
                start = node["start"]
                prefix = source[source.rfind("\n", 0, start) + 1:start]
                indentation = re.match(r"[ \t]*", prefix).group()
                insertion = ("\n" + indentation if prefix.strip() else "") + reason.text + "\n" + indentation
                edits.extend(((start, start, insertion), (node["body_start"] + reason.start, node["body_start"] + reason.end, "")))
                hoisted += 1
            if edits:
                converted = apply_edits(source, edits)
                ensure_same_tokens(source, converted)
                pending.append((path, source, converted))
        if relative in authored:
            by_index = {str(node["token_index"]): node for node in nodes}
            edits = []
            for index, comment in authored[relative].items():
                node = by_index[index]
                if node["commented"]:
                    raise ValueError(f"control already has an explanation: {relative}:{index}")
                if not comment.strip() or "\n" in comment or not comment.endswith("。"):
                    raise ValueError("each reviewed explanation must be one Japanese sentence")
                start = node["start"]
                line_start = source.rfind("\n", 0, start) + 1
                prefix = source[line_start:start]
                indentation = re.match(r"[ \t]*", prefix).group()
                # else前に説明を置く場合も、先行する閉じbraceのtokenを移動しない。
                insertion = ("\n" + indentation if prefix.strip() else "") + "// " + comment + "\n" + indentation
                edits.append((start, start, insertion))
            converted = apply_edits(source, edits)
            ensure_same_tokens(source, converted)
            pending.append((path, source, converted))
    for path, before, _ in pending:
        if path.read_text(encoding="utf-8") != before:
            raise ValueError("source changed while preparing reviewed comments")
    for path, _, content in pending:
        path.write_bytes(content.encode("utf-8"))
    if arguments.report:
        Path(arguments.report).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if not arguments.apply and not arguments.hoist:
        printed = 0
        for relative, nodes in report.items():
            for node in nodes:
                if printed >= arguments.limit:
                    break
                summary = re.sub(r"\s+", " ", node["body"])
                print(f"{relative}:{node['line']} [{node['token_index']}] {node['function']}\n  {node['condition']}\n  {summary[:430]}")
                printed += 1
    count = sum(len(nodes) for nodes in report.values())
    print(f"Missing before edits: {count} in {len(report)} files; authored {sum(len(entries) for entries in authored.values())}; moved existing {hoisted}.")
    return int(arguments.check and bool(count))


if __name__ == "__main__":
    raise SystemExit(main())
