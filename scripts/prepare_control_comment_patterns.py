"""形と失敗時動作を限定した反復処理だけに、監査済みの制御文説明を割り当てる。"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

from audit_source_comments import control_nodes
from source_style import significant_tokens, source_paths


def describe_control(path: str, node: dict) -> tuple[str, str] | None:
    condition = " ".join(token.text for token in significant_tokens(node["condition"]))
    body_tokens = significant_tokens(node["body"])
    body = " ".join(token.text for token in body_tokens)
    if path.startswith("tests/"):
        collection = r"\w+(?: (?:\.|->) \w+)*"
        count_guard = collection + r" (?:\.|->) size \( \) != [0-9]+U?"
        empty_guard = collection + r" (?:\.|->) empty \( \)"
        absent_guard = r"! " + collection + r"(?: \. has_value \( \))?"
        if body == "{ return ; }" and re.fullmatch(
            r"if \( (?:" + count_guard + "|" + empty_guard + "|" + absent_guard
            + r")(?: \|\| (?:" + count_guard + "|" + empty_guard + "|" + absent_guard + r"))* \)", condition
        ):
            return "test_missing_result", "前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。"
        positive_guard = (
            collection + r" (?:\.|->) size \( \) == [0-9]+U?"
            + "|" + collection + r" \. has_value \( \)"
            + "|! " + collection + r" \. empty \( \)"
        )
        if "DRIVERCRATE_EXPECT" in body and re.fullmatch(
            r"if \( (?:" + positive_guard + r")(?: && (?:" + positive_guard + r"))* \)", condition
        ):
            return "test_result_details", "結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。"
        located = re.fullmatch(r"if \( (\w+) != (?:std :: wstring|std :: string|\w+) ::? ?npos \)", condition)
        if not located:
            located = re.fullmatch(r"if \( (\w+) != \w+ \. npos \)", condition)
        if located and "DRIVERCRATE_EXPECT" in body and re.match(
            r"\{ \w+ \. (?:replace|insert|erase) \( " + re.escape(located.group(1)) + r"(?: ,| \))", body
        ):
            return "test_fixture_mutation", "対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。"
    failed = re.fullmatch(r"if \( FAILED \( (\w+) \) \)", condition)
    error = re.fullmatch(r"if \( ((?:\w*[Ee]rror|result|status|operationResult)) != (?:0|ERROR_SUCCESS) \)", condition)
    failure = failed or error
    if failure:
        variable = failure.group(1)
        if body == f"{{ return {variable} ; }}":
            return "propagate_error", "検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。"
        if re.fullmatch(r"\{ return static_cast < (?:NativeError|HRESULT) > \( " + re.escape(variable) + r" \) ; \}", body):
            return "propagate_native_error", "失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。"
        if body in {"{ return false ; }", "{ return std :: nullopt ; }", "{ return { } ; }"}:
            return "reject_partial_result", "処理が失敗した部分結果を有効とみなさず、後続の判定に利用できない結果を返す。"
        if re.fullmatch(r"\{ (\w+) \. error = " + re.escape(variable) + r" ; return \1 ; \}", body):
            return "record_error", "原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。"
        if body == f"{{ return nativeErrorFromWin32 ( {variable} ) ; }}":
            return "win32_error", "Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。"
    succeeded = re.fullmatch(r"if \( SUCCEEDED \( (\w+) \) \)", condition)
    success = re.fullmatch(r"if \( ((?:\w*[Ee]rror|result|status|operationResult)) == (?:0|ERROR_SUCCESS) \)", condition)
    success = succeeded or success
    if success:
        variable = success.group(1)
        if body.startswith("{ " + variable + " = ") and body.endswith(" ; }") and "(" in body and sum(token.text == ";" for token in body_tokens) == 1:
            return "preserve_first_error", "先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。"
    if condition == "if ( FAILED ( apartment . result ( ) ) )" and path.startswith("tests/") and "return" in body:
        return "com_initialization", "COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。"
    if condition == "if ( firstError == 0 )" and body.startswith("{ firstError = ") and sum(token.text == ";" for token in body_tokens) == 1:
        return "first_error", "複数の失敗で最初の原因を失わないよう、診断値が未記録の場合だけ保存する。"
    if re.fullmatch(r"\{ (?:CloseHandle|RegCloseKey|WinHttpCloseHandle|SetupDiDestroyDeviceInfoList|BCryptDestroyKey|CryptDestroyHash|CryptReleaseContext|BCryptCloseAlgorithmProvider) \( [\w ,]+ \) ; \}", body):
        if "INVALID_HANDLE_VALUE" in condition or "nullptr" in condition or " 0 " in condition:
            return "release_valid_resource", "無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。"
    return None


def main() -> None:
    """sourceをread-only走査し、説明候補のplanをwork/tmpへ作成/上書きする。

    sourceへ適用せず、生成だけで適用を許可しない。出力の親directoryは作成せず、
    親欠損や書込み失敗を含むI/O例外は伝播する。部分planは自動削除しない。
    """
    root = Path(__file__).resolve().parents[1]
    plan = {}
    counts = collections.Counter()
    samples = collections.defaultdict(list)
    for path in source_paths(root):
        if path.suffix in {".rc", ".in"}:
            continue
        relative = path.relative_to(root).as_posix()
        for node in control_nodes(path.read_text(encoding="utf-8")):
            if node["commented"]:
                continue
            description = describe_control(relative, node)
            if not description:
                continue
            rule, comment = description
            plan.setdefault(relative, {})[str(node["token_index"])] = comment
            counts[rule] += 1
            if len(samples[rule]) < 3:
                samples[rule].append((relative, node["line"], node["condition"], node["body"]))
    output = root / "work/tmp/source-style-analysis/control-patterns.json"
    output.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"counts": counts, "samples": samples}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
