# ADR 0388: 固定local-index子環境へOS由来SystemDriveを渡す

- 日付: 2026-10-20
- 状態: 採用。G13-I7r245vで実装・有限検証を受入れ、247d/rと242vで本PCのprepare・一対象実収集を確認した。

## 背景

242bの実prepareはexit2 / ABSOLUTE_FIXED_PATHで停止した。242bdの非変更probeで、
executeSetupChildのSystemRoot/PYTHONIOENCODINGだけの環境では、同梱CPython 3.13.16からの
SHGetKnownFolderPath(CommonAppData, KF_FLAG_DONT_VERIFY)が`%SystemDrive%\ProgramData`を
未展開で返し、protected_rootの既存絶対path検査が拒否することを確認した。

## 決定

GetWindowsDirectoryWの元Win32失敗code保持と容量検査を維持し、その成功値が普通の
絶対DOS drive path（ASCII英字・colon・backslashで始まる）であることを確認する。
UNC、device path、drive相対、追加colon、NUL、環境展開記号、相対componentを拒否し、
検査した先頭二文字だけをSystemDriveとして固定子環境へ追加する。
親のSystemDrive値、PATH、Python検索path、任意環境は継承しない。
既存の明示通信操作に限ったproxy四種継承、jobとtimeout、同意・state・予算は変更しない。
OSのWindows directoryが不適格なら子を起動せず、固定診断で停止する。
normal_pathを緩めたりC:\ProgramDataで代用したりしない。

もう一つのrunCollectorSetupWorkspaceはcollector_workspaceとmonitorへ明示rootを渡し、
daily_index_pipeline.protected_rootを呼ぶ経路ではない。今回の対象local-index childとは
別の既存契約として読み取り確認し、その環境構築は変更しない。

## 検証と境界

同一TU unitで不適格Windows pathを拒否し、実子processで偽装した親SystemDriveを採用せず、
OS由来SystemRoot/SystemDrive、CommonAppDataの絶対path展開、拒否環境の欠損を確認する。
実同梱runtimeとpackage CWDの非変更probeで旧二変数環境の拒否と新三変数環境の成功を比較する。
prepare/once、運用native collector、HTTP、Task、鍵、署名、GitHub、driver操作は実行しない。
新assetは別outへ生成し、旧配置とstateを保持する。実prepare成功は後続245rで確認する。

## 有限な実施結果

245a/tで関連native Debug/Release各5件、実子環境16条件、bootstrap49条件、local13件が成功した。
実同梱CPython 3.13.16の同じCWDで、旧二変数環境のABSOLUTE_FIXED_PATHと新三変数環境の成功を
各一回確認した。prepare/onceは呼んでいない。単体EXEの既存fixture379check/47processは成功し、
Debug/Release全target、変更format/metadataと新生成tableを含むDoxygen集合検査も成功した。
245a/t時点では旧配置の実prepareと実収集は未受入だった。後続247d/rで実prepare・一対象収集と
ローカル索引生成が成功した。4系統の追加variant、既存skip1、全suite・公開品質、
GetWindowsDirectoryWのAPI失敗0の実注入を今回の合格へ含めない。
