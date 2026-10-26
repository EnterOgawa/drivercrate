# ADR 0393: collector の正規 file 起動

- 日付: 2026-10-21
- 状態: 実装前契約。限定回帰と変更後配布物の受入は別に記録する。

## 決定

ADR0390のnative workspace／local-index二入口と、将来の明示local-only Task Actionは、
同梱Pythonの固定絶対executableへ`-I -B -S`と固定絶対scriptを渡す通常file起動へ変更する。
scriptはそれぞれ`package/scripts/collector_workspace.py`、`collector_local_index.py`であり、
後続のpackage/action/root/transfer、package/mode/config/scopeのargvは維持する。
Taskは同じlocal script、`pythonw.exe`、package/task-once/configに限定する。
shell、`-c`、compile/exec/runpy、偽の`__file__`、datetime prewarm、監査解除、例外無視や
失敗時の別起動方式へのfallbackを追加しない。

両scriptは直接起動された場合だけ、package依存importより前に自然な`__file__`の絶対pathと
固定scripts所属を検査する。所属rootとpackage argvの完全一致、isolated/no_site/bytecode無効と
同rootの固定runtime executableを要求し、`runtime/python313.zip`、`runtime`、`scripts`の
三pathだけをこの順序で設定する。任意argv、CWD、PATH、siteを探索元に使わない。
同じscriptをcanonical module名で通常importし、実module originと三pathを再照合してmainへ委譲する。
sys.modulesの偽装aliasや検査前のpath復元は行わない。import利用時は既存pathと本体処理を維持する。
Task側のcanonical module origin検査も維持する。

nativeの既存ACL/reparse/全byte hash/manifest/receipt検証、実handle保持期間、最小環境、
継承pipe、job、timeout、Windows quoteと32768文字未満のargv制約は変更しない。
Task guardは新Actionの期待XMLを同じfile方式へ固定する。旧publisher Actionを出発点にする
既存の明示切替contractは維持し、旧local `-c` Actionを暗黙に更新・adoptしない。
所有receiptは新登録／明示切替後の実XMLから保存する既存方式を維持し、旧XML、旧package hash、
config/originや承認を新manifestへ転用しない。既登録Taskの照会・更新・有効化・実行は本変更に含めない。

## 根拠と検証の限界

同梱runtimeの自然file入口では、実package import後に元の監査拒否を登録したまま、cold
`_strptime`を含むread-only workspace bindingが成功し、合成socket eventは拒否された。
一方、`-c`のAttributeErrorの正確なnative C例外源や外部hookの存在／原因はUNKNOWNである。
`__file__`属性の欠損単独を原因とせず、file起動の互換性改善として採用する。

固定file/argv、空白path、三path/flags/canonical origin、未知mode/引数、不一致package、元audit拒否と
cold binding、native二入口、Taskのfake XML/authority/receiptを限定回帰する。
旧fixtureと原失敗は保持し、新EXE／payload／manifest／receiptの再生成と公開snapshot自身の全必要試験、
非通信EXE fixtureの初期化と後段は別工程で受け入れる。限定回帰だけでは新EXE、実Task、公開準備や
Goalを完成としない。registry/seed/対応対象は増やさず、実HTTP・driver導入・署名・公開を行わない。
