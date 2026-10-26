# ADR 0391: collector Python import pathの冪等化

- 日付: 2026-10-20
- 状態: 採用。以下は当初の最小実装と通常Pythonの実import三条件、既存local31／PSguard131等の確認履歴。
  daily209は外側300秒で147件ok・一件中断・61件未着手のため未合格。主担当受入と残試験は未完。

## 背景

ADR0390の固定Task loaderは`[runtime/python313.zip, runtime, scripts]`だけを設定する。
`collector_local_index`が読む`daily_index_pipeline`は、import時に自身のsibling directoryを無条件に
先頭追加していた。このため既存scriptsを重複させ、厳密な三path検査が
`LOCAL_TASK_MODULE_PATH`で拒否した。旧probeの失敗と診断記録は保持する。

## 決定

`str(Path(__file__).resolve().parent)`と同じ文字列が`sys.path`に既に含まれる場合は追加しない。
不在の場合だけ従来どおり先頭へ一回追加する。一つのmembership条件に変更を限定し、
`__main__`限定や全caller／loaderの変更へ広げない。pathの正規化・重複削除・並べ替えは行わない。

既存siblingが後方にある旧`._pth`等の環境では、従来の先頭への重複追加がなくなり、元の位置を保つ。
この探索優先順位の差を明示して実import回帰へ含める。既知prepare caller自身が行う先頭追加は変更しない。
不在の旧単独`-I`入口に必要なsibling追加は維持する。

Taskの三path完全一致と順序、isolated／no_site／bytecode無効、実executable、五module origin、
全hash／ACL検査は変更しない。検査直前のpath復元や実行像の偽装は採用しない。
標準library等の探索が不適切な環境をこのmembership条件だけで受理するものではない。

## 回帰と資格

既存testへfresh実Python child三条件（sibling既存先頭／既存後方／不在）を追加する。
stdlib探索pathを保持し、実sourceのimport前後の全pathを比較する。不在条件は実fileのspecを使い、
`__main__`でないmodule名を`sys.modules`へ登録して実行する。旧sourceの失敗を先に保存し、
同じ分母で修正後の結果を確認する。mockまたはsource fakeコピーだけでは代替しない。
旧単独CLIとprepare callerの非通信拒否／実import、既存local・daily/prepare・PSguardも確認する。

この通常Python回帰は同梱Taskの固定三path実受入ではない。source変更後の新manifest再生成、
別hashの新Qへの新規保護配備、receipt／prepare／strict readonly package-bootstrap-loadを別工程で要する。
既存Q／runtime／ACL／Taskは今回変更しない。Task接続やGoal完成、対応数増加を主張しない。

後続では別hashの保護版を配置し、strict loaderとlocal-only Task経由の検証一回を確認した。
結果はNO_NEW_OBSERVATION/NO_NETWORK・新保存0で、fresh保存ではない。元の300秒中断は当時の失敗として
保持する。今回の公開候補byte自身の全daily209・全必要試験と公開snapshot受入は別に実行する。
