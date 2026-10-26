# ADR 0382: Public日次設定の閉入口と認証済み履歴遷移

- 日付: 2026-10-19
- 状態: 採用。G13-I7r231h15s11b2aのローカル設定接続に限定する。
- 前提: ADR0381の固定Public identity、ADR0373〜0377の原byte・claim・carry・UNKNOWN境界を維持する。

## 決定

従来のv1/v2閉schemaやPrivate既定を緩和せず、`dc-public-daily-index-config-v3`を追加する。
v3は通常の既存loaderで認証できる原v2 configの全fieldを保持する。schemaだけをv3へ変更し、
`predecessorConfigFile`、`predecessorConfigSha256`、`publicPublisherApprovalSha256`を追加する。
旧scopeの位置と原hash、workspace/state/outputRoot、trust、日程、codeRepair/preSignContinuationと
旧carryは変更しない。原v2は通常load_configをそのまま通し、新しい内部loader条件を設けない。
元code pin不一致や既存署名前例外の拒否をPublic移行のために回避しない。
全fieldの比較は数値/booleanの型も区別し、JSON objectのkey順には依存しない。

Public承認recordはOS既知の保護rootにある`control/approved-public-publisher.json`に固定する。
任意pathをconfig/CLIへ追加しない。既存protected_pathによるowner/DACL/ancestor/reparse/hardlink検査と
64KiB以下の原byte SHAを照合し、ADR0381の13閉field・固定Public ID/owner/actor/配布fingerprint検証を行う。
process内でも初回原byteのhashをfrozen値に保持し、使用時に再検査する。recordを本処理から発行しない。

明示preparerは新control directoryへconfig.jsonをCREATE_NEWし、原v1/v2・scopeを上書きしない。
preparer自身も検証済み四moduleと同じ保護versionに配置されていることを要求する。
新outputRoot/日程/credential/署名鍵や旧carryの自己申告を受け付けない。config保存や純粋Public検証は
実行承認ではない。取得用途のPublisher factoryへ固定recordの原byteを接続し、既存二asset/一CASと
暗号・内容検証callbackを保持する。通常アプリ/Provider/C++/CMake/Task sourceは変更しない。

## 未接続の履歴遷移と拒否

旧v2 configの認証だけでは、新config hashによる旧観測・旧予算の再利用を許可しない。
実行を開くには旧artifact/claimの原SHA、原署名結果のexit0とnativeCurrentVerified、原公開秒での
native history検証、stateの世代予約と原receipt、正規dueの別receiptを結合する必要がある。
同観測の再開は原config/claimと既使用carryを保持し、UNKNOWNのCASは原byte readback-onlyに限る。
config SHA差、別counter、新root、current自己申告、codeRepair/preSign削除、日時編集を認証の代用にしない。

この全遷移は今回未接続とする。v3のrun/run_acquisition/Task/report入口は作用前に
`PUBLIC_HISTORY_TRANSITION_REQUIRED`で閉じる。v3 planは実行不可と履歴遷移未接続を明示する。
新しい日付やdue到来だけで拒否を解除しない。旧carry90calls/846.4786秒、gen5期限13:24:11Zを変更せず、
期限経過した旧assetを現在有効と扱わない。旧codeの履歴専用認証、正規due観測への遷移、実保護配置と
Task再bindは後続工程であり、b2親・Public日次運用を完了にしない。

## 検証と限界

隔離fixtureで明示prepare→load→Publisher factoryの正常接続と閉field/pin/位置/ACL拒否を確認する。
v1/v2、Private、署名claim、予算、UNKNOWN readback-only、期限の指定回帰を実行する。
v3 runの拒否は正規due遷移成功の証拠ではない。実Task・保護record/config発行配置・鍵/credential照会・
署名・実収集・外部HTTP/API/remote反映・実app・driver操作を行わない。公開manifestへのADR追加と
公開snapshot再受入も後続とする。通常15pinが不変なら前工程のnative/build資格を継承し、
今回全suite再合格とは表現しない。
