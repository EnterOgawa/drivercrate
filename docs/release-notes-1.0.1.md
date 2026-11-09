# DriverCrate 1.0.1

Windows x64向けの利用者Appです。tagは`v1.0.1`、配布assetは`DriverCrate-windows-x64.zip`と対応する`.sha256`です。
正式配布前にAppのAuthenticode署名・時刻証明、署名後byte/profile、ZIP内容とchecksumを検証します。
実際の配布状態は対応する[GitHub Release](https://github.com/EnterOgawa/drivercrate/releases/tag/v1.0.1)と受け取ったfileで確認してください。

## 主な変更

- 有効な署名索引が同じ世代・内容なら、署名更新情報を照合して索引本体の再取得を省きます。
- 取得したINFのInclude/Needs依存では、元packageとWindows側の参照元を区別して必要内容を検査します。
- 導入後もfilter・行順・カテゴリ開閉・選択位置・scroll位置を保持します。個別結果と再照会した現在状態を同じ行へ残します。
- 成功対象のcheckだけを外し、他の選択意図は旧scanの閲覧専用履歴へ残します。自動で全Providerを再検索しません。
- 検索と導入の段階・件数・全体進捗、および一般化した診断を表示します。

## 取得・導入の境界

検索は候補表示で止まります。未検査参照を明示選択した場合、Installから選択した配布物だけを取得・検査し、
同じdevice/recordの唯一の検証済み候補へ進みます。規約案内と任意全文を同じ選択への「同意してインストール」に結びます。
旧版切替、公式installer、具体的前提条件、WUA固有条件とServerの復旧確認は、それぞれ必要な明示判断を維持します。
driver本体・CAT/INF・適合性・rank・同意・client復元ポイントの検査を省略しません。

## 確認範囲と制限

現行開発系列では、利用者からドライバー導入成功の報告を受けています。表示保持、共有package、初回候補、
失効・部分失敗・復旧失敗は決定的な人工試験で確認しています。過去Private合格と、最終公開snapshotのfresh受入は別に記録します。
最終署名byteでの再導入、全機器・各OS version、別PCでの表示保持は未確認です。成功報告を全機器へ一般化しません。

対象はサポート対象Windows client/Server x64です。Serverではbackup/checkpointの事前確認と管理者同意が必要で、
DriverCrateはServer backupを作成しません。firmware/BIOS/UEFI/OEM utilityは対象外です。
索引の登録件数は実端末の適合件数と異なり、未知・HOLD・期限切れを成功へ数えません。
署名索引の配信はApp Releaseのlatest指定と独立した固定先を使い、今回のApp公開で既存世代・期限・authorityを変更しません。

ZIPの内容はApp、同名index-profile、README、LICENSE、THIRD_PARTY_NOTICESの五fileです。
私有Collector/Setup/収集定義/registry、driver本体、inventory、credential、鍵、workは含めません。
更新方法と制限は[利用ガイド](user-guide.md)、保護境界は[security](security.md)を参照してください。
