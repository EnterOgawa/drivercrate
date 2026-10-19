# アーキテクチャ

DriverCrateはC++20／Win32のWindows x64アプリです。通常アプリは機器列挙、候補表示、選択、
共通取得・検査、既存の導入経路と結果を担当します。メーカー別page解析、対象追加、台帳と更新履歴は
収集PC側へ置き、新製品追加だけでアプリの設定やProviderを増やしません。

## UIとworker

```text
Win32 UI thread
  MainWindow / 表示DTO / 選択と最終確認
        │ 有限queue、operation ID / scan session ID
        ▼
Provider worker thread（COM MTA）
  registry / opaque候補identity / 私有package・導入計画
        ├─ WUA → Windows Update / Microsoft Update / WSUS
        ├─ Driver Store → SetupAPI / NewDev
        └─ 公式HTTP・署名索引 → 実取得・内容検査・端末内照合
```

UIで同期COM、network、導入待機を行いません。WUA objectは作成したapartment内だけで使用し、
interface pointerをUIへ渡しません。所有権が明確なDTOをPostMessageで通知し、古いoperation／scanを破棄します。
終了時は新規受付を止め、worker終了前にWindowの所有状態を破棄しません。
Idle、Scanning、ScanReady、CreatingRestorePoint、Downloading、Installing、Completed、Failed、Stoppingを
区別します。同時操作を拒否し、進捗は確定済み段階・項目から算出します。取消しは協調停止です。

## Providerと候補

registryがstable ID、表示名、能力、既定状態、同一版取得元tierを一元管理します。
WUAは`ssDefault`で管理policyと適用性を尊重し、Driver Storeはpresent deviceの互換listを使います。
公式Providerは共通HTTP／file検証へ配布元固有のhash・publisher・製品条件を追加します。
表示専用metadataを取得可能・導入可能へ自動昇格しません。

UIは種類→device→現在版／候補のtreeを表示し、基本driverにつき一計画を選択します。
同じdevice・action・空でない明示versionが完全一致するgroupも、候補identityとroutingを保持します。
検証済みmetadataのopaque package IDで取得・実行を共有し、device別結果を残します。
表示名、URL、日付から同一性・適用性を推測しません。

## 署名索引と共通取得

収集PCが外部JSON台帳から索引候補を生成し、検証後に同じrepositoryから配布する方式です。
アプリには共通取得、署名・hash・schema・期限・世代検証と端末内照合を接続しています。
公開catalog／検査済みINFのIDと端末inventoryを分け、生端末IDを取得要求へ送りません。

索引recordは発見の根拠であり、serialized planから導入権限を復元しません。
現在scanのrecord、公式取得grant、同意、実byteを結合して検査し、device／OS／x64／Windows rank／
必須条件が成立した計画だけを私有routingへcommitします。元archive、必要INF／CATと参照file、封印と
handleを保持し、直前に再検証します。別sessionや同hashの別workspaceへの付替え、未知・重複・staleを拒否します。

標準INFは既存指定導入境界へ接続し、初回と必要Extension／componentを明示します。
公式installerは専用の署名・publisher・作用範囲と対話引継ぎへ分岐し、INF rankや内容合格を合成しません。
scan中のEXE／MSI実行や無関係なapp・firmware追加は行いません。

## 導入と結果

最終確認を現在scan、選択、EULA、方式、初回／旧版、必要componentと復旧保護へ結合します。
clientは復元ポイント開始失敗時にProviderを呼ばず、開始済みなら例外でも終了通知します。
ServerはSystem Restoreを呼ばず、外部backup／checkpointと復旧手順への管理者同意を要求します。
実OSと保護modeをworkerで再確認します。

全選択のpreflightと直前検査を行い、終了・失敗・例外で計画を失効させます。
取得、API結果、実状態、再起動、後始末の診断は独立です。Extensionのstageやbase成功を個別反映成功とせず、
installer終了をdriver導入済みとしません。完了後は全Providerを自動scanせず、選択deviceの読取り専用
事後観測と結果を残します。旧scanを再利用せず、crash後も新しいscanを正本にします。

## 収集PCとsetup

新メーカー・新製品の調査は人による保守作業で、対象は外部JSONへ追加します。
収集PCは登録済み対象の更新確認と索引生成を担当します。AI／P2P／有料検索API／Cloud Runを
現行機能や次の実装前提にしません。原則日次収集・週次索引更新は方針であり、運用受入とは別です。
研究台帳、locator、取得証拠、監視state、公開索引を分け、製品参照、metadata、本体取得、内容、適合、
導入を別集計します。有限予算、期限、24時間待機、host保留、単一writerと中断回復を移設でも維持します。

Collector setupは通常アプリと別成果物です。native EXEが閉じたpayload集合とmanifestを検査し、
v3以降は固定CPython runtimeとlicenseも同梱します。v4は保護workspaceと非通信の停止export／import／resume、
v5は正式原点へ結合した明示一回monitorを持ちます。実装・人工試験は実正本の開始許可や別PC受入ではありません。
[Collectorセットアップ](collector-setup-guide.md)と[台帳説明](../data/collector-registry/README.md)を参照してください。

## 検証状態

限定した実収集・取得と、INFを含むドライバー本体の内容検査には正常例があります。
通常画面で実端末に照合した正常候補の表示・実取得を一連で確認する受入は未完了です。
現在の必須source gateと決定的unit／CLI／UIは資格付きで技術受入済みです。
実driver導入と必要Extensionの個別反映は未確認です。
通常製品の固定配布公開鍵と独立revision1取得policyはsourceへ登録済みです。ローカル受入optionは
既定OFFで、過去の受入profileの鍵・同意・期限を通常製品へ引き継ぎません。
現行ソースに対応する収集用ローカルv5 packageの配置・検査・保持／解除と、非通信の初期化・検証・
停止export／import・人工中断からのnative再開は、このPCで有限に受入済みです。空のローカルmonitorによる確認で、
実正本の結合・オンライン開始、実GitHub→通常アプリの正常候補・取得、日次継続／再起動、別PC移設は未受入です。
画像metadata、過去Git履歴、最終公開一覧と新しい公開用build、Private push／readback、本人のPublic承認も
未完了です。814件のsource候補は最終allowlistではありません。

[セキュリティ設計](security.md)、[テスト方針](testing.md)、[Release checklist](release-checklist.md)を参照してください。
