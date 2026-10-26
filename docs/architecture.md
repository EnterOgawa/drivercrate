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

通常配布と検証用storeは用途別domainへ分離し、domainごとの世代下限を保持します。
旧共用store/未知rootが存在する場合はfail-closedで停止し、移動・削除・resetしません。
旧移動専用tool/API/trustは廃止し、現在のdomain分離・世代下限・原byte/hashを維持します。
[ADR 0397](adr/0397-release-completion-and-index-expiry-compatibility.md)を現行契約とします。

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
現行v7の固定77payloadにCPython runtime/license・seedとdistribution dataを同梱します。
receipt-v3だけを扱い、旧packageの受理/自動移行と固定local-index入口を廃止しました。
非通信停止移設、native metadata Taskと別同意のdistribution Taskは異なる現行責務です。
[Collectorセットアップ](collector-setup-guide.md)と[台帳説明](../data/collector-registry/README.md)を参照してください。

## 検証状態

通常appは署名索引の共通検証・保存・端末内照合・取得/内容検査・既存導入経路を使用します。
Collectorは現行v7/receipt-v3で、native metadata日次と別同意の汎用検査取得日次を分けます。
同じ私有typed観測から未署名候補を生成し、手動prepare/sign/publishへ原byteと各期限を渡します。
署名済み型、未署名の申告、実取得authorityと端末適合性を相互に代用しません。

新規配布recordは8日、発行に使えるnative/汎用PAGE・内容観測は24h未満です。
汎用の独立根拠は四範囲それぞれの実手動確認時刻を保持し、原PAGE観測時刻から分離します。
現行profile/edits/jobはv2で、四scopeの原`bodySha256`とは別に`contentSha256`を結合します。
比較は全raw byteを正本とし、実`</body>\n</html>`の外側・EOF直結の厳密なWP Fastest Cache
生成診断コメント一件だけを区別します（ADR0399）。原本文/hash/時刻と各期限は保持し、
script/属性文字列内の偽終端、本文/リンク/規約/前提・任意commentの変更は許容しません。
保存v1 dataはpackage switch/verifyと新data importの旧active比較だけで原manifest/byte/参照を監査し、
現行run/plan/native jobへは受理しません。新v2 import前の収集は拒否します。
限定offline検証と実HTTPでの新取得は別の資格であり、過去の実失敗を成功へ変更しません。
汎用収集の同run完全PAGEは、原結果を先に保存した後、保護runの固定`page-<ordinal>.body`へ
最大2MiBの原byteで保持します（ADR0398、実装済み・有限fixture確認、実運用の新PAGE捕捉は未確認）。hash拒否でも元errorを保持し、
本文を取得権限へ復元したり、通常UI/log/公開索引・可搬参照へ含めたりしません。
新実行では同結果の原hash/size/公式起点/転送観測への照合を必須とし、旧runの本文欠測は補完しません。
候補期限は同run実内容検査・実PAGE観測・各実手動確認の各+8日のminです。
全原期限minが実公開時点から7日超でない場合は手動公開を拒否します。
manifestは全原期限minを保持し、実HTTP待機・課金、署名/内容/適用性・世代下限を変更しません。

実取得/INF検査、人工試験、historical replay、実PC適合と実導入の資格は
[リリースノート](release-notes-0.1.1.md)と[テスト方針](testing.md)へ分けます。
公開sourceは私有履歴から独立した具体的な集合を固定し、そのsnapshotからfresh buildします。
manifestの`finalAllowlist=false`は候補schemaの契約であり、固定集合のreview receiptとは別です。
GitHub Actionsは通常運用に使用せず、公開開始後の履歴を保持します。

[セキュリティ設計](security.md)、[Release checklist](release-checklist.md)を参照してください。
