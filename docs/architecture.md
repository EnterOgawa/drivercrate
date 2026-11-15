# アーキテクチャ

## 同選択SYSTEM依存の私有計画（ADR0491）

既NativeLoaderは、検証済みSYSTEM/INBOX・元Store/CATと正確なNeeds文脈へ、全作用の列挙後に型/所有関係/実提供copyを照合します。共有readerを使い、元原文の全field・元file/CAT/hash/権限・必要なservice安定config/SDを既RequiredDriverComponentPlanへ保持し、native直前の再構築値へ完全比較します。固定Windows遅延登録の有無を一般SYSTEM file proofと分け、候補発行やcallback成功を登録完了へ読み替えません。現在の内部資格/配布/実機確認の範囲はADR0491と847p9の記録を正本とします。

## App用Setupとバージョン更新（1.0.5）

Appは現在ユーザーの`%LOCALAPPDATA%\Programs\DriverCrate`へInno Setupで配置します。
App/profile/配布文書の明示5fileだけを管理し、同じrootの私有Collectorと保持dataを別製品として扱います。
数値版/24hの純粋policy、専用AppUpdateService/worker、Windows backend、通常MainWindowの通知を小さく分けます。
HTTP・ファイル検査・Authenticodeは既共通moduleを再利用し、ProviderWorkerの操作/scan sessionや署名索引の権限と独立させます。
同意した署名Setupだけを元Explorerの通常ユーザーへ渡し、Appの正常終了後の置換は標準Innoが担当します。
同じ対話sessionのAppは配置を問わず一つとし、driver処理を強制終了するhelper/serviceは追加しません。
詳しくは[ADR0481](adr/0481-app-inno-setup-and-update-checks.md)を参照してください。実装と非通信fixture、隔離user領域でのInno確認を実施しました。将来の正式版への実自己更新と別管理者アカウントでの引継ぎは未確認です。

ADR0479ではmanualの確定METADATA_HTTP/403/原code・終端・producer式一致をlocal周期の別根拠にし、counterは不明のまま保持します。既publication-resumeは同authorityの完了claim/receiptと署名公開viewからADR0480の共通15分窓内でcutoff以内の全短期限recordだけを先行撤去し、非空残集合を原byte/期限とremote完全一致へ結んで公開します。収集予約と独立し、active復旧を先行します。 通常の新規候補にも元fresh/report検証後・予約前に同cutoffを適用し、保存済み短期限recordの再導入を防ぐ。元head/reportとactive復旧は変更しない。

ADR0478のmanual収集は既confirmed collectかつ!offlineだけの内部flagでローカル24h周期を除きます。既原cost/end/attempt/producer式を照合し、source下限・全host待機/review・不明予約と新24h記録を維持します。日次入口や永続schemaは変更しません。

ADR0477のcollectorは同所有INFへWin10/build19045・Win11/build26100のAMD64 workstation/suite0をV3で明示し、target/hash/実code/Modelsを一つのprivate観測へ結びます。Appの現在OS NULL指定と実端末適用性は従来のままです。

ADR0476の常駐収集は既owner.nextDueUtcだけを使い、正常保存した未試行WAITの最短下限へ全体確認を再予約します。開始前のoldDue・終了60秒後を下限とし、次回も全familyの原target/全host待機を再検証します。新しい永続schema/worker/schedulerは追加しません。

> 2026-11-10、1.0.3 source（813e主担当受入/実機確認は未完了）: ADR0474により導入終端の自動全scanを撤去。選択subsetだけを消費し、元未処理route/native lease/保護workspaceを初めから保持する。次の明示操作は新operation/現同意/復旧と対象限定検証へ進む。同taskの未消費routeと、別recordの新LOCAL claimによる独立検査を分け、安定indexの原content ownerへ直接参照する。

通常TreeViewは種類カテゴリ→opaque PnP deviceの二階層・一device一行とし、デバイス名・現在版・候補版の
三列へ要約し、状態・検査・個別結果はダブルクリック詳細へ集約する。同deviceの全候補と現在観測はUIの所有snapshotへ保持し、詳細dialogで比較する。
詳細の閲覧だけでは選択を変えず、明示button後に元scan session・device・candidate indexを再照合して
一device一候補をcheckboxへ結合する。共有packageや同名の別deviceは統合しない。導入後の個別結果は
candidate identityへ結合して詳細へ残し、全候補を失効させる。[ADR 0421](adr/0421-simple-list-and-device-details.md)を参照する。
workerは選択対象だけをread-onlyで再openし、元scan/opaque deviceへ結合した現在名・版・class・問題観測を
InstallResultへ添付する。UIは個別結果を保持して対象行を再構築し、API成功から現在状態を補完しない。

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
通常UIの検索開始はworkerでWindowsハードウェア再検出一回→現在PnP再列挙→更新検索の順に実行します。
再検出の失敗ではProvider走査へ進まず、内部再監査・取得時照合・導入後のread-only確認には再検出を加えません。
同期再検出の完了は全deviceの開始・driver導入完了を保証しません。詳細は[ADR0419](adr/0419-hardware-refresh-before-update-search.md)を参照してください。

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

通常検索は毎回小さな署名更新情報を認証し、保護storeの全再認証で現在有効な原envelopeと完全一致した場合は索引本体の再取得を省きます。初回・新版・有効cache不在は従来の全体取得と検査へ進みます。同一成功はUNCHANGEDとして一時HTTP失敗時のcache利用と区別し、後続の通常load・端末内照合・候補表示は毎回行います。[ADR0467](adr/0467-authenticated-unchanged-index-cache-reuse.md)を参照してください。

索引recordは発見の根拠であり、serialized planから導入権限を復元しません。
現在scanのrecord、公式取得grant、同意、実byteを結合して検査し、device／OS／x64／Windows rank／
必須条件が成立した計画だけを私有routingへcommitします。元archive、必要INF／CATと参照file、封印と
handleを保持し、直前に再検証します。別sessionや同hashの別workspaceへの付替え、未知・重複・staleを拒否します。

通常配布と検証用storeは用途別domainへ分離し、domainごとの世代下限を保持します。
旧共用store/未知rootが存在する場合はfail-closedで停止し、移動・削除・resetしません。
旧移動専用tool/API/trustは廃止し、現在のdomain分離・世代下限・原byte/hashを維持します。
[ADR 0397](adr/0397-release-completion-and-index-expiry-compatibility.md)を現行契約とします。

既存headを開くときは、保護root/DPAPI/wire・原manifest署名・gzip/展開hashから履歴の世代下限を
認証します。この下限だけの内部値はrecord・snapshot・導入許可を持ちません。現在のrecord codecで
読めない過去headも下限を維持し、fresh入力が現在期限と全schema・原byteの検証を通った場合だけ
同じrootで次世代へ保存できます。現在cache・同世代再利用・commit後readbackは全schemaを必須とし、
旧fieldの補完や旧readerを追加しません。Open成功は現在cacheの利用可能性を保証しません。
attestationの元発行への結合と、実現在の失効・取得・適用性の既存adapter検証を維持します。
[ADR 0411](adr/0411-authenticated-history-floor-without-record-hydration.md)に能力の分離を定めます。

監視PCの匿名索引readbackは、既存daily名pairと16桁世代のcandidate-publication名pairだけを
同parent・同stemで許可します。固定保護root・同handle・ACL・reparse拒否と匿名三resourceの
hash/署名/期限検証は別途必須です。任意filenameやURL、通信権限を追加しません。
[ADR 0412](adr/0412-public-readback-canonical-artifact-pairs.md)を正本とします。

標準INFは既存指定導入境界へ接続し、初回と必要Extension／componentを明示します。
公式installerは専用の署名・publisher・作用範囲と対話引継ぎへ分岐し、INF rankや内容合格を合成しません。
scan中のEXE／MSI実行や無関係なapp・firmware追加は行いません。

[ADR0450](adr/0450-windows-managed-driver-package-scope.md)の開発sourceは、全SDF/CAT内容検査と
同deviceの私有native選択scopeを分けます。copied driver DATAの内容合格からprogram実行stepを作らず、
元未評価作用を保持したまま実DDInstallのcopy/source/Windows宛先・関連service/softwareを再読します。
そのfactoryと元rank/bindingを通った通常計画だけを既存NewDev/SetupAPIへ渡します。CopyINFの独立基本INFは
stage用内容であり、追加deviceのinstall memberを発行しません。標準圧縮sourceの一意原名・展開byteと
原CABを来歴へ結び、所有中間回収後も元hashと既存3GiB保持上限を維持します。実機/配布物は別受入です。

通常UIの明示検索は公式探索をmetadata取得へ限定し、候補表示で止まります。汎用取得dialogを開きません。
元署名索引・record・device・取得targetに結合した参照は、installable=falseのまま選択意図を表せます。
Install操作は選んだopaque候補集合を既存取得承認へ結合し、必要EULA全文/revisionだけを明示同意します。
Compositeは元私有Referenceから取得集合を再照合し、未選択targetの取得を拒否します。
取得後の同task・referenceIndex・recordへ一致するcommit済みrouteが唯一の場合だけ、新しい検証済み候補へ解決します。
既検証WUA/Driver Store候補との混在でも元選択集合を維持します。新downgrade・真の複数候補・未成立では停止します。
必要Extension/componentは既存の検証済み基本計画へ含め、復旧前検査を維持します。
取消し、新検索、close、旧eventで継続意図を破棄し、実導入APIは未取得参照を引き続き拒否します。
[ADR 0422](adr/0422-search-select-install-intent.md)を正本とし、新byteの通常実UI受入と実導入は別工程で記録します。

## 導入と結果

Install操作を現在scanの明示選択へ結合し、必要なEULA・方式・旧版・必要componentの新条件だけを確認します。
現実装のclientはWindowsの実在一覧を正本にlocal暦日初回の保護準備/同日再利用を区別し、保護未成立時にProviderを呼びません。
native BEGINを所有したscopeだけが例外時も同sequenceへEND一回を通知します。reuseでは両native操作はNOT_STARTEDです。
既保護storeの固定メモ1件は最適化用で、正常END/実在確認後だけ保存し、読書失敗だけを導入失敗へ合算しません。
ServerはSystem Restoreを呼ばず、外部backup／checkpointと復旧手順への管理者同意を要求します。
実OSと保護modeをworkerで再確認します。

全選択のpreflightと直前検査を行い、終了・失敗・例外で計画を失効させます。
取得、API結果、実状態、再起動、後始末の診断は独立です。Extensionのstageやbase成功を個別反映成功とせず、
installer終了をdriver導入済みとしません。完了後は全Providerを自動scanせず、選択deviceの読取り専用
事後観測と結果を残します。未消費の同scan ownerを保持し、明示Search/closeで失効します。crash後は新scanを正本にします。
元INF（OEM別名は元byte照合）/provider/版と現在状態の実一致をprivate workerで確認し、UIには一致区分だけを渡します。
同deviceの既知のより新しい推奨表示候補/未完了roleがなければ解消済み表示とし、元itemで枠を外し、次の明示推奨filterで除外します。

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

## 認証済み個別device投影（ADR 0413）

署名索引の同一公開IDに複数present機能が一致する場合は元aggregate関係を保持し、DriverStoreの完全個別観測からprivateな一device関係を追加する。原record/public tuple・同owner/lease・全cohort/元診断へ結合し、同record/deviceの複数公開IDは一つの基本参照へ集約する。

詳細は[ADR 0413](adr/0413-authenticated-per-device-index-projection.md)を参照する。

## 単一INFの唯一最良Windows node（ADR 0414）

元INF完全path、Provider、packed版、日付に一致する全Windows nodeを有限正常終端まで読み、
実full rankの最小値が一件のときだけ固定する。同最良の同点、途中障害、列挙上限は拒否する。
導入前の元INF再検証と登録先node再選択でも同じ唯一winnerを要求し、元section/rank/全snapshotの
変化を拒否する。詳細は[ADR 0414](adr/0414-unique-minimum-windows-rank-binding.md)を参照する。

## 選択batch内のnative proof寿命（ADR 0418）

同じ公開IDに一致する別deviceを続けて導入する場合、全選択事前検証後の私有stack scopeが
元proofの解放を同batch終端まで延期する。resolverと新callback生成は開始時に閉じる。
scopeはsnapshotを強所有せず、新scan・明示失効・終端・例外では元proofを失効させる。
各deviceの直前現在状態、rank、固有binding、原byteと期限は引き続き再検証する。
詳細は[ADR 0418](adr/0418-signed-index-batch-proof-lifetime.md)を参照する。


ADR0485のsource実装は、Provider前停止の元operation/選択にworker-localな一回の続行pendingを結びます。
既完了event→UI本人判断→新operationの既command経路だけを使い、同ownerの未消費route/取得済み検査物を再検証します。
client専用の明示復元なしmodeをServer/通常保護と区別し、原失敗operationと復元なし実行を記録します。
新しい永続設定/暗号基盤やworkerからの同期UI呼出しを追加しません。
内部fakeで確認し、revision5のoutput配布へ反映しました。実利用者の新操作・実導入成功は未確認です。
