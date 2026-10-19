# セキュリティ設計

DriverCrateは公式性、実取得byte、driver内容、現在端末への適用性、選択と同意、復旧準備を独立して検証します。
署名や公式配布元であることだけでは導入を許可しません。操作は[利用ガイド](user-guide.md)を参照してください。

## WindowsとProvider

WUAは`ssDefault`でWindows Update／Microsoft Update／WSUSと管理policyを尊重します。
非適用、導入済み、非表示、置換済みupdateを独自判断で候補へ戻しません。
Driver Storeはpresent deviceの互換driver listを使い、導入直前にもdevice・INF・metadata・rankを照合します。
公式Providerの信頼境界はWUAとは異なります。

registryがstable ID、能力、既定状態、同一版取得元tierを一元管理します。未知・重複・矛盾した設定を拒否します。
表示IDからURLやpathを組み立てず、現在scanとworker内の私有routingに結合します。
同じdevice・action・明示versionの完全一致による取得元groupも候補identityと選択肢を削除しません。

## 公式HTTPと内容検査

HTTPS、公式起点からの導線、record、有限redirect、公開宛先、応答上限、schemaを確認します。
未登録hostだけでは除外せず、検証済みCDN委譲をsession・record・用途限定で扱います。
検索順位、名称、HTTPSだけでは公式と確定せず、広告・投稿・無関係なlink・任意転送・private宛先を拒否します。

共通HTTP／file検証へ期待size、公開hash、必要なpublisher根拠を結合します。
実byte、INF／CATと参照する全file、OS装飾、x64、署名、driver-only、明示必須条件を検査し、
初回導入・必要Extension／componentとWindows選択条件を扱います。版・日付だけでは適用性を決めません。
未知、条件不成立、検査失敗、方式未対応を分けます。
共有packageは検証済みmetadataのopaque IDで一回取得・実行し、device別の部分失敗を保持します。

EXE／MSIはscan中に実行しません。公式installer引継ぎは元record・hash・期待publisher・作用範囲、
現在deviceの再照合と別の最終確認を要求します。終了codeをdriver導入成功へ変換しません。
BIOS／UEFI／firmware、OEM utility、app、Windows software updateはdriver導入対象ではありません。
同じpageのfirmware記載だけで通常driverを一律除外せず、具体的な必須条件を個別に評価します。

## 署名索引

固定公開鍵pin、署名manifest、世代、期限、asset hashとschemaを検証し、端末内で照合します。
公開catalog／検査済みINFのIDと端末inventoryは別の来歴です。索引は導入許可ではなく、
実取得byte、内容、端末適用性、現在scanのbindingを再確認します。旧世代復帰にも署名・期限の契約を適用します。

通常製品はsourceに固定した配布公開鍵と、署名認証から独立したrevision1取得policyを持ちます。
ローカル受入optionは既定OFFです。検証用profileの人工試験や有限なローカル正常例を、実GitHubの
通常配布の受入としません。公開鍵の登録、取得同意、保護runtime、実配布は別の確認です。

通常配布の保護storeは`%ProgramData%\DriverCrate\SignedIndex-distribution-v1`、検証用は
同親の`SignedIndex-local-<完全公開鍵SHA-256>-v1`です。domain間で世代下限を混ぜず、
同じdomainのrollbackと同世代異内容は拒否します。旧共用`SignedIndex-v1`が残る間は
通常のopen/reload/commitを`ERROR_REVISION_MISMATCH`で拒否し、旧productionの世代下限を
無視した初期化を防ぎます。旧headの削除やresetを回復手順にしません。

明示buildする`DriverCrateIndexStoreMigrator`は通常ALL/packageに含めません。
事前確認した原headの完全SHA-256と実署名・gzip・全schemaを検証し、固定公開鍵に対応する
用途別名へ同親directoryを移動します。旧pathは消失しますが、directory identity、DPAPI
entropy、head/lock byteと世代下限を保持します。旧local公開鍵はこの歴史認証専用であり、
通常manifest trustや取得認可へ追加しません。期限切れ履歴の移動は現在snapshot、
attestationの期限延長、取得grant、導入許可を発行しません。

移行中は旧アプリを終了します。最終再認証まで旧lockとheadを保持し、rename直前は子handleを
閉じます。DELETE権限付き・DELETE非共有のroot handleは旧/新store ownerと両立せず、同じ
directoryをpinし続けます。既存移動先、未知署名、破損、保護不整合、期待hash差を拒否します。
rename失敗は結果不確定とし、自動rollbackしません。中断後は固定移動先の同pin/全履歴認証を
確認した明示再実行だけをalready migratedと報告します。このPCでは旧検証用storeの実署名認証、
原byte・世代下限を保った移動と通常配布storeへの世代5保存を有限に確認しました。
他の旧storeや別PCの保証ではありません。[ADR 0380](adr/0380-signed-index-trust-domain-store-migration.md)を参照してください。

## Session、同意、復旧

有限queueと単調増加するoperation／scan IDを使い、古いscan、未表示・未知・重複候補、Provider不一致を拒否します。
同時操作を拒否し、終了時は新規受付を止めworkerを待ちます。Windowsの導入を強制終了しません。
検索、検査用取得、EULA、導入は別の同意です。最終選択・確認前にWUAのEULAを受諾しません。

clientは復元ポイント開始失敗時にProviderを呼ばず、開始後は失敗・例外でも終了通知します。
ServerはSystem Restoreを呼ばず、外部backup／checkpointと復旧手順への管理者同意を要求します。
実OSと保護modeをworkerで再確認します。復元ポイントは完全backupではありません。
Server backup、VSS snapshot、hypervisor checkpointを作成・変更しません。

全選択のpreflightと直前再検証後に実行し、終了時はscanと計画を失効させます。
取得、API結果、実状態、再起動、後始末を分け、Extensionの登録やbase成功を個別反映成功としません。
選択deviceの読取り専用事後確認を残し、次の導入は新しいscanを要求します。無条件の自動retryは行いません。

## Privacyと保存

telemetry、広告、利用追跡、自動crash uploadはありません。生Hardware／Compatible ID、instance ID、
serial、credentialをvendorや検索serviceへ送りません。契約で認める最小表示名も明示した探索範囲に限ります。
通常行・共有logへ実IDやpathを出しません。端末内詳細は画面／sessionに結合し、serial、credential、
期限付きURLの認証tokenを隠します。

通常動作に永続logは必須ではありません。共有可能な診断は時刻、version、操作・状態、Provider、件数、
進捗、result code／HRESULTに限定し、title、ID、URL、path、EULA、payloadを含めません。
保護cacheは管理者保護store、端末binding、公式起点・record・hash・parser版・時刻へ結合します。
cacheは高速化用で、探索対象や恒久的な導入許可にせず、構成・OS・parser・policy・期限等で失効します。

## Collectorと配布運用

研究台帳、保護state、公開JSON索引を分けます。研究seedのhashは署名ではありません。
driver本体、実inventory、cookie／token、秘密鍵、保護descriptorを公開索引や可搬snapshotへ含めません。
snapshot配置だけでTask・収集を開始せず、停止export／検証／import／明示再開と元の待機・予算を維持します。
[Collectorセットアップ](collector-setup-guide.md)と[台帳説明](../data/collector-registry/README.md)を参照してください。

日次receiptは元200本文、hash、request／record／fetchを保護storeへ結合します。304再確認、未通信再利用、
期限前HOLDを分けます。配布pipelineは専用鍵profileと再投影した二assetを扱い、固定repositoryへのreadbackと
一回CASを行うコードを持ちます。失敗・応答喪失を成功とせず旧世代を保持します。
Taskの定義生成、新規登録、既存Action限定更新は実装済みですが、実切替許可と実運用受入は別です。
現在userのInteractiveToken／HighestAvailableと保護runtime・config・祖先ACLを要求し、password保存、
policy変更、任意Actionへの置換を認めません。
Publicには署名索引のmanifestと圧縮JSONだけを配置済みです。現在のpublisherはPrivate identityを
要求するためPublic日次運用は未対応で、旧日次・smoke Taskは停止中です。自動再開しません。

## 検証の限界

必須品質gateと決定的unit／CLI／UIの技術受入は、実導入や全OS／全機器の保証ではありません。
現行ソースに対応する未署名の収集用ローカルv5 packageは、このPCの配置・検査・保持／解除と非通信の
初期化・検証・停止export／import・人工中断からのnative再開を有限に確認済みです。空のローカルmonitorでの
確認に限り、実正本の結合・確認を伴うオンライン開始、日次継続と別PC移設は未受入です。
通常アプリではPublic索引のHTTP 200・世代5保存と、1 packageの実取得・内容検査を確認しました。
72 INF中57件の内容・署名合格、15件の未解析・未対応を残し、同じ1機器への標準INF旧版候補3件は未選択です。
全archiveや全機器の成功、実導入成功とは扱いません。公開sourceは私有履歴と分離して初回検証後に公開し、
変更ごとに固定snapshotの再確認を行います。アプリ・collectorの公開binary Releaseと実導入は未確認です。
実導入と今後のremote反映は必要な明示承認の範囲で行います。
脆弱性報告は[SECURITY.md](../SECURITY.md)、試験の資格は[テスト方針](testing.md)を参照してください。
