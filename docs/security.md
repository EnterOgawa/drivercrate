# セキュリティ設計

収集v7のdata bundle/active世代はpackage/通信同意と別です。非通信importは全schema/参照/原byte hashと
B1再reviewを検査し、親/固定子は同じactive原byteを使用します。別daily opt-inはpackageとworkspaceの
実directory identityへ結合し、copyでは復元しません。運用export-v3は最大課金/待機/cursor/世代と
公開参照だけを引継ぎ、private run/permit/鍵/credential/driver byteを移設しません。
元候補のprovenance本文はhash/原時刻へ射影し、元/射影hashを分けます。新原点の実検査証拠として再使用しません。
日次は既存private caller/run/buildへ進み、署名/公開を呼びません。別PCの実受入は未確認です。Taskの有限実測はリリースノートへ分けます。

DriverCrateは公式性、実取得byte、driver内容、現在端末への適用性、選択と同意、復旧準備を独立して検証します。
署名や公式配布元であることだけでは導入を許可しません。操作は[利用ガイド](user-guide.md)を参照してください。

## WindowsとProvider

現行v7/receipt-v3のcollector setupは現在user SID/rootから導出する所有Taskだけを管理します。
通常installへの同意はmetadata15時Task一件、検査取得17時Taskは別の明示同意です。
asInvoker/InteractiveToken/LUAと保護root、current user/SYSTEM/Administratorsの境界を維持します。
先行plan/nonce、disabled登録、全定義・非実行・SDDL読戻し、所有receiptのflush/readback、
未来境界の再検査、enable/有効readbackの順で処理し、S_OKだけを成功にします。
既知のEnabled既定行省略だけを有限候補で照合し、Taskやreceiptの原byteを書換えません。

通常uninstallは所有・定義・非実行を照合し、両所有Taskの正常不存在を確認後に管理programを削除します。
旧admin receipt混在・所有不明・running/queued・不正XML/SDDLは保持して拒否します。
設定・seed・収集データ・待機履歴を保持し、copy/importからTask所有や通信許可を発行しません。
実測と未確認は[リリースノート](release-notes-0.1.1.md)に分けます。

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
新規配布recordの期間上限は8日です。発行観測の24h未満と実HTTPの24h待機は別で、
現在UTCでの原期限を再検査します。merge/rebaseでも期限を延長しません。
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

旧client/setup/dataの互換・自動移行は提供しません。旧store移動toolも廃止しています。
所有不明・既存未知rootを拒否し、旧Task/store/dataを自動移動・削除・resetしません。
独立したtrust、原hash/期限と世代下限を維持します。

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

汎用配布検査用の新source入口は、明示`--distribution-run-once ... --confirm-inspection-download`です。
同じsetup親がpackage/receipt/runtime/moduleと祖先の実handle、両側origin、native writerを保持し、
固定Python子が同じmonitor writerを保持します。一接続の有限duplexで実子PID/image/pipe peerを確認し、
保存済みPAGE/payload予約と原job/全入力/plan/順序/期限/capへ結合した私有の一回権限だけを実行します。
公開成功JSONの再import、任意command/URL RPC、別processへの許可JSONはありません。
PAGE2MiB+1byteとpayload cap+1byte、各最大3要求を64要求/32MiB/600秒内で先払いします。
完全な同native HTTPだけを一回実数精算し、停止・欠損は最大課金と元待機を保持します。
PAGEの同run借用でもjob別anchor/session/hash/通常全INF検査を省略しません。
新規originの非通信初期化と専用pristine型は、旧admissionの空request拒否を変えません。
未知を含む旧履歴の観測は拒否前に単調記録し、既知origin/履歴の消失・置換をfreshにしません。
native共有scopeはHOLD、campaign/segmented/未知scopeは拒否します。
配布runの親側拒否でも、同じ所有Job/childを停止し、子の終端を有限確認するまでRAIIがnative writerを
保持します。停止/5秒待機で終端不明のOS異常は固定診断付き異常終了とし、通常結果や再開へ変換しません。
同runの通常全INF/公開identity結果は、JSON decoderを持たない私有所有観測へ保持します。
親がその同じ結果objectからv2候補を新規保存/flush/readbackし、原journalと生存中の親精算へhash結合します。
同じ固定childの非通信assembleが既存v2/GZip/raw manifest・全分母report/provenanceを生成し、
親は原候補と実出力byteを照合して共通未署名validatorへ渡します。未署名receiptから署名済みmanifest/
asset型や取得permitを構築する入口はありません。候補headの世代はローカルの準備値です。
認証済公開headを今回取得していないため、署名用次世代確定とは扱いません。
旧成功の原時刻/期限、全体・個別失敗、他OS未観測、v2表現限界を保持し、空成功/全失敗では旧headを更新しません。
以上はsourceと完全fake試験の接続です。現setupへの同梱、active data/import、専用日次、
実INF/Models抽出とアプリlookup/bindingの全受入、実HTTP/WinTrust/別PC/配布物の受入は未了です。
鍵照会/作成・署名・trust登録・公開・driver導入をrun/buildへ含めません。

## 検証の限界

人工試験、元packageの実内容検査、実端末適合、実導入を別の資格として扱います。
最終公開sourceからのfresh buildと最終配布物の確認は、その具体的なbyteへ結合する必要があります。
過去版の成功や署名検証だけを、全機器への適合・導入成功・復旧保証へ読み替えません。
実driver導入と各OS/機器の実測範囲は[リリースノート](release-notes-0.1.1.md)、
再現方法は[テスト方針](testing.md)を参照してください。
