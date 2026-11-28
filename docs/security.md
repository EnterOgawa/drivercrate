# セキュリティ設計

署名付き索引の全体期限、候補ごとの期限、保護済みキャッシュの世代と原署名を検証します。1.0.14の新旧入口の検証は [ADR 0607](adr/0607-independent-signed-index-record-expiry.md) の契約に従います。

## 索引条件とストレージ候補の確認

署名索引のWindowsビルドや機器条件は、端末の情報を外部へ送らず照合します。対応するストレージ候補では原署名とINFの参照を再確認し、導入前に共有設定や必要なINFなどの変更範囲を表示します。Windowsの再起動や後から反映される登録が必要な場合は、導入結果に確認状態を表示します。

## SYSTEM Needsの型付き構成（ADR0489/0491）

SYSTEM Needsの読取りでは、同選択から到達する検証済みSYSTEM/INBOX原文と対応Store/CATを根拠に、型付き媒体データと固定Windows標準登録だけを検査します。原INF内interface、元CopyFilesの完全hash/CAT、固定System32二実体の署名形式別cache-only trustと防改変権限を要求し、導入直前にも元tupleを再確認します。未知root/型/flag、任意command/ACL/autorun、PACKAGEのglobal設定を一律許可しません。CATや署名方式のtrust失敗を別方式/通信で救済しません。

Windows標準登録はOS側の遅延処理です。native導入成功をその登録完了へ読み替えず、該当する元私有計画の証拠がある結果だけに未確認を表示します。この機能の実機での適用と反映は、公開配布物の検証とは別に確認します。

ADR0491では、同検証済みSYSTEM原文の選択文脈に限り、SYS/service/copy、相対HKR、媒体COM/VfW、property、interface、WDF/companion、同serviceの閉じたETW関係を二相で列挙/解決します。全field/参照/共有上限と元file/CAT/防改変権限・必要な安定service config/SDを私有計画へ保持し、導入直前にfresh値と完全比較します。PACKAGEのglobalroot、任意COM/program/filter/ACL/未知作用を署名だけで許可しません。通常SYSTEM fileの検査と、実際の固定RunOnceから得る遅延登録factを分けます。

## 通常ユーザーの収集とsetup限定の公開親検査（ADR0483）

Collectorだけが明示する`CURRENT_USER_INSPECTION`は、OS KnownFolderのLocalAppDataへ固有領域を新規作成し、
本人ownerと本人/SYSTEM二ACEのprotected DACLをroot/子/外部writer取込みへ使います。派生nested/INF閉包とcacheも同modeを保持します。
既定consumerのWindows Temp/Admin保護を維持し、native導入binding/stagingと準備済み導入executorはinspection modeを作用前に拒否します。
modeは原取得証拠・hash/CAT/INF・端末適合性や導入同意を代替しません。

同user/machine/元配置の所有済みv2 setupだけが、協調停止・host/control/writer排他と同setup journalの後、program置換前に
既存公開設定の同authority bindingを照合します。必要な場合だけ同bundle EXEを親PID限定で標準UACへ接続します。
元limited/full linked tokenの同user/logon、同実EXE、三排他handleとjournalを再確認し、OS固定ProgramData/DriverCrate親一個だけへ
本人の非継承`READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE`（0x001200A0）一ACEを追加します。
旧0x000200A0や別SID/未知owner/余分ACE/reparseを採用せず、元二ACEのbyte/順序/flags・owner/group・子ACLを保持します。
原SDの直前比較と同handle readback、元非昇格tokenによる通常metadata再open、commit前の非変更再確認を要求します。本人exact ACEが未準備のまま昇格起動したsetupは拒否し、通常の非昇格setupから進めます。
内容読取・列挙・作成/変更/削除・WRITE_DAC/WRITE_OWNERを本人へ追加しません。通常起動/timer/copy/import/uninstallはACLを変更しません。
取消し/期限/部分失敗/不確定ではdata/journalを保持し、盲目的rollbackやauthority移動・鍵/認証再作成を行いません。
ACL診断は固定API/descriptor/ACE段階とpath種別・元Win32数値だけです。実path/SID/本文/URL/credentialを一般logへ渡しません。
本修正の実setup/UAC・実収集/公開と変更後byteの利用者受入は、source/隔離fixtureから分けて未確認です。

## AppのSetupと更新確認（1.0.5）

App用Inno Setupは現在ユーザーのAppData\Local内だけへ配置し、通常は`Programs\DriverCrate`を使います。
管理対象はApp/profileと配布文書の5file、標準shortcut/uninstallerに限り、同rootのCollector、data、設定、log、未知fileを削除しません。
Appの管理者権限とSetupの現在ユーザー権限を分け、更新時は元のExplorerへ同じ配置先の通常Setupだけを渡します。
Explorerを確認できない場合はAppを維持し、管理者の別配置や全user登録へ退避しません。

App更新は固定`EnterOgawa/drivercrate`の正式latestだけを確認します。通知への同意後に固定名Setupを取得し、TLS/許可host、有限サイズ、ReleaseのSHA-256、
Windows Authenticode成功と発行元`ENTER SYSTEM, K.K.`、製品役割と数値版を取得後/起動直前に検査します。
検査済みfileの書換え/削除を禁止したhandleを引継ぎまで保持し、未署名を許す更新fallbackは設けません。
索引の署名/世代/期限とドライバーの適合性・導入同意・復旧は別の境界です。
WindowsのSmartScreen・証明書・組織policyに従い、ユーザー領域や署名だけで警告を回避できるとは保証しません。
詳細な契約は[ADR0481](adr/0481-app-inno-setup-and-update-checks.md)を参照してください。将来の正式版を取得して自己更新する実往復と、別管理者アカウントでの更新は未確認です。

ADR0479の403例外は成功や既知counterを生成せず、原retry/review・host・notBeforeを保ちます。新403もRetry-Afterを照会し欠損/照会失敗を分け、429/503とreviewの元24h下限を維持します。ADR0480の期限前保守は共通15分cutoff以内だけを一律撤去し、実発行nowと分けます。確認済み公開viewのhash/署名/完了claim/receipt・全履歴とremote原byte一致を必須にし、未失効原record/期限を変えず、空/不確定CASを迂回しません。 通常の新規候補にも元fresh/report検証後・予約前に同cutoffを適用し、保存済み短期限recordの再導入を防ぐ。元head/reportとactive復旧は変更しない。

ADR0478の手動同意はlocal周期だけの一回例外です。元Retry-After/clamp・明示notBefore・全host HOLD/review・未完了/不明予約を消さず、所有/排他/停止/clock/有限枠・署名/内容検査・公開retryも維持します。原state/ownerの手修正やcopyによる例外発行は行いません。

ADR0477の明示Models観測は導入適用性を代替しません。同INF前後hashとCAT/member/publisherを再検証し、別target/hash・未知API結果から成功を生成しません。PAGE/内容/規約等の独立時刻と原24hを維持し、旧record期限を書き換えません。

ADR0476の早い日次再確認は通信許可を追加しません。正常終端の未試行HOLD/ORIGINAL_OR_RUNTIME_WAITだけを根拠とし、原対象24h、baseline、全hostのRetry-After/manual HOLD、同意とclock下限を毎回維持します。取消し/期限終了/例外/不明結果では元通常予約を残します。

> 2026-11-10、1.0.3 source（813e主担当受入/実機確認は未完了）: ADR0474の未処理U/実行Sは原context/thread/generation/operation/subsetを全照合する。lookupを凍結して新しい列挙権限を作らず、旧tokenを復活させない。再利用本体は元owner/issuer/ledger/seal/全配布tupleと原A/B期限を再検証し、新明示承認のLOCAL claimで独立検査する。消費済transfer grantは由来/原最小期限だけの不変証拠であり、現在の読取・実行許可にはしない。元成功日時/900秒/CDN上限を更新しない。

## 私有native collectorの変更時自動公開（ADR0444）

2026-11-05の利用者指示により、明示有効化した私有C++ collectorだけが、内容成功を含む変更索引を
既存配布専用CNG鍵で署名して固定公開先へ送ります。通常consumerへ署名／公開能力をlinkしません。
ADR0445では設定済みの収集PCは通常自動公開とし、日常menuの公開切替を外します。copy／authority未接続から権限を作りません。
専用Windows資格マネージャーのtokenだけを固定api.github.com／uploads.github.comへ送り、
asset redirectは匿名へ落としてpublic DNS／HTTPSを再検査します。一般driver HTTPの認証禁止を維持します。
各sendのnetwork costと原待機・取消し、収集とは別の公開5分期限を保持し、累積回数／取得量quotaを追加しません。

元PrivateIndex229 anchorの保護と全祖先の置換／write境界、同authorityのpipeline.lock、全claimと原fenceを照合します。
旧claimは原byte／SHAを保持し、原receiptは既存nativeのLEGACY_FENCE readerで原store/headへ照合します。
原record全体と最小原期限を共通codecへ渡し、実署名後もconsumerで検証します。新namespace、鍵生成／回転／exportは行いません。
二assetの原byteをreadbackしてからReleaseを公開し、index-only branchの唯一のcurrentをbeforeOid／force=falseでCASします。
その後、認証付きcurrentと通常client共通の匿名三resource／codecを確認します。

副作用が不確定なsend、署名出力欠損、CAS後の中断はUNKNOWNとして原intentを保持します。
Release操作だけは同tag／同原byteのGETで実作用を確定した場合に限り、同claimを再開します。
正常404を未適用証明にせず、CASや未知Git objectを再送しません。空／別claimの完了fileを過去成功へ昇格しません。
通常uninstallの標準確認・停止と排他成功後は公開同意もfalseにし、pending／claim／資格／鍵は保持します。
設定、EXE署名、実収集／実公開の受入はsource・人工fixture・未署名配布候補と分けます。

ADR0454に従う開発sourceの「今すぐ公開」は同READY所有rootの
明示一回の操作です。保存済みauthority・資格・鍵だけを使い、自動公開enabledを変更しません。
最新準備headと元run/report・三原file hash・原期限を照合し、最新収集が全待機でも原成功を利用できます。
任意indexやbootstrap、破損候補から古いrunへの代替は許可しません。同control/writer/pipeline排他、
原待機・従量制拒否・5分phase・協調停止を保持します。
旧digestから証明できる完全世代prefixだけを元pinへ復元し、追加した手動完了世代の署名・claim・
全送信終端・原時間枠とcurrentを照合してからpinを進めます。旧UNKNOWNは保持し、同claim/byte/commitに
結ぶ後続VERIFIEDと全元終端で解決した場合だけ受理します。原byte改変・削除・未知schema・未解決は拒否します。

収集v7のdata bundle/active世代はpackage/通信同意と別です。非通信importは全schema/参照/原byte hashと
B1再reviewを検査し、親/固定子は同じactive原byteを使用します。別daily opt-inはpackageとworkspaceの
実directory identityへ結合し、copyでは復元しません。運用export-v3は最大課金/待機/cursor/世代と
公開参照だけを引継ぎ、private run/permit/鍵/credential/driver byteを移設しません。
元候補のprovenance本文はhash/原時刻へ射影し、元/射影hashを分けます。新原点の実検査証拠として再使用しません。
日次は既存private caller/run/buildへ進み、署名/公開を呼びません。別PCの実受入は未確認です。Taskの有限実測はリリースノートへ分けます。

DriverCrateは公式性、実取得byte、driver内容、現在端末への適用性、選択と同意、復旧準備を独立して検証します。
署名や公式配布元であることだけでは導入を許可しません。操作は[利用ガイド](user-guide.md)を参照してください。

開発sourceのADR0450では、標準INFがコピーする
driver付属program/scriptも受動DATAとして元全SDF・到達CopyINF・実hash・全CAT/member/publisherを
検査します。内容検査と独立したprogram起動許可を分け、元の未評価作用情報を保持します。
同deviceのWindows native選択、実DDInstallの全コピー/source/Windows宛先、関連kernel/service/softwareを
私有factoryで再確認した通常計画は、NewDev/SetupAPIの標準driver操作だけを持ちます。
DriverCrateが個別EXE/MSI/script/DLLを独自に起動するstepは追加しません。Windows自身による元driver宣言の
処理とvendor binary内部の作用は別であり、Display Type1や回復scriptがWindows側で実行されないという保証はしません。
独立app、Store取得、外部launcher/autorun/foreignコピーや既知firmwareを当該通常計画へ含めません。
CopyINFの独立基本INFは全内容を検査するstage用元fileで、それだけで別deviceの導入memberを生成しません。
標準圧縮sourceは同位置一意aliasとWindows非実行解凍へ結び、原/展開hash・size・来歴と有限保持量を確認します。
原CABを保持したまま所有中間aliasだけを回収し、上限を引き上げません。source/内部fixture/実機/配布物の受入は別です。

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
実測と未確認はリリースノートに分けます。

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
検索は公式metadata照会だけで、payload取得やEULA同意を含みません。Install操作は明示選択集合の実行意思です。
取得前の選択意図は実導入許可ではなく、workerの同scan私有参照・元record/targetと、検査後の唯一routeで再照合します。
未選択targetの取得、新たなdowngrade・曖昧候補の暗黙選択を拒否します。必要規約の全文・revisionに同意する前に
当該payloadを取得せず、WUAの既存EULA受諾も最終選択・明示判断の後に限ります。汎用の件数確認を重ねません。
ADR0423により、公式取得は選択時の画面内規約案内と任意全文閲覧を提供し、同scan/計画/選択集合と
原全文・revision・出典・tokenが完全一致する「同意してインストール」だけを明示同意へ結合します。
独立EULA dialogを開かず、検索・選択・閲覧だけでは同意を発行しません。欠落・差替え・旧選択・staleは停止し、
同意を永続保存しません。具体的前提の確認とWUAの既存条件は維持します。
取消し・新scan・close・失効で継続意図を破棄します。ADR 0422を正本とします。

現実装のclientはWindows一覧によるpoint実在確認を必須とし、local暦日初回の保護準備と同日再利用を区別します。
既存sequenceを新規作成と表示せず、実BEGINを所有するscopeだけが失敗・例外でもENDを一回通知します。
既管理者保護領域の固定メモは権限/実在証明ではありません。破損・読書不可ではreuse根拠に使わず、native保護が成立すれば継続します。
保存失敗は実導入結果と分け、他operationのbusyと保護未成立は拒否します。設定/頻度registryを変更しません。
ServerはSystem Restoreを呼ばず、外部backup／checkpointと復旧手順への管理者同意を要求します。
実OSと保護modeをworkerで再確認します。復元ポイントは完全backupではありません。
Server backup、VSS snapshot、hypervisor checkpointを作成・変更しません。

全選択のpreflightと直前再検証後に実行し、終了時は選択作用subsetだけを消費します。
取得、API結果、実状態、再起動、後始末を分け、Extensionの登録やbase成功を個別反映成功としません。
選択deviceの読取り専用事後確認を残し、未処理候補は次の明示操作で対象限定再検証を要求します。無条件の自動retryは行いません。

## Privacyと保存

telemetry、広告、利用追跡、自動crash uploadはありません。生Hardware／Compatible ID、instance ID、
serial、credentialをvendorや検索serviceへ送りません。契約で認める最小表示名も明示した探索範囲に限ります。
通常行・共有logへ実IDやpathを出しません。端末内詳細は画面／sessionに結合し、serial、credential、
期限付きURLの認証tokenを隠します。

通常動作に永続logは必須ではありません。共有可能な診断は時刻、version、操作・状態、Provider、件数、
進捗、result code／HRESULTに限定し、title、ID、URL、path、EULA、payloadを含めません。
保護cacheは管理者保護store、端末binding、公式起点・record・hash・parser版・時刻へ結合します。
cacheは高速化用で、探索対象や恒久的な導入許可にせず、構成・OS・parser・policy・期限等で失効します。

通常索引の本体GET省略は、新しく認証したcurrentと、既存保護headを署名・gzip/hash・schema・現在期限・attestationまで再確認した原envelopeの完全一致だけで許可します。世代だけで省略せず、原headのgeneration/hashを共通highwater verifierへ渡してrollback・同世代異manifestを拒否します。外側だけの再署名差は従来取得へ進み、破損/失効/未知rootを修復・adopt・resetせず、原期限を延長しません。HTTP中にstore排他を保持せず、同じ90秒期限と取消しを維持します。ADR0467を参照してください。

## Collectorと配布運用

現C++収集管理製品は一controller/run/所有writerの内部で最大3familyを処理します。
worker間へJSON DOMを共有せず、各MTAで所有文字列から入力を構築します。試行前24h記録と結果保存は
controllerだけが行います。429/503/Retry-After/host HOLDは次のdispatch/sendへ共有し、
終了時はUI外で全workerを協調停止・joinします。累積通信回数/取得量のquotaは設けません。
全体30分・対象時間、metadata一応答2MiB/payload一応答2GiB、schema/解析/展開上限、
原byte/hash/期限・署名・内容検査・従量制拒否・同意は維持します。
counterは観測下限とknown区分で保存し、不明な予約を実消費へ変換しません。
ADR0443の収集診断は固定allowlistの操作/段階と元32bit数値codeへ限定し、例外本文を保存しません。
native結果が未取得ならnativeError=nullを維持し、ローカル解析等の失敗codeは別のdiagnosticに残します。
転送完了とhash/CAT/INF/候補の成功を分離し、後続HTTPの開始で先行転送の確認値を消しません。
現C++ v2だけは明示setupから同user/machine/元directory identityの所有dataを更新・再installできます。
READYは旧閉programとownerの旧hash対、REMOVEDは保護root/v2 owner・解除票・dailyConsent=falseを照合し、
新閉programの全file検査後にだけ再接続します。前確認はread-only、確認後の協調停止・host/control/writer排他と
同じsetupに結ぶ局所journalを必要とし、state/成功/原待機・運用customを保持します。旧quotaだけを時間形式へ揃えます。
不明/旧Task等のrootは採用せず、通常起動/copyからの再接続・resetはありません。
中断は原/予定byteへ限定して再検査し、不確定な変更や一時fileを消去して進めません。
ADR0446の私有定義ZIPは共通ZIPのpath/重複/種別/CRC・64MiB/1025 entry検査後に、
現在user/SYSTEMの新規stageへ閉じたJSONだけを保存します。既知fileと空stageだけを解除し、未知rootを採用・再帰削除しません。
全schemaと既存source/recordの同ID内容保持・target削除拒否を確認してから、元control/writer内の定義交換へ接続します。
新source/recordのappendは原byte/hash/期限を保持し、日次期限・24h/Retry-After/HOLD・公開権限やfresh成功を発行しません。
ZIPはローカル専用で、credential/鍵/owner/state/driver本体を含めず、remote配布やZIP署名基盤は追加しません。
以下のTask/export/importの説明は旧v7等の運用記録で、現C++版の移行機能ではありません。

研究台帳、保護state、公開JSON索引を分けます。研究seedのhashは署名ではありません。
driver本体、実inventory、cookie／token、秘密鍵、保護descriptorを公開索引や可搬snapshotへ含めません。
snapshot配置だけでTask・収集を開始せず、停止export／検証／import／明示再開と元の待機・予算を維持します。
Collectorセットアップと台帳説明を参照してください。

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
実driver導入と各OS/機器の実測範囲はリリースノート、
再現方法は[テスト方針](testing.md)を参照してください。

## 認証済み個別device投影（ADR 0413）

個別device投影は公開DTOだけから発行できない。未知Classは完全なNoDriver/属性/全ID同時観測と当該Hardware exact一致が必要で、他node不足は元completed/errorへ残す。同cohort内の他deviceへの証拠転用も拒否する。標準INF検査だけに限定し、実rank/全INF-CAT/期限/同意/復元と直前再検証は維持する。

詳細はADR 0413を参照する。

## 唯一最小full-rankの固定（ADR 0414）

同INF metadataに複数Windows nodeがあっても、元完全tuple内の実最小full rankが一件なら固定できる。
先頭採用やrank推測は行わず、全有限列挙・全必要読取と正常終端を要求する。同最良同点、
直前winner/section/rankの変化は拒否する。Class、署名/hash/全INF-CAT閉包、期限/世代、同意・復元と
一device指定の境界は維持する。ADR 0414を参照する。

## 選択batch内のproof寿命（ADR 0418）

署名索引の全選択事前検証後だけ、元native proofのProvider所有を同batch終端まで維持する。
新取得は既存の不可逆閉鎖を保ち、旧resolverも新callback生成も閉じる。scopeは新scanや
明示失効を妨げず、終端・例外で元proofを解放する。過去のrecord関係を現在状態の証拠へ
昇格させず、第二自身の変化、rankの未知・曖昧性、原byte/署名/期限の失効は拒否する。
詳細はADR 0418を参照する。


833の収集setup専用起動は、標準完了画面で起動を選んだFull callerからだけ、既所有READYの自己閉programを
同session/SID/linked AuthenticationIdの実medium Explorerへ渡します。COM desktopも同PIDへ結び、
任意path/commandや別user/昇格fallbackを受けません。helperはowner/hash/停止・journalをread-only照合し、
ACL/credential/authorityや日次同意・期限を変更しません。COM受理と実host/収集/公開成功は分けます。
source/無害fixtureと実Full setupからの受入を区別します。設計はADR0483の833追補を参照してください。

ADR0483/835の公開pipeline lockは同pathのGENERIC_READ/share0で旧READ|WRITE/share0とも排他します。setupだけが元v2/本人保護store・不変fence/manifestと三排他へ結ぶroot/原activeに非継承exact0x001200A6を準備し、元owner/group/ACE順/子SDを保持します。新規native file/dirだけを本人/SYSTEM/BAの保護SDで作成し、既不変fileの置換は拒否します。disabled/無設定からcreate権を追加しません。

ADR0427/839の診断revision2は閉stage/数値だけでWUA取得と復元最終guard・実UI選択を同run/operationへ結ぶ。元URL/UpdateID/device ID/番号・日付/SID/path/credentialを出さず、既queue/slot/行容量を維持する。診断の保存失敗は導入許可・元結果・実在必須を変更しない。


ADR0485の明示復元なし続行は内部fake確認済みで、revision5配布へ反映しました。実利用者の新操作は未確認です。Provider未実行/元選択・scanと未消費routeをworkerが
証明した保護失敗だけに短命pendingを持ち、本人選択後の新operationで一回照合・消費します。原lease/期限/全hash、
同意/適用性/権限・排他を再検証し、無言fallback/永続無効設定/Server偽装を追加しません。Provider後・部分成功、
END不成立/取消し/clock不整合/busy・stale/変更選択/再送は拒否します。元失敗と復元なし事実を既匿名数値診断へ残します。
