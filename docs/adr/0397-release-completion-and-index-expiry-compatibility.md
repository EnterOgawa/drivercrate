# ADR 0397: アプリ署名を除く現行リリースの完成条件

- 日付: 2026-10-24
- 状態: 旧版互換案は利用者の後続指示により撤回。最新版だけの簡素な設計と完成条件を採用。正式リリース完了ではない。

## 最新の利用者判断（先行する契約を更新）

利用者は、現在は未提供の新規開発段階であり、旧版互換のために不要なコードを増やさず、
必要な新しい仕組みをシンプルに実装するよう明示した。したがって、旧版codecへ合わせる
配布期限短縮案と255bの互換試験は現行要件から除外する。未受入の370専用差分は保存基線から
限定除去し、元の検証結果と途中成果物を保持する。最新版のapp/collector/indexを同じ仕様で
検証する。署名・hash・原期限・端末適合性・権限・運用データ保護を弱める判断ではない。
本書は255s/255aでこの判断を正本とする完成条件へ改訂した。旧案は末尾の撤回履歴だけに残す。

2026-10-25の最新判断はADR0402を正本とする。取得できない対象は失敗/HOLDの分母と理由を
保持して後続へ送り、日次試行と週内一回程度の成功を運用目標とする。全取得先の同時fresh成功や
七日実運用を最終source/配布物確定の前提にしない。公開準備を先行し、実現在での原有効性は
必須のまま、七日超残存をprepare/sign/publishの拒否条件から外す。診断は既存run/result/bodyと
一般summaryを再利用し、privacy・待機/課金・索引署名・原byte/期限・世代下限を維持する。

## 完成条件

利用者のGoal「リリースに向けて、アプリ署名以外の全て作業を完了させること」を採用する。
除外する署名はEXEのコード署名だけであり、索引署名・固定公開鍵・hash・CAT/publisher・
INF/参照本体・端末適合性・権限の検査は維持する。全driverの実導入は利用者が不要と明示しており、
既存の実取得・INFと参照本体の内容検査方針を維持する。実導入0を記録し、未確認を成功へ数えない。
previewへ目的を縮小せず、未署名という理由だけで停止しない。

369で確認した残件から、次の有限な証拠行列へ分解する。AGENTS、ADR0379/0390/0396と
release checklistの安全境界を維持し、全過去Goal・全1,718研究record・全機器の再受入を追加しない。

| 工程 | 固定する対象と証拠 | 完成の判定 |
| --- | --- | --- |
| 255s/255a | 370差分と開始基線、現行releaseに必要な処理/旧版専用処理の区別、本契約 | 370の未受入互換差分だけを除去し、現行producer原manifest/GZipのD/R認証/lookup/acquisition/bindingを確認。不要な旧版処理の次の最小整理工程を固定し、主担当受入 |
| 255c | 最新app/collector/setupの有限な対象・期待結果を実行前固定 | 実取得とINF/本体検査、通常画面/索引接続、所有Task登録・有効readback・実行・解除/不存在を必要範囲で確認。既存Task/待機/課金/データを保持 |
| 255d | 最終公開sourceのpath/mode/byte/hash、version、README/ガイド/Release note、license/notice | 公開対象だけの閉包・秘密情報/実inventory/私有絶対path不在、説明と実装/未確認の一致、本人review用の固定一覧 |
| 255e | 同じ固定sourceを唯一のbuildへ切替、元設定/tool/input pinも保存 | fresh x64 Debug/Release ALL、必要unit/UI/Python/PowerShell、format/source/Doxygen current hashと必須/analyze、通常開発source/構成への復帰 |
| 255f | 同snapshotからapp ZIP/collector単体EXE/checksum/notice | 内容・x64 PE/manifest/緩和策・新規配置/起動/UI・hash読戻し・未署名表記を最終byteへ結合 |
| 255g | 上記行列・残る未確認と具体的source/成果物 | 本人による最終確認後、該当する明示承認の範囲で反映/tag/Release等を実行しcommit/tag/asset/checksumを読戻す。既存公開履歴を保持 |

340/S850のfresh受入、固定Intel一件の自然日次新保存、348/v6の実Task受入はそのbyte/範囲の
既存合格として保持する。最新変更へ自動継承せず、不変経路の資格は差分と根拠を記録する。
日次七回・再起動・別PCの全実受入を一律の新しい前提にはしない。検証済みと提供する操作には
該当する有限受入を結合する。versionは後段255dでresource/tag/説明/packageを統一する。
既公開sourceの0.1.0との識別には0.1.1を推奨するが、本工程で製品versionを先行変更しない。
実導入と実GitHub公開の別承認を維持する。

## 現行仕様を優先する設計境界

必要なschema/API変更は許される。旧client/旧setup/旧dataの後方互換や自動移行は前提にしない。
旧版利用者の存在を仮定した変換・分岐を増やさず、現行アプリ/collector/署名索引を同じ仕様で
検証する。Windows/機器の適合性、WUA/Driver Storeの役割、公式性・内容検査を旧版互換と混同しない。
形式名にあるv1/v2等だけを理由に削除せず、現行の役割と利用箇所で判断する。

371では370開始時の保存byte/hashから、配布attestation短縮、native親の深いcopyによる期限正規化、
全配布期限一致を要求する専用validator強化、旧codec用fixture/expectationを限定除去する。
既存367以前の現行producer/consumerは変更せず、原候補・原record・原観測の期限をそのまま保持する。
manifest期限=min(収録recordの原期限)と、各recordの原時刻/期限・最大期間・実利用時の失効検査を維持する。
各recordの期限とmanifest期限の同一化は要求しない。

私有typed観測からの投影、同runの原candidate保存/readback/hash/精算とnative親の原record完全一致、
署名型と未署名値の分離、全recordの署名用途検査、実byte/hash、CAT/publisher、端末内適合性、
expiry/antirollback・stale拒否を維持する。任意JSONを認証済み観測や実行権限へ復元しない。
候補・観測・署名を永久再利用せず、新しい発行時刻や移設で元期限/旧URLの待機を延長/解除しない。

既存運用データの待機・課金・所有者を保護する拒否処理は後方互換の提供とは区別する。
既存Taskの無断変更、運用storeの初期化、異常/不確定結果の成功扱いを簡素化の理由で行わない。
広い既存機構の整理は有限に分類してから別工程へ登録する。371では370専用差分除去を先に完了する。

## 415: 同じ現形式workspaceのpackage明示切替

413/414でP1の原dataは現producer/consumerに受理され、変換は不要と確認した。一方、
現setupの通常workspace操作は現在のpackage/seed hashと正規install receiptを先に要求する。
同じ現形式のままpackage byteを更新する正規操作がないため、255c2ptsは既存setupへ一操作
`--workspace-switch-package <workspace> <事前reviewした原workspace raw SHA-256>
--confirm-source-stopped` を加える。実装と有限検証、主担当受入、実originへの適用は分ける。

現在の自己package-v7/seed/policy全byteと通常installが発行するreceipt-v3を、既存の
native検査で認証する。切替操作はreceiptを合成・発行しない。原workspaceはstrictな
`dc-collector-explicit-workspace-v1`の六fieldだけを受理し、実raw hashを利用者が先に
reviewしたhashと照合する。旧package/seed hashはその原byteを識別する値に限り、
旧bundle/binaryの受理・実行、現在の成功や通信許可の復元に使わない。旧codec・欠損補完・
自動移行・別root/namespace・予算resetを加えない。

既存owner/三principal ACL/単一link/reparse拒否、三rootの実identity、両側origin、
初回完了descriptorと原plan、native writer lease、同child image/継承pipeをそのまま使う。
originはpackage hashを持たず三rootのpath/identityへ結合するので書き換えない。
切替時のnative admissionは履歴を再保存せず、descriptorに保存済みの履歴集合が完全に
一致しなければ拒否する。native inspectorの未回収/未知mode拒否も維持する。
monitor writerを同時に所有し、全metadata予約とdistribution run/job/requestが確定停止し、
pending/UNKNOWN_OUTCOMEがないこと、active data/原時刻/全履歴の検証を要求する。

成功時の意味差分はworkspaceの`packageManifestSha256`と`seedManifestSha256`だけである。
原workspaceの全raw byteを同root内の既知`package-switches/<原SHA-256>.json`へ
CREATE_NEW/flush保存し、新workspaceの固定`workspace.pending.json`をflushした後だけ
同volumeでatomic置換する。原archiveは上書きせず、同じ原hashの再適用を拒否する。
通常validateは有限なarchive集合の名前/hash/strict schemaを検証して受理する。未知fileや
中断pendingは拒否し、原archive/部分fileを自動削除・rollback・再適用しない。
失敗/中断でも原workspaceまたは置換後workspaceと原archiveを保持し、結果は元exitと
原hash/新hashへ結ぶ。成功のstdoutを取得し損ねても現在byteの実検証なしに成功扱いしない。

切替は通信許可/日次同意/Taskを発行せず、原origin/key/ledger/run/課金/待機/expiryは全byte
不変とする。通常package lifecycleでは新しい自己所有配置へ正規installし、そのreceiptと
全byteを検証してから、停止済みの同workspaceを明示切替する。既存配置の上書き更新や
旧Taskのadoptは提供しない。切替先packageに対する明示実行/日次同意は従来の別操作である。
未確定保存窓は所有者による別reviewを要し、切替だけを自動回復・通信許可の入口にしない。

415は人工所有root/fakeの非通信試験と影響build/品質だけを扱う。P1実originの切替、
正規install/Task/実取得、独立根拠の再確認、最終source/fresh配布物は後続へ残す。
原独立review時刻2026-10-24T02:44:54ZとNov1上限を付け替えず、週次七日残期間不足を
本操作で解消したとは表現しない。411配布物のbyte資格は本変更へ自動継承しない。

## 371の有限受入

中断時process/handleを確認し、原FAIL・370途中成果物と主担当の最新指示記録を保持する。
同じ唯一buildで影響targetのx64 D/Rを確認する。現行のA+B追加・既存B更新について、元B1の
確認待ちimport→別review→CURRENT import、通常実INF parserのmode29/12、原A/B期限、
旧URL24h待機/課金を維持し、同producerの原manifest/GZipから通常アプリRAM認証/reader/
lookup/acquisition/bindingの153 assertionと必要最小codec/Python・変更品質を確認する。
旧consumer互換試験や旧codecのcompile/linkは実行しない。

immutable通常fileのFILE_READ_DATA、directoryのFILE_LIST_DIRECTORY、mutable access、三directory pin、
子終端までlease、同child/pipe/proof/private permitを維持する。32job/64要求/32MiB/600秒・16MiB JSON・
24h・native共有HOLDを変えない。実HTTP/WUA/inventory/Task/運用store/永続鍵/trust/本番署名/導入/
復元/Git操作/公開は本工程で開始しない。fresh公開snapshot/最終EXE生成は後段に残す。

## 373: 現行形式だけの生成・受理と入口整理

255spは未提供の旧版を互換対象にせず、次の有限集合へ揃える。版名の変更だけを目的とする
renumberや変換層は追加しない。実装と検証は255s3～s6/spt、主担当受入は255spvに分ける。

- monitorの停止exportはdistributionなしのexport-v1と、公開参照/portable-historyを持つ
  export-v3を生成・受理する。生成されないprivate export-v2はschemaで拒否する。
  v3は私有run/typed観測/candidate headを輸出せず、元hash・期限・最大予約・待機課金と停止同意を保持する。
- collector packageは`dc-collector-package-v7` / `EXPLICIT_DISTRIBUTION_DATA_DAILY`だけを
  生成・受理し、配置receiptは`dc-collector-install-receipt-v3`だけを扱う。
  v1～v6 packageとreceipt-v1/v2の成功分岐、旧package builderのmode指定、固定local-index専用の
  setup公開入口を廃止する。現在のv7へ自動変換しない。未知/旧packageやreceiptは変更/削除せず拒否する。
  旧Daily229をv6 local-indexへ切り替える`UpdateDisabledLocalAction`専用cutoverと、そのconsumer/
  success fixtureも255s4aで除去する。現在必要な手動署名/公開用Task管理は維持する。
  callerのない旧Daily229/Smoke229所有解除module/APIと専用fixture/targetは255s4bで廃止する。
  現行`collector_user_task`の旧管理者receipt混在拒否は保持し、旧Taskの照会/解除へ分岐しない。
  Taskの現行distribution action/plan/ownerだけを発行し、旧Taskをadoptしない。旧名Taskの不存在確認は
  安全なuninstallと所有保護のため保持し、両名の不存在を確認できる前に管理fileを削除しない。
- distribution journalのjobは現producerが保存する候補三fieldを含む厳密な`JOB_FIELDS`だけを
  受理する。不明/欠損fieldをfresh履歴や空ledgerへ変換しない。保存窓/不確定予約回復・元課金/待機を
  維持し、公開JSONから私有typed観測やpermitを復元しない。
- 旧app共用storeを移動する専用EXCLUDE_FROM_ALL tool、移動API・実装・移動専用trustと
  成功fixtureを廃止する。通常appは現在の固定trust domainを使い、既存の未知root/旧共用rootを
  fail-closedで拒否する。旧storeを移動/削除/resetする代替入口は設けない。

固定native取得primitive、metadata-only monitor、現役のmanifest/envelope-v1、metadata record-v1と
acquisition record-v2、通常appのdistribution/local trust分離は現行callerの責務なので保持する。
v7の保護workspace/署名/lease/汎用distributionで使う処理を旧版番号だけで削除しない。
同I/O/proof/private permit、同child/image/pipe peer、三directory pin・子終端までlease、原byte/hash・
high-water/rollback・元expiryと32job/64要求/32MiB/600秒・16MiB JSON・24h/native共有HOLDは維持する。

実HTTP/DNS/WUA/inventory、実Task、運用store、永続鍵/trust、本番署名、実導入/復元、Git反映/公開は
373で行わない。自己所有file/process/IPCとfake Task/RAM cryptoで現producer/new consumerを検証する。
最新実動作受入とversion/最終source/fresh snapshot/配布物/最終承認は255c～gへ残す。

## 375: 研究観測時点と実通信待機の責務分離

255cの固定P1では、既登録recordに旧root本文hashがなく、現在の公式PAGE観測を補うと
汎用pipelineが`pageObservation.checkedAt + 24h`だけを理由に初回取得を止めた。
研究PAGE観測は手動確認の根拠時点であり、保護journalのHTTP予約・精算recordではない。
この二つを混同する待機を255ct2で除去し、現行の保護state/journal/native admissionに記録された
actual attempt/nextDueAtを通信待機の正本とする。これは既存の実通信待機を短縮する変更ではない。

研究観測の原hash・原時点、将来時刻拒否、公式PAGE/anchorの同run再確認と期限を保持する。
研究日時だけを通信許可・取得成功・private PAGE proofへ変換しない。実request rowがある場合は
旧URL/hostのnextDueAt、HOLD、native共有scope、未確定予約の最大課金と元予算を維持する。
rowの欠損/腐敗をfreshへ補正せず、新root/import/新profile revisionで履歴をresetしない。
現役metadata monitorにも同じ混同がある場合だけ整合させ、過去report/履歴のbyteは変更しない。

手動researchの実GETとcollectorの実GETは、PLANの有限予算へ別の操作として記録する。
初回のfresh研究観測＋actual ledgerなし、actual prior-requestの24h拒否、hostHOLD/未知clock/
不確定最大課金を決定的に検証する。同runの実HTTP・hash/INF/CAT/publisher/参照本体を経ない
索引生成を認めない。32job/64要求/32MiB/600秒・16MiB JSON等と実導入/公開の別承認は不変。

変更後のpackageを実受入する場合、旧自己所有配置は旧setupの通常uninstallで両Task不存在を
確認して管理fileだけ解除し、data/元ledgerを保持する。新byteと新しい自己所有rootを実行前に
PLAN追補する。旧packageの成功を新byteへ継承せず、主担当255cvは未完了へ残す。

## 375: distribution Task Actionの保護親検査

v7のdistribution Actionは導入root直下の`DriverCrateCollectorSetup.exe`である。
初回実opt-inで、Action fileの親に継承child ACLを要求する共通helperが、正しいprotected-root
DACLを`WORKSPACE_CHILD_ACE`として拒否した。native Actionの`bin`親とは実際の役割が異なる。
255ct4は呼出し元が明示したprotected-root親に既存の完全protected descriptor predicateを使い、
通常fileは既存の継承三principal/単一link/実path/読取pinを維持する。既存ACLの修復や、
root/child双方を曖昧に許すfallbackを追加しない。両Taskの所有XML/SDDL/非実行と不存在確認は不変。

## 375: 未登録の任意distribution Taskの不存在確認

通常v7 installはnative Taskだけを作り、distribution Taskは別の明示opt-inで作る。
実解除では、未opt-inまたはplan保存前に拒否されたdistributionについてもplanを必須とする
共通解除処理が`USER_TASK_UNINSTALL_OWNERSHIP`で停止した。先に解除されたnative Taskと
全program/dataは保持されている。255ct5はplan/ownerが共にない場合に、配置receipt-v3で
結合した現在SID/root/manifestから導出した固定Task名の正常不存在だけを確認して0件解除とする。
同名が存在する、ownerだけある、取得拒否/UNKNOWNの場合は変更せず停止する。未所有Taskを
削除する権限や旧Taskを扱う経路は増やさない。両名不存在後だけ管理fileを削除する順序は維持する。

## 377: 同一native閉包へ結ぶflat/一段nested identity

255ct8iは375の実取得成功とnested投影0を受け、現行app/collector/indexの公開identityを
同じ10fieldへ揃える。`publishedIdentityEvidence.nestedArchiveIdentity`を必須文字列とし、
flatとUNKNOWNでは明示空、一段nestedではouter内のslash区切り相対archive memberとする。
field欠損、未知/重複field、null、unsafe memberは拒否する。旧reader/変換/欠損補完を追加しない。
`infIdentity`はflatではouter内、nestedではその一つのarchive内の相対INF memberである。
一段nested以外へ連鎖するselectorは設けない。nested memberはZIP/CAB suffixだけを許す。

member文法は`OfficialDownloadWorkspace`の既存安全検証を小さい非I/O共通predicateとして公開し、
nativeのbackslashと公開identityのslashという明示区切りだけを指定する。ASCII通常文字、
160文字全体/96文字component、Windows禁止文字/予約device名、空/dot/parent/末尾dot・空白・
absolute/別区切りの拒否を共有する。大文字小文字や内容を正規化せず、`+`や空白等の通常名も
同じ規則で扱う。公開文字列からworkspaceやfilesystem pathを構築しない。

archive memberは原caseも含む完全なidentityとして比較する。native/codecのASCII制限を
維持し、Unicode memberを今回追加しない。ClassGUID/Models節/PnP IDはWindows ordinalの
case非依存規則で比較する。公開PnPは原ASCIIの大小文字を保持して受理し、重複判定用keyだけ
大文字化する。kind付きcase alias重複を拒否し、同じ等価規則でnative全ID集合へ一致させる。
原record byteや証拠hashを再serialize/正規化せず、端末resolverにも既存のcase非依存keyを使う。

producerはouter原SHA-256/size、nested member、INF member/原SHA-256、Models節、ClassGUIDと
種別付き公開PnP全集合を同じ通常native検査から投影する。mapの一意性とrecordIdはnested/INF
memberを含め、別memberの同名/同内容INFを混同しない。署名者一意性、全ID上限/64KiB record、
16MiB候補、現OSだけのModels選択と原期限を維持する。nestedの一律保留だけを解除する。
通常Python保存/assembleと共通未署名codec、明示署名用validatorもこの現行契約を用いる。
投影JSONは認証済み観測・実行permit・端末適合性にはならない。

appは元認証lookupのrelationIndexからrecordIndexへ戻り、outer実hash/sizeと同owned native
INFのnested/INF member、現HINFから再読取りした原hash/Models/Class/公開PnP集合の完全一致を
確認したrecordだけへrankとtokenを結ぶ。同target/deviceの先頭Referenceへ丸めず、複数recordを
保持する。取得targetは従来の同payloadで共有でき、device hintはdevice単位で重複除去する。
同owned workspace/closure/infOrdinal、全INF直前再検査と指定導入の同tokenを維持する。

外側の期待hash/sizeが未提示でも、それだけで通常公式driverを対象外にはしない。
署名索引の当該原recordSha256へ同一private grant/seal/hintが結合した実取得hash/sizeを使える。
期待値がある場合は全て照合し、不足があるrecordはその同PreparedRecordの元record hashとの
完全一致を追加要求する。未知期待値の別recordへ同payload扱いの実byteを貸与しない。
汎用producerは実計算outer hash/sizeを常に投影する。公開JSONを私有sealへ復元せず、
メーカー公表hashと収集者計算hashを区別し、identity不一致を不適合やdriverなしへ読み替えない。

255ct8tはflat/nested正例と同名・同hash別member/各tuple差・unsafe/欠損/未知/重複selector拒否、
現producer原manifest/GZip→unsigned共通codec→RAM認証/reader/lookup/acquisition/bindingを
決定的に確認する。既存private mode29/12の通常parserを使い、成功DTOのshortcutへ戻さない。
保存実ZIPのLOCAL通常CAT/全参照本体検査は、新GETやfresh PAGE proofとは区別する。
元P1 runは終了済みでauthorityをJSONから復元しない。元actual nextDueAtとHOLD/課金を保持し、
追加HTTP/DNS/WUA/inventory/実Task/運用store/永続鍵/本番署名/導入/復元/Git/公開0。
P1のfresh実collector候補生成、A1のPublic正例、最終source/fresh ALL/配布物は後段未確認である。

### 377: 同payloadの原relation集合とdevice数

通常multi回帰は完全なINF tupleへ直した結果、既存adapterが異なるdeviceのrelationだけを
共有し、relation数をdeviceCountへ流用していたため原正例2/33/128-INFでFAIL15となった。
255ct8igは同じ既知outer hash/sizeと全取得descriptor/公式主体/policy/期限が一致した原relationを
一つの取得targetへ保持し、deviceCountはその集合のunique device数だけを表す。
relation集合は既存lookupの32768枠内、deviceは32、native INFは128、pairとcandidate routeは4096、
targetは256という別々の既存上限を維持する。原relationを別のrecordへ置換せず、同deviceの
複数record/公開ID関係をそれぞれ元位置で保持する。UNKNOWN outerの別record共有は許さない。

describe時とclaim/inspection入力発行時に各元relationのcontext/source/recordId/recordSha256/公開ID・
独立取得認可・原期限を再検証する。集合の重複位置、unique device数、代表との全共有policy一致も
再確認し、一部の一致から全groupの権限を作らない。同payload一回取得後もnative HINFと完全tupleの
結合は各原recordについて独立に行う。原FAIL15を保持し、33/128-INFと偽target/原改変/失効拒否を
通常adapter→plan→claim→bindingで有限に確認する。HTTP等の実外部操作は追加しない。

同device複数recordは監査reportの既表示参照行も複数になる。共通validatorは行数をdevice数へ
置換せず、既表示の原行ごとのProvider/一意ID/監査状態を全件検査し、全report合計4096行枠を
維持する。targetの作用device上限にはそれらのunique device数を照合する。新deviceや未知行を
作る権限を追加しない。これにより通常UIにも各INF/recordの独立候補を反映できる。
複数独立taskの予算/例外fixtureは同payload複製だけへ依存せず、異なる明示payload routeで
独立取得条件を表す。正例候補数や取消し/失効/部分失敗の検証を減らさず、原FAILを保持する。

32768原relationを保持しても、完全tuple一致後の原record候補pairがnative rank/tokenへ進める
件数は一取得4096枠内とする。共有relation数を実発行枠へ昇格せず、native観測前とglobal route/token
作成前にも既存4096上限を確認する。device32/INF128によるnative組合せ上限も独立に維持する。

## 379: 汎用候補の世代確定と手動production署名への接続

255d0は既存`daily_index_pipeline.py`へ明示`prepare-candidate`と`sign-candidate`を追加する。
既存Public設定の保護runtime/tool hash/固定公開fingerprintと、同じ`outputRoot/pipeline.lock`を使う。
新signer、秘密鍵操作の代替、通常appの設定やProviderは追加しない。通常日次Taskと
`collector_distribution_pipeline::run_once/build_candidate`は未署名候補までで、署名/公開を呼ばない。

prepareはoperatorが明示pinしたcandidate-headとその固定runの原index/GZip/manifest/report/provenanceを
hash照合する。これらは未署名dataであり、monitorIdentityやvalidatedラベルを私有観測/permitへ復元しない。
全recordの`recordBytesBase64/recordSha256`、sources、原checkedAt/validUntilと元reportは変更しない。
未署名仮generationを配布世代へ採用せず、下記下限の最大値+1を整数上限9007199254740991以内で選ぶ。
新assetGenerationとmanifest両generation、決定的GZip、そのhash/size/tagを同一prepareで作る。
publishedAtだけをprepare実時刻へ更新し、expiresAtは全原record期限のminへ完全一致させる。
各record期限をmanifest期限へ同一化、延長、短縮しない。空/期限切れ/未知recordは既存native unsigned
validatorで拒否し、元候補と失敗分母を保持する。

世代下限は次の既存責務を使う。

- 固定Public repository/currentは既存Publisherのread-only取得/identity確認を使う。
  metadata-onlyまたはacquisitionという明示profileの既存native history検証を一度だけ行う。
  profileの自動fallbackはしない。原署名・manifest・GZip/hash/size・全recordと署名発行秒/現在UTCの
  順序を認証し、expired currentは歴史世代下限にだけ使う。現在利用receipt/grantは出さない。
  head不明/404/欠損/署名不正を初回0へ戻さない。sign直前にも同currentを再取得・認証する。
- operatorがpinした現在のlocal daily receiptは既存native
  `--verify-daily-reservation ... LEGACY_FENCE`で保護counter/同run/原byteと完全一致させる。
  daily-generation-v1は元実観測の予約なので、汎用候補のreceiptへ書き換えない。
- 同じ保護公開rootの既存`issuance-v1-*.claim.json`を最大4096件の閉schemaで検査する。
  固定scopeの現役claimも汎用claimも、未署名予約・署名失敗/不確定・署名済未公開を区別せず
  世代を消費する。不正/未知/部分fileはfreshへ直さず拒否する。下限は署名/取得権限ではない。
  固定scopeの既存callerも同lock/同claim名を使うため、汎用予約と同世代の別bodyを上書きできない。

新汎用claimはunsignedの不変prepare意図で、原入力hash/候補出力hash、認証したPublic head/commit、
local receipt、選んだ世代/時刻/出力hashを固定する。claimを先にCREATE_NEW/flush/readbackし、その後
固定名へ出力する。prepare途中停止は同claim/同byteだけを補完し、世代を巻き戻さない。
同世代異body、元record改変、出力改変、未来/不明時計、overflowを拒否する。

signはclaimの原byte hashと公開fingerprintをoperatorが明示した独立操作とする。
現在config/tool pin、candidate原byte、Public current、local counter/全claim下限、原期限と
native unsigned検査を再確認する。署名意図を新規保存後、固定native exeの構造化argvで既存
`--distribution-acquisition-sign rawManifest gzip envelope fingerprint`だけを一回呼ぶ。
署名器自身の固定配布鍵・保護・purpose・全record・署名/hash/size/期限検査を省かない。
原manifestと返却envelope内manifestのbyte完全一致を確認し、既存current acquisition verifyも行う。
child exit0/原envelope hash/公開検証結果を保存した場合だけSIGNED_NOT_PUBLISHEDとする。
署名意図後の例外/非zero/結果保存前停止は不確定のまま保持し、再署名しない。
再開は保存済みの同envelopeの原manifest完全一致とnative current再検証だけとし、JSONのsuccessラベル
単独では認証しない。署名返却後→verify/結果保存前の中断、verify一時失敗、child非zeroでも完全な
同envelopeがある場合は、再署名0で署名artifactだけを認証し直せる。原UNKNOWN/child非zeroの
結果fileは上書きせず、結果欠損はoriginal exit不明のまま保存する。artifactの検証合格と元署名operationの
成功/失敗/不明を別fieldにする。保存envelopeなし、部分/別body/誤署名/失効/下限変更は拒否する。
GitHub write/upload/CASへの接続はこの二操作へ含めない。

255d0tはfake remote/native reservation/signと自己所有file、現producer flat/nested/複数record、
既存共通codec/RAM署名で原byte/各期限保持・下限/衝突・誤key/purpose・失効・部分停止/再開を検証する。
実運用root、実HTTP/DNS/WUA/inventory/Task、永続鍵照会/作成、production署名/公開/導入は0。
既存expired Publicの現在利用拒否とP1 actual待機は維持し、通常appの正例と最終公開受入へ換算しない。

## 381: 現行製品版・公開向け説明と配布seed

255d1では、既公開sourceの0.1.0と現行仕様を識別する製品版を**0.1.1**に確定する。
CMake project versionを正本とし、VERSIONINFO/UI、アプリmanifestのassemblyIdentity、配布builderの
既定値、利用例とRelease noteを一致させる。独立file版XX.YY.ZZ、旧ADR・実測・配布物の履歴は変更しない。
この版採番は最終公開snapshotのfresh build・最終配布物・本人確認や公開の完了を意味しない。

Public向けREADME/guideは現行v7/receipt-v3の操作を正本とする。通常installのnative15時Task、
別同意distribution17時Task、通常解除/両Task正常不存在後の管理file削除とdata保持を説明する。
379の手動prepare/sign接続と通常Taskの未署名候補までを区別し、署名・公開を自動化したと記載しない。
旧版互換/移行/変換を新設せず、所有不明の旧Task/root・元待機課金と原期限を保持する。
375の実Task有効読戻し/同Action直接実行/通常解除の有限成功はそのbyteだけの実績とする。
最終byteでの再受入、fresh Public通常画面正例、v7自然trigger/七日/別PC/実導入は未確認へ残す。

配布seedは375で手動確認した既存Prolific一record/七製品参照のPAGE観測7・locator2・profile1を
通常のdata訂正として取り込む。元三JSONの原byte/hashを照合して差分を限定し、既存研究record・
製品・メーカーの追加/削除/意味変更を行わない。既存payload取得証拠は通常carry-forwardで新台帳へ
再結合し、元row/取得時刻/hash/originを保持する。driver本体/raw PAGE/私有state/ledgerは配布しない。
研究127メーカー/6,584製品参照/1,718record、収集profile1と実内容検査/実device適合/実導入を
別の単位で報告する。通常アプリに署名配布索引は同梱せず、取得時に署名/hash/世代/期限を再検証する。
P1の元run投影0とactual nextDueAt=2026-10-25T03:21:15Zは保持し、新seedをfresh実投影成功へ換算しない。

## 383: 現行複数source集合と明示手動公開

255d2pは既登録A1 IntelとP1 Prolificの有限集合だけを扱う。汎用collectorは同journalの
未失効candidateをsource/record単位で保持できるが、固定Intelのnative日次六入力は別経路である。
native receiptは世代下限であってIntel recordを作らない。prepareに明示pinした六入力documentを
任意で渡し、既存`project_daily_distribution_acquisition`で非I/O投影して汎用headと合成する。
六入力はscope/evidence/release/inspection/review/scriptの原file/hashを閉schemaで指定し、
scopeとreceiptは現在config/明示reservationに完全一致させる。JSONからtyped私有観測/permitを
復元せず、全recordは既存unsigned codecで再検査する。取得や検査の再実行はしない。
sourceId衝突はsource原値完全一致、recordのsourceId/recordId衝突は拒否する。
既存の純粋な六入力auditも使い、embedded原byteのpin/privacy/現在期限とreviewの既存1MiB上限を維持する。
base64/hash/原record/checkedAt/各validUntilを保持し、manifest期限は原期限minに限る。
署名済Publicや期限切れrecordを現在候補へ持ち越さない。

保存済み実Public世代5の原manifest/GZipは必須10field追加前のrecordである。現readerの旧形式
互換を設けず、`HISTORY_FLOOR`を明示した世代下限専用のnative検証を追加する。
既存manifestの署名/固定repo/channel/key/全世代/署名発行秒と現在UTC、asset原hash/sizeと
有限GZipを認証し、record schema/意味は評価しない。結果は非秘密の下限数値と診断だけで、
認証済record、取得/導入grant、保護store更新、現在利用receiptを出さない。
未来/未知時計/誤署名/別repository/改変/欠損を拒否する。history専用の原発行時点照合を
current利用の時計変更へ転用しない。従来の全record履歴検査も別modeとして維持する。

同じpipelineに明示`publish-candidate`を接続する。固定claim/hash/fingerprintと原head/六入力、
現在native reservation/全local claim/Public下限、保存ready/signing intent/envelopeと原manifestを
再確認し、既存native current検証後だけ既存Publisherへ渡す。署名器、counter、authority層を
追加せず、通常Taskへ署名/公開を追加しない。公開操作は再収集/再署名を呼ばない。
Public currentが保存bundleと同byteなら再公開writeをせず既存readback経路を使う。
それ以外はprepare時のhead完全一致を必須とし、直前にも検査して既存CASを使う。
CAS前に不変intentを保存し、不確定再開ではreadback_onlyだけを許す。部分assetは同byteだけを
既存Publisherで補完できる。manual publishの履歴認証はfloor専用入口へ固定する。prepare時の
profile名は照合の役割だけをfloorへ揃え、原commit/全hash/世代の比較を省略しない。
現在の候補は全record検査のままである。匿名原byte確認を同じ有限PublicOperationBudgetへ結合し、元UNKNOWN/
非zero/失敗terminalを上書きしない。署名artifactの現認証と元署名operation成功は区別する。

検証は人工A1/P1・flat/nested・原複数source→世代確定→RAM/署名代役→fake Publisher→匿名
readback→通常appを有限に行う。保存実Public原byteのfloor成功とcurrent失効拒否を別に確認する。
実運用のfresh Intel/P1集合・本番署名/公開・P1待機後fresh投影と実PC適合は未確認へ残す。
実追加HTTPは保存byte不足時だけ最大5resource/16MiBの固定公開索引readに限る。
元P1 actual待機/運用data/全世代下限と実公開/導入の承認境界を維持する。

通常app fixtureの追加native一recordは、原package/INF hashを小型架空ZIPへ付け替えず未照合に保つ。
同集合の全record codec/保存と元三架空deviceのlookup/取得/照合は確認するが、追加native行自身の
lookup/取得/binding正例は未証明である。四行parseをA1 Intelのapp接続成功としない。
主担当d2pvでこの残件と実Public A1/c2aの範囲を確認し、必要なら最終source固定前の別有限工程にする。

## 385: 元Intel archiveの明示historical replayと内部native署名接続

`intel-wired-31-2-2-win11` の元保存archiveは40,477,087B、SHA-256
`2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5`。
元選択 `PRO2500/Winx64/W11/e2fn.inf` は102,405B、SHA-256
`a93fa3c2b8725aed2081e0d239766474fac205f75ddbe16849502af6acba2417` で、
原inspectionの二Models/選択Models全22 Hardware ID/Class GUIDと元recordが一致する。
383の人工native行は架空の一IDであり、実archiveの完全tupleへ結ぶ成功ではない。

六原入力の元publicationは2026-10-18T16:32:04Z、元期限は2026-10-19T13:24:11Z。
現UTCで失効する原観測をfreshへ再発行しない。現producerへ六原byteと元publication秒を
明示した非運用historical replayだけを作り、原recordの全field/期限を保持する。
現producer必須のflat用 `nestedArchiveIdentity` 空fieldは通常producerが付与する。
旧record reader互換/期限延長/運用保存/私有観測やgrantの復元は追加しない。
RAM隔離署名・fake clock/HTTP/deviceと実package検査を分け、現在UTCの失効拒否も確認する。

通常workerはinventory低位fixtureと署名fixtureの両方を必須とし、片方だけのnative混在を拒否する。
このguardを変更せず、既存内部 `ScopedFixture` に引数なしのnative署名用factoryを追加する。
同thread所有scopeから、既存productionの実 `SetupVerifyInfFileW` とCAT memberの実
`WinVerifyTrust` へ引数/返却値をそのまま委譲する。whole-chain/chain-exclude-root/revocation/
policyを含む既存検証を変更せず、cache-only専用APIや署名検証のcopyを増やさない。
署名者/hash/member/publisher成功を人工値へ補完せず、現policy・OS trustを変更しない。
任意の成功bool/鍵/公開JSONを受けず、署名factoryは索引認証/取得/適用性/導入能力を発行しない。
従来の人工file/hash固定factoryと製品の通常native dispatchは維持する。

通常app用の明示一件modeでは元archive全byteをfake HTTPで返し、既存native authority factory、
同owned workspace、opaque token、原record完全tuple・全22ID、直前再検証へ通す。
fake Windows inventory/rankは元公開IDから明示した一deviceだけで、実PC適合とは数えない。
元archiveの72INF全行は成功/個別拒否を分母へ保持し、元選択INFのbindingだけを正例対象とする。
実driver導入/復旧/明示driver HTTP/任意検索/WUA/実inventory/Task/鍵/本番署名/公開は行わない。
2026-10-24の主担当追加許可により、標準署名APIが必要とする証明書等の読取通信は許可する。
実OS時計/trust/policyは変更しない。証明書通信の件数を観測しなければ不明とし、総network0とは報告しない。

385の有限実行では最新sourceのDebug/Releaseで各四条件が成功した。元archive/全22IDの一件は
通常lookup/規約同意/取得/実INF・CAT/全参照本体/完全tuple/opaque bindingを通り、候補一件を発行した。
誤byteは取得境界、同意欠落はpayload前、21ID欠損copyは同内容検査後の完全tupleで拒否した。
全72INF中57内容合格/15構造拒否（各0x80070032）とpairの二失敗を保持し、選択e2fnの実署名者と
SYS/DLL二本を個別確認した。現在UTCと原期限秒の拒否、元120file不変、通常構成を維持した。
このhistorical有限正例をfresh実収集/実Public/実PC適合/実導入へ換算せず、親工程は未完了に残す。

## 387: 発行fresh窓と今後の配布record有効期間

実装確認の結果、native取得recordは原観測+1日、汎用取得recordは内容/PAGE/独立根拠の原時刻+7日の
最小値だった。日次収集・週次公開ではnativeが先に失効し、汎用も発行までの経過分だけ7日を割る。
発行に使える観測の新しさ、配布recordの有効期間、実HTTPの24h待機を別の契約として整合する。

- 今後、新しいfresh観測から作る配布取得recordの期間は8日とする。7日の更新間隔と24h未満の
  発行fresh窓を合わせた有限値であり、無期限cacheや期限後の利用猶予を追加しない。
- nativeの配布scopeは既存`projectionPolicyRevision=2`だけを新規発行へ受理する。rev1を変換/受理せず、
  原六入力や旧recordを新しい発行時刻で救済しない。元receiptのvalidated <= now < validated+24h、
  内容/規約/script/body/hash、原世代とnotBeforeを維持し、期限は原observed+8日とする。
  metadata/受入専用の従来1日投影は配布用途と分離したまま維持する。
- 汎用producerは新typed PAGE/内容検査の24h未満のfresh条件を明示し、
  min(内容checked+8日、同PAGE observed+8日、四独立根拠の原時刻+8日)を新recordに記録する。
  同じtyped観測を後日のbuild時刻でfreshへ置き換えず、独立根拠の原時刻も更新しない。
- 端末のattestation期間上限は8日へ揃える。manifest最大14日、現在UTC、原hash/実byte、CAT/publisher、
  完全INF tuple、適用性、同意、復旧、世代下限と役割別trustは維持する。
- 2026-10-25のADR0402により、週次更新を覆う七日超の残存期間は運用目標へ変更する。
  prepare/sign/publishは全原recordのhash/期限minとmanifest発行時刻 <= 実now < 期限minを要求し、
  残存七日以下でも原期限内なら扱う。新規署名前・公開前・CAS直前にも実現在で再検査する。
  期限到達や不明時計は拒否し、短いrecordの任意除外・期限延長・原観測の更新で成功扱いしない。
  preflightは収集・再署名を起動せず、不確定意図と原失敗terminalを保持する。
  既存署名artifactとCAS意図後/既存同byte currentのreadback-onlyも、原期限内の署名/全record/
  匿名原byte検査を維持する。新発行のfresh窓と保存済み旧成功の保持を区別する。

既存raw record/署名束/個別期限は書換えない。merge/rebaseは原wrapper/base64/hash/sourceと各期限を保持し、
manifest期限=min(収録原期限)のままとする。署名済み旧Public世代5は期限切れのままで、下限認証の成功を
現在利用へ昇格しない。旧六入力の現在発行拒否と、保存済み旧recordの原期限での拒否を別に検査する。
通常Taskは未署名候補まで、署名と公開は明示手動を維持する。自動sign/publish、旧client互換、
新authority/counter/framework、実HTTP待機/課金resetは追加しない。

## 387: 公開集合の入力と任意QAの出力

公開sourceに私有workの具体的な日付pathを含めない。ignoreは`work/`へ集約し、既存tracked履歴や
実fileを移動・削除しない。任意のmaintenance reference QAの出力rootは既存buildの
`test-scratch/maintenance-{reached,residual}-reference-<CONFIG>`へ分離する。
archive等の入力は従来どおり明示し、所有/祖先/CREATE_NEWの境界を維持する。追加build treeは作らない。
この任意QAを通常の必須試験や新しい実package受入へ追加しない。

## 391: 必須解析のWindows SDK境界とsource revision

387の固定sourceからの初回MSVC解析は、13 translation unitでWindows SDK 10.0.26100の
WindowsNumerics.inlにあるC28252/C28253/C6101と、`/WX`によるC2220で停止した。
初回156診断に自作source locationはなく、共通headerから先にwinrt/base.hを展開するため
従来の一部CPP内のSDK局所pragmaより前に到達することを確認した。原失敗は保持する。

AGENTS第12.3節のSDK header限定例外に従い、CMakeのanalyze ON分岐だけで選定SDKの
Include rootはCMAKE_MTの実SDK version directoryから求め、
WindowsNumerics.inlとcppwinrt/base.hの存在、source/buildとの相互非包含を必須確認する。
そのroot直下の実toolchain INCLUDEに存在するucrt/um/shared/winrt/cppwinrtだけを、元の順序で
`/external:I`へ指定する。親root自体をinclude検索へ追加しない。親rootを追加したrevision1では
`<winrt/Windows.Data.Json.h>`がcppwinrt projectionより先にSDK winrtのABI headerへ解決され、
原ALL解析が構文拒否した。この原失敗/revisionを保持し、revision2でleaf限定へ訂正する。
SDK正例には実Json型とcollection headerも含め、header選択を確認する。
`/external:W4`で通常warningを維持し、`/external:templates-`で自作側のtemplate境界も保持した上で
`/analyze:external-`をSDK headerへ限定する。自作sourceとproject/generated headerには
`/analyze`、`/W4`、`/WX`を維持する。全includeや環境INCLUDEの包括的external指定は使わない。
意味はMicrosoftの[/analyze](https://learn.microsoft.com/en-us/cpp/build/reference/analyze-code-analysis)と
[/external](https://learn.microsoft.com/en-us/cpp/build/reference/external-external-headers-diagnostics)を参照する。

自作C++、通常OFFのflags/target/source集合、配布schema/API、原期限/署名/適用性の変更は行わない。
SDK正例と、故意の自作CPP・自作project header・自作generated headerの解析違反を同じ実flagsで
非zero拒否する四制御を行う。制御用の違反sourceは実行せず、自己所有の検証出力へだけ置く。
通常OFFの前後集合を比較し、原150件の成功を保持した上で新revisionのfresh D/R ALL、必須解析、
影響するbuild-profile/閉包/品質と代表試験を確認する。原150件を新revisionで全再実行したとは記述しない。
387の874入力集合は上書きせず、変更したCMake/本契約を含む明示新revisionへ再固定する。

revision2のSDK診断通過後、INF依存native adapterの不在候補分岐でNativeError（int32_t）と
HRESULT型の比較二件にC6221が露出した。比較先のFILE/PATH_NOT_FOUND HRESULT値だけを
NativeErrorへ明示変換し、CreateFile直後のfileMissing観測と二値の完全一致を維持する。
FAILED一般化によって権限・競合・reparse等を不在へ広げず、元HRESULT/byte境界を保持する。
当該CPPの版履歴・format/規約・Doxygenと影響INF native試験を別に確認する。
既存native API matrix46/flagなし不在・権限/reparse拒否を保持し、同fixtureの実openに対する
親ありfile不在と親なしpath不在の二条件だけを追加する。fixtureの親有無と元Win32不在を
事前に観測し、全体成功でも参照未解決・署名/導入許可なしのままであることを確認する。
既存試験fileを含む四file差分のrevision3へ再固定する。原revision2のC6221/exit1は保持する。
revision3の追加試験でWin32期待値とDWORDの比較に出たC4389も保持し、期待値だけの
DWORD明示変換をrevision4へ再固定する。製品側の二HRESULT値/不在条件は変更しない。

## 393: 自作sourceと試験の必須解析対処

revision4の実ALL解析で残った自作source/試験の警告を、全体抑止や試験除外で回避しない。
NativeErrorとの比較は既存HRESULTの同値をNativeErrorへ明示変換し、限定された原因の完全一致を
維持する。enum保存と必須pointerは元の例外/codeで明示拒否してから添字・参照を使用する。
失敗した試験backendはfalse/原失敗を返し、nullをdereferenceして負例を成立させない。
APIのclose結果と解放前の有効性判定は一回ずつ保存し、無効化後のhandleを判定に再利用しない。

大容量の固定path/read領域は既存の容量とゼロ初期値を保つRAII containerでheapへ移す。
取得・導入・noexcept境界の既存bad_alloc/例外変換を確認し、callbackへ例外を漏らさない。
新しい成功fallbackや無制限bufferを追加せず、GetLastErrorの即時保存を維持する。
試験の大きなfixture/resultも所有期間・実行順を維持してheapまたは独立関数scopeへ移し、
元の不正enum/null/権限/reparse/壊れたmetadata等の負例を削除しない。
診断出力は同じbit値を明示unsignedへ変換し、公開API/schema/期限/適用性/署名/同意/待機は変えない。

解析C6248が対象にするnull DACLの意図した負例は削除しない。RAM内の
`D:PNO_ACCESS_CONTROL`を既存のSDDL変換APIで構築し、OSのGetSecurityDescriptorDaclで
DACL present=true・ACL=nullptrを、controlの保護bitと元ownerも独立確認してから同じvalidatorの
拒否へ通す。空ACL/不在DACLへ置換せず、fileや実運用rootへ適用しない。
`NO_ACCESS_CONTROL`のnull ACL表現はMicrosoftの
[Security Descriptor String Format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
を参照する。実fixtureの等価性はOS返却値を正本とする。

元snapshotと全原FAILを保存し、同874path/modeの新revisionから唯一buildのfresh D/R ALL、
影響する通常全75CTest/各構成とformat/規約/両Doxygenの現hash、実analyze Release ALLを確認する。
元150件やrevision4の各6件の成功を新revisionの再実行として扱わない。解析合格後だけ同候補HOMEで
通常OFF Releaseをfresh再生成し、package/Task/通常HOME復帰は後段へ分ける。

## 397: 自作target共通の診断path変換

395の配布監査は、inner setupの静的library由来の診断文字列に開発source絶対pathが残り、
単体EXEの埋込resourceにも同じbyteが入るため拒否した。既存のdeterministic/pathmapは
配布EXEのPRIVATE compile optionだけで、drivercrate_platformの実compileへ届いていなかった。
原byteと監査FAILを保持し、既存二optionをdrivercrate_apply_compiler_optionsへ移す。

自作targetのCXX compileだけに、既存の`/experimental:deterministic`と
`/pathmap:<source root>=.`を共通適用する。特定CPP名や配布file名による例外を追加しない。
固定hash第三者sourceの独自compile規則、SDK external五leaf、`/W4`、`/WX`と安全flagは維持する。
明示的な位置情報は試験の診断/行番号に限られ、導入・取得・照合のfile入力へ流用していない。
C++全byteを保持し、今回の変更をAPI/schema・署名/適用性・権限・待機の変更へ広げない。

元874path/modeの新snapshotを作り、唯一buildのfresh通常D/R ALL、実strict Release ALL、
通常OFFへの復帰とfresh Releaseを確認する。実命令差分はsource prefixと既存二optionだけへ限定し、
先に固定した15CTest名を各構成で実行する。旧source6の全150、format、Doxygenは元資格として
保持し、新snapshotで全て再実行したとは記述しない。新C++差分や新しい懸念が判明した場合は
別工程を先に登録して必要な検証を追加する。
同HOMEの既存builderで新規先へ生成し、固定CPython原catalogの区別以外は元の私有path拒否を
維持した通常監査へ通す。合格した新byteだけで配置/Task/初期UIを受入後、通常workspace HOMEへ戻す。
元snapshot、旧配布byte、原失敗と元dataを上書きしない。実索引署名/公開/driver導入は別工程とする。

## 401: 同じnative runの公式recordからの明示本体取得

通常metadata-onlyの日次入口は維持する。別の明示取得入口だけで、同じ保護writer lockと
全既存source/request待機の下、新HTTP200の私有公式record/evidenceを生存させたまま
既存RecordScopedDownloadGrantとOfficialAcquisitionSessionへ一回接続する。
304は新payload取得を許可せず、旧PAGE・保存JSON・公開metadataからauthorityを復元しない。
明示本体modeはIf-None-Matchを送らず、新200を要求する。metadata-onlyの条件付き再確認は維持し、
不意の304でも無条件の二回目GETや保存本文からのgrant発行へfallbackしない。
同日完了、既存run再利用、HOLDから新本体取得成功を合成しない。

明示入力は保護された原release JSONの全byte pin、その許諾revision/抽出全文hash、
同意の絶対UTC期限、今回一fileの最大byte予算である。これらは同意と期待値だけで、
公式authorityではない。明示同意がなく、異版/異全文・欠損hash・失効/未知時計なら
payloadを開始しない。本文の表面的なhash差だけを許諾変更と断定せず、同じ新200から
既存parserが得たrevision/全文と比較する。以降の六入力のtemplate/script再確認は
既存のより保守的な条件を維持する。

一回の予算は検証済み同recordの上限と明示承認予算の小さい方、絶対128MiB以下とする。
公表exact sizeがある場合はその値を維持する。今回のIntel原40,477,087Bは運用入力であり、
製品へ特定ZIPのsize/hashを固定しない。概算sizeや承認予算を公表exact sizeへ変換しない。
一file/一session、再試行0、元runの単調時間予算/原grant期限、公式起点/CDN用途限定、
HTTPS/public宛先/redirect/実hash/回線cost/空き容量を既存共通取得器で維持する。
generic32MiBは変更せず、新provider・別counter・新authority保存機構を追加しない。

出力は同じ既存operations/jobの新receipt名から導出する新archiveだけへ限定する。
通信前に保護親をpinし、既存final/partialを拒否する。取得は既存保護workspaceで行い、
同生存sessionの封印証拠と原byteを再検査してから、同じ保護親内のCREATE_NEW partialへ
有限copy・hash/size再検査・flush・非置換atomic renameする。原archiveの上書き/移動0。
失敗/途中/不確定のpartialや完了後の孤立archiveを成功に昇格せず、自動再取得しない。
archive commit失敗は日次成功/新予約を発行しない。commit後のstate/receipt失敗でも原待機と
元世代下限を保持し、孤立archiveや再起動から新authorityを再発行しない。

取得開始前のIN_PROGRESSへ一回の最大待機を先払いし、中断からの再開では新HTTPをせず
FAILEDへ閉じる。HTTPが始まった試行の終端は元の完了+24hを短縮せず保存する。
同source/別manifest/別binaryでも元待機を集約し、旧counter/claim/root/鍵をresetしない。
新200で本体保存まで成立した場合だけ現行日次receiptと元予約を発行する。
既存の内容検査と六入力準備へ新archiveを渡し、実hash/INF/CAT/参照本体・全公開tuple・
原terms/script/原期限を確認する。明示準備入口は未署名の六入力までとし、署名/公開/Task/
installer実行/driver導入を開始しない。アプリの画面/機能は追加しない。

401は実HTTP0の有限内部検証であり、fresh実取得/新terms一致/署名索引公開は未確認として
source受入後へ残す。旧397配布byteの資格を変更sourceへ継承しない。

## 405: scope準備での旧署名assetの世代下限認証

403の正規scope準備は、旧原署名assetに対し現producerの再投影byte一致を要求したため、
現在必須の空`nestedArchiveIdentity`一fieldの追加だけで拒否した。旧recordを現codecで
再生成することは世代下限の認証には不要である。利用者の現行一本化方針に従い、
旧byteは書き換えず、既存の`--distribution-verify-floor-history`へ一本化する。

`load_config`/`validate_legacy_metadata`は同root/原config・receipt・manifest・GZip・envelopeの
原hash、日程、key、原publicationとreceipt世代/manifest世代/asset世代の一致を構造検査する。
receiptの原field/投影hash/観測時刻検査は再利用するが、旧recordは解釈・再生成しない。
準備の既存四入口は元のnative reservation照合を維持し、署名履歴検査をfloor専用APIへ替える。
実行時の旧metadata原assetとの完全hash一致分岐も同APIを使う。APIが認証するrepo/channel/
key/publication/世代/原hash/size/GZipと失敗拒否を維持し、現在利用receipt/record/grant/
authority/store更新は一切得ない。未知headを世代0へ戻さない。

現在候補は既存のacquisition verifierと六原入力・全record・原期限の検査を維持する。
全issuance claim/native counter/fence、同root/namespace、旧raw terms/同意/期限は変更しない。
旧codec/互換変換/試行fallback/別counterは追加しない。Pythonの有限内部回帰と既存実署名の
非変更floor認証を確認し、scope/config発行と実取得はsource受入後の運用工程へ残す。

## 409: 明示収集の呼出し内拒否段階

407の新PAGEはHTTP200後error13で失敗したが、最初の拒否段階を観測していない。
原FAILと待機を維持し、過去の原因を推定で確定しない。新しい診断は既存resolveTargetから
LocalCollectorTargetResultへ一時enumを返し、明示`--daily-acquire`の`COLLECTOR_PAYLOAD`へ
数値`stage`一項だけを出力する。通常UI、通常metadata出力、永続checkpoint/receiptへ追加しない。

数値はNONE=0、REQUEST_SESSION=1、METADATA=2、EVIDENCE=3、PARSE=4、ADAPT=5、
RECORD_VALIDATION=6、PAYLOAD=7とする。最初に拒否した処理区間を示し、元NativeError/
HTTP status/exitを置換しない。成功と今回未試行、保護stateエラー、再開で未観測の結果は0とする。
0だけから過去の成功を判定しない。Intelのparser/adapter短絡判定を二判定に分け、各区間の
元入力と順序、失敗値を維持する。新しいauthority、旧reader、Provider、設定、DBを作らない。

URL、本文、hash、ID、端末情報はstdoutへ追加しない。既存の閉stdout consumerは現行の
成功`stage=0`へ揃え、非0/欠損を成功へ許容しない。非通信fakeと既存23payload条件を使い、
到達可能な拒否、成功0、未試行/再開0を確認する。到達不能な段階のためのtest hookは増やさない。
今回の有限差分は409/PLANへ固定し、実HTTP/待機reset/Task/鍵/索引署名/公開/導入は行わない。

## 423: 手動確認とHTTP観測の時刻の分離

原PAGEの観測後に四範囲を手動で再確認しても、従来は各`evidence.checkedAt`と
`pageObservation.checkedAt`の完全一致により原HTTP観測時刻へ固定していた。
さらに候補期限が旧PAGE時刻+8日へ制約され、24h待機後の週次7日超という条件と衝突した。
既存`evidence.checkedAt`を、そのscopeを実際に手動確認した時刻として扱う。
閉field/schema/入口は追加せず、原PAGEの時刻とhashを書き換えない。

Pythonのvalidate/upsert/readは、各scopeのlocatorId/bodySha256/scopeの結合と
原PAGE観測 <= 実手動確認 <= 当該profiles.asOf、および実手動確認 <= 実現在を検査する。
旧HTTP datasetの`locators.asOf`を手動確認の上限へ流用しない。
REVIEW_REQUIREDの旧根拠保持は引き続き実行許可にならない。
native jobの既存17閉fieldにprofiles.asOfは存在しないため、nativeはその値を推測・復元せず、
原PAGE観測 <= 各実手動確認 <= 実現在を独立に再検査する。
profile.asOfとの結合は正規data producerの検証責務とし、既存の保護data/私有job境界を維持する。
旧等日時の入力もこの順序を満たす範囲で引き続き受理する。

候補期限は、同run実INF内容検査・同run実PAGE観測・四scopeそれぞれの実手動確認の
各+8日のminとする。小数秒は既存どおり延長せず秒へ切り下げる。
PAGEは既存私有所有観測だけを使い、routeVerified/fresh実200/同hash/24h未満を維持する。
実PAGE本文がreview対象原hashから変われば既存検査で拒否する。
日次再取得や同hash一致だけで手動確認時刻を更新せず、公開JSON/旧ZIPからauthorityを復元しない。
8日上限、原expiry、実HTTP待機・予算・課金、世代下限を緩めない。
週次strict7日の残存条件は後続ADR0402により実現在での原有効性へ更新する。

423では実データの日時変更・手動review/update/import・実HTTP・署名・公開を行わない。
既存fieldで別時刻の根拠を表せる実装と有限回帰までを対象にし、実運用と新配布物は後続へ残す。

## 撤回履歴

370では旧descriptorの期限順序に合わせるため、配布recordだけの期限短縮とnative親の独立正規化照合を
試作した。後続の利用者指示で不要になったため未受入のまま中止し、371で開始基線へ戻す。
370の原観測・途中D/R・原FAILは私有証拠として保持し、旧互換の成功や現release受入へ換算しない。
