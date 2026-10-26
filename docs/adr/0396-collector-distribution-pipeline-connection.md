# ADR 0396: 保護callerと汎用配布pipelineの接続

- 日付: 2026-10-23
- 状態: **採用・実装未完了**。主担当が252b3a/252b3arの現物と追補を確認して採用した。以下の追加API・schema・通信経路は、個別の実装・検証が完了するまで利用可能とは扱わない。
- 対応工程: G13-I7r252b3a、主担当指摘4点の追補252b3arは設計採用済み。実装252b3b、受入252c、snapshot/setup/初回origin/日次接続252dは未完了。
- 実使用推論強度: max。単独・再委譲なし。対応系列・実device・実収集・実導入の増加0。

## 1. 判断と現物

ADR0395の外部データ→共通取得/全INF通常検査→未署名v2を接続する。
`CollectorRegistryJobRunner::run`をpublic化せず、setupのnative親processへ
`CollectorRegistryJobProtectedCaller`を実装する。固定Python childとの有限duplex bridgeを追加する。
別Collector processへ許可JSONを渡し、親が保持するwriterを取り直させる構成にはしない。

現物の結合点は次のとおり。

| 現物 | 継承するもの / 必要な差分 |
|---|---|
| `collector_setup_workspace.cpp::runCollectorSetupWorkspace` | package/祖先実handle固定、originの両側binding、native admissionの所有、固定Python起動、660秒監督。現pipeは一方向context+EOFなので、新action専用のduplexを追加する。 |
| `collector_setup_admission.cpp::acquireCollectorSetupAdmission` | `initializeExistingWriter`で非作成のnative writerを取得し、legacy全scopeを検査する。campaign/segmented/未知scopeは現行どおり拒否。これは共有native予算を予約するAPIではない。 |
| `local_collector_state_store.cpp::initialize/initializeExistingWriter` | 前者の`initialize(root,true)`は保護directory/runs/current/lockを作成してwriterを所有できる。後者は作成しない。現admissionは`requests.empty()`を拒否するため、新規PC用のorigin初期化と専用admissionは追加実装が必要。 |
| `collector_workspace.py::NativeAdmission` | pipe serverのsetup image/生存HANDLE、package/seed/policyと実directory identity、有限時計、一回消費。公開receiptやboolでは代用しない。 |
| `registry_daily_monitor.py::writer_lock/run_once` | 同じ`writer.lock`先頭1byteのOS排他、URL key、24h、host待機、先行保存、停止回収、元成功保持。新pipelineから`run_once`を再入呼出ししない。 |
| `collector_registry_job.{h,cpp}` | private one-shot runner、原page hash/一意anchor、保護session、実archive、通常全INF/CAT/公開identity検査。同名friendは現在未定義。 |
| `collector_user_task.cpp::make...TaskXml` | 現Actionは`bin/DriverCrateCollector.exe --once config/targets.json work/state/collector`。metadata同意をpayload取得同意へ読み替えない。 |

今回読了: AGENTS.md全節、ADR0395、352/HANDOFF、353/HANDOFFとnullable追補、354/REVIEW。
固定Intelの`project_collected_native_index.py`と`daily_index_pipeline.py`のscope/pinは拡張しない。

## 2. process・lock・能力と一jobの順序

新setup actionを`--distribution-run-once <workspace> --confirm-inspection-download`とする。
引数は固定の操作と検証済み保護workspaceだけで、任意command・URL・成功JSONは受け取らない。
通常`DriverCrateCollector.exe --registry-job`の単独JSON実行は拒否を維持する。

1. native setup親は既存package/receipt、module実byte、固定runtime、originを検査・固定する。
   下記の`acquireCollectorDistributionAdmission`が取得したnative storeを子終了まで強所有する。
   同じCOM MTA監督threadが後述callerを実行する。C++ mutexを保持したままHTTPしない。
2. 固定Python childは`load_inputs/validate_profiles/plan_profiles`を使い、元registry/locator/profileの
   原byte、参照fingerprint、全対象と分母を再計算する。保護親で固定した入力hashと照合する。
   `monitor.writer_lock(activeMonitorRoot)`をrun全体で保持する。親native writer→child monitor writerの
   順序を固定し、逆順取得と同rootの再lockを行わない。
3. childは一回の`NativeAdmission.consume`で現native footprintを適用する。全jobのroot/payload hostと
   GET requestを比較し、既存共有request/hostと明示heldSourceIdsを理由付きHOLDへ残す。
   非共有の正常な静的jobは次へ進める。campaign等の未知native modeはrun全体拒否のままとする。
4. childは同じmonitor writer内で、PAGE既存request keyとpayload補助予約を照合する。
   全段の予算・24h・host待機を先払い保存/読戻しした後にだけ`EXECUTE_JOB`を送る。
   新PAGE GETを行う場合だけ既存PAGE stateの`IN_PROGRESS`を作り、同じ保護root配下の版付き補助journalを先に保存する。
   PAGE保存後、補助保存前の停止も未完予約として回収し、payload送信を許さない。
   同runのprivate PAGE proof借用なら新PAGE予約・新PAGE GETは0とし、当該payloadの予約だけを作る。
5. 親は自分が固定したrun/input/planとordinal、原job hash、予約hash、実monitor identityを再照合する。
   検証済み固定childの実process/pipeを確認し、同じ保護fileの保存済み予約を再読する。
   JSONの`lockHeld`等は設けない。monitor lockの所有は、親が固定したchild codeの制御フローが担う。
   公開fileをcopyしてこのprocess・lease・実入力照合を代用する入口はない。
6. 親だけが一回使用の`CollectorRegistryExecutionPermit`をprivate構築する。permitはrun/job/予約、
   native lease、child process、deadline、effective capへ結合し、copy禁止とする。
   callerがpermitを消費して`CollectorRegistryJobRunner`を構築し、`run`を同期一回だけ呼ぶ。
   各jobで新runner、0でない親採番session ID、実network cost reader、deadline/子生存cancelを使う。
7. 同じnative結果objectから候補recordを生成して保護run directoryの新規fileへ保存・読戻しする。
   childへは固定結果参照/hash/件数だけ返す。通常stdoutはURL/公開IDを含まない数値と固定理由だけ。
   childは親の同native I/O観測で精算し、旧lastSuccess・全分母を残す。親/子いずれかの停止・結果欠損は
   UNKNOWN_OUTCOME、最大予約課金、元待機維持となり、予約cancelによる即時再送を許さない。

duplexは既存実handle/固定child起動を再利用し、継承handle listを限定する。
新protocol `dc-collector-distribution-bridge-v1`は長さ付きframe、最大job 1MiB、最大32job、
run 600秒/監督660秒、単調sequence、固定runId/plan hashに限定する。
messageは`BEGIN_RUN/EXECUTE_JOB/FINISH_RUN/ABORT`だけで、任意path/commandはない。
job結果本文はpipeへ無制限に返さず、固定run-relative member/hashへ参照する。
親は任意client接続を受ける公開serverにならず、起動した同じchild HANDLE/実image/pipe peerへ結合する。
再接続、同ordinal再実行、別runへのpermit転用、時刻変更、入力差替えを拒否する。

## 3. 予約・待機・予算

`dc-collector-distribution-run-v1`補助journalをactive monitorと同じ保護root・writer管理下へ追加する。
既存state schemaをpayload成功の意味へ変えない。固定fieldはrunId/inputHashes/planHash、
job ordinal/hash、PAGE/payload request hash・host hash、開始/期限/nextDue、予約上限・課金、phase、
結果/候補memberとhash、固定status/reason、前成功参照とする。未知fieldを拒否する。
export/import/layoutの閉集合へ版付きで追加する。別の並列監視DBは作らない。

PAGEは既存`GET\nURL`/URL共有keyと24hを使い、payloadもURLの恒久keyで24hを共有する。
profile ID/revision・registry世代は待機keyへ含めない。新データ世代でもhost review/Retry-Afterと
旧試行は保持する。同じPAGEをmonitorとpipelineで二重取得しない。
同じrunのparentが所有するprivate immutable PAGE proof/bodyを、後述の限定APIで別jobへ借用する。
新PAGE GETの24h待機は保持しつつ、同run内の別payloadを一件/24hへ制限しない。
共有製品一recordはB1の一jobとして先に統合する。別recordのURL一致だけでpayload共有認定しない。

実行capは原jobを変更せず、callerだけがprivate引数として渡す。

```
pageReserve = sameRunPrivatePageProof ? 0 : 2 MiB + 1 byte
payloadProbeReserve = 1 byte
payloadCap = min(job.maximumBytes, COLLECTOR_INSPECTION_MAXIMUM_BYTES,
                 monitorRemainingBytes - pageReserve - payloadProbeReserve,
                 applicableNativeRemainingBytes)
```

負数/overflowと1byte未満を拒否する。既定32MiB/profile、空のmonitor枠なら最大30MiB未満となる。
`CollectorRegistryJobRunner::run(..., const CollectorRegistryExecutionLimits&, ...)`へ限定追加し、
内部adapterへminだけを渡す。原job/原maximumBytesは結果にそのまま保持し、effective capを別fieldで返す。
Content-Length/実転送がcapを超えれば取得拒否であり、Range・分割取得・次run再送で回避しない。
同じprofileを書き直させず、次回の空枠なら同じ上限で実行できる。原hash/size不一致の拒否は維持する。

現物はPAGEの`getCollectorInspectionPage`とpayloadの`downloadToFile`へ各`2U` redirectを渡すため、
各最大3要求（起点1+redirect2）である。初回はPAGE最大3+payload最大3=6要求と
PAGE2MiB+検出用1byteとeffective cap+検出用1byteを先払いし、proof借用時はPAGE0+payload最大3要求/byteだけを先払いする。
前案の各4/全8要求と、成功時も上限を全額消費する記述は誤りとして本追補で置き換える。

最小の追加は`CollectorHttpTransferObservation`（PAGE/PAYLOAD別）で、同じnative HTTP I/Oだけが生成する。
read-only fieldはstage、attemptedRequests、bodyBytesRead、terminalStatus、completion（COMPLETE/UNKNOWN）、
元run/job/予約bindingである。公開JSONのconstructor/decoderを設けず、private recorderへだけ更新を許す。
`openGetRequest`の送信直前で要求attemptを数え、`consumeResponse`の実readData完了ごとにbyteを数える。
originPolicyIndicesは送信前のURL検証でも増えるため、要求実数の代用にしない。
EOF・Content-Length整合・同じhandleでの保存/flush完了まで確認できた段だけCOMPLETEとする。
budget byteは既存monitorと同じ実読取りHTTP本文byteで、header/TLSを含む回線全byteの計測とは称さない。
失敗・途中受信・例外・cancel・cap超過・結果欠損はUNKNOWNのままとし、その段の予約最大値を課金する。
payload未実行に終わった失敗も当該予約を取り消さない。INF/CAT拒否など後段失敗はHTTP完了とは別で、
先行HTTPのCOMPLETE観測が確定・永続受領済みなら、その段の実転送量で精算できる。

同じparentが署名ではない内部結果として返したCOMPLETE観測を、childは所有中writerのjournalへ
`RESERVED → SETTLED_ACTUAL`で一度保存・読戻しする。UNKNOWNは`SETTLED_MAXIMUM`とする。
完全精算の保存前は予約全額を残量から引き、保存後だけ差分を同runの別URL用の残枠へ戻す。
精算はbyte/要求の課金だけを変え、元attempt、nextDue、host review、request key、一回使用済みpermitを
一切消さない。同じURLの同日再送を許す返金ではない。再受領・再精算・旧phase差替えは拒否する。
例えばPAGE128KiB+payload1MiBが各1要求で完全取得されれば約1.125MiB/2要求を消費し、
32MiB原profileのまま別payloadを続けられる。同PAGE借用の後続jobはPAGE増分0byte/0要求である。
同意文書GETが必要な形式は初版では未対応/保留。将来は追加要求・byteを先払いする別形式契約が必要。
monitorの64要求/32MiB/600秒と30秒終端余裕、256MiB空き、回線同意、最低24hを維持する。

356の途中変更を再開確認した際、現`consumeResponse`の残cap+1読取りは`indexControl`限定で、
収集経路は64KiB chunkのままと主担当が確認した。収集限定で要求量を
`min(available, bufferSize, maximumBytes - receivedTotal + 1)`へ制限し、通常HTTPと既存索引経路は変えない。
超過検出用byteも実測へ計上し、UNKNOWN時の予約最大課金が実読取りを下回らないよう上記で先払いする。
許可payload上限と検出用余裕を混同せず、余分なbyteを保存・解析・成功へ使用しない。
この訂正は252b3b1rの読取り制限と252b3b2の予約へ適用し、現運用の予算増額や待機resetは行わない。

現`CollectorSetupAdmission`はlegacy共有scopeの予約APIではない。native共有request/hostは引き続きHOLDし、
元native budgetを消費した・予約したとは報告しない。実行可能なのは非共有と証明したscopeである。
そのscopeでは既存workspaceと同じくlegacy metadata日予算は非適用、native inspectionの32MiB等は適用する。
将来native共有scopeを通す場合は、既存Recovery/SharedStoreの私有予約へ接続する別工程が必要であり、
8MiB/応答等を32MiBへ拡張したり、新ledgerで元JST日予算を迂回してはならない。
全HOLDを接続完了にせず、架空非共有hostの正常jobが親callerから実行される決定的正例を必須にする。

32はrunのbatch上限であり総製品数ではない。既処理/待機対象を飛ばした安定順で未処理へ進み、
33件目以降をDEFERRED_BATCHへ残す。新世代で同じ先頭32件を毎回選び続けない。
run中にmetadata monitorを同時実行しない。同じ一回入口へ統合する場合も共通64/32MiB/600秒を分割共有する。

### 3.1 同run内だけのprivate PAGE共有

parent所有の`CollectorRunPageProof`を追加する。外部構築・JSON復元・保存cacheからの復元を禁止し、
`CollectorRegistryJobProtectedCaller`と`CollectorInspectionAcquisition`だけが借用できる。
同じ実`getCollectorInspectionPage`の成功raw body（最大2MiB）・decoded HTML・SHA-256・最終URL・
UTC・完全transfer観測を不変所有し、run ID/親lease/child process/全入力hash/plan/deadline/
原root URL/exact root hostへ結合する。run内cacheは最大32entry、raw合計32MiB以下で、退避・復活しない。
first PAGE GETを一度だけ予約・実行し、親がproofを確定してから、以後同じkeyのjobへconst参照を渡す。

runner/adapterにprivateな`acquireWithRunPage(..., const CollectorRunPageProof&, ...)`を追加する。
各jobで新しいone-shot runner/session/workspace/permitを作り、proofの生存・全binding・deadlineと
当該jobのexpectedPageSha256を照合する。最終URLをbaseに当該href/payload/exact hostを再解決し、
`verifyCollectorInspectionLink`で当該anchorの一意性を毎回確認してから、当該jobだけの新grantと
封印取得証拠を作る。別jobのsourceVerified/grant/sessionを借用しない。実payload/hash/CAT/全INF検査も各jobで行う。
`pageObservation`は元PAGE観測へ参照し、`pageReusedInRun`と今回増分0要求/0byteを別に記録する。
proofは同run中にjobのpayload検査が失敗しても、PAGE取得自体が完全なら他anchorの独立確認に使える。
run終了/親子停止/deadline到達で全proofを破棄し、再起動後は保存観測から復元しない。
停止後の同PAGE新GETは元nextDueまで待機し、未実行payloadは成功にせずDEFERREDへ残す。

### 3.2 新規PCのorigin初期化

現`acquireCollectorSetupAdmission`は`initializeExistingWriter → inspectLocalCollectorLegacy`の後に
`snapshot.requests.empty()`を`NATIVE_REQUEST_SCOPE_MISSING`で拒否する。空storeを作るだけでは動かない。
旧関数の拒否を弱めず、新しい非通信`initializeCollectorDistributionOrigins`と、専用
`acquireCollectorDistributionAdmission`を追加する。旧historyを作った実通信やlegacy試験を初回条件にしない。

initializerは新固定setup action`--initialize-distribution-origins`からだけ呼ぶ。
既存package/receipt・root/祖先handleと非重複を固定し、正式に選択済みのorigin参照/移設stateが
ある場合はその実体へ従う。既存originを別の新空rootへ置換して待機をresetするAPIにしない。
初回だけ新nativeRootに`LocalCollectorStateStore::initialize(root,true)`を呼び、同writerを保持して
`runs/current`が空、余剰file/未知mode/segments/history/staging/旧pointer/cooldownがないことを実handleで検査する。
monitor側は既存`monitor.initialize`で空state/reports/lockを作り、実deviceや成功履歴を捏造しない。
両側には既存の7field`collector-monitor-origin-v1.json`/`origin.json`の実identity bindingを保存する。
新しい有限な`distribution-origin-init-v1.json`を保護workspaceに置き、初回plan、root identities、
開始/完了phase、空集合fingerprintと`legacyHistoryEverObserved=false`を保持する。これはHTTP許可ではない。
両参照の保存窓停止は非通信resumeだけで回復し、同じ予定identity/空集合を再確認する。
不完全初期化中は通信不可。既存rootへ作成APIを無条件再適用せず、既知参照なしの既存空rootも
明示初回登録で全空/保護を確認できた場合だけ扱い、部分履歴を空へ初期化しない。

専用admissionは同writer下で全既存検査を行い、二つの明示型に分ける。

- `VERIFIED_LEGACY_V4`: historyがある場合は既存admissionと全request/host footprintを使う。
  不完全/未知mode/回収必要/requests欠損は元拒否のまま。見つけたlegacy historyをdescriptorへ単調記録する。
- `VERIFIED_PRISTINE_V1`: 初回登録完了/両側identity一致、runs空、currentが既知origin markerのみ、
  snapshot.waits/requests空、過去legacy historyを一度も確認していないことを全て実検査した場合だけ使う。
  新distribution専用contextだけが空footprintを許す。旧NativeAdmissionの非空条件は変更しない。
  初回以後も毎run再検査し、後からlegacy historyが現れたら上のLEGACY型へ移る。逆遷移は許さない。

pristine型でもheldSourceIdsと現在native target/policyから非通信builderで得る予約host/request scopeを
適用し、将来の既存native収集と共有するscopeを許可しない。新規の非共有static hostは初回から実行できる。
既存monitorの履歴/待機やdistribution journalはこの型に関係なく毎回適用する。
旧origin既知なのに消滅/identity変更/履歴消去があればfreshへ降格せず拒否し、移設は停止export/importで引き継ぐ。
この初期化・空履歴admission/再開の実装と決定的試験はb3b-1/252dの必須残件である。

## 4. 汎用producerと非通信build

新native `collector_distribution_candidate.{h,cpp}`に
`makeCollectorDistributionRecords(const CollectorRegistryVerifiedObservation&, ...)`を置く。
入力型はcallerが同runの`CollectorRegistryJobResult`からprivate生成する所有値だけとし、
JSON decoderやpublic成功boolからは構築できない。B2の全INF結果を内側typed値で保持する限定変更を行う。
外部台帳と研究receiptを読み込んでCONTENT_INSPECTEDへ昇格させるPython APIは作らない。

- 一成功INF・一Models節・観測したOS familyごとにv2一recordとする。相対INF区切りは投影時だけslash化する。
  元source/record/profile/全共有productとの対応はsidecarへ全件保持し、製品表示名を適合条件にしない。
  recordIdは元source/recordと実INF hash・Models節・OS familyの完全hashから決定的に導出し、
  表示名/実行世代をidentityに使わない。
- 公開ID/ClassGUID/version/date/provider/verifiedPublisher/CATは同じ実検査から取る。実hash/sizeをcalculatedへ、
  元公開hashをpublishedへ分ける。downloadUrl=null/MISSINGの元recordを書き換えずfresh観測を別に持つ。
  v2のdriver version/dateはfresh実検証INFの原値を使う。packageVersion、古い研究driverVersion/date、
  観測世代/時刻はsidecarへ別の役割として保持し、文字列相違だけで保留しない。
  同じ台帳recordでも公式更新後のINF版が旧観測から変わることは通常更新であり、実検査へ進める。
  明示immutableな公開hash/expected INF version等の実行条件が指定されている場合だけ、それとの
  不一致を拒否する。現在の旧観測driverVersionを暗黙のimmutable pinへ変換しない。
- `modelsScope=CURRENT_WINDOWS_X64_SELECTION_ONLY`とbuild/server/SKUをsidecarへ保持する。
  v2のtargetOsは元公式申告と現在監視PCのOS familyの共通部分だけを出し、他OS分はMODELS_OS_UNOBSERVED。
  同familyの全build/SKU適合を実証したとはしない。端末の実INF/Windows rank bindingを必須のままにする。
- 一節128 ID超、64KiB record超、identityを現行codecで一意に表せない行は全原集合を保って
  V2_REPRESENTATION_LIMITへ保留する。初版はIDを分割/切捨てしない。他の完全な節は部分成功として扱える。
  共通検査の全INF上限等によるjob全体失敗では、先行合格もDISCARDED_JOB_FAILUREで投影しない。
- 個別INF拒否/identity失敗は別件数へ残し、全体FAILEDからrecordを救済しない。全拒否/全失敗時は新候補を出さない。
- 共有packageは実hash/size/形式/route/条件の同値で扱う。複数INF recordのdescriptorを同一に保ち、
  A4で既存acquisition groupの一target化を確認する。recordIdだけを根拠に別payloadを同一化しない。
  `IndexAcquisitionDescriptor`にはINF selectorを追加しない。INF/Modelsのidentityは既存
  `publishedIdentityEvidence`に置き、取得descriptorは同packageで共通にする。
- attestationのcheckedAtは元fresh確認、validUntilは既存最大7日と根拠期限のminで、build時刻へ更新しない。
  terms/prerequisites/authority根拠が不足すれば取得KNOWNを発行しない。sourceVerifiedだけを根拠にしない。

親が生成候補をCREATE_NEW/flush/readbackし、原run journalへ候補hashを結合した後、
`collector_distribution_pipeline.py::build_candidate(workspace, run_id, ...)`が非通信でassembleする。
buildは保護root/原点・journal・全入力と実producer版・候補原byte/hashを再検証する。
任意`--native-result some.json`は設けず、copyされた公開receiptだけを成功入力として受理しない。
buildは新しい取得permitを作らず、実行済み観測の未署名成果物を作るだけである。

出力は既存`driver-index-records-v2`、決定的GZip、`driver-index-manifest-v1`、全分母reportとprovenance。
現行identityはADR0397の377追補に従い必須nestedArchiveIdentityを含む10fieldとする。
modelsScope等はsidecarに残す。generationは保護候補headから単調採番し、
未署名候補headと端末の署名済high-waterを混同しない。同run再buildは同byteを返す。
既存配布channelで署名済みの世代は既存検証器で認証した公開headを下限として照合する。
固定Intel経路と汎用経路を同じchannelへ同時採番せず、署名/公開の既存直列操作で衝突・後退を拒否する。
公開headが確認不能なら候補は準備できても署名用の次世代確定とは扱わない。
旧成功Aと新成功BのassembleはAの期限/原観測を保持し、manifest期限は全収録record期限のminとする。
期限切れAを延長復活させない。全失敗時は旧head/assetを保持し、成功空索引を新世代にしない。
部分成功は候補生成と全target成功を分け、失敗分を含むexit/reportを残す。

非通信検証は`validateUnsignedIndexCandidate(manifest,gzip,now)`を新設し、既存manifest/record/quality/GZipの
内部検証を共通化して再利用する。戻り値は未署名検証receiptで、AuthenticatedIndexManifestや
AuthenticatedIndexAssetBytesを構築できない。通常アプリの署名境界は変えない。
既存`signDistributionAcquisitionIndex`/対応CLIへ未署名manifestとGZipを渡せる形にする。
run/buildから鍵照会/作成・署名・trust登録・公開を呼ばない。

## 5. データ更新・snapshot・日次への到達点

一度この機構を含むsetupを導入した後の同形式製品追加は、データupsert→validate/plan→同じrun/buildで
済ませる。アプリ/collector/setupの再build、メーカー別Provider、索引手編集、Task再設定を要求しない。
immutableな同梱seedだけを実行入力にせず、検証済みactive data世代を保護workspaceに取り込む
`import-data`を252dで実装する。seedは初期世代。新snapshot hashをpackage hashへ同一視しない。
active世代pointerを原子的に切り替え、旧世代とhistoryを保持し、参照変更のB1再reviewを維持する。

snapshot新版へprofiles/確認履歴/候補/provenanceの閉集合とhash/全参照を追加する。
保護run journal・credential・鍵・driver byteは可搬データへ混入させない。
運用停止export/importでは補助予約の未確定/host review/nextDueの最大値を既存stateと一緒に保持する。
単なるdata copy/importは通信許可を発行せず、importした候補は元時刻を保持する参照成果物である。

日次は将来構想だけに残さず、252b3b/252dの実装・決定的試験の残件にする。
新固定`--distribution-daily` dispatcherが同じcaller/run/buildを呼び、active data世代を毎回検証して読む。
既存`--once`の動作/同意を拡張せず、新dispatcherの初回opt-in、payload検査取得範囲/予算の明示同意、
新所有Taskの固定Action/schemaと有効readbackを実装・試験する。署名/公開は自動化しない。
既存実Task/Actionを今回変更しない。実登録/切替は元所有境界と別の明示指示に従う。
実接続前は日次未接続と明記し、追加対象を恒久的な別手動試作経路へ置いたままGoal完了にしない。

### 5.1 252dの固定契約（2026-10-23）

`dc-collector-distribution-data-v1`をpackageとは独立した可搬data bundleとする。
必須fileはregistry.json、locators.json、collection-profiles.json、research-index.jsonとmanifest.json。
元確認履歴はregistryのobservationsとprofileのreview/historyに保持する。任意の旧候補は公開出力だけの
reference集合へ格納し、元producer/origin/input hash・時刻と全file hashを保持する参照成果物とする。
元provenance内の私有candidate本文は公開hash/原時刻だけへ射影し、射影前後の両hashを明記する。
任意file、秘密field、実driver byte、鍵、端末固有state、私有candidate/job/result/permitは受けない。
研究索引は元registryから再生成照合する。原入力byteのhashと全参照を検証し、参照hashはtoolが計算する。

保護workspaceのdata/generations/<manifest-sha256>を不変保存し、data/active.jsonをflush/readback後に
atomic replaceする。初回seedを同じimportへ渡し、以後はactive世代を読む。旧世代を削除しない。
親はactive pointer/manifest/三入力を実handleで固定してhashを独立計算し、固定childは全schema/参照を再検査する。
runとbuildの両方が同active原byte/hashを照合する。data importは既存monitor/native履歴と同意を変更しない。
旧profileのsemantic参照が変わる場合は既存B1 upsert/reviewを必須とし、data import自体はreviewを作らない。
既存更新は確認待ちのREVIEW_REQUIRED世代を先にactiveへimportし、別の明示upsert/review後に
同じsemantic参照のCURRENT世代を再importする。旧activeから意味変更後CURRENTへの直接importは拒否する。
確認待ち対象の取得を保留し、両importとも旧URLの24h待機・課金・旧候補/元期限を保持する。

停止exportはdistributionの未確定予約を最大課金へ射影した公開待機ledger、cursor、旧成功参照、
旧世代番号とhash付き公開索引/provenanceを保持する。新PCへ私有run結果を復元しない。
importされた公開参照をprivate typed観測へ変換せず、新runは新原点検査・明示再開から開始する。
欠損/腐敗した必須履歴をfreshへ直さない。data importと運用停止export/importは別操作である。
停止snapshotは`dc-registry-monitor-export-v3`とし、私有runを含む旧v2のimportは拒否して元storeからの
新しい非通信exportを要求する。従来metadataだけのv1 importは維持する。

新packageは`dc-collector-package-v7` / `EXPLICIT_DISTRIBUTION_DATA_DAILY`とし、v6閉包へ
profiles/pipeline/data moduleと初期data bundleを追加する。新install receiptはv3とする。
通常installの既存native日次Task同意は維持する。汎用payloadの日次収集は別の初回明示操作
`--enable-distribution-daily <workspace> --confirm-daily-inspection-download`を必要とする。
同意範囲はactive登録済みの既知static ZIP/CAB形式・全INF検査、32job/batch、64要求/32MiB/600秒、24h待機であり、
同形式追加ごとの再同意/Task再設定は不要。dataだけで範囲/予算/commandは変更できない。
保護した8field同意receiptをpackage manifest/実package directory identity/実workspace identityへ結合し、
同じbyteを別package directoryへcopyしても許可しない。copy/importでは発行しない。

新Taskは既存SID/root導出名へ`-Distribution`を付けた別所有名、plan/ownership-v2と専用metadata fileを使う。
唯一Actionは導入済み`DriverCrateCollectorSetup.exe --distribution-daily`で、引数からURLやscriptを受けない。
既存native Taskの15:00は変更せず、新Taskは17:00とする。既存Taskの最大70分から間隔を取り、
なおwriter競合時はその回を拒否して次の日次へ待機する。即時retryや待機/予算のresetは行わない。
dispatcherは保護同意を再検査して同じ`distribution-run-once`のcaller/run/buildを呼ぶ。
既存`--once`、v1-v6のAction/receipt、旧管理者Task所有範囲を変更しない。
v7 uninstallは両新所有名の正常不存在を確認後だけ管理programを削除し、data/workspaceを保持する。
有効readback/冪等/失敗保持/解除は既存のTask backendを流用し、今回の受入はFakeTaskだけで実Schedulerを呼ばない。
単体EXEは別outへ構築し、code signingなしと明記する。実Task、別PC、七日実運用、実収集/導入/公開は未確認に残す。

## 6. 小さな実装順と固定受入

| 順序 | 変更file/関数 | 完了の証拠 |
|---|---|---|
| b3b-1 | `official_http_client.{h,cpp}`typed transfer、`collector_inspection_acquisition.{h,cpp}`private PAGE proof、`collector_registry_job.{h,cpp}`private limits、専用unit | 先にnative共通primitiveを実装。2redirect/最大3要求、完全HTTP実数/途中UNKNOWN、same-run PAGE借用とjob別anchor/grant、32MiB原profile→30MiB以下capを固定。通常通信入口は拒否のまま。 |
| b3b-2 | `collector_setup_workspace.{h,cpp}`新action/duplex、`collector_setup_admission.{h,cpp}`専用admission、`collector_registry_job_protected_caller.{h,cpp}`、`collector_workspace.py`、`collector_distribution_pipeline.py`、`registry_daily_monitor.py`予約/精算helper、CMake | native lease+monitor writer下の非共有job、初回最大6要求先行予約/完全HTTP実数精算/停止最大課金、同PAGE複数payload、別URLへの残枠再利用。pristine/legacyとJSON/copy/二回実行/親死亡拒否。全guard完成後だけ通常入口へ接続。A1/A5/A6。 |
| b3b-3 | `collector_distribution_candidate.{h,cpp}`、`signed_index_records.cpp`内部codec抽出、非通信unsigned validator/CLI | 同run native結果からv2/GZip/manifest、quality一致、OS scope/128ID超/全体・個別失敗、旧期限保持。A1/A2。 |
| c | Python producer integration fixture + native manifest/lookup/binding tests | producer実出力そのものをA3/A4の本物codec→lookup→DriverStore fake→取得group/INF/rank bindingへ渡す。 |
| d | snapshot/setup/module閉包validator、origin initializer/非通信resume、active data import、新dispatcher/opt-in/Task schemaと同test | 新規PCの空originからlegacy実通信なしで開始、旧history/待機を無視しない。同形式データ追加で再build不要、A7、日次呼出しが同run/buildへ到達。既存Action不変/未同意payload0。 |

A1/A2は既存352のA社二製品/共通record、B社一製品/別record、新INF/Models/架空IDを固定する。
追補正例として、同じ公式PAGEに異なるrecordの二payloadを置き、PAGE1+payload2の各1要求/
合計3要求で両jobが検査されることをA1/A5へ追加する。A社共有製品はそのまま一payload取得に保つ。
小さい二payloadを既定32MiB profileで連続処理でき、予約最大ではなく成功actualが課金されることを確認する。
packageVersionとfresh INF版が異なる例、旧driverVersionからfresh INF版への通常更新を正例とし、
明示immutable公開hash/版条件の矛盾だけを負例とする。
A3はこのproducerの実manifest/GZipを、既存unitのRAM fixture署名鍵（永続鍵storeなし）で認証し、
`authenticateSignedIndexManifest → authenticateIndexAssetBytes → readSignedIndexRecords`とquality、
`lookupSignedIndexRecords`を通す。テスト専用公開pinを通常binaryのtrustへ入れない。
A4は同receiptから既存binding fakeへ渡し、A二機器一取得target、Class不一致/未知ID/実INF/rank拒否を確認する。
fixtureを別の手書きv2へ差し替えず、Python shape assertだけで合格にしない。
A5は新世代でもAの同日再送0/Bの新対象反映、33件以上の次batch継続を確認する。
同run PAGE proofは共有できても次run/停止後は消滅し、同PAGE新GETが24h待機することを固定する。
COMPLETE精算後も同URL再送0、失敗/UNKNOWNは最大課金、二重精算拒否を確認する。
A6は未知形式/terms・条件未知/anchor不在・曖昧/private宛先/hash・publisher・CAT拒否/期限切れ/
cap超過/全体失敗・部分失敗/各保存窓停止/親死亡/共有native HOLDを固定し、失敗を分母から除かない。
A7はsnapshot copy/import/追加file・破損・未知schema拒否、待機引継ぎ、setup seedとactive追加、
初回日次opt-in以外のcopy/import/validateでHTTP・Task・鍵・署名・driver動作0を確認する。
初回originは、完全新規→非通信初期化→両参照読戻し→非共有job正例、初期化各保存窓の非通信resume、
既存historyあり/不完全/未来時計/既存origin消滅・再配置拒否、legacy観測後のpristine逆遷移拒否を固定する。

未確定はbridge/補助journalの最終field順・package/snapshot新revisionの採番、unsigned validatorの
共通内部helper名であり、実装着手時に固定する。lock所有・能力発行主体・全段先払い・共有HOLD・
producer入力境界・OS範囲・日次接続の完了条件は本案で固定する。
今回build/test/HTTP/運用state/Task/鍵/Git操作は実施していない。実WinTrust正常、新規実収集、
実日次/別PC/署名公開の受入は本設計で確認済みにしない。

## 7. 252b3b2実装時の保存構造

固定childのduplexは一接続のlocal named pipeとし、親が実child HANDLE、OSのpipe client PID、
固定runtime imageを照合する。標準入出力へ任意RPCを公開しない。継承handle listは標準出力とNUL入力だけとする。
Python子はserver PIDと固定setup imageを実handleで再照合する。

補助journalのglobal本文へ過去runの全分母を累積せず、各runのcontent-addressed
`state-<sha256>.json`を固定run directoryへCREATE_NEW/flush/readbackし、global本文はmember/hash参照を保持する。
元request待機とcursorは同じglobal正本で保持する。各JSONの既存16MiB、移設の既存file/総byte予算を維持し、
上限到達は理由付き保留とする。無制限DB・自動履歴削除・待機resetは導入しない。

主担当の再開確認で、実registryが10,947,741byte、locatorsが1,099,931byteに対し、
nativeの`distributionHash`が1MiB入口を使う不整合を確認した。収集JSONの原byte照合は
上記16MiB文脈を維持したまま共通CNG処理を再利用し、既存1MiB/8MiB入口の契約は変更しない。
大きい上限の共通hash入口を使う場合も呼出前に16MiBを厳密確認し、JSON読取り予算を拡大しない。
小fixtureだけの合格へ読み替えず、現台帳/locatorの非通信hashと1MiB超・16MiB境界を確認する。

directory/plan作成前にpendingRunを、job/PAGE/reservation保存前にpendingJobを同じ保護正本へ先行保存する。
既知intentに一致する未完fileだけを非通信回収し、最大予約課金・元待機を保持する。
run snapshot保存とglobal pointer更新の間に残った自己hash一致snapshotは保持するが、成功や実行権限として採用しない。
分母の不変identityと可変結果statusを分離し、次runでも成功/失敗の結果更新を破損と取り違えない。

例外経路も、所有中の同じJob/childを停止して子processのsignaled終端を有限確認するRAII guardを
native writerの解放より前に置く。guardは同じleaseを強所有し、子終了の確認前に通常解放へ進まない。
停止・5秒待機でも終端を確認できないOS異常は固定診断を残して異常終了とし、通常成功/再開へ変換しない。
自己所有fixtureの親側予約拒否と実子停止で、guard内の子終端・保持中writer競合、unwind後のwriter再取得を確認する。

BEGIN_RUNでplanを読む前に、同run directoryと新しい内部祖先を既存実handle/ACL helperで固定する。
通常fileのatomic更新を妨げず、directory保持は同じChildLifetimeによる子終端確認より後に解放する。
自己所有run directoryの兄弟先への移動を一回試し、修正前は復元して安全停止、修正後は
ERROR_SHARING_VIOLATION拒否と元正常2job/3fake送信を確認する。新しいpath/実行権限の入口は追加しない。

vpの実probeで、metadata accessだけの既存directory handleは移動を拒否しないことを確認した。
directory時（drive rootを含む）だけFILE_LIST_DIRECTORYを明示取得して削除共有制限を実効化し、
一般fileのaccessは変更しない。[Microsoft一次資料](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-control-processing)は
主担当が参照し、本担当は修正前後の同じ自己所有directory移動の実結果で確認する。

## 8. 252b3b3の値境界と候補保存

同run結果は公開JSONとは独立した私有所有観測を持つ。通常全INF検査と公開identity読取の
同じ戻り値からのみ構築し、runner以外のconstructor/decoderは置かない。投影は原job参照と
全個別INF/Models集合、実archive・PAGE・内容検査時刻、実Windows build/server/SKUを所有する。
公開JSONやsuccess boolからこの観測を作る入口はない。通常CLIの通信拒否を維持する。

親が固定run内の`candidate-<ordinal>.json`を新規保存/flush/readbackし、resultと独立のhashを
同じjob journalと親の生存中settlementへ結合する。候補は既存v2 record/sourceとsidecarだけを持ち、
署名receiptや通信能力ではない。childは同じmonitor writerと生存pipeの内側で非通信assembleし、
固定run内のindex/GZip/raw manifest/report/provenanceを新規保存する。FINISH_RUNで親が自分の
候補hashと全保存済み精算を再照合し、同じ実出力byteを未署名共通validatorへ渡した後だけ
未署名検証receiptを保存する。新しいnetwork permitを生成しない。任意JSONのimportは設けない。

候補headはmonitor配下の補助領域で署名済high-waterとは独立して保持する。実producer/moduleと
元package/入力hash・monitor identity・runへのbindingを保持し、同run再assembleは原byteを
照合する。新しい成功recordがないrunはhead/assetを更新しない。旧成功参照の元期限は保存し、
期限切れは理由付きで除外する。認証済公開headを今回取得しないため、候補世代はローカル準備値で
あり署名用次世代確定ではない。実署名/公開の直列操作で既存公開headとの衝突を別途拒否する。

既存`validateBinding`はattestation期限がmanifest期限以下であることを要求していた。しかし第4節の
「manifest期限は全収録record期限のmin」と原attestation期限の保存を両立できない。単純な
不等号逆転では従来合法だった長manifest/短recordを拒否するため、共通codecでは両者の順序を
強制しない。各attestationの最大7日、checkedAtがmanifest発行以前、manifest発行時に未失効という
条件と実利用時の双方の期限確認を維持する。新producer/未署名候補はmanifest期限=min(record期限)を
別に厳密確認する。旧長manifest/短recordと新短manifest/長recordを双方正例とし、個別期限切れ・
7日超・発行前・manifest期限切れの拒否を検証する。短いmanifestが長い根拠を延長することはない。

未署名validatorはmanifest/asset/records内部の同じ値codecを使い、未署名専用receiptだけを返す。
署名側wrapperは従来どおり署名認証済入力だけから構築する。鍵照会、鍵作成、署名、trust登録は
validator/run/buildへ追加しない。ADR0397の377でidentityにnested memberを追加し、provider/CAT・全共有製品・原source record・
OS範囲と原時刻はsidecarに置く。実INF/Models抽出とアプリlookup/bindingの全受入は252cへ残す。

producer接続前の既知v1 job field集合も厳密に読取り、元待機/課金/旧resultを保持する。
候補参照三fieldの中途欠損や未知fieldは拒否する。旧jobへ候補を補完せず、公開result JSONから
typed観測を復元しない。旧historyの存在を理由にfresh初期化や24h待機の解除を行わない。

未署名manifest値codecの成功はdata有り/元拒否なしで表す。元拒否はoptionalな既存manifest拒否値だけを
返し、`AUTHENTICATED`を値検査成功の別名へ変更しない。公開未署名結果と非通信CLIにも認証成功区分を
流さず、成功診断は`manifestFailure=NONE`とする。署名wrapperが実署名検証後に返す認証成功は維持する。
