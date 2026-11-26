# テスト方針

## 1.0.12の確認範囲

公開ソースのビルドでは、署名索引の条件、候補詳細での配布物検査、ストレージの作用と事後確認を人工データで検査します。実機でのドライバー導入、再起動後の起動、全機器の組み合わせは別の確認です。配布物の検証結果はリリース本文を参照してください。

## 型付きSYSTEM Needsと同七選択（ADR0491）

限定内部UIの`original-selection`は、明示した私有原公開record/原三CABを既Common/archive/INF/CAT/全rank/Needs検査へ通し、同controller/workerの7 READYからfresh再検証とstrict fake native3/managed4・fake復元へ接続します。Windows INF/CAB本文はrepo fixtureへ複写しません。原公開署名/原byteと実cache-only CAT/member/file/権限検査、人工issuer/PnP/rank/時計/Store・提供先投影を別の資格として記録します。明示5 SYSTEM INFのSetupVerifyInfFile実scoreも独立したreadonly観測であり、人工INBOXへ合算しません。

原8 Camera familyの各準備、正負の共有型validator、提供mapping欠損/原service差/失効/依存INF不在、部分失敗時の実Tree readonly checkと成功対象だけの解除を限定実行します。原43 Needs/146作用節との消費集合は原INF hashと正確な節/辺tupleで比較し、単なる総数の大小を根拠にしません。旧WUA 0x80070057は原API地点が不明な履歴として保持し、strict GUID helperと診断fakeの成功を実WUA COM成功へ読み替えません。

現sourceは実装接続済み、同最終byteのD/Rと変更規約資格を847p9fのq3で封止しました。配布revision10と後続revision11、実TestPC結果は別です。

## 通常ユーザー収集の権限回帰（ADR0483）

`drivercrate_collector_workspace_permissions_tests`は新規隔離objectと実OS LUA/restricted medium tokenを使い、
本人owner/default DACL・BA deny-only・非昇格を保って旧BA owner指定の1307を再現します。
本人root/子/外部writer・実CAB reader・一段nested/INF閉包、原hash拒否・既存path/余分ACL/reparse拒否・cleanupと
native binding拒否を非通信で確認します。比較用のAdmin ACL fixtureを作る親test processには管理者tokenが必要です。
公開親は本番と無関係の本人LocalAppData内へ架空の二ACE親を作り、元5、exact 0x001200A0一ACE後の元token ACL/metadata再open、
内容read/列挙/作成の拒否、元子SD byte不変、冪等、旧mask/余分write/別SID/未知owner拒否とlinked tokenの正負を確認します。
fixtureのOS token/SDは回帰専用で、実installed host・authority/key/credentialを読んだり変更したりしません。
同じ`build/`のDebug/Releaseで実行し、既存collector runtime/manager・INF/取得証拠の必要回帰と規約gateを併用します。
実UACの取消し/中断、通常setup更新、実HTTP・実公開・自然日次は内部fixtureと分けて未確認です。
D022のContractRestoreは、現serviceの検証済み事前/事後保護を返すFakeへ補正しました。
既定protection()のUNAVAILABLEをbegin成功だけで補完せず、拒否例・期待値・実coreを維持し、実復元APIは呼びません。

## ソースコメントの検査

`check_source_standard.py`は、宣言と定義の各sourceに独立した概要・実引数名/方向・戻り値があるかを確認します。
関数・メソッドの独立block、所属に応じた枠、参照だけの省略と代表的な閲覧委譲、無名引数・削除宣言の扱いも検査します。
raw literal、型/field、macro定義の論理行は関数として数えず、未解析署名とdelimiter不整合は拒否します。
Doxygenのmerge済み文書だけでは両sourceの合格にせず、実処理・所有・例外・threadの意味はbody reviewで確認します。

```powershell
python -B scripts/test_source_style.py
python -B scripts/test_source_method_contracts.py
python -B scripts/check_source_standard.py
python -B scripts/audit_doxygen_members.py --check
```

`audit_source_contracts.py`は、XMLにある宣言/定義の位置から各raw契約を監査します。定義を`@see`だけに置換しません。
手作業で実本体へ照合して不足を補い、参照省略の新たな生成や日本語の完全な自動意味判定を前提にしません。

## App用Setup・自動更新（1.0.5）

`drivercrate_app_update_tests`は数値版・24h時計・GitHub JSON/正確asset、完全fake HTTP、byte/署名/版拒否、cache排他、取消しと専用workerを非通信で確認します。
`drivercrate_metadata_ui_tests --run-ui-tests app-update`は通常MainWindowでbusy/modal通知待ち、同意前取得0、ドライバー作用0、取得取消し・引継ぎ失敗時の画面保持・正常終了を確認します。
Providerのscan sessionや索引権限を更新workerへ混ぜません。Windows.Data.Jsonのfactoryは局所所有し、同じprocessでの反復と不正JSON/HRESULTを試験します。

```powershell
cmake --build build --config Release --target DriverCrate drivercrate_app_update_tests drivercrate_metadata_ui_tests
ctest --test-dir build -C Release -R app_update --output-on-failure
./scripts/test_app_distribution_documents.ps1
```

ローカルInno確認はTest AppIdと隔離した現在ユーザー領域だけを使います。1.0.4→1.0.5更新・同版修復、古い版/使用中/領域外の拒否、copy前の標準取消し、
現在ユーザー登録/機械全体登録0、実App起動と正常close、通常解除とCollector/data/log等の合成marker保持を確認します。
受入用STA Explorer launcherによる通常user Setup起動、製品workerの非通信fixture、実App起動は別の実績です。
822cの内部確認では、製品MTAから将来の正式Releaseを取得して自己更新する実往復、別管理者アカウント、実署名済みSetupの配布受入を実施していません。最終配布物の署名・展開受入は822e/fの記録で確認します。
実ドライバー導入は行いません。配布READMEは画像/guideを同版tagのURLへ変換し、Setup/ZIPの両方で確認します。

ADR0479の関連fixtureは確定403 manualとcounter不明/原host待機保持、403 header欠損/正値/照会失敗/不正値を非通信で確認します。期限保守は原完了claim→実公開gzipの全byte・全未失効wrapper集合を照合し、窓前1秒0/等号/窓内の元全体期限前完了・空/元hash/remote不一致/未同意と既取消し/clock/activeCASを分けます。RAM鍵・fake公開の成功を自然期限到来や実署名公開へ換算しません。 通常の新規候補にも元fresh/report検証後・予約前に同cutoffを適用し、保存済み短期限recordの再導入を防ぐ。元head/reportとactive復旧は変更しない。

ADR0478は同時刻manual再取得/部分保留からの再取得、daily step0、新24h事前/終端保存を既manager fixtureで確認します。短/長retry・host review/notBefore・未同意/offline/clock/停止/排他・複数overlap/未知予約を有限確認し、実収集/HTTPの成功と区別します。

818の関連確認は実SetupAPI V3の両client観測点/build別Models選択・server/x86不成立と、私有target/hash結合による投影を分けます。実API選択成功を実driver導入/原package再検査/実収集成功へ換算しません。

817のsetup版gateは既manager fixtureで既配布版/通常自己packageの区別と全hash/schema/余分なfile拒否を確認し、最終packageの実既存配置へのread-only preflightを別証拠にする。read-only成功を実更新installや自然収集の成功へ換算しない。

ADR0476は既manager fixtureの非通信時計で、全待機3秒差/部分実行、oldDue/終了60秒下限、複数待機、試行済み失敗24h、全host/manual HOLD、取消し/期限/不明/例外、clock/再起動/保存/排他を有限確認します。実HTTP/自然日次/実更新installの成功とは分け、原失敗と実assert分母を保持します。

> 2026-11-10、改善813の有限確認は私有HANDOFFへ記録する。直接DS・同task・別recordを既native/worker/UI fixtureで確認し、全体scan/metadata GET0、同owned本体GET合計1、現task/原期限/同意/署名/復旧の正負条件を分ける。過去812のfresh全再評価試験は当時のsource/原票として保存し、1.0.3の契約へ読み替えない。実HTTP/WUA/driver導入/署名/公開は未実施。

## 2026-11-08の同一索引本体GET省略（794）

ADR0467の追加fixtureは、実隔離DPAPI storeと人工RAM署名・完全fake HTTPを使い、初回/次呼出し/別client＋再open/新版の本体GETを1/0/0/1へ固定しました。同世代異manifest、rollback、署名不正、外側だけの再署名差、失効・破損cache、attestation失効、reload中の取消し/90秒到達/UTC欠損を含む新14条件66項目はD/Rとも失敗0です。既41 refresh条件・匿名readback群を保持したrefresh全体は各522/0、既loggerは192/0、画像なしrefresh-probeは58/0（UNCHANGED通常load→元plan一件→同target唯一候補の選択可能guard11/0を含む）。9変更sourceは規約0error・format0diff、既Doxygen設定の変更契約はwarning0です。原失敗と局所fixture修正、同一native handleの終了票は`out/index-cache-795`へ保持しました。実HTTP/実App再起動/実driver/全suite/新画像/署名/公開は未実施で、主担当受入・配布は別工程です。

## 2026-11-06の公開検証時刻と保留19

G13-I7r310／ADR0456は保存済み世代19の原署名二assetを通常公開鍵codecへ非通信再生し、
発行秒の1秒前/原期限ではINVALID_TIME、発行秒/現在では成功することとbyte改変拒否を確認します。
元publisherはHEAD中2秒経過で署名後のPUBLICATION_CONSUMER_CODEC/code13を再現します。
検証直前のremote.utc()再観測後は同条件で正常に進み、原三送信済みdraftは同19/同claim/同署名byte、
追加署名0で再開します。rollbackと原期限跨ぎは公開PATCH/CAS前に止まります。
manifest時刻へ時計を合わせず、原期限/署名/consumer codecの検査条件を維持します。
本番19の署名成功と公開未成功は利用者の元試行であり、今回の内部確認を実公開成功へ読み替えません。
最終D/Rは時計限定各423条件、既公開55case各3309、収集限定Manager各264、GUI各50が全成功しました。
3source format差0、規約317control/0error・metadata正常、Doxygen45/45/未知診断0です。
原束のcopy/hash一致・元clock-red・同19/draft/署名byte保持と関連結果は
`work/analysis/20261106-publication-consumer-repair-745`へ保存し、実authorityの再開や署名配布は別受入に残します。

## 2026-11-06の公開REST field上限とHEAD診断

G13-I7r309／ADR0455では、固定公開APIの匿名GET9件を一度だけ保存し、以後の確認は同じ原byteの非通信再生に限定します。
元publisherは2件目のrepo原応答84fieldでHEAD/code13を再現し、診断追加だけでは
HEAD_IDENTITY_REPO_JSON_FIELDS_LIMIT/code13を返します。API専用128fieldへ分離後、同じ原byteを
通常の固定公開鍵codecへ渡し、世代18/UNCHANGED・署名0まで確認します。
元blobのLF37個は元Windows strict decoderが受理するためbase64の条件は変更しません。
API84/128の受理と129/重複/不正UTF8/深さ拒否、local64受理/local65拒否を対にし、
保存RESTの上限・重複・UTF8・深さ・required id型・base64改変は固定substageで拒否します。
原収集/設定/authority/installedには書かず、実署名・claim作成・GitHub公開・driver導入は行いません。
署名配布と利用者による実再確認は主担当受入後の別工程です。
最終D/Rは公開55case各3309条件（旧3301＋API8）、収集限定Manager各264、GUI各50、保存REST再生7case各245が正常でした。
5source format差0、規約356control/0error・metadata正常、Doxygen48/48/未知診断0です。
元case28は人工recordの三時刻だけがOS秒境界で1秒変化した原失敗を保存し、同内容専用fixtureの原時刻を固定しました。
期待をPUBLISHEDへ変更せず、UNCHANGEDと製品の全field内容比較・原期限を維持しています。
証拠とApp/Collector/Signer/engine非依存のCMake根拠、保持hashは`work/analysis/20261106-publication-head-repair-743`に保存しています。

## 2026-11-06の保存済み候補の手動公開

G13-I7r308／ADR0454は既存`--publication-only`のRAM鍵と固定GitHub fakeへ手動条件を追加します。
保存済み候補の正常公開、最新all-waitからの原成功参照、同内容・候補なし・失効・改変・無設定・
別binding・REMOVED、原自動無効保持、busy・取消し・原待機を分けます。
正規17→18型の原UNKNOWNと後続VERIFIED、原署名/claim/三出力/child hash鎖/時間枠/currentを照合し、
旧byte改変・削除・同世代追加・未知file/schema・未終端・署名不明・current不一致を拒否します。
実18の既知schemaを人工byteで再現し、RAM鍵の成功を本番配布鍵の署名成功へ換算しません。
Debug/Releaseの影響target、収集限定ManagerとGUI固定分類・実resource、変更sourceの品質gateを確認し、
実HTTP・実GitHub公開・実installed/authority/credential/秘密鍵への変更は行いません。
署名配布物と利用者の実menu操作はG13-I7r308f/gへ残します。
最終Debug/Releaseは公開55case各3301条件（旧25/新30）、収集限定Manager各264、GUI分類/実resource各50が成功しました。
10sourceのformat差0、規約363control/0error、metadata正常、Doxygen102/102/未知診断0です。
included試験.cppの更新が旧TUを再compileしなかった原case9停止を保持し、既知三includeの明示依存を追加後、
両構成の新TU compile行と55case/EXE hashを確認しました。新TUの一時参照compile拒否とDoxygen原診断も保持しています。
証拠は`work/analysis/20261106-manual-publication-741`へ保存しています。実公開/実収集と配布更新はこの内部成功に含めません。

## 2026-11-05の私有定義ZIP

G13-I7r304／ADR0446は、Managerの`--definition-zip-only`限定fixtureで同一ZIP取込、
target/source/recordのappendと通常collector認識、元state/owner・日次期限・24h/Retry-After/host HOLD保持を確認します。
path逸脱/絶対path/重複/閉集合違反/symlink/reparse/CRC/展開量・entry上限、不正schema、既存source/recordの変更・削除、取消しを拒否し、
正しいZIPの次回取込が不正入力で妨げられないことを確認します。HTTP・資格・Startup・実installedは操作しません。
既存認証表示の有限回帰とManager Debug/Release・局所品質、現55 JSONのZIP原byte一致・未署名閉59file候補を確認します。
701の最終D/RはZIP限定各1328条件（不正archive14、旧source/record変更・削除4、取消しと再取込、追加target/source/record各1）、
既存collection-only各191、既存認証表示各22が正常でした。11sourceのformat差0、規約290control/0error、Doxygen56/56/0です。
閉59file/58宣言入力/他57非EXEの原byte・ISCC59入力を照合しました。初回include/comment不足とfixture側の絶対名生成・共有host期待の失敗を保存し、
補正後の成功と区別します。実target追加/実HTTPを行わず、原data・実資格/鍵を触っていません。
実install/GUIのZIP選択・取込と最終署名配布は主担当/利用者の別受入です。新targetの実通信成功は今回の人工追加に含めません。

## 2026-11-05の通常自動動作・認証結果表示

G13-I7r302／ADR0445は、GUIと同じ固定結果分類と最終Managerの実resourceをdatafileとして読み、
取消しの表示なし、入力／取込み／保存／prompt失敗の原codeと操作別案内、保存成功を非通信で確認します。
収集限定Managerの既存191条件をD/Rで確認し、日次原期限／対象待機と単一workerを維持します。
Innoの日次既定選択と既存入口の配線はsourceとISCC compileで確認し、実Startupを触るsetup全suiteは実行しません。
変更していない公開25caseや全native suiteは反復せず、実資格UI／実install／実公開は後続の受入へ残します。

## 2026-11-05の内容変更後native自動公開

G13-I7r300／ADR0444は、実Manager controllerから生成した候補、RAM RSA3072/PSS、実consumer全codec、
同じ保存二assetを扱う固定GitHub fake、通常client共通の匿名三resourceを接続して確認します。
25ケースでは正常／部分成功、内容不変の通常通信0、全失敗／取消し、資格／鍵不足、確定401、完全500、
CAS適用済み／未適用の切断、競合、署名出力欠損、原期限切れretired、旧claim／原receipt改変、pipeline排他、
空／別世代terminal、未追跡claim、remote asset改変、Release／upload／draftの不確定GET再照合を分けます。
送信中に時計を180秒進めた原Retry-Afterも受信時から7200秒以上保持し、入口時刻で短縮しないことを確認します。
再起動相当の通常workerから、再収集や24h変更なしのpending公開と元collection結果保持も確認します。
低位7ケースは認証付き初回／匿名redirect、EOF／途中read、取消し、private宛先、従量制拒否、原Retry-After／reviewを確認します。
人工authorityのACL／原storeはin-process seamで、本物C:運用configの非変更preflightとは別です。

実C: preflightは旧claim原byteの挿入順とnative key順の不一致を原exit2で保持し、原SHAと閉schemaを維持する
局所修正後、全旧履歴と最大LEGACY_FENCE10を既存native store/headへ照合して正常0を確認しました。
保護configのrepositoryRootを明示した同じ照合は`C:\Windows`のcwdからも正常で、processのcwdを変更しません。
この照合は設定保存・鍵操作・通信・installed data変更をしません。既存Startupを拒否するsetup全suiteは再実行しません。
最終Debug／Releaseは公開2282、収集限定Manager191、native544、protocol69条件が合格しました。
format16file差0、規約662control/8case/0error、Doxygen214/214/0です。
実HTTP、実credential接続、実配布鍵での新索引署名、GitHub write、EXE署名、実install／自然日次は今回の内部受入へ含めません。
検証証拠は`work/analysis/20261105-collector-auto-publication-690`へ保存し、主担当の確認と現場受入を別工程に残します。

## 2026-11-05の所有v2同場所更新・再install

G13-I7r296/ADR0441は、現C++ v2の同じ元配置での更新・正規解除後REMOVEDの再installを
非通信fixtureで確認しました。READYの旧program閉集合とowner旧hash対、REMOVEDの元binding/保護DACL/
解除票/dailyConsent=false、前確認取消しのread-only、host停止失敗、旧/新byte限定の中断再実行、
未知root/旧schema/別binding/旧program変更/異なるjournal/state変更の拒否を分けます。
日次設定の保持、明示解除、REMOVED未同意と明示enable、初回24hと保存済みの遅い期限を確認しました。

人工定義だけでなく、9fa版の保全bundleと681の原state（endedAtUtc/reservationあり）・旧54定義・
39familyの原結果を私有の新規所有rootへ配置し、同じ元位置に正しく結んだfixtureを使用します。
直前0d8版のREADY更新、同版再実行も別に確認します。ownerと旧3quota以外の全定義内容、原315bootstrap、
state/run/unsigned/result/lockの原byteと待機・nextDueを比較し、実現場のroot/Startup/Taskは操作しません。
preflightの保存日次trueは正常の終了値10、通常正常は0、期待拒否は2です。全process exit0とは記載しません。
現場dataのbindingをその場で変更したり、再取得・待機解除をしていません。

最終Debug/Releaseは各管理196・native501・protocol/形式35条件が合格しました。必要6TUを同じbuildで
fresh compile/linkし、変更6sourceは規約222control/0error・Doxygen13/13/0error・format差0です。
最終Release配布bundleの原manifest対でも9fa REMOVED/0d8 READY/同版の3私有ケースが合格しました。
Inno compile入力59fileとtemp/通常deployの同集合を照合し、実展開と区別しています。
確認証拠は`work/analysis/20261105-collector-reinstall-684`へ保存しました。原終端は同HANDLE/creation・
両EOF・元exitと強制停止なしを保持します。実Inno GUI/展開、Startup登録/解除・実ログオン/復帰・
自然日次・実HTTP・実際の速度は利用者受入とし、source/内部試験・私有未署名package確認と分けます。

## 2026-11-05の時間上限と最大3系列収集

G13-I7r295/ADR0440は全て非通信fixtureで確認しました。有限な人工対象を事前に固定し、
最大3の実重なりと4以上なし、遅い先頭より先に空き枠で後続開始、共有familyの一取得、
単一owner writer、部分成功・不正/不確定後の継続、host待機の即時共有を別に検証しました。
旧64要求/host32要求/metadata64MiB/payload2GiBの累積値はfake accountingで超過させ、
実転送や30分自然待ちを要求せず、全体/対象期限・取消し・例外時の全worker joinを確認しました。
nativeの一応答2MiB境界・超過拒否、開始済みread保持と次send拒否、429通知、
複数metadataの累積4MiB超過も確認しました。signature/hash/内容検査の既存境界は維持します。
最終Debug/Releaseは各管理144・native501・protocol/形式35条件で合格、変更8sourceは規約314control/0error・
Doxygen36/36/0error・format差0です。不確定stepは元errorが0でも成功へ進めず、観測下限とknown=falseを保持しました。
最終D/Rと変更品質、原終端・定義54/family39/原315record・私有packageの証拠は
`work/analysis/20261105-collector-time-only-682`へ保存します。実HTTP・実install・実速度は未確認です。

## 2026-11-02の導入済み参照と初回確認の表示分類

G13-I7r273/ADR0424では、元取得targetへの結合だけで版不明参照を更新候補へ算入した誤分類を修正しました。
画像相当の登録済み二device（現在版1.9.74.0・参照版空）はfilter ONで更新0となり、全候補と詳細で参照を保持します。
同scan/deviceの妥当なCode28観測だけを未検査の「初回の確認候補」として残し、導入可能候補数と分けます。
版欠損REGISTERED/UNKNOWN、旧session/別device/不正観測、同版・旧版、新版と同版の混在、WUA/Storeの正当候補、
同名別device、filter ON/OFF・明示選択・代表版を固定13条件226 assertion/0失敗で確認しました。
WUAの検査委譲を一律の独自検査済みと表現せず、最終captionは「更新・初回の導入候補」です。

最終Debug/Release App/UI/unit target buildはexit0、UIは両方hardware825/default735/binding230/index539/preparation380の失敗0です。
272の規約UI固定12条件も両方313/0で、初回二機能はfilter ONの検索→選択してInstallを維持しています。
UIのみの変更でunit byteが603と同一であるため、全unit各79,996/0の元終端を再利用しました。
変更5sourceのformat差0・規約986control/199case/0error、Doxygen4source202/202を確認しました。
初回赤試験と最初の補正試験は追加fixtureを既存固定planの前に置いた不整合で停止し、所有fake子の同handle/作成時刻で
exit81へ停止した原結果を保持します。追加matrixを既存固定条件の後へ移し、製品の単調session/plan検証は変更していません。
取得前参照にはdriverVersionがなく、配布releaseVersionから同版や適用性を推測していません。
実App・通信・実再検出・復旧・実導入・署名・Task/鍵・GitHubは0、通常outputの反映と利用者の実OS状態確認は未実施です。

## 2026-11-02の公式規約案内とInstallの内部確認

G13-I7r272/ADR0423では、検索後と通常公式Installの独立EULA dialogが0、選択時の画面内案内、
原出典/revision/全文の任意read-only閲覧と偽装IDYESの非実行を、既存private desktopの完全fakeで確認しました。
閲覧だけでは取得・同意・導入0で、選択変更/本文差替えからのInstallは取得前に停止します。
固定12条件は両構成313 assertion/0失敗で、共有payload一取得、既検証候補との混在、取消し/newscan/close、
取得・内容拒否、曖昧候補、未選択target、復元失敗時install0と既存個別結果を保持しています。
案内帯は通常幅/最小幅の実control座標と実fontの必要高さを確認し、任意全文の合成PNGを視認しました。
初回主画面PrintWindowのclient黒画像は表示受入へ数えていません。

必要Debug/Release App/UI/unit build、各全unit79,996/0、各UI hardware598/default735/binding230/index539/preparation380の
内部試験が合格しました。変更6sourceのformat差分0・既存規約0error、Doxygen対象5source/208memberの集合一致を確認しました。
実通信・実device再検出・実復元・実導入・署名・Task/鍵操作・GitHub操作は行っていません。
WUAの未受諾条件は従来の確認を維持しており、今回の公式EULA統合とは別です。
通常outputへの反映、主担当確認と利用者による新byteの実UI受入は、この内部確認から分けます。

## 配布周期と期限の差分確認

以下の旧保守pipelineの日次は未署名候補までです。ADR0444の明示有効化したnative自動公開とは分けます。新しい配布scopeは`projectionPolicyRevision=2`で、
取得recordの原期間は8日です。発行観測の24h未満、原recordの8日、実HTTPの24h待機を別に確認します。
prepare/sign/publishは実now+7日 < 全原期限minを共通検査し、境界ちょうどや遅延では
`CANDIDATE_WEEKLY_RECONFIRM_REQUIRED`で拒否します。旧scope1を新発行へ変換しません。
旧raw・原期限・原3record/2sourceの保存fixtureは書換えません。

`test_weekly_index_validity.py`はnative新規8日/発行fresh24h、週次境界±1秒、準備/署名/公開遅延、
短い一recordの拒否と原署名束・失敗terminal保持を人工入力で確認します。
nativeとの結合には新しい自己所有fixtureを生成します。明示test EXEと未存在の出力親を指定してください。

```powershell
py -3 -B scripts/test_distribution_native_fixture.py $PipelineTestExe $NewFixtureParent --parsed-producer-fixture --fresh-weekly-evidence
```

一段nestedの正例は`--nested-producer-fixture --fresh-weekly-evidence`です。
このflagは新しい人工根拠を生成して現producerのtyped観測を得る試験専用の指定です。
過去の保存fixtureを修正せず、HTTP/DNS/CAT信頼はfake、ZIP/INF parser/親子pipe/候補codecは実処理です。
`test_candidate_publication_native.py`へ生成先を明示すると、原byteの手動公開代役と通常appの
現在/7日後のlookup・取得・完全tuple bindingを確認します。元の153/154assertと7日後の分母を別に記録します。
OS時計・実端末・実通信・永続鍵・本番署名・導入・公開を操作しません。

元Intel archiveのhistorical検査は保存済み原manifest/GZipを明示します。
旧六入力を新policyで再投影せず、元期限での現在拒否を維持します。

## 0.1.1の確認履歴

最終公開snapshotのfresh全target/静的解析と最終配布物は未受入です。過去の成功を最新byteへ継承しません。
10月24日のv7中間成果物では、現在userのnative15時Taskと別同意distribution17時Taskの有効readback、
同Actionの直接実行、通常解除後の両Task正常不存在と44 data file/37,878,778byte保持を確認しました。
Scheduler Run/自然trigger・七日・再起動・別PCは未確認です。

固定Prolific一record/七既存製品参照の実取得はHTTP2要求/506,429byte、INF2件のCAT/publisher/全参照本体検査が成功しました。
元runはnested投影0です。その後のflat/一段nested identityと同payload複数recordの通常producer/codec/reader/
lookup/acquisition/bindingは人工試験で内部受入済みですが、fresh実collector投影は未確認です。
元actual nextDueAt=2026-10-25T03:21:15Z、課金/HOLDと原期限を保持します。
直近のPublic通常appは世代5の2026-10-19T13:24:11Z期限切れを拒否しました。有効な最新Public索引の
候補/版表示は未確認です。以下の10月19日などの実績はその時点の原結果です。

手動prepare/sign接続は既存保護root/lock/世代下限/native signerを使う内部検証で、新23試験と
flat/nestedのDebug/Release原byte→実unsigned codec→RAM通常app各153assertを確認しています。
追加全daily229件は修正前新main fixture一FAIL/既存209件成功を保持し、修正後新23成功と分離しています。
本番署名/新しい公開成功、実driver導入/復元へ換算しません。

工程383は現行の手動`publish-candidate`までをfake remoteで接続します。保存済み実Public世代5の
原1493byte manifest/3352byte GZipは、現nativeの`--distribution-verify-floor-history`で世代下限だけを
認証します。現行currentと全record historyの拒否は維持し、旧record reader互換を追加しません。
下限結果は世代数値だけで、record認証/取得receipt/grantではありません。追加HTTPは0です。

人工native六入力と汎用headの原wrapper/source/個別期限保持、誤pin/失効/衝突、部分upload、
署名/公開不確定、同byte headの再開、CAS意図後のwrite禁止と匿名wire/永続予算を有限試験します。
元三record/二sourceのfake公開原byteはRAM通常appの153assertへ、追加native一recordを含む四record/
三sourceは154assertへ渡します。追加Intel行は未照合のままcodec/保存を通し、元三架空deviceの
lookup/取得/照合は維持します。383時点ではIntel同行の通常app取得/bindingは未証明です。
原結果・失敗・byte pinは公開集合の外で保持し、上記の有限資格を検証結果として扱います。

工程385は保存済みIntel `intel-wired-31-2-2-win11` の原40,477,087byte ZIPと六原入力だけを使います。
原publication秒2026-10-18T16:32:04Zの明示historical fake sessionで現producerへ投影し、原全field/
全22公開ID/元期限2026-10-19T13:24:11Zを保持します。現必須nested空fieldは現producerが付与し、
旧record reader互換を追加しません。実現在UTCと原期限秒ちょうどの失効拒否を別に確認します。
`drivercrate_index_binding_tests --distribution-application-native-archive-fixture`
はmanifest/GZip/原archive/原規約document/固定scenario 0～3を明示したときだけ実行します。
RAM索引署名・隔離store・fake HTTP/device/rankと、元Windows INF/CAT/member署名APIを分けます。
内部argless native adapterは既存署名検証へ引数/返却値をそのまま委譲し、成功値を補完しません。
通常workerの混在guard、原record完全tuple、owned workspace/opaque bindingと直前再検証を維持します。

Debug/Release各四条件では、原e2fnの通常lookup→規約同意→取得/内容検査→候補1件（Intel、2.1.5.7、
2025/09/03）、誤byteの取得拒否、同意欠落のpayload未取得、21ID欠損copyの全tuple拒否を確認しました。
全72INFを分母に保持し、57内容合格/15構造拒否（各0x80070032）の全相対名と元診断を保存します。
e2fnの実CAT publisherと参照SYS/DLL二本を個別確認しました。他INFの拒否とpairの二失敗も保持します。
明示driver HTTP/実inventory/導入/復元/公開は0です。標準署名APIの証明書読取通信は許可・未観測で、
総network0とはしません。fresh収集/現在Public/この実PCのA1適合や通常画面成功とは別の有限受入です。
元archiveと六入力・原結果のpinは公開集合の外で保持します。driver本体はsourceへ含めません。

## v7のdata追加・別日次・停止移設の有限fixture（工程365）

同じEXE/modulesでAのみactive→B追加import→同じ保護日次dispatcher/run/buildを確認します。
Aの同日再送0、B実synthetic ZIP/INFからの新record、旧期限/世代保持、未同意/同意copy拒否、
非通信export/importと別rootでの明示再開・GET0を確認します。33件後続batchと停止最大課金は同じPython基盤のfixtureです。
新旧Task共存・固定Action/17時・有効readback・冪等・解除後不存在はFakeTaskだけで検査し、
実Schedulerは照会/登録/変更しません。HTTP/DNSとCAT信頼はfake、実ZIP/全INF/Models/parserと親子/pipe/leaseは実処理です。
実Task/七日/別実機/実CAT信頼・実driver導入/公開を有限fixture合格へ読み替えません。

## 2026-10-23のEnabled省略修正と通常ライフサイクルの有限受入（工程348）

ADR0394の九番目の既定値と、実原XMLとは別の一行挿入witnessを追加しました。同じ候補対の
両hashと原SDDLが保護ownerへ完全一致する場合だけ所有と認め、schemaとdisabled原pinは維持します。
全DOM契約、実Enabled、非実行を先行検査し、未知XML・false省略・API矛盾・容量/書式を拒否します。
唯一buildの影響6targetを両Debug/Releaseでbuildし、両5suiteは各5/5、user fakeはU01-U40各40/40です。
既存36caseと追加の正常ライフサイクル、7改変拒否、11XML/API/容量/書式拒否、disable後の原pin再確認を
含みます。変更3fileはformat差0、規約130control/41case/error0、正式Doxygen61/61/error0でした。

新bundle/未署名単体EXEの75file、seed8/runtime34、source/Release/ZIP/notice/license/checksum、
embedded75、default38check/19call、通常13条件/sidecar4と通常D/R ALLを確認しました。
旧347の有効Taskは全原byte・owner/plan/SDDL・非実行を再確認し、通常解除一回で削除しました。
初回348は製品install exit0の後、typed UserIdをSID文字列と比べる試験側のassertで停止しました。
固定一件のread-only診断で、typed値は現在userの短いaccount名、rawXMLは完全なSIDと確認しました。
他のtyped Action/trigger/settings・owner両pin/SDDLは全一致です。製品・assetを変えず、試験側だけを
rawXMLの完全namespace付き唯一SIDと現在token由来の閉じた三表記へ訂正し、人工正例3/負例8を確認しました。
原FAILとその20分期限を保持し、通常解除・保全後の別HARNESS_CAUSE_CHANGED phaseを一回だけ実施しました。

同じ元root/固定二名で、native/単体EXE双方の有効読戻し、全75配置byte、同版冪等、非通信validate、
配置済みUninstall.cmd相当の通常解除、両Taskの正常不存在がPASSです。configの不正JSON、seed、work内の
人工待機sentinel、未知fileもbyte保持しました。8native call/8固定Task query、Run/Stop/HTTP/旧Task0です。
二つの失敗fixtureは承認先へ各一回Moveし、19file/14directoryの相対byteを保持しました。
二回目Move後の予約込みread guardの原FAILも保存し、総1GiBの内側の予約振替後にhash照合だけを完了しました。
元の344/345/347と初回348の失敗を成功へ読み替えず、phaseや予算の期限も変更していません。

外側gateと通常解除は原stdout/stderr byte・argv/cwd/exit/EOFを保持し、integration内の子streamは
従来のdecoded textです。再packageとpayload README変更0。既存closure資格を再利用し、全855fileの
再hashや全closure再実行は行っていません。主担当349の最終確認も完了しました。
自然日次/七日/再起動/別PC/署名公開は未確認です。
以下は当時の原結果として保持します。

## 2026-10-23の原pin検査による有効化後の停止（工程347）

346のsourceと決定的回帰の主担当受入後、同じ唯一buildから新bundle/未署名x64単体EXEを生成しました。
74payload+manifest75file、seed8、CPython原34とsource/Release/ZIP/notice/license/checksumを確認し、
`--check-embedded`75file/child0、default38check/19callがPASSです。通常D/R ALLのdry/実buildは両no work、
normal13・sidecar4・source/binary24pinも一致しました。検査後repackとpayload README変更は0です。

345で保持したdisabled初回pending Taskは、旧manifest/payload/receipt/planを上書きせず、新native setupの
通常`--uninstall`一回で削除し、固定二名の正常不存在、program削除と13保持fileの全byteを確認しました。
解除後の人工fixtureだけを指定先へMove一回で保全し、18file/14directoryのrelative byte/hash一致を確認しました。
344/345の原FAIL・旧期限・元archiveは保持しています。新stateによる実収集の待機回避ではありません。

同じ元root/固定二名の新20分phase・各native180秒を一回実行しました。最初のnative installは有効化後に
`USER_TASK_XML_ENABLED`/exit2で停止し、外側はexit1です。有効/state3/instance0の一件と所有receipt/plan、
bundle一致の全75配置を保持し、もう一件は正常不存在でした。完全な有効読戻し、同版冪等、非通信validate、
通常所有Taskの解除/data保持、単体EXEからの導入と配置済み`Uninstall.cmd`相当の解除はNOT_RUNです。

保存済み原XMLは`Settings/Enabled=true`を省略しています。明示Enabledの一行だけを戻した仮想XMLが
保存済みownerのdisabled/enabled両hashへそれぞれ一致し、省略以外の全byteと原SDDLは一致しました。
これは原因の証拠であり、仮想XMLをTaskや所有記録へ書き戻していません。未登録NewTaskへ原XMLをloadした
設定なし/false/trueの再出力も記録しましたが、いずれも原XMLまたは保存済みowner hashを再現しませんでした。
このprobeは実Task照会/変更0で、製品修正や実Task受入ではありません。

原stream/argv/cwd/exit/EOFと段階は347の保守記録へ保存しています。外側と初回pending解除は原byte、
integration内のnative子streamはdecoded textです。追加Task変更・再install・Run/Stop/HTTP・旧Task照会・
署名/公開・対応増は0です。生成物はTask未受入・再修正後差替予定で、自然日次/七日/再起動/別PCは未確認です。
下記345/344/342の記録は当時の結果として保持します。

## 2026-10-23のseparator修正と再受入の原失敗（工程345）

新`withCollectorSetupProtectedFile`内だけで入力pathを所有copyし、`make_preferred`でseparator表記を
揃えました。祖先・実file・継承親へ同じ値を使い、共有実path/ACL/reparse/単一link検査は不変です。
同じ保護通常fileのbackslash/forward/混在、Unicode/空白と、dot/親参照・hardlink・不適格ACL・reparseを
実helperで検査しました。Debug/Release各6targetと両5suiteがPASSで、workspace19＋bootstrap57、
新user fake32、旧cleanup26case/71assertion、transport4case/20check、admission8group/88checkを区別します。
変更2fileのformat差0・規約98control/error0、正式Doxygen7file/63member/error0を確認しました。

保持workspace容量の回帰はADR 0401へ対応します。
`test_collector_distribution_data.py`は原byteへbindingした有効data三世代の実合計72MiB超をimport/検証し、
256MiBの保存中ピーク境界と一byte超過、8192entry、既存世代増分0とactive pending、初期scaffolding、
一file超過/hardlinkと可搬inputの従来16MiB/64MiBを検査します。容量拒否時はactive/全世代と全file指紋の
不変を照合します。総input境界の大きい研究索引だけは試験内で生成を置換します。
`drivercrate_collector_setup_workspace_tests`は実保護fixtureと固定fake子を使い、64MiB超/256MiBちょうどの
native事前/最終検査、総量超過と従来package/embedded上限を確認します。
実運用rootへのimport/verify、最終配布物、実Task/HTTP/driver導入の受入を代替しません。

修正後のfresh bundleは74payload+manifest75file、seed8、CPython原34とsource/Release/ZIP/checksumが一致し、
新しい未署名x64単体EXEの内包75file検査とdefault38check/19callがPASSです。通常D/R ALLのdry-runと
実buildは両no work/exit0、normal13・sidecar4を確認し、残存embedded EXEを通常profileのtargetに数えません。
同梱READMEは生成時点の説明のまま固定し、検査後に再packしていません。

工程344の失敗fixtureだけを、元native終了・固定二名の正常不存在・新plan/所有receiptなし・全file pinを
確認して一度退避し、全81fileのrelative byte/hash保持を確認しました。同じ固定二名と元導入先を再利用し、
修正後のsource/assetによる別の20分phase・各native180秒を先行固定して一回だけ実行しました。
最初のnative導入は`USER_TASK_CONTRACT`/exit2で停止しました。Task一件はdisabled/state1/instance0、
もう一件は正常不存在で、先行planあり・所有receiptなしです。有効読戻し、同版冪等、非通信validate、
通常解除/data保持と単体EXE自身の導入/解除はNOT_RUNです。Taskを名前だけで削除せず全状態を保持しています。
原XML/SDDLと未登録の期待XMLの構造差を保守側の証拠へ残し、追加修正や再installは行いませんでした。

新成果物もTask未受入・再修正後差替予定です。初期harnessの引数渡し失敗、診断harnessの日時型変換と
単一差分assertの不成立も保持し、製品成功に数えません。外側gateは原byte/EOF、native子はdecoded textです。
実Run/Stop/HTTP/driver/署名/公開、旧Task照会、対応拡大は0です。下記344/342の記録は当時の結果として保持します。

## 2026-10-23の新packageと実Task受入の原失敗

工程344で新bundleの74payload+manifest=75file、seed8file、CPython原34fileと全文license、
source/script/通常Release実byte、ZIP/checksum、未署名x64/版を確認しました。
新単体EXEの`--check-embedded`は75file/child0/network0、default試験は38check/19callがPASSです。
各旧caseのNOT_RUNは維持し、旧三staging全byteや実runtime importへ拡張しません。
通常Debug/Release ALLのdry-runと実buildは両no work/exit0で、normal13、現sidecar4、
受入済み342のnative12binary全hashは不変です。通常profileにはInstaller targetがなく、
build内に残るembedded EXEを通常版binaryと数えません。

実Task試験は最大二名を先行固定し、全二名の初期不存在を確認しました。
最初のnative導入がexit2/`WORKSPACE_HANDLE_PATH`で停止したため、ライフサイクルはFAILです。
製品の`bin/DriverCrateCollector.exe`を含むpathとWindowsの最終backslash表記が一致しないことを
read-onlyの実handle8条件で確認しました。Task登録前の停止で、二名は失敗後も正常不存在です。
部分配置75fileのbundle一致と配置receipt保持を確認し、新user plan/所有receiptは未作成でした。
新単体EXE自身の導入、enabled/readback、同版冪等、非通信validate、通常解除/data保持はNOT_RUNです。
Run/Stop/HTTP/driver/署名/公開は0で、製品修正・再導入・fixture移動は行っていません。
新成果物はTask未受入・修正後差替予定です。原stage/argv/streamと二名の観測は344工程記録へ保存します。

相対build指定の拒否、analysis harness起動二件、EXEへdirectory用validatorを使ったtest入口の拒否、
read-only診断helperの配列構築失敗を原FAILとして保持しています。同一物理先の絶対path表記、
既存file用validatorへのtest入口修正、helperの括弧訂正だけを行い、製品の原失敗は成功へ変えていません。
test子processのstreamはdecoded textであり、原byteとは主張しません。外側gateの原byte/EOFは別保存です。
通常のcase-insensitive Windows rootでの有限試験で、case-sensitive別objectへの所有metadata一式copy、
自然日次・七日・再起動・別PC・全seed生成・署名・公開・実driver導入は未確認です。

## 2026-10-23の新user日次Task sourceと有限な確認（工程342時点）

ADR0394の最新v6通常installは実Taskの有効登録まで
接続するため、従来v6正常install/uninstallをTask0のdefault試験として実行しません。
`test-collector-installer.ps1`/`test-seeded-collector-package.ps1`のdefaultは検査だけで、
v6正常系をNOT_RUNと記録します。製品入口にtest bypassやno-op Actionを加えていません。
`test-collector-user-task-integration.ps1 -AllowTaskRegistration`は、先に固定した新root/SID由来の
最大二名だけを使い、native/単体EXE install→完全定義・有効状態・所有pin→同一版冪等→
uninstall→正常不存在・data hash保持を将来due前に確認する別入口です。今回実行していません。
旧Task照会、全Task列挙、Run/Stop、HTTP、driver導入、鍵、公開は行いません。

新unitのU01-U32はfake backendの有限32枠です。登録/部分失敗/修復/解除の操作順序と保持を確認し、
実COM権限・Task登録を代替しません。U05/U06は同意/版dispatchの呼出し側を表すfake観測、
U29/U30は旧所有境界を表すfake拒否、U31はmetadataのmemory分離であり、実UI/旧schema/seedそのものの
受入ではありません。旧cleanup・workspace/transport/admission回帰、一般receipt-v1/v2/未知schema拒否、
旧registrar fakeと公開候補閉包を別に対応づけます。config形式不正は登録を拒否し、解除では設定を保持します。
変更sourceは通常Debug/Releaseの影響6target、両5suite（新32枠を含む）、Python一般reader36、
旧registrar fake145、旧PowerShell synthetic30で有限確認しました。実collectorの非通信validate4例も
新しい人工rootで確認し、state/lockの新規作成は0です。変更7fileのformat/規約、Doxygen6file63member、
PS6file構文と855fileの静的公開候補閉包を確認しました。内側の追加失敗変異を32枠の増加に数えません。
両構成の最終build/変更gateと未実行の区別を工程記録へ保存します。全unit/全CTest/全対象の再実行合格、
実Task/変更後EXE・自然日次・七日・再起動・別PCの受入を、このsource/fake確認から主張しません。

## 2026-10-22の単体EXEとfile入口の有限再確認

未署名の現単体setup EXEはSHA-256
`86c8db753adc27f2f453fe13e0898675ed990ade0df12876dd9d28642bbebdd2`に固定し、
修正した人工中断用file補助と新規fixtureで47呼出し／382確認を完了しました。
期待exitの内訳は正常0が12、目的人工中断1が1、拒否2が34であり、47件の通常成功という集計ではありません。
人工FILE_SAVEDのmarkerと保存物、同じsnapshotのresume／verify、非所有の解除と14file保持を確認しました。
管理program5fileは解除後に不存在でした。旧人工中断の失敗と後続未実施の原結果は保持しています。

この再確認でC++、CMake、製品script、台帳／dataと三配布物は変更せず、
配布に含まれないtest補助だけを変更しました。Task確認はfresh非所有rootから固定二名を読む経路に限定し、
登録・変更・無効化・削除・run・stopは0です。実所有Taskの削除、日次七回、別PC移設、実導入と
新しい公開反映は未確認です。下記の379確認は各節に示した当時の版の履歴として残します。
固定source、asset、元argv／rawと個別受入記録は公開集合の外で保持し、公開承認と分けます。

## 公開source自身の全CTest並列予算（2026-10-21）

公開候補をCMake sourceへ固定し、唯一のNinja Multi-Config buildで全targetをDebug／Releaseに
buildした後、各構成で`ctest --test-dir build -C Debug --output-on-failure --parallel 2`と
`ctest --test-dir build -C Release --output-on-failure --parallel 2`を実行します。
`drivercrate_collector_projected_http_tests`、`drivercrate_collector_segment_preparation_recovery_tests`、
`drivercrate_collector_operation_capacity_tests`、`drivercrate_collector_cache_startup_tests`は
保護file I/Oの重い独立partitionで、CMakeの`RUN_SERIAL TRUE`により他の全testとの同時実行を禁止します。
元の各300／600秒、全73件、assertionとsource rootの作業directoryは維持します。
UIの既存RUN_SERIALも維持し、live testは無効です。過去parallel 12のtimeoutに対する
直列成功は条件差として記録し、過去の瞬間負荷の内訳は断定しません。
全受入工程は実開始から90分のUTC絶対期限とし、終了前最低5分を通常profile復帰・証拠保存へ予約します。
工程予算停止は製品失敗や成功へ読み替えず、同条件の失敗再実行を行いません。

## collector単体EXEの有限非通信確認（2026-10-20）

ADR0387のv6は74payloadとmanifestの75fileをraw RCDATAへ埋め込み、同梱CPython 3.13.16と
最新日次scriptを含むWindows x64の未署名EXEとしてローカル生成しました。公開配布ではありません。
保存前に全親を実handle/ACLへ結合し元Win32 codeも保持する最終c3t6版で、実EXEの改変・閉包拒否、外部Pythonなしの
fixture配置・非通信workspace・解除/data保持を379 checks/47 processで確認しました。
旧ZIPの合格を単体EXEの合格へ換算していません。

新local入口の13件は人工保護原点とnative fakeだけです。新200/実304相当のreceipt、
FRESH_INPUT、同一state、四file/hash結合、HOLD/NO_NETWORK/未知/部分保存/有限timeoutを確認し、
本物通信や本PCの運用索引生成の成功とは数えません。config9fieldと非可搬origin metadata、
admin保護operations内の結果jobだけを使い、新state・予算・待機resetを許可しません。

Debug/Release全targetと関連native五件ずつ、Python216件（215成功・1skip）、
旧v1 setup74 checksとv6 seeded270 checksを有限に確認しました。skipは
`test_native_validated_v4_and_stopped_monitor_import_save_one_page`で、別target生成の
`DRIVERCRATE_NATIVE_SCOPE_FIXTURE`未指定が理由です。seeded試験自身のcollector validationと
runtime実行はNOT_RUNで、runtimeの実行証拠は実EXE試験へ対応させます。

設計のB10/V7/L13の30familyを分母に残し、部分variantを全合格へ丸めません。
B05の同時差替え全interleaving、B07の実disk-full/short-write・外側180秒timeout等、
L04の本物の運用approval ACL、L08の既存署名索引の失効再検証は未実施です。
旧daily全99件を誤って含めた初回束は195.459秒で中断し、未完のまま保持しています。
未変更dailyを除く明示focused集合へ変更した後の216件を最終の関係回帰とします。

当時の入口は`test-collector-installer.ps1`と、後に廃止した旧local-index fixture、および
関連native setup unitです。閉集合・元Win32 code・保持/解除・30familyの部分variantを分け、
実行ごとのasset/source pin、command原本と品質結果は公開集合の外へ保存します。
全unit/全CTest・UI全suite、実運用既定先への導入・実HTTP、鍵/署名/Task/GitHub/driver操作は
このc3t6当時の工程では行っていません。後続の有限受入と本PC実収集は末尾の記録と区別します。

## 現在の通常画面と公開索引の有限確認

2026-10-27の限定是正で、履歴headの下限認証と現在snapshot復元を分離し、匿名readbackの
既存daily/candidate名pairを一致させました。現rootのDebug/Releaseでunit/app/collectorの必要対象を
buildし、store 353・manifest/asset/HTTP境界718・record/descriptor 800・lookup/取得adapter 2580の
assertionを各configで確認しました。名前pairの26正負assertionを含みます。
これは最終公開snapshotの全target fresh buildや新配布assetの資格ではありません。

同じ本番storeのroot/ACLと下限5を保持した通常アプリ一回のscanで、HTTP200・更新診断0・commit成功・
manifest9/保存9を確認しました。元gen5 ciphertextはAdmin/SYSTEM限定の別backupとして保持しています。
実PnPは258件、署名索引は2/2recordを読み、未判定関係48、取得対象0/不足未対応48/保持枠超過0でした。
索引候補0を更新不要や不適合の判定へ換算しません。実driver取得・導入・復元は行っていません。
アプリは通常closeし、元の同じprocess handleでexit0とstdout/stderr両EOFを確認しました。
新local collectorの匿名read-only確認では公開済み世代9の三resourceが原hashで一致しました。
元publisherのUNKNOWNを成功へ書き換えず、保護runtime更新・再発行・再署名・期限延長・remote変更は
この確認へ含めていません。変更sourceのfresh公開資格と公開反映は別工程です。

2026-10-19に、初回公開source 822 fileをローカルで検証して公開し、Publicへ署名索引の
manifestと圧縮JSONを配置しました。通常アプリはローカル受入option OFFのまま、HTTP 200、
manifest世代5と保存世代5を確認しています。旧検証用storeの実署名認証・用途別移動と元byte・
世代下限の保全も確認しました。公開Releaseは索引assetだけで、アプリ・collectorのbinaryは未配布です。

通常画面で対象を1 packageに固定し、40,477,087 byteを16.085秒で取得して内容検査へ到達しました。
72 INFのうち57件が内容・署名検査に合格し、15件は未解析・未対応として分母に残っています。
最初の個別不足は`0x80070032`です。system照合57組のうち3組が合格、判定不能0で、
同じ1機器への標準INF旧版候補3件を発行しました。候補は未選択、実導入0です。
全体部分結果・個別結果を保持し、archive全体、全機器、更新推奨、実導入成功へ換算しません。

期待package hashは公開recordから別照合しましたが、補助readerが取得fileのdigestや個別CAT署名者を
別採取した結果ではありません。内容入力到達は製品の封印・実byte/record hash照合経路を通った証拠です。
結果保存後の補助readerにはclose済みchildを読む後処理raceが残りました。原exit 2を保持し、
通常appのexit 0と保存済みの取得・検査結果を製品取得失敗へ読み替えていません。

部分結果resourceの一律「導入経路は未接続」は候補別導入可否を確認する文言へ修正し、人工UI回帰で確認しました。
同修正後の追加live取得は行わず、内容処理不変の根拠と元実測を分けています。
公開変更ごとの固定snapshot全build/testと主担当確認は別途必要です。Public日次publisherの実運用は
未受入です。local-only日次Taskの実接続は末尾を参照してください。日次七回・再起動・別PC移設、実導入と必要Extensionの
個別反映、有限対象外の対応不足は未確認として残します。

## 変更箇所の決定的回帰

署名索引の候補binding回帰は、`drivercrate_index_binding_tests`をDebug/Releaseで実行します。
通常aggregateの`drivercrate_unit_tests --index-candidate-binding`からも同じ候補群へ到達します。
人工の配布申告版1.2.3.4、現在版0.9.0.0／1.0.0.0／2.0.0.0、検証INF版1.0.0.0を分け、
取得前行の版・日付・発行元・package状態が現在行から補完されず、端末表示情報だけを保持すること、
取得後は検証INF値と更新・同版・旧版・初回の分類を保持することを確認します。
同意前の導入拒否と既存の失効・部分結果の試験を維持し、人工成功を通常画面の実取得へ換算しません。

`drivercrate_metadata_ui_binding_tests`は既存六条件に、発行済み候補を残した部分内容結果の表示条件を
加えています。正常なfixture worker由来の一候補と、合格1/2 INF・未対応0x80070032の人工表示summaryを
同じ通知で処理し、下部controlの部分結果、候補別導入可否、件数・HRESULT・未選択・導入前の状態を
確認します。全件未接続の断定や導入成功への読み替えを拒否し、この追加条件ではfake導入も実行しません。

署名索引storeの変更回帰は、通常の同一build treeで`drivercrate_unit_tests`をDebug/Releaseに
buildし、各EXEの`--signed-index-store`で既存保護store群と認証移行群を実行できます。
人工RAM署名と自作NTFS/DPAPI sandboxだけを使用し、固定ProgramData、実鍵store、通信、
実driver導入を使いません。旧production/localの分類、元root消失後の再実行、既存先競合、
暗号byte/identity/floor保全、期限切れ履歴、世代rollback/同世代衝突、未知鍵/破損、
移動前後の中断、root/lock競合と旧store再出現guardを含みます。製品鍵の真署名や通常画面の
受入をこの人工試験へ換算しません。実移行CLIはこの自動試験から実行しません。

DriverCrateの決定的な試験はnetwork、実Windows Update、実driver導入に依存させません。
Provider、復元ポイント、低位Windows APIのfakeを使い、人工のID・URL・packageを使用します。
実端末のinventory、credential、取得payloadをfixtureへ入れません。
コード接続、人工試験の合格、有限な実取得、実導入、実配布は別の到達段階です。

2026-10-19のG13-I7r231h14r9では、日次取得経路のcallerだけを既存の整数UTC秒契約へ接続しました。
実壁時計は小数秒を保ち、完了時の投影・初回公開時刻・署名前監査・current/readback監査の入力だけを
秒へ切り捨てます。保存済み公開時刻、元観測、notBefore、排他的な期限、FRESH_INPUTと有限予算は維持します。
非0小数秒の200/304 cold準備と、実production関数を使う人工発行・公開・同byte再利用の新2 method、
関連する旧26 methodが直接合格しました。整数UTC秒validatorの拒否と旧126 methodのASTは不変です。
修正前の新2 methodの2 ERROR／2 FAILは原rawに保持し、全suite・実署名・実配布の合格へ換算しません。
実partialのreview欠損は依然拒否され、実再開・通常画面の正常例・全Goalは未完了です。

## h10時点の技術受入（履歴）

以下はh10で結合した当時のsource/pinと817候補のsnapshotです。後続ADR 0373／0374で
変更したPython sourceへ、そのまま全case成功を引き継ぎません。今回の直接回帰は後段に分けます。

2026-10-18の現sourceは、自作780 file（native 656、Python 90、PowerShell 22、その他12）です。
長path修復前の主担当受入済み品質と、その後に修正したnative八件の受入証拠を、現在のpath・byte数・
SHA-256へ結合しました。必須formatter・metadata／規約の656件、Doxygen対象652件について
現在hashに対応する証拠の欠測はありません。後続八件には、実XMLの非空member・関数・型・alias集合と、
XMLへ現れないlocal型／fieldのsource契約の確認を含みます。これは有限なgateと個別reviewの受入であり、
数字だけで全sourceの意味や全機器の動作を保証しません。今回の再結合では必須gate・unit・native・buildを
追加実行していません。統合結果は主担当が独立照合して受け入れています。

| h10時点の集合 | 結合した結果と条件 |
|---|---|
| Python／CLI／PowerShell | 下表の1,181固有case・CLI 27・PS 144 check＋guard 69は対象source不変の証拠を継承。手動PS五入口のNOT_RUNは維持。 |
| Native 144 | 通常構成の非UI 118 PASSと、private desktopで実行した元UI 26 PASSを資格付きで継承。最終UI PEで元26を再実行した結果ではない。 |
| 新しいUI境界制御 | 限定補正後のDebug／Release各一回、各30期待・失敗0を別枠で受入。元144の件数へ追加しない。 |
| x64 build | 既存の通常Debug／Release全targetと、後続の対象buildを現source・70 PE・123 compiler依存・786 build入力へ結合。31観測入力のmanifest一件は許可文書追加前のpinで、追加後は817候補の現pinへ別結合しています。全31不変とは扱いません。新しい独立export checkoutのbuildは未実施。 |
| 公開候補 | ADR 0372を含む817 path。静的source依存の確認対象であり、`finalAllowlist=false`の候補。公開承認やfresh buildの代用ではない。 |

ADR 0372の自己supervisionはUI試験専用です。
同じ試験EXEの子を起動時にprivateな非入力desktopへ所属させ、元のargv・作業directory・600秒property・
453の元期待を保持します。実MainWindow・workerの所属と、同作成handleのPID／作成時刻／終端を確認し、
所有job・handle・desktopを回収します。環境markerのkeyは完全一致・大文字小文字非依存で処理し、
modalのPID／thread不一致はmessage照会前、操作条件不成立はclick前に拒否します。
実20ms timerのYES=6／NO=7を確認しています。ユーザーdesktopの切替・入力遮断は行いません。
通常アプリの実GitHub／実端末／目視受入を、この人工UI試験で代替しません。

原143 PASS／1 FAIL、Debug closeの51期待中3失敗、旧制御の失敗は原記録へ保持しています。
後続成功から原失敗原因を推定せず、原因UNKNOWNを維持します。原条件の全診断を再開することは、
独立した通常アプリ受入の前提にしません。

### 長path修復前の受入履歴

2026-10-18の長path修復前のsource／コメント整理では、自作780 fileの固定集合について、必須のformatter、
metadata・規約、Doxygen member集合gateと決定的unit／CLI／UIを資格付きで技術受入しています。
以下はその時点の結果です。後述の長path修復後の有限試験と区別します。

| 集合 | 受入結果と条件 |
|---|---|
| Python | 44 module、1,191 slot、1,181固有caseがPASS。元の失敗・ERROR・SKIPを保持し、訂正tailをcase IDで結合した結果。 |
| Native | 修復前の144登録caseがPASS。その入力と一致する78件の継承と、事前固定66件の実行を区別。後者に実group `Ui` の26件を含む。 |
| 単独CLI | 27 caseがPASS。fixture生成を含む28子processの実終了値は正常6件が0、期待拒否22件が2。全子exit 0ではない。 |
| PowerShell | 四moduleの144 checkと既受入guard 69。元三件と別保存の第四訂正tailを結合し、元observer exit 1を保持。 |
| x64 build | 修復前入力に結合したDebug／Release各85 targetの既存build結果を継承。公開用exportからの新しいbuildとは別。 |

任意の宣言監査はexit 1／47件、strict Doxygenはwarning 3,643件、移行診断は43 tupleを残しています。
R123の実headerの九つの順序付き`@param`と`@return`は確認済みですが、Doxygenの警告発生機構はUNKNOWNです。
必須member集合gateの合格を一般warningゼロと呼びません。手動PowerShell五入口はNOT_RUNで、
全入口成功や最新版installer受入へ換算しません。有限試験は全OS I/O、全race、全機器の保証ではありません。

以下は長path修復前の受入当時の状態です。通常画面の後続実測は冒頭へ分けています。
通常製品の固定配布公開鍵と独立revision1取得policyは
sourceへ登録済みで、ローカル受入optionは既定OFFです。過去の受入profileの鍵・同意・期限を
通常配布へ引き継ぎません。実driver導入、必要Extensionの個別反映、
実GitHub→通常アプリの正常例、日次継続と別PC移設は別の未受入事項です。

長path修復前のソースに対応する収集用ローカルv5 packageは、h8q／h8qvで69 payload／70 fileの固定成果物を受入済みです。
このPCで展開・配置・検査・保持／解除、非通信の初期化・検証・停止export／importと、人工FILE_SAVED中断からの
native再開を確認しました。新しい空のローカルmonitorによる確認で、実正本の運用履歴や別PC移設ではありません。
未署名previewであり、確認なしrun-onceのexit 2拒否と、同梱moduleのfake同意／admission拒否2件のtransport 0を
確認しています。確認を伴う実オンライン開始・実正本bindの受入や、五つの手動PowerShell入口の実行には数えません。

### 最新collector packageの非通信受入

2026-10-18に、現行Release collector/setup、現module、固定CPython原archiveと研究seedから、
新しい未署名v5 packageを一回作成しました。旧h8q packageの合格をこの成果物へ流用していません。
識別情報は次のとおりです。ローカル検証用の成果物で、download用Release assetはまだありません。

| 項目 | 実測 |
|---|---|
| ZIP名 | `DriverCrateCollector-0.1.0-windows-x64-preview-48299785f3a546ce91c3143657cc2599.zip` |
| ZIP byte数／SHA-256 | 13,284,530／`52ac17a747b637b0867f432e0bd2e6a3977e70f327ca61a19db5371e4ccccdc8` |
| payload／manifestを含むfile数 | 69／70。payload合計40,319,669 byte。ZIPのdirectory entryを含めると72 entry。 |
| manifest byte数／SHA-256 | 11,549／`a371f43ebd45df7b17dced2691aeba974b68a7ec7c4225065c938d82b64e6d2b` |
| runtime／研究seed | CPython 3.13.16 x64原34 fileと全文license／notice・`._pth`を原byteで保持。snapshot v4の8 JSON、127メーカー／6,584製品／1,718研究record、388 locator。 |

事前固定した集合の全入力・package本文・ZIP本文・展開fileをhash照合し、余分なfileがないことを確認しました。
setupの共通cached-only検査で原PSF四fileを受理し、DriverCrate自身のbinaryは未署名previewです。
研究seedの`researchOnly=true`、`publishable=false`、`installAuthorized=false`、
`applicability=NOT_CHECKED`を維持します。seed内の旧取得件数は今回の実収集や端末適合へ数えません。

実同梱setupで展開検査・新規配置・配置後検査、非通信initialize／verify、停止export／importと移設先verify、
人工FILE_SAVED中断からの同一snapshotの明示resumeと再verifyを確認しました。
実run-onceは確認flag不足の入口拒否（exit 2）だけを実行し、別の同梱module fake二件は同意拒否／
admissionなしHOLD・transport 0です。確認を伴う実run、実正本bind、Task登録、実通信は行っていません。
通信許可false・native制約UNKNOWN・元日予算UNVERIFIED・originなしを保持しています。

新規の別uninstall fixtureだけで固定管理program／receipt60 fileを除去し、config・seed・setup・
Uninstall.cmdの11 fileを保持しました。元ZIP、元package、展開元、独立した配置先は復旧元として保持しています。
旧成果物・既存親ACL・本番stateは変更していません。操作のargv・CWD・PID／作成時刻・同handleの待機／終端・
終了値・rawを保存しています。子processの観測は有限な10ms間隔で、全OS I/Oやnative sandboxの証明ではありません。
空の新規ローカルmonitorを使った同一PC確認であり、実運用履歴の移設、別PC、七日運用、通常画面の
実GitHub／実端末正常候補、実導入の受入とは別です。主担当は現物の保存384 file、ZIP69 payload、
原runtime34 file、実15起動と現780 sourceを独立に実読・照合して受け入れました。
保存時の既読hashの継承と、主担当による現物の再読は別に記録しています。

## 開発環境と再現

Windows x64、Visual Studio Build ToolsとWindows SDK、Ninja、CMake 3.30以降を使用します。
通常アプリの実行時にPythonや外部frameworkは必要ありません。開発用Pythonは3.10以降です。
Doxygenは1.10.0を使用します。
repository rootをcurrent directoryにし、x64のVisual Studio developer shellで実行してください。

G13-I7r255h0dでは、保存済みIntel Ethernet本文を非通信で同じparserへ通し、
SHA-512単独掲載の解析と共通record/grantへの保持を確認する。関連unitの
`drivercrate_unit_tests --intel-ethernet-metadata`は、両hash掲載・欠損・改変・重複と
誤製品/OS/hostの拒否を合成HTMLで確認する。これは実取得や内容検査の成功ではない。

```powershell
cmake --preset windows-x64
cmake --build --preset debug
cmake --build --preset release
ctest --preset debug
ctest --preset release
```

build treeは`build/`一つです。両構成を同じNinja Multi-Configで生成し、generatorを混在させません。
開発Privateを正本とし、GitHub Actionsを通常運用の確認経路にしません。
公開snapshot自身で両構成と必要なPython／PowerShell入口をローカル確認します。
live testと解析optionは通常OFFです。通常buildへ受入用公開pin・署名toolを追加しません。
初回configureは固定版・固定hashのminiz／LZMA SDK sourceを取得する場合があります。
これはbuild依存の取得で、決定的なunitの実行時にdriverや公式pageへ通信する要件ではありません。

## 必須source gate

G13-I7r263 / ADR 0416では、既存の非通信MainWindow UI試験を
カテゴリ→deviceの二階層・一device一行・四列へ更新する。同名の別device、現在属性優先、
metadataと検査後候補、複数候補の明示指定、一device一計画、推奨filter/全解除、失効後の個別結果を
確認対象とする。詳細の実combobox・選択button、閲覧時の選択不変、現在構成の選択拒否も確認する。
既存の署名索引/共有取得/初回/必要構成/部分失敗/stale worker UI群は残し、診断と必要構成の期待を
主一覧の子行から同candidateの詳細表示へ移す。これは非通信fixtureの受入であり、通常実機の
最新byte受入・実導入・署名配布物の更新とは区別する。

Python launcher、clang-format、固定Doxygenを利用できる開発環境で次を実行します。
`$DoxygenExe`は、事前に存在と版1.10.0を確認したDoxygen executableの絶対pathを設定する変数です。
PATHのclang-formatが使えない場合は、formatterの`--clang-format`で確認済み実体を指定します。

```powershell
py -3 -X utf8 -B scripts/test_source_style.py
py -3 -X utf8 -B scripts/format_source.py --check
py -3 -X utf8 -B scripts/check_source_standard.py
py -3 -X utf8 -B scripts/test_doxygen_members.py
py -3 -X utf8 -B scripts/audit_doxygen_members.py --check --doxygen $DoxygenExe
```

規約本文、独立file版、旧履歴、Copyright／Apache-2.0節、制御文・宣言説明、field／enumの前置`///`と
XML抽出集合を確認します。Doxygenの近傍コメント数だけではmember gateを代替できません。
[採用規約](c_cpp_coding_standard.md)と[契約・当時の移行結果](adr/0141-revised-source-standard-contract.md)を参照してください。
任意の`audit_source_declarations.py`やstrict設定、一括移行writerは必須source gateと別です。
一般warningや未解決tupleを、説明不足ゼロや移行済みへ自動変換しません。

## Python、CLI、setupの試験

各`test_*.py`の対象と入力条件を確認し、必要な試験ファイルを明示して実行します。次は公開用ソースの閉包を確認する非通信試験です。

```powershell
py -3 -X utf8 -B scripts/test_public_source_closure.py
```

`scripts/check_public_source_closure.py`は候補一覧の静的なsource／fixture／import／固定payload依存を
確認するtoolです。動的pathの完全証明やnative buildではありません。
現在の候補ファイル一覧と検証条件は `scripts/public_source_export_manifest.json` で確認できます。
各リリースは、その時点の公開対象を使って検証します。

## 公開snapshotのローカル事前確認

ADR 0379に従い、公開前の確認をローカルで行います。
Private working treeの既存build・増分試験の合格と、公開snapshotからの新しい検証は別に記録します。
初回公開822 fileはDebug全72件の結合受入（元68件と条件変更後の直列4件）、Release全72件、
Python43入口と必要source／PowerShell gateを確認済みです。Debugの元並列8による3 FAIL／1 TIMEOUTは
履歴に残し、一回の全72件直列runと表現しません。変更後の公開snapshotへ自動継承せず再確認します。

1. `scripts/public_source_export_manifest.json`の具体的file集合をレビューし、最終公開対象を固定します。
   `.git`、Actions workflow、work記録、鍵・credential、実inventory、driver本体、個人絶対path、
   build成果物・PDBを含めません。必要文書link、画像metadata、license／noticeも監査します。
2. 次のcheckerでpath・byte数・SHA-256と静的依存を保存し、その集合だけを独立directoryへコピーします。
   `$ClosureReport`には公開集合の外にある未存在のローカルreport pathを指定します。
   コピー先では別の未存在report pathを指定して同じcommandを実行し、全file pinと`sourceSetSha256`の一致、
   余分なfileがないことを確認します。

   ```powershell
   py -3 -X utf8 -B scripts/check_public_source_closure.py --report $ClosureReport
   ```

3. build treeは開発workspace直下の既存`build/`一つだけです。公開候補directoryに別buildを作りません。
   現presetの`binaryDir`は`${sourceDir}/build`なので、コピー先で上記presetをそのまま実行しません。
   実行前に現CMake契約と安全な切替方法を確認し、既存buildのsourceを固定snapshotへ一時切替する工程を
   別途登録します。元source／構成／tool／入力pinはmetadataだけを保持し、旧buildをarchiveしません。
   cache・生成物の切替とclean、旧出力を合格証拠へ混入させない初回Debug／Release全target・必要試験、
   通常開発source／構成への復帰と確認までを登録します。別build treeの新設はしません。
   初回公開ではこの切替・clean・復帰を実行しました。後続もその時点の入力と構成を固定して行います。
4. 同じsnapshotで「必須source gate」の全commandと、変更範囲に必要なPython／PowerShell・UI試験を
   明示実行します。native／UI試験の実行場所は前項の唯一buildと確認済み手順へ結合します。
5. 実command、対象集合、tool版、終了値、実時間、未実行項目をローカル記録へ残し、
   [Release checklist](release-checklist.md)のpackage・権利・秘密情報確認と合わせてレビューします。
   不合格・未確認を成功へ数えず、公開するbyteが変わった場合は影響する確認をやり直します。

この手順の採用は実行済みを意味しません。静的checkerは全Markdown link、秘密情報、権利、動的依存を
完全検証するtoolではありません。初回公開後の変更は公開側の履歴へ残し、remote反映とPublic化は
各明示承認の対象とします。現在の開発PrivateとPublicは双方Actions無効です。
workflow削除だけをremote停止の証拠にせず、remote反映時には実設定も別途照合します。

日次pipelineのADR 0373回帰は、実失敗経路の
原JSON pinを保持したSHA-256値照合と、旧startのexact検証・取得用途の開始記録／公開出力の分離を
人工保護入力で確認します。receipt／terminal／lockと元の日次予算は共有します。
旧metadata成功は取得用途成功へ数えません。この内部試験は保護配備、実収集・内容検査・署名配布、
通常アプリの実端末候補表示の成功を示しません。

ADR 0374の限定回帰は、
`ReceiptAnchorAndRepairTests`で実`protected_path`／`check_acl`へ人工の継承ACL snapshotを接続し、
専用rootとoperation包含の両方を検証します。一段だけの修復継承は前config/start/receiptの
原byteと現code/native pin、不変意味入力、現receiptのFRESH_INPUT、旧署名historyへ拘束します。
旧fenceの値は履歴として保持し、初期inheritの現head照合を省略した成功とは数えません。
旧startの上書き・receiptの再収集・予算resetを行わず、未知claimと部分準備は既存規則で拒否します。
この人工試験と今回の変更source回帰は、冒頭のh10時点817候補／旧Python成功snapshotとは別の結果です。
今回の有限な直接回帰は、新規12caseと既存42caseが合格しました。全Python／全nativeの再実行ではありません。
実保護配備・実preparer・実内容検査・署名・Private登録・通常アプリ実正常例は今回未実施です。

ADR 0375の直接回帰は、
`PreSignCheckpointContinuationTests`で一回だけの明示署名前継承を実loader/preparer/mainへ接続します。
旧四moduleの実byteと旧修復marker、原process証拠、body/releaseの二artifactを認証し、
欠損inspection/script/reviewだけを作成します。元codeRepair/初期inheritの既定拒否は維持します。
JST日付跨ぎでも元job bucketへterminal/reportを保持し、UTC receipt日、元window、FRESH_INPUT、
claim-before-signと既使用予算を維持します。marker前の署名前状態とmarker後の完全束再利用を区別します。
このsource工程では実配備・実preparer/native・収集・署名・Private登録を行っていません。
既存の実内容検査1/1と、元pipeline完遂0/1は別の実績です。
限定合格集合は既存63caseと新15caseの非重複78caseです。初回76testのうち新p05の二subcaseは、
先行native pin拒否の診断コード期待が不正確でした。原失敗を保持してfield別exact codeへ修正し、
p05と追加p14を直接確認しました。現configの全byte結合はp01/p13/p15の直接tailで確認し、
全suiteや既に合格した旧classを再実行した結果としては扱いません。

ADR 0376の直接回帰対象は
`VerifiedUnsignedRefreshTests`です。既存の明示preSign入口だけで、旧全config/四module/nativeと
元marker/receipt/四raw/FAILED terminal/保守carryを拘束した一回caller更新を扱います。
旧二原file開始の既定拒否を維持し、native再解析・再検査・script再取得をせず、唯一欠損のreviewを
実producerと六入力auditの後だけ保存します。200/304・小数秒・完全束のbyte再利用、各pin、
全意味入力、余分/欠損/二度目refresh、未知署名/CAS、UTC日/期限/head/lock/予算縮小を試験します。
元128methodのbody/期待値を維持し、限定classの回帰と全suiteを区別します。
観測helperは作業証拠だけに置き、Popen原handle/PID/creation/要求argv/cwd/raw先を先に保存し、
optional OS照会の失敗後も同handleの終端を回収します。要求値とOS観測値は別fieldで、
元h14r8のprocess観測欠損を復元済みとしません。実配備・実prepare/run・署名・Private反映、
全build/全unit/UI/packageをこのsource工程の実績に数えません。既存69payload packageは
pipeline/preparer/直接testを含まず、本変更だけを理由に再生成しません。
この工程の限定合格集合は新19＋関連旧80の非重複99methodです。最終sourceでの正常再利用
1method再確認を含め、物理実行100method、unit外側processの実経過合計413.0533687000279秒です。
元128methodのAST bodyと期待値は不変です。観測helperの人工4例、静的閉包、実原入力の読取り認証は
unitとは別の証拠であり、実native/有効署名/配布成功へ換算しません。

ADR 0377 の upload 回帰は
`AssetUploadLengthTests`、検証 closure の同等性は `AcquisitionVerifierFactoryTests` で確認します。
3352/1493 byte、非 ASCII byte 長、長さ header 一件、原 byte、通常 GET/JSON、
不正 upload の子起動前拒否を試験します。factory は元 closure と同じ native argv / 保存 byte /
current 六入力監査 / history 分岐を維持します。旧 146 method の AST と旧 e05 の全 assertion は不変です。
e05 だけは body=None の upload が新契約で起動前拒否となるため、二 route の人工入力を bytes/MIME へ直しました。
初回全154は153合格/1 errorを保持し、修正後のe05＋新7の直接8件は合格しました。
この合成した154件の確認を、最終sourceで全suiteを再実行した合格とは表現しません。
証拠専用の有限回復 helper は製品 module / 公開 source の依存に追加しません。
一般 draft 探索、保護配置、実回復、GitHubの400解消、全build/全unit/UI/packageは今回未確認です。

build profile試験はPowerShell 7の安定版とCMake 3.28以降を開発toolとして使います。
`--suite resolver`はmockだけ、`--suite native`は実guardと`cmake -P`を使用し、configure／製品実行はしません。
省略toolはPATHから解決し、`--powershell`／`--cmake`へ引数を含まない確認済み絶対file pathを指定できます。
tool不在等は`P3_NOT_RUN`とexit 2で、resolver-only成功をnative成功に数えません。

```powershell
py -3 -X utf8 -B scripts/test_index_build_profile.py --suite resolver
py -3 -X utf8 -B scripts/test_index_build_profile.py --suite native
```

package作成・配置・解除の試験は通常unitと異なりfileを変更します。固定runtime archive、package世代、
対象root、実行権限と期待終了値を先に固定し、元失敗を残して確認します。
現在の五つの手動PowerShell統合入口の未実行を、この説明やfake試験で埋めません。

## collectorの長いlegacy子pathの回帰履歴

ADR 0371は、検査済みabsolute DOS pathの
内部Win32表記だけを統一します。長い未存在JSONの`read`が成功0・`found=false`・空出力となり、
fileを作らないことと、同じ本文の保存・列挙・再開、ACL・同時writer拒否を既存state試験へ追加します。
不正相対名、reparse、hardlink、広いACL、collection／historyの旧入口拒否は維持します。

旧export試験h8uのDebug四失敗と中断、Release未実行、およびh8wの89文字再現は旧結果として保持します。
修復後は既存buildのDebug／Release各`all`を更新し、新しい89 UTF-16単位CWDとwork/state祖先を固定した
source-dataで、元四件・独立state・segment-read-contextの各六件を有限に確認します。
この十二件を全144 native、更新export、package、実通信・実導入・GitHub公開の合格へ換算しません。
実CLI opt-inは設定せず、`--once`を含むbranchは実行しません。全長・全shell・全OSの保証でもありません。

実測では最初の十二件は2 PASS・10 FAILで、長いlegacy子を含むstateはD/R各65/0でした。
深部へ進んで顕在化した試験側の生I/Oを指定三CPPだけで補正し、D/Rの二test targetを更新した後の
十件は8 PASS・2 FAILでした。runは993/0、projectedは75,523/0、completedは7,458/0、
segment-read-contextは1,372/0を両構成で確認しました。

残るcampaignの両9,775/1は、評価plan一件が814入力にないための失敗でした。
既存の同一planをローカル入力へ一件追加した815 epochでDebugは9,775/0、Releaseは元300秒の
予約不足によりNOT_RUNです。原十二件・C2十件・C3一件と一NOT_RUNを保持し、実callは23件です。
二つの同一source／PEのstate成功を継承したfocused十二役割は11 PASS・1未完了です。
全144、Release全体、最終source閉包や公開allowlistの受入ではありません。

今回のDebug／Releaseの`all`各一回と、指定二test target各一回の追加buildは成功しました。
六通常製品PE・profile・cacheの一致、変更範囲のformatter固定点・metadata・commentと
実Doxygen member集合69/69および54/54を確認しました。主担当確認、Releaseの残件、
fixtureの最終公開privacy／権利・依存監査、更新exportとpackageは後続です。

以上は当時の固定epochの結果です。その後、fixture I/Oと二local型契約を補正し、通常構成の
全nativeを確認した143 PASS／1 FAILの原記録を経て、上記private desktopの元26成功と
限定境界補正を受け入れました。当時のFAIL／TIMEOUT／NOT_RUNは書き換えず、現在の結合結果と区別します。

## 必ず区別する結果

- 二重操作、stale／unknown／重複／Provider不一致、取消し・Window終了と遅延結果の拒否。
- 0件、対象外、検索失敗、metadata／取得／内容拒否、未知、一部失敗の独立表示。
- 取得成功後の導入失敗、初回導入、共有packageの一回実行とdevice別結果、同意とscan失効。
- 通常clientの実在保護未成立時にProviderを呼ばず、native BEGIN所有時だけ例外でもEND一回、同日reuseでは両native操作0となること。
- 最新実一致/同版、旧版/再起動/未確認/既知新版/必要role、元item/残check保持と次の明示推奨filter除外を分けること。
- 同日二操作/アプリ再起動、日替り/OS旧point/消失/破損memo/保存失敗/BEGIN-END失敗/並行/clockを完全fakeで確認し、不完全callbackを実WMI/本番storeへfallbackしないこと。
- Serverで復元serviceを呼ばず、専用同意と実OS／保護modeを照合すること。
- 標準INFの内容／署名／依存閉包／PnP／rank、公式installerの別引継ぎと実状態未確認。
- 全Provider自動scanをせず、選択対象の事後観測、再起動、必要Extensionの未確認を保持すること。

## 実機・公開前の残件

2026-11-10の814c/dでは、最新実一致後の枠0/元item保持/次filter除外と日内point再利用を既fixtureへ接続しました。
関連8 selectorはDebug/Release各6,415項目で失敗0（復元214、controller/準備951、worker421、索引3533、最新UI278、対象限定54、表示274、準備失敗690）。
Debugの不変gateは原成功とsource出自を保持し、限定fixture補正の影響selectorとWMI同値cast後の復元は通常byteで再確認しました。
全callbackを明示したfakeと私有固定file fixtureだけで、実復元API/WMI/本番メモ/実driverを使っていません。
実機の復元/導入と変更後output配布は別受入です。

実WUA／公式HTTPの試験は明示optionと固定した有限対象でだけ行い、通常の必須試験にしません。
実導入は対象を確認した別の明示指示を必要とします。失敗を分母から除かず、内容合格、端末適合、
導入API、実状態を別集計します。原因・条件が同じ失敗は反復せず、独立に進められる確認を続けます。

最新source・同梱READMEと一致するcollector packageの作成と有限な非通信確認は上記のとおりで、
主担当の独立確認も完了しています。Public索引から通常画面の実取得・内容検査・候補表示の有限実測は冒頭の範囲です。
私有履歴は開発Privateに保持し、初回公開snapshotは分離して検証・公開済みです。
変更後の公開source集合からのDebug／Release build・全必要試験・監査と主担当確認、
承認範囲内の両repository追加反映は変更ごとに行います。
保護record保存とTask切替も別操作です。日次七回・再起動後の運用、別PCの実移設、対応拡大・SDIO不足解消を
現在の有限なローカル受入と混同しません。過去の詳細工程は保守側で原証拠を保持しています。
[Release checklist](release-checklist.md)を参照してください。

## 単体collector setupの本PC実受入（2026-10-20）

Windows x64未署名単体EXEから既定先へ配置し、同じ保護approval・repository/stateを使用した
prepare/once各一回が成功しました。固定Intel metadata一対象のNEW_200、FRESH_INPUT、世代5→6、
原receiptと四file/resultの実byte/hash結合を主担当が独立確認しています。実onceは1.9056127秒です。
実装回帰はlocal15/15、関連native両構成各5/5、Debug/Release全target、installer379check/47process。
受入EXEのSHA-256は`607aa32a7931c135c25985115960b5f3bd48982d3e5481859c474b4409b48e21`です。
旧二失敗はそれぞれの分母へ保持し、修正後の正常例と混ぜていません。旧配置は二backupへ保持しました。
TaskはDisabledのまま、署名・公開・driver本体取得／導入0。全suite/全対象/別PC/日次七回の合格ではありません。

ADR0390のTask薄入口は既存local15件を保持し、
追加16件を含む31件の有限fakeで確認します。NEW_200/304/FRESH_INPUTと同一operation、HOLD/NO_NEW、
固定argv/root/Task名、owner/write/DACL、全74payload pinとtargets、余分code、hardlink/reparse、
origin/config拒否、timeout/例外/部分保存/結果保存失敗とpythonw標準stream欠損を区別します。
guardのACL snapshotとruntime読込元は人工値であり、実ProgramData/Taskの受入にはしません。
既存L14の実子はnative argvをread-only Python cwd probeへ差し替える資格を維持します。
このsource/fake時点の保護配備・実Task受入は後続に分けました。現在の接続結果は末尾を参照し、
新索引保存と今回byteの公開snapshot/package受入は未確認です。

ADR0390のDisabled local-only Action guardは、旧69caseと追加62caseの計131case、および既存入力31caseを
PowerShell 7で非通信fakeとして確認します。追加正例は全74payload等の人工原byte/hashとfake ACLを使い、
production入力validator二回、fake Scheduler三read/一updateを結合します。直前の実config byte改変は更新0、
更新例外・readback不一致はUNKNOWN、retry/旧Action復帰/Start/delete0です。
Windows PowerShell 5.1では明示UTF-8 ParseInputの構文確認と、通常ファイル実行を区別します。
本PCの`-File`二入口は実効Restrictedにより実行前に拒否され、その失敗を保持しています。
その後、利用者の明示承認により検証子だけ`-ExecutionPolicy RemoteSigned`を指定し、UTF-8を明示して
同じharnessを読み込みました。初回はGetNewClosureのscope差によりfull131中29/Input31中19が失敗し、
関数を同じscopeへdot-sourceする条件修正後は131/131と31/31が成功しました。原失敗は保持しています。
MachinePolicy/UserPolicy/CurrentUser/LocalMachineは変更せず、子終了後の全scope Undefined・実効Restrictedも
実行前と一致しました。Set-ExecutionPolicy、GPO、永続変更、Bypassは使用していません。
これは限定loaderによる内部fakeの資格です。通常ParseFileのBOMなしUTF-8日本語のANSI読解差は別の制限であり、
通常`-File`互換や本PCのTask受入を断定しません。

## local-only Taskの現在地と公開候補の変更回帰

2026-10-21の所有Task解除変更（ADR0392）は、
解除policy fake26case/71assertions、登録guard/所有pin fake143case、関連native四testをDebug／Releaseで
各全成功、Release native setupの不正receipt拒否・file/data保持を含む79checksで確認しました。
変更五sourceのformat差分0、既存規約gate0error、変更四C++ sourceのDoxygen member22/22を照合しました。
既存全source規約の初回7診断、guard fixture root未作成とDTD診断期待値違いの初回失敗は保持し、
原因を修正して変更対象を再確認しています。実Task登録・解除は未実施です。旧公開候補や配布物の
合格を本変更へ転用せず、新source候補／EXEの確認範囲は個別の保存記録を正本とします。

上記fake/旧配置時点とは別に、保護配置・Action更新・EnableとTask経由の検証一回を主担当が確認しました。
元日程・原点・head6・待機を保持し、実結果はNO_NEW_OBSERVATION/NO_NETWORK/exit2です。
native二操作は正常で既存観測を一件再利用し、HTTP0・新索引保存0でした。HOLDやfresh成功へ読み替えません。
自然dueの新保存、日次七回、再起動・別PC移設、実導入、変更後の公開snapshot/配布物は未受入です。

三builderとinstaller fixtureには、script自身のsourceを持つcacheの`-BuildDirectory`を渡せます。
通常profile・Ninja Multi-Config/Debug;Release・HOME一致・x64/実PE/profile/trustと新規out境界を検査します。
releaseの同版出力は既定時も削除せず拒否し、新規`-OutputDirectory`を指定して再生成します。
installerは同一buildで生成しembeddedをfinally解除、主失敗/復帰失敗を別々に保持します。

新回帰は`test_index_build_profile.py --suite package`と`test_public_source_closure.py`に追加しました。
前者はproduction helperの合成cache/output/失敗保持と三builderの副作用前Private fallback拒否、
後者は生成table/resource templateと明示v6 edgeの欠損拒否を扱います。実装追加だけで合格とはしません。
既存profileのnative34条件、resolverと他の既存分母を保持し、実行結果は別工程に保存します。

現candidateは850 source file/false-onlyです。受入済み127世代三入力から同じ8JSONを再生成する必要があり、
元71世代と旧取得証拠8件は保守側に保持し、新4件へ合算しません。新しい研究/driver対応数増加ではありません。
固定snapshot自身から全target/全必要試験とsource・文書・権利・秘密情報を確認するまでは未受入です。
Python日次209は既往約1430秒のため外側3600秒を確保し、旧300/1200秒wrapperを再利用しません。

## 汎用配布検査の保護接続

`test_collector_distribution_pipeline.py`は、自己所有fixtureと試験内bridgeで予約・精算・全分母・
33件継続、同URL待機、旧成功、既知保存窓回収とexport/importのbyte/待機保持を確認します。
`drivercrate_collector_distribution_pipeline_tests`と`test_distribution_native_fixture.py`は、
実固定Python子、実named pipeのpeer、保護file、native/monitor writerと本物callerを使います。
低位HTTP/DNSと通常runner内のINF/CAT/公開metadata I/Oだけを既存の専用test seamへ置換します。
同PAGE二payloadの3送信、次run追加0送信、予約欠損/子死亡の特定guard、初回originの保存窓再開、
旧履歴への単調移行と欠損/未知履歴消失後のpristine逆遷移拒否を確認する有限fixtureです。
専用parent-death modeは親processを実終了し、残予約の最大課金/再送0を別processから確認します。
fake設定を製品CLIや環境変数に公開せず、運用store、実HTTP/DNS、Task、永続鍵、実driverを使用しません。
通常callerの接続確認を実WinTrust/CAT成功、新規対象対応、日次/setup同梱の受入へ換算しません。
同utilityの`--hash-only`は既存1/8MiB APIの契約を保持し、収集JSONの1MiB超/16MiB/超過と
現registry/locator原byteのPython期待SHA-256を非通信照合します。例外cleanupの専用probeは、
同じ実子終端、guard内の保持中writer競合、unwind後のwriter再取得を確認します。

汎用producerの追加fixtureは2メーカー3製品を使い、A二製品/一jobの共通archiveから新INF二件と、
B別archiveのfresh更新版を、同じ私有結果→v2候補→実GZip/raw manifest→親の共通未署名validatorへ通します。
同じ実parentの個別/全体失敗fixtureは、全分母を保持した一recordの部分候補と、全失敗時のhead/asset非作成を確認します。
`drivercrate_collector_distribution_candidate_tests`は元検査seamから全Models/公開IDを取得し、旧研究版との役割分離、
同package descriptor、128 ID/64KiB限界、nested/署名者の表現限界、全job拒否と他OS未観測を検証します。
`test_collector_distribution_candidate.py`はその実producer byteをnativeの同codecへ渡します。
署名型を発行しない検査、quality/hash/未知wire/個別・manifest期限拒否、旧v2の両期限順序互換を確認します。
同fileの世代1→2→3・旧A/新B・再build/旧期限/全失敗/空成功は、明示した試験bridgeによる非通信assemble検証です。
実origin/実日次の世代更新やactive data importと区別します。

252cの`--parsed-producer-fixture`と`--parsed-producer-mutated-fixture`は別の有限正例です。
自己所有の未署名synthetic ZIP/INF/SYS/CATを作り、全HTTP/DNSと全原file hash付きの最下層署名/CAT
fixtureだけを模擬します。通常ZIP展開・全INF閉包/参照file検査・SetupAPIの公開Models/ID/ClassGUID・
版/日付/provider読取りを同じrunner→私有観測→本物producerへ通し、3record/2sourceを生成します。
後者はA一INFのIDと版だけを本文で変更し、record identity/実INF hashと表示版への反映を確認します。
元の完全fake検査fixtureを実INF検査へ読み替えません。

同runの`manifest.raw.json`と`index.json.gz`をそのまま`drivercrate_index_binding_tests`または
`drivercrate_unit_tests --distribution-application-fixture <manifest> <gzip> <fixture-package>`へ渡します。
既存RAM-only RSA fixtureで元manifest byteを署名し、隔離trustの認証wrapper→asset/GZip/record/quality→
保護store commit/reload→通常workerのDriverStore fake/lookup→共通取得adapter→実archive再検査→
INF/rank binding→表示用候補へ接続します。原manifest/GZipを再生成・手書きv2へ置換しません。
製品trustへfixture鍵を登録しません。A二機器がdeviceCount=2の一取得target、Bが別targetとなり、
fake payload GETは合計2回です。通常更新/Code28初回、ID/Class不一致、INF完全path/rank/CAT hash拒否、
現在属性欠損のUNKNOWN、旧世代/旧session/未表示ID拒否、個別CAT拒否と成功候補の並存を区別します。
Class全不一致の候補0は除外結果であり「最新」や対応済みへ計上しません。
候補/選択境界までの非導入受入であり、WinTrust/CAT実署名正常・実device適用・画面の実描画・
実driver導入成功は未確認です。setup/active data/日次接続は252dに残し、対応数の増加は0です。
<!-- ADR0408: 未署名候補stagingの有限な検証入口。 -->
未署名候補stagingの人工境界試験は`test_collector_candidate_staging.py`です。
native leaseをfakeとし、部分成功の原record/producer/期限保持、dead/wrong-operation/消費済みの
admission、原点差、fresh観測なし/失効、非空/重複先、原source CASとprovenance改変拒否を検査します。
nativeの重複・非空先・原点欠損は`drivercrate_collector_setup_workspace_tests`で別に確認します。
実保護staging、専用CNG署名、通常validatorの実受入は人工試験と分けます。
公開済み索引Releaseの正式版/プレリリース分類は`test_published_index_release_reader.py`で確認します。
draft・不正bool・返却tag差・asset不足/差替え・verifier拒否を検査し、新Release writerの
prerelease方針を維持します。実currentの失効はhistory/floorと現在有効性を分けて記録します。


## 認証済み個別device投影（ADR 0413）

認証済み個別device投影は、生MULTIPLEの非一意負例を維持して、二present/未知Class完全初回・第三node不足・record/source/hash/publicId/device/context/cohort/error/owner/lease改変を分離する。共有一取得、選択一件だけのfake導入と非選択0、通常準備UIも検査する。実機READY/実導入/署名/公開の実績は分けて記録する。

詳細はADR 0413を参照する。

## 唯一最小Windows full-rank（ADR 0414）

同tuple異rankの両列挙順、同最良同点拒否、後の低rankによる旧同点解消、別Provider/packed版/日付/完全path、
後続rank/detail/API失敗、正常終端不足・上限・候補無し、導入前winner変化/同点化と登録先だけの
低rank追加/同点化、完了後の旧scan失効を完全低位fakeで確認する。完全初回/未知Class、
共有一取得/選択一件/非選択0の既存回帰を維持する。fixture成功と新signed appの通常READY、
実導入の実績を分ける。ADR 0414を参照する。

## 同ID二件の選択batch（ADR 0418）

同Hardware ID・異instanceの二deviceを共有一取得から明示選択し、第一のfake指定成功後に
第一自身の現在属性だけを反映する。既知同ID・完全初回・第三node不足の三正例と、第二の
実状態変化・未知rank・同最良同点・元API拒否・同保護INF byte変化・原期限切れを分離する。
単独第二選択では未選択第一のAPI呼出し0を維持する。proof寿命は通常終端・例外・新scan・
明示失効と旧resolver/新callback閉鎖を別に確認する。既存の偽binding・別device・stale・
署名hash期限拒否とpartial結果表示を保持する。内部成功は実機二件の解消確認ではない。
詳細はADR 0418を参照する。

## 収集stepの複数HTTP完了と固定診断（ADR 0443）

G13-I7r299の非通信確認では、実nativeの低位HTTP/DNS表を置換し、Catalogの
検索/details/dialog/payload/補助起点を通します。正常な補助取得、503、途中read失敗、
誤MIME、原hash不一致、前段途中失敗と、HTTP完了後のmodel JSON schema拒否を分けます。
未修正版の完了assert失敗を保持し、変更後Debug/Releaseはnative各544条件、形式/protocol各69条件で合格しました。
保存原CABも実CAT/INF/identity readerまで各構成の2HTTP/5HTTPで一件受理し、complete=trueを確認しました。
再生metadataは人工であり、fresh収集や実HTTP成功の証拠にはしません。

Managerは`--collection-only`で各構成191条件を確認しました。元負HRESULTと32bit両境界、
端数/範囲外拒否、結果解析/選択と固定段階・本文非記録に加え、既存の24h/host待機、
最大3worker、取消し/期限/例外時joinを含みます。既存setup回帰は現在のinstalled Startupを
所有外として拒否したため、原exit1を保持し、今回の合格へ含めません。製品の所有検査とStartupは変更していません。
保存再生の旧4field budget拒否も保持し、原入力を変更せず私有fixtureだけを時間専用schemaへ揃えました。

変更7sourceの書式差0、規約319control/0error、Doxygen28/28/0を確認しました。
必要targetと直接header依存をfresh compileし、通常Appと署名済み配布物は保持します。
実HTTP、稼働data、Startup/Task、鍵、署名、公開、package更新は本確認に含めません。
契約はADR 0443を参照してください。


833では`drivercrate_collection_setup_launch_tests`が、閉program/所有rootに無害なasInvoker子だけを配置し、
既COM desktopからの引継ぎと実子のtoken/image・無引数/同cwd・有限自然終了を確認します。
所有/hash/停止・journal、token/session/desktop不一致は作用前拒否します。新UACを発行せず、現在の実token条件を記録します。
固定CLIの余分な引数と標準Runの通常/Full・checkbox/silentの選択も別に確認し、本番host/HTTP/公開を起動しません。
fresh必要D/Rと変更規約を最終sourceへ結び、832の無変更source/PE/inputの資格は原証拠へ分離して再利用します。
全CTest/cache/coreの機械的再実行を行わず、実Full installerからの利用者起動成功は別受入に残します。

835の限定回帰は、元read-only SD/実limited tokenの旧lock・create拒否、同名READ lockとの双方向排他、setup限定準備後の新規claim/dir/file、元子SD/byte保持と不正write・active/binding・元receipt/本人store拒否を対象にします。必要な同build x64 D/Rと変更source/format/Doxygenを実行し、本番ACL/収集/公開成功へは読み替えません。

839の追加診断は既fake/DTO/匿名sinkで取得APIの固定stage/元HRESULT/選択ordinal、復元最終guardと表示resourceを照合する。実WUA/driver/復元APIの故障再現や実障害修正成功とは区別し、必要D/Rと変更source gateだけを実行する。

840のWUA検索回帰は、実scanと同じ共有producer終端へ原到達不可HRESULTを渡し、本物Compositeの
共通整合guardを通してDriver Storeの架空148候補が警告付き成功へ残ることを確認する。
成功/空/途中失敗/中止と矛盾した結果の拒否を非通信fixtureで区別し、診断revision3と839診断も
必要D/Rで確認する。実WUA/環境設定や別PCの到達不可解消は未確認とし、全CTestを繰り返さない。
841の取得予約回帰は、RAM署名/隔離保存した5recordから実adapterが外側sizeを記述し、実UIの共有
approval builder→controllerへ同じ2選択を渡す。原2GiB×2の予算拒否と、58,973/39,157byteの受理を
成功/警告付き成功の両方で区別する。未知の原cap、oversize、snapshot/同意/前提/再送、累積予約/取消しは
既core fakeと合わせて確認し、grant/HTTPのexact cap/元hash/size・失効leaseも既完全fakeで確認する。
展開上限を圧縮byteへ縮めず、revision4の匿名拒否には原内側理由と予約値だけを出す。
必要D/Rと変更source gateに限定し、実HTTP/導入/復元や別PCの実拒否原因の確定へ読み替えない。


842/ADR0485の明示続行はsource実装済みで、必要な同build x64 Debug/Releaseの結果を842/b-runへ個別記録しています。既fakeで通常保護成功/同日reuse、
Provider前422の既定中止、同scan/元選択の新operation一回・新BEGIN/END0を確認します。旧BEGIN所有時は旧END一回成功後だけ
提示し、Provider後/部分成功/END失敗・cancel/close/stale/変更選択/再送/期限/他操作busy/Server混同を拒否します。
取得済み物の再取得0/対象限定再検証、原codeと復元なし記録/匿名性/保存失敗非干渉を必要D/Rで確認し、実導入成功と分けます。
実UI/署名索引workerの追加4条件は、失敗表示後の現在版欠測/実Tree選択を通し、続行だけfresh operation、
Provider1/追加GET0/新BEGIN・END0、中止・変更選択・原期限失効はProvider0でした。各UI75、
共通保護351/匿名245、既予約1331、WUA102、sink227が成立し、最終21source規約/formatとDoxygen999件はerror0です。
原失敗は保存し、最終UI sourceはfresh再確認、残る同source/PE/inputの8資格はhash一致で再利用しています。
revision5をoutput固定配布物へ反映しました。内部fakeの原資格は保持し、配布物の最終主担当確認と
実利用者の新操作・実導入成功（未確認）を分けて記録します。
