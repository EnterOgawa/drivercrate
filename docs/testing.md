# テスト方針

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

[ADR 0372](adr/0372-test-only-private-desktop-lifecycle.md)の自己supervisionはUI試験専用です。
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

限定した実収集・取得と、INFを含むドライバー本体の内容検査には正常例があります。
通常画面で実端末に照合した正常候補の表示・実取得を一連で確認する受入は未完了です。
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
通常アプリの実行時にPythonや外部frameworkは必要ありません。開発用Pythonは3.10以降、
collector保守・固定runtimeの検証にはPython 3.13を使います。Doxygenは1.10.0です。
repository rootをcurrent directoryにし、x64のVisual Studio developer shellで実行してください。

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

各`test_*.py`の対象moduleと入力契約を確認して、必要な試験fileを明示実行します。例えば次は非通信の
source閉包、台帳、日次pipelineの人工試験です。これら三入口だけで過去に集計した1,181固有caseを再実行したとはしません。

```powershell
py -3 -X utf8 -B scripts/test_public_source_closure.py
py -3 -X utf8 -B scripts/test_collector_registry.py
py -3 -X utf8 -B scripts/test_daily_index_pipeline.py
```

`scripts/check_public_source_closure.py`は候補一覧の静的なsource／fixture／import／固定payload依存を
確認するtoolです。動的pathの完全証明やnative buildではありません。
現在の822候補は、自動workflow一件を除きADR 0379一件を加えた集合です。同数の旧822候補とは異なります。
最終allowlistではなく、除外された私有履歴を追加して閉包を成立させません。

## 公開snapshotのローカル事前確認

[ADR 0379](adr/0379-local-prepublication-verification-without-actions.md)に従い、公開前の確認をローカルで行います。
Private working treeの既存build・増分試験の合格と、公開snapshotからの新しい検証は別に記録します。
現在、独立した初回公開snapshotからのDebug／Release buildと全必要試験は未受入です。

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
   具体的な切替・clean・復帰commandの確認と実行は未実施であり、この手順だけで実行可能とは扱いません。
4. 同じsnapshotで「必須source gate」の全commandと、変更範囲に必要なPython／PowerShell・UI試験を
   明示実行します。native／UI試験の実行場所は前項の唯一buildと確認済み手順へ結合します。
   `scripts/test-non-ai-build.ps1`は廃止AI option拒否の補助試験であり、
   アプリ全体のbuild／testを代行する入口ではありません。
5. 実command、対象集合、tool版、終了値、実時間、未実行項目をローカル記録へ残し、
   [Release checklist](release-checklist.md)のpackage・権利・秘密情報確認と合わせてレビューします。
   不合格・未確認を成功へ数えず、公開するbyteが変わった場合は影響する確認をやり直します。

この手順の採用は実行済みを意味しません。静的checkerは全Markdown link、秘密情報、権利、動的依存を
完全検証するtoolではありません。初回公開後の変更は公開側の履歴へ残し、remote反映とPublic化は
各明示承認の対象とします。現在のローカルworkflow削除は、未反映のremote workflowを停止しません。
実移行時には公開準備repoと旧開発repoの双方でActions不使用を確認します。現時点のremote無効化は
未承認・保留であり、旧移行予算へ追加せず、必要な操作・予算を実移行前に再登録します。

日次pipelineの[ADR 0373](adr/0373-acquisition-digest-and-legacy-day-entry.md)回帰は、実失敗経路の
原JSON pinを保持したSHA-256値照合と、旧startのexact検証・取得用途の開始記録／公開出力の分離を
人工保護入力で確認します。receipt／terminal／lockと元の日次予算は共有します。
旧metadata成功は取得用途成功へ数えません。この内部試験は保護配備、実収集・内容検査・署名配布、
通常アプリの実端末候補表示の成功を示しません。

[ADR 0374](adr/0374-receipt-anchor-and-code-only-continuation.md)の限定回帰は、
`ReceiptAnchorAndRepairTests`で実`protected_path`／`check_acl`へ人工の継承ACL snapshotを接続し、
専用rootとoperation包含の両方を検証します。一段だけの修復継承は前config/start/receiptの
原byteと現code/native pin、不変意味入力、現receiptのFRESH_INPUT、旧署名historyへ拘束します。
旧fenceの値は履歴として保持し、初期inheritの現head照合を省略した成功とは数えません。
旧startの上書き・receiptの再収集・予算resetを行わず、未知claimと部分準備は既存規則で拒否します。
この人工試験と今回の変更source回帰は、冒頭のh10時点817候補／旧Python成功snapshotとは別の結果です。
今回の有限な直接回帰は、新規12caseと既存42caseが合格しました。全Python／全nativeの再実行ではありません。
実保護配備・実preparer・実内容検査・署名・Private登録・通常アプリ実正常例は今回未実施です。

[ADR 0375](adr/0375-explicit-presign-checkpoint-continuation.md)の直接回帰は、
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

[ADR 0376](adr/0376-verified-unsigned-presign-caller-refresh.md)の直接回帰対象は
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

[ADR 0377](adr/0377-asset-upload-length-and-pinned-draft-recovery.md) の upload 回帰は
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

[ADR 0371](adr/0371-collector-legacy-store-extended-paths.md)は、検査済みabsolute DOS pathの
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
- clientの復元開始失敗時にProviderを呼ばず、開始後は例外でも終了通知すること。
- Serverで復元serviceを呼ばず、専用同意と実OS／保護modeを照合すること。
- 標準INFの内容／署名／依存閉包／PnP／rank、公式installerの別引継ぎと実状態未確認。
- 全Provider自動scanをせず、選択対象の事後観測、再起動、必要Extensionの未確認を保持すること。

## 実機・公開前の残件

実WUA／公式HTTPの試験は明示optionと固定した有限対象でだけ行い、通常の必須試験にしません。
実導入は対象を確認した別の明示指示を必要とします。失敗を分母から除かず、内容合格、端末適合、
導入API、実状態を別集計します。原因・条件が同じ失敗は反復せず、独立に進められる確認を続けます。

最新source・同梱READMEと一致するcollector packageの作成と有限な非通信確認は上記のとおりで、
主担当の独立確認も完了しています。実収集→GitHub→通常画面の正常候補・目視・実取得／内容検査は未受入です。
公開画像metadataと過去Git履歴の扱い、最終一覧、新しい公開用sourceからの独立Debug／Release buildと試験、
Private push／readback、本人のPublic承認も残ります。
保護record保存とTask切替も別操作です。日次七回・再起動後の運用、別PCの実移設、対応拡大・SDIO不足解消を
現在の有限なローカル受入と混同しません。過去の詳細工程は保守側で原証拠を保持しています。
[Release checklist](release-checklist.md)を参照してください。
