# ADR 0390: ローカル日次Task接続と公開パッケージ作成の受入

- 日付: 2026-10-20
- 状態: Task薄入口・guard・保護配備と本PCのlocal-only Task経由検証一回を有限受入。自然dueの新保存、変更後公開snapshotの検証・配布物生成は未受入。

## 背景と完了証拠

利用者の「日時タスクとの接続とpublic公開パッケージの作成可能な状態まで進める」を、
文脈上の日次収集Taskと公開前ローカル作成のGoalとして採用する。実装やfake試験だけで完了にしない。
本PCの既存承認repository/state、待機、lease、世代、原receiptを保持した実Task経由の有限実行と
未署名ローカル索引保存、固定公開source自体のx64 Debug／Release全target・必要試験／品質gate、
同sourceからの通常アプリ配布物と収集用単体setup EXE・SHA-256・notice・可搬seed生成を必要とする。
旧Private buildや旧公開snapshotの合格を、新しく固定したbyteの初回合格へ読み替えない。

本Goalは実push／tag／Release／visibility変更、署名、公開送信、driver実導入を承認しない。
日次七回、全件検証、別PC移設、対応拡大は別工程であり、対応増は0のままとする。

## 日次接続の最小変更

既存のv6 package、`collector_local_index.py`の9field config／origin検証と`collect`、
固定native三操作、projection、原結果保持を再利用する。別の収集engine、DB、Task管理framework、
新state移行は追加しない。Task用の薄い入口だけを既存moduleへ追加し、開始・終了・config／package
hash・native operation・終了値の有限な相関を残す。署名・publisherへ分岐しない。

導入済み利用者所有packageを、そのまま昇格Taskの信頼入力にしない。既存Task guardの
SYSTEM／Administrators／TrustedInstaller限定owner・非許可write拒否・reparse拒否を維持する。
既存v6の固定program閉包だけを新しい版固定の保護directoryへ配備する案を選ぶ。
runtime・license・seedを含む既存75fileを再利用し、運用work・state・receipt履歴・鍵はコピーしない。
同じpackage hashへ結合する配置receiptと新config／originだけを保護下へ新規作成し、実identityは
元の承認repository/stateを参照する。これは運用stateの移設・待機や世代の再初期化ではない。
既存保護runtimeと固定CPython版／byteを比較し、差の有無と理由を保持する。新package側は公式runtime
manifestと受入済み全閉包のACL／pinを正本とし、既存runtimeとの差を埋めるために改変しない。
2026-10-20の配置検査では、既存runtimeの`python313._pth`だけが保護された旧sibling scriptsの参照を
追加しており、残33fileは一致した。新packageの同fileは公式manifestの80byte／SHA-256
`35ddf94682ff9aa713a8d63557242ad00f3f28fdd39337f02c3bda4c0f791577`と一致する。
旧参照を新packageへ移さず、固定loaderによる三つのsys.path、isolated／no_site／bytecode無効、
実module読込元と全pinの既存検証をreadonly probeで確認する。旧比較の失敗は保持し、probe未実施の
段階でruntime実受入としない。この説明は検証の正本を区別するもので、未登録差分の包括許可ではない。

Task Actionは版固定packageの`pythonw.exe`と、既存native launcherの`LOCAL_BOOTSTRAP`と同じ
固定`-I -B -S -c` loaderから既存moduleの薄いTask入口を呼ぶ。shell、PATH、任意command、
環境由来module探索を採用しない。C++ setupの利用者を含む三ACE契約は変更しない。
Task用入口ではProgramData下の限定owner／DACLを追加で要求する。一般の手動onceの意味は維持する。

Task薄入口は`packages/local-v6-<manifest SHA-256先頭16桁>`と`work/local-index/task-249.json`へ限定する。
既存protected_path/check_aclで必要なancestorとchildのowner/write/reparse/hardlinkを検査し、専用rootと
配置rootのprotected DACL、固定74payload名・全pin・manifest・配置receiptを要求する。手動onceで編集可能な
targets.jsonもTaskではpinへ含め、固定isolated pythonw・三つの探索pathと読込済みmoduleの配置元を照合する。
program外は固定Task config/originと既存形式のoperation出力名だけを有限に検査する。4096項目・検査間20秒の
上限で列挙I/O失敗も拒否し、過去projectionの再解析や新しい履歴stateを作らない。各OS I/Oのhard deadlineではない。
同じ既存operationsのjobへtask-start.json、既存local-result.json、task-terminal.jsonを新規保存し、Task名、
config/package hash、UTC、operation、status/exit、nativeTrace、部分を含むfile pinを結合する。
信頼root検証前の拒否では開始fileがなくTask結果不明となる。信頼root後のload拒否はnative0の終端を残す。
HOLDはexit3、NO_NEW_OBSERVATION/拒否はexit2で、新保存成功に数えない。timeoutと結果保存不明はUNKNOWN、
終端保存失敗もexit0にせず原start/receipt/部分fileを保持し再試行しない。標準streamのないpythonwや
出力不能でも保存済み結果と終了値を維持する。source/fake確認は実Task/実ACLの受入ではない。

`register_daily_index_task.ps1`の既存guardを、明示したlocal-only authorityの場合だけ拡張する。
現状のReady／Enabledを要求する旧publisher用modeは維持し、新modeはDisabled／instance 0の
Daily229だけを受理する。旧XML／Action／SDDL・configと新全file pinを更新直前にも再照合し、
Actionだけを一回更新する。principal、trigger、設定、SDDL、Disabledを変えない。
Schedulerが省略する既定のtrigger Enabledは、単一daily triggerの意味としてtrueと照合するが、
欠落以外の未知値・重複・明示falseを拒否し、更新後の非Action定義は元のまま保持する。
不明な更新結果へ自動retry、旧Action復帰、Start、deleteを行わない。

local-only guardのauthorityは`dc-local-daily-task-cutover-v1`、modeは`LOCAL_ONLY_DISABLED_ACTION_UPDATE`へ
固定する。これはTask更新の承認入力であり、collectorの9field config/schema/engine/stateを追加しない。
authorityの未知field、未知pin、switch混用は更新前に拒否する。packageManifestSha256からQを決定し、
全74payload名とmanifest、配置receipt、固定config/origin、旧config/pipeline、新XML、実行するregistrar自身、
固定approval/manifest/scopeだけを閉じたpin集合とする。originの既存実identityはレビュー済み原byteへ結合し、
guardがdirectory実identityを独自に再構築したとはしない。実行時の既存Python/native検証を維持する。
新QのrootはAdministrators owner/protected DACL、書込主体はSYSTEM/Administratorsに限定する。
元保護入力の既存ACL契約は維持する。DisabledのNextRun表示は参考値であり、時計を跨いだ変化だけで
非Action driftとはしない。更新前後のXML/SDDL/Disabled/principal/元triggerそのものを正本とする。
切替switchは`-UpdateDisabledLocalAction`であり、`Register`、`Smoke`、旧`UpdateExistingAction`との
混用を拒否する。新Qのruntime/15moduleを含む全74payload＋manifestと配置receiptを照合し、
program以外のpinも固定authorityから閉じる。更新前の新Qにはconfig/origin以外の運用出力を要求しない。
同じ結果の再利用やTask実行をガードのfake成功へ含めない。

## 利用者承認と実受入

2026-10-20の非同期回答「有効化＋検証用に1回実行する」を採用する。主担当の設計・実装・試験
受入後、local-only ActionをreadbackしたDaily229に限り、元の毎日15時と
2026-10-22T15:31+09:00終了を維持して有効化し、検証Startを一回許可する。
Smoke、日程延長、旧publisher再開は含めない。有効化時のStartWhenAvailableによる自然起動も観測し、
既に実行中なら重ねてStartせず、その事実と承認済一回の使用状態を記録する。

TaskのCOM instance／LastRun／LastTaskResult／Action hashと、保護した開始・終端／native receipt／
保存物を相関する。HOLD、NO_NEW_OBSERVATION、失敗、結果不明を成功にしない。
検証Startが待機中のHOLDなら、実接続だけの受入とし、HTTP 0・head不変・新索引なしを記録する。
最初の適格な自然dueでNEW_200またはREVALIDATED_304、同じ原点のFRESH_INPUT、世代と原receipt、
四fileおよびresultの実byte／hash結合を確認するまで、Task経由の新索引保存は未確認に残す。
期限内に適格な実行を確認できなければ未完とし、期限を無断延長しない。

## 公開sourceと配布物

`public_source_export_manifest.json`は現在candidate契約で`finalAllowlist=false`を要求し、checkerも
trueを拒否する。これを無断でtrueへ変更しない。閉包を直したcandidate一覧と全byte／SHA-256を固定し、
別のローカル最終レビュー記録へ集合hash・mode・理由・未確認を結合する。固定集合以外の追加を禁止する。
checkerを実行しただけで公開承認・秘密不在・再現buildを主張しない。

現CMake入力、header、bootstrap template、package入口／test、新しい公開契約ADRと利用者文書の
必要閉包を追加する。公開文書の不在link、私有work参照、個人絶対pathは公開前にportableな説明へ直し、
必要な契約を根拠なく削除しない。私有履歴は元のwork／roadmapに保持する。
`.git`、Actions、運用state、inventory、credential、秘密鍵、driver本体をexportしない。
public pinだけは秘密鍵と区別する。READMEの受入済み範囲と未署名・未確認を現実へ整合する。

snapshotは既存checkerのpath／上限／閉包規則を保ってexact copyし、両側の全pinとextra 0を確認する。
`.git`がない状態で品質gate・builderが動作することを確認し、私有Git履歴は投入しない。
必要なscript相対の入力はsnapshot由来に固定する。配布builderには明示build directoryを渡せる
最小変更を行い、指定cacheのsourceがsnapshotと一致しない場合は拒否する。旧Private成果物へのfallbackは設けない。

唯一の開発workspace `build/`を、元cache／tool／入力metadataを保存してNinja両構成clean後に
`cmake --fresh -S <snapshot> -B <唯一build>`で切り替える。presetのsnapshot内buildは作らない。
旧第三者source／archiveは保持し、候補用FetchContent cacheだけを同じbuild内へ限定する。
全target、unit／UI、対象Python／PowerShell、format／metadata／Doxygen、文書／license／秘密情報を
このsnapshotで確認する。全体finallyで元source／cacheへfresh復帰し、両構成全targetと通常profileを確認する。
失敗・中断・未実行を保持し、同条件retryや分母削除をしない。別build／過去build archiveは作らない。

同snapshotの台帳・locator・payload evidenceから非通信で可搬seedを生成・検証し、固定CPython archiveと
同snapshotからbuildしたRelease像を使って既存collector builderを実行する。
通常アプリZIP、collector ZIPと単体setup EXE、各SHA-256、実内容／notice／seed検証と非通信fixtureを保存する。
配布物へPDB・開発絶対path・運用config・鍵・実端末情報・driver payloadを混入させない。
単体EXEのresource付きbuild後も、埋込みoptionを空へ戻して通常profileに復帰する。

## 失敗時と残件

配備は新しい版の新規作成だけとし、旧program／Action XML／失敗出力を保持する。Task変更前の失敗は
Disabled旧Taskを保持する。Action更新後の異常では、状態が確認できた場合のDaily限定停止と原因調査を
優先し、署名・remote副作用がある旧Actionを自動復帰しない。head／lease／待機をresetしない。
build失敗と通常復帰の成否は別記録とし、所有process停止が不明なら追加cleanを止める。

このADRだけで実装・運用・公開準備完了にはならない。公開sourceの契約は本書と同梱の試験を正本とし、
各実行の具体path、固定対象、command、有限予算、原結果は公開集合の外で保持する。

## 明示buildと出力境界の具体契約（2026-10-20、249d2実装前追補）

三builderの`-BuildDirectory`はscript自身のsource/buildを既定とし、明示値は完全修飾のlocal pathに限る。
開発用builderは既存profile verifierの実要件であるPowerShell 7を明示要求する。実行policyは変更しない。
空・不在・非directory・reparseと不適格cacheを副作用前に拒否し、Private buildへfallbackしない。
共通helperは最大1MiBのCMakeCacheを読み、HOME_DIRECTORY:INTERNALがscript自身のsource rootへ
正規化後に完全一致すること、Ninja Multi-Config、Debug;Release、通常の四OFF/三emptyを一意照合する。
重複・不明type・欠損・別sourceを拒否する。既存v2 profile/compiled trust/PE原hash検証とx64検査を維持する。
installerの内部configure中だけは、同じsource/buildと自身が生成したembedded pathを認証して解除する。

releaseには`-OutputDirectory`を追加する。出力既定はsource/out、明示先はsource/out又は選択build親/outの
新規childに限る。全既存祖先の通常directory/非reparse、成分境界、既存先、package入力との包含を検査する。
installer fixtureも同じBuildDirectoryと明示FixtureRootへ束縛する。R/buildを選んだsnapshotから
R/outの新しいchildへ出力できるが、任意rootへの書込み許可にはしない。
releaseの従来の同版directory/ZIP/checksum削除は既定時も廃止し、既存の一つでもあれば副作用前に拒否する。
再生成する場合は利用者が別の新規OutputDirectoryを選ぶ。既存成果物を自動整理しない。

installerのRelease入力、generated、configure、buildとfinallyは同一の明示buildを用いる。
復帰前にもsource/cacheを再照合し、他sourceをconfigureしない。主処理と復帰の両方が失敗した場合は
二つの原例外をAggregateExceptionに保持し、片方を消さない。生成途中の出力は保持し成功扱いしない。
installer内部のembedded解除と、全工程外側の通常開発source/profile復帰は別の責務である。

既受入127メーカー/6584製品参照/1718研究record/388 locatorのseed8JSONを、既存codecでsource三入力へ
明示同期する。registryは四collectionから再構成し、原manifestのSHAへ完全一致させる。
旧source三入力の原byte/hash/metadataと旧取得証拠8件を先に保持し、新seedの4件へ合算しない。
異なる証拠世代の切替であり、新しい研究やdriver対応数増加ではない。

本PCではlocal-only DailyのAction更新・Enable・Task経由の検証一回を主担当が確認した。
結果はNO_NEW_OBSERVATION/NO_NETWORK/exit2、native二操作正常・既存観測再利用一件・新索引保存0である。
HOLDやfresh成功に読み替えない。元日程・待機を保持した自然dueの新保存、日次七回、別PC移設、
本変更の公開snapshot全試験・配布物生成、実導入と新しい公開反映は未受入である。

### app-only cacheの限定互換（249d2a、実装前）

通常app-only構成ではCMakeがembedded cache keyを定義しないため、その一点を未生成として扱う。
`DRIVERCRATE_BUILD_COLLECTOR:BOOL`はON/OFFの一意必須keyとし、欠損・未知値・type/重複違いを拒否する。
OFFだけembedded key不在を許す。存在する場合はPATH型・空・重複検査を保持し、ONでは必須とする。
liveを含む四OFFと他の空値条件、source binding・PE・trustは変更しない。
collector/installer/fixtureの全解決は明示RequireCollectorでONを要求し、OFF cacheに残る旧EXEを採用しない。
releaseだけapp-only cacheを受理する。この互換を任意欠損keyやPrivate fallbackへ一般化しない。
