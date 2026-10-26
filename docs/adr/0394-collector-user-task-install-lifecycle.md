# ADR 0394: 収集用setupの現在ユーザーTask登録・解除

- 日付: 2026-10-23
- 状態: 採用。工程348のsource/fakeと、このPCの固定二件の実Task/単体EXE導入・解除を主担当349が有限な機能受入として確認。自然日次・七日・別PC・署名公開は未確認。

## 背景と対象

収集用インストーラーのインストールでTaskを登録し、アンインストールでTaskを削除する。
対象は最新のv6収集用setupと、それを同梱するWindows x64単体setup EXEである。
AGENTS第4節、ADR0226、ADR0387等の配置時Task非登録契約は、この対象について更新する。
旧v1-v5の手動配置、既存の管理者用索引Task、元の待機・予算、署名・公開・実driver導入の
別承認境界は維持する。過去の非Task配置の受入を新しい動作の検証済み根拠にしない。

日次化するのは既存の`Collect.cmd`相当のnative metadata収集である。
`config/targets.json`の正規対象を使い、Task用に対象を追加・削除しない。
同梱既定値はASUS LANとIntel Windows 11 Ethernetの2targetであり、既存の上限32target、
公開source/field検査、3600秒の日予算、86400秒の待機、保護stateと再開を変更しない。
研究seed全件の収集、全台帳の索引生成、開発PC専用local-index、署名、GitHub送信の
自動化とは区別する。新規Taskのために既存開発原点、署名鍵、gh、外部Pythonを要求しない。

## 実行主体とAction

通常の`DriverCrate.exe`にTask管理を追加せず、収集用setupだけにnative Task Scheduler COMの
小さい専用moduleを置く。既存の管理者用登録scriptへ新しいper-user契約を混在させない。

TaskのActionは導入先の`bin/DriverCrateCollector.exe`一件とする。
引数は既存の`--once`、導入先`config/targets.json`、導入先`work/state/collector`だけを渡し、
WorkingDirectoryを導入先rootに固定する。nativeのcwd/ADR marker/state位置の検査を維持する。
任意command、任意Task名、shell、PATH探索、外部Python/PowerShellを実行依存にしない。
Taskを登録できただけで、別原点に固定されたlocal-index入口へ接続できたとはしない。

principalは現在のprocess user SID、`TASK_LOGON_INTERACTIVE_TOKEN`、`TASK_RUNLEVEL_LUA`とする。
setupのasInvokerを維持し、runas、password保存、S4U、SYSTEM/service account、別user、
Task登録を通すためのpolicy変更を追加しない。権限または組織policyの拒否はそのまま失敗にする。
Built-in AdministratorまたはUAC無効時はOSがRunLevelを無視するため、必ず非管理者で実行すると
保証しない。同じuserとAdministratorsを信頼する既存collectorの境界を維持する。

## 日次設定と開始境界

Taskは次の設定で登録する。

- PCのlocal時刻で毎日15:00、DaysInterval=1。初回は登録時から最低5分先となる未来の15:00。
- ログオン中のみ実行し、画面ロック中も実行できる。登録triggerとlogon triggerは作らない。
- StartWhenAvailable=false、MultipleInstancesPolicy=IgnoreNew、RunOnlyIfIdle=false、WakeToRun=false。
- DisallowStartIfOnBatteries=false、StopIfGoingOnBatteries=false。
- ExecutionTimeLimit=PT1H10M、AllowHardTerminate=false。

TaskのScheduler上限を既存nativeの日予算3600秒より短くせず、native側の有限処理を維持する。
OS I/OやCOM呼出しがhard deadlineで中断できる保証は追加しない。
登録時にはdisabledで作り、所有記録の保存後に未来の初回境界を再確認して有効化する。
install/uninstallからRun/RunEx/Stopを呼ばず、インストール中の即時収集、HTTP、driver操作、
署名、GitHub送信を開始しない。旧Taskの日程や設定を延長・変更しない。

## 所有記録と旧契約の分離

新Task名は現在SIDと検証済み導入rootから決定する専用prefixの一件とし、Scheduler rootで扱う。
manifestの版や表示名だけで別Task名を作らず、任意名/別folder/全Task列挙を入口にしない。
名前の一致だけでは所有と判定しない。

新v6の`install-receipt.json`は、同じ3fieldの`dc-collector-install-receipt-v2`とする。
これはfile配置と新user Task契約の識別であり、Task登録成功の証明そのものではない。
旧receipt-v1の意味を維持し、一般package検査はv1/v2の閉集合へ追従する。
旧local-index Taskの名前、固定scope、approved-origin、publisherの許可は広げない。

新専用planを`collector-user-task-plan.json`、所有receiptを
`collector-user-task-ownership.json` / `dc-collector-user-task-ownership-v1`とする。
現在SID、package root、package manifest hash、Task path、取引nonce、期待するAction/設定を
先行planへ結合する。登録後の原XMLはSettings/Enabledだけをtrue/falseへ置換した両hash、
owner/group/DACLの原SDDL hashとともに所有receiptへ結合する。他のXMLを正規化して
変更を許可せず、未知field、容量超過、不正hashを拒否する。

rootは既存のuser/SYSTEM/Administratorsのprotected DACLを維持し、receiptは同じ3principalの
継承ACLを持つ通常fileとする。実handle/path、owner/DACL、非reparse、単一linkを検査する。
旧`dc-collector-task-ownership-v1`のSYSTEM/Administrators専用owner/write条件を緩めず、
新user receiptを旧管理者Taskの所有証明として受け付けない。

receipt-v2の解除は新user Taskだけを扱う。旧管理者receiptが混在した場合は旧Taskの照会・変更前に
拒否する。旧receipt-v1の解除はADR0392の管理者用契約を維持する。
新Taskの受付や試験を理由に、旧Daily229/Smoke229をadopt、移行、変更、削除しない。

## 登録成功、失敗、修復

正常系は次の順序とする。

1. package/対象pathを検査し、配置と定期metadata収集への対話同意または明示`--yes`を得る。
2. 新規保護copyと全byte/配置receipt検査を完了し、configを既存native parserで非通信検査する。
3. 専用planを先行保存し、同名Taskの正常な不存在を確認する。既存Taskを暗黙上書きしない。
4. `TASK_CREATE | TASK_IGNORE_REGISTRATION_TRIGGERS | TASK_DONT_ADD_PRINCIPAL_ACE`でdisabled Taskを一回作る。
5. S_OKと、実TaskのSID/LUA/InteractiveToken、nonce、唯一のdaily trigger/Action/cwd、設定、
   非実行状態の読戻しを確認する。
6. 実XML/SDDLへ結合した所有receiptをflushし、ACL/byteの読戻しまで確認する。
7. package/Task/未来境界を再照合してEnabled=trueにし、S_OKと有効状態の読戻しを確認する。

disabled作成、定義出力、receipt保存だけを導入成功にしない。
SCHED_S_BATCH_LOGON_PROBLEMやSCHED_S_SOME_TRIGGERS_FAILED等の正値の警告も成功にせず、
HRESULTと段階、部分作用、UNKNOWNを保持する。完全な有効readbackまで成功表示・exit0にしない。

file copy/入力/plan保存で失敗した場合はTask作成へ進まず、部分program/dataを保持する。
作成後のreceipt保存失敗ではenableせず、同じ呼出しの作成証明と先行planのnonce/定義/SDDLを
再確認できた新disabled Taskだけを回収し、不存在を確認する。確認できなければ保持して非成功とする。
crash/timeoutを含む作成途中の回収も、同じplanのnonceと完全な期待契約を満たすdisabled Taskだけに
限定する。Task名だけを根拠にdelete/adoptせず、不明結果へ自動retry、enable、旧状態復帰を行わない。
enableや読戻しに失敗した場合もreceipt/program/dataを保持し、対話とCLIの両方で非成功を示す。

再導入で修復できるのは、同じmanifestと新receipt-v2を検証できる新配置のTask登録だけである。
完全一致enabledは冪等成功、Task欠損または所有disabledはprogram/config/stateをcopyし直さず
有限修復する。初回境界を過ぎた取引は、所有disabled/非実行を確認した回収と未来境界の新取引に
限定し、setup中にcatch-upしない。衝突、別SID/root/manifest/nonce、旧receipt、任意の既存directory、
未対応in-place upgradeは変更前に拒否し、旧Taskとdataを保持する。
既存のfile削除途中失敗に対する完全rollbackや、解除後の残存directoryへのin-place再配置を
実装済みとしない。待機を消すための新state/空rootへの作り直しを修復手順にしない。

## 解除とdata保持

通常`--uninstall`は、現在userの新Task一件のSID/実行契約/root/manifest/原XML/SDDLを照合する。
取得拒否、可視性不足、状態不明を不存在へ変換しない。running/queued/instanceありならStopせず
解除全体を中止し、program/dataを保持する。

非実行の再確認後、Enabled=false、disabled XML/SDDL/instance再確認、DeleteTask(0)、正常な不存在
確認の順とし、新Taskが存在しないことを確認してから固定管理fileを削除する。
一部失敗ではreceipt/program/dataを保持し、保存済みdisabled pinまたは既に正常不存在の対象から
再実行できる。非所有Taskは削除しない。Task管理の同時変更に対するCASはないため、同時操作を避ける。

設定、seed、work内state/待機/結果、未知file、自己setup、Uninstall.cmdは既存どおり保持する。
Task/plan/所有receiptは端末固有とし、可搬seed/exportへ追加しない。
新PCでは現在SID/rootから新Taskを登録するが、data copy/import成功からTask所有や通信許可を発行しない。
既存monitorの停止確認/import/元履歴保持や、開発用local-index原点の移行を今回の前提にしない。

## 確認画面、CLI、有限な受入

導入確認は一回で、配置先、現在Windowsユーザー用Task一件、対象config、15:00/ログオン条件、
将来の公式metadata通信を説明する。研究seed全件の収集やdriver本体取得/導入、署名/GitHub送信へ
同意したとは扱わない。`--install ROOT --yes`は同じ範囲の明示非対話同意とする。
検査modeはTaskを変更せず、最新v6の通常installを試験用no-opやdisabled-onlyへ変更しない。
失敗時はstage/HRESULTと保持状態、安全な次操作を示し、成功案内を出さない。

default unitはfakeだけとする。登録、正値警告/読戻し/receipt/enableの失敗、衝突、同一版修復、
旧境界の非接触、running/queued、解除途中失敗、data保持を決定的に検査する。
旧v1/v2等の非Task fixtureは維持し、v6の実install/解除は明示integrationへ分離する。
実Task試験は実行前に固定した最大二件の新規所有名だけを使い、旧Taskを照会・変更せず、
Run/Stop/HTTP/driver導入を行わない。実binary/config/cwdの非通信検査と、Actionの完全読戻しを分ける。
no-op Actionへ差し替えて日次収集の接続成功に数えない。

製品実装、fake、唯一buildでのx64 Debug/Releaseと必要な品質gate、実Taskの有効登録・読戻し・
削除・不存在/data保持、変更後単体EXE自身の導入/解除、公開候補閉包と文書一致を別に受け入れる。
本ADRの採用だけではこれらを完了にしない。自然日次の実通信、七日、再起動、別PC、全対象、
署名・公開・実driver導入は別の未確認として残す。

## 2026-10-23のsource実装における所有取引の補足（実Task/新EXE未受入）

先行planは閉schemaの8fieldとし、root/SID/manifest/導出名/nonce/初回境界に加えて、
`previousOwnershipSha256`を保存する。初回は空、同一版修復では直前の保護所有receiptの全fieldを
hashした値とする。新plan保存後から新receipt保存前に失敗して旧receiptだけが残っても、
この結合が一致する同じ取引だけを次の明示installで識別できる。
旧receiptを新Taskの所有証明へ転用せず、新planのnonce/全契約/SDDL policyに一致する
新disabled Taskだけを回収する。結合hashの改変、不一致nonce、別root/SID/manifestは拒否する。
この補足は復旧対象・Task名・実行権限を広げず、原設定・stateを保持する既存契約の実装詳細である。

新v2解除は編集可能なtargets.jsonのJSON内容をTask所有証明に使わない。通常file/実path/単一linkと
継承ACLを確認し、不正JSONもそのまま保持する。登録/修復では引き続き既存native parserを必須にする。
新v2解除はconfig/全体を保持し、旧receipt-v1の削除集合は変更しない。
新user所有metadataと旧配置receiptの混在も旧Task照会前に拒否し、schemaだけを書き換えて
Task不存在確認を迂回しない。新TaskのAction実EXEと継承親、配置receiptも既存の三principal規則で検査する。

明示SDDLは現在user/SYSTEM/Administratorsの三ACEをwriterが全て指定する。
[TASK_CREATIONの一次仕様](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_creation)に従い、
`TASK_DONT_ADD_PRINCIPAL_ACE`も指定してserviceによるprincipal allow ACEの自動追加を抑止する。
三ACEへの重複回避をOSの暗黙動作へ依存させず、CREATE/IGNORE_REGISTRATION_TRIGGERSと
protected DACL・owner/group・原SDDL pinの検査は維持する。実OSの登録/readbackは別の未確認である。

## 2026-10-23の実試験で判明したseparator不一致の修正

最初の実installは全75fileの配置後、新Action fileの保護検査で
`WORKSPACE_HANDLE_PATH`を返して停止した。Task作成前の失敗であり、固定二名は正常不存在だった。
新しい`withCollectorSetupProtectedFile`へ渡した混在separatorの入力文字列と、
`GetFinalPathNameByHandleW`のbackslash表記がordinal比較で不一致になることを実handleで確認した。

同helperの入口で`fs::path`を所有コピーし、`make_preferred`でseparator表記だけを揃え、
その同じ値を祖先・実file・継承親の検査に使う。`lexically_normal`によるdot componentの補正は行わず、
共有`openChecked`の実path比較、既存のowner/DACL、reparse、単一linkの拒否を維持する。
回帰は人工保護filesystemの同じ通常fileをbackslash/forward/混在、Unicodeと空白を含むpathで
実helperへ渡して確認し、dot/親参照・hardlink・不適格ACL・reparseの拒否も検査する。
元の実試験FAILと旧成果物は履歴として保持し、修正後の新成果物・同じ固定二名を別の有限工程で受け入れる。

工程345の限定修正と直接回帰・影響D/Rの確認後、新成果物の最初のnative installはTaskをdisabledで作成し、
登録後の`USER_TASK_CONTRACT`で停止した。先行planと原XML/SDDLを保持し、所有receiptは未作成である。
もう一件の固定名は正常不存在で、enable・通常解除・単体EXE自身の導入/解除は未受入である。
登録後XMLと未登録の期待XMLの構造差は別の原因調査へ残し、本工程で比較の緩和・所有receiptの後付け・
名前だけの削除・追加製品修正は行わない。元のFAILと新しいphaseの期限をどちらも保持する。

## 2026-10-23の登録XML表現差と未確定取引の解除

工程345の保存済み実XMLと未登録の期待XMLを比較し、登録時にSecurityDescriptorが追加され、
既定値8要素が省略され、子要素順序も変わることを確認した。原FAILとdisabled Task一件は保持する。
この表現差を設定改変と混同しないため、製品修正前に次の比較契約を採用する。

- 登録へ渡す三principalのSecurityDescriptorを期待XMLにも明示する。実Taskから未知の値を
  期待値へ取り込まず、独立したowner/group/DACL検査と所有receiptの原SDDL pinも維持する。
- Microsoftの[Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
  でxs:allのTask、RegistrationInfo、Principal、Settings、IdleSettings、ScheduleByDayだけは
  子要素順序に依存しない比較とする。Actions、Exec、CalendarTrigger等のsequenceは順序を保持する。
- 省略と同値に扱うのは、Principal/RunLevel=LeastPrivilege、SettingsのHidden=false、Priority=7、
  RunOnlyIfIdle=false、RunOnlyIfNetworkAvailable=false、StartWhenAvailable=false、WakeToRun=false、
  CalendarTrigger/Enabled=trueの8つの完全な名前空間付きpathと値だけに限定する。
  省略処理より前に重複を検査し、未知要素・属性・名前空間、非既定値、追加Action/trigger、
  DTD/外部参照を許可しない。Settings/Enabledの原byte pin方式は変更しない。
- この意味比較は初回所有確定と未確定disabled取引の回収用であり、所有receipt保存後は引き続き
  原XMLの両Enabled hashと原SDDL hashの完全一致を要求する。

解除時の所有receipt未作成だけを理由に、初回登録途中で止まった自分のdisabled Taskを
回収不能にしない。保護された新receipt-v2と先行plan、現在SID/root/manifest/導出名/nonce/境界、
空のpreviousOwnershipSha256を検証できる初回未確定取引に限り、通常の--uninstallでも
既存の同一plan回収規則を利用する。Taskが存在する場合は全期待契約・SDDL・disabled・非実行を
確認し、packageと削除直前の原pinを再照合してからDeleteTask(0)と正常不存在確認を行う。
正常不存在ならprogram削除へ進める。所有receiptを後付けせず、enable/Run/Stopも行わない。
planなし、enabled、running/queued、別設定、改変、取得拒否、旧管理者receipt、
前所有結合のある取引で所有receiptを失った場合は従来どおり拒否する。
通常の所有receipt付き解除とdata保持規則は維持する。

修正後は実OS登録前に、保存済み表現差を匿名fixtureへ置換した回帰、各既定値の非既定値・重複・
未知要素・sequence変更の拒否、未確定解除の正常/失敗/競合を決定的に確認する。
実Taskの後続工程は元の固定二名だけとし、旧phaseの期限・FAILを変更しない。
保持中の一件は修正後setupの通常--uninstallだけで解除し、名前だけの削除やmetadataの捏造をしない。
本追補の採用は製品修正・実解除・新単体EXE受入の完了を意味しない。

## 2026-10-23の修正後受入と有効XMLの既定値省略（工程347）

346のsource/決定的回帰の主担当受入後、新bundle/未署名単体EXEを生成し、75fileの閉包・元byte・
埋込み検査・既定38checkと通常build profileを確認した。保持中の初回pending一件は、新setupの
通常`--uninstall`で全取引照合を通って削除され、二名の正常不存在とprogram解除後のdata保持を確認した。
旧配置のmanifest/payload/receipt/planは上書きせず、所有receiptも後付けしていない。
解除後の人工fixtureだけを指定先へ一度保全退避し、元FAIL・期限と全relative byteを保持した。

同じ元root/固定二名の別20分phaseで、新native installは所有receipt保存と有効化の後、
`USER_TASK_XML_ENABLED`で停止した。一件は有効/state3/instance0で、所有receipt/plan/全75配置と
原XML/SDDLを保持した。もう一件は正常不存在で、再installや追加のTask変更は実施していない。
OSの原XMLは既定`Settings/Enabled=true`を省略したが、現`xmlPins`は実Enabledに一致する明示要素を
契約比較の前に要求する。保存済みXMLの一行省略以外を変えない仮想false/trueが、保存済み所有receiptの
両hashと完全一致した。この仮想byteを製品metadataやTaskへ書き戻していない。

保存済み原XMLを未登録NewTaskへloadした設定なし/false/trueのXmlTextも記録したが、
いずれも元原XMLまたは保存済み所有hashを再現しなかった。この未登録probeは実Task照会/変更を伴わない。
原XML両pinの表現契約の追加判断と製品修正は後続工程へ残す。本節は比較の緩和を採用するものではない。
初回pending解除の成功を完全な有効読戻し・通常所有Taskの解除・新単体EXE導入後の配置済み通常解除の
成功へ換算せず、新成果物は再修正後差替予定とする。単体EXEは導入入口で、解除は配置済みUninstall.cmdから
native setupの通常解除へ委譲する。自然日次・七日・再起動・別PC・署名/公開は未確認のままである。

## 2026-10-23の有効時Enabled既定行の省略

工程347で初回pendingの通常解除は成功したが、新規登録は所有receipt保存・有効化後に
USER_TASK_XML_ENABLEDで停止した。実OSはSettings/Enabled=trueも省略していた。
主担当は保存済み原XMLの他の全byteを維持し、Enabled行だけを挿入したtrue/falseの両SHA-256と
原SDDLのSHA-256が保護所有receiptへ完全一致することを独立確認した。
未登録NewTaskの再出力は順序と既定値も変え、原hashを再現しないため回収根拠にしない。

製品変更前に、意味比較の既定値省略へSettings/Enabled=trueを九番目の完全pathとして追加する。
APIの実Enabledとの整合を確認し、falseの省略、未知/重複/非既定値や別設定の変更は許可しない。
所有schemaと既存の明示true/false両pin、原SDDL pinは維持し、省略形の所有確認は次に限定する。

- 実Enabled=true、期待する全Task契約、原SDDL、非実行状態を先に検査する。
- 生XMLのSettings内にEnabledがない場合だけ、既知の直接子の行境界で一行を補った候補を有限に
  作る。候補は最大32、容量は従前の上限内とし、元の他の全byteを一切変更しない。
  indentationと改行は既存の直接子の行から限定取得し、解釈不能な形式は拒否する。
- 同じ挿入位置・同じ行形式の明示true/false両hashが、同一の保護所有receiptの両hashへ
  完全一致した場合だけ所有を認める。一方だけの一致、意味比較だけの一致、SDDL相違は拒否する。
  実原XMLのhashと検証用挿入候補のhashを区別し、仮想XMLを実取得原byteと表現しない。
- 候補XMLをTaskやmetadataへ書き戻さず、receiptの後付け・書換え・別schemaへの移行をしない。
  初回所有保存とdisabled回収では従来の実disabled原XMLと両pinを使用する。
  新しい正常解除も所有一致後のdisable→disabled原pin再確認→Delete→正常不存在の順を維持する。

これにより既に残った347の所有receipt付き有効Taskも、修正後setupの通常--uninstallで
検証して解除できる設計とする。実解除前に原hash・設定・非実行を再確認し、名前だけで削除しない。
匿名の実省略形、全残byte・両pin・SDDLの改変拒否、disable後の原pin一致、通常解除までを回帰する。
製品変更・試験後に主担当確認を挟んでから実Task受入へ進み、当該Taskのlocal15:00より前に完了する。
元347のFAIL・期限・保存byteは保持し、自然日次・七日・別PC・公開を検証済みにしない。

## 2026-10-23の限定修正と有限ライフサイクル受入（工程348）

有効Enabled省略では実原XMLのhashをそのまま保持し、既知Settings直接子の既存行から取得した
indentation/EOLで一行だけを挿入したtrue/false候補を別に持つ。現在の閉集合は最大13候補で、
契約上限32と65536文字の容量を守る。同じ候補対の両hashと保護ownerの両hash、原SDDLが一致する
場合だけ所有とする。全DOM契約・実Enabled・非実行を先行検査し、disabled時は従来の実原両pinを使う。
所有schema、receipt field、Task原XMLを書き換えず、既存enable/disable/削除/不存在の順序を維持した。

両構成の影響build・5suiteとU01-U40、変更規約・Doxygenを確認し、新75file bundleと未署名単体EXEを
資格化した。347の保持有効Taskは旧metadata/payloadの上書きなしに通常解除で削除し、dataを保持した。
初回348では製品installが完全な有効読戻しを通ってexit0になった後、独立試験のtyped UserId文字列表記
assertが停止した。実OSは短いaccount名、rawXMLは完全SIDを返した。rawXMLの完全namespace付き唯一
Principal/UserId=current token SIDを必須のまま、typed値はtokenのSID/完全Name/正確な末尾名の閉集合へ
試験だけを訂正した。任意account解決は行わず、LogonType/RunLevelと他の全設定・原両pin/SDDLは維持した。

原FAIL・期限を保持し、通常解除と承認先への相対byte保全後、同じ元root/二名の別原因変更済みphaseを
一回実施した。native/単体EXE双方で登録・有効読戻し・同版冪等・全75配置・非通信validate・配置済み通常
解除・正常不存在と、不正JSON/config/seed/work/未知fileの保持が通過した。Run/Stop/HTTP/旧Task操作0。
製品の再修正・再packageはなく、外側原streamと内側decoded streamの区分を保持する。
この受入は本PCの人工fixtureの機能確認で、自然日次・七日・再起動・別PC・全機器・署名公開の確認ではない。

## 一次仕様（参照先）

- [RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertaskdefinition)
- [TASK_CREATION](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_creation)
- [Security Contexts for Running Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
- [GetInstances](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-getinstances)
- [DeleteTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask)
