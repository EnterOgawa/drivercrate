# DriverCrate Collector セットアップ案内

CollectorはWindows x64の収集PC用ツールで、通常の`DriverCrate.exe`とは別成果物です。
driver本体や通常アプリを同梱せず、配置だけで収集、規約同意、Task登録、GitHub送信、driver導入を開始しません。
現在は未署名の開発用previewです。現行ソースに対応するローカルv5 packageの有限な非通信受入は下記の範囲で完了し、実オンライン開始、別PCの実移設、日次継続は未受入です。

## Packageの違い

| 版 | 内容と入口 |
|---|---|
| v1 | 旧二sourceの手動metadata collectorとnative setup。 |
| v2 | v1に7 JSONの研究snapshotを追加。 |
| v3 | snapshot v4の8 JSON、固定10保守module、CPython 3.13.16 x64 embeddable全34 fileとmetadata。64 payload。 |
| v4 | 保護workspace、非通信initialize／verify／export／import／resumeを追加。69 payload。 |
| v5 | v4と同じ69 payload、正式原点に結合した明示一回monitor。未対応共有scopeはHOLD。 |

native collector／setupの起動に外部PythonやPowerShellは不要です。v3以降の明示packageは固定runtimeを
同梱し、v4／v5の明示workspace操作で使います。配置・copy・package検査だけではPythonを起動しません。
runtime全license／noticeを`runtime/LICENSE.txt`へ原byteで保持し、native／stdlib／`._pth`を変更しません。
研究seedは未署名情報で、最新版、実機適合、導入許可ではありません。

## 配置と検査

ZIPと同名の`.sha256`を照合し、新しいfolderへ展開します。SHA-256は破損・改変検知で、制作者認証ではありません。
`Install.cmd`で対象と変更を確認し、新規folderへ配置します。既定は実行userの
`%LOCALAPPDATA%\DriverCrate\Collector`です。既存先は空でも上書きせず、途中失敗も自動削除しません。

以下の大文字引数は、実行前に確認した絶対local pathへ置き換えるplaceholderです。空白を含む値は引用します。
package、workspace、移設元／先は相互に別の非重複rootとし、共有・取り外しdrive・reparseを含むpathを使いません。

```text
DriverCrateCollectorSetup.exe --check-package PACKAGE_ROOT
DriverCrateCollectorSetup.exe --install INSTALL_ROOT
DriverCrateCollectorSetup.exe --check-installed INSTALL_ROOT
```

配置先の`Validate.cmd`は旧手動collectorの入力と保存領域を非通信で検査します。
`config/targets.json`を確認した上で、引数なし`Collect.cmd`の明示通信確認に同意すると、ASUS公式catalogと
固定Intel Windows 11 Ethernet pageの旧metadata経路を一回実行します。台帳全体のmonitorではありません。
終了値は全件確認0、部分失敗1、入力／状態拒否2、通信取消し3です。本体取得・適合・導入成功ではありません。

## v4の保護workspaceと非通信移設

導入済みv4／v5の自己packageを検査し、同梱固定runtimeで明示操作します。
実行user、SYSTEM、Administratorsの保護DACL、通常file、祖先・hardlink等の条件を検査します。
既存の親folderや組織policyを変更して通しません。

```text
DriverCrateCollectorSetup.exe --workspace-initialize WORKSPACE --confirm-offline
DriverCrateCollectorSetup.exe --workspace-verify WORKSPACE
DriverCrateCollectorSetup.exe --workspace-export WORKSPACE EXPORT_ROOT --confirm-source-stopped
DriverCrateCollectorSetup.exe --workspace-import NEW_WORKSPACE SNAPSHOT --confirm-source-stopped
DriverCrateCollectorSetup.exe --workspace-resume NEW_WORKSPACE SNAPSHOT --confirm-source-stopped
```

旧hostのcollectorを停止し、終端を確認してからexportします。停止flagは申告であり遠隔停止ではありません。
hash・閉集合・元state／全reportを検証し、待機・失敗・旧成功・予算の来歴を保持します。
import成功だけでは通信を許可せず、`communicationAuthorized=false`、`nativeConstraints=UNKNOWN`、
`originalDayBudget=UNVERIFIED`を残します。resumeは中断した同一snapshotだけを受理します。
保護済みstateの単純copyや空rootで待機を回避せず、鍵、credential、実inventory、Task、通信同意を移送しません。
同一PCの人工移設と別PCの実受入は別です。

## v5の明示一回monitor

```text
DriverCrateCollectorSetup.exe --workspace-bind-origins WORKSPACE NATIVE_ORIGIN MONITOR_ORIGIN --confirm-source-stopped
DriverCrateCollectorSetup.exe --workspace-run-once WORKSPACE --confirm-monitor-once
```

既存の停止済みnative storeと非空のmonitor正本を選び、実directory identity・保護anchorと元履歴へ結合します。
正本が不明なら開始しません。copy／renameやmarkerだけで新しい正本にせず、import後も正式な再結合が必要です。
`Collect.cmd --monitor-once WORKSPACE --confirm-monitor-once`も同じ明示入口です。
実正本のbind／runと、このPCの開始許可は別の未受入事項です。

OS APIから得たSystem32 curlの実file、hash、共通cached-only署名検証を使い、PATHの別toolへ逃げません。
署名cache不足等は元errorで停止します。環境proxy／NO_PROXY、未設定時のOS／per-user／自動routeを尊重し、
未対応route・認証要求・解決失敗をDIRECTへfallbackしません。targetの公開DNSとCONNECT先IPを固定し、
元URLのTLS名とtrustを維持します。proxy値・credential・URLをlogや索引へ保存しません。

保持中native writerの検証済み履歴へ一回の非公開contextを結合し、非共有PAGEだけを既存run／saveへ渡します。
二held source、同URL alias、同native host、未知mode、未接続campaign／segmented共有予約はHOLDです。
monitor一回64要求／32MiB／600秒、24時間待機・host保留を維持し、通信action外側660秒、非通信180秒です。
native campaignの共有JST日1200予約／1GiB／初予約から14400秒は別制約で、未接続の共有予約を許可しません。
PAGE成功は本文・link hashとreview queueの観測で、driver本体や公開可能索引の成功ではありません。

## 作成者向けbuildとpackage

repository rootのx64 developer shellで、既存の単一`build/`を使用します。

```powershell
cmake --preset windows-x64 -DDRIVERCRATE_BUILD_COLLECTOR=ON -DBUILD_TESTING=ON -DDRIVERCRATE_BUILD_LIVE_TESTS=OFF -DDRIVERCRATE_LOCAL_INDEX_ACCEPTANCE=OFF -DDRIVERCRATE_LOCAL_INDEX_ACQUISITION=OFF -DDRIVERCRATE_BUILD_LOCAL_INDEX_SIGNER=OFF -DDRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB:FILEPATH= -DDRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256:STRING=
cmake --build build --config Debug --target DriverCrateCollector DriverCrateCollectorSetup --parallel 1
cmake --build build --config Release --target DriverCrateCollector DriverCrateCollectorSetup --parallel 1
```

ローカル索引受入・取得・署名toolのoptionはOFF、公開blob用のlocal cache値は空であることを確認します。
これは通常製品の固定配布公開鍵を空にする操作ではありません。package guardはEXEのhashと配布profileを照合します。
作成scriptは`scripts/package-collector.ps1`です。`-SeedSnapshot`はv2、`-RegistrySnapshot`と
`-PythonRuntimeArchive`の組はv3、さらに`-ProtectedWorkspace`でv4、`-ExplicitMonitor`でv5を選びます。
v3の組と`-SeedSnapshot`は併用できません。`-PythonExecutable`と`-OutputDirectory`で確認済み実体・新規出力先を
指定できます。固定公式CPython archiveのhash、全entry、x64、必要なPSF署名とlicenseを検査し、別版fallbackや
自動downloadをしません。作成にはPython 3.13と許可されたPowerShell環境が必要です。実行policyを変更しません。
データの非通信生成は[台帳説明](../data/collector-registry/README.md)を参照してください。

v5の作成例です。変数には検証済みの絶対pathを設定してください。`$Snapshot`は可搬研究snapshot、
`$RuntimeArchive`は固定版CPython原ZIP、`$PythonExe`は作成PCのPython 3.13、`$NewOutput`は新規出力先です。
scriptはビルド・runtimeのdownload・公開を行いません。既存の受入済みReleaseを再利用する場合は、
sourceとEXE／profileの一致を確認し、package作成のためだけに構成や試験設定を変えないでください。

```powershell
.\scripts\package-collector.ps1 -RegistrySnapshot $Snapshot -PythonRuntimeArchive $RuntimeArchive -PythonExecutable $PythonExe -OutputDirectory $NewOutput -ProtectedWorkspace -ExplicitMonitor
```

一意名のdirectory、ZIP、同名`.sha256`を作成します。ZIPを展開して内容とhashを検査し、
新規配置先で`--check-installed`まで確認してください。作成成功は収集開始や外部配布の承認ではありません。

## 解除と確認範囲

配置先の`Uninstall.cmd`で対象を確認します。固定の管理program、receipt、v3以降のmodule／runtimeを解除し、
`config/targets.json`、seed、work、未知file、自己EXEと`Uninstall.cmd`を残します。
v4／v5の固定`config/monitor-policy.json`は管理fileとして除去し、別workspaceは削除しません。
改変・欠損・reparse時は拒否し、workspaceを再帰削除しません。

2026-10-18の現行Release collector/setup・現module・同梱説明から新しいローカルv5 packageを一回作成しました。
この現物で展開・配置・検査・保持／解除、原34 runtime fileと全文license／研究seedの同一性、非通信の
初期化・検証・停止export／import・人工FILE_SAVED中断からのnative再開と移設先の再検査を確認済みです。
成果物の名前・hash・件数は[テスト方針](testing.md#最新collector-packageの非通信受入)に記載しています。
空のローカルmonitorによる確認で、実正本の運用履歴や別PC移設ではありません。主担当も現物と保存証拠を独立に読み直し、この有限な範囲を確認しました。
新規uninstall fixtureでは固定60 program fileを除去し、11 config／seed／setup／uninstall fileを保持しました。
過去の長パス有効のこのPCでの283文字配置確認は、全長・全shell・別PCの保証ではありません。
setupは長パス設定、ExecutionPolicy、UAC、Defenderを変更しません。

[ADR 0371](adr/0371-collector-legacy-store-extended-paths.md)では、検証済みlegacy storeの内部Win32表記を
既存collectionと同じextended DOSへ揃えます。外部path、保護ACL、reparse／hardlink、writer、
mode、同意の受理条件は維持します。任意長や別PCでの動作保証ではありません。
長いlegacy子を含むstate回帰はこのPCのDebug／Releaseで各65 assertions・失敗0でした。
89文字CWDのfocused確認は一部結果の継承を含む11/12で、Release campaign一件が未完了です。
その後の現sourceの品質結合と最新packageの有限な非通信受入は上記の範囲です。
ここに記した旧focused結果を全native再実行や実通信成功へ読み替えません。

実正本bindと確認を伴う一回開始、実route／DNS／HTTP、日次七回・再起動後運用、
別PCの移設・再開は未受入です。日次receipt／署名配布／Taskの開発入口は別の保護運用で、setup配置から
自動接続しません。現在の保護日次Taskは旧metadata-only構成で、acquisition-v2への配備・切替は未承認です。
通常アプリの実導入や外部配布の許可にもなりません。[テスト方針](testing.md)と[Release checklist](release-checklist.md)を参照してください。
