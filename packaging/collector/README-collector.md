# DriverCrate Collector 手動セットアップpreview

Windows x64専用の未署名の開発用previewです。通常のDriverCrate.exeやdriver本体は同梱しません。
配置先にビルド環境、外部PowerShell／Python、GPU、AIモデルは不要です。
配置だけで収集、規約同意、Task登録、GitHub送信、driver導入を開始しません。

## 配置

1. ZIPと同名の`.sha256`を照合し、新しいfolderへ展開します。
2. `Install.cmd`を開き、対象と変更を確認します。既定先は実行userの`%LOCALAPPDATA%\DriverCrate\Collector`です。
3. 配置先の`Validate.cmd`で旧手動collectorの入力と保存領域を非通信検査します。
4. `config/targets.json`を確認し、引数なし`Collect.cmd`で明示的に同意した場合だけ公式metadataを一回収集します。

別の新規先を使う形式は次のとおりです。大文字引数は確認済み絶対local pathへ置き換え、空白を含む値は引用します。

```text
DriverCrateCollectorSetup.exe --install INSTALL_ROOT
DriverCrateCollectorSetup.exe --check-installed INSTALL_ROOT
```

既存先は空でも上書きしません。共有・取り外しdrive・reparseを含むpathを拒否し、途中失敗を自動削除しません。
SmartScreen、証明書警告、組織policyを回避しないでください。SHA-256は制作者認証ではありません。
setupは長パス対応manifestを持ちますが、Windows側の設定に従い、全長・全shell・別PCの動作を保証しません。
ExecutionPolicy、UAC、Defender、長パス設定を変更しません。

## 同梱データと版

v1は旧二sourceの手動metadata版、v2は7 JSONの研究seed付きです。
v3はsnapshot v4の8 JSON、固定10保守module、CPython 3.13.16 x64 embeddable全34 fileとmetadataを持つ64 payload版です。
全runtime license／noticeを`runtime/LICENSE.txt`へ原byteで保持し、native、stdlib、`._pth`を変更しません。
v4／v5は固定adapter、monitor policyと入口を加えた69 payload版です。
配置・copy・package検査だけではPythonを起動しません。v4／v5の明示workspace操作は同梱runtimeを使用します。

seedは未署名の研究情報です。件数は同梱snapshotのmanifestと索引のcountsで確認してください。
snapshotとpackageの世代を区別し、調査件数を実収集数、driver対応、機器適合、導入許可へ換算しません。`researchOnly=true`、`publishable=false`、
`installAuthorized=false`、`applicability=NOT_CHECKED`を維持します。
旧Collect.cmdはASUS catalogと固定Intel Windows 11 Ethernet pageだけの手動経路で、台帳全体のmonitorではありません。
終了値は全件確認0、部分失敗1、入力／状態拒否2、通信取消し3です。本体取得・導入は行いません。

## v4の非通信workspace

package、workspace、移設元／先は互いに別の非重複rootを使います。元collectorの停止と終端を確認します。
停止flagは利用者の申告で、旧hostの遠隔停止ではありません。

```text
DriverCrateCollectorSetup.exe --workspace-initialize WORKSPACE --confirm-offline
DriverCrateCollectorSetup.exe --workspace-verify WORKSPACE
DriverCrateCollectorSetup.exe --workspace-export WORKSPACE EXPORT_ROOT --confirm-source-stopped
DriverCrateCollectorSetup.exe --workspace-import NEW_WORKSPACE SNAPSHOT --confirm-source-stopped
DriverCrateCollectorSetup.exe --workspace-resume NEW_WORKSPACE SNAPSHOT --confirm-source-stopped
```

保護DACL、祖先、reparse／hardlink、hash、閉集合、state／全reportを検査します。
既存先や改変を拒否し、部分stateを保持します。resumeは中断した同一snapshotだけに使用します。
元待機、失敗、旧成功を維持しても、通信許可はfalse、native制約と元日予算は未確認です。
保護stateを単純copyして新しいrootから開始せず、鍵、credential、実inventory、Task、通信同意を移送しません。
初期seedの配置は稼働stateの移設ではありません。

## v5の明示一回monitor

```text
DriverCrateCollectorSetup.exe --workspace-bind-origins WORKSPACE NATIVE_ORIGIN MONITOR_ORIGIN --confirm-source-stopped
DriverCrateCollectorSetup.exe --workspace-run-once WORKSPACE --confirm-monitor-once
```

既存の停止済みnative storeと非空monitor正本を実directory identity・保護anchor・元履歴へ結合します。
正本が不明なら開始しません。copy／renameやmarkerだけで待機を初期化しません。
同じ入口を`Collect.cmd --monitor-once WORKSPACE --confirm-monitor-once`でも指定できます。
v4は非通信のままです。実正本bind／run、このPCの開始許可は未受入です。

System32 curlの実file・hash・cached-only署名を検査し、別toolへfallbackしません。
環境proxy／NO_PROXYとOSのrouteを尊重し、未対応・認証要求・解決失敗でDIRECTへ逃げません。
公開target DNSとCONNECT先IP、元URLのTLS名・trustを維持し、proxy値・credential・URLをlogへ保存しません。
保持中native writerの元履歴に一回contextを結合し、非共有PAGEだけを扱います。
二held source、同URL alias、同native host、未知mode、未接続のcampaign／segmented共有予約はHOLDです。
monitorは一回64要求／32MiB／600秒、24時間待機・host保留、外側660秒、非通信180秒を維持します。
native campaignの共有JST日1200予約／1GiB／初予約から14400秒は別制約です。
PAGE成功は本文・link hashとreview queueで、driver取得や公開可能索引の成功ではありません。

## 検査・解除と制限

`Uninstall.cmd`は対象を確認後、固定管理programとreceiptを解除します。v3以降のmodule／runtimeも管理対象です。
`config/targets.json`、seed、work、未知file、setup EXEとUninstall.cmdは残します。
v4／v5の固定`config/monitor-policy.json`は除去し、別workspaceは削除しません。
改変・欠損・reparse時は拒否し、workspaceを再帰削除しません。

現行ソースに対応するローカルv5 packageは、このPCで展開・配置・検査・保持／解除と非通信の初期化・検証・
停止export／import・人工中断からのnative再開を有限に確認済みです。空のローカルmonitorによる確認で、
実正本の結合・確認を伴うオンライン開始、実route／DNS／HTTP、日次七回・再起動後運用、別PC移設は未受入です。
この確認は実際に検査したpackageに限り、後続の変更や別PCへ自動的に引き継ぎません。
日次receipt／配布／Taskの保護運用は別で、setupから自動開始しません。
現在の日次Taskは旧metadata-only構成で、acquisition-v2への配備・切替は未承認です。
実driver導入、外部配布、Public化の許可を意味しません。本人がsource、README、最終公開一覧、検証結果を
確認し別途明示承認するまで公開しません。

Sourceとdocumentのlicenseはrepository rootの[LICENSE](../../LICENSE)、第三者表示は
[THIRD_PARTY_NOTICES](../../THIRD_PARTY_NOTICES.md)を参照してください。
配布packageでは、展開先直下に同梱する`LICENSE`と`THIRD_PARTY_NOTICES.md`を参照してください。
作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
