# ADR 0481: ユーザー領域へのApp用Inno Setupと通知からのアプリ更新

- 日付: 2026-11-11
- 状態: 採用・実装済み（G13-I7r822b/c/d）。source・非通信fixtureと隔離した通常userのInno有限確認を完了した。最終公開sourceと署名配布物の資格は822e/fの記録へ結ぶ。将来の正式版への実自己更新と別管理者アカウントでの引継ぎは未確認。
- 根拠: 利用者の「JSON配置が必要ならインストーラー方式」「アプリ側の自動更新」、続く「配置先はユーザー領域」の明示指示、ADR0379/0406/0460/0461/0472。

## 判断と今回の範囲

一般利用者向けAppをInno Setupで配置し、起動時と稼働中の24時間ごとに公式App Releaseを確認する。
新版を通知し、利用者が「更新する」を選んだ後にSetupを取得・検査して通常のインストーラーへ渡す。
従前のAppコピー配布を標準とする方針は、この最新指示で更新する。
初回版は1.0.5候補とし、既公開v1.0.4のtag・assetは変更しない。

私有Collectorとは別製品・別AppIdにする。Collectorの所有store、receipt、Task、移行journalをAppへ導入しない。
これはApp自身の版更新であり、署名索引の取得・世代・期限、ドライバーの取得・検査・導入・同意・復旧を変更しない。
製品runtimeはC++20/Win32とWindows標準APIだけで完結させる。新たな配布worker、service、Task、常駐機能は設けない。

## 確認した既存経路

| 対象 | 現状と再利用点 |
| --- | --- |
| src/app/main.cpp、main_window.cpp/.h | 管理者manifest、MainWindow、ProviderWorker、既busy判定と協調終了がある。通常起動に更新タイマー・更新設定はない。 |
| src/platform/official_http_client.cpp/.h、official_http_transport.h | WinHTTP、system/per-user proxy、HTTPS/host/redirect、宛先検査、取消し、streamと完全な試験I/O表を再利用できる。 |
| src/platform/official_file_verifier.cpp/.h | computeFileSha256、verifyOfficialFileMetadata、verifyAuthenticodePublisherがある。期待発行元は現署名のsimple name「ENTER SYSTEM, K.K.」。 |
| CMakeLists.txt、cmake/RecordIndexBuildProfile.cmake | 製品版1.0.4、x64専用、EXEとv2 profileのsha256・通常fingerprint・policy1結合がある。windowsapp/oleaut32/shell32も既linkする。 |
| scripts/release_signing.ps1、package-release.ps1 | App署名後のprofile再結合とZIPの5file集合を再利用する。既Installer署名入口は旧Collector名限定であり、App Setupのrole追加が必要。 |
| packaging/collector/collection-manager.iss | 通常Inno配置/解除、lowest、UseSetupLdr=x64の実例がある。Collector固有の停止・data再接続codeは転用しない。 |
| zrdpのdocs/client-updates.md、src/client/update/*、installer/app_installer_setup.iss | 起動時/24h、同意後取得、同じ新版の再通知抑止、worker分離、PrepareToInstallでの実行中/旧版拒否を参考にする。二EXE置換helper・独自manifestは移植しない。 |

read-onlyでGitHubのlatestを確認し、正式App v1.0.4、Release ID441149596、ZIP/checksum二assetを確認した。
現native/Python索引公開はprerelease=true・make_latest=falseであり、Appの正式latestと区別できる。
固定outputの署名AppはAuthenticode Valid、署名者thumbprintは既指定値と一致した。鍵は使用していない。
既Collector Setupの外側PEはAMD64だった。現在のInno scriptはx64 loaderを明示するが、内側engineやuninstallerとは区別する。

## 配置、権限、更新・解除

- 標準配置は %LOCALAPPDATA%\Programs\DriverCrate。PrivilegesRequired=lowest、現在user用shortcutと解除登録、UsePreviousAppDir=yesとする。全user登録やProgram Files配置は行わない。
- AppIdはApp専用に一つ固定し、CollectorのAB679A4F-A7B0-4C13-96D9-88F72EC0136Cとは分ける。更新・同版再install・通常uninstallはInnoの既存登録を使う。
- 同梱元はDriverCrate.exe、DriverCrate.exe.index-profile.json、README.md、LICENSE、THIRD_PARTY_NOTICES.mdの5fileを明示する。profileの意味とconsumer検証は維持する。
- [Files]はその5fileだけを指定し、再帰copy・再帰delete・{app}\*の削除を使わない。Inno管理のuninstallerとshortcutも通常の登録に限る。
- 同root内のCollector、隣接Collector-data、log、cache、設定、未知fileは更新・解除の対象にしない。rootに他のfileがあるだけでは拒否しない。旧コピー配置を探索して移動・削除する機能も追加しない。
- 既存の同名EXEがDriverCrateとして確認でき、同版または旧版なら通常更新する。新しい版を古いSetupで上書きしない。同名別製品・版を確認できないfileは、通常の説明で別配置または手動確認へ送る。
- ArchitecturesAllowed/ArchitecturesInstallIn64BitModeはx64os、UseSetupLdr=x64、MinVersion=10.0を基本とする。App payloadはAMD64のみ。[UseSetupLdr](https://jrsoftware.org/ishelp/topic_setup_usesetupldr.htm)と[architecture指定](https://jrsoftware.org/ishelp/topic_setup_architecturesallowed.htm)に従い、updaterはSetupをApp用x64 PE検査へ流さない。
- AppのrequireAdministratorとドライバー導入の権限境界は維持する。Setup完了画面の「DriverCrateを起動する」から通常起動し、WindowsのUACに従う。

[lowest](https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm)はper-user方式を選ぶもので、管理者Appからの子起動を自動的に元のuserへ戻す保証ではない。
更新のSetup起動は、同じ対話sessionのExplorer automation経由で通常userへ渡す。
別管理者の資格でAppを起動した場合も、admin tokenを削る方式や機械全体登録へ退避しない。
Explorerへの引継ぎが失敗したらAppを維持し、通常userによるSetup実行を案内する。
この実装は[MicrosoftのExplorer経由起動の説明](https://devblogs.microsoft.com/oldnewthing/20131118-00/?p=2643/)を参考に新規作成する。
Innoの[runasoriginaluser](https://jrsoftware.org/ishelp/topic_runsection.htm)だけで管理者App起点を補えるとは扱わない。

ユーザー領域を標準にする。SmartScreenはWindowsの標準判定と実署名の運用に従い、配置先だけで警告が出ないとは保証しない。

## 更新確認と画面操作

1. 通常Window作成後に一回確認し、以後は単調時計で24時間ごとに一回確認する。起動ごとの一回と稼働中の周期は区別する。スリープ中の実行・PC起動・経過日数分の連続実行は行わない。
2. 小さい「ヘルプ」menuに「アプリの更新を確認…」と、check付き「更新を自動確認」を置く。新しい設定画面は作らない。検索とドライバーinstallの二操作は維持する。
3. 自動確認は既定有効。選択したboolだけをEXEと同じ配置の任意DriverCrate.settings.iniへ保存する。file不在は既定値、無効/不正値は更新だけ停止し、保存失敗を操作別に表示する。repo・host・実行commandは設定できない。Innoはこの設定fileを同梱・上書き・解除しない。
4. 新版通知は現在版・更新先・「更新する」「あとで」を示す。「更新する」への明示選択前はSetupを取得しない。同じ新版の「あとで」は同processの周期確認で再通知せず、手動確認または次の通常起動で再検討できる。
5. 検索・取得・復元保護・ドライバーinstall・取消し/終了待ち・候補詳細/同意等のmodal中は通知と適用を待たせる。元の下部progressを上書きしない。idleへ戻ってから一回通知する。
6. App更新の取得を受理したら新規の検索/ドライバーinstallを無効にする。App更新の取消しや取得/検証失敗では元の候補・選択を保持して操作を戻す。driver operationの取消しや自動開始へ変換しない。
7. 自動確認だけの通信失敗はmodalで繰り返さず、手動確認と同意後の失敗は操作・安全な次操作・HTTP/HRESULTを示す。同版/旧版では更新を提案しない。

自動チェックを無効にした場合は次の自動通信を止める。手動確認はその一回だけ実行する。
確認・取得は一つの専用workerと一要求/一結果の有限交換にし、PostMessageでUIへDTOだけを渡す。
UI破棄後の遅延結果は適用しない。ProviderWorkerの操作ID・scan sessionや索引grantを更新workerへ流用しない。

## 公式取得とSetupの検査

確認先はGET https://api.github.com/repos/EnterOgawa/drivercrate/releases/latest に固定する。
[GitHub Release API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release)の正式公開情報を匿名で読み、
draft=false、prerelease=false、canonicalなvMAJOR.MINOR.PATCH、現在より大きい数値版を要求する。
版は各要素0..65535とし、PEの四要素末尾0へ対応させる。文字列比較や索引世代の比較は使わない。

新しい版だけについて、正確名DriverCrateSetup-windows-x64.exeのuploaded assetが一個、sizeが正の128MiB以内、
digestが有効なsha256であることを要求する。browser_download_urlも固定repo/tag/nameと一致させ、実際の起点はそのtupleから構築する。
asset名の部分一致、別repo、body内link、ZIPやCollector Setupを代替取得しない。
旧v1.0.4のように現在版以下なら、Setup未添付だけを更新失敗にしない。新しい版でSetup/digest等が欠ける場合は当該更新だけ拒否する。

- Metadataは256KiB/asset配列32件を上限とし、Windows SDKのWindows.Data.Jsonによる既存WinRT利用形を使う。必須型、欠落、重複asset、過大/不正UTF-8を拒否し、無関係な追加fieldは無視する。閉schemaの署名索引ReaderをGitHub汎用JSON用へ拡張しない。
- OfficialHttpClientにApp更新用途を限定した内部入口を追加する。既WinHTTP request/URL/DNS/stream/試験I/Oを再利用し、通常Providerのcache/ledger/grant・索引署名のpolicyを変更しない。
- APIはapi.github.comへredirectなし。Setupの起点はgithub.comの固定tag assetとし、最大4redirect・HTTPS/443・exact GitHub配布host（github.com、objects.githubusercontent.com、release-assets.githubusercontent.com）を毎hop照合する。元repoの変更、userinfo、fragment、private宛先、HTTPへの退避を拒否する。
- system/per-user proxy、TLS、OSの信頼policyを維持し、認証token/cookie/既定server資格・inventoryを送らない。API本文・期限付きredirect URL・署名識別値を通常logへ保存しない。
- 通信のcheckpoint・取消しと既WinHTTP timeoutを使い、metadataは15秒、Setup取得は2分のphase目安とする。HTTP 403/429/Retry-After等は失敗と次回下限へ保持し、自動の即時再送をしない。Windowsの同期DNS/WinTrustまでその秒数で強制終了できるとは表明しない。
- downloadは当該App配置の専用一時領域.app-update内の固定part/Setupだけへstreamする。単一更新lock、通常file/reparse/共有確認、上限、exact size/hash、flush後に候補を確定する。自己管理した二file以外は掃除しない。保留は一つに限り、前回のcacheを起動時に自動実行しない。
- 取得後と引継ぎ直前に、exact SHA-256/size、Windows Authenticode成功、期待発行元「ENTER SYSTEM, K.K.」、SetupのProductName「DriverCrate」/FileDescription「DriverCrate Setup」、VS_FIXEDFILEINFOのFileVersion/ProductVersionの期待四要素を検査する。発行元はHTTPSやfilenameだけで確定せず、現certificateのthumbprintを永久pinする方式も採らない。
- 共通verifyAuthenticodePublisherのOS chain/revocation検証を使い、[WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)は0だけを成功とする。失敗/未確認の署名を許すfallbackは設けない。stageの書換え/削除を禁止したread handleを引継ぎまで保持し、検査済みbyteと実行対象を結ぶ。

新たなApp更新用署名manifest、独自鍵配布、独自DB、任意URL設定は設けない。
GitHub APIのdigestは輸送byteの一致、Authenticodeは期待発行元の検査として扱い、索引署名とは別用途にする。

## 終了と通常Setupへの引継ぎ

更新状態は概ねIdle → Checking → Offered → Downloading/Verifying → Ready → HandingOff、拒否/失敗/取消しはIdleへ戻す。
Providerのbusy/modal/終了状態を引継ぎ直前にも再検査する。強制終了やdriver operationへの更新command注入は行わない。
検査済みSetupだけをExplorerへ渡し、引数は元userのLocalAppData内と検証した実App配置の/DIR一つに限定する。remote由来の引数・silent install・runasを使わず通常wizardを開く。
引継ぎ要求が失敗すれば元Appを保つ。成功したら新規commandを閉じ、更新worker/ProviderWorkerと診断を既存の正常終了経路で完了させる。
Appと同じ場所のfile置換はInnoが行い、同じAppのcopyによる置換helperは作らない。

Appは生存中だけの固定Local named mutexにより、同じ対話sessionでは配置を問わず一つだけ起動する。
822c2の主担当reviewで、当初の「同配置」という記述と実装の範囲差をこの方針へ整合した。
別コピーから独立したドライバー操作や更新・解除を同時に始めないためであり、PC全体・別sessionの排他保証ではない。
Setup/解除も同sessionの稼働App（別コピーを含む）の通常終了を案内し、強制終了しない。
Setup側はSetupMutexで同製品の二重Setupを避ける。
自己更新ではSetup起動時に親Appがまだ終了中になり得るため、AppMutexの起動時dialogへ依存せず、
[PrepareToInstall](https://jrsoftware.org/ishelp/topic_scriptevents.htm)で[CheckForMutexes](https://jrsoftware.org/ishelp/topic_isxfunc_checkformutexes.htm)と対象file使用中を再確認し、copy前に通常の中止理由を返す。
CloseApplications=no、RestartApplications=noを基本とし、他のApp instanceやdriver処理をSetupから閉じない。
uninstallも稼働Appがあれば通常の終了案内で止める。rootにCollectorが存在することはApp稼働中とは扱わない。

Setup取消し/失敗後に、更新成功とは表示しない。通常のInno rollbackに従い、電源断を含む複数fileの完全atomic性は保証しない。
EXE/profileの不一致は既consumer検証で拒否し、同じ正規Setupの通常再実行で修復する。
成功時はSetup完了の起動checkboxから新版を開く。scan/選択/同意・driver操作の自動再開は行わない。

## 最小の変更候補と配布順

新規sourceはsrc/core/app_update.h/.cpp（版/DTO/純粋policy）、src/platform/app_update_service.h/.cpp（GitHub解析・取得/検証backend・専用worker）、
src/platform/app_update_windows.cpp（Windowsのfile/署名/Explorer境界）、src/app/main_window_app_update.cpp（更新menu/通知/正常終了への結合）を基本とする。
既main/main_window/resource、OfficialHttpClient、CMakeへ必要な接続だけを追加し、
packaging/app/app.iss、scripts/package-app-setup.ps1と対応するunit/HTTP/UI/package fixtureを追加する。
新source/installer/test/必要文書だけをscripts/public_source_export_manifest.jsonへ明示追加し、Private CMakeをPublicへ一括copyしない。

通常build/packageは証明書なしでも同じ固定名を生成する。最終Releaseは次の順とする。

1. 公開snapshot自身から唯一build/で必要なDebug/Release、関連試験・解析/品質gateを確認する。
2. 最終Appへ既helperでAuthenticode/RFC3161署名し、その後のEXE SHAへprofileを再結合する。
3. 同じ署名App/profileと公開文書だけからInnoを作る。最終配布ではInno SignTool/SignedUninstallerを使い、標準uninstallerと一時engineも実署名確認する。[SignedUninstaller](https://jrsoftware.org/ishelp/topic_setup_signeduninstaller.htm)参照。
4. 最終Setupの署名・発行元/時刻証明・版・実展開した5file/profileを確認してからchecksumを作る。既x64限定PE署名helperをInno内部x86へ無条件適用しない。必要ならAppInstaller/Inno内部専用roleを小さく追加し、App payloadのx64制限は維持する。
5. output直下のDriverCrate.exe/profileとDriverCrateSetup-windows-x64.exe/.sha256を固定名更新する。署名有無による別名・版別folder・新output subfolderを作らない。Innoの署名用中間fileはbuild/generated等へ置く。
6. 新App正式Releaseの基本assetをSetup/checksumにし、latestへ結ぶ。既ZIPは補助の手動配布として生成可能だが、READMEの標準入口とupdaterはSetupを使う。既v1.0.4は不変。
7. README/guide/release/security/testingは実装後に整合し、手動JSON配置説明を標準手順から外す。検索→チェックしてinstall、任意の版/取得元詳細を実button名と画像で維持する。公開build/package完了後は既方式で通常Private設定へ戻す。

## 有限な実装・受入計画

822cへ進む前に、小工程を実装・非通信確認・実install/文書に分けてroadmapへ登録する。主担当822bの確認前には実装しない。

| 区分 | 固定して確認する内容 |
| --- | --- |
| 純粋policy/worker | 数値版の大小/桁あふれ、正式tag、draft/prerelease、asset欠落/重複/別repo/別名/size/hash不正、busy/modal通知待ち、同意前download 0、あとで/手動確認、二重要求/遅延result/close、fake時計の起動・24h・sleep復帰/rollback。 |
| HTTP/署名/引継ぎ | 完全なfake I/Oで許可route、HTTP/port/private/redirect過多、oversize/途中切れ/取消し/Retry-After、hash/版/発行元/未署名拒否、元byte差替え拒否、Explorer失敗時App保持、busy時Setup起動0。実Inno loaderをApp PE検査で誤拒否しないこと。 |
| UI/既回帰 | 元MainWindowの検索・導入終了/候補保持・準備/同意・遅延通知、既HTTP/Authenticode/profile/package試験と変更source品質を必要範囲で確認する。UI fixtureは実driver導入なし。 |
| 通常Inno | 未署名の内部fixtureと実配布物を区別する。現在user登録、5file同配置、App起動、同版修復/新版更新、旧版/使用中拒否、取消し、通常uninstallを有限確認し、残す設定/log/Collector/Collector-dataの無変更を確認する。 |
| 最終署名/public | 署名後App/profile、Inno内部/outer・実展開payload、固定asset/checksum、最終public sourceの必要D/R・関連試験/品質、公開metadata/新規download/署名を主担当が受入する。 |

今回のaは調査・設計だけで、code変更、build、test、署名、package、実install、remote writeは行わない。
最初の更新対応版は旧1.0.4から手動Setupで導入する。1.0.4には更新機能がないため、それ以前からの自動更新成功は表明しない。
次の正式版を使う実GitHub往復の自動更新は、非通信fixture・実Setup引継ぎ・同版再installとは別の実績として記録する。
全旧基盤の再監査、七日運用、全deviceや実driver導入を今回のApp更新受入の前提に追加しない。
