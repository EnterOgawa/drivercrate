# Architecture

## App用Setupとバージョン更新（1.0.5）

Appは現在ユーザーの`%LOCALAPPDATA%\Programs\DriverCrate`へInno Setupで配置します。
App/profile/配布文書の明示5fileだけを管理し、同じrootの私有Collectorと保持dataを別製品として扱います。
数値版/24hの純粋policy、専用AppUpdateService/worker、Windows backend、通常MainWindowの通知を小さく分けます。
HTTP・ファイル検査・Authenticodeは既共通moduleを再利用し、ProviderWorkerの操作/scan sessionや署名索引の権限と独立させます。
同意した署名Setupだけを元Explorerの通常ユーザーへ渡し、Appの正常終了後の置換は標準Innoが担当します。
同じ対話sessionのAppは配置を問わず一つとし、driver処理を強制終了するhelper/serviceは追加しません。
詳しくは[ADR0481](adr/0481-app-inno-setup-and-update-checks.md)を参照してください。実装と非通信fixture、隔離user領域でのInno確認を実施しました。将来の正式版への実自己更新と別管理者アカウントでの引継ぎは未確認です。

公開sourceはC++20/Win32のconsumer Appと非通信試験の明示集合です。CMakeの共通compiler/linker設定、
公開鍵と通常profileを維持し、私有の収集管理製品や索引発行者を含めません。

## UIとworker

UIはカテゴリ→現在のPnP deviceの二階層treeで一device一行です。デバイス名・現在版・候補版を表示し、
ダブルクリック詳細で取得元・信頼境界・問題状態・導入結果を確認します。同名の別device/functionは別行です。
検索/取得/検査/導入はworkerで行い、UI threadでblocking処理を実行しません。controllerがsession、取消し、結果を所有します。
Install後は処理した対象だけを読み取り専用で再照会し、結果と表示位置、未処理の対象の選択・候補を保持します。残りの導入では適用性、期限、同意と内容を対象ごとに検証します。

## Providerと共通取得

WUAは適用候補とcontent処理、Driver StoreはSetupAPIの互換listと直前再照合を正本とします。
公式Provider/署名索引/local ZIPの取得は共通のhash、署名、INF/CAT閉包、適合性、rank検査へ進みます。
collectorという名前を持つ共通取得/provenance/codecもAppに必要な部分は保持しています。
元target/record/deviceと取得byteを結び、他候補への検査結果転用や版番号だけの適合判定をしません。

## 署名索引

App Releaseと独立した固定先から署名manifestと索引assetを読み、公開鍵、hash、原期限、世代下限を検証します。
同世代・原manifest一致かつ保存cache再認証が成立する場合は、本体GETを省きます。未知/破損/失効は成功にしません。
端末照合はPC内で実施し、生inventoryを送信しません。store所有/保護と中断時の原状態保持を維持します。

## 導入と復旧

一deviceの基本driverは一候補を明示選択します。Installで集合を固定し、規約と必要条件への明示同意を結びます。
Windowsクライアントは同日に作成した復元ポイントの実在を確認して再利用し、保護を準備できない場合はProviderを呼びません。Serverは事前backup/checkpointの確認と同意を要求します。
部分失敗・実状態未確認・再起動待ちを分け、成功を推測して現在版を更新しません。
詳細は[利用ガイド](user-guide.md)と[security](security.md)を参照してください。
