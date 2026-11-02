<h1 align="center"><a href="src/app/assets/drivercrate.ico"><img src="src/app/assets/drivercrate-icon-master.png" width="64" height="64" alt="DriverCrateの木箱アイコン"></a> DriverCrate</h1>

<p align="center"><strong>ドライバー探しを、かんたんに</strong></p>

DriverCrateは、Windows Updateやメーカーの公式配布元からドライバー候補を探し、見比べて選べるWindowsアプリです。
機器ごとに現在のドライバーと候補を並べ、取得元・検査結果・導入結果を確認できます。

このソースの製品版は **1.0.0 / Windows x64** です。
1.0.0のアプリ／Collector binaryは公開前のローカル候補です。公開後の正式な配布先は [Releases](https://github.com/EnterOgawa/drivercrate/releases) です。
ローカル候補のAppとCollector SetupはAuthenticode署名と時刻証明を検証済みです。Appは署名前の内容保持も確認しました。
正式配布に使う自作EXEは最終byteで署名を検証します。受け取ったfileごとの署名状態も確認してください。
索引署名は別用途の専用鍵で検証します。通常のソースビルドは証明書不要です。
版ごとの確認範囲は [リリースノート](docs/release-notes-1.0.0.md) にあります。

## ✨ できること

| 取得元 | 機能 |
|---|---|
| Windows Update / WSUS | WindowsがこのPCに適用可能と判定した未導入ドライバーを検索・選択・取得・導入します。管理ポリシーを尊重します。 |
| Windows Driver Store | 現在接続されている機器の互換ドライバーを列挙し、選んだ候補を指定して導入します。 |
| 公式カタログ・公式ページ | Dell・Lenovo・HP・VAIOなどの配布情報を調べます。取得・内容検査・導入への対応範囲は経路によって異なります。 |
| 署名索引 | GitHubの固定配布先から索引を取得・検証し、PC内で照合して候補表示と取得・内容検査へつなぎます。 |
| ローカルZIP | 指定した対応形式のドライバーを検査し、このPCへの適合性を確認します。 |

「取得元」で使う経路を確認・変更できます。主一覧は「種類→デバイス」の二階層で、一つの機器を一行に
まとめます。一覧はデバイス名・現在版・候補版の三列で、状態や複数候補の版・取得元は詳細で確認し、一件を選択します。
取得前の配布情報、内容検査済みの候補、検索失敗、未確認を区別し、0件を「すべて最新」とは扱いません。
推奨表示では、登録済み機器の版不明参照や検査済み同版を更新へ数えず、未導入機器の「初回の確認候補」を検査済み候補と分けます。
登録済み・状態不明の版不明な取得前情報や同版・旧版は、全候補表示の詳細で一件を明示指定できます。
詳しい対応範囲と操作は [利用ガイド](docs/user-guide.md) を参照してください。

## 🌱 対応範囲

収集PC用データには、**127メーカー・6,584製品参照・1,718研究用配布record** を登録しています。
公式ページなどのlocatorは390件、検査用取得の条件を確認した汎用profileは既存1 record分です。
native Intelの収集は別の経路です。製品参照や研究recordは、検証済みドライバー対応数ではありません。

通常アプリは公開された署名索引を検索時に取得する方式です。索引の同梱数は対応数を表しません。
既存の公開署名索引は世代10・Windows 11向け3 record・2 sourceで、原期限は2026-11-02 09:28:33 UTCです。
収録数とPCへの適合数は別で、端末内の照合結果に応じて候補が変わります。期限の延長や今回の再発行はしていません。
研究登録・検査済みpackage/INF・署名索引の収録数・実機適合・実導入の実績は、
[リリースノートの対応範囲](docs/release-notes-1.0.0.md#対応範囲と件数の見方) に分けて掲載しています。
元データの意味は [同梱データの案内](data/collector-registry/README.md#データの意味) にあります。

メーカーの公式情報を確認しながら、対応するメーカーや機器を順次増やしていきます。
利用者から、1.0.0でNICのインストールが正常に完了し、表示も期待どおりだったと報告を受けています。
報告時の実行ファイルのhashは採取しておらず、署名後のAppを起動し直した動作と実導入は別途未確認です。
他機器・各OSでの動作を含め、すべての機器への対応を保証するものではありません。

## 🚀 使う流れ

アプリ用ZIPを展開した、またはソースからビルドした `DriverCrate.exe` を使います。
先に重要なデータをバックアップし、元のドライバーへ戻す方法を確認してください。

1. 起動してUACを確認し、「更新を検索」を押します。検索は候補を表示して止まり、取得準備の確認は表示しません。
2. 一覧で対象を選び、「選択した更新をインストール」を押します。元配布物に結合した取得前候補も選べます。
   公式取得の規約は選択時に主画面で案内し、原全文を任意に閲覧できます。「同意してインストール」で
   同じ選択・規約へ同意し、別のEULA画面を挟まず、選択した配布物の取得・検査と唯一の適合候補への導入へ進みます。
   版・適用性が未確認の情報を導入可能と扱いません。複数候補や新たな旧版切替は理由を表示して停止します。
   Clientは復元ポイント必須、Serverは事前backupの確認が必要です。詳細は行のダブルクリックで開けます。

導入完了後は推奨・初回候補の表示フィルターを解除して全デバイスを表示し、選択対象の読み取れた現在版と個別結果を保持します。
二段階の接続や部分失敗などは内部fakeでも確認しています。

再検出中にWindowsが保存済みドライバーを自動適用する場合があります。これはDriverCrateで選択した
候補の導入とは別です。検索前再検出を含む署名後Appの実動作は別途未確認です。

## 🛡️ 導入とプライバシー

- DriverCrateによる導入は明示選択しInstall操作を行った対象だけです。必須規約、復旧、旧版・方式の新たな条件を確認します。
- Windowsクライアントでは、導入前の復元ポイント作成が必須です。失敗した場合は導入を中止します。
  復元ポイントは完全なバックアップや復旧保証ではありません。
- Windows Serverでは復元ポイントを作成しません。事前のバックアップ／チェックポイントと復旧手順を管理者が確認し、
  専用の警告へ同意する必要があります。DriverCrateはServerのバックアップを作成・検証しません。
- 公式配布元の候補も、取得元・署名とハッシュ・内容・PCへの適合性をそれぞれ確認します。
  BIOS・UEFI・ファームウェア、OEMユーティリティや一般アプリは導入対象外です。
- UAC、Windows Update／WSUS、プロキシ、証明書、DefenderやFirewallの制限を回避しません。
- 広告・利用追跡・自動クラッシュ送信はありません。生の機器ID・シリアル番号や機器一覧を外部へ送信しません。
  索引配布にドライバー本体・実端末情報・認証情報・署名秘密鍵を含めません。

詳細は [セキュリティ設計](docs/security.md)、不具合を共有するときの注意と非公開の報告先は
[SECURITY.md](SECURITY.md) にあります。

## 🖥️ 動作環境

Microsoftのサポート対象となるWindows 10／11と対応するWindows Serverの **x64版** が対象です。
各OS・機器での実測範囲はリリースノートを確認してください。起動には管理者権限、
オンライン検索には利用するWindows Update／WSUS・公式配布元への接続が必要です。

通常アプリに外部の言語ランタイム、AIモデル、専用GPU／NPUは不要です。

## 📦 収集PC用セットアップ

`DriverCrateCollectorSetup` は通常アプリと別の成果物です。固定版CPythonと研究データを含み、
通常installへの同意で現在ユーザー用のmetadata収集Taskを毎日15時に登録します。
検査用取得のTaskは別の明示同意で毎日17時に登録します。ログオン中に動作し、copy/importだけで収集を始めません。

日次処理は未署名候補までです。署名とGitHub公開は手動の別操作です。
通常uninstallでは所有Taskの正常不存在を確認して管理プログラムを解除し、設定・収集データ・待機履歴を保持します。
操作と制限は [セットアップ案内](docs/collector-setup-guide.md) にあります。

## 🔧 ソースからビルドする

Windows x64で、MSVC C++開発ツール、Windows SDK、Ninja、**CMake 3.30以上** を用意します。
x64 Native Tools／Developer PowerShellを開き、リポジトリのルートで実行します。
初回構成では、固定版・固定ハッシュのminizとLZMA SDKソースを取得します。

```powershell
cmake --preset windows-x64
cmake --build --preset debug
ctest --preset debug
cmake --build --preset release
ctest --preset release
```

同じ `build/` にDebug／Releaseを生成します。Release版は `.\build\Release\DriverCrate.exe` です。
実サービスへのlive試験、ローカル索引の受入・取得・署名ツール、静的解析は既定でOFFです。
追加テストと品質確認は [貢献方法](CONTRIBUTING.md) と [テスト方針](docs/testing.md) を参照してください。

## 📚 設計とライセンス

[アーキテクチャ](docs/architecture.md) ／ [利用ガイド](docs/user-guide.md) ／ [リリースノート](docs/release-notes-1.0.0.md)

制作者：**Shunji Ogawa**（EnterSystem）  
Copyright (c) 2026 EnterSystem CO.,LTD.

正式なリポジトリは [EnterOgawa/drivercrate](https://github.com/EnterOgawa/drivercrate) です。
自作ソース・文書・アイコンには [Apache License 2.0](LICENSE) を適用します。
第三者資産の条件は [Third-Party Notices](THIRD_PARTY_NOTICES.md) を参照してください。
DriverCrateは独自に作成したアプリで、Snappy Driver Installer Originのforkやバイナリー再配布ではありません。
