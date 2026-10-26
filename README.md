<h1 align="center"><a href="src/app/assets/drivercrate.ico"><img src="src/app/assets/drivercrate-icon-master.png" width="64" height="64" alt="DriverCrateの木箱アイコン"></a> DriverCrate</h1>

<p align="center"><strong>ドライバー探しを、かんたんに</strong></p>

DriverCrateは、Windows Updateやメーカーの公式配布元からドライバー候補を探し、見比べて選べるWindowsアプリです。
機器ごとに現在のドライバーと候補を並べ、取得元・検査結果・導入結果を確認できます。

このソースの製品版は **0.1.1 / Windows x64** です。
配布されている版とファイルは正式な [Releases](https://github.com/EnterOgawa/drivercrate/releases) で確認してください。
この版の自作EXEはコード署名なしです。索引は専用鍵で署名し、別に検証します。通常のソースビルドは証明書不要です。
版ごとの確認範囲は [リリースノート](docs/release-notes-0.1.1.md) にあります。

## ✨ できること

| 取得元 | 機能 |
|---|---|
| Windows Update / WSUS | WindowsがこのPCに適用可能と判定した未導入ドライバーを検索・選択・取得・導入します。管理ポリシーを尊重します。 |
| Windows Driver Store | 現在接続されている機器の互換ドライバーを列挙し、選んだ候補を指定して導入します。 |
| 公式カタログ・公式ページ | Dell・Lenovo・HP・VAIOなどの配布情報を調べます。取得・内容検査・導入への対応範囲は経路によって異なります。 |
| 署名索引 | GitHubの固定配布先から索引を取得・検証し、PC内で照合して候補表示と取得・内容検査へつなぎます。 |
| ローカルZIP | 指定した対応形式のドライバーを検査し、このPCへの適合性を確認します。 |

「取得元」で使う経路を確認・変更できます。候補は「種類 → 機器 → ドライバー」の一覧に表示します。
取得前の配布情報、内容検査済みの候補、検索失敗、未確認を区別し、0件を「すべて最新」とは扱いません。
詳しい対応範囲と操作は [利用ガイド](docs/user-guide.md) を参照してください。

## 🌱 対応範囲

収集PC用データには、**127メーカー・6,584製品参照・1,718研究用配布record** を登録しています。
公式ページなどのlocatorは390件、検査用取得の条件を確認した汎用profileは既存1 record分です。
native Intelの収集は別の経路です。製品参照や研究recordは、検証済みドライバー対応数ではありません。

通常アプリは公開された署名索引を検索時に取得する方式です。索引の同梱数は対応数を表しません。
署名索引の発行候補は世代9・Windows 11向け2 record・1 sourceで、原期限は2026-11-02 09:28:33 UTCです。
ローカル署名検証済み・公開前の記録です。収録数とPCへの適合数は別で、端末内の照合結果に応じて候補が変わります。
研究登録・検査済みpackage/INF・署名索引の収録数・実機適合・実導入の実績は、
[リリースノートの対応範囲](docs/release-notes-0.1.1.md#対応範囲と件数の見方) に分けて掲載しています。
元データの意味は [同梱データの案内](data/collector-registry/README.md#データの意味) にあります。

メーカーの公式情報を確認しながら、対応するメーカーや機器を順次増やしていきます。
すべての機器への対応を保証するものではありません。実際のドライバー導入は未確認です。

## 🚀 使う流れ

アプリ用ZIPを展開した、またはソースからビルドした `DriverCrate.exe` を使います。
先に重要なデータをバックアップし、元のドライバーへ戻す方法を確認してください。

1. 起動してUACを確認し、「更新を検索」を押します。取得や規約の確認が出たら内容を読みます。
2. 機器を展開し、版・取得元・検査状態・導入方法を見比べます。
3. 導入可能な候補から使うものを選び、「選択した更新をインストール」を押します。
4. 対象・件数・使用許諾・復旧方法を最終確認し、同意する場合に続行します。
5. 個別の結果・エラーコード・再起動要否を確認します。次の導入には新しい検索が必要です。

## 🛡️ 導入とプライバシー

- 選択と最終確認を経た対象だけを導入します。検査用取得ではインストールしません。
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

[アーキテクチャ](docs/architecture.md) ／ [利用ガイド](docs/user-guide.md) ／ [リリースノート](docs/release-notes-0.1.1.md)

制作者：**Shunji Ogawa**（EnterSystem）  
Copyright (c) 2026 EnterSystem CO.,LTD.

正式なリポジトリは [EnterOgawa/drivercrate](https://github.com/EnterOgawa/drivercrate) です。
自作ソース・文書・アイコンには [Apache License 2.0](LICENSE) を適用します。
第三者資産の条件は [Third-Party Notices](THIRD_PARTY_NOTICES.md) を参照してください。
DriverCrateは独自に作成したアプリで、Snappy Driver Installer Originのforkやバイナリー再配布ではありません。
