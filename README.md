# DriverCrate

<p align="center">
  <img src="https://raw.githubusercontent.com/EnterOgawa/drivercrate/v1.0.4/src/app/assets/drivercrate-icon-master.png" width="72" height="72" alt="DriverCrateのアイコン">
</p>

このPCに合うドライバーを探して、使うものだけ選んで更新。

DriverCrateは、Windows Update、PC内のドライバー、メーカーの公式配布元から候補を探すWindows x64アプリです。選んだドライバーの署名や適合性を検査してから、インストールへ進みます。

**[1.0.4をダウンロード（Windows x64）](https://github.com/EnterOgawa/drivercrate/releases/download/v1.0.4/DriverCrate-windows-x64.zip)** · [SHA-256](https://github.com/EnterOgawa/drivercrate/releases/download/v1.0.4/DriverCrate-windows-x64.zip.sha256) · [変更点](https://github.com/EnterOgawa/drivercrate/releases/tag/v1.0.4)

## はじめて使う

### 1. 展開して起動する

ZIPを展開し、`DriverCrate.exe`を開きます。`DriverCrate.exe.index-profile.json`は、EXEと同じフォルダーに置いてください。

### 2. 更新を探す

「更新を検索」を押します。機器ごとに、現在のバージョンと候補のバージョンを見比べられます。

![機器の一覧とバージョンの表示例](https://raw.githubusercontent.com/EnterOgawa/drivercrate/v1.0.4/docs/images/device-list.png)

*画面は説明用のサンプルです。*

### 3. 候補を選ぶ

機器名をダブルクリックすると、詳しい候補が開きます。バージョンと配布元を確認し、「この候補を選択」を押しましょう。

主画面で対象にチェックを入れ、「選択した更新をインストール」を押します。メーカー規約がある場合は「同意してインストール」と表示されます。

![ドライバー候補の詳細と選択の表示例](https://raw.githubusercontent.com/EnterOgawa/drivercrate/v1.0.4/docs/images/candidate-details.png)

*候補の詳細もサンプルデータで表示しています。*

インストール後も、ほかの機器の候補とチェックは残ります。処理結果や再起動の要否も確認できます。

## もっと詳しく

[詳しい使い方](https://github.com/EnterOgawa/drivercrate/blob/v1.0.4/docs/user-guide.md) · [ビルドと試験](https://github.com/EnterOgawa/drivercrate/blob/v1.0.4/docs/testing.md)

[Apache-2.0](LICENSE)で公開しています。[第三者ライセンス](THIRD_PARTY_NOTICES.md)もご覧ください。
