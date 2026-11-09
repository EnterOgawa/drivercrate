<h1 align="center"><a href="src/app/assets/drivercrate.ico"><img src="src/app/assets/drivercrate-icon-master.png" width="64" height="64" alt="DriverCrateの木箱アイコン"></a> DriverCrate</h1>

<p align="center"><strong>ドライバー探しを、かんたんに</strong></p>

DriverCrateは、Windows Update、Windows Driver Store、メーカーの公式配布元からドライバー候補を探し、
利用者が選んだ候補だけを取得・検査・導入するWindows x64アプリです。
このソースの製品版は **1.0.1** です。配布先は [GitHub Releases](https://github.com/EnterOgawa/drivercrate/releases)、
変更点と確認範囲は [1.0.1リリースノート](docs/release-notes-1.0.1.md)を参照してください。

## できること

- 種類カテゴリと機器のツリーで、デバイス名・現在の版・候補の版を表示します。詳細はダブルクリックで開きます。
- Windows Update/WSUSがこのPCに適用可能と判定した更新、Driver Storeの互換候補、実装済みの公式配布経路を検索します。
- 署名索引を固定配布先から取得・検証し、端末内で照合します。同じ有効世代では索引本体の再取得を省きます。
- 一つの機器につき基本ドライバー候補を一つ明示選択し、Install操作から選択した配布物だけを取得します。
- 実際のbyte・hash・署名・INF/CATと参照file・Windows適合性を検査します。索引への収録だけでは導入を許可しません。
- 成功・失敗・再起動待ち・現在状態未確認を分け、導入後も一覧と個別結果を保持します。次の導入には新しい検索が必要です。

取得前の参照、内容検査済み候補、実機適合、実導入成功は別の結果です。全メーカー・全機器への対応や
最新ドライバーの存在を保証しません。ファームウェア、BIOS/UEFI、OEMアプリ、第三者driver packは導入対象外です。

## 使う流れ

1. 対応するApp Releaseの`DriverCrate-windows-x64.zip`と`.sha256`を取得し、SHA-256を照合します。
2. ZIP内の`DriverCrate.exe`と`DriverCrate.exe.index-profile.json`を同じ場所へ展開します。更新時はAppを閉じます。
3. `DriverCrate.exe`を起動し、UACを確認して「更新を検索」を押します。
4. 詳細で候補・取得元・規約・前提条件を確認し、対象を選択して「同意してインストール」を実行します。
5. 結果と再起動要否を確認します。失敗した項目は個別の診断を確認してください。

正式配布ではAppのAuthenticode署名と時刻証明を検証します。署名の実状態は受け取ったfileで確認してください。
索引署名は別用途の公開鍵で検証します。通常のソースbuildに署名証明書は不要です。
私有の収集管理製品・setup・定義・registryやdriver本体は、このApp Releaseと公開sourceに含めません。

## 導入とプライバシー

Windows clientでは復元ポイントの作成失敗時に導入を中止します。Windows ServerではSystem Restoreを呼ばず、
管理者が事前backup/checkpointと復旧手順を確認して同意した場合だけ導入します。DriverCrateはServer backupを作りません。
復元ポイントや署名が、すべてのdriver変更からの復旧を保証するものではありません。

WUA/WSUS、proxy、証明書、UAC、組織policyを迂回しません。検索語へ生Hardware ID、instance ID、serial、credentialを送りません。
通常の診断logには段階・件数・一般化した数値結果を残し、個々の機器名/ID・URL・任意本文を含めません。
保護storeが未知・所有不明の場合は停止し、無断の移動・削除・resetや旧形式の自動移行をしません。

## 動作環境と確認範囲

対象はMicrosoftのサポート対象Windows 10/11 x64および対応Windows Server x64です。全version・全機器の実機確認は未完了です。
C++20/Win32の単体Appで、実行時に外部言語runtimeやAI modelを要求しません。x86/ARM64版は提供しません。
利用者から現行開発系列でのドライバー導入成功を確認しています。最終配布byteでの再導入や別PCの成功を意味しません。
UIの表示保持は人工試験で確認しており、実機表示のfeedbackは引き続き受け付けます。

## ソースからビルドする

MSVC C++開発ツール、Windows SDK、Ninja、CMake 3.30以上を用意し、x64 Developer PowerShellで実行します。
初回構成では固定版・固定SHA-256のminiz/LZMA SDK sourceを取得します。

```powershell
cmake --preset windows-x64
cmake --build --preset debug
ctest --preset debug
cmake --build --preset release
ctest --preset release
```

Debug/Releaseは同じ`build/`を使います。Appは`build/Release/DriverCrate.exe`です。
公開sourceはconsumer Appと非通信試験の明示集合で、私有Collector/索引署名tool/live試験は生成しません。
[テスト方針](docs/testing.md)、[貢献方法](CONTRIBUTING.md)、[公開前checklist](docs/release-checklist.md)を参照してください。

## 設計とライセンス

[アーキテクチャ](docs/architecture.md) ／ [利用ガイド](docs/user-guide.md) ／ [セキュリティ](docs/security.md)

制作者：**Shunji Ogawa**（EnterSystem）  
Copyright (c) 2026 EnterSystem CO.,LTD.

正式repoは[EnterOgawa/drivercrate](https://github.com/EnterOgawa/drivercrate)です。
自作source/document/iconは[Apache License 2.0](LICENSE)、第三者表示は[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md)を参照してください。
