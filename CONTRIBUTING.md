# Contributing to DriverCrate

変更前に[設計](docs/architecture.md)、[セキュリティ境界](docs/security.md)、
[採用C/C++規約](docs/c_cpp_coding_standard.md)、[テスト方針](docs/testing.md)を確認してください。
要件や公開APIの意味を変える場合は、実装前に決定と理由を文書化します。
実装済み、人工試験済み、実機確認済み、計画中を分け、未確認を成功へ変換しないでください。

## Buildと品質

Visual Studioのx64 developer shellから既存presetを使います。通常構成はCMake 3.30以降、
Ninja Multi-Configと単一`build/`です。Debug／Releaseを同じtreeへ生成し、解析後も通常設定へ戻します。
別のgeneratorを同じtreeへ重ねず、工程別・解析別のbuild treeや過去build archiveを増やしません。
開発toolやcheckoutの絶対pathをsourceへ固定しないでください。

```powershell
cmake --preset windows-x64
cmake --build --preset debug
cmake --build --preset release
ctest --preset debug
ctest --preset release
```

開発Privateを正本とし、GitHub Actionsは通常運用に使用しません。公開前には、固定した公開snapshot
自身からローカルで両構成と品質gateを確認します。[公開前の手順](docs/testing.md#公開snapshotのローカル事前確認)と
[ADR 0379](docs/adr/0379-local-prepublication-verification-without-actions.md)を参照してください。
MSVC／Ninjaは実`/showIncludes`の言語をconfigure時に確認し、launcherへ結合します。
依存情報の不一致時は同じtreeの該当構成をclean-firstで再構築し、古い依存情報を信頼しないでください。

自作C/C++、header、test、resource、生成元templateは採用規約と[見本](docs/examples/c_cpp_coding_standard_sample.cpp)へ
従います。独立file版、旧履歴、作成日、Copyright／Apache-2.0節、field／enumの前置`///`を保持します。
契約と2026-09-11当時の355 file移行結果は[ADR 0141](docs/adr/0141-revised-source-standard-contract.md)にあります。
355は現在のsource数でも固定上限でもありません。

日常の整形は`py -3 scripts/format_source.py --write`、確認は`--check`です。
Python 3.10以降とclang-formatは開発用で、アプリの実行時依存ではありません。
formatter回帰、source規約、Doxygen 1.10.0のmember集合突合を必須とし、具体的commandは
[テスト方針](docs/testing.md)へまとめています。一般Doxygen warningや任意宣言監査は別に確認します。
一括移行writerを日常整形として使わず、退避とレビューのない説明文の自動書換えを行いません。

## 変更の提出

- 目的、利用者への影響、失敗時動作、未確認を説明し、関連する決定的試験を実行する。
- interfaceや挙動の変更へ文書と試験を追随させ、通常buildの安全option・trust境界を維持する。
- 外部codeやassetは由来、版、license、noticeを確認し、原権利表示を保持する。
- source、fixture、build／runtime依存の閉包を維持し、除外された私有解析履歴を必須入力にしない。
- 研究台帳の製品追加をアプリのメーカー別設定・Provider追加へ直結させない。

`scripts/test_index_build_profile.py`のnative試験には開発用PowerShell 7とCMake 3.28以降が必要です。
tool不在のNOT_RUN、mock-only合格、実guard実行を区別してください。
通常のnative unitは実導入を行いません。実HTTP、Task、鍵・署名、実導入、remote反映は
通常試験と分け、対象と許可を確認して扱います。実行policyを変更して試験を通しません。

## Privacyと権利

実端末のtitle、Hardware／Compatible ID、instance ID、serial、download URL、local path、credentialを
Issue、commit、検証log、fixtureに含めないでください。報告はWindows／DriverCrate version、操作段階、
一般化したHRESULTから始めます。脆弱性は[SECURITY.md](SECURITY.md)の非公開経路を使ってください。

自作sourceとdocumentのlicenseは[LICENSE](LICENSE)、第三者表示は[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md)です。
公開前には[Release checklist](docs/release-checklist.md)を確認します。公開候補一覧は最終allowlistではなく、
remote push、Release、Public化には該当する明示承認が必要です。
