# Release checklist

対象はDriverCrate 0.1.1です。今回の配布候補はEXEコード署名なしで確認し、コード署名は後続へ残します。
索引署名・原hash/期限・CAT/publisher・端末適合性と権限の検証を維持します。
[ADR0406](adr/0406-verified-authenticode-build-transition.md)、[ADR0397](adr/0397-release-completion-and-index-expiry-compatibility.md)、
[ADR0402](adr/0402-partial-collection-and-release-priority.md)、
[ADR0403](adr/0403-independent-producer-publication-input.md)と[リリースノート](release-notes-0.1.1.md)を正本とします。
本書は最終候補ごとの確認手順です。実績と承認は対象byteへ結び付いた検証記録で管理し、
この一覧を現在の実績報告とは扱いません。未完了checkboxを過去版の成功で埋めません。
開発Privateを正本とし、GitHub Actionsは通常運用に使いません。初回source/署名索引の公開と
最新source/アプリ・collectorのbinary Releaseは別の受入です。

## 最終sourceと再現性

- [ ] CMake製品版、UI/VERSIONINFO/manifest、配布builder、Release titleとtag予定を0.1.1へ一致させる。
- [ ] README/guide/Release note、現行package-v7/receipt-v3、通常Taskと手動署名/公開の境界を最終sourceへ照合する。
  旧client/setup/dataの互換・移行・変換は前提にせず、旧Task/store/dataの所有保護・待機課金を維持する。
- [ ] 公開するpath/mode/byte/SHA-256とlicense/noticeを固定し、本人が具体的な集合を確認する。
  checkerの`finalAllowlist`値と、本人による固定集合の受入・公開承認を分けて記録する。
- [ ] `.git`、Actions、鍵、credential、実inventory、driver本体、私有絶対path、work記録・build/PDBを公開集合へ含めない。
  コピー元とsnapshotのpin一致・余分なfileの不在と必要source/fixture/runtime/licenseの閉包を確認する。
- [ ] 既存の唯一`build/`へ最終snapshotをsourceとして切り替え、fresh x64 Debug/Release全targetと必要unit/UI/Python/PSを確認する。
  元source/構成/tool/input pin、切替/cleanと通常source/構成への復帰を記録し、別tree/archiveを作らない。
  後続候補が文書差分だけの場合は、原snapshot自身のfresh受入とbuild/同梱入力不変の差分資格を結び、
  後続候補自身のfresh buildとは区別する。
- [ ] formatter差分0、source規約error0、現hashに結合したDoxygen member集合gateを確認する。
- [ ] 必須MSVC `/analyze`を確認し、必要な残警告を解決する。通常buildの合格では代替しない。
- [ ] [公開snapshotのローカル手順](testing.md#公開snapshotのローカル事前確認)に従い、Privateの増分build合格をfresh受入へ流用しない。

## 配布物と有限実動作

- [ ] 同snapshotの通常構成からアプリZIP/collector単体EXE/checksumを作り、同じ最終byteへ確認を結合する。
  三builderへ唯一buildを`-BuildDirectory`で明示し、新規出力先を使う。既存成果物を削除/上書きしない。
- [ ] app ZIPはEXE/README/LICENSE/THIRD_PARTY_NOTICESだけ、collectorは現行基本77payload（参考索引つき83payload）+manifestの意図した閉包であることを確認する。
  CPython原34file/PSF署名・license、研究seed/collection profileとpackage内全hashを確認する。
- [ ] x64 PE、実行権限manifest、Common Controls v6、ASLR/DEP/CFGと意図しないimportを確認する。
- [ ] SHA-256を再計算し、実Authenticode状態と未署名表記をguide/Release noteへ一致させる。
- [ ] 後続のコード署名時は三builderの任意`CodeSigning`へ操作者の指定store/thumbprint・SDK path/hash・公式確認済みTSA URLを渡す。
  内PE/原v2検査→実署名・Wintrust/timestamp/署名だけの変化→署名後v2→manifest/ZIP→resource/outer build→
  outer署名/検証→最終checksumの順を守る。原SDK/chain/鍵可用性は実署名工程で確認し、人工fixture成功を代用しない。
  既存未署名assetと本接続の実装だけを署名済み実績にせず、第三者Python原34file/署名は変更しない。
- [ ] 最終配置の起動/UI応答/正常終了と検索・取得/検査の有限な結果、未確認を記録する。
  実行したbyte・索引世代・原期限と成否を記録し、期限切れ拒否や過去の正例を新しい有効Public正例へ継承しない。
- [ ] 少なくとも一系統の非空成功入力を、汎用のみ/nativeのみ/両方から明示pinして確認する。
  全file/hash対を要求し、指定した不正入力を黙って除外しない。未指定側の成功は必須にしない。
  P1を含む失敗/HOLDは元分母・理由・最終試行/次回下限へ残し、元待機/課金を維持して後続へ送る。
- [ ] 最終collectorの配置・所有Task登録/有効readback・実行・通常解除/両名正常不存在とdata保持を必要範囲で確認する。
  実確認したsetup/packageのbyteへ結果を結び、自然trigger/七日/再起動/別PCの未確認を明記する。
- [ ] Provider別の公式経路、実byte/hash、署名、INF/全参照本体、端末適合、必須条件、導入方式の確認範囲を記録する。
  研究登録数/record数/INF数/実device適合数と実導入数を分ける。
- [ ] 実driver導入は別の明示指示がある場合だけ実施する。未実施0を記録する。
  clientの復元開始失敗拒否、Serverのbackup/checkpoint確認を既存人工試験と分ける。

## 承認と公開

- [ ] 手動候補確定/署名の実運用下限・原期限・既存native署名検証と公開候補asset/checksumを確認する。
  通常日次Taskは未署名候補までとし、prepare/signから公開writeを始めない。
  原receipt/head・全claimの世代下限と不確定意図を保持し、内容成功とLEGACY_FENCEを分ける。
  実現在の全原record/manifestの有効性を署名前・公開前・CAS直前も検査し、原byte/hash/期限を変更しない。
- [ ] 本人が具体的なsource/README/配布物/検証結果と未確認を確認する。
- [ ] 該当する明示承認後だけpush/tag/Release/visibility変更を行い、commit/tag/asset/checksum/公開状態をreadbackする。
  Private pushとPublic承認を分け、公開開始後の履歴を保持する。force-pushやroot作り直しで消さない。

初回公開822file、旧v5/v6のpackage/Task、10月19日の通常画面1 package/72 INF中57合格・15未対応/
同1機器の旧版候補3件などは[当時の実測](testing.md)として保持します。最終0.1.1の受入には継承しません。
全取得先の同時fresh成功・七日実運用・公開時の七日超残存は、最終source/配布物確定の前提にしません。
全失敗・全HOLD・空成功で、前回headや公開assetを空の新世代へ置き換えません。
全機器の実導入、全1,718研究recordの再受入、別PC/SDIO不足解消を一律のrelease前提に増やしません。
