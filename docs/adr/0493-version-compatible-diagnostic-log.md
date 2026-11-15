# ADR 0493: 同じ診断wireの製品版更新と原ログ保持

- 状態: 採用、実装済み。内部資格は849c記録、主担当849d受入待ち
- 日付: 2026-11-14
- 根拠: 849cのリリース準備と主担当の狭い修正採用

## 問題

wire v1の所有headerが製品版完全一致のため、1.0.6の両slotを残して1.0.7へ更新すると保存できない。古い1.0.1の開発fixtureでも同じ拒否を確認した。clean folderの成功を更新互換の証拠にはしない。

## 決定

所有headerは固定prefix `# DriverCrate anonymous diagnostics v1 app=`、先頭0を許さない十進3要素、各1〜5桁/0〜65535、`.`区切り、LF終端だけを受理する。互換範囲はこの形式の起点である1.0.1から今回1.0.7まで。同じmajor/minorの既知範囲に限り、1.0.0/0.x/将来patch/別major/minor/未知wire/余剰/途中headerは受理しない。将来版への拡張は再判断する。

headerのappは作成時の版とし、現在実行中の製品版はstartupの閉じた数値列 `appVersionMajor/appVersionMinor/appVersionPatch` で別記録する。診断revision12は維持する。既定列と数値型、privacy、slot2/各256KiB/record2048byte/queue256は維持する。

全行閉文法を照合し、通常file/祖先固定/reparse/hardlink拒否が成立した同slotだけを末尾へseekする。起動時resetをやめ、両slotの原prefix全byteを保持する。容量到達時の既存2slot rotationだけは従来通りで、無期限保存/追加archiveは提供しない。不正/未知/リンクは採用/消去/resetせず、writerの元失敗段階/codeを保持する。

## 受入

実製品FileSinkで1.0.1/1.0.6の閉じた元slotを保持して追記できること、両slot1.0.6を持つ最終1.0.7 UI試験EXEでstartup保存と原prefix保持を確認する。未来/範囲外/桁/区切り/改行/余剰/不正本文と既link拒否、従来容量rotationを確認する。本番ログ・実端末は変更しない。内部fixtureを実機更新/導入成功へ換算しない。

実装上の受理上限はCMake正本の実行版patchへ結合しており、今回の上限は7である。次版ではこの上限変更と互換範囲・拒否fixtureを合わせてreviewする。起動時prefix保持は容量rotationで古いslotを再利用しない保証ではない。
