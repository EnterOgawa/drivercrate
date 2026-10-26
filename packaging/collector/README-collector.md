# DriverCrate Collector

Windows x64収集PC用のセットアップです。製品版0.1.1です。
この版の自作EXEはコード署名なしです。通常のソースビルドは証明書不要です。
driver本体と通常アプリは同梱しません。
現行package-v7 / EXPLICIT_DISTRIBUTION_DATA_DAILYと配置receipt-v3だけを扱います。
基本77payload（参考索引つきは83payload）とmanifest、CPython 3.13.16 x64全34file、研究seedと初期distribution dataを含みます。
研究seedは127メーカー/6,584製品参照/1,718研究recordで、390 locatorと既存1 record用の収集profileがあります。
これらは内容検査済みdriver数・INF数・実device適合数ではありません。
初期packageはWindows 11向け2 record・1 sourceの参考索引を含みます。原期限2026-11-02 09:28:33 UTCを保持し、通信許可やnative authorityを付けません。
旧package/receipt/local-index入口の互換・自動移行は提供しません。未知形式は既存dataを変更せず拒否します。

`Install.cmd`は対象を確認して配置し、現在user用のnative metadata日次Task一件を毎日15時へ
登録・有効読戻しします。即時収集・driver導入・索引署名/公開は開始しません。
`Validate.cmd`は配置を非通信で検査します。固定原byte/hash/x64とcached-only PSF署名を要求します。

登録対象の追加・更新は外部台帳/locator/collection profileから可搬dataを生成し、
`--import-data ROOT DATA --confirm-offline`で取り込みます。意味変更は確認待ちの先行importと別reviewが必要です。
旧世代・元候補/期限・24時間待機・課金を保持し、索引の手編集やアプリの再buildを要求しません。

汎用日次は`--enable-distribution-daily ROOT --confirm-daily-inspection-download`への別同意で、
毎日17時の別所有Taskへ接続します。32job/64要求/32MiB/600秒・最低24時間待機と全INF検査を維持します。
copy/import/validateではこの同意やTask所有を発行しません。private観測/鍵/driver本体を移設しません。
停止snapshotは現行export-v1/v3だけを受理します。未確定予約は最大課金で保持します。

同schemaの停止workspaceを現packageへ向け直す明示操作は
`--workspace-switch-package ROOT ORIGINAL_SHA256 --confirm-source-stopped`です。
正規の現install receiptと全payload、所有者が先にreviewした原workspace raw SHA-256、
既存owner/ACL/三root/両origin/原planと確定停止を要求します。変更はpackage/seedの二hash値だけで、
原workspace全byteを`package-switches/<原SHA-256>.json`へ保存してatomic切替します。
原履歴・待機・課金・active dataを保持し、通信許可/Task/receiptを発行しません。
通常操作の旧binding受理、旧codec/自動移行、異版の既存配置上書きは提供しません。
原hashの再適用/中断pending/不確定runは保持して拒否し、別reviewなしにresetしません。
新しい配置の正規installと切替、明示実行/日次同意は別操作です。10月25日の配布候補で、
停止済み同一workspaceの実切替、同一dataのimport・workspace検証を確認しました。

`Uninstall.cmd`は両所有Taskの非実行・所有照合と正常不存在を確認後に管理programを削除します。
不明/改変/失敗では保持します。config・seed・work/data・未知file・自己setupとUninstall.cmdは残します。
旧管理者Taskをadopt・更新・削除せず、旧receipt混在は拒否します。stateを削除して待機を回避しません。

同じv7単体セットアップで、通常installのTask登録・有効読戻しと、通常解除・所有Task不存在・data保持を
確認しました。登録後のTaskは未実行の待機状態でした。
10月24日の既存1 packageの実取得/INF2件のCAT・参照本体検査に合格しましたが、元runは投影0です。
nested修正後のfresh実投影、公開前の最終ソース・文書・配布物の照合、別PC・Taskの実行/自然日次・実導入は未確認です。
過去の有限成功を現byteの成功へ読み替えません。通常Taskは未署名候補までで、署名・公開を行いません。

日次試行・週内一回程度の成功を運用目標とし、取得できない対象は元の失敗/HOLD理由と診断を残して
後日切り分けます。全取得先の同時成功や七日運用を公開準備の前提にしません。
未失効の前回成功は原byte/期限のまま利用し、全失敗で候補・公開assetを空の新世代へ置き換えません。
手動prepare/sign/publishは七日超残存を必須にせず、実現在の原有効性を署名前・公開前・CAS直前も検査します。
期限延長や待機resetは行いません。保護されたrun/result/本文と一般summaryを区別し、私有診断を公開しないでください。

権利条件は同梱のLICENSE/THIRD_PARTY_NOTICES.md、または正式repositoryの
[LICENSE](https://github.com/EnterOgawa/drivercrate/blob/main/LICENSE)と
[THIRD_PARTY_NOTICES.md](https://github.com/EnterOgawa/drivercrate/blob/main/THIRD_PARTY_NOTICES.md)を参照してください。
