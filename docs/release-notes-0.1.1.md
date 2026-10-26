# DriverCrate 0.1.1 リリースノート

Windows x64用。この文書は0.1.1ソースの変更と確認範囲を説明します。
本書の確認範囲・未確認事項・承認状態は2026-10-26の文書確認時点の記録であり、公開直前の実績・未確認事項はReleasesの記載と照合します。
公開されている版・assetは [Releases](https://github.com/EnterOgawa/drivercrate/releases) で確認してください。
配布候補のローカル検査と通常セットアップの有限確認は「確認範囲と制限」に記載します。
公開する固定ソース・文書・配布物の本人最終承認と、
新しい有効なPublic索引の実受入は未完了です。
この版の自作EXE（通常アプリ、collector、内側setup、単体setupのouter）はコード署名なしです。
以前の署名済みbyteの検証結果は今回の再buildへ継承しません。通常のソースビルドは証明書不要です。
コード署名と索引署名は別用途です。索引署名・原hash/期限・CAT/publisher・
INFと参照ファイル・端末適合性・同意と復旧・世代下限の検証は維持します。

## 主な変更

- Windows Update/WSUS、Driver Store、公式配布元、署名索引の候補を取得元別に表示します。
  取得・内容検査・端末適合・導入の結果を分け、選択と最終確認を経た対象だけを実行します。
- 署名索引のflat/一段nested ZIP/CABと各INFの完全tupleを同じ共通経路へ結合します。
  共有packageも各recordの原hash・INF・Models・Class・公開PnP全集合を照合します。
- Collectorはpackage-v7/receipt-v3へ統一しました。通常installのmetadata15時Taskと
  別同意の検査取得17時Task、所有Task正常不存在後の解除・data保持を使います。
  旧client/setup/dataの互換・自動移行は提供せず、旧Task/store/dataを無断変更しません。
- 日次処理は未署名候補までです。prepare/sign/publishは手動の別操作で、原byteと期限を保持します。
  汎用のみ/nativeのみ/両方から、少なくとも一系統の非空成功入力と完全なfile/hash対を明示pinします。
  指定した不正入力は黙って除外せず、内容成功と世代下限用の原receipt/head・全claim履歴を分けます。
  nativeの新配布scopeはprojectionPolicyRevision=2、新規recordは8日、発行観測は24h未満です。
  日次試行・週内一回程度の成功を運用目標とし、部分失敗を理由付きで残して公開準備を先行します。
  七日超の残存期間は必須とせず、実操作時点で全原recordとmanifestが有効であることを要求します。
  全失敗時に前回の候補・公開assetを空の新世代へ置き換えません。
  HTTP待機24h・課金・旧rawの期限は変更しません。
- 既存Prolificの調査観測/locator/profileを訂正しました。このリリース準備で新メーカー・製品・recordは増やしていません。

## 対応範囲と件数の見方

単位の違う数を「対応ドライバー数」へ合算しません。

| 単位 | 確認した件数と意味 |
|---|---|
| 研究登録 | 127メーカー、6,584製品参照、1,718配布record。公式情報の参照で、端末適合や導入成功ではありません。 |
| 汎用収集条件 | locator390件、collection profile1件（既存Prolificの1 record/7製品参照）。native Intelは別経路です。 |
| 取得証拠 | 同梱payload-evidenceの4行。元観測/hashを保持した別集合で、全recordの内容合格ではありません。 |
| 検査済みpackage/INF | 10月24日のProlific一packageは実HTTP2要求/506,429byte、INF2件のCAT/全参照本体検査に合格。fresh索引投影と実PC適合は未確認です。 |
| Intel原packageの有限検査 | 保存済み一package/72 INF中57内容合格、15構造拒否（0x80070032）。元22公開IDの選択INF一件をhistorical通常appへ結合。実PC適合・現在有効な索引の成功ではありません。 |
| 署名索引の発行候補 | 世代9、Windows 11向け2 record、1 source。2026-10-26 11:32:09 UTCにローカル発行・専用鍵の署名検証済み、未公開。原期限2026-11-02 09:28:33 UTC。実PC適合数は未判定です。 |
| 実PCの候補実績 | 10月19日の別byte/通常画面で、同じ1機器に旧版候補3件（未選択）。最新0.1.1の実PC成功には継承しません。 |
| 実driver導入 | 0件。実導入と復旧は未確認です。 |

<!-- RELEASE_INDEX_COUNTS: generation=9 recordCount=2 sourceCount=1 expiresAtUtc=2026-11-02T09:28:33Z; locally signed/validated, NOT_PUBLISHED. -->

通常アプリは署名索引を同梱せずPublic配布先から取得します。同梱0は対応0を意味しません。
直近の通常アプリは旧公開世代5の期限切れを拒否しました。現在有効なPublic索引の候補/版表示は未確認です。
検査取得は一対象・部分成功一件で、394,773 byteの一archive、INF/CAT/参照本体2件が内容検査を通過しました。
Windows 10の2件はMODELS_OS_UNOBSERVED、未profiledの1,717研究recordは別に保持します。
7製品参照を実適合数へ加算しません。研究台帳全1,718 recordが通常アプリで利用できるとは表示しません。
Collectorの初期packageは研究seed/収集条件と2 record・1 sourceの参考索引を含みます。
参考索引はbootstrap用の未署名候補で、元観測・producer・原期限を保持し、通信許可やnative authorityを付けません。
今後、公式情報を確認しながらメーカー・製品を順次拡大します。全機器への対応保証ではありません。

## 確認範囲と制限

10月25日のv7単体セットアップで、通常配置時の所有Task登録・有効読戻し、停止済み同一workspaceの
package切替、同一dataのimport・workspace検証、通常解除・所有Task不存在・data保持を確認しました。
登録後のTaskは未実行の待機状態でした。Taskの実行/自然日次、七日、再起動、別PC、
全対象OS/機器の実測は未確認です。
Prolific元runの投影0と元actual待機/課金を保持します。nested修正後のfresh実投影は未確認で、
理由と次回試行下限を残して後続へ送ります。一系統以上の非空成功から進め、P1単独の成功を必須にしません。

共有package、初回導入、同意、失効、部分失敗、復旧失敗、nested完全tupleは人工試験で確認しています。
Intelの保存原manifest/GZip/実packageによるhistorical正例と現在UTCでの原期限拒否も別に確認しました。
過去版・fake・historicalの成功を、最終配布byte・実PC適合・実導入へ換算しません。

Windowsクライアントは導入前の復元ポイントが必須です。Serverでは作成せず、
事前backup/checkpointと復旧手順への明示確認が必要です。DriverCrateはServerのbackupを作成・検証しません。
x86/ARM64、BIOS/UEFI/firmware、OEM utilityや一般アプリは導入対象外です。
OSや管理ポリシーによる拒否を回避しません。

操作は [利用ガイド](user-guide.md)、収集用は [セットアップ案内](collector-setup-guide.md)、
各時点の検証と再現方法は [テスト方針](testing.md) を参照してください。
