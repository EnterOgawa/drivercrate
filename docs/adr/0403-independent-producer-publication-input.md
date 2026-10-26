# ADR 0403: 成功した収集系統を独立に手動発行へ接続する

- 日付: 2026-10-26
- 状態: 採用。ADR0402の部分成功方針を既存の手動三段階入口へ反映する。

## 判断

`prepare-candidate`、`sign-candidate`、`publish-candidate`は、保守担当が明示pinした
汎用候補のみ、native六原入力のみ、または両方を同じ経路で扱う。
少なくとも一系統を必須とし、各file/hash対の欠損、不正pin、指定した入力の内容拒否を
他系統へのfallbackや黙った除外へ変換しない。未指定・不完全対はload/lock/外部作用前に拒否する。
疑似的な汎用headや私有authorityを作らず、取得/署名/公開を一括する旧runへ迂回しない。

汎用入力には既存head、build-commit、validation、全出力の原byte/hash検査を維持する。
native入力には既存`dc-candidate-native-inputs-v1`の閉六file/pinと、同configのscope・
原reservation receiptとの一致、非通信producer、原bundle監査を維持する。
非空record、同runの内容/PAGE/独立根拠、fresh24h、八日上限、原byte/hash/source/個別期限、
型付き権限を弱めない。原wrapper/sourceを保持し、統合後の期限は全原recordのminとする。

## 既存claimと世代の意味

既存`dc-distribution-candidate-publication-v1`、`issuance-v1`名、同outputRoot/lockを維持する。
`candidateHeadSha256`と`candidateOutputs`は、汎用未指定の場合だけ同時にnullとし、
この場合は`nativeInputsSha256`を必須にする。汎用指定時は従来のhashと閉五出力を必須にし、
native指定の有無は既存`nativeInputsSha256`へ結ぶ。両系統のpinがともにnullの場合と、
汎用hash/出力の片側だけがnullの場合を拒否する。
prepare再開、sign、publishは、この同じ明示入力とconfig・原出力pinに結合する。
保存済み従来claimを同じ検査で読み、原世代と不確定意図を下限へ残す。
未知履歴を飛ばす新namespace、floorのreset、旧claimの変換を追加しない。

内容証拠としてのnative六入力と、rollback防止の`nativeReservation`は別の役割である。
どの系統を選んでも原receipt/原native headを既存`verify_reservation(LEGACY_FENCE)`で
認証し、Public署名履歴・全local claimとの最大世代を維持する。
汎用のみの成功に、新しいnative収集成功を必須にしない。native予約を内容成功とは数えない。
新rawを署名済みとして扱わず、明示signの一回呼出し、原署名束、expected-head CAS、
不確定時のreadback-only再開を維持する。実現在の原有効性は各段階とCAS直前に検査する。

## 有限確認と資格

原六入力fixtureとfake署名/remoteを使い、各片系統と両系統の三段階、欠損対、入力切替、
原pin/内容拒否、期限minと失効、同世代再開、署名不確定、旧claim下限/CAS境界を確認する。
実HTTP、鍵照会/署名、Task操作、driver導入、remote writeは行わない。
日次Task、通常app、collector同梱code、既存配布byteを変更せず、既存不変配布物の再生成を要件にしない。
修正後の公開source候補と差分資格は後段で更新し、修正前snapshot/レビュー資料は原本として保持する。

失敗/HOLDの分母、原理由/待機、未失効の旧成功を保持するADR0402を維持する。
日次試行・週内一回程度の成功は運用目標であり、期限延長や実成功の保証ではない。
新deviceにも同じ規則を適用し、今回は対応追加0、実fresh成功0、新候補数nullを維持する。
人工三段階の成功を、新しい署名索引や通常appの有効Public正例へ換算しない。
