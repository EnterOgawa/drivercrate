# ADR 0198: 公開SHA-512の共通取得照合

- 日付: 2026-09-23。
- 状態: 採用。実装・実配布物の検証とは分ける。
- 工程: G13-D6j15f4b3a／b3b。

## 原因と範囲

共通のrecord、grant、取得結果は公開SHA-256だけを表現している。配布元がSHA-512を
示す場合に別の取得器やメーカー別hash処理を作らず、既存の取得境界へ追加する。
EXE入口・非実行内容検査・128／512 MiB超の予算・INF依存分類は独立した後続工程であり、
この変更では許可範囲を増やさない。

## 契約

1. Recordとgrantに任意の公開SHA-512（空または128桁ASCII hex）を追加する。
   SHA-256と排他的にせず、両方の公開値が存在すれば両方の完全一致を要求する。
   不正形式はfile作成・network開始前、不一致は取得file破棄後に失敗として返す。
2. SHA-512はrecord fingerprint、payload一致、grant発行・move・再解決へ結合する。
   SHA-512が全payloadで空なら既存canonical byte列を変更しない。一件でも存在する場合は
   末尾へ固定domain `published-sha512-v1`、payload数、ordinal順の小文字hex列を追加する。
   Hashの変更・削除・追加は別recordとして扱い、既存SHA-256-only証跡を無効化しない。
3. CNGを用いた共通file hash関数を共有し、64 KiBの読取りbufferでEOFまで処理する。
   SHA-256による内部file identityは常に維持し、公開SHA-512の有無とは独立させる。
   取得結果は`publishedSha256Verified`と`publishedSha512Verified`を区別する。
   SHA-512成功をSHA-256成功へ置換せず、AI開発入口のhash gateはどちらかの公開照合成功を要求する。
4. 固定URL要求にも任意SHA-512を追加する。Grant経路に固定側hashを混ぜた要求は拒否する。
   既存の公式根拠、同意、有限予算、public宛先、進捗、取消し、保護workspaceを維持する。
5. Hash一致は署名・実機適合・実行許可ではない。既存のINF／CAT・publisher検査を変更しない。

## 検証

既知byte列、SHA-512のみ、両hash、大小文字、片方不一致、不正桁／文字、hash削除・変更、
grant移動／再解決、固定と委譲の混在拒否、失敗file回収、旧SHA-256-only fingerprint不変を
非通信fixtureで確認する。Debug／Releaseのbuild・unit・通常OFF復帰を行う。
P5 Realtekは既存512 MiB取得専用で別run一回だけ測り、未検査のbyte取得を内容成功へ数えない。

## 一次資料

- [Microsoft CNG algorithm identifiers](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers)
- [BCryptOpenAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider)

既存のCNG連続hash処理を利用する。追加の外部libraryや実行runtimeを要求しない。
