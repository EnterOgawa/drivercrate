# ADR 0404: Intel Ethernet公開SHA-512を区別して保持する

- 日付: 2026-10-26。
- 状態: 採用。非通信解析と実取得成功を分ける。
- 工程: G13-I7r255h0d1a。既存データ/取得要求更新はG13-I7r255h0e。

## 原因

保存した実200本文のIntel Ethernet配布はSHA-512だけを掲載する。現parserは
`SHA256:`と64桁uppercase hexを必須にし、配布情報を拒否した。同じ原本文のhash欄だけを
架空の従来形式へ置換した非通信対照は従来parserを通る。失敗はchallengeや製品一覧欠損ではない。
実配布版も旧承認入力とは異なるため、形式修正だけで旧metadata用の技術的同意bindingを
新配布物へ読み替えない。利用者の承認は公式pageのOBL v2025.02.12に基づく検査用取得であり、
旧版への限定承認ではない。同一の許諾全文について利用者の再同意を増やさず、新metadataへの
技術的なbinding再生成と新しい許諾の承認を区別する。

## 契約と範囲

1. 共通Ethernet page metadataと`OfficialReleaseRecord`へ任意の`publishedSha512`相当fieldを
   追加する。SHA-256は64桁、SHA-512は128桁のASCII hexとして別々に保持し、変換・切詰め・
   実測値による補完をしない。旧SHA-256のuppercase条件は維持し、SHA-512は公表された大小文字を保持する。
2. 少なくとも一方の公開hashを要求する。両方が掲載された場合は両方の一意性・形式を要求し、
   一方の不正を他方で救済しない。公式起点/host、唯一のWindows x64 driver ZIP、版と説明、
   OS/製品marker、size表示、完全許諾snapshotの条件は維持する。
3. 通常recordと収集候補adapterは両hashをADR0198の既存payload fieldへ渡す。
   Windows 11 parser revisionを4、共有coreのServer parser revisionを3へ更新し、旧cacheを新解釈へ流用しない。
   収集metadata codecもIntelのSHA-512-onlyを表現できるようにし、ASUSのSHA-256必須契約は維持する。
4. 保存release解析CLIは少なくとも一つのhashを要求し、SHA-512がある場合は追加fieldを
   `dc-saved-release-analysis-v2`へ保存する。SHA-256-onlyは従来v1を維持する。
   旧readerがSHA-512を無視してSHA-256へfallbackしないよう、v2を明示的な後段更新境界にする。
   新HTTP証拠、取得grant、同意、適用性、署名、導入許可を発行しない。
5. 旧expected release、取得要求、保護runtime、原receipt/失敗/待機は本修正で更新しない。
   現行のSHA-256-only明示取得要求が新配布物を拒否する状態は残し、既存データと取得要求の更新を
   h0eへ分ける。実取得/内容検査/索引生成/公開の成功を非通信解析から主張しない。

## 検証

実174245byteの保存解析と、合成したSHA-512-only/両hash/従来SHA-256の正例、hash欠落・
桁/文字改変・重複・片方不正・誤製品/OS/hostの負例を確認する。
実本文と許諾全文は公開fixtureへ入れず、既存合成HTMLを使う。
変更targetのx64 Debug/Release、関連unit、変更sourceのformat/metadata/Doxygenを有限確認する。

## 関連判断

- [ADR0198: 公開SHA-512の共通取得照合](0198-published-sha512-acquisition-binding.md)。
- [ADR0400: Intel失敗pageの私有診断](0400-intel-failed-page-diagnostic-capture.md)。
- [ADR0402: 部分収集とリリース準備](0402-partial-collection-and-release-priority.md)。
