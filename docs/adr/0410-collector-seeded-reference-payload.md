# ADR 0410: 収集setupの初期参考索引を既存v7へ接続する

- 状態: 採用
- 日付: 2026-10-26

既存distribution-data-v1は参考索引を含む12ファイルを検証・importできるが、
v7 packageの固定mappingが基本5ファイルだけだったため初期同梱へ到達しなかった。
既存schemaを維持し、`includesReference=true`のdataを既知6ファイルの完全な任意セットとして接続する。

追加対象は`reference.json`と`references/`下の`index.json`、`index.json.gz`、
`manifest.raw.json`、`build-report.json`、`provenance.json`だけとする。
package manifestの全順序・hash、nativeの閉集合と元data manifestの全hash検査を維持し、
不完全・重複・未知file・改変を拒否する。参考なしの現行v7も受理し、旧schema互換は増やさない。
生成時とimport時は既存`validate_reference`/`verify_bundle`を使う。

参考はbootstrap dataであり、元観測・producer・原期限を保持する。
`privateEvidence=false`と`communicationAuthorized=false`を維持し、native authority、
新しい観測、公開済み索引、端末適合やinstall許可へ昇格しない。
setupは同じ保護copyと通常Task同意を使い、通信開始・署名・公開を追加しない。
uninstallは従来どおりseed/dataを保持する。
