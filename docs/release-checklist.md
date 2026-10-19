# Release checklist

この一覧は公開前の確認項目です。現在の技術受入を公開済み・署名済み・全機器確認済みと扱いません。
人工試験と実機、通常buildとローカル受入profileを区別します。[テスト方針](testing.md)を参照してください。
開発Privateを正本とし、GitHub Actionsは通常運用に使いません。
初回source公開と署名索引二assetの配置は完了しています。以下の未完了checkboxは後続変更または
アプリ・collectorのbinary Releaseに対する確認で、索引用Releaseをinstaller配布として扱いません。
[ADR 0379](adr/0379-local-prepublication-verification-without-actions.md)と
[公開snapshotのローカル手順](testing.md#公開snapshotのローカル事前確認)に従います。

## Sourceと再現性

- [ ] 最終公開path一覧を本人が確認し、必要source／fixture／runtime／license／見本の閉包を確認する。
  現在の825候補は初回822 fileへADR 0380と移行専用header／CLIを加えた集合で、`finalAllowlist=false`である。既存の受入receiptを新しいbyte集合へ自動流用せず、私有解析履歴を追加してlinkやbuildを通さない。
- [ ] 公開fileのpath・mode・byteとSHA-256を固定し、コピー元／公開snapshotのpin一致と余分なfileの不在を確認する。
  `.git`、Actions workflow、鍵、実inventory、driver本体、個人絶対path、build／PDB、work記録を公開集合へ含めない。
- [ ] source、文書、画像metadata、secret／実inventory／個人絶対pathと、到達可能な過去Git履歴の公開方法を確認する。
  過去のlicense・author metadataを遡及改変しない。
- [ ] 現CMake契約を確認し、開発workspace直下の既存`build/`一つへ公開snapshotをsourceとして一時切替する工程を事前登録する。
  元source／構成／tool／入力pinはmetadataだけを保持し、cache・生成物の切替／clean、旧出力を混入させない初回検証、通常開発source／構成への復帰と確認を含める。旧build archiveや別build treeを新設しない。
- [ ] 登録・確認済み手順に従い、その唯一buildで最終公開snapshotを入力とする新しいx64 Debug／Release全targetと必要試験を成功させ、元の通常開発構成へ復帰する。
  Private working treeの既存増分build合格を、公開snapshotのfresh build合格へ読み替えない。
- [ ] formatter回帰・差分0、source規約error 0、Doxygen 1.10.0のmember集合gateを確認する。
  現sourceの656件／Doxygen対象652件は既受入証拠と後続八件を現在hashへ結合済みで、欠測0。統合結果の主担当独立確認は完了し、最終公開一覧の確認は残る。任意strict 3,643 warning、宣言exit 1／47件、移行43 tupleは当時の診断として保持し、最新sourceでの再実行やwarningゼロとはしない。
- [ ] MSVC `/analyze`を確認し、必須の残警告を解決する。既存の通常build合格で代替しない。
- [ ] 製品名、version、resource、CHANGELOG、tag予定、package名を一致させる。
- [ ] PE x64、requireAdministrator、Common Controls v6、ASLR／DEP／CFGと意図しないimportの不在を確認する。

## Packageと実機

- [x] 長path修復前のソースに対応する収集用ローカルv5 packageの有限な展開・配置・検査・保持／解除と、非通信の初期化・検証・停止export／import・人工中断からのnative再開を、このPCで受け入れた。
  h8q／h8qvの69 payload／70 file、ZIP 13,284,206 byte、SHA-256 `b8739dde7fcc0eec3f73397d3a85721482313a247c61a3b5559ce83f8d1aa1d2`に限る。
  原34 CPython fileと全文license／notice、`._pth`、研究seedを保持した未署名previewで、空のローカルmonitorを使用した。実正本bind／オンライン開始や別PC受入ではない。文書更新後の派生packageは別途確認する。
- [x] 最新source・同梱READMEに一致するcollector packageを一回作成し、このPCの有限な非通信確認を行った。
  `DriverCrateCollector-0.1.0-windows-x64-preview-48299785f3a546ce91c3143657cc2599.zip`、13,284,530 byte、
  SHA-256 `52ac17a747b637b0867f432e0bd2e6a3977e70f327ca61a19db5371e4ccccdc8`、69 payload／70 file。
  詳細は[テスト方針](testing.md#最新collector-packageの非通信受入)。旧v5成功を流用せず、現物で配置・初期化・停止移設・人工中断resume・同意不足拒否・保持／解除を確認した。主担当も現物・保存証拠と現sourceを独立照合した。
- [ ] 通常アプリZIPを展開し、EXE、README、LICENSE、THIRD_PARTY_NOTICESと意図したfileだけであることを確認する。
- [ ] SHA-256を再計算し、未署名／実際のAuthenticode状態を利用ガイド・Release noteと一致させる。
- [ ] 新しい配置先の同梱EXEで検索、候補表示、UI応答、正常終了を確認し、未確認を記録する。
  元UI 26はprivateな非入力desktopでの人工試験、最終補正の二境界制御は各30期待成功である。元26は不変経路に限定した継承で、現在PEによる再実行ではない。通常ユーザーdesktopの目視確認とは分ける。
- [x] 実収集→署名索引→GitHub→通常アプリで、有限対象の実取得・内容検査と標準INF候補表示を確認した。
  通常製品の固定公開鍵・独立取得policyを確認し、ローカル受入用の鍵・同意・期限を流用しない。
  1 package／1機器、72 INF中57合格・15未解析/未対応、旧版候補3件・未選択・実導入0の範囲に限る。
- [ ] Providerごとの公式経路、実byte、署名、内容、端末適用性、必須条件、導入方式を確認し、
  内部検証と実機確認を区別する。内容未対応やinstallerを標準INF合格へ数えない。
- [ ] 実導入を行う場合は対象と別の明示指示を確認する。Serverはbackup／checkpointと復旧手順、
  clientは復元開始失敗の拒否を含め、実施範囲と未確認を残す。
- [ ] 日次継続、再起動、別PC移設は別の運用受入として確認し、setup配置やfakeの合格で代替しない。

## Remoteと公開

- [ ] 許可対象のPrivate push／readbackを確認する。これをPublic承認としない。
- [ ] 公開開始後の変更を公開側の履歴へ保持する。毎回のroot作り直しやforce-pushで公開履歴を消さない。
- [ ] 本人がsource、README、具体的な最終公開一覧、検証結果を確認し、Public化を別途明示承認する。
- [ ] 該当する承認後だけpush／tag／Release／visibility変更を行い、repository、commit、tag、asset、
  checksum、公開状態をreadbackする。

初回公開は画像metadata・私有履歴分離・固定822 fileの検証と本人承認を経て実行済みです。
後続変更の公開集合・新しいbuild/testと監査・追加反映、アプリbinaryのRelease受入は別に確認します。
Public日次publisherは未対応、旧日次・smoke Taskは停止中であり、Task再開・切替は別の明示操作です。
日次七回・別PC実移設、対応拡大／SDIO不足解消は後続の目標で、有限なローカル機能受入とは区別します。
