# ADR 0399: 原PAGEを保持した限定末尾診断コメントの比較

- 日付: 2026-10-25
- 状態: 採用・実装・有限検証合格・主担当434受入済み。新配布物と新実取得は別受入
- 対応: G13-I7r255c2ptn0/ni/nt/nv、実使用強度max、単独・対応増0

431/432では375/431の原本文各111656byteの差が、末尾のWP Fastest Cache生成秒数・日時
コメントだけと確認された。他111564byteは完全一致する。現在のraw SHA完全一致はこの差も
手動四scopeの失効として扱いpayload前で拒否する。427の欠測111702byteの原因は未確定である。

原本文・bodySha256・bodyBytes・checkedAtと、同HTTPの実観測/私有proofを変更しない。
手動scope evidenceへ独立した必須`contentSha256`を加え、locatorId/bodySha256/contentSha256を
同じ原PAGEへ結合する。四scopeは同じ三値を必要とし、scopeと各原手動確認時刻も検査する。
profiles/edits/jobは現行v2だけを生成・実行する。raw fieldへ比較digestを流用しない。

比較digestは1～2MiBの原byteを入力とし、通常は全rawのSHA-256である。次の全条件が成立する
場合だけ、末尾コメント開始より前の全byteをSHA-256へ渡す。元本文そのものを変更しない。

- 原末尾は厳密な`</body>\n</html>`直後のコメント一件とEOFであり、後続空白も許容しない。
- コメントは`<!-- WP Fastest Cache file was created in 0.`、ASCII数字14桁、
  ` seconds, on `、有効な`dd-mm-yy HH:MM:SS`（年2000～2099）、` -->`の完全書式である。
- 固定開始markerは全rawで一件だけ。重複・不正・非末尾のものは除去しない。
- 既存collectorの有限HTML tag/comment/引用符/非表示要素走査を再利用し、末尾body/html終了tagが
  実tagであることを確認する。script/style/template等や属性文字列、既存comment内の偽終端、
  未終端・過大tag/過大集合は除去対象にしない。script/HTMLを実行しない。

Pythonの手動保守用純粋digest関数とC++の実取得比較は同じ契約と固定caseを使う。
手動確認者は実際に確認した原byteからdigestを計算し、四scopeへ記録する。digestだけで
公式性・規約・前提・適用性を認定せず、既存locator/raw結合を維持する。
実取得では同HTTPのrawまたは同runで生存する完全PAGE proofのrawを比較し、その後に
既存のexact対象anchor検査へ進む。保存bodyをproof/grantへ復元しない。
本文/anchor/script/規約/前提の一byte差や任意コメント変更を自動許容しない。

既存workspaceの保存v1 dataは現行実行として受理しない。非通信のpackage switch/verifyと
新data import時の旧active比較だけは、元manifest・全byte/hash/size・閉集合とregistry/locators/
research-index・保存profile参照/世代を履歴として検査する。原dataを書換・変換しない。
新import元、通常active選択、plan、native job、candidate生成はv2必須であり、import前の
旧activeからの収集は拒否する。未知schemaは履歴でも拒否する。旧成功を新資格へ補完しない。

元manual四時刻・PAGE原時刻からの候補期限最小値、実PAGEのfresh24h、原URL待機・予約最大課金・
所有/署名/hash/CAT/INF/適用性/同意/復旧を維持する。今回外部bundle・運用state更新は0。
原375/431のオフライン正例と変更負例をPython producer→native job/acquisition→candidateへ通し、
共有PAGE/期限/予算/原raw保持を決定的に確認する。実HTTP/Task/鍵・署名/driver導入/remoteは0。

433では最終通常Debug/Releaseで各18caseを確認した。手動raw=375を固定し、実fake response=431でも
比較digest一致によってcandidate一件へ進み、元四時刻からの期限を維持した。各16負例は
0x8007051A/payload未開始/candidate0を保持した。既存native14mode/consumer18/選定CTest10、
影響各8target/解析16contextと局所品質を確認し、通常build設定へ復帰した。
repo初期profileも原375のraw/四確認時刻を保持してv2へ揃え、通常plan一件を確認した。
外部運用bundle/元ledger/待機は更新していない。原FAILや427欠測を成功へ変更しない。
