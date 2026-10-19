# ADR 0209: 常時稼働PCで先行する公式配布元の継続収集

> 公開版の読者へ（2026-10-18）: 以下は採用時と追記時の決定履歴で、当時の「現コード」や件数を
> 現在の実装・受入状態へ読み替えない。Cloud移行・AIは現行範囲外、新製品調査は人による保守作業である。
> 現在は登録済み対象の収集と共通署名索引を用い、Task／配布／setupのコード接続と実運用受入を分ける。
> 現行ソースに対応する収集用ローカルv5 packageは、このPCで配置・検査・保持／解除と、非通信の初期化・検証・
> 停止export／import・人工中断からのnative再開を有限に確認済みである。空のローカルmonitorによる確認で、
> 実正本の結合・オンライン開始、実GitHub→通常アプリ、日次継続、別PC移設と公開は未受入である。
> 現在の自己完結した説明は[アーキテクチャ](../architecture.md)、[Collector案内](../collector-setup-guide.md)、
> [テスト方針](../testing.md)を参照する。以下のADR番号と基本設計は保守側に保持する履歴参照である。

> 2026-10-02追記: ADR 0224を優先する。
> AI機能を撤去し、常時稼働Windows PCの非AI収集 → ローカル索引生成 →
> 検証後の同一GitHub repository配布とする。原則日次収集・週次索引更新、
> Cloud Run移行なし。実公開・Task登録の実行許可を含まない。

> 2026-09-27追記: ADR 0217によりCloud移植を
> 現行範囲から外した。このPCでの収集可否の実測を先行し、GitHub公開は最後とする。
> 以下のCloud移行・実測後の移植判断は当時の設計履歴であり、現在の実行予定ではない。

- 日付: 2026-09-24
- 作成者: Shunji Ogawa
- 状態: 収集方法を採用。限定二sourceのmetadata CLIとADR 0210の台帳保護を実装・検証。定期実行・大規模実測は未実施。
- 工程: G13-D6j15j2q5a
- 根拠: 利用者の「このマシンで収集機能を作りこんでからCloud Runへ移す。まず収集方法を固める」という指示。
- 詳細: ローカル継続収集の基本設計

## 1. 順序と責務

このPCを最初の収集hostとする。収集対象はこのPCに接続されたdeviceに限定せず、公式の
製品一覧・catalog・support pageから得た公開製品と配布情報とする。現PC247 PnP nodeは
端末照合の別評価集合として保持し、収集対象数や必要なdriver本数には変換しない。

先行予定だったADR 0208のworker内PnP接続は保留し、収集の発見・差分・再開・計数を先行する。
収集機能の合格に全247 nodeの適合完了を要求しない。Windows上での内容検査と端末適合、
製品UI接続は引き続き必要だが、収集collectorのCloud移植とは別の受入とする。

日次で期限の来たmetadataを収集し、週次で索引候補を生成する。これは実行前の初期設定案であり、
今回Task Schedulerへ登録しない。ADR 0205の同一GitHub repositoryへの週次公開方針は維持する。
同ADRの「週次Cloud Runによる生成を先行」は、ローカルの日次収集・週次候補生成を先行する
本ADRへ置き換える。Cloud側の日次／週次の実行頻度と費用はローカル実測後に再判定する。

## 2. 収集経路

1. 公式配布元のroot、公式性の根拠、取得・解析policyをsource registryで管理する。
2. 公式catalog、公開製品一覧、公式pageから辿れるAPI、sitemap／feedを使って製品を列挙する。
3. 各製品の公式配布情報を収集し、製品関係・OS・x64・版・分類・公開hash・再探索先を正規化する。
4. 新規・変更配布物を、許諾と有限予算を満たすものから検査用に取得する。
5. Windows検査workerで対応形式のINF／CAT・署名・閉包を検査し、非公開の根拠を追加する。
6. 集計と品質確認を経て週次索引候補を生成する。署名・GitHub公開は既存の別工程で扱う。

製品ごとのURLをsourceへ延々と直書きする方式を基本にしない。ただし新しいメーカーの公式起点や
独自page形式への対応は不要にならない。汎用の構造化データ／link抽出を先に試し、未対応は
理由付きで残してadapterを追加する。検索結果やAIは新しい起点の発見補助に限り、公式性や
製品適合を決定しない。有料検索API、利用者のchat account、GPU／modelを収集の必須条件にしない。

Microsoft Update Catalogの外部巡回・非公式追跡site・CAPTCHA回避は初期collectorに加えない。
既存WUAは端末経路として維持する。助言中のRSS・APIの存在や利用条件は、将来の採用時に
公式資料と現物を確認する。未確認のendpointを監視可能と記述しない。

## 3. 台帳と信頼段階

初期状態storeは非公開のUTF-8 JSON file群とする。単一writer、世代固定の結果、checksum付き
checkpoint、最後に更新する世代pointerで再開する。公開索引はこの台帳から生成する別成果物とする。
JSONのhashは破損検知であり、署名や公式性の証明ではない。

`sourceId`、公開製品／配布recordのidentity、変更検知用digest、実取得SHA-256を区別する。
同じpayloadでもOEM製品関係は消さず、別製品の同名・同版を同じdriverと推測しない。
期限付きURL、credential、cookie、EULA全文、端末inventoryは台帳へ保存しない。公開起点と
許可fieldへの射影を保存し、driver取得時は新しいsessionで公式元と許諾を再確認する。

配布情報、link解決、全byte取得、内容検査、端末適合は独立した到達段階とする。HTTP 200／HEAD成功や
ZIP保存だけを「対象device用driver取得成功」へ昇格しない。内容未対応のEXE／MSIは候補として保持し、
自動実行せず未検査を示す。通常driverと同じpageにfirmwareの記載があるだけでは一括除外しない。

将来のID逆引き根拠には、公式catalogの公表IDに加え、公式配布packageの検査済みINFに公表された
Hardware／Compatible IDを利用できる。package hash、INF member hash、parser版、検査結果を結合し、
端末から収集したIDとは別の来歴を必須にする。これはADR 0207の公表IDの出典を明確化する追加である。
現v1／v2射影へID fieldを追加せず、新schemaと拒否試験の受入までは公開索引へ含めない。
INFの対応IDだけでOEM条件・OS装飾・依存関係・Windows rankを省略しない。

## 4. 差分・再開

HTTPが対応する場合はETag／Last-Modifiedによる条件付きGETを使用する。304は同じ要求条件と
保存済み検証結果への結合が成立する場合のみmetadata再確認とする。parser／policy変更後や
保存データ欠損時は無条件GETへ戻す。304を新しい取得grantの公式応答根拠として利用しない。
既存のcacheを拒否する取得adapterを緩めず、収集用の応答・射影型を別に設ける。
[HTTP条件付き要求と304](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5)。

毎回新しい全量を上書きせず、成功targetをcommitしてから次へ進む。再起動後は未完了targetだけを
再取得し、日次runの固定母数と原失敗記録を維持する。通信の重複が起こり得ることは認め、commitと
計数を冪等にする。403／CAPTCHA／schema変更／規約待ちは即時反復せず保留し、429はRetry-Afterを
尊重する。timeout等も初期の同一run自動retryは0とし、次回dueで別観測を残す。

失敗、件数減少、削除疑いで最後の成功データを消さず、鮮度・今回の失敗を記録する。
確認できていない古いrecordの日時を書き換えて更新済みにしない。公開candidateの作成に失敗した場合も
前世代を維持する。無人の全driver一括取得は行わない。

## 5. WindowsとCloudの境界

専用collectorはC++20のCLIとし、queue・差分・状態・射影をWindows APIから分離する設計とする。
現コードにはWinHTTP、WinRT JSON、Windows署名APIがあるため、既存EXEをそのままCloud Runで
動かせるとは扱わない。初期Windows実装では既存HTTP policyとparserをadapter経由で再利用する。
Cloud用transport／parserの移植・同値fixtureは後続工程である。

Cloud RunはLinux x86_64実行環境であり、instance filesystemは停止後に永続化されない。
移行対象は収集・差分・索引生成で、状態storeは専用外部storageへ置き換える。
WinTrust／SetupAPIによる署名policy・端末PnP／rankはWindows検査worker／端末に残す。
Cloud移行後に内容検査済み情報も更新する場合は、Windows workerとの結合を別途受け入れる。
[Cloud Run実行契約](https://docs.cloud.google.com/run/docs/container-contract)。

## 6. 合格条件

- 固定targetを全件accountingし、成功・対象行なし・失敗・保留・未到達を落とさない。
- 変更なし、変更あり、schema変更、429、途中終了、二重起動、壊れたcheckpointのfixtureを通す。
- 既存32公開対象を含む、少なくとも16配布元・300公開製品を目標とした評価manifestを実行前に固定する。
  条件違いの同一modelを水増しせず、未対応配布元も分母へ残す。未達時は実数を報告する。
- 製品数、metadata到達製品数、link解決製品数、driver取得製品数、固有package取得数、
  内容検査数を別に報告する。部分取得sampleだけから300製品の取得率を推計しない。
- 日次運用7回と途中再開、週次候補生成1回を観測して収集の初期採否を判定する。
  ADR 0205の公開後4週の評価は別に残す。Cloud化と公開はこの採否だけで自動実施しない。

本ADRを採用したq5a時点は設計のみで、対応系列・ソース接続・内部合格・実device実測の増加はいずれも0だった。
後続q5bの限定metadata CLIと台帳保護の実装・検証はロードマップとADR 0210に分けて記録する。
