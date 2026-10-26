# ADR 0398: 同runの完全PAGE原本文を診断用に保持する

- 日付: 2026-10-25
- 状態: 採用・実装済み、有限fake検証合格・主担当430受入済み。実運用の新PAGE捕捉は未完了
- 対応工程: G13-I7r255c2ptd0 / c2ptdi / c2ptdt / c2ptdv
- 実使用推論強度: max、単独・再委譲0、対応増0

427ではHTTP200/111702byteの完全PAGEが期待hash不一致で拒否されたが、原本文は
同run memoryだけにあり、旧111656byteとの差の意味を後から確認できなかった。
再取得で同じ応答を再現したと見なさず、完全な同HTTP応答を収集側へ残す。

既存friend `CollectorRegistryJobProtectedCaller`は、結果JSONを先に新規保存した後、
同じ生存scopeにある `CollectorRunPageProof::raw_`を `page-<ordinal>.body`へ保存する。
最大2MiB、HTTP200、同起点、COMPLETE、原byte数/hashを既存観測と照合する。
文字コード変換・HTML実行は行わず、既存CREATE_NEW/flush/ACL/単一link/reparse拒否/
読戻しを用いる。hash不一致でも、元の原結果・HRESULTとcandidate0を変更しない。
共有PAGEは各ordinalの原結果と同じ本文を保存し、新PAGE GETや課金を増やさない。

保存失敗は専用のPAGE保存stageを報告し、先に保存した元resultを保持する。
実行は拒否して予約と待機を残す。部分fileを成功や新権限へ変えず、削除・自動retryしない。
成功した新EXECUTE_JOB応答のpageProofがtrueなら、本文存在と既存result.pageObservation/
pageTransfer/job sourceとの照合を必須とする。既存IPC/schema fieldは増やさない。

closed run layoutは既知ordinalの固定body memberだけを許可する。存在するbodyは
同resultの原hash/size、HTTP200/COMPLETE、実観測時刻と入力sourceを検査する。
結果保存後・精算前の停止窓も同じ検査を使う。従来runのbody不在は許容するが、
捕捉済み・再確認済みと補完しない。同schemaの旧runと新runを保存履歴だけで識別できないため、
保存後にbodyだけが消えた事実は旧runの不在と区別できない。この限界はauthorityに影響しない。
新実行時は応答を受ける時点で存在を必須検査する。改変・余剰名・不完全観測は拒否する。

bodyは保護された収集PC内の診断資料だけで、proof/grantを復元しない。
通常UI/log/Public索引・build report・公開exportへ混入させない。索引は従来の検査済み
候補だけから生成する。可搬参照は本文を含まず、実runや権限としてimportしない。
新authority/API/一般cache・自動承認・別GETは追加しない。
24h待機、最大予約、元期限、署名/CAT/INF/適用性/同意/復旧の境界を維持する。
今回の保存実装だけを、実PAGE差分の確認・driver取得成功・索引署名可とは扱わない。

429ではPython pipeline21方法、native両構成七mode、consumer各9方法、選定CTest各4件を
有限確認した。原mismatch fixtureの後続job実行仮定は誤りだったため、原exit1を保持して
実際のDEFERRED/HOST_REVIEW_REQUIRED・最大課金へ試験期待だけを訂正した。
成功済みDebug default/parsedは元test binaryの結果として保持し、新test byteへ継承しない。
製品保存sourceはその訂正で不変更。新実HTTP/Task/署名/公開/導入は行っていない。
