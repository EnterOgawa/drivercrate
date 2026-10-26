# ADR 0400: Intel明示収集の同HTTP失敗PAGEを別の保護診断へ保持する

- 日付: 2026-10-25
- 状態: 採用・実装済み、有限fake検証合格・主担当436受入済み。実HTTPでの捕捉と保護先保存成功は未確認
- 対応工程: G13-I7r255c2fdiag0 / diagi / diagt / diagv
- 実使用推論強度: max、単独・再委譲0、対応増0

407のIntel fresh収集はPAGE200後error13/records0/payload0で失敗した。同HTTPの原本文は
失敗後に破棄され、409の拒否stage追加だけでは次の一回の原本文比較ができない。
過去407の原因を推測せず、次の許可時刻以降の明示収集で完全200本文を別診断へ残す。

明示 `--daily-acquire` の同invocationだけを対象とする。既存
`getCollectorMetadataForSource` が厳密受信・UTF-8・hashと取得証拠を検査して返した完全200の
原byte/hashを、失敗時専用のephemeral fieldへ移す。失敗時のbodySha256、lastFetchedAt、
retainedMetadataBytesは最後の成功checkpointのままとし、新fieldをcheckpointへ保存しない。
304、部分受信、上限超過、原byte欠測、未試行、再開または旧成功から本文を合成しない。

実Intel metadata request上限は2MiB（official_release_metadata.cppのMAXIMUM_METADATA_BYTES）。
成功receipt/evidence本文の512KiB制限を診断へ流用せず、完全rawは2MiBまで、base64を含む
別診断JSONは3MiBまでとする。切り詰め保存は禁止する。既存保護writerの1MiB制限は通常出力へ
維持し、dailyの固定suffix `.failed-page.json` だけ3MiBを許可する。

出力先は原receiptの拡張子を `.failed-page.json` へ置換した同ProgramData operations一job内の
固定派生名とする。通信前に新規性・祖先・実ACLを検査し、元receiptを先にCREATE_NEW保存する。
診断は既存writerの同handle祖先固定・reparse/owner/DACL検査・CREATE_NEW/全書込み/flushを使う。
任意pathや通常work/analysisへの診断出力入口を作らない。

診断schemaは `dc-collector-failed-page-diagnostic-v1` とし、元receipt全byte SHA-256、
manifest/contract hash、source、HTTP status、元collector code/error/stage、試行時刻/次回待機、
原body hash/size/base64を保持する。生成時に同runの原receipt全byte一致とraw再hashを検査する。
検証済み配布record、grant、取得token、URL、header、端末inventoryは追加しない。
診断JSONを成功receipt/六入力/署名候補とみなすconsumerやimport機能は追加しない。

診断保存の成否は数値だけstderrへ分離する。保存失敗や診断生成例外が元collector code/error/stage、
原stdout、原receipt、24h待機を覆わない。部分fileを削除・再送・自動retryしない。
成功evidence writerの200/error0/検証成功条件、receipt/checkpoint schema、厳密成功stdoutは維持する。
fresh pipelineは固定派生診断名の既存衝突も通信前に拒否し、失敗後に六入力準備へ進まない。

本資料は収集PC内の私有診断だけで、公式性・parser成功・取得権限・署名権限・候補数を増やさない。
通常UI/log/共有資料/公開索引へ混入させない。通常collectorの予算/待機/reset、署名/hash/適用性/
同意/復旧/公開承認境界は変更しない。実HTTP・Task・鍵・署名・導入・remote・運用更新は今回0。

435では影響Debug/Release build、各1331assert/失敗0の既存native、追加11条件と14拒否条件、
fresh consumer九方法、CLI六拒否を確認した。2MiB境界を切り詰めず復号して照合し、
旧成功三field/recordと原receiptを保持した。既存CLI実装を人工runへ使う限定probeは
保護外87/欠測13を返し、元code1/error13/stage4/receiptを維持してfile作成0だった。
保護ProgramDataへの実診断保存成功は試していない。
局所四C++のformat差0/519control・8case/error0、両Doxygen118/118/error0と実依存39objectの
限定解析/診断0を確認し、通常構成へ復帰した。過去407の原因や新実捕捉成功へ換算しない。
