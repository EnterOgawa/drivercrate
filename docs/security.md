# Security boundaries

DriverCrateはWindowsの署名/適合/権限と組織policyを尊重します。WUAが非適用・導入済み・置換済みとした候補を独自に戻しません。
公式の取得情報と実際に取得したbyte、検査済み候補と実端末の適合、実導入結果を分けます。

## 取得と内容検査

取得先、grant、hash/サイズ、HTTPS/redirect/host制約と有限予算を検査し、従量制拒否・取消しを維持します。
標準driverではINF/CATの整合と全参照file、署名、対象OS/x64、device/class、Windowsのrankと直前再照合を要求します。
未評価の必須条件や分離不能firmwareは理由付きで保留/対象外とします。一般的な依存の可能性だけでは一律除外しません。
公式installerは標準INF導入と分け、同じ選択と予定変更範囲への明示許可へ結びます。

## 署名索引と保護store

公開鍵、署名manifest、asset hash、原期限、世代下限、consumer codecを検証してから端末内で照合します。
同世代cacheの利用でも再認証を省きません。未知の所有root、reparseや破損を無断adopt/reset/移動/削除しません。
AppのAuthenticode、driver CAT、索引署名は別用途です。どれか一つの成功で他の検査を代用しません。

## Session・同意・復旧

選択を同scan/device/recordへ固定し、stale/重複/不明候補を拒否します。旧版切替と具体的な新条件は明示確認へ結びます。
Windowsクライアントでは同日の復元ポイントをWindowsで確認して再利用し、保護を準備できない場合は導入を中止します。開始した操作は例外時も終了処理を行います。Serverは事前backup/checkpointの管理者確認を要求します。
処理した対象の選択は完了時に消費します。残りの候補は元の検索結果で保持し、次の導入時に期限・内容・適用性・同意を再確認します。

## Privacy

telemetry、広告、追跡、P2Pは実装しません。探索契約に従う最小の製品表示名と、生Hardware/Compatible ID・instance ID・serialを区別します。
後者やcredentialを検索語へ送りません。通常の診断は段階・件数・数値codeに限定し、URL/token/任意本文や生inventoryを残しません。
私有Collector/定義/registry、driver本体、鍵、credential、私有診断は公開source/Releaseへ含めません。
脆弱性報告は[SECURITY](../SECURITY.md)、確認方法は[testing](testing.md)を参照してください。
