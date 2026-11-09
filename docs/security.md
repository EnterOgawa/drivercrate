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
client復元ポイントの開始失敗は導入中止、終了処理は例外時も実行します。Serverは事前backup/checkpointの管理者確認を要求します。
復旧の成功や全driver変更の巻戻しは保証しません。Install終端はscanを失効し、次の導入には新しい検索を要求します。

## Privacy

telemetry、広告、追跡、P2Pは実装しません。探索契約に従う最小の製品表示名と、生Hardware/Compatible ID・instance ID・serialを区別します。
後者やcredentialを検索語へ送りません。通常の診断は段階・件数・数値codeに限定し、URL/token/任意本文や生inventoryを残しません。
私有Collector/定義/registry、driver本体、鍵、credential、私有診断は公開source/Releaseへ含めません。
脆弱性報告は[SECURITY](../SECURITY.md)、確認方法は[testing](testing.md)を参照してください。
