# 公式ドライバーの共通調査台帳

このdirectoryは、公式配布情報の研究台帳と、locator・取得証拠・監視policyを収めます。
新メーカー・新製品は人が公式情報を調査して外部JSONへ追加し、通常の対象追加をcollector／アプリの
code変更から切り離します。未対応のsite形式だけを別のparser実装・実測として扱います。
自動の新製品調査、製品AI、有料検索API、Cloud Runを現行機能にしません。

## データの意味

このdirectoryの台帳`20261004-15`は71メーカー・3,586製品参照・1,136研究record、locatorは130件です。
保守側で固定した別世代の127メーカー・6,584製品・1,718研究record・388 locatorとは区別します。
いずれも調査対象の件数で、実収集成功、driver対応、端末適合、導入成功の件数ではありません。
新対象拡大は現在の機能受入後の保守で、総数の上限や全対応の保証は設けません。

| file | 用途 |
|---|---|
| [registry.json](registry.json) | source・製品・配布record・観測のstable IDと参照関係。 |
| [locators.json](locators.json) | 公式pageと再探索先、未取得linkやreview条件。 |
| [payload-evidence.json](payload-evidence.json) | 台帳hashとrecordへ結合した後日の取得・内容観測。driver本体は含まない。 |
| [monitor-policy.json](monitor-policy.json) | 登録済み対象の保留条件。待機や未接続native制約を回避しない。 |

製品の`recordIds`が対応の正本です。共通recordを共有できますが、名前・版だけで同一driverと推測しません。
不明値は`null`、本体link未確認は`MISSING`です。`OFFICIAL_LINK`には公式pageからの同URL観測、
`HEAD_OK`にはそのURLへのHEAD 200が必要です。HTTP 200や公開hashの記載だけでは実byte、署名、適合を保証しません。
元metadataの`NOT_DOWNLOADED`を後日の取得で上書きせず、取得証拠を別に結合します。

研究索引は`researchOnly=true`、`publishable=false`、`installAuthorized=false`を維持します。
人のURL調査を実HTTP download grantや導入許可と扱いません。cookie、credential、認証query、
端末path、実inventory、署名秘密鍵を登録しないでください。通常アプリが使う署名配布索引とは別成果物です。

## 非通信の検証とsnapshot

repository rootでPython 3.13の標準libraryを使用します。アプリの実行時要件ではありません。
次の`out/registry-example`等はlocal生成物用の例で、保存済み公開fileへのlinkではありません。
出力先には存在しない新規directory／ZIPを指定します。

```powershell
py -3.13 -X utf8 -B scripts/collector_registry.py validate data/collector-registry/registry.json
py -3.13 -X utf8 -B scripts/collector_registry.py build data/collector-registry/registry.json out/registry-example
py -3.13 -X utf8 -B scripts/collector_registry.py verify out/registry-example
py -3.13 -X utf8 -B scripts/collector_registry.py zip out/registry-example out/registry-example.zip
```

台帳のみは6 file、取得証拠を含むsnapshotは7 fileです。全fileをcopy後に`verify`し、hash、schema、
参照、件数と索引を再計算します。checksumは破損検知であり、署名や観測者の真正性ではありません。

```powershell
py -3.13 -X utf8 -B scripts/collector_payload_evidence.py validate data/collector-registry/registry.json data/collector-registry/payload-evidence.json
py -3.13 -X utf8 -B scripts/collector_payload_evidence.py build data/collector-registry/registry.json data/collector-registry/payload-evidence.json out/registry-evidence-example
py -3.13 -X utf8 -B scripts/collector_payload_evidence.py verify out/registry-evidence-example
py -3.13 -X utf8 -B scripts/collector_locator_snapshot.py build data/collector-registry/registry.json data/collector-registry/locators.json out/registry-locator-example --evidence data/collector-registry/payload-evidence.json
py -3.13 -X utf8 -B scripts/collector_locator_snapshot.py verify out/registry-locator-example
```

locatorと取得証拠を結合するsnapshot v4は8 JSONです。履歴を引き継ぐtoolは旧snapshotを検証し、
元観測日時・hash・取得rowを保持します。過去取得を新規downloadへ数えず、元snapshotを残します。
追加・補完の許容範囲を各carry-forward入口で明示し、旧source・製品・recordを無断変更・削除しません。

## 登録済み対象の監視

`scripts/registry_daily_monitor.py`は登録済み対象を有限に監視する保守入口です。
`init`／`verify`、`run`、`run-locators`、`run-pages`、停止`export`／`verify-export`、
`import-export`／`resume-import`を持ちます。通信するrun系は確認済みの対象と同意を別に必要とします。
要求前に待機を保存し、最低24時間、host保留、一回64要求／32MiB／600秒を維持します。
失敗・保留・未到達を報告へ残し、直前の成功を削除しません。共有native制約が未接続のsourceはHOLDです。

停止exportはlockを除く閉じたsnapshotを作り、新規rootへの明示importは元待機・全reportを保持します。
元hostの停止確認は申告であり遠隔停止ではありません。exportから直接通信せず、importだけで開始許可を得ません。
別PCのnative保護stateや元日予算の来歴を空にするcopyを行わないでください。
setupとの結合と未受入は[Collectorセットアップ](../../docs/collector-setup-guide.md)を参照してください。

## 端末接続との区別

アプリは共通の署名索引検証と端末内照合を使い、研究JSONのboolから導入権限を作りません。
実取得byte、署名、内容、OS／x64、端末適合、選択・同意と復旧を端末側で再確認します。
固定公開鍵・独立取得policyを用い、Public索引から通常画面で1 packageの取得・検査と1機器への候補表示を
有限に確認しました。台帳件数、索引収録数、内容合格・端末適合・実導入は別集計です。
[アーキテクチャ](../../docs/architecture.md)、[セキュリティ](../../docs/security.md)、
[テスト方針](../../docs/testing.md)に現在の境界と残件をまとめています。
