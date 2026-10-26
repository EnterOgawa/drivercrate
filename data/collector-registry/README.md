# 公式ドライバーの共通調査台帳

このdirectoryは、公式配布情報の研究台帳と、locator・取得証拠・監視policyを収めます。
新メーカー・新製品は人が公式情報を調査して外部JSONへ追加し、通常の対象追加をcollector／アプリの
code変更から切り離します。未対応のsite形式だけを別のparser実装・実測として扱います。
自動の新製品調査、製品AI、有料検索API、Cloud Runを現行機能にしません。

## 新規対象の追加チェックリスト

今後の新device・メーカー・製品にも、[ADR0402](../../docs/adr/0402-partial-collection-and-release-priority.md)の
部分収集規則と[ADR0403](../../docs/adr/0403-independent-producer-publication-input.md)の手動発行規則、
[ADR0405](../../docs/adr/0405-metadata-bound-native-acquisition.md)のmetadata結合取得規則を適用します。
追加作業ごとに次を確認します。記載だけで新対象の収集・端末適合・導入を確認済みにはしません。

- [ ] 工程と有限対象・期待結果を事前登録し、公式情報を手動調査して外部JSONのregistry/locator/profileへ追加し、
  既存の共通検証へ通します。新形式のparser実装・実測だけを別工程へ登録し、メーカー固有のアプリ分岐・
  製品AI・自動調査を追加しません。具体的な保守・検証・import操作は本書の後続節と[収集手順](../../docs/collector-setup-guide.md)を使います。
- [ ] 台帳登録・実取得・内容検査・端末適用性・実導入を別集計し、登録だけを利用可能driver数や対応数にしません。
  未確認・失敗・HOLD・未知を元の比較分母と理由へ残します。
- [ ] 取得不可・一時障害・HOLDの理由、元観測時刻、最終試行・次回試行下限を既存の保護run/result/待機履歴へ残し、
  許可済み次回試行または手動reviewへ送ります。未試行を実試行とせず、他対象と公開準備を進めます。
  credential・生inventory・URL/token・私有本文を一般ログや公開assetへ追加しません。
- [ ] 日次試行・週内一回程度の成功を運用目標とし、既存の同意・待機/Retry-After・有限予算・課金を維持します。
  週内成功を保証や原期限延長にせず、HOLDを自動解除したりroot/namespace/counterをresetしたりしません。
- [ ] 検証済みの成功分と未失効の前回成功を既存候補経路へ進め、原record/byte/hash/署名/期限を保持します。
  全失敗・全HOLD・空成功で前回headや公開assetを空の新世代へ置き換えません。期限切れの保存と現在利用を分けます。
- [ ] 索引署名、実取得byte、INF/CAT/全参照file、端末適用性、同意・復旧、世代下限を維持します。
  新発行には必要なfresh観測・独立根拠確認を使い、旧成功の保持をfresh根拠へ換算せず、各段階で原期限を再確認します。
  EXEコード署名の延期を索引署名の省略へ広げません。
  公表されたSHA-256/SHA-512は全算法を実byteへ照合し、片方の不正を無視したりSHA-512からSHA-256を合成したりしません。
  exact sizeは掲載時だけ制約とし、未掲載を0や概算MBで補いません。新版の期待metadataと原manual/body・旧archiveは
  別の原byte/hash/時刻で保持し、INF/Modelsの操作者制約を新版での存在・内容検査成功へ換算しません。
- [ ] 通常日次は未署名候補生成までとし、prepare/sign/publishは明示手動で分けます。成功した汎用のみ/nativeのみ/両方を
  完全なfile/hash対でpinし、指定した不正入力を黙って除外しません。実導入とpush/tag/Releaseはそれぞれ別の明示指示を必要とします。
  metadata結合の設定生成には[正規preparer](../../scripts/prepare_daily_index_config.py)の`--inherit-config`と
  明示scope v2のfile/hash対を使い、原release/body/review/scriptの完全対と必要時の技術review四入力を渡します。
  私有宣言や保存診断を手作りの保護authorityへ復元せず、同一許諾への再同意を増やしません。
- [ ] 全対象の実導入・全取得先の同時成功・七日観測・全機器網羅を公開準備の前提にせず、実績と未確認・未完了を区別します。

## データの意味

このdirectoryの台帳`accept375-existing-prolific-20261024`は127メーカー・6,584製品参照・
1,718研究record、locatorは390件、collection profileは既存1 record用の1件です。
2026-10-11世代の全source・製品・recordと旧観測を保持し、既存Prolific七製品参照の公式PAGE観測7件、
PAGE/ZIP locator2件とprofile1件だけを補いました。元PAGE観測は2026-10-24T02:44:54Z、本文は同梱しません。
新メーカー・製品・record追加は0です。既存取得証拠4行は通常carry-forwardで新台帳へ結合し、元時刻/hashを保持します。
旧71メーカー世代の三入力と取得証拠8件は保守側に原byteで保持しています。現世代の取得証拠4件とは
別集合であり、合算したり新規取得と表示したりしません。condition-reviews、link-completion、sample-planは
旧世代に結合する明示履歴入力で、現在のseedへ暗黙に混ぜません。
いずれも調査対象の件数で、実収集成功、driver対応、端末適合、導入成功の件数ではありません。
新対象拡大は現在の機能受入後の保守で、総数の上限や全対応の保証は設けません。

| file | 用途 |
|---|---|
| [registry.json](registry.json) | source・製品・配布record・観測のstable IDと参照関係。 |
| [locators.json](locators.json) | 公式pageと再探索先、未取得linkやreview条件。 |
| [payload-evidence.json](payload-evidence.json) | 台帳hashとrecordへ結合した後日の取得・内容観測。driver本体は含まない。 |
| [monitor-policy.json](monitor-policy.json) | 登録済み対象の保留条件。待機や未接続native制約を回避しない。 |
| [collection-profiles.json](collection-profiles.json) | 台帳・locatorを参照する収集条件。既存1 record分を登録し、通信や導入の許可と分ける。 |

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

### collection profileの非通信保守

`scripts/collector_collection_profiles.py`の`validate`／`plan`／`upsert`は通信を行いません。
`--registry`、`--locators`と`--profiles`で原入力を明示します。`plan`は必須の`--output`へ
新規JSONを作り、通常出力は件数だけです。新規出力の親directoryは事前に用意してください。
setup親の専用callerへ実native job、active data import、snapshot/setup同梱と専用日次dispatcherを接続しています。
実child/pipe/保護file/lock、模擬HTTP/CATと通常ZIP/INF parserを使う有限試験で確認しました。
10月24日の固定1 packageは実HTTP2要求/506,429byte、INF2件のCAT/参照本体検査に合格しましたが元runは投影0です。
nested修正の内部検証後のfresh実投影、最終0.1.1配布物・自然日次・別PCは未確認です。

追加・更新は`dc-collector-collection-profile-edits-v2`の`profiles`へ変更profileだけを置き、
`upsert --edits ... --revision ... --as-of ... --output ...`を使います。新規作成時の`--profiles`は省略可です。
製品・URL・OS・版・公開hashを転記せずstable IDで参照し、原bytehashと世代bindingはtoolが計算します。
世代を変える場合は旧profileと`--previous-registry`／`--previous-locators`も指定します。
参照先・実行条件の変更は`REVIEW_REQUIRED`となり、旧確認を自動付替えしません。
保留解除には次のupsertで当該profileの全確認入力と新しいprofile revision、
`--review-profile ID`を明示します。規約不明等は解除後もHOLDです。
profileの全fieldと根拠入力の固定例は`scripts/test_collector_collection_profiles.py`の
`collection_fixture()`にあります。生成索引の手編集やhashの手計算は不要です。

四範囲の`evidence.checkedAt`は、そのscopeを実際に手動確認した時刻です。
対象のlocatorId/bodySha256/contentSha256/scopeへ結び、原PAGE観測以降かつprofiles.asOfと実現在以下を要求します。
現行profiles v2の`contentSha256`は、厳密な末尾診断コメントだけを除外できる独立した比較digestです。
四範囲とも同じ原PAGEのraw hashとcontent digestを保持し、原本文・原hash・観測時刻を置換しません。
原PAGEの時刻/hashを書き換えず、旧HTTP datasetのlocators.asOfとは区別します。
日次の同hash再取得だけで手動確認時刻は更新しません。候補期限は同run内容検査/PAGE観測と
四範囲の実手動確認の各+8日のminです。この修正だけでは実review/importや実収集の完了を意味しません。

planは全対象をstable順に残し、未知形式を`UNSUPPORTED_SOURCE_FORMAT`、条件不明を`HOLD`、
一回32jobを超える分を`DEFERRED_BATCH`へ分けます。`--completed-profile ID`は次batch選択だけで、
成功や待機解除を表しません。未profileの台帳recordも`unprofiledRecords`に
`NO_COLLECTION_PROFILE`として全件残し、実行対象や対応済みへ数えません。
jobのschemaは`dc-collector-registry-job-v2`で、exact起点・payload・
原hrefの`source`、参照解決済み`record`／`products`、原`pageObservation`、原入力binding、
`container`／`maximumBytes`／`infSelection`／`review`を持ちます。実行許可・内容合格の証拠ではありません。

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
