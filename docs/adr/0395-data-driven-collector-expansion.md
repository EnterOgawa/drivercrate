# ADR 0395: 外部データによる収集対象の追加と配布索引候補生成

- 日付: 2026-10-23
- 状態: **採用**。主担当が汎用取得/通常全INF検査/全record署名条件と既存native admissionを確認した。実装・回帰・setup受入は未実施。
- 対応工程: G13-I7r252a/252av。実装は252b以降。
- 実使用推論強度: max。対応系列・実device実測・実導入の増加は0。

## 目的と最小構成

新対象を手動調査して外部データへ登録・更新し、対応する共通形式ならcollectorと通常アプリの
code変更なしで、公式経路の更新確認、検査用取得、通常内容検査、アプリ用の未署名配布索引候補生成まで
進められるようにする。既存の明示署名入口へ渡すところまでを実装対象とする。
研究索引の件数増加や固定Intel一件の成功だけでは本Goalを完了としない。

追加は、既存台帳を参照する外部profile、一つの汎用native job、一つの有限な保守pipelineに絞る。
初回の共通形式は`STATIC_HTML_ANCHOR_V1`とし、既存のexact anchor確認とZIP/CAB通常検査を使う。
メーカー名・製品名を条件とするProviderを追加しない。動的API、query付きpayload、同意gate、
POST、script実行、未知installerの展開は、この形式へ暗黙に取り込まない。
未対応形式は`UNSUPPORTED_SOURCE_FORMAT`として残し、必要時だけ別工程で形式adapterを追加する。

## 既存実装の再利用と未接続

| 根拠 | 再利用する契約 | 現在の限界 |
|---|---|---|
| `scripts/collector_registry.py:288,467` | 台帳の参照・公式観測検証、研究用bool固定 | 配布v2 producerではない。 |
| `scripts/registry_daily_monitor.py:68,675`、`scripts/collector_workspace.py:174,299` | URL単位要求共有、writer lock、要求前予約、24h・host待機、native admissionと共有hostのHOLD | 現行はmetadata/PAGE・LINK監視。payload検査jobとの予約・精算接続が必要。 |
| `src/platform/collector_inspection_acquisition.cpp:256`、ADR0280 | 実cost、公式HTMLの一意anchor再確認、exact root/payload host、公開DNS、共通取得session・封印証拠 | 一record/session、32MiB。通常collector CLIへの汎用接続は未実装。 |
| `src/platform/common_driver_package.h:274,288` | 全INFまたは明示一INFの通常閉包/CAT/member検査。ZIP/CAB、個別拒否の保持 | Windows適合・公式性・導入許可とは独立。 |
| `src/app/local_index_signing_main.cpp:585` | `--inspect-collected-package`による取得済みarchive実copy/hash確認、公開INF ID/ClassGUID/publisher読取り | 外側一INFだけのreceipt。JSONの成功値自体は権限ではない。 |
| `src/platform/local_index_signing.cpp:564,832` | 全recordに対する取得用途検査、既存固定配布鍵の明示署名 | 署名器は実CAT/公式性を再検査しない。producerの検査を代行させない。 |
| `src/platform/signed_index_records.h:49,446`、`signed_index_record_lookup.cpp`、`signed_index_candidate_binding.cpp:750` | 既存v2、公開ID/ClassGUIDの端末内照合、実取得と実INF/Windows rank binding | 研究JSONを直接読む経路ではない。 |
| `scripts/collector_locator_snapshot.py:25,63`、既存collector setup | 閉じたfile集合・hash・参照検証、seed配置、停止export/import | profile等の新fileと版付き検証の同梱は未接続。 |

`scripts`の実行用v2 producerを検索した範囲では、生成箇所は
`project_collected_native_index.py`だけであり、固定Intelのsource/page/payload/hash/INF/節を要求する。
`acquire_registry_samples.ps1`、`collector_payload_evidence.py`、`derive_registry_inf_closures.py`には
台帳起点の汎用研究取得・証拠・閉包生成があるが、通常配布v2と生存取得権限のproducerではない。
それらの研究receiptを配布可能へbool変更して流用しない。
旧project/daily pipelineの固定scope・schema・予約・pinは維持し、別の明示入口で汎用経路を作る。

## 外部profileの契約

`data/collector-registry/collection-profiles.json`を追加し、版付きの厳密なfield集合を検証する。
台帳・locator原bytehashとrevision、profile revision、対象の`sourceId`・`recordId`・必要な`locatorId`、
有限な`sourceFormat`、台帳にない実行条件だけを持つ。URL、製品名、版、公開hash、OSは参照先から
解決し、二重に転記しない。参照矛盾、重複、未知field、値の上限超過は通信前に拒否する。

不足する実行条件は、原href、ZIP/CABの明示形式、取得上限、全INFまたは明示選択INF、
公式主体・取得前条件・規約・具体的必須条件の手動確認根拠である。
根拠は元公式文書のURL/hash/観測時刻・確認範囲へ結合する。`NO_CONSENT`や空必須条件を既定補完しない。
任意command、引数配列、plugin DLL、script、shell、任意実行file path、署名鍵は受け取らない。
通常追加は台帳/locator/profileの追記と非通信検証だけで済み、アプリの設定やProvider一覧は増やさない。
保守toolは入力の参照解決・世代hash計算と検証を共通化し、保守担当にhashや索引recordの手計算を
要求しない。既存製品の更新と新製品の追加を同じ入口で扱い、生成済み配布索引の手編集を不要にする。

製品と配布recordの多対多は既存`product.recordIds`を使う。同一payloadは、検証後の実hash/size・形式・
公式導線・条件の同値を確認して一回だけ取得・検査する。URLやtitleだけで共有を推測しない。
全INFを選ぶ場合も既存の128 INF等の上限を維持し、全体上限拒否を部分合格へ変換しない。
公開ID/ClassGUID/INF名/Models節・版・publisherは実内容から抽出する。新IDをcodeへ列挙しない。
複数の節・OSは既存v2が表現できる単位へ分け、128 IDを超える原集合を無言に切り捨てない。

### 台帳とlocatorのリンク状態の分離

主担当354の実入力比較で、既存台帳が`downloadUrl=null/linkState=MISSING`のままでも、
公式PAGE/PAYLOAD locatorと独立確認がそろう合法なprofileからplanがjobを生成することを確認した。
nativeもこの組を入力として扱い、未取得の研究状態を保持する。実行URLは同じrecordへ参照結合した
locator由来のsourceから取り、freshな原本文hash・一意anchor・実取得/署名/INF検査を省略しない。
旧recordのURLやlinkStateを書き換えず、取得結果は新しい観測として別に残す。既知URLの不一致、
null以外とMISSINGの矛盾、未確認の規約/条件などは引き続き拒否する。NULLの受理自体は取得成功ではない。

## 実行と安全境界

1. 既存保護workspace、固定実行file/module、台帳/locator/profileを検証して対象集合を固定する。
   非通信`validate/plan`と明示`run-once`、未署名`build`を保守入口にする。自動新製品調査は行わない。
2. 既存monitor writer lockとnative admission下で予約する。PAGE要求は既存URL keyの待機を共有し、
   payload GET・許諾文書GETを追加の明示予約として数える。新規profileやrevision変更を待機resetにしない。
   payloadの予約・予算は新しい版付きの補助ledgerとして同じ保護rootに置き、既存stateの意味を変えない。
   PAGEとpayloadを開始前に先払いし、二要求目を行わなかった場合も試行を抹消して再試行権を作らない。
3. nativeの一jobで`CollectorInspectionAcquisition`と通常内容検査を呼ぶ。公式root観測の原hash/時刻と
   実archive・公開INF情報を同じjob内で結合する。既存adapterに必要な観測返却は限定APIとし、
   公開JSONの`sourceVerified`等から封印証拠を作る入口を設けない。
4. nativeが固定した実結果からのみ未署名v2 recordを生成する。外部の検査成功JSONを取込み、
   freshな公式確認や`CONTENT_INSPECTED`へ昇格させるAPIは作らない。assemblyはnative jobの原出力・
   全入力と実行fileのhash・元観測を再結合し、research receiptを受理しない。
5. 認定済み行だけを別の配布候補へ集め、未評価・失敗・未知・未対応行は研究台帳と結果reportへ残す。
   部分失敗のexit/countと全分母を保持し、配布候補ができても全target成功と表示しない。
   全失敗時は新しい成功索引を出さない。旧索引/原失敗を保持し、失効を延長して復活させない。
6. 既存v2 parser/quality検査に通るmanifest/GZipを新規出力へ作り、既存の明示配布署名入口へ渡す。
   署名・trust登録・鍵生成・GitHub送信をrun/buildへ含めない。通常アプリは既存署名索引経路を使う。

初回の予算は既存adapterの一payload 32MiB、256MiB空き容量と回線同意境界、
monitorの一回64要求/32MiB/600秒と最低24hを緩めない。要求/byte枠はHTTP全段を含む最小値で判定し、
失敗の転送量不明は予約最大値を課金する。32target等も実行batchの枠であり総対応上限ではない。
安定した未処理順序で次batchへ進め、期限・予算延期を成功から分ける。
nativeと共有するrequest/hostの待機を安全に調整できない場合は、既存同様HOLDとする。
初回の汎用形式追加を理由に、ASUS/Intel共有sourceのHOLDや既存管理者Taskを解除しない。

32MiB超の既取得local ZIP/CABは、既存`copyLocalDriverArchive`の128MiB上限と通常検査を使える。
ただしlocal検査だけではfresh公式導線・取得前条件の確認にならず、それらが不足すれば
`LOCAL_BYTES_INSPECTED_ROUTE_UNCONFIRMED`のまま配布取得候補へ昇格させない。
128MiB超・SFXの切出し・分割HTTP/Range・閉包再ZIPを、元容量制約や全原物検査の迂回に使わない。
既存の研究閉包導出は研究用途で保持する。大容量/複合形式対応は必要時に別工程へ登録する。

## 可搬性と短い保守手順

初期台帳・locator・profile・確認履歴・研究索引・未署名候補を閉じたsnapshotへ版付きで同梱する。
旧snapshotは維持し、新schemaの全file集合/hash/参照再計算をsetup validatorにも追加する。
driver本体、実端末inventory、cookie/token、署名秘密鍵、端末固有保護stateは含めない。
運用の移設は既存停止export/importと待機の最大値引継ぎを使い、新PCで検証して明示再開する。
data copy/importだけで通信・署名許可を発行しない。新規Task登録や既存TaskのAction変更は本Goalに含めない。

保守手順は「公式調査→台帳/locator/profileを追加→validate/plan→明示run-once/build→結果確認→
既存署名操作」の一経路とする。署名は別操作のままにし、source形式未対応なら理由と次工程を提示する。
既存v6 setupのTask契約はADR0394のままであり、この追加経路まで日次自動化済みと表示しない。

## 実装順と変更file

| 順序 | 主なfile | 完成させる差分 |
|---|---|---|
| 252b-1 | 新`collection-profiles.json`、新`scripts/collector_collection_profiles.py`と同test | 外部参照・厳密schema、plan、共有package・unknownの分類。研究台帳の契約は維持。 |
| 252b-2 | 新`src/platform/collector_registry_job.{h,cpp}`、`collector_inspection_acquisition.{h,cpp}`、`src/app/local_driver_collector_main.cpp`、`CMakeLists.txt` | 固定CLIから一jobを実取得/通常全INF検査し、公開metadataと原観測を結合。既存one-INF serializerは共通化して流用。 |
| 252b-3 | 新`scripts/collector_distribution_pipeline.py`、`registry_daily_monitor.py`、`collector_workspace.py`と各test | 同じ保護root/lock/admission・待機・予約、非通信build、決定的manifest/GZip、部分失敗report。固定Intel pipelineを変更しない。 |
| 252c | 新native job test、`tests/unit/signed_index_manifest_tests.cpp`、`signed_index_candidate_binding_tests.cpp`、pipeline test | 次節の固定受入を本物native codec/matcher/共通取得groupまで通す。 |
| 252d | `collector_locator_snapshot.py`、`packaging/collector/collector-setup.psm1`、`scripts/package-collector.ps1`、setupの固定file表/validatorと同test、公開source集合、台帳README/案内 | 新版snapshot・profile/module同梱、copy/import検証、短い追加手順。旧版拒否を維持。 |

上記の枝番は実装担当への分割案である。着手時に主担当が252b/c/dの下へ個別登録し、
新規公開schemaやsetup package版の採番を確定する。安全境界を単純化できない場合は変更を隠さず
次の小工程として登録し、Goalの範囲を研究JSON編集だけへ縮めない。

## 実装前に固定する有限受入条件

| ID | 固定入力と期待結果 |
|---|---|
| A1 | 架空3製品/2メーカー。A社2製品は一配布record/共通archiveを共有し、B社1製品は別record。外部データだけの追加でplan/run/buildへ反映。製品名の増加と取得/適合数を分ける。 |
| A2 | Aのarchiveに新しい架空公開IDと別INF名/Models節を含め、全INF通常検査結果からv2へ収録。Aは一回取得/検査、Bは独立処理。実ID・実端末inventoryをfixtureへ入れない。 |
| A3 | A1のproducer出力そのものを既存native manifest/asset/GZip/record/quality parserへ渡し、`lookupSignedIndexRecords`と既存DriverStore fakeの公開ID/ClassGUID照合へ接続。Aの2機器/Bの1機器が期待関係を持ち、Class不一致/未知IDは候補にしない。Pythonのshape assertだけでは不合格。 |
| A4 | Aの2機器について既存acquisition adapter/binding fakeを通し、共通packageが一取得targetとなること、新IDがcode列挙なしで候補へ進むこと、実INF/rank不成立ではbinding拒否を確認。実driver installは0。 |
| A5 | 次の有限runでBの更新を外部データへ反映。Aの待機/原成功と旧候補を保持し、同日再送0。33対象のfixtureは32等のbatch枠を越える分をDEFERREDとして残し、後続batchで処理可能。総対応上限としない。 |
| A6 | 未知形式、anchor不在/曖昧、非public宛先、不正hash/publisher/CAT、terms/条件未知、期限切れ、32MiB超、部分失敗、停止後UNKNOWN_OUTCOME、native共有host HOLDを固定負例に含める。失敗を分母から除かず、署名可候補へ混入させない。 |
| A7 | 新snapshotを別directoryへcopyして全file/参照/件数を再検証。破損・unknown field/schema・追加file・秘密混入を拒否。export/import後は元待機を保持し、copy/import/validateだけのHTTP/Task/鍵/署名/driver動作0。setupにも同じprofileが同梱される。 |

通信・実機・署名storeを使わないfake受入を先行する。source形式/共通native APIの既存実測と
新pipelineの接続試験は区別する。既取得archiveを使う実WinTrust再検査は利用可能な固定二配布までとし、
実行前にpath/hash/対象INFを主担当が固定し、古いbyte/観測時刻を新取得へ数えない。
新ネット通信、実鍵作成/署名、実Task操作、実GitHub公開、実driver導入を試験の暗黙前提にしない。
変更sourceの規約gate、影響targetのx64 Debug/Release、関係unit/Python/setup回帰と文書一致を受入する。
全850file hashや全研究1,718 recordの再検査は、この追加機構の初回受入の前提としない。

## 本設計で未確認のまま残す事項

本書の採用時点はsource読取りによる設計確認であり、実装・test・通信・新規対象追加は実施していない。
署名/公開・実端末適合/実導入の成功率、全メーカー対応、日次七回、別実機移設は本書で確認済みにしない。
既存snapshot・旧固定Intel pipelineの受入実績を、新しい汎用pipelineの受入へ読み替えない。
