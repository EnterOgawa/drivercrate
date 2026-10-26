# ADR 0387: 閉じたresource bootstrapと既存原点のローカル索引入口

- 決定日: 2026-10-20
- 状態: c2vで設計受入済み。c3aで実装し、c3tで単体EXE生成と有限な非通信検証を実施した。
  c3v/c4で有限なローカル受入、247d/rと242vで本PCへの実配置・一対象metadataの実収集と
  未署名ローカル索引生成を受入れた。初回prepare失敗とnative CWD不一致はADR0388/0389で修正した。
- 前提: ADR 0386、0353、0355、0357。既存v1〜v5とPublic publisherの意味は変更しない。

## 実装詳細の追補（2026-10-20、c3a）

c3v/c4は最終EXEの内容・改変拒否・配置/解除とdata保持・同梱runtime/明示確認についての有限受入である。
30familyの26有限入力成功/4部分variantを全variant合格へ換算しない。追加fault/競合検証は243qへ残し、
公開品質や本物の収集成功を意味しない。実運用先からの収集・観測に結合した索引生成は242で別に確認する。

9field configを維持し、prepareが`outputRoot/origin.json`へ原config hash・approval hashと
repository/stateの実directory identityをCREATE_NEWで保存する。onceは閉schemaと全値を再照合し、
欠損・改変・別実体を拒否する。この記録は端末内の保護操作metadataであり、移設seed・公開索引へ
含めず、新state・待機resetの許可にしない。

既存nativeの日次receipt出力はKnownFolder内のadmin保護`PrivateIndex229/operations/<job>`へ限定される。
この契約を変更せず、onceだけが既存operations内に新規`local-index-<GUID>`結果jobを作り、
原receiptを保存してFRESH_INPUTを照合する。prepareはoperationsを作らない。
jobは結果保存領域であり、収集stateRoot・日付・予算の新設ではない。
四fileはconfigの導入root内outputRootへ投影し、原receiptと予約hashを最後のresultへ結合する。
実装工程の試験はfixture/fakeで隔離し、実運用operationsへの作成・本物通信は次の実受入だけで行う。

c3t3では、v6かつOS KnownFolderから得た既定先だけ、欠損する`DriverCrate`親一階層を
全bundle検査・配置同意後に既存保護creatorで新規作成する。既存親は三信頼主体の保護または
継承ACLと実handleを検査し、reparse・通常file・不適格ACLを拒否する。ACL修復、任意custom親の
再帰作成、旧版の動作変更はしない。作成した親と部分配置は後段失敗でも保持する。
実user KnownFolderへの試験配置は本工程では行わず、同じhelperを新規fixtureで確認する。

c3t5ではstaging保存前の親固定を明示する。保護rootと固定相対名の各子directoryを
成分ごとにcreate-or-openし、非reparse・通常directory・実path・継承ACLを検査したhandleを
子process終了まで保持してから、次の成分またはfileのCREATE_NEW/flushへ進む。
保存後の全tree/hash再検査は追加防御であり、保存前検査の代用にしない。既存親のACL修復や
link先への保存は行わず、拒否時の既存byteと今回の部分fileを保持する。

## 決定

単体配布EXEはC++20/x64の小さなbootstrapへ、検証済みpackageの全fileを非圧縮の
`RT_RCDATA`として埋め込む方式とする。新しい第三者installer frameworkや展開libraryは追加しない。
通常のnative `DriverCrateCollectorSetup.exe`は内部payloadに含め、配置・解除・workspace操作の
state machineを再利用する。bootstrap自身はresource検査、安全なstaging、固定した内部setupの起動と
終了値の伝播だけを担当する。

生成時にresourceの固定ID・相対名・size・SHA-256と外側manifestのSHA-256をcompile時tableへ結合する。
bootstrap自身を内部packageのpayloadへ含めず、自己hashの循環を作らない。ZIPは内部・開発形式として
残せるが、利用者に展開やInstall.cmd、外部Python・開発環境の準備を要求しない。
生成には唯一のbuild/と既存の通常配布profileを使い、別build treeや信頼設定を作らない。

既存v5の69 payloadを変えず、新v6 `dc-collector-package-v6` /
`EXPLICIT_LOCAL_INDEX_WITH_DAILY_TOOLS`にだけ次の5 fileを追加する。

- `scripts/collector_local_index.py`（新規の明示ローカル入口）
- `scripts/daily_index_pipeline.py`
- `scripts/prepare_daily_index_config.py`
- `scripts/project_collected_native_index.py`
- `scripts/register_daily_index_task.ps1`

v6は74 payload、外側manifestを含め75 fileの予定である。既存`collector_registry.py`を重複追加しない。
初期snapshot-v4の8 JSONと固定CPython 3.13.16 x64の全34 file・metadata・全文license/noticeを保持する。
v6はv5のcached-only検証、保護配置・workspace・正式原点の境界を引き継ぎ、内容を検査する前に
同梱Pythonやsetup以外のpayloadを実行しない。

## stagingと配置

OSのKnownFolderで求めたLocalAppData直下の専用一意名stagingを、既存の保護root作成処理で
新規作成する。通常file・固定drive・非reparseの全祖先と実handleを検査し、user/SYSTEM/Administratorsの
既存保護契約を再利用する。入力側のfile一覧やcommandは採用しない。
固定ID集合、言語、重複、各size/hash、総量を検査し、固定相対名だけをCREATE_NEWで保存する。
一file64 MiB、全payload64 MiB、entry128を初期上限とし、超過時は拒否して別工程へ戻す。

全fileの再照合後だけ絶対pathの内部setupを起動し、既存`--check-package`と`--install`へ接続する。
任意command、PATH探索、shell、暗黙昇格を追加しない。子が終了するまで検証済み実fileとdirectoryを
保持し、成功・拒否・取消し・timeoutを区別する。部分stagingと部分配置は既存どおり自動rollbackしない。
初期実装は成功後もstagingを保持し、その事実を診断resultへ記録する。将来の整理も固定fileと
空directoryの非再帰処理に限り、未知fileを残す。整理機能を本Goalの実装前提にしない。

配置先は既存のLocalAppData/DriverCrate/Collectorを既定とし、既存先上書き拒否を維持する。
binary rootの新規配置を既存data rootの新規初期化に結び付けない。解除は既存どおり設定・seed・work・
未知fileと自己setup等を保持し、ProgramData側の運用data、Task、鍵・credentialを扱わない。

## 本Goalで必要な明示ローカル入口

公開pipelineの`run`/`run-public`は現在、収集から署名・GitHub反映までを一体で扱い、
ローカルだけの完了入口を持たない。fake remoteの注入を実運用modeへ転用せず、別の明示入口を追加する。

CLIは導入済みv6 setupの次の二つとする。契約は本書、再現入口は同梱local-index試験を正本とする。

```text
DriverCrateCollectorSetup.exe --local-index-prepare NEW_CONFIG EXISTING_METADATA_SCOPE --confirm-existing-origin
DriverCrateCollectorSetup.exe --local-index-once CONFIG --confirm-local-collection
```

prepareは非通信である。このPCの受入ではOS KnownFolder内PrivateIndex229/controlの既存保護approvalを
検証し、そこに記録された同じstateRoot・collector manifestと、既存metadata-only scopeをpinする。
configに任意の新stateRoot、URL、script、署名鍵、publisher認証を指定させない。
新PCの未設定状態は`LOCAL_ORIGIN_NOT_CONFIGURED`として残し、空storeで旧待機を回避しない。

onceはnativeの既存`--daily-evidence`を一回呼び、同じstateRootの全契約を跨ぐdue・要確認・排他と
単調な日次世代を正本にする。親がnative writer leaseを保持したまま同じrootの子を起動しない。
新しい実200または実304のreceiptだけを、既存`project_daily`で未署名索引・gzip・raw manifest・報告へ
投影する。実本文hash・原観測時刻・receipt鎖・native予約世代へ結合し、研究seedの再生成とは別に扱う。
`HOLD`、`NO_NETWORK`、失敗、未知、部分保存を成功にしない。receiptのJST run日をUTC暦日へ読み替えない。
任意の世代番号指定、旧head reset、失効済み署名索引の延命は行わない。

同梱固定runtimeを`-I -B -S`と固定bootstrapで起動し、検証済みのstdlib/runtime/scriptsだけを参照する。
PATH、user site、外部Python、pip、downloadで補わない。ローカル入口はTask登録・Enable、同意の代行、
署名tool/鍵、gh、GitHub API/公開を呼ばない。最新の日次scriptとnative readback機能の同梱は行うが、
既存Public履歴移行・Task切替の完成を単体EXE生成の前提にしない。

## 同意・予算・受入

setupの配置確認と、登録済対象への一回通信確認を分ける。既存のdriver規約同意・取得grantや
driver導入許可をmetadata収集の同意で代用しない。最終Goalは本PCへの単体EXE配置と、配置済み本体からの
本物の登録済対象の収集・観測に結合したローカル索引生成であり、offline/fake/HOLDだけでは達成しない。

新ローカル操作の有限予算を実行前に固定する。既存nativeの全待機・失敗・日予算、旧操作の
90 calls/846.4786425890825秒と元日程を残し、新操作を旧Public再開の予算resetとして使わない。
Public再開・署名・公開・実driver導入はそれぞれ元の別承認境界に残す。
全1,718 record、全SDIO、七日実運用、別PC移設、対応数拡大を本Goalの完了前提へ追加しない。

公開する契約は本書とADR0388/0389、具体的な再現入口は`scripts/package-collector-installer.ps1`、
`scripts/test-collector-installer.ps1`、`scripts/test_collector_local_index.py`と関連native setup unitとする。
各実行の原pin・固定case・実測と未実行variantは公開集合の外へ保持する。私有解析fileをbuild入力にしない。
fixtureでの配置とlocal fake投影を実運用の成功へ換算せず、実配置・本物通信の結果は後続242へ残す。
