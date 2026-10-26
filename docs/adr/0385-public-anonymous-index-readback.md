# ADR 0385: Public索引の匿名readbackを公開成功の必要条件にする

- 状態: 採用。実装・有限fake検証中。実匿名通信、保護配置、旧runtime移行、Task、自動開始、実公開は未受入。
- 決定日: 2026-10-20
- 対象工程: G13-I7r231h15s11b3b / b3bt。主担当確認b3bvは別工程。

## 決定

受入済みの閉じた通信・原byte照合設計を採用する。公開するwire契約を以下の本文へ保持し、
同梱のsigned-index native unitと`test_daily_index_pipeline.py`を再現入口とする。
設計だけでは利用可能・検証済みとしない。各実行の固定caseと原結果は公開集合の外へ保存する。

既存Collectorに正確な5 argvの閉mode
`--public-index-readback EXPECTED_ENVELOPE EXPECTED_GZIP REMAINING_MILLISECONDS`を追加する。
残時間はASCII十進1..90000。URL・trust・出力先等の引数を許さない。同じ保護job内の
`.acquisition.manifest.json`と`.acquisition.index.json.gz`を既存同handleのowner/DACL・全祖先・
reparse・hardlink検査で読み、期待envelope上限96KiB、gzip上限16MiBとする。

新platform glueは既存OfficialHttpClientのprivate typed roleとcompiled public trust、既存の
manifest署名・gzip/hash・展開・records codecを再利用する。store/cache/stateへの書込は行わない。
固定raw currentと、認証tagから導出した固定repositoryのimmutable manifest/gzipを無条件GETし、
三resourceの原byte完全一致を要求する。HTTPS/443・公開DNS・exact host・redirect・MIME・
応答上限・自動logon HIGH・cookie禁止等の共通境界を維持し、credential/helperを使わない。
通常appの5send/90秒を維持し、monitorだけ最大9send・共有min(90秒,親残時間)を持つ。
成功本文上限16973824byte、拒否probe込み16973825byte。期限・UTC後退・不明は拒否する。

native stdoutは後述の順序固定10field・三role各7fieldのcanonical原byteだけとする。
Public annotationはVERIFIED/PENDINGの13field、UNKNOWNの14field、worker7/verifier5fieldとし、
元config/claim/generation/bundle/commit・実pin・同journalへ結合する。実child exitはDWORDの
uint32または渡されたsigned原値を保持し、int32への狭め・成功値への補完を行わない。

Public Publisherは匿名callback欠損をpublish作用前拒否し、両PUBLISHED経路でworkerと親の
既存acquisition_verifierの成功を必要とする。CAS後匿名失敗は既知commitと元署名束・journalを
保持したUNKNOWNであり、success/cycleを確定しない。同prefix/config/budgetの完全束だけで
readback-only再観測でき、再収集・再署名・upload・CASは行わない。未完intentは元予約全時間と
最大9send不明を保持し、一般retry・日/予算reset・v3 SCRIPT_PIN例外を追加しない。

匿名のない旧cycle/successはimmutableな当時の認証API成功として保持し、現在の匿名観測は
sourceCycleSha256付きの別terminalへ保存する。未解決の閉PENDING/UNKNOWNは次dayを止める。
真の旧runtime/configの移行は未実装として残す。root9/start10/cycle13/summary6・九files/六inputs・
4 MODULE_NAMESとPrivateの既存条件を維持する。

## 公開する閉wire契約

欠損・余剰・重複field、bool-as-int、浮動小数、NaN、BOM、末尾byteを拒否する。
SHAは小文字64hex、commitは小文字40hex、UTCはASCII `YYYY-MM-DDTHH:MM:SSZ`の20byteで実在秒とする。
native stdoutはUTF-8 object一個、非空64KiB以下、改行/空白/説明行なしで次の順序を要求する。
stderrにURL/header/本文/任意例外文を出さない。

| field（native stdout順序固定） | 型・境界 |
| --- | --- |
| schema | `dc-public-index-readback-result-v1`。 |
| outcome | `VERIFIED`又は`UNKNOWN`。 |
| startedAtUtc | UTC又は時計取得不能時のnull。VERIFIEDは非null。 |
| completedAtUtc | UTC又は時計取得不能時のnull。VERIFIEDは非null、開始以上。 |
| elapsedMilliseconds | uint64又は単調時計不明時のnull。VERIFIEDは非null、親予約ms以下かつ90000以下。clampしない。 |
| resources | CURRENT_ENVELOPE、IMMUTABLE_ENVELOPE、IMMUTABLE_GZIPの三個を固定順。 |
| sends | 整数0..9、resource合計と一致。 |
| receivedBytes | 整数0..16973825、拒否probeを含むresource合計と一致。 |
| nativeError | 元HRESULT bit patternのuint32。VERIFIEDは0、UNKNOWNは非0。 |
| failureStage | NONE/ARGUMENTS/INPUT/TRUST/TIME/CURRENT/MANIFEST_ASSET/GZIP_ASSET/CONTENT/CANCELLED。NONEはVERIFIEDだけ。 |

各resourceは`role,state,httpStatus,sends,receivedBytes,sha256,nativeError`の順序固定7field。
roleは上記三値、stateはNOT_STARTED/COMPLETE/FAILED、httpStatusは未観測0又は100..599。
sendsはcurrent 0..1、各asset 0..4。bytesはcurrent/manifest 0..98305、gzip 0..16777217。
COMPLETEだけ非null SHAで、HTTP200・非空・期待原byteのsize/SHA一致を必要とする。
他のstateはSHA null。nativeErrorはNOT_STARTED/COMPLETEなら0、FAILEDは非0。
NOT_STARTEDはstatus/sends/bytesも全0。最後の署名/content検査が拒否した場合は三resourceが
COMPLETEでも全体UNKNOWNである。HTTP200や三hash一致だけで成功へ昇格しない。

専用native writerは固定field順、最短unsigned十進、固定enum/SHA、検査済みASCII UTCとliteral nullだけを出力する。
外部の任意文字列をserializerへ渡さない。Pythonは重複を拒否してparseした後、既知field順へ明示再構築し、
canonical原byteをstdoutと完全一致させる。入力のJSON順序/整数表記の差を正規化して証拠を書換えない。

Public annotationの共通schemaは`dc-public-anonymous-readback-v1`。閉13fieldは次の通りで、
UNKNOWNだけ末尾の論理fieldとして`failure`を加えた14fieldとする。

```text
schema,status,configSha256,signingClaimSha256,generation,commit,tag,
envelopeSha256,gzipSha256,sourceCycleSha256,worker,verifier,verifiedAtUtc
```

statusはVERIFIED/PENDING/UNKNOWN。四つのconfig/claim/envelope/gzip hashは必須SHA。
generationはboolでない整数1..9007199254740991、commit/tagは認証remoteと元manifestの固定値へ照合する。
sourceCycleSha256は原cycle SHA、新cycle保存前だけnull。保存には既存の共有canonical契約を用いる。

| status | worker/verifier | verifiedAtUtc | failure |
| --- | --- | --- | --- |
| VERIFIED | 両方非null・実exit0・完全report/journal照合。 | 非null UTCで現在fresh。 | field自体を許さない。 |
| PENDING | 両方null。 | null。 | field自体を許さない。 |
| UNKNOWN | 未起動ならnull、起動後は閉じた原結果。 | null。 | 必須のstage/code二field。 |

workerの7fieldは`ordinal,intentSha256,completeSha256,exeSha256,childExitCode,stdoutSha256,report`。
verifierは先頭五field。ordinalは整数0..95、intent/exe hashは非null SHA。
complete hashは未完intentだけnull、childExitCodeは同handleで確定した元整数-2147483648..4294967295、
未確定だけnullとする。WindowsのDWORDをint32へ狭めず、符号付き原値も変換せず保持する。
stdout hashは実取得した原byteのSHA、未取得だけnull。reportは上記canonical検査成立時のobject、
parse不能/欠損はnull。VERIFIEDは全field非null、worker report.outcome=VERIFIEDと実exit0を要求する。
worker<verifierの別ordinal、同PublicOperationBudget/contextの実intent/complete hash鎖とfinal summaryの
tail以前の存在を照合する。exe hashはconfigが認証したCollector/signerの実pinと一致させる。
config/claim/generation/envelope/gzip/tag/commitは同receipt・六raw・元取得束へ突き合わせる。

failure.stageはBEFORE_WORKER/WORKER/VERIFIER/RESULT_SAVE、codeはTRANSPORT/HTTP/PARTIAL/
BYTE_MISMATCH/SIGNATURE/CONTENT/EXPIRED/TIME_UNKNOWN/CANCELLED/BUDGET/PROCESS_UNKNOWN/REPORT_INVALID。
任意の例外textを保存しない。PENDINGは認証commit確認後・worker intent前だけのmarkerで、次day資格を持たない。
起動/timeoutで原stdoutを読めなければreport/sendsを合成せず、未完intentと最大9send/予約全時間を保持する。
原completeがある非0 childは限定readback-only対象になり得るが、旧失敗は削除しない。
実budget childの同handle exit0、canonical原stdout、pin済みnativeによる実byte比較、同journalと
直後の既存acquisition_verifier exit0/六raw監査を全て要求し、自己申告boolを公開資格へ変換しない。

## 固定検証分母と予算（当初の実装工程）

新Pythonは6method/A01..A24の24 named条件、nativeはN01..N28の28 named条件を固定する。
旧108method（9/157明示subTest＋99/500明示subTest）とwork補足2/2は別集計する。
未実施・skip・guard発火を合格へ数えず、原失敗・修正理由・最終同pin証拠を保持する。
managed会計の予定値は通常68(native18/GH50)、開始69、preflight後57、readback18、
HOLD13、二HOLD＋通常94で、HTTP9sendとは異なる単位としてfixture traceで検証する。

当初実装の計画は固定100分・保存5分・延長0、唯一build/のD/R全target直列累積1200秒・parallel16、
native境界累積600秒/12回、Python累積1800秒/単process300秒直列・import前外部遮断、変更品質300秒を
守る。通常15pinの前後、cache/presets/trust不変と生成像の差を記録する。全I/Oを計測できなければ
実測値はnullとし、compiler内部I/Oを測定済みとしない。実HTTP/API/gh/remote、Task、保護配置、
credential/鍵query、実署名/収集、app/driver/installer/restore/SCM、stage/commit/push/tag/公開は0。

## 残る限界

有限fakeの合格は実匿名通信・日次運用・公開品質・全機器対応の受入ではない。変更後のCollectorと
pipelineは新pinを必要とし、旧native/build資格をそのまま継承しない。実保護配置、一般旧v3移行、
Disabled Task再bind、自動開始、日次運用、旧asset復帰、実公開は後続の明示承認と受入を要する。
