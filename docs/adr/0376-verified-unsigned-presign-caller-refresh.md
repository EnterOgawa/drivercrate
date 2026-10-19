# ADR 0376: 検証済み四原fileを保持する一回限りの署名前caller更新

日付: 2026-10-19
状態: 採用。sourceと人工回帰だけの工程。実配置・実prepare/run・署名・Private反映は別工程。

## 決定と対象

ADR 0375の既存`--continue-presign-config`に、既知の四原file保持状態からの
一回限りのcaller更新を追加する。新しいCLI modeや任意chainは作らない。
通常の二原file開始と完全束再利用、および通常入口の四file partial拒否を維持する。
対象は旧preSignのmarker後、body/release/inspection/scriptがあり、review保存前に
`DISTRIBUTION_UTC_SECONDS`で停止した、未署名の既知状態だけである。

`preSignContinuation.schema`をdiscriminatorとする。既存
`dc-daily-presign-continuation-v1`のfield集合・意味は変更しない。追加する
`dc-daily-presign-verified-unsigned-refresh-v1`は下表のfieldだけを必須とし、
欠損・余分・型違い・二度目refreshを拒否する。

| field | 型と拘束 |
| --- | --- |
| schema | 上記追加schemaの文字列完全一致 |
| configFile / configSha256 | 直前の旧preSign v1全canonical raw。旧codeRepairあり、refreshなし |
| markerFile / markerSha256 | 元bucketの既存preSign marker全raw。旧config hashへ結合 |
| bodySha256 / releaseSha256 / inspectionSha256 / scriptSha256 | receipt由来の固定名四file全raw。pathを入力しない |
| failureTerminalFile / failureTerminalSha256 | 同bucketのFAILED/DISTRIBUTION_UTC_SECONDS原terminal全raw |
| budgetWitnessFile / budgetWitnessSha256 | 保護controlに保存する元BUDGET-CARRY全raw。下記の閉集合 |
| priorNativeCalls / priorElapsedSeconds | witnessの累積保守上界と完全一致。最低15call/144.72357580207824秒 |
| preparationNativeCalls / preparationElapsedSeconds | 新prepareの2callと実測秒。実行時に同96call/1800秒から控除 |

各SHAは小文字hex64桁。pathは通常の保護path/ACL/容量検査を通す。
budget witnessの実field集合は`utc, priorNativeCalls, priorElapsedSeconds,
actualPrepareNativeCalls, actualPrepareMeasuredSeconds, prepareOuterObservedSeconds,
runActualMeasuredSeconds, runProcessCountDirectlyObserved, runPathNativeCallUpperBound,
runWallSecondsConservativeUpperBound, runWallUpperBoundBasis,
nativeCallsIncludingCarryUpperBound, elapsedSecondsIncludingCarryConservativeUpperBound,
globalLimits, qualification`である。観測欠損二fieldはnull、元handle終端はfalseを要求する。
run上界4call、元prepare2callと旧carryの加算を確認し、wall区間以上の保守秒と加算を確認する。
これは元runのprocess数・実測時間・終端を復元した証拠ではない。

## 旧版認証と不変入力

旧configのmodule/native pinは、それぞれ旧宣言versionの実byteで検証する。
productionのglobal `__file__`を書き換えず、内部の明示旧版contextを使用する。
旧preSign→旧codeRepair→元configの既存有限連鎖を全て検証し、元start/receipt/修復marker/
preSign marker/元process証拠も保持する。旧schemaを現在版として検証しない。
旧版contextでの四file許可はこの追加遷移の認証専用であり、通常旧入口に適用しない。

pipeline/preparer pin、同byteの新version配置path、追加記述子と新prepare使用分以外の
意味入力を変えない。projection/registry/native hash、scope全byte、manifest、originalInputs、
archive hash/size/selectedInf、key/fingerprint、state/output、smoke/first/window、fence、
receipt/day/notBeforeとglobal claim名は全て維持する。元codeRepairは新configでも完全一致する。
job bucketは認証済み元startから導出し、UTC dayの一致・原window・期限を別々に要求する。

## 遷移・再利用・停止

同operation lockで旧四fileと全pinを再検証し、prepareとrunでFRESH_INPUTを省略しない。
新markerの前、およびreview欠損中は、対象世代のglobal claim、unsigned二file、envelope、
success、署名結果witness、CAS意図の全てが不在でなければ拒否する。
一般catchの`UNKNOWN_NO_RE_SIGN`は実署名呼出しの証拠でも再署名許可でもない。

runは旧markerを変更せず、新config/旧config/旧marker/receipt/四pin/witness/dayに結合する
`.acquisition.verified-unsigned-refresh.json`を一つだけ保存する。四原fileは上書きしない。
native parse/再検査/script取得を繰り返さず、唯一欠損のreviewだけを既存
`make_pinned_static_terms_revalidation`が実時刻で生成する。原manual/content/script/receiptの
観測秒と期限は維持する。既存投影と六入力auditが通った後だけ`write_new`でreviewを保存する。
完全束は保存byteを再利用し、publicationを再生成せず、既存global claim-before-sign、
一回署名、current/history/readback/CAS検証へ接続する。claimのみ・未知署名は停止する。

## 検証と制限

実関数を人工file/native/remoteへ接続する200/304・非0小数秒・完全束再利用と、各pin、
意味入力、partial/extra、旧/現code、二度目refresh、未知署名/CAS、day/expiry/window/head、
lock/予算縮小の拒否を追加する。既存128test bodyと期待値は維持する。
外部観測helperは作業証拠内だけでPopen原handleを即保持し、要求argv/cwd/raw先と
OS観測値を別に保存する。optional PEB照会の失敗は同handle待機を妨げない。
元h14r8の観測欠損は修正済み履歴へ変換しない。

この変更は実native・保護書込み・通信・署名・Git・Task・実導入を行わず、
実内容1/1、pipeline0/1、Private取得用索引0、端末候補数null、対応増0を維持する。
