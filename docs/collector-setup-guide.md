# DriverCrate Collector セットアップ案内

CollectorはWindows x64の収集PC用で、通常の`DriverCrate.exe`とは別成果物です。
製品版は0.1.1です。この版の自作EXEはコード署名なしです。
通常のソースビルドは証明書不要です。現行仕様だけを生成・受理し、旧版client/setup/dataの互換や
自動移行は提供しません。10月25日の配布候補はローカル検査を終えています。
公開前の最終ソース・文書・配布物の照合と公開は未完了です。
同日のv7単体セットアップで、通常配置時のTask登録・有効読戻し、停止済み同一workspaceの切替、
同一dataのimport・workspace検証、通常解除・所有Task不存在・data保持を確認しました。
Taskの実行・自然日次・七日・再起動・別PCの実受入は未確認です。過去の成功を変更後のbyteへ継承しません。

## 現行packageと生成

`dc-collector-package-v7` / `EXPLICIT_DISTRIBUTION_DATA_DAILY`、配置receipt-v3だけを使います。
v1～v6 package、receipt-v1/v2、旧local-index setup入口は拒否します。既存dataは変更しません。
唯一の通常buildから、次の入力で新規packageを生成します。既存出力を上書きしません。

```powershell
./scripts/package-collector.ps1 -RegistrySnapshot RESEARCH -PythonRuntimeArchive PYTHON_ZIP `
  -PythonExecutable PYTHON -DistributionDataBundle DATA -OutputDirectory NEW_OUTPUT
./scripts/package-collector-installer.ps1 -PackageDirectory PACKAGE -OutputDirectory NEW_OUTPUT
```

RESEARCHはlocatorを含むsnapshot-v4、DATAは検証済みdistribution-data-v1です。
固定CPython 3.13.16 x64原34file、license、元hashとcached-only PSF署名を検査します。
初期packageは研究seed、収集条件とWindows 11向け2 recordの参考索引を含みます。
参考索引はbootstrap dataで、元観測・producer・原期限2026-11-02 09:28:33 UTCを保持します。
参考dataのcopy/importは通信許可やnative authorityを発行しません。
生成・配置・data copy/import/validateだけで即時収集・driver導入・署名・公開を始めません。

## data追加と汎用日次

同形式の製品追加はdataだけで行い、アプリ/collector/setupやTaskを作り直しません。
現行v7は基本77payload/manifest込み78file、参考索引つきは83payload/84fileです。旧local-index専用5toolは同梱しません。
初期dataには127メーカー/6,584製品参照/1,718研究recordの台帳、390 locator、研究索引と既存1 record用の
collection profileを含みます。profileは既登録Prolificの七製品参照を扱う取得条件です。研究1,718recordを
収集・内容検査済みへ昇格しません。公式導線と確認根拠は従来どおり手動保守し、新しいsite形式は別途実装します。
通常アプリの取得・照合・表示は共通経路のままです。

保守担当は外部台帳/locatorを修正して既存の`collector_registry.py validate`と
`collector_public_locators.py --registry ... --locators ...`で検証し、
`collector_collection_profiles.py upsert`で参照hashを計算します。
`collector_distribution_data.py build REGISTRY LOCATORS PROFILES NEW_BUNDLE`で可搬dataを作り、
`verify NEW_BUNDLE`で全原byte/hash・schema・参照・研究索引を検証します。索引の手編集は不要です。
以下は配置済みsetupの固定操作で、ROOTは保護workspace、DATAは新bundleです。

1. 初回は`--workspace-initialize ROOT --confirm-offline`を実行します。seedをactive初期世代へ取り込みます。
   `--initialize-distribution-origins ROOT NATIVE_ROOT ROOT\monitor --confirm-offline`で空原点を非通信登録します。
   旧原点がある場合は停止移設手順を使い、履歴を空rootへ置き換えません。
2. 新規追加は`--import-data ROOT DATA --confirm-offline`で反映します。既存製品の意味が変わる更新は
   次の二段階手順を使います。data hashはpackage hashと別で、
   active pointerだけを原子的に切り替え、旧世代/旧候補・元観測時刻・24時間待機と課金を保持します。
3. 初回だけ`--enable-distribution-daily ROOT --confirm-daily-inspection-download`へ明示同意します。
   登録static ZIP/CABの検査取得・全INF検査を毎日17時、32job/batch・64要求/32MiB/600秒・
   最低24時間待機で行う別所有Taskを登録し、有効readbackまで確認します。通常installの既存native15時Taskは
   維持します。writer競合は当回拒否して次日まで待ち、即時retryしません。署名/公開は日次へ含めません。

既存製品の版・取得先・実行条件などが変わる場合は、次の順序が必要です。OLDは現在のactiveから
`export-active`した旧bundle、NEWは保守toolで更新した台帳/locator、EDITSは更新profileの全確認入力です。
製品/record/profileのidentityを維持し、同じfileを上書きせず新しいrevisionと出力先を指定します。

1. `collector_collection_profiles.py upsert`へNEWの`--registry`/`--locators`、OLDの`--profiles`と
   `--previous-registry`/`--previous-locators`、`--edits EDITS`、新しい`--revision`/`--as-of`/`--output`を渡します。
   同じ呼出しで`--review-profile`を指定しても意味変更は`REVIEW_REQUIRED`です。
2. NEWの台帳/locatorとこの確認待ちprofileで`build`/`verify`したPENDING bundleを、
   **先に**`--import-data ROOT PENDING --confirm-offline`でactiveへ取り込みます。
   この段階の更新対象は取得保留です。旧activeから意味変更後の`CURRENT`を直接importすると
   `DATA_B1_REVIEW_REQUIRED`で拒否され、旧active/候補/待機は保持されます。
3. 公式導線、規約、前提条件と根拠を手動確認し、別の`upsert`へPENDING内の台帳/locator/profile、
   全確認入力の`--edits`、対象の`--review-profile PROFILE_ID`、別のrevision/出力先を渡します。
   ここで意味や取得条件をさらに変更した場合は再び確認待ちとなり、手順1～2へ戻ります。
4. 出力が`CURRENT`になったことを`plan`で確認し、同じ台帳/locatorとreview後profileで別のCURRENT bundleを
   `build`/`verify`して、`--import-data ROOT CURRENT --confirm-offline`を実行します。
   次の許可済み日次または明示一回取得が、同じ保護caller/run/buildで通常のarchive/全INF検査と索引生成を行います。

import/reviewは24時間待機や旧URLの課金を消しません。同じURLは元の期限まで待ちます。
研究PAGE観測の日時だけでは初回収集を待機させず、実通信の24時間待機は保護されたrequest/hostの
試行・nextDueAtを正本にします。研究の原hash/時点、将来時刻拒否と同runの公式PAGE再確認は保持します。
手動で別の公式PAGE/PAYLOADを確認して登録した場合も旧URLの履歴は保持します。時計や保護stateの編集は不要です。
hashは各toolが計算し、生成索引の手編集、アプリ/collector/setupの再build、Taskの再登録は必要ありません。

Taskの唯一Actionは自己導入先の`DriverCrateCollectorSetup.exe --distribution-daily`です。
同意receiptを実package/workspace identityへ結合し、同じbyteを別rootへcopyしても許可しません。
copy/import/validateと初回原点登録ではTask・通信許可を作りません。手動一回取得は
`--distribution-run-once ROOT --confirm-inspection-download`です。同日待機・全HOLD・一部失敗を
完全成功にせず、元理由と既存候補を保持します。
取得できない対象は後日の切り分けへ残し、他の成功と未失効の前回成功を利用します。
全失敗や全HOLDで前回の候補・公開assetを空の新世代へ置き換えません。
件数・失敗理由・数値結果・開始/終了/次回試行下限は既存の保護されたrun/resultと待機履歴へ残します。
私有の診断本文を公開assetや一般ログへ入れないでください。

今後の新device・メーカー・製品は[ADR0402](adr/0402-partial-collection-and-release-priority.md)と
[台帳READMEの追加チェックリスト](../data/collector-registry/README.md#新規対象の追加チェックリスト)に従い、台帳登録と実取得/内容検査の成功を分けます。
取得不可・一時障害・HOLDは理由・最終試行・次回試行下限を記録し、許可済みの次回試行または手動reviewへ送り、
他対象と公開準備を進めます。未確認の登録を利用可能driver数へ数えず、全対象成功や全機器網羅を公開要件にしません。
通常の追加は手動調査と外部JSON台帳/locator/profileの保守で行い、新しいsite形式のparserだけを別作業にします。
メーカー固有のアプリ分岐や製品AI、自動調査は追加しません。週内成功は目標であり、成功保証・期限延長・HOLD自動解除ではありません。

移設は元運用を停止し、`--workspace-export ROOT EXPORT --confirm-source-stopped`で待機snapshotを作ります。
保守toolの`collector_distribution_data.py export-active ROOT NEW_DATA`でactiveと公開参照成果物を別bundleへまとめ、
両方をfile copyします。新PCではv7 setup配置後に`--workspace-import NEW_ROOT EXPORT\snapshot --confirm-source-stopped`、
`--import-data NEW_ROOT NEW_DATA --confirm-offline`、新原点の非通信登録を行い、最後に日次opt-inを明示します。
未確定予約は最大課金、host review/nextDue・旧成功参照・世代/cursorを保持し、private run/permitや
credential/署名秘密鍵/driver本体は移設しません。公開参照は元hash/producer/origin/期限を保持する参考成果物で、
新原点の実検査証拠として復元しません。受理するsnapshotは現行export-v1/v3だけです。旧export-v2はschemaで拒否し、自動変換しません。
v7 uninstallは両所有Taskの正常不存在を確認後に管理programを削除し、dataを保持します。
配布用の単体EXEにもAuthenticode署名を検証します。別実機・自然日次・実導入の成功は未確認です。

## 候補確定・手動署名と公開

通常distribution日次は収集・内容検査・未署名候補生成までです。
収集は原則日次、週内に一回程度の成功を運用目標とし、署名索引の更新は手動操作です。
全取得先の同時成功や七日運用を公開準備の前提にはしません。新規配布scopeは`projectionPolicyRevision=2`で、
fresh観測からのrecord期間は8日です。発行観測は24h未満を要求し、実HTTPの24h待機とは分けます。
汎用は内容/PAGE/独立根拠の原時刻からの期限minを使い、独立根拠も明示再確認が必要です。
prepare/sign/publishでは、実現在で全原recordとmanifestが有効であることを要求します。
残存期間が七日以下でも原期限内だけ扱い、新規署名前・公開前・CAS直前も再確認します。
原期限に達した場合は拒否します。元recordや期限を手編集せず、新発行には必要なfresh観測と根拠確認を行ってください。
旧scope1の新発行/自動変換は行いません。旧原recordは原期限のまま保持し、merge/rebaseでも延長しません。
既存native収集のscope準備では、旧config/receipt/署名assetの原hash・同root・世代を保ち、
既存の署名floor専用検証で旧assetを世代下限だけへ結びます。旧recordの現codec再生成や
現在利用許可への変換は行わず、新候補の全record・原期限・内容検査は従来どおり必要です。

保守担当の明示操作として、既存の
`daily_index_pipeline.py prepare-candidate`と`sign-candidate`を接続しています。
保護された公開設定、明示pinした成功入力、認証したPublic世代、現在native receiptと保存済みclaimを
再確認し、原record/hash/個別期限を保持して既存native署名器へ一回だけ渡します。
期限切れPublicは世代下限だけに使い、不明なheadを初回0へ戻しません。署名後の不確定結果は保持し、
保存済みの同envelopeを再検証する場合も再署名しません。両操作はGitHubへのwrite/uploadを行いません。
この接続は内部試験で確認した範囲です。実運用下限・production署名/公開の新しい実受入は未確認です。
署名秘密鍵はseedや移設snapshotへ含めません。

現行の明示`publish-candidate`は、この保護設定・同outputRoot/lock/claimを再利用し、保存済みの
原署名束だけを既存Publisherへ渡します。収集・再署名を開始せず、immutable二assetの原byte検査、
expected-head CAS、匿名原byte読戻しを必須にします。同じ出力が既にcurrentなら新しいwriteをせず
読戻します。CAS意図後の不確定再開もreadback-onlyで、元UNKNOWN/非zero/失敗を上書きしません。
公開操作は本人の別の明示承認後だけ実行します。本番の新しい公開成功は未確認です。

native日次候補を単独または汎用候補と併せて選ぶ場合、現在configのscopeと明示reservationに一致する
六原入力を`dc-candidate-native-inputs-v1`の`inputs`へ指定します。fieldは
`scope/evidence/release/inspection/review/script`の六件で、各値は保護された絶対`file`と原`sha256`です。
document自体も`--native-inputs FILE --native-inputs-sha256 HASH`でpinし、prepare/sign/publishの
全三操作へ同じ組を渡します。既存の非通信projectorで投影し、原record/base64/hash/sourceと個別期限を
保持します。native receiptだけを渡してもIntel recordは含まれません。期限切れPublic recordも足しません。

手動操作は三段階とも、共通の`CONFIG`、`--reservation-receipt RECEIPT`とその
`--reservation-receipt-sha256 HASH`を必須とします。この原receiptとnative headは
`LEGACY_FENCE`として世代下限へ使い、native内容の収集成功とは別に検査します。
汎用だけの発行にも原予約照合は必要ですが、新しいnative取得成功は必要ありません。

内容の入力は次の一系統以上を明示し、全三操作へ同じ選択とpinを渡します（[ADR0403](adr/0403-independent-producer-publication-input.md)）。

- 汎用候補のみ: `--candidate-head HEAD --candidate-head-sha256 HASH`。
  原head、build-commit、validation、閉出力を検査し、native六入力は指定しません。
- native候補のみ: `--native-inputs FILE --native-inputs-sha256 HASH`。
  上記の六原入力を検査し、汎用headの指定や生成は必要ありません。
- 両方: 上記二組を併記します。原wrapper/sourceを保持し、期限は全原recordのminにします。

どちらも未指定、不完全なfile/hash対、指定した入力の不正・失効は拒否します。
失敗した入力を黙って除外したり、別系統の成功で補完したりしません。
汎用未指定のclaimは`candidateHeadSha256`と`candidateOutputs`が同時nullとなり、
`nativeInputsSha256`を必須にします。原claim/世代/不確定意図は同じ履歴に保持します。
選択を変更する場合は元claimへ差し替えず、改めてprepareします。段階ごとの追加pinは次のとおりです。

- `prepare-candidate`: `--head-profile HISTORY_FLOOR`。既存Publicの署名/原asset/世代だけを認証し、
  record互換や現在の取得receiptへ昇格しません。不明/欠損/未来/誤署名は0世代へ補完せず拒否します。
- `sign-candidate`: `--claim CLAIM --claim-sha256 HASH --fingerprint PIN`。全原入力/期限/下限を再確認し、
  既存native signerを一回だけ呼びます。公開は行いません。
- `publish-candidate`: 同じclaim/fingerprintに`--envelope-sha256 HASH`を加えます。保存ready/署名意図と
  原envelope/GZip、現在Public/local下限を再確認します。保護された同operationの有限予算を再開時も保持します。

この接続の内部検証では、汎用のみ/nativeのみ/両方の明示三段階、複数sourceのflat/nested原候補と
人工Intel六入力の合成、fake署名/公開/匿名確認を
扱います。通常app用の三架空deviceは既存fixtureの取得/照合を確認し、追加Intel行は同集合でcodec/保存を
通した未照合の行です。別の元Intel archiveによるhistorical通常app取得/binding正例は確認しましたが、
fresh P1実投影・実PC適合・新Public正例とは区別します。原recordを架空ZIPへ付け替えません。

## native一recordの明示本体取得と未署名準備

通常metadata日次Taskとは別に、保守担当の明示操作
`daily_index_pipeline.py prepare-fresh-native CONFIG --fresh-receipt NEW_RECEIPT --maximum-payload-bytes BYTES --terms-consent-not-after UTC_SECONDS --accept-pinned-terms`
を追加しています。CONFIGは既存原点を正規継承した現行scope2の保護v2設定です。
同意対象は明示pinしたexpected releaseに含まれる許諾revisionと抽出全文hashであり、
期限は現在から24h以内の絶対UTC秒を明示します。BYTESは今回一recordの最大予算で、
公表exact sizeと同一とはみなしません。実際の原terms確認/同意を省略する入力ではありません。

新receiptは同CONFIGの保護outputRoot内の未使用JSON名にします。同じstemの
`.payload.zip`、`.payload.partial.zip`、`.approved-release.json`、`.native-inputs.json`を新規専用名にします。
既存final/partialを再利用・上書きしません。nativeは同writer/元source・request待機の下で、
新200の私有公式recordから一回だけ既存grant取得を呼びます。304/旧PAGE/公開JSONから新権限を作りません。
失敗・中断・不確定の最大待機と原fileを保持し、HOLDは待機や自動再試行をせず返します。
本体のflush/hash/sizeと非置換保存が成立した後、既存INF/CAT/参照本体検査とterms/script再確認へ渡します。
既存template条件が変わった場合は、新しい許諾と断定せずレビュー待ちで停止します。

成功時は既存`dc-candidate-native-inputs-v1`の六file/pinだけを返します。
署名/公開/Task操作/installer実行/driver導入を開始しません。通常アプリに設定や画面は増えません。
この接続は内部fakeの検証対象であり、変更後sourceのfresh実転送・現在terms一致・本番署名/公開は
未確認です。過去の保存ZIPや397配布byteの成功を変更後の実取得成功へ読み替えません。

ADR0405の新metadata用scope `dc-metadata-bound-distribution-acquisition-scope-v2`は、
`acquisitionBinding`へexpected releaseの原byte/hash、操作者が選ぶpackage相対`selectedInf`、
投影する`modelSection`、有限`maximumBytes`を明示します。版/URL/file名/掲載hashをcodeへ固定しません。
保存解析v1のSHA-256、v2のSHA-512のみ/両掲載を受け、掲載された全hashを同じ取得byteへ照合します。
公表exact sizeは掲載時だけ制約にし、未掲載を0や概算MBから補いません。最大128MiB・HTTP途中切れ・
全byte hash・ZIP/INF/CAT/全参照本体・Windows署名・x64/driver-onlyの検査は維持します。
新scopeは保護v2設定で`PINNED_STATIC_REVALIDATION_V2`を明示し、原manualのrelease/review/scriptに
原`body`のfile/hash対も指定します。既存`archiveFile/archiveSha256/archiveBytes`は旧原byteの履歴です。
新取得の期待値と実archive identityへ流用しません。新scope/保護設定の作成・昇格は明示保守作業です。
正規生成は`prepare_daily_index_config.py --inherit-config`へ`--acquisition-scope`と
`--acquisition-scope-sha256`を渡し、64KiB以内のscope原byteを保持します。原四入力は
`--original-release/body/review/script`のそれぞれへfileと`-sha256`を指定します。
任意の技術reviewも`--binding-release/body/review/script`の四roleすべてへfile/hash対を指定し、
不完全な組・未知field・保護root外・明示INF selectorの矛盾を拒否します。私有宣言の作成と保護設定発行は別です。
expected releaseの原観測秒は書換えず、待機で86401秒以上経過しても取得期待宣言として保持します。
今回の同意期限は実clockから24h以内に明示し、新発行の24h fresh窓と8日上限は新しい実receiptと
実検査へ適用します。旧metadataや旧manualの時刻を新観測へ読み替えません。

同一許諾の全文/revisionと旧manual原byte/時刻を保持し、新bodyの一意なDOM/linkとscriptを再検査します。
script更新だけでcode変更や同じ許諾への再同意を要求しません。必要な新しい技術reviewは
`originalInputs`へ完全な`bindingRelease/bindingBody/bindingReview/bindingScript`のfile/hash対で明示し、
その原body・script・六witnessから再確認します。未指定では原レビュー済みscriptの一致を要求し、
未確認のscriptを自動承認しません。旧許諾と異なる全文や未検証DOMはreviewへ送ります。
raw許諾documentは`licenseModal`内の一意な`content-raw`だけを照合し、補助textareaの本文を混ぜません。
対象の欠損・重複・container外・許諾本文改変を拒否し、六witnessと同一許諾全文/revisionを維持します。

内容検査artifact v3は同じ保護copyから実SHA-256/SHA-512/byte数を計算します。
現行アプリの索引形式は増やさず、SHA-512のみの場合は公表SHA-256をUNKNOWNと記載し、検査済みの
実SHA-256をcalculatedHashへ載せます。端末側の取得byte identity・署名・適用性・同意・復旧は維持します。
この接続の合成4条件は通常C++ reader/取得候補adapterまで内部確認しました。
実31.3の本体・INF/CAT・署名・実device適合・fresh/署名/公開の成功は未確認のままです。

## 通常installと所有Task

単体EXEまたは`DriverCrateCollectorSetup.exe --install ROOT --yes`の同意には、配置と現在user用の
native metadata日次Task一件の登録・有効読戻しを含みます。同梱既定の二targetを毎日local15時、
同userのInteractiveToken/LUAで処理します。検査取得を含む17時distribution Taskは前記の別opt-inです。
IgnoreNew・catch-up/idle/wakeなし・battery可・AllowHardTerminate=falseです。installからRun/Stopしません。

同じmanifestとreceipt-v3の既存配置だけはTask登録を修復できます。program/config/stateを
copy/resetせず、完全一致enabledなら冪等です。異版/旧receipt/任意既存先は上書きしません。
失敗時はstage/元HRESULTと部分program/dataを保持し、UNKNOWNやdisabledを成功としません。

通常uninstallは両所有Taskの非実行・所有・定義/SDDLを照合し、disable/delete/正常不存在を
確認後に管理programを削除します。running/queued/所有不明/改変/権限不足では保持します。
config・seed・work/data・未知file・自己setupと`Uninstall.cmd`は残します。旧管理者receiptの混在は
旧Task照会前に拒否し、旧Taskをadopt・更新・削除しません。旧Daily229向けlocal cutover入口は廃止しました。

明示`--daily-acquire`の`COLLECTOR_PAYLOAD`行の`stage`は今回最初の拒否区間だけです。
0は成功または今回未観測、1はrequest/session、2はmetadata取得、3は取得証拠、4は解析、
5はrecord変換、6はrecord検証、7は本体取得/保存です。元error/HTTP status/終了値を置換せず、
永続checkpoint/receiptへ保存しません。再開時の0から過去の原因や取得成功を判断できません。
URL/本文/IDは追加出力しません。この診断で過去の未観測失敗原因は確定しません。

同じ明示`--daily-acquire`が失敗しても、今回のHTTP200が完全に受信・検査された場合だけ、
原receipt名の拡張子を`.failed-page.json`へ置換した同じ保護job内へ原本文を新規保存します。
Intelの実request上限2MiBまでの全byte/hash/sizeと原error/stage、原receipt全byte hashを結び、
診断JSONは最大3MiBです。切り詰めず、304・部分受信・欠測・旧成功・再開から補いません。
元receiptと成功checkpointは維持し、失敗本文を成功evidence・六入力・署名索引へ渡しません。
診断先の既存fileは通信前に拒否します。保存結果は数値だけstderrへ分離し、保存失敗でも元の
収集終了値・error/stage・待機を保持します。失敗途中のfileを自動削除・再試行しません。
この私有診断は取得権限や公式配布検証の成功を示さず、実HTTPでの捕捉は未確認です。

## 停止workspaceと検証範囲

非通信のinitialize/verify/export/import/resumeは固定同梱runtimeで処理します。
停止確認、原byte/hash、移設snapshotの4096file/64MiB、各JSON16MiB、最大予約精算と元待機を保持します。
私有typed観測/permit/candidate headは移設で復元しません。未登録hostへの任意通信や
共有native scopeを許可せず、同I/O・同child・pipe peer/proof・子終了までleaseを要求します。

保持workspaceは全entry8192、一file16MiB、全履歴・monitor・管理fileの合計256MiBを有限上限とします。
非通信data importは新世代とactive pendingを加えた置換前のピークをwriter lock内で検査し、
超過は世代保存・active変更前に拒否します。既存世代の再利用でもpendingを数えます。
旧世代は自動削除せず、特定の世代数や無制限運用を保証しません。packageと可搬data一集合の総64MiB、
embedded一集合の総64MiBは維持します。実装・決定的検証と、最終配布物・実workspace接続の受入は別です。
採用根拠と境界は[ADR 0401](adr/0401-retained-workspace-capacity-preflight.md)を参照してください。

同じ現形式workspaceのpackage更新には、正規installが発行した現在のreceipt-v3と全byteを
検証したsetupから、停止済みの元workspaceへ次を明示します。`ORIGINAL_SHA256`は操作前に
所有者が内容とともにreviewした`workspace.json`原byteの小文字SHA-256です。

```text
DriverCrateCollectorSetup.exe --workspace-switch-package ROOT ORIGINAL_SHA256 --confirm-source-stopped
```

この操作は現在のschemaだけを扱い、旧bundle/binaryの受理・実行やdata変換を行いません。
既存owner/ACL、三root identity、両origin、初回完了と原plan、native/monitorの排他writerと
確定停止を検査します。未確定/未知run、原hash差、既存未知rootは修復せず拒否します。
原workspace全byteを`ROOT/package-switches/<原SHA-256>.json`へ保持し、二hash値だけを
現在package/seedへatomic切替します。archiveは最大256件の有限保存で、対応製品数の上限ではありません。
原origin/key/ledger/待機課金/active dataは変更せず、通信許可・receipt・Taskを発行しません。
通常のverify/run/importは切替前のbindingを受理せず、切替contextを実取得へ転用できません。

通常package lifecycleでは新しい自己所有配置へ正規installし、receiptと全byteを検査してから
同workspaceを明示切替します。通常installに含まれるnative日次Taskと、切替そのものの非通信を
区別してください。既存配置の異版上書きや旧Taskのadoptは提供しません。明示実行・日次同意は別操作です。
原archiveの再適用や中断した`package-switches/workspace.pending.json`を自動回復せず、
部分fileを保持して停止します。所有者による別reviewなしに削除/再初期化して続行しないでください。
10月25日の配布候補で、停止済み同一workspaceの実切替・同一dataのimport・検証を確認しました。
別PC移設と収集再開の実受入は未確認です。

PAGE内容変更で保留された一hostには、現在の承認baselineを非通信で再確認する次の明示操作を
sourceへ接続しました。変更後packageでの実運用解除は未受入です。

```text
DriverCrateCollectorSetup.exe --workspace-review-held-host ROOT REVIEW_REQUEST_JSON --confirm-source-stopped
```

`REVIEW_REQUEST_JSON`は64KiB以内の`dc-collector-held-host-review-v1`です。所有者がreviewした
一host/profile/record、workspace/state/journalと現三入力の期待SHA-256、原run/resultと欠測rawの
明示、現PAGE観測、原四scope、baseline再確認だけを行い課金/待機を保持する意思へ結合します。
同じdirectoryの固定`baseline.raw.html`と`current.raw.html`（各1MiB以内）だけを読みます。
URL/command/pathをrequestから実行せず、既存package/receipt・ACL・三実identity・両anchorを検査し、
同じnative leaseとmonitor writerの内側でCAS確認します。Task操作やHTTPは行いません。

完全PAGE/200の内容拒否`ACQUISITION_REJECTED/0x8007051A`でpayload未開始の原失敗だけが対象です。
最新host失敗と確定最大課金、現四scopeに結合したbaseline rawと手動PAGEの厳密content一致を要求します。
原raw欠測は復元済みや原因再現へ読み替えません。別原因、共有profile/native scope、未確定run/予約、
原待機未満、時計逆行、不一致・失効reviewは拒否します。現PAGEは一日以内、四scopeは原checkedAtから
八日以内を要求し、原確認時刻を延長しません。

対象hostの`held`とstateの実単調`observedAt`だけを変更し、元失敗/nextDue/課金/全requests/
journal/旧成功/世代/同意を保持します。`ROOT/host-reviews/<reviewId>`へ原request・両raw・原state/
journal・after-state・intentを耐久保存してからstateをatomic置換し、読戻し後に完了receiptを残します。
中断fileを削除・rollbackせず、完全な原監査とexact-afterに一致する同requestだけreceiptを補えます。
同request完了済みは状態を再変更しません。この操作を取得成功・fresh索引・通信grantに数えません。
人工workspaceの正負/中断試験とnative境界試験は確認しましたが、実HOLD解除・変更後配布物の署名/
package/lifecycleは別の受入です。契約は[ADR 0407](adr/0407-explicit-held-host-baseline-review.md)を参照してください。

現行の非通信検証は`test-collector-setup.ps1 -PackageDirectory PACKAGE -FixtureRoot NEW_ROOT`と
`test-seeded-collector-package.ps1 -Archive ZIP -FixtureRoot NEW_ROOT`です。既定は実Taskを操作しません。
実Task試験は別の明示受入工程です。10月24日の実取得は既存1 package・HTTP2要求/506,429byteで、
INF2件のCAT・全参照本体検査に合格しました。元runの投影は0件で、nested形式のsource修正と
内部試験後のfresh実投影は未確認です。元actual nextDueAtと課金を保持し、再取得で待機を回避しません。
公開前の最終ソース・文書・配布物の照合と、別PC・Taskの実行/自然日次・実導入は未確認です。

取得済みの未署名候補を発行pipelineへ渡すため、次の非通信入口をsourceへ追加しました。

```text
DriverCrateCollectorSetup.exe --workspace-stage-candidate ROOT EMPTY_DESTINATION --confirm-source-stopped
```

現行v7 packageの全byteと、結合済み原点・停止状態・native leaseを検査し、同じmonitor writerで
原候補・journal・provenance・active dataを照合します。原producer/期限と部分失敗を保持し、
固定出力だけを新しい`EMPTY_DESTINATION/distribution`へ保存します。途中出力を上書き・削除しません。
この操作だけは正常な未install packageもcallerにでき、Task登録のためのinstallを必要としません。
未installの利用は保護配置済みの保守callerに限定し、ZIP展開だけで実行資格を付けません。
この入口はcallerの保護配置・receipt作成・Task登録を行いません。
原workspace bindingを変更せず、現在callerのbyteへ過去の内容検査資格を継承しません。
保存先は発行側の通常ACL・unsigned codecで別途再検査し、通常prepare/signで世代を確定します。
staging自体は通信同意・再観測・署名・公開ではありません。契約は
[ADR 0408](adr/0408-protected-candidate-staging.md)を参照してください。変更後byteの実受入は別記録です。

10月26日の有限受入では、既存原点からWindows11向け二件を非通信stagingし、通常の管理者保護reader・
unsigned codecと既存の世代予約/専用CNG署名/現在validatorへ接続しました。世代9はローカル生成だけで、
GitHub未公開です。原期限2026-11-02T09:28:33Z、target分母1/部分1・Windows10二件の未観測と
未profiled1717を保持しています。通常appの取得/実端末候補・実導入、変更後setupのコード署名と
公開用最終source/配布物の受入は別です。RDP操作中のためEXE署名は後続に残します。
現在索引の読取は、公開済みの正式版/プレリリース双方を署名等の通常検証へ渡します。
新Releaseをprereleaseとして発行する方針は維持します（[ADR 0409](adr/0409-published-index-release-classification.md)）。
