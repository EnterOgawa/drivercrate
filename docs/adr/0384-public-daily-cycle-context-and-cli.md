# ADR 0384: 固定Public contextと日次cycleの閉CLI

- 日付: 2026-10-20
- 状態: 採用。hd/hdtのローカル有限source/fakeを対象とし、実配置・Task接続・実運用は含まない。
- 前提: ADR0381–0383、236 design/CASESと主担当hcv確認。v1/v2通常loader、Private、既存Publisher・Budget・署名verifierを維持する。

## 閉profile

全JSONはUTF-8 BOMなしcanonical原byte、重複/未知/欠損fieldを拒否する。SHAは小文字64桁、日付は実在JST暦日8桁、世代はboolでない正整数、commitは小文字40桁。pathは絶対normal_path/既存protected_pathでowner/DACL/ancestor/reparse/hardlinkを検証する。rootは64KiB、start/summary/terminalは64KiB以下、cycleは1MiB以下、通常全file上限16MiBを維持する。

固定root `control/<同config>/public-context.json`は9field: schema=`dc-public-daily-context-v1`, kind=`BOOTSTRAP_ANCHORED_PUBLIC_CYCLE`, publicConfigFile, publicConfigSha256, bootstrapHistoryFile, bootstrapHistorySha256, publisherApprovalSha256, dayPolicy=`JST_NATIVE_RUN_DAY_V1`, scheduleSha256。historyは同control/history.json。schedule SHAはsmokeLocal/firstDailyLocal/days=7のcanonical SHA。config/承認record/hashを変更せず、root自身のSHAはCLIへ明示pinする。

start-v2の10fieldはschema=`dc-public-daily-cycle-start-v2`, configSha256, contextRootSha256, previousEvidenceSha256, previousReceiptSha256, previousBudgetSummarySha256, previousTerminalPins, oldGeneration, day, retainedCarry。初回summaryだけnull、継続は完成summary原SHA、terminalPinsは全名前→SHAの閉snapshot。

cycle-v1の13fieldはschema=`dc-public-daily-cycle-evidence-v1`, contextRootSha256, publicConfigSha256, operationDay, previousEvidenceSha256, files, inputs, terminalPins, budgetContextSha256, budgetLastEntrySha256, nativeGeneration, publicationCommit, retainedBootstrapCarry。filesはstart/receipt/claim/rawManifest/gzip/envelope/signingResult/success/terminalの9role、inputsはscope/evidence/release/inspection/review/scriptの6role、entryはfile/sha256の2field。terminalは日別64/全512、chainは元七日で最大7件、tree4096、attempt32を広げない。carryはcalls整数0..96/seconds有限数0..1800で原七fileから導出する。

summary-v2はschema=`dc-public-operation-budget-summary-v2`, contextSha256, calls, elapsedSeconds, lastEntrySha256, completedCycleSha256の6field。completedCycleSha256は未完成null/完成cycle原SHA。bridge start/summary-v1を黙って変換しない。cycle→summary→次startの一方向hashとし、cycleからsummaryへ逆参照しない。

## 認証と保存

旧v2 bootstrapは原公開時刻の履歴専用、Public派生cycleは同configの共通claim・六raw・原署名exit0/nativeCurrentVerified・原PUBLISHED/commit・receipt SHA鎖を認証する。祖先は有限pure pin鎖、managed native history/LEGACY_FENCE/remote currentは直前だけ。未実行/未解決前日を飛ばさず、date/remote+1/自己申告counterで新予算を作らない。

同じpipeline.lock内で共通success→Public main terminal→cycle CREATE_NEW→既存budget summary-v2→unlockとする。元cycle byteは再開でも不変、次startは最終summaryと全terminal snapshotをpinする。部分cycle/最終summary欠損/tail不一致はPUBLIC_CYCLE_EVIDENCE_INCOMPLETE/PUBLIC_BUDGET_JOURNALで要保守として閉じる。

strict HOLDだけ原run前generation/http/attempt/error/stateError=0・head不進行・未完child/claim/署名/CASなしを認証し同日同予算でdueへ再入場できる。NO_NETWORK/FAILED/partial/UNKNOWNはHOLDに戻さない。完全署名束と原署名成功・既知予算だけ同日/翌日元prefixでreadback-only、追加収集/署名/upload/CAS0。跨日未署名/日程外/失効/native別headは閉じる。

HOLDの受付は「新日operationの認証済みpreflight/予算確保」であり、まだ実観測の許可ではない。Public継続だけはpredecessor notBefore直前もこのpreflightへ入り、元nativeの未通信HOLDを同予算へ保存できる。HOLDのnotBeforeを原predecessorへ一致させ、実観測はlastAttemptAt >= predecessor notBeforeを必須にする。MAX_WAIT300秒/一回待機を維持し、15JSTの秒ずれを日付変更で免除しない。旧一回bridge/v1/v2のbefore-due拒否は変更しない。

前日完成束の翌日readbackは、その日の予定時刻前かつ前receiptのnotBefore前なら元prefixを選ぶ。予定時刻以後は新日のpreflightを選び、数秒先のdueを元native HOLDで待つ。未完成の完全署名束は予定時刻に関わらず元prefix/readback-onlyであり、前日の未解決を飛ばさない。完了保存時の外側時間が1800秒に達した場合は完成SHAを付けず予算停止とし、clampで成功時間を隠さない。

全metadata/lock/journal時間を受付単調startから同96calls/1800秒へ永続計上する。preflight前67call/後55call、readback16callの残枠を要求し不足はPUBLIC_CYCLE_BUDGET_INSUFFICIENT。静的67/native17/GH50（write前identity GET16込み）、HOLD13は未実測案でfake traceと照合する。旧90calls/846.4786425890825秒は来歴として保持する。

## 時刻とCLI

native receipt.dayは固定JST run開始日。Public scheduleは+09:00だけ、受付dayを凍結してnative前後/署名前に照合する。UTC epoch/due/公開時刻と暦日を区別する。freshはnow < lastSuccessfulValidationAt+86400（notBefore）であり、predecessor notBefore到来は次観測のdue下限だけ。旧manifestの期限を延ばさない。通常v1/v2/native/producerは変更しない。

正規CLIは `run-public CONFIG --public-context ROOT --public-context-sha256 SHA`。両option必須pair、略記/重複/未知/mixed/output/user-sid/smokeは作用前拒否（PUBLIC_CLI_ARGUMENTS）。v3旧run/Task/reportは引き続きPUBLIC_HISTORY_TRANSITION_REQUIRED。任意day/counter/budget/authorityを引数へ追加しない。preparerは排他 `--public-context-from-history HISTORY --public-history-sha256 SHA --public-config CONFIG --public-config-sha256 SHA` だけで同controlのrootをCREATE_NEWし、公開承認は発行しない。

将来Taskの固定pythonw -I Actionは上記CLIと固定原SHAを使う設計に限る。現Task sourceの旧run生成/拒否は維持し、b4で別受入する。元2026-10-16〜22/15JST、gen5期限、通常15pin、署名/hash/適用性/privacy/実公開の別承認は不変。機能未達はHANDOFF/resultへ明示し、本ADRだけで利用可能としない。
