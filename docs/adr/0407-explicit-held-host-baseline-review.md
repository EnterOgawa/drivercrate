# ADR 0407: PAGE内容拒否後の一host明示baseline review

- 状態: 採用（2026-10-26）。実運用解除・変更後配布物の受入は別工程。
- 対応工程: G13-I7r255h0g2ri0。
- 関連: ADR 0397、0402、0406。498提案の全面pending guard/復旧基盤は採用しない。

## 判断

既存setupへ `--workspace-review-held-host <workspace> <review-request.json>
--confirm-source-stopped` を追加する。現行v7/receipt-v3のpackage/owner/ACL/両anchorと
三実identityを検査し、既存 `acquireCollectorDistributionAdmission(..., false)` のnative
leaseを固定Python childの終了まで保持する。非通信180秒、monitor writerの順で排他する。
独立Python編集、Task操作、HTTP、UI/Provider追加、通信grant発行は行わない。

対象は一host/一current profile/一record、同じhostを使う他profileは拒否する。requestは
64KiB以内の閉じたJSONで、自由command/URL/pathを含めない。requestと同じdirectoryの
固定 `baseline.raw.html` と `current.raw.html`（各1MiB以下）だけをnativeで固定する。
baseline rawは現四scopeのbody/content hash、current rawは手動観測raw hashと厳密content
hashへ結合する。両content一致により全本文とstatic href/条件の不変を確認する。
四scopeの原checkedAt、原PAGE観測、台帳・dataと手動review期限を更新しない。
手動PAGE証拠は一日以内、既存四scopeは原checkedAtから八日以内を要求する。

解除原因はPAGE COMPLETE/200・payload UNSTARTED/要求0・sourceVerified=false・
ACQUISITION_REJECTED/0x8007051Aかつ旧期待rawとの差が原resultに残る場合だけ。
元jobと現jobのsource/reference/record/productsが一致し、hostの最新失敗と同runの
確定最大課金へ結合する。別原因/unknown/別host/共有profile/未確定runや予約は拒否する。
原失敗rawの欠測はrequestで明示承認し、現在承認baselineの再検証だけを意思とする。
欠測rawを復元した事実、原拒否の再現、取得成功、fresh成功には読み替えない。

native lease→monitor writer内でstate/journal/workspace/data/policyの期待hash、実identity、
親生存を検査し、実UTCが全observedAtと対象host/関連requestのnextDueAt以上であることを要求する。
原state/journal/request/両raw/after-state/intentをCREATE_NEW/flush/fsyncで耐久保存し、
再CAS後に既存save_stateでatomic replace、exact readback後に完了receiptを保存する。
許すstate差分は一hostのheld true→falseとobservedAtの実単調時刻だけ。
failedAt/nextDue/全requests/旧成功/課金/journal/run/世代/予算/floors/grants/同意は不変。

## 中断と範囲

auditは既存workspace内 `host-reviews/<reviewId>` の私有記録とし、通常ログ/公開物へ出さない。
中断時は原fileを削除せず、無条件rollbackしない。intent後・replace前はHOLD保持、
replace後・receipt前はexact-afterと完全な原監査が一致する同requestだけ完了receiptを補う。
完了済み同requestはALREADY_REVIEWED、state/時刻を再変更しない。異なるrequestまたは
新しいstateは拒否し、全run/export/switchへのglobal pending guardや新token/HMACは作らない。
SHA整合性をHMACと呼ばない。fixture成功と実運用受入、現署名配布物を分ける。

## 有限検証

自己所有fake workspaceで成功・原履歴不変、CAS/identity/lease競合、別原因、未settled、
原待機/時計、古い・不一致raw/四scope、原監査保存/replace/receipt中断を確認する。
native境界は新操作の固定振分け、request/両rawの実handle、原点要求、非保存lease、
非通信180秒の接続を対象にする。実HTTP/Task/実HOLD解除/導入/署名/package/remoteは0。
