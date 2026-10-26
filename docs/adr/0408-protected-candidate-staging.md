# ADR 0408: 未署名候補の非通信staging

- 日付: 2026-10-26
- 状態: 採用、実装・有限受入は別記録
- 対象: G13-I7r255h0g2ps0

## 背景

現行collectorは、同じnative leaseとmonitor writerで内容検査済み候補を作る。
workspaceは現在user/SYSTEM/Administratorsを信頼するため、管理者保護だけを要求する
発行pipelineの`candidate_publication_input`はこの配置を正しく拒否する。
既存のportable exportは待機・最大課金の移設用で、private runを発行入力として輸出しない。
ACLを緩めたりworkspaceを手書きで信頼化したりせず、非通信の専用受渡しを追加する。

## 決定

`--workspace-stage-candidate ROOT DESTINATION --confirm-source-stopped`を追加する。
対象は現行package-v7、正式に結合済みのdistribution workspaceだけである。
既存のpackage検査・三実identity・両anchor・初回完了・停止状態・native leaseを維持する。
同じleaseの内側でdistribution sourceの実fileを読取り専用handleへ固定し、固定childが
monitor writerを取得する。終了・例外でも子の確定終端より先にleaseを解放しない。

保存先は所有者が事前作成した空の通常directoryを要求し、package/workspace/native/monitor
との重複を拒否する。ancestor handleを保持し、既存fileやACLを修復しない。
発行用の管理者保護directoryは既存`daily_index_pipeline.protected_path`で別途検査する。
native workspaceのuser保護を発行用ACLへ読み替えない。

この非通信操作に限り、正常package全byte検査を通った未installの現行v7 packageもcallerに
できる。receiptが存在すれば通常のreceipt検査を必須とし、receiptを捏造しない。
Task登録のためだけにinstallしない。source workspaceは現行schemaの原bindingを保持し、
headの原package/seed hashへ完全一致させる。現在callerとの二hash差はread-only stagingだけに
限定し、switch・import・取得・導入の許可へ転用しない。原workspace byteは前後CASする。

同じwriter内で現在head・commit・validation・全出力の原hash、原journal/run/job/reservationと
candidate/provenance・active data hashを照合する。全recordのbase64本文/sourceを元候補へ
再照合し、原期限と現在時刻を検査する。選ばれた観測の少なくとも一つは実観測から24時間以内
でなければ拒否する。保持中の原candidate producer/package識別を変更後packageへ書き換えず、
旧byteに基づく観測として保存する。現在packageの能力で再取得・再検査したとは数えない。

固定出力だけを`DESTINATION/distribution`へCREATE_NEWで保存し、headを最後に置く。
途中失敗は部分出力を残し、上書き・削除・自動再開しない。保存前後に同じsource byteと
親生存・実identityを再照合する。出力は未署名dataであり、authority、通信同意、freshな
再観測、予約receipt、署名済世代を発行しない。全target成功へ変換しない。

staging後は通常の保護reader・unsigned native validator・`prepare-candidate`・
`sign-candidate`を使用する。現在のGitHub identity/headのread-only取得、既存namespaceの
LEGACY_FENCEと全claim履歴、正規世代確定、原期限、専用CNG鍵、CASは変更しない。
GitHubへのwrite・公開は別の明示承認が必要であり、この工程では行わない。

## 検証

正常・部分成功のrecord保持、原producer差、期限切れ、fresh観測なし、source改変、
dead/wrong-operation admission、原点差、保存先非空/重複、途中保存失敗をfakeで検査する。
変更nativeの必要target/規約検査と実保護staging・正常署名validatorの受入を別記録する。
Task、driver導入、vendor HTTP、EV署名再試行は本操作へ接続しない。
