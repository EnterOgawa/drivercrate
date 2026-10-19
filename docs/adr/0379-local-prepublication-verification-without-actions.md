# ADR 0379: Private開発と公開snapshotのローカル事前検証

- 日付: 2026-10-19
- 状態: 方針採用。公開snapshotの初回ローカル受入とremote移行は未実施。

## 背景

本人の「actionsを利用するよりも、開発はprivateで行いpublic公開版は公開前にローカルで確認すればいい」
を採用する。開発Privateを正本として保持し、公開版は必要なfileだけを固定したsnapshotから検証する。
GitHub Actionsを通常の開発・公開確認の実行経路にしない。

## 決定

main push／pull requestで起動する`.github/workflows/ci.yml`をローカルで削除し、公開候補manifestから外す。
手動Actionsへの置換はしない。将来Actionsを採用する場合は別の方針判断とし、read-only既定権限と
外部Actionの検証済みcommit SHA固定条件を維持する。ローカル削除はremoteのworkflow無効化ではない。

公開するpath・mode・byteとSHA-256を固定し、必要source／fixture／runtime／文書／license／noticeの
閉包を確認する。その集合だけを独立した公開候補directoryへコピーし、byte一致を確認する。
build treeは開発workspace直下の既存`build/`一つだけとし、公開候補directory内へ別buildを作らない。
実行前に現CMake契約を確認し、既存buildのsourceを公開snapshotへ一時切替する工程を別途登録する。
元source／構成／tool／入力pinはmetadataだけを保持し、cache・生成物の切替とclean方法、旧生成物を
受入証拠へ混入させない初回検証、通常開発source／構成への復帰と確認を登録範囲に含める。
旧build archiveや別build treeを新設しない。具体的切替手順の確認・再構成・clean・buildは未実施である。
固定snapshotを入力にx64 Debug／Release全target、必要unit／UI／Python／PowerShell試験、source規約と
Doxygen gateをローカル実行する。既存Private working treeの増分build合格を、このsnapshotの初回検証へ読み替えない。
具体的入口は[テスト方針](../testing.md#公開snapshotのローカル事前確認)へまとめる。

`.git`、Actions workflow、鍵・credential、実inventory、driver本体、個人の絶対path、build／PDB、
私有のwork記録を公開集合へ含めない。必要な文書link・秘密情報・画像metadata・権利表示も確認する。
静的閉包checkerの規則や品質gateを弱めず、除外で合格を作らない。検証後に公開集合が変われば、
変更の影響に応じて再検証し、実際に公開するbyteと証拠を一致させる。

開発Privateの履歴は保持する。初回公開snapshotへ旧私有履歴を持ち込まない方針を維持し、
公開開始後の変更は公開側の履歴へ残す。毎回rootを作り直したり、force-pushで公開履歴を消さない。
remote反映、tag／Release、Public化はそれぞれ該当する明示承認の範囲で行い、方針採用だけで実行しない。
署名／hash／適用性／同意／復旧／privacyと有限予算の境界は維持する。

## 既存候補と未完了

ADR 0378の822file候補とtree `316e16a685dad9c92d8507beaf0274402adff7f9`は当時の予備確認として保持する。
自動CIを含む旧候補を今後の移行へそのまま流用しない。今回はworkflow一件を除き、この公開手順の
根拠となる本ADR一件を加えるため、現在の候補は822fileである。同数でも旧集合・旧hashとは異なり、
`finalAllowlist=false`と最終公開一覧の確認待ちを維持する。ADR 0378自体は私有の移行記録として残す。

履歴分離の実行工程は保留中である。現API／publisherはPrivate identity必須で、Public化後は
`PRIVATE_IDENTITY`で拒否する既存制約を変更していない。新repo作成、初回公開snapshotを入力とする初回build、
匿名取得、通常アプリの実端末正常例、実導入、Public継続日次を本変更で受入済みにしない。
remoteへの反映は行わないため、既存remoteの自動workflowを削除・無効化したとも記載しない。
将来の実移行では、公開準備repoと旧開発repoの双方でActions不使用を確認する必要がある。
旧開発remoteには自動workflowが残る。現段階のremote無効化は未承認・保留とし、既存の移行工程の
API write予算へ無断追加せず、実移行前に必要な操作と予算を改めて登録する。

## 影響と確認

Actionsの自動確認は提供しない。公開前のローカル検証結果、未実行項目、対象集合を記録してレビューする。
今回は文書・manifest・workflow削除の有限確認であり、製品source／CMake／安全gateの変更や
全campaignの再実行は行わない。[Release checklist](../release-checklist.md)の未完了項目を保持する。
