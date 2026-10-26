# ADR 0381: Public日次索引publisherの明示identity境界

- 日付: 2026-10-19
- 状態: 採用。G13-I7r231h15s11b1のローカル内部境界に限定する。
- 根拠: s11a設計とs11av主担当受入。通常アプリと運用入口は変更しない。

## 決定

`daily_index_pipeline.py`に、非空64KiB以下のUTF-8 JSON原byteを検証する純粋関数を置く。
閉fieldはschema、approvalKind、mode、purpose、repository、repositoryId、repositoryNodeId、
ownerLogin、ownerId、actorLogin、actorId、visibility、publicFingerprintの13件とする。
重複・未知・欠損fieldと型違いを拒否し、整数はboolを含めず完全一致で検査する。

固定値は`dc-approved-public-index-publisher-v1`、`EXPLICIT_PUBLIC_SIGNED_INDEX`、
`PUBLIC_SIGNED_INDEX_V1`、`DISTRIBUTION_ACQUISITION`、`EnterOgawa/drivercrate`、
repository ID 1425267459、node `R_kgDOVPPbAw`、owner/actor `EnterOgawa`とID 113655398、
visibility `public`、配布公開fingerprint
`0ac4d0ce9873c82b3c7bb7bd3fb3f5d2a57044bf968c5c6e2af02176cee39d3f`とする。
任意repositoryやremote応答から承認値を生成しない。

Publisherのkeyword引数へこの原byteを明示注入した場合だけPublic境界へ入る。
純粋検証後の原byteとhashはfrozen値として所有し、identity検査時にも原byteを再検証する。
用途が取得用でなければ構築時に拒否する。既定targetなしのPrivate条件・エラー・呼出し順、
既存v1/v2閉schema、CLIとload_configは変更しない。
Publicでも既存verify callbackを新bundle、実asset読戻し、取得用途の同byte再開へ必ず呼ぶ。
callbackの暗号・内容検証の実装責任は既存の呼出し側にあり、承認recordだけで署名成功としない。

Publicのremote identityはuserのlogin/id、repoのfull_name/id/node_id、ownerのlogin/id、
`private is False`とvisibility `public`を完全照合する。欠損、bool-as-int、旧ID、同名別ID、
別node、owner/actor差、公開状態矛盾は追加write前に拒否する。
既存の開始時とRelease公開後のidentity再確認を保持し、Publicだけ各remote write直前にも
同じ照合を加える。before_cas callback後も再確認し、CAS repositoryIdは承認済みnodeに結合する。
REST/upload allowlistは既存正式名のまま、二asset、hash/署名callback、history限定の旧current、
一回CAS/force=false、readback-onlyを維持する。
追加identity GETも同じremote/GitHub Budgetを使用し、既存96calls/1800秒の計上と停止を免除しない。
今回のRAM fake成功は実Public運用がその予算へ収まる実測ではない。

## 限界と失敗時動作

identity応答と次のwriteはGitHub全体の原子的操作ではない。renameや権限変更との競合を
完全に排他できるとは保証しない。不一致・例外では追加writeを停止し、既存draft/assets等の
部分作用を自動削除・rollback・retryしない。CAS後の応答不明を成功や旧current保持と推定しない。

今回実装するのは原byteの純粋検証とRAM fake接続だけである。承認recordの実発行、固定保護位置への
配置・ACL/ancestor/reparse/hardlink検査とhash pin、v3 config/preparer、旧carryと履歴の移行、
匿名readback transport、Disabled Task再bind、旧assetへの新manifest復帰は未実装の後続工程とする。
実HTTP、Task変更/開始、鍵照会/署名、実app、driver取得/導入、remote反映は行わない。
既公開gen5の期限2026-10-19T13:24:11Zとcarry90calls/846.4786秒を変更しない。

## 検証

固定CASESへtest名・variant・期待エラー・remote作用数を実行前登録し、Public正常と厳密拒否、
既定Private回帰、途中identity変更時の停止、二asset、readback-onlyと既存取得/CAS/予算を確認する。
通常唯一buildのDebug/Releaseと両signed-index-boundariesは今回差分受入として別記し、
旧全suite合格・Public日次実運用・公開snapshot再受入へ読み替えない。
