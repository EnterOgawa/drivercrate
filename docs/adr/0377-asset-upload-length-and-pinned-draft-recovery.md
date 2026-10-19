# ADR 0377: asset の実 byte 長指定と既署名束の固定 draft 回復

日付: 2026-10-19
状態: 採用。source と非通信試験の範囲。実配置・回復実行・Private 反映は別工程。

## 決定

`GitHub.api` の Release asset upload に限り、固定 repository、POST、正の Release ID、
`index.json.gz` / `manifest.json` の完全な path と MIME を検査する。body は非空の
`bytes` で既存 `MAX_FILE` 以下とし、実際に stdin へ渡す同じ byte 列の `len` を一度だけ
`Content-Length` に指定する。URL、hostname、既存 gh 認証、MIME と body は保持する。
不正要求は子 process の起動と要求 ordinal の消費前に拒否する。通常 GET / JSON の契約は維持する。

gh 2.89.0 の一致する一次 source では `--input -` の size は -1 であり、自動長指定の条件を
満たさない。明示した長さは HTTP request の ContentLength に使用される。
これは source 上の要求契約不備の根拠である。元の HTTP 400 の raw / wire は欠損しており、
唯一の原因と断定せず、元 POST の remoteWriteOutcome UNKNOWN を維持する。
[gh stdin 処理](https://github.com/cli/cli/blob/v2.89.0/pkg/cmd/api/api.go#L561)、
[gh 明示長処理](https://github.com/cli/cli/blob/v2.89.0/pkg/cmd/api/http.go#L49)、
[公式 asset upload 契約](https://docs.github.com/en/rest/releases/assets#upload-a-release-asset)。

## 有限な証拠専用回復

作業証拠内の helper だけで既知の generation 5 / 正確な tag / draft 416566109 を拘束する。
任意 ID の入力、一般 draft 探索、404 後の新規 draft 作成は許可しない。通常 Publisher の
published-only tag lookup による draft 発見の制限は未修正として残す。

原 config の全 byte / 全 module pin を実際の旧保護 module context で認証する。
旧 `__file__` や pin を現在 source に見せかけず、現在 Publisher は別 namespace でロードする。
実行時だけ、別途確認した未存在の固定保護 directory へ現在三 module、helper、凍結 plan の
五 file を create-new で配置し、全 hash / ACL / membership を読戻す。旧 module / config は変更しない。
plan は他四 file を拘束し、外側の確認済み配置記録と argv の plan hash が第五 file を拘束する。
workspace の可変 source を live import せず、保護 directory の OS 作成時刻以後の配置・起動時間も
同じ運用 Budget から控除する。この工程では directory を作成しない。
新 config chain、旧 pipeline / prepare の再実行、収集、parse、package 再検査、再署名は行わない。
同じ claim、envelope、gzip、六入力、native current 成功 terminal、原 UTC bucket / receipt / 時刻、
公開 fingerprint と別に固定した現在 source を使用する。

既存 Publisher の byte readback、immutable conflict、未知 asset 拒否、generation、
index-only tree と一回 CAS を再利用する。native current / history と六入力 audit を共用するため、
既存 run_acquisition の verify closure だけを同等な factory へ抽出する。
通常経路の署名・claim・native argv・audit 順序と例外を変更しない。

helper は既存 operation lock を保持し、最初と CAS 直前に native FRESH_INPUT を確認する。
全 write 境界で原 byte / claim / UTC day / expiry / 残予算を再確認し、ref は観測済みの不在を要求する。
異なる head、未知 asset、starter、内容 conflict、失効、原証拠欠損は停止する。CAS intent は
既存 terminal 系列へ保存し、その後の不明結果は exact readback だけに制限する。
回復結果は別 file とし、元 FAILED terminal を成功へ書き換えない。

実 Budget へ carry 59 call / 817.6585010021417 秒を一度だけ適用し、同じ 96 call / 1800 秒と
追加最大 30 managed call（gh 24 / native 検証 6）を守る。開発・人工試験・レビュー時間は
別工程とし、実運用で新たに使う時間と process は次の実行時に加算する。UTC day / 期限は reset しない。
既存 gh 認証を使用し、token の読取り・保存を行わない。Private repository だけを対象とする。

## 検証と制限

非通信試験で 3352 / 1493 byte、非 ASCII byte 長、header 一件、原 byte 一致、通常 GET / JSON、
不正 upload の no-child を確認する。既存 147 test のうち 146 method の AST を維持する。
全 route へ body=None を送る旧 e05 だけは、この起動前拒否と矛盾するため upload 二 route に
有効な人工 bytes / MIME を渡す fixture へ修正し、診断 assertion は全て維持する。原失敗を残す。
factory の argv / 保存 byte / current audit / history 分岐を旧 closure と比較する。
helper の固定 draft / config / claim / expiry / carry 拒否、署名禁止と Publisher の失敗境界を確認する。
これは実 GitHub の 400 解消、公開品質や実運用完了の証拠ではない。

この source 工程では native・通信・保護書込み・Git・Task・実導入を実行しない。
実内容 1/1、pipeline 0/1、受入済み Private 取得用索引 0、端末候補数 null、対応系列増 0 を維持する。
