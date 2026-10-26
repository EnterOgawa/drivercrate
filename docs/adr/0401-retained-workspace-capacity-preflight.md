# ADR 0401: 保持workspaceの有限容量とdata import前判定

- 日付: 2026-10-25
- 状態: 採用。実装・決定的検証はG13-I7r255c2capで別管理し、最終配布物・実workspace接続の受入を含めない。
- 関連: ADR 0397、0398、G13-I7r255c2off、G13-I7r255c2cap

## 背景

441の現行setupは外部v2 dataを非通信で保存し、子が`DATA_IMPORTED_OFFLINE`を返した後、
native最終`inspectTree`が総64MiB超過で操作全体をexit2とした。原workspaceは
55,704,664から71,637,253byteとなり、各fileは16MiB以内だった。新active/世代と旧履歴は
保持済みだが、import全体とnative verifyは合格していない。旧世代を削除して回避しない。

`inspectTree`はembedded staging、package、操作rootの事前/最終検査で共用され、
通常file16MiB/総64MiBが操作rootにも適用されていた。Pythonの`import_data`は
writer lock内で旧active/履歴/B1/時刻を検査してから新世代を保存し、active pendingをflush/readbackして
atomic置換する。保存前の保持root全体の容量判定がなかった。

## 決定

1. 保持workspaceの総通常file byte上限だけを**268,435,456byte（256MiB）**へ分ける。
   最大64MiBの可搬data三世代と残る64MiBの履歴・管理領域を収容し得る有限な作業予算として選ぶ。
   実際の全treeを毎回数えるため、三世代の保持を保証せず、世代数制限・予約領域・自動削除は加えない。
   現71,637,253byteの保持例を許容するが、無制限運用や全製品数の上限を定義するものではない。
2. nativeの操作root事前/最終は同じ256MiB、一file16MiB、全entry8192を使用する。
   packageは一file16MiB/総64MiB、embedded stagingは一file/総64MiBの既存値を維持する。
   data bundle総64MiB、一file16MiB、移設snapshotの既存4096file/64MiBも変えない。
   全用途で減算による加算前判定を保ち、ACL、実identity、reparse/hardlink拒否とhandle保持を変えない。
3. Python importはwriter lock内で、**世代fileを一つも保存する前**に実workspace全treeの
   byte/entry/一file/通常file・directory/linkを有限列挙して検査する。新規data storeの場合は
   `data`/`generations`/`writer.lock`作成前にも同じ判定を行い、作成後のlock内で再確認する。
4. 容量は既存全treeに、新世代の全file/必要directory、および旧activeと同時に存在する
   active pending一file/原byteを加えたピークで判定する。既存世代は全byte一致を確認し、
   世代の増分を0とするが、pointer置換を行うためpendingは数える。旧activeのbyteやentryを
   保存前に差し引かない。Python整数に固定幅overflowはないが、同じ上限からの減算で判定する。
5. 容量・件数・一file超過は新世代保存/active置換前に固定理由で拒否し、既存active/全世代を
   変更しない。新規store作成前の拒否も空data storeを残さない。原hash/期限/世代下限、
   B1再review、待機・予算・同意を維持し、容量不足を通信許可や成功へ置換しない。
   既存のI/O障害・中断による部分保存の保持契約は維持し、同一user/SYSTEM/Administratorsを
   信頼する既存境界を変更しない。同じ権限の任意書換えとの完全な競合防止を新しく保証しない。

## 実装前に固定する検証範囲

- 自己所有の有効dataを複数世代importし、実合計64MiB超でも原hash/旧世代を保持しactiveを検証する。
- 256MiBピークのちょうど境界と一byte超過、既存世代再import、初期scaffoldingを検査する。
  拒否時は全既存fileのbyte/hashと世代集合、active、pending不在を照合する。
- entry8192の境界、一file16MiB直後、hardlink/reparse、package総64MiB/一file16MiB、
  data input総64MiB/一file16MiB、embeddedの既存上限を維持する決定的検証を行う。
- nativeは実保護fixtureの操作root事前/最終と固定fake childを使用し、実運用root/Task/HTTPを使わない。
- 変更target Debug/Release、局所format/source/Doxygen/Python構文、変更TUの必要MSVC解析を行い、
  唯一buildの通常cacheへ戻す。全150/fullstrictの根拠のない反復は行わない。

## 結果と残件

採用は配布・実接続の完了ではない。原441失敗、現在active、三root identity、元待機・counter/claimを
保持する。最終source/fresh build/packageの再資格と修正版実接続は主担当の後工程へ残す。
EXEコード署名だけ延期し、索引署名・原期限・公開承認の境界は維持する。
