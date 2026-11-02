# ADR 0414: 元INF完全tuple内の一意なWindows最小full-rank node

- 日付: 2026-10-27
- 状態: 採用（実装・内部検証・通常READY・実導入は別に記録する）
- 関連: ADR 0329、0413

通常appの実取得済みINFを実SetupAPIで有限read-only列挙したところ、同一INF完全path、
provider、packed version、date、DDInstall節に対して異なるfull rankのnodeが二件あった。
最良は後者一件で、metadata一致node数だけによる重複拒否は適用候補を失わせた。

## 決定

1. 単一INF互換listを既存上限内で正常終端まで列挙する。元INF完全path、provider、
   packed version、dateを満たす全nodeの実Windows full rankを読み、最小値が一件だけの
   場合にそのnode全snapshotを固定する。列挙順や名称・版比較からrankを推測しない。
2. 最小rank同点が複数なら拒否する。途中の同点は後のより低rankで解消できるが、
   正常終端前に成功や同点拒否を確定しない。metadata/detail/rank/API失敗、列挙不足・上限、
   候補無しは従前の診断を保持し、部分一致で成功にしない。
3. 導入前の元INF再検証も同じ唯一winnerを再計算し、発行時の同device/section/rank/全snapshotに
   一致しなければ拒否する。登録先nodeの指定も元完全tuple内の唯一最小rankへ揃え、
   元winnerより良い別nodeや同点が現れても古いwinnerを指定しない。
4. Class、全PnP根拠、署名索引・原hash/期限/世代、実取得byte、全INF/CAT閉包、同意、
   復元、指定一deviceの境界を維持する。製品別分岐、先頭採用、同点許可、metadata補完は行わない。

## 検証

異rank二件の両順序、後者最良、同最良同点、後の低rankによる旧同点解消、wrong tuple、
late rank/detail/API失敗、正常終端欠測・上限・候補無し、導入直前winner変化/失効を回帰する。
既存の完全初回/未知Class・共有一取得/選択一件/非選択0を維持する。
新signed appの通常READY確認までを今回の範囲とし、親確認前の実導入/復元は行わない。
