# ADR 0413: 署名索引の認証済み個別device投影

- 日付: 2026-10-27
- 状態: 採用（実装・内部検証・実機READYは別に記録する）
- 関連: ADR 0329、0406

同じ公表PnP IDが複数のpresent機能へ正当に一致する場合、従来のlookupは全opaque関係を
NON_UNIQUEとして保持し、一device用の取得準備を作れなかった。元MULTIPLEをMATCHEDへ
変更せず、DriverStoreが認証した個別観測だけを追加のprivate関係へ投影する。

## 決定

1. DriverStoreだけが構築できるmint keyを持つ不変の`NativeIndexDeviceProof`を追加する。
   同operation/scan/inventory、元公開IDの役割・文字列・Class、owner thread、生存lease、
   callbackの元completed/error、全一致opaque cohortと対象opaque一件を結ぶ。
   元Windows観測から発行するだけで、公開DTOや表示名から証拠を合成しない。
2. 完全な列挙を終え、必要な両native ID属性が成功し、Class観測が正常な個別nodeだけが対象となる。
   未知Classは既存の独立した完全NoDriver/Code28/present/installed-node空/六属性と
   Class/全ID同時観測が成立し、当該公開IDがHardware集合へexact一致した場合だけ発行する。
   元の既知Class専用partial proofを未知Classへ転用しない。他node不足はcompleted/errorに残す。
3. lookupは原aggregate関係を保持する。元tuple/context/cohort/error/completedが一致する
   private証拠を確認した場合だけ、原record位置/hash/source/record/publicIdIndexを所有する
   lookup内部で対象一件の`VERIFIED_DEVICE`関係を追加する。通常uniqueや既存partial-singleは
   二重に投影しない。元aggregateの未知/不足/非一意は成功へ変更しない。
4. 投影も全cohortを保持し、対象一件はproofに完全結合する。同cohortの別deviceへの転用を拒否する。
   同原record/publicId/deviceの重複と全batch上限を検査し、保持するopaque総数32768、
   present4096、共有取得最大32deviceの有限枠を維持する。
5. adapterは投影の原record完全tupleと生存proofを使用時にも再検証する。この新経路は
   STANDARD_INF_ARCHIVEの検査だけに限定し、installerの作用範囲を推測しない。
   同record/deviceに複数公開IDが当たる場合は表示/基本planを一件へまとめ、元関係は保持する。
   同原recordの別投影は、元全文を取得済みで全member検証が成立した同共有bindingの規約を再使用し、
   同じ規約の追加GETを行わない。別recordの許諾取得や同意を同一と推測しない。
   共有取得と導入選択を分け、導入対象は利用者が選択したdeviceだけとする。

署名索引・原hash/期限/世代、実取得byte、全INF/CAT閉包、実Windows rank、同意、復元、
導入直前の同device再検証は変更しない。raw IDを通常UI/log/networkへ追加しない。
生のMULTIPLE、偽造/失効/別contextの証拠は引き続き候補化しない。

## 検証と公開境界

生MULTIPLEの負例、private証拠のtuple/device/cohort/owner/lease改変、未知Classの完全初回、
他node不足、重複公開ID、共有一取得/選択一件/非選択導入0とrank・stale拒否を分離して確認する。
通常本番索引で新appのREADYを確認する。主担当レビュー前の新codeから実driver導入は行わない。
source変更・fixture成功・署名・通常READY・実導入・公開をそれぞれ別の実績として扱う。
