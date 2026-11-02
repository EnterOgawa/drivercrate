# ADR 0418: 署名索引の選択batch内だけのnative proof寿命

- 日付: 2026-10-28
- 状態: 採用（内部検証と実機再試験は別に記録する）
- 関連: ADR 0413、0414、0417

同Hardware ID・異instanceの二deviceを同じ署名索引packageから選択した場合、第一の
指定INF入口が索引inventoryを解放し、ADR0413の個別proofが持つweak leaseを失効させていた。
第二の原record再検証はこの失効でE_ACCESSDENIEDとなり、第二指定APIへ到達しない。
完全低位fakeの三条件で修正前に再現した。実機568の元HRESULTは同値だが、その実発生箇所は
runtimeで記録されていないため、source再現を実機原因の直接観測とはしない。

## 決定

1. 全選択の原record/byte/期限・固有bindingを事前検証した後に、署名索引の私有実行入口だけが
   stack上のscopeを開始する。同scopeは新しいproof、device、candidate、許可を発行しない。
2. scope内では元inventoryをProviderの私有proof専用memberへ移し、強所有をProvider自身だけが
   維持する。個別指定INF入口の既存read-only能力解放は変更せず、必要SWC子の新規bindingへ
   旧scan snapshotの検査を追加しない。scopeはsnapshotを別に強所有しない。全経路のreturn/例外で
   scope終了時に同世代の元inventoryを解放し、残るweak proofを失効させる。
3. 元resolverの能力はscope開始で不可逆に閉鎖する。既存callbackも新callback生成も拒否する。
   新取得は既存closeAcquisitionForInstallの閉鎖を維持する。scopeが新scanや明示失効を妨げず、
   それらは従来どおり元inventoryを直ちに解放する。旧scope終了で新世代を解放しない。
4. 元proofは過去のrecord・device関係を再確認する証拠に限る。各deviceの直前現在状態、
   完全Windows rank、元固有binding、全INF/CAT/member、原hash・署名・期限を引き続き再検証する。
   第一自身やINF登録状態の変化で未変更第二の原取得権限を失効させず、第二自身が変われば拒否する。
5. 未選択deviceへの作用、同名/同Hardware IDだけの導入、無条件retry、権限変更、元HRESULTの
   握潰し、snapshotの無条件trustは行わない。取得共有一回と指定APIはdevice別一回を区別する。

## 検証と残る確認

修正前の原exit/両EOF/実行時byteを保持し、同ID二件の成功と第二APIの原拒否、第二の実状態変化、
scope外・scope終端・新scanのproof失効とresolver閉鎖を別に確認する。既存stale/別device/
未知・曖昧rank/署名hash期限拒否を維持する。実機は一件Code0/一件Code28のまま保持し、
source修正・内部成功・新byte・署名・output更新・実機二件再試験を別の実績として扱う。
