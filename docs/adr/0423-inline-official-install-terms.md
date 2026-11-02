# ADR 0423: 公式取得の規約案内を選択画面とインストールへまとめる

- 日付: 2026-11-02
- 状態: 採用。実装はG13-I7r272b、内部検証は272c、主担当確認と利用者の実UI確認は272v/d。
- 関連: ADR 0144、0329、0421、0422

## 決定

利用者の「製品版だとこれは省いてほしい」に従い、通常の公式取得で独立したEULA同意dialogを
開かない。選択した取得対象に同意が必要なら、主画面に選択件数とメーカー規約への案内、任意の
「規約全文」閲覧を表示し、実行buttonを「同意してインストール」にする。この操作を、画面で
案内した同一scan・計画・選択集合・全文/revision/source/shared tokenに対する明示同意とする。
検索、候補選択、全文の閲覧・終了だけでは同意もpayload取得も導入も行わない。

表示snapshotは現行OfficialPreparationPlan/Targetを端末内で短命に保持する。Install時に現在の
選択identity、plan/session/上限と全target fieldを再照合し、一致した対象だけの同意を既存の
OfficialPreparationApprovalへ結合する。規約未取得、未知、本文差替え、共有token不整合、
選択変更、旧sessionでは旧snapshotから承認しない。新しい選択案内へ更新しても、過去のInstall
同意を保存・流用しない。任意全文は原出典・revisionと原本文をread-onlyで表示し、同意buttonを
持たず、外部linkの実行、network、永続logへの本文保存を行わない。

規約への同意と、CNDA等の契約・組織を代表する権限・用途などの具体的な前提確認は区別する。
既存targetが要求する具体的判断は維持し、通常導線へ汎用の取得概要・対象追加・件数確認は戻さない。
Windows Updateの未受諾条件は既存API/確認契約のままとし、今回WUA本文取得を新設しない。
混在時に残るこの確認と、公式取得の独立EULA廃止を区別して説明する。

元選択だけの予算付き取得、実byte/hash・索引・署名・INF閉包・Windows rank・適用性・proof、
唯一の検証済み候補への再結合を維持する。Client復元ポイント、Server復旧、旧版、必要構成、
公式installerの作用範囲、Windowsのsource/certificate/policy警告は変更しない。取得・検査失敗、
取消し、新検索、close後は自動再試行・旧同意再利用をしない。導入後の限定観測と個別結果を保持する。
製品版と内部検証版で同意の意味を変えない。

これは別dialogを廃止し利用者の明示Install意思へ結合するUI設計であり、個別契約の法的適合を
保証する判断ではない。Intel公式配布ページの規約本文をsourceへ転載しない。
参照: [Intel公式Windows 11ネットワークドライバー配布ページ](https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html)。

## 有限な検証と戻し方

既存の完全fakeでSearch後dialog0、選択案内、Install時の独立EULA0、任意全文閲覧だけでは
取得/同意/導入0、複数対象と共有payload、選択変更、規約差替え/欠落/未知、stale、取消しと失敗を
固定して確認する。実通信・実復旧・実driver導入・署名・公開を内部試験に含めない。
戻す場合は主画面の案内snapshotと通常Installからの結合を旧dialogへ戻す。worker検証、保護store、
索引形式とProvider導入許可は変更しない。
