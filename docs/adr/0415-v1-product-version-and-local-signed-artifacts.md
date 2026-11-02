# ADR 0415: 初回製品版1.0.0と署名済みローカル配布物

- 日付: 2026-10-27
- 状態: 採用、最終byteの検証と公開承認は別途

## 判断

利用者の「今署名できる環境なので先に署名だけしておきたい」「初期バージョンv1.0.0」に従い、
CMake製品版を1.0.0へ変更し、App、Collector、内側setup、外側setupの実使用版情報と配布名を揃える。
製品版を持たなかったCollectorと内側setupへ、同じCMake生成値のVERSIONINFOを最小限追加する。
独立したsource file版、package-v7、receipt-v3、索引schema、第三者runtimeの版は変更しない。
通常source buildは証明書不要とし、ADR0406の任意CodeSigning経路で新しい未署名buildを一度だけ署名する。
実署名・時刻証明・元image保持とpackage全hashを確認してから署名済みと記録する。

## 境界

旧source履歴、署名済み成果物、Task、保護runtime/store/dataを上書き・移動・削除・自動移行しない。
現行package-v7/receipt-v3の所有・同意・待機・期限・世代下限・索引署名と端末適用性を維持する。
索引署名とAuthenticodeは別用途であり、今回の署名準備で索引を再発行しない。
メーカー別機能、互換layer、driver導入、Task操作、収集を追加しない。

README等は1.0.0の配布手順と現在の公開状態を区別し、未公開binaryを入手可能と記載しない。
既存の索引10公開（3record/2source）と0.1.1一件実導入の有限実績を説明できるが、
新1.0.0 byteの実導入成功や全機器保証へ継承しない。通常日次の未署名候補という意味は維持する。
最新公開候補集合自身を唯一build treeのsourceにして必要なDebug/Release検証を行い、
最終byte・同梱文書・checksum・source由来をローカル記録で結ぶ。
remote push、tag、Release、asset公開は今回行わず、具体的成果物の確認と別の明示承認に残す。
