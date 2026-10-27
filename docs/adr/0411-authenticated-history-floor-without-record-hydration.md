# ADR 0411: 履歴headの下限認証と現在snapshot復元を分離する

- 状態: 採用
- 日付: 2026-10-27

本番の世代5 headはroot/ACL/DPAPI/wire/plain digest・原manifest署名/発行時刻・gzipと
展開hashが正常だが、旧recordに現在必須のnestedArchiveIdentityがなく現在codecが拒否する。
現codec拒否を維持し、下限回収のために旧readerやfieldの暗黙補完を追加しない。

保存headの下限認証は既存の実root/祖先/ACL/share0 lock/DPAPI、strict wire/version/digest、
固定公開trustによる原発行秒でのmanifest認証、世代/publishedSeconds/manifestHash、
assetGeneration・gzip署名size/hash・有限展開/CRC/ISIZE/末尾・wire.indexHashと展開hashの結合を要求する。
内部の履歴下限型は認証済みwireだけを所有し、record/receipt/snapshot/install grantを持たない。
既存共通manifest/asset APIを再利用し、collector署名module・秘密鍵機能をアプリへリンクしない。

Store.openの成功は保護storeと履歴下限の認証であり、現在使用できるcacheを保証しない。
reloadは下限を保持した後、元manifestの現在期限と現在codecの全record/schema/attestationを
再検証する。失敗時snapshotなし・認証済みpersistedGenerationと元拒否を返し、genesisへ戻さない。
fresh commitは同じlock内で下限を再読取りし、現在時刻・全record・attestation・原byteの全検証を
満たす場合だけ既存stage/write/flush/atomic rename/readbackへ進む。
下位世代・同世代異manifest/gzipを拒否し、不正freshでheadを変更しない。

同世代同byteのNO_CHANGEも保存headを現在の全検証へ通してからsnapshotを返す。
commit後readbackも下限認証だけでは成功にせず、原envelope/gzip/manifest/展開hash一致と
現在hydrationを必須とする。既存NO_CHANGE/COMMITTED_NO_SNAPSHOT/COMMIT_UNCERTAINと
世代報告の意味、transient HTTPだけのcache使用条件を維持する。
旧recordの利用可能性、期限延長、root移動/reset、世代下限削除を追加しない。

受入は人工旧recordの下限保持/snapshot拒否とN+1成功、不正headの下限拒否、不正freshの書込0、
既存保護/atomic障害/HTTP回帰、および通常appでの本番5→9を別々に記録する。
最終公開sourceのfresh資格や配布byteの受入へ過去の合格を継承しない。
