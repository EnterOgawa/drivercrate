# ADR 0380: 署名索引の用途別storeと旧storeの認証移動

- 日付: 2026-10-19
- 状態: 採用（実装前に記録。隔離回帰と、このPCでの有限な実移行・通常配布再受入を確認）
- 関連: ADR 0329、0337、0348、G13-I7r231h15s10e1

## 原因と決定

従来の固定`SignedIndex-v1`はlocal acceptanceと通常配布で共用されていた。
通常配布のtrustは旧local署名を認証しないため、受信した正常な索引も既存headの
履歴再認証で停止する。DPAPI整合やkeyIdの申告を旧署名の真正性として扱わない。

通常配布は同親の`SignedIndex-distribution-v1`を使用する。検証用は公開鍵の完全
SHA-256を含む`SignedIndex-local-<fingerprint>-v1`を使用する。通常配布のrootは
配布鍵の更新で変えず、同じdomainの世代下限を継承する。検証用と配布用の世代は
独立し、検証用世代5は配布用世代5の同世代上書き許可にはならない。

旧rootが残っている間、通常のopen/reload/commitは明示移行待ちで拒否する。
新rootだけを作って旧productionの世代下限を無視する経路を設けない。

## 明示移行と保全

配布とは別の明示CLIは、事前に確認した旧headの完全SHA-256を要求する。
公開blobは既存の非秘密fileから確認した旧local鍵を移行専用の固定集合へ登録する。
通常のmanifest trustと取得許可集合へは登録しない。通常配布鍵も移行専用集合に
明示登録し、実署名認証したkeyIdから移動先domainを決定する。任意path、利用者入力の
公開鍵、未知keyIdからtrustを構築しない。

旧rootは既存のpath/NTFS/owner/DACL/reparse/単一link/DPAPI/strict wire検査に加え、
署名発行時点で実署名・gzip・全record schemaを再認証する。期限切れの履歴を現在有効な
snapshotへ変換しない。未来発行は現在UTCとの比較で拒否する。署名認証した世代だけを報告する。

旧directoryの保持handleをDELETE権限付きで取得し、祖先をpinし、旧store.lockを
share0で保持する。最終操作前に同handleのidentity/path/ACL、原head hashと全認証を再確認する。
NTFSは開いた子fileを含むdirectory renameを拒否するため、最終確認後に子head/lockのhandleを
閉じる。DELETE権限付き・DELETE非共有のroot handleは旧/新store ownerと両立せず、
renameまで排他とdirectory pinを維持する。通常storeのshare0契約は変更しない。
同親への`SetFileInformationByHandle(FileRenameInfo)`をReplaceIfExists=falseで一回だけ行う。
既存destinationはmerge/上書きせず拒否する。旧directory identityとhead/lock byteはそのまま
移動するため、root identityに結合された既存DPAPI entropyと世代下限を保持する。
旧pathは消失し、旧dataは用途別pathへ保全される。削除、reset、再暗号化、headの書換えはしない。

rename前の中断は旧名、rename後の中断は新名が正本となる。新名から同じ期待head hashと
全履歴認証を確認できる明示再実行だけをalready migratedと報告する。新旧両方の存在、
destination競合、未知署名、壊れたwire/DPAPI、ACL不整合、異なる期待hashは拒否する。
rename API失敗は結果不確定として報告し、旧名が残ったと推測しない。自動rollbackはしない。
旧binaryを同時稼働しないことを移行手順へ明記する。新入口は操作開始とhead切替前にも旧rootの
再出現を拒否し、旧binaryが再作成したstateを黙って無視しない。

## 有限確認

架空RAM鍵・自作NTFS/DPAPI隔離rootで、期限切れ履歴のlocal移動、production移動、
byte/identity/floor保全、別domainの同番号受理、同domainのrollback/同世代異内容拒否、
移動前/後の中断と再実行、両側競合、別鍵/破損/DPAPI不整合/hash不一致、実lock競合を確認する。
対象Debug/Releaseと変更source品質を確認し、全CTest・公開snapshot・実PC移行と通常appの
再受入は後続に残す。実導入、秘密鍵照会、Task/remote変更はこの工程に含めない。

本工程では同じ製品namespace処理へ人工RAM trustを限定注入し、旧store313 assertionと
新移行89 assertionがDebug/Releaseとも失敗0となった。署名/asset/fake refreshの466 assertionも
両構成で失敗0である。実際の旧local署名の真正性はこの人工試験で確認したとはせず、
このPCの明示移行で独立認証する。通常manifest trust/取得認可は変更していない。

API仕様: [FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)、
[SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)。

## 2026-10-19の有限な実受入追記

主担当確認後、このPCの旧検証用storeを実署名認証し、元head/lock byteと世代下限5を保って
用途別名へ移動した。通常配布storeでは別domainのPublic世代5をHTTP 200で取得・保存した。
通常画面で1 packageの実取得・内容検査と1機器への標準INF旧版候補3件を確認した。
72 INF中57件が内容・署名検査に合格し、15件の未解析・未対応と全体部分結果を保持した。
候補は未選択、実導入0であり、全store・別PC移行や全機器の保証へは換算しない。
全target・全CTest・変更後公開snapshotの受入は別の記録で確認する。
