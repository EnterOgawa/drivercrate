# ADR 0406: 検証済みAuthenticode遷移を配布byteへ結合する

- 日付: 2026-10-26。
- 状態: 採用。実装・人工回帰と実EV署名/配布物の受入は分ける。
- 工程: G13-I7r255h0g1b0/b1/b2/b3。実使用推論強度max。

## 決定

利用者の「現在は署名可能な環境です」によりコード署名をリリース準備へ戻す。
通常のCMake/source buildと既存未署名開発packageは証明書不要のままとする。
アプリ/Provider/収集対象、C++/link flags、package-v7/receipt-v3を変更しない。
三package builderに明示的な任意`CodeSigning`入力を置き、共有build helperだけで署名する。
証明書thumbprint、store、SDK signtool pathと実SHA-256、RFC3161 timestamp URLを操作者が指定する。
`CodeSigning`は`CertificateStore`（`CurrentUser`または`LocalMachine`）、
`CertificateThumbprint`（40桁hex）、`SignToolPath`（絶対path）、`SignToolSha256`（64桁hex）、
`TimestampUrl`の五つのstring fieldだけを持つhashtableとする。未知field/不完全指定は拒否する。
個人の値、秘密鍵、PFX/password、既定証明書やTSA URLをsourceへ埋め込まない。

### 内側PEと既存v2 profile

app/collector/inner setupの固定Release role/pathを選び、既存source/build resolverの通常構成と
`Assert-IndexPackageExecutable`の原全byte hash/x64/閉field v2/profile/公開policyを検査する。
このrole一覧へ第三者runtime、任意path、任意sourceや別buildを追加しない。
既存profileはroleを宣言しないためroleをprofileから推測せず、builderの固定入力pathへ束縛する。
署名済みPEの再署名は拒否し、新規stagingへ原PE/profileを保存して原入力を変更せず署名する。

SDK toolの明示hashとWindowsの有効なMicrosoft Authenticode署名、選定したMy store一件の
CodeSigning EKU/期間/非自己発行/秘密鍵有無を確認する。鍵使用前にWindows trust storeと
online revocationによるCodeSigning chainも検証する。秘密鍵をexportせず、`/sha1`でその一件を
指定し、`/fd SHA256 /tr <明示URL> /td SHA256`を使う。署名/検証の原exitが0以外なら拒否する。
環境・chainの検証関数は成功時に値を返さず、失敗時は例外で通知する。
環境/chain確認中の原PE変更で未検証byteを一度でも署名しないよう、stagingへcopyした直後かつ
署名命令の前にcandidateと原PEの実SHA-256を原v2/原buildの期待hashへ再照合する。
不一致時はsignを呼ばず、元profile/検証後CASや署名後の厳格な比較も維持する。
`signtool verify /pa /all /tw`の既定Authenticode/WinVerifyTrust policyと、Windowsが返した
有効なembedded signature、指定した署名証明書、CodeSigning EKUとtimestamp証明書を確認する。
catalog fallback、test root、allow-unsigned、trustを緩めるoptionは設けない。

Windowsの有効署名だけでは元buildとの同一性を保証しないため、別にPEの遷移を検査する。
原PEはx64/PE32+かつCertificate Tableなし、署名後は同じheader layoutでなければならない。
原全byteのうち変更可能なのはOptional HeaderのCheckSum 4byteとCertificate Table directory
8byteだけとし、その二範囲を除く原長までの全byteをSHA-256で比較する。section/resource/
overlay/debugを含め、Authenticodeのhash対象外になり得るbyteも元のままとする。
末尾の0〜7byteのzero alignmentと、一個の整列済みWIN_CERTIFICATEの追加だけを許可する。
途中への挿入、既存certificate、追加trailer、table外data、複数certificateや過大入力は拒否する。
この比較を署名検証の代わりにせず、署名検証も内容比較の代わりにしない。

両方の検査後、原PE/profileのCAS hashを再確認し、署名後の実全byte SHA-256だけを原v2の
`sha256`へ更新する。schema/他field/公開policy/roleを再解釈しない。新profileは既存guardへ
再度通す。二fileの更新は一つのOS transactionではないため、PE後/profile前の失敗は原backupと
stagingを保持し、その不整合を既存hash guardで拒否する。無条件再発行や成功への自動rollbackはしない。
再buildで署名が消えた場合は再度原正常buildから署名する。過去の署名資格を新byteへ継承しない。

### packageとouter

順序は内側PE署名/検証→署名後profile→既存copy/manifest/ZIP/checksum→resource生成/
outer build/`--check-embedded`→outer署名/検証→最終checksumと`installer-build.json`とする。
最初の二builderは引き続きbuildせず、第三だけが既存outer targetをbuildする。
署名指定された第三builderは内側の自作二PEも同じ指定証明書/timestampで検証してから埋め込む。
第三者Python runtimeのarchive/34原file/署名/manifestは署名対象にせず、元hash検査を維持する。

outerには既存CMakeのv2 profileがない。新しい疑似profileを発行せず、既存builderが検査した
同source・同内側PE・全manifest/resource pinとfresh outerの実原hashへ結合して署名だけの遷移を
同じ比較器で検証する。outer署名後の実byteからchecksum/sizeを計算し、`signed=true`は実検証結果
がある場合だけ記録する。要求flagだけで成功にせず、署名前checksum/`signed=false`を使い回さない。
署名後にresource編集やouter再buildを行わない。署名に伴うTSA/chain通信はdriver収集と別である。

## 検証と実運用の境界

隔離tempの人工PEと模擬Wintrust/署名toolで、変更許可範囲/section・resource・overlay改変、
wrong role/profile、原hash不一致、失敗/未署名/誤証明書/期限/EKU/timestamp不足、昇格とpackage順序を
決定的に検証する。fixture成功を実EV/chain/鍵利用/TSA成功へ数えない。
この採用時点では実EV署名、鍵access/export、TSA POST、実配布物生成を行っていない。
最終sourceの確認後に実SDK trust/鍵可用性/chainと正規TSA手順を再確認する。
索引CNG鍵は別用途のまま、元receipt/head/世代下限/待機/同意/期限を維持する。

## 一次資料

- [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool):
  `/pa`の既定認証policy、catalogを指定しないembedded検証、`/tw`の警告と原exit 0/1/2。
- [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format):
  CheckSum/Certificate Tableの除外とcertificate整列。元byte比較はこの署名hashより厳格に行う。
- [Microsoft Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature):
  Windowsの署名状態とcatalog優先動作。helperはembedded種別を明示確認する。
- [GlobalSign: Microsoft SigntoolによるCode Signing](https://support.globalsign.com/code-signing/code-signing/code-signing-windows-7-8-and-10):
  token-based署名、RFC3161 `/tr`とSHA256 `/td`の手順。TSA URLは実署名工程で公式の現行値を
  確認して操作者入力へpinし、このADRの採用やdocs GETをTSA成功とはしない。
