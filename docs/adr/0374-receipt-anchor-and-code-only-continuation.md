# ADR 0374: receipt保護anchorと一段だけのcode-only修復継承

日付: 2026-10-18
状態: 採用。実保護配備・実再開は未実施。

## 背景

ADR 0373の実取得はgeneration5のreceiptを生成した後、operation directoryを
`protected_path`のrootへ渡して停止した。rootは包含下限ではなく、DACL保護必須の専用anchorと
厳格な内容変更maskの境界である。operation directoryの継承DACLへ保護flagを要求するのは誤り。
ACL policyは変更せず、operation_rootによる包含と専用rootの保護検査を両方維持する。

修正によりcode/config hashが変わる。旧acquisition.startは元configの全byteへ結合済みであり、
書換え・削除は許さない。元legacy fence4のnative検証はhead5と一致しない。fenceを5へ上げると
取得receipt5を新規導入対象として扱えないため、初期inherit prepareを繰り返す方法は使わない。

## 決定

既存v2から一段だけ、明示`--repair-config`でcode-only継承を準備できる。前config/start/receiptの
pathと期待SHA-256を明示し、前configの旧四module・binaryを旧pinで実読検証する。前configに
既にcodeRepairがあれば拒否する。新codeの四moduleとbinaryは現pinで別検証し、変更可能箇所は
pipeline/preparer byteと同version配置pathだけ。projection/registry、scope byte/hash、native binary
hash、入力、key、state/output、日程、terms、legacy binding/fenceは完全一致を要求する。

前startは既存legacy startの原byte hashと前config hashへexact照合し、receiptは同operationの
当日成功観測一件へexact結合する。元fenceは履歴として保存し、現在のreceiptについて既存nativeの
FRESH_INPUTで現head/run全byte・契約・元notBeforeを検証する。旧署名historyも既存nativeで検証する。
これは旧fenceと現headが等しいと主張する初期inheritとは異なり、metadataを取得成果へ昇格しない。

新configは閉fieldのcodeRepairに前config/start/receiptのexact pinと既使用予算を保存する。
実行時も前chainと現codeを再検証し、同じglobal lock内でFRESH_INPUTを行ってから、同じ日付の
`.acquisition.code-repair.json`へ新config hashをexact記録する。元startは保持する。別日、root、nonce、
receipt、旧pinの無効化へ逃げない。同じcollection/terminal/claim/成功output名前空間と既存署名profile、
部分失敗・未知署名拒否、CASを維持する。既存成功receiptを使い、daily-evidence再収集は呼ばない。

1800秒/96 native call/32日次attemptと元観測windowを維持する。前実行の実測既使用call/秒を
明示入力し、継承prepareの実測分を足して新configへ保存し、新runの実Budgetから控除する。
この会計は管理対象の明示callと測定区間であり、全OS processや全再開履歴の証明ではない。
前実行は1call/0.7296035秒。新しい制御配置・実prepare・実runは主担当受入後の別工程である。

## 検証と制限

実protected_path/check_aclへ人工ACL snapshotを接続し、旧callが継承operation DACLを拒否し、
専用rootのcallが通ることとowner/write/ancestor/hardlink/reparse/包含拒否を確認する。
既存fixtureで正当な継承、前chain/意味入力/native/head変更拒否、同byte再開、再収集なし、
重複署名なし、部分・未知claim、lock/day/expiry/HOLD/予算を確認する。fixtureは実成功ではない。
本ADRはアプリ/native変更、Task、鍵変更、実導入、公開を許可しない。
