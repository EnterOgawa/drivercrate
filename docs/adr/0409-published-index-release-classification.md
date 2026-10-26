# ADR 0409: 公開済み索引のRelease分類と読取条件

- 日付: 2026-10-26
- 状態: 採用、実装・有限受入は別記録
- 対象: G13-I7r255h0g2ps0e2

## 実原因

正常prepareが読んだ既存索引Releaseは`draft=false`、`prerelease=false`だった。
索引branchが指す旧世代5は失効済みであり、現在の取得許可ではなく世代下限としてだけ読む。
既存current readerは`prerelease=true`も要求していたため、assetの取得・署名履歴認証と
世代予約より前に`CURRENT_RELEASE`で停止した。原失敗・原応答を保持し、remote設定は変えない。

## 判断

[GitHub REST Release公式仕様](https://docs.github.com/en/rest/releases/releases#create-a-release)は
`draft`を未公開/公開、`prerelease`をプレリリース/正式版の識別とし、`make_latest`も別に扱う。
本アプリケーションの索引の信頼根拠は、固定repository/actorの実identity、索引専用branchの
一file、固定形式の索引tag、完全な二assetの名前/state/size、current envelopeとのbyte一致、
配布専用鍵の署名・gzip/hash・用途・世代/期限の通常native認証である。
Releaseの正式版分類を、これらの検証結果の代用にも拒否理由にも使わない。

## 決定

`Publisher.current`の読取は、`draft is False`、`prerelease`が厳密なbool、
`tag_name`がcurrent manifestの固定索引tagへ完全一致する公開済みReleaseだけを受理する。
`prerelease`のtrue/false双方を扱い、不在・null・数値・文字列は拒否する。
返却tagとの明示一致を加え、任意の正式版Releaseを索引へ採用しない。

固定Public identity、tree/blobの閉集合、tag形式、asset名前/一意性/state/正size/完全集合、
current/Releaseのenvelope一致、通常nativeの署名/hash/用途/世代・historical時刻認証は維持する。
失効した旧currentはhistory/high-waterだけで、現在有効な索引や新観測へ読み替えない。
draft、asset不足/差替え、不正署名、同世代衝突、後退・不確定CASを救済しない。

新しい索引Releaseを`prerelease=true`、`make_latest=false`で作成・公開する既存writerの
方針と、原assetを上書きしない規則は変更しない。既存remoteのmetadataを書き換えず、
currentを模造するtransportや別namespaceも追加しない。

条件変更後の再評価は、同じ原二件・原expiry・fence8・全claim履歴と元失敗を保持し、
元8callと元開始時刻からの96call/1800秒予算を保守的に継承する。
現source/保護module/configを新名へ正規配置し、同じnormal preparer/prepare/signを使用する。

## 有限確認

正式版/プレリリースの両current、draft/不正型/返却tag差、asset不完全/差替え、
native verifier拒否と世代/CASの回帰をfakeで検査する。新Release writerのprerelease方針も確認する。
実GitHub読取り・専用CNG署名・通常現在validatorの結果は人工試験と分ける。
