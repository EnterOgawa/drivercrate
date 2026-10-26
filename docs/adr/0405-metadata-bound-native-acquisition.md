# ADR 0405: 新metadataへ取得・内容検査・索引投影を結合する

- 日付: 2026-10-26。
- 状態: 採用。実HTTP・本体取得・fresh発行の成功とは分ける。
- 工程: G13-I7r255h0e0/e1/e2。実使用推論強度max。

## 決定

保存解析v1/v2を次の取得の期待値として使う。公開SHA-256とSHA-512は別々のhexであり、
少なくとも一方を要求し、掲載された全算法の形式と実byteとの一致を要求する。不正な片方を
無視しない。内部archive/receiptのSHA-256は実byteから計算し、公表SHA-512を変換しない。
native承認はtermsと全公開hashに加え、payload URL/file名/package版を新200 recordへ照合する。
commitは共通取得器の全該当algorithm検証済みflagを要求する。

公表exact sizeは任意の正数とし、欠損は未知、0は不正、有限最大128MiB超と期待値の矛盾は拒否する。
概算の表示sizeをexactへ変換しない。共通HTTPの受信上限・truncation/Content-Length検査、
共通file hash・ZIP・INF/CAT/全参照file・Windows署名・OS/x64・driver-only検査を維持する。
保存解析にはexact値がある場合だけ`publishedSizeBytes`を保存する。
native日次のmetadata GETと検査用本体の`OfficialAcquisitionSession` ledgerは別用途である。
本体はunknown exactなら最大値を一file/provider/sessionへ同額予約し、実byteを精算する。
metadataを同ledgerへ重複予約せず、汎用campaignの日次1GiB予約経路へも混用しない。
通常CLIの128MiB予約/最低空き64MiB/一fileとsource待機を保つ正例をfake HTTPで確認する。

監視側の明示scope v2（`dc-metadata-bound-distribution-acquisition-scope-v2`）へ
`acquisitionBinding`を追加する。この閉集合は`expectedRelease`（原byte Base64とSHA-256）、
`selectedInf`（安全なpackage相対path）、`modelSection`（投影する明示Models節）、
`maximumBytes`だけとする。旧scope v1と旧pinは履歴として保持する。
新版の本体hash/実size/INF hash/版/Models/署名を期待値として捏造せず、同runの検査結果から得る。
新scopeのrecord IDは操作者が明示した公開識別子とし、版をcodeへ固定しない。

現行configの`archiveFile/archiveSha256/archiveBytes`は旧原archiveのidentityとして保つ。
新scopeはこれを新payload期待値へ転用せず、scope内のexpected releaseをnative承認へ渡す。
原manual入力はrelease/review/scriptに加えて明示pinした`body`を要求する。
新取得のarchive SHA-256/SHA-512/sizeを有限streamで測定し、同SHA-256の保護copyを既存native
内容検査へ渡す。新検査artifact v3はcopyの実SHA-512も保持し、projectorが全公開hashを照合する。
六入力（scope/evidence/release/inspection/review/script）からの投影は原receiptのbody/版/世代、
expected metadataの全payload binding、同archiveの検査結果、明示INF/Models節に閉じる。
expected releaseの原`observedUtcSeconds`は正の整数文字列として保持し、新しい観測時刻へ書換えない。
この保存metadata宣言の経過24hを、新HTTP receiptのfresh期限へ流用しない。
479の22:04:08Z観測と次回下限の翌22:04:09Z（86401秒差）でも、今回の同意期限を実clockから
24h以内に明示し、今回の新200/内容/規約証拠が成立した場合だけ進む。
署名前の24h窓・8日上限と各原期限の最小値は実receipt/実検査へ適用し、古い期待宣言や
旧manualの原時刻から新しいfresh根拠を生成しない。

## 許諾と公開形式

### 正規設定生成入口

`prepare_daily_index_config.py --inherit-config`は既存v1の同state/output・日程・原receiptと
署名floor/LEGACY_FENCEを継承する入口を維持し、新期待値には`--acquisition-scope`と
`--acquisition-scope-sha256`を明示する。scope v2の原byteを64KiB以内で検証してそのまま
新controlへ保存し、manifest/公開pinと`selectedInf`を照合する。明示scopeをv1へ縮退させない。
`--selected-inf`の省略時だけscopeのselectorを使い、明示値の矛盾は拒否する。

v2では`--original-release/body/review/script`を各`-sha256`との完全な対で要求する。
任意の`--binding-release/body/review/script`も指定するなら四role全部のfile/hash対を要求し、
原manualと技術reviewをそれぞれ原body/原script/六witnessへ結合して同一許諾を確認する。
未知field、不完全対・role、改変hash、保護root外入力、CLI mode混入を新規書込前に拒否する。
全modeの同一CLI option重複は、`--name value`と`--name=value`を同じoptionとして
`preparation_arguments`が`PREPARE_ARGUMENT_DUPLICATE`でparse/file I/Oより前に拒否する。
public contextも同じ診断と順序に従う。異なるmode/意味fieldの混在は既存の専用検査で拒否し、
正常contextの原byte保存と既存出力への再生成拒否は維持する。
旧v1の三入力は既存履歴用だけに残し、旧archive identityを新版期待値へ変更しない。
保存解析やこの設定生成を新HTTP/本体取得/署名/導入の成功や通信許可へ読み替えない。

新mode `PINNED_STATIC_REVALIDATION_V2`とreview v3は、旧manual原byte/時刻/旧bodyを保持する。
旧manualのDOM/script証拠を原bodyで再検査し、新bodyの同じraw許諾文書・全文/revisionと同じ
script byte/六witness・一意な実DOM/新payload linkを再検査する。page本文やpayload版の変更だけを
許諾変更へ数えない。許諾全文、script byte、selector/DOMの意味が変われば手動reviewへ送る。
script更新はcode変更条件ではない。操作者は外部JSONの`originalInputs`へ任意の完全な四入力
`bindingRelease/bindingBody/bindingReview/bindingScript`をfile/hash対で明示できる。
この技術review組の原body/metadata/同一terms・手動六witness/原scriptを再検査し、新しい
script byteの一致先をその組へ結合する。旧四入力と原manual時刻は別に保持する。
不完全な追加組や未レビューscriptへのfallbackは拒否する。実scriptの一致は実試行で判断する。
機械確認時刻を旧manual時刻へ書き換えず、同一許諾への利用者再同意を増やさない。
保存診断bodyを新しいHTTP証拠/authority/grantへ復元しない。

実保存pageには許諾用のほかに補助textareaがあるため、raw許諾documentの同値検査は
`licenseModal`内の一意な`content-raw`だけへ限定する。無関係textareaの本文を許諾へ混ぜない。
対象の欠損・重複・container外と選択した許諾本文の改変は拒否し、原六witness・全文/revision・
DOM/link検査は維持する。この選択規則を人工fixtureにも適用し、旧成功へ無条件継承しない。

アプリの現行索引schemaはSHA-256を扱うため、SHA-512-onlyでは公表SHA-256をUNKNOWNと明記し、
検査済み実archive SHA-256をcalculatedHashへ載せる。公表SHA-512は六入力の検証根拠へ保持する。
両掲載時は公表SHA-256も載せる。アプリの取得時にはこの実byte identityと既存の署名・適用性・
同意・復旧検証を維持し、メーカー固有処理や追加画面を増やさない。

旧scope/receipt/claim/headの原byte・原時刻・原expiry・全世代下限/LEGACY_FENCE・不確定意図、
署名/CAS、24h fresh窓、8日上限、独立producer入力は変えない。別namespaceやcounter resetは作らない。
変更したCollector/Signerは唯一のbuildで再buildしpinを記録する。旧Signer資格を継承せず、
保護runtime/configへの昇格、実署名、実試行、配布物再生成は別工程とする。

## 検証と未確認

架空新版/別file/変動size/明示selectorのSHA-256のみ、SHA-512のみ、両hashを、有限fake HTTPから
実byte SHA-256、内容検査fake/既存INF検査、六入力、共通索引投影まで接続する。
片方不正/欠測/改変、旧archive/receipt混入、metadata/body/terms不一致、未検証INF/署名/期限、
size/予算と全既存安全境界の負例を確認する。実HTML/許諾全文/端末inventoryを公開fixtureへ入れない。
原479は分母1/失敗1/成功0、Intel次回下限2026-10-26T22:04:09Zを保持する。
実取得・新fresh・対応拡大は本工程の成果へ含めない。

関連: [ADR0404](0404-intel-ethernet-published-sha512-parser.md)、
[ADR0403](0403-independent-producer-publication-input.md)、
[ADR0198](0198-published-sha512-acquisition-binding.md)。
