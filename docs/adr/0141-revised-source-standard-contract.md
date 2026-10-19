# ADR 0141: 改訂ソース規約と全自作source再移行の契約

> 公開版の読者へ（2026-10-18）: 本ADRの355 fileと結果は2026-09-11の移行時点の記録であり、
> 現在のsource数や全診断ゼロを意味しない。採用契約・法的表示・当時の決定は変更していない。
> 現在の必須gate、任意診断と未受入は[テスト方針](../testing.md)を参照する。
> 保守用AGENTS／ロードマップ／当時の実施記録は公開用sourceの必須入力ではない。

- 日付: 2026-09-11
- 状態: 採用・実装済み。全355自作sourceの移行とlocal受入検証を完了した。
- 対応工程: G12-X4e-02l0、追補02l0a・02l2a0、実装・移行・検証02l1～02l7。

## 1. 背景と今回の範囲

利用者は2026/09/11に、フィールドと列挙値の前置`///`、指定著作権行、
`Ver.01.00.00`形式の更新履歴を承認した。さらに「1番を進めましょう」により、
大量変換の前に規約の競合を確定する工程を選択した。

現在の自作source列挙は355fileである。2026/09/10の02kの移行結果を取り消さず、
その後の規約改訂を02lとして扱う。355という数を将来の固定上限にせず、移行開始時に
追跡・未追跡双方の対象を再棚卸しする。実装動作、Provider、安全境界、公開APIは変更しない。

02l0時点の`check_source_standard.py`は、見本の独立版数と指定著作権行を旧契約で拒否した。
02l0実施時のread-only検査は355file・6,433制御文・620 case・2 errorだった。
これは新版不適合の全件数ではなく、当時の旧checkerが検出した範囲だけである。

## 2. 正本と適用範囲

1. 言語・Windows ABI・第三者権利・製品安全境界は書式変更で上書きしない。
2. 最新の利用者明示指示、DriverCrate固有設定の`AGENTS.md`、
   `docs/c_cpp_coding_standard.md`本文の順で適用する。
3. `docs/examples/c_cpp_coding_standard_sample.cpp`を実例とし、本文の規則を確認する。
   本文が規定しない折返し・初期化リスト配置は第5節の整形契約へ従う。
4. `docs/c_cpp_comment_standard.md`は旧案であり、採用規則を追加・上書きしない。
   02kの過去の検証記録も、02lの現在の検証成功を示すものではない。

対象は`src`、`tests`、`cmake`、`docs/examples`の自作C/C++、resource、生成元template。
拡張子と除外directoryの列挙は`source_style.source_paths`を共有し、tool別の独自リストを
作らない。CMakeやresourceが要求する既存file名も改名しない。
第三者source、旧SDIO参照、取得済みvendor payload、生成済みfile、build出力は除外する。
Markdownの短い例は規則を説明する抜粋であり、単独でcompile可能な完成品とは扱わない。

## 3. 製品版とファイル版の分離

- 製品版は引き続きCMakeの`project(VERSION)`を正本とし、現在の`0.1.0`を変更しない。
  EXE VERSIONINFO、UI、計測report、package、tagの製品版とファイル版を混同しない。
- ファイル版の`@version`はASCII数字2桁×3要素の`XX.YY.ZZ`。
  新しい更新履歴の各行は`Ver.XX.YY.ZZ`とし、最後の行と`@version`を一致させる。
- 新規fileは`01.00.00`。小規模修正・書式・コメントだけの改訂は第3要素を増やす。
  機能追加は第2要素を増やして第3要素を00へ戻す。非互換変更は個別判断で第1要素を増やす。
  数値tupleで単調増加させ、同じ版を別履歴へ再利用しない。
- 各要素は00～99。下位要素の99からは直上へ繰り上げ、下位を00へ戻す。
  `99.99.99`の次は自動採番せず規約変更を判断する。書式都合の繰上げを機能変更と説明しない。
- 一つの論理変更を編集中に保存・整形・testを繰り返しても、その変更の版数を何度も上げない。
  確定後の別変更では次の版を採番する。内容不変のformatter再実行で履歴を増やさない。
- `@date`と既存のauthor・日付・理由は保持する。過去履歴を架空の連番に置換しない。
  既に新形式の見本の`01.01.00`までの履歴は保持した。02l0bで実際にheaderを修正したため、
  新しい`01.01.01`の履歴を追加した。file版を文書版へ一致させる必要はない。

### 3.1 旧製品版履歴の移行

既存sourceには同じ`Ver.0.1.0`を再使用した履歴や日付順でない履歴がある。
これを`Ver.01.00.00`へ一括置換して過去の独立file版だったように見せない。

旧履歴はfile header内の`@par 移行前更新履歴（製品版）`と`<pre>`へ、
行の内容・順序を保って移す。現在の`@par 更新履歴`には独立file版の初回として
`Ver.01.00.00`を記載し、「独立ファイル版と改訂コメント規約へ移行。」等の実際の理由を残す。
`@version`を`01.00.00`にすることは製品版の更新を意味しない。
旧履歴の比較対象は02l1で保存する開始時点の内容とし、Git HEADで代用しない。
旧履歴を持たない新規fileへ空の移行前節を作らない。

## 4. 著作権行とLICENSE

02l0では会社表示とMIT許諾を採用した。その後、利用者がApache-2.0と、年を2026と明示したため、
追補02l0aで自作部分の採用ライセンスをApache License, Version 2.0へ変更する。
これは著作権者名だけの変更ではなく、MITからApache-2.0への採用契約の変更である。

利用者が一ファイル試行後に見本headerを手動で整理し、続けて01.01.01の履歴追加と
全sourceへの修正を指示した。この最新の見本を採用形とし、著作権をDoxygenの
`@copyright`、許諾条件を独立した`@par ライセンス`として次の順序で記載する。

```text
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * https://www.apache.org/licenses/LICENSE-2.0
```

`All Rights Reserved.`、旧MITライセンス節、タグなしCopyright行は新しいheaderへ併記しない。
`@copyright`は`@author`の直後に一件だけ置き、ライセンス節との間に空行を置く。
ライセンス節、SPDX行、日本語の適用説明、ルートLICENSEの案内、Apache公式URLは
各一件をこの順序で記載する。`@par 会社名`の`EnterSystem`はライセンス節の後に置く。
`@author`と新履歴authorは`Shunji Ogawa`を維持する。
2026は利用者指定の権利表記年であり、file追加日・作成日・過去履歴を書き換える根拠にしない。

[Apache公式FAQ](https://www.apache.org/foundation/license-faq.html)は、
自作ソフトウェアにLICENSE全文を添付し、CopyrightとSPDX識別子の短縮headerを使う方法を示す。
識別子の正本は[SPDXのApache-2.0](https://spdx.org/licenses/Apache-2.0.html)とする。
ルートのLICENSEには[公式の英語全文](https://www.apache.org/licenses/LICENSE-2.0.txt)を
改変せず保存し、付録のplaceholderも公式文のまま残す。会社の表示はREADMEと自作headerに置く。
LICENSEの恒常的なLF保存は`.gitattributes`でも指定する。

第三者notice、原著作権者、取り込んだ原文の許諾条件は変更しない。
minizのMITやLZMA SDKのpublic domainをApache-2.0へ一括置換しない。
既存のTHIRD_PARTY_NOTICESを保持し、今回新たなNOTICE fileや広告・事前許可条件を追加しない。
第三者のNOTICEが必要な資産を後で追加する場合は、原文と配布要件をその工程で確認する。

利用者の一ファイル試行指示により、02l0bではCPP見本一件のheaderだけを先に更新した。
その後、その他のsourceへの実適用を02l4、独立検証を02l5／02l6で完了した。
見本試行時に残ったformatter差も現行toolの固定点へ正規化済みである。既存の配布物やGitの
過去履歴は遡及して書き換えず、今回のlocal変更をremote push・公開の承認とも扱わない。

## 5. formatterの契約

JNI Native由来の採用書式を維持し、標準clang-format単独の出力へ規約を変更しない。
`.clang-format`と`scripts/format_source.py`／`source_style.py`を一組の実装とする。
toolの現在の出力が規約と違う場合は、規約を緩めずtool側を修正する。

- UTF-8 BOMなし、LF、indent・整列はタブ幅4。行長は100を目安、120以内を推奨する。
  既存の`ColumnLimit: 100`、`UseTab: Always`、`ReflowComments: false`を基準にする。
  タブで到達できない継続列への残り空白は許可する。literalを折返しのため分割しない。
- 関数開始braceは次行、制御文・型・namespace開始braceは同じ行。
  引数のある呼出し・宣言・制御構文は開始丸括弧内に一空白、閉じ側は空白なし。
  空引数は`()`。実行文・宣言の`;`の前は一空白。for区切りはこの規則の対象外。
- 算術・比較のグループ括弧は`(value - limit)`のように内側へ空白を付けない。
  `>`／`>>`だけでtemplate呼出しと判定せず、比較式と区別する。
- フィールドは個別の`///`と宣言を一体として扱う。同じ型・access区分内で連続する
  data memberの論理groupは、個別`///`やgroup内の一空行を挟んでも識別子をタブ整列する。
  method、別の型、access label、preprocessor、明示sectionでgroupを終了する。
  複雑な複数行宣言は無理にgroupへ吸収せず、独立して整形し、説明の関連付けを保持する。
- `///`を行末へ移さず、説明対象との間に空行を挿入しない。複数行説明を結合しない。
  型・関数のDoxygen、`<pre>`履歴、raw string、macroの論理行を保護する。
- 上記で決まらない継続引数の位置、集約初期化リストのbrace配置は基本formatterへ委ねる。
  見本を後続で一度正規化し、その正規化済み見本をbyte単位の固定点fixtureにする。
  値・順序と14ケースの一行一ケースの可読性は維持する。
- 日常formatterは空白と既存コメントの配置だけを扱い、版数・著作権・説明内容を
  自動変更しない。意味のあるC/C++ token、literal、preprocessor論理行の変化を拒否する。
  不完全構文、編集競合、有限回内で非収束・循環した場合も書込み前に失敗させる。

今回、実際のwrapperで見本をメモリ上だけ整形し、5差分領域を確認した。
フィールド整列3行の消失と比較式内グループへの余分な空白は修正対象。
継続引数のタブ化と配列brace配置は上記の一度の正規化対象とする。
コード・見本・formatter設定は02l0では変更していない。
後続の02l0bでは見本headerだけを変更し、本文のこれら5領域は保持した。
02l0cのformatter checkは差分ありであり、規約への完全適合や固定点合格とは扱わない。

## 6. コメントとcheckerの契約

- class／struct／unionの名前付きdata memberとenumの各列挙値は、公開・非公開、
  static／constexprを問わず宣言直前の`///`で個別に説明する。local classも含む。
  `//`、行末`///<`、型全体の説明だけでは代替しない。
- ファイル、名前付き型の契約、関数・methodは`/** ... */`。
  local・namespace／file-scope変数・定数、macro、処理説明は`//`。
  classの定数はdata memberの規則を優先する。引数は関数の`@param`で説明する。
- 既存の安全境界、所有権、失敗時動作を失わず、現在のcodeに存在しない保証を補わない。
  anonymous／macro生成／条件付き宣言を字句だけで分類できない場合は個別に監査し、
  未判定を合格や対象0件へ置き換えない。
- metadata検査はCMake版との一致と旧MIT文字列の必須条件を廃止し、
  block comment内の指定`@copyright`、ライセンス節、SPDX行、適用説明、LICENSE案内、公式URL、
  `@file`、作成日、氏名、会社、独立版数、新履歴の一意性・単調増加・末尾一致を検査する。
  検査中にsourceを更新しない。新履歴と移行前履歴を別にparseし、旧版の重複を
  新履歴の例外として許可しない。移行前節への新しい変更行の追記も許可しない。
  各必須項目はheaderに一件だけ、上記の順序で記載する。年や識別子の相違・欠落・重複、
  タグなしCopyright、自作headerへの旧MIT／All Rights Reserved併記を拒否する。
  第三者と履歴記録は別に扱う。
- コメント・空白以外のtokenは今回の移行前後で完全一致させる。命名やbrace不足が
  見つかった場合は別工程へ事前登録し、無審査のtoken例外にしない。

### 6.1 Doxygenによる抽出確認

既存の「通常コメントが近くにある」検査だけではフィールド文書化の合格としない。
現行sourceから生成したXMLを使用し、`EXTRACT_ALL=NO`、private／static／local class／
anonymous namespaceの抽出を有効にする。全名前付きdata member・enumvalueについて、
空でないbriefまたはdetailed descriptionが正しい宣言へ関連付いていることを確認する。

文書がない要素はXML自体から消える場合があるため、独立に列挙した対象宣言との突合が必要。
XMLファイルなし、古いhash、解析対象欠落、fixture要素0件を成功にしない。
sampleの4列挙値＋3フィールド、private／static／union／local class、複数行説明、
通常`//`・行末`///<`・空行・別宣言への誤関連付けのnegative fixtureを持つ。

全体監査では解析設定、入力hash、対象・抽出・未文書化・未判定件数を記録する。
preprocessorで落ちる宣言も棚卸しと照合し、必要な構成を追加する。
parser制限は対象を列挙した個別レビューで解決し、警告を隠す設定や包括除外で合格にしない。
通常のlocal変数・macroの`//`は引き続き字句検査と内容レビューで確認する。
この厳密な抽出gateは今回の移行の必須受入条件として実装し、全対象へ適用した。

## 7. 実装・移行の受入条件

1. 02l1で開始時点の全対象・除外・hashと既存の未commit変更を保存する。
   過去の02k退避を現在のbaselineとして使わず、コピー先の上書きも避ける。
2. tool修正前に失敗を再現し、版数・履歴・コメント分類・5整形領域・Doxygen抽出の
   positive／negative fixtureを追加する。既存のliteral保護・回帰testも維持する。
3. tool単体と見本の検証成功後に、対象を区分して全自作sourceへ移行する。
   不明な宣言を一括正規表現で書き換えず、失敗時は対象fileを示して停止する。
4. 全対象で新metadata・コメント・書式検査、二回目の整形差分0、token／literal／
   preprocessor不変、旧履歴と作成日の保持、Doxygenの突合・契約レビューを満たす。
5. 単一`build/`でx64 Debug／Release全targetと決定的unit testを確認する。
   開始時のassertion数・失敗数と比較し、根拠なくtestを削減しない。
   独立見本も両構成でbuildし、14 case・失敗0を確認する。
6. CMake製品版、EXEの名前・版・architecture、安全option、Provider登録を変更しない。
   自動scan、driver install、復元ポイント、payload取得、remote push・公開は行わない。
7. 新規約をtoolで検証できるようになった時点でCONTRIBUTINGとCIの説明を更新する。
   現行のCIを無効化・除外追加で通さず、未実施のremote CIを成功と報告しない。

## 8. 実装・移行結果

2026/09/11に、02l1で保存した個別hash付きbaselineを入力として全355自作sourceを移行した。
旧製品版履歴1,830行と作成日355件を保持し、field／enum説明1,871件を宣言直前の`///`へ移した。
Code token、literal、preprocessor論理行はbaselineと一致し、移行後の集約SHA-256は
`e67ed5a18c583b659e2107edd32778efd1cb0b3f52be7e65cd6b78d79fc47a79`である。

現行toolの結果は、formatter 355file・差分0、metadata・制御文6,433・case 620・error 0、
型付き宣言2,695件とlocal宣言の不足0、Doxygen member inventory 1,878・文書抽出1,878・
集合error 0である。一般Doxygen warning 5,885行は、通常`//`を採用する変数・定数、
宣言側を正本とする関数引数・戻り値等として分類し、member集合gateの合格と混同しない。

単一`build/`では、MSVC x64環境を初期化してDebug／Release全targetを各218 actionでbuildし、
CTestは各1/1、直接unit testは各7,144 assertion・失敗0だった。独立見本も両構成でbuildし、
各14 case・失敗0。`DriverCrate.exe`は両構成ともPE32+ x64、製品版0.1.0、元file名
`DriverCrate.exe`で、ASLR、DEP、High Entropy VA、Control Flow Guardを保持した。

最初のDebug buildはVisual C++／Windows SDK環境を初期化していないPowerShellから実行したため、
標準headerと`Windows.h`を解決できず失敗した。Source defectではなく、`vcvars64.bat`を呼び出した
同一build treeで再実行して上記の両構成合格を得た。Live scan、payload取得、driver install、
復元ポイント、remote push、公開は行っていない。Remote CIは未実行であり、local結果から成功を
推定しない。CIはDoxygen 1.10.0を固定し、tool回帰・member集合監査・formatter・metadata検査を
必須gateとして実行する。

## 9. 参照

- [採用規約](../c_cpp_coding_standard.md)
- [見本](../examples/c_cpp_coding_standard_sample.cpp)
- AGENTS
- ロードマップ
- 2026/09/10の移行記録
- 今回の実施案
