# ADR 0371: 検証済みcollector storeの内部extended DOS表記を共通化する

- 日付: 2026-10-18
- 状態: 採用。実装・有限受入の結果は本ADRの末尾とテスト方針へ記録する。
- 対象工程: G13-I7r231h8x。主担当確認はG13-I7r231h8xvで別に行う。

## 背景と判定根拠

公開用source候補814 fileを入力にした既存native試験で、CWDの長さに依存する失敗があった。
診断h8wでは同じDebug PE・引数・source-dataを使い、短いrepository CWDの四件は正常終了した。
祖先を用意した89 UTF-16単位のCWDでは元四件の失敗を再現し、新しい実行ではWin32 error 3を観測した。
元のh8u失敗はWin32値を記録していないため、元のerrorを3と遡及確定しない。
四件のうち深部の最初のWin32 APIを特定していないものはUNKNOWNのまま残す。

`LocalCollectorStateStore::State::apiPath`はcollectionと親所有子だけをextended DOS表記へ変換し、
legacy storeは通常DOS表記でAPIを呼んでいた。sourceの伝播から、既存directory下の304文字の
未存在JSONを`CreateFileW`で開くと、通常表記のpath長による3が`read`の不在契約へ混入することを
説明できる。`read`は実file欠損2だけを成功0・`found=false`へ変換し、3を正常な初回として扱わない。
ここをerrorの握り潰しで変更せず、既に検査したpathの内部API表記を揃える。

Pythonからの普通／extended API対照は両方成功し、native試験とはprocess manifest等の条件が異なる。
これをnative原因の直接証明にはしない。93文字CWDの祖先欠損2と、別のstaging境界での3も
89文字の再現とは別の観測として保持する。

## 採用する変更

検証済みcanonical absolute DOS pathを受け取るprivate `apiPath`だけを共通化する。
従来のcollection処理と同じく、separatorを`make_preferred`でbackslashへ揃え、`\\?\`を付けて
Win32 backendへ渡す。外部rootや相対名の受理条件、public API、通常アプリの機能を追加しない。

この変換を使うのは既存のdirectory作成／pin、file open、列挙、staging置換である。
`initializeImpl`のabsolute DOS・正規化・固定drive・永続ACL検査を通るrootと、
固定名または`safeRelative`を通るJSON名が入力になる。長さやcomponentの既存制約、
有限entry・byte予算とOSの実errorを維持する。任意長や全shell／全OSでの成功を保証しない。

## 維持する安全境界

UNC、device namespace、drive-relative、非正規化`..`等を新しく受理しない。
実handleのpath照合、祖先固定、reparse／hardlink拒否、owner・保護DACL、share、writer lock、
実size・hash、flush、世代、mode、取得・導入同意を変更しない。既存の広いACLを修復しない。
collection／historyをlegacy writerで直接開く拒否123／13も維持する。
Windowsの`LongPathsEnabled`、manifest、ExecutionPolicy、UAC等の設定は変更しない。

legacyの長い子JSONを読む`--validate`が、従来の通常表記による3から本来の内容検証へ進む可能性はある。
これはbackend表記修復によるread-only検証の変化であり、mode拒否を緩める許可ではない。
`--once`は修復により実HTTPへ進み得るため、今回の有限試験では実行しない。
未確認の`local_driver_collector.cpp`の別raw path境界やCLI期待値を無断で変更しない。

## 有限な検証と測定限界

既存state試験へ、300～400文字のlegacy子JSONで未存在readが0・空出力・`found=false`・非作成となる
回帰を追加する。同じfileのwrite／read／list／再open、本文とACL、同時writer拒否と
既存の不正相対名・reparse・hardlink・ACL拒否を確認する。
診断三testの一時出力は除去し、元EXPECTの値・評価回数・短絡を維持する。
worker欠損時の失敗EXPECTと例外guardは保持し、元SegFaultを正常結果へ置換しない。

既存buildをrepository根のままDebug／Release各一回`--target all --parallel 4`で更新する。
新しい89 UTF-16単位のCWDへ現在の814 source-dataだけを固定copyし、work/state祖先を先に用意する。
各構成で元四件、独立state owner、segment-read-contextの計六件、合計十二processを直接監督する。
各実登録TIMEOUT以上かつ600秒以下、全group1800秒、同条件retryなしとする。
全144 native、更新exportからの最終受入、package、GitHub公開の合格へ換算しない。

## 復帰

private helperの表記統一と今回の回帰追加だけを対象に変更を取り消せる。
既存state schema・本文・ACLの移行やWindows設定の復元は不要である。
旧失敗・sealed fixtureは変更せず、再発時はその条件と新しい失敗を別に保持する。
実導入・Task・鍵・署名・実GitHub書込み・Public化は今回の範囲外である。

## 一次資料

Microsoftの[Maximum Path Length Limitation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
は、extended表記のseparatorと相対要素の制約、通常APIの長path opt-inとmanifest条件を説明する。
[Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
も参照する。これらの仕様説明と、このPCでの有限な実測結果を区別する。

## 実行結果

本判断を実装前に記録し、private helperの表記だけを変更した。Debug／Releaseの既存`all`は各一回成功した。
長いlegacy子を含むstate試験は両構成65 assertions・失敗0で、未存在readの非作成、保存・列挙・再開、
本文・ACLと同時writer拒否を確認した。外部rootの新しい種類やWindows設定は追加していない。

最初の十二processは2 PASS・10 FAILだった。backendの初期失敗を越えた後、試験側の通常DOS表記による
削除・ifstream・cleanupの失敗へ進んだため、C2として三CPPの指定された自作fixture I/Oだけを補正した。
期待値・評価順・短絡・GUID／非reparse境界を維持し、既存のextended helperを共用した。
変更品質は初回五CPPのmember 69/69、C2三CPPの54/54が実集合で一致し、format・metadata・commentも通過した。
C2のDebug／Releaseの二test target追加buildは各一回成功し、六通常製品PE・profile・cacheは不変だった。

C2の失敗五件ずつを新しい89文字CWDで測った十processは8 PASS・2 FAILだった。
両campaignの9,775 assertions中の一失敗は、814入力にない既存評価planを相対ifstreamで読む閉包不足だった。
元の十二件とC2十件の全rawを固定した後、C3では既存planの同一55,248 byteだけをローカル試験入力へ追加した。
source・期待・PE・buildは変更せず、815入力epochのDebug campaignは9,775/0で成功した。
Releaseは元の300秒と保存余裕をgroup締切内に予約できずNOT_RUNとし、C2の9,775/1を未解消として残した。

実callは23件で、二つの不変state結果を継承したfocused十二役割は11 PASS・1未完了である。
同条件retry・期限延長はない。原失敗と入力epochを保持し、cleanupだけの成功を全体合格にしない。
主担当h8xv、Releaseを含む全144 native、最終source閉包・公開allowlistのprivacy／権利監査、
更新exportとpackageは未受入である。ローカルのfixture追加は公開許可ではない。
