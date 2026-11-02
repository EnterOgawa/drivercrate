# DriverCrate 1.0.0 — 初回公開準備

2026年11月3日時点のWindows x64向けローカル配布候補です。ソースは公開済みで、アプリ／Collector binaryの公開は未実施です。
製品版の正本はCMakeの1.0.0で、Windows版情報とpackage名へ反映します。
正式配布には、自作App／Collector／内側setup／外側setupのAuthenticode署名と時刻証明を
最終byteで検証した成果物を使います。通常source buildは証明書不要です。
ローカル候補のAppとCollector SetupはAuthenticode署名と時刻証明を検証済みです。
Appは署名前の内容保持も確認しました。これらの検証とbinaryの公開は別です。

## 機能と確認範囲

Windows Update／WSUS、Windows Driver Store、公式配布元、署名索引と対応local ZIPを共通の
候補表示・選択・取得／内容検査・既存導入経路へ接続します。取得前のmetadataと実INFの版を区別し、
初回導入、共有package、同意、失効、部分失敗、復旧失敗等を決定的な人工試験で確認しています。
初回導入でClassが未知の場合も元の個別観測を保持し、同じrecord／deviceのproofを集約します。
元の完全なINF tuple内で、Windows full rank最小が一件の場合だけ導入対象に固定します。
同点・照会失敗・直前のbinding変化は拒否し、版や名称だけで適用性を決めません。

利用者から、1.0.0でNICのインストールが正常に完了し、表示も期待どおりだったと報告を受けています。
報告時の実行ファイルのhashは採取していません。署名後のAppを起動し直した動作・実導入は
別途未確認です。この報告を全機器や各OSの動作保証にはしません。

現行署名済み1.0.0 Collector Setupでは、通常配置・新所有native日次Taskの登録と有効readback、
同workspace／native origin／monitorを維持した切替・data import・native verify、通常解除と
新所有Taskの正常不存在・data保持を確認しました。登録時のTaskはReady・未実行です。
Task実行・自然日次・七日・再起動・別PCは未確認です。

旧0.1.1署名済みAppではWindows 11のIntel Ethernet一機能で通常画面からの初回導入を確認しました。
復元ポイント102、Intel 1.9.74.0、問題コード28から0への変化とINF結合、他15 NICのbinding保持を確認した
有限な一件の記録です。OS全体の再起動不要や他機器・各OSでの動作を保証しません。
旧Collector/setupの通常配置・Task有効読戻し・同workspace切替／data import／verify・通常解除と
所有Task不存在／data保持も、その旧byteだけの実績です。Task実行・自然日次・七日・再起動・別PCは未確認です。

## 対応範囲と件数の見方

- 研究台帳は127メーカー、6,584製品参照、1,718配布record、390 locator、既存1 record分の汎用profileです。
  登録数を取得・内容検査・実機適合・実導入の成功数へ換算しません。
- 初版受入時の公開署名索引は世代10、Windows 11向け3 record／2 sourceでした。
  この過去世代の原期限2026-11-02 09:28:33 UTCは変更せず、旧世代のReleaseとassetを保持しています。
- 現在の公開署名索引は [世代11](https://github.com/EnterOgawa/drivercrate/releases/tag/index-v1-20261102-ae53e47e0c1f37fec8033bef3236bdc4b1ddfc89e70cc5148909a67ed9de0831)、Windows 11 x64向け通常ドライバー1 record／1 sourceです。
  2026-11-02 15:42:23 UTC発行、原期限2026-11-10 14:48:31 UTCです。
  Intel 1.9.74.0を実際に再取得し、内容・INF／CAT検査を通した索引の再発行です。
  ドライバーの版は前回と同じで、今回の実機適用性・実導入の再試験は行っていません。
  Prolificは再取得とINF 2件の内容検査に成功しましたが、結果受け渡しの失敗（DISTRIBUTION_PIPE_RESULT／Win32 109）で
  公開入力を確定できず、今回の索引には含めていません。内容不適合とは扱わず、原因究明・修復は別工程です。
  世代10の期限切れ2 recordを混ぜず、公開収録数は3 record／2 sourceから1 record／1 sourceへ減っています。
  索引の収録数は端末内適合数と異なり、期限切れや未判定を成功へ数えません。
  公開索引は通常Appと同じ鍵・配布先を使う匿名取得と公開鍵の署名検証で確認し、今回App画面の操作は行っていません。
- Collector同梱の参考索引はWindows 11向け2 record／1 sourceの元snapshotです。
  現在の公開索引11とは別で、元byte／観測／期限を維持し、通信許可・native authorityを付けません。

現行package-v7／receipt-v3だけを扱い、旧client／setup／dataの互換・自動移行は提供しません。
旧Task／store／dataを無断で移動・削除・resetせず、所有不明・未知rootは拒否します。
通常installでのmetadata日次Task同意と、検査取得の日次Task同意は別です。
通常日次は未署名候補までであり、索引署名・GitHub公開を自動実行しません。

## 配布と制限

App ZIPはDriverCrate.exe、README、LICENSE、THIRD_PARTY_NOTICESの四fileです。
Collectorは別成果物で、固定CPythonの原34file／署名／licenseを維持します。
EXEコード署名と索引署名は別用途であり、driver packageのCAT／publisher・hash・端末適合・同意・復旧を代替しません。
Windows clientの復元ポイント作成失敗時は中止し、Serverは専用のbackup／checkpoint確認を要求します。
全機器・全研究record・全取得先同時fresh成功・七日・別PCを今回の署名準備の前提へ増やしません。
現行1.0.0のsourceは公開済みです。アプリ配布用のbinary／tag／Releaseは未公開です。
