# ADR 0375: 既知の署名前checkpointだけの明示継承

日付: 2026-10-18
状態: 採用。sourceと人工回帰の範囲。実配備・実prepare・署名・Private反映は別工程。

## 決定

ADR 0374の一段だけのcodeRepairと初期inheritの既定拒否を維持する。
明示`--continue-presign-config`だけに、一度だけ`preSignContinuation`を追加する。
対象は、旧codeRepair markerがあり、保存bodyと成功したnative解析releaseだけがある、
内容検査入口で停止した既知のcheckpointである。一般的なmigrationや任意partial修復ではない。

旧修復configの全byte、旧四module/nativeの実byteとpin、旧config/start/receiptの連鎖、
旧修復marker、body/release、失敗terminal、元管理process証拠と追加の内容検査証拠を検証する。
旧修復configを現moduleとして検証しない。pipeline/preparerと同version配置path以外の
全意味入力を維持し、projection/registry/native hash、scope、原入力、terms、key、state/output、
日程、window、fenceを変更しない。現code/config pinも通常どおり厳格に確認する。

bodyはreceiptの元body byte/hashへ、releaseは原pin付きreleaseの全field（観測秒以外）と
receiptの原検証秒へ結合する。元成功native parseの完全argv/exit/同handle証拠も要求する。
bodyとreleaseを上書きせず、解析を繰り返さず、欠損しているinspection/script/reviewだけを
通常の検証で作成する。別の部分集合、余分なartifact、変更byteは拒否する。

新markerがまだない段階では、対象世代のglobal claim、署名envelope、unsigned成果物、
成功記録、CAS意図や署名結果のwitnessがなく、checkpointがbody+releaseだけであることを要求する。
固定の失敗terminalの`UNKNOWN_NO_RE_SIGN`は一般catchの表記であり、それだけを署名呼出しの
観測事実とはしない。実process証拠と旧codeのclaim-before-sign順序を組み合わせる限定判断であり、
全OS操作の不在証明を主張しない。元raw terminalは保持する。

同lock内でFRESH_INPUTを再確認後、新config/旧config/旧marker/receipt/checkpointに結合した
決定的な一個のmarkerを保存する。marker後もbody+releaseまたは通常の完全入力束だけを扱う。
完全束は既存の投影・exact byte・global claim-before-sign・署名結果・profile・CAS検査を通る。
claimのみ、未知署名、部分envelope、CAS結果不明を再署名へ変換しない。

## 日付と予算

再開job bucketは認証した元startのdayからだけ導出する。任意day引数は設けない。
JSTの現日付が翌日へ変わっても元collection/lock/attempt/terminal/reportの名前空間を使う。
これはUTC観測日を変更する機能ではない。receiptのUTC dayは現在UTC dayと一致する必要があり、
元seven-day window、native FRESH_INPUTの現head/run全byte/元notBeforeは維持する。
翌UTC日、foreign receipt、window終了は拒否する。

既使用9callと3.4540565秒（原実測の浮動小数端数を含む保守的値）を、pin付き追加内容検査証拠へ
結合して持ち越す。追加prepareの2callと実測秒、およびrun時の検証を同じ96call/1800秒から控除する。
32日次attempt、HOLD、元lock、元fence4、世代5、root、nonceをresetしない。

## 検証と制限

実production関数を人工file/native/remote fixtureへ接続し、正当な継承と完全束再利用、
旧/現pin・意味入力・partial・claim・未知署名・head・UTC日・window・lock・予算の拒否、
local midnightと元bucketのterminal/reportを確認する。旧modeの拒否期待値は維持する。
実内容検査1/1と元pipeline完遂0/1は別実績であり、本変更を実再開成功と記述しない。
実native/preparer、収集、署名、GitHub、Task、実導入をこのsource工程では実行しない。
