# ADR 0373: 公表digestの値照合と継承日次入口の用途結合

- 日付: 2026-10-18
- 状態: 採用。ローカルsource修正と決定的試験を対象とし、保護配置・実収集の受入ではない。
- 対応工程: G13-I7r231h14r1。

実preparerは、原releaseの大文字SHA-256と固定小文字SHA-256の文字列比較で
`ACQUISITION_ARCHIVE_BINDING`を返した。同じdigest値を持つ公表表記は、既存
`project_collected_native_index.digest`でstr型・64桁ASCII hexを検査してから比較する。
正規化するのは比較する値だけであり、原JSON・全byte pin・観測時刻は変更しない。
別digest、不正型・長さ・非hex・空白は拒否し、archive size・選択INF・native内容検査を維持する。

旧v1とacquisition-v2は同じoutputRoot・日程・state・`pipeline.lock`を共有する。
従来の`YYYYMMDD.start.json`はv1 configへ結合しており、新configの開始に使うと衝突する。
これは実prepare失敗の後にある未到達の潜在競合であり、二件目の実失敗とはしない。

acquisitionはlock内で旧metadata拘束を再検証する。旧startが存在する場合は、その全byteが
当日の正当な旧configのstartと一致する必要がある。旧startは作成・変更しない。
`YYYYMMDD.acquisition.start.json`を新設し、当日・用途・現在config hash・旧config hash・
旧startの有無と全byte hashへ固定する。同一byteだけを再利用し、foreign・malformed・
旧startの出現／消失・変更・現在configの変更は収集やnative予約・署名・公開より前に拒否する。
v1のstart、同config再開と不一致拒否は従来のままとする。

同日のmanifest raw・gzip・envelope・successにも用途の衝突があるため、acquisition分だけ
`YYYYMMDD.acquisition`のsuffixへ分離する。旧metadata出力を取得索引として再利用しない。
reportは全terminalと七日分母を保持し、旧metadata成功を`legacyMetadataResult`へ残す。
取得用途の成功は専用successまたは取得用途terminalに基づき、旧metadata成功から昇格しない。

収集receiptとterminalのday prefix、世代別claim、native予約headと旧fence、共通lockを維持する。
旧receiptを捨てて再収集する入口は作らず、日次32attempt・terminal上限・native96回・
runtime1800秒・HOLD一回待機・元七日窓を変更しない。共用receiptの世代やheadが不適合なら
従来どおり停止し、日付・root・nonceで予算を再初期化しない。

人工保護入力を使う実production関数の回帰で、大小文字の正例と不正入力、旧startの不変、
用途別出力、同config再開、不正markerとconfig差のeffect前拒否、共通lock・予算を確認する。
新runtime・依存・Provider・checker例外・telemetryは追加しない。
source受入後も、別の固定保護versionと新controlへの配備、実収集・内容検査・署名・Private反映、
通常アプリの実端末表示は別途確認を必要とする。Public公開・実driver導入の承認は含まない。
