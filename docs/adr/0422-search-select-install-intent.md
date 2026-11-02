# ADR 0422: 検索と選択してインストールの二段階

- 日付: 2026-10-28
- 状態: 採用。実装と内部受入はG13-I7r271b/c、主担当確認と通常実UIは271v/dへ分ける。
- 関連: ADR 0144、0329、0416、0420、0421

## 決定

最新利用者指示「そもそも確認が不要」「検索、選択してインストール、この2ステップが望ましい」
により、ADR0420の検索後の自動取得確認を廃止する。通常検索は候補表示で止まり、利用者が
device行のcheckboxで対象を選び、インストール操作を行う。汎用の取得概要、対象追加、予約上限、
最終件数の確認dialogをこの通常導線へ挟まない。Install操作をその選択集合の実行意思とする。

workerが同scanの元認証lookup、公式record、取得targetとdeviceへ結合できた索引参照は、
未検査のまま明示選択できる。これは「取得・検査後に適合すれば導入する」短命の選択意図であり、
`installable`、適用性、更新・初回・旧版判定を付与しない。候補版の欠損を現在版や名称から補わない。
既存の直接Install APIは未検査参照を引き続き拒否する。

2026-11-02のADR0423により、公式取得のEULAは主画面で選択時に案内し、原全文/revisionを任意に閲覧できる。
案内済みの同一snapshotへの「同意してインストール」を明示同意とし、独立したEULA dialogを開かない。
検索・選択・閲覧だけでは同意しない。具体的前提・WUA既存条件・metered/unknown回線の
既存制限を保持する。同意しない対象はInstallせず、payloadを取得しない。通常の非従量回線に追加確認を要求しない。
取得承認へ元選択opaque identity集合を結合し、workerが私有Referenceと元targetを再照合する。
選択した配布物だけを共有取得し、元署名索引、期限、実byte/hash、署名、INF閉包、Windows rank、
proofを既存共通経路で検査する。同payloadの他deviceの検査結果を未選択deviceへの導入許可にしない。

検査後の私有route/reference位置から元device・元recordへ一致する唯一の新しい検証済み候補だけを
継続対象へ解決する。同選択から発行した検証済み候補の元target表示結合はfilterでも維持し、
新しい取得権限へ読み替えず導入終端で失効する。取得・検査失敗、未適用、複数候補、新たな旧版切替は
理由を残し、無断で候補を選ばない。検証済みの必要Extension/componentは基本driverの同じ計画に
含めて既存導入へ維持する。既検証のWUA/Driver Store候補との混在は同じ選択集合を保つ。
取消し、新検索、close、失効、旧eventでは継続意図を破棄し、自動再試行しない。

Clientの復元ポイントは必須で、開始失敗時は導入0。Serverのbackup/checkpoint確認、旧版警告、
公式installerの作用範囲への明示同意、Windowsのsource/certificate/policy境界を保持する。
通常のClient標準INF導入に重複する件数Yes/Noは表示しない。導入後の限定read-only観測、
個別結果・部分失敗・再起動と旧候補失効を保持する。実導入・実UI受入の成功は内部fakeから継承しない。

## 有限な検証

通常Search→確認0→二NIC行の選択/規約案内→同意してInstall（独立EULA0）→共有payload一取得・検査→復旧→同二件の
fake導入→個別結果/現在表示を優先する。任意全文だけでは同意0、混在・未選択・旧規約拒否payload0・取得/内容拒否・
曖昧候補・stale/newscan/cancel/close・復旧失敗install0を既存fake/unit/UIへ固定する。
実network、OS再検出、実driver導入へのfallbackを使わない。

## 戻し方

選択意図のDTOとworker/UI接続を取り除けば未検査参照は閲覧専用へ戻る。保護store形式、
索引署名、package/receipt、Providerの実導入許可は変更しない。
