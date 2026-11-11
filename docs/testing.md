# Testing

## ソースコメントの検査

`check_source_standard.py`は、宣言と定義の各sourceに独立した概要・実引数名/方向・戻り値があるかを確認します。
関数・メソッドの独立block、所属に応じた枠、参照だけの省略と代表的な閲覧委譲、無名引数・削除宣言の扱いも検査します。
raw literal、型/field、macro定義の論理行は関数として数えず、未解析署名とdelimiter不整合は拒否します。
Doxygenのmerge済み文書だけでは両sourceの合格にせず、実処理・所有・例外・threadの意味はbody reviewで確認します。

```powershell
python -B scripts/test_source_style.py
python -B scripts/test_source_method_contracts.py
python -B scripts/check_source_standard.py
python -B scripts/audit_doxygen_members.py --check
```

`audit_source_contracts.py`は、XMLにある宣言/定義の位置から各raw契約を監査します。定義を`@see`だけに置換しません。
手作業で実本体へ照合して不足を補い、参照省略の新たな生成や日本語の完全な自動意味判定を前提にしません。

## App用Setup・自動更新（1.0.5）

`drivercrate_app_update_tests`は数値版・24h時計・GitHub JSON/正確asset、完全fake HTTP、byte/署名/版拒否、cache排他、取消しと専用workerを非通信で確認します。
`drivercrate_metadata_ui_tests --run-ui-tests app-update`は通常MainWindowでbusy/modal通知待ち、同意前取得0、ドライバー作用0、取得取消し・引継ぎ失敗時の画面保持・正常終了を確認します。
Providerのscan sessionや索引権限を更新workerへ混ぜません。Windows.Data.Jsonのfactoryは局所所有し、同じprocessでの反復と不正JSON/HRESULTを試験します。

```powershell
cmake --build build --config Release --target DriverCrate drivercrate_app_update_tests drivercrate_metadata_ui_tests
ctest --test-dir build -C Release -R app_update --output-on-failure
./scripts/test_app_distribution_documents.ps1
```

ローカルInno確認はTest AppIdと隔離した現在ユーザー領域だけを使います。1.0.4→1.0.5更新・同版修復、古い版/使用中/領域外の拒否、copy前の標準取消し、
現在ユーザー登録/機械全体登録0、実App起動と正常close、通常解除とCollector/data/log等の合成marker保持を確認します。
受入用STA Explorer launcherによる通常user Setup起動、製品workerの非通信fixture、実App起動は別の実績です。
822cの内部確認では、製品MTAから将来の正式Releaseを取得して自己更新する実往復、別管理者アカウント、実署名済みSetupの配布受入を実施していません。最終配布物の署名・展開受入は822e/fの記録で確認します。
実ドライバー導入は行いません。配布READMEは画像/guideを同版tagのURLへ変換し、Setup/ZIPの両方で確認します。

公開sourceのconsumer targetをx64 Debug/Releaseで確認します。実HTTP/実WUA/実導入をunit試験へ含めず、
Provider、復旧、HTTP、署名入力には決定的なfakeを使います。人工署名と実証明書によるコード署名は別の資格です。
Privateの合格や過去版の実導入を、最終snapshot/配布byteへ自動継承しません。

## NativeとUI

```powershell
cmake --preset windows-x64
cmake --build --preset debug
ctest --preset debug
cmake --build --preset release
ctest --preset release
```

UIのCTestはdefault/close/queue/index/binding/multi/unknown/components/needs/extension/formats/preparation/refreshの13入口です。
追加でmetadata_ui_testsへ`--run-ui-tests hardware`、`format-order`、`refresh-probe`、`history-results`、`install-view`を明示指定します。
共有取得のcollector_inspection試験もconsumerの検証対象です。名前だけで共有検証を除外しません。
実driver導入、実復元ポイント、実証明書/索引鍵、保護storeや日次収集は実行しません。

## 必須source gate

Python 3.10以降、clang-format、Doxygen 1.10.0、開発用PowerShell 7とCMakeを用意します。

```powershell
py -3 -B scripts/test_public_source_closure.py
py -3 -B scripts/check_public_source_closure.py
py -3 -B scripts/test_source_style.py
py -3 -B scripts/test_source_method_contracts.py
py -3 -B scripts/format_source.py --check
py -3 -B scripts/check_source_standard.py
py -3 -B scripts/test_doxygen_members.py
py -3 -B scripts/audit_doxygen_members.py --check --doxygen $DoxygenExe
py -3 -B scripts/test_index_build_profile.py --suite native --powershell $PwshExe --cmake $CmakeExe
py -3 -B scripts/test_index_build_profile.py --suite resolver
```

profile試験のpackage suiteには私有producerのbuilder確認も含まれ、consumer sourceの対象にはしません。
署名helperのconsumer人工fixtureは`test_release_signing.ps1 -AppOnly`で確認します。実鍵操作はしません。
Releaseでは同じbuildをDRIVERCRATE_ENABLE_ANALYZE=ONで再構成してconsumerを解析し、OFFへ戻します。

## 公開snapshotのローカル事前確認

明示manifestのpath/mode/checkout byteとSHA-256を固定し、そのsnapshot自身から唯一buildでfresh D/Rを実行します。
別のbuild treeや旧build archiveは作りません。source/工具/options/依存、graphのcommand/cwd/TIMEOUTと失敗を私有記録へ残します。
public source/cacheの結合を実署名・packageまで保持し、配布候補を保全後に通常source/optionsへD/R復帰します。
失敗時もfinallyで復帰し、未実施を合格にしません。詳細は[release checklist](release-checklist.md)を参照してください。

1.0.4の関連試験では、処理済み対象の結果と未処理の選択を保持すること、既知の推奨更新を実観測で解消した対象の表示、同日の復元ポイント再利用と保護失敗を検証します。
