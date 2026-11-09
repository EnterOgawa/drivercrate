# Testing

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
