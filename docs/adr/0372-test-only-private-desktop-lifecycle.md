# ADR 0372: UI試験専用private desktopの有限な自己supervision

- 日付: 2026-10-18
- 状態: 採用。実装・受入結果はテスト方針と当該工程の証拠へ記録する。
- 対応工程: G13-I7r231h9e、G13-I7r231h9f。

既存UI試験の外部argv、作業directory、600秒のCTest propertyを保持し、同じ試験EXEの
子processを起動時の`STARTUPINFO.lpDesktop`で新しい非入力desktopへ接続する。
実装ownerは`tests/ui/metadata_ui_tests.cpp`だけとし、製品EXEとCTest構成は変更しない。
元の453期待、実MainWindow、worker、modal、20ms timer、五秒pump、撮影・pixel・focus・
geometry検査を維持する。新しい制御の期待は別集計とする。

限定補正h9fでは、子環境から置換する内部markerのkeyを`=`の前で切り出し、
完全一致・大文字小文字非依存で比較する。似たprefix／suffixやdrive entry、非一致の値は保持する。
markerが指定する生存ownerのPID／作成時刻と実desktopを照合するが、OSの実親子系譜を
独立に証明する実装ではない。`UOI_IO`の非入力標本確認は名前の確認とは別に行う。

実modal timerは、popupのPID／threadが現在の試験と一致しない場合、message照会前に戻る。
自作ownerとの関係、owner無効状態、既定NO、YES／NOの操作許可が揃った場合だけclickする。
共通のkey／identity／click判定を固定synthetic正負例で検査し、同じ新boundary mode内で
実20ms timerによるYES=6／NO=7も確認する。外部windowは負例に使わない。
単独WM_CLOSE制御の観測は送信後の所有HWND消失であり、WM_DESTROY専用callbackの計数ではない。
新boundaryはDebug／Release各一回に限定し、旧26／118の結果は不変経路付きの継承として残す。

windowless親は最小0x87の権利でdesktopを作成し、明示所属と復帰を検査する。
子はCOM/control生成前にprocess-local markerと実所属・非入力状態を照合する。
markerは内部再帰防止用であり認証情報ではない。不一致は失敗とし通常desktopへ進まない。
実UI HWNDと既存fake factory callbackのworker threadも実所属を観測する。

標準入出力だけを複製し、STARTUPINFOEXの明示handle listで継承する。
子はsuspendedで生成しkill-on-close jobへ所属させてから再開する。
親は作成時の同じprocess handleでPID・作成時刻・終端を確認し、期限切れは失敗として
所有jobを終了し、全handleとdesktopを回収する。launch・job・復帰・cleanupの失敗を伝播する。
desktop切替、入力遮断、global hook、ACL変更や他process/windowの探索は行わない。

独立制御はstartup/UI/worker、YES/NO/default-NOとWM_CLOSE/破棄、誤marker、
live HWND時の所属拒否、所有held-child期限切れ、launch/cleanup失敗の六群とする。
影響する元26UIは各構成一回だけ実行し、失敗と未実行を分母へ残す。
非入力desktopで元の描画・focus検査が成立しなければ期待を緩めず採用を保留し、元sourceへ復帰する。

原Debug closeの3失敗と143PASS/1FAIL、API probe C1の失敗は履歴として保持する。
今回の成功から原失敗原因を推定しない。通常製品のユーザーdesktop上の目視受入、
実GitHub取得、全品質再閉包、実導入・公開の別承認は残る。

一次資料はMicrosoftの[thread connection](https://learn.microsoft.com/en-us/windows/win32/winstation/thread-connection-to-a-desktop)、
[SetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop)、
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)、
[process attribute list](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)、
[job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)とする。
