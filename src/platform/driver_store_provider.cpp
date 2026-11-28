//------------------------------------------------------------------------------
/**
 * @file driver_store_provider.cpp
 * @brief Driver Store provider実装
 * @version 01.94.01
 * @date 2026/10/24
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Binding指定INF導入を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  個別binding破棄境界を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Device列挙進捗通知追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Setup class GUID取得追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通scan条件対応
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  検証済み外部INF導入境界追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local coverage集計追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Local探索経路追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  PnP rank非退行監査追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Windows管理監査状態追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  現在版を推奨候補にしないよう修正
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末内binding生成境界追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Local列挙計測と上限終端確認を追加
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Device観測と読取り失敗時の表示保持を追加
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  現在版を要求しない単一INF適合観測を追加
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  Native IDから有限bus分類だけを現在行へ追加
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  種別別の同scan秘密snapshotと失効resolverを追加
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  Native初回状態と登録INF root/実byteの再検証を接続
 * Ver.01.06.01 Shunji Ogawa  2026/10/12  Session失効時の重複stage cache清掃を整理
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.07.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  元Class未確定の真初回と実INF/native Class拘束を追加
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  同親と必要SWC子だけの指定APIと未確認役割を分離
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  元INF完全pathとbounded detailから必要構成を再確認
 * Ver.01.11.00 Shunji Ogawa  2026/10/14  明示local liveの索引resolverへ匿名分岐診断を追加
 * Ver.01.12.00 Shunji Ogawa  2026/10/14  公表INFとnativeの両ID役割を照合し既知部分根拠を発行
 * Ver.01.12.01 Shunji Ogawa  2026/10/15  必要roleの登録INFを計画終端まで変更非共有で保持
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  必要INF bindingの拒否段階を非機密数値として採取
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  実選択Needs件数を必要計画の再検証へ結合
 * Ver.01.14.01 Shunji Ogawa  2026/10/17  Native IDの実一文字NULだけを明示空listとして検証
 * Ver.01.15.00 Shunji Ogawa  2026/10/24  原公開PnPのcaseを保持して既存native照合keyへ結合
 * Ver.01.16.00 Shunji Ogawa  2026/10/27  完全個別観測と初回Hardware根拠から専用証拠を発行
 * Ver.01.17.00 Shunji Ogawa  2026/10/27  元完全tuple内の唯一最小Windows rankを固定し直前再選択
 * Ver.01.17.01 Shunji Ogawa  2026/10/28  同ID二件の元proof寿命を選択batch終端まで保持
 * Ver.01.18.00 Shunji Ogawa  2026/10/28  選択対象の導入後実観測と現在行の自動更新を接続
 * Ver.01.19.00 Shunji Ogawa  2026/11/06  元CopyINF stage内容と別deviceの機能導入を分離
 * Ver.01.20.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合
 * Ver.01.21.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.22.00 Shunji Ogawa  2026/11/09  導入後の一回fresh候補再評価と元表示保持を接続
 * Ver.01.23.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.24.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続
 * Ver.01.24.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.25.00 Shunji Ogawa  2026/11/12  本人検査領域とsetup限定の公開親metadata権限へ整合
 * Ver.01.25.01 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.25.02 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.25.03 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.25.04 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.26.00 Shunji Ogawa  2026/11/15  非実行collector内容からの通常binding発行を拒否
 * Ver.01.27.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.28.00 Shunji Ogawa  2026/11/16  MTDを裸の通常bindingとstageから分離
 * Ver.01.29.00 Shunji Ogawa  2026/11/17  MTD共有copyと同選択DIFを原期限へ結合
 * Ver.01.30.00 Shunji Ogawa  2026/11/17  必要子の実観測と短命proofをbindingへ結合
 * Ver.01.31.00 Shunji Ogawa  2026/11/18  CopyINF由来の限定registry-only内容と通常導入拒否を分離
 * Ver.01.32.00 Shunji Ogawa  2026/11/19  公表と端末のIDを同じ不透明な文字列として照合
 * Ver.01.33.00 Shunji Ogawa  2026/11/19  固有のWindows互換nodeから元Models行のIDを読み取り照合
 * Ver.01.34.00 Shunji Ogawa  2026/11/19  実ドライバー行で対象クラスと元端末の登録を照会
 * Ver.01.35.00 Shunji Ogawa  2026/11/19  対象クラスの読み取りを選択元INFのクラス節に結合
 * Ver.01.36.00 Shunji Ogawa  2026/11/19  独自クラスの実Models行だけを順位監査に使用
 * Ver.01.37.00 Shunji Ogawa  2026/11/19  独自クラスの配置先INFとCATと必要ファイルを照合
 * Ver.01.38.00 Shunji Ogawa  2026/11/19  独自クラスの元選択を指定導入と二時点の権限再確認へ接続
 * Ver.01.39.00 Shunji Ogawa  2026/11/19  独自クラスの読取りと配置先照会を同じ完全API表へ接続
 * Ver.01.40.00 Shunji Ogawa  2026/11/20  Catalog配布条件を同scanのHardware IDと個別証拠へ結合
 * Ver.01.41.00 Shunji Ogawa  2026/11/20  指定導入のbindingを公式対象IDの端末再観測へ結合
 * Ver.01.42.00 Shunji Ogawa  2026/11/20  Catalog対象の署名権限とHardwareIdsを登録と指定導入の直前に検査
 * Ver.01.42.01 Shunji Ogawa  2026/11/20  公式対象Hardware IDの導入直前検査を共通の呼称に整合
 * Ver.01.43.00 Shunji Ogawa  2026/11/20  完全なHardwareIdsの弱参照を同一端末の証拠へ結合
 * Ver.01.44.00 Shunji Ogawa  2026/11/20  現在のHardwareIds全体から公式ファームウェア群を再観測
 * Ver.01.45.00 Shunji Ogawa  2026/11/20  登録と指定適用の直前に同じファームウェア群の確認を要求
 * Ver.01.46.00 Shunji Ogawa  2026/11/21  正式メディアチェンジャーにストレージ導入資格を要求
 * Ver.01.47.00 Shunji Ogawa  2026/11/21  HDCの既存サービスと共有起動ログを同期資格として再照合
 * Ver.01.48.00 Shunji Ogawa  2026/11/21  HDCの登録と適用の直前に元署名承認を再確認
 * Ver.01.49.00 Shunji Ogawa  2026/11/21  標準シリアルページを元選択時と適用直前に照合
 * Ver.01.50.00 Shunji Ogawa  2026/11/22  公式Modelsの元行を一意なWindows nodeと端末属性へ結合
 * Ver.01.51.00 Shunji Ogawa  2026/11/22  公式Modelsの確定行と実選択の必要関係を返す
 * Ver.01.52.00 Shunji Ogawa  2026/11/22  公式Modelsの所有閉包・現端末・実作用を私有計画へ固定
 * Ver.01.53.00 Shunji Ogawa  2026/11/22  同じ公式Modelsの端末・元行・作用を既存トークンで再照合
 * Ver.01.54.00 Shunji Ogawa  2026/11/22  公式Modelsの登録と適用を元権限・登録済み閉包へ結合
 * Ver.01.55.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスのフィルター置換を元端末と変更直前へ照合
 * Ver.01.56.00 Shunji Ogawa  2026/11/22  公式Netの同梱依存と端末フィルターを導入直前に再照合
 * Ver.01.57.00 Shunji Ogawa  2026/11/22  所有された元端末の存在と完全Hardware IDを再観測
 * Ver.01.58.00 Shunji Ogawa  2026/11/22  補助サービス作用の導入資格を現在状態の検査まで保留
 * Ver.01.59.00 Shunji Ogawa  2026/11/22  現在のストレージ機器から実際に使用中の配布を照合
 * Ver.01.60.00 Shunji Ogawa  2026/11/22  選択機器を含むサービスの所有者と登録先照会を同じ経路へ結合
 * Ver.01.61.00 Shunji Ogawa  2026/11/22  現用登録の全証拠から補助サービスと配置済みファイルの共有所有を照合
 * Ver.01.62.00 Shunji Ogawa  2026/11/22  共有補助作用の資格を発行し登録と指定適用直前に元署名と端末状態を再照合
 * Ver.01.63.00 Shunji Ogawa  2026/11/22  指定適用後の補助サービスと配置ファイルの反映を元登録へ照合
 * Ver.01.64.00 Shunji Ogawa  2026/11/23  自動起動候補と同じ選択機器の現用署名元を読取り
 * Ver.01.65.00 Shunji Ogawa  2026/11/23  選択機器の現用署名元と現在構成を再確認へ保持
 * Ver.01.66.00 Shunji Ogawa  2026/11/23  現用と候補の関連サービスを使う全機器を照合
 * Ver.01.67.00 Shunji Ogawa  2026/11/23  自動起動型の読取り計画を同一端末の私有資格に結合
 * Ver.01.68.00 Shunji Ogawa  2026/11/23  自動起動補助の登録済み閉包を指定適用まで照合
 * Ver.01.69.00 Shunji Ogawa  2026/11/23  自動起動型の指定適用後に同じ登録と共有設定を読取り
 * Ver.01.70.00 Shunji Ogawa  2026/11/23  旧イベント資源と同サービスの他機器、再起動待ちを照合
 * Ver.01.70.01 Shunji Ogawa  2026/11/23  自動起動型の元操作と登録先照会を最初のINF登録前に確認
 * Ver.01.71.00 Shunji Ogawa  2026/11/23  登録先の正規照会に結び自動起動型の導入資格を発行
 * Ver.01.72.00 Shunji Ogawa  2026/11/23  同一Windows互換ノードの同梱INF委譲を読取り確認
 * Ver.01.73.00 Shunji Ogawa  2026/11/23  適用後のイベント資源配置と省略した旧資源を確認
 * Ver.01.74.00 Shunji Ogawa  2026/11/23  現在の単一ブート機器を前後で同じ署名付き実登録へ照合
 * Ver.01.75.00 Shunji Ogawa  2026/11/23  機器登録の前後確認内で局所値とイベントを再観測
 * Ver.01.76.00 Shunji Ogawa  2026/11/23  所在と全機器の元登録を同じ電源設定の照合へ結合
 * Ver.01.77.00 Shunji Ogawa  2026/11/23  単一ブート候補の電源変更分類を端末読取りに結合
 * Ver.01.78.00 Shunji Ogawa  2026/11/23  単一ブート候補の正規SYS配置先を同じ端末観測へ結合
 * Ver.01.79.00 Shunji Ogawa  2026/11/23  単一起動候補の変更範囲を同じ端末と元選択の資格へ結合
 * Ver.01.80.00 Shunji Ogawa  2026/11/23  単一起動の実適用直前と事後の署名元・設定の照合を追加
 * Ver.01.81.00 Shunji Ogawa  2026/11/23  WiXの元Models行とWindows選択の完全ID列を資格に保持
 * Ver.01.81.01 Shunji Ogawa  2026/11/26  公式INFの公開オーバーロードの引数説明を署名に整合
 * Ver.01.81.02 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.01.81.03 Shunji Ogawa  2026/11/26  ストレージ適用後のサービス不在を共通エラー型で比較
 * Ver.01.81.04 Shunji Ogawa  2026/11/26  限定導入の証拠を個別に説明し再起動後の元結果を同型で比較
 * Ver.01.81.05 Shunji Ogawa  2026/11/26  ストレージ資格が所有する観測領域へ直接読み込む
 * Ver.01.81.06 Shunji Ogawa  2026/11/26  初回クラス登録の表示を元資格の存在へ直接結合
 * Ver.01.82.00 Shunji Ogawa  2026/11/27  付随INFを伴う候補の登録済み基本パッケージを検証
 * Ver.01.83.00 Shunji Ogawa  2026/11/27  未評価作用を持つ必須SoftwareComponentを親の選択節へ結合
 * Ver.01.84.00 Shunji Ogawa  2026/11/27  元選択の登録と適用前に付随INFの不在を再確認
 * Ver.01.85.00 Shunji Ogawa  2026/11/27  Displayの共用判定用に全現在機器の登録と子属性を読取
 * Ver.01.86.00 Shunji Ogawa  2026/11/27  現用Displayの署名、実親子と共用判定を候補の導入計画へ結合
 * Ver.01.87.00 Shunji Ogawa  2026/11/27  Displayの登録と親指定適用の直前に元所有と元承認を再照合
 * Ver.01.88.00 Shunji Ogawa  2026/11/27  現用Displayの列挙と同名補助の共用照合を分離
 * Ver.01.89.00 Shunji Ogawa  2026/11/27  元Type 1実行物の到達先を署名付き現用子と一台の親に照合
 * Ver.01.90.00 Shunji Ogawa  2026/11/27  到達先を確認した必要子のType 1元宣言を保持
 * Ver.01.91.00 Shunji Ogawa  2026/11/27  選択した必要子の実行記録を同じ導入操作へ接続
 * Ver.01.92.00 Shunji Ogawa  2026/11/27  親のOpenCL登録を今回の署名付き子の保持ファイルへ照合
 * Ver.01.93.00 Shunji Ogawa  2026/11/27  同じ子の実行完了後に共有コピー全件の反映を再確認
 * Ver.01.94.00 Shunji Ogawa  2026/11/27  同じPnPデバイスに結び付く物理GPU種別を読取り
 * Ver.01.94.01 Shunji Ogawa  2026/11/28  必須子の新しい選択節検査をDisplayの親に限定
 * </pre>
 *
 * @note SetupAPIによるPnP deviceとDriver Store履歴の列挙を実装します。選択された指定版は実行直前に再照合します。Native device identityと
 *       INF pathはworker内だけで保持します
 */
//------------------------------------------------------------------------------

#include "core/index_capacity_limits.h"
#include "platform/driver_store_provider.h"
#include "platform/driver_store_inf_transport_internal.h"

#include "core/device_observation.h"
#include "core/metadata_search_budget.h"

#include "platform/official_catalog_device.h"
#include "platform/official_discovery_inventory.h"
#include "platform/official_release_local_probe.h"

#include "core/candidate_audit.h"
#include "core/provider_registry.h"
#include "core/scan_measurement.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/common_driver_package.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/signed_index_codec_internal.h"
#include "platform/signed_index_records.h"
#include "platform/official_file_verifier.h"
#include "platform/inf_dependency_native.h"
#include "platform/mtd_handler_internal.h"
#include "platform/system_inf_effects_internal.h"
#include "platform/registered_driver_store_package_internal.h"
#include "platform/display_inf_scope_internal.h"
#include "platform/display_type1_event_log_internal.h"
#include "platform/storage_inf_effects_internal.h"
#include "platform/mtd_queue_internal.h"
// Windows.h は SetupAPI の基本型より先、initguid.h は DEVPROPKEY 定義より先に必要である
// clang-format off
#include <Windows.h>
#include <Objbase.h>
#include <SetupAPI.h>
#include <initguid.h>
#include <devpkey.h>
#include <devguid.h>
#include <ntddvdeo.h>
#include <newdev.h>
#include <cfg.h>
#include <cfgmgr32.h>
#include <winternl.h>
#include <d3dkmthk.h>
#include <dxcore.h>
#include <wrl/client.h>
// clang-format on

#include <algorithm>
#include <array>
#include <bit>
#include <cwchar>
#include <cstddef>
#include <cwctype>
#include <cstring>
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
#include <cstdio>
#endif
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <type_traits>
#include <vector>

namespace drivercrate {
namespace driver_store_inf_detail {
// 本worker lifetimeだけの内部fixture。製品は常にnullptrです
thread_local ScopedFixture *activeFixture = nullptr ;
//------------------------------------------------------------------------------
/**
 * @brief 同workerへ完全fake表が固定されているか確認します
 * @return 内部scopeの生存中だけtrueです
 */
//------------------------------------------------------------------------------
bool						fixtureActive() noexcept
{
	return activeFixture != nullptr ;
}
// 製品が使用する変更不能な完全Windows API表です
const Transport NATIVE_CALLS{
	.inventory			   = {},
	.create				   = SetupDiCreateDeviceInfoList,
	.open				   = SetupDiOpenDeviceInfoW,
	.build				   = SetupDiBuildDriverInfoList,
	.enumerate			   = SetupDiEnumDriverInfoW,
	.detail				   = SetupDiGetDriverInfoDetailW,
	.getParameters		   = SetupDiGetDeviceInstallParamsW,
	.setParameters		   = SetupDiSetDeviceInstallParamsW,
	.rank				   = SetupDiGetDriverInstallParamsW,
	.destroyDrivers		   = SetupDiDestroyDriverInfoList,
	.stage				   = SetupCopyOEMInfW,
	.install			   = DiInstallDevice,
	.architecture		   = GetNativeSystemInfo,
	.windowsDirectory	   = GetWindowsDirectoryW,
	.storageStoreLocation  = SetupGetInfDriverStoreLocationW,
	.infClass			   = SetupDiGetINFClassW,
	.serviceDeviceListSize = CM_Get_Device_ID_List_SizeW,
	.serviceDeviceList	   = CM_Get_Device_ID_ListW,
	.mtd				   = {.setSelected		= SetupDiSetSelectedDriverW,
							  .getSelected		= SetupDiGetSelectedDriverW,
							  .callInstaller	= SetupDiCallClassInstaller,
							  .openQueue		= SetupOpenFileQueue,
							  .queueCount		= SetupGetFileQueueCount,
							  .scanQueue		= SetupScanFileQueueW,
							  .queueSection		= SetupQueueCopySectionW,
							  .commitQueue		= SetupCommitFileQueueW,
							  .closeQueue		= SetupCloseFileQueue,
							  .openInf			= SetupOpenInfFileW,
							  .closeInf			= SetupCloseInfFile,
							  .storeLocation	= SetupGetInfDriverStoreLocationW,
							  .windowsDirectory = GetWindowsDirectoryW,
							  .openClassKey		= SetupDiOpenClassRegKeyExW,
							  .openDeviceKey	= SetupDiOpenDevRegKey,
							  .classProperty	= SetupDiGetClassPropertyW,
							  .queryRegistry	= RegQueryValueExW,
							  .closeRegistry	= RegCloseKey,
							  .createFile		= CreateFileW,
							  .fileInfo			= GetFileInformationByHandle,
							  .fileInfoEx		= GetFileInformationByHandleEx,
							  .finalPath		= GetFinalPathNameByHandleW,
							  .freeSpace		= GetDiskFreeSpaceExW,
							  .securityInfo		= GetSecurityInfo,
							  .localFree		= LocalFree,
							  .readFile			= ReadFile,
							  .writeFile		= WriteFile,
							  .flushFile		= FlushFileBuffers,
							  .setFileInfo		= SetFileInformationByHandle,
							  .closeHandle		= CloseHandle},
	.declarativeClass	   = DeclarativeClassTransport{
			 .observation	= {SetupDiClassNameFromGuidW, SetupDiClassGuidsFromNameW,
							   SetupDiOpenClassRegKeyExW, SetupDiGetClassPropertyW,
							   SetupDiGetDevicePropertyW, RegOpenKeyExW, RegQueryValueExW, RegCloseKey},
			 .storeLocation = SetupGetInfDriverStoreLocationW}} ;
//------------------------------------------------------------------------------
/**
 * @brief 全guardが使用する完全表を固定します
 * @param[in] calls Nativeを含まない完全fake表
 */
//------------------------------------------------------------------------------
ScopedFixture::ScopedFixture( Transport calls) noexcept : calls_( std::move( calls))
{
	activeFixture = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同workerのAPI表を解除します
 */
//------------------------------------------------------------------------------
ScopedFixture::~ScopedFixture() noexcept
{
	// 別workerや既存scopeのtableを解除しません
	if( activeFixture == this) {
		activeFixture = nullptr ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 製品nativeまたは同worker固定完全表を参照します
 * @return 同期呼出し中有効な借用参照。欠損fallbackはありません
 */
//------------------------------------------------------------------------------
const Transport &transport() noexcept
{
	return activeFixture ? activeFixture->calls_ : NATIVE_CALLS ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同workerでMTD操作に必要な全低位slotを確認します
 * @return 全slotがある場合だけtrueです。欠損時のnative補完はありません
 */
//------------------------------------------------------------------------------
bool mtdTransportReady() noexcept
{
	// 同workerに固定されたMTD専用低位表です
	const auto &api = transport().mtd ;
	return api.setSelected && api.getSelected && api.callInstaller && api.openQueue &&
		   api.queueCount && api.scanQueue && api.queueSection && api.commitQueue &&
		   api.closeQueue && api.openInf && api.closeInf && api.storeLocation &&
		   api.windowsDirectory && api.openClassKey && api.openDeviceKey && api.classProperty &&
		   api.queryRegistry && api.closeRegistry && api.createFile && api.fileInfo &&
		   api.fileInfoEx && api.finalPath && api.freeSpace && api.securityInfo && api.localFree &&
		   api.readFile && api.writeFile && api.flushFile && api.setFileInfo && api.closeHandle ;
}
// 固定低位表のfactoryは内部test構成へ限定します
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief MTD専用tableの全slotが未指定かを確認します
 * @param[in] api 同workerへ渡すMTD専用表です
 * @return 全slotが空の場合だけtrueです
 */
//------------------------------------------------------------------------------
bool mtdTableEmpty( const MtdTransport &api) noexcept
{
	return !api.setSelected && !api.getSelected && !api.callInstaller && !api.openQueue &&
		   !api.queueCount && !api.scanQueue && !api.queueSection && !api.commitQueue &&
		   !api.closeQueue && !api.openInf && !api.closeInf && !api.storeLocation &&
		   !api.windowsDirectory && !api.openClassKey && !api.openDeviceKey && !api.classProperty &&
		   !api.queryRegistry && !api.closeRegistry && !api.createFile && !api.fileInfo &&
		   !api.fileInfoEx && !api.finalPath && !api.freeSpace && !api.securityInfo &&
		   !api.localFree && !api.readFile && !api.writeFile && !api.flushFile &&
		   !api.setFileInfo && !api.closeHandle ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同ABI slotの欠損と実native混入を確認します
 * @tparam Function 同ABIの関数pointer型です
 * @param[in] actual 固定する低位slotです
 * @param[in] native 対応する実Windows APIです
 * @return slotが非空かつ実nativeと異なる場合だけtrueです
 */
//------------------------------------------------------------------------------
template <typename Function> bool isFakeApiSlot( Function actual, Function native) noexcept
{
	return actual && actual != native ;
}

//------------------------------------------------------------------------------
/**
 * @brief MTD専用の全slotを完全fakeとして確認します
 * @param[in] api 同workerへ固定するMTD専用表です
 * @return 全slotが非空で実nativeを含まない場合だけtrueです
 */
//------------------------------------------------------------------------------
bool mtdTableIsCompleteFake( const MtdTransport &api) noexcept
{
	return isFakeApiSlot( api.setSelected, &SetupDiSetSelectedDriverW) &&
		   isFakeApiSlot( api.getSelected, &SetupDiGetSelectedDriverW) &&
		   isFakeApiSlot( api.callInstaller, &SetupDiCallClassInstaller) &&
		   isFakeApiSlot( api.openQueue, &SetupOpenFileQueue) &&
		   isFakeApiSlot( api.queueCount, &SetupGetFileQueueCount) &&
		   isFakeApiSlot( api.scanQueue, &SetupScanFileQueueW) &&
		   isFakeApiSlot( api.queueSection, &SetupQueueCopySectionW) &&
		   isFakeApiSlot( api.commitQueue, &SetupCommitFileQueueW) &&
		   isFakeApiSlot( api.closeQueue, &SetupCloseFileQueue) &&
		   isFakeApiSlot( api.openInf, &SetupOpenInfFileW) &&
		   isFakeApiSlot( api.closeInf, &SetupCloseInfFile) &&
		   isFakeApiSlot( api.storeLocation, &SetupGetInfDriverStoreLocationW) &&
		   isFakeApiSlot( api.windowsDirectory, &GetWindowsDirectoryW) &&
		   isFakeApiSlot( api.openClassKey, &SetupDiOpenClassRegKeyExW) &&
		   isFakeApiSlot( api.openDeviceKey, &SetupDiOpenDevRegKey) &&
		   isFakeApiSlot( api.classProperty, &SetupDiGetClassPropertyW) &&
		   isFakeApiSlot( api.queryRegistry, &RegQueryValueExW) &&
		   isFakeApiSlot( api.closeRegistry, &RegCloseKey) &&
		   isFakeApiSlot( api.createFile, &CreateFileW) &&
		   isFakeApiSlot( api.fileInfo, &GetFileInformationByHandle) &&
		   isFakeApiSlot( api.fileInfoEx, &GetFileInformationByHandleEx) &&
		   isFakeApiSlot( api.finalPath, &GetFinalPathNameByHandleW) &&
		   isFakeApiSlot( api.freeSpace, &GetDiskFreeSpaceExW) &&
		   isFakeApiSlot( api.securityInfo, &GetSecurityInfo) &&
		   isFakeApiSlot( api.localFree, &LocalFree) && isFakeApiSlot( api.readFile, &ReadFile) &&
		   isFakeApiSlot( api.writeFile, &WriteFile) &&
		   isFakeApiSlot( api.flushFile, &FlushFileBuffers) &&
		   isFakeApiSlot( api.setFileInfo, &SetFileInformationByHandle) &&
		   isFakeApiSlot( api.closeHandle, &CloseHandle) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独自クラスの読取りと配置先照会が完全な試験APIか確認する
 * @param[in] table 同workerの独自クラス用API表
 * @return 全関数があり対応する実Windows APIと異なる場合true
 */
//------------------------------------------------------------------------------
bool declarativeTableIsCompleteFake( const DeclarativeClassTransport &table) noexcept
{
	const auto &api = table.observation ;	// 元端末とクラスを読む固定表
	return isFakeApiSlot( api.className, &SetupDiClassNameFromGuidW) &&
		   isFakeApiSlot( api.classGuids, &SetupDiClassGuidsFromNameW) &&
		   isFakeApiSlot( api.openClassKey, &SetupDiOpenClassRegKeyExW) &&
		   isFakeApiSlot( api.classProperty, &SetupDiGetClassPropertyW) &&
		   isFakeApiSlot( api.deviceProperty, &SetupDiGetDevicePropertyW) &&
		   isFakeApiSlot( api.openKey, &RegOpenKeyExW) &&
		   isFakeApiSlot( api.readValue, &RegQueryValueExW) &&
		   isFakeApiSlot( api.closeKey, &RegCloseKey) &&
		   isFakeApiSlot( table.storeLocation, &SetupGetInfDriverStoreLocationW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 欠損・native混在・scope上書きを拒否します
 * @param[in] calls 完全なfake WinAPI表。成功DTOを受けません
 * @return 完全表だけを所有するscope。不足時はnullptrです
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::create( Transport calls)
{
	// 欠損やnative混在を拒否し、fixture要求で実OSを変更しません
	if( activeFixture || (!mtdTableEmpty( calls.mtd) && !mtdTableIsCompleteFake( calls.mtd)) ||
	   (calls.declarativeClass && !declarativeTableIsCompleteFake( *calls.declarativeClass)) ||
	   calls.storageStoreLocation == SetupGetInfDriverStoreLocationW || !calls.create ||
	   calls.create == SetupDiCreateDeviceInfoList || !calls.open ||
	   calls.open == SetupDiOpenDeviceInfoW || !calls.build ||
	   calls.build == SetupDiBuildDriverInfoList || !calls.enumerate ||
	   calls.enumerate == SetupDiEnumDriverInfoW || !calls.detail ||
	   calls.detail == SetupDiGetDriverInfoDetailW || !calls.getParameters ||
	   calls.getParameters == SetupDiGetDeviceInstallParamsW || !calls.setParameters ||
	   calls.setParameters == SetupDiSetDeviceInstallParamsW || !calls.rank ||
	   calls.rank == SetupDiGetDriverInstallParamsW || !calls.destroyDrivers ||
	   calls.destroyDrivers == SetupDiDestroyDriverInfoList || !calls.stage ||
	   calls.stage == SetupCopyOEMInfW || !calls.install || calls.install == DiInstallDevice ||
	   !calls.architecture || calls.architecture == GetNativeSystemInfo || !calls.inventory.open ||
	   !calls.windowsDirectory || calls.windowsDirectory == GetWindowsDirectoryW ||
	   !calls.infClass || calls.infClass == SetupDiGetINFClassW || !calls.serviceDeviceListSize ||
	   calls.serviceDeviceListSize == CM_Get_Device_ID_List_SizeW || !calls.serviceDeviceList ||
	   calls.serviceDeviceList == CM_Get_Device_ID_ListW ||
	   calls.inventory.open == SetupDiGetClassDevsW || !calls.inventory.enumerate ||
	   calls.inventory.enumerate == SetupDiEnumDeviceInfo || !calls.inventory.property ||
	   calls.inventory.property == SetupDiGetDevicePropertyW || !calls.inventory.instanceId ||
	   calls.inventory.instanceId == SetupDiGetDeviceInstanceIdW || !calls.inventory.close ||
	   calls.inventory.close == SetupDiDestroyDeviceInfoList || !calls.inventory.nodeStatus ||
	   calls.inventory.nodeStatus == CM_Get_DevNode_Status) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedFixture>{new ScopedFixture( std::move( calls))} ;
}
#endif

//------------------------------------------------------------------------------
/**
 * @brief 互換nodeのDetailsから型と順序を維持したModels IDを読み取る
 * @param[in] buffer Windowsが返したHardwareID以降の完全な可変長領域
 * @param[in] compatOffset Hardware ID直後のCompatible ID開始位置
 * @param[in] compatLength Windowsが返したCompatible ID全長
 * @param[out] modelIds Hardware IDと各Compatible IDの原順。失敗時は使用しない
 * @return 終端・長さ・ID件数が確認できた場合true
 */
//------------------------------------------------------------------------------
bool readDriverModelIds( std::span<const wchar_t> buffer, std::size_t compatOffset,
						std::size_t compatLength, std::vector<std::wstring> &modelIds)
{
	// 対応する署名Models行にはHardware IDがあるため、不明確なoffsetを補わない
	if( compatOffset <= 1U || compatOffset > buffer.size() ||
	   compatLength > buffer.size() - compatOffset || buffer[compatOffset - 1U] != L'\0') {
		return false ;
	}

	const auto hardware = buffer.first( compatOffset - 1U) ;	// 終端を除いた最初の原ID
	// Hardware IDの途中に別のIDを隠さない
	if( std::ranges::find( hardware, L'\0') != hardware.end()) {
		return false ;
	}

	modelIds.emplace_back( hardware.data(), hardware.size()) ;
	// Compatible IDなしはHardware ID一件として扱う
	if( compatLength == 0U) {
		return true ;
	}

	auto compatible = buffer.subspan( compatOffset, compatLength) ;	// Windowsの宣言範囲だけを読む
	// Compatible IDがあれば一文字以上の値と二重終端を確認する
	while( compatible.size() > 1U) {
		const auto end = std::ranges::find( compatible, L'\0') ;	// 現在IDの最初の終端
		// 空ID、途切れた値、終端欠損、過大なID列を拒否する
		if( end == compatible.begin() || end == compatible.end() || end == compatible.end() - 1 ||
		   modelIds.size() >= 63U) {
			return false ;
		}

		modelIds.emplace_back( compatible.data(), end - compatible.begin()) ;
		compatible = compatible.subspan( static_cast<std::size_t>( end - compatible.begin()) + 1U) ;
	}

	return compatible.size() == 1U && compatible.front() == L'\0' && modelIds.size() > 1U ;
}

} // namespace driver_store_inf_detail
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr DWORD MAXIMUM_DEVICE_PROPERTY_BYTES	   = 64U * 1024U ;	// Device property受信上限（byte）
constexpr DWORD MAXIMUM_DRIVER_DETAIL_BYTES		   = 64U * 1024U ;	// Driver detail受信上限（byte）
constexpr DWORD MAXIMUM_DEVICE_INSTANCE_CHARACTERS = 4096 ;			// Instance ID上限（UTF-16文字）
constexpr DWORD MAXIMUM_DEVICES				   = 4096 ;				// 一回のscanで列挙するpresent device数の上限
constexpr DWORD MAXIMUM_DRIVERS_PER_DEVICE	   = 512 ;				// 一deviceで列挙するcompatible driver数上限
constexpr std::size_t MAXIMUM_TOTAL_CANDIDATES = 32768 ;			// 全device合計candidate数上限
constexpr std::size_t MAXIMUM_OFFICIAL_INF_BINDINGS = 4096U ;		// 一scanの公式INF binding上限
constexpr int		  GUID_STRING_CHARACTERS		= 39 ;			// Brace付きGUIDと終端nullのUTF-16文字数

// 通常経路が使う不変のWindows API表。実行中のglobal差替えを行わない
const DriverStoreInventoryTransport NATIVE_INVENTORY_TRANSPORT{} ;

//------------------------------------------------------------------------------
// 内部型定義
//------------------------------------------------------------------------------

/**
 * @brief HDEVINFO を SetupDiDestroyDeviceInfoList で解放する RAII wrapper である
 */
class DeviceInfoSet					final {
public:
	/**
     * @brief 指定 handle の device information set ownership を取得する
     * @param[in] value `SetupDiGetClassDevsW` が返した handle
     * @param[in] transport Handle生成元のAPI表。Close関数をcopyして保持する
     */
	//------------------------------------------------------------------------------
	explicit DeviceInfoSet( const HDEVINFO						value,
										   const DriverStoreInventoryTransport &transport =
											   driver_store_inf_detail::transport().inventory) noexcept
		: value_( value), close_( transport.close)
	{
	}

	/**
     * @brief 有効な device information set handle を解放する
     */
	//------------------------------------------------------------------------------
	~DeviceInfoSet()
	{
		// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う
		if( value_ != INVALID_HANDLE_VALUE) {
			close_( value_) ;
		}
	}

	// 一つのHDEVINFOを重複解放しないようcopyを禁止する
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DeviceInfoSet( const DeviceInfoSet &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DeviceInfoSet		  &operator=( const DeviceInfoSet &) = delete ;

	/**
     * @brief 所有する device information set handle を返す
     * @return 呼出し側へ ownership を移さない HDEVINFO
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HDEVINFO get() const noexcept
	{
		return value_ ;
	}

	/**
     * @brief 所有 handle が SetupAPI の失敗 sentinel でないかを判定する
     * @return 解放可能な handle の場合は `true`
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] bool valid() const noexcept
	{
		return value_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// DestroyDeviceInfoListで解放する所有handle
	HDEVINFO								value_{INVALID_HANDLE_VALUE} ;
	/// 同じbackendの解放関数。API表自体の寿命へ依存しない
	decltype( &SetupDiDestroyDeviceInfoList) close_{
		driver_store_inf_detail::transport().inventory.close} ;
} ;

/**
 * @brief device に関連付けた compatible driver list を確実に破棄する RAII guard である
 */
class DriverInfoList final {
public:
	/**
     * @brief 指定 device に構築される compatible driver list の解放条件を保持する
     * @param[in] set device information set
     * @param[in,out] device list を構築する対象 device metadata
     * 指定 device に構築される compatible driver listの解放条件を保持する
     */
	//------------------------------------------------------------------------------
	DriverInfoList( const HDEVINFO set, SP_DEVINFO_DATA &device) noexcept
		: set_( set), device_( &device)
	{
	}

	/**
     * @brief 構築済みの場合だけ compatible driver list を破棄する
     */
	//------------------------------------------------------------------------------
	~DriverInfoList()
	{
		// 構築が成功した互換driver listに対してだけSetupAPIの解放を行う
		if( built_) {
			driver_store_inf_detail::transport().destroyDrivers( set_, device_, SPDIT_COMPATDRIVER) ;
		}
	}

	// 同一compatible listを重複破棄しないようcopyを禁止する
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DriverInfoList( const DriverInfoList &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DriverInfoList &operator=( const DriverInfoList &) = delete ;

	/**
     * @brief compatible driver list の構築成功を記録する
     */
	//------------------------------------------------------------------------------
	void			markBuilt() noexcept
	{
		built_ = true ;
	}

private:
	/// Driver listを所有する非所有device information set
	HDEVINFO		 set_{} ;
	/// 呼出し元がlifetimeを保持する非所有device metadata
	SP_DEVINFO_DATA *device_{} ;
	/// trueの場合だけdestructorでcompatible listを破棄する
	bool			 built_{} ;
} ;

/**
 * @brief 現在使用中の driver を表示・比較するための local metadata である
 */
struct CurrentDriverMetadata {
	/// 現在driverのINF file名
	std::wstring				 infFileName ;
	/// 現在driverのprovider名
	std::wstring				 provider ;
	/// 現在driverの表示version
	std::wstring				 version ;
	/// 現在driverのYYYY/MM/DD表示日付
	std::wstring				 date ;
	/// 解釈できたpacked version
	std::optional<std::uint64_t> packedVersion ;
	/// INF属性の読取り結果。生file名はこのworker内だけに保持する
	DevicePropertyReadStatus	 infRead ;
	/// Provider属性の読取り結果
	DevicePropertyReadStatus	 providerRead ;
	/// 現在版属性の読取り結果
	DevicePropertyReadStatus	 versionRead ;
	/// 日付属性の読取り結果
	DevicePropertyReadStatus	 dateRead ;
} ;

/**
 * @brief driver node の導入時再照合に使用する非公開 metadata である
 */
struct DriverDetail {
	/// Candidate driver nodeのINF file名
	std::wstring			  infFileName ;
	/// Candidate driver nodeのinstall section名
	std::wstring			  sectionName ;
	/// 明示的に要求した場合だけ取得するnodeの元Hardware IDとCompatible ID
	std::vector<std::wstring> modelIds ;
} ;

/**
 * @brief G11-D監査中だけ保持する現在deviceとdriverの秘密metadataである
 */
struct DeviceRankSnapshot {
	/// 現在deviceのsetup class名
	std::wstring					   deviceClass ;
	/// 原Class propertyの不存在/空/失敗を区別した状態です
	DevicePropertyReadStatus		   classRead ;
	/// 原ClassGUID propertyの型付き読取状態です
	DevicePropertyReadStatus		   classGuidRead ;
	/// 原ClassGUID propertyの値。不存在時は空です
	std::wstring					   observedClassGuid ;
	/// 再open直後のClassGUID。一覧構築で変更されるmetadataと分離します
	std::wstring					   nativeClassGuid ;
	/// 原ClassとGUIDが整合した観測方式。未知現在driverを初回へ補完しません
	OfficialDriverRankDeviceClassState classState{OfficialDriverRankDeviceClassState::KNOWN_CLASS} ;
	/// 具体性順のdevice Hardware ID群
	std::vector<std::wstring>		   hardwareIds ;
	/// 具体性順のdevice Compatible ID群
	std::vector<std::wstring>		   compatibleIds ;
	/// Windowsが現在driverに使用したPnP ID
	std::wstring					   matchingDeviceId ;
	/// Matching IDの正式不存在を空文字や読取失敗と区別します
	DevicePropertyReadStatus		   matchingRead ;
	/// 現在driver nodeの再照合metadata
	CurrentDriverMetadata			   currentDriver ;
	/// NativeでPresent/Code28/全属性欠損/installed-node不在を確認した場合だけtrueです
	bool							   noDriver{} ;
	/// 同一照会のdevnode statusとproblem。直前変化を検出するためworker内で保持します
	DeviceNodeObservation			   node ;
	/// 生driver keyの読取り状態。欠損をAPI失敗から区別します
	DevicePropertyReadStatus		   driverKeyRead ;
	/// 現在driver keyのworker内限定値
	std::wstring					   driverKey ;
} ;

/**
 * @brief 単一外部INFから一意に特定したWindows compatible driver nodeである
 */
struct CandidateDriverNodeSnapshot {
	/// 同じ検査済みINFがWindowsへ申告したClassGUIDです
	std::wstring			  infClassGuid ;
	/// 単一INFの互換一覧が返したClassGUIDです。元device観測とは別軸です
	std::wstring			  classGuid ;
	/// SetupAPIが返したinstall section名
	std::wstring			  sectionName ;
	/// 一意なnodeで明示的に要求した元Models行の順序付きID
	std::vector<std::wstring> modelIds ;
	/// SetupAPIが返したProvider表示名
	std::wstring			  provider ;
	/// SetupAPIが返した4要素version
	std::wstring			  version ;
	/// SetupAPIが返したYYYY/MM/DD日付
	std::wstring			  date ;
	/// SetupAPIが返したpacked version
	std::uint64_t			  packedVersion{} ;
	/// SetupAPIが返したFILETIME日付
	std::uint64_t			  dateTicks{} ;
	/// SetupAPIが算出したfull Windows rank
	std::uint32_t			  rank{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 error を NativeError に保持できる HRESULT へ変換する
 *
 * @param[in] error `GetLastError` が返した値
 * @return HRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/** @brief 登録先照合中のfile/directory handleを単独所有します */
class RegisteredInfHandle final {
public:
	/**
	 * @brief 未取得handleを作ります
	 */
	RegisteredInfHandle() = default ;
	/**
	 * @brief 取得したhandleだけを解放します
	 */
	~RegisteredInfHandle() noexcept
	{
		// 所有している一handleだけをWindowsへ返します
		if( valid()) {
			CloseHandle( handle_) ;
		}
	}
	/**
	 * @brief Handleの二重所有を禁止します
	 */
	RegisteredInfHandle( const RegisteredInfHandle &) = delete ;
	/**
	 * @brief Handleのcopy代入を禁止します
	 */
	RegisteredInfHandle &operator=( const RegisteredInfHandle &) = delete ;
	/**
	 * @brief 新しい一handleの所有だけを取得します
	 * @param[in] handle CreateFileWの返却値。INVALID_HANDLE_VALUEも保持できます
	 */
	void				 reset( HANDLE handle) noexcept
	{
		// 以前の取得に成功している場合だけ古いhandleを返します
		if( valid()) {
			CloseHandle( handle_) ;
		}

		handle_ = handle ;
	}
	/**
	 * @brief 読取り用の借用handleを返します
	 * @return このguardの生存中だけ有効なhandleです
	 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}
	/**
	 * @brief Handle取得が成功しているか確認します
	 * @return NullとINVALID_HANDLE_VALUE以外だけtrueです
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return handle_ && handle_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// 同scope内だけで所有するfile/directory handle
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

/** @brief 登録rootと元INF/登録INFを指定導入終端までpinし、実byte一致を確認します */
class RegisteredInfGuard final {
public:
	/**
	 * @brief 既知Windows INF rootと元保護INFを変更不能な読取りへ固定します
	 * @param[in] source 元保護workspaceの完全INF path
	 * @return 全root/source確認成功0、元API失敗またはpath拒否HRESULTです
	 */
	[[nodiscard]] NativeError initialize( const std::wstring &source)
	{
		std::array<wchar_t, MAX_PATH> directory{} ;	// 同backendの既知Windows rootだけです
		const auto length = driver_store_inf_detail::transport().windowsDirectory(
			directory.data(),
			// Native/defaultまたは完全fake
			static_cast<UINT>( directory.size())) ;
		// 切詰めや不正終端のrootから登録先を推測しません
		if( length == 0U || length >= directory.size() || directory[length] != L'\0' ||
		   std::find( directory.begin(), directory.begin() + length, L'\0') !=
			   directory.begin() + length) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring windowsRoot{directory.data(),
									   length} ;	// 元返却rootは正規化で範囲を広げません
		// UNC/相対rootや再解析されたWindows directoryを登録先へ認めません
		if( windowsRoot.size() < 3U || windowsRoot[1] != L':' || windowsRoot[2] != L'\\' ||
		   windowsRoot.find( L'/', 0U) != std::wstring::npos || windowsRoot.back() == L'\\') {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		const auto windowsAttributes = GetFileAttributesW( windowsRoot.c_str()) ;	// Rootの実属性
		rootPath_					 = windowsRoot + L"\\INF" ;
		const auto rootAttributes =
			// 登録直下directoryの実属性
			GetFileAttributesW( rootPath_.c_str()) ;
		// 欠損/再解析点/通常fileを既知登録directoryへ昇格しません
		if( windowsAttributes == INVALID_FILE_ATTRIBUTES ||
		   rootAttributes == INVALID_FILE_ATTRIBUTES ||
		   (windowsAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   ((windowsAttributes | rootAttributes) & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		root_.reset( CreateFileW( rootPath_.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
								FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
								FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
								nullptr)) ;
		const auto sourceAttributes = GetFileAttributesW( source.c_str()) ;	// 元共通検査INFの属性
		// 元INFの欠損・再解析点・directoryから内容証拠を生成しません
		if( !root_.valid() || sourceAttributes == INVALID_FILE_ATTRIBUTES ||
		   (sourceAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		source_.reset( CreateFileW( source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
								  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		// 元INFをwrite/deleteと共有せず、stageと指定導入の間も変更を防ぎます
		if( !source_.valid()) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		LARGE_INTEGER size{} ;	// 元INFの正の完全byte数
		// 長さ不明のINFを登録済み内容と比較しません
		if( !GetFileSizeEx( source_.get(), &size) || size.QuadPart <= 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		sourceBytes_ = static_cast<std::uint64_t>( size.QuadPart) ;
		return computeFileSha256( source, sourceSha256_) ;
	}
	/**
	 * @brief 完全返却pathのroot containmentと元INF全byteを照合します
	 * @param[in] staged Windows stageが返した未変更の完全path
	 * @return 登録rootと全byte一致0、それ以外は元HRESULTです
	 */
	[[nodiscard]] NativeError verify( const std::wstring &staged)
	{
		std::array<wchar_t, MAX_PATH> canonical{} ;	// 相対/別名/脱出を受理しない完全path
		const auto					  length =
			GetFullPathNameW( staged.c_str(), static_cast<DWORD>( canonical.size()), canonical.data(),
							 nullptr) ;							// 書換えはせず元値との一致を要求します
		const auto separator = staged.find_last_of( L'\\') ;	// 登録root直下の親境界
		// 部分prefixや..、別root、nested directoryを登録先と扱いません
		if( length == 0U || length >= canonical.size() || staged.size() != length ||
		   CompareStringOrdinal( staged.c_str(), -1, canonical.data(), -1, TRUE) != CSTR_EQUAL ||
		   separator == std::wstring::npos || separator + 1U >= staged.size() ||
		   CompareStringOrdinal( staged.substr( 0U, separator).c_str(), -1, rootPath_.c_str(), -1,
								TRUE) != CSTR_EQUAL) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		const auto attributes = GetFileAttributesW( staged.c_str()) ;	// 実登録fileの属性
		// 登録pathの通常file以外を指定導入へ渡しません
		if( attributes == INVALID_FILE_ATTRIBUTES ||
		   (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		// 最初の正常pathをwrite/deleteと共有せず指定導入終端までpinします
		if( !staged_.valid()) {
			staged_.reset( CreateFileW( staged.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		}

		// 実fileのopen失敗を保護sourceへのfallbackで補いません
		if( !staged_.valid()) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::array<wchar_t, 1024U> rootFinal{} ;	// Pinしたdirectoryの実解決先
		std::array<wchar_t, 1024U> stagedFinal{} ;	// Pinした登録fileの実解決先
		const auto				   rootLength = GetFinalPathNameByHandleW(
			root_.get(), rootFinal.data(), static_cast<DWORD>( rootFinal.size()),
			FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// Pin済みrootの実解決長です
		const auto stagedLength = GetFinalPathNameByHandleW(
			staged_.get(), stagedFinal.data(), static_cast<DWORD>( stagedFinal.size()),
			FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// Pin済み登録fileの実解決長です
		// 各pinの実解決先も同directory直下でなければ親再解析/別名を拒否します
		if( rootLength == 0U || rootLength >= rootFinal.size() || stagedLength == 0U ||
		   stagedLength >= stagedFinal.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring expectedFinal = std::wstring{rootFinal.data(), rootLength} +
										   // 直下一fileだけ
										   staged.substr( separator) ;
		// Rootの文字列一致だけでなくpinした実pathの完全一致を要求します
		if( CompareStringOrdinal( expectedFinal.c_str(), -1, stagedFinal.data(), -1, TRUE) !=
		   CSTR_EQUAL) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		return verifyOfficialFileMetadata( staged, {sourceBytes_, sourceSha256_}) ;
	}
	/**
	 * @brief Stage cacheを元完全内容へ結合するhashを返します
	 * @return Guard生存中の元INF SHA-256です。取得権限ではありません
	 */
	[[nodiscard]] const std::wstring &sourceSha256() const noexcept
	{
		return sourceSha256_ ;
	}

private:
	/// 書換え/deletionと共有しない元INF handle
	RegisteredInfHandle source_ ;
	/// 同backendの登録INF rootを移動/deletionと共有しないdirectory handle
	RegisteredInfHandle root_ ;
	/// 書換え/deletionと共有しない登録INF handle
	RegisteredInfHandle staged_ ;
	/// 完全照合する既知Windows root直下INF directory
	std::wstring		rootPath_ ;
	/// 元共通検査INFの完全SHA-256
	std::wstring		sourceSha256_ ;
	/// 元共通検査INFの正の完全byte数
	std::uint64_t		sourceBytes_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を区別しない照合用に Windows identifierを正規化する
 *
 * @param[in] value Hardware ID または path component
 * @return invariant な大文字表現
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeIdentifier( const std::wstring_view value)
{
	std::wstring normalized( value) ;	// 大文字へ正規化するmutable識別子
	// Windows の device identifier は大文字小文字を区別しないため、全 code unit を正規化する
	std::transform(
		normalized.begin(), normalized.end(), normalized.begin(),
		[]( const wchar_t character) { return static_cast<wchar_t>( std::towupper( character)) ; }) ;
	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一台のDisplayデバイスに対応する物理GPUの種別をWindowsから取得する
 * @param[in] instanceId 同じ検索で読んだDisplayデバイスの生ID。Windowsの宣言に従い書込み可能バッファを渡す
 * @return 一台の内蔵又はディスクリートGPUを確認した種別。不明・未対応・曖昧な場合はUNKNOWN
 * @note 読取り専用。元IDとLUIDは同期中だけ使い、種別は自動選択にだけ渡す
 */
//------------------------------------------------------------------------------
GraphicsAdapterKind readGraphicsAdapterKind( std::wstring &instanceId)
{
	const std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype( &FreeLibrary)> module(
		LoadLibraryExW( L"dxcore.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32),
		&FreeLibrary) ;	// OS機能の同期所有
	// DXCoreがないWindowsでも通常の端末検索を継続する
	if( !module || instanceId.empty()) {
		return GraphicsAdapterKind::UNKNOWN ;
	}

	using CreateFactory = HRESULT( WINAPI *)( REFIID, void **) ;	// 公開関数のWindows ABI
	const auto create	= std::bit_cast<CreateFactory>( GetProcAddress(
		  // 同じABIとしてシステム関数を借用
		  module.get(), "DXCoreCreateAdapterFactory")) ;
	Microsoft::WRL::ComPtr<IDXCoreAdapterFactory> factory ;	// システムモジュール内の照会元
	// 未対応の関数又はファクトリ作成失敗に推定を加えない
	if( !create || FAILED( create( IID_PPV_ARGS( factory.GetAddressOf())))) {
		return GraphicsAdapterKind::UNKNOWN ;
	}

	GUID arrival = GUID_DISPLAY_DEVICE_ARRIVAL ;	// 同じデバイスのWDDMインターフェイス
	std::array<wchar_t, 4096U> interfaces{} ;		// デバイス限定の現在のパスを満たす有限領域
	const auto				   listed = CM_Get_Device_Interface_ListW(
		&arrival, instanceId.data(), interfaces.data(), static_cast<ULONG>( interfaces.size()),
		CM_GET_DEVICE_INTERFACE_LIST_PRESENT) ;					// 元OS結果
	const auto end = std::ranges::find( interfaces, L'\0') ;	// 先頭インターフェイスの終端
	// 対応なし、複数候補又は上限を超える結果は一台へ分類しない
	if( listed != CR_SUCCESS || end == interfaces.begin() || end == interfaces.end() ||
	   end + 1 == interfaces.end() || *(end + 1) != L'\0') {
		return GraphicsAdapterKind::UNKNOWN ;
	}

	D3DKMT_OPENADAPTERFROMDEVICENAME opened{} ;	// 同じデバイスのLUIDを読む
	opened.pDeviceName = interfaces.data() ;
	// 同じインターフェイスで開けるデバイスだけをDXCoreへ結び付ける
	if( D3DKMTOpenAdapterFromDeviceName( &opened) != 0) {
		return GraphicsAdapterKind::UNKNOWN ;
	}

	Microsoft::WRL::ComPtr<IDXCoreAdapter> adapter ;	// 開いたLUIDに対応するDXCoreアダプター
	const auto							   matched = factory->GetAdapterByLuid( opened.AdapterLuid,
																			   // LUIDの照合結果
																			   IID_PPV_ARGS( adapter.GetAddressOf())) ;
	const D3DKMT_CLOSEADAPTER close{opened.hAdapter} ;					// 登録や変更を伴わない照会ハンドル
	const auto				  closed = D3DKMTCloseAdapter( &close) ;	// 照会元への参照解放の診断
	// 同一の有効なグラフィックスアダプターを確認できる場合だけ種別を調べる
	if( FAILED( matched) || closed != 0 || !adapter || !adapter->IsValid() ||
	   !adapter->IsAttributeSupported( DXCORE_ADAPTER_ATTRIBUTE_D3D11_GRAPHICS)) {
		return GraphicsAdapterKind::UNKNOWN ;
	}

	bool hardware{} ;		// DXCoreの物理GPU確認
	UINT physicalCount{} ;	// 同じ論理アダプターの物理台数
	bool integrated{} ;		// Windowsが報告する内蔵GPUの真偽
	// ソフトウェアアダプターと複数の物理GPUを一台として数えない
	if( FAILED( adapter->GetProperty( DXCoreAdapterProperty::IsHardware, &hardware)) || !hardware ||
	   FAILED( adapter->GetProperty( DXCoreAdapterProperty::PhysicalAdapterCount, &physicalCount)) ||
	   physicalCount != 1U ||
	   FAILED( adapter->GetProperty( DXCoreAdapterProperty::IsIntegrated, &integrated)) ||
	   !adapter->IsValid()) {
		return GraphicsAdapterKind::UNKNOWN ;
	}

	return integrated ? GraphicsAdapterKind::INTEGRATED : GraphicsAdapterKind::DISCRETE ;
}

//------------------------------------------------------------------------------
/**
 * @brief path を UI へ渡さず、照合に必要な file name componentだけを得る
 *
 * @param[in] path INF path または file name
 * @return 最後の区切り以降を正規化した値
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizedFileName( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L"\\/") ;	// 最後のpath区切り位置
	return normalizeIdentifier( separator == std::wstring_view::npos ? path
																	: path.substr( separator + 1)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Win32失敗を属性欠損・不正・有限上限と区別して保持する
 * @param[in] error 元APIまたは検証失敗のcode。0は不正応答として扱う
 * @return 値を持たない読取り結果
 */
//------------------------------------------------------------------------------
DevicePropertyReadStatus propertyFailure( const DWORD error) noexcept
{
	DevicePropertyReadState state = DevicePropertyReadState::FAILED ;	// 原因を保持する既定区分
	// OSが明示したproperty不存在だけを欠損として扱う
	if( error == ERROR_NOT_FOUND) {
		state = DevicePropertyReadState::NOT_PRESENT ;
	}
	// 型・終端不正や診断なし失敗を通常の欠損と混同しない
	else if( error == ERROR_INVALID_DATA || error == ERROR_SUCCESS) {
		state = DevicePropertyReadState::INVALID_DATA ;
	}
	// 容量増大や有限上限を再確保ループで回避しない
	else if( error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_MORE_DATA) {
		state = DevicePropertyReadState::LIMIT_REACHED ;
	}

	return {state,
			{DeviceDiagnosticDomain::WINDOWS_ERROR,
			 error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Propertyを必要量照会と一回の取得で検証する
 * @param[in] set 借用するdevice information set
 * @param[in,out] device 同じ集合のdevice metadata
 * @param[in] key 取得する固定property key
 * @param[in] expectedType 許可するproperty型
 * @param[out] bytes 成功時だけ実sizeの値を保持する。失敗時は空
 * @param[in] transport 同じ集合のAPI表
 * @return 型・size・API成否を区別した結果
 * @note STRING_LISTの実一文字はここではbyte境界だけを確認し、内容と終端は専用parserで検証する
 */
//------------------------------------------------------------------------------
DevicePropertyReadStatus readObservedProperty( const HDEVINFO set, SP_DEVINFO_DATA &device,
											  const DEVPROPKEY &key, const DEVPROPTYPE expectedType,
											  std::vector<std::byte>			  &bytes,
											  const DriverStoreInventoryTransport &transport)
{
	bytes.clear() ;
	DEVPROPTYPE type{} ;		// APIが返した型
	DWORD		required{} ;	// 必要容量（byte）
	// 必要容量を一度だけ照会し、二回目の増大時は再確保しない
	const BOOL	sized	  = transport.property( set, &device, &key, &type, nullptr, 0, &required, 0) ;
	const DWORD sizeError = sized ? ERROR_SUCCESS : GetLastError() ;	// 直前の失敗だけを保持する
	// 通常の必要量通知以外の失敗は取得を始めず保持する
	if( !sized && sizeError != ERROR_INSUFFICIENT_BUFFER) {
		return propertyFailure( sizeError) ;
	}

	// 固定上限を超える値は確保しない
	if( required > MAXIMUM_DEVICE_PROPERTY_BYTES) {
		return propertyFailure( ERROR_MORE_DATA) ;
	}

	// 文字列とFILETIMEの必要量を確保前に検証する
	if( required == 0U ||
	   (expectedType == DEVPROP_TYPE_STRING && required % sizeof( wchar_t) != 0U) ||
	   (expectedType == DEVPROP_TYPE_STRING_LIST &&
		(required < sizeof( wchar_t) || required % sizeof( wchar_t) != 0U)) ||
	   (expectedType == DEVPROP_TYPE_FILETIME && required != sizeof( FILETIME))) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> buffer( required) ;	// 上限確認済みの借用API出力領域
	DWORD				   returned{} ;			// 二回目にAPIが返した実size（byte）
	// Windows byte buffer境界だけでcastし、型付き値へは検証後にcopyする
	if( !transport.property( set, &device, &key, &type, reinterpret_cast<PBYTE>( buffer.data()),
						   required, &returned, 0)) {
		return propertyFailure( GetLastError()) ;
	}

	// 成功自己申告でも型・実size・UTF-16境界の不整合を拒否する
	if( type != expectedType || returned == 0U || returned > required ||
	   (expectedType == DEVPROP_TYPE_STRING && returned % sizeof( wchar_t) != 0U) ||
	   (expectedType == DEVPROP_TYPE_STRING_LIST &&
		(returned < sizeof( wchar_t) || returned % sizeof( wchar_t) != 0U)) ||
	   (expectedType == DEVPROP_TYPE_FILETIME && returned != sizeof( FILETIME))) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	buffer.resize( returned) ;
	bytes = std::move( buffer) ;
	return {DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列の実sizeと終端を検証し、空値と失敗を分離する
 * @param[in] set 借用するdevice information set
 * @param[in,out] device 同じ集合のdevice metadata
 * @param[in] key 固定property key
 * @param[out] value 成功した文字列。失敗時は空
 * @param[in] transport 同じ集合のAPI表
 * @return 値・空・欠損・失敗・不正・上限を区別した結果
 */
//------------------------------------------------------------------------------
DevicePropertyReadStatus readObservedDeviceString( const HDEVINFO set, SP_DEVINFO_DATA &device,
												  const DEVPROPKEY &key, std::wstring &value,
												  const DriverStoreInventoryTransport &transport)
{
	value.clear() ;
	std::vector<std::byte> bytes ;	// 実際に返されたbyte列だけを保持する
	// 型・size・API成否を持つ、本文解釈前の結果
	const auto			   status =
		readObservedProperty( set, device, key, DEVPROP_TYPE_STRING, bytes, transport) ;
	// API未成功の値を文字列として解釈しない
	if( status.state != DevicePropertyReadState::VALUE) {
		return status ;
	}

	std::wstring text( bytes.size() / sizeof( wchar_t), L'\0') ;	// Alignmentを満たすcopy先
	std::memcpy( text.data(), bytes.data(), bytes.size()) ;
	const auto end = std::find( text.begin(), text.end(), L'\0') ;	// 実size内の最初の終端
	// 未終端と埋込みNUL後の余剰を拒否し、初期化領域を成功終端にしない
	if( end == text.end() || end + 1 != text.end()) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	text.pop_back() ;
	value = std::move( text) ;
	return {value.empty() ? DevicePropertyReadState::EMPTY : DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief DEVPROP_TYPE_STRING property を上限付きで取得する
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[in] key property key
 * @param[out] value 取得できた文字列
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する
 * @return property を取得できた場合は `true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDeviceString(
	const HDEVINFO set, SP_DEVINFO_DATA &device, const DEVPROPKEY &key, std::wstring &value,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	const auto status =
		// 型付き観測
		readObservedDeviceString( set, device, key, value, transport) ;
	const bool success = status.state == DevicePropertyReadState::VALUE ||
						 // 旧bool APIでは正規空文字も成功とする
						 status.state == DevicePropertyReadState::EMPTY ;
	// 既存呼出し側が参照する診断を、今回の結果だけへ固定する
	SetLastError( success ? ERROR_SUCCESS : status.diagnostic.code) ;
	return success ;
}

//------------------------------------------------------------------------------
/**
 * @brief DEVPROP_TYPE_STRING_LIST property を上限付きで取得する
 *
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[in] key property key
 * @return 検証済みの各文字列。未定義または不正な property は空集合
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::wstring> readDeviceStringList( const HDEVINFO	   set,
															 SP_DEVINFO_DATA  &device,
															 const DEVPROPKEY &key)
{
	DEVPROPTYPE type{} ;		// SetupAPIが返すproperty型
	DWORD		required{} ;	// MULTI_SZ取得に必要なbuffer size（byte）
	driver_store_inf_detail::transport().inventory.property( set, &device, &key, &type, nullptr, 0,
															&required, 0) ;
	// 文字列listの最小終端・UTF-16境界・容量上限を確保前に検証する
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof( wchar_t) * 2U ||
	   required > MAXIMUM_DEVICE_PROPERTY_BYTES || required % sizeof( wchar_t) != 0) {
		return {} ;
	}

	std::vector<std::byte> buffer( required) ;	// 上限検証後に確保するMULTI_SZ受信領域
	// 再取得に失敗したpropertyと文字列list型でないpropertyを照合へ渡さない
	if( driver_store_inf_detail::transport().inventory.property(
		   set, &device, &key, &type, reinterpret_cast<PBYTE>( buffer.data()), required, nullptr,
		   0) == FALSE ||
	   type != DEVPROP_TYPE_STRING_LIST) {
		return {} ;
	}

	const auto		 *text = reinterpret_cast<const wchar_t *>( buffer.data()) ;	// MULTI_SZ先頭位置
	const std::size_t characters = buffer.size() / sizeof( wchar_t) ;				// Buffer内のUTF-16文字数
	std::vector<std::wstring> values ;												// 検証済みのproperty各要素
	std::size_t				  offset{} ;											// 現在読み取る要素のbuffer内文字offset

	// MULTI_SZ の二重 NUL までを buffer 上限内で走査する
	while( offset < characters && text[offset] != L'\0') {
		const std::size_t	 remaining = characters - offset ;	// 未走査のUTF-16文字数
		const wchar_t *const begin	   = text + offset ;		// 現在要素の先頭位置
		// 現在要素の終端null位置
		const wchar_t *const terminator = std::find( begin, begin + remaining, L'\0') ;
		// 残りbuffer内に終端がないlist要素を部分的に採用しない
		if( terminator == begin + remaining) {
			return {} ;
		}

		// 現在要素の終端nullを除く文字数
		const std::size_t length = static_cast<std::size_t>( terminator - begin) ;
		values.emplace_back( text + offset, length) ;
		offset += length + 1 ;
	}

	return values ;
}

//------------------------------------------------------------------------------
/**
 * @brief device instance IDを有限取得し、失敗と不正な応答を分離する
 *
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[out] instanceId worker 内だけで保持する instance ID
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する
 * @return 値または失敗の区分。失敗時のinstanceIdは空
 */
//------------------------------------------------------------------------------
[[nodiscard]] DevicePropertyReadStatus readObservedInstanceId(
	const HDEVINFO set, SP_DEVINFO_DATA &device, std::wstring &instanceId,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	instanceId.clear() ;
	DWORD	   required{} ;	// Instance ID取得に必要なUTF-16文字数
	const BOOL sized =
		// 必要文字数照会
		transport.instanceId( set, &device, nullptr, 0, &required) ;
	const DWORD error = sized ? ERROR_SUCCESS : GetLastError() ;	// 当該APIの診断
	// 容量通知以外の失敗をmissingや空文字へ変換しない
	if( !sized && error != ERROR_INSUFFICIENT_BUFFER) {
		return propertyFailure( error) ;
	}

	// 上限を超えるidentityは再確保せず打ち切る
	if( required > MAXIMUM_DEVICE_INSTANCE_CHARACTERS) {
		return propertyFailure( ERROR_MORE_DATA) ;
	}

	// 空identityをnative照合へ登録しない
	if( required < 2U) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	std::vector<wchar_t> buffer( required, L'\xffff') ;	// 初期0を終端として採用しない受信領域
	DWORD				 returned{} ;					// 実際に返されたNUL込み文字数
	// instance IDの再取得に失敗した場合は未確定値を返さない
	if( transport.instanceId( set, &device, buffer.data(), required, &returned) == FALSE) {
		return propertyFailure( GetLastError()) ;
	}

	// API成功でも実sizeが不正なら確保領域の余りを文字列にしない
	if( returned < 2U || returned > required) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	buffer.resize( returned) ;

	const auto end =
		// 確保済み範囲内の終端だけを許す
		std::find( buffer.begin(), buffer.end(), L'\0') ;
	// API成功でも未終端bufferを無制限の文字列constructorへ渡さない
	if( end == buffer.end() || end == buffer.begin() || end + 1 != buffer.end()) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	instanceId.assign( buffer.begin(), end) ;
	return {DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存のnative照合へ有限なinstance IDを渡す
 * @param[in] set 借用device集合
 * @param[in,out] device 同じ集合のdevice
 * @param[out] instanceId 成功時のID。失敗時は空
 * @param[in] transport 集合と同じAPI表
 * @return 有効な非空IDを取得した場合true。失敗診断をGetLastErrorへ保持する
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDeviceInstanceId(
	const HDEVINFO set, SP_DEVINFO_DATA &device, std::wstring &instanceId,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	const auto status = readObservedInstanceId( set, device, instanceId, transport) ;	// 型付き観測
	SetLastError( status.state == DevicePropertyReadState::VALUE ? ERROR_SUCCESS
																: status.diagnostic.code) ;
	return status.state == DevicePropertyReadState::VALUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief installed driver の FILETIME property を日付表示へ変換する
 *
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[out] date 成功時のYYYY/MM/DD。失敗時は空
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する
 * @return 日付の読取り・変換結果
 */
//------------------------------------------------------------------------------
[[nodiscard]] DevicePropertyReadStatus readObservedDriverDate(
	const HDEVINFO set, SP_DEVINFO_DATA &device, std::wstring &date,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	date.clear() ;
	std::vector<std::byte> bytes ;	// 検証済みFILETIMEのbyte列
	const auto			   status =
		readObservedProperty( set, device, DEVPKEY_Device_DriverDate, DEVPROP_TYPE_FILETIME, bytes,
							 transport) ;	// 固定型・固定size検証
	// 不明日付を0時刻や現在時刻へ補完しない
	if( status.state != DevicePropertyReadState::VALUE) {
		return status ;
	}

	FILETIME value{} ;	// Alignmentを満たすUTC値のcopy先
	std::memcpy( &value, bytes.data(), sizeof( value)) ;

	SYSTEMTIME systemTime{} ;	// 表示用に分解したUTC driver日付
	// FILETIMEを有効なcalendar値へ変換できなければ日付を推測しない
	if( FileTimeToSystemTime( &value, &systemTime) == FALSE) {
		auto failure  = propertyFailure( GetLastError()) ;	// 変換APIの元診断を直ちに保持する
		failure.state = DevicePropertyReadState::INVALID_DATA ;
		return failure ;
	}

	std::array<wchar_t, 16> formatted{} ;	// YYYY/MM/DDと終端nullの受信領域
	// 終端nullを除いて整形されたUTF-16文字数
	const int written = swprintf_s( formatted.data(), formatted.size(), L"%04u/%02u/%02u",
								   systemTime.wYear, systemTime.wMonth, systemTime.wDay) ;
	// 不正calendarや表示容量不足を正規の空日付にしない
	if( written <= 0) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	date.assign( formatted.data(), static_cast<std::size_t>( written)) ;
	return {DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一回のConfiguration Manager照会から有限なnode状態を得る
 * @param[in] device 列挙したdevice。DevInstを同じmachineでのみ使用する
 * @param[in] transport 照会するread-only API表
 * @return 元CONFIGRETまたは成功時のstatus／problem。秘密を保持しない
 */
//------------------------------------------------------------------------------
DeviceNodeObservation readObservedNode( const SP_DEVINFO_DATA			   &device,
									   const DriverStoreInventoryTransport &transport) noexcept
{
	ULONG			flags{} ;	// 同一呼出しで得るstatus bit集合
	ULONG			problem{} ;	// DN_HAS_PROBLEM時だけ有効なcode
	const CONFIGRET result =
		// 元APIの戻り値
		transport.nodeStatus( &flags, &problem, device.DevInst, 0) ;
	// GetLastErrorとは別のCONFIGRETをそのまま保持する
	if( result != CR_SUCCESS) {
		return {{DevicePropertyReadState::FAILED,
				 {DeviceDiagnosticDomain::CONFIGURATION_MANAGER, result}},
				{},
				{}} ;
	}

	DeviceNodeObservation observed{{DevicePropertyReadState::VALUE, {}}, flags, {}} ;	// 成功した一組
	// 有効bitがないときはAPI出力bufferのproblemを採用しない
	if( (flags & DN_HAS_PROBLEM) != 0U) {
		observed.problemCode = problem ;
	}

	// 成功自己申告でも不整合を持つ一組は値を破棄する
	if( !isDeviceNodeObservationValid( observed)) {
		return {propertyFailure( ERROR_INVALID_DATA), {}, {}} ;
	}

	return observed ;
}

//------------------------------------------------------------------------------
/**
 * @brief DWORDLONG 形式の driver version を四要素へ整形する
 *
 * @param[in] version SP_DRVINFO_DATA が返した version
 * @return `a.b.c.d` 形式
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverVersion( const std::uint64_t version)
{
	return std::to_wstring( (version >> 48U) & 0xFFFFU) + L"." +
		   std::to_wstring( (version >> 32U) & 0xFFFFU) + L"." +
		   std::to_wstring( (version >> 16U) & 0xFFFFU) + L"." + std::to_wstring( version & 0xFFFFU) ;
}

//------------------------------------------------------------------------------
/**
 * @brief setup class GUIDをcanonical文字列へ変換する
 *
 * Windows固有のGUID型をcore DTOに公開せず、UIがSetupAPI class iconを選択できる文字列へ変換する
 *
 * @param[in] classGuid SP_DEVINFO_DATAが返したsetup class GUID
 * @return Brace付きcanonical GUID文字列。変換失敗時は空文字列
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatClassGuid( const GUID &classGuid)
{
	std::array<wchar_t, GUID_STRING_CHARACTERS> text{} ;	// GUID文字列の受信領域
	const int									written =
		// 終端込み文字数
		StringFromGUID2( classGuid, text.data(), static_cast<int>( text.size())) ;
	return written > 1 ? std::wstring( text.data(), static_cast<std::size_t>( written - 1))
					   : std::wstring{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 四要素までの表示 version を DWORDLONG へ変換する
 *
 * @param[in] version device property が返した version
 * @return 全要素が 16-bit 範囲で解釈できた場合の packed version
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseDriverVersion( const std::wstring_view version)
{
	std::array<std::uint64_t, 4> parts{} ;		// 左から最大四個の16-bit version要素
	std::size_t					 partIndex{} ;	// 次に格納するparts内index
	std::size_t					 offset{} ;		// 次に解析するversion文字列内offset

	// 最大四要素を左から読み、空要素、非数字、16-bit 超過を拒否する
	while( offset < version.size() && partIndex < parts.size()) {
		const std::size_t separator = version.find( L'.', offset) ;	// 次の区切り位置
		// 現在要素の終端位置
		const std::size_t end = separator == std::wstring_view::npos ? version.size() : separator ;
		// 空のversion componentをゼロで補って比較しない
		if( end == offset) {
			return std::nullopt ;
		}

		std::uint64_t value{} ;	// 現在解析中のversion要素値
		// 現在要素の全文字を10進数字として検証し、16-bit上限内で組み立てる
		for( std::size_t index = offset; index < end; ++index) {
			// version componentにASCII数字以外を許可しない
			if( version[index] < L'0' || version[index] > L'9') {
				return std::nullopt ;
			}

			value = value * 10U + static_cast<std::uint64_t>( version[index] - L'0') ;
			// DWORDLONGの一componentに対応する16-bit範囲を超える値を拒否する
			if( value > 0xFFFFU) {
				return std::nullopt ;
			}
		}

		parts[partIndex] = value ;
		++partIndex ;
		// dotが残っていない場合は入力末尾まで消費済みとして確定する
		if( separator == std::wstring_view::npos) {
			offset = version.size() ;
		} else {
			offset = separator + 1 ;
		}
	}

	// component未取得と四要素に収まらない残余入力を拒否する
	if( partIndex == 0 || offset < version.size()) {
		return std::nullopt ;
	}

	return (parts[0] << 48U) | (parts[1] << 32U) | (parts[2] << 16U) | parts[3] ;
}

//------------------------------------------------------------------------------
/**
 * @brief FILETIME を日付文字列へ変換する
 *
 * @param[in] value driver metadata の UTC 日付
 * @return `YYYY/MM/DD` または空文字列
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverDate( const FILETIME &value)
{
	SYSTEMTIME systemTime{} ;	// 表示用に分解したUTC driver日付
	// 無効なFILETIMEは空表示とし、推測の日付を返さない
	if( FileTimeToSystemTime( &value, &systemTime) == FALSE) {
		return {} ;
	}

	std::array<wchar_t, 16> formatted{} ;	// YYYY/MM/DDと終端nullの受信領域
	// 終端nullを除いて整形されたUTF-16文字数
	const int written = swprintf_s( formatted.data(), formatted.size(), L"%04u/%02u/%02u",
								   systemTime.wYear, systemTime.wMonth, systemTime.wDay) ;
	return written > 0 ? std::wstring( formatted.data(), static_cast<std::size_t>( written))
					   : std::wstring{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF DriverVerの日付を検証してWindows node表示形式へ揃える
 *
 * 区切りと全数字を検証し、Windowsの暦日変換を往復して存在しない日付をfail-closedで拒否する
 *
 * @param[in] value INF DriverVerのMM/DD/YYYY日付
 * @return 妥当な暦日のYYYY/MM/DD表記。不正な場合は`std::nullopt`
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeInfDriverDate( const std::wstring_view value)
{
	// INF DriverVer日付の固定長とslash位置が一致しなければ拒否する
	if( value.size() != 10U || value[2U] != L'/' || value[5U] != L'/') {
		return std::nullopt ;
	}

	// 区切り以外をASCII数字へ限定し、locale依存の解釈を避ける
	for( std::size_t index = 0U; index < value.size(); ++index) {
		// 日付の数字位置にASCII数字以外を許可しない
		if( index != 2U && index != 5U && (value[index] < L'0' || value[index] > L'9')) {
			return std::nullopt ;
		}
	}

	// INF表記から取得する月
	const WORD month = static_cast<WORD>( (value[0U] - L'0') * 10 + (value[1U] - L'0')) ;
	// INF表記から取得する日
	const WORD day = static_cast<WORD>( (value[3U] - L'0') * 10 + (value[4U] - L'0')) ;
	// INF表記から取得する西暦年
	const WORD year = static_cast<WORD>( (value[6U] - L'0') * 1000 + (value[7U] - L'0') * 100 +
										(value[8U] - L'0') * 10 + (value[9U] - L'0')) ;
	SYSTEMTIME source{} ;	// INF値から構築する検証前の暦日
	source.wYear  = year ;
	source.wMonth = month ;
	source.wDay	  = day ;
	FILETIME fileTime{} ;	// Windowsの暦日検証を通したUTC FILETIME
	// calendar値をFILETIMEへ変換できなければ不正日付として拒否する
	if( SystemTimeToFileTime( &source, &fileTime) == FALSE) {
		return std::nullopt ;
	}

	SYSTEMTIME roundTrip{} ;	// 自動補正がないことを確認する往復後の暦日
	// calendarのround-tripで年月日が変化する値を実在日付として扱わない
	if( FileTimeToSystemTime( &fileTime, &roundTrip) == FALSE || roundTrip.wYear != year ||
	   roundTrip.wMonth != month || roundTrip.wDay != day) {
		return std::nullopt ;
	}

	std::wstring normalized = formatDriverDate( fileTime) ;	// Windows node比較用表記
	// 検証済み日付でも表示形式を生成できなければ未確定として返す
	if( normalized.empty()) {
		return std::nullopt ;
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief FILETIME の bit pattern を比較・再照合用整数へ変換する
 *
 * @param[in] value 変換元 FILETIME
 * @return 64-bit tick 値
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t fileTimeTicks( const FILETIME &value) noexcept
{
	ULARGE_INTEGER ticks{} ;	// FILETIMEのlow/highを連結する共用体
	ticks.LowPart  = value.dwLowDateTime ;
	ticks.HighPart = value.dwHighDateTime ;
	return ticks.QuadPart ;
}

//------------------------------------------------------------------------------
/**
 * @brief driver node の INF と section metadata を上限付きで取得する
 *
 * driver node の INF と section metadataを上限付きで取得する
 *
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[in] driver driver node metadata
 * @param[out] detail UI へ公開しない照合 metadata
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @param[in] captureModelIds 同nodeの可変長のHardware IDとCompatible IDを確認する場合true
 * @return 取得できた場合は `true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDriverDetail( const HDEVINFO set, SP_DEVINFO_DATA &device,
									SP_DRVINFO_DATA_W &driver, DriverDetail &detail,
									InfFailureDiagnostic *diagnostic	  = nullptr,
									bool				  captureModelIds = false)
{
	detail = {} ;
	DWORD required{} ;	// Driver detail取得に必要なbuffer size（byte）
	SetLastError( ERROR_SUCCESS) ;
	driver_store_inf_detail::transport().detail( set, &device, &driver, nullptr, 0, &required) ;
	const DWORD sizeError = GetLastError() ;	// 元の一回の照会結果を直後に固定します
	// driver詳細の必要量が構造体以上かつ上限以下でなければ確保しない
	if( sizeError != ERROR_INSUFFICIENT_BUFFER || required < sizeof( SP_DRVINFO_DETAIL_DATA_W) ||
	   required > MAXIMUM_DRIVER_DETAIL_BYTES || required % sizeof( wchar_t) != 0U) {
		markInfFailure( diagnostic, InfDiagnosticStage::DETAIL_SIZE,
					   sizeError != ERROR_SUCCESS && sizeError != ERROR_INSUFFICIENT_BUFFER
						   ? InfDiagnosticOrigin::NATIVE_API
						   : InfDiagnosticOrigin::INTERNAL_CONTRACT,
					   sizeError) ;
		return false ;
	}

	std::vector<std::byte> buffer( required) ;	// 上限検証後に確保するdetail受信領域
	// Buffer上の可変長SP_DRVINFO_DETAIL_DATA view
	auto *nativeDetail	 = reinterpret_cast<SP_DRVINFO_DETAIL_DATA_W *>( buffer.data()) ;
	nativeDetail->cbSize = sizeof( SP_DRVINFO_DETAIL_DATA_W) ;
	DWORD returned{} ;	// 可変IDを含む二回目の必要byte長です。固定fieldだけのFALSEと分けます
	// static fieldを得たINSUFFICIENT_BUFFERでも完全detail成功へ昇格しません
	if( driver_store_inf_detail::transport().detail( set, &device, &driver, nativeDetail, required,
												   &returned) == FALSE) {
		markInfFailure( diagnostic, InfDiagnosticStage::DETAIL_READ,
					   InfDiagnosticOrigin::NATIVE_API) ;
		return false ;
	}

	const auto infEnd =
		std::find( std::begin( nativeDetail->InfFileName), std::end( nativeDetail->InfFileName),
				  L'\0') ;	// 固定MAX_PATHの範囲内終端です
	const auto sectionEnd =
		std::find( std::begin( nativeDetail->SectionName), std::end( nativeDetail->SectionName),
				  L'\0') ;	// 固定LINE_LENの範囲内終端です
	// byte容量、再照会必要長、固定文字列の終端を別々に検証します
	if( returned > required || (returned != 0U && returned < sizeof( SP_DRVINFO_DETAIL_DATA_W)) ||
	   infEnd == std::end( nativeDetail->InfFileName) ||
	   sectionEnd == std::end( nativeDetail->SectionName)) {
		SetLastError( ERROR_INVALID_DATA) ;
		markInfFailure( diagnostic, InfDiagnosticStage::DETAIL_BOUNDS,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return false ;
	}

	detail.infFileName.assign( nativeDetail->InfFileName, infEnd) ;
	detail.sectionName.assign( nativeDetail->SectionName, sectionEnd) ;
	// Models行を照合する呼出しだけがWindowsの可変長ID領域を使用する
	if( captureModelIds) {
		constexpr auto start = offsetof( SP_DRVINFO_DETAIL_DATA_W, HardwareID) ;	// 可変長領域の境界
		// byte長が文字境界に一致する場合だけHardwareID以降を読む
		if( returned == 0U || returned % sizeof( wchar_t) != 0U ||
		   !driver_store_inf_detail::readDriverModelIds(
			   {reinterpret_cast<const wchar_t *>( buffer.data() + start),
				(returned - start) / sizeof( wchar_t)},
			   nativeDetail->CompatIDsOffset, nativeDetail->CompatIDsLength, detail.modelIds)) {
			SetLastError( ERROR_INVALID_DATA) ;
			markInfFailure( diagnostic, InfDiagnosticStage::DETAIL_BOUNDS,
						   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return false ;
		}
	}

	const bool complete =
		!detail.infFileName.empty() && !detail.sectionName.empty() ;	// 元必須metadata判定です
	// API成功でも空metadataを完全detailへ補完しません
	if( !complete) {
		markInfFailure( diagnostic, InfDiagnosticStage::DETAIL_EMPTY,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
	}

	return complete ;
}

//------------------------------------------------------------------------------
/**
 * @brief compatible driver list を構築するための device install parameter を設定する
 *
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[out] diagnostic 任意の原parameter失敗leafです。null可です
 * @return 設定できた場合は `true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool configureCompatibleDriverSearch( const HDEVINFO set, SP_DEVINFO_DATA &device,
												   InfFailureDiagnostic *diagnostic = nullptr)
{
	SP_DEVINSTALL_PARAMS_W parameters{} ;	// Compatible list構築条件を保持するparameter
	parameters.cbSize = sizeof( parameters) ;
	// 現在のinstall parameterを取得できなければ互換listの条件を変更しない
	if( driver_store_inf_detail::transport().getParameters( set, &device, &parameters) == FALSE) {
		markInfFailure( diagnostic, InfDiagnosticStage::PARAMETERS_READ,
					   InfDiagnosticOrigin::NATIVE_API) ;
		return false ;
	}

	// PnP driver の多くは ExcludeFromSelect のため、この flag がないと履歴を列挙できない
	parameters.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS ;
	const BOOL changed = driver_store_inf_detail::transport().setParameters(
		set, &device, &parameters) ;	// 元APIを一回だけ呼びます
	// 元BOOLの成否を変えず、code取得は従来のcallerへ残します
	if( changed == FALSE) {
		markInfFailure( diagnostic, InfDiagnosticStage::PARAMETERS_WRITE,
					   InfDiagnosticOrigin::NATIVE_API) ;
	}

	return changed != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在使用中 driver の表示・照合 metadata を取得する
 *
 * @param[in] set device information set
 * @param[in] device 対象 device
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する
 * @return property がない項目を空値とした metadata
 */
//------------------------------------------------------------------------------
[[nodiscard]] CurrentDriverMetadata readCurrentDriver(
	const HDEVINFO set, SP_DEVINFO_DATA &device,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	CurrentDriverMetadata current ;	// Property欠損を空値で保持する現在driver metadata
	current.infRead		  = readObservedDeviceString( set, device, DEVPKEY_Device_DriverInfPath,
													 current.infFileName, transport) ;
	current.providerRead  = readObservedDeviceString( set, device, DEVPKEY_Device_DriverProvider,
													 current.provider, transport) ;
	current.versionRead	  = readObservedDeviceString( set, device, DEVPKEY_Device_DriverVersion,
													 current.version, transport) ;
	current.dateRead	  = readObservedDriverDate( set, device, current.date, transport) ;
	current.packedVersion = parseDriverVersion( current.version) ;
	return current ;
}

/** @brief Windowsが現在の機器に対して実際に記録した登録INFと導入節 */
struct InstalledStorageInfSelection {
	/// Windows INFフォルダの現在使用中INF名
	std::wstring				publishedInf ;
	/// 現在使用中のDDInstallの元の基本節
	std::wstring				basicSection ;
	/// 元のプラットフォーム装飾。明示空と属性の不存在を区別する
	std::optional<std::wstring> sectionExtension ;
	/**
	 * @brief 同じデバイスから独立に再読した値と照合する
	 * @param[in] other 再観測したINF名・基本節・装飾
	 * @return 元の各値と装飾の有無が一致した場合true
	 */
	bool operator==( const InstalledStorageInfSelection &other) const = default ;
} ;

/** @brief 現在の機器が使用する配布を元属性と同じ署名CATへ結び付けた読み取り結果 */
struct VerifiedInstalledStorageOwner {
	/// 設定前後の再確認に使う同じ機器の元属性
	InstalledStorageInfSelection	 selection ;
	/// 同じ登録INFの署名カタログと選択節から読み取った証拠
	RegisteredStoragePackageEvidence package ;
	/**
	 * @brief 適用前の別読取りと実配布を照合する
	 * @param[in] other 同じ機器を独立に読み直した結果
	 * @return Windows属性と割り当て済み配布の全証拠が一致した場合true
	 */
	bool operator==( const VerifiedInstalledStorageOwner &other) const = default ;
} ;

/** @brief 自動起動補助を調べる現在機器の元登録属性 */
struct AutomaticStorageDeviceRegistration {
	/// 同じインスタンスの現在の関連サービス。正式な未導入では空
	std::wstring				 service ;
	/// 同じインスタンスの公開INFと実節。正式な未導入では空
	InstalledStorageInfSelection selection ;
	/**
	 * @brief 同じ機器の照合前後で現在属性を比較する
	 * @param[in] other 同じ機器を独立に読み直した値
	 * @return 関連名と元INF、基本節、装飾が一致すればtrue
	 */
	bool operator==( const AutomaticStorageDeviceRegistration &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現在使用中INFと実際の導入基本節を同じ機器から取得する
 * @param[in] devices 現在機器の元情報集合
 * @param[in,out] device 同じ情報集合で開いた読み取り対象
 * @param[in] transport 元集合と同じ属性取得のAPI表
 * @param[out] result 成功時だけ元INF名、基本節、元装飾を保持する
 * @return 現在の値の取得成功0、未確定または読取り失敗はHRESULT
 * @note Windowsが返す装飾を保存し、別節へ補正しない
 */
//------------------------------------------------------------------------------
NativeError readInstalledStorageInfSelection( HDEVINFO devices, SP_DEVINFO_DATA &device,
											 const DriverStoreInventoryTransport &transport,
											 InstalledStorageInfSelection		 &result)
{
	result = {} ;
	InstalledStorageInfSelection made ;	// 必須二属性と元装飾の全取得まで保持する
	const std::array			 required{
		std::pair{&DEVPKEY_Device_DriverInfPath, &made.publishedInf},
		std::pair{&DEVPKEY_Device_DriverInfSection, &made.basicSection}} ;	// 現在の必須属性
	// INF名と導入節は候補側の値で補わず、現在の機器自身から取得する
	for( const auto &[key, value] : required) {
		const auto read =
			// 元query結果
			readObservedDeviceString( devices, device, *key, *value, transport) ;
		// 明示空や読取り失敗を候補のINF/節に補完しない
		if( read.state != DevicePropertyReadState::VALUE) {
			return nativeErrorFromWin32( read.diagnostic.code ? read.diagnostic.code
															 : ERROR_NOT_FOUND) ;
		}
	}

	std::wstring extension ;	// Windowsが保持する実際の装飾文字列
	const auto	 read =
		readObservedDeviceString( devices, device, DEVPKEY_Device_DriverInfSectionExt, extension,
								 transport) ;	// 不存在とは別に成功時の空値を保持
	// 実際に読めた属性だけを元装飾として保存する
	if( read.state == DevicePropertyReadState::VALUE ||
	   read.state == DevicePropertyReadState::EMPTY) {
		made.sectionExtension = std::move( extension) ;
	}
	// 未設定とエラー・不正型を混同しない
	else if( read.state != DevicePropertyReadState::NOT_PRESENT) {
		return nativeErrorFromWin32( read.diagnostic.code ? read.diagnostic.code
														 : ERROR_INVALID_DATA) ;
	}

	result = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ現在機器を開き、元登録属性の前後確認の間で読み取り処理を実行する
 * @tparam Inspect 元登録属性を同期利用する読み取り関数の型
 * @param[in] instanceId 先の観測で特定した一機器の元識別子
 * @param[in] noDriver 先の観測が正式な未導入を確認したときtrue
 * @param[in] expectedInf 先の観測が確認した現在INF。不明では空
 * @param[in] inspect 元登録属性、同じAPI表、情報集合と機器情報を同期中だけ借用する処理
 * @return 同一機器と処理の成立で0、元読取り失敗または登録変更はHRESULT
 * @note 処理結果は呼出元の作業領域に置き、前後比較が成功するまで公開しない
 */
//------------------------------------------------------------------------------
template <class Inspect>
NativeError inspectPresentStorageDeviceRegistration( const std::wstring &instanceId, bool noDriver,
													std::wstring_view expectedInf, Inspect inspect)
{
	const auto	 &api = driver_store_inf_detail::transport() ;	// 同じworkerのWindows属性と照会表
	DeviceInfoSet devices( api.create( nullptr, nullptr)) ;		// 対象一つだけを開く情報集合
	// 情報集合が作れないときは同名の別機器を探さない
	if( !devices.valid()) {
		const auto native = GetLastError() ;	// 情報集合の元エラー
		return nativeErrorFromWin32( native ? native : ERROR_INVALID_DATA) ;
	}

	SP_DEVINFO_DATA device{} ;	// 同じ選択機器と結ぶWindows情報
	device.cbSize = sizeof( device) ;
	// 候補の選択時に固定した機器だけを開く
	if( !api.open( devices.get(), instanceId.c_str(), nullptr, 0U, &device)) {
		const auto native = GetLastError() ;	// 同じ選択機器の元エラー
		return nativeErrorFromWin32( native ? native : ERROR_NO_SUCH_DEVINST) ;
	}

	// 同じ情報集合の同じ現在インスタンスを前後で確認する。各参照はこの同期読取りだけで有効
	const auto read = [&]( AutomaticStorageDeviceRegistration &value) -> NativeError {
		std::wstring instance ;	// Windows属性から独立に読んだ現在の識別
		// 実際に開いた機器の識別属性と元診断
		const auto	 identity =
			readObservedInstanceId( devices.get(), device, instance, api.inventory) ;
		// 古い登録や別インスタンスの属性を同じ機器へ付け替えない
		if( identity.state != DevicePropertyReadState::VALUE ||
		   normalizeIdentifier( instance) != normalizeIdentifier( instanceId)) {
			return nativeErrorFromWin32( identity.diagnostic.code ? identity.diagnostic.code
																 : ERROR_NO_SUCH_DEVINST) ;
		}

		std::vector<std::byte> present ;	// 機器の現在存在を示す型付き属性
		// 元集合にある機器の現在存在と取得診断
		const auto presence = readObservedProperty( devices.get(), device, DEVPKEY_Device_IsPresent,
												   DEVPROP_TYPE_BOOLEAN, present, api.inventory) ;
		// 取り外し後に属性が残った場合も現在の照合とは扱わない
		if( presence.state != DevicePropertyReadState::VALUE ||
		   present.size() != sizeof( DEVPROP_BOOLEAN) ||
		   present.front() != static_cast<std::byte>( DEVPROP_TRUE)) {
			return nativeErrorFromWin32( presence.diagnostic.code ? presence.diagnostic.code
																 : ERROR_NO_SUCH_DEVINST) ;
		}

		// 同じ機器が現在選択中の関連サービスを取得する
		const auto service = readObservedDeviceString( devices.get(), device, DEVPKEY_Device_Service,
													  value.service, api.inventory) ;
		// 選択時に未導入で現在も正式にサービス不在なら、旧登録の照合は不要
		if( noDriver && service.state == DevicePropertyReadState::NOT_PRESENT) {
			// 先の順位観測と同じ明示不在を現用INFにも要求する
			const auto inf =
				readObservedDeviceString( devices.get(), device, DEVPKEY_Device_DriverInfPath,
										 value.selection.publishedInf, api.inventory) ;
			return inf.state == DevicePropertyReadState::NOT_PRESENT
					   ? 0U
					   : nativeErrorFromWin32( inf.diagnostic.code ? inf.diagnostic.code
																  : ERROR_RETRY) ;
		}

		// 明示空、診断失敗や未導入状態の変化を別のサービスへ変換しない
		if( noDriver || service.state != DevicePropertyReadState::VALUE || value.service.empty() ||
		   value.service.size() > 256U) {
			return nativeErrorFromWin32( service.diagnostic.code ? service.diagnostic.code
																: ERROR_RETRY) ;
		}

		// 選択時の現在INFと、現用機器から読み直す実節を照合する
		const auto error =
			readInstalledStorageInfSelection( devices.get(), device, api.inventory, value.selection) ;
		// 先に観測した現用INFがある場合は、後から変更された現在INFを同じ登録にしない
		if( error != 0U ||
		   (!expectedInf.empty() && normalizeIdentifier( value.selection.publishedInf) !=
										normalizeIdentifier( expectedInf))) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		return 0U ;
	} ;

	AutomaticStorageDeviceRegistration original ;	// 署名元の読取りを開始する前の元属性
	auto error = read( original) ;					// 同インスタンスに実在する元選択の確認
	// 元属性が未確定なら登録先の読取りへ進めない
	if( error != 0U) {
		return error ;
	}

	// 同じ元登録の署名元と現在状態だけを同期で読み取る
	const auto inspected = inspect( original, api, devices.get(), device) ;	// 読取り処理の元診断
	// 失敗時も登録属性を再読取りし、途中変更を所有不明の別登録として扱わない
	AutomaticStorageDeviceRegistration fresh ;	// 機器の取り外しと登録変更を検知する最後の観測
	error = read( fresh) ;
	// 実体の照合が成立してもWindowsの現在属性が変わった場合は再観測が必要
	if( error != 0U || fresh != original) {
		return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	return inspected ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ選択インスタンスから現用サービスと署名付き元登録を同期照合する
 * @param[in] instanceId 同じ候補のWindows順位を確認した選択インスタンス
 * @param[in] noDriver 同じ順位観測で厳密に確認した未導入状態
 * @param[in] expectedInf 同じ選択時の現用INF名。未導入や旧サービスの他機器で指定なしの場合は空
 * @param[in] intended 同じ選択の署名付き自動起動補助を持つ更新候補
 * @param[out] result 同じ選択機器の現在署名元と補助・イベント観測。失敗時は空
 * @return 現用登録または確認済みの初回状態の読取り成功0、途中変更や照合失敗はHRESULT
 * @note 候補のサービス名で現用名を補わない。設定、起動、導入、共有所有の判断は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectCurrentAutomaticStorageRegistration( const std::wstring &instanceId,
													   bool noDriver, std::wstring_view expectedInf,
													   const SelectedStorageServiceFacts &intended,
													   StorageAutomaticRegistrationSnapshot &result)
{
	result = {} ;
	StorageAutomaticRegistrationSnapshot made ;	// 機器属性の前後一致まで公開しない現在観測
	// 現用署名元と現在構成の検証中だけ、同じ機器属性とAPI表を借用する
	const auto							 error = inspectPresentStorageDeviceRegistration(
		  instanceId, noDriver, expectedInf,
		  [&]( const AutomaticStorageDeviceRegistration &original, const auto &api, HDEVINFO,
			  SP_DEVINFO_DATA &) -> NativeError {
			  // 未導入の選択では署名元や現在登録を候補名から補完しない
			  if( noDriver) {
				  return 0U ;
			  }

			  const auto &selection = original.selection ;	// 現在機器から取得した元登録
			  const auto  extension = selection.sectionExtension
																  ? std::wstring_view{*selection.sectionExtension}
																  : std::wstring_view{} ;	// 属性不在は有無を含めて保持する
			  // 同じWindowsルートと現在登録のDriver Storeへの正規照会
			  const DriverStorePackageLookup lookup{api.windowsDirectory, api.storageStoreLocation} ;
			  const auto read = readCurrentRegisteredAutomaticStoragePackageEvidence(
				  selection.publishedInf, selection.basicSection, extension, original.service,
				  intended, made.package.emplace(), made.events, made.auxiliary,
				  lookup) ;	// 署名元の読取り
			  made.sectionExtension = selection.sectionExtension ;
			  return read ;
		  }) ;
	// 署名元または同じ現在機器の確認が成立しなければ部分観測は返さない
	if( error == 0U) {
		result = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ現在デバイスの登録属性と元Driver Store配布を照合する
 * @param[in] devices 現在の機器を開いた情報集合
 * @param[in,out] device 同じ関連サービスを使う実機器
 * @param[in] transport このデバイス情報集合を開いたAPI表
 * @param[in] lookup 同じ配布元のWindowsルートと登録INFから元の配置先を得るAPI表
 * @param[in] current 同じ端末で別途取得済みの現在INF名
 * @param[in] target 同じ操作から検査した元関連サービス・補助サービス
 * @param[in] host 同じサービス、配置ファイル、イベントの現在観測
 * @param[out] result 元属性と保護された登録配布の照合結果。失敗時は空
 * @return 元配布を同じ機器に結び付けられた場合0、別配布・元API・状態の変化はHRESULT
 * @note 現在使用中の元配布の読み取りに限定する。導入許可の発行は別に行う
 */
//------------------------------------------------------------------------------
NativeError readVerifiedInstalledStorageOwner( HDEVINFO devices, SP_DEVINFO_DATA &device,
											  const DriverStoreInventoryTransport &transport,
											  const DriverStorePackageLookup	  &lookup,
											  const CurrentDriverMetadata		  &current,
											  const SelectedStorageServiceFacts	  &target,
											  const StorageAuxiliaryHostSnapshot  &host,
											  VerifiedInstalledStorageOwner		  &result)
{
	result = {} ;
	// 現在の変更先と使用中のINFが未観測なら配布を推測しない
	if( !target.auxiliary || current.infRead.state != DevicePropertyReadState::VALUE) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	VerifiedInstalledStorageOwner made ;	// 端末の元属性と登録配布の一時値
	// 現在デバイスの登録属性を読み、同じ元INFを照合する処理の診断値
	auto error = readInstalledStorageInfSelection( devices, device, transport, made.selection) ;
	// 同じ端末で先に観測した現在INFと異なる配布を採用しない
	if( error != 0U || made.selection.publishedInf != current.infFileName) {
		return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const auto &selection = made.selection ;	// 同じ元属性を同期して署名照合へ渡す
	const auto	extension = selection.sectionExtension
								? std::wstring_view{*selection.sectionExtension}
								: std::wstring_view{} ;	// 不在と明示空の差は元属性に保持
	error = readRegisteredStoragePackageEvidence( selection.publishedInf, selection.basicSection,
												 extension, target, host, made.package, lookup) ;
	// 同じ登録配布を照合できなければ端末の所有証拠にしない
	if( error != 0U) {
		return error ;
	}

	InstalledStorageInfSelection fresh ;	// 配布の検証中に機器側で変更がなかったことの対照
	error = readInstalledStorageInfSelection( devices, device, transport, fresh) ;
	// 旧配布への過去の観測を現在の機器へ使い回さない
	if( error != 0U || fresh != selection) {
		return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	result = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 再open直後のClass名/GUIDを失敗と未確定から区別します
 * @param[in] set 同deviceを所有する借用集合です
 * @param[in,out] device 一覧構築前の元deviceです。Classを推測更新しません
 * @param[in] inventory 同backendの完全property表です
 * @param[out] snapshot 元Class観測と方式だけを保存します。不正時は許可を発行しません
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 整合した観測なら0、失敗/不正/上限なら元HRESULTです
 * @note Worker内で同期使用し、公開recordやnetworkを参照しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDeviceClassSnapshot( const HDEVINFO set, SP_DEVINFO_DATA &device,
												  const DriverStoreInventoryTransport &inventory,
												  DeviceRankSnapshot				  &snapshot,
												  InfFailureDiagnostic *diagnostic = nullptr)
{
	snapshot.nativeClassGuid = formatClassGuid( device.ClassGuid) ;
	snapshot.classRead		 = readObservedDeviceString( set, device, DEVPKEY_Device_Class,
														snapshot.deviceClass, inventory) ;
	std::vector<std::byte> bytes ;	// GUID propertyの型付き実byteです
	snapshot.classGuidRead = readObservedProperty( set, device, DEVPKEY_Device_ClassGuid,
												  DEVPROP_TYPE_GUID, bytes, inventory) ;
	const std::array reads{&snapshot.classRead, &snapshot.classGuidRead} ;	// 原診断の固定二軸です
	// API失敗/不正型/容量上限をClassの不存在へ変換しません
	for( const auto *read : reads) {
		// 明示的な不存在以外の失敗を元HRESULTへ保持します
		if( read->state == DevicePropertyReadState::FAILED ||
		   read->state == DevicePropertyReadState::INVALID_DATA ||
		   read->state == DevicePropertyReadState::LIMIT_REACHED) {
			markInfFailure( diagnostic, InfDiagnosticStage::CURRENT_CLASS_PROPERTY,
						   InfDiagnosticOrigin::UNRECORDED) ;
			return nativeErrorFromWin32( read->diagnostic.code != 0U ? read->diagnostic.code
																	: ERROR_INVALID_DATA) ;
		}
	}

	GUID observed{} ;	// 検証した実GUID propertyの値だけです
	// 値を返したGUIDはSDK幅と元node GUIDの一致を必須にします
	if( snapshot.classGuidRead.state == DevicePropertyReadState::VALUE) {
		// 短いGUIDや同device内のClass矛盾を許可へ補完しません
		if( bytes.size() != sizeof( observed)) {
			markInfFailure( diagnostic, InfDiagnosticStage::CURRENT_CLASS_SIZE,
						   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::memcpy( &observed, bytes.data(), sizeof( observed)) ;
		snapshot.observedClassGuid = formatClassGuid( observed) ;
		// 元nodeとpropertyが異なる観測を同一Classと扱いません
		if( !IsEqualGUID( observed, device.ClassGuid)) {
			markInfFailure( diagnostic, InfDiagnosticStage::CURRENT_CLASS_MATCH,
						   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	const bool nativeUnknown = IsEqualGUID( device.ClassGuid, GUID_NULL) ||
							   // 既知GUIDを欠損名から推測しません
							   IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_UNKNOWN) ;
	// 正式不存在とnull/Unknown native値の整合を別方式へ保持します
	if( snapshot.classRead.state == DevicePropertyReadState::NOT_PRESENT && nativeUnknown &&
	   (snapshot.classGuidRead.state == DevicePropertyReadState::NOT_PRESENT ||
		snapshot.classGuidRead.state == DevicePropertyReadState::VALUE)) {
		snapshot.classState = OfficialDriverRankDeviceClassState::NOT_PRESENT ;
		return 0U ;
	}

	// 正式Unknown名は正式Unknown GUIDと型付き実propertyがある場合だけ認めます
	if( snapshot.classRead.state == DevicePropertyReadState::VALUE &&
	   normalizeIdentifier( snapshot.deviceClass) == L"UNKNOWN" &&
	   snapshot.classGuidRead.state == DevicePropertyReadState::VALUE &&
	   IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_UNKNOWN)) {
		snapshot.classState = OfficialDriverRankDeviceClassState::UNKNOWN_CLASS ;
		return 0U ;
	}

	// 空文字・曖昧name/GUID・既知nameと未知GUIDを未確定初回へ転用しません
	if( snapshot.classRead.state != DevicePropertyReadState::VALUE || nativeUnknown ||
	   normalizeIdentifier( snapshot.deviceClass) == L"UNKNOWN" ||
	   snapshot.classGuidRead.state != DevicePropertyReadState::VALUE) {
		markInfFailure( diagnostic, InfDiagnosticStage::CURRENT_CLASS_STATE,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	snapshot.classState = OfficialDriverRankDeviceClassState::KNOWN_CLASS ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのdevice監査snapshotが同じ実状態を表すか判定する
 *
 * 監査中のdevice変更を検出し、異なる時点の根拠を混在させない
 *
 * @param[in] left Rank取得前のdevice監査snapshot
 * @param[in] right Rank取得後のdevice監査snapshot
 * @return Rank判定に使用する全metadataが一致する場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool deviceRankSnapshotsEqual( const DeviceRankSnapshot &left,
											const DeviceRankSnapshot &right) noexcept
{
	return left.deviceClass == right.deviceClass && left.classState == right.classState &&
		   left.classRead.state == right.classRead.state &&
		   left.classGuidRead.state == right.classGuidRead.state &&
		   left.observedClassGuid == right.observedClassGuid &&
		   left.nativeClassGuid == right.nativeClassGuid &&
		   left.matchingRead.state == right.matchingRead.state &&
		   left.hardwareIds == right.hardwareIds && left.compatibleIds == right.compatibleIds &&
		   left.matchingDeviceId == right.matchingDeviceId &&
		   left.currentDriver.infFileName == right.currentDriver.infFileName &&
		   left.currentDriver.provider == right.currentDriver.provider &&
		   left.currentDriver.version == right.currentDriver.version &&
		   left.currentDriver.date == right.currentDriver.date &&
		   left.currentDriver.packedVersion == right.currentDriver.packedVersion &&
		   left.noDriver == right.noDriver && left.node.read.state == right.node.read.state &&
		   left.node.statusFlags == right.node.statusFlags &&
		   left.node.problemCode == right.node.problemCode &&
		   left.driverKeyRead.state == right.driverKeyRead.state &&
		   left.driverKey == right.driverKey ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの公式driver rank監査結果が完全に一致するか判定する
 *
 * 同じApplicable判断でも根拠が変化した場合は同一視しない
 *
 * @param[in] left 発行時または呼出側が保持するrank監査結果
 * @param[in] right 現在のWindows状態から再生成したrank監査結果
 * @return 全判断値、位置、rank、scoreが一致する場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool officialRankAuditsEqual( const OfficialDriverRankAudit &left,
										   const OfficialDriverRankAudit &right) noexcept
{
	return left.decision == right.decision && left.currentState == right.currentState &&
		   left.currentPosition.kind == right.currentPosition.kind &&
		   left.currentPosition.index == right.currentPosition.index &&
		   left.candidatePosition.kind == right.candidatePosition.kind &&
		   left.candidatePosition.index == right.candidatePosition.index &&
		   left.currentRank == right.currentRank && left.candidateRank == right.candidateRank &&
		   left.currentIdentifierScore == right.currentIdentifierScore &&
		   left.candidateIdentifierScore == right.candidateIdentifierScore ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのcandidate Windows node snapshotが完全一致するか判定
 *
 * INF名だけが同じ別DDInstall nodeへの差替えを拒否する
 *
 * @param[in] left Binding発行時のcandidate node
 * @param[in] right 導入前に再列挙したcandidate node
 * @return Section、取得した場合の原順ID、Provider、版、日付、rankが一致する場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool candidateNodeSnapshotsEqual( const CandidateDriverNodeSnapshot &left,
											   const CandidateDriverNodeSnapshot &right) noexcept
{
	return left.infClassGuid == right.infClassGuid && left.classGuid == right.classGuid &&
		   left.sectionName == right.sectionName && left.modelIds == right.modelIds &&
		   left.provider == right.provider && left.version == right.version &&
		   left.date == right.date && left.packedVersion == right.packedVersion &&
		   left.dateTicks == right.dateTicks && left.rank == right.rank ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一deviceのPnP具体性と現在driver照合metadataを取得する
 *
 * 新しいdevice information setで実状態を固定し、PnP IDをUI、logまたはnetworkへ渡さない
 *
 * @param[in] instanceId Worker内だけで保持するdevice instance ID
 * @param[out] snapshot 成功時の秘密metadata
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 取得成功時は0、不足またはSetupAPI失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDeviceRankSnapshot( const std::wstring_view instanceId,
												 DeviceRankSnapshot		&snapshot,
												 InfFailureDiagnostic	*diagnostic = nullptr)
{
	snapshot = {} ;
	// 空または途中NULのinstance IDを端末内照合へ渡さない
	if( instanceId.empty() || instanceId.find( L'\0') != std::wstring_view::npos) {
		markInfFailure( diagnostic, InfDiagnosticStage::INPUT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DeviceInfoSet devices(
		// 一device用set
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を作成できない場合はOSの診断を返す
	if( !devices.valid()) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::DEVICE_CREATE,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	const std::wstring nativeInstanceId( instanceId) ;	// API用のnull終端instance ID
	SP_DEVINFO_DATA	   device{} ;						// Instance IDから再openするdevice metadata
	device.cbSize = sizeof( device) ;
	// 指定deviceを開けない場合は別deviceへ照合を広げず失敗を返す
	if( driver_store_inf_detail::transport().open( devices.get(), nativeInstanceId.c_str(), nullptr,
												 0, &device) == FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元0戻値へleafを残さず、後段の別失敗だけを識別します
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::DEVICE_OPEN,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	const auto &inventory =
		// 同backendの全propertyです
		driver_store_inf_detail::transport().inventory ;
	const NativeError classError = readDeviceClassSnapshot(
		// 元Classだけを読みます
		devices.get(), device, inventory, snapshot, diagnostic) ;
	// ClassのAPI失敗・不正・上限を不存在や正式Unknownへ補完しません
	if( classError != 0U) {
		return classError ;
	}

	snapshot.hardwareIds = readDeviceStringList( devices.get(), device, DEVPKEY_Device_HardwareIds) ;
	snapshot.compatibleIds =
		readDeviceStringList( devices.get(), device, DEVPKEY_Device_CompatibleIds) ;
	snapshot.matchingRead =
		readObservedDeviceString( devices.get(), device, DEVPKEY_Device_MatchingDeviceId,
								 snapshot.matchingDeviceId, inventory) ;
	snapshot.driverKeyRead = readObservedDeviceString( devices.get(), device, DEVPKEY_Device_Driver,
													  snapshot.driverKey, inventory) ;
	snapshot.node		   = readObservedNode( device, inventory) ;
	snapshot.currentDriver = readCurrentDriver( devices.get(), device) ;
	const std::array<const DevicePropertyReadStatus *, 6U> currentReads{
		&snapshot.driverKeyRead,
		&snapshot.matchingRead,
		&snapshot.currentDriver.infRead,
		&snapshot.currentDriver.providerRead,
		&snapshot.currentDriver.versionRead,
		&snapshot.currentDriver.dateRead} ;	// 明示欠損と元API失敗を混同しません
	// 現在属性の取得失敗は元Windows診断を返し、NO_DRIVERへ補完しません
	for( const auto *read : currentReads) {
		// 欠損以外のAPI失敗や不正値を初回/既知どちらのbindingへも採用しません
		if( read->state == DevicePropertyReadState::FAILED ||
		   read->state == DevicePropertyReadState::INVALID_DATA ||
		   read->state == DevicePropertyReadState::LIMIT_REACHED) {
			markInfFailure( diagnostic, InfDiagnosticStage::CURRENT_PROPERTY,
						   InfDiagnosticOrigin::UNRECORDED) ;
			return nativeErrorFromWin32( read->diagnostic.code != 0U ? read->diagnostic.code
																	: ERROR_INVALID_DATA) ;
		}
	}

	std::vector<std::byte> presentBytes ;	// 正式BOOLEAN型の実present属性だけです
	const auto			   presentRead =
		readObservedProperty( devices.get(), device, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN,
							 presentBytes, inventory) ;	// Opaque scanの旧presentだけを信用しません
	// Present属性の元Windows読取失敗を単なる不在へ置換しません
	if( presentRead.state == DevicePropertyReadState::FAILED) {
		// 元非ゼロproperty errorにだけ未記録の下位leafを結びます
		if( presentRead.diagnostic.code != 0U) {
			markInfFailure( diagnostic, InfDiagnosticStage::PRESENT_PROPERTY,
						   InfDiagnosticOrigin::UNRECORDED) ;
		}

		return nativeErrorFromWin32( presentRead.diagnostic.code) ;
	}

	// Node statusのCONFIGRETとWindows errorを混同せず変更直前拒否へ保持します
	if( snapshot.node.read.state == DevicePropertyReadState::FAILED) {
		const auto nodeDiagnostic = snapshot.node.read.diagnostic ;	// 当該nodeの元API診断です
		// 元CONFIGRET変換を一回だけ実行し、戻値を変更しません
		const auto nodeError = nativeErrorFromWin32(
			nodeDiagnostic.domain == DeviceDiagnosticDomain::CONFIGURATION_MANAGER
				? CM_MapCrToWin32Err( nodeDiagnostic.code, ERROR_INVALID_DATA)
				: nodeDiagnostic.code) ;
		// 同じ元変換結果が失敗の場合だけ当該nodeのcodeを保持します
		if( nodeError != 0U) {
			markInfFailure( diagnostic, InfDiagnosticStage::NODE_STATE,
						   InfDiagnosticOrigin::NATIVE_API, nodeDiagnostic.code) ;
		}

		return nodeError ;
	}

	// Device消失・present不明・型不整合を未導入へ補完しません
	if( presentRead.state != DevicePropertyReadState::VALUE ||
	   presentBytes.size() != sizeof( DEVPROP_BOOLEAN) ||
	   presentBytes.front() != std::byte{static_cast<unsigned char>( DEVPROP_TRUE)} ||
	   snapshot.node.read.state != DevicePropertyReadState::VALUE) {
		markInfFailure( diagnostic, InfDiagnosticStage::PRESENT_STATE,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const bool missingDriverProperties =
		snapshot.driverKeyRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.matchingRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.infRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.providerRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.versionRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.dateRead.state ==
			DevicePropertyReadState::NOT_PRESENT ;	// 全不在の整合根拠
	// Native Code28だけで現在node不在を推測せず、installed-only listを完全に確認します
	if( missingDriverProperties &&
	   snapshot.node.problemCode == static_cast<std::uint32_t>( CM_PROB_FAILED_INSTALL) &&
	   snapshot.node.statusFlags && (*snapshot.node.statusFlags & DN_HAS_PROBLEM) != 0U &&
	   (!snapshot.hardwareIds.empty() || !snapshot.compatibleIds.empty())) {
		SP_DEVINSTALL_PARAMS_W parameters{} ;	// 同deviceをinstalled-onlyへ限定する読取り条件
		parameters.cbSize = sizeof( parameters) ;
		// 現在node一覧の条件が取得不能なら初回bindingを発行しません
		if( driver_store_inf_detail::transport().getParameters( devices.get(), &device,
															  &parameters) == FALSE) {
			const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
			// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
			if( error != ERROR_SUCCESS) {
				markInfFailure( diagnostic, InfDiagnosticStage::INSTALLED_NODE,
							   InfDiagnosticOrigin::NATIVE_API, error) ;
			}

			return nativeErrorFromWin32( error) ;
		}

		parameters.Flags &= ~DI_ENUMSINGLEINF ;
		parameters.FlagsEx |= DI_FLAGSEX_INSTALLEDDRIVER | DI_FLAGSEX_ALLOWEXCLUDEDDRVS ;
		parameters.DriverPath[0] = L'\0' ;
		DriverInfoList installedList{devices.get(), device} ;	// 同backendの一覧を必ず解放します
		// Installed-only条件と全列挙開始の失敗を欠損へ変換しません
		if( driver_store_inf_detail::transport().setParameters( devices.get(), &device,
															  &parameters) == FALSE ||
		   driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
			   FALSE) {
			const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
			// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
			if( error != ERROR_SUCCESS) {
				markInfFailure( diagnostic, InfDiagnosticStage::INSTALLED_NODE,
							   InfDiagnosticOrigin::NATIVE_API, error) ;
			}

			return nativeErrorFromWin32( error) ;
		}

		installedList.markBuilt() ;
		SP_DRVINFO_DATA_W installed{} ;	// 現在nodeが一件でもあれば初回を拒否します
		installed.cbSize = sizeof( installed) ;
		// Code28と属性欠損に矛盾する実nodeを成功へ補完しません
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, 0U, &installed) != FALSE) {
			markInfFailure( diagnostic, InfDiagnosticStage::INSTALLED_NODE,
						   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto installedError = GetLastError() ;	// 完全空終端かAPI失敗かを区別します
		// 正式な空終端以外は未導入の証明に使用しません
		if( installedError != ERROR_NO_MORE_ITEMS) {
			// 元0戻値を後段の別失敗へ持ち越しません
			if( installedError != ERROR_SUCCESS) {
				markInfFailure( diagnostic, InfDiagnosticStage::INSTALLED_NODE,
							   InfDiagnosticOrigin::NATIVE_API, installedError) ;
			}

			return nativeErrorFromWin32( installedError) ;
		}

		snapshot.noDriver = true ;
		return 0U ;
	}

	// Rankを現在driverへ拘束できないproperty欠損は、推測で補わず拒否する
	if( snapshot.classState != OfficialDriverRankDeviceClassState::KNOWN_CLASS ||
	   snapshot.matchingRead.state != DevicePropertyReadState::VALUE ||
	   snapshot.deviceClass.empty() ||
	   (snapshot.hardwareIds.empty() && snapshot.compatibleIds.empty()) ||
	   snapshot.currentDriver.infFileName.empty() || snapshot.currentDriver.provider.empty() ||
	   !snapshot.currentDriver.packedVersion.has_value()) {
		snapshot = {} ;
		markInfFailure( diagnostic, InfDiagnosticStage::CURRENT_TUPLE,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの外部INFだけをcompatible listの検索対象に設定する
 *
 * `DI_ENUMSINGLEINF`で候補範囲を一fileへ限定する。Driver Storeへのstage、選択またはinstallは行わない
 *
 * @param[in] set 対象deviceを所有するinformation set
 * @param[in] device 対象device metadata
 * @param[in] infPath G11-C workspace内のnullを含まない絶対path
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 条件設定成功時は0、入力またはSetupAPI失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError configureSingleInfDriverSearch( const HDEVINFO			 set,
														 SP_DEVINFO_DATA		&device,
														 const std::wstring_view infPath,
														 InfFailureDiagnostic *diagnostic = nullptr)
{
	SP_DEVINSTALL_PARAMS_W parameters{} ;	// 単一INF list構築条件
	parameters.cbSize = sizeof( parameters) ;
	// 既存install parameterを取得できなければ外部INF検索条件を変更しない
	if( driver_store_inf_detail::transport().getParameters( set, &device, &parameters) == FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::PARAMETERS_READ,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	// 空または途中NULのINF pathをSetupAPIへ渡さない
	if( infPath.empty() || infPath.find( L'\0') != std::wstring_view::npos) {
		markInfFailure( diagnostic, InfDiagnosticStage::INPUT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// INF pathがDriverPath fieldに収まらない場合は切り詰めず拒否する
	if( infPath.size() >= std::size( parameters.DriverPath)) {
		markInfFailure( diagnostic, InfDiagnosticStage::INPUT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	parameters.Flags |= DI_ENUMSINGLEINF ;
	parameters.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS ;
	std::ranges::copy( infPath, parameters.DriverPath) ;
	parameters.DriverPath[infPath.size()] = L'\0' ;
	// 特定INFへの検索条件設定が失敗した場合は広い検索へ戻さず診断を返す
	if( driver_store_inf_detail::transport().setParameters( set, &device, &parameters) == FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::PARAMETERS_WRITE,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ保護INFのClass名/GUIDをWindowsへ独立確認します
 * @param[in] infPath 検査済み実INFの絶対pathです。呼出中だけ借用します
 * @param[in] expectedClass 内容検査が確認したClass名です。公開recordの値ではありません
 * @param[out] classGuid 成功時だけ確定するINFのClassGUIDです。不正時はnullです
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 整合時0、元API失敗または不正応答時HRESULTです
 * @note Stage/導入やClassのregistry設定を行いません。再試行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCandidateInfClass( const std::wstring_view infPath,
												const std::wstring_view expectedClass,
												GUID				   &classGuid,
												InfFailureDiagnostic   *diagnostic = nullptr)
{
	classGuid = {} ;
	// 絶対pathの元INFと検査済みClassを欠く要求を拒否します
	if( infPath.empty() || infPath.size() >= MAX_PATH ||
	   infPath.find( L'\0') != std::wstring_view::npos || expectedClass.empty()) {
		markInfFailure( diagnostic, InfDiagnosticStage::INPUT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring						path{infPath} ;	// 作用範囲を固定したnull終端API入力です
	std::array<wchar_t, MAX_CLASS_NAME_LEN> name{} ;		// SDKの有限Class名受信です
	DWORD									required{} ;	// 終端込みClass名要素数です
	GUID									observed{} ;	// 全検証までcallerへ出力しません
	// 元実INFの読取失敗を内容成功や公開Classへ補完しません
	if( driver_store_inf_detail::transport().infClass( path.c_str(), &observed, name.data(),
													 static_cast<DWORD>( name.size()),
													 &required) == FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::INF_CLASS_READ,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	// 型のないClass名bufferも終端/実長/検査済み名/既知GUIDへ照合します
	if( required <= 1U || required > name.size() || name[required - 1U] != L'\0' ||
	   std::wcslen( name.data()) != required - 1U ||
	   normalizeIdentifier( name.data()) != normalizeIdentifier( expectedClass) ||
	   IsEqualGUID( observed, GUID_NULL) || IsEqualGUID( observed, GUID_DEVCLASS_UNKNOWN)) {
		markInfFailure( diagnostic, InfDiagnosticStage::INF_CLASS_VALUE,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	classGuid = observed ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIが一driver nodeへ算出したrankを取得する
 *
 * Rankの算式を再実装せず、SetupAPIが保持する値を正本とする
 *
 * @param[in] set Compatible listを所有するinformation set
 * @param[in] device 対象device metadata
 * @param[in] driver 列挙済みdriver node
 * @param[out] rank Windowsが算出したfull rank
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 取得成功時は0、SetupAPI失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDriverRank( const HDEVINFO set, SP_DEVINFO_DATA &device,
										 SP_DRVINFO_DATA_W &driver, std::uint32_t &rank,
										 InfFailureDiagnostic *diagnostic = nullptr)
{
	SP_DRVINSTALL_PARAMS parameters{} ;	// Driver node固有のinstall parameter
	parameters.cbSize = sizeof( parameters) ;
	SetLastError( ERROR_SUCCESS) ;
	// SetupAPIのrank取得が失敗した場合は順位を推測せず診断を返す
	if( driver_store_inf_detail::transport().rank( set, &device, &driver, &parameters) == FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		markInfFailure( diagnostic, InfDiagnosticStage::RANK_READ,
					   error == ERROR_SUCCESS ? InfDiagnosticOrigin::INTERNAL_CONTRACT
											  : InfDiagnosticOrigin::NATIVE_API,
					   error) ;
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	rank = parameters.Rank ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一deviceのcompatible listから照合対象driverの最良rankを得る
 *
 * Rank順を仮定せず一致nodeを全件調べ、最良のWindows rankを採用する。Device状態を変更するAPIは呼ばない
 *
 * @param[in] instanceId Worker内のdevice instance ID
 * @param[in] singleInfPath Candidate時だけ指定する単一INF path
 * @param[in] expectedInf 照合するINF file名または絶対path
 * @param[in] expectedProvider 完全一致させるProvider名
 * @param[in] expectedVersion 完全一致させるpacked version
 * @param[in] expectedDate 指定時に完全一致させるYYYY/MM/DD日付
 * @param[out] rank 一致nodeがあれば最小rank、なければ空値
 * @param[in] expectedClass 単一INF検索で要求する内容検査済みClass名。現在検索では空です
 * @param[out] infClassGuid 両GUID出力が非nullの候補検索でだけ更新します。失敗値を権限へ使用しません
 * @param[out] nativeClassGuid infClassGuidと対で指定する返却候補GUIDです。null可、外へ保持しません
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 列挙完了時は0、入力またはSetupAPI失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectMatchingDriverRank(
	const std::wstring_view instanceId, const std::optional<std::wstring_view> singleInfPath,
	const std::wstring_view expectedInf, const std::wstring_view expectedProvider,
	const std::uint64_t expectedVersion, const std::optional<std::wstring_view> expectedDate,
	std::optional<std::uint32_t> &rank, const std::wstring_view expectedClass = {},
	std::wstring *infClassGuid = nullptr, std::wstring *nativeClassGuid = nullptr,
	InfFailureDiagnostic *diagnostic = nullptr)
{
	rank.reset() ;
	// device・期待INF・publisherが揃わない要求ではrankを照合しない
	if( instanceId.empty() || expectedInf.empty() || expectedProvider.empty()) {
		markInfFailure( diagnostic, InfDiagnosticStage::INPUT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DeviceInfoSet devices(
		// 一device用set
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合の作成失敗をOSの診断値で返す
	if( !devices.valid()) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::DEVICE_CREATE,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	const std::wstring nativeInstanceId( instanceId) ;	// API用のnull終端instance ID
	SP_DEVINFO_DATA	   device{} ;						// Rank取得対象device metadata
	device.cbSize = sizeof( device) ;
	// 指定deviceを開けなければ別deviceへ照合を広げず失敗とする
	if( driver_store_inf_detail::transport().open( devices.get(), nativeInstanceId.c_str(), nullptr,
												 0, &device) == FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元0戻値へleafを残さず、後段の別失敗だけを識別します
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::DEVICE_OPEN,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	GUID candidateClass{} ;	// 同じ保護INFだけのClassです。元deviceを上書きしません
	// 候補のClassを公開recordやdevice名から推測せず実INFへ結びます
	if( singleInfPath) {
		const NativeError classError = readCandidateInfClass(
			*singleInfPath, expectedClass, candidateClass, diagnostic) ;	// 同backendの元INF読取です
		// Class未確認の候補をWindows適合として公開しません
		if( classError != 0U) {
			return classError ;
		}
	}

	// 単一INFの指定がある場合はそのINFだけを検索対象へ固定する
	if( singleInfPath.has_value()) {
		const NativeError configureError =	// 単一candidate INFの検索条件設定結果
			configureSingleInfDriverSearch( devices.get(), device, singleInfPath.value(),
										   diagnostic) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( configureError != 0) {
			return configureError ;
		}
	}
	// 互換driverの検索条件を設定できなければ既定条件で検索しない
	else if( !configureCompatibleDriverSearch( devices.get(), device, diagnostic)) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::PARAMETERS_READ,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		// 下位bool helperが保持した同API leafへ既callerの原codeだけを補います
		if( diagnostic && diagnostic->origin == InfDiagnosticOrigin::NATIVE_API &&
		   !diagnostic->nativeCodeKnown) {
			diagnostic->nativeCode		= error ;
			diagnostic->nativeCodeKnown = true ;
		}

		// 元0戻値の補足leafを次の候補errorへ結びません
		if( error == ERROR_SUCCESS && diagnostic) {
			const auto phase = diagnostic->phase ;	// 同監査区間だけは維持します
			*diagnostic		 = {.phase = phase} ;
		}

		return nativeErrorFromWin32( error) ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// Compatible listのRAII guard
	// 互換listの構築に失敗した場合はrankを推測せず診断を返す
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		const DWORD error = GetLastError() ;	// 元API失敗直後の原codeです
		// 元0戻値を後段の別失敗へ持ち越しません
		if( error != ERROR_SUCCESS) {
			markInfFailure( diagnostic, InfDiagnosticStage::LIST_BUILD,
						   InfDiagnosticOrigin::NATIVE_API, error) ;
		}

		return nativeErrorFromWin32( error) ;
	}

	driverList.markBuilt() ;

	// 一覧構築で返却されたClassを同INFのClassへ完全一致させます
	if( singleInfPath && !IsEqualGUID( device.ClassGuid, candidateClass)) {
		markInfFailure( diagnostic, InfDiagnosticStage::LIST_CLASS_MATCH,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 原device Classではなく候補Classの独立証拠だけを出力します
	if( singleInfPath && infClassGuid && nativeClassGuid) {
		*infClassGuid	 = formatClassGuid( candidateClass) ;
		*nativeClassGuid = formatClassGuid( device.ClassGuid) ;
	}

	bool enumerationComplete{} ;	// ERROR_NO_MORE_ITEMSまで列挙できた場合はtrue
	// indexはnode位置を表し、有限上限内の同一packageから最良rankを選ぶ
	for( DWORD index = 0; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在照合中のcompatible driver node
		driver.cbSize = sizeof( driver) ;
		SetLastError( ERROR_SUCCESS) ;
		// 列挙APIの終了通知を正常終端と失敗へ分けて処理する
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙完了またはSetupAPI失敗code
			// 正常終端以外の列挙失敗を途中までのrank結果で隠さない
			if( error != ERROR_NO_MORE_ITEMS) {
				rank.reset() ;
				// 元非ゼロAPI errorだけを保存し、後段の別失敗へ旧leafを持ち越しません
				if( error != ERROR_SUCCESS) {
					markInfFailure( diagnostic, InfDiagnosticStage::NODE_ENUMERATION,
								   InfDiagnosticOrigin::NATIVE_API, error) ;
				}

				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			enumerationComplete = true ;
			break ;
		}

		DriverDetail detail ;	// Driver nodeのINFとsection metadata
		// driver詳細を取得できなければ照合の完全性を保証できないため中断する
		if( !readDriverDetail( devices.get(), device, driver, detail, diagnostic)) {
			const DWORD error = GetLastError() ;	// Detail API失敗または不正metadata診断値
			// 既callerが取得した同じ原codeだけをAPI leafへ補います
			if( diagnostic && diagnostic->origin == InfDiagnosticOrigin::NATIVE_API &&
			   !diagnostic->nativeCodeKnown) {
				diagnostic->nativeCode		= error ;
				diagnostic->nativeCodeKnown = true ;
			}

			return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
		}

		const bool matches =	// 現在版または候補版の固定metadataとの完全一致結果
			normalizedFileName( detail.infFileName) == normalizedFileName( expectedInf) &&
			normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( expectedProvider) &&
			driver.DriverVersion == expectedVersion &&
			(!expectedDate.has_value() ||
			 formatDriverDate( driver.DriverDate) == expectedDate.value()) ;
		// 期待INF・publisher・versionに一致しないnodeをrank比較から除く
		if( !matches) {
			continue ;
		}

		std::uint32_t	  currentRank{} ;	// 現在一致したdriver nodeのfull Windows rank
		const NativeError rankError =
			// Rank取得結果
			readDriverRank( devices.get(), device, driver, currentRank, diagnostic) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( rankError != 0) {
			return rankError ;
		}

		// 一致nodeのうちWindowsが算出した最小rankだけを最良値として保持する
		if( !rank.has_value() || currentRank < rank.value()) {
			rank = currentRank ;
		}
	}

	// 列挙上限で打ち切った場合は、未確認nodeを無視せず監査失敗にする
	// 元の正常終端未確認だけを診断し、戻値は変更しません
	if( !enumerationComplete) {
		markInfFailure( diagnostic, InfDiagnosticStage::ENUMERATION_LIMIT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
	}

	return enumerationComplete ? 0 : nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 単一外部INFの完全tuple内で唯一最小full-rankのWindows nodeを固定する
 *
 * 全nodeを有限上限内で正常終端まで列挙し、元INF完全path、Provider、版、日付を満たす
 * nodeの実Windows full rankを比較する。同最良rank複数と読取不足はfail-closedで拒否する
 *
 * @param[in] instanceId Worker内の秘密device instance ID
 * @param[in] infPath 保護workspace内の単一INF絶対path
 * @param[in] expectedClass 同じ実INFの内容検査で確認したClass名です。元device Classではありません
 * @param[in] expectedProvider 監査済みINFのProvider表示名
 * @param[in] expectedVersion 監査済みINFのpacked version
 * @param[in] expectedDate 監査済みINFのYYYY/MM/DD日付
 * @param[out] snapshot 一意に固定したWindows node metadata
 * @param[in] captureModelIds Models行を照合するために同nodeの全IDも取得する場合true
 * @return 一意なnode取得時は0、不一致、重複またはSetupAPI失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectUniqueCandidateDriverNode(
	const std::wstring_view instanceId, const std::wstring_view infPath,
	const std::wstring_view expectedClass, const std::wstring_view expectedProvider,
	const std::uint64_t expectedVersion, const std::wstring_view expectedDate,
	CandidateDriverNodeSnapshot &snapshot, bool captureModelIds = false)
{
	snapshot = {} ;
	// device・INF・publisher・日付が欠落した要求ではnodeを固定しない
	if( instanceId.empty() || infPath.empty() || expectedProvider.empty() || expectedDate.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DeviceInfoSet devices(
		// 一device用set
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合の作成失敗時はOSの診断を返す
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::wstring nativeInstanceId( instanceId) ;	// API用のnull終端instance ID
	SP_DEVINFO_DATA	   device{} ;						// Candidate node取得対象device metadata
	device.cbSize = sizeof( device) ;
	// 指定deviceを開けない場合はnode固定処理を中止する
	if( driver_store_inf_detail::transport().open( devices.get(), nativeInstanceId.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	GUID			  infClass{} ;	// 同検査済み実INFのClassです。元端末Classを変更しません
	const NativeError classError =
		// 独立した元INF確認です
		readCandidateInfClass( infPath, expectedClass, infClass) ;
	// Class読取不能をWindows node適合へ補完しません
	if( classError != 0U) {
		return classError ;
	}

	const NativeError configureError =	// 単一INFだけへ列挙範囲を限定した結果
		configureSingleInfDriverSearch( devices.get(), device, infPath) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( configureError != 0) {
		return configureError ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// Compatible listのRAII guard
	// 単一INFの互換listを構築できなければnodeを固定しない
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	// 未確定deviceでも候補ClassはWindows互換一覧と同INF GUIDの一致で確認します
	if( !IsEqualGUID( device.ClassGuid, infClass)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	snapshot.infClassGuid = formatClassGuid( infClass) ;
	snapshot.classGuid	  = formatClassGuid( device.ClassGuid) ;
	bool found{} ;					// 完全tupleに一致する最小rankのnodeを保持した場合はtrue
	bool bestRankTied{} ;			// 現在の最小rankを持つnodeが複数の場合はtrue
	bool enumerationComplete{} ;	// ERROR_NO_MORE_ITEMSまで確認できた場合はtrue
	// 全一致nodeの実rankを読み、最後まで確認してから唯一最良を確定する
	for( DWORD index = 0U; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在照合中のcandidate Windows node
		driver.cbSize = sizeof( driver) ;
		SetLastError( ERROR_SUCCESS) ;
		// 列挙APIの終了を正常終端と障害に区別して一意性を確認する
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙完了またはSetupAPI失敗code
			// 正常終端以外の列挙障害を部分一致で成功扱いにしない
			if( error != ERROR_NO_MORE_ITEMS) {
				snapshot = {} ;
				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			enumerationComplete = true ;
			break ;
		}

		DriverDetail detail ;	// INF file名とDDInstall sectionの秘密metadata
		// node詳細を取得できなければ一意性確認を中止して診断を返す
		if( !readDriverDetail( devices.get(), device, driver, detail, nullptr, captureModelIds)) {
			const DWORD error = GetLastError() ;	// Detail取得失敗の診断値
			return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
		}

		const std::wstring nodeDate = formatDriverDate( driver.DriverDate) ;	// Nodeの暦日
		const bool		   matches	=											// 監査済みglobal INF metadataとの完全一致結果
			normalizeIdentifier( detail.infFileName) == normalizeIdentifier( infPath) &&
			normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( expectedProvider) &&
			driver.DriverVersion == expectedVersion && nodeDate == expectedDate ;
		// 期待するINF・publisher・版・日付と一致しないnodeを除外する
		if( !matches) {
			continue ;
		}

		std::uint32_t	  rank{} ;	// Windowsが現在nodeへ算出したfull rank
		// 対応driverのrank読取り結果。Rank未確認を適用成功にしないため保持する
		const NativeError rankError = readDriverRank( devices.get(), device, driver, rank) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( rankError != 0) {
			return rankError ;
		}

		// 同最良の重複は記録し、後続のより低rankで解消できるため列挙を継続する
		if( found && rank == snapshot.rank) {
			bestRankTied = true ;
			continue ;
		}

		// より悪いrankのnodeは唯一最良のsnapshotを変更しない
		if( found && rank > snapshot.rank) {
			continue ;
		}

		snapshot.sectionName   = std::move( detail.sectionName) ;
		snapshot.modelIds	   = std::move( detail.modelIds) ;
		snapshot.provider	   = driver.ProviderName ;
		snapshot.version	   = formatDriverVersion( driver.DriverVersion) ;
		snapshot.date		   = nodeDate ;
		snapshot.packedVersion = driver.DriverVersion ;
		snapshot.dateTicks	   = fileTimeTicks( driver.DriverDate) ;
		snapshot.rank		   = rank ;
		found				   = true ;
		bestRankTied		   = false ;
	}

	// 列挙上限までに正常終端へ達しなければ一意性を未確定として拒否する
	if( !enumerationComplete) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 一致nodeまたはそのsectionがない場合は固定snapshotを返さない
	if( !found || snapshot.sectionName.empty()) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// 正常終端後にも最小rankが同点なら、先頭のnodeを推測採用しない
	if( bestRankTied) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意の既診断へ原errorと最初の拒否だけを保持します
 * @param[in,out] diagnostic 呼出し元が所有する任意診断です
 * @param[in] error 元HRESULTです
 * @param[in] stage 固定拒否位置です
 * @param[in] observed 元enumまたは件数です
 * @return 未変更の元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError bindingFailure( RequiredInfBindingDiagnostic *diagnostic, const NativeError error,
						   const InfBindingReject stage, const std::uint32_t observed = 0U) noexcept
{
	return diagnostic ? diagnostic->reject( error, stage, observed) : error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 公式INF binding用の現在状態とcandidate nodeを同時に固定する
 * Rank取得の前後で現在INF、版、日付を含む全snapshotを比較し、異なる時点の根拠を一bindingへ混在させない
 * @param[in] instanceId Worker内の秘密device instance ID
 * @param[in] infPath 保護workspace内の単一INF絶対path
 * @param[in] package 内容監査済みINF package metadata
 * @param[in] candidateVersion INF global版のpacked値
 * @param[in] candidateDate INF global日付のYYYY/MM/DD表記
 * @param[out] deviceSnapshot 監査前後で一致した現在device状態
 * @param[out] candidateSnapshot 一意に固定したWindows node
 * @param[out] rankAudit 現在状態に対する具体性とrank監査結果
 * @param[out] diagnostic null可の同期中だけ借用する拒否段階記録先です。記録する失敗branchだけで更新し、それ以外は元値を保持します
 * @param[in] confirmedModel 独自クラス又は公式Models専用行で必須の照合済みnodeです
 * @param[in] storageModel ストレージの元行全IDを取り、既存順位と同じ観測で元行の順位も確認する場合trueです
 * @return 状態固定完了時は0、変更、曖昧性またはSetupAPI失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectOfficialInfBindingState(
	const std::wstring_view instanceId, const std::wstring_view infPath,
	const OfficialInfPackage &package, const std::uint64_t candidateVersion,
	const std::wstring_view candidateDate, DeviceRankSnapshot &deviceSnapshot,
	CandidateDriverNodeSnapshot &candidateSnapshot, OfficialDriverRankAudit &rankAudit,
	RequiredInfBindingDiagnostic	  *diagnostic	  = nullptr,
	const CandidateDriverNodeSnapshot *confirmedModel = nullptr, const bool storageModel = false)
{
	deviceSnapshot	  = {} ;
	candidateSnapshot = {} ;
	rankAudit		  = {} ;
	const bool requiresModel =
		package.inspectionPurpose == OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ||
		(package.inspectionPurpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
		 package.scopedModels) ;	// 元Models行を固定する読取り用途です
	// 端末ストレージ専用の照合を他用途へ流用せず、従来の署名済み元行も要求する
	if( (storageModel &&
		package.inspectionPurpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) ||
	   requiresModel != (confirmedModel != nullptr) ||
	   (confirmedModel && confirmedModel->modelIds.empty())) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_INVALIDARG),
							  InfBindingReject::INPUT) ;
	}

	DeviceRankSnapshot before ;														// Rank取得前に固定する現在deviceとdriver状態
	NativeError		   nativeError = readDeviceRankSnapshot( instanceId, before) ;	// 取得結果
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CURRENT_BEFORE) ;
	}

	// 現在driverの日付が未確定なら導入bindingを構築しない
	if( !before.noDriver && before.currentDriver.date.empty()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::optional<std::uint32_t> currentRank ;	// 現在driver nodeの最良Windows rank
	// Native未導入では架空current rankを作らず、既知現在driverだけを比較に使用します
	if( !before.noDriver) {
		nativeError = collectMatchingDriverRank(
			instanceId, std::nullopt, before.currentDriver.infFileName,
			before.currentDriver.provider, before.currentDriver.packedVersion.value(),
			std::wstring_view( before.currentDriver.date), currentRank) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CURRENT_RANK) ;
	}

	nativeError = collectUniqueCandidateDriverNode(
		instanceId, infPath, package.className, package.providerName, candidateVersion,
		candidateDate, candidateSnapshot, confirmedModel != nullptr || storageModel) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CANDIDATE_NODE) ;
	}

	// 同じ元INFの別行に切り替わっていた場合は元行の順位を引き継ぎません
	if( confirmedModel && !candidateNodeSnapshotsEqual( *confirmedModel, candidateSnapshot)) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_RETRY),
							  InfBindingReject::CANDIDATE_NODE) ;
	}

	DeviceRankSnapshot after ;	// Rank取得後に再取得する現在deviceとdriver状態
	nativeError = readDeviceRankSnapshot( instanceId, after) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CURRENT_AFTER) ;
	}

	// 監査前後でdevice状態が変化した場合は再scanを要求する
	if( !deviceRankSnapshotsEqual( before, after)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 既知ClassのGUIDが候補INFと異なる場合は名前一致だけで適合としません
	if( before.classState == OfficialDriverRankDeviceClassState::KNOWN_CLASS &&
	   before.nativeClassGuid != candidateSnapshot.classGuid) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const OfficialDriverRankEvidence evidence{
		// Pure evaluatorへ渡す秘密PnP根拠
		.deviceClass		 = before.deviceClass,
		.candidateClass		 = package.className,
		.deviceHardwareIds	 = before.hardwareIds,
		.deviceCompatibleIds = before.compatibleIds,
		.candidateIds		 = confirmedModel ? candidateSnapshot.modelIds : package.hardwareIds,
		.currentMatchingDeviceId  = before.matchingDeviceId,
		.currentRank			  = currentRank,
		.candidateRank			  = candidateSnapshot.rank,
		.currentState			  = before.noDriver ? OfficialDriverRankCurrentState::NO_DRIVER
													: OfficialDriverRankCurrentState::KNOWN_DRIVER,
		.deviceClassState		  = before.classState,
		.candidateInfClassGuid	  = candidateSnapshot.infClassGuid,
		.candidateNativeClassGuid = candidateSnapshot.classGuid,
	} ;
	// 取得した証拠からrank判断を成立させられなければbindingを作らない
	if( !evaluateOfficialDriverRank( evidence, rankAudit)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// WiXは既存の全INF順位に加え、Windowsが実選択した元行のIDだけでも適用性を確認する
	if( storageModel) {
		auto					rowEvidence = evidence ;	// 同じ端末と順位の同期借用
		OfficialDriverRankAudit rowAudit ;					// 実選択行だけを使った独立の順位判定
		rowEvidence.candidateIds = candidateSnapshot.modelIds ;
		// 同じINFの非選択行の具体性を選択行の導入に引き継がない
		if( !evaluateOfficialDriverRank( rowEvidence, rowAudit) ||
		   rowAudit.decision != OfficialDriverRankDecision::APPLICABLE) {
			return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_RETRY),
								  InfBindingReject::CANDIDATE_NODE) ;
		}
	}

	deviceSnapshot = std::move( before) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief driver candidate が現在使用中の package かを判定する
 *
 * @param[in] current installed driver metadata
 * @param[in] detail candidate INF metadata
 * @param[in] driver candidate driver node
 * @return INF file と version が一致する場合は `true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isCurrentDriver( const CurrentDriverMetadata &current, const DriverDetail &detail,
								   const SP_DRVINFO_DATA_W &driver)
{
	return !current.infFileName.empty() &&
		   normalizedFileName( current.infFileName) == normalizedFileName( detail.infFileName) &&
		   (!current.packedVersion.has_value() ||
			current.packedVersion.value() == driver.DriverVersion) ;
}

//------------------------------------------------------------------------------
/**
 * @brief current version に対する候補操作を表示用に分類する
 *
 * current version に対する候補操作を表示用に分類する。 注記:この比較は操作の説明だけに使い、compatibilityまたは推奨順位を決定しない
 *
 * @param[in] current installed driver metadata
 * @param[in] candidateVersion candidate の packed version
 * @return update、reinstall、downgrade の分類
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const CurrentDriverMetadata &current,
										  const std::uint64_t		   candidateVersion) noexcept
{
	// 現在版を数値比較できない場合は通常更新と断定せず再導入に分類する
	if( !current.packedVersion.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 候補版が現在版より大きい場合だけ表示上の更新に分類する
	if( candidateVersion > current.packedVersion.value()) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版より小さい場合だけ表示上の旧版に分類する
	if( candidateVersion < current.packedVersion.value()) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 端末内で完全一致に使うIDの有限ASCIIを確認します
 * @param[in] value 元propertyまたは検証済み索引の一ID
 * @return 1～512文字の非空・非制御ASCIIの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validIndexNativeId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 512U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   // 元の文字をRAMで保持し、非ASCIIと制御文字を拒否します
			   return character >= L'!' && character <= L'~' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原propertyの型・実size・明示空listまたは二重終端と全IDを検証します
 * @param[in] set 同scanで所有する集合
 * @param[in,out] device 同じ集合の現在node
 * @param[in] key 固定したHardwareまたはCompatible property
 * @param[in] transport 完全な同backend API表
 * @param[out] ids 成功した大文字IDだけ。失敗時は空です
 * @return 全property成功時0、欠損や不正時は元診断に対応するHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readIndexIds( const HDEVINFO set, SP_DEVINFO_DATA &device,
									   const DEVPROPKEY					   &key,
									   const DriverStoreInventoryTransport &transport,
									   std::vector<std::wstring>		   &ids)
{
	ids.clear() ;
	std::vector<std::byte> bytes ;	// 型と実sizeを確認した原byte
	const auto status = readObservedProperty( set, device, key, DEVPROP_TYPE_STRING_LIST, bytes,
											 transport) ;	// 元propertyの独立した診断
	// 欠損やAPI失敗を正常な空ID集合へ変換しません
	if( status.state != DevicePropertyReadState::VALUE) {
		return nativeErrorFromWin32( status.diagnostic.code) ;
	}

	// 空シーケンスの実一文字だけを検査し、確保領域の初期NULで終端を補いません
	if( bytes.size() == sizeof( wchar_t)) {
		wchar_t emptyMarker{} ;	// Alignmentを持つ実一文字のcopy先です
		std::memcpy( &emptyMarker, bytes.data(), sizeof( emptyMarker)) ;
		return emptyMarker == L'\0' ? 0U : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Readerの変更に依存せず、copy先のUTF-16容量と二重終端の最小量を独立確認します
	if( bytes.size() < sizeof( wchar_t) * 2U || bytes.size() % sizeof( wchar_t) != 0U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring text( bytes.size() / sizeof( wchar_t), L'\0') ;	// Alignmentを持つ受信copy
	std::memcpy( text.data(), bytes.data(), bytes.size()) ;
	// 実size外の初期値で二重NULを補完しません
	if( text.size() < 2U || text[text.size() - 1U] != L'\0' || text[text.size() - 2U] != L'\0') {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t offset{} ;	// 実size内の未処理先頭
	// 最後の二重NULまで有限に進み、全要素成功後だけ出力します
	while( offset + 1U < text.size() && text[offset] != L'\0') {
		const auto end	 = text.find( L'\0', offset) ;								// 実size内の要素終端
		const auto rawId = std::wstring_view{text}.substr( offset, end - offset) ;	// 元の秘密ID
		// 公開schemaのsubsetをNative listの正常性条件へ転用しません
		if( !validIndexNativeId( rawId)) {
			ids.clear() ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto id = normalizeIdentifier( rawId) ;	// 検証済みASCIIだけの秘密key
		// 不正IDまたは同種別の重複を、部分的な一致へ残しません
		if( std::find( ids.begin(), ids.end(), id) != ids.end()) {
			ids.clear() ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		ids.push_back( id) ;
		offset = end + 1U ;
	}

	// 空list以外の途中二重NULや余剰byteを成功へ丸めません
	if( offset != text.size() - 1U && !(offset == 0U && text.size() == 2U)) {
		ids.clear() ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式の必須IDが元HardwareIdsの完全値に含まれるかを検査します
 * @param[in] ids 端末が返した元HardwareIdsです
 * @param[in] requiredId そのまま比較する元署名レコードの検証済みIDです
 * @return 大小文字だけを無視した完全一致があればtrueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsScopedHardwareId( const std::span<const std::wstring> ids,
											const std::wstring_view				requiredId) noexcept
{
	return std::ranges::any_of( ids, [&]( const std::wstring &id) {
		return CompareStringOrdinal( id.c_str(), -1, requiredId.data(),
									static_cast<int>( requiredId.size()), TRUE) == CSTR_EQUAL ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知のPnPインスタンス一台の現在のHardwareIds全体を読み取ります
 * @param[in] instanceId 元の端末instanceです
 * @param[out] hardwareIds 正規化した現在の全HardwareIdsです。失敗時は空です
 * @param[in] requirePresent 同じ現在インスタンスとpresent属性を必須にする場合trueです
 * @return 読取り成功は0、SetupAPI又はプロパティ検証の拒否はHRESULTです
 * @note 端末の生IDはDriverStore内だけで使います
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readScopedHardwareIds( const std::wstring		  &instanceId,
												std::vector<std::wstring> &hardwareIds,
												const bool				   requirePresent = false)
{
	hardwareIds.clear() ;
	const auto	 &transport = driver_store_inf_detail::transport() ;	// 既存の同期SetupAPI表です
	DeviceInfoSet devices( transport.create( nullptr, nullptr)) ;		// 対象一件だけを開く集合です
	// 集合の生成失敗は別の端末や属性から補完しません
	if( !devices.valid()) {
		const auto native = GetLastError() ;	// 終了直後の元診断です
		return nativeErrorFromWin32( native ? native : ERROR_INVALID_DATA) ;
	}

	SP_DEVINFO_DATA device{} ;	// 発行時と同じinstanceの読取り先です
	device.cbSize = sizeof( device) ;
	// 同じinstanceを開けない場合は適用を保留します
	if( !transport.open( devices.get(), instanceId.c_str(), nullptr, 0, &device)) {
		const auto native = GetLastError() ;	// 端末を開けなかった理由です
		return nativeErrorFromWin32( native ? native : ERROR_INVALID_DATA) ;
	}

	// 配布前の再観測で、取り外された端末や別インスタンスの値を認めません
	if( requirePresent) {
		std::wstring actualInstance ;	// 同じインスタンスか確認する内部値です
		const auto	 identity = readObservedInstanceId( devices.get(), device, actualInstance,
													   transport.inventory) ;	// Windowsの元識別子です
		// SetupAPIの読取り失敗又は別インスタンスの属性へ進みません
		if( identity.state != DevicePropertyReadState::VALUE ||
		   normalizeIdentifier( actualInstance) != normalizeIdentifier( instanceId)) {
			return nativeErrorFromWin32( identity.diagnostic.code != 0U ? identity.diagnostic.code
																	   : ERROR_NO_SUCH_DEVINST) ;
		}

		std::vector<std::byte> present ;	// 正式なBOOLEAN属性の値だけを受け取ります
		const auto			   presence = readObservedProperty(
			devices.get(), device, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN, present,
			transport.inventory) ;	// 同じインスタンスの現在属性です
		// 古いレジストリにHardwareIdsが残る場合も現端末と判定しません
		if( presence.state != DevicePropertyReadState::VALUE ||
		   present.size() != sizeof( DEVPROP_BOOLEAN) ||
		   present.front() != static_cast<std::byte>( DEVPROP_TRUE)) {
			return nativeErrorFromWin32( presence.diagnostic.code != 0U ? presence.diagnostic.code
																	   : ERROR_NO_SUCH_DEVINST) ;
		}
	}

	return readIndexIds( devices.get(), device, DEVPKEY_Device_HardwareIds, transport.inventory,
						hardwareIds) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元署名の承認を再確認し、同端末が今も公式Hardware IDを持つことを確認します
 * @param[in] instanceId 元の端末instanceです
 * @param[in] requiredId 検証済みの元署名レコードの公式Hardware IDです
 * @param[in] authorizationCheck 元署名と期限を検証する有効な同期処理です
 * @return 元承認と端末の完全一致で0、元承認又はWindowsの拒否はHRESULTです
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError authorizeScopedHardwareDevice(
	const std::wstring &instanceId, const std::wstring_view requiredId,
	const std::function<NativeError()> &authorizationCheck)
{
	const auto error = authorizationCheck() ;	// Windows変更前の元権限の結果です
	// 元署名や期限が失効した場合は端末を開く前に続行を止めます
	if( error != 0U) {
		return error ;
	}

	std::vector<std::wstring> hardwareIds ;	// 同スキャンと同じ検査を通した現在の完全値です
	const auto				  read =
		// 同一インスタンスだけを開きます
		readScopedHardwareIds( instanceId, hardwareIds) ;
	// HardwareIdsの元診断を単なる不一致で上書きしません
	if( read != 0U) {
		return read ;
	}

	return containsScopedHardwareId( hardwareIds, requiredId) ? 0U
															 : nativeErrorFromWin32( ERROR_RETRY) ;
}

} // namespace

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同じ現在機器の登録属性を保護付きの署名原本と配置へ照合する
 * @param[in] original 前観測で確定したINFと実節と関連サービス
 * @param[out] evidence 読み取った同じ署名付き登録。正式未導入または失敗時は空
 * @return 読取り成功0、元署名や登録の未確認はHRESULT
 * @note 未導入は呼出元が二属性の不在で確認する。別サービスから補完しない
 */
//------------------------------------------------------------------------------
NativeError readSingleBootStorageRegisteredEvidence(
	const AutomaticStorageDeviceRegistration &original,
	RegisteredSingleBootDeviceEvidence		 &evidence)
{
	evidence = {} ;
	// 前観測が正式な未導入を示す場合だけ空の登録を観測する
	if( original.service.empty()) {
		return 0U ;
	}

	const auto &selection = original.selection ;	// 同じ機器に記録された元選択
	const auto	extension = selection.sectionExtension
								? std::wstring_view{*selection.sectionExtension}
								: std::wstring_view{} ;	// 元節装飾を借用し有無は別に保持する
	const bool	inbox =
		// 同梱NVMeの検査範囲
		normalizeIdentifier( selection.publishedInf) == L"STORNVME.INF" ;
	// 同梱の既知の実選択は装飾なしで照合し、二属性の連結で既知節を作らない
	if( inbox && !extension.empty()) {
		return nativeErrorFromWin32( extension.front() == L'.' ? ERROR_NOT_SUPPORTED
															  : ERROR_INVALID_DATA) ;
	}

	// 架空機器の登録名から実Windowsの署名元やSCMを参照しない
	if( driver_store_inf_detail::fixtureActive()) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	RegisteredSingleBootDeviceEvidence made ;	// 元署名が成立するまで保持する作業値
	made.sectionExtension = selection.sectionExtension ;
	// 同梱とOEMはWindowsから得た実選択に対応する独立した元検査を使う
	const auto error = inbox ? readRegisteredInboxSingleBootStorageEvidence(
								   selection.publishedInf, selection.basicSection, original.service,
								   made.registered.emplace())
							 : readRegisteredOemSingleBootStorageEvidence(
								   selection.publishedInf, selection.basicSection, extension,
								   original.service, made.registered.emplace()) ;
	// 未対応または不一致になった元登録の途中結果は共有しない
	if( error == 0U) {
		evidence = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ機器の現用証拠と署名候補の局所値・サービス・イベントを一度読む
 * @param[in] devices 前観測と同じWindowsの情報集合
 * @param[in,out] device 開いた同じ機器。SetupAPIの読取り中だけ借用
 * @param[in] instanceId 所有を照合済みの元機器識別
 * @param[in] original 同じ機器から読んだ元登録属性
 * @param[in] intended 同じ署名付き候補の局所作用と関連サービス
 * @param[out] made 両回の比較まで公開しない作業領域。失敗時は使用しない
 * @return 全部の読取り成功0。現在登録や個別観測の不成立はHRESULT
 * @note イベントの実在を署名元の所有に変換しない
 */
//------------------------------------------------------------------------------
NativeError readSingleBootDeviceComponents( HDEVINFO devices, SP_DEVINFO_DATA &device,
										   std::wstring_view						 instanceId,
										   const AutomaticStorageDeviceRegistration &original,
										   const StorageInfEffects					&intended,
										   StorageSingleBootDeviceSnapshot			&made)
{
	auto error =
		// 同じ機器が実際に選択した元配布
		readSingleBootStorageRegisteredEvidence( original, made.installed) ;
	// 未確認の現在ドライバーを正式未導入に置き換えない
	if( error != 0U) {
		return error ;
	}

	error =
		readSingleBootStorageRegistrySnapshot( devices, device, instanceId, intended, made.registry) ;
	// 同じ機器と保護を確認できた局所観測だけを保持する
	if( error != 0U) {
		return error ;
	}

	const auto &candidate = intended.service.name ;	// 同じ候補が書く関連サービス名
	error				  = readSingleBootStorageEventSnapshot( candidate, made.candidateEvent) ;
	// 失敗をイベントの正式不在に置き換えない
	if( error != 0U) {
		return error ;
	}

	// 同じ関連名で取得した署名元と現在構成だけを共用する
	const bool usesCandidate = made.installed.registered && normalizeIdentifier( original.service) ==
																normalizeIdentifier( candidate) ;
	// 現用と候補の関連名が異なる場合は別々の署名根拠と現在イベントを保持する
	if( made.installed.registered && !usesCandidate) {
		error = readSingleBootStorageEventSnapshot( original.service,
												   made.otherInstalledEvent.emplace()) ;
		// 現用イベントの不明を別のイベント観測で補完しない
		if( error != 0U) {
			return error ;
		}
	}

	made.candidateService.name = candidate ;
	// 同じ現用サービスでは先に署名元の読取りと一緒に確認したSCMを使う
	if( usesCandidate) {
		made.candidateService.evidence = made.installed.registered->service ;
		return 0U ;
	}

	error = readStorageServiceEvidence( candidate, made.candidateService.evidence.emplace()) ;
	// SCMとレジストリのキー、イベントの不在はそれぞれ独立した事実として保持する
	if( error == nativeErrorFromWin32( ERROR_SERVICE_DOES_NOT_EXIST)) {
		made.candidateService.evidence.reset() ;
		return 0U ;
	}

	return error ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief Windowsの同じ現在機器を同梱またはOEMの署名付き単一ブート登録に結合する
 * @param[in] instanceId 以前のOS観測で選択した元機器のインスタンス
 * @param[in] noDriver 以前の観測がINFとサービスの未導入を示した場合true
 * @param[in] expectedInf 以前の元機器の公開INF。独立した観測では空も許可
 * @param[out] result 前後の機器属性と元署名が成立した証拠。正式未導入と失敗時は空
 * @return 現用元または正式な未導入の確認成功0、途中変更、未対応、読取り不成立はHRESULT
 * @note 元機器の識別やレジストリを外部へ渡さず、Windowsを変更しない
 */
//------------------------------------------------------------------------------
NativeError readCurrentSingleBootStorageDeviceEvidence( const std::wstring &instanceId,
													   bool noDriver, std::wstring_view expectedInf,
													   RegisteredSingleBootDeviceEvidence &result)
{
	result = {} ;
	// 空の識別と、元の導入状態が矛盾する指示から実機器を検索しない
	if( instanceId.empty() || instanceId.find( L'\0') != instanceId.npos ||
	   (noDriver && !expectedInf.empty())) {
		return E_INVALIDARG ;
	}

	RegisteredSingleBootDeviceEvidence made ;	// 機器登録の再確認まで公開しない署名付き読取り
	// 既存の同一機器の前後照合の中で、現在の元情報だけを読む
	const auto						   error = inspectPresentStorageDeviceRegistration(
		instanceId, noDriver, expectedInf,
		[&]( const AutomaticStorageDeviceRegistration &original, const auto &, HDEVINFO,
			SP_DEVINFO_DATA &) { return readSingleBootStorageRegisteredEvidence( original, made) ; }) ;
	// 部分観測を同じ署名付き登録として扱わない
	if( error == 0U) {
		result = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在機器の属性に候補の局所設定と現用・候補のイベント・SCMを同じ同期処理で結ぶ
 * @param[in] instanceId 前観測の同じ機器を開くWindows識別
 * @param[in] noDriver 同じ先の観測で未導入が正式に確認された場合true
 * @param[in] expectedInf 登録済みの機器で先に確認した元公開名。正式未導入なら空
 * @param[in] intended 同じ候補の署名付き元選択から読み取った作用
 * @param[out] snapshot 全観測が二回一致し外側の機器も変わらなかった場合の結果。失敗時は空
 * @return 同一の安定観測で0、属性・個別読取りの不成立はHRESULT
 * @note 機器情報を外へ出さず、ファイルやレジストリとSCMは読取りだけに使う
 */
//------------------------------------------------------------------------------
NativeError readCurrentSingleBootStorageDeviceSnapshot( const std::wstring &instanceId,
													   bool noDriver, std::wstring_view expectedInf,
													   const StorageInfEffects		   &intended,
													   StorageSingleBootDeviceSnapshot &snapshot)
{
	snapshot = {} ;
	// 既知の前観測と矛盾する入力や不明の機器を再検索しない
	if( instanceId.empty() || instanceId.size() > 512U ||
	   instanceId.find( L'\0') != instanceId.npos || noDriver != expectedInf.empty() ||
	   intended.service.name.empty()) {
		return E_INVALIDARG ;
	}

	try {
		StorageSingleBootDeviceSnapshot made ;	// 二回の観測と機器の最終確認まで作業領域に置く
		// 同じ情報集合と元候補を読み取り中だけ借用し、すべての観測を前後の属性で囲む
		const auto						error = inspectPresentStorageDeviceRegistration(
			 instanceId, noDriver, expectedInf,
			 [&]( const AutomaticStorageDeviceRegistration &original, const auto &, HDEVINFO devices,
				 SP_DEVINFO_DATA &device) {
				 // 架空機器では署名元、SCM、レジストリのいずれも実Windowsへ照会しない
				 if( driver_store_inf_detail::fixtureActive()) {
					 return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				 }

				 return readStableSingleBootDeviceSnapshot(
					 [&]( StorageSingleBootDeviceSnapshot &pass) {
						 return readSingleBootDeviceComponents( devices, device, instanceId, original,
																				   intended, pass) ;
					 },
					 made) ;
			 }) ;
		// 複数の読取りが成立しても別機器や変更後の観測には転用しない
		if( error == 0U) {
			snapshot = std::move( made) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

/** @brief 元署名Modelsの実選択からだけ発行する私有の導入計画 */
struct DeclarativeInfInstallQualification {
	/// この観測を所有するDriver Store
	const DriverStoreProvider			   *owner ;
	/// 元scan
	ScanSessionId							session ;
	/// 同scanの対象端末
	std::wstring							deviceIdentity ;
	/// 署名を確認した同じ保護領域
	const OfficialDownloadWorkspace		   *workspace ;
	/// 同じ保護領域から読んだ元INFの構造
	const OfficialInfPackage			   *package ;
	/// 署名済みレコードに記された現在OSの元Models節
	std::wstring							modelsSection ;
	/// 同じ元INFのハッシュとクラス節の表示情報
	OfficialInfDeclarativeClassRegistration registration ;
	/// 元端末の状態
	DeviceRankSnapshot						current ;
	/// 元INFの実選択と元順ID
	CandidateDriverNodeSnapshot				selected ;
	/// 元端末と対象クラスの読み取り結果
	DeclarativeClassEffects					effects ;
} ;

/** @brief 同じ端末と同じWindows nodeから読み取った公式Modelsの内部証拠です */
struct DriverStoreProvider::ScopedInfObservation {
	/// 同じ端末の不変な元PnPインスタンスです
	std::wstring				instance ;
	/// 順位比較中に観測した元端末の実状態です
	DeviceRankSnapshot			current ;
	/// 同じ候補の元順付きHardware IDとCompatible ID、実順位です
	CandidateDriverNodeSnapshot candidate ;
	/// 公式対象内の一意な行と基本導入節です
	OfficialInfScopedModelMatch row ;
	/// 元行に基づく実導入節と元ファイルの関係です
	OfficialInfPackage			relations ;
	/// 同じ現在端末と候補nodeに対する順位監査値です
	OfficialDriverRankAudit		rank ;
	/**
	 * @brief 同じ端末の元行と現在のWindows選択が一致しているか比較します
	 * @param[in] other 同じ用途で取り直した端末選択です
	 * @return 同じPnPインスタンス・元行・現在状態・候補node・順位ならtrueです
	 */
	[[nodiscard]] bool			sameSelection( const ScopedInfObservation &other) const noexcept
	{
		return instance == other.instance && row.modelRow == other.row.modelRow &&
			   row.hardwareId == other.row.hardwareId && row.installBase == other.row.installBase &&
			   deviceRankSnapshotsEqual( current, other.current) &&
			   candidateNodeSnapshotsEqual( candidate, other.candidate) &&
			   officialRankAuditsEqual( rank, other.rank) ;
	}
} ;

/** @brief 選択端末と同梱の仮想Wi-Fiバスに結ぶ現在状態です */
struct ScopedWifiBusInstallEvidence {
	/// 署名済み同梱INF、同じStoreの元ファイルと現在サービスです
	ScopedWifiBusDependencyEvidence dependencies ;
	/// 元端末の状態、型と上位フィルターの全バイトです
	MtdHandlerProperty				upperFilters ;
	/**
	 * @brief 同じ端末で確認した同梱証拠とフィルター原値を比較します
	 * @param[in] other 独立に読み直した同じ選択の結果です
	 * @return 全同梱証拠と端末の型・原値が完全一致する場合trueです
	 */
	[[nodiscard]] bool operator==( const ScopedWifiBusInstallEvidence &other) const = default ;
} ;

/** @brief 同一取得・端末・実選択と再検査可能な作用を保持する内部計画です */
struct ScopedInfInstallQualification {
	/// 最初の確認を行った同じDriver Storeです
	const DriverStoreProvider							*owner{} ;
	/// 保持可能な同一ownerのスキャンです
	ScanSessionId										 session{} ;
	/// 元操作が選択した端末の不透明IDです
	std::wstring										 deviceIdentity ;
	/// 対象recordと結び付いた取得物、元閉包と元ファイルを強所有します
	std::shared_ptr<const CollectorDriverPackageContent> content ;
	/// 認証済み索引領域の元ハッシュです
	std::wstring										 indexSha256 ;
	/// 取得が使用した元レコードのハッシュです
	std::wstring										 recordSha256 ;
	/// レコードが同じ署名欄に指定した元Models証拠のハッシュです
	IndexManifestSha256									 evidenceSha256{} ;
	/// 元レコードが指定した現在OSの節です
	std::wstring										 modelsSection ;
	/// 実端末の状態と、選択された元行・候補node・順位です
	DriverStoreProvider::ScopedInfObservation			 observed ;
	/// その実選択から得たSYS、サービスとWindows標準DLLの証拠です
	OfficialScopedNetworkEffects						 effects ;
	/// 同じ実選択が同梱の仮想Wi-Fiバスを必要とする場合の現サービスと端末原値です
	std::optional<ScopedWifiBusInstallEvidence>			 wifiBus ;
	/**
	 * @brief 元の不変閉包が所有する同じ保護領域と基本INFを確認します
	 * @param[in] workspace 照合対象の保護領域です
	 * @param[in] package 照合対象の元基本INFです
	 * @return 同じ内容の所有元と同一objectならtrueです
	 */
	[[nodiscard]] bool ownsSource( const OfficialDownloadWorkspace &workspace,
								  const OfficialInfPackage		  &package) const noexcept
	{
		return content && content->infs.size() == 1U &&
			   content->infs.front().workspace.get() == &workspace &&
			   content->infs.front().closure.packages.size() == 1U &&
			   &content->infs.front().closure.packages.front() == &package &&
			   package.inspectionPurpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
			   package.scopedModels.has_value() ;
	}
} ;

/** @brief base後に実列挙した子自身の状態と一意node/rankの同期借用です */
struct DriverStoreProvider::RequiredChildObservation {
	/// 同子のClass/ID/現在状態です
	const DeviceRankSnapshot		  &device ;
	/// 同元component INFでWindowsが選択した一意nodeです
	const CandidateDriverNodeSnapshot &candidate ;
	/// 同子に対するWindows full rankです
	const OfficialDriverRankAudit	  &rank ;
} ;

/** @brief exact現serviceを使う全present adapterの元native状態です。外部から構築しません */
struct StorageServiceOwnershipProof {
	/** @brief 原service使用nodeと同新packageへのWindows適合証拠です */
	struct Owner {
		/// 元Windowsの秘密instanceです
		std::wstring								 instance ;
		/// 元現在device/driver/Class/rankの全事実です
		DeviceRankSnapshot							 current ;
		/// 同原packageの一意nodeです
		CandidateDriverNodeSnapshot					 candidate ;
		/// 同peerの元全rankです
		OfficialDriverRankAudit						 rank ;
		/// 補助作用の検査時にだけ、同じownerの現在登録済み元配布を保持する
		std::optional<VerifiedInstalledStorageOwner> registeredPackage ;
	} ;
	/// exact service filterの原順です。全PnP再列挙ではありません
	std::vector<Owner> owners ;
} ;

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 全現用機器の署名付き元登録を現在の共有構成へ照合する
 * @param[in] host 読取り済みの同じSCM・配置ファイル・Systemイベントの状態
 * @param[in] ownership 同じ関連サービスを使用する全機器の検証済み元登録
 * @return 元登録と現在の共有構成の照合が成立した場合0、失敗時はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyStorageServiceAuxiliaryOwnership( const StorageAuxiliaryHostSnapshot &host,
												   const StorageServiceOwnershipProof &ownership)
{
	std::vector<const RegisteredStoragePackageEvidence *> packages ;	// 全現用機器の同期借用
	packages.reserve( ownership.owners.size()) ;
	// どの機器も共有先の判定から省略しない
	for( const auto &owner : ownership.owners) {
		// 未照合の元登録を別機器の成功で補わない
		if( !owner.registeredPackage) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		packages.push_back( &owner.registeredPackage->package) ;
	}

	return verifyRegisteredStorageAuxiliaryOwnership( host, packages) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 補助サービスの現在登録を、同じ操作で適用した元INF・CAT・選択節へ照合する
 * @param[in] applied 同じ対象が現在使う署名付き登録と実選択節
 * @param[in] inspected 指定適用前に確認した元閉包の全事実
 * @param[in] service 同じ元選択の関連SYS、補助EXEと導入節
 * @return 同じ元配布と補助EXEの元バイトを確認した場合0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyAppliedStorageAuxiliaryOrigin( const RegisteredStoragePackageEvidence &applied,
												const CommonInfInspection			   &inspected,
												const SelectedStorageServiceFacts	   &service)
{
	// 適用先は同じ元基本INFの検証済み閉包に限る
	if( !service.auxiliary || inspected.closure.packages.size() != 1U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto &base	  = inspected.closure.packages.front() ;	// 元の署名INFとCATの同一参照
	const auto &entries	  = inspected.closure.entries ;				// 元の完全byteハッシュを保持する各項目
	const auto	findEntry = [&entries]( const std::wstring &path) {
		 return std::ranges::find_if( entries, [&path]( const OfficialZipEntry &entry) {
			 return CompareStringOrdinal( entry.relativePath.c_str(), -1, path.c_str(), -1, TRUE) ==
					CSTR_EQUAL ;
		 }) ;
	} ; // 同じ閉包の相対パスをWindowsと同じ大文字小文字の扱いで同期照合する
	const auto inf = findEntry( base.infRelativePath) ;		// 元INFの監査済み項目
	const auto cat = findEntry( base.catalogRelativePath) ;	// 元CATの監査済み項目
	// 別版・別署名・別導入節や実際に配置したファイルの証拠不足を反映済みにしない
	if( inf == entries.end() || cat == entries.end() || inf->sha256.size() != 64U ||
	   cat->sha256.size() != 64U || applied.infSha256 != inf->sha256 ||
	   applied.catalogSha256 != cat->sha256 || applied.driverSha256 != service.binarySha256 ||
	   normalizeIdentifier( applied.installedSection) !=
		   normalizeIdentifier( service.selectedInstallSection) ||
	   !applied.helper || applied.helper->sourceSha256 != service.auxiliary->copy.sha256 ||
	   applied.helper->deployedSha256 != service.auxiliary->copy.sha256) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 要求時起動の補助サービスの元配布と現在の配置、構成を照合する
 * @param[in] applied 同じ適用機器の署名付き現在登録
 * @param[in] inspected 指定適用前に確認した元閉包
 * @param[in] service 同じ元選択の関連SYS、補助EXEと導入節
 * @param[in] host 適用後の同じSCM、System32とイベントの観測
 * @return 元配布と現在の配置・構成が確認できた場合0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyAppliedStorageAuxiliaryEvidence( const RegisteredStoragePackageEvidence &applied,
												  const CommonInfInspection				 &inspected,
												  const SelectedStorageServiceFacts		 &service,
												  const StorageAuxiliaryHostSnapshot	 &host)
{
	const auto error =
		// 同じ元配布
		verifyAppliedStorageAuxiliaryOrigin( applied, inspected, service) ;
	// 別配布または欠けた配置を現在の所有照合で補わない
	if( error != 0U) {
		return error ;
	}

	const std::array packages{&applied} ;	// 同じ適用先の署名が実配置と現在構成を裏付ける
	return verifyRegisteredStorageAuxiliaryOwnership( host, packages) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定適用後の同一機器と候補が変更する共有先を読み取る
 * @param[in] instance 指定適用した機器の元インスタンス
 * @param[in] noDriver 正式な未導入状態を読み取る場合true
 * @param[in] publishedInf 確認するOEM INF名。正式な未導入の確認だけ空
 * @param[in] intended 同じ元選択のストレージ作用
 * @param[out] result 全読取りと元登録照合後の保護付き観測。失敗時は空
 * @return 同じ機器・登録と作用を読めた場合0、違いや読取り失敗はHRESULT
 * @note 読取り専用。AutoLoggerが実際に稼働中かどうかは構成とは独立に保持する
 */
//------------------------------------------------------------------------------
NativeError readAutomaticStoragePostState( const std::wstring &instance, bool noDriver,
										  std::wstring_view				publishedInf,
										  const StorageInfEffects	   &intended,
										  StorageAutomaticHostSnapshot &result)
{
	result = {} ;
	// 元の選択と読取り対象を別の公開INFへ切り替えない
	if( noDriver != publishedInf.empty() || !intended.autoLogger) {
		return E_INVALIDARG ;
	}

	StorageAutomaticHostSnapshot observed ;				// 同じ適用元と全観測の成立まで公開しない
	auto	   &device	= observed.device.emplace() ;	// ここでは指定した一機器の現在登録を読む
	const auto &service = intended.service ;			// 署名付き選択の関連サービスと補助
	auto		error	= inspectCurrentAutomaticStorageRegistration(
		 instance, noDriver, publishedInf, service,
		 device.selected) ;	// 同じ機器の現在INF、補助、イベント
	// 選択機器の元登録が確認できた場合だけ、元選択のイベント変更先を読む
	if( error == 0U) {
		error = readNamedStorageEventSnapshot( service, observed.events) ;
	}

	// 同じ元選択が直接置くDLLを既存イベントの登録とは独立に読む
	if( error == 0U) {
		error = readStorageAutomaticEventResource( service, observed.eventResource) ;
	}

	// 実際に動く補助の正規配置先を、選択機器の旧登録の補助とは独立に読む
	if( error == 0U) {
		error = readAutoStartStorageAuxiliarySnapshot( service, observed.auxiliary) ;
	}

	// 元署名や配置が変わった候補の共有設定を当該操作に帰属させない
	if( error != 0U) {
		return error ;
	}

	auto &boot		  = observed.boot.emplace() ;	// 関連サービスと現在の正規SYS配置
	boot.related.name = service.name ;
	error			  = readStorageServiceEvidence( service.name, boot.related.evidence.emplace()) ;
	// 正式に適用した関連サービスの保護と正規SYSの配置を確認する
	if( error == 0U) {
		error = validateStorageServiceEvidence( *boot.related.evidence) ;
	}
	// 適用前も不在だった場合に比較できるよう、Windowsの正式な不在だけを保持する
	else if( error == nativeErrorFromWin32( ERROR_SERVICE_DOES_NOT_EXIST)) {
		boot.related.evidence.reset() ;
		error = 0U ;
	}

	// 現用SCMの読取りが成立した場合だけ対応する保護付きSYSを読む
	if( error == 0U) {
		error = readSystem32StorageDriverSnapshot( service.binaryTarget, boot.destination) ;
	}

	// 起動サービスが確認できなければ、共有値だけで反映済みを構成しない
	if( error != 0U) {
		return error ;
	}

	error = readStorageServiceEvidence( L"ACPI", observed.shared.acpiService) ;
	// ACPIの正規カーネルサービスが保護付きで読める場合だけ共有構成を確認する
	if( error == 0U) {
		error = validateStorageServiceEvidence( observed.shared.acpiService) ;
	}

	// ローカルの共有レジストリと同じWindowsの固定ACPI.sysだけを照合する
	if( error == 0U) {
		std::array<wchar_t, MAX_PATH> windows{} ;	// 固定System32パスを作るWindowsルート
		// 終端を除く値。切詰めを別ルートで補わない
		const auto count = GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
		// ルートの取得に失敗した場合は別のACPIファイルを探さない
		if( count <= 3U || count >= windows.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Windows固定の正規ACPIカーネルファイル
		const auto acpi = std::wstring{windows.data(), count} + L"\\System32\\drivers\\ACPI.sys" ;
		WindowsSystemFileTrust trust ;	// 同じWindowsの保護と正規署名をキャッシュで照合
		error = verifyWindowsSystemFileCachedOnly( acpi, trust) ;
	}

	// 共有作用は現在のACPI、AutoLogger、電源の順に読み、最初の失敗を保持する
	if( error == 0U) {
		error = readStorageAcpiSnapshot( observed.shared.acpi) ;
	}

	// 同じ元セッションの設定を読み、稼働状態で代替しない
	if( error == 0U) {
		error = readStorageAutoLoggerSnapshot( *intended.autoLogger, observed.shared.autoLogger,
											  StorageAutoLoggerProfile::TRIAGE_BUFFER) ;
	}

	// セッションの正式不在とアクセス拒否を区別する
	if( error == 0U) {
		error = readStorageAutoLoggerRuntimePresence( *intended.autoLogger,
													 observed.autoLoggerRuntimePresent.emplace()) ;
	}

	// 元の電源定義と既定値がそろうまで観測を外へ出さない
	if( error == 0U) {
		error = readStoragePowerSettingsSnapshot( intended.powerSettings, observed.power) ;
	}

	// 個別の読取りが全部成立した場合だけ、元と照合する観測へ移す
	if( error == 0U) {
		result = std::move( observed) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ指定機器の現在登録と共有する補助構成を適用後に読み直す
 * @param[in] instance 同じ操作で指定適用した機器の元識別子
 * @param[in] inspected 同じ選択の元閉包
 * @param[in] service 元選択の関連サービスと補助サービス
 * @param[in] host 適用後に読んだ変更先の状態。署名照合後に再観測する
 * @return 元選択と現在の補助作用が一致した場合0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyAppliedStorageAuxiliaryRegistration( const std::wstring				 &instance,
													  const CommonInfInspection			 &inspected,
													  const SelectedStorageServiceFacts	 &service,
													  const StorageAuxiliaryHostSnapshot &host)
{
	const auto	 &api = driver_store_inf_detail::transport() ;	// 同workerが使った端末照会表
	DeviceInfoSet devices( api.create( nullptr, nullptr)) ;		// 同一機器だけを開く情報集合
	// 適用直後に端末を開けない場合は以前取得した現在値を流用しない
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// 同じ選択機器の元node
	device.cbSize = sizeof( device) ;
	// 同じ元選択に対応する機器だけの現在登録を確認する
	if( !api.open( devices.get(), instance.c_str(), nullptr, 0U, &device)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	std::wstring currentService ;	// 適用後に関連付いたカーネルサービス名
	const auto	 serviceRead =
		readObservedDeviceString( devices.get(), device, DEVPKEY_Device_Service, currentService,
								 api.inventory) ;	// 現在の関連サービス照会
	// ファイルが存在しても指定機器のサービスが未更新なら反映済みにしない
	if( serviceRead.state != DevicePropertyReadState::VALUE ||
	   normalizeIdentifier( currentService) != normalizeIdentifier( service.name)) {
		return nativeErrorFromWin32( serviceRead.diagnostic.code ? serviceRead.diagnostic.code
																: ERROR_RETRY) ;
	}

	const auto current =
		// 現在の登録INFと選択節
		readCurrentDriver( devices.get(), device, api.inventory) ;
	// 登録先が読めなかった元診断も確認結果へ保持する
	if( current.infRead.state != DevicePropertyReadState::VALUE) {
		return nativeErrorFromWin32(
			current.infRead.diagnostic.code ? current.infRead.diagnostic.code : ERROR_NOT_FOUND) ;
	}

	const DriverStorePackageLookup lookup{api.windowsDirectory,
										  api.storageStoreLocation} ;	// 同API表の登録済み配布照会
	VerifiedInstalledStorageOwner  applied ;							// 元登録、選択節と実配置済みバイトの証拠
	auto						   error =
		readVerifiedInstalledStorageOwner( devices.get(), device, api.inventory, lookup, current,
										  service, host, applied) ;	// 元登録と署名の診断
	// 端末の現在登録が成立した場合に同じ適用元へ結び付ける
	if( error == 0U) {
		error = verifyAppliedStorageAuxiliaryEvidence( applied.package, inspected, service, host) ;
	}

	// 照合済みの構成も、署名検査中に変わった場合は完了としない
	if( error == 0U) {
		StorageAuxiliaryHostSnapshot fresh ;	// 同じ作用先の安定性を調べる二度目の観測
		error = readStorageAuxiliaryHostSnapshot( service, fresh) ;
		// 同じ状態をもう一度確認した場合だけ実反映を記録する
		if( error == 0U && fresh != host) {
			error = nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 補助作用の反映と、Windowsが再起動を求めた旧EXEの残存を区別する
 * @param[in] effects COPYFLG_FORCE_FILE_IN_USEの同名コピーに結合した補助作用と適用前の観測
 * @param[in] ownership 適用前に確認済みの署名付き共有所有
 * @param[in] current 保護された作用先の適用後の観測
 * @param[in] rebootRequired 同じ指定導入APIが報告した再起動要求
 * @param[in] error 適用後の登録・現在構成の照合結果
 * @return 確認済み、再起動後要確認、元診断付き未確認のいずれか
 * @note 旧ファイルがそのままの場合でもWindowsの置換予約そのものは保証しない
 */
//------------------------------------------------------------------------------
DriverAuxiliaryExecutionResult classifyStorageAuxiliaryReflection(
	const StorageInfEffects &effects, const StorageServiceOwnershipProof &ownership,
	const StorageAuxiliaryHostSnapshot &current, bool rebootRequired, NativeError error)
{
	// 元配布と現在の全作用が一致した場合は実際に反映済みと記録する
	if( error == 0U) {
		return {DriverAuxiliaryReflectionState::CONFIRMED, 0U} ;
	}

	// 適用前の同じ署名付きEXEと構成が残り、Windowsが再起動を求めた場合は後で確認する
	if( rebootRequired && effects.service.auxiliary && effects.auxiliaryHost &&
	   current.executable.existing &&
	   effects.auxiliaryHost->executable.existing == current.executable.existing &&
	   current.executable.existing->sha256 != effects.service.auxiliary->copy.sha256) {
		const auto ownershipError = verifyStorageServiceAuxiliaryOwnership(
			current, ownership) ;	// 既存の署名と現在の構成の診断
		// 旧版と一致するファイルに加えて、現在も同じ共有構成と確認できることを求める
		if( ownershipError == 0U) {
			return {DriverAuxiliaryReflectionState::RESTART_CHECK, 0U} ;
		}

		error = ownershipError ;
	}

	return {DriverAuxiliaryReflectionState::UNCONFIRMED, error} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定導入APIの成功後に補助作用の現在状態を読み取って結果を作る
 * @param[in] instance 同じ指定機器の元識別子
 * @param[in] inspected 同じ適用元の署名付き閉包
 * @param[in] effects 同じ選択の補助作用と適用前の観測
 * @param[in] ownership 適用前に照合した全現用機器の元登録
 * @param[in] rebootRequired Windowsの実再起動要求
 * @return 現在の反映状況。指定導入APIそのものの成否とは別に保持する
 */
//------------------------------------------------------------------------------
DriverAuxiliaryExecutionResult observeAppliedStorageAuxiliary(
	const std::wstring &instance, const CommonInfInspection &inspected,
	const StorageInfEffects &effects, const StorageServiceOwnershipProof &ownership,
	bool rebootRequired)
{
	try {
		StorageAuxiliaryHostSnapshot current ;	// 同じ作用先の適用後の現在値
		const auto					 error =
			// 適用後の読取り診断
			readStorageAuxiliaryHostSnapshot( effects.service, current) ;
		// 取得失敗から再起動後の反映を推測しない
		if( error != 0U) {
			return {DriverAuxiliaryReflectionState::UNCONFIRMED, error} ;
		}

		const auto verified = verifyAppliedStorageAuxiliaryRegistration(
			instance, inspected, effects.service, current) ;	// 現在登録と元配布の診断
		return classifyStorageAuxiliaryReflection( effects, ownership, current, rebootRequired,
												  verified) ;
	} catch( const std::bad_alloc &) {
		return {DriverAuxiliaryReflectionState::UNCONFIRMED, E_OUTOFMEMORY} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが同じ関連サービスを使用中と返す全present機器の一覧を読む
 * @param[in] service 署名付き選択または現用登録が示した正確な関連サービス名
 * @param[out] result 全IDの取得と終端確認に成功した場合だけ保持する。正式な空は空
 * @return 一覧の読取り成功0、重複・上限・読取り不成立はHRESULT
 * @note 同じサービスの機器ノードを新規生成しない。IDは端末内の照合だけに使う
 */
//------------------------------------------------------------------------------
NativeError readStorageRelatedDeviceIds( const std::wstring		  &service,
										std::vector<std::wstring> &result)
{
	result.clear() ;
	const auto	   &api = driver_store_inf_detail::transport() ;	// 同一workerの有限照会表
	// 同じサービスのpresentノードに限定し、Windowsにノードを追加させない
	constexpr ULONG FLAGS =
		CM_GETIDLIST_FILTER_SERVICE | CM_GETIDLIST_FILTER_PRESENT | CM_GETIDLIST_DONOTGENERATE ;
	ULONG	   capacity{} ;	// Windowsが保証する終端を含む必要容量
	// 元APIが必要容量を確定した成否
	const auto sized = api.serviceDeviceListSize( &capacity, service.c_str(), FLAGS) ;
	// 容量が取得できなかった一覧を正常な空と扱わない
	if( sized != CR_SUCCESS || capacity == 0U || capacity > 65536U) {
		return nativeErrorFromWin32( sized != CR_SUCCESS
										? CM_MapCrToWin32Err( sized, ERROR_GEN_FAILURE)
										: ERROR_INVALID_DATA) ;
	}

	std::vector<wchar_t> names( capacity, L'\xFFFF') ;	// 未書込みを明示終端と区別する
	// 同じフィルターで現在一覧を取得した成否
	const auto listed = api.serviceDeviceList( service.c_str(), names.data(), capacity, FLAGS) ;
	// 一覧取得や容量変動の失敗を部分集合に置き換えない
	if( listed != CR_SUCCESS) {
		return nativeErrorFromWin32( CM_MapCrToWin32Err( listed, ERROR_GEN_FAILURE)) ;
	}

	std::vector<std::wstring>		 made ;							// 二つ目の終端の確認まで公開しない一覧
	std::unordered_set<std::wstring> seen ;							// Windowsの識別子の大小文字違いを同一と扱う
	auto							 position = names.cbegin() ;	// 元の複数文字列の次の未読位置
	// 終端まで全IDを順に解析し、一部機器だけの成功を返さない
	while( position != names.cend() && *position != L'\0') {
		const auto end = std::find( position, names.cend(), L'\0') ;	// 次の一件の終端
		// 元一覧の欠損、不正長と上限超過を拒否する
		if( end == names.cend() || made.size() >= 32U || end - position > MAX_DEVICE_ID_LEN) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto &instance = made.emplace_back( position, end) ;	// 同じWindowsが返した元識別子
		// 重複した識別子を別の所有者として扱わない
		if( !seen.insert( normalizeIdentifier( instance)).second) {
			return nativeErrorFromWin32( ERROR_DUP_NAME) ;
		}

		position = end + 1 ;
	}

	// 最終の確認済み終端が無い一覧を現在の完全集合へ変換しない
	if( position == names.cend()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	result = std::move( made) ;
	return 0U ;
}

/** @brief 同じ全現在機器のうち調べる元登録属性の範囲 */
enum class PresentDevicePeerMode {
	/// 非空の元サービスと現在INFが必要な従来ストレージ照合
	STORAGE_POWER,
	/// INFのある機器では元サービスの正式不在または正規空値も扱うDisplay照合
	DISPLAY,
} ;

/** @brief SoftwareComponentを現在の親と完全Hardware IDで照合する内部値 */
struct DisplayPeerComponentProperties {
	/// 正規化した現在の完全親インスタンスID。値が確認できなければ空
	std::wstring			  parent ;
	/// 親の非空値・空値・正式不在・照会失敗の区分
	DevicePropertyReadState	  parentState{DevicePropertyReadState::NOT_READ} ;
	/// 親属性の元診断に対応するHRESULT。正常な読取りは0
	NativeError				  parentDiagnostic{} ;
	/// Windowsの順序を保った正規化済みHardware ID。失敗時は空
	std::vector<std::wstring> hardwareIds ;
	/// 正常な読取りは0、正式不在はERROR_NOT_FOUND、その他は元診断に対応するHRESULT
	NativeError				  hardwareIdsDiagnostic{} ;
	/**
	 * @brief 同じSoftwareComponentから独立に読み取った関係属性を照合する
	 * @param[in] other 同じ機器の親とHardware IDの元観測
	 * @return 値と各属性の診断が等しい場合true
	 */
	bool operator==( const DisplayPeerComponentProperties &other) const = default ;
} ;

/** @brief present機器の登録情報を元署名確認の前後で比較する内部値 */
struct PresentDevicePeerRegistration {
	/// 同じWindows内でのみ使う正規化した機器識別
	std::wstring								  instance ;
	/// 同じ現在機器が持つ署名確認前の登録属性
	AutomaticStorageDeviceRegistration			  registration ;
	/// 両属性の正式不在を観測すればtrue
	bool										  noDriver{} ;
	/// 関連サービスの値・正式不在、またはDisplayの正規空値を読めればtrue
	bool										  serviceKnown{} ;
	/// 単一ブートの元署名を読む既存処理の対象クラス
	bool										  storageClass{} ;
	/// 正式不在または元登録の読取成功は0、その他は元診断
	NativeError									  diagnostic{} ;
	/// Displayでの関連サービス属性の到達区分。ストレージ照合では未照会区分を保持
	DevicePropertyReadState						  serviceState{DevicePropertyReadState::NOT_READ} ;
	/// DisplayでSetupAPIがSoftwareComponentクラスを示した機器だけが持つ追加属性
	std::optional<DisplayPeerComponentProperties> softwareComponent ;
	/**
	 * @brief 全present機器の同じ機器を読み直した結果と比較する
	 * @param[in] other 同じ機器の元属性と診断
	 * @return 元属性と診断が同じ場合true
	 */
	bool operator==( const PresentDevicePeerRegistration &other) const = default ;
} ;

/** @brief 従来のストレージ照合で使う全現在機器の元登録属性 */
using StoragePowerPeerRegistration = PresentDevicePeerRegistration ;

//------------------------------------------------------------------------------
/**
 * @brief 現在のSoftwareComponentから親インスタンスとHardware IDを独立に取得する
 * @param[in] devices 同じ現在機器を含む借用情報集合
 * @param[in,out] node SetupAPIがSoftwareComponentクラスを返した機器の元情報
 * @param[in] api 同じ情報集合の型付き属性照会
 * @return 元の親とHardware IDの値または個別の診断
 * @note 全現在機器の登録状態を判定する際の診断とは別に保持する
 */
//------------------------------------------------------------------------------
DisplayPeerComponentProperties readDisplayPeerComponentProperties(
	const HDEVINFO devices, SP_DEVINFO_DATA &node, const DriverStoreInventoryTransport &api)
{
	DisplayPeerComponentProperties result ;	// 同じSoftwareComponentの端末内限定属性
	auto parent = readObservedDeviceString( devices, node, DEVPKEY_Device_Parent, result.parent,
										   api) ;	// 同じ機器の型付き親関係
	// 列挙した完全インスタンスIDと同じ有限の長さで照合する
	if( parent.state == DevicePropertyReadState::VALUE) {
		// 親の長さ不整合を既知の別親に置き換えない
		if( result.parent.size() >= MAXIMUM_DEVICE_INSTANCE_CHARACTERS) {
			parent = propertyFailure( ERROR_INVALID_DATA) ;
			result.parent.clear() ;
		} else {
			result.parent = normalizeIdentifier( result.parent) ;
		}
	}

	result.parentState		= parent.state ;
	result.parentDiagnostic = nativeErrorFromWin32( parent.diagnostic.code) ;
	// 正規の空リスト、正式不在と取得失敗を区別したまま、元の順序でIDを保持する
	result.hardwareIdsDiagnostic =
		readIndexIds( devices, node, DEVPKEY_Device_HardwareIds, api, result.hardwareIds) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全セットアップクラスの現在機器から元登録属性を有界に読み取る
 * @param[in] mode ストレージまたはDisplayの元登録条件と取得する追加属性の範囲
 * @param[out] result 全present機器の属性と個別の未確認理由。列挙失敗時は空
 * @return IDと列挙終端が確認できた場合0、母集合の不明や途中失敗はHRESULT
 * @note 個別のINFまたはサービス属性の失敗は機器自体を分母から除かない
 */
//------------------------------------------------------------------------------
NativeError readPresentDevicePeerRegistrations( const PresentDevicePeerMode				   mode,
											   std::vector<PresentDevicePeerRegistration> &result)
{
	result.clear() ;
	const auto	 &api = driver_store_inf_detail::transport().inventory ;	// 同一workerの元属性照会
	DeviceInfoSet devices( api.open( nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT),
						  api) ;	// 関連サービスに限定しない現在の全機器
	// 全体の列挙を開始できなければ個別の未確認とは別の失敗を返す
	if( !devices.valid()) {
		const auto native = GetLastError() ;	// 情報集合生成の元診断
		return nativeErrorFromWin32( native ? native : ERROR_INVALID_DATA) ;
	}

	// 既存の単一ブート署名検査が扱うWindowsセットアップクラス
	constexpr GUID SCSI_ADAPTER{
		0x4d36e97b, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
	const bool display = mode == PresentDevicePeerMode::DISPLAY ;	// Display専用の読取を行う有効範囲
	std::vector<PresentDevicePeerRegistration> made ;				// 末尾の完全性を確認するまで保持
	// 既存機器列挙と同じ上限を使い、上限ちょうどでも終端を確認する
	for( DWORD index = 0U; index <= MAXIMUM_DEVICES; ++index) {
		SP_DEVINFO_DATA node{} ;	// 同じ情報集合の一機器
		node.cbSize = sizeof( node) ;
		// 終端以外の元診断から、有効な全一覧を作らない
		if( !api.enumerate( devices.get(), index, &node)) {
			const auto native = GetLastError() ;	// Windowsが返す終端または列挙失敗
			// 元のAPIの終端を確認した場合だけ収集した母集合を使う
			if( native != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( native ? native : ERROR_INVALID_DATA) ;
			}

			break ;
		}

		// 上限を超えた対象を一覧に載せられない場合に部分集合を返さない
		if( index == MAXIMUM_DEVICES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		auto	  &entry = made.emplace_back() ;	// 個別の失敗でも分母に残す同一機器
		// 元機器の完全IDと属性取得の診断
		const auto identity = readObservedInstanceId( devices.get(), node, entry.instance, api) ;
		// 所属一覧と照合できない機器を推測で別識別子へ置き換えない
		if( identity.state != DevicePropertyReadState::VALUE) {
			return nativeErrorFromWin32( identity.diagnostic.code ? identity.diagnostic.code
																 : ERROR_NO_SUCH_DEVINST) ;
		}

		entry.instance	   = normalizeIdentifier( entry.instance) ;
		entry.storageClass = IsEqualGUID( node.ClassGuid, SCSI_ADAPTER) != FALSE ;
		// SoftwareComponentの親関係とIDの不明を全機器の登録失敗とは別に保持する
		if( display && IsEqualGUID( node.ClassGuid, GUID_DEVCLASS_SOFTWARECOMPONENT)) {
			entry.softwareComponent = readDisplayPeerComponentProperties( devices.get(), node, api) ;
		}

		auto	  &registered = entry.registration ;	// このノードが示す現在の元属性
		// 同じ現用機器に属する関連サービスの属性
		const auto service = readObservedDeviceString( devices.get(), node, DEVPKEY_Device_Service,
													  registered.service, api) ;
		// 同じ機器の公開INF。サービスが不明でも診断と名前は維持する
		const auto inf = readObservedDeviceString( devices.get(), node, DEVPKEY_Device_DriverInfPath,
												  registered.selection.publishedInf, api) ;
		entry.serviceKnown = service.state == DevicePropertyReadState::VALUE ||
							 service.state == DevicePropertyReadState::NOT_PRESENT ||
							 (display && service.state == DevicePropertyReadState::EMPTY) ;
		// Displayでは型付き空値と正式不在を再観測時にも区別する
		if( display) {
			entry.serviceState = service.state ;
		}

		entry.noDriver = service.state == DevicePropertyReadState::NOT_PRESENT &&
						 inf.state == DevicePropertyReadState::NOT_PRESENT ;
		const bool acceptedService =
			service.state == DevicePropertyReadState::VALUE ||
			(display && entry.serviceKnown) ;	// 元登録に使える関連サービス属性
		// 正式未導入以外では確認できたINFと現在の実節を必要とする
		if( !entry.noDriver && (!acceptedService || inf.state != DevicePropertyReadState::VALUE)) {
			// Displayで受理したサービスの正式不在はINFの読取失敗を隠さない
			const auto reason = (!display || !acceptedService) && service.diagnostic.code
									? service.diagnostic.code
									: inf.diagnostic.code ;
			entry.diagnostic  = nativeErrorFromWin32( reason ? reason : ERROR_NOT_FOUND) ;
		}
		// 一意な現在登録がある場合にだけWindowsの実節と装飾を取得する
		else if( !entry.noDriver) {
			InstalledStorageInfSelection section ;	// 元の公開INFとの一致まで保持する節
			entry.diagnostic = readInstalledStorageInfSelection( devices.get(), node, api, section) ;
			// 先に取得したINFと矛盾する元節を同じ機器に結び付けない
			if( entry.diagnostic == 0U &&
			   normalizeIdentifier( section.publishedInf) ==
				   normalizeIdentifier( registered.selection.publishedInf)) {
				registered.selection = std::move( section) ;
			}
			// 元診断がなく公開名だけが変わった場合は追加の再観測が必要
			else if( entry.diagnostic == 0U) {
				entry.diagnostic = nativeErrorFromWin32( ERROR_RETRY) ;
			}
		}
	}

	std::ranges::sort( made, {}, &PresentDevicePeerRegistration::instance) ;
	// 同じ識別子を二件の互いに独立な証拠として数えない
	if( std::ranges::adjacent_find( made, {}, &PresentDevicePeerRegistration::instance) !=
	   made.end()) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	result = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 従来のストレージ照合に使う全現在機器の元登録を読み取る
 * @param[out] result 全present機器の属性と個別の未確認理由。列挙失敗時は空
 * @return 全識別子と列挙終端が確認できた場合0、母集合の不明や途中失敗はHRESULT
 * @note 現在INFのある機器では関連サービスの非空値を要求する
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerPeerRegistrations( std::vector<StoragePowerPeerRegistration> &result)
{
	return readPresentDevicePeerRegistrations( PresentDevicePeerMode::STORAGE_POWER, result) ;
}

/** @brief 現用または依存INFの指定実節を読んだ結果 */
struct DisplayPeerInfRead {
	/// 同じ元ファイルの正式位置、保護及び全ハッシュ
	ProtectedExecutableSnapshot file ;
	/// 同じ元INFの選択節または全節の読取り結果
	DisplayInfUse				scope ;
	/**
	 * @brief 別の読み取りでINFの元ファイルと作用が同じか確認する
	 * @param[in] other 元の実節または依存INFの独立観測
	 * @return ファイルと作用が一致した場合true
	 */
	bool						operator==( const DisplayPeerInfRead &other) const = default ;
} ;
} // namespace

/** @brief 検査済みType 1の同じクラスとPnP到達先を二度読んだ証拠 */
struct DisplayType1Reachability {
	/// 同じ元制御セットと保護された元クラス登録
	DisplayType1ClassSnapshot				 classes ;
	/// 同じ元実行物の検索条件で現在機器から確認した親子
	DisplayType1Topology					 topology ;
	/// 同じDisplayの保護された親レジストリを読むWindows Driver属性
	std::wstring							 parentDriver ;
	/// 同じ親と共有箇所にある元の作用対象値と保護
	DisplayType1RegistrySnapshot			 registry ;
	/// 選択した同じ署名付き子INFの元宣言と非Storeの全コピー指定
	OfficialType1Registration				 registration ;
	/// 同じ順の正規共有先と実ファイルの保護、元内容または正式不在
	std::vector<ProtectedExecutableSnapshot> sharedFiles ;
	/// 旧登録値が現用子を参照し、元旧マーカーも不在の場合true
	bool									 currentChildReferencesMatch{} ;
	/**
	 * @brief 同じ選択の到達先を別の観測と比較する
	 * @param[in] other 同じ選択について独立に再読取りした証拠
	 * @return 元クラス、到達先、元親と保護された作用対象値・共有ファイルが一致する場合true
	 */
	bool operator==( const DisplayType1Reachability &other) const = default ;
} ;

/** @brief 一つの署名候補に対する現用Display補助サービスの所有と共用の証拠 */
struct DisplayAuxiliaryOwnershipProof {
	/// 同じ現用親の正規公開INF、Store元INF、CATの保護順
	std::array<ProtectedExecutableSnapshot, 3U>							parentFiles ;
	/// Windowsの現用補助サービスの設定、保護、同じ署名配布に属する実行先
	DisplayAuxiliaryServiceObservation									service ;
	/// 同じ現用宣言によるApplicationイベント源の保護と観測
	DisplayApplicationEventSnapshot										event ;
	/// 対象の子が存在する場合の公開INF、Store元INF、CATの保護順
	std::optional<std::array<ProtectedExecutableSnapshot, 3U>>			childFiles ;
	/// 元実行物の検査が一致した場合のクラスと到達先。通常は空
	std::optional<DisplayType1Reachability>								type1 ;
	/// 同じ対象と共用可能性を照合した現在機器の母集合。worker内限定
	std::vector<PresentDevicePeerRegistration>							devices ;
	/// 正規公開INF葉と実節で一意な保護と作用。依存と拡張の全節は実節なし
	std::map<std::pair<std::wstring, std::wstring>, DisplayPeerInfRead> infs ;
	/**
	 * @brief 同じ候補について読み直した現在所有を比較する
	 * @param[in] other 同じ選択の独立観測
	 * @return 全ての機器・INF・共有先と変更対象の状態に差がなければtrue
	 */
	bool operator==( const DisplayAuxiliaryOwnershipProof &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 選択Displayの必須子と同じ元宣言だけを内容範囲の再照合へ渡す
 * @param[in] proof 同じ親と現用所有・到達先を確認した証拠
 * @param[in] selected 再照合する同じ元選択の必須子
 * @return 同じ元INFと選択節を持つ既知の宣言への借用。別の選択ではnullptr
 * @note 参照は証拠の所有者より長く保持できない。実行許可を発行しない
 */
//------------------------------------------------------------------------------
const OfficialType1Registration *reviewedDisplayType1Registration(
	const DisplayAuxiliaryOwnershipProof &proof, const OfficialInfPackage &selected) noexcept
{
	// 所有の読取りだけでは、補助実行物の到達先を確認した証拠にならない
	if( !proof.type1) {
		return nullptr ;
	}

	const auto &registration = proof.type1->registration ;	// この親に結合した同じ選択子の元宣言
	return registration.infRelativePath == selected.infRelativePath &&
				   registration.basicSection == selected.selectedBasicSection &&
				   registration.installSection == selected.selectedInstallSection
			   ? &registration
			   : nullptr ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 現用Displayの所有確認で止まった箇所を示す非機密の診断
 */
//------------------------------------------------------------------------------
enum class DisplayOwnershipObservation : std::uint32_t {
	/// 現在機器の母集合
	PRESENT = 1,
	/// 現用親の選択と署名
	PARENT,
	/// 同じWin32サービスを使う現在機器の所属
	ASSOCIATED,
	/// 現用INFの読取りと作用の共用
	PEER_INF,
	/// 現用子の親関係、主ID、署名または候補子との結合
	CHILD,
	/// 公開領域の拡張INFの列挙
	EXTENSIONS,
	/// 依存と拡張の全節
	DEPENDENCIES,
	/// SCMと実行ファイルの所有
	SCM,
	/// 現用Applicationイベント源
	EVENT,
	/// 照合後の現在機器の再読取り
	PRESENT_AGAIN,
	/// 候補子の直接関係、実選択と限定作用
	CANDIDATE_CHILD,
	/// 検査済みType 1のクラスと現在の全到達先
	TYPE1_PATH,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 実行物と既知の探索条件に照合し、署名付き現用子と一台の親への到達を観測する
 * @param[in] inspection 同じ公式元配布の保護領域と署名閉包
 * @param[in] candidate 同じ候補の選択済み子INF
 * @param[in] device 同じ現用子のWindows属性
 * @param[in] parentInstance 同じ候補の選択親の正規化済みWindows ID
 * @param[in] current 同じ現用子の保護付き元署名パッケージ
 * @param[out] reachability 既知の構文と現在の範囲が成立した場合だけ保持する
 * @return 既知の観測成功か未分類で0、既知実行物の元条件又は範囲が不成立ならHRESULT
 * @note 未分類時は証拠を付与しない。配布元、共有値、共有ファイルと実行確認は別途必要
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1Reachability( const CommonInfInspection				  &inspection,
										 const OfficialInfPackage				  &candidate,
										 const PresentDevicePeerRegistration	  &device,
										 const std::wstring						  &parentInstance,
										 const RegisteredSoftwareComponentPackage &current,
										 std::optional<DisplayType1Reachability>  &reachability)
{
	reachability.reset() ;
	constexpr std::wstring_view REVIEWED_SHA256 =
		L"D340C0A33BFC06C8B52B46A49EDC37E116379E05AADC6394233BD3347ED828B4" ;	// 公式26.11.2で内容を検査した実行物
	constexpr std::array families{
		std::wstring_view{L"SWC\\AMDOCL"}, std::wstring_view{L"SWC\\AMDOGL"},
		std::wstring_view{L"SWC\\AMDVLK"}} ;	// 同じ実行物が走査する条件の閉集合
	OfficialType1Registration program ;			// 同じ子INFと完全バイトを照合した元実行物
	const auto				  read = readSelectedOfficialType1Registration(
		   *inspection.workspace, inspection.closure.entries, candidate,
		   program) ;	// 同じ保護領域と実節からの読み取り
	// 未分類の内容にはこの観測を付与せず、後段の既存判定に委ねる
	if( read != 0U || normalizeIdentifier( program.binarySha256) != REVIEWED_SHA256) {
		return 0U ;
	}

	// 同じ実行物でも、静的に確認した引数と子単位指定を別構成へ読み替えない
	if( !program.perDevice || program.softwareName != L"AMDOCLComponent" ||
	   program.softwareVersion != L"25.10.243.11107" || program.arguments.size() != 1U ||
	   program.arguments.front() != L"x") {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	DisplayType1Reachability observed ;										// 二度の読み取りが揃うまで返さない範囲
	DisplayType1Reachability fresh ;										// 途中変更を確認する独立した読み取り
	const auto				&api = driver_store_inf_detail::transport() ;	// 同じworkerの端末照会
	DeviceInfoSet devices( api.create( nullptr, nullptr)) ;					// 同一の選択親だけを開く情報集合
	// 正式なWindows選択親から作用先を取得できない場合は範囲未確認とする
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA parent{} ;	// 選択親のSetupAPI属性
	parent.cbSize = sizeof( parent) ;
	// 固定クラス番号を仮定せず同じ機器を開き直す
	if( !api.open( devices.get(), parentInstance.c_str(), nullptr, 0U, &parent)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// クラス、PnP、親と共有先の値を順に読み、同じ状態を二度照合する
	for( auto *proof : {&observed, &fresh}) {
		auto error = readDisplayType1ClassSnapshot( proof->classes) ;	// 同じWindowsの正式クラス登録
		// 全クラスの母集合が分かった場合だけ現在の到達先を読む
		if( error == 0U) {
			error = readDisplayType1Topology( families, proof->topology) ;
		}

		// 両方の観測から同じ現用子・親へ一意に結ぶ
		if( error == 0U) {
			error = verifyDisplayType1ParentBinding( proof->classes, proof->topology, families,
													parentInstance, device.instance,
													device.softwareComponent->hardwareIds.front(),
													current.storeInf, proof->parentDriver) ;
		}

		// 正式な親と同じ制御セットで保護された値と正式不在を確認する
		if( error == 0U) {
			error = readDisplayType1RegistrySnapshot( devices.get(), parent, proof->registry) ;
		}

		// 読み取り失敗や共有を一台の選択へ補わない
		if( error != 0U) {
			return error ;
		}

		// 制御セット、Driver属性又は保護の結合が変わった観測は保存しない
		if( proof->registry.controlSet != proof->classes.controlSet ||
		   normalizeIdentifier( proof->registry.driverKey) !=
			   normalizeIdentifier( proof->parentDriver)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// 共有先は署名が示す元コピー位置からだけ解決し、全宛先を保護付きで読む
		for( const auto &copy : program.sharedCopies) {
			// 既知のWindows共有配置を他のDIRIDや任意フォルダへ広げない
			if( copy.dirid != 11 && copy.dirid != 10) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			ProtectedExecutableSnapshot file ;	// 同じ宛先の保護と現在の全ハッシュ
			error = readWindowsSharedDriverFileSnapshot( copy.target, copy.dirid == 10, file) ;
			// 正式不在と読めない宛先を混同しない
			if( error != 0U) {
				return error ;
			}

			proof->sharedFiles.push_back( std::move( file)) ;
		}
	}

	// 途中で別の到達先や登録に変わった場合は所有を引き継がない
	if( observed != fresh) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const auto childDirectory			 = current.storeInf.substr( 0U,
																   // 署名と照合した現用子の正規Storeの親
																   current.storeInf.rfind( L'\\') + 1U) ;
	observed.currentChildReferencesMatch = matchesDisplayType1ReflectedRegistry(
		observed.registry, childDirectory + L"amdocl64.dll", childDirectory + L"amdocl32.dll") ;
	observed.registration = std::move( program) ;
	reachability		  = std::move( observed) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定適用後の同じ署名付き必須子を元操作のWindows実行記録へ結ぶ
 * @param[in] before 同じ導入操作の最初の変更より前に確認したイベント境界
 * @param[in] reviewed 同じ親子の元Type 1宣言と導入前の制御セット・共有配置
 * @param[in] selected 同じ導入が選んだ子の実節と署名済みファイルの構成
 * @param[in] entries 同じ公式配布の署名確認済み元閉包
 * @param[in] registeredInf 同じ導入が変更非共有で保持する選択子の登録INF
 * @param[in] parentInstance 今回指定した親の完全ID
 * @param[in] parentBeforeChild 親の指定導入後かつ子の指定導入前の現在観測
 * @param[in] childInstance 同じ親の必須子として一意に選んだ完全ID
 * @param[in] hardwareIds 署名済みの親が要求する同じ子のHardware ID
 * @return 同じ操作へ照合した実行と反映状態。元署名、親子またはログを取得できない場合は未確認
 * @note 読取り専用。実行完了を確認してから親の登録と共有先の結果を照合する
 */
//------------------------------------------------------------------------------
DisplayType1InstallResult observeAppliedDisplayType1(
	const DisplayType1EventBoundary &before, const DisplayType1Reachability &reviewed,
	const OfficialInfPackage &selected, std::span<const OfficialZipEntry> entries,
	const std::wstring &registeredInf, const std::wstring &parentInstance,
	const DeviceRankSnapshot &parentBeforeChild, const std::wstring &childInstance,
	const std::span<const std::wstring> hardwareIds)
{
	try {
		const auto	   &registration = reviewed.registration ;			// この導入が選んだ同じ実行物と元宣言
		const auto	   &api = driver_store_inf_detail::transport() ;	// 同じworkerのWindows照会
		DeviceInfoSet	devices( api.create( nullptr, nullptr)) ;		// 現在の同じ子だけを開く集合
		SP_DEVINFO_DATA child{} ;										// 同じWindows子の読み取り属性
		child.cbSize = sizeof( child) ;
		// 開けない子を導入済みの子の代わりに使わない
		if( !devices.valid() ||
		   !api.open( devices.get(), childInstance.c_str(), nullptr, 0U, &child)) {
			return {DisplayType1InstallState::UNCONFIRMED, nativeErrorFromWin32( GetLastError())} ;
		}

		std::vector<std::byte> present ;	// Windowsが現在も存在すると示す型付き値
		// 同じ子の現在存在を示す元属性の読み取り結果
		const auto presence = readObservedProperty( devices.get(), child, DEVPKEY_Device_IsPresent,
												   DEVPROP_TYPE_BOOLEAN, present, api.inventory) ;
		// 取り外し後に残った登録を今回の現用子として扱わない
		if( presence.state != DevicePropertyReadState::VALUE ||
		   present.size() != sizeof( DEVPROP_BOOLEAN) ||
		   present.front() != static_cast<std::byte>( DEVPROP_TRUE)) {
			return {DisplayType1InstallState::UNCONFIRMED,
					nativeErrorFromWin32( presence.diagnostic.code ? presence.diagnostic.code
																  : ERROR_NO_SUCH_DEVINST)} ;
		}

		std::wstring parent ;	// 子の現在の親属性
		const auto	 parentRead = readObservedDeviceString(
			  // 現在の型付き属性
			  devices.get(), child, DEVPKEY_Device_Parent, parent, api.inventory) ;
		const auto ids = readDeviceStringList(
			// 同じ子の現在のHardware ID
			devices.get(), child, DEVPKEY_Device_HardwareIds) ;
		// 前の親子を保証済みと扱わず、現在も選択した親の元IDに対応する場合だけ進む
		if( parentRead.state != DevicePropertyReadState::VALUE ||
		   normalizeIdentifier( parent) != normalizeIdentifier( parentInstance) || ids.size() != 1U ||
		   std::ranges::none_of( hardwareIds, [&]( const auto &id) {
			   return normalizeIdentifier( id) == normalizeIdentifier( ids.front()) ;
		   })) {
			return {DisplayType1InstallState::UNCONFIRMED, nativeErrorFromWin32( ERROR_RETRY)} ;
		}

		InstalledStorageInfSelection selection ;	// 現在の子の公開INFと実節
		auto error = readInstalledStorageInfSelection( devices.get(), child, api.inventory,
													  selection) ;	// Windowsが現に使用する元位置
		// 今回登録した公開名と異なる同版・旧子を今回の導入へ結び付けない
		if( error != 0U || registeredInf.empty() ||
		   normalizedFileName( registeredInf) != normalizeIdentifier( selection.publishedInf)) {
			return {DisplayType1InstallState::UNCONFIRMED,
					error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY)} ;
		}

		RegisteredSoftwareComponentPackage applied ;	// 署名済みのStore元INFと実節
		error = readRegisteredSoftwareComponentPackage(
			selection.publishedInf, selection.basicSection,
			selection.sectionExtension.value_or( L""), ids.front(), applied) ;

		const auto separator = applied.storeInf.rfind( L'\\') ;	// 正規Store元INFの親
		const auto catalog	 = std::ranges::find_if( entries, [&]( const auto &entry) {
			  return CompareStringOrdinal( entry.relativePath.c_str(), -1,
										  selected.catalogRelativePath.c_str(), -1,
										  TRUE) == CSTR_EQUAL ;
		  }) ; // 選択した子が所有する元CATと完全バイトの証拠
		// 旧INFや別の元CATの現在子を今回の実行物に付け替えない
		if( error != 0U || catalog == entries.end() || separator == std::wstring::npos ||
		   normalizeIdentifier( applied.installedSection) !=
			   normalizeIdentifier( registration.installSection) ||
		   !applied.storeFile.existing || !applied.catalogFile.existing ||
		   normalizeIdentifier( applied.storeFile.existing->sha256) !=
			   normalizeIdentifier( registration.infSha256) ||
		   applied.catalogFile.existing->bytes != catalog->uncompressedSize ||
		   normalizeIdentifier( applied.catalogFile.existing->sha256) !=
			   normalizeIdentifier( catalog->sha256)) {
			return {DisplayType1InstallState::UNCONFIRMED,
					error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY)} ;
		}

		const auto directory =
			// 同じ署名付き子の登録先
			applied.storeInf.substr( 0U, separator + 1U) ;
		const auto binary = directory + registration.softwareBinary ;	// 元宣言の正規Store完全位置
		ProtectedExecutableSnapshot executable ;						// 同じ正規Store内の保護された実行物
		error = readRegisteredDriverStoreExecutableSnapshot( binary, binary, executable) ;
		// 元署名で確認したファイルと異なる実体をコマンド照合に使わない
		if( error != 0U || !executable.existing ||
		   executable.existing->bytes != registration.binaryBytes ||
		   normalizeIdentifier( executable.existing->sha256) !=
			   normalizeIdentifier( registration.binarySha256)) {
			return {DisplayType1InstallState::UNCONFIRMED,
					error != 0U ? error : nativeErrorFromWin32( ERROR_CRC)} ;
		}

		auto observed = observeDisplayType1InstallEvents(
			before, {0U, false, registration.softwareName, binary, registration.arguments,
					 childInstance, true, false, false}) ;	// 同じ実行の終了と元失敗の確認
		// 照合済みの完了より前の共有ファイルや親の登録を反映証拠にしない
		if( observed.state != DisplayType1InstallState::REFLECTION_PENDING) {
			return observed ;
		}

		const auto shared = verifyDisplayType1SharedCopies(
			registration.sharedCopies, reviewed.sharedFiles,
			readWindowsSharedDriverFileSnapshot) ;	// 実行終了を観測した後の共有コピー

		RegisteredDriverStorePackage   pinned ;	// 親の値を照合する間、子の署名閉包を読取り保持する
		const DriverStorePackageLookup lookup{api.windowsDirectory,
											  api.storageStoreLocation} ;	// 同じ登録先の照会
		const auto		 native = directory + L"amdocl64.dll" ;				// 64ビット実装の元実行物による登録先
		const auto		 wow	= directory + L"amdocl32.dll" ;				// 32ビット実装の元実行物による登録先
		const std::array members{native, wow, binary} ;						// 保持を要求する元閉包内の三点
		SP_DEVINFO_DATA	 selectedParent{} ;									// 同じ選択親の読み取り属性
		selectedParent.cbSize = sizeof( selectedParent) ;
		const auto parentOpen = api.open( devices.get(), parentInstance.c_str(), nullptr, 0U,
										 &selectedParent) ;	// 別の親や登録番号を探索しない
		std::vector<std::byte>		 parentPresent ;		// 親の型付き現在存在属性
		DisplayType1RegistrySnapshot registry ;				// 同じ親の現用キーから得た実値と旧値
		DeviceRankSnapshot			 parentAfter ;			// 値の照合後も同じ親の登録であるかの観測
		const bool					 registryReflected =
			parentOpen &&
			readObservedProperty( devices.get(), selectedParent, DEVPKEY_Device_IsPresent,
								 DEVPROP_TYPE_BOOLEAN, parentPresent, api.inventory)
					.state == DevicePropertyReadState::VALUE &&
			parentPresent.size() == sizeof( DEVPROP_BOOLEAN) &&
			parentPresent.front() == static_cast<std::byte>( DEVPROP_TRUE) &&
			pinned.pinFromClosure( registeredInf, selected, entries, lookup) == 0U &&
			pinned.containsPinnedMembers( applied.storeInf, members) &&
			readDisplayType1RegistrySnapshot( devices.get(), selectedParent, registry) == 0U &&
			registry.controlSet == reviewed.registry.controlSet &&
			matchesDisplayType1ReflectedRegistry( registry, native, wow) &&
			readDeviceRankSnapshot( parentInstance, parentAfter) == 0U &&
			parentAfter.driverKeyRead.state == DevicePropertyReadState::VALUE &&
			normalizeIdentifier( parentAfter.driverKey) == normalizeIdentifier( registry.driverKey) &&
			deviceRankSnapshotsEqual( parentBeforeChild, parentAfter) &&
			// 欠落・未知・元親の変更は反映待ちのままにする
			pinned.verify() == 0U ;

		InstalledStorageInfSelection fresh ;	// 値と元ファイルの照合後の同じ子の現用登録
		const auto					 freshParent = readObservedDeviceString(
			  // 親子の現在結合
			  devices.get(), child, DEVPKEY_Device_Parent, parent, api.inventory) ;
		const auto freshPresence = readObservedProperty(
			devices.get(), child, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN, present,
			api.inventory) ;	// 途中の取り外しを確認
		// 読取り中の親子の変更や他のINFへの切替を反映証拠にしない
		if( freshParent.state != DevicePropertyReadState::VALUE ||
		   normalizeIdentifier( parent) != normalizeIdentifier( parentInstance) ||
		   freshPresence.state != DevicePropertyReadState::VALUE ||
		   present.size() != sizeof( DEVPROP_BOOLEAN) ||
		   present.front() != static_cast<std::byte>( DEVPROP_TRUE) ||
		   readInstalledStorageInfSelection( devices.get(), child, api.inventory, fresh) != 0U ||
		   fresh != selection) {
			return {DisplayType1InstallState::UNCONFIRMED, nativeErrorFromWin32( ERROR_RETRY)} ;
		}

		// 実行完了後の一台の必須子、親と共有先が全て確定した場合だけ反映済みとする
		if( registryReflected && shared == S_OK) {
			observed.state = DisplayType1InstallState::REFLECTED ;
		}

		// 事後の読取失敗は元診断として返し、指定導入APIやWindows実行の失敗に置き換えない
		if( FAILED( shared)) {
			observed.error = shared ;
		}

		return observed ;
	} catch( const std::bad_alloc &) {
		return {DisplayType1InstallState::UNCONFIRMED, E_OUTOFMEMORY} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現用の共用候補一件を同じ署名計画の直接必須子として検査する
 * @param[in] inspection 候補の署名検査済みINFを所有する保護領域と閉包
 * @param[in] packages 候補の選択済み親子
 * @param[in] parent 現用親の署名付き元選択
 * @param[in] parentInstance 同じ現用親の正規化済みWindowsインスタンスID
 * @param[in] device 共用候補の現在の読取り情報
 * @param[in] target 同じ候補Displayが宣言する補助サービス
 * @param[out] files 成功時の公開INF、Store元INF、CATの保護と全ハッシュ。失敗時は空
 * @param[out] type1 既知Type 1実行物の到達先の観測。未分類または失敗時は空
 * @param[in,out] observation 候補側の照合開始時に更新する非機密の段階
 * @return 現用子と候補子が一意で署名元が確認できた場合0、その他はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readDisplayPeerChild(
	const CommonInfInspection &inspection, std::span<const OfficialInfPackage> packages,
	const RegisteredDisplayAuxiliaryPackage &parent, const std::wstring &parentInstance,
	const PresentDevicePeerRegistration &device, const OfficialDisplayAuxiliaryService &target,
	std::optional<std::array<ProtectedExecutableSnapshot, 3U>> &files,
	std::optional<DisplayType1Reachability> &type1, DisplayOwnershipObservation &observation)
{
	// 既に一件を確認した場合と別の機器の共有は同じ作用に含めない
	if( files || !device.softwareComponent) {
		return nativeErrorFromWin32( ERROR_SHARING_VIOLATION) ;
	}

	const auto &relation = *device.softwareComponent ;	// 型付きWindows親と主IDの元属性
	// 同じ親の一つの現在子であることをWindowsの属性で確認する
	if( relation.parentState != DevicePropertyReadState::VALUE ||
	   relation.parent != parentInstance || relation.hardwareIdsDiagnostic != 0U ||
	   relation.hardwareIds.size() != 1U) {
		return nativeErrorFromWin32( ERROR_SHARING_VIOLATION) ;
	}

	const auto &id		 = relation.hardwareIds.front() ;	// 現用子の一意な主ID
	const auto &selected = device.registration.selection ;	// 現用子の署名照合に使うWindowsの実節
	RegisteredSoftwareComponentPackage child ;				// 現用子の正規登録と同じCAT
	auto							   error = readRegisteredSoftwareComponentPackage(
		  selected.publishedInf, selected.basicSection, selected.sectionExtension.value_or( L""), id,
		  child) ;									// 同じ子の署名と実選択の診断
	const OfficialInfPackage *candidate = nullptr ;	// 同じ現用子に結び付いた選択済み候補
	// 現用子が署名・主IDへ結び付いた場合だけ候補の同じ子を照合する
	if( error == 0U) {
		observation = DisplayOwnershipObservation::CANDIDATE_CHILD ;
		error = verifyDisplayPeerCandidateChild( *inspection.workspace, parent.components, packages,
												id, target, &candidate) ;
	}

	// 元宣言と現在署名の成立後だけ、既知実行物が実際に探索する範囲へ結ぶ
	if( error == 0U) {
		// 一意な候補の返却を確認してから署名実行物の観測に渡す
		if( !candidate) {
			return E_UNEXPECTED ;
		}

		observation = DisplayOwnershipObservation::TYPE1_PATH ;
		error = readDisplayType1Reachability( inspection, *candidate, device, parentInstance, child,
											 type1) ;
	}

	// 両方の子の元情報が確認できた場合だけ証拠を保存する
	if( error == 0U) {
		files.emplace( std::array{std::move( child.publishedFile), std::move( child.storeFile),
								 std::move( child.catalogFile)}) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 列挙した全現在機器から同じ現用Displayの補助サービスの所有と共用を確かめる
 * @param[in] inspection 選択元の署名と元ファイルを保持する検査結果
 * @param[in] packages 同じ選択の親と全必要INF。先頭は選択親
 * @param[in] instanceId 同じ候補が適合した現在の選択親
 * @param[in] expectedInf 元の候補適合性で観測した現用親の公開INF
 * @param[in] target 候補の選択節から確認した同名サービスとイベント源
 * @param[in] devices 同じWindowsの全現在機器の取得済み属性。この照会が所有する
 * @param[out] result 現用の署名・全現在機器と作用の証拠。失敗時は空
 * @param[out] observation 元デバイス情報を含まない現在の照合段階
 * @return 所有と対象範囲の確認成功で0、その他HRESULT
 * @note 読取専用。候補の必要ソフトウェアの実行範囲は別途確認が必要
 */
//------------------------------------------------------------------------------
NativeError inspectDisplayAuxiliaryOwnership(
	const CommonInfInspection &inspection, std::span<const OfficialInfPackage> packages,
	const std::wstring &instanceId, std::wstring_view expectedInf,
	const OfficialDisplayAuxiliaryService				  &target,
	std::vector<PresentDevicePeerRegistration>			   devices,
	std::shared_ptr<const DisplayAuxiliaryOwnershipProof> &result,
	DisplayOwnershipObservation							  &observation)
{
	result.reset() ;
	observation			= DisplayOwnershipObservation::PARENT ;
	const auto parentId = normalizeIdentifier( instanceId) ;			// 同じ候補で固定された秘密PnP親
	auto made = std::make_shared<DisplayAuxiliaryOwnershipProof>() ;	// 全照合まで外に渡さない証拠
	made->devices = std::move( devices) ;
	const auto selected =
		std::ranges::lower_bound( made->devices, parentId, {},
								 &PresentDevicePeerRegistration::instance) ;	// 現在観測での選択親
	// 不明な親、新規登録または選択後に現用INFが変化した機器は同じ更新として扱わない
	if( selected == made->devices.end() || selected->instance != parentId || selected->noDriver ||
	   selected->diagnostic != 0U ||
	   normalizeIdentifier( selected->registration.selection.publishedInf) !=
		   normalizeIdentifier( expectedInf)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const auto &registration = selected->registration ;	// 選択親の現用INF、実節とカーネル関連名
	const auto &inf			 = registration.selection ;	// 同じ元の公開INFと実節
	RegisteredDisplayAuxiliaryPackage parent ;			// 保護位置の現用親、CATと元宣言
	auto							  error = readRegisteredDisplayAuxiliaryPackage(
		 inf.publishedInf, inf.basicSection, inf.sectionExtension.value_or( L""),
		 registration.service, target, parent) ;	// 現用親の元照合結果
	// 現用親の実署名と元宣言が成立しないときは共有先の変更を許可しない
	if( error != 0U) {
		return error ;
	}

	observation = DisplayOwnershipObservation::ASSOCIATED ;
	std::vector<std::wstring> members ;	// Windowsが同じ名前に直接関係付けた現在機器
	error = readStorageRelatedDeviceIds( target.serviceName, members) ;
	// 補助Win32サービスを現在機器の関連サービスとしても使うケースは別用途になる
	if( error != 0U || !members.empty()) {
		return error ? error : nativeErrorFromWin32( ERROR_SHARING_VIOLATION) ;
	}

	std::set<std::wstring> dependencies ;	// 同じWindowsの全参照先を重複なく検証する待ち集合
	// 同一INFの別個体も共用主体として別々に確認し、構文の読取だけを共有する
	for( const auto &device : made->devices) {
		observation = DisplayOwnershipObservation::PEER_INF ;
		// 明示的な未登録だけを対象INFなしと判断する
		if( device.noDriver) {
			continue ;
		}

		// 未確認の現用INFや同じサービスへの直接関連を共有なしに変換しない
		if( device.diagnostic != 0U || normalizeIdentifier( device.registration.service) ==
										  normalizeIdentifier( target.serviceName)) {
			return device.diagnostic ? device.diagnostic
									 : nativeErrorFromWin32( ERROR_SHARING_VIOLATION) ;
		}

		const auto &location = device.registration.selection ;	// 同じ現在機器のWindows登録
		const auto	key		 = std::pair{normalizeIdentifier( location.publishedInf),
									 normalizeIdentifier( location.basicSection +
															 // 同じ元INFと実節
															 location.sectionExtension.value_or( L""))} ;
		const auto [position, inserted] =
			// 同じ実節への初回か再利用位置
			made->infs.try_emplace( key) ;
		auto &observed = position->second ;	// 選択節と同じ元バイトの保護観測
		// 新しく見つけた実節だけを読み取り、次の依存先を集める
		if( inserted) {
			error = readPublishedDisplayInfUse( key.first, key.second, target, observed.scope,
											   observed.file) ;
			// 現在機器の未読の宣言を共用なしと判断しない
			if( error != 0U) {
				return error ;
			}

			dependencies.insert( observed.scope.includeFiles.begin(),
								observed.scope.includeFiles.end()) ;
		}

		const auto &scope = observed.scope ;	// 機器に帰属させる同じ選択節の作用
		// 現用親の公開INFで同じ補助・イベントおよび元バイトを再確認する
		if( device.instance == parentId) {
			// 現用親の未知レジストリ作用と、公開INFの途中変更を受理しない
			if( !scope.serviceDeclaration || !scope.applicationEvent || scope.serviceRegistry ||
			   observed.file != parent.publishedFile) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			continue ;
		}

		// 別宣言とイベント源の共有は親子関係であってもこの作用に含めない
		if( scope.serviceDeclaration || scope.applicationEvent ||
		   (scope.serviceRegistry && !scope.scopedChildRegistration)) {
			return nativeErrorFromWin32( ERROR_SHARING_VIOLATION) ;
		}

		// 同じ親の必要子として署名と作用の一意性を確認できた場合だけ限定一値を扱う
		if( scope.scopedChildRegistration) {
			observation = DisplayOwnershipObservation::CHILD ;
			error = readDisplayPeerChild( inspection, packages, parent, parentId, device, target,
										 made->childFiles, made->type1, observation) ;
			// 子の元署名否認と途中での公開側の差を正常な親子へ置き換えない
			if( error != 0U || !made->childFiles || observed.file != made->childFiles->front()) {
				return error ? error : nativeErrorFromWin32( ERROR_RETRY) ;
			}
		}
	}

	observation = DisplayOwnershipObservation::EXTENSIONS ;
	std::vector<std::wstring> extensions ;	// Windows登録済みの同梱およびOEM拡張INF葉
	error = listPublishedExtensionInfs( extensions) ;
	// 読めない拡張集合を現在作用なしへ変えない
	if( error != 0U) {
		return error ;
	}

	dependencies.insert( extensions.begin(), extensions.end()) ;
	observation = DisplayOwnershipObservation::DEPENDENCIES ;
	// 依存と拡張の全節を有界に辿る。同じファイルへ戻っても読み直さない
	while( !dependencies.empty()) {
		const auto leaf = normalizeIdentifier( *dependencies.begin()) ;	// Windows配下の同じ公開INF葉
		dependencies.erase( dependencies.begin()) ;
		// 母集合と依存を合わせた上限に達したら部分結果を公開しない
		if( made->infs.size() >= MAXIMUM_DEVICES || dependencies.size() >= MAXIMUM_DEVICES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		const auto [position, inserted] =
			// 全節を読む元ファイル
			made->infs.try_emplace( std::pair{leaf, std::wstring{}}) ;
		// 循環または既処理の参照から追加の読み取りは行わない
		if( !inserted) {
			continue ;
		}

		auto &observed = position->second ;	// 同じ依存INFの全節と保護
		error = readPublishedDisplayInfUse( leaf, {}, target, observed.scope, observed.file) ;
		// 選択元の分からない依存と拡張には親子の限定一値を適用しない
		if( error != 0U || observed.scope.serviceDeclaration || observed.scope.applicationEvent ||
		   observed.scope.serviceRegistry) {
			return error ? error : nativeErrorFromWin32( ERROR_SHARING_VIOLATION) ;
		}

		dependencies.insert( observed.scope.includeFiles.begin(), observed.scope.includeFiles.end()) ;
	}

	observation = DisplayOwnershipObservation::SCM ;
	error		= readRegisteredDisplayAuxiliaryService( parent, made->service) ;
	// SCMと元実行位置の所有が同じ場合にApplicationの現用登録も照合する
	if( error == 0U) {
		observation = DisplayOwnershipObservation::EVENT ;
		error		= readDisplayApplicationEventSnapshot( parent.declaration, made->event) ;
	}

	// 同じ全現在機器を再読取し、途中着脱と選択・親子の変化を拒否する
	if( error == 0U) {
		observation = DisplayOwnershipObservation::PRESENT_AGAIN ;
		std::vector<PresentDevicePeerRegistration> fresh ;	// 元観測の終端照合
		error = readPresentDevicePeerRegistrations( PresentDevicePeerMode::DISPLAY, fresh) ;
		// 元の読み取りと異なる場合に証拠を発行しない
		if( error == 0U && fresh != made->devices) {
			error = nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 現用署名、全作用と現在機器が同じ候補に結び付いた場合だけ保持する
	if( error == 0U) {
		made->parentFiles = {std::move( parent.publishedFile), std::move( parent.storeFile),
							 std::move( parent.catalogFile)} ;
		result			  = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全現在機器を読み取り、同じ現用Displayの補助サービスの所有を確かめる
 * @param[in] inspection 選択元の署名付き閉包
 * @param[in] packages 同じ選択済み親と全必要INF
 * @param[in] instanceId 同じ候補が適合した現在の選択親
 * @param[in] expectedInf 元の適合性観測で固定した現用親の公開INF
 * @param[in] target 候補の実節から取得した補助サービスとイベント源
 * @param[out] result 成功した同じ現用所有の証拠。失敗時は空
 * @param[out] observation 非機密な照合段階
 * @return 列挙と所有の全成立で0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readDisplayAuxiliaryOwnership(
	const CommonInfInspection &inspection, std::span<const OfficialInfPackage> packages,
	const std::wstring &instanceId, std::wstring_view expectedInf,
	const OfficialDisplayAuxiliaryService				  &target,
	std::shared_ptr<const DisplayAuxiliaryOwnershipProof> &result,
	DisplayOwnershipObservation							  &observation)
{
	result.reset() ;
	observation = DisplayOwnershipObservation::PRESENT ;
	std::vector<PresentDevicePeerRegistration> devices ;	// 終端を確認した全現在機器
	const auto error = readPresentDevicePeerRegistrations( PresentDevicePeerMode::DISPLAY,
														  devices) ;	// 全現在機器の取得診断
	// 列挙失敗から元選択の共用なしを導かない
	if( error != 0U) {
		return error ;
	}

	return inspectDisplayAuxiliaryOwnership( inspection, packages, instanceId, expectedInf, target,
											std::move( devices), result, observation) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正確な関連サービスの所属一覧とpresent機器の確認済み属性を突き合わせる
 * @param[in] service 候補または現用元に属する関連サービス名
 * @param[in] devices 同じ観測の全present機器。識別子の昇順
 * @param[out] result Windowsが示す全所属機器の正規化された昇順。失敗時は空
 * @return 所属一覧が確認済み属性と矛盾しなければ0、その他はHRESULT
 * @note 機器側の属性が未確認であっても、所属を読めた場合は別の観測として残す
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerServiceMembers( const std::wstring							&service,
										   std::span<const StoragePowerPeerRegistration> devices,
										   std::vector<std::wstring>					&result)
{
	result.clear() ;
	std::vector<std::wstring> made ;									// 属性との突合まで外へ出さない元一覧
	const auto error = readStorageRelatedDeviceIds( service, made) ;	// Windowsの所属取得診断
	// 元サービスの一覧失敗を正式な空にしない
	if( error != 0U) {
		return error ;
	}

	// Windowsの識別子の表記差と列挙順を同じ所属へ正規化する
	for( auto &instance : made) {
		instance = normalizeIdentifier( instance) ;
	}

	std::ranges::sort( made) ;
	const auto key = normalizeIdentifier( service) ;	// 機器側の既知関連名と比較する元サービス
	// 同時に確認できた所属と、同一機器から読んだ既知関連名を照合する
	for( const auto &member : made) {
		// 同じ正規化IDで現在一覧の元属性を引く
		const auto found =
			std::ranges::lower_bound( devices, member, {}, &StoragePowerPeerRegistration::instance) ;
		// 列挙母集合にいない機器と、判明している別名への所属を許さない
		if( found == devices.end() || found->instance != member ||
		   (found->serviceKnown && normalizeIdentifier( found->registration.service) != key)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 機器の確定関連名に一致する対象を所属一覧から漏らさない
	for( const auto &device : devices) {
		// 読み取れなかった関連名から所属なしを推定せず、別に残した診断を使う
		if( device.serviceKnown && normalizeIdentifier( device.registration.service) == key &&
		   !std::ranges::binary_search( made, device.instance)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	result = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ現在機器の観測済み属性を署名付き電源宣言へ照合する
 * @param[in] device 外側の全present一覧で確認した同じ機器
 * @param[out] result 成功時の元署名。失敗時は内容を使用しない
 * @return 元登録の署名と電源宣言を確認できれば0、未対応や不一致はHRESULT
 * @note OEMの原本だけを使い、元パッケージと現在SCMの一致を推定しない
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerPeerOrigin( const StoragePowerPeerRegistration &device,
									   RegisteredStoragePackageEvidence	  &result)
{
	return inspectPresentStorageDeviceRegistration(
		device.instance, false, device.registration.selection.publishedInf,
		[&]( const AutomaticStorageDeviceRegistration &original, const auto &, HDEVINFO,
			SP_DEVINFO_DATA &) -> NativeError {
			// 一覧を読んだ時の既知属性とWindowsが同じ機器から返した属性を結ぶ
			if( original != device.registration) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			const auto &selection = original.selection ;	// 同じ機器の署名元の選択
			RegisteredSingleBootStorageEvidence verified ;	// 読取り中だけ所有する元配布
			NativeError							error{} ;	// INFの元と現在の正規登録を確認した診断
			// 同梱NVMeは既存のWindows署名と同じ選択の照合を使う
			if( normalizeIdentifier( selection.publishedInf) == L"STORNVME.INF") {
				RegisteredSingleBootDeviceEvidence current ;	// 既存同梱の保護付き現用証拠
				error = readSingleBootStorageRegisteredEvidence( original, current) ;
				// 同梱を別のOEM元配布で補わない
				if( error != 0U || !current.registered) {
					return error != 0U ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				result = std::move( current.registered->package) ;
				return 0U ;
			}

			// 実Windowsの正引き・逆引きでOEMは元配布と同じ選択だけを検査する
			const DriverStorePackageLookup lookup{&GetSystemWindowsDirectoryW,
												  &SetupGetInfDriverStoreLocationW,
												  &SetupGetInfPublishedNameW} ;
			const auto					   extension =
				selection.sectionExtension
										? std::wstring_view{*selection.sectionExtension}
										: std::wstring_view{} ;	// Windowsが返した元装飾があればそのまま使う
			error = readRegisteredOemSingleBootStorageOrigin( selection.publishedInf,
															 selection.basicSection, extension,
															 original.service, verified, lookup) ;
			// 元配布の読取りが部分的に成立した場合は署名証拠を返さない
			if( error == 0U) {
				result = std::move( verified.package) ;
			}

			return error ;
		}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の機器の母集合と関連サービス所属を元署名の電源宣言に結び付ける
 * @param[in] selected 同じ候補で属性を検査した選択機器の正規化した識別
 * @param[out] devices 同じ回に取得した全present機器の元属性
 * @param[in,out] snapshot 元選択の局所値に所属・署名元・未確認理由を加える作業値
 * @return 既知の所属と全体一覧が成立した場合0、途中変更や母集合不明はHRESULT
 * @note 対象外の元署名も個別の未確認として保持する
 */
//------------------------------------------------------------------------------
NativeError readSingleBootSharingPeers( const std::wstring						 &selected,
									   std::vector<StoragePowerPeerRegistration> &devices,
									   StorageSingleBootSharingSnapshot			 &snapshot)
{
	auto error = readStoragePowerPeerRegistrations( devices) ;	// 全クラスの現在の属性
	// 母集合の取得失敗を他機器なしと扱わない
	if( error != 0U) {
		return error ;
	}

	// 先に署名まで確認した選択機器に対応する元一覧の一件
	const auto active =
		std::ranges::lower_bound( devices, selected, {}, &StoragePowerPeerRegistration::instance) ;
	const auto &installed = snapshot.device.installed.registered ;	// 同じ機器の署名付き現用証拠
	// 同じ機器の正式不在又は元署名が全体の現在属性と一致することを確認する
	if( active == devices.end() || active->instance != selected || active->diagnostic != 0U ||
	   active->noDriver == installed.has_value()) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const auto &current = active->registration ;	// 全機器の列挙で読んだ同一機器の元登録
	// 元署名に固定した実際の公開名、節、装飾、サービスを現在属性と照合する
	if( installed &&
	   (normalizeIdentifier( installed->package.publishedInf) !=
			normalizeIdentifier( current.selection.publishedInf) ||
		normalizeIdentifier( installed->package.installedBasicSection) !=
			normalizeIdentifier( current.selection.basicSection) ||
		snapshot.device.installed.sectionExtension != current.selection.sectionExtension ||
		normalizeIdentifier( installed->package.installedService) !=
			normalizeIdentifier( current.service))) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const auto &candidate = snapshot.device.candidateService.name ;	// 同じ候補の元サービス名
	error = readStoragePowerServiceMembers( candidate, devices, snapshot.candidateServiceDevices) ;
	// 候補側の所属未確認を正式な空にしない
	if( error != 0U) {
		return error ;
	}

	// 現用が同じ名前なら一つの所属を共用し、別名は独立に確認する
	if( installed && normalizeIdentifier( candidate) != normalizeIdentifier( current.service)) {
		error = readStoragePowerServiceMembers( current.service, devices,
											   snapshot.otherInstalledServiceDevices) ;
		// 途中で所属を読めなかった場合は候補側だけで全体を確定しない
		if( error != 0U) {
			return error ;
		}

		// 同じ機器が異なる関連サービスの双方の一覧に出た場合は再確認する
		if( std::ranges::any_of( snapshot.otherInstalledServiceDevices, [&]( const auto &member) {
			   return std::ranges::binary_search( snapshot.candidateServiceDevices, member) ;
		   })) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	snapshot.peers.reserve( devices.size() - 1U) ;
	// 全ての選択外機器について、肯定的に確認した元署名と未知を別に残す
	for( const auto &peer : devices) {
		// 選択機器の元署名は同じ局所観測に保持済み
		if( peer.instance == selected) {
			continue ;
		}

		auto &observed			  = snapshot.peers.emplace_back() ;	// 個別の元登録または未確認
		observed.instance		  = peer.instance ;
		observed.service		  = peer.registration.service ;
		observed.serviceKnown	  = peer.serviceKnown ;
		observed.publishedInf	  = peer.registration.selection.publishedInf ;
		observed.basicSection	  = peer.registration.selection.basicSection ;
		observed.sectionExtension = peer.registration.selection.sectionExtension ;
		observed.noDriver		  = peer.noDriver ;
		observed.diagnostic		  = peer.diagnostic ;
		// 正式な未導入と元属性が読めなかった機器は別々に保持する
		if( observed.noDriver || observed.diagnostic != 0U) {
			continue ;
		}

		// 既存の署名読取りで照合し得る元と、候補・現用サービスの実所属
		const bool relevant =
			peer.storageClass ||
			normalizeIdentifier( peer.registration.selection.publishedInf) == L"STORNVME.INF" ||
			std::ranges::binary_search( snapshot.candidateServiceDevices, peer.instance) ||
			std::ranges::binary_search( snapshot.otherInstalledServiceDevices, peer.instance) ;
		// 未対応のクラス・署名を読まない場合も未使用とは判断しない
		if( !relevant) {
			observed.diagnostic = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			continue ;
		}

		observed.diagnostic = readStoragePowerPeerOrigin( peer, observed.origin.emplace()) ;
		// 途中変更は安定した個別未知で代替せず、全体を再観測に送る
		if( observed.diagnostic == nativeErrorFromWin32( ERROR_RETRY) ||
		   observed.diagnostic == nativeErrorFromWin32( ERROR_NO_SUCH_DEVINST) ||
		   observed.diagnostic == nativeErrorFromWin32( ERROR_NO_SUCH_DEVICE) ||
		   observed.diagnostic == nativeErrorFromWin32( ERROR_DEVICE_NOT_CONNECTED)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// 読めなかった個別元登録に署名付き元証拠を付けない
		if( observed.diagnostic != 0U) {
			observed.origin.reset() ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名付き現用登録と既存イベントが適用前後で維持されたか照合する
 * @param[in] before 適用前に固定した現用機器の元登録と保護付き資源
 * @param[in] after 同じ機器から独立に読み直した現在値
 * @return 元登録・構成・資源と保護が一致した場合true
 * @note イベントの書込み時刻とサービスの稼働状況は、資源の内容や構成と分ける
 */
//------------------------------------------------------------------------------
bool matchesPreservedAutomaticStorageRegistration(
	const StorageAutomaticRegistrationSnapshot &before,
	const StorageAutomaticRegistrationSnapshot &after)
{
	// 同じ表示名や版だけで現在の登録先とイベントの所有を補完しない
	if( before.package != after.package || before.sectionExtension != after.sectionExtension ||
	   before.events.controlSet != after.events.controlSet ||
	   before.events.eventParents != after.events.eventParents ||
	   before.auxiliary.service.has_value() != after.auxiliary.service.has_value()) {
		return false ;
	}

	// Windowsによる既存イベントの同値書込みだけで資源の喪失と判定しない
	for( std::size_t index = 0U; index < before.events.events.size(); ++index) {
		const auto &old	  = before.events.events[index] ;	// 適用前の同じイベントと保護
		const auto &fresh = after.events.events[index] ;	// 適用後の同じイベントと保護
		// 元型、資源参照、ACLや別名への変更は書込み時刻とは独立に検出する
		if( std::tie( old.name, old.present, old.messageFile, old.messageFileType, old.typesSupported,
					old.categoryCount, old.security) !=
		   std::tie( fresh.name, fresh.present, fresh.messageFile, fresh.messageFileType,
					fresh.typesSupported, fresh.categoryCount, fresh.security)) {
			return false ;
		}
	}

	auto currentAuxiliary = after.auxiliary ;	// 稼働状況だけを除く比較に使う同期コピー
	// 同じサービスの稼働有無が変わっても配置や構成を失ったと判定しない
	if( currentAuxiliary.service) {
		currentAuxiliary.service->status = before.auxiliary.service->status ;
	}

	return currentAuxiliary == before.auxiliary ;
}

//------------------------------------------------------------------------------
/**
 * @brief 適用前の新旧サービスを使う選択外の全機器と元イベントを読み直す
 * @param[in] instance 適用対象の同一インスタンス
 * @param[in] intended 署名付き候補と適用前の所有者
 * @param[in,out] observed 現在の選択機器を含む観測。成功時だけ検証済み他機器を追加する
 * @return 同じ適用対象と他機器の範囲・元登録が確認できた場合0、それ以外はHRESULT
 * @note 適用対象が別サービスへ移っても適用前の旧サービス名を読み、他機器の再順位付けはしない
 */
//------------------------------------------------------------------------------
NativeError readPreservedAutomaticStoragePeers( std::wstring_view			   instance,
											   const StorageInfEffects		  &intended,
											   StorageAutomaticDeviceSnapshot &observed)
{
	observed.owners.clear() ;
	// 適用前に所有者を確定していない場合は当該操作の保持確認に使わない
	if( !intended.automaticHost || !intended.automaticHost->device) {
		return E_INVALIDARG ;
	}

	const auto &before		= *intended.automaticHost->device ;	// 署名付きの適用前の全機器
	const auto	selectedKey = normalizeIdentifier( instance) ;	// Windows内部の同一インスタンス比較
	const auto &active		= observed.selected.package ;		// 指定機器の実際の現在登録または正式不在
	std::vector<std::wstring> services{intended.service.name} ;	// 適用前に確認した新旧サービス名
	// 旧から新へ移った場合も、旧サービスに残る他機器を照合する
	if( before.selected.package && normalizeIdentifier( before.selected.package->installedService) !=
									  normalizeIdentifier( intended.service.name)) {
		services.push_back( before.selected.package->installedService) ;
	}

	std::vector<StorageAutomaticServiceOwner> peers ;	// 適用前の全件が再確認できるまで保持する
	std::unordered_set<std::wstring>		  seen ;	// 新旧リストの間でも同じ機器は一度だけ
	// 新旧の正確なサービス名からpresent機器の完全集合を取得する
	for( const auto &service : services) {
		const auto key = normalizeIdentifier( service) ;					// 同じ割当てを比較するサービス名
		std::vector<std::wstring> members ;									// Windowsが返した同サービスの全present機器
		const auto error = readStorageRelatedDeviceIds( service, members) ;	// 全一覧の元診断
		// 照会失敗を所有者なしに読み替えない
		if( error != 0U) {
			return error ;
		}

		// 各機器の同一性と元登録の保持を個別に確認する
		for( const auto &id : members) {
			const auto keyId = normalizeIdentifier( id) ;	// 元機器の内部比較値
			// 二つの一覧に重複した機器は途中で割当てが変わった可能性がある
			if( !seen.insert( keyId).second) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			// 適用対象だけは既に観測した現在登録への移動を許す
			if( keyId == selectedKey) {
				// 現在未登録または別サービスという独立した観測と矛盾する場合は保留する
				if( !active || normalizeIdentifier( active->installedService) != key) {
					return nativeErrorFromWin32( ERROR_RETRY) ;
				}

				continue ;
			}

			const auto owner = std::ranges::find_if( before.owners, [&]( const auto &entry) {
				return normalizeIdentifier( entry.instance) == keyId ;
			}) ; // 適用前に同じインスタンスで確認した登録を借用
			// 未知の機器、新旧間の別機器の移動や元署名の欠損を保持としない
			if( owner == before.owners.end() || !owner->registered.package ||
			   normalizeIdentifier( owner->registered.package->installedService) != key) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			auto &peer	  = peers.emplace_back() ;	// 同じ署名元・現在イベントの再観測
			peer.instance = id ;
			// 旧公開INFと現在の署名付き登録を同じ機器へ結ぶ診断
			const auto read = inspectCurrentAutomaticStorageRegistration(
				id, false, owner->registered.package->publishedInf, intended.service,
				peer.registered) ;
			// 同じ署名元と他機器が使うイベント、EXEと保護を確認する
			if( read != 0U ||
			   !matchesPreservedAutomaticStorageRegistration( owner->registered, peer.registered)) {
				return read ? read : nativeErrorFromWin32( ERROR_RETRY) ;
			}
		}
	}

	// 選択外の元機器の欠落と、現在の選択機器の割当て確認の欠落を区別して検出する
	if( peers.size() != before.owners.size() || seen.contains( selectedKey) != active.has_value()) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	std::ranges::sort( peers, {}, &StorageAutomaticServiceOwner::instance) ;
	observed.owners = std::move( peers) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補が省略するイベント資源と、同じSystem32の署名元に一致する実DLLを読む
 * @param[in] intended 元候補と適用前のイベント、署名元の全観測
 * @param[in] after 適用後の同じ二つのイベント源
 * @param[out] resource 元の参照がある場合の保護付きDLL。不在なら空、失敗時は空
 * @return 元の省略または参照・型・保護とDLLの一致で0、差や読取り不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readPreservedAutomaticStorageEventResource( const StorageInfEffects			&intended,
													   const StorageSystemEventSnapshot &after,
													   ProtectedExecutableSnapshot		&resource)
{
	resource = {} ;
	// 元選択でイベントの資源を読めていない状態を正式な省略とは扱わない
	if( !intended.automaticHost || !intended.automaticHost->device) {
		return E_INVALIDARG ;
	}

	const auto &before = *intended.automaticHost ;	// 適用直前に保持した共有イベントの元値
	const auto &event  = before.events.events[1U] ;	// 候補が資源を指定しない明示イベント
	const auto &fresh  = after.events[1U] ;			// 同じ名前に対して読み直した元値と保護
	// 共有イベントの既存資源の型・原値や既存のACLを変化後の状態へ補正しない
	if( before.events.controlSet != after.controlSet ||
	   before.events.eventParents != after.eventParents || event.name != fresh.name ||
	   event.messageFile != fresh.messageFile || event.messageFileType != fresh.messageFileType ||
	   (event.present && (!fresh.present || event.security != fresh.security))) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 元配布が資源を省略し、現在の値も不在を維持する場合はDLL照会が要らない
	if( !event.messageFile) {
		return 0U ;
	}

	const RegisteredStorageEventReference *source{} ;	// 実在の資源を裏付ける適用前の元署名
	const auto findSource = [&]( const StorageAutomaticRegistrationSnapshot &registration) {
		// 同名イベントでも元資源ファイルを宣言しないパッケージは所有の根拠にならない
		if( !registration.package || !registration.package->eventReferences[1U]) {
			return true ;
		}

		const auto &candidate =
			*registration.package->eventReferences[1U] ;	// 同じ元登録の明示イベント
		// 適用前の型・元値・正確なイベント名まで一致する旧宣言に限定する
		if( candidate.resourceLeaf.empty() || candidate.resourceSha256.size() != 64U ||
		   !matchesRegisteredStorageEvent( candidate, event)) {
			return true ;
		}

		// 署名元だけを読んだ登録から適用前の実ファイルを推測しない
		if( !candidate.deployedResource || !candidate.deployedResource->existing) {
			return false ;
		}

		// 同じ資源名に複数の異なる元バイトがある状態は一件の成功へまとめない
		if( source && (source->resourceSha256 != candidate.resourceSha256 ||
					  source->deployedResource != candidate.deployedResource ||
					  normalizeIdentifier( source->resourceLeaf) !=
						  normalizeIdentifier( candidate.resourceLeaf))) {
			return false ;
		}

		source = &candidate ;
		return true ;
	} ; // 適用前の署名付き登録を同期で借用する。導入ヘルパーは呼ばない

	// 選択機器が旧登録を離れても、適用前の旧署名と他の所有者を照合する
	if( !findSource( before.device->selected) ||
	   !std::ranges::all_of( before.device->owners,
							[&]( const auto &owner) { return findSource( owner.registered) ; }) ||
	   !source) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::array<wchar_t, MAX_PATH> directory{} ;	// 旧DLLの正規宛先を構成するSystem32
	// 固定Windows APIの文字数で終端と切詰めを判断する
	const auto size = GetSystemDirectoryW( directory.data(), static_cast<UINT>( directory.size())) ;
	// 別ディレクトリや同じ名前の別DLLからの補完を拒否する
	if( size <= 3U || size >= directory.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto path =
		std::wstring{directory.data(), size} + L"\\" + source->resourceLeaf ;	// 正規の旧資源
	ProtectedExecutableSnapshot held ;											// 元バイトと現在のファイル保護が両方一致するまで公開しない
	const auto read = readSystem32StorageEventResourceSnapshot( path, held) ;	// 現在DLLの同一性と保護
	// 同じ値を参照していてもDLLが不在、別バイトまたは別保護の場合は保持としない
	if( read != 0U || !held.existing || held.existing->sha256 != source->resourceSha256 ||
	   source->deployedResource != held) {
		return read ? read : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	resource = std::move( held) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ機器に適用前の署名付き登録と共有設定が残っていることを照合する
 * @param[in] before 適用前に同じ機器と全共有先を確認した観測
 * @param[in] after 同じ機器の旧登録を読み、他機器と旧イベント資源を別途確認した観測
 * @return 同じ旧登録または正式な未導入と全変更先が維持された場合true
 * @note 再起動を判断する前に元の保護と端末状態を確認する。操作の成否は呼出元で保持する
 */
//------------------------------------------------------------------------------
bool matchesRetainedAutomaticStorageHost( const StorageAutomaticHostSnapshot &before,
										 const StorageAutomaticHostSnapshot &after)
{
	// 適用前後で共有イベント資源の有無と配置先が一致するかを保持します
	const bool resources = before.eventResource.has_value() == after.eventResource.has_value() &&
						   (!before.eventResource ||
							before.eventResource->destination == after.eventResource->destination) ;
	return before.device && after.device && before.boot && after.boot &&
		   matchesPreservedAutomaticStorageRegistration( before.device->selected,
														after.device->selected) &&
		   before.shared == after.shared && before.power == after.power && resources &&
		   before.events == after.events && before.auxiliary == after.auxiliary &&
		   before.autoLoggerRuntimePresent == after.autoLoggerRuntimePresent &&
		   before.boot->related == after.boot->related &&
		   before.boot->destination == after.boot->destination ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定適用の直後に自動起動型が指定した登録と共有設定を確認する
 * @param[in] instance 同じ操作で指定した機器の元インスタンス
 * @param[in] registered 同じ指定適用に使用したOEM INFの正規絶対位置
 * @param[in] inspected 適用前に検査した署名付き元閉包
 * @param[in] intended 同じ選択の作用と適用前の観測
 * @param[in] rebootRequired 同じ指定適用APIがWindowsの再起動を要求した場合true
 * @return 新しい作用の反映、元観測で裏付けた再起動後確認、または確認不能と元診断
 * @note 実際の観測とWindowsの再起動要求を元のまま使い、結果確認による追加入力は発行しない
 */
//------------------------------------------------------------------------------
DriverAuxiliaryExecutionResult observeAppliedAutomaticStorage( const std::wstring		&instance,
															  std::wstring_view			 registered,
															  const CommonInfInspection &inspected,
															  const StorageInfEffects	&intended,
															  bool rebootRequired)
{
	try {
		const auto slash = registered.rfind( L'\\') ;	// 保持したOEM INF名の開始位置
		// 同じ適用前の観測と保持済みOEM INFがある場合だけ結果を確認する
		if( slash == registered.npos || slash + 1U == registered.size() || !intended.automaticHost ||
		   !intended.automaticHost->device) {
			return {DriverAuxiliaryReflectionState::UNCONFIRMED, E_INVALIDARG} ;
		}

		const auto	published = registered.substr( slash + 1U) ;	// 同じ指定適用の公開INF名
		const auto &before	  = *intended.automaticHost ;			// 同じ操作が保持した全共有先
		const bool	writesResource =
			intended.service.auxiliary && intended.service.auxiliary->eventMessageCopy
											  .has_value() ;	// 元イベントに資源を指定した選択

		// 同じ選択機器と保持対象を一組として採取する同期処理
		const auto read = [&]( bool noDriver, std::wstring_view expected,
							  StorageAutomaticHostSnapshot &state,
							  ProtectedExecutableSnapshot  &resource) -> NativeError {
			const auto error = readAutomaticStoragePostState( instance, noDriver, expected, intended,
															 state) ;	// 同じ機器の元署名と現在値
			// 現在登録が確認できない場合は他機器の一致で適用を保証しない
			if( error != 0U) {
				return error ;
			}

			const auto peers = readPreservedAutomaticStoragePeers(
				instance, intended, *state.device) ;	// 適用前の全他機器を同じ新旧サービスで再観測
			// 明示配置は元候補の新しいバイトと照合する。資源の省略では旧配置を照合する
			return peers != 0U || writesResource ? peers
												 : readPreservedAutomaticStorageEventResource(
													   intended, state.events, resource) ;
		} ;

		// 元署名、所有者、旧DLLと全変更先を独立した再観測に照合する
		const auto readStable = [&]( bool noDriver, std::wstring_view expected,
									StorageAutomaticHostSnapshot &state) -> NativeError {
			ProtectedExecutableSnapshot resource ;							// 旧資源が存在する場合の保護付きDLL
			const auto error = read( noDriver, expected, state, resource) ;	// 最初の完全観測
			// 一部しか読めなかった現在値から途中変更の判定をしない
			if( error != 0U) {
				return error ;
			}

			StorageAutomaticHostSnapshot fresh ;									// 別に読み直した現在機器と全共有先
			ProtectedExecutableSnapshot	 freshResource ;							// 旧資源の独立した再確認
			const auto repeated = read( noDriver, expected, fresh, freshResource) ;	// 再観測の元診断
			return repeated != 0U || (fresh == state && freshResource == resource)
					   ? repeated
					   : nativeErrorFromWin32( ERROR_RETRY) ;
		} ;

		StorageAutomaticHostSnapshot observed ;					// 当該適用先の完全な現在観測
		auto status = readStable( false, published, observed) ;	// 新しい登録と共有先の診断
		// 新登録を読み切ったときは他のバージョンや別パッケージへ代替しない
		if( status == 0U) {
			status = verifyAppliedStorageAuxiliaryOrigin( *observed.device->selected.package,
														 inspected, intended.service) ;
			// 新しい署名元が成立した場合だけ全作用と既知の旧起動SYSを照合する
			if( status == 0U) {
				status = verifyAppliedAutomaticStorageEffects( intended, observed, rebootRequired) ;
			}

			// 構成の反映と既知の旧起動SYSが残る状態を別の結果にする
			if( status == 0U || status == S_FALSE) {
				return {status == 0U ? DriverAuxiliaryReflectionState::CONFIRMED
									 : DriverAuxiliaryReflectionState::RESTART_CHECK,
						0U} ;
			}
		}
		// Windowsが再起動を求め、旧状態をもう一度安全に検証できる元診断の場合だけ確認する
		else if( rebootRequired && (status == nativeErrorFromWin32( ERROR_RETRY) ||
								   (status == nativeErrorFromWin32( ERROR_NOT_FOUND) &&
									!before.device->selected.package))) {
			const auto &old = before.device->selected.package ;	// 署名付き旧登録または正式不在
			StorageAutomaticHostSnapshot retained ;				// 同一機器の旧登録と保護付き変更先
			// 同じ機器の旧状態を二度確認した診断
			const auto					 readOld = readStable(
				  !old, old ? std::wstring_view{old->publishedInf} : std::wstring_view{}, retained) ;
			// 候補の反映が確認できなくても、同じ旧登録と共有先の残存が成立する場合だけ待機とする
			if( readOld == 0U && matchesRetainedAutomaticStorageHost( before, retained)) {
				return {DriverAuxiliaryReflectionState::RESTART_CHECK, 0U} ;
			}

			// 再読取りの具体的な診断がある場合は、失われた元観測を再起動待ちへ置換しない
			if( readOld != 0U) {
				status = readOld ;
			}
		}

		return {DriverAuxiliaryReflectionState::UNCONFIRMED, status} ;
	} catch( const std::bad_alloc &) {
		return {DriverAuxiliaryReflectionState::UNCONFIRMED, E_OUTOFMEMORY} ;
	}
}

/** @brief 同じ候補のWindows順位と実選択節を照合するための同期借用 */
struct StorageAutomaticCandidateSelection {
	/// 署名と閉包を検査した元候補
	const OfficialInfPackage &package ;
	/// 元候補の保護配置先
	std::wstring_view		  infPath ;
	/// 選択機器の実候補節
	std::wstring_view		  section ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現用・候補の関連サービスが使われる全機器と署名元を独立照合する
 * @param[in] selectedInstance 選択した一台のWindowsインスタンス
 * @param[in] noDriver 同じ選択機器の確認済み未導入状態
 * @param[in] expectedInf 選択時にWindowsが確認した現在INF。未導入では空
 * @param[in] candidate 同じ候補とWindowsが選んだ実節の借用
 * @param[in] intended 署名付きの選択から確定した関連サービスと補助
 * @param[out] result 選択機器と全機器の署名元と現在観測。失敗時は空
 * @return 同じ関連サービスの元登録を全部照合した場合0、欠落や途中変更はHRESULT
 * @note 元署名とWindows順位の読取りだけを行い、他機器の導入や共有設定を変更しない
 */
//------------------------------------------------------------------------------
NativeError inspectAutomaticStorageDevices( const std::wstring &selectedInstance, bool noDriver,
										   std::wstring_view						 expectedInf,
										   const StorageAutomaticCandidateSelection &candidate,
										   const SelectedStorageServiceFacts		&intended,
										   StorageAutomaticDeviceSnapshot			&result)
{
	result = {} ;
	// 導入済み選択機器は順位取得時の現在INFに結合して読取する
	if( !noDriver && expectedInf.empty()) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	StorageAutomaticDeviceSnapshot made ;	// 選択機器も他機器も揃うまでは公開しない
	// 選択機器の実INFから現在の関連サービス名を取得する
	auto error = inspectCurrentAutomaticStorageRegistration( selectedInstance, noDriver, expectedInf,
															intended, made.selected) ;
	// 現用サービス名を候補の名前で補完しない
	if( error != 0U) {
		return error ;
	}

	const auto selectedId	= normalizeIdentifier( selectedInstance) ;	// 同じ選択機器との比較値
	const auto incomingName = normalizeIdentifier( intended.name) ;		// 候補の関連サービスの比較値
	std::vector<std::wstring> services{intended.name} ;					// 同じ名前ならWindows照会は一回
	// 現用登録で異なる関連サービスを確認した場合は両方の一覧を照合する
	if( made.selected.package &&
	   normalizeIdentifier( made.selected.package->installedService) != incomingName) {
		services.push_back( made.selected.package->installedService) ;
	}

	std::unordered_set<std::wstring> seen ;	// 同じIDが別サービスの一覧にも出た途中変更を検知する
	// 候補と現用の関連サービスのどの一覧も省略しない
	for( const auto &service : services) {
		std::vector<std::wstring> instances ;	// 今回Windowsが確認した全present機器
		error = readStorageRelatedDeviceIds( service, instances) ;
		// Windowsの一覧の不明を所有者なしに置き換えない
		if( error != 0U) {
			return error ;
		}

		const auto currentName = normalizeIdentifier( service) ;	// 同じWindowsサービス名で比較
		// 元一覧を全件確認し、所有者の集合と現在の割当ての差を拒否する
		for( const auto &instance : instances) {
			const auto identity = normalizeIdentifier( instance) ;	// 一度だけ数える機器の比較値
			// 現用・候補の二一覧の間でも重複と全体の上限を拒否する
			if( seen.size() >= 32U || !seen.insert( identity).second) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			// 選択機器は先に確定した関連サービスと同じ一覧にある場合だけ再利用する
			if( identity == selectedId) {
				// 選択機器の現用関連サービスの割当てが途中で変わっていないことを確認する
				if( !made.selected.package ||
				   normalizeIdentifier( made.selected.package->installedService) != currentName) {
					return nativeErrorFromWin32( ERROR_RETRY) ;
				}

				continue ;
			}

			StorageAutomaticServiceOwner owner ;	// 一機器の関連サービス・元登録・候補順位
			owner.instance = instance ;
			std::wstring observedInf ;	// 同じ候補をWindowsで確認した機器の現在INF
			// 候補と同じカーネルサービスを使う他機器には、同じ候補節への適合を要求する
			if( currentName == incomingName) {
				DeviceRankSnapshot			current ;	// 同一機器の現在適合根拠
				CandidateDriverNodeSnapshot node ;		// 同じ候補の一意なWindows選択
				OfficialDriverRankAudit		audit ;		// Windowsの現在順位の判定
				error = collectOfficialInfBindingState(
					instance, candidate.infPath, candidate.package,
					parseDriverVersion( candidate.package.driverVersion).value_or( 0U),
					normalizeInfDriverDate( candidate.package.driverDate).value_or( L""), current,
					node, audit) ;
				// 適用の影響を受ける同サービスの機器で候補節と現在INFを確定する
				if( error != 0U || current.noDriver ||
				   audit.decision != OfficialDriverRankDecision::APPLICABLE ||
				   current.currentDriver.infRead.state != DevicePropertyReadState::VALUE ||
				   normalizeIdentifier( node.sectionName) !=
					   normalizeIdentifier( candidate.section)) {
					return error != 0U ? error : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				observedInf			   = std::move( current.currentDriver.infFileName) ;
				owner.candidateSection = std::move( node.sectionName) ;
				owner.candidateRank	   = node.rank ;
			}

			// 旧サービスだけを使う機器も同じ登録前後で署名元と現在の共有先を確認する
			error = inspectCurrentAutomaticStorageRegistration( instance, false, observedInf,
															   intended, owner.registered) ;
			// 正式な現在の割当てがWindowsの元一覧と違えばその集合を採用しない
			if( error != 0U || !owner.registered.package ||
			   normalizeIdentifier( owner.registered.package->installedService) != currentName) {
				return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
			}

			made.owners.push_back( std::move( owner)) ;
		}
	}

	// 現用登録を持つ選択機器が対応する全present一覧に含まれなければ再観測する
	if( made.selected.package && !seen.contains( selectedId)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// Windowsの複数文字列の並び順だけの差を所有の変化と区別する
	std::ranges::sort( made.owners, {}, &StorageAutomaticServiceOwner::instance) ;
	result = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じストレージサービスを使う全ての現在機器の割当てと元配布を照合する
 * @param[in] devices 呼出し側が同期中に保持する元端末の情報集合
 * @param[in] effects 元の選択節で確認した関連サービスと利用予定の共有作用
 * @param[in] base 候補の内容検査を完了した元INF
 * @param[in] candidateInfPath 同候補の保護済み元INF配置先
 * @param[in] selectedInstance 選択機器の元instance識別子
 * @param[in] selectedService 同機器の現在Service属性。明示未導入では空
 * @param[in] servicePresent 関連サービスの現在構成の元観測がある場合true
 * @param[out] result 全対象の照合が成立した場合だけ保持する。途中失敗時は空
 * @return 全件を確認した場合0、元読取り・範囲・一致の失敗はHRESULT
 * @note 同じworkerの読取りに限る。導入資格の発行やWindows設定変更は行わない
 */
//------------------------------------------------------------------------------
NativeError readStorageServiceOwners( HDEVINFO devices, const StorageInfEffects &effects,
									 const OfficialInfPackage &base,
									 std::wstring_view		   candidateInfPath,
									 std::wstring_view		   selectedInstance,
									 std::wstring_view selectedService, bool servicePresent,
									 StorageServiceOwnershipProof &result)
{
	result = {} ;
	StorageServiceOwnershipProof made ;							// 全件の読取りが成立するまで元証拠を外へ渡さない
	const auto &api = driver_store_inf_detail::transport() ;	// 同一workerの固定読取り表
	// 新adapter初回でも、同serviceの実所有adapterを限定Windows照会で検証します
	if( servicePresent) {
		std::vector<std::wstring> instances ;	// 現サービスの重複なしの完全一覧
		// 同名サービスの有限一覧照会の結果
		const auto listed = readStorageRelatedDeviceIds( effects.service.name, instances) ;
		// 実在する関連サービスの取得失敗や所有機器なしはこの経路で承認しない
		if( listed != 0U || instances.empty()) {
			return listed != 0U ? listed : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// exact serviceの全現在nodeを原順で上限内に確認し、不明peerを省略しません
		for( auto &instance : instances) {
			// exact service一覧から開いた一所有adapterです
			SP_DEVINFO_DATA peer{} ;
			peer.cbSize = sizeof( peer) ;
			// exact一覧の各adapterを実native集合へ限定して開きます
			if( !api.open( devices, instance.c_str(), nullptr, 0U, &peer)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 当該所有adapterの現在Service propertyです
			std::wstring peerService ;
			// 元property照会の成功/不存在/失敗を区別する状態です
			const auto	 read = readObservedDeviceString( devices, peer, DEVPKEY_Device_Service,
														 peerService, api.inventory) ;
			// 同名一覧へ混ざった別service又は読取不能を拒否します
			if( read.state != DevicePropertyReadState::VALUE ||
			   normalizeIdentifier( peerService) != normalizeIdentifier( effects.service.name)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 元byte又は所有adapterの同期中の単独保持です
			StorageServiceOwnershipProof::Owner owner ;
			owner.instance = std::move( instance) ;
			// 下位検査の最初の診断を後続へ返す一時値です
			const auto error = collectOfficialInfBindingState(
				owner.instance, candidateInfPath, base,
				parseDriverVersion( base.driverVersion).value_or( 0U),
				normalizeInfDriverDate( base.driverDate).value_or( L""), owner.current,
				owner.candidate, owner.rank) ;
			// 同名serviceだけでは不十分です。同原packageへの全native適合も必要です
			if( error != 0U || owner.current.noDriver ||
			   owner.rank.decision != OfficialDriverRankDecision::APPLICABLE) {
				return error != 0U ? error : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 補助作用は現在の全所有者について、実割当ての元INF・CATと現在状態を照合する
			if( effects.service.auxiliary) {
				// 現在の共有先を読めない場合は登録の一部だけで証拠を作らない
				if( !effects.auxiliaryHost) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// WindowsとDriver Storeの位置を現在のAPIから取得するための照合用設定
				const DriverStorePackageLookup lookup{api.windowsDirectory,
													  api.storageStoreLocation} ;
				const auto					   installed = readVerifiedInstalledStorageOwner(
					devices, peer, api.inventory, lookup, owner.current.currentDriver,
					effects.service, *effects.auxiliaryHost,
					// 同じ実機器から読み取った元配布
					owner.registeredPackage.emplace()) ;
				// 現在配布を取得できない一部所有者を除外しない
				if( installed != 0U) {
					return installed ;
				}

				std::wstring finalService ;	// 署名確認の前後で同じ関連サービスの利用を照合する
				// 同一デバイスが引き続き対象サービスを使用しているかを確認した診断値
				const auto reread = readObservedDeviceString( devices, peer, DEVPKEY_Device_Service,
															 finalService, api.inventory) ;
				// 署名照合中のowner変更を後続の安全な観測と取り違えない
				if( reread.state != DevicePropertyReadState::VALUE || finalService != peerService) {
					return nativeErrorFromWin32( reread.diagnostic.code ? reread.diagnostic.code
																	   : ERROR_RETRY) ;
				}
			}

			made.owners.push_back( std::move( owner)) ;
		}
	}

	// 共有作用の選択機器が現在そのサービスを使う場合は、同じ所有一覧に含まれることを確認する
	if( (effects.service.auxiliary || effects.autoLogger) &&
	   normalizeIdentifier( selectedService) == normalizeIdentifier( effects.service.name) &&
	   std::ranges::none_of( made.owners, [&]( const auto &owner) {
		   return normalizeIdentifier( owner.instance) == normalizeIdentifier( selectedInstance) ;
	   })) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	result = std::move( made) ;
	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ候補の選択機器、電源所在と他機器の元宣言を二度確認する
 * @param[in] instanceId 同じ候補と先の順位観測に結んだ選択機器
 * @param[in] noDriver 先の観測が示す正式な未導入
 * @param[in] expectedInf 先の観測で確認した公開INF。未導入では空
 * @param[in] intended 検査済みの署名付き局所作用と電源定義
 * @param[out] snapshot 安定した母集合、選択機器の合成観測と電源変更の分類。失敗時は空
 * @return 同じ読み取りが成立すれば0、元の失敗または途中変更はHRESULT
 * @note 署名未確認機器を残し、この観測から導入資格を発行しない
 */
//------------------------------------------------------------------------------
NativeError readCurrentSingleBootStorageSharingSnapshot( const std::wstring		&instanceId,
														bool					 noDriver,
														std::wstring_view		 expectedInf,
														const StorageInfEffects &intended,
														StorageSingleBootSharingSnapshot &snapshot)
{
	snapshot = {} ;
	// 署名付き候補が電源に作用する場合だけ全域の共有照合を行う
	if( intended.powerSettings.empty()) {
		return E_INVALIDARG ;
	}

	try {
		const auto selected = normalizeIdentifier( instanceId) ;	// 全体の中の同一機器
		// 同じ候補と機器を同期中だけ借用し、両回で同じ経路と母集合を観測する
		const auto read = [&]( StorageSingleBootSharingSnapshot			&made,
							  std::vector<StoragePowerPeerRegistration> &inventory) -> NativeError {
			auto error = readCurrentSingleBootStorageDeviceSnapshot(
				instanceId, noDriver, expectedInf, intended, made.device) ;	// 選択機器の元状態
			// 選択機器を照合できなければ未確認の他機器だけを観測成功にしない
			if( error != 0U) {
				return error ;
			}

			error =
				readStoragePowerSettingsAndLocationsSnapshot( intended.powerSettings, made.power) ;
			// 元候補の全設定について現在の保護と全所在を確認する
			if( error != 0U) {
				return error ;
			}

			error =
				readSystem32StorageDriverSnapshot( intended.service.binaryTarget, made.destination) ;
			// 候補のSYSが現在配置される場所の正式不在または完全値を確認する
			if( error != 0U) {
				return error ;
			}

			error = readSingleBootSharingPeers( selected, inventory, made) ;
			// 同時に取得した機器群だけを同じ設定の元宣言に照らす
			return error == 0U ? classifySingleBootStoragePowerChanges( intended.powerSettings, made)
							   : error ;
		} ;

		StorageSingleBootSharingSnapshot		  made ;							// 後観測との一致まで公開しない元状態
		std::vector<StoragePowerPeerRegistration> inventory ;						// 全present母集合の元属性
		auto									  error = read( made, inventory) ;	// 第一観測の結果
		// 断片的な前観測を後観測だけで成功に変えない
		if( error != 0U) {
			return error ;
		}

		StorageSingleBootSharingSnapshot		  fresh ;			// 同じ選択に対する独立した後観測
		std::vector<StoragePowerPeerRegistration> freshInventory ;	// 母集合と登録属性の再読取り
		error = read( fresh, freshInventory) ;
		// 同じ署名の結論でも途中で母集合、局所値や登録場所が変わった観測を返さない
		if( error != 0U || fresh != made || freshInventory != inventory) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		StoragePowerSettingsSnapshot lastPower ;	// 他機器の署名確認が終わった時点の所在
		error = readStoragePowerSettingsAndLocationsSnapshot( intended.powerSettings, lastPower) ;
		// 最後の署名確認中に所在・定義が変わった場合は同じ観測として渡さない
		if( error != 0U || lastPower != made.power) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		ProtectedExecutableSnapshot
			lastDestination ;	// 他機器の照合終了後に同じSYS配置先を再確認する
		error = readSystem32StorageDriverSnapshot( intended.service.binaryTarget, lastDestination) ;
		// 同じ名前のまま元ファイルや親の保護が変わった場合は再観測へ戻す
		if( error != 0U || lastDestination != made.destination) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// 最終確認で同じ選択機器の現在登録と照合する既知の元属性
		const auto active = std::ranges::lower_bound( freshInventory, selected, {},
													 &StoragePowerPeerRegistration::instance) ;
		// 前後一致した同じインスタンスと元属性を最後まで同期中だけ借用する
		error = inspectPresentStorageDeviceRegistration(
			instanceId, noDriver, expectedInf,
			[&]( const AutomaticStorageDeviceRegistration &original, const auto &, HDEVINFO,
				SP_DEVINFO_DATA &) {
				return active != freshInventory.end() && active->instance == selected &&
							   original == active->registration
						   ? 0U
						   : nativeErrorFromWin32( ERROR_RETRY) ;
			}) ;
		// 最終時点で機器や関連サービスが変わった結果を使わない
		if( error != 0U) {
			return error ;
		}

		snapshot = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 単一起動の適用後にも維持される旧サービスと現在所属を独立して読む
 * @param[in] before 同じ選択機器から確認した署名付き旧登録と元観測
 * @param[in] intended 同じ機器へ適用した署名付き候補と関連サービス
 * @param[out] retained 旧サービスが別名の場合の構成、実体、イベントと所属。対象外や失敗時は空
 * @return 必要な観測を完了または旧サービスが対象外なら0、それ以外はHRESULT
 * @note 同名の新しいサービスの読取りとは分離し、設定やファイルを変更しない
 */
//------------------------------------------------------------------------------
NativeError readRetainedSingleBootStorage(
	const StorageSingleBootSharingSnapshot &before, const StorageInfEffects &intended,
	std::optional<StorageSingleBootRetainedServiceSnapshot> &retained)
{
	retained.reset() ;
	const auto &old = before.device.installed.registered ;	// 同じ選択機器が適用前に使った署名元
	// 未導入と同名サービスでは別の旧サービスの保持先を作らない
	if( !old || normalizeIdentifier( old->package.installedService) ==
				   normalizeIdentifier( intended.service.name)) {
		return 0U ;
	}

	// 適用前の旧配置が署名元に結び付いているものだけを維持確認へ渡す
	if( !old->package.bootService || !before.device.otherInstalledEvent) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	StorageSingleBootRetainedServiceSnapshot made ;	// 全読取りが成立するまで公開しない
	made.service.name = old->package.installedService ;
	auto error		  = readStorageServiceEvidence( made.service.name,
												   // 旧SCMの元診断
												   made.service.evidence.emplace()) ;
	// 保持すべき旧SCMが読める場合だけ、同じ署名付き登録のSYSを確認する
	if( error == 0U) {
		error =
			readSystem32StorageDriverSnapshot( old->package.bootService->binary, made.destination) ;
	}

	// 同じ旧サービスのイベントを新しい選択先から独立に読む
	if( error == 0U) {
		error = readSingleBootStorageEventSnapshot( made.service.name, made.event) ;
	}

	std::vector<StoragePowerPeerRegistration>
		present ;	// 旧サービスの現在の所属を照らす全present属性
	// 読取りに成功した旧サービスの所属を全現在機器へ照合する
	if( error == 0U) {
		error = readStoragePowerPeerRegistrations( present) ;
	}

	// 全一覧が確認できた場合だけWindowsの所属照会を使う
	if( error == 0U) {
		error = readStoragePowerServiceMembers( made.service.name, present, made.devices) ;
	}

	// 元診断や部分データを旧構成の維持に置き換えない
	if( error == 0U) {
		retained = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定適用した単一起動の正規登録と各影響先を同じ元選択で確認する
 * @param[in] instance 同じ適用機器のインスタンス。呼出し中だけ借用する
 * @param[in] registered 実際の指定適用に使った、保持中のOEM INFの完全位置
 * @param[in] inspection 同じ元選択について署名付きファイルを確認した元閉包
 * @param[in] intended 元閉包の同じ選択が宣言した作用
 * @param[in] before 適用の直前にも再確認した同じ機器の元観測
 * @param[in] rebootRequired 同じWindows APIが再起動を求めた場合true
 * @return 完全反映、確認済みの旧状態による再起動待ち、または未確認と元診断
 * @note 読取り専用。APIの成功・失敗や再起動指定は呼出元が別途保持する
 */
//------------------------------------------------------------------------------
DriverStorageReflectionResult observeAppliedSingleBootStorage(
	const std::wstring &instance, std::wstring_view registered,
	const CommonInfInspection &inspection, const StorageInfEffects &intended,
	const StorageSingleBootInstallScope &before, bool rebootRequired)
{
	try {
		const auto slash = registered.rfind( L'\\') ;	// 指定適用が選んだOEM公開名の開始位置
		// 署名付き元閉包と同じ選択の公開名がない場合は別の登録を調べない
		if( slash == registered.npos || slash + 1U == registered.size() ||
		   inspection.closure.packages.empty()) {
			return {DriverStorageReflectionState::UNCONFIRMED, E_INVALIDARG} ;
		}

		const auto &base	  = inspection.closure.packages.front() ;	// 同じ選択の署名付き基礎INF
		const auto &entries	  = inspection.closure.entries ;			// 閉包でハッシュを確認した全ファイル
		const auto	findEntry = [&]( const std::wstring &name) {
			 return std::ranges::find_if( entries, [&]( const auto &entry) {
				 return CompareStringOrdinal( entry.relativePath.c_str(), -1, name.c_str(), -1,
											 TRUE) == CSTR_EQUAL ;
			 }) ;
		} ; // 同じ閉包の元位置を処理中だけ借用する
		const auto inf = findEntry( base.infRelativePath) ;		// 保持中の元INF
		const auto cat = findEntry( base.catalogRelativePath) ;	// 実際に元INFを署名するCAT
		// 元署名ファイルの完全なハッシュを持つ候補に限って反映を照合する
		if( inf == entries.end() || cat == entries.end() || inf->sha256.size() != 64U ||
		   cat->sha256.size() != 64U) {
			return {DriverStorageReflectionState::UNCONFIRMED, TRUST_E_BAD_DIGEST} ;
		}

		std::optional<StorageSingleBootRetainedServiceSnapshot>
			 retained ;	// 新しい機器を読む前の旧構成
		auto error = readRetainedSingleBootStorage( before.observed, intended,
												   retained) ;	// 旧構成の最初の照会
		// 保持すべき旧構成が読めなければ新旧の成否を推定しない
		if( error != 0U) {
			return {DriverStorageReflectionState::UNCONFIRMED, error} ;
		}

		StorageSingleBootSharingSnapshot observed ;	// 同機器の新しい署名と現在の設定
		error = readCurrentSingleBootStorageSharingSnapshot(
			instance, false, registered.substr( slash + 1U), intended, observed) ;
		// 新しい登録を読み切った場合は、旧構成も読み直して同じ組として検証する
		if( error == 0U) {
			std::optional<StorageSingleBootRetainedServiceSnapshot> fresh ;	// 旧構成の独立再観測
			error = readRetainedSingleBootStorage( before.observed, intended, fresh) ;
			// 新しい機器を読む間に旧構成または所属が変わった場合は成功にしない
			if( error == 0U) {
				error =
					fresh != retained
						? nativeErrorFromWin32( ERROR_RETRY)
						: verifyAppliedSingleBootStorageEffects(
							  intended, before, observed, registered.substr( slash + 1U),
							  inf->sha256, cat->sha256, normalizeIdentifier( instance), retained) ;
			}

			return {error == 0U ? DriverStorageReflectionState::CONFIRMED
								: DriverStorageReflectionState::UNCONFIRMED,
					error} ;
		}

		const auto &old = before.observed.device.installed.registered ;	// 同じ機器の署名付き旧登録
		// 再起動要求が元状態の確認を必要とする場合だけ同じ機器と候補を同期中に借用する
		return resolveUnconfirmedSingleBootStorageReflection(
			before.observed, error, rebootRequired,
			[&]( StorageSingleBootSharingSnapshot &unchanged) {
				return readCurrentSingleBootStorageSharingSnapshot(
					instance, !old,
					old ? std::wstring_view{old->package.publishedInf} : std::wstring_view{},
					intended, unchanged) ;
			}) ;
	} catch( const std::bad_alloc &) {
		return {DriverStorageReflectionState::UNCONFIRMED, E_OUTOFMEMORY} ;
	}
}
} // namespace

/** @brief 同information setから作り、発行後不変な索引用秘密stateです */
struct DriverStoreProvider::IndexInventoryState {
	/** @brief 同scanの一present nodeに属する必要属性だけの秘密観測です */
	struct Node {
		/// 同scanのopaque nodeです
		std::wstring			  identity ;
		/// 既知classの大文字GUID。未知は空です
		std::wstring			  classGuid ;
		/// 同scanで確認した元Class観測です。公開recordで上書きしません
		DeviceRankSnapshot		  classObservation ;
		/// Class欠損と失敗を混同しない元HRESULTです
		NativeError				  classError{} ;
		/// 完全native未導入証拠を持つClass未確定deviceだけtrueです
		bool					  initialClassUnknown{} ;
		/// 成功した当該種別の秘密IDだけを保持します
		std::vector<std::wstring> hardware ;
		/// Hardwareへ読み替えない秘密Compatible IDです
		std::vector<std::wstring> compatible ;
		/// Hardware propertyの元HRESULTです
		NativeError				  hardwareError{} ;
		/// Compatible propertyの元HRESULTです
		NativeError				  compatibleError{} ;
	} ;
	/// 発行元のscan sessionです。Install sessionとは独立です
	ScanSessionId													session{} ;
	/// 単調増加するinventory世代です
	std::uint64_t													generation{} ;
	/// 実際にscanした所有threadです
	std::uint32_t													ownerThread{} ;
	/// 元未処理ownerが残る間だけ保持するleaseです。同workerだけが変更します
	mutable bool													resolutionOpen{true} ;
	/// 原lookup以外の再列挙を不可逆に拒否します
	mutable bool													lookupFrozen{} ;
	/// 全列挙と二巡目の必要属性captureが完了した場合trueです
	bool															enumerationComplete{} ;
	/// 部分列挙の元HRESULTです
	NativeError														enumerationError{} ;
	/// Captureした全present opaque集合です。Raw IDを含みません
	std::vector<std::wstring>										present ;
	/// 全presentの種別を保持した秘密属性です。任意DTOから受け取りません
	std::vector<Node>												nodes ;
	/// 秘密IDの元文字列viewから元node ordinalへ引く同state内だけの有限表です
	std::unordered_map<std::wstring_view, std::vector<std::size_t>> idNodes ;
	/// 両属性のどちらかが失敗したnodeを元class別に全件保持します。空keyは未知classです
	std::unordered_map<std::wstring_view, std::vector<std::size_t>> failedIdNodes ;
	/// 有限秘密mapに登録した全ID件数です
	std::size_t														retainedIds{} ;
} ;

/** @brief Providerだけが強所有する秘密stateへの失効可能なcallbackです */
class DriverStoreProvider::IndexInventoryResolver final : public IndexPublicIdResolver {
public:
	/**
	 * @brief 秘密stateの所有を増やさずcontextを固定します
	 * @param[in] state Providerの不変stateへのweak所有
	 * @param[in] context 本callbackの発行context
	 * @param[in] lease 同factoryが元stateへ結ぶread-openのweak寿命証拠です
	 */
	IndexInventoryResolver( std::weak_ptr<const IndexInventoryState>		 state,
						   IndexLookupContext							 context,
						   std::shared_ptr<const NativeIndexLookupLease> lease)
		: state_( std::move( state)), context_( context), lease_( std::move( lease))
	{
	}
	/**
	 * @brief Nativeだけが元inventoryの私有leaseを共有します
	 * @return 元factory発行の不変証拠の共有所有です。generic callbackでは空です。証拠objectは共有しても元inventory/contextの有効性や権限を
	 *         延長しません
	 * @note このresolverが既に保持するlease_のshared_ptrを返します。この関数からinventory列挙やleaseの新発行は行いません
	 */
	[[nodiscard]] std::shared_ptr<const NativeIndexLookupLease> leaseProof() const noexcept override
	{
		return lease_ ;
	}
	/**
	 * @brief 元公開ID役割を保持し、native両集合とClassGUIDを照合します
	 * @param[in] kind メーカー公表INF側identifierの元役割。native property指定ではありません
	 * @param[in] publishedId 元公開ASCII ID。端末actual IDではありません
	 * @param[in] classGuid 元申告ClassGUID
	 * @param[in] context 現在のworker context
	 * @param[in] present 現在の有限opaque集合。本呼出し中だけ借用します
	 * @return 完了区分・元HRESULTとopaque候補集合。全inventory列挙と照合の全完了だけがcompleted trueです。部分集合・列挙失敗・全presentか不明
	 *         な入力ではcompleted falseを返します。DriverStoreの私有証拠がある既知positiveだけを全体不足と分離でき、適合やrankは示しません
	 * @note 例外は共通入口で診断へ変換されます。同workerから呼び、再入しません
	 * @note 元scanの弱参照state・所有thread・完全present集合を検査し、保存済みの両ID集合とClassGUIDを照合します。この関数から新しいinventoryを取
	 *       得しません
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		const IndexPnpIdKind kind, const std::string_view publishedId,
		const std::string_view classGuid, const IndexLookupContext context,
		const std::span<const std::wstring> present) const override
	{
		return resolveCapturedIds( kind, publishedId, classGuid, context, present, false) ;
	}
	/**
	 * @brief Catalogの配布対象を同scanのHardwareIdsとClassGUIDへ照合します
	 * @param[in] publishedId 配布対象の完全な公開ASCII Hardware IDです
	 * @param[in] classGuid 元レコードの公開ClassGUIDです
	 * @param[in] context 現在のworker contextです
	 * @param[in] present 今回の全opaque集合を同期呼出し中だけ借用します
	 * @return 元診断と完全一致のopaque集合です。個別観測が成立した元deviceへHardware専用証拠を付けます
	 * @note 一致の判定にはHardwareIdsだけを使い、Class未確定時には既存の完全初回導入証拠も必要です。適合や導入許可は示しません
	 */
	[[nodiscard]] IndexPublicIdResolution resolveHardwareId(
		const std::string_view publishedId, const std::string_view classGuid,
		const IndexLookupContext			context,
		const std::span<const std::wstring> present) const override
	{
		return resolveCapturedIds( IndexPnpIdKind::HARDWARE, publishedId, classGuid, context,
								  present, true) ;
	}

private:
	/**
	 * @brief 発行元の同scanに照合を限定し、元属性と全cohortを個別証拠へ結びます
	 * @param[in] kind 元公開INFのID役割です。Hardware限定ではHARDWAREです
	 * @param[in] publishedId 大小文字を正規化して完全照合する公開ASCII IDです
	 * @param[in] classGuid 元レコードの公開ClassGUIDです
	 * @param[in] context 発行元と照合する現在のworker contextです
	 * @param[in] present 全opaque集合を同期呼出し中だけ借用します
	 * @param[in] hardwareOnly trueは一致の判定にHardware属性だけを使い、falseは元の両属性を使います
	 * @return 元属性不足を保持した完了区分・元HRESULTとopaque集合、条件に応じた不変証拠です
	 * @note 同workerの保存済みcaptureだけを使います。列挙不完全や失効時は証拠を発行しません
	 */
	[[nodiscard]] IndexPublicIdResolution resolveCapturedIds(
		const IndexPnpIdKind kind, const std::string_view publishedId,
		const std::string_view classGuid, const IndexLookupContext context,
		const std::span<const std::wstring> present, const bool hardwareOnly) const
	{
		IndexPublicIdResolution result{context_, false, 0U, {}} ;	// 成功を推測しない初期状態
		const auto				state = state_.lock() ;				// 呼出し中だけの秘密state所有
		// 新scan・install・破棄とcontext違いを現在stateへ結び直しません
		if( !state || !state->resolutionOpen || state->lookupFrozen || context != context_ ||
		   state->ownerThread != GetCurrentThreadId()) {
			result.error = nativeErrorFromWin32( ERROR_INVALID_STATE) ;
			return result ;
		}

		// 全present集合の一部や重複・余剰を照合完了へ変換しません
		if( present.size() != state->present.size() ||
		   !std::is_permutation( present.begin(), present.end(), state->present.begin())) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		const std::wstring originalId( publishedId.begin(),
									  // 公開ASCII入力だけの一時copy
									  publishedId.end()) ;
		const std::wstring guid( classGuid.begin(), classGuid.end()) ;	// 原申告classの一時copy
		// 型不明、非ASCII ID、無効GUIDを正常な一致なしへ分類しません
		if( (kind != IndexPnpIdKind::HARDWARE && kind != IndexPnpIdKind::COMPATIBLE) ||
		   !validIndexNativeId( originalId) || guid.size() != 38U || guid.front() != L'{' ||
		   guid.back() != L'}') {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		bool nonzero{} ;	// 未知classの全0表記を拒否します
		// 固定GUIDの全hexと区切りをRAM内だけで確認します
		for( std::size_t index = 1U; index < 37U; ++index) {
			const wchar_t value = guid[index] ;	// 原申告の一文字
			const bool	  separator =
				// 固定区切り
				index == 9U || index == 14U || index == 19U || index == 24U ;
			// 不正hex・UTF-8 byte・異なる区切りを暗黙補正しません
			if( separator ? value != L'-'
						 : !((value >= L'0' && value <= L'9') || (value >= L'A' && value <= L'F') ||
							 (value >= L'a' && value <= L'f'))) {
				result.error = static_cast<NativeError>( E_INVALIDARG) ;
				return result ;
			}

			nonzero = nonzero || (!separator && value != L'0') ;
		}

		// 公開全0を既知classへ補完しません
		if( !nonzero) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		result.error = state->enumerationError ;
		// 全present列挙と詳細captureが未完了なら、部分一致で成功にしません
		if( !state->enumerationComplete) {
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
			std::printf( "INDEX_RESOLVER_DIAGNOSTIC kind=%u enumerationComplete=0 "
						"enumerationError=0x%08lx\n",
						static_cast<unsigned>( kind), static_cast<unsigned long>( result.error)) ;
#endif
			return result ;
		}

		const auto normalizedClass = normalizeIdentifier( guid) ;	// 公開GUIDのcase非依存key
		const auto id =
			// 原公開IDを変更しない同じnative照合keyです
			normalizeIdentifier( originalId) ;
		result.completed = true ;
		bool allPositiveClassesKnown{true} ;	// 部分positive証拠へ未知Classを含めません
		std::vector<const std::vector<std::wstring> *>
			individualObservations ;	// 各一致nodeの完全個別観測を元cohortと同順に保持します
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
		std::size_t knownClassIdFailures{} ;			// 同classの必要ID失敗node数です
		std::size_t unknownClassIdFailures{} ;			// 未知classの必要ID失敗node数です
		std::size_t missingPropertyFailures{} ;			// 元ERROR_NOT_FOUNDの必要ID失敗数です
		std::size_t matchingKnownClassNodes{} ;			// 既知classと当種別IDが一致した数です
		std::size_t matchingUnknownClassNodes{} ;		// 当種別IDだけ一致した未知class数です
		std::size_t classRejectedNodes{} ;				// ID一致後に元Class観測が拒否された数です
		std::size_t otherKindKnownClassMatches{} ;		// 別native種別にexact一致した既知Class数です
		std::size_t otherKindUnknownClassMatches{} ;	// 別native種別にexact一致した未知Class数です
		std::size_t otherKindReadFailures{} ;			// Queryに影響し得る別native種別の読取拒否数です
		NativeError firstIdError{} ;					// 最初の必要ID失敗の元HRESULTです
#endif
		std::vector<std::size_t> relevantNodes ;	// 全cohortと失敗を原node順で処理する有限unionです
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
		// 詳細診断の別種別非一致件数は元の全node分母を維持します
		relevantNodes.resize( state->nodes.size()) ;
		// live診断は非一致nodeも原分母へ残すため、全ordinalを順に用意します
		for( std::size_t ordinal = 0U; ordinal < relevantNodes.size(); ++ordinal) {
			relevantNodes[ordinal] = ordinal ;
		}
#else
		// 両種別の逆引きを使い、各nodeの種別と必要属性は後段で検証します
		if( const auto found = state->idNodes.find( id) ; found != state->idNodes.end()) {
			relevantNodes = found->second ;
		}

		// 同class/未知classの必要ID失敗は、IDが逆引きに無くても必ず未判定へ残します
		for( const auto failureClass : {std::wstring_view{normalizedClass}, std::wstring_view{}}) {
			// 同class又は未知classの属性失敗を、逆引き非該当でも未判定へ残します
			if( const auto found = state->failedIdNodes.find( failureClass) ;
			   found != state->failedIdNodes.end()) {
				relevantNodes.insert( relevantNodes.end(), found->second.begin(),
									 found->second.end()) ;
			}
		}

		std::sort( relevantNodes.begin(), relevantNodes.end()) ;
		relevantNodes.erase( std::unique( relevantNodes.begin(), relevantNodes.end()),
							relevantNodes.end()) ;
#endif
		// 元ordinal順なので、最初のHRESULTとcohort/proofの全順序を変更しません
		for( const auto ordinal : relevantNodes) {
			const auto &node = state->nodes[ordinal] ;	// 不変captureの元nodeだけを借用します
			// 既知異classなら、無関係なID欠損を本queryへ持ち込みません
			if( !node.classGuid.empty() && node.classGuid != normalizedClass) {
				continue ;
			}

#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
			// 両属性を使う従来照合だけで別種別の匿名内訳を数えます
			if( !hardwareOnly) {
				const auto otherError =
					kind == IndexPnpIdKind::HARDWARE
						? node.compatibleError
						: node.hardwareError ;	// 判定へ混ぜない別種別の元診断です
				const auto &otherIds = kind == IndexPnpIdKind::HARDWARE
										   ? node.compatible
										   : node.hardware ;	// 同scan秘密captureの別種別だけです
				otherKindReadFailures += otherError != 0U ? 1U : 0U ;
				// 元属性の成功とexact一致だけを匿名件数にし、公開種別を補正しません
				if( otherError == 0U &&
				   std::find( otherIds.begin(), otherIds.end(), id) != otherIds.end()) {
					otherKindKnownClassMatches += node.classGuid.empty() ? 0U : 1U ;
					otherKindUnknownClassMatches += node.classGuid.empty() ? 1U : 0U ;
				}
			}
#endif
			const NativeError error =
				hardwareOnly || node.hardwareError != 0U
					? node.hardwareError
					: node.compatibleError ;	// 必要属性の元診断をHardware優先で保持します
			// 必要IDを読めない同classまたは未知classは不一致と断定しません
			if( error != 0U) {
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
				knownClassIdFailures += node.classGuid.empty() ? 0U : 1U ;
				unknownClassIdFailures += node.classGuid.empty() ? 1U : 0U ;
				missingPropertyFailures += error == nativeErrorFromWin32( ERROR_NOT_FOUND) ? 1U : 0U ;
				firstIdError = firstIdError != 0U ? firstIdError : error ;
#endif
				result.completed = false ;
				result.error	 = result.error != 0U ? result.error : error ;
				continue ;
			}

			// 正規化した完全値の一致を個別の初回証拠にも使います
			const bool hardwareMatches =
				std::ranges::find( node.hardware, id) != node.hardware.end() ;
			// Hardware限定では逆引きに含まれたCompatibleの一致を採用しません
			if( !hardwareMatches &&
			   (hardwareOnly || std::ranges::find( node.compatible, id) == node.compatible.end())) {
				continue ;
			}

#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
			matchingKnownClassNodes += node.classGuid.empty() ? 0U : 1U ;
			matchingUnknownClassNodes += node.classGuid.empty() ? 1U : 0U ;
#endif
			// ID一致でも未知classをWindows適合や正常不一致へ分類しません
			if( node.classError != 0U || (node.classGuid.empty() && !node.initialClassUnknown)) {
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
				++classRejectedNodes ;
#endif
				result.completed = false ;
				result.error	 = result.error != 0U ? result.error : node.classError ;
				continue ;
			}

			result.devices.push_back( node.identity) ;
			allPositiveClassesKnown = allPositiveClassesKnown && !node.classGuid.empty() ;
			individualObservations.push_back( !node.classGuid.empty() ||
													 (node.initialClassUnknown && hardwareMatches)
												 ? &node.hardware
												 : nullptr) ;
		}

		// 従来照合では全列挙を終えた同scanの既知Class一致だけに部分集合の証拠を付けます
		if( !hardwareOnly && !result.completed && state->enumerationError == 0U &&
		   !result.devices.empty() && allPositiveClassesKnown) {
			result.positiveProof = std::make_shared<const NativeIndexPositiveProof>(
				NativeIndexPositiveProof::MintKey{}, context_, kind, publishedId, classGuid,
				state->ownerThread, std::weak_ptr<const void>{state}, result.devices, result.error) ;
		}

		// 元列挙と全一致cohortを保ち、Hardware限定では一意の結果にも最大32deviceの個別証拠を発行します
		if( state->enumerationError == 0U && !result.devices.empty() &&
		   result.devices.size() <= 32U &&
		   (hardwareOnly || result.devices.size() > 1U ||
			(!result.completed && !allPositiveClassesKnown)) &&
		   std::ranges::any_of( individualObservations,
							   []( const auto *ids) { return ids != nullptr ; })) {
			result.deviceProofs.resize( result.devices.size()) ;
			// 全一致nodeを一度ずつ確認し、未認証の未知Class slotを成功へ変えません
			for( std::size_t index = 0U; index < result.devices.size(); ++index) {
				// 未知Classは完全初回証拠に加え当該Hardware exact一致を必要とします
				if( !individualObservations[index]) {
					continue ;
				}

				std::weak_ptr<const std::vector<std::wstring>>
					hardwareIds ;	// 同じ端末の完全観測です
				// HardwareIdsを複製せず、元stateの寿命が終われば証拠も失効します
				if( hardwareOnly) {
					hardwareIds = std::shared_ptr<const std::vector<std::wstring>>{
						state, individualObservations[index]} ;
				}

				result.deviceProofs[index] = std::make_shared<const NativeIndexDeviceProof>(
					NativeIndexDeviceProof::MintKey{}, context_, kind, publishedId, classGuid,
					state->ownerThread, std::weak_ptr<const void>{state}, result.devices,
					result.error, result.completed, result.devices[index], hardwareOnly,
					std::move( hardwareIds)) ;
			}
		}

#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
		std::printf(
			"INDEX_RESOLVER_DIAGNOSTIC kind=%u enumerationComplete=1 "
			"enumerationError=0x%08lx knownClassIdFailures=%zu unknownClassIdFailures=%zu "
			"missingPropertyFailures=%zu firstIdError=0x%08lx matchingKnownClassNodes=%zu "
			"matchingUnknownClassNodes=%zu classRejectedNodes=%zu "
			"otherKindKnownClassMatches=%zu otherKindUnknownClassMatches=%zu "
			"otherKindReadFailures=%zu completed=%u error=0x%08lx\n",
			static_cast<unsigned>( kind), static_cast<unsigned long>( state->enumerationError),
			knownClassIdFailures, unknownClassIdFailures, missingPropertyFailures,
			static_cast<unsigned long>( firstIdError), matchingKnownClassNodes,
			matchingUnknownClassNodes, classRejectedNodes, otherKindKnownClassMatches,
			otherKindUnknownClassMatches, otherKindReadFailures,
			static_cast<unsigned>( result.completed), static_cast<unsigned long>( result.error)) ;
#endif
		return result ;
	}

	/// Providerが失効させる秘密stateです。強所有を持ちません
	std::weak_ptr<const IndexInventoryState>	  state_ ;
	/// 発行時に固定したoperation・scan・inventoryです
	IndexLookupContext							  context_ ;
	/// 同factoryだけが発行したread-openのweak寿命証拠です
	std::shared_ptr<const NativeIndexLookupLease> lease_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同workerの検証済みProviderと元世代だけを借用します
 * @param[in] owner 借用Provider。nullは開始拒否で、終了時に何も変更しません
 * @param[in] generation ownerが保持した正の元inventory世代。null ownerでは0です
 * @param[in] operation 当該予約済みの新操作です
 */
//------------------------------------------------------------------------------
DriverStoreProvider::IndexInstallProofScope::IndexInstallProofScope(
	DriverStoreProvider *owner, const std::uint64_t generation,
	const OperationId operation) noexcept
	: owner_( owner), generation_( generation), operation_( operation)
{
}
//------------------------------------------------------------------------------
/**
 * @brief 当該Sの借用だけを終了し、未処理Uの元proofを保持します
 */
//------------------------------------------------------------------------------
DriverStoreProvider::IndexInstallProofScope::~IndexInstallProofScope()
{
	// 古いscopeから新operation/新世代の所有を変更しません
	if( owner_ && owner_->installProofInventory_ && owner_->activeInstallOperation_ == operation_ &&
	   owner_->installProofInventory_->generation == generation_) {
		owner_->activeIndexDevices_.clear() ;
		owner_->installProofInventory_.reset() ;
		// 最後の未処理scope終了または明示失効だけで閉じます
		if( owner_->pendingIndexDevices_.empty() && owner_->indexInventory_) {
			owner_->indexInventory_->resolutionOpen = false ;
		}
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 元同worker/scanのscope開始が成立したか確認します
 * @return 開始した元scopeだけtrueです
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::IndexInstallProofScope::active() const noexcept
{
	return owner_ != nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原lookup完了後の再factory/全体再列挙を不可逆に閉じます
 * @param[in] origin 元完全contextです
 * @return 同じ原ownerへ適用した場合trueです
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::sealIndexLookup( const IndexLookupContext origin) noexcept
{
	// 原lookupだけを一度閉じ、失効後のreadOpenを再開しません
	if( !indexInventory_ || origin != issuedIndexContext_ || !indexInventory_->resolutionOpen ||
	   indexInventory_->lookupFrozen || GetCurrentThreadId() != indexInventory_->ownerThread ||
	   origin.inventoryGeneration != indexInventory_->generation) {
		return false ;
	}

	indexInventory_->lookupFrozen = true ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元スキャンの未処理又は実行中の端末一台から現在のHardwareIdsを読み取る
 * @param[in] origin 元の凍結済み索引照合を示す完全な文脈です
 * @param[in] deviceIdentity 所有元から現在の対象一台へ解決する匿名識別子です
 * @param[in] requirePresent Windowsの現在present属性を必須にする場合trueです
 * @param[out] hardwareIds 比較用に正規化した現在の完全値です。失敗時は空です
 * @return 全値の読取りに成功した場合0、所有・状態又は読取りの不成立はHRESULTです
 * @note 所有workerで同期し、現端末の生属性を公開DTOに渡しません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::readRetainedIndexHardwareIds(
	const IndexLookupContext origin, const std::wstring &deviceIdentity, const bool requirePresent,
	std::vector<std::wstring> &hardwareIds) const
{
	hardwareIds.clear() ;
	// 元スキャンの所有者と凍結済みの元スナップショットを確認します
	if( !indexInventory_ || !indexInventory_->resolutionOpen || !indexInventory_->lookupFrozen ||
	   origin != issuedIndexContext_ || origin.scanSessionId != scanSessionId_ ||
	   origin.inventoryGeneration != indexInventory_->generation ||
	   GetCurrentThreadId() != ownerThreadId_) {
		return E_ACCESSDENIED ;
	}

	const bool executing = installProofInventory_ == indexInventory_ &&
						   std::ranges::find( activeIndexDevices_, deviceIdentity) !=
							   // 実行中の同じ対象です
							   activeIndexDevices_.end() ;
	const auto device =
		// 生instanceを同じworker内で借用します
		deviceInstances_.find( deviceIdentity) ;
	// 元の未処理端末又は実行対象に限り、識別子を同じ一台へ解決します
	if( device == deviceInstances_.end() ||
	   (!executing && !pendingIndexDevices_.contains( deviceIdentity))) {
		return E_ACCESSDENIED ;
	}

	return readScopedHardwareIds( device->second, hardwareIds, requirePresent) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元スキャンが所有する対象一台の現在のHardwareIdsから公式群を再判定します
 * @param[in] origin 元の凍結済み索引照合を示す完全な文脈です
 * @param[in] deviceIdentity 所有元から現在の対象一台へ解決する匿名識別子です
 * @param[in] record 同じ選択の承認を照合した元署名レコードです
 * @param[in] expectedGroup その元レコード内で同意対象を結ぶ公式群位置です
 * @return 同じ公式群が一意なら0、違う群・競合なら再確認、読取り失敗なら元HRESULTです
 * @note 元スキャンと実行中の端末に限って読み取ります。値の公開や権限発行は行いません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::reobserveIndexFirmwareGroup( const IndexLookupContext origin,
															 const std::wstring &deviceIdentity,
															 const IndexDistributionRecord &record,
															 const std::size_t expectedGroup) const
{
	// 同じ署名に存在する公式群以外の入力では端末を開きません
	if( record.recordSchemaVersion != 5U || !record.platformDeviceScope ||
	   expectedGroup >= record.platformFirmwareGroups.size()) {
		return E_ACCESSDENIED ;
	}

	std::vector<std::wstring> currentIds ;	// 端末一台の完全な現在値です
	const auto				  error =
		// 元と同じプロパティを読みます
		readRetainedIndexHardwareIds( origin, deviceIdentity, false, currentIds) ;
	// 欠損や不正属性の元エラーを群の不一致へ変更しません
	if( error != 0U) {
		return error ;
	}

	const auto match =
		// 署名済み完全IDだけの照合です
		classifyIndexPlatformFirmwareGroup( record, currentIds) ;
	// 群を判定できない場合は現在の端末を確認済みにしません
	if( match.state == IndexPlatformFirmwareMatchState::UNAVAILABLE) {
		return E_ACCESSDENIED ;
	}

	return match.state == IndexPlatformFirmwareMatchState::UNIQUE &&
				   match.groupIndex == expectedGroup
			   ? 0U
			   : nativeErrorFromWin32( ERROR_RETRY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選んだ元端末が現在も存在し、同じ完全Hardware IDを持つかを調べる
 * @param[in] origin 凍結済みの元照合と操作・スキャン・インベントリの文脈です
 * @param[in] deviceIdentity 元スキャンの端末一台を指す匿名識別子です
 * @param[in] requiredHardwareId 元署名の選択行にある完全Hardware IDです
 * @return 現在の同一端末に完全一致した場合は0、元観測の失敗又は不一致はHRESULTです
 * @note 所有workerで同期して読み取り、比較値を外部に返しません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::reobserveIndexHardwareId(
	const IndexLookupContext origin, const std::wstring &deviceIdentity,
	const std::wstring_view requiredHardwareId) const
{
	// 壊れた署名由来の比較値をSetupAPIへ渡しません
	if( !validIndexNativeId( requiredHardwareId)) {
		return E_ACCESSDENIED ;
	}

	std::vector<std::wstring> currentIds ;	// 凍結した元端末だけの現在属性です
	const auto				  error = readRetainedIndexHardwareIds( origin, deviceIdentity, true,
																   currentIds) ;	// 現在存在する同じ対象に限ります
	// 元端末の観測に失敗した場合は診断を保持します
	if( error != 0U) {
		return error ;
	}

	return containsScopedHardwareId( currentIds, requiredHardwareId)
			   ? 0U
			   : nativeErrorFromWin32( ERROR_RETRY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未処理または当該実行中subsetへの結合を検証します
 * @param[in] origin 元contextです
 * @param[in] operation 明示操作です
 * @param[in] devices 元一意subsetです
 * @param[in] executing trueは当該scopeのS、falseは未処理Uです
 * @return 完全一致だけtrueです。新しい権限を作りません
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::validateRetainedIndexSelection(
	const IndexLookupContext origin, const OperationId operation,
	const std::span<const std::wstring> devices, const bool executing) const noexcept
{
	// 生存leaseだけで新device/旧操作へ許可しません
	if( !indexInventory_ || origin != issuedIndexContext_ || !indexInventory_->resolutionOpen ||
	   !indexInventory_->lookupFrozen || origin.scanSessionId != scanSessionId_ ||
	   origin.inventoryGeneration != indexInventory_->generation ||
	   GetCurrentThreadId() != ownerThreadId_ || operation == 0U || devices.empty() ||
	   devices.size() > 4096U ||
	   (operation != activeInstallOperation_ && operation <= lastAcceptedInstallOperation_)) {
		return false ;
	}

	// 全対象を不変の元device集合と現在のU/Sへ照合します
	for( std::size_t index{}; index < devices.size(); ++index) {
		const auto &device = devices[index] ;	// 元opaqueです
		// 重複/原対応喪失/別scopeを拒否します
		if( !deviceInstances_.contains( device) ||
		   std::find( devices.begin(), devices.begin() + static_cast<std::ptrdiff_t>( index),
					 device) != devices.begin() + static_cast<std::ptrdiff_t>( index) ||
		   (executing
				? operation != activeInstallOperation_ ||
					  std::ranges::find( activeIndexDevices_, device) == activeIndexDevices_.end()
				: !pendingIndexDevices_.contains( device))) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全選択事前検証後だけ新resolverを閉じ、元proofの解放を一batch終端へ延期します
 * @param[in] origin 元factoryの原contextです
 * @param[in] operation 当該予約済み新操作です
 * @param[in] devices 元Uの一意な選択subsetです
 * @return 同worker/scanの一回scope。不一致/閉鎖済みはinactiveです
 * @note 新取得・proof・導入許可を発行せず、各deviceの直前再検証は別に必須です
 */
//------------------------------------------------------------------------------
DriverStoreProvider::IndexInstallProofScope DriverStoreProvider::beginIndexInstallProofScope(
	const IndexLookupContext origin, const OperationId operation,
	const std::span<const std::wstring> devices) noexcept
{
	// 原owner/Uの検証が終わる前に一部だけ消費しません
	if( installProofInventory_ || operation != activeInstallOperation_ ||
	   !validateRetainedIndexSelection( origin, operation, devices, false)) {
		return {nullptr, 0U, 0U} ;
	}

	try {
		std::vector<std::wstring> selected{devices.begin(),
										   // 確保失敗時はUを変更しません
										   devices.end()} ;
		activeIndexDevices_.swap( selected) ;
		installProofInventory_ = indexInventory_ ;
		// 検証と全確保後だけUからSへ移します
		for( const auto &device : devices) {
			pendingIndexDevices_.erase( device) ;
		}

		return {this, indexInventory_->generation, operation} ;
	} catch( ...) {
		// noexceptの確保例外をabortさせずinactiveへ返します。状態変更は確保後だけです
		return {nullptr, 0U, 0U} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現在属性の非通信内部試験用API表を所有copyする
 * @param[in] transport 完全なSetupAPI代替表。欠損をnative呼出しで補完しない
 * @note このinstanceはscanCurrentInventory専用。通常scanと導入sessionを発行しない
 */
//------------------------------------------------------------------------------
DriverStoreProvider::DriverStoreProvider( DriverStoreInventoryTransport transport) noexcept
	: testInventoryTransport_( std::move( transport))
{
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の PnP device と compatible Driver Store 履歴を列挙する。現在の PnP device と compatible Driver Store履
 *        歴を列挙する。 注記: network 通信、download、およびsystem state の変更は行わない
 * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。 呼出し側が割り当てた 0 ではないsession ID
 * @param[in] options Aggregate Provider以外では既定値を使用するscan設定。 複合Providerで検証済みのscan条件
 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先
 * @return 現在版と切替可能な local driver 候補を含む scan 結果
 * @note network 通信、download、および system state の変更は行わない
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scan( const ScanSessionId scanSessionId, const ScanOptions &options,
									 const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( options) ;
	return scanInventory( scanSessionId, progressCallback, nullptr, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 履歴・native照合map・install targetを生成せず現在属性だけを列挙する
 * @param[in] scanSessionId 専用contextと一致するworker session
 * @param[in,out] execution 同期呼出し中だけ借用する取消し・期限context
 * @param[in] progressCallback 確定した列挙件数の通知先
 * @return 表示専用の現在行。途中停止では検証済み行と不完全な計測を保持
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scanCurrentInventory(
	const ScanSessionId scanSessionId, MetadataSearchExecutionContext &execution,
	const ProviderProgressCallback &progressCallback)
{
	return scanInventory( scanSessionId, progressCallback, &execution) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在属性scanへ索引専用の秘密ID captureだけを追加します
 * @param[in] scanSessionId 専用contextと一致する正のsession
 * @param[in,out] execution 同期呼出し中だけ借用する停止context
 * @param[in] progressCallback 確定進捗の通知先
 * @return 表示専用の現在行と独立した秘密resolver state
 * @note 完全transport内だけで実行し、履歴・install session・native fallbackを発行しません
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scanCurrentIndexInventory(
	const ScanSessionId scanSessionId, MetadataSearchExecutionContext &execution,
	const ProviderProgressCallback &progressCallback)
{
	return scanInventory( scanSessionId, progressCallback, &execution, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの秘密snapshotをweak所有するread-only resolverを発行します
 * @param[in] operationId 結合する正のworker operation
 * @param[out] context 発行時だけsessionと単調inventory世代を返します。拒否時は空です
 * @param[out] present 全観測opaque集合。拒否時は空です。生IDは含みません
 * @return 所有threadの有効snapshotだけがcallbackを持ちます。拒否時はnullptrです
 * @note Workerで同期呼出しし再入しません。新scan・install・Provider破棄で旧callbackは失効します。不完全snapshotのcallbackも発行できますが、
 *       resolveのcompletedはfalseです
 */
//------------------------------------------------------------------------------
std::unique_ptr<IndexPublicIdResolver> DriverStoreProvider::makeIndexPublicIdResolver(
	const std::uint64_t operationId, IndexLookupContext &context,
	std::vector<std::wstring> &present) const
{
	context = {} ;
	present.clear() ;
	// 未発行、別thread、0 operationへ秘密stateの能力を渡しません
	if( !indexInventory_ || !indexInventory_->resolutionOpen || indexInventory_->lookupFrozen ||
	   issuedIndexContext_.operationId != 0U || operationId == 0U ||
	   indexInventory_->ownerThread != GetCurrentThreadId()) {
		return nullptr ;
	}

	const IndexLookupContext issued{operationId, indexInventory_->session,
									indexInventory_->generation} ;	// このcallbackだけの結合tuple
	issuedIndexContext_ = issued ;
	auto lease			= std::make_shared<const NativeIndexLookupLease>(
		 NativeIndexLookupLease::MintKey{}, issued, indexInventory_->ownerThread,
		 std::weak_ptr<const void>{indexInventory_},
		 &indexInventory_->resolutionOpen) ;	// 秘密stateを強所有しません
	auto resolver = std::make_unique<IndexInventoryResolver>( indexInventory_, issued,
															 // Weak所有
															 std::move( lease)) ;
	present		  = indexInventory_->present ;
	context		  = issued ;
	return resolver ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常scanと現在属性専用scanが共有する有界present列挙
 * @param[in] scanSessionId 呼出側が発行した非ゼロsession
 * @param[in] progressCallback 同期の進捗通知先
 * @param[in,out] execution Nullは通常履歴検索、非nullは表示専用
 * @param[in] captureIndexIds 同scanの索引照合用秘密属性を保持する場合true
 * @return 列挙結果。専用modeではinstall sessionを発行しない
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scanInventory( const ScanSessionId			  scanSessionId,
											  const ProviderProgressCallback &progressCallback,
											  MetadataSearchExecutionContext *execution,
											  const bool					  captureIndexIds)
{
	invalidateScanSession() ;
	progressCallback( {.stage = ProviderStage::SCANNING_DEVICES}) ;
	ScanResult result{} ;	// 全present deviceとcompatible driverを格納するscan結果
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.purpose = execution != nullptr ? ScanPurpose::METADATA_ONLY : ScanPurpose::STANDARD ;
	const auto &transport =
		// Instance固定I/O
		testInventoryTransport_.value_or( driver_store_inf_detail::transport().inventory) ;
	// Fixture依存を通常scanへ使わず、不完全tableをnative APIで補完しない
	if( (testInventoryTransport_ && execution == nullptr) || !transport.open ||
	   !transport.enumerate || !transport.property || !transport.instanceId || !transport.close ||
	   !transport.nodeStatus) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// 未発行sessionへdeviceと導入targetを登録しない
	if( scanSessionId == 0 ||
	   (execution != nullptr && execution->scanSessionId() != scanSessionId)) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	ownerThreadId_ = GetCurrentThreadId() ;
	// 世代overflow後は旧値の再利用や0世代の発行を行いません
	if( indexInventoryGeneration_ == std::numeric_limits<std::uint64_t>::max()) {
		result.error = nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		return result ;
	}

	++indexInventoryGeneration_ ;
	std::shared_ptr<IndexInventoryState> indexState ;	// 同scanだけが作る可変capture
	// 通常scanと明示索引用現在属性scanだけに秘密stateを作ります
	if( captureIndexIds) {
		indexState				= std::make_shared<IndexInventoryState>() ;
		indexState->session		= scanSessionId ;
		indexState->generation	= indexInventoryGeneration_ ;
		indexState->ownerThread = ownerThreadId_ ;
	}

	// Queue内での取消しや期限切れはWindows列挙を開始しない
	if( execution != nullptr && execution->checkpoint() != 0) {
		result.error   = execution->checkpoint() ;
		result.outcome = execution->sessionStopReason() == MetadataSearchReason::CANCELLED
							 ? OutcomeCode::ABORTED
							 : OutcomeCode::FAILURE ;
		inventoryMeasurement_.enumeratedDeviceCount = {std::nullopt,
													   MeasurementExtent::UNAVAILABLE} ;
		return result ;
	}

	DeviceInfoSet devices(	// 本scan中の全present deviceを所有するinformation set
		transport.open( nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT), transport) ;
	// present device集合を作成できなければsessionを失効してscanを失敗とする
	if( !devices.valid()) {
		result.error = nativeErrorFromWin32( GetLastError()) ;
		invalidateScanSession() ;
		inventoryMeasurement_.enumeratedDeviceCount	   = {std::nullopt,
														  MeasurementExtent::UNAVAILABLE} ;
		inventoryMeasurement_.unrepresentedDeviceCount = {std::nullopt,
														  MeasurementExtent::UNAVAILABLE} ;
		inventoryMeasurement_.reasons.push_back(
			{MeasurementReason::INCOMPLETE, MeasurementUnit::QUERY, 1U}) ;
		inventoryMeasurement_.error = result.error ;
		return result ;
	}

	bool		  partialFailure{} ;			// trueの場合は列挙欠損を警告付き成功として返す
	DWORD		  deviceCount{} ;				// 本scanで保持して詳細確認するpresent device数
	std::uint64_t observedDeviceCount{} ;		// 上限probeを含め、存在を確認できたnode数
	std::uint64_t assessedDeviceCount{} ;		// Compatible listを最後まで判定できたdevice数
	std::uint64_t limitAffectedDeviceCount{} ;	// 列挙上限で詳細を完了できなかったnode数
	bool deviceEnumerationComplete{} ;			// ERROR_NO_MORE_ITEMSで全device終端を確認した場合true
	bool candidateLimitReached{} ;				// 全候補上限により後続deviceを処理できない場合true
	BoundedEnumerationStop deviceStop{
		BoundedEnumerationStop::LIMIT} ;	// 上限まで列挙した場合の本体停止理由
	BoundedEnumerationProbe deviceProbe{
		BoundedEnumerationProbe::NOT_RUN} ;	// 上限到達時だけ設定する一回probe結果
	NativeError deviceEnumerationError{} ;	// 本体またはprobeで最初に得た列挙診断値
	// 同一workerでだけ呼び、同期API境界の停止を最初のinventory診断へ保持する
	const auto	checkInventoryStop = [&]() {
		 // 通常scanには新しい取消し契約を暗黙追加しない
		 if( execution == nullptr) {
			 return false ;
		 }

		 const NativeError error = execution->checkpoint() ;	// 最新の主停止理由
		 // 停止していなければ列挙を継続する
		 if( error == 0) {
			 return false ;
		 }

		 partialFailure = true ;
		 // 後続停止で先行API errorを上書きしない
		 if( inventoryMeasurement_.error == 0) {
			 inventoryMeasurement_.error = error ;
		 }

		 return true ;
	 } ;
	// 詳細処理前に同一information setを一巡し、進捗表示の正確な分母を確定する
	for( DWORD deviceIndex = 0; deviceIndex < MAXIMUM_DEVICES; ++deviceIndex) {
		// 個数確認の途中停止を正常終端へ読み替えない
		if( checkInventoryStop()) {
			deviceStop			   = BoundedEnumerationStop::API_FAILURE ;
			deviceEnumerationError = inventoryMeasurement_.error ;
			break ;
		}

		SP_DEVINFO_DATA device{} ;	// 件数確認中のpresent device metadata
		device.cbSize = sizeof( device) ;
		// 件数確認の列挙終了を検出し、正常終端か障害かを判定する
		if( transport.enumerate( devices.get(), deviceIndex, &device) == FALSE) {
			const DWORD error = GetLastError() ;	// 件数列挙の正常終端または失敗code
			// 本体loopの停止理由を保持し、上限到達とは別に後で純粋分類する
			if( error == ERROR_NO_MORE_ITEMS) {
				deviceStop = BoundedEnumerationStop::NORMAL_END ;
			} else {
				deviceStop			   = BoundedEnumerationStop::API_FAILURE ;
				deviceEnumerationError = nativeErrorFromWin32( error) ;
			}

			break ;
		}

		++deviceCount ;
	}

	// 上限ちょうどで終端したか、少なくとも一件超過したかを一回だけ追加確認する
	if( deviceStop == BoundedEnumerationStop::LIMIT) {
		// 上限probeの直前も停止を確認し、追加APIを呼ばない
		if( checkInventoryStop()) {
			deviceProbe			   = BoundedEnumerationProbe::API_FAILURE ;
			deviceEnumerationError = inventoryMeasurement_.error ;
		} else {
			SP_DEVINFO_DATA probe{} ;	// 保持しない4097件目の存在確認用metadata
			probe.cbSize = sizeof( probe) ;
			// Probe結果は保持せず、正常終端・超過・API失敗だけを計測する
			if( transport.enumerate( devices.get(), MAXIMUM_DEVICES, &probe) == FALSE) {
				const DWORD error = GetLastError() ;	// 上限probeの正常終端または失敗code
				// ERROR_NO_MORE_ITEMSの場合だけ4096件を正確な全件数として扱う
				if( error == ERROR_NO_MORE_ITEMS) {
					deviceProbe = BoundedEnumerationProbe::NORMAL_END ;
				} else {
					deviceProbe			   = BoundedEnumerationProbe::API_FAILURE ;
					deviceEnumerationError = nativeErrorFromWin32( error) ;
				}
			} else {
				// 追加nodeを候補化せず、純粋分類へ実要素の存在だけを渡す
				deviceProbe = BoundedEnumerationProbe::ELEMENT_FOUND ;
			}
		}
	}

	const auto deviceBoundary = classifyBoundedEnumeration(
		static_cast<std::uint64_t>( deviceCount), static_cast<std::uint64_t>( MAXIMUM_DEVICES),
		deviceStop, deviceProbe, deviceEnumerationError) ;	// 本体と一回probeの整合済み分類
	// 内部列挙状態の矛盾を部分成功へ隠さず、scan全体をfail-closedで終了する
	if( !deviceBoundary || !deviceBoundary->observedItemCount.value.has_value()) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		invalidateScanSession() ;
		return result ;
	}

	observedDeviceCount							= deviceBoundary->observedItemCount.value.value() ;
	deviceEnumerationComplete					= deviceBoundary->enumerationComplete ;
	inventoryMeasurement_.enumeratedDeviceCount = deviceBoundary->observedItemCount ;
	// API失敗では最初の診断値を保持し、超過確認では上限影響nodeを一件記録する
	if( deviceBoundary->error != 0) {
		partialFailure				= true ;
		inventoryMeasurement_.error = deviceBoundary->error ;
	}

	// 上限外のpresent deviceを確認した場合だけ、未処理nodeを一件以上として記録する
	if( deviceBoundary->limitExceeded) {
		++limitAffectedDeviceCount ;
		partialFailure = true ;
	}

	progressCallback(
		{.stage = ProviderStage::SCANNING_DEVICES, .completedItems = 0, .totalItems = deviceCount}) ;
	result.coverage.eligibleDeviceCount = deviceCount ;

	// Present deviceを上限付きで列挙し、各deviceの現在版とcompatible履歴を収集する
	for( DWORD deviceIndex = 0; deviceIndex < deviceCount; ++deviceIndex) {
		// 詳細列挙で未処理のnodeは表示済み母数へ含めない
		if( checkInventoryStop()) {
			break ;
		}

		SP_DEVINFO_DATA device{} ;	// 現在列挙中のpresent device metadata
		device.cbSize = sizeof( device) ;
		// 事前列挙で存在したnodeを再取得できなければ同一集合の詳細処理を完了にしない
		if( transport.enumerate( devices.get(), deviceIndex, &device) == FALSE) {
			const DWORD error = GetLastError() ;	// 二巡目の列挙失敗code
			partialFailure	  = true ;
			// 事前列挙と矛盾する正常終端はERROR_INVALID_DATAとして保持する
			if( inventoryMeasurement_.error == 0) {
				inventoryMeasurement_.error =
					nativeErrorFromWin32( error == ERROR_NO_MORE_ITEMS ? ERROR_INVALID_DATA : error) ;
			}

			break ;
		}

		// UIへ渡せるscan session内のopaque device ID
		const std::wstring deviceIdentity =
			L"device:" + std::to_wstring( scanSessionId) + L":" + std::to_wstring( deviceIndex) ;
		DeviceObservation observation ;	// 生属性を含まない一deviceの観測
		observation.scanSessionId  = scanSessionId ;
		observation.deviceIdentity = deviceIdentity ;
		std::wstring instanceId ;	// 有効時だけ秘密mapへ登録するworker内ID
		observation.instanceIdentity =
			readObservedInstanceId( devices.get(), device, instanceId, transport) ;
		// 通常検索の同じDisplay機器にだけ、OSが明示した物理GPU種別を結び付ける
		if( execution == nullptr &&
		   observation.instanceIdentity.state == DevicePropertyReadState::VALUE &&
		   IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_DISPLAY)) {
			observation.graphicsAdapter = readGraphicsAdapterKind( instanceId) ;
		}

		// Worker内instance IDを分類後に破棄し、候補へは有限busだけを渡す
		const OfficialDiscoveryDeviceBus discoveryBus =
			classifyOfficialDiscoveryDeviceBus( instanceId) ;
		observation.node = readObservedNode( device, transport) ;
		std::wstring deviceName ;	// FriendlyNameまたはDeviceDescから得る表示名
		observation.friendlyName = readObservedDeviceString(
			devices.get(), device, DEVPKEY_Device_FriendlyName, deviceName, transport) ;
		// 名前の空・欠損・失敗時は標準説明を試し、元の失敗も観測へ残す
		if( observation.friendlyName.state != DevicePropertyReadState::VALUE) {
			observation.deviceDescription = readObservedDeviceString(
				devices.get(), device, DEVPKEY_Device_DeviceDesc, deviceName, transport) ;
		}

		std::wstring	   manufacturer ;	// Device propertyが返す製造元表示名
		std::wstring	   deviceClass ;	// Device propertyが返すsetup class表示名
		// UIのWindows標準class icon選択に使用するcanonical GUID
		const std::wstring deviceClassGuid = formatClassGuid( device.ClassGuid) ;
		observation.manufacturer		   = readObservedDeviceString(
			  devices.get(), device, DEVPKEY_Device_Manufacturer, manufacturer, transport) ;
		observation.deviceClass = readObservedDeviceString(
			devices.get(), device, DEVPKEY_Device_Class, deviceClass, transport) ;
		std::wstring driverKey ;	// 内容をUI・logへ転送しない一時key
		observation.driverKey = readObservedDeviceString(
			devices.get(), device, DEVPKEY_Device_Driver, driverKey, transport) ;
		// Worker内の現在属性と、値を含まない読取り結果
		const CurrentDriverMetadata current = readCurrentDriver( devices.get(), device, transport) ;
		observation.infName					= current.infRead ;
		observation.provider				= current.providerRead ;
		observation.version					= current.versionRead ;
		observation.date					= current.dateRead ;
		observation.driverPresence =
			classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
		// 有効な実IDを持ち、後続で消失が見つからない場合だけnative照合へ進む
		bool nativeIdentityAvailable =
			observation.instanceIdentity.state == DevicePropertyReadState::VALUE ;
		bool observationFailed = !nativeIdentityAvailable ;	// 失敗時も代表行を残すが完全観測としない
		const std::array<const DevicePropertyReadStatus *, 11>
			reads{&observation.instanceIdentity,
				  &observation.node.read,
				  &observation.friendlyName,
				  &observation.deviceDescription,
				  &observation.manufacturer,
				  &observation.deviceClass,
				  &observation.driverKey,
				  &observation.infName,
				  &observation.provider,
				  &observation.version,
				  &observation.date} ;	// 全読取りから失敗と消失だけを確認する固定集合
		// 属性失敗を件数に保持し、途中のdevice消失時はnative照合能力を発行しない
		for( const auto *read : reads) {
			const bool failed = read->state == DevicePropertyReadState::FAILED ||
								read->state == DevicePropertyReadState::INVALID_DATA ||
								// 欠損とは別の実失敗
								read->state == DevicePropertyReadState::LIMIT_REACHED ;
			observationFailed = observationFailed || failed ;
			// 一件目の失敗を全体診断へ保持し、元の領域付きcodeは観測から失わない
			if( (failed || read == &observation.instanceIdentity) && read->diagnostic.code != 0U &&
			   inventoryMeasurement_.error == 0) {
				inventoryMeasurement_.error = nativeErrorFromWin32(
					read->diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR
						? read->diagnostic.code
						: ERROR_GEN_FAILURE) ;
			}

			// OSが消失を返したdeviceへ、前段で得たIDを再利用しない
			if( (read->diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
				read->diagnostic.code == ERROR_NO_SUCH_DEVINST) ||
			   (read->diagnostic.domain == DeviceDiagnosticDomain::CONFIGURATION_MANAGER &&
				read->diagnostic.code == CR_NO_SUCH_DEVNODE)) {
				nativeIdentityAvailable = false ;
				// 消失したnodeを全present確認済みへ残しません
				if( indexState) {
					indexState->enumerationError = nativeErrorFromWin32( ERROR_NO_SUCH_DEVINST) ;
				}
			}
		}

		partialFailure = partialFailure || observationFailed ;
		// 同じ現在nodeの元IDとClassGUIDを、表示・現在driver属性とは独立にcaptureします
		if( indexState) {
			indexState->present.push_back( deviceIdentity) ;
			IndexInventoryState::Node node ;	// 当該nodeだけの必要属性を所有します
			node.identity = deviceIdentity ;
			// null/正式Unknown GUIDを公開recordのClassへ補完しません
			if( !IsEqualGUID( device.ClassGuid, GUID_NULL) &&
			   !IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_UNKNOWN)) {
				node.classGuid = normalizeIdentifier( deviceClassGuid) ;
			}

			// Inventory-only transportを互換driverのnative fallbackへ接続しません
			if( !testInventoryTransport_) {
				node.classError = readDeviceClassSnapshot( devices.get(), device, transport,
														  node.classObservation) ;
				// 未確定Classだけを完全な初回証拠で仮照合対象へ進めます
				if( node.classError == 0U && node.classGuid.empty() && nativeIdentityAvailable) {
					DeviceRankSnapshot proof ;	// 元opaqueの独立した全native初回証拠です
					const NativeError  proofError =
						// 完全表のみです
						readDeviceRankSnapshot( instanceId, proof) ;
					// Classと元node/六属性の同時観測が変わった証拠を流用しません
					if( proofError == 0U && proof.noDriver &&
					   proof.classRead.state == observation.deviceClass.state &&
					   proof.classState == node.classObservation.classState &&
					   proof.nativeClassGuid == node.classObservation.nativeClassGuid &&
					   proof.observedClassGuid == node.classObservation.observedClassGuid &&
					   proof.deviceClass == deviceClass &&
					   proof.node.statusFlags == observation.node.statusFlags &&
					   proof.node.problemCode == observation.node.problemCode &&
					   observation.driverKey.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.infName.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.provider.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.version.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.date.state == DevicePropertyReadState::NOT_PRESENT) {
						node.classObservation	 = std::move( proof) ;
						node.initialClassUnknown = true ;
					} else {
						node.classError =
							proofError != 0U ? proofError : nativeErrorFromWin32( ERROR_RETRY) ;
					}
				}
			}

			node.hardwareError	 = readIndexIds( devices.get(), device, DEVPKEY_Device_HardwareIds,
												transport, node.hardware) ;
			node.compatibleError = readIndexIds( devices.get(), device, DEVPKEY_Device_CompatibleIds,
												transport, node.compatible) ;
			// 初回証拠のID順序/種別と同snapshotの公開ID照合素材を一致させます
			if( node.initialClassUnknown) {
				const auto sameIds = []( const std::wstring &left, const std::wstring &right) {
					return left == normalizeIdentifier( right) ;
				} ; // 同期中だけ両秘密値を借用し、正規化した全IDを比較します
				// 二観測の変化を初回候補へ結び直しません
				if( node.hardwareError != 0U || node.compatibleError != 0U ||
				   !std::equal( node.hardware.begin(), node.hardware.end(),
							   node.classObservation.hardwareIds.begin(),
							   node.classObservation.hardwareIds.end(), sameIds) ||
				   !std::equal( node.compatible.begin(), node.compatible.end(),
							   node.classObservation.compatibleIds.begin(),
							   node.classObservation.compatibleIds.end(), sameIds)) {
					node.initialClassUnknown = false ;
					node.classError			 = nativeErrorFromWin32( ERROR_RETRY) ;
				}
			}

			// 有限RAM枠超過は部分一致で成功にせず、両種別を未完了へ残します
			if( node.hardware.size() + node.compatible.size() >
			   index_capacity::NATIVE_INVENTORY_IDS - indexState->retainedIds) {
				indexState->enumerationError = indexState->enumerationError == 0U
												   ? nativeErrorFromWin32( ERROR_MORE_DATA)
												   : indexState->enumerationError ;
			} else {
				indexState->retainedIds += node.hardware.size() + node.compatible.size() ;
				indexState->nodes.push_back( std::move( node)) ;
			}
		}

		// 専用modeとidentity未確認時はnative照合mapを構築しない
		if( execution == nullptr && nativeIdentityAvailable) {
			// WUA candidate を同じ device node へ統合するため全 Hardware/Compatible ID を内部 map
			// に持つ
			// WUA候補との内部照合に使用するHardware ID群
			std::vector<std::wstring> hardwareIds =
				readDeviceStringList( devices.get(), device, DEVPKEY_Device_HardwareIds) ;
			// 同じ照合へ追加するCompatible ID群
			std::vector<std::wstring> compatibleIds =
				readDeviceStringList( devices.get(), device, DEVPKEY_Device_CompatibleIds) ;
			hardwareIds.insert( hardwareIds.end(), compatibleIds.begin(), compatibleIds.end()) ;
			// WUA候補との照合用に、Hardware IDとCompatible IDを同じ正規化表へ登録する
			for( const std::wstring &hardwareId : hardwareIds) {
				const std::wstring normalized = normalizeIdentifier( hardwareId) ;	// 大文字照合key
				// Hardware ID mapへの追加位置と新規追加flag
				const auto [iterator, inserted] =
					hardwareToDevice_.emplace( normalized, deviceIdentity) ;
				// 一つの照合IDが複数deviceを指す場合は誤統合を避けて解決不能にする
				if( !inserted && iterator->second != deviceIdentity) {
					// 一つの ID が複数 device に一致する場合は誤統合を避けて解決不能とする
					iterator->second.clear() ;
				}
			}
		}

		std::vector<UpdateCandidate> deviceCandidates ;	// このdeviceの表示候補群
		std::vector<InstallTarget>	 deviceTargets ;	// Candidate indexと対応する秘密install metadata
		bool foundCurrent{} ;							// trueの場合はcompatible list内で現在packageを特定済み
		bool deviceAssessed{!observationFailed} ;		// 観測とcompatible listがerrorなしの場合true
		bool deviceLimitAffected{} ;					// このdeviceでdriverまたは候補上限に達した場合true

		// 専用modeとidentity未確認時はcompatible list・rank・install targetを生成しない
		if( execution == nullptr && nativeIdentityAvailable) {
			// 互換driverの検索条件を設定できたdeviceだけを履歴列挙へ進める
			if( configureCompatibleDriverSearch( devices.get(), device)) {
				DriverInfoList driverList( devices.get(), device) ;	// Compatible listのRAII guard
				// 互換listの構築成功後にだけRAII解放対象として登録し、nodeを列挙する
				if( driver_store_inf_detail::transport().build( devices.get(), &device,
															  SPDIT_COMPATDRIVER) != FALSE) {
					driverList.markBuilt() ;
					std::unordered_set<std::wstring> deduplicationKeys ;	// INF/version重複検出key
					DWORD enumeratedDriverCount{} ;							// SetupAPIから存在を確認したcompatible node数
					BoundedEnumerationStop driverStop{
						BoundedEnumerationStop::LIMIT} ;	// 上限まで列挙した場合の本体停止理由
					BoundedEnumerationProbe driverProbe{
						BoundedEnumerationProbe::NOT_RUN} ;	// 上限時だけ設定する一回probe結果
					NativeError driverEnumerationError{} ;	// 本体またはprobeの最初の列挙診断値

					// Windows が rank 順に構築した compatible list を並べ替えずに列挙する
					for( DWORD driverIndex = 0; driverIndex < MAXIMUM_DRIVERS_PER_DEVICE;
						++driverIndex) {
						SP_DRVINFO_DATA_W driver{} ;	// 現在列挙中のcompatible driver node
						driver.cbSize = sizeof( driver) ;
						// driver nodeの列挙が終了した時点で正常終端と障害を区別する
						if( driver_store_inf_detail::transport().enumerate(
							   devices.get(), &device, SPDIT_COMPATDRIVER, driverIndex, &driver) ==
						   FALSE) {
							const DWORD error =
								// Driver列挙の正常終端または失敗code
								GetLastError() ;
							// 本体loopの停止理由を保持し、上限到達とは別に後で純粋分類する
							if( error == ERROR_NO_MORE_ITEMS) {
								driverStop = BoundedEnumerationStop::NORMAL_END ;
							} else {
								driverStop			   = BoundedEnumerationStop::API_FAILURE ;
								driverEnumerationError = nativeErrorFromWin32( error) ;
							}

							break ;
						}

						++enumeratedDriverCount ;

						DriverDetail detail ;	// UIへ渡さないINFとsection metadata
						// 詳細を取得できないdriver nodeを飛ばし、そのdeviceの監査不完全を記録する
						if( !readDriverDetail( devices.get(), device, driver, detail)) {
							const DWORD error =
								// Detail取得失敗または不正metadata code
								GetLastError() ;
							partialFailure = true ;
							deviceAssessed = false ;
							// APIが診断を設定しない不正値はERROR_INVALID_DATAとして保持する
							if( inventoryMeasurement_.error == 0) {
								inventoryMeasurement_.error = nativeErrorFromWin32(
									error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
							}

							continue ;
						}

						// 同一 package/version の別 model section
						// は履歴上の別版ではないため一件にまとめる
						// 同一package/versionをまとめるkey
						const std::wstring deduplicationKey =
							normalizedFileName( detail.infFileName) + L"|" +
							std::to_wstring( driver.DriverVersion) ;
						// 同じINF・versionのdriver nodeを重複した候補として追加しない
						if( !deduplicationKeys.insert( deduplicationKey).second) {
							continue ;
						}

						// 現在使用中packageと完全一致する最初のnode
						const bool currentCandidate =
							!foundCurrent && isCurrentDriver( current, detail, driver) ;
						foundCurrent = foundCurrent || currentCandidate ;
						UpdateCandidate candidate ;	// UIへ渡す現在compatible driver候補
						candidate.deviceIdentity = deviceIdentity ;
						candidate.title =
							driver.Description[0] == L'\0' ? deviceName : driver.Description ;
						candidate.manufacturer	  = manufacturer ;
						candidate.model			  = deviceName ;
						candidate.driverClass	  = deviceClass ;
						candidate.deviceClassGuid = deviceClassGuid ;
						candidate.discoveryBus	  = discoveryBus ;
						candidate.provider		  = driver.ProviderName ;
						candidate.version		  = formatDriverVersion( driver.DriverVersion) ;
						candidate.driverDate	  = formatDriverDate( driver.DriverDate) ;
						candidate.sourceName	  = L"Windows Driver Store" ;
						candidate.sourceLocation  = L"ローカル（Windows が検証・格納）" ;
						candidate.discoveryBasis  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
						candidate.action		  = currentCandidate
														? DriverAction::NONE
														: classifyAction( current, driver.DriverVersion) ;
						candidate.current		  = currentCandidate ;
						// 現在版と利用者が選ぶ旧版候補は自動選択の対象にしない
						candidate.recommended = false ;
						candidate.installable = !currentCandidate ;
						candidate.audit		  = makeWindowsManagedCandidateAudit( currentCandidate) ;

						InstallTarget target ;	// 実行直前の再照合に使用する秘密metadata
						target.deviceInstanceId = instanceId ;
						target.infFileName		= detail.infFileName ;
						target.sectionName		= detail.sectionName ;
						target.providerName		= driver.ProviderName ;
						target.driverVersion	= driver.DriverVersion ;
						target.driverDateTicks	= fileTimeTicks( driver.DriverDate) ;
						deviceCandidates.push_back( std::move( candidate)) ;
						deviceTargets.push_back( std::move( target)) ;
					}

					// 512件ちょうどで終端したか、513件目が存在するかを一回だけ確認する
					if( driverStop == BoundedEnumerationStop::LIMIT) {
						SP_DRVINFO_DATA_W probe{} ;	// 保持しない513件目のdriver node metadata
						probe.cbSize = sizeof( probe) ;
						// Probeは候補やinstall targetを追加せず、終端状態だけを取得する
						if( driver_store_inf_detail::transport().enumerate(
							   devices.get(), &device, SPDIT_COMPATDRIVER,
							   MAXIMUM_DRIVERS_PER_DEVICE, &probe) == FALSE) {
							const DWORD error =
								// Driver上限probeの終端または失敗code
								GetLastError() ;
							// ERROR_NO_MORE_ITEMSなら512件を完全なcompatible listとして扱う
							if( error == ERROR_NO_MORE_ITEMS) {
								driverProbe = BoundedEnumerationProbe::NORMAL_END ;
							} else {
								driverProbe			   = BoundedEnumerationProbe::API_FAILURE ;
								driverEnumerationError = nativeErrorFromWin32( error) ;
							}
						} else {
							// 513件目を保持せず、純粋分類へ実要素の存在だけを渡す
							driverProbe = BoundedEnumerationProbe::ELEMENT_FOUND ;
						}
					}

					const auto driverBoundary = classifyBoundedEnumeration(
						static_cast<std::uint64_t>( enumeratedDriverCount),
						static_cast<std::uint64_t>( MAXIMUM_DRIVERS_PER_DEVICE), driverStop,
						driverProbe,
						driverEnumerationError) ;	// Compatible list本体と一回probeの整合済み分類
					// 内部状態の矛盾または列挙不完全を、このdeviceの判定済み状態へ含めない
					if( !driverBoundary) {
						partialFailure = true ;
						deviceAssessed = false ;
						// 分類不能には既存の先行診断を上書きしない共通codeを使う
						if( inventoryMeasurement_.error == 0) {
							inventoryMeasurement_.error = static_cast<NativeError>( E_UNEXPECTED) ;
						}
					} else {
						// 列挙APIまたはprobeの失敗を最初のinventory診断として保持する
						if( driverBoundary->error != 0) {
							partialFailure = true ;
							deviceAssessed = false ;
							// 先に取得した診断値を維持し、最初のdriver列挙失敗だけを公開する
							if( inventoryMeasurement_.error == 0) {
								inventoryMeasurement_.error = driverBoundary->error ;
							}
						}

						// 上限外の実nodeを確認した場合だけ、当該deviceを上限影響へ数える
						if( driverBoundary->limitExceeded) {
							partialFailure		= true ;
							deviceAssessed		= false ;
							deviceLimitAffected = true ;
						}
					}
				} else {
					const DWORD error = GetLastError() ;	// Compatible list構築失敗code
					partialFailure	  = true ;
					deviceAssessed	  = false ;
					// 最初のcompatible list構築失敗だけをinventory診断へ保持する
					if( inventoryMeasurement_.error == 0) {
						inventoryMeasurement_.error = nativeErrorFromWin32( error) ;
					}
				}
			} else {
				const DWORD error = GetLastError() ;	// Compatible search設定失敗code
				partialFailure	  = true ;
				deviceAssessed	  = false ;
				// 最初のcompatible search設定失敗だけをinventory診断へ保持する
				if( inventoryMeasurement_.error == 0) {
					inventoryMeasurement_.error = nativeErrorFromWin32( error) ;
				}
			}
		}

		// 属性読取り待機中の取消し後には未commitのdeviceを公開しない
		if( checkInventoryStop()) {
			break ;
		}

		// 互換list内で現在driverを特定できない場合も現在propertyの表示専用行を残す
		if( !foundCurrent) {
			UpdateCandidate installed ;	// Compatible listで特定不能だった現在版の表示候補
			installed.deviceIdentity  = deviceIdentity ;
			installed.title			  = deviceName ;
			installed.manufacturer	  = manufacturer ;
			installed.model			  = deviceName ;
			installed.driverClass	  = deviceClass ;
			installed.deviceClassGuid = deviceClassGuid ;
			installed.discoveryBus	  = discoveryBus ;
			installed.provider		  = current.provider ;
			installed.version		  = current.version ;
			installed.driverDate	  = current.date ;
			installed.sourceName	  = L"現在のデバイス構成" ;
			installed.sourceLocation  = L"ローカル" ;
			installed.discoveryBasis  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			installed.action		  = DriverAction::NONE ;
			installed.audit			  = makeWindowsManagedCandidateAudit( true) ;
			installed.current		  = true ;
			installed.recommended	  = false ;
			deviceCandidates.insert( deviceCandidates.begin(), std::move( installed)) ;
			// 通常履歴だけにcandidateと対応するtarget領域を持たせる
			if( execution == nullptr) {
				deviceTargets.insert( deviceTargets.begin(), InstallTarget{}) ;
			}
		} else {
			// 現在使用中候補のvector内位置
			const auto currentIterator =
				std::find_if( deviceCandidates.begin(), deviceCandidates.end(),
							 []( const UpdateCandidate &candidate) { return candidate.current ; }) ;
			// 現在行が先頭でない場合は候補と導入targetを同時に移動して対応を保つ
			if( currentIterator != deviceCandidates.end() &&
			   currentIterator != deviceCandidates.begin()) {
				// Candidateとtargetを同時に回転するindex
				const std::size_t currentIndex = static_cast<std::size_t>(
					std::distance( deviceCandidates.begin(), currentIterator)) ;
				std::rotate( deviceCandidates.begin(), currentIterator, currentIterator + 1) ;
				std::rotate( deviceTargets.begin(), deviceTargets.begin() + currentIndex,
							deviceTargets.begin() + currentIndex + 1) ;
			}
		}

		bool		currentRepresented{} ;		// 現在版行を候補集合へ追加できた場合true
		std::size_t appendedCandidateCount{} ;	// このdeviceで全体結果へ追加できた候補数
		// UI に渡す identity は session 内の連番とし、秘密性のある native identifier を含めない
		for( std::size_t index = 0; index < deviceCandidates.size(); ++index) {
			// 現在版補完行を含む各追加の直前に全体上限を検査する
			if( result.candidates.size() >= MAXIMUM_TOTAL_CANDIDATES) {
				partialFailure		  = true ;
				deviceAssessed		  = false ;
				deviceLimitAffected	  = true ;
				candidateLimitReached = true ;
				break ;
			}

			UpdateCandidate &candidate = deviceCandidates[index] ;	// Identityを付与する表示候補
			candidate.identity		   = L"store:" + std::to_wstring( scanSessionId) + L":" +
								 std::to_wstring( deviceIndex) + L":" + std::to_wstring( index) ;
			candidate.providerId = std::wstring( DRIVER_STORE_PROVIDER_ID) ;
			// 現在構成の代表行だけへ観測を結合し、更新候補へ複製しない
			if( candidate.current) {
				candidate.deviceObservation = observation ;
			}

			// 専用modeで取得対象を示すidentityを発行しない
			if( execution == nullptr) {
				candidate.packageIdentity = L"driver-store-node:" + candidate.identity ;
			}

			// install可能な候補だけを現在sessionの指定導入routingへ登録する
			if( candidate.installable) {
				installTargets_.emplace( candidate.identity, std::move( deviceTargets[index])) ;
			}

			currentRepresented = currentRepresented || candidate.current ;
			result.candidates.push_back( std::move( candidate)) ;
			++appendedCandidateCount ;
		}

		// 代表行があり実identityも確認できたdeviceだけを秘密mapへ登録する
		if( currentRepresented && execution == nullptr && nativeIdentityAvailable) {
			deviceInstances_.emplace( deviceIdentity, std::move( instanceId)) ;
		}

		// 上限到達後に未追加候補または後続deviceがある場合だけ打切りとして扱う
		if( result.candidates.size() >= MAXIMUM_TOTAL_CANDIDATES &&
		   (appendedCandidateCount < deviceCandidates.size() || deviceIndex + 1U < deviceCount)) {
			partialFailure		  = true ;
			deviceAssessed		  = false ;
			deviceLimitAffected	  = true ;
			candidateLimitReached = true ;
		}

		assessedDeviceCount += deviceAssessed ? 1U : 0U ;
		// Driver上限だけに達したdeviceは一件として有限な理由集計へ加える
		if( deviceLimitAffected) {
			++limitAffectedDeviceCount ;
		}

		const std::uint64_t completed =	// 現在deviceまでの詳細処理完了件数
			static_cast<std::uint64_t>( deviceIndex) + 1 ;
		progressCallback(
			{.stage			  = ProviderStage::SCANNING_DEVICES,
			 .percentComplete = static_cast<std::uint32_t>( completed * 100 / deviceCount),
			 .completedItems  = completed,
			 .totalItems	  = deviceCount}) ;

		// 全候補上限後は未収録deviceを候補化せず、既知の残数を理由件数へ加える
		if( candidateLimitReached) {
			limitAffectedDeviceCount += static_cast<std::uint64_t>( deviceCount - deviceIndex - 1U) ;
			break ;
		}
	}

	// present deviceがない場合も列挙完了を進捗へ反映する
	if( deviceCount == 0 && !checkInventoryStop()) {
		progressCallback( {.stage = ProviderStage::SCANNING_DEVICES, .percentComplete = 100}) ;
	}

	std::uint64_t representedDeviceCount{} ;		// 公開できた一意な現在版行数
	std::uint64_t missingManufacturerCount{} ;		// 現在版行のmanufacturer欠損数
	std::uint64_t missingClassCount{} ;				// 現在版行のsetup class欠損数
	std::uint64_t missingVersionCount{} ;			// 現在版行のdriver version欠損数
	std::uint64_t missingAttributeDeviceCount{} ;	// 一つ以上の表示属性が欠けた現在node数
	// 最終候補の現在版だけを一巡し、表示済み母数と属性欠損を確定する
	for( const UpdateCandidate &candidate : result.candidates) {
		// 非現在版はinventory母数と属性欠損へ加えない
		if( !candidate.current) {
			continue ;
		}

		++representedDeviceCount ;
		missingManufacturerCount += candidate.manufacturer.empty() ? 1U : 0U ;
		missingClassCount += candidate.driverClass.empty() ? 1U : 0U ;
		missingVersionCount += candidate.version.empty() ? 1U : 0U ;
		missingAttributeDeviceCount += candidate.manufacturer.empty() ||
											   candidate.driverClass.empty() ||
											   candidate.version.empty()
										   ? 1U
										   : 0U ;
	}

	inventoryMeasurement_.representedDeviceCount   = {representedDeviceCount,
													  MeasurementExtent::EXACT} ;
	inventoryMeasurement_.missingManufacturerCount = {missingManufacturerCount,
													  MeasurementExtent::EXACT} ;
	inventoryMeasurement_.missingClassCount		   = {missingClassCount, MeasurementExtent::EXACT} ;
	inventoryMeasurement_.missingCurrentVersionCount = {missingVersionCount,
														MeasurementExtent::EXACT} ;
	// 同じ列挙集合の観測下限から実際に表現できた現在版を引き、確定度は昇格させない
	if( observedDeviceCount >= representedDeviceCount) {
		inventoryMeasurement_.unrepresentedDeviceCount = {
			observedDeviceCount - representedDeviceCount,
			deviceEnumerationComplete ? MeasurementExtent::EXACT : MeasurementExtent::LOWER_BOUND} ;
	} else {
		// 同一information set内で母数が逆転した場合は計測を信用可能な値として公開しない
		inventoryMeasurement_.unrepresentedDeviceCount = {std::nullopt,
														  MeasurementExtent::UNAVAILABLE} ;
		partialFailure								   = true ;
	}

	inventoryMeasurement_.detailedEnumerationComplete =
		deviceEnumerationComplete && !partialFailure && assessedDeviceCount == deviceCount &&
		representedDeviceCount == deviceCount ;
	// 同一deviceの複数属性欠損を一件として理由内訳へ残す
	if( missingAttributeDeviceCount != 0) {
		inventoryMeasurement_.reasons.push_back( {MeasurementReason::MISSING_ATTRIBUTE,
												 MeasurementUnit::DEVICE,
												 missingAttributeDeviceCount}) ;
	}

	// 上限に影響されたことが確定したnodeだけをdevice単位で記録する
	if( limitAffectedDeviceCount != 0) {
		inventoryMeasurement_.reasons.push_back(
			{MeasurementReason::LIMIT_REACHED, MeasurementUnit::DEVICE, limitAffectedDeviceCount}) ;
	}

	// 詳細判定できなかった既知nodeは、列挙数との差を下限として保持する
	if( observedDeviceCount > assessedDeviceCount) {
		inventoryMeasurement_.reasons.push_back( {MeasurementReason::INCOMPLETE,
												 MeasurementUnit::DEVICE,
												 observedDeviceCount - assessedDeviceCount}) ;
	}

	// 必要属性以外の欠損・履歴失敗をID照合の完了軸へ混ぜません
	if( indexState) {
		indexState->enumerationComplete =
			deviceEnumerationComplete && indexState->present.size() == deviceCount &&
			!checkInventoryStop() && indexState->enumerationError == 0U ;
		// Capture前の消失診断を正常終端で上書きしません
		if( indexState->enumerationError == 0U) {
			indexState->enumerationError = deviceEnumerationError ;
		}

		// 二巡目消失や停止だけは元inventory診断を保持します
		if( !indexState->enumerationComplete && indexState->enumerationError == 0U) {
			indexState->enumerationError = inventoryMeasurement_.error ;
		}

		// 全nodeの移動が終わってからviewを作り、vector再確保で秘密keyを失効させません
		for( std::size_t ordinal = 0U; ordinal < indexState->nodes.size(); ++ordinal) {
			const auto &node = indexState->nodes[ordinal] ;	// 発行後不変の秘密captureです
			// HardwareとCompatibleの両集合を同じ原nodeへ結びます
			for( const auto &ids : {std::cref( node.hardware), std::cref( node.compatible)}) {
				// 捕捉した全秘密IDのviewだけを原ordinalへ登録します
				for( const auto &id : ids.get()) {
					indexState->idNodes[id].push_back( ordinal) ;
				}
			}

			// 一方の属性だけ成功したnodeも、元union全体の失敗診断を保持します
			if( node.hardwareError != 0U || node.compatibleError != 0U) {
				indexState->failedIdNodes[node.classGuid].push_back( ordinal) ;
			}
		}

		indexInventory_ = std::move( indexState) ;
	}

	scanSessionId_ = execution == nullptr ? scanSessionId : 0U ;
	// 未処理集合は元scanで一度だけ作り、導入後に追加しません
	for( const auto &entry : deviceInstances_) {
		pendingIndexDevices_.insert( entry.first) ;
	}

	result.succeeded = true ;
	result.outcome	 = partialFailure ? OutcomeCode::SUCCEEDED_WITH_ERRORS : OutcomeCode::SUCCESS ;
	// 現在属性だけの列挙を従来のcompatible driver判定数へ数えない
	result.coverage.assessedDeviceCount = execution == nullptr ? assessedDeviceCount : 0U ;
	// Cancel・全体期限停止では、現在行を保持しても正常scan成功を返さない
	if( execution != nullptr && execution->checkpoint() != 0) {
		result.succeeded = false ;
		indexInventory_.reset() ;
		result.error   = execution->checkpoint() ;
		result.outcome = execution->sessionStopReason() == MetadataSearchReason::CANCELLED
							 ? OutcomeCode::ABORTED
							 : OutcomeCode::FAILURE ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 直前のscanで実際に観測したlocal inventory計測を取得する
 * @return Providerが所有する計測値への参照。次のscan、installまたは失効まで有効である
 * @note 生のdevice識別子を含まず、呼出し元はworker thread内でだけ参照する
 */
//------------------------------------------------------------------------------
const DeviceInventoryMeasurement &DriverStoreProvider::inventoryMeasurement() const noexcept
{
	return inventoryMeasurement_ ;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 原deviceの未処理Uまたは当該実行Sへの所属を照合します
 * @param[in] device 元opaque deviceです
 * @return 未消費または当該scopeへ予約済みだけtrueです
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::ownsInstallDevice( const std::wstring_view device) const noexcept
{
	return std::ranges::any_of( pendingIndexDevices_,
							   [&]( const auto &entry) { return entry == device ; }) ||
		   (activeInstallOperation_ != 0U &&
			std::ranges::find( activeIndexDevices_, device) != activeIndexDevices_.end()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の実行操作が元計画の端末を予約しているか確認します
 * @param[in] qualification 同じDriver Storeが確認した選択と作用です
 * @return 同じ発行元、スキャン、threadと操作中の元索引端末ならtrueです
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::ownsActiveScopedInfInstall(
	const ScopedInfInstallQualification &qualification) const noexcept
{
	return qualification.owner == this && qualification.session != 0U &&
		   qualification.session == scanSessionId_ && GetCurrentThreadId() == ownerThreadId_ &&
		   activeInstallOperation_ != 0U &&
		   std::ranges::find( activeIndexDevices_, qualification.deviceIdentity) !=
			   activeIndexDevices_.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元deviceまたは同active親に結ぶ一時的な必要子を照合します
 * @param[in] device 同bindingのopaque identityです
 * @param[in] workspace 元byteを所有する同じ保護領域です
 * @param[in] package 元計画で選択された同じpackageです
 * @return 元deviceまたは同scopeで全項一致した必要子ならtrueです
 * @note 新しいscan候補や外部から指定可能な子権限を発行しません
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::ownsBindingDevice( const std::wstring_view			 device,
											const OfficialDownloadWorkspace &workspace,
											const OfficialInfPackage		&package) const noexcept
{
	const auto *proof = activeRequiredChild_ ;	// 同同期操作だけの借用です
	// 導出子と異なる元scan deviceの資格を変更しません
	if( (!proof || proof->childIdentity != device) && ownsInstallDevice( device)) {
		return true ;
	}

	// 別operation、thread、元親、元内容や未知roleから子の権限を作りません
	if( !proof || proof->session == 0U || proof->session != scanSessionId_ ||
	   proof->operation == 0U || proof->operation != activeInstallOperation_ ||
	   GetCurrentThreadId() != ownerThreadId_ || proof->parentBindingToken == 0U ||
	   proof->parentIdentity.empty() || proof->childIdentity != device ||
	   proof->childIdentity == proof->parentIdentity || proof->parentInstance.empty() ||
	   proof->childInstance.empty() || !proof->inspection || !proof->plan || !proof->observation ||
	   proof->package != &package || proof->inspection->workspace.get() != &workspace ||
	   !indexInventory_ || installProofInventory_ != indexInventory_ ||
	   proof->inspection->scanSessionId != proof->session ||
	   proof->plan->session_ != proof->session ||
	   proof->roleIndex >= proof->plan->members_.size() ||
	   !std::ranges::any_of(
		   activeInstallDevices_,
		   [&]( const auto &value) { return std::wstring_view{value} == proof->parentIdentity ; }) ||
	   !ownsInstallDevice( proof->parentIdentity)) {
		return false ;
	}

	const auto &member = proof->plan->members_[proof->roleIndex] ;	// 同原計画の一役割です
	// 異なるroleや元packageを同じ子へ差し替えません
	if( member.role != DriverPlanRole::DRIVER_COMPONENT ||
	   member.parentPackageOrdinal >= proof->plan->selectedPackages_.size() ||
	   (member.parentPackageOrdinal != 0U &&
		proof->plan->selectedPackages_[member.parentPackageOrdinal].role !=
			DriverPlanRole::EXTENSION) ||
	   member.packageOrdinal >= proof->inspection->requiredInfPackages.size() ||
	   &proof->inspection->requiredInfPackages[member.packageOrdinal] != &package) {
		return false ;
	}

	const auto parentBinding =
		// 同issuerの元親です
		officialInfInstallBindings_.find( proof->parentBindingToken) ;
	// 親bindingと同不変planが失われた場合は継続しません
	if( parentBinding == officialInfInstallBindings_.end() ||
	   parentBinding->second.scanSessionId != proof->session ||
	   parentBinding->second.deviceIdentity != proof->parentIdentity ||
	   parentBinding->second.device.deviceInstanceId != proof->parentInstance ||
	   parentBinding->second.requiredPlan.get() != proof->plan) {
		return false ;
	}

	// 元親と実列挙子が同じ秘密mapに固定されていることを確認します
	const auto contains = [&]( const std::wstring_view identity, const std::wstring_view instance) {
		return std::ranges::any_of( deviceInstances_, [&]( const auto &entry) {
			return std::wstring_view{entry.first} == identity &&
				   std::wstring_view{entry.second} == instance ;
		}) ;
	} ;
	return contains( proof->parentIdentity, proof->parentInstance) &&
		   contains( proof->childIdentity, proof->childInstance) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元同scanの選択scopeと未処理所有を当該操作へ結びます
 * @param[in] operationId 当該新操作です
 * @param[in] session 未失効の元scanです
 * @param[in] identities 元表示の選択candidate subsetです
 * @return 元scopeの全件照合成功0、それ以外は拒否HRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::beginInstallOperation(
	const OperationId operationId, const ScanSessionId session,
	const std::span<const std::wstring> identities)
{
	std::vector<std::wstring> devices ;	// 元mapからだけ選択deviceを求めます
	// 別候補やnative値を外から補完しません
	for( const auto &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// 元発行候補です
		// 存在しない候補から予約を作りません
		if( target == installTargets_.end()) {
			return E_INVALIDARG ;
		}

		const auto device = std::ranges::find(
			deviceInstances_, target->second.deviceInstanceId,
			[]( const auto &entry) { return entry.second ; }) ;	// 同nativeの元opaqueです
		// 元native対応を失った候補を使いません
		if( device == deviceInstances_.end()) {
			return E_INVALIDARG ;
		}

		devices.push_back( device->first) ;
	}

	return bindInstallDevices( operationId, session, devices) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Compositeで検証した元device subsetを当該操作へ拘束します
 * @param[in] operationId 新しいInstall操作です
 * @param[in] session 未失効の元scanです
 * @param[in] devices 元発行の一意なdevice subsetです
 * @param[in] allowEmpty WUAだけの操作にnative実行scopeを作らず元ownerを保持する内部指定です
 * @return 成功0、stale/不明/重複は失敗です。native変更は行いません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::bindInstallDevices( const OperationId					operationId,
													const ScanSessionId					session,
													const std::span<const std::wstring> devices,
													const bool							allowEmpty)
{
	// 別scan/thread、旧操作、二重操作を予約前に拒否します
	if( session == 0U || session != scanSessionId_ || ownerThreadId_ != GetCurrentThreadId() ||
	   operationId == 0U || operationId <= lastAcceptedInstallOperation_ ||
	   activeInstallOperation_ != 0U || (!allowEmpty && devices.empty()) ||
	   devices.size() > 4096U) {
		return E_INVALIDARG ;
	}

	std::unordered_set<std::wstring> unique ;	// 全件検証後だけcommitします
	std::vector<std::wstring>		 pending ;	// 確保失敗時に元集合を変えません
	// 同scanの未処理deviceだけを一度ずつ予約します
	for( const auto &device : devices) {
		// 新device/消費済みdevice/重複を権限へ追加しません
		if( !deviceInstances_.contains( device) || !pendingIndexDevices_.contains( device) ||
		   !unique.insert( device).second) {
			return E_INVALIDARG ;
		}

		pending.push_back( device) ;
	}

	activeInstallDevices_.swap( pending) ;
	activeInstallOperation_		  = operationId ;
	lastAcceptedInstallOperation_ = operationId ;
	installEntered_				  = false ;
	return 0 ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実Provider入口を通った当該操作だけを消費対象へ記録します
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::markInstallEntered() noexcept
{
	installEntered_ = activeInstallOperation_ != 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元同scanの選択scopeと未処理所有を当該操作へ結びます
 * @param[in] operationId 当該新操作です
 * @param[in] session 未失効の元scanです
 * @return 当該操作の原未消費subsetです。不明な操作は空です
 */
//------------------------------------------------------------------------------
std::optional<InstallRetentionSummary> DriverStoreProvider::finishInstallOperation(
	const OperationId operationId, const ScanSessionId session)
{
	// 他操作の終端から残存所有を公開しません
	if( operationId == 0U || operationId != activeInstallOperation_ || session != scanSessionId_) {
		return std::nullopt ;
	}

	InstallRetentionSummary retained{operationId, session, installEntered_, {}, {}} ;	// 元subsetです
	// 実行入口を通ったdeviceの候補だけを消費します
	if( installEntered_) {
		// 元集合の各要素を同じscopeへ一度ずつ照合します
		for( const auto &device : activeInstallDevices_) {
			const auto native = deviceInstances_.find( device) ;	// 元所有の対応です
			pendingIndexDevices_.erase( device) ;
			// 他deviceの候補や元native対応は破棄しません
			if( native != deviceInstances_.end()) {
				std::erase_if( installTargets_, [&]( const auto &entry) {
					return entry.second.deviceInstanceId == native->second ;
				}) ;
			}
		}
	}

	// 同selected deviceの未使用tokenも一括終了し、old eventから再検査許可を作りません
	if( installEntered_) {
		std::erase_if( officialInfInstallBindings_, [&]( const auto &entry) {
			return std::ranges::find( activeInstallDevices_, entry.second.deviceIdentity) !=
				   activeInstallDevices_.end() ;
		}) ;
		std::erase_if( officialInstallerBindings_, [&]( const auto &entry) {
			return std::ranges::find( activeInstallDevices_, entry.second.identity) !=
				   activeInstallDevices_.end() ;
		}) ;
	}

	// 未消費の実targetだけを同scanの元opaqueへ結びます
	for( const auto &entry : installTargets_) {
		const auto device =
			std::ranges::find( deviceInstances_, entry.second.deviceInstanceId,
							  []( const auto &item) { return item.second ; }) ;	// 同nativeです
		// 原対応を失った候補を継続しません
		if( device != deviceInstances_.end() && pendingIndexDevices_.contains( device->first)) {
			retained.candidates.push_back( {entry.first, device->first}) ;
		}
	}

	activeInstallDevices_.clear() ;
	activeInstallOperation_ = 0U ;
	installEntered_			= false ;
	return retained ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択された local driver node を再照合して device へ導入する。選択された local driver node を再照合して deviceへ導入する。 注記
 *        : scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合する
 * @param[in] scanSessionId 選択元の Driver Store scan session ID
 * @param[in] identities UI に提示済みの opaque identity 群
 * @param[in] parentWindowNative device installer の親 HWND を整数表現で渡す値。 device installer の親 HWNDを整数表現で渡
 *                   す値
 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先
 * @return 選択候補ごとの導入結果
 * @note scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合する
 */
//------------------------------------------------------------------------------
InstallResult DriverStoreProvider::install( const ScanSessionId				   scanSessionId,
										   const std::span<const std::wstring> identities,
										   const std::uintptr_t				   parentWindowNative,
										   const ProviderProgressCallback	  &progressCallback)
{
	InstallResult result{} ;	// 選択identity順で個別結果を保持するinstall結果
	result.updates.reserve( identities.size()) ;
	// 後続検証の成否にかかわらず、全選択identityへ個別結果を返す領域を用意する
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	// stale session、別 thread、空または不明 selection は system state を変える前に拒否する
	std::unordered_set<std::wstring> uniqueIdentities ;	// 重複検証済みidentity集合
	std::unordered_set<std::wstring> uniqueDevices ;	// 一device一候補を検証するnative ID集合
	// 空の選択、失効session、所有thread外からの導入要求は全体失敗にしてsessionを破棄する
	if( identities.empty() || scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// Identityの重複、scan session内の存在、および一device一候補を事前検証する
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時に保持した秘密target検索結果
		// 未知候補、候補の重複、一deviceへの複数指定は導入前に全件拒否する
		if( !uniqueIdentities.insert( identity).second || target == installTargets_.end() ||
		   !uniqueDevices.insert( target->second.deviceInstanceId).second) {
			result.downloadOutcome = OutcomeCode::FAILURE ;
			result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
			result.installOutcome  = OutcomeCode::FAILURE ;
			result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}
	}

	result.downloadOutcome = OutcomeCode::SUCCESS ;
	markInstallEntered() ;
	// Local Driver Store候補は追加downloadを必要としないため全件を成功扱いにする
	for( UpdateExecutionResult &update : result.updates) {
		update.downloadOutcome = OutcomeCode::SUCCESS ;
	}

	progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
					  .percentComplete = 20,
					  .completedItems  = identities.size(),
					  .totalItems	   = identities.size()}) ;
	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 20,
					  .completedItems  = 0,
					  .totalItems	   = identities.size()}) ;

	std::size_t successCount{} ;	// Installに成功したselection数
	NativeError lastError{} ;		// 最後に発生したinstall error。全成功時は0
	// 元の選択順を維持し、各候補を再照合して個別結果へ反映する
	for( std::size_t index = 0; index < identities.size(); ++index) {
		bool rebootRequired{} ;	// 現在targetが再起動を要求した場合はtrue
		lastError = installTarget( installTargets_.at( identities[index]), parentWindowNative,
								  rebootRequired) ;
		UpdateExecutionResult &update = result.updates[index] ;	// 現在targetの個別結果
		update.rebootRequired		  = rebootRequired ;
		result.rebootRequired		  = result.rebootRequired || rebootRequired ;
		// 指定nodeの導入が成功した候補だけを成功件数へ含める
		if( lastError == 0) {
			update.installOutcome = OutcomeCode::SUCCESS ;
			++successCount ;
		} else {
			update.installOutcome = OutcomeCode::FAILURE ;
			update.installError	  = lastError ;
		}

		const std::uint64_t completed = index + 1 ;	// 現在までに導入を試行した候補数
		progressCallback(
			{.stage			  = ProviderStage::INSTALLING,
			 .percentComplete = static_cast<std::uint32_t>( 20 + completed * 80 / identities.size()),
			 .completedItems  = completed,
			 .totalItems	  = identities.size()}) ;
	}

	result.succeeded = successCount == identities.size() ;
	result.installOutcome =
		successCount == identities.size()
			? OutcomeCode::SUCCESS
			: (successCount == 0 ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	result.installError = result.succeeded ? 0 : lastError ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA の Hardware ID と一致する local device の opaque identity を取得する
 * @param[in] hardwareId WUA が返した Hardware ID。外部へ公開しない
 * @return 現在の scan で一致する device identity。曖昧または未検出なら `std::nullopt`
 */
//------------------------------------------------------------------------------
std::optional<std::wstring> DriverStoreProvider::deviceIdentityForHardwareId(
	const std::wstring_view hardwareId) const
{
	// 空のHardware IDからdeviceを推測しない
	if( hardwareId.empty()) {
		return std::nullopt ;
	}

	// 正規化Hardware IDに対応するlocal device検索結果
	const auto iterator = hardwareToDevice_.find( normalizeIdentifier( hardwareId)) ;
	// 端末内で一意な照合先が得られないHardware IDは候補へ結び付けない
	if( iterator == hardwareToDevice_.end() || iterator->second.empty() ||
	   !deviceInstances_.contains( iterator->second)) {
		return std::nullopt ;
	}

	return iterator->second ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式catalog snapshotへ端末内限定binding fingerprintを付与する。公式catalog snapshotへ端末内bindingを付与する。Opaque
 *        identityをworker内mapでnative IDへ解決し、全件成功した場合だけfingerprintを反映する。生IDは返さない
 * @param[in] secret 管理者保護stateから読み取った端末固有HMAC key。 管理者保護stateの端末固有HMAC key
 * @param[in,out] devices 現在scanのopaque identityを持つ非機密snapshot。 現在scanの公式catalog用snapshot
 * @return 全deviceへ付与できた場合は0、session、identity、CNG失敗時はHRESULT。 全deviceへ付与できた場合は0、入力またはCNG失敗時はHRESULT
 * @note Native device instance IDは本関数から返さず、network、UI、logへ渡さない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::attachLocalOfficialBindingFingerprints(
	const LocalOfficialBindingSecret &secret, const std::span<OfficialCatalogDevice> devices) const
{
	constexpr std::size_t MAXIMUM_BINDING_DEVICES = 4'096U ;	// 一scanの付与件数上限
	// 有効な所有threadのscanと上限内のsnapshotだけにbindingを付与する
	if( scanSessionId_ == 0U || GetCurrentThreadId() != ownerThreadId_ ||
	   devices.size() > MAXIMUM_BINDING_DEVICES) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::unordered_set<std::wstring> identities ;	// Opaque identity重複検出集合
	std::vector<std::wstring>		 fingerprints ;	// 全件成功まで保持するHMAC結果
	identities.reserve( devices.size()) ;
	fingerprints.reserve( devices.size()) ;
	// 現在scanのopaque identityを一件ずつnative IDへ解決して不可逆化する
	for( const OfficialCatalogDevice &device : devices) {
		const auto instance =	// Worker内だけで参照するnative instance ID検索結果
			deviceInstances_.find( device.deviceIdentity) ;
		// 空、重複、現在scanに存在しないdevice identityはbinding対象にしない
		if( device.deviceIdentity.empty() || !identities.insert( device.deviceIdentity).second ||
		   instance == deviceInstances_.end()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::wstring	  fingerprint ;	// 現在deviceの端末内HMAC表記
		const NativeError error = makeLocalOfficialDeviceBindingFingerprint(
			secret, instance->second, fingerprint) ;	// Native ID不可逆化結果
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( error != 0) {
			return error ;
		}

		fingerprints.push_back( std::move( fingerprint)) ;
	}

	// 全件の生成成功後だけcallerのsnapshotを更新する
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		devices[index].localBindingFingerprint = std::move( fingerprints[index]) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief G11-Cで分離した一つのINFを現在deviceのrankとread-onlyで比較する。G11-Cで分離した一INFのPnP具体性とrankを監査する。現在driverと単一候
 *        補INFのWindows rankをread-onlyで取得し、ID具体性とrankが退行しない場合だけApplicableとする
 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID
 * @param[in] deviceIdentity UIへ提示済みのopaque device identity
 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace
 * @param[in] package G11-Cで構造を検証した一つのINF package。 G11-Cで構造検証した一INF package
 * @param[out] audit PnP ID文字列を含まない具体性とrankの監査結果。 PnP ID文字列を含まない監査結果
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 拒否を含む監査判定の生成時は0、入力またはSetupAPI失敗時はHRESULT。 拒否を含む監査判定の生成時は0、処理失敗時はHRESULT
 * @note 戻り値0だけでinstallを許可せず、auditのApplicableを別途確認する
 * @note Driver Storeへのstage、driver選択、installまたはdevice state変更を行わない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::auditOfficialInfRank( const ScanSessionId	  scanSessionId,
													  const std::wstring_view deviceIdentity,
													  const OfficialDownloadWorkspace &workspace,
													  const OfficialInfPackage		  &package,
													  OfficialDriverRankAudit		  &audit,
													  InfFailureDiagnostic *diagnostic) const
{
	InfFailureDiagnostic failure ;	// 同評価内で最初の元失敗だけを保持します
	const NativeError	 result = [&]() -> NativeError {
		   audit			   = {} ;
		   const auto instance =	// Opaque identityからworker内のnative IDを得る検索結果
			   deviceInstances_.find( std::wstring( deviceIdentity)) ;
		   const std::optional<std::uint64_t> candidateVersion =
			   // Candidateのpacked version
			   parseDriverVersion( package.driverVersion) ;
		   // session、device、INF metadata、数値版の前提が揃わないrank監査要求を拒否する
		   if( scanSessionId == 0 || scanSessionId != scanSessionId_ ||
			  GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
			  instance == deviceInstances_.end() || package.infRelativePath.empty() ||
			  package.className.empty() || package.providerName.empty() ||
			  package.hardwareIds.empty() || !candidateVersion.has_value()) {
			   markInfFailure( &failure, InfDiagnosticStage::INPUT,
							  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			   return static_cast<NativeError>( E_INVALIDARG) ;
		   }

		   SYSTEM_INFO nativeSystem{} ;	// Native OS architectureの取得先
		   driver_store_inf_detail::transport().architecture( &nativeSystem) ;
		   // x64以外の実OSではこのINF監査経路を使用しない
		   if( nativeSystem.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
			   return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		   }

		   const std::wstring candidateInfPath =	// SetupAPIへ渡すworkspace内INF絶対path
			   workspace.path( package.infRelativePath) ;
		   // 展開先から候補INFを解決できなければ監査を開始しない
		   if( candidateInfPath.empty()) {
			   markInfFailure( &failure, InfDiagnosticStage::INPUT,
							  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			   return static_cast<NativeError>( E_INVALIDARG) ;
		   }

		   const DWORD attributes = GetFileAttributesW( candidateInfPath.c_str()) ;	// INFのfile属性
		   // 候補INFの属性取得失敗は元のWindows診断値で返す
		   if( attributes == INVALID_FILE_ATTRIBUTES) {
			   const DWORD error = GetLastError() ;	// 元属性APIの原codeです
			   markInfFailure( &failure, InfDiagnosticStage::INF_ATTRIBUTES,
							  InfDiagnosticOrigin::NATIVE_API, error) ;
			   return nativeErrorFromWin32( error) ;
		   }

		   // ディレクトリや再解析点を候補INFとして監査しない
		   if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
			   return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		   }

		   // Rank取得前に固定するdeviceと現在driver metadata
		   DeviceRankSnapshot before ;
		   failure.phase = InfDiagnosticPhase::CURRENT_BEFORE ;
		   NativeError nativeError =
			   // 取得結果
			   readDeviceRankSnapshot( instance->second, before, &failure) ;
		   // 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		   if( nativeError != 0) {
			   return nativeError ;
		   }

		   std::optional<std::uint32_t> currentRank ;	// 現在driverのWindows full rank
		   // Native未導入に現在rankを仮定せず、既知driverだけを非退行比較します
		   if( !before.noDriver) {
			   failure.phase = InfDiagnosticPhase::CURRENT_RANK ;
			   nativeError	 = collectMatchingDriverRank(
				 instance->second, std::nullopt, before.currentDriver.infFileName,
				 before.currentDriver.provider, before.currentDriver.packedVersion.value(),
				 std::nullopt, currentRank, {}, nullptr, nullptr, &failure) ;
		   }

		   // 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		   if( nativeError != 0) {
			   return nativeError ;
		   }

		   std::optional<std::uint32_t> candidateRank ;				// 単一candidate INFのWindows full rank
		   std::wstring					candidateInfClassGuid ;		// 同検査済み実INFのClassです
		   std::wstring					candidateNativeClassGuid ;	// Windows互換一覧のClassです
		   failure.phase = InfDiagnosticPhase::CANDIDATE_RANK ;
		   nativeError	 = collectMatchingDriverRank(
			 instance->second, std::wstring_view( candidateInfPath), candidateInfPath,
			 package.providerName, candidateVersion.value(), std::nullopt, candidateRank,
			 package.className, &candidateInfClassGuid, &candidateNativeClassGuid, &failure) ;
		   // 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		   if( nativeError != 0) {
			   return nativeError ;
		   }

		   DeviceRankSnapshot after ;	// Rank取得後に再取得するdeviceと現在driver metadata
		   failure.phase = InfDiagnosticPhase::CURRENT_AFTER ;
		   nativeError	 = readDeviceRankSnapshot( instance->second, after, &failure) ;
		   // 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		   if( nativeError != 0) {
			   return nativeError ;
		   }

		   // 監査中にdevice状態が変化した場合は結果を採用せず再確認を要求する
		   if( !deviceRankSnapshotsEqual( before, after)) {
			   markInfFailure( &failure, InfDiagnosticStage::STATE_MATCH,
							  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			   return nativeErrorFromWin32( ERROR_RETRY) ;
		   }

		   // 既知device GUIDと候補GUIDの違いをClass名一致だけで通しません
		   if( before.classState == OfficialDriverRankDeviceClassState::KNOWN_CLASS &&
			  before.nativeClassGuid != candidateNativeClassGuid) {
			   markInfFailure( &failure, InfDiagnosticStage::DEVICE_CLASS_MATCH,
							  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			   return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		   }

		   const OfficialDriverRankEvidence evidence{
			   // Pure evaluatorへ渡すworker内限定根拠
			   .deviceClass				= before.deviceClass,
			   .candidateClass			= package.className,
			   .deviceHardwareIds		= before.hardwareIds,
			   .deviceCompatibleIds		= before.compatibleIds,
			   .candidateIds			= package.hardwareIds,
			   .currentMatchingDeviceId = before.matchingDeviceId,
			   .currentRank				= currentRank,
			   .candidateRank			= candidateRank,
			   .currentState		  = before.noDriver ? OfficialDriverRankCurrentState::NO_DRIVER
														: OfficialDriverRankCurrentState::KNOWN_DRIVER,
			   .deviceClassState	  = before.classState,
			   .candidateInfClassGuid = candidateInfClassGuid,
			   .candidateNativeClassGuid = candidateNativeClassGuid,
		   } ;
		   // rank判定に必要な証拠が整合しなければ監査成功としない
		   if( !evaluateOfficialDriverRank( evidence, audit)) {
			   markInfFailure( &failure, InfDiagnosticStage::RANK_EVIDENCE,
							  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			   return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		   }

		   return 0 ;
	}() ; // 元制御/戻値のまま、外で同errorへ診断を閉じます
	// 任意出力だけへ非機密な失敗値をcopyします
	if( diagnostic) {
		*diagnostic = failure ;
	}

	return finishInfFailure( diagnostic, InfDiagnosticPath::FULL_RANK_AUDIT, result) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 現在版を要求せず単一INFのWindows compatible nodeを観測する
 * @param[in] scanSessionId 現在inventoryのsession
 * @param[in] deviceIdentity 当該sessionのopaque device identity
 * @param[in] workspace 検証済みINF閉包の所有領域
 * @param[in] package 内容と署名を検証したINF
 * @param[out] candidateRank 一致nodeの最小Windows rank。非適用・失敗時は空
 * @param[out] diagnostic 任意の元失敗leafです。null可、実行判定には使いません
 * @return 全列挙完了時0、入力・SetupAPI・有限上限違反時はHRESULT
 * @note 空結果とAPI失敗を区別する。現在driverとの順位比較や導入許可は発行しない。Workerから呼び、staging、driver選択、installを行わない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::observeInfCandidateRank(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::optional<std::uint32_t> &candidateRank, InfFailureDiagnostic *diagnostic) const
{
	InfFailureDiagnostic failure ;	// 同評価内で最初の元失敗だけを保持します
	const NativeError	 result = [&]() -> NativeError {
		   candidateRank.reset() ;
		   // Session、所有thread、有限なopaque IDを先に確認する
		   if( scanSessionId == 0 || scanSessionId != scanSessionId_ ||
			  GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
			  deviceIdentity.size() > 256U) {
			   markInfFailure( &failure, InfDiagnosticStage::INPUT,
							  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			   return static_cast<NativeError>( E_INVALIDARG) ;
		   }

		   try {
			   const auto instance =
				   // 秘密native ID
				   deviceInstances_.find( std::wstring( deviceIdentity)) ;
			   const auto version = parseDriverVersion( package.driverVersion) ;	// 候補だけの明示版
			   const std::wstring path = workspace.path( package.infRelativePath) ;	// 保護された単一INF
			   // 現在版や表示名を要求せず、候補の固定metadataと対象identityを確認する
			   if( instance == deviceInstances_.end() || !version || path.empty() ||
				  package.providerName.empty() || package.hardwareIds.empty()) {
				   markInfFailure( &failure, InfDiagnosticStage::INPUT,
								  InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
				   return static_cast<NativeError>( E_INVALIDARG) ;
			   }

			   const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// INFの現在属性
			   // Fileを読めない失敗をPnP非適用へ変換しない
			   if( attributes == INVALID_FILE_ATTRIBUTES) {
				   const DWORD error = GetLastError() ;	// 元属性APIの原codeです
				   markInfFailure( &failure, InfDiagnosticStage::INF_ATTRIBUTES,
								  InfDiagnosticOrigin::NATIVE_API, error) ;
				   return nativeErrorFromWin32( error) ;
			   }

			   // 通常file以外をSetupAPIへ渡さない
			   if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
				   return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
			   }

			   failure.phase		   = InfDiagnosticPhase::CANDIDATE_RANK ;
			   const NativeError error = collectMatchingDriverRank(
				   instance->second, std::wstring_view( path), path, package.providerName, *version,
				   std::nullopt, candidateRank, package.className, nullptr, nullptr,
				   &failure) ;	// Windowsの適合観測
			   // 部分列挙に成功したnodeがあっても、全列挙失敗なら結果を公開しない
			   if( error != 0) {
				   candidateRank.reset() ;
			   }

			   return error ;
		   } catch( const std::bad_alloc &) {
			   candidateRank.reset() ;
			   return static_cast<NativeError>( E_OUTOFMEMORY) ;
		   }
	}() ; // 元制御/戻値のまま、外で同errorへ診断を閉じます
	// 任意出力だけへ非機密な失敗値をcopyします
	if( diagnostic) {
		*diagnostic = failure ;
	}

	return finishInfFailure( diagnostic, InfDiagnosticPath::CANDIDATE_OBSERVATION, result) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 元端末とINFの対象クラスを読み取りで確認する
 * @param[in] instance 元scanの端末の非公開識別子
 * @param[in] package 元INFの識別と対象クラス
 * @param[out] effects 対象クラスと元端末の読み取り結果
 * @return 確認できた場合0、失敗時はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readDeclarativeClassObservation( const std::wstring		 &instance,
											const OfficialInfPackage &package,
											DeclarativeClassEffects	 &effects)
{
	const auto &transport = driver_store_inf_detail::transport() ;	// 元端末を開いた同じAPI表
	// 独自クラスの表がない試験では実Windowsの値を読み取りません
	if( !transport.declarativeClass) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	GUID target{} ;	// 元INFに宣言された導入先GUID
	// 完全な対象GUIDでだけクラス登録を照会します
	if( FAILED( IIDFromString( package.classGuid.c_str(), &target))) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	SetLastError( ERROR_SUCCESS) ;
	DeviceInfoSet devices(
		// 元端末を読み取る情報集合
		transport.create( nullptr, nullptr), transport.inventory) ;
	SP_DEVINFO_DATA source{} ;	// 一覧構築前の端末の実クラス
	source.cbSize = sizeof( source) ;
	// 互換一覧構築が書き換える前の元端末を開きます
	if( !devices.valid() || !transport.open( devices.get(), instance.c_str(), nullptr, 0U, &source)) {
		const DWORD error = GetLastError() ;	// 元Windows診断
		return nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
	}

	return observeDeclarativeClassEffects( devices.get(), source, target, package.className,
										  transport.declarativeClass->observation, effects) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択端末の上位フィルターを元PnPインスタンスから読み直します
 * @param[in] instance 同issuerが元選択に固定した実端末のインスタンスIDです
 * @param[out] observed 成功時の状態、型と元バイトです。途中失敗時は空です
 * @return 別フィルターを失わず原値を観測できた場合0、その他は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError readSelectedWifiBusUpperFilters( const std::wstring &instance,
											MtdHandlerProperty &observed)
{
	observed			  = {} ;
	const auto &transport = driver_store_inf_detail::transport() ;	// 同issuerが使う端末API表です
	SetLastError( ERROR_SUCCESS) ;
	DeviceInfoSet	devices( transport.create( nullptr, nullptr),
							transport.inventory) ;	// 元端末を再読取りするための集合です
	SP_DEVINFO_DATA device{} ;						// 今回開いた元端末を示す情報です
	device.cbSize = sizeof( device) ;
	// 上位フィルターを別の端末やクラスの観測から補いません
	if( !devices.valid() || !transport.open( devices.get(), instance.c_str(), nullptr, 0U, &device)) {
		const auto error = GetLastError() ;	// 端末を開くAPIの元診断です
		return nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
	}

	return observeWifiBusUpperFilters( devices.get(), device, transport.inventory.property,
									  observed) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式Netの実選択が使う元媒体と同梱依存を現在の端末で照合します
 * @param[in] inf 元アーカイブの全一覧と同じ署名付きの展開閉包です
 * @param[in] selected 現在の端末で確定した同一INFの実選択です
 * @param[in] instance 元PnPインスタンスです。外部へ公開しません
 * @param[out] effects 元媒体と標準イベント資源の証拠です。失敗時は空です
 * @param[out] wifiBus 元選択に同梱依存がある場合の現状態です。失敗時は空です
 * @return 元閉包と現在状態の全照合が成立した場合0、その他は元HRESULTです
 * @pre 同じ公式署名レコードと保護領域、Windowsの一意な選択を確認済みです
 * @note 読取り専用です。登録や導入資格を発行しません
 */
//------------------------------------------------------------------------------
NativeError observeScopedNetworkInstallEffects( const CollectorInfContentInspection &inf,
											   const OfficialInfPackage			   &selected,
											   const std::wstring				   &instance,
											   OfficialScopedNetworkEffects		   &effects,
											   std::optional<ScopedWifiBusInstallEvidence> &wifiBus)
{
	effects = {} ;
	wifiBus.reset() ;
	try {
		std::optional<ScopedWifiBusInstallEvidence> observed ;	// 同じ選択でだけ作る現在状態です
		const ScopedInboxNeedsVerifier verify = [&]( const OfficialInfInstallInventory &inventory) {
			return inspectScopedWifiBusDependencies(
				*inf.workspace, inf.closure, inf.scopedDependencyArchiveEntries, inventory,
				inf.scanSessionId, &observed.emplace().dependencies) ;
		} ; // 元CABの同じ全一覧と選択を同期中だけ用います
		OfficialScopedNetworkEffects current ;	// 同じ目標端末の元媒体とWindows資源です
		auto						 error = verifySelectedScopedNetworkInfEffects(
			*inf.workspace, inf.closure.entries, selected, current,
			// 元選択の診断です
			inf.scopedDependencyArchiveEntries.empty() ? nullptr : &verify) ;
		// 同梱INFや元媒体を照合できない場合は端末効果を返しません
		if( error != 0U) {
			return error ;
		}

		// 仮想Wi-Fiバスに置き換える元選択だけは現在の端末の原値も保ちます
		if( observed) {
			error = readSelectedWifiBusUpperFilters( instance, observed->upperFilters) ;
			// 既存フィルターや読み取り不明を照合済みとして扱いません
			if( error != 0U) {
				return error ;
			}
		}

		effects = std::move( current) ;
		wifiBus = std::move( observed) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 独自クラスの指定導入で起動または変更し得る既存登録を確認する
 * @param[in] effects 型付きで読み取ったクラスと端末の状態
 * @return 別のインストーラーやフィルターの評価を必要としない場合true
 * @note プロパティページはこの導入経路では呼び出さない
 */
//------------------------------------------------------------------------------
bool declarativeEffectsSupported( const DeclarativeClassEffects &effects) noexcept
{
	const std::array properties{
		&effects.classInstaller,	&effects.classCoInstallers,	 &effects.classUpperFilters,
		&effects.classLowerFilters, &effects.deviceCoInstallers, &effects.deviceUpperFilters,
		&effects.deviceLowerFilters} ;	// 未知の実行または構成変更につながる登録
	return effects.registration != SetupClassRegistration::UNOBSERVED &&
		   std::ranges::none_of( properties, []( const auto *property) {
			   return property->state == MtdHandlerState::PRESENT ;
		   }) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名付きストレージ候補の一意な選択から、同梱INFへの空導入を確認する
 * @param[in] scanSessionId 元の検索セッション
 * @param[in] deviceIdentity 同セッションが所有する端末の不透明ID
 * @param[in] inspection 同じ元CATと全閉包を確認した内容検査結果
 * @param[in] modelsSection 同じ署名レコードの現在OS用Models節
 * @param[in] requiredHardwareId 同じ元レコードに結ぶ完全Hardware ID
 * @param[in] observedRank 同じ元INFについて直前に観測したWindowsの順位
 * @param[out] delegated 委譲宣言、実選択、同梱署名が一致した場合true。失敗と通常選択はfalse
 * @return 読取り成功0、不一致、途中変化または読取り失敗はHRESULT
 * @note 同一発行元の所有スレッドで同期読取りを行い、登録や導入資格は発行しない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::observeStorageInboxNullDriver(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const CommonInfInspection &inspection, const std::wstring &modelsSection,
	const std::wstring_view requiredHardwareId, const std::uint32_t observedRank,
	bool &delegated) const
{
	delegated = false ;
	// 検査済みの同一元端末と元INF以外から委譲を推定しない
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   inspection.scanSessionId != scanSessionId || GetCurrentThreadId() != ownerThreadId_ ||
	   !ownsInstallDevice( deviceIdentity) || !validIndexNativeId( requiredHardwareId) ||
	   !inspection.workspace || inspection.closure.packages.size() != 1U ||
	   inspection.closure.packages.front().inspectionPurpose !=
		   OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) {
		return E_ACCESSDENIED ;
	}

	try {
		const auto &package = inspection.closure.packages.front() ;						// 元CAT検証済みのストレージINF
		const auto instance = deviceInstances_.find( std::wstring{deviceIdentity}) ;	// 元端末の秘密ID
		const auto version =
			// Windows互換ノードと比較する版
			parseDriverVersion( package.driverVersion) ;
		const auto date =
			// Windows互換ノードと比較する日付
			normalizeInfDriverDate( package.driverDate) ;
		const auto path =
			// 同じ保護された元INF
			inspection.workspace->path( package.infRelativePath) ;
		// 不完全な入力から元ModelsやWindows選択を再構成しない
		if( instance == deviceInstances_.end() || !version || !date || path.empty()) {
			return E_INVALIDARG ;
		}

		auto			   error = reverifyCommonDriverInf( inspection) ;	// 元CATと全閉包の再確認結果
		DeviceRankSnapshot before ;											// 同じ操作内の現在機器と使用中ドライバー
		// 元ファイルに変化がない場合に限り、端末の現在状態を読む
		if( error == 0U) {
			error = readDeviceRankSnapshot( instance->second, before) ;
		}

		// 読取り失敗は通常選択として続けない
		if( error != 0U) {
			return error ;
		}

		const auto readNode = [&]( CandidateDriverNodeSnapshot &value) {
			return collectUniqueCandidateDriverNode( instance->second, path, package.className,
													package.providerName, *version, *date, value,
													true) ;
		} ; // 同一端末の単一INF互換一覧だけを同期借用し、全IDを読む
		CandidateDriverNodeSnapshot node ;	// 曖昧さのないWindowsの選択
		error = readNode( node) ;
		// 複数最良、別順位、別クラスは委譲の根拠にしない
		if( error != 0U || node.rank != observedRank ||
		   normalizeIdentifier( package.classGuid) != normalizeIdentifier( node.infClassGuid) ||
		   node.classGuid != node.infClassGuid) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		OfficialInfPackage selected ;	// 同じ選択節が持つ元の必要関係
		error = inspectSelectedOfficialInfRelations(
			*inspection.workspace, inspection.closure.entries, package, node.sectionName, selected) ;
		bool matched{} ;	// 元選択の同梱委譲宣言を確認したか
		// 実選択の読み取りが成立した場合だけ元の委譲宣言を照合する
		if( error == 0U) {
			error = inspectSelectedStorageNullDriverDelegation(
				*inspection.workspace, inspection.closure.entries, selected, modelsSection,
				node.modelIds, matched) ;
		}

		// 通常のドライバー行は既存の適用判定に戻し、異常な宣言では結果を発行しない
		if( error != 0U || !matched) {
			return error ;
		}

		// 元署名が指すHardware IDから別の互換行や現在の別機器へ読み替えない
		if( node.modelIds.empty() ||
		   normalizeIdentifier( node.modelIds.front()) != normalizeIdentifier( requiredHardwareId) ||
		   !containsScopedHardwareId( before.hardwareIds, requiredHardwareId)) {
			return E_ACCESSDENIED ;
		}

		error = verifyWindowsInboxNullDriver() ;
		CandidateDriverNodeSnapshot confirmed ;	// 同梱INFの確認直後に取り直す互換ノード
		// 信頼が成立しない場合はいずれの観測も確定しない
		if( error == 0U) {
			error = readNode( confirmed) ;
		}

		DeviceRankSnapshot after ;	// 同梱INFの確認直後の現在機器と使用中ドライバー
		// 再列挙に成功した場合だけ端末属性を再確認する
		if( error == 0U) {
			error = readDeviceRankSnapshot( instance->second, after) ;
		}

		// 確認中に選択や端末が変わった場合は元の判断を確定させない
		if( error != 0U || !candidateNodeSnapshotsEqual( node, confirmed) ||
		   !deviceRankSnapshotsEqual( before, after)) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		delegated = true ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 端末の一意なWindows互換nodeを保護INFの現在Models行へ照合し、実ドライバーのクラス作用と順位を確認する
 * @param[in] scanSessionId 現在の検索セッション
 * @param[in] deviceIdentity 同セッションの非公開端末識別子
 * @param[in] workspace 元INFの内容検査を保持する保護領域
 * @param[in] package 端末の独自クラスの内容検査結果
 * @param[in] expectedSha256 照合済みの元INFハッシュ
 * @param[in] modelsSection 元recordが使う現在OSのModels節
 * @param[out] role 元行の確認時にだけ返す作用
 * @param[out] rankAudit 実ドライバーの元行と端末の順位証拠。空サービスまたは失敗では空
 * @param[in,out] diagnostic 指定導入の作用照会の失敗段階を保持する任意の診断
 * @param[out] qualification 任意の出力先。仕様内の実選択だけを保持する
 * @return Windows選択と元行を確認した場合0、その他はHRESULT
 * @note 曖昧なnodeの選択、staging、導入資格の発行は行わない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::observeDeclarativeInfModelRole(
	ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::wstring_view expectedSha256, const std::wstring &modelsSection,
	OfficialInfSelectedModelRole &role, std::optional<OfficialDriverRankAudit> &rankAudit,
	InfFailureDiagnostic									  *diagnostic,
	std::shared_ptr<const DeclarativeInfInstallQualification> *qualification) const
{
	role = OfficialInfSelectedModelRole::UNASSESSED ;
	rankAudit.reset() ;
	// 照合できなかった候補に前回の観測を残しません
	if( qualification) {
		qualification->reset() ;
	}

	// 実端末を観測する所有スレッドと内容用途を限定する
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
	   deviceIdentity.size() > 256U ||
	   package.inspectionPurpose != OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ||
	   workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   expectedSha256.size() != 64U || modelsSection.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto instance =
			// 同検索で所有する端末
			deviceInstances_.find( std::wstring( deviceIdentity)) ;
		const auto version = parseDriverVersion( package.driverVersion) ;	// 元INFに記載された版
		const auto date = normalizeInfDriverDate( package.driverDate) ;		// Windowsのnodeと比較する日付
		const auto path = workspace.path( package.infRelativePath) ;		// 同内容検査の元INF
		// 完全な元identityがそろった場合だけ互換nodeを照会する
		if( instance == deviceInstances_.end() || !version || !date || path.empty() ||
		   package.className.empty() || package.classGuid.empty() || package.providerName.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		CandidateDriverNodeSnapshot node ;	// 一意なWindows選択の非公開情報
		const auto					error = collectUniqueCandidateDriverNode(
			 instance->second, path, package.className, package.providerName, *version, *date, node,
			 true) ;	// 元INFだけに限定した選択結果
		// 互換nodeがない場合や同じ最良順位が複数ある場合は元診断を返す
		if( error != 0) {
			return error ;
		}

		// 元INFのGUIDとWindowsが選んだ互換nodeのGUIDを両方照合する
		if( normalizeIdentifier( package.classGuid) != normalizeIdentifier( node.infClassGuid) ||
		   node.classGuid != node.infClassGuid) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		OfficialInfSelectedModelRole selected{} ;	// Windowsが選んだ元Models行の作用
		std::optional<OfficialInfDeclarativeClassRegistration>
				   registration ;	// 同元行に結び付いたクラス登録
		const auto modelError = inspectOfficialInfSelectedModelRole(
			workspace, package, expectedSha256, modelsSection, node.sectionName, node.modelIds,
			selected, &registration) ;	// 選択行とクラス登録の検査結果
		// 照合できた実ドライバー行だけが指定導入用のクラス観測を必要とします
		if( modelError != 0U || selected != OfficialInfSelectedModelRole::KERNEL_DRIVER) {
			role = selected ;
			return modelError ;
		}

		DeclarativeClassEffects effects ;	// 元端末のクラスと導入先の登録観測
		const auto				classError =
			 registration ? readDeclarativeClassObservation( instance->second, package, effects)
									  : nativeErrorFromWin32(
								ERROR_INVALID_DATA) ;	// 元クラス節が成立した場合だけ端末を照会する
		// クラス作用の照会失敗はModelsの不一致から区別します
		if( classError != 0U) {
			markInfFailure( diagnostic, InfDiagnosticStage::DECLARATIVE_CLASS_EFFECTS,
						   InfDiagnosticOrigin::UNRECORDED) ;
			return classError ;
		}

		DeviceRankSnapshot			current ;	// 順位の前後で固定する同じ端末の状態
		CandidateDriverNodeSnapshot confirmed ;	// 元Models行との一致を求める再列挙結果
		OfficialDriverRankAudit		audit ;		// 選んだ一行から生成するWindows順位の評価
		const auto					rankError = collectOfficialInfBindingState(
			 instance->second, path, package, *version, *date, current, confirmed, audit, nullptr,
			 &node) ;	// 保護元行を固定した端末と順位の照合結果
		// 順位を確定できなかった元行を適合として集計しません
		if( rankError != 0U || current.nativeClassGuid != formatClassGuid( effects.sourceClass)) {
			markInfFailure( diagnostic, InfDiagnosticStage::RANK_EVIDENCE,
						   InfDiagnosticOrigin::UNRECORDED) ;
			return rankError != 0U ? rankError : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// 既存作用を評価できる元選択だけを私有計画として保持します
		if( qualification && audit.decision == OfficialDriverRankDecision::APPLICABLE &&
		   declarativeEffectsSupported( effects)) {
			*qualification = std::make_shared<const DeclarativeInfInstallQualification>(
				DeclarativeInfInstallQualification{
					this, scanSessionId, std::wstring( deviceIdentity), &workspace, &package,
					modelsSection, std::move( *registration), std::move( current),
					std::move( confirmed), std::move( effects)}) ;
		}

		role	  = selected ;
		rankAudit = audit ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 公式配布が指定した元行を一意なWindows nodeと現在の端末HardwareIdsへ結びます
 * @param[in] scanSessionId 現在の検索セッションです
 * @param[in] deviceIdentity 同セッションが所有する端末の不透明IDです
 * @param[in] workspace 検査対象の元INFを所有する保護領域です
 * @param[in] closure 公式Models証拠を持つ基本INFと全必要参照です
 * @param[in] modelsSection 同じ署名レコードの元Models節です
 * @param[out] selected 元行が確定した場合だけ公式ID、元行番号と導入節を返します
 * @param[out] selectedRelations 同じ元行の実導入節と必要関係です。失敗時は空です
 * @param[out] rankAudit 同じ端末・同じnodeを再確認して得た順位です
 * @return 全条件成立時0、その他は元HRESULTです
 * @note 端末と元ファイルを読取専用で確認します。変更や導入資格の発行は行いません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::observeScopedInfModel(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	const std::wstring_view modelsSection, OfficialInfScopedModelMatch &selected,
	OfficialInfPackage &selectedRelations, std::optional<OfficialDriverRankAudit> &rankAudit) const
{
	selected = {} ;
	rankAudit.reset() ;
	// 同じ閉包の元パッケージを結果で上書きしないようエイリアスを拒否します
	if( !closure.packages.empty() && &closure.packages.front() == &selectedRelations) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	selectedRelations = {} ;
	// 元ModelsとWindowsの実選択を合わせた局所の観測結果
	ScopedInfObservation observed ;
	// 元の一覧と現在デバイスの選択を再照合した診断値
	const auto error = observeScopedInfModelState( scanSessionId, deviceIdentity, workspace, closure,
												  modelsSection, observed) ;
	// 照合が成立した場合だけ公式行とWindowsの実選択を出力します
	if( error == 0U) {
		selected		  = std::move( observed.row) ;
		selectedRelations = std::move( observed.relations) ;
		rankAudit		  = observed.rank ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ端末に対する公式行・Windowsの一意選択・順位と実導入節を観測します
 * @param[in] scanSessionId 同workerの現在スキャンです
 * @param[in] deviceIdentity 同スキャンに属する端末の不透明IDです
 * @param[in] workspace 同じ元INFを保持する保護領域です
 * @param[in] closure 元の公式Models証拠付きINFと全参照です
 * @param[in] modelsSection 元署名レコードで指定した節です
 * @param[out] observation 同じ状態を全条件で確認した場合だけの内部結果です
 * @return 安定した実選択と現在状態の読み取り成功時0、元拒否はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::observeScopedInfModelState(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	const std::wstring_view modelsSection, ScopedInfObservation &observation) const
{
	observation = {} ;
	// 元scanの所有スレッド・保護領域・単一の有効な対象という条件を確認します
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
	   deviceIdentity.size() > 256U || closure.packages.size() != 1U ||
	   workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   modelsSection.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 閉包中の唯一の基本INF。現在の選択照合中だけ借用します
	const auto &package = closure.packages.front() ;
	// 収集時の公式範囲を保持した基本ドライバーだけをこの照合へ進めます
	if( package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
	   package.role != DriverPlanRole::BASE_DRIVER || !package.scopedModels) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		// 元scanが保持する内向きの端末実体へ解決した位置
		const auto instance = deviceInstances_.find( std::wstring{deviceIdentity}) ;
		// 候補の元バージョンの厳格な変換結果
		const auto version = parseDriverVersion( package.driverVersion) ;
		// Windows互換ノードの元日付と比較できる候補側の正規化結果
		const auto date = normalizeInfDriverDate( package.driverDate) ;
		// 元INFを開くために参照する保護作業領域のパス
		const auto path = workspace.path( package.infRelativePath) ;
		// 元scanの端末、版・日付と発行元・クラスの証拠が欠けている選択を拒否します
		if( instance == deviceInstances_.end() || !version || !date || path.empty() ||
		   package.className.empty() || package.classGuid.empty() || package.providerName.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::vector<std::wstring> hardwareBefore ;	// 元端末の完全なHardwareIdsです
		// 実選択の確認前に、同じ端末から完全Hardware ID列を読み取った診断値
		auto					  error = readScopedHardwareIds( instance->second, hardwareBefore) ;
		// 端末の元IDを確定できない場合は公式行の適用性を判断しません
		if( error != 0U || hardwareBefore.empty()) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_NOT_FOUND) ;
		}

		CandidateDriverNodeSnapshot node ;	// 実Windowsの唯一最良nodeです
		error = collectUniqueCandidateDriverNode( instance->second, path, package.className,
												 package.providerName, *version, *date, node, true) ;
		// Windowsが選ぶ一意の互換ノードを取得できない場合は元診断を返します
		if( error != 0U) {
			return error ;
		}

		// Windowsの互換ノードと実INFのクラスが元配布のクラスに一致することを確認します
		if( normalizeIdentifier( package.classGuid) != normalizeIdentifier( node.infClassGuid) ||
		   node.classGuid != node.infClassGuid) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		OfficialInfScopedModelMatch observed ;	// 原行の全確認後だけ呼出元へ移します
		OfficialInfPackage			relations ;	// 同じ元行の選択節と必要関係です
		error =
			inspectSelectedScopedInfRelations( workspace, closure.entries, package, modelsSection,
											  node.sectionName, node.modelIds, observed, relations) ;
		// 元Modelsの行と現在のWindows選択が一致しない場合は順位確認へ進みません
		if( error != 0U) {
			return error ;
		}

		DeviceRankSnapshot			current ;	// 順位の前後で状態を固定した同じ端末です
		CandidateDriverNodeSnapshot confirmed ;	// 元行を選んだnodeの再列挙です
		// 同じ端末について既存ドライバーと公式候補の順位を比較した評価結果
		OfficialDriverRankAudit		audit ;
		error = collectOfficialInfBindingState( instance->second, path, package, *version, *date,
											   current, confirmed, audit, nullptr, &node) ;
		// 実機の順位を確定できない場合は元診断を返します
		if( error != 0U) {
			return error ;
		}

		std::vector<std::wstring> hardwareAfter ;	// 同じ端末の完全な再観測です
		error = readScopedHardwareIds( instance->second, hardwareAfter) ;
		// 観測後の端末を同じ元選択へ固定し直せない場合は結果を確定しません
		if( error != 0U) {
			return error ;
		}

		// 別の時点の順位とHardwareIdsを同じ一観測へ併合しません
		if( hardwareAfter != hardwareBefore ||
		   !std::ranges::equal( hardwareAfter, current.hardwareIds,
							   []( const std::wstring &key, const std::wstring &id) {
								   return key == normalizeIdentifier( id) ;
							   })) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// CompatibleIdsへの一致や順位だけを公式HardwareIdsの証拠へ補完しません
		if( !containsScopedHardwareId( hardwareAfter, observed.hardwareId)) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		relations.selectedNativeRank = audit.candidateRank ;
		observation = {instance->second,	std::move( current),	  std::move( confirmed),
					   std::move( observed), std::move( relations), audit} ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 認証済み元配布と一意な現在の選択・作用を同じ不変計画に結びます
 * @param[in] session 現在のスキャンです
 * @param[in] device 元操作が選択した不透明な端末IDです
 * @param[in] content 元検査が所有する不変の配布物閉包です
 * @param[in] hint 取得時に元署名・レコード・配布物へ結び付けた値です
 * @param[in] original 同じ認証済み領域の原レコードです
 * @param[out] qualification 同じ端末・取得物・元行・作用を確認した内部計画です
 * @return 全検査が成立した場合0、元拒否はHRESULTです
 * @pre 呼出し側で元署名と元取得許可、期限および元CABの実バイトを再確認します
 * @note 読取りだけを行い、登録や導入のトークンを作りません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::buildScopedInfInstallQualification(
	const ScanSessionId session, const std::wstring_view device,
	const std::shared_ptr<const CollectorDriverPackageContent> &content,
	const IndexedDriverArchiveHint &hint, const IndexDistributionRecord &original,
	std::shared_ptr<const ScopedInfInstallQualification> &qualification) const
{
	qualification.reset() ;
	// 元索引レコードの公式Models証拠。現在の選択を照合する間だけ借用します
	const auto &proof = original.scopedModelsEvidence ;
	// 署名済みレコードが指定する元Models節のUTF-8
	const auto &sourceSection = original.publishedIdentityEvidence.modelSection ;
	// 元scanと現端末、標準INFの取得経路、署名済みの元証拠がそろうことを確認します
	if( session == 0U || session != scanSessionId_ || GetCurrentThreadId() != ownerThreadId_ ||
	   device.empty() || device.size() > 256U || !content || original.recordSchemaVersion != 6U ||
	   original.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE || !proof ||
	   original.scopedModelsEvidenceSha256 != proof->evidenceSha256 ||
	   original.originalBytes.empty() || sourceSection.empty() || sourceSection.size() > 1'016U ||
	   hint.indexSha256.size() != 64U ||
	   !std::ranges::all_of( hint.indexSha256, []( const wchar_t digit) {
		   return (digit >= L'0' && digit <= L'9') || (digit >= L'a' && digit <= L'f') ;
	   })) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		// 元索引レコードの実SHA-256を受け取る所有文字列
		std::wstring originalHash ;
		// 元レコードの原文を以前の候補ヒントに再結合するハッシュ計算結果
		auto		 error = computeBytesSha256( original.originalBytes, originalHash) ;
		// 元レコードの原文が同じ候補ヒントのハッシュに結び付かない場合は発行を拒否します
		if( error != 0U || originalHash != hint.recordSha256) {
			return error != 0U ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		std::array<wchar_t, 254U> section{} ;	// 元codecと同じWindows節名の上限です
		// 元Models節名を不正文字の置換なしでWindows文字列へ変換した文字数
		const auto length = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, sourceSection.data(),
												static_cast<int>( sourceSection.size()),
												section.data(), static_cast<int>( section.size())) ;
		// UTF-8をWindowsの元節名へ変換できなければ該当節として扱いません
		if( length <= 0) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 元の節名と照合するため変換バッファーから同期中だけ借用する範囲
		const std::wstring_view modelName{section.data(), static_cast<std::size_t>( length)} ;
		error = reverifyIndexedScopedDriverPackage( session, hint, *proof, *content) ;
		// 実取得内容を元証拠に確認できなかった場合は資格を発行しません
		if( error != 0U) {
			return error ;
		}

		// 検査済み内容が保持する単一の元INF。資格の構築中は内容の所有が継続します
		const auto			&inf = content->infs.front() ;
		// 現端末で選択したWindowsノード、その元Models行と順位の組立て先
		ScopedInfObservation observed ;
		error = observeScopedInfModelState( session, device, *inf.workspace, inf.closure, modelName,
										   observed) ;
		// 同じ元行で順位が適用可と確定した場合だけ資格を作ります
		if( error != 0U || observed.rank.decision != OfficialDriverRankDecision::APPLICABLE) {
			return error != 0U ? error : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		OfficialScopedNetworkEffects effects ;					// 元ファイルと現在Windowsイベント資源です
		std::optional<ScopedWifiBusInstallEvidence> wifiBus ;	// 同じ端末の同梱作用とフィルターです
		error = observeScopedNetworkInstallEffects( inf, observed.relations, observed.instance,
												   effects, wifiBus) ;
		// 同梱作用または元フィルターが未確認なら資格を発行しません
		if( error != 0U) {
			return error ;
		}

		qualification =
			std::make_shared<const ScopedInfInstallQualification>( ScopedInfInstallQualification{
				this, session, std::wstring{device}, content, hint.indexSha256,
				std::move( originalHash), proof->evidenceSha256, std::wstring{modelName},
				std::move( observed), std::move( effects), std::move( wifiBus)}) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 私有計画の同じ取得物、署名記録と生存する端末の実選択・作用を読み直します
 * @param[in] session 同じ元のスキャンです
 * @param[in] device 同じ端末の不透明IDです
 * @param[in] content 同じ元取得を所有する不変閉包です
 * @param[in] hint 元取得を指定した索引とレコードのhashです
 * @param[in] original 同じ認証済み領域の元レコードです
 * @param[in] qualification 取得後に確認した元の私有計画です
 * @return 元の完全観測と現在が一致した場合0、元拒否はHRESULTです
 * @pre 呼出し側で元署名・元取得許可・期限および元CABを再確認します
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateScopedInfInstallQualification(
	const ScanSessionId session, const std::wstring_view device,
	const std::shared_ptr<const CollectorDriverPackageContent> &content,
	const IndexedDriverArchiveHint &hint, const IndexDistributionRecord &original,
	const std::shared_ptr<const ScopedInfInstallQualification> &qualification) const
{
	// 元の資格が同じ所有者・端末・署名済み原取得に対するものかを確認します
	if( !qualification || qualification->owner != this || qualification->session != session ||
	   qualification->deviceIdentity != device || qualification->content != content ||
	   qualification->indexSha256 != hint.indexSha256 ||
	   qualification->recordSha256 != hint.recordSha256 ||
	   original.scopedModelsEvidenceSha256 != qualification->evidenceSha256) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 同じ元取得を現在状態で検査し直して得る、新しい比較用の資格
	std::shared_ptr<const ScopedInfInstallQualification> fresh ;
	// 現在の端末選択と導入作用を再検査した診断値
	const auto											 error =
		buildScopedInfInstallQualification( session, device, content, hint, original, fresh) ;
	// 現在の資格を再計算できない場合は保留中の資格で導入を続けません
	if( error != 0U) {
		return error ;
	}

	// 元節、Windows選択、同梱依存または作用に差があれば再確認を要求します
	if( fresh->modelsSection != qualification->modelsSection ||
	   !qualification->observed.sameSelection( fresh->observed) ||
	   qualification->effects != fresh->effects || qualification->wifiBus != fresh->wifiBus) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief トークンに保持した私有計画と同じ元選択・現在状態・作用を確認します
 * @param[in] qualification 元取得を所有する同じ発行元の計画です
 * @param[out] current 全照合に成功した場合だけ同じ現在観測を返します
 * @return 端末、行、順位とファイル作用が一致した場合0です
 * @note 元署名の有効期限と取得許可の検査は実行側が別に行います
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::reobserveScopedInfInstallQualification(
	const ScopedInfInstallQualification &qualification, ScopedInfObservation &current) const
{
	current = {} ;
	// 自分が発行し保護領域を保持する単一INFの資格だけを現在状態へ照合します
	if( qualification.owner != this || !qualification.content ||
	   qualification.content->infs.size() != 1U || !qualification.content->infs.front().workspace) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元資格が所有する検査済みINF。再観測が終わるまで借用します
	const auto			&inf = qualification.content->infs.front() ;
	// 直前に現在デバイスの同じ元行と順位を観測した結果の格納先
	ScopedInfObservation observed ;
	// 元資格の現在の選択とWindowsの候補を再照合した診断値
	auto error = observeScopedInfModelState( qualification.session, qualification.deviceIdentity,
											*inf.workspace, inf.closure,
											qualification.modelsSection, observed) ;
	// 現在の観測が発行時と異なる場合は元資格での導入を終了します
	if( error != 0U || !qualification.observed.sameSelection( observed)) {
		return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	OfficialScopedNetworkEffects				effects ;	// 同じ選択の元媒体と現在Windows資源です
	std::optional<ScopedWifiBusInstallEvidence> wifiBus ;	// 同じ端末の同梱作用と現在原値です
	error = observeScopedNetworkInstallEffects( inf, observed.relations, observed.instance, effects,
											   wifiBus) ;
	// 元資格から変化したフィルター、同梱作用や現サービスを適用しません
	if( error != 0U || qualification.effects != effects || qualification.wifiBus != wifiBus) {
		return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	current = std::move( observed) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検査済みの公式元行を同じDriver Storeの一scanトークンに固定します
 * @param[in] session 同じ検索スキャンです
 * @param[in] device 計画と同じ対象の不透明IDです
 * @param[in] qualification 同じ元配布・端末と作用を照合した不変計画です
 * @param[in] expectedCurrentProvider 検索時に固定された現在の提供元です
 * @param[in] expectedCurrentVersion 検索時に固定された現在のバージョンです
 * @param[in] expectedCurrentDate 検索時に固定された現在の日付です
 * @param[out] binding 同じ計画に対応する既存形式のトークンです。失敗時は空です
 * @return 現在の端末と同じ公式選択を確認できた場合0です
 * @pre 呼出し側で元の署名レコード、取得許可および期限を再確認します
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createScopedInfInstallBinding(
	const ScanSessionId session, const std::wstring_view device,
	const std::shared_ptr<const ScopedInfInstallQualification> &qualification,
	const std::wstring_view expectedCurrentProvider, const std::wstring_view expectedCurrentVersion,
	const std::wstring_view expectedCurrentDate, OfficialInfInstallBinding &binding)
{
	binding = {} ;
	// 所有元・端末・scanが同じ資格の単一内容だけをトークンに固定します
	if( !qualification || qualification->owner != this || qualification->session != session ||
	   qualification->deviceIdentity != device || !qualification->content ||
	   qualification->content->infs.size() != 1U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元資格から同期で借用する、同じ一つの検査済みINF
	const auto &inf = qualification->content->infs.front() ;
	// 元の保護領域と単一の閉包がそろわない資格を発行に使いません
	if( !inf.workspace || inf.closure.packages.size() != 1U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return createOfficialInfInstallBindingImpl(
		session, device, *inf.workspace, inf.closure.packages.front(), expectedCurrentProvider,
		expectedCurrentVersion, expectedCurrentDate, qualification->observed.rank, binding, nullptr,
		nullptr, {}, qualification->observed.row.hardwareId, false, qualification) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 監査済み公式INFを現在device状態と一意なWindows nodeへ拘束する。監査済み公式INFを現在状態と一意なWindows nodeへ拘束する。現在状態と候補nodeを
 *        再取得し、全照合成功後だけ単調増加tokenへ秘密metadataをcommitする。OS状態は変更しない
 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID
 * @param[in] deviceIdentity UIへ提示済みのopaque device identity
 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace
 * @param[in] package G11-Cで構造を検証した一つのINF package。 内容監査済みの一INF package
 * @param[in] expectedCurrentProvider Scan結果に固定した現在Provider表示名。 Scan時の現在Provider名
 * @param[in] expectedCurrentVersion Scan結果に固定した現在version。 Scan時の現在version
 * @param[in] expectedCurrentDate Scan結果に固定した現在のYYYY/MM/DD日付。 Scan時の現在日付
 * @param[in] expectedRankAudit 発行前に合格したPnP具体性とrank監査結果。 直前に合格したrank監査結果
 * @param[out] binding 成功時の一scan限定opaque binding。失敗時は空値。 成功時の非機密opaque binding
 * @param[out] diagnostic 任意の元拒否位置です。実行判定に使用しません
 * @param[in] requiredHardwareId 再観測した端末のHardwareIdsに必要な元公開ID。空は追加条件なし
 * @param[in] requiresFirmwareAuthorization 元のファームウェア群を各変更直前に確認する場合trueです
 * @return Binding発行時は0、入力不正、端末状態の変化、候補の曖昧性、またはSetupAPIの失敗時はHRESULTです
 * @note 生のinstance ID、PnP ID、INF path、sectionはDriver Store内だけに保持する
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createOfficialInfInstallBinding(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::wstring_view expectedCurrentProvider, const std::wstring_view expectedCurrentVersion,
	const std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
	OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic,
	const std::wstring_view requiredHardwareId, const bool requiresFirmwareAuthorization)
{
	// 公開入口でだけ診断を初期化し、下位から戻った拒否を保持します
	if( diagnostic) {
		*diagnostic		 = {} ;
		diagnostic->path = 1U ;
	}

	// 基礎node適合だけで未確認の明示依存を実行可能な標準INFへ補完しません
	if( package.hasExternalDependencies || !package.unresolvedCopyInfPaths.empty()) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::SINGLE_DEPENDENCY) ;
	}

	const auto error = createOfficialInfInstallBindingImpl(
		scanSessionId, deviceIdentity, workspace, package, expectedCurrentProvider,
		expectedCurrentVersion, expectedCurrentDate, expectedRankAudit, binding, diagnostic,
		nullptr, {}, requiredHardwareId,
		requiresFirmwareAuthorization) ;	// 下位の最初の拒否位置を維持します
	return bindingFailure( diagnostic, error, InfBindingReject::BINDING_STATE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 標準入口または私有計画入口で確認したbase nodeを発行します
 * @param[in] scanSessionId 元scanです
 * @param[in] deviceIdentity 元opaqueです
 * @param[in] workspace 検証済み閉包です
 * @param[in] package 検証済み一INFです
 * @param[in] expectedCurrentProvider 元現在providerです
 * @param[in] expectedCurrentVersion 元現在versionです
 * @param[in] expectedCurrentDate 元現在日付です
 * @param[in] expectedRankAudit 元Windows rankです
 * @param[out] binding 同状態の一意nodeだけです
 * @param[out] diagnostic 任意の元拒否位置です。実行判定に使用しません
 * @param[in] storageQualification 同issuerの全原作用資格です。通常入口はnullで、用途だけでは発行しません
 * @param[in] declarativeQualification 同issuerが元Modelsと既存作用に結び付けた私有観測
 * @param[in] requiredHardwareId 発行時の端末HardwareIdsに必要な元公開ID。空は追加条件なし
 * @param[in] requiresFirmwareAuthorization 登録と指定適用の直前に元の群を確認する場合trueです
 * @param[in] scopedQualification 公式Modelsの同じ元選択・端末・作用を保持する私有計画です
 * @param[in] storageModel WiX用に同じ元Modelsで確認した候補節と全ID。通常のストレージはnullです
 * @return 一意性/全状態一致0、それ以外はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createOfficialInfInstallBindingImpl(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::wstring_view expectedCurrentProvider, const std::wstring_view expectedCurrentVersion,
	const std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
	OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic,
	const StorageInfQualification							 *storageQualification,
	std::shared_ptr<const DeclarativeInfInstallQualification> declarativeQualification,
	const std::wstring_view requiredHardwareId, const bool requiresFirmwareAuthorization,
	std::shared_ptr<const ScopedInfInstallQualification> scopedQualification,
	const OfficialCandidateNodeState					*storageModel)
{

	binding = {} ;
	// 管理者側の内容検査も導入資格ではなく、通常native処理へ入る前に拒否します
	const bool storage =
		storageQualification && storageQualification->session_ == scanSessionId &&
		storageQualification->deviceIdentity_ == deviceIdentity &&
		storageQualification->infPath_ == workspace.path( package.infRelativePath) &&
		storageQualification->inspection_ &&
		storageQualification->inspection_->workspace.get() == &workspace &&
		package.inspectionPurpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
		storageQualification->effects_.service.infRelativePath == package.infRelativePath &&
		storageQualification->effects_.service.className == package.className &&
		storageQualification->effects_.service.classGuid == package.classGuid ;
	// 起動に作用する両方式はWindowsから登録先を確認できる場合に限って資格を発行する
	if( storage &&
	   (storageQualification->effects_.automaticHost || storageQualification->singleBoot_) &&
	   !driver_store_inf_detail::transport().storageStoreLocation) {
		// 登録後の閉包を確認できない端末では導入候補を発行しない
		if( diagnostic) {
			diagnostic->stage = 14031U ;
		}

		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::DEPENDENCY) ;
	}

	const bool declarative =
		declarativeQualification &&
		package.inspectionPurpose == OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT &&
		declarativeQualification->owner == this &&
		declarativeQualification->session == scanSessionId &&
		declarativeQualification->deviceIdentity == deviceIdentity &&
		declarativeQualification->workspace == &workspace &&
		declarativeQualification->package == &package && !package.hasExternalDependencies &&
		!package.hasUnassessedProgramReferences &&
		!package.unresolvedIncludeNeeds ;	// 署名済みの同じ元選択と単一INFを使用する
	// 元の配布とscanに結び付いた公式選択資格がこの入口へ適用可能かを保持します
	const bool scoped = scopedQualification && scopedQualification->owner == this &&
						scopedQualification->session == scanSessionId &&
						scopedQualification->deviceIdentity == deviceIdentity &&
						scopedQualification->ownsSource( workspace, package) &&
						ownsInstallDevice( deviceIdentity) && !storageQualification &&
						!declarativeQualification && !requiresFirmwareAuthorization &&
						requiredHardwareId == scopedQualification->observed.row.hardwareId ;
	// WiXの元行は既存の単一起動資格と同じ完全Hardware IDを持つ場合だけ固定する
	if( storageModel &&
	   (!storage || !storageQualification->singleBoot_ || storageModel->modelsSection.empty() ||
		storageModel->modelIds.empty() || requiredHardwareId != storageModel->modelIds.front())) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_ACCESSDENIED),
							  InfBindingReject::INPUT) ;
	}

	// collector registry-only/限定null/裸storageは通常公開入口で先に拒否します
	if( package.requiredRegistryOnlyCompanion || package.requiredNullCompanion ||
	   (declarativeQualification && !declarative) || (scopedQualification && !scoped) ||
	   (!storage && !declarative && !scoped &&
		(package.inspectionPurpose != OfficialInfInspectionPurpose::STANDARD_DRIVER ||
		 CompareStringOrdinal( package.className.c_str(), -1, L"SCSIAdapter", -1, TRUE) ==
			 CSTR_EQUAL ||
		 CompareStringOrdinal( package.className.c_str(), -1, L"MTD", -1, TRUE) == CSTR_EQUAL ||
		 CompareStringOrdinal( package.className.c_str(), -1, L"MediumChanger", -1, TRUE) ==
			 CSTR_EQUAL))) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::INPUT) ;
	}

	// collectorの本人検査領域からnative導入bindingを発行しません
	if( workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR) {
		return E_ACCESSDENIED ;
	}

	const auto instance =	// Opaque identityからworker内のnative IDを得る検索結果
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	const std::optional<std::uint64_t> candidateVersion =
		// Candidate INFのpacked version
		parseDriverVersion( package.driverVersion) ;
	const std::optional<std::uint64_t> currentVersion =
		// Scan時現在版のpacked値
		parseDriverVersion( expectedCurrentVersion) ;
	const std::optional<std::wstring> candidateDate =
		// Candidate INFの正規化日付
		normalizeInfDriverDate( package.driverDate) ;
	const bool initialInstall = expectedRankAudit.currentState ==
								OfficialDriverRankCurrentState::NO_DRIVER ;	// 実rank監査方式
	// 現在版、候補版、日付、適用可能rankを含むbindingの全前提を確認する
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
	   instance == deviceInstances_.end() ||
	   !ownsBindingDevice( deviceIdentity, workspace, package) || package.infRelativePath.empty() ||
	   package.className.empty() || package.providerName.empty() || package.hardwareIds.empty() ||
	   (!requiredHardwareId.empty() &&
		(requiresFirmwareAuthorization || !validIndexNativeId( requiredHardwareId))) ||
	   (initialInstall
			? !expectedCurrentProvider.empty() || !expectedCurrentVersion.empty() ||
				  !expectedCurrentDate.empty()
			: expectedCurrentProvider.empty() || expectedCurrentVersion.empty() ||
				  expectedCurrentDate.empty() || !currentVersion || *currentVersion == 0U) ||
	   !candidateVersion.has_value() || candidateVersion.value() == 0U ||
	   !candidateDate.has_value() ||
	   expectedRankAudit.decision != OfficialDriverRankDecision::APPLICABLE) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_INVALIDARG),
							  InfBindingReject::INPUT) ;
	}

	// scan内のbinding保持数が上限に達した場合は追加を拒否する
	if( officialInfInstallBindings_.size() >= MAXIMUM_OFFICIAL_INF_BINDINGS) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 無効値や周回するtokenを発行せず、bindingの一意性を維持する
	if( nextOfficialBindingToken_ == 0U ||
	   nextOfficialBindingToken_ == std::numeric_limits<std::uint64_t>::max()) {
		return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
	}

	SYSTEM_INFO nativeSystem{} ;	// Native OS architectureの取得先
	driver_store_inf_detail::transport().architecture( &nativeSystem) ;
	// x64以外の実OSには公式INF導入bindingを作成しない
	if( nativeSystem.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::ARCHITECTURE, nativeSystem.wProcessorArchitecture) ;
	}

	const std::wstring candidateInfPath =	// SetupAPIへ渡すworkspace内INF絶対path
		workspace.path( package.infRelativePath) ;
	// 空または埋込NULを含むINF pathをWindows APIへ渡さない
	if( candidateInfPath.empty() || candidateInfPath.find( L'\0') != std::wstring::npos) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_INVALIDARG),
							  InfBindingReject::INPUT) ;
	}

	const DWORD attributes = GetFileAttributesW( candidateInfPath.c_str()) ;	// INFのfile属性
	// binding対象INFの属性取得失敗をそのまま通知する
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( GetLastError()),
							  InfBindingReject::INF_FILE) ;
	}

	// 通常file以外のINFをbindingへ登録しない
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceRankSnapshot			deviceSnapshot ;	// 発行時に固定する現在device状態
	CandidateDriverNodeSnapshot candidateSnapshot ;	// 発行時に固定するWindows node
	OfficialDriverRankAudit		currentRankAudit ;	// 発行時に再生成するrank監査結果
	const NativeError			collectError = [&]() {
		  // 公式範囲の資格を使う場合は同じ元選択を現在状態で読み直します
		  if( scoped) {
			  // 同じ元資格の有効性を確認する現在の選択観測
			  ScopedInfObservation current ;
			  // ターゲット限定の再観測で得た診断値
			  const auto		   error =
				  reobserveScopedInfInstallQualification( *scopedQualification, current) ;
			  // 現在の観測が成立した場合だけ元選択をbindingの組立てに使います
			  if( error == 0U) {
				  deviceSnapshot	= std::move( current.current) ;
				  candidateSnapshot = std::move( current.candidate) ;
				  currentRankAudit	= current.rank ;
			  }

			  return error ;
		  }

		  return collectOfficialInfBindingState(
			  instance->second, candidateInfPath, package, *candidateVersion, *candidateDate,
			  deviceSnapshot, candidateSnapshot, currentRankAudit, diagnostic,
			  declarative ? &declarativeQualification->selected : nullptr, storageModel != nullptr) ;
	  }() ; // 用途ごとに同じ現端末と候補の事実を取り直します
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( collectError != 0) {
		return bindingFailure( diagnostic, collectError, InfBindingReject::BINDING_STATE) ;
	}

	// 公式配布対象は発行時と同じ現在端末のHardwareIdsに完全一致する必要がある
	if( !requiredHardwareId.empty() &&
	   !containsScopedHardwareId( deviceSnapshot.hardwareIds, requiredHardwareId)) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_RETRY),
							  InfBindingReject::BINDING_STATE) ;
	}

	// 資格化した実native節から変化したwinnerを同じstorage資格へ転用しません
	if( storage && storageQualification->basicSection_ != candidateSnapshot.sectionName) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 元行照合後の再列挙でも原順の全IDと順位を同じWindows選択に固定する
	if( storageModel && (storageModel->modelIds != candidateSnapshot.modelIds ||
						storageModel->infClassGuid != candidateSnapshot.infClassGuid ||
						storageModel->classGuid != candidateSnapshot.classGuid ||
						storageModel->dateTicks != candidateSnapshot.dateTicks ||
						storageModel->rank != candidateSnapshot.rank)) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_RETRY),
							  InfBindingReject::CANDIDATE_NODE) ;
	}

	// 独自クラスの選択時から変わった現在状態を別候補へ引き継ぎません
	if( declarative &&
	   !deviceRankSnapshotsEqual( deviceSnapshot, declarativeQualification->current)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// base後に出現した必要子は、その子自身の実観測を同scopeで再照合します
	if( activeRequiredChild_ && activeRequiredChild_->childIdentity == deviceIdentity) {
		// 同親/role/元byteのproofを失った子は先へ進めません
		if( !ownsBindingDevice( deviceIdentity, workspace, package)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const auto &observed = *activeRequiredChild_->observation ;	// 同子の最初の実観測です
		// 子のClass/ID/現在状態、唯一nodeとfull rankの途中変化を拒否します
		if( observed.device.classState != OfficialDriverRankDeviceClassState::KNOWN_CLASS ||
		   observed.device.classRead.state != DevicePropertyReadState::VALUE ||
		   observed.device.classGuidRead.state != DevicePropertyReadState::VALUE ||
		   !deviceRankSnapshotsEqual( observed.device, deviceSnapshot) ||
		   !candidateNodeSnapshotsEqual( observed.candidate, candidateSnapshot) ||
		   !officialRankAuditsEqual( observed.rank, currentRankAudit)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}
	// 通常deviceは同inventory世代の元Classを別観測へ置き換えません
	else if( indexInventory_) {
		const auto origin =
			std::find_if( indexInventory_->nodes.begin(), indexInventory_->nodes.end(),
						 [deviceIdentity]( const IndexInventoryState::Node &node) {
							 return node.identity == deviceIdentity ;
						 }) ; // 同期中だけopaqueを借用します
		// 元scanのClass読取失敗や状態変化を候補Classから補完しません
		if( origin == indexInventory_->nodes.end() || origin->classError != 0U ||
		   deviceSnapshot.classState != origin->classObservation.classState ||
		   deviceSnapshot.classRead.state != origin->classObservation.classRead.state ||
		   deviceSnapshot.classGuidRead.state != origin->classObservation.classGuidRead.state ||
		   deviceSnapshot.deviceClass != origin->classObservation.deviceClass ||
		   deviceSnapshot.nativeClassGuid != origin->classObservation.nativeClassGuid ||
		   deviceSnapshot.observedClassGuid != origin->classObservation.observedClassGuid ||
		   (deviceSnapshot.classState != OfficialDriverRankDeviceClassState::KNOWN_CLASS &&
			!origin->initialClassUnknown)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// Scan表示値、現在実状態、直前監査のいずれかが変わった場合は再scanを要求する
	if( deviceSnapshot.currentDriver.provider != expectedCurrentProvider ||
	   deviceSnapshot.currentDriver.version != expectedCurrentVersion ||
	   deviceSnapshot.currentDriver.date != expectedCurrentDate ||
	   deviceSnapshot.noDriver != initialInstall ||
	   (!initialInstall && deviceSnapshot.currentDriver.packedVersion != currentVersion) ||
	   currentRankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
	   !officialRankAuditsEqual( expectedRankAudit, currentRankAudit)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	OfficialInfInstallBindingRecord record ;	// Tokenへcommitする秘密binding記録
	// 自己媒体Portsの同じ未修飾選択に限り、標準ページの実ファイルを確認する
	if( package.nativePortsPage) {
		// Windowsの実互換nodeと元Modelsの選択が違えば新たな導入資格を発行しない
		if( normalizeIdentifier( candidateSnapshot.sectionName) !=
		   normalizeIdentifier( package.nativePortsPage->basicSection)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const auto error = inspectWindowsSerialPropertyPage(
			workspace, record.serialPropertyPage.emplace()) ;	// 元DLLの署名と同じバイトの証拠
		// 固定DLLを検査できない場合はこの選択を導入へ渡さない
		if( error != 0U) {
			return error ;
		}
	}

	record.scanSessionId			   = scanSessionId ;
	record.deviceIdentity			   = deviceIdentity ;
	record.device.deviceInstanceId	   = instance->second ;
	record.device.deviceClass		   = std::move( deviceSnapshot.deviceClass) ;
	record.device.hardwareIds		   = std::move( deviceSnapshot.hardwareIds) ;
	record.device.compatibleIds		   = std::move( deviceSnapshot.compatibleIds) ;
	record.device.matchingDeviceId	   = std::move( deviceSnapshot.matchingDeviceId) ;
	record.device.currentInfFileName   = std::move( deviceSnapshot.currentDriver.infFileName) ;
	record.device.currentProvider	   = std::move( deviceSnapshot.currentDriver.provider) ;
	record.device.currentVersion	   = std::move( deviceSnapshot.currentDriver.version) ;
	record.device.currentDate		   = std::move( deviceSnapshot.currentDriver.date) ;
	record.device.currentPackedVersion = deviceSnapshot.currentDriver.packedVersion.value_or( 0U) ;
	record.device.noDriver			   = deviceSnapshot.noDriver ;
	record.device.classRead			   = deviceSnapshot.classRead ;
	record.device.classGuidRead		   = deviceSnapshot.classGuidRead ;
	record.device.observedClassGuid	   = std::move( deviceSnapshot.observedClassGuid) ;
	record.device.nativeClassGuid	   = std::move( deviceSnapshot.nativeClassGuid) ;
	record.device.classState		   = deviceSnapshot.classState ;
	record.device.node				   = deviceSnapshot.node ;
	record.device.driverKeyRead		   = deviceSnapshot.driverKeyRead ;
	record.device.matchingRead		   = deviceSnapshot.matchingRead ;
	record.device.driverKey			   = std::move( deviceSnapshot.driverKey) ;
	record.candidate.infPath		   = candidateInfPath ;
	record.candidate.sectionName	   = std::move( candidateSnapshot.sectionName) ;
	record.candidate.provider		   = std::move( candidateSnapshot.provider) ;
	record.candidate.version		   = std::move( candidateSnapshot.version) ;
	record.candidate.date			   = std::move( candidateSnapshot.date) ;
	record.candidate.packedVersion	   = candidateSnapshot.packedVersion ;
	record.candidate.dateTicks		   = candidateSnapshot.dateTicks ;
	record.candidate.rank			   = candidateSnapshot.rank ;
	record.candidate.infClassGuid	   = std::move( candidateSnapshot.infClassGuid) ;
	record.candidate.classGuid		   = std::move( candidateSnapshot.classGuid) ;
	// WiXの元行と再列挙が一致した場合だけ発行する私有トークンへ全IDを保存する
	if( storageModel) {
		record.candidate.modelsSection = storageModel->modelsSection ;
		record.candidate.modelIds	   = std::move( candidateSnapshot.modelIds) ;
	}

	record.rankAudit					 = currentRankAudit ;
	record.declarativeQualification		 = std::move( declarativeQualification) ;
	record.scopedQualification			 = std::move( scopedQualification) ;
	record.requiredHardwareId			 = requiredHardwareId ;
	record.requiresFirmwareAuthorization = requiresFirmwareAuthorization ;

	OfficialInfInstallBinding output ;	// Commit成功後だけcallerへ渡す非機密binding
	output.token			 = nextOfficialBindingToken_ ;
	output.currentProvider	 = record.device.currentProvider ;
	output.currentVersion	 = record.device.currentVersion ;
	output.currentDate		 = record.device.currentDate ;
	output.candidateProvider = record.candidate.provider ;
	output.candidateVersion	 = record.candidate.version ;
	output.candidateDate	 = record.candidate.date ;
	output.rankAudit		 = record.rankAudit ;
	// 初回に実際にクラスを登録する場合だけ、元表示情報を同意へ渡します
	if( record.declarativeQualification && record.declarativeQualification->effects.registration ==
											  SetupClassRegistration::UNREGISTERED) {
		const auto &registration =
			record.declarativeQualification->registration ;	// 署名済み元クラス節の表示情報
		output.setupClassRegistration =
			SetupClassRegistrationSummary{package.className, registration.classGuid,
										  registration.displayName, registration.builtInIcon} ;
	}

	try {
		// 単調増加tokenをemplaceし、既存bindingを上書きしない
		const auto insertResult =
			officialInfInstallBindings_.emplace( output.token, std::move( record)) ;
		// 既存tokenへの挿入失敗を成功扱いせず、一意なbindingだけを返す
		if( !insertResult.second) {
			return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
		}
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	++nextOfficialBindingToken_ ;
	binding = std::move( output) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同issuer元記録から全import内容とdevice別選択関係を再構築します
 * @param[in] inspection 同保護元byteと全CAT/memberの検査所有者です
 * @param[in] record 同session/device/元INFに固定した私有binding記録です
 * @param[out] plan 成功時だけ同原順の不変内容計画です。失敗時は空です
 * @param[out] diagnosticStage 任意の数値段階です。生ID・path・節名を含みません
 * @return 元byteと選択節/role関係確認0、その他は元HRESULTです
 * @note Worker内read-only処理です。単独の導入許可を発行しません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::buildRequiredInfComponentPlan(
	const CommonInfInspection &inspection, const OfficialInfInstallBindingRecord &record,
	std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	RequiredInfBindingDiagnostic					   *diagnosticStage) const
{
	plan.reset() ;
	// 明示された端末内診断だけへ段階を返し、実行可否の入力には使いません
	if( diagnosticStage) {
		diagnosticStage->stage = 3U ;
	}

	const auto error =
		// 非機能importも全byte/CATへ再照合します
		reverifyCommonDriverInf( inspection) ;
	// 別元INF/session/private stateの節を同内容へ転用しません
	if( error != 0 || record.scanSessionId != inspection.scanSessionId || !inspection.workspace ||
	   normalizeIdentifier( record.candidate.infPath) !=
		   normalizeIdentifier( inspection.workspace->path( inspection.infRelativePath))) {
		return error ? error : static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<OfficialInfPackage> selections{	// 元順の全import copyです
												   inspection.closure.packages.front()} ;
		selections.insert( selections.end(), inspection.requiredInfPackages.begin(),
						  inspection.requiredInfPackages.end()) ;
		OfficialInfPackage selectedBase ;	// 元metadataと出力をaliasさせない選択copyです
		// 元private節の関係解析と元内容再検査の拒否を区別します
		if( diagnosticStage) {
			diagnosticStage->stage = 4U ;
		}

		const auto selectedError = inspectSelectedOfficialInfRelations(
			*inspection.workspace, inspection.closure.entries, selections.front(),
			record.candidate.sectionName,
			selectedBase) ;	// 同private nodeの基本名だけから解析します
		// 任意節や非実在fallbackを必要役割の選択成功へ変換しません
		if( selectedError != 0) {
			return bindingFailure( diagnosticStage, selectedError,
								  InfBindingReject::SELECTED_RELATIONS) ;
		}

		selectedBase.selectedNativeRank = record.candidate.rank ;
		selections.front()				= std::move( selectedBase) ;
		const bool displayParent		= normalizeIdentifier( selections.front().className) ==
								   L"DISPLAY" ;	// Display必須子は作用分類に依存せず選択する
		std::vector<bool> visited(
			// 八package以内で各active roleを一度だけ解析します
			selections.size()) ;
		std::vector<std::size_t> queue{0U} ;	// private選択baseからの有限機能queueです
		visited[0] = true ;
		// 選択節のCopyINFだけを解析します。非選択importは全内容検査のまま保持します
		for( std::size_t position = 0U; position < queue.size(); ++position) {
			const auto index = queue[position] ;	// 同原順の選択packageです
			// 現deviceで必要な元参照だけを同保護閉包へ結合します
			for( const auto &path : selections[index].activeRequiredInfPaths) {
				const auto found = std::ranges::find_if( selections, [&]( const auto &value) {
					return normalizeIdentifier( value.infRelativePath) == normalizeIdentifier( path) ;
				}) ; // 元内容copyだけを同期借用します
				// 原importの欠損を基本INFだけの成功へ変換しません
				if( found == selections.end()) {
					// 元配布で不在を確かめた基本INFの付随参照は必須構成の照合と分けます
					if( canDeferMissingRootCopyInf( inspection, index, path)) {
						continue ;
					}

					// 同じHRESULTになる二つの拒否を数値だけで区別します
					if( diagnosticStage) {
						diagnosticStage->stage = found == selections.end() ? 5U : 6U ;
					}

					return bindingFailure( diagnosticStage,
										  nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
										  InfBindingReject::COPY_INF_MISSING) ;
				}

				// 元CopyINFの独立基本INFはstage用内容です。別deviceのnative nodeやinstallを作りません
				if( found->role == DriverPlanRole::BASE_DRIVER) {
					continue ;
				}

				const auto ordinal =
					// 八件内ordinalです
					static_cast<std::size_t>( found - selections.begin()) ;
				// 共有参照は一度だけ解決し、循環は全import graphで別に拒否します
				if( visited[ordinal]) {
					continue ;
				}

				visited[ordinal] = true ;
				// Extensionだけは同じ親の役割ClassとWindows compatible nodeで選択節を固定します
				if( found->role == DriverPlanRole::EXTENSION) {
					// 追加役割のnative nodeと関係解析を別段階に保持します
					if( diagnosticStage) {
						diagnosticStage->stage = 7U ;
					}

					CandidateDriverNodeSnapshot node ;	// 同親/同元INFだけの私有互換nodeです
					const auto					nodeError = collectUniqueCandidateDriverNode(
						 record.device.deviceInstanceId,
						 inspection.workspace->path( found->infRelativePath), found->className,
						 found->providerName, parseDriverVersion( found->driverVersion).value_or( 0U),
						 normalizeInfDriverDate( found->driverDate).value_or( L""),
						 node) ;	// base Class/rankを流用しません
					// 同Extensionのnative適合失敗を名称やbase成功から補完しません
					if( nodeError != 0) {
						return bindingFailure( diagnosticStage, nodeError,
											  InfBindingReject::CANDIDATE_NODE, 7U) ;
					}

					OfficialInfPackage selected ;	// 同役割nodeからの機能関係だけです
					// 実役割node選択後の元INF解析段階です
					if( diagnosticStage) {
						diagnosticStage->stage = 8U ;
					}

					const auto relationError = inspectSelectedOfficialInfRelations(
						*inspection.workspace, inspection.closure.entries, *found, node.sectionName,
						selected) ;	// 同元INFを借用します
					// 元役割選択の解析失敗を一baseの成功へ代替しません
					if( relationError != 0) {
						return bindingFailure( diagnosticStage, relationError,
											  InfBindingReject::SELECTED_RELATIONS, 8U) ;
					}

					selected.selectedNativeRank = node.rank ;
					*found						= std::move( selected) ;
				}
				// Displayの必須子だけを同じ親のAddComponentで解決し、他クラスの未評価作用は従来の拒否を維持する
				else if( displayParent && found->role == DriverPlanRole::DRIVER_COMPONENT) {
					const OfficialInfComponentReference *required = nullptr ;	// 借用する親の元宣言
					// 同親が指定する全必須子を確認し、同じINFへの複数の関係を先頭一件へ絞りません
					for( const auto &reference : selections[index].requiredComponents) {
						const bool matches =
							std::ranges::any_of( reference.hardwareIds, [&found]( const auto &id) {
								return containsScopedHardwareId( found->hardwareIds, id) ;
							}) ; // 元子INFとの関係候補です。主IDと節は後段で確認します
						// 同じ親の別の子宣言を、このINFの作用へ結び付けない
						if( !matches) {
							continue ;
						}

						// 曖昧な必須関係を同じ子と判断しない
						if( required != nullptr) {
							return bindingFailure( diagnosticStage,
												  nativeErrorFromWin32( ERROR_DUP_NAME),
												  InfBindingReject::SELECTED_RELATIONS, 8U) ;
						}

						required = &reference ;
					}

					// 付随媒体にあるだけの子へ作用の選択を発行しない
					if( required == nullptr) {
						return bindingFailure( diagnosticStage,
											  nativeErrorFromWin32( ERROR_NOT_FOUND),
											  InfBindingReject::SELECTED_RELATIONS, 8U) ;
					}

					OfficialInfPackage selected ;	// 現OSの元Modelsで照合される子の導入節
					const auto		   relationError = inspectRequiredOfficialInfComponentSelection(
						*inspection.workspace, inspection.closure.entries, *found,
						required->hardwareIds, selected) ;	// 子未生成時もrankの代用は発行しない
					// 子への明示関係と元節が確定した場合だけ作用検査へ渡す
					if( relationError != 0) {
						return bindingFailure( diagnosticStage, relationError,
											  InfBindingReject::SELECTED_RELATIONS, 8U) ;
					}

					*found = std::move( selected) ;
				}

				queue.push_back( ordinal) ;
			}
		}

		// 共通内容計画の拒否を上位private選択の拒否と区別します
		if( diagnosticStage) {
			diagnosticStage->stage = 9U ;
		}

		// 元の自動起動候補を対象セッションと実選択の位置へ再結合する入力
		const StorageAutomaticCandidateSelection candidate{
			selections.front(), record.candidate.infPath, record.candidate.sectionName} ;
		// 元作用が自動起動補助を持つ場合、同期中だけ同じ候補・選択機器を借用する
		const StorageRegisteredDeviceRead registeredDeviceRead =
			[&record, &candidate]( const SelectedStorageServiceFacts &intended,
								  StorageAutomaticDeviceSnapshot	&snapshot) {
				return inspectAutomaticStorageDevices(
					record.device.deviceInstanceId, record.device.noDriver,
					record.device.currentInfFileName, candidate, intended, snapshot) ;
			} ;
		// 選択された元署名と同じ現在機器だけに補助サービスの所有照会を結び付ける
		const DisplayRegisteredDeviceRead displayDeviceRead =
			[&inspection, &record, diagnosticStage,
			 &selections]( const OfficialDisplayAuxiliaryService					&target,
						  std::shared_ptr<const DisplayAuxiliaryOwnershipProof> &proof) {
				DisplayOwnershipObservation observation ;	// 元個体名を含まない照合の到達段階
				// 現用署名と全現在機器の読取結果。拒否時には到達段階も保持する
				const auto					ownership = readDisplayAuxiliaryOwnership(
					 inspection, selections, record.device.deviceInstanceId,
					 record.device.currentInfFileName, target, proof, observation) ;
				return diagnosticStage
						   ? diagnosticStage->reject( ownership, InfBindingReject::DISPLAY_OWNERSHIP,
													 static_cast<std::uint32_t>( observation))
						   : ownership ;
			} ;
		const auto prepared = makeRequiredDriverComponentPlan(
			inspection, selections, plan, diagnosticStage, &registeredDeviceRead,
			&displayDeviceRead) ;	// 実選択と現在作用の読取結果
		// 適用後の所有と必要子の確認が未接続の間は、元候補を導入準備成功へ変えない
		if( prepared == 0U && plan && plan->displayOwnership_) {
			plan.reset() ;
			return bindingFailure( diagnosticStage, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
								  InfBindingReject::DISPLAY_REFLECTION_PENDING) ;
		}

		return prepared ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同原計画と元deviceのService propertyをprivate storage資格へ結びます
 * @param[in] inspection 元ADMIN保護archiveの内容です
 * @param[in] record 実測した同issuerの元device/native選択です
 * @param[in] plan 全作用/依存/必要importの元不変計画です
 * @param[out] qualification 全原値成立時だけの同device資格です。失敗時空です
 * @return 全型/元所有/現service観測成立0、その他は原HRESULTです
 * @note 旧serviceのbinary/hash/configと提案新値との一致を要求しません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::buildStorageInfQualification(
	const CommonInfInspection &inspection, const OfficialInfInstallBindingRecord &record,
	const RequiredDriverComponentPlan			   &plan,
	std::shared_ptr<const StorageInfQualification> &qualification) const
{
	qualification.reset() ;
	// 非権限purposeや計画だけをprivate資格へ昇格しません
	if( !inspection.workspace ||
	   inspection.workspace->protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   inspection.scanSessionId == 0U || inspection.scanSessionId != scanSessionId_ ||
	   record.scanSessionId != inspection.scanSessionId || !plan.storageEffects_ ||
	   plan.session_ != record.scanSessionId || inspection.closure.packages.empty() ||
	   plan.selectedPackages_.empty() ||
	   plan.selectedPackages_.front().selectedBasicSection != record.candidate.sectionName ||
	   GetCurrentThreadId() != ownerThreadId_ || !ownsInstallDevice( record.deviceIdentity)) {
		return E_ACCESSDENIED ;
	}

	// 同対象とexact service所有者だけを開く借用集合です
	DeviceInfoSet devices( driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// 同deviceを読めなければ別nodeへ代替しません
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 同同期中だけ使用する元PnP nodeです
	SP_DEVINFO_DATA device{} ;
	device.cbSize = sizeof( device) ;
	// 元対象を再openできない場合は現service所有を推測しません
	if( !driver_store_inf_detail::transport().open(
		   devices.get(), record.device.deviceInstanceId.c_str(), nullptr, 0U, &device)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	StorageInfQualification made ;	// 全観測が成立するまで外部へ渡さない資格の組立て先
	// MTD選択だけhost handlerと現在hardware属性を追加固定します
	if( normalizeIdentifier( plan.storageEffects_->service.className) == L"MTD") {
		// 現在の三handler propertyを発行前の資格へ直接読み込みます
		auto	  &current = made.mtdHandlers_.emplace() ;
		// handler観測の元診断です
		const auto error = inspectMtdHandlers( devices.get(), device, current) ;
		// handler property取得の元診断を返します
		if( error != 0U) {
			return error ;
		}

		// 現在deviceのMTD属性を同じ発行前の資格へ保持します
		auto	  &properties = made.mtdCurrentProperties_.emplace() ;
		// 正式DWORD propertyの不在・値・失敗を区別するreaderです
		const auto readDword = [&]( const DEVPROPKEY				&key,
								   std::optional<std::uint32_t> &value) -> NativeError {
			// propertyの原byte bufferです
			std::vector<std::byte> bytes ;
			// 型付きpropertyの状態と原診断です
			const auto			   read =
				readObservedProperty( devices.get(), device, key, DEVPROP_TYPE_UINT32, bytes,
									 driver_store_inf_detail::transport().inventory) ;
			// 正式なproperty不在を数値0とは区別します
			if( read.state == DevicePropertyReadState::NOT_PRESENT) {
				return 0U ;
			}

			// 型・長さ不一致や読取失敗を値として受理しません
			if( read.state != DevicePropertyReadState::VALUE ||
			   bytes.size() != sizeof( std::uint32_t)) {
				return nativeErrorFromWin32( read.diagnostic.code ? read.diagnostic.code
																 : ERROR_INVALID_DATA) ;
			}

			// 原DWORD byteから復元する現在値です
			std::uint32_t currentValue{} ;
			std::memcpy( &currentValue, bytes.data(), sizeof( currentValue)) ;
			value = currentValue ;
			return 0U ;
		} ;
		// DeviceType取得からの最初の診断です
		auto propertyError = readDword( DEVPKEY_Device_DevType, properties.deviceType) ;
		// DeviceType確認後にCharacteristicsも独立して読みます
		if( propertyError == 0U) {
			propertyError = readDword( DEVPKEY_Device_Characteristics, properties.characteristics) ;
		}

		// 一方でも取得に失敗すれば元診断を返します
		if( propertyError != 0U) {
			return propertyError ;
		}
	}

	std::wstring currentService ;	// 元deviceのexact現在Service propertyです
	// 不存在と照会失敗を分ける元Service property状態です
	const auto	 serviceRead =
		readObservedDeviceString( devices.get(), device, DEVPKEY_Device_Service, currentService,
								 driver_store_inf_detail::transport().inventory) ;
	// 未導入の明示不存在と、既知現在driverの所有serviceを分けます
	if( record.device.noDriver ? serviceRead.state != DevicePropertyReadState::NOT_PRESENT
							  : serviceRead.state != DevicePropertyReadState::VALUE ||
									currentService.empty() || currentService.size() > 256U) {
		return serviceRead.diagnostic.code != 0U ? nativeErrorFromWin32( serviceRead.diagnostic.code)
												 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 同原選択の全作用と必要serviceの観測です
	const auto &effects	  = *plan.storageEffects_ ;
	const bool singleBoot = effects.singleBootEvent.has_value() ;	// 元署名から確認した単一起動の作用
	// 独立検査で得た現在又は元終端の観測です
	const auto observed = std::ranges::find_if( effects.services, [&]( const auto &value) {
		return normalizeIdentifier( value.name) == normalizeIdentifier( effects.service.name) ;
	}) ;
	// 名前だけで既存serviceの所有関係を生成しません
	if( !singleBoot && observed == effects.services.end()) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::shared_ptr<StorageServiceOwnershipProof> ownership ;	// 従来経路が独立収集する全所有者
	const bool									  automatic = effects.service.auxiliary &&
						   effects.service.auxiliary->start == SERVICE_AUTO_START &&
						   // 元の自動起動配置方式
						   effects.service.auxiliary->copy.dirid == 13 ;
	// 元の開始方式と機器に結ぶ観測の組が一致しなければ別方式へ代替しない
	if( automatic != effects.automaticHost.has_value()) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto &base = plan.selectedPackages_.front() ;	// 同じ元INFとWindows実選択
	// ブート構成を変更する計画は、現在使われた順位と同じ正規の実選択を必要とする
	if( (automatic || singleBoot) &&
	   (!effects.loadOrder || base.infRelativePath != effects.service.infRelativePath ||
		base.selectedInstallSection != effects.service.selectedInstallSection ||
		base.selectedNativeRank != record.candidate.rank ||
		record.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
		record.rankAudit.candidateRank != record.candidate.rank)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 単一起動候補は同じ機器の署名付き現用元と電源・起動・局所設定を独立に照合する
	if( singleBoot) {
		// 別方式の作用または模擬環境の端末を実OSの読み取りで補わない
		if( automatic || effects.service.auxiliary || effects.auxiliaryHost || effects.autoLogger ||
		   effects.sharedAcpiStorageFeatures || effects.sharedDiskTimeout ||
		   driver_store_inf_detail::fixtureActive()) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		auto &scope = made.singleBoot_.emplace() ;	// 発行前の資格が所有する保護付き観測
		// 選択機器の現在状態を照会し、最初の元診断を保持する
		auto  error = readCurrentSingleBootStorageSharingSnapshot(
			 record.device.deviceInstanceId, record.device.noDriver,
			 record.device.currentInfFileName, effects, scope.observed) ;
		// 取得した端末証拠から、既存サービスを含めた元候補の変更範囲を分類する
		if( error == 0U) {
			error = classifySingleBootStorageChanges( effects, scope.observed, scope.changes) ;
		}

		// 読取りや元作用との照合不成立は別方式の資格へ変換しない
		if( error != 0U) {
			return error ;
		}

		const auto &installed = scope.observed.device.installed.registered ;	// 同じ機器の現在登録
		// 選択機器の元属性が先の順位観測から動いた場合は同じ選択として扱わない
		if( installed.has_value() == record.device.noDriver ||
		   (installed && normalizeIdentifier( installed->package.installedService) !=
							 normalizeIdentifier( currentService))) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const auto conflict = []( StorageServiceChange change) {
			return change == StorageServiceChange::UPDATE_SHARED ||
				   change == StorageServiceChange::UNVERIFIED ;
		} ; // 起動と局所の共有変更・所有不明を同じ規則で拒否する
		// 所有が不明な作用も対象機器以外への更新も同意の対象としない
		if( conflict( scope.changes.boot) || conflict( scope.changes.event) ||
		   std::ranges::any_of( scope.changes.registry, conflict) ||
		   std::ranges::any_of( scope.observed.powerChanges, []( StoragePowerChange change) {
			   return change == StoragePowerChange::UPDATE_SHARED ||
					  change == StoragePowerChange::UNVERIFIED ;
		   })) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	// 自動起動型はNativeLoaderが照合した全共有先を同じWindows選択の資格へ結ぶ
	else if( automatic) {
		const auto &host = *effects.automaticHost ;	// 全現在値、保護と現用登録
		// 私有計画の元観測を別の名前・順位・選択へ持ち替えない
		if( !host.device || !host.boot || host.boot->related != *observed ||
		   !host.autoLoggerRuntimePresent || *host.autoLoggerRuntimePresent ||
		   !host.serviceChanges || host.powerChanges.size() != effects.powerSettings.size() ||
		   !effects.autoLogger || effects.auxiliaryHost) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const auto &installed = host.device->selected.package ;	// 同じ機器の署名付き現在登録
		// 直前の端末観測が元計画の署名元とまだ一致していることを確認する
		if( installed.has_value() == record.device.noDriver ||
		   (installed && (normalizeIdentifier( installed->installedService) !=
							  normalizeIdentifier( currentService) ||
						  normalizeIdentifier( installed->publishedInf) !=
							  normalizeIdentifier( record.device.currentInfFileName)))) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		made.autoLogger_ = host.shared.autoLogger ;
	} else {
		// 従来の配置方式では同サービスを使う全機器を専用の観測へ集約する
		ownership = std::make_shared<StorageServiceOwnershipProof>() ;
		// 同サービスを使う現用機器の所有を列挙した結果
		const auto ownerError =
			readStorageServiceOwners( devices.get(), effects, inspection.closure.packages.front(),
									 record.candidate.infPath, record.device.deviceInstanceId,
									 currentService, observed->evidence.has_value(), *ownership) ;
		// 一部機器だけの観測で既存サービスの所有を確定しない
		if( ownerError != 0U) {
			return ownerError ;
		}

		// 要求時起動の補助作用では、元登録とSystem32配置先を既存方式で照合する
		if( effects.service.auxiliary) {
			// 正式な不存在も含む現在値が確定するまで配置先を使わない
			if( !effects.auxiliaryHost) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			const auto error = verifyStorageServiceAuxiliaryOwnership(
				*effects.auxiliaryHost, *ownership) ;	// 元登録と現在の共有構成の照合
			// 共有状態の不明は元診断を保つ
			if( error != 0U) {
				return error ;
			}
		}

		// 従来の共有ログは既知所有者と現在値の両方を保持する
		if( effects.autoLogger) {
			// 選択と同じ共有ログの読取り結果
			const auto error =
				readStorageAutoLoggerSnapshot( *effects.autoLogger, made.autoLogger_.emplace()) ;
			// 読取りや元設定との不一致があれば資格を発行しない
			if( error != 0U) {
				return error ;
			}

			// 既存ログの元となるサービスの所有者を確認する
			if( made.autoLogger_->existing && ownership->owners.empty()) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}
	}

	made.session_			   = record.scanSessionId ;
	made.deviceIdentity_	   = record.deviceIdentity ;
	made.infPath_			   = inspection.workspace->path( inspection.infRelativePath) ;
	made.basicSection_		   = record.candidate.sectionName ;
	made.effects_			   = effects ;
	made.currentDeviceService_ = std::move( currentService) ;
	made.ownershipProof_	   = std::move( ownership) ;
	made.inspection_		   = std::make_shared<const CommonInfInspection>( inspection) ;
	qualification			   = std::make_shared<const StorageInfQualification>( std::move( made)) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief app原archiveと実native選択から全storage資格を発行します
 * @param[in] session 元scanです
 * @param[in] identity 元選択deviceです
 * @param[in] inspection ADMIN原byteの独立検査です
 * @param[out] plan 元全作用/importの計画です。失敗時空です
 * @param[in] provider 元現在providerです
 * @param[in] version 元現在versionです
 * @param[in] date 元現在日付です
 * @param[in] audit 元全rankです
 * @param[out] binding 同issuerの成功tokenです。失敗時空です
 * @param[out] diagnostic null可の元固定拒否です
 * @param[in] requiredHardwareId 元ストレージ端末の再観測HardwareIdsに必要な公開ID。空は追加条件なし
 * @param[in] requiresFirmwareAuthorization 各ストレージ作用の直前に元の群を確認する場合trueです
 * @param[in] modelScope 私有WiXの元Modelsと同機器の完全ID範囲。通常のストレージはnullです
 * @return 全原値/元device/一意node成立0、その他は元HRESULTです
 * @note BOOT0/SYSTEM1/DEMAND3の原値を保持し、stage又はinstallを行いません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createStorageInfInstallBinding(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection &inspection, std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const std::wstring_view provider, const std::wstring_view version, const std::wstring_view date,
	const OfficialDriverRankAudit &audit, OfficialInfInstallBinding &binding,
	RequiredInfBindingDiagnostic *diagnostic, const std::wstring_view requiredHardwareId,
	const bool requiresFirmwareAuthorization, const OfficialStorageInfModelScope *modelScope)
{
	binding = {} ;
	plan.reset() ;
	// 同workerの原ADMIN所有/全byte検査が先に成立している必要があります
	if( diagnostic) {
		*diagnostic		 = {} ;
		diagnostic->path = 3U ;
	}

	// 外部へ返さない正確な元instance identityです
	const auto instance = deviceInstances_.find( std::wstring{identity}) ;
	// 別scan/別所有者/非ADMIN用途からprivate資格を発行しません
	if( session == 0U || session != scanSessionId_ || inspection.scanSessionId != session ||
	   GetCurrentThreadId() != ownerThreadId_ || !inspection.workspace ||
	   !ownsInstallDevice( identity) || instance == deviceInstances_.end() ||
	   inspection.closure.packages.size() != 1U ||
	   inspection.closure.packages.front().requiredRegistryOnlyCompanion ||
	   inspection.closure.packages.front().inspectionPurpose !=
		   OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) {
		return E_ACCESSDENIED ;
	}

	// WiXでは元関係が許可した完全IDだけを使い、別方式の対象条件を混在させない
	if( modelScope &&
	   (requiresFirmwareAuthorization || !requiredHardwareId.empty() ||
		modelScope->modelsSection.empty() || modelScope->modelsSection.size() > 256U ||
		modelScope->modelsSection.find( L'\0') != std::wstring_view::npos ||
		modelScope->hardwareIds.empty() ||
		modelScope->hardwareIds.size() > INDEX_RECORD_PNP_MAX_COUNT ||
		!std::ranges::all_of( modelScope->hardwareIds, []( const auto &id) {
			return validIndexNativeId( id) && id.find( L'*') == id.npos ;
		}))) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_INVALIDARG),
							  InfBindingReject::INPUT) ;
	}

	// 下位検査の最初の診断を後続へ返す一時値です
	auto error = reverifyCommonDriverInf( inspection) ;
	// 全原byteの不成立をnode成功で上書きしません
	if( error != 0U) {
		return bindingFailure( diagnostic, error, InfBindingReject::CONTENT_REVERIFY) ;
	}

	// 同選択の原root又は必要importです
	const auto				   &package = inspection.closure.packages.front() ;
	// 比較に使う現在nodeの全snapshotです
	DeviceRankSnapshot			current ;
	// 同原INFで一意に確認するnative driver nodeです
	CandidateDriverNodeSnapshot node ;
	// 原deviceに対して独立再取得する全rankです
	OfficialDriverRankAudit		freshAudit ;
	error = collectOfficialInfBindingState(
		instance->second, inspection.workspace->path( package.infRelativePath), package,
		parseDriverVersion( package.driverVersion).value_or( 0U),
		normalizeInfDriverDate( package.driverDate).value_or( L""), current, node, freshAudit,
		diagnostic, nullptr, modelScope != nullptr) ;
	// 原scan/rankの退行又は観測変化では資格化しません
	if( error != 0U || !officialRankAuditsEqual( audit, freshAudit) ||
	   current.currentDriver.provider != provider || current.currentDriver.version != version ||
	   current.currentDriver.date != date) {
		return bindingFailure( diagnostic, error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY),
							  InfBindingReject::BINDING_STATE) ;
	}

	OfficialInfInstallBindingRecord observed ;	// 実native基本節だけから全作用計画を作ります
	observed.scanSessionId			   = session ;
	observed.deviceIdentity			   = identity ;
	observed.device.deviceInstanceId   = instance->second ;
	observed.device.noDriver		   = current.noDriver ;
	observed.device.currentInfFileName = current.currentDriver.infFileName ;
	observed.candidate.infPath		   = inspection.workspace->path( inspection.infRelativePath) ;
	observed.candidate.sectionName	   = node.sectionName ;
	observed.candidate.rank			   = node.rank ;
	observed.rankAudit				   = freshAudit ;
	// WiXに限り実選択の主Hardware IDと元Modelsの完全な一行を同じ端末へ結ぶ
	if( modelScope) {
		// 一覧の下位候補やCompatible IDの一致で実選択の主Hardware IDを補完しない
		if( node.modelIds.empty() ||
		   !containsScopedHardwareId( modelScope->hardwareIds, node.modelIds.front()) ||
		   !containsScopedHardwareId( current.hardwareIds, node.modelIds.front())) {
			return bindingFailure( diagnostic, static_cast<NativeError>( E_ACCESSDENIED),
								  InfBindingReject::CANDIDATE_NODE) ;
		}

		error = verifyOfficialStorageInfModelSelection(
			*inspection.workspace, inspection.closure.entries, package, modelScope->modelsSection,
			node.sectionName, node.modelIds) ;
		// 現在OSの原行との照合不成立では作用計画を作らない
		if( error != 0U) {
			return bindingFailure( diagnostic, error, InfBindingReject::CANDIDATE_NODE) ;
		}

		observed.candidate.modelsSection = modelScope->modelsSection ;
		observed.candidate.modelIds		 = std::move( node.modelIds) ;
		observed.candidate.infClassGuid	 = std::move( node.infClassGuid) ;
		observed.candidate.classGuid	 = std::move( node.classGuid) ;
		observed.candidate.dateTicks	 = node.dateTicks ;
	}

	error = buildRequiredInfComponentPlan( inspection, observed, plan, diagnostic) ;
	// 同issuerが全原検査後だけ保持する不変storage資格です
	std::shared_ptr<const StorageInfQualification> qualification ;
	// 全原作用計画が成立した場合だけprivate資格を構築します
	if( error == 0U && plan) {
		error = buildStorageInfQualification( inspection, observed, *plan, qualification) ;
		// 元service所有関係の拒否をraw作用検査から固定段階で分離します
		if( error != 0U) {
			// 資格の固定拒否段階を任意診断へ保持します
			if( diagnostic) {
				diagnostic->stage = 14010U ;
			}

			error = bindingFailure( diagnostic, error, InfBindingReject::DEPENDENCY) ;
		}
	}

	// 全PACKAGE/SYSTEM作用の資格がない状態では元tokenを発行しません
	if( error == 0U && qualification) {
		error = createOfficialInfInstallBindingImpl(
			session, identity, *inspection.workspace, package, provider, version, date, audit,
			binding, diagnostic, qualification.get(), {},
			modelScope ? std::wstring_view( observed.candidate.modelIds.front())
					   : requiredHardwareId,
			requiresFirmwareAuthorization, {}, modelScope ? &observed.candidate : nullptr) ;
		// 同issuerが発行したtokenだけに全作用資格を保持します
		if( error == 0U) {
			// 当該issuerが所有する同session/deviceの私有記録です
			auto &record				= officialInfInstallBindings_.at( binding.token) ;
			record.requiredPlan			= plan ;
			record.storageQualification = std::move( qualification) ;
			error = revalidateRequiredInfInstallBinding( session, identity, inspection, plan,
														binding, diagnostic) ;
		}
	}

	// 未完成資格/途中失敗のtoken/計画を外へ出しません
	if( error != 0U || binding.token == 0U) {
		static_cast<void>( discardOfficialInfInstallBinding( session, binding.token)) ;
		binding = {} ;
		plan.reset() ;
		return bindingFailure( diagnostic,
							  error != 0U ? error : nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::DEPENDENCY) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み役割計画を単一親の私有bindingへ固定します
 * @param[in] session 元scanです
 * @param[in] identity 元親opaqueです
 * @param[in] inspection 元全byte/CATです
 * @param[out] plan 同元native選択の計画です
 * @param[in] provider 元現在providerです
 * @param[in] version 元現在versionです
 * @param[in] date 元現在日付です
 * @param[in] audit 元全rankです
 * @param[out] binding 成功時だけの元親bindingです
 * @param[out] diagnosticStage null可の元拒否です
 * @param[in] requiredHardwareId 元親の再観測HardwareIdsに必要な公開ID。空は追加条件なし
 * @param[in] requiresFirmwareAuthorization 各必要役割の直前に元親と公式群を確認する場合trueです
 * @return 全成立0、元拒否HRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createRequiredInfInstallBinding(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection &inspection, std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const std::wstring_view provider, const std::wstring_view version, const std::wstring_view date,
	const OfficialDriverRankAudit &audit, OfficialInfInstallBinding &binding,
	RequiredInfBindingDiagnostic *diagnosticStage, const std::wstring_view requiredHardwareId,
	const bool requiresFirmwareAuthorization)
{
	binding = {} ;
	plan.reset() ;
	// 空入力と実検査以降を別の数値として保持します
	if( diagnosticStage) {
		*diagnosticStage	  = {} ;
		diagnosticStage->path = 2U ;
	}

	// 公開件数や別sessionから元閉包の導入権限を発行しません
	if( !inspection.workspace || inspection.scanSessionId != session) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 元全role/CAT/memberの再検証開始を採取します
	if( diagnosticStage) {
		diagnosticStage->stage = 1U ;
	}

	auto error = reverifyCommonDriverInf( inspection) ;	// 全role/CAT/memberを再確認します
	// 再検証失敗はbindingへ進めません
	if( error != 0U) {
		return bindingFailure( diagnosticStage, error, InfBindingReject::CONTENT_REVERIFY) ;
	}

	// 元親の完全native状態の固定段階です
	if( diagnosticStage) {
		diagnosticStage->stage = 2U ;
	}

	error = createOfficialInfInstallBindingImpl(
		session, identity, *inspection.workspace, inspection.closure.packages.front(), provider,
		version, date, audit, binding, diagnosticStage, nullptr, {}, requiredHardwareId,
		requiresFirmwareAuthorization) ;
	// 元親の完全状態と一意nodeを先に固定します
	if( error != 0U) {
		return error ;
	}

	auto &record =
		// 同issuerで今固定した元nodeです
		officialInfInstallBindings_.at( binding.token) ;
	error = buildRequiredInfComponentPlan( inspection, record, plan, diagnosticStage) ;
	// 選択した元端末のフィルターを確認できた場合だけ、同じ原値を元資格へ保持します
	if( error == 0U && plan->replacesWifiBusUpperFilters_) {
		error = readSelectedWifiBusUpperFilters( record.device.deviceInstanceId,
												record.wifiBusUpperFilters.emplace()) ;
		// 端末を確定できない場合は、後段で元tokenごと破棄します
		if( error != 0U) {
			constexpr auto STAGE = static_cast<std::uint32_t>(
				SystemInfDiagnosticStage::
					WIFI_FILTER_BINDING) ;	// フィルター観測不成立の固定段階です
			// 任意の診断出力に端末の実値を含めません
			if( diagnosticStage) {
				diagnosticStage->stage = STAGE ;
			}

			error = bindingFailure( diagnosticStage, error, InfBindingReject::DEPENDENCY, STAGE) ;
		}
	}

	// 私有node解析が成立した計画だけを元tokenへ固定します
	if( error == 0) {
		record.requiredPlan = plan ;
		// 同issuer記録との直前再照合を別段階として採取します
		if( diagnosticStage) {
			diagnosticStage->stage = 10U ;
		}

		error = revalidateRequiredInfInstallBinding( session, identity, inspection, plan, binding,
													diagnosticStage) ;
		// 下位が採取した最初の拒否を維持し、元binding再照合失敗の欠測も防ぎます
		error = bindingFailure( diagnosticStage, error, InfBindingReject::BINDING_STATE, 10U) ;
	}

	// 関係/適用性拒否では未公開tokenを残しません
	if( error != 0U) {
		static_cast<void>( discardOfficialInfInstallBinding( session, binding.token)) ;
		binding = {} ;
		plan.reset() ;
	}

	// 全成功だけを最終段階へ進め、失敗した段階は変更しません
	if( error == 0U && diagnosticStage) {
		diagnosticStage->stage = 11U ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元親と全必要役割を変更前にread-onlyで再検証します
 * @param[in] session 元scanです
 * @param[in] identity 元親opaqueです
 * @param[in] inspection 元保護閉包です
 * @param[in] plan 元私有関係です
 * @param[in] binding 元親bindingです
 * @param[in,out] diagnosticStage null可の最初の固定拒否段階です
 * @return 全byte/関係/元状態一致0、失効/未確認はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateRequiredInfInstallBinding(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection								 &inspection,
	const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnosticStage) const
{
	const auto stored = officialInfInstallBindings_.find( binding.token) ;	// 元issuer記録です
	// 別byte/別session/公開DTOから転用した計画は拒否します
	if( !plan || !inspection.workspace || stored == officialInfInstallBindings_.end() ||
	   stored->second.requiredPlan != plan || plan->session_ != session ||
	   plan->basePath_ != inspection.infRelativePath) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto error = revalidateOfficialInfInstallBinding(
		session, identity, *inspection.workspace, inspection.closure.packages.front(),
		binding) ;	// 同元node/現在stateを先に再照合します
	// 元選択変化を旧節名の再解析で隠しません
	if( error != 0) {
		return error ;
	}

	std::shared_ptr<const RequiredDriverComponentPlan>
		fresh ;	// 現在の同原byte/役割nodeから再構築します
	error = buildRequiredInfComponentPlan( inspection, stored->second, fresh, diagnosticStage) ;
	// 元必要関係の全memberを現在byteへ再照合します
	if( error != 0U || !fresh || fresh->members_.size() != plan->members_.size() ||
	   fresh->defersRootCopyInf_ != plan->defersRootCopyInf_ ||
	   fresh->verifiedNeedsEdgeCount_ != plan->verifiedNeedsEdgeCount_ ||
	   fresh->dependencyFiles_ != plan->dependencyFiles_ ||
	   fresh->systemFiles_ != plan->systemFiles_ || fresh->systemEffects_ != plan->systemEffects_ ||
	   fresh->systemServices_ != plan->systemServices_ ||
	   fresh->replacesWifiBusUpperFilters_ != plan->replacesWifiBusUpperFilters_ ||
	   fresh->replacesWifiBusUpperFilters_ != stored->second.wifiBusUpperFilters.has_value() ||
	   fresh->storageEffects_ != plan->storageEffects_ ||
	   fresh->stageOnlyImportOrdinals_ != plan->stageOnlyImportOrdinals_ ||
	   fresh->delayedRegistration_ != plan->delayedRegistration_) {
		return error ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 現用親子と全作用の差があれば同じ補助サービスの所有を引き継がない
	if( static_cast<bool>( fresh->displayOwnership_) != static_cast<bool>( plan->displayOwnership_) ||
	   (fresh->displayOwnership_ && *fresh->displayOwnership_ != *plan->displayOwnership_)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 同一の端末と元バイトを資格の発行時と変更の直前で独立に観測します
	if( stored->second.wifiBusUpperFilters) {
		MtdHandlerProperty current ;	// 同元端末の新しい読み取り値です
		error = readSelectedWifiBusUpperFilters( stored->second.device.deviceInstanceId, current) ;
		// 空と不在の間の変化も含め、元観測の差を許可済みへ変換しません
		if( error != 0U || current != *stored->second.wifiBusUpperFilters) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 元whole graphと現deviceのservice所有関係をprivate資格へ再照合します
	if( stored->second.storageQualification) {
		// 比較に使う現在nodeの全snapshotです
		std::shared_ptr<const StorageInfQualification> current ;
		error = buildStorageInfQualification( inspection, stored->second, *fresh, current) ;
		// 元資格又は元原文から保持した比較値です
		const auto &original = *stored->second.storageQualification ;
		// 現在config/所有集合/全raw作用が変化した場合は元資格を失効させます
		if( error != 0U || !current || current->effects_ != original.effects_ ||
		   current->autoLogger_ != original.autoLogger_ ||
		   current->singleBoot_ != original.singleBoot_ ||
		   current->mtdHandlers_ != original.mtdHandlers_ ||
		   current->mtdCurrentProperties_ != original.mtdCurrentProperties_ ||
		   current->currentDeviceService_ != original.currentDeviceService_ ||
		   current->basicSection_ != original.basicSection_ ||
		   current->infPath_ != original.infPath_ || current->session_ != original.session_ ||
		   current->deviceIdentity_ != original.deviceIdentity_) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// 自動起動型の全所有者は既に一致したeffectsの現在観測に含まれる
		const bool separateOwners =
			!original.effects_.automaticHost && !original.singleBoot_ ;	// 従来の配置方式だけで保持
		// 途中の照合で二方式の証拠を混ぜず、従来方式は全所有者の件数も保つ
		if( static_cast<bool>( current->ownershipProof_) != separateOwners ||
		   static_cast<bool>( original.ownershipProof_) != separateOwners ||
		   (separateOwners &&
			current->ownershipProof_->owners.size() != original.ownershipProof_->owners.size())) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		// 元exact所有adapterを原順でfresh snapshotへ照合します
		for( std::size_t index = 0U;
			original.ownershipProof_ && index < original.ownershipProof_->owners.size(); ++index) {
			// 変更前の元観測を後続比較まで保持します
			const auto &before = original.ownershipProof_->owners[index] ;
			// 元入力から独立に再取得する比較先の観測です
			const auto &after = current->ownershipProof_->owners[index] ;
			// 各peerの現在状態と原package node/rankの途中変化を拒否します
			if( before.instance != after.instance ||
			   before.registeredPackage != after.registeredPackage ||
			   !deviceRankSnapshotsEqual( before.current, after.current) ||
			   !candidateNodeSnapshotsEqual( before.candidate, after.candidate) ||
			   !officialRankAuditsEqual( before.rank, after.rank)) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}
		}
	}
	// 通常計画へstorage作用だけを後付けした状態を拒否します
	else if( fresh->storageEffects_) {
		return E_ACCESSDENIED ;
	}

	// 件数一致だけで異なるWindows選択節/role rankを受理しません
	if( fresh->selectedPackages_.size() != plan->selectedPackages_.size()) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 非機能importの原順と機能選択の全関係を維持します
	for( std::size_t index = 0U; index < plan->selectedPackages_.size(); ++index) {
		const auto &before = plan->selectedPackages_[index] ;	// 同private planの元選択です
		const auto &after  = fresh->selectedPackages_[index] ;	// 現在の同元INF選択です
		// 別node節/装飾/Windows rank/参照/必要子を同計画へ補正しません
		if( before.selectedBasicSection != after.selectedBasicSection ||
		   before.selectedInstallSection != after.selectedInstallSection ||
		   before.selectedNativeRank != after.selectedNativeRank ||
		   before.activeRequiredInfPaths != after.activeRequiredInfPaths ||
		   before.unresolvedCopyInfPaths != after.unresolvedCopyInfPaths ||
		   before.requiredComponents != after.requiredComponents) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 検証されたsource順と関係を保持し、件数だけで一致しません
	for( std::size_t i = 0; i < plan->members_.size(); ++i) {
		const auto &a = plan->members_[i] ;		// 元関係です
		const auto &b = fresh->members_[i] ;	// 現在byteの関係です
		// 親/ID/Class役割の差は復旧前に拒否します
		if( a.packageOrdinal != b.packageOrdinal || a.role != b.role ||
		   a.parentPackageOrdinal != b.parentPackageOrdinal ||
		   a.componentHardwareIds != b.componentHardwareIds ||
		   a.packageOrdinal >= inspection.requiredInfPackages.size()) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const auto &package = inspection.requiredInfPackages[a.packageOrdinal] ;	// 元roleです
		GUID		nativeClass{} ;													// 実INFの独立Classです
		error = readCandidateInfClass( inspection.workspace->path( package.infRelativePath),
									  package.className, nativeClass) ;
		// Class文字列だけでroleを確定しません
		if( error != 0U || normalizeIdentifier( formatClassGuid( nativeClass)) !=
							  normalizeIdentifier( package.classGuid)) {
			return error ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Extensionは同じ元親のPnP一致が必要で、base Class一致は要求しません
		if( a.role == DriverPlanRole::EXTENSION) {
			const auto &device = stored->second.device ;	// 元親の秘密IDだけです
			const bool	match  = std::ranges::any_of( package.hardwareIds, [&]( const auto &id) {
				  return std::ranges::any_of( device.hardwareIds,
											 [&]( const auto &local) {
												 return normalizeIdentifier( id) ==
														normalizeIdentifier( local) ;
											 }) ||
						 std::ranges::any_of( device.compatibleIds, [&]( const auto &local) {
							 return normalizeIdentifier( id) == normalizeIdentifier( local) ;
						 }) ;
			  }) ; // Modelsの表記同一ではなく実PnP一致です
			// 別device extensionを一計画へ追加しません
			if( !match) {
				return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
			}
		}
	}

	return revalidateOfficialInfInstallBinding( session, identity, *inspection.workspace,
											   inspection.closure.packages.front(), binding) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 登録と適用の境界で同じ署名索引の再確認を必要とするか判定する
 * @param[in] effects 元の署名済みストレージパッケージの作用とクラス
 * @return HDC、メディアチェンジャー、単一起動、共有起動ログ又は共有補助サービスの場合true
 */
//------------------------------------------------------------------------------
static bool requiresSignedStorageAuthorization( const StorageInfEffects &effects)
{
	const auto &name = effects.service.className ;	// 元検査済みのストレージクラス
	return effects.singleBootEvent || effects.autoLogger || effects.service.auxiliary ||
		   CompareStringOrdinal( name.c_str(), -1, L"HDC", -1, TRUE) == CSTR_EQUAL ||
		   CompareStringOrdinal( name.c_str(), -1, L"MediumChanger", -1, TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実登録又は親指定適用の直前に同じDisplay所有と索引操作を再照合する
 * @param[in] session 元スキャン
 * @param[in] identity 同じ親のopaque ID
 * @param[in] inspection 同じ元署名閉包
 * @param[in] plan 現用所有を読取済みの同じ親計画
 * @param[in] binding 同じ一台の私有binding
 * @param[in] operation 登録開始時の実行操作ID
 * @param[in] authorize 同じ署名元と実UTCの最終確認
 * @return 全照合成立で0、それ以外はHRESULT
 * @note 現用の再観測中または元承認の確認中に操作が変わった場合は登録・適用へ進めない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::authorizeDisplayInfMutation(
	ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
	const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const OfficialInfInstallBinding &binding, OperationId operation,
	const std::function<NativeError()> &authorize) const
{
	// 同じworkerの実行中索引と親選択を、再照合するたびに確認する
	const auto ownsOperation = [this, session, identity, operation] {
		return session != 0U && session == scanSessionId_ &&
			   GetCurrentThreadId() == ownerThreadId_ && operation != 0U &&
			   operation == activeInstallOperation_ && installEntered_ && indexInventory_ &&
			   installProofInventory_ == indexInventory_ &&
			   std::ranges::find( activeIndexDevices_, identity) != activeIndexDevices_.end() ;
	} ;
	// 同じ保護済み候補、現用親と全共用先、元登録位置を同期して読み直す
	const auto reobserve = [&] {
		const auto fresh =
			revalidateRequiredInfInstallBinding( session, identity, inspection, plan,
												binding) ;	// 元所有・候補と計画の一致を確認する
		// 先の照会失敗を保持し、対象外の不在検査を追加しない
		if( fresh != 0U || !plan->defersRootCopyInf_ ||
		   inspection.closure.unresolvedRootCopyInfAbsence !=
			   OfficialRootCopyInfAbsence::NATIVE_SOURCE) {
			return fresh ;
		}

		return verifyPreparedNativeCopyInfAbsence( inspection) ;
	} ;
	return verifyDisplayMutationBoundary( ownsOperation, reobserve, authorize) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 必要役割をstageし指定親と一意な必要SWC子だけを導入します
 * @param[in] session 元scanです
 * @param[in] identity 元選択親です
 * @param[in] inspection 元検証済み閉包です
 * @param[in] plan 元私有関係です
 * @param[in] binding 元親bindingです
 * @param[in] parentWindowNative 明示操作の親windowです
 * @param[out] roles 登録と指定導入の実結果、必要な補助サービスの反映確認を役割別に保持します
 * @param[out] imports 必要nullの原ordinal/登録結果です。部分失敗と未実行を保持します
 * @param[out] rebootRequired 実APIが返した再起動要否です
 * @param[in] authorizationCheck 同原署名recordと実UTCを同期再検証する。HDC、MTD、メディアチェンジャー、共有補助サービスとCatalog対象では必須
 * @return 指定API完了かつ必須作用の未確認なしは0、未反映または未確認はS_FALSE、API失敗はHRESULTです
 * @note 必要roleの元/登録INF/rootを変更非共有で計画終端まで保持します。Extension反映をbase API成功から推測しません。全device導入APIを呼びません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installBoundRequiredInfPlan(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection								 &inspection,
	const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const OfficialInfInstallBinding &binding, const std::uintptr_t parentWindowNative,
	std::vector<DriverPlanRoleExecutionResult> &roles, std::vector<RequiredInfStageResult> &imports,
	bool &rebootRequired, const std::function<NativeError()> &authorizationCheck)
{
	roles.clear() ;
	imports.clear() ;
	rebootRequired = false ;
	auto error	   = revalidateRequiredInfInstallBinding( session, identity, inspection, plan,
														 binding) ;	// 変更直前の同issuer診断です
	// 全選択preflightとは別に変更直前も全関係を確認します
	if( error != 0U) {
		return error ;
	}

	const auto &bound =
		// 同issuerの元端末と全作用です
		officialInfInstallBindings_.at( binding.token) ;
	const auto qualification = bound.storageQualification ;	// 同issuerの不変storage資格です
	const bool wifiBus =
		// 同じ端末の置換前の値を保持しています
		bound.wifiBusUpperFilters.has_value() ;
	const bool singleHardwareId = !bound.requiredHardwareId.empty() ;	// 従来の完全IDを要求するかです
	const bool hardwareScoped =
		singleHardwareId || bound.requiresFirmwareAuthorization ;	// 元署名レコードの端末条件です
	// 再確認を必要とする元ストレージ作用は単一の判定を使う
	const bool signedStorage =
		qualification && requiresSignedStorageAuthorization( qualification->effects_) ;
	const bool auxiliaryStorage =
		qualification && qualification->effects_.service.auxiliary ;	// 共有補助を持つ元選択です
	const bool automaticStorage =
		qualification && qualification->effects_.automaticHost.has_value() ;	// 自動起動を伴う元選択
	const bool singleBootStorage =
		qualification && qualification->singleBoot_.has_value() ;	// 関連起動サービスだけを持つ元選択
	const bool checkStorageReflection =
		automaticStorage || singleBootStorage ;	// 指定適用中に同じ登録の反映を読む場合
	const bool deferredCopyInf =
		plan->defersRootCopyInf_ ;								// 基本閉包の登録後照合を要する通常更新です
	const bool display = plan->displayOwnership_ != nullptr ;	// 現用補助の所有を確かめる指定Display
	const auto displayOperation =
		display ? activeInstallOperation_ : 0U ;			// 同じDisplay変更が属する実操作
	DisplayType1EventBoundary	  displayEventBoundary ;	// 最初の変更前だけに取得する同操作の境界
	NativeError					  displayEventError{} ;		// イベント取得不能は導入APIの元結果と分ける
	DriverStorageReflectionResult storageReflection ;		// 同じOEM閉包を保持した指定適用直後の読取り
	// 登録後に基本閉包を確認する場合も、元署名と期限を各変更の前に再検証します
	if( (hardwareScoped || signedStorage || wifiBus || deferredCopyInf || display) &&
	   !authorizationCheck) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 登録先の閉包を読む方式は元索引で実行中の対象だけに限定する
	if( checkStorageReflection || deferredCopyInf || display) {
		// 保留中の候補や別操作の対象から共有サービスの変更を始めない
		if( !installProofInventory_ || activeInstallOperation_ == 0U ||
		   std::ranges::find( activeIndexDevices_, identity) == activeIndexDevices_.end()) {
			return E_ACCESSDENIED ;
		}

		// OEM INFの登録前に、対応するFileRepositoryを確認できることを確定する
		if( !driver_store_inf_detail::transport().storageStoreLocation) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	const std::function<NativeError()> hardwareAuthorization = [&]() {
		return authorizeScopedHardwareDevice( bound.device.deviceInstanceId,
											 bound.requiredHardwareId, authorizationCheck) ;
	} ; // 必要roleの変更前にも同じ元親と期限を再確認します
	const auto *hardwareBoundary =
		singleHardwareId ? &hardwareAuthorization
		: (bound.requiresFirmwareAuthorization || signedStorage || deferredCopyInf || display)
			? &authorizationCheck
			: nullptr ;	// 各役割の変更前に同じ端末と群を照合します
	const std::function<NativeError()> wifiStageAuthorization = [&]() {
		const auto authorized = hardwareBoundary
									? (*hardwareBoundary)()
									: authorizationCheck() ;	// 元署名と対象の再照合結果です
		return authorized != 0U ? authorized
								: revalidateRequiredInfInstallBinding( session, identity, inspection,
																	  plan, binding) ;
	} ; // 各登録APIの直前に元署名、サービスと同じ端末のフィルターを照合します
	const std::function<NativeError()> storageStageAuthorization = [&]() {
		const auto fresh = revalidateRequiredInfInstallBinding(
			session, identity, inspection, plan, binding) ;	// 現在の共有所有と選択の再照合
		return fresh != 0U ? fresh : (*hardwareBoundary)() ;
	} ; // 共有設定の再観測後に元署名と実UTCを確認してから登録する
	// 同じ計画と現在所有を実登録の直前に再観測し、最後に元承認を確認する
	const std::function<NativeError()> displayStageAuthorization = [&] {
		return authorizeDisplayInfMutation( session, identity, inspection, plan, binding,
										   displayOperation, *hardwareBoundary) ;
	} ;
	const auto *stageBoundary = display ? &displayStageAuthorization
								: (auxiliaryStorage || singleBootStorage)
									? &storageStageAuthorization
								: wifiBus ? &wifiStageAuthorization
										  : hardwareBoundary ;	// base適用前の各登録にだけ渡します
	roles.resize( plan->members_.size() + 1U) ;
	roles.front().role	  = DriverPlanRole::BASE_DRIVER ;
	roles.front().ordinal = 1U ;
	// import失敗時も全機能roleの未実行を結果分母へ保持します
	for( std::size_t i = 0U; i < plan->members_.size(); ++i) {
		roles[i + 1U].role	  = plan->members_[i].role ;
		roles[i + 1U].ordinal = static_cast<std::uint32_t>( i + 2U) ;
	}

	// 同意/復旧が成立したこの入口で、最初のstageより前から共有先を終端まで保持します
	std::unique_ptr<MtdSharedFileOperation> mtdFiles ;
	// 同MTD操作のqueueと部分copy結果です
	MtdQueueResult							mtdResult ;
	// 同選択が正式MTD資格を持つかの判定です
	const bool								mtd =
		qualification && normalizeIdentifier( qualification->effects_.service.className) == L"MTD" ;
	// MTDだけ同意・復旧成立後に共有DLLの保持を開始します
	if( mtd) {
		roles.front().sharedCopy.emplace() ;
		// 対象roleの共有copy結果です
		auto &shared = *roles.front().sharedCopy ;
		error		 = authorizationCheck ? authorizationCheck() : E_ACCESSDENIED ;
		// 元recordが有効な場合だけ原共有file preflightを行います
		if( error == 0U) {
			error = MtdSharedFileOperation::prepare( *inspection.workspace,
													qualification->effects_.service, mtdFiles) ;
		}

		shared.preflightOutcome = error ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		shared.preflightError	= error ;
		// preflight失敗を対象の結果へ保持しstageへ進みません
		if( error != 0U) {
			roles.front().reflection = DriverPlanReflectionState::FAILED ;
			return error ;
		}
	}

	// 親の適用から子が動く場合も読むため、既知Type 1の境界を最初の登録前に一度だけ採取する
	if( display && plan->displayOwnership_->type1) {
		displayEventError = captureDisplayType1EventBoundary( displayEventBoundary) ;
	}

	imports.resize( plan->stageOnlyImportOrdinals_.size()) ;
	// 必要nullの元/登録byte guardを計画終端まで所有します
	std::vector<std::unique_ptr<RegisteredInfGuard>> importRegistrations( imports.size()) ;
	// 必要nullは独立候補/役割にせず、登録結果だけを全分母へ保持します
	for( std::size_t index = 0U; index < imports.size(); ++index) {
		imports[index].packageOrdinal =
			static_cast<std::uint32_t>( plan->stageOnlyImportOrdinals_[index]) ;
	}

	// 全作用が資格化された必要importを先に登録し、終端まで元/登録byteを保持します
	for( std::size_t index = 0U; index < imports.size(); ++index) {
		// 成功確定まで部分値を外へ出さない当該結果です
		auto	   &result = imports[index] ;
		// 同選択の原root又は必要importです
		const auto &package = inspection.requiredInfPackages.at( result.packageOrdinal) ;
		error				= mtd && !hardwareScoped ? authorizationCheck() : 0U ;
		// Displayでは下位の変更直前で同選択を確認する。他は従来の位置で照合する
		if( error == 0U && !display) {
			error =
				revalidateRequiredInfInstallBinding( session, identity, inspection, plan, binding) ;
		}

		importRegistrations[index] = std::make_unique<RegisteredInfGuard>() ;
		// 変更直前の元資格が成立した場合だけsource guardを取得します
		if( error == 0U) {
			error = importRegistrations[index]->initialize(
				inspection.workspace->path( package.infRelativePath)) ;
		}

		// 既登録guardへ確認する返却pathです。導入権限ではありません
		std::wstring staged ;
		// sourceの原byteを保持できた場合だけ必要importを登録します
		if( error == 0U) {
			error = stageOfficialInfPackage( *inspection.workspace, package, staged,
											qualification.get(), nullptr, stageBoundary) ;
		}

		// 登録結果の完全原byteを確認できたものだけを成功へ進めます
		if( error == 0U) {
			error = importRegistrations[index]->verify( staged) ;
		}

		result.error   = error ;
		result.outcome = error == 0U ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
		// 部分登録を消去せず、後続base/installを未実行として返します
		if( error != 0U) {
			return error ;
		}
	}

	std::vector<std::unique_ptr<RegisteredInfGuard>> registrations(
		// 計画終端まで全登録INFをpinします
		roles.size()) ;
	std::wstring type1RegisteredInf ;	// 同じ導入が保持する審査済みType 1子の登録先

	// Windows CopyINFの再帰import前に全必要INFを同境界でstageします
	for( std::size_t order = 0; order < roles.size(); ++order) {
		const auto	i = (order + 1U) % roles.size() ;	// 必要role先行、baseは最後です
		const auto &package =
			i ? inspection.requiredInfPackages[plan->members_[i - 1U].packageOrdinal]
			  : inspection.closure.packages.front() ;	// 実閉包memberです
		std::wstring staged ;							// 検証済み登録先です
		registrations[i] =
			std::make_unique<RegisteredInfGuard>() ;	// 各roleの元/root/登録を単独所有します
		error = mtd && !hardwareScoped ? authorizationCheck() : 0U ;
		// Displayでは下位の変更直前で同選択を確認する。他は従来の位置で照合する
		if( error == 0U && !display) {
			error =
				revalidateRequiredInfInstallBinding( session, identity, inspection, plan, binding) ;
		}

		// 同元資格の直前再照合後だけ機能roleのsource guardを取得します
		if( error == 0U) {
			error =
				registrations[i]->initialize( inspection.workspace->path( package.infRelativePath)) ;
		}

		// 元/rootを保持できない役割は登録や後続device作用へ進めません
		if( error == 0U) {
			error = stageOfficialInfPackage( *inspection.workspace, package, staged,
											qualification.get(), nullptr, stageBoundary) ;
		}

		// 関数内stage guardの終了後も同じ全byteを保持し、後続base作用中の変更を防ぎます
		if( error == 0U) {
			error = registrations[i]->verify( staged) ;
		}

		roles[i].stageError	  = error ;
		roles[i].stageOutcome = error ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		roles[i].reflection =
			error ? DriverPlanReflectionState::FAILED : DriverPlanReflectionState::STAGED ;
		// 部分stageを全成功にせず、後続未実行を残します
		if( error != 0U) {
			return error ;
		}

		// 審査済みType 1子だけの登録先を現用子の事後照合へ引き継ぐ
		if( i != 0U && display &&
		   reviewedDisplayType1Registration(
			   *plan->displayOwnership_,
			   plan->selectedPackages_.at( plan->members_[i - 1U].packageOrdinal + 1U))) {
			type1RegisteredInf = std::move( staged) ;
		}
	}

	error = installBoundOfficialInfImpl(
		session, identity, *inspection.workspace, inspection.closure.packages.front(), binding,
		parentWindowNative, rebootRequired, &roles.front().installDiagnosticMissing, mtdFiles.get(),
		mtd ? &mtdResult : nullptr,
		mtd || hardwareScoped || signedStorage || wifiBus || deferredCopyInf || display
			? &authorizationCheck
			: nullptr,
		nullptr, wifiBus ? &inspection : nullptr,
		checkStorageReflection ? &storageReflection : nullptr,
		deferredCopyInf ? &inspection : nullptr, display ? &inspection : nullptr) ;
	// MTDの部分copy結果を既詳細へ反映します
	if( mtd) {
		// copy開始後の原失敗を空のcopy成功へ変換しません
		if( error != 0U && mtdResult.preparationStarted && !mtdResult.commitCompleted &&
		   mtdResult.copyError == 0U) {
			mtdResult.copyError = error ;
		}

		// 対象roleへ反映する共有copy結果です
		auto &shared = *roles.front().sharedCopy ;
		// copy開始済みの場合だけ実行結果を投影します
		if( mtdResult.preparationStarted) {
			shared.copyOutcome = mtdResult.copyError		 ? OutcomeCode::FAILURE
								 : mtdResult.commitCompleted ? OutcomeCode::SUCCESS
															 : OutcomeCode::NOT_STARTED ;
			shared.copyError   = mtdResult.copyError ;
		}

		shared.renameSucceeded		 = mtdResult.shared.renameSucceeded ;
		shared.created				 = mtdResult.shared.created ;
		shared.reused				 = mtdResult.shared.reused ;
		shared.cleanupUncertain		 = mtdResult.shared.cleanupUncertain ;
		shared.parameterCleanupError = mtdResult.parameterCleanupError ;
		shared.postVerifyError		 = mtdResult.postVerifyError ;
		shared.queueStarted			 = mtdResult.commitStarted ;
		shared.queueCompleted		 = mtdResult.commitCompleted ;
		shared.systemDelayed		 = mtdResult.systemDelayed ;
		shared.failureStage			 = mtdResult.shared.failureStage ;
	}

	roles.front().installError =
		mtd && mtdResult.deviceInstallStarted ? mtdResult.deviceInstallError : error ;
	roles.front().installOutcome = mtd ? (!mtdResult.deviceInstallStarted ? OutcomeCode::NOT_STARTED
										  : mtdResult.deviceInstallSucceeded ? OutcomeCode::SUCCESS
																			 : OutcomeCode::FAILURE)
								   : error ? OutcomeCode::FAILURE
										   : OutcomeCode::SUCCESS ;
	roles.front().reflection	 = mtd && mtdResult.deviceInstallSucceeded
									   ? DriverPlanReflectionState::INSTALL_API_COMPLETED
								   : error ? DriverPlanReflectionState::FAILED
										   : DriverPlanReflectionState::INSTALL_API_COMPLETED ;
	// Base API失敗では必要子/extension完了を推測しません
	if( error != 0U) {
		return error ;
	}

	bool	   pending{} ;														// 必須作用に反映待ちまたは未確認があるかです
	const auto parentInstance = deviceInstances_.at( std::wstring( identity)) ;	// 元選択親です
	// Windows APIの成功を保持したまま、同じ対象の補助作用の実反映を確認します
	if( auxiliaryStorage) {
		auto &result = roles.front().auxiliaryService ;	// 基本役割に紐付く補助作用の結果です
		// 自動起動型は指定適用に使用したOEM INFを保持した時点の観測を使う
		if( automaticStorage) {
			result = storageReflection ;
		} else {
			result =
				qualification->ownershipProof_
					? observeAppliedStorageAuxiliary(
						  parentInstance, inspection, qualification->effects_,
						  *qualification->ownershipProof_, rebootRequired)
					: DriverAuxiliaryExecutionResult{DriverAuxiliaryReflectionState::UNCONFIRMED,
													 nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
		}

		pending = result->state != DriverAuxiliaryReflectionState::CONFIRMED ;
	}

	// 指定APIが成功しても、単一起動の反映と必要な再起動は独立した結果として保持する
	if( singleBootStorage) {
		roles.front().singleBootStorage = storageReflection ;
		pending = storageReflection.state != DriverStorageReflectionState::CONFIRMED ;
	}

	// 各必要roleを同じ親だけへ限定します
	for( std::size_t i = 0; i < plan->members_.size(); ++i) {
		const auto &member = plan->members_[i] ;	// 元AddComponent/CopyINF関係です
		auto	   &role   = roles[i + 1U] ;		// 候補別に保持する実結果です
		// ExtensionのWindows適用順位と反映を独自に置換しません
		if( member.role == DriverPlanRole::EXTENSION) {
			role.reflection = DriverPlanReflectionState::WINDOWS_PENDING ;
			pending			= true ;
			continue ;
		}

		DeviceRankSnapshot parent ;	// 実base反映とstartedをread-only確認します
		error			 = readDeviceRankSnapshot( parentInstance, parent) ;
		const auto &base = inspection.closure.packages.front() ;	// 元検証baseです
		// Base API成功だけで子の親startedや反映を補完しません
		if( error != 0U || parent.node.read.state != DevicePropertyReadState::VALUE ||
		   (parent.node.statusFlags.value_or( 0U) & DN_STARTED) == 0U || parent.noDriver ||
		   normalizeIdentifier( parent.currentDriver.provider) !=
			   normalizeIdentifier( base.providerName) ||
		   parent.currentDriver.version != base.driverVersion ||
		   parent.currentDriver.date != normalizeInfDriverDate( base.driverDate).value_or( L"")) {
			role.reflection	  = DriverPlanReflectionState::WINDOWS_PENDING ;
			role.installError = error ;
			pending			  = true ;
			continue ;
		}

		DeviceInfoSet devices( driver_store_inf_detail::transport().inventory.open(
			nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT)) ;	// Present子だけです
		std::wstring  childInstance ;										// 一意に結合した秘密SWC子です
		// 集合生成失敗を子不存在へ変換しません
		if( !devices.valid()) {
			error = nativeErrorFromWin32( GetLastError()) ;
		} else {
			// 元親とSWC IDが一致する一意なpresent子を有限列挙します
			for( DWORD n = 0; n <= 4096U; ++n) {
				SP_DEVINFO_DATA child{} ;	// 同集合の候補子です
				child.cbSize = sizeof( child) ;
				// 正式終端以外の失敗を部分一致成功にしません
				if( !driver_store_inf_detail::transport().inventory.enumerate( devices.get(), n,
																			 &child)) {
					const auto native = GetLastError() ;	// 元列挙診断です
					error = native == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( native) ;
					break ;
				}

				// 有限上限を超える集合では実行しません
				if( n == 4096U) {
					error = nativeErrorFromWin32( ERROR_MORE_DATA) ;
					break ;
				}

				std::wstring relation ;	// 親の正式read-only propertyです
				// 未読取や異なる親を必要子としません
				if( !readDeviceString( devices.get(), child, DEVPKEY_Device_Parent, relation) ||
				   normalizeIdentifier( relation) != normalizeIdentifier( parentInstance)) {
					continue ;
				}

				// 同present子の元Hardware ID群です。worker内の照合だけに使います
				const auto ids =
					readDeviceStringList( devices.get(), child, DEVPKEY_Device_HardwareIds) ;
				const bool matches = std::ranges::any_of( ids, [&]( const auto &id) {
					return std::ranges::any_of(
						member.componentHardwareIds, [&]( const auto &expected) {
							return normalizeIdentifier( id) == normalizeIdentifier( expected) ;
						}) ;
				}) ; // 元ComponentIDsにWindowsが付加するSWC IDだけです
				// 無関係SWC/appを導入しません
				if( !matches) {
					continue ;
				}

				std::wstring instance ;	// worker内限定childです
				// 曖昧子とID読取失敗を一意な子へ変換しません
				if( !childInstance.empty() ||
				   !readDeviceInstanceId( devices.get(), child, instance)) {
					error = nativeErrorFromWin32( ERROR_DUP_NAME) ;
					break ;
				}

				childInstance = std::move( instance) ;
			}
		}

		// 列挙失敗は部分失敗、正式不存在はWindows反映待ちです
		if( error != 0U) {
			role.installError	= error ;
			role.installOutcome = OutcomeCode::FAILURE ;
			role.reflection		= DriverPlanReflectionState::FAILED ;
			return error ;
		}

		// 非同期にまだ生成されていない子を推測導入しません
		if( childInstance.empty()) {
			role.reflection = DriverPlanReflectionState::WINDOWS_PENDING ;
			pending			= true ;
			continue ;
		}

		// 計画ordinalに結合した元検査済み子packageです
		const auto				   &package = inspection.requiredInfPackages[member.packageOrdinal] ;
		DeviceRankSnapshot			child ;	// 子の全現在状態です
		CandidateDriverNodeSnapshot node ;	// 子の一意な指定INF nodeです
		OfficialDriverRankAudit		audit ;	// 子に対する実rankです
		error = collectOfficialInfBindingState(
			childInstance, inspection.workspace->path( package.infRelativePath), package,
			parseDriverVersion( package.driverVersion).value_or( 0U),
			normalizeInfDriverDate( package.driverDate).value_or( L""), child, node, audit) ;
		const auto childIdentity = std::wstring( identity) + L"/required-component-" +
								   // UI非公開の同操作内opaqueです
								   std::to_wstring( i + 1U) ;
		OfficialInfInstallBinding	   childBinding ;						// 同issuer child用です
		const RequiredChildObservation observation{child, node, audit} ;	// 同実子の状態です
		const RequiredChildProof	   proof{
			  session,		  activeInstallOperation_,
			  binding.token,  i,
			  &inspection,	  plan.get(),
			  &package,		  &observation,
			  identity,		  childIdentity,
			  parentInstance, childInstance} ;	// 元親と実列挙子だけの同期proofです
		bool	   childInserted{} ;			// このscopeが新規に所有したmap entryだけを回収します
		const auto releaseChild = [&]( void *) noexcept {
			// このscopeのproofとtokenだけを終了し、既存entryは削除しません
			if( childInserted && activeRequiredChild_ == &proof) {
				// この子scopeで発行できたbindingだけを破棄します
				if( childBinding.token != 0U) {
					static_cast<void>(
						discardOfficialInfInstallBinding( session, childBinding.token)) ;
				}

				activeRequiredChild_ = nullptr ;
				deviceInstances_.erase( childIdentity) ;
			}
		} ;
		// 途中失敗でもこの同期scopeの新規子だけを回収します
		const std::unique_ptr<void, decltype( releaseChild)> childScope{this, releaseChild} ;
		// 子の同Class/全状態/一意node/非退行rankからのみ権限を発行します
		if( error == 0U) {
			// 別scopeや既存identityを上書きして自分の所有へ取り込みません
			if( activeRequiredChild_) {
				error = nativeErrorFromWin32( ERROR_BUSY) ;
			} else {
				childInserted = deviceInstances_.emplace( childIdentity, childInstance).second ;
				// 同名entryは別所有として保持し、子権限を発行しません
				if( !childInserted) {
					error = E_INVALIDARG ;
				} else {
					activeRequiredChild_ = &proof ;
					error				 = createOfficialInfInstallBindingImpl(
						   session, childIdentity, *inspection.workspace, package,
						   child.currentDriver.provider, child.currentDriver.version,
						   child.currentDriver.date, audit, childBinding) ;
				}
			}

			// 完全に固定した元親を子tokenの私有作用範囲へ結合します
			if( error == 0U) {
				officialInfInstallBindings_.at( childBinding.token).requiredParentInstance =
					parentInstance ;
			}
		}

		DeviceRankSnapshot beforeChild ;	// 指定子の直前に親の完全状態を再確認します
		// 別親/started変化では子を導入しません
		if( error == 0U) {
			error = readDeviceRankSnapshot( parentInstance, beforeChild) ;
			// 子binding作成中の親変化を拒否します
			if( error == 0U && !deviceRankSnapshotsEqual( parent, beforeChild)) {
				error = nativeErrorFromWin32( ERROR_RETRY) ;
			}
		}

		bool childReboot{} ;	// 子APIの実再起動値です
		// flags0の非null一意nodeだけを一present子へ導入します
		if( error == 0U) {
			error = installBoundOfficialInfImpl( session, childIdentity, *inspection.workspace,
												package, childBinding, parentWindowNative,
												childReboot, &role.installDiagnosticMissing,
												nullptr, nullptr, hardwareBoundary) ;
		}

		rebootRequired		= rebootRequired || childReboot ;
		role.installError	= error ;
		role.installOutcome = error ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		role.reflection		= error ? DriverPlanReflectionState::FAILED
									: DriverPlanReflectionState::INSTALL_API_COMPLETED ;
		// 変更済みbaseと未実行残memberを保持して部分失敗を返します
		if( error != 0U) {
			return error ;
		}

		const auto *selected = display ? &plan->selectedPackages_.at( member.packageOrdinal + 1U)
									   : nullptr ;	// 同じ親の実選択節を保持した審査済み必要子に限る
		// 子の指定APIが成功した後は、登録処理の実行と反映を同じ前後の観測で判定する
		if( selected && reviewedDisplayType1Registration( *plan->displayOwnership_, *selected)) {
			DisplayType1InstallResult observed{
				DisplayType1InstallState::UNCONFIRMED,
				displayEventError} ;	// 元境界の取得エラーは実APIの失敗へ変えない
			// 元の導入操作が維持される場合だけ同じ子の実行記録と反映内容を読む
			if( displayEventError == 0U && activeInstallOperation_ == displayOperation) {
				observed = observeAppliedDisplayType1(
					displayEventBoundary, *plan->displayOwnership_->type1, *selected,
					inspection.closure.entries, type1RegisteredInf, parentInstance, beforeChild,
					childInstance, member.componentHardwareIds) ;
			}

			role.installError = observed.error ;
			// 同じ実行と結合したWindowsの失敗だけを原HRESULT付きの部分失敗にする
			if( observed.state == DisplayType1InstallState::FAILED) {
				return observed.error != 0U ? observed.error : static_cast<NativeError>( E_FAIL) ;
			}

			pending = pending || observed.state != DisplayType1InstallState::REFLECTED ;
		}
	}

	return pending ? static_cast<NativeError>( S_FALSE) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式INF導入bindingと現在のdeviceおよびWindows nodeを再照合する。公式INF導入bindingと現在状態を再照合する。発行時の現在INF、版、日付、PnP
 *        状態と候補section、版、日付、rankを再取得値へ比較する。OS状態は変更しない
 * @param[in] scanSessionId Bindingを発行した現在session ID。 Binding発行元のscan session ID
 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 Bindingに対応するopaque device ID
 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みcandidateの保護workspace
 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package
 * @param[in] binding Provider workerが保持した非機密binding。 Provider workerが保持する非機密binding
 * @return 全記録が一致する場合は0、失効、変更またはSetupAPI失敗時はHRESULT。 全記録一致時は0、失効、変更またはSetupAPI失敗時はHRESULT
 * @note 本関数はDriver Storeへのstage、driver選択、installを行わない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateOfficialInfInstallBinding(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const OfficialInfInstallBinding &binding) const
{
	const auto stored =	// Opaque tokenから秘密binding記録を得る検索結果
		officialInfInstallBindings_.find( binding.token) ;
	const auto instance =	// Opaque identityが現在scanに存在するかの検索結果
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	// token、session、所有thread、deviceの対応が保持記録と一致する場合だけ再検証する
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || binding.token == 0U || deviceIdentity.empty() ||
	   stored == officialInfInstallBindings_.end() || instance == deviceInstances_.end() ||
	   !ownsBindingDevice( deviceIdentity, workspace, package) ||
	   stored->second.scanSessionId != scanSessionId ||
	   stored->second.deviceIdentity != deviceIdentity ||
	   stored->second.device.deviceInstanceId != instance->second) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialInfInstallBindingRecord &record = stored->second ;		// 発行時の秘密記録
	const auto *declarative	 = record.declarativeQualification.get() ;		// 独自クラスの発行時の元選択
	const auto *scoped		 = record.scopedQualification.get() ;			// 公式範囲の発行時の元選択です
	const bool	storageModel = !record.candidate.modelsSection.empty() ;	// WiXで固定した元選択だけ
	// 公式範囲のトークンが現在も同じ所有者・scan・元INFを指すことを確認します
	if( scoped && (scoped->owner != this || scoped->session != scanSessionId ||
				  scoped->deviceIdentity != deviceIdentity || !ownsInstallDevice( deviceIdentity) ||
				  !scoped->ownsSource( workspace, package))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 非権限用途の書換えや他issuerの資格をこの元tokenへ転用しません
	if( package.requiredRegistryOnlyCompanion ||
	   (storageModel &&
		(!record.storageQualification || !record.storageQualification->singleBoot_ ||
		 record.candidate.modelIds.empty() ||
		 record.requiredHardwareId != record.candidate.modelIds.front())) ||
	   (!scoped &&
		(record.storageQualification
			 ? (package.inspectionPurpose !=
					OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ||
				record.storageQualification->session_ != scanSessionId ||
				record.storageQualification->deviceIdentity_ != deviceIdentity ||
				!record.storageQualification->inspection_ ||
				record.storageQualification->inspection_->workspace.get() != &workspace)
		 : declarative
			 ? (package.inspectionPurpose !=
					OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ||
				declarative->owner != this || declarative->session != scanSessionId ||
				declarative->deviceIdentity != deviceIdentity ||
				declarative->workspace != &workspace || declarative->package != &package)
			 : (package.inspectionPurpose != OfficialInfInspectionPurpose::STANDARD_DRIVER ||
				package.requiredNullCompanion ||
				normalizeIdentifier( package.className) == L"SCSIADAPTER" ||
				normalizeIdentifier( package.className) == L"MEDIUMCHANGER")))) {
		return E_ACCESSDENIED ;
	}

	// Callerが保持した非機密部分もtokenの記録と完全一致しなければ拒否する
	if( binding.currentProvider != record.device.currentProvider ||
	   binding.currentVersion != record.device.currentVersion ||
	   binding.currentDate != record.device.currentDate ||
	   binding.candidateProvider != record.candidate.provider ||
	   binding.candidateVersion != record.candidate.version ||
	   binding.candidateDate != record.candidate.date ||
	   !officialRankAuditsEqual( binding.rankAudit, record.rankAudit)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const bool registering =
		declarative && declarative->effects.registration ==
						   SetupClassRegistration::UNREGISTERED ;	// 同意が必要な初回登録
	const auto &summary = binding.setupClassRegistration ;			// 発行時の初回登録の表示値
	// 別の表示名や既登録状態へ同意を使い回しません
	if( summary.has_value() != registering ||
	   (summary && (!declarative || summary->className != package.className ||
					summary->classGuid != declarative->registration.classGuid ||
					summary->displayName != declarative->registration.displayName ||
					summary->builtInIcon != declarative->registration.builtInIcon))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 公式範囲の選択は通常のパッケージ比較に加えて元Modelsへ再照合します
	if( scoped) {
		// 元トークンと比較する現在の署名付き選択観測
		ScopedInfObservation current ;
		return reobserveScopedInfInstallQualification( *scoped, current) ;
	}

	const std::optional<std::uint64_t> candidateVersion =
		// 再検証INFのpacked version
		parseDriverVersion( package.driverVersion) ;
	const std::optional<std::wstring> candidateDate =
		// 再検証INFの正規化日付
		normalizeInfDriverDate( package.driverDate) ;
	// 再検証に必要なINF metadata、候補版、日付が欠けた要求を拒否する
	if( package.infRelativePath.empty() || package.className.empty() ||
	   package.providerName.empty() || package.hardwareIds.empty() ||
	   !candidateVersion.has_value() || candidateVersion.value() == 0U ||
	   !candidateDate.has_value()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring candidateInfPath =	// 再検証済みworkspace内INF絶対path
		workspace.path( package.infRelativePath) ;
	// 再検証するINF pathが空または埋込NUL付きなら拒否する
	if( candidateInfPath.empty() || candidateInfPath.find( L'\0') != std::wstring::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 候補path、provider、版、日付がbinding作成時から変わった場合は再確認を要求する
	if( candidateInfPath != record.candidate.infPath ||
	   normalizeIdentifier( package.providerName) !=
		   normalizeIdentifier( record.candidate.provider) ||
	   candidateVersion.value() != record.candidate.packedVersion ||
	   candidateDate.value() != record.candidate.date) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const DWORD attributes = GetFileAttributesW( candidateInfPath.c_str()) ;	// INFのfile属性
	// 再検証時にINF属性を取得できなければ導入へ進めない
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// binding作成後に通常file以外へ変わったINFを拒否する
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceRankSnapshot			deviceSnapshot ;	// 導入前に再取得する現在device状態
	CandidateDriverNodeSnapshot candidateSnapshot ;	// 導入前のcandidate Windows node
	OfficialDriverRankAudit		currentRankAudit ;	// 導入前に再生成するrank監査結果
	const NativeError			collectError = collectOfficialInfBindingState(
		  instance->second, candidateInfPath, package, candidateVersion.value(),
		  candidateDate.value(), deviceSnapshot, candidateSnapshot, currentRankAudit, nullptr,
		  declarative ? &declarative->selected : nullptr,
		  storageModel) ;	// 全状態のread-only再検証結果
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( collectError != 0) {
		return collectError ;
	}

	const bool deviceMatches =	// 同じ端末、現在構成、Windowsの適合性を比較した結果です
		deviceSnapshot.deviceClass == record.device.deviceClass &&
		deviceSnapshot.classState == record.device.classState &&
		deviceSnapshot.classRead.state == record.device.classRead.state &&
		deviceSnapshot.classGuidRead.state == record.device.classGuidRead.state &&
		deviceSnapshot.observedClassGuid == record.device.observedClassGuid &&
		deviceSnapshot.nativeClassGuid == record.device.nativeClassGuid &&
		deviceSnapshot.node.read.state == record.device.node.read.state &&
		deviceSnapshot.node.statusFlags == record.device.node.statusFlags &&
		deviceSnapshot.node.problemCode == record.device.node.problemCode &&
		deviceSnapshot.driverKeyRead.state == record.device.driverKeyRead.state &&
		deviceSnapshot.matchingRead.state == record.device.matchingRead.state &&
		deviceSnapshot.driverKey == record.device.driverKey &&
		(record.requiresFirmwareAuthorization ||
		 deviceSnapshot.hardwareIds == record.device.hardwareIds) &&
		deviceSnapshot.compatibleIds == record.device.compatibleIds &&
		deviceSnapshot.matchingDeviceId == record.device.matchingDeviceId &&
		deviceSnapshot.currentDriver.infFileName == record.device.currentInfFileName &&
		deviceSnapshot.currentDriver.provider == record.device.currentProvider &&
		deviceSnapshot.currentDriver.version == record.device.currentVersion &&
		deviceSnapshot.currentDriver.date == record.device.currentDate &&
		deviceSnapshot.noDriver == record.device.noDriver &&
		(record.device.noDriver ? !deviceSnapshot.currentDriver.packedVersion
								: deviceSnapshot.currentDriver.packedVersion &&
									  *deviceSnapshot.currentDriver.packedVersion ==
										  record.device.currentPackedVersion) ;
	CandidateDriverNodeSnapshot expectedCandidate ;	// 発行時nodeの比較用snapshot
	expectedCandidate.infClassGuid	= record.candidate.infClassGuid ;
	expectedCandidate.classGuid		= record.candidate.classGuid ;
	expectedCandidate.sectionName	= record.candidate.sectionName ;
	expectedCandidate.modelIds		= record.candidate.modelIds ;
	expectedCandidate.provider		= record.candidate.provider ;
	expectedCandidate.version		= record.candidate.version ;
	expectedCandidate.date			= record.candidate.date ;
	expectedCandidate.packedVersion = record.candidate.packedVersion ;
	expectedCandidate.dateTicks		= record.candidate.dateTicks ;
	expectedCandidate.rank			= record.candidate.rank ;
	// device、候補node、rankの再照合結果が保持証拠と異なる場合は導入を拒否する
	if( !deviceMatches ||
	   !candidateNodeSnapshotsEqual( declarative ? declarative->selected : expectedCandidate,
									candidateSnapshot) ||
	   currentRankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
	   !officialRankAuditsEqual( record.rankAudit, currentRankAudit)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// WiXの主IDを同じpresent端末の完全HardwareIdsと元署名付きINFに再照合する
	if( storageModel) {
		std::vector<std::wstring> hardwareIds ;										// 同端末の型と終端を検証した全HardwareIds
		auto error = readScopedHardwareIds( instance->second, hardwareIds, true) ;	// 最初の元診断
		// 再観測で主Hardware IDが消えた場合にCompatible IDから補わない
		if( error != 0U || !containsScopedHardwareId( hardwareIds, record.requiredHardwareId)) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		error = verifyOfficialStorageInfModelSelection(
			workspace, record.storageQualification->inspection_->closure.entries, package,
			record.candidate.modelsSection, candidateSnapshot.sectionName,
			candidateSnapshot.modelIds) ;
		// 同じ現在OSの一意な元行が証明できるまで変更前確認を確定しない
		if( error != 0U) {
			return error ;
		}
	}

	// 同じ自己媒体Portsの選択と元証拠を登録前と適用直前に確認する
	if( record.serialPropertyPage.has_value() != package.nativePortsPage.has_value()) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 元DLLを再照合し、署名・位置・バイト・権限の差があれば適用しない
	if( record.serialPropertyPage) {
		// 元の実nodeと同じ未修飾選択が生きていることを確認する
		if( normalizeIdentifier( candidateSnapshot.sectionName) !=
		   normalizeIdentifier( package.nativePortsPage->basicSection)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		WindowsSystemFileTrust current ;	// Windowsの正規DLLについて独立に取り直した証拠
		const auto			   error =
			// 元署名とexportの再照合
			inspectWindowsSerialPropertyPage( workspace, current) ;
		// 検査の失敗や発行時の証拠との差から同じ作用を推定しない
		if( error != 0U || current != *record.serialPropertyPage) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 独自クラスは元INF、実選択行、登録状態と既存作用も導入のたびに読み直します
	if( declarative) {
		OfficialInfSelectedModelRole						   role{} ;			// 検査済み元Models一行の作用
		std::optional<OfficialInfDeclarativeClassRegistration> registration ;	// 元クラス節の再読取り
		auto error = inspectOfficialInfSelectedModelRole(
			workspace, package, declarative->registration.infSha256, declarative->modelsSection,
			candidateSnapshot.sectionName, candidateSnapshot.modelIds, role,
			&registration) ;	// 同一元行の再照合
		// 同じ実行行と表示情報がそろった場合だけ登録状態の照会へ進みます
		if( error != 0U || role != OfficialInfSelectedModelRole::KERNEL_DRIVER || !registration ||
		   *registration != declarative->registration) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		DeclarativeClassEffects effects ;	// 導入直前の元端末と対象クラスの登録
		error = readDeclarativeClassObservation( instance->second, package, effects) ;
		// 既存作用やクラスの登録が変わった場合は元の同意を無効にします
		if( error != 0U || effects != declarative->effects) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定scanに属する一つの公式INF導入bindingを明示的に破棄する。現在sessionと所有workerを照合し、他候補のbindingを維持したまま未発行候補の秘密記録だけ
 *        を破棄する
 * @param[in] scanSessionId Bindingを発行したscan session ID
 * @param[in] token Driver Storeが発行した0ではないopaque token。 Driver Storeが発行したopaque token
 * @return 一件を破棄した場合true。別session、別workerまたは未登録ならfalse。 一件を破棄した場合true。不一致または未登録ならfalse
 * @note 他Providerが同じscanで保持するbindingは変更しない
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::discardOfficialInfInstallBinding( const ScanSessionId scanSessionId,
														   const std::uint64_t token) noexcept
{
	// 旧sessionまたは別workerから現在tokenを破棄させない
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ || token == 0U ||
	   GetCurrentThreadId() != ownerThreadId_) {
		return false ;
	}

	return officialInfInstallBindings_.erase( token) == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定scanに属する全公式INF導入bindingを明示的に失効させる。指定scanの公式INF導入bindingを明示的に失効させる。現在sessionと所有workerが一致す
 *        る場合だけ全tokenを破棄する。旧sessionから現在bindingを失効させない
 * @param[in] scanSessionId Bindingを発行したscan session ID
 * @note 旧sessionまたは所有worker以外からの要求では現在bindingを変更しない
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::invalidateOfficialInfInstallBindings(
	const ScanSessionId scanSessionId) noexcept
{
	// 別sessionまたは所有thread外の要求では現在のbindingを失効させない
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_) {
		return ;
	}

	officialInfInstallBindings_.clear() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同保護INFのbyteを再確認して一度だけstoreへimportします
 * @param[in] workspace 元保護領域です
 * @param[in] package 同byte検証済みINFです
 * @param[out] stagedInfPath 検証済み登録root直下の秘密pathです
 * @param[in] storageQualification 同原workspace/全作用に結ぶ私有資格です。nullは既通常policyだけです
 * @param[in] declarativeQualification 独自クラスの検査済み元選択
 * @param[in] authorizationCheck 登録前に実UTCと元選択を再検証する任意の同期処理
 * @param[in] scopedQualification 公式範囲で同じ端末、元INF、作用に結ぶ計画です
 * @return stageと元/登録byte一致0、それ以外はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::stageOfficialInfPackage(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::wstring &stagedInfPath, const StorageInfQualification *storageQualification,
	const DeclarativeInfInstallQualification *declarativeQualification,
	const std::function<NativeError()>		 *authorizationCheck,
	const ScopedInfInstallQualification		 *scopedQualification) const
{
	stagedInfPath.clear() ;
	// 非実行内容と未資格storageは既存tokenやstage cacheでもOS登録へ昇格しません
	const bool storage =
		storageQualification && storageQualification->session_ == scanSessionId_ &&
		storageQualification->inspection_ &&
		storageQualification->inspection_->workspace.get() == &workspace &&
		(package.inspectionPurpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ||
		 package.inspectionPurpose == OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT) ;
	const bool singleBootStorage =
		storage && storageQualification->singleBoot_.has_value() ;	// 通常署名索引の単一起動だけ
	const auto bootOperation =
		singleBootStorage ? activeInstallOperation_ : 0U ;	// 同じ選択が属する元操作
	// 単一起動は元索引の実行中の元操作と同じ機器だけを登録する
	if( singleBootStorage &&
	   (!installProofInventory_ || bootOperation == 0U ||
		std::ranges::find( activeIndexDevices_, storageQualification->deviceIdentity_) ==
			activeIndexDevices_.end())) {
		return E_ACCESSDENIED ;
	}

	const bool declarative =
		declarativeQualification &&
		package.inspectionPurpose == OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT &&
		declarativeQualification->owner == this &&
		declarativeQualification->session == scanSessionId_ &&
		declarativeQualification->package == &package &&
		declarativeQualification->workspace ==
			&workspace ;	// 同scanで検証した元INFの配置だけを許可する
	// 現在の導入操作で元INFの公式資格を使えるかを示します
	const bool scoped = scopedQualification && ownsActiveScopedInfInstall( *scopedQualification) &&
						scopedQualification->ownsSource( workspace, package) ;
	// 公式資格を検査した時点での導入操作ID。通常経路では0
	const auto scopedOperation = scoped ? activeInstallOperation_ : 0U ;
	// registry-onlyと資格を持たないstorage/nullを通常stage経路へ通しません
	if( package.requiredRegistryOnlyCompanion || (declarativeQualification && !declarative) ||
	   (scopedQualification && !scoped) ||
	   (!storage && !declarative && !scoped &&
		(package.inspectionPurpose != OfficialInfInspectionPurpose::STANDARD_DRIVER ||
		 package.requiredNullCompanion ||
		 CompareStringOrdinal( package.className.c_str(), -1, L"SCSIAdapter", -1, TRUE) ==
			 CSTR_EQUAL ||
		 CompareStringOrdinal( package.className.c_str(), -1, L"MTD", -1, TRUE) == CSTR_EQUAL ||
		 CompareStringOrdinal( package.className.c_str(), -1, L"MediumChanger", -1, TRUE) ==
			 CSTR_EQUAL))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 対象のストレージ作用は登録キャッシュにも元署名レコードを要求する
	if( (scoped ||
		(storage && requiresSignedStorageAuthorization( storageQualification->effects_))) &&
	   (!authorizationCheck || !*authorizationCheck)) {
		return E_ACCESSDENIED ;
	}

	// private資格の原全閉包に属する同metadataだけを登録します
	if( storage) {
		// 全成功まで外へ発行しない原内容検査の所有結果です
		const auto &inspected = *storageQualification->inspection_ ;
		// 同原rootの内容と全metadataです
		const auto &base = inspected.closure.packages.front() ;
		// 当該ordinalに対応する元required importです
		const auto	imported =
			std::ranges::find( inspected.requiredInfPackages, package.infRelativePath,
							  &OfficialInfPackage::infRelativePath) ;
		// 元資格又は元原文から保持した比較値です
		const auto original =
			package.infRelativePath == base.infRelativePath
				? &base
				: (imported == inspected.requiredInfPackages.end() ? nullptr : &*imported) ;
		// private資格内の同原import又はrootだけを登録対象にします
		if( !original || original->inspectionPurpose != package.inspectionPurpose ||
		   original->requiredNullCompanion != package.requiredNullCompanion ||
		   original->requiredRegistryOnlyCompanion != package.requiredRegistryOnlyCompanion ||
		   original->catalogRelativePath != package.catalogRelativePath ||
		   original->classGuid != package.classGuid || original->className != package.className ||
		   original->sourceFiles != package.sourceFiles) {
			return E_ACCESSDENIED ;
		}

		// 下位検査の最初の診断を後続へ返す一時値です
		const auto error = reverifyCommonDriverInf( inspected) ;
		// 全原byte/CATの再検査失敗を旧資格で補完しません
		if( error != 0U) {
			return error ;
		}
	}

	// 本人検査modeはOS登録やnative作用の前に拒否します
	if( workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR) {
		return E_ACCESSDENIED ;
	}

	const auto sourceInfPath = workspace.path( package.infRelativePath) ;	// 元秘密pathです
	// 登録APIのpath上限と完全な終端を確保します
	if( sourceInfPath.empty() || sourceInfPath.find( L'\0') != std::wstring::npos ||
	   sourceInfPath.size() >= MAX_PATH) {
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	RegisteredInfGuard registration ;										// 同root/元byte/登録byteを保持します
	auto			   error = registration.initialize( sourceInfPath) ;	// 登録前確認です
	// 保護root/元byte未確認ではstageしません
	if( error != 0U) {
		return error ;
	}

	// 元ファイルの保持を確認した後、登録や既登録の再使用を確定する直前に元権限を検査します
	if( scoped) {
		// 実際に登録する元INFのハッシュが検査した導入作用に一致することを確認します
		if( registration.sourceSha256() != scopedQualification->effects.infSha256) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		// Driver Storeへの登録直前に公式選択を再観測する格納先
		ScopedInfObservation current ;
		error = reobserveScopedInfInstallQualification( *scopedQualification, current) ;
		// 公式資格と現在の選択の再照合が失敗した場合は登録を行いません
		if( error != 0U) {
			return error ;
		}
	}

	// 特別な認可を要求する経路では作用直前に同じ承認が有効かを確認します
	if( authorizationCheck) {
		error = (*authorizationCheck)() ;
		// 元権限の拒否を作業済み登録へ補いません
		if( error != 0U) {
			return error ;
		}
	}

	// 再確認中に導入操作が差し替わった場合は公式資格を消費しません
	if( scoped && (scopedOperation != activeInstallOperation_ ||
				  !ownsActiveScopedInfInstall( *scopedQualification))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 登録を伴う同期再確認中も、同じ実行操作と選択が有効であることを要求する
	if( singleBootStorage &&
	   (bootOperation != activeInstallOperation_ || !installProofInventory_ ||
		std::ranges::find( activeIndexDevices_, storageQualification->deviceIdentity_) ==
			activeIndexDevices_.end())) {
		return E_ACCESSDENIED ;
	}

	const auto cached =
		declarative || scoped
			? stagedOfficialInfs_.end()
			: stagedOfficialInfs_.find( sourceInfPath) ;	// 独自クラスではINF単独で配置を再利用しない
	// 同byte登録先だけを再利用します
	if( cached != stagedOfficialInfs_.end()) {
		// 変化した元byteへ旧登録先を流用しません
		if( cached->second.sourceSha256 != registration.sourceSha256()) {
			return nativeErrorFromWin32( ERROR_CRC) ;
		}

		stagedInfPath = cached->second.path ;
	} else {
		std::array<wchar_t, MAX_PATH> destination{} ;	// Windows返却の完全登録先です
		DWORD						  required{} ;		// NUL込み要素数です
		SetLastError( ERROR_SUCCESS) ;
		const auto copied = driver_store_inf_detail::transport().stage(
			sourceInfPath.c_str(), nullptr, SPOST_PATH, SP_COPY_NOOVERWRITE, destination.data(),
			// importのみです
			static_cast<DWORD>( destination.size()), &required, nullptr) ;
		const auto copyError = copied ? ERROR_SUCCESS : GetLastError() ;	// 元診断です
		// 既存登録以外のstage失敗を保持します
		if( !copied && copyError != ERROR_FILE_EXISTS) {
			return nativeErrorFromWin32( copyError ? copyError : ERROR_INVALID_DATA) ;
		}

		// 切詰め、未終端、埋込NULのpathを許可しません
		if( required <= 1U || required > destination.size() || destination.front() == L'\0' ||
		   destination[required - 1U] != L'\0') {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		stagedInfPath.assign( destination.data(), required - 1U) ;
		// 初期bufferの余りをpathへ含めません
		if( stagedInfPath.find( L'\0') != std::wstring::npos) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	error = registration.verify( stagedInfPath) ;
	// 登録root直下と全元byte一致を確認します
	if( error != 0U) {
		return error ;
	}

	// 初回確認済み登録だけをcacheします
	if( !declarative && !scoped && cached == stagedOfficialInfs_.end()) {
		stagedOfficialInfs_.emplace( sourceInfPath,
									StagedOfficialInf{registration.sourceSha256(), stagedInfPath}) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Bindingで固定した監査済み公式INFをstagingして指定deviceへ導入する。Bindingを再検証後、SetupCopyOEMInfWが返した登録先INFから一意な
 *        nodeを再構築する。導入直前にも現在状態を確認し、DiInstallDeviceへ非nullのDriverInfoDataとFlags 0を渡す
 * @param[in] scanSessionId Bindingを発行した現在scan session ID。 Bindingを発行した現在session
 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 対象のopaque device identity
 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みINF閉包の保護workspace
 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package
 * @param[in] binding Provider workerが保持する一scan限定binding。 Providerが保持する一scan限定binding
 * @param[in] parentWindowNative Windows導入dialogの親Window値。 Installer親HWNDの整数表現
 * @param[out] rebootRequired 導入完了に再起動が必要な場合はtrue
 * @return Stagingと指定device導入の成功時は0、それ以外はHRESULT
 * @note Windowsが返した登録先INFだけを再照合し、登録済みpackageを自動削除しない
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installBoundOfficialInf( const ScanSessionId	 scanSessionId,
														 const std::wstring_view deviceIdentity,
														 const OfficialDownloadWorkspace &workspace,
														 const OfficialInfPackage		 &package,
														 const OfficialInfInstallBinding &binding,
														 const std::uintptr_t parentWindowNative,
														 bool				 &rebootRequired) const
{
	const auto stored = officialInfInstallBindings_.find( binding.token) ;	// 私有権限の境界です
	// 公開single-INF入口から必要役割計画のtokenを部分導入しません
	if( package.hasExternalDependencies || !package.unresolvedCopyInfPaths.empty() ||
	   (stored != officialInfInstallBindings_.end() &&
		(stored->second.requiredPlan || stored->second.scopedQualification))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	return installBoundOfficialInfImpl( scanSessionId, deviceIdentity, workspace, package, binding,
									   parentWindowNative, rebootRequired) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有前提を満たした指定一deviceの元実装を実行します
 * @param[in] scanSessionId 元scanです
 * @param[in] deviceIdentity 元opaqueです
 * @param[in] workspace 元保護閉包です
 * @param[in] package 元検証済みINFです
 * @param[in] binding 元一意nodeです
 * @param[in] parentWindowNative 明示操作の親windowです
 * @param[out] rebootRequired 実APIの再起動値です
 * @param[out] diagnosticMissing 非nullは同期中だけ借用する出力です。FALSE/LastError0の観測だけtrueです
 * @param[in,out] mtdFiles 同意/復旧後かつstage前に準備したMTD共有先です。旧経路はnullです
 * @param[out] mtdResult MTDのcopy部分作用です。旧経路はnullです
 * @param[in] authorizationCheck 同原署名recordと実UTCの同期再検証です。対象限定、対応storageと独自クラスで必須です
 * @param[in] declarativeSource 独自クラスの署名確認済み元閉包です。従来経路はnullです
 * @param[in] wifiSource この端末のフィルターを置換する元内容の同期中の借用です。それ以外はnullです
 * @param[out] storageReflection 自動起動補助または単一起動の事後観測。指定適用成功時に記録し、他の経路はnull
 * @param[in] copyInfSource 付随INFの不在を確認した基本INFと元CAT・必須ファイル。他の経路はnull
 * @param[in] displaySource 現用所有を照合する同じDisplay基本INFの元閉包。他の経路ではnull
 * @return stage/指定API完了0、それ以外はHRESULTです
 * @note FALSE/LastError0では内部ERROR_INVALID_DATAを返し、実Windowsの同error観測と区別します
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installBoundOfficialInfImpl(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const OfficialInfInstallBinding &binding, const std::uintptr_t parentWindowNative,
	bool &rebootRequired, bool *diagnosticMissing, MtdSharedFileOperation *mtdFiles,
	MtdQueueResult *mtdResult, const std::function<NativeError()> *authorizationCheck,
	const CommonInfInspection *declarativeSource, const CommonInfInspection *wifiSource,
	DriverStorageReflectionResult *storageReflection, const CommonInfInspection *copyInfSource,
	const CommonInfInspection *displaySource) const
{
	// 未到達・他の拒否を指定APIの診断欠落へ読み替えません
	if( diagnosticMissing) {
		*diagnosticMissing = false ;
	}

	rebootRequired = false ;
	const bool declarative =
		package.inspectionPurpose ==
		OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;		// 閉包の配置先照合が必須の用途
	const auto &driverStore = driver_store_inf_detail::transport() ;	// 元クラスと配置先の照会表
	// 元閉包を持たない独自クラスや、同じ元INFの別配置を指定した入力を拒否する
	if( declarative != (declarativeSource != nullptr) ||
	   (authorizationCheck && !*authorizationCheck) ||
	   (declarative && (!authorizationCheck || !driverStore.declarativeClass)) ||
	   (declarativeSource &&
		(declarativeSource->scanSessionId != scanSessionId ||
		 declarativeSource->state != CommonInfInspectionState::VERIFIED ||
		 declarativeSource->error != 0U || declarativeSource->workspace.get() != &workspace ||
		 declarativeSource->closure.packages.size() != 1U ||
		 &declarativeSource->closure.packages.front() != &package))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	NativeError nativeError = revalidateOfficialInfInstallBinding(
		scanSessionId, deviceIdentity, workspace, package, binding) ;	// Staging前の固定状態確認
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return nativeError ;
	}

	const auto stored =	// 再検証済みtokenから秘密node記録を得る検索結果
		officialInfInstallBindings_.find( binding.token) ;
	const auto instance =	// Opaque identityからnative device IDを得る検索結果
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	// bindingと現在deviceの対応を失った場合はINF登録を開始しない
	if( stored == officialInfInstallBindings_.end() || instance == deviceInstances_.end() ||
	   stored->second.device.deviceInstanceId != instance->second) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialInfInstallBindingRecord &record = stored->second ;	// 固定済み秘密binding記録
	const bool							   display =
		record.requiredPlan &&
		record.requiredPlan->displayOwnership_ ;	// 同じDisplayの現用所有を要求する計画
	const auto displayOperation =
		display ? activeInstallOperation_ : 0U ;	// 下位境界を通る同じ実操作
	// 別元閉包、別方式または元承認のない入力へDisplayの変更効果を渡さない
	if( display != (displaySource != nullptr) ||
	   (displaySource &&
		(!authorizationCheck || !driverStore.storageStoreLocation || displayOperation == 0U ||
		 displaySource->scanSessionId != scanSessionId ||
		 displaySource->workspace.get() != &workspace ||
		 displaySource->closure.packages.size() != 1U ||
		 &displaySource->closure.packages.front() != &package ||
		 (copyInfSource && copyInfSource != displaySource) || wifiSource || declarativeSource ||
		 record.storageQualification || record.scopedQualification))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 未解決参照を扱う場合は、実行中の署名索引操作・計画・同じ基本閉包を照合する
	if( (record.requiredPlan && record.requiredPlan->defersRootCopyInf_) !=
		   (copyInfSource != nullptr) ||
	   (copyInfSource &&
		(!authorizationCheck || !driverStore.storageStoreLocation || !installProofInventory_ ||
		 activeInstallOperation_ == 0U ||
		 std::ranges::find( activeIndexDevices_, deviceIdentity) == activeIndexDevices_.end() ||
		 copyInfSource->scanSessionId != scanSessionId ||
		 copyInfSource->workspace.get() != &workspace ||
		 copyInfSource->closure.packages.size() != 1U ||
		 &copyInfSource->closure.packages.front() != &package ||
		 package.unresolvedCopyInfPaths.empty() ||
		 !canDeferMissingRootCopyInf( *copyInfSource, 0U,
									 package.unresolvedCopyInfPaths.front())))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元選択と同じ仮想Wi-Fiバスの元内容でだけ専用の再照合を行います
	if( record.wifiBusUpperFilters.has_value() != (wifiSource != nullptr) ||
	   (wifiSource &&
		(!authorizationCheck || !record.requiredPlan || wifiSource->workspace.get() != &workspace ||
		 wifiSource->closure.packages.empty() ||
		 &wifiSource->closure.packages.front() != &package))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto scoped		   = record.scopedQualification ;				// 同じ元閉包を実行終端まで保持します
	const auto scopedOperation = scoped ? activeInstallOperation_ : 0U ;	// 公式対象の元操作です
	// 公式対象の資格を別操作の登録へ再利用しません
	if( scoped && (!ownsActiveScopedInfInstall( *scoped) || !authorizationCheck ||
				  !driverStore.declarativeClass || !driverStore.declarativeClass->storeLocation)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const bool singleHardwareId = !record.requiredHardwareId.empty() ;	// 従来の単一IDの条件です
	const bool hardwareScoped =
		singleHardwareId || record.requiresFirmwareAuthorization ;	// 元署名の公式対象を持つ記録です
	// 最終適用でも元署名レコードの再確認を要するストレージ資格
	const bool signedStorage =
		record.storageQualification &&
		requiresSignedStorageAuthorization( record.storageQualification->effects_) ;
	// 同じ元ストレージ資格に補助サービスの作用が含まれるかを保持します
	const bool auxiliaryStorage =
		record.storageQualification && record.storageQualification->effects_.service.auxiliary ;
	// Driver Storeから直接補助を実行する選択では登録先の閉包を確認する
	const bool automaticStorage = record.storageQualification &&
								  record.storageQualification->effects_.automaticHost.has_value() ;
	const bool singleBootStorage = record.storageQualification &&
								   // 関連起動サービスだけを持つ元選択
								   record.storageQualification->singleBoot_.has_value() ;
	const bool verifyStorageClosure =
		automaticStorage || singleBootStorage ;	// 同じ登録の全ファイルと反映が必要な方式
	const auto bootOperation =
		singleBootStorage ? activeInstallOperation_ : 0U ;	// 単一起動の指定適用を許可する元操作
	// 起動作用を対応する事後観測のない入口へ通さない
	if( verifyStorageClosure != (storageReflection != nullptr)) {
		return E_ACCESSDENIED ;
	}

	// 単一起動の指定適用は同じ計画を持つ索引の実行中操作からだけ行う
	if( singleBootStorage &&
	   (!record.requiredPlan || !installProofInventory_ || bootOperation == 0U ||
		std::ranges::find( activeIndexDevices_, deviceIdentity) == activeIndexDevices_.end())) {
		return E_ACCESSDENIED ;
	}

	// 対象限定または元署名が必要な資格では適用時も再確認を必須とする
	if( (hardwareScoped || signedStorage) && (!authorizationCheck || !*authorizationCheck)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 起動作用がある場合は登録先の正規Store対応を照会できるときだけ進む
	if( verifyStorageClosure && !driverStore.storageStoreLocation) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const std::function<NativeError()> hardwareAuthorization = [&]() {
		return authorizeScopedHardwareDevice( record.device.deviceInstanceId,
											 record.requiredHardwareId, *authorizationCheck) ;
	} ; // 実際の登録と適用の直前に現在のHardwareIdsも照合します
	const auto *baseAuthorization =
		singleHardwareId && !scoped
			? &hardwareAuthorization
			: authorizationCheck ;	// ファームウェア群は元承認に結ぶ同期検査で判定します
	const std::function<NativeError()> wifiAuthorization = [&]() {
		const auto authorized = (*baseAuthorization)() ;	// 現在も有効な元署名と端末条件です
		return authorized != 0U
				   ? authorized
				   : revalidateRequiredInfInstallBinding( scanSessionId, deviceIdentity, *wifiSource,
														 record.requiredPlan, binding) ;
	} ; // 元署名と内容のほか、同じサービスと端末の原値を再検査します
	const bool nativeSourceCopyInf =
		copyInfSource &&
		copyInfSource->closure.unresolvedRootCopyInfAbsence ==
			OfficialRootCopyInfAbsence::NATIVE_SOURCE ;	// 保護された登録元の不在を再確認する方式
	const std::function<NativeError()> copyInfAuthorization = [&]() {
		const auto authorized = (*baseAuthorization)() ;	// 同じ元レコードの現時刻と承認を確認
		return authorized != 0U ? authorized : verifyPreparedNativeCopyInfAbsence( *copyInfSource) ;
	} ; // 元保護領域と元選択を同期呼出し中だけ借用する
	const std::function<NativeError()> storageAuthorization = [&]() {
		const auto &qualification = *record.storageQualification ;	// 同一issuerの元資格
		// 元選択を同じ端末の最新観測に照合した診断
		const auto	fresh = revalidateRequiredInfInstallBinding( scanSessionId, deviceIdentity,
																*qualification.inspection_,
																record.requiredPlan, binding) ;
		return fresh != 0U ? fresh : (*baseAuthorization)() ;
	} ; // 現在の共有所有と端末を読み直した後で元署名・期限を確認する
	// DisplayではCopyINFの不在も含めて現用所有を読み直し、元承認を最後に確かめる
	const std::function<NativeError()> displayAuthorization = [&] {
		return authorizeDisplayInfMutation( scanSessionId, deviceIdentity, *displaySource,
										   record.requiredPlan, binding, displayOperation,
										   *baseAuthorization) ;
	} ;
	const auto *boundaryAuthorization =
		display									  ? &displayAuthorization
		: (auxiliaryStorage || singleBootStorage) ? &storageAuthorization
		: wifiSource							  ? &wifiAuthorization
		: nativeSourceCopyInf					  ? &copyInfAuthorization
							  : baseAuthorization ;	// 登録と適用が共有する同期検査です
	// 同recordがMTD指定経路を要求するかの判定です
	const bool mtd =
		record.storageQualification &&
		normalizeIdentifier( record.storageQualification->effects_.service.className) == L"MTD" ;
	// MTDだけ同operationでstage前から保持した共有先と完全表を要求します
	if( (mtd && (!mtdFiles || !mtdResult || !authorizationCheck ||
				!driver_store_inf_detail::mtdTransportReady())) ||
	   (!mtd && (mtdFiles || mtdResult))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 従来のMTDでは共有先を保持した状態で早期に元recordを確認します
	if( mtd && !hardwareScoped) {
		nativeError = (*authorizationCheck)() ;
		// 失効の元診断を保持してstageを止めます
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	// storageは全作用/現service/helper/原期限側の再検査をstage前にも必須にします
	if( record.storageQualification) {
		nativeError = revalidateRequiredInfInstallBinding( scanSessionId, deviceIdentity,
														  *record.storageQualification->inspection_,
														  record.requiredPlan, binding) ;
		// storage全作用の直前不一致ではbase登録を開始しません
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	const std::wstring sourceInfPath =	// SetupCopyOEMInfWへ渡すnull終端の監査済みINF path
		workspace.path( package.infRelativePath) ;
	// 空または埋込NUL付きのsource INF pathを登録APIへ渡さない
	if( sourceInfPath.empty() || sourceInfPath.find( L'\0') != std::wstring::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 登録APIへ渡すpathが対応長を超える場合は切り詰めず拒否する
	if( sourceInfPath.size() >= static_cast<std::size_t>( MAX_PATH)) {
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	RegisteredInfGuard registration ;	// Root/元INF/登録INFを指定導入の終端までpinします
	nativeError = registration.initialize( sourceInfPath) ;
	// 登録rootや元実byteを確認できなければstageを呼びません
	if( nativeError != 0U) {
		return nativeError ;
	}

	std::wstring stagedInfPath ;	// 共通stage境界が照合した登録先だけです
	// 従来の独自クラスでは登録用境界をもう一度開く前に元権限を確認します
	if( declarative && !hardwareScoped) {
		nativeError = (*authorizationCheck)() ;
		// 元権限が失効している場合は登録処理を開始しません
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	nativeError = stageOfficialInfPackage(
		workspace, package, stagedInfPath, record.storageQualification.get(),
		record.declarativeQualification.get(),
		(mtd || declarative) && !hardwareScoped ? nullptr : boundaryAuthorization, scoped.get()) ;
	// 共通境界の失敗を指定device導入へ進めません
	if( nativeError != 0U) {
		return nativeError ;
	}

	// 同じ導入操作と資格が現在も有効である場合だけ指定導入へ進みます
	if( scoped &&
	   (scopedOperation != activeInstallOperation_ || !ownsActiveScopedInfInstall( *scoped))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	nativeError = registration.verify( stagedInfPath) ;
	// 既知登録rootの直下と元INF全byteが一致する場合だけnode再構築へ進みます
	if( nativeError != 0U) {
		return nativeError ;
	}

	const auto *requiredBaseSource =
		displaySource ? displaySource : copyInfSource ;	// 同じ基本INFだけを保持する元閉包
	// 元閉包からファイルを使う導入方式の保持条件
	const bool verifyStorePackage =
		verifyStorageClosure || declarativeSource || scoped || requiredBaseSource ;
	RegisteredDriverStorePackage storePackage ;	// 配置された元閉包を実適用の完了まで保持する
	// 同じINFの別パッケージを元選択の実閉包へ結びません
	if( requiredBaseSource) {
		const DriverStorePackageLookup lookup{driverStore.windowsDirectory,
											  driverStore.storageStoreLocation} ;	// 正規の登録先照会
		nativeError = storePackage.pinFromClosure( stagedInfPath, package,
												  requiredBaseSource->closure.entries, lookup) ;
		// 登録だけの成功では同じ内容の指定適用へ進めない
		if( nativeError != 0U) {
			return nativeError ;
		}
	}
	// 既存の用途はそれぞれの元閉包を同じ登録へ結合する
	else if( verifyStorePackage) {
		// 同じ資格が保持する元閉包のファイル一覧
		const auto					  &entries = verifyStorageClosure
													 ? record.storageQualification->inspection_->closure.entries
												 : scoped ? scoped->content->infs.front().closure.entries
														  : declarativeSource->closure.entries ;
		// 導入方式ごとに使う既存の正規Store照会
		const DriverStorePackageLookup lookup{driverStore.windowsDirectory,
											  verifyStorageClosure
												  ? driverStore.storageStoreLocation
												  : driverStore.declarativeClass->storeLocation} ;
		nativeError = storePackage.pin( stagedInfPath, package, entries, lookup) ;
		// 元CATまたは元ファイルとの不一致を実適用へ持ち込みません
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	const DWORD stagedAttributes = GetFileAttributesW( stagedInfPath.c_str()) ;	// 登録先属性
	// 登録先INFの属性を取得できなければnodeの再構築へ進めない
	if( stagedAttributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 登録先がディレクトリまたは再解析点なら導入を拒否する
	if( (stagedAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceInfoSet devices(
		// 対象一件用set
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を取得できなければ登録済みnodeを検索しない
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// Bindingで固定したinstanceを再openしたdevice metadata
	device.cbSize = sizeof( device) ;
	// binding対象deviceを開けなければ別deviceへ代替せず中止する
	if( driver_store_inf_detail::transport().open( devices.get(), instance->second.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	GUID stagedClass{} ;	// 元byteと一致する登録INFの独立Class確認です
	nativeError = readCandidateInfClass( stagedInfPath, package.className, stagedClass) ;
	// 同じ実INFのClassが発行時と異なれば指定nodeへ進みません
	if( nativeError != 0U || formatClassGuid( stagedClass) != record.candidate.infClassGuid) {
		return nativeError != 0U ? nativeError : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 実デバイスの現在クラスが元選択と異なる場合は指定導入を中断します
	if( scoped && !IsEqualGUID( device.ClassGuid, stagedClass)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	nativeError = configureSingleInfDriverSearch( devices.get(), device, stagedInfPath) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return nativeError ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// Staged INF compatible listのRAII guard
	// Windowsの互換driver list構築に失敗した場合は独自候補を作らない
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	SP_DRVINFO_DATA_W selectedDriver{} ;	// 元完全tuple内で唯一最小rankのstaged node
	// 一覧構築の返却Classも元INFと発行時候補の両GUIDに結合します
	if( !IsEqualGUID( device.ClassGuid, stagedClass) ||
	   formatClassGuid( device.ClassGuid) != record.candidate.classGuid) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	bool found{} ;					// 元完全tuple内の最小rank候補を保持した場合はtrue
	bool bestRankTied{} ;			// 現在の最小full rankに複数nodeがある場合はtrue
	bool selectedMatchesBinding{} ;	// 最小nodeの節、原日時ticksとrankも元bindingに一致する場合はtrue
	const auto *expectedModelIds =
		scoped								? &scoped->observed.candidate.modelIds
		: declarative						? &record.declarativeQualification->selected.modelIds
		: record.candidate.modelIds.empty() ? nullptr
											: &record.candidate.modelIds ;	// 元行の全ID
	std::uint32_t bestRank{} ;												// foundの場合だけ有効なWindows full rank
	bool		  enumerationComplete{} ;									// trueの場合はcompatible nodeを上限内で最後まで確認済み
	// Windowsがstaged INFから生成した全nodeを読み、元tuple内の唯一最良を再選択する
	for( DWORD index = 0U; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在照合しているstaged INFのdriver node
		driver.cbSize = sizeof( driver) ;
		SetLastError( ERROR_SUCCESS) ;
		// 列挙APIの終了を検出し、正常終端と途中失敗を区別する
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			const DWORD enumerationError = GetLastError() ;	// 列挙終了または失敗診断値
			// 候補列挙の正常終端以外は診断値を保持して中止する
			if( enumerationError != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( enumerationError ? enumerationError
															 : ERROR_INVALID_DATA) ;
			}

			enumerationComplete = true ;
			break ;
		}

		DriverDetail detail ;	// Staged nodeが参照するINFとinstall section
		// node詳細が取得不能または不正なら一意性を確認できないため中止する
		if( !readDriverDetail( devices.get(), device, driver, detail, nullptr,
							 expectedModelIds != nullptr)) {
			const DWORD detailError = GetLastError() ;	// Detail取得失敗または不正値
			return nativeErrorFromWin32( detailError == ERROR_SUCCESS ? ERROR_INVALID_DATA
																	 : detailError) ;
		}

		std::uint32_t rank{} ;	// Windowsがstaged nodeへ算出したfull rank
		nativeError = readDriverRank( devices.get(), device, driver, rank) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( nativeError != 0) {
			return nativeError ;
		}

		const bool matches =	// 元INF完全path、Provider、packed版、暦日の一致結果
			normalizeIdentifier( detail.infFileName) == normalizeIdentifier( stagedInfPath) &&
			normalizeIdentifier( driver.ProviderName) ==
				normalizeIdentifier( record.candidate.provider) &&
			driver.DriverVersion == record.candidate.packedVersion &&
			formatDriverDate( driver.DriverDate) == record.candidate.date ;
		// 登録先INFと保持証拠に一致しないnodeは導入対象から除外する
		if( !matches) {
			continue ;
		}

		// 同点を即時確定せず、後の低rankで旧同点を解消できるよう保持する
		if( found && rank == bestRank) {
			bestRankTied = true ;
			continue ;
		}

		// 元winnerより悪いnodeがあるだけでは指定導入を曖昧にしない
		if( found && rank > bestRank) {
			continue ;
		}

		selectedDriver		   = driver ;
		found				   = true ;
		bestRank			   = rank ;
		bestRankTied		   = false ;
		selectedMatchesBinding = normalizeIdentifier( detail.sectionName) ==
									 normalizeIdentifier( record.candidate.sectionName) &&
								 fileTimeTicks( driver.DriverDate) == record.candidate.dateTicks &&
								 (!expectedModelIds || detail.modelIds == *expectedModelIds) &&
								 rank == record.candidate.rank ;
	}

	// 列挙上限までに正常終端を確認できなければ一意性を保証しない
	if( !enumerationComplete) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 登録先に一致するnodeが存在しなければ導入しない
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// 最小rankの同点は登録済みnodeでも許可しない
	if( bestRankTied) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	// 旧nodeが残っていても新しい唯一winnerへ差し替わった場合は再scanを要求する
	if( !selectedMatchesBinding) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// Staging中の現在driver変更も検出し、成功済み登録を削除せずdevice導入だけを中止する
	nativeError = revalidateOfficialInfInstallBinding( scanSessionId, deviceIdentity, workspace,
													  package, binding) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( nativeError != 0) {
		return nativeError ;
	}

	nativeError = registration.verify( stagedInfPath) ;
	// Node検索後にもpinした登録path/全byteを再確認し、元INF以外を指定しません
	if( nativeError != 0U) {
		return nativeError ;
	}

	// 登録/候補列挙の間に変わった全storage作用/現service/helperもapply前に拒否します
	if( record.storageQualification) {
		nativeError = revalidateRequiredInfInstallBinding( scanSessionId, deviceIdentity,
														  *record.storageQualification->inspection_,
														  record.requiredPlan, binding) ;
		// 登録後にも全作用資格が一致した場合だけ指定APIへ進めます
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	const HWND parentWindow =	// Caller所有のHWNDをWin32境界でだけ元の型へ戻す
		reinterpret_cast<HWND>( parentWindowNative) ;
	BOOL nativeRebootRequired = FALSE ;	// DiInstallDeviceが返す再起動要求flag
	// 指定nodeの導入失敗はWindows診断値として呼出側へ返す
	// 必要SWCは指定node直前にも元親を正式propertyへ再照合します
	if( !record.requiredParentInstance.empty()) {
		std::wstring currentParent ;	// 同present子の現在親です
		// 親の変更/読取不成立を元選択の範囲へ補完しません
		if( !readDeviceString( devices.get(), device, DEVPKEY_Device_Parent, currentParent) ||
		   normalizeIdentifier( currentParent) !=
			   normalizeIdentifier( record.requiredParentInstance)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 同一選択MTDだけ限定SetupAPI queue経路を使います
	if( mtd) {
		// 同workerの完全低位表です
		const auto &calls = driver_store_inf_detail::transport() ;
		// 同workerのMTD専用低位表です
		const auto &api = calls.mtd ;
		// 元recordに結ぶMTD資格です
		const auto &qualification = *record.storageQualification ;
		// host handlerを元観測と照合する関数です
		const auto	checkHandlers = [&]() -> NativeError {
			 // 再照会した三handler propertyです
			 MtdHandlerObservation current ;
			 // handler再照会の元診断です
			 const auto			   error = inspectMtdHandlers( devices.get(), device, current) ;
			 // handler再照会の元失敗を返します
			 if( error != 0U) {
				 return error ;
			 }

			 return qualification.mtdHandlers_ && current == *qualification.mtdHandlers_
						? 0U
						: nativeErrorFromWin32( ERROR_RETRY) ;
		 } ;
		// 選択nodeの原tupleとrankを再確認する関数です
		const auto checkSelected = [&]() -> NativeError {
			// Windowsから読戻す選択nodeです
			SP_DRVINFO_DATA_W current{} ;
			current.cbSize = sizeof( current) ;
			// 選択node読取の元Windows失敗を返します
			if( !api.getSelected( devices.get(), &device, &current)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 同nodeのdriver detailです
			DriverDetail  detail ;
			// 同nodeの完全rankです
			std::uint32_t rank{} ;
			// 元選択nodeの型・版・識別情報・rank変化を拒否します
			if( current.DriverType != selectedDriver.DriverType ||
			   current.Reserved != selectedDriver.Reserved ||
			   current.DriverVersion != selectedDriver.DriverVersion ||
			   fileTimeTicks( current.DriverDate) != fileTimeTicks( selectedDriver.DriverDate) ||
			   normalizeIdentifier( current.ProviderName) !=
				   normalizeIdentifier( selectedDriver.ProviderName) ||
			   !readDriverDetail( devices.get(), device, current, detail) ||
			   normalizeIdentifier( detail.infFileName) != normalizeIdentifier( stagedInfPath) ||
			   normalizeIdentifier( detail.sectionName) !=
				   normalizeIdentifier( record.candidate.sectionName)) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			// rank取得の元診断です
			const auto error = readDriverRank( devices.get(), device, current, rank) ;
			return error != 0U					   ? error
				   : rank == record.candidate.rank ? 0U
												   : nativeErrorFromWin32( ERROR_RETRY) ;
		} ;
		// 元record・handler・node・INF・bindingを再検証する関数です
		const auto revalidate = [&]() -> NativeError {
			// 元record再検証から保持する最初の診断です
			auto error = (*boundaryAuthorization)() ;
			// 元recordが有効な場合だけhandlerを再照合します
			if( error == 0U) {
				error = checkHandlers() ;
			}

			// handlerが不変な場合だけ選択nodeを再照合します
			if( error == 0U) {
				error = checkSelected() ;
			}

			// 登録INFの原byteと保持を再照合します
			if( error == 0U) {
				error = registration.verify( stagedInfPath) ;
			}

			// 同operationのdevice・内容bindingを再照合します
			if( error == 0U) {
				error = revalidateRequiredInfInstallBinding( scanSessionId, deviceIdentity,
															*qualification.inspection_,
															record.requiredPlan, binding) ;
			}

			return error ;
		} ;
		// 明示選択した同nodeを設定できなければ元診断を返します
		if( !api.setSelected( devices.get(), &device, &selectedDriver)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		nativeError = revalidate() ;
		// 元選択の再検証失敗後にqueueを作りません
		if( nativeError != 0U) {
			return nativeError ;
		}

		// 変更前のdevice install parameterです
		SP_DEVINSTALL_PARAMS_W baseline{} ;
		baseline.cbSize = sizeof( baseline) ;
		// 元device install parameterの取得失敗を返します
		if( !calls.getParameters( devices.get(), &device, &baseline)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 未評価handlerや既存queueを元parameterから採用しません
		if( baseline.FileQueue || baseline.InstallMsgHandler || baseline.InstallMsgHandlerContext ||
		   (baseline.Flags & (DI_NOVCP | DI_NOFILECOPY | DI_FORCECOPY | DI_CLASSINSTALLPARAMS)) ||
		   baseline.ClassInstallReserved || baseline.Reserved) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 元file DIFが構成する未commit queueです
		const auto originalQueue = api.openQueue() ;
		// 原queueを作れない場合は元Windows診断を返します
		if( !originalQueue || originalQueue == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		/** @brief 同操作が作った原queueだけの所有です */
		struct QueueOwner {
			/// 同workerの完全低位API表です
			const driver_store_inf_detail::MtdTransport &api ;
			/// 所有する原queueです
			HSPFILEQ									 handle ;
			/**
			 * @brief 所有する原queueだけを閉じます
			 */
			~QueueOwner()
			{
				api.closeQueue( handle) ;
			}
		} originalOwner{api, originalQueue} ;
		// 元parameterの復旧が必要かを保持します
		bool	   parametersChanged{} ;
		// 各DIFでWindowsが報告した再起動flagsです
		DWORD	   rebootFlags{} ;
		// 限定MTDの原queue・制御copy・選択DIFを実行する関数です
		const auto apply = [&]() -> NativeError {
			// 元parameterから構成する同deviceの一時設定です
			SP_DEVINSTALL_PARAMS_W parameters = baseline ;
			parameters.Flags |= DI_NOVCP ;
			parameters.FileQueue  = originalQueue ;
			parameters.hwndParent = parentWindow ;
			// 原queueを指定するparameter設定失敗を返します
			if( !calls.setParameters( devices.get(), &device, &parameters)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			parametersChanged = true ;
			// Windowsから読戻す一時parameterです
			SP_DEVINSTALL_PARAMS_W observed{} ;
			observed.cbSize = sizeof( observed) ;
			// parameterの読戻し失敗を返します
			if( !calls.getParameters( devices.get(), &device, &observed)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 元queueやhandler・flagsが変わった場合はfile DIFを始めません
			if( observed.FileQueue != originalQueue || observed.InstallMsgHandler ||
			   observed.InstallMsgHandlerContext || observed.Flags != parameters.Flags ||
			   observed.FlagsEx != parameters.FlagsEx || observed.hwndParent != parentWindow ||
			   observed.ClassInstallReserved || observed.Reserved ||
			   std::wcscmp( observed.DriverPath, parameters.DriverPath) != 0) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			// file DIF前の最初の再検証診断です
			auto error = revalidate() ;
			// file DIF前の元recordと選択再検証に失敗すれば止めます
			if( error != 0U) {
				return error ;
			}

			mtdResult->preparationStarted = true ;
			SetLastError( ERROR_SUCCESS) ;
			// DIF_INSTALLDEVICEFILESの原成否です
			const auto queued = api.callInstaller( DIF_INSTALLDEVICEFILES, devices.get(), &device) ;
			// file DIF失敗直後の元Windows診断です
			const auto queueError = queued ? ERROR_SUCCESS : GetLastError() ;
			observed			  = {} ;
			observed.cbSize		  = sizeof( observed) ;
			// file DIF後のparameterを読めなければ元API結果を区別します
			if( !calls.getParameters( devices.get(), &device, &observed)) {
				return queued ? nativeErrorFromWin32( GetLastError())
							  : nativeErrorFromWin32( queueError ? queueError : ERROR_INVALID_DATA) ;
			}

			rebootFlags |= observed.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) ;
			// file DIF自体の失敗をcopy結果に保持します
			if( !queued) {
				mtdResult->copyError =
					nativeErrorFromWin32( queueError ? queueError : ERROR_INVALID_DATA) ;
				return mtdResult->copyError ;
			}

			// file DIF後にqueue・handler・flagsが変わった場合は拒否します
			if( observed.FileQueue != originalQueue || observed.InstallMsgHandler ||
			   observed.InstallMsgHandlerContext ||
			   (observed.Flags & ~(DI_NEEDREBOOT | DI_NEEDRESTART)) !=
				   (parameters.Flags & ~(DI_NEEDREBOOT | DI_NEEDRESTART)) ||
			   observed.FlagsEx != parameters.FlagsEx || observed.ClassInstallReserved ||
			   observed.Reserved || std::wcscmp( observed.DriverPath, parameters.DriverPath) != 0) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			error = revalidate() ;
			// 原queue照合前のbinding変化を元診断で返します
			if( error != 0U) {
				return error ;
			}

			// 原tupleへ結ぶ所有制御queueです
			std::unique_ptr<MtdQualifiedQueue> qualified ;
			error = MtdQualifiedQueue::prepare(
				originalQueue, stagedInfPath, *qualification.inspection_->workspace,
				qualification.effects_.service, *mtdFiles, qualified) ;
			// 原queueの不一致をcopy失敗に保持します
			if( error != 0U) {
				mtdResult->copyError = error ;
				return error ;
			}

			mtdResult->prepared = true ;
			error				= revalidate() ;
			// 元選択を再確認した場合だけ制御queueをcommitします
			if( error == 0U) {
				error = qualified->commit( parentWindow, {}, *boundaryAuthorization, *mtdResult) ;
			}

			mtdResult->copyError = error ;
			rebootRequired		 = mtdResult->systemDelayed || rebootFlags != 0U ;
			// 共有充足やqueue commitの失敗をそのまま返します
			if( error != 0U) {
				return error ;
			}

			error = revalidate() ;
			// 最終DIF前に保持fileを再照合します
			if( error == 0U) {
				error = mtdFiles->verify() ;
			}

			// 同record・fileの失効や変化後に最終DIFを呼びません
			if( error != 0U) {
				return error ;
			}

			parameters			 = observed ;
			parameters.Flags	 = (parameters.Flags & ~DI_NOVCP) | DI_NOFILECOPY ;
			parameters.FileQueue = nullptr ;
			// コピー充足後のNOFILECOPY parameter設定失敗を返します
			if( !calls.setParameters( devices.get(), &device, &parameters)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			observed		= {} ;
			observed.cbSize = sizeof( observed) ;
			// 最終DIF用parameterの読戻し失敗を返します
			if( !calls.getParameters( devices.get(), &device, &observed)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 別queue・handler・未評価flagsがあれば最終DIFを呼びません
			if( observed.FileQueue || observed.InstallMsgHandler ||
			   observed.InstallMsgHandlerContext || observed.Flags != parameters.Flags ||
			   observed.FlagsEx != parameters.FlagsEx || observed.ClassInstallReserved ||
			   observed.Reserved || std::wcscmp( observed.DriverPath, parameters.DriverPath) != 0) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			error = revalidate() ;
			// 選択DIF直前に共有fileを再照合します
			if( error == 0U) {
				error = mtdFiles->verify() ;
			}

			// 最終DIF直前の検証失敗を元診断で返します
			if( error != 0U) {
				return error ;
			}

			mtdResult->deviceInstallStarted = true ;
			SetLastError( ERROR_SUCCESS) ;
			// 同選択DIF_INSTALLDEVICEの原成否です
			const auto installed = api.callInstaller( DIF_INSTALLDEVICE, devices.get(), &device) ;
			// 選択DIF失敗直後の元Windows診断です
			const auto installError			  = installed ? ERROR_SUCCESS : GetLastError() ;
			mtdResult->deviceInstallSucceeded = installed != FALSE ;
			mtdResult->deviceInstallError =
				installed ? 0U
						  : nativeErrorFromWin32( installError ? installError : ERROR_INVALID_DATA) ;
			mtdResult->postVerifyError = mtdFiles->verify() ;
			observed				   = {} ;
			observed.cbSize			   = sizeof( observed) ;
			// Windowsが報告した再起動flagsを原parameter復旧へ保持します
			if( calls.getParameters( devices.get(), &device, &observed)) {
				rebootFlags |= observed.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) ;
			}
			// 導入成功後に結果読取が失敗した場合はその診断を保持します
			else if( installed) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			rebootRequired = mtdResult->systemDelayed || rebootFlags != 0U ;
			// 指定DIF自体の失敗を後続の再検証と区別します
			if( !installed) {
				// Windows診断の欠測を別の結果flagへ残します
				if( diagnosticMissing) {
					*diagnosticMissing = installError == ERROR_SUCCESS ;
				}

				return mtdResult->deviceInstallError ;
			}

			return mtdResult->postVerifyError ;
		} ;
		nativeError = apply() ;
		rebootRequired |= rebootFlags != 0U || mtdResult->systemDelayed ;
		// 変更したdevice parameterだけを元状態へ戻します
		if( parametersChanged) {
			baseline.Flags |= rebootFlags ;
			// parameter復旧失敗を元診断として別に保持します
			if( !calls.setParameters( devices.get(), &device, &baseline)) {
				mtdResult->parameterCleanupError = nativeErrorFromWin32( GetLastError()) ;
				// 先行失敗がない場合だけ復旧失敗を主診断にします
				if( nativeError == 0U) {
					nativeError = mtdResult->parameterCleanupError ;
				}
			}
		}

		// 部分作用を保持したまま最初の失敗を返します
		if( nativeError != 0U) {
			return nativeError ;
		}

		rememberInstalledObservationTarget( instance->second, stagedInfPath,
										   selectedDriver.ProviderName,
										   selectedDriver.DriverVersion) ;
		return 0U ;
	}

	// 実適用直前も同じOEM INFが保持済みのDriver Storeに対応することを確認します
	if( verifyStorePackage) {
		nativeError = storePackage.verify() ;
		// 元配布物との対応が変わった場合はWindowsの適用を呼びません
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	// 同梱依存を必要とする公式選択の現在作用を適用直前に照合します
	if( scoped && scoped->wifiBus) {
		ScopedInfObservation current ;	// 元実選択と現在の同梱作用を確認する再観測です
		nativeError = reobserveScopedInfInstallQualification( *scoped, current) ;
		// Store検証後に同梱INFやサービスが変わった場合は実適用を中止します
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	// 時間のかかる現在状態の確認後に、元承認と有効期限をもう一度照合します
	if( boundaryAuthorization) {
		nativeError = (*boundaryAuthorization)() ;
		// 配置まで進んでいても期限切れや拘束の変化があれば実適用を止めます
		if( nativeError != 0U) {
			return nativeError ;
		}
	}

	// 元の公式対象の操作は最終適用時まで有効である必要があります
	if( scoped &&
	   (scopedOperation != activeInstallOperation_ || !ownsActiveScopedInfInstall( *scoped))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 単一起動は実際の指定適用でも登録前から同じ索引操作と同じ選択を維持する
	if( singleBootStorage &&
	   (bootOperation != activeInstallOperation_ || !installProofInventory_ ||
		std::ranges::find( activeIndexDevices_, deviceIdentity) == activeIndexDevices_.end())) {
		return E_ACCESSDENIED ;
	}

	// 実際に指定導入する同じdevnodeの値を直前に読み、元選択の全バイトに照合します
	const auto *upperFilters =
		scoped && scoped->wifiBus
			? &scoped->wifiBus->upperFilters
			: (record.wifiBusUpperFilters ? &*record.wifiBusUpperFilters
										  : nullptr) ;	// 同じ端末資格のフィルターだけです
	// 上位フィルターを対象にした計画では同じデバイスの現在値を再確認します
	if( upperFilters) {
		MtdHandlerProperty current ;	// 実適用の対象そのものから観測する現在値です
		nativeError = observeWifiBusUpperFilters( devices.get(), device,
												 driverStore.inventory.property, current) ;
		// 別フィルターの追加や、型と元値の変化があればWindowsの適用を呼びません
		if( nativeError != 0U || current != *upperFilters) {
			return nativeError != 0U ? nativeError : nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 同private sessionの再確認済みdevice/nodeだけをflags0で指定します
	if( driver_store_inf_detail::transport().install( parentWindow, devices.get(), &device,
													&selectedDriver, 0,
													&nativeRebootRequired) == FALSE) {
		const DWORD installError =
			// FALSE直後の元診断です。欠落は成功ではありません
			GetLastError() ;
		rebootRequired = nativeRebootRequired != FALSE ;
		// 内部補完と実Windows診断を別観測へ保持します。所有権は移しません
		if( diagnosticMissing) {
			*diagnosticMissing = installError == ERROR_SUCCESS ;
		}

		return nativeErrorFromWin32( installError == ERROR_SUCCESS ? ERROR_INVALID_DATA
																  : installError) ;
	}

	rebootRequired = nativeRebootRequired != FALSE ;
	// Windowsが成功を返した後も、同じOEM INFとDriver Storeの閉包を保持して実際の反映を読む
	if( storageReflection) {
		const auto &qualification = *record.storageQualification ;	// 同じ実選択と適用前の観測
		*storageReflection =
			singleBootStorage
				? observeAppliedSingleBootStorage(
					  instance->second, stagedInfPath, *qualification.inspection_,
					  qualification.effects_, *qualification.singleBoot_, rebootRequired)
				: observeAppliedAutomaticStorage( instance->second, stagedInfPath,
												 *qualification.inspection_, qualification.effects_,
												 rebootRequired) ;
	}

	rememberInstalledObservationTarget( instance->second, stagedInfPath, selectedDriver.ProviderName,
									   selectedDriver.DriverVersion) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み外部INFを現在scanの一つのopaque deviceへ導入する。検証済み外部INFを現在scanの一deviceへ導入する。指定INF一件だけからcompatible
 *        listを構築し、Providerとversionが一意なnodeだけを対象deviceへ導入する
 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID
 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。 対象のopaque device identity
 * @param[in] infPath Providerが再検証した保護workspace内INF絶対path。 再検証済みINFの保護workspace絶対path
 * @param[in] expectedProvider Scan時に検証したINF Provider表示名。 Scan時のINF Provider表示名
 * @param[in] expectedVersion Scan時に検証した4要素numeric driver version。 Scan時の4要素numeric version
 * @param[in] parentWindowNative Device installerの親HWNDを整数表現で渡す値。 Installer親HWNDの整数表現
 * @param[out] rebootRequired 完了に再起動が必要な場合は`true`
 * @return 導入成功時は0、session、再照合またはWindows API失敗時はHRESULT。 対象nodeの再照合と導入成功時は0、それ以外はHRESULT
 * @pre 呼出し側はINF、CAT、全参照fileの署名とPnP適用性を直前に再検証する
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installVerifiedExternalInf(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const std::wstring_view infPath, const std::wstring_view expectedProvider,
	const std::wstring_view expectedVersion, const std::uintptr_t parentWindowNative,
	bool &rebootRequired) const
{

	rebootRequired = false ;
	const std::optional<std::uint64_t> packedVersion =
		// Scan時versionの再照合値
		parseDriverVersion( expectedVersion) ;
	const auto instance = deviceInstances_.find( std::wstring( deviceIdentity)) ;	// Native ID検索
	// 有効なsession、所有thread、device、INF path、provider、数値版を導入前に確認する
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() || infPath.empty() ||
	   infPath.find( L'\0') != std::wstring_view::npos || expectedProvider.empty() ||
	   !packedVersion.has_value() || instance == deviceInstances_.end()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring externalInf( infPath) ;									// Windows APIへ渡すnull終端絶対path
	const DWORD		   attributes = GetFileAttributesW( externalInf.c_str()) ;	// 通常file属性
	// 外部INFの属性取得失敗は診断値を保持して中止する
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 外部INFが通常file以外の場合は導入対象にしない
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceInfoSet devices(
		// 対象一件用set
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を作成できなければ外部INFを適用しない
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// Opaque identityから再openした対象device metadata
	device.cbSize = sizeof( device) ;
	// 照合済みdeviceを開けない場合は他deviceへ適用先を広げない
	if( driver_store_inf_detail::transport().open( devices.get(), instance->second.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const NativeError configureError =	// 単一INF compatible listの条件設定結果
		configureSingleInfDriverSearch( devices.get(), device, externalInf) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( configureError != 0) {
		return configureError ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// 外部INF compatible listのRAII guard
	// 互換driver listの構築失敗を独自照合で補わない
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	SP_DRVINFO_DATA_W selectedDriver{} ;	// 一意に再照合できた外部INF driver node
	bool			  found{} ;				// trueの場合だけDiInstallDeviceを許可する
	// 外部INFから構築された全nodeを確認し、曖昧な複数一致をfail-closedで拒否する
	for( DWORD index = 0; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在再照合中の外部driver node
		driver.cbSize = sizeof( driver) ;
		// 列挙終了時は正常終端かを確認して検索を終える
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			// 正常終端以外の列挙失敗は呼出側へ返す
			if( GetLastError() != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			break ;
		}

		DriverDetail detail ;	// Driver nodeが参照するINFとsection metadata
		// INF詳細の取得失敗や不正metadataを導入前に拒否する
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			const DWORD error = GetLastError() ;	// Detail API失敗または不正metadata診断値
			return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
		}

		const bool matches =
			normalizedFileName( detail.infFileName) == normalizedFileName( externalInf) &&
			normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( expectedProvider) &&
			// Scan時metadataとの完全一致結果
			driver.DriverVersion == packedVersion.value() ;
		// 指定INF、provider、版に一致しないnodeを除外する
		if( !matches) {
			continue ;
		}

		// 複数nodeが一致する曖昧な導入要求を拒否する
		if( found) {
			return nativeErrorFromWin32( ERROR_DUP_NAME) ;
		}

		selectedDriver = driver ;
		found		   = true ;
	}

	// 指定条件に合う互換nodeがなければ導入しない
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// Parentはcaller所有のHWNDをnative API境界でだけ元の型へ戻す
	const HWND parentWindow = reinterpret_cast<HWND>( parentWindowNative) ;	// 非所有parent HWND
	BOOL	   nativeRebootRequired = FALSE ;								// DiInstallDeviceが返す再起動要求flag
	// 外部INFの指定node導入失敗を元の診断値で返す
	if( driver_store_inf_detail::transport().install( parentWindow, devices.get(), &device,
													&selectedDriver, 0,
													&nativeRebootRequired) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	rebootRequired = nativeRebootRequired != FALSE ;
	rememberInstalledObservationTarget( instance->second, externalInf, selectedDriver.ProviderName,
									   selectedDriver.DriverVersion) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief scan で照合済みの Driver Store 候補を再列挙して導入する
 * @param[in] target worker 内に保持した対象 metadata
 * @param[in] parentWindowNative device installer UI の親 HWND
 * @param[out] rebootRequired 完了に再起動が必要な場合は `true`
 * @return 成功時は 0、失敗時は HRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installTarget( const InstallTarget &target,
											   const std::uintptr_t parentWindowNative,
											   bool				   &rebootRequired) const
{
	rebootRequired = false ;
	DeviceInfoSet devices(
		// 対象一件用set
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を取得できなければ保存候補の再照合を中止する
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// Instance IDで再openした対象device metadata
	device.cbSize = sizeof( device) ;
	// scanで照合したdeviceを開けなければ指定版を導入しない
	if( driver_store_inf_detail::transport().open( devices.get(), target.deviceInstanceId.c_str(),
												 nullptr, 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 互換driver検索を構成できなければ検索範囲を広げず中止する
	if( !configureCompatibleDriverSearch( devices.get(), device)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// 再構築compatible listのRAII guard
	// Windowsの互換候補構築に失敗した場合は導入を中止する
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	SP_DRVINFO_DATA_W selectedDriver{} ;	// 全metadataがscan時targetと一致したdriver node
	bool			  found{} ;				// trueの場合だけselected_driverをDiInstallDeviceへ渡せる
	// 再構築したcompatible listからscan時metadataと完全一致する一件だけを選択する
	for( DWORD index = 0; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 再照合中のcompatible driver node
		driver.cbSize = sizeof( driver) ;
		// 列挙が終了または失敗した場合は候補探索を打ち切る
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			break ;
		}

		DriverDetail detail ;	// 再照合中nodeのINFとsection metadata
		// 詳細を取得できないnodeを指定版として採用しない
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			continue ;
		}

		// INF、section、provider、版、日付がscan記録と一致するnodeだけを採用する
		if( normalizedFileName( detail.infFileName) == normalizedFileName( target.infFileName) &&
		   normalizeIdentifier( detail.sectionName) == normalizeIdentifier( target.sectionName) &&
		   normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( target.providerName) &&
		   driver.DriverVersion == target.driverVersion &&
		   fileTimeTicks( driver.DriverDate) == target.driverDateTicks) {
			selectedDriver = driver ;
			found		   = true ;
			break ;
		}
	}

	// scan記録と一致するnodeが失われていれば導入しない
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// parent は caller が整数化した HWND だけを受け取り、native API 境界で元の型へ戻す
	// Installer UIに渡す呼出し元所有のparent Window handle
	const HWND parentWindow			= reinterpret_cast<HWND>( parentWindowNative) ;
	BOOL	   nativeRebootRequired = FALSE ;	// DiInstallDeviceが返す再起動要求flag
	// 保存候補の指定node導入失敗は診断値を保持して返す
	if( driver_store_inf_detail::transport().install( parentWindow, devices.get(), &device,
													&selectedDriver, 0,
													&nativeRebootRequired) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	rebootRequired = nativeRebootRequired != FALSE ;
	rememberInstalledObservationTarget( target.deviceInstanceId, target.infFileName,
									   target.providerName, target.driverVersion) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 成功した指定対象だけを実事後照合用へ保持します
 * @param[in] instance Worker内だけの元instanceです
 * @param[in] inf 指定済みの実INFです
 * @param[in] provider 指定nodeのproviderです
 * @param[in] version 指定nodeのpacked版です
 * @note 確保失敗は読取証明を省き、実導入結果を変更しません
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::rememberInstalledObservationTarget(
	const std::wstring_view instance, const std::wstring_view inf, const std::wstring_view provider,
	const std::uint64_t version) const noexcept
{
	// 再記録前に当該instanceの旧証明を無確保で消し、例外時は未確認にします
	for( auto found = installedObservationTargets_.begin();
		found != installedObservationTargets_.end(); ++found) {
		// 同operationの旧対象を先に消して確保失敗時の流用を防ぎます
		if( found->first == instance) {
			installedObservationTargets_.erase( found) ;
			break ;
		}
	}

	// 証明用copyの確保失敗を実API成功の失敗へ置き換えません
	try {
		installedObservationTargets_.insert_or_assign( std::wstring( instance),
													  InstallTarget{std::wstring( instance),
																	std::wstring( inf),
																	{},
																	std::wstring( provider),
																	version,
																	0U}) ;
	} catch( ...) {
		// 欠測は後続で未確認として扱います
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元scanの対象だけを同worker内で導入後にread-only照会する関数を作ります
 * @param[in] session 元scan sessionです。導入権限を延長しません
 * @param[in] devices 同scanの選択済みopaque device集合です
 * @return 同workerのinstall呼出し内だけで一回使用する読取関数。生IDをUIへ渡しません
 * @note 対象instanceとAPI表を一時所有し、期待mapはProviderから借用します。同owner thread・Provider生存中の同期呼出しだけが有効です。captured
 *       sessionと現在scanの不一致では期待mapを使いません。全PnP scan/再検出/候補発行は行いません
 */
//------------------------------------------------------------------------------
std::function<std::vector<PostInstallDeviceObservation>()> DriverStoreProvider::
	capturePostInstallObservations( const ScanSessionId				   session,
								   const std::span<const std::wstring> devices) const
{
	// 前operationの表示証明を再使用しません
	installedObservationTargets_.clear() ;
	// 通常scanの元deviceだけを有限に保持し、専用metadata fixtureをnativeへ補完しません
	if( devices.empty() || devices.size() > MAXIMUM_OFFICIAL_INF_BINDINGS) {
		return {} ;
	}

	const bool valid = session != 0U && session == scanSessionId_ &&
					   ownerThreadId_ == GetCurrentThreadId() &&
					   !testInventoryTransport_ ;	// 同workerの元対応表です
	std::vector<std::pair<std::wstring, std::wstring>>
		targets ;	// Opaqueとprivate instanceの一時対応です
	targets.reserve( devices.size()) ;
	// 指定deviceだけをcopyし、未解決を別deviceや全列挙へ置き換えません
	for( const auto &device : devices) {
		const auto found = deviceInstances_.find( device) ;	// 元scanで照合したprivate値です
		targets.emplace_back( device,
							 valid && found != deviceInstances_.end() ? found->second : L"") ;
	}

	const auto calls =
		// 同worker fixtureまたは製品固定の完全表です
		driver_store_inf_detail::transport() ;
	const DWORD owner = GetCurrentThreadId() ;	// 別threadへread処理を移しません
	return [targets = std::move( targets), calls, owner, session, this] {
		std::vector<PostInstallDeviceObservation> observations ;	// 生IDを含まない返却値です
		observations.reserve( targets.size()) ;
		// 最大元選択件数だけを一件ずつ再openし、compatible listやdriver候補を列挙しません
		for( const auto &[deviceIdentity, instance] : targets) {
			PostInstallDeviceObservation observed ;	// 成功値を候補のmetadataで補完しません
			observed.observation.scanSessionId	= session ;
			observed.observation.deviceIdentity = deviceIdentity ;
			// 解決失敗・thread違いはAPI前に拒否し、元bindingの寿命を延ばしません
			if( instance.empty() || GetCurrentThreadId() != owner) {
				observed.error = static_cast<NativeError>( E_INVALIDARG) ;
				observations.push_back( std::move( observed)) ;
				continue ;
			}

			DeviceInfoSet	set{calls.create( nullptr, nullptr),
								calls.inventory} ;	// 対象一件用のread-only集合です
			SP_DEVINFO_DATA device{} ;				// 再open先の現在metadataです
			device.cbSize = sizeof( device) ;
			// 対象を開けなければ不在とAPI失敗を元診断で保持します
			if( !set.valid() || !calls.open( set.get(), instance.c_str(), nullptr, 0U, &device)) {
				observed.error = nativeErrorFromWin32( GetLastError()) ;
				observations.push_back( std::move( observed)) ;
				continue ;
			}

			std::wstring actualInstance ;	// 値はこのcallbackの外へ渡しません
			observed.observation.instanceIdentity =
				readObservedInstanceId( set.get(), device, actualInstance, calls.inventory) ;
			std::vector<std::byte> present ;	// 同対象の現在present属性だけです
			const auto			   presentRead = readObservedProperty(
				set.get(), device, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN, present,
				calls.inventory) ;	// 既存の型/容量検証を使用します
			// 元deviceと異なる返却・非present・確認不能は現在表示へ昇格しません
			if( observed.observation.instanceIdentity.state != DevicePropertyReadState::VALUE ||
			   normalizeIdentifier( actualInstance) != normalizeIdentifier( instance) ||
			   presentRead.state != DevicePropertyReadState::VALUE ||
			   present.size() != sizeof( DEVPROP_BOOLEAN) ||
			   present.front() != static_cast<std::byte>( DEVPROP_TRUE)) {
				observed.error = nativeErrorFromWin32( presentRead.diagnostic.code != 0U
														  ? presentRead.diagnostic.code
														  : ERROR_NO_SUCH_DEVINST) ;
				observations.push_back( std::move( observed)) ;
				continue ;
			}

			auto &observation		 = observed.observation ;	// 同deviceの元読取状態です
			observation.node		 = readObservedNode( device, calls.inventory) ;
			observation.friendlyName = readObservedDeviceString(
				set.get(), device, DEVPKEY_Device_FriendlyName, observed.name, calls.inventory) ;
			// FriendlyName欠損時だけ標準説明へfallbackし、元の欠損を保持します
			if( observation.friendlyName.state != DevicePropertyReadState::VALUE) {
				observation.deviceDescription = readObservedDeviceString(
					set.get(), device, DEVPKEY_Device_DeviceDesc, observed.name, calls.inventory) ;
			}

			observation.manufacturer =
				readObservedDeviceString( set.get(), device, DEVPKEY_Device_Manufacturer,
										 observed.manufacturer, calls.inventory) ;
			observation.deviceClass = readObservedDeviceString(
				set.get(), device, DEVPKEY_Device_Class, observed.driverClass, calls.inventory) ;
			observed.deviceClassGuid = formatClassGuid( device.ClassGuid) ;
			std::wstring driverKey ;	// 生keyは現在値の登録有無だけへ分類して破棄します
			observation.driverKey = readObservedDeviceString(
				set.get(), device, DEVPKEY_Device_Driver, driverKey, calls.inventory) ;
			const auto current =
				// 実propertyだけです
				readCurrentDriver( set.get(), device, calls.inventory) ;
			observation.infName	 = current.infRead ;
			observation.provider = current.providerRead ;
			observation.version	 = current.versionRead ;
			observation.date	 = current.dateRead ;
			observation.driverPresence =
				classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
			observed.provider	= current.provider ;
			observed.version	= current.version ;
			observed.driverDate = current.date ;
			const auto expected =
				session == scanSessionId_ && GetCurrentThreadId() == ownerThreadId_
					? installedObservationTargets_.find( instance)
					: installedObservationTargets_.end() ;	// 元scanの今回実指定したtargetだけです
			bool sameInf = expected != installedObservationTargets_.end() &&
						   normalizedFileName( current.infFileName) ==
							   // 原名一致です
							   normalizedFileName( expected->second.infFileName) ;
			// OEM別名でも、既登録rootと元INF全byteの一致を要求します
			if( !sameInf && expected != installedObservationTargets_.end()) {
				RegisteredInfGuard			  registration ;	// 既保護root/元byteのscopeです
				std::array<wchar_t, MAX_PATH> directory{} ;		// 同backendのWindows rootです
				const auto					  length = calls.windowsDirectory( directory.data(),
																			  // production/fakeを混在させません
																			  static_cast<UINT>( directory.size())) ;
				// 同backendのWindows rootと元INF検証が成立する場合だけ別名を照合します
				if( length > 0 && length < directory.size() && directory[length] == L'\0' &&
				   registration.initialize( expected->second.infFileName) == 0) {
					const auto published = std::wstring( directory.data(), length) + L"\\INF\\" +
										   // 私有の登録先です
										   normalizedFileName( current.infFileName) ;
					sameInf = registration.verify( published) == 0 ;
				}
			}

			observed.selectedTargetMatched =
				expected != installedObservationTargets_.end() &&
				current.infRead.state == DevicePropertyReadState::VALUE &&
				current.providerRead.state == DevicePropertyReadState::VALUE &&
				current.packedVersion && sameInf &&
				normalizeIdentifier( current.provider) ==
					normalizeIdentifier( expected->second.providerName) &&
				*current.packedVersion == expected->second.driverVersion ;

			observations.push_back( std::move( observed)) ;
		}

		return observations ;
	} ; // 元install呼出し内・Provider生存中にだけ使うread-only map借用です。install許可・leaseはcaptureしません
}

//------------------------------------------------------------------------------
/**
 * @brief scan session と秘密性のある device metadata を失効させる
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::invalidateScanSession() noexcept
{
	installedObservationTargets_.clear() ;
	issuedIndexContext_ = {} ;
	activeIndexDevices_.clear() ;
	pendingIndexDevices_.clear() ;
	activeInstallDevices_.clear() ;
	activeInstallOperation_		  = 0U ;
	lastAcceptedInstallOperation_ = 0U ;
	installEntered_				  = false ;
	indexInventory_.reset() ;
	installProofInventory_.reset() ;
	installTargets_.clear() ;
	hardwareToDevice_.clear() ;
	deviceInstances_.clear() ;
	officialInfInstallBindings_.clear() ;
	officialInstallerBindings_.clear() ;
	stagedOfficialInfs_.clear() ;
	inventoryMeasurement_ = {} ;
	scanSessionId_		  = 0 ;
	ownerThreadId_		  = 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元scanのpresent deviceを公式installer専用の秘密guardへ固定します
 * @param[in] session 元scan sessionです
 * @param[in] device 元表示のopaque deviceです
 * @param[in] provider 元現在行のproviderです。native再観測へ完全一致を要求します
 * @param[in] version 元現在行の版です
 * @param[in] date 元現在行の日付です
 * @param[out] token 全原状態一致時だけ非zero guardです。失敗時0です
 * @return 同worker/native x64/present/原現在状態確認0、拒否は元HRESULTです
 * @note 標準INFのWindows rank合格を発行しません
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createOfficialInstallerDeviceBinding(
	const ScanSessionId session, const std::wstring_view device, const std::wstring_view provider,
	const std::wstring_view version, const std::wstring_view date, std::uint64_t &token)
{
	token				= 0U ;
	const auto instance = deviceInstances_.find( std::wstring{device}) ;	// 同scan秘密instanceです
	// 別thread/session/未知deviceや枠超過からguardを発行しません
	if( session == 0U || session != scanSessionId_ || ownerThreadId_ != GetCurrentThreadId() ||
	   instance == deviceInstances_.end() || !ownsInstallDevice( device) ||
	   officialInstallerBindings_.size() >= MAXIMUM_OFFICIAL_INF_BINDINGS ||
	   nextOfficialBindingToken_ == 0U ||
	   nextOfficialBindingToken_ == std::numeric_limits<std::uint64_t>::max()) {
		return E_ACCESSDENIED ;
	}

	SYSTEM_INFO system{} ;	// 元低位backendの実architectureです
	driver_store_inf_detail::transport().architecture( &system) ;
	// ARM64 emulation等をnative x64へ補完しません
	if( system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	DeviceRankSnapshot current ;	// 実present/全current属性/全PnPを同時に確認します
	const auto		   error =
		// rank成功は発行しません
		readDeviceRankSnapshot( instance->second, current) ;
	// 元現在行と変わったnative状態からinstaller guardを発行しません
	if( error != 0U || current.currentDriver.provider != provider ||
	   current.currentDriver.version != version || current.currentDriver.date != date) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	}

	OfficialInstallerDeviceBindingRecord record ;	// 同scanの秘密状態だけを保存します
	record.session					= session ;
	record.identity					= device ;
	record.device					= {instance->second,
									   std::move( current.deviceClass),
									   std::move( current.hardwareIds),
									   std::move( current.compatibleIds),
									   std::move( current.matchingDeviceId),
									   std::move( current.currentDriver.infFileName),
									   std::move( current.currentDriver.provider),
									   std::move( current.currentDriver.version),
									   std::move( current.currentDriver.date),
									   current.currentDriver.packedVersion.value_or( 0U),
									   current.noDriver} ;
	record.device.classRead			= current.classRead ;
	record.device.classGuidRead		= current.classGuidRead ;
	record.device.observedClassGuid = std::move( current.observedClassGuid) ;
	record.device.nativeClassGuid	= std::move( current.nativeClassGuid) ;
	record.device.classState		= current.classState ;
	record.device.node				= current.node ;
	record.device.driverKeyRead		= current.driverKeyRead ;
	record.device.matchingRead		= current.matchingRead ;
	record.device.driverKey			= std::move( current.driverKey) ;
	const auto issued				= nextOfficialBindingToken_ ;	// 元issuerだけの単調tokenです
	// 全値の保存後だけguardを発行し、既存tokenを上書きしません
	if( !officialInstallerBindings_.emplace( issued, std::move( record)).second) {
		return HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS) ;
	}

	++nextOfficialBindingToken_ ;
	token = issued ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元installer guardを変更直前のpresent/全秘密状態へ再照合します
 * @param[in] session 元scanです
 * @param[in] device 元opaque deviceです
 * @param[in] token 未使用の同issuer guardです
 * @return 全native状態一致0、それ以外は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateOfficialInstallerDeviceBinding(
	const ScanSessionId session, const std::wstring_view device, const std::uint64_t token) const
{
	const auto stored = officialInstallerBindings_.find( token) ;	// 同issuerの元guardです
	// 別thread/元選択外/古session/使用済みguardの引継ぎを拒否します
	if( session == 0U || session != scanSessionId_ || ownerThreadId_ != GetCurrentThreadId() ||
	   stored == officialInstallerBindings_.end() || stored->second.session != session ||
	   stored->second.identity != device || stored->second.consumed || !ownsInstallDevice( device)) {
		return E_ACCESSDENIED ;
	}

	DeviceRankSnapshot current ;							// 変更直前の全native状態です
	const auto		  &original = stored->second.device ;	// UI/通常logへ渡さない元秘密状態です
	const auto		   error =
		// 同低位backendだけです
		readDeviceRankSnapshot( original.deviceInstanceId, current) ;
	// 完全なpresent/current/PnP/classの変化を無視して起動しません
	if( error != 0U || current.deviceClass != original.deviceClass ||
	   current.classState != original.classState ||
	   current.classRead.state != original.classRead.state ||
	   current.classGuidRead.state != original.classGuidRead.state ||
	   current.observedClassGuid != original.observedClassGuid ||
	   current.nativeClassGuid != original.nativeClassGuid ||
	   current.node.statusFlags != original.node.statusFlags ||
	   current.node.problemCode != original.node.problemCode ||
	   current.driverKeyRead.state != original.driverKeyRead.state ||
	   current.matchingRead.state != original.matchingRead.state ||
	   current.driverKey != original.driverKey || current.hardwareIds != original.hardwareIds ||
	   current.compatibleIds != original.compatibleIds ||
	   current.matchingDeviceId != original.matchingDeviceId ||
	   current.currentDriver.infFileName != original.currentInfFileName ||
	   current.currentDriver.provider != original.currentProvider ||
	   current.currentDriver.version != original.currentVersion ||
	   current.currentDriver.date != original.currentDate ||
	   current.noDriver != original.noDriver ||
	   current.currentDriver.packedVersion.value_or( 0U) != original.currentPackedVersion) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 明示選択済みguardを一回だけ消費します
 * @param[in] session 元scanです
 * @param[in] device 元opaque deviceです
 * @param[in] token 元未使用guardです
 * @return 全再照合成功0、再使用/変化は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::consumeOfficialInstallerDeviceBinding(
	const ScanSessionId session, const std::wstring_view device, const std::uint64_t token)
{
	const auto error =
		// 直前native確認です
		revalidateOfficialInstallerDeviceBinding( session, device, token) ;
	// 失効したguardを消費済み成功へ変更しません
	if( error == 0U) {
		officialInstallerBindings_.at( token).consumed = true ;
	}

	return error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同issuerの未公開installer guardだけをrollbackします
 * @param[in] session 元scanです
 * @param[in] token 当該issuerの元guardです
 * @return 元sessionのguardを除去した場合trueです
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::discardOfficialInstallerDeviceBinding( const ScanSessionId session,
																const std::uint64_t token) noexcept
{
	const auto found = officialInstallerBindings_.find( token) ;	// このissuerだけの元guardです
	// 古sessionや未知tokenの秘密状態へ触れません
	if( found == officialInstallerBindings_.end() || found->second.session != session ||
	   ownerThreadId_ != GetCurrentThreadId()) {
		return false ;
	}

	officialInstallerBindings_.erase( found) ;
	return true ;
}

} // namespace drivercrate
