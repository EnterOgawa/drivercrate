//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_package.h
 * @brief NVIDIA WinOF-2 MSI driver閉包選択定義。
 * @version 01.00.00
 * @date 2026/09/07
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  MSI内CABのdriver閉包選択を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得元identityの後段拘束を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 取得済みWinOF-2 MSIを実行せず、Data1.cabと選択INFが参照するfileだけを保護workspaceへ分離します。PnP／rank、署名、導入可否は確定しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "platform/official_cab.h"
#include "platform/official_driver_closure.h"
#include "platform/official_msi.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief WinOF-2 MSIから一つのdriver閉包を選ぶ有限上限を表す。
 */
struct NvidiaWinof2DriverClosurePolicy {
	/// MSIとData1.cabの取得上限。
	OfficialMsiStreamExtractionPolicy msiStreamPolicy ;
	/// Media／File table照会上限。
	OfficialMsiCabinetInventoryPolicy msiInventoryPolicy ;
	/// CAB全entryと選択展開の有限上限。
	OfficialCabExtractionPolicy		  cabPolicy ;
	/// 選択INFから保持するPnP ID数上限。
	std::size_t						  maximumHardwareIds ;
	/// 選択INFから保持する参照file数上限。
	std::size_t						  maximumSourceFiles ;
	/// INF、CAT、参照fileの一意件数上限。
	std::size_t						  maximumClosureFiles ;
	/// Driver閉包の展開後合計byte数上限。
	std::uint64_t					  maximumClosureBytes ;
	/// 生CAB名から論理名へ複写するbuffer byte数。
	std::uint32_t					  copyBufferBytes ;
} ;

/**
 * @brief 取得・検証済みWinOF-2 MSIと利用者が選択した一INFを表す。
 */
struct NvidiaWinof2DriverClosureRequest {
	/// 保護workspace内のlocal絶対MSI path。
	std::wstring_view databasePath ;
	/// 外側7z展開時に固定したMSI byte数。
	std::uint64_t	  expectedDatabaseSize ;
	/// 外側7z展開時に固定したMSI SHA-256。
	std::wstring_view expectedDatabaseSha256 ;
	/// MSI取得元と同じ0ではないsession ID。
	ScanSessionId	  scanSessionId{} ;
	/// 外側公式payloadの0ではない取得連番。
	std::uint64_t	  sourceAcquisitionId{} ;
	/// 許可6系列から選んだ論理INF名。
	std::wstring_view selectedInfPath ;
	/// 成功閉包を所有する保護領域識別子。
	std::wstring_view workspaceTag ;
} ;

/**
 * @brief WinOF-2 CAB全体照合後に分離した一つのdriver閉包を表す。
 */
struct NvidiaWinof2DriverClosure {
	/// 閉包を作成した公式取得元のscan session。
	ScanSessionId		  scanSessionId{} ;
	/// 外側公式payloadの取得連番。
	std::uint64_t		  sourceAcquisitionId{} ;
	/// 閉包作成前後に固定したMSI byte数。
	std::uint64_t		  databaseSize{} ;
	/// 閉包作成前後に固定したMSI SHA-256。
	std::wstring		  databaseSha256 ;
	/// 閉包へ選択した許可INF論理名。
	std::wstring		  selectedInfPath ;
	/// MSI mappingとCABで一致した全file数。
	std::size_t			  cabinetFileCount{} ;
	/// 選択INF、CAT、参照fileだけの論理名閉包。
	OfficialDriverClosure closure ;
} ;

/**
 * @brief 取得済みWinOF-2 MSIから選択INF一件のdriver閉包だけを分離する。
 * MSI／CABを実行せず、選択INFが参照しないmixed内容を除外する。
 * @param[in] request 外側取得連番、MSI identity、scan session、選択INF、出力識別子。 外側取得連番、MSI identity、session、選択
 *                   INF。
 * @param[in] policy MSI、CAB、INF、閉包、複写bufferの有限上限。 MSI、CAB、INF、閉包、複写の有限上限。
 * @param[in,out] workspace 成功した論理名driver fileだけを所有する保護領域。 成功した論理名driver閉包の所有領域。
 * @param[out] result 取得元identity、全mapping照合件数と構造検証済みdriver閉包。 取得元identity、CAB照合件数、検証済み閉包。
 * @return 全identity、mapping、選択展開、INF構造検証成功時は0。
 * @note 処理はblockingのためProvider worker threadで実行し、任意codeを起動しない。
 */
[[nodiscard]] NativeError extractNvidiaWinof2DriverClosure(
	const NvidiaWinof2DriverClosureRequest &request, const NvidiaWinof2DriverClosurePolicy &policy,
	OfficialDownloadWorkspace &workspace, NvidiaWinof2DriverClosure &result) ;

} // namespace drivercrate
