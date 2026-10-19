//------------------------------------------------------------------------------
/**
 * @file dell_server_catalog_parser.h
 * @brief Dell PowerEdge Enterprise catalog parser定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note OpenPGP検証後のDell Enterprise catalogから、対象PowerEdge／Windows Server x64／PCI IDへ一致する個別driver DUP
 *       だけを抽出します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief 一つのPowerEdge driver DUPとlocal照合に使う検証済みmetadataである。
 */
struct DellServerDriverRelease {
	/// Dell発行の英数字release ID。
	std::wstring			  releaseId ;
	/// Catalogの英語driver名称。
	std::wstring			  title ;
	/// Hardware vendor driver version。
	std::wstring			  version ;
	/// Dell package revision。
	std::wstring			  dellVersion ;
	/// Catalogの公開日表示。
	std::wstring			  releaseDate ;
	/// Dell CDN基準の相対DUP path。
	std::wstring			  path ;
	/// Catalog宣言の小文字64桁SHA-256。
	std::wstring			  sha256 ;
	/// Catalog宣言のDUP byte数。
	std::uint64_t			  size{} ;
	/// RecommendedまたはUrgentの場合true。
	bool					  recommended{} ;
	/// Catalogが再起動必須と宣言した場合true。
	bool					  rebootRequired{} ;
	/// Catalog PCIInfoから構成したlocal照合ID群。
	std::vector<std::wstring> hardwareIds ;
} ;

/**
 * @brief Dell Enterprise catalogから対象Server buildの個別driver DUPを取得する。
 * Dell Enterprise catalogからPowerEdge driverを取得する。
 * ComponentType DRVRのうちmodel／Server build／x64が一致し、PCI IDを持つindividual DUPだけを成功時に一括反映する。
 * @param[in] xmlUtf16 OpenPGP、GZip、encoding検証済みEnterprise catalog XML。 署名・GZip・encoding検証済みXML。
 * @param[in] systemModel SMBIOS由来のDell system product名。 SMBIOS由来system product名。
 * @param[in] windowsBuild 実行中Windows ServerのCurrentBuildNumber。 実Windows Server build番号。
 * @param[out] releases 成功時のmodel／OS／x64／PCI適合driver群。0件も成功。 成功時の適合driver群。0件も成功。
 * @return 成功時は0、schema、上限、metadata不正時はHRESULT bit pattern。
 * @note BIOS、firmware、application、bundle、PCI IDなしcomponentは返さない。
 */
[[nodiscard]] NativeError parseDellServerCatalog( std::wstring_view					   xmlUtf16,
												 std::wstring_view					   systemModel,
												 std::uint32_t						   windowsBuild,
												 std::vector<DellServerDriverRelease> &releases) ;

} // namespace drivercrate
