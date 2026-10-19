//------------------------------------------------------------------------------
/**
 * @file official_cab.h
 * @brief 公式CAB安全解析および選択展開定義。
 * @version 01.00.01
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Cleanup fault-injection境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note SetupAPIのCAB列挙を二回使用し、全entryを書込み前に検証したうえで、指定された通常fileだけを保護workspaceへ展開します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "platform/official_zip.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief CAB展開fileを一件ずつ破棄する非所有callbackとcontextを表す。
 *
 * @note `context`とcallbackが参照するobjectは、best-effort cleanup呼出し中だけ有効とする。
 */
struct OfficialCabFileDiscardOperation {
	/**
	 * @brief 作成済みCAB fileの相対名を同期cleanupへ渡す。contextの借用期間は外側operationに従う。
	 */
	using Callback = NativeError ( *)( void *context, std::wstring_view relativePath) ;

	/// Callbackへ渡す非所有context。Callbackがnullを許可する場合だけnull可。
	void	*context{} ;
	/// 一fileを破棄する同期callback。nullは不正入力。
	Callback callback{} ;
} ;

/**
 * @brief 公式CABを解析および展開するときの有限上限を表す。
 */
struct OfficialCabExtractionPolicy {
	/// CAB入力fileの最大byte数。
	std::uint64_t maximumArchiveBytes ;
	/// 一fileの展開後最大byte数。
	std::uint64_t maximumSingleFileBytes ;
	/// 全file合計の展開後最大byte数。
	std::uint64_t maximumTotalExpandedBytes ;
	/// CABが保持するfile数上限。
	std::uint32_t maximumEntryCount ;
} ;

/**
 * @brief CAB処理で作成した全fileを一件の失敗または例外後も破棄し続ける。
 * CAB展開fileを失敗または例外後も可能な限り破棄する。
 * 一fileの失敗またはC++例外を記録して後続fileを処理する。Callbackを呼べない不正入力はfail-closedで拒否する。
 * @param[in] relativePaths Workspaceが追跡する検証済み相対path群。 Workspaceが追跡する相対path群。
 * @param[in] operation 呼出し中だけ有効な同期破棄callbackと非所有context。
 * @return 全件成功時は0、失敗がある場合は最初のHRESULT bit pattern。 全件成功時は0、失敗があれば最初のHRESULT。
 * @note CallbackのC++例外を外へ漏らさず、後続fileの破棄を継続する。
 */
[[nodiscard]] NativeError discardOfficialCabFilesBestEffort(
	std::span<const std::wstring>		   relativePaths,
	const OfficialCabFileDiscardOperation &operation) noexcept ;

/**
 * @brief CABの全entryと展開量をfileを作成せず検証する。
 * 公式CABの全entryを展開せず検証する。
 * Fileを作成せず二回目の選択展開に必要な全構造を固定する。
 * @param[in] archivePath 保護workspaceにある通常CABの絶対path。 保護領域のCAB絶対path。
 * @param[in] policy Providerが固定した入力、展開量、entry数上限。 入力と展開量の有限上限。
 * @param[out] entries 成功時の通常file一覧。SHA-256は空とする。 成功時の検証済み通常file群。
 * @return 成功時は0、形式不正、path不正、重複、上限超過時はHRESULT。 列挙と全上限の検証成功時は0。
 * @note ASCII相対pathと単一CABだけを受理し、分割CABは拒否する。
 */
[[nodiscard]] NativeError inspectOfficialCab( std::wstring_view					archivePath,
											 const OfficialCabExtractionPolicy &policy,
											 std::vector<OfficialZipEntry>	   &entries) ;

/**
 * @brief CAB全体を事前検証し、固定相対pathの通常fileだけを展開する。
 * 公式CABから固定相対pathの通常fileだけを展開する。
 * 事前検証と展開を分離し、選択外entryをdiskへ書き出さない。
 * @param[in] archivePath 保護workspaceにある通常CABの絶対path。 保護領域のCAB絶対path。
 * @param[in] policy CAB全体へ適用する入力、展開量、entry数上限。 CAB全体へ適用する有限上限。
 * @param[in] selectedFiles 一件以上のASCII `\\`区切り相対file path。 展開する固定相対path群。
 * @param[in,out] workspace 初期化済みで選択fileを所有する保護workspace。 選択fileの所有とcleanup先。
 * @param[out] entries 成功時に作成した通常file一覧とSHA-256。 展開済みfileとSHA-256の一覧。
 * @return 全entryの事前検証と選択fileの完全な展開成功時は0。 全entry検証、選択展開、size、hash確定の成功時は0。
 * @note 選択pathの欠落、重複、不正pathはfile作成前に拒否する。
 */
[[nodiscard]] NativeError extractOfficialCabFiles( std::wstring_view					 archivePath,
												  const OfficialCabExtractionPolicy &policy,
												  std::span<const std::wstring_view> selectedFiles,
												  OfficialDownloadWorkspace			&workspace,
												  std::vector<OfficialZipEntry>		&entries) ;

} // namespace drivercrate
