//------------------------------------------------------------------------------
/**
 * @file official_msi.h
 * @brief 公式MSI stream取得・cabinet mapping定義。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Read-only MSI stream取得境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Media／File mapping照会を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 取得済みMSIをWindows Installerのread-only databaseとして開き、固定名streamの保存とMedia／File mappingの照会だけを行います
 *       。MSIやcustom actionは実行しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief MSI databaseと選択streamへ適用する有限上限を表す。
 */
struct OfficialMsiStreamExtractionPolicy {
	/// 入力MSI全体の最大byte数。
	std::uint64_t maximumDatabaseBytes ;
	/// 選択streamの最大byte数。
	std::uint64_t maximumStreamBytes ;
	/// 一回のMSI読取りに使用するbuffer byte数。
	std::uint32_t readBufferBytes ;
} ;

/**
 * @brief 取得済みMSIのidentityと選択streamを拘束する要求を表す。
 */
struct OfficialMsiStreamExtractionRequest {
	/// 保護workspace内のlocal絶対MSI path。
	std::wstring_view databasePath ;
	/// 7z展開時に固定したMSI byte数。
	std::uint64_t	  expectedDatabaseSize ;
	/// 7z展開時に固定したMSI SHA-256。
	std::wstring_view expectedDatabaseSha256 ;
	/// 完全一致させる固定MSI stream名。
	std::wstring_view streamName ;
	/// 新規作成するworkspace相対path。
	std::wstring_view outputRelativePath ;
} ;

/**
 * @brief MSIから保護workspaceへ取得した一streamのidentityを表す。
 */
struct OfficialMsiStreamEntry {
	/// MSI recordと完全一致したstream名。
	std::wstring  streamName ;
	/// Workspace内の検証済み相対path。
	std::wstring  relativePath ;
	/// MSI recordが宣言し、保存したbyte数。
	std::uint64_t streamSize{} ;
	/// 保存file全体の64桁小文字SHA-256。
	std::wstring  sha256 ;
} ;

/**
 * @brief MSIのembedded cabinetに属する一fileの名前対応とidentityを表す。
 */
struct OfficialMsiCabinetFileEntry {
	/// CABが保持する`File` primary key名。
	std::wstring  cabinetRelativePath ;
	/// `FileName`のlong nameから得た論理file名。
	std::wstring  targetRelativePath ;
	/// `FileSize`が宣言する展開後byte数。
	std::uint64_t uncompressedSize{} ;
	/// Media範囲内で一意な`File.Sequence`。
	std::uint32_t sequence{} ;
} ;

/**
 * @brief MSI embedded cabinetの`Media`／`File`照会へ適用する有限上限を表す。
 */
struct OfficialMsiCabinetInventoryPolicy {
	/// 入力MSI全体の最大byte数。
	std::uint64_t maximumDatabaseBytes ;
	/// 一つの`File` rowに許可する最大byte数。
	std::uint64_t maximumSingleFileBytes ;
	/// 対象cabinetに許可する`File` row数。
	std::uint32_t maximumFileCount ;
} ;

/**
 * @brief 取得済みMSIのidentityと照会するembedded cabinet streamを表す。
 */
struct OfficialMsiCabinetInventoryRequest {
	/// 保護workspace内のlocal絶対MSI path。
	std::wstring_view databasePath ;
	/// 外側展開時に固定したMSI byte数。
	std::uint64_t	  expectedDatabaseSize ;
	/// 外側展開時に固定したMSI SHA-256。
	std::wstring_view expectedDatabaseSha256 ;
	/// `Media.Cabinet`へ`#`付きで照合する名前。
	std::wstring_view streamName ;
} ;

/**
 * @brief MSI embedded cabinetのMedia範囲と順序付きfile mappingを表す。
 */
struct OfficialMsiCabinetInventory {
	/// `Media.Cabinet`と一致したstream名。
	std::wstring							 streamName ;
	/// Sequence昇順のfile mapping。
	std::vector<OfficialMsiCabinetFileEntry> files ;
} ;

/**
 * @brief 取得済み公式MSIから固定名stream一件だけをread-onlyで取得する。
 * Read-only parameter queryだけを実行し、失敗時は出力を戻す。
 * @param[in] request 入力identity、固定stream名、出力相対path。 入力identity、固定stream、出力path。
 * @param[in] policy MSI、stream、読取りbufferへ適用する有限上限。 MSI、stream、bufferの有限上限。
 * @param[in,out] workspace 初期化済みで出力fileを所有する保護workspace。 CREATE_NEW出力を所有する保護領域。
 * @param[out] entry 成功時のstream identity。失敗時は既定値。
 * @return 全検証、完全書込み、hash成功時は0、拒否またはAPI失敗時はHRESULT。 全検証、完全書込み、hash成功時は0、拒否時はHRESULT。
 * @note Windows Installer databaseをread-onlyで照会し、install sequenceを実行しない。
 */
[[nodiscard]] NativeError extractOfficialMsiStream(
	const OfficialMsiStreamExtractionRequest &request,
	const OfficialMsiStreamExtractionPolicy &policy, OfficialDownloadWorkspace &workspace,
	OfficialMsiStreamEntry &entry) ;

/**
 * @brief 取得済みMSIの固定embedded cabinetに属するfile mappingだけを照会する。
 * Mediaのsequence範囲だけをFile tableへparameter queryし、install sequenceやcustom actionを起動しない。
 * @param[in] request 入力identityと`Media.Cabinet`へ完全一致させるstream名。 入力MSI identityと固定stream名。
 * @param[in] policy MSI、file、row件数へ適用する有限上限。 MSI、file size、row件数の有限上限。
 * @param[out] inventory 成功時のstream名とSequence昇順file mapping。 成功時のMedia／File mapping。
 * @return 全table、mapping、入力identity検証成功時は0、拒否時はHRESULT。 Read-only照会と前後identity検証成功時は0、拒否時はHRESULT。
 * @note Read-only queryだけを実行し、install sequenceまたはcustom actionを起動しない。
 */
[[nodiscard]] NativeError inspectOfficialMsiCabinetInventory(
	const OfficialMsiCabinetInventoryRequest &request,
	const OfficialMsiCabinetInventoryPolicy &policy, OfficialMsiCabinetInventory &inventory) ;

} // namespace drivercrate
