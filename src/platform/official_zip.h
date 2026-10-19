//------------------------------------------------------------------------------
/**
 * @file official_zip.h
 * @brief 公式ZIP package安全展開定義。
 * @version 01.00.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定subdirectory選択展開追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  展開file SHA-256保持追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定file集合の選択展開追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 未信頼ZIPのpath traversal、重複名、reparse表現、暗号化、展開量超過を拒否して保護workspaceへ展開します。内容の真正性は呼出側が検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief 公式ZIPを解析および展開するときの有限上限を表す。
 */
struct OfficialZipExtractionPolicy {
	/// ZIP入力全体の最大byte数。
	std::uint64_t maximumArchiveBytes ;
	/// 一fileの展開後最大byte数。
	std::uint64_t maximumSingleFileBytes ;
	/// 全file合計の展開後最大byte数。
	std::uint64_t maximumTotalExpandedBytes ;
	/// Directoryを含むentry数上限。
	std::uint32_t maximumEntryCount ;
} ;

/**
 * @brief 検証済みZIP内の一つの通常fileを表す。
 */
struct OfficialZipEntry {
	/// Workspace基準の安全な`\\`区切り相対path。
	std::wstring  relativePath ;
	/// 展開後のbyte数。
	std::uint64_t uncompressedSize ;
	/// Scan後の差替えを検出する64桁小文字SHA-256。展開直後は空を許可する。
	std::wstring  sha256 ;
} ;

/**
 * @brief 公式ZIPの全entryと展開量を、fileを作成せず検証する。
 * 公式ZIPの全entryをfile作成なしで検証する。
 * 展開前preflightとしてpath、種別、圧縮方式、展開量を検証し、成功時だけimmutable相当の一覧を公開する。
 * @param[in] archive ZIP container全体。有効期間は本呼出し中に限る。 ZIP container全byte列。
 * @param[in] policy Providerが固定した入力、展開量、entry数上限。 Providerが固定した有限上限。
 * @param[out] entries 成功時の通常file一覧。Directory entryは含めない。
 * @return 成功時は0、形式不正、path不正、重複、上限超過時はHRESULT bit pattern。 全entryが安全なら0、不正形式または上限違反はHRESULT。
 * @note ASCII file名、storedまたはDeflate、単一disk archiveだけを受理する。
 */
[[nodiscard]] NativeError inspectOfficialZip( std::span<const std::byte>			archive,
											 const OfficialZipExtractionPolicy &policy,
											 std::vector<OfficialZipEntry>	   &entries) ;

/**
 * @brief 公式ZIPを事前検証し、全通常fileを保護workspaceへ展開する。
 * 公式ZIPを保護workspaceへ安全に展開する。
 * 全entryを事前検証後、CREATE_NEWしたfileへstream展開する。失敗時の部分fileはworkspace destructorが既知pathだけ除去する。
 * @param[in] archive ZIP container全体。有効期間は本呼出し中に限る。 ZIP container全byte列。
 * @param[in] policy Providerが固定した入力、展開量、entry数上限。 Providerが固定した有限上限。
 * @param[in,out] workspace 初期化済みで空の保護workspace。 初期化済みの保護workspace。
 * @param[out] entries 成功時に作成した通常file一覧。失敗時は空にする。
 * @return 成功時は0、検証、file作成、CRCまたは展開失敗時はHRESULT bit pattern。 全fileのCRC検証付き展開成功時は0、失敗時はHRESULT。
 * @note 本関数はZIPの真正性を保証しない。呼出側でhashまたは展開後署名を検証すること。
 */
[[nodiscard]] NativeError extractOfficialZip( std::span<const std::byte>			archive,
											 const OfficialZipExtractionPolicy &policy,
											 OfficialDownloadWorkspace		   &workspace,
											 std::vector<OfficialZipEntry>	   &entries) ;

/**
 * @brief ZIP全体を事前検証し、固定subdirectory内の通常fileだけを展開する。
 * 公式ZIPの固定subdirectoryだけを安全に展開する。
 * 選択外entryも事前検証するが、実行可能fileを含めfileを作成しない。
 * @param[in] archive ZIP container全体。有効期間は本呼出し中に限る。 ZIP container全byte列。
 * @param[in] policy ZIP全体へ適用する入力、展開量、entry数上限。 ZIP全体へ適用する有限上限。
 * @param[in] subdirectory ASCIIと`\\`で表す、末尾separatorなしの固定相対directory。 選択する固定ASCII相対directory。
 * @param[in,out] workspace 初期化済みで空の保護workspace。 初期化済みの保護workspace。
 * @param[out] entries 成功時に選択して作成した通常file一覧。失敗時は空にする。 成功時に作成した選択file一覧。
 * @return 全entryの事前検証と選択fileのCRC検証付き展開成功時は0。 ZIP全体と選択fileの検証・展開成功時は0。
 * @note 選択外entryも有限上限、path、重複、形式を検証するがfileを作成しない。
 */
[[nodiscard]] NativeError extractOfficialZipSubdirectory( std::span<const std::byte>			archive,
														 const OfficialZipExtractionPolicy &policy,
														 std::wstring_view			subdirectory,
														 OfficialDownloadWorkspace &workspace,
														 std::vector<OfficialZipEntry> &entries) ;

/**
 * @brief ZIP全体を事前検証し、固定相対pathの通常fileだけを展開する。
 * 公式ZIPの固定file集合だけを安全に展開する。
 * 選択外entryを事前検査だけに留め、fileとして作成しない。
 * @param[in] archive ZIP container全体。有効期間は本呼出し中に限る。 ZIP container全byte列。
 * @param[in] policy ZIP全体へ適用する入力、展開量、entry数上限。 ZIP全体へ適用する有限上限。
 * @param[in] selectedFiles 一件以上のASCII `\\`区切り相対file path。 選択する固定ASCII相対file path群。
 * @param[in,out] workspace 初期化済みで空の保護workspace。 選択fileを単独所有する保護workspace。
 * @param[out] entries 成功時に選択して作成した通常file一覧。失敗時は空にする。 成功時に作成した選択file一覧。
 * @return 全entryと固定pathの検証および選択fileのCRC検証付き展開成功時は0。 ZIP全体、選択集合、CRC検証付き展開の全成功時は0。
 * @note 選択pathの欠落、重複、不正pathをfile作成前にfail-closedで拒否する。
 */
[[nodiscard]] NativeError extractOfficialZipFiles( std::span<const std::byte>		 archive,
												  const OfficialZipExtractionPolicy &policy,
												  std::span<const std::wstring_view> selectedFiles,
												  OfficialDownloadWorkspace			&workspace,
												  std::vector<OfficialZipEntry>		&entries) ;

} // namespace drivercrate
