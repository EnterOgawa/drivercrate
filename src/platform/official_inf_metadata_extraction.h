//------------------------------------------------------------------------------
/**
 * @file official_inf_metadata_extraction.h
 * @brief ZIP／PEの全INFと署名補助CATを共通の有限境界で抽出する。
 * @version 01.00.00
 * @date 2026/10/06
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  非実行のINF／CAT共通抽出契約を追加。
 * </pre>
 *
 * @note 同期worker専用。抽出は認証・署名合格・導入許可を発行しない。
 * @see docs/adr/0278-sealed-inf-catalog-support.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_zip.h"

#include <cstddef>
#include <span>
#include <vector>

namespace drivercrate {
class OfficialDownloadWorkspace ;

/** @brief 最終fileの形式を明示し、失敗時の自動fallbackを禁止する。 */
enum class OfficialInfContainerFormat {
	/// 全entryを既存ZIP parserで検査する既定形式。
	ZIP,
	/// PE32+ x64 readonly dataの有限flat-table。一般EXE対応ではない。
	PE_FLAT_TABLE,
} ;

// 元封印経路と同じ全ZIP宣言予算。INF／CAT実抽出は別の小さい予算で検査する。
inline constexpr OfficialZipExtractionPolicy OFFICIAL_INF_ARCHIVE_POLICY{
	128ULL * 1024ULL * 1024ULL, 128ULL * 1024ULL * 1024ULL, 512ULL * 1024ULL * 1024ULL, 8192U} ;

/**
 * @brief 明示ZIP／PEの全INFと全CATを、原byteから同じ保護領域へ抽出する。
 * @param[in] raw 本呼出し中に不変の全container。ZIP128 MiB／PE64 MiBまで。
 * @param[in] format 明示形式。自動判定や拒否後のfallbackを行わない。
 * @param[in,out] workspace 初期化済み空領域。部分fileも同領域で追跡する。
 * @param[out] metadata 完全成功時だけ全INF／CATの原相対位置・実size・原hashを返す。
 * @return 完了0、形式・危険項目・容量・CRC・API・例外のHRESULT。
 * @pre 同期worker専用。入力storageは出力とaliasしない。
 * @post 失敗時のmetadataは空。部分fileはworkspaceで回収する。
 * @note INF64／個別ZIP4 MiB・PE1 MiB／合計16 MiB、CAT64／個別32 MiB、全metadata64 MiB。
 * CATなしでもINF抽出は成功できる。SYS／DLL／EXEは抽出・実行せず、署名は別に検査する。
 */
[[nodiscard]] NativeError extractOfficialInfMetadata( std::span<const std::byte>		raw,
													 OfficialInfContainerFormat		format,
													 OfficialDownloadWorkspace	   &workspace,
													 std::vector<OfficialZipEntry> &metadata) ;
} // namespace drivercrate
