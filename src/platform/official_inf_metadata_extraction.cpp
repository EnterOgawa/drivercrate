//------------------------------------------------------------------------------
/**
 * @file official_inf_metadata_extraction.cpp
 * @brief 原ZIP／PEから全INFと署名補助CATを非実行抽出する。
 * @version 01.00.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  全選択metadataの共通有限抽出を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note 同期worker専用。危険な非選択も先行検査し、部分出力を返さない。
 * @see docs/adr/0278-sealed-inf-catalog-support.md
 */
//------------------------------------------------------------------------------
#include "platform/official_inf_metadata_extraction.h"
#include "platform/official_download_workspace.h"
#include "platform/official_pe_inf_extraction.h"

#include <Windows.h>
#include <cstdint>
#include <new>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::uint64_t MAX_INF_BYTES	   = 4ULL * 1024ULL * 1024ULL ;		// ZIP一INF上限。
constexpr std::uint64_t MAX_INF_TOTAL	   = 16ULL * 1024ULL * 1024ULL ;	// 全INF上限。
constexpr std::uint64_t MAX_CAT_BYTES	   = 32ULL * 1024ULL * 1024ULL ;	// 一CAT上限。
constexpr std::uint64_t MAX_METADATA_TOTAL = 64ULL * 1024ULL * 1024ULL ;	// 全metadata上限。

//------------------------------------------------------------------------------
/**
 * @brief 原名の有限suffixだけをordinal case非依存で識別する。
 * @param[in] name 全ZIP parserが検査した相対位置。
 * @param[in] suffix 四文字の固定suffix。
 * @return 同じsuffixならtrue。
 */
//------------------------------------------------------------------------------
bool					metadataSuffix( std::wstring_view name, std::wstring_view suffix) noexcept
{
	return name.size() >= suffix.size() &&
		   CompareStringOrdinal( name.data() + name.size() - suffix.size(),
								static_cast<int>( suffix.size()), suffix.data(),
								static_cast<int>( suffix.size()), TRUE) == CSTR_EQUAL ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 明示ZIP／PEの全INFと全CATを、原byteから同じ保護領域へ抽出する。
 * @param[in] raw 本呼出し中に不変の全container。ZIP128 MiB／PE64 MiBまで。
 * @param[in] format 明示形式。自動判定や拒否後のfallbackを行わない。
 * @param[in,out] workspace 初期化済み空領域。部分fileも同領域で追跡する。
 * @param[out] metadata 完全成功時だけ全INF／CATの原相対位置・実size・原hashを返す。
 * @return 完了0、形式・危険項目・容量・CRC・API・例外のHRESULT。
 * @pre 同期worker専用。入力storageは出力とaliasしない。
 * @post 失敗時のmetadataは空。部分fileはworkspaceで回収する。
 * @note INF64／個別ZIP4 MiB・PE1 MiB／合計16 MiB、CAT64／個別32 MiB、全metadata64 MiB。CATなしでもINF抽出は成功できる。SYS／DLL
 *       ／EXEは抽出・実行せず、署名は別に検査する。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialInfMetadata( std::span<const std::byte>	  raw,
									   OfficialInfContainerFormat	  format,
									   OfficialDownloadWorkspace	 &workspace,
									   std::vector<OfficialZipEntry> &metadata)
{
	metadata.clear() ;
	try {
		// PEは明示された場合だけ唯一表の全原範囲へ委譲する。
		if( format == OfficialInfContainerFormat::PE_FLAT_TABLE) {
			MaintenanceEmbeddedFileTable table ;	// 全表を検査する原範囲結果。
			return extractPeTableInfCatalogFiles( raw, workspace, metadata, table) ;
		}

		// 未定義形式をZIPとして扱わない。
		if( format != OfficialInfContainerFormat::ZIP) {
			return E_INVALIDARG ;
		}

		std::vector<OfficialZipEntry> entries ;											// 非選択を含む全宣言。
		auto error = inspectOfficialZip( raw, OFFICIAL_INF_ARCHIVE_POLICY, entries) ;	// 全先行検査。
		// 危険な全宣言を検査する前にfileを作らない。
		if( error != 0) {
			return error ;
		}

		std::vector<std::wstring_view> selected ;	// 全選択原位置の同期借用。
		std::size_t					   infs{} ;		// INF member数。最大64。
		std::size_t					   cats{} ;		// 補助CAT数。最大64。
		std::uint64_t				   infTotal{} ;	// 全INF byte。最大16 MiB。
		std::uint64_t				   total{} ;	// 全metadata byte。最大64 MiB。
		// 全INF／CATを選び、容量を抽出開始前に固定する。
		for( const auto &entry : entries) {
			const bool inf = metadataSuffix( entry.relativePath, L".inf") ;	// 導入名の開始member。
			const bool cat = metadataSuffix( entry.relativePath, L".cat") ;	// 署名補助だけ。
			// 実行fileや本体payloadを抽出しない。
			if( !inf && !cat) {
				continue ;
			}

			const std::uint64_t maximum = inf ? MAX_INF_BYTES : MAX_CAT_BYTES ;	// 個別上限。
			// 空・過大・過多・合計overflowを部分集合で成功させない。
			if( entry.uncompressedSize == 0U || entry.uncompressedSize > maximum ||
			   (inf && (infs >= 64U || entry.uncompressedSize > MAX_INF_TOTAL - infTotal)) ||
			   (cat && cats >= 64U) || entry.uncompressedSize > MAX_METADATA_TOTAL - total) {
				return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
			}

			infs += inf ;
			cats += cat ;
			infTotal += inf ? entry.uncompressedSize : 0U ;
			total += entry.uncompressedSize ;
			selected.push_back( entry.relativePath) ;
		}

		// CATだけを空INFの成功へ変換しない。
		if( infs == 0U) {
			return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
		}

		std::vector<OfficialZipEntry> extracted ;	// 全成功まで公開しない原metadata。
		error = extractOfficialZipFiles( raw, OFFICIAL_INF_ARCHIVE_POLICY, selected, workspace,
										extracted) ;
		// 一つでも欠けた全選択を成功にしない。
		if( error != 0 || extracted.size() != selected.size()) {
			return error != 0 ? error : E_UNEXPECTED ;
		}

		metadata = std::move( extracted) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		metadata.clear() ;
		return E_OUTOFMEMORY ;
	} catch( ...) {
		metadata.clear() ;
		return E_UNEXPECTED ;
	}
}
} // namespace drivercrate
