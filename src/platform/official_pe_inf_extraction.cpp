//------------------------------------------------------------------------------
/**
 * @file official_pe_inf_extraction.cpp
 * @brief PE内全表を検査し、INFと署名補助CATを原範囲から保護抽出する。
 * @version 01.01.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  既存PE parserから全INFを原byteで複写する。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  有限CAT補助抽出を追加し旧INF-onlyを維持。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 同期worker専用。元PEや実行可能memberを実行・loadしない。
 * @see docs/adr/0275-sealed-pe-inf-range-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_pe_inf_extraction.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
constexpr std::size_t MAX_INF_BYTES		 = 1024U * 1024U ;			// 既存PE parserと同じ一INF上限。
constexpr std::size_t MAX_INF_TOTAL		 = 16U * 1024U * 1024U ;	// 所有adapterと同じ合計上限。
constexpr std::size_t MAX_CAT_BYTES		 = 32U * 1024U * 1024U ;	// 一署名補助CATの上限。
constexpr std::size_t MAX_METADATA_TOTAL = 64U * 1024U * 1024U ;	// INF＋CATの合計上限。

/** @brief 部分書込でも所有handleを回収する。 */
struct PeInfHandleCloser {
	/** @brief 有効な所有handleを閉じる。
	 * @param[in] value Workspaceから所有を受け取ったfile handle。
	 */
	void operator()( void *value) const noexcept
	{
		// 未取得または失敗handleを閉じない。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief Fileのscope所有型。
 */
using PeInfHandle = std::unique_ptr<void, PeInfHandleCloser> ;

/** @brief 検査済みflat名からcase非依存のINFだけを識別する。
 * @param[in] name Parserが検査したASCII名。
 * @return INF suffixだけならtrue。
 */
bool isPeInfName( std::string_view name) noexcept
{
	// Suffixより短い名を末尾参照しない。
	if( name.size() < 4U) {
		return false ;
	}

	const auto suffix = name.substr( name.size() - 4U) ;	// 最大四byteの借用。
	return suffix[0] == '.' && (suffix[1] == 'i' || suffix[1] == 'I') &&
		   (suffix[2] == 'n' || suffix[2] == 'N') && (suffix[3] == 'f' || suffix[3] == 'F') ;
}

/** @brief 検査済みflat名からcase非依存のCATを識別する。
 * @param[in] name Parserが検査したASCII名。
 * @return CAT suffixだけならtrue。
 */
bool isPeCatName( std::string_view name) noexcept
{
	// Suffixより短い名を末尾参照しない。
	if( name.size() < 4U) {
		return false ;
	}

	const auto suffix = name.substr( name.size() - 4U) ;	// 四byteの同期借用。
	return suffix[0] == '.' && (suffix[1] == 'c' || suffix[1] == 'C') &&
		   (suffix[2] == 'a' || suffix[2] == 'A') && (suffix[3] == 't' || suffix[3] == 'T') ;
}

/** @brief 原範囲の全byteを新fileへ保存し、共通size／hashへ一致させる。
 * @param[in] body 呼出し側が全表と個別上限を検査した32 MiB以下の原metadata。
 * @param[in] name 検査済みflat相対名。
 * @param[in,out] workspace 新fileを単独追跡する領域。
 * @param[out] entry 成功時だけ原sizeとSHA-256を保持する。
 * @return 完了0、hash・file作成・書込・close・再照合のHRESULT。
 */
NativeError copyPeMetadataRange( std::span<const std::byte> body, const std::wstring &name,
								OfficialDownloadWorkspace &workspace, OfficialZipEntry &entry)
{
	std::wstring hash ;	// 原byteから計算する共通SHA-256。
	// Byte列とchar列の同じ表現を、共通CNG境界への同期借用だけに使用する。
	auto		 error = computeDriverContainerSha256(
		std::string_view( reinterpret_cast<const char *>( body.data()), body.size()), hash) ;
	// 原hashを作れなければfileを作成しない。
	if( error != 0) {
		return error ;
	}

	HANDLE created = INVALID_HANDLE_VALUE ;	// Workspaceから所有を受け取るhandle。
	error		   = workspace.createFile( name, created) ;
	// 衝突や保護失敗を既存fileの上書きへfallbackしない。
	if( error != 0) {
		return error ;
	}

	PeInfHandle file( created) ;	// 全失敗経路でもwriterを回収する。
	DWORD		written{} ;			// 保存した実byte数。
	// 元のfile範囲だけを一回の有限writeで複写する。
	if( !WriteFile( file.get(), body.data(), static_cast<DWORD>( body.size()), &written, nullptr)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	// Short writeは元byteの取得成功にしない。
	if( written != body.size()) {
		return HRESULT_FROM_WIN32( ERROR_WRITE_FAULT) ;
	}

	// Writerのcloseが成功した場合だけ別read handleの再照合へ進む。
	if( !CloseHandle( file.get())) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	(void)file.release() ;
	error = verifyOfficialFileMetadata( workspace.path( name), {body.size(), hash}) ;
	// 実保存byteまで一致してから固定metadataを公開する。
	if( error == 0) {
		entry = {name, body.size(), std::move( hash)} ;
	}

	return error ;
}
/** @brief 共通の原範囲抽出で旧INF-onlyとCAT補助選択を扱う。
 * @param[in] executable 不変の全PE byte。
 * @param[in,out] workspace 抽出fileを追跡する初期化済み空領域。
 * @param[out] entries 完全成功時だけ全選択metadataを返す。
 * @param[out] table 完全成功時だけ原表を返す。
 * @param[in] catalogs trueなら全CATも選び、falseなら旧INF-only予算を維持する。
 * @return 完了0、元parser・容量・API・例外のHRESULT。
 * @note 選択boolは私有の抽出形式だけで、認証・署名許可ではない。
 */
NativeError extractPeMetadata( std::span<const std::byte>	 executable,
							  OfficialDownloadWorkspace		&workspace,
							  std::vector<OfficialZipEntry> &entries,
							  MaintenanceEmbeddedFileTable &table, bool catalogs)
{
	entries.clear() ;
	table = {} ;
	try {
		MaintenanceEmbeddedFileTable parsed ;									// 全表の元範囲を私有の一時結果へ保持する。
		auto error = inspectMaintenanceEmbeddedFileTable( executable, parsed) ;	// 全表の元診断。
		// 危険な非選択fileも全表で拒否してからINFを選ぶ。
		if( error != 0) {
			return error ;
		}

		std::size_t		  count{} ;		// 全選択metadata数。最大128。
		std::size_t		  infs{} ;		// 全INF数。最大64。
		std::size_t		  cats{} ;		// 全CAT数。最大64。
		std::size_t		  infTotal{} ;	// 全INFの原byte合計。
		std::size_t		  total{} ;		// 全選択metadataの原byte合計。
		const std::size_t totalLimit =
			catalogs ? MAX_METADATA_TOTAL : MAX_INF_TOTAL ;	// 旧予算を維持。
		// 全原範囲と抽出集合の容量をfile作成前に確認する。
		for( const auto &member : parsed.files) {
			const bool inf = isPeInfName( member.name) ;				// INFだけを開始memberにする。
			const bool cat = catalogs && isPeCatName( member.name) ;	// 補助CATは別予算。
			// 選択外はmemoryの全表検査だけに留める。
			if( !inf && !cat) {
				continue ;
			}

			const std::size_t maximum = inf ? MAX_INF_BYTES : MAX_CAT_BYTES ;	// 個別byte上限。
			// 切断・過大・過多を部分集合で受理しない。
			if( member.bytes == 0U || member.bytes > maximum ||
			   (inf && (infs >= 64U || member.bytes > MAX_INF_TOTAL - infTotal)) ||
			   (cat && cats >= 64U) || member.bytes > totalLimit - total ||
			   member.offset > executable.size() ||
			   member.bytes > executable.size() - member.offset) {
				return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
			}

			++count ;
			infs += inf ;
			cats += cat ;
			infTotal += inf ? member.bytes : 0U ;
			total += member.bytes ;
		}

		// INFなしを空の成功集合へ昇格させない。
		if( infs == 0U) {
			return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
		}

		std::vector<OfficialZipEntry> captured ;	// 全成功まで外部へ出さない実metadata。
		captured.reserve( count) ;
		// 全表内の選択metadataを宣言順で原範囲からだけ抽出する。
		for( const auto &member : parsed.files) {
			// 旧入口ではCATも除外し、両入口で実行memberを展開しない。
			if( !isPeInfName( member.name) && !(catalogs && isPeCatName( member.name))) {
				continue ;
			}

			const std::wstring name( member.name.begin(),
									// ParserがASCIIを検証済みの原名。
									member.name.end()) ;
			OfficialZipEntry   entry ;	// 本memberの実byte metadata。
			error = copyPeMetadataRange( executable.subspan( member.offset, member.bytes), name,
										workspace, entry) ;
			// 一つでも失敗したら全結果を空のまま保持する。
			if( error != 0) {
				return error ;
			}

			captured.push_back( std::move( entry)) ;
		}

		entries = std::move( captured) ;
		table	= std::move( parsed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		table = {} ;
		return E_OUTOFMEMORY ;
	} catch( ...) {
		entries.clear() ;
		table = {} ;
		return E_UNEXPECTED ;
	}
}
} // namespace

NativeError extractPeTableInfFiles( std::span<const std::byte>	  executable,
								   OfficialDownloadWorkspace	 &workspace,
								   std::vector<OfficialZipEntry> &entries,
								   MaintenanceEmbeddedFileTable	 &table)
{
	return extractPeMetadata( executable, workspace, entries, table, false) ;
}

NativeError extractPeTableInfCatalogFiles( std::span<const std::byte>	 executable,
										  OfficialDownloadWorkspace		&workspace,
										  std::vector<OfficialZipEntry> &entries,
										  MaintenanceEmbeddedFileTable	&table)
{
	return extractPeMetadata( executable, workspace, entries, table, true) ;
}
} // namespace drivercrate
