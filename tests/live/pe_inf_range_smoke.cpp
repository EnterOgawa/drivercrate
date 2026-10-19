//------------------------------------------------------------------------------
/**
 * @file pe_inf_range_smoke.cpp
 * @brief 明示local PEの全INF原範囲と抽出byteを非実行観測する。
 * @version 01.00.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  原PEと全INFのhash限定測定器を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/06  ReadFile失敗とshort readの診断を分離。
 * Ver.01.00.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Localの実byte結合だけを測る。公式sessionの証拠や署名・導入許可を発行しない。
 * @see docs/adr/0275-sealed-pe-inf-range-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_pe_inf_extraction.h"
#include "platform/official_file_verifier.h"
#include "platform/official_download_workspace.h"
#include "platform/inf_dependency_native.h"

#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {
/** @brief Scope内だけのread handleを回収する。 */
struct RangeHandleCloser {
	/** @brief 有効なhandleを閉じる。
	 * @param[in] value 所有するread handle。
	 */
	void operator()( void *value) const noexcept
	{
		// 未取得や失敗値をAPIへ渡さない。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief 原fileのread-only所有。
 */
using RangeHandle = std::unique_ptr<void, RangeHandleCloser> ;

/** @brief 外部文字列を出さず、元診断だけの全体拒否を表示する。
 * @param[in] error 元HRESULT。
 * @return 拒否の終了値2。
 */
int rejectRange( drivercrate::NativeError error)
{
	std::cout << "{\"state\":\"REJECTED\",\"error\":" << error << "}\n" ;
	return 2 ;
}

/** @brief 64桁小文字SHA-256だけを識別する。
 * @param[in] value 引数または共通hashの結果。
 * @return 小文字ASCII64桁ならtrue。
 */
bool validRangeHash( std::wstring_view value) noexcept
{
	return value.size() == 64U && std::ranges::all_of( value, []( wchar_t character) {
			   // 公開hash以外の文字列を出力へ渡さない。
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'a' && character <= L'f') ;
		   }) ;
}

/** @brief 検証済みhashだけを出力用ASCIIへ変換する。
 * @param[in] value 小文字ASCII64桁。
 * @return 同じhex列。
 */
std::string narrowRangeHash( std::wstring_view value)
{
	std::string result ;	// 検証済みASCII hexだけの出力。
	// 64桁のASCII値だけを明示的に狭め、Unicode文字列の汎用変換にしない。
	for( const auto character : value) {
		result.push_back( static_cast<char>( character)) ;
	}

	return result ;
}

/** @brief 明示local PEを固定handleと元hashへ結合して全INFだけを観測する。
 * @param[in] count 四個だけのOS引数数。
 * @param[in] arguments 原path・期待hash・期待size。呼出し中だけ借用する。
 * @return 全成功0、拒否2。
 * @note Source authenticationと署名を検査せず、結果はNOT_CHECKEDに固定する。
 */
int observePeRanges( int count, wchar_t **arguments)
{
	// 実行commandや余分な操作指定を受け付けない。
	if( count != 4) {
		return rejectRange( E_INVALIDARG) ;
	}

	const std::wstring		path( arguments[1]) ;		// 明示local原PEだけの位置。
	const std::wstring		hash( arguments[2]) ;		// 研究用期待値。認証能力はない。
	const std::wstring_view decimal( arguments[3]) ;	// 64 MiB以内の期待size。
	std::uint64_t			expected{} ;				// 解析する正の期待byte数。
	// 通常DOS位置とhashの有限構文を先に確認する。
	if( !drivercrate::validInfDependencyPath( path, true) || !validRangeHash( hash) ||
	   decimal.empty() || decimal.size() > 8U) {
		return rejectRange( E_INVALIDARG) ;
	}

	// 各桁を上限内で解析し、signedや空白を許容しない。
	for( const auto character : decimal) {
		// 非十進表現を暗黙補正しない。
		if( character < L'0' || character > L'9') {
			return rejectRange( E_INVALIDARG) ;
		}

		expected = expected * 10U + static_cast<std::uint64_t>( character - L'0') ;
	}

	// 0とparser上限超過をmemory確保前に拒否する。
	if( expected == 0U || expected > 64ULL * 1024ULL * 1024ULL) {
		return rejectRange( E_INVALIDARG) ;
	}

	RangeHandle file( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
								 OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
								 nullptr)) ;	// Writer・削除と共有しない。
	// Open失敗を元HRESULTで保持する。
	if( file.get() == INVALID_HANDLE_VALUE) {
		return rejectRange( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	BY_HANDLE_FILE_INFORMATION information{} ;	// 通常leafとsizeを同じhandleで確認する。
	// Reparseやdirectoryを原PEにしない。
	if( GetFileType( file.get()) != FILE_TYPE_DISK ||
	   !GetFileInformationByHandle( file.get(), &information) ||
	   (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0U) {
		return rejectRange( E_INVALIDARG) ;
	}

	auto error = drivercrate::verifyOfficialFileMetadata(
		path, {expected, hash}) ;	// 元byte identityだけの共通照合。
	// 期待byte不一致では構造検査へ進まない。
	if( error != 0) {
		return rejectRange( error) ;
	}

	std::vector<std::byte> raw( static_cast<std::size_t>( expected)) ;	// 固定sizeの原memory。
	std::size_t			   offset{} ;									// 読取済みbyte数。
	// 同じhandleから全byteを有限chunkで読み取る。
	while( offset < raw.size()) {
		const DWORD requested =
			// 一chunk上限。
			static_cast<DWORD>( std::min<std::size_t>( 65536U, raw.size() - offset)) ;
		DWORD received{} ;	// 実際に受け取ったbyte数。
		// API失敗の元Win32 errorをshort readの診断へ丸めない。
		if( !ReadFile( file.get(), raw.data() + offset, requested, &received, nullptr)) {
			return rejectRange( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		// API成功でも全byteを受け取っていない場合は部分取得を拒否する。
		if( received != requested) {
			return rejectRange( HRESULT_FROM_WIN32( ERROR_READ_FAULT)) ;
		}

		offset += received ;
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// 抽出INFだけを所有する新領域。
	error = workspace.initialize( L"pe-range-observation", 8501U) ;
	drivercrate::MaintenanceEmbeddedFileTable  table ;		// 全表の原範囲。公式由来ではない。
	std::vector<drivercrate::OfficialZipEntry> entries ;	// 抽出全INFの原byte metadata。
	// 保護領域を確保してから元memoryの全表を検査する。
	if( error == 0) {
		error = drivercrate::extractPeTableInfFiles( raw, workspace, entries, table) ;
	}

	// 構造か抽出の一失敗でも部分観測を出さない。
	if( error != 0) {
		return rejectRange( error) ;
	}

	error = drivercrate::verifyOfficialFileMetadata(
		path, {expected, hash}) ;	// 出力前にも原fileを再確認する。
	// 原PEの固定byteと全抽出の両方が成功してからJSONを作る。
	if( error != 0) {
		return rejectRange( error) ;
	}

	std::string rows ;	// 名前をhashへ置換した全INFの出力行。
	// 抽出全INFを元表の原相対名と一意に結合する。
	for( const auto &entry : entries) {
		const auto source = std::ranges::find_if( table.files, [&entry]( const auto &member) {
			// Parserが重複を拒否した原名のまま照合する。
			return std::wstring( member.name.begin(), member.name.end()) == entry.relativePath ;
		}) ; // この元表内だけの原範囲。
		// 結合不能を新しい範囲の推測で救済しない。
		if( source == table.files.end() || source->bytes != entry.uncompressedSize ||
		   !validRangeHash( entry.sha256)) {
			return rejectRange( E_UNEXPECTED) ;
		}

		std::wstring nameHash ;	// 原ASCII名の非秘密identity。
		error = drivercrate::computeBytesSha256( source->name, nameHash) ;
		// 名hashを作れなければ原名をそのまま出さない。
		if( error != 0) {
			return rejectRange( error) ;
		}

		rows += (rows.empty() ? "" : ",") + std::string( "{\"nameSha256\":\"") +
				narrowRangeHash( nameHash) + "\",\"offset\":" + std::to_string( source->offset) +
				",\"bytes\":" + std::to_string( source->bytes) + ",\"sha256\":\"" +
				narrowRangeHash( entry.sha256) + "\"}" ;
	}

	std::cout
		<< "{\"schema\":\"dc-pe-inf-range-observation-v1\",\"researchOnly\":true,"
		   "\"publishable\":false,\"installAuthorized\":false,\"officialProvenance\":\"NOT_CHECKED\","
		   "\"byteBound\":true,\"sourceSha256\":\""
		<< narrowRangeHash( hash) << "\",\"sourceBytes\":" << expected
		<< ",\"tableOffset\":" << table.tableOffset << ",\"blobOffset\":" << table.blobOffset
		<< ",\"blobBytes\":" << table.blobBytes << ",\"tableFileCount\":" << table.files.size()
		<< ",\"infCount\":" << entries.size() << ",\"nonInfFilesExtracted\":0,\"infs\":[" << rows
		<< "]}\n" ;
	return std::cout.good() ? 0 : 2 ;
}
} // namespace

/** @brief 明示local入力だけでhash限定の非導入観測を実行する。
 * @param[in] count OS引数数。
 * @param[in] arguments 本呼出し中だけ借用するOS引数。
 * @return 全成功0、入力・検査・例外の拒否2。
 */
int wmain( int count, wchar_t **arguments)
{
	try {
		return observePeRanges( count, arguments) ;
	} catch( ...) {
		// Raw pathや本文を出さず、例外を全体拒否として保持する。
		return rejectRange( E_UNEXPECTED) ;
	}
}
