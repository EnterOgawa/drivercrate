//------------------------------------------------------------------------------
/**
 * @file indexed_driver_package_smoke.cpp
 * @brief 取得済み原archiveを索引hintから通常検査へ非導入接続する。
 * @version 01.00.00
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  索引hintと通常検査の非導入接続を追加。
 * </pre>
 *
 * @note 明示local入力だけを使用する。実行・staging・PnP列挙・driver HTTPを行わず、path・IDを出力しない。
 * @see docs/adr/0262-index-hint-to-acquired-package-inspection.md
 */
//------------------------------------------------------------------------------

#include "platform/com_raii.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

/**
 * @brief 有限の十進byte数を解析する。
 * @param[in] text CLIの期待byte数。先頭0・符号を許可しない。
 * @param[out] bytes 成功時の1～128 MiB。失敗時は0。
 * @return 形式と予算が有効ならtrue。
 */
bool parseBytes( const std::wstring_view text, std::uint64_t &bytes) noexcept
{
	constexpr std::uint64_t MAXIMUM = 128ULL * 1024ULL * 1024ULL ;	// 通常入力と同じ上限。
	bytes							= 0 ;
	// 任意桁数・先頭0を受理しない。
	if( text.empty() || text.size() > 9 || text.front() == L'0') {
		return false ;
	}

	std::uint64_t parsed{} ;	// 成功までoutへ出さない有限値。
	// Overflow前に上限を確認する。
	for( const wchar_t digit : text) {
		// 数字以外と乗算overflowを拒否する。
		if( digit < L'0' || digit > L'9' || parsed > (MAXIMUM - (digit - L'0')) / 10) {
			return false ;
		}

		parsed = parsed * 10 + (digit - L'0') ;
	}

	bytes = parsed ;
	return bytes != 0 ;
}

/**
 * @brief 検査済み小文字hashだけをASCIIへ変換する。
 * @param[in] hash 小文字64桁で検証済みのhint値。
 * @return JSONへ安全に出せるASCII hash。
 * @pre matchesIndexedDriverArchiveHintを通過済みである。
 */
std::string narrowHash( const std::wstring_view hash)
{
	std::string result ;	// 任意pathを変換する用途に使わない。
	// 既に検査済みのASCII文字をそのまま転記する。
	for( const wchar_t digit : hash) {
		result.push_back( static_cast<char>( digit)) ;
	}

	return result ;
}

/**
 * @brief 有限終端状態を固定文字列へ変換する。
 * @param[in] state 通常入口の到達状態。
 * @return JSON用の固定識別子。
 */
const char *stateName( const drivercrate::IndexedDriverInspectionState state) noexcept
{
	// 有限状態以外は合格へ変換しない。
	switch( state) {
		case drivercrate::IndexedDriverInspectionState::INPUT_REJECTED:	// 入力拒否。
			return "INPUT_REJECTED" ;
		case drivercrate::IndexedDriverInspectionState::CANCELLED:	// 明示取消し。
			return "CANCELLED" ;
		case drivercrate::IndexedDriverInspectionState::INSPECTION_FAILED:	// 全体検査失敗。
			return "INSPECTION_FAILED" ;
		case drivercrate::IndexedDriverInspectionState::INSPECTION_COMPLETED:	// 合格0件も完了。
			return "INSPECTION_COMPLETED" ;
		default:	// 未開始・未知状態を成功としない。
			return "NOT_STARTED" ;
	}
}

/**
 * @brief 固定metadataと件数だけを出力する。
 * @param[in] hint 構文検査済みの期待identity。
 * @param[in] result 非導入検査結果。内容合格と検査完了は独立。
 * @return JSON出力とflushに成功した場合true。
 */
bool emitResult( const drivercrate::IndexedDriverArchiveHint		  &hint,
				const drivercrate::IndexedDriverPackageInspection &result)
{
	std::size_t verified{} ;			// 合格した通常INFだけの数。
	std::size_t closureRejected{} ;		// 閉包policy拒否。
	std::size_t signatureRejected{} ;	// 実署名拒否。
	std::string errors ;				// 個別元HRESULTだけを保持する。
	// 各INFの拒否段階を数え、path・表示名・IDを出さない。
	for( const drivercrate::CommonInfInspection &inf : result.inspection.infs) {
		// 署名合格・静的拒否・署名拒否を独立に集計する。
		switch( inf.state) {
			case drivercrate::CommonInfInspectionState::VERIFIED:	// 通常内容署名の合格。
				++verified ;
				break ;

			case drivercrate::CommonInfInspectionState::CLOSURE_REJECTED:	// 静的拒否。
				++closureRejected ;
				break ;

			case drivercrate::CommonInfInspectionState::SIGNATURE_REJECTED:	// 実署名拒否。
				++signatureRejected ;
				break ;

			default:	// 未定義状態を既知の拒否または合格へ変換しない。
				return false ;
		}

		// JSONの区切りだけを挿入する。
		if( !errors.empty()) {
			errors += ',' ;
		}

		errors += std::to_string( inf.error) ;
	}

	const std::string output =
		"{\"schema\":\"dc-indexed-common-package-inspection-v1\",\"researchOnly\":true,"
		"\"publishable\":false,\"installAuthorized\":false,\"applicability\":\"NOT_CHECKED\","
		"\"indexSha256\":\"" +
		narrowHash( hint.indexSha256) + "\",\"recordSha256\":\"" + narrowHash( hint.recordSha256) +
		"\",\"archiveSha256\":\"" + narrowHash( hint.archiveSha256) +
		"\",\"archiveBytes\":" + std::to_string( hint.archiveBytes) +
		",\"inputBound\":" + (result.inputBound ? "true" : "false") + ",\"state\":\"" +
		stateName( result.state) + "\",\"error\":" + std::to_string( result.error) +
		",\"inventoryFileCount\":" + std::to_string( result.inspection.inventoryFileCount) +
		",\"infCount\":" + std::to_string( result.inspection.infs.size()) +
		",\"verifiedInfCount\":" + std::to_string( verified) +
		",\"closureRejectedInfCount\":" + std::to_string( closureRejected) +
		",\"signatureRejectedInfCount\":" + std::to_string( signatureRejected) + ",\"infErrors\":[" +
		errors + "]}\n" ;	// Byte・段階・件数だけの研究観測。
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ;
}

} // namespace

/**
 * @brief 明示取得済み原archiveを保護copyして通常検査へ渡す。
 * @param[in] argc 実行名を含む引数数。6だけを受理する。
 * @param[in] argv 元path・索引hash・record hash・archive hash・byte数。
 * @return 検査完了0、全体検査失敗1、不正引数または出力失敗2。
 * @note 元fileと展開物を実行せず、network・導入・復旧APIを開始しない。
 */
int wmain( const int argc, wchar_t **argv)
{
	// 任意引数をechoせず拒否する。
	if( argc != 6) {
		return 2 ;
	}

	try {
		constexpr drivercrate::ScanSessionId  SESSION = 6301U ;						// 明示一回だけのsession。
		drivercrate::IndexedDriverArchiveHint hint{argv[2], argv[3], argv[4], 0} ;	// CLI期待値。
		// 有限size以外をcopy入口へ渡さない。
		if( !parseBytes( argv[5], hint.archiveBytes)) {
			return 2 ;
		}

		const drivercrate::DriverArchiveInput expected{SESSION, argv[1], hint.archiveBytes,
													   hint.archiveSha256} ;	// 非I/Oの構文確認。
		// 不正hashやpathを出力・copyしない。
		if( !drivercrate::matchesIndexedDriverArchiveHint(
			   SESSION, hint, expected, drivercrate::OfficialDriverArchiveFormat::ZIP)) {
			return 2 ;
		}

		const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// 署名API用の同一MTA。
		// COM失敗では検査を開始しない。
		if( FAILED( apartment.result())) {
			return 1 ;
		}

		drivercrate::OfficialDownloadWorkspace		workspace ;	// 終了まで原copyを所有する。
		drivercrate::DriverArchiveInput				input ;		// 保護copyが確定する実identity。
		drivercrate::OfficialDriverArchiveFormat	format{} ;	// 既存copyが確定するZIPまたはCAB。
		drivercrate::IndexedDriverPackageInspection result ;	// 通常結果の単独所有者。
		const drivercrate::NativeError				copyError = drivercrate::copyLocalDriverArchive(
			 argv[1], SESSION, workspace, input, format) ;	// 既存の共通取得済み入力入口。
		// Copy失敗を元file直読みで回避しない。
		if( copyError != 0) {
			result.state = drivercrate::IndexedDriverInspectionState::INPUT_REJECTED ;
			result.error = copyError ;
		} else {
			result.error =
				drivercrate::inspectIndexedDriverPackage( SESSION, hint, input, format, result) ;
		}

		// 部分JSONを完了証拠にしない。
		if( !emitResult( hint, result)) {
			return 2 ;
		}

		return result.state == drivercrate::IndexedDriverInspectionState::INSPECTION_COMPLETED ? 0
																							   : 1 ;
	} catch( ...) {
		// CLI例外もpath・秘密を出さず失敗を返す。
		std::fprintf( stderr, "Inspection runner failed\n") ;
		return 2 ;
	}
}
