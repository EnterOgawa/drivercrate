//------------------------------------------------------------------------------
/**
 * @file acquired_inf_dependency_smoke.cpp
 * @brief 保護ZIPの選択INFと実Windows参照を非実行で結合する独立測定器。
 * @version 01.05.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  取得済みINFの有限非実行依存測定を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  独立targetだけで空取得根拠の拒否観測を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/06  独立targetで共通ZIP／PE metadataを実測。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  明示live targetで実取得と封印nativeを接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  別targetで全内側ZIPの有限明示計画を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/06  収集共通scopeからZIP／明示PEの生存測定を接続。
 * </pre>
 *
 * @note CLI内だけで同期所有し、raw path・ID・commandを出力しない。
 *       Local入力はPackage由来未検査。明示live分岐も作用・実device適合・導入許可を認定しない。
 * @see docs/adr/0272-acquired-inf-native-dependency-observation.md
 */
//------------------------------------------------------------------------------

#include "platform/common_driver_package.h"
#include "platform/inf_dependency_native.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_zip.h"
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
#include "platform/official_inf_metadata_extraction.h"
#endif
#if defined( DRIVERCRATE_UNTRUSTED_INF_PROBE) || defined( DRIVERCRATE_LIVE_SEALED_INF_PROBE)
#include "platform/official_inf_archive_binding.h"
#endif
#ifdef DRIVERCRATE_LIVE_SEALED_INF_PROBE
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/official_acquisition.h"
#include "platform/official_http_client.h"
#include "platform/official_inf_metadata_extraction.h"
#include "platform/official_release_metadata.h"
#endif
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
#include "platform/collector_inspection_acquisition.h"
#endif

#include <Windows.h>
#include <SetupAPI.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES = 128ULL * 1024ULL * 1024ULL ;	// 共通入力上限。
constexpr drivercrate::OfficialZipExtractionPolicy ZIP_POLICY{
	MAXIMUM_ARCHIVE_BYTES, MAXIMUM_ARCHIVE_BYTES, 256ULL * 1024ULL * 1024ULL, 4096U} ;	// 固定予算。

/**
 * @brief 小文字64桁のhashを非秘密のASCII識別子へ検証する。
 * @param[in] value 元byteまたはINFの期待hash。
 * @return 64桁の小文字hexならtrue。
 */
bool validHash( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::ranges::all_of( value, []( const wchar_t digit) {
			   // ASCII hexの有限文字集合だけを受理する。
			   return (digit >= L'0' && digit <= L'9') || (digit >= L'a' && digit <= L'f') ;
		   }) ;
}

/**
 * @brief 検証済みhashを出力用ASCIIへ変換する。
 * @param[in] value 空または小文字64桁の内部hash。
 * @return 元hashと同じASCII列。
 * @pre 外部pathや未検証の文字列を渡さない。
 */
std::string narrowHash( const std::wstring_view value)
{
	std::string result ;	// 検証済みASCIIだけの有限出力。
	// 小文字hexの範囲が既知なので明示変換し、暗黙narrowingを行わない。
	for( const wchar_t digit : value) {
		result.push_back( static_cast<char>( digit)) ;
	}

	return result ;
}

/**
 * @brief 有限で正規な十進sizeを読む。
 * @param[in] text 先頭0のない十進CLI値。
 * @param[out] bytes 成功時の1～128 MiB、失敗時は0。
 * @return 全桁が有限入力条件を満たす場合true。
 */
bool parseBytes( const std::wstring_view text, std::uint64_t &bytes) noexcept
{
	bytes = 0 ;
	// 空・先頭0・過長を暗黙補正しない。
	if( text.empty() || text.size() > 9U || text.front() == L'0') {
		return false ;
	}

	std::uint64_t parsed{} ;	// 最終成功まで公開しない有限byte数。
	// 乗算前に入力上限を確認する。
	for( const wchar_t digit : text) {
		// 数字以外とoverflowを拒否する。
		if( digit < L'0' || digit > L'9' ||
		   parsed > (MAXIMUM_ARCHIVE_BYTES - (digit - L'0')) / 10U) {
			return false ;
		}

		parsed = parsed * 10U + (digit - L'0') ;
	}

	bytes = parsed ;
	return parsed != 0 ;
}

/**
 * @brief 保護copyの有限原byteを読む。
 * @param[in] input 既存copy層が所有する不変入力。
 * @param[out] bytes 完全読取り成功時だけ保持する原byte。
 * @return 完全読取り成功0、失敗はHRESULT。
 */
drivercrate::NativeError readArchive( const drivercrate::DriverArchiveInput &input,
									 std::vector<char>					   &bytes)
{
	bytes.clear() ;
	std::ifstream	  stream( std::filesystem::path( input.inspectionPath),
							 std::ios::binary) ;							// 同期借用。
	std::vector<char> read( static_cast<std::size_t>( input.byteCount)) ;	// 128 MiB以内の一入力。
	stream.read( read.data(), static_cast<std::streamsize>( read.size())) ;
	// EOF以外の読取失敗・短縮・末尾追加を完全入力としない。
	if( !stream || stream.gcount() != static_cast<std::streamsize>( read.size()) ||
	   stream.peek() != std::char_traits<char>::eof()) {
		return HRESULT_FROM_WIN32( ERROR_READ_FAULT) ;
	}

	bytes = std::move( read) ;
	return 0 ;
}

/**
 * @brief 現在OS用Modelsの導入名だけを有限に列挙する。
 * @param[in] path 保護展開済みINFの絶対path。呼出し中に変更しない。
 * @param[out] bases 成功時だけ一意な導入名を保持する。失敗時は空。
 * @return 列挙完了0、SetupAPI・形式・予算失敗のHRESULT。
 * @note PnP ID fieldを取得しない。各名の最終検査は共通棚卸しAPIへ委譲する。
 */
drivercrate::NativeError currentInstallBases( const std::wstring		   &path,
											 std::vector<std::wstring> &bases)
{
	bases.clear() ;
	const HINF opened =
		// 読取だけ。
		SetupOpenInfFileW( path.c_str(), nullptr, INF_STYLE_WIN4, nullptr) ;
	// 無効handleを所有deleterへ渡さない。
	if( opened == INVALID_HANDLE_VALUE) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	std::unique_ptr<void, decltype( &SetupCloseInfFile)> inf( opened,
															SetupCloseInfFile) ;	// 同期所有。
	INFCONTEXT manufacturer{} ;														// 現OS Models選択のメーカー行。
	// Manufacturerがない入力を任意sectionへfallbackしない。
	if( !SetupFindFirstLineW( inf.get(), L"Manufacturer", nullptr, &manufacturer)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	std::vector<std::wstring> selected ;	// 全列挙成功時だけ返す一意な名。
	std::size_t				  lines{} ;		// ManufacturerとModelsの合計4096行まで。
	// 全メーカーの現OS Modelsを対象とし、別architectureへfallbackしない。
	do {
		// 重複メーカーも走査量へ数える。
		if( ++lines > 4096U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::array<wchar_t, 256U> models{} ;	// Windowsが選ぶ節名の有限buffer。
		// 互換なしと容量・構文失敗を区別する。
		if( !SetupDiGetActualModelsSectionW( &manufacturer, nullptr, models.data(),
										   static_cast<DWORD>( models.size()), nullptr, nullptr)) {
			const DWORD error = GetLastError() ;	// 元のSetupAPI診断。
			// 構文や容量失敗をメーカー対象外として握り潰さない。
			if( error != ERROR_NO_COMPAT_DRIVERS && error != ERROR_SECTION_NOT_FOUND) {
				return HRESULT_FROM_WIN32( error) ;
			}

			continue ;
		}

		INFCONTEXT model{} ;	// 導入名だけを読むモデル行。
		// 欠落Modelsを推測で補完しない。
		if( !SetupFindFirstLineW( inf.get(), models.data(), nullptr, &model)) {
			continue ;
		}

		// 共通APIと同じ有限量で現在Modelsを列挙する。
		do {
			// 共有Modelsの再走査も予算へ数える。
			if( ++lines > 4096U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::array<wchar_t, 255U> name{} ;	// 導入名254文字と終端だけ。
			// PnP IDは読まず、導入名不足・切詰めを拒否する。
			if( SetupGetFieldCount( &model) < 2U ||
			   !SetupGetStringFieldW( &model, 1U, name.data(), static_cast<DWORD>( name.size()),
									 nullptr) ||
			   name.front() == L'\0') {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			const std::wstring base( name.data()) ;	// Modelsの第1 fieldのみ。
			const bool		   duplicate =
				std::ranges::any_of( selected, [&base]( const std::wstring &prior) {
					// Windowsと同じ大文字小文字非依存で導入名を一意にする。
					return CompareStringOrdinal( prior.c_str(), -1, base.c_str(), -1, TRUE) ==
						   CSTR_EQUAL ;
				}) ;
			// 同じ導入名の機種数を新しい導入名数へ加算しない。
			if( !duplicate) {
				// 一INFの測定対象を128導入名に限定する。
				if( selected.size() == 128U) {
					return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				}

				selected.push_back( base) ;
			}
		} while( SetupFindNextLine( &model, &model)) ;
	} while( SetupFindNextLine( &manufacturer, &manufacturer)) ;
	bases = std::move( selected) ;
	return 0 ;
}

/**
 * @brief 節名を原UTF-16LE byteの非秘密hashへ置換する。
 * @param[in] section 結果へ名前を出さない内部導入名。
 * @param[out] hash 成功時の小文字SHA-256。失敗時は空。
 * @return Hash成功0、有限量またはCNG失敗のHRESULT。
 */
drivercrate::NativeError sectionHash( const std::wstring_view section, std::wstring &hash)
{
	// Windows x64のwchar_t原byteをCNG境界へ借用し、文字列正規化を行わない。
	const auto bytes =
		// 非所有原UTF-16LE。
		std::as_bytes( std::span( section.data(), section.size())) ;
	return drivercrate::computeBytesSha256(
		std::string_view( reinterpret_cast<const char *>( bytes.data()), bytes.size()), hash) ;
}

/**
 * @brief 安全なentryの拡張子をWindowsと同じ比較で判定する。
 * @param[in] path 全entry preflight済みの相対path。
 * @param[in] extension 固定の四文字拡張子。
 * @return 末尾の拡張子一致の場合true。
 */
bool hasExtension( const std::wstring &path, const wchar_t *extension)
{
	return path.size() >= 4U && CompareStringOrdinal( path.c_str() + path.size() - 4U, 4, extension,
													 4, TRUE) == CSTR_EQUAL ;
}

/**
 * @brief 全metadataを閉じた有限選択へ固定する。
 * @param[in] entries 全ZIPの検証済みmetadata。
 * @param[out] selected 成功時だけ全INFとCATの相対位置を借用する。
 * @return 予算と通常metadata検査成功0、失敗はHRESULT。
 */
#ifndef DRIVERCRATE_COMMON_INF_METADATA_PROBE
drivercrate::NativeError metadataSelection(
	const std::vector<drivercrate::OfficialZipEntry> &entries,
	std::vector<std::wstring_view>					 &selected)
{
	selected.clear() ;
	std::vector<std::wstring_view> paths ;		// Entry storageを展開終了まで同期借用する。
	std::size_t					   infs{} ;		// 閉じたINF集合は最大64。
	std::size_t					   cats{} ;		// CAT数は最大64。
	std::uint64_t				   bytes{} ;	// 全選択metadata合計64 MiB以内。
	// 非選択entryも既に共通preflightを通った一覧からのみ選ぶ。
	for( const auto &entry : entries) {
		const bool inf = hasExtension( entry.relativePath, L".inf") ;	// 作用を実行しないmetadata。
		const bool cat = hasExtension( entry.relativePath, L".cat") ;	// INF member確認用だけのCAT。
		// 実行fileやdriver本体を展開しない。
		if( !inf && !cat) {
			continue ;
		}

		const std::uint64_t maximum = (inf ? 4ULL : 32ULL) * 1024ULL * 1024ULL ;	// 個別上限。
		// 空・過大・集合上限・合計overflowを展開前に拒否する。
		if( entry.uncompressedSize == 0U || entry.uncompressedSize > maximum ||
		   (inf && ++infs > 64U) || (cat && ++cats > 64U) ||
		   entry.uncompressedSize > 64ULL * 1024ULL * 1024ULL - bytes) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		bytes += entry.uncompressedSize ;
		paths.push_back( entry.relativePath) ;
	}

	// 開始INFがないZIPを任意fileへfallbackしない。
	if( infs == 0U) {
		return E_INVALIDARG ;
	}

	selected = std::move( paths) ;
	return 0 ;
}
#endif

/**
 * @brief native結果を固定分類・hashだけのJSONへ縮約する。
 * @param[in] result 全体成功または全て空の拒否出力。
 * @param[in] rootPath 開始INFの相対位置。root辺の棚卸し位置だけへ結合する。
 * @param[out] json 全hash生成成功時だけ非秘密JSONを保持する。
 * @return 成功0、hash失敗時はHRESULT。
 */
drivercrate::NativeError nativeJson( const drivercrate::InfDependencyNativeResult &result,
									const std::wstring &rootPath, std::string &json)
{
	json.clear() ;
	std::string output = "{\"documents\":[" ;	// 全documentの三証拠軸を保持する。
	bool		first  = true ;					// 重複辺を消さずJSON区切りだけを管理する。
	// 元byteと個別診断を結合し、signerやCAT位置を出さない。
	for( const auto &document : result.dependency.documents) {
		const auto finding = std::ranges::find_if( result.findings, [&document]( const auto &item) {
			// 同run identityだけで元診断へ結合する。
			return item.identity == document.identity ;
		}) ; // 借用findingは本同期関数内だけ有効。
		// 不完全な内部結果を成功観測へ縮約しない。
		if( finding == result.findings.end()) {
			return E_UNEXPECTED ;
		}

		output += (first ? "" : ",") + std::string( "{\"identity\":") +
				  std::to_string( document.identity) + ",\"sha256\":\"" +
				  narrowHash( document.sha256) +
				  "\",\"bytes\":" + std::to_string( document.byteCount) +
				  ",\"origin\":" + std::to_string( static_cast<int>( document.origin)) +
				  ",\"byteBinding\":" + std::to_string( static_cast<int>( document.byteBinding)) +
				  ",\"signature\":" + std::to_string( static_cast<int>( document.signature)) +
				  ",\"provenance\":" + std::to_string( static_cast<int>( document.provenance)) +
				  ",\"signatureError\":" + std::to_string( finding->signatureError) +
				  ",\"provenanceError\":" + std::to_string( finding->provenanceError) + "}" ;
		first = false ;
	}

	output += "],\"sections\":[" ;
	first = true ;
	// seedと追跡節の存在は作用完全性と区別して残す。
	for( const auto &section : result.dependency.sections) {
		std::wstring hash ;											// 原UTF-16LE節名のidentity。
		const auto	 error = sectionHash( section.section, hash) ;	// 原名称は永続出力しない。
		// Hash失敗時は部分JSONを返さない。
		if( error != 0) {
			return error ;
		}

		output += (first ? "" : ",") + std::string( "{\"identity\":") +
				  std::to_string( section.identity) + ",\"sectionSha256\":\"" + narrowHash( hash) +
				  "\",\"state\":" + std::to_string( static_cast<int>( section.state)) + "}" ;
		first = false ;
	}

	output += "],\"edges\":[" ;
	first = true ;
	// 同元節・同targetの重複を維持する。
	for( const auto &edge : result.dependency.edges) {
		std::wstring section ;										// 元節の非秘密identity。
		std::wstring target ;										// 参照原名の非秘密identity。
		std::wstring inventoryTarget ;								// root棚卸しとの別位置identity。子INF辺では空。
		auto error = sectionHash( edge.sourceSection, section) ;	// 名称ではなくhashだけを保存する。
		// 全hash成功を要求する。
		if( error == 0) {
			error = sectionHash( edge.target, target) ;
		}

		// 元節名は同一でもIncludeの親位置はrootにだけ結合する。
		if( error == 0 && edge.sourceIdentity == 1U) {
			std::wstring name = edge.target ;	// Needsは明示節名のまま保持する。
			// 親位置付き旧棚卸しhashを原相対名hashとは別に作る。
			if( edge.directive == drivercrate::InfDependencyDirective::INCLUDE) {
				const auto parent = rootPath.find_last_of( L'\\') ;	// 元INF親の有限境界。
				// Root直下では余分なseparatorを追加しない。
				if( parent != std::wstring::npos) {
					name = rootPath.substr( 0U, parent + 1U) + name ;
				}
			}

			error = sectionHash( name, inventoryTarget) ;
		}

		// 不完全な辺を切り捨てない。
		if( error != 0) {
			return error ;
		}

		output += (first ? "" : ",") + std::string( "{\"sourceIdentity\":") +
				  std::to_string( edge.sourceIdentity) + ",\"sourceSectionSha256\":\"" +
				  narrowHash( section) + "\",\"targetSha256\":\"" + narrowHash( target) +
				  "\",\"inventoryTargetSha256\":\"" + narrowHash( inventoryTarget) +
				  "\",\"directive\":" + std::to_string( static_cast<int>( edge.directive)) +
				  ",\"state\":" + std::to_string( static_cast<int>( edge.state)) +
				  ",\"reason\":" + std::to_string( static_cast<int>( edge.reason)) +
				  ",\"targetIdentity\":" + std::to_string( edge.targetIdentity) +
				  ",\"candidateCount\":" + std::to_string( edge.candidateCount) + "}" ;
		first = false ;
	}

	const auto &plan = result.dependency.plan ;	// 実行能力を持たない確認用の結果だけ。
	output +=
		"],\"referencesResolved\":" + std::string( plan.referencesResolved ? "true" : "false") +
		",\"rootEvidenceVerified\":" + (plan.rootEvidenceVerified ? "true" : "false") +
		",\"actionCoverage\":" + std::to_string( static_cast<int>( plan.actionCoverage)) +
		",\"deviceApplicability\":" + std::to_string( static_cast<int>( plan.deviceApplicability)) +
		",\"installRoute\":" + std::to_string( static_cast<int>( plan.installRoute)) + "}" ;
	json = std::move( output) ;
	return 0 ;
}

/**
 * @brief 一開始INFの全導入名を棚卸しと実依存観測へ接続する。
 * @param[in] workspace 全INFとCATを保護所有する同期領域。
 * @param[in] entries 元ZIP metadata。抽出metadataだけに実hashがある。
 * @param[in] extracted 実hashを保持する全抽出metadata。
 * @param[in] infPath 実byteの開始INF相対path。
 * @param[in] infHash 期待原INF hash。
 * @param[out] selections 全列挙成功時だけ保持するJSON行集合。
 * @param[out] count 列挙完了後の全選択分母。失敗時は0。
 * @param[out] observed native観測成功数。失敗時は0。
 * @param[in] binding Live専用compileでだけ貸し出す封印所有者。旧local経路はnullptr。
 * @param[in] session Live専用compileの元取得session。bindingと同時に指定する。
 * @param[in] archive Live専用compileの元取得領域。bindingと同時に指定する。
 * @return 全列挙完了0、入力・hash・容量失敗のHRESULT。
 * @note 個別棚卸し・native拒否は分母に残す。
 */
drivercrate::NativeError observeSelections(
	const drivercrate::OfficialDownloadWorkspace	 &workspace,
	const std::vector<drivercrate::OfficialZipEntry> &entries,
	const std::vector<drivercrate::OfficialZipEntry> &extracted, const std::wstring &infPath,
	const std::wstring &infHash, std::string &selections, std::size_t &count, std::size_t &observed
#ifdef DRIVERCRATE_LIVE_SEALED_INF_PROBE
	,
	const drivercrate::OfficialInfArchiveBinding  *binding = nullptr,
	const drivercrate::OfficialAcquisitionSession *session = nullptr,
	const drivercrate::OfficialDownloadWorkspace  *archive = nullptr
#endif
)
{
	selections.clear() ;
	count	 = 0 ;
	observed = 0 ;
#ifdef DRIVERCRATE_LIVE_SEALED_INF_PROBE
	// 生存取得の三所有者が揃わない呼出しを旧local観測へ落とさない。
	if( (binding != nullptr || session != nullptr || archive != nullptr) &&
	   (binding == nullptr || session == nullptr || archive == nullptr)) {
		return E_INVALIDARG ;
	}
#endif
	std::vector<drivercrate::InfDependencyPackageMember> members ;			// 全INFの閉じた固定集合。
	std::size_t											 rootIndex = 64U ;	// 未発見sentinel。
	// CATをINF memberとして登録しない。
	for( const auto &entry : extracted) {
		// 全実INFだけを閉じた集合へ加える。
		if( hasExtension( entry.relativePath, L".inf")) {
			// 開始memberの位置と原byteを同時に固定する。
			if( entry.relativePath == infPath && entry.sha256 == infHash) {
				rootIndex = members.size() ;
			}

			members.push_back( {entry.relativePath, entry.sha256, entry.uncompressedSize}) ;
		}
	}

	// 元hash不一致を別INFへfallbackしない。
	if( rootIndex >= members.size()) {
		return E_INVALIDARG ;
	}

	std::vector<std::wstring> bases ;										// 現OSの導入名だけ、PnP IDを含めない。
	auto error = currentInstallBases( workspace.path( infPath), bases) ;	// 実deviceの列挙ではない。
	// モデル列挙全体拒否時には個別処理へ進まない。
	if( error != 0) {
		return error ;
	}

	std::string rows ;			// 完全成功まで呼出し側へ公開しないJSON。
	std::size_t completed{} ;	// 成功・拒否を含む全導入名の分母。
	std::size_t successful{} ;	// nativeの完了数。参照解決・適合・導入数ではない。
	// 一導入名につき独立したfinite native graphを作る。
	for( const auto &base : bases) {
		std::wstring baseHash ;	// 前世代と同じ原UTF-16LE identity。
		error = sectionHash( base, baseHash) ;
		// 旧選択identityを作れない場合は全体拒否する。
		if( error != 0) {
			return error ;
		}

		drivercrate::OfficialInfInstallInventory inventory ;	// 全作用の解析済み証明ではない。
		const auto inventoryError = drivercrate::inspectOfficialInfInstallInventory(
			workspace, entries, infPath, base, inventory) ;	// 訪問済み明示節の契約を再利用する。
		drivercrate::InfDependencyNativeResult result ;		// 全体拒否で空になる独立非実行結果。
		const auto							   nativeError =
			inventoryError != 0 ? inventoryError
#ifdef DRIVERCRATE_LIVE_SEALED_INF_PROBE
			: binding != nullptr
				? binding->inspectDependencies( *session, *archive, rootIndex,
											   inventory.visitedSections, 6402U + completed, result)
#endif
				: drivercrate::inspectNativeInfDependencies(
					  workspace, members, rootIndex, inventory.visitedSections, 6402U + completed,
					  result) ;	// 旧local経路のPackage由来は未検査。
		std::string native ;	// raw名称を含まない縮約結果。
		error = nativeJson( result, infPath, native) ;
		// 署名不足と縮約不能を区別し、後者では部分出力をしない。
		if( error != 0) {
			return error ;
		}

		// 個別拒否を含む一導入名の有限・hash限定観測行。
		const std::string row =
			"{\"baseSectionSha256\":\"" + narrowHash( baseHash) +
			"\",\"inventoryError\":" + std::to_string( inventoryError) +
			",\"nativeError\":" + std::to_string( nativeError) +
			",\"seedCount\":" + std::to_string( inventory.visitedSections.size()) +
			",\"native\":" + native + "}" ;
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
		constexpr std::size_t MAXIMUM_ROWS_BYTES =
			2U * 1024U * 1024U - 32768U ;	// 全metadata header余裕。
#else
		constexpr std::size_t MAXIMUM_ROWS_BYTES = 2U * 1024U * 1024U - 4096U ;	// Header余裕込み。
#endif
		// 総出力上限では失敗行を切り捨てて成功率を上げない。
		if( row.size() + 1U > MAXIMUM_ROWS_BYTES ||
		   rows.size() > MAXIMUM_ROWS_BYTES - row.size() - 1U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		rows += (completed == 0U ? "" : ",") + row ;
		++completed ;
		successful += nativeError == 0 ;
	}

	selections = std::move( rows) ;
	count	   = completed ;
	observed   = successful ;
	return 0 ;
}

/**
 * @brief 六引数だけを有限ZIP／metadata展開／native graphへ結合する。
 * @param[in] count 実行名を含む引数数。
 * @param[in] arguments Local ZIP位置・hash・size・INF相対位置・INF hash。
 * @return 完了0、検査拒否1、引数不正2。
 * @note 元入力は実行・変更しない。全抽出metadataの終了時identityを再確認する。
 */
int inspect( const int count, wchar_t **arguments)
{
	std::uint64_t expectedBytes{} ;	// 正規十進の有限期待size。
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
	constexpr int EXPECTED_ARGUMENTS = 7 ;	// 形式を明示する共通metadata測定target。
#else
	constexpr int EXPECTED_ARGUMENTS = 6 ;	// 旧targetの引数契約を維持。
#endif
	// Raw引数をechoせず、構文不正ではfileを操作しない。
	if( count != EXPECTED_ARGUMENTS || !validHash( arguments[2]) ||
	   !parseBytes( arguments[3], expectedBytes) || !validHash( arguments[5]) ||
	   !drivercrate::validInfDependencyPath( arguments[1], true) ||
	   !drivercrate::validInfDependencyPath( arguments[4], false)) {
		return 2 ;
	}

	const std::wstring					   archiveHash( arguments[2]) ;	// 期待原ZIP identity。
	const std::wstring					   infHash( arguments[5]) ;		// 期待開始INF identity。
	const std::wstring					   infPath( arguments[4]) ;		// 永続出力しない相対位置。
	drivercrate::OfficialDownloadWorkspace archiveWorkspace ;			// 共通copy所有者。
	drivercrate::OfficialDownloadWorkspace workspace ;					// 全metadataだけの展開所有者。
	drivercrate::DriverArchiveInput		   input ;						// 不変copyの期待identity。
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
	drivercrate::OfficialInfContainerFormat format{} ;	// 旧targetから分離した明示形式。
	// 未知形式を拡張子から推測しない。
	if( std::wstring_view( arguments[6]) == L"pe") {
		// 既存parserの入力上限をmemory確保前にも適用する。
		if( expectedBytes > 64ULL * 1024ULL * 1024ULL) {
			return 2 ;
		}

		format = drivercrate::OfficialInfContainerFormat::PE_FLAT_TABLE ;
	} else {
		// ZIP以外の明示形式も拡張子から推測しない。
		if( std::wstring_view( arguments[6]) != L"zip") {
			return 2 ;
		}

		format = drivercrate::OfficialInfContainerFormat::ZIP ;
	}

	input.inspectionPath = arguments[1] ;
	input.byteCount		 = expectedBytes ;
	input.sha256		 = archiveHash ;
	auto error			 = drivercrate::verifyOfficialFileMetadata(
		  input.inspectionPath, {expectedBytes, archiveHash}) ;	// 研究用identity。
	std::string fileMetadata ;									// 原位置をhashへ縮約した全抽出metadata。
#else
	drivercrate::OfficialDriverArchiveFormat format{} ;	// ZIP以外へfallbackしない。
	auto error = drivercrate::copyLocalDriverArchive( arguments[1], 6402U, archiveWorkspace, input,
													 format) ;	// Local読取だけ。
#endif
	bool		bound = false ;		// 原ZIP期待byte一致だけを表す。
	std::string selections ;		// 全体失敗では破棄する非秘密JSON。
	std::size_t selectionCount{} ;	// 個別失敗も含む分母。
	std::size_t observed{} ;		// Native観測の完了数。
	std::size_t infCount{} ;		// 閉じた全INF数。
	std::size_t catCount{} ;		// 実展開CAT数。
#ifdef DRIVERCRATE_UNTRUSTED_INF_PROBE
	drivercrate::OfficialAcquisitionSession	  missingSession ;		// 履歴から初期化しない空session。
	drivercrate::OfficialAcquiredFileEvidence missingEvidence ;		// issuerを発行しない空証拠。
	drivercrate::OfficialInfArchiveBinding	  untrustedBinding ;	// 研究ZIPを公式認証へ昇格しない。
	const auto								  sealedBindError = untrustedBinding.bind(
		   missingSession, std::move( missingEvidence), archiveWorkspace, {}) ;	// 必ず拒否を保持する。
	drivercrate::InfDependencyNativeResult sealedResult ;						// 拒否出力が空かを実測する。
	const auto sealedInspectError = untrustedBinding.inspectDependencies(
		missingSession, archiveWorkspace, 0U, {}, 6403U, sealedResult) ;	// 元byte検査ではない。
	const bool sealedOutputEmpty = sealedResult.dependency.documents.empty() &&
								   sealedResult.dependency.sections.empty() &&
								   sealedResult.dependency.edges.empty() &&
								   // 不完全根拠でnativeへ進んだと誤表示しない。
								   sealedResult.findings.empty() ;
#endif
	// Copy成功を由来証明へ流用しない。
#ifndef DRIVERCRATE_COMMON_INF_METADATA_PROBE
	// 旧copy経路は同じZIP形式と原byteへの一致だけを認める。
	if( error == 0 && (format != drivercrate::OfficialDriverArchiveFormat::ZIP ||
					  input.byteCount != expectedBytes || input.sha256 != archiveHash)) {
		error = E_INVALIDARG ;
	}
#endif

	// 全entry preflightとmetadata選択を成功順に行う。
	if( error == 0) {
		bound = true ;
		std::vector<char>						   raw ;		// 最大128 MiBのcopy原byte。
		std::vector<drivercrate::OfficialZipEntry> entries ;	// 非選択fileを含む全metadata。
#ifndef DRIVERCRATE_COMMON_INF_METADATA_PROBE
		std::vector<std::wstring_view> selected ;	// Entry storageを同期借用する位置。
#endif
		std::vector<drivercrate::OfficialZipEntry> extracted ;	// 実抽出metadataのhash。
		error = readArchive( input, raw) ;
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
		std::wstring capturedHash ;	// 読取りmemoryを期待原byteへも照合する。
		// 同期memoryそのものを検査してから共通抽出へ渡す。
		if( error == 0) {
			error = drivercrate::computeDriverContainerSha256(
				std::string_view( raw.data(), raw.size()), capturedHash) ;
		}

		// Fileの前後一致だけで途中の異なるmemoryを受理しない。
		if( error == 0 && capturedHash != archiveHash) {
			error = TRUST_E_BAD_DIGEST ;
		}

		// 原memoryが一致した場合だけ新規保護領域を作る。
		if( error == 0) {
			error = workspace.initialize( L"common-inf-metadata", 6402U) ;
		}

		// 封印所有者と同じ共通APIから全INF／CATを原範囲で抽出する。
		if( error == 0) {
			error	= drivercrate::extractOfficialInfMetadata( std::as_bytes( std::span( raw)), format,
															  workspace, extracted) ;
			entries = extracted ;
		}
#else
		// 指定INFだけを読んで他entryの不正を無視しない。
		if( error == 0) {
			error =
				drivercrate::inspectOfficialZip( std::as_bytes( std::span( raw)), ZIP_POLICY, entries) ;
		}

		// 個別・集合・合計の展開予算を先に確定する。
		if( error == 0) {
			error = metadataSelection( entries, selected) ;
		}

		// 観測専用の新規保護領域を作る。
		if( error == 0) {
			error = workspace.initialize( L"acquired-inf-dependency", 6402U) ;
		}

		// SYS・EXE等はmetadataだけに残す。
		if( error == 0) {
			error = drivercrate::extractOfficialZipFiles( std::as_bytes( std::span( raw)), ZIP_POLICY,
														 selected, workspace, extracted) ;
		}
#endif

		// 元metadataを原byteに結合し、非選択fileに架空hashを付けない。
		for( const auto &entry : extracted) {
			const auto original = std::ranges::find_if( entries, [&entry]( const auto &item) {
				// 相対位置の完全一致だけを受理する。
				return item.relativePath == entry.relativePath ;
			}) ; // 元metadataへの同期借用iterator。
			// 抽出器とmetadataの不一致を拒否する。
			if( original == entries.end() || original->uncompressedSize != entry.uncompressedSize) {
				error = E_UNEXPECTED ;
				break ;
			}

			original->sha256 = entry.sha256 ;
			infCount += hasExtension( entry.relativePath, L".inf") ;
			catCount += hasExtension( entry.relativePath, L".cat") ;
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
			std::wstring nameHash ;	// 全抽出の原位置identity。
			error = sectionHash( entry.relativePath, nameHash) ;
			// 非秘密hashを作れない場合は全体拒否する。
			if( error != 0) {
				break ;
			}

			fileMetadata += (fileMetadata.empty() ? "" : ",") + std::string( "{\"nameSha256\":\"") +
							narrowHash( nameHash) +
							"\",\"bytes\":" + std::to_string( entry.uncompressedSize) +
							",\"sha256\":\"" + narrowHash( entry.sha256) + "\",\"kind\":\"" +
							(hasExtension( entry.relativePath, L".inf") ? "INF" : "CAT") + "\"}" ;
#endif
		}

		// 全memberの期待byteを固定してから明示seedを実loaderへ渡す。
		if( error == 0) {
			error = observeSelections( workspace, entries, extracted, infPath, infHash, selections,
									  selectionCount, observed) ;
		}

		// 全体成功には原ZIPの終了時identity一致も必要とする。
		if( error == 0) {
			error = drivercrate::verifyOfficialFileMetadata( input.inspectionPath,
															{expectedBytes, archiveHash}) ;
		}

		// 未訪問metadataを含む全抽出fileの改変を検査する。
		for( const auto &entry : extracted) {
			// 元失敗を上書きせず、部分成功を公開しない。
			if( error != 0) {
				break ;
			}

			error = drivercrate::verifyOfficialFileMetadata( workspace.path( entry.relativePath),
															{entry.uncompressedSize, entry.sha256}) ;
		}
	}

	// 全体失敗では全観測集合と件数を空にする。
	if( error != 0) {
		selections.clear() ;
		selectionCount = 0 ;
		observed	   = 0 ;
		infCount	   = 0 ;
		catCount	   = 0 ;
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
		fileMetadata.clear() ;
#endif
	}

	const std::string output =
#ifdef DRIVERCRATE_COMMON_INF_METADATA_PROBE
		"{\"schema\":\"dc-common-inf-metadata-dependency-observation-v1\",\"fileMetadata\":[" +
		fileMetadata + "]," +
#else
#ifdef DRIVERCRATE_UNTRUSTED_INF_PROBE
		"{\"schema\":\"dc-untrusted-inf-dependency-observation-v1\","
		"\"sealedBindError\":" +
		std::to_string( sealedBindError) +
		",\"sealedInspectError\":" + std::to_string( sealedInspectError) +
		",\"sealedOutputEmpty\":" + (sealedOutputEmpty ? "true," : "false,") +
#else
		"{\"schema\":\"dc-acquired-inf-dependency-observation-v1\","
#endif
#endif
		"\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,\"samePcOnly\":true,"
		"\"archiveSha256\":\"" +
		narrowHash( archiveHash) + "\",\"archiveBytes\":" + std::to_string( expectedBytes) +
		",\"infSha256\":\"" + narrowHash( infHash) +
		"\",\"inputBound\":" + (bound ? "true" : "false") + ",\"error\":" + std::to_string( error) +
		",\"packageInfCount\":" + std::to_string( infCount) +
		",\"packageCatCount\":" + std::to_string( catCount) +
		",\"selectionCount\":" + std::to_string( selectionCount) +
		",\"observedSelections\":" + std::to_string( observed) + ",\"selections\":[" + selections +
		"]}\n" ;	// 実OS識別子・raw名前・pathを出さない。
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ? (error == 0 ? 0 : 1)
																			  : 2 ;
}

#ifdef DRIVERCRATE_LIVE_SEALED_INF_PROBE
#ifdef DRIVERCRATE_LIVE_SEALED_NESTED_PROBE
/**
 * @brief 全宣言を検査し、直接INFと一段ZIPの構造計画だけを作る。
 * @param[in] raw 最大32 MiBの不変原ZIP。取得認証は呼出し側の別責務。
 * @param[out] chains 成功時だけ空chainまたは一原ZIP位置を持つ最大16branch。
 * @return 完了0、危険宣言・過多・INF／ZIPなしのHRESULT。
 * @note 展開・実行・認証を行わない。選んだ全ZIPの内容はbinderで別に検査する。
 */
drivercrate::NativeError metadataChainPlan( std::span<const std::byte>			   raw,
										   std::vector<std::vector<std::wstring>> &chains)
{
	chains.clear() ;
	// 実取得と同じ小さいinput上限を構造計画にも適用する。
	if( raw.size() > 32U * 1024U * 1024U) {
		return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
	}

	std::vector<drivercrate::OfficialZipEntry> entries ;	// 非選択を含む全宣言。
	const auto								   error = drivercrate::inspectOfficialZip(
		raw, drivercrate::OFFICIAL_INF_ARCHIVE_POLICY, entries) ;	// 共通先行検査。
	// 危険な非選択を省略して成功しない。
	if( error != 0) {
		return error ;
	}

	std::vector<std::vector<std::wstring>> plan ;	// 成功commit前の所有位置。
	const bool direct = std::ranges::any_of( entries, []( const auto &entry) {
		return hasExtension( entry.relativePath, L".inf") ;
	}) ; // 直接INFがある場合だけ空chainを作る。
	// 全直接INFもbinderの閉じた集合へ渡す。
	if( direct) {
		plan.emplace_back() ;
	}

	// 原表順の全ZIP memberを一段の明示位置へ変換する。
	for( const auto &entry : entries) {
		// 非ZIPの実行fileやreadmeを最終containerと推測しない。
		if( !hasExtension( entry.relativePath, L".zip")) {
			continue ;
		}

		// 過多を切捨てず全体拒否する。
		if( plan.size() >= 16U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		plan.push_back( {entry.relativePath}) ;
	}

	// metadataの構造起点なしをdriver不適合としない。
	if( plan.empty()) {
		return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
	}

	chains = std::move( plan) ;
	return 0 ;
}

/**
 * @brief local原byteから構造計画だけを確認し、由来を認定しない。
 * @param[in] arguments 検査済み位置・hash・byte数を含む五引数。
 * @return 計画完了0、拒否1、構文／出力失敗2。
 * @note 旧測定器と同じ有限読取を使い、実HTTP／証拠発行を行わない。
 */
int inspectLocalMetadataPlan( wchar_t **arguments)
{
	std::uint64_t bytes{} ;	// 最大32 MiBの期待入力。
	// 原引数をechoせず不正入力は読取り前に拒否する。
	if( !drivercrate::validInfDependencyPath( arguments[2], true) || !validHash( arguments[3]) ||
	   !parseBytes( arguments[4], bytes) || bytes > 32ULL * 1024ULL * 1024ULL) {
		return 2 ;
	}

	drivercrate::DriverArchiveInput input ;	// 研究用identity。取得証拠ではない。
	input.inspectionPath = arguments[2] ;
	input.sha256		 = arguments[3] ;
	input.byteCount		 = bytes ;
	std::vector<char> raw ;									// 不変原ZIPの有限memory。
	auto			  error = readArchive( input, raw) ;	// 完全読取り。
	std::wstring	  hash ;								// 期待原byteとの独立照合。
	// memoryを照合してから計画する。
	if( error == 0) {
		error = drivercrate::computeDriverContainerSha256( std::string_view( raw.data(), raw.size()),
														  hash) ;
	}

	// 同じsizeだけで別byteを受理しない。
	if( error == 0 && hash != input.sha256) {
		error = TRUST_E_BAD_DIGEST ;
	}

	std::vector<std::vector<std::wstring>> chains ;	// 元位置は出力しない。
	// 原byte確認後にだけ構造計画を行う。
	if( error == 0) {
		error = metadataChainPlan( std::as_bytes( std::span( raw)), chains) ;
	}

	const std::string output =
		"{\"schema\":\"dc-local-metadata-chain-plan-v1\","
		"\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,"
		"\"officialProvenance\":\"NOT_CHECKED\",\"networkRequests\":0,\"error\":" +
		std::to_string( error) + ",\"branchCount\":" + std::to_string( chains.size()) +
		"}\n" ;	// 構造だけの件数。
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ? (error == 0 ? 0 : 1)
																			  : 2 ;
}
#endif
/**
 * @brief 一配布を実HTTP取得し、同じ生存sessionの封印全INFを観測する。
 * @param[in] preflight trueは組込み定義だけを確認し、通信・COM・file操作を行わない。
 * @param[in] collectorSource 新targetでのみ使う台帳定義。Nullは旧Prolific経路。
 * @param[in] collectorChain 新targetの明示原member。Nullは旧直接指定。
 * @param[in] collectorFormat 新targetの明示最終形式。旧経路はZIPだけ。
 * @return 観測完了0、元検証拒否1、出力失敗2。
 * @note 一回32 MiB・一file。実network costは承認を合成しない。結果は非実行の研究用だけ。
 */
int inspectLiveProlific( const bool preflight
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
						,
						const drivercrate::CollectorInspectionSource *collectorSource = nullptr,
						const std::vector<std::wstring>				 *collectorChain  = nullptr,
						drivercrate::OfficialInfContainerFormat		  collectorFormat =
							drivercrate::OfficialInfContainerFormat::ZIP
#endif
)
{
	constexpr drivercrate::ScanSessionId SESSION = 6408U ;						// 同process内だけの世代。
	constexpr std::uint64_t MAXIMUM_BYTES		 = 32ULL * 1024ULL * 1024ULL ;	// 一回の取得予算。
	const auto			   *definition			 = drivercrate::officialSourceDefinition(
		  drivercrate::OfficialReleaseFamily::PROLIFIC_DCHU) ;	// 既存公式起点とparser。
	// 定義不在を別社Providerや任意URLで補わない。
	if(
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
		collectorSource == nullptr &&
#endif
		( definition == nullptr ||
		 definition->providerId != drivercrate::PROLIFIC_OFFICIAL_PROVIDER_ID)) {
		return 1 ;
	}

	// 非通信検査は生存取得・署名の成功を出力しない。
	if( preflight) {
		return std::printf(
				   "{\"schema\":\"dc-live-sealed-inf-preflight-v1\","
				   "\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,"
				   "\"networkRequests\":0,\"maximumFileBytes\":33554432,\"maximumFiles\":1}\n") >=
						   0 &&
					   std::fflush( stdout) == 0
				   ? 0
				   : 2 ;
	}

	drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;						// 同期測定のCOM寿命。
	auto		  error = static_cast<drivercrate::NativeError>( apartment.result()) ;	// 元COM診断。
	// 0COM・1metadata・2領域・3ledger・4取得・5証拠・6封印・7観測・8再確認。
	std::uint32_t stage{} ;
	bool		  metadataRejected{} ;									// 通信と本文／取得根拠拒否を分ける。
	drivercrate::OfficialHttpClient				  http( false) ;		// Cacheから生存取得を代用しない。
	drivercrate::OfficialReleaseRecord			  release ;				// URLは同期寿命内だけ。
	drivercrate::OfficialDownloadWorkspace		  archive ;				// 実取得を全観測終了まで所有する。
	drivercrate::OfficialAcquisitionSession		  session ;				// 本scope内の生存issuer。
	drivercrate::OfficialHttpAcquisitionTransport transport( http) ;	// 本物のWinHTTP以外を使わない。
	drivercrate::WindowsOfficialNetworkCostReader costReader ;			// 実OSの回線区分。
	drivercrate::OfficialAcquisitionResult	  acquisition ;				// 実byteと元診断。実pathは出力しない。
	drivercrate::OfficialAcquiredFileEvidence evidence ;				// 私有成功記録からだけ発行する。
	drivercrate::OfficialInfArchiveBinding	  binding ;					// 全INF／CATを元取得へ結合する所有者。
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
	drivercrate::CollectorInspectionAcquisition collector ;	// 実HTTPだけの収集一回scope。
	const auto									providerId = collectorSource == nullptr
																 ? definition->providerId
								 // Manufacturer別Providerを増やさない。
																 : drivercrate::COLLECTOR_INSPECTION_PROVIDER_ID ;
#else
	const auto providerId = definition->providerId ;	// 旧組み込み経路のidentityを維持する。
#endif
	bool		acquired{} ;	// 共通取得成功を封印成功や導入成功と区別する。
	// 同じHTTP clientのpayload ledger確認。
	bool		sourceVerified{} ;
	bool		bound{} ;		// bind成功の事実。各native軸は別に出力する。
	std::size_t infCount{} ;	// 個別失敗でも保持する封印全INF分母。
	std::size_t catCount{} ;	// CATはINFに加算しない。
	std::string roots ;			// 全体成功まで非秘密JSONを公開しない。
	// 成功したCOM初期化だけで公式metadataを読取る。
	if( error >= 0) {
		stage = 1U ;
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
		// 台帳経路はcollector自身がcost確認後に実起点を読む。
		if( collectorSource == nullptr) {
#endif
			error = drivercrate::readOfficialReleaseMetadata(
				drivercrate::OfficialReleaseFamily::PROLIFIC_DCHU, SESSION, http, release,
				metadataRejected) ;
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
		} else {
			error = 0 ;
		}
#endif
	}

	// 解析した公式行のURLを同じsessionでのみ使う。
	if( error == 0) {
		stage = 2U ;
		error = archive.initialize( providerId, SESSION) ;
	}

	// 一fileの有限予算を取得前に固定する。
	if( error == 0) {
		stage = 3U ;
		error = session.initialize( SESSION, {MAXIMUM_BYTES, MAXIMUM_BYTES, MAXIMUM_BYTES,
											 256ULL * 1024ULL * 1024ULL, 1U, 1U}) ;
	}

	// Network cost不明／制限付きへの自動承認は追加しない。
	if( error == 0) {
		stage = 4U ;
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
		// 同じ私有scopeで公式HTMLとpayloadを実取得し、公開boolを取り込まない。
		if( collectorSource != nullptr) {
			error = collector.acquire( SESSION, *collectorSource, session, archive, costReader, {},
									  acquisition) ;
		} else {
#endif
			const drivercrate::OfficialAcquisitionRequest request{
				.url			   = release.downloadUrl,
				.providerId		   = definition->providerId,
				.resourceId		   = drivercrate::OFFICIAL_PAYLOAD_RESOURCE_ID,
				.workspaceFileName = L"inspection.zip",
				.maximumFileBytes  = MAXIMUM_BYTES,
				.publishedSize	   = release.publishedSizeBytes,
				.publishedSha256   = release.publishedSha256} ;	// 公表値だけ。
			error = session.acquire(
				request, archive, transport, costReader,
				[]( std::uint64_t, std::uint64_t) { /* 通常logへ進捗内容を保存しない。 */ }, {},
				acquisition) ;
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
		}
#endif
		acquired = error == 0 && acquisition.state ==
									 drivercrate::OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ;
		sourceVerified =
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
			collectorSource != nullptr
				? acquired && collector.sourceVerified()
				:
#endif
				acquired && http.hasSourceEvidence( SESSION, definition->providerId,
												   drivercrate::OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	}

	// 公開成功boolから証拠を作らず、実sessionの私有成功記録を使う。
	if( error == 0) {
		stage = 5U ;
		error = session.bindAcquiredFile( archive, acquisition.acquisitionId, evidence) ;
	}

	std::vector<std::vector<std::wstring>> chains( 1U) ;	// 旧targetは直接ZIP一branchを維持する。
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
	// 原memberと形式は監査済みの明示計画で、取得認証そのものではない。
	if( collectorSource != nullptr && collectorChain != nullptr) {
		chains.front() = *collectorChain ;
	}
#endif
#ifdef DRIVERCRATE_LIVE_SEALED_NESTED_PROBE
	// 生存証拠とmemoryを同じ原取得へ照合して明示chainを選ぶ。
	if( error == 0) {
		drivercrate::DriverArchiveInput input ;	// 生存元取得の内部読取り値。
		input.inspectionPath = acquisition.inspectionPath ;
		input.byteCount		 = acquisition.byteCount ;
		input.sha256		 = acquisition.sha256 ;
		std::vector<char> raw ;	// 取得終了後の原byte。
		error = readArchive( input, raw) ;
		std::wstring hash ;	// memoryと元取得の一致。
		// memory自体を有限hashへ照合する。
		if( error == 0) {
			error = drivercrate::computeDriverContainerSha256(
				std::string_view( raw.data(), raw.size()), hash) ;
		}

		// 期待sizeと同じ別byteを構造選択へ渡さない。
		if( error == 0 && hash != acquisition.sha256) {
			error = TRUST_E_BAD_DIGEST ;
		}

		// 元取得証拠も再確認し、研究hashから認証を作らない。
		if( error == 0) {
			error = session.verifyAcquiredFile( evidence, archive) ;
		}

		// 全原宣言から取得権限を持たない有限計画を作る。
		if( error == 0) {
			error = metadataChainPlan( std::as_bytes( std::span( raw)), chains) ;
		}
	}
#endif
	std::size_t rootIndex{} ;	// 全branchを通じた一意なroot順。
	// 全明示branchを元取得から観測し、部分失敗を無視しない。
	for( const auto &chain : chains) {
		// 前のbranchが失敗した状態で次の成功を全体へ上書きしない。
		if( error != 0) {
			break ;
		}

		error = session.bindAcquiredFile( archive, acquisition.acquisitionId, evidence) ;

		// 全INF／CATを閉じた元container集合へ結合する。
		if( error == 0) {
			stage = 6U ;
			error = binding.bind( session, std::move( evidence), archive, chain
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
								 ,
								 collectorSource == nullptr
									 ? drivercrate::OfficialInfContainerFormat::ZIP
									 : collectorFormat
#endif
			) ;
			bound = error == 0 ;
			// 全branch合計も旧分母上限を超えて部分成功にしない。
			if( binding.members().size() > 64U - infCount ||
			   binding.catalogs().size() > 64U - catCount) {
				error = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 有限分母の容量拒否後に過大な部分件数を公開しない。
			if( error == 0) {
				infCount += binding.members().size() ;
				catCount += binding.catalogs().size() ;
			}
		}

		// 非実行棚卸し用metadataを封印一覧からだけ構成する。
		if( error == 0) {
			stage = 7U ;
			std::vector<drivercrate::OfficialZipEntry> entries ;	// 全INF／CATだけ。SYSは読まない。
			// 原INF順はbindingとroot位置を一致させる。
			for( const auto &member : binding.members()) {
				entries.push_back( {.relativePath	 = member.relativePath,
								   .uncompressedSize = member.byteCount,
								   .sha256			 = member.sha256}) ;
			}

			// CATをINF memberに加えずmetadataだけへ含める。
			for( const auto &catalog : binding.catalogs()) {
				entries.push_back( catalog) ;
			}

			// 一開始INFの個別失敗も全集合の分母へ残す。
			for( const auto &member : binding.members()) {
				std::string selections ;	// 原名をhashへ縮約した全導入名。
				std::size_t count{} ;		// 現OS Modelsの全導入名。
				std::size_t observed{} ;	// Native完了数。署名／導入数ではない。
				const auto	rootError = observeSelections(
					 *binding.workspace(), entries, entries, member.relativePath, member.sha256,
					 selections, count, observed, &binding, &session, &archive) ;	// 生存接続。
				const std::string row =
					"{\"ordinal\":" + std::to_string( rootIndex) + ",\"infSha256\":\"" +
					narrowHash( member.sha256) + "\",\"error\":" + std::to_string( rootError) +
					",\"selectionCount\":" + std::to_string( count) +
					",\"observedSelections\":" + std::to_string( observed) + ",\"selections\":[" +
					selections + "]}" ;	// 失敗行も保持する。
				constexpr std::size_t MAXIMUM_OUTPUT =
					2U * 1024U * 1024U - 4096U ;	// 全root＋headerの有限量。
				// 出力容量不足で一部rootだけを成功表示しない。
				if( row.size() + 1U > MAXIMUM_OUTPUT ||
				   roots.size() > MAXIMUM_OUTPUT - row.size() - 1U) {
					error = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
					break ;
				}

				roots += (rootIndex == 0U ? "" : ",") + row ;
				++rootIndex ;
			}
		}

		// 全元byte／CATの終了再確認も全体成功条件にする。
		if( error == 0) {
			stage = 8U ;
			error = binding.verify( session, archive) ;
		}
	}

	// 全体拒否は部分native出力を公開しないが実取得の事実・分母は保持する。
	if( error != 0) {
		bound = false ;
		roots.clear() ;
	}

	const std::string output =
		"{\"schema\":\"dc-live-sealed-inf-observation-v1\","
		"\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,\"samePcOnly\":true,"
		"\"stage\":" +
		std::to_string( stage) + ",\"error\":" + std::to_string( error) +
		",\"metadataRejected\":" + (metadataRejected ? "true" : "false") +
		",\"acquired\":" + (acquired ? "true" : "false") +
		",\"sourceLedgerVerified\":" + (sourceVerified ? "true" : "false") +
		",\"sealedBound\":" + (bound ? "true" : "false") +
		",\"acquisitionState\":" + std::to_string( static_cast<int>( acquisition.state)) +
		",\"networkCost\":" + std::to_string( static_cast<int>( acquisition.networkCost)) +
		",\"networkCostError\":" + std::to_string( acquisition.networkCostError) +
		",\"archiveBytes\":" + std::to_string( acquisition.byteCount) + ",\"archiveSha256\":\"" +
		narrowHash( acquisition.sha256) + "\",\"packageInfCount\":" + std::to_string( infCount) +
		",\"packageCatCount\":" + std::to_string( catCount) + ",\"roots\":[" + roots +
		"]}\n" ;	// URL・path・端末IDなし。
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ? (error == 0 ? 0 : 1)
																			  : 2 ;
}
#endif
} // namespace

/**
 * @brief CLI境界で例外を止め、部分結果を出さない。
 * @param[in] count OSが渡す引数数。
 * @param[in] arguments 本呼出し中だけ借用するOS引数列。
 * @return 完了0、検査拒否1、引数・例外・出力失敗2。
 */
int wmain( const int count, wchar_t **arguments)
{
	try {
#ifdef DRIVERCRATE_COLLECTOR_INSPECTION_PROBE
		// 外部台帳の一recordだけを明示入力し、成功JSON／任意Provider IDは受け取らない。
		if( count == 9 && (std::wstring_view( arguments[1]) == L"--live-collector-inspection" ||
						  std::wstring_view( arguments[1]) == L"--collector-preflight")) {
			const drivercrate::CollectorInspectionSource source{
				arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]} ;	// 台帳定義。
			const std::wstring_view member( arguments[7]) ;								// 空は直接ZIP。
			const std::wstring_view format( arguments[8]) ;								// 明示ZIPまたは唯一のPE表。
			// 未検証URL・不明形式・不正memberを実HTTPへ渡さない。
			if( !drivercrate::validateCollectorInspectionSource( source) ||
			   (format != L"ZIP" && format != L"PE_FLAT_TABLE") ||
			   (!member.empty() && !drivercrate::validInfDependencyPath( member, false))) {
				return 2 ;
			}

			const std::vector<std::wstring> chain =
				member.empty() ? std::vector<std::wstring>{}
							   : std::vector<std::wstring>{std::wstring( member)} ;	// 元一member。
			return inspectLiveProlific(
				std::wstring_view( arguments[1]) == L"--collector-preflight", &source, &chain,
				format == L"ZIP" ? drivercrate::OfficialInfContainerFormat::ZIP
								 : drivercrate::OfficialInfContainerFormat::PE_FLAT_TABLE) ;
		}
#endif
#ifdef DRIVERCRATE_LIVE_SEALED_NESTED_PROBE
		// 非通信の構造計画は実取得証拠を発行しない。
		if( count == 5 && std::wstring_view( arguments[1]) == L"--local-metadata-plan") {
			return inspectLocalMetadataPlan( arguments) ;
		}
#endif
#ifdef DRIVERCRATE_LIVE_SEALED_INF_PROBE
		// 新targetでもこの明示操作以外は実通信へ進めない。
		if( count == 2 && arguments != nullptr && arguments[1] != nullptr) {
			// 非通信preflightは取得証拠を作らない。
			if( std::wstring_view( arguments[1]) == L"--preflight-prolific") {
				return inspectLiveProlific( true) ;
			}

			// 明示された一配布の検査用取得だけを実行する。
			if( std::wstring_view( arguments[1]) == L"--live-prolific-inspection") {
				return inspectLiveProlific( false) ;
			}
		}
#endif
		return inspect( count, arguments) ;
	} catch( ...) {
		// 診断にraw引数を含めず、失敗終了値を維持する。
		return 2 ;
	}
}
