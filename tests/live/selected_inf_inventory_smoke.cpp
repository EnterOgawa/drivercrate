//------------------------------------------------------------------------------
/**
 * @file selected_inf_inventory_smoke.cpp
 * @brief 取得済みZIPの明示INFから選択作用・参照を非実行で観測する。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  保護ZIPと選択棚卸しの非導入結合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  独立定義のhash限定参照文脈・不足観測を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/15  明示local binding診断へ共通内容・実rank・数値拒否点を接続。
 * </pre>
 *
 * @note 明示local ZIPだけを読む。HTTP・実行・導入を行わない。
 *       明示binding診断だけは端末をread-only列挙し、発行した一時bindingを直ちに破棄する。
 *       相対path・ID・導入名・registry値・command本文を出力しない。
 * @see docs/adr/0265-acquired-selected-inf-inventory-observation.md
 * @see docs/adr/0268-selected-inf-reference-context-and-coverage.md
 */
//------------------------------------------------------------------------------

#include "platform/common_driver_package.h"
#include "platform/com_raii.h"
#include "platform/driver_store_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_zip.h"

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

namespace drivercrate {

/** @brief 開発用local診断から私有必要INF bindingの数値結果だけを取得します。 */
class DriverStoreBindingProbe final {
public:
	/** @brief 元検査と現在rankを通常bindingへ通し一時tokenを必ず破棄します。
	 * @param[in,out] store 同threadの実read-only scan所有者です。
	 * @param[in] current 同scanの現在行です。
	 * @param[in] inf 元byte/CATの検査所有者です。
	 * @param[in] audit 同device/INFの実rank結果です。
	 * @param[out] stage 必要INFの非機密な到達段階です。
	 * @return 通常bindingの元HRESULTです。導入権限を返しません。
	 */
	static NativeError inspect( DriverStoreProvider &store, const UpdateCandidate &current,
							   const CommonInfInspection &inf, const OfficialDriverRankAudit &audit,
							   RequiredInfBindingDiagnostic &stage)
	{
		OfficialInfInstallBinding binding ;							// 診断scopeだけの一時tokenです。
		std::shared_ptr<const RequiredDriverComponentPlan> plan ;	// 同元byteの内容関係です。
		const auto &package = inf.closure.packages.front() ;		// 同検査の基本INFです。
		const auto	error =
			 package.hasExternalDependencies || !inf.requiredInfPackages.empty()
				 ? store.createRequiredInfInstallBinding(
					   inf.scanSessionId, current.deviceIdentity, inf, plan, current.provider,
					   current.version, current.driverDate, audit, binding, &stage)
				 : store.createOfficialInfInstallBinding( inf.scanSessionId, current.deviceIdentity,
														 *inf.workspace, package, current.provider,
														 current.version, current.driverDate, audit,
														 binding) ;	// 通常と同じ依存分岐です。
		// 成功tokenを表示候補や後の導入へ転用しません。
		if( binding.token != 0U) {
			static_cast<void>(
				store.discardOfficialInfInstallBinding( inf.scanSessionId, binding.token)) ;
		}

		return error ;
	}
} ;

} // namespace drivercrate

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
 * @brief 一つの選択棚卸しを固定件数とhashだけへ縮約する。
 * @param[in] baseHash 元導入名の検証済みhash。
 * @param[in] selectedHash 成功時の選択節hash。拒否時は空。
 * @param[in] error 元HRESULT。成功時0。
 * @param[in] inventory 共通APIの全成功または空の拒否出力。
 * @return Path・ID・値を含まないJSON object。
 */
std::string selectionJson( const std::wstring &baseHash, const std::wstring &selectedHash,
						  drivercrate::NativeError						  error,
						  const drivercrate::OfficialInfInstallInventory &inventory)
{
	std::array<std::size_t, 8U> effects{} ;	// ADR 0264の作用enum順。
	std::array<std::size_t, 4U> present{} ;	// 同じ参照enum順のmetadata存在。
	std::array<std::size_t, 4U> missing{} ;	// 同じ参照enum順のmetadata欠落。
	// 宣言値やdirective名を出さず有限種類へ数える。
	for( const auto &effect : inventory.effects) {
		effects.at( static_cast<std::size_t>( effect.kind))++ ;
	}

	// Metadata存在と充足を混同しない二系列へ数える。
	for( const auto &reference : inventory.references) {
		(reference.targetPresent ? present : missing)
			.at( static_cast<std::size_t>( reference.kind))++ ;
	}

	std::string output = "{\"baseSectionSha256\":\"" + narrowHash( baseHash) +
						 "\",\"selectedSectionSha256\":\"" + narrowHash( selectedHash) +
						 "\",\"error\":" + std::to_string( error) +
						 ",\"sections\":" + std::to_string( inventory.visitedSections.size()) +
						 ",\"lines\":" + std::to_string( inventory.scannedLines) +
						 ",\"effects\":[" ;	// 値は固定schemaのみ。
	// 八作用の固定順序を維持する。
	for( std::size_t index = 0U; index < effects.size(); ++index) {
		output += (index == 0U ? "" : ",") + std::to_string( effects[index]) ;
	}

	output += "],\"presentReferences\":[" ;
	// 四参照の存在件数だけを出す。
	for( std::size_t index = 0U; index < present.size(); ++index) {
		output += (index == 0U ? "" : ",") + std::to_string( present[index]) ;
	}

	output += "],\"missingReferences\":[" ;
	// 欠落した参照も消さず固定順序で出す。
	for( std::size_t index = 0U; index < missing.size(); ++index) {
		output += (index == 0U ? "" : ",") + std::to_string( missing[index]) ;
	}

	return output + "]}" ;
}

// 独立targetだけで参照文脈を出力し、旧世代の固定JSONを変えない。
#if defined( DRIVERCRATE_INF_CONTEXT_OUTPUT)
/**
 * @brief 元節・対象hashと有限不足だけを選択JSONへ追加する。
 * @param[in] inventory 同期借用する全成功または空の共通結果。
 * @param[in,out] json 旧選択JSON。Hash全成功時だけ末尾objectへ追加する。
 * @return 完了0、hash生成失敗のHRESULT。失敗時はjsonを変更しない。
 * @note Include／Needs以外の参照とraw名称・directive・値は出力しない。
 */
drivercrate::NativeError appendSelectionContext(
	const drivercrate::OfficialInfInstallInventory &inventory, std::string &json)
{
	std::string extra = ",\"dependencyReferences\":[" ;	// 全hash成功時だけ結合する拡張。
	std::size_t count{} ;								// 重複も保持した依存辺数。
	// IncludeとNeedsを元節に結合し、同節以外から依存を補完しない。
	for( const auto &reference : inventory.references) {
		const bool included =
			reference.kind ==
			drivercrate::OfficialInfInstallReferenceKind::INCLUDE_INF ;	// INF参照。
		const bool needed =
			reference.kind == drivercrate::OfficialInfInstallReferenceKind::LOCAL_SECTION &&
			CompareStringOrdinal( reference.directive.c_str(), -1, L"Needs", -1, TRUE) ==
				CSTR_EQUAL ;	// 節参照。
		// 他directiveのローカル欠落をNeedsとして数えない。
		if( !included && !needed) {
			continue ;
		}

		std::wstring			 sourceHash ;											// worker内元節の原UTF-16LE hash。
		std::wstring			 targetHash ;											// worker内参照先の原UTF-16LE hash。
		drivercrate::NativeError error = sectionHash( reference.section, sourceHash) ;	// 元節結合。
		// Hash不成立の辺を削除して部分出力しない。
		if( error != 0) {
			return error ;
		}

		error = sectionHash( reference.target, targetHash) ;
		// 対象のhash生成にも全成功を要求する。
		if( error != 0) {
			return error ;
		}

		extra += (count++ == 0U ? "" : ",") + std::string( "{\"sectionSha256\":\"") +
				 narrowHash( sourceHash) + "\",\"targetSha256\":\"" + narrowHash( targetHash) +
				 "\",\"directive\":" + (included ? "0" : "1") +
				 ",\"targetPresent\":" + (reference.targetPresent ? "true" : "false") + "}" ;
	}

	extra += "],\"coverageGaps\":[" ;
	count = 0U ;
	// 本文を出さず、不足を元節hashと有限種類へ縮約する。
	for( const auto &gap : inventory.coverageGaps) {
		std::wstring				   sourceHash ;	// 不足がある元節の非秘密identity。
		const drivercrate::NativeError error =
			// 値は保持しない。
			sectionHash( gap.section, sourceHash) ;
		// 一つの不足でも結合不能なら拡張全体を破棄する。
		if( error != 0) {
			return error ;
		}

		extra += (count++ == 0U ? "" : ",") + std::string( "{\"sectionSha256\":\"") +
				 narrowHash( sourceHash) +
				 "\",\"kind\":" + std::to_string( static_cast<std::size_t>( gap.kind)) + "}" ;
	}

	json.pop_back() ;
	json += extra + "]}" ;
	return 0 ;
}
#endif	// defined(DRIVERCRATE_INF_CONTEXT_OUTPUT)

/**
 * @brief 明示ZIPの一INFを保護copy・共通棚卸しへ接続する。
 * @param[in] count 実行名を含む引数数。六個だけを受理する。
 * @param[in] arguments Local path・archive hash・size・INF相対path・INF hash。
 * @return 列挙完了0、全体検査拒否1、CLI形式不正2。
 * @note 各導入名の拒否は完了結果へ含める。実deviceの選択を表さない。
 */
int inspect( const int count, wchar_t **arguments)
{
	std::uint64_t expectedBytes{} ;	// CLI期待byte数。
	// 不正引数をechoしたり任意fileへ操作したりしない。
	if( count != 6 || !validHash( arguments[2]) || !parseBytes( arguments[3], expectedBytes) ||
	   !validHash( arguments[5])) {
		return 2 ;
	}

	const std::wstring						 archiveHash( arguments[2]) ;	// 検証済み原ZIP期待hash。
	const std::wstring						 infHash( arguments[5]) ;		// 検証済み選択INF期待hash。
	drivercrate::OfficialDownloadWorkspace	 archiveWorkspace ;				// 不変入力copy所有者。
	drivercrate::OfficialDownloadWorkspace	 infWorkspace ;					// 一INFだけの保護展開所有者。
	drivercrate::DriverArchiveInput			 input ;						// 共通copyが生成するidentity。
	drivercrate::OfficialDriverArchiveFormat format{} ;						// ZIP以外は拒否する。
	drivercrate::NativeError				 error = drivercrate::copyLocalDriverArchive(
		arguments[1], 6401U, archiveWorkspace, input, format) ;	// 元fileは実行しない。
	bool		bound = false ;									// 実archiveの期待identity一致だけを表す。
	std::string selections ;									// 全体成功時だけ出力する非秘密観測。
	std::size_t selectionCount{} ;								// 成功と個別拒否を含む導入名数。
	std::size_t inventoried{} ;									// 共通棚卸し成功数。内容署名数ではない。
	// Copy成功でも期待identity・ZIP形式が違えば棚卸しへ進まない。
	if( error == 0 && (format != drivercrate::OfficialDriverArchiveFormat::ZIP ||
					  input.byteCount != expectedBytes || input.sha256 != archiveHash)) {
		error = E_INVALIDARG ;
	}

	// 全体失敗まで単一のscope内で保護入力を所有する。
	if( error == 0) {
		bound = true ;
		std::vector<char> raw ;	// 最大128 MiBの保護原ZIP。
		error = readArchive( input, raw) ;
		std::vector<drivercrate::OfficialZipEntry> entries ;	// 全ZIPのmetadataだけ。
		// 全entryのpreflightを省略して指定INFだけを読むことを禁止する。
		if( error == 0) {
			error =
				drivercrate::inspectOfficialZip( std::as_bytes( std::span( raw)), ZIP_POLICY, entries) ;
		}

		const std::wstring infPath( arguments[4]) ;	// 出力しないworker内相対path。
		const auto		   entry = std::ranges::find_if( entries, [&infPath]( const auto &item) {
			// 相対pathの完全一致だけを選び、表示名から推測しない。
			return item.relativePath == infPath ;
		}) ;
		// 欠落・非INF・過大INFの実物測定を開始しない。
		if( error == 0 &&
		   (entry == entries.end() || entry->uncompressedSize == 0U ||
			entry->uncompressedSize > 4ULL * 1024ULL * 1024ULL || infPath.size() < 4U ||
			CompareStringOrdinal( infPath.c_str() + infPath.size() - 4U, 4, L".inf", 4, TRUE) !=
				CSTR_EQUAL)) {
			error = E_INVALIDARG ;
		}

		// 書込みは新規保護領域の指定INFだけに限定する。
		if( error == 0) {
			error = infWorkspace.initialize( L"selected-inf-inventory", 6401U) ;
		}

		std::vector<drivercrate::OfficialZipEntry> extracted ;	// 実展開INFのhash保持。
		// 非選択fileはmetadataだけで、DLL・EXE・SYSを展開しない。
		if( error == 0) {
			const std::array<std::wstring_view, 1U> selected{infPath} ;	// 一意の指定INF。
			error = drivercrate::extractOfficialZipFiles( std::as_bytes( std::span( raw)), ZIP_POLICY,
														 selected, infWorkspace, extracted) ;
		}

		// INF指定を表示名だけで受理せず原hashへ結合する。
		if( error == 0 && (extracted.size() != 1U || extracted.front().sha256 != infHash)) {
			error = E_INVALIDARG ;
		}

		std::vector<std::wstring> bases ;	// 現OS Modelsの一意導入名のみ。
		// INF自身の実hashをmetadataへ固定して現在Modelsを列挙する。
		if( error == 0) {
			entry->sha256 = infHash ;
			error		  = currentInstallBases( infWorkspace.path( infPath), bases) ;
		}

		// 各導入名の拒否を分母へ残し、共通処理だけで作用を調べる。
		for( const std::wstring &base : bases) {
			std::wstring baseHash ;	// 導入名の非秘密identity。
			error = sectionHash( base, baseHash) ;
			// Hash失敗時は全ての部分観測を破棄する。
			if( error != 0) {
				break ;
			}

			drivercrate::OfficialInfInstallInventory inventory ;	// 共通処理が有限に所有する一選択。
			const drivercrate::NativeError			 selectedError =
				drivercrate::inspectOfficialInfInstallInventory(
					infWorkspace, entries, infPath, base, inventory) ;	// 通常導入拒否と別軸。
			std::wstring selectedHash ;									// 成功時だけの選択節identity。
			// 共通成功を署名や導入へ昇格せず、選択節hashだけを作る。
			if( selectedError == 0) {
				error = sectionHash( inventory.selectedInstallSection, selectedHash) ;
				// 出力identityを作れない部分成功は全体拒否とする。
				if( error != 0) {
					break ;
				}

				++inventoried ;
			}

			std::string selectedJson =
				// 旧固定観測。
				selectionJson( baseHash, selectedHash, selectedError, inventory) ;
			// Context世代だけで追加hashを生成し、旧v1を拡張schemaへ読み替えない。
#if defined( DRIVERCRATE_INF_CONTEXT_OUTPUT)
			error = appendSelectionContext( inventory, selectedJson) ;
			constexpr std::size_t MAXIMUM_SELECTION_JSON_BYTES =
				2U * 1024U * 1024U - 2048U ;	// Header余裕を除く上限。
			// Hash失敗・総出力超過では全体を拒否し、選択の切捨てを行わない。
			if( error != 0 || selectedJson.size() + 1U > MAXIMUM_SELECTION_JSON_BYTES ||
			   selections.size() > MAXIMUM_SELECTION_JSON_BYTES - selectedJson.size() - 1U) {
				error = error != 0 ? error : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				break ;
			}
#endif	// defined(DRIVERCRATE_INF_CONTEXT_OUTPUT)
			selections += (selectionCount == 0U ? "" : ",") + selectedJson ;
			++selectionCount ;
		}

		// 同期処理完了後にも実ZIPとINFのidentityを再照合する。
		if( error == 0) {
			error = drivercrate::verifyOfficialFileMetadata( input.inspectionPath,
															{expectedBytes, archiveHash}) ;
		}

		// 個別失敗後でも展開元INFの変更を全体拒否にする。
		if( error == 0) {
			error = drivercrate::verifyOfficialFileMetadata( infWorkspace.path( infPath),
															{entry->uncompressedSize, infHash}) ;
		}
	}

	// 全体失敗時は部分作用・部分選択を出さない。
	if( error != 0) {
		selections.clear() ;
		selectionCount = 0 ;
		inventoried	   = 0 ;
	}

	const std::string output =
	// 独立compile定義のschemaだけでhash集合を公開する。
#if defined( DRIVERCRATE_INF_CONTEXT_OUTPUT)
		"{\"schema\":\"dc-selected-inf-context-observation-v1\","
#else
		"{\"schema\":\"dc-selected-inf-inventory-observation-v1\","
#endif	// defined(DRIVERCRATE_INF_CONTEXT_OUTPUT)
		"\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,"
		"\"applicability\":\"NOT_CHECKED\",\"archiveSha256\":\"" +
		narrowHash( archiveHash) + "\",\"archiveBytes\":" + std::to_string( expectedBytes) +
		",\"infSha256\":\"" + narrowHash( infHash) +
		"\",\"inputBound\":" + (bound ? "true" : "false") + ",\"state\":\"" +
		(error == 0 ? "INVENTORY_COMPLETED" : "REJECTED") +
		"\",\"error\":" + std::to_string( error) +
		",\"selectionCount\":" + std::to_string( selectionCount) +
		",\"inventoriedSelections\":" + std::to_string( inventoried) + ",\"selections\":[" +
		selections + "]}\n" ;	// 固定metadataと件数だけ。
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ? (error == 0 ? 0 : 1)
																			  : 2 ;
}

/** @brief 同SHAの明示ZIPを通常内容・実rank・bindingへ非通信で通します。
 * @param[in] count OS引数数です。
 * @param[in] arguments mode、local ZIP、SHA-256、byte数の固定入力です。借用し出力しません。
 * @return 全観測完了と適合binding成功0、拒否1、引数不正2です。
 */
int inspectBinding( const int count, wchar_t **arguments)
{
	std::uint64_t expectedBytes{} ;	// 元ZIPの期待byte数です。
	// pathや不正入力をechoせず明示された固定identityだけを扱います。
	if( count != 5 || !validHash( arguments[3]) || !parseBytes( arguments[4], expectedBytes)) {
		return 2 ;
	}

	drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// 同threadのCOM寿命です。
	// COMの初期化失敗をread-only成功へ変換しません。
	if( FAILED( apartment.result())) {
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace	 workspace ;	// 元ZIPの不変copyです。
	drivercrate::DriverArchiveInput			 input ;		// 実copyが生成したidentityです。
	drivercrate::OfficialDriverArchiveFormat format{} ;		// ZIP以外は拒否します。
	// 原fileのコピー結果を元診断として保持します。
	auto error = drivercrate::copyLocalDriverArchive( arguments[2], 6402U, workspace, input, format) ;
	// 保存済み入力は原hash/size一致を必須とし、公式権限へ昇格しません。
	if( error == 0U && (input.sha256 != arguments[3] || input.byteCount != expectedBytes ||
					   format != drivercrate::OfficialDriverArchiveFormat::ZIP)) {
		error = E_INVALIDARG ;
	}

	drivercrate::CommonDriverPackageInspection inspection ;	// 元全INFの内容分母です。
	// 既存共通署名・全参照byte検査だけを使用します。
	if( error == 0U) {
		error = drivercrate::inspectCommonDriverPackage( input, format, inspection) ;
	}

	drivercrate::DriverStoreProvider store ;	// 同threadの実端末snapshot所有者です。
	drivercrate::ScanResult			 scan ;		// 端末内でだけ参照する現在行です。
	// 内容検査失敗後に無関係な端末列挙を行いません。
	if( error == 0U) {
		scan  = store.scan( 6402U, {}, []( const drivercrate::ProviderProgress &) {
			 // 診断は同期read-only進捗を受け取り、端末属性を保存しません。
		 }) ;
		error = scan.succeeded ? 0U : (scan.error != 0U ? scan.error : E_FAIL) ;
	}

	std::size_t verified{} ;	// 全内容合格数です。適合数ではありません。
	std::size_t examined{} ;	// 一意なINF/deviceの実rank照合数です。
	std::size_t applicable{} ;	// 完全rank適合数です。
	std::size_t bound{} ;		// 診断scope内だけのbinding成功数です。
	// 全元INFを元順のordinalに保ち、欠落や失敗を分母から取り除きません。
	for( std::size_t ordinal = 0U; error == 0U && ordinal < inspection.infs.size(); ++ordinal) {
		const auto &inf = inspection.infs[ordinal] ;	// 同元保護閉包です。
		// 内容拒否をrank成功の入力へ使用しません。
		if( inf.state != drivercrate::CommonInfInspectionState::VERIFIED || inf.error != 0U) {
			continue ;
		}

		++verified ;
		const auto &package = inf.closure.packages.front() ;	// 同検査の主INFです。
		// 追加役割を独立基本driverへ変換しません。
		if( package.role != drivercrate::DriverPlanRole::BASE_DRIVER) {
			continue ;
		}

		std::vector<std::wstring> devices ;	// 同現在snapshotに一致するopaqueだけです。
		// 公開catalog側のIDをworker内mapへ照合し、networkや出力へ渡しません。
		for( const auto &id : package.hardwareIds) {
			const auto device = store.deviceIdentityForHardwareId( id) ;	// 同scanの一意な対応です。
			// 複数modelが同deviceへ一致しても一pairだけを検査します。
			if( device && std::ranges::find( devices, *device) == devices.end()) {
				devices.push_back( *device) ;
			}
		}

		// 同内容に一致する有限deviceだけを同Windows APIへ渡します。
		for( const auto &device : devices) {
			const auto current = std::ranges::find_if( scan.candidates, [&]( const auto &row) {
				return row.current && row.deviceIdentity == device ;
			}) ; // 同scanだけを同期借用します。
			// private binding予算と同scan現在行の存在を必須とします。
			if( examined >= 131072U || current == scan.candidates.end()) {
				error = E_UNEXPECTED ;
				break ;
			}

			++examined ;
			drivercrate::OfficialDriverRankAudit audit ;	// 実Windows完全rank結果です。
			// 同実INF/deviceの元API診断だけを保持します。
			const auto							 rankError =
				store.auditOfficialInfRank( 6402U, device, *inf.workspace, package, audit) ;
			// API完了だけで適合へ昇格しません。
			if( rankError != 0U ||
			   audit.decision != drivercrate::OfficialDriverRankDecision::APPLICABLE) {
				continue ;
			}

			++applicable ;
			drivercrate::RequiredInfBindingDiagnostic stage ;	// 生情報のない拒否段階です。
			// 元bindingから返るHRESULTを結果件数と区別します。
			const auto								  bindingError =
				drivercrate::DriverStoreBindingProbe::inspect( store, *current, inf, audit, stage) ;
			bound += bindingError == 0U ? 1U : 0U ;
			const bool selected =
				CompareStringOrdinal( inf.infRelativePath.c_str(), -1,
									 L"PRO2500\\Winx64\\W11\\e2fn.inf", -1,
									 TRUE) == CSTR_EQUAL ;	// 公表済み選択の一致だけです。
			std::printf(
				"{\"infOrdinal\":%zu,\"selectedInf\":%d,\"requiredInfCount\":%zu,"
				"\"externalDependencies\":%d,\"includeNeeds\":%d,\"requiredBranch\":%d,"
				"\"stage\":%u,\"bindingError\":%u,\"referencesResolved\":%d,"
				"\"rootEvidenceVerified\":%d,\"unresolvedReferences\":%zu,\"firstReferenceReason\":%u,"
				"\"rootSignatureError\":%u,\"firstDependencySignatureError\":%u,"
				"\"firstDependencyProvenanceError\":%u,\"verifiedRegistryRows\":%zu}\n",
				ordinal, selected ? 1 : 0, inf.requiredInfPackages.size(),
				package.hasExternalDependencies ? 1 : 0, package.unresolvedIncludeNeeds ? 1 : 0,
				package.hasExternalDependencies || !inf.requiredInfPackages.empty() ? 1 : 0,
				stage.stage, bindingError, stage.referencesResolved ? 1 : 0,
				stage.rootEvidenceVerified ? 1 : 0, stage.unresolvedReferenceCount,
				stage.firstReferenceReason, stage.rootSignatureError,
				stage.firstDependencySignatureError, stage.firstDependencyProvenanceError,
				stage.verifiedRegistryRowCount) ;
		}
	}

	std::printf( "{\"schema\":\"dc-local-binding-probe-v1\",\"newGet\":false,"
				"\"normalUiSuccess\":false,\"installAuthorized\":false,\"error\":%u,"
				"\"totalInfs\":%zu,\"verifiedInfs\":%zu,\"examinedPairs\":%zu,"
				"\"applicablePairs\":%zu,\"bindingSucceededPairs\":%zu}\n",
				error, inspection.infs.size(), verified, examined, applicable, bound) ;
	return std::fflush( stdout) == 0 && error == 0U && applicable != 0U && bound == applicable ? 0
																							  : 1 ;
}

} // namespace

/**
 * @brief 例外をCLI境界で止め、部分結果を出さない。
 * @param[in] count OS引数数。
 * @param[in] arguments OS所有の引数列。本呼出し中だけ借用する。
 * @return 完了0、検査拒否1、引数・例外・出力失敗2。
 */
int wmain( const int count, wchar_t **arguments)
{
	try {
		// 明示local診断だけがread-only端末照合へ進み、旧棚卸し入口は維持します。
		if( count > 1 && std::wstring_view( arguments[1]) == L"--binding-probe") {
			return inspectBinding( count, arguments) ;
		}

		return inspect( count, arguments) ;
	} catch( ...) {
		// 詳細pathを出さず失敗終了値で例外を保持する。
		return 2 ;
	}
}
