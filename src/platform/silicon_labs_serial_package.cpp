//------------------------------------------------------------------------------
/**
 * @file silicon_labs_serial_package.cpp
 * @brief Silicon Labs CP210x署名済みINF ZIP検証実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  同一familyの新版受入追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  保護workspace tag上限適合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note CP210xの審査済み標準ID集合、Windows x64参照file、WHCP CAT memberを検証します。選択ZIPの入手元そのものは証明しません。
 */
//------------------------------------------------------------------------------

#include "platform/silicon_labs_serial_package.h"

#include "platform/official_download_workspace.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <ranges>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES	  = 1ULL * 1024ULL * 1024ULL ;	// ZIP入力上限。
constexpr std::uint64_t MAXIMUM_SINGLE_FILE_BYTES = 256ULL * 1024ULL ;			// 一file上限。
constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES	  = 1ULL * 1024ULL * 1024ULL ;	// 全展開上限。
constexpr std::uint32_t MAXIMUM_ENTRY_COUNT		  = 32U ;						// Directoryを含む全entry上限。
constexpr std::size_t	MAXIMUM_INF_COUNT		  = 1U ;						// 固定package内のINF数上限。

constexpr OfficialZipExtractionPolicy ZIP_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // CP210x公式ZIP全体へ適用する有限上限。

constexpr std::array SELECTED_FILES{std::wstring_view( L"silabser.inf"),
									std::wstring_view( L"silabser.cat"),
									// Windows x64導入に必要な固定file群。
									std::wstring_view( L"x64\\silabser.sys")} ;
constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Ports")} ;	// 許可setup class。
constexpr std::array ACCEPTED_PROVIDERS{								// 許可INF Provider。
										std::wstring_view( L"Silicon Laboratories Inc.")} ;
constexpr std::array ACCEPTED_INF_SIGNATURES{	// CP210x Universal INF signature。
											 std::wstring_view( L"$WINDOWS NT$")} ;
constexpr std::array ACCEPTED_SIGNERS{
	// CAT signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;
constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds = 32U,
	.maximumSourceFiles = 8U,
	.acceptedClasses	= ACCEPTED_CLASSES,
	.acceptedProviders	= ACCEPTED_PROVIDERS,
	.acceptedSignatures = ACCEPTED_INF_SIGNATURES,
} ; // CP210x Ports INFの構造policy。

constexpr std::array ACCEPTED_HARDWARE_IDS{
	std::wstring_view( L"USB\\VID_10C4&PID_EA60"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA63"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA70&MI_00"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA70&MI_01"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA71&MI_00"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA71&MI_01"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA71&MI_02"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA71&MI_03"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA7A&MI_00"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA7A&MI_01"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA7B&MI_00"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA7B&MI_01"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA7B&MI_02"),
	std::wstring_view( L"USB\\VID_10C4&PID_EA7B&MI_03"),
} ; // CP210x 11.5.0のNTamd64 model sectionにある標準PnP ID群。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII英字を小文字へ変換する。
 *
 * Localeに依存しないPnP IDとpath比較に使用する。
 *
 * @param[in] character 比較対象の一文字。
 * @return ASCII英大文字は小文字、それ以外は入力値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] constexpr wchar_t asciiLower( const wchar_t character) noexcept
{
	return character >= L'A' && character <= L'Z' ? static_cast<wchar_t>( character - L'A' + L'a')
												  : character ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字列を大文字小文字を区別せず比較する。
 *
 * 部分一致やlocale依存のcase foldingを許可しない。
 *
 * @param[in] left 左辺文字列。
 * @param[in] right 右辺文字列。
 * @return ASCII英字の大小を除いて完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	return left.size() == right.size() &&
		   std::ranges::equal(
			   left, right, []( const wchar_t leftCharacter, const wchar_t rightCharacter) noexcept {
				   return asciiLower( leftCharacter) == asciiLower( rightCharacter) ;
			   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathの最後のfile名を取得する。
 *
 * 固定INFとCATのfile名をdirectoryから分離する。
 *
 * @param[in] path ZIP検証済み相対path。
 * @return 最後のseparatorより後ろのfile名。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view fileName( const std::wstring_view path) noexcept
{
	const std::size_t separator = path.find_last_of( L"\\/") ;	// 最後のpath separator。
	return separator == std::wstring_view::npos ? path : path.substr( separator + 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CP210xのDriverVer形式を検証する。
 *
 * 版の大小から適用性を判定せず、構文だけを検証する。
 *
 * @param[in] package 構造検証済みPorts class INF。
 * @return 実在日付と4個の16bit版要素がある場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validDriverVer( const OfficialInfPackage &package)
{
	const std::wstring_view date = package.driverDate ;	// MM/DD/YYYY形式の検証対象。
	// 不明な日付形式をfamilyの新版として受理しない。
	if( date.size() != 10U || date[2] != L'/' || date[5] != L'/') {
		return false ;
	}

	// Separator以外をASCII数字へ限定し、後続の数値変換を有限にする。
	for( std::size_t index = 0; index < date.size(); ++index) {
		// DriverVer の日付区切り以外に十進数字でない文字がある場合は拒否する。
		if( index != 2U && index != 5U && (date[index] < L'0' || date[index] > L'9')) {
			return false ;
		}
	}

	const unsigned month = static_cast<unsigned>( (date[0] - L'0') * 10 + date[1] - L'0') ;	// 月。
	const unsigned day	 = static_cast<unsigned>( (date[3] - L'0') * 10 + date[4] - L'0') ;	// 日。
	const int	   year = (date[6] - L'0') * 1000 + (date[7] - L'0') * 100 + (date[8] - L'0') * 10 +
					 date[9] - L'0' ;	// 西暦年。
	// Windows日付範囲外と存在しない日付を拒否する。
	if( year < 1601 || !std::chrono::year_month_day{std::chrono::year{year},
												   std::chrono::month{month}, std::chrono::day{day}}
						   .ok()) {
		return false ;
	}

	const std::wstring_view version = package.driverVersion ;	// 数字4要素の版。
	// 空または表記上限を超える DriverVer version を拒否する。
	if( version.empty() || version.size() > 23U) {
		return false ;
	}

	unsigned components{} ;	// 完了した16bit要素数。
	unsigned value{} ;		// 現在要素の値。乗算前に65535以下を検証する。
	unsigned digits{} ;		// 現在要素の桁数。空要素を拒否する。
	// 有限長のDriverVerを走査し、符号、空白、suffixを許可しない。
	for( const wchar_t character : version) {
		// Dot ごとに version 成分を確定し、次の数値を読み始める。
		if( character == L'.') {
			// 空成分と許可成分数を超える区切りを拒否する。
			if( digits == 0U || ++components > 3U) {
				return false ;
			}

			value  = 0U ;
			digits = 0U ;
		} else {
			// Version の非数字と単一成分の五桁超過を拒否する。
			if( character < L'0' || character > L'9' || ++digits > 5U) {
				return false ;
			}

			value = value * 10U + static_cast<unsigned>( character - L'0') ;
			// Version 成分の数値が 16-bit 上限を超えた場合は拒否する。
			if( value > 65535U) {
				return false ;
			}
		}
	}

	return components == 3U && digits != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief CP210x familyの固定構造と可変DriverVerを照合する。
 *
 * 版更新だけを許可し、未知IDやfile構成の追加は拒否する。
 *
 * @param[in] package 構造検証済みINF metadata。
 * @return 審査済みfamilyの全条件が一致する場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSiliconLabsSerialPackage( const OfficialInfPackage &package)
{
	// INF・CAT・class・publisher・版・ID 件数・参照 SYS の固定条件を全て必須とする。
	if( !asciiEqual( fileName( package.infRelativePath), L"silabser.inf") ||
	   !asciiEqual( fileName( package.catalogRelativePath), L"silabser.cat") ||
	   !asciiEqual( package.className, L"Ports") ||
	   !asciiEqual( package.providerName, L"Silicon Laboratories Inc.") ||
	   !validDriverVer( package) || package.hardwareIds.size() != ACCEPTED_HARDWARE_IDS.size() ||
	   package.sourceFiles.size() != 1U ||
	   !asciiEqual( package.sourceFiles.front(), L"x64\\silabser.sys")) {
		return false ;
	}

	// 標準IDが各一件だけ存在することを検証し、重複による欠落の隠蔽も拒否する。
	return std::ranges::all_of(
		ACCEPTED_HARDWARE_IDS, [&package]( const std::wstring_view accepted) noexcept {
			return std::ranges::count_if( package.hardwareIds,
										 [accepted]( const std::wstring &actual) {
											 return asciiEqual( actual, accepted) ;
										 }) == 1 ;
		}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Silicon Labs固有の利用者選択ZIP policyを返す。
 *
 * ZIP全体を検査し、x64導入に必要な3 fileだけを展開する。
 * @return Process lifetime中有効なCP210x family固有policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const UserSelectedInfPackagePolicy &siliconLabsPackagePolicy() noexcept
{
	static constexpr UserSelectedInfPackagePolicy POLICY{
		.workspaceTag			   = L"silabs-serial-package",
		.zipPolicy				   = ZIP_POLICY,
		.maximumInfCount		   = MAXIMUM_INF_COUNT,
		.maximumNestedArchiveCount = 0U,
		.archiveSubdirectory	   = {},
		.archiveSelectedFiles	   = SELECTED_FILES,
		.integrityMode			   = UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS,
		.acceptedArchiveSha256	   = {},
		.embeddedSignatureFiles	   = {},
		.infPolicy				   = INF_POLICY,
		.signers				   = ACCEPTED_SIGNERS,
		.packagePredicate		   = isSiliconLabsSerialPackage,
	} ; // 同一familyの新版を許可し、署名と固定構造を維持するpolicy。
	return POLICY ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/silicon_labs_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isSiliconLabsSerialPackageFamily( const OfficialInfPackage &package)
{
	return isSiliconLabsSerialPackage( package) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/silicon_labs_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isSiliconLabsSerialCandidateHardwareId( const std::wstring_view hardwareId) noexcept
{
	return std::ranges::any_of( ACCEPTED_HARDWARE_IDS,
							   [hardwareId]( const std::wstring_view accepted) noexcept {
								   return asciiEqual( hardwareId, accepted) ;
							   }) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/silicon_labs_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectSiliconLabsSerialPackageFile( const std::wstring_view			  selectedPath,
												const ScanSessionId				  scanSessionId,
												OfficialDownloadWorkspace		 &workspace,
												SiliconLabsSerialPackageContents &contents)
{
	return inspectUserSelectedInfPackageFile( selectedPath, scanSessionId,
											 siliconLabsPackagePolicy(), workspace, contents) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/silicon_labs_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifySiliconLabsSerialInfPackage( const OfficialDownloadWorkspace		   &workspace,
												const std::span<const OfficialZipEntry> entries,
												const OfficialInfPackage			   &expected)
{
	return reverifyUserSelectedInfPackage( workspace, entries, expected, siliconLabsPackagePolicy()) ;
}

} // namespace drivercrate
