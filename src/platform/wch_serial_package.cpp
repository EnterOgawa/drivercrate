//------------------------------------------------------------------------------
/**
 * @file wch_serial_package.cpp
 * @brief WCH USB serial署名済みINF ZIP検証実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定公式ZIP SHA-256検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CH342／CH343系package検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式ZIP全体を未信頼入力として事前検査し、製品familyごとの固定directory内にある現行x64 INF packageだけを選択します。Setup executableは
 *       展開・実行せず、不一致時は候補を一件も返しません。
 */
//------------------------------------------------------------------------------

#include "platform/wch_serial_package.h"

#include "platform/official_download_workspace.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES =
	4ULL * 1024ULL * 1024ULL ;	// CH341SER入力ZIPの最大byte数。
constexpr std::uint64_t MAXIMUM_SINGLE_FILE_BYTES =
	1024ULL * 1024ULL ;	// CH341SER内の一通常fileの最大byte数。
constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES =
	8ULL * 1024ULL * 1024ULL ;										// CH341SER全entryの最大展開後byte数。
constexpr std::uint32_t		MAXIMUM_ENTRY_COUNT			 = 64U ;	// 公式ZIP全体のentry数上限。
constexpr std::size_t		MAXIMUM_INF_COUNT			 = 1U ;		// 選択directoryのINF数上限。
constexpr std::size_t		MAXIMUM_HARDWARE_IDS_PER_INF = 16U ;	// WCH INFのPnP ID数上限。
constexpr std::size_t		MAXIMUM_SOURCE_FILES_PER_INF = 32U ;	// WCH INFの参照file数上限。
constexpr std::wstring_view SELECTED_SUBDIRECTORY =
	L"CH341SER\\WIN 1X" ;	// 公式ZIP内で現行Windows packageを保持する固定directory。

constexpr OfficialZipExtractionPolicy ZIP_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // WCH公式ZIP全体へ適用する有限展開上限。

constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Ports")} ;		// 許可setup class。
constexpr std::array ACCEPTED_PROVIDERS{std::wstring_view( L"wch.cn")} ;	// 許可INF Provider。
constexpr std::array ACCEPTED_INF_SIGNATURES{								// WCH公式INFが使用するSignature。
											 std::wstring_view( L"$CHICAGO$")} ;
constexpr std::array ACCEPTED_SIGNERS{
	// CAT signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;
constexpr std::array ACCEPTED_ARCHIVE_SHA256{
	std::wstring_view( L"59967d9ce371d0bf3df02dec0b66c8dfbf9ca576da0572ff4404148a7c381807"),
} ; // 公式CH341SER 4.0 ZIPを審査時の全byteへ固定するSHA-256 allowlist。
constexpr std::array EMBEDDED_SIGNATURE_FILES{
	std::wstring_view( L"CH341SER\\WIN 1X\\CH341S64.sys"),
	std::wstring_view( L"CH341SER\\WIN 1X\\CH341PTA64.DLL"),
	std::wstring_view( L"CH341SER\\WIN 1X\\CH341PORTSA64.DLL"),
	std::wstring_view( L"CH341SER\\WIN 1X\\CH341PT.DLL"),
} ; // NTamd64 install sectionが参照し、WHCP埋込み署名を必須にする固定file群。

constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds = MAXIMUM_HARDWARE_IDS_PER_INF,
	.maximumSourceFiles = MAXIMUM_SOURCE_FILES_PER_INF,
	.acceptedClasses	= ACCEPTED_CLASSES,
	.acceptedProviders	= ACCEPTED_PROVIDERS,
	.acceptedSignatures = ACCEPTED_INF_SIGNATURES,
} ; // WCH CH341SER INFへ適用する構造policy。

constexpr std::array ACCEPTED_HARDWARE_IDS{
	std::wstring_view( L"USB\\VID_1A86&PID_7523"),
	std::wstring_view( L"USB\\VID_1A86&PID_5523"),
	std::wstring_view( L"USB\\VID_1A86&PID_7522"),
	std::wstring_view( L"USB\\VID_1A86&PID_E523"),
	std::wstring_view( L"USB\\VID_4348&PID_5523"),
	std::wstring_view( L"USB\\VID_4348&PID_5523&REV_0250"),
} ; // WCH署名済みCH341SER INF 4.0が明示するPnP ID allowlist。

constexpr std::array REQUIRED_X64_FILES{
	std::wstring_view( L"ch341s64.sys"),
	std::wstring_view( L"ch341pta64.dll"),
	std::wstring_view( L"ch341portsa64.dll"),
	std::wstring_view( L"ch341pt.dll"),
} ; // NTamd64 install sectionが参照する必須binary名。
constexpr std::wstring_view ACCEPTED_DRIVER_DATE = L"02/11/2026" ;	// 固定ZIP内のDriverVer日付。
constexpr std::wstring_view ACCEPTED_DRIVER_VERSION =
	L"4.0.2026.02" ;	// 固定ZIP内のDriverVer version。

constexpr std::uint64_t MULTI_MAXIMUM_ARCHIVE_BYTES =
	4ULL * 1024ULL * 1024ULL ;	// CH343SER入力ZIPの最大byte数。
constexpr std::uint64_t MULTI_MAXIMUM_SINGLE_FILE_BYTES =
	1024ULL * 1024ULL ;	// CH343SER内の一通常fileの最大byte数。
constexpr std::uint64_t MULTI_MAXIMUM_EXPANDED_BYTES =
	8ULL * 1024ULL * 1024ULL ;											// CH343SER全entryの最大展開後byte数。
constexpr std::uint32_t		MULTI_MAXIMUM_ENTRY_COUNT = 64U ;			// CH343SER公式ZIP全体のentry数上限。
constexpr std::size_t		MULTI_MAXIMUM_INF_COUNT	  = 1U ;			// 固定directoryのINF数上限。
constexpr std::size_t		MULTI_MAXIMUM_HARDWARE_IDS_PER_INF = 64U ;	// 固定INFのPnP ID数上限。
constexpr std::size_t		MULTI_MAXIMUM_SOURCE_FILES_PER_INF = 32U ;	// 固定INFの参照file数上限。
constexpr std::wstring_view MULTI_SELECTED_SUBDIRECTORY =
	L"CH343SER\\Driver\\WIN 1X" ;	// CH343SER 2.2の現行Windows固定directory。

constexpr OfficialZipExtractionPolicy MULTI_ZIP_POLICY{
	.maximumArchiveBytes	   = MULTI_MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MULTI_MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MULTI_MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MULTI_MAXIMUM_ENTRY_COUNT,
} ; // CH343SER公式ZIP全体へ適用する有限展開上限。

constexpr std::array MULTI_ACCEPTED_ARCHIVE_SHA256{
	std::wstring_view( L"6084fd47cc2a6bf27eb3df3a6f57430ec8a3fa69d8f32dc9c6f6807816a15e57"),
} ; // 公式CH343SER 2.2 ZIPを審査時の全byteへ固定するSHA-256 allowlist。
constexpr std::array MULTI_EMBEDDED_SIGNATURE_FILES{
	std::wstring_view( L"CH343SER\\Driver\\WIN 1X\\CH343S64.sys"),
	std::wstring_view( L"CH343SER\\Driver\\WIN 1X\\CH343PTA64.DLL"),
	std::wstring_view( L"CH343SER\\Driver\\WIN 1X\\CH343PORTSA64.DLL"),
	std::wstring_view( L"CH343SER\\Driver\\WIN 1X\\CH343PT.DLL"),
} ; // NTamd64 install sectionが参照し、WHCP埋込み署名を必須にする固定file群。

constexpr OfficialInfInspectionPolicy MULTI_INF_POLICY{
	.maximumHardwareIds = MULTI_MAXIMUM_HARDWARE_IDS_PER_INF,
	.maximumSourceFiles = MULTI_MAXIMUM_SOURCE_FILES_PER_INF,
	.acceptedClasses	= ACCEPTED_CLASSES,
	.acceptedProviders	= ACCEPTED_PROVIDERS,
	.acceptedSignatures = ACCEPTED_INF_SIGNATURES,
} ; // WCH CH343SER INFへ適用する構造policy。

constexpr std::array MULTI_ACCEPTED_HARDWARE_IDS{
	std::wstring_view( L"USB\\VID_1A86&PID_55D2&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D2&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D3"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D4"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D5&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D5&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D5&MI_04"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D5&MI_06"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D6"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D7&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D7&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55D8"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DA&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DA&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DB&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DD&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DE&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DE&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DF&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DF&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DF&MI_04"),
	std::wstring_view( L"USB\\VID_1A86&PID_55DF&MI_06"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E7&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E7&MI_01"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E8&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E8&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E8&MI_04"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E8&MI_06"),
	std::wstring_view( L"USB\\VID_1A86&PID_55E9"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EA&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EA&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EB&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EC&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EC&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EF&MI_00"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EF&MI_02"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EF&MI_04"),
	std::wstring_view( L"USB\\VID_1A86&PID_55EF&MI_06"),
	std::wstring_view( L"USB\\VID_1A86&PID_5610&MI_01"),
	std::wstring_view( L"USB\\VID_1A86&PID_7523&REV_8234"),
} ; // CH343SER 2.2のNTamd64 model sectionが明示するPnP ID allowlist。

constexpr std::array MULTI_REQUIRED_X64_FILES{
	std::wstring_view( L"ch343s64.sys"),
	std::wstring_view( L"ch343pta64.dll"),
	std::wstring_view( L"ch343portsa64.dll"),
	std::wstring_view( L"ch343pt.dll"),
} ; // CH343SER 2.2のNTamd64 install sectionが参照する必須binary名。
constexpr std::wstring_view MULTI_ACCEPTED_DRIVER_DATE =
	L"05/19/2026" ;	// 固定ZIP内のDriverVer日付。
constexpr std::wstring_view MULTI_ACCEPTED_DRIVER_VERSION =
	L"2.2.2026.05" ;	// 固定ZIP内のDriverVer version。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字を小文字へ変換する。
 *
 * Locale依存変換を避け、PnP IDとfile名の比較へ使用する。
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
 * @brief 二つのASCII文字列をcase非依存で比較する。
 *
 * Allocationを行わず、固定allowlistとの完全一致だけを許可する。
 *
 * @param[in] left 左側のASCII文字列。
 * @param[in] right 右側のASCII文字列。
 * @return 長さと全ASCII文字がcase非依存で一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	return left.size() == right.size() &&
		   std::ranges::equal( left, right, []( const wchar_t lhs, const wchar_t rhs) noexcept {
			   return asciiLower( lhs) == asciiLower( rhs) ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathの最後のfile名を取得する。
 *
 * INFと必須binaryの固定family判定だけに使用する。
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
 * @brief WCH CH341SER固有の署名済みINFか判定する。
 *
 * 同じpublisher署名を持つ別WCH製品や別機能を受理しない。
 *
 * @param[in] package 構造検証済みPorts class INF。
 * @return 固定INF、PnP ID集合、x64必須binaryを満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isWchSerialPackage( const OfficialInfPackage &package)
{
	// CH341 の固定 INF 名・日付・版と非空 PnP ID 集合を必須とする。
	if( !asciiEqual( fileName( package.infRelativePath), L"CH341SER.INF") ||
	   package.driverDate != ACCEPTED_DRIVER_DATE ||
	   package.driverVersion != ACCEPTED_DRIVER_VERSION || package.hardwareIds.empty()) {
		return false ;
	}

	// 全PnP IDを固定allowlistへ限定し、追加された別製品を黙って受理しない。
	for( const std::wstring &hardwareId : package.hardwareIds) {
		// CH341 の許可 PnP ID 以外を含む package は受理しない。
		if( !isWchSerialCandidateHardwareId( hardwareId)) {
			return false ;
		}
	}

	// NTamd64 install sectionで必要な全binaryがINF参照集合にあることを確認する。
	for( const std::wstring_view requiredName : REQUIRED_X64_FILES) {
		// 必須file名がINFの参照閉包に存在するかを示す。名前viewは同期探索中だけ借用する。
		const bool found = std::ranges::any_of(
			package.sourceFiles, [requiredName]( const std::wstring &sourceFile) noexcept {
				return asciiEqual( fileName( sourceFile), requiredName) ;
			}) ;
		// 必須の対応項目が package 内に見つからなければ拒否する。
		if( !found) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH CH342／CH343系の固定署名済みINFか判定する。
 *
 * CH343SER 2.2に未掲載のcustom IDや別WCH packageを拒否する。
 *
 * @param[in] package 構造検証済みPorts class INF。
 * @return 固定INF、PnP ID集合、x64必須binaryを満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isWchMultiSerialPackage( const OfficialInfPackage &package)
{
	// CH343 系の固定 INF 名・日付・版と非空 PnP ID 集合を必須とする。
	if( !asciiEqual( fileName( package.infRelativePath), L"CH343SER.INF") ||
	   package.driverDate != MULTI_ACCEPTED_DRIVER_DATE ||
	   package.driverVersion != MULTI_ACCEPTED_DRIVER_VERSION || package.hardwareIds.empty()) {
		return false ;
	}

	// 固定NTamd64 model section外のIDを黙って候補化しない。
	for( const std::wstring &hardwareId : package.hardwareIds) {
		// CH342／CH343 系の許可 PnP ID 以外を含む package を拒否する。
		if( !isWchMultiSerialCandidateHardwareId( hardwareId)) {
			return false ;
		}
	}

	// x64 installに必要な全binaryがINF参照集合へ含まれることを確認する。
	for( const std::wstring_view requiredName : MULTI_REQUIRED_X64_FILES) {
		// Multi-serial側の必須fileがINF参照閉包に存在するかを示す。探索中だけ名前viewを借用する。
		const bool found = std::ranges::any_of(
			package.sourceFiles, [requiredName]( const std::wstring &sourceFile) noexcept {
				return asciiEqual( fileName( sourceFile), requiredName) ;
			}) ;
		// CH343 系 package に必須の対応項目がない場合は拒否する。
		if( !found) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH固有の利用者選択ZIP policyを返す。
 *
 * ZIP全体の事前検査後に現行Windows subtreeだけを選択する。
 * @return Process lifetime中有効なWCH固有policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const UserSelectedInfPackagePolicy &wchPackagePolicy() noexcept
{
	static constexpr UserSelectedInfPackagePolicy POLICY{
		.workspaceTag			   = L"wch-serial-package",
		.zipPolicy				   = ZIP_POLICY,
		.maximumInfCount		   = MAXIMUM_INF_COUNT,
		.maximumNestedArchiveCount = 0,
		.archiveSubdirectory	   = SELECTED_SUBDIRECTORY,
		.archiveSelectedFiles	   = {},
		.integrityMode =
			UserSelectedInfPackageIntegrityMode::PINNED_ARCHIVE_AND_EMBEDDED_SIGNATURES,
		.acceptedArchiveSha256	= ACCEPTED_ARCHIVE_SHA256,
		.embeddedSignatureFiles = EMBEDDED_SIGNATURE_FILES,
		.infPolicy				= INF_POLICY,
		.signers				= ACCEPTED_SIGNERS,
		.packagePredicate		= isWchSerialPackage,
	} ; // WCH CH341SER固有の変更不可policy。
	return POLICY ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH CH342／CH343系の利用者選択ZIP policyを返す。
 *
 * ZIP全体の固定hash確認後に現行Windows subtreeだけを選ぶ。
 * @return Process lifetime中有効なCH343SER 2.2固定policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const UserSelectedInfPackagePolicy &wchMultiPackagePolicy() noexcept
{
	static constexpr UserSelectedInfPackagePolicy POLICY{
		.workspaceTag			   = L"wch-multi-serial-package",
		.zipPolicy				   = MULTI_ZIP_POLICY,
		.maximumInfCount		   = MULTI_MAXIMUM_INF_COUNT,
		.maximumNestedArchiveCount = 0,
		.archiveSubdirectory	   = MULTI_SELECTED_SUBDIRECTORY,
		.archiveSelectedFiles	   = {},
		.integrityMode =
			UserSelectedInfPackageIntegrityMode::PINNED_ARCHIVE_AND_EMBEDDED_SIGNATURES,
		.acceptedArchiveSha256	= MULTI_ACCEPTED_ARCHIVE_SHA256,
		.embeddedSignatureFiles = MULTI_EMBEDDED_SIGNATURE_FILES,
		.infPolicy				= MULTI_INF_POLICY,
		.signers				= ACCEPTED_SIGNERS,
		.packagePredicate		= isWchMultiSerialPackage,
	} ; // WCH CH343SER 2.2固有の変更不可policy。
	return POLICY ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/wch_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isWchSerialCandidateHardwareId( const std::wstring_view hardwareId) noexcept
{
	return std::ranges::any_of( ACCEPTED_HARDWARE_IDS,
							   [hardwareId]( const std::wstring_view accepted) noexcept {
								   return asciiEqual( hardwareId, accepted) ;
							   }) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/wch_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isWchMultiSerialCandidateHardwareId( const std::wstring_view hardwareId) noexcept
{
	return std::ranges::any_of( MULTI_ACCEPTED_HARDWARE_IDS,
							   [hardwareId]( const std::wstring_view accepted) noexcept {
								   return asciiEqual( hardwareId, accepted) ;
							   }) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/wch_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectWchSerialPackageFile( const std::wstring_view	   selectedPath,
										const ScanSessionId		   scanSessionId,
										OfficialDownloadWorkspace &workspace,
										WchSerialPackageContents  &contents)
{
	return inspectUserSelectedInfPackageFile( selectedPath, scanSessionId, wchPackagePolicy(),
											 workspace, contents) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/wch_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyWchSerialInfPackage( const OfficialDownloadWorkspace		   &workspace,
										const std::span<const OfficialZipEntry> entries,
										const OfficialInfPackage			   &expected)
{
	return reverifyUserSelectedInfPackage( workspace, entries, expected, wchPackagePolicy()) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/wch_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectWchMultiSerialPackageFile( const std::wstring_view	selectedPath,
											 const ScanSessionId		scanSessionId,
											 OfficialDownloadWorkspace &workspace,
											 WchSerialPackageContents  &contents)
{
	return inspectUserSelectedInfPackageFile( selectedPath, scanSessionId, wchMultiPackagePolicy(),
											 workspace, contents) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/wch_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyWchMultiSerialInfPackage( const OfficialDownloadWorkspace		&workspace,
											 const std::span<const OfficialZipEntry> entries,
											 const OfficialInfPackage				&expected)
{
	return reverifyUserSelectedInfPackage( workspace, entries, expected, wchMultiPackagePolicy()) ;
}

} // namespace drivercrate
