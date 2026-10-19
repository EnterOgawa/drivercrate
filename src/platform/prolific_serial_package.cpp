//------------------------------------------------------------------------------
/**
 * @file prolific_serial_package.cpp
 * @brief Prolific serial署名済みINF ZIP検証実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  整合性modeを明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Prolific公式pageが明示するDCHU INFと標準VIDだけを受理します。選択fileの入手元は証明せず、検証結果と署名だけを信頼します。
 */
//------------------------------------------------------------------------------

#include "platform/prolific_serial_package.h"

#include "platform/official_download_workspace.h"

#include <algorithm>
#include <array>
#include <ranges>
#include <string>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES		 = 16ULL * 1024ULL * 1024ULL ;	// 外側ZIP上限。
constexpr std::uint64_t MAXIMUM_SINGLE_FILE_BYTES	 = 8ULL * 1024ULL * 1024ULL ;	// 一file上限。
constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES		 = 64ULL * 1024ULL * 1024ULL ;	// 全展開上限。
constexpr std::uint32_t MAXIMUM_ENTRY_COUNT			 = 256U ;						// 外側と内側を合わせたentry上限。
constexpr std::size_t	MAXIMUM_INF_COUNT			 = 4U ;							// Windows 10と11用を含むINF数上限。
constexpr std::size_t	MAXIMUM_NESTED_ARCHIVE_COUNT = 2U ;							// 外側ZIPに許可する内側ZIP数。

constexpr OfficialZipExtractionPolicy ZIP_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // Prolific DCHU配布物に適用する展開上限。

constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Ports")} ;		// 許可setup class。
constexpr std::array ACCEPTED_PROVIDERS{std::wstring_view( L"Prolific")} ;	// 許可INF Provider。
constexpr std::array ACCEPTED_INF_SIGNATURES{								// Prolific DCHUが使用するINF signature。
											 std::wstring_view( L"$CHICAGO$")} ;
constexpr std::array ACCEPTED_SIGNERS{
	// CAT signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;
constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds = 128U,
	.maximumSourceFiles = 64U,
	.acceptedClasses	= ACCEPTED_CLASSES,
	.acceptedProviders	= ACCEPTED_PROVIDERS,
	.acceptedSignatures = ACCEPTED_INF_SIGNATURES,
} ; // Prolific Ports INFの構造policy。

constexpr std::array ACCEPTED_PIDS{std::wstring_view( L"2303"), std::wstring_view( L"2304"),
								   std::wstring_view( L"2323"), std::wstring_view( L"23a3"),
								   std::wstring_view( L"23b3"), std::wstring_view( L"23c3"),
								   std::wstring_view( L"23d3"), std::wstring_view( L"23e3"),
								   // 公式pageが明示する標準PID。
								   std::wstring_view( L"23f3")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII英字を小文字へ変換する。
 *
 * Localeやallocationに依存しないPnP ID比較に使用する。
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
 * 長さと全文字を照合し、部分一致を許可しない。
 *
 * @param[in] left 左辺文字列。
 * @param[in] right 右辺文字列。
 * @return ASCII英字の大小を除いて完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// 文字数が異なる名称は大文字小文字に関係なく不一致とする。
	if( left.size() != right.size()) {
		return false ;
	}

	// 同じindexの全文字を比較し、最初の不一致で拒否する。
	for( std::size_t index = 0; index < left.size(); ++index) {
		// 同じ位置の ASCII 正規化文字が異なる時点で不一致を返す。
		if( asciiLower( left[index]) != asciiLower( right[index])) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字列が指定prefixで始まるか判定する。
 *
 * PnP IDのVID／PID境界をallocationなしで確認する。
 *
 * @param[in] value 検査対象文字列。
 * @param[in] prefix 先頭に必要な文字列。
 * @return ASCII英字の大小を除いてprefixが一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiStartsWith( const std::wstring_view value,
								   const std::wstring_view prefix) noexcept
{
	return value.size() >= prefix.size() && asciiEqual( value.substr( 0, prefix.size()), prefix) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列が指定数のASCII十六進数字だけか判定する。
 *
 * Revisionとinterface番号への任意文字混入を拒否する。
 *
 * @param[in] value 検査対象文字列。
 * @param[in] expectedSize 必須文字数。
 * @return 長さと全桁が条件を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isFixedHex( const std::wstring_view value,
							  const std::size_t		  expectedSize) noexcept
{
	// Hex 識別部分が指定桁数でなければ内容比較へ進まない。
	if( value.size() != expectedSize) {
		return false ;
	}

	return std::ranges::all_of( value, []( const wchar_t character) {
		const wchar_t normalized = asciiLower( character) ;
		return (normalized >= L'0' && normalized <= L'9') ||
			   (normalized >= L'a' && normalized <= L'f') ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Prolific PnP IDの後置componentを検証する。
 *
 * 各componentの桁数と終端を検証し、末尾の任意文字を拒否する。
 *
 * @param[in] suffix 4桁PIDより後ろの文字列。
 * @return 空、REV、MI、またはREVとMIの順序付き組合せなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedSuffix( const std::wstring_view suffix) noexcept
{
	constexpr std::wstring_view REVISION_PREFIX	 = L"&rev_" ;	// Revision component prefix。
	constexpr std::wstring_view INTERFACE_PREFIX = L"&mi_" ;	// Interface component prefix。
	// 後置 component がない基本 PnP ID も許可形式として受理する。
	if( suffix.empty()) {
		return true ;
	}

	// Interface 後置指定は固定二桁の hex 値だけを許可する。
	if( asciiStartsWith( suffix, INTERFACE_PREFIX)) {
		return isFixedHex( suffix.substr( INTERFACE_PREFIX.size()), 2U) ;
	}

	// Revision prefix または必要な四桁を欠く後置 component を拒否する。
	if( !asciiStartsWith( suffix, REVISION_PREFIX) || suffix.size() < REVISION_PREFIX.size() + 4U) {
		return false ;
	}

	const std::wstring_view revision =
		// 固定4桁のrevision番号。
		suffix.substr( REVISION_PREFIX.size(), 4U) ;
	const std::wstring_view remainder =
		// Revision後の任意interface component。
		suffix.substr( REVISION_PREFIX.size() + 4U) ;
	// Revision が固定四桁の hex 値でなければ拒否する。
	if( !isFixedHex( revision, 4U)) {
		return false ;
	}

	return remainder.empty() || (asciiStartsWith( remainder, INTERFACE_PREFIX) &&
								 isFixedHex( remainder.substr( INTERFACE_PREFIX.size()), 2U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字列を小文字化する。
 *
 * Localeに依存せず、署名対象metadataを完全一致比較する。
 *
 * @param[in] value INF由来のpathまたはPnP ID。
 * @return ASCII英大文字だけを小文字化したcopy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeAscii( const std::wstring_view value)
{
	std::wstring normalized( value) ;	// 入力を変更しない比較用copy。
	std::ranges::transform( normalized, normalized.begin(), []( const wchar_t character) {
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character - L'A' + L'a')
				   : character ;
	}) ;
	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathの最後のfile名を取得する。
 *
 * INFとSYSの固定file family判定だけに使用する。
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
 * @brief Prolific DCHU固有の署名済みINFか判定する。
 *
 * 署名済みでも別製品用のINFをserial候補として受理しない。
 *
 * @param[in] package 構造検証済みPorts class INF。
 * @return PLSER INF、SYS、Prolific VID、許可PIDを持つ場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isProlificSerialPackage( const OfficialInfPackage &package)
{
	const std::wstring infName = normalizeAscii( fileName( package.infRelativePath)) ;	// INF名。
	// 対象 DCHU INF 名以外と PnP ID のない package を拒否する。
	if( (infName != L"plser.inf" && infName != L"plser_1.inf") || package.hardwareIds.empty()) {
		return false ;
	}

	bool hasAllowedId{} ;	// 公式pageにある標準PIDが一件以上ある場合true。
	// 全IDのVIDをProlificに限定し、候補化可能なPIDの存在も確認する。
	for( const std::wstring &hardwareId : package.hardwareIds) {
		const std::wstring normalized = normalizeAscii( hardwareId) ;	// 現在IDの小文字copy。
		// Package 内の ID が Prolific USB vendor の境界を外れる場合は拒否する。
		if( !normalized.starts_with( L"usb\\vid_067b&pid_")) {
			return false ;
		}

		hasAllowedId = hasAllowedId || isProlificSerialCandidateHardwareId( normalized) ;
	}

	const bool hasDriverBinary =
		std::ranges::any_of( package.sourceFiles, []( const std::wstring &sourceFile) {
			const std::wstring name = normalizeAscii( fileName( sourceFile)) ;	// 現在参照file名。
			return name.starts_with( L"plser") && name.ends_with( L".sys") ;
		}) ; // 少なくとも一つのPLSER driver binaryがある場合true。
	return hasAllowedId && hasDriverBinary ;
}

//------------------------------------------------------------------------------
/**
 * @brief Prolific固有の利用者選択ZIP policyを返す。
 *
 * 公式配布物のWindows 10用と11用nested ZIPを最大2件許可する。
 * @return Process lifetime中有効なProlific固有policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const UserSelectedInfPackagePolicy &prolificPackagePolicy() noexcept
{
	static constexpr UserSelectedInfPackagePolicy POLICY{
		.workspaceTag			   = L"prolific-serial-package",
		.zipPolicy				   = ZIP_POLICY,
		.maximumInfCount		   = MAXIMUM_INF_COUNT,
		.maximumNestedArchiveCount = MAXIMUM_NESTED_ARCHIVE_COUNT,
		.archiveSubdirectory	   = {},
		.archiveSelectedFiles	   = {},
		.integrityMode			   = UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS,
		.acceptedArchiveSha256	   = {},
		.embeddedSignatureFiles	   = {},
		.infPolicy				   = INF_POLICY,
		.signers				   = ACCEPTED_SIGNERS,
		.packagePredicate		   = isProlificSerialPackage,
	} ; // Prolific DCHU固有の変更不可policy。
	return POLICY ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/prolific_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isProlificSerialCandidateHardwareId( const std::wstring_view hardwareId) noexcept
{
	constexpr std::wstring_view PREFIX = L"usb\\vid_067b&pid_" ;	// 標準VIDまでのID prefix。
	// 固定の vendor prefix と必要な PID 桁数がない ID は対象と扱わない。
	if( !asciiStartsWith( hardwareId, PREFIX) || hardwareId.size() < PREFIX.size() + 4U) {
		return false ;
	}

	const std::wstring_view pid = hardwareId.substr( PREFIX.size(), 4U) ;	// 固定4桁PID。
	const std::wstring_view suffix =
		// PID後ろのrevision／interface component。
		hardwareId.substr( PREFIX.size() + 4U) ;
	const bool acceptedPid =
		std::ranges::any_of( ACCEPTED_PIDS, [pid]( const std::wstring_view accepted) noexcept {
			return asciiEqual( pid, accepted) ;
		}) ; // 公式page掲載PIDとの一致。
	return acceptedPid && isAllowedSuffix( suffix) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/prolific_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectProlificSerialPackageFile( const std::wstring_view		selectedPath,
											 const ScanSessionId			scanSessionId,
											 OfficialDownloadWorkspace	   &workspace,
											 ProlificSerialPackageContents &contents)
{
	return inspectUserSelectedInfPackageFile( selectedPath, scanSessionId, prolificPackagePolicy(),
											 workspace, contents) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/prolific_serial_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyProlificSerialInfPackage( const OfficialDownloadWorkspace		&workspace,
											 const std::span<const OfficialZipEntry> entries,
											 const OfficialInfPackage				&expected)
{
	return reverifyUserSelectedInfPackage( workspace, entries, expected, prolificPackagePolicy()) ;
}

} // namespace drivercrate
