//------------------------------------------------------------------------------
/**
 * @file generic_inf_package.cpp
 * @brief 汎用署名済みINF ZIP検証実装。
 * @version 01.01.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要Printer INF対応追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  PrinterとPrintQueueの照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WIA user-mode Image INF対応追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Nested archive拒否を厳格化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Peripheral firmware拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual audio PnP ID拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual capture PnP ID拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Mobile flash payload拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual payload拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Software device全class拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通個別INF検査のlocal入力adapterを追加。
 * </pre>
 *
 * @note Provider名を入手元の証明に使用せず、現在Windows x64用の非boot-critical INF、WHCP署名、CAT SHA-256 member、現在deviceと
 *       の照合だけを許可します。
 */
//------------------------------------------------------------------------------

#include "platform/generic_inf_package.h"

#include "platform/common_driver_package.h"
#include "platform/official_download_workspace.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES = 128ULL * 1024ULL * 1024ULL ;
// 利用者指定archiveから受理する単一fileの展開後byte上限。
constexpr std::uint64_t MAXIMUM_SINGLE_FILE_BYTES = 64ULL * 1024ULL * 1024ULL ;
// 利用者指定package全体を展開する際の累積byte上限。
constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES		 = 512ULL * 1024ULL * 1024ULL ;
constexpr std::uint32_t MAXIMUM_ENTRY_COUNT			 = 4096U ;	// ZIP内の通常file数上限。
constexpr std::size_t	MAXIMUM_INF_COUNT			 = 128U ;	// 一ZIP内のINF数上限。
constexpr std::size_t	MAXIMUM_HARDWARE_IDS_PER_INF = 1024U ;	// 一INFのPnP ID数上限。
constexpr std::size_t	MAXIMUM_SOURCE_FILES_PER_INF = 2048U ;	// 一INFの参照file数上限。
// 汎用driver-only境界外のpayloadを検出した場合に返す共通HRESULT。
constexpr NativeError	DISALLOWED_PAYLOAD_ERROR =
	static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;

constexpr OfficialZipExtractionPolicy ZIP_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // 汎用driver-only ZIPへ適用する有限展開上限。

constexpr std::array ACCEPTED_CLASSES{
	std::wstring_view( L"Biometric"), std::wstring_view( L"Bluetooth"), std::wstring_view( L"Camera"),
	std::wstring_view( L"Display"), std::wstring_view( L"HIDClass"), std::wstring_view( L"Image"),
	std::wstring_view( L"Keyboard"), std::wstring_view( L"MEDIA"), std::wstring_view( L"Modem"),
	std::wstring_view( L"Monitor"), std::wstring_view( L"Mouse"), std::wstring_view( L"Multifunction"),
	std::wstring_view( L"Net"), std::wstring_view( L"Ports"), std::wstring_view( L"Printer"),
	std::wstring_view( L"Sensor"), std::wstring_view( L"SmartCardReader"), std::wstring_view( L"USB"),
	// 汎用導入を許可する非boot-critical class。
	std::wstring_view( L"USBDevice")} ;

constexpr std::array ACCEPTED_INF_SIGNATURES{	// 現行Windows packageに許可するINF signature。
											 std::wstring_view( L"$Windows NT$")} ;
constexpr std::array ACCEPTED_SIGNERS{
	// CAT signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;
constexpr std::array REJECTED_NESTED_CONTAINER_EXTENSIONS{
	std::wstring_view( L".7z"), std::wstring_view( L".bz2"), std::wstring_view( L".cab"),
	std::wstring_view( L".ca_"), std::wstring_view( L".gz"), std::wstring_view( L".iso"),
	std::wstring_view( L".ova"), std::wstring_view( L".ovf"), std::wstring_view( L".qcow"),
	std::wstring_view( L".qcow2"), std::wstring_view( L".rar"), std::wstring_view( L".tar"),
	std::wstring_view( L".tgz"), std::wstring_view( L".txz"), std::wstring_view( L".vfd"),
	std::wstring_view( L".vhd"), std::wstring_view( L".vhdx"), std::wstring_view( L".vmdk"),
	std::wstring_view( L".xz"), std::wstring_view( L".zip"),
	// 拒否する内側archive／virtual image拡張子。
	std::wstring_view( L".zi_")} ;
constexpr std::array REJECTED_FIRMWARE_EXTENSIONS{
	std::wstring_view( L".bin"), std::wstring_view( L".cap"), std::wstring_view( L".dfu"),
	std::wstring_view( L".dfuse"), std::wstring_view( L".elf"), std::wstring_view( L".fls"),
	std::wstring_view( L".ftf"), std::wstring_view( L".fw"), std::wstring_view( L".hex"),
	std::wstring_view( L".ihx"), std::wstring_view( L".img"), std::wstring_view( L".kdz"),
	std::wstring_view( L".mbn"), std::wstring_view( L".ofp"), std::wstring_view( L".pac"),
	std::wstring_view( L".pit"), std::wstring_view( L".rom"), std::wstring_view( L".sin"),
	// Firmware／flash image拡張子。
	std::wstring_view( L".tot"), std::wstring_view( L".uf2")} ;
constexpr std::array REJECTED_SOFTWARE_DEVICE_ID_PREFIXES{
	std::wstring_view( L"ROOT\\"), std::wstring_view( L"SWD\\"), std::wstring_view( L"HTREE\\"),
	// 別capabilityで扱うsoftware enumeratorのPnP ID prefix。
	std::wstring_view( L"UMB\\")} ;
constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds	 = MAXIMUM_HARDWARE_IDS_PER_INF,
	.maximumSourceFiles	 = MAXIMUM_SOURCE_FILES_PER_INF,
	.acceptedClasses	 = ACCEPTED_CLASSES,
	.acceptedProviders	 = {},
	.acceptedSignatures	 = ACCEPTED_INF_SIGNATURES,
	.acceptAnyProvider	 = true,
	.requireDriverBinary = false,
} ; // CATで保護されたProvider名だけを汎用的に受理するINF構造policy。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字列を大文字小文字を除いて比較する。
 *
 * 検証済み相対pathの拡張子比較だけに使用する。
 *
 * @param[in] left 左辺文字列。
 * @param[in] right 右辺文字列。
 * @return ASCII英字のcaseだけを無視して完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiStringsEqual( const std::wstring_view left,
									 const std::wstring_view right) noexcept
{
	// 長さの異なるASCII文字列を同一識別子とみなさない。
	if( left.size() != right.size()) {
		return false ;
	}

	// 全文字を有限回比較し、locale依存のcase変換を使用しない。
	for( std::size_t index = 0; index < left.size(); ++index) {
		const wchar_t leftCharacter	  = left[index] ;	// 現在位置の左辺文字。
		const wchar_t rightCharacter  = right[index] ;	// 現在位置の右辺文字。
		const wchar_t normalizedLeft  = leftCharacter >= L'A' && leftCharacter <= L'Z'
											? static_cast<wchar_t>( leftCharacter - L'A' + L'a')
											: leftCharacter ;	// ASCII小文字化した左辺文字。
		const wchar_t normalizedRight = rightCharacter >= L'A' && rightCharacter <= L'Z'
											? static_cast<wchar_t>( rightCharacter - L'A' + L'a')
											: rightCharacter ;	// ASCII小文字化した右辺文字。
		// 大小文字を除いても異なる文字があれば不一致とする。
		if( normalizedLeft != normalizedRight) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII prefixを大文字小文字を除いて確認する。
 *
 * PnP IDのenumeratorだけを有限prefixへ照合する。部分的なdevice identity照合には使用しない。
 *
 * @param[in] value 検査する文字列。
 * @param[in] prefix 文字列先頭へ要求するASCII文字列。
 * @return ASCII英字のcaseを除いてprefixが一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasAsciiPrefix( const std::wstring_view value,
								  const std::wstring_view prefix) noexcept
{
	return value.size() >= prefix.size() &&
		   asciiStringsEqual( value.substr( 0, prefix.size()), prefix) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathが指定拡張子で終わるか確認する。
 *
 * File名prefixやdirectory名のdotを拡張子として扱わない。
 *
 * @param[in] path ZIP検証済みの相対path。
 * @param[in] extension `.`から始まるASCII拡張子。
 * @return 最終path要素の拡張子が完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasExtension( const std::wstring_view path,
								const std::wstring_view extension) noexcept
{
	const std::size_t separator = path.find_last_of( L"\\/") ;	// 最終separator位置。
	const std::size_t dot		= path.find_last_of( L'.') ;	// 最終dot位置。
	return dot != std::wstring_view::npos &&
		   (separator == std::wstring_view::npos || dot > separator) &&
		   asciiStringsEqual( path.substr( dot), extension) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathが拒否対象のnested containerか確認する。
 *
 * 汎用経路は内側containerを解釈せず、署名済みINFから参照されないarchive、virtual disk、applianceもdriver-only packageとして受理しない。
 *
 * @param[in] path ZIP検証済みの相対path。
 * @return 拒否対象archive／virtual image拡張子の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isRejectedNestedContainer( const std::wstring_view path) noexcept
{
	return std::ranges::any_of( REJECTED_NESTED_CONTAINER_EXTENSIONS,
							   [path]( const std::wstring_view extension) noexcept {
								   return hasExtension( path, extension) ;
							   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathが拒否対象のfirmware imageか確認する。
 *
 * Driverとdevice firmwareの一括導入を汎用INF経路へ混在させず、INFから参照されないimageもfail-closedで拒否する。
 *
 * @param[in] path ZIP検証済みの相対path。
 * @return Firmware imageとして拒否する拡張子の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isRejectedFirmwarePayload( const std::wstring_view path) noexcept
{
	return std::ranges::any_of( REJECTED_FIRMWARE_EXTENSIONS,
							   [path]( const std::wstring_view extension) noexcept {
								   return hasExtension( path, extension) ;
							   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathが汎用driver-only境界外のpayloadか確認する。
 *
 * ADR 0078／0079／0082／0083の拒否条件をscan時とinstall直前で共有する。
 *
 * @param[in] path ZIP検証済みの相対path。
 * @return 内側container、virtual image、firmwareの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisallowedGenericPayload( const std::wstring_view path) noexcept
{
	return isRejectedNestedContainer( path) || isRejectedFirmwarePayload( path) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFがsoftware enumeratorを対象にするか確認する。
 *
 * ADR 0080／0081／0083に従いvirtual device、filter、bus、software endpointを物理PnP device用経路から分離する。
 *
 * @param[in] package 構造検証済みのINF metadata。
 * @return 拒否enumeratorを一つでも含む場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSoftwareEnumeratedPackage( const OfficialInfPackage &package) noexcept
{
	return std::ranges::any_of( package.hardwareIds, []( const std::wstring &hardwareId) {
		return std::ranges::any_of( REJECTED_SOFTWARE_DEVICE_ID_PREFIXES,
								   [&hardwareId]( const std::wstring_view prefix) noexcept {
									   return hasAsciiPrefix( hardwareId, prefix) ;
								   }) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 4要素numeric driver versionか確認する。
 *
 * 表示文字列から版を推測せず、INFの明示4要素だけを扱う。
 *
 * @param[in] version INF DriverVerのversion field。
 * @return `a.b.c.d`の全要素がuint32範囲なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isFourPartVersion( const std::wstring_view version) noexcept
{
	std::size_t	  partCount{} ;	// 確定した数値要素数。
	std::uint64_t value{} ;		// 現在要素のoverflow検査用値。
	bool		  hasDigit{} ;	// 現在要素が一桁以上持つ場合true。
	// 終端を仮想separatorとして扱い、空要素と5要素以上を拒否する。
	for( std::size_t index = 0; index <= version.size(); ++index) {
		const wchar_t character = index == version.size() ? L'.' : version[index] ;	// 現在文字。
		// 版の数字を現在要素へ取り込み、区切りと分けて検証する。
		if( character >= L'0' && character <= L'9') {
			const std::uint64_t digit =
				// 現在桁の数値。
				static_cast<std::uint64_t>( character - L'0') ;
			// 次の桁を加える前に32-bit要素のoverflowを防ぐ。
			if( value > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
				return false ;
			}

			value	 = value * 10U + digit ;
			hasDigit = true ;
			continue ;
		}

		// 不正な区切り、空要素、過剰な版要素を拒否する。
		if( character != L'.' || !hasDigit || partCount >= 4U) {
			return false ;
		}

		++partCount ;
		value	 = 0 ;
		hasDigit = false ;
	}

	return partCount == 4U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 汎用経路で扱える署名済みINFか判定する。
 *
 * Provider名はfamily判定に使わず、CAT保護された表示値として保持する。Printerとvendor DLLを参照するWIA Image INFだけはADR 0076／0077の限定
 * 条件でSYSなしを許可する。ADR 0078～0083に従い、複合payload、software device、firmwareを拒否する。
 *
 * @param[in] package ClassとProvider名を構造検証済みのINF。
 * @return Container／virtual image／firmware参照がなく、Printer、DLL型Image、またはSYSを持つ場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isGenericInfPackage( const OfficialInfPackage &package)
{
	// 必須metadataの欠落、禁止payload、software列挙packageを汎用経路から除外する。
	if( package.providerName.empty() || !isFourPartVersion( package.driverVersion) ||
	   package.hardwareIds.empty() || package.sourceFiles.empty() ||
	   std::ranges::any_of( package.hardwareIds,
						   []( const std::wstring &hardwareId) { return hardwareId.empty() ; }) ||
	   std::ranges::any_of(
		   package.sourceFiles,
		   []( const std::wstring &sourceFile) { return isDisallowedGenericPayload( sourceFile) ; }) ||
	   isSoftwareEnumeratedPackage( package)) {
		return false ;
	}

	// 基本条件を満たすPrinter classを汎用driver-only対象として認める。
	if( asciiStringsEqual( package.className, L"Printer")) {
		return true ;
	}

	// Image classは参照DLLを含む場合に汎用対象として認める。
	if( asciiStringsEqual( package.className, L"Image") &&
	   std::ranges::any_of( package.sourceFiles, []( const std::wstring &sourceFile) {
		   return hasExtension( sourceFile, L".dll") ;
	   })) {
		return true ;
	}

	return std::ranges::any_of( package.sourceFiles, []( const std::wstring &sourceFile) {
		return hasExtension( sourceFile, L".sys") ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 汎用署名済みINF ZIPの固定policyを返す。
 *
 * Nested container、firmware、実行installer、software deviceを許可せず、全INFをCAT SHA-256 member境界で検証する。
 * @return Process lifetime中有効な変更不可policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const UserSelectedInfPackagePolicy &genericInfPackagePolicy() noexcept
{
	static constexpr UserSelectedInfPackagePolicy POLICY{
		.workspaceTag			   = L"generic-inf-package",
		.zipPolicy				   = ZIP_POLICY,
		.maximumInfCount		   = MAXIMUM_INF_COUNT,
		.maximumNestedArchiveCount = 0,
		.archiveSubdirectory	   = {},
		.archiveSelectedFiles	   = {},
		.integrityMode			   = UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS,
		.acceptedArchiveSha256	   = {},
		.embeddedSignatureFiles	   = {},
		.infPolicy				   = INF_POLICY,
		.signers				   = ACCEPTED_SIGNERS,
		.packagePredicate		   = isGenericInfPackage,
	} ; // 汎用経路の変更不可policy。
	return POLICY ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/generic_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isGenericInfPackageSupported( const OfficialInfPackage &package)
{
	return isGenericInfPackage( package) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/generic_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isGenericInfDeviceClassMatch( const std::wstring_view infClass,
								  const std::wstring_view deviceClass) noexcept
{
	return asciiStringsEqual( infClass, deviceClass) ||
		   (asciiStringsEqual( infClass, L"Printer") &&
			asciiStringsEqual( deviceClass, L"PrintQueue")) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/generic_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectGenericInfPackageFile( const std::wstring_view	selectedPath,
										 const ScanSessionId		scanSessionId,
										 OfficialDownloadWorkspace &workspace,
										 GenericInfPackageContents &contents)
{
	// 共通検証器が返した最初の構造・署名違反、または成功を保持する診断値。
	const NativeError error = inspectUserSelectedInfPackageFile(
		selectedPath, scanSessionId, genericInfPackagePolicy(), workspace, contents) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 禁止payloadを一つでも含むarchiveは抽出結果を破棄して拒否する。
	if( std::ranges::any_of( contents.entries, []( const OfficialZipEntry &entry) {
		   return isDisallowedGenericPayload( entry.relativePath) ;
	   })) {
		// 参照有無にかかわらず複合payloadを含むpackageはfail-closedで破棄する。
		contents = {} ;
		contents.verificationStage =
			UserSelectedInfPackageVerificationStage::OUTER_ARCHIVE_EXTRACTED ;
		return DISALLOWED_PAYLOAD_ERROR ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/generic_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyGenericInfPackage( const OfficialDownloadWorkspace		 &workspace,
									  const std::span<const OfficialZipEntry> entries,
									  const OfficialInfPackage				 &expected)
{
	// 導入直前にも全entryを確認し、禁止payloadの混入を拒否する。
	if( std::ranges::any_of( entries, []( const OfficialZipEntry &entry) {
		   return isDisallowedGenericPayload( entry.relativePath) ;
	   })) {
		return DISALLOWED_PAYLOAD_ERROR ;
	}

	return reverifyUserSelectedInfPackage( workspace, entries, expected, genericInfPackagePolicy()) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/generic_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isGenericInfCandidateHardwareId( const std::wstring_view hardwareId) noexcept
{
	return !hardwareId.empty() ;
}

/**
 * @see src/platform/generic_inf_package.h 宣言側の契約を正本とする。
 */
NativeError inspectCommonLocalInfPackageFile( const std::wstring_view		 selectedPath,
											 const ScanSessionId			 scanSessionId,
											 OfficialDownloadWorkspace		&workspace,
											 UserSelectedInfPackageContents &contents)
{
	contents = {} ;
	DriverArchiveInput			input ;		// 公式由来を持たない内容identity。
	OfficialDriverArchiveFormat format{} ;	// Local取込みが確定した静的形式。
	NativeError					error =
		// 保護copy。
		copyLocalDriverArchive( selectedPath, scanSessionId, workspace, input, format) ;
	// 取込み失敗時は元fileを検査経路へ直接渡さない。
	if( error != 0) {
		return error ;
	}

	auto inspection = std::make_unique<CommonDriverPackageInspection>() ;	// 個別閉包の所有結果。
	error			= inspectCommonDriverPackage( input, format, *inspection) ;
	// 全体失敗では個別成功と拒否の部分集合も公開しない。
	if( error != 0) {
		return error ;
	}

	contents.archiveSha256	  = input.sha256 ;
	contents.archiveSize	  = input.byteCount ;
	contents.commonInspection = std::move( inspection) ;
	return 0 ;
}

} // namespace drivercrate
