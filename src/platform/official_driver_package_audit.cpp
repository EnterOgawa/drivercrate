//------------------------------------------------------------------------------
/**
 * @file official_driver_package_audit.cpp
 * @brief 固定profileによる公式driver閉包・署名・PnP監査。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  WinOF-2閉包profileを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet Server監査profileを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX AX88179A監査profileを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Profile固定Providerの参照境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note ASUS、Broadcom、WinOF-2、Intel EthernetおよびASIXの同一scan取得物を共通監査します。
 */
//------------------------------------------------------------------------------

#include "platform/official_driver_package_audit.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/generic_inf_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES =
	4ULL * 1024ULL * 1024ULL * 1024ULL ;	// 一つの取得済みarchive入力上限。
constexpr std::uint64_t MAXIMUM_SINGLE_FILE_BYTES =
	2ULL * 1024ULL * 1024ULL * 1024ULL ;	// 一つの展開後file上限。
constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES =
	8ULL * 1024ULL * 1024ULL * 1024ULL ;	// 全entryの展開後size合計上限。
constexpr std::uint64_t MAXIMUM_CLOSURE_BYTES =
	2ULL * 1024ULL * 1024ULL * 1024ULL ;								// 一INF閉包の展開後size合計上限。
constexpr std::uint32_t		MAXIMUM_ENTRY_COUNT = 32'768U ;				// 一archiveのdirectory込みentry上限。
constexpr std::uint32_t		MAXIMUM_EXPANSION_RATIO = 200U ;			// Archiveに対する展開後倍率上限。
constexpr std::size_t		MAXIMUM_INF_COUNT		= 256U ;			// 一archive内で個別監査するINF数上限。
constexpr std::size_t		MAXIMUM_HARDWARE_IDS	= 4'096U ;			// 一INFから保持するPnP ID数上限。
constexpr std::size_t		MAXIMUM_SOURCE_FILES	= 8'192U ;			// 一INFから保持する参照file数上限。
constexpr std::size_t		MAXIMUM_CLOSURE_FILES	= 8'194U ;			// INF、CAT、参照file合計上限。
constexpr std::size_t		MAXIMUM_LOCAL_DEVICES	= 4'096U ;			// 一scanでG11-D監査するdevice数上限。
constexpr std::wstring_view WORKSPACE_TAG = L"asus-driver-closure" ;	// 合格閉包の保護領域名。

constexpr std::array		ACCEPTED_CLASSES{
	   std::wstring_view( L"Biometric"), std::wstring_view( L"Bluetooth"), std::wstring_view( L"Camera"),
	   std::wstring_view( L"Display"), std::wstring_view( L"HIDClass"), std::wstring_view( L"Image"),
	   std::wstring_view( L"Keyboard"), std::wstring_view( L"MEDIA"), std::wstring_view( L"Modem"),
	   std::wstring_view( L"Monitor"), std::wstring_view( L"Mouse"), std::wstring_view( L"Multifunction"),
	   std::wstring_view( L"Net"), std::wstring_view( L"Ports"), std::wstring_view( L"Printer"),
	   std::wstring_view( L"Sensor"), std::wstring_view( L"SmartCardReader"), std::wstring_view( L"USB"),
	   // Boot-criticalでない許可setup class。
	   std::wstring_view( L"USBDevice")} ;
constexpr std::array ACCEPTED_INF_SIGNATURES{	// Windows x64 packageに許可するINF signature。
											 std::wstring_view( L"$Windows NT$")} ;
constexpr std::array ACCEPTED_SIGNERS{
	// CAT signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;

constexpr OfficialZipExtractionPolicy ZIP_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // 公式 ZIPへ適用する有限上限。

constexpr OfficialCabExtractionPolicy CAB_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // 公式単一CABへ適用する有限上限。

constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds	 = MAXIMUM_HARDWARE_IDS,
	.maximumSourceFiles	 = MAXIMUM_SOURCE_FILES,
	.acceptedClasses	 = ACCEPTED_CLASSES,
	.acceptedProviders	 = {},
	.acceptedSignatures	 = ACCEPTED_INF_SIGNATURES,
	.acceptAnyProvider	 = true,
	.requireDriverBinary = false,
} ; // Provider名はCATで保護し、非boot-critical classだけを許可するINF policy。

constexpr OfficialDriverClosurePolicy CLOSURE_POLICY{
	.zipPolicy				   = ZIP_POLICY,
	.cabPolicy				   = CAB_POLICY,
	.infPolicy				   = INF_POLICY,
	.maximumInfCount		   = 1U,
	.maximumClosureFiles	   = MAXIMUM_CLOSURE_FILES,
	.maximumClosureBytes	   = MAXIMUM_CLOSURE_BYTES,
	.maximumExpansionRatio	   = MAXIMUM_EXPANSION_RATIO,
	.maximumNestedArchiveDepth = 1U,
} ; // 一INFずつ独立監査する選択閉包policy。

/** @brief 登録済み取得元だけに適用する内部監査条件である。 */
struct PackageAuditPolicy {
	/// 取得ledgerに要求する固定Provider。
	std::wstring_view			providerId ;
	/// 閉包所有領域の内部識別子。
	std::wstring_view			workspaceTag ;
	/// 既存の有限展開とINF検証条件。
	OfficialDriverClosurePolicy closure ;
	/// 一配布物の全INF列挙上限。
	std::size_t					maximumInfCount ;
	/// 成功閉包の保持量累計上限。
	std::uint64_t				maximumRetainedBytes ;
	/// trueなら公開hash照合済み取得だけを受理する。
	bool						publishedHashRequired ;
} ;

// 公式Ethernet packageの固定Net class。Provider名は署名で保護し、端末内で照合する。
constexpr std::array				  NET_CLASSES{std::wstring_view( L"Net")} ;
constexpr OfficialInfInspectionPolicy NET_INF_POLICY{
	.maximumHardwareIds	 = MAXIMUM_HARDWARE_IDS,
	.maximumSourceFiles	 = MAXIMUM_SOURCE_FILES,
	.acceptedClasses	 = NET_CLASSES,
	.acceptedProviders	 = {},
	.acceptedSignatures	 = ACCEPTED_INF_SIGNATURES,
	.acceptAnyProvider	 = true,
	.requireDriverBinary = true,
} ; // SYS参照を必須とし、Net以外のdriverをこのprofileへ混入させない。
constexpr std::uint64_t BROADCOM_INPUT_BYTES =
	128ULL * 1024ULL * 1024ULL ;												// 取得上限と同じ入力上限。
constexpr std::uint64_t BROADCOM_EXPANDED_BYTES = 512ULL * 1024ULL * 1024ULL ;	// 展開／保持上限。
constexpr OfficialDriverClosurePolicy BROADCOM_CLOSURE_POLICY{
	.zipPolicy		 = {BROADCOM_INPUT_BYTES, BROADCOM_INPUT_BYTES, BROADCOM_EXPANDED_BYTES, 4096U},
	.cabPolicy		 = {BROADCOM_INPUT_BYTES, BROADCOM_INPUT_BYTES, BROADCOM_EXPANDED_BYTES, 4096U},
	.infPolicy		 = NET_INF_POLICY,
	.maximumInfCount = 1U,
	.maximumClosureFiles	   = MAXIMUM_CLOSURE_FILES,
	.maximumClosureBytes	   = BROADCOM_INPUT_BYTES,
	.maximumExpansionRatio	   = MAXIMUM_EXPANSION_RATIO,
	.maximumNestedArchiveDepth = 1U,
} ; // 共通閉包処理の署名・参照・実行拒否規則を変更しない。
constexpr std::uint64_t INTEL_ETHERNET_INPUT_BYTES =
	128ULL * 1024ULL * 1024ULL ;	// 取得上限と同じ入力・一INF閉包上限。
constexpr std::uint64_t INTEL_ETHERNET_EXPANDED_BYTES =
	512ULL * 1024ULL * 1024ULL ;	// Inventory展開と合格閉包の保持量上限。
constexpr OfficialDriverClosurePolicy INTEL_ETHERNET_CLOSURE_POLICY{
	.zipPolicy				   = {INTEL_ETHERNET_INPUT_BYTES, INTEL_ETHERNET_INPUT_BYTES,
								  INTEL_ETHERNET_EXPANDED_BYTES, 4096U},
	.cabPolicy				   = {INTEL_ETHERNET_INPUT_BYTES, INTEL_ETHERNET_INPUT_BYTES,
								  INTEL_ETHERNET_EXPANDED_BYTES, 4096U},
	.infPolicy				   = NET_INF_POLICY,
	.maximumInfCount		   = 1U,
	.maximumClosureFiles	   = MAXIMUM_CLOSURE_FILES,
	.maximumClosureBytes	   = INTEL_ETHERNET_INPUT_BYTES,
	.maximumExpansionRatio	   = MAXIMUM_EXPANSION_RATIO,
	.maximumNestedArchiveDepth = 1U,
} ; // 公開hash付きServer 2025 ZIPでも既存Net監査条件を緩和しない。
constexpr std::uint64_t ASIX_INPUT_BYTES =
	8ULL * 1024ULL * 1024ULL ;	// 取得契約と一致する外側・一段内側archive入力上限。
constexpr std::uint64_t ASIX_SINGLE_FILE_BYTES =
	32ULL * 1024ULL * 1024ULL ;	// 一つの展開fileと一INF閉包の上限。
constexpr std::uint64_t ASIX_EXPANDED_BYTES =
	128ULL * 1024ULL * 1024ULL ;	// Inventory展開と合格閉包の保持量上限。
constexpr OfficialDriverClosurePolicy ASIX_CLOSURE_POLICY{
	.zipPolicy			   = {ASIX_INPUT_BYTES, ASIX_SINGLE_FILE_BYTES, ASIX_EXPANDED_BYTES, 4096U},
	.cabPolicy			   = {ASIX_INPUT_BYTES, ASIX_SINGLE_FILE_BYTES, ASIX_EXPANDED_BYTES, 4096U},
	.infPolicy			   = NET_INF_POLICY,
	.maximumInfCount	   = 1U,
	.maximumClosureFiles   = MAXIMUM_CLOSURE_FILES,
	.maximumClosureBytes   = ASIX_SINGLE_FILE_BYTES,
	.maximumExpansionRatio = MAXIMUM_EXPANSION_RATIO,
	.maximumNestedArchiveDepth = 1U,
} ; // ASIXの小容量取得を有限展開し、既存Net監査条件を緩和しない。

constexpr PackageAuditPolicy ASUS_AUDIT_POLICY{ASUS_PROVIDER_ID,
											   WORKSPACE_TAG,
											   CLOSURE_POLICY,
											   MAXIMUM_INF_COUNT,
											   std::numeric_limits<std::uint64_t>::max(),
											   true} ;	// ASUSの既存上限と公開hash必須を維持する。
constexpr PackageAuditPolicy BROADCOM_AUDIT_POLICY{
	BROADCOM_NET_XTREME_PROVIDER_ID, L"broadcom-driver-closure",
	BROADCOM_CLOSURE_POLICY,		 32U,
	BROADCOM_EXPANDED_BYTES,		 false} ;	// 公開hash省略時も取得時実測hashを閉包層で再照合する。
constexpr PackageAuditPolicy INTEL_ETHERNET_AUDIT_POLICY{
	INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
	L"intel-ethernet-server-2025-driver-closure",
	INTEL_ETHERNET_CLOSURE_POLICY,
	32U,
	INTEL_ETHERNET_EXPANDED_BYTES,
	true} ;	// 公式pageの公開SHA-256と一致した取得物だけを受け入れる。
constexpr PackageAuditPolicy ASIX_AUDIT_POLICY{
	ASIX_AX88179A_PROVIDER_ID,
	L"asix-driver-closure",
	ASIX_CLOSURE_POLICY,
	32U,
	ASIX_EXPANDED_BYTES,
	false} ;	// 公開hashなしでも取得時実測hashとCAT保護fileを共通監査する。

constexpr std::array	WINOF2_CLASSES{std::wstring_view( L"Net"), std::wstring_view( L"NetTrans"),
									   std::wstring_view( L"System"),
									   // 固定6系列のsetup class。
									   std::wstring_view( L"Ports")} ;
constexpr std::array	WINOF2_PROVIDERS{std::wstring_view( L"Mellanox"),
										 // 固定6系列のINF Provider。
										 std::wstring_view( L"Mellanox Technologies Ltd.")} ;
constexpr std::uint64_t WINOF2_CLOSURE_BYTES = 64ULL * 1024ULL * 1024ULL ;	// 一INF閉包上限。
constexpr OfficialInfInspectionPolicy WINOF2_INF_POLICY{
	.maximumHardwareIds			= MAXIMUM_HARDWARE_IDS,
	.maximumSourceFiles			= MAXIMUM_SOURCE_FILES,
	.acceptedClasses			= WINOF2_CLASSES,
	.acceptedProviders			= WINOF2_PROVIDERS,
	.acceptedSignatures			= ACCEPTED_INF_SIGNATURES,
	.acceptAnyProvider			= false,
	.requireDriverBinary		= true,
	.rejectUnreferencedPrograms = false,
	.rejectInstallActions		= true,
} ; // MSI閉包へ限定し、現在Windows x64 sectionと任意install action不在を再検証する。
constexpr OfficialDriverClosurePolicy WINOF2_CLOSURE_POLICY{
	.zipPolicy			 = {WINOF2_CLOSURE_BYTES, WINOF2_CLOSURE_BYTES, WINOF2_CLOSURE_BYTES, 256U},
	.cabPolicy			 = {WINOF2_CLOSURE_BYTES, WINOF2_CLOSURE_BYTES, WINOF2_CLOSURE_BYTES, 256U},
	.infPolicy			 = WINOF2_INF_POLICY,
	.maximumInfCount	 = 1U,
	.maximumClosureFiles = MAXIMUM_CLOSURE_FILES,
	.maximumClosureBytes = WINOF2_CLOSURE_BYTES,
	.maximumExpansionRatio	   = MAXIMUM_EXPANSION_RATIO,
	.maximumNestedArchiveDepth = 1U,
} ; // 再検証ではarchiveを再展開せず、保持閉包の同一条件だけを使用する。
constexpr PackageAuditPolicy WINOF2_AUDIT_POLICY{
	NVIDIA_WINOF2_PROVIDER_ID, L"winof2-driver-closure",
	WINOF2_CLOSURE_POLICY,	   1U,
	WINOF2_CLOSURE_BYTES,	   true} ;	// 公開SHA-256付き外側payloadからの閉包だけを受け入れる。

//------------------------------------------------------------------------------
/**
 * @brief 外部入力からclass・publisher・取得元の条件を追加しない。
 *
 * @param[in] profile 内部登録された監査profile。
 * @return 登録済み条件への非所有pointer。未知値はnullptr。
 */
//------------------------------------------------------------------------------
const PackageAuditPolicy *auditPolicy( const OfficialDriverAuditProfile profile) noexcept
{
	// 固定profileに対応する審査済みpolicyだけを選び、未知profileを拒否する。
	switch( profile) {
		// ASUS profile には固定の ASUS 監査 policy を使用する。
		case OfficialDriverAuditProfile::ASUS:
			return &ASUS_AUDIT_POLICY ;
		// Broadcom profile には固定の NetXtreme-E 監査 policy を使用する。
		case OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E:
			return &BROADCOM_AUDIT_POLICY ;
		// NVIDIA WinOF-2 profile には専用の固定監査 policy を使用する。
		case OfficialDriverAuditProfile::NVIDIA_WINOF2:
			return &WINOF2_AUDIT_POLICY ;
		// Intel Ethernet Server 2025 profile には専用の固定監査 policy を使用する。
		case OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025:
			return &INTEL_ETHERNET_AUDIT_POLICY ;
		// ASIX AX88179A profile には専用の固定監査 policy を使用する。
		case OfficialDriverAuditProfile::ASIX_AX88179A:
			return &ASIX_AUDIT_POLICY ;
		// 未知の profile に既定の許可 policy を割り当てない。
		default:
			// 未登録profileを既定の許可条件へ変換しない。
			return nullptr ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 入力を検証し、所有する状態だけを更新する。
 *
 * @param[in,out] audit 内容・適用性監査結果と所有閉包。
 * @return 成功時0、失敗時はHRESULT。個別拒否は監査件数へ残す。
 */
//------------------------------------------------------------------------------
NativeError cancelAudit( OfficialDriverPackageAudit &audit)
{
	audit					  = {} ;
	audit.summary.state		  = OfficialDriverPackageAuditState::FAILURE ;
	audit.summary.error		  = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	audit.applicability.state = OfficialDriverApplicabilityState::FAILURE ;
	audit.applicability.error = audit.summary.error ;
	return audit.summary.error ;
}

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII英字のcaseだけを無視し、localeによる別文字への変換をしない。
 *
 * @param[in] left 比較する一方の文字列またはINF構造。
 * @param[in] right 比較する他方の文字列またはINF構造。
 * @return 条件成立時はtrue、それ以外はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiStringsEqual( const std::wstring_view left,
									 const std::wstring_view right) noexcept
{
	// 長さの異なるASCII policy値を同一とみなさない。
	if( left.size() != right.size()) {
		return false ;
	}

	// 全文字をASCII規則だけで比較し、locale依存の正規化を行わない。
	for( std::size_t index = 0U; index < left.size(); ++index) {
		const wchar_t leftCharacter	 = left[index] ;	// 現在比較する左側文字。
		const wchar_t rightCharacter = right[index] ;	// 現在比較する右側文字。
		const auto	  lower			 = []( const wchar_t value) noexcept {
			return value >= L'A' && value <= L'Z' ? static_cast<wchar_t>( value - L'A' + L'a')
															  : value ;
		} ; // ASCII大文字だけを小文字へ変換する局所関数。
		// ASCII大小文字差を除いても異なる文字は不一致とする。
		if( lower( leftCharacter) != lower( rightCharacter)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 64桁のASCII 16進数だけを受理する。
 *
 * @param[in] value 検証するhash文字列。
 * @return 条件成立時はtrue、それ以外はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSha256Hex( const std::wstring_view value) noexcept
{
	// SHA-256の固定64桁に合わない値を拒否する。
	if( value.size() != 64U) {
		return false ;
	}

	// 全文字をASCII 16進表現へ限定し、locale依存文字を受理しない。
	for( const wchar_t character : value) {
		const bool decimal = character >= L'0' && character <= L'9' ;	// 10進数字判定。
		const bool lower   = character >= L'a' && character <= L'f' ;	// 小文字hex判定。
		const bool upper   = character >= L'A' && character <= L'F' ;	// 大文字hex判定。
		// ASCII hex以外をhash値として受理しない。
		if( !decimal && !lower && !upper) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF metadataを全fieldで比較し、一部だけの一致を受理しない。
 *
 * @param[in] left 比較する一方の文字列またはINF構造。
 * @param[in] right 比較する他方の文字列またはINF構造。
 * @return 条件成立時はtrue、それ以外はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool packagesEqual( const OfficialInfPackage &left,
								 const OfficialInfPackage &right) noexcept
{
	return left.infRelativePath == right.infRelativePath &&
		   left.catalogRelativePath == right.catalogRelativePath &&
		   left.className == right.className && left.providerName == right.providerName &&
		   left.driverDate == right.driverDate && left.driverVersion == right.driverVersion &&
		   left.hardwareIds == right.hardwareIds && left.sourceFiles == right.sourceFiles ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最終拡張子だけを比較し、名前の途中からarchive形式を推測しない。
 *
 * @param[in] path 検証済み相対path。
 * @param[in] extension dot付き拡張子。
 * @return 条件成立時はtrue、それ以外はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasExtension( const std::wstring_view path,
								const std::wstring_view extension) noexcept
{
	// 拡張子より長いfile名部分がないpathを対象形式とみなさない。
	if( path.size() <= extension.size()) {
		return false ;
	}

	return asciiStringsEqual( path.substr( path.size() - extension.size()), extension) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有限inventoryの全INFを順番に列挙し、上限超過を拒否する。
 *
 * @param[in] entries 有限検証済みの通常file一覧。
 * @param[out] infPaths 成功時の全INF path群。
 * @param[in] maximumInfCount profileで定めたINF数上限。
 * @return 成功時0、失敗時はHRESULT。個別拒否は監査件数へ残す。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectInfPaths( const std::span<const OfficialZipEntry> entries,
										  std::vector<std::wstring>				 &infPaths,
										  const std::size_t						  maximumInfCount)
{
	infPaths.clear() ;
	try {
		// Inventory全体を順に確認し、拡張子がINFのfileを全て保持する。
		for( const OfficialZipEntry &entry : entries) {
			// INF拡張子のentryだけを監査対象へ集める。
			if( hasExtension( entry.relativePath, L".inf")) {
				// INF数が上限を超える場合は部分的な選択集合を返さない。
				if( infPaths.size() >= maximumInfCount) {
					infPaths.clear() ;
					return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
				}

				infPaths.push_back( entry.relativePath) ;
			}
		}
	} catch( const std::bad_alloc &) {
		infPaths.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 外側にINFがない場合に一意の一段ZIP／CABだけを選ぶ。曖昧な複数候補を推測しない。
 *
 * @param[in] entries 有限検証済みの通常file一覧。
 * @param[out] nestedPath 一意な一段archive。該当なしは空。
 * @return 成功時0、失敗時はHRESULT。個別拒否は監査件数へ残す。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError selectSingleNestedArchive( const std::span<const OfficialZipEntry> entries,
													std::wstring &nestedPath)
{
	nestedPath.clear() ;
	// 外側inventory全体から許可containerを数え、二件目を検出したら拒否する。
	for( const OfficialZipEntry &entry : entries) {
		// ZIPとCAB以外をnested archive候補から除外する。
		if( !hasExtension( entry.relativePath, L".zip") &&
		   !hasExtension( entry.relativePath, L".cab")) {
			continue ;
		}

		// 内部archiveが複数ある場合は一つを推測採用しない。
		if( !nestedPath.empty()) {
			nestedPath.clear() ;
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
		}

		try {
			nestedPath = entry.relativePath ;
		} catch( const std::bad_alloc &) {
			nestedPath.clear() ;
			return static_cast<NativeError>( E_OUTOFMEMORY) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 登録済み取得元とhash契約を確認する。実測hashと公開hashの意味を混同しない。
 *
 * @param[in] request 取得identity・公開hash・固定profile。
 * @return 条件成立時はtrue、それ以外はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidAcquisition( const OfficialDriverPackageAuditRequest &request) noexcept
{
	const PackageAuditPolicy *policy = auditPolicy( request.profile) ;	// 登録済み取得元条件。
	// 取得物なし・未知profileではfileを開かない。
	if( request.acquisition == nullptr || policy == nullptr) {
		return false ;
	}

	const OfficialAcquisitionResult &acquisition = *request.acquisition ;	// 同一workerの取得記録。
	// 取得成功だけで別Providerやmetadataをdriver監査へ転用しない。
	if( acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.error != 0 || acquisition.scanSessionId == 0U ||
	   acquisition.acquisitionId == 0U || !isSha256Hex( acquisition.sha256) ||
	   !asciiStringsEqual( acquisition.providerId, policy->providerId) ||
	   !asciiStringsEqual( acquisition.resourceId, OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		return false ;
	}

	// 公開hashが未指定の場合はpolicyの省略許可と検証状態の整合性を要求する。
	if( request.expectedSha256.empty()) {
		return !policy->publishedHashRequired && !acquisition.publishedSha256Verified ;
	}

	return isSha256Hex( request.expectedSha256) && acquisition.publishedSha256Verified &&
		   asciiStringsEqual( acquisition.sha256, request.expectedSha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未評価・未知値を非適用成功へ変換せず、定義された拒否だけを分類する。
 *
 * @param[in] decision PnP監査の判断値。
 * @return 条件成立時はtrue、それ以外はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isKnownRankRejection( const OfficialDriverRankDecision decision) noexcept
{
	// 定義されたrank拒否理由だけを非適用へ分類する。
	switch( decision) {
		// 根拠不正は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::INVALID_EVIDENCE:
		// Class 不一致は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::CLASS_MISMATCH:
		// 候補非一致は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED:
		// 現在 driver の対応不明は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::CURRENT_MATCH_UNAVAILABLE:
		// 現在 rank の取得不能は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::CURRENT_RANK_UNAVAILABLE:
		// 候補 rank の取得不能は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::CANDIDATE_RANK_UNAVAILABLE:
		// Identifier 位置の後退は定義済み rank 拒否として共通分類へ進む。
		case OfficialDriverRankDecision::IDENTIFIER_POSITION_REGRESSION:
		// 識別子scoreの悪化は、現在版からの切替を拒むrank理由に含める。
		case OfficialDriverRankDecision::IDENTIFIER_SCORE_REGRESSION:
		// 総合rankの悪化も、適用不能として扱う既知の拒否理由に含める。
		case OfficialDriverRankDecision::OVERALL_RANK_REGRESSION:
			return true ;
		// 未評価を、評価済みのrank拒否へ読み替えない。
		case OfficialDriverRankDecision::NOT_EVALUATED:
		// 適用可能な結果は、拒否理由の分類から除外する。
		case OfficialDriverRankDecision::APPLICABLE:
		// 未知の判定値を、既知の非適用理由へ読み替えない。
		default:
			return false ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring_view officialDriverAuditProviderId( const OfficialDriverAuditProfile profile) noexcept
{
	const PackageAuditPolicy *policy = auditPolicy( profile) ;	// 固定profileの内部policy。
	return policy == nullptr ? std::wstring_view{} : policy->providerId ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditOfficialDriverPackage( const OfficialDriverPackageAuditRequest &request,
									   OfficialDriverPackageAudit			   &audit,
									   const OfficialAuditCancellation		   &cancellation)
{
	audit = {} ;
	// 登録済み取得元とhash契約を満たさない取得証拠を拒否する。
	if( !isValidAcquisition( request)) {
		audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
		audit.summary.error = static_cast<NativeError>( E_ACCESSDENIED) ;
		return audit.summary.error ;
	}

	try {
		// 未開始の監査を実行せずに終了する。
		if( cancellation && cancellation()) {
			return cancelAudit( audit) ;
		}

		const PackageAuditPolicy &policy = *auditPolicy( request.profile) ;	// 入力検証済み条件。
		audit.scanSessionId				 = request.acquisition->scanSessionId ;
		OfficialDriverArchiveInventoryRequest inventoryRequest{
			.acquisition	   = request.acquisition,
			.archiveFormat	   = request.archiveFormat,
			.nestedArchivePath = {}} ;				// 最初は外側archive全体を対象にする。
		OfficialDriverArchiveInventory inventory ;	// 現在監査対象の全通常file一覧。
		NativeError error = inspectOfficialDriverArchiveInventory( inventoryRequest, policy.closure,
																  inventory) ;	// 外側inventory結果。
		// archive検査の失敗を監査拒否として保持する。
		if( error != 0) {
			audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
			audit.summary.error = error ;
			return error ;
		}

		std::vector<std::wstring> infPaths ;	// 現在archive内の全INF path。
		error = collectInfPaths( inventory.entries, infPaths, policy.maximumInfCount) ;
		// INF列挙失敗ではmemory不足とmetadata拒否を区別する。
		if( error != 0) {
			audit.summary.state = error == static_cast<NativeError>( E_OUTOFMEMORY)
									  ? OfficialDriverPackageAuditState::FAILURE
									  : OfficialDriverPackageAuditState::REJECTED ;
			audit.summary.error = error ;
			return error ;
		}

		std::wstring nestedPath ;	// 外側にINFがない場合の一意な一段container path。
		// 外側にINFがない場合だけ一意な一段nested archiveを探す。
		if( infPaths.empty()) {
			error = selectSingleNestedArchive( inventory.entries, nestedPath) ;
			// 内部archive選択が曖昧または不正なら監査を拒否する。
			if( error != 0) {
				audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
				audit.summary.error = error ;
				return error ;
			}

			// 一意な内部archiveを得た場合だけそのinventoryを検査する。
			if( !nestedPath.empty()) {
				inventoryRequest.nestedArchivePath = nestedPath ;
				error = inspectOfficialDriverArchiveInventory( inventoryRequest, policy.closure,
															  inventory) ;
				// 内部archive検査失敗を監査拒否として保持する。
				if( error != 0) {
					audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
					audit.summary.error = error ;
					return error ;
				}

				error = collectInfPaths( inventory.entries, infPaths, policy.maximumInfCount) ;
				// 内部INF列挙失敗もmemory不足とmetadata拒否を区別する。
				if( error != 0) {
					audit.summary.state = error == static_cast<NativeError>( E_OUTOFMEMORY)
											  ? OfficialDriverPackageAuditState::FAILURE
											  : OfficialDriverPackageAuditState::REJECTED ;
					audit.summary.error = error ;
					return error ;
				}
			}
		}

		audit.summary.inventoryFileCount = inventory.entries.size() ;
		audit.summary.infCount			 = infPaths.size() ;
		audit.summary.archiveDepth		 = inventory.archiveDepth ;
		audit.auditedPackages.reserve( infPaths.size()) ;
		// 全INFを個別workspaceへ分離し、一件の拒否で未確認INFを飛ばさない。
		for( const std::wstring &infPath : infPaths) {
			// 未検査INFを飛ばして全体合格とはしない。
			if( cancellation && cancellation()) {
				return cancelAudit( audit) ;
			}

			auto workspace = std::make_unique<OfficialDownloadWorkspace>() ;	// 閉包所有領域。
			const std::wstring_view selectedInf = infPath ;						// 一件だけ選ぶ正式inventory path。
			const std::array		selectedInfPaths{selectedInf} ;				// 閉包APIへ渡す固定一件集合。
			const OfficialDriverClosureRequest closureRequest{
				.acquisition	   = request.acquisition,
				.archiveFormat	   = request.archiveFormat,
				.nestedArchivePath = nestedPath,
				.selectedInfPaths  = selectedInfPaths,
				.workspaceTag	   = policy.workspaceTag} ;	// 現在INFの選択閉包要求。
			OfficialDriverClosure closure ;					// 現在INFの静的検査と抽出結果。
			error =
				extractOfficialDriverClosure( closureRequest, policy.closure, *workspace, closure) ;
			// 単一の対応driver-only閉包が成立した場合だけCAT member整合性を検証する。
			if( error == 0 && closure.packages.size() == 1U &&
			   isGenericInfPackageSupported( closure.packages.front())) {
				error = verifyOfficialInfPackageIntegrity( *workspace, closure.packages.front(),
														  ACCEPTED_SIGNERS) ;
			}
			// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
			else if( error == 0) {
				error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
			}

			// 一INFの監査失敗は拒否件数へ残し、他INFの監査を続ける。
			if( error != 0) {
				// 最初のINF拒否理由を後続の失敗で上書きしない。
				if( audit.summary.firstRejectionError == 0) {
					audit.summary.firstRejectionError = error ;
				}

				++audit.summary.rejectedInfCount ;
				continue ;
			}

			// 署名API実行中に届いた取消しも保持前に反映する。
			if( cancellation && cancellation()) {
				return cancelAudit( audit) ;
			}

			// 保持閉包の総byte上限を超えた場合は既存合格分も破棄する。
			if( closure.expandedBytes >
			   policy.maximumRetainedBytes - audit.summary.retainedClosureBytes) {
				// 容量超過時は既に合格した部分閉包も残さない。
				audit				= {} ;
				audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
				audit.summary.error =
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
				return audit.summary.error ;
			}

			audit.summary.retainedClosureBytes += closure.expandedBytes ;
			audit.auditedPackages.push_back( {.workspace = std::move( workspace),
											 .closure	= std::move( closure),
											 .profile	= request.profile}) ;
			++audit.summary.auditedInfCount ;
		}

		// 全件拒否・空inventoryでも最後の取消しを確定する。
		if( cancellation && cancellation()) {
			return cancelAudit( audit) ;
		}

		audit.summary.state = audit.auditedPackages.empty()
								  ? OfficialDriverPackageAuditState::NO_SUPPORTED_INF
								  : OfficialDriverPackageAuditState::AUDITED ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		audit				= {} ;
		audit.summary.state = OfficialDriverPackageAuditState::FAILURE ;
		audit.summary.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		return audit.summary.error ;
	} catch( const std::length_error &) {
		audit				= {} ;
		audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
		audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		return audit.summary.error ;
	} catch( ...) {
		// 取消しcallback等の例外では部分合格を破棄する。
		audit				= {} ;
		audit.summary.state = OfficialDriverPackageAuditState::FAILURE ;
		audit.summary.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return audit.summary.error ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditOfficialDriverApplicability( const ScanSessionId scanSessionId,
											 const std::span<const OfficialCatalogDevice> devices,
											 const OfficialInfRankAuditor	 &rankAuditor,
											 OfficialDriverPackageAudit		 &audit,
											 const OfficialAuditCancellation &cancellation)
{
	audit.rankApprovedTargets.clear() ;
	audit.applicability = {} ;
	// 同一sessionの正常監査結果、件数整合、device上限、rank auditorを要求する。
	if( scanSessionId == 0U || scanSessionId != audit.scanSessionId || !rankAuditor ||
	   devices.size() > MAXIMUM_LOCAL_DEVICES ||
	   audit.summary.state != OfficialDriverPackageAuditState::AUDITED ||
	   audit.summary.error != 0 || audit.auditedPackages.empty() ||
	   audit.summary.auditedInfCount != audit.auditedPackages.size()) {
		audit.applicability.state = OfficialDriverApplicabilityState::REJECTED ;
		audit.applicability.error = static_cast<NativeError>( E_INVALIDARG) ;
		return audit.applicability.error ;
	}

	try {
		// 取消し要求がある場合は部分監査結果を取り消して返す。
		if( cancellation && cancellation()) {
			return cancelAudit( audit) ;
		}

		std::unordered_set<std::wstring> deviceIdentities ;	// Opaque ID重複検証集合。
		deviceIdentities.reserve( devices.size()) ;
		// Rank監査結果を一意なscan deviceへ拘束するため、全opaque IDを先に検証する。
		for( const OfficialCatalogDevice &device : devices) {
			// 空または重複のdevice identityを適用性監査へ含めない。
			if( device.deviceIdentity.empty() ||
			   !deviceIdentities.insert( device.deviceIdentity).second) {
				audit.applicability.state = OfficialDriverApplicabilityState::REJECTED ;
				audit.applicability.error = static_cast<NativeError>( E_INVALIDARG) ;
				return audit.applicability.error ;
			}
		}

		// 内容監査を通過した各INFを、同じsetup classの全local deviceへread-only照合する。
		for( std::size_t packageIndex = 0U; packageIndex < audit.auditedPackages.size();
			++packageIndex) {
			const OfficialAuditedInfPackage &auditedPackage =
				audit.auditedPackages[packageIndex] ;	// 現在監査する一INF閉包。
			// 所有workspaceと単一INF閉包の前提が崩れた監査記録を拒否する。
			if( auditedPackage.workspace == nullptr ||
			   auditedPackage.closure.packages.size() != 1U) {
				audit.rankApprovedTargets.clear() ;
				audit.applicability		  = {} ;
				audit.applicability.state = OfficialDriverApplicabilityState::REJECTED ;
				audit.applicability.error = static_cast<NativeError>( E_UNEXPECTED) ;
				return audit.applicability.error ;
			}

			const OfficialInfPackage &package =
				// G11-C／CAT合格INF metadata。
				auditedPackage.closure.packages.front() ;
			// classやHardware IDの証拠が欠けた監査packageを拒否する。
			if( package.className.empty() || package.hardwareIds.empty()) {
				audit.rankApprovedTargets.clear() ;
				audit.applicability		  = {} ;
				audit.applicability.state = OfficialDriverApplicabilityState::REJECTED ;
				audit.applicability.error = static_cast<NativeError>( E_UNEXPECTED) ;
				return audit.applicability.error ;
			}

			// Class不一致deviceはSetupAPI候補listを構築せず、候補組合せから除外する。
			for( const OfficialCatalogDevice &device : devices) {
				// 同期PnP照合の間で取消しを反映する。
				if( cancellation && cancellation()) {
					return cancelAudit( audit) ;
				}

				// classが不明またはINFと異なるdeviceをrank照合から除外する。
				if( device.driverClass.empty() ||
				   !asciiStringsEqual( package.className, device.driverClass)) {
					continue ;
				}

				OfficialDriverRankAudit rankAudit ;	// PnP IDを含まないG11-D判断結果。
				++audit.applicability.examinedPairCount ;
				const NativeError pairError =
					rankAuditor( scanSessionId, device.deviceIdentity, *auditedPackage.workspace,
								package, rankAudit) ;	// SetupAPI結果。
				// 一組のrank監査API失敗を記録し、他の組合せを続ける。
				if( pairError != 0) {
					// 最初の組合せ監査失敗を保持する。
					if( audit.applicability.firstPairError == 0) {
						audit.applicability.firstPairError = pairError ;
					}

					++audit.applicability.failedPairCount ;
					continue ;
				}

				// 適用可能と明示された組合せだけを承認対象へ保持する。
				if( rankAudit.decision == OfficialDriverRankDecision::APPLICABLE) {
					audit.rankApprovedTargets.push_back( {.deviceIdentity = device.deviceIdentity,
														 .auditedPackageIndex = packageIndex,
														 .rankAudit			  = rankAudit}) ;
					++audit.applicability.applicablePairCount ;
					continue ;
				}

				// 未知のrank判定値を正常な非適用に変換しない。
				if( !isKnownRankRejection( rankAudit.decision)) {
					const NativeError contractError =
						// Auditor契約違反の診断値。
						static_cast<NativeError>( E_UNEXPECTED) ;
					// 先行診断がない場合だけauditor契約違反を記録する。
					if( audit.applicability.firstPairError == 0) {
						audit.applicability.firstPairError = contractError ;
					}

					++audit.applicability.failedPairCount ;
					continue ;
				}

				++audit.applicability.rejectedPairCount ;
			}
		}

		// 全組合せ確認後も取消しを確認し、取消し済み結果を公開しない。
		if( cancellation && cancellation()) {
			return cancelAudit( audit) ;
		}

		audit.applicability.state = audit.rankApprovedTargets.empty()
										? OfficialDriverApplicabilityState::NO_APPLICABLE_TARGETS
										: OfficialDriverApplicabilityState::APPLICABLE_TARGETS ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		// 全体例外では内容監査済みの閉包も保持しない。
		audit					  = {} ;
		audit.summary.state		  = OfficialDriverPackageAuditState::FAILURE ;
		audit.summary.error		  = static_cast<NativeError>( E_OUTOFMEMORY) ;
		audit.applicability.state = OfficialDriverApplicabilityState::FAILURE ;
		audit.applicability.error = audit.summary.error ;
		return audit.applicability.error ;
	} catch( ...) {
		// Callback例外をworker境界から漏らさず、部分的な合格集合を全て破棄する。
		// Callback例外で部分的な内容・適用性合格を残さない。
		audit					  = {} ;
		audit.summary.state		  = OfficialDriverPackageAuditState::FAILURE ;
		audit.summary.error		  = static_cast<NativeError>( E_UNEXPECTED) ;
		audit.applicability.state = OfficialDriverApplicabilityState::FAILURE ;
		audit.applicability.error = audit.summary.error ;
		return audit.applicability.error ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyOfficialAuditedInfPackage( const OfficialAuditedInfPackage &auditedPackage)
{
	const PackageAuditPolicy *policy = auditPolicy( auditedPackage.profile) ;	// 保持時と同じ条件。
	// 既知policy、所有workspace、非空entry、単一INFが揃わなければ再検証しない。
	if( policy == nullptr || auditedPackage.workspace == nullptr ||
	   auditedPackage.closure.entries.empty() || auditedPackage.closure.packages.size() != 1U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialDownloadWorkspace &workspace =
		*auditedPackage.workspace ;	// Scan時から閉包fileを所有する保護領域。
	// 全閉包fileをscan時snapshotへ戻し、部分的に差し替えられた状態を拒否する。
	for( const OfficialZipEntry &entry : auditedPackage.closure.entries) {
		const std::wstring path = workspace.path( entry.relativePath) ;	// 現在entry絶対path。
		// entryの保護pathと保存SHA-256を検証してから実fileを照合する。
		if( path.empty() || !isSha256Hex( entry.sha256)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const OfficialFileMetadataPolicy metadata{
			.expectedSize	= entry.uncompressedSize,
			.expectedSha256 = entry.sha256,
		} ; // Scan時に確定したsizeとhash。
		const NativeError error = verifyOfficialFileMetadata( path, metadata) ;	// 再照合結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}
	}

	const OfficialInfPackage &expected =
		// Scan時の完全なINF metadata。
		auditedPackage.closure.packages.front() ;
	OfficialInfPackage actual ;	// 現在fileから再解析するINF metadata。
	NativeError		   error =
		inspectOfficialInfPackage( workspace, auditedPackage.closure.entries,
								  expected.infRelativePath, policy->closure.infPolicy,
								  actual) ;	// Scan時と同じ構造policyによる結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 再解析したINFがdriver-only条件を満たさなければ拒否する。
	if( !isGenericInfPackageSupported( actual)) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	}

	error = verifyOfficialInfPackageIntegrity( workspace, actual, ACCEPTED_SIGNERS) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	return packagesEqual( expected, actual)
			   ? 0
			   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
}

} // namespace drivercrate
