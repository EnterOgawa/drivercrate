//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_audit.cpp
 * @brief WinOF-2閉包の内容・PnP監査と候補発行実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式取得identityとdriver閉包を同一scanへ拘束し、CAT監査後だけlocal PnP／rankを確認します。Hardware IDまたはlocal pathを候補へ渡
 *       しません。
 */
//------------------------------------------------------------------------------

#include "platform/nvidia_winof2_driver_audit.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_DEVICES		  = 4096U ;	// 一回のWinOF-2適用性監査対象上限。
constexpr std::size_t	MAXIMUM_CLOSURE_FILES = 8194U ;	// INF、CAT、参照fileの保持上限。
constexpr std::uint64_t MAXIMUM_CLOSURE_BYTES =
	64ULL * 1024ULL * 1024ULL ;	// 一INF閉包の展開後合計上限。
constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Net"), std::wstring_view( L"NetTrans"),
									  std::wstring_view( L"System"),
									  // 固定6系列のclass。
									  std::wstring_view( L"Ports")} ;
constexpr std::array ACCEPTED_PROVIDERS{std::wstring_view( L"Mellanox"),
										// 固定6系列のINF Provider。
										std::wstring_view( L"Mellanox Technologies Ltd.")} ;
constexpr std::array ACCEPTED_INF_NAMES{
	std::wstring_view( L"mlx5.inf"), std::wstring_view( L"mlx5mux.inf"),
	std::wstring_view( L"mlx5muxp.inf"), std::wstring_view( L"MlxRshimBus.inf"),
	std::wstring_view( L"MlxRshimCom.inf"),
	// 前段閉包が許可する固定INF名。
	std::wstring_view( L"MlxRshimEth.inf")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 公式英語classとmakerのlocale非依存比較だけに使用する。
 *
 * @param[in] value 比較する一文字。
 * @return ASCII英大文字は小文字、それ以外は入力値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] wchar_t asciiFold( const wchar_t value) noexcept
{
	return value >= L'A' && value <= L'Z' ? static_cast<wchar_t>( value + (L'a' - L'A')) : value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非ASCII文字を変換せず、英語policy値だけを比較する。
 *
 * @param[in] left 比較する一方の英語値。
 * @param[in] right 比較する他方の英語値。
 * @return ASCII英字の大小を無視して完全一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// 長さの異なるpolicy値を同一とみなさない。
	if( left.size() != right.size()) {
		return false ;
	}

	// 同じ位置の全文字を比較し、一文字でも異なる値を拒否する。
	for( std::size_t index = 0U; index < left.size(); ++index) {
		// ASCII大小文字差を除いても異なる値は不一致にする。
		if( asciiFold( left[index]) != asciiFold( right[index])) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通信要否とlocal監査対象を絞るためだけに使用する。
 *
 * @param[in] value 検索対象の非機密表示値。
 * @param[in] token 検索する固定英語maker名。
 * @return ASCII英字の大小を無視してtokenを含む場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiContains( const std::wstring_view value,
								 const std::wstring_view token) noexcept
{
	// 空tokenや入力より長いtokenを表示名probeの一致に使わない。
	if( token.empty() || token.size() > value.size()) {
		return false ;
	}

	// Tokenを収められる各開始位置を有限走査し、完全一致する窓を探す。
	for( std::size_t offset = 0U; offset <= value.size() - token.size(); ++offset) {
		// ASCII比較で一致する表示名部分を見つけたらprobe成功とする。
		if( asciiEqual( value.substr( offset, token.size()), token)) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示値や短縮hashを内部identityへ転用しない。
 *
 * @param[in] value 検証するSHA-256文字列。
 * @return 64桁の小文字16進数の場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSha256( const std::wstring_view value) noexcept
{
	// SHA-256の固定64桁に合わない内部identityを拒否する。
	if( value.size() != 64U) {
		return false ;
	}

	// 全桁を確認し、大文字または16進数以外を拒否する。
	for( const wchar_t character : value) {
		// 小文字hex以外のhash表現を内部identityとして受理しない。
		if( !((character >= L'0' && character <= L'9') ||
			 (character >= L'a' && character <= L'f'))) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式metadataの表示だけを取得済みidentityとして扱わない。
 *
 * @param[in] acquisition 外側WinOF-2 EXEの取得結果。
 * @return 固定Provider、payload用途、公開hash照合が成立する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidAcquisition( const OfficialAcquisitionResult &acquisition) noexcept
{
	return acquisition.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION &&
		   acquisition.error == 0 && acquisition.scanSessionId != 0U &&
		   acquisition.acquisitionId != 0U && acquisition.providerId == NVIDIA_WINOF2_PROVIDER_ID &&
		   acquisition.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID &&
		   !acquisition.inspectionPath.empty() && acquisition.byteCount != 0U &&
		   isSha256( acquisition.sha256) && acquisition.publishedSha256Verified ;
}

//------------------------------------------------------------------------------
/**
 * @brief Display、firmware、software componentを候補へ混入させない。
 *
 * @param[in] value INFまたはdeviceのsetup class。
 * @return WinOF-2固定6系列の許可classである場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedClass( const std::wstring_view value) noexcept
{
	// 固定class群だけを比較し、未知classを既定許可へ変換しない。
	for( const std::wstring_view accepted : ACCEPTED_CLASSES) {
		// 明示allowlistに一致するdriver classだけを認める。
		if( asciiEqual( value, accepted)) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief CATで保護するProvider値を候補発行前にも固定する。
 *
 * @param[in] value INFが明示したProvider表示名。
 * @return WinOF-2固定6系列の許可Providerである場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedProvider( const std::wstring_view value) noexcept
{
	// 固定Provider群だけを比較し、未知publisherを表示名から許可しない。
	for( const std::wstring_view accepted : ACCEPTED_PROVIDERS) {
		// 明示allowlistに一致するINF Provider値だけを認める。
		if( asciiEqual( value, accepted)) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 後段で任意のMSI fileをdriver閉包へ昇格しない。
 *
 * @param[in] value MSI mappingから解決した論理INF名。
 * @return ADR 0117の固定6系列に含まれる場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedInfName( const std::wstring_view value) noexcept
{
	// 固定INF群だけを比較し、pathや別名を推測して補完しない。
	for( const std::wstring_view accepted : ACCEPTED_INF_NAMES) {
		// 明示allowlistに一致するINF名だけを閉包監査へ渡す。
		if( asciiEqual( value, accepted)) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 再検証callbackの前にoverflowや空hashを拒否する。
 *
 * @param[in] closure 前段で作成した一INF閉包metadata。
 * @return Entry identityと合計sizeが有限で自己整合する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidClosureMetadata( const OfficialDriverClosure &closure) noexcept
{
	// 閉包のentry数、単一package、展開byte数が上限内で整合することを要求する。
	if( closure.entries.empty() || closure.entries.size() > MAXIMUM_CLOSURE_FILES ||
	   closure.packages.size() != 1U || closure.expandedBytes == 0U ||
	   closure.expandedBytes > MAXIMUM_CLOSURE_BYTES) {
		return false ;
	}

	std::uint64_t totalBytes{} ;	// 全entryを一度ずつ加算する検証済み合計。
	// 全entryの非空path、hash、size合計を確認し、overflow時点で拒否する。
	for( std::size_t index = 0U; index < closure.entries.size(); ++index) {
		const OfficialZipEntry &entry = closure.entries[index] ;	// 現在検証する閉包entry。
		// entry path、hash、合計byte上限を満たさない閉包を拒否する。
		if( entry.relativePath.empty() || !isSha256( entry.sha256) ||
		   entry.uncompressedSize > MAXIMUM_CLOSURE_BYTES - totalBytes) {
			return false ;
		}

		// 現在位置より前のpathだけと比較し、大文字小文字違いの重複も拒否する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			// Windows上で同一とみなすpathの重複を閉包へ含めない。
			if( asciiEqual( entry.relativePath, closure.entries[previous].relativePath)) {
				return false ;
			}
		}

		totalBytes += entry.uncompressedSize ;
	}

	return totalBytes == closure.expandedBytes ;
}

//------------------------------------------------------------------------------
/**
 * @brief 要素を補完せず、比較不能な版を最新版と推測しない。
 *
 * @param[in] value INFまたは現在driverの明示version。
 * @return 四要素をlosslessに解析できた場合は数値配列、それ以外は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::array<std::uint32_t, 4>> parseDriverVersion(
	const std::wstring_view value) noexcept
{
	std::array<std::uint32_t, 4> parts{} ;		// 解析済みの四要素。
	std::size_t					 partIndex{} ;	// 現在確定する要素index。
	std::uint64_t				 partValue{} ;	// Overflow検出用の現在要素値。
	bool						 hasDigit{} ;	// 現在要素に数字がある場合true。
	// 全文字を一度走査し、四要素以外、空要素、ASCII数字以外を拒否する。
	for( const wchar_t character : value) {
		// 数値版の数字を現在の要素へ取り込む。
		if( character >= L'0' && character <= L'9') {
			const std::uint32_t digit =
				// 現在の十進一桁。
				static_cast<std::uint32_t>( character - L'0') ;
			// 版要素の32-bit overflowを桁追加前に検出する。
			if( partValue > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
				return std::nullopt ;
			}

			partValue = partValue * 10U + digit ;
			hasDigit  = true ;
			continue ;
		}

		// 不正な区切り、空要素、過剰な版構成を拒否する。
		if( character != L'.' || !hasDigit || partIndex >= parts.size() - 1U) {
			return std::nullopt ;
		}

		parts[partIndex] = static_cast<std::uint32_t>( partValue) ;
		++partIndex ;
		partValue = 0U ;
		hasDigit  = false ;
	}

	// 末尾の空要素や必要要素数の不一致を補完せず拒否する。
	if( !hasDigit || partIndex != parts.size() - 1U) {
		return std::nullopt ;
	}

	parts[partIndex] = static_cast<std::uint32_t>( partValue) ;
	return parts ;
}

//------------------------------------------------------------------------------
/**
 * @brief 比較不能時は安全性や最新性を推測せず再導入へ分類する。
 *
 * @param[in] candidateVersion INFが明示した候補version。
 * @param[in] currentVersion 同じdeviceの現在driver version。
 * @return 厳密比較結果に対応する更新、再導入または旧版切替。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidateVersion,
										  const std::wstring_view currentVersion) noexcept
{
	const auto candidate = parseDriverVersion( candidateVersion) ;	// INFの明示version。
	const auto current	 = parseDriverVersion( currentVersion) ;	// 現在driverの明示version。
	// 比較不能な版は通常更新ではなく再導入に分類する。
	if( !candidate || !current) {
		return DriverAction::REINSTALL ;
	}

	// 候補版が現在版を上回る場合だけ通常更新に分類する。
	if( *candidate > *current) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版を下回る場合は旧版への切替として区別する。
	if( *candidate < *current) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 日付は表示だけに使用し、適用性または版比較に使用しない。
 *
 * @param[in] value INF DriverVerのMM/DD/YYYY日付。
 * @return YYYY/MM/DD形式。不正形式は空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverDate( const std::wstring_view value)
{
	// 固定形式に合わないINF日付から表示日付を推測しない。
	if( value.size() != 10U || value[2U] != L'/' || value[5U] != L'/') {
		return {} ;
	}

	// 区切り以外の全位置をASCII数字に限定する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		// 年月日の数値位置に数字以外を許容しない。
		if( index != 2U && index != 5U && (value[index] < L'0' || value[index] > L'9')) {
			return {} ;
		}
	}

	return std::wstring( value.substr( 6U, 4U)) + L"/" + std::wstring( value.substr( 0U, 2U)) + L"/" +
		   std::wstring( value.substr( 3U, 2U)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_driver_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isNvidiaWinof2AuditDevice( const OfficialCatalogDevice &device) noexcept
{
	const bool acceptedMaker = asciiContains( device.manufacturer, L"Mellanox") ||
							   // 公式系列に対応するlocal maker表示。
							   asciiContains( device.manufacturer, L"NVIDIA") ;
	return !device.deviceIdentity.empty() && !device.model.empty() && acceptedMaker &&
		   isAllowedClass( device.driverClass) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_driver_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditNvidiaWinof2DriverClosureForTesting(
	const OfficialAcquisitionResult			  &acquisition,
	std::unique_ptr<OfficialDownloadWorkspace> workspace, NvidiaWinof2DriverClosure driverClosure,
	const std::span<const OfficialCatalogDevice> devices,
	const NvidiaWinof2ClosureReverifier &reverifier, const OfficialInfRankAuditor &rankAuditor,
	NvidiaWinof2DriverAudit &audit)
{
	audit									 = {} ;
	OfficialDriverPackageAudit &packageAudit = audit.package ;	// 共通CAT、PnP、rank監査の出力部分。
	const bool					identityValid =
		isValidAcquisition( acquisition) && workspace != nullptr && reverifier && rankAuditor &&
		driverClosure.scanSessionId == acquisition.scanSessionId &&
		driverClosure.sourceAcquisitionId == acquisition.acquisitionId &&
		driverClosure.databaseSize != 0U && isSha256( driverClosure.databaseSha256) &&
		isAllowedInfName( driverClosure.selectedInfPath) && driverClosure.cabinetFileCount != 0U &&
		isValidClosureMetadata( driverClosure.closure) && !devices.empty() &&
		// 外側取得からlocal対象までの有限identity条件。
		devices.size() <= MAXIMUM_DEVICES ;
	// 取得identityが監査前提に合わなければ閉包監査を拒否する。
	if( !identityValid) {
		packageAudit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
		packageAudit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		return packageAudit.summary.error ;
	}

	try {
		std::unordered_set<std::wstring> deviceIdentities ;	// Local opaque IDの重複検査集合。
		deviceIdentities.reserve( devices.size()) ;
		// 全対象をWinOF-2のmaker／classへ限定し、別系列deviceをPnP監査へ渡さない。
		for( const OfficialCatalogDevice &device : devices) {
			// 対象外deviceやopaque identity重複を監査要求へ含めない。
			if( !isNvidiaWinof2AuditDevice( device) ||
			   !deviceIdentities.insert( device.deviceIdentity).second) {
				packageAudit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
				packageAudit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
				return packageAudit.summary.error ;
			}
		}

		const OfficialInfPackage &package =
			// 前段で構造監査したINF metadata。
			driverClosure.closure.packages.front() ;
		// 選択INF、CAT、参照file、Hardware ID、class、Providerの前提を確認する。
		if( !asciiEqual( driverClosure.selectedInfPath, package.infRelativePath) ||
		   package.catalogRelativePath.empty() || package.hardwareIds.empty() ||
		   package.sourceFiles.empty() || !isAllowedClass( package.className) ||
		   !isAllowedProvider( package.providerName)) {
			packageAudit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
			packageAudit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
			return packageAudit.summary.error ;
		}

		audit.scanSessionId		  = acquisition.scanSessionId ;
		audit.sourceAcquisitionId = acquisition.acquisitionId ;
		audit.databaseSha256	  = driverClosure.databaseSha256 ;
		audit.selectedInfPath	  = driverClosure.selectedInfPath ;
		OfficialAuditedInfPackage auditedPackage{
			.workspace = std::move( workspace),
			.closure   = std::move( driverClosure.closure),
			.profile   = OfficialDriverAuditProfile::NVIDIA_WINOF2} ;	// 再検証対象の所有値。
		const NativeError contentError = reverifier( auditedPackage) ;	// x64、CAT、publisher結果。
		packageAudit.scanSessionId	   = acquisition.scanSessionId ;
		packageAudit.summary.inventoryFileCount	  = auditedPackage.closure.entries.size() ;
		packageAudit.summary.infCount			  = 1U ;
		packageAudit.summary.archiveDepth		  = auditedPackage.closure.archiveDepth ;
		packageAudit.summary.retainedClosureBytes = auditedPackage.closure.expandedBytes ;
		// 内容検証に失敗した閉包は診断を保持し、PnP監査へ進めない。
		if( contentError != 0) {
			packageAudit.summary.state				 = OfficialDriverPackageAuditState::REJECTED ;
			packageAudit.summary.error				 = contentError ;
			packageAudit.summary.firstRejectionError = contentError ;
			packageAudit.summary.rejectedInfCount	 = 1U ;
			// CATまたはx64拒否をPnP監査へ進めない。
			return contentError ;
		}

		packageAudit.summary.state			 = OfficialDriverPackageAuditState::AUDITED ;
		packageAudit.summary.auditedInfCount = 1U ;
		packageAudit.auditedPackages.push_back( std::move( auditedPackage)) ;
		return auditOfficialDriverApplicability( acquisition.scanSessionId, devices, rankAuditor,
												packageAudit) ;
	} catch( const std::bad_alloc &) {
		audit						= {} ;
		audit.package.summary.state = OfficialDriverPackageAuditState::FAILURE ;
		audit.package.summary.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		return audit.package.summary.error ;
	} catch( ...) {
		// Callback例外時に部分合格閉包または適用対象を残さない。
		audit						= {} ;
		audit.package.summary.state = OfficialDriverPackageAuditState::FAILURE ;
		audit.package.summary.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return audit.package.summary.error ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_driver_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditNvidiaWinof2DriverClosure( const OfficialAcquisitionResult			 &acquisition,
										   std::unique_ptr<OfficialDownloadWorkspace> workspace,
										   NvidiaWinof2DriverClosure				  driverClosure,
										   const std::span<const OfficialCatalogDevice> devices,
										   const OfficialInfRankAuditor				   &rankAuditor,
										   NvidiaWinof2DriverAudit					   &audit)
{
	const NvidiaWinof2ClosureReverifier reverifier = []( const OfficialAuditedInfPackage &package) {
		return reverifyOfficialAuditedInfPackage( package) ;
	} ; // 固定共通再検証境界。
	return auditNvidiaWinof2DriverClosureForTesting( acquisition, std::move( workspace),
													std::move( driverClosure), devices, reverifier,
													rankAuditor, audit) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_driver_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<UpdateCandidate> makeNvidiaWinof2AuditedCandidates(
	const OfficialAcquisitionResult				&acquisition,
	const std::span<const OfficialCatalogDevice> devices, const NvidiaWinof2DriverAudit &audit)
{
	const OfficialDriverPackageAudit &packageAudit =
		audit.package ;	// 候補へ変換する共通内容・適用性監査結果。
	// 取得・監査session、閉包、rank承認件数の全証拠が整合する場合だけ候補を公開する。
	if( !isValidAcquisition( acquisition) || devices.empty() || devices.size() > MAXIMUM_DEVICES ||
	   audit.scanSessionId != acquisition.scanSessionId ||
	   audit.sourceAcquisitionId != acquisition.acquisitionId || !isSha256( audit.databaseSha256) ||
	   !isAllowedInfName( audit.selectedInfPath) ||
	   packageAudit.scanSessionId != acquisition.scanSessionId ||
	   packageAudit.summary.state != OfficialDriverPackageAuditState::AUDITED ||
	   packageAudit.summary.error != 0 || packageAudit.summary.auditedInfCount == 0U ||
	   packageAudit.summary.auditedInfCount != packageAudit.auditedPackages.size() ||
	   packageAudit.applicability.state != OfficialDriverApplicabilityState::APPLICABLE_TARGETS ||
	   packageAudit.applicability.error != 0 ||
	   packageAudit.applicability.applicablePairCount != packageAudit.rankApprovedTargets.size() ||
	   packageAudit.rankApprovedTargets.empty() ||
	   packageAudit.rankApprovedTargets.size() > MAXIMUM_DEVICES) {
		throw std::logic_error( "invalid WinOF-2 candidate publication") ;
	}

	std::unordered_map<std::wstring_view, const OfficialCatalogDevice *>
		deviceIndex ;	// Opaque local device索引。
	deviceIndex.reserve( devices.size()) ;
	// 監査時deviceを一意に索引化し、別scanまたは別makerの表示値を混入させない。
	for( const OfficialCatalogDevice &device : devices) {
		// 対象外またはidentity重複のdevice集合から候補を作らない。
		if( !isNvidiaWinof2AuditDevice( device) ||
		   !deviceIndex.emplace( device.deviceIdentity, &device).second) {
			throw std::logic_error( "invalid WinOF-2 candidate device") ;
		}
	}

	std::set<std::pair<std::wstring, std::wstring>> publishedVersions ;	// Device／版集合。
	std::vector<UpdateCandidate> candidates ;							// UIへ渡せる非機密の監査済み候補群。
	candidates.reserve( packageAudit.rankApprovedTargets.size()) ;
	// G11-D合格順で候補を作り、同じdevice／versionの複数INFを一件へまとめる。
	for( std::size_t index = 0U; index < packageAudit.rankApprovedTargets.size(); ++index) {
		const OfficialRankApprovedInfTarget &approved =
			packageAudit.rankApprovedTargets[index] ;						// 現在発行するINF／device合格組合せ。
		const auto device = deviceIndex.find( approved.deviceIdentity) ;	// 同一scanのdevice位置。
		// rank未承認、未知device、範囲外package indexを候補へ変換しない。
		if( approved.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
		   device == deviceIndex.end() ||
		   approved.auditedPackageIndex >= packageAudit.auditedPackages.size()) {
			throw std::logic_error( "invalid WinOF-2 rank target") ;
		}

		const OfficialAuditedInfPackage &audited =
			packageAudit.auditedPackages[approved.auditedPackageIndex] ;	// 対応する保持閉包。
		// 所有workspace、監査profile、単一packageの前提を公開前に確認する。
		if( !audited.workspace || audited.profile != OfficialDriverAuditProfile::NVIDIA_WINOF2 ||
		   audited.closure.packages.size() != 1U) {
			throw std::logic_error( "invalid WinOF-2 audited package") ;
		}

		const OfficialInfPackage &package = audited.closure.packages.front() ;	// INF明示metadata。
		// INF明示metadataと選択INF・device classの対応を再確認する。
		if( package.driverVersion.empty() || package.catalogRelativePath.empty() ||
		   package.hardwareIds.empty() || package.sourceFiles.empty() ||
		   !isAllowedProvider( package.providerName) || !isAllowedClass( package.className) ||
		   !asciiEqual( audit.selectedInfPath, package.infRelativePath) ||
		   !asciiEqual( package.className, device->second->driverClass)) {
			throw std::logic_error( "invalid WinOF-2 INF metadata") ;
		}

		// 同じdevice／同版の重複を表示候補へ発行しない。
		if( !publishedVersions.emplace( approved.deviceIdentity, package.driverVersion).second) {
			continue ;
		}

		UpdateCandidate candidate ;	// PathとPnP IDを含まない監査済み表示候補。
		candidate.identity = L"nvidia-winof2-driver:" + std::to_wstring( acquisition.scanSessionId) +
							 L":" + std::to_wstring( index) ;
		candidate.deviceIdentity  = approved.deviceIdentity ;
		candidate.providerId	  = std::wstring( NVIDIA_WINOF2_PROVIDER_ID) ;
		candidate.packageIdentity = L"nvidia-winof2-package:" +
									std::to_wstring( acquisition.scanSessionId) + L":" +
									std::to_wstring( acquisition.acquisitionId) ;
		candidate.title			  = L"NVIDIA Networking WinOF-2 Driver " + package.driverVersion ;
		candidate.manufacturer	  = device->second->manufacturer ;
		candidate.model			  = device->second->model ;
		candidate.driverClass	  = device->second->driverClass ;
		candidate.deviceClassGuid = device->second->deviceClassGuid ;
		candidate.provider		  = package.providerName ;
		candidate.version		  = package.driverVersion ;
		candidate.driverDate	  = formatDriverDate( package.driverDate) ;
		candidate.sourceName	  = L"NVIDIA Networking WinOF-2 official package" ;
		candidate.sourceLocation  = L"network.nvidia.com / content.mellanox.com" ;
		candidate.maximumDownloadBytes = acquisition.byteCount ;
		candidate.action = classifyAction( package.driverVersion, device->second->currentVersion) ;
		candidate.defaultPreference		 = CandidateDefaultPreference::NONE ;
		candidate.discoveryBasis		 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
		candidate.audit					 = makeOfficialReadyCandidateAudit() ;
		candidate.audit.installReadiness = CandidateInstallReadiness::BLOCKED ;
		candidate.current				 = false ;
		candidate.recommended			 = false ;
		candidate.installable			 = false ;
		candidate.eulaAccepted			 = false ;
		candidate.allContentCached		 = true ;
		candidate.rebootMayBeRequired	 = true ;
		candidate.browseOnly			 = false ;
		candidates.push_back( std::move( candidate)) ;
	}

	// 承認済みの公開要求から候補が一件も生成されない不整合を拒否する。
	if( candidates.empty()) {
		throw std::logic_error( "empty WinOF-2 candidate publication") ;
	}

	return candidates ;
}

} // namespace drivercrate
