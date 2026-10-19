//------------------------------------------------------------------------------
/**
 * @file asix_update_provider.cpp
 * @brief ASIX AX88179A公式検索・取得準備Provider実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  取得成功後の一回監査と独立結果保持を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  Driver Store rank監査callbackを保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  二page再確認と一回限定の検査用取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  取得準備snapshotと失効境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定ASIX pageへの要求に端末識別情報を加えず、取得URLはUIへ渡しません。二page結合済み情報だけを一配布物の未承認targetへ変換します。同意・前提確認後に一回だけ検
 *       査用取得を行い、内容監査と導入は許可しません。
 */
//------------------------------------------------------------------------------

#include "platform/asix_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/asix_catalog_parser.h"
#include "platform/asix_preparation.h"
#include "platform/official_prepared_acquisition.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <span>
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

constexpr std::size_t	MAXIMUM_DEVICES			   = 4096U ;					// 一回のscanで扱うdevice snapshot上限。
constexpr std::size_t	MAXIMUM_DISPLAY_CHARACTERS = 512U ;						// Local表示値の文字数上限。
constexpr std::uint64_t MAXIMUM_PRODUCT_PAGE_BYTES = 2ULL * 1024ULL * 1024ULL ;	// 製品page受信上限。
constexpr std::uint64_t MAXIMUM_TERMS_PAGE_BYTES   = 256ULL * 1024ULL ;			// 固定Termsの受信上限。
constexpr std::uint64_t MAXIMUM_ASIX_PAYLOAD_BYTES =
	8ULL * 1024ULL * 1024ULL ;									// 一file／Provider／scanに予約する取得上限。
constexpr std::uint32_t		WINDOWS10_MINIMUM_BUILD = 10'240U ;	// 対象Windows clientの下限。
// 端末情報を付加せず取得する、AX88179A英語製品pageの固定URL。
constexpr std::wstring_view PRODUCT_PAGE_URL =
	L"https://www.asix.com.tw/en/product/USBEthernet/Super-Speed_USB_Ethernet/AX88179A" ;
constexpr std::wstring_view TERMS_PAGE_URL =
	L"https://www.asix.com.tw/en/useterm" ;	// 製品pageから参照する固定許諾起点。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Class名やGUIDの部分一致を対象deviceとして受理しない。
 *
 * @param[in] value 最大512文字のlocal表示値。
 * @param[in] expected 完全一致を要求するsetup class値。
 * @return 大文字小文字以外が完全一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameText( const std::wstring_view value,
							const std::wstring_view expected) noexcept
{
	return !value.empty() && value.size() <= MAXIMUM_DISPLAY_CHARACTERS &&
		   value.size() == expected.size() &&
		   CompareStringOrdinal( value.data(), static_cast<int>( value.size()), expected.data(),
								static_cast<int>( expected.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief Hardware IDを構築せず、有限なlocal表示名のprobeだけに使用する。
 *
 * @param[in] text 最大512文字のlocal表示値。
 * @param[in] token 大文字小文字を無視して探す系列語。
 * @return Tokenが含まれる場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsText( const std::wstring_view text,
								const std::wstring_view token) noexcept
{
	// 空、上限外または長さ不整合を拒否する。
	if( text.empty() || text.size() > MAXIMUM_DISPLAY_CHARACTERS || token.empty() ||
	   token.size() > text.size()) {
		return false ;
	}

	// Tokenを配置可能な全開始位置で有限回比較する。
	for( std::size_t offset = 0U; offset <= text.size() - token.size(); ++offset) {
		// 表示名内の有限な比較範囲が大小を無視して一致した場合にだけprobeを成立とする。
		if( CompareStringOrdinal( text.data() + offset, static_cast<int>( token.size()), token.data(),
								static_cast<int>( token.size()), TRUE) == CSTR_EQUAL) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Server、Windows 10未満、build不明をnetwork検索前に除外する。
 *
 * @param[in] windowsServer 実OSがServerの場合true。
 * @param[in] windowsBuild 実OSのmajor build。0は判定不能。
 * @return Windows 10以降のclient buildならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSupportedWindowsClient( const bool			windowsServer,
											const std::uint32_t windowsBuild) noexcept
{
	return !windowsServer && windowsBuild >= WINDOWS10_MINIMUM_BUILD ;
}

//------------------------------------------------------------------------------
/**
 * @brief Page版をtitleだけへ表示し、INF版または更新必要性として扱わない。
 *
 * @param[in] session 当該検索session。
 * @param[in] ordinal Session内の0始まり表示行連番。
 * @param[in] device Local probeが一致したdevice snapshot。
 * @param[in] release 実OSに対応する公式pageの配布情報。
 * @return URLを含まない非選択・非推奨の所有DTO。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeAsixCandidate( const ScanSessionId			 session,
												const std::size_t			 ordinal,
												const OfficialCatalogDevice &device,
												const AsixDriverPageEntry	&release)
{
	UpdateCandidate	   candidate ;								// UIへ返す表示専用の所有DTO。
	const std::wstring sourceId( ASIX_AX88179A_PROVIDER_ID) ;	// Registryと一致する取得元ID。
	candidate.identity =
		sourceId + L":info:" + std::to_wstring( session) + L":" + std::to_wstring( ordinal) ;
	candidate.packageIdentity = sourceId + L":release:" + std::to_wstring( session) + L":0" ;
	candidate.providerId	  = sourceId ;
	candidate.deviceIdentity  = device.deviceIdentity ;
	candidate.title			  = release.title + L" " + release.version + L"（公式配布情報）" ;
	candidate.manufacturer	  = device.manufacturer ;
	candidate.model			  = device.model ;
	candidate.driverClass	  = device.driverClass ;
	candidate.deviceClassGuid = device.deviceClassGuid ;
	candidate.driverDate	  = release.releaseDate ;
	// Registryの表示名だけを取得元名称の正本として使用する。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// ASIXの正式表示名は同じstable IDのregistry定義から取得する。
		if( descriptor.id == ASIX_AX88179A_PROVIDER_ID) {
			candidate.sourceName = descriptor.displayName ;
			break ;
		}
	}

	candidate.sourceLocation	= L"ASIX公式 HTTPS（www.asix.com.tw、payload未取得）" ;
	candidate.discoveryBasis	= CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	candidate.audit				= makeOfficialDiscoveryCandidateAudit() ;
	candidate.action			= DriverAction::NONE ;
	candidate.defaultPreference = CandidateDefaultPreference::NONE ;
	candidate.current			= false ;
	candidate.recommended		= false ;
	candidate.installable		= false ;
	candidate.eulaAccepted		= false ;
	candidate.allContentCached	= false ;
	candidate.browseOnly		= false ;
	return candidate ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hashとEULAがない事実を維持し、観測比較以外の許可へ変換しない。
 *
 * @param[in] release 専用parserが検証した公式pageの配布情報。
 * @return 数値download IDをstable keyとするworker内専用record。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialReleaseRecord makeAsixReleaseRecord( const AsixDriverPageEntry &release)
{
	OfficialReleaseRecord record ;	// 全fieldを所有し、候補DTOへは渡さない配布情報。
	record.family		  = OfficialReleaseFamily::ASIX_AX88179A ;
	record.releaseKey	  = release.releaseKey ;
	record.packageVersion = release.version ;
	record.displaySize	  = release.displaySize ;
	record.downloadUrl	  = release.downloadUrl ;
	record.license		  = OfficialReleaseLicense::UNRESOLVED ;
	record.parserRevision = 1U ;
	return record ;
}

//------------------------------------------------------------------------------
/**
 * @brief Scanと取得直前再確認が同じ順序・parser・OS選択を使用する。
 *
 * @param[in] session 二pageに共通する検索session。
 * @param[in] windowsServer Serverでは取得前に拒否する。
 * @param[in] windowsBuild 対象clientのmajor build。
 * @param[in] productReader 製品pageと取得根拠を確認する同期境界。
 * @param[in] termsReader 同じsource sessionのTerms取得境界。
 * @param[out] productHtml 成功時に表示候補解析へ再利用する製品本文。
 * @param[out] record 全条件成立時の結合済み配布record。失敗時は空。
 * @param[out] rejected 入力・metadata拒否の場合true。
 * @return 成功時0。通信失敗は元の診断値、metadata不成立はERROR_INVALID_DATA。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readPreparedPages( const ScanSessionId session, const bool windowsServer,
											const std::uint32_t			 windowsBuild,
											const AsixProductPageReader &productReader,
											const AsixTermsPageReader	&termsReader,
											std::wstring				&productHtml,
											OfficialReleaseRecord &record, bool &rejected)
{
	productHtml.clear() ;
	record	 = {} ;
	rejected = false ;
	// 不正session、reader欠落、未対応OSでは製品page取得を開始しない。
	if( session == 0U || !productReader || !termsReader ||
	   !isSupportedWindowsClient( windowsServer, windowsBuild)) {
		rejected = true ;
		// 不正条件でpage取得を開始しない。
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	NativeError error = productReader( session, productHtml) ;	// 元の通信診断値。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	AsixAx88179aCatalog catalog ;	// Terms取得前に検査する製品metadata。
	AsixDriverPageEntry entry ;		// 実OSに対応する一配布行。
	// 製品pageのschemaまたはOS選択が不正ならmetadata拒否として返す。
	if( !parseAsixAx88179aProductPage( productHtml, catalog) ||
	   !selectAsixAx88179aWindowsEntry( catalog, windowsServer, windowsBuild, entry)) {
		rejected = true ;
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	std::wstring termsHtml ;	// この同期呼出しの間だけ保持するTerms本文。
	error = termsReader( session, termsHtml) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 製品pageとTermsの結合に失敗した場合は準備用recordを発行しない。
	if( !makeAsixAx88179aPreparedRelease( productHtml, termsHtml, windowsServer, windowsBuild,
										record)) {
		rejected = true ;
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補のdevice identityを対応の正本とし、入力順や表示名から推測しない。全検証完了まで出力を変更しない。
 *
 * @param[in] session 候補を生成した0ではないscan session。
 * @param[in] devices 検索へ渡した全deviceの非機密snapshot。
 * @param[in] result ASIX検索が返した候補順の結果。
 * @param[out] retainedDevices 成功時に候補順で更新する対象device群。
 * @param[out] retainedCandidateIdentities 同順で更新するopaque候補ID群。
 * @return 全候補が一意なASIX対象deviceへ一対一対応する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool makeAsixScanBindings( const ScanSessionId							 session,
										const std::span<const OfficialCatalogDevice> devices,
										const ScanResult							&result,
										std::vector<OfficialCatalogDevice> &retainedDevices,
										std::vector<std::wstring> &retainedCandidateIdentities)
{
	// 失敗・空・旧session・上限外の結果を取得後監査へ保持しない。
	if( session == 0U || !result.succeeded || result.scanSessionId != session ||
	   result.state != ProviderScanState::CANDIDATES_AVAILABLE || result.candidates.empty() ||
	   result.candidates.size() > MAXIMUM_DEVICES || devices.size() > MAXIMUM_DEVICES) {
		return false ;
	}

	// 全inventory identityの重複を再確認する集合。
	std::unordered_set<std::wstring>								inventoryIdentities ;
	// ASIX候補が参照できるdevice identityと入力snapshotの対応表。
	std::unordered_map<std::wstring, const OfficialCatalogDevice *> eligibleDevices ;
	inventoryIdentities.reserve( devices.size()) ;
	eligibleDevices.reserve( result.candidates.size()) ;
	// 検索と同じ対象条件を再適用し、候補から逆引きできる有限な対応表を作る。
	for( const OfficialCatalogDevice &device : devices)	// 現在検証中の非機密snapshot。
	{
		// 空または重複identityを同じdeviceとして扱わない。
		if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
		   !inventoryIdentities.insert( device.deviceIdentity).second) {
			return false ;
		}

		// 一つのASIX identityへ複数snapshotを割り当てない。
		if( isAsixAx88179aDevice( device) &&
		   !eligibleDevices.emplace( device.deviceIdentity, &device).second) {
			return false ;
		}
	}

	// 表示されていない対象deviceまたは対応deviceのない候補を拒否する。
	if( eligibleDevices.size() != result.candidates.size()) {
		return false ;
	}

	std::vector<OfficialCatalogDevice> matchedDevices ;			// 候補順へ揃えた一時device群。
	std::vector<std::wstring>		   candidateIdentities ;	// 同じindexの一時候補ID群。
	// 候補identityの重複を検証する集合。
	std::unordered_set<std::wstring>   uniqueCandidateIdentities ;
	// 一つのdeviceへ複数候補を対応付けないための消費済みidentity集合。
	std::unordered_set<std::wstring>   consumedDeviceIdentities ;
	matchedDevices.reserve( result.candidates.size()) ;
	candidateIdentities.reserve( result.candidates.size()) ;
	uniqueCandidateIdentities.reserve( result.candidates.size()) ;
	consumedDeviceIdentities.reserve( result.candidates.size()) ;
	// Resultの候補順を維持し、明示device identityだけで入力snapshotへ対応付ける。
	for( const UpdateCandidate &candidate : result.candidates)	// 現在対応付ける表示候補。
	{
		// 候補が指す対象deviceを検索する一時iterator。
		const auto device = eligibleDevices.find( candidate.deviceIdentity) ;
		// 別Provider、未知deviceまたは重複対応を保持しない。
		if( candidate.identity.empty() || candidate.providerId != ASIX_AX88179A_PROVIDER_ID ||
		   device == eligibleDevices.end() ||
		   !uniqueCandidateIdentities.insert( candidate.identity).second ||
		   !consumedDeviceIdentities.insert( candidate.deviceIdentity).second) {
			return false ;
		}

		matchedDevices.push_back( *device->second) ;
		candidateIdentities.push_back( candidate.identity) ;
	}

	retainedDevices				= std::move( matchedDevices) ;
	retainedCandidateIdentities = std::move( candidateIdentities) ;
	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isAsixAx88179aDevice( const OfficialCatalogDevice &device) noexcept
{
	// 不正identityまたは過大表示値をnetwork対象にしない。
	if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
	   device.model.size() > MAXIMUM_DISPLAY_CHARACTERS ||
	   device.manufacturer.size() > MAXIMUM_DISPLAY_CHARACTERS) {
		return false ;
	}

	const bool netClass =
		sameText( device.driverClass, L"Net") &&
		sameText( device.deviceClassGuid,
				 L"{4d36e972-e325-11ce-bfc1-08002be10318}") ;	// Net classの完全一致境界。
	const bool asixName = containsText( device.manufacturer, L"ASIX") ||
						  // Localメーカー表示境界。
						  containsText( device.model, L"ASIX") ;
	return netClass && asixName && containsText( device.model, L"AX88179A") ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
AsixUpdateProvider::AsixUpdateProvider( OfficialInfRankAuditor rankAuditor)
	: rankAuditor_( std::move( rankAuditor))
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
AsixUpdateProvider::AsixUpdateProvider( OfficialInfRankAuditor			 rankAuditor,
									   OfficialInfInstallBinder			 binder,
									   OfficialInfInstallBindingReleaser releaser,
									   OfficialBoundInfInstaller		 installer)
	: rankAuditor_( std::move( rankAuditor)), bindingCreator_( std::move( binder)),
	  bindingReleaser_( std::move( releaser)), boundInstaller_( std::move( installer))
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
AsixUpdateProvider::~AsixUpdateProvider()
{
	invalidateScanSession() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void AsixUpdateProvider::configureReleaseObservationContext(
	const std::span<const LocalOfficialReleaseObservation> previous,
	const OfficialReleaseEnvironmentFingerprints		  &environment)
{
	previousReleaseObservations_.assign( previous.begin(), previous.end()) ;
	observationEnvironment_ = environment ;
	currentReleaseObservations_.clear() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const LocalOfficialReleaseObservation> AsixUpdateProvider::releaseObservations()
	const noexcept
{
	return currentReleaseObservations_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult scanAsixAx88179aProductPage( const ScanSessionId							scanSessionId,
									   const std::span<const OfficialCatalogDevice> devices,
									   const bool windowsServer, const std::uint32_t windowsBuild,
									   const AsixProductPageReader			 &reader,
									   const ProviderProgressCallback		 &progressCallback,
									   const AsixReleaseObservationEvaluator &observationEvaluator)
{
	ScanResult result{.scanSessionId = scanSessionId,
					  .outcome		 = OutcomeCode::FAILURE,
					  .state		 = ProviderScanState::FAILURE} ;	// 全条件成立までは失敗。
	// 未発行session、過大な対象集合、callback欠落では通信しない。
	if( scanSessionId == 0U || devices.size() > MAXIMUM_DEVICES || !reader || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 不正session、上限またはcallback欠落では通信しない。
		return result ;
	}

	std::vector<const OfficialCatalogDevice *> matched ;	// 呼出し中だけ有効な対象device参照。
	std::unordered_set<std::wstring>		   identities ;	// Opaque identityの重複検出集合。
	// 全deviceを有限回確認し、ASIX AX88179Aだけを検索対象へ残す。
	for( const OfficialCatalogDevice &device : devices) {
		// 空・過長・重複のdevice identityを曖昧な候補へ変換しない。
		if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
		   !identities.insert( device.deviceIdentity).second) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			// 空または重複identityから曖昧な候補を生成しない。
			return result ;
		}

		// ASIX AX88179Aに対応するlocal deviceだけを検索対象へ含める。
		if( isAsixAx88179aDevice( device)) {
			matched.push_back( &device) ;
		}
	}

	result.coverage.eligibleDeviceCount = matched.size() ;
	// 対応deviceがない場合と未対応OSでは通信せず対象外を返す。
	if( matched.empty() || !isSupportedWindowsClient( windowsServer, windowsBuild)) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100U,
						  .completedItems  = 0U,
						  .totalItems	   = 0U}) ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 0U,
					  .completedItems  = 0U,
					  .totalItems	   = matched.size()}) ;
	std::wstring html ;	// 固定上限内のASIX製品page本文。
	result.error = reader( scanSessionId, html) ;
	// 通信失敗を候補なしとして扱わない。
	if( result.error != 0) {
		return result ;
	}

	AsixAx88179aCatalog catalog ;	// Schema検証済み二OS分の表示情報。
	AsixDriverPageEntry release ;	// 実OSへ対応する一行の表示情報。
	// page schema変更とOS行欠落を推測で補わずmetadata拒否にする。
	if( !parseAsixAx88179aProductPage( html, catalog) ||
	   !selectAsixAx88179aWindowsEntry( catalog, windowsServer, windowsBuild, release)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		// Page変更またはOS行欠落を推測で補完しない。
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 70U,
					  .completedItems  = 0U,
					  .totalItems	   = matched.size()}) ;
	const OfficialReleaseRecord releaseRecord =
		// 数値IDを表示行から分離した観測入力。
		makeAsixReleaseRecord( release) ;
	bool observationFailed{} ;	// 一件でも評価不能なら全候補の差分表示を破棄する。
	// 同じ配布情報を対象deviceごとの表示行へ変換する。
	for( std::size_t index = 0U; index < matched.size(); ++index) {
		UpdateCandidate candidate =
			// 表示行。
			makeAsixCandidate( scanSessionId, index, *matched[index], release) ;
		// 観測callbackがあり先行失敗もない場合にだけrelease差分を評価する。
		if( observationEvaluator && !observationFailed) {
			const std::optional<ReleaseObservationDifference> difference =
				// 非機密差分だけを受領。
				observationEvaluator( *matched[index], releaseRecord) ;
			// 評価済みの差分が得られた候補にだけ観測情報を付記する。
			if( difference.has_value()) {
				candidate.releaseObservationDifference = *difference ;
			} else {
				observationFailed = true ;
			}
		}

		result.candidates.push_back( std::move( candidate)) ;
		progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete =
							  static_cast<std::uint32_t>( 70U + (index + 1U) * 30U / matched.size()),
						  .completedItems = index + 1U,
						  .totalItems	  = matched.size()}) ;
	}

	// 観測評価が一件でも失敗した場合は部分的な差分表示を全候補から除く。
	if( observationFailed) {
		// 部分的な差分表示を残さず、従来の表示専用候補だけを維持する。
		for( UpdateCandidate &candidate : result.candidates) {
			candidate.releaseObservationDifference.reset() ;
		}
	}

	result.coverage.assessedDeviceCount = matched.size() ;
	result.succeeded					= true ;
	result.outcome						= OutcomeCode::SUCCESS ;
	result.state						= ProviderScanState::CANDIDATES_AVAILABLE ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<OfficialPreparationTarget> makeAsixPreparationTargets(
	const OfficialReleaseRecord &release, const ScanSessionId scanSessionId,
	const std::uint64_t planId, const std::uint32_t deviceCount)
{
	// 未結合、対象外または予約上限外の情報を取得承認へ渡さない。
	if( release.family != OfficialReleaseFamily::ASIX_AX88179A || scanSessionId == 0U ||
	   planId == 0U || deviceCount == 0U || deviceCount > MAXIMUM_DEVICES ||
	   release.parserRevision < 2U || release.packageVersion.empty() ||
	   release.publishedDate.empty() ||
	   release.license != OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ||
	   release.eulaRevision.empty() || !validPreparationEulaText( release.eulaText) ||
	   !validPreparedReleaseIdentity( release) ||
	   (!release.publishedSha256.empty() &&
		(release.publishedSha256.size() != 64U ||
		 release.publishedSha256.find_first_not_of( L"0123456789ABCDEF") != std::wstring::npos)) ||
	   (release.publishedSizeBytes.has_value() &&
		(*release.publishedSizeBytes == 0U ||
		 *release.publishedSizeBytes > MAXIMUM_ASIX_PAYLOAD_BYTES))) {
		return {} ;
	}

	const OfficialSourceDefinition *const definition =
		// Registryとsource policyに結合した定義。
		officialSourceDefinition( release.family) ;
	// 未登録系列からProvider IDを推測しない。
	if( definition == nullptr) {
		return {} ;
	}

	OfficialPreparationTarget target ;	// URLを含まず、利用者へ提示できる固定snapshot。
	target.providerId = definition->providerId ;
	target.identity	  = target.providerId + L":prepare:" + std::to_wstring( planId) ;
	target.resourceId = OFFICIAL_PAYLOAD_RESOURCE_ID ;
	target.releaseIdentity =
		target.providerId + L":release:" + std::to_wstring( scanSessionId) + L":0" ;
	target.parserRevision					= release.parserRevision ;
	target.maximumBytes						= MAXIMUM_ASIX_PAYLOAD_BYTES ;
	target.deviceCount						= deviceCount ;
	target.terms							= OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
	target.eulaRevision						= release.eulaRevision ;
	target.eulaText							= release.eulaText ;
	target.requiresPrerequisiteConfirmation = true ;
	const OfficialPreparationLimits limits{.maximumFileBytes	 = MAXIMUM_ASIX_PAYLOAD_BYTES,
										   .maximumProviderBytes = MAXIMUM_ASIX_PAYLOAD_BYTES,
										   .maximumSessionBytes	 = MAXIMUM_ASIX_PAYLOAD_BYTES,
										   .maximumProviderFiles = 1U,
										   .maximumSessionFiles =
											   1U} ;	// ASIXだけへ適用する一file／一回の予約上限。
	OfficialPreparationSession		validation ;		// 共通のID、本文、件数、容量検証境界。
	// UIへ提示した後で不正になるtargetを発行しない。
	if( validation.initialize( {scanSessionId, planId, limits, {target}}) !=
	   OfficialPreparationError::NONE) {
		return {} ;
	}

	return {std::move( target)} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult AsixUpdateProvider::scanWithPreparedPageReaders(
	const ScanSessionId scanSessionId, const std::span<const OfficialCatalogDevice> devices,
	const bool windowsServer, const std::uint32_t windowsBuild,
	const AsixProductPageReader &productReader, const AsixTermsPageReader &termsReader,
	const ProviderProgressCallback		  &progressCallback,
	const AsixReleaseObservationEvaluator &observationEvaluator)
{
	ScanResult result{.scanSessionId = scanSessionId,
					  .outcome		 = OutcomeCode::FAILURE,
					  .state = ProviderScanState::FAILURE} ;	// 全条件成立まで保持を許可しない結果。
	// 別threadのscanでは所有workerのsnapshotに触れず拒否する。
	if( ownerThreadId_ != 0U && GetCurrentThreadId() != ownerThreadId_) {
		result.error = static_cast<NativeError>( E_ACCESSDENIED) ;
		// 別threadの新scanで所有workerのsnapshotを失効させない。
		return result ;
	}

	resetPreparedSnapshot() ;
	httpClient_.invalidateSourceSession() ;
	currentReleaseObservations_.clear() ;
	// readerと進捗通知先が揃わない要求を対象外へ変換しない。
	if( !productReader || !termsReader || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		// Reader欠落を対象外や許諾不要に変換しない。
		return result ;
	}

	try {
		OfficialReleaseRecord		release ;				// 候補と観測へ共通使用する二page結合済みrecord。
		bool						metadataRejected{} ;	// 通信失敗とparser拒否の区別。
		const AsixProductPageReader joinedReader = [&]( const ScanSessionId session,
													   std::wstring		  &html) {
			return readPreparedPages( session, windowsServer, windowsBuild, productReader,
									 termsReader, html, release, metadataRejected) ;
		} ; // Local probe成功後だけ二pageを読み、完了前にTermsを確認する。
		AsixReleaseObservationEvaluator joinedEvaluator ;	// 任意の端末内観測境界。
		// 観測評価が必要な場合は二page結合後のrecordを渡すcallbackを使用する。
		if( observationEvaluator) {
			joinedEvaluator = [&]( const OfficialCatalogDevice &device,
								  const OfficialReleaseRecord &) {
				return observationEvaluator( device, release) ;
			} ; // Revision 1の旧recordを渡さない。
		}

		result = scanAsixAx88179aProductPage( scanSessionId, devices, windowsServer, windowsBuild,
											 joinedReader, progressCallback, joinedEvaluator) ;
		// scan不成立時はsource sessionと部分観測を破棄して次工程へ引き継がない。
		if( !result.succeeded || result.state != ProviderScanState::CANDIDATES_AVAILABLE) {
			// metadataに起因する失敗を一般的な通信失敗から区別する。
			if( metadataRejected) {
				result.state = ProviderScanState::METADATA_REJECTED ;
			}

			httpClient_.invalidateSourceSession() ;
			currentReleaseObservations_.clear() ;
			// 不成立の取得根拠や部分観測を次工程へ引き継がない。
			return result ;
		}

		// 配布familyまたはdevice・候補bindingが不正なら準備状態を確定しない。
		if( release.family != OfficialReleaseFamily::ASIX_AX88179A ||
		   !makeAsixScanBindings( scanSessionId, devices, result, retainedDevices_,
								 retainedCandidateIdentities_)) {
			result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		} else {
			retainedRelease_	  = std::move( release) ;
			retainedSessionId_	  = scanSessionId ;
			retainedDeviceCount_  = static_cast<std::uint32_t>( result.candidates.size()) ;
			retainedWindowsBuild_ = windowsBuild ;
			ownerThreadId_		  = GetCurrentThreadId() ;
			return result ;
		}
	} catch( const std::bad_alloc &) {
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// Callback例外も診断値へ変換する。
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	resetPreparedSnapshot() ;
	httpClient_.invalidateSourceSession() ;
	currentReleaseObservations_.clear() ;
	result.succeeded					= false ;
	result.outcome						= OutcomeCode::FAILURE ;
	result.state						= ProviderScanState::FAILURE ;
	result.coverage.assessedDeviceCount = 0U ;
	result.candidates.clear() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<OfficialPreparationTarget> AsixUpdateProvider::preparationTargets(
	const ScanSessionId scanSessionId, const std::uint64_t planId)
{
	// Session、thread、監査境界またはsnapshotが不成立なら計画を発行しない。
	if( scanSessionId == 0U || scanSessionId != retainedSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || acquisitionAttempted_ || planId == 0U ||
	   planId <= preparedPlanId_ || retainedDeviceCount_ == 0U || !rankAuditor_ ||
	   retainedDevices_.size() != retainedDeviceCount_ ||
	   retainedCandidateIdentities_.size() != retainedDevices_.size()) {
		return {} ;
	}

	auto targets = makeAsixPreparationTargets( retainedRelease_, scanSessionId, planId,
											  retainedDeviceCount_) ;	// 一配布物の対象。
	// 有効な準備対象が生成された場合にだけ対象とplan IDを保持する。
	if( !targets.empty()) {
		preparedTarget_ = targets.front() ;
		preparedPlanId_ = planId ;
	}

	return targets ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void AsixUpdateProvider::resetPreparedSnapshot() noexcept
{
	// 自分が発行したtokenだけを破棄し、他Providerのbindingを失効させない。
	if( bindingReleaser_) {
		// 保持routingの上限内で、一候補に一つのtokenを解放する。
		for( const auto &entry : installTargets_)	// 現在解放する候補routing。
		{
			static_cast<void>( bindingReleaser_( retainedSessionId_, entry.second.binding.token)) ;
		}
	}

	installTargets_.clear() ;
	candidatesPublished_ = false ;
	// INF閉包を外側取得fileとworkspaceより先に解放する。
	preparedAudit_ = {} ;
	acquisition_   = {} ;
	acquisitionSession_.reset() ;
	// 専用RAIIが自分で作成した取得fileだけを解放する。
	workspace_.reset() ;
	acquisitionAttempted_ = false ;
	auditReportResolved_  = false ;
	preparedTarget_.reset() ;
	retainedRelease_ = {} ;
	retainedCandidateIdentities_.clear() ;
	// 候補IDより後に参照先deviceの所有copyを解放する。
	retainedDevices_.clear() ;
	retainedSessionId_	  = 0U ;
	retainedDeviceCount_  = 0U ;
	retainedWindowsBuild_ = 0U ;
	ownerThreadId_		  = 0U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError AsixUpdateProvider::readProductPage( const ScanSessionId session, std::wstring &html)
{
	NativeError error = httpClient_.beginSourceSession(
		session, ASIX_AX88179A_PROVIDER_ID) ;	// Source session開始の元診断値。
	// Session開始と取得の元診断値を保持し、根拠が成立した本文だけを返す。
	if( error == 0) {
		error = httpClient_.getUtf8TextForSource( PRODUCT_PAGE_URL, OFFICIAL_LANDING_RESOURCE_ID,
												 MAXIMUM_PRODUCT_PAGE_BYTES, html) ;
	}

	// 本文だけで公式由来と判断しない。
	if( error == 0 && !httpClient_.hasSourceEvidence( session, ASIX_AX88179A_PROVIDER_ID,
													OFFICIAL_LANDING_RESOURCE_ID)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError AsixUpdateProvider::readTermsPage( const ScanSessionId session, std::wstring &html)
{
	// 別sessionのTermsだけを取得しない。
	if( !httpClient_.hasSourceEvidence( session, ASIX_AX88179A_PROVIDER_ID,
									  OFFICIAL_LANDING_RESOURCE_ID)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const NativeError error = httpClient_.getUtf8TextForSource(
		TERMS_PAGE_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, MAXIMUM_TERMS_PAGE_BYTES,
		html) ;	// 固定Termsの取得診断値。
	// 先行する製品pageの取得根拠がない状態ではTerms取得を許可しない。
	if( error == 0 && !httpClient_.hasSourceEvidence( session, ASIX_AX88179A_PROVIDER_ID,
													OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult AsixUpdateProvider::acquireForInspection(
	const OfficialPreparationTask &task, const PreparationCancellation &cancellation)
{
	// 同意済みtaskと保持snapshot・所有thread・両pageの公式由来が一致しない取得を拒否する。
	if( !preparedTarget_ || acquisitionAttempted_ || task.operationId == 0U ||
	   task.scanSessionId == 0U || task.scanSessionId != retainedSessionId_ ||
	   task.planId != preparedPlanId_ || task.target != *preparedTarget_ ||
	   GetCurrentThreadId() != ownerThreadId_ || retainedDeviceCount_ == 0U || !rankAuditor_ ||
	   retainedDevices_.size() != retainedDeviceCount_ ||
	   retainedCandidateIdentities_.size() != retainedDevices_.size() ||
	   preparedTarget_->deviceCount != retainedDeviceCount_ ||
	   preparedTarget_->maximumBytes != MAXIMUM_ASIX_PAYLOAD_BYTES ||
	   !preparedTarget_->requiresPrerequisiteConfirmation ||
	   preparedTarget_->terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED ||
	   !httpClient_.hasSourceEvidence( retainedSessionId_, ASIX_AX88179A_PROVIDER_ID,
									  OFFICIAL_LANDING_RESOURCE_ID) ||
	   !httpClient_.hasSourceEvidence( retainedSessionId_, ASIX_AX88179A_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_INVALIDARG), 0} ;
	}

	// 受理した試行は取消し・失敗も含め一回で消費する。
	acquisitionAttempted_ = true ;
	// 検索時と実OSが変わっていれば、別OS向け配布物を取得せず手動再検索を要求する。
	if( isWindowsServer() || currentWindowsBuildNumber() != retainedWindowsBuild_) {
		return {OfficialPreparationItemState::REJECTED,
				static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)), 0} ;
	}

	try {
		// 利用者の取消しが確定済みなら、workspace作成とmetadata再取得も開始しない。
		if( cancellation && cancellation()) {
			return {OfficialPreparationItemState::CANCELLED,
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)), 0} ;
		}

		workspace_			= std::make_unique<OfficialDownloadWorkspace>() ;
		acquisitionSession_ = std::make_unique<OfficialAcquisitionSession>() ;
		const OfficialAcquisitionLimits limits{MAXIMUM_ASIX_PAYLOAD_BYTES,
											   MAXIMUM_ASIX_PAYLOAD_BYTES,
											   MAXIMUM_ASIX_PAYLOAD_BYTES,
											   256ULL * 1024ULL * 1024ULL,
											   1U,
											   1U} ;	// ASIX一fileと256 MiBの空き容量reserve。
		NativeError						error = workspace_->initialize( ASIX_AX88179A_PROVIDER_ID,
																	   retainedSessionId_) ;	// 初期化診断値。
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = acquisitionSession_->initialize( retainedSessionId_, limits) ;
		}

		OfficialPreparationTransferResult transfer{OfficialPreparationItemState::FAILURE, error,
												   0} ;	// 初期化失敗は取得を呼ばない。
		// 先行検証に成功した場合だけ同じsource sessionで再確認と取得へ進む。
		if( error == 0) {
			OfficialHttpAcquisitionTransport transport( httpClient_) ;	// 同じsource session。
			WindowsOfficialNetworkCostReader costReader ;				// Windows標準の課金状態照会。
			const PreparedReleaseRefresh	 refresh = [this]( OfficialReleaseRecord &current,
														  bool					&rejected) {
				const AsixProductPageReader productReader = [this]( const ScanSessionId session,
																   std::wstring		  &html) {
					return readProductPage( session, html) ;
				} ; // 同じ固定製品pageを再確認する。
				const AsixTermsPageReader termsReader = [this]( const ScanSessionId session,
															   std::wstring		  &html) {
					return readTermsPage( session, html) ;
				} ; // 両pageの公式取得根拠を再構築する。
				std::wstring productHtml ;	// この同期再確認だけで使う製品本文。
				return readPreparedPages( retainedSessionId_, false, retainedWindowsBuild_,
											 productReader, termsReader, productHtml, current,
											 rejected) ;
			} ; // 本文・版・日付・ID・URL・hash等の全field一致を共通adapterが要求する。
			transfer = acquirePreparedRelease( task, *preparedTarget_, retainedRelease_, refresh,
											  *acquisitionSession_, *workspace_, transport,
											  costReader, cancellation, acquisition_) ;
		}

		// 実際に取得成功したpayloadだけを内容・適用性監査へ渡す。
		if( transfer.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
		   transfer.error == 0) {
			try {
				static_cast<void>( auditAsixAx88179aPreparedPackage(
					retainedSessionId_, acquisition_, retainedRelease_.publishedSha256,
					retainedDevices_, rankAuditor_, cancellation, preparedAudit_)) ;
			} catch( ...) {
				// 監査例外では部分閉包を破棄し、確定済みの取得成功と実受信量を維持する。
				preparedAudit_					   = {} ;
				preparedAudit_.scanSessionId	   = retainedSessionId_ ;
				preparedAudit_.summary.state	   = OfficialDriverPackageAuditState::FAILURE ;
				preparedAudit_.summary.error	   = static_cast<NativeError>( E_UNEXPECTED) ;
				preparedAudit_.applicability.state = OfficialDriverApplicabilityState::FAILURE ;
				preparedAudit_.applicability.error = preparedAudit_.summary.error ;
			}
		} else {
			preparedAudit_ = {} ;
			acquisition_   = {} ;
			acquisitionSession_.reset() ;
			// 取得失敗の保持物を解放し、試行済み状態は戻さない。
			workspace_.reset() ;
		}

		return transfer ;
	} catch( const std::bad_alloc &) {
		preparedAudit_ = {} ;
		acquisition_   = {} ;
		acquisitionSession_.reset() ;
		workspace_.reset() ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_OUTOFMEMORY), 0} ;
	} catch( ...) {
		preparedAudit_ = {} ;
		acquisition_   = {} ;
		acquisitionSession_.reset() ;
		workspace_.reset() ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_UNEXPECTED), 0} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationAuditReport> AsixUpdateProvider::preparationAuditReport(
	const ScanSessionId scanSessionId, const std::wstring_view targetIdentity)
{
	// 未取得・旧session・未監査・別thread・再照会を補完しない。
	if( scanSessionId == 0U || scanSessionId != retainedSessionId_ || !preparedTarget_ ||
	   preparedTarget_->identity != targetIdentity || !acquisitionAttempted_ ||
	   acquisition_.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition_.error != 0 || acquisition_.scanSessionId != scanSessionId ||
	   acquisition_.providerId != ASIX_AX88179A_PROVIDER_ID ||
	   acquisition_.resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID || acquisition_.byteCount == 0U ||
	   acquisition_.acquisitionId == 0U ||
	   preparedAudit_.summary.state == OfficialDriverPackageAuditState::NOT_STARTED ||
	   retainedDevices_.empty() || retainedDevices_.size() != retainedDeviceCount_ ||
	   retainedCandidateIdentities_.size() != retainedDevices_.size() || !rankAuditor_ ||
	   GetCurrentThreadId() != ownerThreadId_ || auditReportResolved_) {
		return std::nullopt ;
	}

	OfficialPreparationAuditReport report = makeAsixPreparationAuditReport(
		scanSessionId, targetIdentity, retainedDevices_, retainedCandidateIdentities_,
		preparedAudit_) ;	// URL、path、生PnP IDを含まない既存行snapshot。
	// 失敗・0件も再発行しない。
	auditReportResolved_ = true ;
	// 内容・適用性合格前にはbindingを発行しない。
	if( report.content != CandidateAuditGateState::PASSED ||
	   report.applicability != CandidateAuditGateState::PASSED) {
		return report ;
	}

	// binding作成・解放・指定導入callbackが揃わない間は導入候補を公開しない。
	if( !bindingCreator_ || !bindingReleaser_ || !boundInstaller_) {
		report.publication.state	  = OfficialPreparationCandidatePublicationState::FAILURE ;
		report.publication.firstError = static_cast<NativeError>( E_NOTIMPL) ;
		// 全callbackが揃うまで選択可能な候補を公開しない。
		return report ;
	}

	publishAsixPreparedCandidates( scanSessionId, acquisition_.acquisitionId, acquisition_.byteCount,
								  retainedDevices_, preparedAudit_, bindingCreator_,
								  bindingReleaser_, report, installTargets_) ;
	candidatesPublished_ = report.publication.state ==
						   OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
	return report ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult AsixUpdateProvider::scan( const ScanSessionId							 scanSessionId,
									const std::span<const OfficialCatalogDevice> devices,
									const LocalHardwareIdMatcher				&hardwareIdMatcher,
									const ProviderProgressCallback				&progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	// 所有thread以外からのscan要求は保持中状態を変更せず拒否する。
	if( ownerThreadId_ != 0U && GetCurrentThreadId() != ownerThreadId_) {
		return {.scanSessionId = scanSessionId,
				.outcome	   = OutcomeCode::FAILURE,
				.state		   = ProviderScanState::FAILURE,
				.error		   = static_cast<NativeError>( E_ACCESSDENIED)} ;
	}

	// Public失効は観測contextも消去するため、Compositeが今回設定した値だけを退避する。
	std::vector<LocalOfficialReleaseObservation> previousObservations =
		// 今回scan用の前回観測。
		std::move( previousReleaseObservations_) ;
	OfficialReleaseEnvironmentFingerprints observationEnvironment =
		// 今回scan用の現在環境。
		std::move( observationEnvironment_) ;
	invalidateScanSession() ;
	previousReleaseObservations_	   = std::move( previousObservations) ;
	observationEnvironment_			   = std::move( observationEnvironment) ;
	const AsixProductPageReader reader = [this]( const ScanSessionId session, std::wstring &html) {
		return readProductPage( session, html) ;
	} ; // 端末情報を付加しない固定製品page取得境界。
	const AsixTermsPageReader termsReader = [this]( const ScanSessionId session,
												   std::wstring		  &html) {
		return readTermsPage( session, html) ;
	} ; // 同じsource sessionの固定Terms取得境界。
	FILETIME observedTime{} ;	// Live metadata確認へ使用する現在UTC FILETIME。
	GetSystemTimeAsFileTime( &observedTime) ;
	ULARGE_INTEGER observedTimeValue{} ;	// FILETIMEを永続64-bit値へ変換する共用体。
	observedTimeValue.LowPart  = observedTime.dwLowDateTime ;
	observedTimeValue.HighPart = observedTime.dwHighDateTime ;
	bool observationFailed{} ;								// 一件でも失敗した場合に今回観測全体を破棄する。
	AsixReleaseObservationEvaluator observationEvaluator ;	// 環境成立時だけ設定する評価境界。
	// OSとdevice構成の観測境界が揃う場合にだけrelease比較を有効にする。
	if( !observationEnvironment_.operatingSystem.empty() &&
	   !observationEnvironment_.deviceConfiguration.empty()) {
		observationEvaluator =
			[this, &observationFailed, observedFileTime = observedTimeValue.QuadPart](
				const OfficialCatalogDevice &device, const OfficialReleaseRecord &release)
			-> std::optional<ReleaseObservationDifference> {
			// 先行device失敗後は部分観測を追加しない。
			if( observationFailed) {
				return std::nullopt ;
			}

			OfficialReleaseObservationEvaluation evaluation ;	// 今回観測と非機密差分。
			// 一件の観測不整合でもProvider全体の部分観測を破棄する。
			if( !evaluateOfficialReleaseObservation( OfficialReleaseFamily::ASIX_AX88179A, release,
												   device, observationEnvironment_.operatingSystem,
												   observationEnvironment_.deviceConfiguration,
												   observedFileTime, previousReleaseObservations_,
												   evaluation)) {
				observationFailed = true ;
				currentReleaseObservations_.clear() ;
				// 一件の不整合でProvider全体の観測を破棄する。
				return std::nullopt ;
			}

			currentReleaseObservations_.push_back( std::move( evaluation.observation)) ;
			return evaluation.difference ;
		} ;
	}

	ScanResult result = scanWithPreparedPageReaders(
		scanSessionId, devices, isWindowsServer(), currentWindowsBuildNumber(), reader, termsReader,
		progressCallback,
		observationEvaluator) ;	// 実OSとlocal probe成立後に二pageを確認する。
	// 候補があっても公式originの取得根拠が揃わなければsessionごと拒否する。
	if( result.succeeded && result.state == ProviderScanState::CANDIDATES_AVAILABLE &&
	   (!httpClient_.hasSourceEvidence( scanSessionId, ASIX_AX88179A_PROVIDER_ID,
									   OFFICIAL_LANDING_RESOURCE_ID) ||
		!httpClient_.hasSourceEvidence( scanSessionId, ASIX_AX88179A_PROVIDER_ID,
									   OFFICIAL_PRIMARY_METADATA_RESOURCE_ID))) {
		invalidateScanSession() ;
		result.succeeded					= false ;
		result.outcome						= OutcomeCode::FAILURE ;
		result.state						= ProviderScanState::SOURCE_REJECTED ;
		result.error						= static_cast<NativeError>( E_UNEXPECTED) ;
		result.coverage.assessedDeviceCount = 0U ;
		result.candidates.clear() ;
		// 公式origin根拠がない候補をUIへ渡さない。
		return result ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult AsixUpdateProvider::install( const ScanSessionId				  scanSessionId,
										  const std::span<const std::wstring> identities,
										  const std::uintptr_t				  parentWindowNative,
										  const ProviderProgressCallback	 &progressCallback)
{
	// 別threadのinstall要求では所有workerの保持物にも触れず失敗を返す。
	if( ownerThreadId_ != 0U && GetCurrentThreadId() != ownerThreadId_) {
		InstallResult rejected ;	// 別threadでは保持物にも触れず拒否する。
		rejected.downloadOutcome = OutcomeCode::FAILURE ;
		rejected.installOutcome	 = OutcomeCode::FAILURE ;
		rejected.downloadError	 = static_cast<NativeError>( E_INVALIDARG) ;
		rejected.installError	 = static_cast<NativeError>( E_INVALIDARG) ;
		return rejected ;
	}

	const bool sourceConfirmed =
		scanSessionId != 0U && scanSessionId == retainedSessionId_ && candidatesPublished_ &&
		auditReportResolved_ && acquisitionAttempted_ && preparedTarget_.has_value() &&
		rankAuditor_ && boundInstaller_ && currentWindowsBuildNumber() == retainedWindowsBuild_ &&
		preparedTarget_->providerId == ASIX_AX88179A_PROVIDER_ID &&
		preparedTarget_->resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID &&
		preparedTarget_->parserRevision == retainedRelease_.parserRevision &&
		preparedTarget_->terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
		preparedTarget_->requiresPrerequisiteConfirmation &&
		preparedTarget_->eulaRevision == retainedRelease_.eulaRevision &&
		preparedTarget_->eulaText == retainedRelease_.eulaText &&
		(retainedRelease_.publishedSha256.empty() ||
		 (acquisition_.publishedSha256Verified &&
		  retainedRelease_.publishedSha256 == acquisition_.sha256)) &&
		httpClient_.hasSourceEvidence( scanSessionId, ASIX_AX88179A_PROVIDER_ID,
									  OFFICIAL_LANDING_RESOURCE_ID) &&
		httpClient_.hasSourceEvidence( scanSessionId, ASIX_AX88179A_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) &&
		httpClient_.hasSourceEvidence( scanSessionId, ASIX_AX88179A_PROVIDER_ID,
									  OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// 固定同意と公式取得根拠。
	try {
		const BoundPreparedInstallContext context{.scanSessionId   = scanSessionId,
												  .acquisition	   = &acquisition_,
												  .targets		   = &installTargets_,
												  .auditedPackages = preparedAudit_.auditedPackages,
												  .windowsServer   = isWindowsServer(),
												  .windowsBuild	   = currentWindowsBuildNumber(),
												  .sourceEvidenceConfirmed =
													  sourceConfirmed} ;	// 同じworkerの非所有入力。
		const PreparedInfReverifier reverifier = []( const OfficialAuditedInfPackage &package) {
			return reverifyOfficialAuditedInfPackage( package) ;
		} ; // 本番の共通CAT再検証。
		// 再検証と指定INF導入を経た候補別結果。保存session失効後も返却用に保持する。
		InstallResult result =
			executeAsixPreparedInstall( context, identities, reverifier, rankAuditor_,
									   boundInstaller_, parentWindowNative, progressCallback) ;
		invalidateScanSession() ;
		return result ;
	} catch( ...) {
		// 例外でもtokenを閉包より先に解放し、workerが失敗結果と復旧処理を確定する。
		invalidateScanSession() ;
		throw ;
	}
}
//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void AsixUpdateProvider::invalidateScanSession() noexcept
{
	// 別threadから保持物の寿命を変更せず、所有workerでの明示失効を要求する。
	if( ownerThreadId_ != 0U && GetCurrentThreadId() != ownerThreadId_) {
		return ;
	}

	resetPreparedSnapshot() ;
	httpClient_.invalidateSourceSession() ;
	previousReleaseObservations_.clear() ;
	observationEnvironment_ = {} ;
	currentReleaseObservations_.clear() ;
}

} // namespace drivercrate
