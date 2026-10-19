//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_update_provider.cpp
 * @brief NVIDIA Networking WinOF-2公式表示専用Provider実装。
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
 * @note NVIDIA公式pageの固定委譲と段階的metadata応答を同一scan内で検証します。Local device情報、payload URL、SHA-256またはform
 *       bodyをUI／logへ渡しません。
 */
//------------------------------------------------------------------------------

#include "platform/nvidia_winof2_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/nvidia_winof2_catalog_parser.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
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

constexpr std::size_t	MAXIMUM_DEVICES			   = 4096U ;			// 一回のscanで扱うdevice数上限。
constexpr std::size_t	MAXIMUM_DISPLAY_CHARACTERS = 512U ;				// Local表示値の文字数上限。
constexpr std::uint64_t MAXIMUM_LANDING_BYTES	   = 512ULL * 1024ULL ;	// 公式page受信上限。
constexpr std::uint64_t MAXIMUM_METADATA_BYTES	   = 256ULL * 1024ULL ;	// 一POST応答上限。
constexpr std::size_t	EXPECTED_EVIDENCE_COUNT	   = 6U ;				// Landing一件とmetadata POST五件の根拠数。
// WinOF-2の公式委譲経路を確認する固定landing起点。
constexpr std::wstring_view LANDING_PAGE_URL =
	L"https://network.nvidia.com/products/adapter-software/ethernet/windows/winof-2/" ;
// 委譲確認後のrelease照会に使用する固定metadata endpoint。
constexpr std::wstring_view METADATA_ENDPOINT_URL =
	L"https://downloaders.azurewebsites.net/downloaders/winof2_downloader/helper.php" ;
// Local製品名を照合する、明示対応adapter系列の集合。
constexpr std::array SUPPORTED_FAMILIES{
	std::wstring_view( L"ConnectX-4 Lx"), std::wstring_view( L"ConnectX-5"),
	std::wstring_view( L"ConnectX-6"),	 std::wstring_view( L"ConnectX-7"),
	std::wstring_view( L"ConnectX-8"),	 std::wstring_view( L"ConnectX-9"),
	std::wstring_view( L"BlueField-2"),	 std::wstring_view( L"BlueField-3")} ;

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
 * @param[in] token 大文字小文字を無視して探す製品系列語。
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
		// 大小文字を除く表示名token一致をlocal probeの根拠にする。
		if( CompareStringOrdinal( text.data() + offset, static_cast<int>( token.size()), token.data(),
								static_cast<int>( token.size()), TRUE) == CSTR_EQUAL) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief ConnectX-4一般をConnectX-4 Lxへ拡張せず、明示された系列だけを受理する。
 *
 * @param[in] model Local device model表示。
 * @return 現行WinOF-2資料の対応系列語を一つ含む場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasSupportedFamily( const std::wstring_view model) noexcept
{
	return std::ranges::any_of( SUPPORTED_FAMILIES, [model]( const std::wstring_view family) {
		return containsText( model, family) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local device由来値を受けず、制御文字と非ASCIIをfail-closedで拒否する。
 *
 * @param[in] value ParserまたはOS対応表が検証したASCII公開値。
 * @param[in,out] body Percent encodeした値を末尾へ追加するform body。
 * @return 有限ASCII値を追加できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendFormValue( const std::wstring_view value, std::string &body)
{
	constexpr char HEX_DIGITS[] = "0123456789ABCDEF" ;	// Percent escapeの大文字hex表。
	// 空または過大な公開値をformへ追加しない。
	if( value.empty() || value.size() > 256U) {
		return false ;
	}

	// 全文字をASCIIとして有限回encodeする。
	for( const wchar_t character : value) {
		// 制御文字または非ASCIIを送信値へ変換しない。
		if( character < 0x20 || character > 0x7e) {
			return false ;
		}

		const unsigned char byte = static_cast<unsigned char>( character) ;	// ASCII byte値。
		const bool unreserved	 = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
								(byte >= '0' && byte <= '9') || byte == '-' || byte == '.' ||
								byte == '_' ||
								// RFC 3986のunreserved文字だけをそのまま送る。
								byte == '~' ;
		// URL非予約ASCII文字だけをform値へ直接保持する。
		if( unreserved) {
			body.push_back( static_cast<char>( byte)) ;
		} else {
			body.push_back( '%') ;
			body.push_back( HEX_DIGITS[(byte >> 4U) & 0x0fU]) ;
			body.push_back( HEX_DIGITS[byte & 0x0fU]) ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Field名をruntime入力から作らず、値だけをpercent encodeする。
 *
 * @param[in] name Source固定のASCII field名。
 * @param[in] value 検証済み公開値。
 * @param[in,out] body Fieldを末尾へ追加するform body。
 * @return Field名と値を有限bodyへ追加できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendFormField( const std::string_view name, const std::wstring_view value,
								   std::string &body)
{
	// 固定field名の変更または上限超過を拒否する。
	if( name.empty() || name.size() > 32U || !std::ranges::all_of( name, []( const char character) {
		   return character >= 'a' && character <= 'z' ;
	   })) {
		return false ;
	}

	// 二つ目以降のform fieldだけに区切りを追加する。
	if( !body.empty()) {
		body.push_back( '&') ;
	}

	body.append( name) ;
	body.push_back( '=') ;
	return appendFormValue( value, body) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Actionごとのfield順を固定し、端末識別情報を引数に持たない。
 *
 * @param[in] action 固定metadata action。
 * @param[in] version 検証済みcurrent版。空の場合は省略する。
 * @param[in] distribution 検証済み公開distribution名。空の場合は省略する。
 * @param[in] osLabel 検証済み公開OS名。空の場合は省略する。
 * @param[in] architecture 固定architecture。空の場合は省略する。
 * @return 成功時の有限form body。不正入力時は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string makeFormBody( const std::wstring_view action,
									   const std::wstring_view version,
									   const std::wstring_view distribution,
									   const std::wstring_view osLabel,
									   const std::wstring_view architecture)
{
	std::string body ;	// 2 KiB共通上限より十分小さい所有form body。
	// action値を安全なform fieldへ変換できなければ要求を作らない。
	if( !appendFormField( "action", action, body)) {
		return {} ;
	}

	const std::array fields{
		std::pair{std::string_view( "version"), version},
		std::pair{std::string_view( "distro"), distribution},
		std::pair{std::string_view( "os"), osLabel},
		std::pair{std::string_view( "arch"), architecture}} ;	// Action後の固定field順。
	// 空の未到達段階を省略し、検証済み値だけをformへ加える。
	for( const auto &[name, value] : fields) {
		// 値がある追加fieldの変換失敗時は部分requestを返さない。
		if( !value.empty() && !appendFormField( name, value, body)) {
			return {} ;
		}
	}

	return body ;
}

//------------------------------------------------------------------------------
/**
 * @brief 類似OS名、大小文字差または部分一致へfallbackしない。
 *
 * @param[in] values Parserが重複を拒否した公開選択肢。
 * @param[in] expected Local OS対応表から得た完全一致値。
 * @return 期待値が一度存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool listContains( const std::vector<std::wstring> &values,
								const std::wstring_view			 expected) noexcept
{
	return std::count( values.begin(), values.end(), expected) == 1 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 空bodyを通信せず拒否し、Readerへlocal device値を渡さない。
 *
 * @param[in] session 現在のscan session。
 * @param[in] reader 固定metadata取得境界。
 * @param[in] action 固定action。
 * @param[in] version 検証済みcurrent版または空。
 * @param[in] distribution 検証済みdistributionまたは空。
 * @param[in] osLabel 検証済みOS labelまたは空。
 * @param[in] architecture 固定x64または空。
 * @param[out] json 成功時のmetadata応答。
 * @return Form生成とreader成功時は0、失敗時はnative error。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readMetadata( const ScanSessionId				 session,
									   const NvidiaWinof2MetadataReader &reader,
									   const std::wstring_view			 action,
									   const std::wstring_view			 version,
									   const std::wstring_view			 distribution,
									   const std::wstring_view			 osLabel,
									   const std::wstring_view architecture, std::wstring &json)
{
	const std::string body =
		// POST body。
		makeFormBody( action, version, distribution, osLabel, architecture) ;
	// 空bodyを送信せず、既存応答も破棄して要求を拒否する。
	if( body.empty()) {
		json.clear() ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	return reader( session, body, json) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同期通信中は直前の確定値を保持し、完了した段階だけで率を進める。
 *
 * @param[in] callback 確定済み進捗の通知先。
 * @param[in] completedSteps 完了した通信段階数。0から6。
 * @param[in] totalDevices 後段で候補化する対象device数。
 */
//------------------------------------------------------------------------------
void notifyMetadataProgress( const ProviderProgressCallback &callback,
							const std::uint32_t completedSteps, const std::size_t totalDevices)
{
	callback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
			  .percentComplete = completedSteps * 10U,
			  .completedItems  = 0U,
			  .totalItems	   = totalDevices}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名をProvider内へ複製せず、stable IDで一度だけ解決する。
 * @return Registryに登録されたWinOF-2 Provider表示名。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring providerDisplayName()
{
	// Registryの表示名だけを取得元名称の正本として使用する。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// stable IDが一致するregistry項目からだけ表示名を取得する。
		if( descriptor.id == NVIDIA_WINOF2_PROVIDER_ID) {
			return descriptor.displayName ;
		}
	}

	// Registry不整合は後段validationで候補拒否となる。
	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Package版をtitleだけへ表示し、INF版または更新必要性として扱わない。
 *
 * @param[in] session 当該検索session。
 * @param[in] ordinal Session内の0始まり表示行連番。
 * @param[in] device Local probeが一致したdevice snapshot。
 * @param[in] release 検証済み公式配布情報。
 * @param[in] sourceName Registryから解決した取得元表示名。
 * @return URLとhashを含まない非選択・非推奨の所有DTO。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeNvidiaWinof2Candidate( const ScanSessionId			 session,
														const std::size_t			 ordinal,
														const OfficialCatalogDevice &device,
														const NvidiaWinof2Release	&release,
														const std::wstring_view		 sourceName)
{
	UpdateCandidate	   candidate ;								// UIへ返す表示専用の所有DTO。
	const std::wstring sourceId( NVIDIA_WINOF2_PROVIDER_ID) ;	// Registryと一致する取得元ID。
	candidate.identity =
		sourceId + L":info:" + std::to_wstring( session) + L":" + std::to_wstring( ordinal) ;
	candidate.packageIdentity = sourceId + L":sha256:" + release.sha256 ;
	candidate.providerId	  = sourceId ;
	candidate.deviceIdentity  = device.deviceIdentity ;
	candidate.title			  = L"NVIDIA WinOF-2 " + release.packageVersion + L"（公式配布情報、" +
					  release.displaySize + L"）" ;
	candidate.manufacturer		= device.manufacturer ;
	candidate.model				= device.model ;
	candidate.driverClass		= device.driverClass ;
	candidate.deviceClassGuid	= device.deviceClassGuid ;
	candidate.sourceName		= sourceName ;
	candidate.sourceLocation	= L"NVIDIA公式 HTTPS（network.nvidia.comから委譲、payload未取得）" ;
	candidate.discoveryBasis	= CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
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
 * @brief 一部取得だけで候補を発行せず、URLを参照せずregistryへ照合する。
 *
 * @param[in] evidence 現在HTTP clientが保持するopaque取得根拠。
 * @param[in] session 期待するscan session。
 * @return Landing一件とmetadata五件が順序どおり全て有効な場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sourceEvidenceIsComplete( const std::span<const OfficialSourceEvidence> evidence,
											const ScanSessionId session) noexcept
{
	// 必要な取得証拠の件数が揃わなければ完了とみなさない。
	if( evidence.size() != EXPECTED_EVIDENCE_COUNT) {
		return false ;
	}

	// 登録順を確認し、全取得が同じsessionとProviderへ拘束されていることを検証する。
	for( std::size_t index = 0U; index < evidence.size(); ++index) {
		const OfficialSourceEvidence &item = evidence[index] ;	// 現在の取得根拠。
		// 先頭はlanding、後続はmetadataとして照合する期待resource ID。
		const std::wstring_view		  expectedResource =
			  index == 0U ? OFFICIAL_LANDING_RESOURCE_ID : OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ;
		// 各証拠の妥当性、session、Provider、resource対応を確認する。
		if( !isValidOfficialSourceEvidence( item) || item.scanSessionId != session ||
		   item.providerId != NVIDIA_WINOF2_PROVIDER_ID || item.resourceId != expectedResource) {
			return false ;
		}

		// 欠落または並べ替えられた取得段階を完全な根拠として受理しない。
		if( item.acquisitionId != static_cast<std::uint64_t>( index) + 1U) {
			return false ;
		}
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isNvidiaWinof2Device( const OfficialCatalogDevice &device) noexcept
{
	// 不正identityまたは過大表示値をnetwork対象にしない。
	if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
	   device.model.size() > MAXIMUM_DISPLAY_CHARACTERS ||
	   device.manufacturer.size() > MAXIMUM_DISPLAY_CHARACTERS ||
	   device.currentProvider.size() > MAXIMUM_DISPLAY_CHARACTERS) {
		return false ;
	}

	const bool netClass =
		sameText( device.driverClass, L"Net") &&
		sameText( device.deviceClassGuid,
				 L"{4d36e972-e325-11ce-bfc1-08002be10318}") ;	// Net class完全一致境界。
	const bool vendorName = containsText( device.manufacturer, L"NVIDIA") ||
							containsText( device.manufacturer, L"Mellanox") ||
							containsText( device.currentProvider, L"NVIDIA") ||
							containsText( device.currentProvider, L"Mellanox") ||
							containsText( device.model, L"NVIDIA") ||
							// Local vendor表示境界。
							containsText( device.model, L"Mellanox") ;
	return netClass && vendorName && hasSupportedFamily( device.model) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult scanNvidiaWinof2Catalog( const ScanSessionId							scanSessionId,
								   const std::span<const OfficialCatalogDevice> devices,
								   const bool windowsServer, const std::uint32_t windowsBuild,
								   const NvidiaWinof2LandingPageReader &landingReader,
								   const NvidiaWinof2MetadataReader	   &metadataReader,
								   const ProviderProgressCallback	   &progressCallback)
{
	ScanResult result{.scanSessionId = scanSessionId,
					  .outcome		 = OutcomeCode::FAILURE,
					  .state		 = ProviderScanState::FAILURE} ;	// 全条件成立までは失敗。
	// session、device数、reader、通知先の前提不備では通信を開始しない。
	if( scanSessionId == 0U || devices.size() > MAXIMUM_DEVICES || !landingReader ||
	   !metadataReader || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 不正session、上限またはcallback欠落では通信しない。
		return result ;
	}

	std::vector<const OfficialCatalogDevice *> matched ;	// 呼出し中だけ有効な対象device参照。
	std::unordered_set<std::wstring>		   identities ;	// Opaque identityの重複検出集合。
	// 全deviceを有限回確認し、WinOF-2対象系列だけを検索対象へ残す。
	for( const OfficialCatalogDevice &device : devices) {
		// 空、過大、重複のdevice identityから候補を作らない。
		if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
		   !identities.insert( device.deviceIdentity).second) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			// 空または重複identityから曖昧な候補を生成しない。
			return result ;
		}

		// WinOF-2対象のlocal deviceだけを照会対象へ集める。
		if( isNvidiaWinof2Device( device)) {
			matched.push_back( &device) ;
		}
	}

	result.coverage.eligibleDeviceCount = matched.size() ;
	NvidiaWinof2OsSelection osSelection ;	// 実OSに対応する公開Download Center選択値。
	// 対象deviceまたは既知OS選択がなければ通信せず対象外にする。
	if( matched.empty() || !selectNvidiaWinof2Os( windowsServer, windowsBuild, osSelection)) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100U,
						  .completedItems  = 0U,
						  .totalItems	   = 0U}) ;
		return result ;
	}

	notifyMetadataProgress( progressCallback, 0U, matched.size()) ;

	std::wstring response ;	// 各通信段階で上書きする有限UTF-16応答。
	result.error = landingReader( scanSessionId, response) ;
	// 製品page取得失敗を候補なしとして扱わない。
	if( result.error != 0) {
		return result ;
	}

	// 公式起点ページの委譲構造が変わった場合はmetadataを拒否する。
	if( !parseNvidiaWinof2LandingPage( response)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		// NVIDIA公式pageからの委譲変更を推測で補完しない。
		return result ;
	}

	notifyMetadataProgress( progressCallback, 1U, matched.size()) ;

	std::wstring version ;	// Current一覧と一致したWinOF-2 package版。
	result.error =
		readMetadata( scanSessionId, metadataReader, L"get_versions", L"", L"", L"", L"", response) ;
	// 版照会の失敗を保持し、後続条件を推測で補わない。
	if( result.error != 0) {
		return result ;
	}

	// current版を一意に解析できなければmetadata拒否として返す。
	if( !parseNvidiaWinof2Versions( response, version)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		return result ;
	}

	notifyMetadataProgress( progressCallback, 2U, matched.size()) ;

	std::vector<std::wstring> values ;	// 各段階で上書きする公開選択肢。
	result.error = readMetadata( scanSessionId, metadataReader, L"get_distros", version, L"", L"",
								L"", response) ;
	// distribution照会の失敗時は後続照会へ進まない。
	if( result.error != 0) {
		return result ;
	}

	// 期待distributionを応答から確認できなければ代替名を使わない。
	if( !parseNvidiaWinof2StringList( response, values) ||
	   !listContains( values, osSelection.distribution)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		// 期待distribution欠落を別名へfallbackしない。
		return result ;
	}

	notifyMetadataProgress( progressCallback, 3U, matched.size()) ;

	result.error = readMetadata( scanSessionId, metadataReader, L"get_oses", version,
								osSelection.distribution, L"", L"", response) ;
	// OS照会の失敗時は後続照会へ進まない。
	if( result.error != 0) {
		return result ;
	}

	// 期待OS labelがなければ類似buildへ代替しない。
	if( !parseNvidiaWinof2StringList( response, values) ||
	   !listContains( values, osSelection.osLabel)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		// 期待OS欠落を近似buildへfallbackしない。
		return result ;
	}

	notifyMetadataProgress( progressCallback, 4U, matched.size()) ;

	result.error = readMetadata( scanSessionId, metadataReader, L"get_arches", version,
								osSelection.distribution, osSelection.osLabel, L"", response) ;
	// architecture照会の失敗時は取得先照会へ進まない。
	if( result.error != 0) {
		return result ;
	}

	// 応答にx64が明示されない場合は別architectureへ代替しない。
	if( !parseNvidiaWinof2StringList( response, values) || !listContains( values, L"x64")) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		// x64欠落を別architectureへfallbackしない。
		return result ;
	}

	notifyMetadataProgress( progressCallback, 5U, matched.size()) ;

	result.error = readMetadata( scanSessionId, metadataReader, L"get_download_info", version,
								osSelection.distribution, osSelection.osLabel, L"x64", response) ;
	// download情報照会の失敗時は候補を構築しない。
	if( result.error != 0) {
		return result ;
	}

	NvidiaWinof2Release release ;	// SHA-256まで整合した表示用配布情報。
	// 版と公式fileを結合して検証できなければmetadataを拒否する。
	if( !parseNvidiaWinof2DownloadInfo( response, version, release)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		// 複数file、別hostまたは別版を候補へ渡さない。
		return result ;
	}

	notifyMetadataProgress( progressCallback, 6U, matched.size()) ;

	const std::wstring sourceName = providerDisplayName() ;	// Registry由来の取得元表示名。
	// registry表示名を解決できない場合は独自名で候補を発行しない。
	if( sourceName.empty()) {
		result.state = ProviderScanState::SOURCE_REJECTED ;
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		// Registry不整合時に独自表示名で候補を発行しない。
		return result ;
	}

	// 同じ検証済みpackageを対象deviceごとの表示行へ変換する。
	for( std::size_t index = 0U; index < matched.size(); ++index) {
		result.candidates.push_back(
			makeNvidiaWinof2Candidate( scanSessionId, index, *matched[index], release, sourceName)) ;
		progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete =
							  static_cast<std::uint32_t>( 60U + (index + 1U) * 40U / matched.size()),
						  .completedItems = index + 1U,
						  .totalItems	  = matched.size()}) ;
	}

	result.coverage.assessedDeviceCount = matched.size() ;
	result.succeeded					= true ;
	result.outcome						= OutcomeCode::SUCCESS ;
	result.state						= ProviderScanState::CANDIDATES_AVAILABLE ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult NvidiaWinof2UpdateProvider::scan( const ScanSessionId scanSessionId,
											const std::span<const OfficialCatalogDevice> devices,
											const LocalHardwareIdMatcher   &hardwareIdMatcher,
											const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	invalidateScanSession() ;
	const NvidiaWinof2LandingPageReader landingReader = [this]( const ScanSessionId session,
															   std::wstring		  &html) {
		NativeError error =
			// 開始結果。
			httpClient_.beginSourceSession( session, NVIDIA_WINOF2_PROVIDER_ID) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		return httpClient_.getUtf8TextForSource( LANDING_PAGE_URL, OFFICIAL_LANDING_RESOURCE_ID,
												MAXIMUM_LANDING_BYTES, html) ;
	} ; // 端末情報を付加しない固定製品page取得境界。
	const NvidiaWinof2MetadataReader metadataReader =
		[this, scanSessionId]( const ScanSessionId session, const std::string_view formBody,
							  std::wstring &json) {
			// 別sessionのPOST要求を拒否して応答を破棄する。
			if( session != scanSessionId) {
				json.clear() ;
				// 別sessionのPOSTを拒否する。
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			return httpClient_.postFormUtf8TextForSource( METADATA_ENDPOINT_URL,
														 OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
														 formBody, MAXIMUM_METADATA_BYTES, json) ;
		} ; // 検証済み公開値だけを送る固定POST境界。

	ScanResult result = scanNvidiaWinof2Catalog(
		scanSessionId, devices, isWindowsServer(), currentWindowsBuildNumber(), landingReader,
		metadataReader, progressCallback) ;	// 実OSとlocal probeを先に確認する。
	// 候補取得が完了しない場合は部分的な取得証拠を次操作へ残さない。
	if( !result.succeeded || result.state != ProviderScanState::CANDIDATES_AVAILABLE) {
		invalidateScanSession() ;
		// 一部取得根拠を次操作へ残さない。
		return result ;
	}

	// 全公式取得証拠が揃わない候補を破棄して取得元拒否として返す。
	if( !sourceEvidenceIsComplete( httpClient_.sourceEvidence(), scanSessionId)) {
		invalidateScanSession() ;
		result.succeeded = false ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.state	 = ProviderScanState::SOURCE_REJECTED ;
		result.error	 = static_cast<NativeError>( E_UNEXPECTED) ;
		result.candidates.clear() ;
		// 公式origin根拠が完全でない候補をUIへ渡さない。
		return result ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult NvidiaWinof2UpdateProvider::install( const ScanSessionId				  scanSessionId,
												  const std::span<const std::wstring> identities,
												  const std::uintptr_t parentWindowNative,
												  const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( scanSessionId) ;
	static_cast<void>( identities) ;
	static_cast<void>( parentWindowNative) ;
	static_cast<void>( progressCallback) ;
	InstallResult result ;	// 表示専用Providerの固定拒否結果。
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = static_cast<NativeError>( E_NOTIMPL) ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = static_cast<NativeError>( E_NOTIMPL) ;
	invalidateScanSession() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void NvidiaWinof2UpdateProvider::invalidateScanSession() noexcept
{
	httpClient_.invalidateSourceSession() ;
}

} // namespace drivercrate
