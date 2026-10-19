//------------------------------------------------------------------------------
/**
 * @file windows_update_provider.cpp
 * @brief Windows Update provider実装。
 * @version 01.01.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  WUA処理進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Install後session契約明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通scan条件対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Firmware候補除外追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  WUA既定選択根拠追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  管理service探索経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Windows管理監査状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  WUA system query計測根拠を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  WUA／WSUS既定service選択の試験境界を追加。
 * </pre>
 *
 * @note WUAによるdriver updateの検索、download、およびinstallを実装します。WUAの適用性判定を正本とし、独自URLとversion比較を使用しません。
 *       Driver rank判定もWUAへ委譲します。
 */
//------------------------------------------------------------------------------

#include "platform/windows_update_provider.h"

#include "core/candidate_audit.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"

#include <OleAuto.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr wchar_t CLIENT_APPLICATION_ID[] = L"DriverCrate" ;	// WUA client識別名。
// 未導入かつ非表示でないdriverのWUA検索条件。
constexpr wchar_t DRIVER_SEARCH_CRITERIA[]	   = L"IsInstalled=0 and Type='Driver' and IsHidden=0" ;
constexpr UINT	  MAXIMUM_UPDATE_ID_CHARACTERS = 256 ;	// WUA UpdateID上限（UTF-16文字）。
constexpr UINT	  MAXIMUM_TITLE_CHARACTERS	   = 1024 ;	// Update title上限（UTF-16文字）。
constexpr UINT	  MAXIMUM_METADATA_CHARACTERS  = 4096 ;	// その他BSTR metadata上限（UTF-16文字）。
constexpr LONG	  MAXIMUM_UPDATE_CANDIDATES	   = 4096 ;	// 一回のWUA scan候補数上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief UI へ公開できる update service の論理名と取得場所である。
 */
struct UpdateSourceMetadata {
	/// UIへ表示する論理update source名。
	std::wstring name{L"Windows Update Agent"} ;
	/// Policy境界を示す取得場所。
	std::wstring location{L"端末の既定更新サービス"} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HRESULT を portable な 32-bit diagnostic 値へ保持する。
 *
 * @param[in] result 変換元 HRESULT。
 * @return bit pattern を維持した error 値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError toNativeError( const HRESULT result) noexcept
{
	return static_cast<NativeError>( result) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA の OperationResultCode を core の結果分類へ変換する。
 *
 * @param[in] code WUA が返した operation result。
 * @return UI と test が Windows header に依存せず扱える分類。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OutcomeCode toOutcomeCode( const OperationResultCode code) noexcept
{
	// WUA の処理状態を core の分類へ対応付け、未知 code は失敗として扱う。
	switch( code) {
		// WUA未開始は、coreでも処理済みとして扱わない。
		case orcNotStarted:
			return OutcomeCode::NOT_STARTED ;
		// WUA処理中は、成功または失敗へ確定させない。
		case orcInProgress:
			return OutcomeCode::IN_PROGRESS ;
		// WUAが全成功とした結果だけを、通常の成功へ対応させる。
		case orcSucceeded:
			return OutcomeCode::SUCCESS ;
		// 一部エラーを伴う成功は、全成功から区別して保持する。
		case orcSucceededWithErrors:
			return OutcomeCode::SUCCEEDED_WITH_ERRORS ;
		// WUAの失敗は、coreの失敗区分へ引き継ぐ。
		case orcFailed:
			return OutcomeCode::FAILURE ;
		// WUAの中止は、処理失敗と区別して保持する。
		case orcAborted:
			return OutcomeCode::ABORTED ;
		// 未知のWUA結果を、成功として表示しない。
		default:
			return OutcomeCode::FAILURE ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 成功扱いできる WUA result code かを判定する。
 *
 * @param[in] outcome 判定対象の core 結果分類。
 * @return 成功または警告付き成功の場合は `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSuccessOutcome( const OutcomeCode outcome) noexcept
{
	return outcome == OutcomeCode::SUCCESS || outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
}

//------------------------------------------------------------------------------
/**
 * @brief COM getter が返す BSTR を `std::wstring` へ所有 copy する。
 *
 * @tparam Getter `BSTR*` を受け取る callable。
 * @param[in] getter 対象 property getter。
 * @param[out] value 取得成功時の文字列。
 * @param[in] maximumCharacters 受理する BSTR の最大文字数。
 * @return property getter の HRESULT。
 */
//------------------------------------------------------------------------------
template <typename Getter>
[[nodiscard]] HRESULT readBstr( Getter &&getter, std::wstring &value,
							   const UINT maximumCharacters = MAXIMUM_METADATA_CHARACTERS)
{
	UniqueBstr	  text ;							// COM getterが割り当てるBSTRのRAII所有object。
	const HRESULT result = getter( text.put()) ;	// Property取得結果。
	// COM getter の失敗時は以前の文字列を残さず HRESULT を返す。
	if( FAILED( result)) {
		value.clear() ;
		return result ;
	}

	const BSTR rawText = text.get() ;										// textが所有する非所有BSTR view。
	const UINT length  = rawText == nullptr ? 0U : SysStringLen( rawText) ;	// BSTR文字数。
	// 取得文字数が許可上限を超える場合は値を消去して拒否する。
	if( length > maximumCharacters) {
		value.clear() ;
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	value.assign( rawText == nullptr ? L"" : rawText, length) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Automatic Updates の既定 service 名と管理種別を読み取る。
 * @return 取得不能時も秘密性のある URL を含まない fallback metadata。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateSourceMetadata readDefaultUpdateSource()
{
	UpdateSourceMetadata source ;							// 取得不能時も使用できる安全なfallback表示metadata。
	Microsoft::WRL::ComPtr<IUpdateServiceManager> manager ;	// 登録service列挙manager。
	// UpdateServiceManager作成または後続property取得結果。
	HRESULT result = CoCreateInstance( __uuidof( UpdateServiceManager), nullptr, CLSCTX_INPROC_SERVER,
									  IID_PPV_ARGS( manager.GetAddressOf())) ;
	// Service manager の作成に失敗した場合は既定の取得元表示を維持する。
	if( FAILED( result)) {
		return source ;
	}

	Microsoft::WRL::ComPtr<IUpdateServiceCollection>
		services ;	// 登録済みupdate service collection。
	result = manager->get_Services( services.GetAddressOf()) ;
	LONG count{} ;	// Collectionに登録されたservice数。
	// Service collection の取得失敗と件数範囲外では個別 service の探索を行わない。
	if( FAILED( result) || FAILED( services->get_Count( &count)) || count < 0 || count > 64) {
		return source ;
	}

	// 登録済み service のうち Automatic Updates が既定に選んだ一件だけを使用する。
	for( LONG index = 0; index < count; ++index) {
		Microsoft::WRL::ComPtr<IUpdateService> service ;	// 現在検査中の登録service。
		// 個別 service が取得できない場合は次の service を確認する。
		if( FAILED( services->get_Item( index, service.GetAddressOf()))) {
			continue ;
		}

		Microsoft::WRL::ComPtr<IUpdateService2> service2 ;	// Default AU判定用拡張interface。
		VARIANT_BOOL isDefault = VARIANT_FALSE ;			// TRUEの場合はAutomatic Updates既定service。
		// 既定 Automatic Updates service と確認できない項目は表示元に選ばない。
		if( FAILED( service.As( &service2)) || FAILED( service2->get_IsDefaultAUService( &isDefault)) ||
		   isDefault != VARIANT_TRUE) {
			continue ;
		}

		std::wstring serviceName ;	// WUAが返すservice表示名。
		// 既定 service の非空表示名を取得できた場合だけ source 名へ反映する。
		if( SUCCEEDED( readBstr( [&service]( BSTR *value) { return service->get_Name( value) ; },
							  serviceName)) &&
		   !serviceName.empty()) {
			source.name = std::move( serviceName) ;
		}

		VARIANT_BOOL isManaged = VARIANT_FALSE ;	// TRUEの場合は組織管理service。
		// 管理対象 service と明示確認できた場合は組織管理の取得元として表示する。
		if( SUCCEEDED( service->get_IsManaged( &isManaged)) && isManaged == VARIANT_TRUE) {
			source.location = L"組織で管理された更新サービス（WSUS 等）" ;
		} else {
			source.location = L"Microsoft 更新サービス" ;
		}

		break ;
	}

	return source ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA DATE を利用者 locale の短い日付文字列へ変換する。
 *
 * @param[in] value OLE Automation DATE。
 * @return 変換できない場合は空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverDate( const DATE value)
{
	SYSTEMTIME systemTime{} ;	// OLE DATEを分解したlocal日付。
	// DATE を system time に変換できなければ日付表示を補完しない。
	if( VariantTimeToSystemTime( value, &systemTime) == 0) {
		return {} ;
	}

	// 短い日付と終端nullに必要なUTF-16文字数。
	const int required = GetDateFormatEx( LOCALE_NAME_USER_DEFAULT, DATE_SHORTDATE, &systemTime,
										 nullptr, nullptr, 0, nullptr) ;
	// 短い日付文字列の必要量が取得できなければ空表示を返す。
	if( required <= 1) {
		return {} ;
	}

	std::wstring formatted( static_cast<std::size_t>( required), L'\0') ;	// 日付受信領域。
	// 終端nullを含めて実際に書き込まれたUTF-16文字数。
	const int	 written = GetDateFormatEx( LOCALE_NAME_USER_DEFAULT, DATE_SHORTDATE, &systemTime,
										   nullptr, formatted.data(), required, nullptr) ;
	// 有効な日付文字列を書き込めなかった場合は部分表示を返さない。
	if( written <= 1) {
		return {} ;
	}

	formatted.resize( static_cast<std::size_t>( written - 1)) ;
	return formatted ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列に大小文字を区別せず禁止tokenが含まれるか判定する。
 *
 * Localeに依存しないWindows ordinal比較でmetadataを検査する。
 *
 * @param[in] text 検査対象文字列。
 * @param[in] token 検出する空でないASCII token。
 * @return tokenを含む場合は`true`。入力長を安全に変換できない場合は`false`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsOrdinalIgnoreCase( const std::wstring_view text,
											 const std::wstring_view token) noexcept
{
	// 空 token、短すぎる本文、Windows 比較 API の上限超過では検索しない。
	if( token.empty() || text.size() < token.size() ||
	   text.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   token.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	const int		  tokenLength = static_cast<int>( token.size()) ;	// Win32比較へ渡すtoken文字数。
	const std::size_t lastOffset  = text.size() - token.size() ;		// 検査可能な最後の開始位置。
	// Tokenが現れる可能性のある有限な全開始位置を順番に検査する。
	for( std::size_t offset{}; offset <= lastOffset; ++offset) {
		// 現在位置とtokenのlocale非依存比較結果。
		const int comparison = CompareStringOrdinal( text.data() + offset, tokenLength, token.data(),
													tokenLength, TRUE) ;
		// 大小文字を無視した token 完全一致が見つかった時点で包含を返す。
		if( comparison == CSTR_EQUAL) {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA update identity から revision を含む opaque identityを作成する。
 *
 * @param[in] update identity の取得元 update。
 * @param[out] identity UI と後続 install で照合する文字列。
 * @return 全必須 property を取得した結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readUpdateIdentity( IUpdate *const update, std::wstring &identity)
{
	Microsoft::WRL::ComPtr<IUpdateIdentity> updateIdentity ;				// UpdateIDとrevision取得interface。
	HRESULT result = update->get_Identity( updateIdentity.GetAddressOf()) ;	// Property取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	std::wstring updateId ;	// WUAが発行したupdate固有GUID文字列。
	result =
		readBstr( [&updateIdentity]( BSTR *value) { return updateIdentity->get_UpdateID( value) ; },
				 updateId, MAXIMUM_UPDATE_ID_CHARACTERS) ;
	// WUA update ID の取得失敗と空値を拒否し、opaque identity を生成しない。
	if( FAILED( result) || updateId.empty()) {
		return FAILED( result) ? result : E_UNEXPECTED ;
	}

	LONG revision{} ;	// WUA update identityの非負revision番号。
	result = updateIdentity->get_RevisionNumber( &revision) ;
	// Revision 取得失敗または負の revision は有効な identity と扱わない。
	if( FAILED( result) || revision < 0) {
		return FAILED( result) ? result : E_UNEXPECTED ;
	}

	identity = updateId + L"#" + std::to_wstring( revision) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA update から UI に公開可能な metadata を読み取る。
 *
 * @param[in] update 読取元の driver update。
 * @param[in] source 既定 update service の表示 metadata。
 * @param[out] candidate hardware ID を含まない表示用 DTO。
 * @param[out] hardwareId aggregate Provider 内だけで device照合に使う Hardware ID。
 * @param[out] candidateAllowed driver-only境界を満たす場合はtrue。
 * @return identity と title を含む必須 property の取得結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readCandidate( IUpdate *const update, const UpdateSourceMetadata &source,
									UpdateCandidate &candidate, std::wstring &hardwareId,
									bool &candidateAllowed)
{
	candidateAllowed = false ;
	HRESULT result	 = readUpdateIdentity( update, candidate.identity) ;	// 必須metadata取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	candidate.providerId	  = std::wstring( WINDOWS_UPDATE_PROVIDER_ID) ;
	candidate.packageIdentity = L"wua-update:" + candidate.identity ;

	result = readBstr( [update]( BSTR *value) { return update->get_Title( value) ; }, candidate.title,
					  MAXIMUM_TITLE_CHARACTERS) ;
	// 必須 title の取得失敗と空値では表示候補を生成しない。
	if( FAILED( result) || candidate.title.empty()) {
		return FAILED( result) ? result : E_UNEXPECTED ;
	}

	candidate.sourceName		= source.name ;
	candidate.sourceLocation	= source.location ;
	candidate.action			= DriverAction::UPDATE ;
	candidate.defaultPreference = CandidateDefaultPreference::MANAGED_APPLICABLE ;
	candidate.discoveryBasis	= CandidateDiscoveryBasis::MANAGED_SERVICE ;
	candidate.recommended		= true ;
	candidate.installable		= true ;

	VARIANT_BOOL booleanValue = VARIANT_FALSE ;	// 複数のWUA boolean property受信領域。
	// EULA 同意状態を取得できた場合だけ現在の同意済み flag を反映する。
	if( SUCCEEDED( update->get_EulaAccepted( &booleanValue))) {
		candidate.eulaAccepted = booleanValue == VARIANT_TRUE ;
	}

	booleanValue = VARIANT_FALSE ;
	// WUA が全 payload の cache 有無を返した場合だけ取得状態へ反映する。
	if( SUCCEEDED( update->get_IsDownloaded( &booleanValue))) {
		// IsDownloaded は全 payload の local cache 有無であり、install 状態ではない。
		candidate.allContentCached = booleanValue == VARIANT_TRUE ;
	}

	DECIMAL	  maximumSize{} ;	// WUAが返す最大download sizeのAutomation decimal。
	ULONGLONG maximumBytes{} ;	// 変換後の最大download size（byte）。
	// 最大取得 size を非負の整数へ変換できた場合だけ byte 数として表示する。
	if( SUCCEEDED( update->get_MaxDownloadSize( &maximumSize)) &&
	   SUCCEEDED( VarUI8FromDec( &maximumSize, &maximumBytes))) {
		candidate.maximumDownloadBytes = static_cast<std::uint64_t>( maximumBytes) ;
	}

	Microsoft::WRL::ComPtr<IWindowsDriverUpdate> driverUpdate ;	// Driver固有metadata interface。
	result = update->QueryInterface( IID_PPV_ARGS( driverUpdate.GetAddressOf())) ;
	// DriverClassを検証できない候補はfirmware除外を証明できないため拒否する。
	if( FAILED( result)) {

		return result ;
	}

	result = readBstr( [&driverUpdate]( BSTR *value) { return driverUpdate->get_DriverClass( value) ; },
					  candidate.driverClass) ;
	// 空classはfirmwareか通常driverかをfail-closedで判定できない。
	if( FAILED( result) || candidate.driverClass.empty()) {

		return FAILED( result) ? result : E_UNEXPECTED ;
	}

	// Driver-only 境界を満たさない更新は候補にせず、取得自体の失敗とは区別する。
	if( !isWuaDriverCandidateAllowed( candidate.driverClass, candidate.title)) {
		return S_OK ;
	}

	candidateAllowed = true ;

	static_cast<void>( readBstr(
		[&driverUpdate]( BSTR *value) { return driverUpdate->get_DriverManufacturer( value) ; },
		candidate.manufacturer)) ;
	static_cast<void>(
		readBstr( [&driverUpdate]( BSTR *value) { return driverUpdate->get_DriverModel( value) ; },
				 candidate.model)) ;
	static_cast<void>(
		readBstr( [&driverUpdate]( BSTR *value) { return driverUpdate->get_DriverProvider( value) ; },
				 candidate.provider)) ;
	static_cast<void>(
		readBstr( [&driverUpdate]( BSTR *value) { return driverUpdate->get_DriverHardwareID( value) ; },
				 hardwareId)) ;

	DATE driverDate{} ;	// WUAが返すdriver version日付のOLE DATE。
	// WUA の明示 driver 日付を取得できた場合だけ表示用の日付へ変換する。
	if( SUCCEEDED( driverUpdate->get_DriverVerDate( &driverDate))) {
		candidate.driverDate = formatDriverDate( driverDate) ;
	}

	Microsoft::WRL::ComPtr<IWindowsDriverUpdate2> driverUpdate2 ;	// Reboot metadata interface。
	// 追加 driver interface を取得できる場合だけ再起動見込みを照会する。
	if( SUCCEEDED( update->QueryInterface( IID_PPV_ARGS( driverUpdate2.GetAddressOf())))) {
		booleanValue = VARIANT_FALSE ;
		// 再起動情報を取得できた場合だけ候補の見込み値を反映する。
		if( SUCCEEDED( driverUpdate2->get_RebootRequired( &booleanValue))) {
			candidate.rebootMayBeRequired = booleanValue == VARIANT_TRUE ;
		}
	}

	Microsoft::WRL::ComPtr<IWindowsDriverUpdate3> driverUpdate3 ;	// BrowseOnly metadata interface。
	// BrowseOnly を公開する追加 interface がある場合だけ状態を照会する。
	if( SUCCEEDED( update->QueryInterface( IID_PPV_ARGS( driverUpdate3.GetAddressOf())))) {
		booleanValue = VARIANT_FALSE ;
		// BrowseOnly の取得成功時だけ任意更新の区別を候補へ反映する。
		if( SUCCEEDED( driverUpdate3->get_BrowseOnly( &booleanValue))) {
			candidate.browseOnly = booleanValue == VARIANT_TRUE ;
		}
	}

	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全 update entry の未設定 download error を共通失敗で埋める。
 *
 * @param[in,out] result 更新対象の install 結果。
 * @param[in] error 記録する HRESULT。
 */
//------------------------------------------------------------------------------
void applyDownloadFailure( InstallResult &result, const HRESULT error)
{
	result.succeeded	   = false ;
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = toNativeError( error) ;

	// 個別結果がまだない entry だけへ operation-level error を関連付ける。
	for( UpdateExecutionResult &update : result.updates) {
		// 未開始の download 結果だけを共通失敗で埋め、確定済み個別結果を保持する。
		if( update.downloadOutcome == OutcomeCode::NOT_STARTED) {
			update.downloadOutcome = OutcomeCode::FAILURE ;
			update.downloadError   = toNativeError( error) ;
		}
	}
}

} // namespace

//------------------------------------------------------------------------------
/** @see src/platform/windows_update_provider.h 宣言側の契約を正本とします。 */
//------------------------------------------------------------------------------
ServerSelection windowsUpdateServerSelection() noexcept
{
	return ssDefault ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isWuaDriverCandidateAllowed( const std::wstring_view driverClass,
											   const std::wstring_view title) noexcept
{
	// 必須 class・title の欠落と metadata 長上限超過を driver 候補へ受理しない。
	if( driverClass.empty() || title.empty() ||
	   driverClass.size() > static_cast<std::size_t>( MAXIMUM_METADATA_CHARACTERS) ||
	   title.size() > static_cast<std::size_t>( MAXIMUM_TITLE_CHARACTERS)) {
		return false ;
	}

	return !containsOrdinalIgnoreCase( driverClass, L"firmware") &&
		   !containsOrdinalIgnoreCase( driverClass, L"uefi") &&
		   !containsOrdinalIgnoreCase( driverClass, L"bios") &&
		   !containsOrdinalIgnoreCase( title, L"firmware") &&
		   !containsOrdinalIgnoreCase( title, L"uefi") && !containsOrdinalIgnoreCase( title, L"bios") ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult WindowsUpdateProvider::scan( const ScanSessionId			   scanSessionId,
									   const ScanOptions			  &options,
									   const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( options) ;
	invalidateScanSession() ;
	progressCallback( {.stage = ProviderStage::SEARCHING_WINDOWS_UPDATE}) ;

	ScanResult result{} ;	// WUA候補または失敗情報を保持するscan結果。
	result.scanSessionId = scanSessionId ;

	// 0 は session 不在の sentinel であり、後続 install と安全に照合できないため拒否する。
	if( scanSessionId == 0) {
		result.outcome = OutcomeCode::FAILURE ;
		result.error   = toNativeError( E_INVALIDARG) ;
		return result ;
	}

	measurementEvidence_.providerId	   = WINDOWS_UPDATE_PROVIDER_ID ;
	measurementEvidence_.scanSessionId = scanSessionId ;
	measurementEvidence_.scope		   = MeasurementScope::SYSTEM_QUERY ;

	HRESULT operationResult = ensureSession() ;	// 現在段階のWUA/COM実行結果。
	// Scan 準備の失敗を WUA の HRESULT と共に返す。
	if( FAILED( operationResult)) {
		measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
		result.outcome					  = OutcomeCode::FAILURE ;
		result.error					  = toNativeError( operationResult) ;
		return result ;
	}

	Microsoft::WRL::ComPtr<IUpdateSearcher> searcher ;	// Online driver検索を実行するWUA object。
	operationResult = session_->CreateUpdateSearcher( searcher.GetAddressOf()) ;
	// WUA session の準備失敗時は検索を開始しない。
	if( FAILED( operationResult)) {
		measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
		result.outcome					  = OutcomeCode::FAILURE ;
		result.error					  = toNativeError( operationResult) ;
		return result ;
	}

	// ssDefault により、利用者または管理者が構成した Windows Update/WSUS policy を尊重する。
	operationResult = searcher->put_ServerSelection( windowsUpdateServerSelection()) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = searcher->put_Online( VARIANT_TRUE) ;
	}

	UniqueBstr clientId( CLIENT_APPLICATION_ID) ;	// Searcherへ設定する所有client ID BSTR。
	// Client ID の BSTR 確保失敗を正常な空 ID と扱わない。
	if( SUCCEEDED( operationResult) && clientId.get() == nullptr) {
		operationResult = E_OUTOFMEMORY ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = searcher->put_ClientApplicationID( clientId.get()) ;
	}

	UniqueBstr criteria( DRIVER_SEARCH_CRITERIA) ;	// Driver検索条件を保持する所有BSTR。
	// 検索条件の BSTR を確保できなければ検索を開始しない。
	if( SUCCEEDED( operationResult) && criteria.get() == nullptr) {
		operationResult = E_OUTOFMEMORY ;
	}

	Microsoft::WRL::ComPtr<ISearchResult> searchResult ;	// 同期online検索のoperation結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		measurementEvidence_.queryOutcome = OutcomeCode::IN_PROGRESS ;
		operationResult = searcher->Search( criteria.get(), searchResult.GetAddressOf()) ;
	}

	// 検索設定または実行の失敗を scan 全体の失敗として返す。
	if( FAILED( operationResult)) {
		measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
		result.outcome					  = OutcomeCode::FAILURE ;
		result.error					  = toNativeError( operationResult) ;
		return result ;
	}

	OperationResultCode wuaOutcome = orcNotStarted ;	// WUA検索全体の結果分類。
	operationResult				   = searchResult->get_ResultCode( &wuaOutcome) ;
	// 検索結果 code の取得に失敗した場合は正常 scan と仮定しない。
	if( FAILED( operationResult)) {
		measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
		result.outcome					  = OutcomeCode::FAILURE ;
		result.error					  = toNativeError( operationResult) ;
		return result ;
	}

	result.outcome					  = toOutcomeCode( wuaOutcome) ;
	measurementEvidence_.queryOutcome = result.outcome ;
	// 検索結果が成功分類でなければ候補列挙へ進まず失敗を通知する。
	if( !isSuccessOutcome( result.outcome)) {
		// ISearchResult は operation-level HRESULT を公開しないため、失敗分類を E_FAIL
		// と関連付ける。
		result.error = toNativeError( E_FAIL) ;
		return result ;
	}

	Microsoft::WRL::ComPtr<IUpdateCollection> updates ;	// WUAが返したdriver候補collection。
	operationResult = searchResult->get_Updates( updates.GetAddressOf()) ;
	// 検索結果の更新 collection を取得できなければ scan を中止する。
	if( FAILED( operationResult)) {
		result.outcome = OutcomeCode::FAILURE ;
		result.error   = toNativeError( operationResult) ;
		return result ;
	}

	LONG count{} ;	// WUA collection内の候補数。
	operationResult = updates->get_Count( &count) ;
	// 件数取得の失敗、負の件数、候補上限超過を列挙前に拒否する。
	if( FAILED( operationResult) || count < 0 || count > MAXIMUM_UPDATE_CANDIDATES) {
		result.outcome = OutcomeCode::FAILURE ;
		result.error   = toNativeError(
			  FAILED( operationResult)
				  ? operationResult
				  : (count < 0 ? E_UNEXPECTED : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_WINDOWS_UPDATE,
					  .percentComplete = 50,
					  .completedItems  = 0,
					  .totalItems	   = static_cast<std::uint64_t>( count)}) ;

	result.candidates.reserve( static_cast<std::size_t>( count)) ;
	std::unordered_map<std::wstring, LONG> indexes ;	// Opaque identityからWUA indexへの対応。
	indexes.reserve( static_cast<std::size_t>( count)) ;
	std::unordered_map<std::wstring, std::wstring> hardwareIds ;	// 内部照合用Hardware ID表。
	hardwareIds.reserve( static_cast<std::size_t>( count)) ;
	const UpdateSourceMetadata source = readDefaultUpdateSource() ;	// UIへ示す取得元metadata。

	// WUA collection の全候補を順番どおり DTO 化し、identity の一意性も同時に検証する。
	for( LONG index = 0; index < count; ++index) {
		Microsoft::WRL::ComPtr<IUpdate> update ;	// 現在DTOへ変換中のWUA update。
		operationResult = updates->get_Item( index, update.GetAddressOf()) ;
		// 個別 update の取得に失敗したら不完全な列挙を打ち切る。
		if( FAILED( operationResult)) {
			break ;
		}

		UpdateCandidate candidate ;				// UIへ渡すdriver candidate DTO。
		std::wstring	hardwareId ;			// Aggregate provider内だけで使用するHardware ID。
		bool			candidateAllowed{} ;	// trueの場合だけ表示およびinstall mapへ保持する。
		operationResult =
			readCandidate( update.Get(), source, candidate, hardwareId, candidateAllowed) ;
		// 候補 metadata の取得に失敗したら部分一覧を確定しない。
		if( FAILED( operationResult)) {
			break ;
		}

		// Driver-only 境界を満たす候補だけを identity map と表示一覧へ追加する。
		if( candidateAllowed) {
			candidate.audit = makeWindowsManagedCandidateAudit( false) ;
			// WUA identity の重複があれば routing の曖昧さを残さず列挙を中止する。
			if( !indexes.emplace( candidate.identity, index).second) {
				operationResult = E_UNEXPECTED ;
				break ;
			}

			// WUA が Hardware ID を返した候補だけに worker 内の照合情報を保持する。
			if( !hardwareId.empty()) {
				hardwareIds.emplace( candidate.identity, std::move( hardwareId)) ;
			}

			result.candidates.push_back( std::move( candidate)) ;
			measurementEvidence_.records.push_back( {result.candidates.back().identity, {}}) ;
		}

		const std::uint64_t completed =	// 現在までにDTO変換を完了したWUA候補数。
			static_cast<std::uint64_t>( index) + 1 ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_WINDOWS_UPDATE,
						  .percentComplete = static_cast<std::uint32_t>(
							  50 + completed * 50 / static_cast<std::uint64_t>( count)),
						  .completedItems = completed,
						  .totalItems	  = static_cast<std::uint64_t>( count)}) ;
	}

	// 列挙途中で失敗した場合は候補一覧を破棄し scan 失敗として返す。
	if( FAILED( operationResult)) {
		result.succeeded = false ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.error	 = toNativeError( operationResult) ;
		result.candidates.clear() ;
		measurementEvidence_.recordExtent		 = MeasurementExtent::LOWER_BOUND ;
		measurementEvidence_.applicabilityExtent = MeasurementExtent::LOWER_BOUND ;
		measurementEvidence_.readinessExtent	 = MeasurementExtent::LOWER_BOUND ;
		return result ;
	}

	scanUpdates_   = std::move( updates) ;
	updateIndexes_ = std::move( indexes) ;
	hardwareIds_   = std::move( hardwareIds) ;
	scanSessionId_ = scanSessionId ;
	// WUA collection が空の場合も検索段階の確定完了を通知する。
	if( count == 0) {
		progressCallback(
			{.stage = ProviderStage::SEARCHING_WINDOWS_UPDATE, .percentComplete = 100}) ;
	}

	result.succeeded = true ;
	// 完全成功だけを確定範囲とし、部分成功で未処理recordが残る場合は下限を維持する。
	const MeasurementExtent completedExtent	 = result.outcome == OutcomeCode::SUCCESS
												   ? MeasurementExtent::EXACT
												   : MeasurementExtent::LOWER_BOUND ;
	measurementEvidence_.recordExtent		 = completedExtent ;
	measurementEvidence_.applicabilityExtent = completedExtent ;
	measurementEvidence_.readinessExtent	 = completedExtent ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::wstring> WindowsUpdateProvider::hardwareIdForIdentity(
	const std::wstring_view identity) const
{
	const auto iterator = hardwareIds_.find( std::wstring( identity)) ;	// Hardware ID検索結果。
	// 候補に対応する worker 内 ID がない場合は未取得として返す。
	if( iterator == hardwareIds_.end()) {
		return std::nullopt ;
	}

	return iterator->second ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const ProviderMeasurementEvidence &WindowsUpdateProvider::measurementEvidence() const noexcept
{
	return measurementEvidence_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult WindowsUpdateProvider::install( const ScanSessionId				 scanSessionId,
											 const std::span<const std::wstring> identities,
											 const std::uintptr_t				 parentWindowNative,
											 const ProviderProgressCallback		&progressCallback)
{
	InstallResult result{} ;	// 選択identity順で個別結果を保持するinstall結果。
	result.updates.reserve( identities.size()) ;
	// 後続の失敗段階にかかわらず、全選択identityへ個別結果を返せる領域を用意する。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	// stale result、空選択、別 thread からの呼出しを WUA object へ到達させない。
	if( identities.empty() || scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   scanUpdates_ == nullptr || GetCurrentThreadId() != ownerThreadId_) {
		applyDownloadFailure( result, E_INVALIDARG) ;
		return result ;
	}

	std::unordered_set<std::wstring> uniqueIdentities ;	// 重複検証済み選択identity集合。
	uniqueIdentities.reserve( identities.size()) ;

	Microsoft::WRL::ComPtr<IUpdateCollection> selectedUpdates ;	// 選択順で再構築するWUA collection。
	// 現在段階のWUA/COM実行結果。
	HRESULT									  operationResult =
		CoCreateInstance( __uuidof( UpdateCollection), nullptr, CLSCTX_INPROC_SERVER,
						 IID_PPV_ARGS( selectedUpdates.GetAddressOf())) ;
	// 導入準備の失敗時は未開始 download を失敗にし session を失効させる。
	if( FAILED( operationResult)) {
		applyDownloadFailure( result, operationResult) ;
		invalidateScanSession() ;
		return result ;
	}

	// identity を再検証して、現在の WUA collection から選択順に新しい collection を構築する。
	for( const std::wstring &identity : identities) {
		// 選択 identity が重複した場合は collection の構築を中止する。
		if( !uniqueIdentities.insert( identity).second) {
			operationResult = E_INVALIDARG ;
			break ;
		}

		// Scan collection内のWUA index検索結果。
		const auto indexIterator = updateIndexes_.find( identity) ;
		// 現在 scan にない identity は未知選択として拒否する。
		if( indexIterator == updateIndexes_.end()) {
			operationResult = HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
			break ;
		}

		Microsoft::WRL::ComPtr<IUpdate> update ;	// 現在選択collectionへ追加するWUA update。
		operationResult = scanUpdates_->get_Item( indexIterator->second, update.GetAddressOf()) ;
		// 選択 update を WUA collection から取得できなければ中止する。
		if( FAILED( operationResult)) {
			break ;
		}

		VARIANT_BOOL eulaAccepted = VARIANT_FALSE ;	// TRUEの場合はWUA EULA受諾済み。
		operationResult			  = update->get_EulaAccepted( &eulaAccepted) ;
		// 同意状態を確認でき、未同意である選択対象だけを最終確認後に承認する。
		if( SUCCEEDED( operationResult) && eulaAccepted != VARIANT_TRUE) {
			// UI の最終確認後に到達する境界でだけ、選択対象の EULA を承認する。
			operationResult = update->AcceptEula() ;
		}

		// EULA 状態の取得または承認に失敗したら download へ進まない。
		if( FAILED( operationResult)) {
			break ;
		}

		LONG insertedIndex{} ;	// Selected collectionへ追加された0-based index。
		operationResult = selectedUpdates->Add( update.Get(), &insertedIndex) ;
		// 選択 update の collection 追加に失敗したら部分集合で実行しない。
		if( FAILED( operationResult)) {
			break ;
		}
	}

	// Installを一度試みたselectionは再利用せず、次回操作前の明示的な再scanを要求する。
	invalidateScanSession() ;
	// 選択 collection の準備失敗を download の失敗として全対象へ反映する。
	if( FAILED( operationResult)) {
		applyDownloadFailure( result, operationResult) ;
		return result ;
	}

	Microsoft::WRL::ComPtr<IUpdateDownloader> downloader ;	// 選択collectionの同期downloader。
	operationResult = session_->CreateUpdateDownloader( downloader.GetAddressOf()) ;
	UniqueBstr clientId( CLIENT_APPLICATION_ID) ;	// Downloader/installer共通の所有client ID BSTR。
	// Downloader 用 client ID を確保できなければ memory 不足として中止する。
	if( SUCCEEDED( operationResult) && clientId.get() == nullptr) {
		operationResult = E_OUTOFMEMORY ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = downloader->put_ClientApplicationID( clientId.get()) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = downloader->put_Updates( selectedUpdates.Get()) ;
	}

	// Downloader の準備失敗時は未開始対象に共通 error を残す。
	if( FAILED( operationResult)) {
		applyDownloadFailure( result, operationResult) ;
		return result ;
	}

	// cache 済みの selection も WUA downloader へ渡し、全 content の利用可能性を再確認する。
	progressCallback( {.stage		  = ProviderStage::DOWNLOADING,
					  .completedItems = 0,
					  .totalItems	  = identities.size()}) ;
	Microsoft::WRL::ComPtr<IDownloadResult> downloadResult ;	// Collection全体のdownload結果。
	operationResult = downloader->Download( downloadResult.GetAddressOf()) ;
	// WUA download API の失敗を対象別の未開始結果へ反映する。
	if( FAILED( operationResult)) {
		applyDownloadFailure( result, operationResult) ;
		return result ;
	}

	OperationResultCode downloadCode = orcNotStarted ;	// Collection全体のdownload結果分類。
	LONG				downloadError{} ;				// Collection全体のdownload HRESULT bit pattern。
	operationResult = downloadResult->get_ResultCode( &downloadCode) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = downloadResult->get_HResult( &downloadError) ;
	}

	// Download 全体結果の取得失敗を成功にせず共通診断値として返す。
	if( FAILED( operationResult)) {
		applyDownloadFailure( result, operationResult) ;
		return result ;
	}

	result.downloadOutcome = toOutcomeCode( downloadCode) ;
	result.downloadError   = static_cast<NativeError>( downloadError) ;
	bool allDownloaded	   = true ;	// 全候補が成功かつcache済みの場合だけtrueを維持する。

	// 各 update の download 結果と実際の cache 状態を照合してから install を許可する。
	for( std::size_t index = 0; index < result.updates.size(); ++index) {
		Microsoft::WRL::ComPtr<IUpdateDownloadResult> updateDownloadResult ;	// 個別download結果。
		const LONG wuaIndex = static_cast<LONG>( index) ;						// WUA collection用の符号付きindex。
		operationResult =
			downloadResult->GetUpdateResult( wuaIndex, updateDownloadResult.GetAddressOf()) ;
		// 個別 download 結果が取得できない対象は失敗とし、確認済み進捗を通知する。
		if( FAILED( operationResult)) {
			result.updates[index].downloadOutcome = OutcomeCode::FAILURE ;
			result.updates[index].downloadError	  = toNativeError( operationResult) ;
			allDownloaded						  = false ;
			const std::uint64_t completed		  = index + 1 ;	// 結果確認済みdownload候補数。
			progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
							  .percentComplete = static_cast<std::uint32_t>( completed * 50 /
																			result.updates.size()),
							  .completedItems  = completed,
							  .totalItems	   = result.updates.size()}) ;
			continue ;
		}

		OperationResultCode updateDownloadCode = orcNotStarted ;	// 個別download結果分類。
		LONG				updateDownloadError{} ;					// 個別download HRESULT bit pattern。
		// 個別結果分類propertyの取得結果。
		const HRESULT		codeResult = updateDownloadResult->get_ResultCode( &updateDownloadCode) ;
		// 個別HRESULT propertyの取得結果。
		const HRESULT		errorResult = updateDownloadResult->get_HResult( &updateDownloadError) ;
		// 個別結果の code・HRESULT が読めない場合は最初の取得失敗を保持する。
		if( FAILED( codeResult) || FAILED( errorResult)) {
			// 最初に失敗した個別property取得code。
			const HRESULT propertyError			  = FAILED( codeResult) ? codeResult : errorResult ;
			result.updates[index].downloadOutcome = OutcomeCode::FAILURE ;
			result.updates[index].downloadError	  = toNativeError( propertyError) ;
			allDownloaded						  = false ;
			const std::uint64_t completed		  = index + 1 ;	// 結果確認済みdownload候補数。
			progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
							  .percentComplete = static_cast<std::uint32_t>( completed * 50 /
																			result.updates.size()),
							  .completedItems  = completed,
							  .totalItems	   = result.updates.size()}) ;
			continue ;
		}

		result.updates[index].downloadOutcome = toOutcomeCode( updateDownloadCode) ;
		result.updates[index].downloadError	  = static_cast<NativeError>( updateDownloadError) ;

		Microsoft::WRL::ComPtr<IUpdate> update ;		// Cache状態を再確認する選択update。
		VARIANT_BOOL  isDownloaded = VARIANT_FALSE ;	// 全contentがcache済みの場合はTRUE。
		// Selected collectionからupdateを再取得した結果。
		const HRESULT itemResult = selectedUpdates->get_Item( wuaIndex, update.GetAddressOf()) ;
		// IsDownloaded propertyまたはitem取得失敗code。
		const HRESULT downloadedResult =
			SUCCEEDED( itemResult) ? update->get_IsDownloaded( &isDownloaded) : itemResult ;
		// 結果成功と WUA の cache 完了確認が両方成立しない対象を未取得として扱う。
		if( !isSuccessOutcome( result.updates[index].downloadOutcome) || FAILED( downloadedResult) ||
		   isDownloaded != VARIANT_TRUE) {
			allDownloaded = false ;
		}

		const std::uint64_t completed = index + 1 ;	// 結果確認を完了したdownload候補数。
		progressCallback(
			{.stage			  = ProviderStage::DOWNLOADING,
			 .percentComplete = static_cast<std::uint32_t>( completed * 50 / result.updates.size()),
			 .completedItems  = completed,
			 .totalItems	  = result.updates.size()}) ;
	}

	// collection の一部だけを install して結果を曖昧にしない。
	if( !allDownloaded || !isSuccessOutcome( result.downloadOutcome)) {
		return result ;
	}

	Microsoft::WRL::ComPtr<IUpdateInstaller> installer ;	// 選択collectionの同期installer。
	operationResult = session_->CreateUpdateInstaller( installer.GetAddressOf()) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = installer->put_ClientApplicationID( clientId.get()) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = installer->put_Updates( selectedUpdates.Get()) ;
	}

	// Installer の準備が成功した場合だけ WUA dialog の親 Window を設定する。
	if( SUCCEEDED( operationResult)) {
		// WUA が所有する dialog を DriverCrate の top-level Window に関連付ける。
		// WUA dialogに渡す呼出し元所有のparent Window handle。
		const HWND parentWindow = reinterpret_cast<HWND>( parentWindowNative) ;
		operationResult			= installer->put_ParentHwnd( parentWindow) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = installer->put_AllowSourcePrompts( VARIANT_TRUE) ;
	}

	// Installer の設定失敗は取得成功と分離して導入失敗として返す。
	if( FAILED( operationResult)) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = toNativeError( operationResult) ;
		return result ;
	}

	VARIANT_BOOL installerBusy = VARIANT_FALSE ;	// TRUEの場合は別installが実行中。
	operationResult			   = installer->get_IsBusy( &installerBusy) ;
	// Busy 状態の照会失敗または使用中の installer では導入を開始しない。
	if( FAILED( operationResult) || installerBusy == VARIANT_TRUE) {
		// Property取得失敗または明示的なERROR_BUSY。
		const HRESULT busyError =
			FAILED( operationResult) ? operationResult : HRESULT_FROM_WIN32( ERROR_BUSY) ;
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = toNativeError( busyError) ;
		return result ;
	}

	VARIANT_BOOL rebootBeforeInstall = VARIANT_FALSE ;	// Install前再起動要求flag。
	operationResult = installer->get_RebootRequiredBeforeInstallation( &rebootBeforeInstall) ;
	// 事前再起動の照会失敗と明示要求を拒否し、必要な再起動情報を保持する。
	if( FAILED( operationResult) || rebootBeforeInstall == VARIANT_TRUE) {
		// Property取得失敗または再起動要求code。
		const HRESULT rebootError = FAILED( operationResult)
										? operationResult
										: HRESULT_FROM_WIN32( ERROR_SUCCESS_REBOOT_REQUIRED) ;
		result.installOutcome	  = OutcomeCode::FAILURE ;
		result.installError		  = toNativeError( rebootError) ;
		result.rebootRequired	  = rebootBeforeInstall == VARIANT_TRUE ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 50,
					  .completedItems  = 0,
					  .totalItems	   = identities.size()}) ;
	Microsoft::WRL::ComPtr<IInstallationResult> installationResult ;	// Collection install結果。
	operationResult = installer->Install( installationResult.GetAddressOf()) ;
	// WUA install API が失敗した場合は導入の診断値を保持する。
	if( FAILED( operationResult)) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = toNativeError( operationResult) ;
		return result ;
	}

	OperationResultCode installCode = orcNotStarted ;		// Collection全体のinstall結果分類。
	LONG				installError{} ;					// Collection全体のinstall HRESULT bit pattern。
	VARIANT_BOOL		rebootRequired = VARIANT_FALSE ;	// Collection全体の再起動要求flag。
	operationResult					   = installationResult->get_ResultCode( &installCode) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = installationResult->get_HResult( &installError) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( operationResult)) {
		operationResult = installationResult->get_RebootRequired( &rebootRequired) ;
	}

	// 導入全体結果を確認できない場合は成功と仮定しない。
	if( FAILED( operationResult)) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = toNativeError( operationResult) ;
		return result ;
	}

	result.installOutcome = toOutcomeCode( installCode) ;
	result.installError	  = static_cast<NativeError>( installError) ;
	result.rebootRequired = rebootRequired == VARIANT_TRUE ;
	bool allInstalled	  = true ;	// 全個別installが成功の場合だけtrueを維持する。

	// WUA の collection 順序と selection 順序が一致する契約に基づき個別結果を対応付ける。
	for( std::size_t index = 0; index < result.updates.size(); ++index) {
		Microsoft::WRL::ComPtr<IUpdateInstallationResult> updateInstallResult ;	// 個別結果。
		// Collection indexに対応する個別result取得結果。
		const HRESULT itemResult = installationResult->GetUpdateResult(
			static_cast<LONG>( index), updateInstallResult.GetAddressOf()) ;
		// 個別 install 結果を取得できない対象は失敗とし、結果確認の進捗を通知する。
		if( FAILED( itemResult)) {
			result.updates[index].installOutcome = OutcomeCode::FAILURE ;
			result.updates[index].installError	 = toNativeError( itemResult) ;
			allInstalled						 = false ;
			const std::uint64_t completed		 = index + 1 ;	// 結果確認済みinstall候補数。
			progressCallback( {.stage		   = ProviderStage::INSTALLING,
							  .percentComplete = static_cast<std::uint32_t>(
								  50 + completed * 50 / result.updates.size()),
							  .completedItems = completed,
							  .totalItems	  = result.updates.size()}) ;
			continue ;
		}

		OperationResultCode updateInstallCode = orcNotStarted ;		// 個別install結果分類。
		LONG				updateInstallError{} ;					// 個別install HRESULT bit pattern。
		VARIANT_BOOL		updateRebootRequired = VARIANT_FALSE ;	// 個別再起動要求flag。
		// 個別結果分類propertyの取得結果。
		const HRESULT		codeResult = updateInstallResult->get_ResultCode( &updateInstallCode) ;
		// 個別HRESULT propertyの取得結果。
		const HRESULT		errorResult = updateInstallResult->get_HResult( &updateInstallError) ;
		// 個別再起動propertyの取得結果。
		const HRESULT rebootResult = updateInstallResult->get_RebootRequired( &updateRebootRequired) ;
		// 個別 code・HRESULT・再起動情報の取得失敗を診断値付き導入失敗として保持する。
		if( FAILED( codeResult) || FAILED( errorResult) || FAILED( rebootResult)) {
			// 最初に失敗した個別property取得code。
			const HRESULT propertyError			 = FAILED( codeResult)
													   ? codeResult
													   : (FAILED( errorResult) ? errorResult : rebootResult) ;
			result.updates[index].installOutcome = OutcomeCode::FAILURE ;
			result.updates[index].installError	 = toNativeError( propertyError) ;
			allInstalled						 = false ;
			const std::uint64_t completed		 = index + 1 ;	// 結果確認済みinstall候補数。
			progressCallback( {.stage		   = ProviderStage::INSTALLING,
							  .percentComplete = static_cast<std::uint32_t>(
								  50 + completed * 50 / result.updates.size()),
							  .completedItems = completed,
							  .totalItems	  = result.updates.size()}) ;
			continue ;
		}

		result.updates[index].installOutcome = toOutcomeCode( updateInstallCode) ;
		result.updates[index].installError	 = static_cast<NativeError>( updateInstallError) ;
		result.updates[index].rebootRequired = updateRebootRequired == VARIANT_TRUE ;
		result.rebootRequired = result.rebootRequired || result.updates[index].rebootRequired ;
		allInstalled = allInstalled && isSuccessOutcome( result.updates[index].installOutcome) ;
		const std::uint64_t completed = index + 1 ;	// 結果確認済みinstall候補数。
		progressCallback( {.stage		   = ProviderStage::INSTALLING,
						  .percentComplete = static_cast<std::uint32_t>(
							  50 + completed * 50 / result.updates.size()),
						  .completedItems = completed,
						  .totalItems	  = result.updates.size()}) ;
	}

	result.succeeded = allInstalled && isSuccessOutcome( result.installOutcome) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
HRESULT WindowsUpdateProvider::ensureSession()
{
	const DWORD currentThreadId = GetCurrentThreadId() ;	// 現在呼出しthread ID。
	// apartment-bound COM object を別 thread から利用しない。
	if( session_ != nullptr) {

		return currentThreadId == ownerThreadId_ ? S_OK : RPC_E_WRONG_THREAD ;
	}

	// WUA session作成またはClientApplicationID設定結果。
	HRESULT result = CoCreateInstance( __uuidof( UpdateSession), nullptr, CLSCTX_INPROC_SERVER,
									  IID_PPV_ARGS( session_.GetAddressOf())) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	UniqueBstr clientId( CLIENT_APPLICATION_ID) ;	// Sessionへ設定する所有client ID BSTR。
	// Client ID を確保できなければ途中の WUA session を破棄する。
	if( clientId.get() == nullptr) {
		session_.Reset() ;
		return E_OUTOFMEMORY ;
	}

	result = session_->put_ClientApplicationID( clientId.get()) ;
	// WUA session 設定の失敗時は不完全な session を保持しない。
	if( FAILED( result)) {
		session_.Reset() ;
		return result ;
	}

	ownerThreadId_ = currentThreadId ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void WindowsUpdateProvider::invalidateScanSession() noexcept
{
	scanUpdates_.Reset() ;
	updateIndexes_.clear() ;
	hardwareIds_.clear() ;
	measurementEvidence_ = {} ;
	scanSessionId_		 = 0 ;
}

} // namespace drivercrate
