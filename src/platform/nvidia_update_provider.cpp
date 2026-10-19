//------------------------------------------------------------------------------
/**
 * @file nvidia_update_provider.cpp
 * @brief NVIDIA公式driver Provider実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  世代hintの一時文字列参照を所有値化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  対象外時の不存在session member参照を削除。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  未監査EXE直接導入経路を削除。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通local照合契約対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider識別情報追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Scan状態分類追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通file検証へ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local coverage集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Notebook既定選択境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式構造化探索経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy registry接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式HTTP取得根拠記録追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note NVIDIA公式lookup APIで製品名を照合し、Game ReadyとStudioの現行・過去版を表示します。EXEの非実行監査が未接続のため導入は拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/nvidia_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/nvidia_catalog_parser.h"

#include <Windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <limits>
#include <optional>
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

constexpr std::uint64_t MAXIMUM_METADATA_BYTES	= 16U * 1024U * 1024U ;					// API応答上限。
constexpr std::uint64_t MAXIMUM_INSTALLER_BYTES = 4ULL * 1024ULL * 1024ULL * 1024ULL ;	// EXE上限。
constexpr std::size_t	MAXIMUM_SERIES_QUERIES	= 128 ;									// 一deviceで照会するseries数上限。
constexpr std::size_t	MAXIMUM_RELEASES_PER_CHANNEL = 10 ;								// UIへ保持するchannel別release上限。
constexpr std::wstring_view DISPLAY_CLASS_GUID_KEY =
	L"4D36E968E32511CEBFC108002BE10318" ;	// Display adapter setup class GUID。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief NVIDIA lookup APIで特定したseries IDとproduct IDの組である。
 */
struct NvidiaProductIdentity {
	/// DriverManualLookupのpsidへ渡す数字ID。
	std::wstring seriesId ;
	/// DriverManualLookupのpfidへ渡す数字ID。
	std::wstring productId ;
	/// 公式productまたはseries名がnotebook向けを示す場合true。
	bool		 notebook{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 *
 * @param[in] error GetLastErrorが返したWin32 error。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Product名を大文字英数字だけの照合keyへ変換する。
 *
 * 表示上の空白や商標記号だけを無視し、model番号は維持する。
 *
 * @param[in] name LocalまたはNVIDIA公式のproduct表示名。
 * @return 空白、記号、商標記号を除いた大文字照合key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeProductName( const std::wstring_view name)
{
	std::wstring normalized ;	// 製品名照合用のmutable key。
	normalized.reserve( name.size()) ;
	// Unicode英数字だけを維持し、大文字小文字差を除去する。
	for( const wchar_t character : name) {
		// 製品名の英数字だけを照合keyへ残して区切り表記の差を除く。
		if( std::iswalnum( character) != 0) {
			normalized.push_back( static_cast<wchar_t>( std::towupper( character))) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA社名接頭辞を除いたproduct完全一致keyを作る。
 *
 * Windows表示名の`NVIDIA GeForce`と公式の`GeForce`を同一視し、model部分は完全一致のまま維持する。
 *
 * @param[in] name LocalまたはNVIDIA公式のproduct表示名。
 * @return 任意のNVIDIA接頭辞だけを除いた大文字英数字key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring productMatchKey( const std::wstring_view name)
{
	std::wstring				key = normalizeProductName( name) ;	// 接頭辞除去前のproduct key。
	constexpr std::wstring_view VENDOR_PREFIX = L"NVIDIA" ;			// Windows側に付く社名接頭辞。
	// 先頭の社名だけを除き、製品名本体で完全一致照合する。
	if( key.starts_with( VENDOR_PREFIX)) {
		key.erase( 0, VENDOR_PREFIX.size()) ;
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA product type IDの照会優先順を決定する。
 *
 * 公開lookup APIの製品区分へ絞り、不要な全catalog照会を避ける。
 *
 * @param[in] model Local NVIDIA device表示名。
 * @return NVIDIA lookup APIのParentID優先順。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::wstring> productTypeIds( const std::wstring_view model)
{
	const std::wstring normalized = normalizeProductName( model) ;	// 分類用product名。
	// GeForce表示に対応するproduct typeを照会対象にする。
	if( normalized.find( L"GEFORCE") != std::wstring::npos) {
		return {L"1"} ;
	}

	// TITAN表示は専用typeを優先し、既定の代替typeも照会する。
	if( normalized.find( L"TITAN") != std::wstring::npos) {
		return {L"11", L"1"} ;
	}

	// QuadroまたはRTX表示を対応するproduct typeへ振り分ける。
	if( normalized.find( L"QUADRO") != std::wstring::npos ||
	   normalized.find( L"RTX") != std::wstring::npos) {
		return {L"3"} ;
	}

	// Tesla表示を対応するproduct typeへ振り分ける。
	if( normalized.find( L"TESLA") != std::wstring::npos) {
		return {L"7"} ;
	}

	// GRID表示を対応するproduct typeへ振り分ける。
	if( normalized.find( L"GRID") != std::wstring::npos) {
		return {L"9"} ;
	}

	// NVS表示を対応するproduct typeへ振り分ける。
	if( normalized.find( L"NVS") != std::wstring::npos) {
		return {L"8"} ;
	}

	// ION表示を対応するproduct typeへ振り分ける。
	if( normalized.find( L"ION") != std::wstring::npos) {
		return {L"6"} ;
	}

	return {L"3", L"4"} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Seriesをlocal productに近い順へ並べ替える。
 *
 * 世代keyとNotebook表記をhintにするが、除外はせずfallbackを残す。
 *
 * @param[in] model Local NVIDIA product名。
 * @param[in,out] series NVIDIA APIが返したseries群。
 */
//------------------------------------------------------------------------------
void prioritizeSeries( const std::wstring_view model, std::vector<NvidiaLookupValue> &series)
{
	const std::wstring modelKey	  = normalizeProductName( model) ;			// Local照会順hint用key。
	const std::wstring generation = nvidiaProductGenerationKey( model) ;	// 所有値の世代hint。
	const bool		   laptop	  =											// Local名がnotebook系seriesの先行照会を要求する場合true。
		modelKey.find( L"LAPTOP") != std::wstring::npos ||
		modelKey.find( L"NOTEBOOK") != std::wstring::npos ;
	const auto score = [&generation, laptop]( const NvidiaLookupValue &value) {
		const std::wstring seriesKey = normalizeProductName( value.name) ;	// Series照合key。
		int				   result{} ;										// 大きいほど先に照会するpriority score。
		// 製品の世代keyを含むseriesを照会順で優先する。
		if( !generation.empty() && seriesKey.find( generation) != std::wstring::npos) {
			result += 100 ;
		}

		const bool notebook =	// 公式series名がnotebook向けを示す場合true。
			isNvidiaNotebookProduct( {}, value.name) ;
		// notebook区分の一致をseries照会順の補助条件にする。
		if( notebook == laptop) {
			result += 10 ;
		}

		return result ;
	} ;
	std::stable_sort( series.begin(), series.end(),
					 [&score]( const NvidiaLookupValue &left, const NvidiaLookupValue &right) {
						 return score( left) > score( right) ;
					 }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA lookup XMLを公式APIから取得する。
 *
 * 応答上限とschemaを検証し、不正応答を候補へ使用しない。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] url www.nvidia.com上のlookup URL。
 * @param[out] values 成功時のlookup value群。
 * @return 取得・parse成功時は0、失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError fetchLookup( OfficialHttpClient &client, const std::wstring_view url,
									  std::vector<NvidiaLookupValue> &values)
{
	std::wstring	  xml ;	// NVIDIA公式APIから受信するlookup XML。
	const NativeError error = client.getUtf8TextForSource(
		url, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, MAXIMUM_METADATA_BYTES, xml) ;	// HTTP結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 公式lookup XMLを解析できなければmetadata失敗として返す。
	if( !parseNvidiaLookupXml( xml, values)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local product名に対応するNVIDIA series/product IDを探す。
 *
 * 表示名の記号差だけを正規化し、部分一致で別製品を選ばない。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] model SetupAPIが返したNVIDIA device名。
 * @param[out] identity 成功時のNVIDIA series/product ID。
 * @return 完全一致時は0、未検出または取得失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError findNvidiaProduct( OfficialHttpClient	   &client,
											const std::wstring_view model,
											NvidiaProductIdentity  &identity)
{
	const std::wstring				modelKey = productMatchKey( model) ;	// Local product完全一致key。
	NativeError						firstError{} ;							// 複数type照会中の最初の診断error。
	const std::vector<std::wstring> typeIds = productTypeIds( model) ;		// Product type優先順。
	// NVIDIA product typeごとにseriesとproductを照会する。
	for( const std::wstring &typeId : typeIds) {
		const std::wstring seriesUrl =	// 指定product typeの公式series lookup URL。
			L"https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=" +
			typeId ;
		std::vector<NvidiaLookupValue> series ;										// Product type配下のseries群。
		const NativeError seriesError = fetchLookup( client, seriesUrl, series) ;	// 取得結果。
		// series照会失敗を記録し、他の既定typeの照会を続ける。
		if( seriesError != 0) {
			// 複数の失敗で最初の原因を失わないよう、診断値が未記録の場合だけ保存する。
			if( firstError == 0) {
				firstError = seriesError ;
			}

			continue ;
		}

		prioritizeSeries( model, series) ;
		// seriesの照会数を上限へ制限する。
		if( series.size() > MAXIMUM_SERIES_QUERIES) {
			series.resize( MAXIMUM_SERIES_QUERIES) ;
		}

		// 優先順にseries product listを取得し、local product名の完全一致を探す。
		for( const NvidiaLookupValue &seriesValue : series) {
			const std::wstring productsUrl =	// 指定seriesの公式product lookup URL。
				L"https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=" +
				seriesValue.value ;
			std::vector<NvidiaLookupValue> products ;										// Series配下のproduct群。
			const NativeError productsError = fetchLookup( client, productsUrl, products) ;	// 結果。
			// product照会失敗を記録し、別seriesの照会を続ける。
			if( productsError != 0) {
				// 複数の失敗で最初の原因を失わないよう、診断値が未記録の場合だけ保存する。
				if( firstError == 0) {
					firstError = productsError ;
				}

				continue ;
			}

			// Product表示名の記号差だけを除いて完全一致させる。
			for( const NvidiaLookupValue &product : products) {
				// 正規化製品名が完全一致した場合だけ公式seriesとproduct IDを採用する。
				if( productMatchKey( product.name) == modelKey) {
					identity.seriesId  = seriesValue.value ;
					identity.productId = product.value ;
					identity.notebook  = isNvidiaNotebookProduct( product.name, seriesValue.name) ;
					return 0 ;
				}
			}
		}
	}

	return firstError != 0 ? firstError : nativeErrorFromWin32( ERROR_NOT_FOUND) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実行中Windowsに対応するNVIDIA OS IDを取得する。
 *
 * RtlGetVersionで実buildを取得し、manifest依存のversion lieを避ける。
 * @return Windows 11は`135`、Windows 10は`57`。対象外は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring nvidiaWindowsOsId()
{
	HMODULE ntdll = GetModuleHandleW( L"ntdll.dll") ;	// Process lifetime中有効な非所有module。
	// OS版照会に必要なmoduleがなければOS IDを推測しない。
	if( ntdll == nullptr) {
		return {} ;
	}

	using RtlGetVersionFunction = LONG( WINAPI *)( PRTL_OSVERSIONINFOW) ;	// NTDLL API signature。
	// GetProcAddressはFARPROCを返すため、文書化済みsignatureへWin32境界でだけ変換する。
	const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
		// 実OS version取得関数。
		GetProcAddress( ntdll, "RtlGetVersion")) ;
	// OS版取得関数を解決できなければOS IDを返さない。
	if( rtlGetVersion == nullptr) {
		return {} ;
	}

	RTL_OSVERSIONINFOW version{} ;	// RtlGetVersionが設定する実OS version。
	version.dwOSVersionInfoSize = sizeof( version) ;
	// OS版の取得失敗や対象外major versionから対応OSを推測しない。
	if( rtlGetVersion( &version) != 0 || version.dwMajorVersion != 10) {
		return {} ;
	}

	return version.dwBuildNumber >= 22'000 ? L"135" : L"57" ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA channelのdriver releaseを公式APIから取得する。
 *
 * Windows x64 DCHのWHQL releaseを最大10件取得する。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] product NVIDIA series/product ID。
 * @param[in] osId NVIDIA Windows OS ID。
 * @param[in] studio trueの場合はStudio channel。
 * @param[out] entries 成功時のrelease群。
 * @return 取得・parse成功時は0、失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError fetchNvidiaReleases( OfficialHttpClient		  &client,
											  const NvidiaProductIdentity &product,
											  const std::wstring_view osId, const bool studio,
											  std::vector<NvidiaDriverEntry> &entries)
{
	const std::wstring url =	// NVIDIA DriverManualLookup API URL。
		L"https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/"
		L"AjaxDriverService.php?func=DriverManualLookup&psid=" +
		product.seriesId + L"&pfid=" + product.productId + L"&osID=" + std::wstring( osId) +
		L"&languageCode=1033&beta=0&isWHQL=1&dltype=-1&dch=1&upCRD=" + (studio ? L"1" : L"0") +
		L"&qnf=0&sort1=0&numberOfResults=10" ;
	std::wstring	  json ;	// NVIDIA公式APIから受信するdriver JSON。
	const NativeError error = client.getUtf8TextForSource(
		url, OFFICIAL_SECONDARY_METADATA_RESOURCE_ID, MAXIMUM_METADATA_BYTES, json) ;	// HTTP結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// driver JSONの解析失敗を候補なしとして返さない。
	if( !parseNvidiaDriverJson( json, entries)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 一channelで保持するrelease数を上限へ制限する。
	if( entries.size() > MAXIMUM_RELEASES_PER_CHANNEL) {
		entries.resize( MAXIMUM_RELEASES_PER_CHANNEL) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dotted versionを比較可能な数値componentへ分解する。
 *
 * Version表示以外のrankには使用せず、同一NVIDIA channel内のupdate/downgrade表示分類だけに使用する。
 *
 * @param[in] version Dot区切りのASCII数字version。
 * @return 1～8 componentの数値列。不正時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::vector<std::uint32_t>> parseVersion(
	const std::wstring_view version)
{
	// 空の版や末尾が空要素の版を比較対象にしない。
	if( version.empty() || version.back() == L'.') {
		return std::nullopt ;
	}

	std::vector<std::uint32_t> components ;	// 解析済みversion component群。
	std::size_t				   begin{} ;	// 現在componentの先頭位置。
	// 最大8要素までの版をdot境界ごとに解析する。
	while( begin < version.size() && components.size() < 8) {
		const std::size_t		end	 = version.find( L'.', begin) ;	// Component終端またはnpos。
		const std::wstring_view part =								// 現在の数字component。
			version.substr( begin,
						   end == std::wstring_view::npos ? version.size() - begin : end - begin) ;
		// 空または10桁を超える版要素を拒否する。
		if( part.empty() || part.size() > 10) {
			return std::nullopt ;
		}

		std::uint64_t number{} ;	// Overflow検出用64-bit component値。
		// 桁数制限済みの版要素を数値へ変換する。
		for( const wchar_t character : part) {
			// 10進数字以外を版要素として受理しない。
			if( character < L'0' || character > L'9') {
				return std::nullopt ;
			}

			number = number * 10 + static_cast<std::uint64_t>( character - L'0') ;
			// 版要素の値が32-bit範囲を超えた場合は拒否する。
			if( number > std::numeric_limits<std::uint32_t>::max()) {
				return std::nullopt ;
			}
		}

		components.push_back( static_cast<std::uint32_t>( number)) ;
		// 最後の要素まで消費したことを記録する。
		if( end == std::wstring_view::npos) {
			begin = version.size() ;
		} else {
			begin = end + 1 ;
		}
	}

	// 要素上限による未消費部分や空の解析結果を拒否する。
	if( begin < version.size() || components.empty()) {
		return std::nullopt ;
	}

	return components ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA表示versionを比較する。
 *
 * UI操作分類だけに使い、Windowsのdriver rankを置き換えない。
 *
 * @param[in] left Candidate NVIDIA version。
 * @param[in] right 現在のNVIDIA version。
 * @return leftが新しければ1、同じなら0、古ければ-1。解析不能は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] int compareVersions( const std::wstring_view left, const std::wstring_view right)
{
	const std::optional<std::vector<std::uint32_t>> leftParts  = parseVersion( left) ;	// 左辺。
	const std::optional<std::vector<std::uint32_t>> rightParts = parseVersion( right) ;	// 右辺。
	// 数値化できない版から大小関係を推測しない。
	if( !leftParts.has_value() || !rightParts.has_value()) {
		return 0 ;
	}

	const std::size_t count = std::max( leftParts->size(), rightParts->size()) ;	// 比較桁数。
	// 不足要素を0として同じ位置の数値を順に比較する。
	for( std::size_t index = 0; index < count; ++index) {
		// 比較する左版数の現在成分。省略された末尾成分は0。
		const std::uint32_t leftValue = index < leftParts->size() ? (*leftParts)[index] : 0 ;
		// 比較する右版数の現在成分。省略された末尾成分は0。
		const std::uint32_t rightValue = index < rightParts->size() ? (*rightParts)[index] : 0 ;
		// 最初に異なる要素で版の大小を確定する。
		if( leftValue != rightValue) {
			return leftValue > rightValue ? 1 : -1 ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Candidate versionからdriver操作分類を決定する。
 *
 * 数値比較不能時は優劣を推測せずReinstallとして表示する。
 *
 * @param[in] candidate NVIDIA candidate version。
 * @param[in] current 現在のNVIDIA表示version。
 * @return Update、Reinstall、Downgradeのいずれか。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyNvidiaAction( const std::wstring_view candidate,
												const std::wstring_view current)
{
	const int comparison = compareVersions( candidate, current) ;	// Version比較結果。
	// 候補版が現在版を上回る場合だけ通常更新に分類する。
	if( comparison > 0) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版を下回る場合は旧版への切替として区別する。
	if( comparison < 0) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA英語release日付をYYYY/MM/DDへ変換する。
 *
 * UI sortを安定させるためlocale非依存で英語月名を変換する。
 *
 * @param[in] value `Wed Aug 26, 2026`形式の日付。
 * @return 変換できた日付。不正時は元文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatReleaseDate( const std::wstring_view value)
{
	std::vector<std::wstring_view> tokens ;		// 空白で分割した日付token群。
	std::size_t					   position{} ;	// 次tokenの検索位置。
	// 日付文字列を有限個の空白区切りtokenへ分解する。
	while( position < value.size()) {
		// token間の空白だけを入力範囲内で読み飛ばす。
		while( position < value.size() && std::iswspace( value[position]) != 0) {
			++position ;
		}

		const std::size_t begin = position ;	// Token先頭位置。
		// 次の空白または入力末尾までを日付tokenとして読む。
		while( position < value.size() && std::iswspace( value[position]) == 0) {
			++position ;
		}

		// 空でない日付tokenだけを保持する。
		if( begin < position) {
			tokens.push_back( value.substr( begin, position - begin)) ;
		}
	}

	// 既知の4要素日付でなければ元の表示を保持する。
	if( tokens.size() != 4) {
		return std::wstring( value) ;
	}

	// 公式日付の英語月名を月番号へ変換する固定対応。
	constexpr std::array<std::wstring_view, 12> MONTHS{L"Jan", L"Feb", L"Mar", L"Apr",
													   L"May", L"Jun", L"Jul", L"Aug",
													   L"Sep", L"Oct", L"Nov", L"Dec"} ;
	const auto monthIterator = std::find( MONTHS.begin(), MONTHS.end(), tokens[1]) ;	// 月位置。
	// 月名が既知表記に合わなければ日付を推測変換しない。
	if( monthIterator == MONTHS.end()) {
		return std::wstring( value) ;
	}

	std::wstring day( tokens[2]) ;	// Commaを除去する日文字列。
	// 日付表現の末尾commaだけを日数から取り除く。
	if( !day.empty() && day.back() == L',') {
		day.pop_back() ;
	}

	// 日と年の数値形式が不正なら原文表示を維持する。
	if( day.empty() || day.size() > 2 || tokens[3].size() != 4 ||
	   !std::all_of(
		   day.begin(), day.end(),
		   []( const wchar_t character) { return character >= L'0' && character <= L'9' ; }) ||
	   !std::all_of( tokens[3].begin(), tokens[3].end(), []( const wchar_t character) {
		   return character >= L'0' && character <= L'9' ;
	   })) {
		return std::wstring( value) ;
	}

	// 一桁の日を表示用の2桁へ揃える。
	if( day.size() == 1) {
		day.insert( day.begin(), L'0') ;
	}

	const std::size_t monthIndex =	// 0-based月位置。
		static_cast<std::size_t>( std::distance( MONTHS.begin(), monthIterator)) ;
	// 日付表示へ組み込む、二桁に整えた月番号。
	const std::wstring month = monthIndex + 1 < 10 ? L"0" + std::to_wstring( monthIndex + 1)
												   : std::to_wstring( monthIndex + 1) ;
	return std::wstring( tokens[3]) + L"/" + month + L"/" + day ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA表示file sizeをbyte数へ変換する。
 *
 * 小数3桁までを整数演算し、overflow時は0を返す。
 *
 * @param[in] value `984.3 MB`等の表示値。
 * @return 変換できた概算byte数。不正時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t parseDownloadSize( const std::wstring_view value) noexcept
{
	const std::size_t space = value.find( L' ') ;	// 数値と単位の区切り位置。
	// 数値と単位の区切りがなければbyte数を推測しない。
	if( space == std::wstring_view::npos) {
		return 0 ;
	}

	const std::wstring_view number = value.substr( 0, space) ;	// 小数を含む数値部。
	const std::wstring_view unit   = value.substr( space + 1) ;	// Size単位。
	std::uint64_t			multiplier{} ;						// 単位あたりbyte数。
	// KB表示に対応するbyte換算係数を使う。
	if( unit == L"KB") {
		multiplier = 1024 ;
	}
	// MB表示に対応するbyte換算係数を使う。
	else if( unit == L"MB") {
		multiplier = 1024U * 1024U ;
	}
	// GB表示に対応するbyte換算係数を使う。
	else if( unit == L"GB") {
		multiplier = 1024ULL * 1024ULL * 1024ULL ;
	} else {
		return 0 ;
	}

	const std::size_t		dot	  = number.find( L'.') ;		// 小数点位置。
	const std::wstring_view whole = number.substr( 0, dot) ;	// 整数部。
	const std::wstring_view fraction =
		// 小数部。
		dot == std::wstring_view::npos ? std::wstring_view{} : number.substr( dot + 1) ;
	// 整数部欠落や許可精度を超えるsize表示を拒否する。
	if( whole.empty() || fraction.size() > 3) {
		return 0 ;
	}

	std::uint64_t wholeValue{} ;	// 整数部数値。
	// 整数部をoverflowと取得上限を確認しながら数値化する。
	for( const wchar_t character : whole) {
		// size整数部に数字以外を許容しない。
		if( character < L'0' || character > L'9') {
			return 0 ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// size整数部の64-bit overflowを桁追加前に検出する。
		if( wholeValue > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return 0 ;
		}

		wholeValue = wholeValue * 10 + digit ;
		// 単位換算後にinstaller上限を超えるsizeを拒否する。
		if( wholeValue > MAXIMUM_INSTALLER_BYTES / multiplier) {
			return 0 ;
		}
	}

	std::uint64_t fractionValue{} ;		// 小数部数値。
	std::uint64_t fractionScale{1} ;	// 小数部の10進scale。
	// 上限付き小数部を整数と10進scaleへ分けて変換する。
	for( const wchar_t character : fraction) {
		// size小数部に数字以外を許容しない。
		if( character < L'0' || character > L'9') {
			return 0 ;
		}

		fractionValue = fractionValue * 10 + static_cast<std::uint64_t>( character - L'0') ;
		fractionScale *= 10 ;
	}

	return wholeValue * multiplier +
		   (fraction.empty() ? 0 : fractionValue * multiplier / fractionScale) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NvidiaUpdateProvider::NvidiaUpdateProvider( const bool useCatalogCache) noexcept
	: httpClient_( useCatalogCache)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring nvidiaProductGenerationKey( const std::wstring_view model)
{
	const std::wstring normalized = normalizeProductName( model) ;	// 世代抽出用product名。
	// 世代hintを抽出する既知製品family。適用性の除外には使用しない。
	constexpr std::array<std::wstring_view, 5> PREFIXES{L"RTX", L"GTX", L"MX", L"GT", L"NVS"} ;
	// Known family prefix直後のmodel番号を探す。
	for( const std::wstring_view prefix : PREFIXES)	// 現在照合中の製品family。
	{
		const std::size_t prefixPosition = normalized.find( prefix) ;	// Family prefix位置。
		// 製品名に含まれない系列prefixを世代判定から除外する。
		if( prefixPosition == std::wstring::npos) {
			continue ;
		}

		const std::size_t numberBegin = prefixPosition + prefix.size() ;	// Model番号先頭。
		std::size_t		  numberEnd	  = numberBegin ;						// Model番号直後。
		// Family直後の連続数字だけを有限に読み、世代hintへ縮約する。
		while( numberEnd < normalized.size() && normalized[numberEnd] >= L'0' &&
			  normalized[numberEnd] <= L'9') {
			++numberEnd ;
		}

		const std::wstring number =	// 切出し文字列を所有し、一時値への参照を残さない。
			normalized.substr( numberBegin, numberEnd - numberBegin) ;
		// 4桁以上の製品番号では先頭2桁をseries照会用の世代keyに使う。
		if( number.size() >= 4) {
			return std::wstring( prefix) + std::wstring( number.substr( 0, 2)) ;
		}

		// 3桁の製品番号では百番台をseries照会用の世代keyに使う。
		if( number.size() == 3) {
			return std::wstring( prefix) + std::wstring( 1, number.front()) + L"00" ;
		}
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isNvidiaNotebookProduct( const std::wstring_view productName,
							 const std::wstring_view seriesName)
{
	const std::wstring productKey = normalizeProductName( productName) ;	// Product照合key。
	const std::wstring seriesKey  = normalizeProductName( seriesName) ;		// Series照合key。
	return productKey.find( L"NOTEBOOK") != std::wstring::npos ||
		   productKey.find( L"LAPTOP") != std::wstring::npos ||
		   seriesKey.find( L"NOTEBOOK") != std::wstring::npos ||
		   seriesKey.find( L"LAPTOP") != std::wstring::npos ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring nvidiaVersionFromWindowsVersion( const std::wstring_view windowsVersion)
{
	const std::optional<std::vector<std::uint32_t>> parts =	// Windows version component群。
		parseVersion( windowsVersion) ;
	// 4要素のWindows driver版を得られなければ表示版を推測しない。
	if( !parts.has_value() || parts->size() != 4) {
		return {} ;
	}

	const std::wstring encoded =	// NVIDIA表示versionを含む末尾component連結値。
		std::to_wstring( (*parts)[2]) + std::to_wstring( (*parts)[3]) ;
	// 表示版を取り出すための桁数が不足する値を拒否する。
	if( encoded.size() < 5) {
		return {} ;
	}

	const std::wstring digits = encoded.substr( encoded.size() - 5) ;	// `xxxyy`表示version数字列。
	std::wstring	   major  = digits.substr( 0, 3) ;					// 小数点前のversion。
	// 表示版のmajor部分は一桁を残して先頭0を除く。
	while( major.size() > 1 && major.front() == L'0') {
		major.erase( major.begin()) ;
	}

	return major + L"." + digits.substr( 3) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult NvidiaUpdateProvider::scan( const ScanSessionId						   scanSessionId,
									  const std::span<const OfficialCatalogDevice> devices,
									  const LocalHardwareIdMatcher	 &hardwareIdMatcher,
									  const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	invalidateScanSession() ;
	ScanResult result ;	// NVIDIA公式catalogのscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	// 無効なscan sessionで候補を保持しない。
	if( scanSessionId == 0) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	std::vector<OfficialCatalogDevice> nvidiaDevices ;	// NVIDIA製と判定できた現在device群。
	// Display classかつmanufacturerまたはmodelがNVIDIAと示すdeviceだけをlookup対象にする。
	for( const OfficialCatalogDevice &device : devices) {
		const std::wstring manufacturer = normalizeProductName( device.manufacturer) ;	// 製造元key。
		const std::wstring model		= normalizeProductName( device.model) ;			// Model key。
		// Braceとhyphenを除いたsetup class GUID。
		const std::wstring classGuid  = normalizeProductName( device.deviceClassGuid) ;
		const bool		   nvidiaName =	// NVIDIA display productと判断できる表示名条件。
			manufacturer.find( L"NVIDIA") != std::wstring::npos ||
			model.find( L"NVIDIA") != std::wstring::npos ||
			model.find( L"GEFORCE") != std::wstring::npos ||
			model.find( L"QUADRO") != std::wstring::npos ;
		// Display classとNVIDIA名の両方が一致するdeviceだけを検索対象へ集める。
		if( classGuid == DISPLAY_CLASS_GUID_KEY && nvidiaName) {
			nvidiaDevices.push_back( device) ;
		}
	}

	result.coverage.eligibleDeviceCount = nvidiaDevices.size() ;
	progressCallback( {.stage		  = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .completedItems = 0,
					  .totalItems	  = nvidiaDevices.size()}) ;
	// 対象deviceがなければ対象外として検索を完了する。
	if( nvidiaDevices.empty()) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	const std::wstring osId = nvidiaWindowsOsId() ;	// NVIDIA APIの対象Windows ID。
	// 公式OS IDを決定できないWindowsで検索条件を推測しない。
	if( osId.empty()) {
		result.error = nativeErrorFromWin32( ERROR_OLD_WIN_VERSION) ;
		return result ;
	}

	const NativeError sourceSessionError =
		// 監査session開始結果。
		httpClient_.beginSourceSession( scanSessionId, NVIDIA_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( sourceSessionError != 0) {
		result.error = sourceSessionError ;
		return result ;
	}

	const NativeError invalidMetadataError =	// Parserが返すmetadata拒否code。
		nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	const NativeError productNotFoundError =	// Lookup成立後に完全一致しなかったcode。
		nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	NativeError firstError{} ;			// 一部device失敗時に返す最初の診断error。
	std::size_t succeededDevices{} ;	// Catalog検索または対象外判定が成立したdevice数。
	bool		metadataRejected{} ;	// 全失敗時にschema拒否を区別するflag。
	// NVIDIA deviceごとにproduct IDを特定して両driver channelを取得する。
	for( std::size_t deviceIndex = 0; deviceIndex < nvidiaDevices.size(); ++deviceIndex) {
		const OfficialCatalogDevice &device = nvidiaDevices[deviceIndex] ;	// 現在検索中device。
		NvidiaProductIdentity		 product ;								// 公式lookupで特定するseries/product ID。
		// Local製品表示名を公式製品定義へ照合した結果。
		const NativeError productError = findNvidiaProduct( httpClient_, device.model, product) ;
		// 製品照合失敗を分類して現在deviceの処理を終了する。
		if( productError != 0) {
			// 照会成功後の製品不一致は通信失敗と区別して処理済みに数える。
			if( productError == productNotFoundError) {
				// 公式lookupが成立して完全一致製品がない場合は通信失敗にしない。
				++succeededDevices ;
			} else {
				metadataRejected = metadataRejected || productError == invalidMetadataError ;
				// 複数の失敗で最初の原因を失わないよう、診断値が未記録の場合だけ保存する。
				if( firstError == 0) {
					firstError = productError ;
				}
			}

			const std::uint64_t completed = deviceIndex + 1 ;	// 完了扱いにするdevice数。
			progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
							  .percentComplete = static_cast<std::uint32_t>( completed * 100 /
																			nvidiaDevices.size()),
							  .completedItems  = completed,
							  .totalItems	   = nvidiaDevices.size()}) ;
			continue ;
		}

		std::vector<NvidiaDriverEntry> gameReady ;	// Game Ready release群。
		std::vector<NvidiaDriverEntry> studio ;		// Studio release群。
		const NativeError			   gameError =	// Game Ready検索結果。
			fetchNvidiaReleases( httpClient_, product, osId, false, gameReady) ;
		const NativeError studioError =	// Studio検索結果。
			fetchNvidiaReleases( httpClient_, product, osId, true, studio) ;
		// 両channelの取得失敗時は診断を残し、現在deviceから候補を作らない。
		if( gameError != 0 && studioError != 0) {
			metadataRejected = metadataRejected || gameError == invalidMetadataError ||
							   studioError == invalidMetadataError ;
			// 複数の失敗で最初の原因を失わないよう、診断値が未記録の場合だけ保存する。
			if( firstError == 0) {
				firstError = gameError ;
			}

			const std::uint64_t completed = deviceIndex + 1 ;	// 完了扱いにするdevice数。
			progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
							  .percentComplete = static_cast<std::uint32_t>( completed * 100 /
																			nvidiaDevices.size()),
							  .completedItems  = completed,
							  .totalItems	   = nvidiaDevices.size()}) ;
			continue ;
		}

		// 片方のchannelだけの失敗も最初の診断として保持する。
		if( firstError == 0 && (gameError != 0 || studioError != 0)) {
			firstError = gameError != 0 ? gameError : studioError ;
		}

		++succeededDevices ;

		const std::wstring currentVersion =	// NVIDIA表示形式へ変換した現在版。
			nvidiaVersionFromWindowsVersion( device.currentVersion) ;
		std::unordered_set<std::wstring> releaseIds ;		// Channel間のdownload ID重複排除集合。
		std::size_t						 releaseOrdinal{} ;	// Device内candidate identity用連番。
		auto appendReleases = [&]( std::vector<NvidiaDriverEntry> &entries,
								  const bool					  channelStudio) {
			bool primaryUpdateSeen{} ;	// このchannelで先頭の通常更新を処理済みの場合true。
			// API順を維持し、activeなWHQL Windows x64 releaseを候補へ変換する。
			for( NvidiaDriverEntry &entry : entries) {
				// 非active、非WHQL、非x64、重複releaseを候補から除外する。
				if( !entry.active || !entry.whql || !entry.x64 ||
				   !releaseIds.insert( entry.id).second) {
					continue ;
				}

				const DriverAction action =	// 現在版に対する操作分類。
					classifyNvidiaAction( entry.version, currentVersion) ;
				const bool primaryUpdate =	// Game Ready内の先頭通常更新の場合true。
					!channelStudio && !primaryUpdateSeen && action == DriverAction::UPDATE ;
				UpdateCandidate candidate ;	// UIへ渡すNVIDIA公式release候補。
				candidate.identity = L"nvidia:" + std::to_wstring( scanSessionId) + L":" +
									 std::to_wstring( deviceIndex) + L":" +
									 std::to_wstring( releaseOrdinal++) ;
				candidate.deviceIdentity  = device.deviceIdentity ;
				candidate.providerId	  = std::wstring( NVIDIA_PROVIDER_ID) ;
				candidate.packageIdentity = L"nvidia-installer:" + entry.id ;
				candidate.title			  = entry.name + L" " + entry.version ;
				candidate.manufacturer =
					device.manufacturer.empty() ? L"NVIDIA" : device.manufacturer ;
				candidate.model			  = device.model ;
				candidate.driverClass	  = device.driverClass ;
				candidate.deviceClassGuid = device.deviceClassGuid ;
				candidate.provider		  = L"NVIDIA Corporation" ;
				candidate.version		  = entry.version ;
				candidate.driverDate	  = formatReleaseDate( entry.releaseDate) ;
				candidate.sourceName	  = L"NVIDIA 公式ドライバーカタログ" ;
				candidate.sourceLocation =
					product.notebook ? L"NVIDIA公式 HTTPS（Notebook向け、OEM固有構成は未検証）"
									 : L"NVIDIA公式 HTTPS（nvidia.com / download.nvidia.com）" ;
				candidate.maximumDownloadBytes = parseDownloadSize( entry.downloadSize) ;
				candidate.action			   = action ;
				candidate.defaultPreference	   = CandidateDefaultPreference::NONE ;
				candidate.discoveryBasis   = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
				candidate.audit			   = makeOfficialMetadataCandidateAudit() ;
				candidate.current		   = false ;
				candidate.recommended	   = false ;
				candidate.installable	   = false ;
				candidate.eulaAccepted	   = false ;
				candidate.allContentCached = false ;
				candidate.rebootMayBeRequired = true ;
				candidate.browseOnly		  = false ;
				primaryUpdateSeen			  = primaryUpdateSeen || primaryUpdate ;

				result.candidates.push_back( std::move( candidate)) ;
			}
		} ;
		appendReleases( gameReady, false) ;
		appendReleases( studio, true) ;

		const std::uint64_t completed = deviceIndex + 1 ;	// 検索完了device数。
		progressCallback(
			{.stage			  = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
			 .percentComplete = static_cast<std::uint32_t>( completed * 100 / nvidiaDevices.size()),
			 .completedItems  = completed,
			 .totalItems	  = nvidiaDevices.size()}) ;
	}

	result.coverage.assessedDeviceCount = succeededDevices ;
	// 成功したdevice検索が一件もなければ候補とsessionを破棄する。
	if( succeededDevices == 0) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		// 全件失敗にmetadata不正を含む場合は拒否状態を明示する。
		if( metadataRejected) {
			result.state = ProviderScanState::METADATA_REJECTED ;
		}

		result.error = firstError != 0 ? firstError : nativeErrorFromWin32( ERROR_NOT_FOUND) ;
		return result ;
	}

	// 候補がある場合は一次・二次metadata双方の公式取得証拠を要求する。
	if( !result.candidates.empty() &&
	   (!httpClient_.hasSourceEvidence( scanSessionId, NVIDIA_PROVIDER_ID,
									   OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
		!httpClient_.hasSourceEvidence( scanSessionId, NVIDIA_PROVIDER_ID,
									   OFFICIAL_SECONDARY_METADATA_RESOURCE_ID))) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.outcome = OutcomeCode::FAILURE ;
		result.state   = ProviderScanState::SOURCE_REJECTED ;
		result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
		return result ;
	}

	result.succeeded = true ;
	result.outcome	 = firstError == 0 ? OutcomeCode::SUCCESS : OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	result.error	 = firstError ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult NvidiaUpdateProvider::install( const ScanSessionId					scanSessionId,
											const std::span<const std::wstring> identities,
											const std::uintptr_t				parentWindowNative,
											const ProviderProgressCallback	   &progressCallback)
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
 * @see src/platform/nvidia_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void NvidiaUpdateProvider::invalidateScanSession() noexcept
{
	httpClient_.invalidateSourceSession() ;
}

} // namespace drivercrate
