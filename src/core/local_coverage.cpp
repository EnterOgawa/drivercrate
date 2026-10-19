//------------------------------------------------------------------------------
/**
 * @file local_coverage.cpp
 * @brief Local候補到達集計実装。
 * @version 01.01.01
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択package取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Manufacturer intake分類追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  準備後もscan時点の段階別計測を保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Opaque device identityを現在scan中の重複排除にだけ使用し、集計結果へ保持しません。候補到達件数はProviderの適用性判定率とは別の指標です。
 */
//------------------------------------------------------------------------------

#include "core/local_coverage.h"

#include "core/provider_registry.h"

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

// Windowsまたはinbox／generic表示としてS63+ manufacturer調査から除外する正規化名。
constexpr std::array PLATFORM_MANUFACTURER_ALIASES{
	std::wstring_view( L"GENERIC"),
	std::wstring_view( L"GENERICUSBAUDIO"),
	std::wstring_view( L"GENERICUSBHUB"),
	std::wstring_view( L"MICROSOFT"),
	std::wstring_view( L"MICROSOFTCORPORATION"),
	std::wstring_view( L"MICROSOFTWINDOWS"),
	std::wstring_view( L"STANDARD"),
	std::wstring_view( L"STANDARDIDEATAATAPICONTROLLERS"),
	std::wstring_view( L"STANDARDSYSTEMDEVICES"),
	std::wstring_view( L"STANDARDUSBHOSTCONTROLLER"),
	std::wstring_view( L"汎用USBオーディオ"),
	std::wstring_view( L"標準IDEATAATAPIコントローラー"),
	std::wstring_view( L"標準USBホストコントローラー"),
	std::wstring_view( L"標準システムデバイス"),
	std::wstring_view( L"標準の記憶域コントローラー"),
	std::wstring_view( L"標準モニターの種類")} ;

// S01～S62で審査したmanufacturerの表示名を端末内だけで照合する正規化alias。
constexpr std::array REVIEWED_MANUFACTURER_ALIASES{
	std::wstring_view( L"ACER"),
	std::wstring_view( L"ADVANCEDMICRODEVICESINC"),
	std::wstring_view( L"AMD"),
	std::wstring_view( L"AORUS"),
	std::wstring_view( L"APPLE"),
	std::wstring_view( L"APPLEINC"),
	std::wstring_view( L"ASMEDIA"),
	std::wstring_view( L"ASMEDIATECHNOLOGYINC"),
	std::wstring_view( L"ASROCK"),
	std::wstring_view( L"ASUS"),
	std::wstring_view( L"ASUSTEKCOMPUTERINC"),
	std::wstring_view( L"AVERMEDIA"),
	std::wstring_view( L"AVERMEDIATECHNOLOGIESINC"),
	std::wstring_view( L"AYANEO"),
	std::wstring_view( L"ATHEROS"),
	std::wstring_view( L"BEELINK"),
	std::wstring_view( L"BIOSTAR"),
	std::wstring_view( L"BLACKMAGICDESIGN"),
	std::wstring_view( L"BROADCOM"),
	std::wstring_view( L"BROADCOMINC"),
	std::wstring_view( L"BROTHER"),
	std::wstring_view( L"BROTHERINDUSTRIESLTD"),
	std::wstring_view( L"CANON"),
	std::wstring_view( L"CANONINC"),
	std::wstring_view( L"CHUWI"),
	std::wstring_view( L"CIRRUSLOGIC"),
	std::wstring_view( L"CLEVO"),
	std::wstring_view( L"CMEDIA"),
	std::wstring_view( L"CONEXANT"),
	std::wstring_view( L"CORSAIR"),
	std::wstring_view( L"CREATIVE"),
	std::wstring_view( L"CREATIVETECHNOLOGY"),
	std::wstring_view( L"CRUCIAL"),
	std::wstring_view( L"DATALOGIC"),
	std::wstring_view( L"DELL"),
	std::wstring_view( L"DELLCOMPUTERCORPORATION"),
	std::wstring_view( L"DELLINC"),
	std::wstring_view( L"DELLTECHNOLOGIES"),
	std::wstring_view( L"DLINK"),
	std::wstring_view( L"DISPLAYLINK"),
	std::wstring_view( L"DYMO"),
	std::wstring_view( L"DYNABOOK"),
	std::wstring_view( L"ECS"),
	std::wstring_view( L"ELAN"),
	std::wstring_view( L"ELANMICROELECTRONICSCORPORATION"),
	std::wstring_view( L"ELGATO"),
	std::wstring_view( L"EMULEX"),
	std::wstring_view( L"EPSON"),
	std::wstring_view( L"FOCUSRITE"),
	std::wstring_view( L"FRAMEWORK"),
	std::wstring_view( L"FRESCOLOGIC"),
	std::wstring_view( L"FTDI"),
	std::wstring_view( L"FTDICHIP"),
	std::wstring_view( L"FUJIFILM"),
	std::wstring_view( L"FUJIFILMBUSINESSINNOVATION"),
	std::wstring_view( L"FUJITSU"),
	std::wstring_view( L"GATEWAY"),
	std::wstring_view( L"GETAC"),
	std::wstring_view( L"GIGABYTE"),
	std::wstring_view( L"GOODIX"),
	std::wstring_view( L"GOOGLE"),
	std::wstring_view( L"GOOGLELLC"),
	std::wstring_view( L"GPD"),
	std::wstring_view( L"HONEYWELL"),
	std::wstring_view( L"HONOR"),
	std::wstring_view( L"HP"),
	std::wstring_view( L"HPINC"),
	std::wstring_view( L"HPE"),
	std::wstring_view( L"HUAWEI"),
	std::wstring_view( L"HEWLETTPACKARD"),
	std::wstring_view( L"HEWLETTPACKARDCOMPANY"),
	std::wstring_view( L"IIYAMA"),
	std::wstring_view( L"INTEL"),
	std::wstring_view( L"INTELCORPORATION"),
	std::wstring_view( L"INTELRCORPORATION"),
	std::wstring_view( L"KIOXIA"),
	std::wstring_view( L"KONICAMINOLTA"),
	std::wstring_view( L"KYOCERA"),
	std::wstring_view( L"LENOVO"),
	std::wstring_view( L"LEXMARK"),
	std::wstring_view( L"LG"),
	std::wstring_view( L"LGELECTRONICS"),
	std::wstring_view( L"LOGI"),
	std::wstring_view( L"LOGITECH"),
	std::wstring_view( L"MARVELL"),
	std::wstring_view( L"MEDIATEK"),
	std::wstring_view( L"MEDION"),
	std::wstring_view( L"MICROCHIP"),
	std::wstring_view( L"MICROCHIPTECHNOLOGYINC"),
	std::wstring_view( L"MICRON"),
	std::wstring_view( L"MINISFORUM"),
	std::wstring_view( L"MSI"),
	std::wstring_view( L"MOUSECOMPUTER"),
	std::wstring_view( L"NATIVEINSTRUMENTS"),
	std::wstring_view( L"NEC"),
	std::wstring_view( L"NETGEAR"),
	std::wstring_view( L"NVIDIA"),
	std::wstring_view( L"NVIDIACORPORATION"),
	std::wstring_view( L"NZXT"),
	std::wstring_view( L"OKI"),
	std::wstring_view( L"ONENETBOOK"),
	std::wstring_view( L"ONEXPLAYER"),
	std::wstring_view( L"ORACLE"),
	std::wstring_view( L"ORIGINCORP"),
	std::wstring_view( L"ORIGINPC"),
	std::wstring_view( L"PANASONIC"),
	std::wstring_view( L"PARALLELS"),
	std::wstring_view( L"PFU"),
	std::wstring_view( L"PRESONUS"),
	std::wstring_view( L"PROLIFIC"),
	std::wstring_view( L"PROLIFICTECHNOLOGYINC"),
	std::wstring_view( L"QLOGIC"),
	std::wstring_view( L"QUALCOMM"),
	std::wstring_view( L"QUALCOMMATHEROS"),
	std::wstring_view( L"QUMRANET"),
	std::wstring_view( L"RALINK"),
	std::wstring_view( L"RAZER"),
	std::wstring_view( L"REALTEK"),
	std::wstring_view( L"REALTEKSEMICONDUCTORCORP"),
	std::wstring_view( L"REDHAT"),
	std::wstring_view( L"REDMI"),
	std::wstring_view( L"RICOH"),
	std::wstring_view( L"ROLAND"),
	std::wstring_view( L"SAMSUNG"),
	std::wstring_view( L"SAMSUNGELECTRONICS"),
	std::wstring_view( L"SATO"),
	std::wstring_view( L"SCHENKER"),
	std::wstring_view( L"SEAGATE"),
	std::wstring_view( L"SHARP"),
	std::wstring_view( L"SHUTTLE"),
	std::wstring_view( L"SILICONLABORATORIES"),
	std::wstring_view( L"SILICONLABORATORIESINC"),
	std::wstring_view( L"SKHYNIX"),
	std::wstring_view( L"SOLIDIGM"),
	std::wstring_view( L"STEELSERIES"),
	std::wstring_view( L"STEINBERG"),
	std::wstring_view( L"SUPERMICRO"),
	std::wstring_view( L"SYNAPTICS"),
	std::wstring_view( L"THIRDWAVE"),
	std::wstring_view( L"TOSHIBA"),
	std::wstring_view( L"TOSHIBATEC"),
	std::wstring_view( L"TONGFANG"),
	std::wstring_view( L"TPLINK"),
	std::wstring_view( L"TURTLEBEACH"),
	std::wstring_view( L"TYAN"),
	std::wstring_view( L"VAIO"),
	std::wstring_view( L"VALVE"),
	std::wstring_view( L"VIRTUALBOX"),
	std::wstring_view( L"VMWARE"),
	std::wstring_view( L"WACOM"),
	std::wstring_view( L"WCH"),
	std::wstring_view( L"WESTERNDIGITAL"),
	std::wstring_view( L"XEROX"),
	std::wstring_view( L"XIAOMI"),
	std::wstring_view( L"XMG"),
	std::wstring_view( L"YAMAHA"),
	std::wstring_view( L"ZEBRA"),
	std::wstring_view( L"ZOTAC")} ;

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief Candidate取得元のtrust boundaryを集計列へ対応付ける。
 */
enum class CoverageSource {
	/// Windows Updateまたは管理service。
	MANAGED,
	/// Hardware maker公式network。
	OFFICIAL,
	/// 利用者が明示したlocal package。
	USER_SELECTED,
	/// Local Driver Store。
	LOCAL,
	/// 署名索引の収集者確認。Live公式探索やWUAの保証ではありません。
	INDEXED,
} ;

/**
 * @brief 一つの表示groupと重複排除用device集合を保持する。
 */
struct CoverageState {
	/// UIへ返すmanufacturer／class別集計値。
	LocalCoverageEntry				 entry ;
	/// 任意取得元候補が届いたdevice集合。
	std::unordered_set<std::wstring> candidateDevices ;
	/// 管理service候補が届いたdevice集合。
	std::unordered_set<std::wstring> managedDevices ;
	/// 公式network候補が届いたdevice集合。
	std::unordered_set<std::wstring> officialDevices ;
	/// 利用者選択候補のdevice集合。
	std::unordered_set<std::wstring> userSelectedDevices ;
	/// Driver Store別版が届いたdevice集合。
	std::unordered_set<std::wstring> localDevices ;
	/// 索引由来の実公開候補だけが到達したdevice集合。
	std::unordered_set<std::wstring> indexedDevices ;
	/// 取得前または非適用の非導入索引参照集合。
	std::unordered_set<std::wstring> indexedReferences ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Manufacturer表示名を比較用keyへ正規化する。
 *
 * Alias完全一致の表記差吸収にだけ使用する。非ASCII文字は推測変換せず保持し、Hardware ID等を入力へ追加しない。
 *
 * @param[in] manufacturer Windowsが返した表示用manufacturer名。
 * @return ASCII英字を大文字化し、ASCII記号と空白を除いた端末内key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeManufacturerKey( const std::wstring_view manufacturer)
{
	std::wstring key ;	// 本呼出し内だけで保持するmanufacturer比較key。
	key.reserve( manufacturer.size()) ;
	// ASCII英数字と非ASCII文字だけを保持し、会社名の句読点と空白差を吸収する。
	for( const wchar_t character : manufacturer) {
		// ASCIIの大文字小文字による表示名の揺れを、比較用keyだけで吸収する。
		if( character >= L'a' && character <= L'z') {
			key.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 正規化済みの英大文字と数字は保持し、メーカー名の識別に必要な文字を残す。
		else if( (character >= L'A' && character <= L'Z') ||
				(character >= L'0' && character <= L'9')) {
			key.push_back( character) ;
		}
		// ASCII外のメーカー名は保持しつつ、区切り用の全角空白を比較から除く。
		else if( character > 0x7f && character != L'\u3000') {
			key.push_back( character) ;
		}
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正規化manufacturerが明示alias表に含まれるか確認する。
 *
 * Fuzzy matchや部分一致で会社を推測せず、誤一致を防ぐ。
 *
 * @tparam Size 正規化済みalias固定表の要素数。全要素を完全一致で照合する。
 * @param[in] aliases Source review済みの正規化alias固定表。
 * @param[in] key 正規化済みmanufacturer比較key。
 * @return 完全一致するaliasがある場合は`true`、ない場合は`false`。
 */
//------------------------------------------------------------------------------
template <std::size_t Size>
[[nodiscard]] bool containsManufacturerAlias( const std::array<std::wstring_view, Size> &aliases,
											 const std::wstring_view key) noexcept
{
	return std::ranges::find( aliases, key) != aliases.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider capabilityから単一のcoverage取得元を解決する。
 *
 * 候補件数を誤ったtrust boundaryへ表示しないため、capabilityの矛盾をfail-closedで拒否する。
 *
 * @param[in] provider Registryが保持するProvider定義。
 * @return Trust boundaryが一意な場合は対応する取得元。未分類または複数分類の場合は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<CoverageSource> resolveCoverageSource(
	const ProviderDescriptor &provider)
{
	const bool managed =	// trueの場合は管理service境界を使用するProvider。
		(provider.capabilities & capabilityMask( ProviderCapability::MANAGED_SERVICE)) != 0 ;
	const bool official =	// trueの場合はhardware maker公式network Provider。
		(provider.capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0 ;
	const bool local =	// trueの場合はlocal inventory Provider。
		(provider.capabilities & capabilityMask( ProviderCapability::LOCAL_INVENTORY)) != 0 ;
	const bool userSelected =	// trueの場合は利用者選択file Provider。
		(provider.capabilities & capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0 ;
	const bool indexed =	// 収集者確認の独立境界。
		(provider.capabilities & capabilityMask( ProviderCapability::SIGNED_INDEX_ACQUISITION)) != 0 ;
	const unsigned int sourceCount =
		static_cast<unsigned int>( managed) + static_cast<unsigned int>( official) +
		static_cast<unsigned int>( local) +
		// 有効な境界分類数。
		static_cast<unsigned int>( userSelected) + static_cast<unsigned int>( indexed) ;
	// 取得元が一種類に定まらないProviderは、件数を任意の分類へ配分しない。
	if( sourceCount != 1U) {
		return std::nullopt ;
	}

	// 管理serviceの候補到達数を、公式catalogやlocalの件数から分離する。
	if( managed) {
		return CoverageSource::MANAGED ;
	}

	// 公式networkの候補到達数を、Windows管理serviceの合格と混同しない。
	if( official) {
		return CoverageSource::OFFICIAL ;
	}

	// 利用者指定fileの候補到達数を、公式取得済みの件数から分離する。
	if( userSelected) {
		return CoverageSource::USER_SELECTED ;
	}

	return indexed ? CoverageSource::INDEXED : CoverageSource::LOCAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 重複排除集合の件数を64-bit表示値へ変換する。
 *
 * x64対象でsize_tを64-bit件数へlosslessに変換する。
 *
 * @param[in] devices 一つの取得元へ候補が届いたopaque device集合。
 * @return 集合の要素数。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t deviceSetSize( const std::unordered_set<std::wstring> &devices) noexcept
{
	static_assert( sizeof( std::size_t) <= sizeof( std::uint64_t)) ;
	return static_cast<std::uint64_t>( devices.size()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/local_coverage.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ManufacturerReviewState classifyManufacturerReviewState( const std::wstring_view manufacturer)
{
	const std::wstring key = normalizeManufacturerKey( manufacturer) ;	// 端末内比較key。
	// メーカー名の比較keyを作れない場合は、対応や未対応を推測せず未識別とする。
	if( key.empty()) {
		return ManufacturerReviewState::UNIDENTIFIED ;
	}

	// OS基盤の表示名は製品メーカーの審査対象と分けて分類する。
	if( containsManufacturerAlias( PLATFORM_MANUFACTURER_ALIASES, key)) {
		return ManufacturerReviewState::PLATFORM ;
	}

	// 審査対象として登録した別名だけを対応メーカーへ分類し、名前から対応を推測しない。
	if( containsManufacturerAlias( REVIEWED_MANUFACTURER_ALIASES, key)) {
		return ManufacturerReviewState::REVIEWED ;
	}

	return ManufacturerReviewState::PENDING_INTAKE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/local_coverage.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::vector<LocalCoverageEntry>> aggregateLocalCoverage(
	const std::span<const UpdateCandidate>	  candidates,
	const std::span<const ProviderDescriptor> providers)
{
	std::unordered_map<std::wstring, CoverageSource> providerSources ;	// ID別trust boundary。
	providerSources.reserve( providers.size()) ;
	// Registryの重複IDと曖昧なtrust boundaryをcandidate処理前に拒否する。
	for( const ProviderDescriptor &provider : providers) {
		const std::optional<CoverageSource> source =
			// Providerの一意な集計分類。
			resolveCoverageSource( provider) ;
		// 取得元を一意に解決できないProvider定義を、coverage集計へ持ち込まない。
		if( provider.id.empty() || !source.has_value() ||
		   !providerSources.emplace( provider.id, source.value()).second) {
			return std::nullopt ;
		}
	}

	using CoverageKey = std::pair<std::wstring, std::wstring> ;		// Manufacturer／class group key。
	std::map<CoverageKey, std::size_t>			  coverageIndexes ;	// 表示文字列順のgroup index表。
	std::unordered_map<std::wstring, std::size_t> deviceIndexes ;	// Opaque device別group index。
	std::vector<CoverageState> states ;								// 現在deviceから構築するgroup別集計作業領域。
	states.reserve( candidates.size()) ;
	deviceIndexes.reserve( candidates.size()) ;

	// 現在版だけをpresent device inventoryとして一device一件の母数を作る。
	for( const UpdateCandidate &candidate : candidates) {
		// 現在存在するdeviceの母数を先に作るため、更新候補の行はこの集計から除く。
		if( !candidate.current) {
			continue ;
		}

		const auto provider = providerSources.find( candidate.providerId) ;	// 現在版の取得元分類。
		// 現在deviceの母数には一意なlocal列挙結果だけを使い、外部候補から補完しない。
		if( candidate.deviceIdentity.empty() || provider == providerSources.end() ||
		   provider->second != CoverageSource::LOCAL ||
		   deviceIndexes.contains( candidate.deviceIdentity)) {
			return std::nullopt ;
		}

		const CoverageKey key{candidate.manufacturer, candidate.driverClass} ;	// 表示group key。
		auto			  coverageIndex = coverageIndexes.find( key) ;			// 既存groupの検索結果。
		// メーカーとclassの組合せが初出の場合だけ集計枠を作り、同じ分類を重複させない。
		if( coverageIndex == coverageIndexes.end()) {
			const std::size_t newIndex = states.size() ;	// 新規groupのvector index。
			states.push_back( {.entry = {.manufacturer = candidate.manufacturer,
										.driverClass  = candidate.driverClass,
										.reviewState  = classifyManufacturerReviewState(
											 candidate.manufacturer)}}) ;
			coverageIndex = coverageIndexes.emplace( key, newIndex).first ;
		}

		CoverageState &state = states[coverageIndex->second] ;	// 現在deviceが属する集計group。
		// device件数の加算で整数上限を超える場合は、誤った母数を返さない。
		if( state.entry.deviceCount == std::numeric_limits<std::uint64_t>::max()) {
			return std::nullopt ;
		}

		++state.entry.deviceCount ;
		deviceIndexes.emplace( candidate.deviceIdentity, coverageIndex->second) ;
	}

	// 非現在版候補をlocal deviceへ照合し、同じ取得元の重複候補を一device一件へまとめる。
	for( const UpdateCandidate &candidate : candidates) {
		// 候補の到達件数には現在版を含めず、母数のdeviceを重複して数えない。
		if( candidate.current) {
			continue ;
		}

		const auto provider = providerSources.find( candidate.providerId) ;	// Candidate取得元分類。
		// deviceや取得元を識別できない候補は、coverageの正常な到達件数に含めない。
		if( candidate.deviceIdentity.empty() || provider == providerSources.end()) {
			return std::nullopt ;
		}

		const auto device = deviceIndexes.find( candidate.deviceIdentity) ;	// Local device照合結果。
		// WUA等でlocal deviceを安全に解決できない候補を表示groupへ推測配賦しない。
		if( device == deviceIndexes.end()) {

			continue ;
		}

		CoverageState &state = states[device->second] ;	// Candidateが到達したdeviceの集計group。
		// 索引参照は表示だけであり、候補成功やdriver対応到達へ数えません。
		if( provider->second == CoverageSource::INDEXED && !candidate.installable) {
			state.indexedReferences.insert( candidate.deviceIdentity) ;
			continue ;
		}

		state.candidateDevices.insert( candidate.deviceIdentity) ;
		// 取得元ごとにdeviceを集合へ登録し、同じdeviceの複数候補で件数を水増ししない。
		switch( provider->second) {
			// Windows 管理取得元の到達 device を重複排除して集計する。
			case CoverageSource::MANAGED:
				state.managedDevices.insert( candidate.deviceIdentity) ;
				break ;

			// 公式取得元の到達 device を管理 service と分けて集計する。
			case CoverageSource::OFFICIAL:
				state.officialDevices.insert( candidate.deviceIdentity) ;
				break ;

			// 利用者指定 file の到達 device を独立の集合へ集計する。
			case CoverageSource::USER_SELECTED:
				state.userSelectedDevices.insert( candidate.deviceIdentity) ;
				break ;

			// Local Driver Store の到達 device を network 取得元と分けて集計する。
			case CoverageSource::LOCAL:
				state.localDevices.insert( candidate.deviceIdentity) ;
				break ;

			// 実公開索引候補を第五境界にだけ集計します。
			case CoverageSource::INDEXED:
				state.indexedDevices.insert( candidate.deviceIdentity) ;
				break ;
		}
	}

	std::vector<LocalCoverageEntry> coverage ;	// Manufacturer／class順の確定集計。
	coverage.reserve( states.size()) ;
	// Mapの表示文字列順を維持して各重複排除集合を件数へ確定する。
	for( const auto &[key, stateIndex] : coverageIndexes) {
		// 順序付けにだけ使用し、表示値はstate内の正本を使う。
		static_cast<void>( key) ;
		CoverageState &state			 = states[stateIndex] ;	// 件数を確定するgroup作業領域。
		state.entry.candidateDeviceCount = deviceSetSize( state.candidateDevices) ;
		state.entry.managedCandidateDeviceCount		 = deviceSetSize( state.managedDevices) ;
		state.entry.officialCandidateDeviceCount	 = deviceSetSize( state.officialDevices) ;
		state.entry.userSelectedCandidateDeviceCount = deviceSetSize( state.userSelectedDevices) ;
		state.entry.localCandidateDeviceCount		 = deviceSetSize( state.localDevices) ;
		state.entry.indexedCandidateDeviceCount		 = deviceSetSize( state.indexedDevices) ;
		state.entry.indexedReferenceDeviceCount		 = deviceSetSize( state.indexedReferences) ;
		// 候補の到達数が現在deviceの母数を超える矛盾を検出したら、集計全体を返さない。
		if( state.entry.candidateDeviceCount > state.entry.deviceCount ||
		   state.entry.managedCandidateDeviceCount > state.entry.deviceCount ||
		   state.entry.officialCandidateDeviceCount > state.entry.deviceCount ||
		   state.entry.userSelectedCandidateDeviceCount > state.entry.deviceCount ||
		   state.entry.localCandidateDeviceCount > state.entry.deviceCount ||
		   state.entry.indexedCandidateDeviceCount > state.entry.deviceCount ||
		   state.entry.indexedReferenceDeviceCount > state.entry.deviceCount) {
			return std::nullopt ;
		}

		coverage.push_back( std::move( state.entry)) ;
	}

	return coverage ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/local_coverage.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool preserveLocalCoverageMeasurements(
	const std::span<const LocalCoverageEntry> scanCoverage,
	const std::span<LocalCoverageEntry>		  refreshedCoverage) noexcept
{
	// Groupの追加・欠落がある候補集合へ古い計測を位置だけで対応付けない。
	if( scanCoverage.size() != refreshedCoverage.size()) {
		return false ;
	}

	try {
		using CoverageKey = std::pair<std::wstring_view, std::wstring_view> ;	// 表示groupの一意key。
		std::map<CoverageKey, const LocalCoverageEntry *> measurements ;		// Scan時点のgroup索引。
		// Scan時点の全groupを表示値で一意に索引化し、重複groupを拒否する。
		for( const LocalCoverageEntry &entry : scanCoverage) {
			const CoverageKey key{entry.manufacturer, entry.driverClass} ;	// 現在登録するgroup key。
			// 同じ表示groupが二重にある不正snapshotを部分的に引き継がない。
			if( !measurements.emplace( key, &entry).second) {
				return false ;
			}
		}

		std::set<CoverageKey> refreshedKeys ;	// 再集計側の重複を検出するkey集合。
		// 現在版母数が一致する全groupへ、候補準備前のmeasurementだけをcopyする。
		for( LocalCoverageEntry &entry : refreshedCoverage) {
			const CoverageKey key{entry.manufacturer, entry.driverClass} ;	// 再集計groupのkey。
			const auto		  found = measurements.find( key) ;				// 対応するscan時点group。
			// Group重複、欠落または現在版device数の変化を別時点の計測として拒否する。
			if( !refreshedKeys.insert( key).second || found == measurements.end() ||
			   found->second->deviceCount != entry.deviceCount) {
				return false ;
			}

			entry.measurement = found->second->measurement ;
		}
	} catch( ...) {
		// Allocation失敗時は一部だけ古いmeasurementを対応付けた状態を成功としない。
		return false ;
	}

	return true ;
}

} // namespace drivercrate
