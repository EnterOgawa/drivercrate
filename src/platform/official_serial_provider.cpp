//------------------------------------------------------------------------------
/**
 * @file official_serial_provider.cpp
 * @brief 公式serial ZIP共通Provider実装。
 * @version 01.01.00
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  許可IDの候補監査と回帰確認。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Metadataと後段監査の計測根拠を分離。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  実HTTP取得経路の計測要約を接続。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  新一scan承認と回線許可をpayload取得へ結合。
 * </pre>
 *
 * @note 署名済み原本を保持し、許可IDだけでdeviceとrankを監査します。未審査IDの許可や既存の監査条件の迂回は行いません。
 */
//------------------------------------------------------------------------------

#include "platform/official_serial_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_release_metadata.h"
#include "platform/prolific_serial_package.h"
#include "platform/silicon_labs_catalog_parser.h"
#include "platform/silicon_labs_serial_package.h"
#include "platform/wch_catalog_parser.h"
#include "platform/wch_serial_package.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {
/** @brief 組み込みfamilyの取得先と既存内容監査を結合する。 */
struct SerialPolicy {
	/// Registryとcandidateの安定した識別子。
	std::wstring_view providerId ;
	/// 許可した公式検索起点。
	std::wstring_view landing ;
	/// 補助JSON。空の場合はlanding内の配布行を使用する。
	std::wstring_view metadata ;
	/// 候補の製品系列と取得元表示。
	std::wstring_view title ;
	/// 今回の検査同意。別familyの同意を転用しない。
	bool ScanOptions::							  *consent ;
	/// 共通結果型の既存内容監査。
	decltype( &inspectProlificSerialPackageFile)	   inspect ;
	/// 導入直前の内容再監査。
	decltype( &reverifyProlificSerialInfPackage)	   reverify ;
	/// 審査済みID境界。
	decltype( &isProlificSerialCandidateHardwareId) allowsId ;
	/// 既存familyの32 MiB上限。
	std::uint64_t								   maximumArchiveBytes{32ULL * 1024ULL * 1024ULL} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Network情報から監査関数や許可hostを変更させない。
 *
 * @param[in] family 構築時に固定したfamily。
 * @return Process寿命中の非所有policy。未知enumはnullptr。
 */
//------------------------------------------------------------------------------
const SerialPolicy *serialPolicy( const OfficialSerialFamily family) noexcept
{
	static constexpr SerialPolicy PROLIFIC{
		// ADR 0092のDCHU限定契約。
		.providerId = PROLIFIC_OFFICIAL_PROVIDER_ID,
		.landing	= {},	// Prolificの起点は共通OfficialSourceDefinitionを正本とする。
		.metadata	= {},
		.title		= L"Prolific 公式DCHU INF",
		.consent	= &ScanOptions::prolificInspectionApproved,
		.inspect	= &inspectProlificSerialPackageFile,
		.reverify	= &reverifyProlificSerialInfPackage,
		.allowsId	= &isProlificSerialCandidateHardwareId} ;
	static constexpr SerialPolicy SILICON_LABS{
		// ADR 0093のCP210x公開JSON契約。
		.providerId = SILICON_LABS_OFFICIAL_PROVIDER_ID,
		.landing	= L"https://www.silabs.com/software-and-tools/"
				   L"usb-to-uart-bridge-vcp-drivers?tab=downloads",
		.metadata = L"https://www.silabs.com/sl/search/softwaredocumentsearchquery.json/"
					L"ct-software/soft-drivers_vcp-drivers.json",
		.title	  = L"Silicon Labs 公式CP210x INF",
		.consent  = &ScanOptions::siliconLabsInspectionApproved,
		.inspect  = &inspectSiliconLabsSerialPackageFile,
		.reverify = &reverifySiliconLabsSerialInfPackage,
		.allowsId = &isSiliconLabsSerialCandidateHardwareId} ;
	static constexpr SerialPolicy WCH_CH341{
		// 固定CH341SER監査へ渡す公開ZIP取得契約。
		.providerId = WCH_OFFICIAL_PROVIDER_ID,
		.landing	= L"https://www.wch.cn/downloads/CH341SER_ZIP.html",
		.metadata	= L"https://api1.wch.cn/api/official/website/common/"
					L"relationFiles?fileName=CH341SER_ZIP.html",
		.title				 = L"WCH 公式CH340／CH341 INF",
		.consent			 = &ScanOptions::wchInspectionApproved,
		.inspect			 = &inspectWchSerialPackageFile,
		.reverify			 = &reverifyWchSerialInfPackage,
		.allowsId			 = &isWchSerialCandidateHardwareId,
		.maximumArchiveBytes = 4ULL * 1024ULL * 1024ULL} ;
	static constexpr SerialPolicy WCH_CH343{
		// 固定CH343SER監査へ渡す公開ZIP取得契約。
		.providerId = WCH_MULTI_OFFICIAL_PROVIDER_ID,
		.landing	= L"https://www.wch.cn/downloads/CH343SER_ZIP.html",
		.metadata	= L"https://api1.wch.cn/api/official/website/common/"
					L"relationFiles?fileName=CH343SER_ZIP.html",
		.title				 = L"WCH 公式CH342／CH343系 INF",
		.consent			 = &ScanOptions::wchMultiInspectionApproved,
		.inspect			 = &inspectWchMultiSerialPackageFile,
		.reverify			 = &reverifyWchMultiSerialInfPackage,
		.allowsId			 = &isWchMultiSerialCandidateHardwareId,
		.maximumArchiveBytes = 4ULL * 1024ULL * 1024ULL} ;
	// 系列から固定 policy を選択し、network metadata で検証境界を変更させない。
	switch( family) {
		// Prolific系列は、同社向けの固定された監査・取得policyに結び付ける。
		case OfficialSerialFamily::PROLIFIC:
			return &PROLIFIC ;
		// Silicon Labs系列は、同社専用の組み込みpolicyに結び付ける。
		case OfficialSerialFamily::SILICON_LABS:
			return &SILICON_LABS ;
		// WCH CH341系列は、CH343と区別した組み込みpolicyを使用する。
		case OfficialSerialFamily::WCH_CH341:
			return &WCH_CH341 ;
		// WCH CH343系列は、CH341と区別した組み込みpolicyを使用する。
		case OfficialSerialFamily::WCH_CH343:
			return &WCH_CH343 ;
	}

	// 定義外enumを既定メーカーとして解釈しない。
	return nullptr ;
}

constexpr std::uint64_t		 METADATA_LIMIT	 = 2ULL * 1024ULL * 1024ULL ;	// 各HTML／JSONの受信上限。
constexpr std::size_t		 MAXIMUM_DEVICES = 4096U ;						// 一回に監査するinventoryの有限上限。
constexpr std::size_t		 MAXIMUM_CANDIDATES = 4096U ;					// UIとinstall表へ保持する候補上限。

//------------------------------------------------------------------------------
/**
 * @brief 4個の16bit版を比較用整数へ変換する。
 *
 * 適用性を決めず、監査後の更新／同版／旧版分類に限定する。
 *
 * @param[in] text INFまたは現在driverの明示版。
 * @return 正規4要素版の比較値。不正形式はnullopt。
 */
//------------------------------------------------------------------------------
std::optional<std::uint64_t> versionValue( const std::wstring_view text) noexcept
{
	// 空または四つの 16-bit 成分の表記上限を超える version を拒否する。
	if( text.empty() || text.size() > 23U) {
		return std::nullopt ;
	}

	std::uint64_t result{} ;	// 先行要素を16bitずつ結合した比較値。
	unsigned	  value{} ;		// 現在要素の数値。
	unsigned	  digits{} ;	// 現在要素の桁数。
	unsigned	  parts{} ;		// 完了した要素数。
	// 終端を仮想separatorとして扱い、4要素以外を拒否する。
	for( std::size_t index = 0; index <= text.size(); ++index) {
		const wchar_t character = index == text.size() ? L'.' : text[index] ;	// 現在文字。
		// Dot ごとに現在成分を確定し、次の 16-bit 成分へ移る。
		if( character == L'.') {
			// 空の version 成分と四成分を超える区切りを拒否する。
			if( digits == 0U || ++parts > 4U) {
				return std::nullopt ;
			}

			result = (result << 16U) | value ;
			value  = 0U ;
			digits = 0U ;
		} else {
			// 十進数字以外と五桁を超える version 成分は解析しない。
			if( character < L'0' || character > L'9' || ++digits > 5U) {
				return std::nullopt ;
			}

			value = value * 10U + static_cast<unsigned>( character - L'0') ;
			// 各 version 成分が 16-bit の上限を超えた時点で拒否する。
			if( value > 65535U) {
				return std::nullopt ;
			}
		}
	}

	return parts == 4U ? std::optional( result) : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存済みrankとの一致を確認する。
 *
 * Scan後のdevice状態変化を導入前に拒否する。
 *
 * @param[in] left 保存済み監査。
 * @param[in] right 現在の監査。
 * @return 全判断根拠が一致しApplicableである場合true。
 */
//------------------------------------------------------------------------------
bool sameRank( const OfficialDriverRankAudit &left, const OfficialDriverRankAudit &right) noexcept
{
	return left.decision == OfficialDriverRankDecision::APPLICABLE &&
		   left.decision == right.decision &&
		   left.currentPosition.kind == right.currentPosition.kind &&
		   left.currentPosition.index == right.currentPosition.index &&
		   left.candidatePosition.kind == right.candidatePosition.kind &&
		   left.candidatePosition.index == right.candidatePosition.index &&
		   left.currentRank == right.currentRank && left.candidateRank == right.candidateRank &&
		   left.currentIdentifierScore == right.currentIdentifierScore &&
		   left.candidateIdentifierScore == right.candidateIdentifierScore ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialSerialProvider::OfficialSerialProvider( const OfficialSerialFamily family) noexcept
	: family_( family)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring_view OfficialSerialProvider::providerId() const noexcept
{
	const SerialPolicy *const policy = serialPolicy( family_) ;	// 非所有の組み込み契約。
	return policy == nullptr ? std::wstring_view{} : policy->providerId ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::uint64_t OfficialSerialProvider::maximumArchiveBytes() const noexcept
{
	const SerialPolicy *const policy = serialPolicy( family_) ;	// 取得で使用する同じ非所有契約。
	return policy == nullptr ? 0U : policy->maximumArchiveBytes ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const ProviderMeasurementEvidence &OfficialSerialProvider::measurementEvidence() const noexcept
{
	return measurementEvidence_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseOfficialSerialZipUrl( const OfficialSerialFamily family, const std::wstring_view html,
							   const std::wstring_view metadata, std::wstring &url)
{
	url.clear() ;
	// 系列に対応する専用 parser だけへ公式配布情報を渡す。
	switch( family) {
		// ProlificのHTML解析では、未定義の追加metadataを受け入れない。
		case OfficialSerialFamily::PROLIFIC:
			return metadata.empty() && parseProlificOfficialZipUrl( html, url) ;
		// Silicon LabsのHTMLとmetadataは、同社向けの検証器だけへ渡す。
		case OfficialSerialFamily::SILICON_LABS:
			return parseSiliconLabsOfficialZipUrl( html, metadata, url) ;
		// CH341配布物の照合は、WCH parserへ対象系列を明示する。
		case OfficialSerialFamily::WCH_CH341:
			return parseWchOfficialZipUrl( WchOfficialPackageKind::CH341, html, metadata, url) ;
		// CH343配布物の照合は、別系列への誤対応を避けて対象を明示する。
		case OfficialSerialFamily::WCH_CH343:
			return parseWchOfficialZipUrl( WchOfficialPackageKind::CH343, html, metadata, url) ;
	}

	// 定義外enumを有効な取得種別と解釈しない。
	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseProlificOfficialZipUrl( const std::wstring_view html, std::wstring &url)
{
	url.clear() ;
	constexpr std::wstring_view MARKER =
		L"Windows DCHU+DFx+Modem Standy Driver INF Setup" ;			// 審査済み配布種別の識別文。
	constexpr std::wstring_view PREFIX = L"/wp-content/uploads/" ;	// 登録済み配布path。
	// 空・上限超過・埋込み NUL を持つ公式 page を parser へ受理しない。
	if( html.empty() || html.size() > METADATA_LIMIT || html.find( L'\0') != html.npos) {
		return false ;
	}

	const std::size_t marker = html.find( MARKER) ;	// 対象配布説明の位置。
	// 行がない場合と複数ある場合を推測で解決しない。
	if( marker == html.npos || html.find( MARKER, marker + MARKER.size()) != html.npos) {
		return false ;
	}

	const std::size_t start = html.rfind( L"<tr", marker) ;		// 対象行の開始。
	const std::size_t end	= html.find( L"</tr>", marker) ;	// 対象行の終端。
	// 配布行の境界欠落、長さ超過、別行への跨りを拒否する。
	if( start == html.npos || end == html.npos || end - start > 32768U ||
	   html.find( L"</tr>", start) != end) {
		return false ;
	}

	const std::wstring_view row = html.substr( start, end - start) ;	// 他製品を含まない行。
	// 対象 Windows 表記のない配布行から ZIP を選択しない。
	if( row.find( L"Win10 / Win11") == row.npos) {
		return false ;
	}

	const std::size_t anchor = row.find( L"<a href=\"") ;	// 審査済みdownload anchor形式。
	// 複数downloadリンクを任意選択しない。
	if( anchor == row.npos || row.find( L"<a", anchor + 2U) != row.npos) {
		return false ;
	}

	const std::size_t valueStart = anchor + 9U ;					// href属性値の先頭。
	const std::size_t valueEnd	 = row.find( L'\"', valueStart) ;	// 属性値の終端。
	// URL 属性値の終端がない配布行は拒否する。
	if( valueEnd == row.npos) {
		return false ;
	}

	const std::wstring_view path = row.substr( valueStart, valueEnd - valueStart) ;	// 相対URL。
	// 固定公式 path prefix に一致しない URL と長さ超過を拒否する。
	if( !path.starts_with( PREFIX) || path.size() > 180U) {
		return false ;
	}

	const std::wstring_view tail = path.substr( PREFIX.size()) ;	// 年／月／file名。
	// 配布 path の日付 directory 形式が一致しなければ拒否する。
	if( tail.size() < 9U || tail[4] != L'/' || tail[7] != L'/') {
		return false ;
	}

	// 年月は数字だけを許可し、別directoryへの遷移を禁止する。
	for( std::size_t index = 0; index < 7U; ++index) {
		// 日付 directory の区切り以外に数字でない文字があれば拒否する。
		if( index != 4U && (tail[index] < L'0' || tail[index] > L'9')) {
			return false ;
		}
	}

	const std::wstring_view name = tail.substr( 8U) ;	// 配布種別を拘束するfile名。
	// 対象 DCHU ZIP 名の prefix・拡張子に一致しない名前と親参照を拒否する。
	if( !name.starts_with( L"PL2303G_DCHU") || !name.ends_with( L".zip") ||
	   name.find( L"..") != name.npos) {
		return false ;
	}

	// Encoding、query、別階層、空白を許可せず、URL曖昧性を排除する。
	for( const wchar_t character : name) {
		// 配布 file 名の許可文字以外を含む path を受理しない。
		if( !((character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') ||
			 (character >= L'0' && character <= L'9') || character == L'_' || character == L'-' ||
			 character == L'.')) {
			return false ;
		}
	}

	url = L"https://www.prolific.com.tw" + std::wstring( path) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditOfficialSerialDevice(
	const OfficialSerialFamily family, const ScanSessionId session,
	const std::wstring_view deviceIdentity, const OfficialDownloadWorkspace &workspace,
	const OfficialInfPackage &package, const LocalHardwareIdMatcher &matcher,
	const OfficialSerialRankAuditor &rankAuditor, OfficialDriverRankAudit &audit)
{
	audit = {} ;
	// 不正callbackと無制限metadataを外部APIへ渡さない。
	if( session == 0U || deviceIdentity.empty() || !matcher || !rankAuditor ||
	   package.hardwareIds.empty() || package.hardwareIds.size() > 128U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const SerialPolicy *const policy = serialPolicy( family) ;	// 組み込みfamilyだけを解決する。
	// 未知familyを別メーカーへ転用しない。
	if( policy == nullptr) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	OfficialInfPackage restricted = package ;	// 署名原本を変えずrank evidenceだけを限定するcopy。
	std::erase_if( restricted.hardwareIds,
				  [policy]( const std::wstring &id) { return !policy->allowsId( id) ; }) ;
	bool matched{} ;	// 許可IDが対象のopaque deviceへ完全一致した場合true。
	// 未審査IDはmatcherにも渡さず、有限な許可IDの中で対象deviceを探す。
	for( const std::wstring &id : restricted.hardwareIds) {
		const std::optional<std::wstring> resolved = matcher( id) ;	// Worker内限定の照合結果。
		// 許可 ID の local 解決先が要求 device と一致した場合だけ対象と認める。
		if( resolved && *resolved == deviceIdentity) {
			matched = true ;
			break ;
		}
	}

	// 許可 ID が対象 device へ解決しない場合は非一致とし、API 失敗と区別する。
	if( !matched) {
		audit.decision = OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED ;
		// 許可IDなし／曖昧／別deviceをpackage破損やAPI失敗にしない。
		return 0 ;
	}

	const NativeError error =
		// 現在状態の再確認。
		rankAuditor( session, deviceIdentity, workspace, restricted, audit) ;
	// Rank API の失敗時は途中までの適用可能判定を消去する。
	if( error != 0) {
		// API失敗時に中間のApplicableを残さない。
		audit = {} ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult OfficialSerialProvider::scan( const ScanSessionId session, const ScanOptions &options,
										const std::span<const OfficialCatalogDevice> devices,
										const LocalHardwareIdMatcher				&matcher,
										const OfficialSerialRankAuditor				&rankAuditor,
										const ProviderProgressCallback				&progress)
try {
	invalidate() ;
	ScanResult				  result{.scanSessionId = session,
									 .outcome		= OutcomeCode::FAILURE,
									 .state = ProviderScanState::FAILURE} ;	// 初期状態は失敗扱い。
	const SerialPolicy *const policy = serialPolicy( family_) ;				// 変更不可の組み込み取得契約。
	// Policy、session、上限、設定、照合・進捗 callback の不備を scan 前に拒否する。
	if( policy == nullptr || session == 0U || devices.size() > MAXIMUM_DEVICES ||
	   !validateScanOptions( options) || !matcher || !rankAuditor || !progress) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	measurementEvidence_.providerId		 = policy->providerId ;
	measurementEvidence_.scanSessionId	 = session ;
	measurementEvidence_.scope			 = MeasurementScope::DEVICE_QUERY ;
	measurementEvidence_.eligible.extent = MeasurementExtent::EXACT ;
	measurementEvidence_.eligible.identities.reserve( devices.size()) ;
	std::unordered_set<std::wstring> deviceIdentities ;	// Inventory内のopaque identity一意性。
	deviceIdentities.reserve( devices.size()) ;
	// 全入力を通信前に検証し、clientで探索対象となるPorts nodeを順序どおり保持する。
	for( const OfficialCatalogDevice &device : devices) {
		// 空・過長・重複identityから候補または計測根拠を作らない。
		if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
		   !deviceIdentities.insert( device.deviceIdentity).second) {
			measurementEvidence_ = {} ;
			result.error		 = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		// Serial各系列の宣言済み探索範囲はWindows clientのPorts classとする。
		if( device.driverClass == L"Ports") {
			measurementEvidence_.eligible.identities.push_back( device.deviceIdentity) ;
		}
	}

	result.coverage.eligibleDeviceCount = measurementEvidence_.eligible.identities.size() ;
	bool payloadApproved{} ;			// 今回のdriver package検査用取得許可。
	bool restrictedNetworkApproved{} ;	// 今回の制限／不明回線のみに有効な許可。
	// 新しい一scan承認は個別boolと併用せず、同じProvider範囲へ再照合する。
	if( options.officialDiscoveryApproval) {
		const auto descriptors = builtInProviderDescriptors() ;	// Provider登録順の正本。
		const auto descriptor  = std::find_if( descriptors.begin(), descriptors.end(),
											  [policy]( const ProviderDescriptor &candidate) {
												  return candidate.id == policy->providerId ;
											  }) ; // 今回のserial Provider正本。
		// 承認したProvider集合に含まれない直接呼出しを拒否する。
		if( descriptor == descriptors.end() || !isProviderEnabled( options, *descriptor)) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		payloadApproved = options.officialDiscoveryApproval->inspectionPermission ==
						  OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE ;
		restrictedNetworkApproved = options.officialDiscoveryApproval->restrictedNetworkApproved ;
	} else {
		// 移行期間の旧個別承認は従来どおり制限／不明回線も今回だけ許可する。
		payloadApproved			  = options.*(policy->consent) ;
		restrictedNetworkApproved = payloadApproved ;
	}

	// 新承認も旧個別承認もないscanから通信を開始しない。
	if( !options.officialDiscoveryApproval && !payloadApproved) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// 別packageのServer対応を、client向けserial配布へ転用しない。
	if( isWindowsServer()) {
		measurementEvidence_.eligible.identities.clear() ;
		measurementEvidence_.queryOutcome		   = OutcomeCode::SUCCESS ;
		measurementEvidence_.queryCompleted.extent = MeasurementExtent::EXACT ;
		measurementEvidence_.information.extent	   = MeasurementExtent::EXACT ;
		measurementEvidence_.applicabilityExtent   = MeasurementExtent::EXACT ;
		measurementEvidence_.readinessExtent	   = MeasurementExtent::EXACT ;
		measurementEvidence_.recordExtent		   = MeasurementExtent::EXACT ;
		result.coverage.eligibleDeviceCount		   = 0U ;
		result.succeeded						   = true ;
		result.outcome							   = OutcomeCode::SUCCESS ;
		result.state							   = ProviderScanState::NOT_APPLICABLE ;
		return result ;
	}

	// 対象 device がゼロの場合は公式 ZIP を取得せず対象外として完了する。
	if( result.coverage.eligibleDeviceCount == 0U) {
		measurementEvidence_.queryOutcome		   = OutcomeCode::SUCCESS ;
		measurementEvidence_.queryCompleted.extent = MeasurementExtent::EXACT ;
		measurementEvidence_.information.extent	   = MeasurementExtent::EXACT ;
		measurementEvidence_.applicabilityExtent   = MeasurementExtent::EXACT ;
		measurementEvidence_.readinessExtent	   = MeasurementExtent::EXACT ;
		measurementEvidence_.recordExtent		   = MeasurementExtent::EXACT ;
		result.succeeded						   = true ;
		result.outcome							   = OutcomeCode::SUCCESS ;
		result.state							   = ProviderScanState::NOT_APPLICABLE ;
		return result ;
	}

	WindowsOfficialNetworkCostReader
							costReader ;	// Metadata送信前とpayload取得で共通する回線状態照会。
	OfficialNetworkCostKind networkCost =
		OfficialNetworkCostKind::UNKNOWN ;									// 開始直前の有限回線分類。
	const NativeError networkCostError = costReader.read( networkCost) ;	// Windows回線状態の診断値。
	// 制限または判定不能回線は、今回の明示許可なしにmetadata通信も開始しない。
	if( (networkCostError != 0 || networkCost != OfficialNetworkCostKind::UNRESTRICTED) &&
	   !restrictedNetworkApproved) {
		measurementEvidence_.queryOutcome = OutcomeCode::NOT_STARTED ;
		result.succeeded				  = true ;
		result.outcome					  = OutcomeCode::SUCCESS ;
		result.state					  = ProviderScanState::NETWORK_NOT_APPROVED ;
		return result ;
	}

	progress( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 0U}) ;
	measurementEvidence_.queryOutcome		   = OutcomeCode::IN_PROGRESS ;
	measurementEvidence_.queryCompleted.extent = MeasurementExtent::LOWER_BOUND ;
	measurementEvidence_.information.extent	   = MeasurementExtent::LOWER_BOUND ;
	measurementEvidence_.applicabilityExtent   = MeasurementExtent::LOWER_BOUND ;
	measurementEvidence_.readinessExtent	   = MeasurementExtent::LOWER_BOUND ;
	measurementEvidence_.recordExtent		   = MeasurementExtent::LOWER_BOUND ;
	std::wstring url ;	// 当該公式pageの配布行から得たworker内URL。
	// Prolific は共通の公式配布 metadata 境界を通して ZIP の取得先を決める。
	if( family_ == OfficialSerialFamily::PROLIFIC) {
		OfficialReleaseRecord release ;				// Payload取得前の共通配布情報。
		bool				  metadataRejected{} ;	// 取得失敗と解析・根拠拒否の区別。
		result.error = readOfficialReleaseMetadata( OfficialReleaseFamily::PROLIFIC_DCHU, session,
												   http_, release, metadataRejected) ;
		refreshMeasurementResources() ;
		// 共通 metadata 取得の失敗時は payload 取得へ進まない。
		if( result.error != 0) {
			measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
			// Metadata の形式・由来拒否は一般の通信失敗と分けて保持する。
			if( metadataRejected) {
				result.state = ProviderScanState::METADATA_REJECTED ;
			}

			// 共通化後も由来・解析拒否でpayloadを取得しない。
			return result ;
		}

		url = std::move( release.downloadUrl) ;
	} else {
		result.error = http_.beginSourceSession( session, policy->providerId) ;
		std::wstring html ;	// 公式landing本文。端末情報を付加しない。
		// 取得元の準備に成功した場合だけ固定 landing page を取得する。
		if( result.error == 0) {
			result.error = http_.getUtf8TextForSource( policy->landing, OFFICIAL_LANDING_RESOURCE_ID,
													  METADATA_LIMIT, html) ;
		}

		refreshMeasurementResources() ;

		// 公式 page を取得できなければ部分情報から scan を継続しない。
		if( result.error != 0) {
			measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
			return result ;
		}

		std::wstring metadata ;	// CP210x／WCHの補助公式JSON本文。
		// 追加 metadata の固定配布先がある系列だけ、その公式情報も取得する。
		if( !policy->metadata.empty()) {
			result.error = http_.getUtf8TextForSource(
				policy->metadata, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, METADATA_LIMIT, metadata) ;
			refreshMeasurementResources() ;
			// Metadata取得失敗を候補なしへ置換しない。
			if( result.error != 0) {
				measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
				return result ;
			}
		}

		// 同 session の取得根拠と専用 parser の両方が成立しなければ URL を受理しない。
		if( !http_.hasSourceEvidence( session, policy->providerId, OFFICIAL_LANDING_RESOURCE_ID) ||
		   (!policy->metadata.empty() &&
			!http_.hasSourceEvidence( session, policy->providerId,
									 OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) ||
		   !parseOfficialSerialZipUrl( family_, html, metadata, url)) {
			result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
			result.state = ProviderScanState::METADATA_REJECTED ;
			measurementEvidence_.queryOutcome = OutcomeCode::FAILURE ;
			return result ;
		}
	}

	// 公式由来とschemaを通った一recordを、payload処理と独立して確定する。
	measurementEvidence_.queryOutcome	= OutcomeCode::SUCCESS ;
	measurementEvidence_.queryCompleted = measurementEvidence_.eligible ;
	measurementEvidence_.recordExtent	= MeasurementExtent::EXACT ;
	measurementEvidence_.records.push_back(
		{std::wstring( policy->providerId) + L":record:" + std::to_wstring( session) + L":0", {}}) ;
	// Metadata限定承認は正常終端とし、workspace、payload、署名、rankを開始しない。
	if( !payloadApproved) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::PAYLOAD_NOT_APPROVED ;
		progress( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100U}) ;
		return result ;
	}

	progress( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 10U}) ;
	OfficialDownloadWorkspace		downloadWorkspace ;		// 取得中archiveを所有する一時保護領域。
	OfficialAcquisitionSession		acquisitionSession ;	// Family別の一回一file有限取得ledger。
	const OfficialAcquisitionLimits limits{.maximumFileBytes	 = policy->maximumArchiveBytes,
										   .maximumProviderBytes = policy->maximumArchiveBytes,
										   .maximumSessionBytes	 = policy->maximumArchiveBytes,
										   .minimumFreeBytes	 = 256ULL * 1024ULL * 1024ULL,
										   .maximumProviderFiles = 1U,
										   .maximumSessionFiles =
											   1U} ;	// 追加archiveへ拡張しない上限。
	result.error = downloadWorkspace.initialize( policy->providerId, session) ;
	// 前段が成功した場合だけ有限上限付きの取得 session を初期化する。
	if( result.error == 0) {
		result.error = acquisitionSession.initialize( session, limits) ;
	}

	OfficialAcquisitionResult		 acquisition ;			// 成功時の由来と実hash。まだ候補ではない。
	OfficialHttpAcquisitionTransport transport( http_) ;	// 共通WinHTTPへの非所有adapter。
	// 取得 session を初期化できた場合だけ確認済み ZIP を取得する。
	if( result.error == 0) {
		const OfficialAcquisitionRequest request{
			.url					   = url,
			.providerId				   = policy->providerId,
			.resourceId				   = OFFICIAL_PAYLOAD_RESOURCE_ID,
			.workspaceFileName		   = L"serial.zip",
			.maximumFileBytes		   = policy->maximumArchiveBytes,
			.restrictedNetworkApproved = restrictedNetworkApproved} ;	// 一scan承認の回線範囲。
		result.error = acquisitionSession.acquire(
			request, downloadWorkspace, transport, costReader,
			[&progress]( const std::uint64_t done, const std::uint64_t total) {
				progress( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = total == 0U
												 ? 10U
												 : static_cast<std::uint32_t>(
													   10U + std::min( done, total) * 40U / total)}) ;
			},
			{}, acquisition) ;
	}

	refreshMeasurementResources() ;

	// 取得 error または監査待ち以外の状態では内容監査へ進まない。
	if( result.error != 0 ||
	   acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) {
		result.state = ProviderScanState::DOWNLOAD_FAILED ;
		// 取得状態が不正でも診断値がゼロなら内部不整合の失敗を明示する。
		if( result.error == 0) {
			result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		}

		return result ;
	}

	contentsWorkspace_ = std::make_unique<OfficialDownloadWorkspace>() ;
	result.error =
		policy->inspect( acquisition.inspectionPath, session, *contentsWorkspace_, contents_) ;
	// 内容監査の失敗または取得時の hash・size との不一致では保持物を失効させる。
	if( result.error != 0 || contents_.archiveSha256 != acquisition.sha256 ||
	   contents_.archiveSize != acquisition.byteCount) {
		result.state = ProviderScanState::CONTENT_REJECTED ;
		// 取得根拠の不一致に診断値がない場合は不正 data の失敗を付ける。
		if( result.error == 0) {
			result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		}

		invalidatePreparedState() ;
		return result ;
	}

	// 署名済みINF全体は保持し、候補化時に許可IDのdeviceだけを監査する。
	session_	 = session ;
	ownerThread_ = GetCurrentThreadId() ;
	std::uint64_t completed{} ;					// 実際に全INFとの照合を終了したPorts device数。
	std::uint64_t assessed{} ;					// API失敗なしで全INFとの照合を完了したdevice数。
	NativeError	  auditError{} ;				// 候補0件とAPI失敗を区別する診断値。
	bool		  classificationIncomplete{} ;	// 適用一致後に通常更新区分を確定できない場合true。
	// 各deviceと有限INF集合をrank監査し、同一deviceの複数版を個別に表示する。
	for( const OfficialCatalogDevice &device : devices) {
		// Ports class 以外の device は serial INF の適用性監査から除外する。
		if( device.driverClass != L"Ports") {
			continue ;
		}

		bool deviceFailed{} ;		// 一つでもrank APIが失敗したdeviceは判定済みに数えない。
		bool deviceInformation{} ;	// 一つ以上の検証済みINFがlocal nodeへ結合した場合true。
		// INFが複数OS版を含む場合もWindowsの適用性とrankで選別する。
		for( std::size_t index = 0; index < contents_.packages.size(); ++index) {
			const OfficialInfPackage &package = contents_.packages[index] ;	// 内容監査済みINF。
			OfficialDriverRankAudit	  rank ;								// このdeviceとINFのread-only監査結果。
			// 一deviceと監査済みserial packageのPnP・rank照合結果。
			const NativeError		  error =
				auditOfficialSerialDevice( family_, session, device.deviceIdentity,
										  *contentsWorkspace_, package, matcher, rankAuditor, rank) ;
			// Rank 監査の API 失敗を非適用とせず、device の判定失敗として保持する。
			if( error != 0) {
				auditError	 = error ;
				deviceFailed = true ;
				// API失敗を単なる非適用に読み替えない。
				continue ;
			}

			// 非一致以外のrank判断は、このINF recordが当該nodeへ結合した肯定的根拠である。
			if( !deviceInformation &&
			   rank.decision != OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) {
				deviceInformation = true ;
				measurementEvidence_.information.identities.push_back( device.deviceIdentity) ;
				measurementEvidence_.records.front().deviceIdentities.push_back(
					device.deviceIdentity) ;
			}

			// 不明なrankやID退行を候補化しない。
			if( rank.decision != OfficialDriverRankDecision::APPLICABLE) {
				continue ;
			}

			const auto proposed = versionValue( package.driverVersion) ;	// INF明示版。
			const auto current	= versionValue( device.currentVersion) ;	// 現在driver明示版。
			// 旧版切替警告を省略し得る不明版は導入対象にしない。
			if( !proposed || !current) {
				classificationIncomplete = true ;
				continue ;
			}

			UpdateCandidate candidate ;	// 外部URLと端末識別情報を含まない表示DTO。
			// 候補上限に達した場合は不完全な対象一覧を公開せず保持状態を失効させる。
			if( result.candidates.size() >= MAXIMUM_CANDIDATES) {
				result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TOO_MANY_NAMES)) ;
				result.candidates.clear() ;
				invalidatePreparedState() ;
				// 上限到達時は不完全な対象表を公開しない。
				return result ;
			}

			candidate.identity = std::wstring( policy->providerId) + L":" +
								 std::to_wstring( session) + L":" +
								 std::to_wstring( result.candidates.size()) ;
			candidate.deviceIdentity  = device.deviceIdentity ;
			candidate.providerId	  = policy->providerId ;
			candidate.packageIdentity = std::wstring( policy->providerId) + L":" +
										contents_.archiveSha256 + L":" + std::to_wstring( index) ;
			candidate.title			  = std::wstring( policy->title) + L" " + package.driverVersion ;
			candidate.manufacturer	  = device.manufacturer ;
			candidate.model			  = device.model ;
			candidate.driverClass	  = device.driverClass ;
			candidate.deviceClassGuid = device.deviceClassGuid ;
			candidate.provider		  = package.providerName ;
			candidate.version		  = package.driverVersion ;
			candidate.driverDate	  = package.driverDate.size() == 10U
											? package.driverDate.substr( 6U, 4U) + L"/" +
											  package.driverDate.substr( 0U, 2U) + L"/" +
											  package.driverDate.substr( 3U, 2U)
											: package.driverDate ;
			candidate.sourceName	  = policy->title ;
			candidate.sourceLocation  = L"公式ZIP取得・署名／PnP rank監査済み" ;
			candidate.maximumDownloadBytes = contents_.archiveSize ;
			candidate.action =
				*proposed > *current
					? DriverAction::UPDATE
					: (*proposed < *current ? DriverAction::DOWNGRADE : DriverAction::REINSTALL) ;
			candidate.discoveryBasis	  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
			candidate.audit				  = makeOfficialReadyCandidateAudit() ;
			candidate.installable		  = true ;
			candidate.allContentCached	  = true ;
			candidate.rebootMayBeRequired = true ;
			// 区分Bの汎用部品版を推奨・既定選択には昇格させない。
			candidate.recommended		= false ;
			candidate.defaultPreference = CandidateDefaultPreference::NONE ;
			targets_.emplace(
				candidate.identity,
				Target{.device = device.deviceIdentity, .packageIndex = index, .rank = rank}) ;
			result.candidates.push_back( std::move( candidate)) ;
		}

		++completed ;
		// 監査 API の失敗がなかった device だけを判定済み件数へ加える。
		if( !deviceFailed) {
			++assessed ;
		}

		progress( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
				  .percentComplete = static_cast<std::uint32_t>(
					  50U + completed * 50U / result.coverage.eligibleDeviceCount),
				  .completedItems = completed,
				  .totalItems	  = result.coverage.eligibleDeviceCount}) ;
	}

	result.coverage.assessedDeviceCount = assessed ;
	result.error						= auditError ;
	const MeasurementExtent auditExtent =
		auditError == 0 && !classificationIncomplete
			? MeasurementExtent::EXACT
			: MeasurementExtent::LOWER_BOUND ;	// 全対象監査の確定度。
	measurementEvidence_.information.extent	 = auditExtent ;
	measurementEvidence_.applicabilityExtent = auditExtent ;
	measurementEvidence_.readinessExtent	 = auditExtent ;
	// 監査失敗があり候補もない場合は scan 失敗として保持状態を失効させる。
	if( auditError != 0 && result.candidates.empty()) {
		result.state = ProviderScanState::FAILURE ;
		invalidatePreparedState() ;
		return result ;
	}

	result.succeeded = true ;
	result.outcome	 = auditError == 0 ? OutcomeCode::SUCCESS : OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	result.state	 = result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
												 : ProviderScanState::CANDIDATES_AVAILABLE ;
	return result ;
} catch( ...) {
	// Workerの例外報告へ委譲する前に、途中候補を破棄し先に確定した検索根拠だけを残す。
	invalidatePreparedState() ;
	throw ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult OfficialSerialProvider::install( const ScanSessionId				  session,
											  const std::span<const std::wstring> identities,
											  const std::uintptr_t				  parentWindow,
											  const LocalHardwareIdMatcher		 &matcher,
											  const OfficialSerialRankAuditor	 &rankAuditor,
											  const VerifiedExternalInfInstaller &installer,
											  const ProviderProgressCallback	 &progress)
try {
	InstallResult					 result ;							// 個別失敗を保持する導入結果。
	std::unordered_set<std::wstring> devices ;							// 一device一候補の検証集合。
	const SerialPolicy *const		 policy = serialPolicy( family_) ;	// Scanと同一の再検証契約。
	bool valid = policy != nullptr && session != 0U && session == session_ &&
				 ownerThread_ == GetCurrentThreadId() && contentsWorkspace_ &&
				 !identities.empty() && matcher && rankAuditor && installer && progress &&
				 !isWindowsServer() ;	// 再検証前に必要なsession条件。
	// 全選択を先に検証し、不正な後続IDがあれば一件も導入しない。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
		const auto target = targets_.find( identity) ;	// 保存済みopaque対象。
		// 未知候補または同じ device の重複選択があれば導入要求全体を無効とする。
		if( target == targets_.end() || !devices.insert( target->second.device).second) {
			valid = false ;
		}
	}

	std::size_t succeeded{} ;	// 実際にWindows導入が成功した件数。
	NativeError lastError{} ;	// 最後の失敗を成功後も保持する診断値。
	// 要求順に処理し、失敗後も個別結果を残す。
	for( std::size_t index = 0; index < result.updates.size(); ++index) {
		UpdateExecutionResult &update = result.updates[index] ;			// 今回の表示結果。
		NativeError error = static_cast<NativeError>( E_INVALIDARG) ;	// 入力不正時は導入しない。
		// 全選択の事前照合が成立した場合だけ保持 INF を再監査する。
		if( valid) {
			const Target			 &target = targets_.at( update.identity) ;	// 事前照合済みtarget。
			const OfficialInfPackage &package =
				// 保存INF。
				contents_.packages.at( target.packageIndex) ;
			error = policy->reverify( *contentsWorkspace_, contents_.entries, package) ;
			OfficialDriverRankAudit currentRank ;	// 直前のread-only監査結果。
			// INF 再検証に成功した場合だけ現在 device の rank を再確認する。
			if( error == 0) {
				error =
					auditOfficialSerialDevice( family_, session, target.device, *contentsWorkspace_,
											  package, matcher, rankAuditor, currentRank) ;
				// 現在 rank が保持した結果と異なる場合は古い選択による導入を拒否する。
				if( error == 0 && !sameRank( target.rank, currentRank)) {
					error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
				}
			}

			// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
			if( error == 0) {
				error = installer( session, target.device,
								  contentsWorkspace_->path( package.infRelativePath),
								  package.providerName, package.driverVersion, parentWindow,
								  update.rebootRequired) ;
			}
		}

		update.downloadOutcome = valid ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
		update.downloadError   = valid ? 0 : error ;
		update.installError	   = error ;
		update.installOutcome  = error == 0 ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
		result.rebootRequired  = result.rebootRequired || update.rebootRequired ;
		// 導入の正常終了だけを成功件数として集計する。
		if( error == 0) {
			++succeeded ;
		} else {
			lastError = error ;
		}

		// 進捗 callback がある場合だけ処理済み候補数から確定進捗を通知する。
		if( progress) {
			progress( {.stage = ProviderStage::INSTALLING,
					  .percentComplete =
						  static_cast<std::uint32_t>( (index + 1U) * 100U / result.updates.size()),
					  .completedItems = index + 1U,
					  .totalItems	  = result.updates.size()}) ;
		}
	}

	result.succeeded	   = valid && succeeded == identities.size() ;
	result.downloadOutcome = valid ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
	result.downloadError   = valid ? 0 : static_cast<NativeError>( E_INVALIDARG) ;
	result.installOutcome  = result.succeeded ? OutcomeCode::SUCCESS
											  : (succeeded != 0U ? OutcomeCode::SUCCEEDED_WITH_ERRORS
																 : OutcomeCode::FAILURE) ;
	result.installError =
		result.succeeded ? 0
						 : (lastError != 0 ? lastError : static_cast<NativeError>( E_INVALIDARG)) ;
	invalidate() ;
	return result ;
} catch( ...) {
	// 外側の保護installは復元ポイント終了と失敗報告を行う。再利用可能なtargetを残さない。
	invalidate() ;
	throw ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialSerialProvider::invalidatePreparedState() noexcept
{
	targets_.clear() ;
	contents_ = {} ;
	contentsWorkspace_.reset() ;
	http_.invalidateSourceSession() ;
	session_	 = 0U ;
	ownerThread_ = 0U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialSerialProvider::refreshMeasurementResources() noexcept
{
	static_cast<void>(
		summarizeOfficialSourceEvidence( http_.sourceEvidence(), measurementEvidence_.resources)) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_serial_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialSerialProvider::invalidate() noexcept
{
	invalidatePreparedState() ;
	measurementEvidence_ = {} ;
}
} // namespace drivercrate
