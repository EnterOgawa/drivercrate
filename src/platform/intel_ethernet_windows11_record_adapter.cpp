//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_windows11_record_adapter.cpp
 * @brief Intel ZIP releaseの共通record変換とWindows 11互換resolverの実装。
 * @version 01.05.00
 * @date 2026/09/15
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Intel record 727998用adapterを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  固定root typed resolverを実装。
 * Ver.01.01.01 Shunji Ogawa  2026/09/15  公開parser identity定数へ統一。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  三つのIntel ZIP系列の変換と根拠照合を共通化。
 * Ver.01.02.01 Shunji Ogawa  2026/09/23  共通化後の説明を三系列の実装範囲へ訂正。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  通常／収集field共有と727998の一時target照合を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  未知より明示矛盾を優先し配布欠測理由を補修。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  配布・許諾・identity・全対象へ同一controlを接続。
 * </pre>
 *
 * @note AdapterはProvider parserが選んだ一つのreleaseだけを変換し、URLやexact sizeを推測しません。
 *       共通record検証とgrant発行は後続のworker境界で行います。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/official_collector_public_text.h"

#include "core/official_source_policy.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view RECORD_ROUTE =
	L"intel-download-record" ;	// 組み込みrootからrecordへ到達するroute ID。
constexpr std::wstring_view PRODUCT_FAMILY =
	L"Intel Ethernet Network Adapters" ;									// Recordが明示する公開製品系列。
constexpr std::wstring_view OPERATING_SYSTEM = L"Microsoft Windows 11" ;	// 対象OS。
constexpr std::wstring_view CONTENT_TYPE	 = L"application/zip" ;			// ZIP応答の期待型。
constexpr std::uint64_t		MAXIMUM_PAYLOAD_BYTES =
	128ULL * 1'024ULL * 1'024ULL ;									// ADR 0152の検査用payload上限。
constexpr std::size_t MAXIMUM_FILE_NAME_CHARACTERS	   = 260U ;		// 公開basename上限。
constexpr std::size_t MAXIMUM_VERSION_CHARACTERS	   = 64U ;		// 配布版上限。
constexpr std::size_t MAXIMUM_DISPLAY_SIZE_CHARACTERS  = 32U ;		// 概算size上限。
constexpr std::size_t MAXIMUM_DATE_CHARACTERS		   = 128U ;		// 公開日表示上限。
constexpr std::size_t MAXIMUM_EULA_REVISION_CHARACTERS = 4'096U ;	// EULA識別子上限。
constexpr std::size_t MAXIMUM_EULA_CHARACTERS		   = 65'536U ;	// EULA plain text上限。
constexpr std::size_t MAXIMUM_URL_CHARACTERS		   = 8'192U ;	// Worker内秘密URL上限。
// 固定root引数の不整合を表す診断値。
constexpr NativeError INVALID_ARGUMENT = static_cast<NativeError>( E_INVALIDARG) ;
// 取得証拠の差替えを表す診断値。
constexpr NativeError SOURCE_ACCESS_DENIED = static_cast<NativeError>( E_ACCESSDENIED) ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief Plain textが有限で制御文字を含まないか確認します。
 * @param[in] value 検証する文字列。
 * @param[in] maximumCharacters 許可するUTF-16 code unit上限。
 * @param[in] allowEmpty 空文字列を許可する場合は`true`。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] allowLineBreaks Tab、CR、LFを許可する場合は`true`。
 * @return 指定した有限plain text条件を満たす場合は`true`。
 */
[[nodiscard]] bool	  isFiniteText( CollectorParserContext *control, const std::wstring_view value,
								   const std::size_t maximumCharacters, const bool allowEmpty,
								   const bool allowLineBreaks)
{
	collectorParserCheckpoint( control) ;
	// 空値の可否と文字数上限を文字走査前に確定する。
	if( (!allowEmpty && value.empty()) || value.size() > maximumCharacters) {
		return false ;
	}

	// 全code unitを確認し、許可した改行以外の制御文字を拒否する。
	for( const wchar_t character : value) {
		collectorParserStep( control) ;
		// EULA本文だけで許可する可視整形文字か示す。
		const bool allowedLineBreak =
			allowLineBreaks && (character == L'\t' || character == L'\r' || character == L'\n') ;
		// NUL、C0、DELを表示またはEULAへ残さない。
		if( !allowedLineBreak && (character < L' ' || character == L'\x7f')) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Intel pageが公表したuppercase SHA-256形式か確認します。
 * @param[in] value 検証するhash文字列。
 * @return 64桁のuppercase ASCII hexの場合は`true`。
 */
[[nodiscard]] bool isUpperSha256( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::ranges::all_of( value, []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'A' && character <= L'F') ;
		   }) ;
}

/**
 * @brief URLを除くIntel ZIP release fieldが選択familyのprofileと整合するか確認します。
 * @param[in] release 専用parserから得たrelease metadata。
 * @param[in] expectedFileName 配布版から構築した期待basename。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] parserRevision Familyに対応する既存parser版。
 * @return Family、parser revision、file、hash、EULAが全て整合する場合は`true`。
 */
[[nodiscard]] bool hasValidRelease( CollectorParserContext	   *control,
								   const OfficialReleaseRecord &release,
								   const std::wstring_view		expectedFileName,
								   const std::uint32_t			parserRevision)
{
	collectorParserCheckpoint( control) ;
	// 呼出し元が選んだfamilyと別parser版の結果を結合しない。
	if( release.parserRevision != parserRevision || !release.releaseKey.empty()) {
		return false ;
	}

	// File、版、概算表示、公開日とURLの有限性を再確認する。
	if( !isFiniteText( control, release.fileName, MAXIMUM_FILE_NAME_CHARACTERS, false, false) ||
	   release.fileName != expectedFileName ||
	   !isFiniteText( control, release.packageVersion, MAXIMUM_VERSION_CHARACTERS, false, false) ||
	   !isFiniteText( control, release.displaySize, MAXIMUM_DISPLAY_SIZE_CHARACTERS, false, false) ||
	   !isFiniteText( control, release.publishedDate, MAXIMUM_DATE_CHARACTERS, true, false) ||
	   !isFiniteText( control, release.downloadUrl, MAXIMUM_URL_CHARACTERS, false, false)) {
		return false ;
	}

	// Exact sizeが将来明示された場合も共通上限内の正数だけを保持する。
	if( release.publishedSizeBytes &&
	   (*release.publishedSizeBytes == 0U || *release.publishedSizeBytes > MAXIMUM_PAYLOAD_BYTES)) {
		return false ;
	}

	// 公開hashとdownload前EULA snapshotの欠落・型違いを拒否する。
	return isUpperSha256( release.publishedSha256) &&
		   release.license == OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD &&
		   isFiniteText( control, release.eulaRevision, MAXIMUM_EULA_REVISION_CHARACTERS, false,
						false) &&
		   isFiniteText( control, release.eulaText, MAXIMUM_EULA_CHARACTERS, false, true) ;
}

/**
 * @brief Adapterへ渡すroot evidenceとrecord時刻の最低限の整合性を確認します。
 * @param[in] evidence 固定root本文の取得証拠。
 * @param[in] recordEvidenceId Session内record証拠ID。
 * @param[in] resolvedUtcSeconds Record固定時刻。
 * @return Network本文、非cache、landing、単調時刻の条件を満たす場合は`true`。
 */
[[nodiscard]] bool hasValidRootBinding( const OfficialSourceEvidence &evidence,
									   const std::uint64_t			 recordEvidenceId,
									   const std::uint64_t			 resolvedUtcSeconds) noexcept
{
	// URL非保持evidenceの必須identityとnetwork本文取得状態を要求する。
	if( evidence.scanSessionId == 0U || evidence.acquisitionId == 0U ||
	   evidence.providerId.empty() || evidence.policyId.empty() ||
	   evidence.resourceId != OFFICIAL_LANDING_RESOURCE_ID ||
	   evidence.acquisition != MeasurementAcquisition::NETWORK_BODY || evidence.cachePermitted ||
	   !evidence.bodyAcquiredUtcSeconds || !evidence.originValidatedUtcSeconds ||
	   recordEvidenceId == 0U || resolvedUtcSeconds == 0U) {
		return false ;
	}

	return resolvedUtcSeconds >= *evidence.bodyAcquiredUtcSeconds &&
		   resolvedUtcSeconds >= *evidence.originValidatedUtcSeconds ;
}

/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 * @param[in] error 変換するWin32 error code。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/**
 * @brief 現在UTCをUnix epoch秒へ変換する。
 * @return 0ではないUTC秒。Clockがepoch以前または表現範囲外なら0。
 */
[[nodiscard]] std::uint64_t currentUtcSeconds() noexcept
{
	const auto now = std::chrono::system_clock::now().time_since_epoch() ;	// 現在のepoch差。
	const auto seconds =
		std::chrono::duration_cast<std::chrono::seconds>( now).count() ;	// 秒単位の符号付き値。
	// 負時刻または符号なし型へ収まらない時刻をrecordへ結合しない。
	if( seconds <= 0 ||
	   static_cast<std::uintmax_t>( seconds) > std::numeric_limits<std::uint64_t>::max()) {
		return 0U ;
	}

	return static_cast<std::uint64_t>( seconds) ;
}

/**
 * @brief 検証済みIntel releaseの配布fieldだけを通常／収集recordへ組み立てます。
 * @tparam Record URLをworker内で所有する通常recordまたは収集候補。
 * @param[in,out] release 既存parserで検証した配布情報。秘密URL等を結果へ移動します。
 * @param[in] definition 既知familyの固定source定義。
 * @param[in] recordEvidenceId 呼出元の0ではない一時IDまたは通常証拠ID。
 * @param[in] resolvedUtcSeconds 配布情報を解決したUTC秒。
 * @param[out] record 出典証拠以外の全配布field。
 * @note URLやrootの検証結果を本関数の呼出しだけから推論しません。
 */
template <class Record>
void fillIntelZipRecordFields( OfficialReleaseRecord			&&release,
							  const OfficialSourceDefinition &definition,
							  const std::uint64_t			  recordEvidenceId,
							  const std::uint64_t resolvedUtcSeconds, Record &record)
{
	const bool wifi = release.family == OfficialReleaseFamily::INTEL_WIFI ;	// 固定ZIP系列。
	const bool server =
		// Server限定系列。
		release.family == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ;
	record.recordEvidenceId	  = recordEvidenceId ;
	record.parserId			  = wifi	 ? L"intel-wifi-zip-page"
								: server ? L"intel-server-zip-page"
										 : std::wstring{INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_ID} ;
	record.parserRevision	  = release.parserRevision ;
	record.recordRoute		  = RECORD_ROUTE ;
	record.recordKey		  = definition.productKey ;
	record.productFamily	  = wifi ? L"Intel Wireless Wi-Fi Adapters" : PRODUCT_FAMILY ;
	record.operatingSystem	  = server ? L"Windows Server 2025"
								: wifi ? L"Windows 10 and Windows 11"
									   : OPERATING_SYSTEM ;
	record.architecture		  = OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	  = std::move( release.packageVersion) ;
	record.publishedDate	  = std::move( release.publishedDate) ;
	record.terms			  = OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
	record.eulaRevision		  = std::move( release.eulaRevision) ;
	record.eulaText			  = std::move( release.eulaText) ;
	record.resolvedUtcSeconds = resolvedUtcSeconds ;
	record.payloads.reserve( 1U) ;
	OfficialDistributionPayloadRecord payload ;	// 一配布だけを保持するZIP。
	payload.resourceId			= OFFICIAL_PAYLOAD_RESOURCE_ID ;
	payload.payloadOrdinal		= 0U ;
	payload.kind				= OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ;
	payload.fileDisplayName		= std::move( release.fileName) ;
	payload.publishedSizeBytes	= release.publishedSizeBytes ;
	payload.publishedSha256		= std::move( release.publishedSha256) ;
	payload.expectedContentType = CONTENT_TYPE ;
	payload.maximumBytes		= MAXIMUM_PAYLOAD_BYTES ;
	payload.targetUrl			= SecretOfficialUrl{std::move( release.downloadUrl)} ;
	record.payloads.push_back( std::move( payload)) ;
}

/**
 * @brief 公開target fieldの有限性と制御文字／URL混入を検査します。
 * @param[in] value 明示された公開値。
 * @param[in] maximum UTF-16 code unit上限。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] allowEmpty 任意chip fieldに限り空を許可します。
 * @return 公開値として成立すればtrue。
 */
[[nodiscard]] bool validCollectorText( CollectorParserContext *control,
									  const std::wstring_view value, const std::size_t maximum,
									  const bool allowEmpty = false)
{
	collectorParserCheckpoint( control) ;
	// 空値と上限超過は公開targetとして扱いません。
	if( value.size() > maximum || (!allowEmpty && value.empty()) ||
	   !(control != nullptr ? isOfficialCollectorPublicTextForCollector(
								  value, 1'024U, OfficialCollectorPublicTextKind::TEXT, *control)
							: isOfficialCollectorPublicText( value, 1'024U))) {
		return false ;
	}

	// URL、制御文字、pathを公開照合値へ混ぜません。
	for( const wchar_t ch : value) {
		collectorParserStep( control) ;
		// 一文字でも不正ならtargetだけを不明へ落とします。
		if( ch < L' ' || (ch >= L'\x7f' && ch <= L'\x9f') || ch == L'/' || ch == L'\\' ||
		   ch == L'?' || ch == L'#' || ch == L'&' || ch == L'=') {
			return false ;
		}
	}

	return collectorParserFind( control, value, L"://") == std::wstring_view::npos ;
}

/**
 * @brief 公開target名を一覧と同じNFC比較表現へ変換します。
 * @param[in] model 明示された公開製品名。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] comparison 成功時のNFC比較名。
 * @return 有限公開名ならtrue。
 */
[[nodiscard]] bool collectorComparisonName( CollectorParserContext *control,
										   const std::wstring_view model, std::wstring &comparison)
{
	collectorParserCheckpoint( control) ;
	comparison.clear() ;
	// 比較名は通常の表示文字列だけを受け付けます。
	if( !validCollectorText( control, model, 256U) || model.front() == L' ' || model.back() == L' ' ||
	   collectorParserFind( control, model, L"  ") != std::wstring_view::npos) {
		return false ;
	}

	std::array<wchar_t, 512U> buffer{} ;	// Windows NFCの有限出力。
	const int				  length =
		NormalizeString( NormalizationC, model.data(), static_cast<int>( model.size()), buffer.data(),
						// 実NFC出力長。
						static_cast<int>( buffer.size())) ;
	// 新経路ではAPI原値を名前不採用に潰しません。
	if( length <= 0 && control != nullptr) {
		control->failed( CollectorIoErrorDomain::WIN32_ERROR, GetLastError()) ;
	}

	collectorParserCheckpoint( control) ;
	// APIが失敗した場合や製品名上限を越す場合は推測補完しません。
	if( length <= 0 || length > 256) {
		return false ;
	}

	comparison.assign( buffer.data(), static_cast<std::size_t>( length)) ;
	return validCollectorText( control, comparison, 256U) ;
}

/**
 * @brief 公開target入力のschemaを確認します。
 * @param[in] query 一対象の公開条件。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] comparison 正規化した製品名。
 * @return 必須公開fieldが有効ならtrue。
 */
[[nodiscard]] bool validCollectorQuery( CollectorParserContext		   *control,
									   const IntelCollectorTargetQuery &query,
									   std::wstring					   &comparison)
{
	collectorParserCheckpoint( control) ;
	return validCollectorText( control, query.targetKey, 128U) &&
		   validCollectorText( control, query.maker, 128U) &&
		   collectorComparisonName( control, query.model, comparison) &&
		   validCollectorText( control, query.kind, 64U) &&
		   validCollectorText( control, query.purpose, 64U) &&
		   validCollectorText( control, query.operatingSystem, 64U) &&
		   validCollectorText( control, query.architecture, 32U) &&
		   validCollectorText( control, query.chip, 128U, true) ;
}

/**
 * @brief 優先順位に従って確定した三状態を記録します。
 * @param[out] target 一時判定結果。
 * @param[in] state 確定した状態。
 * @param[in] reason 同じ状態内の最初の軸理由。
 */
void setCollectorState( IntelCollectorTargetAssessment  &target,
					   const IntelCollectorTargetState	state,
					   const IntelCollectorTargetReason reason) noexcept
{
	target.state  = state ;
	target.reason = reason ;
}

/**
 * @brief 一つの対象と同一本文の一時候補を取得権限なしで照合します。
 * @param[in] query 一対象の公開条件。
 * @param[in] identity 同一本文の採用済み製品集合。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in,out] target 確定した状態と採用製品名を設定します。
 */
void assessCollectorTarget( CollectorParserContext *control, const IntelCollectorTargetQuery &query,
						   const IntelCollectorIdentityResult &identity,
						   IntelCollectorTargetAssessment	  &target)
{
	collectorParserCheckpoint( control) ;
	std::wstring comparison ;	// NFCへ正規化した対象製品名。
	// 不正な公開fieldを不適合と断定しません。
	if( !validCollectorQuery( control, query, comparison)) {
		setCollectorState( target, IntelCollectorTargetState::UNKNOWN,
						  IntelCollectorTargetReason::INVALID_QUERY) ;
		return ;
	}

	// 固定公式pageと明示的に矛盾するmaker／kindだけをNO_MATCHにします。
	if( query.maker != L"Intel" || query.kind != L"NETWORK_ADAPTER") {
		setCollectorState( target, IntelCollectorTargetState::NO_MATCH,
						  IntelCollectorTargetReason::PRODUCT_CONFLICT) ;
		return ;
	}

	const auto product = std::find_if( identity.products.begin(), identity.products.end(),
									  [&]( const IntelCollectorProductIdentity &item) {
										  collectorParserStep( control) ;
										  return item.comparisonName == comparison ;
									  }) ; // 元一覧の一意な一致identity。
	IntelCollectorTargetReason unknown = IntelCollectorTargetReason::MATCHED ;	// 最初の未知軸。
	// 未掲載は一覧にないことだけを示し、非対応の証拠にはしません。
	if( product == identity.products.end()) {
		unknown = identity.collisions != 0U ? IntelCollectorTargetReason::PRODUCT_AMBIGUOUS
											: IntelCollectorTargetReason::PRODUCT_UNLISTED ;
	} else {
		target.sku			  = product->sku ;
		target.displayName	  = product->displayName ;
		target.comparisonName = product->comparisonName ;
	}

	// 未掲載でも後続軸の明示矛盾を調べ、未知より優先します。
	if( query.purpose != L"Ethernet") {
		// 既知の別用途は元一覧の未掲載より優先する明示矛盾です。
		if( query.purpose == L"Wi-Fi" || query.purpose == L"Bluetooth") {
			setCollectorState( target, IntelCollectorTargetState::NO_MATCH,
							  IntelCollectorTargetReason::PURPOSE_CONFLICT) ;
			return ;
		}

		// 未知は同種類の最初の軸だけを残します。
		if( unknown == IntelCollectorTargetReason::MATCHED) {
			unknown = IntelCollectorTargetReason::PURPOSE_UNKNOWN ;
		}
	}

	// OSの未知表記は同義・不適合と推測しません。
	if( query.operatingSystem != L"Windows 11") {
		const bool conflict = query.operatingSystem == L"Windows 10" ||
							  // 既知の別OS。
							  query.operatingSystem == L"Windows Server 2025" ;
		// 検証済みprofileと異なる既知OSは明示矛盾です。
		if( conflict) {
			setCollectorState( target, IntelCollectorTargetState::NO_MATCH,
							  IntelCollectorTargetReason::OS_CONFLICT) ;
			return ;
		}

		// 前段の未知理由を後段の未知で上書きしません。
		if( unknown == IntelCollectorTargetReason::MATCHED) {
			unknown = IntelCollectorTargetReason::OS_UNKNOWN ;
		}
	}

	// Architectureも明示の別値だけを矛盾とします。
	if( query.architecture != L"x64") {
		const bool conflict = query.architecture == L"x86" ||
							  // 既知の別architecture。
							  query.architecture == L"arm64" ;
		// 既知の異なるarchitectureだけを明示矛盾にします。
		if( conflict) {
			setCollectorState( target, IntelCollectorTargetState::NO_MATCH,
							  IntelCollectorTargetReason::ARCHITECTURE_CONFLICT) ;
			return ;
		}

		// 最初の未知を保持しつつ残るchip軸へ進みます。
		if( unknown == IntelCollectorTargetReason::MATCHED) {
			unknown = IntelCollectorTargetReason::ARCHITECTURE_UNKNOWN ;
		}
	}

	// Chipの独立構造証拠はこのHTMLから得られません。
	if( !query.chip.empty() && unknown == IntelCollectorTargetReason::MATCHED) {
		unknown = IntelCollectorTargetReason::CHIP_UNKNOWN ;
	}

	setCollectorState( target,
					  unknown == IntelCollectorTargetReason::MATCHED
						  ? IntelCollectorTargetState::MATCH
						  : IntelCollectorTargetState::UNKNOWN,
					  unknown) ;
}

} // namespace

//------------------------------------------------------------------------------
/** @brief 旧入口と制御付き入口で配布・一覧・全対象を同じ順序で照合します。
 * @param[in,out] control 新経路の制御。旧入口だけnull。
 * @param[in] html 同一本文。
 * @param[in] targets 全公開対象。
 * @param[in] resolvedUtcSeconds 本文の解決時刻。
 * @param[out] assessment 所有照合結果。
 * @return 集合契約の成立。
 */
static bool inspectIntelCollectorMetadataPageCore(
	CollectorParserContext *control, const std::wstring_view html,
	const std::span<const IntelCollectorTargetQuery> targets,
	const std::uint64_t resolvedUtcSeconds, IntelCollectorMetadataAssessment &assessment)
{
	collectorParserCheckpoint( control) ;
	assessment = {} ;
	// 意味のない時刻や有限上限外の集合を一括で拒否します。
	// 集合の明示上限だけをLIMITへ分離します。
	if( targets.size() > 300U) {
		collectorParserLimit( control) ;
	}

	// 公開時刻・非空集合の契約を確認します。
	if( resolvedUtcSeconds == 0U || targets.empty() || targets.size() > 300U) {
		return false ;
	}

	// 重複keyは対象edgeの帰属を曖昧にするため全体拒否します。
	for( std::size_t index = 0U; index < targets.size(); ++index) {
		collectorParserStep( control) ;
		// Keyだけはtargetごとの診断ではなく集合の契約です。
		if( !validCollectorText( control, targets[index].targetKey, 128U)) {
			return false ;
		}

		// 最大300件なので既出keyを有限の線形走査で確認します。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			collectorParserStep( control) ;
			// 同じkeyを二つの対象へ割り当てません。
			if( targets[index].targetKey == targets[previous].targetKey) {
				return false ;
			}
		}
	}

	try {
		IntelCollectorMetadataAssessment parsed ;	// 全検査後にだけ公開する一時結果。
		OfficialReleaseRecord			 release ;	// 旧727998 parserの所有結果。
		const bool						 releaseParsed =
			  control != nullptr
									  ? parseIntelCollectorReleaseRecord( html, release, *control)
									  : parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, html,
																   release) ;	// 配布解析結果。
		// 同じ借用HTMLから製品一覧を読み、配布URLをheroへ結合します。
		if( control != nullptr) {
			const auto result = parseIntelCollectorProductIdentityControlled(
				html, releaseParsed ? std::wstring_view( release.downloadUrl) : std::wstring_view{},
				// 同じcontrolの下位終了値。
				control->httpControl(), parsed.identity) ;
			// 構造／上限／停止／OOMを配布欠測へ変換しません。
			if( result.status != CollectorParserStatus::COMPLETED) {
				throw CollectorParserFailure{result} ;
			}
		}
		// 旧経路では従来のsource状態を維持します。
		else if( releaseParsed) {
			parsed.identity =
				parseIntelCollectorProductIdentityForPayload( html, release.downloadUrl) ;
		} else {
			parsed.identity = parseIntelCollectorProductIdentity( html) ;
		}

		const auto *definition = officialSourceDefinition(
			OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 固定公式source。
		const bool identityBound =
			parsed.identity.status == IntelCollectorIdentityStatus::ACCEPTED ||
			parsed.identity.status ==
				IntelCollectorIdentityStatus::PARTIAL_REJECTED ;	// 不正行は除外済み。
		const bool releaseValid =
			releaseParsed && definition != nullptr &&
			release.family == OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11 &&
			hasValidRelease(
				control, release, L"Wired_driver_" + release.packageVersion + L"_x64.zip",
				INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION) ;	// Hero所属とは独立の配布条件。
		// 配布情報と同一heroが成立した場合だけ証拠未発行の候補を作ります。
		if( releaseValid && identityBound) {
			OfficialCollectorRecordCandidate candidate ;	// GET根拠を含まない一時record。
			fillIntelZipRecordFields( std::move( release), *definition, 1U, resolvedUtcSeconds,
									 candidate) ;
			parsed.candidate	 = std::move( candidate) ;
			parsed.releaseParsed = true ;
		}

		parsed.targets.reserve( targets.size()) ;
		// 入力順と分母を保ち、個別不明も省略しません。
		for( const auto &query : targets) {
			collectorParserCheckpoint( control) ;
			IntelCollectorTargetAssessment target ;	// 現在の公開target案。
			target.targetKey = query.targetKey ;
			// 配布候補がない場合は明示不一致を作りません。
			if( parsed.candidate) {
				target.candidateOrdinal = 0U ;
				assessCollectorTarget( control, query, parsed.identity, target) ;
			} else {
				target.reason = releaseValid ? IntelCollectorTargetReason::IDENTITY_UNKNOWN
											 : IntelCollectorTargetReason::RELEASE_UNKNOWN ;
			}

			parsed.targets.push_back( std::move( target)) ;
			collectorParserCheckpoint( control) ;
		}

		assessment = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		// 新経路だけ原OOMを保持します。
		if( control != nullptr) {
			throw ;
		}

		assessment = {} ;
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_ethernet_windows11_record_adapter.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool adaptIntelEthernetWindows11DistributionRecord( OfficialReleaseRecord	   &&release,
												   const OfficialSourceEvidence &rootEvidence,
												   const std::uint64_t			 recordEvidenceId,
												   const std::uint64_t			 resolvedUtcSeconds,
												   OfficialDistributionRecord	&record)
{
	record = {} ;
	// 旧APIへ別familyを渡した場合は共通変換へ進めない。
	if( release.family != OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) {
		return false ;
	}

	return adaptIntelZipDistributionRecord( std::move( release), rootEvidence, recordEvidenceId,
										   resolvedUtcSeconds, record) ;
}

/** @see intel_ethernet_windows11_record_adapter.h */
bool adaptIntelZipDistributionRecord( OfficialReleaseRecord		 &&release,
									 const OfficialSourceEvidence &rootEvidence,
									 const std::uint64_t		   recordEvidenceId,
									 const std::uint64_t		   resolvedUtcSeconds,
									 OfficialDistributionRecord	  &record)
{
	record = {} ;
	try {
		const auto *definition = officialSourceDefinition( release.family) ;		// 組み込みfamily定義。
		const bool	wifi = release.family == OfficialReleaseFamily::INTEL_WIFI ;	// ZIP配布種別。
		const bool	server =
			// OS別配布。
			release.family == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ;
		// 審査済みの三parser以外を名前やURLからIntelと推測しない。
		if( definition == nullptr ||
		   (!wifi && !server &&
			release.family != OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ||
		   rootEvidence.providerId != definition->providerId ||
		   rootEvidence.policyId != definition->sourceId) {
			return false ;
		}

		const std::uint32_t revision =
			wifi	 ? 2U
			: server ? 2U
					 : INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION ;	// 既存parser契約。
		const std::wstring expectedFileName =
			wifi
				? L"WiFi-" + release.packageVersion + L"-Driver64-Win10-Win11.zip"
				: L"Wired_driver_" + release.packageVersion + L"_x64.zip" ;	// 公開版と配布名の結合。
		// Provider parser結果とroot bindingが揃わなければ秘密URLを移動しない。
		if( !hasValidRelease( nullptr, release, expectedFileName, revision) ||
		   !hasValidRootBinding( rootEvidence, recordEvidenceId, resolvedUtcSeconds)) {
			return false ;
		}

		OfficialDistributionRecord parsed ;	// 全field設定後だけ公開する一時record。
		parsed.rootEvidence = rootEvidence ;
		fillIntelZipRecordFields( std::move( release), *definition, recordEvidenceId,
								 resolvedUtcSeconds, parsed) ;

		record = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		record = {} ;
		return false ;
	}
}

/** @see intel_ethernet_windows11_record_adapter.h */
OfficialDiscoveryFixedRootResult resolveIntelEthernetWindows11OfficialDiscoveryRecord(
	const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
	const std::wstring_view providerId, const std::wstring_view rootResourceId,
	const std::wstring_view builtInRootUrl, const std::uint64_t maximumRecordBytes,
	const OfficialRecordFetchMode fetchMode, OfficialHttpClient &client,
	OfficialDistributionRecord &record)
{
	record											 = {} ;
	const OfficialSourceDefinition *const definition = officialSourceDefinition(
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 審査済み固定検索定義。
	// Registryから渡された固定値だけをproduction readerへ接続する。
	if( scanSessionId == 0U || recordEvidenceId == 0U || definition == nullptr ||
	   providerId != definition->providerId || rootResourceId != OFFICIAL_LANDING_RESOURCE_ID ||
	   builtInRootUrl != definition->landingUrl ||
	   maximumRecordBytes != definition->maximumMetadataBytes ||
	   maximumRecordBytes > OFFICIAL_DISCOVERY_RECORD_BYTES_LIMIT ||
	   fetchMode != OfficialRecordFetchMode::BYPASS_CACHE || client.usesCatalogCache()) {
		return {.state = OfficialDiscoveryFixedRootState::METADATA_REJECTED,
				.error = INVALID_ARGUMENT} ;
	}

	OfficialReleaseRecord release ;				// Windows 11専用parserのworker内出力。
	bool				  metadataRejected{} ;	// 取得後schema拒否時だけtrue。
	const NativeError	  readError = readOfficialReleaseMetadata(
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, scanSessionId, client, release,
		metadataRejected) ;	// Cacheなしの固定root取得結果。
	// Schema拒否を通常通信失敗へ縮退させず、両方とも秘密recordを返さない。
	if( readError != 0 || metadataRejected) {
		return {.state = metadataRejected ? OfficialDiscoveryFixedRootState::METADATA_REJECTED
										  : OfficialDiscoveryFixedRootState::FAILED,
				.error = readError != 0 ? readError : nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	}

	const std::span evidence = client.sourceEvidence() ;	// URL非保持の現在session取得根拠。
	const OfficialSourcePolicy *const policy =
		// Registryと一致させる公式policy。
		officialSourcePolicyForProvider( providerId) ;
	// 単一landing network本文以外の根拠をrecord 727998へ結合しない。
	if( policy == nullptr || evidence.size() != 1U ||
	   !isValidOfficialSourceEvidence( evidence.front()) ||
	   evidence.front().scanSessionId != scanSessionId ||
	   evidence.front().providerId != providerId || evidence.front().policyId != policy->id ||
	   evidence.front().resourceId != rootResourceId ||
	   evidence.front().acquisition != MeasurementAcquisition::NETWORK_BODY ||
	   evidence.front().cachePermitted) {
		return {.state = OfficialDiscoveryFixedRootState::SOURCE_REJECTED,
				.error = SOURCE_ACCESS_DENIED} ;
	}

	const std::uint64_t resolvedUtcSeconds = currentUtcSeconds() ;	// Root検証後のrecord固定時刻。
	// 時刻とroot取得証拠を一つの型付きrecordへ結合する。
	if( resolvedUtcSeconds == 0U ||
	   !adaptIntelEthernetWindows11DistributionRecord(
		   std::move( release), evidence.front(), recordEvidenceId, resolvedUtcSeconds, record)) {
		record = {} ;
		return {.state = OfficialDiscoveryFixedRootState::METADATA_REJECTED,
				.error = nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	}

	return {.state = OfficialDiscoveryFixedRootState::RESOLVED, .error = 0} ;
}

/** @see intel_ethernet_windows11_record_adapter.h */
bool inspectIntelCollectorMetadataPage( std::wstring_view						  html,
									   std::span<const IntelCollectorTargetQuery> targets,
									   std::uint64_t					 resolvedUtcSeconds,
									   IntelCollectorMetadataAssessment &assessment)
{
	return inspectIntelCollectorMetadataPageCore( nullptr, html, targets, resolvedUtcSeconds,
												 assessment) ;
}

/** @see intel_ethernet_windows11_record_adapter.h */
CollectorParserResult inspectIntelCollectorMetadataPageControlled(
	std::wstring_view html, std::span<const IntelCollectorTargetQuery> targets,
	std::uint64_t resolvedUtcSeconds, OfficialCollectorHttpControl &control,
	IntelCollectorMetadataAssessment &assessment)
{
	assessment = {} ;
	IntelCollectorMetadataAssessment parsed ;	// 完了後だけ公開する値。
	const auto outcome = runCollectorParser( control, [&]( CollectorParserContext &context) {
		return inspectIntelCollectorMetadataPageCore( &context, html, targets, resolvedUtcSeconds,
													 parsed) ;
	}) ; // 配布・許諾・一覧・全対象の同じ制御。
	// 停止や部分処理から候補を公開しません。
	if( outcome.status == CollectorParserStatus::COMPLETED) {
		assessment = std::move( parsed) ;
	}

	return outcome ;
}

} // namespace drivercrate
