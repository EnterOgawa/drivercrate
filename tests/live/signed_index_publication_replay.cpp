//------------------------------------------------------------------------------
/**
 * @file signed_index_publication_replay.cpp
 * @brief 保存公式応答と実ZIPを索引監査・候補公開まで非通信で再生します。
 * @version 01.00.00
 * @date 2026/10/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/15  同byteの取得後全経路と非機密例外観測を追加。
 * </pre>
 *
 * @note HTTP・DNS・回線分類だけを人工応答へ置換します。CAT・INF・rankは実APIです。
 *       実GET・通常画面正常・実導入へ計上せず、秘密pathやIDを出力しません。
 * @see docs/adr/0330-function-first-collector-and-app-acceptance.md
 */
//------------------------------------------------------------------------------
#include "core/candidate_assessment.h"
#include "core/official_preparation_operation.h"
#include "core/provider_registry.h"
#include "local_index_acceptance.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"
#include "platform/official_acquisition.h"
#include "platform/official_file_verifier.h"
#include "platform/official_http_transport.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_candidate_binding_internal.h"
#include "platform/signed_index_scan.h"
#include "platform/signed_index_store.h"
#include "platform/windows_product_type.h"

#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
/** @brief 元二応答だけを同threadへ固定する非通信transport状態です。 */
struct Replay {
	/// 同SHAの保存ZIPです。表示しません。
	std::filesystem::path zip ;
	/// 元公式配布pageの保存本文です。表示しません。
	std::filesystem::path html ;
	/// 同一取得中だけ開く実原byte streamです。
	std::ifstream		  input ;
	/// 現応答の未読byte数です。
	std::uint64_t		  remaining{} ;
	/// 元ZIP応答の場合true、元HTML応答の場合falseです。
	bool				  payload{} ;
	/// 検証した接続先がpayload hostの場合trueです。
	bool				  payloadHost{} ;
	/// 一期のsession非所有tokenです。
	int					  session{} ;
	/// 一期のconnection非所有tokenです。
	int					  connection{} ;
	/// 一期のrequest非所有tokenです。
	int					  request{} ;
	/// 保存payload応答を開いた実回数です。実GET数ではありません。
	unsigned			  payloadReplays{} ;
	/// 保存HTML応答を開いた実回数です。
	unsigned			  htmlReplays{} ;
} ;
// 同threadの診断呼出し中だけ借用します。
thread_local Replay *activeReplay{} ;

/** @brief 人工回線分類を非通信再生だけへ固定します。 */
class ReplayCost	 final : public drivercrate::IOfficialNetworkCostReader {
public:
	/** @brief 再生を許す人工回線分類を返します。
	 * @param[out] cost 常にUNRESTRICTEDです。実回線観測ではありません。
	 * @return 人工応答の成功0です。
	 */
	drivercrate::NativeError read( drivercrate::OfficialNetworkCostKind &cost) noexcept override
	{
		cost = drivercrate::OfficialNetworkCostKind::UNRESTRICTED ;
		return 0U ;
	}
} ;
/** @brief 同期観測と私有sessionを全return・例外経路で解除します。 */
struct SessionEnd {
	/// 同scope終端まで生存する元sessionです。
	drivercrate::SignedIndexScanSession &session ;
	/** @brief 元tokenを実issuer生存中に破棄し、同期観測を解除します。 */
	~SessionEnd() noexcept
	{
		session.invalidate() ;
		drivercrate::signed_index_candidate_binding_detail::Access::observePublication( nullptr,
																					   nullptr) ;
		activeReplay = nullptr ;
	}
} ;

/** @brief 固定二host以外を再生transportでも拒否します。
 * @param[in] host 元clientが検証したhostです。保存しません。
 * @return 固定二hostならtrueです。
 */
[[nodiscard]] bool knownHost( const std::wstring_view host) noexcept
{
	return host == L"www.intel.com" || host == L"downloadmirror.intel.com" ;
}

/** @brief 完全な低位HTTP表を元保存応答だけへ接続します。
 * @return 実networkへfallbackしない全関数表です。
 */
[[nodiscard]] drivercrate::OfficialHttpTransport transport()
{
	drivercrate::OfficialHttpTransport result ;	// 全低位関数を以下で置換します。
	// session・connection・requestは同thread内の非所有tokenだけです。
	result.open = +[]( LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) noexcept -> HINTERNET {
		return &activeReplay->session ;
	} ;
	result.connect = +[]( HINTERNET, LPCWSTR host, INTERNET_PORT port, DWORD) noexcept -> HINTERNET {
		// 固定公式host・HTTPS以外から保存byteを読みません。
		if( !host || !knownHost( host) || port != INTERNET_DEFAULT_HTTPS_PORT) {
			SetLastError( ERROR_ACCESS_DENIED) ;
			return nullptr ;
		}

		activeReplay->payloadHost = std::wstring_view( host) == L"downloadmirror.intel.com" ;
		return &activeReplay->connection ;
	} ;
	// 元検証済みGETの完全pathだけに対応する同SHA fileを開きます。
	result.openRequest = +[]( HINTERNET, LPCWSTR verb, LPCWSTR path, LPCWSTR, LPCWSTR, LPCWSTR *,
							 DWORD flags) noexcept -> HINTERNET {
		try {
			const bool payload = activeReplay->payloadHost ;	// 同接続先の応答種別です。
			const auto expected =
				payload
					? L"/923981/Wired_driver_31.2.2_x64.zip"
					// 元公式routeです。
					: L"/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html" ;
			// 別route、別method、再生上限超過を元応答へ補完しません。
			if( !verb || std::wstring_view( verb) != L"GET" || !path ||
			   std::wstring_view( path) != expected || (flags & WINHTTP_FLAG_SECURE) == 0U ||
			   (payload ? activeReplay->payloadReplays >= 1U : activeReplay->htmlReplays >= 2U)) {
				SetLastError( ERROR_ACCESS_DENIED) ;
				return nullptr ;
			}

			activeReplay->input.close() ;
			activeReplay->input.clear() ;
			activeReplay->input.open( payload ? activeReplay->zip : activeReplay->html,
									 std::ios::binary) ;
			// 読出失敗を空の成功応答へ変更しません。
			if( !activeReplay->input) {
				SetLastError( ERROR_READ_FAULT) ;
				return nullptr ;
			}

			activeReplay->payload	= payload ;
			activeReplay->remaining = payload ? 40477087U : 173557U ;
			activeReplay->payloadReplays += payload ? 1U : 0U ;
			activeReplay->htmlReplays += payload ? 0U : 1U ;
			return &activeReplay->request ;
		} catch( ...) {
			SetLastError( ERROR_READ_FAULT) ;
			return nullptr ;
		}
	} ;
	// 待機・設定・送信・応答は人工transport内で完結し、実WinHTTPを呼びません。
	result.setTimeouts = +[]( HINTERNET, int, int, int, int) noexcept -> BOOL { return TRUE ; } ;
	result.setOption   = +[]( HINTERNET, DWORD, LPVOID, DWORD) noexcept -> BOOL { return TRUE ; } ;
	result.addHeaders  = +[]( HINTERNET, LPCWSTR, DWORD, DWORD) noexcept -> BOOL { return TRUE ; } ;
	result.sendRequest = +[]( HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD,
							 DWORD_PTR) noexcept -> BOOL { return TRUE ; } ;
	result.receiveResponse = +[]( HINTERNET, LPVOID) noexcept -> BOOL { return TRUE ; } ;
	// 元byte数・形式だけを有限headerとして返し、未知headerを補完しません。
	result.queryHeaders = +[]( HINTERNET, DWORD query, LPCWSTR, LPVOID buffer, LPDWORD bytes,
							  LPDWORD index) noexcept -> BOOL {
		// 数値status以外を数値headerへ偽装しません。
		if( query == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER) && buffer &&
		   *bytes >= sizeof( DWORD)) {
			*static_cast<DWORD *>( buffer) = 200U ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const wchar_t *text =
			query == WINHTTP_QUERY_CONTENT_TYPE
				? (activeReplay->payload ? L"application/zip" : L"text/html; charset=UTF-8")
			: query == WINHTTP_QUERY_CONTENT_LENGTH
				? (activeReplay->payload ? L"40477087" : L"173557")
				: nullptr ;	// 固定応答headerです。
		// 未取得headerを別値へ推測しません。
		if( !text || (index && *index != 0U)) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto needed =
			// 終端を含む容量です。
			static_cast<DWORD>( (std::wcslen( text) + 1U) * sizeof( wchar_t)) ;
		// WinHTTPと同じ容量照会を実施します。
		if( !buffer || *bytes < needed) {
			*bytes = needed ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( buffer, text, needed) ;
		*bytes = needed - sizeof( wchar_t) ;
		// 同名headerは一件だけです。本照会後は位置を前進させます。
		if( index) {
			++*index ;
		}

		return TRUE ;
	} ;
	// 同streamの確定未読byteだけを返し、時間に基づく進捗を生成しません。
	result.queryAvailable = +[]( HINTERNET, LPDWORD bytes) noexcept -> BOOL {
		*bytes = static_cast<DWORD>( std::min<std::uint64_t>( activeReplay->remaining, 65536U)) ;
		return TRUE ;
	} ;
	// 保存済み物理byteを通常共通取得の出力fileへそのまま渡します。
	result.readData =
		+[]( HINTERNET, LPVOID buffer, DWORD maximum, LPDWORD received) noexcept -> BOOL {
		const auto count = static_cast<DWORD>(
			std::min<std::uint64_t>( maximum, activeReplay->remaining)) ;	// 上限内要求だけです。
		activeReplay->input.read( static_cast<char *>( buffer), count) ;
		*received = static_cast<DWORD>( activeReplay->input.gcount()) ;
		activeReplay->remaining -= *received ;
		// 途中EOFやI/O異常を短い正常応答へ補完しません。
		if( *received != count) {
			SetLastError( ERROR_READ_FAULT) ;
			return FALSE ;
		}

		return TRUE ;
	} ;
	result.closeHandle = +[]( HINTERNET) noexcept -> BOOL { return TRUE ; } ;
	// 人工DNSは固定二hostへpublic分類の一addressだけを返します。実DNS根拠ではありません。
	result.resolveDestination =
		[]( const std::wstring_view									 host,
		   std::vector<drivercrate::OfficialResolvedNetworkAddress> &addresses) {
			addresses.clear() ;
			// 別hostや任意宛先の再生を認めません。
			if( !knownHost( host)) {
				return static_cast<drivercrate::NativeError>( E_ACCESSDENIED) ;
			}

			drivercrate::OfficialResolvedNetworkAddress address ;	// 非通信のpublic分類fixtureです。
			address.bytes[0] = std::byte{8} ;
			address.bytes[1] = std::byte{8} ;
			address.bytes[2] = std::byte{8} ;
			address.bytes[3] = std::byte{8} ;
			addresses.push_back( address) ;
			return drivercrate::NativeError{} ;
		} ;
	result.utcNow = []() {
		return static_cast<std::uint64_t>(
			std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now())
				.time_since_epoch()
				.count()) ;
	} ;
	return result ;
}

/** @brief 元公開条件の数値だけを即時保存できるstdoutへ通知します。
 * @param[in] value 原文字列を含まない同期snapshotです。
 * @param[in,out] state 未使用の非所有状態です。
 */
void publication(
	const drivercrate::signed_index_candidate_binding_detail::PublicationDiagnostic &value,
	void																			*state) noexcept
{
	static_cast<void>( state) ;
	std::printf(
		"PUBLICATION stage=%u ordinal=%zu current=%u providerMatch=%u versionMatch=%u contextValid=%u originValid=%u observationValid=%u ready=%u base=%zu extension=%zu component=%zu verifiedNeeds=%zu additionalMembers=%zu\n",
		value.stage, value.infOrdinal, static_cast<unsigned>( value.candidateCurrent),
		static_cast<unsigned>( value.providerMatches), static_cast<unsigned>( value.versionMatches),
		static_cast<unsigned>( value.contentContextValid), static_cast<unsigned>( value.originValid),
		static_cast<unsigned>( value.observationValid), static_cast<unsigned>( value.assessmentReady),
		value.baseRequirements, value.extensionRequirements, value.componentRequirements,
		value.verifiedNeedsEdges, value.additionalMembers) ;
	std::fflush( stdout) ;
}

/** @brief 固定一対象の全取得後経路を実native検証のまま再生します。
 * @param[in] zip 同SHA保存ZIPの明示pathです。出力しません。
 * @param[in] html 同原本文の明示pathです。出力しません。
 * @return 公開正常0、不足または拒否1です。
 */
int replay( const wchar_t *zip, const wchar_t *html)
{
	using namespace drivercrate ;
	// 明示profileと元public pinのない通常buildはinventoryより前に拒否します。
	if( local_index_profile::ACQUISITION_KEYS.empty() ||
	   local_index_profile::PUBLIC_FINGERPRINT !=
		   "68ab95e96e45db00c62a241d733d29a2e347ef074949aec01293ed2ab024f18d") {
		return 1 ;
	}

	// 元物理byteのhash・sizeを入口で確認し、不一致を元応答へ補完しません。
	if( verifyOfficialFileMetadata(
		   zip, {40477087U, L"2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5"}) !=
		   0U ||
	   verifyOfficialFileMetadata(
		   html, {173557U, L"c0bdf3708bd3904072693574a4bdb5306582ac817493617fdc42abccccb0f09a"}) !=
		   0U) {
		return 1 ;
	}

	ComApartment apartment( COINIT_MULTITHREADED) ;	// 同threadの実COM寿命です。
	// 実COM初期化が失敗した場合はnative検証へ進みません。
	if( FAILED( apartment.result())) {
		return 1 ;
	}

	Replay state ;	// 保存二fileと人工transportの短命所有者です。
	state.zip	 = zip ;
	state.html	 = html ;
	activeReplay = &state ;
	provider_worker_index_detail::Services services ;	// 同製品store・時計・OSへ接続します。
	services.load = []( const std::optional<std::chrono::sys_seconds> now) {
		return SignedIndexStore::reloadFixedExisting( now) ;
	} ;
	services.utc = []() {
		return std::optional<std::chrono::sys_seconds>{
			std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now())} ;
	} ;
	services.monotonic = []() { return std::chrono::steady_clock::now() ; } ;
	services.targetOs  = []() -> std::optional<IndexTargetOs> {
		 const auto build = currentWindowsBuildNumber() ;	// 実OS観測だけです。
		 // 未確認OSを索引記載から補完しません。
		 if( build == 0U) {
			 return std::nullopt ;
		 }

		 return isWindowsServer() ? IndexTargetOs::WINDOWS_SERVER
				: build >= 22000U ? IndexTargetOs::WINDOWS_11
								  : IndexTargetOs::WINDOWS_10 ;
	} ;
	services.httpTransport = &transport ;
	services.costReader	   = []() { return std::make_unique<ReplayCost>() ; } ;
	SignedIndexScanSession	index ;				// Compositeより長く私有recordを保持します。
	CompositeUpdateProvider provider ;			// 実native Driver Storeと全publication validatorです。
	const SessionEnd		cleanup{index} ;	// issuer生存中に全tokenを回収します。
	signed_index_candidate_binding_detail::Access::observePublication( &publication, nullptr) ;
	signed_index_candidate_binding_detail::Access::bind( provider, index, services, 22501U) ;
	ScanOptions options ;	// 他のnetwork ProviderやWUAを実行しません。
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
								   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
	auto scan =
		// 実端末snapshotです。
		provider.scan( 22501U, options, []( const ProviderProgress &) {}) ;
	std::printf( "REPLAY stage=1 scanSuccess=%u candidates=%zu\n",
				static_cast<unsigned>( scan.succeeded), scan.candidates.size()) ;
	// 元通常scan成功だけを計画へ接続します。
	if( !scan.succeeded) {
		return 1 ;
	}

	const auto limits = options.officialDiscoveryApproval
							? options.officialDiscoveryApproval->payloadLimits
							: OfficialDiscoveryPayloadLimits{} ;	// 同通常workerの元予算factoryです。
	auto	   plan =
		provider.preparationPlan( scan.scanSessionId, 22501U)
			.value_or( OfficialPreparationPlan{
				scan.scanSessionId,
				22501U,
				{limits.maximumFileBytes, limits.maximumProviderBytes, limits.maximumSessionBytes,
				 limits.maximumProviderFiles, limits.maximumSessionFiles},
				{}}) ;	// 元Provider未発行時の通常workerと同じ補完です。
	std::printf(
		"REPLAY_PLAN file=%llu provider=%llu session=%llu providerFiles=%u sessionFiles=%u payloadReplayLimit=67108864\n",
		static_cast<unsigned long long>( plan.limits.maximumFileBytes),
		static_cast<unsigned long long>( plan.limits.maximumProviderBytes),
		static_cast<unsigned long long>( plan.limits.maximumSessionBytes),
		plan.limits.maximumProviderFiles, plan.limits.maximumSessionFiles) ;
	IndexPreparationSummary planned ;	// 権限と未知の別集計です。
	const auto				planError =
		// 実署名元recordを再認証します。
		index.augmentPreparationPlan( plan, services, planned) ;
	std::printf(
		"REPLAY stage=2 planError=%u authority=%u targets=%zu unavailable=%zu htmlReplays=%u\n",
		planError, planned.authorityError, plan.targets.size(), planned.unavailableRelations,
		state.htmlReplays) ;
	// 元一対象と元規約だけに承認を限定します。
	if( planError != 0U || planned.authorityError != 0U || plan.targets.size() != 1U ||
	   plan.targets.front().eulaRevision !=
		   L"Intel OBL Distribution (Commercial Use) License Agreement [v2025.02.12]" ||
	   plan.targets.front().eulaText.size() != 16580U) {
		return 1 ;
	}

	signed_index_candidate_binding_detail::Access::publishReferences( provider, plan, scan) ;
	OfficialPreparationSession preparation ;	// 同planのapprove/claim状態です。
	// 計画初期化が成立しない場合は取得ledgerを開始しません。
	if( preparation.initialize( plan) != OfficialPreparationError::NONE) {
		return 1 ;
	}

	OfficialPreparationApproval approval{
		22502U,
		plan.scanSessionId,
		plan.planId,
		plan.limits,
		{{plan.targets.front(), true, true, false, false}}} ;	// 元同意・回線例外なしです。
	auto result = executeOfficialPreparation(
		preparation, approval,
		[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
			return index.acquireForInspection( preparation, task, services, cancel) ;
		},
		[]() { return false ; },
		[]( const OfficialPreparationProgress &) {}) ;						// 同元grantと実byteを通常取得へ通します。
	const auto summary = index.preparationSummary( approval.operationId) ;	// 例外前の確定内容です。
	std::printf(
		"REPLAY stage=3 approval=%u control=%u items=%zu summary=%zu payloadReplays=%u newGet=0 nativeCat=1 nativeRank=1\n",
		static_cast<unsigned>( result.approvalError), result.controlError, result.items.size(),
		summary.items.size(), state.payloadReplays) ;
	// 元取得・内容の各結果を成功へ補完せず数値だけ保持します。
	for( const auto &item : summary.items) {
		std::printf(
			"REPLAY_CONTENT acquisition=%u acquisitionError=%u content=%u error=%u bound=%u files=%zu infs=%zu accepted=%zu\n",
			static_cast<unsigned>( item.acquisition), item.acquisitionError,
			static_cast<unsigned>( item.content), item.contentError,
			static_cast<unsigned>( item.inputBound), item.inventoryFileCount, item.infCount,
			item.acceptedInfCount) ;
	}

	std::fflush( stdout) ;
	result.auditReports =
		// 具体typedthrowをCLIへ保持します。
		provider.preparationAuditReports( result) ;
	std::size_t candidates{} ;	// 全reportから公開された候補数です。
	// 元監査の全pairを分母のまま保持します。
	for( const auto &report : result.auditReports) {
		candidates += report.publishedCandidates.size() ;
		std::printf(
			"REPLAY_AUDIT content=%u contentError=%u accepted=%u examined=%u applicable=%u failed=%u publicationExamined=%u published=%u excluded=%u publicationError=%u\n",
			static_cast<unsigned>( report.content), report.contentError, report.acceptedInfCount,
			report.examinedPairCount, report.applicablePairCount, report.failedPairCount,
			report.publication.examinedPairCount, report.publication.publishedCount,
			report.publication.excludedPairCount, report.publication.firstError) ;
	}

	std::printf(
		"REPLAY stage=4 reports=%zu published=%zu compositeCommitted=1 normalUiPositive=0 actualInstall=0\n",
		result.auditReports.size(), candidates) ;
	return result.controlError == 0U && candidates != 0U ? 0 : 1 ;
}
}

/** @brief 明示保存二fileだけを再生し、固定例外分類以外を出力しません。
 * @param[in] count OS引数数です。
 * @param[in] arguments mode・保存ZIP・保存HTMLです。秘密値をechoしません。
 * @return 公開正常0、拒否1、引数またはtyped例外2です。
 */
int wmain( const int count, wchar_t **arguments)
{
	// 明示mode以外でinventory・file・HTTPを開始しません。
	if( count != 4 || std::wstring_view( arguments[1]) != L"--saved-publication-replay") {
		return 2 ;
	}

	try {
		return replay( arguments[2], arguments[3]) ;
	} catch( const std::length_error &error) {
		const std::string_view message{error.what()} ;	// 固定literal比較にだけ使用します。
		std::printf( "REPLAY_EXCEPTION type=length code=%u\n",
					message == "index routing limit" ? 4U : 0U) ;
	} catch( const std::logic_error &error) {
		const std::string_view message{error.what()} ;	// 生文字列を出力しません。
		const auto			   code = message == "index content assessment mismatch"			? 2U
									  : message == "index assessment not ready"					? 3U
									  : message == "index binding version mismatch"				? 1U
									  : message == "index publication mismatch"					? 5U
									  : message == "preparation candidate publication mismatch" ? 6U
									  : message == "preparation candidate routing collision"
										  ? 7U
										  : 0U ;	// 固定されたthrow識別値です。
		std::printf( "REPLAY_EXCEPTION type=logic code=%u\n", code) ;
	} catch( const std::bad_alloc &) {
		std::printf( "REPLAY_EXCEPTION type=allocation code=0\n") ;
	} catch( ...) {
		std::printf( "REPLAY_EXCEPTION type=other code=0\n") ;
	}

	return 2 ;
}
