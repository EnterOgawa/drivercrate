//------------------------------------------------------------------------------
/**
 * @file official_prepared_acquisition_tests.cpp
 * @brief 配布物再確認付き取得の内部試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  集約件数をtask、結果をidentityで照合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX取得の異常系と一回限定fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX配布IDと算出許諾本文識別子を検証。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  再確認と取得境界の試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 合成metadataとcallbackで再確認と取得の接続を試験し、実HTTPを呼びません。
 */
//------------------------------------------------------------------------------

#include "official_prepared_acquisition_tests.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_prepared_acquisition.h"
#include "platform/official_release_discovery_provider.h"
#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
namespace drivercrate::test {
namespace {
/**
 * @brief 取得準備の保存値・再確認値・取消し・失敗を、実通信なしで差し替える試験状態。
 */
struct PreparedFixture {
	/// 計画へ固定した対象。
	OfficialPreparationTarget target ;
	/// Claim済みとする合成token。
	OfficialPreparationTask	  task ;
	/// 取得前に保持した公式情報の合成値。
	OfficialReleaseRecord	  retained ;
	/// 再確認callbackが返す情報。
	OfficialReleaseRecord	  current ;
	/// Worker専用取得結果。
	OfficialAcquisitionResult acquisition ;
	/// 再確認の呼出回数。
	std::uint32_t			  refreshCount{} ;
	/// payload取得callbackの呼出回数。
	std::uint32_t			  acquireCount{} ;
	/// 取消し照会の返却値。
	bool					  cancelled{} ;
	/// 再確認中の取消し競合を再現する。
	bool					  cancelAfterRefresh{} ;
	/// 再確認結果をparser拒否にする。
	bool					  metadataRejected{} ;
	/// 再確認の例外を再現する。
	bool					  throwRefresh{} ;
	/// 取得の例外を再現する。
	bool					  throwAcquire{} ;
	/// trueなら失敗時のpartial受信byte数を偽装する。
	bool					  preserveErrorBytes{} ;
	/// 再確認で返す合成HRESULT。
	NativeError				  refreshError{} ;
	/// 取得で返す合成HRESULT。
	NativeError				  acquireError{} ;
	/// 終端分類。
	OfficialAcquisitionState  acquireState{OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION} ;
	/// 取得結果として返すbyte数。
	std::uint64_t			  acquiredBytes{50} ;
	/// 内部callbackへ渡されたURL。実送信しない。
	std::wstring			  observedUrl ;
	/// 当該対象へのnetwork承認を保持する。
	bool					  observedNetwork{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief URLや署名は実取得の根拠ではなく、callbackの入力を検証する合成値である。
 * @return 架空のIntel系列配布物と本文を含むfixture。
 */
//------------------------------------------------------------------------------
PreparedFixture makePreparedFixture()
{
	PreparedFixture fixture ;	// 各caseが独立して変更する合成状態。
	fixture.target						= {L"target:1",
										   std::wstring( INTEL_WIFI_OFFICIAL_PROVIDER_ID),
										   std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
										   L"release:1",
										   1,
										   100,
										   1,
										   OfficialPreparationTerms::ACCEPTANCE_REQUIRED,
										   L"terms:1",
										   L"Synthetic test terms. No real license."} ;
	fixture.task						= {2, 1, 1, fixture.target, false} ;
	fixture.retained.family				= OfficialReleaseFamily::INTEL_WIFI ;
	fixture.retained.fileName			= L"Synthetic.zip" ;
	fixture.retained.packageVersion		= L"99.0" ;
	fixture.retained.displaySize		= L"fixture" ;
	fixture.retained.publishedSizeBytes = 50 ;
	fixture.retained.publishedSha256.assign( 64, L'A') ;
	fixture.retained.downloadUrl	= L"https://downloadmirror.intel.com/fixture/Synthetic.zip" ;
	fixture.retained.license		= OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
	fixture.retained.eulaRevision	= fixture.target.eulaRevision ;
	fixture.retained.parserRevision = 1 ;
	fixture.retained.eulaText		= fixture.target.eulaText ;
	fixture.current					= fixture.retained ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実TermsやURLを取得せず、ASIX固有契約を共通取得境界へ渡す。
 * @return ASIXの数値配布ID、Terms、8 MiB上限を持つ合成fixture。
 */
//------------------------------------------------------------------------------
PreparedFixture makeAsixPreparedFixture()
{
	constexpr std::uint64_t MAXIMUM_ASIX_FIXTURE_BYTES =
		8ULL * 1024ULL * 1024ULL ;	// 本番targetと一致させる一配布物上限。
	PreparedFixture fixture ;		// 各異常系で一fieldだけ変更する基準状態。
	fixture.target.identity		   = L"asix:prepare:7" ;
	fixture.target.providerId	   = std::wstring( ASIX_AX88179A_PROVIDER_ID) ;
	fixture.target.resourceId	   = std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	fixture.target.releaseIdentity = L"asix:release:71:0" ;
	fixture.target.parserRevision  = 2U ;
	fixture.target.maximumBytes	   = MAXIMUM_ASIX_FIXTURE_BYTES ;
	fixture.target.deviceCount	   = 2U ;
	fixture.target.terms		   = OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
	fixture.target.eulaRevision	   = L"DriverCrate content SHA-256: synthetic-asix-terms" ;
	fixture.target.eulaText		   = L"Synthetic ASIX terms for a deterministic fixture." ;
	fixture.target.requiresPrerequisiteConfirmation = true ;
	fixture.task									= {8U, 71U, 7U, fixture.target, false} ;
	fixture.retained.family							= OfficialReleaseFamily::ASIX_AX88179A ;
	fixture.retained.releaseKey						= L"2081" ;
	fixture.retained.packageVersion					= L"4.22.1.0" ;
	fixture.retained.displaySize					= L"129.5 KB" ;
	fixture.retained.publishedDate					= L"2026-01-15" ;
	fixture.retained.downloadUrl	= L"https://www.asix.com.tw/en/support/download/file/2081" ;
	fixture.retained.license		= OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
	fixture.retained.eulaRevision	= fixture.target.eulaRevision ;
	fixture.retained.parserRevision = fixture.target.parserRevision ;
	fixture.retained.eulaText		= fixture.target.eulaText ;
	fixture.current					= fixture.retained ;
	// 公表概算とは独立したfakeの実受信量。
	fixture.acquiredBytes = 129ULL * 1024ULL ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief Fakeはfileやnetworkを作らず、callbackの回数と取得入力だけを保持する。
 *
 * @param[in,out] fixture 合成metadata、失敗条件と呼出回数。
 * @return 共通再確認adapterの取得状態。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult runPreparedFixture( PreparedFixture &fixture)
{
	const PreparedReleaseRefresh refresh = [&fixture]( OfficialReleaseRecord &output,
													  bool					&rejected) {
		++fixture.refreshCount ;
		// 再確認callbackに例外を注入し、取得へ進まない経路を検証する。
		if( fixture.throwRefresh) {
			throw std::runtime_error( "synthetic refresh failure") ;
		}

		output			  = fixture.current ;
		rejected		  = fixture.metadataRejected ;
		fixture.cancelled = fixture.cancelled || fixture.cancelAfterRefresh ;
		return fixture.refreshError ;
	} ; // 固定起点からの再確認を代替する合成reader。
	const PreparedReleaseAcquire acquire = [&fixture]( const OfficialAcquisitionRequest &request,
													  const PreparationCancellation &cancellation,
													  OfficialAcquisitionResult		&output) {
		// このfakeは即時完了し、外側の取消し照会を試験する。
		static_cast<void>( cancellation) ;
		++fixture.acquireCount ;
		fixture.observedUrl		= request.url ;
		fixture.observedNetwork = request.restrictedNetworkApproved ;
		// 取得callbackに例外を注入し、完了結果への変換を検証する。
		if( fixture.throwAcquire) {
			throw std::runtime_error( "synthetic acquire failure") ;
		}

		output.state		 = fixture.acquireState ;
		output.error		 = fixture.acquireError ;
		output.scanSessionId = fixture.task.scanSessionId ;
		output.providerId	 = request.providerId ;
		output.resourceId	 = request.resourceId ;
		output.byteCount	 = fixture.acquireError == 0 || fixture.preserveErrorBytes
								   ? fixture.acquiredBytes
								   : 0 ;	// 失敗時partial byteの非公開化も試験できる値。
		return fixture.acquireError ;
	} ; // 実HTTPを呼ばない取得境界。
	return revalidateAndAcquireRelease(
		fixture.task, fixture.target, fixture.retained, refresh, acquire,
		[&fixture] { return fixture.cancelled ; }, fixture.acquisition) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定した対象と公式再確認が一致した場合だけ一回取得する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedReleaseSuccess( TestContext &context)
{
	PreparedFixture fixture				   = makePreparedFixture() ;	// 正常取得の基準値。
	fixture.task.restrictedNetworkApproved = true ;
	const auto result					   = runPreparedFixture( fixture) ;	// UIへ渡す限定結果。
	DRIVERCRATE_EXPECT( context,
					   result.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, result.byteCount == 50) ;
	DRIVERCRATE_EXPECT( context, fixture.refreshCount == 1) ;
	DRIVERCRATE_EXPECT( context, fixture.acquireCount == 1) ;
	DRIVERCRATE_EXPECT( context, fixture.observedUrl == fixture.retained.downloadUrl) ;
	DRIVERCRATE_EXPECT( context, fixture.observedNetwork) ;
	PreparedFixture noConsent = makePreparedFixture() ;	// 明示的な同意不要分類の合成経路。
	noConsent.target.terms	  = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	noConsent.target.eulaRevision.clear() ;
	noConsent.target.eulaText.clear() ;
	noConsent.task.target	   = noConsent.target ;
	noConsent.retained.license = OfficialReleaseLicense::CONFIRMED_NO_CONSENT ;
	noConsent.retained.eulaRevision.clear() ;
	noConsent.retained.eulaText.clear() ;
	noConsent.current = noConsent.retained ;
	DRIVERCRATE_EXPECT( context, runPreparedFixture( noConsent).state ==
									OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同URLのhash変更と同revisionの本文変更もpayload取得前に拒否する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedReleaseChangeRejection( TestContext &context)
{
	// 同じ配布物の識別に使う十fieldを一つずつ変更する。
	for( int scenario = 0; scenario < 10; ++scenario) {
		PreparedFixture fixture = makePreparedFixture() ;	// 一条件だけ変更する状態。
		// 現在の配布metadataをfieldごとに差し替え、保持snapshotとの照合を検証する。
		switch( scenario) {
			// 再確認で取得URLが変化した場合の拒否を検証する。
			case 0:
				fixture.current.downloadUrl += L"?changed" ;
				break ;

			// 同じURLでも公開hashが変化した場合の拒否を検証する。
			case 1:
				fixture.current.publishedSha256[0] = L'B' ;
				break ;

			// 同じrevisionでもEULA本文が変化した場合を検証する。
			case 2:
				fixture.current.eulaText += L" Changed." ;
				break ;

			// EULA revisionが変化した後の同意流用を検証する。
			case 3:
				fixture.current.eulaRevision += L"2" ;
				break ;

			// 公開されたbyte数の変化を検出する。
			case 4:
				fixture.current.publishedSizeBytes = 51 ;
				break ;

			// package版数の変化を、別配布物として検出する。
			case 5:
				fixture.current.packageVersion = L"100.0" ;
				break ;

			// 公開file名が変化した配布物の拒否を検証する。
			case 6:
				fixture.current.fileName = L"Different.zip" ;
				break ;

			// parser revisionの変更を再確認時に検出する。
			case 7:
				++fixture.current.parserRevision ;
				break ;

			// 製品系列の差替えを取得前に拒否する入力を作る。
			case 8:
				fixture.current.family = OfficialReleaseFamily::PROLIFIC_DCHU ;
				break ;

			// 利用条件の区分変更も、取得前の差分検出対象に含める。
			default:
				fixture.current.license = OfficialReleaseLicense::CONFIRMED_NO_CONSENT ;
				break ;
		}

		const auto result = runPreparedFixture( fixture) ;	// 変更検出の結果。
		DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::REJECTED) ;
		DRIVERCRATE_EXPECT( context, result.error == static_cast<NativeError>( HRESULT_FROM_WIN32(
														ERROR_REVISION_MISMATCH))) ;
		DRIVERCRATE_EXPECT( context, fixture.refreshCount == 1) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 未解決条件とsnapshot差替えでは再確認も取得も開始しない。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedReleaseTargetRejection( TestContext &context)
{
	// 操作ID、対象差替え、本文欠落、未知familyを個別に拒否する。
	for( int scenario = 0; scenario < 8; ++scenario) {
		PreparedFixture fixture = makePreparedFixture() ;	// 一つの入力不整合だけを持つ状態。
		// taskや保持metadataを不完全にし、再確認前の拒否を検証する。
		switch( scenario) {
			// operation identityが欠けたtaskを検証する。
			case 0:
				fixture.task.operationId = 0 ;
				break ;

			// 保存した対象と容量制限が一致しないtaskを検証する。
			case 1:
				++fixture.task.target.maximumBytes ;
				break ;

			// 必要なEULA本文が失われた保存metadataを検証する。
			case 2:
				fixture.retained.eulaText.clear() ;
				break ;

			// 利用条件が未解決の保存metadataを検証する。
			case 3:
				fixture.retained.license = OfficialReleaseLicense::UNRESOLVED ;
				break ;

			// 製品系列が不明な保存metadataを検証する。
			case 4:
				fixture.retained.family = OfficialReleaseFamily::UNKNOWN ;
				break ;

			// scan session identityが欠けたtaskを検証する。
			case 5:
				fixture.task.scanSessionId = 0 ;
				break ;

			// 計画identityが欠けたtaskを検証する。
			case 6:
				fixture.task.planId = 0 ;
				break ;

			// task内のEULA本文だけを差し替えた場合を検証する。
			default:
				fixture.task.target.eulaText += L" Changed." ;
				break ;
		}

		const auto result = runPreparedFixture( fixture) ;	// 入力拒否の結果。
		DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::REJECTED) ;
		DRIVERCRATE_EXPECT( context, fixture.refreshCount == 0) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 再確認前と再確認後の取消しでpayloadを取得しない。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedReleaseCancellation( TestContext &context)
{
	// 再確認の前後を区別して取消しによる無駄な取得を防ぐ。
	for( int scenario = 0; scenario < 2; ++scenario) {
		PreparedFixture fixture	   = makePreparedFixture() ;	// 取消し時点を制御する合成状態。
		fixture.cancelled		   = scenario == 0 ;
		fixture.cancelAfterRefresh = scenario == 1 ;
		const auto result		   = runPreparedFixture( fixture) ;	// 取消しの終端結果。
		DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::CANCELLED) ;
		DRIVERCRATE_EXPECT( context, fixture.refreshCount == static_cast<std::uint32_t>( scenario)) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 再確認の通信失敗・拒否・例外を成功や候補なしへ置換しない。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedReleaseFailures( TestContext &context)
{
	// 再確認の三つの失敗経路では取得callbackを呼ばない。
	for( int scenario = 0; scenario < 3; ++scenario) {
		PreparedFixture fixture	 = makePreparedFixture() ;	// 元の失敗codeを確認する状態。
		fixture.refreshError	 = scenario == 0 ? static_cast<NativeError>( E_ACCESSDENIED) : 0 ;
		fixture.metadataRejected = scenario == 1 ;
		fixture.throwRefresh	 = scenario == 2 ;
		const auto result		 = runPreparedFixture( fixture) ;	// 再確認失敗の結果。
		DRIVERCRATE_EXPECT( context, result.error < 0) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0) ;
		DRIVERCRATE_EXPECT( context,
						   result.state == (scenario == 1 ? OfficialPreparationItemState::REJECTED
														  : OfficialPreparationItemState::FAILURE)) ;
	}

	PreparedFixture fixture = makePreparedFixture() ;	// 取得callback例外の確認。
	fixture.throwAcquire	= true ;
	DRIVERCRATE_EXPECT( context,
					   runPreparedFixture( fixture).state == OfficialPreparationItemState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, fixture.acquireCount == 1) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Network同意不足・取消し・取得拒否・失敗と不正成功を区別する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAcquisitionResultMapping( TestContext &context)
{
	const std::array states{OfficialAcquisitionState::AWAITING_NETWORK_CONSENT,
							OfficialAcquisitionState::CANCELLED, OfficialAcquisitionState::REJECTED,
							OfficialAcquisitionState::FAILURE} ;	// 明示した負の終端分類。
	// 四つの負の終端状態を取得済みへ昇格させずに返す。
	for( int scenario = 0; scenario < 4; ++scenario) {
		PreparedFixture fixture = makePreparedFixture() ;	// 終端分類だけを変えるfake。
		fixture.acquireError	= static_cast<NativeError>( E_FAIL) ;
		fixture.acquireState	= states[static_cast<std::size_t>( scenario)] ;
		const auto result		= runPreparedFixture( fixture) ;	// 終端変換結果。
		DRIVERCRATE_EXPECT( context, result.error == static_cast<NativeError>( E_FAIL)) ;
		DRIVERCRATE_EXPECT( context, result.byteCount == 0) ;
		DRIVERCRATE_EXPECT( context,
						   result.state != OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
	}

	PreparedFixture invalid = makePreparedFixture() ;	// 上限を超えた偽成功を返すfake。
	invalid.acquiredBytes	= 101 ;
	DRIVERCRATE_EXPECT( context,
					   runPreparedFixture( invalid).state == OfficialPreparationItemState::REJECTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Broadcomの固定定義を共通adapterへ通し、同じ本文IDでも本文変更は取得前に拒否する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparedAdapter( TestContext &context)
{
	PreparedFixture fixture	  = makePreparedFixture() ;	// 既存fakeをBroadcom系列へ結合する。
	fixture.target.providerId = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	fixture.retained.family	  = OfficialReleaseFamily::BROADCOM_NET_XTREME_E ;
	fixture.retained.downloadUrl =
		L"https://docs.broadcom.com/docs-and-downloads/ethernet-network-adapters/"
		L"NXE/BRCM_100.9.8.7/Windows_Drivers-100.2.3.4.zip" ;
	fixture.task.target = fixture.target ;
	fixture.current		= fixture.retained ;
	DRIVERCRATE_EXPECT( context, runPreparedFixture( fixture).state ==
									OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, fixture.acquireCount == 1) ;
	fixture.acquireCount = 0 ;
	fixture.current.eulaText += L" Changed." ;
	DRIVERCRATE_EXPECT( context,
					   runPreparedFixture( fixture).state == OfficialPreparationItemState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel取得対象を共通再確認へ通し、差替え・取消しは取得callback前に拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetPreparedAdapter( TestContext &context)
{
	// 正常一件と、本文・版・hash・URL・parser差替え、取消し、対象改変の八条件を分離する。
	for( unsigned scenario = 0U; scenario < 8U; ++scenario) {
		PreparedFixture fixture			= makePreparedFixture() ;	// 実通信を行わない取得境界。
		fixture.retained.family			= OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ;
		fixture.retained.parserRevision = 2U ;
		const auto targets				= makeReleasePreparationTargets( fixture.retained, 1U, 1U,
																		2U) ;	// 二deviceに対応しても一配布物。
		DRIVERCRATE_EXPECT( context, targets.size() == 1U) ;
		// 失敗を記録した後に空collectionを参照しない。
		if( targets.size() != 1U) {
			return ;
		}

		fixture.target = targets[0] ;
		OfficialPreparationSession preparation ;	// 本文同意と前提確認を本番の承認境界へ通す。
		DRIVERCRATE_EXPECT( context,
						   preparation.initialize(
							   {1U, 1U, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {fixture.target}}) ==
							   OfficialPreparationError::NONE) ;
		const OfficialPreparationApproval approval{
			2U,
			1U,
			1U,
			DEFAULT_OFFICIAL_PREPARATION_LIMITS,
			{{.target				  = fixture.target,
			  .acquire				  = true,
			  .eulaAccepted			  = true,
			  .prerequisitesConfirmed = true}}} ;	// 架空本文への合成同意。実契約の同意ではない。
		DRIVERCRATE_EXPECT( context,
						   preparation.approve( approval) == OfficialPreparationError::NONE) ;
		const auto task = preparation.claimNext() ;	// 一度だけclaimした取得token。
		DRIVERCRATE_EXPECT( context, task.has_value()) ;
		// 未承認tokenで後続adapterだけを成功させない。
		if( !task) {
			return ;
		}

		fixture.task	= *task ;
		fixture.current = fixture.retained ;
		// Intelの本文・hash・URL変更と取消しを分離して取得前の拒否を検証する。
		switch( scenario) {
			// Intel EULA本文の変更を、取得callbackより前に検出する。
			case 1U:
				fixture.current.eulaText += L" Synthetic changed clause." ;
				break ;

			// Intel EULA revisionの変更による同意失効を検証する。
			case 2U:
				fixture.current.eulaRevision += L":new" ;
				break ;

			// Intel公開hashの差替えを、取得前に検出する。
			case 3U:
				fixture.current.publishedSha256.assign( 64U, L'B') ;
				break ;

			// Intel取得URLの差替えを、再確認境界で検出する。
			case 4U:
				fixture.current.downloadUrl += L".changed" ;
				break ;

			// Intel parser revisionの変更を、再確認境界で検出する。
			case 5U:
				++fixture.current.parserRevision ;
				break ;

			// metadata再確認後の取消しで、payload取得を開始しないことを検証する。
			case 6U:
				fixture.cancelAfterRefresh = true ;
				break ;

			// 必要な前提確認をtaskから除いた場合の拒否を検証する。
			case 7U:
				fixture.task.target.requiresPrerequisiteConfirmation = false ;
				break ;

			// 無改変caseでは、通常の取得経路を検証できるfixtureを保つ。
			default:
				break ;
		}

		const auto result = runPreparedFixture( fixture) ;	// 実fileを作らない共通adapter結果。
		// 変更を加えていないscenarioでは保持URLによる一回の取得成功を確認する。
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context, fixture.acquireCount == 1U) ;
			DRIVERCRATE_EXPECT( context, fixture.observedUrl == fixture.retained.downloadUrl) ;
			DRIVERCRATE_EXPECT( context, result.state ==
											OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
		} else {
			DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0U) ;
			DRIVERCRATE_EXPECT(
				context, result.state == (scenario == 6U ? OfficialPreparationItemState::CANCELLED
														 : OfficialPreparationItemState::REJECTED)) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不完全metadataから対象を発行せず、未準備Providerへの直接取得を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetPreparationRejection( TestContext &context)
{
	// 本文・改訂・hash・parser・許諾分類の欠落や不正を独立して拒否する。
	for( unsigned scenario = 0U; scenario < 5U; ++scenario) {
		PreparedFixture fixture			= makePreparedFixture() ;	// 正常値を一箇所だけ変更する入力。
		fixture.retained.family			= OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ;
		fixture.retained.parserRevision = 2U ;
		// 配布metadataの必須fieldを個別に不正化し、準備対象を発行しないことを確認する。
		switch( scenario) {
			// EULA本文が欠けたmetadataから、対象を発行しないことを検証する。
			case 0U:
				fixture.retained.eulaText.clear() ;
				break ;

			// EULA revisionが欠けたmetadataの拒否を検証する。
			case 1U:
				fixture.retained.eulaRevision.clear() ;
				break ;

			// 16進形式に合わない公開hashの拒否を検証する。
			case 2U:
				fixture.retained.publishedSha256[0] = L'Z' ;
				break ;

			// 期待するparser revisionと一致しないmetadataを検証する。
			case 3U:
				fixture.retained.parserRevision = 1U ;
				break ;

			// 利用条件が未解決のmetadataを、取得可能へ昇格させないことを検証する。
			default:
				fixture.retained.license = OfficialReleaseLicense::UNRESOLVED ;
				break ;
		}

		DRIVERCRATE_EXPECT( context,
						   makeReleasePreparationTargets( fixture.retained, 1U, 1U, 1U).empty()) ;
	}

	const std::array families{OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
							  OfficialReleaseFamily::INTEL_WIFI,
							  OfficialReleaseFamily::ASIX_AX88179A} ;	// 他系列への誤routingも試す。
	// 成功scanと計画がない全系列で、取消しcallbackより前に拒否する。
	for( const OfficialReleaseFamily family : families) {
		OfficialReleaseDiscoveryProvider provider( family) ;				// Networkを開始しない本番object。
		PreparedFixture					 fixture = makePreparedFixture() ;	// 未準備の合成token。
		bool	   cancellationCalled{} ;									// 入力拒否より先に処理を進めていないことの確認値。
		const auto result = provider.acquireForInspection( fixture.task, [&cancellationCalled] {
			cancellationCalled = true ;
			return false ;
		}) ; // 本番の最初の境界だけを試験する。
		DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::REJECTED) ;
		DRIVERCRATE_EXPECT( context, !cancellationCalled) ;
		DRIVERCRATE_EXPECT( context, provider.preparationTargets( 1U, 1U).empty()) ;
		provider.invalidatePreparation() ;
		DRIVERCRATE_EXPECT( context, provider.preparationTargets( 2U, 2U).empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-8本文の既知SHA-256と不正本文の出力破棄を非通信で確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testComputedEulaRevision( TestContext &context)
{
	// ASCII本文`abc`に対する既知の種別prefix付きSHA-256。
	constexpr std::wstring_view EXPECTED =
		L"DriverCrate content SHA-256: "
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
	// UTF-8の三byteになる日本語本文`あ`に対する既知の算出識別子。
	constexpr std::wstring_view EXPECTED_JAPANESE =
		L"DriverCrate content SHA-256: "
		L"dc5a4d3d82f7e15792959dc661538ae0e541ce66494516f5c9cfd9cd3308494d" ;
	std::wstring revision ;	// 正常なASCII本文から作る算出識別子。
	DRIVERCRATE_EXPECT( context, makeComputedEulaRevision( L"abc", revision) == 0) ;
	DRIVERCRATE_EXPECT( context, revision == EXPECTED) ;

	std::wstring repeated ;	// 同じ本文が同じ識別子になることの再計算結果。
	DRIVERCRATE_EXPECT( context, makeComputedEulaRevision( L"abc", repeated) == 0) ;
	DRIVERCRATE_EXPECT( context, repeated == revision) ;
	DRIVERCRATE_EXPECT( context, makeComputedEulaRevision( L"あ", repeated) == 0) ;
	DRIVERCRATE_EXPECT( context, repeated == EXPECTED_JAPANESE) ;

	revision = L"stale" ;
	DRIVERCRATE_EXPECT( context, makeComputedEulaRevision( L"", revision) != 0) ;
	DRIVERCRATE_EXPECT( context, revision.empty()) ;
	const std::wstring invalidSurrogate(
		1U, static_cast<wchar_t>( 0xD800)) ;	// UTF-8へ一意変換できない単独high surrogate。
	revision = L"stale" ;
	DRIVERCRATE_EXPECT( context, makeComputedEulaRevision( invalidSurrogate, revision) != 0) ;
	DRIVERCRATE_EXPECT( context, revision.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASIXだけが固定URLと同じ数値IDでfile名なし取得へ進み、他系列と改変IDはcallback前に拒否されることを確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testAsixPreparedReleaseIdentity( TestContext &context)
{
	PreparedFixture fixture		= makePreparedFixture() ;	// ASIXのfile名なし正常経路。
	fixture.target.providerId	= std::wstring( ASIX_AX88179A_PROVIDER_ID) ;
	fixture.retained.family		= OfficialReleaseFamily::ASIX_AX88179A ;
	fixture.retained.releaseKey = L"2081" ;
	fixture.retained.fileName.clear() ;
	fixture.retained.downloadUrl = L"https://www.asix.com.tw/en/support/download/file/2081" ;
	DRIVERCRATE_EXPECT( context, makeComputedEulaRevision( fixture.target.eulaText,
														 fixture.target.eulaRevision) == 0) ;
	fixture.retained.eulaRevision = fixture.target.eulaRevision ;
	fixture.task.target			  = fixture.target ;
	fixture.current				  = fixture.retained ;
	DRIVERCRATE_EXPECT( context, validPreparedReleaseIdentity( fixture.retained)) ;
	DRIVERCRATE_EXPECT( context, runPreparedFixture( fixture).state ==
									OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, fixture.refreshCount == 1U) ;
	DRIVERCRATE_EXPECT( context, fixture.acquireCount == 1U) ;

	OfficialReleaseRecord changed = fixture.retained ;	// 一条件ずつ壊すidentityの基準値。
	changed.releaseKey			  = L"20A1" ;
	DRIVERCRATE_EXPECT( context, !validPreparedReleaseIdentity( changed)) ;
	changed = fixture.retained ;
	changed.downloadUrl += L"?time=1" ;
	DRIVERCRATE_EXPECT( context, !validPreparedReleaseIdentity( changed)) ;
	changed			 = fixture.retained ;
	changed.fileName = L"inferred.zip" ;
	DRIVERCRATE_EXPECT( context, !validPreparedReleaseIdentity( changed)) ;
	changed			   = fixture.retained ;
	changed.releaseKey = L"2085" ;
	DRIVERCRATE_EXPECT( context, !validPreparedReleaseIdentity( changed)) ;

	PreparedFixture other = makePreparedFixture() ;	// 既存Intel系列のfile名欠落経路。
	other.retained.fileName.clear() ;
	other.current = other.retained ;
	DRIVERCRATE_EXPECT( context, !validPreparedReleaseIdentity( other.retained)) ;
	DRIVERCRATE_EXPECT( context,
					   runPreparedFixture( other).state == OfficialPreparationItemState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, other.refreshCount == 0U) ;
	DRIVERCRATE_EXPECT( context, other.acquireCount == 0U) ;
	OfficialReleaseRecord unknown = fixture.retained ;	// File名を付けても拒否する未定義系列。
	unknown.family				  = OfficialReleaseFamily::UNKNOWN ;
	unknown.fileName			  = L"unknown.zip" ;
	DRIVERCRATE_EXPECT( context, !validPreparedReleaseIdentity( unknown)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASIXの二page結合record全fieldを比較し、差替え時は取得を開始しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testAsixPreparedReleaseFieldChanges( TestContext &context)
{
	// Default比較対象の全十三fieldを一つずつ変更し、表示値の差も見逃さない。
	for( unsigned scenario = 0U; scenario < 13U; ++scenario) {
		PreparedFixture fixture = makeAsixPreparedFixture() ;	// 一条件だけ変更するASIX状態。
		// ASIXの二page結合recordをfieldごとに変え、差替え時の取得拒否を検証する。
		switch( scenario) {
			// ASIX対象への別製品系列の混入を検出する。
			case 0U:
				fixture.current.family = OfficialReleaseFamily::INTEL_WIFI ;
				break ;

			// 二pageを結合したrelease keyの変化を検出する。
			case 1U:
				fixture.current.releaseKey = L"2085" ;
				break ;

			// 結合済みの公開file名の差替えを検出する。
			case 2U:
				fixture.current.fileName = L"inferred.zip" ;
				break ;

			// 結合済みのpackage版数の差替えを検出する。
			case 3U:
				fixture.current.packageVersion = L"4.22.1.1" ;
				break ;

			// 表示用容量であってもsnapshotの差分として検出する。
			case 4U:
				fixture.current.displaySize = L"130.0 KB" ;
				break ;

			// 公開日の変化をsnapshot比較から漏らさないことを検証する。
			case 5U:
				fixture.current.publishedDate = L"2026-01-16" ;
				break ;

			// 公開byte数の変化を、取得前に検出する。
			case 6U:
				fixture.current.publishedSizeBytes = 132'608U ;
				break ;

			// 公開hashが後から付与された場合もsnapshot変更として検出する。
			case 7U:
				fixture.current.publishedSha256.assign( 64U, L'A') ;
				break ;

			// 別releaseの取得endpointへの差替えを検出する。
			case 8U:
				fixture.current.downloadUrl =
					L"https://www.asix.com.tw/en/support/download/file/2085" ;
				break ;

			// ASIX利用条件区分の変更による承認の不一致を検証する。
			case 9U:
				fixture.current.license = OfficialReleaseLicense::CONFIRMED_NO_CONSENT ;
				break ;

			// ASIX EULA revisionの変更を検出する。
			case 10U:
				fixture.current.eulaRevision += L":changed" ;
				break ;

			// ASIX parser revisionの変更を検出する。
			case 11U:
				++fixture.current.parserRevision ;
				break ;

			// ASIX EULA本文の差替えも、取得前に検出する。
			default:
				fixture.current.eulaText += L" Synthetic changed clause." ;
				break ;
		}

		const auto result = runPreparedFixture( fixture) ;	// 差替え検出後の共通終端状態。
		DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::REJECTED) ;
		DRIVERCRATE_EXPECT( context, result.error == static_cast<NativeError>( HRESULT_FROM_WIN32(
														ERROR_REVISION_MISMATCH))) ;
		DRIVERCRATE_EXPECT( context, fixture.refreshCount == 1U) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 再確認前後の取消しと通信・schema・例外を取得成功へ変換しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testAsixPreparedReleaseCancellationAndRefreshFailures( TestContext &context)
{
	// 取消しを再確認前と再確認直後へ分け、payload callbackが未実行であることを確認する。
	for( unsigned scenario = 0U; scenario < 2U; ++scenario) {
		PreparedFixture fixture	   = makeAsixPreparedFixture() ;	// 取消し位置を変える状態。
		fixture.cancelled		   = scenario == 0U ;
		fixture.cancelAfterRefresh = scenario == 1U ;
		const auto result		   = runPreparedFixture( fixture) ;	// 取消しの終端状態。
		DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::CANCELLED) ;
		DRIVERCRATE_EXPECT( context, result.byteCount == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.refreshCount == scenario) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0U) ;
	}

	// 通信失敗、metadata拒否、callback例外を独立させ、元の分類を確認する。
	for( unsigned scenario = 0U; scenario < 3U; ++scenario) {
		PreparedFixture fixture	 = makeAsixPreparedFixture() ;	// 一つの再確認失敗だけを持つ状態。
		fixture.refreshError	 = scenario == 0U ? static_cast<NativeError>( E_ACCESSDENIED) : 0 ;
		fixture.metadataRejected = scenario == 1U ;
		fixture.throwRefresh	 = scenario == 2U ;
		const auto result		 = runPreparedFixture( fixture) ;	// 再確認失敗の終端状態。
		DRIVERCRATE_EXPECT( context, result.byteCount == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.refreshCount == 1U) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 0U) ;
		DRIVERCRATE_EXPECT( context, result.state == (scenario == 1U
														 ? OfficialPreparationItemState::REJECTED
														 : OfficialPreparationItemState::FAILURE)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 8 MiB上限、network承認伝達、負の取得状態とpartial byte非公開を確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testAsixPreparedReleaseCapacityCostAndTerminalStates( TestContext &context)
{
	constexpr std::uint64_t MAXIMUM_ASIX_FIXTURE_BYTES =
		8ULL * 1024ULL * 1024ULL ;											// ASIX targetへ固定した取得打切り上限。
	PreparedFixture			  budgetFixture = makeAsixPreparedFixture() ;	// ASIX予約量の基準値。
	OfficialPreparationLimits insufficientLimits =
		DEFAULT_OFFICIAL_PREPARATION_LIMITS ;	// 一fileだけを一byte不足させる合成予算。
	insufficientLimits.maximumFileBytes = MAXIMUM_ASIX_FIXTURE_BYTES - 1U ;
	OfficialPreparationSession insufficientBudget ;	// 取得前に不足を拒否する共通予算境界。
	DRIVERCRATE_EXPECT( context, insufficientBudget.initialize(
									{71U, 7U, insufficientLimits, {budgetFixture.target}}) ==
									OfficialPreparationError::INVALID_PLAN) ;

	PreparedFixture maximum				   = makeAsixPreparedFixture() ;	// 上限ちょうどの合成成功。
	maximum.acquiredBytes				   = MAXIMUM_ASIX_FIXTURE_BYTES ;
	maximum.task.restrictedNetworkApproved = true ;
	const auto maximumResult			   = runPreparedFixture( maximum) ;	// 上限内取得結果。
	DRIVERCRATE_EXPECT( context, maximumResult.state ==
									OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, maximumResult.byteCount == MAXIMUM_ASIX_FIXTURE_BYTES) ;
	DRIVERCRATE_EXPECT( context, maximum.observedNetwork) ;

	PreparedFixture oversized  = makeAsixPreparedFixture() ;	// 上限を一byte超える偽成功。
	oversized.acquiredBytes	   = MAXIMUM_ASIX_FIXTURE_BYTES + 1U ;
	const auto oversizedResult = runPreparedFixture( oversized) ;	// 矛盾成功の拒否結果。
	DRIVERCRATE_EXPECT( context, oversizedResult.state == OfficialPreparationItemState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, oversizedResult.byteCount == 0U) ;

	const std::array terminalStates{
		OfficialAcquisitionState::AWAITING_NETWORK_CONSENT, OfficialAcquisitionState::CANCELLED,
		OfficialAcquisitionState::REJECTED,
		OfficialAcquisitionState::FAILURE} ;	// 共通取得が返せる負の終端状態。
	const std::array expectedStates{
		OfficialPreparationItemState::AWAITING_NETWORK_CONSENT,
		OfficialPreparationItemState::CANCELLED, OfficialPreparationItemState::REJECTED,
		OfficialPreparationItemState::FAILURE} ;	// UIへ返す対応済み終端分類。
	// 課金同意待ち、取消し、拒否、失敗を取得済みへ昇格せず、partial byteをUIへ返さない。
	for( std::size_t index = 0U; index < terminalStates.size(); ++index) {
		PreparedFixture fixture	   = makeAsixPreparedFixture() ;	// 終端状態だけを変える取得結果。
		fixture.acquireState	   = terminalStates[index] ;
		fixture.acquireError	   = static_cast<NativeError>( E_ACCESSDENIED) ;
		fixture.preserveErrorBytes = true ;
		fixture.acquiredBytes	   = 1024U ;
		const auto result		   = runPreparedFixture( fixture) ;	// 共通変換後のASIX結果。
		DRIVERCRATE_EXPECT( context, result.state == expectedStates[index]) ;
		DRIVERCRATE_EXPECT( context, result.byteCount == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.acquireCount == 1U) ;
		DRIVERCRATE_EXPECT( context, !fixture.observedNetwork) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 二deviceを束ねた一配布物の失敗後は再claimせず、Install能力も発行しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testAsixSinglePackageFailureAndInstallBlock( TestContext &context)
{
	PreparedFixture fixture = makeAsixPreparedFixture() ;	// 二deviceを一配布物へ束ねた対象。
	OfficialPreparationSession	  preparation ;				// 本番と同じ一回限定claim境界。
	const OfficialPreparationPlan plan{71U,
									   7U,
									   DEFAULT_OFFICIAL_PREPARATION_LIMITS,
									   {fixture.target}} ;	// 一targetだけを持つ合成計画。
	DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
	const OfficialPreparationApproval approval{
		8U,
		71U,
		7U,
		DEFAULT_OFFICIAL_PREPARATION_LIMITS,
		{{.target					 = fixture.target,
		  .acquire					 = true,
		  .eulaAccepted				 = true,
		  .restrictedNetworkApproved = true,
		  .prerequisitesConfirmed	 = true}}} ;	// 架空Termsへの合成承認。
	DRIVERCRATE_EXPECT( context, preparation.approve( approval) == OfficialPreparationError::NONE) ;
	const auto task = preparation.claimNext() ;	// 最初の一回だけ発行される取得task。
	DRIVERCRATE_EXPECT( context, task.has_value()) ;
	DRIVERCRATE_EXPECT( context, task && task->restrictedNetworkApproved) ;
	DRIVERCRATE_EXPECT( context, !preparation.claimNext().has_value()) ;
	// 取得できた集約taskへ失敗を返し、同じ配布物が再claimされないことを検証する。
	if( task) {
		DRIVERCRATE_EXPECT( context, task->target.deviceCount == 2U) ;
		const OfficialPreparationTransferResult failed{OfficialPreparationItemState::FAILURE,
													   static_cast<NativeError>( E_ACCESSDENIED),
													   0U} ;	// 二device共通配布物の取得失敗。
		DRIVERCRATE_EXPECT( context, preparation.complete( *task, failed)) ;
	}

	DRIVERCRATE_EXPECT( context, !preparation.claimNext().has_value()) ;
	DRIVERCRATE_EXPECT( context, preparation.items().size() == 1U) ;
	// 一配布物分の結果がある場合にだけidentityと失敗状態を参照する。
	if( preparation.items().size() == 1U) {
		DRIVERCRATE_EXPECT( context,
						   preparation.items().front().identity == fixture.target.identity) ;
		DRIVERCRATE_EXPECT( context, preparation.items().front().result.state ==
										OfficialPreparationItemState::FAILURE) ;
	}

	bool descriptorFound{} ;	// RegistryにASIX定義を確認した場合true。
	// Registryは導入能力を持つが、取得失敗自体は候補や導入成功へ昇格しない。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// ASIXのregistry定義に対してのみ取得・導入capabilityを検証する。
		if( descriptor.id == ASIX_AX88179A_PROVIDER_ID) {
			descriptorFound = true ;
			DRIVERCRATE_EXPECT( context, (descriptor.capabilities &
										 capabilityMask( ProviderCapability::DOWNLOAD)) != 0U) ;
			DRIVERCRATE_EXPECT( context, (descriptor.capabilities &
										 capabilityMask( ProviderCapability::INSTALL)) != 0U) ;
		}
	}

	DRIVERCRATE_EXPECT( context, descriptorFound) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_prepared_acquisition_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialPreparedAcquisitionTests( TestContext &context)
{
	testPreparedReleaseSuccess( context) ;
	testPreparedReleaseChangeRejection( context) ;
	testPreparedReleaseTargetRejection( context) ;
	testPreparedReleaseCancellation( context) ;
	testPreparedReleaseFailures( context) ;
	testPreparedAcquisitionResultMapping( context) ;
	testBroadcomPreparedAdapter( context) ;
	testIntelEthernetPreparedAdapter( context) ;
	testIntelEthernetPreparationRejection( context) ;
	testComputedEulaRevision( context) ;
	testAsixPreparedReleaseIdentity( context) ;
	testAsixPreparedReleaseFieldChanges( context) ;
	testAsixPreparedReleaseCancellationAndRefreshFailures( context) ;
	testAsixPreparedReleaseCapacityCostAndTerminalStates( context) ;
	testAsixSinglePackageFailureAndInstallBlock( context) ;
}

} // namespace drivercrate::test
