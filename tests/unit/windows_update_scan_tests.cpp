//------------------------------------------------------------------------------
/**
 * @file windows_update_scan_tests.cpp
 * @brief WUA共有終端と通常Compositeの部分結果保持を非通信で検証します
 * @version 01.00.06
 * @date 2026/11/12
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/12  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * Ver.01.00.03 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.00.04 Shunji Ogawa  2026/11/13  bounded opaque PnP IDのrank照合と限定回帰を接続
 * Ver.01.00.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.00.06 Shunji Ogawa  2026/11/14  導入後の推奨表示から処理済み対象だけを除外
 * </pre>
 * @note 全実Providerのscanをfakeまたは無効へ固定し、現在行/通信/保護state生成を持ちません
 */
//------------------------------------------------------------------------------
#include "platform/windows_update_provider.h"
#include "platform/windows_update_identity_internal.h"
#include "platform/signed_index_candidate_binding_internal.h"
#include "platform/local_diagnostic_log.h"
#include "core/candidate_audit.h"
#include "core/provider_registry.h"
#include "test_framework.h"
#include "windows_update_provider_tests.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>

namespace {
using namespace drivercrate ;
//------------------------------------------------------------------------------
// 非通信fixture定義
//------------------------------------------------------------------------------
constexpr NativeError	ENDPOINT_UNREACHABLE = static_cast<NativeError>( 0x80240438U) ;	// 元codeです
constexpr ScanSessionId SESSION				 = 840U ;									// 架空scanだけの正のsessionです

/** @brief 実APIを呼ばず、生のWUA結果を共有producer終端へ渡すfixtureです */
class ResultProvider	final : public IUpdateProvider {
public:
	   /// Native代替入力です。stateは既定値から開始できます
	   ScanResult				raw ;
	   /// WUAの製品共有終端を通す場合trueです
	   bool						complete{} ;
	   /// 旧不備/悪意あるproducerを共通guardへ渡す場合だけtrueです
	   bool						corruptState{} ;
	   /// 同期scanの呼出し数です
	   unsigned					calls{} ;
	   /**
	 * @brief 生結果を製品共有終端へ渡し、既registry callbackへ返します
	 * @param[in] session 当該Compositeが固定したsessionです
	 * @param[in] options 未使用の第2引数です。外部Providerを選択しません
	 * @param[in] progress 未使用の第3引数です。実APIを呼びません
	 * @return 共有終端の結果または故意に矛盾させた拒否試験入力です
	 */
	   [[nodiscard]] ScanResult scan( const ScanSessionId session, const ScanOptions &options,
									 const ProviderProgressCallback &progress) override
	   {
		   static_cast<void>( options) ;
		   static_cast<void>( progress) ;
		   ++calls ;
		   auto result			= raw ;	// state期待値を手書きせず、製品共有処理へ元fieldを渡します
		   result.scanSessionId = session ;
		   // WUAだけが使用する製品終端そのものを実行します
		   if( complete) {
			   result = completeWindowsUpdateScanResult( std::move( result)) ;
		   }

		   // 改変結果を共有guardが受け入れないことを独立に確認します
		   if( corruptState) {
			   result.state = ProviderScanState::NO_CANDIDATES ;
		   }

		   return result ;
	   }
	   /**
	 * @brief 検索だけのfixtureが導入へ進む要求を拒否します
	 * @param[in] session 未使用の第1引数です
	 * @param[in] identities 未使用の第2引数です
	 * @param[in] parent 未使用の第3引数です
	 * @param[in] progress 未使用の第4引数です
	 * @return 作用なしの失敗結果です
	 */
	   [[nodiscard]] InstallResult install( ScanSessionId				   session,
										   std::span<const std::wstring>   identities,
										   std::uintptr_t				   parent,
										   const ProviderProgressCallback &progress) override
	   {
		   static_cast<void>( session) ;
		   static_cast<void>( identities) ;
		   static_cast<void>( parent) ;
		   static_cast<void>( progress) ;
		   return {.installOutcome = OutcomeCode::FAILURE} ;
	   }
} ;
//------------------------------------------------------------------------------
/**
 * @brief 元個数だけの架空Windows管理候補を作ります
 * @param[in] provider 既registryのWUAまたはDriver Store IDです
 * @param[in] count 148以下の表示候補数です
 * @return 現在行/秘密/実device結合を持たない所有候補集合です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<UpdateCandidate> candidates( const std::wstring_view provider,
													  const unsigned		  count)
{
	std::vector<UpdateCandidate> result ;	// 元数と順序を持つ合成候補です
	// 同名の実deviceや実driverへ結び付けず、有限個のpublic fake IDだけを使います
	for( unsigned index{}; index < count; ++index) {
		UpdateCandidate candidate ;	// 一行だけのWindows管理metadataです
		candidate.identity		  = std::wstring( provider) + L"-fixture-" + std::to_wstring( index) ;
		candidate.deviceIdentity  = L"fixture-device-" + std::to_wstring( index) ;
		candidate.packageIdentity = candidate.identity ;
		candidate.providerId	  = provider ;
		candidate.manufacturer	  = L"Fixture" ;
		candidate.title			  = L"Fixture driver" ;
		candidate.driverClass	  = L"Net" ;
		candidate.version		  = L"2.0.0.0" ;
		candidate.action		  = DriverAction::UPDATE ;
		candidate.installable	  = true ;
		candidate.audit			  = makeWindowsManagedCandidateAudit( false) ;
		candidate.discoveryBasis  = provider == WINDOWS_UPDATE_PROVIDER_ID
										? CandidateDiscoveryBasis::MANAGED_SERVICE
										: CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		result.push_back( std::move( candidate)) ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実Compositeの既registryへ非通信の二slotを接続します
 * @param[in,out] context assertion集計先です
 * @param[in] managed WUAの生結果と共有終端のfixtureです
 * @param[in] inventoryCount 元Driver Store成功の合成候補数です
 * @param[in] cancel 作用前取消しを確認する場合trueです
 * @return 本物Compositeの検証/候補統合を通った結果です
 * @note 現在行0により公式snapshotは空、他Provider全無効で保護state生成と通信はありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanResult aggregate( drivercrate::test::TestContext		 &context,
								   const std::shared_ptr<ResultProvider> &managed,
								   const unsigned inventoryCount = 148U, const bool cancel = false)
{
	auto composite =
		std::make_unique<CompositeUpdateProvider>() ;					// 大きな本物registryを単独所有します
	auto inventory			  = std::make_shared<ResultProvider>() ;	// 実native列挙を持ちません
	inventory->raw.succeeded  = true ;
	inventory->raw.outcome	  = OutcomeCode::SUCCESS ;
	inventory->raw.candidates = candidates( DRIVER_STORE_PROVIDER_ID, inventoryCount) ;
	DRIVERCRATE_EXPECT(
		context, signed_index_candidate_binding_detail::Access::setInventoryScanFixture( *composite,
																						inventory)) ;
	DRIVERCRATE_EXPECT( context, signed_index_candidate_binding_detail::Access::setManagedFixture(
									*composite, managed)) ;
	const ScanOptions options{.useDefaultProviders = false,
							  .enabledProviderIds  = {std::wstring( DRIVER_STORE_PROVIDER_ID),
													  // 他の実Providerを全て無効にします
													  std::wstring( WINDOWS_UPDATE_PROVIDER_ID)}} ;
	auto			  result = composite->scanWithCancellation(
		 SESSION, options, [cancel] { return cancel ; },
		 []( const ProviderProgress &) {}) ;	// 固定取消しだけを照会し、loggerも開始しません
	DRIVERCRATE_EXPECT( context, inventory->calls == (cancel ? 0U : 1U)) ;
	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 到達不可の旧拒否と修正後の148候補保持を同じCompositeで照合します
 * @param[in,out] context assertion集計先です
 */
//------------------------------------------------------------------------------
void endpointRegression( drivercrate::test::TestContext &context)
{
	auto managed = std::make_shared<ResultProvider>() ;	// 旧NO_CANDIDATESを既定のまま保持します
	managed->raw.outcome = OutcomeCode::FAILURE ;
	managed->raw.error	 = ENDPOINT_UNREACHABLE ;
	DRIVERCRATE_EXPECT( context, !isProviderScanResultConsistent( managed->raw, true)) ;
	const auto old = aggregate( context, managed) ;	// 原source経路の形状を非通信で再現します
	DRIVERCRATE_EXPECT( context, !old.succeeded && old.outcome == OutcomeCode::FAILURE &&
									old.error == static_cast<NativeError>( E_UNEXPECTED) &&
									old.candidates.empty()) ;
	managed->complete = true ;
	const auto fixed  = aggregate( context, managed) ;	// 同じ生HRESULTを製品終端へ渡します
	DRIVERCRATE_EXPECT( context,
					   fixed.succeeded && fixed.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	DRIVERCRATE_EXPECT( context,
					   fixed.error == ENDPOINT_UNREACHABLE && fixed.candidates.size() == 148U) ;
	DRIVERCRATE_EXPECT( context, std::ranges::all_of( fixed.candidates, []( const auto &value) {
						   return value.providerId == DRIVER_STORE_PROVIDER_ID ;
					   })) ;
	const auto report = std::ranges::find_if( fixed.providerReports, []( const auto &value) {
		return value.descriptor.id == WINDOWS_UPDATE_PROVIDER_ID ;
	}) ; // 表示用stateと元HRESULTを確認します
	DRIVERCRATE_EXPECT( context, report != fixed.providerReports.end() &&
									report->state == ProviderScanState::FAILURE &&
									report->error == ENDPOINT_UNREACHABLE &&
									report->candidateCount == 0U &&
									report->outcome == OutcomeCode::FAILURE) ;
	managed->corruptState = true ;
	const auto corrupt	  = aggregate( context, managed) ;	// 共有終端後の不正結果も受理しません
	DRIVERCRATE_EXPECT( context, !corrupt.succeeded &&
									corrupt.error == static_cast<NativeError>( E_UNEXPECTED) &&
									corrupt.candidates.empty()) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 成功/空/部分成功/失敗途中/中止を製品共有終端と実集約で確認します
 * @param[in,out] context assertion集計先です
 */
//------------------------------------------------------------------------------
void terminalMatrix( drivercrate::test::TestContext &context)
{
	const std::array<OutcomeCode, 7> outcomes{
		OutcomeCode::SUCCESS, OutcomeCode::SUCCEEDED_WITH_ERRORS, OutcomeCode::FAILURE,
		OutcomeCode::ABORTED, OutcomeCode::NOT_STARTED, OutcomeCode::IN_PROGRESS,
		// 非終端も拒否します
		static_cast<OutcomeCode>( 999)} ;
	// 一件だけの未確定WUA候補が失敗時に残らず、他Providerの148件だけを保つことを確認します
	for( const auto outcome : outcomes) {
		ScanResult raw ;	// state/succeededを期待値で埋めず、製品終端に任せます
		raw.scanSessionId = SESSION ;
		raw.outcome		  = outcome ;
		raw.error = outcome == OutcomeCode::SUCCESS || outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS
						? 0
						: ENDPOINT_UNREACHABLE ;
		raw.candidates	   = candidates( WINDOWS_UPDATE_PROVIDER_ID, 1U) ;
		const bool success = outcome == OutcomeCode::SUCCESS ||
							 // 元WUA終端分類です
							 outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
		const auto terminal = completeWindowsUpdateScanResult( raw) ;	// 製品と同じ処理を使います
		DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( terminal, true)) ;
		DRIVERCRATE_EXPECT( context, terminal.error == raw.error && terminal.succeeded == success &&
										terminal.scanSessionId == SESSION) ;
		DRIVERCRATE_EXPECT( context,
						   terminal.state == (success ? ProviderScanState::CANDIDATES_AVAILABLE
													  : ProviderScanState::FAILURE) &&
							   terminal.candidates.size() == (success ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, terminal.outcome == (success || outcome == OutcomeCode::ABORTED
															 ? outcome
															 : OutcomeCode::FAILURE)) ;
		auto managed	  = std::make_shared<ResultProvider>() ;	// 元の途中候補を共有終端へ渡します
		managed->raw	  = raw ;
		managed->complete = true ;
		const auto result = aggregate( context, managed) ;	// 期待stateだけをfakeへ手書きしません
		DRIVERCRATE_EXPECT( context,
						   result.succeeded && result.candidates.size() == (success ? 149U : 148U)) ;
		DRIVERCRATE_EXPECT( context, result.outcome == (outcome == OutcomeCode::SUCCESS
														   ? OutcomeCode::SUCCESS
														   : OutcomeCode::SUCCEEDED_WITH_ERRORS)) ;
	}

	auto empty			= std::make_shared<ResultProvider>() ;	// 候補0でもquery成功と失敗を分けます
	empty->complete		= true ;
	empty->raw.outcome	= OutcomeCode::SUCCESS ;
	const auto terminal = completeWindowsUpdateScanResult( empty->raw) ;	// 正常な空検索です
	DRIVERCRATE_EXPECT( context,
					   terminal.succeeded && terminal.state == ProviderScanState::NO_CANDIDATES &&
						   terminal.error == 0 && isProviderScanResultConsistent( terminal, true)) ;
	const auto noCandidates = aggregate( context, empty, 0U) ;	// 全Providerの正常空終端です
	DRIVERCRATE_EXPECT( context, noCandidates.succeeded &&
									noCandidates.outcome == OutcomeCode::SUCCESS &&
									noCandidates.state == ProviderScanState::NO_CANDIDATES &&
									noCandidates.candidates.empty()) ;
	const auto cancelled = aggregate( context, empty, 148U, true) ;	// 元Composite取消しも維持します
	DRIVERCRATE_EXPECT( context, !cancelled.succeeded && cancelled.outcome == OutcomeCode::ABORTED &&
									cancelled.candidates.empty() && empty->calls == 1U) ;
	ScanResult noNativeError ;	// WUA結果区分だけの既失敗を確認します
	noNativeError.outcome = OutcomeCode::ABORTED ;
	const auto abort = completeWindowsUpdateScanResult( noNativeError) ;	// 元ABORTED/E_FAILを保ちます
	DRIVERCRATE_EXPECT( context, abort.outcome == OutcomeCode::ABORTED &&
									abort.error == static_cast<NativeError>( E_FAIL) &&
									abort.state == ProviderScanState::FAILURE) ;
	WindowsUpdateProvider native ;													// session0拒否はCOM初期化前の実producer入口です
	const auto invalid = native.scan( 0U, {}, []( const ProviderProgress &) {}) ;	// 実WUA呼出し0です
	DRIVERCRATE_EXPECT( context, !invalid.succeeded && invalid.state == ProviderScanState::FAILURE &&
									invalid.error == static_cast<NativeError>( E_INVALIDARG) &&
									isProviderScanResultConsistent( invalid, true)) ;
	DRIVERCRATE_EXPECT( context, LOCAL_DIAGNOSTIC_REVISION == 12U) ;
}
//------------------------------------------------------------------------------
/**
 * @brief WUAの36/38文字UUIDだけを非ProgIDの製品parserで検証します
 * @param[in,out] context 同processの有限assertion集計です
 * @note 実WUA/registry/文字列の永続登録を呼びません
 */
//------------------------------------------------------------------------------
void strictIdentity( drivercrate::test::TestContext &context)
{
	GUID plain{}, braced{}, zero{} ;	// 解析結果だけを比較する非秘密の架空UUIDです
	DRIVERCRATE_EXPECT( context, windows_update_detail::parseIdentity(
									L"12345678-9abc-def0-1234-56789abcdef0", plain) == S_OK) ;
	DRIVERCRATE_EXPECT( context, windows_update_detail::parseIdentity(
									L"{12345678-9ABC-DEF0-1234-56789ABCDEF0}", braced) == S_OK &&
									IsEqualGUID( plain, braced)) ;
	DRIVERCRATE_EXPECT( context, windows_update_detail::parseIdentity(
									L"00000000-0000-0000-0000-000000000000", zero) == S_OK &&
									IsEqualGUID( zero, GUID_NULL)) ;
	const std::array<std::wstring, 11U> invalid{
		// 固定契約から作る独立した正負の期待です
		{L"", L"Synthetic.ProgId", L"12345678-9abc-def0-1234-56789abcdef0x",
		 L"{12345678-9abc-def0-1234-56789abcdef0", L"12345678-9abc-def0-1234-56789abcdef0}",
		 L" 12345678-9abc-def0-1234-56789abcdef0", L"123456789abc-def0-1234-56789abcdef0",
		 L"１２３４５６７８-9abc-def0-1234-56789abcdef0", L"12345678-9abc-def0-1234-56789abcdeg0",
		 std::wstring{L"12345678-9abc-def0-1234-56789abcdef0\0tail", 41U},
		 std::wstring{L"{12345678-9abc-def0-1234-56789abcdef0}\0tail", 43U}}} ;
	// BSTR全長と同じviewを渡し、NUL後tailも省略しません
	for( const auto &value : invalid) {
		GUID rejected{} ;	// 固定契約から作る独立した正負の期待です
		DRIVERCRATE_EXPECT( context,
						   windows_update_detail::parseIdentity( value, rejected) == E_INVALIDARG) ;
	}
}
}
//------------------------------------------------------------------------------
/**
 * @brief 実検索を使わずWUA終端/共通guard/Compositeの有限回帰を実行します
 * @return 全期待成立0、例外または期待不一致1です
 */
//------------------------------------------------------------------------------
int main()
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) ;
	drivercrate::test::TestContext context ;	// popupやabortを使わない集計です
	try {
		drivercrate::test::runWindowsUpdateProviderTests( context) ;
		endpointRegression( context) ;
		terminalMatrix( context) ;
		strictIdentity( context) ;
	} catch( ...) {
		// 私有例外本文を出さず、実行失敗を分母に残します
		DRIVERCRATE_EXPECT( context, false) ;
	}

	std::printf( "WUA_SCAN checks=%d failures=%d realWua=0 realInventory=0 network=0\n",
				context.assertionCount(), context.failureCount()) ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
