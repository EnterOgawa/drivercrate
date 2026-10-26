//------------------------------------------------------------------------------
/**
 * @file common_inf_contract_cases.h
 * @brief 共通INFの34定義に対応する内部挙動と未接続範囲を試験する。
 * @version 01.00.02
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  34定義の内部範囲別試験を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.00.02 Shunji Ogawa  2026/10/24  必須解析の同値NativeError比較を明示。
 * </pre>
 *
 * @note 専用試験TUがBatchFixture定義後にだけ読み込む。製品許可や公開candidateを生成しない。
 * Windows署名・PnP・指定導入はfakeで、実封印・file固定・core復旧処理だけを実行する。
 * @see docs/adr/0287-common-inf-contract-runtime-scope.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/protected_install.h"
#include "platform/indexed_driver_package_inspection.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

namespace drivercrate::test {
namespace {

/** @brief 架空fileへの操作handleだけを回収する。 */
struct ContractHandleCloser {
	/** @brief 正常に開いたfixture handleを閉じる。
	 * @param[in] value 単独所有handle。無効値は閉じない。
	 */
	void operator()( void *value) const noexcept
	{
		// 無効値をWindowsへ渡さない。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief Fixtureだけの単独所有。
 */
using ContractHandle = std::unique_ptr<void, ContractHandleCloser> ;

/** @brief 制御したfake rank・bindingで封印初期化の拒否を観測する。
 * @param[in,out] target 空factory。
 * @param[in] session 生存issuer。
 * @param[in,out] archive 元workspace。失敗時も保持する。
 * @param[in,out] evidence 元封印。失敗時も保持する。
 * @return 検証対象initializeの元HRESULT。
 */
NativeError initializeContractSource( CommonInfPlanFactory							  &target,
									 std::shared_ptr<const OfficialAcquisitionSession> session,
									 std::unique_ptr<OfficialDownloadWorkspace>		  &archive,
									 OfficialAcquiredFileEvidence					  &evidence)
{
	// 初期化試験ではrankを呼ばず、準備境界へのfallbackを成功にしない。
	const OfficialInfRankAuditor rank = []( ScanSessionId, std::wstring_view,
										   const OfficialDownloadWorkspace &,
										   const OfficialInfPackage &, OfficialDriverRankAudit &) {
		return static_cast<NativeError>( E_NOTIMPL) ;
	} ;
	// 初期化だけのfixtureは有効tokenを発行しない。
	const OfficialInfInstallBinder binder =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, std::wstring_view, std::wstring_view, std::wstring_view,
		   const OfficialDriverRankAudit &,
		   OfficialInfInstallBinding &) { return static_cast<NativeError>( E_NOTIMPL) ; } ;
	// このfixtureでは発行tokenがなく、Windows登録物を変更しない。
	const OfficialInfInstallBindingReleaser release = []( ScanSessionId, std::uint64_t) {
		return true ;
	} ;
	return target.initialize( std::move( session), archive, evidence,
							 OfficialDriverArchiveFormat::ZIP, rank, binder, release) ;
}

/** @brief 任意の実IDを使わない現在版付き発行要求を作る。
 * @param[in] number 架空candidate／device番号。
 * @return 同scanの一基本INF要求。
 */
CommonInfPlanRequest contractRequest( unsigned number = 1U)
{
	return {91U,
			0U,
			L"candidate:" + std::to_wstring( number),
			L"device:" + std::to_wstring( number),
			L"Fictional Provider",
			L"1.0.0.0",
			L"2025/01/01"} ;
}

/** @brief 単一または共有INFの成功とfile固定・全失効を確認する。
 * @param[in,out] context Assertion集計先。
 * @param[in] count 同じ元取得を使う架空device数。1～33。
 */
void contractSuccess( TestContext &context, unsigned count = 1U)
{
	BatchFixture					  fixture( context) ;	// 一回だけ取得した元archive。
	std::vector<CommonInfInstallPlan> plans ;				// 同じ所有workerに限定する非複写計画。
	plans.reserve( count) ;
	std::vector<CommonInfPlanSelection> selected ;	// 実行終了まで位置を固定する借用列。
	selected.reserve( count) ;
	// 有限device数の準備を終えてから全件実行する。
	for( unsigned number = 1U; number <= count; ++number) {
		plans.emplace_back() ;
		selected.push_back( fixture.prepare( plans.back(), number)) ;
	}

	DRIVERCRATE_EXPECT( context, fixtureDownloads == 1U && fixture.installs == 0U) ;
	const auto report = fixture.execute( selected) ;	// GETを増やさず同じ元取得を使用する。
	DRIVERCRATE_EXPECT( context, report.result.succeeded && report.cleanupError == 0 &&
									fixture.installs == count && fixture.checks == count * 2U &&
									fixture.ranks == count * 3U) ;
	DRIVERCRATE_EXPECT( context, fixtureDownloads == 1U && fixture.released.size() == count) ;
	// 終了時にどの計画も再利用できない。
	for( const auto &plan : plans) {
		DRIVERCRATE_EXPECT( context, !plan.isBound()) ;
	}
}

/** @brief 再検証失敗と導入callback失敗を別の停止位置へ注入する。
 * @param[in,out] context Assertion集計先。
 * @param[in] kind 0は共有内容、1はrank、2は第二の直前binding、3は第二導入、4は導入例外。
 */
void contractFailure( TestContext &context, unsigned kind)
{
	BatchFixture						  fixture( context) ;	// 独立した一回の封印取得。
	CommonInfInstallPlan				  first ;				// 第一選択。
	CommonInfInstallPlan				  second ;				// 第二選択。
	std::array<CommonInfPlanSelection, 2> selected{				// 同じ通常閉包を共有する。
												   fixture.prepare( first, 1U),
												   fixture.prepare( second, 2U)} ;
	// 全件preflightで共有内容を拒否する。
	if( kind == 0U) {
		rejectContentAt = contentChecks + 1U ;
	}

	// 全rankの一field変更を拒否する。
	if( kind == 1U) {
		fixture.changeRank = true ;
	}

	// 第一導入後、第二の直前bindingを拒否する。
	if( kind == 2U) {
		fixture.rejectBindingAt = 4U ;
	}

	// 第一成功と第二導入失敗を保持する。
	if( kind == 3U) {
		fixture.rejectInstallAt = 2U ;
	}

	// 呼出し後の例外には変更可能性を保持する。
	if( kind == 4U) {
		fixture.throwInstall = true ;
	}

	const auto report = fixture.execute( selected) ;	// 共通実装へ失敗位置を渡す。
	DRIVERCRATE_EXPECT( context, !report.result.succeeded && !first.isBound() && !second.isBound() &&
									fixture.released.size() == 2U &&
									report.result.updates.size() == 2U) ;
	// 全件停止では一件も指定導入しない。
	if( kind <= 1U) {
		DRIVERCRATE_EXPECT( context,
						   fixture.installs == 0U && !report.installerInvoked[0] &&
							   !report.installerInvoked[1] &&
							   report.result.installError ==
								   static_cast<NativeError>(
									   kind == 0U ? E_FAIL : HRESULT_FROM_WIN32( ERROR_RETRY))) ;
	} else {
		DRIVERCRATE_EXPECT( context, fixture.installs == (kind == 3U ? 2U : 1U) &&
										report.installerInvoked[0] && report.result.rebootRequired) ;
		DRIVERCRATE_EXPECT( context,
						   report.result.installError ==
							   static_cast<NativeError>( kind == 4U ? E_UNEXPECTED : E_FAIL)) ;
	}
}

/** @brief Windowsの復元APIを呼ばない保護service。 */
struct ContractRestore final : IRestorePointService {
	/// 保護開始拒否を返す場合true。
	bool						reject{} ;
	/// 実coreからの開始回数。
	unsigned					begins{} ;
	/// 実coreからの終了回数。
	unsigned					ends{} ;
	/** @brief 架空開始結果だけを返す。
	 * @param[in] description 使用しない説明。
	 * @return 架空成功またはE_FAIL。
	 */
	RestorePointOperationResult begin( std::wstring_view description) noexcept override
	{
		static_cast<void>( description) ;
		++begins ;
		return reject ? RestorePointOperationResult{OutcomeCode::FAILURE, E_FAIL, 0}
					  : RestorePointOperationResult{OutcomeCode::SUCCESS, 0, 23} ;
	}
	/** @brief 架空終了を数え、成功を返す。
	 * @param[in] sequenceNumber 実coreが返した番号。
	 * @return 架空成功。
	 */
	RestorePointOperationResult complete( std::int64_t sequenceNumber) noexcept override
	{
		++ends ;
		return {OutcomeCode::SUCCESS, 0, sequenceNumber} ;
	}
} ;

/** @brief 実core復旧処理と内部adapterだけを接続する試験専用Provider。 */
struct ContractProvider final : IUpdateProvider {
	/// 呼出し終了まで生存する架空所有者。
	BatchFixture						   &fixture ;
	/// 実行中変更しない私有計画の借用集合。
	std::span<const CommonInfPlanSelection> selected ;
	/** @brief 試験の借用を固定する。
	 * @param[in,out] value 架空所有者。
	 * @param[in] selection 借用集合。
	 */
	ContractProvider( BatchFixture &value, std::span<const CommonInfPlanSelection> selection)
		: fixture( value), selected( selection)
	{
	}
	/** @brief この試験ではscanしない。
	 * @param[in] scan 使用しないsession。
	 * @param[in] options 使用しない設定。
	 * @param[in] progress 使用しない通知。
	 * @return 空の未開始結果。
	 */
	ScanResult scan( ScanSessionId scan, const ScanOptions &options,
					const ProviderProgressCallback &progress) override
	{
		static_cast<void>( scan) ;
		static_cast<void>( options) ;
		static_cast<void>( progress) ;
		return {} ;
	}
	/** @brief 保護coreから内部adapterへ同期委譲する。
	 * @param[in] scan 同じscan。
	 * @param[in] identities 使用しない架空表示ID。製品routingの代替ではない。
	 * @param[in] parentWindowNative 使用しない親値。
	 * @param[in] progress 借用同期通知。
	 * @return 元adapter結果。製品の最終同意や実OS確認を発行しない。
	 */
	InstallResult install( ScanSessionId scan, std::span<const std::wstring> identities,
						  std::uintptr_t				  parentWindowNative,
						  const ProviderProgressCallback &progress) override
	{
		static_cast<void>( identities) ;
		static_cast<void>( parentWindowNative) ;
		return fixture.execute( selected, progress, scan).result ;
	}
} ;

/** @brief 実coreのclient／Server保護経路と拒否をfake adapterへ接続する。
 * @param[in,out] context Assertion集計先。
 * @param[in] server Server専用core経路の場合true。実OS判定ではない。
 * @param[in] reject 保護開始拒否の場合true。Serverでは指定しない。
 */
void contractProtection( TestContext &context, bool server, bool reject = false)
{
	BatchFixture						  fixture( context) ;						// Fake指定導入だけを行う所有者。
	CommonInfInstallPlan				  plan ;									// 一device計画。
	std::array<CommonInfPlanSelection, 1> selected{fixture.prepare( plan, 1U)} ;	// 固定借用。
	ContractProvider provider( fixture, selected) ;									// 実coreから当該adapterへ委譲する。
	ContractRestore	 restore ;														// 実復元ポイントを作らないservice。
	restore.reject = reject ;
	std::array<std::wstring, 1>	   identities{selected[0].candidateIdentity} ;	// 架空表示IDだけ。
	// 同期通知は何も保存せず、実状態を推測しない。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;
	// 保護開始結果と元adapter結果を既存coreで集約する。
	const auto					   result =
		server
								? installWithoutRestorePointOnServer( provider, 91U, identities, 0U, progress)
								: installWithRestorePoint( provider, restore, 91U, identities, 0U, progress, L"Fixture") ;
	// Serverでは復元serviceを一度も呼ばない。
	if( server) {
		DRIVERCRATE_EXPECT( context,
						   result.succeeded && restore.begins == 0U && restore.ends == 0U &&
							   result.restorePointCreation.outcome == OutcomeCode::NOT_STARTED) ;
	} else {
		DRIVERCRATE_EXPECT( context, restore.begins == 1U && restore.ends == (reject ? 0U : 1U)) ;
	}

	DRIVERCRATE_EXPECT( context,
					   fixture.installs == (reject ? 0U : 1U) && result.succeeded == !reject) ;
	// 保護拒否ではProviderが未開始で、計画失効はworker接続の残件として区別する。
	if( reject) {
		DRIVERCRATE_EXPECT( context,
						   plan.isBound() && result.updates.size() == 1U &&
							   result.updates[0].installOutcome == OutcomeCode::NOT_STARTED) ;
		DRIVERCRATE_EXPECT( context, fixture.factory.invalidate() == 0 && !plan.isBound()) ;
	}
}

/** @brief 一定義の実装済み範囲だけを実行する。未接続の3定義は呼ばない。
 * @param[in,out] context Assertion集計先。
 * @param[in] number 定義番号1～34。
 */
void runContractCase( TestContext &context, unsigned number)
{
	// 認証・内容・選択・終了の実装済み範囲を原定義へ一対一対応する。
	switch( number) {
		// D001。公式record結合はI4へ残し、実封印から内部計画を発行する。
		case 1U:
			contractSuccess( context) ;
			break ;

		// D002。既定の公開値から計画を作れず、空証拠は生存issuerでも拒否する。
		case 2U: {
			static_assert( !std::is_constructible_v<CommonInfInstallPlan, IndexedDriverArchiveHint>) ;
			static_assert( !std::is_constructible_v<CommonInfInstallPlan, bool>) ;
			BatchFixture				 fixture( context, false) ;	// 元封印までの所有者。
			OfficialAcquiredFileEvidence empty ;					// 誰も発行していない公開既定値。
			DRIVERCRATE_EXPECT( context, initializeContractSource( fixture.factory, fixture.session,
																 fixture.archive, empty) != 0 &&
											fixture.archive && fixture.evidence.issuerAlive()) ;
			break ;
		}
		// D004。元archive・正常単一INF・全memberの所有と実byte固定を実行する。
		case 4U:
			contractSuccess( context, 2U) ;
			break ;

		// D005。別workspaceの同byteと研究DTOを計画の由来へ付け替えない。
		case 5U: {
			static_assert( !std::is_constructible_v<CommonInfInstallPlan, MaintenanceInfInspection>) ;
			BatchFixture first( context, false) ;	// 証拠を発行した元取得。
			BatchFixture other( context, false) ;	// 同じabc byteでも別位置。
			DRIVERCRATE_EXPECT( context,
							   initializeContractSource( first.factory, first.session, other.archive,
														first.evidence) != 0 &&
								   first.evidence.issuerAlive() && other.archive) ;
			break ;
		}
		// D006。Writer競合では使用中保護を取得できず、導入前に拒否する。
		case 6U: {
			BatchFixture						  fixture( context) ;					// 元取得の所有者。
			CommonInfInstallPlan				  plan ;								// 一device選択。
			std::array<CommonInfPlanSelection, 1> chosen{fixture.prepare( plan, 1U)} ;	// 固定借用。
			ContractHandle writer( CreateFileW( fixture.sourcePath.c_str(), GENERIC_WRITE,
											  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
											  OPEN_EXISTING, 0, nullptr)) ;	// 自分のfixtureだけ。
			DRIVERCRATE_EXPECT( context, writer.get() != INVALID_HANDLE_VALUE) ;
			const auto report = fixture.execute( chosen) ;	// 固定を阻害した状態で実行する。
			DRIVERCRATE_EXPECT( context, fixture.installs == 0U && !plan.isBound() &&
											report.result.installError ==
												static_cast<NativeError>(
													HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION))) ;
			break ;
		}
		// D007。通常合格かつ明示依存なしを受理する。
		case 7U:
			contractSuccess( context) ;
			break ;

		// D008。内容拒否と依存を止める。公式recordの必須条件は未接続である。
		case 8U: {
			// 単一INFでも明示依存と通常内容拒否を別々に拒否する。
			for( unsigned mode = 0U; mode < 2U; ++mode) {
				// 明示依存と通常内容拒否を別々の所有者で測る。
				BatchFixture		 fixture( context, true, 2U, mode == 0U,
									 mode == 1U ? CommonInfInspectionState::SIGNATURE_REJECTED
														: CommonInfInspectionState::VERIFIED) ;
				CommonInfInstallPlan plan ;	// 発行されない出力。
				DRIVERCRATE_EXPECT( context, fixture.factory.prepare( contractRequest(), plan) != 0 &&
												!plan.isBound() && fixture.binds == 0U &&
												fixture.installs == 0U) ;
			}

			break ;
		}
		// D009。通常合格に任意app不在や保守coverageを追加の必須入力にしない。
		case 9U:
			contractSuccess( context) ;
			break ;

		// D010。完全rankとbindingの全結合を実行する。実Windows nodeは未接続である。
		case 10U:
			contractSuccess( context) ;
			break ;

		// D011。現在metadata欠損と未評価rank・不一致bindingでは発行しない。
		case 11U: {
			// 各停止条件に元取得と未commit出力を独立に与える。
			for( unsigned mode = 0U; mode < 5U; ++mode) {
				BatchFixture		 fixture( context) ;			// 停止条件ごとの所有者。
				CommonInfPlanRequest request = contractRequest() ;	// 架空の正常現在snapshot。
				CommonInfInstallPlan plan ;							// 拒否対象の出力。
				// 現在Provider欠損を初回導入の架空値で補わない。
				if( mode == 0U) {
					request.currentProvider.clear() ;
				}

				// 現在版欠損を版比較だけで補わない。
				if( mode == 1U) {
					request.currentVersion.clear() ;
				}

				// 現在日付欠損を推測しない。
				if( mode == 2U) {
					request.currentDate.clear() ;
				}

				fixture.rejectRank	   = mode == 3U ;
				fixture.corruptBinding = mode == 4U ;
				DRIVERCRATE_EXPECT( context,
								   fixture.factory.prepare( request, plan) != 0 && !plan.isBound()) ;
				DRIVERCRATE_EXPECT( context, fixture.binds == (mode == 4U ? 1U : 0U) &&
												fixture.installs == 0U) ;
			}

			break ;
		}
		// D012。発行後の完全rank変更と現在node変更の拒否を保持する。
		case 12U:
			contractFailure( context, 1U) ;
			contractFailure( context, 2U) ;
			break ;

		// D013。非複写・移動と共有issuer所有を維持する。
		case 13U: {
			static_assert( !std::is_copy_constructible_v<CommonInfInstallPlan>) ;
			BatchFixture		 fixture( context) ;	// 生存issuerをfactoryへ移した所有者。
			CommonInfInstallPlan original ;				// 移動元計画。
			static_cast<void>( fixture.prepare( original, 1U)) ;
			CommonInfInstallPlan moved( std::move( original)) ;						// 同worker内の所有移動。
			std::weak_ptr<OfficialAcquisitionSession> issuer = fixture.session ;	// 生存所有の監視。
			fixture.session.reset() ;
			DRIVERCRATE_EXPECT( context,
							   !original.isBound() && moved.isBound() && !issuer.expired()) ;
			DRIVERCRATE_EXPECT( context, fixture.factory.invalidate() == 0 && !moved.isBound()) ;
			break ;
		}
		// D014。公開DTOとreadinessから私有状態を発行できない。
		case 14U: {
			static_assert( !std::is_constructible_v<CommonInfInstallPlan, CommonInfInspection>) ;
			CommonInfInstallPlan				  empty ;				// Factoryが発行していない空値。
			BatchFixture						  fixture( context) ;	// 空値を補完しない取得所有者。
			std::array<CommonInfPlanSelection, 1> selected{
				{{&empty, L"candidate:1", L"device:1"}}} ;	// 架空公開ID。
			DRIVERCRATE_EXPECT( context, !fixture.execute( selected).result.succeeded &&
											fixture.installs == 0U) ;
			break ;
		}
		// D015。別threadと全失効後の旧計画を変更せず拒否する。
		case 15U: {
			BatchFixture						  fixture( context) ;	// Owner workerを保持する。
			CommonInfInstallPlan				  plan ;				// 発行済み計画。
			std::array<CommonInfPlanSelection, 1> selected{				// Joinまで固定する。
														   fixture.prepare( plan, 1U)} ;
			std::thread							  other( [&] {
				  // 所有者とfixtureをjoinまで借り、別thread拒否だけを観測する。
				  DRIVERCRATE_EXPECT( context, fixture.execute( selected).result.installError ==
																		  RPC_E_WRONG_THREAD) ;
			  }) ;
			other.join() ;
			DRIVERCRATE_EXPECT( context, plan.isBound() && fixture.released.empty()) ;
			DRIVERCRATE_EXPECT( context, fixture.factory.invalidate() == 0 && !plan.isBound()) ;
			DRIVERCRATE_EXPECT( context, !fixture.execute( selected).result.succeeded &&
											fixture.installs == 0U) ;
			break ;
		}
		// D017。有効元取得でも必須callback欠落を初期化前に拒否する。
		case 17U: {
			BatchFixture fixture( context, false) ;	// 未消費の有効元取得。
			DRIVERCRATE_EXPECT( context, fixture.factory.initialize( fixture.session, fixture.archive,
																   fixture.evidence,
																   OfficialDriverArchiveFormat::ZIP,
																   {}, {}, {}) == E_INVALIDARG) ;
			DRIVERCRATE_EXPECT( context, fixture.archive && fixture.evidence.issuerAlive() &&
											fixture.installs == 0U) ;
			break ;
		}
		// D018。発行途中の取消し／例外では新規tokenだけを回収する。
		case 18U: {
			// 先行commit計画を持たせ、二つのrollback原因を個別に実行する。
			for( unsigned mode = 0U; mode < 2U; ++mode) {
				BatchFixture		 fixture( context) ;	// 先行と未commitを同じ所有者へ結ぶ。
				CommonInfInstallPlan first ;				// 維持される先行計画。
				static_cast<void>( fixture.prepare( first, 1U)) ;
				fixture.binderResult = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
				fixture.throwBinder	 = mode == 1U ;
				CommonInfInstallPlan next ;	// 発行されない新規計画。
				const NativeError	 error =
					// 元診断。
					fixture.factory.prepare( contractRequest( 2U), next) ;
				DRIVERCRATE_EXPECT(
					context,
					error == static_cast<NativeError>(
								 mode == 1U ? E_UNEXPECTED : HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
				DRIVERCRATE_EXPECT( context, first.isBound() && !next.isBound() &&
												fixture.installs == 0U &&
												fixture.released == std::vector<std::uint64_t>{2U}) ;
			}

			break ;
		}
		// D019。同一元取得を共有して各deviceを個別に指定する。
		case 19U:
			contractSuccess( context, 2U) ;
			break ;

		// D020。未知候補・別device・重複・別scanの全件事前拒否を実行する。
		case 20U: {
			// 各不一致を新しい所有者で実行し、他の選択も開始しない。
			for( unsigned mode = 0U; mode < 4U; ++mode) {
				BatchFixture		 fixture( context) ;	// 当該不一致だけを測定する。
				CommonInfInstallPlan first ;				// 正常第一選択。
				CommonInfInstallPlan second ;				// 不一致を注入する第二選択。
				std::array<CommonInfPlanSelection, 2> selected{fixture.prepare( first, 1U),
															   // 入力集合の位置を保持する。
															   fixture.prepare( second, 2U)} ;
				// Unknown候補のIDを推測で補完しない。
				if( mode == 0U) {
					selected[1].candidateIdentity = L"unknown" ;
				}

				// 別deviceへの計画転用を拒否する。
				if( mode == 1U) {
					selected[1].deviceIdentity = selected[0].deviceIdentity ;
				}

				// 同じ計画の重複選択を拒否する。
				if( mode == 2U) {
					selected[1] = selected[0] ;
				}

				// 保護開始結果と元adapter結果を既存coreで集約する。
				const auto result =
					// 別scanも拒否する。
					fixture.execute( selected, {}, mode == 3U ? 92U : 91U) ;
				DRIVERCRATE_EXPECT( context, result.result.installError == E_INVALIDARG &&
												fixture.installs == 0U && !first.isBound() &&
												!second.isBound()) ;
			}

			break ;
		}
		// D021。同じdeviceの代替draftは選択前に削除せず、選択後も再検証する。
		case 21U: {
			BatchFixture						  fixture( context) ;	// 一つの通常内容の所有者。
			CommonInfInstallPlan				  first ;				// 既定候補のdraft。
			CommonInfInstallPlan				  alternative ;			// 同版代替のdraft。
			std::array<CommonInfPlanSelection, 1> selected{				// 一件だけ選択する。
														   fixture.prepare( first, 1U)} ;
			CommonInfPlanRequest request = contractRequest( 2U) ;	// 別candidateの要求。
			request.deviceIdentity		 = selected[0].deviceIdentity ;
			DRIVERCRATE_EXPECT( context, fixture.factory.prepare( request, alternative) == 0 &&
											first.isBound() && alternative.isBound()) ;
			const auto before = contentChecks ;	// 成功cache後の再検証回数。
			DRIVERCRATE_EXPECT( context, fixture.execute( selected).result.succeeded &&
											contentChecks > before && fixture.installs == 1U &&
											!alternative.isBound()) ;
			break ;
		}
		// D022。実coreの保護経路だけをfake serviceへ接続し、実OS・同意とは分ける。
		case 22U:
			contractProtection( context, false) ;
			contractProtection( context, true) ;
			break ;

		// D023。復元拒否とmode不一致ではcallbackを呼ばない。
		case 23U:
			contractProtection( context, false, true) ;
			DRIVERCRATE_EXPECT( context, !isInstallProtectionModeAllowed(
											true, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
			DRIVERCRATE_EXPECT( context,
							   !isInstallProtectionModeAllowed(
								   false, InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT)) ;
			break ;

		// D025。全件と直前再検証後だけ既存形状callbackへ渡す。
		case 25U:
			contractSuccess( context, 2U) ;
			break ;

		// D026。再検証拒否／例外でfallbackせず、全計画を失効する。
		case 26U: {
			// 二つの境界失敗で指定導入呼出し0を独立に確認する。
			for( unsigned mode = 0U; mode < 2U; ++mode) {
				BatchFixture						  fixture( context) ;	// 失敗位置ごとの所有者。
				CommonInfInstallPlan				  plan ;				// 正常に発行した計画。
				std::array<CommonInfPlanSelection, 1> chosen{				// 固定選択。
															 fixture.prepare( plan, 1U)} ;
				fixture.rejectBindingAt = 1U ;
				fixture.throwCheckAt	= mode == 1U ? 1U : 0U ;
				const auto report = fixture.execute( chosen) ;	// callback内の例外も結果へ変換する。
				DRIVERCRATE_EXPECT(
					context, fixture.installs == 0U && !plan.isBound() &&
								 report.result.installError ==
									 static_cast<NativeError>( mode == 1U ? E_UNEXPECTED : E_FAIL)) ;
			}

			break ;
		}
		// D027。共有内容・rankと第二device直前失敗の元HRESULTを分ける。
		case 27U:
			contractFailure( context, 0U) ;
			contractFailure( context, 1U) ;
			contractFailure( context, 2U) ;
			break ;

		// D028。個別結果・再起動・終了失効を確認し、事後device照会はI4へ残す。
		case 28U:
			contractSuccess( context, 2U) ;
			break ;

		// D029。未選択計画を導入せず、終了後の旧計画を実行しない。
		case 29U: {
			BatchFixture						  fixture( context) ;	// 一操作の全draftを保持する。
			CommonInfInstallPlan				  first ;				// 唯一の選択。
			CommonInfInstallPlan				  unselected ;			// 未選択のdraft。
			std::array<CommonInfPlanSelection, 1> chosen{				// 第一だけを選ぶ。
														 fixture.prepare( first, 1U)} ;
			static_cast<void>( fixture.prepare( unselected, 2U)) ;
			DRIVERCRATE_EXPECT( context, fixture.execute( chosen).result.succeeded &&
											fixture.installs == 1U && !unselected.isBound() &&
											fixture.released.size() == 2U) ;
			DRIVERCRATE_EXPECT( context, !fixture.execute( chosen).result.succeeded &&
											fixture.installs == 1U && fixtureDownloads == 1U) ;
			break ;
		}
		// D030。呼出し後例外を変更なしと扱わず、再起動観測を保持する。
		case 30U:
			contractFailure( context, 4U) ;
			break ;

		// D031。部分成功・導入例外と保護拒否を全成功にしない。
		case 31U:
			contractFailure( context, 3U) ;
			contractFailure( context, 4U) ;
			contractProtection( context, false, true) ;
			break ;

		// D032。私有有限計画をworker内だけで保持する。
		case 32U:
			contractSuccess( context) ;
			break ;

		// D033。INF・一回候補・identity・累計取得の予算を拒否する。
		case 33U: {
			BatchFixture oversizedInfs( context, true, 129U) ;	// 上限超過の架空通常解析。
			DRIVERCRATE_EXPECT(
				context, oversizedInfs.factory.infCount() == 0U && oversizedInfs.archive &&
							 oversizedInfs.evidence.issuerAlive() && oversizedInfs.installs == 0U) ;
			BatchFixture						fixture( context) ;						// 候補とidentity上限を測る。
			CommonInfInstallPlan				plan ;									// 拒否前後で所有を保つ一計画。
			const auto							chosen = fixture.prepare( plan, 1U) ;	// 正常な一件。
			std::vector<CommonInfPlanSelection> tooMany( 4097U, chosen) ;				// 一実行だけの超過集合。
			DRIVERCRATE_EXPECT( context,
							   fixture.execute( tooMany).result.installError == E_INVALIDARG &&
								   fixture.installs == 0U && plan.isBound()) ;
			std::array<CommonInfPlanSelection, 1> tooLong{chosen} ;	// 過大文字列を結果へ複写しない。
			tooLong[0].candidateIdentity.assign( 257U, L'x') ;
			DRIVERCRATE_EXPECT( context,
							   fixture.execute( tooLong).result.installError == E_INVALIDARG &&
								   plan.isBound()) ;
			OfficialAcquisitionSession budget ;	// 別issuerの厳密な3 byte累計予算。
			DRIVERCRATE_EXPECT( context, budget.initialize( 92U, {3U, 3U, 3U, 0U, 2U, 2U}) == 0) ;
			OfficialDownloadWorkspace archive ;	// 架空byteだけの有限所有領域。
			DRIVERCRATE_EXPECT( context, archive.initialize( L"budget-fixture", 92U) == 0) ;
			BatchTransport			   transport ;	// 実通信しない取得境界。
			BatchCost				   cost ;		// 実回線状態を照会しない境界。
			OfficialAcquisitionRequest request{.url = L"https://us.download.nvidia.com/fixture.bin",
											   .providerId		  = NVIDIA_PROVIDER_ID,
											   .resourceId		  = OFFICIAL_PAYLOAD_RESOURCE_ID,
											   .workspaceFileName = L"one.bin",
											   .maximumFileBytes  = 3U} ;	// 一回で累計を使い切る。
			OfficialAcquisitionResult  acquired ;							// pathを出力しない内部結果。
			// 確定通知を保存せず、取得許可だけの境界を実行する。
			const HttpDownloadProgressCallback progress = []( std::uint64_t, std::uint64_t) {} ;
			DRIVERCRATE_EXPECT( context, budget.acquire( request, archive, transport, cost, progress,
													   {}, acquired) == 0) ;
			const auto downloads	  = fixtureDownloads ;	// 成功後のtransport呼出し数。
			request.workspaceFileName = L"two.bin" ;
			DRIVERCRATE_EXPECT( context, budget.acquire( request, archive, transport, cost, progress,
													   {}, acquired) != 0 &&
											fixtureDownloads == downloads) ;
			break ;
		}
		// D034。旧profileの32件制約を共通計画の対応上限に流用しない。
		case 34U:
			contractSuccess( context, 33U) ;
			break ;

		// 未接続定義の実行を呼出し側が誤って要求した場合は試験を失敗させる。
		default:
			DRIVERCRATE_EXPECT( context, false) ;
			break ;
	}
}

/** @brief 34定義を境界全確認・部分確認・未接続のまま出力する。
 * @param[in,out] context Base試験に追加する集計先。
 */
void runContractTests( TestContext &context)
{
	constexpr std::array<unsigned, 15> RUNTIME_CASES{
		4U, 5U, 6U, 7U, 9U, 11U, 12U, 13U, 15U, 18U, 19U, 25U, 27U, 30U, 32U} ;	// 内部範囲全確認。
	// 原定義の順序を保持し、未実行をassertionへ加算しない。
	for( unsigned number = 1U; number <= 34U; ++number) {
		const bool deferred = number == 3U || number == 16U || number == 24U ;	// 製品routeが未実装。
		const bool full		= std::find( RUNTIME_CASES.begin(), RUNTIME_CASES.end(), number) !=
						  // 内部定義を全確認する。
						  RUNTIME_CASES.end() ;
		const int before   = context.assertionCount() ;	// 当該caseだけの実行差分。
		const int failures = context.failureCount() ;	// 当該caseだけの失敗差分。
		// 未接続は実行済みや合格に変換しない。
		if( !deferred) {
			runContractCase( context, number) ;
		}

		std::cout << "Common INF contract D" << (number < 10U ? "00" : "0") << number << ": scope="
				  << (deferred ? "DEFERRED"
					  : full   ? "RUNTIME"
							   : "PARTIAL")
				  << ", assertions=" << context.assertionCount() - before
				  << ", failures=" << context.failureCount() - failures << '\n' ;
	}
}
} // namespace
} // namespace drivercrate::test
