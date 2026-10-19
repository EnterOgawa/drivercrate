//------------------------------------------------------------------------------
/**
 * @file provider_worker.cpp
 * @brief Provider worker実装。
 * @version 01.08.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  候補発行例外時の保持物失効を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  件数付き進捗event追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント保護追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  公式vendor Provider統合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider選択条件転送追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Server用install保護mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan計測へoperation IDとapplication版を拘束。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  一scan承認結合と協調取消し信号を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  同scan索引の取得計画・実taskと内容結果を接続。
 * Ver.01.03.01 Shunji Ogawa  2026/10/12  索引取得callback例外で能力を失効し項目診断を維持。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  必要構成不足を復旧開始より前に拒否。
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  同MTAで完全低位依存fixtureの所有と停止を結合。
 * Ver.01.08.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * </pre>
 *
 * @note COM MTA worker threadと有限command/result queueを実装します。UIへの通知はPostMessageを使用し、COM objectをUI
 *       threadへ渡しません。
 */
//------------------------------------------------------------------------------

#include "platform/provider_worker.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/driver_store_inf_transport_internal.h"
#include "platform/driver_package_signature_internal.h"
#include <stdexcept>

#include "core/protected_install.h"
#include "core/metadata_search.h"
#include "core/metadata_search_budget.h"
#include "core/provider_registry.h"
#include "core/scan_measurement.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"
#include "platform/official_acquisition.h"
#include "platform/windows_product_type.h"
#include "platform/windows_restore_point_service.h"

#include "drivercrate_version.h"

#include <Windows.h>

#include <atomic>
#include <algorithm>

#include <limits>
#include <memory>
#include <type_traits>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ScanResultから不正または未拘束の新計測だけを一括で除く。
 * @param[in,out] result 正常候補と従来集計を保持するscan結果。
 */
//------------------------------------------------------------------------------
void clearPublishedScanMeasurement( ScanResult &result) noexcept
{
	result.measurement.reset() ;
	// Provider別の一部だけを残さず、全reportを未接続状態へ戻す。
	for( ProviderScanReport &report : result.providerReports) {
		report.coverage.measurement.reset() ;
	}

	// Group別の一部だけを残さず、従来到達件数だけを維持する。
	for( LocalCoverageEntry &entry : result.localCoverage) {
		entry.measurement.reset() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Compositeのscan計測へUI発行operationと実application版を拘束する。
 * @param[in] operationId UI state machineが発行した非ゼロoperation ID。
 * @param[in] scanSessionId Workerが発行した非ゼロscan session ID。
 * @param[in,out] result Provider結果。計測だけを拘束・検証し、候補権限は変更しない。
 */
//------------------------------------------------------------------------------
void bindPublishedScanMeasurement( const OperationId operationId, const ScanSessionId scanSessionId,
								  ScanResult &result) noexcept
{
	// 未接続の旧Provider結果へ新しい0件計測を生成しない。
	if( !result.measurement.has_value()) {
		return ;
	}

	try {
		ScanMeasurementContext &context = result.measurement->context ;	// Worker公開前のcontext。
		// Compositeはoperation未確定の0を渡す。別IDや別sessionは上書きで隠さない。
		if( operationId == 0U || scanSessionId == 0U || context.operationId != 0U ||
		   context.scanSessionId != scanSessionId || result.scanSessionId != scanSessionId) {
			clearPublishedScanMeasurement( result) ;
			return ;
		}

		context.operationId		   = operationId ;
		context.applicationVersion = DRIVERCRATE_VERSION_WSTRING ;
		// UI境界と同じvalidatorに通らない計測は、候補とは独立に全公開値を破棄する。
		if( !isPublishedScanMeasurementValid( operationId, result)) {
			clearPublishedScanMeasurement( result) ;
		}
	} catch( ...) {
		// Version文字列copy等の失敗で正常候補をscan失敗へ変更しない。
		clearPublishedScanMeasurement( result) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 既定の全組み込みaggregate Providerを生成する。
 *
 * WUA、Driver Store、公式vendorを統合するProviderを生成する。
 * @return worker thread が単独所有する Provider。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::unique_ptr<IUpdateProvider> makeCompositeUpdateProvider()
{
	return std::make_unique<CompositeUpdateProvider>() ;
}

//------------------------------------------------------------------------------
/**
 * @brief COM 初期化不能時の scan result を作成する。
 *
 * @param[in] scanSessionId 失敗した scan に予約していた session ID。
 * @param[in] error COM 初期化 HRESULT。
 * @return fail-closed の scan result。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanResult makeFailedScan( const ScanSessionId scanSessionId,
										const HRESULT		error) noexcept
{
	return {.succeeded	   = false,
			.scanSessionId = scanSessionId,
			.outcome	   = OutcomeCode::FAILURE,
			.error		   = static_cast<NativeError>( error)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider 初期化不能時の install result を作成する。
 *
 * @param[in] identities 選択されていた update identity 群。
 * @param[in] error COM または Provider 初期化 HRESULT。
 * @param[in] protectionMode Install要求で固定した保護方針。
 * @return 全 entry を未導入の失敗として示す結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult makeFailedInstall( const std::span<const std::wstring> identities,
											  const HRESULT						  error,
											  const InstallProtectionMode		  protectionMode)
{
	InstallResult result{} ;	// 全identityを同じerrorで失敗とするsynthetic結果。
	result.protectionMode  = protectionMode ;
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = static_cast<NativeError>( error) ;
	result.updates.reserve( identities.size()) ;

	// UI が選択した全 entry を結果画面で対応付けられるよう保持する。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::FAILURE,
								  .downloadError   = static_cast<NativeError>( error)}) ;
	}

	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ProviderWorker::ProviderWorker( const HWND notificationWindow, const UINT notificationMessage)
	: ProviderWorker( notificationWindow, notificationMessage, makeCompositeUpdateProvider)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ProviderWorker::ProviderWorker( const HWND notificationWindow, const UINT notificationMessage,
							   ProviderFactory providerFactory)
	: ProviderWorker( notificationWindow, notificationMessage, std::move( providerFactory),
					 makeWindowsRestorePointService)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ProviderWorker::~ProviderWorker()
{
	stop() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool ProviderWorker::requestScan( const OperationId operationId, ScanOptions options)
{
	// Provider正本と一scan承認をqueueへcopyする前に検証する。
	if( !validateScanOptions( options) ||
	   (options.officialDiscoveryApproval &&
		options.officialDiscoveryApproval->operationId != operationId)) {
		return false ;
	}

	std::scoped_lock lock( commandMutex_) ;	// Queue検査と追加を直列化するlock。
	// 停止中または queue 上限時は、UI state と異なる未実行 command を保持しない。
	if( stopping_ || commands_.size() >= MAXIMUM_QUEUED_COMMANDS || operationId == 0U ||
	   operationId <= latestRequestedOperationId_) {
		return false ;
	}

	commands_.push_back(
		ScanCommand{operationId, std::move( options), std::make_shared<std::atomic_bool>( false)}) ;
	latestRequestedOperationId_ = operationId ;
	commandReady_.notify_one() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool ProviderWorker::requestScanCancel( const OperationId operationId)
{
	std::scoped_lock lock( commandMutex_) ;	// 取消し対象と信号の所有を同時に照合する。
	// 0、停止中または完了済みの操作を取消し成功にしない。
	if( operationId == 0U || stopping_) {
		return false ;
	}

	// 実行中の同じ通常scanへだけ信号を設定する。
	if( activeScanId_ == operationId && activeScanCancellation_) {
		activeScanCancellation_->store( true) ;
		return true ;
	}

	// 最大4件の未開始queueから同種類・同IDのみを取り消す。
	for( Command &command : commands_) {
		ScanCommand *const pending =
			std::get_if<ScanCommand>( &command) ;	// 通常scan variantの借用参照。
		// 他操作の取消し信号に転用しない。
		if( pending != nullptr && pending->operationId == operationId) {
			pending->cancellation->store( true) ;
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool ProviderWorker::requestInstall( const OperationId					operationId,
									const ScanSessionId					scanSessionId,
									const std::span<const std::wstring> identities,
									const HWND							parentWindow,
									const InstallProtectionMode			protectionMode)
{
	std::scoped_lock lock( commandMutex_) ;	// Queue検査と追加を直列化するlock。
	// 空 selection は Provider へ渡さず、queue resource も消費しない。
	if( stopping_ || identities.empty() || commands_.size() >= MAXIMUM_QUEUED_COMMANDS ||
	   operationId == 0U || operationId <= latestRequestedOperationId_) {
		return false ;
	}

	InstallCommand command ;	// Ownershipをqueueへ移すinstall要求。
	command.operationId	  = operationId ;
	command.scanSessionId = scanSessionId ;
	command.identities.assign( identities.begin(), identities.end()) ;
	command.parentWindow   = parentWindow ;
	command.protectionMode = protectionMode ;
	commands_.push_back( std::move( command)) ;
	latestRequestedOperationId_ = operationId ;
	commandReady_.notify_one() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<WorkerEvent> ProviderWorker::takeEvents()
{
	std::scoped_lock		 lock( eventMutex_) ;	// Event queueの移動と消去を直列化するlock。
	std::vector<WorkerEvent> result ;				// UI threadへownershipごと返すevent群。
	result.reserve( events_.size()) ;

	// queue の到着順を維持して、各 event の ownership を UI thread へ移す。
	while( !events_.empty()) {
		result.push_back( std::move( events_.front())) ;
		events_.pop_front() ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void ProviderWorker::stop() noexcept
{
	{
		std::scoped_lock lock( commandMutex_) ;	// Stop flagと未処理queueを保護するlock。
		// 停止要求が既に登録されている場合は終了手順を重複実行しない。
		if( stopping_) {
			return ;
		}

		stopping_ = true ;
		// 進行中の通常scanに協調取消しを通知し、導入を強制停止しない。
		if( activeScanCancellation_) {
			// 通常scanはProviderが安全に戻る取消し地点へ通知する。
			activeScanCancellation_->store( true) ;
		}

		// 進行中の準備取得にも独立した協調取消しを通知する。
		if( activePreparationCancellation_) {
			// 取得だけを協調取消しする。
			activePreparationCancellation_->store( true) ;
		}

		// 情報検索は同期callから戻った安全地点で停止し、導入の強制停止はしない。
		if( activeMetadataSearchCancellation_) {
			activeMetadataSearchCancellation_->store( true) ;
		}

		// まだ開始していない command は、Window 終了後に system state を変更しないよう破棄する。
		commands_.clear() ;
	}

	commandReady_.notify_all() ;
	// 所有 worker thread がある場合は安全な終了を待ってから戻る。
	if( thread_.joinable()) {
		thread_.join() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void ProviderWorker::run() noexcept
{
	const ComApartment	   apartment( COINIT_MULTITHREADED) ;	// Worker threadのCOM MTA lifetime。
	SignedIndexScanSession indexSession ;						// Providerより長く元取得根拠を所有します。
	std::unique_ptr<driver_store_inf_detail::ScopedFixture>
		driverStoreFixture ;	// 同MTAの固定低位表。
	std::unique_ptr<inf_dependency_native_detail::ScopedFixture>
		dependencyFixture ;	// 同MTAの完全依存表です。
	std::unique_ptr<driver_package_signature_detail::ScopedFixture>
		signatureFixture ;	// 同MTAの実hash署名表。
	std::unique_ptr<driver_package_signature_detail::ScopedAuthenticodeFixture>
		authenticodeFixture ;	// 同MTAの完全Authenticode表です。
	std::unique_ptr<signed_index_candidate_binding_detail::ScopedInstallerFixture>
									 installerFixture ;	// 同MTAの完全launch表です。
	std::unique_ptr<IUpdateProvider> provider ;			// Worker threadだけが所有するprovider。
	OfficialPreparationSession preparation ;			// 固定計画とscan全体の予約をworkerだけが所有する。
	ScanPurpose	  scanPurpose = ScanPurpose::STANDARD ;	// 候補の自己申告とは独立した実行用途。
	ScanSessionId installSession{} ;					// 成功した通常scanだけから得る導入元session。
	// Worker threadだけが所有するWindows復元ポイントservice。
	std::unique_ptr<IRestorePointService> restorePointService ;

	// COM MTA の初期化に成功した場合だけ worker 内の service と Provider を作る。
	if( SUCCEEDED( apartment.result())) {
		try {
			// Provider COM objectより先にprocess-wide COM securityを初期化する。
			// 内部fixtureはnative混在・不完全表を拒否し、製品は固定native表を維持します。
			if( indexServices_->driverStoreFixture || indexServices_->signatureFixture) {
				// 片方だけの内部fixtureを拒否し、製品native呼出しと混在させません。
				if( !indexServices_->driverStoreFixture || !indexServices_->signatureFixture) {
					throw std::runtime_error( "incomplete internal index fixture") ;
				}

				driverStoreFixture = indexServices_->driverStoreFixture() ;
				signatureFixture   = indexServices_->signatureFixture() ;
				// 固定factoryが拒否したworkerを起動せず、低位境界を閉じます。
				if( !driverStoreFixture || !signatureFixture) {
					throw std::runtime_error( "internal index fixture rejected") ;
				}

				// 依存fixtureも元署名・私有nodeと同threadで完全表を所有します。
				if( indexServices_->dependencyFixture) {
					dependencyFixture = indexServices_->dependencyFixture() ;
					// 欠落表は実SYSTEMへfallbackしません。
					if( !dependencyFixture) {
						throw std::runtime_error( "dependency fixture rejected") ;
					}
				}
			}

			// Installerの低位fixtureは全署名・launch・inventory表の閉包を必要とします。
			if( indexServices_->authenticodeFixture || indexServices_->installerFixture) {
				// 不完全な内部表を製品native呼出しへ補完しません。
				if( !driverStoreFixture || !signatureFixture ||
				   !indexServices_->authenticodeFixture || !indexServices_->installerFixture) {
					throw std::runtime_error( "incomplete installer fixture") ;
				}

				authenticodeFixture = indexServices_->authenticodeFixture() ;
				installerFixture	= indexServices_->installerFixture() ;
				// 各完全表のissuerが拒否したscopeを使用しません。
				if( !authenticodeFixture || !installerFixture) {
					throw std::runtime_error( "installer fixture rejected") ;
				}
			}

			restorePointService = restorePointFactory_() ;
			provider			= providerFactory_() ;
		} catch( ...) {
			// ServiceまたはProvider生成例外をthread entryから漏らさず、commandごとに失敗を返す。
			provider.reset() ;
			restorePointService.reset() ;
		}
	}

	// 停止要求後にqueueが空になるまで、受理済みcommandを一件ずつ直列実行する。
	while( true) {
		Command command ;	// Queueから一件ずつownershipを取得する実行対象。
		{
			std::unique_lock lock( commandMutex_) ;	// Wait中に解除可能なcommand queue lock。
			commandReady_.wait( lock, [this]() { return stopping_ || !commands_.empty() ; }) ;
			// 停止要求があり受理済み command を処理し終えた時点で worker loop を終了する。
			if( stopping_ && commands_.empty()) {
				break ;
			}

			command = std::move( commands_.front()) ;
			commands_.pop_front() ;
			// Popと停止／取消しを同じlockで直列化し、開始直前の取消しを失わない。
			// 通常scanの信号を同じoperation IDと組にして実行中登録する。
			if( const auto *pending = std::get_if<ScanCommand>( &command)) {
				activeScanId_			= pending->operationId ;
				activeScanCancellation_ = pending->cancellation ;
			}

			// 取得commandの場合だけそのvariant内を参照し、他操作の信号は作らない。
			if( const auto *pending = std::get_if<PreparationCommand>( &command)) {
				activePreparationId_		   = pending->approval.operationId ;
				activePreparationCancellation_ = pending->cancellation ;
			}

			// Queue内で設定された情報検索取消しを、そのまま実行中の信号へ移す。
			if( const auto *pending = std::get_if<MetadataSearchCommand>( &command)) {
				activeMetadataSearchId_			  = pending->operationId ;
				activeMetadataSearchCancellation_ = pending->cancellation ;
			}
		}

		try {
			std::visit(
				[this, &provider, &restorePointService, &apartment, &preparation, &scanPurpose,
				 &installSession, &indexSession]( auto &&typedCommand) {
					// Variantからdispatchしたcommandの実型。
					using CommandType = std::decay_t<decltype( typedCommand)> ;
					// Scan command では旧準備を失効させ、新しい scan session を割り当てる。
					if constexpr( std::is_same_v<CommandType, ScanCommand>) {
						indexSession.invalidate() ;
						scanPurpose	   = ScanPurpose::STANDARD ;
						installSession = 0U ;
						// 新scanで旧計画を失効させる。
						static_cast<void>( preparation.invalidate()) ;
						// Provider が生成済みなら scan の成否に先立って旧準備 metadata を失効させる。
						if( provider != nullptr) {
							provider
								->invalidatePreparation() ;	// Scan拒否や例外でも旧metadataを残さない。
						}

						ScanSessionId scanSessionId{} ;	// 今回scanへ割り当てるsession ID。
						// 新 session ID を割り当てられなければ scan 失敗を通知して処理を終了する。
						if( !allocateScanSessionId( scanSessionId)) {
							publishEvent( {.kind		   = WorkerEventKind::SCAN_COMPLETED,
										  .operationId = typedCommand.operationId,
										  .scanResult  = makeFailedScan( 0, E_UNEXPECTED)}) ;
							return ;
						}

						// Provider進捗を現在のscan operationへ関連付けてUIへ渡す通知関数。
						const ProviderProgressCallback progressCallback =
							[this, operationId =
									   typedCommand.operationId]( const ProviderProgress &progress) {
								ProviderProgress bounded =
									progress ;	// 索引区間を残した実Provider進捗。
								bounded.percentComplete =
									std::min( progress.percentComplete, 100U) * 90U / 100U ;
								publishEvent( {.kind		   = WorkerEventKind::PROGRESS,
											  .operationId = operationId,
											  .progress	   = bounded}) ;
							} ;
						// Provider実行または初期化失敗を含むscan結果。
						const ProviderScanCancellation cancellation =
							[signal = typedCommand.cancellation]() noexcept {
								return signal->load() ;
							} ; // Commandが所有する不変の取消し照会。
						auto *composite = dynamic_cast<CompositeUpdateProvider *>(
							// 実本体registry所有者。
							provider.get()) ;
						// 同worker借用を固定してからregistry内の索引scanを一回実行します。
						if( composite) {
							composite->bindSignedIndexSession( indexSession, *indexServices_,
															  typedCommand.operationId,
															  cancellation) ;
						}

						ScanResult scanResult =
							provider == nullptr
								? makeFailedScan( scanSessionId, FAILED( apartment.result())
																	? apartment.result()
																	: E_UNEXPECTED)
								: provider->scanWithCancellation( scanSessionId,
																 typedCommand.options, cancellation,
																 progressCallback) ;
						// 通常callbackが情報検索packetを返しても計画作成へ進めない。
						if( scanResult.purpose != ScanPurpose::STANDARD ||
						   scanResult.metadataSearch) {
							scanResult = makeFailedScan( scanSessionId, E_INVALIDARG) ;
						}

						bindPublishedScanMeasurement( typedCommand.operationId, scanSessionId,
													 scanResult) ;
						WorkerEvent event{.kind		   = WorkerEventKind::SCAN_COMPLETED,
										  .operationId = typedCommand.operationId,
										  .scanResult  = std::move( scanResult)} ;	// 結果と任意計画。
						// 同じ通常scanの成功結果だけを索引seamへ結びます。
						if( provider && event.scanResult.succeeded &&
						   event.scanResult.scanSessionId == scanSessionId) {
							// Compositeはregistry callback内で既に読み、postscanを二重実行しません。
							if( composite) {
								event.indexSummary = composite->signedIndexSummary_ ;
							}
							// 汎用fixtureも同じregistryの明示有効条件でだけ索引へ進めます。
							else if( std::any_of(
										builtInProviderDescriptors().begin(),
										builtInProviderDescriptors().end(),
										[&typedCommand]( const ProviderDescriptor &descriptor) {
											return descriptor.id == SIGNED_INDEX_PROVIDER_ID &&
												   isProviderEnabled( typedCommand.options,
																	 descriptor) ;
										})) {
								event.indexSummary = indexSession.scan(
									*provider, typedCommand.operationId, scanSessionId,
									*indexServices_, cancellation,
									[this, operationId = typedCommand.operationId](
										const IndexScanSummary &value) {
										const auto percent =
											90U + static_cast<std::uint32_t>(
													  value.totalRecords == 0U
														  ? 0U
														  : value.processedRecords * 9U /
																value.totalRecords) ;
										// 全record確定区間も計画終端までは99%以下を保持します。
										publishEvent(
											{.kind		  = WorkerEventKind::PROGRESS,
											 .operationId = operationId,
											 .progress	  = {
													ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
													percent, value.processedRecords,
													value.totalRecords}}) ;
									}) ;
							}
						} else {
							event.indexSummary.status = IndexScanStatus::SCAN_FAILED ;
						}

						// 現在 session の正常 scan に対してだけ任意の準備計画を取得する。
						if( provider != nullptr && event.scanResult.succeeded &&
						   event.scanResult.scanSessionId == scanSessionId) {
							installSession = scanSessionId ;
							try {
								// 計画 ID の上限到達時は再使用せず準備機能の失敗を通知する。
								if( nextPreparationPlanId_ ==
								   std::numeric_limits<std::uint64_t>::max()) {
									event.preparationError = static_cast<NativeError>( E_UNEXPECTED) ;
								} else {
									// 新しいIDは空計画でも再使用しない。
									const std::uint64_t planId = nextPreparationPlanId_++ ;
									// Providerから所有権を受け取る任意の非機密計画。
									auto plan = provider->preparationPlan( scanSessionId, planId) ;
									// 既存の同scan承認予算を索引も共有し、Provider未発行時だけ空計画を用意します。
									if( !plan) {
										const auto limits =
											typedCommand.options.officialDiscoveryApproval
												? typedCommand.options.officialDiscoveryApproval
													  ->payloadLimits
												: OfficialDiscoveryPayloadLimits{} ;	// 現行の有限既定値。
										plan = OfficialPreparationPlan{scanSessionId,
																	   planId,
																	   {limits.maximumFileBytes,
																		limits.maximumProviderBytes,
																		limits.maximumSessionBytes,
																		limits.maximumProviderFiles,
																		limits.maximumSessionFiles},
																	   {}} ;
									}

									const auto indexError = indexSession.augmentPreparationPlan(
										*plan, *indexServices_,
										event.indexPreparation) ;	// 同認証原lookupだけを結合します。
									// 取得計画の衝突や不整合では全準備を失効し、正常scanとは分離します。
									if( indexError != 0U) {
										event.preparationError = indexError ;
										indexSession.invalidate() ;
										plan.reset() ;
									}

									// Provider が準備計画を返した場合だけ、その ID と内部契約を検証する。
									if( plan && !plan->targets.empty()) {
										// 元targetを索引参照へ一対一結合し、通常treeと同じ候補snapshotへ発行します。
										if( composite) {
											composite->finishSignedIndexScanPublication(
												*plan, event.scanResult) ;
										}

										// 要求 session・plan ID と異なる計画および初期化に失敗する計画を拒否する。
										if( plan->scanSessionId != scanSessionId ||
										   plan->planId != planId ||
										   preparation.initialize( *plan) !=
											   OfficialPreparationError::NONE) {
											event.preparationError =
												static_cast<NativeError>( E_INVALIDARG) ;
											indexSession.invalidate() ;
										} else {
											event.preparationPlan = std::move( plan) ;
										}
									}
								}
							} catch( ...) {
								// 計画作成例外で正常なdriver scanの候補を失敗へ変更しない。
								static_cast<void>( preparation.invalidate()) ;
								indexSession.invalidate() ;
								event.preparationError = static_cast<NativeError>( E_UNEXPECTED) ;
							}
						}

						bool cancelled{} ;	// 取消し受付と終端公開の同じ線形化点です。
						{
							std::scoped_lock lock(
								commandMutex_) ;	// 外部I/Oを行わない終端の確定です。
							cancelled	  = typedCommand.cancellation->load() || stopping_ ;
							activeScanId_ = 0U ;
							activeScanCancellation_.reset() ;
						}
						// 最終取消しを受理したscanへ導入session・計画・秘密関係を残しません。
						if( cancelled) {
							indexSession.invalidate() ;
							installSession = 0U ;
							static_cast<void>( preparation.invalidate()) ;
							// 初期化失敗時もnull Providerを呼びません。
							if( provider) {
								provider->invalidatePreparation() ;
							}

							event.preparationPlan.reset() ;
							event.indexPreparation = {} ;
							event.scanResult =
								makeFailedScan( scanSessionId, HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
							event.scanResult.outcome  = OutcomeCode::ABORTED ;
							event.indexSummary.status = IndexScanStatus::CANCELLED ;
						}

						// 索引と計画の終端確定後にだけ全体100%を通知します。
						if( !cancelled) {
							publishEvent( {.kind		   = WorkerEventKind::PROGRESS,
										  .operationId = typedCommand.operationId,
										  .progress	   = {ProviderStage::MERGING_CANDIDATES, 100U,
														  event.indexSummary.processedRecords,
														  event.indexSummary.totalRecords}}) ;
						}

						publishEvent( std::move( event)) ;
					}
					// 情報検索は専用callbackだけを使用し、通常scanと取得計画を呼ばない。
					else if constexpr( std::is_same_v<CommandType, MetadataSearchCommand>) {
						indexSession.invalidate() ;
						scanPurpose	   = ScanPurpose::METADATA_ONLY ;
						installSession = 0U ;
						static_cast<void>( preparation.invalidate()) ;
						// 新検索の成功可否に先立ち、古い取得同意を失効させる。
						if( provider) {
							provider->invalidatePreparation() ;
						}

						ScanSessionId session{} ;	// 専用結果にも単調増加IDを割り当てる。
						ScanResult	  result ;		// 契約不正時には公開可能な部分値を持たない失敗。
						result.purpose = ScanPurpose::METADATA_ONLY ;
						result.outcome = OutcomeCode::FAILURE ;
						result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
						// Providerと一意sessionがなければ専用callbackを開始しない。
						if( provider && allocateScanSessionId( session)) {
							// 送信ごとにCOM MTA内でcostを再照会し、未知を許可へ変えない。
							const MetadataNetworkCostReader readCost = []() {
								WindowsOfficialNetworkCostReader reader ;	// 一回照会の非共有境界。
								OfficialNetworkCostKind cost = OfficialNetworkCostKind::UNKNOWN ;
								const NativeError		error =
									// 元のHRESULTを保存する。
									reader.read( cost) ;
								return MetadataNetworkCost{
									error == 0 && cost == OfficialNetworkCostKind::UNRESTRICTED,
									error} ;
							} ;
							MetadataSearchExecutionContext execution(
								session, typedCommand.request,
								[signal = typedCommand.cancellation]() { return signal->load() ; },
								{}, readCost) ;
							result = provider->scanMetadataOnly(
								session, typedCommand.request, execution,
								[this, operationId = typedCommand.operationId](
									const ProviderProgress &progress) {
									publishEvent( {.kind		   = WorkerEventKind::PROGRESS,
												  .operationId = operationId,
												  .progress	   = progress}) ;
								}) ;
							bool bound = result.metadataSearch &&
										 result.metadataSearch->operationId == 0U &&
										 result.metadataSearch->scanSessionId == session &&
										 result.metadataSearch->request == typedCommand.request &&
										 result.metadataSearch->usage ==
											 // 実contextとの独立照合。
											 execution.usage() ;
							// 実行済みProviderの消費と主因を、callbackの自己申告へ照合する。
							for( const auto &actual : execution.providers()) {
								// 欠けたsummaryに対して参照を生成しない。
								if( !bound) {
									break ;
								}

								const auto detail =
									std::find_if( result.metadataSearch->providers.begin(),
												 result.metadataSearch->providers.end(),
												 [&actual]( const auto &value) {
													 return value.providerId == actual.providerId ;
												 }) ; // 同じ実行の確定消費。
								bound = detail != result.metadataSearch->providers.end() &&
										detail->usage == actual.usage &&
										detail->reason == actual.reason &&
										detail->error == actual.error ;
							}

							// operationは0から一度だけ拘束し、矛盾した元値を上書きしない。
							if( bound) {
								result.metadataSearch->operationId = typedCommand.operationId ;
								bindPublishedScanMeasurement( typedCommand.operationId, session,
															 result) ;
							}

							// 不正packetは行とreportを一括破棄し、権限なしの失敗だけを返す。
							if( !bound ||
							   !isMetadataSearchResultValid( typedCommand.operationId,
															typedCommand.request, result)) {
								result		   = makeFailedScan( session, E_INVALIDARG) ;
								result.purpose = ScanPurpose::METADATA_ONLY ;
							}
						}

						publishEvent( {.kind		   = WorkerEventKind::METADATA_SEARCH_COMPLETED,
									  .operationId = typedCommand.operationId,
									  .scanResult  = std::move( result)}) ;
					}
					// Install command では旧承認を失効させ、OS 別の保護手順を選択する。
					else if constexpr( std::is_same_v<CommandType, InstallCommand>) {
						indexSession.closeAcquisitionForInstall() ;
						static_cast<void>(
							// 導入開始後に旧承認を使わせない。
							preparation.invalidate()) ;
						// 監査済み保持物は保護判定と導入結果の確定まで生存させる。
						InstallResult installResult ;	// 保護付きProvider処理または初期化失敗結果。
						const bool	  restorePointServiceRequired =
							typedCommand.protectionMode ==
							InstallProtectionMode::WINDOWS_RESTORE_POINT ;
						// Provider または必要な復元ポイント service がない場合は導入を呼ばない。
						if( scanPurpose != ScanPurpose::STANDARD || installSession == 0U ||
						   typedCommand.scanSessionId != installSession || provider == nullptr ||
						   (restorePointServiceRequired && restorePointService == nullptr)) {
							installResult = makeFailedInstall(
								typedCommand.identities,
								FAILED( apartment.result()) ? apartment.result() : E_UNEXPECTED,
								typedCommand.protectionMode) ;
						} else {
							// Provider進捗を現在のinstall operationへ関連付けてUIへ渡す通知関数。
							const ProviderProgressCallback progressCallback =
								[this, operationId = typedCommand.operationId](
									const ProviderProgress &progress) {
									publishEvent( {.kind		   = WorkerEventKind::PROGRESS,
												  .operationId = operationId,
												  .progress	   = progress}) ;
								} ;
							const bool windowsServer =
								// Worker境界で再確認する実OS種別。
								isWindowsServer() ;
							const auto *composite =
								dynamic_cast<CompositeUpdateProvider *>( provider.get()) ;
							const NativeError requiredPreflight =
								composite ? composite->preflightRequiredSignedIndexInstall(
												typedCommand.scanSessionId,
												typedCommand.identities)
										  : 0 ;	// 復旧開始前の全元必要役割です。
							// 実 OS と要求保護 mode が一致しなければ system 変更前に拒否する。
							if( requiredPreflight != 0U) {
								installResult =
									makeFailedInstall( typedCommand.identities,
													  static_cast<HRESULT>( requiredPreflight),
													  typedCommand.protectionMode) ;
							}
							// 適合済みselectionもOS保護境界を省略しません。
							else if( !isInstallProtectionModeAllowed( windowsServer,
																	typedCommand.protectionMode)) {
								// UI値と実OSが一致しない場合はProviderを呼ばずfail-closedで拒否する。
								installResult =
									makeFailedInstall( typedCommand.identities, E_ACCESSDENIED,
													  typedCommand.protectionMode) ;
							}
							// 確認済み Server mode だけを復元ポイント API を使わない導入経路へ渡す。
							else if( typedCommand.protectionMode ==
									InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) {
								installResult = installWithoutRestorePointOnServer(
									*provider, typedCommand.scanSessionId, typedCommand.identities,
									reinterpret_cast<std::uintptr_t>( typedCommand.parentWindow),
									progressCallback) ;
							} else {
								installResult = installWithRestorePoint(
									*provider, *restorePointService, typedCommand.scanSessionId,
									typedCommand.identities,
									reinterpret_cast<std::uintptr_t>( typedCommand.parentWindow),
									progressCallback, L"DriverCrate driver installation") ;
							}
						}

						// Provider が存在する場合は保護拒否や部分失敗でも導入後の保持物を失効させる。
						if( provider != nullptr) {
							// 保護拒否・部分失敗でも解放する。
							provider->invalidatePreparation() ;
						}

						publishEvent( {.kind			 = WorkerEventKind::INSTALL_COMPLETED,
									  .operationId	 = typedCommand.operationId,
									  .installResult = std::move( installResult)}) ;
						indexSession.invalidate() ;
						installSession = 0U ;
					}
					// 準備 command は操作専用の取消し signal と取得境界で処理する。
					else if constexpr( std::is_same_v<CommandType, PreparationCommand>) {
						// 行のinstallable改ざんや古い承認にかかわらず専用sessionを拒否する。
						if( scanPurpose != ScanPurpose::STANDARD || installSession == 0U ||
						   typedCommand.approval.scanSessionId != installSession) {
							indexSession.invalidate() ;
							static_cast<void>( preparation.invalidate()) ;
							publishEvent(
								{.kind				= WorkerEventKind::PREPARATION_COMPLETED,
								 .operationId		= typedCommand.approval.operationId,
								 .preparationResult = {
									 .operationId	= typedCommand.approval.operationId,
									 .scanSessionId = typedCommand.approval.scanSessionId,
									 .planId		= typedCommand.approval.planId,
									 .controlError	= static_cast<NativeError>( E_ACCESSDENIED)}}) ;
							return ;
						}

						const OperationId operationId =
							typedCommand.approval.operationId ;	// この取得commandの操作ID。
						// このcommandだけに結び付けた、thread-safeな取消し照会。
						const PreparationCancellation cancellation =
							[signal = typedCommand.cancellation]() { return signal->load() ; } ;
						const PreparationAcquireFunction acquire =
							[this, &provider, &indexSession,
							 &preparation]( const OfficialPreparationTask &task,
										   const PreparationCancellation &cancelled) {
								// 共通索引IDだけを同scan adapterへ送り、他のProvider routingを維持します。
								if( task.target.providerId == SIGNED_INDEX_PROVIDER_ID) {
									try {
										return indexSession.acquireForInspection(
											preparation, task, *indexServices_, cancelled) ;
									} catch( ...) {
										// 項目失敗へ吸収される前に能力だけを失効し、確定内容と後続callbackの所有を保持します。
										indexSession.invalidateAcquisition() ;
										// 元executorのE_UNEXPECTEDと他Providerの部分失敗継続へ同じ例外を返します。
										throw ;
									}
								}

								// Provider がない場合は準備取得を開始せず失敗結果を返す。
								if( provider == nullptr) {
									return OfficialPreparationTransferResult{
										OfficialPreparationItemState::FAILURE,
										static_cast<NativeError>( E_UNEXPECTED), 0U} ;
								}

								return provider->acquireForInspection( task, cancelled) ;
							} ; // 承認済みtaskだけをProvider境界へ渡す。
						const PreparationProgressCallback progress =
							[this, operationId]( const OfficialPreparationProgress &value) {
								publishEvent( {.kind		   = WorkerEventKind::PREPARATION_PROGRESS,
											  .operationId = operationId,
											  .preparationProgress = value}) ;
							} ; // Install／downloadの旧進捗と混同しない専用通知。
						// 既存導入とは独立した、検査用取得の確定結果。
						auto result = executeOfficialPreparation( preparation, typedCommand.approval,
																 acquire, cancellation, progress) ;
						// 承認と制御処理が成功し Provider がある場合だけ監査 report を集約する。
						if( provider != nullptr &&
						   result.approvalError == OfficialPreparationError::NONE &&
						   result.controlError == 0) {
							try {
								result.auditReports = provider->preparationAuditReports( result) ;
							} catch( ...) {
								// 表示集約の失敗は取得成功と分離し、部分reportを表示しない。
								result.auditReports.clear() ;
								result.controlError = static_cast<NativeError>( E_UNEXPECTED) ;
								// Compositeは自分のtransactionをrollback済みで、他Providerの既存routeを保持します。
								if( dynamic_cast<CompositeUpdateProvider *>( provider.get()) ==
								   nullptr) {
									provider->invalidatePreparation() ;
								}
							}
						}

						auto indexResult = indexSession.preparationSummary(
							operationId) ;	// 実byteの独立非機密結果。
						// 確定取消し・承認拒否・制御異常で未使用取得能力を残しません。
						if( cancellation() ||
						   result.approvalError != OfficialPreparationError::NONE ||
						   result.controlError != 0U || indexResult.authorityError != 0U) {
							indexSession.invalidate() ;
						}

						// URLも実device IDも含まない確定結果だけをUIへ渡す。
						publishEvent( {.indexPreparation	 = std::move( indexResult),
									  .kind				 = WorkerEventKind::PREPARATION_COMPLETED,
									  .operationId		 = operationId,
									  .preparationResult = std::move( result)}) ;
					}
				},
				command) ;
		} catch( ...) {
			// allocation 等の予期しない例外でも worker process を終了させず、現在操作を失敗にする。
			indexSession.invalidate() ;
			std::visit(
				[this, &preparation, &provider, &installSession]( const auto &typedCommand) {
					installSession = 0U ;
					// 例外発生中だったcommandの実型。
					using CommandType = std::decay_t<decltype( typedCommand)> ;
					// Scan 処理の例外を対応する完了 event の失敗結果へ変換する。
					if constexpr( std::is_same_v<CommandType, ScanCommand>) {
						publishEvent(
							{.indexSummary = {.status = IndexScanStatus::SCAN_FAILED,
											  .error  = static_cast<NativeError>( E_UNEXPECTED)},
							 .kind		   = WorkerEventKind::SCAN_COMPLETED,
							 .operationId  = typedCommand.operationId,
							 .scanResult   = makeFailedScan( 0, E_UNEXPECTED)}) ;
					}
					// 情報検索例外を通常scan完了へ変換せず専用の失敗で終端する。
					else if constexpr( std::is_same_v<CommandType, MetadataSearchCommand>) {
						ScanResult result =
							// 部分packetを公開しない。
							makeFailedScan( 0U, E_UNEXPECTED) ;
						result.purpose = ScanPurpose::METADATA_ONLY ;
						publishEvent( {.kind		   = WorkerEventKind::METADATA_SEARCH_COMPLETED,
									  .operationId = typedCommand.operationId,
									  .scanResult  = std::move( result)}) ;
					}
					// Install 処理の例外は保持物を失効させた上で導入失敗として通知する。
					else if constexpr( std::is_same_v<CommandType, InstallCommand>) {
						// 生成済み Provider の導入準備物を例外後の操作へ持ち越さない。
						if( provider != nullptr) {
							// 例外時も保持物を次操作へ残さない。
							provider->invalidatePreparation() ;
						}

						publishEvent( {.kind		   = WorkerEventKind::INSTALL_COMPLETED,
									  .operationId = typedCommand.operationId,
									  .installResult =
										  makeFailedInstall( typedCommand.identities, E_UNEXPECTED,
															typedCommand.protectionMode)}) ;
					}
					// 準備処理の例外では承認と計画を失効させ、対応する完了結果を通知する。
					else if constexpr( std::is_same_v<CommandType, PreparationCommand>) {
						// 未開始の承認を例外後に再利用しない。
						preparation.cancel() ;
						static_cast<void>( preparation.invalidate()) ;
						// 生成済み Provider の途中の候補 routing も例外 cleanup で取り消す。
						if( provider != nullptr) {
							// 発行途中の候補routingも破棄する。
							provider->invalidatePreparation() ;
						}

						publishEvent( {.kind				 = WorkerEventKind::PREPARATION_COMPLETED,
									  .operationId		 = typedCommand.approval.operationId,
									  .preparationResult = {
										  .operationId	 = typedCommand.approval.operationId,
										  .scanSessionId = typedCommand.approval.scanSessionId,
										  .planId		 = typedCommand.approval.planId,
										  .controlError = static_cast<NativeError>( E_UNEXPECTED)}}) ;
					}
				},
				command) ;
		}

		{
			std::scoped_lock lock( commandMutex_) ;	// 完了済み操作へ取消しを後付けしない。
			activeScanId_ = 0U ;
			activeScanCancellation_.reset() ;
			activePreparationId_ = 0U ;
			activePreparationCancellation_.reset() ;
			activeMetadataSearchId_ = 0U ;
			activeMetadataSearchCancellation_.reset() ;
		}
	}

	indexSession.invalidate() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void ProviderWorker::publishEvent( WorkerEvent event) noexcept
{
	try {
		// 通常scan完了はUI通知より先に取消し受付を閉じる。
		if( event.kind == WorkerEventKind::SCAN_COMPLETED) {
			std::scoped_lock lock( commandMutex_) ;	// 取消し要求と終端の線形化地点。
			// 遅延eventから別のscan信号を解除しない。
			if( activeScanId_ == event.operationId) {
				activeScanId_ = 0U ;
				activeScanCancellation_.reset() ;
			}
		}

		// 終端公開後の取消しを受理したように見せず、専用登録を先に解除する。
		if( event.kind == WorkerEventKind::METADATA_SEARCH_COMPLETED) {
			std::scoped_lock lock( commandMutex_) ;	// 取消し要求と終端の線形化地点。
			// 別操作の登録を遅延eventから解除しない。
			if( activeMetadataSearchId_ == event.operationId) {
				activeMetadataSearchId_ = 0U ;
				activeMetadataSearchCancellation_.reset() ;
			}
		}

		// 準備完了 event は UI 通知前に取消し対象の登録を解除する。
		if( event.kind == WorkerEventKind::PREPARATION_COMPLETED) {
			std::scoped_lock lock( commandMutex_) ;	// 完了通知より先に取消し対象から除外する。
			// 完了した操作と現在の取消し対象 ID が一致する場合だけ登録を解除する。
			if( activePreparationId_ == event.operationId) {
				activePreparationId_ = 0U ;
				activePreparationCancellation_.reset() ;
			}
		}

		{
			std::scoped_lock lock( eventMutex_) ;	// Event queueの上限確認と追加を直列化するlock。
			// UI が長時間応答しない場合も memory が無制限に増えないよう最古 event を破棄する。
			if( events_.size() >= MAXIMUM_QUEUED_EVENTS) {
				events_.pop_front() ;
			}

			events_.push_back( std::move( event)) ;
		}

		// message には所有 pointer を含めないため、Window 破棄との競合で leak しない。
		static_cast<void>( PostMessageW( notificationWindow_, notificationMessage_, 0, 0)) ;
	} catch( ...) {
		// event allocation failure は thread boundary から例外を漏らさない。
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool ProviderWorker::allocateScanSessionId( ScanSessionId &scanSessionId) noexcept
{
	// wrap した session ID を再利用すると古い selection と区別できないため上限で停止する。
	if( nextScanSessionId_ == 0 || nextScanSessionId_ == std::numeric_limits<ScanSessionId>::max()) {
		return false ;
	}

	scanSessionId = nextScanSessionId_ ;
	++nextScanSessionId_ ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool ProviderWorker::requestPreparation( const OfficialPreparationApproval &approval)
{
	// Queueへ保持するpacketの対象数を有限にする。
	if( approval.decisions.empty() || approval.decisions.size() > 256U) {
		return false ;
	}

	std::size_t eulaCharacters{} ;	// 全対象の本文量。Queueへのcopy前に合計上限を調べる。
	// コピー前に各tokenと本文の長さを制限し、最大4 packetのmemory使用量も有限にする。
	for( const OfficialPreparationDecision &decision : approval.decisions) {
		const OfficialPreparationTarget &target = decision.target ;	// コピー予定の対象snapshot。
		// 各識別値と EULA の単体・累積長上限を超える承認は queue へ受理しない。
		if( target.identity.size() > 128U || target.providerId.size() > 128U ||
		   target.resourceId.size() > 128U || target.releaseIdentity.size() > 128U ||
		   target.eulaRevision.size() > 128U ||
		   target.eulaText.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS ||
		   target.eulaText.size() > MAXIMUM_PREPARATION_PLAN_EULA_CHARACTERS - eulaCharacters) {
			return false ;
		}

		eulaCharacters += target.eulaText.size() ;
	}

	std::scoped_lock lock( commandMutex_) ;	// Queueと操作ID・停止状態の同時検査。
	// 古い操作を再投入せず、未開始queueを無制限に増やさない。
	if( stopping_ || commands_.size() >= MAXIMUM_QUEUED_COMMANDS || approval.operationId == 0U ||
	   approval.operationId <= latestRequestedOperationId_) {
		return false ;
	}

	commands_.push_back( PreparationCommand{approval, std::make_shared<std::atomic_bool>( false)}) ;
	latestRequestedOperationId_ = approval.operationId ;
	commandReady_.notify_one() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool ProviderWorker::requestPreparationCancel( const OperationId operationId)
{
	std::scoped_lock lock( commandMutex_) ;	// 信号の所有権と対象IDを同時に確認する。
	// 無効な操作 ID の取消し要求は受理しない。
	if( operationId == 0U) {
		return false ;
	}

	// 実行中の準備 ID と一致する要求だけに専用取消し signal を設定する。
	if( activePreparationId_ == operationId && activePreparationCancellation_) {
		activePreparationCancellation_->store( true) ;
		return true ;
	}

	// 最大4件の未開始queueだけを調べ、別操作への取消し転用を防ぐ。
	for( Command &command : commands_) {
		PreparationCommand *const preparation =
			std::get_if<PreparationCommand>( &command) ;	// 一致するvariantだけの非所有参照。
		// Queue 内の同じ準備操作だけを取消し対象にし、他の command へ波及させない。
		if( preparation != nullptr && preparation->approval.operationId == operationId) {
			preparation->cancellation->store( true) ;
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/provider_worker.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ProviderWorker::ProviderWorker( const HWND notificationWindow, const UINT notificationMessage,
							   ProviderFactory	   providerFactory,
							   RestorePointFactory restorePointFactory)
	: ProviderWorker( notificationWindow, notificationMessage, std::move( providerFactory),
					 std::move( restorePointFactory),
					 std::make_unique<provider_worker_index_detail::Services>(
						 provider_worker_index_detail::Services{
							 .load =
								 []( std::optional<std::chrono::sys_seconds> now) {
									 return SignedIndexStore::reloadFixedExisting( now) ;
								 },
							 .utc =
								 []() {
									 return std::optional<std::chrono::sys_seconds>{
										 std::chrono::floor<std::chrono::seconds>(
											 std::chrono::system_clock::now())} ;
								 },
							 .monotonic = []() { return std::chrono::steady_clock::now() ; },
							 .targetOs	= []() -> std::optional<IndexTargetOs> {
								  const auto build =
									  // 判定不能は0です。
									  currentWindowsBuildNumber() ;
								  // 対象OSの実観測がなければ取得条件を推測しません。
								  if( build == 0U) {
									  return std::nullopt ;
								  }

								  return isWindowsServer() ? IndexTargetOs::WINDOWS_SERVER
										 : build >= 22000U ? IndexTargetOs::WINDOWS_11
														   : IndexTargetOs::WINDOWS_10 ;
							 },
							 .refresh =
								 []( const ProviderScanCancellation &cancel) {
									 return refreshFixedSignedIndex( cancel) ;
								 }}))
{
}

/** @see provider_worker.h */
ProviderWorker::ProviderWorker(
	const HWND notificationWindow, const UINT notificationMessage, ProviderFactory providerFactory,
	RestorePointFactory										restorePointFactory,
	std::unique_ptr<provider_worker_index_detail::Services> indexServices)
	: notificationWindow_( notificationWindow), notificationMessage_( notificationMessage),
	  providerFactory_( std::move( providerFactory)),
	  restorePointFactory_( std::move( restorePointFactory)),
	  indexServices_( std::move( indexServices)), thread_( [this]() { run() ; })
{
}

/** @see provider_worker_index_internal.h */
std::unique_ptr<ProviderWorker> provider_worker_index_detail::Access::create(
	ProviderFactory providerFactory, RestorePointFactory restoreFactory, Services services)
{
	return std::unique_ptr<ProviderWorker>{
		new ProviderWorker{nullptr, WM_APP, std::move( providerFactory), std::move( restoreFactory),
						   std::make_unique<Services>( std::move( services))}} ;
}

/** @see provider_worker_index_internal.h 宣言側の契約を正本とする。 */
std::unique_ptr<ProviderWorker> provider_worker_index_detail::Access::createAcquisitionFixture(
	ProviderFactory providerFactory, RestorePointFactory restoreFactory, Services services)
{
	// 内部取得fixtureでも完全fake依存を必須にし、製品APIへfallbackしません。
	if( !services.httpTransport || !services.costReader || !services.targetOs) {
		return nullptr ;
	}

	services.beginAcquisition = []( SignedIndexAcquisitionAdapter				 &adapter,
								   std::shared_ptr<const SignedIndexRecordLookup> lookup,
								   IndexLookupContext context, IndexTargetOs os,
								   std::optional<std::chrono::sys_seconds> now) {
		return signed_index_acquisition_detail::Access::beginFixture( adapter, std::move( lookup),
																	 context, os, now) ;
	} ; // 固定fixture-main／revision1だけの既存private policyです。外部鍵・許可boolを受けません。
	return create( std::move( providerFactory), std::move( restoreFactory), std::move( services)) ;
}

/** @see src/platform/provider_worker.h */
bool ProviderWorker::requestMetadataSearch( const OperationId	 operationId,
										   MetadataSearchRequest request)
{
	// 未対応・未知・重複集合をqueueへ入れず、通常scanへ代替しない。
	if( !validateMetadataSearchRequest( request, builtInProviderDescriptors())) {
		return false ;
	}

	std::scoped_lock lock( commandMutex_) ;	// 受付IDと停止状態の同時検査。
	// 有限queueと単調IDの契約は通常operationと共有する。
	if( stopping_ || commands_.size() >= MAXIMUM_QUEUED_COMMANDS || operationId == 0U ||
	   operationId <= latestRequestedOperationId_) {
		return false ;
	}

	commands_.push_back( MetadataSearchCommand{operationId, std::move( request),
											  std::make_shared<std::atomic_bool>( false)}) ;
	latestRequestedOperationId_ = operationId ;
	commandReady_.notify_one() ;
	return true ;
}

/** @see src/platform/provider_worker.h */
bool ProviderWorker::requestMetadataSearchCancel( const OperationId operationId)
{
	std::scoped_lock lock( commandMutex_) ;	// 操作IDと信号所有権を同時に確認する。
	// 未開始を表す0を取消し対象へ変換しない。
	if( operationId == 0U || stopping_) {
		return false ;
	}

	// 実行中の同じ情報検索にだけ取消しを通知する。
	if( activeMetadataSearchId_ == operationId && activeMetadataSearchCancellation_) {
		activeMetadataSearchCancellation_->store( true) ;
		return true ;
	}

	// 最大4件のqueueから同じ種類・同じIDだけを取り消す。
	for( auto &command : commands_) {
		auto *pending = std::get_if<MetadataSearchCommand>( &command) ;	// 当該variantの借用参照。
		// 通常scan、取得、導入には取消しを転用しない。
		if( pending && pending->operationId == operationId) {
			pending->cancellation->store( true) ;
			return true ;
		}
	}

	return false ;
}

} // namespace drivercrate
