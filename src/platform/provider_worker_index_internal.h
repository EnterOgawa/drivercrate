//------------------------------------------------------------------------------
/**
 * @file provider_worker_index_internal.h
 * @brief 通常workerの固定索引serviceと隔離fixture能力を定義します。
 * @version 01.05.00
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  Private constructor限定の索引fixture能力を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同scan取得の固定fixtureと共通HTTP依存を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.02.01 Shunji Ogawa  2026/10/12  署名fixture factory型を分離し前置member説明を結合。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  完全依存API fixtureの同worker所有factoryを定義。
 * Ver.01.05.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * </pre>
 *
 * @note 製品constructorはこの能力を外部入力から作りません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/inf_dependency_native_internal.h"
#include "platform/provider_worker.h"
#include "platform/signed_index_store.h"
#include "platform/signed_index_refresh.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/official_http_transport.h"
#include "platform/driver_store_inf_transport_internal.h"
#include "platform/driver_package_signature_internal.h"
#include "platform/signed_index_candidate_binding_internal.h"
#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace drivercrate::provider_worker_index_detail {
/** @brief 元lookupと完全scan contextだけをadapter開始へ渡す内部関数型です。 */
using IndexAcquisitionBegin = std::function<NativeError(
	SignedIndexAcquisitionAdapter &, std::shared_ptr<const SignedIndexRecordLookup>,
	IndexLookupContext, IndexTargetOs, std::optional<std::chrono::sys_seconds>)> ;
/** @brief 実member hashを照合する内部署名fixtureの単独所有factory型です。 */
using PackageSignatureFixtureFactory =
	std::function<std::unique_ptr<driver_package_signature_detail::ScopedFixture>()> ;
/** @brief Worker生成前に固定し、そのworkerだけが呼ぶ非通信serviceです。 */
struct Services {
	/// 同じ実保護store reloadへ戻る所有callback。
	std::function<IndexStoreResult( std::optional<std::chrono::sys_seconds>)> load ;
	/// 信頼UTCを確認できない場合はnulloptを返すcallback。
	std::function<std::optional<std::chrono::sys_seconds>()>				 utc ;
	/// 協調期限へ使用する単調時計。
	std::function<std::chrono::steady_clock::time_point()>					 monotonic ;
	/// 一operation最大record。固定製品上限以下です。
	std::size_t																 maximumRecords{16384U} ;
	/// 一operation最大callback。固定製品上限以下です。
	std::size_t																 maximumCalls{32768U} ;
	/// 一operation最大関係tuple。固定製品上限以下です。
	std::size_t													 maximumRelations{32768U} ;
	/// 超過後は新規処理を開始しない協調期限。最大5秒です。
	std::chrono::milliseconds									 duration{5000} ;
	/// Workerだけが確認するOS条件。不明では取得対象を作りません。
	std::function<std::optional<IndexTargetOs>()>				 targetOs ;
	/// 内部createAcquisitionFixtureだけが固定fixture-mainの開始関数を保持します。
	IndexAcquisitionBegin										 beginAcquisition ;
	/// 内部fixtureの完全な低位HTTP呼出し表。製品入口は空です。
	std::function<OfficialHttpTransport()>						 httpTransport ;
	/// 内部fixtureの回線分類境界。製品入口はWindows標準境界を使用します。
	std::function<std::unique_ptr<IOfficialNetworkCostReader>()> costReader ;
	/// 内部factoryが全低位Windows表を同worker lifetimeへ固定します。製品は空です。
	std::function<std::unique_ptr<driver_store_inf_detail::ScopedFixture>()> driverStoreFixture ;
	/// 実INF/CAT/member hashを全共通処理で検査する固定内部署名表。製品は空です。
	PackageSignatureFixtureFactory											 signatureFixture ;
	/// Installer専用の完全Authenticode表を同workerへ固定します。製品は空です。
	std::function<std::unique_ptr<driver_package_signature_detail::ScopedAuthenticodeFixture>()>
		authenticodeFixture ;
	/// Installer専用の完全launch表を同workerへ固定します。製品は空です。
	std::function<std::unique_ptr<signed_index_candidate_binding_detail::ScopedInstallerFixture>()>
																				  installerFixture ;
	/// 同workerで全五APIを所有する依存検査fixtureです。製品入口は空です。
	std::function<std::unique_ptr<inf_dependency_native_detail::ScopedFixture>()> dependencyFixture ;
	/// 製品固定refreshまたは明示完全fakeです。空は既存の純local fixtureで、nativeへ補完しません。
	std::function<IndexRefreshSummary( const ProviderScanCancellation &)>		  refresh ;
} ;
/** @brief Unit専用serviceをprivate worker constructorへ結ぶ内部能力です。 */
struct Access {
	/** @brief 実command queueと通常ScanCommandを使用する隔離workerを作ります。
	 * @param[in] providerFactory 非通信Providerをworker内で生成する関数。
	 * @param[in] restoreFactory 実復旧APIを呼ばない生成関数。
	 * @param[in] services 真署名・隔離storeだけを使用するservice。
	 * @return 通知Windowを持たない実worker。実native fallbackを許可しません。
	 */
	[[nodiscard]] static std::unique_ptr<ProviderWorker> create( ProviderFactory		providerFactory,
																RestorePointFactory restoreFactory,
																Services			services) ;
	/** @brief 真署名隔離snapshotの固定取得policyへ限定した実workerを作ります。
	 * @param[in] providerFactory 同threadの非通信inventory Provider生成関数。
	 * @param[in] restoreFactory 実復旧APIを呼ばない生成関数。
	 * @param[in] services 同scanの実store再認証・完全fake HTTP・costの依存。
	 * @return 任意鍵や許可boolを受けない内部worker。完全fake依存欠損ではnullptrです。
	 */
	[[nodiscard]] static std::unique_ptr<ProviderWorker> createAcquisitionFixture(
		ProviderFactory providerFactory, RestorePointFactory restoreFactory, Services services) ;
} ;
} // namespace drivercrate::provider_worker_index_detail
