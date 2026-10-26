//------------------------------------------------------------------------------
/**
 * @file metadata_ui_fixture.cpp
 * @brief 専用Win32画面試験の非通信Provider契約。
 * @version 01.17.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  実device・network・復旧操作を持たないUI fixtureを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  Registry件数に依存しないfixture説明へ更新。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通常scanの協調取消しfakeを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  真署名索引・非空ZIP・完全HTTPの同worker入力を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  複数INF・同認証payload共有・根拠欠損の元入力を固定。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/10/12  規約GETの固定cache headerとCookie禁止を低位観測。
 * Ver.01.04.02 Shunji Ogawa  2026/10/12  CABの同期lambda説明と借用・例外契約を補足。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  元二recordの出典・公開revision差を独立取得へ固定。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  CAT所有者を含む元固定28条件の実ZIP byteを生成。
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  別Models/OSの選択機能と全importの元byteを生成。
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  元50条件を維持してWin32 service正常・拒否38条件の実byteを追加。
 * Ver.01.08.01 Shunji Ogawa  2026/10/13  元88を保持し同leafの不正binary位置三条件を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  元91を保持し必要Win32の位置・標準DIRID・正式flags24条件を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  同媒体sourceの正常・誤位置・欠損・曖昧24条件を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  元141を保持しroot-only媒体と選択節依存の実byteを追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/13  元141/root-onlyと固定15選択依存の実byte入力を生成。
 * Ver.01.13.00 Shunji Ogawa  2026/10/14  通常取得commandへ原HTML全文と第二payload拒否を結合。
 * Ver.01.13.01 Shunji Ogawa  2026/10/15  到達済みHKR AddRegの採用にfixture説明を整合。
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  追加INFなしの選択Needs・欠損・未選択条件を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/10/15  33INF正例とarchive128/129境界の完全閉包入力を分離。
 * Ver.01.16.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.17.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * </pre>
 *
 * @note 製品EXEへ組み込まず、内部UI試験だけで使用する。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "support/metadata_ui_fixture.h"

#include "core/candidate_audit.h"
#include "core/metadata_search.h"
#include "core/metadata_search_budget.h"
#include "core/provider_registry.h"
#include "platform/metadata_search_runner.h"
#include "platform/official_acquisition.h"
#include "platform/signed_index_manifest_internal.h"
#include "platform/signed_index_store_internal.h"
#include "platform/signed_index_records.h"
#include "platform/signed_index_asset_bytes.h"
#include "platform/official_download_workspace.h"
#include <SetupAPI.h>
#include <bcrypt.h>
#include <miniz.h>

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>
#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace drivercrate::test {
namespace {

/** @brief 通常APIとsystem変更を持たない画面試験用Provider。 */
class MetadataUiProvider final : public IUpdateProvider {
public:
	/**
     * @brief UIとの共有状態を所有する。
     * @param[in] state 操作counterと有限待機信号。
     */
	explicit MetadataUiProvider( std::shared_ptr<MetadataUiState> state) : state_( std::move( state))
	{
	}

	/**
     * @brief 通常scanの明示操作だけを空結果で再現する。
     * @param[in] session Workerの一意ID。
     * @param[in] options 使用しない通常条件。
     * @param[in] progress 使用しない進捗callback。
     * @return 同sessionの正常な空集合。実I/Oはない。
     */
	ScanResult scan( const ScanSessionId session, const ScanOptions &options,
					const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		static_cast<void>( progress) ;
		++state_->normalCalls ;
		return {.succeeded = true, .scanSessionId = session, .outcome = OutcomeCode::SUCCESS} ;
	}

	/**
	 * @brief 通常scanを有限待機させ、workerの協調取消しcallbackを観測する。
	 * @param[in] session Workerの一意ID。
	 * @param[in] options 使用しない通常条件。
	 * @param[in] cancellation 同じworker operationの非blocking取消し照会。
	 * @param[in] progress 使用しない進捗callback。
	 * @return 取消し時はABORTED、それ以外は同sessionの正常な空集合。
	 */
	ScanResult scanWithCancellation( const ScanSessionId session, const ScanOptions &options,
									const ProviderScanCancellation &cancellation,
									const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		static_cast<void>( progress) ;
		++state_->normalCalls ;
		// 明示された一回だけを有限loopへ入れ、通常の画面試験を遅延させない。
		if( state_->holdNextNormal.exchange( false)) {
			state_->waiting = true ;
			const auto deadline =
				// 待機上限。
				std::chrono::steady_clock::now() + std::chrono::seconds( 5) ;
			// 取消しまたはfixture解除まで10 ms単位で安全地点を再現する。
			while( std::chrono::steady_clock::now() < deadline) {
				// Workerが同じoperationを取り消した場合は部分候補を発行しない。
				if( cancellation && cancellation()) {
					++state_->normalCancelled ;
					state_->waiting = false ;
					ScanResult aborted ;	// 通常scanの有効な取消し終端。
					aborted.scanSessionId = session ;
					aborted.purpose		  = ScanPurpose::STANDARD ;
					aborted.outcome		  = OutcomeCode::ABORTED ;
					aborted.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
					return aborted ;
				}

				// 試験側が明示解除した場合は正常終端へ進む。
				if( state_->release.try_acquire_for( std::chrono::milliseconds( 10))) {
					state_->waiting = false ;
					return {.succeeded	   = true,
							.scanSessionId = session,
							.outcome	   = OutcomeCode::SUCCESS} ;
				}
			}

			++state_->waitTimeouts ;
			state_->waiting = false ;
		}

		return {.succeeded = true, .scanSessionId = session, .outcome = OutcomeCode::SUCCESS} ;
	}

	/**
     * @brief 正本runnerへ現在属性と公式metadataのfakeだけを渡す。
     * @param[in] session Workerの一意session。
     * @param[in] request 専用dialogで明示選択した今回の条件。
     * @param[in,out] execution Workerの取消し・期限。
     * @param[in] progress 同じ画面へ返す確定進捗。
     * @return 製品と同じ検証を通る表示専用結果。
     */
	ScanResult scanMetadataOnly( const ScanSessionId session, const MetadataSearchRequest &request,
								MetadataSearchExecutionContext &execution,
								const ProviderProgressCallback &progress) override
	{
		++state_->metadataCalls ;
		std::vector<MetadataSearchRegistration> registrations ;	// Registryの全登録を照合する。
		// 専用能力があるentryにだけ非通信callbackを割り当てる。
		for( const auto &descriptor : builtInProviderDescriptors()) {
			MetadataSearchRegistration entry{descriptor, {}} ;	// 正本と同じ値をcopyする。
			// 非対応providerを通常scanで補完しない。
			if( isMetadataSearchProvider( descriptor)) {
				entry.scan = [this, id = descriptor.id](
								 ScanSessionId							idSession,
								 std::span<const OfficialCatalogDevice> devices, bool,
								 std::uint32_t, MetadataSearchExecutionContext &budget,
								 const ProviderProgressCallback &notify,
								 ProviderMeasurementEvidence	&evidence) {
					++state_->officialCalls ;
					// Inventory完了後の安全地点でだけ有限待機し、取消し画面を再現する。
					if( state_->holdNext.exchange( false)) {
						state_->waiting = true ;
						// Fixture解除を待ち続けず、期限切れは試験結果へ残す。
						if( !state_->release.try_acquire_for( std::chrono::seconds( 5))) {
							++state_->waitTimeouts ;
						}

						state_->waiting = false ;
					}

					const auto scenario =
						// このcallbackの終端条件を固定する。
						state_->scenario.load() ;
					const auto stopped =
						// 待機中に要求された取消しを観測する。
						budget.checkpoint() ;
					const bool failed = stopped != 0 || scenario == MetadataUiScenario::FAILED ||
										// 正常な0件と失敗を区別する。
										scenario == MetadataUiScenario::REJECTED ;
					ScanResult result ;	// 通信・payloadを持たない公式子結果。
					result.scanSessionId = idSession ;
					result.purpose		 = ScanPurpose::METADATA_ONLY ;
					result.succeeded	 = !failed ;
					result.error =
						stopped != 0 ? stopped : (failed ? static_cast<NativeError>( E_FAIL) : 0) ;
					result.outcome			 = failed ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
					result.state			 = scenario == MetadataUiScenario::REJECTED
												   ? ProviderScanState::METADATA_REJECTED
											   : failed ? ProviderScanState::FAILURE
											   : scenario == MetadataUiScenario::NOT_APPLICABLE
												   ? ProviderScanState::NOT_APPLICABLE
											   : scenario == MetadataUiScenario::NO_INFORMATION
												   ? ProviderScanState::NO_CANDIDATES
												   : ProviderScanState::CANDIDATES_AVAILABLE ;
					evidence.providerId		 = id ;
					evidence.scanSessionId	 = idSession ;
					evidence.scope			 = MeasurementScope::DEVICE_QUERY ;
					evidence.queryOutcome	 = result.outcome ;
					evidence.eligible.extent = MeasurementExtent::EXACT ;
					evidence.queryCompleted.extent =
						failed ? MeasurementExtent::LOWER_BOUND : MeasurementExtent::EXACT ;
					evidence.information.extent = evidence.queryCompleted.extent ;
					evidence.recordExtent		= evidence.queryCompleted.extent ;
					// 最後の一台をcurrent-onlyとして残し、展開と折畳みの違いを検査する。
					for( std::size_t index = 0U; index < devices.size() && index < 2U; ++index) {
						// 対象外scenarioではTも作らない。
						if( scenario == MetadataUiScenario::NOT_APPLICABLE) {
							continue ;
						}

						const auto &device =
							devices[index] ;	// 同型でも別opaque identityを保持する。
						evidence.eligible.identities.push_back( device.deviceIdentity) ;
						// 失敗したqueryからQや情報を作らない。
						if( failed) {
							continue ;
						}

						evidence.queryCompleted.identities.push_back( device.deviceIdentity) ;
						// Query成功record0件は情報行なしで明示する。
						if( scenario == MetadataUiScenario::NO_INFORMATION) {
							continue ;
						}

						evidence.information.identities.push_back( device.deviceIdentity) ;
						UpdateCandidate row ;	// 全行が選択不能で取得権限なし。
						row.identity			 = id + L":info:" + device.deviceIdentity ;
						row.deviceIdentity		 = device.deviceIdentity ;
						row.providerId			 = id ;
						row.model				 = device.model ;
						row.title				 = L"Fixture distribution" ;
						row.manufacturer		 = device.manufacturer ;
						row.driverClass			 = device.driverClass ;
						row.deviceClassGuid		 = device.deviceClassGuid ;
						row.sourceName			 = L"Fixture official metadata" ;
						row.sourceLocation		 = L"fixture.example" ;
						row.discoveryBasis		 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
						row.audit				 = makeOfficialDiscoveryCandidateAudit() ;
						row.metadataDistribution = MetadataDistributionDetails{
							index == 0U ? L"9.8" : L"", MetadataLicenseStatus::UNRESOLVED} ;
						row.maximumDownloadBytes = index == 0U ? 123456U : 0U ;
						result.candidates.push_back( std::move( row)) ;
					}

					// 一recordが二deviceへ対応してもrecord数は一件だけにする。
					if( !evidence.information.identities.empty()) {
						evidence.records.push_back(
							{id + L":record", evidence.information.identities}) ;
					}

					notify( {.stage			 = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
							.percentComplete = 100U,
							.completedItems	 = 1U,
							.totalItems		 = 1U}) ;
					return result ;
				} ;
			}

			registrations.push_back( std::move( entry)) ;
		}

		ScanMeasurementContext conditions ;	// 実OSと混同しない画面用の合成条件。
		conditions.osKind  = MeasurementOsKind::CLIENT ;
		conditions.osBuild = 26100U ;
		return runMetadataSearch(
			session, request, execution, registrations,
			[]( ScanSessionId id, MetadataSearchExecutionContext &budget,
			   const ProviderProgressCallback &notify, DeviceInventoryMeasurement &measurement) {
				ScanResult result ;	// 三台だけの非機密な現在属性。
				result.scanSessionId = id ;
				result.purpose		 = ScanPurpose::METADATA_ONLY ;
				result.outcome		 = OutcomeCode::FAILURE ;
				result.state		 = ProviderScanState::FAILURE ;
				// 開始前取消しでは合成deviceも発行しない。
				if( const auto error = budget.checkpoint() ; error != 0) {
					result.error = error ;
					return result ;
				}

				// 架空三台を現在行にし、driver版の未知値も再現する。
				for( unsigned index = 0U; index < 3U; ++index) {
					UpdateCandidate row ;	// 実ID・pathを持たない現在版。
					row.identity		= L"current-" + std::to_wstring( index) ;
					row.deviceIdentity	= L"fixture-device-" + std::to_wstring( index) ;
					row.providerId		= DRIVER_STORE_PROVIDER_ID ;
					row.model			= L"Fixture device " + std::to_wstring( index) ;
					row.title			= row.model ;
					row.manufacturer	= L"Fixture maker" ;
					row.driverClass		= L"Ports" ;
					row.deviceClassGuid = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
					row.current			= true ;
					row.version			= index == 0U ? L"1.2.3.4" : L"" ;
					row.discoveryBasis	= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
					row.audit			= makeWindowsManagedCandidateAudit( true) ;
					result.candidates.push_back( std::move( row)) ;
				}

				measurement.enumeratedDeviceCount		= {3U, MeasurementExtent::EXACT} ;
				measurement.unrepresentedDeviceCount	= {0U, MeasurementExtent::EXACT} ;
				measurement.detailedEnumerationComplete = true ;
				result.succeeded						= true ;
				result.outcome							= OutcomeCode::SUCCESS ;
				result.state							= ProviderScanState::CANDIDATES_AVAILABLE ;
				notify( {.stage			 = ProviderStage::SCANNING_DEVICES,
						.percentComplete = 100U,
						.completedItems	 = 3U,
						.totalItems		 = 3U}) ;
				return result ;
			},
			conditions, progress) ;
	}

	/**
     * @brief 誤った準備要求をcounterで検出する。
     * @param[in] session 未使用の検索ID。
     * @param[in] planId 未使用の計画ID。
     * @return 常に計画なし。
     */
	std::optional<OfficialPreparationPlan> preparationPlan( ScanSessionId session,
														   std::uint64_t planId) override
	{
		static_cast<void>( session) ;
		static_cast<void>( planId) ;
		++state_->planCalls ;
		return {} ;
	}

	/**
     * @brief 誤った取得要求をcounterで検出する。
     * @param[in] task 使用しない取得対象。
     * @param[in] cancellation 使用しない取消し信号。
     * @return 合成失敗。Fileを生成しない。
     */
	OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) override
	{
		static_cast<void>( task) ;
		static_cast<void>( cancellation) ;
		++state_->forbiddenCalls ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_FAIL), 0U} ;
	}

	/**
     * @brief 実導入へ接続せず、誤呼出しを検出する。
     * @param[in] session 未使用の検索ID。
     * @param[in] identities 未使用の候補集合。
     * @param[in] parentWindow 未使用の親Window。
     * @param[in] progress 未使用の通知先。
     * @return 合成失敗だけの結果。
     */
	InstallResult install( ScanSessionId session, std::span<const std::wstring> identities,
						  std::uintptr_t				  parentWindow,
						  const ProviderProgressCallback &progress) override
	{
		static_cast<void>( session) ;
		static_cast<void>( identities) ;
		static_cast<void>( parentWindow) ;
		static_cast<void>( progress) ;
		++state_->forbiddenCalls ;
		return {} ;
	}

private:
	/// Worker停止まで保つ両thread共有のcounter。
	std::shared_ptr<MetadataUiState> state_ ;
} ;

/** @brief Windows System Restoreを初期化しない復旧fake。 */
class MetadataUiRestore final : public IRestorePointService {
public:
	/**
     * @brief 誤呼出しcounterを共有する。
     * @param[in] state UIとWorkerが所有する状態。
     */
	explicit MetadataUiRestore( std::shared_ptr<MetadataUiState> state) : state_( std::move( state))
	{
	}
	/**
     * @brief 復旧操作の誤呼出しだけを記録する。
     * @param[in] description 使用しない説明。
     * @return 合成失敗。実復元ポイントを作成しない。
     */
	RestorePointOperationResult begin( std::wstring_view description) noexcept override
	{
		static_cast<void>( description) ;
		++state_->restoreCalls ;
		return {.outcome = OutcomeCode::FAILURE, .error = static_cast<NativeError>( E_FAIL)} ;
	}
	/**
     * @brief 復旧終了の誤呼出しだけを記録する。
     * @param[in] sequenceNumber 使用しない番号。
     * @return 合成失敗。System Restore APIを呼ばない。
     */
	RestorePointOperationResult complete( std::int64_t sequenceNumber) noexcept override
	{
		static_cast<void>( sequenceNumber) ;
		++state_->restoreCalls ;
		return {.outcome = OutcomeCode::FAILURE, .error = static_cast<NativeError>( E_FAIL)} ;
	}

private:
	/// UIとWorker終了まで共有する誤呼出しcounter。
	std::shared_ptr<MetadataUiState> state_ ;
} ;

} // namespace

/** @see support/metadata_ui_fixture.h */
ProviderFactory metadataUiProviderFactory( std::shared_ptr<MetadataUiState> state)
{
	return [state = std::move( state)] { return std::make_unique<MetadataUiProvider>( state) ; } ;
}

/** @see support/metadata_ui_fixture.h */
RestorePointFactory metadataUiRestoreFactory( std::shared_ptr<MetadataUiState> state)
{
	return [state = std::move( state)] { return std::make_unique<MetadataUiRestore>( state) ; } ;
}

} // namespace drivercrate::test

namespace drivercrate::test {
namespace {

// 固定検査UTC。OS時計を使わず期限境界を決定的に検査する。
const std::chrono::sys_seconds NOW =
	std::chrono::sys_days{std::chrono::year{2026} / 10 / 11} + std::chrono::hours{6} ;
// 架空assetの固定digest。実asset検証を実行したことにはしない。
constexpr std::string_view ASSET_HASH =
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;

/** @brief API失敗をfixture成功へ変換せずunit processへ通知します。
 * @param[in] status 元NTSTATUS。
 */
void checkNative( const NTSTATUS status)
{
	// 秘密materialを含まない固定説明だけでfixture生成失敗を通知する。
	if( status < 0) {
		throw std::runtime_error( "CNG RAM fixture API failed") ;
	}
}

/** @brief 鍵生成・署名に使うCNG resourceをRAM内だけで単独所有します。 */
class RamKey final {
public:
	/** @brief 取得前のownerを作ります。 */
	RamKey() = default ;
	/** @brief 秘密鍵を含むCNG handleとalgorithmを全経路で解放します。 */
	~RamKey() noexcept
	{
		// 鍵をalgorithmより先に回収し、秘密鍵を永続化しない。
		if( key_ != nullptr) {
			static_cast<void>( BCryptDestroyKey( key_)) ;
		}

		// SHA algorithmも途中のfixture失敗で残さない。
		if( sha_ != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( sha_, 0U)) ;
		}

		// RSA algorithmは最後に回収する。
		if( rsa_ != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( rsa_, 0U)) ;
		}
	}
	/** @brief 単独所有のためコピー構築を禁止します。 */
	RamKey( const RamKey &) = delete ;
	/** @brief 単独所有のためコピー代入を禁止します。
     * @return 呼出しは禁止されます。
     */
	RamKey &operator=( const RamKey &) = delete ;

	/** @brief 名前を持たない非永続RSA鍵を一回生成します。
     * @param[in] bits FixtureのRSA bit長。
     * @note Public blobだけをexportします。秘密鍵exportやNCrypt永続storeを使いません。
     */
	void	generate( const ULONG bits)
	{
		checkNative( BCryptOpenAlgorithmProvider( &rsa_, BCRYPT_RSA_ALGORITHM, nullptr, 0U)) ;
		checkNative( BCryptGenerateKeyPair( rsa_, &key_, bits, 0U)) ;
		checkNative( BCryptFinalizeKeyPair( key_, 0U)) ;
		checkNative( BCryptOpenAlgorithmProvider( &sha_, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)) ;
		ULONG bytes{} ;	// Public blob容量。Private blobを要求しない。
		checkNative( BCryptExportKey( key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0U, &bytes, 0U)) ;
		publicBlob.resize( bytes) ;
		checkNative( BCryptExportKey( key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(), bytes,
									&bytes, 0U)) ;
		publicBlob.resize( bytes) ;
	}

	/** @brief Test側の独立CNG hashで原byteをSHA-256へ結合します。
     * @param[in] bytes 原byte。
     * @return 実CNG digest。
     */
	[[nodiscard]] IndexManifestSha256 digest( const std::string_view bytes) const
	{
		std::vector<std::uint8_t> input( bytes.begin(), bytes.end()) ;	// CNG境界だけの所有copy。
		IndexManifestSha256		  hash{} ;								// 固定32byte出力。
		checkNative( BCryptHash( sha_, nullptr, 0U, input.data(), static_cast<ULONG>( input.size()),
							   hash.data(), static_cast<ULONG>( hash.size()))) ;
		return hash ;
	}

	/** @brief 原byteをRAM内private keyで実RSA-PSS署名します。
     * @param[in] bytes 署名対象。再整形しません。
     * @param[in] saltBytes 固定32または拒否fixture用の別salt長。
     * @return 原byteに対する実署名。
     */
	[[nodiscard]] std::vector<std::uint8_t> sign( const std::string_view bytes,
												 const ULONG			saltBytes = 32U) const
	{
		IndexManifestSha256		hash = digest( bytes) ;							// 製品hash APIに依存しない署名対象。
		BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, saltBytes} ;	// Native PSS設定。
		ULONG					size{} ;										// Key長に由来する実署名長。
		checkNative( BCryptSignHash( key_, &padding, hash.data(), static_cast<ULONG>( hash.size()),
								   nullptr, 0U, &size, BCRYPT_PAD_PSS)) ;
		std::vector<std::uint8_t> signature( size) ;	// Secret keyとは別の署名byte。
		checkNative( BCryptSignHash( key_, &padding, hash.data(), static_cast<ULONG>( hash.size()),
								   signature.data(), size, &size, BCRYPT_PAD_PSS)) ;
		signature.resize( size) ;
		return signature ;
	}
	/// Test verifierへ渡すpublic blobだけの所有値。
	std::vector<std::uint8_t> publicBlob ;

private:
	/// RAMだけのRSA algorithm。
	BCRYPT_ALG_HANDLE rsa_{} ;
	/// RAMだけの秘密鍵handle。Exportや保存をしません。
	BCRYPT_KEY_HANDLE key_{} ;
	/// RAMだけのSHA-256 algorithm。
	BCRYPT_ALG_HANDLE sha_{} ;
} ;

/** @brief Test側で正規base64を作ります。
 * @param[in] bytes 原byte。
 * @return 標準alphabetと正規paddingのASCII。
 */
[[nodiscard]] std::string encodeBase64( const std::span<const std::uint8_t> bytes)
{
	constexpr std::string_view ALPHABET =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ;	// 標準alphabet。
	std::string encoded ;														// Test専用所有base64。
	// 原byteを三byteずつ走査し、末尾だけをpaddingする。
	for( std::size_t offset = 0U; offset < bytes.size(); offset += 3U) {
		const unsigned first = bytes[offset] ;	// 必須第一byte。
		const unsigned second =
			offset + 1U < bytes.size() ? bytes[offset + 1U] : 0U ;						// 欠けたbyteはpaddingで表す。
		const unsigned third = offset + 2U < bytes.size() ? bytes[offset + 2U] : 0U ;	// 最終byte。
		encoded.push_back( ALPHABET[first >> 2U]) ;
		encoded.push_back( ALPHABET[((first & 3U) << 4U) | (second >> 4U)]) ;
		encoded.push_back(
			offset + 1U < bytes.size() ? ALPHABET[((second & 15U) << 2U) | (third >> 6U)] : '=') ;
		encoded.push_back( offset + 2U < bytes.size() ? ALPHABET[third & 63U] : '=') ;
	}

	return encoded ;
}

/** @brief UTF-8原byteをtest側base64へ変換します。
 * @param[in] bytes 原UTF-8。
 * @return 原byteのbase64。
 */
[[nodiscard]] std::string encodeText( const std::string_view bytes)
{
	const std::vector<std::uint8_t> input( bytes.begin(),
										  // Const pointer castを使わないcopy。
										  bytes.end()) ;
	return encodeBase64( input) ;
}

/** @brief 人工manifest原byteを作ります。Field順は製品契約として固定しません。
 * @return 全必須値を持つ架空manifest。
 */
[[nodiscard]] std::string manifest()
{
	return "{\"schema\":\"driver-index-manifest-v1\",\"repository\":\"EnterOgawa/drivercrate\","
		   "\"channel\":\"driver-index\",\"keyId\":\"fixture-main\",\"generation\":7,\"assetGeneration\":7,"
		   "\"publishedAtUtc\":\"2026-10-11T05:00:00Z\",\"expiresAtUtc\":\"2026-10-25T05:00:00Z\","
		   "\"asset\":{\"tag\":\"index-v1-20261011-" +
		   std::string{ASSET_HASH} +
		   "\",\"name\":\"index.json.gz\",\"compression\":\"gzip\",\"sizeBytes\":123,\"sha256\":\"" +
		   std::string{ASSET_HASH} +
		   "\"},\"quality\":{\"sourceCount\":1,\"recordCount\":3,"
		   "\"metadataOnlyCount\":1,\"contentInspectedCount\":1,\"unconfirmedCount\":1}}" ;
}

/** @brief 一箇所だけを意図した値へ変える拒否fixtureを作ります。
 * @param[in] bytes 元fixture。
 * @param[in] before 必ず存在する元断片。
 * @param[in] after 変更断片。
 * @return 一箇所を変更した所有原byte。
 */
[[nodiscard]] std::string replaced( std::string bytes, const std::string_view before,
								   const std::string_view after)
{
	const std::size_t position = bytes.find( before) ;	// 意図した唯一の変更位置。
	// Test生成不成立をcodec拒否の合格へ読み替えない。
	if( position == std::string::npos) {
		throw std::runtime_error( "fixture replacement not found") ;
	}

	bytes.replace( position, before.size(), after) ;
	return bytes ;
}

/** @brief Testで署名済み原byteを有限envelopeへ包みます。
 * @param[in] raw 元manifest。
 * @param[in] signature 元署名。
 * @param[in] keyId 外側ID。
 * @return 署名対象を再serializationしない外側JSON。
 */
[[nodiscard]] std::string envelope( const std::string_view			   raw,
								   const std::span<const std::uint8_t> signature,
								   const std::string_view			   keyId = "fixture-main")
{
	return "{\"schema\":\"driver-index-envelope-v1\",\"keyId\":\"" + std::string{keyId} +
		   "\",\"manifestBytesBase64\":\"" + encodeText( raw) + "\",\"signatureBase64\":\"" +
		   encodeBase64( signature) + "\"}" ;
}

// 人工hash値は出典やpackageの実検証を表さず、元申告の型付き保持だけを検査する。
constexpr std::string_view RECORD_CLAIM_HASH =
	"1111111111111111111111111111111111111111111111111111111111111111" ;
// 原出典byteの元申告。Record原byte hashと混同しない。
constexpr std::string_view RECORD_EVIDENCE_HASH =
	"2222222222222222222222222222222222222222222222222222222222222222" ;

/** @brief Test側の独立CNG原hashを小文字hexへ表現します。
 * @param[in] key 既存RAM鍵helper。秘密materialをexportしません。
 * @param[in] raw 元byte。
 * @return 実原bytehashの小文字64桁。
 */
[[nodiscard]] std::string recordDigest( const RamKey &key, const std::string_view raw)
{
	const auto				   hash = key.digest( raw) ;	// 同じRAM helperの独立実CNG digest。
	constexpr std::string_view HEX	= "0123456789abcdef" ;	// 固定hex表。
	std::string				   result ;						// Test専用の所有表現。
	// 全32byteを原値どおり二桁へ表現する。
	for( const auto byte : hash) {
		result.push_back( HEX[byte >> 4U]) ;
		result.push_back( HEX[byte & 15U]) ;
	}

	return result ;
}

/** @brief 原record byteだけをentryへ結びます。
 * @param[in] key 既存RAM helper。
 * @param[in] raw 原UTF-8。
 * @param[in] hashOverride Hash取り違え用の明示digest。空は実原hashです。
 * @return 原byteを再整形しないbase64 entry。
 */
[[nodiscard]] std::string recordEntry( const RamKey &key, const std::string_view raw,
									  const std::string_view hashOverride = {})
{
	return "{\"recordBytesBase64\":\"" + encodeText( raw) + "\",\"recordSha256\":\"" +
		   (hashOverride.empty() ? recordDigest( key, raw) : std::string{hashOverride}) + "\"}" ;
}

/** @brief 架空sourceの公開申告またはUNKNOWNを作ります。
 * @param[in] id 架空のASCII identity。
 * @param[in] unknown 元公式性未確認を保持する指定。
 * @return 通信しないtestだけのsource JSON。
 */
[[nodiscard]] std::string recordSource( const std::string_view id	  = "fixture-source",
									   const bool			  unknown = false)
{
	const std::string evidence =
		unknown
			? "{\"state\":\"UNKNOWN\",\"kind\":\"UNKNOWN\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"source not verified\"}"
			: "{\"state\":\"PUBLISHED\",\"kind\":\"OFFICIAL_PAGE\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				  std::string{RECORD_EVIDENCE_HASH} +
				  "\",\"reason\":\"\"}" ;	// 元申告または明示UNKNOWN。
	return "{\"sourceId\":\"" + std::string{id} +
		   "\",\"officialOrigin\":\"https://vendor.example/\",\"distributionPage\":\"https://vendor.example/support\"," +
		   "\"officialEvidence\":" + evidence + "}" ;
}

/** @brief 明示既知のtext条件を作ります。
 * @param[in] value 固定架空値。Quoteを含みません。
 * @return Test用KNOWN JSON。
 */
[[nodiscard]] std::string recordKnown( const std::string_view value)
{
	return "{\"state\":\"KNOWN\",\"value\":\"" + std::string{value} + "\",\"reason\":\"\"}" ;
}

/** @brief 架空recordの完全な型付き元申告を作ります。
 * @param[in] id Source内の架空identity。
 * @param[in] identityPublished PnP evidenceの元申告を持つ指定。FalseではUNKNOWNを保持します。
 * @param[in] stage 発行側の段階。
 * @param[in] source 存在するか拒否用の架空source ID。
 * @return Test専用の元record byte。
 * @note 通常文字列で元byteを保持し、Doxygenのraw JSON誤解析によるmember欠落を避けます。
 */
[[nodiscard]] std::string distributionRecord( const std::string_view id				  = "metadata",
											 const bool				identityPublished = true,
											 const std::string_view stage  = "METADATA_ONLY",
											 const std::string_view source = "fixture-source")
{
	constexpr std::string_view UNKNOWN =
		"{\"state\":\"UNKNOWN\",\"value\":\"\",\"reason\":\"not supplied\"}" ;	// 欠損を補完しない条件。
	constexpr std::string_view UNKNOWN_HASH =
		// 未知hash。
		"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not inspected\"}" ;
	const std::string hash =
		"{\"state\":\"KNOWN\",\"sha256\":\"" + std::string{RECORD_CLAIM_HASH} +
		"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
		std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}" ;	// 型だけを確認する元申告。
	const std::string identity =
		identityPublished
			? "{\"state\":\"PUBLISHED\",\"kind\":\"INF\",\"pnpIds\":[{\"kind\":\"HARDWARE\",\"value\":\"TESTBUS\\\\SYNTH_0001\"}],\"classGuid\":\"{11111111-2222-3333-4444-555555555555}\",\"nestedArchiveIdentity\":\"\",\"infIdentity\":\"drivers/fixture.inf\",\"modelSection\":\"Fixture.NTamd64\",\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				  std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}"
			// 元公開identityか不足理由。
			: "{\"state\":\"UNKNOWN\",\"kind\":\"UNKNOWN\",\"pnpIds\":[],\"classGuid\":\"\",\"nestedArchiveIdentity\":\"\",\"infIdentity\":\"\",\"modelSection\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"public INF identity missing\"}" ;
	return "{\"schema\":\"driver-index-record-v1\",\"sourceId\":\"" + std::string{source} +
		   "\",\"recordId\":\"" + std::string{id} + "\",\"product\":\"Synthetic fixture\"," +
		   "\"targetOs\":" +
		   (identityPublished ? recordKnown( "WINDOWS_11") : std::string{UNKNOWN}) +
		   ",\"architecture\":" + (identityPublished ? recordKnown( "X64") : std::string{UNKNOWN}) +
		   ",\"driverKind\":" +
		   (identityPublished ? recordKnown( "NORMAL_DRIVER") : std::string{UNKNOWN}) +
		   ",\"version\":" + (identityPublished ? recordKnown( "1.2.3.4") : std::string{UNKNOWN}) +
		   ",\"publishedDate\":" +
		   (identityPublished ? recordKnown( "2026-10-01") : std::string{UNKNOWN}) +
		   ",\"acquisition\":" +
		   (identityPublished ? recordKnown( "STANDARD_INF_ARCHIVE") : std::string{UNKNOWN}) +
		   ",\"packageEvidence\":{\"publishedHash\":" +
		   (identityPublished ? hash : std::string{UNKNOWN_HASH}) +
		   ",\"calculatedHash\":" + (identityPublished ? hash : std::string{UNKNOWN_HASH}) +
		   ",\"size\":" +
		   (identityPublished
				? std::string{"{\"state\":\"KNOWN\",\"valueBytes\":1234,\"reason\":\"\"}"}
				: std::
					  string{"{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"not inspected\"}"}) +
		   "},\"lastSuccessfulObservationUtc\":" +
		   (identityPublished ? recordKnown( "2026-10-10T03:00:00Z") : std::string{UNKNOWN}) +
		   ",\"inspectionStage\":\"" + std::string{stage} +
		   "\",\"publishedIdentityEvidence\":" + identity + "}" ;
}

/** @brief 静的取得descriptorの完全な人工元申告を作ります。
 * @param[in] unknown 取得情報だけを明示UNKNOWNへする指定。
 * @param[in] rich 規約全文と具体的条件を含む入れ子の正例を作る指定。
 * @return 通信や同意を行わない全13fieldの人工JSON。
 */
[[nodiscard]] std::string descriptorFixture( const bool unknown = false, const bool rich = false)
{
	const std::string evidence{RECORD_EVIDENCE_HASH} ;	// 元出典byteの架空申告。
	const std::string terms =
		rich
			? "{\"state\":\"ACCEPTANCE_REQUIRED\",\"reason\":\"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				  evidence +
				  "\",\"revisionKind\":\"VENDOR_LITERAL\",\"revision\":\"Original 1.0\",\"textDocument\":{\"url\":\"https://vendor.example/terms.txt\",\"sha256\":\"" +
				  evidence + "\",\"sizeBytes\":123,\"contentType\":\"text/plain; charset=utf-8\"}}"
			: "{\"state\":\"CONFIRMED_NO_CONSENT\",\"reason\":\"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				  evidence +
				  "\",\"revisionKind\":\"NONE\",\"revision\":\"\",\"textDocument\":null}" ;	// 元規約の別状態。
	const std::string prerequisites =
		rich
			? "{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[{\"kind\":\"LOCAL_CHECK\",\"description\":\"Check a specific prerequisite\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				  evidence + "\"}]}"
			: "{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[]}" ;	// 明示空集合か個別条件。
	// UNKNOWNは取得URLやattestationを補完せず、独立した未知理由も保持する。
	if( unknown) {
		return "{\"schema\":\"driver-index-acquisition-v1\",\"state\":\"UNKNOWN\",\"reason\":\"static route not supplied\",\"payloadUrl\":\"\",\"fileName\":\"\",\"format\":\"UNKNOWN\",\"expectedContentType\":\"\",\"maximumBytes\":0,\"route\":[],\"terms\":{\"state\":\"UNKNOWN\",\"reason\":\"terms not supplied\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"revisionKind\":\"NONE\",\"revision\":\"\",\"textDocument\":null},\"prerequisites\":{\"state\":\"UNKNOWN\",\"reason\":\"prerequisites not supplied\",\"items\":[]},\"publisher\":{\"state\":\"UNKNOWN\",\"value\":\"\",\"reason\":\"publisher not supplied\"},\"attestation\":null}" ;
	}

	return "{\"schema\":\"driver-index-acquisition-v1\",\"state\":\"KNOWN\",\"reason\":\"\",\"payloadUrl\":\"https://vendor.example/fixture.zip\",\"fileName\":\"Fixture 1.2 (x64).zip\",\"format\":\"ZIP\",\"expectedContentType\":\"application/zip\",\"maximumBytes\":134217728,\"route\":[{\"url\":\"https://vendor.example/fixture.zip\",\"kind\":\"OFFICIAL_PAYLOAD_LINK\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
		   evidence + "\"}],\"terms\":" + terms + ",\"prerequisites\":" + prerequisites +
		   ",\"publisher\":{\"state\":\"KNOWN\",\"value\":\"Synthetic publisher\",\"reason\":\"\"},\"attestation\":{\"kind\":\"COLLECTOR_VERIFIED_OFFICIAL_ROUTE\",\"policyRevision\":1,\"checkedAtUtc\":\"2026-10-10T03:00:00Z\",\"validUntilUtc\":\"2026-10-12T03:00:00Z\",\"authorityMethod\":\"OFFICIAL_SITE_CONTROL_AND_LINK\",\"authorityEvidenceUrl\":\"https://vendor.example/support\",\"authorityEvidenceSha256\":\"" +
		   evidence + "\"}}" ;
}

/** @brief Descriptorをschemaより先に置くv2原recordを作ります。
 * @param[in] descriptor 全13fieldの人工元取得情報。
 * @param[in] raw 旧14fieldの人工record。欠損を補いません。
 * @return 原field順を明示した15fieldの人工record。
 */
[[nodiscard]] std::string descriptorRecord( const std::string_view descriptor,
										   std::string			  raw = distributionRecord())
{
	raw = replaced( std::move( raw), "driver-index-record-v1", "driver-index-record-v2") ;
	return "{\"acquisitionDescriptor\":" + std::string{descriptor} + "," + raw.substr( 1U) ;
}

/** @brief Sourcesとrecordsをouter schemaより先に置くv2原indexを作ります。
 * @param[in] sources 人工source集合。
 * @param[in] entries 原byteと実hashに結合した人工entry集合。
 * @return Outer field順を固定しない全4fieldの人工index。
 */
[[nodiscard]] std::string descriptorIndex( const std::string_view sources,
										  const std::string_view entries)
{
	return "{\"sources\":[" + std::string{sources} + "],\"records\":[" + std::string{entries} +
		   "],\"assetGeneration\":7,\"schema\":\"driver-index-records-v2\"}" ;
}

/** @brief 架空原byteをminizで実圧縮し、CRC／ISIZEを持つ単一GZipを作ります。
 * @param[in] raw 架空の不変原byte。最大128MiB+1で、巨大fixtureは同一文字の繰返しです。
 * @return 実Deflateを持つ単一member。失敗時はtest processへ例外を通知します。
 */
[[nodiscard]] std::vector<std::byte> assetGzip( const std::string_view raw)
{
	const std::size_t		   capacity = raw.size() > 1024U * 1024U
											  ? raw.size() / 64U + 65536U
											  : raw.size() + 128U ;		// Testだけの有限圧縮buffer。
	std::vector<unsigned char> packed( capacity) ;						// Zlib containerの一時所有値。
	mz_ulong	packedSize = static_cast<mz_ulong>( packed.size()) ;	// 実圧縮長の格納先。
	// 原char byteをminizの読取り型へ借用するtest compressor境界です。
	const auto *input = reinterpret_cast<const unsigned char *>( raw.data()) ;
	const int	compressed =
		mz_compress2( packed.data(), &packedSize, input, static_cast<mz_ulong>( raw.size()),
					 MZ_BEST_COMPRESSION) ;	// 実miniz結果。
	// 生成失敗を検査対象の拒否と混同しない。
	if( compressed != MZ_OK || packedSize < 6U) {
		throw std::runtime_error( "synthetic gzip compression failed") ;
	}

	std::vector<std::byte> gzip{std::byte{0x1f}, std::byte{0x8b}, std::byte{8}, std::byte{0},
								std::byte{0},	 std::byte{0},	  std::byte{0}, std::byte{0},
								std::byte{0},	 std::byte{0xff}} ;	// GZip固定header。
	// Zlibのheader二byteとAdler四byteを除いた実raw Deflateだけを移す。
	for( std::size_t offset = 2U; offset < packedSize - 4U; ++offset) {
		gzip.push_back( static_cast<std::byte>( packed[offset])) ;
	}

	const std::uint32_t crc = static_cast<std::uint32_t>(
		// 原展開byteの独立CRC32。
		mz_crc32( MZ_CRC32_INIT, input, raw.size())) ;
	// CRC32と実原byte数を一値ずつtrailerのlittle endianへ欠落なく追加する。
	for( const std::uint32_t value : {crc, static_cast<std::uint32_t>( raw.size())}) {
		// 固定四byteだけを下位側から順に追加する。
		for( unsigned shift = 0U; shift < 32U; shift += 8U) {
			gzip.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
		}
	}

	return gzip ;
}

//------------------------------------------------------------------------------

/**
 * @brief Delegated GET一hopの架空HTTP応答を表す。
 */
struct DelegatedHttpResponse {
	/// 応答status code。
	DWORD						status{HTTP_STATUS_OK} ;
	/// Redirect応答の絶対Location。最終応答では未指定。
	std::optional<std::wstring> location ;
	/// 最終応答で返す架空本文。
	std::string					body{"abc"} ;
	/// Content-Length文字列。未指定時はchunked相当。
	std::optional<std::wstring> declared{L"3"} ;
	/// 索引経路だけが照合する元最終Content-Type。
	std::optional<std::wstring> contentType{L"application/zip"} ;
} ;

/**
 * @brief Delegated GETの全WinHTTP呼出しを非通信で再現するfixtureである。
 */
struct DelegatedHttpFixture {
	/// 元HTML規約pageの用途限定cache headerを照合する場合trueです。
	bool							   htmlTerms{} ;
	/// 索引の各DNS address拒否試験だけで私設addressを返す指定。
	bool							   privateDns{} ;
	/// Request順に返す有限応答列。
	std::vector<DelegatedHttpResponse> responses{DelegatedHttpResponse{}} ;
	/// 現在responseの0起点index。送信前は最大値。
	std::size_t						   activeResponseIndex{std::numeric_limits<std::size_t>::max()} ;
	/// 現在本文で次に読み取るbyte位置。
	std::size_t						   bodyOffset{} ;
	/// 一回のReadDataで返すbyte上限。
	DWORD							   chunk{64U * 1'024U} ;
	/// Connectへ渡された架空host列。
	std::vector<std::wstring>		   connectedHosts ;
	/// OpenRequestへ渡された架空path／query列。
	std::vector<std::wstring>		   requestedPaths ;
	/// Local resolverへ渡された架空host列。
	std::vector<std::wstring>		   resolvedHosts ;
	/// Hop開始ごとに返す架空UTC秒列。
	std::vector<std::uint64_t> utcSeconds{20'010U, 20'010U, 20'010U, 20'010U, 20'010U, 20'010U} ;
	/// 次に返すUTC秒のindex。
	std::size_t				   utcIndex{} ;
	/// 作成したsession／connection／request handle数。
	std::uint32_t			   opened{} ;
	/// 解放した架空handle数。
	std::uint32_t			   closed{} ;
	/// Bodyなしで実行したGET送信数。
	std::uint32_t			   sends{} ;
	/// ReadData呼出し数。
	std::uint32_t			   reads{} ;
	/// 自動redirect禁止を設定した回数。
	std::uint32_t			   redirectDisabled{} ;
	/// HIGH auto-logon policyを設定した回数。
	std::uint32_t			   highLogon{} ;
	/// 規約GETでCookie送受信を無効化した回数。
	std::uint32_t			   cookieDisabled{} ;
	/// 規約GETへ固定のcache再検証headerを設定した回数。
	std::uint32_t			   cacheControlHeaders{} ;
	/// System proxy、HTTPS GET、headerなしbodyなしを維持した場合true。
	bool					   safeRequest{true} ;
	/// 1-basedで失敗させるReadData回数。0は失敗なし。
	std::uint32_t			   failReadAt{} ;
	/// 指定ReadData回数の直後に取消しを成立させる。0は取消しなし。
	std::uint32_t			   cancelAfterRead{} ;
	/// 取消しcallbackが返す現在値。
	bool					   cancellationRequested{} ;
} ;

// WinHttpOpenと注入clockから現在fixtureを解決する試験thread限定の借用先。
thread_local DelegatedHttpFixture  *activeDelegatedHttpFixture{} ;

/**
 * @brief Delegated GET専用の完全な非通信I/O表を作る。
 * @return WinHTTP、DNS、UTCの全境界を現在threadのfixtureへ委譲する表。
 * @pre 呼出しthreadのactiveDelegatedHttpFixtureは、そのworker停止まで所有するfixtureを指します。
 * @note Fake handleは同fixtureを借用し、実通信へのfallbackを持ちません。
 * 固定headerや安全optionが一致しない呼出しはsafeRequestへ残し、終端後の観測で拒否します。
 */
[[nodiscard]] OfficialHttpTransport makeDelegatedHttpTransport()
{
	OfficialHttpTransport transport ;	// 全低位I/Oを以下のfakeで置換する結果。
	// System／per-user proxyを選択するsessionだけを架空作成する。
	transport.open = []( LPCWSTR userAgent, const DWORD access, LPCWSTR proxy, LPCWSTR bypass,
						DWORD flags) -> HINTERNET {
		auto &fixture = *activeDelegatedHttpFixture ;	// 試験scopeが所有する現在fixture。
		++fixture.opened ;
		fixture.safeRequest &= userAgent != nullptr &&
							   std::wstring_view( userAgent) ==
								   L"Mozilla/5.0 (compatible; DriverCrate/0.1.0; "
								   L"+https://github.com/EnterOgawa/drivercrate)" &&
							   access == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY && proxy == nullptr &&
							   bypass == nullptr && flags == 0U ;
		return &fixture ;
	} ;
	// 検証済みhostへのHTTPS既定port接続を記録する。
	transport.connect = []( const HINTERNET session, LPCWSTR serverName, const INTERNET_PORT port,
						   const DWORD reserved) -> HINTERNET {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( session) ;	// Sessionのfixture。
		++fixture.opened ;
		fixture.safeRequest &= port == INTERNET_DEFAULT_HTTPS_PORT && reserved == 0U ;
		fixture.connectedHosts.emplace_back( serverName) ;
		return &fixture ;
	} ;
	// BodyなしHTTPS GETのpathだけを試験内に記録する。
	transport.openRequest = []( const HINTERNET connection, LPCWSTR verb, LPCWSTR objectName,
							   LPCWSTR, LPCWSTR referer, LPCWSTR *,
							   const DWORD flags) -> HINTERNET {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( connection) ;	// Connectionのfixture。
		++fixture.opened ;
		fixture.safeRequest &=
			std::wstring_view( verb) == L"GET" && referer == nullptr && flags == WINHTTP_FLAG_SECURE ;
		fixture.requestedPaths.emplace_back( objectName) ;
		return &fixture ;
	} ;
	// 全phaseが正の有限timeoutなら安全設定を維持する。
	transport.setTimeouts = []( const HINTERNET handle, const int resolve, const int connect,
							   const int send, const int receive) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Timeout対象fixture。
		fixture.safeRequest &= resolve > 0 && connect > 0 && send > 0 && receive > 0 &&
							   resolve <= 60'000 && connect <= 60'000 && send <= 60'000 &&
							   receive <= 60'000 ;
		return TRUE ;
	} ;
	// 自動redirect禁止とcredential非送信のHIGH policyだけを受理する。
	transport.setOption = []( const HINTERNET handle, const DWORD option, const LPVOID value,
							 const DWORD bytes) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Option対象fixture。
		fixture.safeRequest &= value != nullptr && bytes == sizeof( DWORD) ;
		const DWORD setting =
			// 固定option値。
			value == nullptr ? 0U : *static_cast<const DWORD *>( value) ;
		// ApplicationがLocationを検証するための自動redirect禁止を数える。
		if( option == WINHTTP_OPTION_REDIRECT_POLICY) {
			fixture.redirectDisabled += setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER ? 1U : 0U ;
			fixture.safeRequest &= setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER ;
		}
		// Dynamic targetへ既定credentialを送らないHIGH policyを数える。
		else if( option == WINHTTP_OPTION_AUTOLOGON_POLICY) {
			fixture.highLogon += setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ? 1U : 0U ;
			fixture.safeRequest &= setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;
		}
		// 規約GETのCookie禁止を観測し、別featureの無効化を受理しません。
		else if( option == WINHTTP_OPTION_DISABLE_FEATURE) {
			fixture.cookieDisabled += setting == WINHTTP_DISABLE_COOKIES ? 1U : 0U ;
			fixture.safeRequest &= setting == WINHTTP_DISABLE_COOKIES ;
		} else {
			fixture.safeRequest = false ;
		}

		return TRUE ;
	} ;
	// 共通の固定Acceptと規約GETだけのcache再検証headerを厳密に照合します。
	transport.addHeaders = []( const HINTERNET handle, LPCWSTR headers, const DWORD length,
							  const DWORD flags) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Header対象fixture。
		const std::wstring_view value( headers, length) ;				// 今回追加するheader。
		const bool				accept =
			value ==
			// 本番共通GETの固定値です。
			L"Accept: application/json, application/xml, text/xml, application/octet-stream, */*\r\n" ;
		const bool cache = value == L"Cache-Control: no-cache\r\n" &&
						   !fixture.requestedPaths.empty() &&
						   // 規約用途だけです。
						   (fixture.requestedPaths.back() == L"/terms.txt" ||
							(fixture.htmlTerms && fixture.requestedPaths.back() == L"/support")) ;
		fixture.cacheControlHeaders += cache ? 1U : 0U ;
		fixture.safeRequest &=
			(accept || cache) && flags == (WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) ;
		return TRUE ;
	} ;
	// 任意bodyまたは個別headerなしの一回GETだけを次の応答へ進める。
	transport.sendRequest = []( const HINTERNET handle, LPCWSTR headers, const DWORD length,
							   LPVOID optional, const DWORD optionalLength, const DWORD totalLength,
							   const DWORD_PTR context) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// 送信対象fixture。
		fixture.safeRequest &= headers == nullptr && length == 0U && optional == nullptr &&
							   optionalLength == 0U && totalLength == 0U && context == 0U ;
		// 用意した応答数を超える予期しない送信を失敗させる。
		if( fixture.sends >= fixture.responses.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		fixture.activeResponseIndex = fixture.sends ;
		fixture.bodyOffset			= 0U ;
		++fixture.sends ;
		return TRUE ;
	} ;
	// Send成功済み応答だけを受信済みとして返す。
	transport.receiveResponse = []( const HINTERNET handle, LPVOID) -> BOOL {
		const auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// 応答fixture。
		// 現在応答がなければ受信成功を返さない。
		if( fixture.activeResponseIndex >= fixture.responses.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		return TRUE ;
	} ;
	// Status、Location、Content-LengthのWinHTTP二段階照会を再現する。
	transport.queryHeaders = []( const HINTERNET handle, const DWORD info, LPCWSTR, LPVOID output,
								LPDWORD bytes, LPDWORD headerIndex) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Header対象fixture。
		// 現在応答がなければheader値を返さない。
		if( fixture.activeResponseIndex >= fixture.responses.size() || bytes == nullptr) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		const DelegatedHttpResponse &response =
			fixture.responses[fixture.activeResponseIndex] ;	// 現在hopの応答。
		// Status codeは数値照会へ直接返す。
		if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = response.status ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const std::optional<std::wstring> *value = nullptr ;	// 照会対象の任意header。
		// Redirect Locationを選択する。
		if( info == WINHTTP_QUERY_LOCATION) {
			value = &response.location ;
		}
		// 最終本文のContent-Lengthを選択する。
		else if( info == WINHTTP_QUERY_CONTENT_LENGTH) {
			value = &response.declared ;
		}
		// 索引の共通有限header readerだけへ一つのmedia typeを返す。
		else if( info == WINHTTP_QUERY_CONTENT_TYPE) {
			// 既に一headerを返したreaderへ重複を合成しない。
			if( headerIndex != nullptr && *headerIndex != 0U) {
				SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
				return FALSE ;
			}

			value = &response.contentType ;
		}

		// 未指定または対象外headerは欠損として返す。
		if( value == nullptr || !value->has_value()) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const DWORD required =	// 終端NULを含むheader byte数。
			static_cast<DWORD>( ((*value)->size() + 1U) * sizeof( wchar_t)) ;
		// 一段目または不足bufferには必要量だけを返す。
		if( output == nullptr || *bytes < required) {
			*bytes = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( output, (*value)->c_str(), required) ;
		*bytes = required - sizeof( wchar_t) ;
		// 同名header反復readerだけへ前進を通知する。
		if( info == WINHTTP_QUERY_CONTENT_TYPE && headerIndex != nullptr) {
			++*headerIndex ;
		}

		return TRUE ;
	} ;
	// 現在本文の未読byte数を有限DWORDで返す。
	transport.queryAvailable = []( const HINTERNET handle, LPDWORD bytes) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// 本文対象fixture。
		// 現在応答と出力先がなければ本文量を返さない。
		if( fixture.activeResponseIndex >= fixture.responses.size() || bytes == nullptr) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		const auto &body = fixture.responses[fixture.activeResponseIndex].body ;	// 現在の架空本文。
		*bytes			 = static_cast<DWORD>( body.size() - fixture.bodyOffset) ;
		return TRUE ;
	} ;
	// 現在本文をchunk上限までcopyし、部分成功後の故障と取消しを注入する。
	transport.readData = []( const HINTERNET handle, LPVOID buffer, const DWORD requested,
							LPDWORD received) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Read対象fixture。
		++fixture.reads ;
		// 指定回のAPI故障ではbyteを返さない。
		if( fixture.failReadAt == fixture.reads) {
			SetLastError( ERROR_WINHTTP_CONNECTION_ERROR) ;
			return FALSE ;
		}

		const auto &body = fixture.responses[fixture.activeResponseIndex].body ;	// 現在の架空本文。
		const DWORD copied = std::min( {requested, fixture.chunk,
									   // 実copy量。
									   static_cast<DWORD>( body.size() - fixture.bodyOffset)}) ;
		std::memcpy( buffer, body.data() + fixture.bodyOffset, copied) ;
		fixture.bodyOffset += copied ;
		*received = copied ;
		// 指定回の読取り後に次の保存前取消しを成立させる。
		if( fixture.cancelAfterRead == fixture.reads) {
			fixture.cancellationRequested = true ;
		}

		return TRUE ;
	} ;
	// 同じfake backendが作った所有handleの解放数を記録する。
	transport.closeHandle = []( const HINTERNET handle) -> BOOL {
		++static_cast<DelegatedHttpFixture *>( handle)->closed ;
		return TRUE ;
	} ;
	// 架空hostを一件のIPv4へ解決し、private名だけ10/8を返す。
	transport.resolveDestination = []( const std::wstring_view					   host,
									  std::vector<OfficialResolvedNetworkAddress> &addresses) {
		auto &fixture = *activeDelegatedHttpFixture ;	// Resolver対象fixture。
		fixture.resolvedHosts.emplace_back( host) ;
		addresses.clear() ;
		OfficialResolvedNetworkAddress address ;	// 一件だけ返す架空IPv4 address。
		address.family = OfficialNetworkAddressFamily::IPV4 ;
		// Private拒否fixtureのhostだけ10.0.0.1へ解決する。
		if( fixture.privateDns || host.find( L"private") != std::wstring_view::npos) {
			address.bytes[0] = std::byte{10U} ;
			address.bytes[3] = std::byte{1U} ;
		} else {
			address.bytes[0] = std::byte{8U} ;
			address.bytes[1] = std::byte{8U} ;
			address.bytes[2] = std::byte{8U} ;
			address.bytes[3] = std::byte{8U} ;
		}

		addresses.push_back( address) ;
		return static_cast<NativeError>( 0) ;
	} ;
	// 各hop直前にfixtureが用意したUTC秒を一回ずつ返す。
	transport.utcNow = []() {
		auto &fixture = *activeDelegatedHttpFixture ;	// 時計対象fixture。
		// 用意した回数を超えるhopは0時刻でfail-closedにする。
		if( fixture.utcIndex >= fixture.utcSeconds.size()) {
			return std::uint64_t{0U} ;
		}

		return fixture.utcSeconds[fixture.utcIndex++] ;
	} ;
	return transport ;
}

/** @brief 有限recordとINF条件を持つ人工IDだけの非空ZIPをRAMで作ります。
 * @param[in] partial 二つの架空PnP IDを含める場合trueです。
 * @param[in] multiInf 独立して検証する二つ目の基本INFを含める場合trueです。
 * @param[in] capacityBoundary 正常なINFを33組含む入力の場合trueです。
 * @param[in] unknownDependency 確認不能な外部INF依存を明示する場合trueです。
 * @param[in] componentCase 0は従来byte、1～91と100～149は元入力、150以後は固定した追加回帰です。
 * @param[in] archiveInfCount 0は従来入力、128または129は独立したarchive境界の基本INF閉包数です。
 * @return 実原container。人工CATは実署名の証明ではありません。
 */
std::string uiDriverZip( const bool partial, const bool multiInf, const bool capacityBoundary,
						const bool unknownDependency, const unsigned componentCase = 0U,
						const unsigned archiveInfCount = 0U)
{
	// 明示境界入力は登録した二値だけとし、誤指定を通常入力へ丸めません。
	if( archiveInfCount != 0U && archiveInfCount != 128U && archiveInfCount != 129U) {
		throw std::runtime_error( "UI archive INF boundary rejected") ;
	}

	std::string inf = "[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Ports\r\n"
					  "ClassGuid={4d36e978-e325-11ce-bfc1-08002be10318}\r\nProvider=%Vendor%\r\n"
					  "DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=fixture.cat\r\n"
					  "[Manufacturer]\r\n%Vendor%=Models,NTamd64\r\n[Models.NTamd64]\r\n"
					  "%Device%=Install,TESTBUS\\SYNTH_0001\r\n" ;	// 架空通常INFの完全な元byteです。
	// 二deviceは同INF内の独立Models節へ結び、各recordがその節の全IDを持ちます。
	if( partial) {
		inf = replaced( std::move( inf), "%Vendor%=Models,NTamd64\r\n",
					   "%Vendor%=Models,NTamd64\r\nSecond=SecondModels,NTamd64\r\n") ;
		inf += "[SecondModels.NTamd64]\r\n%Device%=Install,TESTBUS\\SYNTH_0002\r\n" ;
	}

	inf += "[Install]\r\nCopyFiles=Files\r\n[Files]\r\nfixture.sys\r\n"
		   "[DestinationDirs]\r\nFiles=12\r\n[SourceDisksNames]\r\n1=\"fixture\"\r\n"
		   "[SourceDisksFiles]\r\nfixture.sys=1\r\n[Strings]\r\n"
		   "Vendor=\"Fixture Vendor\"\r\nDevice=\"Fixture Device\"\r\n" ;
	// 不明な具体的外部依存を元INFへ明示し、通常基本INFへ補完させません。
	if( unknownDependency) {
		inf = replaced(
			std::move( inf), "[Install]\r\n",
			"[Install]\r\nInclude=missing-required.inf\r\nNeeds=MissingRequiredSection\r\n") ;
	}

	const bool component = componentCase == 2U || componentCase == 3U || componentCase == 4U ||
						   componentCase == 5U || componentCase == 6U || componentCase == 9U ||
						   componentCase == 20U || componentCase == 22U || componentCase == 23U ||
						   componentCase == 24U ||
						   // 必要SWCを実byteへ固定します。
						   componentCase == 26U || (componentCase >= 32U && componentCase <= 177U) ;
	const bool extension = componentCase != 0U && componentCase != 2U && componentCase != 9U &&
						   componentCase != 22U && componentCase != 23U && componentCase != 24U &&
						   componentCase < 32U ;	// 元31条件のExtensionだけを不変更で固定します。
	// Baseの選択DDInstallにだけ具体的必要参照を追加します。
	if( componentCase) {
		std::string copies =
			extension ? "CopyINF=extension.inf\r\n" : "" ;	// 現選択DDInstallの元import宣言です。
		// C03だけはExtensionを元SWC producerとします。
		if( component && componentCase != 3U) {
			copies += "CopyINF=component.inf\r\n" ;
		}

		// 同ExtensionId競合を二つの元INFで固定します。
		if( componentCase == 12U) {
			copies += "CopyINF=competing.inf\r\n" ;
		}

		inf = replaced( std::move( inf), "[Install]\r\n", "[Install]\r\n" + copies) ;
		// 元AddComponentの必要子を同INFのComponentIDsへ結合します。
		if( component && componentCase != 3U) {
			inf += "[Install.Components]\r\nAddComponent=RequiredChild,,Child\r\n"
				   "[Child]\r\nComponentIDs=SYNTH_COMPONENT\r\n" ;
		}

		// 未検証OS/store依存を元関係として保持します。
		if( componentCase == 27U) {
			inf = replaced( std::move( inf), "[Install]\r\n",
						   "[Install]\r\nInclude=system.inf\r\nNeeds=Unverified\r\n") ;
		}

		// 別current-OS modelの未選択子を必要集合へ混入させません。
		if( componentCase == 29U) {
			inf = replaced( std::move( inf), "[Models.NTamd64]\r\n",
						   "[Models.NTamd64]\r\nOther=OtherInstall,TESTBUS\\UNSELECTED\r\n") ;
			inf +=
				"[OtherInstall]\r\n[OtherInstall.Components]\r\nAddComponent=Foreign,,ForeignChild\r\n"
				"[ForeignChild]\r\nComponentIDs=UNSELECTED_COMPONENT\r\n" ;
		}

		// 別OSのCopyINFもSetupCopyOEMInfの潜在importとして見落としません。
		if( componentCase == 30U) {
			inf += "[Unused.NTarm64]\r\nCopyINF=unselected.inf\r\n" ;
		}

		// 新固定条件はdevice別の異なるDDInstallと現在x64装飾を実元byteへ保持します。
		if( componentCase >= 32U) {
			inf = replaced( std::move( inf), "[Models.NTamd64]\r\n",
						   "[Models.NTamd64]\r\nOther=OtherInstall,TESTBUS\\UNSELECTED\r\n") ;
			inf = replaced( std::move( inf), "[Install]\r\n", "[Install.NTamd64]\r\n") ;
			// 追加memberなしの四回帰へ架空のComponents節を作りません。
			if( component) {
				inf = replaced( std::move( inf), "[Install.Components]\r\n",
							   "[Install.NTamd64.Components]\r\n") ;
			}

			// 別nodeを選ぶ正例では元Modelsの同device所属も同時に固定します。
			if( componentCase == 40U) {
				inf = replaced( std::move( inf), "Install,TESTBUS\\SYNTH_0001",
							   "Install,TESTBUS\\UNSELECTED") ;
				inf = replaced( std::move( inf), "OtherInstall,TESTBUS\\UNSELECTED",
							   "OtherInstall,TESTBUS\\SYNTH_0001") ;
				inf = replaced( std::move( inf), "ComponentIDs=SYNTH_COMPONENT",
							   "ComponentIDs=UNSELECTED_COMPONENT") ;
			}

			// 二元deviceの共有例では二番目だけが別DDInstallに属します。
			if( componentCase == 48U || componentCase == 80U) {
				inf = replaced( std::move( inf), "Install,TESTBUS\\SYNTH_0002",
							   "OtherInstall,TESTBUS\\SYNTH_0002") ;
			}

			const bool otherSelected =
				// 元別node正例です。
				componentCase == 40U || componentCase == 48U || componentCase == 80U ;
			inf += "[OtherInstall.NTamd64]\r\n" ;
			// 選択対象の別処理だけが必要SWCをimportします。
			if( otherSelected) {
				inf += "CopyINF=component.inf\r\n" ;
			}

			inf += "[OtherInstall.NTamd64.Components]\r\nAddComponent=Foreign,,ForeignChild\r\n"
				   "[ForeignChild]\r\nComponentIDs=" ;
			inf += otherSelected ? "SYNTH_COMPONENT\r\n" : "UNSELECTED_COMPONENT\r\n" ;
			// 基本名fallbackに実在保証がないことを元Models内の欠損節で確認します。
			if( componentCase == 38U) {
				inf = replaced( std::move( inf), "[Models.NTamd64]\r\n",
							   "[Models.NTamd64]\r\nMissing=MissingInstall,TESTBUS\\UNUSED\r\n") ;
			}

			// 別OSの実在節は現在OS Models所属の代用になりません。
			if( componentCase == 42U) {
				inf +=
					"[Models.NTarm64]\r\nArm=ForeignOs,TESTBUS\\SYNTH_0001\r\n[ForeignOs.NTarm64]\r\n" ;
			}

			// SetupCopyOEMInfの全潜在importを非選択architectureに明示します。
			if( componentCase == 33U || componentCase == 34U || componentCase == 35U ||
			   componentCase == 49U || componentCase == 50U) {
				inf += "[Unused.NTarm64]\r\nCopyINF=importonly.inf\r\n" ;
			}
		}
	}

	// 新固定Include/Needs条件は元deviceの選択節だけへ結び、旧条件のbyteを変更しません。
	if( (componentCase >= 151U && componentCase <= 169U) ||
	   (componentCase >= 178U && componentCase <= 180U)) {
		const bool systemDependency = componentCase == 152U || componentCase == 155U ||
									  componentCase == 157U ||
									  // SYSTEMだけは元閉包へ複写しません。
									  componentCase == 159U || componentCase >= 178U ;
		const std::string include =
			systemDependency ? "peer.inf" : "component.inf" ;	// 元明示参照です。
		const std::string needs =
			// 正確な必要節です。
			componentCase == 153U || componentCase == 179U ? "MissingShared" : "Shared" ;
		// 非選択OSだけの参照は現在x64の作用へ混入させません。
		if( componentCase == 161U || componentCase == 180U) {
			inf += "[Unused.NTarm64]\r\nInclude=missing-unused.inf\r\nNeeds=MissingUnused\r\n" ;
		} else {
			inf =
				replaced( std::move( inf), "[Install.NTamd64]\r\n",
						 "[Install.NTamd64]\r\nInclude=" + include + "\r\nNeeds=" + needs + "\r\n") ;
		}
	}

	mz_zip_archive archive{} ;	// 全経路で終了するRAM writerです。
	// Writer開始不成立を内容検査正例に数えません。
	if( !mz_zip_writer_init_heap( &archive, 0U, 0U)) {
		throw std::runtime_error( "UI ZIP initialization failed") ;
	}

	const std::string sys =
		"fictional nonexecuting system driver bytes" ;				// 実driverではありません。
	const std::string cat = "fictional unsigned catalog bytes" ;	// Windows署名chainは未確認です。
	// 完全な三memberを追加できた場合だけ原ZIPを発行します。
	if( !mz_zip_writer_add_mem( &archive, "fixture.inf", inf.data(), inf.size(), MZ_NO_COMPRESSION) ||
	   !mz_zip_writer_add_mem( &archive, "fixture.sys", sys.data(), sys.size(), MZ_NO_COMPRESSION) ||
	   !mz_zip_writer_add_mem( &archive, "fixture.cat", cat.data(), cat.size(), MZ_NO_COMPRESSION)) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "UI ZIP members failed") ;
	}

	// 必要memberごとに実INF/CATを作り、署名低位表へ元byteを渡します。
	if( componentCase) {
		const auto add = [&]( const char *name, const std::string &bytes) {
			// 原memberの欠落を正常なcontainerへ変更しません。
			if( !mz_zip_writer_add_mem( &archive, name, bytes.data(), bytes.size(),
									  MZ_NO_COMPRESSION)) {
				mz_zip_writer_end( &archive) ;
				throw std::runtime_error( "Required role ZIP member failed") ;
			}
		} ; // RAM writerを同期中だけ借用します。
		// 正式Class/GUID/ExtensionIdと元親Modelsを持つ完全な人工INFです。
		std::string ext =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Extension\r\n"
			"ClassGuid={e2f84ce7-8efa-411c-aa69-97454ca4cb57}\r\n"
			"ExtensionId={e7886766-7203-4153-a704-d1d8a36bc00f}\r\nProvider=\"Fixture Vendor\"\r\n"
			"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=extension.cat\r\n"
			"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
			"Device=Install,TESTBUS\\SYNTH_0001\r\n" ;
		// 共有元親の両IDを同じExtension Modelsへ明示します。
		if( partial) {
			ext += "Device=Install,TESTBUS\\SYNTH_0002\r\n" ;
		}

		ext += "[Install]\r\nAddReg=Settings\r\n[Settings]\r\nHKR,,FixtureFlag,0x00010001,1\r\n" ;
		// C03はExtensionの実AddComponentを親device producerとします。
		if( componentCase == 3U) {
			ext =
				replaced( std::move( ext), "[Install]\r\n", "[Install]\r\nCopyINF=component.inf\r\n") ;
			ext +=
				"[Install.Components]\r\nAddComponent=RequiredChild,,Child\r\n[Child]\r\nComponentIDs=SYNTH_COMPONENT\r\n" ;
		}

		// 元必要file欠損はCopyINFを読んだだけで正常へ補完しません。
		if( extension && componentCase != 7U) {
			// 不一致の元Modelsをrole専用適用性で拒否します。
			if( componentCase == 8U) {
				ext = replaced( std::move( ext), "TESTBUS\\SYNTH_0001", "TESTBUS\\WRONG_DEVICE") ;
			}

			// Class名が同じでも異なるGUIDを拒否します。
			if( componentCase == 10U) {
				ext = replaced( std::move( ext), "e2f84ce7-8efa-411c-aa69-97454ca4cb57",
							   "5c4c3332-344d-483c-8739-259e934c9cc8") ;
			}

			// 現x64以外のModelsを正常sectionへ補完しません。
			if( componentCase == 11U) {
				ext = replaced( std::move( ext), "NTamd64", "NTarm64") ;
				ext = replaced( std::move( ext), "NTamd64", "NTarm64") ;
			}

			// 実CopyINF cycleを有限関係監査へ渡します。
			if( componentCase == 13U) {
				ext = replaced( std::move( ext), "[Install]\r\n",
							   "[Install]\r\nCopyINF=fixture.inf\r\n") ;
			}

			add( "extension.inf", ext) ;
			add( "extension.cat", cat) ;
			// 未選択OS sectionの追加importも元実INF/CATを持つ入力です。
			if( componentCase == 30U) {
				add( "unselected.inf", replaced( ext, "extension.cat", "unselected.cat")) ;
				add( "unselected.cat", cat) ;
			}

			// 同ExtensionIdの独立競合memberを別CATへ結合します。
			if( componentCase == 12U) {
				add( "competing.inf", replaced( ext, "extension.cat", "competing.cat")) ;
				add( "competing.cat", cat) ;
			}
		}

		// 必要SWCを別base候補にせず、元ComponentIDsとdriver-only内容へ固定します。
		if( component) {
			std::string swc =
				"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SoftwareComponent\r\n"
				"ClassGuid={5c4c3332-344d-483c-8739-259e934c9cc8}\r\nProvider=\"Fixture Vendor\"\r\n"
				"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=component.cat\r\n"
				"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
				"Device=Install,SWC\\SYNTH_COMPONENT\r\n[Install]\r\nAddReg=Settings\r\n"
				"[Settings]\r\nHKR,,DriverComponentFlag,0x00010001,1\r\n" ;	// Serviceなしの正例です。
			// 元必須子ID不一致を名前から一致へ補完しません。
			if( componentCase == 9U) {
				swc = replaced( std::move( swc), "SWC\\SYNTH_COMPONENT", "SWC\\WRONG_COMPONENT") ;
			}

			// ClassだけでAddSoftwareをdriver-onlyへ昇格しません。
			if( componentCase == 26U) {
				swc +=
					"[Install.Software]\r\nAddSoftware=UnrelatedApp,,App\r\n[App]\r\nSoftwareType=2\r\nSoftwareID=pfn://UnrelatedApp\r\n" ;
			}

			// 元50入力は不変更で、新条件だけを同INFの完全サービスbyteへ固定します。
			if( (componentCase >= 51U && componentCase <= 91U) ||
			   (componentCase >= 100U && componentCase <= 150U)) {
				swc = replaced( std::move( swc), "[Install]\r\n",
							   "[Install]\r\nCopyFiles=ServiceFiles\r\n") ;
				swc +=
					"[Install.Services]\r\nAddService=FixtureDeviceService,0,DeviceService\r\n"
					"[DeviceService]\r\nServiceType=0x10\r\nStartType=3\r\nErrorControl=1\r\n"
					"ServiceBinary=%13%\\component_service.exe\r\n"
					"[ServiceFiles]\r\ncomponent_service.exe\r\n[DestinationDirs]\r\nServiceFiles=13\r\n"
					"[SourceDisksNames]\r\n1=\"fixture\"\r\n[SourceDisksFiles]\r\ncomponent_service.exe=1\r\n" ;
				// Shared-process種別も同じ元コピー/source/byte境界を必要とします。
				if( componentCase == 52U) {
					swc = replaced( std::move( swc), "ServiceType=0x10", "ServiceType=0x20") ;
				}

				// サービス根拠のない第二EXEを、正当な第一EXEから包括許可しません。
				if( componentCase == 53U) {
					swc = replaced( std::move( swc), "[ServiceFiles]\r\n",
								   "[ServiceFiles]\r\nextra.exe\r\n") ;
					swc += "extra.exe=1\r\n" ;
					add( "extra.exe", "fictional arbitrary program bytes") ;
				}

				// AddSoftwareは同INFのWin32 serviceとは別の拒否機構です。
				if( componentCase == 54U) {
					swc +=
						"[Install.Software]\r\nAddSoftware=UnrelatedApp,,App\r\n[App]\r\n"
						"SoftwareType=1\r\nSoftwareBinary=%13%\\component_service.exe\r\nSoftwareVersion=1.0.0.0\r\n" ;
				}

				// 必須ServiceBinaryの欠損をSourceDisksFiles名だけで補完しません。
				if( componentCase == 55U) {
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe\r\n",
								   "") ;
				}

				// 必須種別の欠損をClass名から補完しません。
				if( componentCase == 56U) {
					swc = replaced( std::move( swc), "ServiceType=0x10\r\n", "") ;
				}

				// 未対応複合種別を単純0x10へ補正しません。
				if( componentCase == 57U) {
					swc = replaced( std::move( swc), "ServiceType=0x10", "ServiceType=0x110") ;
				}

				// 未知文字列から定数値を推測しません。
				if( componentCase == 58U) {
					swc = replaced( std::move( swc), "ServiceType=0x10",
								   "ServiceType=SERVICE_WIN32_OWN_PROCESS") ;
				}

				// 実byteだけがあってもsource宣言なしを受理しません。
				if( componentCase == 60U) {
					swc = replaced( std::move( swc), "component_service.exe=1\r\n", "") ;
				}

				// 別binary名へ原ServiceBinaryだけを変更します。
				if( componentCase == 61U) {
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=%13%\\other_service.exe") ;
				}

				// Renameされたsourceを同名byteの許可へ換算しません。
				if( componentCase == 62U) {
					swc = replaced( std::move( swc), "[ServiceFiles]\r\ncomponent_service.exe\r\n",
								   "[ServiceFiles]\r\ncomponent_service.exe,renamed.exe\r\n") ;
				}

				// コピー先とServiceBinaryのDIRID不一致を固定します。
				if( componentCase == 63U) {
					swc = replaced( std::move( swc), "ServiceFiles=13", "ServiceFiles=12") ;
				}

				// ExtensionへWin32の必要SWC権限を流用しません。
				if( componentCase == 65U) {
					swc = replaced( std::move( swc), "Class=SoftwareComponent", "Class=Extension") ;
					swc = replaced( std::move( swc), "5c4c3332-344d-483c-8739-259e934c9cc8",
								   "e2f84ce7-8efa-411c-aa69-97454ca4cb57") ;
				}

				// 正式Classと別GUIDの矛盾を同名roleへ補完しません。
				if( componentCase == 66U) {
					swc = replaced( std::move( swc), "5c4c3332-344d-483c-8739-259e934c9cc8",
								   "e2f84ce7-8efa-411c-aa69-97454ca4cb57") ;
				}

				// 別DDInstall serviceの存在を選択節の任意EXEコピーへ転用しません。
				if( componentCase == 79U) {
					swc = replaced( std::move( swc), "[Install.Services]", "[OtherInstall.Services]") ;
					swc += "[OtherInstall]\r\nAddReg=Settings\r\n" ;
				}

				// Kernel種別へEXE参照の限定許可を流用しません。
				if( componentCase == 82U) {
					swc = replaced( std::move( swc), "ServiceType=0x10", "ServiceType=1") ;
				}

				// 必須起動値の欠損をDEMANDへ補完しません。
				if( componentCase == 83U) {
					swc = replaced( std::move( swc), "StartType=3\r\n", "") ;
				}

				// 未定義ErrorControl値を通常値へ補正しません。
				if( componentCase == 84U) {
					swc = replaced( std::move( swc), "ErrorControl=1", "ErrorControl=4") ;
				}

				// ServiceBinary全値の引数をbasenameへ切り詰めません。
				if( componentCase == 85U) {
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=%13%\\component_service.exe --unknown") ;
				}

				// 別INFのCATをcomponentの署名根拠へ借用しません。
				if( componentCase == 86U) {
					swc = replaced( std::move( swc), "CatalogFile=component.cat",
								   "CatalogFile=fixture.cat") ;
				}

				// 同leafの任意絶対位置を同INF copy宛先の成功へ変換しません。
				if( componentCase == 89U) {
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=C:\\unrelated\\component_service.exe") ;
				}

				// 裸basenameの一致では完全なcopy宛先の証明になりません。
				if( componentCase == 90U) {
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=component_service.exe") ;
				}

				// 未解決位置tokenを既知DIRIDのコピーへ補完しません。
				if( componentCase == 91U) {
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=%UnknownDestination%\\component_service.exe") ;
				}

				std::string serviceSource =
					"component_service.exe" ;	// 元root byteの位置を維持する初期値です。
				// 新subdir条件だけは同元source位置と宛先全値を固定します。
				if( componentCase == 100U || componentCase == 101U || componentCase == 102U ||
				   componentCase == 103U || componentCase == 115U || componentCase == 117U ||
				   componentCase == 120U || componentCase == 121U || componentCase == 123U ||
				   componentCase == 124U || componentCase == 125U) {
					const std::string directory = componentCase == 101U
													  ? "service_bin\\amd64"
													  : "service_bin" ;	// 元subdirです。
					swc							= replaced( std::move( swc), "ServiceFiles=13\r\n",
														   "ServiceFiles=13," + directory + "\r\n") ;
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=%13%\\" + directory + "\\component_service.exe") ;
					swc = replaced( std::move( swc), "component_service.exe=1\r\n",
								   "component_service.exe=1," + directory + "\r\n") ;
					serviceSource = directory + "/component_service.exe" ;
					std::replace( serviceSource.begin(), serviceSource.end(), '\\', '/') ;
				}

				// sourceと異なるDIRID13 subdirでも実source byteは不変更です。
				if( componentCase == 102U) {
					swc = replaced( std::move( swc), "ServiceFiles=13,service_bin",
								   "ServiceFiles=13,target_bin") ;
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\service_bin",
								   "ServiceBinary=%13%\\target_bin") ;
				}

				// subdir内でもrenameを同名source許可へ変換しません。
				if( componentCase == 103U) {
					swc = replaced( std::move( swc), "[ServiceFiles]\r\ncomponent_service.exe\r\n",
								   "[ServiceFiles]\r\ncomponent_service.exe,renamed.exe\r\n") ;
				}

				// 他標準DIRIDも同HINFの完全binary/copy値を一致させます。
				if( componentCase == 104U || componentCase == 105U || componentCase == 106U) {
					const std::string dirid =
						// 固定標準DIRIDです。
						componentCase == 106U ? "12" : "11" ;
					swc = replaced( std::move( swc), "ServiceFiles=13", "ServiceFiles=" + dirid) ;
					swc = replaced( std::move( swc), "ServiceBinary=%13%",
								   "ServiceBinary=%" + dirid + "%") ;
				}

				// DIRID11ではsourceとdestのsubdirが異なる正式コピーを固定します。
				if( componentCase == 105U) {
					swc = replaced( std::move( swc), "ServiceFiles=11\r\n",
								   "ServiceFiles=11,target_bin\r\n") ;
					swc = replaced( std::move( swc), "ServiceBinary=%11%\\component_service.exe",
								   "ServiceBinary=%11%\\target_bin\\component_service.exe") ;
					swc = replaced( std::move( swc), "component_service.exe=1\r\n",
								   "component_service.exe=1,source_bin\r\n") ;
					serviceSource = "source_bin/component_service.exe" ;
				}

				// 他標準DIRIDを認めてもServiceBinary不一致を許可しません。
				if( componentCase == 107U) {
					swc = replaced( std::move( swc), "ServiceFiles=13", "ServiceFiles=11") ;
				}

				// 新flag条件の正式・不正スカラーを元AddServiceへ一度だけ固定します。
				if( (componentCase >= 108U && componentCase <= 112U) || componentCase == 116U ||
				   componentCase == 118U) {
					const std::string flags =
						componentCase == 108U	? "0x18"
						: componentCase == 109U ? "0x800"
						: componentCase == 110U ? "0x19F8"
						: componentCase == 111U ? "0x2"
						: componentCase == 112U ? "0x4"
						: componentCase == 116U
							? "24"
							: "SPSVCINST_STARTSERVICE" ;	// code前の固定全値です。
					swc = replaced( std::move( swc), "AddService=FixtureDeviceService,0,",
								   "AddService=FixtureDeviceService," + flags + ",") ;
				}

				// custom DIRIDの解決結果からsource許可を作りません。
				if( componentCase == 113U) {
					swc = replaced( std::move( swc), "ServiceFiles=13", "ServiceFiles=32768") ;
					swc = replaced( std::move( swc), "ServiceBinary=%13%", "ServiceBinary=%32768%") ;
				}

				// 宛先traversalをWindowsのpath補正で正常位置へ変換しません。
				if( componentCase == 114U) {
					swc = replaced( std::move( swc), "ServiceFiles=13\r\n",
								   "ServiceFiles=13,..\\escape\r\n") ;
					swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								   "ServiceBinary=%13%\\..\\escape\\component_service.exe") ;
				}

				// 宣言したsubdirの実byte欠損をroot同leafで補完しません。
				if( componentCase == 115U) {
					serviceSource = "component_service.exe" ;
				}

				// 正常serviceのsubdirに同梱された無関係EXEは包括許可しません。
				if( componentCase == 117U) {
					swc += "extra.exe=1,service_bin\r\n" ;
					add( "service_bin/extra.exe", "fictional arbitrary program bytes") ;
				}

				// 未対応媒体pathをrootと誤認しない入力を実媒体memberへ固定します。
				if( componentCase == 119U) {
					swc =
						replaced( std::move( swc), "1=\"fixture\"\r\n", "1=\"fixture\",,,media\r\n") ;
					serviceSource = "media/component_service.exe" ;
				}

				// 正式直接CopyFilesも明示DefaultDestDirの同subdirを必要とします。
				if( componentCase == 120U) {
					swc = replaced( std::move( swc), "CopyFiles=ServiceFiles",
								   "CopyFiles=@component_service.exe") ;
					swc = replaced( std::move( swc), "ServiceFiles=13,service_bin",
								   "DefaultDestDir=13,service_bin") ;
				}

				// 明示同名sourceはrenameを含まない正常コピーです。
				if( componentCase == 121U) {
					swc = replaced(
						std::move( swc), "[ServiceFiles]\r\ncomponent_service.exe\r\n",
						"[ServiceFiles]\r\ncomponent_service.exe,component_service.exe\r\n") ;
				}

				// 十六進の正式start/controlも全値スカラーだけを使用します。
				if( componentCase == 122U) {
					swc = replaced( std::move( swc), "StartType=3", "StartType=0x3") ;
					swc = replaced( std::move( swc), "ErrorControl=1", "ErrorControl=0x1") ;
				}

				// 媒体条件の新byteだけを変更し、元C01～C125の実入力を保持します。
				if( componentCase >= 126U && componentCase <= 150U) {
					std::string media = "media" ;	// 同INF source IDへ結ぶ媒体pathです。
					std::string directory ;			// DIRID13照合には媒体を含めない元file subdirです。
					// 元subdir付き正常と13不一致負例を同じ実sourceへ固定します。
					if( componentCase == 127U || componentCase == 128U || componentCase == 143U ||
					   componentCase == 149U) {
						directory = componentCase == 128U ? "service_bin\\nested" : "service_bin" ;
					}

					// 深い媒体位置もsource subdirとは別の元値です。
					if( componentCase == 128U) {
						media = "media\\amd64" ;
					}

					// DIRID11はsourceと異なるコピー先へ同元fileだけを結びます。
					if( componentCase == 129U) {
						directory = "source_bin" ;
						swc		  = replaced( std::move( swc), "ServiceFiles=13",
											 "ServiceFiles=11,target_bin") ;
						swc = replaced( std::move( swc), "ServiceBinary=%13%\\component_service.exe",
									   "ServiceBinary=%11%\\target_bin\\component_service.exe") ;
					}

					// DIRID12も同一媒体のroot sourceを保持します。
					if( componentCase == 130U) {
						swc = replaced( std::move( swc), "ServiceFiles=13", "ServiceFiles=12") ;
						swc = replaced( std::move( swc), "ServiceBinary=%13%", "ServiceBinary=%12%") ;
					}

					// 同元subdirをSourceDisksFilesとDIRID13の両方へ固定します。
					if( !directory.empty()) {
						swc = replaced( std::move( swc), "component_service.exe=1\r\n",
									   "component_service.exe=1," + directory + "\r\n") ;
						// DIRID11の別宛先はsource subdirへ読み替えません。
						if( componentCase != 129U) {
							swc = replaced( std::move( swc), "ServiceFiles=13\r\n",
										   "ServiceFiles=13," + directory + "\r\n") ;
							swc = replaced(
								std::move( swc), "ServiceBinary=%13%\\component_service.exe",
								"ServiceBinary=%13%\\" + directory + "\\component_service.exe") ;
						}
					}

					serviceSource = media + "/" + (directory.empty() ? "" : directory + "/") +
									"component_service.exe" ;
					std::replace( serviceSource.begin(), serviceSource.end(), '\\', '/') ;

					// 宣言位置とは異なるroot byteだけを持つ負例です。
					if( componentCase == 131U) {
						serviceSource = "component_service.exe" ;
					}

					// 危険な媒体宣言は安全な元ZIP memberへ補正しません。
					if( componentCase == 133U || componentCase == 134U || componentCase == 135U ||
					   componentCase == 146U) {
						media = componentCase == 133U	? "..\\escape"
								: componentCase == 134U ? "C:\\escape"
								: componentCase == 135U ? "\\\\server\\share"
														: "media\\..\\other" ;
					}

					// 同INF媒体ID2だけを選び、ID1のroot/別媒体へfallbackしません。
					if( componentCase == 136U || componentCase == 137U) {
						swc = replaced( std::move( swc), "component_service.exe=1",
									   "component_service.exe=2") ;
						// 正常条件だけがID2の元媒体行を持ちます。
						if( componentCase == 136U) {
							swc			  = replaced( std::move( swc), "[SourceDisksFiles]\r\n",
													 "2=\"fixture2\",,,media2\r\n[SourceDisksFiles]\r\n") ;
							serviceSource = "media2/component_service.exe" ;
						}
					}

					// 同一active媒体IDの競合を先頭値へ縮約しません。
					if( componentCase == 138U) {
						swc = replaced( std::move( swc), "[SourceDisksFiles]\r\n",
									   "1=\"conflicting\",,,other_media\r\n[SourceDisksFiles]\r\n") ;
					}

					// 同一source fileの別ID宣言を末尾へ加えて曖昧性を固定します。
					if( componentCase == 139U) {
						swc += "component_service.exe=2,other_source\r\n" ;
					}

					// 正常媒体に同梱しても無関係な参照EXEは包括許可しません。
					if( componentCase == 142U) {
						swc += "extra.exe=1\r\n" ;
						add( "media/extra.exe", "fictional arbitrary program bytes") ;
					}

					// 直接copyは同INFの明示DefaultDestDirへ結びます。
					if( componentCase == 143U) {
						swc = replaced( std::move( swc), "CopyFiles=ServiceFiles",
									   "CopyFiles=@component_service.exe") ;
						swc = replaced( std::move( swc), "ServiceFiles=13,service_bin",
									   "DefaultDestDir=13,service_bin") ;
					}

					// 公式媒体root記法の先頭区切りを実archive root相対位置へ結びます。
					if( componentCase == 144U) {
						media = "\\media" ;
					}

					// SetupAPIが保証する媒体末尾区切り解決を元byte位置へ結びます。
					if( componentCase == 145U) {
						media = "\"media\\\"" ;
					}

					// 別媒体の同leafを宣言媒体の成功へ換算しません。
					if( componentCase == 147U) {
						serviceSource = "other_media/component_service.exe" ;
					}

					// 同sourceの二copy参照は一つの許可へ重複排除しません。
					if( componentCase == 148U) {
						swc = replaced( std::move( swc), "CopyFiles=ServiceFiles",
									   "CopyFiles=ServiceFiles,ServiceFiles") ;
					}

					// DIRID13比較へ媒体prefixを混ぜる不正宛先は成功にしません。
					if( componentCase == 149U) {
						swc = replaced( std::move( swc), "ServiceFiles=13,service_bin",
									   "ServiceFiles=13,media\\service_bin") ;
						swc = replaced( std::move( swc), "ServiceBinary=%13%\\service_bin",
									   "ServiceBinary=%13%\\media\\service_bin") ;
					}

					// 区切りだけの非空媒体を空媒体へ救済せず、既存root byteがあっても拒否します。
					if( componentCase == 150U) {
						media		  = "\"\\\"" ;
						serviceSource = "component_service.exe" ;
					}

					swc = replaced( std::move( swc), "1=\"fixture\"\r\n",
								   "1=\"fixture\",,," + media + "\r\n") ;
				}

				// 欠損EXE条件だけは原archiveへ当該byteを生成しません。
				if( componentCase != 59U && componentCase != 132U) {
					add( serviceSource.c_str(), "fictional nonexecuting Win32 service bytes") ;
				}
			}

			// PACKAGEの必要節と全payloadを同元SWC/CATへ結びます。
			if( componentCase >= 151U && componentCase <= 169U) {
				swc += "[Shared]\r\nCopyFiles=@component.sys\r\n[DestinationDirs]\r\n"
					   "DefaultDestDir=12\r\n[SourceDisksNames]\r\n1=\"fixture\"\r\n"
					   "[SourceDisksFiles]\r\ncomponent.sys=1\r\n" ;
				// 循環参照は元baseの正確な選択節へ戻します。
				if( componentCase == 156U) {
					swc = replaced( std::move( swc), "[Shared]\r\n",
								   "[Shared]\r\nInclude=fixture.inf\r\nNeeds=Install.NTamd64\r\n") ;
				}

				// 解決済みの同じ到達節にある文脈限定HKR AddRegを実byteで検査します。
				if( componentCase == 162U) {
					swc =
						replaced( std::move( swc), "[Shared]\r\n", "[Shared]\r\nAddReg=Settings\r\n") ;
				}

				add( "component.sys", "fictional dependency package bytes") ;
			}

			add( "component.inf", swc) ;
			// 欠損CAT負例の原containerを完全fixtureのために救済しません。
			if( componentCase != 87U) {
				add( "component.cat", cat) ;
			}
		}

		// 同梱の無関係appは必要参照でなく別拒否行のままです。
		if( componentCase == 6U) {
			add( "utility.inf",
				"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SoftwareComponent\r\n[Install.Software]\r\nAddSoftware=Utility,,App\r\n") ;
			add( "utility.exe", "fictional nonexecuting application bytes") ;
			// 完全低位owner表は拒否INFも同CATへ固定します。
			add( "utility.cat", cat) ;
		}

		// 選択外importは全INF/CAT/memberを持ち、必要子のComponentIDsと区別します。
		if( componentCase == 33U || componentCase == 34U || componentCase == 35U ||
		   componentCase == 49U || componentCase == 50U) {
			std::string imported =
				"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SoftwareComponent\r\n"
				"ClassGuid={5c4c3332-344d-483c-8739-259e934c9cc8}\r\nProvider=\"Fixture Vendor\"\r\n"
				"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=importonly.cat\r\n"
				"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
				"Device=Install,SWC\\IMPORT_ONLY\r\n[Install]\r\nCopyFiles=Files\r\n"
				"[Files]\r\nimportonly.sys\r\n[DestinationDirs]\r\nFiles=12\r\n"
				// 実driverではありません。
				"[SourceDisksNames]\r\n1=\"fixture\"\r\n[SourceDisksFiles]\r\nimportonly.sys=1\r\n" ;
			// 独立基本INFのimportも明示導入なしで全byteを検査します。
			if( componentCase == 50U) {
				imported = replaced( std::move( imported), "Class=SoftwareComponent", "Class=Ports") ;
				imported = replaced( std::move( imported), "5c4c3332-344d-483c-8739-259e934c9cc8",
									"4d36e978-e325-11ce-bfc1-08002be10318") ;
				imported =
					replaced( std::move( imported), "SWC\\IMPORT_ONLY", "TESTBUS\\IMPORT_ONLY") ;
			}

			add( "importonly.inf", imported) ;
			add( "importonly.sys", "fictional unselected driver bytes") ;
			// 固定欠損例だけは未選択importのCATを欠き、元期待を保ちます。
			if( componentCase != 34U) {
				add( "importonly.cat", cat) ;
			}
		}
	}

	const unsigned basicInfCount = archiveInfCount != 0U ? archiveInfCount
								   : capacityBoundary	 ? 33U
								   : multiInf			 ? 2U
														 : 1U ;	// 元INFを含む閉包数です。
	// 全基本INFを別名・別元byteと完全な独立CAT/member閉包へ固定し、上限外も切り捨てません。
	for( unsigned ordinal = 1U; ordinal < basicInfCount; ++ordinal) {
		const auto base = ordinal == 1U
							  ? std::string{"alternate"}
							  : "alternate" + std::to_string( ordinal) ;	// 全基本INFの一意名です。
		auto alternate	= replaced( inf, "fixture.cat", base + ".cat") ;	// 別基本INFの原byteです。
		alternate		= replaced( std::move( alternate), "fixture.sys", base + ".sys") ;
		alternate		= replaced( std::move( alternate), "fixture.sys", base + ".sys") ;
		const std::string alternateSys =
			"alternate fictional nonexecuting system bytes" ;	// 元第一INFと異なる人工memberです。
		const std::string alternateCat =
			"alternate fictional unsigned catalog bytes" ;	// 実署名chainを持たない人工CATです。
		// 完全な第二閉包の欠損を第一INFの合格で補完しません。
		if( !mz_zip_writer_add_mem( &archive, (base + ".inf").c_str(), alternate.data(),
								  alternate.size(), MZ_NO_COMPRESSION) ||
		   !mz_zip_writer_add_mem( &archive, (base + ".sys").c_str(), alternateSys.data(),
								  alternateSys.size(), MZ_NO_COMPRESSION) ||
		   !mz_zip_writer_add_mem( &archive, (base + ".cat").c_str(), alternateCat.data(),
								  alternateCat.size(), MZ_NO_COMPRESSION)) {
			mz_zip_writer_end( &archive) ;
			throw std::runtime_error( "UI alternate ZIP members failed") ;
		}
	}

	void	   *memory{} ;	// mz_freeへ返す原container所有です。
	std::size_t bytes{} ;	// 有限な実container長です。
	// 原containerの生成失敗を合格INFへ変更しません。
	if( !mz_zip_writer_finalize_heap_archive( &archive, &memory, &bytes)) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "UI ZIP finalization failed") ;
	}

	const std::unique_ptr<void, decltype( &mz_free)> owner{memory,
														  &mz_free} ;	// 原heapの単独所有です。
	mz_zip_writer_end( &archive) ;
	return {static_cast<const char *>( owner.get()), bytes} ;
}

/** @brief 自作ZIPの元INFと明示Models節を署名fixtureの公開tupleへ結びます。
 * @param[in] key 同じRAM hash helperです。
 * @param[in] zip 自作した原ZIP byteです。
 * @param[in] member 同ZIPに実在する基本INF名です。
 * @param[in] section 同INFに明示された全IDを読むModels節です。
 * @param[in] raw 元recordの他の条件を保持するfixture byteです。
 * @return 原INF hash/member/節/全公開IDへ結合した署名前のfixtureです。
 * @note SetupAPIのread-only HINFを使います。CAT/適合/候補成功を生成しません。
 */
std::string uiInfIdentity( const RamKey &key, const std::string &zip, const std::string &member,
						  const std::wstring &section, std::string raw)
{
	mz_zip_archive archive{} ;	// 同原ZIPを同期でだけ借用します。
	// 原ZIPを読めない場合は公開tupleを生成しません。
	if( !mz_zip_reader_init_mem( &archive, zip.data(), zip.size(), 0U)) {
		throw std::runtime_error( "UI identity archive failed") ;
	}

	std::size_t size{} ;	// 同原INFの実byte長です。
	void *const extracted = mz_zip_reader_extract_file_to_heap( &archive, member.c_str(), &size,
															   0U) ;	// Fixture内memberだけです。
	mz_zip_reader_end( &archive) ;
	const std::unique_ptr<void, decltype( &mz_free)> bytes{extracted,
														  &mz_free} ;	// 全経路で原heapを解放します。
	// 元INFの全byteがない場合はfixture生成を停止します。
	if( !bytes || size == 0U || size > 65536U) {
		throw std::runtime_error( "UI identity INF missing") ;
	}

	OfficialDownloadWorkspace workspace ;					// HINF読取だけの自作保護領域です。
	HANDLE					  file = INVALID_HANDLE_VALUE ;	// 成功時だけRAIIへ移します。
	// 保護領域を所有できなければ元fileを直接読取りません。
	if( workspace.initialize( L"index-identity-fixture", 377U) != 0U ||
	   workspace.createFile( L"fixture.inf", file) != 0U) {
		throw std::runtime_error( "UI identity workspace failed") ;
	}

	std::unique_ptr<void, decltype( &CloseHandle)> fileOwner{
		file, &CloseHandle} ;	// 同書込handleだけを所有します。
	DWORD written{} ;			// 同原INF全byteの実書込数です。
	// 元INFの全byteを書き終える前にHINFを開きません。
	if( !WriteFile( file, bytes.get(), static_cast<DWORD>( size), &written, nullptr) ||
	   written != size) {
		throw std::runtime_error( "UI identity copy failed") ;
	}

	fileOwner.reset() ;
	const auto path =
		// 公開identityから生成したpathではありません。
		workspace.path( L"fixture.inf") ;
	const HINF opened = SetupOpenInfFileW(
		// 原HINFです。
		path.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
	// 元HINFが開けなければmetadataを合成しません。
	if( opened == INVALID_HANDLE_VALUE) {
		throw std::runtime_error( "UI identity HINF failed") ;
	}

	const std::unique_ptr<void, decltype( &SetupCloseInfFile)> inf{
		opened, &SetupCloseInfFile} ;	// 同HINFを閉じます。
	INFCONTEXT line{} ;					// 明示節の原行です。
	// 明示された元Models節を欠損時に補完しません。
	if( !SetupFindFirstLineW( opened, section.c_str(), nullptr, &line)) {
		throw std::runtime_error( "UI identity Models missing") ;
	}

	std::string ids = "[" ;	// 同節の全公開IDを保持します。
	// 元Modelsの全行を末尾まで読み、全集合を保持します。
	do {
		// 元行の第2 field以降を種別付きで全件読みます。
		for( DWORD field = 2U; field <= SetupGetFieldCount( &line); ++field) {
			std::array<wchar_t, 513U> id{} ;	// 既存ID上限だけの受信bufferです。
			// 一IDの取得失敗を部分集合へ丸めません。
			if( !SetupGetStringFieldW( &line, field, id.data(), static_cast<DWORD>( id.size()),
									 nullptr)) {
				throw std::runtime_error( "UI identity ID missing") ;
			}

			ids += ids.size() == 1U ? "" : "," ;
			ids += field == 2U ? "{\"kind\":\"HARDWARE\",\"value\":\""
							   : "{\"kind\":\"COMPATIBLE\",\"value\":\"" ;
			// 既知ASCII fixtureのJSON escapeだけを行います。
			for( const wchar_t character : std::wstring_view{id.data()}) {
				// JSONで必要なbackslashだけを二重化します。
				if( character == L'\\') {
					ids += '\\' ;
				}

				ids += static_cast<char>( character) ;
			}

			ids += "\"}" ;
		}
	} while( SetupFindNextLine( &line, &line)) ;
	ids += "]" ;
	const auto identityStart =
		// 自作recordの固定objectです。
		raw.find( "\"publishedIdentityEvidence\":{") ;
	const auto idsStart = raw.find( "[", identityStart) ;	// 元ID配列だけです。
	const auto idsEnd	= raw.find( "]", idsStart) ;		// 自作fixtureの平坦なID配列終端です。
	raw.replace( idsStart, idsEnd - idsStart + 1U, ids) ;
	// 固定object内の元文字列だけを書換え、他の時刻/条件を保持します。
	const auto replaceIdentityField = [&]( const std::string &name, const std::string &value) {
		const auto start = raw.find( "\"" + name + "\":\"", identityStart) + name.size() +
						   4U ;						// 固定fieldの値先頭です。
		const auto end = raw.find( '"', start) ;	// 既知ASCII fixture値の終端です。
		raw.replace( start, end - start, value) ;
	} ;
	replaceIdentityField( "infIdentity", member) ;
	std::string modelName ;	// 明示ASCII Models名だけを元表記で保持します。
	// 既知fixtureでもnarrowing前にASCII上限を確認します。
	for( const wchar_t character : section) {
		// 非ASCII名をlossy変換して正のidentityへ変更しません。
		if( character < 0x20 || character > 0x7e) {
			throw std::runtime_error( "UI identity section encoding failed") ;
		}

		modelName.push_back( static_cast<char>( character)) ;
	}

	replaceIdentityField( "modelSection", modelName) ;
	replaceIdentityField( "evidenceSha256",
						 recordDigest( key, {static_cast<const char *>( bytes.get()), size})) ;
	return raw ;
}

/** @brief 実network cost照会を行わない固定低位境界です。 */
class UiIndexCostReader final : public IOfficialNetworkCostReader {
public:
	/** @brief 無課金の架空回線条件だけを返します。
	 * @param[out] cost 固定UNRESTRICTEDです。
	 * @return 読取り成功0です。
	 */
	NativeError read( OfficialNetworkCostKind &cost) noexcept override
	{
		cost = OfficialNetworkCostKind::UNRESTRICTED ;
		return 0 ;
	}
} ;
} // namespace

/** @brief 原ZIPの全memberを非圧縮CABへ実byte変換する有限fixtureです。
 * @param[in] zip 全原INF/CAT/memberを保持した実ZIPです。
 * @return 通常Windows CAB readerへ渡す非圧縮Cabinetの元全byteです。
 * @throws std::runtime_error 元ZIPを読めない場合、member上限超過または抽出失敗です。
 * @note zipは同期変換中だけ借用し、返却byteは呼出し側が所有します。実driver操作は行いません。
 */
[[nodiscard]] std::string uiDriverCabinet( const std::string &zip)
{
	mz_zip_archive reader{} ;	// 元ZIPをRAMで読む第三者readerです。
	// 原ZIPを読めない場合は正常CABを合成しません。
	if( !mz_zip_reader_init_mem( &reader, zip.data(), zip.size(), 0)) {
		throw std::runtime_error( "CAB fixture ZIP rejected") ;
	}

	// 元scopeだけで使用する有限な検査値です。未知を成功へ補完しません。
	std::string files ;
	std::string data ;	// CFFILE群と一非圧縮folderの実全byteです。
	// 終端または元集合の有限必要数です。成功数を推測しません。
	const auto	count = mz_zip_reader_get_num_files( &reader) ;
	// Captureなしの同期lambdaです。借用outputへ元valueを固定幅bytes（2または4）で追記します。
	const auto	append = []( std::string &output, std::uint32_t value, unsigned bytes) {
		 // 固定幅の全byteを欠落なく追記します。
		 for( unsigned i = 0; i < bytes; ++i) {
			 output.push_back( static_cast<char>( value & 255U)) ;
			 value >>= 8U ;
		 }
	 } ;
	// 有限な通常fileだけを元相対名と全byteへ結合します。
	for( mz_uint i = 0; i < count; ++i) {
		mz_zip_archive_file_stat stat{} ;	// 元file metadataです。
		// Directoryや過大なfolderを固定正例へ追加しません。
		if( !mz_zip_reader_file_stat( &reader, i, &stat) || stat.m_is_directory ||
		   stat.m_uncomp_size > 32768U - data.size()) {
			mz_zip_reader_end( &reader) ;
			throw std::runtime_error( "CAB fixture capacity") ;
		}

		// 原ZIP memberの全byte受信です。人工成功内容へ置換しません。
		std::string member( static_cast<std::size_t>( stat.m_uncomp_size), '\0') ;
		// 全byteの実抽出なしではCAB memberを発行しません。
		if( !mz_zip_reader_extract_to_mem( &reader, i, member.data(), member.size(), 0)) {
			mz_zip_reader_end( &reader) ;
			throw std::runtime_error( "CAB fixture extraction") ;
		}

		append( files, static_cast<std::uint32_t>( member.size()), 4U) ;
		append( files, static_cast<std::uint32_t>( data.size()), 4U) ;
		append( files, 0U, 2U) ;
		append( files, 0U, 2U) ;
		append( files, 0U, 2U) ;
		append( files, 0U, 2U) ;
		files += stat.m_filename ;
		files.push_back( '\0') ;
		data += member ;
	}

	mz_zip_reader_end( &reader) ;
	std::string cabinet{"MSCF"} ;	// 固定Cabinet headerです。
	append( cabinet, 0U, 4U) ;
	append( cabinet, static_cast<std::uint32_t>( 44U + files.size() + 8U + data.size()), 4U) ;
	append( cabinet, 0U, 4U) ;
	append( cabinet, 44U, 4U) ;
	append( cabinet, 0U, 4U) ;
	cabinet.push_back( 3) ;
	cabinet.push_back( 1) ;
	append( cabinet, 1U, 2U) ;
	append( cabinet, count, 2U) ;
	append( cabinet, 0U, 2U) ;
	append( cabinet, 0U, 2U) ;
	append( cabinet, 0U, 2U) ;
	append( cabinet, static_cast<std::uint32_t>( 44U + files.size()), 4U) ;
	append( cabinet, 1U, 2U) ;
	append( cabinet, 0U, 2U) ;
	cabinet += files ;
	append( cabinet, 0U, 4U) ;
	append( cabinet, static_cast<std::uint32_t>( data.size()), 2U) ;
	append( cabinet, static_cast<std::uint32_t>( data.size()), 2U) ;
	cabinet += data ;
	return cabinet ;
}
/** @see support/metadata_ui_fixture.h */
SignedIndexUiInput makeSignedIndexUiInput( const bool partial, const bool shared,
										  const bool multiInf, const bool capacityBoundary,
										  const bool				 unknownDependency,
										  const bool				 unknownPayloadEvidence,
										  const SignedIndexUiOptions options)
{
	RamKey key ;	// 秘密鍵はこのscopeのCNG RAM handleだけです。
	key.generate( 3072U) ;
	SignedIndexUiInput result ;	// 実storeと原ZIPの所有返却です。
	result.zip = uiDriverZip( partial, multiInf, capacityBoundary, unknownDependency,
							 options.requiredComponentCase, options.archiveInfCount) ;
	// 境界試験の投入全数を完成した原ZIPから独立に列挙し、製品の部分結果破棄と区別します。
	if( capacityBoundary || options.archiveInfCount != 0U) {
		mz_zip_archive reader{} ;	// 原ZIP byteを借用する同期readerです。
		// 完成した原containerを列挙できない場合は投入件数を推定しません。
		if( !mz_zip_reader_init_mem( &reader, result.zip.data(), result.zip.size(), 0)) {
			throw std::runtime_error( "UI archive boundary inventory failed") ;
		}

		// Captureなしのdeleterが同期readerをscope終了・例外の両方で解放します。
		const auto closeReader = []( mz_zip_archive *archive) { mz_zip_reader_end( archive) ; } ;
		// 借用readerの内部resourceを例外時も解放するscope所有者です。
		const std::unique_ptr<mz_zip_archive, decltype( closeReader)> readerOwner{&reader,
																				 closeReader} ;
		const auto memberCount = mz_zip_reader_get_num_files( &reader) ;	// 全原memberの有限数です。
		// 全entryを末尾まで調べ、129個目も投入分母へ保持します。
		for( mz_uint memberIndex = 0U; memberIndex < memberCount; ++memberIndex) {
			mz_zip_archive_file_stat member{} ;	// 同原entryの名前と非圧縮長です。
			// 不正metadataを部分的な成功件数へ置換しません。
			if( !mz_zip_reader_file_stat( &reader, memberIndex, &member)) {
				throw std::runtime_error( "UI archive boundary entry failed") ;
			}

			const std::string name{member.m_filename} ;	// 人工相対名だけの所有copyです。
			// 対象基本INFだけを数え、CAT/SYSを別INFへ数えません。
			if( !name.ends_with( ".inf")) {
				continue ;
			}

			++result.originalArchiveInfCount ;
			const auto base		= name.substr( 0U, name.size() - 4U) ;	// 同名閉包を結ぶ人工名です。
			const auto catIndex = mz_zip_reader_locate_file( &reader, (base + ".cat").c_str(),
															nullptr, 0) ;	// 原CAT位置です。
			const auto sysIndex = mz_zip_reader_locate_file( &reader, (base + ".sys").c_str(),
															nullptr, 0) ;	// 原SYS位置です。
			mz_zip_archive_file_stat catalog{} ;							// 同名CATの非空確認です。
			mz_zip_archive_file_stat system{} ;								// 同名SYSの非空確認です。
			// 全三memberの存在と非空を確認し、署名・内容合格の判断は製品共通検査へ残します。
			if( member.m_uncomp_size != 0U && catIndex >= 0 && sysIndex >= 0 &&
			   mz_zip_reader_file_stat( &reader, static_cast<mz_uint>( catIndex), &catalog) &&
			   mz_zip_reader_file_stat( &reader, static_cast<mz_uint>( sysIndex), &system) &&
			   catalog.m_uncomp_size != 0U && system.m_uncomp_size != 0U) {
				++result.originalArchiveBasicClosureCount ;
			}
		}
	}

	// 従前の元ZIPを不変に保持します。
	result.payload = result.zip ;
	// 元recordのEXE/MSI方式だけを標準INFと区別します。
	const bool installer = options.format == IndexPayloadFormat::WINDOWS_EXE ||
						   options.format == IndexPayloadFormat::WINDOWS_MSI ;
	// CABは実全memberを保ち、installerは実起動不能な架空byteだけに限定します。
	if( options.format == IndexPayloadFormat::CABINET) {
		result.payload = uiDriverCabinet( result.zip) ;
	}
	// 実起動不能な架空EXE/MSI byteだけを元署名入力へ固定します。
	else if( installer) {
		result.payload =
			options.format == IndexPayloadFormat::WINDOWS_EXE
				? std::string{"MZ fictional signed driver installer fixture"}
				: std::string{"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 fictional MSI driver fixture"} ;
	}

	const auto driverHash = recordDigest( key, result.payload) ;	// 同実payloadの全byte hashです。
	auto	   raw = descriptorRecord( descriptorFixture()) ;		// 全取得条件の元record byteです。
	raw			   = replaced( std::move( raw), RECORD_CLAIM_HASH, driverHash) ;
	raw			   = replaced( std::move( raw), RECORD_CLAIM_HASH, driverHash) ;
	raw			   = replaced( std::move( raw), "\"valueBytes\":1234",
							  "\"valueBytes\":" + std::to_string( result.payload.size())) ;
	raw			   = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
							  "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
	// 事前固定した四形式だけの拡張子です。任意filenameを使いません。
	const std::string extension = options.format == IndexPayloadFormat::CABINET		  ? "cab"
								  : options.format == IndexPayloadFormat::WINDOWS_EXE ? "exe"
								  : options.format == IndexPayloadFormat::WINDOWS_MSI ? "msi"
																					  : "zip" ;
	// 元strict codecへ固定する有限形式申告です。内容合格ではありません。
	const std::string format = options.format == IndexPayloadFormat::CABINET	   ? "CABINET"
							   : options.format == IndexPayloadFormat::WINDOWS_EXE ? "WINDOWS_EXE"
							   : options.format == IndexPayloadFormat::WINDOWS_MSI ? "WINDOWS_MSI"
																				   : "ZIP" ;
	// 元URL/filename/形式/Content-Typeを同一の実payloadへ原byteで固定します。
	if( options.format != IndexPayloadFormat::ZIP) {
		raw = replaced( std::move( raw), "fixture.zip", "fixture." + extension) ;
		raw = replaced( std::move( raw), "fixture.zip", "fixture." + extension) ;
		raw = replaced( std::move( raw), "(x64).zip", "(x64)." + extension) ;
		raw = replaced( std::move( raw), "\"format\":\"ZIP\"", "\"format\":\"" + format + "\"") ;
		raw = replaced( std::move( raw), "application/zip", "application/octet-stream") ;
	}

	// 原acquisition方式だけを変更し、標準INF recordへinstallerを偽装しません。
	// 実起動不能な架空EXE/MSI byteを元形式の有限入力へ固定します。
	if( installer) {
		raw = replaced( std::move( raw), "STANDARD_INF_ARCHIVE", "OFFICIAL_INSTALLER") ;
	}

	// 独立に固定した原文書とtitle付き全文です。共通rendererの出力を期待値へ代入しません。
	const std::string htmlDocument =
		"<html><head><title>Original 1.0</title></head><body>"
		"<p>Fictional complete driver license.</p><p>Original terms line two.</p></body></html>" ;
	// 改行も含めた共通HTML profileの完全な固定期待です。
	const std::string htmlText =
		"Original 1.0\r\n\r\nFictional complete driver license.\r\n\r\nOriginal terms line two.\r\n" ;
	// 原payload操作と一意textareaを同pageの有限selectorへ固定します。
	const std::string htmlPage =
		"<html><body><div id=\"consent\"><textarea id=\"terms\">" + htmlDocument +
		"</textarea></div><button data-modal=\"one\" data-href=\"https://vendor.example/fixture.zip\">"
		"Download</button></body></html>" ;
	// 共有logへ出さない架空全文です。HTMLは全文を含む元page byteで返します。
	const std::string termsText =
		options.htmlTerms ? htmlPage
						  : "Fictional complete driver license.\nOriginal terms line two.\n" ;
	// 同意必須recordへ全原byte hash/size/公開revisionをcode前期待どおり固定します。
	if( options.termsRequired) {
		// 変更前の同意不要申告の完全原fieldです。
		const auto previous =
			"{\"state\":\"CONFIRMED_NO_CONSENT\",\"reason\":\"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} +
			"\",\"revisionKind\":\"NONE\",\"revision\":\"\",\"textDocument\":null}" ;
		// 元全文hash・正確なsize・公開revisionを固定した申告です。
		const auto next =
			"{\"state\":\"ACCEPTANCE_REQUIRED\",\"reason\":\"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} +
			"\",\"revisionKind\":\"VENDOR_LITERAL\",\"revision\":\"Original 1.0\",\"textDocument\":{\"url\":\"https://vendor.example/terms.txt\",\"sha256\":\"" +
			recordDigest( key, termsText) + "\",\"sizeBytes\":" + std::to_string( termsText.size()) +
			",\"contentType\":\"text/plain; charset=utf-8\"}}" ;
		raw = replaced( std::move( raw), previous, next) ;
		// 共通HTML schemaの原page、選択文書、全文、改訂とpayload関係を真署名へ結びます。
		if( options.htmlTerms) {
			// 原page byteのhashをsource/route/termsの同根拠へ固定します。
			const auto		  pageHash = recordDigest( key, termsText) ;
			// 既存plain四fieldの原文書をHTML五fieldへだけ変更します。
			const std::string extraction =
				"\"htmlExtraction\":{\"profile\":\"TEXTAREA_HTML_DOCUMENT_V1\","
				"\"selector\":{\"tag\":\"textarea\",\"attribute\":\"id\",\"value\":\"terms\"},"
				"\"containerSelector\":{\"tag\":\"div\",\"attribute\":\"id\",\"value\":\"consent\"},"
				"\"linkSelector\":{\"tag\":\"button\",\"attribute\":\"data-modal\",\"value\":\"one\"},"
				"\"payloadAttribute\":\"data-href\",\"documentSha256\":\"" +
				recordDigest( key, htmlDocument) +
				"\",\"documentSizeBytes\":" + std::to_string( htmlDocument.size()) +
				",\"textSha256\":\"" + recordDigest( key, htmlText) +
				"\",\"textSizeBytes\":" + std::to_string( htmlText.size()) +
				",\"bindingEvidenceUrl\":\"https://vendor.example/binding.js\",\"bindingEvidenceSha256\":\"" +
				pageHash + "\"}" ;
			raw = replaced( std::move( raw), "https://vendor.example/terms.txt",
						   "https://vendor.example/support") ;
			raw = replaced( std::move( raw), "\"contentType\":\"text/plain; charset=utf-8\"}",
						   "\"contentType\":\"text/html; charset=utf-8\"," + extraction + "}") ;
			// 有限な元recordの全公開page根拠を同原byteへ結び、旧placeholderを混在させません。
			while( raw.find( RECORD_EVIDENCE_HASH) != raw.npos) {
				raw = replaced( std::move( raw), RECORD_EVIDENCE_HASH, pageHash) ;
			}
		}
	}

	// 具体的条件だけを原recordへ含め、同pageのNVM等を推測追加しません。
	if( options.prerequisite || installer) {
		// 元recordの具体的条件分類です。未知条件を同意へ変換しません。
		const auto kind = options.prerequisite.value_or( IndexPrerequisiteKind::USER_CONFIRMATION) ;
		// 元条件分類の有限wire値です。任意commandではありません。
		const std::string kindName = kind == IndexPrerequisiteKind::LOCAL_CHECK ? "LOCAL_CHECK"
									 : kind == IndexPrerequisiteKind::INSEPARABLE_FIRMWARE
										 ? "INSEPARABLE_FIRMWARE"
										 : "USER_CONFIRMATION" ;
		// 確認または保留する元具体的条件です。作用証明を合成しません。
		const std::string description =
			installer ? (options.wrongScope ? "unknown installer scope"
											: "DriverCrate:installer-scope=selected-driver-only")
			: kind == IndexPrerequisiteKind::LOCAL_CHECK
				? (options.unknownLocal ? "unknown local prerequisite"
										: "DriverCrate:target-os=WINDOWS_11")
				: "Concrete fictional prerequisite" ;
		raw = replaced(
			std::move( raw), "\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[]}",
			"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[{\"kind\":\"" +
				kindName + "\",\"description\":\"" + description +
				"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH} + "\"}]}") ;
	}

	// 同URL/titleでも共有根拠がない元metadataをUNKNOWNのまま署名します。
	if( unknownPayloadEvidence) {
		const auto knownHash =
			"{\"state\":\"KNOWN\",\"sha256\":\"" + driverHash +
			"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} +
			"\",\"reason\":\"\"}" ;	// 元recordの完全な既知hash申告です。
		const std::string unknownHash =
			// 欠損理由を保持する未知申告です。
			"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"payload digest unavailable\"}" ;
		raw = replaced( std::move( raw), knownHash, unknownHash) ;
		raw = replaced( std::move( raw), knownHash, unknownHash) ;
		raw = replaced(
			std::move( raw),
			"{\"state\":\"KNOWN\",\"valueBytes\":" + std::to_string( result.zip.size()) +
				",\"reason\":\"\"}",
			"{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"exact payload size unavailable\"}") ;
	}

	const auto templateRaw = raw ;	// 各実INFへ独立した公開tupleを結ぶ前の元条件です。
	raw = uiInfIdentity( key, result.zip, "fixture.inf", L"Models.NTamd64", std::move( raw)) ;
	std::string entries = recordEntry( key, raw) ;	// 元byteと実hashを結ぶ第一entryです。
	std::string secondTemplate ;					// 同意/主体の差も保持する第二元条件です。
	std::size_t recordCount = 1U ;					// 実INF/Modelsごとの元record件数です。
	// 異なる二deviceの別recordを一意identityと原byteへ固定します。
	if( partial) {
		auto second = replaced( templateRaw, "\"recordId\":\"metadata\"",
							   "\"recordId\":\"second\"") ;	// 第二原recordです。
		second		= replaced( std::move( second), "TESTBUS\\\\SYNTH_0001", "TESTBUS\\\\SYNTH_0002") ;
		// 同Providerでも別の元source subjectへ同意を流用しません。
		if( options.secondTermsSubject) {
			second = replaced( std::move( second), "\"sourceId\":\"fixture-source\"",
							  "\"sourceId\":\"fixture-second-source\"") ;
		}

		// 原payloadを変えず、第二recordの公開revisionだけを独立条件へ固定します。
		if( options.secondTermsRevision) {
			second = replaced( std::move( second), "\"revision\":\"Original 1.0\"",
							  "\"revision\":\"Original 2.0\"") ;
		}

		// 旧P05は同URLでも取得descriptorが異なる独立対として原分母を維持します。
		if( !shared) {
			second = replaced( std::move( second), "\"fileName\":\"Fixture 1.2 (x64).zip\"",
							  "\"fileName\":\"Fixture independent (x64).zip\"") ;
		}

		secondTemplate = second ;
		second		   = uiInfIdentity( key, result.zip, "fixture.inf", L"SecondModels.NTamd64",
									   std::move( second)) ;
		entries += "," + recordEntry( key, second) ;
		++recordCount ;
	}

	const unsigned basicInfCount = options.archiveInfCount != 0U ? options.archiveInfCount
								   : capacityBoundary			 ? 33U
								   : multiInf					 ? 2U
											  : 1U ;	// 原ZIPへ生成した有限な基本INF数です。
	// 別INFのrank流用を前提にせず、全基本INFの本来の原tupleを署名前に用意します。
	for( unsigned ordinal = 1U; ordinal < basicInfCount; ++ordinal) {
		const auto base = ordinal == 1U
							  ? std::string{"alternate"}
							  : "alternate" + std::to_string( ordinal) ;	// ZIPと同じ一意名です。
		auto	   alternate =
			replaced( templateRaw, "\"recordId\":\"metadata\"",
					 "\"recordId\":\"metadata-" + base + "\"") ;	// 他の条件は元recordです。
		alternate =
			uiInfIdentity( key, result.zip, base + ".inf", L"Models.NTamd64", std::move( alternate)) ;
		entries += "," + recordEntry( key, alternate) ;
		++recordCount ;
		// 同共有deviceの第二Models節も同じ実INFへ独立に結びます。
		if( partial) {
			auto second =
				replaced( secondTemplate, "\"recordId\":\"second\"",
						 "\"recordId\":\"second-" + base + "\"") ;	// 元第二主体/同意を保持します。
			second = uiInfIdentity( key, result.zip, base + ".inf", L"SecondModels.NTamd64",
								   std::move( second)) ;
			entries += "," + recordEntry( key, second) ;
			++recordCount ;
		}
	}

	std::string sources = recordSource() ;	// 原source集合を署名byteへ固定します。
	// HTMLのsource根拠だけを同原pageへ結び、製品の保護storeや鍵は変更しません。
	if( options.htmlTerms) {
		sources = replaced( std::move( sources), RECORD_EVIDENCE_HASH, recordDigest( key, termsText)) ;
	}

	// 第二元subjectも同じstrict source schemaと公式起点根拠を通します。
	if( partial && options.secondTermsSubject) {
		sources += "," + recordSource( "fixture-second-source") ;
	}

	const auto	index = descriptorIndex( sources, entries) ;	// 原field順のv2 assetです。
	const auto	gzip  = assetGzip( index) ;						// 実Deflate/CRC/ISIZEの単一GZipです。
	std::string gzipText ;										// CNG digestへ渡す実原containerの所有copyです。
	// 全byteを欠落なくhash入力へ移し、JSONの再整形をしません。
	for( const auto byte : gzip) {
		gzipText.push_back( static_cast<char>( std::to_integer<unsigned char>( byte))) ;
	}

	const auto gzipHash = recordDigest( key, gzipText) ;				// 実圧縮byteの独立CNG hashです。
	auto manifestBytes	= replaced( manifest(), ASSET_HASH, gzipHash) ;	// 署名対象の原manifestです。
	manifestBytes		= replaced( std::move( manifestBytes), ASSET_HASH, gzipHash) ;
	manifestBytes		= replaced( std::move( manifestBytes), "\"sizeBytes\":123",
								   "\"sizeBytes\":" + std::to_string( gzip.size())) ;
	const auto count	= std::to_string( recordCount) ;	// 全実INF/Modelsの原record数です。
	manifestBytes		= replaced(
		  std::move( manifestBytes),
		  "{\"sourceCount\":1,\"recordCount\":3,\"metadataOnlyCount\":1,\"contentInspectedCount\":1,\"unconfirmedCount\":1}",
		  "{\"sourceCount\":" + std::string{partial && options.secondTermsSubject ? "2" : "1"} +
			  ",\"recordCount\":" + std::string{count} + ",\"metadataOnlyCount\":" + count +
			  ",\"contentInspectedCount\":0,\"unconfirmedCount\":0}") ;
	const auto signedEnvelope =
		// 実RSA-PSS3072/salt32署名です。
		envelope( manifestBytes, key.sign( manifestBytes)) ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;	// Public材料だけです。
	auto authenticated = signed_index_detail::authenticateWithTrustKeys(
		signedEnvelope, NOW, std::nullopt, trust) ;	// 製品と同じ原byte verifierです。
	// 実署名認証失敗からstoreや候補DTOを合成しません。
	if( !authenticated.manifest) {
		throw std::runtime_error( "UI manifest authentication failed") ;
	}

	const auto bytes =
		// 実原GZip検査です。
		authenticateIndexAssetBytes( *authenticated.manifest, gzip, NOW) ;
	// 実byte検査が完了していない入力をschemaへ渡しません。
	if( !bytes.receipt) {
		throw std::runtime_error( "UI index asset rejected") ;
	}

	const auto records = readSignedIndexRecords( *bytes.receipt, NOW) ;	// 実strict schema検査です。
	// 不正recordを固定正例として認めません。
	if( !records.receipt) {
		throw std::runtime_error( "UI index record rejected") ;
	}

	auto opened = signed_index_store_detail::Access::createIsolated(
		trust) ;	// 任意pathを受理しない保護rootです。
	// 実保護store初期化なしではworkerへ進みません。
	if( !opened.store) {
		throw std::runtime_error( "UI isolated store failed") ;
	}

	// 従来fixtureは従来どおり保存し、P5だけは実workerのrefreshへcommitを遅延します。
	if( !options.deferredRefresh) {
		const auto committed =
			// 実原子保存です。
			opened.store->commit( *records.receipt, signedEnvelope, gzip, NOW) ;
		// 保存前receiptを保存後snapshotへ読み替えません。
		if( !committed.snapshot || !opened.store->reload( NOW).snapshot) {
			throw std::runtime_error( "UI index commit/reload failed") ;
		}
	}

	auto store = std::shared_ptr<SignedIndexStore>{	// Worker停止までのstore所有です。
												   std::move( opened.store)} ;
	auto http  = std::make_shared<DelegatedHttpFixture>() ;	// 全低位HTTPと原ZIPをRAM所有します。
	http->htmlTerms = options.htmlTerms ;
	http->utcSeconds.assign( 4096U, static_cast<std::uint64_t>( NOW.time_since_epoch().count())) ;
	http->responses.assign( partial && (!shared || unknownPayloadEvidence ||
									   options.secondTermsSubject || options.secondTermsRevision)
							   ? 2U
							   : 1U,
						   DelegatedHttpResponse{}) ;
	// 事前固定した一または二GETだけに同じ元ZIPを返します。
	for( auto &response : http->responses) {
		response.body		 = result.payload ;
		response.declared	 = std::to_wstring( result.payload.size()) ;
		response.contentType = options.format == IndexPayloadFormat::ZIP
								   ? L"application/zip"
								   : L"application/octet-stream" ;
		// 内容hash差だけを作り、元sizeやwire filenameを同時に変更しません。
		if( options.corruptPayload) {
			response.body.front() = 'X' ;
		}
	}

	// 原二targetの第二payloadだけを拒否し、第一成功と部分失敗を独立保持します。
	if( options.corruptSecondPayload && http->responses.size() == 2U) {
		http->responses[1].body.front() = 'X' ;
	}

	// 各原recordの全文GETをpayload GETより先に固定し、hash差は同長byteの差だけにします。
	if( options.termsRequired) {
		// 原全文だけを返す独立HTTP応答です。Payload応答とは分離します。
		DelegatedHttpResponse terms ;
		terms.body	   = termsText ;
		terms.declared = std::to_wstring( termsText.size()) ;
		terms.contentType =
			options.htmlTerms ? L"text/html; charset=utf-8" : L"text/plain; charset=utf-8" ;
		// 拒否fixtureは同長本文の一byte差だけを作り、他条件を変えません。
		if( options.corruptTerms) {
			// HTMLは許容される周辺markupでなく元選択文書の一byteだけを改変します。
			if( options.htmlTerms) {
				const auto offset =
					// 事前固定した元選択文書の位置です。
					terms.body.find( "complete") ;
				// 改変位置不存在を別byteで補完せずfixture生成を失敗へ残します。
				if( offset == terms.body.npos) {
					throw std::runtime_error( "HTML fixture document position unavailable") ;
				}

				terms.body[offset] = 'X' ;
			} else {
				terms.body.front() = 'X' ;
			}
		}

		http->responses.insert( http->responses.begin(), partial ? 2U : 1U, terms) ;
	}

	result.services	   = {.load		 = [store]( auto time) { return store->reload( time) ; },
						  .utc		 = []() { return std::optional{NOW} ; },
						  .monotonic = []() { return std::chrono::steady_clock::now() ; },
						  .targetOs	 = []() { return std::optional{IndexTargetOs::WINDOWS_11} ; },
						  .httpTransport =
							  [http]() {
								  activeDelegatedHttpFixture = http.get() ;
								  return makeDelegatedHttpTransport() ;
							  },
						  .costReader = []() { return std::make_unique<UiIndexCostReader>() ; }} ;
	result.observeHttp = [http]() {
		return SignedIndexUiHttpObservation{http->sends,		  http->opened,
											http->closed,		  http->safeRequest,
											http->cookieDisabled, http->cacheControlHeaders} ;
	} ; // 同operation終端後だけ低位callを同期観測します。
	// この観測は同worker terminal/stop後だけ読み、製品DTOやgrantへしません。
	auto refreshObserved =
		std::make_shared<std::array<std::uint32_t, 4U>>() ;	// calls/load/empty/commitです。
	result.observeRefresh = [refreshObserved]() { return *refreshObserved ; } ;
	// 追加P5 fixtureだけは実暗号・codec・隔離commit/reloadをrefresh呼出しへ接続します。
	if( options.deferredRefresh) {
		result.services.load = [store, refreshObserved]( auto time) {
			++(*refreshObserved)[1] ;
			return store->reload( time) ;
		} ;
		result.services.refresh = [store, refreshObserved, signedEnvelope, gzip,
								   publicBlob =
									   key.publicBlob]( const ProviderScanCancellation &cancel) {
			++(*refreshObserved)[0] ;
			// 取消済みfixtureは実隔離storeへも新しいcommitを開始しません。
			if( cancel && cancel()) {
				return IndexRefreshSummary{
					.status = IndexRefreshStatus::CANCELLED,
					.error	= static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))} ;
			}

			const auto prior = store->reload( NOW) ;	// 保存前の実状態です。
			// 初回emptyだけを実観測として保持します。
			if( (*refreshObserved)[0] == 1U) {
				(*refreshObserved)[2] = prior.status == IndexStoreStatus::EMPTY_STORE ? 1U : 0U ;
			}

			const std::array<signed_index_detail::TrustKey, 1U> keys{
				{{"fixture-main", publicBlob}}} ;	// RAM公開鍵です。
			auto auth = signed_index_detail::authenticateWithTrustKeys(
				signedEnvelope, NOW, std::nullopt, keys) ;	// 実署名です。
			// 不成立を偽の成功callbackで補完しません。
			if( !auth.manifest) {
				return IndexRefreshSummary{.status = IndexRefreshStatus::MANIFEST_REJECTED} ;
			}

			const auto asset =
				// 原gzip検査です。
				authenticateIndexAssetBytes( *auth.manifest, gzip, NOW) ;
			// Size/hash/gzip拒否からschemaへ進みません。
			if( !asset.receipt) {
				return IndexRefreshSummary{.status = IndexRefreshStatus::ASSET_REJECTED} ;
			}

			const auto decoded = readSignedIndexRecords( *asset.receipt, NOW) ;	// 原record検査です。
			// 原recordなしでは実commitを開始しません。
			if( !decoded.receipt) {
				return IndexRefreshSummary{.status = IndexRefreshStatus::RECORDS_REJECTED} ;
			}

			const auto saved =
				// 実隔離commitです。
				store->commit( *decoded.receipt, signedEnvelope, gzip, NOW) ;
			(*refreshObserved)[3] = saved.snapshot ? 1U : 0U ;
			return IndexRefreshSummary{.status = saved.snapshot ? IndexRefreshStatus::REFRESHED
																: IndexRefreshStatus::STORE_FAILED,
									   .error  = saved.error,
									   .attemptedGeneration = saved.persistedGeneration,
									   .store				= {.status				= saved.status,
															   .commit				= saved.commit,
															   .error				= saved.error,
															   .persistedGeneration = saved.persistedGeneration,
															   .usableSnapshot = saved.snapshot.has_value()}} ;
		} ;
	}

	return result ;
}
} // namespace drivercrate::test
