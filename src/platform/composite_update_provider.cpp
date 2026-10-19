//------------------------------------------------------------------------------
/**
 * @file composite_update_provider.cpp
 * @brief 複合update provider実装。
 * @version 01.15.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX取得後監査report callbackを接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIXへDriver Store rank監査境界を注入。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXの計画・取得routingを共通workerへ接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Provider統合loopの目的を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet指定INF導入を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行report失敗時の一括rollbackを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetへrank監査境界を固定。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet監査reportを接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  ASIXのRelease観測を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後候補のinstall routingを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの取得後監査を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  Prolific公式候補の許可ID照合を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Setup class GUID統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  複合処理進捗統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  NVIDIA公式catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Dell公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider registryと状態報告追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Manufacturer／class集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元group追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Lenovo公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  HP公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider別coverage統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  VAIO照合用driver provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  VAIO公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠検証。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Intel Wireless local ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  失敗Providerのcoverage診断保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific serial local ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH serial local ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs CP210x ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  PrinterとPrintQueueの照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査整合性検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD表示専用Provider統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Provider scan状態矛盾拒否追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS段階Provider統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS監査／install routing追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock表示専用Provider統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Local release観測失効接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Provider release差分・保存接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Provider根拠を段階別scan snapshotへ統合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  観測snapshotと候補詳細をsessionへ結合。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  汎用local入力を共通INF検査とWindows適合観測へ接続。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11表示検索を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  Present inventoryの自動探索hintを接続。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  固定root自動探索registrationをCompositeへ接続。
 * Ver.01.06.00 Shunji Ogawa  2026/09/15  Workerの通常scan取消しをresolverへ結合。
 * Ver.01.07.00 Shunji Ogawa  2026/09/15  通常scanのProvider段階間協調取消しを追加。
 * Ver.01.08.00 Shunji Ogawa  2026/09/15  通常scanを共通公式自動探索executorへ接続。
 * Ver.01.09.00 Shunji Ogawa  2026/09/15  自動探索payloadを準備取得と共通内容検査へ接続。
 * Ver.01.10.00 Shunji Ogawa  2026/09/15  自動探索取得後のPnP観測と表示reportを接続。
 * Ver.01.11.00 Shunji Ogawa  2026/09/15  URL非保持探索cacheの通常scan接続を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.13.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.13.01 Shunji Ogawa  2026/10/12  原子的publicationへ使用する非導入参照の所有値を説明。
 * Ver.01.14.00 Shunji Ogawa  2026/10/12  共有取得の原record群をdevice別参照と私有routeへ接続。
 * Ver.01.15.00 Shunji Ogawa  2026/10/13  元workerから必要構成の全選択preflightへ接続。
 * </pre>
 *
 * @note 既存registryで検索・選択取得・導入を振り分け、sessionとProviderの一致を維持します。
 */
//------------------------------------------------------------------------------

#include "platform/composite_update_provider.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/driver_store_inf_transport_internal.h"

#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/local_coverage.h"
#include "core/official_discovery_execution.h"
#include "core/official_discovery_planner.h"

#include "platform/generic_inf_package.h"
#include "platform/official_acquisition.h"
#include "platform/official_discovery_inventory.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/prolific_serial_package.h"
#include "platform/silicon_labs_serial_package.h"
#include "platform/wch_serial_package.h"
#include "platform/windows_product_type.h"

#include "core/candidate_source_group.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

/**
 * @brief 固定familyだけをcaptureする非取得のregistry callbackを作る。
 * @param[in] family 当該登録に固定した初期metadata系列。
 * @return 専用HTTPを呼出し内だけ所有し、通常Provider instanceを参照しないcallback。
 */
MetadataProviderScan metadataScanner( const OfficialReleaseFamily family)
{
	return
		[family]( const ScanSessionId session, const std::span<const OfficialCatalogDevice> devices,
				 const bool server, const std::uint32_t build,
				 MetadataSearchExecutionContext &execution,
				 const ProviderProgressCallback &progress, ProviderMeasurementEvidence &evidence) {
			return scanOfficialMetadataOnly( family, session, devices, server, build, execution,
											progress, evidence) ;
		} ;
}

constexpr std::uint64_t FILE_TIME_TICKS_PER_SECOND = 10000000ULL ;		// FILETIMEの1秒当たりtick数。
constexpr std::uint64_t UNIX_EPOCH_FILE_TIME = 116444736000000000ULL ;	// 1970年開始のFILETIME値。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 現在UTCをUnix秒で取得する。
 * @return 1970年以後の時刻、または変換不能時は値なし。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> currentUtcSeconds() noexcept
{
	FILETIME fileTime{} ;	// Windowsが返す現在UTCの100ns tick値。
	GetSystemTimeAsFileTime( &fileTime) ;
	ULARGE_INTEGER ticks{} ;	// FILETIMEの上下32bitを一つの64bit値へ結合する領域。
	ticks.LowPart  = fileTime.dwLowDateTime ;
	ticks.HighPart = fileTime.dwHighDateTime ;
	// Unix epochより前の異常値をunsigned減算でwrapさせない。
	if( ticks.QuadPart < UNIX_EPOCH_FILE_TIME) {
		return std::nullopt ;
	}

	return (ticks.QuadPart - UNIX_EPOCH_FILE_TIME) / FILE_TIME_TICKS_PER_SECOND ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常scanの取消しcallbackを例外非送出で確認する。
 * @param[in] cancellation 同じworker operationが所有する非blocking照会。
 * @return 取消し要求済み、またはcallback契約違反時はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isStandardScanCancellationRequested(
	const ProviderScanCancellation &cancellation) noexcept
{
	// Callbackがない従来の同期呼出しへ取消し状態を推測しない。
	if( !cancellation) {
		return false ;
	}

	try {
		return cancellation() ;
	} catch( ...) {
		// 取消し照会の例外後にnetworkまたは候補公開を継続しない。
		return true ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 通常scanの協調取消し終端を構築する。
 * @param[in] scanSessionId Workerが今回発行したscan session ID。
 * @return 候補、計測、取得権限を持たないABORTED結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanResult makeCancelledStandardScan( const ScanSessionId scanSessionId) noexcept
{
	ScanResult result ;	// UI状態機械へ返す最小の取消し終端。
	result.scanSessionId = scanSessionId ;
	result.purpose		 = ScanPurpose::STANDARD ;
	result.outcome		 = OutcomeCode::ABORTED ;
	result.state		 = ProviderScanState::FAILURE ;
	result.error		 = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider registry entryが共通公式自動探索の対象か確認する。
 * @param[in] descriptor Registry正本の一Provider。
 * @return 自動探索capabilityを宣言している場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAutomaticDiscoveryDescriptor( const ProviderDescriptor &descriptor) noexcept
{
	return (descriptor.capabilities & capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY)) !=
		   0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTTP未実行または内部拒否を候補なしの単一Provider結果へ変換する。
 * @param[in] scanSessionId 現在の通常scan session ID。
 * @param[in] state 対象外、回線未許可または一般失敗の有限状態。
 * @param[in] error 失敗時のnative診断値。正常制御終端では0。
 * @return 候補、取得権限、install routingを持たないProvider結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanResult makeAutomaticDiscoveryControlResult( const ScanSessionId	 scanSessionId,
															 const ProviderScanState state,
															 const NativeError error = 0) noexcept
{
	ScanResult result ;	// 共通executor開始前の有限なProvider結果。
	result.scanSessionId = scanSessionId ;
	result.purpose		 = ScanPurpose::STANDARD ;
	result.state		 = state ;
	result.error		 = error ;
	// 対象外と回線未許可は処理失敗ではない正常制御終端として保持する。
	if( state == ProviderScanState::NOT_APPLICABLE ||
	   state == ProviderScanState::NETWORK_NOT_APPROVED) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
	} else {
		result.succeeded = false ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.state	 = ProviderScanState::FAILURE ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通取得結果を取得成功と監査成功を分離した準備結果へ変換する。
 * @param[in] error 取得APIが返した診断値。
 * @param[in] task Worker承認済みの取得対象と上限。
 * @param[in] acquisition URL非保持の共通取得結果。
 * @return 取得段階だけを表す対象別結果。内容検査または導入の合格を含みません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialPreparationTransferResult automaticDiscoveryTransferResult(
	const NativeError error, const OfficialPreparationTask &task,
	const OfficialAcquisitionResult &acquisition) noexcept
{
	// 戻り値と取得結果の状態・対象・上限が矛盾する成功を拒否する。
	if( error != acquisition.error ||
	   (error == 0 &&
		(acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
		 acquisition.byteCount == 0U || acquisition.byteCount > task.target.maximumBytes ||
		 acquisition.scanSessionId != task.scanSessionId ||
		 acquisition.providerId != task.target.providerId ||
		 acquisition.resourceId != task.target.resourceId || !acquisition.delegatedRecord))) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_UNEXPECTED), 0U} ;
	}

	// 取得成功は内容検査用fileを固定した状態だけとして返す。
	if( error == 0) {
		return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, acquisition.byteCount} ;
	}

	// 正数の失敗値や未開始状態を既知の失敗へ推測変換しない。
	if( error > 0) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_UNEXPECTED), 0U} ;
	}

	// 取得境界の有限状態を準備操作の同じ意味へ変換する。
	switch( acquisition.state) {
		// 制限または不明回線の未許可を再同意可能な待機状態として返す。
		case OfficialAcquisitionState::AWAITING_NETWORK_CONSENT:
			return {OfficialPreparationItemState::AWAITING_NETWORK_CONSENT, error, 0U} ;
		// 協調取消しを実行失敗や拒否へ変換しない。
		case OfficialAcquisitionState::CANCELLED:
			return {OfficialPreparationItemState::CANCELLED, error, 0U} ;
		// 入力、予算、disk、証拠拒否を通常の通信失敗と区別する。
		case OfficialAcquisitionState::REJECTED:
			return {OfficialPreparationItemState::REJECTED, error, 0U} ;
		// NetworkまたはWindows API失敗を取得失敗として返す。
		case OfficialAcquisitionState::FAILURE:
			return {OfficialPreparationItemState::FAILURE, error, 0U} ;
		// 未開始と矛盾する成功状態を内部拒否に固定する。
		default:
			return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_UNEXPECTED),
					0U} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief WUAのsystem query根拠を今回のlocal母数と照合済み候補へ拘束する。
 * @param[in] devices 現在版行から作った重複のないlocal device集合。
 * @param[in] candidates Compositeが検証・統合した全表示候補。
 * @param[in,out] evidence WUAが発行したrecord根拠。成功時だけlocal結合を反映する。
 * @return System query、record、候補の契約が整合し、結合を完了した場合はtrue。
 * @note Hardware IDを受け取らず、Compositeが既に確定したopaque device identityだけを使う。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool bindManagedMeasurementEvidence(
	const std::span<const OfficialCatalogDevice> devices,
	const std::span<const UpdateCandidate>		 candidates,
	ProviderMeasurementEvidence					&evidence) noexcept
{
	// WUA以外のscopeやProvider内で既にlocal結合された根拠を二重に配賦しない。
	if( evidence.providerId != WINDOWS_UPDATE_PROVIDER_ID ||
	   evidence.scope != MeasurementScope::SYSTEM_QUERY || !evidence.eligible.identities.empty() ||
	   !evidence.information.identities.empty()) {
		return false ;
	}

	try {
		std::unordered_set<std::wstring_view> localDevices ;	// Dに属するopaque deviceの索引。
		localDevices.reserve( devices.size()) ;
		evidence.eligible.identities.reserve( devices.size()) ;
		// Current rowから作った同一sessionのDをWUAのsystem query対象へ設定する。
		for( const OfficialCatalogDevice &device : devices) {
			// Dの重複や空identityを計測側で隠して受理しない。
			if( device.deviceIdentity.empty() ||
			   !localDevices.insert( device.deviceIdentity).second) {
				return false ;
			}

			evidence.eligible.identities.push_back( device.deviceIdentity) ;
		}

		evidence.eligible.extent = MeasurementExtent::EXACT ;

		// WUA record IDから統合候補へ対応付ける、同一呼出し中だけ有効な索引。
		std::unordered_map<std::wstring_view, const UpdateCandidate *> managedCandidates ;
		managedCandidates.reserve( evidence.records.size()) ;
		// WUAの非現在版行だけをrecord結合先候補として索引化する。
		for( const UpdateCandidate &candidate : candidates) {
			// 別Providerと現在版行はWUA recordの結合根拠にしない。
			if( candidate.providerId != WINDOWS_UPDATE_PROVIDER_ID || candidate.current) {
				continue ;
			}

			// 同じWUA candidate identityの重複は既存候補契約違反として拒否する。
			if( !managedCandidates.emplace( candidate.identity, &candidate).second) {
				return false ;
			}
		}

		std::unordered_set<std::wstring_view> informationDevices ;	// Rへ一度だけ入れるD内device。
		informationDevices.reserve( evidence.records.size()) ;
		// Providerが識別した各recordを、Compositeが安全に解決したlocal候補へだけ結合する。
		for( MeasurementRecordEvidence &record : evidence.records) {
			// Provider層はlocal identityを知らないため、事前結合済みrecordを受理しない。
			if( !record.deviceIdentities.empty()) {
				return false ;
			}

			const auto candidate = managedCandidates.find( record.identity) ;	// 同じopaque候補ID。
			// WUA scan失敗後に破棄された行、またはlocal未照合行はrecord件数だけを保持する。
			if( candidate == managedCandidates.end() ||
			   !localDevices.contains( candidate->second->deviceIdentity)) {
				continue ;
			}

			record.deviceIdentities.push_back( candidate->second->deviceIdentity) ;
			// 同じdeviceへ複数updateがあっても情報到達deviceは一件にする。
			if( informationDevices.insert( candidate->second->deviceIdentity).second) {
				evidence.information.identities.push_back( candidate->second->deviceIdentity) ;
			}
		}

		// WUA collectionの完了度をrecordと情報到達の両方へ維持する。
		evidence.information.extent = evidence.recordExtent ;
	} catch( ...) {
		// Allocation失敗時は部分的なlocal結合を計測根拠として公開しない。
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief outcome が成功または警告付き成功かを判定する。
 *
 * @param[in] outcome 判定対象。
 * @return 処理を継続できる結果なら `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSuccessOutcome( const OutcomeCode outcome) noexcept
{
	return outcome == OutcomeCode::SUCCESS || outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 複数 Provider の outcome を全体 outcome へ集約する。
 *
 * @param[in] outcomes 実行された Provider の結果。
 * @return 全成功、部分成功、全失敗を表す outcome。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OutcomeCode aggregateOutcomes( const std::span<const OutcomeCode> outcomes) noexcept
{
	std::size_t succeeded{} ;	// 成功または警告付き成功だったprovider数。
	// 各providerの継続可能な結果を数え、全体の成功度を決定する。
	for( const OutcomeCode outcome : outcomes) {
		// 成功と警告付き成功だけを集約上の成功件数へ含める。
		if( isSuccessOutcome( outcome)) {
			++succeeded ;
		}
	}

	// 全件が成功系でも警告を含む場合は全体を警告付き成功として返す。
	if( succeeded == outcomes.size()) {
		return std::any_of( outcomes.begin(), outcomes.end(),
						   []( const OutcomeCode outcome) {
							   return outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
						   })
				   ? OutcomeCode::SUCCEEDED_WITH_ERRORS
				   : OutcomeCode::SUCCESS ;
	}

	return succeeded == 0 ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider が実行前に拒否した selection の結果を作る。
 *
 * @param[in] identities 拒否対象 identity 群。
 * @param[in] error 検証失敗 HRESULT。
 * @return 全 entry を未導入失敗とした結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult makeFailedInstall( const std::span<const std::wstring> identities,
											  const NativeError					  error)
{
	InstallResult result{} ;	// 各identityを同じerrorで拒否するsynthetic結果。
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = error ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = error ;
	result.updates.reserve( identities.size()) ;
	// UIが全選択候補を失敗結果へ対応付けられるようidentityを維持する。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::FAILURE,
								  .downloadError   = error,
								  .installOutcome  = OutcomeCode::FAILURE,
								  .installError	   = error}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stable IDに対応する組み込みProvider定義を取得する。
 *
 * 内部登録漏れはprogramming errorとしてconstructorを失敗させる。
 *
 * @param[in] providerId Registryへ登録済みのstable ID。
 * @return 対応するProvider定義。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ProviderDescriptor descriptorFor( const std::wstring_view providerId)
{
	const std::span descriptors = builtInProviderDescriptors() ;	// 組み込み定義の正本。
	// Stable IDに対応するregistry定義の位置。検索IDは呼出し中だけ借用する。
	const auto		found = std::find_if(
		 descriptors.begin(), descriptors.end(),
		 [providerId]( const ProviderDescriptor &descriptor) { return descriptor.id == providerId ; }) ;
	// stable IDに対応する定義がない内部不整合を既定Providerで補わない。
	if( found == descriptors.end()) {
		throw std::logic_error( "Built-in provider descriptor is missing.") ;
	}

	return *found ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider進捗をaggregate scanの指定範囲へ変換する。
 *
 * 経過時間を推測せず、Providerが確定した値だけを変換する。
 *
 * @param[in] callback Aggregate進捗通知先。
 * @param[in] start Providerへ割り当てる開始percent。
 * @param[in] width Providerへ割り当てるpercent幅。
 * @return Provider進捗を0～100から指定範囲へ変換するcallback。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ProviderProgressCallback scaledProgress( const ProviderProgressCallback &callback,
													  const std::uint32_t			  start,
													  const std::uint32_t			  width)
{
	return [&callback, start, width]( const ProviderProgress &progress) {
		ProviderProgress aggregate = progress ;	// Aggregate全体へ変換する進捗値。
		aggregate.percentComplete =
			start + std::min<std::uint32_t>( progress.percentComplete, 100) * width / 100 ;
		callback( aggregate) ;
	} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Prolific serial用の利用者選択Provider policyを作成する。
 *
 * 署名済みINFの複数版を表示し、自動選択は共通実装で禁止する。
 * @return Prolific固有のstable ID、表示文字列、検証関数の所有値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeProlificProviderPolicy()
{
	return {.providerId						= std::wstring( PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
			.deviceClass					= L"Ports",
			.identityPrefix					= L"prolific-serial-package:",
			.packagePrefix					= L"prolific-serial-inf:",
			.titlePrefix					= L"Prolific Serial Driver ",
			.sourceName						= L"Prolific serial署名済みINF ZIP",
			.sourceLocation					= L"利用者選択local ZIP（端末内で署名・PnP ID検証）",
			.inspect						= inspectProlificSerialPackageFile,
			.reverify						= reverifyProlificSerialInfPackage,
			.hardwareIdAllowed				= isProlificSerialCandidateHardwareId,
			.allowMultiplePackagesPerDevice = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Silicon Labs CP210x用の利用者選択Provider policyを作成する。
 *
 * 審査済みCP210x familyのINFを表示し、自動選択を禁止する。
 * @return CP210x固有のstable ID、表示文字列、検証関数の所有値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeSiliconLabsProviderPolicy()
{
	return {.providerId						= std::wstring( SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID),
			.deviceClass					= L"Ports",
			.identityPrefix					= L"silicon-labs-serial-package:",
			.packagePrefix					= L"silicon-labs-serial-inf:",
			.titlePrefix					= L"Silicon Labs CP210x Serial Driver ",
			.sourceName						= L"Silicon Labs CP210x署名済みINF ZIP",
			.sourceLocation					= L"利用者選択local ZIP（x64 INF・署名・PnP ID検証）",
			.inspect						= inspectSiliconLabsSerialPackageFile,
			.reverify						= reverifySiliconLabsSerialInfPackage,
			.hardwareIdAllowed				= isSiliconLabsSerialCandidateHardwareId,
			.allowMultiplePackagesPerDevice = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH serial用の利用者選択Provider policyを作成する。
 *
 * 署名済みCH341SER INFだけを表示し、自動選択を禁止する。
 * @return WCH固有のstable ID、表示文字列、検証関数の所有値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeWchProviderPolicy()
{
	return {.providerId		   = std::wstring( WCH_SERIAL_PACKAGE_PROVIDER_ID),
			.deviceClass	   = L"Ports",
			.identityPrefix	   = L"wch-serial-package:",
			.packagePrefix	   = L"wch-serial-inf:",
			.titlePrefix	   = L"WCH CH340/CH341 Serial Driver ",
			.sourceName		   = L"WCH CH341SER署名済みINF ZIP",
			.sourceLocation	   = L"利用者選択local ZIP（現行subtree・署名・PnP ID検証）",
			.inspect		   = inspectWchSerialPackageFile,
			.reverify		   = reverifyWchSerialInfPackage,
			.hardwareIdAllowed = isWchSerialCandidateHardwareId,
			.allowMultiplePackagesPerDevice = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH CH342／CH343系の利用者選択Provider policyを作成する。
 *
 * 固定CH343SER 2.2 INFだけを表示し、自動選択を禁止する。
 * @return WCH CH343SER固有のID、表示文字列、検証関数の所有値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeWchMultiProviderPolicy()
{
	return {.providerId		   = std::wstring( WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID),
			.deviceClass	   = L"Ports",
			.identityPrefix	   = L"wch-multi-serial-package:",
			.packagePrefix	   = L"wch-multi-serial-inf:",
			.titlePrefix	   = L"WCH CH342/CH343 Family Serial Driver ",
			.sourceName		   = L"WCH CH343SER署名済みINF ZIP",
			.sourceLocation	   = L"利用者選択local ZIP（固定archive・署名・PnP ID検証）",
			.inspect		   = inspectWchMultiSerialPackageFile,
			.reverify		   = reverifyWchMultiSerialInfPackage,
			.hardwareIdAllowed = isWchMultiSerialCandidateHardwareId,
			.allowMultiplePackagesPerDevice = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 汎用署名済みINFの利用者選択Provider policyを作成する。
 *
 * 検証済みINF自身のclassを現在deviceへ完全一致させ、取得元、PrinterだけはPrintQueueへ一方向照合する。取得元、最新版、OEM推奨は表示上も保証しない。
 * @return 取得元未証明の汎用stable ID、表示文字列、検証関数。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeGenericInfProviderPolicy()
{
	return {.providerId						= std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
			.deviceClass					= {},
			.identityPrefix					= L"generic-signed-inf-package:",
			.packagePrefix					= L"generic-signed-inf:",
			.titlePrefix					= L"署名済みDriver ",
			.sourceName						= L"署名済みINF ZIP",
			.sourceLocation					= L"利用者選択local ZIP（取得元未証明・端末内検証）",
			.inspect						= inspectCommonLocalInfPackageFile,
			.reverify						= reverifyGenericInfPackage,
			.hardwareIdAllowed				= isGenericInfCandidateHardwareId,
			.deviceClassMatches				= isGenericInfDeviceClassMatch,
			.allowMultiplePackagesPerDevice = true,
			.usePackageDeviceClass			= true,
			.useCommonInspection			= true} ;
}

} // namespace

/** @see composite_update_provider.h */
std::unique_ptr<IndexPublicIdResolver> CompositeUpdateProvider::indexScanInventory(
	const OperationId operationId, IndexLookupContext &context, std::vector<std::wstring> &present)
{
	return driverStoreProvider_.makeIndexPublicIdResolver( operationId, context, present) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
CompositeUpdateProvider::CompositeUpdateProvider()
	: asixUpdateProvider_(
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 OfficialDriverRankAudit &audit) {
			  return driverStoreProvider_.auditOfficialInfRank( sessionId, deviceIdentity, workspace,
															   package, audit) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 const std::wstring_view currentProvider, const std::wstring_view currentVersion,
				 const std::wstring_view currentDate, const OfficialDriverRankAudit &rankAudit,
				 OfficialInfInstallBinding &binding) {
			  return driverStoreProvider_.createOfficialInfInstallBinding(
				  sessionId, deviceIdentity, workspace, package, currentProvider, currentVersion,
				  currentDate, rankAudit, binding) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::uint64_t token) noexcept {
			  return driverStoreProvider_.discardOfficialInfInstallBinding( sessionId, token) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 const OfficialInfInstallBinding &binding, const std::uintptr_t parentWindow,
				 bool &rebootRequired) {
			  return driverStoreProvider_.installBoundOfficialInf( sessionId, deviceIdentity,
																  workspace, package, binding,
																  parentWindow, rebootRequired) ;
		  }),
	  broadcomUpdateProvider_(
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 OfficialDriverRankAudit &audit) {
			  return driverStoreProvider_.auditOfficialInfRank( sessionId, deviceIdentity, workspace,
															   package, audit) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const std::wstring_view infPath, const std::wstring_view expectedProvider,
				 const std::wstring_view expectedVersion, const std::uintptr_t parentWindow,
				 bool &rebootRequired) {
			  return driverStoreProvider_.installVerifiedExternalInf(
				  sessionId, deviceIdentity, infPath, expectedProvider, expectedVersion,
				  parentWindow, rebootRequired) ;
		  }),
	  intelEthernetServerOfficialProvider_(
		  OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 OfficialDriverRankAudit &audit) {
			  return driverStoreProvider_.auditOfficialInfRank( sessionId, deviceIdentity, workspace,
															   package, audit) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 const std::wstring_view currentProvider, const std::wstring_view currentVersion,
				 const std::wstring_view currentDate, const OfficialDriverRankAudit &rankAudit,
				 OfficialInfInstallBinding &binding) {
			  return driverStoreProvider_.createOfficialInfInstallBinding(
				  sessionId, deviceIdentity, workspace, package, currentProvider, currentVersion,
				  currentDate, rankAudit, binding) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::uint64_t token) noexcept {
			  return driverStoreProvider_.discardOfficialInfInstallBinding( sessionId, token) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 const OfficialInfInstallBinding &binding, const std::uintptr_t parentWindow,
				 bool &rebootRequired) {
			  return driverStoreProvider_.installBoundOfficialInf( sessionId, deviceIdentity,
																  workspace, package, binding,
																  parentWindow, rebootRequired) ;
		  }),
	  asusUpdateProvider_(
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				 OfficialDriverRankAudit &audit) {
			  return driverStoreProvider_.auditOfficialInfRank( sessionId, deviceIdentity, workspace,
															   package, audit) ;
		  },
		  [this]( const ScanSessionId sessionId, const std::wstring_view deviceIdentity,
				 const std::wstring_view infPath, const std::wstring_view expectedProvider,
				 const std::wstring_view expectedVersion, const std::uintptr_t parentWindow,
				 bool &rebootRequired) {
			  return driverStoreProvider_.installVerifiedExternalInf(
				  sessionId, deviceIdentity, infPath, expectedProvider, expectedVersion,
				  parentWindow, rebootRequired) ;
		  }),
	  genericSignedInfPackageProvider_( makeGenericInfProviderPolicy()),
	  prolificSerialPackageProvider_( makeProlificProviderPolicy()),
	  siliconLabsSerialPackageProvider_( makeSiliconLabsProviderPolicy()),
	  wchSerialPackageProvider_( makeWchProviderPolicy()),
	  wchMultiSerialPackageProvider_( makeWchMultiProviderPolicy())
{
	providerRegistry_.reserve( builtInProviderDescriptors().size()) ;
	// 各instanceの固定契約を使い、scan／installのWindows接続を一か所で登録する。
	for( const auto &[serial, metadataFamily] : std::array{
			std::pair{&prolificOfficialProvider_, OfficialReleaseFamily::PROLIFIC_DCHU},
			std::pair{&siliconLabsOfficialProvider_, OfficialReleaseFamily::SILICON_LABS_CP210X},
			std::pair{&wchOfficialProvider_, OfficialReleaseFamily::WCH_CH341},
			std::pair{&wchMultiOfficialProvider_, OfficialReleaseFamily::WCH_CH343}}) {
		providerRegistry_.push_back(
			{.descriptor = descriptorFor( serial->providerId()),
			 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
			 .scan =
				 [this, serial]( const ScanSessionId sessionId, const ScanOptions &options,
								const std::span<const OfficialCatalogDevice> devices,
								const LocalHardwareIdMatcher				&matcher,
								const ProviderProgressCallback				&progress) {
					 const OfficialSerialRankAuditor
						 auditor =	// 現在inventoryへ閉じたread-only監査。
						 [this]( const ScanSessionId session, const std::wstring_view device,
								const OfficialDownloadWorkspace &workspace,
								const OfficialInfPackage &package, OfficialDriverRankAudit &audit) {
							 return driverStoreProvider_.auditOfficialInfRank(
								 session, device, workspace, package, audit) ;
						 } ;
					 return serial->scan( sessionId, options, devices, matcher, auditor, progress) ;
				 },
			 .install =
				 [this, serial](
					 const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					 const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
					 const LocalHardwareIdMatcher matcher =	// 現在session内だけで許可IDを解決する。
						 [this]( const std::wstring_view id) {
							 return driverStoreProvider_.deviceIdentityForHardwareId( id) ;
						 } ;
					 const OfficialSerialRankAuditor auditor =	// 導入直前のPnP／rank再監査。
						 [this]( const ScanSessionId session, const std::wstring_view device,
								const OfficialDownloadWorkspace &workspace,
								const OfficialInfPackage &package, OfficialDriverRankAudit &audit) {
							 return driverStoreProvider_.auditOfficialInfRank(
								 session, device, workspace, package, audit) ;
						 } ;
					 const VerifiedExternalInfInstaller installer =	// 既存Windows標準導入境界。
						 [this]( const ScanSessionId session, const std::wstring_view device,
								const std::wstring_view inf, const std::wstring_view provider,
								const std::wstring_view version, const std::uintptr_t parent,
								bool &reboot) {
							 return driverStoreProvider_.installVerifiedExternalInf(
								 session, device, inf, provider, version, parent, reboot) ;
						 } ;
					 return serial->install( sessionId, identities, parentWindow, matcher, auditor,
											installer, progress) ;
				 },
			 .measurementEvidence = [serial]() -> const ProviderMeasurementEvidence & {
				 return serial->measurementEvidence() ;
			 },
			 .metadataScan = metadataScanner( metadataFamily)}) ;
	}

	providerRegistry_.push_back(
		{.descriptor = descriptorFor( DRIVER_STORE_PROVIDER_ID),
		 .phase		 = ProviderPhase::INVENTORY,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice>, const LocalHardwareIdMatcher &,
					const ProviderProgressCallback &progress) {
				 return driverStoreProvider_.scan( sessionId, options, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return driverStoreProvider_.install( sessionId, identities, parentWindow, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( WINDOWS_UPDATE_PROVIDER_ID),
		 .phase		 = ProviderPhase::MANAGED_SERVICE,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice>, const LocalHardwareIdMatcher &,
					const ProviderProgressCallback &progress) {
				 return windowsUpdateProvider_.scan( sessionId, options, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return windowsUpdateProvider_.install( sessionId, identities, parentWindow,
													   progress) ;
			 },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return windowsUpdateProvider_.measurementEvidence() ;
		 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( NVIDIA_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return nvidiaUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return nvidiaUpdateProvider_.install( sessionId, identities, parentWindow,
													  progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return intelWirelessPackageProvider_.scan( sessionId, options, devices, matcher,
														   progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 const VerifiedExternalInfInstaller installer =
					 [this]( const ScanSessionId		inventorySessionId,
							const std::wstring_view deviceIdentity, const std::wstring_view infPath,
							const std::wstring_view expectedProvider,
							const std::wstring_view expectedVersion,
							const std::uintptr_t installerParent, bool &rebootRequired) {
						 return driverStoreProvider_.installVerifiedExternalInf(
							 inventorySessionId, deviceIdentity, infPath, expectedProvider,
							 expectedVersion, installerParent, rebootRequired) ;
					 } ; // Worker内だけで検証済みINFを現在inventoryへ接続する関数。
				 return intelWirelessPackageProvider_.install( sessionId, identities, parentWindow,
															  installer, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return prolificSerialPackageProvider_.scan( sessionId, options, devices, matcher,
															progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 const VerifiedExternalInfInstaller installer =
					 [this]( const ScanSessionId		inventorySessionId,
							const std::wstring_view deviceIdentity, const std::wstring_view infPath,
							const std::wstring_view expectedProvider,
							const std::wstring_view expectedVersion,
							const std::uintptr_t installerParent, bool &rebootRequired) {
						 return driverStoreProvider_.installVerifiedExternalInf(
							 inventorySessionId, deviceIdentity, infPath, expectedProvider,
							 expectedVersion, installerParent, rebootRequired) ;
					 } ; // 検証済みProlific INFを現在inventoryへ接続する関数。
				 return prolificSerialPackageProvider_.install( sessionId, identities, parentWindow,
															   installer, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return siliconLabsSerialPackageProvider_.scan( sessionId, options, devices, matcher,
															   progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 const VerifiedExternalInfInstaller installer =
					 [this]( const ScanSessionId		inventorySessionId,
							const std::wstring_view deviceIdentity, const std::wstring_view infPath,
							const std::wstring_view expectedProvider,
							const std::wstring_view expectedVersion,
							const std::uintptr_t installerParent, bool &rebootRequired) {
						 return driverStoreProvider_.installVerifiedExternalInf(
							 inventorySessionId, deviceIdentity, infPath, expectedProvider,
							 expectedVersion, installerParent, rebootRequired) ;
					 } ; // 検証済みCP210x INFを現在inventoryへ接続する関数。
				 return siliconLabsSerialPackageProvider_.install(
					 sessionId, identities, parentWindow, installer, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( WCH_SERIAL_PACKAGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return wchSerialPackageProvider_.scan( sessionId, options, devices, matcher,
													   progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 const VerifiedExternalInfInstaller installer =
					 [this]( const ScanSessionId		inventorySessionId,
							const std::wstring_view deviceIdentity, const std::wstring_view infPath,
							const std::wstring_view expectedProvider,
							const std::wstring_view expectedVersion,
							const std::uintptr_t installerParent, bool &rebootRequired) {
						 return driverStoreProvider_.installVerifiedExternalInf(
							 inventorySessionId, deviceIdentity, infPath, expectedProvider,
							 expectedVersion, installerParent, rebootRequired) ;
					 } ; // 検証済みWCH INFを現在inventoryへ接続する関数。
				 return wchSerialPackageProvider_.install( sessionId, identities, parentWindow,
														  installer, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return wchMultiSerialPackageProvider_.scan( sessionId, options, devices, matcher,
															progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 const VerifiedExternalInfInstaller installer =
					 [this]( const ScanSessionId		inventorySessionId,
							const std::wstring_view deviceIdentity, const std::wstring_view infPath,
							const std::wstring_view expectedProvider,
							const std::wstring_view expectedVersion,
							const std::uintptr_t installerParent, bool &rebootRequired) {
						 return driverStoreProvider_.installVerifiedExternalInf(
							 inventorySessionId, deviceIdentity, infPath, expectedProvider,
							 expectedVersion, installerParent, rebootRequired) ;
					 } ; // 検証済みWCH CH343SER INFを現在inventoryへ接続する関数。
				 return wchMultiSerialPackageProvider_.install( sessionId, identities, parentWindow,
															   installer, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId sessionId, const ScanOptions &options,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 const CommonInfRankObserver observer =
					 [this]( const ScanSessionId session, const std::wstring_view device,
							const OfficialDownloadWorkspace &workspace,
							const OfficialInfPackage &package, std::optional<std::uint32_t> &rank) {
						 return driverStoreProvider_.observeInfCandidateRank(
							 session, device, workspace, package, rank) ;
					 } ; // Composite所有期間内のDriver Storeを同じworkerで借用する。
				 return genericSignedInfPackageProvider_.scan( sessionId, options, devices, matcher,
															  progress, observer) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 const VerifiedExternalInfInstaller installer =
					 [this]( const ScanSessionId		inventorySessionId,
							const std::wstring_view deviceIdentity, const std::wstring_view infPath,
							const std::wstring_view expectedProvider,
							const std::wstring_view expectedVersion,
							const std::uintptr_t installerParent, bool &rebootRequired) {
						 return driverStoreProvider_.installVerifiedExternalInf(
							 inventorySessionId, deviceIdentity, infPath, expectedProvider,
							 expectedVersion, installerParent, rebootRequired) ;
					 } ; // 取得元未証明でも全検証済みのINFだけを現在inventoryへ接続する関数。
				 return genericSignedInfPackageProvider_.install( sessionId, identities,
																 parentWindow, installer, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( DELL_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return dellUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return dellUpdateProvider_.install( sessionId, identities, parentWindow, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( DELL_POWER_EDGE_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return dellServerUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return dellServerUpdateProvider_.install( sessionId, identities, parentWindow,
														  progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( LENOVO_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return lenovoUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return lenovoUpdateProvider_.install( sessionId, identities, parentWindow,
													  progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( HP_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return hpUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return hpUpdateProvider_.install( sessionId, identities, parentWindow, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( VAIO_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return vaioUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return vaioUpdateProvider_.install( sessionId, identities, parentWindow, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( AMD_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return amdUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return amdUpdateProvider_.install( sessionId, identities, parentWindow, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( ASUS_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return asusUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return asusUpdateProvider_.install( sessionId, identities, parentWindow, progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( ASROCK_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return asrockUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return asrockUpdateProvider_.install( sessionId, identities, parentWindow,
													  progress) ;
			 }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( BROADCOM_NET_XTREME_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return broadcomUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return broadcomUpdateProvider_.install( sessionId, identities, parentWindow,
														progress) ;
			 },
		 .preparationTargets =
			 [this]( const ScanSessionId sessionId, const std::uint64_t planId) {
				 return broadcomUpdateProvider_.preparationTargets( sessionId, planId) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { broadcomUpdateProvider_.invalidatePreparation() ; },
		 .acquireForInspection =
			 [this]( const OfficialPreparationTask &task,
					const PreparationCancellation &cancellation) {
				 return broadcomUpdateProvider_.acquireForInspection( task, cancellation) ;
			 },
		 .preparationAuditReport =
			 [this]( const ScanSessionId session, const std::wstring_view target) {
				 return broadcomUpdateProvider_.preparationAuditReport( session, target) ;
			 },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 broadcomUpdateProvider_.configureReleaseObservationContext( previous, environment) ;
			 },
		 .releaseObservations =
			 [this]() { return broadcomUpdateProvider_.releaseObservations() ; }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( INTEL_WIFI_OFFICIAL_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return intelWifiOfficialProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return intelWifiOfficialProvider_.install( sessionId, identities, parentWindow,
														   progress) ;
			 },
		 .preparationTargets =
			 [this]( const ScanSessionId sessionId, const std::uint64_t planId) {
				 return intelWifiOfficialProvider_.preparationTargets( sessionId, planId) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { intelWifiOfficialProvider_.invalidatePreparation() ; },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 intelWifiOfficialProvider_.configureReleaseObservationContext( previous,
																			   environment) ;
			 },
		 .releaseObservations =
			 [this]() { return intelWifiOfficialProvider_.releaseObservations() ; },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return intelWifiOfficialProvider_.measurementEvidence() ;
		 },
		 .metadataScan = metadataScanner( OfficialReleaseFamily::INTEL_WIFI)}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return intelEthernetServerOfficialProvider_.scan( sessionId, devices, matcher,
																  progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return intelEthernetServerOfficialProvider_.install( sessionId, identities,
																	 parentWindow, progress) ;
			 },
		 .preparationTargets =
			 [this]( const ScanSessionId sessionId, const std::uint64_t planId) {
				 return intelEthernetServerOfficialProvider_.preparationTargets( sessionId, planId) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { intelEthernetServerOfficialProvider_.invalidatePreparation() ; },
		 .acquireForInspection =
			 [this]( const OfficialPreparationTask &task,
					const PreparationCancellation &cancellation) {
				 return intelEthernetServerOfficialProvider_.acquireForInspection( task,
																				  cancellation) ;
			 },
		 .preparationAuditReport =
			 [this]( const ScanSessionId session, const std::wstring_view target) {
				 return intelEthernetServerOfficialProvider_.preparationAuditReport( session,
																					target) ;
			 },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 intelEthernetServerOfficialProvider_.configureReleaseObservationContext(
					 previous, environment) ;
			 },
		 .releaseObservations =
			 [this]() { return intelEthernetServerOfficialProvider_.releaseObservations() ; },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return intelEthernetServerOfficialProvider_.measurementEvidence() ;
		 },
		 .metadataScan = metadataScanner( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025)}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return intelEthernetWindows11OfficialProvider_.scan( sessionId, devices, matcher,
																	 progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return intelEthernetWindows11OfficialProvider_.install( sessionId, identities,
																		parentWindow, progress) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { intelEthernetWindows11OfficialProvider_.invalidatePreparation() ; },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 intelEthernetWindows11OfficialProvider_.configureReleaseObservationContext(
					 previous, environment) ;
			 },
		 .releaseObservations =
			 [this]() { return intelEthernetWindows11OfficialProvider_.releaseObservations() ; },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return intelEthernetWindows11OfficialProvider_.measurementEvidence() ;
		 },
		 .metadataScan = metadataScanner( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11)}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( ASIX_AX88179A_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return asixUpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return asixUpdateProvider_.install( sessionId, identities, parentWindow, progress) ;
			 },
		 .preparationTargets =
			 [this]( const ScanSessionId session, const std::uint64_t plan) {
				 return asixUpdateProvider_.preparationTargets( session, plan) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { asixUpdateProvider_.invalidateScanSession() ; },
		 .acquireForInspection =
			 [this]( const OfficialPreparationTask &task,
					const PreparationCancellation &cancellation) {
				 return asixUpdateProvider_.acquireForInspection( task, cancellation) ;
			 },
		 .preparationAuditReport =
			 [this]( const ScanSessionId session, const std::wstring_view target) {
				 return asixUpdateProvider_.preparationAuditReport( session, target) ;
			 },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 asixUpdateProvider_.configureReleaseObservationContext( previous, environment) ;
			 },
		 .releaseObservations = [this]() { return asixUpdateProvider_.releaseObservations() ; }}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( RICOH_UNIVERSAL_PRINT_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return ricohUniversalPrintProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return ricohUniversalPrintProvider_.install( sessionId, identities, parentWindow,
															 progress) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { ricohUniversalPrintProvider_.invalidatePreparation() ; },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 ricohUniversalPrintProvider_.configureReleaseObservationContext( previous,
																				 environment) ;
			 },
		 .releaseObservations =
			 [this]() { return ricohUniversalPrintProvider_.releaseObservations() ; },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return ricohUniversalPrintProvider_.measurementEvidence() ;
		 },
		 .metadataScan = metadataScanner( OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6)}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( WACOM_WINDOWS_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return wacomWindowsProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return wacomWindowsProvider_.install( sessionId, identities, parentWindow,
													  progress) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { wacomWindowsProvider_.invalidatePreparation() ; },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 wacomWindowsProvider_.configureReleaseObservationContext( previous, environment) ;
			 },
		 .releaseObservations = [this]() { return wacomWindowsProvider_.releaseObservations() ; },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return wacomWindowsProvider_.measurementEvidence() ;
		 },
		 .metadataScan = metadataScanner( OfficialReleaseFamily::WACOM_WINDOWS_TABLET)}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( FOCUSRITE_SCARLETT2I2_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return focusriteScarlett2i2Provider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return focusriteScarlett2i2Provider_.install( sessionId, identities, parentWindow,
															  progress) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { focusriteScarlett2i2Provider_.invalidatePreparation() ; },
		 .configureReleaseObservations =
			 [this]( const std::span<const LocalOfficialReleaseObservation> previous,
					const OfficialReleaseEnvironmentFingerprints		  &environment) {
				 focusriteScarlett2i2Provider_.configureReleaseObservationContext( previous,
																				  environment) ;
			 },
		 .releaseObservations =
			 [this]() { return focusriteScarlett2i2Provider_.releaseObservations() ; },
		 .measurementEvidence = [this]() -> const ProviderMeasurementEvidence & {
			 return focusriteScarlett2i2Provider_.measurementEvidence() ;
		 },
		 .metadataScan = metadataScanner( OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN)}) ;
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( NVIDIA_WINOF2_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId							 sessionId, const ScanOptions &,
					const std::span<const OfficialCatalogDevice> devices,
					const LocalHardwareIdMatcher				&matcher,
					const ProviderProgressCallback				&progress) {
				 return nvidiaWinof2UpdateProvider_.scan( sessionId, devices, matcher, progress) ;
			 },
		 .install =
			 [this]( const ScanSessionId sessionId, const std::span<const std::wstring> identities,
					const std::uintptr_t parentWindow, const ProviderProgressCallback &progress) {
				 return nvidiaWinof2UpdateProvider_.install( sessionId, identities, parentWindow,
															progress) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept { nvidiaWinof2UpdateProvider_.invalidateScanSession() ; }}) ;

	// 同じcanonical索引entryへscan・監査・指定導入を全て結合します。
	providerRegistry_.push_back(
		{.descriptor = descriptorFor( SIGNED_INDEX_PROVIDER_ID),
		 .phase		 = ProviderPhase::OFFICIAL_CATALOG,
		 .scan =
			 [this]( const ScanSessionId session, const ScanOptions &,
					std::span<const OfficialCatalogDevice>, const LocalHardwareIdMatcher &,
					const ProviderProgressCallback &) {
				 ScanResult result{
					 .succeeded		= true,
					 .scanSessionId = session,
					 .outcome = OutcomeCode::SUCCESS} ;	// 認証不能は索引summaryへ独立保持します。
				 // Worker借用がない直接呼出しから索引能力を作りません。
				 if( signedIndexSession_ && signedIndexServices_) {
					 signedIndexSummary_ =
						 signedIndexSession_->scan( *this, signedIndexOperation_, session,
												   *signedIndexServices_, signedIndexCancellation_) ;
				 }

				 return result ;
			 },
		 .install =
			 [this]( const ScanSessionId session, std::span<const std::wstring> ids,
					std::uintptr_t parent, const ProviderProgressCallback &progress) {
				 // 借用sessionと実private routeが生存する場合だけ実executorへ渡します。
				 if( !signedIndexSession_ || !signedIndexServices_) {
					 return InstallResult{.installOutcome = OutcomeCode::FAILURE,
										  .installError = static_cast<NativeError>( E_ACCESSDENIED)} ;
				 }

				 return signedIndexSession_->binding_.executeBoundInstall(
					 *signedIndexSession_, driverStoreProvider_, *signedIndexServices_, session,
					 ids, parent, progress) ;
			 },
		 .invalidatePreparation =
			 [this]() noexcept {
				 // 新scan・terminalはconsumed read-only proofまで全失効します。
				 if( signedIndexSession_) {
					 signedIndexSession_->invalidate() ;
				 }
			 },
		 .preparationAuditReport =
			 [this]( ScanSessionId session, std::wstring_view target) {
				 // 同workerの私有元取得recordだけを監査し、公開DTOを権限にしません。
				 if( !signedIndexSession_ || !signedIndexServices_ || session != scanSessionId_) {
					 return std::optional<OfficialPreparationAuditReport>{} ;
				 }

				 return signedIndexSession_->binding_.auditPreparedRecord(
					 *signedIndexSession_, driverStoreProvider_, *signedIndexServices_, target,
					 displayedCandidates_) ;
			 }}) ;

	const OfficialDiscoveryFixedRootResolver intelWindows11Resolver =
		[this]( const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
			   const std::wstring_view providerId, const std::wstring_view rootResourceId,
			   const std::wstring_view builtInRootUrl, const std::uint64_t maximumRecordBytes,
			   const OfficialRecordFetchMode fetchMode, OfficialDistributionRecord &record) {
			return resolveIntelEthernetWindows11OfficialDiscoveryRecord(
				scanSessionId, recordEvidenceId, providerId, rootResourceId, builtInRootUrl,
				maximumRecordBytes, fetchMode, officialDiscoveryHttpClient_, record) ;
		} ; // Composite所有HTTP clientを固定Intel resolverへ結合するworker内callback。
	const OfficialRecordResolutionCancellation automaticDiscoveryCancellation = [this]() noexcept {
		// 通常scanの同期実行期間外は取消し権限を推測しない。
		if( !officialDiscoveryCancellation_) {
			return false ;
		}

		try {
			return officialDiscoveryCancellation_() ;
		} catch( ...) {
			// 取消し照会の契約違反時はnetwork継続をfail-closedで拒否する。
			return true ;
		}
	} ; // Compositeが所有する操作限定照会への安定callback。
	const auto registrations = makeBuiltInOfficialDiscoveryRegistrations(
		officialDiscoveryRecordSession_, intelWindows11Resolver, automaticDiscoveryCancellation,
		// Provider正本へ照合済みの自動探索registration。
		builtInProviderDescriptors()) ;
	// 内部契約が一件でも不整合なら自動探索だけを未接続にして通常scan動作を維持する。
	if( registrations) {
		officialDiscoveryRegistrations_ = *registrations ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void CompositeUpdateProvider::prepareLocalReleaseObservationContext(
	const std::span<OfficialCatalogDevice> devices)
{
	reusableReleaseObservations_.clear() ;
	releaseEnvironmentFingerprints_ = {} ;
	// 空または上限外inventoryではfingerprintを作らず、過去観測を変更しない。
	if( devices.empty() || devices.size() > 4'096U) {
		return ;
	}

	LocalOfficialBindingSecret secret{} ;				// 本関数終了時に消去する端末固有HMAC key。
	bool					   secretRegenerated{} ;	// Key不在または破損による再生成状態。
	NativeError				   error = releaseObservationStore_.loadOrCreateBindingSecret(
		   secret, secretRegenerated) ;	// 保護state読取りまたは生成結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = driverStoreProvider_.attachLocalOfficialBindingFingerprints(
			secret, devices) ;	// Native IDを外へ出さないbinding付与結果。
	}

	std::vector<std::wstring> deviceBindings ;	// Device構成hashへ渡す不可逆fingerprint集合。
	// device binding付与が成功した場合にだけOSと構成の環境fingerprintを作る。
	if( error == 0) {
		deviceBindings.reserve( devices.size()) ;
		// 付与済みfingerprintだけを現在device構成へ集約する。
		for( const OfficialCatalogDevice &device : devices) {
			deviceBindings.push_back( device.localBindingFingerprint) ;
		}

		error = makeLocalOfficialEnvironmentFingerprints(
			isWindowsServer(), currentWindowsBuildNumber(), currentWindowsProductSku(),
			deviceBindings, releaseEnvironmentFingerprints_) ;	// OSとdevice集合の失効条件。
	}

	SecureZeroMemory( secret.data(), secret.size()) ;
	// 環境fingerprintが確定しなければ部分bindingを全deviceから除く。
	if( error != 0) {
		// 部分的なbindingをProviderへ渡さず、X6-04の再利用をfail-closedで止める。
		for( OfficialCatalogDevice &device : devices) {
			device.localBindingFingerprint.clear() ;
		}

		releaseEnvironmentFingerprints_ = {} ;
		return ;
	}

	// secretを再生成した場合は旧HMACを比較に使わず観測snapshotを失効させる。
	if( secretRegenerated) {
		// 新keyでは過去HMACを照合できないため、観測snapshotを明示的に失効させる。
		releaseObservationStore_.discard() ;
		releaseObservationStore_.discardDiscoveryCache() ;
		return ;
	}

	ReleaseObservationStoreResult stored ;	// 保護stateから読み取る前回観測集合。
	error = releaseObservationStore_.load( stored) ;
	// 保存観測を正常に読み出せなければ過去差分の再利用を行わない。
	if( error != 0 || stored.state != ReleaseObservationStoreState::LOADED) {
		return ;
	}

	std::vector<LocalOfficialReleaseObservation> retained ;	// 現在環境へ一致する観測集合。
	retained.reserve( stored.observations.size()) ;
	// OSまたはdevice構成が変わった観測をProvider差分確認へ渡さない。
	for( LocalOfficialReleaseObservation &observation : stored.observations) {
		// 現在のOSとdevice構成の両fingerprintが一致する観測だけを再利用する。
		if( observation.environment.operatingSystemFingerprint ==
			   releaseEnvironmentFingerprints_.operatingSystem &&
		   observation.environment.deviceConfigurationFingerprint ==
			   releaseEnvironmentFingerprints_.deviceConfiguration) {
			retained.push_back( std::move( observation)) ;
		}
	}

	// 永続化失敗時はmemory上だけを現在扱いとして使用しない。
	if( retained.size() != stored.observations.size() &&
	   releaseObservationStore_.store( retained) != 0) {
		return ;
	}

	reusableReleaseObservations_ = std::move( retained) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult CompositeUpdateProvider::scanMetadataOnly(
	const ScanSessionId scanSessionId, const MetadataSearchRequest &request,
	MetadataSearchExecutionContext &execution, const ProviderProgressCallback &progressCallback)
{
	invalidateScanSession() ;
	scanPurpose_ = ScanPurpose::METADATA_ONLY ;
	std::vector<MetadataSearchRegistration> registrations ;	// 正本registryからだけ作る借用snapshot。
	registrations.reserve( providerRegistry_.size()) ;
	// 既定有効集合を流用せず、各登録の専用callbackだけを実行境界へ渡す。
	for( const RegisteredProvider &provider : providerRegistry_) {
		registrations.push_back( {provider.descriptor, provider.metadataScan}) ;
	}

	ScanMeasurementContext context ;	// Worker内で固定する実行開始条件。
	context.scanSessionId	  = scanSessionId ;
	context.startedUtcSeconds = currentUtcSeconds() ;
	context.osKind	 = isWindowsServer() ? MeasurementOsKind::SERVER : MeasurementOsKind::CLIENT ;
	const auto build = currentWindowsBuildNumber() ;	// 判定不能は0であり対応とみなさない。
	// 未取得のbuildを有効なOS測定値にしない。
	if( build != 0U) {
		context.osBuild = build ;
	}

	// Driver Storeの現在属性だけの入口を借用し、通常scanとnative matcherを渡さない。
	const MetadataInventoryScan inventory = [this]( const ScanSessionId			   session,
												   MetadataSearchExecutionContext &budget,
												   const ProviderProgressCallback &progress,
												   DeviceInventoryMeasurement	  &measurement) {
		// 現在属性だけを所有し、同じ呼出し地点の列挙根拠を後で取り出す。
		ScanResult result = driverStoreProvider_.scanCurrentInventory( session, budget, progress) ;
		measurement		  = driverStoreProvider_.inventoryMeasurement() ;
		return result ;
	} ;
	return runMetadataSearch( scanSessionId, request, execution, registrations, inventory,
							 std::move( context), progressCallback) ;
}

/** @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。 */
ScanResult CompositeUpdateProvider::scan( const ScanSessionId			 scanSessionId,
										 const ScanOptions				&options,
										 const ProviderProgressCallback &progressCallback)
{
	return scanWithCancellation( scanSessionId, options, {}, progressCallback) ;
}

/** @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。 */
const OfficialDiscoverySummary *CompositeUpdateProvider::officialDiscoverySummary() const noexcept
{
	return officialDiscoverySummary_ ? &*officialDiscoverySummary_ : nullptr ;
}

/** @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。 */
ScanResult CompositeUpdateProvider::scanWithCancellation(
	const ScanSessionId scanSessionId, const ScanOptions &options,
	const ProviderScanCancellation &cancellation, const ProviderProgressCallback &progressCallback)
{
	const std::optional<std::uint64_t> scanStartedUtcSeconds =
		// Provider処理前に固定したscan開始UTC。
		currentUtcSeconds() ;
	invalidateScanSession() ;
	// 今回の同期scanだけの借用照会。
	officialDiscoveryCancellation_ = cancellation ;
	ScanResult result{} ;	// 全Providerの候補、状態、警告を統合するscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// 未発行sessionと矛盾したProvider設定は統合scan開始前に拒否する。
	if( scanSessionId == 0 || !validateScanOptions( options)) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// 開始前取消しではdevice、WUA、公式Providerのどれも呼び出さない。
	if( isStandardScanCancellationRequested( cancellation)) {
		return makeCancelledStandardScan( scanSessionId) ;
	}

	/** @brief 同scan中のregistry借用とProvider固有の所有結果を結合します。 */
	struct ProviderOutput {
		/// 元registryの非所有entryです。同scan中はregistry集合を変更しません。
		RegisteredProvider *registration{} ;
		/// 当該Providerから受け取った所有scan結果です。成功を補完しません。
		ScanResult			scanResult ;
	} ;
	std::vector<ProviderOutput> outputs ;	// Registry順のscan結果集合。
	outputs.reserve( providerRegistry_.size()) ;
	// Registry全entryの今回scanにおける有効状態を、利用者設定から先に固定する。
	for( RegisteredProvider &provider : providerRegistry_) {
		provider.enabledForSession = isProviderEnabled( options, provider.descriptor) ;
	}

	RegisteredProvider *inventoryProvider{} ;	// Device inventoryを構築する必須entry。
	// Registry順に一つだけ存在する必須Inventory Providerを検索する。
	for( RegisteredProvider &provider : providerRegistry_) {
		// registryでinventory段階と定義されたProviderをlocal列挙の起点にする。
		if( provider.phase == ProviderPhase::INVENTORY) {
			inventoryProvider = &provider ;
			break ;
		}
	}

	// inventory Provider欠落の内部不整合では公式検索を始めない。
	if( inventoryProvider == nullptr) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return result ;
	}

	const LocalHardwareIdMatcher emptyMatcher ;	// Inventory/managed scanでは未使用のmatcher。
	// Inventory段階のdevice・local候補・診断を所有するscan結果。
	ScanResult inventoryResult = inventoryProvider->scan( scanSessionId, options, {}, emptyMatcher,
														 scaledProgress( progressCallback, 0, 35)) ;
	// 同期device列挙の安全な終端後に取消しを確認し、後続networkへ進まない。
	if( isStandardScanCancellationRequested( cancellation)) {
		invalidateScanSession() ;
		return makeCancelledStandardScan( scanSessionId) ;
	}

	std::vector<OfficialCatalogDevice> officialDevices ;	// 公式catalog用の非機密snapshot。
	// 異なるsessionや代表行重複を公式照合対象へ昇格せず、network開始前に拒否する。
	if( !isCandidateDetailsSetValid( inventoryResult.candidates, scanSessionId)) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	std::unordered_set<std::wstring> officialDeviceIdentities ;	// Device重複排除集合。
	officialDevices.reserve( inventoryResult.candidates.size()) ;
	// 現在版行だけをnative identifierを含まない公式catalog用snapshotへ変換する。
	for( const UpdateCandidate &candidate : inventoryResult.candidates) {
		// 現在行以外と重複deviceを公式Provider向けの対象集合へ含めない。
		if( !candidate.current ||
		   !officialDeviceIdentities.insert( candidate.deviceIdentity).second) {
			continue ;
		}

		officialDevices.push_back( {.deviceIdentity	  = candidate.deviceIdentity,
								   .model			  = candidate.model,
								   .manufacturer	  = candidate.manufacturer,
								   .driverClass		  = candidate.driverClass,
								   .deviceClassGuid	  = candidate.deviceClassGuid,
								   .currentProvider	  = candidate.provider,
								   .currentVersion	  = candidate.version,
								   .currentDate		  = candidate.driverDate,
								   .deviceObservation = candidate.deviceObservation,
								   .discoveryBus	  = candidate.discoveryBus}) ;
	}

	// 完全fixtureでは端末固有keyや保護stateを作成・変更しません。
	if( !driver_store_inf_detail::fixtureActive()) {
		prepareLocalReleaseObservationContext( officialDevices) ;
	}

	// 完全なpresent inventoryだけをCore検証済みのraw ID非保持hintへ変換する。
	const auto discoveryHints = makeOfficialDiscoveryDeviceHints(
		scanSessionId, driverStoreProvider_.inventoryMeasurement().detailedEnumerationComplete,
		officialDevices) ;	// 一件でも不正なら部分snapshotを返さない変換結果。
	officialDiscoveryHints_ = discoveryHints.value_or( std::vector<OfficialDiscoveryDeviceHint>{}) ;
	outputs.push_back( {inventoryProvider, std::move( inventoryResult)}) ;

	// Managed serviceは現在一つだがregistry経由で実行し、無効時は通信しない。
	for( RegisteredProvider &provider : providerRegistry_) {
		// 管理service段階以外のProviderをWUA検索の段階では実行しない。
		if( provider.phase != ProviderPhase::MANAGED_SERVICE) {
			continue ;
		}

		ScanResult providerResult{} ;	// Managed service固有のscan結果。
		providerResult.scanSessionId = scanSessionId ;
		// 有効な管理service Providerだけを呼び、成功時にだけ全present deviceを判定済みと数える。
		if( provider.enabledForSession) {
			providerResult = provider.scan( scanSessionId, options, officialDevices, emptyMatcher,
										   scaledProgress( progressCallback, 35, 30)) ;
			providerResult.coverage.eligibleDeviceCount = officialDevices.size() ;
			// System全体のWUA適用性queryが成立した場合だけ全present deviceを判定済みと数える。
			providerResult.coverage.assessedDeviceCount =
				providerResult.succeeded ? officialDevices.size() : 0 ;
		} else {
			providerResult.succeeded = true ;
			providerResult.outcome	 = OutcomeCode::SUCCESS ;
			providerResult.state	 = ProviderScanState::DISABLED ;
			progressCallback(
				{.stage = ProviderStage::SEARCHING_WINDOWS_UPDATE, .percentComplete = 65}) ;
		}

		outputs.push_back( {&provider, std::move( providerResult)}) ;
		// WUA等の同期Providerが戻った安全地点で取消しを反映する。
		if( isStandardScanCancellationRequested( cancellation)) {
			invalidateScanSession() ;
			return makeCancelledStandardScan( scanSessionId) ;
		}
	}

	// Catalog側IDをworker内だけでopaque deviceへ解決する関数。所有Providerの寿命内だけ使用する。
	const LocalHardwareIdMatcher hardwareIdMatcher = [this]( const std::wstring_view hardwareId) {
		return driverStoreProvider_.deviceIdentityForHardwareId( hardwareId) ;
	} ;
	// 今回のsessionで有効な公式Provider数。公式scan区間の進捗配分に使用する。
	const std::size_t enabledOfficialCount = static_cast<std::size_t>( std::count_if(
		providerRegistry_.begin(), providerRegistry_.end(), []( const RegisteredProvider &provider) {
			return provider.phase == ProviderPhase::OFFICIAL_CATALOG && provider.enabledForSession ;
		})) ;
	std::unordered_map<std::wstring, ScanResult>
			   automaticDiscoveryResults ;		// 共通executorから各自動探索Providerへ戻す結果。
	bool	   automaticDiscoveryExecuted{} ;	// 複数登録があっても共通planを一度だけ実行する。
	const auto executeAutomaticDiscovery = [this, scanSessionId, &options, &discoveryHints,
											&automaticDiscoveryResults]() {
		auto assignControlResult = [this, scanSessionId, &automaticDiscoveryResults](
									   const ProviderScanState state, const NativeError error = 0) {
			// 今回有効な自動探索Provider全件へ同じ事前停止理由を一度だけ設定する。
			for( const RegisteredProvider &registered : providerRegistry_) {
				// 別段階、無効または従来Providerへ共通結果を作らない。
				if( registered.phase != ProviderPhase::OFFICIAL_CATALOG ||
				   !registered.enabledForSession ||
				   !isAutomaticDiscoveryDescriptor( registered.descriptor)) {
					continue ;
				}

				automaticDiscoveryResults.insert_or_assign(
					registered.descriptor.id,
					makeAutomaticDiscoveryControlResult( scanSessionId, state, error)) ;
			}
		} ; // 共通入口のfail-closed結果をProvider別に複製する端末内callback。

		// 一scan承認なしではlocal matcherやHTTPを実行せず、通信未許可を明示する。
		if( !options.officialDiscoveryApproval) {
			assignControlResult( ProviderScanState::NETWORK_NOT_APPROVED) ;
			return ;
		}

		// 不完全inventoryまたはhint変換拒否から部分routeを作らない。
		if( !discoveryHints.has_value()) {
			assignControlResult( ProviderScanState::FAILURE, static_cast<NativeError>( E_INVALIDARG)) ;
			return ;
		}

		// Present deviceが0件なら通信せず、Provider対象外として正常終了する。
		if( discoveryHints->empty()) {
			assignControlResult( ProviderScanState::NOT_APPLICABLE) ;
			return ;
		}

		const std::span descriptors = builtInProviderDescriptors() ;	// Provider registry正本。
		// UIが表示した承認snapshotから権限を拡張せず構築する通常scan要求。
		const auto		request = makeStandardOfficialDiscoveryRequest( options, descriptors) ;
		// 承認snapshotと自動探索Provider集合の不整合では通信しない。
		if( !request) {
			assignControlResult( ProviderScanState::FAILURE, static_cast<NativeError>( E_INVALIDARG)) ;
			return ;
		}

		// Inventory世代の上限後に0へwrapして古いbindingを再使用しない。
		if( latestOfficialDiscoveryInventoryGeneration_ ==
		   std::numeric_limits<std::uint64_t>::max()) {
			assignControlResult( ProviderScanState::FAILURE, static_cast<NativeError>( E_UNEXPECTED)) ;
			return ;
		}

		const OfficialDiscoveryBinding binding{
			.operationId		 = options.officialDiscoveryApproval->operationId,
			.scanSessionId		 = scanSessionId,
			.inventoryGeneration = ++latestOfficialDiscoveryInventoryGeneration_} ;	// 今回binding。
		const auto plan = makeOfficialDiscoveryRoutePlan(
			binding, *request, true, *discoveryHints, officialDiscoveryRegistrations_,
			descriptors) ;	// Resolverをまだ呼ばない固定root計画。
		// Registry、hintまたはroute上限の不整合を部分実行へ縮退させない。
		if( !plan) {
			assignControlResult( ProviderScanState::FAILURE, static_cast<NativeError>( E_UNEXPECTED)) ;
			return ;
		}

		const auto signedNowUtcSeconds = std::chrono::duration_cast<std::chrono::seconds>(
											 std::chrono::system_clock::now().time_since_epoch())
											 .count() ;	// Cache期限へ使用するUnix UTC秒。
		const std::uint64_t		  nowUtcSeconds = signedNowUtcSeconds > 0
													  ? static_cast<std::uint64_t>( signedNowUtcSeconds)
													  : 0U ;	// 検証済み時刻。
		DiscoveryCacheStoreResult storedCache ;					// 保護storeからのURL非保持entry集合。
		const bool				  cacheEnvironmentReady =
			nowUtcSeconds != 0U && !releaseEnvironmentFingerprints_.operatingSystem.empty() &&
			!releaseEnvironmentFingerprints_.deviceConfiguration
				 .empty() ;	// 全失効条件が計算済みならtrue。
		const NativeError cacheLoadError =
			cacheEnvironmentReady
				? releaseObservationStore_.loadDiscoveryCache( storedCache)
				: static_cast<NativeError>( E_UNEXPECTED) ;	// 読取りまたは利用不可診断。
		const bool cacheStoreUsable =
			// Missing／invalidatedも新しいsnapshotを保存できる状態です。
			cacheLoadError == 0 ;
		std::vector<OfficialDiscoveryCacheEntry> storedCacheEntries =
			cacheLoadError == 0 && storedCache.state == DiscoveryCacheStoreState::LOADED
				? std::move( storedCache.entries)
				: std::vector<
					  OfficialDiscoveryCacheEntry>{} ;	// 読取り失敗時はcacheを正本にしない空集合。
		std::unordered_map<std::uint64_t, OfficialDiscoveryCacheEntry>
			cachedPositiveEntriesByRoute ;	// 表示だけへ使うroute別fresh positive copy。
		const OfficialDiscoveryRouteCacheLookup cacheLookup =
			[this, request = &*request, &storedCacheEntries, &cachedPositiveEntriesByRoute,
			 nowUtcSeconds]( const OfficialDiscoveryRequest &lookupRequest,
							const OfficialDiscoveryRoute   &route)
			-> std::optional<OfficialDiscoveryRouteSummary> {
			// 開始時request、環境または時刻が変化したcallbackからcacheを返しません。
			if( lookupRequest != *request || nowUtcSeconds == 0U ||
			   releaseEnvironmentFingerprints_.operatingSystem.empty() ||
			   releaseEnvironmentFingerprints_.deviceConfiguration.empty()) {
				return std::nullopt ;
			}

			const auto registration = std::find_if(
				officialDiscoveryRegistrations_.begin(), officialDiscoveryRegistrations_.end(),
				[&route]( const OfficialDiscoveryRegistration &value) {
					return value.providerId == route.providerId &&
						   value.rootResourceId == route.rootResourceId && value.kind == route.kind ;
				}) ; // Current routeを所有するparser registration。
			// Registration欠落または重複時はcacheを利用せずexecutorの検証へ委ねます。
			if( registration == officialDiscoveryRegistrations_.end() ||
			   std::count_if( officialDiscoveryRegistrations_.begin(),
							 officialDiscoveryRegistrations_.end(),
							 [&route]( const OfficialDiscoveryRegistration &value) {
								 return value.providerId == route.providerId &&
										value.rootResourceId == route.rootResourceId &&
										value.kind == route.kind ;
							 }) != 1) {
				return std::nullopt ;
			}

			const auto cached =
				std::find_if( storedCacheEntries.begin(), storedCacheEntries.end(),
							 [&route, &registration]( const OfficialDiscoveryCacheEntry &entry) {
								 return entry.providerId == route.providerId &&
										entry.policyId == registration->sourcePolicyId &&
										entry.rootResourceId == route.rootResourceId ;
							 }) ; // 同じProvider固定rootの保存entry。
			// 未保存rootはnetwork resolverへ渡します。
			if( cached == storedCacheEntries.end()) {
				return std::nullopt ;
			}

			const OfficialDiscoveryCacheQuery query{
				.cacheMode					= lookupRequest.cacheMode,
				.providerId					= route.providerId,
				.policyId					= registration->sourcePolicyId,
				.rootResourceId				= route.rootResourceId,
				.policyRevision				= lookupRequest.policyRevision,
				.parserId					= registration->parserId,
				.parserRevision				= registration->parserRevision,
				.nowUtcSeconds				= nowUtcSeconds,
				.operatingSystemFingerprint = releaseEnvironmentFingerprints_.operatingSystem,
				.deviceConfigurationFingerprint =
					releaseEnvironmentFingerprints_.deviceConfiguration} ;	// Current freshness条件。
			const OfficialDiscoveryCacheDisposition disposition =
				// 全失効条件の判定結果。
				evaluateOfficialDiscoveryCacheEntry( *cached, query) ;
			// Fresh positiveだけをroute summaryと後段表示用copyへ結合します。
			if( disposition == OfficialDiscoveryCacheDisposition::FRESH_POSITIVE) {
				cachedPositiveEntriesByRoute.insert_or_assign( route.routeId, *cached) ;
				return OfficialDiscoveryRouteSummary{
					.routeId	  = route.routeId,
					.providerId	  = route.providerId,
					.kind		  = route.kind,
					.state		  = OfficialDiscoveryRouteState::CACHE_POSITIVE,
					.error		  = 0,
					.deviceCount  = static_cast<std::uint32_t>( route.deviceIdentities.size()),
					.recordCount  = 1U,
					.packageCount = static_cast<std::uint32_t>( cached->payloads.size())} ;
			}

			// Fresh negativeは同じ固定rootの送信省略だけを表します。
			if( disposition == OfficialDiscoveryCacheDisposition::FRESH_NEGATIVE) {
				return OfficialDiscoveryRouteSummary{
					.routeId	  = route.routeId,
					.providerId	  = route.providerId,
					.kind		  = route.kind,
					.state		  = OfficialDiscoveryRouteState::CACHE_NEGATIVE,
					.error		  = 0,
					.deviceCount  = static_cast<std::uint32_t>( route.deviceIdentities.size()),
					.recordCount  = 0U,
					.packageCount = 0U} ;
			}

			return std::nullopt ;
		} ; // URL、grant、EULA本文またはPnP IDを公開しないworker内cache照会。

		std::optional<OfficialDiscoverySummary> summary ;	// 実行または事前停止の非機密結果。
		bool networkApproved = true ;						// Routeがなければ回線状態を照会せずtrueのままにする。
		// 一件以上の固定rootへ到達する直前だけWindowsの回線costを確認する。
		if( !plan->routes.empty()) {
			WindowsOfficialNetworkCostReader costReader ;	// Windows標準のmachine-wide cost境界。
			OfficialNetworkCostKind			 networkCost =
				OfficialNetworkCostKind::UNKNOWN ;									// 読取り失敗も不明回線として扱う。
			const NativeError networkCostError = costReader.read( networkCost) ;	// 一回照会結果。
			networkApproved =
				(networkCostError == 0 && networkCost == OfficialNetworkCostKind::UNRESTRICTED) ||
				request->restrictedNetworkApproved ;
		}

		// Networkを使う可能性がある場合だけ秘密record sessionを開始します。
		if( networkApproved) {
			const NativeError beginError = officialDiscoveryRecordSession_.beginSession(
				binding, *request, descriptors) ;	// 旧秘密recordを再使用しないsession開始。
			// Sessionを開始できなければcache hitへ縮退せず、現在scanを失敗にします。
			if( beginError != 0) {
				assignControlResult( ProviderScanState::FAILURE, beginError) ;
				return ;
			}
		}

		// 各routeでfresh cacheを先に評価し、missだけを今回の回線許可へ従わせます。
		summary = runOfficialDiscoveryRoutePlan( binding, *request, *plan, *discoveryHints,
												officialDiscoveryRegistrations_, descriptors,
												cacheLookup, networkApproved) ;

		// Summaryを開始時planへ戻せない場合は全自動探索Providerを失敗にする。
		if( !summary) {
			officialDiscoveryRecordSession_.invalidate() ;
			assignControlResult( ProviderScanState::FAILURE, static_cast<NativeError>( E_UNEXPECTED)) ;
			return ;
		}

		officialDiscoverySummary_ = *summary ;
		std::unordered_map<std::wstring, std::vector<UpdateCandidate>>
			displayCandidatesByProvider ;	// Provider別の非選択公式配布行。
		std::unordered_map<std::wstring, std::vector<std::wstring>>
			candidateIdentitiesByPackage ;	// 準備対象へ戻すpackage別表示行ID。
		std::optional<std::vector<OfficialDiscoveryPackageGroup>>
			groups ;	// 一取得単位の全payload群。
		std::vector<OfficialRecordPayloadDescriptor>
					displayPayloadDescriptors ;	// Groupと同順のURL非保持表示metadata。
		std::size_t totalDisplayCandidates{} ;	// Cacheとnetworkから追加するdevice別行数。
		// Fresh positive routeを現在deviceへ表示専用で結合し、取得対象mapへ追加しません。
		for( std::size_t routeIndex{}; routeIndex < plan->routes.size(); ++routeIndex) {
			const OfficialDiscoveryRoute &route =
				plan->routes[routeIndex] ;	// 現在planの固定root route。
			const OfficialDiscoveryRouteSummary &routeSummary =
				(*summary).routes[routeIndex] ;	// 同位置のcacheまたはnetwork結果。
			// Fresh positive以外はnetwork record処理または空結果へ残します。
			if( routeSummary.state != OfficialDiscoveryRouteState::CACHE_POSITIVE) {
				continue ;
			}

			const auto cachedEntry =
				// Callbackが採用したentry copy。
				cachedPositiveEntriesByRoute.find( route.routeId) ;
			const auto registration = std::find_if(
				officialDiscoveryRegistrations_.begin(), officialDiscoveryRegistrations_.end(),
				[&route]( const OfficialDiscoveryRegistration &value) {
					return value.providerId == route.providerId &&
						   value.rootResourceId == route.rootResourceId && value.kind == route.kind ;
				}) ; // Entryの現在parser正本。
			const auto provider = std::find_if( descriptors.begin(), descriptors.end(),
											   [&route]( const ProviderDescriptor &value) {
												   return value.id == route.providerId ;
											   }) ; // Entryを所有するProvider正本。
			// Callback結果をentry、registration、Providerへ戻せない内部不整合を部分表示しません。
			if( cachedEntry == cachedPositiveEntriesByRoute.end() ||
			   registration == officialDiscoveryRegistrations_.end() ||
			   provider == descriptors.end()) {
				officialDiscoveryRecordSession_.invalidate() ;
				assignControlResult( ProviderScanState::FAILURE,
									static_cast<NativeError>( E_UNEXPECTED)) ;
				return ;
			}

			const OfficialDiscoveryCacheQuery query{
				.cacheMode					= request->cacheMode,
				.providerId					= route.providerId,
				.policyId					= registration->sourcePolicyId,
				.rootResourceId				= route.rootResourceId,
				.policyRevision				= request->policyRevision,
				.parserId					= registration->parserId,
				.parserRevision				= registration->parserRevision,
				.nowUtcSeconds				= nowUtcSeconds,
				.operatingSystemFingerprint = releaseEnvironmentFingerprints_.operatingSystem,
				.deviceConfigurationFingerprint =
					releaseEnvironmentFingerprints_
						.deviceConfiguration} ;	// 表示直前の同じfreshness条件。
			auto candidates = makeOfficialDiscoveryCachedDisplayCandidates(
				cachedEntry->second, query, scanSessionId, route, *discoveryHints,
				*provider) ;	// Download／install routingを持たないdevice別表示行。
			// Entry再検証失敗または全体候補上限超過を部分表示へ縮退させません。
			if( !candidates || candidates->empty() ||
			   candidates->size() > 32'768U - totalDisplayCandidates) {
				officialDiscoveryRecordSession_.invalidate() ;
				assignControlResult( ProviderScanState::FAILURE,
									static_cast<NativeError>( E_UNEXPECTED)) ;
				return ;
			}

			auto &providerCandidates =
				displayCandidatesByProvider[route.providerId] ;	// 同Providerのcache表示集合。
			providerCandidates.insert( providerCandidates.end(),
									  std::make_move_iterator( candidates->begin()),
									  std::make_move_iterator( candidates->end())) ;
			totalDisplayCandidates += candidates->size() ;
		}

		// 解決済みpayloadがある場合は取得許可と独立して非選択の配布情報行を作る。
		if( !officialDiscoveryRecordSession_.resolvedPackages().empty()) {
			groups = groupOfficialDiscoveryPackages(
				officialDiscoveryRecordSession_
					.resolvedPackages()) ;	// Record由来だけの重複排除結果。
			NativeError displayError =
				groups ? officialDiscoveryRecordSession_.describeDisplayPayloads(
							 binding, *groups, displayPayloadDescriptors)
					   : static_cast<NativeError>( E_UNEXPECTED) ;	// 秘密recordをclaimしない再照合。
			// Groupとdescriptorの一対一対応が崩れた結果を部分表示しない。
			if( displayError == 0 &&
			   (!groups || groups->empty() || groups->size() != displayPayloadDescriptors.size())) {
				displayError = static_cast<NativeError>( E_UNEXPECTED) ;
			}

			// Group順にregistry定義とdevice hintへ結合し、Provider別表示集合を作る。
			for( std::size_t groupIndex{};
				displayError == 0 && groups && groupIndex < groups->size(); ++groupIndex) {
				const OfficialDiscoveryPackageGroup &group =
					(*groups)[groupIndex] ;	// 今回変換する一payload group。
				const OfficialRecordPayloadDescriptor &payloadDescriptor =
					displayPayloadDescriptors[groupIndex] ;	// 同順の公開metadata。
				const auto provider = std::find_if( descriptors.begin(), descriptors.end(),
												   [&group]( const auto &value) {
													   return value.id == group.providerId ;
												   }) ; // Groupを所有するregistry正本。
				auto	   candidates =
					  provider == descriptors.end()
							  ? std::optional<std::vector<UpdateCandidate>>{}
							  : makeOfficialRecordPayloadDisplayCandidates(
								group, payloadDescriptor, *discoveryHints, *provider) ;	// Device別行。
				// 未知Provider、device欠落または全体候補上限超過を部分表示にしない。
				if( !candidates || candidates->empty() ||
				   candidates->size() > 32'768U - totalDisplayCandidates) {
					displayError = static_cast<NativeError>( E_UNEXPECTED) ;
					break ;
				}

				std::vector<std::wstring> candidateIdentities ;	// Groupと同順の表示行ID。
				candidateIdentities.reserve( candidates->size()) ;
				// Candidate本体の移動前に準備監査用のopaque IDだけを所有する。
				for( const UpdateCandidate &candidate : *candidates) {
					candidateIdentities.push_back( candidate.identity) ;
				}

				// 同じpackage IDの二重生成はrecord／payload重複排除違反として全体拒否する。
				if( !candidateIdentitiesByPackage
						.emplace( group.packageIdentity, std::move( candidateIdentities))
						.second) {
					displayError = static_cast<NativeError>( E_UNEXPECTED) ;
					break ;
				}

				auto &providerCandidates =
					displayCandidatesByProvider[group.providerId] ;	// 同Providerの表示集合。
				providerCandidates.insert( providerCandidates.end(),
										  std::make_move_iterator( candidates->begin()),
										  std::make_move_iterator( candidates->end())) ;
				totalDisplayCandidates += candidates->size() ;
			}

			// 表示metadataの一件不整合でも秘密recordを失効させ、全Providerを失敗にする。
			if( displayError != 0) {
				officialDiscoveryRecordSession_.invalidate() ;
				assignControlResult( ProviderScanState::FAILURE, displayError) ;
				return ;
			}
		}

		// 読取り境界が利用可能な場合だけ、fresh保持分と今回の正常network結果をatomic snapshotへ保存します。
		if( cacheStoreUsable) {
			std::vector<OfficialDiscoveryCacheEntry>
				nextCacheEntries ;	// 全検証後に保存するURL非保持集合。
			nextCacheEntries.reserve( storedCacheEntries.size() + plan->routes.size()) ;
			// 現在の組み込みregistration、環境、revisionと期限に合う保存entryだけを保持します。
			for( OfficialDiscoveryCacheEntry &entry : storedCacheEntries) {
				const auto registration = std::find_if(
					officialDiscoveryRegistrations_.begin(), officialDiscoveryRegistrations_.end(),
					[&entry]( const OfficialDiscoveryRegistration &value) {
						return value.providerId == entry.providerId &&
							   value.sourcePolicyId == entry.policyId &&
							   value.rootResourceId == entry.rootResourceId &&
							   value.parserId == entry.parserId ;
					}) ; // 保存entryに対応する現在parser登録。
				// 削除済みProvider、policy、rootまたはparserのentryを次snapshotへ移しません。
				if( registration == officialDiscoveryRegistrations_.end()) {
					continue ;
				}

				const OfficialDiscoveryCacheQuery query{
					.cacheMode					= request->cacheMode,
					.providerId					= registration->providerId,
					.policyId					= registration->sourcePolicyId,
					.rootResourceId				= registration->rootResourceId,
					.policyRevision				= request->policyRevision,
					.parserId					= registration->parserId,
					.parserRevision				= registration->parserRevision,
					.nowUtcSeconds				= nowUtcSeconds,
					.operatingSystemFingerprint = releaseEnvironmentFingerprints_.operatingSystem,
					.deviceConfigurationFingerprint =
						releaseEnvironmentFingerprints_.deviceConfiguration} ;	// 現在の全失効条件。
				const OfficialDiscoveryCacheDisposition disposition =
					// 保存entryの現在freshness。
					evaluateOfficialDiscoveryCacheEntry( entry, query) ;
				// Fresh positive／negativeだけを次snapshotへ移動します。
				if( disposition == OfficialDiscoveryCacheDisposition::FRESH_POSITIVE ||
				   disposition == OfficialDiscoveryCacheDisposition::FRESH_NEGATIVE) {
					nextCacheEntries.push_back( std::move( entry)) ;
				}
			}

			// Provider、policy、rootが同じ旧entryを新しい正常結果の前に除く端末内処理です。
			const auto removePreviousRoot =
				[&nextCacheEntries]( const std::wstring_view providerId,
									const std::wstring_view policyId,
									const std::wstring_view rootResourceId) {
					std::erase_if( nextCacheEntries, [providerId, policyId,
													 rootResourceId]( const auto &entry) {
						return entry.providerId == providerId && entry.policyId == policyId &&
							   entry.rootResourceId == rootResourceId ;
					}) ;
				} ;
			// Networkへ到達した各routeの正常なpositiveまたはrecordなしだけを新entryへ変換します。
			for( std::size_t routeIndex{}; routeIndex < plan->routes.size(); ++routeIndex) {
				const OfficialDiscoveryRoute &route =
					plan->routes[routeIndex] ;	// 現在保存判定するroute。
				const OfficialDiscoveryRouteSummary &routeSummary =
					(*summary).routes[routeIndex] ;	// 同位置の実行結果。
				const auto registration = std::find_if(
					officialDiscoveryRegistrations_.begin(), officialDiscoveryRegistrations_.end(),
					[&route]( const OfficialDiscoveryRegistration &value) {
						return value.providerId == route.providerId &&
							   value.rootResourceId == route.rootResourceId &&
							   value.kind == route.kind ;
					}) ; // Network結果を生成したparser登録。
				// 実行済みrouteのregistration欠落時はcache保存だけを省略します。
				if( registration == officialDiscoveryRegistrations_.end()) {
					continue ;
				}

				// 正常なrecordなしだけを6時間のnegative entryへ置換します。
				if( routeSummary.state == OfficialDiscoveryRouteState::NO_RECORD) {
					const auto negative = makeOfficialDiscoveryNegativeCacheEntry(
						OfficialDiscoveryCacheEntryKind::NO_RECORD, route.providerId,
						registration->sourcePolicyId, route.rootResourceId, request->policyRevision,
						registration->parserId, registration->parserRevision, nowUtcSeconds,
						releaseEnvironmentFingerprints_.operatingSystem,
						releaseEnvironmentFingerprints_
							.deviceConfiguration) ;	// 現在環境の否定結果。
					// 全fieldをcache schemaへ縮退できた場合だけ旧root結果を置換します。
					if( negative) {
						removePreviousRoot( route.providerId, registration->sourcePolicyId,
										   route.rootResourceId) ;
						nextCacheEntries.push_back( *negative) ;
					}

					continue ;
				}

				// 現在networkで解決した二状態以外からpositive cacheを生成しません。
				if( routeSummary.state != OfficialDiscoveryRouteState::DEDICATED_RESOLVED &&
				   routeSummary.state != OfficialDiscoveryRouteState::GENERIC_RESOLVED) {
					continue ;
				}

				std::vector<OfficialRecordPayloadDescriptor>
					routeDescriptors ;	// 同じrouteが解決したpayload集合。
				// Groupと表示descriptorの同位置を走査し、現在routeを含むrecordだけを集めます。
				for( std::size_t groupIndex{}; groups && groupIndex < groups->size(); ++groupIndex) {
					const OfficialDiscoveryPackageGroup &group =
						(*groups)[groupIndex] ;	// 現在group。
					// 別routeだけが解決したpayloadを現在rootのcacheへ混在させません。
					if( std::find( group.routeIds.begin(), group.routeIds.end(), route.routeId) ==
					   group.routeIds.end()) {
						continue ;
					}

					routeDescriptors.push_back( displayPayloadDescriptors[groupIndex]) ;
				}

				std::ranges::sort( routeDescriptors, {},
								  &OfficialRecordPayloadDescriptor::payloadOrdinal) ;
				const auto positive = makeOfficialDiscoveryPositiveCacheEntry(
					routeDescriptors, request->policyRevision, registration->parserId,
					registration->parserRevision, nowUtcSeconds,
					releaseEnvironmentFingerprints_.operatingSystem,
					releaseEnvironmentFingerprints_
						.deviceConfiguration) ;	// 一recordの完全payload集合。
				// 複数record、欠落ordinalまたは不正metadataは現在scanを維持してcache保存だけを省略します。
				if( positive) {
					removePreviousRoot( route.providerId, registration->sourcePolicyId,
									   route.rootResourceId) ;
					nextCacheEntries.push_back( *positive) ;
				}
			}

			// 保存失敗は現在sessionの検証済み結果を破棄せず、次scanでnetwork再確認へ進ませます。
			static_cast<void>( releaseObservationStore_.storeDiscoveryCache( nextCacheEntries)) ;
		}

		// 一scan承認がpayload検査まで許可した場合だけ既存準備UIへURL非保持対象を作る。
		if( request->inspectionPermission ==
			   OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE &&
		   groups && !groups->empty()) {
			std::vector<OfficialDiscoveryPackageGroup>
				acquisitionGroups ;	// Grantを発行できる方式だけの一取得単位集合。
			acquisitionGroups.reserve( groups->size()) ;
			// Unsupported payloadは表示に残し、取得件数と予約予算には含めない。
			for( std::size_t groupIndex{}; groupIndex < groups->size(); ++groupIndex) {
				// Record方式が取得を許可するgroupだけを準備対象候補へ移す。
				if( displayPayloadDescriptors[groupIndex].downloadGrantSupported) {
					acquisitionGroups.push_back( (*groups)[groupIndex]) ;
				}
			}

			// 取得可能file数が開始時に表示した一scan上限を超える場合はgrantを発行しない。
			if( acquisitionGroups.size() > request->payloadLimits.maximumSessionFiles) {
				officialDiscoveryRecordSession_.invalidate() ;
				assignControlResult(
					ProviderScanState::FAILURE,
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
				return ;
			}

			std::vector<OfficialPreparationTarget> targets ;	// 既存準備計画へ渡す対象集合。
			std::vector<OfficialDiscoveryEulaPackage>
				eulaPackages ;	// 完全一致EULA group化前snapshot集合。
			std::vector<OfficialRecordPayloadDescriptor>
						payloadDescriptors ;	// 取得対象と同順のURL非保持表示descriptor集合。
			NativeError preparationError =
				acquisitionGroups.empty()
					? 0
					: officialDiscoveryRecordSession_.describePreparationTargets(
						  binding, acquisitionGroups, targets, eulaPackages,
						  payloadDescriptors) ;	// 全秘密recordをclaimせず再照合する。

			// Descriptorと対象の一対一対応が崩れた結果を部分的な準備計画へ使わない。
			if( preparationError == 0 && targets.size() != payloadDescriptors.size()) {
				preparationError = static_cast<NativeError>( E_UNEXPECTED) ;
			}

			// 取得可能payloadがある場合だけEULA sessionと準備状態を構築する。
			if( preparationError == 0 && !targets.empty()) {
				preparationError =
					officialDiscoveryEulaSession_.beginSession( binding, eulaPackages) ;
			}

			std::vector<OfficialDiscoveryPreparedPayload>
				preparedPayloads ;	// 全targetをgroupとEULAへ結合後だけ公開する状態集合。
			std::unordered_set<std::uint64_t>
				preparedRecordEvidenceIds ;	// 現行grantが一record一payloadを要求する一意性集合。
			// 先行変換が成立した場合だけ各対象のgroupと共有tokenを固定する。
			if( preparationError == 0) {
				preparedPayloads.reserve( targets.size()) ;
				preparedRecordEvidenceIds.reserve( targets.size()) ;
				// 取得可能対象だけを同じopaque package groupと表示descriptorへ一対一で戻す。
				for( std::size_t targetIndex{}; targetIndex < targets.size(); ++targetIndex) {
					OfficialPreparationTarget &target = targets[targetIndex] ;	// 今回の準備対象。
					const OfficialRecordPayloadDescriptor &payloadDescriptor =
						payloadDescriptors[targetIndex] ;	// 対象と同順の公開descriptor。
					const auto packageGroup =
						std::find_if( acquisitionGroups.begin(), acquisitionGroups.end(),
									 [&target]( const auto &group) {
										 return group.packageIdentity == target.identity ;
									 }) ; // 対象のrecord／route／device結合group。
					const auto candidateIdentities = candidateIdentitiesByPackage.find(
						target.identity) ;	// 同じpackageの表示行ID。
					// 生成元groupまたは完全一致descriptorが欠落する対象を計画へ公開しない。
					if( packageGroup == acquisitionGroups.end() ||
					   packageGroup->recordEvidenceIds.empty() ||
					   candidateIdentities == candidateIdentitiesByPackage.end() ||
					   candidateIdentities->second.size() !=
						   packageGroup->deviceIdentities.size() ||
					   !isOfficialRecordPayloadDescriptorValid( payloadDescriptor) ||
					   payloadDescriptor.providerId != target.providerId ||
					   payloadDescriptor.payloadResourceId != target.resourceId ||
					   payloadDescriptor.recordFingerprint.bytes !=
						   packageGroup->recordFingerprint.bytes ||
					   payloadDescriptor.payloadCount != packageGroup->payloadCount ||
					   payloadDescriptor.payloadOrdinal != packageGroup->payloadOrdinal) {
						preparationError = static_cast<NativeError>( E_UNEXPECTED) ;
						break ;
					}

					// Record内の複数payloadは個別grantの安全な一括発行が未接続なので取得対象化しない。
					if( !preparedRecordEvidenceIds.insert( packageGroup->recordEvidenceIds.front())
							.second) {
						preparationError = static_cast<NativeError>( E_NOTIMPL) ;
						break ;
					}

					OfficialDiscoveryPreparedPayload prepared ;	// 一対象のworker内取得状態。
					prepared.target				 = target ;
					prepared.group				 = *packageGroup ;
					prepared.descriptor			 = payloadDescriptor ;
					prepared.candidateIdentities = candidateIdentities->second ;
					// 同意必須対象はEULA snapshotと一つの短命group tokenへ結合する。
					if( target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
						const auto eulaPackage = std::find_if(
							eulaPackages.begin(), eulaPackages.end(), [&target]( const auto &value) {
								return value.packageIdentity == target.identity ;
							}) ; // 対象と完全一致するEULA package snapshot。
						const auto eulaGroup = std::find_if(
							officialDiscoveryEulaSession_.groups().begin(),
							officialDiscoveryEulaSession_.groups().end(),
							[&target]( const auto &group) {
								return std::find( group.packageIdentities.begin(),
												 group.packageIdentities.end(),
												 target.identity) != group.packageIdentities.end() ;
							}) ; // 同じpackageを含む完全一致EULA group。
						// Snapshotまたはgroup欠落時に従来の対象単位同意へ縮退させない。
						if( eulaPackage == eulaPackages.end() ||
						   eulaGroup == officialDiscoveryEulaSession_.groups().end() ||
						   eulaGroup->providerId != target.providerId ||
						   eulaGroup->eulaRevision != target.eulaRevision ||
						   eulaGroup->eulaText != target.eulaText) {
							preparationError = static_cast<NativeError>( E_UNEXPECTED) ;
							break ;
						}

						target.sharedEulaToken = eulaGroup->token.value ;
						prepared.target		   = target ;
						prepared.eulaPackage   = *eulaPackage ;
						prepared.eulaRequired  = true ;
					}

					preparedPayloads.push_back( std::move( prepared)) ;
				}
			}

			// 一件の準備不整合でも秘密recordとEULAを破棄して取得をfail-closedにする。
			if( preparationError != 0) {
				officialDiscoveryRecordSession_.invalidate() ;
				officialDiscoveryEulaSession_.invalidate() ;
				assignControlResult( ProviderScanState::FAILURE, preparationError) ;
				return ;
			}

			// 取得可能対象がなければ未使用の秘密URLとEULA本文をscan中にも保持しない。
			if( preparedPayloads.empty()) {
				officialDiscoveryRecordSession_.invalidate() ;
				officialDiscoveryEulaSession_.invalidate() ;
			} else {
				officialDiscoveryPreparedPayloads_ = std::move( preparedPayloads) ;
				officialDiscoveryAcceptedEulaGroups_.assign(
					officialDiscoveryEulaSession_.groups().size(), false) ;
			}
		} else {
			// Metadata限定または対象0件では取得に使わない秘密URLをsummary確定直後に破棄する。
			officialDiscoveryRecordSession_.invalidate() ;
		}

		// 共通summaryを各Providerへ分離し、旧Provider scanとの二重HTTPを防ぐ。
		for( const RegisteredProvider &registered : providerRegistry_) {
			// 今回有効な自動探索Providerだけをsummaryから変換する。
			if( registered.phase != ProviderPhase::OFFICIAL_CATALOG ||
			   !registered.enabledForSession ||
			   !isAutomaticDiscoveryDescriptor( registered.descriptor)) {
				continue ;
			}

			auto providerResult = makeOfficialDiscoveryProviderScanResult(
				scanSessionId, registered.descriptor.id, *discoveryHints, *plan, *summary,
				descriptors) ;	// Provider別到達状態。
			// 一件の変換不整合でも当該Providerを候補なし成功へ変換しない。
			if( !providerResult) {
				automaticDiscoveryResults.insert_or_assign(
					registered.descriptor.id,
					makeAutomaticDiscoveryControlResult( scanSessionId, ProviderScanState::FAILURE,
														static_cast<NativeError>( E_UNEXPECTED))) ;
				continue ;
			}

			const auto displayCandidates = displayCandidatesByProvider.find(
				registered.descriptor.id) ;	// 当該Providerの表示行。
			// 取得前の配布情報行がある場合は候補ありへ変更し、導入権限なしで所有権を移す。
			if( displayCandidates != displayCandidatesByProvider.end() &&
			   !displayCandidates->second.empty()) {
				providerResult->candidates = std::move( displayCandidates->second) ;
				providerResult->state	   = ProviderScanState::CANDIDATES_AVAILABLE ;
			}

			automaticDiscoveryResults.insert_or_assign( registered.descriptor.id,
													   std::move( *providerResult)) ;
		}
	} ; // 同一通常scanの承認、inventory、回線、共通executorを一回だけ結合する処理。
	std::size_t officialIndex{} ;	// 有効な公式Provider内の0始まり進捗index。
	// 公式ProviderをRegistry順に実行し、無効entryはnetworkへ到達させず状態だけ確定する。
	for( RegisteredProvider &provider : providerRegistry_) {
		// 公式catalog段階以外のProviderをvendor検索の段階では実行しない。
		if( provider.phase != ProviderPhase::OFFICIAL_CATALOG) {
			continue ;
		}

		ScanResult providerResult{} ;	// 公式Provider固有のscan結果。
		providerResult.scanSessionId = scanSessionId ;
		// 有効な公式Providerだけに観測設定と割当進捗区間を渡して検索する。
		if( provider.enabledForSession) {
			// 観測比較を実装したProviderにだけ端末内fingerprintと前回観測を渡す。
			if( provider.configureReleaseObservations &&
			   !isAutomaticDiscoveryDescriptor( provider.descriptor)) {
				// HMACと前回観測はProvider内部のlocal差分評価だけへ渡す。
				provider.configureReleaseObservations( reusableReleaseObservations_,
													  releaseEnvironmentFingerprints_) ;
			}

			const std::uint32_t start =	// 65～90%を有効な公式Providerで等分する開始値。
				65 + static_cast<std::uint32_t>( officialIndex * 25 / enabledOfficialCount) ;
			// 現在の公式Providerへ割り当てた全体進捗区間の終端。
			const std::uint32_t end =
				65 + static_cast<std::uint32_t>( (officialIndex + 1) * 25 / enabledOfficialCount) ;
			// 自動探索Providerは共通planを一度だけ実行し、従来scanによる二重HTTPを行わない。
			if( isAutomaticDiscoveryDescriptor( provider.descriptor)) {
				// 最初の自動探索Provider位置で全routeをまとめて実行する。
				if( !automaticDiscoveryExecuted) {
					progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
									  .percentComplete = start}) ;
					executeAutomaticDiscovery() ;
					automaticDiscoveryExecuted = true ;
				}

				const auto automaticResult =
					// 当該Provider結果。
					automaticDiscoveryResults.find( provider.descriptor.id) ;
				// 共通executorが結果を返さない内部不整合をfail-closedで確定する。
				providerResult = automaticResult == automaticDiscoveryResults.end()
									 ? makeAutomaticDiscoveryControlResult(
										   scanSessionId, ProviderScanState::FAILURE,
										   static_cast<NativeError>( E_UNEXPECTED))
									 : std::move( automaticResult->second) ;
				progressCallback(
					{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = end}) ;
			} else {
				providerResult =
					provider.scan( scanSessionId, options, officialDevices, hardwareIdMatcher,
								  scaledProgress( progressCallback, start, end - start)) ;
			}

			++officialIndex ;
		} else {
			providerResult.succeeded = true ;
			providerResult.outcome	 = OutcomeCode::SUCCESS ;
			providerResult.state	 = ProviderScanState::DISABLED ;
		}

		outputs.push_back( {&provider, std::move( providerResult)}) ;
		// 一つの公式Provider終端ごとに取消しを確認し、次の通信を開始しない。
		if( isStandardScanCancellationRequested( cancellation)) {
			invalidateScanSession() ;
			return makeCancelledStandardScan( scanSessionId) ;
		}
	}

	// 有効な公式Providerがない場合は未実施の待機を作らず統合段階へ進む。
	if( enabledOfficialCount == 0) {
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 90}) ;
	}

	// Provider別状態は候補のownershipを移す前に確定する。
	std::vector<OutcomeCode> outcomes ;	// 実行したProviderの集約対象outcome。
	outcomes.reserve( outputs.size()) ;
	bool baseProviderSucceeded{} ;	// Inventoryまたは有効managed serviceの成立状態。
	// Provider別結果を検証し、表示reportと全体outcomeへ同じ順序で集約する。
	for( const ProviderOutput &output : outputs) {
		const RegisteredProvider &provider = *output.registration ;	// 対応registry entry。
		// 無効Providerは0とする、そのProviderの表示候補件数。
		const std::uint64_t		  count =
			  provider.enabledForSession ? countDisplayCandidates( output.scanResult) : 0 ;
		const ProviderScanState resolvedState =
			resolveProviderScanState( output.scanResult,
									 provider.enabledForSession) ;	// 正規化済みscan状態。
		result.providerReports.push_back( {.descriptor	  = provider.descriptor,
										  .state		  = resolvedState,
										  .error		  = output.scanResult.error,
										  .candidateCount = count,
										  .coverage		  = output.scanResult.coverage,
										  .outcome		  = provider.enabledForSession
																? output.scanResult.outcome
																: OutcomeCode::NOT_STARTED}) ;
		// Providerの成功flag・outcome・監査状態が矛盾する結果を全体成功へ昇格しない。
		if( !isProviderScanResultConsistent( output.scanResult, provider.enabledForSession)) {
			// 矛盾する成功flag、outcome、監査状態をaggregate成功へ昇格しない。
			result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
			result.outcome = OutcomeCode::FAILURE ;
			return result ;
		}

		// 対象・判定済み件数が矛盾する集計を統合結果へ渡さない。
		if( !isValidProviderCoverage( output.scanResult.coverage)) {
			// 不正な集計を後段へ渡さず、Provider識別用の報告だけを保持する。
			result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
			result.outcome = OutcomeCode::FAILURE ;
			return result ;
		}

		// 必須inventoryと有効Providerの結果だけを全体outcomeへ集約する。
		if( provider.phase == ProviderPhase::INVENTORY || provider.enabledForSession) {
			outcomes.push_back( output.scanResult.outcome) ;
		}

		// inventoryまたは有効な管理serviceの成功を基礎検索の成立条件に数える。
		if( (provider.phase == ProviderPhase::INVENTORY ||
			(provider.phase == ProviderPhase::MANAGED_SERVICE && provider.enabledForSession)) &&
		   output.scanResult.succeeded) {
			baseProviderSucceeded = true ;
		}

		// 最初に検出したProvider診断を後続の結果で上書きしない。
		if( result.error == 0 && output.scanResult.error != 0) {
			result.error = output.scanResult.error ;
		}
	}

	// 基礎Providerが一つも成功していない場合はvendor候補だけで全体成功としない。
	if( !baseProviderSucceeded) {
		result.outcome = OutcomeCode::FAILURE ;
		return result ;
	}

	std::vector<std::wstring> refreshedObservationProviders ;			// 成立した観測対応Provider ID。
	std::vector<LocalOfficialReleaseObservation> currentObservations ;	// 今回生成した全観測。
	// 検証済みProvider結果だけを一つのatomic snapshot更新へ集約する。
	for( const ProviderOutput &output : outputs) {
		const RegisteredProvider &provider = *output.registration ;	// 今回結果のregistry正本。
		// 有効かつ成功した公式Providerの取得済み観測だけを保存候補へ集める。
		if( provider.phase != ProviderPhase::OFFICIAL_CATALOG || !provider.enabledForSession ||
		   !output.scanResult.succeeded || !provider.releaseObservations) {
			continue ;
		}

		refreshedObservationProviders.push_back( provider.descriptor.id) ;
		const std::span<const LocalOfficialReleaseObservation> observations =
			// Provider所有の今回観測。
			provider.releaseObservations() ;
		currentObservations.insert( currentObservations.end(), observations.begin(),
								   observations.end()) ;
	}

	// 更新対象Providerと環境fingerprintが揃う場合にだけ観測snapshotを保存する。
	if( !refreshedObservationProviders.empty() &&
	   !releaseEnvironmentFingerprints_.operatingSystem.empty() &&
	   !releaseEnvironmentFingerprints_.deviceConfiguration.empty()) {
		std::vector<LocalOfficialReleaseObservation> mergedObservations ;	// 保存候補snapshot。
		// 観測統合とatomic保存が成功した後にだけmemory上の再利用snapshotを更新する。
		if( mergeLocalOfficialReleaseObservations( reusableReleaseObservations_,
												 refreshedObservationProviders, currentObservations,
												 mergedObservations) &&
		   releaseObservationStore_.store( mergedObservations) == 0) {
			// Atomic保存成功後だけmemory上の次回参照も今回観測へ更新する。
			reusableReleaseObservations_ = std::move( mergedObservations) ;
		}
	}

	std::unordered_map<std::wstring, std::wstring> deviceClassGuids ;	// Device icon metadata。
	deviceClassGuids.reserve( officialDevices.size()) ;
	// 取得経路と監査状態を検証してaggregate sessionへ一件追加するcallback。
	auto appendCandidate = [this, &result]( const RegisteredProvider &provider,
										   UpdateCandidate			 candidate) {
		// Provider ID、既定選択根拠、監査状態のいずれかが矛盾する候補を登録しない。
		if( candidate.identity.empty() || candidate.deviceIdentity.empty() ||
		   candidate.packageIdentity.empty() || candidate.providerId != provider.descriptor.id ||
		   !isCandidateDefaultPreferenceValid( candidate, provider.descriptor) ||
		   !isCandidateAuditValid( candidate, provider.descriptor) ||
		   !isCandidateDetailsValid( candidate, result.scanSessionId) ||
		   !identityDevices_.emplace( candidate.identity, candidate.deviceIdentity).second) {
			return false ;
		}

		// install可能なcandidate identityのProvider routing衝突を拒否する。
		if( candidate.installable &&
		   !identityProviders_.emplace( candidate.identity, provider.descriptor.id).second) {
			return false ;
		}

		// Providerが設定した統合annotationを信用せず、aggregateだけが確定する。
		candidate.equivalentSourceCount = 1 ;
		candidate.preferredSource		= true ;
		result.candidates.push_back( std::move( candidate)) ;
		return true ;
	} ;

	// Inventoryの現在版は常に表示し、無効時はDriver Store別版だけを除外する。
	for( ProviderOutput &output : outputs) {
		// local候補の統合段階ではinventory Providerの結果だけを扱う。
		if( output.registration->phase != ProviderPhase::INVENTORY) {
			continue ;
		}

		// Inventoryの現在版と、有効時だけのDriver Store別版を表示集合へ移動する。
		for( UpdateCandidate &candidate : output.scanResult.candidates) {
			// Driver Storeを無効にした場合も現在行は保持し、過去候補は表示しない。
			if( !output.registration->enabledForSession && !candidate.current) {
				continue ;
			}

			// class GUIDが判明しているdeviceだけをWUA表示補完用の索引へ含める。
			if( !candidate.deviceClassGuid.empty()) {
				deviceClassGuids.try_emplace( candidate.deviceIdentity, candidate.deviceClassGuid) ;
			}

			// local候補のidentity整合性が崩れた場合は部分一覧を破棄する。
			if( !appendCandidate( *output.registration, std::move( candidate))) {
				result.candidates.clear() ;
				result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
				result.outcome = OutcomeCode::FAILURE ;
				return result ;
			}
		}
	}

	// 公式Provider候補はlocal deviceとの照合後にregistryの走査順で統合する。
	// この順序は同等な既定選択根拠の安定順序にだけ使用し、取得元の固定優先順位にしない。
	for( ProviderOutput &output : outputs) {
		// 有効な公式catalog Provider以外の結果をvendor候補として統合しない。
		if( output.registration->phase != ProviderPhase::OFFICIAL_CATALOG ||
		   !output.registration->enabledForSession) {
			continue ;
		}

		// Local deviceとの照合を終えた公式候補を、Provider内の入力順で表示集合へ移動する。
		for( UpdateCandidate &candidate : output.scanResult.candidates) {
			// 公式候補のidentity整合性が崩れた場合は部分一覧を破棄する。
			if( !appendCandidate( *output.registration, std::move( candidate))) {
				result.candidates.clear() ;
				result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
				result.outcome = OutcomeCode::FAILURE ;
				return result ;
			}
		}
	}

	ProviderOutput *managedOutput{} ;	// WUA Hardware IDをlocal deviceへ照合する結果。
	// Provider別結果からRegistryのstable IDでWUA結果を一意に検索する。
	for( ProviderOutput &output : outputs) {
		// Windows Updateのstable IDに対応する出力だけをWUA照合対象にする。
		if( output.registration->descriptor.id == WINDOWS_UPDATE_PROVIDER_ID) {
			managedOutput = &output ;
			break ;
		}
	}

	// WUA出力が存在する場合の管理service候補件数。未実行時は0。
	const std::size_t managedCount =
		managedOutput == nullptr ? 0 : managedOutput->scanResult.candidates.size() ;
	progressCallback( {.stage		   = ProviderStage::MERGING_CANDIDATES,
					  .percentComplete = 90,
					  .completedItems  = 0,
					  .totalItems	   = managedCount}) ;
	// 有効なWUA出力がある場合にだけ端末内deviceへの照合を行う。
	if( managedOutput != nullptr && managedOutput->registration->enabledForSession) {
		// WUA候補を端末内deviceへ一件ずつ照合し、確定件数だけ進捗へ反映する。
		for( std::size_t index = 0; index < managedCount; ++index) {
			UpdateCandidate candidate =
				// 現在のWUA候補。
				std::move( managedOutput->scanResult.candidates[index]) ;
			// WUA候補に対応するcatalog側ID。Worker内の照合後はUIへ渡さない。
			const std::optional<std::wstring> hardwareId =
				windowsUpdateProvider_.hardwareIdForIdentity( candidate.identity) ;
			// Catalog側IDをlocal inventoryへ照合したopaque device identity。未一致は値なし。
			const std::optional<std::wstring> localDevice =
				hardwareId.has_value()
					? driverStoreProvider_.deviceIdentityForHardwareId( hardwareId.value())
					: std::nullopt ;
			candidate.deviceIdentity = localDevice.has_value()
										   ? localDevice.value()
										   : L"wua-device:" + std::to_wstring( scanSessionId) +
												 L":" + std::to_wstring( index) ;
			// 候補deviceのclass表示に使用する、inventory内のGUID位置。
			const auto classGuid = deviceClassGuids.find( candidate.deviceIdentity) ;
			// 同じdeviceのclass GUIDが判明している場合にだけ表示属性を補完する。
			if( classGuid != deviceClassGuids.end()) {
				candidate.deviceClassGuid = classGuid->second ;
			}

			// model表示がないWUA候補は既存titleを表示用に使用する。
			if( candidate.model.empty()) {
				candidate.model = candidate.title ;
			}

			// WUA候補のidentity整合性が崩れた場合は部分一覧を破棄する。
			if( !appendCandidate( *managedOutput->registration, std::move( candidate))) {
				result.candidates.clear() ;
				result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
				result.outcome = OutcomeCode::FAILURE ;
				return result ;
			}

			const std::uint64_t completed = index + 1 ;	// 統合済みmanaged候補数。
			progressCallback(
				{.stage			  = ProviderStage::MERGING_CANDIDATES,
				 .percentComplete = static_cast<std::uint32_t>( 90 + completed * 10 / managedCount),
				 .completedItems  = completed,
				 .totalItems	  = managedCount}) ;
		}
	}

	// WUA候補がない場合も待機を捏造せず統合段階の完了を通知する。
	if( managedCount == 0) {
		progressCallback( {.stage = ProviderStage::MERGING_CANDIDATES, .percentComplete = 100}) ;
	}

	const auto sourceGroups = groupEquivalentCandidateSources(
		result.candidates, builtInProviderDescriptors()) ;	// 明示版完全一致の取得元group。
	// 同一版取得元groupが不正ならsessionを失効させて候補を全て破棄する。
	if( !sourceGroups.has_value()) {
		result.candidates.clear() ;
		result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
		result.outcome = OutcomeCode::FAILURE ;
		invalidateScanSession() ;
		return result ;
	}

	// Candidate行とroutingは保持し、同一版取得元数と既定取得元だけをannotationする。
	for( const CandidateSourceGroup &group : sourceGroups.value()) {
		// 取得元groupの件数表現と既定候補indexが範囲外なら全体を拒否する。
		if( group.candidateIndexes.size() > std::numeric_limits<std::uint32_t>::max() ||
		   group.preferredCandidateIndex >= result.candidates.size()) {
			result.candidates.clear() ;
			result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
			result.outcome = OutcomeCode::FAILURE ;
			invalidateScanSession() ;
			return result ;
		}

		const auto sourceCount =
			// 同一版取得元数。
			static_cast<std::uint32_t>( group.candidateIndexes.size()) ;
		// 同一版groupの全候補行へ取得元数と既定取得元だけを注釈する。
		for( const std::size_t candidateIndex : group.candidateIndexes) {
			// 取得元groupが参照する候補indexの範囲外を検出したら全体を拒否する。
			if( candidateIndex >= result.candidates.size()) {
				result.candidates.clear() ;
				result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
				result.outcome = OutcomeCode::FAILURE ;
				invalidateScanSession() ;
				return result ;
			}

			UpdateCandidate &candidate = result.candidates[candidateIndex] ;	// Annotation対象行。
			candidate.equivalentSourceCount = sourceCount ;
			candidate.preferredSource		= candidateIndex == group.preferredCandidateIndex ;
		}
	}

	std::vector<ProviderMeasurementEvidence> measurementEvidence ;	// 接続済みProviderの所有根拠。
	measurementEvidence.reserve( providerRegistry_.size()) ;
	// 有効かつ観測adapterを持つProviderだけから、同じsessionの根拠をcopyする。
	for( const RegisteredProvider &provider : providerRegistry_) {
		// 無効Providerと未接続Providerの旧coverageを新しい集合として推測しない。
		if( !provider.enabledForSession || !provider.measurementEvidence) {
			continue ;
		}

		ProviderMeasurementEvidence evidence =
			// Provider所有根拠のcopy。
			provider.measurementEvidence() ;
		// 初期値だけの未発行根拠はadapter未接続と同じ未計測として扱う。
		if( evidence.providerId.empty() && evidence.scanSessionId == 0) {
			continue ;
		}

		// WUAのsystem queryだけは、Compositeが確定したDとlocal照合結果を補う。
		if( evidence.providerId == WINDOWS_UPDATE_PROVIDER_ID &&
		   !bindManagedMeasurementEvidence( officialDevices, result.candidates, evidence)) {
			// 計測adapterの矛盾で正常候補を失効させず、WUA新指標だけを未計測にする。
			continue ;
		}

		measurementEvidence.push_back( std::move( evidence)) ;
	}

	std::vector<std::wstring> routableCandidateIds ;	// 既存install routingが保持する候補IDのcopy。
	routableCandidateIds.reserve( identityProviders_.size()) ;
	// 計測側でroutingを発行せず、既存mapに登録済みのIDだけを渡す。
	for( const auto &[identity, providerId] : identityProviders_) {
		// Provider IDはrouting mapの検証済み値であり、ここでは候補IDだけを集計へ渡す。
		static_cast<void>( providerId) ;
		routableCandidateIds.push_back( identity) ;
	}

	ScanMeasurementContext measurementContext ;	// Scan開始条件と完了時点を固定するcontext。
	measurementContext.scanSessionId		= scanSessionId ;
	measurementContext.startedUtcSeconds	= scanStartedUtcSeconds ;
	measurementContext.completedUtcSeconds	= currentUtcSeconds() ;
	measurementContext.usedDefaultProviders = options.useDefaultProviders ;
	const std::uint32_t windowsBuild = currentWindowsBuildNumber() ;	// 実行中Windowsのbuild番号。
	// 取得できたbuildだけを値として公開し、0を実build番号として扱わない。
	if( windowsBuild != 0U) {
		measurementContext.osBuild = windowsBuild ;
		measurementContext.osKind =
			isWindowsServer() ? MeasurementOsKind::SERVER : MeasurementOsKind::CLIENT ;
	}

	measurementContext.enabledProviderIds.reserve( providerRegistry_.size()) ;
	// Registryで解決済みの有効集合を現在のUI設定から独立したsnapshotへcopyする。
	for( const RegisteredProvider &provider : providerRegistry_) {
		// 今回無効なProviderを検索済み集合へ含めない。
		if( provider.enabledForSession) {
			measurementContext.enabledProviderIds.push_back( provider.descriptor.id) ;
		}
	}

	std::optional<ScanMeasurementAggregation> measurement ;	// 成功時だけ公開する段階別集計。
	try {
		measurement = aggregateScanMeasurement(
			measurementContext, result.candidates, builtInProviderDescriptors(),
			driverStoreProvider_.inventoryMeasurement(), measurementEvidence, routableCandidateIds) ;
	} catch( ...) {
		// 計測用allocation失敗を正常な候補sessionの権限変更へ波及させない。
		measurement.reset() ;
	}

	// 全根拠が整合した場合だけ、全体・Provider・groupの値を同時に公開する。
	if( measurement.has_value()) {
		result.measurement	 = std::move( measurement->snapshot) ;
		result.localCoverage = std::move( measurement->localCoverage) ;
		// Registry別集計を同じstable IDの既存reportへ一対一で接続する。
		for( const ProviderMeasurementEntry &entry : measurement->providers) {
			const auto report =
				std::find_if( result.providerReports.begin(), result.providerReports.end(),
							 [&entry]( const ProviderScanReport &value) {
								 return value.descriptor.id == entry.providerId ;
							 }) ; // 対応するProvider report。
			// Constructor registryから作ったreport欠落は発生しないが、部分mappingは公開しない。
			if( report == result.providerReports.end()) {
				result.measurement.reset() ;
				result.localCoverage.clear() ;
				// 既に対応付けたProvider measurementも一括で破棄する。
				for( ProviderScanReport &published : result.providerReports) {
					published.coverage.measurement.reset() ;
				}

				break ;
			}

			report->coverage.measurement = entry.measurement ;
		}
	}

	// 新計測が未接続または拒否された場合も、従来の候補到達集計と正常候補を維持する。
	if( result.localCoverage.empty() && !result.candidates.empty()) {
		const auto localCoverage = aggregateLocalCoverage(
			result.candidates, builtInProviderDescriptors()) ;	// 従来の端末内候補到達集計。
		// 既存候補契約まで検証できない場合だけscan sessionをfail-closedで拒否する。
		if( !localCoverage.has_value()) {
			result.candidates.clear() ;
			result.error   = static_cast<NativeError>( E_UNEXPECTED) ;
			result.outcome = OutcomeCode::FAILURE ;
			invalidateScanSession() ;
			return result ;
		}

		result.localCoverage = std::move( localCoverage.value()) ;
	}

	// 集約処理中に到着した取消しでは候補やsession routingを公開しない。
	if( isStandardScanCancellationRequested( cancellation)) {
		invalidateScanSession() ;
		return makeCancelledStandardScan( scanSessionId) ;
	}

	result.outcome = aggregateOutcomes( outcomes) ;
	// 対象Providerに失敗が一つでも残る場合は全体を警告付き成功へ変更する。
	if( std::any_of( outputs.begin(), outputs.end(), []( const ProviderOutput &output) {
		   return (output.registration->phase == ProviderPhase::INVENTORY ||
				   output.registration->enabledForSession) &&
				  !output.scanResult.succeeded ;
	   })) {
		result.outcome = OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	}

	result.succeeded = true ;
	result.state	 = countDisplayCandidates( result) == 0 ? ProviderScanState::NO_CANDIDATES
														   : ProviderScanState::CANDIDATES_AVAILABLE ;
	// 取得後候補を同じscanへ追加する照合snapshot。
	displayedCandidates_ = result.candidates ;
	scanSessionId_		 = scanSessionId ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult CompositeUpdateProvider::install( const ScanSessionId				   scanSessionId,
											   const std::span<const std::wstring> identities,
											   const std::uintptr_t			   parentWindowNative,
											   const ProviderProgressCallback &progressCallback)
{
	// 空選択、未発行session、古いscanのinstall要求を全件拒否する。
	if( scanPurpose_ != ScanPurpose::STANDARD || identities.empty() || scanSessionId == 0 ||
	   scanSessionId != scanSessionId_) {
		return makeFailedInstall( identities, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	std::unordered_set<std::wstring> uniqueIdentities ;	// 重複検証済みの選択identity集合。
	std::unordered_set<std::wstring> uniqueDevices ;	// 一device一候補を検証するdevice集合。
	std::unordered_map<std::wstring, std::vector<std::wstring>>
		providerSelections ;	// Registry Provider ID別の選択identity群。
	// 選択をfail-closedで検証し、scan時のregistry routing先へ振り分ける。
	for( const std::wstring &identity : identities) {
		// 同じcandidate identityを二度処理する選択を全件拒否する。
		if( !uniqueIdentities.insert( identity).second) {
			return makeFailedInstall( identities, static_cast<NativeError>( E_INVALIDARG)) ;
		}

		const auto device = identityDevices_.find( identity) ;	// Identityに対応するdevice検索結果。
		// UI を迂回した同一 device の複数版 selection も system state 変更前に拒否する。
		if( device == identityDevices_.end() || !uniqueDevices.insert( device->second).second) {

			return makeFailedInstall( identities, static_cast<NativeError>( E_INVALIDARG)) ;
		}

		const auto provider = identityProviders_.find( identity) ;	// Scan時のrouting先。
		// 現在のscanでProviderへ登録されていないidentityを拒否する。
		if( provider == identityProviders_.end()) {
			return makeFailedInstall( identities, static_cast<NativeError>( E_INVALIDARG)) ;
		}

		providerSelections[provider->second].push_back( identity) ;
	}

	std::vector<InstallResult> providerResults ;	// 実行したproviderごとのinstall結果。
	providerResults.reserve( providerSelections.size()) ;
	const std::uint64_t totalItems = identities.size() ;	// 複合処理の選択候補総数。
	std::uint64_t		completedProviderItems{} ;			// 完了済み取得元に属する候補数。
	const auto			executeProvider = [&providerSelections, &providerResults, &progressCallback,
								   &completedProviderItems, totalItems, scanSessionId,
								   parentWindowNative]( RegisteredProvider &provider) {
		 const auto selection = providerSelections.find( provider.descriptor.id) ;	// Provider選択。
		 // 選択対象のないProviderと無効Providerのinstallを呼び出さない。
		 if( selection == providerSelections.end() || selection->second.empty() ||
			!provider.enabledForSession) {
			 return ;
		 }

		 const std::uint64_t			providerItems = selection->second.size() ;	// Provider候補数。
		 const ProviderProgressCallback providerProgress =
			 [&progressCallback, completedProviderItems, providerItems,
			  totalItems]( const ProviderProgress &progress) {
				 ProviderProgress aggregateProgress = progress ;	// 全体範囲へ変換する進捗値。
				 aggregateProgress.percentComplete = static_cast<std::uint32_t>(
					 (completedProviderItems * 100 +
					  providerItems * std::min<std::uint32_t>( progress.percentComplete, 100)) /
					 totalItems) ;
				 progressCallback( aggregateProgress) ;
			 } ;
		 providerResults.push_back( provider.install( scanSessionId, selection->second,
															parentWindowNative, providerProgress)) ;
		 completedProviderItems += providerItems ;
	} ; // Provider一件の進捗範囲と結果をaggregateへ追加する処理。

	// 外部Providerが現在deviceへINFを導入できるよう、inventory sessionを保持したまま先に実行する。
	for( RegisteredProvider &provider : providerRegistry_) {
		// network系の選択をDriver Storeより先に処理する。
		if( provider.phase != ProviderPhase::INVENTORY) {
			executeProvider( provider) ;
		}
	}

	// Driver Store自身のinstallはinventory sessionを失効させるため、必ず最後に実行する。
	for( RegisteredProvider &provider : providerRegistry_) {
		// Driver Storeの選択は他Providerの処理後に実行する。
		if( provider.phase == ProviderPhase::INVENTORY) {
			executeProvider( provider) ;
		}
	}

	// 選択件数とProviderへ渡した件数が一致しなければsessionを失効して失敗とする。
	if( completedProviderItems != totalItems) {
		invalidateScanSession() ;
		return makeFailedInstall( identities, static_cast<NativeError>( E_UNEXPECTED)) ;
	}

	InstallResult result{} ;	// 元selection順へ個別結果を集約する最終結果。
	result.updates.reserve( identities.size()) ;
	std::unordered_map<std::wstring, UpdateExecutionResult> updateResults ;	// Identity別個別結果。
	std::vector<OutcomeCode> downloadOutcomes ;								// Provider別download結果分類。
	std::vector<OutcomeCode> installOutcomes ;								// Provider別install結果分類。
	bool					 providerResultsValid{true} ;					// 全個別結果が選択と一対一ならtrue。
	// Provider別の全体結果と個別結果をidentity索引へ集約する。
	for( InstallResult &providerResult : providerResults) {
		downloadOutcomes.push_back( providerResult.downloadOutcome) ;
		installOutcomes.push_back( providerResult.installOutcome) ;
		result.rebootRequired = result.rebootRequired || providerResult.rebootRequired ;
		// 最初のdownload失敗だけを全体診断へ引き継ぐ。
		if( result.downloadError == 0 && providerResult.downloadError != 0) {
			result.downloadError = providerResult.downloadError ;
		}

		// 最初のinstall失敗だけを全体診断へ引き継ぐ。
		if( result.installError == 0 && providerResult.installError != 0) {
			result.installError = providerResult.installError ;
		}

		// Providerが返した個別結果のownershipをaggregate索引へ移す。
		for( UpdateExecutionResult &update : providerResult.updates) {
			// 未選択identityと重複した個別結果をProvider結果の不整合として扱う。
			if( !uniqueIdentities.contains( update.identity) ||
			   !updateResults.emplace( update.identity, std::move( update)).second) {
				providerResultsValid = false ;
			}
		}
	}

	// trueの場合は全selectionに対する個別結果が存在する。
	bool complete = providerResultsValid && updateResults.size() == identities.size() ;
	// Provider実行順ではなく利用者の元selection順で個別結果を再構成する。
	for( const std::wstring &identity : identities) {
		const auto iterator = updateResults.find( identity) ;	// 元selectionの個別結果検索位置。
		// 選択した候補の結果が欠落した場合は合成失敗を残し、全体成功にしない。
		if( iterator == updateResults.end()) {
			complete = false ;
			result.updates.push_back( {.identity		   = identity,
									  .downloadOutcome = OutcomeCode::FAILURE,
									  .downloadError   = static_cast<NativeError>( E_UNEXPECTED),
									  .installOutcome  = OutcomeCode::FAILURE,
									  .installError	   = static_cast<NativeError>( E_UNEXPECTED)}) ;
		} else {
			result.updates.push_back( std::move( iterator->second)) ;
		}
	}

	result.downloadOutcome = aggregateOutcomes( downloadOutcomes) ;
	result.installOutcome  = aggregateOutcomes( installOutcomes) ;
	result.succeeded	   = complete && std::all_of( providerResults.begin(), providerResults.end(),
													 []( const InstallResult &providerResult) {
													 return providerResult.succeeded ;
												 }) ;
	invalidateScanSession() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void CompositeUpdateProvider::invalidateScanSession() noexcept
{
	invalidatePreparation() ;
	officialDiscoveryRecordSession_.invalidate() ;
	officialDiscoveryHttpClient_.invalidateSourceSession() ;
	identityProviders_.clear() ;
	identityDevices_.clear() ;
	displayedCandidates_.clear() ;
	officialDiscoveryHints_.clear() ;
	officialDiscoveryCancellation_ = {} ;
	officialDiscoverySummary_.reset() ;
	reusableReleaseObservations_.clear() ;
	releaseEnvironmentFingerprints_ = {} ;
	// 全Registry entryの今回scan専用有効状態を破棄する。
	for( RegisteredProvider &provider : providerRegistry_) {
		provider.enabledForSession = false ;
	}

	scanSessionId_ = 0 ;
	scanPurpose_   = ScanPurpose::STANDARD ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationPlan> CompositeUpdateProvider::preparationPlan(
	const ScanSessionId scanSessionId, const std::uint64_t planId)
{
	// 失効した候補と新しい計画を結び付けない。
	if( scanPurpose_ != ScanPurpose::STANDARD || scanSessionId == 0U ||
	   scanSessionId != scanSessionId_ || planId == 0U) {
		return std::nullopt ;
	}

	OfficialPreparationPlan plan{
		scanSessionId, planId, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {}} ;	// 固定予算の所有計画。
	// 自動探索対象は一回だけ発行した計画IDへ結合し、別planによる再承認を拒否する。
	if( !officialDiscoveryPreparedPayloads_.empty()) {
		// 同じscanから異なる計画IDを再発行しない。
		if( officialDiscoveryPreparationPlanId_ != 0U) {
			throw std::logic_error( "automatic discovery preparation plan already issued") ;
		}

		officialDiscoveryPreparationPlanId_ = planId ;
		plan.targets.reserve( officialDiscoveryPreparedPayloads_.size()) ;
		// URL非保持対象だけをworker内取得状態から所有計画へ複製する。
		for( const OfficialDiscoveryPreparedPayload &prepared : officialDiscoveryPreparedPayloads_) {
			plan.targets.push_back( prepared.target) ;
		}
	}

	// 組み込みregistryだけから計画生成処理を選び、別のメーカー一覧を作らない。
	for( const RegisteredProvider &provider : providerRegistry_) {
		// 対象外と既存取得付きscanのProviderを新計画へ混ぜない。
		if( !provider.enabledForSession || !provider.preparationTargets) {
			continue ;
		}

		auto targets = provider.preparationTargets( scanSessionId, planId) ;	// 非機密対象値。
		// 計画だけの異常をworkerへ返す。
		if( targets.size() > 256U - plan.targets.size()) {
			throw std::length_error( "preparation target limit") ;
		}

		// 当該registryのProvider IDとの一致を確認してから所有権を集約する。
		for( OfficialPreparationTarget &target : targets) {
			// 異常を対象なしにしない。
			if( target.providerId != provider.descriptor.id) {
				throw std::logic_error( "preparation provider mismatch") ;
			}

			plan.targets.push_back( std::move( target)) ;
		}
	}

	// 準備対象がない場合は空の承認計画を発行しない。
	if( plan.targets.empty()) {
		return std::nullopt ;
	}

	return plan ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void CompositeUpdateProvider::invalidatePreparation() noexcept
{
	// 内容検査結果を先に解放してから外側取得fileの保護workspaceを破棄する。
	officialDiscoveryPreparedPayloads_.clear() ;
	officialDiscoveryAcquisitionSession_.reset() ;
	officialDiscoveryWorkspace_.reset() ;
	// Claim済みrecord内の未使用秘密URLと未claim recordを同時に失効させる。
	officialDiscoveryClaimedRecords_.clear() ;
	officialDiscoveryRecordSession_.invalidate() ;
	officialDiscoveryEulaSession_.invalidate() ;
	officialDiscoveryAcceptedEulaGroups_.clear() ;
	officialDiscoveryPreparationPlanId_ = 0U ;
	nextOfficialDiscoveryGrantId_		= 1U ;
	// 組み込みのnoexcept callbackだけを呼び、別のProvider一覧を持たない。
	for( RegisteredProvider &provider : providerRegistry_) {
		// 準備状態を持つProviderだけにその失効を委譲し、既存install routingは保つ。
		if( provider.invalidatePreparation) {
			provider.invalidatePreparation() ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult CompositeUpdateProvider::acquireForInspection(
	const OfficialPreparationTask &task, const PreparationCancellation &cancellation)
{
	// 未発行operation・session・planと古いscanからの取得要求を拒否する。
	if( scanPurpose_ != ScanPurpose::STANDARD || task.operationId == 0U ||
	   task.scanSessionId == 0U || task.scanSessionId != scanSessionId_ || task.planId == 0U) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_INVALIDARG), 0} ;
	}

	const auto automaticPrepared = std::find_if(
		officialDiscoveryPreparedPayloads_.begin(), officialDiscoveryPreparedPayloads_.end(),
		[&task]( const OfficialDiscoveryPreparedPayload &prepared) {
			return prepared.target.identity == task.target.identity ;
		}) ; // 自動探索のopaque対象ID完全一致位置。
	// 自動探索対象はregistry固有callbackへ渡さずrecord限定共通取得を一度だけ実行する。
	if( automaticPrepared != officialDiscoveryPreparedPayloads_.end()) {
		OfficialDiscoveryPreparedPayload &prepared = *automaticPrepared ;	// 今回対象の保持状態。
		// Plan、target、group、一回性を取得権限の使用前に再照合する。
		if( officialDiscoveryPreparationPlanId_ == 0U || !officialDiscoverySummary_ ||
		   task.planId != officialDiscoveryPreparationPlanId_ || task.target != prepared.target ||
		   prepared.attempted || !isOfficialDiscoveryPackageGroupValid( prepared.group) ||
		   prepared.group.recordEvidenceIds.empty() ||
		   officialDiscoverySummary_->request.inspectionPermission !=
			   OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE) {
			return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_INVALIDARG),
					0U} ;
		}

		// 取消し・失敗後も同じ承認taskから秘密URLを再使用しない。
		prepared.attempted = true ;
		try {
			// EULA必須対象はworkerが発行した同じgroup tokenへ今回の許可を一度だけ記録する。
			if( prepared.eulaRequired) {
				const std::uint64_t tokenValue =
					prepared.target.sharedEulaToken ;	// UI表示済みtoken。
				const auto eulaGroups =
					// 現在scanのEULA群。
					officialDiscoveryEulaSession_.groups() ;
				// 0、範囲外または判断状態欠落tokenを同意済みへ補完しない。
				if( tokenValue == 0U || tokenValue > eulaGroups.size() ||
				   officialDiscoveryAcceptedEulaGroups_.size() != eulaGroups.size()) {
					return {OfficialPreparationItemState::REJECTED,
							static_cast<NativeError>( E_ACCESSDENIED), 0U} ;
				}

				const std::size_t tokenIndex =
					// 検証済みEULA group index。
					static_cast<std::size_t>( tokenValue - 1U) ;
				const OfficialDiscoveryEulaGroupToken &token =
					eulaGroups[tokenIndex].token ;	// Binding込みのworker token。
				// 同じgroupの最初の選択対象だけでUI承認済み判断を記録する。
				if( !officialDiscoveryAcceptedEulaGroups_[tokenIndex]) {
					const NativeError decisionError = officialDiscoveryEulaSession_.recordDecision(
						officialDiscoveryRecordSession_.activeBinding(), token,
						true) ;	// Task発行前のCore承認で全文同意を検証済み。
					// Staleまたは再判断拒否後にpayload grantを発行しない。
					if( decisionError != 0) {
						return {OfficialPreparationItemState::REJECTED, decisionError, 0U} ;
					}

					officialDiscoveryAcceptedEulaGroups_[tokenIndex] = true ;
				}

				// 取得直前にもProvider、revision、全文hash、package、予算を完全一致で照合する。
				if( !officialDiscoveryEulaSession_.isPackageAccepted(
					   officialDiscoveryRecordSession_.activeBinding(), token,
					   prepared.eulaPackage)) {
					return {OfficialPreparationItemState::REJECTED,
							static_cast<NativeError>( E_ACCESSDENIED), 0U} ;
				}
			}

			const std::uint64_t evidenceId =
				// Group初出の秘密record証拠ID。
				prepared.group.recordEvidenceIds.front() ;
			auto claimed =
				// Claim済みrecord位置。
				officialDiscoveryClaimedRecords_.find( evidenceId) ;
			// 初回だけrecord adapterから秘密URLの所有権を一回claimする。
			if( claimed == officialDiscoveryClaimedRecords_.end()) {
				ResolvedOfficialDistributionRecord record ;	// Adapterから受け取る秘密record所有値。
				const NativeError claimError = officialDiscoveryRecordSession_.claimResolvedRecord(
					task.scanSessionId, evidenceId, record) ;	// Staleと再claimをadapterで拒否する。
				// Claim失敗時に別証拠IDまたは公開値からURLを再構成しない。
				if( claimError != 0) {
					return {OfficialPreparationItemState::REJECTED, claimError, 0U} ;
				}

				const auto inserted = officialDiscoveryClaimedRecords_.emplace(
					evidenceId, std::move( record)) ;	// 後続grant発行まで秘密recordを所有する。
				// 証拠ID衝突時は移動済みrecordを別IDへfallbackしない。
				if( !inserted.second) {
					return {OfficialPreparationItemState::REJECTED,
							static_cast<NativeError>( E_UNEXPECTED), 0U} ;
				}

				claimed = inserted.first ;
			}

			// Grant IDの上限後に0へwrapして過去権限を再使用しない。
			if( nextOfficialDiscoveryGrantId_ == std::numeric_limits<std::uint64_t>::max()) {
				return {OfficialPreparationItemState::REJECTED,
						static_cast<NativeError>( E_UNEXPECTED), 0U} ;
			}

			const std::optional<std::uint64_t> issuedUtcSeconds =
				// 発行時UTC。
				currentUtcSeconds() ;
			// 時計を確定できない場合は期限付きgrantを発行しない。
			if( !issuedUtcSeconds) {
				return {OfficialPreparationItemState::FAILURE,
						static_cast<NativeError>( E_UNEXPECTED), 0U} ;
			}

			const std::uint64_t grantId =
				// 今回だけの単調grant ID。
				nextOfficialDiscoveryGrantId_++ ;
			RecordScopedDownloadGrant grant ;	// Secret URLをHTTP requestへ一回だけ移すgrant。
			const NativeError		  grantError = grant.issue(
				claimed->second.record, claimed->second.evidence, prepared.group.payloadOrdinal,
				grantId, *issuedUtcSeconds, 0U) ;	// URL以外のstable recordを再検証して発行する。
			// Record、期限またはpayload不整合時は通信を開始しない。
			if( grantError != 0) {
				return {OfficialPreparationItemState::REJECTED, grantError, 0U} ;
			}

			const RecordScopedDownloadGrantMetadata &grantMetadata =
				// Grant結合値。
				grant.metadata() ;
			const RecordScopedDownloadGrantPayloadView payload =
				// 公開payload値。
				grant.payloadView() ;
			// Target、group、record、grantの全fieldをHTTP開始前に相互照合する。
			if( grantMetadata.recordEvidenceId != evidenceId ||
			   grantMetadata.providerId != prepared.group.providerId ||
			   grantMetadata.policyId != prepared.group.policyId ||
			   grantMetadata.rootResourceId != prepared.group.rootResourceId ||
			   grantMetadata.recordFingerprint.bytes != prepared.group.recordFingerprint.bytes ||
			   grantMetadata.payloadOrdinal != prepared.group.payloadOrdinal ||
			   payload.resourceId != prepared.target.resourceId ||
			   payload.maximumBytes != prepared.target.maximumBytes) {
				return {OfficialPreparationItemState::REJECTED,
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)), 0U} ;
			}

			// 一scan全体で共有する保護workspaceと成功取得ledgerを最初の選択時だけ開始する。
			if( !officialDiscoveryWorkspace_ || !officialDiscoveryAcquisitionSession_) {
				auto workspace = std::make_unique<OfficialDownloadWorkspace>() ;	// 初期化前領域。
				auto acquisitionSession =
					std::make_unique<OfficialAcquisitionSession>() ;	// 初期化前取得ledger。
				const OfficialDiscoveryPayloadLimits &payloadLimits =
					officialDiscoverySummary_->request.payloadLimits ;	// UI承認時の固定予算。
				const OfficialAcquisitionLimits limits{
					.maximumFileBytes	  = payloadLimits.maximumFileBytes,
					.maximumProviderBytes = payloadLimits.maximumProviderBytes,
					.maximumSessionBytes  = payloadLimits.maximumSessionBytes,
					.minimumFreeBytes	  = 256ULL * 1'024ULL * 1'024ULL,
					.maximumProviderFiles = payloadLimits.maximumProviderFiles,
					.maximumSessionFiles  = payloadLimits.maximumSessionFiles} ;	// 取得層予算。
				NativeError initializationError = workspace->initialize(
					L"automatic-official", task.scanSessionId) ;	// 保護領域作成。
				// Workspace成功時だけ同じscanの取得ledgerを初期化する。
				if( initializationError == 0) {
					initializationError =
						acquisitionSession->initialize( task.scanSessionId, limits) ;
				}

				// 初期化失敗時はlocal所有objectの既知path cleanupへ委ねて通信しない。
				if( initializationError != 0) {
					return {OfficialPreparationItemState::FAILURE, initializationError, 0U} ;
				}

				officialDiscoveryWorkspace_			 = std::move( workspace) ;
				officialDiscoveryAcquisitionSession_ = std::move( acquisitionSession) ;
			}

			const std::wstring workspaceFileName =
				L"payload-" + std::to_wstring( grantId) + L".bin" ;	// UI値を使わない一意な保存名。
			OfficialAcquisitionRequest acquisitionRequest ;			// Record限定値だけを持つ取得要求。
			acquisitionRequest.workspaceFileName		 = workspaceFileName ;
			acquisitionRequest.restrictedNetworkApproved = task.restrictedNetworkApproved ;
			acquisitionRequest.delegatedGrant			 = &grant ;
			acquisitionRequest.delegatedGrantId			 = grantId ;
			acquisitionRequest.delegatedUtcNow			 = []() noexcept {
				  return currentUtcSeconds().value_or( 0U) ;
			} ; // HTTP claim直前と各hopは実UTCを再確認する。
			OfficialHttpAcquisitionTransport transport(
				officialDiscoveryHttpClient_) ;				// HTTP adapter。
			WindowsOfficialNetworkCostReader   costReader ;	// Windows標準のmachine-wide cost照会。
			const HttpDownloadProgressCallback progress = []( std::uint64_t, std::uint64_t) {
			} ; // 外側workerは確定対象件数だけを通知する。
			OfficialAcquisitionResult acquisition ;	// URL非保持の今回取得結果。
			const NativeError acquisitionError = officialDiscoveryAcquisitionSession_->acquire(
				acquisitionRequest, *officialDiscoveryWorkspace_, transport, costReader, progress,
				cancellation, acquisition) ;	// 共通HTTPS、予算、hash、size、SSRF検証を実行する。
			prepared.acquisition = acquisition ;
			const OfficialPreparationTransferResult transfer =
				automaticDiscoveryTransferResult( acquisitionError, task,
												 acquisition) ;	// 内容監査と分離した取得結果。
			// 取得に成功しなければ内容検査を開始せず確定した理由を返す。
			if( transfer.state != OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION ||
			   transfer.error != 0) {
				return transfer ;
			}

			// INF archiveだけをURL非保持入力へ変換し、installerを共通INF検査へ偽装しない。
			if( payload.kind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE) {
				DelegatedOfficialPackageInput packageInput ;	// 共通内容検査へ渡す由来結合入力。
				// 取得由来の入力変換または後続内容検査が返す最初の診断値。
				NativeError					  inspectionError =
					makeDelegatedOfficialPackageInput( acquisition, grant, packageInput) ;
				CommonDriverPackageInspection packageInspection ;	// 内容検査の全体・個別結果。
				// 変換成功した取得物だけをZIP／CAB共通driver-only監査へ渡す。
				if( inspectionError == 0) {
					inspectionError = inspectDelegatedOfficialDriverPackage(
						task.scanSessionId, packageInput, packageInspection,
						cancellation) ;	// Install、stageまたは候補選択は行わない。
				}

				std::vector<DelegatedOfficialDeviceApplicability>
					applicability ;	// Device別PnP集計。
				NativeError
					applicabilityError{} ;	// 全PnP観測の診断値。内容未合格時は未実施の0です。
				// 内容検査全体が完了した場合だけ、groupの全deviceを現在inventoryへ再結合する。
				if( inspectionError == 0) {
					std::vector<OfficialDiscoveryDeviceHint>
						devices ;	// Group順のlocal device hint集合。
					devices.reserve( prepared.group.deviceIdentities.size()) ;
					// 秘密PnP IDを使わず、scan内opaque identity完全一致で各deviceを取り出す。
					for( const std::wstring &deviceIdentity : prepared.group.deviceIdentities) {
						const auto hint = std::find_if(
							officialDiscoveryHints_.begin(), officialDiscoveryHints_.end(),
							[&deviceIdentity]( const OfficialDiscoveryDeviceHint &value) {
								return value.deviceIdentity == deviceIdentity ;
							}) ; // 現在scanのdevice hint位置。
						// Groupが現在inventoryへ完全には戻らない場合はPnP全体失敗とする。
						if( hint == officialDiscoveryHints_.end()) {
							applicabilityError = static_cast<NativeError>(
								HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
							devices.clear() ;
							break ;
						}

						devices.push_back( *hint) ;
					}

					// 全deviceがそろった場合だけDriver Storeのread-only rank観測を呼ぶ。
					if( applicabilityError == 0) {
						const DelegatedOfficialInfRankObserver rankObserver =
							[this]( const ScanSessionId session, std::wstring_view deviceIdentity,
								   const OfficialDownloadWorkspace &workspace,
								   const OfficialInfPackage		   &package,
								   std::optional<std::uint32_t>	   &candidateRank) {
								return driverStoreProvider_.observeInfCandidateRank(
									session, deviceIdentity, workspace, package, candidateRank) ;
							} ; // Windows標準候補nodeを観測し、stageやinstallを行わないcallback。
						applicabilityError = inspectDelegatedOfficialDriverApplicability(
							task.scanSessionId, packageInput, packageInspection, devices,
							rankObserver, applicability, cancellation) ;
					}
				}

				prepared.packageInput		= std::move( packageInput) ;
				prepared.packageInspection	= std::move( packageInspection) ;
				prepared.applicability		= std::move( applicability) ;
				prepared.inspectionError	= inspectionError ;
				prepared.applicabilityError = applicabilityError ;
			} else {
				// 公式installerは取得成功を維持し、専用監査未接続を独立診断として保持する。
				prepared.inspectionError =
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
			}

			// 内容拒否または専用監査未接続でもdownload成功を上書きしない。
			return transfer ;
		} catch( const std::bad_alloc &) {
			return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_OUTOFMEMORY),
					0U} ;
		} catch( ...) {
			// Worker境界外へ例外を漏らさず同じ秘密URLを再使用不能のまま失敗させる。
			return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_UNEXPECTED),
					0U} ;
		}
	}

	// 現在scanで有効なProvider一件だけへ照合tokenを渡す。
	for( const RegisteredProvider &provider : providerRegistry_) {
		// stable ID一致、有効状態、取得capabilityが揃うProviderへだけ要求を渡す。
		if( provider.descriptor.id == task.target.providerId && provider.enabledForSession &&
		   provider.acquireForInspection) {
			return provider.acquireForInspection( task, cancellation) ;
		}
	}

	return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_NOTIMPL), 0} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

std::vector<OfficialPreparationAuditReport> CompositeUpdateProvider::preparationAuditReports(
	const OfficialPreparationOperationResult &result)
{
	std::vector<OfficialPreparationAuditReport> reports ;	// 最大256対象の表示結果。
	// 別sessionと未承認操作へ保持監査を結び付けない。
	if( scanPurpose_ != ScanPurpose::STANDARD || result.scanSessionId == 0U ||
	   result.scanSessionId != scanSessionId_ || result.operationId == 0U || result.planId == 0U ||
	   result.approvalError != OfficialPreparationError::NONE || result.controlError != 0) {
		return reports ;
	}

	// 監査表示の対象数が固定上限を超える結果を受理しない。
	if( result.items.size() > 256U) {
		throw std::length_error( "preparation audit report limit") ;
	}

	auto nextIdentityProviders = identityProviders_ ;						// 全件成功時だけ反映するrouting候補。
	auto nextIdentityDevices   = identityDevices_ ;							// 全件成功時だけ反映するdevice対応。
	std::vector<UpdateCandidate> nextCandidates = displayedCandidates_ ;	// 検証用の表示snapshot。
	try {
		// 取得成功した対象だけを照会し、未取得対象へ監査結果を発行しない。
		for( const OfficialPreparationItem &item : result.items) {
			// 検査用取得が完了していない対象から監査reportを要求しない。
			if( item.result.state != OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) {
				continue ;
			}

			const auto automaticPrepared =
				std::find_if( officialDiscoveryPreparedPayloads_.begin(),
							 officialDiscoveryPreparedPayloads_.end(),
							 [&item]( const OfficialDiscoveryPreparedPayload &prepared) {
								 return prepared.target.identity == item.identity ;
							 }) ; // 自動探索取得物のworker内監査状態。
			// 自動探索対象はregistry固有reportへ渡さず、既存表示行だけを原子的に更新する。
			if( automaticPrepared != officialDiscoveryPreparedPayloads_.end()) {
				const OfficialDiscoveryPreparedPayload &prepared =
					*automaticPrepared ;	// 固定監査入力。
				auto report =
					// 自動探索取得物へ対応する非機密監査reportです。
					makeDelegatedOfficialPreparationAuditReport(
						prepared.target, prepared.group, prepared.descriptor,
						prepared.candidateIdentities, prepared.acquisition,
						prepared.inspectionError, prepared.packageInspection,
						prepared.applicabilityError, prepared.applicability) ;
				// 取得成功した自動対象に不整合があれば、部分的な監査行を反映しない。
				if( !report || report->targetIdentity != item.identity || reports.size() >= 256U ||
				   !validatePreparationCandidatePublication( *report, nextCandidates)) {
					throw std::logic_error( "automatic preparation audit mismatch") ;
				}

				std::unordered_map<std::wstring_view, const OfficialPreparationCandidateAudit *>
					updates ;	// 現report内だけ有効な既存候補ID索引。
				updates.reserve( report->candidates.size()) ;
				// 重複行を拒否し、監査以外のcandidate fieldは複製しない。
				for( const OfficialPreparationCandidateAudit &row : report->candidates) {
					// 同じ候補を一reportで複数回更新しない。
					if( !updates.emplace( row.identity, &row).second) {
						throw std::logic_error( "automatic preparation audit duplicate") ;
					}
				}

				std::size_t updatedCount{} ;	// 既存候補へ完全対応した監査行数。
				// Composite保持snapshotもUIと同じ監査結果へ更新し、次の検証で旧状態を使わない。
				for( UpdateCandidate &candidate : nextCandidates) {
					const auto update = updates.find( candidate.identity) ;	// 現在候補の監査行。
					// 対応行だけを取得済み監査へ更新し、選択可能性は変更しない。
					if( update != updates.end()) {
						candidate.audit			   = update->second->audit ;
						candidate.allContentCached = true ;
						// Scan時の未取得詳細を取得後も真であるかのように残さない。
						if( candidate.assessment && candidate.assessment->acquisition.reason ==
													   CandidateAssessmentReason::NOT_ACQUIRED) {
							candidate.assessment.reset() ;
						}

						++updatedCount ;
					}
				}

				// 未知IDを含むreportは保持snapshotへ一部だけ適用しない。
				if( updatedCount != report->candidates.size()) {
					throw std::logic_error( "automatic preparation audit candidate mismatch") ;
				}

				reports.push_back( std::move( *report)) ;
				continue ;
			}

			// 各Providerが保持する対象IDとの完全一致で当該reportだけを返す。
			for( const RegisteredProvider &provider : providerRegistry_) {
				// 無効Providerと監査reportを実装しないProviderは集約対象にしない。
				if( !provider.enabledForSession || !provider.preparationAuditReport) {
					continue ;
				}

				auto report = provider.preparationAuditReport(
					result.scanSessionId, item.identity) ;	// 非機密値の所有snapshot。
				// reportが得られた場合にだけその結合と追加候補を検証する。
				if( report) {
					// reportのProvider・対象identity不一致と上限超過を全件拒否する。
					if( report->providerId != provider.descriptor.id ||
					   report->targetIdentity != item.identity || reports.size() >= 256U) {
						throw std::logic_error( "preparation audit provider mismatch") ;
					}

					// 既存scanとの候補発行整合性を検証できなければroutingを変更しない。
					if( !validatePreparationCandidatePublication( *report, nextCandidates)) {
						throw std::logic_error( "preparation candidate publication mismatch") ;
					}

					// 新候補を一件ずつ複製routingへ加え、ID衝突時は全reportを拒否する。
					for( const UpdateCandidate &candidate : report->publishedCandidates) {
						// 追加候補のdeviceまたはProvider routingでID衝突した場合は全reportを拒否する。
						if( !nextIdentityDevices
								.emplace( candidate.identity, candidate.deviceIdentity)
								.second ||
						   !nextIdentityProviders
								.emplace( candidate.identity, provider.descriptor.id)
								.second) {
							throw std::logic_error( "preparation candidate routing collision") ;
						}

						nextCandidates.push_back( candidate) ;
					}

					reports.push_back( std::move( *report)) ;
				}
			}
		}

		// 全report成功後の原子的な反映。
		identityProviders_.swap( nextIdentityProviders) ;
		identityDevices_.swap( nextIdentityDevices) ;
		displayedCandidates_.swap( nextCandidates) ;
		// 全report・全cloneの検証後だけ索引tokenをnoexcept swap commitします。
		if( signedIndexSession_) {
			signedIndexSession_->binding_.commit() ;
		}
	} catch( ...) {
		// 索引transaction失敗では新tokenだけをdiscardし、他Providerの既存routingを保持します。
		if( signedIndexSession_ && signedIndexSession_->binding_.pending_) {
			signedIndexSession_->binding_.rollback( driverStoreProvider_) ;
		} else {
			invalidatePreparation() ;
		}

		throw ;
	}

	return reports ;
}

/** @see composite_update_provider.h */
void CompositeUpdateProvider::bindSignedIndexSession(
	SignedIndexScanSession &session, const provider_worker_index_detail::Services &services,
	const OperationId operationId, ProviderScanCancellation cancellation) noexcept
{
	signedIndexSession_		 = &session ;
	signedIndexServices_	 = &services ;
	signedIndexOperation_	 = operationId ;
	signedIndexCancellation_ = std::move( cancellation) ;
	signedIndexSummary_		 = {} ;
	session.bindingStore_	 = &driverStoreProvider_ ;
}
/** @see composite_update_provider.h */
void CompositeUpdateProvider::finishSignedIndexScanPublication( const OfficialPreparationPlan &plan,
															   ScanResult &result)
{
	// 署名索引が未成立・未有効なら通常Provider候補をそのまま維持します。
	if( !signedIndexSession_ || !signedIndexSession_->acquisitionLookup_) {
		return ;
	}

	// 同snapshotと原計画から発行する非導入参照の所有copy。全検証後だけcommitする。
	auto references = signedIndexSession_->binding_.makeReferences(
		signedIndexSession_->acquisitionLookup_, signedIndexSession_->adapter_, plan,
		displayedCandidates_, officialDiscoveryHints_) ;
	auto providers	 = identityProviders_ ;		// 全検証後にだけswapするrouting。
	auto devices	 = identityDevices_ ;		// 全検証後にだけswapするdevice対応。
	auto candidates	 = displayedCandidates_ ;	// 他Providerを保持した所有snapshot。
	auto publication = result.candidates ;		// UIへ同時発行する所有snapshot。
	// 同Provider・同deviceの参照identityを一意に追加します。
	for( const auto &candidate : references) {
		// 索引参照の監査または一意IDが不整合なら公開前に全体を拒否します。
		if( !isCandidateAuditValid( candidate, descriptorFor( SIGNED_INDEX_PROVIDER_ID)) ||
		   !providers.emplace( candidate.identity, candidate.providerId).second ||
		   !devices.emplace( candidate.identity, candidate.deviceIdentity).second) {
			throw std::logic_error( "index reference publication mismatch") ;
		}

		candidates.push_back( candidate) ;
		publication.push_back( candidate) ;
	}

	identityProviders_.swap( providers) ;
	identityDevices_.swap( devices) ;
	displayedCandidates_.swap( candidates) ;
	result.candidates.swap( publication) ;
}

/** @see src/platform/composite_update_provider.h 宣言側の契約を正本とする。 */
NativeError CompositeUpdateProvider::preflightRequiredSignedIndexInstall(
	const ScanSessionId session, const std::span<const std::wstring> identities) const
{
	// 元workerの索引owner未結合では必要計画を発行していません。
	if( !signedIndexSession_ || !signedIndexServices_) {
		return 0 ;
	}

	return signedIndexSession_->binding_.preflightRequiredInstall(
		*signedIndexSession_, driverStoreProvider_, *signedIndexServices_, session, identities) ;
}

} // namespace drivercrate
