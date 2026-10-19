//------------------------------------------------------------------------------
/**
 * @file official_delegated_package_inspection.h
 * @brief Record限定取得結果と共通driver package検査の接続定義。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record限定取得と共通内容検査のadapterを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  公式由来を表示専用候補評価へ再結合。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Device別PnP観測と取得後表示reportを追加。
 * </pre>
 *
 * @note 本型と関数はProvider worker内だけで使用します。秘密URLと実pathをUI、log、cacheへ渡さず、
 *       取得成功を内容、適用性、推奨または導入可能性の合格へ昇格させません。
 * @see docs/adr/0151-common-package-content-and-origin-separation.md
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/common_driver_package.h"
#include "core/official_discovery.h"
#include "core/official_preparation.h"
#include "core/official_preparation_audit.h"
#include "platform/official_acquisition.h"
#include "platform/official_download_grant.h"
#include "platform/official_record_payload_routing.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief URLを含まず一つの取得ledger行とrecord限定grantを結合するworker内証拠です。
 */
struct DelegatedOfficialPackageProvenance {
	/// 成功取得を所有するscan session IDです。
	ScanSessionId					scanSessionId{} ;
	/// Session内で単調増加する成功取得ledger IDです。
	std::uint64_t					acquisitionId{} ;
	/// Provider registryのstable IDです。
	std::wstring					providerId ;
	/// 組み込み公式取得元policyのstable IDです。
	std::wstring					policyId ;
	/// Recordを得たlandingまたはmetadata resource IDです。
	std::wstring					rootResourceId ;
	/// 取得したpayload resource IDです。
	std::wstring					payloadResourceId ;
	/// Grant発行元のopaque record証拠IDです。
	std::uint64_t					recordEvidenceId{} ;
	/// 消費済みのopaque download grant IDです。
	std::uint64_t					downloadGrantId{} ;
	/// Record内の0起点payload行番号です。
	std::uint32_t					payloadOrdinal{} ;
	/// URLを含まないstable record fingerprintです。
	OfficialStableRecordFingerprint recordFingerprint ;
	/// RootからURLを再解決した0または1の回数です。
	std::uint32_t					grantReresolutionCount{} ;
	/// 全hopでpublicと検証したDNS address数です。
	std::uint32_t					validatedDestinationAddressCount{} ;
	/// 全hopをworker内でlocal解決した場合trueです。
	bool							destinationLocallyResolved{} ;
	/// 公開exact sizeが存在し、実取得sizeと一致した場合trueです。
	bool							publishedSizeVerified{} ;
	/// 公開SHA-256が存在し、実取得hashと一致した場合trueです。
	bool							publishedSha256Verified{} ;
} ;

/**
 * @brief Record限定取得から共通内容検査へ渡すworker内入力です。
 * @note `archive.inspectionPath`は取得workspaceが所有し、本値はそのworkspaceより長く保持しません。
 */
struct DelegatedOfficialPackageInput {
	/// 由来能力を持たない固定済みarchive identityです。
	DriverArchiveInput				   archive ;
	/// Recordが明示したbasenameだけから決めた共通検査形式です。
	OfficialDriverArchiveFormat		   format{OfficialDriverArchiveFormat::ZIP} ;
	/// 取得ledgerと消費済みrecord grantのURL非保持結合証拠です。
	DelegatedOfficialPackageProvenance provenance ;
} ;

/**
 * @brief 一つのdeviceについて内容合格INFとのread-only PnP観測件数を保持します。
 */
struct DelegatedOfficialDeviceApplicability {
	/// 入力hintと同じscan内のopaque device identityです。
	std::wstring  deviceIdentity ;
	/// Windows候補nodeを照会したINF組合せ数です。
	std::uint32_t examinedPairCount{} ;
	/// 一致するWindows候補nodeを確認したINF組合せ数です。
	std::uint32_t applicablePairCount{} ;
	/// Windows APIを完了できなかったINF組合せ数です。
	std::uint32_t failedPairCount{} ;
	/// 最初の個別Windows API失敗HRESULTです。失敗なしは0です。
	NativeError	  firstPairError{} ;
} ;

/**
 * @brief 一つの検証済みINF閉包を一deviceへread-only照合するcallbackです。
 * @param[in] scanSessionId 現在inventoryと内容検査に共通するscan session IDです。
 * @param[in] deviceIdentity UIへ提示済みのopaque device identityです。
 * @param[in] workspace 検証済みINF閉包を所有する保護workspaceです。
 * @param[in] package 内容と署名を検証した一INFです。
 * @param[out] candidateRank 一致時のWindows candidate rank、非適用時は空です。
 * @return 全Windows列挙完了時0、入力またはSetupAPI失敗時はHRESULTです。
 */
using DelegatedOfficialInfRankObserver = std::function<NativeError(
	ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::optional<std::uint32_t> &candidateRank)> ;

/**
 * @brief Record限定取得結果と消費済みgrantを共通package検査入力へ変換します。
 * @param[in] acquisition 成功取得ledgerが公開したworker内結果です。
 * @param[in] grant 当該取得で一回使用され、成功終端したrecord限定grantです。
 * @param[out] input 成功時だけ設定するURL非保持の共通検査入力です。
 * @return 全ID、状態、公開metadata検証結果、形式と実file identityが一致すれば0です。
 * @post 失敗時は`input`を初期値へ戻します。
 * @note 形式はgrantが保持する公開basenameからだけ決定し、実pathやURLから推測しません。
 */
[[nodiscard]] NativeError makeDelegatedOfficialPackageInput(
	const OfficialAcquisitionResult &acquisition, const RecordScopedDownloadGrant &grant,
	DelegatedOfficialPackageInput &input) noexcept ;

/**
 * @brief 現在sessionのrecord限定取得fileをADR 0151の共通内容検査へ渡します。
 * @param[in] activeScanSessionId 現在のworker scan session IDです。
 * @param[in] input 取得workspaceの存続中だけ有効な変換済み入力です。
 * @param[out] inspection 全体成功時は個別INF結果、全体失敗時は診断値だけを保持します。
 * @param[in] cancellation 空またはworker内で呼ぶ非blocking取消し照会です。
 * @return 共通検査完了時0、stale、入力不整合、取消しまたは検査失敗時はHRESULTです。
 * @note 個別INF拒否は他のINF検査を止めません。導入、stagingまたは由来合格は行いません。
 */
[[nodiscard]] NativeError inspectDelegatedOfficialDriverPackage(
	ScanSessionId activeScanSessionId, const DelegatedOfficialPackageInput &input,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

/**
 * @brief 内容合格INFを結合済みdeviceへWindows標準APIでread-only照合します。
 * @param[in] activeScanSessionId 現在のworker scan session IDです。
 * @param[in] input 同じ取得物のURL非保持入力です。
 * @param[in] packageInspection 全体成功済みの共通INF検査結果です。
 * @param[in] devices Package groupへ結合した重複なしdevice hint集合です。
 * @param[in] rankObserver Driver Storeが所有する現在PnP候補node照会です。
 * @param[out] results 成功時だけdevicesと同順の有限件数結果です。
 * @param[in] cancellation 空またはworker内で呼ぶ非blocking取消し照会です。
 * @return 全組合せを確認した場合0、stale、入力不整合、取消しまたは例外時はHRESULTです。
 * @post 失敗時は全結果を空にし、stage、driver選択またはinstallを行いません。
 */
[[nodiscard]] NativeError inspectDelegatedOfficialDriverApplicability(
	ScanSessionId activeScanSessionId, const DelegatedOfficialPackageInput &input,
	const CommonDriverPackageInspection				  &packageInspection,
	std::span<const OfficialDiscoveryDeviceHint>	   devices,
	const DelegatedOfficialInfRankObserver			  &rankObserver,
	std::vector<DelegatedOfficialDeviceApplicability> &results,
	const std::function<bool()>						  &cancellation = {}) ;

/**
 * @brief 取得、内容検査、device別PnP観測を既存表示行の非機密reportへ変換します。
 * @param[in] target 利用者が取得を承認したURL非保持準備対象です。
 * @param[in] group 同じpayloadをrecord、routeとdeviceへ結合した実行groupです。
 * @param[in] descriptor Scan時に同じtargetへ結合したpayload方式と公開metadataです。
 * @param[in] candidateIdentities Groupのdevice順にscanで発行済みの候補ID集合です。
 * @param[in] acquisition Record限定取得の成功ledger行です。
 * @param[in] inspectionError 内容検査または専用監査未接続の診断値です。
 * @param[in] packageInspection 標準INF方式で得た全体・個別内容検査結果です。
 * @param[in] applicabilityError Device別PnP観測の全体診断値です。正常完了時は0です。
 * @param[in] applicability 正常完了時だけcandidateIdentitiesと同順のPnP集計です。
 * @return 全bindingと件数が整合する場合は監査report、それ以外は値なしです。
 * @post 適用性が合格しても候補発行とinstall routingは開始しません。
 */
[[nodiscard]] std::optional<OfficialPreparationAuditReport>
makeDelegatedOfficialPreparationAuditReport(
	const OfficialPreparationTarget &target, const OfficialDiscoveryPackageGroup &group,
	const OfficialRecordPayloadDescriptor &descriptor,
	std::span<const std::wstring> candidateIdentities, const OfficialAcquisitionResult &acquisition,
	NativeError inspectionError, const CommonDriverPackageInspection &packageInspection,
	NativeError											  applicabilityError,
	std::span<const DelegatedOfficialDeviceApplicability> applicability) ;

/**
 * @brief 共通内容検査の一INFと公式record由来を表示専用候補の八軸評価へ再結合します。
 * @param[in] activeScanSessionId 現在のworker scan session IDです。
 * @param[in] input 当該package検査を開始したURL非保持入力です。
 * @param[in] candidate Provider IDとopaque identityを設定済みの表示候補です。
 * @param[in] packageInspection `input`から得た全体成功の共通検査結果です。
 * @param[in] infOrdinal 結合する0起点INF結果番号です。
 * @param[in] packageEvidenceId Scan内で実内容検査へ割り当てた0ではない証拠IDです。
 * @param[in] applicabilityError Windows適合観測のHRESULTです。未実施を0で渡しません。
 * @param[in] candidateRank Windowsの一致node rankです。非適用・失敗時は空です。
 * @param[out] assessment 成功時の表示専用八軸評価です。失敗時は空です。
 * @return Session、Provider、archive、INF、由来と候補identityを安全に結合できればtrueです。
 * @post 成功時もmethodは未対応、executorはfalseで、導入可能にはなりません。
 */
[[nodiscard]] bool makeDelegatedOfficialInfCandidateAssessment(
	ScanSessionId activeScanSessionId, const DelegatedOfficialPackageInput &input,
	const UpdateCandidate &candidate, const CommonDriverPackageInspection &packageInspection,
	std::size_t infOrdinal, std::uint64_t packageEvidenceId, NativeError applicabilityError,
	std::optional<std::uint32_t> candidateRank, CandidateAssessment &assessment) ;

} // namespace drivercrate
