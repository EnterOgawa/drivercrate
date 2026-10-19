//------------------------------------------------------------------------------
/**
 * @file official_discovery.h
 * @brief 端末内起点の公式自動探索に使用する有限値型と検証契約。
 * @version 01.02.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  自動探索の値型と厳格validatorを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  有限bus分類の共通候補型への移動を反映。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Planner実行状態と未route device集合を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  一scan承認から固定自動探索要求を作る境界を追加。
 * Ver.01.02.01  Shunji Ogawa  2026/10/16  既定比較の引数と一致条件の契約を明記。
 * </pre>
 *
 * @note 本値型はURL、Hardware ID、Compatible ID、instance ID、serial、local pathを
 * 保持しません。UIまたはnetworkへ送る前に、worker内の同一operation、session、
 * inventory generationへ完全一致で結合します。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 自動探索の固定境界。
//------------------------------------------------------------------------------

// 製品から選べる唯一の初期自動探索policy。
inline constexpr std::wstring_view OFFICIAL_DISCOVERY_POLICY_ID =
	L"official-discovery-initial-20260915-v1" ;
// 固定policyの解釈を変える場合に更新するrevision。
inline constexpr std::uint32_t OFFICIAL_DISCOVERY_POLICY_REVISION = 1U ;
// 一回の要求またはregistryで扱えるProvider数。
inline constexpr std::size_t   OFFICIAL_DISCOVERY_PROVIDER_LIMIT = 64U ;
// 一回のinventory snapshotで扱えるpresent device数。
inline constexpr std::size_t   OFFICIAL_DISCOVERY_DEVICE_LIMIT = 4096U ;
// 一回のscanで計画できる重複排除済みroute数。
inline constexpr std::size_t   OFFICIAL_DISCOVERY_ROUTE_LIMIT = 64U ;
// 外部識別情報を格納させないopaque identityの最大文字数。
inline constexpr std::size_t   OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT = 256U ;
// Local routing hintとして保持できる一表示値の最大文字数。
inline constexpr std::size_t   OFFICIAL_DISCOVERY_DISPLAY_VALUE_LIMIT = 512U ;
// Registryで固定するProviderまたはresource IDの最大ASCII文字数。
inline constexpr std::size_t   OFFICIAL_DISCOVERY_STABLE_ID_LIMIT = 128U ;

/**
 * @brief Registryで固定する公式自動探索routeの種類を表す。
 */
enum class OfficialDiscoveryRouteKind {
	/// Provider固有schemaとmatcherを使用する専用routeである。
	DEDICATED,
	/// 登録済み固定rootを共通の有限parserで解決するrouteである。
	GENERIC_OFFICIAL_ROOT,
} ;

/**
 * @brief 一つの公式自動探索routeの終了または待機状態を表す。
 */
enum class OfficialDiscoveryRouteState {
	/// Routeをまだ開始していない。
	NOT_STARTED,
	/// Provider設定により今回実行しない。
	DISABLED,
	/// Local hintが登録条件に一致しない。
	NOT_ROUTABLE,
	/// Fresh positive cacheから配布recordを復元した。
	CACHE_POSITIVE,
	/// Fresh negative cacheにより今回の送信を省略した。
	CACHE_NEGATIVE,
	/// 専用routeが一件以上のrecordを解決した。
	DEDICATED_RESOLVED,
	/// 汎用固定root routeが一件以上のrecordを解決した。
	GENERIC_RESOLVED,
	/// 同じProvider／rootの専用routeが全deviceを解決したため実行しない。
	SKIPPED_AFTER_DEDICATED,
	/// 公式rootを正常に確認したがrecordがなかった。
	NO_RECORD,
	/// 対応する組み込み公式rootが存在しない。
	NO_TRUSTED_ROOT,
	/// 制限または未知回線への今回の許可がない。
	NETWORK_NOT_APPROVED,
	/// 必須EULAの別同意を待っている。
	AWAITING_EULA,
	/// 固定metadataまたはpayload予算へ到達した。
	BUDGET_EXCEEDED,
	/// 利用者または終了処理により協調取消しした。
	CANCELLED,
	/// API、I/Oまたは内部契約に失敗した。
	FAILED,
	/// 固定公式source境界の検証に失敗した。
	SOURCE_REJECTED,
	/// 公式metadataのschemaまたは内容を拒否した。
	METADATA_REJECTED,
} ;

/**
 * @brief 自動探索snapshotを三つの単調IDへ結合する。
 */
struct OfficialDiscoveryBinding {
	/// UIが発行した0ではないoperation ID。
	OperationId	  operationId{} ;
	/// Workerが発行した0ではないscan session ID。
	ScanSessionId scanSessionId{} ;
	/// Present device snapshotを識別する0ではない世代。
	std::uint64_t inventoryGeneration{} ;

	/**
	 * @brief 三つのbinding値を完全一致で比較する。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	bool		  operator==( const OfficialDiscoveryBinding &other) const = default ;
} ;

/**
 * @brief 一回の通常またはmetadata専用scanに限定した自動探索要求を表す。
 */
struct OfficialDiscoveryRequest {
	/// 通常scanとmetadata専用scanを区別する用途。
	ScanPurpose							  purpose{ScanPurpose::STANDARD} ;
	/// trueならregistryの既定有効集合だけを使用する。
	bool								  useDefaultProviders{true} ;
	/// 既定集合を使わない場合の重複なしProvider ID。
	std::vector<std::wstring>			  enabledProviderIds ;
	/// 今回だけ許可するmetadataまたは検査用payload範囲。
	OfficialDiscoveryInspectionPermission inspectionPermission{
		OfficialDiscoveryInspectionPermission::METADATA_ONLY} ;
	/// trueなら今回だけ制限または未知回線への通信を許可する。
	bool							restrictedNetworkApproved{} ;
	/// Fresh cache利用または明示再確認の選択。
	OfficialDiscoveryCacheMode		cacheMode{OfficialDiscoveryCacheMode::USE_FRESH} ;
	/// 製品で固定した自動探索policyのID。
	std::wstring					policyId{OFFICIAL_DISCOVERY_POLICY_ID} ;
	/// Policy解釈のrevision。未知値を拒否する。
	std::uint32_t					policyRevision{OFFICIAL_DISCOVERY_POLICY_REVISION} ;
	/// 一scan承認で表示した固定metadata取得予算。
	OfficialDiscoveryMetadataLimits metadataLimits ;
	/// 一scan承認で表示した固定payload取得予算。
	OfficialDiscoveryPayloadLimits	payloadLimits ;

	/**
	 * @brief 権限を補完せず全request fieldを完全一致で比較する。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	bool operator==( const OfficialDiscoveryRequest &other) const = default ;
} ;

/**
 * @brief 一つのpresent deviceから得たraw識別子を含まないlocal routing hintを表す。
 */
struct OfficialDiscoveryDeviceHint {
	/// Scan結果の代表device行と結合するopaque identity。
	std::wstring			   deviceIdentity ;
	/// 元enumerator文字列を破棄した有限bus分類。
	OfficialDiscoveryDeviceBus bus{OfficialDiscoveryDeviceBus::UNKNOWN} ;
	/// Canonical文字列で保持するSetup class GUID。
	std::wstring			   setupClassGuid ;
	/// Setup classの上限付き表示値。空は欠損を表す。
	std::wstring			   deviceClass ;
	/// Manufacturerの上限付き表示値。空は欠損を表す。
	std::wstring			   manufacturer ;
	/// Modelの上限付き表示値。空は欠損を表す。
	std::wstring			   model ;
	/// 現在driver Providerの上限付き表示値。空は欠損を表す。
	std::wstring			   currentProvider ;
	/// 生値を含まない同じdeviceの有限観測。
	DeviceObservation		   observation ;
} ;

/**
 * @brief 同じ固定公式rootと正規化hintへまとめた一つの実行routeを表す。
 */
struct OfficialDiscoveryRoute {
	/// Scan session内で1から単調増加するroute ID。
	std::uint64_t			   routeId{} ;
	/// Provider registryのstable ID。
	std::wstring			   providerId ;
	/// Provider source policy内の固定root resource ID。
	std::wstring			   rootResourceId ;
	/// 専用または汎用固定rootの有限route種別。
	OfficialDiscoveryRouteKind kind{OfficialDiscoveryRouteKind::DEDICATED} ;
	/// 同じ正規化hint groupを表すURL非保持のopaque identity。
	std::wstring			   hintGroupIdentity ;
	/// このrouteへ結合する重複なしのopaque device identity。
	std::vector<std::wstring>  deviceIdentities ;
} ;

/**
 * @brief 一つのrouteについてUIへ公開できる非機密の有限集計を表す。
 */
struct OfficialDiscoveryRouteSummary {
	/// 元planの0ではないroute ID。
	std::uint64_t				routeId{} ;
	/// 元routeと完全一致するProvider stable ID。
	std::wstring				providerId ;
	/// 元routeと完全一致するroute種別。
	OfficialDiscoveryRouteKind	kind{OfficialDiscoveryRouteKind::DEDICATED} ;
	/// 候補0件と失敗を区別するroute状態。
	OfficialDiscoveryRouteState state{OfficialDiscoveryRouteState::NOT_STARTED} ;
	/// FAILED、SOURCE_REJECTED、METADATA_REJECTED時の最初の診断値。
	NativeError					error{} ;
	/// Routeへ結合した重複なしのpresent device数。
	std::uint32_t				deviceCount{} ;
	/// 検証済みmetadataから解決したrecord数。
	std::uint32_t				recordCount{} ;
	/// Driver packageと分類したpayload数。取得や導入成功数ではない。
	std::uint32_t				packageCount{} ;
} ;

/**
 * @brief 一回の自動探索結果を開始時snapshotへ結合する非機密summaryを表す。
 */
struct OfficialDiscoverySummary {
	/// 遅延結果を拒否するoperation、session、inventoryの結合。
	OfficialDiscoveryBinding				   binding ;
	/// 開始時に固定した要求の所有copy。
	OfficialDiscoveryRequest				   request ;
	/// 全present nodeを上限内で列挙できた場合だけtrue。
	bool									   inventoryComplete{} ;
	/// Snapshot内で保持した重複なしのpresent device数。
	std::uint32_t							   deviceCount{} ;
	/// 汎用固定rootだけへ対応し、専用adapterを持たないopaque device identity。
	std::vector<std::wstring>				   dedicatedUnavailableDeviceIdentities ;
	/// 選択済み固定rootへ一件も対応しなかったopaque device identity。
	std::vector<std::wstring>				   noTrustedRootDeviceIdentities ;
	/// 計画済みrouteと一対一に対応する非機密結果。
	std::vector<OfficialDiscoveryRouteSummary> routes ;
} ;

/**
 * @brief 自動探索に使える既知capabilityと固定公式policyを検証する。
 * @param[in] descriptor 検証する一つのProvider登録定義。
 * @return 単一公式境界、SCAN、自動探索、固定policyが整合する場合true。
 */
[[nodiscard]] bool isOfficialDiscoveryProvider( const ProviderDescriptor &descriptor) noexcept ;

/**
 * @brief 一回の要求とProvider集合を通信前に厳格検証する。
 * @param[in] request 開始時に所有copyする自動探索要求。
 * @param[in] descriptors Provider registryの正本または合成fixture。
 * @return Policy、purpose、権限、既定または明示集合が全て整合する場合true。
 */
[[nodiscard]] bool validateOfficialDiscoveryRequest(
	const OfficialDiscoveryRequest	   &request,
	std::span<const ProviderDescriptor> descriptors) noexcept ;

/**
 * @brief 通常scanの新しい一scan承認を自動探索requestへ権限拡張なしで変換する。
 * @param[in] options Provider集合と利用者へ表示した承認snapshot。
 * @param[in] descriptors Provider registryの正本または合成fixture。
 * @return 新承認と自動探索Providerが完全に整合する場合だけ固定request。
 */
[[nodiscard]] std::optional<OfficialDiscoveryRequest> makeStandardOfficialDiscoveryRequest(
	const ScanOptions &options, std::span<const ProviderDescriptor> descriptors) noexcept ;

/**
 * @brief 遅延結果を拒否する三つの単調IDを検証する。
 * @param[in] binding Operation、scan session、inventory generationの結合。
 * @return 全IDが0ではない場合true。
 */
[[nodiscard]] bool isOfficialDiscoveryBindingValid(
	const OfficialDiscoveryBinding &binding) noexcept ;

/**
 * @brief Raw識別情報を持たない一deviceのhintと観測結合を検証する。
 * @param[in] hint 一つのpresent deviceから構築したlocal hint。
 * @param[in] scanSessionId 観測を結合する0ではないscan session ID。
 * @return 全有限値とopaque identityが妥当で観測が同じdeviceへ結合する場合true。
 */
[[nodiscard]] bool validateOfficialDiscoveryDeviceHint( const OfficialDiscoveryDeviceHint &hint,
													   ScanSessionId scanSessionId) noexcept ;

/**
 * @brief 一routeのProvider、固定root、device参照を完全一致で検証する。
 * @param[in] route 検証するroute。
 * @param[in] devices 同じinventory snapshotの検証済みdevice hint集合。
 * @param[in] descriptors Provider registryの正本または合成fixture。
 * @return 全参照が一意で自動探索Providerと固定resourceへ結合する場合true。
 */
[[nodiscard]] bool validateOfficialDiscoveryRoute(
	const OfficialDiscoveryRoute &route, std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const ProviderDescriptor> descriptors) noexcept ;

/**
 * @brief 一route summaryのidentity、状態、診断、件数を元routeへ再結合する。
 * @param[in] route 開始時に検証した元route。
 * @param[in] summary Resolverまたはworkerが返した非機密集計。
 * @return Routeと全fieldが一致し、状態別件数が矛盾しない場合true。
 */
[[nodiscard]] bool isOfficialDiscoveryRouteSummaryValid(
	const OfficialDiscoveryRoute &route, const OfficialDiscoveryRouteSummary &summary) noexcept ;

/**
 * @brief 公開summaryを開始時binding、request、route集合へ一括で再結合する。
 * @param[in] binding 開始時に固定したoperation、session、inventoryの結合。
 * @param[in] request 開始時に固定した自動探索要求。
 * @param[in] devices 開始時に検証したpresent device hint集合。
 * @param[in] routes 開始時に検証した重複なしroute集合。
 * @param[in] summary Workerが公開する非機密summary。
 * @param[in] descriptors Provider registryの正本または合成fixture。
 * @return 全snapshot、有限状態、件数が矛盾せず一対一に結合する場合true。
 */
[[nodiscard]] bool isOfficialDiscoverySummaryValid(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const OfficialDiscoveryRoute> routes, const OfficialDiscoverySummary &summary,
	std::span<const ProviderDescriptor> descriptors) noexcept ;

} // namespace drivercrate
