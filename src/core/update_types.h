//------------------------------------------------------------------------------
/**
 * @file update_types.h
 * @brief Driver update共通値型定義。
 * @version 01.10.02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Provider別install注意種別を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  公式pageの概算size表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  公式release観測差分を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後EULA同意状態へ契約を拡張。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント結果追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  デバイスクラス識別子追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Operation進捗値追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  公式catalog検索段階追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider registry値型追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元統合値追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider別coverage追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local候補到達集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  OS別install保護方針追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式候補の探索経路区分追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択Provider file入力追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択候補のcoverage追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  取得元未証明Provider区分追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Manufacturer intake状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元監査根拠追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  取得根拠連番追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Opaque origin経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  未接続を区別する任意の段階別計測を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  公式resourceの実取得経路と時刻を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索専用の型と拒否境界を追加。
 * Ver.01.00.02 Shunji Ogawa  2026/09/14  表示GUIDの用途へ種類別groupを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  現在構成行へ有限なDevice観測を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  詳細assessmentと初回導入の表示分類を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  公式自動探索capabilityを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  端末内探索用の有限bus分類を候補へ追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  一scanの公式探索承認と固定予算snapshotを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/15  Metadata確定後のpayload未許可状態を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  必要役割のstageと指定APIと適用未確認を分離。
 * Ver.01.10.01 Shunji Ogawa  2026/10/13  観測field説明を完全な宣言開始前へ配置。
 * Ver.01.10.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Provider、状態管理、およびUI間で交換する値型を定義します。Windows固有型を公開せず、unit testからも利用できる構成とします。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/device_observation.h"
#include "core/candidate_assessment.h"
#include "core/metadata_search_types.h"
#include "core/official_release_observation.h"
#include "core/scan_measurement_types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 共通値型定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つの非同期UI operationを識別する単調増加ID。
 */
using OperationId = std::uint64_t ;
/**
 * @brief Scan結果とinstall要求を結び付けるsession ID。
 */
using ScanSessionId = std::uint64_t ;
/**
 * @brief HRESULTまたはWin32 errorの32-bit bit pattern。
 */
using NativeError = std::int32_t ;

/**
 * @brief Provider operation の結果分類を表す。
 */
enum class OutcomeCode {
	/// Operationを開始していない。
	NOT_STARTED,
	/// Operationを実行中である。
	IN_PROGRESS,
	/// 全対象が成功した。
	SUCCESS,
	/// 一部対象だけが成功した。
	SUCCEEDED_WITH_ERRORS,
	/// 対象が成功しなかった。
	FAILURE,
	/// Providerまたは利用者判断により中止した。
	ABORTED,
} ;

/**
 * @brief 候補を選択した場合に実行される driver 操作を表す。
 */
enum class DriverAction {
	/// 現在使用中など、system変更を行わない表示候補。
	NONE,
	/// 現在版から別の通常更新候補へ切り替える。
	UPDATE,
	/// 同版または比較不能な別候補を再導入する。
	REINSTALL,
	/// 現在版より古い版へ明示的に切り替える。
	DOWNGRADE,
	/// 初回導入の表示分類。Executor接続前は導入・初期選択を禁止する。
	INITIAL_INSTALL,
} ;

/**
 * @brief Providerが実装する操作と信頼境界のcapabilityを表す。
 */
enum class ProviderCapability : std::uint32_t {
	/// Candidateを検索できる。
	SCAN = 1U << 0U,
	/// Networkからpayloadを取得できる。
	DOWNLOAD = 1U << 1U,
	/// Driverをsystemへ導入できる。
	INSTALL = 1U << 2U,
	/// 現在版以外の履歴を提示できる。
	HISTORY = 1U << 3U,
	/// Windows Update等の管理されたserviceを使用する。
	MANAGED_SERVICE = 1U << 4U,
	/// Hardware makerの公式network取得元を使用する。
	OFFICIAL_NETWORK = 1U << 5U,
	/// Local deviceまたはDriver Storeを列挙する。
	LOCAL_INVENTORY = 1U << 6U,
	/// 利用者が明示した単一local fileだけを入力にする。
	USER_SELECTED_FILE = 1U << 7U,
	/// Payloadを取得しない専用callbackで情報検索できる。
	METADATA_ONLY_SCAN = 1U << 8U,
	/// 固定公式rootと端末内hintから自動探索routeを作成できる。
	AUTOMATIC_DISCOVERY = 1U << 9U,
	/// 認証snapshotと封印grantを必要とする共通索引の取得経路である。
	SIGNED_INDEX_ACQUISITION = 1U << 10U,
} ;

/**
 * @brief ProviderCapabilityのbit集合。
 */
using ProviderCapabilityMask = std::uint32_t ;

/**
 * @brief 元enumerator文字列を返さない有限なdevice bus分類を表す。
 */
enum class OfficialDiscoveryDeviceBus {
	/// PCIまたはPCI Expressのpresent deviceである。
	PCI,
	/// USB bus上のpresent deviceである。
	USB,
	/// ACPIで列挙されたpresent deviceである。
	ACPI,
	/// HID enumeratorのpresent deviceである。
	HID,
	/// Bluetooth bus上のpresent deviceである。
	BLUETOOTH,
	/// Software device enumeratorのpresent deviceである。
	SOFTWARE,
	/// Root enumeratorのpresent deviceである。
	ROOT,
	/// 既知分類以外と判定できたpresent deviceである。
	OTHER,
	/// 元情報の欠損または不正によりbusを分類できない。
	UNKNOWN,
} ;

/**
 * @brief 候補別既定選択根拠を検証するProvider取得元区分を表す。
 *
 * @note Enum順を候補の固定優先順位として使用しない。
 */
enum class ProviderSelectionTier : std::uint32_t {
	/// Windows Updateまたは管理者構成serviceである。
	MANAGED_SERVICE,
	/// PC OEMがmodel適用性を提示する公式取得元である。
	OEM_OFFICIAL,
	/// Component makerの公式取得元である。
	COMPONENT_OFFICIAL,
	/// 利用者指定fileであり、取得元をDriverCrateが証明しない。
	USER_PROVIDED,
	/// 端末内のDriver Storeまたは現在構成である。
	LOCAL_INVENTORY,
} ;

/**
 * @brief 推奨通常更新を一device一候補へ初期選択する際の検証根拠を表す。
 *
 * @note 取得元の安全性、最新性、またはdevice適用性の保証には使用しない。
 */
enum class CandidateDefaultPreference {
	/// 現在版、旧版、同版、または初期選択の根拠を持たない。
	NONE,
	/// System makerがmodel、OS、architectureを検証した候補。
	OEM_VALIDATED,
	/// Component makerがreference適用範囲を公開した候補。
	COMPONENT_REFERENCE,
	/// WUAが管理serviceと現在端末へ適用可能と判定した候補。
	MANAGED_APPLICABLE,
	/// 公式component候補だがOEM固有構成では未検証である。
	COMPONENT_GENERIC,
} ;

/**
 * @brief Candidateを発見した経路を表す。
 *
 * @note 取得経路の表示と自動選択制御に使用し、安全性、最新性、適用性の格付けには
 * 使用しない。
 */
enum class CandidateDiscoveryBasis {
	/// Providerが探索経路を提示していない不正な状態。
	UNSPECIFIED,
	/// WUA／WSUS等の端末管理serviceから取得した。
	MANAGED_SERVICE,
	/// 現在deviceまたはDriver Storeから取得した。
	LOCAL_INVENTORY,
	/// 公式の構造化metadataから取得した区分A。
	OFFICIAL_STRUCTURED_CATALOG,
	/// 公式の利用者向けWeb pageから取得した区分B。
	OFFICIAL_WEB_PAGE,
	/// 利用者が明示したlocal packageから取得した区分C。
	USER_IMPORTED_PACKAGE,
	/// 署名索引の収集者による配布確認であり、メーカーのlive検索保証ではありません。
	SIGNED_INDEX_COLLECTOR_ATTESTATION,
} ;

/**
 * @brief Install最終確認へ追加するProvider固有の注意文種別を表す。
 *
 * @note 注意文の選択だけに使用し、監査合格、適用性または利用者同意の証明に使用しない。
 */
enum class InstallNoticeKind {
	/// Provider固有の追加注意文を必要としない。
	NONE,
	/// Intel Ethernet Server base driver固有の注意文を表示する。
	INTEL_ETHERNET_SERVER,
	/// ASIX client NICの通信断と復旧操作の注意文を表示する。
	ASIX_CLIENT_NIC,
} ;

/**
 * @brief 一つの組み込みProviderを安定したIDとcapabilityで表す。
 */
struct ProviderDescriptor {
	/// 設定とroutingに使用する変更しないASCII ID。
	std::wstring			id ;
	/// UIへ表示する取得元名称。
	std::wstring			displayName ;
	/// 実装済みoperationと信頼境界のbit集合。
	ProviderCapabilityMask	capabilities{} ;
	/// 候補別根拠を検証する取得元区分。
	ProviderSelectionTier	selectionTier{} ;
	/// Registryが許可する候補探索経路。信頼性や適用性の保証とは区別する。
	CandidateDiscoveryBasis discoveryBasis{CandidateDiscoveryBasis::UNSPECIFIED} ;
	/// 最終確認へ追加する注意種別。
	InstallNoticeKind		installNotice{InstallNoticeKind::NONE} ;
	/// trueの場合は初回scanで有効にする。
	bool					enabledByDefault{} ;
	/// OfficialNetwork Providerに対応する組み込みorigin policy ID。
	std::wstring			officialSourcePolicyId ;
} ;

/**
 * @brief 公式resourceの取得元検証をscan session内で示すopaqueな根拠である。
 *
 * @note URL、host、端末識別子またはcredentialを保持しない。各IDを表示用文字列から
 * 推測せず、組み込みregistryへ完全一致させる。
 */
struct OfficialSourceEvidence {
	/// 取得を行った0ではないscan session ID。
	ScanSessionId				 scanSessionId{} ;
	/// Provider session内で1から単調増加する取得連番。
	std::uint64_t				 acquisitionId{} ;
	/// Provider registryのstable ID。
	std::wstring				 providerId ;
	/// 組み込み公式取得元policyのstable ID。
	std::wstring				 policyId ;
	/// Policy内で検証したresourceのstable ID。
	std::wstring				 resourceId ;
	/// 起点を含まない実redirect回数。
	std::uint32_t				 redirectCount{} ;
	/// 起点から最終originまでのallowed_hosts内index。URLは保持しない。
	std::vector<std::uint32_t>	 originPolicyIndices ;
	/// 今回実際に本文を得た経路。
	MeasurementAcquisition		 acquisition{MeasurementAcquisition::UNKNOWN} ;
	/// Network本文取得UTC。Cacheでは不明を許す。
	std::optional<std::uint64_t> bodyAcquiredUtcSeconds ;
	/// Origin応答またはcache保存時の検証UTC。
	std::optional<std::uint64_t> originValidatedUtcSeconds ;
	/// 当該API呼出しでcatalog cacheを許可した場合だけtrue。
	bool						 cachePermitted{} ;
} ;

/**
 * @brief 一つの候補に対する独立した監査gateの到達状態を表す。
 *
 * @note `PASSED`だけがDriverCrateによる該当gateの完了を表す。
 * `MANAGED_BY_WINDOWS`と`PROVIDER_VALIDATED`を`PASSED`へ読み替えてはならない。
 */
enum class CandidateAuditGateState {
	/// 候補の取得経路では該当gateを実行しない。
	NOT_APPLICABLE,
	/// Install前のworker処理で監査する未完了状態。
	PENDING,
	/// DriverCrateが該当gateを検証して合格とした。
	PASSED,
	/// WUAまたはWindows標準APIへ判定を委譲する。
	MANAGED_BY_WINDOWS,
	/// Provider固有照合済みだがsystem監査合格ではない。
	PROVIDER_VALIDATED,
	/// 利用者入力でありDriverCrateが取得元を証明していない。
	USER_PROVIDED_UNVERIFIED,
	/// 検証結果がpolicy条件を満たさず拒否した。
	REJECTED,
	/// 通信、I/OまたはOS API失敗により判定できなかった。
	FAILURE,
} ;

/**
 * @brief 候補行からinstall workflowを開始できる準備状態を表す。
 */
enum class CandidateInstallReadiness {
	/// 現在版等の表示専用行でありinstall対象にしない。
	DISPLAY_ONLY,
	/// 選択後の保護されたworker処理で残りの監査を実施する。
	AUDIT_PENDING,
	/// 必要な監査を完了またはWindows管理経路へ委譲済みである。
	READY,
	/// 拒否、失敗または不整合によりinstallを許可しない。
	BLOCKED,
} ;

/**
 * @brief 候補の取得根拠、取得、内容、system監査とinstall準備状態を保持する。
 *
 * @note URL、Hardware ID、device instance IDまたはlocal pathを保持しない。
 * 各値はscan session時点のimmutableな表示用事実である。
 */
struct CandidateAuditStatus {
	/// 公式origin、Windows管理経路または利用者入力であることの確認状態。
	CandidateAuditGateState	  sourceOrigin{CandidateAuditGateState::PENDING} ;
	/// DriverCrateがpayloadを検査用workspaceへ取得した状態。
	CandidateAuditGateState	  inspectionDownload{CandidateAuditGateState::PENDING} ;
	/// Driver-only分類、file閉包、hash、署名等の内容監査状態。
	CandidateAuditGateState	  contentIntegrity{CandidateAuditGateState::PENDING} ;
	/// 現在device、OS、architecture、class、PnP rankへの適用性監査状態。
	CandidateAuditGateState	  systemApplicability{CandidateAuditGateState::PENDING} ;
	/// 利用者がこの候補からinstall workflowを開始できる状態。
	CandidateInstallReadiness installReadiness{CandidateInstallReadiness::BLOCKED} ;
} ;

/**
 * @brief 一つのProviderによるscanの到達状態を表す。
 */
enum class ProviderScanState {
	/// 利用者設定により候補検索を実行しなかった。
	DISABLED,
	/// 対象vendorまたは対応deviceが存在しなかった。
	NOT_APPLICABLE,
	/// 検索は成立したが表示候補を返さなかった。
	NO_CANDIDATES,
	/// 一件以上の表示候補を返した。
	CANDIDATES_AVAILABLE,
	/// Metadataは確定したがpayloadの検査用取得を今回許可していない。
	PAYLOAD_NOT_APPROVED,
	/// 制限または状態不明の回線に今回の通信許可がない。
	NETWORK_NOT_APPROVED,
	/// 通信、API、OS等の理由で検索が成立しなかった。
	FAILURE,
	/// Schema、hash、署名等の検証でmetadataを拒否した。
	METADATA_REJECTED,
	/// HTTPS originまたはredirectが公式policyに反した。
	SOURCE_REJECTED,
	/// 取得元確認後の検査用downloadが成立しなかった。
	DOWNLOAD_FAILED,
	/// 取得payloadのdriver-only内容監査で拒否した。
	CONTENT_REJECTED,
} ;

/**
 * @brief 利用者が一つのProviderへ明示したlocal file入力を表す。
 *
 * @note `path`はUIとworker間だけで保持し、candidate、永続logまたはnetworkへ渡さない。
 */
struct UserSelectedProviderFile {
	/// 入力を受け取るUserSelectedFile capability付きProvider ID。
	std::wstring providerId ;
	/// File dialogで選択した一つのlocal file絶対path。
	std::wstring path ;
} ;

/**
 * @brief 一回のscanで公式resourceに許可する検査範囲を表す。
 */
enum class OfficialDiscoveryInspectionPermission {
	/// 配布metadataだけを読み、payloadを取得しない。
	METADATA_ONLY,
	/// 検証済みdriver packageを共通内容検査のために取得できる。
	ALLOW_VERIFIED_DRIVER_PACKAGE,
} ;

/**
 * @brief 一回のscanで使用する公式record cache方針を表す。
 */
enum class OfficialDiscoveryCacheMode {
	/// Bindingが一致するfresh entryだけを利用できる。
	USE_FRESH,
	/// Cacheを正本にせず固定rootを再取得する。
	FORCE_REFRESH,
} ;

/**
 * @brief 一scan承認へ固定する公式metadata取得予算を表す。
 */
struct OfficialDiscoveryMetadataLimits {
	/// 一logical resourceの本文byte上限。
	std::uint64_t resourceBytes{2ULL * 1024ULL * 1024ULL} ;
	/// 一Providerの本文byte上限。
	std::uint64_t providerBytes{4ULL * 1024ULL * 1024ULL} ;
	/// 一scan全体の本文byte上限。
	std::uint64_t sessionBytes{32ULL * 1024ULL * 1024ULL} ;
	/// 一Providerのlogical resource数上限。
	std::uint32_t providerResources{2U} ;
	/// 一scan全体のlogical resource数上限。
	std::uint32_t sessionResources{20U} ;
	/// 一ProviderのHTTP送信試行上限。
	std::uint32_t providerAttempts{12U} ;
	/// 一scan全体のHTTP送信試行上限。
	std::uint32_t sessionAttempts{120U} ;
	/// 一Providerの経過millisecond上限。
	std::uint64_t providerMilliseconds{90000U} ;
	/// Inventoryを含む一scanの経過millisecond上限。
	std::uint64_t sessionMilliseconds{300000U} ;

	/**
	 * @brief 表示時とworker受付時の全予算を完全一致で比較する。
	 * @param[in] other 比較対象のmetadata予算。
	 * @return 全fieldが一致する場合true。
	 */
	bool		  operator==( const OfficialDiscoveryMetadataLimits &other) const = default ;
} ;

/**
 * @brief 一scan承認へ固定する検査用driver package取得予算を表す。
 */
struct OfficialDiscoveryPayloadLimits {
	/// 一fileへ予約できるbyte上限。
	std::uint64_t maximumFileBytes{128ULL * 1024ULL * 1024ULL} ;
	/// 一Providerへ予約できる累計byte上限。
	std::uint64_t maximumProviderBytes{256ULL * 1024ULL * 1024ULL} ;
	/// 一scan全体へ予約できる累計byte上限。
	std::uint64_t maximumSessionBytes{512ULL * 1024ULL * 1024ULL} ;
	/// 一Providerへ予約できるfile数上限。
	std::uint32_t maximumProviderFiles{2U} ;
	/// 一scan全体へ予約できるfile数上限。
	std::uint32_t maximumSessionFiles{4U} ;

	/**
	 * @brief 表示時とworker受付時の全予算を完全一致で比較する。
	 * @param[in] other 比較対象のpayload予算。
	 * @return 全fieldが一致する場合true。
	 */
	bool		  operator==( const OfficialDiscoveryPayloadLimits &other) const = default ;
} ;

/**
 * @brief 通常scan一回にだけ結合する公式networkと検査用取得の承認snapshotを表す。
 *
 * @note Install、firmware、utility、applicationまたはWUA EULAへの同意ではない。
 */
struct OfficialDiscoveryScanApproval {
	/// UI state machineが割り当て、worker commandと完全一致させるoperation ID。
	OperationId							  operationId{} ;
	/// Metadata限定または検証済みdriver package取得を許可する範囲。
	OfficialDiscoveryInspectionPermission inspectionPermission{
		OfficialDiscoveryInspectionPermission::METADATA_ONLY} ;
	/// trueなら今回だけ制限または状態不明のnetwork通信を許可する。
	bool							restrictedNetworkApproved{} ;
	/// Fresh cache利用または利用者が選んだ明示再確認。
	OfficialDiscoveryCacheMode		cacheMode{OfficialDiscoveryCacheMode::USE_FRESH} ;
	/// UIへ表示した固定metadata取得予算。
	OfficialDiscoveryMetadataLimits metadataLimits ;
	/// UIへ表示した固定payload取得予算。
	OfficialDiscoveryPayloadLimits	payloadLimits ;

	/**
	 * @brief 別scanや拡大予算へ承認を流用しないよう全fieldを比較する。
	 * @param[in] other 比較対象の承認snapshot。
	 * @return 全fieldが一致する場合true。
	 */
	bool operator==( const OfficialDiscoveryScanApproval &other) const = default ;
} ;

/**
 * @brief scan sessionで使用するProvider選択と利用者選択fileを表す。
 */
struct ScanOptions {
	/// trueの場合はenabled_provider_idsを無視して各Providerの既定値を使用する。
	bool										 useDefaultProviders{true} ;
	/// useDefaultProvidersがfalseの場合にだけ有効にするProvider ID集合。
	std::vector<std::wstring>					 enabledProviderIds ;
	/// UserSelectedFile Providerへ一件ずつ渡す、process内だけで有効なlocal file入力。
	std::vector<UserSelectedProviderFile>		 userSelectedFiles ;
	/// 今回のProvider集合、通信条件、固定予算へだけ結合した新しい一scan承認。
	std::optional<OfficialDiscoveryScanApproval> officialDiscoveryApproval ;
	/// 今回のProlific公式ZIP検査用取得だけを許可する。課金／不明networkを含む。
	/// InstallとEULAへの同意ではなく、次回scanへ自動的に持ち越さない。
	bool										 prolificInspectionApproved{} ;
	/// 今回のCP210x公式ZIP検査用取得だけを許可する。課金／不明networkを含む。
	/// Prolificまたはinstall／EULAへの同意として流用しない。
	bool										 siliconLabsInspectionApproved{} ;
	/// 今回のCH341SER公式ZIP検査用取得だけを許可する。Install／EULA同意ではない。
	bool										 wchInspectionApproved{} ;
	/// 今回のCH343SER公式ZIP検査用取得だけを許可する。CH341SER同意からも独立させる。
	bool										 wchMultiInspectionApproved{} ;
} ;

/**
 * @brief 一つのProviderがlocal端末内で判定したdevice coverageを表す。
 *
 * @note 値は端末内のUI表示だけに使用し、network、telemetry、永続logへ送信しない。
 */
struct ProviderCoverage {
	/// Provider固有条件の検索対象になったdevice数。
	std::uint64_t					   eligibleDeviceCount{} ;
	/// 適用性または候補なしまで判定できたdevice数。
	std::uint64_t					   assessedDeviceCount{} ;
	/// 新契約の集計。旧二値から推測しない。
	std::optional<ProviderMeasurement> measurement ;
} ;

/**
 * @brief UIへ返す一つのProviderのscan状態を表す。
 */
struct ProviderScanReport {
	/// Scan時に使用したProvider定義。
	ProviderDescriptor descriptor ;
	/// Provider固有の到達状態。
	ProviderScanState  state{ProviderScanState::DISABLED} ;
	/// Failedまたは各監査拒否時のnative error。
	NativeError		   error{} ;
	/// このProviderが返した表示候補数。
	std::uint64_t	   candidateCount{} ;
	/// 端末内だけで集計した対象／判定device数。
	ProviderCoverage   coverage ;
	/// 部分成功を独立して保持する実行結果。
	OutcomeCode		   outcome{OutcomeCode::NOT_STARTED} ;
} ;

/**
 * @brief Local coverageに表示するmanufacturerのロードマップ審査状態を表す。
 *
 * @note 候補の適用性、安全性、最新性、またはProvider対応を表す値ではない。
 */
enum class ManufacturerReviewState {
	/// ロードマップで審査したmanufacturerの明示aliasと一致した。
	REVIEWED,
	/// MicrosoftまたはWindows標準／generic deviceとして分類した。
	PLATFORM,
	/// 空でないが審査済みaliasと一致せず、S63+調査候補である。
	PENDING_INTAKE,
	/// Manufacturer表示名が空または記号だけで識別できない。
	UNIDENTIFIED,
} ;

/**
 * @brief Manufacturerとsetup class別のlocal候補到達件数を表す。
 *
 * @note 値は現在scanのUI memoryだけに保持し、network、telemetry、永続logへ送信しない。
 * 候補が0件でも、最新、問題なし、またはProvider未対応であることを意味しない。
 */
struct LocalCoverageEntry {
	/// 現在device propertyから得た製造元表示名。取得不能時は空。
	std::wstring							  manufacturer ;
	/// 現在device propertyから得たsetup class表示名。取得不能時は空。
	std::wstring							  driverClass ;
	/// 表示名だけを端末内の審査済みalias表へ照合したintake状態。
	ManufacturerReviewState					  reviewState{ManufacturerReviewState::UNIDENTIFIED} ;
	/// 同じmanufacturer／classに属するpresent device数。
	std::uint64_t							  deviceCount{} ;
	/// 一つ以上の非現在版候補へlocal照合できたdevice数。
	std::uint64_t							  candidateDeviceCount{} ;
	/// Windows Updateまたは管理service候補へlocal照合できたdevice数。
	std::uint64_t							  managedCandidateDeviceCount{} ;
	/// Hardware maker公式network候補へlocal照合できたdevice数。
	std::uint64_t							  officialCandidateDeviceCount{} ;
	/// 利用者が明示したlocal package候補へ照合できたdevice数。
	std::uint64_t							  userSelectedCandidateDeviceCount{} ;
	/// Driver Store内の非現在版候補が存在したdevice数。
	std::uint64_t							  localCandidateDeviceCount{} ;
	/// 署名索引から実binding付き候補へ到達したdevice数。参照行を含みません。
	std::uint64_t							  indexedCandidateDeviceCount{} ;
	/// 未導入の索引参照行を持つdevice数。内容や適合の成功ではありません。
	std::uint64_t							  indexedReferenceDeviceCount{} ;
	/// 同じ現在版groupの段階別和集合。
	std::optional<NetworkCoverageMeasurement> measurement ;
} ;

/**
 * @brief UI に表示できる一件の driver update 候補を表す。
 *
 * @note `identity` と `deviceIdentity` は現在の scan session 内で Provider が発行した opaque
 * 値として扱う。Hardware ID、device instance ID、実 INF path を設定してはならない。
 * `providerId`はregistryのstable ID、`packageIdentity`は検証済みmetadataから作るopaque値とし、
 * 表示名、title、任意URLから推測してはならない。
 * `deviceClassGuid` はWindows標準class icon・種類別表示用のbrace付きcanonical GUIDであり、
 * local deviceへ照合できない場合は空とする。
 * `allContentCached` は WUA の `IsDownloaded`、または公式Providerの保護workspaceへ
 * 全contentを取得済みであることを表す。Install済みという意味ではない。
 * `displayDownloadSize`は公式pageの公表文字列であり、取得上限、完全性検証または
 * `maximumDownloadBytes`の代替に使用してはならない。
 */
struct UpdateCandidate {
	/// Scan session内だけで有効なopaque candidate identity。
	std::wstring			   identity ;
	/// 同じdeviceの候補を束ねるopaque identity。
	std::wstring			   deviceIdentity ;
	/// Registryへ登録された取得元Provider ID。
	std::wstring			   providerId ;
	/// 同一payloadの重複実行を防ぐopaque package ID。
	std::wstring			   packageIdentity ;
	/// Providerが提示するdriver updateまたはdriver node名称。
	std::wstring			   title ;
	/// Device製造元。Providerが返さない場合は空。
	std::wstring			   manufacturer ;
	/// UIの親nodeに表示するdevice model名。
	std::wstring			   model ;
	/// Windows device setup classの表示名。
	std::wstring			   driverClass ;
	/// Windows標準のclass icon・種類別表示に限定して使うcanonical setup class GUID。
	std::wstring			   deviceClassGuid ;
	/// Driver packageを提供するpublisher名。
	std::wstring			   provider ;
	/// Providerが提示するdriver version文字列。
	std::wstring			   version ;
	/// Driver日付の表示文字列。取得不能時は空。
	std::wstring			   driverDate ;
	/// Windows Update等の論理的な取得元名称。
	std::wstring			   sourceName ;
	/// Network/localとpolicy境界を示す取得場所。
	std::wstring			   sourceLocation ;
	/// 公式pageが公表した概算size。正確なbyte数または取得上限として使用しない。
	std::wstring			   displayDownloadSize ;
	/// WUAが返す最大download size（byte）。
	std::uint64_t			   maximumDownloadBytes{} ;
	/// 選択時に実行するdriver操作分類。
	DriverAction			   action{DriverAction::NONE} ;
	/// 推奨通常更新の初期選択だけに使用する、Providerが検証した根拠。
	CandidateDefaultPreference defaultPreference{CandidateDefaultPreference::NONE} ;
	/// Candidateを発見した経路。署名または適用性の保証として扱わない。
	CandidateDiscoveryBasis	   discoveryBasis{CandidateDiscoveryBasis::UNSPECIFIED} ;
	/// 由来、取得、内容、system適用性とinstall準備状態を独立して保持する。
	CandidateAuditStatus	   audit ;
	/// 公式metadata候補だけが持つ前回観測との差。取得・監査・導入の許可ではない。
	std::optional<ReleaseObservationDifference> releaseObservationDifference ;
	/// trueの場合は現在device構成の代表行である。Driver存在は観測で別確認する。
	bool										current{} ;
	/// trueの場合はProviderが初期選択を許可する候補である。
	bool										recommended{} ;
	/// trueの場合だけ明示選択後のinstall workflowを開始できる。監査完了とは限らない。
	bool										installable{} ;
	/// trueの場合は候補発行前に対象EULAを受諾済みである。
	bool										eulaAccepted{} ;
	/// trueの場合はProviderが全contentを保持済み。
	bool										allContentCached{} ;
	/// trueの場合はinstall後に再起動する可能性がある。
	bool										rebootMayBeRequired{} ;
	/// trueの場合はWindows Update上のoptional候補である。
	bool										browseOnly{} ;
	/// 同一device／同一版にある取得元候補数。
	std::uint32_t								equivalentSourceCount{1} ;
	/// trueの場合は同一版内の既定取得元である。
	bool										preferredSource{true} ;
	/// 情報検索だけの配布版と許諾表示。通常scan／現在属性行では値なし。
	std::optional<MetadataDistributionDetails>	metadataDistribution ;
	/// Local現在構成行だけが持つsession結合済み観測。生IDや導入許可を含まない。
	std::optional<DeviceObservation>			deviceObservation ;
	/// Local現在構成から元enumerator文字列を破棄して得た有限bus分類。
	OfficialDiscoveryDeviceBus					discoveryBus{OfficialDiscoveryDeviceBus::UNKNOWN} ;
	/// 個別検査の詳細。未収集の旧Providerでは値なしとし、合格を推測しない。
	std::optional<CandidateAssessment>			assessment ;
	/// 同byteから確認した必要Extension件数です。表示専用で導入権限を持ちません。
	std::uint32_t								requiredExtensionCount{} ;
	/// 元AddComponentへ結合した必要driver-only SWC件数です。
	std::uint32_t								requiredDriverComponentCount{} ;
} ;

/**
 * @brief Provider による一回の scan 結果を表す。
 */
struct ScanResult {
	/// trueの場合は候補0件を含めscan自体が成立した。
	bool								 succeeded{} ;
	/// 結果を発行したscan session ID。
	ScanSessionId						 scanSessionId{} ;
	/// Provider全体のscan結果分類。
	OutcomeCode							 outcome{OutcomeCode::NOT_STARTED} ;
	/// 単一Providerのscan到達状態。
	ProviderScanState					 state{ProviderScanState::NO_CANDIDATES} ;
	/// Scan失敗または警告を示すnative code。成功時は0。
	NativeError							 error{} ;
	/// UIへ渡す表示可能なdriver候補。
	std::vector<UpdateCandidate>		 candidates ;
	/// 取得元別のscan到達状態。
	std::vector<ProviderScanReport>		 providerReports ;
	/// Manufacturer／setup class別に端末内だけで保持する候補到達件数。
	std::vector<LocalCoverageEntry>		 localCoverage ;
	/// 単一Providerがscan中に集計したlocal coverage。
	ProviderCoverage					 coverage ;
	/// Scan完了時点の計測。未接続時は値なし。
	std::optional<ScanMeasurement>		 measurement ;
	/// 通常scanと情報専用検索の権限を区別する。
	ScanPurpose							 purpose{ScanPurpose::STANDARD} ;
	/// 専用modeのrequest・消費・停止理由。通常scanでは値なし。
	std::optional<MetadataSearchSummary> metadataSearch ;
} ;

/** @brief 一基本driver計画で確認する役割です。任意appを含みません。 */
enum class DriverPlanRole {
	/// 選択parentの基本driverです。
	BASE_DRIVER,
	/// 元選択parentへ適合した拡張です。Windowsの適用完了は別観測です。
	EXTENSION,
	/// 元AddComponentへ結合するdriver-only子です。
	DRIVER_COMPONENT,
} ;

/** @brief stage事実と指定導入API・反映未確認を分離する段階です。 */
enum class DriverPlanReflectionState {
	/// 当該役割をまだ実行していません。
	NOT_STARTED,
	/// package登録だけを確認しています。
	STAGED,
	/// 適用未確認です。queued済みや再起動後の反映を保証しません。
	WINDOWS_PENDING,
	/// 指定device/node導入APIが成功しました。実状態観測とは別です。
	INSTALL_API_COMPLETED,
	/// 当該役割の処理が失敗しました。
	FAILED,
} ;

/** @brief 必要構成一件の非機密実行事実です。INF名・ID・pathを公開しません。 */
struct DriverPlanRoleExecutionResult {
	/// 計画内の役割です。
	DriverPlanRole			  role{DriverPlanRole::BASE_DRIVER} ;
	/// 当該役割の1起点の計画内連番です。
	std::uint32_t			  ordinal{} ;
	/// package登録処理の結果です。
	OutcomeCode				  stageOutcome{OutcomeCode::NOT_STARTED} ;
	/// 元stage HRESULTです。
	NativeError				  stageError{} ;
	/// 指定導入APIの結果です。Extension stageだけならNOT_STARTEDです。
	OutcomeCode				  installOutcome{OutcomeCode::NOT_STARTED} ;
	/// 元指定導入または反映待ち診断です。
	NativeError				  installError{} ;
	/// 指定APIのFALSEとLastError0を観測した場合trueです。installErrorは内部補完値です。
	bool					  installDiagnosticMissing{} ;
	/// 観測した事実の段階です。
	DriverPlanReflectionState reflection{DriverPlanReflectionState::NOT_STARTED} ;
} ;

/** @brief 一候補の取得・指定導入と必要役割の個別事実を保持します。 */
struct UpdateExecutionResult {
	/// Scan結果と対応付けるopaque candidate identity。
	std::wstring							   identity ;
	/// 個別downloadの結果分類。
	OutcomeCode								   downloadOutcome{OutcomeCode::NOT_STARTED} ;
	/// 個別downloadのnative error。成功時は0。
	NativeError								   downloadError{} ;
	/// 個別installの結果分類。
	OutcomeCode								   installOutcome{OutcomeCode::NOT_STARTED} ;
	/// 個別installのnative error。成功時は0。
	NativeError								   installError{} ;
	/// trueの場合はこのinstall完了に再起動が必要である。
	bool									   rebootRequired{} ;
	/// 公式installer引継ぎを実行した方式です。driver導入済みを意味しません。
	bool									   installerHandoff{} ;
	/// 専用引継ぎの成否です。installOutcomeはNOT_STARTEDのまま保持します。
	OutcomeCode								   handoffOutcome{OutcomeCode::NOT_STARTED} ;
	/// 引継ぎ開始または終了の元HRESULTです。正常時0です。
	NativeError								   handoffError{} ;
	/// 実process終端を確認できた場合だけ元exit codeを保持します。
	std::optional<std::uint32_t>			   installerExitCode ;
	/// 元一候補の必要構成順の個別結果です。空は従来単一方式です。
	std::vector<DriverPlanRoleExecutionResult> requiredRoles ;
} ;

/**
 * @brief Windows の復元ポイント開始または終了操作の結果を表す。
 */
struct RestorePointOperationResult {
	/// 復元ポイントAPIの結果分類。
	OutcomeCode	 outcome{OutcomeCode::NOT_STARTED} ;
	/// 失敗時のHRESULTまたはWin32 error。
	NativeError	 error{} ;
	/// Windowsが返した復元ポイント識別番号。失敗時は0。
	std::int64_t sequenceNumber{} ;
} ;

/**
 * @brief Driver install前に適用するOS別の回復保護方針を表す。
 */
enum class InstallProtectionMode {
	/// Windows clientで復元ポイントの成功を必須にする。
	WINDOWS_RESTORE_POINT,
	/// Windows Serverで管理者同意後に復元ポイントなしで実行する。
	SERVER_WITHOUT_RESTORE_POINT,
} ;

/**
 * @brief 選択された update collection 全体の実行結果を表す。
 */
struct InstallResult {
	/// Install開始時に検証したOS別の回復保護方針。
	InstallProtectionMode			   protectionMode{InstallProtectionMode::WINDOWS_RESTORE_POINT} ;
	/// Driver変更前の復元ポイント開始結果。
	RestorePointOperationResult		   restorePointCreation ;
	/// Driver変更処理後の復元ポイント終了結果。
	RestorePointOperationResult		   restorePointCompletion ;
	/// trueの場合はOS別の回復保護契約と全選択対象のinstallが成功した。
	bool							   succeeded{} ;
	/// Collection全体のdownload結果。
	OutcomeCode						   downloadOutcome{OutcomeCode::NOT_STARTED} ;
	/// Collection downloadのnative error。成功時は0。
	NativeError						   downloadError{} ;
	/// Collection全体のinstall結果。
	OutcomeCode						   installOutcome{OutcomeCode::NOT_STARTED} ;
	/// Collection installのnative error。成功時は0。
	NativeError						   installError{} ;
	/// trueの場合は少なくとも一件が再起動を要求した。
	bool							   rebootRequired{} ;
	/// 選択候補と同じidentity集合の個別結果。
	std::vector<UpdateExecutionResult> updates ;
} ;

/**
 * @brief Provider が長時間処理のどの段階にいるかを表す。
 */
enum class ProviderStage {
	/// Present deviceとDriver Storeを列挙する段階。
	SCANNING_DEVICES,
	/// Windows Updateへ適用可能な候補を照会する段階。
	SEARCHING_WINDOWS_UPDATE,
	/// Hardware makerの公式catalogを照会する段階。
	SEARCHING_OFFICIAL_CATALOGS,
	/// 複数取得元の候補をdevice単位へ統合する段階。
	MERGING_CANDIDATES,
	/// Driver変更前の復元ポイントを作成する段階。
	CREATING_RESTORE_POINT,
	/// Payloadの取得またはcache検証段階。
	DOWNLOADING,
	/// Driverをsystemへ適用する段階。
	INSTALLING,
	/// Driver変更後の復元ポイントを確定する段階。
	FINALIZING_RESTORE_POINT,
} ;

/**
 * @brief Provider operationの確定済み進捗をUIへ渡す値である。
 *
 * @note `percentComplete`はoperation全体に対する0～100の値である。
 * `totalItems`が0の場合、現在段階では件数を確定できないことを示す。
 */
struct ProviderProgress {
	/// 現在実行中の処理段階。
	ProviderStage stage{ProviderStage::SCANNING_DEVICES} ;
	/// Operation全体の完了率（0～100）。
	std::uint32_t percentComplete{} ;
	/// 現在段階で処理を完了した項目数。
	std::uint64_t completedItems{} ;
	/// 現在段階の総項目数。未確定時は0。
	std::uint64_t totalItems{} ;
} ;

} // namespace drivercrate
