//------------------------------------------------------------------------------
/**
 * @file official_driver_package_audit.h
 * @brief 公式取得物の共通内容・適用性監査契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  WinOF-2閉包profileを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet Server監査profileを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX AX88179A監査profileを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Profile固定Providerの参照境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 取得元profileと同一scanを拘束し、保持閉包をworker内だけで所有します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/update_types.h"
#include "platform/official_catalog_device.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 内部登録された取得元と内容監査条件の組合せである。 */
enum class OfficialDriverAuditProfile {
	/// 公開hash付きASUSの既存非boot-critical class群。
	ASUS,
	/// 公式取得済みNet class、SYS参照必須。
	BROADCOM_NET_XTREME_E,
	/// NVIDIA WinOF-2の固定x64 driver-only class群。
	NVIDIA_WINOF2,
	/// Server 2025向け公開hash付きNet class。
	INTEL_ETHERNET_SERVER2025,
	/// Windows client向け公開hashなしNet class。
	ASIX_AX88179A,
} ;

/**
 * @brief 登録済み内容監査profileに固定されたProvider IDを参照する。
 * 共通監査policyを正本とし、report側へProvider一覧を複製しない。
 * @param[in] profile 内部登録された監査profile。
 * @return Registryと取得ledgerへ照合する固定Provider ID。未知値の場合は空。
 * @note 戻り値はprocess寿命中有効であり、取得元証明または任意Providerの許可には使用しない。
 */
[[nodiscard]] std::wstring_view officialDriverAuditProviderId(
	OfficialDriverAuditProfile profile) noexcept ;

/** @brief 同じworkerから呼ぶ、空または非blockingの協調取消し照会である。 */
using OfficialAuditCancellation = std::function<bool()> ;

/**
 * @brief G11-Dを実装するDriver Store境界をworker内で呼び出す関数である。
 *
 * @note 入力のPnP IDとpathは呼出し中だけ有効であり、callback外へ保持してはならない。
 */
using OfficialInfRankAuditor =
	std::function<NativeError( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							  const OfficialInfPackage &, OfficialDriverRankAudit &)> ;

/**
 * @brief 公式 package内容監査が到達した状態を表す。
 */
enum class OfficialDriverPackageAuditState {
	/// 内容監査を開始していない。
	NOT_STARTED,
	/// 一つ以上のINFが全内容監査を通過した。
	AUDITED,
	/// 全INFを確認したが許可driver閉包がなかった。
	NO_SUPPORTED_INF,
	/// 取得identity、archive構造または全体policyを拒否した。
	REJECTED,
	/// MemoryまたはWindows API処理により監査を完了できなかった。
	FAILURE,
} ;

/**
 * @brief 公式 package一件の内容監査件数と診断値を表す。
 */
struct OfficialDriverPackageAuditSummary {
	/// 到達状態。
	OfficialDriverPackageAuditState state{OfficialDriverPackageAuditState::NOT_STARTED} ;
	/// 全体処理失敗。成功または候補なしの場合は0。
	NativeError						error{} ;
	/// 最初に拒否したINFの診断値。拒否なしは0。
	NativeError						firstRejectionError{} ;
	/// 実際に監査したarchive内の通常file数。
	std::size_t						inventoryFileCount{} ;
	/// Inventoryで確認した全INF数。
	std::size_t						infCount{} ;
	/// CATとpublisherまで合格したINF数。
	std::size_t						auditedInfCount{} ;
	/// 構造または内容policyで拒否したINF数。
	std::size_t						rejectedInfCount{} ;
	/// 0は外側直下、1は一段nested archive。
	std::uint32_t					archiveDepth{} ;
	/// 成功閉包の保持byte数合計。
	std::uint64_t					retainedClosureBytes{} ;
} ;

/**
 * @brief 公式内容監査へ渡す取得identityと公開hashを表す。
 */
struct OfficialDriverPackageAuditRequest {
	/// 本呼出し中有効なG11-B `ACQUIRED_FOR_INSPECTION`結果への非所有pointer。
	const OfficialAcquisitionResult *acquisition{} ;
	/// 公式metadataの公開hash。Profileで必須の場合は実測値を代用せず指定する。
	std::wstring_view				 expectedSha256 ;
	/// 外側形式。
	OfficialDriverArchiveFormat		 archiveFormat{OfficialDriverArchiveFormat::ZIP} ;
	/// 固定取得元／内容条件。
	OfficialDriverAuditProfile		 profile{OfficialDriverAuditProfile::ASUS} ;
} ;

/**
 * @brief CAT memberとpublisher監査を通過した一つのINF閉包を所有する。
 */
struct OfficialAuditedInfPackage {
	/// INF、CAT、参照fileをscope終了まで所有する単独所有workspace。
	std::unique_ptr<OfficialDownloadWorkspace> workspace ;
	/// 一つの検証済みINFとfile閉包。
	OfficialDriverClosure					   closure ;
	/// 再検証時も固定する条件。
	OfficialDriverAuditProfile				   profile{OfficialDriverAuditProfile::ASUS} ;
} ;

/**
 * @brief 公式内容監査済みINFとlocal deviceのG11-D合格組合せを表す。
 *
 * @note 本値はProvider worker内のinstall準備記録であり、候補identityまたはinstall許可ではない。
 */
struct OfficialRankApprovedInfTarget {
	/// Scan session内のopaque local device identity。
	std::wstring			deviceIdentity ;
	/// `auditedPackages`内のINF閉包index。
	std::size_t				auditedPackageIndex{} ;
	/// PnP ID文字列を含まないG11-D合格根拠。
	OfficialDriverRankAudit rankAudit ;
} ;

/**
 * @brief 公式 package一件に対するlocal PnP／Rank監査の到達状態を表す。
 */
enum class OfficialDriverApplicabilityState {
	/// Local system監査を開始していない。
	NOT_STARTED,
	/// 一つ以上のINFとdeviceの組合せがG11-Dに合格した。
	APPLICABLE_TARGETS,
	/// 全組合せを確認したがG11-D合格対象がなかった。
	NO_APPLICABLE_TARGETS,
	/// 入力、sessionまたは保持構造の不整合を拒否した。
	REJECTED,
	/// Memory不足等により全組合せを確認できなかった。
	FAILURE,
} ;

/**
 * @brief 公式 package一件のlocal PnP／Rank監査件数と診断値を表す。
 */
struct OfficialDriverApplicabilitySummary {
	/// Local system監査の到達状態。
	OfficialDriverApplicabilityState state{OfficialDriverApplicabilityState::NOT_STARTED} ;
	/// 全体処理失敗。全組合せ確認時は0。
	NativeError						 error{} ;
	/// 最初の個別SetupAPI失敗。失敗なしは0。
	NativeError						 firstPairError{} ;
	/// G11-Dへ渡したINFとdeviceの組合せ数。
	std::size_t						 examinedPairCount{} ;
	/// `APPLICABLE`となった組合せ数。
	std::size_t						 applicablePairCount{} ;
	/// Policy判断で非適用となった組合せ数。
	std::size_t						 rejectedPairCount{} ;
	/// SetupAPI処理を完了できなかった組合せ数。
	std::size_t						 failedPairCount{} ;
} ;

/**
 * @brief 公式 archive一件の内容監査結果と合格閉包を所有する。
 *
 * @note Hardware IDとworkspace pathはProvider worker内だけで使用し、UIまたはlogへ渡さない。
 */
struct OfficialDriverPackageAudit {
	/// 内容監査の元session。0は未監査。
	ScanSessionId							   scanSessionId{} ;
	/// 件数、状態および診断値。
	OfficialDriverPackageAuditSummary		   summary ;
	/// 全内容監査合格INF群。
	std::vector<OfficialAuditedInfPackage>	   auditedPackages ;
	/// Local PnPとRank非退行を通過したINF／device組合せ。
	std::vector<OfficialRankApprovedInfTarget> rankApprovedTargets ;
	/// G11-Dの件数、状態および診断値。
	OfficialDriverApplicabilitySummary		   applicability ;
} ;

/**
 * @brief 取得済み公式 ZIP／CABの全INFを内容監査する。
 * 既存閉包・署名部品で全INFを監査する。取消し・全体失敗では部分閉包を破棄する。
 * @param[in] request G11-B取得結果、公式公開hashおよび外側archive形式。 取得identity・公開hash・固定profile。
 * @param[out] audit 内容・適用性の監査結果と所有閉包。既存値は初期化し、監査件数と
 *                   CAT／publisher検証済みの非boot-critical INF閉包群を保持する。
 * @param[in] cancellation 空または協調取消し照会。取消しは部分合格を破棄する。 空または非blockingの取消し照会。
 * @return 全archive処理完了時は0、取得identityまたは全体処理失敗時はHRESULT。 成功時0、失敗時はHRESULT。個別拒否は監査件数へ残す。
 * @note 個別INFの拒否は全INFを確認するため処理を継続し、summaryへ件数を残す。
 * @note 外側にINFがなくnested ZIP／CABが一件だけある場合は、その一段内側を監査する。
 */
[[nodiscard]] NativeError auditOfficialDriverPackage(
	const OfficialDriverPackageAuditRequest &request, OfficialDriverPackageAudit &audit,
	const OfficialAuditCancellation &cancellation = {}) ;

/**
 * @brief 内容監査済み公式 INFを現在scanのlocal deviceとG11-D監査する。
 * 同一sessionの同class deviceだけを端末内で照合し、Applicableな組合せだけを保持する。
 * @param[in] scanSessionId Device inventoryと同じ0ではないscan session ID。 内容監査と同一の検索session。
 * @param[in] devices Hardware IDを含まない現在device snapshot群。 現在deviceの非機密snapshot群。
 * @param[in] rankAuditor Driver Storeのread-only PnP／Rank監査関数。 同じworker内のWindows標準PnP／rank監査。
 * @param[in,out] audit 内容監査合格INFと、成功時に追加するG11-D合格組合せ。 内容・適用性監査結果と所有閉包。
 * @param[in] cancellation 空または協調取消し照会。取消しは部分合格を破棄する。 空または非blockingの取消し照会。
 * @return 全組合せを確認した場合は0、入力または全体処理失敗時はHRESULT。 成功時0、失敗時はHRESULT。個別拒否は監査件数へ残す。
 * @note 個別SetupAPI失敗または非適用後も残りを確認し、`APPLICABLE`だけを保持する。
 */
[[nodiscard]] NativeError auditOfficialDriverApplicability(
	ScanSessionId scanSessionId, std::span<const OfficialCatalogDevice> devices,
	const OfficialInfRankAuditor &rankAuditor, OfficialDriverPackageAudit &audit,
	const OfficialAuditCancellation &cancellation = {}) ;

/**
 * @brief 内容監査済み公式 INF閉包をinstall直前に完全再検証する。
 * 同じprofileで全file・INF構造・CAT memberを再検証する。導入許可は別途必要。
 * @param[in] auditedPackage Scan時に固定した保護workspace、file hashおよびINF metadata。 取得後から保持したINF閉包とprofile。
 * @return 全file、INF構造、CAT member、publisherがscan時と一致する場合は0。 成功時0、失敗時はHRESULT。個別拒否は監査件数へ残す。
 * @note 管理者権限を持つ競合processによるscan後の差替えをSetupAPI呼出し前に拒否する。
 */
[[nodiscard]] NativeError reverifyOfficialAuditedInfPackage(
	const OfficialAuditedInfPackage &auditedPackage) ;

} // namespace drivercrate
