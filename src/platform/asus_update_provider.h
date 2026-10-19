//------------------------------------------------------------------------------
/**
 * @file asus_update_provider.h
 * @brief ASUS公式support page Provider定義。
 * @version 01.00.01
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Package内容監査接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Local PnP／Rank監査接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補化とinstall routing接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Local SMBIOSに一致するASUS公式pageを取得し、G11-B取得物をG11-CのINF／CAT／publisherとG11-DのPnP／Rank監査へ接続し、全gate
 *       合格候補をDriver Store導入境界へroutingします。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/asus_driver_package_audit.h"
#include "platform/asus_package_acquisition.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_http_client.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief 再検証済みASUS INFをDriver Storeの現在deviceへ導入する関数である。
 */
using AsusVerifiedInfInstaller =
	std::function<NativeError( ScanSessionId, std::wstring_view, std::wstring_view,
							  std::wstring_view, std::wstring_view, std::uintptr_t, bool &)> ;

//------------------------------------------------------------------------------
// ASUS Provider class定義。
//------------------------------------------------------------------------------

/**
 * @brief ASUS公式製品別support pageをG11監査とSetupAPI導入へ接続するProviderである。
 *
 * @note Hardware ID、instance ID、serial numberをnetworkへ送信しない。公式archiveの検査用取得が
 * 大容量になり得るため、従量制network同意UIが接続されるまで既定無効とする。
 */
class AsusUpdateProvider final : public IOfficialCatalogProvider {
public:
	/**
	 * @brief Driver Store監査／導入境界へ接続したASUS Providerを作成する。
	 * CallbackはComposite worker内だけで呼び、device秘密情報をASUS Providerまたはnetworkへ渡さない。
	 * @param[in] rankAuditor 現在PnPと候補INFのG11-D監査関数。 G11-Dのread-only監査関数。
	 * @param[in] installer 再検証済みINFを指定deviceへ導入する関数。 再検証済みINFのSetupAPI導入関数。
	 */
	AsusUpdateProvider( AsusOfficialInfRankAuditor rankAuditor, AsusVerifiedInfInstaller installer) ;

	/**
     * @brief 保持中の取得file、取得根拠およびscan sessionを解放する。
     */
	~AsusUpdateProvider() override ;

	// Source sessionと保護workspaceを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief ASUS取得元sessionと保護workspaceの二重管理を防ぐため、コピー構築を禁止する。
	 */
	AsusUpdateProvider( const AsusUpdateProvider &) = delete ;
	/**
	 * @brief ASUS取得元sessionと保護workspaceを別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	AsusUpdateProvider &operator=( const AsusUpdateProvider &) = delete ;
	/**
	 * @brief ASUS取得元sessionと保護workspaceを元のASUS Providerに留めるため、移動構築を禁止する。
	 */
	AsusUpdateProvider( AsusUpdateProvider &&) = delete ;
	/**
	 * @brief 元のASUS Providerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	AsusUpdateProvider		   &operator=( AsusUpdateProvider &&) = delete ;

	/**
	 * @brief Local ASUS modelに対応する公式driverを取得、監査して候補化する。
	 * ASUS公式driver metadataを検索する。
	 * SMBIOS modelだけを固定ASUS pageへ送り、全archiveを有限取得する。G11-C／D合格組合せだけを候補へ昇格する。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。 0ではないscan session ID。
	 * @param[in] devices Networkへ送信せずlocal G11-Dと候補表示に使用するdevice群。 外部送信せずlocal監査するdevice群。
	 * @param[in] hardwareIdMatcher 使用しない。Hardware IDをnetworkへ渡さないため保持もしない。 呼び出さないlocal照合。
	 * @param[in] progressCallback Page取得、archive監査および候補化の進捗通知先。 取得、監査、候補化の進捗通知先。
	 * @return 対象外、監査失敗、候補0件または監査合格候補を含むscan結果。 対象外、監査失敗、候補0件または合格候補を含む結果。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId							scanSessionId,
									 std::span<const OfficialCatalogDevice> devices,
									 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
									 const ProviderProgressCallback		   &progressCallback) override ;

	/**
	 * @brief 選択されたASUS候補を再検証して指定deviceへ導入する。
	 * ASUS監査済みINFを再検証して導入する。
	 * Stale／重複選択を拒否し、同じarchiveを一回再検証する。INF閉包とRankを再監査し、個別導入後にsessionを失効する。
	 * @param[in] scanSessionId 要求元のscan session ID。 要求元session ID。
	 * @param[in] identities 要求されたopaque候補identity群。 要求された候補identity群。
	 * @param[in] parentWindowNative 呼出し側の親Window値。
	 * @param[in] progressCallback 呼出し側の進捗通知先。
	 * @return 選択順の再検証、download cache確認およびinstall結果。 選択順のcache再検証、INF導入および個別結果。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					scanSessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parentWindowNative,
										const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief Scanで固定した一つのASUS archiveを候補化せず検査用取得する。
	 * ASUS archive一件を候補化せず検査用取得する。
	 * 現sessionの完全一致IDだけを共通G11-Bへ渡し、URLやpathを呼出し側に組み立てさせない。
	 * @param[in] scanSessionId 現在保持するscan session ID。
	 * @param[in] opaqueId Scan中だけ保持したASUS metadata record ID。 Scan session内のASUS record ID。
	 * @param[in] restrictedNetworkApproved 今回だけcost制限networkを許可する状態。 今回だけのcost同意。
	 * @param[in,out] costReader Machine-wide network cost照会境界。
	 * @param[in] progressCallback 確定済み受信byte数の通知先。 確定済み受信進捗通知先。
	 * @param[in] cancellationCallback 空または取消し状態を返す非blocking関数。 取消し状態確認先。
	 * @param[out] result 成功または失敗の監査前取得状態。URLを含まない。 URLを含まない監査前取得状態。
	 * @return 検査対象固定成功時は0、session、ID、取得失敗時はHRESULT bit pattern。
	 * @note 本結果だけで候補、適用可能またはinstall可能へ昇格してはならない。
	 */
	[[nodiscard]] NativeError	acquireForInspection(
		  ScanSessionId scanSessionId, std::wstring_view opaqueId, bool restrictedNetworkApproved,
		  IOfficialNetworkCostReader		 &costReader,
		  const HttpDownloadProgressCallback &progressCallback,
		  const HttpCancellationCallback &cancellationCallback, OfficialAcquisitionResult &result) ;

	/**
	 * @brief G11-Bで取得した一つのASUS archiveの全INFを内容監査する。
	 * 取得済みASUS archiveの全INFを内容監査する。
	 * Recordの公開SHA-256と取得identityを再拘束し、G11-CとCAT／publisher合格閉包だけを後続G11-D用に保持する。
	 * @param[in] scanSessionId 現在保持するscan session ID。
	 * @param[in] opaqueId Scan中だけ保持したASUS metadata record ID。 Scan時ASUS metadataの内部record ID。
	 * @param[in] acquisition `acquireForInspection`が返した同一sessionの取得結果。 同一recordについてG11-Bが返した結果。
	 * @param[out] summary 全INF、合格、拒否件数と内容監査状態。 全INF、合格、拒否件数と監査状態。
	 * @return 全INF確認完了時は0、session、取得identityまたは全体処理失敗時はHRESULT。 全INF確認完了時は0、sessionまたは全体監査失敗は
	 *         HRESULT。
	 * @note 合格閉包は後続G11-Dのlocal PnP／Rank監査用にworker内だけで保持する。
	 */
	[[nodiscard]] NativeError auditAcquiredPackage( ScanSessionId					scanSessionId,
												   std::wstring_view				opaqueId,
												   const OfficialAcquisitionResult &acquisition,
												   AsusDriverPackageAuditSummary   &summary) ;

	/**
	 * @brief 内容監査済みASUS archiveを現在のlocal PnP／Rankと照合する。
	 * 内容監査済みASUS archiveをlocal PnP／Rank監査する。
	 * 同一workerとsessionの内容監査済み閉包だけをG11-Dへ渡し、合格組合せを後続routingまでProvider内に保持する。
	 * @param[in] scanSessionId 現在保持するDevice inventoryとASUS scan session ID。 Device inventoryと同じ
	 *                   session ID。
	 * @param[in] opaqueId 内容監査済みASUS metadataの内部record ID。 内容監査済みASUS record ID。
	 * @param[in] rankAuditor Driver Storeのread-only G11-D監査関数。 Driver StoreのG11-D監査関数。
	 * @param[out] summary 全組合せ、合格、拒否、失敗件数と到達状態。
	 * @return 全組合せを確認した場合は0、session、IDまたは全体処理失敗時はHRESULT。 全組合せを確認した場合は0、全体処理失敗時はHRESULT。
	 * @note 合格組合せはcandidate routing生成までworker内だけで保持する。
	 */
	[[nodiscard]] NativeError auditRetainedPackageApplicability(
		ScanSessionId scanSessionId, std::wstring_view opaqueId,
		const AsusOfficialInfRankAuditor &rankAuditor, AsusDriverApplicabilitySummary &summary) ;

private:
	/**
     * @brief 一つのASUS record IDと内容監査済み閉包をscan session内で所有する。
     */
	struct AuditedArchive {
		/// ASUS metadata recordとの完全一致用内部ID。
		std::wstring			  opaqueId ;
		/// 外側archiveの固定size／hashと保護path。
		OfficialAcquisitionResult acquisition ;
		/// 全INF監査結果と合格閉包の所有object。
		AsusDriverPackageAudit	  package ;
	} ;

	/**
     * @brief 一つの候補を監査済みarchive、INFおよびdeviceへ拘束する。
     */
	struct InstallTarget {
		/// 同じ外側archiveを束ねるopaque package ID。
		std::wstring			packageIdentity ;
		/// Scan session内のopaque local device ID。
		std::wstring			deviceIdentity ;
		/// `auditedArchives_`内のarchive index。
		std::size_t				archiveIndex{} ;
		/// Archive内の監査済みINF index。
		std::size_t				auditedPackageIndex{} ;
		/// Scan時のG11-D完全比較対象。
		OfficialDriverRankAudit rankAudit ;
	} ;

	/**
	 * @brief 保持中のscan session、取得計画、fileおよび取得根拠を失効させる。
	 * ASUS scan sessionと取得物を失効させる。
	 * Workspaceを先に破棄して既知fileを削除し、旧ID、ledger、HTTP取得根拠を次scanへ持ち越さない。
	 */
	void											invalidateScanSession() noexcept ;

	/// ASUSの組み込みoriginだけを許可する同期HTTP client。
	OfficialHttpClient								httpClient_ ;
	/// Driver Storeへ閉じたG11-D監査関数。
	AsusOfficialInfRankAuditor						rankAuditor_ ;
	/// 再検証済みINFのSetupAPI導入関数。
	AsusVerifiedInfInstaller						installer_ ;
	/// Scan sessionに固定したASUS metadata由来の検査用取得計画。
	std::vector<AsusPackageAcquisitionPlanEntry>	acquisitionPlan_ ;
	/// Scan sessionの有限取得量を管理するworker thread専用ledger。
	std::unique_ptr<OfficialAcquisitionSession>		acquisitionSession_ ;
	/// Scan sessionで取得した検査前fileをscope終了まで所有する保護領域。
	std::unique_ptr<OfficialDownloadWorkspace>		workspace_ ;
	/// CAT memberとpublisher監査を通過し、G11-Dを待つarchive群。
	std::vector<AuditedArchive>						auditedArchives_ ;
	/// UIへ発行した候補identityと監査済み内部targetの照合表。
	std::unordered_map<std::wstring, InstallTarget> installTargets_ ;
	/// G11-Dへ渡すHardware IDを含まない現在device snapshot群。
	std::vector<OfficialCatalogDevice>				localDevices_ ;
	/// 現在取得計画を所有するscan session ID。
	ScanSessionId									scanSessionId_{} ;
	/// ASUS sessionを所有するworker thread ID。
	std::uint32_t									ownerThreadId_{} ;
} ;

} // namespace drivercrate
