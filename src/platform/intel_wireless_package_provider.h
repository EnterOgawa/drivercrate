//------------------------------------------------------------------------------
/**
 * @file intel_wireless_package_provider.h
 * @brief 利用者選択INF package Provider定義。
 * @version 01.01.02
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider固有policyの共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Package由来class照合mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider固有class照合関数追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通個別INF検査とWindows適合観測の接続を追加。
 * Ver.01.01.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 利用者が一件だけ選択したINF ZIPを探索区分Cとして検証し、現在deviceへの完全一致候補だけを保持します。Network通信、directory探索、利用許諾の自動承認は行い
 *       ません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_provider.h"
#include "platform/official_catalog_device.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_zip.h"
#include "platform/user_selected_inf_package.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace drivercrate {

/**
 * @brief 検証済みINFを一つのopaque local deviceへ導入するworker内限定関数。
 */
using VerifiedExternalInfInstaller =
	std::function<NativeError( ScanSessionId, std::wstring_view, std::wstring_view,
							  std::wstring_view, std::wstring_view, std::uintptr_t, bool &)> ;

/**
 * @brief 利用者選択ZIPをProvider固有policyで検証する関数。
 */
using UserSelectedInfPackageInspector = NativeError ( *)( std::wstring_view, ScanSessionId,
														OfficialDownloadWorkspace &,
														UserSelectedInfPackageContents &) ;

/**
 * @brief Scan時に保持した一つのINFをinstall直前に再検証する関数。
 */
using UserSelectedInfPackageReverifier = NativeError ( *)( const OfficialDownloadWorkspace &,
														 std::span<const OfficialZipEntry>,
														 const OfficialInfPackage &) ;

/**
 * @brief 署名済みINFのPnP IDが利用者へ公開された対象範囲か判定する関数。
 */
using UserSelectedHardwareIdPredicate = bool ( *)( std::wstring_view) ;

/**
 * @brief Package由来classと現在device classのProvider固有対応を判定する関数。
 */
using UserSelectedDeviceClassMatcher = bool ( *)( std::wstring_view, std::wstring_view) noexcept ;

/**
 * @brief 同じworkerで単一INFと指定deviceのWindows nodeを観測する非実行callback。
 */
using CommonInfRankObserver =
	std::function<NativeError( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							  const OfficialInfPackage &, std::optional<std::uint32_t> &)> ;

/**
 * @brief 利用者選択INF Providerの表示、検証、identity条件を表す。
 */
struct UserSelectedInfProviderPolicy {
	/// Registryに一度だけ登録したstable Provider ID。
	std::wstring					 providerId ;
	/// Coverageと候補化に許可するsetup class。
	std::wstring					 deviceClass ;
	/// Opaque candidate identity用のASCII prefix。
	std::wstring					 identityPrefix ;
	/// Opaque package identity用のASCII prefix。
	std::wstring					 packagePrefix ;
	/// Candidate titleのProvider固有prefix。
	std::wstring					 titlePrefix ;
	/// UIに表示する論理取得元。
	std::wstring					 sourceName ;
	/// UIに表示する信頼境界。
	std::wstring					 sourceLocation ;
	/// Scan時のpackage検証関数。
	UserSelectedInfPackageInspector	 inspect{} ;
	/// Install直前のINF再検証関数。
	UserSelectedInfPackageReverifier reverify{} ;
	/// Candidate化を許可するPnP ID条件。
	UserSelectedHardwareIdPredicate	 hardwareIdAllowed{} ;
	/// Package由来class modeで使用する追加照合関数。空の場合は完全一致。
	UserSelectedDeviceClassMatcher	 deviceClassMatches{} ;
	/// trueの場合は同一deviceの複数版を表示する。
	bool							 allowMultiplePackagesPerDevice{} ;
	/// trueの場合は固定device_classでなく、検証済み各INFのclassを現在deviceへ照合する。
	bool							 usePackageDeviceClass{} ;
	/// trueの場合だけ全個別INF検査とWindows適合観測の共通経路を使用する。
	bool							 useCommonInspection{} ;
} ;

/**
 * @brief 利用者選択INF ZIPをProvider固有policyで検証し導入するProviderである。
 *
 * @note 選択file path、INF path、PnP IDはworker thread内だけに保持し、network、UI、logへ渡さない。
 */
class UserSelectedInfPackageProvider final {
public:
	/**
	 * @brief Intel Wireless用policyを持つProviderを作成する。
	 * Intel Wireless用の利用者選択Providerを作成する。
	 * Intel固有policyを所有する共通実装へ委譲する。
	 */
	UserSelectedInfPackageProvider() ;

	/**
	 * @brief 明示されたProvider固有policyを単独所有するProviderを作成する。
	 * 明示Provider policyを所有する共通実装を作成する。
	 * 文字列と関数pointerを所有し、scan時に必須値を再検証する。
	 * @param[in] policy Stable ID、表示文字列、検証関数およびPnP ID条件。 本instanceが単独所有するProvider固有条件。
	 */
	explicit UserSelectedInfPackageProvider( UserSelectedInfProviderPolicy policy) ;

	/**
     * @brief Scan sessionと保護workspaceを解放する。
     */
	~UserSelectedInfPackageProvider() ;

	// Scan sessionと展開済みpackageを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief scan sessionと展開済みpackageの二重管理を防ぐため、コピー構築を禁止する。
	 */
	UserSelectedInfPackageProvider( const UserSelectedInfPackageProvider &) = delete ;
	/**
	 * @brief scan sessionと展開済みpackageを別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	UserSelectedInfPackageProvider &operator=( const UserSelectedInfPackageProvider &) = delete ;
	/**
	 * @brief scan sessionと展開済みpackageを元の選択package Providerに留めるため、移動構築を禁止する。
	 */
	UserSelectedInfPackageProvider( UserSelectedInfPackageProvider &&) = delete ;
	/**
	 * @brief 元の選択package Providerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	UserSelectedInfPackageProvider &operator=( UserSelectedInfPackageProvider &&) = delete ;

	/**
	 * @brief 利用者選択ZIPを検証し現在deviceに完全一致する候補を作成する。
	 * 利用者選択ZIPを現在device候補へ変換する。
	 * 全INFの検証完了後だけ候補を公開し、複数INFが同じdeviceへ一致した場合はそのdeviceを候補化しない。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。 0ではないscan session ID。
	 * @param[in] options Provider IDと一件のlocal fileを持つ検証対象scan設定。 Provider IDとlocal fileを持つscan設定。
	 * @param[in] devices Driver Store列挙から得た非機密device snapshot群。 非機密current device snapshot群。
	 * @param[in] hardwareIdMatcher INF由来PnP IDをlocal deviceへ解決する照合関数。 INF PnP IDのlocal照合関数。
	 * @param[in] progressCallback 検証段階、件数、完了率の通知先。 検証進捗の通知先。
	 * @param[in] rankObserver 共通検査経路で必須の非実行Windows適合観測。従来経路では空を許す。
	 * @return 検証済み候補、候補なし、入力失敗またはmetadata拒否を含むscan結果。 一意にPnP一致した候補または検証結果を含むscan結果。
	 */
	[[nodiscard]] ScanResult		scan( ScanSessionId scanSessionId, const ScanOptions &options,
										 std::span<const OfficialCatalogDevice> devices,
										 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
										 const ProviderProgressCallback		   &progressCallback,
										 const CommonInfRankObserver		   &rankObserver = {}) ;

	/**
	 * @brief 選択候補のINF／CATを再検証して対応deviceへ導入する。
	 * 選択INFをProvider固有policyで再検証して導入する。
	 * Stale／重複selectionを変更前に拒否し、各INFの署名、CAT member、metadataを再検証してから一deviceずつ導入する。
	 * @param[in] scanSessionId 選択元のscan session ID。 選択元scan session ID。
	 * @param[in] identities UIへ提示済みのopaque candidate identity群。 UI提示済みopaque candidate ID群。
	 * @param[in] parentWindowNative Device installerの親HWNDを整数表現で渡す値。 Installer親HWNDの整数表現。
	 * @param[in] installer 現在inventoryのopaque deviceへINFを導入する関数。 Opaque deviceへINFを適用するworker関数。
	 * @param[in] progressCallback 検証とinstallの進捗通知先。 検証・install進捗通知先。
	 * @return 選択候補ごとの検証・install結果。 選択順の個別検証・install結果。
	 */
	[[nodiscard]] InstallResult		install( ScanSessionId						scanSessionId,
											std::span<const std::wstring>		identities,
											std::uintptr_t						parentWindowNative,
											const VerifiedExternalInfInstaller &installer,
											const ProviderProgressCallback	   &progressCallback) ;

private:
	/**
	 * @brief 共通内容検査をWindows適合観測へ渡し、表示専用の候補を生成する。
	 * @param[in] scanSessionId 現在scan session。
	 * @param[in] devices 現在構成の非機密snapshot。
	 * @param[in] rankObserver 単一INFとdeviceの非実行Windows観測。
	 * @param[in] progressCallback 確定した件数の通知先。
	 * @param[in] inspection 全体検査を完了し、本Providerが所有する個別INF群。
	 * @return 部分拒否と観測失敗を含む候補結果。導入許可を発行しない。
	 */
	[[nodiscard]] ScanResult buildCommonCandidates(
		ScanSessionId scanSessionId, std::span<const OfficialCatalogDevice> devices,
		const CommonInfRankObserver &rankObserver, const ProviderProgressCallback &progressCallback,
		const CommonDriverPackageInspection &inspection) const ;

	/// 共通経路の個別INF結果と閉包。Scan終了後も次回scanまで所有する。
	std::unique_ptr<CommonDriverPackageInspection> commonInspection_ ;
	/**
     * @brief Scan時に検証しinstall直前に再検証する一つのINF対象である。
     */
	struct InstallTarget {
		/// 対応するscan session内opaque device identity。
		std::wstring	   deviceIdentity ;
		/// 署名とPnP IDを検証済みのINF metadata。
		OfficialInfPackage package ;
	} ;

	/**
	 * @brief Scan session、秘密metadata、展開fileを失効させる。
	 * 次回scanまたはinstall完了後にstale identityとlocal pathを再利用できない状態へ戻す。
	 */
	void											invalidateScanSession() noexcept ;

	/// 本Providerが単独所有する固有検証・表示条件。
	UserSelectedInfProviderPolicy					policy_ ;
	/// 展開fileを所有する保護領域。
	std::unique_ptr<OfficialDownloadWorkspace>		workspace_ ;
	/// Install再検証用ZIP entry群。
	std::vector<OfficialZipEntry>					entries_ ;
	/// Candidate別秘密対象。
	std::unordered_map<std::wstring, InstallTarget> installTargets_ ;
	/// Installを許可する現在のscan session ID。
	ScanSessionId									scanSessionId_{} ;
	/// Scanとinstallを所有するworker thread ID。
	std::uint32_t									ownerThreadId_{} ;
} ;

} // namespace drivercrate
