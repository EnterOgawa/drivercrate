//------------------------------------------------------------------------------
/**
 * @file dell_server_update_provider.h
 * @brief Dell PowerEdge公式driver Provider定義。
 * @version 01.00.01
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  G11未接続候補の導入禁止追加。
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
 * @note Dell PowerEdge上のWindows Server x64だけでEnterprise catalogを検索し、検証済み個別driver DUPを利用者の明示確認後に対話起動
 *       します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_catalog_provider.h"
#include "platform/official_http_client.h"

#include <span>
#include <string>
#include <unordered_map>

namespace drivercrate {

/**
 * @brief Dell PowerEdge Enterprise catalogと個別driver DUPを扱うProviderである。
 *
 * @note Hardware ID、device instance ID、Service Tag、serial numberをDellへ送信しない。
 * Catalog側PCI IDだけをworker内local matcherへ渡す。
 */
class DellServerUpdateProvider final : public IOfficialCatalogProvider {
public:
	/**
     * @brief 空のPowerEdge Providerを作成する。
     */
	DellServerUpdateProvider() = default ;

	/**
     * @brief Scan sessionとinstall targetを解放する。
     */
	~DellServerUpdateProvider() = default ;

	// Scan sessionとDUP metadataを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief PowerEdge scan sessionとDUP metadataの二重管理を防ぐため、コピー構築を禁止する。
	 */
	DellServerUpdateProvider( const DellServerUpdateProvider &) = delete ;
	/**
	 * @brief PowerEdge scan sessionとDUP metadataを別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	DellServerUpdateProvider &operator=( const DellServerUpdateProvider &) = delete ;
	/**
	 * @brief PowerEdge scan sessionとDUP metadataを元のServer Providerに留めるため、移動構築を禁止する。
	 */
	DellServerUpdateProvider( DellServerUpdateProvider &&) = delete ;
	/**
	 * @brief 元のServer Providerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	DellServerUpdateProvider   &operator=( DellServerUpdateProvider &&) = delete ;

	/**
	 * @brief Dell PowerEdgeに対応する公式Windows Server x64 driverを検索する。
	 * PowerEdge公式Windows Server x64 driverを検索する。
	 * Server、Dell、PowerEdgeをlocal確認後だけ公式catalogへ接続し、端末IDを送信せずlocal matcherでcandidateを作成する。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。
	 * @param[in] devices Driver Store列挙から得た非機密device snapshot群。 非機密local device snapshot群。
	 * @param[in] hardwareIdMatcher Catalog側PCI IDをlocal deviceへ解決する関数。 Catalog PCI IDのlocal照合関数。
	 * @param[in] progressCallback Catalog取得、検証、照合の進捗通知先。 Catalog処理の進捗通知先。
	 * @return PowerEdge候補または取得・検証失敗を含むscan結果。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId							scanSessionId,
									 std::span<const OfficialCatalogDevice> devices,
									 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
									 const ProviderProgressCallback		   &progressCallback) override ;

	/**
	 * @brief 選択されたPowerEdge driver DUPを取得・検証して対話起動する。
	 * 選択されたPowerEdge DUPを取得・検証して対話起動する。
	 * 実OS、session、identity、一device一候補を再検証し、同じDUPを一度だけ実行して結果を全対応candidateへ反映する。
	 * @param[in] scanSessionId 選択元のscan session ID。 選択元scan session ID。
	 * @param[in] identities UIへ提示済みのopaque candidate identity群。 UIへ提示済みopaque identity群。
	 * @param[in] parentWindowNative 将来のinstaller親Window連携用。現在は使用しない。 現在未使用の親Window値。
	 * @param[in] progressCallback Download、検証、install待機の進捗通知先。 Download/install進捗通知先。
	 * @return 選択候補ごとのdownload/install結果。
	 * @note G11-C／D未接続候補はtargetへ登録せず、identityを拒否する。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					scanSessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parentWindowNative,
										const ProviderProgressCallback &progressCallback) override ;

private:
	/**
     * @brief Scan時に検証しworker内だけで保持するPowerEdge DUP metadataである。
     */
	struct InstallTarget {
		/// 同じDUPを一度だけ実行するopaque package ID。
		std::wstring  packageIdentity ;
		/// Dell発行の安全な英数字release ID。
		std::wstring  releaseId ;
		/// Allowlist検証対象の公式DUP URL。
		std::wstring  downloadUrl ;
		/// Catalog宣言の小文字SHA-256。
		std::wstring  sha256 ;
		/// 対応するopaque local device identity。
		std::wstring  deviceIdentity ;
		/// Catalog宣言のDUP byte数。
		std::uint64_t size{} ;
		/// Catalogが再起動必須と宣言した場合true。
		bool		  rebootRequired{} ;
	} ;

	/**
	 * @brief 現在のscan sessionと全DUP targetを失効させる。
	 * Opaque identity再利用とstale公式URL実行を防ぐ。
	 */
	void											invalidateScanSession() noexcept ;

	/// 公式host限定の同期HTTP client。
	OfficialHttpClient								httpClient_ ;
	/// 候補別DUP metadata。
	std::unordered_map<std::wstring, InstallTarget> installTargets_ ;
	/// Installを許可する現在のscan session ID。
	ScanSessionId									scanSessionId_{} ;
} ;

} // namespace drivercrate
