//------------------------------------------------------------------------------
/**
 * @file lenovo_update_provider.h
 * @brief Lenovo公式driver Provider定義。
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
 * @note Lenovo PCのMachine TypeとWindows世代をlocalで判定し、公式model catalogの署名済みdriver descriptorだけをHardware
 *       IDへlocal照合します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_catalog_provider.h"
#include "platform/official_http_client.h"

#include <span>
#include <string>
#include <unordered_map>

namespace drivercrate {

//------------------------------------------------------------------------------
// Lenovo Provider class定義。
//------------------------------------------------------------------------------

/**
 * @brief Lenovo公式model catalogと署名済みpackage descriptorを扱うProviderである。
 *
 * @note 端末のMachine Typeだけを公式URLへ含める。Hardware ID、instance ID、serial numberは
 * Lenovoへ送信せず、descriptor由来IDをlocal matcherへ渡す。
 */
class LenovoUpdateProvider final : public IOfficialCatalogProvider {
public:
	/**
     * @brief 空のLenovo Providerを作成する。
     */
	LenovoUpdateProvider() = default ;

	/**
     * @brief Scan sessionとdownload targetを解放する。
     */
	~LenovoUpdateProvider() = default ;

	// Scan sessionとinstaller targetを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief Lenovo scan sessionとinstaller対象の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LenovoUpdateProvider( const LenovoUpdateProvider &) = delete ;
	/**
	 * @brief Lenovo scan sessionとinstaller対象を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LenovoUpdateProvider &operator=( const LenovoUpdateProvider &) = delete ;
	/**
	 * @brief Lenovo scan sessionとinstaller対象を元のLenovo Providerに留めるため、移動構築を禁止する。
	 */
	LenovoUpdateProvider( LenovoUpdateProvider &&) = delete ;
	/**
	 * @brief 元のLenovo Providerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	LenovoUpdateProvider	   &operator=( LenovoUpdateProvider &&) = delete ;

	/**
	 * @brief Lenovo PCに対応する公式Windows x64 driver releaseを検索する。
	 * Lenovo PCに対応する公式Windows x64 releaseを検索する。
	 * Lenovo client PCだけでMachine Type別catalogを取得し、descriptor hash、XML署名、local Hardware IDを検証する。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。 0ではないscan session ID。
	 * @param[in] devices Driver Store列挙から得た非機密device snapshot群。 Local device表示metadata群。
	 * @param[in] hardwareIdMatcher Catalog側IDをlocal deviceへ解決する照合関数。 Catalog IDのlocal照合関数。
	 * @param[in] progressCallback Catalog取得・検証・照合の進捗通知先。 Catalog処理の進捗通知先。
	 * @return Lenovo候補または取得・検証失敗を含むscan結果。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId							scanSessionId,
									 std::span<const OfficialCatalogDevice> devices,
									 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
									 const ProviderProgressCallback		   &progressCallback) override ;

	/**
	 * @brief 選択されたLenovo公式packageを取得・検証して対話起動する。
	 * 選択されたLenovo公式payloadを取得・検証して対話起動する。
	 * Session、identity、device重複を検証し、同一payloadを一度だけhash・署名再検証して対話実行する。
	 * @param[in] scanSessionId 選択元のscan session ID。 選択元scan session ID。
	 * @param[in] identities UIに提示済みのopaque Lenovo候補identity群。 UIに提示済みopaque identity群。
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
     * @brief Scan時に署名検証し、worker内だけで保持するLenovo metadataである。
     */
	struct InstallTarget {
		/// 同じpayloadを一回だけ実行するopaque package ID。
		std::wstring  packageIdentity ;
		/// Allowlist検証対象の公式installer URL。
		std::wstring  downloadUrl ;
		/// Descriptorが宣言した小文字SHA-256。
		std::wstring  sha256 ;
		/// 対応するopaque device identity。
		std::wstring  deviceIdentity ;
		/// Descriptorが宣言したinstaller byte数。
		std::uint64_t size{} ;
		/// Descriptor上、再起動可能性がある場合true。
		bool		  rebootMayBeRequired{} ;
	} ;

	/**
	 * @brief Scan sessionとinstaller targetを失効させる。
	 * Opaque identity再利用とstale公式URL実行を防ぐ。
	 */
	void											invalidateScanSession() noexcept ;

	/// 公式host限定の同期HTTP client。
	OfficialHttpClient								httpClient_ ;
	/// 候補別metadata。
	std::unordered_map<std::wstring, InstallTarget> installTargets_ ;
	/// Installを許可する現在のscan session ID。
	ScanSessionId									scanSessionId_{} ;
} ;

} // namespace drivercrate
