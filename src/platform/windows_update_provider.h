//------------------------------------------------------------------------------
/**
 * @file windows_update_provider.h
 * @brief Windows Update provider定義。
 * @version 01.01.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Operation進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通scan条件対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Firmware候補除外追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  WUA query計測参照を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  WUA／WSUS既定service選択の試験境界を追加。
 * Ver.01.01.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Windows Update Agentを利用するdriver update providerを定義します。Instanceと全WUA COM objectは一つのCOM MTA
 *       worker threadに所属します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/scan_measurement.h"
#include "core/update_provider.h"

#include <Windows.h>
#include <wrl/client.h>
#include <wuapi.h>

#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace drivercrate {

//------------------------------------------------------------------------------
// Candidate policy関数定義。
//------------------------------------------------------------------------------

/**
 * @brief WUA検索で使用する端末既定のupdate service選択を返す。
 * @return Windows Update、Microsoft UpdateまたはWSUSの管理policyを尊重する`ssDefault`。
 * @note Providerはこの値を`IUpdateSearcher::ServerSelection`へ設定し、管理対象serviceを迂回しない。
 */
[[nodiscard]] ServerSelection windowsUpdateServerSelection() noexcept ;

/**
 * @brief WUA driver metadataが初期版のdriver-only境界を満たすか判定する。
 * WUA driver metadataがdriver-only境界を満たすか判定する。
 * Classを必須とし、firmware／UEFI／BIOSを示す候補をdefense-in-depthでtitleからも除外する。
 * @param[in] driverClass WUAが返した空でないDriverClass。 WUAが返したDriverClass。
 * @param[in] title WUAが返したupdate title。
 * @return 通常のPnP driver候補として扱える場合は`true`。
 * @note Firmware、UEFI、BIOSを示す候補は大小文字を区別せず拒否する。
 */
[[nodiscard]] bool			  isWuaDriverCandidateAllowed( std::wstring_view driverClass,
														  std::wstring_view title) noexcept ;

//------------------------------------------------------------------------------
// Provider class定義。
//------------------------------------------------------------------------------

/**
 * @brief 端末で構成された Windows Update service を使用する Provider である。
 */
class WindowsUpdateProvider	  final : public IUpdateProvider {
public:
	  /**
     * @brief 現在 thread で遅延初期化する空の WUA Provider を作成する。
     */
	  WindowsUpdateProvider() = default ;

	  /**
     * @brief WUA COM object と scan session を解放する。
     */
	  ~WindowsUpdateProvider() override = default ;

	  // COM apartmentに所属するWUA objectを単独所有するためcopy/moveを禁止する。
	  /**
	   * @brief WUA COM objectとscan sessionの二重管理を防ぐため、コピー構築を禁止する。
	   */
	  WindowsUpdateProvider( const WindowsUpdateProvider &) = delete ;
	  /**
	   * @brief WUA COM objectとscan sessionを別個体の状態で上書きさせないため、コピー代入を禁止する。
	   */
	  WindowsUpdateProvider &operator=( const WindowsUpdateProvider &) = delete ;
	  /**
	   * @brief WUA COM objectとscan sessionを元のCOM apartmentのProviderに留めるため、移動構築を禁止する。
	   */
	  WindowsUpdateProvider( WindowsUpdateProvider &&) = delete ;
	  /**
	   * @brief 元のCOM apartmentのProviderへの結合を保つため、移動代入による管理状態の置換を禁止する。
	   */
	  WindowsUpdateProvider		 &operator=( WindowsUpdateProvider &&) = delete ;

	  /**
	 * @brief 端末に構成された update service へ適用可能な driver を問い合わせる。
	 * 端末に構成された update service へ適用可能な driverを問い合わせる。
	 * 端末に構成された update service へ適用可能な driverを問い合わせる。 注記: online 検索を行うが、payload のdownload と install は
	 * 行わない。
	 * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。 呼出し側が割り当てた 0 ではないsession ID。
	 * @param[in] options Aggregate Provider以外では既定値を使用するscan設定。 複合Providerで検証済みのscan条件。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return WUA の適用性判定と取得元 metadata を含む scan 結果。
	 * @note online 検索を行うが、payload の download と install は行わない。
	 */
	  [[nodiscard]] ScanResult	  scan( ScanSessionId scanSessionId, const ScanOptions &options,
									   const ProviderProgressCallback &progressCallback) override ;

	  /**
	 * @brief scan 時の WUA collection から選択 update を download/install する。
	 * scan 時の WUA collection から選択 update をdownload/install する。
	 * @param[in] scanSessionId 選択元の WUA scan session ID。
	 * @param[in] identities UI に提示済みの opaque WUA identity 群。
	 * @param[in] parentWindowNative WUA installer の親 HWND を整数表現で渡す値。 WUA installer の親 HWNDを整数表現で渡す値
	 *                   。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return 選択 update ごとの download/install 結果。
	 */
	  [[nodiscard]] InstallResult install( ScanSessionId					  scanSessionId,
										  std::span<const std::wstring>	  identities,
										  std::uintptr_t				  parentWindowNative,
										  const ProviderProgressCallback &progressCallback) override ;

	  /**
	 * @brief scan candidate と対応する WUA Hardware ID を aggregate Provider 内で取得する。
	 * scan candidate と対応する WUA Hardware ID を aggregate Provider 内で取得する。 注記: 戻り値を UI、log、外部通信へ渡してはなら
	 * ない。
	 * @param[in] identity 現在の scan session の update identity。
	 * @return WUA が Hardware ID を返した場合の内部照合値。
	 * @note 戻り値を UI、log、外部通信へ渡してはならない。
	 */
	  [[nodiscard]] std::optional<std::wstring> hardwareIdForIdentity(
		  std::wstring_view identity) const ;

	  /**
	 * @brief 直前のWUA system queryで確定した検索結果とrecord根拠を取得する。
	 * @return Provider所有のworker内根拠への参照。Local deviceとの結合はCompositeが補う。
	 * @note WUA全体queryの成功をdevice別query完了へ配賦しない。
	 */
	  [[nodiscard]] const ProviderMeasurementEvidence &measurementEvidence() const noexcept ;

private:
	  /**
	 * @brief WUA session を現在 thread で遅延生成する。
	 * @return 初期化結果を示す HRESULT。
	 */
	  [[nodiscard]] HRESULT							 ensureSession() ;

	  /**
	 * @brief 保持中の scan collection と identity map を破棄する。
	 */
	  void											 invalidateScanSession() noexcept ;

	  /// Owner worker apartmentのWUA session。
	  Microsoft::WRL::ComPtr<IUpdateSession>		 session_ ;
	  /// 現scanで返されたWUA collection。
	  Microsoft::WRL::ComPtr<IUpdateCollection>		 scanUpdates_ ;
	  /// Identityからcollection indexへの対応。
	  std::unordered_map<std::wstring, LONG>		 updateIndexes_ ;
	  /// 内部照合用Hardware ID。
	  std::unordered_map<std::wstring, std::wstring> hardwareIds_ ;
	  /// WUA queryと検証済みrecordのworker内根拠。
	  ProviderMeasurementEvidence					 measurementEvidence_ ;
	  /// Installを許可する現在のscan session ID。
	  ScanSessionId									 scanSessionId_{} ;
	  /// COM objectを所有するworker thread ID。
	  DWORD											 ownerThreadId_{} ;
} ;

} // namespace drivercrate
