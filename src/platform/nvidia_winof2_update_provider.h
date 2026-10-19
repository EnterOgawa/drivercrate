//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_update_provider.h
 * @brief NVIDIA Networking WinOF-2公式表示専用Provider定義。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
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
 * @note NVIDIA公式pageの委譲を確認後、公開OS名だけでWinOF-2 metadataを検索します。Hardware ID等を送信せず、混在EXEをdownload／install
 *       可能な候補にはしません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_catalog_provider.h"
#include "platform/official_http_client.h"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/**
 * @brief 検証済みNVIDIA公式製品page取得を差し替える内部試験境界。
 * @param[in] scanSessionId 0ではないscan session。
 * @param[out] html 成功時の公式製品page本文。失敗時の内容は使用しない。
 * @return 成功時は0、取得を開始または完了できない場合はnative error。
 */
using NvidiaWinof2LandingPageReader =
	std::function<NativeError( ScanSessionId scanSessionId, std::wstring &html)> ;

/**
 * @brief 固定WinOF-2 metadata POSTを差し替える内部試験境界。
 * @param[in] scanSessionId 0ではないscan session。
 * @param[in] formBody 機密情報を含まない検証済みASCII form body。
 * @param[out] json 成功時のUTF-16 JSON。失敗時の内容は使用しない。
 * @return 成功時は0、取得を開始または完了できない場合はnative error。
 */
using NvidiaWinof2MetadataReader = std::function<NativeError(
	ScanSessionId scanSessionId, std::string_view formBody, std::wstring &json)> ;

/**
 * @brief Local deviceがWinOF-2の表示検索対象となるNVIDIA Networking製品か確認する。
 * 通信要否だけを判定し、PnP適用性または最新版を保証しない。
 * @param[in] device 端末内だけで参照する非機密device snapshot。 端末内だけで参照する非機密snapshot。
 * @return Net class、NVIDIA／Mellanox表示、対応系列が全て一致する場合true。 Net class、vendor表示、対応系列が一致する場合true。
 * @note 通信要否を決めるprobeであり、Hardware IDまたはpackage適用性の確認ではない。
 */
[[nodiscard]] bool				 isNvidiaWinof2Device( const OfficialCatalogDevice &device) noexcept ;

/**
 * @brief Local probeと固定readerでWinOF-2の表示専用候補を作る。
 * 対象deviceまたは既知OSがない場合は通信せず、途中応答を補完しない。
 * @param[in] scanSessionId 0ではないscan session。 0ではない検索session。
 * @param[in] devices 最大4096件の外部送信しないdevice snapshot。 最大4096件の外部送信しないsnapshot。
 * @param[in] windowsServer 実OSがWindows Serverの場合true。 実OSがServerの場合true。
 * @param[in] windowsBuild 実OSのmajor build番号。0は判定不能。
 * @param[in] landingReader NVIDIA公式製品pageの差替え取得境界。 固定公式製品pageの取得境界。
 * @param[in] metadataReader 固定form POSTの差替え取得境界。 固定metadata POSTの取得境界。
 * @param[in] progressCallback 確定した処理件数と進捗の通知先。 確定した進捗通知先。
 * @return 表示候補または対象外・通信失敗・metadata拒否。
 */
[[nodiscard]] ScanResult		 scanNvidiaWinof2Catalog( ScanSessionId scanSessionId,
														 std::span<const OfficialCatalogDevice> devices,
														 bool windowsServer, std::uint32_t windowsBuild,
														 const NvidiaWinof2LandingPageReader &landingReader,
														 const NvidiaWinof2MetadataReader &metadataReader,
														 const ProviderProgressCallback &progressCallback) ;

/** @brief NVIDIA Networking WinOF-2の公式metadataを検索する表示専用Provider。 */
class NvidiaWinof2UpdateProvider final : public IOfficialCatalogProvider {
public:
	/** @brief 取得根拠を持たないWinOF-2 Providerを作成する。 */
	NvidiaWinof2UpdateProvider() = default ;
	/**
	 * @brief WinOF-2の取得元sessionと保持中の取得根拠をメンバーの破棄で解放する。
	 */
	~NvidiaWinof2UpdateProvider() override = default ;

	// OfficialHttpClientのsource sessionを単独所有するためcopy／moveを禁止する。
	/**
	 * @brief WinOF-2取得元sessionと取得根拠の二重管理を防ぐため、コピー構築を禁止する。
	 */
	NvidiaWinof2UpdateProvider( const NvidiaWinof2UpdateProvider &) = delete ;
	/**
	 * @brief WinOF-2取得元sessionと取得根拠を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	NvidiaWinof2UpdateProvider &operator=( const NvidiaWinof2UpdateProvider &) = delete ;
	/**
	 * @brief WinOF-2取得元sessionと取得根拠を元のWinOF-2 Providerに留めるため、移動構築を禁止する。
	 */
	NvidiaWinof2UpdateProvider( NvidiaWinof2UpdateProvider &&) = delete ;
	/**
	 * @brief 元のWinOF-2 Providerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	NvidiaWinof2UpdateProvider &operator=( NvidiaWinof2UpdateProvider &&) = delete ;

	/**
	 * @brief 対象deviceと実OSが一致する場合だけ公式WinOF-2 metadataを検索する。
	 * NVIDIA起点と五つのPOST取得根拠が揃わない候補をfail-closedで破棄する。
	 * @param[in] scanSessionId 0ではないscan session。 0ではない検索session。
	 * @param[in] devices 外部送信しない現在device snapshot。 外部送信しないdevice snapshot。
	 * @param[in] hardwareIdMatcher 使用しない。現段階では表示検索に限定する。 使用しないlocal照合関数。
	 * @param[in] progressCallback 確定済み段階の通知先。 確定した進捗通知先。
	 * @return 非選択・非推奨の公式配布情報。Payloadを取得しない。 表示候補またはProvider別失敗状態。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId							scanSessionId,
									 std::span<const OfficialCatalogDevice> devices,
									 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
									 const ProviderProgressCallback		   &progressCallback) override ;

	/**
	 * @brief Capability外のdownload／install要求を拒否する。
	 * Registry capability外の直接呼出しでも混在EXEへ到達せず、根拠を失効する。
	 * @param[in] scanSessionId 拒否する要求のsession。 拒否する要求session。
	 * @param[in] identities 拒否する候補identity群。
	 * @param[in] parentWindowNative 使用しない親Window値。
	 * @param[in] progressCallback 呼び出さない通知先。
	 * @return Downloadとinstallの双方がE_NOTIMPLの結果。 DownloadとinstallをE_NOTIMPLに固定した結果。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					scanSessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parentWindowNative,
										const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 次scanまたは拒否されたinstall要求で旧sessionの取得根拠を破棄する。
	 */
	void						invalidateScanSession() noexcept ;

private:
	/// Workerが所有する公式metadataの取得根拠。
	OfficialHttpClient httpClient_ ;
} ;

} // namespace drivercrate
