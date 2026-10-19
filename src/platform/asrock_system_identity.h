//------------------------------------------------------------------------------
/**
 * @file asrock_system_identity.h
 * @brief ASRock公式一覧用local system識別定義。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Serial numberを読まず、SMBIOS表示名とWindows世代から固定ASRock一覧を選択します。Modelを含む端末情報をnetwork requestへ送信しません
 *       。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// ASRock local system識別値型定義。
//------------------------------------------------------------------------------

/**
 * @brief ASRock公式Latest Drivers Update一覧を照合する非機密要求である。
 */
struct AsrockCatalogRequest {
	/// SMBIOSから選択し公式一覧へ完全一致させるboard名。
	std::wstring boardModel ;
	/// ASRock page上のWindows x64 OS名。
	std::wstring osName ;
	/// 端末情報を含まない固定公式HTTPS URL。
	std::wstring pageUrl ;
} ;

/**
 * @brief SMBIOS表示値からASRock固定一覧要求を決定的に構築する。
 * SMBIOS表示値からASRock固定一覧要求を構築する。
 * Baseboard modelを優先し、固定URLへ端末情報を付加しない。
 * @param[in] systemManufacturer SMBIOS System Manufacturer表示値。 SMBIOS system maker表示値。
 * @param[in] systemProduct SMBIOS System Product Name表示値。 SMBIOS system product表示値。
 * @param[in] baseboardManufacturer SMBIOS BaseBoard Manufacturer表示値。 SMBIOS board maker表示値。
 * @param[in] baseboardProduct SMBIOS BaseBoard Product表示値。 SMBIOS board product表示値。
 * @param[in] windowsBuild CurrentBuildNumberを検証した値。 検証済みCurrentBuildNumber。
 * @param[in] windowsServer 実行中OSがWindows Serverの場合は`true`。
 * @param[out] request ASRock clientの場合のboard名、OS名、固定公式URL。 ASRock clientの場合の固定一覧要求。
 * @param[out] applicable ASRock clientとして安全に識別できた場合は`true`。 ASRock clientの場合は`true`。
 * @return 入力構造を判定できた場合は`true`、必須値が不正なら`false`。 判定成功時は`true`、ASRock必須値が不正なら`false`。
 */
[[nodiscard]] bool		  makeAsrockCatalogRequest( std::wstring_view systemManufacturer,
												   std::wstring_view systemProduct,
												   std::wstring_view baseboardManufacturer,
												   std::wstring_view baseboardProduct,
												   std::uint32_t windowsBuild, bool windowsServer,
												   AsrockCatalogRequest &request, bool &applicable) ;

/**
 * @brief Local registryからASRock固定一覧照合に必要な表示値だけを取得する。
 * Local registryからASRock固定一覧要求を取得する。
 * Serverを除外後、serialを含まない五つのregistry値だけを読み、純粋な要求構築処理へ渡す。
 * @param[out] request ASRock clientの場合のboard名、OS名、固定公式URL。 ASRock clientの場合のmodel、OS、固定URL。
 * @param[out] applicable ASRock clientとして安全に識別できた場合は`true`。 ASRock clientの場合は`true`。
 * @return 判定成功時は0、ASRock端末の必須値欠落またはWin32失敗時はHRESULT。 判定成功時は0、必須値またはWin32失敗時はHRESULT。
 * @note Windows Serverでは追加registry値を読まず対象外とする。
 */
[[nodiscard]] NativeError readLocalAsrockCatalogRequest( AsrockCatalogRequest &request,
														bool				 &applicable) ;

} // namespace drivercrate
