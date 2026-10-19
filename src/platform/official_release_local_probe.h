//------------------------------------------------------------------------------
/**
 * @file official_release_local_probe.h
 * @brief 公式release端末内fingerprint生成定義。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Worker内のnative device識別値を端末固有keyで不可逆化し、OSと対象device集合の失効判定用fingerprintを生成します。生識別値は保持しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_release_observation.h"
#include "core/update_types.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// Local probe値型定義。
//------------------------------------------------------------------------------

/**
 * @brief 現在OSと対象device集合から生成した端末内失効条件である。
 */
struct OfficialReleaseEnvironmentFingerprints {
	/// OS種別、build、x64を表すSHA-256。
	std::wstring operatingSystem ;
	/// 対象device binding集合を表すSHA-256。
	std::wstring deviceConfiguration ;
} ;

/**
 * @brief Native device識別値から端末内限定binding fingerprintを生成する。
 * Native device識別値から端末内bindingを生成する。
 * 用途labelと長さ付きUTF-16だけをHMACし、生IDを保持しない。
 * @param[in] secret 管理者保護stateから得た32 byteの端末固有key。 端末固有HMAC key。
 * @param[in] nativeDeviceIdentity Worker内だけで保持するdevice instance ID。 Worker内のnative device ID。
 * @param[out] fingerprint 成功時の64桁小文字HMAC-SHA-256。失敗時は空。 成功時の小文字HMAC-SHA-256。
 * @return 成功時は0、不正入力またはCNG失敗時はHRESULT bit pattern。
 * @note 入力識別値、secret、fingerprintをnetworkまたはlogへ渡してはならない。
 */
[[nodiscard]] NativeError makeLocalOfficialDeviceBindingFingerprint(
	const LocalOfficialBindingSecret &secret, std::wstring_view nativeDeviceIdentity,
	std::wstring &fingerprint) ;

/**
 * @brief 現在OSと端末内device binding集合の失効用fingerprintを生成する。
 * OSとdevice構成の端末内fingerprintを生成する。
 * OS値とsort済みdevice集合を用途別SHA-256へ変換する。
 * @param[in] windowsServer Windows Serverの場合はtrue、clientの場合はfalse。 Serverならtrue。
 * @param[in] windowsBuild RtlGetVersionで取得した0ではないmajor build番号。 0ではない実OS build。
 * @param[in] windowsProductSku GetProductInfoで取得した0ではないPRODUCT_*値。
 * @param[in] deviceBindings Local probeが生成した64桁小文字fingerprint集合。 端末内binding fingerprint集合。
 * @param[out] fingerprints 成功時のOSとdevice構成fingerprint。失敗時は空。 成功時のOSとdevice構成hash。
 * @return 成功時は0、不正入力、非x64 build、CNG失敗時はHRESULT bit pattern。 成功時は0、不正入力、非x64、CNG失敗時はHRESULT bit
 *         pattern。
 * @note Device集合は順序非依存であり、重複fingerprintは曖昧として拒否する。
 */
[[nodiscard]] NativeError makeLocalOfficialEnvironmentFingerprints(
	bool windowsServer, std::uint32_t windowsBuild, std::uint32_t windowsProductSku,
	std::span<const std::wstring>			deviceBindings,
	OfficialReleaseEnvironmentFingerprints &fingerprints) ;

} // namespace drivercrate
