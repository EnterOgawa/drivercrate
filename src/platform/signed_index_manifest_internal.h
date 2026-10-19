//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest_internal.h
 * @brief 固定信頼公開鍵とnative fixtureだけに限定する内部注入境界を定義します。
 * @version 01.01.00
 * @date 2026/10/11
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  固定trustとRAM内native fixtureの境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * </pre>
 *
 * @note Envelopeや利用者入力をtrustへ登録しません。鍵生成・秘密鍵・永続化は含みません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_manifest.h"
#include <span>

namespace drivercrate::signed_index_detail {

/** @brief Binary固定のpublic keyまたはtest専用RAM materialを借用する内部値です。 */
struct TrustKey {
	/// 1～64byteの固定ASCII ID。Envelopeから鍵materialを作りません。
	std::string_view			  keyId ;
	/// CNG BCRYPT_RSAPUBLIC_BLOB。3072bit／exponent65537だけを認めます。
	std::span<const std::uint8_t> rsaPublicBlob ;
} ;

/** @brief Binary固定trustの配備有無だけを読みます。
 * @return 固定集合が非空の場合true。鍵materialは返しません。
 */
[[nodiscard]] bool						productTrustAvailable() noexcept ;

/**
 * @brief 最大8件の内部固定trustを用い、製品関数と同じ実CNG検証を行います。
 * @param[in] envelope 外側原byte。所有権は取得しません。
 * @param[in] nowUtc 確認済みUTC。時刻なしでは拒否します。
 * @param[in] highWater 保護store由来の最大世代。変更しません。
 * @param[in] trustedKeys 呼出し中有効なbinary固定集合またはnative testのRAM public key。
 * @return 成功時だけ認証receipt。鍵登録・asset検査・保存・networkの作用はありません。
 * @warning Network、設定、利用者入力をtrustedKeysへ投影してはいけません。
 */
[[nodiscard]] SignedIndexManifestResult authenticateWithTrustKeys(
	std::string_view envelope, std::optional<std::chrono::sys_seconds> nowUtc,
	const std::optional<IndexManifestHighWater> &highWater,
	std::span<const TrustKey>					 trustedKeys) noexcept ;

} // namespace drivercrate::signed_index_detail
