//------------------------------------------------------------------------------
/**
 * @file openpgp_signature_verifier.h
 * @brief 固定OpenPGP detached signature検証定義。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Providerへ組み込んだRSA公開鍵とfingerprintだけを信頼し、binary documentのOpenPGP v4 RSA/SHA-256 detached
 *       signatureをprocess内で検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace drivercrate {

/**
 * @brief Providerへ固定するOpenPGP v4 RSA公開鍵の検証情報である。
 */
struct OpenPgpRsaPublicKey {
	/// Public-Key packet bodyだけのBase64。
	std::string_view  packetBodyBase64 ;
	/// 許可する40桁SHA-1 fingerprint。
	std::wstring_view expectedFingerprint ;
} ;

/**
 * @brief Memory上のbinary documentとASCII-armored detached signatureを検証する。
 * Binary documentのOpenPGP detached signatureを検証する。
 * OpenPGP v4 binary RSA/SHA-256一packetだけをprocess内でfail-closed検証する。
 * @param[in] document 署名対象のbinary byte列。有効期間は本呼出し中に限る。 署名対象binary byte列。
 * @param[in] armoredSignature OpenPGP ASCII Armor全体。 Detached signature ASCII Armor。
 * @param[in] publicKey Providerへ固定した公開鍵bodyとfingerprint。 固定公開鍵bodyとfingerprint。
 * @return RSA/SHA-256署名とfingerprintが一致した場合は0、その他はHRESULT bit pattern。 鍵、issuer、digest、RSA署名が一致した場合は
 *         0。
 * @note OpenPGP v4、binary document、RSA、SHA-256、単一packetだけを受理する。
 */
[[nodiscard]] NativeError verifyOpenpgpDetachedSignature( std::span<const std::byte> document,
														 std::string_view armoredSignature,
														 const OpenPgpRsaPublicKey &publicKey) ;

/**
 * @brief Local documentとdetached signature fileを上限付きで読み取り検証する。
 * Local fileのOpenPGP detached signatureを上限付き検証する。
 * Reparse pointを拒否して両fileを読み、networkやkeyringを参照せずmemory検証へ委譲する。
 * @param[in] documentPath 署名対象binary fileのlocal絶対path。 署名対象binary file path。
 * @param[in] maximumDocumentBytes Document読取りの最大byte数。 Document読取り上限byte数。
 * @param[in] signaturePath ASCII-armored detached signatureのlocal絶対path。 Detached signature file
 *                   path。
 * @param[in] maximumSignatureBytes Signature file読取りの最大byte数。 Signature読取り上限byte数。
 * @param[in] publicKey Providerへ固定した公開鍵bodyとfingerprint。 固定公開鍵bodyとfingerprint。
 * @return 署名検証成功時は0、file、形式、鍵、署名の失敗時はHRESULT bit pattern。 File読取りと署名検証成功時は0、失敗時はHRESULT。
 */
[[nodiscard]] NativeError verifyOpenpgpDetachedFile( std::wstring_view documentPath,
													std::uint64_t	  maximumDocumentBytes,
													std::wstring_view signaturePath,
													std::uint64_t	  maximumSignatureBytes,
													const OpenPgpRsaPublicKey &publicKey) ;

} // namespace drivercrate
