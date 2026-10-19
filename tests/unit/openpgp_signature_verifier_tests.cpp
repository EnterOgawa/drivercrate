//------------------------------------------------------------------------------
/**
 * @file openpgp_signature_verifier_tests.cpp
 * @brief OpenPGP detached signature単体試験実装。
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
 * @note Test専用RSA 2048-bit鍵で生成したASCII Armorだけを使用し、keyring、network、実Dell鍵へ依存しません。
 */
//------------------------------------------------------------------------------

#include "openpgp_signature_verifier_tests.h"

#include "platform/openpgp_signature_verifier.h"
#include "test_framework.h"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate::test {
namespace {

constexpr std::string_view	PAYLOAD = "DriverCrate OpenPGP fixture\n" ;	// 署名対象fixture。
constexpr std::wstring_view FINGERPRINT =
	L"CD39BADE14D6D7589C23E0FB492047D1C69CFF31" ;	// Test公開鍵fingerprint。
constexpr std::string_view PUBLIC_KEY_BODY_BASE64 =
	"BGqX27MBCADdvuKaYFW4yOzKHlUbi3GDtYBK/z2s9tMB7/vZ+EuizE/+NlP1Lz0GpaY2hTQiNCOe4b4fUwPqVhqp"
	"gylG21WYfkRUQE3P7TwzoFfGOeFdcHwUIOxlh/7WZUbYfK/kvc0U45uS6rHeegEsz26PmWb4zQpDYtH758xbk6Vgk"
	"b05IznCce3g4Hm83q6swN2gfxCKjOiD4w/Q14BGcsLKfa+GwxH7fYzimsu3/f67sl06F+bibsf8bX3NHp5wgJJA6p"
	"hh3FpTQHT6HSRPU0Nm4i0lGyOibzlJIzZaP90ahVeOT3eCAlWfZ1n59Mcrc1PbFj+uFu0chLIhfvN0scN6uGmHABE"
	"BAAE=" ;	// Public-Key packet body Base64。
constexpr std::string_view VALID_SIGNATURE = R"(-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEzTm63hTW11icI+D7SSBH0cac/zEFAmqX3WwACgkQSSBH0cac
/zFZPAgAkLgQapT0jA8BmAp1C3MYGZl8Bk2IbSiYLwHS4NN+Uge82F5IwnvwSM9v
aIpnUu5LmBQlxAj4rVSmUH1eT2Ga91hCV+VoeR7sSbfuOWKeqXRWKd25NxhftsMB
d8w9awqzxWx7Zob0UlvuizcuLfkqALRXWV7rVvLXnxVSTAarrZBUwKlxk1qVOr9V
V5N0Wn8tLdizCm6WG48jT/KNdxDWuAsD+FAoDl25pgrN4Ycap+Dtn+7r9TLRhhIK
QU/spiupwk74Ojt7YlaZMGlwbxX48dCvoZL7M1tBDMMvo0sFp/FGf6DCgWt+RoeG
8DX8VRUrS+wLmPvp11JrokOc9EeoFg==
=oNZU
-----END PGP SIGNATURE-----
)" ;	// RSA/SHA-256 detached signature fixture。
constexpr std::string_view UNSUPPORTED_SIGNATURE = R"(-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEzTm63hTW11icI+D7SSBH0cac/zEFAmqX2+cACgkQSSBH0cac
/zEJJwf8CfBy6M81OxZsb3TKTzUci7oFmdXDep9NjKcl4bxKpmOb0pVrqtH+7/bV
fZSAcg6g0mX/3lmrpRy9zQ2az+Obas0YZex2yNlGMTRaufBXShD4WMv0c+KHJ3kS
+PaxixqOcSy7iL7oXlKBP4LRu/Ld7uwfruTa8lFKrjw8qRMy0s1uS+lF61lyS2m/
G84S7TgrMyQ5LNODngC1CJQc5TGusanNGXPsKYcq7B+oEeA49yqB7PmEp/vQ2iFp
924NM7LwYfksx2tkLEEHYYpXRkLmuufPECWtOaJVejs2TIgsH5MY1aUpnSaOw1US
n/nUAGbb8yEtUYG43BvTeY1IJDvGlA==
=KTGL
-----END PGP SIGNATURE-----
)" ;	// 同じ鍵で生成した未対応SHA-512 signature fixture。

//------------------------------------------------------------------------------
/**
 * @brief Valid RSA/SHA-256 detached signatureを検証する。
 *
 * 固定fingerprintと公開鍵bodyだけで署名が成立することを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidSignature( TestContext &context)
{
	const std::span payloadBytes =
		// Binary document view。
		std::as_bytes( std::span( PAYLOAD.data(), PAYLOAD.size())) ;
	const OpenPgpRsaPublicKey key{.packetBodyBase64	   = PUBLIC_KEY_BODY_BASE64,
								  .expectedFingerprint = FINGERPRINT} ;	// Test固定鍵。
	DRIVERCRATE_EXPECT( context,
					   verifyOpenpgpDetachedSignature( payloadBytes, VALID_SIGNATURE, key) == 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Document、Armor、fingerprint改ざんを拒否することを検証する。
 *
 * Signatureだけでなくissuer fingerprintとArmor CRCも検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testTampering( TestContext &context)
{
	std::string modifiedPayload( PAYLOAD) ;	// 一byte改ざんするdocument copy。
	modifiedPayload[0] = 'd' ;
	const std::span modifiedBytes =
		// Byte view。
		std::as_bytes( std::span( modifiedPayload.data(), modifiedPayload.size())) ;
	const OpenPgpRsaPublicKey key{.packetBodyBase64	   = PUBLIC_KEY_BODY_BASE64,
								  .expectedFingerprint = FINGERPRINT} ;	// 正しい固定鍵。
	DRIVERCRATE_EXPECT( context,
					   verifyOpenpgpDetachedSignature( modifiedBytes, VALID_SIGNATURE, key) != 0) ;

	const std::span payloadBytes =
		// 正しいdocument view。
		std::as_bytes( std::span( PAYLOAD.data(), PAYLOAD.size())) ;
	std::string malformed( VALID_SIGNATURE) ;	// END後へ追加textを入れるArmor copy。
	malformed.append( "extra") ;
	DRIVERCRATE_EXPECT( context, verifyOpenpgpDetachedSignature( payloadBytes, malformed, key) != 0) ;

	const OpenPgpRsaPublicKey wrongKey{
		.packetBodyBase64	 = PUBLIC_KEY_BODY_BASE64,
		.expectedFingerprint = L"AD39BADE14D6D7589C23E0FB492047D1C69CFF31"} ;	// 未知fingerprint。
	DRIVERCRATE_EXPECT(
		context, verifyOpenpgpDetachedSignature( payloadBytes, VALID_SIGNATURE, wrongKey) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未対応OpenPGP digest algorithmを拒否することを検証する。
 *
 * Valid RSA/SHA-512 signatureでもfilename等から推測せず拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnsupportedAlgorithm( TestContext &context)
{
	const std::span payloadBytes =
		// Binary document view。
		std::as_bytes( std::span( PAYLOAD.data(), PAYLOAD.size())) ;
	const OpenPgpRsaPublicKey key{.packetBodyBase64	   = PUBLIC_KEY_BODY_BASE64,
								  .expectedFingerprint = FINGERPRINT} ;	// Test固定鍵。
	DRIVERCRATE_EXPECT(
		context, verifyOpenpgpDetachedSignature( payloadBytes, UNSUPPORTED_SIGNATURE, key) != 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/openpgp_signature_verifier_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOpenpgpSignatureVerifierTests( TestContext &context)
{
	testValidSignature( context) ;
	testTampering( context) ;
	testUnsupportedAlgorithm( context) ;
}

} // namespace drivercrate::test
