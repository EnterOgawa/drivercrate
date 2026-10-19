//------------------------------------------------------------------------------
/**
 * @file official_release_local_probe_tests.cpp
 * @brief 公式release端末内fingerprint単体試験実装。
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
 * @note Network、実PnP情報、永続stateを使わず決定的な架空入力で検証します。
 */
//------------------------------------------------------------------------------

#include "official_release_local_probe_tests.h"

#include "platform/official_release_local_probe.h"
#include "test_framework.h"

#include <array>
#include <cstddef>
#include <string>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 端末内device bindingの決定性と用途分離を検証する。
 *
 * 同じkeyと架空device値だけが同じHMACを返し、keyまたは値の変更を別bindingとして扱うことを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDeviceBinding( TestContext &context)
{
	LocalOfficialBindingSecret firstSecret{} ;	// 一台目を表す架空HMAC key。
	LocalOfficialBindingSecret secondSecret{} ;	// 別端末を表す架空HMAC key。
	firstSecret.fill( std::byte{0x11}) ;
	secondSecret.fill( std::byte{0x22}) ;
	std::wstring first ;		// 最初のbinding結果。
	std::wstring repeated ;		// 同じ入力の再計算結果。
	std::wstring otherKey ;		// 別keyでの結果。
	std::wstring otherValue ;	// 別device値での結果。
	DRIVERCRATE_EXPECT( context, makeLocalOfficialDeviceBindingFingerprint(
									firstSecret, L"fictional-device-alpha", first) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialDeviceBindingFingerprint(
									firstSecret, L"fictional-device-alpha", repeated) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialDeviceBindingFingerprint(
									secondSecret, L"fictional-device-alpha", otherKey) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialDeviceBindingFingerprint(
									firstSecret, L"fictional-device-beta", otherValue) == 0) ;
	DRIVERCRATE_EXPECT( context, first.size() == 64U) ;
	DRIVERCRATE_EXPECT( context, first == repeated) ;
	DRIVERCRATE_EXPECT( context, first != otherKey) ;
	DRIVERCRATE_EXPECT( context, first != otherValue) ;

	LocalOfficialBindingSecret zeroSecret{} ;				// 未初期化として拒否するkey。
	std::wstring			   rejected = L"unchanged" ;	// 失敗時に空となる出力。
	DRIVERCRATE_EXPECT( context, makeLocalOfficialDeviceBindingFingerprint(
									zeroSecret, L"fictional-device-alpha", rejected) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OSとdevice構成fingerprintの決定性を検証する。
 *
 * Device順序を無視し、OS種別、build、集合変更を失効条件へ反映することを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testEnvironmentFingerprints( TestContext &context)
{
	const std::wstring					   firstBinding( 64U, L'a') ;				// 架空device AのHMAC。
	const std::wstring					   secondBinding( 64U, L'b') ;				// 架空device BのHMAC。
	const std::array					   ordered{firstBinding, secondBinding} ;	// 基準順序。
	const std::array					   reversed{secondBinding, firstBinding} ;	// 逆順。
	OfficialReleaseEnvironmentFingerprints baseline ;								// 基準環境hash。
	OfficialReleaseEnvironmentFingerprints reordered ;								// 逆順集合hash。
	OfficialReleaseEnvironmentFingerprints server ;									// Serverへ変更した環境hash。
	OfficialReleaseEnvironmentFingerprints build ;									// Build変更後の環境hash。
	OfficialReleaseEnvironmentFingerprints edition ;								// Edition変更後の環境hash。
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 48U,
																		 ordered, baseline) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 48U,
																		 reversed, reordered) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( true, 26'100U, 48U,
																		 ordered, server) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( false, 26'200U, 48U,
																		 ordered, build) == 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 49U,
																		 ordered, edition) == 0) ;
	DRIVERCRATE_EXPECT( context, baseline.operatingSystem.size() == 64U) ;
	DRIVERCRATE_EXPECT( context, baseline.deviceConfiguration.size() == 64U) ;
	DRIVERCRATE_EXPECT( context, baseline.deviceConfiguration == reordered.deviceConfiguration) ;
	DRIVERCRATE_EXPECT( context, baseline.operatingSystem == reordered.operatingSystem) ;
	DRIVERCRATE_EXPECT( context, baseline.operatingSystem != server.operatingSystem) ;
	DRIVERCRATE_EXPECT( context, baseline.operatingSystem != build.operatingSystem) ;
	DRIVERCRATE_EXPECT( context, baseline.operatingSystem != edition.operatingSystem) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 曖昧または不正な環境入力を拒否する。
 *
 * 空集合、build 0、重複、非canonical hashをfail-closedで拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidEnvironment( TestContext &context)
{
	OfficialReleaseEnvironmentFingerprints output ;		// 失敗時に空となる出力。
	const std::array<std::wstring, 0>	   empty{} ;	// 対象deviceなしの集合。
	DRIVERCRATE_EXPECT(
		context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 48U, empty, output) != 0) ;

	const std::wstring binding( 64U, L'a') ;			// 正常な架空fingerprint。
	const std::array   one{binding} ;					// 一件の正常集合。
	const std::array   duplicate{binding, binding} ;	// 曖昧な重複集合。
	DRIVERCRATE_EXPECT( context,
					   makeLocalOfficialEnvironmentFingerprints( false, 0U, 48U, one, output) != 0) ;
	DRIVERCRATE_EXPECT(
		context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 0U, one, output) != 0) ;
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 48U,
																		 duplicate, output) != 0) ;
	std::wstring uppercase = binding ;	// Canonicalでない大文字hash。
	uppercase[0]		   = L'A' ;
	const std::array invalid{uppercase} ;	// 不正fingerprint集合。
	DRIVERCRATE_EXPECT( context, makeLocalOfficialEnvironmentFingerprints( false, 26'100U, 48U,
																		 invalid, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.operatingSystem.empty()) ;
	DRIVERCRATE_EXPECT( context, output.deviceConfiguration.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_release_local_probe_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialReleaseLocalProbeTests( TestContext &context)
{
	testDeviceBinding( context) ;
	testEnvironmentFingerprints( context) ;
	testInvalidEnvironment( context) ;
}

} // namespace drivercrate::test
