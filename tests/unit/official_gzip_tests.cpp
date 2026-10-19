//------------------------------------------------------------------------------
/**
 * @file official_gzip_tests.cpp
 * @brief 公式GZip展開単体試験実装。
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
 * @note 架空の小さいGZip fixtureを使用し、実catalogやnetworkへ依存しません。
 */
//------------------------------------------------------------------------------

#include "official_gzip_tests.h"

#include "platform/official_gzip.h"
#include "test_framework.h"

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

constexpr std::array GZIP_FIXTURE{
	std::byte{0x1f}, std::byte{0x8b}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
	std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x0a},
	std::byte{0x73}, std::byte{0x29}, std::byte{0xca}, std::byte{0x2c}, std::byte{0x4b},
	std::byte{0x2d}, std::byte{0x72}, std::byte{0x2e}, std::byte{0x4a}, std::byte{0x2c},
	std::byte{0x49}, std::byte{0x55}, std::byte{0x70}, std::byte{0x8f}, std::byte{0xca},
	std::byte{0x2c}, std::byte{0x50}, std::byte{0x48}, std::byte{0xcb}, std::byte{0xac},
	std::byte{0x28}, std::byte{0x29}, std::byte{0x2d}, std::byte{0x4a}, std::byte{0x05},
	std::byte{0x00}, std::byte{0x6d}, std::byte{0xd5}, std::byte{0xa0}, std::byte{0x1f},
	std::byte{0x18}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}} ;	// Valid GZip fixture。
constexpr std::string_view EXPECTED_TEXT = "DriverCrate GZip fixture" ;		// 展開期待値。

//------------------------------------------------------------------------------
/**
 * @brief Valid GZipを展開できることを検証する。
 *
 * Header、Deflate、CRC32、ISIZEが正しいfixtureを比較する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void					   testValidGzip( TestContext &context)
{
	std::vector<std::byte> expanded ;	// 展開APIが設定するbyte列。
	DRIVERCRATE_EXPECT( context, decompressOfficialGzip( GZIP_FIXTURE, 1024, expanded) == 0) ;
	const std::span expectedBytes =
		// Text期待byte列。
		std::as_bytes( std::span( EXPECTED_TEXT.data(), EXPECTED_TEXT.size())) ;
	DRIVERCRATE_EXPECT( context, std::equal( expanded.begin(), expanded.end(), expectedBytes.begin(),
										   expectedBytes.end())) ;
}

//------------------------------------------------------------------------------
/**
 * @brief GZip CRCと展開上限違反を拒否することを検証する。
 *
 * 改ざんtrailer、ISIZE超過、concatenated memberを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidGzip( TestContext &context)
{
	std::vector<std::byte> corrupted( GZIP_FIXTURE.begin(), GZIP_FIXTURE.end()) ;	// 改ざんfixture。
	corrupted[corrupted.size() - 8] ^= std::byte{1} ;
	std::vector<std::byte> expanded ;	// 失敗時に空であることを確認する出力。
	DRIVERCRATE_EXPECT( context, decompressOfficialGzip( corrupted, 1024, expanded) != 0) ;
	DRIVERCRATE_EXPECT( context, expanded.empty()) ;
	DRIVERCRATE_EXPECT( context, decompressOfficialGzip( GZIP_FIXTURE, 8, expanded) != 0) ;

	std::vector<std::byte> concatenated( GZIP_FIXTURE.begin(), GZIP_FIXTURE.end()) ;	// 二member入力。
	concatenated.insert( concatenated.end(), GZIP_FIXTURE.begin(), GZIP_FIXTURE.end()) ;
	DRIVERCRATE_EXPECT( context, decompressOfficialGzip( concatenated, 1024, expanded) != 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_gzip_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialGzipTests( TestContext &context)
{
	testValidGzip( context) ;
	testInvalidGzip( context) ;
}

} // namespace drivercrate::test
