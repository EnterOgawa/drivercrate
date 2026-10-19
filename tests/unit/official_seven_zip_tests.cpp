//------------------------------------------------------------------------------
/**
 * @file official_seven_zip_tests.cpp
 * @brief 公式7z有限展開単体試験実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  有限decoderの拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Workspace選択展開とcleanup試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Solid選択展開量の判定試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 7-Zip 26.01で合成した非driver fixtureをBase64として保持します。Solid展開量判定はpacked dataを展開せず、過大時のfile非作成を確認しま
 *       す。
 */
//------------------------------------------------------------------------------

#include "official_seven_zip_tests.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_seven_zip.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr OfficialSevenZipExtractionPolicy POLICY{
	4096U,		   3U * 1024U * 1024U, 4U * 1024U * 1024U, 3U * 1024U * 1024U,
	1024U * 1024U, 8U * 1024U * 1024U, 4U * 1024U * 1024U, 32U,
	160U} ;	// 全fixtureを開けるが1 MiB超のdictionaryを拒否する基準policy。

// 基本展開と内容照合に使う架空7z archiveの固定Base64表現。
constexpr std::string_view VALID_ARCHIVE_BASE64 =
	"N3q8ryccAAQzkuQZPwEAAAAAAAAiAAAAAAAAALSbZKTgAMkAq10ALZWJDTchDFgmEhZPzCndWUE3"
	"9A7wLDyk4qmZx4FxqBjALk6Vi1gA5veUlw8b4M3YmmAxRXk7qNzdlxFe/3nDhpqyPP4mUf0trRJr"
	"mnsxLnYGNM3YWK6giPzWCPYHlLTQLVQW4dhjXhj1/vwIlDYn0WlmXIbhAp6dpDSfIe6oAEDk3W2/"
	"6Q2L1MD1B5dAp2aBC01pJ5R5ZxImxW0DiCwcgo+ji/GFhiIiVzKAAAEAI0RyaXZlckNyYXRlIHN5"
	"bnRoZXRpYyB0ZXN0IHBheWxvYWQuCgAAAIEzB64xntxrp1UK3xquA6VDaEbrHTqC/sYdztZqMXIJ"
	"e99Zr1ywZt1LRGPmBTdT12lqJGFyQOVKEKaiJ7+RcLaVGXVPDMEukfXKHHXu/iYrgqUpG07qk3NL"
	"HDjahF4xmfgAFwaA2wEJZAAHCwEAASMDAQEFXQAQAAAMgI4KAeubzhgAAA==" ;

// 暗号化archiveを拒否する境界試験用の固定入力。
constexpr std::string_view ENCRYPTED_ARCHIVE_BASE64 =
	"N3q8ryccAATQXa6cQAEAAAAAAAAwAAAAAAAAABwfdWGxcr+1DjKZzp6fFO7am1A5PN9a58fpK2pI3"
	"tjaJZYSJker6DBGJRk1fUAzNPZm6/CMB50EKD3NSDhM+ZUoGXgHr52BsfO3N7tUhhuVdUnto8fLk8"
	"Hi7stpBaHy1CV3foSWzDaJUH8MS9ygQZgs4Qs17oaiX8fwkUVCmco+M07kJSnQot9gyS62z6SVnA"
	"Rp6SjRYRscViaqYcnd662H1aKCb0CsfftmAMzAzrzKy0eTQYfs9HnRRegQ+UeNzdeG7V6mndv0Tj"
	"Cv1R3b5J92fiJLwiutbNPk8GvypxbqBdB2M/lwgfRcN7WSLRRxD09KPTH1OcKThCD9ikdboJOaHu"
	"S7XjG5/k10dIKC4Mly1P/5uV63fRe2Jy2GN+/0tzRqWtfDeD3x1HkqLPTgFzidzlikrS9kiyTTWH"
	"0vEcuMAworIxcGgMABCYCAAAcLAQABJAbxBwESUw9An4K9Ea/oS/OTN9cNJVndDHIKAWzYZOUAAA==" ;

// 未対応codecを暗黙に受理しないことを確認する固定入力。
constexpr std::string_view UNKNOWN_CODEC_ARCHIVE_BASE64 =
	"N3q8ryccAARJzIzblQAAAAAAAABiAAAAAAAAAJ7Uo8kAWvnILefDyJb2EbVjtr6Rr2dcgX9mFKTC"
	"P/CNudBwTgLN7WM/Bnt9DGFInDDvCHjWmW79Gb/hem0u/2cTgl4YFDD+8CtXhPeS3IoyFsWsNyCH"
	"UnGxClfHSdw+JQ1J2dLnlnBHS+QQKVROSegQ0mJP4kJWUGsmsz7dtNMSuIqCbqArLj+0vfaGuGfJ"
	"zvYmwIWDeKnAAAEEBgABCYCVAAcLAQABIwMEAQUEAAABAAyAygAICgGqvah/AAAFARkEAAAAABEXAG"
	"QAcgBpAHYAZQByAC4AaQBuAGYAAAAZBAAAAAAUCgEAqlTNoOw93QEVBgEAIAAAAAAA" ;

// 危険なentry pathを展開前に拒否する境界試験用の固定入力。
constexpr std::string_view UNSAFE_PATH_ARCHIVE_BASE64 =
	"N3q8ryccAATnP0HVSgEAAAAAAAAiAAAAAAAAAL0a2L7gAMkAq10ALZWJDTchDFgmEhZPzCndWUE3"
	"9A7wLDyk4qmZx4FxqBjALk6Vi1gA5veUlw8b4M3YmmAxRXk7qNzdlxFe/3nDhpqyPP4mUf0trRJr"
	"mnsxLnYGNM3YWK6giPzWCPYHlLTQLVQW4dhjXhj1/vwIlDYn0WlmXIbhAp6dpDSfIe6oAEDk3W2/"
	"6Q2L1MD1B5dAp2aBC01pJ5R5ZxImxW0DiCwcgo+ji/GFhiIiVzKAAAEAI0RyaXZlckNyYXRlIHN5"
	"bnRoZXRpYyB0ZXN0IHBheWxvYWQuCgAAAIEzB64xntxrp1UK3xquA6VDaEbrHTqC/sYdztZqMXIJ"
	"e99Zr1ywZt1LRGPmB/gg3Epy7ZzMJZXBGH+vG6mGQBnR4+mYisR029tosmEe60Bgi+Tu+Av9vGl1"
	"fsNJbRynrr37Ir1cNsew5MKAAGAXBoDbAQlvAAcLAQABIwMBAQVdABAAAAyAlgoBXMnn1wAA" ;

// 同名entryの重複を拒否する境界試験用の固定入力。
constexpr std::string_view DUPLICATE_ARCHIVE_BASE64 =
	"N3q8ryccAAQ4sPrmSQEAAAAAAAAiAAAAAAAAAN/WM4bgAMkAq10ALZWJDTchDFgmEhZPzCndWUE3"
	"9A7wLDyk4qmZx4FxqBjALk6Vi1gA5veUlw8b4M3YmmAxRXk7qNzdlxFe/3nDhpqyPP4mUf0trRJr"
	"mnsxLnYGNM3YWK6giPzWCPYHlLTQLVQW4dhjXhj1/vwIlDYn0WlmXIbhAp6dpDSfIe6oAEDk3W2/"
	"6Q2L1MD1B5dAp2aBC01pJ5R5ZxImxW0DiCwcgo+ji/GFhiIiVzKAAAEAI0RyaXZlckNyYXRlIHN5"
	"bnRoZXRpYyB0ZXN0IHBheWxvYWQuCgAAAIEzB64xntxrp1UK3xquA6VDaEbrHTqC/sYdztZqMXIJ"
	"e99Zr1ywZt1LRGPmBTdT12lqJGFyQOVKEKaiJ7+RcLvrNja32W315pup6julIhG5rYWdq9CyGxk8"
	"KjK3GcCRCMcnMWW25JLi5Y1UABcGgNsBCW4ABwsBAAEjAwEBBV0AEAAADICOCgGnppxIAAA=" ;

// decoder辞書のmemory上限を検証する固定archive入力。
constexpr std::string_view LARGE_DICTIONARY_ARCHIVE_BASE64 =
	"N3q8ryccAARuqTyFfgEAAAAAAABaAAAAAAAAABDAvGP/95oBa10AAG/9//+jt/9HPkgVcjlhUbiS"
	"KOajhgf57uQegtMvxTo8AUuxfsmKik0vow3Zf6bjjCMRU+BZGMV1iuJ3+LaUfwxqwN50SWTi6VxT"
	"sgTY90QMq18NbUbp5cN2iLeWV6y2TeFpHW/7S4gQbELLiD9cAI/QTq8mKJRxHz2PJOFwnqcjX+woy"
	"4XRlZiKfiqR8id19xnABphNmP3Yr9WQD8QlU/j1kTYxBaWw7m/BcE1HDNGREaqtYB26zrEnGFxZh"
	"ulmUli+6XasWeTlWwUI+cfarfz7Uit0zR5bIEL53VM9+ClkCTuAyyps37U78MS9Ll+qDz5LZkKQEw"
	"7/EJP4cXhZ+AvN/5UoRg+p/Hze+5owLlbAj4Xzg4HAZcQlU/j1kTYxBaWw7m/BcE1HDNGREaqtYB"
	"26zrEnGFxZhulmUli+6XasWeTlWwUI+cfarfz7Uit0zR5bIEL53VM9+ClkCTuAyyps37U78MS5K+q"
	"XgAhkAAUAvdcUYQAAAQQGAAEJgX4ABwsBAAEhIQESDOAAACAACAoBfoeJjQAABQEZCAAAAAAAAAAA"
	"ERUAbABhAHIAZwBlAC4AYgBpAG4AAAAUCgEA5v2Ku+w93QEVBgEAIAAAAAAA" ;

// Solid archiveの有限展開を検証する固定入力。
constexpr std::string_view SOLID_ARCHIVE_BASE64 =
	"N3q8ryccAARaq35TIQEAAAAAAAAhAAAAAAAAAHJYGaPgAO0AtF0ALZWJDTchDFgmEhZPzCndWUE3"
	"9A7wLDyk4qmZx4FxqBjALk6Vi1gA5veUlw8b4M3YmmAxRXk7qNzdlxFe/3nDhpqyPP4mUf0trRJr"
	"mnsxLnYGNM3YWK6giPzWCPYHlLTQLVQW4dhjXhj1/vwIlDYn0WlmXIbhAp6dpDSfIe6oAEDk3W2/"
	"6Q2L1MD1B5dAp2aBC01pJ5R5ZxImxW0DiCwcgo+ji/GFhiJeGOlpyu4yoVAEH/4uAAAAgTMHrg/V"
	"MPvQFyTT/rNwGIFAHj7mswbwKmIO9CmsPiYv1clSC3ZTnlwD7GWzub5DPDwDiWaiRoLZ/f1clxzjx"
	"+cTCmq/Uv5WmlLoIZ+dLsvL/sU2lQc0u2Otf4+DUyVuOZiGFwaAvAEJZQAHCwEAASMDAQEFXQAQAA"
	"AMfgoBiYAApQAA" ;

// Directory entryと配下fileの関係を検証する固定入力。
constexpr std::string_view DIRECTORY_ARCHIVE_BASE64 =
	"N3q8ryccAATPn96zIQEAAAAAAAAiAAAAAAAAAFmjJVjgAMkAq10ALZWJDTchDFgmEhZPzCndWUE3"
	"9A7wLDyk4qmZx4FxqBjALk6Vi1gA5veUlw8b4M3YmmAxRXk7qNzdlxFe/3nDhpqyPP4mUf0trRJr"
	"mnsxLnYGNM3YWK6giPzWCPYHlLTQLVQW4dhjXhj1/vwIlDYn0WlmXIbhAp6dpDSfIe6oAEDk3W2/"
	"6Q2L1MD1B5dAp2aBC01pJ5R5ZxImxW0DiCwcgo+ji/GFhiIiVzKAAAAAgTMHrg/VMMjB1yTT/rNw"
	"GIFAHj5JWvrmAeue6phJLpQNAB8qtrbh4miw6M3nlMw6QWHDV1UxUOChO50WF6M7SWBFnnVRjzyS"
	"Cqzkpy9IcBtiHdV9S51ba99xWmCZR/twXvDH9Zij3IQaMT8AFwaAswEJbgAHCwEAASMDAQEFXQAQ"
	"AAAMgIYKARrJg60AAA==" ;

// 架空archiveから展開したINFとbyte単位で照合する固定期待内容。
constexpr std::string_view EXPECTED_INF = "[Version]\n"
										  "Signature=\"$WINDOWS NT$\"\n"
										  "Class=System\n"
										  "\n"
										  "[Manufacturer]\n"
										  "DriverCrate=Models,NTamd64\n"
										  "\n"
										  "[Models.NTamd64]\n"
										  "%Device%=Install,ROOT\\DRIVERCRATE_TEST\n"
										  "\n"
										  "[Strings]\n"
										  "Device=\"DriverCrate synthetic test device\"\n" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Base64文字を6-bit値へ変換する。
 *
 * 合成fixtureをtest memoryへ復元する厳密decoderで使用する。
 *
 * @param[in] character 空白を含まないBase64の一文字。
 * @return 有効文字は0～63、無効文字は-1。
 */
//------------------------------------------------------------------------------
[[nodiscard]] int		   base64Value( const char character) noexcept
{
	// base64の大文字領域を先頭26個の値へ対応付ける。
	if( character >= 'A' && character <= 'Z') {
		return character - 'A' ;
	}

	// base64の小文字領域を大文字領域に続く26個の値へ対応付ける。
	if( character >= 'a' && character <= 'z') {
		return character - 'a' + 26 ;
	}

	// base64の数字領域を英字領域に続く10個の値へ対応付ける。
	if( character >= '0' && character <= '9') {
		return character - '0' + 52 ;
	}

	// base64の加算記号を予約された62番の値へ対応付ける。
	if( character == '+') {
		return 62 ;
	}

	return character == '/' ? 63 : -1 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Base64 fixtureをbyte列へ復元する。
 *
 * Test source内の固定fixture以外を受け取らず、失敗時は空にする。
 *
 * @param[in] input 空白を含まない4文字単位のBase64。
 * @param[out] output 成功時のarchive byte列。
 * @return 構文とpaddingが正しい場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeFixture( const std::string_view input, std::vector<std::byte> &output)
{
	output.clear() ;
	// 空または4文字単位でないbase64 fixtureをdecodeしない。
	if( input.empty() || input.size() % 4U != 0U) {
		return false ;
	}

	output.reserve( input.size() / 4U * 3U) ;
	// Base64四文字を最大三byteへ変換し、paddingは最終groupだけで受理する。
	for( std::size_t index = 0U; index < input.size(); index += 4U) {
		const bool finalGroup	 = index + 4U == input.size() ;								// 最終group判定。
		const bool thirdPadding	 = input[index + 2U] == '=' ;								// 出力一byteのpadding。
		const bool fourthPadding = input[index + 3U] == '=' ;								// 出力二byte以下のpadding。
		const int  first		 = base64Value( input[index]) ;								// 上位6-bit値。
		const int  second		 = base64Value( input[index + 1U]) ;						// 次の6-bit値。
		const int  third		 = thirdPadding ? 0 : base64Value( input[index + 2U]) ;		// 第三値。
		const int  fourth		 = fourthPadding ? 0 : base64Value( input[index + 3U]) ;	// 第四値。
		// 不正文字と終端以外のpaddingを拒否し、部分decode結果を残さない。
		if( first < 0 || second < 0 || third < 0 || fourth < 0 || (thirdPadding && !fourthPadding) ||
		   ((thirdPadding || fourthPadding) && !finalGroup)) {
			output.clear() ;
			return false ;
		}

		const std::uint32_t combined = (static_cast<std::uint32_t>( first) << 18U) |
									   (static_cast<std::uint32_t>( second) << 12U) |
									   (static_cast<std::uint32_t>( third) << 6U) |
									   // 今groupの24-bit値。
									   static_cast<std::uint32_t>( fourth) ;
		output.push_back( static_cast<std::byte>( (combined >> 16U) & 0xffU)) ;
		// 三文字目がpaddingでないgroupからだけ二byte目を復元する。
		if( !thirdPadding) {
			output.push_back( static_cast<std::byte>( (combined >> 8U) & 0xffU)) ;
		}

		// 四文字目がpaddingでないgroupからだけ三byte目を復元する。
		if( !fourthPadding) {
			output.push_back( static_cast<std::byte>( combined & 0xffU)) ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正常archiveの列挙と一件展開を検証する。
 *
 * 非solid LZMA2の二fileを列挙し、INF内容をmemoryだけへ展開する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidInspectionAndExtraction( TestContext &context)
{
	std::vector<std::byte> archive ;	// Base64から復元する正常7z fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( VALID_ARCHIVE_BASE64, archive)) ;
	std::vector<OfficialSevenZipEntry> entries ;	// Decoderが公開する通常file一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, POLICY, entries) == 0) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 2U) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( entries.size() != 2U) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, entries[0].relativePath == L"driver.inf") ;
	DRIVERCRATE_EXPECT( context, entries[0].uncompressedSize == EXPECTED_INF.size()) ;
	DRIVERCRATE_EXPECT( context, entries[1].relativePath == L"driver.sys") ;

	std::vector<std::byte> content ;	// 選択INFのCRC検証済みmemory内容。
	DRIVERCRATE_EXPECT( context, extractOfficialSevenZipFile( archive, POLICY,
															entries[0].archiveIndex, content) == 0) ;
	// 展開内容のbyte比較へ渡す、固定期待INFの文字範囲。
	const std::span<const char>		 expectedCharacters{EXPECTED_INF.data(), EXPECTED_INF.size()} ;
	const std::span<const std::byte> expected = std::as_bytes( expectedCharacters) ;	// 期待byte列。
	DRIVERCRATE_EXPECT( context, std::ranges::equal( content, expected)) ;

	std::vector<std::byte> missingContent{std::byte{0x01}} ;	// 失敗時clear確認用出力。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialSevenZipFile( archive, POLICY, 100U, missingContent) != 0) ;
	DRIVERCRATE_EXPECT( context, missingContent.empty()) ;

	std::vector<std::byte> corrupted = archive ;	// Packed payloadだけを改ざんするfixture。
	corrupted[40] ^= std::byte{0x01} ;
	std::vector<OfficialSevenZipEntry> corruptedEntries ;	// Metadataだけは読める一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( corrupted, POLICY, corruptedEntries) == 0) ;
	std::vector<std::byte> corruptedContent{std::byte{0x01}} ;	// CRC失敗時clear確認用出力。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialSevenZipFile( corrupted, POLICY, entries[0].archiveIndex,
												   corruptedContent) != 0) ;
	DRIVERCRATE_EXPECT( context, corruptedContent.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 暗号化と未知codecの拒否を検証する。
 *
 * Password付きheaderとPPMd payloadを候補一覧へ公開しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testEncryptionAndCodecRejection( TestContext &context)
{
	std::vector<std::byte> encrypted ;	// 暗号化headerを持つ合成fixture。
	std::vector<std::byte> unknown ;	// PPMd coderを持つ合成fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( ENCRYPTED_ARCHIVE_BASE64, encrypted)) ;
	DRIVERCRATE_EXPECT( context, decodeFixture( UNKNOWN_CODEC_ARCHIVE_BASE64, unknown)) ;
	std::vector<OfficialSevenZipEntry> entries ;	// 失敗時に空であるべき公開一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( encrypted, POLICY, entries) != 0) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( unknown, POLICY, entries) != 0) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 危険pathと重複名の拒否を検証する。
 *
 * `..` componentとASCII大小文字だけが異なる同名fileを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testPathAndDuplicateRejection( TestContext &context)
{
	std::vector<std::byte> unsafePath ;	// `..\\escape.inf`を持つ合成fixture。
	std::vector<std::byte> duplicate ;	// Windows上で同名となる二file fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( UNSAFE_PATH_ARCHIVE_BASE64, unsafePath)) ;
	DRIVERCRATE_EXPECT( context, decodeFixture( DUPLICATE_ARCHIVE_BASE64, duplicate)) ;
	std::vector<OfficialSevenZipEntry> entries ;	// 失敗時に空であるべき公開一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( unsafePath, POLICY, entries) != 0) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( duplicate, POLICY, entries) != 0) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief File、合計、entry上限の拒否を検証する。
 *
 * 正常archiveを異なる有限policyで検査し、上限超過を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testEntryAndSizeRejection( TestContext &context)
{
	std::vector<std::byte> archive ;	// 上限変更に使用する正常7z fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( VALID_ARCHIVE_BASE64, archive)) ;
	std::vector<OfficialSevenZipEntry> entries ;	// 失敗時に空であるべき公開一覧。

	OfficialSevenZipExtractionPolicy   filePolicy = POLICY ;	// 一file上限を縮小するpolicy。
	filePolicy.maximumSingleFileBytes			  = 128U ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, filePolicy, entries) != 0) ;

	OfficialSevenZipExtractionPolicy totalPolicy = POLICY ;	// 合計上限を縮小するpolicy。
	totalPolicy.maximumSingleFileBytes			 = 220U ;
	totalPolicy.maximumTotalExpandedBytes		 = 220U ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, totalPolicy, entries) != 0) ;

	OfficialSevenZipExtractionPolicy entryPolicy = POLICY ;	// Entry数上限を縮小するpolicy。
	entryPolicy.maximumEntryCount				 = 1U ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, entryPolicy, entries) != 0) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dictionaryとsolid block上限の拒否を検証する。
 *
 * 2 MiB級LZMA2辞書と238-byte solid folderを個別上限で拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDictionaryAndSolidRejection( TestContext &context)
{
	std::vector<std::byte> largeDictionary ;	// 2 MiB級dictionaryを持つfixture。
	std::vector<std::byte> solid ;				// 二fileを一folderに持つfixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( LARGE_DICTIONARY_ARCHIVE_BASE64, largeDictionary)) ;
	DRIVERCRATE_EXPECT( context, decodeFixture( SOLID_ARCHIVE_BASE64, solid)) ;
	std::vector<OfficialSevenZipEntry> entries ;	// 失敗時に空であるべき公開一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( largeDictionary, POLICY, entries) != 0) ;

	OfficialSevenZipExtractionPolicy solidPolicy = POLICY ;	// 238-byte folder用の狭いpolicy。
	solidPolicy.maximumSingleFileBytes			 = 220U ;
	solidPolicy.maximumSolidBlockBytes			 = 220U ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( solid, solidPolicy, entries) != 0) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspace内の通常file存在を確認する。
 *
 * Cleanup成否だけを確認し、絶対pathを試験出力へ記録しない。
 *
 * @param[in] workspace Pathを所有する試験用保護領域。
 * @param[in] relativePath 検証済みASCII相対file path。
 * @return 通常fileまたはdirectoryが存在する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool workspaceFileExists( const OfficialDownloadWorkspace &workspace,
									   const std::wstring_view			relativePath)
{
	const std::wstring path = workspace.path( relativePath) ;	// 属性照会だけに使う絶対path。
	return !path.empty() && GetFileAttributesW( path.c_str()) != INVALID_FILE_ATTRIBUTES ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非solidとsolidの一意folder量を確認し、現decoder上限超過と不正選択をdecodeおよびfile作成前に拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSelectionFolderAssessment( TestContext &context)
{
	std::vector<std::byte> normalArchive ;	// 二つの非solid folderを持つfixture。
	std::vector<std::byte> solidArchive ;	// 二fileが一folderを共有するfixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( VALID_ARCHIVE_BASE64, normalArchive)) ;
	DRIVERCRATE_EXPECT( context, decodeFixture( SOLID_ARCHIVE_BASE64, solidArchive)) ;

	std::vector<OfficialSevenZipEntry> normalEntries ;	// 非solidの通常file一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( normalArchive, POLICY, normalEntries) == 0) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( normalEntries.size() != 2U) {
		return ;
	}

	const std::array normalSelection{
		normalEntries[0].archiveIndex,
		normalEntries[1].archiveIndex} ;				// 二つの非solid fileを選ぶindex集合。
	OfficialSevenZipSelectionAssessment assessment ;	// Metadataだけで得るfolder要求。
	DRIVERCRATE_EXPECT( context, assessOfficialSevenZipSelection( normalArchive, POLICY,
																normalSelection, assessment) == 0) ;
	DRIVERCRATE_EXPECT( context, assessment.disposition ==
									OfficialSevenZipSelectionDisposition::WITHIN_DECODER_LIMIT) ;
	DRIVERCRATE_EXPECT( context, assessment.folders.size() == 2U) ;
	DRIVERCRATE_EXPECT( context,
					   assessment.totalRequiredUncompressedBytes ==
						   normalEntries[0].uncompressedSize + normalEntries[1].uncompressedSize) ;

	std::vector<OfficialSevenZipEntry> solidEntries ;	// Solid fixtureの通常file一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( solidArchive, POLICY, solidEntries) == 0) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( solidEntries.size() != 2U) {
		return ;
	}

	const std::array solidSelection{
		solidEntries[0].archiveIndex,
		solidEntries[1].archiveIndex} ;	// 同じsolid folderを共有する選択集合。
	DRIVERCRATE_EXPECT( context, assessOfficialSevenZipSelection( solidArchive, POLICY,
																solidSelection, assessment) == 0) ;
	DRIVERCRATE_EXPECT( context, assessment.disposition ==
									OfficialSevenZipSelectionDisposition::WITHIN_DECODER_LIMIT) ;
	DRIVERCRATE_EXPECT( context, assessment.folders.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( assessment.folders.size() == 1U) {
		DRIVERCRATE_EXPECT( context, assessment.folders[0].uncompressedBytes == 238U) ;
		DRIVERCRATE_EXPECT( context, assessment.folders[0].selectedFileCount == 2U) ;
		DRIVERCRATE_EXPECT( context, assessment.totalRequiredUncompressedBytes == 238U) ;
	}

	OfficialSevenZipExtractionPolicy limitedPolicy = POLICY ;	// Decode上限だけを縮小するpolicy。
	limitedPolicy.maximumSingleAllocationBytes	   = 237U ;
	DRIVERCRATE_EXPECT( context, assessOfficialSevenZipSelection( solidArchive, limitedPolicy,
																solidSelection, assessment) == 0) ;
	DRIVERCRATE_EXPECT( context, assessment.disposition ==
									OfficialSevenZipSelectionDisposition::SOLID_BLOCK_TOO_LARGE) ;
	DRIVERCRATE_EXPECT( context, assessment.folders.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, assessment.totalRequiredUncompressedBytes == 238U) ;

	const NativeError expectedSizeError = static_cast<NativeError>(
		// Decode前の明示上限拒否値。
		HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	std::vector<std::byte> content{std::byte{0x01}} ;	// 過大時のmemory非公開確認用出力。
	DRIVERCRATE_EXPECT( context, extractOfficialSevenZipFile( solidArchive, limitedPolicy,
															solidEntries[0].archiveIndex,
															content) == expectedSizeError) ;
	DRIVERCRATE_EXPECT( context, content.empty()) ;

	OfficialDownloadWorkspace workspace ;	// 過大選択時に空を維持する保護領域。
	// 展開先検証用の保護workspaceを開始した結果。
	const NativeError		  initializeError = workspace.initialize( L"seven-zip-test", 206U) ;
	DRIVERCRATE_EXPECT( context, initializeError == 0) ;
	// workspace初期化失敗時はdecode上限の詳細試験を続けない。
	if( initializeError != 0) {
		return ;
	}

	std::vector<OfficialSevenZipEntry> output{{}} ;	// 過大時にclearされる展開結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialSevenZipFiles( solidArchive, limitedPolicy, solidSelection,
													workspace, output) == expectedSizeError) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( workspace, L"driver.inf")) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( workspace, L"driver.sys")) ;

	const std::array duplicateSelection{solidEntries[0].archiveIndex,
										solidEntries[0].archiveIndex} ;	// 重複を含む不正index集合。
	assessment.folders.push_back( {9U, 9U, 9U}) ;
	assessment.totalRequiredUncompressedBytes = 9U ;
	DRIVERCRATE_EXPECT( context, assessOfficialSevenZipSelection(
									solidArchive, POLICY, duplicateSelection, assessment) != 0) ;
	DRIVERCRATE_EXPECT( context, assessment.folders.empty()) ;
	DRIVERCRATE_EXPECT( context, assessment.totalRequiredUncompressedBytes == 0U) ;

	const std::array unknownSelection{100U} ;	// Archiveに存在しないindex集合。
	assessment.folders.push_back( {9U, 9U, 9U}) ;
	assessment.totalRequiredUncompressedBytes = 9U ;
	DRIVERCRATE_EXPECT( context, assessOfficialSevenZipSelection( solidArchive, POLICY,
																unknownSelection, assessment) != 0) ;
	DRIVERCRATE_EXPECT( context, assessment.folders.empty()) ;
	DRIVERCRATE_EXPECT( context, assessment.totalRequiredUncompressedBytes == 0U) ;

	assessment.folders.push_back( {9U, 9U, 9U}) ;
	DRIVERCRATE_EXPECT( context,
					   assessOfficialSevenZipSelection( solidArchive, POLICY, {}, assessment) != 0) ;
	DRIVERCRATE_EXPECT( context, assessment.folders.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択fileのworkspace展開とhash保持を検証する。
 *
 * 逆順指定でもarchive順に展開し、fileごとのSHA-256と選択外file非作成を確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWorkspaceSelectionAndHash( TestContext &context)
{
	std::vector<std::byte> archive ;	// Base64から復元する正常7z fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( VALID_ARCHIVE_BASE64, archive)) ;
	std::vector<OfficialSevenZipEntry> inspected ;	// 選択indexを得る通常file一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, POLICY, inspected) == 0) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( inspected.size() != 2U) {
		return ;
	}

	OfficialDownloadWorkspace workspace ;	// 二fileの展開結果を所有する保護領域。
	// 選択展開試験用の保護workspaceを開始した結果。
	const NativeError		  initializeError = workspace.initialize( L"seven-zip-test", 201U) ;
	DRIVERCRATE_EXPECT( context, initializeError == 0) ;
	// workspace初期化失敗時は選択fileの展開試験を続けない。
	if( initializeError != 0) {
		return ;
	}

	const std::array				   selected{inspected[1].archiveIndex,
								inspected[0].archiveIndex} ;	// 呼出し側の逆順選択。
	std::vector<OfficialSevenZipEntry> extracted ;				// 全成功後に公開される選択file群。
	DRIVERCRATE_EXPECT( context, extractOfficialSevenZipFiles( archive, POLICY, selected, workspace,
															 extracted) == 0) ;
	DRIVERCRATE_EXPECT( context, extracted.size() == 2U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( extracted.size() == 2U) {
		DRIVERCRATE_EXPECT( context, extracted[0].relativePath == L"driver.inf") ;
		DRIVERCRATE_EXPECT( context, extracted[1].relativePath == L"driver.sys") ;
		std::wstring actualHash ;	// Workspace上のINFから再計算する比較用SHA-256。
		DRIVERCRATE_EXPECT( context,
						   computeFileSha256( workspace.path( L"driver.inf"), actualHash) == 0) ;
		DRIVERCRATE_EXPECT( context, extracted[0].sha256 == actualHash) ;
		DRIVERCRATE_EXPECT( context, extracted[0].sha256.size() == 64U) ;
		DRIVERCRATE_EXPECT( context, extracted[1].sha256.size() == 64U) ;
	}

	DRIVERCRATE_EXPECT( context, workspaceFileExists( workspace, L"driver.inf")) ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( workspace, L"driver.sys")) ;

	OfficialDownloadWorkspace selectedWorkspace ;	// 一fileだけを所有する独立保護領域。
	const NativeError		  selectedInitializeError =
		// 独立workspace初期化結果。
		selectedWorkspace.initialize( L"seven-zip-test", 202U) ;
	DRIVERCRATE_EXPECT( context, selectedInitializeError == 0) ;
	// 選択展開用領域を初期化できなければ展開処理を開始しない。
	if( selectedInitializeError != 0) {
		return ;
	}

	const std::array onlyInf{inspected[0].archiveIndex} ;	// 展開を許可するINF indexだけ。
	std::vector<OfficialSevenZipEntry> selectedEntries ;	// 一件だけの成功結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialSevenZipFiles( archive, POLICY, onlyInf, selectedWorkspace,
													selectedEntries) == 0) ;
	DRIVERCRATE_EXPECT( context, selectedEntries.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( selectedWorkspace, L"driver.inf")) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( selectedWorkspace, L"driver.sys")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正な選択index集合をfile作成前に拒否する。
 *
 * 空、重複、上限超過、directory、未知indexをfail-closedで拒否し、公開結果を空に保つ。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWorkspaceSelectionRejection( TestContext &context)
{
	std::vector<std::byte> archive ;	// 通常file選択のnegative試験用fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( VALID_ARCHIVE_BASE64, archive)) ;
	std::vector<OfficialSevenZipEntry> inspected ;	// 重複選択に使う通常file一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, POLICY, inspected) == 0) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( inspected.empty()) {
		return ;
	}

	OfficialDownloadWorkspace workspace ;	// 拒否時に空のまま保持する保護領域。
	// 展開拒否試験用の保護workspaceを開始した結果。
	const NativeError		  initializeError = workspace.initialize( L"seven-zip-test", 203U) ;
	DRIVERCRATE_EXPECT( context, initializeError == 0) ;
	// workspace初期化失敗時は不正選択集合の展開試験を続けない。
	if( initializeError != 0) {
		return ;
	}

	std::vector<OfficialSevenZipEntry> output{{}} ;	// 各失敗時のclear確認用結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialSevenZipFiles( archive, POLICY, {}, workspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;

	const std::array duplicate{inspected[0].archiveIndex,
							   inspected[0].archiveIndex} ;	// 重複index集合。
	DRIVERCRATE_EXPECT(
		context, extractOfficialSevenZipFiles( archive, POLICY, duplicate, workspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;

	const std::array unknown{100U} ;	// Archiveに存在しないindex集合。
	DRIVERCRATE_EXPECT(
		context, extractOfficialSevenZipFiles( archive, POLICY, unknown, workspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;

	std::vector<std::uint32_t> excessive( POLICY.maximumEntryCount + 1U,
										 inspected[0].archiveIndex) ;	// 件数上限超過集合。
	DRIVERCRATE_EXPECT(
		context, extractOfficialSevenZipFiles( archive, POLICY, excessive, workspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;

	std::vector<std::byte> directoryArchive ;	// 明示directoryを含む合成7z fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( DIRECTORY_ARCHIVE_BASE64, directoryArchive)) ;
	const std::array directoryIndex{0U} ;	// Fixture内の明示directory entry index。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialSevenZipFiles( directoryArchive, POLICY, directoryIndex,
													workspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( workspace, L"empty\\driver.inf")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CRCまたはfile作成失敗時のcleanupを検証する。
 *
 * 部分展開fileを直ちに破棄し、呼出し前の同名fileは保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWorkspaceFailureCleanup( TestContext &context)
{
	std::vector<std::byte> archive ;	// 部分展開失敗に使う正常7z fixture。
	DRIVERCRATE_EXPECT( context, decodeFixture( VALID_ARCHIVE_BASE64, archive)) ;
	std::vector<OfficialSevenZipEntry> inspected ;	// 二fileのarchive index一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZip( archive, POLICY, inspected) == 0) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( inspected.size() != 2U) {
		return ;
	}

	OfficialDownloadWorkspace conflictWorkspace ;	// 二件目を衝突させる保護領域。
	const NativeError		  conflictInitializeError =
		// Workspace初期化結果。
		conflictWorkspace.initialize( L"seven-zip-test", 204U) ;
	DRIVERCRATE_EXPECT( context, conflictInitializeError == 0) ;
	// 競合試験用領域を初期化できなければfile作成を開始しない。
	if( conflictInitializeError != 0) {
		return ;
	}

	HANDLE			  existingFile{INVALID_HANDLE_VALUE} ;	// 呼出し前から存在させるSYS handle。
	const NativeError createError =
		// 衝突file作成結果。
		conflictWorkspace.createFile( L"driver.sys", existingFile) ;
	DRIVERCRATE_EXPECT( context, createError == 0) ;
	// 競合fileを作成できなければ作成失敗の注入試験を続けない。
	if( createError != 0) {
		return ;
	}

	const BOOL closeSucceeded = CloseHandle( existingFile) ;	// 衝突fileのhandle解放結果。
	DRIVERCRATE_EXPECT( context, closeSucceeded != FALSE) ;
	const std::array				   selected{inspected[0].archiveIndex,
								inspected[1].archiveIndex} ;	// 二件目で衝突する選択集合。
	std::vector<OfficialSevenZipEntry> output{{}} ;				// 失敗時のclear確認用結果。
	DRIVERCRATE_EXPECT( context, extractOfficialSevenZipFiles( archive, POLICY, selected,
															 conflictWorkspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( conflictWorkspace, L"driver.inf")) ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( conflictWorkspace, L"driver.sys")) ;

	OfficialDownloadWorkspace crcWorkspace ;	// CRC失敗時に空を維持する保護領域。
	const NativeError		  crcInitializeError =
		// 独立workspace初期化結果。
		crcWorkspace.initialize( L"seven-zip-test", 205U) ;
	DRIVERCRATE_EXPECT( context, crcInitializeError == 0) ;
	// CRC試験用領域を初期化できなければ破損archiveを展開しない。
	if( crcInitializeError != 0) {
		return ;
	}

	std::vector<std::byte> corrupted = archive ;	// Packed payloadだけを変更したfixture。
	corrupted[40] ^= std::byte{0x01} ;
	const std::array corruptedSelection{inspected[0].archiveIndex} ;	// CRC失敗対象index。
	output = {{}} ;
	DRIVERCRATE_EXPECT( context, extractOfficialSevenZipFiles( corrupted, POLICY, corruptedSelection,
															 crcWorkspace, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.empty()) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( crcWorkspace, L"driver.inf")) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_seven_zip_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialSevenZipTests( TestContext &context)
{
	testValidInspectionAndExtraction( context) ;
	testEncryptionAndCodecRejection( context) ;
	testPathAndDuplicateRejection( context) ;
	testEntryAndSizeRejection( context) ;
	testDictionaryAndSolidRejection( context) ;
	testSelectionFolderAssessment( context) ;
	testWorkspaceSelectionAndHash( context) ;
	testWorkspaceSelectionRejection( context) ;
	testWorkspaceFailureCleanup( context) ;
}

} // namespace drivercrate::test
