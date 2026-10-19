//------------------------------------------------------------------------------
/**
 * @file official_sfx_tests.cpp
 * @brief 公式自己解凍形式の静的識別単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  正常PE fixtureのraw section境界を修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z識別の拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate zero padding試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空PE／7z fixtureでrange、CRC、重複signature、certificate tableと必要最小zero paddingを検証します。実配布物の実行合格ではあ
 *       りません。
 */
//------------------------------------------------------------------------------

#include "official_sfx_tests.h"

#include "platform/official_sfx.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t PE_OFFSET		   = 0x80U ;	// 架空PE signatureのfile offset。
constexpr std::size_t OPTIONAL_OFFSET  = 0x98U ;	// 架空PE32 optional headerのoffset。
constexpr std::size_t HEADERS_END	   = 0x200U ;	// PE header群の末尾。
constexpr std::size_t IMAGE_END		   = 0x220U ;	// Headerとraw sectionを含むimage末尾。
constexpr std::size_t ARCHIVE_OFFSET   = 0x240U ;	// 架空7z signatureのfile offset。
constexpr std::size_t NEXT_HEADER_SIZE = 8U ;		// 架空7z Next Headerのbyte数。
constexpr std::size_t ARCHIVE_END =
	ARCHIVE_OFFSET + 32U + NEXT_HEADER_SIZE ;						// 架空7z stream直後のoffset。
constexpr std::uint32_t			   CRC32_POLYNOMIAL = 0xedb88320U ;	// IEEE CRC-32反転多項式。
constexpr std::array<std::byte, 6> SEVEN_ZIP_SIGNATURE{
	std::byte{0x37}, std::byte{0x7a}, std::byte{0xbc},
	std::byte{0xaf}, std::byte{0x27}, std::byte{0x1c}} ;	// 7z file signature。
constexpr OfficialSfxInspectionPolicy POLICY{4096U, 512U,
											 1024U} ;	// 全fixtureを包含する通常検査上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Alignmentに依存せず架空PEの16-bit fieldを構築する。
 *
 * @param[in,out] output 十分な長さを確保済みのfixture。
 * @param[in] offset 書込み開始offset。
 * @param[in] value Little-endianで書き込む16-bit値。
 */
//------------------------------------------------------------------------------
void writeU16Le( std::vector<std::byte> &output, const std::size_t offset, const std::uint16_t value)
{
	output[offset]		= static_cast<std::byte>( value & 0xffU) ;
	output[offset + 1U] = static_cast<std::byte>( (value >> 8U) & 0xffU) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Alignmentに依存せず架空PE／7zの32-bit fieldを構築する。
 *
 * @param[in,out] output 十分な長さを確保済みのfixture。
 * @param[in] offset 書込み開始offset。
 * @param[in] value Little-endianで書き込む32-bit値。
 */
//------------------------------------------------------------------------------
void writeU32Le( std::vector<std::byte> &output, const std::size_t offset, const std::uint32_t value)
{
	// 4 byteを下位側から順に書き込む。
	for( std::size_t byteIndex = 0; byteIndex < 4U; ++byteIndex) {
		output[offset + byteIndex] =
			static_cast<std::byte>( (value >> static_cast<unsigned int>( byteIndex * 8U)) & 0xffU) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Alignmentに依存せず架空7zの64-bit fieldを構築する。
 *
 * @param[in,out] output 十分な長さを確保済みのfixture。
 * @param[in] offset 書込み開始offset。
 * @param[in] value Little-endianで書き込む64-bit値。
 */
//------------------------------------------------------------------------------
void writeU64Le( std::vector<std::byte> &output, const std::size_t offset, const std::uint64_t value)
{
	// 8 byteを下位側から順に書き込む。
	for( std::size_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
		output[offset + byteIndex] =
			static_cast<std::byte>( (value >> static_cast<unsigned int>( byteIndex * 8U)) & 0xffU) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Production parserと独立してfixtureの期待CRCを構築する。
 *
 * @param[in] input CRCを付与するfixtureのbyte列。
 * @return IEEE CRC-32値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t calculateCrc32( const std::span<const std::byte> input) noexcept
{
	std::uint32_t crc = std::numeric_limits<std::uint32_t>::max() ;	// CRC初期値。
	// 全入力byteを順番どおりCRCへ反映する。
	for( const std::byte value : input) {
		crc ^= std::to_integer<std::uint8_t>( value) ;
		// 一byteを最下位bitから8回更新する。
		for( unsigned int bitIndex = 0; bitIndex < 8U; ++bitIndex) {
			const std::uint32_t mask =
				0U - (crc & 1U) ;	// 下位bitが1の場合だけ多項式を適用するmask。
			crc = (crc >> 1U) ^ (CRC32_POLYNOMIAL & mask) ;
		}
	}

	return ~crc ;
}

//------------------------------------------------------------------------------
/**
 * @brief Offset試験がStart Header CRCで先に失敗しないよう再計算する。
 *
 * @param[in,out] fixture Start Headerを変更済みの架空7z byte列。
 */
//------------------------------------------------------------------------------
void refreshStartHeaderCrc( std::vector<std::byte> &fixture)
{
	const std::span<const std::byte> startHeader( fixture.data() + ARCHIVE_OFFSET + 12U,
												 20U) ;	// 7z Start Header範囲。
	writeU32Le( fixture, ARCHIVE_OFFSET + 8U, calculateCrc32( startHeader)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Padding分だけNext Headerを短くし、Certificateを固定の8-byte境界へ配置する。
 *
 * @param[in] withCertificate trueなら末尾に最小certificateを付加。
 * @param[in] pe32Plus trueならPE32+、falseならPE32を構築する。
 * @param[in] certificatePaddingSize Certificate直前の0～7 bytes。
 * @return 構造とCRCが整合する架空PE32／PE32+＋7z byte列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> makeValidFixture( const bool		withCertificate,
													  const bool		pe32Plus,
													  const std::size_t certificatePaddingSize = 0U)
{
	constexpr std::size_t CERTIFICATE_SIZE = 8U ;	// 最小WIN_CERTIFICATE長。
	const std::size_t	  archiveEnd =
		ARCHIVE_END - certificatePaddingSize ;	// Padding直前の7z stream末尾。
	const std::size_t	   fixtureSize = withCertificate
											 ? ARCHIVE_END + CERTIFICATE_SIZE
											 : archiveEnd ;	// Certificateを含むfixture全体長。
	std::vector<std::byte> fixture( fixtureSize) ;			// 0初期化した構築対象byte列。

	fixture[0] = std::byte{0x4d} ;
	fixture[1] = std::byte{0x5a} ;
	writeU32Le( fixture, 0x3cU, static_cast<std::uint32_t>( PE_OFFSET)) ;
	fixture[PE_OFFSET]		= std::byte{0x50} ;
	fixture[PE_OFFSET + 1U] = std::byte{0x45} ;
	writeU16Le( fixture, PE_OFFSET + 4U, 0x014cU) ;
	writeU16Le( fixture, PE_OFFSET + 6U, 1U) ;
	const std::uint16_t optionalHeaderSize = static_cast<std::uint16_t>(
		pe32Plus ? 240U : 224U) ;	// 選択したPE形式の標準optional header長。
	writeU16Le( fixture, PE_OFFSET + 20U, optionalHeaderSize) ;

	writeU16Le( fixture, OPTIONAL_OFFSET, static_cast<std::uint16_t>( pe32Plus ? 0x020bU : 0x010bU)) ;
	writeU32Le( fixture, OPTIONAL_OFFSET + 60U, static_cast<std::uint32_t>( HEADERS_END)) ;
	const std::size_t directoryCountOffset =
		OPTIONAL_OFFSET + (pe32Plus ? 108U : 92U) ;	// NumberOfRvaAndSizes位置。
	writeU32Le( fixture, directoryCountOffset, 16U) ;
	const std::size_t sectionOffset =
		OPTIONAL_OFFSET + optionalHeaderSize ;	// 唯一のsection header。
	writeU32Le( fixture, sectionOffset + 16U, 0x20U) ;
	writeU32Le( fixture, sectionOffset + 20U, static_cast<std::uint32_t>( HEADERS_END)) ;

	// certificate付きscenarioでは8-byte境界に固定した証明書領域をfixtureへ追加する。
	if( withCertificate) {
		const std::size_t securityDirectoryOffset =
			OPTIONAL_OFFSET + (pe32Plus ? 112U : 96U) + 4U * 8U ;	// Certificate data directory位置。
		writeU32Le( fixture, securityDirectoryOffset, static_cast<std::uint32_t>( ARCHIVE_END)) ;
		writeU32Le( fixture, securityDirectoryOffset + 4U,
				   static_cast<std::uint32_t>( CERTIFICATE_SIZE)) ;
		writeU32Le( fixture, ARCHIVE_END, static_cast<std::uint32_t>( CERTIFICATE_SIZE)) ;
		writeU16Le( fixture, ARCHIVE_END + 4U, 0x0200U) ;
		writeU16Le( fixture, ARCHIVE_END + 6U, 0x0002U) ;
	}

	std::copy( SEVEN_ZIP_SIGNATURE.begin(), SEVEN_ZIP_SIGNATURE.end(),
			  fixture.begin() + ARCHIVE_OFFSET) ;
	fixture[ARCHIVE_OFFSET + 6U] = std::byte{0x00} ;
	fixture[ARCHIVE_OFFSET + 7U] = std::byte{0x04} ;
	writeU64Le( fixture, ARCHIVE_OFFSET + 12U, 0U) ;
	const std::size_t nextHeaderSize =
		NEXT_HEADER_SIZE - certificatePaddingSize ;	// Padding分を除くNext Header長。
	writeU64Le( fixture, ARCHIVE_OFFSET + 20U, nextHeaderSize) ;
	constexpr std::array<std::byte, NEXT_HEADER_SIZE> NEXT_HEADER{
		std::byte{0x01}, std::byte{0x04}, std::byte{0x06}, std::byte{0x00},
		std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}} ;	// 架空header。
	std::copy_n( NEXT_HEADER.begin(), nextHeaderSize, fixture.begin() + ARCHIVE_OFFSET + 32U) ;
	const std::span<const std::byte> nextHeader( fixture.data() + ARCHIVE_OFFSET + 32U,
												nextHeaderSize) ;	// Next Header範囲。
	writeU32Le( fixture, ARCHIVE_OFFSET + 28U, calculateCrc32( nextHeader)) ;
	refreshStartHeaderCrc( fixture) ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificateなし／ありの単一7z境界を比較する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidSfxLayout( TestContext &context)
{
	const std::vector<std::byte> unsignedFixture =
		// Certificateを持たない正常PE32 fixture。
		makeValidFixture( false, false) ;
	OfficialSfxLayout unsignedLayout{} ;	// Certificateなしの識別結果。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( unsignedFixture, POLICY, unsignedLayout) == 0) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.archiveOffset == ARCHIVE_OFFSET) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.archiveSize == ARCHIVE_END - ARCHIVE_OFFSET) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.certificatePaddingSize == 0U) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.nextHeaderOffset == ARCHIVE_OFFSET + 32U) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.nextHeaderSize == NEXT_HEADER_SIZE) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.certificateOffset == 0U) ;

	const std::vector<std::byte> signedFixture =
		// 最小certificate tableを持つ正常PE32+ fixture。
		makeValidFixture( true, true) ;
	OfficialSfxLayout signedLayout{} ;	// Certificateありの識別結果。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( signedFixture, POLICY, signedLayout) == 0) ;
	DRIVERCRATE_EXPECT( context, signedLayout.certificateOffset == ARCHIVE_END) ;
	DRIVERCRATE_EXPECT( context, signedLayout.certificateSize == 8U) ;
	DRIVERCRATE_EXPECT( context, signedLayout.certificatePaddingSize == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificate tableを次の8-byte境界へ揃える2、3、7 bytesのzero paddingを受理し、archive範囲から分離する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testCertificateAlignmentPaddingAcceptance( TestContext &context)
{
	constexpr std::array<std::size_t, 3> PADDING_SIZES{2U, 3U, 7U} ;	// 実物を含む正常padding長。
	// paddingSizeは現在検証するCertificate直前のzero byte数。
	// 各padding長で7z範囲とCertificate table境界を独立に確認する。
	for( const std::size_t paddingSize : PADDING_SIZES) {
		const std::vector<std::byte> fixture =
			// Zero padding付きPE32+ fixture。
			makeValidFixture( true, true, paddingSize) ;
		OfficialSfxLayout layout{} ;	// 正常識別結果。
		DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( fixture, POLICY, layout) == 0) ;
		DRIVERCRATE_EXPECT( context, layout.archiveOffset == ARCHIVE_OFFSET) ;
		DRIVERCRATE_EXPECT( context,
						   layout.archiveSize == ARCHIVE_END - paddingSize - ARCHIVE_OFFSET) ;
		DRIVERCRATE_EXPECT( context, layout.certificatePaddingSize == paddingSize) ;
		DRIVERCRATE_EXPECT( context, layout.certificateOffset == ARCHIVE_END) ;
		DRIVERCRATE_EXPECT( context, layout.archiveOffset + layout.archiveSize +
											layout.certificatePaddingSize ==
										layout.certificateOffset) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 非zero、8 bytes、Certificateなしtrailer、非aligned tableをfail-closedで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testCertificateAlignmentPaddingRejection( TestContext &context)
{
	std::vector<std::byte> nonzeroPadding =
		// 三byte中の一byteを改ざんするfixture。
		makeValidFixture( true, false, 3U) ;
	nonzeroPadding[ARCHIVE_END - 1U] = std::byte{0x01} ;
	OfficialSfxLayout layout{1U, 1U, 1U, 1U, 1U, 1U, 1U} ;	// 失敗時初期化確認用出力。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( nonzeroPadding, POLICY, layout) != 0) ;
	DRIVERCRATE_EXPECT( context, layout.archiveOffset == 0U) ;
	DRIVERCRATE_EXPECT( context, layout.certificatePaddingSize == 0U) ;

	std::vector<std::byte> oversizedPadding =
		// 正常Certificateを後方へ移す基準fixture。
		makeValidFixture( true, false) ;
	constexpr std::size_t REJECTED_PADDING_SIZE = 8U ;	// 許可範囲を一byte越える間隔。
	oversizedPadding.insert( oversizedPadding.begin() + ARCHIVE_END, REJECTED_PADDING_SIZE,
							std::byte{0x00}) ;
	constexpr std::size_t PE32_SECURITY_DIRECTORY_OFFSET =
		OPTIONAL_OFFSET + 96U + 4U * 8U ;	// PE32 Certificate data directory位置。
	writeU32Le( oversizedPadding, PE32_SECURITY_DIRECTORY_OFFSET,
			   static_cast<std::uint32_t>( ARCHIVE_END + REJECTED_PADDING_SIZE)) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( oversizedPadding, POLICY, layout) != 0) ;

	std::vector<std::byte> unsignedTrailer =
		// Certificateなしの正常fixture。
		makeValidFixture( false, false) ;
	unsignedTrailer.push_back( std::byte{0x00}) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( unsignedTrailer, POLICY, layout) != 0) ;

	std::vector<std::byte> misalignedCertificate =
		// Certificate offset改ざんfixture。
		makeValidFixture( true, false, 3U) ;
	writeU32Le( misalignedCertificate, PE32_SECURITY_DIRECTORY_OFFSET,
			   static_cast<std::uint32_t>( ARCHIVE_END - 1U)) ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( misalignedCertificate, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 切詰め、Start Header CRC、Next Header CRC改ざんを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testTruncationAndCrcRejection( TestContext &context)
{
	std::vector<std::byte> truncated = makeValidFixture( false, false) ;	// 末尾切詰めfixture。
	truncated.pop_back() ;
	OfficialSfxLayout layout{1U, 1U, 1U, 1U, 1U, 1U, 1U} ;	// 失敗時初期化確認用出力。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( truncated, POLICY, layout) != 0) ;
	DRIVERCRATE_EXPECT( context, layout.archiveOffset == 0U) ;

	std::vector<std::byte> startCrc = makeValidFixture( false, false) ;	// Start CRC改ざんfixture。
	startCrc[ARCHIVE_OFFSET + 8U] ^= std::byte{0x01} ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( startCrc, POLICY, layout) != 0) ;

	std::vector<std::byte> nextCrc = makeValidFixture( false, false) ;	// Next CRC改ざんfixture。
	nextCrc[ARCHIVE_OFFSET + 28U] ^= std::byte{0x01} ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( nextCrc, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stub内に別の7z signatureを持つ曖昧な入力を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDuplicateSignatureRejection( TestContext &context)
{
	std::vector<std::byte> duplicate = makeValidFixture( false, false) ;	// 二signature fixture。
	std::copy( SEVEN_ZIP_SIGNATURE.begin(), SEVEN_ZIP_SIGNATURE.end(),
			  duplicate.begin() + IMAGE_END + 8U) ;
	OfficialSfxLayout layout{} ;	// 失敗を期待する識別結果。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( duplicate, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stub／archive上限と64-bit Next Header offset超過を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testLimitAndRangeRejection( TestContext &context)
{
	const std::vector<std::byte>	  fixture = makeValidFixture( false, false) ;	// 正常基準fixture。
	const OfficialSfxInspectionPolicy shortStubPolicy{4096U, 16U,
													  1024U} ;	// 実fixtureのstub長より小さい上限。
	OfficialSfxLayout				  layout{} ;				// 失敗を期待する識別結果。
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( fixture, shortStubPolicy, layout) != 0) ;

	const OfficialSfxInspectionPolicy smallArchivePolicy{4096U, 512U,
														 39U} ;	// 40-byte archiveを拒否する上限。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( fixture, smallArchivePolicy, layout) != 0) ;

	std::vector<std::byte> overflowing =
		// Offset overflow fixture。
		makeValidFixture( false, false) ;
	writeU64Le( overflowing, ARCHIVE_OFFSET + 12U, std::numeric_limits<std::uint64_t>::max()) ;
	refreshStartHeaderCrc( overflowing) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( overflowing, POLICY, layout) != 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_sfx_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialSfxTests( TestContext &context)
{
	testValidSfxLayout( context) ;
	testCertificateAlignmentPaddingAcceptance( context) ;
	testCertificateAlignmentPaddingRejection( context) ;
	testTruncationAndCrcRejection( context) ;
	testDuplicateSignatureRejection( context) ;
	testLimitAndRangeRejection( context) ;
}

} // namespace drivercrate::test
