//------------------------------------------------------------------------------
/**
 * @file official_sfx_tests.cpp
 * @brief 公式自己解凍形式の静的識別単体試験実装
 * @version 01.09.00
 * @date 2026/09/06
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  正常PE fixtureのraw section境界を修正
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z識別の拒否試験を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate zero padding試験を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.01.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.02.00 Shunji Ogawa  2026/11/23  WiX v3のCABと証明書テーブルの境界試験を追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/23  WiX v3マニフェストの選択と不一致の試験を追加
 * Ver.01.04.00 Shunji Ogawa  2026/11/23  WiX v3の元取得identityと外側署名の拒否試験を追加
 * Ver.01.05.00 Shunji Ogawa  2026/11/23  署名付きPE末尾ZIPのオフセット基準と境界試験を追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/23  末尾ZIPの元取得証拠と主署名の拒否試験を追加
 * Ver.01.07.00 Shunji Ogawa  2026/11/23  私有Server向け末尾ZIP収集検査の事前拒否を検証
 * Ver.01.08.00 Shunji Ogawa  2026/11/24  審査済みNSISの元位置・一意性・展開の境界を検証
 * Ver.01.09.00 Shunji Ogawa  2026/11/24  私有NSISの取得条件と原本同一性を検証
 * </pre>
 *
 * @note 架空PEで7z、WiX v3、末尾ZIPそれぞれの元範囲を検証する
 *       署名テーブルは構造だけを再現し、固定原本の信頼検証がこれを拒否することを確認する
 */
//------------------------------------------------------------------------------

#include "official_sfx_tests.h"

#include "platform/common_driver_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_sfx.h"
#include "platform/official_wix_manifest.h"
#include "platform/official_zip.h"
#include "test_framework.h"

#include <Windows.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::size_t PE_OFFSET		   = 0x80U ;	// 架空PE signatureのfile offset
constexpr std::size_t OPTIONAL_OFFSET  = 0x98U ;	// 架空PE32 optional headerのoffset
constexpr std::size_t HEADERS_END	   = 0x200U ;	// PE header群の末尾
constexpr std::size_t IMAGE_END		   = 0x220U ;	// Headerとraw sectionを含むimage末尾
constexpr std::size_t ARCHIVE_OFFSET   = 0x240U ;	// 架空7z signatureのfile offset
constexpr std::size_t NEXT_HEADER_SIZE = 8U ;		// 架空7z Next Headerのbyte数
constexpr std::size_t ARCHIVE_END =
	ARCHIVE_OFFSET + 32U + NEXT_HEADER_SIZE ;						// 架空7z stream直後のoffset
constexpr std::uint32_t			   CRC32_POLYNOMIAL = 0xedb88320U ;	// IEEE CRC-32反転多項式
constexpr std::array<std::byte, 6> SEVEN_ZIP_SIGNATURE{
	std::byte{0x37}, std::byte{0x7a}, std::byte{0xbc},
	std::byte{0xaf}, std::byte{0x27}, std::byte{0x1c}} ;				// 7z file signature
constexpr OfficialSfxInspectionPolicy POLICY{4096U, 512U, 1024U} ;		// 全fixtureを包含する通常検査上限
constexpr OfficialWixBurnInspectionPolicy WIX_POLICY{4096U, 1024U} ;	// 二CABの通常fixture用上限
constexpr std::uint32_t WIX_UX_OFFSET = 0x240U ;						// WiX sectionの末尾で起動用CABが始まる
constexpr std::uint32_t WIX_UX_BYTES  = 39U ;							// 起動用CABと次の証明書の間に1 zero byteを置く
constexpr std::uint32_t WIX_ENGINE_CERTIFICATE_OFFSET = 0x268U ;		// 起動部の証明書位置
constexpr std::uint32_t WIX_CERTIFICATE_BYTES		  = 16U ;			// 一つの架空署名entryと整列を含む長さ
constexpr std::uint32_t WIX_ATTACHED_OFFSET	   = 0x278U ;				// 起動部の証明書直後に添付CABが始まる
constexpr std::uint32_t WIX_ATTACHED_BYTES	   = 44U ;					// 添付CABと次の証明書の間に4 zero byteを置く
constexpr std::uint32_t WIX_CERTIFICATE_OFFSET = 0x2a8U ;				// 元EXEの外側の証明書位置

constexpr OfficialSignedPeZipInspectionPolicy PE_ZIP_POLICY{4096U, 2U} ;	// 架空ZIP 2件を許可する上限
constexpr std::uint32_t PE_ZIP_LOCAL_SIGNATURE	 = 0x04034b50U ;			// Local file headerの識別値
constexpr std::uint32_t PE_ZIP_CENTRAL_SIGNATURE = 0x02014b50U ;			// Central directory entryの識別値
constexpr std::uint32_t PE_ZIP_END_SIGNATURE	 = 0x06054b50U ;			// End of central directoryの識別値
constexpr std::uint32_t PE_ZIP_LOCAL_BYTES		 = 30U ;					// Local file header固定部の長さ
constexpr std::uint32_t PE_ZIP_CENTRAL_BYTES	 = 46U ;					// Central directory entry固定部の長さ
constexpr std::uint32_t PE_ZIP_END_BYTES		 = 22U ;					// End of central directory固定部の長さ
constexpr std::array<std::byte, 5> PE_ZIP_NAME{std::byte{'a'}, std::byte{'.'}, std::byte{'z'},
											   std::byte{'i'}, std::byte{'p'}} ;	// 架空entry名
constexpr std::array<std::byte, 3> PE_ZIP_DATA{std::byte{'p'}, std::byte{'a'},
											   std::byte{'y'}} ;	// 両stored entryの比較用データ
constexpr std::uint16_t			   PE_ZIP_NAME_BYTES =
	// 名前長
	static_cast<std::uint16_t>( PE_ZIP_NAME.size()) ;
constexpr std::uint32_t PE_ZIP_DATA_BYTES =
	// 本体長
	static_cast<std::uint32_t>( PE_ZIP_DATA.size()) ;
constexpr std::uint32_t PE_ZIP_LOCAL_RECORD_BYTES =
	PE_ZIP_LOCAL_BYTES + PE_ZIP_NAME_BYTES + PE_ZIP_DATA_BYTES ;	// Descriptorを除くlocal record長
constexpr std::uint32_t PE_ZIP_CENTRAL_RECORD_BYTES =
	PE_ZIP_CENTRAL_BYTES + PE_ZIP_NAME_BYTES ;										// Central record長
constexpr std::uint32_t PE_ZIP_OFFSET = static_cast<std::uint32_t>( IMAGE_END) ;	// PEの直後のZIP先頭
constexpr std::uint32_t PE_ZIP_CENTRAL_OFFSET =
	PE_ZIP_OFFSET + 2U * PE_ZIP_LOCAL_RECORD_BYTES ;	// Descriptorなしのcentral先頭
constexpr std::uint32_t PE_ZIP_END_OFFSET =
	PE_ZIP_CENTRAL_OFFSET + 2U * PE_ZIP_CENTRAL_RECORD_BYTES ;	// Descriptorなしの終端record先頭
constexpr std::uint16_t PE_ZIP_COMMENT_BYTES = 3U ;				// 終端recordの架空comment長
constexpr std::uint32_t PE_ZIP_ARCHIVE_END =
	PE_ZIP_END_OFFSET + PE_ZIP_END_BYTES + PE_ZIP_COMMENT_BYTES ;	// Commentを含むZIP末尾
constexpr std::uint32_t PE_ZIP_CERTIFICATE_OFFSET =
	(PE_ZIP_ARCHIVE_END + 7U) & ~7U ;	// Descriptorなしの8-byte境界
constexpr std::size_t PE_ZIP_SECURITY_DIRECTORY =
	OPTIONAL_OFFSET + 112U + 32U ;	// PE32+のcertificate directory位置
constexpr std::uint32_t PE_ZIP_CERTIFICATE_BYTES =
	16U ;	// 一つの架空certificate entryと整列を含む長さ

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Alignmentに依存せず架空PEの16-bit fieldを構築する
 *
 * @param[in,out] output 十分な長さを確保済みのfixture
 * @param[in] offset 書込み開始offset
 * @param[in] value Little-endianで書き込む16-bit値
 */
//------------------------------------------------------------------------------
void writeU16Le( std::vector<std::byte> &output, const std::size_t offset, const std::uint16_t value)
{
	output[offset]		= static_cast<std::byte>( value & 0xffU) ;
	output[offset + 1U] = static_cast<std::byte>( (value >> 8U) & 0xffU) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Alignmentに依存せず架空PE／7zの32-bit fieldを構築する
 *
 * @param[in,out] output 十分な長さを確保済みのfixture
 * @param[in] offset 書込み開始offset
 * @param[in] value Little-endianで書き込む32-bit値
 */
//------------------------------------------------------------------------------
void writeU32Le( std::vector<std::byte> &output, const std::size_t offset, const std::uint32_t value)
{
	// 4 byteを下位側から順に書き込む
	for( std::size_t byteIndex = 0; byteIndex < 4U; ++byteIndex) {
		output[offset + byteIndex] =
			static_cast<std::byte>( (value >> static_cast<unsigned int>( byteIndex * 8U)) & 0xffU) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Alignmentに依存せず架空7zの64-bit fieldを構築する
 *
 * @param[in,out] output 十分な長さを確保済みのfixture
 * @param[in] offset 書込み開始offset
 * @param[in] value Little-endianで書き込む64-bit値
 */
//------------------------------------------------------------------------------
void writeU64Le( std::vector<std::byte> &output, const std::size_t offset, const std::uint64_t value)
{
	// 8 byteを下位側から順に書き込む
	for( std::size_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
		output[offset + byteIndex] =
			static_cast<std::byte>( (value >> static_cast<unsigned int>( byteIndex * 8U)) & 0xffU) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Production parserと独立してfixtureの期待CRCを構築する
 *
 * @param[in] input CRCを付与するfixtureのbyte列
 * @return IEEE CRC-32値
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t calculateCrc32( const std::span<const std::byte> input) noexcept
{
	std::uint32_t crc = std::numeric_limits<std::uint32_t>::max() ;	// CRC初期値
	// 全入力byteを順番どおりCRCへ反映する
	for( const std::byte value : input) {
		crc ^= std::to_integer<std::uint8_t>( value) ;
		// 一byteを最下位bitから8回更新する
		for( unsigned int bitIndex = 0; bitIndex < 8U; ++bitIndex) {
			const std::uint32_t mask = 0U - (crc & 1U) ;	// 下位bitが1の場合だけ多項式を適用するmask
			crc						 = (crc >> 1U) ^ (CRC32_POLYNOMIAL & mask) ;
		}
	}

	return ~crc ;
}

//------------------------------------------------------------------------------
/**
 * @brief Offset試験がStart Header CRCで先に失敗しないよう再計算する
 *
 * @param[in,out] fixture Start Headerを変更済みの架空7z byte列
 */
//------------------------------------------------------------------------------
void refreshStartHeaderCrc( std::vector<std::byte> &fixture)
{
	const std::span<const std::byte> startHeader( fixture.data() + ARCHIVE_OFFSET + 12U,
												 20U) ;	// 7z Start Header範囲
	writeU32Le( fixture, ARCHIVE_OFFSET + 8U, calculateCrc32( startHeader)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Padding分だけNext Headerを短くし、Certificateを固定の8-byte境界へ配置する
 *
 * @param[in] withCertificate trueなら末尾に最小certificateを付加
 * @param[in] pe32Plus trueならPE32+、falseならPE32を構築する
 * @param[in] certificatePaddingSize Certificate直前の0～7 bytes
 * @return 構造とCRCが整合する架空PE32／PE32+＋7z byte列
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> makeValidFixture( const bool		withCertificate,
													  const bool		pe32Plus,
													  const std::size_t certificatePaddingSize = 0U)
{
	constexpr std::size_t CERTIFICATE_SIZE = 8U ;	// 最小WIN_CERTIFICATE長
	const std::size_t	  archiveEnd =
		ARCHIVE_END - certificatePaddingSize ;	// Padding直前の7z stream末尾
	const std::size_t	   fixtureSize = withCertificate ? ARCHIVE_END + CERTIFICATE_SIZE
														 : archiveEnd ;	// Certificateを含むfixture全体長
	std::vector<std::byte> fixture( fixtureSize) ;						// 0初期化した構築対象byte列

	fixture[0] = std::byte{0x4d} ;
	fixture[1] = std::byte{0x5a} ;
	writeU32Le( fixture, 0x3cU, static_cast<std::uint32_t>( PE_OFFSET)) ;
	fixture[PE_OFFSET]		= std::byte{0x50} ;
	fixture[PE_OFFSET + 1U] = std::byte{0x45} ;
	writeU16Le( fixture, PE_OFFSET + 4U, 0x014cU) ;
	writeU16Le( fixture, PE_OFFSET + 6U, 1U) ;
	const std::uint16_t optionalHeaderSize =
		// 選択したPE形式の標準optional header長
		static_cast<std::uint16_t>( pe32Plus ? 240U : 224U) ;
	writeU16Le( fixture, PE_OFFSET + 20U, optionalHeaderSize) ;

	writeU16Le( fixture, OPTIONAL_OFFSET, static_cast<std::uint16_t>( pe32Plus ? 0x020bU : 0x010bU)) ;
	writeU32Le( fixture, OPTIONAL_OFFSET + 60U, static_cast<std::uint32_t>( HEADERS_END)) ;
	const std::size_t directoryCountOffset =
		OPTIONAL_OFFSET + (pe32Plus ? 108U : 92U) ;	// NumberOfRvaAndSizes位置
	writeU32Le( fixture, directoryCountOffset, 16U) ;
	const std::size_t sectionOffset = OPTIONAL_OFFSET + optionalHeaderSize ;	// 唯一のsection header
	writeU32Le( fixture, sectionOffset + 16U, 0x20U) ;
	writeU32Le( fixture, sectionOffset + 20U, static_cast<std::uint32_t>( HEADERS_END)) ;

	// certificate付きscenarioでは8-byte境界に固定した証明書領域をfixtureへ追加する
	if( withCertificate) {
		const std::size_t securityDirectoryOffset =
			OPTIONAL_OFFSET + (pe32Plus ? 112U : 96U) + 4U * 8U ;	// Certificate data directory位置
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
		NEXT_HEADER_SIZE - certificatePaddingSize ;	// Padding分を除くNext Header長
	writeU64Le( fixture, ARCHIVE_OFFSET + 20U, nextHeaderSize) ;
	constexpr std::array<std::byte, NEXT_HEADER_SIZE> NEXT_HEADER{
		std::byte{0x01}, std::byte{0x04}, std::byte{0x06}, std::byte{0x00},
		std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}} ;	// 架空header
	std::copy_n( NEXT_HEADER.begin(), nextHeaderSize, fixture.begin() + ARCHIVE_OFFSET + 32U) ;
	const std::span<const std::byte> nextHeader( fixture.data() + ARCHIVE_OFFSET + 32U,
												nextHeaderSize) ;	// Next Header範囲
	writeU32Le( fixture, ARCHIVE_OFFSET + 28U, calculateCrc32( nextHeader)) ;
	refreshStartHeaderCrc( fixture) ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じstored entry二件を持つ架空PE32+末尾ZIPを構築する
 * @param[in] offsetsFromExecutableStart trueならPE先頭、falseならZIP先頭を参照基準とする
 * @param[in] descriptorBytes 先頭entryのdescriptor構造の長さ。0、12、16のいずれか
 * @return ZIP comment、最小のzero整列、架空certificate tableを含むbyte列
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> makeSignedPeZipFixture(
	const bool offsetsFromExecutableStart, const std::uint32_t descriptorBytes = 0U)
{
	auto	   fixture		 = makeValidFixture( false, true) ;				// 既存の架空PE32+共通ヘッダー
	const auto centralOffset = PE_ZIP_CENTRAL_OFFSET + descriptorBytes ;	// 実central開始位置
	const auto endOffset	 = PE_ZIP_END_OFFSET + descriptorBytes ;		// 実EOCD開始位置
	const auto certificateOffset =
		(PE_ZIP_ARCHIVE_END + descriptorBytes + 7U) & ~7U ;						// 実証明書位置
	const auto offsetBase = offsetsFromExecutableStart ? 0U : PE_ZIP_OFFSET ;	// 記録値から除く基準
	const auto crc		  = calculateCrc32( PE_ZIP_DATA) ;						// 両entryが共有するpayloadのCRC
	fixture.resize( certificateOffset + PE_ZIP_CERTIFICATE_BYTES) ;
	std::fill( fixture.begin() + PE_ZIP_OFFSET, fixture.end(), std::byte{}) ;
	writeU16Le( fixture, PE_OFFSET + 4U, 0x8664U) ;
	writeU32Le( fixture, PE_ZIP_SECURITY_DIRECTORY, certificateOffset) ;
	writeU32Le( fixture, PE_ZIP_SECURITY_DIRECTORY + 4U, PE_ZIP_CERTIFICATE_BYTES) ;
	writeU32Le( fixture, certificateOffset, 9U) ;
	writeU16Le( fixture, certificateOffset + 4U, 0x0200U) ;
	writeU16Le( fixture, certificateOffset + 6U, 0x0002U) ;
	fixture[certificateOffset + 8U] = std::byte{0x30} ;

	// Localとcentralを同順で二件作り、先頭の後ろだけにdescriptor用領域を配置する
	for( std::uint32_t entryIndex = 0U; entryIndex < 2U; ++entryIndex) {
		const bool first = entryIndex == 0U ;	// Descriptorの有無とnameを選ぶ順序
		const bool withDescriptor =
			first && descriptorBytes != 0U ;	// Local固定部にCRC・sizeを持たない形式
		const auto flags =
			// Data descriptor bit
			static_cast<std::uint16_t>( withDescriptor ? 8U : 0U) ;
		const auto localOffset =
			first ? PE_ZIP_OFFSET
				  : PE_ZIP_OFFSET + PE_ZIP_LOCAL_RECORD_BYTES + descriptorBytes ;	// 実local開始位置
		const auto recordOffset =
			centralOffset + entryIndex * PE_ZIP_CENTRAL_RECORD_BYTES ;	// 実central record位置
		const auto name = first ? std::byte{'a'} : std::byte{'b'} ;		// entryを区別する名前の先頭byte

		writeU32Le( fixture, localOffset, PE_ZIP_LOCAL_SIGNATURE) ;
		writeU16Le( fixture, localOffset + 4U, 20U) ;
		writeU16Le( fixture, localOffset + 6U, flags) ;
		writeU16Le( fixture, localOffset + 26U, PE_ZIP_NAME_BYTES) ;
		std::copy( PE_ZIP_NAME.begin(), PE_ZIP_NAME.end(),
				  fixture.begin() + localOffset + PE_ZIP_LOCAL_BYTES) ;
		fixture[localOffset + PE_ZIP_LOCAL_BYTES] = name ;
		std::copy( PE_ZIP_DATA.begin(), PE_ZIP_DATA.end(),
				  fixture.begin() + localOffset + PE_ZIP_LOCAL_BYTES + PE_ZIP_NAME_BYTES) ;
		// Descriptor使用時は本体直後に正しいCRCと両sizeを記録する
		if( withDescriptor) {
			const auto descriptor = localOffset + PE_ZIP_LOCAL_RECORD_BYTES ;	// 本体直後の位置
			const auto fields	  = descriptor + descriptorBytes - 12U ;		// CRCの開始位置
			// 16-byte形式ではdescriptor先頭に識別値を置く
			if( descriptorBytes == 16U) {
				writeU32Le( fixture, descriptor, 0x08074b50U) ;
			}

			writeU32Le( fixture, fields, crc) ;
			writeU32Le( fixture, fields + 4U, PE_ZIP_DATA_BYTES) ;
			writeU32Le( fixture, fields + 8U, PE_ZIP_DATA_BYTES) ;
		} else {
			writeU32Le( fixture, localOffset + 14U, crc) ;
			writeU32Le( fixture, localOffset + 18U, PE_ZIP_DATA_BYTES) ;
			writeU32Le( fixture, localOffset + 22U, PE_ZIP_DATA_BYTES) ;
		}

		writeU32Le( fixture, recordOffset, PE_ZIP_CENTRAL_SIGNATURE) ;
		writeU16Le( fixture, recordOffset + 4U, 20U) ;
		writeU16Le( fixture, recordOffset + 6U, 20U) ;
		writeU16Le( fixture, recordOffset + 8U, flags) ;
		writeU32Le( fixture, recordOffset + 16U, crc) ;
		writeU32Le( fixture, recordOffset + 20U, PE_ZIP_DATA_BYTES) ;
		writeU32Le( fixture, recordOffset + 24U, PE_ZIP_DATA_BYTES) ;
		writeU16Le( fixture, recordOffset + 28U, PE_ZIP_NAME_BYTES) ;
		writeU32Le( fixture, recordOffset + 42U, localOffset - offsetBase) ;
		std::copy( PE_ZIP_NAME.begin(), PE_ZIP_NAME.end(),
				  fixture.begin() + recordOffset + PE_ZIP_CENTRAL_BYTES) ;
		fixture[recordOffset + PE_ZIP_CENTRAL_BYTES] = name ;
	}

	writeU32Le( fixture, endOffset, PE_ZIP_END_SIGNATURE) ;
	writeU16Le( fixture, endOffset + 8U, 2U) ;
	writeU16Le( fixture, endOffset + 10U, 2U) ;
	writeU32Le( fixture, endOffset + 12U, 2U * PE_ZIP_CENTRAL_RECORD_BYTES) ;
	writeU32Le( fixture, endOffset + 16U, centralOffset - offsetBase) ;
	writeU16Le( fixture, endOffset + 20U, PE_ZIP_COMMENT_BYTES) ;
	fixture[endOffset + PE_ZIP_END_BYTES]	   = std::byte{'o'} ;
	fixture[endOffset + PE_ZIP_END_BYTES + 1U] = std::byte{'k'} ;
	fixture[endOffset + PE_ZIP_END_BYTES + 2U] = std::byte{'!'} ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief 起動用CABと添付CABおよび両証明書を元宣言から読める架空WiXを構築する
 * @param[in] pe32Plus x64の外側PEにする場合true。falseの場合はx86の外側PE
 * @return 両CABの境界と必要最小整列を含むbyte列
 * @note CABは識別ヘッダーだけを、署名はWIN_CERTIFICATEの構造だけを再現する
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> makeWixFixture( const bool pe32Plus)
{
	auto fixture = makeValidFixture( false, pe32Plus) ;	// 既存の架空PE共通ヘッダー
	fixture.resize( WIX_CERTIFICATE_OFFSET + WIX_CERTIFICATE_BYTES) ;
	std::fill( fixture.begin() + HEADERS_END, fixture.end(), std::byte{}) ;
	// PE32+のBurn対照では実際のx64機械識別値に合わせる
	if( pe32Plus) {
		writeU16Le( fixture, PE_OFFSET + 4U, 0x8664U) ;
	}

	const auto securityDirectory =
		OPTIONAL_OFFSET + (pe32Plus ? 112U : 96U) + 32U ;				// 外側署名の元宣言
	const auto section = OPTIONAL_OFFSET + (pe32Plus ? 240U : 224U) ;	// 架空WiX sectionのheader
	constexpr std::array<std::byte, 8U> name{std::byte{'.'}, std::byte{'w'}, std::byte{'i'},
											 std::byte{'x'}, std::byte{'b'}, std::byte{'u'},
											 std::byte{'r'}, std::byte{'n'}} ;	// 元宣言のsection名
	std::copy( name.begin(), name.end(), fixture.begin() + section) ;
	writeU32Le( fixture, section + 8U, 56U) ;
	writeU32Le( fixture, section + 16U, 64U) ;
	writeU32Le( fixture, securityDirectory, WIX_CERTIFICATE_OFFSET) ;
	writeU32Le( fixture, securityDirectory + 4U, WIX_CERTIFICATE_BYTES) ;

	// 元WiX宣言を架空section内へ置き、インストーラーのコードは含めない
	writeU32Le( fixture, HEADERS_END, 0x00f14300U) ;
	writeU32Le( fixture, HEADERS_END + 4U, 2U) ;
	writeU32Le( fixture, HEADERS_END + 24U, WIX_UX_OFFSET) ;
	writeU32Le( fixture, HEADERS_END + 32U, WIX_ENGINE_CERTIFICATE_OFFSET) ;
	writeU32Le( fixture, HEADERS_END + 36U, WIX_CERTIFICATE_BYTES) ;
	writeU32Le( fixture, HEADERS_END + 40U, 1U) ;
	writeU32Le( fixture, HEADERS_END + 44U, 2U) ;
	writeU32Le( fixture, HEADERS_END + 48U, WIX_UX_BYTES) ;
	writeU32Le( fixture, HEADERS_END + 52U, WIX_ATTACHED_BYTES) ;

	writeU32Le( fixture, WIX_UX_OFFSET, 0x4643534dU) ;
	writeU32Le( fixture, WIX_UX_OFFSET + 8U, WIX_UX_BYTES) ;
	writeU32Le( fixture, WIX_ATTACHED_OFFSET, 0x4643534dU) ;
	writeU32Le( fixture, WIX_ATTACHED_OFFSET + 8U, WIX_ATTACHED_BYTES) ;
	// 内側と外側を別々に初期化し、ヘッダー以外に一byteを持つ架空署名を置く
	for( const auto offset : {WIX_ENGINE_CERTIFICATE_OFFSET, WIX_CERTIFICATE_OFFSET}) {
		writeU32Le( fixture, offset, 9U) ;
		writeU16Le( fixture, offset + 4U, 0x0200U) ;
		writeU16Le( fixture, offset + 6U, 0x0002U) ;
		fixture[offset + 8U] = std::byte{0x30} ;
	}

	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief WiX CABと証明書の正常境界を照合し、7zとの誤認がないことを確認する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testValidWixLayout( TestContext &context)
{
	// x86とx64の外側PEで同じ元範囲が得られることを確認する
	for( const bool pe32Plus : {false, true}) {
		const auto			  fixture = makeWixFixture( pe32Plus) ;	// 正常な架空WiX
		OfficialWixBurnLayout layout{} ;							// 比較する解析結果
		DRIVERCRATE_EXPECT( context, inspectOfficialWixBurn( fixture, WIX_POLICY, layout) == 0U) ;
		DRIVERCRATE_EXPECT( context, layout.uxCabinetOffset == WIX_UX_OFFSET &&
										layout.uxCabinetSize == WIX_UX_BYTES) ;
		DRIVERCRATE_EXPECT( context,
						   layout.engineCertificateOffset == WIX_ENGINE_CERTIFICATE_OFFSET &&
							   layout.engineCertificateSize == WIX_CERTIFICATE_BYTES) ;
		DRIVERCRATE_EXPECT( context, layout.attachedCabinetOffset == WIX_ATTACHED_OFFSET &&
										layout.attachedCabinetSize == WIX_ATTACHED_BYTES) ;
		DRIVERCRATE_EXPECT( context, layout.certificateOffset == WIX_CERTIFICATE_OFFSET &&
										layout.certificateSize == WIX_CERTIFICATE_BYTES) ;
		OfficialSfxLayout sevenZip{} ;	// 別形式の解析結果
		DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( fixture, POLICY, sevenZip) != 0U) ;
	}

	OfficialWixBurnLayout layout{} ;	// 形式違いで空を期待する結果
	DRIVERCRATE_EXPECT(
		context, inspectOfficialWixBurn( makeValidFixture( true, false), WIX_POLICY, layout) != 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WiXの宣言、CAB、証明書と整列の失敗が部分的な範囲を返さないことを確認する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testWixBoundaryRejection( TestContext &context)
{
	const auto fixture = makeWixFixture( false) ;	// 各変形の共通元
	// テスト中の集計先を借り、破損後の各入力で全出力の初期化を確認する
	const auto reject = [&context]( const std::vector<std::byte> &changed) {
		OfficialWixBurnLayout layout{1U, 1U, 1U, 1U,
									 1U, 1U, 1U, 1U} ;	// 古い結果として残してはいけない範囲
		DRIVERCRATE_EXPECT( context, inspectOfficialWixBurn( changed, WIX_POLICY, layout) != 0U) ;
		DRIVERCRATE_EXPECT(
			context, layout.uxCabinetOffset == 0U && layout.uxCabinetSize == 0U &&
						 layout.engineCertificateOffset == 0U &&
						 layout.engineCertificateSize == 0U && layout.attachedCabinetOffset == 0U &&
						 layout.attachedCabinetSize == 0U && layout.certificateOffset == 0U &&
						 layout.certificateSize == 0U) ;
	} ;
	constexpr std::size_t SECTION			 = OPTIONAL_OFFSET + 224U ;			// PE32 section table
	constexpr std::size_t SECURITY_DIRECTORY = OPTIONAL_OFFSET + 96U + 32U ;	// PE32 outer signature
	constexpr std::array<std::size_t, 19U> CORRUPT_OFFSETS{PE_OFFSET + 4U,
														   SECTION,
														   SECTION + 16U,
														   HEADERS_END,
														   HEADERS_END + 4U,
														   HEADERS_END + 24U,
														   HEADERS_END + 32U,
														   HEADERS_END + 36U,
														   HEADERS_END + 40U,
														   HEADERS_END + 44U,
														   HEADERS_END + 48U,
														   HEADERS_END + 52U,
														   SECURITY_DIRECTORY,
														   WIX_ENGINE_CERTIFICATE_OFFSET,
														   WIX_ENGINE_CERTIFICATE_OFFSET + 6U,
														   WIX_UX_OFFSET,
														   WIX_ATTACHED_OFFSET + 8U,
														   WIX_CERTIFICATE_OFFSET + 4U,
														   WIX_CERTIFICATE_OFFSET +
															   15U} ;	// 独立に壊す元field位置
	// 元境界、サイズ、種類を一箇所ずつ変え、契約が変形を取り込まないことを確認する
	for( const auto offset : CORRUPT_OFFSETS) {
		auto changed = fixture ;	// 対照ごとに元範囲から作る入力
		changed[offset] ^= std::byte{0x01} ;
		reject( changed) ;
	}

	// 二つの証明書の直前へ、それぞれ非ゼロのbyteを置く
	for( const auto offset :
		{WIX_UX_OFFSET + WIX_UX_BYTES, WIX_ATTACHED_OFFSET + WIX_ATTACHED_BYTES}) {
		auto changed	= fixture ;	// 独立した非ゼロ整列対照
		changed[offset] = std::byte{0x01} ;
		reject( changed) ;
	}

	auto shortHeader = fixture ;	// 元宣言のvirtual sizeを一byte短くする対照
	writeU32Le( shortHeader, SECTION + 8U, 55U) ;
	reject( shortHeader) ;
	auto duplicated = fixture ;	// 同名sectionの追加対照
	writeU16Le( duplicated, PE_OFFSET + 6U, 2U) ;
	std::copy_n( fixture.begin() + SECTION, 12U, duplicated.begin() + SECTION + 40U) ;
	reject( duplicated) ;
	auto truncated = fixture ;	// 末尾テーブルを切り詰める対照
	truncated.pop_back() ;
	reject( truncated) ;

	OfficialWixBurnLayout				  limited{} ;	// 上限拒否時の結果
	const OfficialWixBurnInspectionPolicy smallCabinet{4096U, WIX_ATTACHED_BYTES -
																  1U} ;	// 添付CABだけ上限超過
	const OfficialWixBurnInspectionPolicy smallFile{512U, 256U} ;		// 元EXEが上限超過
	DRIVERCRATE_EXPECT( context, inspectOfficialWixBurn( fixture, smallCabinet, limited) != 0U) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialWixBurn( fixture, smallFile, limited) != 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificateなし／ありの単一7z境界を比較する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testValidSfxLayout( TestContext &context)
{
	const std::vector<std::byte> unsignedFixture =
		// Certificateを持たない正常PE32 fixture
		makeValidFixture( false, false) ;
	OfficialSfxLayout unsignedLayout{} ;	// Certificateなしの識別結果
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( unsignedFixture, POLICY, unsignedLayout) == 0) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.archiveOffset == ARCHIVE_OFFSET) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.archiveSize == ARCHIVE_END - ARCHIVE_OFFSET) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.certificatePaddingSize == 0U) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.nextHeaderOffset == ARCHIVE_OFFSET + 32U) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.nextHeaderSize == NEXT_HEADER_SIZE) ;
	DRIVERCRATE_EXPECT( context, unsignedLayout.certificateOffset == 0U) ;
	auto olderVersion				  = unsignedFixture ;	// 同じ構造/CRCの7z 0.3表記です
	olderVersion[ARCHIVE_OFFSET + 7U] = std::byte{0x03} ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( olderVersion, POLICY, unsignedLayout) == 0) ;
	olderVersion[ARCHIVE_OFFSET + 7U] = std::byte{0x05} ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( olderVersion, POLICY, unsignedLayout) != 0) ;

	const std::vector<std::byte> signedFixture =
		// 最小certificate tableを持つ正常PE32+ fixture
		makeValidFixture( true, true) ;
	OfficialSfxLayout signedLayout{} ;	// Certificateありの識別結果
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( signedFixture, POLICY, signedLayout) == 0) ;
	DRIVERCRATE_EXPECT( context, signedLayout.certificateOffset == ARCHIVE_END) ;
	DRIVERCRATE_EXPECT( context, signedLayout.certificateSize == 8U) ;
	DRIVERCRATE_EXPECT( context, signedLayout.certificatePaddingSize == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificate tableを次の8-byte境界へ揃える2、3、7 bytesのzero paddingを受理し、archive範囲から分離する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testCertificateAlignmentPaddingAcceptance( TestContext &context)
{
	constexpr std::array<std::size_t, 3> PADDING_SIZES{2U, 3U, 7U} ;	// 実物を含む正常padding長
	// paddingSizeは現在検証するCertificate直前のzero byte数
	// 各padding長で7z範囲とCertificate table境界を独立に確認する
	for( const std::size_t paddingSize : PADDING_SIZES) {
		const std::vector<std::byte> fixture =
			// Zero padding付きPE32+ fixture
			makeValidFixture( true, true, paddingSize) ;
		OfficialSfxLayout layout{} ;	// 正常識別結果
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
 * @brief 非zero、8 bytes、Certificateなしtrailer、非aligned tableをfail-closedで拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testCertificateAlignmentPaddingRejection( TestContext &context)
{
	std::vector<std::byte> nonzeroPadding =
		// 三byte中の一byteを改ざんするfixture
		makeValidFixture( true, false, 3U) ;
	nonzeroPadding[ARCHIVE_END - 1U] = std::byte{0x01} ;
	OfficialSfxLayout layout{1U, 1U, 1U, 1U, 1U, 1U, 1U} ;	// 失敗時初期化確認用出力
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( nonzeroPadding, POLICY, layout) != 0) ;
	DRIVERCRATE_EXPECT( context, layout.archiveOffset == 0U) ;
	DRIVERCRATE_EXPECT( context, layout.certificatePaddingSize == 0U) ;

	std::vector<std::byte> oversizedPadding =
		// 正常Certificateを後方へ移す基準fixture
		makeValidFixture( true, false) ;
	constexpr std::size_t REJECTED_PADDING_SIZE = 8U ;	// 許可範囲を一byte越える間隔
	oversizedPadding.insert( oversizedPadding.begin() + ARCHIVE_END, REJECTED_PADDING_SIZE,
							std::byte{0x00}) ;
	constexpr std::size_t PE32_SECURITY_DIRECTORY_OFFSET =
		OPTIONAL_OFFSET + 96U + 4U * 8U ;	// PE32 Certificate data directory位置
	writeU32Le( oversizedPadding, PE32_SECURITY_DIRECTORY_OFFSET,
			   static_cast<std::uint32_t>( ARCHIVE_END + REJECTED_PADDING_SIZE)) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( oversizedPadding, POLICY, layout) != 0) ;

	std::vector<std::byte> unsignedTrailer =
		// Certificateなしの正常fixture
		makeValidFixture( false, false) ;
	unsignedTrailer.push_back( std::byte{0x00}) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( unsignedTrailer, POLICY, layout) != 0) ;

	std::vector<std::byte> misalignedCertificate =
		// Certificate offset改ざんfixture
		makeValidFixture( true, false, 3U) ;
	writeU32Le( misalignedCertificate, PE32_SECURITY_DIRECTORY_OFFSET,
			   static_cast<std::uint32_t>( ARCHIVE_END - 1U)) ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( misalignedCertificate, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 切詰め、Start Header CRC、Next Header CRC改ざんを拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testTruncationAndCrcRejection( TestContext &context)
{
	std::vector<std::byte> truncated = makeValidFixture( false, false) ;	// 末尾切詰めfixture
	truncated.pop_back() ;
	OfficialSfxLayout layout{1U, 1U, 1U, 1U, 1U, 1U, 1U} ;	// 失敗時初期化確認用出力
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( truncated, POLICY, layout) != 0) ;
	DRIVERCRATE_EXPECT( context, layout.archiveOffset == 0U) ;

	std::vector<std::byte> startCrc = makeValidFixture( false, false) ;	// Start CRC改ざんfixture
	startCrc[ARCHIVE_OFFSET + 8U] ^= std::byte{0x01} ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( startCrc, POLICY, layout) != 0) ;

	std::vector<std::byte> nextCrc = makeValidFixture( false, false) ;	// Next CRC改ざんfixture
	nextCrc[ARCHIVE_OFFSET + 28U] ^= std::byte{0x01} ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( nextCrc, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stub内に別の7z signatureを持つ曖昧な入力を拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testDuplicateSignatureRejection( TestContext &context)
{
	std::vector<std::byte> duplicate = makeValidFixture( false, false) ;	// 二signature fixture
	std::copy( SEVEN_ZIP_SIGNATURE.begin(), SEVEN_ZIP_SIGNATURE.end(),
			  duplicate.begin() + IMAGE_END + 8U) ;
	OfficialSfxLayout layout{} ;	// 失敗を期待する識別結果
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( duplicate, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stub／archive上限と64-bit Next Header offset超過を拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testLimitAndRangeRejection( TestContext &context)
{
	const std::vector<std::byte>	  fixture = makeValidFixture( false, false) ;	// 正常基準fixture
	const OfficialSfxInspectionPolicy shortStubPolicy{4096U, 16U,
													  1024U} ;	// 実fixtureのstub長より小さい上限
	OfficialSfxLayout				  layout{} ;				// 失敗を期待する識別結果
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( fixture, shortStubPolicy, layout) != 0) ;

	const OfficialSfxInspectionPolicy smallArchivePolicy{4096U, 512U,
														 39U} ;	// 40-byte archiveを拒否する上限
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSevenZipSfx( fixture, smallArchivePolicy, layout) != 0) ;

	std::vector<std::byte> overflowing =
		// Offset overflow fixture
		makeValidFixture( false, false) ;
	writeU64Le( overflowing, ARCHIVE_OFFSET + 12U, std::numeric_limits<std::uint64_t>::max()) ;
	refreshStartHeaderCrc( overflowing) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialSevenZipSfx( overflowing, POLICY, layout) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WiX元マニフェストでコンテナー、全MSIおよび英日規約の結合を検証する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testWixManifestBinding( TestContext &context)
{
	constexpr std::wstring_view XML =
		LR"wix(<BurnManifest xmlns="http://schemas.microsoft.com/wix/2008/Burn">
<UX>
<Payload Id="TermsEn" FilePath="1033\License.rtf" FileSize="41" Hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" Packaging="embedded" SourcePath="u0"/>
<Payload Id="TermsJa" FilePath="1041\License.rtf" FileSize="81" Hash="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" Packaging="embedded" SourcePath="u1"/>
</UX>
<Container Id="Attached" FileSize="3000" Hash="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" FilePath="demo.exe" AttachedIndex="1" Attached="yes" Primary="yes"/>
<Payload Id="Fixture64" FilePath="fixture64.msi" FileSize="1000" Hash="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" Packaging="embedded" SourcePath="a0" Container="Attached"/>
<Payload Id="Fixture32" FilePath="fixture32.msi" FileSize="800" Hash="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" Packaging="embedded" SourcePath="a1" Container="Attached"/>
<Chain DisableSystemRestore="yes">
<MsiPackage Id="Fixture64" Size="1000" InstallCondition="SelectFixture AND VersionNT64" Language="1033">
<MsiProperty Id="Unused" Value="DisplayOnly"/>
<PayloadRef Id="Fixture64"/>
</MsiPackage>
<MsiPackage Id="Fixture32" Size="800" InstallCondition="SelectFixture AND NOT VersionNT64" Language="1033">
<PayloadRef Id="Fixture32"/>
</MsiPackage>
</Chain>
</BurnManifest>)wix" ;	// 実行部を含まない架空WiXの元宣言
	constexpr std::array<OfficialWixMsiSelector, 2U> PACKAGES{
		{{{L"Fixture64", L"a0", L"fixture64.msi"},
		  L"SelectFixture AND VersionNT64",
		  OfficialWixMsiArchitecture::AMD64,
		  1033U},
		 {{L"Fixture32", L"a1", L"fixture32.msi"},
		  L"SelectFixture AND NOT VersionNT64",
		  OfficialWixMsiArchitecture::X86,
		  1033U}}} ;	// 元Chainの全順序を指定
	constexpr std::array<OfficialWixMemberSelector, 2U> LICENSES{
		{{L"TermsEn", L"u0", L"1033\\License.rtf"},
		 {L"TermsJa", L"u1", L"1041\\License.rtf"}}} ;	// 元の英語と日本語を独立した役割で照合
	OfficialWixManifest result ;						// 全検査が成立したときの宣言
	DRIVERCRATE_EXPECT( context, inspectOfficialWixManifest( XML, PACKAGES, LICENSES, result) == 0U) ;
	DRIVERCRATE_EXPECT( context, result.attachedCabinetBytes == 3000U &&
									result.attachedCabinetSha1 == std::wstring( 40U, L'c')) ;
	DRIVERCRATE_EXPECT( context, result.uxMembers.size() == 2U && result.msiMembers.size() == 2U &&
									result.licenseIndices == std::vector<std::size_t>( {0U, 1U})) ;
	// 件数検査と独立して、選択時に使う元名・サイズ・SHA-1を確認する
	if( result.msiMembers.size() == 2U) {
		DRIVERCRATE_EXPECT( context, result.msiMembers[0].filePath == L"fixture64.msi" &&
										result.msiMembers[0].bytes == 1000U &&
										result.msiMembers[0].sha1 == std::wstring( 40U, L'd')) ;
	}

	constexpr std::array<std::pair<std::wstring_view, std::wstring_view>, 19U> ALTERATIONS{{
		{L"http://schemas.microsoft.com/wix/2008/Burn", L"https://example.invalid/wix"},
		{L"<UX>", L"<UX><Payload xmlns=\"urn:other\"/>"},
		{L"<UX>", L"<UX><Override/>"},
		{L"AttachedIndex=\"1\"", L"AttachedIndex=\"2\""},
		{L"Attached=\"yes\"", L"Attached=\"no\""},
		{L"FileSize=\"3000\"", L"FileSize=\"03000\""},
		{L"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", L"invalid"},
		{L"SourcePath=\"u1\"", L"SourcePath=\"u0\""},
		{L"FilePath=\"1041\\License.rtf\"", L"FilePath=\"1033\\LICENSE.RTF\""},
		{L"FilePath=\"1033\\License.rtf\"", L"FilePath=\"..\\License.rtf\""},
		{L"Id=\"TermsJa\"", L"Id=\"DefaultTerms\""},
		{L"Container=\"Attached\"", L"Container=\"Another\""},
		{L"SourcePath=\"a0\"", L"SourcePath=\"a0\" DownloadUrl=\"https://example.invalid/file\""},
		{L"<MsiPackage Id=\"Fixture64\"", L"<MsiPackage Id=\"Fixture64\" Undeclared=\"x\""},
		{L"InstallCondition=\"SelectFixture AND VersionNT64\"",
		 L"InstallCondition=\"Other AND VersionNT64\""},
		{L"Language=\"1033\"", L"Language=\"1041\""},
		{L"Size=\"1000\" InstallCondition", L"Size=\"1001\" InstallCondition"},
		{L"<PayloadRef Id=\"Fixture64\"/>", L"<PayloadRef Id=\"Fixture32\"/>"},
		{L"<PayloadRef Id=\"Fixture32\"/>",
		 L"<PayloadRef Id=\"Fixture32\"/><PayloadRef Id=\"Fixture64\"/>"},
	}} ; // それぞれ独立に壊す元宣言
	// 過去の成功値を入れ直し、失敗のたびに全出力を破棄することを確認する
	for( const auto &[from, to] : ALTERATIONS) {
		std::wstring modified( XML) ;					// 元XMLから作る独立した対照
		const auto	 position = modified.find( from) ;	// 対照で変更する文字列の位置
		DRIVERCRATE_EXPECT( context, position != std::wstring::npos) ;
		// 対照の入力自体が不成立なら範囲外へ書き込まない
		if( position == std::wstring::npos) {
			continue ;
		}

		modified.replace( position, from.size(), to) ;
		result.attachedCabinetBytes = 1U ;
		DRIVERCRATE_EXPECT( context,
						   inspectOfficialWixManifest( modified, PACKAGES, LICENSES, result) != 0U) ;
		DRIVERCRATE_EXPECT( context, result.attachedCabinetBytes == 0U &&
										result.attachedCabinetSha1.empty() &&
										result.uxMembers.empty() && result.msiMembers.empty() &&
										result.licenseIndices.empty()) ;
	}

	auto reordered = PACKAGES ;	// 元Chainとは異なる順序
	std::swap( reordered[0], reordered[1]) ;
	DRIVERCRATE_EXPECT( context, inspectOfficialWixManifest( XML, reordered, LICENSES, result) != 0U) ;
	auto duplicateLicense = LICENSES ;	// 二言語に同じ元payloadを設定した対照
	duplicateLicense[1]	  = LICENSES[0] ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialWixManifest( XML, PACKAGES, duplicateLicense, result) != 0U) ;
	const auto dtd = std::wstring( L"<!DOCTYPE BurnManifest [<!ELEMENT BurnManifest ANY>]>")
						 .append( XML) ;	// DTD対照
	DRIVERCRATE_EXPECT( context, inspectOfficialWixManifest( dtd, PACKAGES, LICENSES, result) != 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定元取得の不一致と、構造だけ正しい未署名配布を通常検査が拒否することを確認する
 * @param[in,out] context 所有領域で実行した非通信試験の診断先
 */
//------------------------------------------------------------------------------
void testWixVerifiedSourceRejection( TestContext &context)
{
	const auto				  fixture = makeWixFixture( false) ;	// 構造検査だけを通る架空元ファイル
	OfficialDownloadWorkspace workspace ;							// 通常データと分離する試験ファイル所有領域
	const auto				  initialized =
		workspace.initialize( L"wix-trust-fixture", 854U,
							 OfficialWorkspaceMode::CURRENT_USER_INSPECTION) ;	// 初期化の診断
	DRIVERCRATE_EXPECT( context, initialized == 0U) ;
	// 所有領域が成立した場合だけ対照ファイルを作成する
	if( initialized != 0U) {
		return ;
	}

	constexpr std::wstring_view NAME = L"fixture.exe" ;							// 領域内に新規作成する架空ファイル名
	HANDLE						file{INVALID_HANDLE_VALUE} ;					// 保存が終わるまでのファイル所有handle
	const auto					created = workspace.createFile( NAME, file) ;	// CREATE_NEWの結果
	DRIVERCRATE_EXPECT( context, created == 0U) ;
	// 試験用byte列を開けなければ書き込まない
	if( created != 0U) {
		return ;
	}

	DWORD	   written{} ;	// 今回書き込んだ長さ
	const BOOL saved = WriteFile( file, fixture.data(), static_cast<DWORD>( fixture.size()), &written,
								 nullptr) ;							// 一回で架空ファイル全体を保存する
	const BOOL closed		= CloseHandle( file) ;					// 後続の読取り固定へ渡す前に書込みを閉じる
	const std::wstring path = workspace.path( NAME) ;				// 取得後検査と同じ所有領域の絶対path
	std::wstring	   digest ;										// 架空ファイル全体を固定したSHA-256
	const auto		   hashed = computeFileSha256( path, digest) ;	// 試験元のhash結果
	DRIVERCRATE_EXPECT( context, saved && closed && written == fixture.size() && hashed == 0U) ;
	// 固定元を正しく作れたときだけ拒否理由を照合する
	if( !saved || !closed || written != fixture.size() || hashed != 0U) {
		return ;
	}

	constexpr std::array<std::wstring_view, 1U> PUBLISHERS{
		L"Fixture Publisher"} ;	// 許可した架空署名者
	OfficialSignedExecutableSource source{path, fixture.size() + 1U, digest, PUBLISHERS,
										  true} ;	// 元長の不一致
	OfficialMappedFile			   mapping ;		// どの拒否でも出力に残さない固定入力owner
	OfficialWixBurnLayout		   layout ;			// 拒否時に空へ戻る範囲
	layout.uxCabinetSize = 1U ;
	DRIVERCRATE_EXPECT( context, openVerifiedOfficialWixBurn( source, WIX_POLICY, mapping, layout) ==
									static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
	DRIVERCRATE_EXPECT( context, mapping.bytes().empty() && layout.uxCabinetSize == 0U) ;

	source.expectedBytes  = fixture.size() ;
	std::wstring changed  = digest ;	// 元ファイルを変えず、期待SHA-256だけを差し替える
	changed.front()		  = changed.front() == L'0' ? L'1' : L'0' ;
	source.expectedSha256 = changed ;
	DRIVERCRATE_EXPECT( context, openVerifiedOfficialWixBurn( source, WIX_POLICY, mapping, layout) ==
									static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
	DRIVERCRATE_EXPECT( context, mapping.bytes().empty() && layout.certificateSize == 0U) ;

	source.expectedSha256 = digest ;
	DRIVERCRATE_EXPECT( context,
					   openVerifiedOfficialWixBurn( source, WIX_POLICY, mapping, layout) != 0U) ;
	DRIVERCRATE_EXPECT( context, mapping.bytes().empty() && layout.attachedCabinetSize == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP reference基準の両方式と二種類のdescriptorを元byte位置に照合する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testValidSignedPeZipLayout( TestContext &context)
{
	// ZIP先頭基準とPE先頭基準で同じ物理範囲を取得できることを確認する
	for( const bool fromExecutable : {false, true}) {
		// Descriptorなし、署名値なし、署名値ありを同じ両基準で受理する
		for( const std::uint32_t descriptorBytes : {0U, 12U, 16U}) {
			const auto fixture =
				// 正常構造
				makeSignedPeZipFixture( fromExecutable, descriptorBytes) ;
			const auto archiveEnd = PE_ZIP_ARCHIVE_END + descriptorBytes ;	// 整列を含まないZIP末尾
			OfficialSignedPeZipLayout layout{} ;							// 元byte位置に照合する出力
			DRIVERCRATE_EXPECT( context,
							   inspectOfficialSignedPeZip( fixture, PE_ZIP_POLICY, layout) == 0U) ;
			DRIVERCRATE_EXPECT( context, layout.archiveOffset == PE_ZIP_OFFSET) ;
			DRIVERCRATE_EXPECT( context, layout.archiveSize == archiveEnd - PE_ZIP_OFFSET) ;
			DRIVERCRATE_EXPECT( context, layout.certificateOffset == ((archiveEnd + 7U) & ~7U)) ;
			DRIVERCRATE_EXPECT( context, layout.certificateSize == PE_ZIP_CERTIFICATE_BYTES) ;
			DRIVERCRATE_EXPECT( context, layout.offsetsFromExecutableStart == fromExecutable) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP構造の拒否理由を試験名で識別し、失敗時に以前の範囲が残らないことを確認する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 * @param[in] fixture 呼出し中だけ借用する人工PE全体
 * @param[in] scenario 失敗出力で識別する構造条件
 * @param[in] policy このケースに適用する有限上限
 */
//------------------------------------------------------------------------------
void expectSignedPeZipRejection( TestContext &context, const std::span<const std::byte> fixture,
								const std::string_view					   scenario,
								const OfficialSignedPeZipInspectionPolicy &policy = PE_ZIP_POLICY)
{
	OfficialSignedPeZipLayout layout{1U, 1U, 1U, 1U, true} ;	// 前回成功を模した出力の初期値
	context.expect( inspectOfficialSignedPeZip( fixture, policy, layout) != 0U, scenario, __FILE__,
				   __LINE__) ;
	context.expect( layout.archiveOffset == 0U && layout.archiveSize == 0U &&
					   layout.certificateOffset == 0U && layout.certificateSize == 0U &&
					   !layout.offsetsFromExecutableStart,
				   scenario, __FILE__, __LINE__) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元証明書、ZIP末尾、central宣言と検査上限の負例を確認する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testSignedPeZipEndRejection( TestContext &context)
{
	const auto valid   = makeSignedPeZipFixture( true) ;	// 各境界を独立に変える基準
	auto	   variant = valid ;							// 各試験で元の正常構造へ戻してから変更するPE
	writeU32Le( variant, PE_ZIP_SECURITY_DIRECTORY, 0U) ;
	writeU32Le( variant, PE_ZIP_SECURITY_DIRECTORY + 4U, 0U) ;
	variant.resize( PE_ZIP_ARCHIVE_END) ;
	expectSignedPeZipRejection( context, variant, "ZIP requires a certificate table") ;

	variant = valid ;
	writeU32Le( variant, PE_ZIP_CERTIFICATE_OFFSET, PE_ZIP_CERTIFICATE_BYTES + 1U) ;
	expectSignedPeZipRejection( context, variant, "Certificate entry exceeds its table") ;

	variant					   = valid ;
	variant[PE_ZIP_END_OFFSET] = std::byte{} ;
	expectSignedPeZipRejection( context, variant, "EOCD signature must match") ;

	variant						= valid ;
	variant[PE_ZIP_ARCHIVE_END] = std::byte{1} ;
	expectSignedPeZipRejection( context, variant, "ZIP alignment must contain only zero bytes") ;

	variant = valid ;
	variant.insert( variant.begin() + PE_ZIP_CERTIFICATE_OFFSET, 8U, std::byte{}) ;
	writeU32Le( variant, PE_ZIP_SECURITY_DIRECTORY, PE_ZIP_CERTIFICATE_OFFSET + 8U) ;
	expectSignedPeZipRejection( context, variant,
							   "ZIP alignment must be the minimum number of bytes") ;

	variant = valid ;
	writeU16Le( variant, PE_ZIP_END_OFFSET + 20U,
			   static_cast<std::uint16_t>( PE_ZIP_CERTIFICATE_OFFSET - PE_ZIP_END_OFFSET -
										  PE_ZIP_END_BYTES + 1U)) ;
	expectSignedPeZipRejection( context, variant, "ZIP comment may not cross into the certificate") ;

	variant = valid ;
	writeU32Le( variant, PE_ZIP_END_OFFSET + 12U, 2U * PE_ZIP_CENTRAL_RECORD_BYTES + 1U) ;
	expectSignedPeZipRejection( context, variant,
							   "Central directory cannot extend across its declared end") ;

	variant = valid ;
	writeU16Le( variant, PE_ZIP_END_OFFSET + 4U, 1U) ;
	expectSignedPeZipRejection( context, variant, "Split archive declarations are rejected") ;

	constexpr std::uint16_t APPENDED_COMMENT_BYTES = 24U ;	// 整列を保つ末尾コメントの追加長
	variant										   = valid ;
	variant.insert( variant.begin() + PE_ZIP_ARCHIVE_END, APPENDED_COMMENT_BYTES, std::byte{}) ;
	writeU32Le( variant, PE_ZIP_SECURITY_DIRECTORY,
			   PE_ZIP_CERTIFICATE_OFFSET + APPENDED_COMMENT_BYTES) ;
	writeU16Le( variant, PE_ZIP_END_OFFSET + 20U, PE_ZIP_COMMENT_BYTES + APPENDED_COMMENT_BYTES) ;
	writeU32Le( variant, PE_ZIP_ARCHIVE_END + APPENDED_COMMENT_BYTES - PE_ZIP_END_BYTES,
			   PE_ZIP_END_SIGNATURE) ;
	expectSignedPeZipRejection( context, variant,
							   "ZIP reader must not choose another end record in the comment") ;

	constexpr std::uint16_t CENTRAL_COMMENT_BYTES = 24U ;	// 最終中央エントリの追加コメント長
	constexpr std::uint32_t NEW_END_OFFSET =
		PE_ZIP_END_OFFSET + CENTRAL_COMMENT_BYTES ;					// 移動後の終端
	constexpr std::uint32_t ZIP64_LOCATOR_BYTES		= 20U ;			// ZIP64終端参照の固定長
	constexpr std::uint32_t ZIP64_LOCATOR_SIGNATURE = 0x07064b50U ;	// ZIP64終端参照の識別子
	variant											= valid ;
	variant.insert( variant.begin() + PE_ZIP_END_OFFSET, CENTRAL_COMMENT_BYTES, std::byte{}) ;
	writeU16Le( variant, PE_ZIP_CENTRAL_OFFSET + PE_ZIP_CENTRAL_RECORD_BYTES + 32U,
			   CENTRAL_COMMENT_BYTES) ;
	writeU32Le( variant, NEW_END_OFFSET + 12U,
			   2U * PE_ZIP_CENTRAL_RECORD_BYTES + CENTRAL_COMMENT_BYTES) ;
	writeU32Le( variant, PE_ZIP_SECURITY_DIRECTORY,
			   PE_ZIP_CERTIFICATE_OFFSET + CENTRAL_COMMENT_BYTES) ;
	writeU32Le( variant, NEW_END_OFFSET - ZIP64_LOCATOR_BYTES, ZIP64_LOCATOR_SIGNATURE) ;
	expectSignedPeZipRejection( context, variant,
							   "ZIP64 locator cannot select a different directory") ;

	expectSignedPeZipRejection( context, valid, "Executable size exceeds policy",
							   {valid.size() - 1U, PE_ZIP_POLICY.maximumEntryCount}) ;
	expectSignedPeZipRejection( context, valid, "Entry count exceeds policy",
							   {PE_ZIP_POLICY.maximumExecutableBytes, 1U}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Centralから参照するlocal header、本体とdescriptorの越境や不一致を確認する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testSignedPeZipEntryRejection( TestContext &context)
{
	const auto	   valid = makeSignedPeZipFixture( true) ;	// 各参照を独立に変える基準
	constexpr auto SECOND_CENTRAL =
		PE_ZIP_CENTRAL_OFFSET + PE_ZIP_CENTRAL_RECORD_BYTES ;					// 二件目central位置
	constexpr auto SECOND_LOCAL = PE_ZIP_OFFSET + PE_ZIP_LOCAL_RECORD_BYTES ;	// 二件目local位置
	auto		   variant		= valid ;										// 各試験で元の正常構造へ戻してから変更するPE
	writeU32Le( variant, SECOND_CENTRAL + 42U, PE_ZIP_LOCAL_RECORD_BYTES) ;
	expectSignedPeZipRejection( context, variant, "One ZIP cannot mix the two offset bases") ;

	variant = valid ;
	writeU32Le( variant, PE_ZIP_CENTRAL_OFFSET + 42U, static_cast<std::uint32_t>( HEADERS_END)) ;
	expectSignedPeZipRejection( context, variant,
							   "Local header reference may not target a PE section") ;

	variant = valid ;
	writeU32Le( variant, PE_ZIP_CENTRAL_OFFSET + 42U, PE_ZIP_CERTIFICATE_OFFSET) ;
	expectSignedPeZipRejection( context, variant,
							   "Local header reference may not target the certificate") ;

	variant = valid ;
	writeU32Le( variant, SECOND_LOCAL + 18U, PE_ZIP_DATA_BYTES + 1U) ;
	writeU32Le( variant, SECOND_LOCAL + 22U, PE_ZIP_DATA_BYTES + 1U) ;
	writeU32Le( variant, SECOND_CENTRAL + 20U, PE_ZIP_DATA_BYTES + 1U) ;
	writeU32Le( variant, SECOND_CENTRAL + 24U, PE_ZIP_DATA_BYTES + 1U) ;
	expectSignedPeZipRejection( context, variant,
							   "Local entry data may not reach into the central directory") ;

	variant = valid ;
	writeU16Le( variant, SECOND_LOCAL + 10U, 1U) ;
	writeU16Le( variant, SECOND_CENTRAL + 12U, 1U) ;
	writeU32Le( variant, SECOND_LOCAL + 22U, PE_ZIP_DATA_BYTES + 1U) ;
	writeU32Le( variant, SECOND_CENTRAL + 24U, PE_ZIP_DATA_BYTES + 1U) ;
	expectSignedPeZipRejection( context, variant,
							   "Stored compressed and extracted sizes must agree") ;

	variant = valid ;
	variant.erase( variant.begin() + PE_ZIP_CENTRAL_OFFSET - PE_ZIP_DATA_BYTES,
				  variant.begin() + PE_ZIP_CENTRAL_OFFSET) ;
	variant.insert( variant.begin() + PE_ZIP_END_OFFSET - PE_ZIP_DATA_BYTES, PE_ZIP_DATA_BYTES,
				   std::byte{}) ;
	constexpr auto EMPTY_CENTRAL = SECOND_CENTRAL - PE_ZIP_DATA_BYTES ;	// 本体を除いた二件目中央位置
	writeU32Le( variant, SECOND_LOCAL + 14U, 0U) ;
	writeU32Le( variant, SECOND_LOCAL + 18U, 0U) ;
	writeU32Le( variant, SECOND_LOCAL + 22U, 0U) ;
	writeU32Le( variant, EMPTY_CENTRAL + 16U, 0U) ;
	writeU32Le( variant, EMPTY_CENTRAL + 20U, 0U) ;
	writeU32Le( variant, EMPTY_CENTRAL + 24U, 0U) ;
	writeU16Le( variant, EMPTY_CENTRAL + 32U, static_cast<std::uint16_t>( PE_ZIP_DATA_BYTES)) ;
	writeU32Le( variant, PE_ZIP_END_OFFSET + 12U,
			   2U * PE_ZIP_CENTRAL_RECORD_BYTES + PE_ZIP_DATA_BYTES) ;
	writeU32Le( variant, PE_ZIP_END_OFFSET + 16U, PE_ZIP_CENTRAL_OFFSET - PE_ZIP_DATA_BYTES) ;
	OfficialSignedPeZipLayout emptyLayout{} ;	// 正しい空エントリを受理した場合の元ZIP範囲
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialSignedPeZip( variant, PE_ZIP_POLICY, emptyLayout) == 0U) ;
	writeU32Le( variant, SECOND_LOCAL + 14U, 1U) ;
	writeU32Le( variant, EMPTY_CENTRAL + 16U, 1U) ;
	expectSignedPeZipRejection( context, variant, "Empty entry must carry the CRC of zero bytes") ;

	variant										= valid ;
	variant[PE_ZIP_OFFSET + PE_ZIP_LOCAL_BYTES] = std::byte{'x'} ;
	expectSignedPeZipRejection( context, variant, "Local name must match its central name") ;

	variant = valid ;
	writeU16Le( variant, PE_ZIP_OFFSET + 26U, static_cast<std::uint16_t>( PE_ZIP_NAME_BYTES + 1U)) ;
	expectSignedPeZipRejection( context, variant,
							   "Local name length must match its central name length") ;

	variant = valid ;
	writeU32Le( variant, SECOND_CENTRAL + 42U, PE_ZIP_OFFSET) ;
	variant[SECOND_CENTRAL + PE_ZIP_CENTRAL_BYTES] = PE_ZIP_NAME.front() ;
	expectSignedPeZipRejection( context, variant,
							   "Two central entries cannot reference the same local record") ;

	variant							  = valid ;
	constexpr auto OVERLAP_DATA_BYTES = PE_ZIP_DATA_BYTES + 1U ;	// 二件目の先頭を1 byte含む長さ
	const auto	   overlappingData	  = std::span<const std::byte>( variant).subspan(
		   PE_ZIP_OFFSET + PE_ZIP_LOCAL_BYTES + PE_ZIP_NAME_BYTES,
		   OVERLAP_DATA_BYTES) ;									// 改変後のdata範囲
	const auto overlappingCrc = calculateCrc32( overlappingData) ;	// 重なり以外は整合させるCRC
	writeU32Le( variant, PE_ZIP_OFFSET + 14U, overlappingCrc) ;
	writeU32Le( variant, PE_ZIP_OFFSET + 18U, OVERLAP_DATA_BYTES) ;
	writeU32Le( variant, PE_ZIP_OFFSET + 22U, OVERLAP_DATA_BYTES) ;
	writeU32Le( variant, PE_ZIP_CENTRAL_OFFSET + 16U, overlappingCrc) ;
	writeU32Le( variant, PE_ZIP_CENTRAL_OFFSET + 20U, OVERLAP_DATA_BYTES) ;
	writeU32Le( variant, PE_ZIP_CENTRAL_OFFSET + 24U, OVERLAP_DATA_BYTES) ;
	expectSignedPeZipRejection( context, variant,
							   "A local payload cannot overlap the next local header") ;

	variant = makeSignedPeZipFixture( false, 16U) ;
	writeU32Le( variant, SECOND_LOCAL + 8U, PE_ZIP_DATA_BYTES + 1U) ;
	expectSignedPeZipRejection( context, variant,
							   "Descriptor size must agree with the central entry") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元長、SHA-256または主署名が不成立なら内側ZIPを返さないことを確認する
 * @param[in,out] context 非通信試験の診断と成否の集計先
 */
//------------------------------------------------------------------------------
void testVerifiedSignedPeZipRejection( TestContext &context)
{
	const auto fixture = makeSignedPeZipFixture( false) ;	// 構造は正しく署名が架空のEXE
	OfficialDownloadWorkspace workspace ;					// 実行終了時に試験ファイルを回収する所有領域
	const auto				  initialized =
		workspace.initialize( L"pe-zip-trust-fixture", 854U,
							 OfficialWorkspaceMode::CURRENT_USER_INSPECTION) ;	// 領域作成の診断
	DRIVERCRATE_EXPECT( context, initialized == 0U) ;
	// 所有領域が作成できた場合だけ試験ファイルを保存する
	if( initialized != 0U) {
		return ;
	}

	constexpr std::wstring_view NAME = L"fixture.exe" ;			// 所有領域の架空ファイル名
	HANDLE	   file{INVALID_HANDLE_VALUE} ;						// 書込み完了まで所有する元ファイルのhandle
	const auto created = workspace.createFile( NAME, file) ;	// 既存ファイルを開かない新規作成結果
	DRIVERCRATE_EXPECT( context, created == 0U) ;
	// 開けなかったファイルへ書込みや信頼確認を行わない
	if( created != 0U) {
		return ;
	}

	DWORD	   written{} ;	// 書き込んだ長さの確認値
	const BOOL saved = WriteFile( file, fixture.data(), static_cast<DWORD>( fixture.size()), &written,
								 nullptr) ;						// 架空ファイル全体を保存
	const BOOL closed = CloseHandle( file) ;					// 次の読取り固定を妨げないよう書込みを閉じる
	const auto path	  = workspace.path( NAME) ;					// 同じファイルを再読取りする正規位置
	std::wstring digest ;										// 架空原本全体の期待SHA-256
	const auto	 hashed = computeFileSha256( path, digest) ;	// 原ハッシュの取得結果
	DRIVERCRATE_EXPECT( context, saved && closed && written == fixture.size() && hashed == 0U) ;
	// 試験入力の保存が不完全なら独立した拒否理由を判定できない
	if( !saved || !closed || written != fixture.size() || hashed != 0U) {
		return ;
	}

	constexpr std::array<std::wstring_view, 1U> PUBLISHERS{
		L"Fixture Publisher"} ;												// 架空の許可署名者
	constexpr OfficialZipExtractionPolicy LIMITS{4096U, 256U, 512U, 2U} ;	// 架空ZIP全体の上限
	OfficialSignedExecutableSource		  source{path, fixture.size() + 1U, digest, PUBLISHERS,
											 true} ;	// 元長不一致
	std::vector<std::byte>				  innerZip{
		   std::byte{1}} ;	// 失敗ごとに以前の内容を破棄したことを確認する出力
	DRIVERCRATE_EXPECT( context,
					   readVerifiedOfficialSignedPeZipMember( source, LIMITS, L"a.zip", innerZip) ==
							   static_cast<NativeError>( TRUST_E_BAD_DIGEST) &&
						   innerZip.empty()) ;

	source.expectedBytes  = fixture.size() ;
	auto changed		  = digest ;	// 元ファイルを変えず期待ハッシュだけを変更する対照
	changed.front()		  = changed.front() == L'0' ? L'1' : L'0' ;
	source.expectedSha256 = changed ;
	innerZip.push_back( std::byte{1}) ;
	DRIVERCRATE_EXPECT( context,
					   readVerifiedOfficialSignedPeZipMember( source, LIMITS, L"a.zip", innerZip) ==
							   static_cast<NativeError>( TRUST_E_BAD_DIGEST) &&
						   innerZip.empty()) ;

	source.expectedSha256 = digest ;
	innerZip.push_back( std::byte{1}) ;
	DRIVERCRATE_EXPECT(
		context, readVerifiedOfficialSignedPeZipMember( source, LIMITS, L"a.zip", innerZip) != 0U &&
					 innerZip.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有用途・対象OS・選択形式・取消しを元ファイル取得前に確認する
 * @param[in,out] context ファイルや通信を使わない事前拒否試験の集計先
 */
//------------------------------------------------------------------------------
void testCollectorSignedPeZipRequestBoundary( TestContext &context)
{
	DriverArchiveInput input ;	// 空のpathにより元ファイルへ進んだ場合も試験用データを読み取らない
	input.scanSessionId = 1U ;
	constexpr OfficialInfModelsPlatform			SERVER{.buildNumber = 14393U,
													   .productType = 3U} ;	// Server x64観測点
	constexpr OfficialInfModelsPlatform			CLIENT{.buildNumber =
												   19045U} ;						// 同majorでも私有Server用途外
	constexpr std::array<std::wstring_view, 1U> PUBLISHERS{L"Fixture Publisher"} ;	// 架空の元署名者
	CollectorSignedPeZipContent result ;											// 失敗時に前回結果を残さないことを確認する出力
	result.executableBytes = 1U ;
	DRIVERCRATE_EXPECT( context, inspectCollectorSignedPeZipContent( input, PUBLISHERS, L"inner.zip",
																   L"driver.inf", SERVER,
																   result) == E_INVALIDARG &&
									result.executableBytes == 0U) ;

	input.workspaceMode = OfficialWorkspaceMode::CURRENT_USER_INSPECTION ;
	DRIVERCRATE_EXPECT( context, inspectCollectorSignedPeZipContent( input, PUBLISHERS, L"inner.zip",
																   L"driver.inf", CLIENT,
																   result) == E_INVALIDARG) ;
	DRIVERCRATE_EXPECT( context, inspectCollectorSignedPeZipContent( input, PUBLISHERS, L"inner.cab",
																   L"driver.inf", SERVER,
																   result) == E_INVALIDARG) ;
	DRIVERCRATE_EXPECT( context, inspectCollectorSignedPeZipContent( input, PUBLISHERS, L"inner.zip",
																   L"driver.sys", SERVER,
																   result) == E_INVALIDARG) ;

	result.zipMember = L"old.zip" ;
	// 開始前から取り消された操作を、元ファイルの失敗へ置き換えない
	DRIVERCRATE_EXPECT( context, inspectCollectorSignedPeZipContent(
									input, PUBLISHERS, L"inner.zip", L"driver.inf", SERVER, result,
									[] { return true ; }) == HRESULT_FROM_WIN32( ERROR_CANCELLED) &&
									result.zipMember.empty() && result.inner.infs.empty() &&
									result.identity.models.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 小さい架空NSISブロックを元書庫へ追加する
 * @param[in,out] fixture ブロックを末尾に追加する架空書庫
 * @param[in] bytes 架空記録の内容。65535バイト以下
 * @param[in] deflated trueなら無圧縮コードのraw Deflate、falseならNSIS側stored
 */
//------------------------------------------------------------------------------
void appendNsisFixtureBlock( std::vector<std::byte> &fixture, const std::span<const std::byte> bytes,
							const bool deflated)
{
	const auto tagOffset = fixture.size() ;								// 書き込む長さタグの位置
	const auto tagBytes	 = static_cast<std::uint32_t>( bytes.size()) ;	// 短い架空内容の元長
	fixture.resize( tagOffset + 4U) ;
	writeU32Le( fixture, tagOffset, deflated ? (0x80000000U | (tagBytes + 5U)) : tagBytes) ;
	// 圧縮ブロックは展開ライブラリに依存せず、末尾の非圧縮Deflate構文を作る
	if( deflated) {
		fixture.resize( tagOffset + 9U) ;
		fixture[tagOffset + 4U] = std::byte{0x01} ;
		writeU16Le( fixture, tagOffset + 5U, static_cast<std::uint16_t>( tagBytes)) ;
		writeU16Le( fixture, tagOffset + 7U, static_cast<std::uint16_t>( ~tagBytes)) ;
	}

	fixture.insert( fixture.end(), bytes.begin(), bytes.end()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ルートとx64の二対象に加え、x86の同名を持つ架空NSISを組み立てる
 * @param[in] alias x86レコードもx64の物理ブロックを参照する場合true
 * @param[in] changedCase x64レコードの元名の先頭を大文字にした場合true
 * @param[in] changedMedia x64レコードを別媒体の元ブロックへ向けた場合true
 * @return CRCまで整合する署名のない架空NSIS付きPE32
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> makeReviewedNsisFixture( const bool alias		 = false,
															 const bool changedCase	 = false,
															 const bool changedMedia = false)
{
	constexpr std::size_t COMMANDS		= 68U ;								// 架空元ヘッダー内の命令表の先頭
	constexpr std::size_t COMMAND_BYTES = 28U ;								// 一命令の幅
	constexpr std::size_t STRING_OFFSET = COMMANDS + 6U * COMMAND_BYTES ;	// 命令表直後の文字列表
	constexpr char		  STRINGS[]		= "\xfd\x95\x80\0"
										  "\xfd\x95\x80\\x64\0"
										  "\xfd\x95\x80\\x86\0"
										  "driver.inf\0"
										  "component.sys" ;	// 元パス3件と架空ファイル名2件
	constexpr std::string_view SIGNATURE{"\xef\xbe\xad\xde"
										 "NullsoftInst"} ;							// 架空先頭宣言の形式識別
	constexpr std::array   ROOT{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}} ;	// ルートの架空内容
	constexpr std::array   AMD64{std::byte{'x'}, std::byte{'y'}, std::byte{'z'}} ;	// x64の架空内容
	constexpr std::array   X86{std::byte{'o'}, std::byte{'l'}, std::byte{'d'}} ;	// x86のstored内容
	std::vector<std::byte> header( STRING_OFFSET + sizeof( STRINGS)) ;				// 架空の展開ヘッダー
	writeU32Le( header, 20U, COMMANDS) ;
	writeU32Le( header, 24U, 6U) ;
	writeU32Le( header, 28U, STRING_OFFSET) ;
	writeU32Le( header, 36U, static_cast<std::uint32_t>( header.size())) ;
	std::ranges::copy( std::as_bytes( std::span( STRINGS)), header.begin() + STRING_OFFSET) ;
	constexpr std::uint32_t COMPONENT_NAME = 31U ;	// 文字列表内の同名の先頭
	// 正しい位置と長さのまま、元大文字小文字だけ変えた対照を作る
	if( changedCase) {
		header[STRING_OFFSET + COMPONENT_NAME] = std::byte{'C'} ;
	}

	constexpr std::array<std::uint32_t, 3U> DIRECTORY_NAMES{0U, 4U,
															12U} ;	// 元ディレクトリの文字列位置
	constexpr std::array<std::uint32_t, 3U> FILE_NAMES{20U, COMPONENT_NAME,
													   COMPONENT_NAME} ;	// 元ファイル名の文字列位置
	const std::array<std::uint32_t, 3U>		BLOCK_OFFSETS{0U, changedMedia ? 24U : 12U,
													  alias ? 12U : 24U} ;	// 元物理タグへの参照
	// ルート、x64、x86の順に出力先記録と元抽出記録の対を作る
	for( std::size_t index = 0U; index < DIRECTORY_NAMES.size(); ++index) {
		const auto directory = COMMANDS + index * 2U * COMMAND_BYTES ;	// 出力先記録
		const auto file		 = directory + COMMAND_BYTES ;				// 同じ出力先にある元ファイル記録
		writeU32Le( header, directory, 11U) ;
		writeU32Le( header, directory + 4U, DIRECTORY_NAMES[index]) ;
		writeU32Le( header, directory + 8U, 1U) ;
		writeU32Le( header, file, 20U) ;
		writeU32Le( header, file + 8U, FILE_NAMES[index]) ;
		writeU32Le( header, file + 12U, BLOCK_OFFSETS[index]) ;
	}

	auto fixture = makeValidFixture( false, false) ;	// PE32の構造だけ流用する架空元書庫
	fixture.resize( IMAGE_END + 28U) ;
	std::ranges::copy( std::as_bytes( std::span( SIGNATURE)), fixture.begin() + IMAGE_END + 4U) ;
	writeU32Le( fixture, IMAGE_END + 20U, static_cast<std::uint32_t>( header.size())) ;
	appendNsisFixtureBlock( fixture, header, true) ;
	appendNsisFixtureBlock( fixture, ROOT, true) ;
	appendNsisFixtureBlock( fixture, AMD64, true) ;
	appendNsisFixtureBlock( fixture, X86, false) ;
	const auto footer = fixture.size() ;	// CRCの直前までの架空元EXE終端
	fixture.resize( footer + 4U) ;
	writeU32Le( fixture, IMAGE_END + 24U, static_cast<std::uint32_t>( fixture.size() - IMAGE_END)) ;
	writeU32Le( fixture, footer,
			   calculateCrc32( std::span<const std::byte>( fixture).subspan( 512U, footer - 512U))) ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査NSISの正例と改変時の全件破棄を検証する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testReviewedNsisMembers( TestContext &context)
{
	constexpr std::wstring_view ROOT_SHA =
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// abcのSHA-256
	constexpr std::wstring_view AMD64_SHA =
		L"3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282" ;	// xyzのSHA-256
	constexpr std::array members{
		OfficialReviewedNsisMember{L"driver.inf", 0U, 1U, 0U, 3U, ROOT_SHA},
		OfficialReviewedNsisMember{L"x64\\component.sys", 2U, 3U, 12U, 3U,
								   AMD64_SHA}} ;		// 架空審査定義
	const auto executable = makeReviewedNsisFixture() ;	// 既定の正例
	const auto hash		  = []( const std::vector<std::byte> &bytes) {
		  std::wstring digest ;	// 同じ架空元EXEに対する審査ハッシュ
		  // byte列を文字コード変換せず借りて、対照ごとに審査ハッシュを計算する
		  static_cast<void>( computeDriverContainerSha256(
			  {reinterpret_cast<const char *>( bytes.data()), bytes.size()}, digest)) ;
		  return digest ;
	} ; // 何もcaptureせず、引数のバイトを呼出し中だけ借用する
	const auto					 pinned = hash( executable) ;	// 正例の審査ハッシュ
	std::vector<OfficialZipFile> files ;						// 全件一致した場合だけ返される選択ファイル
	DRIVERCRATE_EXPECT( context, pinned.size() == 64U) ;
	DRIVERCRATE_EXPECT( context,
					   readOfficialReviewedNsisMembers( executable, pinned, members, files) == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   files.size() == 2U && files[0].relativePath == members[0].relativePath &&
						   files[1].relativePath == members[1].relativePath &&
						   hash( files[0].bytes) == ROOT_SHA && hash( files[1].bytes) == AMD64_SHA) ;

	auto damaged = executable ;	// 同じ元位置にある終端CRCを改変した対照
	damaged.back() ^= std::byte{0x01} ;
	DRIVERCRATE_EXPECT( context,
					   readOfficialReviewedNsisMembers( damaged, pinned, members, files) != 0U &&
						   files.empty()) ;
	DRIVERCRATE_EXPECT(
		context, readOfficialReviewedNsisMembers( damaged, hash( damaged), members, files) != 0U &&
					 files.empty()) ;
	damaged = executable ;
	damaged.pop_back() ;
	DRIVERCRATE_EXPECT(
		context, readOfficialReviewedNsisMembers( damaged, hash( damaged), members, files) != 0U &&
					 files.empty()) ;
	damaged = executable ;
	damaged.push_back( std::byte{0}) ;
	DRIVERCRATE_EXPECT(
		context, readOfficialReviewedNsisMembers( damaged, hash( damaged), members, files) != 0U &&
					 files.empty()) ;

	const std::array wrongRecord{makeReviewedNsisFixture( true),
								 makeReviewedNsisFixture( false, true),
								 // 二重参照、大小差、別媒体の対照
								 makeReviewedNsisFixture( false, false, true)} ;
	// 他の元条件も一致するようハッシュを与え直し、書庫構造で拒否することを確認する
	for( const auto &variant : wrongRecord) {
		DRIVERCRATE_EXPECT( context, readOfficialReviewedNsisMembers( variant, hash( variant), members,
																	files) != 0U &&
										files.empty()) ;
	}

	auto recipe = members ;	// 2件目だけの審査条件を順に置き換える対照
	recipe[1].dataOffset += 1U ;
	DRIVERCRATE_EXPECT( context,
					   readOfficialReviewedNsisMembers( executable, pinned, recipe, files) != 0U &&
						   files.empty()) ;
	recipe = members ;
	recipe[1].expandedBytes -= 1U ;
	DRIVERCRATE_EXPECT( context,
					   readOfficialReviewedNsisMembers( executable, pinned, recipe, files) != 0U &&
						   files.empty()) ;
	recipe			 = members ;
	recipe[1].sha256 = ROOT_SHA ;
	DRIVERCRATE_EXPECT( context,
					   readOfficialReviewedNsisMembers( executable, pinned, recipe, files) != 0U &&
						   files.empty()) ;
	recipe[1] = recipe[0] ;
	DRIVERCRATE_EXPECT( context,
					   readOfficialReviewedNsisMembers( executable, pinned, recipe, files) != 0U &&
						   files.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元受領記録の異なる版や別用途を元ZIPを開く前に拒否する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void testReviewedNsisZipInput( TestContext &context)
{
	constexpr std::wstring_view SHA =
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// 架空の元ハッシュ
	constexpr std::array members{
		OfficialReviewedNsisMember{L"driver.inf", 0U, 1U, 0U, 3U, SHA}} ;				// 元EXE内の架空選択
	const OfficialReviewedNsisZip reviewed{10U, SHA, L"driver.exe", 3U, SHA, members} ;	// 審査した版
	DriverArchiveInput input{1U, {}, 10U, std::wstring( SHA), {}} ;						// 元パス未指定で事前診断を区別
	std::vector<OfficialZipFile> files{{L"previous", {std::byte{1}}}} ;					// 拒否時は旧内容も破棄する
	DRIVERCRATE_EXPECT( context, readOfficialReviewedNsisZipMembers( input, reviewed, files) ==
										static_cast<NativeError>( E_INVALIDARG) &&
									files.empty()) ;
	input.workspaceMode = OfficialWorkspaceMode::CURRENT_USER_INSPECTION ;
	input.byteCount += 1U ;
	DRIVERCRATE_EXPECT( context, readOfficialReviewedNsisZipMembers( input, reviewed, files) ==
										static_cast<NativeError>( TRUST_E_BAD_DIGEST) &&
									files.empty()) ;
	input.byteCount		 = reviewed.archiveBytes ;
	input.sha256.front() = L'0' ;
	DRIVERCRATE_EXPECT( context, readOfficialReviewedNsisZipMembers( input, reviewed, files) ==
										static_cast<NativeError>( TRUST_E_BAD_DIGEST) &&
									files.empty()) ;
	input.sha256		 = SHA ;
	auto other			 = reviewed ;	// 同じ受領記録を別の内側配置へ流用する対照
	other.executableName = L"other\\driver.exe" ;
	DRIVERCRATE_EXPECT( context, readOfficialReviewedNsisZipMembers( input, other, files) ==
										static_cast<NativeError>( E_INVALIDARG) &&
									files.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief PE末尾7z・ZIPとWiX v3の境界、元マニフェストの内容選択、破損時の拒否を検証する
 * @param[in,out] context Assertion件数と失敗内容の集計先
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
	testValidWixLayout( context) ;
	testWixBoundaryRejection( context) ;
	testWixManifestBinding( context) ;
	testWixVerifiedSourceRejection( context) ;
	testValidSignedPeZipLayout( context) ;
	testSignedPeZipEndRejection( context) ;
	testSignedPeZipEntryRejection( context) ;
	testVerifiedSignedPeZipRejection( context) ;
	testCollectorSignedPeZipRequestBoundary( context) ;
	testReviewedNsisMembers( context) ;
	testReviewedNsisZipInput( context) ;
}

} // namespace drivercrate::test
