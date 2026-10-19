//------------------------------------------------------------------------------
/**
 * @file official_sfx.cpp
 * @brief 公式自己解凍形式の静的識別実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z形式の静的識別を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate直前zero paddingへ対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 未信頼EXEを実行せず、PE raw image、7z stream、任意のcertificate tableと必要最小限のzero alignmentを検査します。成功するまで呼出
 *       側の識別結果を更新しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_sfx.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	DOS_PE_OFFSET_FIELD	   = 0x3cU ;				// DOS header内のPE header offset位置。
constexpr std::size_t	COFF_HEADER_BYTES	   = 20U ;					// PE signature後のCOFF header長。
constexpr std::size_t	SECTION_HEADER_BYTES   = 40U ;					// 一つのPE section header長。
constexpr std::uint16_t MAXIMUM_SECTIONS	   = 96U ;					// 受理するPE section数の有限上限。
constexpr std::size_t	SEVEN_ZIP_HEADER_BYTES = 32U ;					// 7z Signature Headerの固定長。
constexpr std::size_t	SEVEN_ZIP_START_HEADER_BYTES = 20U ;			// CRC対象Start Header長。
constexpr std::size_t	CERTIFICATE_HEADER_BYTES	 = 8U ;				// WIN_CERTIFICATE固定header長。
constexpr std::uint64_t CERTIFICATE_ALIGNMENT		 = 8U ;				// Certificate entry境界のbyte数。
constexpr std::uint32_t CRC32_POLYNOMIAL			 = 0xedb88320U ;	// IEEE CRC-32反転多項式。
constexpr std::array<std::byte, 4> PE_SIGNATURE{std::byte{0x50}, std::byte{0x45}, std::byte{0x00},
												std::byte{0x00}} ;	// PE\0\0 signature。
constexpr std::array<std::byte, 6> SEVEN_ZIP_SIGNATURE{
	std::byte{0x37}, std::byte{0x7a}, std::byte{0xbc},
	std::byte{0xaf}, std::byte{0x27}, std::byte{0x1c}} ;	// 7z file signature。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 検証済みPE imageとcertificate tableの境界を保持する。
 */
struct PeLayout {
	/// Headerとraw sectionを包含する末尾offset。
	std::uint64_t imageEnd{} ;
	/// 7zと許可paddingが終了すべきfile offset。
	std::uint64_t archiveLimit{} ;
	/// Certificate table先頭。存在しない場合は0。
	std::uint64_t certificateOffset{} ;
	/// Certificate table長。存在しない場合は0。
	std::uint64_t certificateSize{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * 構造不正と上限超過をProvider共通診断型へ保持する。
 *
 * @param[in] error 検証失敗を表すWin32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 加算可能なfile rangeか確認する。
 *
 * 未信頼offsetをindexへ変換する前にfile境界を検証する。
 *
 * @param[in] input 検査対象file全体。
 * @param[in] offset 確認するrangeの開始offset。
 * @param[in] length 確認するrangeのbyte数。
 * @return 加算overflowせず入力内へ完全に収まる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasRange( const std::span<const std::byte> input, const std::uint64_t offset,
							const std::uint64_t length) noexcept
{
	const std::uint64_t inputSize = static_cast<std::uint64_t>( input.size()) ;	// 入力長。
	return offset <= inputSize && length <= inputSize - offset ;
}

//------------------------------------------------------------------------------
/**
 * @brief 64-bit値をoverflowなしで加算する。
 *
 * PE／7zが持つ64-bit offsetのwraparoundを拒否する。
 *
 * @param[in] left 左辺値。
 * @param[in] right 右辺値。
 * @param[out] result 成功時の加算結果。失敗時は変更しない。
 * @return 加算可能な場合は`true`、overflowする場合は`false`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool checkedAdd( const std::uint64_t left, const std::uint64_t right,
							  std::uint64_t &result) noexcept
{
	// 加算前に 64-bit の残余範囲を確認し、overflow を拒否する。
	if( right > std::numeric_limits<std::uint64_t>::max() - left) {
		return false ;
	}

	result = left + right ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 16-bit値を読み取る。
 *
 * Alignmentとhost endianに依存せず値を復元する。
 *
 * @param[in] input 事前にrangeを検証した入力file。
 * @param[in] offset 2 byteを読める検証済みoffset。
 * @return Little-endianから復元した16-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint16_t readU16Le( const std::span<const std::byte> input,
									  const std::uint64_t			   offset) noexcept
{
	const std::size_t	index = static_cast<std::size_t>( offset) ;					// 検証済み配列index。
	const std::uint16_t low	  = std::to_integer<std::uint8_t>( input[index]) ;		// 下位byte。
	const std::uint16_t high  = std::to_integer<std::uint8_t>( input[index + 1U]) ;	// 上位byte。
	return static_cast<std::uint16_t>( low | static_cast<std::uint16_t>( high << 8U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 32-bit値を読み取る。
 *
 * Alignmentとhost endianに依存せず値を復元する。
 *
 * @param[in] input 事前にrangeを検証した入力file。
 * @param[in] offset 4 byteを読める検証済みoffset。
 * @return Little-endianから復元した32-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t readU32Le( const std::span<const std::byte> input,
									  const std::uint64_t			   offset) noexcept
{
	std::uint32_t value{} ;	// 入力から復元する値。
	// 4 byteを下位側から順に配置する。
	for( std::uint64_t byteIndex = 0; byteIndex < 4U; ++byteIndex) {
		const std::size_t inputIndex =
			// 現在byteの配列index。
			static_cast<std::size_t>( offset + byteIndex) ;
		const std::uint32_t part =
			std::to_integer<std::uint8_t>( input[inputIndex]) ;	// 現在byteの値。
		value |= part << static_cast<unsigned int>( byteIndex * 8U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 64-bit値を読み取る。
 *
 * Alignmentとhost endianに依存せず値を復元する。
 *
 * @param[in] input 事前にrangeを検証した入力file。
 * @param[in] offset 8 byteを読める検証済みoffset。
 * @return Little-endianから復元した64-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t readU64Le( const std::span<const std::byte> input,
									  const std::uint64_t			   offset) noexcept
{
	std::uint64_t value{} ;	// 入力から復元する値。
	// 8 byteを下位側から順に配置する。
	for( std::uint64_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
		const std::size_t inputIndex =
			// 現在byteの配列index。
			static_cast<std::size_t>( offset + byteIndex) ;
		const std::uint64_t part =
			std::to_integer<std::uint8_t>( input[inputIndex]) ;	// 現在byteの値。
		value |= part << static_cast<unsigned int>( byteIndex * 8U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief CRC-32を算出する。
 *
 * Tableを持たない有限loopで7z headerの破損を検出する。
 *
 * @param[in] input CRC対象byte列。有効期間は本呼出し中に限る。
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
 * @brief PE certificate tableの連続性を検証する。
 *
 * 未信頼dwLengthによる停滞、越境、端数をfail-closedで拒否する。
 *
 * @param[in] input EXE全体。
 * @param[in] offset Certificate table先頭offset。
 * @param[in] size Certificate table全体のbyte数。
 * @return 全entryが8-byte境界でtable全体を埋める場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inspectCertificateTable( const std::span<const std::byte> input,
										   const std::uint64_t				offset,
										   const std::uint64_t				size) noexcept
{
	std::uint64_t tableEnd{} ;	// Certificate table直後のoffset。
	// Certificate table の終端 overflow と入力範囲外を拒否する。
	if( !checkedAdd( offset, size, tableEnd) || !hasRange( input, offset, size)) {
		return false ;
	}

	std::uint64_t cursor = offset ;	// 現在検査中のWIN_CERTIFICATE先頭。
	// 各entryを8-byte alignment込みで進め、table末尾への完全一致を確認する。
	while( cursor < tableEnd) {
		// Certificate header の全 byte が残っていなければ解析しない。
		if( !hasRange( input, cursor, CERTIFICATE_HEADER_BYTES)) {
			return false ;
		}

		const std::uint64_t certificateLength =
			// Paddingを除く現在entry長。
			readU32Le( input, cursor) ;
		// Certificate 長が header 自体より短い構造を拒否する。
		if( certificateLength < CERTIFICATE_HEADER_BYTES) {
			return false ;
		}

		std::uint64_t lengthWithPadding{} ;	// 8-byte境界へ切り上げたentry消費長。
		// Alignment padding の加算が overflow する certificate を拒否する。
		if( !checkedAdd( certificateLength, CERTIFICATE_ALIGNMENT - 1U, lengthWithPadding)) {
			return false ;
		}

		lengthWithPadding &= ~(CERTIFICATE_ALIGNMENT - 1U) ;
		std::uint64_t nextCursor{} ;	// 次entryまたはtable末尾のoffset。
		// 次の certificate 位置が overflow または table 終端超過なら拒否する。
		if( !checkedAdd( cursor, lengthWithPadding, nextCursor) || nextCursor > tableEnd) {
			return false ;
		}

		cursor = nextCursor ;
	}

	return cursor == tableEnd ;
}

//------------------------------------------------------------------------------
/**
 * @brief PE imageとcertificate tableの境界を検証する。
 *
 * Loaderを呼ばず、raw file構造だけで7z走査開始位置を決める。
 *
 * @param[in] input EXE全体。
 * @param[out] layout 成功時のimage、archive、certificate境界。
 * @return PE32／PE32+のheaderと全file rangeが妥当なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inspectPeLayout( const std::span<const std::byte> input,
								   PeLayout						   &layout) noexcept
{
	layout = {} ;
	// DOS header の必要領域と MZ signature がない入力を PE と扱わない。
	if( !hasRange( input, 0U, DOS_PE_OFFSET_FIELD + sizeof( std::uint32_t)) ||
	   input[0] != std::byte{0x4d} || input[1] != std::byte{0x5a}) {
		return false ;
	}

	const std::uint64_t		peOffset = readU32Le( input, DOS_PE_OFFSET_FIELD) ;	// PE先頭offset。
	constexpr std::uint64_t PE_AND_COFF_BYTES =
		// PE signatureとCOFF headerの合計長。
		PE_SIGNATURE.size() + COFF_HEADER_BYTES ;
	// PE・COFF header が入力範囲に収まらなければ解析を中止する。
	if( !hasRange( input, peOffset, PE_AND_COFF_BYTES)) {
		return false ;
	}

	// PE識別子4 byteを完全一致で確認する。
	for( std::size_t index = 0; index < PE_SIGNATURE.size(); ++index) {
		const std::size_t inputIndex =
			// PE signature内の配列index。
			static_cast<std::size_t>( peOffset) + index ;
		// PE signature の一 byte でも異なる入力を拒否する。
		if( input[inputIndex] != PE_SIGNATURE[index]) {
			return false ;
		}
	}

	const std::uint64_t coffOffset	 = peOffset + PE_SIGNATURE.size() ;		// COFF header先頭offset。
	const std::uint16_t sectionCount = readU16Le( input, coffOffset + 2U) ;	// COFF NumberOfSections。
	const std::uint16_t optionalHeaderSize =
		// COFF SizeOfOptionalHeader。
		readU16Le( input, coffOffset + 16U) ;
	// Section 数がゼロまたは検証上限を超える PE を拒否する。
	if( sectionCount == 0U || sectionCount > MAXIMUM_SECTIONS) {
		return false ;
	}

	const std::uint64_t optionalOffset =
		coffOffset + COFF_HEADER_BYTES ;	// Optional header先頭offset。
	// Optional header の範囲と magic の読取り領域を確認する。
	if( !hasRange( input, optionalOffset, optionalHeaderSize) ||
	   optionalHeaderSize < sizeof( std::uint16_t)) {
		return false ;
	}

	const std::uint16_t optionalMagic = readU16Le( input, optionalOffset) ;	// PE32／PE32+識別値。
	std::uint64_t		directoryCountOffset{} ;							// NumberOfRvaAndSizesのoptional内offset。
	std::uint64_t		directoryOffset{} ;									// Data directory配列のoptional内offset。
	// PE32 の header 配置に従って data directory の位置を選ぶ。
	if( optionalMagic == 0x010bU) {
		directoryCountOffset = 92U ;
		directoryOffset		 = 96U ;
	}
	// PE32+ の header 配置に従って data directory の位置を選ぶ。
	else if( optionalMagic == 0x020bU) {
		directoryCountOffset = 108U ;
		directoryOffset		 = 112U ;
	} else {
		return false ;
	}

	// Data directory の件数と header size の必要 field が欠ける PE を拒否する。
	if( optionalHeaderSize < directoryOffset ||
	   !hasRange( input, optionalOffset + directoryCountOffset, sizeof( std::uint32_t)) ||
	   !hasRange( input, optionalOffset + 60U, sizeof( std::uint32_t))) {
		return false ;
	}

	const std::uint64_t sectionTableOffset =
		optionalOffset + optionalHeaderSize ;	// 最初のsection header位置。
	const std::uint64_t sectionTableSize =
		// 全section header長。
		static_cast<std::uint64_t>( sectionCount) * SECTION_HEADER_BYTES ;
	// Section table 全体が入力範囲に収まらなければ拒否する。
	if( !hasRange( input, sectionTableOffset, sectionTableSize)) {
		return false ;
	}

	std::uint64_t sectionTableEnd{} ;	// Section table直後のoffset。
	// Section table の終端計算が overflow する入力を拒否する。
	if( !checkedAdd( sectionTableOffset, sectionTableSize, sectionTableEnd)) {
		return false ;
	}

	const std::uint64_t sizeOfHeaders =
		// PE SizeOfHeaders値。
		readU32Le( input, optionalOffset + 60U) ;
	// Header 宣言長が section table を覆わない場合と入力超過を拒否する。
	if( sizeOfHeaders < sectionTableEnd || !hasRange( input, 0U, sizeOfHeaders)) {
		return false ;
	}

	std::uint64_t imageEnd = sizeOfHeaders ;	// 全raw sectionを包含する末尾offset。
	// 全sectionのraw rangeを検証し、最大末尾をimage境界とする。
	for( std::uint16_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
		const std::uint64_t sectionOffset =
			sectionTableOffset +
			// 現在header位置。
			static_cast<std::uint64_t>( sectionIndex) * SECTION_HEADER_BYTES ;
		const std::uint64_t rawSize	  = readU32Le( input, sectionOffset + 16U) ;	// SizeOfRawData。
		const std::uint64_t rawOffset = readU32Le( input, sectionOffset + 20U) ;	// PointerToRawData。
		// Raw data を持たない section は file 内領域の照合から除外する。
		if( rawSize == 0U) {
			continue ;
		}

		// Section data が header と重なる場合と入力範囲外を拒否する。
		if( rawOffset < sizeOfHeaders || !hasRange( input, rawOffset, rawSize)) {
			return false ;
		}

		std::uint64_t rawEnd{} ;	// 現在raw section直後のoffset。
		// Section data 終端の overflow を検出したら領域比較を行わない。
		if( !checkedAdd( rawOffset, rawSize, rawEnd)) {
			return false ;
		}

		// Raw section同士の重複を拒否し、曖昧なimage末尾を作らない。
		for( std::uint16_t priorIndex = 0; priorIndex < sectionIndex; ++priorIndex) {
			const std::uint64_t priorSectionOffset =
				sectionTableOffset + static_cast<std::uint64_t>( priorIndex) *
										 SECTION_HEADER_BYTES ;	// 先行section header位置。
			const std::uint64_t priorRawSize =
				// 先行section raw長。
				readU32Le( input, priorSectionOffset + 16U) ;
			const std::uint64_t priorRawOffset =
				// 先行section raw位置。
				readU32Le( input, priorSectionOffset + 20U) ;
			// 過去 section に raw data がなければ領域重複の比較を省く。
			if( priorRawSize == 0U) {
				continue ;
			}

			std::uint64_t priorRawEnd{} ;	// 先行raw section直後のoffset。
			// 過去 section の終端 overflow または section 間の領域重複を拒否する。
			if( !checkedAdd( priorRawOffset, priorRawSize, priorRawEnd) ||
			   (rawOffset < priorRawEnd && priorRawOffset < rawEnd)) {
				return false ;
			}
		}

		imageEnd = std::max( imageEnd, rawEnd) ;
	}

	const std::uint64_t directoryCount =
		// Data directory数。
		readU32Le( input, optionalOffset + directoryCountOffset) ;
	std::uint64_t			certificateOffset{} ;			// Security directoryのfile offset。
	std::uint64_t			certificateSize{} ;				// Security directoryのbyte数。
	constexpr std::uint64_t SECURITY_DIRECTORY_INDEX = 4U ;	// Certificate tableのdirectory index。
	constexpr std::uint64_t DIRECTORY_ENTRY_BYTES	 = 8U ;	// 一data directoryの固定長。
	// Security directory が宣言されている場合だけ certificate table を照会する。
	if( directoryCount > SECURITY_DIRECTORY_INDEX) {
		const std::uint64_t securityEntryOffset =
			optionalOffset + directoryOffset +
			SECURITY_DIRECTORY_INDEX * DIRECTORY_ENTRY_BYTES ;	// Security directory位置。
		// Security directory entry が optional header と入力範囲に収まることを確認する。
		if( optionalHeaderSize <
			   directoryOffset + (SECURITY_DIRECTORY_INDEX + 1U) * DIRECTORY_ENTRY_BYTES ||
		   !hasRange( input, securityEntryOffset, DIRECTORY_ENTRY_BYTES)) {
			return false ;
		}

		certificateOffset = readU32Le( input, securityEntryOffset) ;
		certificateSize	  = readU32Le( input, securityEntryOffset + 4U) ;
	}

	const std::uint64_t inputSize	 = static_cast<std::uint64_t>( input.size()) ;	// EXE全体長。
	std::uint64_t		archiveLimit = inputSize ;									// Certificateがない場合の7z末尾上限。
	// Certificate の offset と size の片方だけがゼロの不整合を拒否する。
	if( (certificateOffset == 0U) != (certificateSize == 0U)) {
		return false ;
	}

	// Certificate table がある場合はその配置と連続性を検証する。
	if( certificateOffset != 0U) {
		std::uint64_t certificateEnd{} ;	// Certificate table直後のoffset。
		// Alignment、size、image 後方配置、file 終端一致、table 構造を全て必須とする。
		if( (certificateOffset % CERTIFICATE_ALIGNMENT) != 0U ||
		   certificateSize < CERTIFICATE_HEADER_BYTES || certificateOffset <= imageEnd ||
		   !checkedAdd( certificateOffset, certificateSize, certificateEnd) ||
		   certificateEnd != inputSize ||
		   !inspectCertificateTable( input, certificateOffset, certificateSize)) {
			return false ;
		}

		archiveLimit = certificateOffset ;
	}

	// PE image 後方に archive を置ける領域がない入力を拒否する。
	if( archiveLimit <= imageEnd) {
		return false ;
	}

	layout = PeLayout{imageEnd, archiveLimit, certificateOffset, certificateSize} ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificate直前のzero alignment paddingを検証する。
 *
 * Certificateがない入力のtrailerと、任意長／非zero dataをfail-closedで拒否する。
 *
 * @param[in] input EXE全体。
 * @param[in] peLayout 検証済みPEとcertificate境界。
 * @param[in] archiveEnd CRC整合済み7z stream直後のoffset。
 * @param[out] paddingSize 成功時の検証済みzero byte数。
 * @return Certificate用の必要最小zero paddingだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inspectCertificateAlignmentPadding( const std::span<const std::byte> input,
													  const PeLayout				  &peLayout,
													  const std::uint64_t			   archiveEnd,
													  std::uint64_t &paddingSize) noexcept
{
	paddingSize = 0U ;
	// 7z streamがCertificate tableまたはfile末尾を越える入力を拒否する。
	if( archiveEnd > peLayout.archiveLimit) {
		return false ;
	}

	const std::uint64_t actualPaddingSize =
		peLayout.archiveLimit - archiveEnd ;	// 7z終端から境界までの実間隔。
	// Certificateなしではtrailing byteを一切許可しない。
	if( peLayout.certificateOffset == 0U) {
		return actualPaddingSize == 0U ;
	}

	const std::uint64_t expectedPaddingSize =
		(CERTIFICATE_ALIGNMENT - (archiveEnd % CERTIFICATE_ALIGNMENT)) %
		CERTIFICATE_ALIGNMENT ;	// 次の8-byte境界へ揃えるための唯一の長さ。
	// 過大、誤alignmentまたはfile範囲外の間隔を拒否する。
	if( actualPaddingSize != expectedPaddingSize || actualPaddingSize >= CERTIFICATE_ALIGNMENT ||
	   !hasRange( input, archiveEnd, actualPaddingSize)) {
		return false ;
	}

	// paddingIndexは必要なpaddingを先頭から検査するbyte位置。
	// 必要なpadding全byteを確認し、未監査trailerをzeroとみなさない。
	for( std::uint64_t paddingIndex = 0U; paddingIndex < actualPaddingSize; ++paddingIndex) {
		const std::size_t inputIndex =
			// 現在paddingの配列index。
			static_cast<std::size_t>( archiveEnd + paddingIndex) ;
		// Certificate 直前の padding にゼロ以外の data があれば拒否する。
		if( input[inputIndex] != std::byte{0x00}) {
			return false ;
		}
	}

	paddingSize = actualPaddingSize ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief PE末尾の7z Signature Headerを検証する。
 *
 * 単一signatureと、Next Header後の必要最小zero paddingだけを受理する。
 *
 * @param[in] input EXE全体。
 * @param[in] peLayout 検証済みPEとcertificate境界。
 * @param[in] policy Stub走査とarchive長の有限上限。
 * @param[out] layout 成功時の7zおよびcertificate範囲。
 * @return 成功時は0、構造またはCRC不正時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSevenZipLayout( const std::span<const std::byte>   input,
												const PeLayout					  &peLayout,
												const OfficialSfxInspectionPolicy &policy,
												OfficialSfxLayout				  &layout) noexcept
{
	// Image 後方の領域が最小 7z stream に足りなければ探索しない。
	if( peLayout.archiveLimit - peLayout.imageEnd < SEVEN_ZIP_HEADER_BYTES + 1U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	std::uint64_t maximumSignatureOffset{} ;	// Stub上限から算出した走査末尾。
	// 探索上限の加算が overflow する場合は表現可能最大値へ飽和させる。
	if( !checkedAdd( peLayout.imageEnd, policy.maximumStubBytes, maximumSignatureOffset)) {
		maximumSignatureOffset = std::numeric_limits<std::uint64_t>::max() ;
	}

	maximumSignatureOffset =
		std::min( maximumSignatureOffset, peLayout.archiveLimit - SEVEN_ZIP_HEADER_BYTES) ;

	std::uint64_t signatureOffset{} ;	// 発見した唯一の7z signature先頭。
	std::uint32_t signatureCount{} ;	// 走査範囲に現れた7z signature数。
	// PE image末尾から有限stub上限まで、一byteずつ完全signatureを探索する。
	for( std::uint64_t candidateOffset = peLayout.imageEnd;
		candidateOffset <= maximumSignatureOffset; ++candidateOffset) {
		bool matches = true ;	// 現在位置が6-byte signatureと完全一致する場合true。
		// Signature全byteを順に比較する。
		for( std::size_t signatureIndex = 0; signatureIndex < SEVEN_ZIP_SIGNATURE.size();
			++signatureIndex) {
			const std::size_t inputIndex = static_cast<std::size_t>( candidateOffset) +
										   signatureIndex ;	// 現在signature byteの配列index。
			// Signature の不一致を検出したら現在位置の比較を打ち切る。
			if( input[inputIndex] != SEVEN_ZIP_SIGNATURE[signatureIndex]) {
				matches = false ;
				break ;
			}
		}

		// 完全一致した signature だけを数え、その位置を保持する。
		if( matches) {
			++signatureCount ;
			signatureOffset = candidateOffset ;
		}
	}

	// 7z signature が一意に決まらなければ stream を選択しない。
	if( signatureCount != 1U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const std::size_t signatureIndex =
		// 7z headerの配列index。
		static_cast<std::size_t>( signatureOffset) ;
	// 対応する 7z version 表記と異なる stream を拒否する。
	if( input[signatureIndex + 6U] != std::byte{0x00} ||
	   input[signatureIndex + 7U] != std::byte{0x04}) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const std::uint32_t expectedStartCrc =
		// 格納されたStart Header CRC。
		readU32Le( input, signatureOffset + 8U) ;
	const std::span<const std::byte> startHeader =
		// CRC対象header。
		input.subspan( signatureIndex + 12U, SEVEN_ZIP_START_HEADER_BYTES) ;
	// Start Header の CRC が一致しなければ後続 offset を使用しない。
	if( calculateCrc32( startHeader) != expectedStartCrc) {
		return nativeErrorFromWin32( ERROR_CRC) ;
	}

	const std::uint64_t nextHeaderRelativeOffset =
		// Signature Header後からの相対位置。
		readU64Le( input, signatureOffset + 12U) ;
	const std::uint64_t nextHeaderSize = readU64Le( input, signatureOffset + 20U) ;	// Next Header長。
	const std::uint32_t expectedNextCrc =
		// 格納されたNext Header CRC。
		readU32Le( input, signatureOffset + 28U) ;
	// 空の Next Header を持つ stream を拒否する。
	if( nextHeaderSize == 0U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	std::uint64_t archiveDataOffset{} ;	// 7z Signature Header直後のoffset。
	std::uint64_t nextHeaderOffset{} ;	// Next Header先頭のfile offset。
	std::uint64_t nextHeaderEnd{} ;		// Next Header直後のfile offset。
	// Next Header 位置の overflow と archive・入力境界超過を拒否する。
	if( !checkedAdd( signatureOffset, SEVEN_ZIP_HEADER_BYTES, archiveDataOffset) ||
	   !checkedAdd( archiveDataOffset, nextHeaderRelativeOffset, nextHeaderOffset) ||
	   !checkedAdd( nextHeaderOffset, nextHeaderSize, nextHeaderEnd) ||
	   nextHeaderEnd > peLayout.archiveLimit ||
	   !hasRange( input, nextHeaderOffset, nextHeaderSize)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	std::uint64_t certificatePaddingSize{} ;	// 7zとCertificate table間の検証済みzero長。
	// Archive と certificate 間の padding が許可形式でなければ拒否する。
	if( !inspectCertificateAlignmentPadding( input, peLayout, nextHeaderEnd,
										   certificatePaddingSize)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const std::uint64_t archiveSize = nextHeaderEnd - signatureOffset ;	// Paddingを除く7z stream長。
	// 識別した archive の byte 数が policy 上限を超える場合は拒否する。
	if( archiveSize > policy.maximumArchiveBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	const std::span<const std::byte> nextHeader =
		input.subspan( static_cast<std::size_t>( nextHeaderOffset),
					  // CRC対象Next Header。
					  static_cast<std::size_t>( nextHeaderSize)) ;
	// Next Header の CRC が一致しなければ抽出範囲を受理しない。
	if( calculateCrc32( nextHeader) != expectedNextCrc) {
		return nativeErrorFromWin32( ERROR_CRC) ;
	}

	layout = OfficialSfxLayout{signatureOffset,			archiveSize,	certificatePaddingSize,
							   nextHeaderOffset,		nextHeaderSize, peLayout.certificateOffset,
							   peLayout.certificateSize} ;
	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_sfx.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialSevenZipSfx( const std::span<const std::byte>	  executable,
									   const OfficialSfxInspectionPolicy &policy,
									   OfficialSfxLayout				 &layout) noexcept
{
	layout = {} ;
	// 空実行 file とゼロ・相互矛盾のある size policy を解析前に拒否する。
	if( executable.empty() || policy.maximumExecutableBytes == 0U || policy.maximumStubBytes == 0U ||
	   policy.maximumArchiveBytes == 0U ||
	   policy.maximumStubBytes > policy.maximumExecutableBytes ||
	   policy.maximumArchiveBytes > policy.maximumExecutableBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 実行 file 全体が取得上限を超える場合は埋込み archive を探索しない。
	if( static_cast<std::uint64_t>( executable.size()) > policy.maximumExecutableBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	PeLayout peLayout{} ;	// 検証済みPE imageとcertificate境界。
	// PE 領域の境界検証が成立しなければ後方 data を archive と扱わない。
	if( !inspectPeLayout( executable, peLayout)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	OfficialSfxLayout inspectedLayout{} ;	// 全検査成功まで局所保持する識別結果。
	const NativeError error =
		// 7z検査結果。
		inspectSevenZipLayout( executable, peLayout, policy, inspectedLayout) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	layout = inspectedLayout ;
	return 0 ;
}

} // namespace drivercrate
