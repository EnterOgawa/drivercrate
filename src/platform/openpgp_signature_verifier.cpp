//------------------------------------------------------------------------------
/**
 * @file openpgp_signature_verifier.cpp
 * @brief 固定OpenPGP detached signature検証実装。
 * @version 01.00.01
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
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note OpenPGP v4 RSA/SHA-256の必要最小限だけを解析し、未知critical subpacket、partial packet、複数packet、未知鍵を
 *       fail-closedで拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/openpgp_signature_verifier.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::string_view ARMOR_BEGIN = "-----BEGIN PGP SIGNATURE-----" ;
// Detached signatureのASCII armorを閉じる固定境界。
constexpr std::string_view ARMOR_END		   = "-----END PGP SIGNATURE-----" ;
constexpr std::uint32_t	   CRC24_INITIAL	   = 0x00b704ceU ;				// OpenPGP Armor CRC24初期値。
constexpr std::uint32_t	   CRC24_POLYNOMIAL	   = 0x01864cfbU ;				// OpenPGP Armor CRC24多項式。
constexpr std::size_t	   MAXIMUM_ARMOR_LINES = 128 ;						// Armor parsingの有限な行数上限。
constexpr std::size_t	   MAXIMUM_SIGNATURE_PACKET_BYTES = 16U * 1024U ;	// Signature packet上限。
constexpr std::size_t	   SHA1_BYTES				 = 20 ;					// OpenPGP v4 fingerprintのSHA-1 byte数。
constexpr std::size_t	   SHA256_BYTES				 = 32 ;					// 対応するdocument digest byte数。
constexpr std::uint8_t	   SIGNATURE_PACKET_TAG		 = 2 ;					// OpenPGP Signature packet tag。
constexpr std::uint8_t	   BINARY_DOCUMENT_SIGNATURE = 0x00 ;				// Binary document signature type。
constexpr std::uint8_t	   RSA_ALGORITHM			 = 1 ;					// RSA Encrypt or Sign algorithm ID。
constexpr std::uint8_t	   SHA256_ALGORITHM			 = 8 ;					// SHA-256 algorithm ID。
constexpr std::uint8_t	   ISSUER_SUBPACKET			 = 16 ;					// Issuer key ID subpacket type。
constexpr std::uint8_t	   ISSUER_FINGERPRINT_SUBPACKET = 33 ;				// Issuer fingerprint subpacket type。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief CloseHandleでlocal file handleを解放するRAII wrapperである。
 */
class UniqueFile		   final {
public:
	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有file handleを設定する。
     *
     * Handle ownershipをobjectへ移し、copy/moveを許可しない。
     *
     * @param[in] handle CloseHandleで解放するfile handle。
     */
	  //------------------------------------------------------------------------------
	  explicit UniqueFile( const HANDLE handle) noexcept : handle_( handle)
	  {
	  }

	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有file handleを解放する。
     *
     * 有効なhandleだけを一度CloseHandleする。
     */
	  //------------------------------------------------------------------------------
	  ~UniqueFile()
	  {
		  // 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		  if( handle_ != INVALID_HANDLE_VALUE) {
			  CloseHandle( handle_) ;
		  }
	  }

	  /**
	   * @brief file HANDLEの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	   */
	  UniqueFile( const UniqueFile &) = delete ;
	  /**
	   * @brief file HANDLEの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	   */
	  UniqueFile &operator=( const UniqueFile &) = delete ;
	  /**
	   * @brief file HANDLEの解放責務を取得したfile ownerに留めるため、移動構築を禁止する。
	   */
	  UniqueFile( UniqueFile &&) = delete ;
	  /**
	   * @brief 取得したfile ownerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	   */
	  UniqueFile		  &operator=( UniqueFile &&) = delete ;

	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有file handleを参照する。
     *
     * Win32 API呼出し中だけhandle値を利用する。
     * @return 所有権を移さないfile handle。
     */
	  //------------------------------------------------------------------------------
	  [[nodiscard]] HANDLE get() const noexcept
	  {
		  return handle_ ;
	  }

private:
	  /// Destructorで解放する所有file handle。
	  HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

/**
 * @brief OpenPGP packet headerで検証したbody範囲である。
 */
struct PacketView {
	/// OpenPGP packet tag。
	std::uint8_t			   tag{} ;
	/// 入力packet内の非所有body view。
	std::span<const std::byte> body ;
	/// Headerを含むpacket全体byte数。
	std::size_t				   consumedBytes{} ;
} ;

/**
 * @brief OpenPGP multi-precision integerの検証済み非所有viewである。
 */
struct MpiView {
	/// 先頭zeroを除くMPI有効bit数。
	std::uint16_t			   bitCount{} ;
	/// Big-endian MPI byte列。
	std::span<const std::byte> data ;
} ;

/**
 * @brief OpenPGP v4 signatureからRSA検証に必要な範囲を保持する。
 */
struct SignatureView {
	/// Versionからhashed subpacket末尾まで。
	std::span<const std::byte> hashedPrefix ;
	/// Packetが宣言したdigest先頭16 bit。
	std::array<std::byte, 2>   hashPrefix{} ;
	/// Big-endian RSA signature MPI。
	MpiView					   rsaSignature ;
} ;

/**
 * @brief OpenPGP v4 RSA public-key packet bodyから得た公開値である。
 */
struct PublicKeyView {
	/// RSA modulus MPI。
	MpiView modulus ;
	/// RSA public exponent MPI。
	MpiView exponent ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * Provider共通の32-bit診断値へ元のerrorを保持する。
 *
 * @param[in] error Win32 API errorまたは検証用error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NTSTATUSをNativeErrorへ変換する。
 *
 * CNGの署名失敗と内部失敗を診断値として区別可能にする。
 *
 * @param[in] status BCrypt APIが返したNTSTATUS。
 * @return HRESULT_FROM_NTで変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromNtstatus( const NTSTATUS status) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Big-endian 16-bit値を読み取る。
 *
 * Alignmentとhost endianに依存せず一byteずつ復元する。
 *
 * @param[in] input 2 byte以上を確認済みの入力。
 * @param[in] offset 読取り可能と確認済みのoffset。
 * @return Big-endianから復元した16-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint16_t readU16Be( const std::span<const std::byte> input,
									  const std::size_t				   offset) noexcept
{
	const std::uint16_t high = std::to_integer<std::uint8_t>( input[offset]) ;		// 上位byte。
	const std::uint16_t low	 = std::to_integer<std::uint8_t>( input[offset + 1]) ;	// 下位byte。
	return static_cast<std::uint16_t>( static_cast<std::uint16_t>( high << 8U) | low) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Big-endian 32-bit値を読み取る。
 *
 * Packet長をhost endianへ安全に復元する。
 *
 * @param[in] input 4 byte以上を確認済みの入力。
 * @param[in] offset 読取り可能と確認済みのoffset。
 * @return Big-endianから復元した32-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t readU32Be( const std::span<const std::byte> input,
									  const std::size_t				   offset) noexcept
{
	std::uint32_t value{} ;	// 入力から復元する値。
	// 4 byteを上位側から順に取り込む。
	for( std::size_t index = 0; index < 4; ++index) {
		const std::uint32_t part =
			std::to_integer<std::uint8_t>( input[offset + index]) ;	// 現在byte。
		value = static_cast<std::uint32_t>( (value << 8U) | part) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Base64 ASCIIを厳密にbyte列へ変換する。
 *
 * Decoderの寛容な空白無視を使わず、Armor境界外文字を拒否する。
 *
 * @param[in] input 空白を含まないBase64文字列。
 * @param[out] output 成功時のdecoded byte列。失敗時は空。
 * @return Canonicalなpaddingと文字だけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeBase64( const std::string_view input, std::vector<std::byte> &output)
{
	output.clear() ;
	// 空または四文字単位でない Base64 入力は decode しない。
	if( input.empty() || input.size() % 4 != 0) {
		return false ;
	}

	const auto decodeCharacter = []( const char character) -> int {
		// ASCII 大文字を Base64 の先頭 26 値へ対応付ける。
		if( character >= 'A' && character <= 'Z') {
			return character - 'A' ;
		}

		// ASCII 小文字を Base64 の続く 26 値へ対応付ける。
		if( character >= 'a' && character <= 'z') {
			return character - 'a' + 26 ;
		}

		// ASCII 数字を Base64 の数値文字領域へ対応付ける。
		if( character >= '0' && character <= '9') {
			return character - '0' + 52 ;
		}

		// Base64 の plus 記号を定義された値へ変換する。
		if( character == '+') {
			return 62 ;
		}

		return character == '/' ? 63 : -1 ;
	} ; // 一つのBase64文字を6-bit値へ変換する局所関数。

	output.reserve( input.size() / 4 * 3) ;
	// 4文字blockごとにpadding位置とunused bitを検証して最大3 byteを生成する。
	for( std::size_t offset = 0; offset < input.size(); offset += 4) {
		const bool finalBlock	 = offset + 4 == input.size() ;	// 最後のblockならtrue。
		const bool paddingThird	 = input[offset + 2] == '=' ;	// 三文字目がpaddingならtrue。
		const bool paddingFourth = input[offset + 3] == '=' ;	// 四文字目がpaddingならtrue。
		// 最終 block 以外の padding と第三文字だけの padding を拒否する。
		if( (!finalBlock && (paddingThird || paddingFourth)) || (paddingThird && !paddingFourth)) {
			output.clear() ;
			return false ;
		}

		const int first	 = decodeCharacter( input[offset]) ;							// 一文字目6-bit値。
		const int second = decodeCharacter( input[offset + 1]) ;						// 二文字目6-bit値。
		const int third	 = paddingThird ? 0 : decodeCharacter( input[offset + 2]) ;		// 三文字目。
		const int fourth = paddingFourth ? 0 : decodeCharacter( input[offset + 3]) ;	// 四文字目。
		// 未知文字と padding 部分の非ゼロ余剰 bit を拒否し、部分出力を消去する。
		if( first < 0 || second < 0 || third < 0 || fourth < 0 ||
		   (paddingThird && (second & 0x0f) != 0) ||
		   (paddingFourth && !paddingThird && (third & 0x03) != 0)) {
			output.clear() ;
			return false ;
		}

		output.push_back( std::byte{static_cast<std::uint8_t>( (first << 2) | (second >> 4))}) ;
		// 第三文字が padding でない場合だけ二 byte 目を復元する。
		if( !paddingThird) {
			output.push_back( std::byte{static_cast<std::uint8_t>( (second << 4) | (third >> 2))}) ;
		}

		// 第四文字が padding でない場合だけ三 byte 目を復元する。
		if( !paddingFourth) {
			output.push_back( std::byte{static_cast<std::uint8_t>( (third << 6) | fourth)}) ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief OpenPGP Armor CRC24を計算する。
 *
 * Armor内checksumをpacket parsing前に完全一致させる。
 *
 * @param[in] input CRC対象のdecoded packet byte列。
 * @return 下位24 bitに格納したOpenPGP Armor checksum。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t computeCrc24( const std::span<const std::byte> input) noexcept
{
	std::uint32_t crc = CRC24_INITIAL ;	// 現在の24-bit CRC状態。
	// 全byteを順序通り処理する。
	for( const std::byte value : input) {
		crc ^= static_cast<std::uint32_t>( std::to_integer<std::uint8_t>( value)) << 16U ;
		// 一byteにつき8回、規定多項式で上位bitを縮約する。
		for( std::uint32_t bit = 0; bit < 8; ++bit) {
			crc <<= 1U ;
			// CRC の上位 bit が立つ場合は定義多項式で剰余を更新する。
			if( (crc & 0x01000000U) != 0) {
				crc ^= CRC24_POLYNOMIAL ;
			}
		}
	}

	return crc & 0x00ffffffU ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII Armorから単一signature packetを復元する。
 *
 * Armor前後の追加text、CR単独、過剰行、checksum欠落を拒否する。
 *
 * @param[in] armor Detached signature ASCII Armor全体。
 * @param[out] packet 成功時のdecoded packet。失敗時は空。
 * @return 境界、Base64、CRC24が全て正しい場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeSignatureArmor( const std::string_view	armor,
										std::vector<std::byte> &packet)
{
	packet.clear() ;
	// 空または許可 size を超える Armor 入力を拒否する。
	if( armor.empty() || armor.size() > MAXIMUM_SIGNATURE_PACKET_BYTES) {
		return false ;
	}

	std::vector<std::string_view> lines ;	// Armor内の終端文字を除く非所有行群。
	lines.reserve( 32) ;
	std::size_t offset{} ;	// 次に分割する文字offset。
	// LFで有限行へ分割し、CRはLF直前に一つだけ許可する。
	while( offset < armor.size()) {
		// Armor の行数上限を超える入力は分割を続けない。
		if( lines.size() >= MAXIMUM_ARMOR_LINES) {
			return false ;
		}

		const std::size_t newline = armor.find( '\n', offset) ;	// 次のLF位置。
		const std::size_t end =
			// 行末位置。
			newline == std::string_view::npos ? armor.size() : newline ;
		std::string_view line = armor.substr( offset, end - offset) ;	// 現在行。
		// CRLF の行末 CR だけを除き、本文の文字と区別する。
		if( !line.empty() && line.back() == '\r') {
			line.remove_suffix( 1) ;
		}

		// 行内に残る CR は不正な Armor 形式として拒否する。
		if( line.find( '\r') != std::string_view::npos) {
			return false ;
		}

		lines.push_back( line) ;
		// 最後の行を取り込んだら改行探索を終了する。
		if( newline == std::string_view::npos) {
			break ;
		}

		offset = newline + 1 ;
	}

	// 固定の Armor 開始行がない入力を署名として受理しない。
	if( lines.empty() || lines.front() != ARMOR_BEGIN) {
		return false ;
	}

	std::size_t lineIndex = 1 ;	// Header行の次に検査するline index。
	// 任意のArmor headerはASCII key:value形式だけを許可する。
	while( lineIndex < lines.size() && !lines[lineIndex].empty()) {
		const std::string_view line = lines[lineIndex] ;	// 現在のArmor header行。
		// 長さ・区切り・許可文字の条件を満たさない Armor header 行を拒否する。
		if( line.size() > 128 || line.find( ':') == std::string_view::npos ||
		   std::any_of( line.begin(), line.end(), []( const unsigned char character) {
			   return character < 0x20U || character > 0x7eU ;
		   })) {
			return false ;
		}

		++lineIndex ;
	}

	// Header と本文の間に必須の空行がなければ拒否する。
	if( lineIndex >= lines.size() || !lines[lineIndex].empty()) {
		return false ;
	}

	++lineIndex ;

	std::string		 bodyBase64 ;	// Line breakを除去したsignature packet Base64。
	std::string_view crcLine ;		// 先頭`=`を除くCRC24 Base64。
	// CRC行までの1～76文字Base64行を連結する。
	while( lineIndex < lines.size() && !lines[lineIndex].starts_with( '=')) {
		const std::string_view line = lines[lineIndex] ;	// 現在のBase64行。
		// 空、長さ超過、空白・制御文字を含む Base64 本文行を拒否する。
		if( line.empty() || line.size() > 76 ||
		   std::any_of( line.begin(), line.end(), []( const unsigned char character) {
			   return character <= 0x20U || character > 0x7eU ;
		   })) {
			return false ;
		}

		bodyBase64.append( line) ;
		++lineIndex ;
	}

	// 署名本文または固定長 CRC 行が欠ける Armor を拒否する。
	if( bodyBase64.empty() || lineIndex >= lines.size() || lines[lineIndex].size() != 5) {
		return false ;
	}

	crcLine = lines[lineIndex].substr( 1) ;
	++lineIndex ;
	// 固定の Armor 終了行がない署名を拒否する。
	if( lineIndex >= lines.size() || lines[lineIndex] != ARMOR_END) {
		return false ;
	}

	++lineIndex ;
	// END行後はterminal LFで生じる空行一つだけを許可する。
	if( lineIndex < lines.size() && (lineIndex + 1 != lines.size() || !lines[lineIndex].empty())) {
		return false ;
	}

	std::vector<std::byte> expectedCrcBytes ;	// Armorが宣言した3 byte CRC24。
	// 本文・CRC の decode 失敗、空 packet、size 超過を検出して出力を破棄する。
	if( !decodeBase64( bodyBase64, packet) || packet.empty() ||
	   packet.size() > MAXIMUM_SIGNATURE_PACKET_BYTES || !decodeBase64( crcLine, expectedCrcBytes) ||
	   expectedCrcBytes.size() != 3) {
		packet.clear() ;
		return false ;
	}

	const std::uint32_t expectedCrc =
		static_cast<std::uint32_t>( std::to_integer<std::uint8_t>( expectedCrcBytes[0])) << 16U |
		static_cast<std::uint32_t>( std::to_integer<std::uint8_t>( expectedCrcBytes[1])) << 8U |
		static_cast<std::uint32_t>(
			std::to_integer<std::uint8_t>( expectedCrcBytes[2])) ;	// Armor CRC24。
	// Armor CRC が packet の計算値と一致しなければ packet を破棄する。
	if( computeCrc24( packet) != expectedCrc) {
		packet.clear() ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのOpenPGP packet headerとbody範囲を解析する。
 *
 * Partial body lengthとold-format indeterminate lengthを拒否する。
 *
 * @param[in] input Packet headerから始まるbyte列。
 * @param[out] packet 成功時のtag、body、消費byte数。
 * @return Definite-length packetを一つ解析できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parsePacket( const std::span<const std::byte> input, PacketView &packet) noexcept
{
	packet = {} ;
	// Packet header の最小 byte 数がない入力を拒否する。
	if( input.size() < 2) {
		return false ;
	}

	const std::uint8_t first = std::to_integer<std::uint8_t>( input[0]) ;	// Packet header先頭。
	// Packet header を示す上位 bit がない入力を拒否する。
	if( (first & 0x80U) == 0) {
		return false ;
	}

	std::size_t	  headerSize = 1 ;	// Packet bodyまでのheader byte数。
	std::uint64_t bodySize{} ;		// Packet bodyの宣言byte数。
	// New-format bit がある packet には新形式の tag と長さ規則を適用する。
	if( (first & 0x40U) != 0) {
		packet.tag = static_cast<std::uint8_t>( first & 0x3fU) ;
		const std::uint8_t lengthFirst =
			std::to_integer<std::uint8_t>( input[headerSize++]) ;	// New-format length先頭。
		// 短い新形式の長さは先頭 byte だけから確定する。
		if( lengthFirst < 192U) {
			bodySize = lengthFirst ;
		}
		// 二 byte 形式の長さは追加 byte を検証して復元する。
		else if( lengthFirst <= 223U) {
			// 二 byte 長の後半が入力にない場合は拒否する。
			if( headerSize >= input.size()) {
				return false ;
			}

			const std::uint8_t lengthSecond =
				std::to_integer<std::uint8_t>( input[headerSize++]) ;	// Length二byte目。
			bodySize = static_cast<std::uint64_t>( (lengthFirst - 192U) << 8U) + lengthSecond + 192U ;
		}
		// 長形式の長さ指定は後続四 byte を明示長として読む。
		else if( lengthFirst == 255U) {
			// 四 byte の長さ field が入力範囲に収まらなければ拒否する。
			if( headerSize + 4 > input.size()) {
				return false ;
			}

			bodySize = readU32Be( input, headerSize) ;
			headerSize += 4 ;
		} else {
			return false ;
		}
	} else {
		packet.tag					  = static_cast<std::uint8_t>( (first >> 2U) & 0x0fU) ;
		const std::uint8_t lengthType = static_cast<std::uint8_t>( first & 0x03U) ;	// Old長形式。
		const std::size_t  lengthBytes =
			// Definite長byte数。
			lengthType == 0 ? 1U : (lengthType == 1 ? 2U : 4U) ;
		// 旧形式の不定長と入力に収まらない長さ field を拒否する。
		if( lengthType == 3 || headerSize + lengthBytes > input.size()) {
			return false ;
		}

		// Old-format lengthをbig-endianで復元する。
		for( std::size_t index = 0; index < lengthBytes; ++index) {
			bodySize = (bodySize << 8U) | std::to_integer<std::uint8_t>( input[headerSize + index]) ;
		}

		headerSize += lengthBytes ;
	}

	// 空 body と入力残量を超える packet 宣言長を拒否する。
	if( bodySize == 0 || bodySize > input.size() - headerSize) {
		return false ;
	}

	packet.body			 = input.subspan( headerSize, static_cast<std::size_t>( bodySize)) ;
	packet.consumedBytes = headerSize + static_cast<std::size_t>( bodySize) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief OpenPGP MPIを解析する。
 *
 * Leading zeroと宣言bit数の不一致を拒否する。
 *
 * @param[in] input MPIを含むpacket body。
 * @param[in,out] offset MPI bit count開始位置。成功時はMPI直後。
 * @param[out] mpi 成功時のbit数とbig-endian byte view。
 * @return Canonicalで非zeroのMPIを解析できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseMpi( const std::span<const std::byte> input, std::size_t &offset,
							MpiView &mpi) noexcept
{
	mpi = {} ;
	// MPI bit 数 field の二 byte が残っていなければ拒否する。
	if( offset + 2 > input.size()) {
		return false ;
	}

	const std::uint16_t bitCount = readU16Be( input, offset) ;	// MPI有効bit数。
	offset += 2 ;
	const std::size_t byteCount = (static_cast<std::size_t>( bitCount) + 7U) / 8U ;	// MPI長。
	// ゼロ bit の MPI と宣言 byte 数が残量を超える入力を拒否する。
	if( bitCount == 0 || byteCount > input.size() - offset) {
		return false ;
	}

	const std::span<const std::byte> data = input.subspan( offset, byteCount) ;	// MPI byte view。
	const std::uint8_t first = std::to_integer<std::uint8_t>( data.front()) ;	// 先頭byte。
	// MPI先頭byteのうち有効と宣言されたbit数。範囲は1～8。
	const std::uint8_t usedBits = static_cast<std::uint8_t>( (bitCount - 1U) % 8U + 1U) ;
	// MPI先頭byteで必ず立っているべき最上位有効bitのmask。
	const std::uint8_t topMask = static_cast<std::uint8_t>( 1U << (usedBits - 1U)) ;
	// MPI先頭byteで0を要求する未使用上位bitのmask。
	const std::uint8_t unusedMask = static_cast<std::uint8_t>( ~((topMask << 1U) - 1U)) ;
	// 宣言 bit 数に対応する先頭 bit と未使用 bit が不正な MPI を拒否する。
	if( (first & topMask) == 0 || (first & unusedMask) != 0) {
		return false ;
	}

	mpi.bitCount = bitCount ;
	mpi.data	 = data ;
	offset += byteCount ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 40桁OpenPGP fingerprintを20 byteへ変換する。
 *
 * 空白、区切り、部分fingerprintを許可しない。
 *
 * @param[in] text Providerへ固定したASCII hex fingerprint。
 * @param[out] fingerprint 成功時の20 byte値。
 * @return 40桁hexを完全変換できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseFingerprint( const std::wstring_view			   text,
									std::array<std::byte, SHA1_BYTES> &fingerprint) noexcept
{
	fingerprint.fill( std::byte{}) ;
	// Fingerprint の hex 桁数が期待 byte 数と一致しなければ拒否する。
	if( text.size() != fingerprint.size() * 2U) {
		return false ;
	}

	const auto hexValue = []( const wchar_t character) -> int {
		// 十進数字の hex 桁を対応する nibble 値へ変換する。
		if( character >= L'0' && character <= L'9') {
			return character - L'0' ;
		}

		// 大文字 A から F の hex 桁を対応する nibble 値へ変換する。
		if( character >= L'A' && character <= L'F') {
			return character - L'A' + 10 ;
		}

		return character >= L'a' && character <= L'f' ? character - L'a' + 10 : -1 ;
	} ; // 一つのhex文字を0～15へ変換する局所関数。
	// 二文字ずつ一byteへ変換する。
	for( std::size_t index = 0; index < fingerprint.size(); ++index) {
		const int high = hexValue( text[index * 2U]) ;		// 上位hex digit。
		const int low  = hexValue( text[index * 2U + 1U]) ;	// 下位hex digit。
		// 上位・下位のいずれかが hex でない fingerprint は拒否する。
		if( high < 0 || low < 0) {
			return false ;
		}

		fingerprint[index] = std::byte{static_cast<std::uint8_t>( (high << 4) | low)} ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief BCryptで複数byte範囲のdigestを計算する。
 *
 * Fragmentを連結copyせず、OpenPGP規定順で同じhashへ投入する。
 *
 * @param[in] algorithm BCrypt SHA algorithm identifier。
 * @param[in] fragments 順序通りhashへ投入する非所有byte範囲。
 * @param[out] digest Algorithmと同じ長さの出力領域。
 * @return 成功時は0、CNGまたはallocation失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError hashFragments( const PCWSTR									  algorithm,
										const std::span<const std::span<const std::byte>> fragments,
										const std::span<std::byte>						  digest)
{
	BCRYPT_ALG_HANDLE algorithmHandle{} ;	// BCryptCloseAlgorithmProviderで解放するhandle。
	// 指定hash algorithmを開いて計算する一連のCNG status。
	NTSTATUS		  status = BCryptOpenAlgorithmProvider( &algorithmHandle, algorithm, nullptr, 0) ;
	// Hash algorithm provider の初期化失敗を NTSTATUS から変換して返す。
	if( !BCRYPT_SUCCESS( status)) {
		return nativeErrorFromNtstatus( status) ;
	}

	DWORD objectBytes{} ;	// BCrypt hash objectに必要なbyte数。
	DWORD resultBytes{} ;	// BCryptGetPropertyが返したbyte数。
	status = BCryptGetProperty( algorithmHandle, BCRYPT_OBJECT_LENGTH,
							   reinterpret_cast<PUCHAR>( &objectBytes), sizeof( objectBytes),
							   &resultBytes, 0) ;
	DWORD digestBytes{} ;	// Algorithmが返すdigest byte数。
	// 先行 property 照会が成功した場合だけ digest 長を照会する。
	if( BCRYPT_SUCCESS( status)) {
		status = BCryptGetProperty( algorithmHandle, BCRYPT_HASH_LENGTH,
								   reinterpret_cast<PUCHAR>( &digestBytes), sizeof( digestBytes),
								   &resultBytes, 0) ;
	}

	// Property 取得失敗と期待 digest・object size の不成立時は algorithm を解放する。
	if( !BCRYPT_SUCCESS( status) || digestBytes != digest.size() || objectBytes == 0) {
		BCryptCloseAlgorithmProvider( algorithmHandle, 0) ;
		return BCRYPT_SUCCESS( status) ? nativeErrorFromWin32( ERROR_INVALID_DATA)
									  : nativeErrorFromNtstatus( status) ;
	}

	std::vector<UCHAR> object( objectBytes) ;	// BCryptが所有しないhash state buffer。
	BCRYPT_HASH_HANDLE hashHandle{} ;			// BCryptDestroyHashで解放するhandle。
	status =
		BCryptCreateHash( algorithmHandle, &hashHandle, object.data(), objectBytes, nullptr, 0, 0) ;
	// Hash object が生成できた場合だけ fragment を順に投入する。
	if( BCRYPT_SUCCESS( status)) {
		// 全fragmentを順序通り同じhashへ投入する。
		for( const std::span<const std::byte> fragment : fragments) {
			// Fragment 長が暗号 API の範囲を超える場合は narrowing せず中止する。
			if( fragment.size() > std::numeric_limits<ULONG>::max()) {
				status = STATUS_INVALID_PARAMETER ;
				break ;
			}

			status = BCryptHashData(
				hashHandle, const_cast<PUCHAR>( reinterpret_cast<const UCHAR *>( fragment.data())),
				static_cast<ULONG>( fragment.size()), 0) ;
			// Hash 更新に失敗したら残り fragment の投入を中止する。
			if( !BCRYPT_SUCCESS( status)) {
				break ;
			}
		}
	}

	// 全 fragment の処理に成功した場合だけ digest を確定する。
	if( BCRYPT_SUCCESS( status)) {
		status = BCryptFinishHash( hashHandle, reinterpret_cast<PUCHAR>( digest.data()),
								  static_cast<ULONG>( digest.size()), 0) ;
	}

	// 生成済みの hash handle だけを解放する。
	if( hashHandle != nullptr) {
		BCryptDestroyHash( hashHandle) ;
	}

	BCryptCloseAlgorithmProvider( algorithmHandle, 0) ;
	return BCRYPT_SUCCESS( status) ? 0 : nativeErrorFromNtstatus( status) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OpenPGP subpacket集合を検証する。
 *
 * 未知critical typeとpartial lengthを拒否し、issuerを固定鍵へ完全一致させる。
 *
 * @param[in] input Hashedまたはunhashed subpacket領域。
 * @param[in] hashed Hashed領域の場合は`true`。
 * @param[in] fingerprint Provider固定fingerprint。
 * @param[in,out] issuerFingerprintFound Fingerprint重複検出状態。
 * @param[in,out] issuerFound Key ID重複検出状態。
 * @return 全subpacketが形式とissuer条件を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validateSubpackets( const std::span<const std::byte> input, const bool hashed,
									  const std::array<std::byte, SHA1_BYTES> &fingerprint,
									  bool &issuerFingerprintFound, bool &issuerFound)
{
	std::size_t offset{} ;	// 次に読むsubpacket length位置。
	// 宣言lengthごとに有限範囲を進める。
	while( offset < input.size()) {
		const std::uint8_t first = std::to_integer<std::uint8_t>( input[offset++]) ;	// 長さ先頭。
		std::uint64_t	   length{} ;													// Type byteを含むsubpacket body長。
		// 短い subpacket 長は先頭 byte の値を使用する。
		if( first < 192U) {
			length = first ;
		}
		// 二 byte 形式の subpacket 長を追加 byte と結合する。
		else if( first <= 223U) {
			// 二 byte 長の後半が欠ける subpacket を拒否する。
			if( offset >= input.size()) {
				return false ;
			}

			const std::uint8_t second =
				std::to_integer<std::uint8_t>( input[offset++]) ;	// 長さ二byte目。
			length = static_cast<std::uint64_t>( (first - 192U) << 8U) + second + 192U ;
		}
		// 長形式の subpacket では後続四 byte から長さを読む。
		else if( first == 255U) {
			// 四 byte 長 field が入力に収まらない subpacket を拒否する。
			if( offset + 4 > input.size()) {
				return false ;
			}

			length = readU32Be( input, offset) ;
			offset += 4 ;
		} else {
			return false ;
		}

		// 種別 byte を含まない長さと残り入力を超える subpacket を拒否する。
		if( length < 1 || length > input.size() - offset) {
			return false ;
		}

		const std::uint8_t encodedType =
			std::to_integer<std::uint8_t>( input[offset]) ;								// Critical flag付きtype。
		const bool		   critical = (encodedType & 0x80U) != 0 ;						// 未知時に拒否するflag。
		const std::uint8_t type		= static_cast<std::uint8_t>( encodedType & 0x7fU) ;	// Type ID。
		const std::span<const std::byte> data =
			// Subpacket data。
			input.subspan( offset + 1, static_cast<std::size_t>( length - 1)) ;
		const bool known = type == 2 || type == 28 || type == ISSUER_SUBPACKET ||
						   // 対応済みtypeならtrue。
						   type == ISSUER_FINGERPRINT_SUBPACKET ;
		// 未知の critical subpacket を無視して署名を受理しない。
		if( !known && critical) {
			return false ;
		}

		// Issuer fingerprint の subpacket は固定鍵の指紋と厳密に照合する。
		if( type == ISSUER_FINGERPRINT_SUBPACKET) {
			// 未署名領域、重複、version・長さ・指紋の不一致を持つ issuer fingerprint を拒否する。
			if( !hashed || issuerFingerprintFound || data.size() != SHA1_BYTES + 1 ||
			   data[0] != std::byte{4} ||
			   !std::equal( fingerprint.begin(), fingerprint.end(), data.begin() + 1)) {
				return false ;
			}

			issuerFingerprintFound = true ;
		}
		// Issuer key ID は固定 fingerprint 末尾の八 byte と照合する。
		else if( type == ISSUER_SUBPACKET) {
			const auto keyIdBegin = fingerprint.end() - 8 ;	// Fingerprint末尾key ID開始。
			// Issuer ID の領域・重複・長さ・値が許可条件と異なる場合は拒否する。
			if( hashed || issuerFound || data.size() != 8 ||
			   !std::equal( keyIdBegin, fingerprint.end(), data.begin())) {
				return false ;
			}

			issuerFound = true ;
		}
		// 署名作成時刻の field が四 byte でない subpacket を拒否する。
		else if( type == 2 && data.size() != 4) {
			return false ;
		}
		// Signer user ID の空 field は受理しない。
		else if( type == 28 && data.empty()) {
			return false ;
		}

		offset += static_cast<std::size_t>( length) ;
	}

	return offset == input.size() ;
}

//------------------------------------------------------------------------------
/**
 * @brief OpenPGP v4 RSA/SHA-256 signature bodyを解析する。
 *
 * Binary document、RSA、SHA-256、v4 issuerだけを受理する。
 *
 * @param[in] body Signature packet body。
 * @param[in] fingerprint Provider固定公開鍵fingerprint。
 * @param[out] signature 成功時のhashed範囲、digest先頭、RSA MPI。
 * @return 対応形式と固定issuerを満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseSignatureBody( const std::span<const std::byte>		   body,
									  const std::array<std::byte, SHA1_BYTES> &fingerprint,
									  SignatureView							  &signature)
{
	signature = {} ;
	// 最小長、v4、binary document、RSA、SHA-256 の全条件を必須とする。
	if( body.size() < 14 || body[0] != std::byte{4} ||
	   body[1] != std::byte{BINARY_DOCUMENT_SIGNATURE} || body[2] != std::byte{RSA_ALGORITHM} ||
	   body[3] != std::byte{SHA256_ALGORITHM}) {
		return false ;
	}

	const std::size_t hashedLength = readU16Be( body, 4) ;	// Hashed subpacket byte数。
	const std::size_t hashedEnd	   = 6 + hashedLength ;		// Hashed領域直後。
	// Hashed 領域の後に必要な長さ field が収まらなければ拒否する。
	if( hashedEnd + 2 > body.size()) {
		return false ;
	}

	const std::size_t unhashedLength  = readU16Be( body, hashedEnd) ;		// Unhashed領域byte数。
	const std::size_t unhashedBegin	  = hashedEnd + 2 ;						// Unhashed開始位置。
	const std::size_t hashPrefixBegin = unhashedBegin + unhashedLength ;	// Digest先頭位置。
	// Hash prefix と MPI の最小領域が残っていなければ拒否する。
	if( hashPrefixBegin + 4 > body.size()) {
		return false ;
	}

	bool issuerFingerprintFound{} ;	// Hashed issuer fingerprintを一つ検出した場合true。
	bool issuerFound{} ;			// Unhashed issuer key IDを一つ検出した場合true。
	// 両 subpacket 領域を検証し、固定鍵の fingerprint と issuer ID を必須とする。
	if( !validateSubpackets( body.subspan( 6, hashedLength), true, fingerprint, issuerFingerprintFound,
						   issuerFound) ||
	   !validateSubpackets( body.subspan( unhashedBegin, unhashedLength), false, fingerprint,
						   issuerFingerprintFound, issuerFound) ||
	   !issuerFingerprintFound || !issuerFound) {
		return false ;
	}

	std::size_t mpiOffset = hashPrefixBegin + 2 ;	// RSA MPI bit count開始位置。
	MpiView		rsaSignature ;						// 解析するRSA署名MPI。
	// RSA signature MPI が不正または末尾に余分な data があれば拒否する。
	if( !parseMpi( body, mpiOffset, rsaSignature) || mpiOffset != body.size()) {
		return false ;
	}

	signature.hashedPrefix = body.first( hashedEnd) ;
	signature.hashPrefix   = {body[hashPrefixBegin], body[hashPrefixBegin + 1]} ;
	signature.rsaSignature = rsaSignature ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief OpenPGP v4 RSA public-key packet bodyを解析する。
 *
 * Encryption subkey、未知algorithm、trailing dataを拒否する。
 *
 * @param[in] body Public-Key packet body。
 * @param[out] key 成功時のRSA modulusとpublic exponent。
 * @return V4 RSA鍵を余剰byteなしで解析できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parsePublicKeyBody( const std::span<const std::byte> body,
									  PublicKeyView					  &key) noexcept
{
	key = {} ;
	// 最小長、v4、RSA 方式に一致しない公開鍵 body を拒否する。
	if( body.size() < 10 || body[0] != std::byte{4} || body[5] != std::byte{RSA_ALGORITHM}) {
		return false ;
	}

	std::size_t offset = 6 ;	// RSA modulus MPI開始位置。
	// MPI 不正、余剰 data、小さすぎる modulus、長すぎる exponent の鍵を破棄する。
	if( !parseMpi( body, offset, key.modulus) || !parseMpi( body, offset, key.exponent) ||
	   offset != body.size() || key.modulus.bitCount < 2048 || key.exponent.data.size() > 8) {
		key = {} ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief OpenPGP v4 public-key fingerprintを検証する。
 *
 * RFC v4の0x99＋16-bit length＋bodyをSHA-1へ投入する。
 *
 * @param[in] body Public-Key packet body。
 * @param[in] expected Providerへ固定したfingerprint。
 * @return 完全一致時は0、不一致またはCNG失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyPublicKeyFingerprint(
	const std::span<const std::byte> body, const std::array<std::byte, SHA1_BYTES> &expected)
{
	// 空または v4 fingerprint の長さ field を超える公開鍵 body を拒否する。
	if( body.empty() || body.size() > std::numeric_limits<std::uint16_t>::max()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::array prefix{
		std::byte{0x99}, std::byte{static_cast<std::uint8_t>( body.size() >> 8U)},
		std::byte{static_cast<std::uint8_t>( body.size() & 0xffU)}} ;						// V4 fingerprint prefix。
	const std::array fragments{std::span<const std::byte>( prefix), body} ;					// Hash投入順。
	std::array<std::byte, SHA1_BYTES> actual{} ;											// 計算した公開鍵fingerprint。
	const NativeError error = hashFragments( BCRYPT_SHA1_ALGORITHM, fragments, actual) ;	// Hash結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	return actual == expected ? 0 : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Documentとv4 signature trailerのSHA-256を計算する。
 *
 * OpenPGP v4規定のtrailerを追加し、改行変換せずhash化する。
 *
 * @param[in] document Binary document全体。
 * @param[in] hashedPrefix Signature versionからhashed領域末尾。
 * @param[out] digest 計算したSHA-256。
 * @return 成功時は0、長さまたはCNG失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError hashSignedDocument( const std::span<const std::byte>	  document,
											 const std::span<const std::byte>	  hashedPrefix,
											 std::array<std::byte, SHA256_BYTES> &digest)
{
	// 署名 trailer の 32-bit 長 field へ収まらない hashed prefix を拒否する。
	if( hashedPrefix.size() > std::numeric_limits<std::uint32_t>::max()) {
		return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
	}

	const std::uint32_t length = static_cast<std::uint32_t>( hashedPrefix.size()) ;	// Trailer長。
	const std::array	trailer{
		   std::byte{4},
		   std::byte{0xff},
		   std::byte{static_cast<std::uint8_t>( length >> 24U)},
		   std::byte{static_cast<std::uint8_t>( length >> 16U)},
		   std::byte{static_cast<std::uint8_t>( length >> 8U)},
		   std::byte{static_cast<std::uint8_t>( length)}} ;	// OpenPGP v4 signature trailer。
	const std::array fragments{document, hashedPrefix,
							   std::span<const std::byte>( trailer)} ;	// Hash投入順。
	return hashFragments( BCRYPT_SHA256_ALGORITHM, fragments, digest) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CNG RSA public keyでPKCS#1 SHA-256署名を検証する。
 *
 * OpenPGP MPIをBCrypt RSA public blobへ変換し、一回だけ検証する。
 *
 * @param[in] key 検証済みOpenPGP RSA公開鍵値。
 * @param[in] signature OpenPGP RSA署名MPI。
 * @param[in] digest OpenPGP規定順で計算したSHA-256。
 * @return PKCS#1署名一致時は0、不一致またはCNG失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyRsaSignature( const PublicKeyView &key, const MpiView &signature,
											 const std::array<std::byte, SHA256_BYTES> &digest)
{
	// CNG の鍵長範囲超過と modulus より長い署名を拒否する。
	if( key.modulus.data.size() > std::numeric_limits<ULONG>::max() ||
	   key.exponent.data.size() > std::numeric_limits<ULONG>::max() ||
	   signature.data.size() > key.modulus.data.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	BCRYPT_RSAKEY_BLOB header{} ;	// CNG RSA public blob header。
	header.Magic	   = BCRYPT_RSAPUBLIC_MAGIC ;
	header.BitLength   = key.modulus.bitCount ;
	header.cbPublicExp = static_cast<ULONG>( key.exponent.data.size()) ;
	header.cbModulus   = static_cast<ULONG>( key.modulus.data.size()) ;
	std::vector<std::byte> blob( sizeof( header) + key.exponent.data.size() +
								// Header＋exponent＋modulus。
								key.modulus.data.size()) ;
	std::copy_n( reinterpret_cast<const std::byte *>( &header), sizeof( header), blob.begin()) ;
	std::copy( key.exponent.data.begin(), key.exponent.data.end(), blob.begin() + sizeof( header)) ;
	std::copy( key.modulus.data.begin(), key.modulus.data.end(),
			  blob.begin() + sizeof( header) + key.exponent.data.size()) ;

	std::vector<std::byte> paddedSignature(
		// Modulus長へ左zero padした署名。
		key.modulus.data.size()) ;
	std::copy( signature.data.begin(), signature.data.end(),
			  paddedSignature.end() - signature.data.size()) ;
	BCRYPT_ALG_HANDLE algorithmHandle{} ;	// BCryptCloseAlgorithmProviderで解放するhandle。
	// RSA algorithmの開始から公開鍵検証へ引き継ぐCNG status。
	NTSTATUS		  status =
		BCryptOpenAlgorithmProvider( &algorithmHandle, BCRYPT_RSA_ALGORITHM, nullptr, 0) ;
	// RSA algorithm provider を初期化できなければ検証を開始しない。
	if( !BCRYPT_SUCCESS( status)) {
		return nativeErrorFromNtstatus( status) ;
	}

	BCRYPT_KEY_HANDLE keyHandle{} ;	// BCryptDestroyKeyで解放するimport済みkey handle。
	status = BCryptImportKeyPair( algorithmHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB, &keyHandle,
								 reinterpret_cast<PUCHAR>( blob.data()),
								 static_cast<ULONG>( blob.size()), 0) ;
	// 公開鍵の import に成功した場合だけ RSA PKCS#1 SHA-256 署名を検証する。
	if( BCRYPT_SUCCESS( status)) {
		BCRYPT_PKCS1_PADDING_INFO padding{} ;	// RSA PKCS#1 v1.5 hash algorithm指定。
		padding.pszAlgId = BCRYPT_SHA256_ALGORITHM ;
		status			 = BCryptVerifySignature(
			  keyHandle, &padding, const_cast<PUCHAR>( reinterpret_cast<const UCHAR *>( digest.data())),
			  static_cast<ULONG>( digest.size()), reinterpret_cast<PUCHAR>( paddedSignature.data()),
			  static_cast<ULONG>( paddedSignature.size()), BCRYPT_PAD_PKCS1) ;
	}

	// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
	if( keyHandle != nullptr) {
		BCryptDestroyKey( keyHandle) ;
	}

	BCryptCloseAlgorithmProvider( algorithmHandle, 0) ;
	return BCRYPT_SUCCESS( status) ? 0 : nativeErrorFromNtstatus( status) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local file全体を上限付きで読み取る。
 *
 * Reparse pointと非disk fileを拒否し、固定workspaceだけを読む。
 *
 * @param[in] path 読取り対象local絶対path。
 * @param[in] maximumBytes 読取りを許可する最大byte数。
 * @param[out] bytes 成功時のfile全体。失敗時は空。
 * @return 成功時は0、通常file以外、上限超過、I/O失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFileBytes( const std::wstring_view path,
										const std::uint64_t		maximumBytes,
										std::vector<std::byte> &bytes)
{
	bytes.clear() ;
	// 空 path、ゼロ上限、address 空間を超える上限は読取り前に拒否する。
	if( path.empty() || maximumBytes == 0 ||
	   maximumBytes > static_cast<std::uint64_t>( std::numeric_limits<std::size_t>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring pathString( path) ;	// Win32 API用終端null付きpath。
	const UniqueFile   file( CreateFileW(
		  pathString.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		  nullptr)) ;	// 読取り専用所有handle。
	// 対象 file を開けなければ署名検証用の内容を読み取らない。
	if( file.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO tagInfo{} ;	// Reparse point判定用属性。
	// 開いた file の属性を確認できなければ内容取得へ進まない。
	if( GetFileInformationByHandleEx( file.get(), FileAttributeTagInfo, &tagInfo, sizeof( tagInfo)) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Reparse point と disk 以外の対象は通常 file として受理しない。
	if( (tagInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
	   GetFileType( file.get()) != FILE_TYPE_DISK) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	LARGE_INTEGER fileSize{} ;	// Local fileの符号付きbyte数。
	// File size の照会失敗時は読取り量を推測しない。
	if( GetFileSizeEx( file.get(), &fileSize) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 空 file と取得上限を超える内容を拒否する。
	if( fileSize.QuadPart <= 0 || static_cast<std::uint64_t>( fileSize.QuadPart) > maximumBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	bytes.resize( static_cast<std::size_t>( fileSize.QuadPart)) ;
	std::size_t offset{} ;	// 次に読込むbuffer offset。
	// DWORD上限ごとの有限chunkでfile sizeと同数のbyteを読み取る。
	while( offset < bytes.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// 今回の要求byte数。
			bytes.size() - offset, std::numeric_limits<DWORD>::max())) ;
		DWORD		received{} ;	// ReadFileが返した実読取りbyte数。
		// 読取り失敗時は部分内容を破棄し Windows の診断値を返す。
		if( ReadFile( file.get(), bytes.data() + offset, requested, &received, nullptr) == FALSE) {
			bytes.clear() ;
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 予定長より早い終端では不完全な内容を残さない。
		if( received == 0) {
			bytes.clear() ;
			return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
		}

		offset += received ;
	}

	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/openpgp_signature_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyOpenpgpDetachedSignature( const std::span<const std::byte> document,
										   const std::string_view			armoredSignature,
										   const OpenPgpRsaPublicKey	   &publicKey)
{
	try {
		// Document と固定公開鍵・fingerprint の根拠が欠ける検証要求を拒否する。
		if( document.empty() || publicKey.packetBodyBase64.empty() ||
		   publicKey.expectedFingerprint.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::array<std::byte, SHA1_BYTES> fingerprint{} ;	// 解析済み固定fingerprint。
		// 固定 fingerprint の表記が不正なら署名を検証しない。
		if( !parseFingerprint( publicKey.expectedFingerprint, fingerprint)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::vector<std::byte> signaturePacket ;	// Armor CRC検証済みpacket byte列。
		// ASCII Armor を厳密に復元できない署名を拒否する。
		if( !decodeSignatureArmor( armoredSignature, signaturePacket)) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		PacketView packet ;	// Header長とtagを検証するsignature packet view。
		// 単一署名 packet として全 byte を解析できなければ拒否する。
		if( !parsePacket( signaturePacket, packet) || packet.tag != SIGNATURE_PACKET_TAG ||
		   packet.consumedBytes != signaturePacket.size()) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		SignatureView signature ;	// Issuerとalgorithm検証済みsignature値。
		// 署名 body が許可方式と固定鍵の条件を満たさなければ拒否する。
		if( !parseSignatureBody( packet.body, fingerprint, signature)) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		std::vector<std::byte> keyBody ;	// Provider固定Base64から復元したpublic-key body。
		// 固定公開鍵の Base64 が不正な policy を拒否する。
		if( !decodeBase64( publicKey.packetBodyBase64, keyBody)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		PublicKeyView key ;	// RSA modulusとexponentの非所有view。
		// 固定公開鍵 body が有効な RSA 鍵でなければ受理しない。
		if( !parsePublicKeyBody( keyBody, key)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		NativeError error =
			// 固定鍵fingerprint検証結果。
			verifyPublicKeyFingerprint( keyBody, fingerprint) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::array<std::byte, SHA256_BYTES> digest{} ;	// OpenPGP規定のdocument SHA-256。
		error = hashSignedDocument( document, signature.hashedPrefix, digest) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 署名内の hash prefix が計算 digest と一致しなければ検証を拒否する。
		if( digest[0] != signature.hashPrefix[0] || digest[1] != signature.hashPrefix[1]) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		return verifyRsaSignature( key, signature.rsaSignature, digest) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/openpgp_signature_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyOpenpgpDetachedFile( const std::wstring_view	 documentPath,
									  const std::uint64_t		 maximumDocumentBytes,
									  const std::wstring_view	 signaturePath,
									  const std::uint64_t		 maximumSignatureBytes,
									  const OpenPgpRsaPublicKey &publicKey)
{
	try {
		std::vector<std::byte> document ;	// 上限検証済み署名対象file全体。
		NativeError			   error = readFileBytes( documentPath, maximumDocumentBytes,
													 document) ;	// Document読取り結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<std::byte> signatureBytes ;	// 上限検証済みArmor file全体。
		error = readFileBytes( signaturePath, maximumSignatureBytes,
							  signatureBytes) ;	// Signature読取り結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const std::string_view signatureText( reinterpret_cast<const char *>( signatureBytes.data()),
											 // ASCII Armor非所有view。
											 signatureBytes.size()) ;
		return verifyOpenpgpDetachedSignature( document, signatureText, publicKey) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
