//------------------------------------------------------------------------------
/**
 * @file official_sfx.cpp
 * @brief 公式自己解凍形式の静的識別実装
 * @version 01.07.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z形式の静的識別を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate直前zero paddingへ対応
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
 * Ver.01.02.00 Shunji Ogawa  2026/11/23  WiX v3の署名領域と内蔵CABの境界検査を追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/23  公式元取得と同じファイルの署名と読取り範囲を照合
 * Ver.01.04.00 Shunji Ogawa  2026/11/23  PE直後の署名領域内ZIPの範囲検査を追加
 * Ver.01.05.00 Shunji Ogawa  2026/11/23  署名済みPEから元取得に結び付くZIPメンバーを読み取る
 * Ver.01.06.00 Shunji Ogawa  2026/11/24  審査済みNSISの原位置と展開結果を照合する
 * Ver.01.07.00 Shunji Ogawa  2026/11/24  公式元ZIPの取得同一性と唯一の内側EXEを照合する
 * </pre>
 *
 * @note 取得したEXEを実行せず、PEと各形式が指定する内容範囲を検査する
 *       取得証拠を照合する入口だけで配布署名を検証する。元EXEは読取り専用で扱う
 */
//------------------------------------------------------------------------------

#include "platform/official_sfx.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_zip.h"

#include <Windows.h>
#include <wintrust.h>

#include "miniz.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::size_t	DOS_PE_OFFSET_FIELD			 = 0x3cU ;			// DOS header内のPE header offset位置
constexpr std::size_t	COFF_HEADER_BYTES			 = 20U ;			// PE signature後のCOFF header長
constexpr std::size_t	SECTION_HEADER_BYTES		 = 40U ;			// 一つのPE section header長
constexpr std::uint16_t MAXIMUM_SECTIONS			 = 96U ;			// 受理するPE section数の有限上限
constexpr std::size_t	SEVEN_ZIP_HEADER_BYTES		 = 32U ;			// 7z Signature Headerの固定長
constexpr std::size_t	SEVEN_ZIP_START_HEADER_BYTES = 20U ;			// CRC対象Start Header長
constexpr std::size_t	CERTIFICATE_HEADER_BYTES	 = 8U ;				// WIN_CERTIFICATE固定header長
constexpr std::uint64_t CERTIFICATE_ALIGNMENT		 = 8U ;				// Certificate entry境界のbyte数
constexpr std::uint32_t CRC32_POLYNOMIAL			 = 0xedb88320U ;	// IEEE CRC-32反転多項式
constexpr std::array<std::byte, 4> PE_SIGNATURE{std::byte{0x50}, std::byte{0x45}, std::byte{0x00},
												std::byte{0x00}} ;	// PE\0\0 signature
constexpr std::array<std::byte, 6> SEVEN_ZIP_SIGNATURE{
	std::byte{0x37}, std::byte{0x7a}, std::byte{0xbc},
	std::byte{0xaf}, std::byte{0x27}, std::byte{0x1c}} ;	// 7z file signature
constexpr std::array<std::byte, 8U> WIX_BURN_SECTION_NAME{
	std::byte{'.'}, std::byte{'w'}, std::byte{'i'}, std::byte{'x'},
	std::byte{'b'}, std::byte{'u'}, std::byte{'r'}, std::byte{'n'}} ;	// COFFの固定名全体
constexpr std::uint32_t WIX_BURN_MAGIC			 = 0x00f14300U ;		// WiX v3のBurn宣言識別子
constexpr std::uint32_t WIX_BURN_VERSION		 = 2U ;					// 対応するBurn宣言の版
constexpr std::uint32_t WIX_BURN_CAB_FORMAT		 = 1U ;					// Burn宣言のCAB形式
constexpr std::uint32_t WIX_BURN_CONTAINER_COUNT = 2U ;					// 起動用と添付の二CAB
constexpr std::uint64_t WIX_BURN_HEADER_BYTES	 = 56U ;				// 二CABの元長を含む宣言の全長
constexpr std::uint32_t CAB_MAGIC			= 0x4643534dU ;				// CABのMSCF識別子をlittle-endianで読む値
constexpr std::uint64_t CAB_HEADER_BYTES	= 36U ;						// CAB共通ヘッダーの最小byte数
constexpr std::uint32_t ZIP_LOCAL_SIGNATURE = 0x04034b50U ;				// ZIPローカルヘッダー識別子
constexpr std::uint32_t ZIP_DIRECTORY_SIGNATURE	 = 0x02014b50U ;		// ZIP中央ディレクトリエントリ識別子
constexpr std::uint32_t ZIP_END_SIGNATURE		 = 0x06054b50U ;		// ZIP中央ディレクトリ終端識別子
constexpr std::uint32_t ZIP64_LOCATOR_SIGNATURE	 = 0x07064b50U ;		// ZIP64終端参照の識別子
constexpr std::uint32_t ZIP_DESCRIPTOR_SIGNATURE = 0x08074b50U ;		// 省略可能なデータ記述子識別子
constexpr std::uint64_t ZIP_LOCAL_HEADER_BYTES	 = 30U ;				// ローカルヘッダーの固定長
constexpr std::uint64_t ZIP_DIRECTORY_HEADER_BYTES = 46U ;				// 中央ディレクトリエントリの固定長
constexpr std::uint64_t ZIP_END_BYTES			   = 22U ;				// ZIP終端レコードの固定長
constexpr std::uint64_t ZIP64_LOCATOR_BYTES		   = 20U ;				// ZIP64終端参照の固定長
constexpr std::uint64_t ZIP_DESCRIPTOR_BYTES	   = 12U ;				// CRCと32-bitの二つの長さ
constexpr std::uint16_t ZIP_HAS_DESCRIPTOR		   = 0x0008U ;			// ローカルデータ後に記述子があるflag
constexpr std::uint16_t ZIP_METHOD_STORED		   = 0U ;				// 無圧縮データの方式

constexpr std::uint64_t MAXIMUM_PE_CERTIFICATE_BYTES =
	1024U * 1024U ;	// 主署名と証明書鎖の読取り上限

constexpr std::size_t	   NSIS_MAXIMUM_EXE		   = 32U * 1024U * 1024U ;	// 審査済み内側EXEの上限
constexpr std::size_t	   NSIS_MAXIMUM_HEADER	   = 1024U * 1024U ;		// 展開する命令と文字列表の上限
constexpr std::uint32_t	   NSIS_MAXIMUM_COMMANDS   = 4096U ;				// 命令と物理ブロック数の上限
constexpr std::size_t	   NSIS_MAXIMUM_SINGLE	   = 16U * 1024U * 1024U ;	// 一メンバーの展開上限
constexpr std::size_t	   NSIS_MAXIMUM_TOTAL	   = 32U * 1024U * 1024U ;	// 選択メンバーの合計上限
constexpr std::size_t	   NSIS_MAXIMUM_MEMBERS	   = 64U ;					// 一審査版で読み取る通常メンバー数
constexpr std::size_t	   NSIS_FIRST_HEADER_BYTES = 28U ;					// 署名、展開長、末尾までの元長を含む
constexpr std::size_t	   NSIS_COMMAND_BYTES	   = 28U ;					// 命令番号と六つの引数の元幅
constexpr std::uint32_t	   NSIS_DEFLATE_TAG		   = 0x80000000U ;			// 長さから分離する圧縮bit
constexpr std::uint32_t	   NSIS_SET_DIRECTORY	   = 11U ;					// 審査形式のディレクトリ記録番号
constexpr std::uint32_t	   NSIS_EXTRACT_FILE	   = 20U ;					// 審査形式のファイル記録番号
constexpr std::string_view NSIS_SIGNATURE{"\xef\xbe\xad\xde"
										  "NullsoftInst"} ;	// 先頭宣言の原識別子
constexpr std::string_view NSIS_ROOT{"\xfd\x95\x80"} ;		// 審査形式の元ルートtoken
constexpr std::string_view NSIS_X64{"\xfd\x95\x80\\x64"} ;	// 審査形式のAMD64ディレクトリ原文

//------------------------------------------------------------------------------
// 内部型定義
//------------------------------------------------------------------------------

/**
 * @brief 検証済みPE imageとcertificate tableの境界を保持する
 */
struct PeLayout {
	/// Headerとraw sectionを包含する末尾offset
	std::uint64_t imageEnd{} ;
	/// 付加内容と許可paddingが終了すべきfile offset
	std::uint64_t archiveLimit{} ;
	/// Certificate table先頭。存在しない場合は0
	std::uint64_t certificateOffset{} ;
	/// Certificate table長。存在しない場合は0
	std::uint64_t certificateSize{} ;
	/// 検証済みsection header tableの先頭
	std::uint64_t sectionTableOffset{} ;
	/// 検証済みsection headerの件数
	std::uint16_t sectionCount{} ;
	/// COFFが宣言する外側PEのmachine
	std::uint16_t machine{} ;
	/// PE32またはPE32+を示すoptional headerの値
	std::uint16_t optionalMagic{} ;
} ;

/**
 * @brief 同じ元EXEの長さタグに結び付く有界ブロック
 */
struct ReviewedNsisBlock {
	/// 元EXE内の長さタグ位置
	std::size_t				   position ;
	/// 長さタグを除いた元データを同期読取り中だけ借用する
	std::span<const std::byte> data ;
	/// 審査済み形式の独立DEFLATEの場合true
	bool					   deflated ;
} ;

/** @brief 末尾証明書との照合で確定した単一ZIPの終端と中央ディレクトリ */
struct ZipEnd {
	/// ZIP終端レコードのfile offset。中央ディレクトリ直後
	std::uint64_t offset ;
	/// コメントを含むZIPの直後で、署名用の整列を含まないfile offset
	std::uint64_t archiveEnd ;
	/// 中央ディレクトリのfile offset
	std::uint64_t directoryOffset ;
	/// ZIP内のオフセットを実file位置に換算する加算値
	std::uint64_t offsetBase ;
	/// ディレクトリを含む全エントリの件数
	std::uint16_t entryCount ;
} ;

/** @brief 一件のローカルヘッダーから圧縮データ・記述子までを含む範囲 */
struct ZipLocalRange {
	/// ローカルヘッダーのfile offset
	std::uint64_t begin ;
	/// このエントリの直後のfile offset
	std::uint64_t end ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する
 *
 * 構造不正と上限超過をProvider共通診断型へ保持する
 *
 * @param[in] error 検証失敗を表すWin32 error code
 * @return HRESULT_FROM_WIN32で変換したbit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 加算可能なfile rangeか確認する
 *
 * 未信頼offsetをindexへ変換する前にfile境界を検証する
 *
 * @param[in] input 検査対象file全体
 * @param[in] offset 確認するrangeの開始offset
 * @param[in] length 確認するrangeのbyte数
 * @return 加算overflowせず入力内へ完全に収まる場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasRange( const std::span<const std::byte> input, const std::uint64_t offset,
							const std::uint64_t length) noexcept
{
	const std::uint64_t inputSize = static_cast<std::uint64_t>( input.size()) ;	// 入力長
	return offset <= inputSize && length <= inputSize - offset ;
}

//------------------------------------------------------------------------------
/**
 * @brief 64-bit値をoverflowなしで加算する
 *
 * PE／7zが持つ64-bit offsetのwraparoundを拒否する
 *
 * @param[in] left 左辺値
 * @param[in] right 右辺値
 * @param[out] result 成功時の加算結果。失敗時は変更しない
 * @return 加算可能な場合は`true`、overflowする場合は`false`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool checkedAdd( const std::uint64_t left, const std::uint64_t right,
							  std::uint64_t &result) noexcept
{
	// 加算前に 64-bit の残余範囲を確認し、overflow を拒否する
	if( right > std::numeric_limits<std::uint64_t>::max() - left) {
		return false ;
	}

	result = left + right ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 16-bit値を読み取る
 *
 * Alignmentとhost endianに依存せず値を復元する
 *
 * @param[in] input 事前にrangeを検証した入力file
 * @param[in] offset 2 byteを読める検証済みoffset
 * @return Little-endianから復元した16-bit値
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint16_t readU16Le( const std::span<const std::byte> input,
									  const std::uint64_t			   offset) noexcept
{
	const std::size_t	index = static_cast<std::size_t>( offset) ;					// 検証済み配列index
	const std::uint16_t low	  = std::to_integer<std::uint8_t>( input[index]) ;		// 下位byte
	const std::uint16_t high  = std::to_integer<std::uint8_t>( input[index + 1U]) ;	// 上位byte
	return static_cast<std::uint16_t>( low | static_cast<std::uint16_t>( high << 8U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 32-bit値を読み取る
 *
 * Alignmentとhost endianに依存せず値を復元する
 *
 * @param[in] input 事前にrangeを検証した入力file
 * @param[in] offset 4 byteを読める検証済みoffset
 * @return Little-endianから復元した32-bit値
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t readU32Le( const std::span<const std::byte> input,
									  const std::uint64_t			   offset) noexcept
{
	std::uint32_t value{} ;	// 入力から復元する値
	// 4 byteを下位側から順に配置する
	for( std::uint64_t byteIndex = 0; byteIndex < 4U; ++byteIndex) {
		const std::size_t inputIndex =
			// 現在byteの配列index
			static_cast<std::size_t>( offset + byteIndex) ;
		const std::uint32_t part = std::to_integer<std::uint8_t>( input[inputIndex]) ;	// 現在byteの値
		value |= part << static_cast<unsigned int>( byteIndex * 8U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 64-bit値を読み取る
 *
 * Alignmentとhost endianに依存せず値を復元する
 *
 * @param[in] input 事前にrangeを検証した入力file
 * @param[in] offset 8 byteを読める検証済みoffset
 * @return Little-endianから復元した64-bit値
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t readU64Le( const std::span<const std::byte> input,
									  const std::uint64_t			   offset) noexcept
{
	std::uint64_t value{} ;	// 入力から復元する値
	// 8 byteを下位側から順に配置する
	for( std::uint64_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
		const std::size_t inputIndex =
			// 現在byteの配列index
			static_cast<std::size_t>( offset + byteIndex) ;
		const std::uint64_t part = std::to_integer<std::uint8_t>( input[inputIndex]) ;	// 現在byteの値
		value |= part << static_cast<unsigned int>( byteIndex * 8U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief CRC-32を算出する
 *
 * Tableを持たない有限loopで7z headerの破損を検出する
 *
 * @param[in] input CRC対象byte列。有効期間は本呼出し中に限る
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
 * @brief PE certificate tableの連続性を検証する
 *
 * 未信頼dwLengthによる停滞、越境、端数をfail-closedで拒否する
 *
 * @param[in] input EXE全体
 * @param[in] offset Certificate table先頭offset
 * @param[in] size Certificate table全体のbyte数
 * @param[in] signedDataOnly trueの場合は全entryにPKCSの型と実データ、zero paddingも要求する
 * @return 全entryが8-byte境界でtable全体を埋め、要求された種別が成立した場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inspectCertificateTable( const std::span<const std::byte> input,
										   const std::uint64_t offset, const std::uint64_t size,
										   const bool signedDataOnly = false) noexcept
{
	std::uint64_t tableEnd{} ;	// Certificate table直後のoffset
	// Certificate table の終端 overflow と入力範囲外を拒否する
	if( !checkedAdd( offset, size, tableEnd) || !hasRange( input, offset, size)) {
		return false ;
	}

	std::uint64_t cursor = offset ;	// 現在検査中のWIN_CERTIFICATE先頭
	// 各entryを8-byte alignment込みで進め、table末尾への完全一致を確認する
	while( cursor < tableEnd) {
		// Certificate header の全 byte が残っていなければ解析しない
		if( tableEnd - cursor < CERTIFICATE_HEADER_BYTES) {
			return false ;
		}

		const std::uint64_t certificateLength =
			// Paddingを除く現在entry長
			readU32Le( input, cursor) ;
		// Certificate 長が header 自体より短い構造を拒否する
		if( certificateLength < CERTIFICATE_HEADER_BYTES) {
			return false ;
		}

		std::uint64_t lengthWithPadding{} ;	// 8-byte境界へ切り上げたentry消費長
		// Alignment padding の加算が overflow する certificate を拒否する
		if( !checkedAdd( certificateLength, CERTIFICATE_ALIGNMENT - 1U, lengthWithPadding)) {
			return false ;
		}

		lengthWithPadding &= ~(CERTIFICATE_ALIGNMENT - 1U) ;
		std::uint64_t nextCursor{} ;	// 次entryまたはtable末尾のoffset
		// 次の certificate 位置が overflow または table 終端超過なら拒否する
		if( !checkedAdd( cursor, lengthWithPadding, nextCursor) || nextCursor > tableEnd) {
			return false ;
		}

		// WiXの署名領域にはデータを持つPKCS entryとその必要最小のzero paddingだけを認める
		if( signedDataOnly) {
			const auto padding =
				input.subspan( static_cast<std::size_t>( cursor + certificateLength),
							  static_cast<std::size_t>( lengthWithPadding -
													   certificateLength)) ;	// 構造上の整列byte
			// 他種別や空entryを証明書領域の成立条件に流用しない
			if( certificateLength == CERTIFICATE_HEADER_BYTES ||
			   readU16Le( input, cursor + 4U) != WIN_CERT_REVISION_2_0 ||
			   readU16Le( input, cursor + 6U) != WIN_CERT_TYPE_PKCS_SIGNED_DATA ||
			   !std::ranges::all_of( padding,
									[]( std::byte value) { return value == std::byte{} ; })) {
				return false ;
			}
		}

		cursor = nextCursor ;
	}

	return cursor == tableEnd ;
}

//------------------------------------------------------------------------------
/**
 * @brief PE imageとcertificate tableの境界を検証する
 *
 * Loaderを呼ばず、raw file構造から検証済みsectionと付加内容の境界を決める
 *
 * @param[in] input EXE全体
 * @param[out] layout 成功時のimage、archive、certificateとsection tableの境界。失敗時は既定値
 * @return PE32／PE32+のheaderと全file rangeが妥当なら`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inspectPeLayout( const std::span<const std::byte> input,
								   PeLayout						   &layout) noexcept
{
	layout = {} ;
	// DOS header の必要領域と MZ signature がない入力を PE と扱わない
	if( !hasRange( input, 0U, DOS_PE_OFFSET_FIELD + sizeof( std::uint32_t)) ||
	   input[0] != std::byte{0x4d} || input[1] != std::byte{0x5a}) {
		return false ;
	}

	const std::uint64_t		peOffset = readU32Le( input, DOS_PE_OFFSET_FIELD) ;	// PE先頭offset
	constexpr std::uint64_t PE_AND_COFF_BYTES =
		// PE signatureとCOFF headerの合計長
		PE_SIGNATURE.size() + COFF_HEADER_BYTES ;
	// PE・COFF header が入力範囲に収まらなければ解析を中止する
	if( !hasRange( input, peOffset, PE_AND_COFF_BYTES)) {
		return false ;
	}

	// PE識別子4 byteを完全一致で確認する
	for( std::size_t index = 0; index < PE_SIGNATURE.size(); ++index) {
		const std::size_t inputIndex =
			// PE signature内の配列index
			static_cast<std::size_t>( peOffset) + index ;
		// PE signature の一 byte でも異なる入力を拒否する
		if( input[inputIndex] != PE_SIGNATURE[index]) {
			return false ;
		}
	}

	const std::uint64_t coffOffset	 = peOffset + PE_SIGNATURE.size() ;		// COFF header先頭offset
	const std::uint16_t sectionCount = readU16Le( input, coffOffset + 2U) ;	// COFF NumberOfSections
	const std::uint16_t optionalHeaderSize =
		// COFF SizeOfOptionalHeader
		readU16Le( input, coffOffset + 16U) ;
	// Section 数がゼロまたは検証上限を超える PE を拒否する
	if( sectionCount == 0U || sectionCount > MAXIMUM_SECTIONS) {
		return false ;
	}

	const std::uint64_t optionalOffset =
		coffOffset + COFF_HEADER_BYTES ;	// Optional header先頭offset
	// Optional header の範囲と magic の読取り領域を確認する
	if( !hasRange( input, optionalOffset, optionalHeaderSize) ||
	   optionalHeaderSize < sizeof( std::uint16_t)) {
		return false ;
	}

	const std::uint16_t optionalMagic = readU16Le( input, optionalOffset) ;	// PE32／PE32+識別値
	std::uint64_t		directoryCountOffset{} ;							// NumberOfRvaAndSizesのoptional内offset
	std::uint64_t		directoryOffset{} ;									// Data directory配列のoptional内offset
	// PE32 の header 配置に従って data directory の位置を選ぶ
	if( optionalMagic == 0x010bU) {
		directoryCountOffset = 92U ;
		directoryOffset		 = 96U ;
	}
	// PE32+ の header 配置に従って data directory の位置を選ぶ
	else if( optionalMagic == 0x020bU) {
		directoryCountOffset = 108U ;
		directoryOffset		 = 112U ;
	} else {
		return false ;
	}

	// Data directory の件数と header size の必要 field が欠ける PE を拒否する
	if( optionalHeaderSize < directoryOffset ||
	   !hasRange( input, optionalOffset + directoryCountOffset, sizeof( std::uint32_t)) ||
	   !hasRange( input, optionalOffset + 60U, sizeof( std::uint32_t))) {
		return false ;
	}

	const std::uint64_t sectionTableOffset =
		optionalOffset + optionalHeaderSize ;	// 最初のsection header位置
	const std::uint64_t sectionTableSize =
		// 全section header長
		static_cast<std::uint64_t>( sectionCount) * SECTION_HEADER_BYTES ;
	// Section table 全体が入力範囲に収まらなければ拒否する
	if( !hasRange( input, sectionTableOffset, sectionTableSize)) {
		return false ;
	}

	std::uint64_t sectionTableEnd{} ;	// Section table直後のoffset
	// Section table の終端計算が overflow する入力を拒否する
	if( !checkedAdd( sectionTableOffset, sectionTableSize, sectionTableEnd)) {
		return false ;
	}

	const std::uint64_t sizeOfHeaders =
		// PE SizeOfHeaders値
		readU32Le( input, optionalOffset + 60U) ;
	// Header 宣言長が section table を覆わない場合と入力超過を拒否する
	if( sizeOfHeaders < sectionTableEnd || !hasRange( input, 0U, sizeOfHeaders)) {
		return false ;
	}

	std::uint64_t imageEnd = sizeOfHeaders ;	// 全raw sectionを包含する末尾offset
	// 全sectionのraw rangeを検証し、最大末尾をimage境界とする
	for( std::uint16_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
		const std::uint64_t sectionOffset =
			sectionTableOffset +
			// 現在header位置
			static_cast<std::uint64_t>( sectionIndex) * SECTION_HEADER_BYTES ;
		const std::uint64_t rawSize	  = readU32Le( input, sectionOffset + 16U) ;	// SizeOfRawData
		const std::uint64_t rawOffset = readU32Le( input, sectionOffset + 20U) ;	// PointerToRawData
		// Raw data を持たない section は file 内領域の照合から除外する
		if( rawSize == 0U) {
			continue ;
		}

		// Section data が header と重なる場合と入力範囲外を拒否する
		if( rawOffset < sizeOfHeaders || !hasRange( input, rawOffset, rawSize)) {
			return false ;
		}

		std::uint64_t rawEnd{} ;	// 現在raw section直後のoffset
		// Section data 終端の overflow を検出したら領域比較を行わない
		if( !checkedAdd( rawOffset, rawSize, rawEnd)) {
			return false ;
		}

		// Raw section同士の重複を拒否し、曖昧なimage末尾を作らない
		for( std::uint16_t priorIndex = 0; priorIndex < sectionIndex; ++priorIndex) {
			const std::uint64_t priorSectionOffset =
				sectionTableOffset + static_cast<std::uint64_t>( priorIndex) *
										 SECTION_HEADER_BYTES ;	// 先行section header位置
			const std::uint64_t priorRawSize =
				// 先行section raw長
				readU32Le( input, priorSectionOffset + 16U) ;
			const std::uint64_t priorRawOffset =
				// 先行section raw位置
				readU32Le( input, priorSectionOffset + 20U) ;
			// 過去 section に raw data がなければ領域重複の比較を省く
			if( priorRawSize == 0U) {
				continue ;
			}

			std::uint64_t priorRawEnd{} ;	// 先行raw section直後のoffset
			// 過去 section の終端 overflow または section 間の領域重複を拒否する
			if( !checkedAdd( priorRawOffset, priorRawSize, priorRawEnd) ||
			   (rawOffset < priorRawEnd && priorRawOffset < rawEnd)) {
				return false ;
			}
		}

		imageEnd = std::max( imageEnd, rawEnd) ;
	}

	const std::uint64_t directoryCount =
		// Data directory数
		readU32Le( input, optionalOffset + directoryCountOffset) ;
	std::uint64_t			certificateOffset{} ;			// Security directoryのfile offset
	std::uint64_t			certificateSize{} ;				// Security directoryのbyte数
	constexpr std::uint64_t SECURITY_DIRECTORY_INDEX = 4U ;	// Certificate tableのdirectory index
	constexpr std::uint64_t DIRECTORY_ENTRY_BYTES	 = 8U ;	// 一data directoryの固定長
	// Security directory が宣言されている場合だけ certificate table を照会する
	if( directoryCount > SECURITY_DIRECTORY_INDEX) {
		const std::uint64_t securityEntryOffset =
			optionalOffset + directoryOffset +
			SECURITY_DIRECTORY_INDEX * DIRECTORY_ENTRY_BYTES ;	// Security directory位置
		// Security directory entry が optional header と入力範囲に収まることを確認する
		if( optionalHeaderSize <
			   directoryOffset + (SECURITY_DIRECTORY_INDEX + 1U) * DIRECTORY_ENTRY_BYTES ||
		   !hasRange( input, securityEntryOffset, DIRECTORY_ENTRY_BYTES)) {
			return false ;
		}

		certificateOffset = readU32Le( input, securityEntryOffset) ;
		certificateSize	  = readU32Le( input, securityEntryOffset + 4U) ;
	}

	const std::uint64_t inputSize	 = static_cast<std::uint64_t>( input.size()) ;	// EXE全体長
	std::uint64_t		archiveLimit = inputSize ;									// Certificateがない場合の7z末尾上限
	// Certificate の offset と size の片方だけがゼロの不整合を拒否する
	if( (certificateOffset == 0U) != (certificateSize == 0U)) {
		return false ;
	}

	// Certificate table がある場合はその配置と連続性を検証する
	if( certificateOffset != 0U) {
		std::uint64_t certificateEnd{} ;	// Certificate table直後のoffset
		// Alignment、size、image 後方配置、file 終端一致、table 構造を全て必須とする
		if( (certificateOffset % CERTIFICATE_ALIGNMENT) != 0U ||
		   certificateSize < CERTIFICATE_HEADER_BYTES || certificateOffset <= imageEnd ||
		   !checkedAdd( certificateOffset, certificateSize, certificateEnd) ||
		   certificateEnd != inputSize ||
		   !inspectCertificateTable( input, certificateOffset, certificateSize)) {
			return false ;
		}

		archiveLimit = certificateOffset ;
	}

	// PE image 後方に archive を置ける領域がない入力を拒否する
	if( archiveLimit <= imageEnd) {
		return false ;
	}

	layout = PeLayout{imageEnd,
					  archiveLimit,
					  certificateOffset,
					  certificateSize,
					  sectionTableOffset,
					  sectionCount,
					  readU16Le( input, coffOffset),
					  optionalMagic} ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificate直前のzero alignment paddingを検証する
 *
 * CABまたは7zの終了位置を直後の証明書テーブル境界と照合する
 *
 * @param[in] input EXE全体
 * @param[in] certificateOffset 証明書テーブルの開始位置
 * @param[in] archiveEnd 元形式のarchive直後のoffset
 * @return Certificate用の必要最小zero paddingだけなら`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inspectCertificateAlignmentPadding( const std::span<const std::byte> input,
													  const std::uint64_t certificateOffset,
													  const std::uint64_t archiveEnd) noexcept
{
	// 署名との重なりや8-byte境界を満たさないテーブル位置を拒否する
	if( archiveEnd > certificateOffset || certificateOffset % CERTIFICATE_ALIGNMENT != 0U) {
		return false ;
	}

	const std::uint64_t actualPaddingSize =
		certificateOffset - archiveEnd ;	// archive終端から証明書までの実間隔

	const std::uint64_t expectedPaddingSize =
		(CERTIFICATE_ALIGNMENT - (archiveEnd % CERTIFICATE_ALIGNMENT)) %
		CERTIFICATE_ALIGNMENT ;	// 次の8-byte境界へ揃えるための唯一の長さ
	// 過大、誤alignmentまたはfile範囲外の間隔を拒否する
	if( actualPaddingSize != expectedPaddingSize ||
	   !hasRange( input, archiveEnd, actualPaddingSize)) {
		return false ;
	}

	// paddingIndexは必要なpaddingを先頭から検査するbyte位置
	// 必要なpadding全byteを確認し、未監査trailerをzeroとみなさない
	for( std::uint64_t paddingIndex = 0U; paddingIndex < actualPaddingSize; ++paddingIndex) {
		const std::size_t inputIndex =
			// 現在paddingの配列index
			static_cast<std::size_t>( archiveEnd + paddingIndex) ;
		// Certificate 直前の padding にゼロ以外の data があれば拒否する
		if( input[inputIndex] != std::byte{0x00}) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名直前のZIP終端レコードを中央ディレクトリと一つのオフセット基準に結ぶ
 * @param[in] input 元EXE全体
 * @param[in] pe 同じ元EXEで検証済みのPE末尾と証明書領域
 * @param[in] offset 固定長の終端レコードを読める候補位置
 * @return 単一ディスクの構造、中央ディレクトリ、コメントと整列が成立した場合の境界
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<ZipEnd> readZipEnd( const std::span<const std::byte> input,
											   const PeLayout				   &pe,
											   const std::uint64_t				offset) noexcept
{
	const std::uint16_t count		   = readU16Le( input, offset + 10U) ;	// 全中央エントリ数
	const std::uint64_t directorySize  = readU32Le( input, offset + 12U) ;	// 宣言された中央領域長
	const std::uint64_t declaredOffset = readU32Le( input, offset + 16U) ;	// 元基準での中央領域位置
	const std::uint64_t end			   = offset + ZIP_END_BYTES ;			// コメントの開始位置
	const std::uint64_t commentSize	   = readU16Le( input, offset + 20U) ;	// 元コメント長
	// 複数ディスク、ZIP64の番兵値、空や領域外の中央ディレクトリはこの形式で扱わない
	if( readU16Le( input, offset + 4U) != 0U || readU16Le( input, offset + 6U) != 0U ||
	   readU16Le( input, offset + 8U) != count || count == 0U ||
	   count == std::numeric_limits<std::uint16_t>::max() ||
	   declaredOffset == std::numeric_limits<std::uint32_t>::max() ||
	   directorySize < static_cast<std::uint64_t>( count) * ZIP_DIRECTORY_HEADER_BYTES ||
	   directorySize > offset - pe.imageEnd || commentSize > pe.certificateOffset - end ||
	   !inspectCertificateAlignmentPadding( input, pe.certificateOffset, end + commentSize)) {
		return std::nullopt ;
	}

	// 共通ZIP処理がZIP64として解釈する終端参照を、固定長の中央領域内に許可しない
	if( readU32Le( input, offset - ZIP64_LOCATOR_BYTES) == ZIP64_LOCATOR_SIGNATURE) {
		return std::nullopt ;
	}

	const std::uint64_t directory = offset - directorySize ;	// 終端直前の実中央領域位置
	// 実中央領域との一意な差がPE先頭またはZIP先頭を示す場合だけ基準を確定する
	if( declaredOffset > directory ||
	   (directory != declaredOffset && directory - declaredOffset != pe.imageEnd)) {
		return std::nullopt ;
	}

	return ZipEnd{offset, end + commentSize, directory, directory - declaredOffset, count} ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIPコメントの最大長と最小整列から一意な終端候補を探す
 * @param[in] input 元EXE全体
 * @param[in] pe 検証済みPE末尾、証明書先頭
 * @return 一意な終端候補と中央領域。欠落、曖昧な終端、範囲外の場合は空
 * @note 中央領域の全件検査を候補ごとに繰り返さない
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<ZipEnd> findZipEnd( const std::span<const std::byte> input,
											   const PeLayout				   &pe) noexcept
{
	constexpr std::uint64_t MAXIMUM_TAIL_BYTES = ZIP_END_BYTES +
												 std::numeric_limits<std::uint16_t>::max() +
												 CERTIFICATE_ALIGNMENT - 1U ;	// 終端探索幅
	// 固定長の終端さえ証明書の前に置けない場合は走査しない
	if( pe.certificateOffset - pe.imageEnd < ZIP_END_BYTES) {
		return std::nullopt ;
	}

	const std::uint64_t first =
		pe.certificateOffset -
		(std::min)( pe.certificateOffset - pe.imageEnd, MAXIMUM_TAIL_BYTES) ;	// 最も早い候補
	const std::uint64_t	  last = pe.certificateOffset - ZIP_END_BYTES ;			// 最後の固定長候補
	std::optional<ZipEnd> found ;												// 一意性が確認できるまで保持する候補
	// 最大コメント長の範囲を一度だけ走査し、署名直前に成立する終端を確認する
	for( std::uint64_t offset = first; offset <= last; ++offset) {
		// 識別子の一致がある場合だけ固定部と末尾の整列を検査する
		if( readU32Le( input, offset) != ZIP_END_SIGNATURE) {
			continue ;
		}

		const auto candidate = readZipEnd( input, pe, offset) ;	// 構造と基準を満たす候補
		// 共通ZIP処理が末尾から先に選ぶ識別子や、第二の成立候補があれば拒否する
		if( found && (candidate || offset <= found->archiveEnd - ZIP_END_BYTES)) {
			return std::nullopt ;
		}

		// 成立しない識別子で既に確認した候補を置換しない
		if( candidate) {
			found = candidate ;
		}
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIPのCRCと圧縮前後の長さを中央宣言と照合する
 * @param[in] input 両方の12 byteを検証済みの元入力
 * @param[in] central 中央ヘッダーのCRCから始まる三値の先頭
 * @param[in] other ローカルヘッダーまたは記述子にある三値の先頭
 * @param[in] allowZero 記述子が後続するローカルヘッダーのゼロ欄を許可する場合true
 * @return 各値が同じ、または許可されたゼロ欄の場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesZipDataFields( const std::span<const std::byte> input,
										const std::uint64_t central, const std::uint64_t other,
										const bool allowZero = false) noexcept
{
	// CRC、圧縮長、展開長をそれぞれ元の32-bit値で比較する
	for( std::uint64_t field = 0U; field < ZIP_DESCRIPTOR_BYTES; field += 4U) {
		const std::uint32_t value = readU32Le( input, other + field) ;	// 比較する元の値
		// 記述子のない位置や正式な記述子ではゼロを未指定として扱わない
		if( readU32Le( input, central + field) != value && (!allowZero || value != 0U)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 圧縮データに続く一意な32-bit ZIPデータ記述子の長さを確認する
 * @param[in] input 元EXE全体。中央ヘッダーの元CRCと長さは読取り可能
 * @param[in] directory ローカル領域の終端となる中央ディレクトリ先頭
 * @param[in] dataEnd 圧縮データ直後。directory以下
 * @param[in] centralData 中央ヘッダーの元CRCと長さ三値の位置
 * @return 一意に一致する記述子長。欠落、越境、曖昧な場合は0
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t readZipDescriptorSize( const std::span<const std::byte> input,
												  const std::uint64_t			   directory,
												  const std::uint64_t			   dataEnd,
												  const std::uint64_t centralData) noexcept
{
	const std::uint64_t available = directory - dataEnd ;	// 中央領域の前で使えるbyte数
	const bool			unmarked  = available >= ZIP_DESCRIPTOR_BYTES &&
						  // 識別子なしの正式な値
						  matchesZipDataFields( input, centralData, dataEnd) ;
	const bool marked = available >= ZIP_DESCRIPTOR_BYTES + 4U &&
						readU32Le( input, dataEnd) == ZIP_DESCRIPTOR_SIGNATURE &&
						// 識別子を持つ正式な値
						matchesZipDataFields( input, centralData, dataEnd + 4U) ;
	// CRCが識別子と同値でも、一意な元記述子であることを要求する
	if( unmarked == marked) {
		return 0U ;
	}

	return ZIP_DESCRIPTOR_BYTES + (marked ? 4U : 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 中央エントリの名前、内容長と相互参照を同じZIPのローカル領域に限定する
 * @param[in] input 元EXE全体
 * @param[in] archiveOffset PE直後のZIP先頭
 * @param[in] zip 中央領域と同じパッケージのオフセット基準
 * @param[in] entry 固定長と可変欄を検証済みの中央エントリ
 * @param[in] nameSize 中央エントリの完全な名前のbyte数
 * @return ローカルヘッダー、圧縮データと記述子の境界。越境または不一致時は空
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<ZipLocalRange> readZipLocalRange( const std::span<const std::byte> input,
															 const std::uint64_t archiveOffset,
															 const ZipEnd		&zip,
															 const std::uint64_t entry,
															 const std::uint16_t nameSize) noexcept
{
	const auto localArea =
		// ZIP中央より前
		input.first( static_cast<std::size_t>( zip.directoryOffset)) ;
	const std::uint64_t start = zip.offsetBase + readU32Le( input, entry + 42U) ;	// 実ローカル位置
	const std::uint16_t flags = readU16Le( input, entry + 8U) ;						// 中央宣言の元flags
	const bool			descriptor = (flags & ZIP_HAS_DESCRIPTOR) != 0U ;			// 後続記述子の有無
	const std::uint16_t method	   = readU16Le( input, entry + 10U) ;				// 両ヘッダーに共通の圧縮方式
	// PEや中央領域を指す参照、中央とは違う名前長・圧縮方式・flagsを拒否する
	if( start < archiveOffset || !hasRange( localArea, start, ZIP_LOCAL_HEADER_BYTES) ||
	   readU32Le( input, start) != ZIP_LOCAL_SIGNATURE || readU16Le( input, start + 6U) != flags ||
	   readU16Le( input, start + 8U) != method || readU16Le( input, start + 26U) != nameSize ||
	   !matchesZipDataFields( input, entry + 16U, start + 14U, descriptor)) {
		return std::nullopt ;
	}

	const std::uint64_t localName	= start + ZIP_LOCAL_HEADER_BYTES ;	// ローカルの名前先頭
	const std::uint64_t localFields = static_cast<std::uint64_t>( nameSize) +
									  // 名前と追加欄を合計したbyte数
									  readU16Le( input, start + 28U) ;
	const std::uint64_t compressed	 = readU32Le( input, entry + 20U) ;	// 元圧縮データ長
	const std::uint64_t uncompressed = readU32Le( input, entry + 24U) ;	// 展開後のデータ長
	// 無圧縮の実読取り長を検証範囲へ合わせ、空データにも正しいCRCを要求する
	if( (method == ZIP_METHOD_STORED && compressed != uncompressed) ||
	   (compressed == 0U && (uncompressed != 0U || readU32Le( input, entry + 16U) != 0U))) {
		return std::nullopt ;
	}

	// 可変ヘッダーと圧縮データの全範囲を中央ディレクトリの手前に限定する
	if( !hasRange( localArea, localName, localFields + compressed) ||
	   !std::ranges::equal(
		   input.subspan( static_cast<std::size_t>( localName), nameSize),
		   input.subspan( static_cast<std::size_t>( entry + ZIP_DIRECTORY_HEADER_BYTES), nameSize))) {
		return std::nullopt ;
	}

	const std::uint64_t dataEnd = localName + localFields + compressed ;	// エントリの圧縮データ直後
	const std::uint64_t tail =
		descriptor ? readZipDescriptorSize( input, zip.directoryOffset, dataEnd, entry + 16U)
				   : 0U ;	// 記述子がある場合は元宣言から一意に定めた長さ
	// 記述子の要求を満たせなければ圧縮データだけをエントリ全体にしない
	if( descriptor && tail == 0U) {
		return std::nullopt ;
	}

	return ZipLocalRange{start, dataEnd + tail} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 中央エントリの全参照が同じPE末尾の単一区間を重複なく覆うことを確認する
 * @param[in] input 元EXE全体
 * @param[in] archiveOffset PE直後のZIP先頭
 * @param[in] zip 検証済みの終端・中央境界と件数。呼出側で件数上限を照合済み
 * @return 中央領域と全ローカル領域が一貫して成立した場合true
 * @throws std::bad_alloc エントリの範囲記録を確保できない場合
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validateSignedZipDirectory( const std::span<const std::byte> input,
											  const std::uint64_t archiveOffset, const ZipEnd &zip)
{
	std::vector<ZipLocalRange> locals ;	// 参照順とは独立に重複を検査する範囲の集合
	locals.reserve( zip.entryCount) ;
	const auto directory =
		// 終端レコードを除く範囲
		input.first( static_cast<std::size_t>( zip.offset)) ;
	std::uint64_t entry = zip.directoryOffset ;	// 現在の中央エントリ位置
	// 宣言件数だけ順に読み、各可変欄とローカル範囲の両方を検証する
	for( std::uint16_t index = 0U; index < zip.entryCount; ++index) {
		// 古典形式の単一ディスク中央エントリだけを扱う
		if( !hasRange( directory, entry, ZIP_DIRECTORY_HEADER_BYTES) ||
		   readU32Le( input, entry) != ZIP_DIRECTORY_SIGNATURE ||
		   readU16Le( input, entry + 34U) != 0U ||
		   readU32Le( input, entry + 20U) == std::numeric_limits<std::uint32_t>::max() ||
		   readU32Le( input, entry + 24U) == std::numeric_limits<std::uint32_t>::max() ||
		   readU32Le( input, entry + 42U) == std::numeric_limits<std::uint32_t>::max()) {
			return false ;
		}

		const std::uint16_t nameSize  = readU16Le( input, entry + 28U) ;	// 中央エントリの名前長
		const std::uint64_t entrySize = ZIP_DIRECTORY_HEADER_BYTES + nameSize +
										readU16Le( input, entry + 30U) +
										// 可変欄込みの中央エントリ長
										readU16Le( input, entry + 32U) ;
		// 名前の空欄や中央領域を越える可変欄からローカル参照を読まない
		if( nameSize == 0U || !hasRange( directory, entry, entrySize)) {
			return false ;
		}

		const auto local =
			// 元参照の全範囲
			readZipLocalRange( input, archiveOffset, zip, entry, nameSize) ;
		// 一つでも成立しない中央参照を部分的に採用しない
		if( !local) {
			return false ;
		}

		locals.push_back( *local) ;
		entry += entrySize ;
	}

	// 宣言件数の後に別の中央データや余分なレコードが残る場合は拒否する
	if( entry != zip.offset) {
		return false ;
	}

	std::ranges::sort( locals, {}, &ZipLocalRange::begin) ;
	std::uint64_t expected = archiveOffset ;	// 次のローカルエントリが始まる唯一の位置
	// 順序を並べ直し、同じ参照、データの重なり、未参照の後挿入領域を拒否する
	for( const auto &local : locals) {
		// 検証済みローカル範囲だけがZIPの元先頭から中央領域まで連続する
		if( local.begin != expected) {
			return false ;
		}

		expected = local.end ;
	}

	return expected == zip.directoryOffset ;
}

//------------------------------------------------------------------------------
/**
 * @brief PEの検証済みsection tableから一意なWiX宣言の位置を読む
 * @param[in] input 元EXE全体
 * @param[in] peLayout 同じEXEで検証したsection tableとPE境界
 * @param[out] headerOffset 成功時のWiX宣言先頭。失敗時は0
 * @return 完全なWiX宣言を含むsectionが一つの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findWixBurnHeader( const std::span<const std::byte> input,
									 const PeLayout &peLayout, std::uint64_t &headerOffset) noexcept
{
	headerOffset = 0U ;
	std::uint64_t found{} ;	// 一意性を確認するまで保持する元宣言の位置
	// 検証済みCOFF tableの全section名だけを照合し、付加領域から識別子を探索しない
	for( std::uint16_t index = 0U; index < peLayout.sectionCount; ++index) {
		const auto section = peLayout.sectionTableOffset +
							 // 元section header位置
							 static_cast<std::uint64_t>( index) * SECTION_HEADER_BYTES ;
		const auto name = input.subspan( static_cast<std::size_t>( section),
										// NUL終端に依存しない8-byte名
										WIX_BURN_SECTION_NAME.size()) ;
		// 他のsectionにある同名データをWiX宣言として扱わない
		if( !std::ranges::equal( name, WIX_BURN_SECTION_NAME)) {
			continue ;
		}

		const auto virtualSize = readU32Le( input, section + 8U) ;	// 元sectionの有効データ長
		const auto rawSize	   = readU32Le( input, section + 16U) ;	// 元sectionの実ファイル長
		// 複数宣言または宣言を全て読めない元sectionを拒否する
		if( found != 0U || virtualSize < WIX_BURN_HEADER_BYTES || rawSize < WIX_BURN_HEADER_BYTES) {
			return false ;
		}

		found = readU32Le( input, section + 20U) ;
	}

	headerOffset = found ;
	return found != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Burnの宣言範囲とCAB共通ヘッダーの長さを照合する
 * @param[in] input 元EXE全体
 * @param[in] offset 元宣言から求めたCABの先頭
 * @param[in] size 元宣言のCAB長
 * @return 入力内に全体があり、CABの識別子と自己申告した長さが一致すればtrue
 * @note 圧縮データ、ファイル表と内容署名は後続のCAB処理で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesWixCabinet( const std::span<const std::byte> input,
									 const std::uint64_t offset, const std::uint64_t size) noexcept
{
	return size >= CAB_HEADER_BYTES && hasRange( input, offset, size) &&
		   readU32Le( input, offset) == CAB_MAGIC && readU32Le( input, offset + 8U) == size ;
}

//------------------------------------------------------------------------------
/**
 * @brief PE末尾の7z Signature Headerを検証する
 *
 * 単一signatureと、Next Header後の必要最小zero paddingだけを受理する
 *
 * @param[in] input EXE全体
 * @param[in] peLayout 検証済みPEとcertificate境界
 * @param[in] policy Stub走査とarchive長の有限上限
 * @param[out] layout 成功時の7zおよびcertificate範囲
 * @return 成功時は0、構造またはCRC不正時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSevenZipLayout( const std::span<const std::byte>   input,
												const PeLayout					  &peLayout,
												const OfficialSfxInspectionPolicy &policy,
												OfficialSfxLayout				  &layout) noexcept
{
	// Image 後方の領域が最小 7z stream に足りなければ探索しない
	if( peLayout.archiveLimit - peLayout.imageEnd < SEVEN_ZIP_HEADER_BYTES + 1U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	std::uint64_t maximumSignatureOffset{} ;	// Stub上限から算出した走査末尾
	// 探索上限の加算が overflow する場合は表現可能最大値へ飽和させる
	if( !checkedAdd( peLayout.imageEnd, policy.maximumStubBytes, maximumSignatureOffset)) {
		maximumSignatureOffset = std::numeric_limits<std::uint64_t>::max() ;
	}

	maximumSignatureOffset =
		std::min( maximumSignatureOffset, peLayout.archiveLimit - SEVEN_ZIP_HEADER_BYTES) ;

	std::uint64_t signatureOffset{} ;	// 発見した唯一の7z signature先頭
	std::uint32_t signatureCount{} ;	// 走査範囲に現れた7z signature数
	// PE image末尾から有限stub上限まで、一byteずつ完全signatureを探索する
	for( std::uint64_t candidateOffset = peLayout.imageEnd;
		candidateOffset <= maximumSignatureOffset; ++candidateOffset) {
		bool matches = true ;	// 現在位置が6-byte signatureと完全一致する場合true
		// Signature全byteを順に比較する
		for( std::size_t signatureIndex = 0; signatureIndex < SEVEN_ZIP_SIGNATURE.size();
			++signatureIndex) {
			const std::size_t inputIndex = static_cast<std::size_t>( candidateOffset) +
										   signatureIndex ;	// 現在signature byteの配列index
			// Signature の不一致を検出したら現在位置の比較を打ち切る
			if( input[inputIndex] != SEVEN_ZIP_SIGNATURE[signatureIndex]) {
				matches = false ;
				break ;
			}
		}

		// 完全一致した signature だけを数え、その位置を保持する
		if( matches) {
			++signatureCount ;
			signatureOffset = candidateOffset ;
		}
	}

	// 7z signature が一意に決まらなければ stream を選択しない
	if( signatureCount != 1U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const std::size_t signatureIndex =
		// 7z headerの配列index
		static_cast<std::size_t>( signatureOffset) ;
	// 対応する 7z version 表記と異なる stream を拒否する
	if( input[signatureIndex + 6U] != std::byte{0x00} ||
	   (input[signatureIndex + 7U] != std::byte{0x03} &&
		input[signatureIndex + 7U] != std::byte{0x04})) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const std::uint32_t expectedStartCrc =
		// 格納されたStart Header CRC
		readU32Le( input, signatureOffset + 8U) ;
	const std::span<const std::byte> startHeader =
		// CRC対象header
		input.subspan( signatureIndex + 12U, SEVEN_ZIP_START_HEADER_BYTES) ;
	// Start Header の CRC が一致しなければ後続 offset を使用しない
	if( calculateCrc32( startHeader) != expectedStartCrc) {
		return nativeErrorFromWin32( ERROR_CRC) ;
	}

	const std::uint64_t nextHeaderRelativeOffset =
		// Signature Header後からの相対位置
		readU64Le( input, signatureOffset + 12U) ;
	const std::uint64_t nextHeaderSize = readU64Le( input, signatureOffset + 20U) ;	// Next Header長
	const std::uint32_t expectedNextCrc =
		// 格納されたNext Header CRC
		readU32Le( input, signatureOffset + 28U) ;
	// 空の Next Header を持つ stream を拒否する
	if( nextHeaderSize == 0U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	std::uint64_t archiveDataOffset{} ;	// 7z Signature Header直後のoffset
	std::uint64_t nextHeaderOffset{} ;	// Next Header先頭のfile offset
	std::uint64_t nextHeaderEnd{} ;		// Next Header直後のfile offset
	// Next Header 位置の overflow と archive・入力境界超過を拒否する
	if( !checkedAdd( signatureOffset, SEVEN_ZIP_HEADER_BYTES, archiveDataOffset) ||
	   !checkedAdd( archiveDataOffset, nextHeaderRelativeOffset, nextHeaderOffset) ||
	   !checkedAdd( nextHeaderOffset, nextHeaderSize, nextHeaderEnd) ||
	   nextHeaderEnd > peLayout.archiveLimit ||
	   !hasRange( input, nextHeaderOffset, nextHeaderSize)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	// Archive と certificate 間の padding が許可形式でなければ拒否する
	if( peLayout.certificateOffset != 0U
		   ? !inspectCertificateAlignmentPadding( input, peLayout.certificateOffset, nextHeaderEnd)
		   : nextHeaderEnd != peLayout.archiveLimit) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const auto certificatePaddingSize = peLayout.archiveLimit - nextHeaderEnd ;	// 検証済みzero長
	const std::uint64_t archiveSize	  = nextHeaderEnd - signatureOffset ;		// Paddingを除く7z stream長
	// 識別した archive の byte 数が policy 上限を超える場合は拒否する
	if( archiveSize > policy.maximumArchiveBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	const std::span<const std::byte> nextHeader =
		input.subspan( static_cast<std::size_t>( nextHeaderOffset),
					  // CRC対象Next Header
					  static_cast<std::size_t>( nextHeaderSize)) ;
	// Next Header の CRC が一致しなければ抽出範囲を受理しない
	if( calculateCrc32( nextHeader) != expectedNextCrc) {
		return nativeErrorFromWin32( ERROR_CRC) ;
	}

	layout = OfficialSfxLayout{signatureOffset,			archiveSize,	certificatePaddingSize,
							   nextHeaderOffset,		nextHeaderSize, peLayout.certificateOffset,
							   peLayout.certificateSize} ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 構造検査済みの末尾テーブルを占める唯一の元PKCS#7と主署名者を照合する
 * @param[in] source 固定した取得元pathと許可署名者、失効確認の方針
 * @param[in] executable 検証中固定される同じ原本の読取り専用owner
 * @param[in] offset 同じ原本で構造検査済みの末尾証明書テーブル先頭
 * @param[in] size 同テーブル全体の長さ。先頭エントリは範囲検証済みとする
 * @return 成功時0、元範囲または署名の不成立の場合はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyPePrimarySignature( const OfficialSignedExecutableSource &source,
												   const OfficialMappedFile				&executable,
												   const std::uint64_t					 offset,
												   const std::uint64_t					 size)
{
	const auto bytes			= executable.bytes() ;			// 保護された元EXEの読取り専用view
	const auto certificateBytes = readU32Le( bytes, offset) ;	// 検証済み先頭エントリの元長
	const auto alignedBytes =
		(static_cast<std::uint64_t>( certificateBytes) + CERTIFICATE_ALIGNMENT - 1U) &
		~(CERTIFICATE_ALIGNMENT - 1U) ;	// 8-byte境界へ整列
	// 元テーブルの全体を占める単一の有界署名だけを外側の署名に選ぶ
	if( alignedBytes != size || certificateBytes > MAXIMUM_PE_CERTIFICATE_BYTES) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const auto certificate =
		bytes.subspan( static_cast<std::size_t>( offset + CERTIFICATE_HEADER_BYTES),
					  // 外側PKCS#7
					  static_cast<std::size_t>( certificateBytes - CERTIFICATE_HEADER_BYTES)) ;
	return verifyPrimaryAuthenticodePublisher( source.executablePath, executable, certificate,
											  source.acceptedPublishers, source.cachedOnly) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元バイトを文字列APIで照合できる借用viewへ変換する
 * @param[in] input 呼出し中に保持される元のバイト列
 * @return 同じ範囲を借用する文字列view
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string_view nsisBytes( const std::span<const std::byte> input) noexcept
{
	// charによるバイト参照を使い、元の文字コードを変換しない
	return {reinterpret_cast<const char *>( input.data()), input.size()} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査済み形式の文字列表から一つの終端付き記録を借りる
 * @param[in] strings 展開済みヘッダー内で確認した文字列表
 * @param[in] offset 文字列表の先頭からの位置
 * @return 終端までの借用view。範囲外または終端欠落時は空optional
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::string_view> nsisString( const std::string_view strings,
														 const std::uint32_t	offset) noexcept
{
	// 文字列表より後ろの別領域を文字列として読まない
	if( offset >= strings.size()) {
		return std::nullopt ;
	}

	const auto tail = strings.substr( offset, 1025U) ;	// 終端を含む形式上限内の候補
	const auto end	= tail.find( '\0') ;				// 当該文字列の終端
	// ANSI文字列の上限内に終端がある場合だけ値を返す
	if( end > 1024U) {
		return std::nullopt ;
	}

	return tail.substr( 0U, end) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NSISの物理ブロック一件の元範囲を読む
 * @param[in] archive 終端CRCを除く元EXE
 * @param[in,out] cursor 元の長さタグ位置。成功時だけ次のタグへ進む
 * @param[out] block 成功時に入力を借用するブロック。失敗時は変更しない
 * @return 長さタグと本体が収まる場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readNsisBlock( const std::span<const std::byte> archive, std::size_t &cursor,
								 ReviewedNsisBlock &block) noexcept
{
	// 終端から切れた長さタグを読まない
	if( !hasRange( archive, cursor, 4U)) {
		return false ;
	}

	const auto tag	 = readU32Le( archive, cursor) ;	// 圧縮bitと元データ長
	const auto bytes = tag & ~NSIS_DEFLATE_TAG ;		// 圧縮bitを除いた元データ長
	const auto start = cursor + 4U ;					// 元データ先頭
	// 空ブロックと終端に重なるブロックでは前進しない
	if( bytes == 0U || !hasRange( archive, start, bytes)) {
		return false ;
	}

	block  = {cursor, archive.subspan( start, bytes), (tag & NSIS_DEFLATE_TAG) != 0U} ;
	cursor = start + bytes ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独立Deflateブロックを指定長に展開する
 * @param[in] block 上限内で読み取った同一元EXEのブロック
 * @param[in] expandedBytes 審査した展開長。呼出し側で個別上限を確認済み
 * @param[out] bytes 成功時の展開内容。失敗途中の内容は呼出し側が破棄する
 * @return 入力全消費かつ出力長一致の場合true
 * @throws std::bad_alloc 展開領域を確保できない場合
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inflateNsisBlock( const ReviewedNsisBlock &block,
									const std::uint32_t		 expandedBytes,
									std::vector<std::byte>	&bytes)
{
	// 選択ブロックに審査した圧縮形式だけを許可する
	if( !block.deflated) {
		return false ;
	}

	bytes.resize( static_cast<std::size_t>( expandedBytes) + 1U) ;
	mz_stream stream{} ;	// 一ブロックの圧縮状態。関数内で解放する
	// minizはunsigned charでバイトを借用する。両長さは32 MiB以下
	stream.next_in	 = reinterpret_cast<const unsigned char *>( block.data.data()) ;
	stream.avail_in	 = static_cast<unsigned int>( block.data.size()) ;
	stream.next_out	 = reinterpret_cast<unsigned char *>( bytes.data()) ;
	stream.avail_out = static_cast<unsigned int>( bytes.size()) ;
	// 圧縮状態を初期化できない場合は内容を使わない
	if( mz_inflateInit2( &stream, -MZ_DEFAULT_WINDOW_BITS) != MZ_OK) {
		return false ;
	}

	const auto result	= mz_inflate( &stream, MZ_FINISH) ;	// 一回の有界展開の終端状態
	const auto consumed = stream.total_in ;					// 終端までに消費した元長
	const auto produced = stream.total_out ;				// 余分な一バイトを含めて観測した出力長
	const auto closed	= mz_inflateEnd( &stream) ;			// 成否を問わず状態を解放
	// 余分な圧縮入力や過不足のある結果を審査内容として扱わない
	if( result != MZ_STREAM_END || closed != MZ_OK || consumed != block.data.size() ||
	   produced != expandedBytes) {
		return false ;
	}

	bytes.resize( expandedBytes) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査済み方式のNSISをPEの元境界と終端CRCに結び付ける
 * @param[in] executable 大きさと元ハッシュを確認した内側EXE
 * @return NSIS先頭宣言から終端CRCまでの借用範囲。不一致時は空
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::span<const std::byte> reviewedNsisArchive(
	const std::span<const std::byte> executable) noexcept
{
	constexpr std::size_t crcStart = 512U ;	// 審査形式でCRCの対象が始まる元EXE位置
	PeLayout			  pe ;				// PEを読み取って確定した元セクションと証明書の終端位置
	// ANSI形式のPE32 stubとその末尾の完全な先頭宣言を要求する
	if( !inspectPeLayout( executable, pe) || pe.machine != IMAGE_FILE_MACHINE_I386 ||
	   pe.optionalMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC || pe.certificateSize != 0U ||
	   pe.imageEnd < crcStart || !hasRange( executable, pe.imageEnd, NSIS_FIRST_HEADER_BYTES + 4U)) {
		return {} ;
	}

	const auto archive = executable.subspan( static_cast<std::size_t>( pe.imageEnd)) ;	// NSIS付加領域
	const auto crcOffset = executable.size() - 4U ;										// 元EXEの終端CRC位置
	// 先頭宣言、元長およびCRCで審査した形式と物理終端との一致を確認する
	if( readU32Le( archive, 0U) != 0U || nsisBytes( archive.subspan( 4U, 16U)) != NSIS_SIGNATURE ||
	   readU32Le( archive, 24U) != archive.size() ||
	   calculateCrc32( executable.subspan( crcStart, crcOffset - crcStart)) !=
		   readU32Le( executable, crcOffset)) {
		return {} ;
	}

	return archive.first( archive.size() - 4U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査したASCII名について、大文字小文字だけの別名も検出する
 * @param[in] name 元命令が参照するANSIの名前
 * @param[in] expected 審査定義のASCII相対名の末尾要素
 * @return ASCIIの大小差を除き全バイトが一致する場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool equalNsisLeaf( const std::string_view	 name,
								 const std::wstring_view expected) noexcept
{
	// 比較中だけそれぞれの一文字を借り、ANSIの非ASCII文字を変換しない
	return std::ranges::equal( name, expected, []( const char left, const wchar_t right) {
		const auto value = static_cast<unsigned char>( left) ;	// ANSI符号なし値
		return value == right || ((value | 0x20U) >= 'a' && (value | 0x20U) <= 'z' &&
								  (value | 0x20U) == (static_cast<unsigned>( right) | 0x20U)) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査メンバーの位置、パスと元データ参照の一意性を確認する
 * @param[in] commands 元ヘッダー内で確定した命令表
 * @param[in] strings 同じヘッダー内で確定した文字列表
 * @param[in] member 元ハッシュに結び付いた審査定義
 * @return 元レコード、ディレクトリ、名前と位置がすべて一致する場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesReviewedNsisMember( const std::span<const std::byte>  commands,
											 const std::string_view			   strings,
											 const OfficialReviewedNsisMember &member) noexcept
{
	const auto amd64 = member.relativePath.starts_with( L"x64\\") ;						// 審査したAMD64配下か
	const auto leaf	 = amd64 ? member.relativePath.substr( 4U) : member.relativePath ;	// 相対名末尾
	const auto directory = amd64 ? NSIS_X64 : NSIS_ROOT ;								// 比較に用いる元パスのリテラル
	const auto count	 = commands.size() / NSIS_COMMAND_BYTES ;						// 元記録数
	// ルートまたは単一AMD64ディレクトリの直下だけを審査範囲とする
	if( leaf.empty() || leaf.find( L'\\') != std::wstring_view::npos ||
	   member.directoryIndex >= member.fileIndex || member.fileIndex >= count) {
		return false ;
	}

	std::size_t		 lastDirectory = count ;	// 直近の出力ディレクトリ記録。未指定時は記録数
	std::string_view lastToken ;				// 直近の有効なディレクトリ原文を借用する
	bool			 found = false ;			// 審査した位置で完全一致を見つけた場合true
	// 命令を実行せず、範囲内を最後まで走査して選択ブロックの別参照を検出する
	for( std::size_t index = 0U; index < count; ++index) {
		const auto record =
			// 元一命令
			commands.subspan( index * NSIS_COMMAND_BYTES, NSIS_COMMAND_BYTES) ;
		const auto opcode = readU32Le( record, 0U) ;	// 元命令番号
		// 出力先を変える原記録だけ、後続の照合に使う境界として保存する
		if( opcode == NSIS_SET_DIRECTORY && readU32Le( record, 8U) != 0U) {
			const auto token = nsisString( strings, readU32Le( record, 4U)) ;	// 原ディレクトリ文字列
			lastDirectory	 = index ;
			lastToken		 = readU32Le( record, 8U) == 1U ? token.value_or( std::string_view{})
														   : std::string_view{} ;
		}

		// 位置の照合に関係しない命令をファイルとして解釈しない
		if( opcode != NSIS_EXTRACT_FILE) {
			continue ;
		}

		const auto name		  = nsisString( strings, readU32Le( record, 8U)) ;	// 配布物内のリテラル名
		const auto dataOffset = readU32Le( record, 12U) ;						// 物理データの元位置
		// 名前の読取り失敗時は別名がないことを確定できない
		if( !name || name->empty()) {
			return false ;
		}

		// 同一ディレクトリ内の別名と、別記録からの選択ブロック参照を拒否する
		if( index != member.fileIndex) {
			// x86など、別ディレクトリに置かれた同名の別ブロックは対象外
			if( dataOffset == member.dataOffset ||
			   (lastToken == directory && equalNsisLeaf( *name, leaf))) {
				return false ;
			}

			continue ;
		}

		// 選択位置では原文の大文字小文字とディレクトリ記録番号も合わせる
		found = lastDirectory == member.directoryIndex && lastToken == directory &&
				dataOffset == member.dataOffset && std::ranges::equal( *name, leaf) ;
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ヘッダーと物理データを審査定義に照合して選択内容を構築する
 * @param[in] archive 先頭と終端を検証したNSIS領域。終端CRCは含めない
 * @param[in] expected 元ハッシュと結び付けた選択内容
 * @param[out] files 成功時だけ追加順の展開内容を保持。失敗時は呼出し側が全体を破棄する
 * @return 全メンバー一致は0、構造、展開または元内容の不一致はHRESULT
 * @throws std::bad_alloc 検査と展開の領域を確保できない場合
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractReviewedNsisMembers(
	const std::span<const std::byte>				  archive,
	const std::span<const OfficialReviewedNsisMember> expected, std::vector<OfficialZipFile> &files)
{
	const auto			   invalid = nativeErrorFromWin32( ERROR_BAD_FORMAT) ;	// 元形式不一致の診断
	const auto			   headerBytes = readU32Le( archive, 20U) ;				// 元先頭宣言のヘッダー展開長
	auto				   cursor	   = NSIS_FIRST_HEADER_BYTES ;				// 初回は圧縮ヘッダーのタグ位置
	ReviewedNsisBlock	   compressedHeader{} ;									// 元圧縮ヘッダーの物理範囲
	std::vector<std::byte> expandedHeader ;										// 展開長を検証するまで外へ渡さない元ヘッダー
	// 命令・文字列表の上限を先に確認し、元ヘッダー全体を展開する
	if( headerBytes < 68U || headerBytes > NSIS_MAXIMUM_HEADER ||
	   !readNsisBlock( archive, cursor, compressedHeader) ||
	   !inflateNsisBlock( compressedHeader, headerBytes, expandedHeader)) {
		return invalid ;
	}

	const std::span<const std::byte> header( expandedHeader) ;					// 同じ展開済みヘッダーから借用
	const auto						 entriesOffset = readU32Le( header, 20U) ;	// 命令表の元位置
	const auto						 entriesCount  = readU32Le( header, 24U) ;	// 宣言された命令数
	const auto						 stringsOffset = readU32Le( header, 28U) ;	// 文字列表の元位置
	const auto languagesOffset					   = readU32Le( header, 36U) ;	// 文字列表の次の元領域
	const auto entriesBytes =
		// 命令表の元長
		static_cast<std::uint64_t>( entriesCount) * NSIS_COMMAND_BYTES ;
	// 命令表と文字列表の完全な境界を確認してから個々の記録を読む
	if( entriesOffset < 68U || entriesCount == 0U || entriesCount > NSIS_MAXIMUM_COMMANDS ||
	   entriesOffset + entriesBytes != stringsOffset || stringsOffset >= languagesOffset ||
	   languagesOffset > header.size()) {
		return invalid ;
	}

	const auto commands =
		// 全命令
		header.subspan( entriesOffset, static_cast<std::size_t>( entriesBytes)) ;
	const auto strings =
		// 全文字列
		nsisBytes( header.subspan( stringsOffset, languagesOffset - stringsOffset)) ;
	const auto					   dataStart = cursor ;	// 元命令のデータ位置が参照する先頭タグ
	std::vector<ReviewedNsisBlock> blocks ;				// 元位置順の物理データ領域
	// 数と終端を制限して全タグを読み、途中のバイトをタグと誤認しない
	while( cursor < archive.size()) {
		ReviewedNsisBlock block{} ;	// 次の物理データ範囲
		// 切詰めや空ブロックを含む書庫から部分的な結果を出さない
		if( blocks.size() == NSIS_MAXIMUM_COMMANDS || !readNsisBlock( archive, cursor, block)) {
			return invalid ;
		}

		blocks.push_back( block) ;
	}

	std::size_t expandedTotal = 0U ;	// 確認済みの選択展開バイト数
	files.reserve( expected.size()) ;
	// 審査定義順に、各元ファイルと参照位置を照合して全件を展開する
	for( const auto &member : expected) {
		// 安全な相対名と各展開上限を先に確認し、組み合わせによる過剰確保を拒否する
		if( member.relativePath.size() > 160U ||
		   !isSafeOfficialArchiveMember( member.relativePath, L'\\') || member.expandedBytes == 0U ||
		   member.expandedBytes > NSIS_MAXIMUM_SINGLE ||
		   member.expandedBytes > NSIS_MAXIMUM_TOTAL - expandedTotal ||
		   member.sha256.size() != 64U) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// Windowsで作用先が同じになる審査名を二件以上に数えない
		const auto duplicate = std::ranges::any_of( files, [&member]( const OfficialZipFile &prior) {
			return CompareStringOrdinal(
					   prior.relativePath.data(), static_cast<int>( prior.relativePath.size()),
					   member.relativePath.data(), static_cast<int>( member.relativePath.size()),
					   TRUE) == CSTR_EQUAL ;
		}) ; // 比較中だけ定義と既に展開したパスを借用する
		const auto block	 = std::ranges::lower_bound(
			blocks, static_cast<std::uint64_t>( dataStart) + member.dataOffset, {},
			&ReviewedNsisBlock::position) ;	// 元位置
		// 物理タグと元命令が一致した場合だけ、その範囲の実バイトを展開する
		if( duplicate || block == blocks.end() || block->position - dataStart != member.dataOffset ||
		   !matchesReviewedNsisMember( commands, strings, member)) {
			return invalid ;
		}

		std::vector<std::byte> content ;	// 元ハッシュ照合前の当該ファイル
		// 同じ長さの別ファイルや展開の余剰を受け入れない
		if( !inflateNsisBlock( *block, member.expandedBytes, content)) {
			return invalid ;
		}

		std::wstring digest ;	// 展開内容のSHA-256
		const auto	 error =
			// 元内容の照合値
			computeDriverContainerSha256( nsisBytes( content), digest) ;
		// ハッシュを計算できない場合は元診断を維持する
		if( error != 0U) {
			return error ;
		}

		// ハッシュが不一致の場合は同じ名前と位置でも元バイトとして扱わない
		if( digest != member.sha256) {
			return nativeErrorFromWin32( ERROR_CRC) ;
		}

		expandedTotal += content.size() ;
		files.push_back( {std::wstring( member.relativePath), std::move( content)}) ;
	}

	return 0U ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief PE image後方の単一7z streamを、実行も展開もせず識別する。PE image後方の単一7z streamを識別する。EXEを実行・展開せず、全検査成功後だけ出力範囲を
 *        確定する
 * @param[in] executable 公式取得後のEXE全体。有効期間は本呼出し中に限る
 * @param[in] policy 入力、stub走査、7z streamへ適用する有限上限。 入力、stub走査、7z streamの有限上限
 * @param[out] layout 成功時の7z、zero padding、certificate table範囲。失敗時は既定値。 成功時の7zおよびcertificate範囲
 * @return 成功時は0、引数、上限、PE／7z構造またはCRC不正時はHRESULT bit pattern。 成功時は0、引数、上限、PE／7z構造、CRC不正時はHRESULT
 * @note 本関数はfileを実行・展開せず、署名、publisher、driver適用性も判定しない
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialSevenZipSfx( const std::span<const std::byte>	  executable,
									   const OfficialSfxInspectionPolicy &policy,
									   OfficialSfxLayout				 &layout) noexcept
{
	layout = {} ;
	// 空実行 file とゼロ・相互矛盾のある size policy を解析前に拒否する
	if( executable.empty() || policy.maximumExecutableBytes == 0U || policy.maximumStubBytes == 0U ||
	   policy.maximumArchiveBytes == 0U ||
	   policy.maximumStubBytes > policy.maximumExecutableBytes ||
	   policy.maximumArchiveBytes > policy.maximumExecutableBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 実行 file 全体が取得上限を超える場合は埋込み archive を探索しない
	if( static_cast<std::uint64_t>( executable.size()) > policy.maximumExecutableBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	PeLayout peLayout{} ;	// 検証済みPE imageとcertificate境界
	// PE 領域の境界検証が成立しなければ後方 data を archive と扱わない
	if( !inspectPeLayout( executable, peLayout)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	OfficialSfxLayout inspectedLayout{} ;	// 全検査成功まで局所保持する識別結果
	const NativeError error =
		// 7z検査結果
		inspectSevenZipLayout( executable, peLayout, policy, inspectedLayout) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( error != 0) {
		return error ;
	}

	layout = inspectedLayout ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 末尾証明書を持つPEから、直後に続く単一ZIPの完全な範囲を識別する
 * @param[in] executable 呼出し中だけ借用する取得済み元EXE全体
 * @param[in] policy 元EXEのbyte数とZIPエントリ数に適用する有限上限
 * @param[out] layout 検証済みの範囲とオフセット基準。失敗時は空
 * @return 成功時は0、引数、上限または構造の不成立はHRESULT
 * @note 原署名の信頼、ZIP内容・CRC・適用性は別に検証する。元EXEの実行・展開は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialSignedPeZip( const std::span<const std::byte>			  executable,
									   const OfficialSignedPeZipInspectionPolicy &policy,
									   OfficialSignedPeZipLayout				 &layout) noexcept
{
	layout = {} ;
	// 呼出側が入力全体と領域計算に使うエントリ数の両方を制限する
	if( executable.empty() || policy.maximumExecutableBytes == 0U ||
	   policy.maximumEntryCount == 0U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 設定済みの取得上限を超えるファイルを構造走査へ進めない
	if( executable.size() > policy.maximumExecutableBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	PeLayout pe{} ;	// 同じ元EXEから得た生セクションの末尾と証明書範囲
	// 署名用の末尾テーブルが成立するPEだけをZIPの境界検査へ渡す
	if( !inspectPeLayout( executable, pe) || pe.certificateOffset == 0U ||
	   !inspectCertificateTable( executable, pe.certificateOffset, pe.certificateSize, true)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const auto zip = findZipEnd( executable, pe) ;	// 唯一の終端、中央領域とオフセット基準
	// 一意なZIP境界が得られなければ推測で範囲を返さない
	if( !zip) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	// 元エントリ件数が方針を超える場合は範囲の配列を確保しない
	if( zip->entryCount > policy.maximumEntryCount) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	try {
		// 全中央参照がPE直後のZIPデータだけに収まる場合に限り境界を公開する
		if( !validateSignedZipDirectory( executable, pe.imageEnd, *zip)) {
			return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
		}

		layout = {pe.imageEnd, zip->archiveEnd - pe.imageEnd, pe.certificateOffset,
				  pe.certificateSize, zip->offsetBase == 0U} ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief WiX v3の元宣言に従って、二つのCABと二つの証明書テーブルの範囲を識別する
 * @param[in] executable 呼出し中だけ借用する取得済み元EXE全体
 * @param[in] policy 入力全体と各CABに適用する有限上限
 * @param[out] layout 全境界の検証が成立した場合だけ保持する元範囲。失敗時は既定値
 * @return 成功時は0、引数、上限または書式不正時はHRESULT
 * @note EXEの実行やCABの展開は行わない。Authenticodeの信頼検証と内容検査は別に必要
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialWixBurn( const std::span<const std::byte>		  executable,
								   const OfficialWixBurnInspectionPolicy &policy,
								   OfficialWixBurnLayout				 &layout) noexcept
{
	layout = {} ;
	// 空入力や矛盾した上限から読み取りを始めない
	if( executable.empty() || policy.maximumExecutableBytes == 0U ||
	   policy.maximumCabinetBytes == 0U ||
	   policy.maximumCabinetBytes > policy.maximumExecutableBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 配布元の取得上限を超えた元ファイルを構造検査へ渡さない
	if( executable.size() > policy.maximumExecutableBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	PeLayout pe{} ;	// 同じファイルのPE、原section tableと末尾証明書領域
	// 末尾の署名領域が不在または元PEに結び付かない配布を拒否する
	if( !inspectPeLayout( executable, pe) || pe.certificateOffset == 0U) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const bool x86Outer =
		pe.machine == IMAGE_FILE_MACHINE_I386 &&
		pe.optionalMagic ==
			IMAGE_NT_OPTIONAL_HDR32_MAGIC ;	// 32-bit起動部。driverのarchitectureとは独立
	const bool x64Outer = pe.machine == IMAGE_FILE_MACHINE_AMD64 &&
						  // 64-bit起動部
						  pe.optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ;
	std::uint64_t header{} ;	// 一意なWiX宣言の開始位置
	// 対象PEのsection tableから宣言を取得し、対応する版と二CAB形式だけを受理する
	if( (!x86Outer && !x64Outer) || !findWixBurnHeader( executable, pe, header) ||
	   readU32Le( executable, header) != WIX_BURN_MAGIC ||
	   readU32Le( executable, header + 4U) != WIX_BURN_VERSION ||
	   readU32Le( executable, header + 40U) != WIX_BURN_CAB_FORMAT ||
	   readU32Le( executable, header + 44U) != WIX_BURN_CONTAINER_COUNT) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	const std::uint64_t stub = readU32Le( executable, header + 24U) ;	// 元起動部の生PE末尾
	const std::uint64_t engineCertificate =
		// 原起動部の証明書先頭
		readU32Le( executable, header + 32U) ;
	const std::uint64_t engineCertificateSize = readU32Le( executable, header + 36U) ;	// 同テーブル長
	const std::uint64_t uxSize		 = readU32Le( executable, header + 48U) ;			// 起動用CABの長さ
	const std::uint64_t attachedSize = readU32Le( executable, header + 52U) ;			// 添付CABの長さ
	const auto			uxEnd		 = stub + uxSize ;									// 32-bit元値二つを64-bitで加えた起動用CAB末尾
	const auto			attached = engineCertificate + engineCertificateSize ;			// 起動部の証明書直後
	const auto			attachedEnd = attached + attachedSize ;							// 元3値を64-bitで加えた添付CAB末尾
	// CABの宣言値だけで取得上限を広げない
	if( uxSize > policy.maximumCabinetBytes || attachedSize > policy.maximumCabinetBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// 起動用CAB、元証明書、添付CAB、末尾証明書を順序と最小整列に固定する
	if( stub != pe.imageEnd || engineCertificateSize <= CERTIFICATE_HEADER_BYTES ||
	   attachedEnd > pe.certificateOffset ||
	   !inspectCertificateAlignmentPadding( executable, engineCertificate, uxEnd) ||
	   !inspectCertificateAlignmentPadding( executable, pe.certificateOffset, attachedEnd) ||
	   !inspectCertificateTable( executable, engineCertificate, engineCertificateSize, true) ||
	   !inspectCertificateTable( executable, pe.certificateOffset, pe.certificateSize, true) ||
	   !matchesWixCabinet( executable, stub, uxSize) ||
	   !matchesWixCabinet( executable, attached, attachedSize)) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	layout =
		OfficialWixBurnLayout{stub,		uxSize,		  engineCertificate,	engineCertificateSize,
							  attached, attachedSize, pe.certificateOffset, pe.certificateSize} ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元取得と署名に結び付いたWiX配布の二つのCAB範囲を読み取り専用で開く
 * @param[in] source 元取得証拠と配布元定義で照合した入力
 * @param[in] policy 元EXE全体と各CABへ適用する有限上限
 * @param[in,out] executable 空で渡す。成功時は署名と同じ元ファイルを固定する所有者
 * @param[out] layout 全検証成功時に確定した元範囲。失敗時は既定値
 * @return 成功時0、元取得情報、保護、範囲、署名が不成立の場合はHRESULT
 * @note 実行や展開は行わない。成功時の元範囲は所有者の寿命内で利用する
 */
//------------------------------------------------------------------------------
NativeError openVerifiedOfficialWixBurn( const OfficialSignedExecutableSource  &source,
										const OfficialWixBurnInspectionPolicy &policy,
										OfficialMappedFile					  &executable,
										OfficialWixBurnLayout				  &layout)
{
	layout = {} ;
	// 元取得の完全な根拠と新規所有者がある要求だけを開始する
	if( !executable.bytes().empty() || source.expectedBytes == 0U ||
	   source.expectedSha256.size() != 64U || source.acceptedPublishers.empty() ||
	   policy.maximumCabinetBytes == 0U ||
	   policy.maximumCabinetBytes > policy.maximumExecutableBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 元取得が許可上限を超えるときは元ファイルを開かない
	if( source.expectedBytes > policy.maximumExecutableBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	auto error =
		// 原本固定結果
		executable.open( source.executablePath, policy.maximumExecutableBytes) ;
	// 所有者が固定できない原本から範囲を生成しない
	if( error != 0U) {
		return error ;
	}

	OfficialWixBurnLayout inspected ;	// 署名信頼が成立するまでは外へ渡さない構造結果
	try {
		error = verifyOfficialFileMetadata(
			source.executablePath, {source.expectedBytes, std::wstring( source.expectedSha256)}) ;
		// 元取得と一致するデータだけを形式検査へ渡す
		if( error == 0U) {
			error = inspectOfficialWixBurn( executable.bytes(), policy, inspected) ;
		}

		// 外側証明書の範囲が確定してから、同じhandleの主署名を検証する
		if( error == 0U) {
			error = verifyPePrimarySignature( source, executable, inspected.certificateOffset,
											 inspected.certificateSize) ;
		}
	} catch( const std::bad_alloc &) {
		error = static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	// 途中で失敗した原本と境界は破棄し、最初の検査診断を返す
	if( error != 0U) {
		static_cast<void>( executable.close()) ;
		return error ;
	}

	layout = inspected ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元取得と主署名の照合を通過したPEから、指定された内側ZIPの原バイトを読み取る
 * @param[in] source 元取得証拠と配布元定義で照合した入力
 * @param[in] policy 元EXE全体と外側ZIPの入力、エントリ数、展開量に適用する有限上限
 * @param[in] member 検査した外側ZIP内の完全な相対名。大文字小文字を保持する
 * @param[out] innerZip 全検証成功時だけ返す内側ZIPの原バイト。失敗時は空
 * @return 成功時0、取得、署名、構造、ZIP読取りまたはメンバー照合の失敗時はHRESULT
 * @note 元ファイルを実行・変更しない。内側ZIPの形式、INF・CATと適用性は呼出し側が検証する
 */
//------------------------------------------------------------------------------
NativeError readVerifiedOfficialSignedPeZipMember( const OfficialSignedExecutableSource &source,
												  const OfficialZipExtractionPolicy	   &policy,
												  const std::wstring_view				member,
												  std::vector<std::byte>			   &innerZip)
{
	innerZip.clear() ;
	// 原取得情報、許可署名者、完全な選択名と有限な検査条件を必須にする
	if( source.expectedBytes == 0U || source.expectedSha256.size() != 64U ||
	   source.acceptedPublishers.empty() || member.empty() || policy.maximumArchiveBytes == 0U ||
	   policy.maximumEntryCount == 0U || policy.maximumSingleFileBytes == 0U ||
	   policy.maximumTotalExpandedBytes == 0U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 取得証拠が上限を超える場合は元ファイルを開かない
	if( source.expectedBytes > policy.maximumArchiveBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// 元ハッシュ、主署名、ZIP読取りを通じて同じ元ファイルを固定
	OfficialMappedFile executable ;
	auto error = executable.open( source.executablePath, policy.maximumArchiveBytes) ;	// 元保護の結果
	// 原本を固定できなければ後続検査へ進まない
	if( error != 0U) {
		return error ;
	}

	try {
		error = verifyOfficialFileMetadata(
			source.executablePath, {source.expectedBytes, std::wstring( source.expectedSha256)}) ;
		// サイズとSHA-256の両方が一致した原本だけを構造と署名の検査に使う
		if( error != 0U) {
			return error ;
		}

		const auto				  bytes = executable.bytes() ;	// 同じ元EXEの読取り専用view
		OfficialSignedPeZipLayout layout ;						// 署名検査とZIPへの読取り範囲を結ぶ元境界
		error = inspectOfficialSignedPeZip(
			bytes, {policy.maximumArchiveBytes, policy.maximumEntryCount}, layout) ;
		// 完全な元構造が成立する場合だけ主署名を選択する
		if( error == 0U) {
			error = verifyPePrimarySignature( source, executable, layout.certificateOffset,
											 layout.certificateSize) ;
		}

		// 署名または構造が不成立なら、元ファイルから選択内容を展開しない
		if( error != 0U) {
			return error ;
		}

		const auto end = layout.archiveOffset + layout.archiveSize ;	// 元署名テーブルより前のZIP末尾
		const auto base =
			layout.offsetsFromExecutableStart ? 0U : layout.archiveOffset ;	// ZIP readerの基準
		const auto					 archive = bytes.subspan( static_cast<std::size_t>( base),
															 // 整列と証明書を除いた有界の元view
															 static_cast<std::size_t>( end - base)) ;
		std::vector<OfficialZipFile> files ;	// 共通ZIP検査と全CRCを通過した外側メンバー
		error = readOfficialZip( archive, policy, files) ;
		// 選択外も含め、共通ZIP検査が失敗すれば内容を渡さない
		if( error != 0U) {
			return error ;
		}

		const auto selected = std::ranges::find( files, member, []( const OfficialZipFile &entry) {
			return std::wstring_view{entry.relativePath} ;
		}) ; // 一致検索中だけ検査済みの完全名を借用する
		// 大文字小文字差や欠落、空のファイルを別ファイルで補わない
		if( selected == files.end() || selected->bytes.empty()) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		innerZip = std::move( selected->bytes) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 審査済みの非solid NSIS 2 ANSIから元メンバーだけを展開する
 * @param[in] executable 呼出し中に不変で借用する内側の元EXE全体
 * @param[in] executableSha256 審査済み内側EXEの小文字64桁SHA-256
 * @param[in] expected 元EXEに結び付けた相対名、元レコード・データ位置、展開長とハッシュ
 * @param[out] files 全件一致時だけ展開バイトを定義順に返す。失敗時は空
 * @return 成功時は0、引数、上限、構造、展開、ハッシュまたは確保の失敗はHRESULT
 * @note 配布の根拠、INF・CATと適用性は呼出し側で検査する。元実行ファイルを実行しない
 */
//------------------------------------------------------------------------------
NativeError readOfficialReviewedNsisMembers(
	const std::span<const std::byte> executable, const std::wstring_view executableSha256,
	const std::span<const OfficialReviewedNsisMember> expected,
	std::vector<OfficialZipFile>					 &files) noexcept
{
	files.clear() ;
	// 元書庫の特定と選択範囲が成立しない入力からは何も展開しない
	if( executable.empty() || executable.size() > NSIS_MAXIMUM_EXE ||
	   executableSha256.size() != 64U || expected.empty() ||
	   expected.size() > NSIS_MAXIMUM_MEMBERS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::wstring digest ;	// 呼出し中に固定した元EXE全体のSHA-256
		const auto	 error =
			// 原ハッシュ結果
			computeDriverContainerSha256( nsisBytes( executable), digest) ;
		// ハッシュの計算に失敗した入力を形式判定へ渡さない
		if( error != 0U) {
			return error ;
		}

		// 異なる配布版や変化した元ファイルを同じ審査定義で展開しない
		if( digest != executableSha256) {
			return nativeErrorFromWin32( ERROR_CRC) ;
		}

		const auto archive = reviewedNsisArchive( executable) ;	// 元PEとCRCを確認したNSIS範囲
		// 元構造の境界を一つに確定できない場合は選択レコードを探索しない
		if( archive.empty()) {
			return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
		}

		std::vector<OfficialZipFile> verified ;	// 全条件が成立するまで呼出し側へ公開しない結果
		const auto					 extraction =
			// 全件の検査結果
			extractReviewedNsisMembers( archive, expected, verified) ;
		// 一件でも欠ける場合、先に確認できたメンバーも渡さない
		if( extraction == 0U) {
			files = std::move( verified) ;
		}

		return extraction ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 私有収集で保存した公式ZIPを固定し、同じ版のNSIS選択ファイルだけを読み取る
 * @param[in] input 現在userの検査領域と元取得のバイト数・ハッシュを結ぶ入力
 * @param[in] reviewed 審査済み元ZIPとその内側EXEの相対名、長さ、ハッシュ、選択ファイル
 * @param[out] files 全照合に成功した元相対名とファイル内容。失敗時は空
 * @return 成功時0、取得条件、元ハッシュ、ZIP、選択、展開または確保の失敗時はHRESULT
 * @note 元ZIPを固定したまま読む。元ファイルの実行、署名済み扱い、導入許可の発行は行わない
 */
//------------------------------------------------------------------------------
NativeError readOfficialReviewedNsisZipMembers( const DriverArchiveInput		 &input,
											   const OfficialReviewedNsisZip &reviewed,
											   std::vector<OfficialZipFile>	 &files)
{
	files.clear() ;
	// 私有検査の元archiveと審査済みの単一EXEだけを対象とする
	if( input.scanSessionId == 0U || input.resourceContent ||
	   input.workspaceMode != OfficialWorkspaceMode::CURRENT_USER_INSPECTION ||
	   reviewed.archiveBytes == 0U || reviewed.archiveBytes > NSIS_MAXIMUM_EXE ||
	   reviewed.executableBytes == 0U || reviewed.executableBytes > NSIS_MAXIMUM_EXE ||
	   reviewed.archiveSha256.size() != 64U || reviewed.executableSha256.size() != 64U ||
	   reviewed.executableName.find( L'\\') != std::wstring_view::npos ||
	   !isSafeOfficialArchiveMember( reviewed.executableName, L'\\') || reviewed.members.empty() ||
	   reviewed.members.size() > NSIS_MAXIMUM_MEMBERS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 元受領記録と審査定義が異なる版を指す場合は、元ファイルを開かずに停止する
	if( input.byteCount != reviewed.archiveBytes || input.sha256 != reviewed.archiveSha256) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	try {
		OfficialMappedFile original ;												// 同一handleの元ZIPを確認完了まで固定する
		auto error = original.open( input.inspectionPath, reviewed.archiveBytes) ;	// 元読み取りの診断
		// 取得記録と一致する実長が確認できない場合は元ZIPを展開しない
		if( error != 0U || original.bytes().size() != reviewed.archiveBytes) {
			return error != 0U ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		std::wstring digest ;	// 同じ固定元ZIP全体のSHA-256
		error = computeDriverContainerSha256( nsisBytes( original.bytes()), digest) ;
		// 別名の原本や変更されたファイルを、前回の受領記録で採用しない
		if( error != 0U || digest != reviewed.archiveSha256) {
			return error != 0U ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		const OfficialZipExtractionPolicy limits{reviewed.archiveBytes, reviewed.executableBytes,
												 reviewed.executableBytes,
												 1U} ;	// ディレクトリも含めて唯一の元エントリを要求
		std::vector<OfficialZipFile>	  unpacked ;	// 元ZIPからCRC確認後に読み取るEXE
		error = readOfficialZip( original.bytes(), limits, unpacked) ;
		// ZIPの不正や審査EXE以外の名前を、別内側ファイルで補わない
		if( error != 0U || unpacked.size() != 1U ||
		   unpacked.front().relativePath != reviewed.executableName ||
		   unpacked.front().bytes.size() != reviewed.executableBytes) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return readOfficialReviewedNsisMembers( unpacked.front().bytes, reviewed.executableSha256,
											   reviewed.members, files) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
