//------------------------------------------------------------------------------
/**
 * @file collector_property_page_export_internal.cpp
 * @brief 元PEの配置とインポート・エクスポートを実行せずに検査します
 * @version 01.01.01
 * @date 2026/11/19
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/19  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/24  共通PE配置とUSB無線の直接依存を非実行で照合
 * Ver.01.01.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 全RVAを一意なfile-backed範囲に結び、原export表の大小文字を保持します
 * @see docs/adr/0515-collector-device-property-page-validation.md
 * @see docs/adr/0582-catalog-usb-wireless-quoted-service.md
 */
//------------------------------------------------------------------------------

#include "platform/collector_property_page_export_internal.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
// PE/COFFのsection上限と、全exportの有限走査上限です
constexpr std::size_t MAXIMUM_PE_SECTIONS = 96U ;
// 原export表で走査する名前数と関数数の上限です
constexpr DWORD		  MAXIMUM_EXPORTS = 4096U ;
// NULを除く一つの元export識別子の上限です
constexpr std::size_t MAXIMUM_EXPORT_NAME = 256U ;

//------------------------------------------------------------------------------
/**
 * @brief 元file内の完全な固定幅値を未整列アクセスなしで読みます
 * @tparam T Windows SDKのlittle-endian PE構造体または固定幅整数です
 * @param[in] bytes 所有者が固定した原範囲です
 * @param[in] offset 原範囲内のbyte offsetです
 * @return 完全に収まるコピー、範囲外なら空です
 */
//------------------------------------------------------------------------------
template <typename T>
std::optional<T> readPeValue( std::span<const std::byte> bytes, std::size_t offset)
{
	// 部分構造体や加算overflowを成功へ変換しません
	if( offset > bytes.size() || sizeof( T) > bytes.size() - offset) {
		return std::nullopt ;
	}

	T value{} ;	// 非整列の元byteを同ABIの値へ複写します
	std::memcpy( &value, bytes.data() + offset, sizeof( value)) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの非負の有限区間が実byteを共有するか照合します
 * @param[in] first 第一範囲の開始です
 * @param[in] firstSize 第一範囲の長さです
 * @param[in] second 第二範囲の開始です
 * @param[in] secondSize 第二範囲の長さです
 * @return 両方に含まれるbyteがあればtrueです
 */
//------------------------------------------------------------------------------
bool overlaps( DWORD first, DWORD firstSize, DWORD second, DWORD secondSize)
{
	return firstSize != 0U && secondSize != 0U &&
		   first < static_cast<std::uint64_t>( second) + secondSize &&
		   second < static_cast<std::uint64_t>( first) + firstSize ;
}

//------------------------------------------------------------------------------
/**
 * @brief export表内の有界な印字可能ASCII文字列を借用します
 * @param[in] tail 元RVAからfile-backedな範囲の末尾までです。forwarderはdirectory末尾に制限します
 * @return 完全な原文字列、空・非ASCII・範囲外・未終端は空です
 */
//------------------------------------------------------------------------------
std::string_view exportText( std::span<const std::byte> tail)
{
	const auto limit = (std::min)( tail.size(), MAXIMUM_EXPORT_NAME + 1U) ;	// NULを含む上限です
	// 印字可能文字とNULだけを有限回検査します
	for( std::size_t index = 0U; index < limit; ++index) {
		const auto code = std::to_integer<unsigned>( tail[index]) ;	// 元ASCII byteです
		// charは任意のobject表現を別名参照でき、所有元の寿命内だけ返します
		if( code == 0U) {
			return {reinterpret_cast<const char *>( tail.data()), index} ;
		}

		// 制御byteや非ASCIIを別のexport名へ置換しません
		if( code < 0x20U || code > 0x7eU) {
			return {} ;
		}
	}

	return {} ;
}
/** @brief 検証済み原PEの配置と同期借用する原バイトです */
struct CollectorPeImage {
	/// 呼出し中だけ借用する元の全バイトです
	std::span<const std::byte>							  bytes ;
	/// 宣言範囲を越えず読み取った原ヘッダーです
	IMAGE_OPTIONAL_HEADER64								  optional ;
	/// 実範囲と仮想範囲を照合した元セクションです
	std::array<IMAGE_SECTION_HEADER, MAXIMUM_PE_SECTIONS> sections ;
	/// 上限内のセクション数です
	WORD												  sectionCount ;

	/**
	 * @brief 元RVAから一意なファイル実体を借用します
	 * @param[in] rva 元の画像内アドレスです
	 * @param[in] executable trueは実行可能節の実バイトだけを許容します
	 * @return 同じ節または許可されたヘッダーの残りです。不成立時は空です
	 */
	[[nodiscard]] std::span<const std::byte> region( DWORD rva, bool executable = false) const
	{
		// 原headerを参照するmetadataはファイル実体だけを読み、実行対象にはしません
		if( rva != 0U && rva < optional.SizeOfHeaders && !executable) {
			return bytes.subspan( rva, optional.SizeOfHeaders - rva) ;
		}

		// 検証済みsectionのfileと仮想空間の共通範囲だけを解決します
		for( const auto &s : std::span( sections).first( sectionCount)) {
			const auto valid =
				(std::min)( s.Misc.VirtualSize, s.SizeOfRawData) ;	// 末尾padding/zero-fillを除きます
			// 全要求byteが同一sectionの実byteへ一意に収まる時だけ返します
			if( rva >= s.VirtualAddress && rva - s.VirtualAddress < valid &&
			   (!executable || (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0U)) {
				return bytes.subspan( static_cast<std::size_t>( s.PointerToRawData) +
										 (rva - s.VirtualAddress),
									 valid - (rva - s.VirtualAddress)) ;
			}
		}

		return {} ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 有限なAMD64 PE32+の元配置を確認します
 * @param[in] bytes 呼出しの間だけ固定された原ファイルです
 * @param[in] isDll trueはDLL、falseはEXEの実行形式を要求します
 * @return すべてのヘッダーと範囲が成立した場合だけ原PEの配置を返します
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<CollectorPeImage> readCollectorPeImage( std::span<const std::byte> bytes,
																   bool						  isDll)
{
	const auto dos = readPeValue<IMAGE_DOS_HEADER>( bytes, 0U) ;	// 原DOS headerです
	// DOS/PE署名または有界な元範囲がない入力を実行形式へ分類しません
	if( bytes.size() > MAXIMUM_PROPERTY_PAGE_DLL_BYTES || !dos ||
	   dos->e_magic != IMAGE_DOS_SIGNATURE ||
	   dos->e_lfanew < static_cast<LONG>( sizeof( IMAGE_DOS_HEADER))) {
		return std::nullopt ;
	}

	const auto pe		 = static_cast<std::size_t>( dos->e_lfanew) ;				// 検証済み非負offsetです
	const auto signature = readPeValue<DWORD>( bytes, pe) ;							// 元PE署名です
	const auto file = readPeValue<IMAGE_FILE_HEADER>( bytes, pe + sizeof( DWORD)) ;	// COFF headerです
	const auto optionalAt = pe + sizeof( DWORD) + sizeof( IMAGE_FILE_HEADER) ;		// optional起点です
	IMAGE_OPTIONAL_HEADER64 optional{} ;											// 宣言長を越えてdirectoryを読みません
	constexpr WORD DLL_IMAGE = IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE ;		// 元DLL属性です
	constexpr auto DIRECTORIES =
		// PE32+の実配列位置です
		offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory) ;
	// 別machine・bit数・欠けたdirectory記述子・過大section数を拒否します
	if( !signature || *signature != IMAGE_NT_SIGNATURE || !file ||
	   file->Machine != IMAGE_FILE_MACHINE_AMD64 ||
	   (file->Characteristics & DLL_IMAGE) != (isDll ? DLL_IMAGE : IMAGE_FILE_EXECUTABLE_IMAGE) ||
	   file->NumberOfSections == 0U || file->NumberOfSections > MAXIMUM_PE_SECTIONS ||
	   file->SizeOfOptionalHeader < DIRECTORIES + sizeof( IMAGE_DATA_DIRECTORY) ||
	   optionalAt > bytes.size() || file->SizeOfOptionalHeader > bytes.size() - optionalAt) {
		return std::nullopt ;
	}

	std::memcpy( &optional, bytes.data() + optionalAt,
				(std::min)( sizeof( optional), static_cast<std::size_t>( file->SizeOfOptionalHeader))) ;
	// 宣言directory数・image配置と実fileのalignmentに矛盾するPEを拒否します
	if( optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || optional.NumberOfRvaAndSizes == 0U ||
	   optional.NumberOfRvaAndSizes >
		   (file->SizeOfOptionalHeader - DIRECTORIES) / sizeof( IMAGE_DATA_DIRECTORY) ||
	   !std::has_single_bit( optional.FileAlignment) ||
	   !std::has_single_bit( optional.SectionAlignment) || optional.FileAlignment > 65536U ||
	   optional.SectionAlignment < optional.FileAlignment ||
	   (optional.SectionAlignment < 4096U ? optional.SectionAlignment != optional.FileAlignment
										  : optional.FileAlignment < 512U) ||
	   optional.SizeOfHeaders % optional.FileAlignment != 0U ||
	   optional.SizeOfImage % optional.SectionAlignment != 0U) {
		return std::nullopt ;
	}

	const auto table = optionalAt + file->SizeOfOptionalHeader ;	// 元section表の起点です
	// 全section表は原header内、原headerはfileとimage内であることを要求します
	if( table + file->NumberOfSections * sizeof( IMAGE_SECTION_HEADER) > optional.SizeOfHeaders ||
	   optional.SizeOfHeaders > bytes.size() || optional.SizeOfHeaders > optional.SizeOfImage) {
		return std::nullopt ;
	}

	std::array<IMAGE_SECTION_HEADER, MAXIMUM_PE_SECTIONS> sections{} ;	// 原sectionだけの有限表です
	// 全宣言を先に検査し、別sectionのrawまたは仮想範囲で同じ位置を名乗らせません
	for( std::size_t i = 0U; i < file->NumberOfSections; ++i) {
		const auto section = readPeValue<IMAGE_SECTION_HEADER>(
			bytes, table + i * sizeof( IMAGE_SECTION_HEADER)) ;	// 元宣言です
		// 読取不能・headerへの重複・実file又はimage末尾を超えるsectionを拒否します
		if( !section || section->VirtualAddress < optional.SizeOfHeaders ||
		   section->VirtualAddress % optional.SectionAlignment != 0U ||
		   static_cast<std::uint64_t>( section->VirtualAddress) +
				   (std::max)( section->Misc.VirtualSize, section->SizeOfRawData) >
			   optional.SizeOfImage ||
		   (section->SizeOfRawData != 0U &&
			(section->PointerToRawData < optional.SizeOfHeaders ||
			 section->PointerToRawData % optional.FileAlignment != 0U ||
			 section->SizeOfRawData % optional.FileAlignment != 0U ||
			 static_cast<std::uint64_t>( section->PointerToRawData) + section->SizeOfRawData >
				 bytes.size()))) {
			return std::nullopt ;
		}

		// 同じraw byteや仮想位置が複数の属性を持つ宣言を拒否します
		for( std::size_t j = 0U; j < i; ++j) {
			const auto &other = sections[j] ;	// 既検証の先行sectionです
			// 空のraw区間だけはfile上の範囲を占めません
			if( overlaps( section->PointerToRawData, section->SizeOfRawData, other.PointerToRawData,
						other.SizeOfRawData) ||
			   overlaps( section->VirtualAddress,
						(std::max)( section->Misc.VirtualSize, section->SizeOfRawData),
						other.VirtualAddress,
						(std::max)( other.Misc.VirtualSize, other.SizeOfRawData))) {
				return std::nullopt ;
			}
		}

		sections[i] = *section ;
	}

	return CollectorPeImage{bytes, optional, sections, file->NumberOfSections} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み原PEから指定名の非転送の実行コードを照合します
 * @tparam Char 呼出し元に合わせたASCII互換の文字型です
 * @param[in] image 同じ原ファイルの固定配置です
 * @param[in] callback ASCIIの元名前です。大小文字を保持します
 * @return 一意な実コードへ到達すれば0、形式不正または不在はHRESULTです
 */
//------------------------------------------------------------------------------
template <typename Char>
[[nodiscard]] NativeError inspectNamedExport( const CollectorPeImage		 &image,
											 std::basic_string_view<Char> callback)
{
	constexpr NativeError INVALID_PE = HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT) ;	// 原構造不正です
	const auto			 &record =
		image.optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] ;	// 元export範囲です
	const auto exports = readPeValue<IMAGE_EXPORT_DIRECTORY>( image.region( record.VirtualAddress),
															 0U) ;	// 元表の件数とRVAです
	// 名前のないDLLや欠けた/過大なtableを許可しません
	if( !exports || record.Size < sizeof( IMAGE_EXPORT_DIRECTORY) ||
	   record.VirtualAddress > image.optional.SizeOfImage ||
	   record.Size > image.optional.SizeOfImage - record.VirtualAddress ||
	   exports->NumberOfFunctions == 0U || exports->NumberOfFunctions > MAXIMUM_EXPORTS ||
	   exports->NumberOfNames == 0U || exports->NumberOfNames > MAXIMUM_EXPORTS ||
	   static_cast<std::uint64_t>( exports->Base) + exports->NumberOfFunctions - 1U > MAXDWORD ||
	   exportText( image.region( exports->Name)).empty()) {
		return INVALID_PE ;
	}

	const auto array = [&]( DWORD rva, DWORD count,
						   std::size_t width) -> std::span<const std::byte> {
		const auto length	  = static_cast<std::size_t>( count) * width ;	// 件数は既に4096以内です
		const auto tableBytes = image.region( rva) ;						// 各RVAに対応するimage内の原fileです
		// tableのRVAはdirectoryと異なる節でも全要素が原byteに収まれば読めます
		if( length > tableBytes.size()) {
			return {} ;
		}

		return tableBytes.first( length) ;
	} ; // 元image内で固定幅配列を解決します
	const auto functions =
		// 元EATです
		array( exports->AddressOfFunctions, exports->NumberOfFunctions, sizeof( DWORD)) ;
	const auto names =
		// 名前RVA全件です
		array( exports->AddressOfNames, exports->NumberOfNames, sizeof( DWORD)) ;
	const auto ordinals = array( exports->AddressOfNameOrdinals, exports->NumberOfNames,
								// EAT indexです
								sizeof( WORD)) ;
	// 一表でも切れていれば正常な先頭entryも採用しません
	if( functions.empty() || names.empty() || ordinals.empty() ||
	   overlaps( exports->AddressOfFunctions, static_cast<DWORD>( functions.size()),
				exports->AddressOfNames, static_cast<DWORD>( names.size())) ||
	   overlaps( exports->AddressOfFunctions, static_cast<DWORD>( functions.size()),
				exports->AddressOfNameOrdinals, static_cast<DWORD>( ordinals.size())) ||
	   overlaps( exports->AddressOfNames, static_cast<DWORD>( names.size()),
				exports->AddressOfNameOrdinals, static_cast<DWORD>( ordinals.size())) ||
	   overlaps( record.VirtualAddress, sizeof( IMAGE_EXPORT_DIRECTORY), exports->AddressOfFunctions,
				static_cast<DWORD>( functions.size())) ||
	   overlaps( record.VirtualAddress, sizeof( IMAGE_EXPORT_DIRECTORY), exports->AddressOfNames,
				static_cast<DWORD>( names.size())) ||
	   overlaps( record.VirtualAddress, sizeof( IMAGE_EXPORT_DIRECTORY),
				exports->AddressOfNameOrdinals, static_cast<DWORD>( ordinals.size()))) {
		return INVALID_PE ;
	}

	const auto forwarded = [&]( DWORD rva) {
		return rva >= record.VirtualAddress && rva - record.VirtualAddress < record.Size ;
	} ; // export directory内は関数本体ではありません
	// forwarderの文字列は元directory内で終端する必要があります
	for( DWORD i = 0U; i < exports->NumberOfFunctions; ++i) {
		const auto target = *readPeValue<DWORD>( functions, i * sizeof( DWORD)) ;	// 元EAT要素です
		// 他の通常exportはdata/absolute値も持つため、callbackと同じ実コード条件を課しません
		if( forwarded( target)) {
			const auto tail = image.region( target) ;	// 同じfileにあるforwarder文字列です
			// 実sectionとexport directoryの共通末尾までの転送名byte数です
			const auto limit =
				(std::min)( tail.size(), static_cast<std::size_t>( record.Size -
																 (target - record.VirtualAddress))) ;
			// 終端がdirectory外又はfile外になる壊れた転送表を拒否します
			if( exportText( tail.first( limit)).empty()) {
				return INVALID_PE ;
			}
		}
	}

	std::string_view previous ;	// 重複や非整列名を原caseで検出します
	bool			 found{} ;	// 同名の多重定義は整列検査で拒否します
	// 全名前の原ordinalと文字列を検査してから結果を公開します
	for( DWORD i = 0U; i < exports->NumberOfNames; ++i) {
		const auto nameRva = *readPeValue<DWORD>( names, i * sizeof( DWORD)) ;	// 元ASCII名です
		const auto ordinal = *readPeValue<WORD>( ordinals, i * sizeof( WORD)) ;	// 元関数indexです
		const auto name	   = exportText( image.region( nameRva)) ;				// NUL確認済みの原名前です
		// 名前表は昇順で一意かつEAT内へ到達する必要があります
		if( name.empty() || (!previous.empty() && name <= previous) ||
		   ordinal >= exports->NumberOfFunctions) {
			return INVALID_PE ;
		}

		previous = name ;
		const auto target =
			*readPeValue<DWORD>( functions, ordinal * sizeof( DWORD)) ;	// 元名の関数RVAです
		// 空slotに名前を割り当てた壊れた表を許可しません
		if( target == 0U) {
			return INVALID_PE ;
		}

		// 元宣言名の厳密なcase一致だけを対象にします
		if( std::ranges::equal( name, callback)) {
			// 転送・非実行section・zero-fill・raw paddingをcallback本体へ数えません
			if( forwarded( target) || image.region( target, true).empty()) {
				return INVALID_PE ;
			}

			found = true ;
		}
	}

	return found ? 0 : HRESULT_FROM_WIN32( ERROR_PROC_NOT_FOUND) ;
}

// 同じDriver Store配置に置かれる元の三つのDLL名です
constexpr std::array<std::string_view, 3U> USB_WIRELESS_DLLS{
	"RTUWPSrvcLib.dll", "RTUWPUsbSwExt.dll", "RTUWPWlanExt.dll"} ;
// 補助EXEが参照する既知WindowsモジュールとAPIセットです
constexpr std::array<std::string_view, 20U> USB_WIRELESS_EXE_SYSTEM_IMPORTS{
	"KERNEL32.dll",
	"ADVAPI32.dll",
	"VERSION.dll",
	"USERENV.dll",
	"api-ms-win-core-debug-minidump-l1-1-0.dll",
	"api-ms-win-core-profile-l1-1-0.dll",
	"api-ms-win-core-synch-l1-1-0.dll",
	"api-ms-win-core-synch-l1-2-0.dll",
	"api-ms-win-core-processthreads-l1-1-0.dll",
	"api-ms-win-core-processthreads-l1-1-1.dll",
	"api-ms-win-core-sysinfo-l1-2-0.dll",
	"api-ms-win-core-sysinfo-l1-1-0.dll",
	"api-ms-win-core-localization-l1-2-0.dll",
	"api-ms-win-core-string-l1-1-0.dll",
	"api-ms-win-core-file-l1-1-0.dll",
	"api-ms-win-core-file-l2-1-0.dll",
	"api-ms-win-core-fibers-l1-1-0.dll",
	"api-ms-win-core-threadpool-l1-2-0.dll",
	"api-ms-win-core-libraryloader-l1-2-0.dll",
	"api-ms-win-core-util-l1-1-0.dll"} ;
// 同梱DLLそれぞれが参照する外部ファイルの完全名です
constexpr std::array<std::string_view, 4U> USB_WIRELESS_SERVICE_IMPORTS{
	"KERNEL32.dll", "USER32.dll", "ADVAPI32.dll", "SETUPAPI.dll"} ;
// 無線切替えDLLの元解析で確認した直接インポート先の閉集合
constexpr std::array<std::string_view, 3U> USB_WIRELESS_SWITCH_IMPORTS{
	"KERNEL32.dll", "ADVAPI32.dll", "SETUPAPI.dll"} ;
// WLAN DLLの元解析で確認した直接インポート先の閉集合
constexpr std::array<std::string_view, 5U> USB_WIRELESS_WLAN_IMPORTS{
	"KERNEL32.dll", "ADVAPI32.dll", "wlanapi.dll", "RPCRT4.dll",
	"ext-ms-win-networking-wlanapi-l1-1-0.dll"} ;
// 未知の補助PEの構造は元セットの上限内でも別経路に委ねます
constexpr std::size_t MAXIMUM_IMPORT_MODULES =
	USB_WIRELESS_EXE_SYSTEM_IMPORTS.size() + USB_WIRELESS_DLLS.size() ;
// 終端を含めるインポート用シンボルの走査上限
constexpr std::size_t MAXIMUM_IMPORT_SYMBOLS = 4096U ;

//------------------------------------------------------------------------------
/**
 * @brief 固定したモジュール名をASCIIの大小文字差だけを無視して比較します
 * @tparam Char ディスク名とPEの形式に応じた文字型です
 * @param[in] expected 正本のASCIIファイル名です
 * @param[in] actual 名前を切らずに読んだ原値です
 * @return 大小文字差を除く完全一致の場合trueです
 */
//------------------------------------------------------------------------------
template <typename Char>
bool equalImportModule( std::string_view expected, std::basic_string_view<Char> actual)
{
	const auto fold = []( unsigned code) {
		return code >= 'A' && code <= 'Z' ? code + ('a' - 'A') : code ;
	} ; // OEM文字や別名をASCIIへ置換しません
	return std::ranges::equal( expected, actual, [&]( char left, Char right) {
		return fold( static_cast<unsigned>( left)) == fold( static_cast<unsigned>( right)) ;
	}) ;
}

/** @brief 一モジュールの元インポート名とテーブル長です */
struct CollectorPeImportSymbols {
	/// 元PEを同期借用する先頭の非空シンボル名です
	std::string_view first ;
	/// 終端を含まない名前の個数です
	std::size_t		 count{} ;
	/// 終端を含む元ILTとIATのバイト数です
	DWORD			 byteCount{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 署名済み補助PE内の名前付き通常インポートを元の二つの配列に照合します
 * @param[in] image 同じ元バイトの検証済みPE配置です
 * @param[in] descriptor 読み込み済みの一モジュール宣言です
 * @param[in] iat 同じPEが宣言するIATの完全RVA範囲です
 * @return 両配列が完全一致し、有界な名前で終端した場合だけ結果を返します
 */
//------------------------------------------------------------------------------
std::optional<CollectorPeImportSymbols> readCollectorPeImportSymbols(
	const CollectorPeImage &image, const IMAGE_IMPORT_DESCRIPTOR &descriptor,
	const IMAGE_DATA_DIRECTORY &iat)
{
	const auto lookup = descriptor.OriginalFirstThunk ;	// 名前を読む元ILTのRVAです
	const auto target = descriptor.FirstThunk ;			// 読み込み前のIATを表す同じPEのRVAです
	// 別形式や結合済みアドレスからインポート名を推測しません
	if( descriptor.TimeDateStamp != 0U || descriptor.ForwarderChain != 0U || lookup == 0U ||
	   lookup % sizeof( std::uint64_t) != 0U || target < iat.VirtualAddress ||
	   target % sizeof( std::uint64_t) != 0U || target - iat.VirtualAddress >= iat.Size) {
		return std::nullopt ;
	}

	const auto				 lookupBytes  = image.region( lookup) ;	// 同じセクションにある元ILTです
	const auto				 targetRegion = image.region( target) ;	// 元IATの実セクションの残りです
	// 対象アドレスから、実領域とIATの宣言長の両方に収まるデータの借用範囲
	const auto				 targetBytes = targetRegion.first( (std::min)(
		  targetRegion.size(), static_cast<std::size_t>( iat.Size - (target - iat.VirtualAddress)))) ;
	CollectorPeImportSymbols result ;	// 終端確認まで確定しない元表です
	// すべての名前を一件ずつ読み、先頭名だけで同じ依存を認定しません
	for( std::size_t index = 0U; index <= MAXIMUM_IMPORT_SYMBOLS; ++index) {
		const auto offset	   = index * sizeof( std::uint64_t) ;					// 二配列で対応する元の位置です
		const auto lookupThunk = readPeValue<std::uint64_t>( lookupBytes, offset) ;	// 元ILTの値です
		const auto targetThunk = readPeValue<std::uint64_t>( targetBytes, offset) ;	// 元IATの値です
		// 今回の元形式で読み取れるRVAは名前を持つ32bit値だけです
		if( !lookupThunk || lookupThunk != targetThunk || *lookupThunk > MAXDWORD) {
			return std::nullopt ;
		}

		// 一つ以上の名前と同じ終端がそろった時点で元配列の全長を確定します
		if( *lookupThunk == 0U) {
			result.count	 = index ;
			result.byteCount = static_cast<DWORD>( offset + sizeof( std::uint64_t)) ;
			return index == 0U || overlaps( lookup, result.byteCount, iat.VirtualAddress, iat.Size)
					   ? std::nullopt
					   : std::optional{result} ;
		}

		const auto data = image.region( static_cast<DWORD>( *lookupThunk)) ;	// 元HintとASCII名です
		// NUL終端文字列を元セクション内から読みます
		if( data.size() <= sizeof( WORD)) {
			return std::nullopt ;
		}

		const auto symbol = exportText( data.subspan( sizeof( WORD))) ;	// Hint直後の完全名です
		// 欠落または壊れた名前から既知の関数を推定しません
		if( symbol.empty()) {
			return std::nullopt ;
		}

		// 同梱DLLは必要な一名前を後続のexport表へ結びます
		if( index == 0U) {
			result.first = symbol ;
		}
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのUSB無線PEが使用する既知の直接モジュールと必要な同梱名を照合します
 * @param[in] image 同じ元PEの検証済み配置です
 * @param[in] systemModules 元PEが参照するWindows側の完全名です
 * @param[out] privateSymbols EXEでは同梱DLLごとの一名前を返します。DLLは空の配列を渡します
 * @return 元の通常インポートがすべて対応すれば0、余分な宣言や不正形式はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError checkCollectorPeImports( const CollectorPeImage			 &image,
									std::span<const std::string_view> systemModules,
									std::span<std::string_view>		  privateSymbols)
{
	constexpr NativeError INVALID  = HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT) ;	// 元形式の診断です
	const auto			 &optional = image.optional ;								// 同じPEにある検査済み元ヘッダーです
	// DLLとEXEの元サブシステムとすべての依存ディレクトリー欄を確認します
	if( optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ||
	   (optional.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI &&
		optional.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI)) {
		return INVALID ;
	}

	// 後から別名を取り込む遅延表や別形式を元の通常インポートへまとめません
	for( const auto index : {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
							IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR}) {
		const auto &entry = optional.DataDirectory[index] ;	// 各元欄を同じ表から照会します
		// 空でない欄は元の閉じた直接依存の範囲外です
		if( entry.VirtualAddress != 0U || entry.Size != 0U) {
			return INVALID ;
		}
	}

	const auto &imports =
		optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] ;	// 元記述子の全範囲です
	const auto &iat =
		optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] ;					// 読み込み前の元IAT範囲です
	const auto descriptors	= image.region( imports.VirtualAddress) ;		// 同じファイルの元記述子です
	const auto targetRegion = image.region( iat.VirtualAddress) ;			// 元IATがある実セクションです
	const auto expected = systemModules.size() + privateSymbols.size() ;	// 元モジュール名の総数です
	constexpr std::size_t MAXIMUM_IAT_BYTES = 1024U * 1024U ;				// 表とゼロ埋め範囲の有限上限です
	// モジュール数は件数と空の終端を含む元ディレクトリー長で照合します
	if( expected > MAXIMUM_IMPORT_MODULES || imports.VirtualAddress == 0U ||
	   imports.Size != (expected + 1U) * sizeof( IMAGE_IMPORT_DESCRIPTOR) ||
	   imports.Size > descriptors.size() || iat.VirtualAddress == 0U || iat.Size == 0U ||
	   iat.Size > targetRegion.size() || iat.Size > MAXIMUM_IAT_BYTES ||
	   overlaps( imports.VirtualAddress, imports.Size, iat.VirtualAddress, iat.Size)) {
		return INVALID ;
	}

	std::array<bool, MAXIMUM_IMPORT_MODULES> seen{} ;						// 各モジュール名の重複を拒否します
	std::array<IMAGE_DATA_DIRECTORY, MAXIMUM_IMPORT_MODULES> targets{} ;	// IATの重複範囲を拒否します
	// すべての元記述子を順に読み、完全な名前と一意なIATへ結び付けます
	for( std::size_t index = 0U; index < expected; ++index) {
		const auto descriptor = *readPeValue<IMAGE_IMPORT_DESCRIPTOR>(
			descriptors,
			index * sizeof( IMAGE_IMPORT_DESCRIPTOR)) ;						// 全記述子は既に実バイト範囲内です
		const auto	name   = exportText( image.region( descriptor.Name)) ;	// 元の完全モジュール名です
		const auto	system = std::ranges::find_if( systemModules, [&]( const auto module) {
			 return equalImportModule( module, name) ;
		 }) ; // Windows側の既知集合を同期借用します
		std::size_t slot =
			// 一意な名前位置です
			static_cast<std::size_t>( system - systemModules.begin()) ;
		// Windows側にない名前はEXEの同梱DLL三件に限り検査します
		if( system == systemModules.end()) {
			const auto found = std::ranges::find_if( USB_WIRELESS_DLLS, [&]( const auto module) {
				return equalImportModule( module, name) ;
			}) ; // 元配布物の完全名だけをローカル依存として扱います
			slot += static_cast<std::size_t>( found - USB_WIRELESS_DLLS.begin()) ;
			// 別CLR、別APIセットや同梱DLLからの追加依存はこの原形式の範囲外です
			if( slot >= expected) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}
		}

		const auto symbols =
			// 元の名前と範囲です
			readCollectorPeImportSymbols( image, descriptor, iat) ;
		// 二つの元宣言から同じ名前を一件に縮約しません
		if( !symbols || std::exchange( seen[slot], true)) {
			return INVALID ;
		}

		targets[index] = {descriptor.FirstThunk, symbols->byteCount} ;
		// 同梱DLLの依存は元の一名前を、関数を提供する同じファイルへ戻して照合します
		if( slot >= systemModules.size()) {
			// 照合対象の同梱モジュールに余分なインポートが含まれるPEを拒否します
			if( symbols->count != 1U) {
				return INVALID ;
			}

			privateSymbols[slot - systemModules.size()] = symbols->first ;
		}
	}

	const auto terminator = descriptors.subspan( expected * sizeof( IMAGE_IMPORT_DESCRIPTOR),
												// 元表の完全な終端です
												sizeof( IMAGE_IMPORT_DESCRIPTOR)) ;
	const auto zero		  = []( std::byte value) {
		  return value == std::byte{} ;
	} ; // 実データのない埋め草です
	// 終端以外の記述子を余白として取り込みません
	if( !std::ranges::all_of( terminator, zero)) {
		return INVALID ;
	}

	const auto ranges = std::span{targets}.first( expected) ;	// 検証済み元モジュールのIAT範囲です
	std::ranges::sort( ranges, {}, &IMAGE_DATA_DIRECTORY::VirtualAddress) ;
	const auto	targetBytes = targetRegion.first( iat.Size) ;	// 元IATの宣言範囲に読取を限定します
	std::size_t next{} ;										// 直前までに確認した元IATの末尾です
	// 実体のない余白を許容し、重なる配列や未申告の値がある範囲を拒否します
	for( const auto &range : ranges) {
		// 対象のアドレス範囲をIATの先頭から測ったバイト位置
		const auto offset = static_cast<std::size_t>( range.VirtualAddress - iat.VirtualAddress) ;
		// 同じ元IATの先頭と各配列間のゼロ埋めだけを認めます
		if( offset < next || !std::ranges::all_of( targetBytes.subspan( next, offset - next), zero)) {
			return INVALID ;
		}

		next = offset + range.Size ;
	}

	return std::ranges::all_of( targetBytes.subspan( next), zero) ? 0 : INVALID ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元AMD64 DLLのexport表と宣言された一意なcallbackを静的に照合します
 * @param[in] bytes 呼出し中固定した原file全体の読取り専用byte列です
 * @param[in] callback 元INFの大小文字を保持したASCII名です
 * @return 実行可能節の原byteへ一意に到達すれば0、不正形式はHRESULTです
 * @note DLLをロードせず、内容の一致だけを扱います。CAT照合と導入判定は呼出し元の別工程です
 */
//------------------------------------------------------------------------------
NativeError inspectCollectorPropertyPageExport( std::span<const std::byte> bytes,
											   std::wstring_view		  callback)
{
	// 有界な名前と元配置を持つDLLだけを名前表の照合に進めます
	if( callback.empty() || callback.size() > MAXIMUM_EXPORT_NAME) {
		return HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT) ;
	}

	const auto image = readCollectorPeImage( bytes, true) ;	// 同じ元DLLの検証済み配置です
	return image ? inspectNamedExport( *image, callback) : HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元USB無線の補助EXEと三つの同梱DLLの直接インポートを静的に照合します
 * @param[in] files 同じ元CATと選択コピーへ結んだ補助EXEと三つのDLLです。並びは任意です
 * @return 元配置、既知Windows側の名前、同梱関数の非転送exportを照合できれば0です
 * @note 実行時に選ぶ追加モジュールや端末の状態は検査しません
 */
//------------------------------------------------------------------------------
NativeError inspectScopedUsbWirelessPeImports( std::span<const CollectorPeFile, 4U> files)
{
	constexpr auto INVALID = HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT) ;	// 元のPE配置の診断です
	// 同じ無線補助機能として照合する、主実行ファイルと三つの同梱DLL
	constexpr std::array<std::string_view, 4U> NAMES{"RTUWPSrvcMain.exe", USB_WIRELESS_DLLS[0],
													 USB_WIRELESS_DLLS[1], USB_WIRELESS_DLLS[2]} ;
	// 三つのDLLそれぞれで許可する直接のインポート先の表
	constexpr std::array<std::span<const std::string_view>, 3U> DLL_IMPORTS{
		USB_WIRELESS_SERVICE_IMPORTS, USB_WIRELESS_SWITCH_IMPORTS, USB_WIRELESS_WLAN_IMPORTS} ;
	std::array<std::optional<CollectorPeImage>, NAMES.size()>
		images ;	// 同じ元ファイルの検査済み配置です
	// 同じ配布物の全四ファイルを始めに役割と元バイト範囲へ一意に結びます
	for( const auto &file : files) {
		const auto expected = std::ranges::find_if( NAMES, [&]( const auto name) {
			return equalImportModule( name, file.name) ;
		}) ; // ファイル名は同じコピー元の借用値です
		// 探索順や拡張子だけで別の元ファイルを補助EXEや同梱DLLに読み替えません
		if( expected == NAMES.end()) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		const auto index = static_cast<std::size_t>( expected - NAMES.begin()) ;	// 元の配列位置です
		// 既に観測した役割への差し替えを許可しません
		if( images[index]) {
			return INVALID ;
		}

		images[index] = readCollectorPeImage( file.bytes, index != 0U) ;
		// 元ファイルが別形式の場合に部分検査で閉包を認定しません
		if( !images[index]) {
			return INVALID ;
		}
	}

	std::array<std::string_view, USB_WIRELESS_DLLS.size()> symbols ;	// EXEの元データを同期借用します
	// 主実行ファイルで確認したインポートの診断値。成功時だけ同梱DLLの照合を続ける
	auto error = checkCollectorPeImports( *images[0], USB_WIRELESS_EXE_SYSTEM_IMPORTS, symbols) ;
	// 補助EXEの全元宣言が揃わない場合は同梱DLLの一部を成功にしません
	if( error != 0U) {
		return error ;
	}

	// 同じモジュールの名前付き関数と、そのDLL自身の元直接インポートを照合します
	for( std::size_t index = 0U; index < symbols.size(); ++index) {
		const auto &image = *images[index + 1U] ;	// 元EXEが指した同じDLLです
		error			  = inspectNamedExport( image, symbols[index]) ;
		// 転送や欠落の名前を別ファイルの同名関数で代用しません
		if( error != 0U) {
			return error ;
		}

		error = checkCollectorPeImports( image, DLL_IMPORTS[index], {}) ;
		// 同梱DLLから先への未知の追加依存は元の閉包を満たしません
		if( error != 0U) {
			return error ;
		}
	}

	return 0U ;
}
} // namespace drivercrate
