//------------------------------------------------------------------------------
/**
 * @file official_pe_resource.cpp
 * @brief 有界PE資源の原範囲解決とイベント用DLLの非実行検査を実装する
 * @version 01.01.01
 * @date 2026/11/03
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/23  イベントメッセージ用AMD64資源DLLの形式を検査
 * Ver.01.01.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 * @note 署名索引の資源slice処理はtreeを使わず、イベントDLLの形式検査は固定元byteを読む
 */
//------------------------------------------------------------------------------
#include "platform/official_resource_content.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_seven_zip.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <new>
#include <set>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::uint64_t PE_BYTES = 64ULL * 1024ULL * 1024ULL ;	// small形式の原親上限
/** @brief 解析scope内だけで元HRESULTを運ぶ */
struct ResourceFailure {
	/// 最初の構造拒否
	NativeError error ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 条件違反を元構造エラーで中断する
 * @param[in] condition 要求する構造条件
 */
//------------------------------------------------------------------------------
void need( const bool condition)
{
	// 不正byteを継続解析しない
	if( !condition) {
		throw ResourceFailure{HRESULT_FROM_WIN32( ERROR_INVALID_DATA)} ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 原範囲を減算で検査して固定viewを作る
 * @param[in] data 呼出し中固定の親
 * @param[in] offset 開始位置
 * @param[in] bytes 読む長さ
 * @return 原範囲の借用view
 */
//------------------------------------------------------------------------------
std::span<const std::byte> part( const std::span<const std::byte> data, const std::uint64_t offset,
								const std::uint64_t bytes)
{
	need( offset <= data.size() && bytes <= data.size() - offset) ;
	return data.subspan( static_cast<std::size_t>( offset), static_cast<std::size_t>( bytes)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 非整列のlittle-endian整数を原範囲内から読む
 * @param[in] data 固定親
 * @param[in] offset 読取り位置
 * @param[in] count 2または4byte
 * @return 幅を拡大した原整数
 */
//------------------------------------------------------------------------------
std::uint32_t integer( const std::span<const std::byte> data, const std::uint64_t offset,
					  const std::size_t count)
{
	const auto	  bytes = part( data, offset, count) ;	// 検査済み整数範囲
	std::uint32_t result{} ;							// 全原byteを組み合わせる値
	// 宣言幅だけをunaligned accessなしで読む
	for( std::size_t index = 0; index < count; ++index) {
		result |= std::to_integer<std::uint32_t>( bytes[index]) << (index * 8U) ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief メッセージテーブルの各ID範囲と可変長エントリーを元資源内で検査する
 * @param[in] table PEの数値資源から検証済み範囲を借用する
 * @param[in,out] remaining 全テーブルで共有する構造読取り件数の残り
 * @throws ResourceFailure 元構造が不足しているか件数の上限を超えた場合
 * @note 文字列は表示や解釈を行わない
 */
//------------------------------------------------------------------------------
void verifyMessageTable( const std::span<const std::byte> table, std::uint64_t &remaining)
{
	constexpr auto BLOCKS_AT = offsetof( MESSAGE_RESOURCE_DATA, Blocks) ;	// ブロック配列の開始
	constexpr auto TEXT_AT	 = offsetof( MESSAGE_RESOURCE_ENTRY, Text) ;	// 元文面の開始幅
	const auto	   count =
		// 元ブロック数
		integer( table, offsetof( MESSAGE_RESOURCE_DATA, NumberOfBlocks), 4U) ;
	// 元テーブル内に収まる場合だけ借用するメッセージ範囲の配列
	const auto blocks =
		part( table, BLOCKS_AT, static_cast<std::uint64_t>( count) * sizeof( MESSAGE_RESOURCE_BLOCK)) ;
	const auto entriesAt = BLOCKS_AT + blocks.size() ;	// ブロック宣言の末尾
	need( count > 0U && count <= remaining) ;
	remaining -= count ;
	// 各ID範囲の元位置から、宣言した件数の可変長行だけを消費する
	for( std::uint64_t blockIndex = 0U; blockIndex < count; ++blockIndex) {
		const auto block = part( blocks, blockIndex * sizeof( MESSAGE_RESOURCE_BLOCK),
								// 元ID範囲の固定欄
								sizeof( MESSAGE_RESOURCE_BLOCK)) ;
		const auto low	 = integer( block, offsetof( MESSAGE_RESOURCE_BLOCK, LowId), 4U) ;	// 最初のID
		const auto high	 = integer( block, offsetof( MESSAGE_RESOURCE_BLOCK, HighId), 4U) ;	// 最後のID
		// このメッセージ範囲の最初の可変長レコードへのテーブル内オフセット
		std::uint64_t at = integer( block, offsetof( MESSAGE_RESOURCE_BLOCK, OffsetToEntries), 4U) ;
		need( low <= high && at >= entriesAt && at <= table.size()) ;
		const auto entries = static_cast<std::uint64_t>( high) - low + 1U ;	// 上下端を含む件数
		need( entries <= (table.size() - at) / (TEXT_AT + 1U) && entries <= remaining) ;
		remaining -= entries ;
		// 長さが立つエントリーだけ次へ進み、各エントリーを元範囲内に固定する
		for( std::uint64_t index = 0U; index < entries; ++index) {
			const auto length =
				// 全欄のbyte数
				integer( table, at + offsetof( MESSAGE_RESOURCE_ENTRY, Length), 2U) ;
			const auto flags =
				// ANSIかUnicode
				integer( table, at + offsetof( MESSAGE_RESOURCE_ENTRY, Flags), 2U) ;
			need( length > TEXT_AT && (flags == 0U || (flags == MESSAGE_RESOURCE_UNICODE &&
													  (length - TEXT_AT) % sizeof( wchar_t) == 0U))) ;
			static_cast<void>( part( table, at, length)) ;
			at += length ;
		}
	}
}
/** @brief RVAを唯一のfile-backed raw sectionへ結ぶための原section */
struct RawSection {
	/// 原VirtualAddress
	std::uint64_t rva ;
	/// 原PointerToRawData
	std::uint64_t offset ;
	/// 原SizeOfRawData
	std::uint64_t bytes ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief UTF-16 resource名がNUL/不正surrogateを含まないか調べる
 * @param[in] text 元名
 * @return 有界で有効ならtrue
 */
//------------------------------------------------------------------------------
bool validName( const std::wstring_view text)
{
	// 未選択名もparserの有限範囲に収める
	if( text.empty() || text.size() > 64U) {
		return false ;
	}

	// Pairを消費し、lone surrogateを認めない
	for( std::size_t index = 0; index < text.size(); ++index) {
		const auto value = static_cast<std::uint16_t>( text[index]) ;	// 原UTF-16 unit
		// NULはidentityへ含めない
		if( value == 0U) {
			return false ;
		}

		// High surrogateの次にはlowが必要
		if( value >= 0xd800U && value <= 0xdbffU) {
			// 読取り前に終端と対の範囲を検査する
			if( ++index == text.size() || text[index] < 0xdc00U || text[index] > 0xdfffU) {
				return false ;
			}
		}
		// lone low surrogateを原名として受理しない
		else if( value >= 0xdc00U && value <= 0xdfffU) {
			return false ;
		}
	}

	return true ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief collector専用に原PEのtyped leafとraw範囲を有界列挙する
 * @param[in] executable 固定したPE32/PE32+原byte。最大64MiB
 * @param[out] resources 成功時だけ原tuple/range。hashは未計算
 * @return 全構造受理0、曖昧・破損・上限はHRESULT。fileを作らない
 */
//------------------------------------------------------------------------------
NativeError collectOfficialPeResourceRanges( const std::span<const std::byte>	executable,
											std::vector<OfficialResourceSlice> &resources)
{
	resources.clear() ;
	try {
		need( !executable.empty() && executable.size() <= PE_BYTES) ;
		need( integer( executable, 0U, 2U) == IMAGE_DOS_SIGNATURE) ;
		const std::uint64_t pe = integer( executable, 0x3cU, 4U) ;	// 原PE header offset
		need( integer( executable, pe, 4U) == IMAGE_NT_SIGNATURE) ;
		const auto count		 = integer( executable, pe + 6U, 2U) ;	// 有限なsection数
		const auto optionalBytes = integer( executable, pe + 20U, 2U) ;	// 原optional header長
		need( count > 0U && count <= 96U) ;
		const auto optional = part( executable, pe + 24U, optionalBytes) ;	// 固定header範囲
		const auto magic	= integer( optional, 0U, 2U) ;					// PE32/PE32+の明示区別
		need( magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ;
		const std::uint64_t directory =
			// DataDirectory位置
			magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 96U : 112U ;
		need( integer( optional, directory - 4U, 4U) > IMAGE_DIRECTORY_ENTRY_RESOURCE) ;
		const auto rootRva	 = integer( optional, directory + 16U, 4U) ;	// resource DataDirectory RVA
		const auto rootBytes = integer( optional, directory + 20U, 4U) ;	// 原directory範囲
		need( rootBytes >= 16U) ;
		std::vector<RawSection> sections ;	// 原raw対応だけを保持
		// section tableを全て原file範囲内で読む
		for( std::uint32_t index = 0U; index < count; ++index) {
			const auto header =
				// 原section
				part( executable, pe + 24U + optionalBytes + index * 40ULL, 40U) ;
			const RawSection section{integer( header, 12U, 4U), integer( header, 20U, 4U),
									 // 原raw範囲
									 integer( header, 16U, 4U)} ;
			static_cast<void>( part( executable, section.offset, section.bytes)) ;
			sections.push_back( section) ;
		}

		const auto raw = [&]( const std::uint64_t rva, const std::uint64_t bytes) {
			need( bytes > 0U && rva <= UINT32_MAX && bytes <= 0x100000000ULL - rva) ;
			std::uint64_t result{} ;	// 一意に解決するoffset
			std::size_t	  matches{} ;	// 曖昧なraw対応を拒否する件数
			// VirtualSizeのzero-tailを原byteとして扱わない
			for( const auto &section : sections) {
				// 全要求範囲を一sectionの実byteへ結ぶ
				if( rva >= section.rva && rva - section.rva <= section.bytes &&
				   bytes <= section.bytes - (rva - section.rva)) {
					result = section.offset + rva - section.rva ;
					++matches ;
				}
			}

			need( matches == 1U) ;
			static_cast<void>( part( executable, result, bytes)) ;
			return result ;
		} ; // RVAの加算overflowと二重対応を局所化
		const auto directoryBytes =
			// 原root相対範囲
			part( executable, raw( rootRva, rootBytes), rootBytes) ;
		const auto identifier = [&]( const std::uint32_t value) {
			OfficialResourceIdentifier result ;	// 全成功後だけ使う原名
			result.named = (value & 0x80000000U) != 0U ;
			// NameIsStringと数値IDを混同しない
			if( result.named) {
				const std::uint64_t offset = value & 0x7fffffffU ;					// root相対文字列位置
				const auto			units  = integer( directoryBytes, offset, 2U) ;	// UTF-16 unit数
				need( units > 0U && units <= 64U) ;
				// 全文字列を幅検査したreaderから読む
				for( std::uint32_t index = 0U; index < units; ++index) {
					result.text.push_back( static_cast<wchar_t>(
						integer( directoryBytes, offset + 2U + index * 2ULL, 2U))) ;
				}

				need( validName( result.text)) ;
			} else {
				need( value <= 65535U) ;
				result.id = value ;
			}

			return result ;
		} ; // Path文字列へ変換しない原atom
		std::set<std::uint64_t>			   visited ;		// cycleとdirectory再参照を検出
		std::size_t						   totalEntries{} ;	// tree全体の共同上限
		std::vector<OfficialResourceSlice> result ;			// 全成功前には公開しない原leaf
		std::function<void( std::uint64_t, unsigned, OfficialResourceTuple)>
			visit ;	// 三段だけの有限走査
		visit = [&]( const std::uint64_t offset, const unsigned level, OfficialResourceTuple tuple) {
			need( level < 3U && visited.size() < 1024U && visited.insert( offset).second) ;
			const auto header = part( directoryBytes, offset, 16U) ;	// 原directory header
			const auto entries =
				// 名+数値の全entry数
				integer( header, 12U, 2U) + integer( header, 14U, 2U) ;
			need( entries <= 4096U - totalEntries) ;
			totalEntries += entries ;
			static_cast<void>( part( directoryBytes, offset + 16U, entries * 8ULL)) ;
			// 全entryを読むことで同じtupleの重複も検知する
			for( std::uint32_t index = 0U; index < entries; ++index) {
				const auto entry =
					// 原entry
					part( directoryBytes, offset + 16U + index * 8ULL, 8U) ;
				const auto atom	  = identifier( integer( entry, 0U, 4U)) ;	// 現段の原ID/名
				const auto target = integer( entry, 4U, 4U) ;				// root相対directory/data位置
				// levelごとの役割を固定しlisting順で推測しない
				if( level == 0U) {
					tuple.type = atom ;
				}
				// 第二段の原nameを明示してleafへ渡す
				else if( level == 1U) {
					tuple.name = atom ;
				} else {
					need( !atom.named) ;
					tuple.language = atom.id ;
				}

				// type/nameではdirectory、languageではdata leafだけを受理
				if( level < 2U) {
					need( (target & 0x80000000U) != 0U) ;
					visit( target & 0x7fffffffU, level + 1U, tuple) ;
				} else {
					need( (target & 0x80000000U) == 0U) ;
					const auto leaf =
						// 原IMAGE_RESOURCE_DATA_ENTRY
						part( directoryBytes, target, 16U) ;
					const auto size = integer( leaf, 4U, 4U) ;	// 原resource size
					need( size <= PE_BYTES) ;
					const auto position = raw( integer( leaf, 0U, 4U), size) ;	// 一意な原file位置
					need( std::ranges::none_of(
						result, [&]( const auto &item) { return item.resource == tuple ; })) ;
					result.push_back( {tuple, position, size, {}}) ;
				}
			}
		} ;
		visit( 0U, 0U, {}) ;
		resources = std::move( result) ;
		return 0 ;
	} catch( const ResourceFailure &failure) {
		return failure.error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 固定されたPEがデータ専用のAMD64イベントメッセージDLLの形を満たすか調べる
 * @param[in] image 元PE全byteの借用範囲。同期中は同じ内容を保持する
 * @return DLLの形式と原メッセージ資源が成立すれば0、その他は元HRESULT
 * @note ファイルを開かず、ロードや実行も行わない。元CATと配布byteの照合は呼出側の責務
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialEventMessageResourceDll( const std::span<const std::byte> image)
{
	try {
		need( image.size() <= PE_BYTES && integer( image, 0U, 2U) == IMAGE_DOS_SIGNATURE) ;
		const std::uint64_t pe = integer( image, 0x3cU, 4U) ;	// PE署名位置の原値
		need( integer( image, pe, 4U) == IMAGE_NT_SIGNATURE) ;
		const auto coff =
			// 元COFFヘッダー
			part( image, pe + sizeof( DWORD), sizeof( IMAGE_FILE_HEADER)) ;
		const auto flags =
			// image種別
			integer( coff, offsetof( IMAGE_FILE_HEADER, Characteristics), 2U) ;
		need( integer( coff, offsetof( IMAGE_FILE_HEADER, Machine), 2U) == IMAGE_FILE_MACHINE_AMD64 &&
			 (flags & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_SYSTEM)) ==
				 (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)) ;

		const std::uint64_t optionalAt =
			pe + sizeof( DWORD) + sizeof( IMAGE_FILE_HEADER) ;	// 元optional位置
		// 元COFFヘッダーが指定したオプションヘッダーのバイト数
		const auto optionalBytes =
			integer( coff, offsetof( IMAGE_FILE_HEADER, SizeOfOptionalHeader), 2U) ;
		const auto optional = part( image, optionalAt, optionalBytes) ;	// 宣言されたoptional範囲
		need( integer( optional, offsetof( IMAGE_OPTIONAL_HEADER64, Magic), 2U) ==
				 IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
			 integer( optional, offsetof( IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint), 4U) == 0U &&
			 integer( optional, offsetof( IMAGE_OPTIONAL_HEADER64, SizeOfCode), 4U) == 0U) ;

		const auto directoryCount = integer(
			optional, offsetof( IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes), 4U) ;	// 元directory数
		// PE32+オプションヘッダー内のディレクトリ配列へのバイト位置
		constexpr std::size_t DIRECTORY_AT = offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory) ;
		need( directoryCount > IMAGE_DIRECTORY_ENTRY_RESOURCE &&
			 directoryCount <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES && optional.size() >= DIRECTORY_AT) ;
		const auto available = std::min( static_cast<std::size_t>( IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
										(optional.size() - DIRECTORY_AT) /
											// 元域で確認できる全欄
											sizeof( IMAGE_DATA_DIRECTORY)) ;
		need( directoryCount <= available) ;
		const auto			 directories = part( optional, DIRECTORY_AT,
												available * sizeof( IMAGE_DATA_DIRECTORY)) ;	// 元域にある欄だけ
		constexpr std::array CODE_DIRECTORIES{
			IMAGE_DIRECTORY_ENTRY_EXPORT,		 IMAGE_DIRECTORY_ENTRY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_TLS,			 IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
			IMAGE_DIRECTORY_ENTRY_IAT,			 IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR} ;	// コードの結合に使う種類
		// 元ヘッダーが宣言する各種類を確認し、RVAとサイズの両方が0の場合だけ空とする
		for( const auto index : CODE_DIRECTORIES) {
			// 元optionalに存在する欄は、元の件数で隠れていても空値を確認する
			if( static_cast<std::size_t>( index) < available) {
				// 個別のディレクトリエントリーへの配列内バイト位置
				const auto at = static_cast<std::uint64_t>( index) * sizeof( IMAGE_DATA_DIRECTORY) ;
				need( integer( directories, at, 4U) == 0U && integer( directories, at + 4U, 4U) == 0U) ;
			}
		}

		// 元COFFヘッダーが指定したセクションの件数
		const auto sectionCount = integer( coff, offsetof( IMAGE_FILE_HEADER, NumberOfSections), 2U) ;
		need( sectionCount > 0U && sectionCount <= 96U) ;
		// 全セクションを宣言範囲と照合し、コード又は実行可能とされた節を拒否する
		for( std::uint64_t index = 0U; index < sectionCount; ++index) {
			// 元バイト範囲に収まる場合だけ借用する現在のセクションヘッダー
			const auto section =
				part( image, optionalAt + optionalBytes + index * sizeof( IMAGE_SECTION_HEADER),
					 sizeof( IMAGE_SECTION_HEADER)) ;
			// セクションがデータ専用の条件を満たすか確認する属性ビット
			const auto attributes =
				integer( section, offsetof( IMAGE_SECTION_HEADER, Characteristics), 4U) ;
			need( (attributes & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) == 0U) ;
		}

		std::vector<OfficialResourceSlice> resources ;	// 元directoryから展開した全資源範囲
		// イベントメッセージ用の資源を元ファイル内で照合した診断値
		const auto error = collectOfficialPeResourceRanges( image, resources) ;
		// 共通解析が返す元の構造エラーを保持する
		if( error != 0U) {
			return error ;
		}

		constexpr std::uint32_t MESSAGE_TABLE_TYPE = 11U ;	// WinUserの数値資源種別RT_MESSAGETABLE
		std::uint64_t			remaining =
			// 元PEサイズに結ぶ全テーブルの共同枠
			image.size() / sizeof( DWORD) ;
		bool checked{} ;	// 数値種別の資源を一件以上検査した場合にtrue
		// 他の資源型をメッセージへ読み替えず、該当する各資源を共有上限内で検査する
		for( const auto &item : resources) {
			// 文字列名を数値種別の代わりにしない
			if( !item.resource.type.named && item.resource.type.id == MESSAGE_TABLE_TYPE) {
				verifyMessageTable( part( image, item.offset, item.length), remaining) ;
				checked = true ;
			}
		}

		need( checked) ;
		return 0U ;
	} catch( const ResourceFailure &failure) {
		return failure.error ;
	}
}
} // namespace drivercrate
