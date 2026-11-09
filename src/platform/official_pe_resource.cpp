//------------------------------------------------------------------------------
/**
 * @file official_pe_resource.cpp
 * @brief collector専用の有界PE resource原範囲解決を実装する。
 * @version 01.00.00
 * @date 2026/11/03
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  原tupleとRVA/raw範囲を非実行で解決。
 * </pre>
 * @note 端末の内容slice処理からこのtree readerを呼ばない。
 */
//------------------------------------------------------------------------------
#include "platform/official_resource_content.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_seven_zip.h"
#include <Windows.h>
#include <algorithm>
#include <functional>
#include <new>
#include <set>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::uint64_t PE_BYTES = 64ULL * 1024ULL * 1024ULL ;	// small形式の原親上限。
/** @brief 解析scope内だけで元HRESULTを運ぶ。 */
struct ResourceFailure {
	/// 最初の構造拒否。
	NativeError error ;
} ;
/** @brief 条件違反を元構造エラーで中断する。
 * @param[in] condition 要求する構造条件。
 */
void need( const bool condition)
{
	// 不正byteを継続解析しない。
	if( !condition) {
		throw ResourceFailure{HRESULT_FROM_WIN32( ERROR_INVALID_DATA)} ;
	}
}
/** @brief 原範囲を減算で検査して固定viewを作る。
 * @param[in] data 呼出し中固定の親。
 * @param[in] offset 開始位置。
 * @param[in] bytes 読む長さ。
 * @return 原範囲の借用view。
 */
std::span<const std::byte> part( const std::span<const std::byte> data, const std::uint64_t offset,
								const std::uint64_t bytes)
{
	need( offset <= data.size() && bytes <= data.size() - offset) ;
	return data.subspan( static_cast<std::size_t>( offset), static_cast<std::size_t>( bytes)) ;
}
/** @brief 非整列のlittle-endian整数を原範囲内から読む。
 * @param[in] data 固定親。
 * @param[in] offset 読取り位置。
 * @param[in] count 2または4byte。
 * @return 幅を拡大した原整数。
 */
std::uint32_t integer( const std::span<const std::byte> data, const std::uint64_t offset,
					  const std::size_t count)
{
	const auto	  bytes = part( data, offset, count) ;	// 検査済み整数範囲。
	std::uint32_t result{} ;							// 全原byteを組み合わせる値。
	// 宣言幅だけをunaligned accessなしで読む。
	for( std::size_t index = 0; index < count; ++index) {
		result |= std::to_integer<std::uint32_t>( bytes[index]) << (index * 8U) ;
	}

	return result ;
}
/** @brief RVAを唯一のfile-backed raw sectionへ結ぶための原section。 */
struct RawSection {
	/// 原VirtualAddress。
	std::uint64_t rva ;
	/// 原PointerToRawData。
	std::uint64_t offset ;
	/// 原SizeOfRawData。
	std::uint64_t bytes ;
} ;
/** @brief UTF-16 resource名がNUL/不正surrogateを含まないか調べる。
 * @param[in] text 元名。
 * @return 有界で有効ならtrue。
 */
bool validName( const std::wstring_view text)
{
	// 未選択名もparserの有限範囲に収める。
	if( text.empty() || text.size() > 64U) {
		return false ;
	}

	// Pairを消費し、lone surrogateを認めない。
	for( std::size_t index = 0; index < text.size(); ++index) {
		const auto value = static_cast<std::uint16_t>( text[index]) ;	// 原UTF-16 unit。
		// NULはidentityへ含めない。
		if( value == 0U) {
			return false ;
		}

		// High surrogateの次にはlowが必要。
		if( value >= 0xd800U && value <= 0xdbffU) {
			// 読取り前に終端と対の範囲を検査する。
			if( ++index == text.size() || text[index] < 0xdc00U || text[index] > 0xdfffU) {
				return false ;
			}
		}
		// lone low surrogateを原名として受理しない。
		else if( value >= 0xdc00U && value <= 0xdfffU) {
			return false ;
		}
	}

	return true ;
}
} // namespace

/** @see official_resource_content.h */
NativeError collectOfficialPeResourceRanges( const std::span<const std::byte>	executable,
											std::vector<OfficialResourceSlice> &resources)
{
	resources.clear() ;
	try {
		need( !executable.empty() && executable.size() <= PE_BYTES) ;
		need( integer( executable, 0U, 2U) == IMAGE_DOS_SIGNATURE) ;
		const std::uint64_t pe = integer( executable, 0x3cU, 4U) ;	// 原PE header offset。
		need( integer( executable, pe, 4U) == IMAGE_NT_SIGNATURE) ;
		const auto count		 = integer( executable, pe + 6U, 2U) ;	// 有限なsection数。
		const auto optionalBytes = integer( executable, pe + 20U, 2U) ;	// 原optional header長。
		need( count > 0U && count <= 96U) ;
		const auto optional = part( executable, pe + 24U, optionalBytes) ;	// 固定header範囲。
		const auto magic	= integer( optional, 0U, 2U) ;					// PE32/PE32+の明示区別。
		need( magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ;
		const std::uint64_t directory =
			// DataDirectory位置。
			magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 96U : 112U ;
		need( integer( optional, directory - 4U, 4U) > IMAGE_DIRECTORY_ENTRY_RESOURCE) ;
		const auto rootRva = integer( optional, directory + 16U, 4U) ;		// resource DataDirectory RVA。
		const auto rootBytes = integer( optional, directory + 20U, 4U) ;	// 原directory範囲。
		need( rootBytes >= 16U) ;
		std::vector<RawSection> sections ;	// 原raw対応だけを保持。
		// section tableを全て原file範囲内で読む。
		for( std::uint32_t index = 0U; index < count; ++index) {
			const auto header =
				// 原section。
				part( executable, pe + 24U + optionalBytes + index * 40ULL, 40U) ;
			const RawSection section{integer( header, 12U, 4U), integer( header, 20U, 4U),
									 // 原raw範囲。
									 integer( header, 16U, 4U)} ;
			static_cast<void>( part( executable, section.offset, section.bytes)) ;
			sections.push_back( section) ;
		}

		const auto raw = [&]( const std::uint64_t rva, const std::uint64_t bytes) {
			need( bytes > 0U && rva <= UINT32_MAX && bytes <= 0x100000000ULL - rva) ;
			std::uint64_t result{} ;	// 一意に解決するoffset。
			std::size_t	  matches{} ;	// 曖昧なraw対応を拒否する件数。
			// VirtualSizeのzero-tailを原byteとして扱わない。
			for( const auto &section : sections) {
				// 全要求範囲を一sectionの実byteへ結ぶ。
				if( rva >= section.rva && rva - section.rva <= section.bytes &&
				   bytes <= section.bytes - (rva - section.rva)) {
					result = section.offset + rva - section.rva ;
					++matches ;
				}
			}

			need( matches == 1U) ;
			static_cast<void>( part( executable, result, bytes)) ;
			return result ;
		} ; // RVAの加算overflowと二重対応を局所化。
		const auto directoryBytes =
			// 原root相対範囲。
			part( executable, raw( rootRva, rootBytes), rootBytes) ;
		const auto identifier = [&]( const std::uint32_t value) {
			OfficialResourceIdentifier result ;	// 全成功後だけ使う原名。
			result.named = (value & 0x80000000U) != 0U ;
			// NameIsStringと数値IDを混同しない。
			if( result.named) {
				const std::uint64_t offset = value & 0x7fffffffU ;					// root相対文字列位置。
				const auto			units  = integer( directoryBytes, offset, 2U) ;	// UTF-16 unit数。
				need( units > 0U && units <= 64U) ;
				// 全文字列を幅検査したreaderから読む。
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
		} ; // Path文字列へ変換しない原atom。
		std::set<std::uint64_t>			   visited ;		// cycleとdirectory再参照を検出。
		std::size_t						   totalEntries{} ;	// tree全体の共同上限。
		std::vector<OfficialResourceSlice> result ;			// 全成功前には公開しない原leaf。
		std::function<void( std::uint64_t, unsigned, OfficialResourceTuple)>
			visit ;	// 三段だけの有限走査。
		visit = [&]( const std::uint64_t offset, const unsigned level, OfficialResourceTuple tuple) {
			need( level < 3U && visited.size() < 1024U && visited.insert( offset).second) ;
			const auto header = part( directoryBytes, offset, 16U) ;	// 原directory header。
			const auto entries =
				// 名+数値の全entry数。
				integer( header, 12U, 2U) + integer( header, 14U, 2U) ;
			need( entries <= 4096U - totalEntries) ;
			totalEntries += entries ;
			static_cast<void>( part( directoryBytes, offset + 16U, entries * 8ULL)) ;
			// 全entryを読むことで同じtupleの重複も検知する。
			for( std::uint32_t index = 0U; index < entries; ++index) {
				const auto entry =
					// 原entry。
					part( directoryBytes, offset + 16U + index * 8ULL, 8U) ;
				const auto atom	  = identifier( integer( entry, 0U, 4U)) ;	// 現段の原ID/名。
				const auto target = integer( entry, 4U, 4U) ;				// root相対directory/data位置。
				// levelごとの役割を固定しlisting順で推測しない。
				if( level == 0U) {
					tuple.type = atom ;
				}
				// 第二段の原nameを明示してleafへ渡す。
				else if( level == 1U) {
					tuple.name = atom ;
				} else {
					need( !atom.named) ;
					tuple.language = atom.id ;
				}

				// type/nameではdirectory、languageではdata leafだけを受理。
				if( level < 2U) {
					need( (target & 0x80000000U) != 0U) ;
					visit( target & 0x7fffffffU, level + 1U, tuple) ;
				} else {
					need( (target & 0x80000000U) == 0U) ;
					const auto leaf =
						// 原IMAGE_RESOURCE_DATA_ENTRY。
						part( directoryBytes, target, 16U) ;
					const auto size = integer( leaf, 4U, 4U) ;	// 原resource size。
					need( size <= PE_BYTES) ;
					const auto position = raw( integer( leaf, 0U, 4U), size) ;	// 一意な原file位置。
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
} // namespace drivercrate
