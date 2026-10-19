//------------------------------------------------------------------------------
/**
 * @file maintenance_embedded_file_table.cpp
 * @brief 保守専用PE内固定長ファイル表の有限解析実装。
 * @version 01.00.01
 * @date 2026/10/05
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  保守専用の有限表解析を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note byteを再配置せず原範囲だけを返します。型番・section名・固定offsetへ依存しません。
 * @see docs/adr/0260-maintenance-pe-flat-file-table.md
 */
//------------------------------------------------------------------------------

#include "platform/maintenance_embedded_file_table.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 固定予算と借用型。
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_BYTES		 = 64U * 1024U * 1024U ;	// 原EXEの有限上限。
constexpr std::size_t NAME_BYTES		 = 260U ;					// 固定名fieldのbyte数。
constexpr std::size_t HEADER_BYTES		 = 264U ;					// 名とuint32長からなる項目長。
constexpr std::size_t MAXIMUM_FILES		 = 128U ;					// 一表の最大項目数。
constexpr std::size_t MAXIMUM_CANDIDATES = 16U ;					// 一入力の最大候補表数。
constexpr NativeError INVALID_DATA =
	// 構造拒否値。
	static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
/**
 * @brief 呼出し中だけ借用する原byte。
 */
using Bytes = std::span<const std::byte> ;

/** @brief 原EXE内の重ならないdata section範囲を保持する。 */
struct Section {
	/// 原EXE内raw先頭。
	std::size_t first{} ;
	/// 原EXE内raw末尾。
	std::size_t last{} ;
	/// Readonly initialized dataならtrue。
	bool		eligible{} ;
} ;

/**
 * @brief 既知の有効範囲からlittle-endian整数をalignment非依存で読む。
 * @param[in] raw 不変の原byte。
 * @param[in] offset 呼出し側が境界確認した先頭。
 * @param[in] count 2または4のfield長。
 * @return uint32に収まるfield値。
 */
std::uint32_t readInteger( const Bytes raw, const std::size_t offset,
						  const std::size_t count) noexcept
{
	std::uint32_t result{} ;	// 4 byte以下のlittle-endian値。
	// 境界確認済みの小fieldだけを順番に読む。
	for( std::size_t index = 0U; index < count; ++index) {
		result |= std::to_integer<std::uint32_t>( raw[offset + index]) << (index * 8U) ;
	}

	return result ;
}

/**
 * @brief 許容されるflat名のASCII文字だけを識別する。
 * @param[in] character 不変の一byte。
 * @return 英数字・underscore・hyphen・periodならtrue。
 */
bool isNameCharacter( const unsigned char character) noexcept
{
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
		   (character >= '0' && character <= '9') || character == '_' || character == '-' ||
		   character == '.' ;
}

/**
 * @brief ASCII名を比較用の小文字へ変換する。
 * @param[in] name 最大259 byteの借用名。
 * @return 同じbyte数の小文字名。
 */
std::string lowerName( const std::string_view name)
{
	std::string result( name) ;	// File名のcase非依存比較専用。
	// ASCII大文字だけを正規化し、localeの影響を受けない。
	for( char &character : result) {
		// 小文字化の対象外byteは変更しない。
		if( character >= 'A' && character <= 'Z') {
			character = static_cast<char>( character + ('a' - 'A')) ;
		}
	}

	return result ;
}

/**
 * @brief NUL後zeroの固定field形状だけを識別する。
 * @param[in] raw 原EXEの不変byte。
 * @param[in] offset section内の候補先頭。
 * @param[in] end section末尾。
 * @return 形状が整合する場合の名byte数。形状不一致は0。
 * @note 安全性は別検査とし、危険名の隣接項目を無視しません。
 */
std::size_t headerNameSize( const Bytes raw, const std::size_t offset,
						   const std::size_t end) noexcept
{
	// 減算によってfield境界とoverflowを同時に拒否する。
	if( offset > end || HEADER_BYTES > end - offset) {
		return 0U ;
	}

	const Bytes field = raw.subspan( offset, NAME_BYTES) ;						// 名fieldだけを借用する。
	const auto	zero  = std::find( field.begin(), field.end(), std::byte{}) ;	// 最初のNUL位置。
	// 空名と終端欠損を表項目として使用しない。
	if( zero == field.begin() || zero == field.end() ||
	   !std::all_of( zero, field.end(),
					[]( const std::byte value) { return value == std::byte{} ; })) {
		return 0U ;
	}

	return static_cast<std::size_t>( zero - field.begin()) ;
}

/**
 * @brief PE header・非重複raw section・certificate範囲を検査する。
 * @param[in] raw 最大64 MiBの原byte。
 * @param[out] sections 成功時の最大96 raw section。失敗時は利用禁止です。
 * @return PE32+ x64の有限な範囲が整合すればtrue。
 */
bool readSections( const Bytes raw, std::vector<Section> &sections)
{
	// DOS headerより短い入力と異形式を静的拒否する。
	if( raw.size() < 64U || raw[0] != std::byte{'M'} || raw[1] != std::byte{'Z'}) {
		return false ;
	}

	const std::size_t pe = readInteger( raw, 60U, 4U) ;	// DOSが指すPE header。
	// PE最小headerを範囲確認してから各fieldを読む。
	if( pe < 64U || pe > raw.size() || 24U > raw.size() - pe ||
	   readInteger( raw, pe, 4U) != 0x00004550U || readInteger( raw, pe + 4U, 2U) != 0x8664U) {
		return false ;
	}

	const std::size_t count			= readInteger( raw, pe + 6U, 2U) ;	// Section数の有限宣言。
	const std::size_t optional		= pe + 24U ;						// Optional header先頭。
	const std::size_t optionalBytes = readInteger( raw, pe + 20U, 2U) ;	// Optional header長。
	// Security directoryまでないheaderや過大section数を受理しない。
	if( count == 0U || count > 96U || optionalBytes < 152U ||
	   optionalBytes > raw.size() - optional || readInteger( raw, optional, 2U) != 0x20bU ||
	   readInteger( raw, optional + 108U, 4U) < 5U) {
		return false ;
	}

	const std::size_t table		  = optional + optionalBytes ;						// PE section表の先頭。
	const std::size_t headers	  = readInteger( raw, optional + 60U, 4U) ;			// SizeOfHeaders。
	const std::size_t certificate = readInteger( raw, optional + 144U, 4U) ;		// Security raw offset。
	const std::size_t certificateBytes = readInteger( raw, optional + 148U, 4U) ;	// Security長。
	// Raw headerとsecurityの不整合をfile表解析で補完しない。
	if( count * 40U > raw.size() - table || headers < table + count * 40U || headers > raw.size() ||
	   (certificate == 0U) != (certificateBytes == 0U) || certificate > raw.size() ||
	   certificateBytes > raw.size() - certificate ||
	   (certificateBytes != 0U && (certificate < headers || certificate % 8U != 0U))) {
		return false ;
	}

	// 各sectionのraw範囲を確認し、表と本文が別領域へはみ出さないようにする。
	for( std::size_t index = 0U; index < count; ++index) {
		const std::size_t	entry = table + index * 40U ;					// 現section header先頭。
		const std::size_t	bytes = readInteger( raw, entry + 16U, 4U) ;	// Raw section長。
		const std::size_t	first = readInteger( raw, entry + 20U, 4U) ;	// Raw section先頭。
		const std::uint32_t flags = readInteger( raw, entry + 36U, 4U) ;	// Section属性。
		// Rawを持たないsectionは走査対象にならない。
		if( bytes == 0U) {
			continue ;
		}

		// 範囲超過・header／certificateとの重なりを拒否する。
		if( first < headers || first > raw.size() || bytes > raw.size() - first ||
		   (certificateBytes != 0U && first < certificate + certificateBytes &&
			first + bytes > certificate)) {
			return false ;
		}

		// 先行sectionとのraw重複を許さない。
		for( const Section &previous : sections) {
			// Aliasする領域を別候補と解釈しない。
			if( first < previous.last && first + bytes > previous.first) {
				return false ;
			}
		}

		sections.push_back( {first, first + bytes,
							(flags & 0x40000040U) == 0x40000040U && (flags & 0xa0000000U) == 0U}) ;
	}

	return !sections.empty() ;
}

/**
 * @brief 安全なflat名と許容file種類を確認する。
 * @param[in] name 比較用小文字ASCII名。
 * @return 許容拡張子ならそのsuffix、危険名なら空です。
 */
std::string_view safeSuffix( const std::string_view name) noexcept
{
	// 隠し名・path区切り・JSON制御文字を受理しない。
	if( name.empty() || name.front() == '.' || name.back() == '.' ||
	   !std::all_of( name.begin(), name.end(), isNameCharacter)) {
		return {} ;
	}

	const std::size_t	   dot	= name.find_last_of( '.') ;				// 拡張子の区切り。
	const std::string_view stem = name.substr( 0U, name.find( '.')) ;	// Windows予約名比較対象。
	// Windows device名は拡張子付きでも拒否する。
	if( stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" ||
	   (stem.size() == 4U && (stem.starts_with( "com") || stem.starts_with( "lpt")) &&
		stem.back() >= '1' && stem.back() <= '9') ||
	   dot == std::string_view::npos) {
		return {} ;
	}

	const std::string_view suffix = name.substr( dot) ;	// 拡張子だけを返す借用view。
	constexpr std::array   allowed{std::string_view( ".inf"), std::string_view( ".cat"),
								   std::string_view( ".sys"), std::string_view( ".dll"),
								   std::string_view( ".exe"), std::string_view( ".chm"),
								   // 観測済みの非圧縮種類。
								   std::string_view( ".txt")} ;
	return std::find( allowed.begin(), allowed.end(), suffix) != allowed.end() ? suffix
																			  : std::string_view{} ;
}

/**
 * @brief 唯一候補の全項目・本文範囲・zero paddingを検査する。
 * @param[in] raw 原EXEの不変byte。
 * @param[in] section 表と本文を包含するreadonly section。
 * @param[in] start 固定項目表の先頭。
 * @param[out] result 成功時の全表。失敗時は利用禁止です。
 * @return 全項目と最低限のINF／CAT／SYS形状が整合すればtrue。
 */
bool readTable( const Bytes raw, const Section &section, const std::size_t start,
			   MaintenanceEmbeddedFileTable &result)
{
	std::size_t				 offset = start ;	// 全形状項目を先に集めるcursor。
	std::vector<std::string> names ;			// Case非依存重複検出用の最大128名。
	bool					 hasInf{} ;			// INF root形状の存在。
	bool					 hasCat{} ;			// CAT root形状の存在。
	bool					 hasSys{} ;			// SYS形状の存在。
	// 形状が連続する限り全項目を検査し、危険名をskipしない。
	while( const std::size_t length = headerNameSize( raw, offset, section.last)) {
		// 項目上限を超える表は部分受理しない。
		if( result.files.size() >= MAXIMUM_FILES) {
			return false ;
		}

		std::string name ;	// ASCIIをbyte単位でコピーする所有名。
		// 検査済みNUL前の名をpointer castなしで取り出す。
		for( std::size_t index = 0U; index < length; ++index) {
			name.push_back( static_cast<char>( std::to_integer<unsigned char>( raw[offset + index]))) ;
		}

		const std::string	   lower  = lowerName( name) ;						// 全項目で統一する比較名。
		const std::string_view suffix = safeSuffix( lower) ;					// 許容種類。空なら拒否。
		const std::size_t bytes = readInteger( raw, offset + NAME_BYTES, 4U) ;	// 宣言された原file長。
		// 重複・危険名・過大宣言・DLL以外のempty fileを拒否する。
		if( suffix.empty() || std::find( names.begin(), names.end(), lower) != names.end() ||
		   bytes > MAXIMUM_BYTES || (bytes == 0U && suffix != ".dll")) {
			return false ;
		}

		hasInf = hasInf || suffix == ".inf" ;
		hasCat = hasCat || suffix == ".cat" ;
		hasSys = hasSys || suffix == ".sys" ;
		names.push_back( lower) ;
		result.files.push_back( {std::move( name), 0U, bytes}) ;
		offset += HEADER_BYTES ;
	}

	// 表にはdriver root三種類と4 byte境界を要求する。
	if( !hasInf || !hasCat || !hasSys || offset % 4U != 0U || result.files.size() < 3U) {
		return false ;
	}

	result.tableOffset = start ;
	result.blobOffset  = offset ;
	// 宣言順に原範囲を割り当て、各種類とpaddingを確認する。
	for( MaintenanceEmbeddedFile &file : result.files) {
		const std::size_t padding = (4U - file.bytes % 4U) % 4U ;	// 0～3 byteの末尾zero。
		// 加算前の減算で範囲超過を検出する。
		if( offset > section.last || file.bytes > section.last - offset ||
		   padding > section.last - offset - file.bytes) {
			return false ;
		}

		file.offset					 = offset ;
		const Bytes			   body	 = raw.subspan( offset, file.bytes) ;	// Paddingを除く原file借用。
		const std::string	   lower = lowerName( file.name) ;				// 本文種類のcase非依存比較。
		const std::string_view suffix = safeSuffix( lower) ;				// 先に安全性を検査済み。
		// 実在PE memberの最小headerを確認し、誤ったdata開始を受理しない。
		if( file.bytes != 0U && (suffix == ".sys" || suffix == ".dll" || suffix == ".exe")) {
			// DOS header未満はPEと扱わない。
			if( body.size() < 64U || body[0] != std::byte{'M'} || body[1] != std::byte{'Z'}) {
				return false ;
			}

			const std::size_t pe = readInteger( body, 60U, 4U) ;	// Member内PE signature位置。
			// Member境界内のPE signatureだけを読む。
			if( pe < 64U || pe > body.size() || 24U > body.size() - pe ||
			   readInteger( body, pe, 4U) != 0x00004550U) {
				return false ;
			}
		}

		// 観測形式のCATは4 byte DER長と宣言長が完全一致する必要がある。
		if( suffix == ".cat" &&
		   (body.size() < 4U || body[0] != std::byte{0x30} || body[1] != std::byte{0x82} ||
			(std::to_integer<std::size_t>( body[2]) * 256U + std::to_integer<std::size_t>( body[3]) +
			 4U) != body.size())) {
			return false ;
		}

		// ASCII INFの先頭有限範囲だけで構造rootを確認する。内容検査は別入口で行う。
		if( suffix == ".inf") {
			std::string prefix ;	// 最大1024 byteの構造確認専用文字列。
			// Raw本文は出力せず、先頭だけをmarker比較へコピーする。
			for( std::size_t index = 0U; index < std::min( body.size(), std::size_t{1024U});
				++index) {
				prefix.push_back( static_cast<char>( std::to_integer<unsigned char>( body[index]))) ;
			}

			// 大容量・別形式・Version欠損を合格INFとしない。
			if( body.size() > 1024U * 1024U || prefix.find( "[Version]") == std::string::npos ||
			   prefix.find( "$Windows NT$") == std::string::npos) {
				return false ;
			}
		}

		const Bytes zeros = raw.subspan( offset + file.bytes, padding) ;	// 4 byte整列の原padding。
		// Paddingをfile本文へ含めたり非zeroを無視したりしない。
		if( !std::all_of( zeros.begin(), zeros.end(),
						[]( const std::byte value) { return value == std::byte{} ; })) {
			return false ;
		}

		offset += file.bytes + padding ;
	}

	result.blobBytes = offset - result.blobOffset ;
	return true ;
}

} // namespace

/**
 * @copydoc drivercrate::inspectMaintenanceEmbeddedFileTable(std::span<const std::byte>, MaintenanceEmbeddedFileTable &)
 */
NativeError inspectMaintenanceEmbeddedFileTable( const Bytes					  executable,
												MaintenanceEmbeddedFileTable &layout) noexcept
{
	layout = {} ;
	try {
		// 大入力と空入力は走査開始前に拒否する。
		if( executable.empty() || executable.size() > MAXIMUM_BYTES) {
			return INVALID_DATA ;
		}

		std::vector<Section> sections ;	// 最大96の検証済みraw領域。
		// PE不整合を別形式fallbackへ渡さない。
		if( !readSections( executable, sections)) {
			return INVALID_DATA ;
		}

		std::vector<std::pair<Section, std::size_t>> candidates ;	// 最大16の固有表位置。
		// Readonly dataだけを一度走査し、INF名を含む固定項目表を見つける。
		for( const Section &section : sections) {
			// 実行・書込み可能なsectionを保守dataとして解釈しない。
			if( !section.eligible) {
				continue ;
			}

			// Suffix照合は5 byte以上の残り範囲内だけで行う。
			for( std::size_t cursor = section.first; section.last - cursor >= 5U; ++cursor) {
				// INF名以外の本文markerは候補表にしない。
				if( executable[cursor] != std::byte{'.'} ||
				   (executable[cursor + 1U] != std::byte{'i'} &&
					executable[cursor + 1U] != std::byte{'I'}) ||
				   (executable[cursor + 2U] != std::byte{'n'} &&
					executable[cursor + 2U] != std::byte{'N'}) ||
				   (executable[cursor + 3U] != std::byte{'f'} &&
					executable[cursor + 3U] != std::byte{'F'}) ||
				   executable[cursor + 4U] != std::byte{}) {
					continue ;
				}

				std::size_t start = cursor ;	// INF名の先頭まで有限に戻すcursor。
				// 一名259 byte以内に制限して安全文字の先頭へ戻す。
				while( start > section.first && cursor - start < NAME_BYTES &&
					  isNameCharacter( std::to_integer<unsigned char>( executable[start - 1U]))) {
					--start ;
				}

				// Suffix以外の名がない候補と固定header形状でない候補を除く。
				if( start == cursor || headerNameSize( executable, start, section.last) == 0U) {
					continue ;
				}

				std::size_t preceding{} ;	// 戻した項目数。上限超過なら表全体を拒否。
				// 危険名も形状段階では含め、table途中だけを選択しない。
				while( start >= section.first + HEADER_BYTES &&
					  headerNameSize( executable, start - HEADER_BYTES, section.last) != 0U) {
					// 過大連続表の無制限後方走査を止める。
					if( ++preceding >= MAXIMUM_FILES) {
						return INVALID_DATA ;
					}

					start -= HEADER_BYTES ;
				}

				// 同じ表に複数INFがあっても候補数を水増ししない。
				if( std::any_of( candidates.begin(), candidates.end(),
							   [start]( const auto &candidate) {
								   // Start値だけを借用期間内に比較する。
								   return candidate.second == start ;
							   })) {
					continue ;
				}

				// 有限候補上限を超える入力は部分受理しない。
				if( candidates.size() >= MAXIMUM_CANDIDATES) {
					return INVALID_DATA ;
				}

				candidates.emplace_back( section, start) ;
			}
		}

		MaintenanceEmbeddedFileTable checked ;	// 全検証成功まで外部へ出さない所有表。
		// 複数候補と未対応は成功範囲なしで拒否する。
		if( candidates.size() != 1U ||
		   !readTable( executable, candidates.front().first, candidates.front().second, checked)) {
			return INVALID_DATA ;
		}

		layout = std::move( checked) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

} // namespace drivercrate
