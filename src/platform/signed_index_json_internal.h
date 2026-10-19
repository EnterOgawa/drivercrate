//------------------------------------------------------------------------------
/**
 * @file signed_index_json_internal.h
 * @brief 署名索引各層で共用する厳格JSON・base64・hash・UTC文法を定義します。
 * @version 01.01.00
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  既存strict文法を共用し有限配列・深さを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  必須fieldの既定を維持しschema別存在maskとnull読取りを追加。
 * </pre>
 *
 * @note 原byteを正規化せず、暗号認証・公式性・保存・端末照合を行いません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_manifest.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

namespace drivercrate::signed_index_json {

/** @brief 各層の拒否理由と元診断だけを保持します。
 * @tparam Status 呼出し層の固定拒否区分。
 */
template <class Status> struct Failure {
	/// 最初に検出した拒否理由。
	Status		status ;
	/// 元HRESULT。入力拒否では0です。
	NativeError error{} ;
} ;

/** @brief 不成立の場合だけ最上位のfail-closed結果へ中断します。
 * @tparam Status 呼出し層の固定拒否区分。
 * @param[in] valid 成立条件。
 * @param[in] status 不成立時の固定分類。
 */
template <class Status> void require( const bool valid, const Status status)
{
	// 不成立の中間値を認証結果へ公開しない。
	if( !valid) {
		throw Failure<Status>{status} ;
	}
}

/**
 * @brief 固定objectだけを読む有限JSON readerです。元byteの順序や空白を変えません。
 * @tparam Status 呼出し層の固定拒否区分。
 * @note 一般JSON DOMを作らず、schemaごとの固定field集合で深さとfield数を限定します。
 */
template <class Status> class Reader final {
public:
	/** @brief 借用原byteのUTF-8を事前に検査します。
     * @param[in] bytes 独立byte上限内の原UTF-8。Readerの寿命中に変更しません。
     * @param[in] failure この層のJSON拒否理由。
     * @param[in] byteLimit 呼出し層の独立実byte上限。
     * @param[in] depthLimit Containerの最大深さ。既定8です。
     */
	Reader( const std::string_view bytes, const Status failure,
		   const std::size_t byteLimit	= INDEX_ENVELOPE_MAX_BYTES,
		   const std::size_t depthLimit = 8U)
		: bytes_( bytes), failure_( failure), depthLimit_( depthLimit)
	{
		// Win32境界のint長へ変換する前に実byteを固定枠へ制限する。
		require( !bytes.empty() && bytes.size() <= byteLimit && byteLimit <= 128U * 1024U * 1024U &&
					depthLimit > 0U && depthLimit <= 8U,
				failure_) ;
		// MB_ERR_INVALID_CHARSで過長UTF-8、surrogate、途中切れを拒否する。
		require( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
									static_cast<int>( bytes.size()), nullptr, 0) != 0,
				failure_) ;
	}

	/** @brief 一つのJSON文字列を標準escapeに従って解除します。
     * @param[in] limit 解除後の実byte上限。
     * @return Unicodeを保持した所有UTF-8。正規化はしません。
     */
	[[nodiscard]] std::string text( const std::size_t limit)
	{
		consume( '"') ;
		std::string value ;	// 上限以内でだけ追記する解除後の所有値。
		// 原byteの終端またはescapeされていないquoteまで一度ずつ走査する。
		while( position_ < bytes_.size()) {
			const char character = bytes_[position_++] ;	// 現在の原byte。
			// 完全な終端quoteがある場合だけ値を確定する。
			if( character == '"') {
				return value ;
			}

			require( static_cast<unsigned char>( character) >= 0x20U, failure_) ;
			// UTF-8原文字は事前検査済みのまま保持する。
			if( character != '\\') {
				append( value, character, limit) ;
				continue ;
			}

			require( position_ < bytes_.size(), failure_) ;
			const char escape = bytes_[position_++] ;	// 標準JSON escape識別子。
			// Unicode escapeはsurrogate pairを含めscalarへ戻す。
			if( escape == 'u') {
				std::uint32_t scalar = hexQuad() ;	// 一つ目のUTF-16 code unit。
				// High surrogateは必ず直後のlow surrogateへ結合する。
				if( scalar >= 0xd800U && scalar <= 0xdbffU) {
					require( bytes_.substr( position_).starts_with( "\\u"), failure_) ;
					position_ += 2U ;
					const std::uint32_t low = hexQuad() ;	// 二つ目のcode unit。
					require( low >= 0xdc00U && low <= 0xdfffU, failure_) ;
					scalar = 0x10000U + ((scalar - 0xd800U) << 10U) + low - 0xdc00U ;
				} else {
					require( scalar < 0xdc00U || scalar > 0xdfffU, failure_) ;
				}

				appendScalar( value, scalar, limit) ;
				continue ;
			}

			// JSONが定義する一byte escapeだけへ戻し、未知escapeを拒否する。
			switch( escape) {
				// Quote escapeは元quoteへ戻す。
				case '"':
				// Slash escapeは元slashへ戻し、同じ共通追記へ進む。
				case '/':
				// Backslash escapeは元backslashへ戻す。
				case '\\':
					append( value, escape, limit) ;
					break ;

				// 制御文字escapeは構文として解除し、意味層の固定値で拒否する。
				case 'b':
					append( value, '\b', limit) ;
					break ;

				// Form feedを構文として解除し、固定値の意味検査へ残す。
				case 'f':
					append( value, '\f', limit) ;
					break ;

				// 改行を構文として解除し、固定値の意味検査へ残す。
				case 'n':
					append( value, '\n', limit) ;
					break ;

				// 復帰を構文として解除し、固定値の意味検査へ残す。
				case 'r':
					append( value, '\r', limit) ;
					break ;

				// Tabを構文として解除し、固定値の意味検査へ残す。
				case 't':
					append( value, '\t', limit) ;
					break ;

				// その他は標準JSONとして成立しない。
				default:
					throw Failure<Status>{failure_} ;
			}
		}

		throw Failure<Status>{failure_} ;
	}

	/** @brief 非負のJSON整数をoverflow前に検査します。
     * @return uint64_tで正確に表現した値。小数・指数・符号は拒否します。
     */
	[[nodiscard]] std::uint64_t number()
	{
		whitespace() ;
		const std::size_t start = position_ ;	// 先頭zeroと空値の検査位置。
		std::uint64_t	  value{} ;				// 全桁を成功した場合だけ返す整数。
		// 十進桁を有限入力の末尾まで走査し、加算前にoverflowを拒否する。
		while( position_ < bytes_.size() && bytes_[position_] >= '0' && bytes_[position_] <= '9') {
			const auto digit = static_cast<std::uint64_t>( bytes_[position_++] - '0') ;	// 次の桁。
			require( value <= (std::numeric_limits<std::uint64_t>::max() - digit) / 10U, failure_) ;
			value = value * 10U + digit ;
		}

		require( position_ != start && (bytes_[start] != '0' || position_ == start + 1U), failure_) ;
		return value ;
	}

	/** @brief 全必須fieldを順序に依存せず一度だけ消費します。
     * @tparam Count 固定field数。最大16です。
     * @tparam Handler Field indexに対応する型付き読取り関数。
     * @param[in] fields Schemaが認める固定field名。
     * @param[in] handler 本Readerだけを借用して値を消費する同期関数。
     */
	template <std::size_t Count, class Handler>
	void object( const std::array<std::string_view, Count> &fields, Handler handler)
	{
		// 既存入口は全field必須のまま保ち、optional fieldを暗黙に許可しない。
		require( objectWithPresence( fields, handler) == (1U << Count) - 1U, failure_) ;
	}

	/** @brief 許可fieldを一度だけ読み、schema確定後の必須集合照合へ存在maskを返します。
     * @tparam Count 許可field数。最大16です。
     * @tparam Handler Field番号から要求型だけを読む同期関数。
     * @param[in] fields このobjectだけが許可する閉じたfield集合。
     * @param[in] handler 本Readerを呼出し中だけ借用する同期handler。
     * @return 読んだfieldのbit mask。呼出し側はschema確定後に全必須集合を厳格照合します。
     * @note 未知field、解除後重複key、深さ、余剰commaを既存と同じ規則で拒否します。
     */
	template <std::size_t Count, class Handler>
	[[nodiscard]] std::uint32_t objectWithPresence(
		const std::array<std::string_view, Count> &fields, Handler handler)
	{
		static_assert( Count > 0U && Count <= 16U) ;
		consume( '{') ;
		enterContainer() ;
		std::uint32_t seen{} ;	// 解除後のfield名に対する重複検査mask。
		// 固定field数以内で全memberを読み、終端または最初の違反で終了する。
		for( std::size_t count = 0U; count < Count; ++count) {
			const std::string key	= text( 64U) ;						// Unicode escapeも解除したfield名。
			const auto		  found = std::ranges::find( fields, key) ;	// 固定schemaの一致位置。
			require( found != fields.end(), failure_) ;
			const auto index = static_cast<std::size_t>( found - fields.begin()) ;	// 固定範囲index。
			const std::uint32_t mask = 1U << index ;								// このfieldの存在bit。
			require( (seen & mask) == 0U, failure_) ;
			seen |= mask ;
			consume( ':') ;
			handler( index) ;
			whitespace() ;
			// 終端の存在集合だけを返し、schema固有の必須判定は呼出し側へ残す。
			if( position_ < bytes_.size() && bytes_[position_] == '}') {
				++position_ ;
				--depth_ ;
				return seen ;
			}

			consume( ',') ;
		}

		throw Failure<Status>{failure_} ;
	}

	/** @brief 次の値がJSON nullの場合だけ消費します。
     * @return nullを消費した場合true。別型ではbyte位置を変えずfalseです。
     * @note Nullの直後のdelimiterと余剰byteは親objectまたはfinishが検査します。
     */
	[[nodiscard]] bool nullValue()
	{
		whitespace() ;
		// 明示nullだけを認め、空値や未知literalを欠損へ補完しない。
		if( bytes_.substr( position_).starts_with( "null")) {
			position_ += 4U ;
			return true ;
		}

		return false ;
	}

	/** @brief 有限配列を順序どおり読みます。
     * @tparam Handler 一要素を型付きで消費する同期関数。
     * @param[in] limit 配列要素数の独立上限。
     * @param[in] handler Readerと所有出力を呼出し期間だけ借用する同期関数。
     * @param[in] limitFailure 上限超過の拒否区分。
     */
	template <class Handler>
	void array( const std::size_t limit, Handler handler, const Status limitFailure)
	{
		consume( '[') ;
		enterContainer() ;
		whitespace() ;
		// 空配列も明示的に消費し、schemaの件数意味は呼出し側へ残す。
		if( position_ < bytes_.size() && bytes_[position_] == ']') {
			++position_ ;
			--depth_ ;
			return ;
		}

		// 上限内の要素だけを読み、完全終端または最初の違反で終了する。
		for( std::size_t count = 0U; count < limit; ++count) {
			handler() ;
			whitespace() ;
			// 配列の全消費だけを成功とし、余剰commaを許可しない。
			if( position_ < bytes_.size() && bytes_[position_] == ']') {
				++position_ ;
				--depth_ ;
				return ;
			}

			consume( ',') ;
		}

		throw Failure<Status>{limitFailure} ;
	}

	/** @brief 最終値以外の末尾byteを拒否します。 */
	void finish()
	{
		whitespace() ;
		require( position_ == bytes_.size(), failure_) ;
	}

private:
	/** @brief Containerを開始し、次の入れ子が有限深さ以内か検査します。 */
	void enterContainer()
	{
		require( depth_ < depthLimit_, failure_) ;
		++depth_ ;
	}
	/** @brief JSONで定義された四種類の空白だけを飛ばします。 */
	void whitespace() noexcept
	{
		// 有限入力に含まれる標準空白だけを消費し、他のbyteで停止する。
		while( position_ < bytes_.size() &&
			  (bytes_[position_] == ' ' || bytes_[position_] == '\t' || bytes_[position_] == '\r' ||
			   bytes_[position_] == '\n')) {
			++position_ ;
		}
	}
	/** @brief 次の標準delimiterを要求します。
     * @param[in] expected 必須delimiter。
     */
	void consume( const char expected)
	{
		whitespace() ;
		require( position_ < bytes_.size() && bytes_[position_] == expected, failure_) ;
		++position_ ;
	}
	/** @brief 四hex桁をUTF-16 code unitとして読みます。
     * @return 0～65535の値。不正桁は拒否します。
     */
	[[nodiscard]] std::uint32_t hexQuad()
	{
		require( bytes_.size() - position_ >= 4U, failure_) ;
		std::uint32_t value{} ;	// 次のscalarへ結合するcode unit。
		// 必須の四桁だけを読み、JSONの大小両hex表現を認める。
		for( std::size_t index = 0U; index < 4U; ++index) {
			const char	  character = bytes_[position_++] ;	// 現在hex桁。
			std::uint32_t digit{} ;							// 検査後の0～15。
			// 数字のhex領域を十進と同じ値へ対応させる。
			if( character >= '0' && character <= '9') {
				digit = static_cast<std::uint32_t>( character - '0') ;
			}
			// 小文字hexを正確に対応させる。
			else if( character >= 'a' && character <= 'f') {
				digit = static_cast<std::uint32_t>( character - 'a' + 10) ;
			}
			// 大文字hexも標準JSONとして認める。
			else if( character >= 'A' && character <= 'F') {
				digit = static_cast<std::uint32_t>( character - 'A' + 10) ;
			} else {
				throw Failure<Status>{failure_} ;
			}

			value = (value << 4U) | digit ;
		}

		return value ;
	}
	/** @brief 解除後byteを上限検査して追記します。
     * @param[in,out] value 所有値。
     * @param[in] character 追記byte。
     * @param[in] limit 実byte上限。
     */
	void append( std::string &value, const char character, const std::size_t limit)
	{
		require( value.size() < limit, failure_) ;
		value.push_back( character) ;
	}
	/** @brief 一つのUnicode scalarを正規UTF-8へ戻します。
     * @param[in,out] value 所有値。
     * @param[in] scalar 検査済みscalar。
     * @param[in] limit 解除後byte上限。
     */
	void appendScalar( std::string &value, const std::uint32_t scalar, const std::size_t limit)
	{
		// ASCIIは一byteで同じ値を保持する。
		if( scalar < 0x80U) {
			append( value, static_cast<char>( scalar), limit) ;
		}
		// 二byte領域は最短UTF-8へ戻す。
		else if( scalar < 0x800U) {
			append( value, static_cast<char>( 0xc0U | (scalar >> 6U)), limit) ;
			append( value, static_cast<char>( 0x80U | (scalar & 0x3fU)), limit) ;
		}
		// 非surrogateのBMP scalarを三byteへ戻す。
		else if( scalar < 0x10000U) {
			append( value, static_cast<char>( 0xe0U | (scalar >> 12U)), limit) ;
			append( value, static_cast<char>( 0x80U | ((scalar >> 6U) & 0x3fU)), limit) ;
			append( value, static_cast<char>( 0x80U | (scalar & 0x3fU)), limit) ;
		} else {
			// Surrogate pairから復元した補助平面scalarを四byteへ戻す。
			append( value, static_cast<char>( 0xf0U | (scalar >> 18U)), limit) ;
			append( value, static_cast<char>( 0x80U | ((scalar >> 12U) & 0x3fU)), limit) ;
			append( value, static_cast<char>( 0x80U | ((scalar >> 6U) & 0x3fU)), limit) ;
			append( value, static_cast<char>( 0x80U | (scalar & 0x3fU)), limit) ;
		}
	}
	/// 呼出し元から借用する変更しない原byte。
	std::string_view bytes_ ;
	/// Envelopeまたはmanifestの固定JSON拒否分類。
	Status			 failure_ ;
	/// 呼出し層が固定した最大container深さ。
	std::size_t		 depthLimit_{} ;
	/// 現在のcontainer深さ。成功した終端で減らします。
	std::size_t		 depth_{} ;
	/// 次に読む原byte位置。入力長を超えません。
	std::size_t		 position_{} ;
} ;

/** @brief 標準base64 alphabetを6bit値へ変換します。
 * @param[in] character 原ASCII。
 * @return 0～63。Alphabet以外は-1。
 */
[[nodiscard]] inline int base64Digit( const char character) noexcept
{
	// 各alphabet領域だけを許可し、空白やURL-safe表現を補正しない。
	if( character >= 'A' && character <= 'Z') {
		return character - 'A' ;
	}

	// 小文字領域は後続26値へ対応させる。
	if( character >= 'a' && character <= 'z') {
		return character - 'a' + 26 ;
	}

	// 数字領域は52から始まる。
	if( character >= '0' && character <= '9') {
		return character - '0' + 52 ;
	}

	// Plusは標準alphabetの62。
	if( character == '+') {
		return 62 ;
	}

	// Slashは標準alphabetの63。
	if( character == '/') {
		return 63 ;
	}

	return -1 ;
}

/** @brief 正規paddingと未使用bitを検査してbase64を有限decodeします。
 * @param[in] text 原base64。空白を認めません。
 * @param[in] limit Decode後の実byte上限。
 * @tparam Status 呼出し層の固定拒否区分。
 * @param[in] sizeFailure Decode後上限違反の分類。
 * @param[in] invalidBase64 不正base64の拒否区分。
 * @return 元順序の所有byte。
 */
template <class Status>
[[nodiscard]] std::vector<std::uint8_t> decodeBase64( const std::string_view text,
													 const std::size_t		limit,
													 const Status			sizeFailure,
													 const Status			invalidBase64)
{
	require( !text.empty() && text.size() % 4U == 0U, invalidBase64) ;
	const std::size_t padding =
		// 末尾だけのpadding。
		text.ends_with( "==") ? 2U : (text.ends_with( "=") ? 1U : 0U) ;
	const std::size_t size = text.size() / 4U * 3U - padding ;	// 外側上限内でoverflowしない。
	require( size > 0U && size <= limit, sizeFailure) ;
	std::vector<std::uint8_t> bytes ;	// 検査後に確保する所有decode結果。
	bytes.reserve( size) ;
	// 一quartetごとに検査し、paddingは最後のquartetだけへ限定する。
	for( std::size_t offset = 0U; offset < text.size(); offset += 4U) {
		const int  first  = base64Digit( text[offset]) ;		// 上位6bit。
		const int  second = base64Digit( text[offset + 1U]) ;	// 後続6bit。
		const bool last	  = offset + 4U == text.size() ;		// Paddingを許可する終端。
		const int  third =
			// 第三値。
			text[offset + 2U] == '=' && last ? 0 : base64Digit( text[offset + 2U]) ;
		const int fourth =
			// 第四値。
			text[offset + 3U] == '=' && last ? 0 : base64Digit( text[offset + 3U]) ;
		require( first >= 0 && second >= 0 && third >= 0 && fourth >= 0, invalidBase64) ;
		require( text[offset + 2U] != '=' || (last && padding == 2U), invalidBase64) ;
		require( text[offset + 3U] != '=' || (last && padding > 0U), invalidBase64) ;
		require( !last || (padding != 2U || (second & 15) == 0), invalidBase64) ;
		require( !last || (padding != 1U || (third & 3) == 0), invalidBase64) ;
		bytes.push_back( static_cast<std::uint8_t>( (first << 2) | (second >> 4))) ;
		// 最後の二paddingでは有効byteを一つに限定する。
		if( !last || padding < 2U) {
			bytes.push_back( static_cast<std::uint8_t>( (second << 4) | (third >> 2))) ;
		}

		// 最後のpaddingがある場合は第三byteを作らない。
		if( !last || padding == 0U) {
			bytes.push_back( static_cast<std::uint8_t>( (third << 6) | fourth)) ;
		}
	}

	return bytes ;
}

/** @brief 小文字64桁hexを固定hash型へ変換します。
 * @tparam Status 呼出し層の固定拒否区分。
 * @param[in] text 原hex。
 * @param[in] failure 不成立時の分類。
 * @return 正確な32byte。
 */
template <class Status>
[[nodiscard]] IndexManifestSha256 decodeHash( const std::string_view text, const Status failure)
{
	require( text.size() == 64U, failure) ;
	IndexManifestSha256 digest{} ;	// 全桁検査後に返すhash。
	// 各byteの二桁だけを読み、大小変換や長さ補正を行わない。
	for( std::size_t index = 0U; index < digest.size(); ++index) {
		std::uint8_t value{} ;	// このbyteの検査済み桁。
		// 上位・下位の二桁を順番に確認する。
		for( std::size_t half = 0U; half < 2U; ++half) {
			const char character = text[index * 2U + half] ;	// 元hex桁。
			require( (character >= '0' && character <= '9') ||
						(character >= 'a' && character <= 'f'),
					failure) ;
			const auto digit = static_cast<std::uint8_t>(
				character <= '9' ? character - '0' : character - 'a' + 10) ;	// 検査済み0～15。
			value = static_cast<std::uint8_t>( (value << 4U) | digit) ;
		}

		digest[index] = value ;
	}

	return digest ;
}

/** @brief 固定桁のASCII十進値を読みます。
 * @tparam Status 呼出し層の固定拒否区分。
 * @param[in] text 桁数が固定された借用値。
 * @param[in] failure 不正時の分類。
 * @return 小さな暦日・時刻値。
 */
template <class Status>
[[nodiscard]] unsigned decimal( const std::string_view text, const Status failure)
{
	unsigned value{} ;	// 最大四桁の暦日値。
	// 固定した桁だけを確認し、符号や空白を認めない。
	for( const char character : text) {
		require( character >= '0' && character <= '9', failure) ;
		value = value * 10U + static_cast<unsigned>( character - '0') ;
	}

	return value ;
}

/** @brief 実在するUTC暦日と秒単位時刻を読みます。
 * @tparam Status 呼出し層の固定拒否区分。
 * @param[in] text 固定20byteのUTC。
 * @param[in] failure 不正暦日・時刻の拒否区分。
 * @return 1970～9999年のUTC秒。
 */
template <class Status>
[[nodiscard]] std::chrono::sys_seconds utc( const std::string_view text, const Status failure)
{
	require( text.size() == 20U && text[4] == '-' && text[7] == '-' && text[10] == 'T' &&
				text[13] == ':' && text[16] == ':' && text[19] == 'Z',
			failure) ;
	const unsigned year	  = decimal( text.substr( 0U, 4U), failure) ;	// UTC暦年。
	const unsigned month  = decimal( text.substr( 5U, 2U), failure) ;	// UTC暦月。
	const unsigned day	  = decimal( text.substr( 8U, 2U), failure) ;	// UTC暦日。
	const unsigned hour	  = decimal( text.substr( 11U, 2U), failure) ;	// 0～23時。
	const unsigned minute = decimal( text.substr( 14U, 2U), failure) ;	// 0～59分。
	const unsigned second = decimal( text.substr( 17U, 2U), failure) ;	// Leap secondを扱わない秒。
	const std::chrono::year_month_day date{std::chrono::year{static_cast<int>( year)},
										   std::chrono::month{month},
										   std::chrono::day{day}} ;	// 補正しない暦日。
	require( year >= 1970U && date.ok() && hour < 24U && minute < 60U && second < 60U, failure) ;
	return std::chrono::sys_days{date} + std::chrono::hours{hour} + std::chrono::minutes{minute} +
		   std::chrono::seconds{second} ;
}

} // namespace drivercrate::signed_index_json
