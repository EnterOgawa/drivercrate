//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_json.cpp
 * @brief 有限JSON字句と新v4 envelopeの原byte整合を検査します。
 * @version 01.00.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限byte・厳密字句・envelope部品を追加。
 * </pre>
 *
 * @note 旧WinRT codecは変更せず、v4保存や予約精算を有効化しません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "local_collector_projected_json.h"
#include "platform/official_file_verifier.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <new>
#include <system_error>
#include <utility>
#include <windows.h>

namespace drivercrate::collector_projected_json {
namespace {
// 旧envelopeと同じschemaですが、こちらは順序・字句も固定します。
constexpr std::string_view ENVELOPE_PREFIX =
	"{\"schema\":\"collector-campaign-envelope-v1\",\"body\":" ;
// 新形式だけに使う外側部品です。残りのfield集合は型付きcodecが検査します。
constexpr std::string_view RESPONSE_PREFIX = "{\"schema\":\"collector-campaign-response-v4\"," ;

/** @brief 数値だけの不成立で処理を中止します。
 * @param[in] valid 成立条件。
 * @param[in] status 不成立時の固定分類。
 */
void					   require( bool valid, Status status = Status::INVALID)
{
	// 呼出し側の出力は最上位の境界で破棄する。
	if( !valid) {
		throw Failure{status} ;
	}
}

/** @brief 追記・解析の予算自体を固定範囲へ限定します。
 * @param[in] limit 層別上限。
 */
void checkLimit( std::size_t limit)
{
	require( limit > 0U && limit <= ENVELOPE_LIMIT) ;
}

/** @brief 過長表現・surrogate・範囲外を含むUTF-8を確保なしで拒否します。
 * @param[in] value 原byte。空文字列は許可します。
 */
void unicode( std::string_view value)
{
	// 各scalarの先頭と継続byteを一度ずつ確認する。
	for( std::size_t position = 0U; position < value.size();) {
		const auto first = static_cast<unsigned char>( value[position++]) ;	// 原先頭byte。
		require( first >= 0x20U) ;
		// ASCIIはそのまま扱い、escapeは別の字句走査で検査する。
		if( first < 0x80U) {
			continue ;
		}

		std::size_t	  tails{} ;		// 必須継続byte数。
		std::uint32_t scalar{} ;	// 復元中のUnicode値。
		std::uint32_t minimum{} ;	// 過長表現を拒否する下限。
		// 正規の二byte先頭だけを認める。
		if( first >= 0xc2U && first <= 0xdfU) {
			tails	= 1U ;
			scalar	= first & 0x1fU ;
			minimum = 0x80U ;
		}
		// 三byteの最小scalarはU+0800。
		else if( first >= 0xe0U && first <= 0xefU) {
			tails	= 2U ;
			scalar	= first & 0x0fU ;
			minimum = 0x800U ;
		}
		// Unicode上限を超える先頭を拒否する。
		else if( first >= 0xf0U && first <= 0xf4U) {
			tails	= 3U ;
			scalar	= first & 0x07U ;
			minimum = 0x10000U ;
		} else {
			throw Failure{Status::INVALID} ;
		}

		require( tails <= value.size() - position) ;
		// 有限個の継続byteからscalarを組み立てる。
		for( std::size_t index = 0U; index < tails; ++index) {
			const auto next = static_cast<unsigned char>( value[position++]) ;	// 原継続byte。
			require( (next & 0xc0U) == 0x80U) ;
			scalar = (scalar << 6U) | (next & 0x3fU) ;
		}

		require( scalar >= minimum && scalar <= 0x10ffffU &&
				!(scalar >= 0xd800U && scalar <= 0xdfffU)) ;
	}
}

/** @brief 元byteの一delimiterを消費します。
 * @param[in] bytes 事前検査済みの入力。
 * @param[in,out] position 消費位置。
 * @param[in] expected 固定delimiter。
 */
void delimiter( std::string_view bytes, std::size_t &position, char expected)
{
	require( position < bytes.size() && bytes[position] == expected) ;
	++position ;
}

/** @brief Escapeを含む一文字列を確保せず走査します。
 * @param[in] bytes 厳密UTF-8を検査済みの入力。
 * @param[in,out] position 文字列の開始位置から直後へ移します。
 */
void scanText( std::string_view bytes, std::size_t &position)
{
	delimiter( bytes, position, '"') ;
	// Unicodeは検査済みなのでquoteと二種類のescapeだけを走査する。
	while( position < bytes.size()) {
		const char current = bytes[position++] ;	// 元byte。
		// 終端quoteはescapeされていない場合だけ有効。
		if( current == '"') {
			return ;
		}

		// slash・非ASCII・制御文字のescapeによる別表現を拒否する。
		if( current == '\\') {
			require( position < bytes.size() && (bytes[position] == '\\' || bytes[position] == '"')) ;
			++position ;
		}
	}

	throw Failure{Status::INVALID} ;
}

/** @brief 正確な整数だけをoverflow前に検査します。
 * @param[in] bytes 元入力。
 * @param[in,out] position 数値の開始位置から直後へ移します。
 * @return MAX_INTEGER以下の値。
 */
std::uint64_t scanNumber( std::string_view bytes, std::size_t &position)
{
	const std::size_t start = position ;	// 先頭zeroの検査位置。
	std::uint64_t	  value{} ;				// 追加前に上限を確認する整数。
	// 非負の十進桁だけを消費し、符号・小数・指数は残して拒否する。
	while( position < bytes.size() && bytes[position] >= '0' && bytes[position] <= '9') {
		const auto digit = static_cast<std::uint64_t>( bytes[position++] - '0') ;	// 次の桁。
		require( value <= (MAX_INTEGER - digit) / 10U) ;
		value = value * 10U + digit ;
	}

	require( position != start && (bytes[start] != '0' || position == start + 1U)) ;
	return value ;
}

/** @brief 固定tokenを完全一致で消費します。
 * @param[in] bytes 元入力。
 * @param[in,out] position 現在位置。
 * @param[in] token 固定ASCII。
 */
void token( std::string_view bytes, std::size_t &position, std::string_view token)
{
	require( position <= bytes.size() && bytes.substr( position).starts_with( token)) ;
	position += token.size() ;
}

/** @brief 一つのcanonical値を最大16段で確保なし走査します。
 * @param[in] bytes 事前Unicode検査済みの有限byte。
 * @param[in,out] position 一値の始点から終点へ移します。
 * @param[in] depth 外側のobject／arrayの数。
 */
void scanValue( std::string_view bytes, std::size_t &position, std::size_t depth)
{
	require( position < bytes.size()) ;
	const char first = bytes[position] ;	// 値の型を決めるASCII。
	// Objectとarrayだけを深さに加算し、文字列中の括弧は数えない。
	if( first == '{' || first == '[') {
		require( depth < 16U) ;
		++position ;
		const char end = first == '{' ? '}' : ']' ;	// 対応する終端。
		// 空containerも一つの深さとして扱う。
		if( position < bytes.size() && bytes[position] == end) {
			++position ;
			return ;
		}

		// 各要素は必ず入力を消費し、残りbyteが尽きれば拒否する。
		for( ;;) {
			// Objectではkeyが必ず文字列で、colonが直後に必要。
			if( first == '{') {
				scanText( bytes, position) ;
				delimiter( bytes, position, ':') ;
			}

			scanValue( bytes, position, depth + 1U) ;
			require( position < bytes.size()) ;
			// 正しい閉じ括弧以外では次要素用commaを必須とする。
			if( bytes[position] == end) {
				++position ;
				return ;
			}

			delimiter( bytes, position, ',') ;
		}
	}

	// 文字列内のescapeを含めcanonical文法を検査する。
	if( first == '"') {
		scanText( bytes, position) ;
	}
	// True以外の同prefixを終端検査で拒否する。
	else if( first == 't') {
		token( bytes, position, "true") ;
	}
	// Falseの小文字表現だけを認める。
	else if( first == 'f') {
		token( bytes, position, "false") ;
	}
	// 欠測値は明示nullだけを認める。
	else if( first == 'n') {
		token( bytes, position, "null") ;
	} else {
		static_cast<void>( scanNumber( bytes, position)) ;
	}
}

/** @brief 既存CNGへ元byteだけを渡し、失敗診断を保持します。
 * @param[in] bytes hash対象の原byte。
 * @param[out] digest 実CNGによる小文字hash。
 * @param[in] probe 任意の失敗だけの診断。
 * @return 原HRESULT。0は実CNG成功時のみ。
 */
NativeError hashBytes( std::string_view bytes, std::wstring &digest, const HashFailureProbe &probe)
{
	const NativeError injected = probe ? probe() : 0 ;	// 成功digestを外部から受け取らない。
	require( injected <= 0) ;
	// 負のHRESULTだけを失敗として返し、0なら必ず本番CNGへ進む。
	if( injected != 0) {
		return injected ;
	}

	return computeBytesSha256( bytes, digest) ;
}

/** @brief Hashの確保失敗をCNG障害から分離します。
 * @param[in] error 元HRESULT。
 * @return 成功、OOM、hash失敗の固定結果。
 */
Result hashResult( NativeError error)
{
	return {error == 0				 ? Status::OK
			: error == E_OUTOFMEMORY ? Status::OUT_OF_MEMORY
									 : Status::HASH_FAILURE,
			error} ;
}

/** @brief 外側に入れる応答の有限字句と新schemaだけを検査します。
 * @param[in] response 元byte。意味検査済みと呼ばない値です。
 */
void checkResponseBytes( std::string_view response)
{
	const Reader checked( response, RESPONSE_LIMIT) ;	// 全byte・Unicode・深さを先に検査する。
	require( response.starts_with( RESPONSE_PREFIX)) ;
	static_cast<void>( checked) ;
}
} // namespace

/** @see local_collector_projected_json.h */
Writer::Writer( std::size_t limit) : limit_( limit)
{
	checkLimit( limit) ;
}
/** @see local_collector_projected_json.h */
void Writer::append( std::string_view bytes)
{
	require( bytes.size() <= limit_ - bytes_.size(), Status::SIZE_LIMIT) ;
	bytes_.append( bytes) ;
}
/** @see local_collector_projected_json.h */
void Writer::text( std::string_view value)
{
	require( value.size() <= limit_ - bytes_.size(), Status::SIZE_LIMIT) ;
	unicode( value) ;
	append( "\"") ;
	// 元のUnicode byteを保ち、quoteとbackslashだけをescapeする。
	for( const char current : value) {
		// Escapeによる増加も一byteずつ追加前の予算検査を通す。
		if( current == '"' || current == '\\') {
			append( "\\") ;
		}

		append( std::string_view( &current, 1U)) ;
	}

	append( "\"") ;
}
/** @see local_collector_projected_json.h */
void Writer::wideText( std::wstring_view value)
{
	require( value.size() <= limit_ - bytes_.size(), Status::SIZE_LIMIT) ;
	append( "\"") ;
	// 有効なUTF-16 pairを一scalarとして処理し、正規化しない。
	for( std::size_t position = 0U; position < value.size(); ++position) {
		std::uint32_t scalar = static_cast<std::uint32_t>( value[position]) ;	// 元code unit。
		// High surrogateは直後のlow surrogateがある場合だけ認める。
		if( scalar >= 0xd800U && scalar <= 0xdbffU) {
			require( position + 1U < value.size()) ;
			const auto low = static_cast<std::uint32_t>( value[++position]) ;	// Pairの後半。
			require( low >= 0xdc00U && low <= 0xdfffU) ;
			scalar = 0x10000U + ((scalar - 0xd800U) << 10U) + low - 0xdc00U ;
		}

		require( scalar >= 0x20U && scalar <= 0x10ffffU &&
				!(scalar >= 0xd800U && scalar <= 0xdfffU)) ;
		std::array<char, 4U> encoded{} ;	// 一scalarだけの固定buffer。
		std::size_t			 count{} ;		// 実際に使うUTF-8 byte数。
		// ASCIIの二つのescape以外は元値を出力する。
		if( scalar < 0x80U) {
			// 引用符とbackslashだけ追加escapeする。
			if( scalar == '"' || scalar == '\\') {
				append( "\\") ;
			}

			encoded[0] = static_cast<char>( scalar) ;
			count	   = 1U ;
		}
		// 二byte scalarの最短表現を作る。
		else if( scalar < 0x800U) {
			encoded[0] = static_cast<char>( 0xc0U | (scalar >> 6U)) ;
			encoded[1] = static_cast<char>( 0x80U | (scalar & 0x3fU)) ;
			count	   = 2U ;
		}
		// BMPのsurrogate以外を三byteへ変換する。
		else if( scalar < 0x10000U) {
			encoded[0] = static_cast<char>( 0xe0U | (scalar >> 12U)) ;
			encoded[1] = static_cast<char>( 0x80U | ((scalar >> 6U) & 0x3fU)) ;
			encoded[2] = static_cast<char>( 0x80U | (scalar & 0x3fU)) ;
			count	   = 3U ;
		} else {
			encoded[0] = static_cast<char>( 0xf0U | (scalar >> 18U)) ;
			encoded[1] = static_cast<char>( 0x80U | ((scalar >> 12U) & 0x3fU)) ;
			encoded[2] = static_cast<char>( 0x80U | ((scalar >> 6U) & 0x3fU)) ;
			encoded[3] = static_cast<char>( 0x80U | (scalar & 0x3fU)) ;
			count	   = 4U ;
		}

		append( std::string_view( encoded.data(), count)) ;
	}

	append( "\"") ;
}
/** @see local_collector_projected_json.h */
void Writer::number( std::uint64_t value)
{
	require( value <= MAX_INTEGER) ;
	std::array<char, 20U> buffer{} ;	// 最大uint64より短い有限十進buffer。
	const auto			  encoded =
		// locale非依存。
		std::to_chars( buffer.data(), buffer.data() + buffer.size(), value) ;
	require( encoded.ec == std::errc{}) ;
	append( std::string_view( buffer.data(), static_cast<std::size_t>( encoded.ptr - buffer.data()))) ;
}
/** @see local_collector_projected_json.h */
std::string_view Writer::view() const noexcept
{
	return bytes_ ;
}
/** @see local_collector_projected_json.h */
std::string Writer::take() noexcept
{
	return std::exchange( bytes_, {}) ;
}

/** @see local_collector_projected_json.h */
Reader::Reader( std::string_view bytes, std::size_t limit) : bytes_( bytes)
{
	checkLimit( limit) ;
	require( bytes.size() <= limit, Status::SIZE_LIMIT) ;
	unicode( bytes) ;
	std::size_t scanned{} ;	// 解析前の全字句走査位置。
	scanValue( bytes, scanned, 0U) ;
	require( scanned == bytes.size()) ;
}
/** @see local_collector_projected_json.h */
void Reader::literal( std::string_view expected)
{
	token( bytes_, position_, expected) ;
}
/** @see local_collector_projected_json.h */
std::string Reader::text( std::size_t limit)
{
	Writer decoded( limit) ;	// 解除後の別予算を持つsink。
	delimiter( bytes_, position_, '"') ;
	// 事前走査で終端とescapeは確定済みだが、呼出し位置の型も再検査する。
	while( position_ < bytes_.size()) {
		char current = bytes_[position_++] ;	// 元byteまたは解除するescape。
		// 未escapeのquoteで文字列が完結する。
		if( current == '"') {
			return decoded.take() ;
		}

		// 二種類のescapeだけを一byteへ戻す。
		if( current == '\\') {
			require( position_ < bytes_.size()) ;
			current = bytes_[position_++] ;
			require( current == '\\' || current == '"') ;
		}

		decoded.append( std::string_view( &current, 1U)) ;
	}

	throw Failure{Status::INVALID} ;
}
/** @see local_collector_projected_json.h */
std::uint64_t Reader::number()
{
	return scanNumber( bytes_, position_) ;
}
/** @see local_collector_projected_json.h */
std::string_view Reader::value()
{
	const std::size_t start = position_ ;	// 原byteの借用開始。
	scanValue( bytes_, position_, 0U) ;
	return bytes_.substr( start, position_ - start) ;
}
/** @see local_collector_projected_json.h */
void Reader::finish() const
{
	require( position_ == bytes_.size()) ;
}

/** @see local_collector_projected_json.h */
bool isHash( std::wstring_view value) noexcept
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(), []( wchar_t current) {
			   return (current >= L'0' && current <= L'9') || (current >= L'a' && current <= L'f') ;
		   }) ;
}

/** @see local_collector_projected_json.h */
Result encodeEnvelope( std::string_view response, std::string &envelope, EnvelopeBytes &body,
					  const HashFailureProbe &probe) noexcept
{
	envelope.clear() ;
	body = {} ;
	try {
		checkResponseBytes( response) ;
		EnvelopeBytes	  prepared ;	// 全検査後にだけ公開する原byteとdigest。
		const NativeError error =
			// 実本文hash。
			hashBytes( response, prepared.responseSha256, probe) ;
		// OOMも含め原値を返し、再試行や最小失敗応答をここで合成しない。
		if( error != 0) {
			return hashResult( error) ;
		}

		Writer encoded( ENVELOPE_LIMIT) ;	// 外側だけの有限sink。
		encoded.append( ENVELOPE_PREFIX) ;
		encoded.text( response) ;
		encoded.append( ",\"sha256\":") ;
		encoded.wideText( prepared.responseSha256) ;
		encoded.append( "}") ;
		prepared.response.assign( response) ;
		body	 = std::move( prepared) ;
		envelope = encoded.take() ;
		return {Status::OK, 0} ;
	} catch( const Failure &failure) {
		return {failure.status, 0} ;
	} catch( const std::bad_alloc &) {
		return {Status::OUT_OF_MEMORY, E_OUTOFMEMORY} ;
	} catch( ...) {
		return {Status::INVALID, 0} ;
	}
}

/** @see local_collector_projected_json.h */
Result decodeEnvelope( std::string_view envelope, EnvelopeBytes &body,
					  const HashFailureProbe &probe) noexcept
{
	body = {} ;
	try {
		Reader reader( envelope, ENVELOPE_LIMIT) ;	// UTF-8・深さ・全字句をparseより先に検査。
		reader.literal( ENVELOPE_PREFIX) ;
		EnvelopeBytes prepared ;	// 元byteを正規化せず保持する一時結果。
		prepared.response = reader.text( RESPONSE_LIMIT) ;
		reader.literal( ",\"sha256\":") ;
		const auto digest = reader.text( 64U) ;	// ASCII lowercase hex以外を後段で拒否。
		prepared.responseSha256.assign( digest.begin(), digest.end()) ;
		require( isHash( prepared.responseSha256)) ;
		reader.literal( "}") ;
		reader.finish() ;
		checkResponseBytes( prepared.response) ;
		std::wstring	  actual ;													// 保存値とは独立に実CNGで再計算する。
		const NativeError error = hashBytes( prepared.response, actual, probe) ;	// 元HRESULT。
		// Hash API失敗は保存STATE_ERRORへ渡す失敗であり、成功やcache missにしない。
		if( error != 0) {
			return hashResult( error) ;
		}

		require( actual == prepared.responseSha256) ;
		body = std::move( prepared) ;
		return {Status::OK, 0} ;
	} catch( const Failure &failure) {
		return {failure.status, 0} ;
	} catch( const std::bad_alloc &) {
		return {Status::OUT_OF_MEMORY, E_OUTOFMEMORY} ;
	} catch( ...) {
		return {Status::INVALID, 0} ;
	}
}
} // namespace drivercrate::collector_projected_json
