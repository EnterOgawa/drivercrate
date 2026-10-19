//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_cache.cpp
 * @brief CACHEの有限codecと決定的な履歴保持を実装します。
 * @version 01.00.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  固定CACHEと履歴保持更新を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 成功CACHEの稼働保存・304送信・登録履歴の受入は行いません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_projected_cache.h"
#include "platform/official_file_verifier.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <set>

namespace drivercrate {
namespace {
using namespace collector_projected_json ;
using namespace std::literals ;
/**
 * @brief 投影jobへ結合するcache値を所有し、codecの読み書きへ渡す。
 */
using Cache = CollectorProjectedCache ;
/**
 * @brief 投影cacheの受理・拒否理由を保持する。
 */
using Reason = CollectorCacheReason ;
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using Object = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値の実種別を表し、schemaで要求する型との一致を検査する。
 */
using Type						  = winrt::Windows::Data::Json::JsonValueType ;
constexpr std::size_t CACHE_LIMIT = 24U * 1024U ;	// 外側64 KiBとは独立した本文予算。
constexpr std::array  REASONS{
	 std::pair{Reason::ACCEPTED, L"ACCEPTED"sv},
	 std::pair{Reason::NO_VALIDATOR, L"NO_VALIDATOR"sv},
	 std::pair{Reason::PARTIAL, L"PARTIAL"sv},
	 std::pair{Reason::NO_CURRENT_MATCH, L"NO_CURRENT_MATCH"sv},
	 std::pair{Reason::DECREASED, L"DECREASED"sv},
	 std::pair{Reason::PROJECTION_LIMIT, L"PROJECTION_LIMIT"sv},
	 std::pair{Reason::WORKER_FAILURE, L"WORKER_FAILURE"sv},
	 std::pair{Reason::CACHE_BASIS_INVALID, L"CACHE_BASIS_INVALID"sv},
	 std::pair{Reason::METADATA_HASH, L"METADATA_HASH"sv},
	 std::pair{Reason::INTERRUPTED, L"INTERRUPTED"sv}} ;	// 未実装304の理由は含めません。

/** @brief 関係違反を修復せず停止します。
 * @param[in] ok 継続可能条件。
 * @throws Failure 不成立の場合。
 */
void require( bool ok)
{
	// 不完全な値を保存候補へ渡しません。
	if( !ok) {
		throw Failure{Status::INVALID} ;
	}
}
/** @brief Catch境界でOOMと字句・関係違反を分けます。
 * @return 元例外の分類とOOM数値。
 * @pre Catch節内からだけ呼びます。
 */
Result failure() noexcept
{
	try {
		throw ;
	} catch( const Failure &error) {
		return {error.status, 0} ;
	} catch( const std::bad_alloc &) {
		return {Status::OUT_OF_MEMORY, E_OUTOFMEMORY} ;
	} catch( const winrt::hresult_error &error) {
		// WinRTの確保失敗も同じ数値を保持します。
		if( error.code() == E_OUTOFMEMORY) {
			return {Status::OUT_OF_MEMORY, E_OUTOFMEMORY} ;
		}

		return {Status::INVALID, 0} ;
	} catch( ...) {
		return {Status::INVALID, 0} ;
	}
}
/** @brief 定義外enumを文字列へ昇格させません。
 * @param[in] reason 固定理由。
 * @return 静的固定名。
 * @throws Failure 定義外値の場合。
 */
std::wstring_view reasonName( Reason reason)
{
	// 固定十値だけを照合します。
	for( const auto &[value, name] : REASONS) {
		// 一つだけ対応する固定名を返します。
		if( value == reason) {
			return name ;
		}
	}

	throw Failure{Status::INVALID} ;
}
/** @brief 固定名以外を保存理由へ変換しません。
 * @param[in] name 元固定名。
 * @return 完全一致した理由。
 * @throws Failure 未定義名の場合。
 */
Reason parseReason( std::wstring_view name)
{
	// 定義された十理由だけを消費します。
	for( const auto &[value, text] : REASONS) {
		// 完全一致した理由を採用します。
		if( name == text) {
			return value ;
		}
	}

	throw Failure{Status::INVALID} ;
}
/** @brief 共通するG／O／応答参照の文法を検査します。
 * @tparam T 三参照fieldを持つ型。
 * @param[in] value 検査対象。
 * @throws Failure 文法違反の場合。
 */
template <class T> void validateReference( const T &value)
{
	require( isHash( value.generation) && isHash( value.operation) && isHash( value.response)) ;
}
/** @brief 二つの公開参照が同じ元応答を指すか比較します。
 * @tparam T 左辺参照型。
 * @tparam U 右辺参照型。
 * @param[in] a 左辺。
 * @param[in] b 右辺。
 * @return 三参照fieldが全て等しい場合true。
 */
template <class T, class U> bool sameReference( const T &a, const U &b)
{
	return a.generation == b.generation && a.operation == b.operation && a.response == b.response ;
}
/** @brief UTCをJSONで正確に表せる実行範囲へ限定します。
 * @param[in] value UTC millisecond。
 * @throws Failure 範囲外の場合。
 */
void validateUtc( std::uint64_t value)
{
	require( value >= 1000U && value <= 4102444799999ULL) ;
}
/** @brief 参照間の構造を検査します。参照先の実在は検査しません。
 * @param[in] cache 最大16成功の公開値。
 * @throws Failure 構造・関係・有限上限に違反した場合。
 */
void validate( const Cache &cache)
{
	require( isHash( cache.request) && isHash( cache.binding)) ;
	validateReference( cache.attempt) ;
	(void)reasonName( cache.reason) ;
	// 型入力でも確保・反復の前に有限件数を確認します。
	if( cache.slices.size() > 16U) {
		throw Failure{Status::SIZE_LIMIT} ;
	}

	std::set<std::wstring> seen ;	// 同一sliceへの二重参照を拒否します。
	// 全成功参照を固定上限内で検査します。
	for( const auto &slice : cache.slices) {
		validateReference( slice) ;
		require( isHash( slice.projection) && isHash( slice.slice) && seen.insert( slice.slice).second) ;
	}

	require( cache.original200.has_value() == cache.validated.has_value()) ;
	// 元完全成功がある場合は検証参照の全fieldを結合します。
	if( cache.original200) {
		const auto &old		= *cache.original200 ;	// 過去headerを延長しません。
		const auto &checked = *cache.validated ;	// 現工程は200由来だけです。
		validateReference( old) ;
		validateReference( checked) ;
		validateUtc( old.headerUtc) ;
		require( isHash( old.projection) && isHash( old.body) && sameReference( old, checked) &&
				old.projection == checked.projection && old.headerUtc == checked.headerUtc) ;
	}

	// 完全成功の二形。
	const bool full = cache.reason == Reason::ACCEPTED || cache.reason == Reason::NO_VALIDATOR ;
	require( cache.reusable == (cache.reason == Reason::ACCEPTED)) ;
	require( cache.etag.has_value() == cache.reusable) ;
	// 再利用可能形に空tagや任意文字列を許しません。
	if( cache.etag) {
		require( isCollectorEntityTag( *cache.etag)) ;
	}

	// 完全成功を名乗る形は最新試行と成功参照を同時に更新していなければ拒否します。
	if( full) {
		require( cache.original200 && sameReference( cache.attempt, *cache.original200)) ;
		require( std::any_of( cache.slices.begin(), cache.slices.end(), [&]( const auto &slice) {
			return sameReference( slice, cache.attempt) &&
				   slice.projection == cache.original200->projection ;
		})) ; // 検査中だけ借用し、現在の成功sliceが少なくとも一つ必要です。
	}
}
/** @brief G／O／応答の固定順prefixを出力します。末尾はcallerが閉じます。
 * @tparam T 三参照fieldを持つ型。
 * @param[in,out] writer 有限sink。
 * @param[in] value 検査済み参照。
 * @throws Failure 有限sinkが拒否した場合。
 */
template <class T> void writeReference( Writer &writer, const T &value)
{
	writer.append( "{\"generation\":") ;
	writer.wideText( value.generation) ;
	writer.append( ",\"operation\":") ;
	writer.wideText( value.operation) ;
	writer.append( ",\"response\":") ;
	writer.wideText( value.response) ;
}
/** @brief 成功参照に共通するprojectionまでを出力します。
 * @tparam T 四参照fieldを持つ型。
 * @param[in,out] writer 有限sink。
 * @param[in] value 検査済み参照。
 * @throws Failure 有限sinkが拒否した場合。
 */
template <class T> void writeProjection( Writer &writer, const T &value)
{
	writeReference( writer, value) ;
	writer.append( ",\"projection\":") ;
	writer.wideText( value.projection) ;
}
/** @brief 検査済み値を既存中断形と同じ順序・byteで符号化します。
 * @param[in] cache 符号化前に検査する公開値。
 * @return 最大24 KiBの本文。
 * @throws Failure 構造・上限が不成立の場合。
 */
std::string serialize( const Cache &cache)
{
	validate( cache) ;
	Writer writer( CACHE_LIMIT) ;	// 追記前に実byte予算を検査します。
	writer.append( "{\"schema\":\"collector-campaign-cache-v1\",\"request\":") ;
	writer.wideText( cache.request) ;
	writer.append( ",\"binding\":") ;
	writer.wideText( cache.binding) ;
	writer.append( ",\"attempt\":") ;
	writeReference( writer, cache.attempt) ;
	writer.append( "}") ;
	writer.append( ",\"original200\":") ;
	// 元200参照をnullと明確に区別します。
	if( cache.original200) {
		writeProjection( writer, *cache.original200) ;
		writer.append( ",\"body\":") ;
		writer.wideText( cache.original200->body) ;
		writer.append( ",\"headerUtc\":") ;
		writer.number( cache.original200->headerUtc) ;
		writer.append( "}") ;
	} else {
		writer.append( "null") ;
	}

	writer.append( ",\"slices\":[") ;
	// 入力順で最大16成功参照を保持します。
	for( std::size_t index = 0; index < cache.slices.size(); ++index) {
		// 二件目からだけdelimiterを置きます。
		if( index != 0U) {
			writer.append( ",") ;
		}

		writeProjection( writer, cache.slices[index]) ;
		writer.append( ",\"slice\":") ;
		writer.wideText( cache.slices[index].slice) ;
		writer.append( "}") ;
	}

	writer.append( "],\"validated\":") ;
	// 欠測を現在時刻で補完しません。
	if( cache.validated) {
		writeProjection( writer, *cache.validated) ;
		writer.append( ",\"headerUtc\":") ;
		writer.number( cache.validated->headerUtc) ;
		writer.append( "}") ;
	} else {
		writer.append( "null") ;
	}

	writer.append( cache.reusable ? ",\"reusable\":true,\"reason\":"
								 : ",\"reusable\":false,\"reason\":") ;
	writer.wideText( reasonName( cache.reason)) ;
	writer.append( ",\"etag\":") ;
	// 非再利用形はnullを出力します。
	if( cache.etag) {
		writer.wideText( *cache.etag) ;
	} else {
		writer.append( "null") ;
	}

	writer.append( "}") ;
	return writer.take() ;
}
/** @brief 有限JSONから文字列型だけを取得します。
 * @param[in] object 有限JSON。
 * @param[in] key 必須field名。
 * @return 元文字列。
 * @throws winrt::hresult_error 欠損・型違反の場合。
 */
std::wstring text( const Object &object, std::wstring_view key)
{
	return std::wstring( object.GetNamedString( key)) ;
}
/** @brief 固定参照の三fieldを読みます。余剰fieldはcanonical比較で拒否します。
 * @tparam T 三参照fieldを持つ型。
 * @param[in] object 有限JSON。
 * @param[out] value 読み取り途中の値。例外時はcallerが破棄します。
 * @throws winrt::hresult_error 欠損・型違反の場合。
 */
template <class T> void readReference( const Object &object, T &value)
{
	value.generation = text( object, L"generation") ;
	value.operation	 = text( object, L"operation") ;
	value.response	 = text( object, L"response") ;
}
/** @brief projectionを含む固定参照を読みます。
 * @tparam T 四参照fieldを持つ型。
 * @param[in] object 有限JSON。
 * @param[out] value 読み取り途中の値。例外時はcallerが破棄します。
 * @throws winrt::hresult_error 欠損・型違反の場合。
 */
template <class T> void readProjection( const Object &object, T &value)
{
	readReference( object, value) ;
	value.projection = text( object, L"projection") ;
}
/** @brief 数値型と丸めなしのUTC範囲を変換前に確認します。
 * @param[in] object headerUtcを持つ有限JSON。
 * @return 検査したUTC整数。
 * @throws Failure 範囲・精度違反の場合。
 */
std::uint64_t readUtc( const Object &object)
{
	const auto number = object.GetNamedNumber( L"headerUtc") ;	// 有限JSON numberのみ。
	require( std::isfinite( number) && std::floor( number) == number && number >= 1000.0 &&
			number <= 4102444799999.0) ;
	return static_cast<std::uint64_t>( number) ;
}
/** @brief 旧値を検査し、最新試行だけ更新して再利用を解除します。
 * @param[in] request 同じ要求key。
 * @param[in] binding 今回binding。
 * @param[in] attempt 今回直接参照。
 * @param[in] before 過去値またはnull。
 * @return 過去成功を保持した非再利用値。
 * @throws Failure 不整合・同操作再適用の場合。
 */
Cache begin( std::wstring_view request, std::wstring_view binding,
			const CollectorCacheAttempt &attempt, const Cache *before)
{
	// 旧値をコピーする前に有限性と同要求・操作の非重複を確認します。
	if( before) {
		validate( *before) ;
		require( before->request == request && before->attempt.operation != attempt.operation) ;
	}

	Cache after	   = before ? *before : Cache{} ;	// 履歴参照はそのまま保持します。
	after.request  = request ;
	after.binding  = binding ;
	after.attempt  = attempt ;
	after.reusable = false ;
	after.etag.reset() ;
	after.reason = Reason::INTERRUPTED ;
	validate( after) ;
	return after ;
}
/** @brief 応答側理由を明示対応させ、未実装の再検証を拒否します。
 * @param[in] reason 元応答codecの理由。
 * @return 対応するCACHE理由。
 * @throws Failure 再検証・未定義値の場合。
 */
Reason fromResponse( CollectorProjectedCacheReason reason)
{
	using R = CollectorProjectedCacheReason ;
	// 数値ordinalを共有せず、意味ごとに固定対応します。
	switch( reason) {
		case R::ACCEPTED:
			// 全成功。
			return Reason::ACCEPTED ;
		case R::NO_VALIDATOR:
			// Tag欠測。
			return Reason::NO_VALIDATOR ;
		case R::PARTIAL:
			// 部分。
			return Reason::PARTIAL ;
		case R::NO_CURRENT_MATCH:
			// 一致なし。
			return Reason::NO_CURRENT_MATCH ;
		case R::DECREASED:
			// 減少。
			return Reason::DECREASED ;
		case R::PROJECTION_LIMIT:
			// 上限。
			return Reason::PROJECTION_LIMIT ;
		case R::WORKER_FAILURE:
			// Worker失敗。
			return Reason::WORKER_FAILURE ;
		case R::CACHE_BASIS_INVALID:
			// 根拠拒否。
			return Reason::CACHE_BASIS_INVALID ;
		case R::METADATA_HASH:
			// Hash故障。
			return Reason::METADATA_HASH ;
		default:
			// 304を本工程へ混入させません。
			throw Failure{Status::INVALID} ;
	}
}
} // namespace

/**
 * @copydoc drivercrate::encodeCollectorProjectedCache(const CollectorProjectedCache &, std::string &)
 */
Result encodeCollectorProjectedCache( const Cache &cache, std::string &body) noexcept
{
	body.clear() ;
	try {
		body = serialize( cache) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		body.clear() ;
		return failure() ;
	}
}
/**
 * @copydoc drivercrate::decodeCollectorProjectedCache(std::string_view, CollectorProjectedCache &)
 */
Result decodeCollectorProjectedCache( std::string_view body, Cache &cache) noexcept
{
	cache = {} ;
	try {
		Reader reader( body, CACHE_LIMIT) ;	// WinRT確保前にbyte／深さ／UTF-8／字句を制限します。
		(void)reader.value() ;
		reader.finish() ;
		const auto object = Object::Parse( winrt::to_hstring( body)) ;	// 最大24 KiBのみ。
		require( text( object, L"schema") == L"collector-campaign-cache-v1") ;
		Cache candidate ;	// 全検査後にだけ出力へ移します。
		candidate.request = text( object, L"request") ;
		candidate.binding = text( object, L"binding") ;
		readReference( object.GetNamedObject( L"attempt"), candidate.attempt) ;
		// 非nullは必ず六fieldの元200参照として読みます。
		if( object.GetNamedValue( L"original200").ValueType() != Type::Null) {
			const auto old = object.GetNamedObject( L"original200") ;	// 元成功のみ。
			candidate.original200.emplace() ;
			readProjection( old, *candidate.original200) ;
			candidate.original200->body		 = text( old, L"body") ;
			candidate.original200->headerUtc = readUtc( old) ;
		}

		const auto slices = object.GetNamedArray( L"slices") ;	// 順序を維持します。
		// 配列の確保・反復を先に制限します。
		if( slices.Size() > 16U) {
			throw Failure{Status::SIZE_LIMIT} ;
		}

		// 最大16件の元成功だけを読みます。
		for( const auto &entry : slices) {
			CollectorCacheSlice slice ;	// 一参照の局所値。
			readProjection( entry.GetObject(), slice) ;
			slice.slice = text( entry.GetObject(), L"slice") ;
			candidate.slices.push_back( std::move( slice)) ;
		}

		// 元検証時刻をnullと区別します。
		if( object.GetNamedValue( L"validated").ValueType() != Type::Null) {
			const auto checked = object.GetNamedObject( L"validated") ;	// 固定五field。
			candidate.validated.emplace() ;
			readProjection( checked, *candidate.validated) ;
			candidate.validated->headerUtc = readUtc( checked) ;
		}

		candidate.reusable = object.GetNamedBoolean( L"reusable") ;
		candidate.reason   = parseReason( text( object, L"reason")) ;
		// 非nullを文字列型だけに限定します。
		if( object.GetNamedValue( L"etag").ValueType() != Type::Null) {
			candidate.etag = text( object, L"etag") ;
		}

		require( serialize( candidate) == body) ;
		cache = std::move( candidate) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return failure() ;
	}
}
/**
 * @copydoc drivercrate::deriveCollectorProjectedCache(const CollectorProjectedJobInput &, std::string_view, const CollectorProjectedCache *, CollectorProjectedCache &, const CollectorProjectedHashProbe &)
 */
Result deriveCollectorProjectedCache( const CollectorProjectedJobInput &job,
									 std::string_view envelope, const Cache *before, Cache &after,
									 const CollectorProjectedHashProbe &probe) noexcept
{
	after = {} ;
	try {
		CollectorProjectedResponseBytes decoded ;	// 元v4 hashとmetadataを独立再計算します。
		// 元二段hashを独立再計算。
		const auto read = decodeCollectorProjectedResponse( job, envelope, decoded, probe) ;
		// 元数値を修復・縮退しません。
		if( read.result.status != Status::OK) {
			return read.result ;
		}

		const auto &response = decoded.value ;	// 以後読み取り専用です。
		require( response.state != CollectorMetadataOutcome::REVALIDATED) ;
		std::wstring operation ;	// 保存監督と同じ算法です。
		// 保存監督と同じ操作keyの実CNG結果。
		const auto	 error =
			computeBytesSha256( "response-v2\n" + winrt::to_string( response.generation) + "\n" +
								   winrt::to_string( response.job) + "\n",
							   operation) ;
		// 実CNGの元数値をそのまま返します。
		if( error != 0) {
			return {error == E_OUTOFMEMORY ? Status::OUT_OF_MEMORY : Status::HASH_FAILURE, error} ;
		}

		Cache candidate	 = begin( response.request, response.cache,
								 {response.generation, operation, decoded.responseSha256},
								 before) ;	// 旧成功をコピーします。
		candidate.reason = fromResponse( response.cacheDecision.reason) ;
		// FETCHEDのACCEPTEDだけを更新し、HELD／失敗の参照を成功へ混ぜません。
		if( response.state == CollectorMetadataOutcome::FETCHED) {
			// 元metadataの有限slice順を保持します。
			for( const auto &slice : response.metadata.slices) {
				// 部分結果の保留sliceは過去の成功を保持します。
				if( slice.disposition != CollectorMetadataDisposition::ACCEPTED) {
					continue ;
				}

				CollectorCacheSlice next{response.generation, operation, decoded.responseSha256,
										 response.projection,
										 slice.scope.key} ;	// 新成功だけの直接参照。
				const auto position = std::find_if( candidate.slices.begin(), candidate.slices.end(),
												   [&]( const auto &old) {
													   return old.slice == next.slice ;
												   }) ; // 借用して同keyだけ比較します。
				// 同じslotの順序は動かしません。
				if( position != candidate.slices.end()) {
					*position = std::move( next) ;
				} else {
					// 17件目を黙って捨てず、更新全体を拒否します。
					if( candidate.slices.size() >= 16U) {
						throw Failure{Status::SIZE_LIMIT} ;
					}

					candidate.slices.push_back( std::move( next)) ;
				}
			}
		}

		// 完全200だけ元200と検証時刻を同時に更新します。
		if( response.cacheDecision.action == CollectorProjectedCacheAction::REPLACE) {
			require( response.status == 200U && response.io.headerUtcMillis.has_value()) ;
			candidate.original200 = CollectorProjectedOriginal200{
				response.generation, operation,		decoded.responseSha256,
				response.projection, response.body, *response.io.headerUtcMillis} ;
			candidate.validated =
				CollectorCacheValidation{response.generation, operation, decoded.responseSha256,
										 response.projection, *response.io.headerUtcMillis} ;
			candidate.reusable = response.responseValidator.has_value() ;
			candidate.etag	   = response.responseValidator ;
		}

		validate( candidate) ;
		after = std::move( candidate) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return failure() ;
	}
}
/**
 * @copydoc drivercrate::makeInterruptedCollectorCache(std::wstring_view, std::wstring_view, const CollectorCacheAttempt &, const CollectorProjectedCache *, CollectorProjectedCache &)
 */
Result makeInterruptedCollectorCache( std::wstring_view request, std::wstring_view binding,
									 const CollectorCacheAttempt &attempt, const Cache *before,
									 Cache &after) noexcept
{
	after = {} ;
	try {
		after = begin( request, binding, attempt, before) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return failure() ;
	}
}
} // namespace drivercrate
