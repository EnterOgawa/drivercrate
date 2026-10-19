//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_response.cpp
 * @brief 応答v4の有限codec・元I/O結合・一回縮退を実装します。
 * @version 01.01.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  非保存応答・元I/O・二段hashの実装を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  元成功参照の全再検証と減少最終化を追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 元結果の伝播・例外変換とcache操作引数の契約を補足。
 * </pre>
 *
 * @note 旧codecと保存storeを変更せず、予約受入・成功CACHE更新を実行しません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_projected_response.h"
#include "platform/local_collector_http_observation.h"
#include "platform/local_collector_projected_start.h"
#include "platform/official_file_verifier.h"
#include <algorithm>
#include <chrono>
#include <limits>
#include <set>
#include <utility>

namespace drivercrate {
namespace {
using namespace collector_projected_json ;
using namespace std::literals ;
/**
 * @brief 収集metadataの終端区分を保持し、本文取得成功と候補適合を混同しない。
 */
using Outcome = CollectorMetadataOutcome ;
/**
 * @brief 収集metadataの不成立理由をschemaの列挙値で保持し、成功結果と区別する。
 */
using Reason = CollectorMetadataReason ;
/**
 * @brief 有限予算の到達段階を保持し、正常完了と区別する。
 */
using Limit = CollectorMetadataLimitStage ;
/**
 * @brief 投影応答が要求するcache操作を保持する。
 */
using Action = CollectorProjectedCacheAction ;
/**
 * @brief 応答へ保存するcache判定理由を保持する。
 */
using CacheReason = CollectorProjectedCacheReason ;
/**
 * @brief I/O診断値の由来となるerror domainを保持する。
 */
using Domain = CollectorIoErrorDomain ;
/**
 * @brief Hash処理が到達した段階を保持し、不完全な検証と完了を区別する。
 */
using HashStage = CollectorProjectedHashStage ;
/**
 * @brief 一回の投影応答の状態と観測値を所有し、codecへ渡す。
 */
using Response = CollectorProjectedResponse ;

constexpr std::array OUTCOMES{std::pair{Outcome::FETCHED, L"FETCHED"sv},
							  std::pair{Outcome::HELD, L"HELD"sv},
							  std::pair{Outcome::FAILED, L"FAILED"sv},
							  std::pair{Outcome::REVALIDATED, L"REVALIDATED"sv}} ;	// 固定状態名。
constexpr std::array ACTIONS{std::pair{Action::REPLACE, L"REPLACE"sv},
							 std::pair{Action::REVALIDATE, L"REVALIDATE"sv},
							 std::pair{Action::INVALIDATE, L"INVALIDATE"sv}} ;	// 固定cache操作名。
constexpr std::array REASONS{
	std::pair{CacheReason::ACCEPTED, L"ACCEPTED"sv},
	std::pair{CacheReason::NO_VALIDATOR, L"NO_VALIDATOR"sv},
	std::pair{CacheReason::REVALIDATED, L"REVALIDATED"sv},
	std::pair{CacheReason::PARTIAL, L"PARTIAL"sv},
	std::pair{CacheReason::NO_CURRENT_MATCH, L"NO_CURRENT_MATCH"sv},
	std::pair{CacheReason::DECREASED, L"DECREASED"sv},
	std::pair{CacheReason::PROJECTION_LIMIT, L"PROJECTION_LIMIT"sv},
	std::pair{CacheReason::WORKER_FAILURE, L"WORKER_FAILURE"sv},
	std::pair{CacheReason::CACHE_BASIS_INVALID, L"CACHE_BASIS_INVALID"sv},
	std::pair{CacheReason::METADATA_HASH, L"METADATA_HASH"sv}} ;	// 固定理由名。
constexpr std::array DOMAINS{
	std::pair{Domain::NONE, L"NONE"sv},
	std::pair{Domain::WIN32_ERROR, L"WIN32"sv},
	std::pair{Domain::WINSOCK_ERROR, L"WINSOCK"sv},
	std::pair{Domain::HRESULT_ERROR, L"HRESULT"sv},
	std::pair{Domain::HTTP, L"HTTP"sv},
	std::pair{Domain::PARSER, L"PARSER"sv}} ;	// 外側は旧応答と同じdomain表記。

/** @brief 元数値と失敗層を失わない内部例外です。 */
struct Stop {
	/// 数値と段階だけの失敗。
	CollectorProjectedResponseResult value ;
} ;
/**
 * @brief 構造・関係違反を固定拒否します。
 * @param[in] condition 成立を必須とする構造・関係条件。
 * @throws Failure 条件不成立時。Status::INVALIDを保持する。
 */
void require( bool condition)
{
	// 修復して成功へ進めません。
	if( !condition) {
		throw Failure{Status::INVALID} ;
	}
}
/**
 * @brief 下位結果を元層付きで伝播します。
 * @param[in] result 検査する下位結果のcopy。OK以外は元の分類と数値を維持します。
 * @param[in] stage 失敗へ結合する元層。成功時は結果へ追加しません。
 * @throws Stop resultがOK以外の場合。元結果とstageを保持します。
 */
void checked( Result result, Limit stage = Limit::NONE)
{
	// OOMを上限へ、原hashを構造拒否へ変換しません。
	if( result.status != Status::OK) {
		throw Stop{{result, stage}} ;
	}
}
/**
 * @brief Catch内だけで元例外を有限結果へ変換します。
 * @return 元の停止結果と層、確保失敗、または構造拒否の分類です。例外を外へ渡しません。
 * @pre 現在の例外を処理するcatch節内から呼び出すこと。
 */
CollectorProjectedResponseResult failure() noexcept
{
	try {
		throw ;
	} catch( const Stop &stop) {
		return stop.value ;
	} catch( const Failure &stop) {
		return {{stop.status, 0}, Limit::NONE} ;
	} catch( const std::bad_alloc &) {
		return {{Status::OUT_OF_MEMORY, E_OUTOFMEMORY}, Limit::NONE} ;
	} catch( const winrt::hresult_error &error) {
		// Library側の確保失敗も独立に返します。
		if( error.code() == E_OUTOFMEMORY) {
			return {{Status::OUT_OF_MEMORY, E_OUTOFMEMORY}, Limit::NONE} ;
		}

		return {{Status::INVALID, 0}, Limit::NONE} ;
	} catch( ...) {
		return {{Status::INVALID, 0}, Limit::NONE} ;
	}
}
/**
 * @brief 成功digestの注入なしに実byte hashを計算します。
 * @param[in] bytes 実CNGへ渡す元byteの借用view。
 * @param[in] probe 失敗HRESULTだけを返す同期診断。空または0では実hashを計算する。
 * @param[in] stage 診断callbackへ通知するhash段階。
 * @param[in] layer Hash失敗を分類する外側の有限層。
 * @return 実byteから計算したSHA-256文字列。失敗時は値を返さず検査例外を送出する。
 */
std::wstring hashBytes( std::string_view bytes, const CollectorProjectedHashProbe &probe,
					   HashStage stage, Limit layer)
{
	const NativeError injected = probe ? probe( stage) : 0 ;	// 原HRESULTだけの任意診断。
	require( injected <= 0) ;
	std::wstring	  digest ;	// 実CNGの出力。
	const NativeError error =
		injected != 0 ? injected : computeBytesSha256( bytes, digest) ;	// 0では必ず実計算。
	checked( {error == 0				  ? Status::OK
			 : error == E_OUTOFMEMORY ? Status::OUT_OF_MEMORY
									  : Status::HASH_FAILURE,
			 error},
			layer) ;
	return digest ;
}
/**
 * @brief 旧保存と同じG／jobの操作keyを実CNGで作ります。
 * @param[in] generation 元Gの64桁小文字SHA-256。同期中だけ借用する。
 * @param[in] job 元job keyの64桁小文字SHA-256。同期中だけ借用する。
 * @return 固定profileとG/jobを結合した実CNGの操作key。入力・hash失敗は検査例外。
 */
std::wstring operation( std::wstring_view generation, std::wstring_view job)
{
	require( isHash( generation) && isHash( job)) ;
	return hashBytes( "response-v2\n" + winrt::to_string( generation) + "\n" + winrt::to_string( job) +
						 "\n",
					 {}, HashStage::METADATA, Limit::NONE) ;
}
/**
 * @brief 元予約UTCだけから固定JST日を導きます。
 * @param[in] millis 1000～4102444799999の元予約UTC、Unix epochからのmillisecond。
 * @return 固定JSTへ9時間加算したYYYYMMDD。範囲違反は検査例外。
 */
std::wstring reservationDay( std::uint64_t millis)
{
	require( millis >= 1000U && millis <= 4102444799999ULL) ;
	const auto date = std::chrono::year_month_day( std::chrono::floor<std::chrono::days>(
		std::chrono::sys_time<std::chrono::milliseconds>( std::chrono::milliseconds( millis)) +
		// 固定JST。
		std::chrono::hours( 9))) ;
	wchar_t	   result[9]{} ;	// YYYYMMDD。
	swprintf_s( result, L"%04d%02u%02u", int( date.year()), unsigned( date.month()),
			   unsigned( date.day())) ;
	return result ;
}

/**
 * @brief 全fieldを同じ順序で移送する応答専用reader／writerです。
 * @note 検査・確保の例外時はsink、読取り位置、移送値の途中状態を保持する。外側codecが完成値だけを公開する。
 */
class Fields final {
public:
	/**
	 * @brief 同じ有限sinkと任意の読込み位置を借用します。
	 * @param[in,out] writer このFieldsより長生きする有限sink。
	 * @param[in,out] reader 読込み位置の借用pointer。nullは書込み専用を表す。
	 */
	Fields( Writer &writer, Reader *reader = nullptr) : writer_( writer), reader_( reader)
	{
		literal( "{") ;
	}
	/**
	 * @brief 固定構文を読込みと出力の両方へ適用します。
	 * @param[in] value 一致させて読み書きする固定ASCII構文。同期中だけ借用する。
	 */
	void literal( std::string_view value)
	{
		// 読込み時は固定字句を正確に消費します。
		if( reader_) {
			reader_->literal( value) ;
		}

		writer_.append( value) ;
	}
	/**
	 * @brief 固定keyの順序・欠損・重複を検査します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 */
	void key( std::string_view name)
	{
		// 元順序のcommaだけを扱います。
		if( !first_) {
			literal( ",") ;
		}

		first_ = false ;
		literal( "\"" + std::string( name) + "\":") ;
	}
	/**
	 * @brief 所有公開文字列を有限移送します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 * @param[in] maximum ReaderのUTF-8 byte上限と所有文字列のUTF-16 code unit上限。
	 */
	void text( std::string_view name, std::wstring &value, std::size_t maximum = 256U)
	{
		key( name) ;
		// Byte上限を変換前に確認します。
		if( reader_) {
			value = winrt::to_hstring( reader_->text( maximum)) ;
		}

		require( value.size() <= maximum) ;
		writer_.wideText( value) ;
	}
	/**
	 * @brief 固定schemaを正規化せず検査します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in] expected 完全一致させる固定文字列。同期中だけ借用する。
	 */
	void constant( std::string_view name, std::wstring_view expected)
	{
		std::wstring actual( expected) ;	// 定数の比較値。
		text( name, actual) ;
		require( actual == expected) ;
	}
	/**
	 * @brief 非負整数を対象格納型へ制限します。
	 * @tparam T 非負整数の格納型。読込み時は型の最大値まで許可する。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	template <class T> void number( std::string_view name, T &value)
	{
		key( name) ;
		// 対象格納型より広い保存数値を切り捨てません。
		if( reader_) {
			const auto raw = reader_->number() ;	// MAX_INTEGER以下の正確な元値。
			require( raw <= (std::numeric_limits<T>::max)()) ;
			value = static_cast<T>( raw) ;
		}

		writer_.number( value) ;
	}
	/**
	 * @brief 実測0と未知nullを保持します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void optionalNumber( std::string_view name, std::optional<std::uint64_t> &value)
	{
		key( name) ;
		// 元値を有限の単一valueとして消費します。
		if( reader_) {
			const auto raw = reader_->value() ;	// 未変更の元byte。
			value.reset() ;
			// null以外には数値型だけを認めます。
			if( raw != "null") {
				Reader scalar( raw, 32U) ;	// Nullと区別した数値の有限reader。
				value = scalar.number() ;
				scalar.finish() ;
			}
		}

		// 欠測を0で補いません。
		if( value) {
			writer_.number( *value) ;
		} else {
			writer_.append( "null") ;
		}
	}
	/**
	 * @brief 元validatorのnullを空文字列と区別します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void optionalText( std::string_view name, std::optional<std::wstring> &value)
	{
		key( name) ;
		// 存在するときだけ元引用符付き文字列を取得します。
		if( reader_) {
			const auto raw = reader_->value() ;	// Nullまたは有限文字列。
			value.reset() ;
			// 一つのvalidatorのescape後上限も有限です。
			if( raw != "null") {
				Reader scalar( raw, 1024U) ;	// Escape後も有限なvalidator reader。
				value = winrt::to_hstring( scalar.text( 256U)) ;
				scalar.finish() ;
			}
		}

		// 大きな文字列を先にsinkへ渡しません。
		if( value) {
			require( value->size() <= 256U) ;
			writer_.wideText( *value) ;
		} else {
			writer_.append( "null") ;
		}
	}
	/**
	 * @brief Boolの字句だけを受け付けます。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void boolean( std::string_view name, bool &value)
	{
		key( name) ;
		// 0／1や文字列へ暗黙変換しません。
		if( reader_) {
			const auto raw = reader_->value() ; /* 元bool字句。 */
			require( raw == "true" || raw == "false") ;
			value = raw == "true" ;
		}

		writer_.append( value ? "true" : "false") ;
	}
	/**
	 * @brief 固定対応表でのみenumを移送します。
	 * @tparam E 保存名へ明示対応する列挙型。
	 * @tparam N 対応表の要素数。全要素を順に照合する。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 * @param[in] names 列挙値と固定保存名の対応表。同期中だけ借用する。
	 */
	template <class E, std::size_t N>
	void enumeration( std::string_view name, E &value,
					 const std::array<std::pair<E, std::wstring_view>, N> &names)
	{
		key( name) ;
		const std::wstring saved =
			reader_ ? std::wstring( winrt::to_hstring( reader_->text( 64U))) : L"" ;	// 元保存名。
		// 未知値のdefaultや数値castを使用しません。
		for( const auto &entry : names) {
			// 同じ表を符号化・復号に使います。
			if( reader_ ? saved == entry.second : value == entry.first) {
				value = entry.first ;
				writer_.wideText( entry.second) ;
				return ;
			}
		}

		throw Failure{Status::INVALID} ;
	}
	/**
	 * @brief 下位codecの検査対象byteを元objectのまま保持します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 * @param[in] maximum Fragmentの元byte上限。下位codecの検証は別途行う。
	 */
	void fragment( std::string_view name, std::string &value, std::size_t maximum)
	{
		key( name) ;
		// 型付き下位codecへ渡す前にbyte上限を確認します。
		if( reader_) {
			const auto raw = reader_->value() ; /* 元object byte。 */
			require( raw.size() <= maximum) ;
			value.assign( raw) ;
		}

		require( value.size() <= maximum) ;
		writer_.append( value) ;
	}
	/**
	 * @brief 元200参照の全fieldを固定順で移送します。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void original( std::optional<CollectorProjectedOriginal200> &value)
	{
		key( "original200") ;
		std::string_view raw ;	// Readerが借用する一つの値。
		// Nullかobjectかを型のまま保持します。
		if( reader_) {
			raw = reader_->value() ;
			value.reset() ;
			// 元200が実在する表現のときだけ所有fieldを作ります。
			if( raw != "null") {
				value.emplace() ;
			}
		}

		// 元200なしの200応答へ架空参照を追加しません。
		if( !value) {
			writer_.append( "null") ;
			return ;
		}

		std::optional<Reader> reader ;	// 参照object内だけの有限reader。
		// 元fragmentを別readerで最後まで照合します。
		if( reader_) {
			reader.emplace( raw, 2048U) ;
		}

		Fields child( writer_, reader ? &*reader : nullptr) ;	// 同じsinkの子object。
		child.text( "generation", value->generation, 64U) ;
		child.text( "operation", value->operation, 64U) ;
		child.text( "response", value->response, 64U) ;
		child.text( "projection", value->projection, 64U) ;
		child.text( "body", value->body, 64U) ;
		child.number( "headerUtc", value->headerUtc) ;
		child.literal( "}") ;
		// 余剰fieldや値を許しません。
		if( reader) {
			reader->finish() ;
		}
	}
	/**
	 * @brief Cache操作の二fieldを固定順で移送します。
	 * @param[in,out] value 書込み時の元操作と理由。読込み時は保存値へ更新し、例外時は途中の値を保持します。
	 */
	void decision( CollectorProjectedCacheDecision &value)
	{
		key( "cacheDecision") ;
		Fields child( writer_, reader_) ;	// 同じ位置とsink。
		child.enumeration( "action", value.action, ACTIONS) ;
		child.enumeration( "reason", value.reason, REASONS) ;
		child.literal( "}") ;
	}

private:
	/// 全階層共通の有限sink。
	Writer &writer_ ;
	/// 読込み時だけの借用位置。
	Reader *reader_ ;
	/// 元field順序の先頭。
	bool	first_{true} ;
} ;

/**
 * @brief 応答の全fieldを固定順で移送します。
 * @param[in,out] fields 同じ有限reader/writer context。
 * @param[in,out] response 書込み元または全外側fieldの読込み先。例外時は途中状態を保持する。
 * @param[in,out] io 下位I/O objectの元byte。書込み元または読込み先。
 * @param[in,out] metadata 下位metadata objectの元byte。書込み元または読込み先。
 */
void responseFields( Fields &fields, Response &response, std::string &io, std::string &metadata)
{
	fields.constant( "schema", L"collector-campaign-response-v4") ;
	fields.text( "generation", response.generation, 64U) ;
	fields.text( "job", response.job, 64U) ;
	fields.text( "source", response.source) ;
	fields.text( "request", response.request, 64U) ;
	fields.text( "cache", response.cache, 64U) ;
	fields.text( "day", response.day, 8U) ;
	fields.number( "maximum", response.maximum) ;
	fields.number( "started", response.started) ;
	fields.number( "finished", response.finished) ;
	fields.number( "accepted", response.accepted) ;
	fields.enumeration( "state", response.state, OUTCOMES) ;
	fields.optionalNumber( "bytes", response.bytes) ;
	fields.number( "sends", response.sends) ;
	fields.number( "status", response.status) ;
	fields.number( "error", response.error) ;
	fields.enumeration( "errorDomain", response.errorDomain, DOMAINS) ;
	fields.number( "retryAfter", response.retryAfter) ;
	fields.boolean( "review", response.review) ;
	fields.boolean( "challenge", response.challenge) ;
	fields.text( "body", response.body, 64U) ;
	fields.text( "projection", response.projection, 64U) ;
	fields.fragment( "io", io, IO_LIMIT) ;
	fields.fragment( "metadata", metadata, METADATA_LIMIT) ;
	fields.optionalText( "requestValidator", response.requestValidator) ;
	fields.optionalText( "responseValidator", response.responseValidator) ;
	fields.original( response.original200) ;
	fields.decision( response.cacheDecision) ;
	fields.literal( "}") ;
}
/**
 * @brief 元I/Oと外側field・metadataの関係を検査します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] response 外側field、元I/O、metadataの関係を検査する所有値。
 */
void validate( const CollectorProjectedJobInput &job, const Response &response)
{
	const auto &io		 = response.io ;		// 元sealed観測。
	const auto &metadata = response.metadata ;	// 同じ元結果のmetadata。
	require( isHash( response.generation) && response.job == job.jobKey &&
			response.source == job.source.sourceId && response.request == job.requestKey &&
			response.cache == job.cacheBinding &&
			response.maximum == job.source.maximumResponseBytes &&
			response.day == reservationDay( response.started) &&
			response.started <= response.finished && response.finished <= response.accepted &&
			response.accepted <= 4102444799999ULL && response.sends <= 1U &&
			(response.status == 0U ||
			 (response.status >= 100U && response.status <= 599U && response.sends == 1U)) &&
			response.retryAfter <= 253402300799999ULL && !response.challenge) ;
	require( io.sealed && io.nativeReleased && io.cause != CollectorIoCause::NONE &&
			io.cause != CollectorIoCause::CLOCK && io.elapsedMillis &&
			io.finishedUtcMillis == response.finished && io.sends == response.sends &&
			io.bytesKnown == response.bytes.has_value() && io.lowerBytes <= response.maximum &&
			(!response.bytes || *response.bytes == io.lowerBytes) &&
			(io.sends != 0U || (response.status == 0U && io.lowerBytes == 0U)) &&
			io.error.domain == response.errorDomain && io.error.code == response.error &&
			io.error.stage == io.stage &&
			((response.errorDomain == Domain::NONE) == (response.error == 0U)) &&
			io.deadlineUtcMillis > response.started &&
			io.deadlineUtcMillis <= response.started + 120000U &&
			(!io.headerUtcMillis || (io.sends == 1U && *io.headerUtcMillis >= response.started &&
									 *io.headerUtcMillis <= response.finished))) ;
	require( response.body.empty() || isHash( response.body)) ;
	require( metadata.binding.body == response.body && response.state == metadata.outcome) ;
	require( !metadata.binding.validatedUtc ||
			(io.headerUtcMillis && *io.headerUtcMillis <= *metadata.binding.validatedUtc &&
			 *metadata.binding.validatedUtc <= response.finished)) ;
	require( !response.requestValidator || isCollectorEntityTag( *response.requestValidator)) ;
	require( !response.responseValidator || isCollectorEntityTag( *response.responseValidator)) ;
	// 原正常終了と親hash失敗によるFAILEDは別軸です。
	if( io.cause == CollectorIoCause::COMPLETE) {
		require( !io.native && io.bytesKnown && io.error.domain == Domain::NONE &&
				io.stage == CollectorIoStage::COMPLETE && io.sends == 1U &&
				*io.elapsedMillis < io.deadlineUtcMillis - response.started &&
				response.finished < io.deadlineUtcMillis && !response.review &&
				response.retryAfter == 0U && (response.status == 200U || response.status == 304U)) ;
		require( response.status != 200U ||
				(isHash( response.body) && io.headerUtcMillis && io.lowerBytes > 0U)) ;
		require( response.status != 304U ||
				(response.body.empty() && io.lowerBytes == 0U && io.headerUtcMillis)) ;
	} else {
		require( io.error.domain != Domain::NONE && response.state != Outcome::FETCHED &&
				response.state != Outcome::REVALIDATED) ;
	}

	// 取消しの受理観測を失っていないことを確認します。
	if( io.cause == CollectorIoCause::CANCELLED || io.cause == CollectorIoCause::SHARED_STOP) {
		require( io.stopElapsedMillis.has_value()) ;
	}

	const auto &diagnostics = metadata.diagnostics ;	// 元parserの固定結果。
	// Worker分類の意味を元I/Oへ再結合します。
	if( diagnostics.workerReason == CollectorProjectedWorkerReason::NONE) {
		require( io.cause == CollectorIoCause::COMPLETE) ;
		// 親hash障害やbyte縮退でも元200の解析成功を失いません。
		if( response.status == 200U) {
			require( diagnostics.parser &&
					diagnostics.parser->status == CollectorParserStatus::COMPLETED) ;
		} else {
			require( response.status == 304U && !diagnostics.parser && !diagnostics.source &&
					!diagnostics.counts) ;
		}
	}
	// 明示LIMITだけがPARSERの元数値一致を要求します。
	else if( diagnostics.workerReason == CollectorProjectedWorkerReason::PROJECTION_LIMIT) {
		require( io.cause == CollectorIoCause::PARSER && diagnostics.parser &&
				diagnostics.parser->status == CollectorParserStatus::LIMIT_EXCEEDED &&
				diagnostics.parser->error.domain == io.error.domain &&
				diagnostics.parser->error.code == io.error.code &&
				diagnostics.parser->error.stage == io.error.stage) ;
	} else {
		require( diagnostics.workerReason == CollectorProjectedWorkerReason::IO_FAILURE &&
				io.cause != CollectorIoCause::COMPLETE) ;
	}

	// 第一worker errorをmetadataの別数値へ変更しません。
	if( metadata.reason == Reason::WORKER_FAILURE) {
		require( metadata.error && metadata.error->domain == io.error.domain &&
				metadata.error->code == io.error.code) ;
	}

	// 特殊hash故障以外の成功hash欠測はencode後の検査で拒否します。
	if( metadata.reason == Reason::METADATA_HASH) {
		require( response.projection.empty() &&
				(io.cause == CollectorIoCause::COMPLETE ||
				 diagnostics.workerReason == CollectorProjectedWorkerReason::PROJECTION_LIMIT)) ;
	}

	// 元200参照は今回200へ紛れ込ませません。
	if( response.original200) {
		const auto &original = *response.original200 ;	// 参照先そのものの真正性は親contextが検査。
		require( response.status == 304U && isHash( original.generation) &&
				isHash( original.operation) && isHash( original.response) &&
				isHash( original.projection) && isHash( original.body) &&
				original.headerUtc >= 1000U && io.headerUtcMillis &&
				original.headerUtc <= *io.headerUtcMillis && response.requestValidator) ;
	}

	// 成功304形の必須参照を確認します。Liveでの許可ではありません。
	if( response.state == Outcome::REVALIDATED) {
		require( response.status == 304U && response.original200 && response.requestValidator &&
				(!response.responseValidator ||
				 response.responseValidator == response.requestValidator)) ;
	}

	// 未pin304の元HTTP拒否以外は、元200根拠を持たない正常304にしません。
	if( response.status == 304U && io.cause == CollectorIoCause::COMPLETE) {
		require( response.original200 && (response.state == Outcome::REVALIDATED ||
										 metadata.reason == Reason::CACHE_BASIS_INVALID ||
										 metadata.reason == Reason::METADATA_HASH)) ;
	}

	const auto expected = collectorProjectedCacheDecision( response) ;	// 任意保存値を独立に再導出。
	require( response.cacheDecision.action == expected.action &&
			response.cacheDecision.reason == expected.reason) ;
}

/**
 * @brief Workerが消去したdraftへ残余が混入していないことを確認します。
 * @param[in] draft Workerが終端で消去したはずの公開draft。
 * @param[in] limited 上限到達用の消去形を検査する場合true。
 * @return 指定終端形の全消去条件が成立する場合true。残余・矛盾がある場合false。
 */
bool clearedDraft( const CollectorMetadataProjectionDraft &draft, bool limited)
{
	return draft.status == (limited ? CollectorProjectionDraftStatus::HELD
									: CollectorProjectionDraftStatus::MINIMAL_FAILURE) &&
		   draft.bodySha256.empty() && draft.sourceId.empty() && draft.providerId.empty() &&
		   draft.policyId.empty() && draft.resourceId.empty() && draft.scopeSha256.empty() &&
		   draft.cacheBinding.empty() && draft.validatedUtcMillis == 0U && !draft.complete &&
		   draft.sourceStatus == 0U && draft.sourceSeen == 0U && draft.sourceDuplicates == 0U &&
		   draft.sourceRejected == 0U && draft.sourceCollisions == 0U &&
		   std::all_of( draft.sourceReasonCounts.begin(), draft.sourceReasonCounts.end(),
					   []( auto value) { return value == 0U ; }) &&
		   draft.slices.empty() && draft.records.empty() && draft.edges.empty() ;
}
/**
 * @brief 下位I/O codecに渡す元byteを作ります。旧byte規則は変更しません。
 * @param[in] response 下位I/Oへ再結合する元応答。同期中だけ借用する。
 * @return 元観測を旧I/O codecで符号化した所有byte。Codec拒否時は検査例外。
 */
std::string ioBytes( const Response &response)
{
	std::string bytes ;	// 旧v1のcanonical object。
	require( encodeCollectorHttpObservation( response.io,
										   operation( response.generation, response.job), bytes)) ;
	require( bytes.size() <= IO_LIMIT) ;
	return bytes ;
}
/**
 * @brief 単一応答の全byteとhashを一度だけ生成します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] response 全関係を検査して符号化する元応答。
 * @param[in] probe 失敗HRESULTだけを注入する同期hash診断。空では実CNGだけを使う。
 * @return 全検査と実hash生成を終えた所有byte群。失敗時は途中出力を返さず例外。
 */
CollectorProjectedResponseBytes encode( const CollectorProjectedJobInput	 &job,
									   const Response					 &response,
									   const CollectorProjectedHashProbe &probe)
{
	validate( job, response) ;
	CollectorProjectedResponseBytes encoded ;	// 全成功まで外部へ公開しません。
	checked( encodeCollectorMetadata( job, response.metadata, encoded.metadata),
			Limit::METADATA_BYTES) ;
	encoded.value = response ;
	// Metadata hash失敗の最小形だけは元失敗を再hashしません。
	if( response.metadata.reason != Reason::METADATA_HASH) {
		const auto digest = hashBytes( encoded.metadata, probe, HashStage::METADATA,
									  Limit::METADATA_BYTES) ;	// 実metadata hash。
		require( response.projection.empty() || response.projection == digest) ;
		encoded.value.projection = digest ;
	}

	std::string io = ioBytes( encoded.value) ;	// 既存codecの固定object。
	try {
		Writer writer( RESPONSE_LIMIT) ;	// 独立した応答上限。
		Fields fields( writer) ;			// 固定field順の出力。
		responseFields( fields, encoded.value, io, encoded.metadata) ;
		encoded.response = writer.take() ;
	} catch( const Failure &error) {
		throw Stop{{{error.status, 0}, Limit::RESPONSE_BYTES}} ;
	}

	EnvelopeBytes body ;	// 実応答hashの生成結果。
	const auto	  result = encodeEnvelope( encoded.response, encoded.envelope, body, [&]() {
		   return probe ? probe( HashStage::RESPONSE) : 0 ;
	   }) ; // 外側も有限sinkで生成。
	checked( result,
			result.status == Status::SIZE_LIMIT ? Limit::ENVELOPE_BYTES : Limit::RESPONSE_BYTES) ;
	encoded.responseSha256 = std::move( body.responseSha256) ;
	return encoded ;
}
} // namespace

/**
 * @copydoc drivercrate::collectorProjectedCacheDecision(const CollectorProjectedResponse &)
 */
CollectorProjectedCacheDecision collectorProjectedCacheDecision( const Response &response) noexcept
{
	const auto reason = response.metadata.reason ;	// Metadata側の理由を優先します。
	// 失敗・保留の固定理由をそのまま無効化候補へ写します。
	if( reason == Reason::WORKER_FAILURE) {
		return {Action::INVALIDATE, CacheReason::WORKER_FAILURE} ;
	}

	// Hash故障はI/O成功と区別します。
	if( reason == Reason::METADATA_HASH) {
		return {Action::INVALIDATE, CacheReason::METADATA_HASH} ;
	}

	// 元200の検査拒否です。
	if( reason == Reason::CACHE_BASIS_INVALID) {
		return {Action::INVALIDATE, CacheReason::CACHE_BASIS_INVALID} ;
	}

	// 件数・byte上限です。
	if( reason == Reason::PROJECTION_LIMIT) {
		return {Action::INVALIDATE, CacheReason::PROJECTION_LIMIT} ;
	}

	// 旧成功を今回へ混ぜません。
	if( reason == Reason::DECREASED) {
		return {Action::INVALIDATE, CacheReason::DECREASED} ;
	}

	// 304の真正性は親contextで別途確認します。
	if( response.state == Outcome::REVALIDATED) {
		return {Action::REVALIDATE, CacheReason::REVALIDATED} ;
	}

	// 未採用を部分成功へ分類しません。
	if( response.state != Outcome::FETCHED) {
		return {Action::INVALIDATE, CacheReason::NO_CURRENT_MATCH} ;
	}

	// 一部edgeが不一致なら全成功basisに使用しません。
	if( !response.metadata.complete || response.metadata.edges.empty() ||
	   std::any_of(
		   response.metadata.edges.begin(), response.metadata.edges.end(),
		   []( const auto &edge) { return edge.state != CollectorProjectedTargetState::MATCH ; })) {
		return {Action::INVALIDATE, CacheReason::PARTIAL} ;
	}

	return {Action::REPLACE,
			response.responseValidator ? CacheReason::ACCEPTED : CacheReason::NO_VALIDATOR} ;
}

/**
 * @copydoc drivercrate::makeCollectorProjectedResponseCandidate(const CollectorProjectedJobInput &, const CollectorProjectedWorkerResult &, std::uint64_t, CollectorProjectedResponse &)
 */
Result makeCollectorProjectedResponseCandidate( const CollectorProjectedJobInput		&job,
											   const CollectorProjectedWorkerResult &worker,
											   std::uint64_t						 acceptedUtc,
											   Response &response) noexcept
{
	response = {} ;
	try {
		const auto &binding = worker.binding ;	// 元workerのbinding。稼働予約との同値は親の責任です。
		require( binding.mode == CollectorRecoveryDispatch::Mode::PROJECTED &&
				binding.jobIndex == job.jobIndex && isHash( binding.generationKey) &&
				binding.startedUtcMillis >= 1000U &&
				binding.anchorUtcMillis >= binding.startedUtcMillis &&
				binding.deadlineUtcMillis > binding.anchorUtcMillis &&
				binding.deadlineSteadyMillis > binding.anchorSteadyMillis &&
				binding.deadlineUtcMillis - binding.anchorUtcMillis ==
					binding.deadlineSteadyMillis - binding.anchorSteadyMillis) ;
		CollectorRecoveryDispatch expected = binding ;	// 元公開jobから再結合する同一数値予約。
		expected.jobKey					   = job.jobKey ;
		expected.requestKey				   = job.requestKey ;
		expected.cacheBinding			   = job.cacheBinding ;
		expected.scopeSha256			   = job.scopeSha256 ;
		expected.source					   = job.source ;
		require(
			sameCollectorRecoveryDispatch( expected, binding) &&
			worker.io.deadlineUtcMillis == binding.deadlineUtcMillis &&
			worker.io.finishedUtcMillis && worker.io.elapsedMillis &&
			*worker.io.finishedUtcMillis >= binding.anchorUtcMillis &&
			(!worker.io.headerUtcMillis || *worker.io.headerUtcMillis >= binding.anchorUtcMillis)) ;
		require( worker.io.cause != CollectorIoCause::COMPLETE ||
				*worker.io.elapsedMillis <
					binding.deadlineSteadyMillis - binding.anchorSteadyMillis) ;
		Response candidate ;	// 予約受入ではない公開候補。
		candidate.generation  = binding.generationKey ;
		candidate.job		  = binding.jobKey ;
		candidate.source	  = binding.source.sourceId ;
		candidate.request	  = binding.requestKey ;
		candidate.cache		  = binding.cacheBinding ;
		candidate.day		  = reservationDay( binding.startedUtcMillis) ;
		candidate.maximum	  = binding.source.maximumResponseBytes ;
		candidate.started	  = binding.startedUtcMillis ;
		candidate.finished	  = *worker.io.finishedUtcMillis ;
		candidate.accepted	  = acceptedUtc ;
		candidate.io		  = worker.io ;
		candidate.sends		  = worker.io.sends ;
		candidate.status	  = worker.http.status ;
		candidate.error		  = worker.io.error.code ;
		candidate.errorDomain = worker.io.error.domain ;
		candidate.retryAfter  = worker.http.retryAfterUtcMillis.value_or( 0U) ;
		candidate.review	  = worker.http.retryAfterNeedsReview ;
		candidate.body		  = worker.http.bodySha256 ;
		// 未観測量を0として保存しません。
		if( worker.io.bytesKnown) {
			candidate.bytes = worker.io.lowerBytes ;
		}

		// 欠測validatorは明示nullです。
		if( !worker.http.entityTag.empty()) {
			candidate.responseValidator = worker.http.entityTag ;
		}

		// 正常draftは同じ公開metadata validatorを通します。
		if( worker.reason == CollectorProjectedWorkerReason::NONE) {
			require( worker.parser && worker.io.cause == CollectorIoCause::COMPLETE &&
					worker.http.status == 200U) ;
			checked( makeCollectorMetadataDocument( job, worker.projection, *worker.parser,
												  candidate.metadata)) ;
		} else {
			const bool limited =
				worker.reason ==
				CollectorProjectedWorkerReason::PROJECTION_LIMIT ;	// 原上限だけを区別。
			require( (limited || worker.reason == CollectorProjectedWorkerReason::IO_FAILURE) &&
					clearedDraft( worker.projection, limited)) ;
			auto &metadata	 = candidate.metadata ;	// 消去済み診断をnullで残す最小所有値。
			metadata.binding = {job.source.sourceId,   job.providerId,	job.policyId,
								job.source.resourceId, job.scopeSha256, job.cacheBinding,
								candidate.body,		   std::nullopt} ;
			metadata.diagnostics.workerReason = worker.reason ;
			metadata.diagnostics.parser		  = worker.parser ;
			metadata.outcome				  = limited ? Outcome::HELD : Outcome::FAILED ;
			metadata.reason = limited ? Reason::PROJECTION_LIMIT : Reason::WORKER_FAILURE ;
			metadata.form =
				limited ? CollectorMetadataForm::FULL : CollectorMetadataForm::MINIMAL_FAILURE ;
			metadata.diagnostics.limitStage = limited ? Limit::WORKER : Limit::NONE ;
			// 第一worker errorだけをそのままmetadataへ保持します。
			if( !limited) {
				metadata.error =
					CollectorMetadataError{CollectorMetadataErrorPhase::WORKER,
										   worker.io.error.domain, worker.io.error.code} ;
			}
		}

		candidate.state			= candidate.metadata.outcome ;
		candidate.cacheDecision = collectorProjectedCacheDecision( candidate) ;
		validate( job, candidate) ;
		response = std::move( candidate) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return failure().result ;
	}
}

/** @see local_collector_projected_response.h */
Result finalizeCollectorProjectedHistory( const CollectorPreparedProjectedJob  &prepared,
										 const CollectorProjectedWorkerResult &worker,
										 std::uint64_t						   acceptedUtc,
										 std::span<const CollectorProjectedHistoryEvidence> history,
										 CollectorProjectedHistoryFinalization			   &output,
										 const CollectorProjectedHashProbe &probe) noexcept
{
	output = {} ;
	try {
		require( history.size() <= 16U) ;
		const auto							 &job = prepared.value() ;	// 今回の固定scope。
		CollectorProjectedHistoryFinalization candidate ;				// 全参照照合まで外部へ公開しません。
		checked(
			makeCollectorProjectedResponseCandidate( job, worker, acceptedUtc, candidate.response)) ;
		std::set<std::wstring> seen ;	// 同sliceの多重履歴を直近成功と誤認しません。
		// 最大16参照を全て検証し、別bindingの破損もcache missへ変換しません。
		for( const auto &entry : history) {
			require( entry.campaign && entry.campaign->job( entry.jobIndex) && !entry.input.empty() &&
					entry.input.size() <= 768U * 1024U && !entry.startIntent.empty() &&
					entry.startIntent.size() <= 4096U && !entry.envelope.empty() &&
					entry.envelope.size() <= ENVELOPE_LIMIT && isHash( entry.generation) &&
					isHash( entry.operation) && isHash( entry.response) && isHash( entry.projection) &&
					isHash( entry.slice) && seen.insert( entry.slice).second) ;
			CollectorProjectedCampaignDefinition definition ;	// 元manifestを再構築します。
			CollectorProjectedCampaignIdentity identity ;		// 元Gをcallerの参照だけから信用しません。
			require( parseCollectorProjectedCampaignIdentity( entry.input, definition, identity) &&
					identity.inputSha256 == entry.campaign->inputSha256() &&
					identity.generationKey == entry.campaign->generationKey() &&
					identity.generationKey == entry.generation) ;
			const auto &oldJob = entry.campaign->job( entry.jobIndex)->value() ;	// 元の不変scope。
			CollectorRecoveryDispatch start ;										// Intentと元preparedの結合を検査します。
			require( parseCollectorProjectedStart( identity, entry.startIntent, start) &&
					start.jobIndex == entry.jobIndex && start.jobKey == oldJob.jobKey &&
					start.requestKey == oldJob.requestKey &&
					start.cacheBinding == oldJob.cacheBinding &&
					start.scopeSha256 == oldJob.scopeSha256) ;
			auto boundStart	  = start ;	// 全source条件も既存の同値判定へ渡します。
			boundStart.source = oldJob.source ;
			require( sameCollectorRecoveryDispatch( start, boundStart)) ;
			CollectorProjectedResponseBytes decoded ;	// 実CNGの二段独立read-back。
			const auto read = decodeCollectorProjectedResponse( oldJob, entry.envelope, decoded,
															   probe) ;	// 元hash故障は保持。
			checked( read.result, read.stage) ;
			const auto &old = decoded.value ;	// 元byteと一致した値のみ比較します。
			require(
				old.generation == entry.generation &&
				entry.operation == operation( old.generation, old.job) &&
				decoded.responseSha256 == entry.response && old.projection == entry.projection &&
				old.request == job.requestKey && old.state == Outcome::FETCHED &&
				old.status == 200U && old.started == start.startedUtcMillis &&
				old.io.deadlineUtcMillis == start.deadlineUtcMillis && old.io.headerUtcMillis &&
				*old.io.headerUtcMillis >= start.anchorUtcMillis &&
				old.finished >= start.anchorUtcMillis && old.io.elapsedMillis &&
				*old.io.elapsedMillis < start.deadlineSteadyMillis - start.anchorSteadyMillis &&
				old.accepted <= worker.binding.anchorUtcMillis && old.accepted <= acceptedUtc &&
				(old.generation != worker.binding.generationKey || old.job != job.jobKey) &&
				old.metadata.slices.size() == 1U &&
				old.metadata.slices.front().scope.key == entry.slice &&
				old.metadata.slices.front().disposition == CollectorMetadataDisposition::ACCEPTED) ;
			// 正当な旧artifact／scopeは、全参照検証後にだけ今回との比較から外します。
			if( old.cache != job.cacheBinding || oldJob.scopeSha256 != job.scopeSha256) {
				continue ;
			}

			require( job.slices.size() == 1U && job.slices.front().key == entry.slice) ;
			// 完全成功でも送信許可にはせず、元200の固定参照だけを返します。
			if( old.cacheDecision.action == Action::REPLACE) {
				require( !candidate.previousFull200) ;
				candidate.previousFull200 = CollectorProjectedOriginal200{
					entry.generation, entry.operation, entry.response,
					entry.projection, old.body,		   *old.io.headerUtcMillis} ;
				candidate.previousValidator = old.responseValidator ;
			}

			// 消去済み失敗配列を「正常200の0件」として比較しません。
			if( worker.reason != CollectorProjectedWorkerReason::NONE) {
				continue ;
			}

			auto &metadata = candidate.response.metadata ;	// hash前の今回配列を保持します。
			require( metadata.slices.size() == 1U &&
					metadata.slices.front().scope.key == entry.slice) ;
			++candidate.comparedSlices ;
			const auto count = [&]( const auto &records) {
				return std::count_if( records.begin(), records.end(), [&]( const auto &record) {
					return record.sliceKey == entry.slice ;
				}) ;
			} ; // Codecが重複排除と所属を照合済みの配列のみ数えます。
			// 減少だけを保留へ最終化し、旧recordを追加して見かけの件数を保ちません。
			if( count( metadata.records) < count( old.metadata.records)) {
				++candidate.decreasedSlices ;
				metadata.outcome					= Outcome::HELD ;
				metadata.reason						= Reason::DECREASED ;
				metadata.complete					= false ;
				metadata.slices.front().disposition = CollectorMetadataDisposition::HELD ;
				metadata.slices.front().reason		= Reason::DECREASED ;
				metadata.slices.front().complete	= false ;
				candidate.response.state			= Outcome::HELD ;
				candidate.response.cacheDecision =
					collectorProjectedCacheDecision( candidate.response) ;
			}
		}

		validate( job, candidate.response) ;
		output = std::move( candidate) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return failure().result ;
	}
}

/**
 * @copydoc drivercrate::encodeCollectorProjectedResponse(const CollectorProjectedJobInput &, const CollectorProjectedResponse &, CollectorProjectedResponseBytes &, const CollectorProjectedHashProbe &)
 */
CollectorProjectedResponseResult encodeCollectorProjectedResponse(
	const CollectorProjectedJobInput &job, const Response &response,
	CollectorProjectedResponseBytes &encoded, const CollectorProjectedHashProbe &probe) noexcept
{
	encoded = {} ;
	try {
		encoded = encode( job, response, probe) ;
		return {{Status::OK, 0}, Limit::NONE} ;
	} catch( ...) {
		return failure() ;
	}
}

/** @see local_collector_projected_response.h */
CollectorProjectedResponseResult decodeCollectorProjectedResponse(
	const CollectorProjectedJobInput &job, std::string_view envelope,
	CollectorProjectedResponseBytes &decoded, const CollectorProjectedHashProbe &probe) noexcept
{
	decoded = {} ;
	try {
		EnvelopeBytes outer ;	// 独立に実CNG検査する元応答byte。
		checked( decodeEnvelope( envelope, outer,
							   [&]() { return probe ? probe( HashStage::READ_RESPONSE) : 0 ; }),
				Limit::RESPONSE_BYTES) ;
		Reader reader( outer.response, RESPONSE_LIMIT) ;	// 元応答の有限位置。
		Writer canonical( RESPONSE_LIMIT) ;					// 固定順・表記の再出力。
		Fields fields( canonical, &reader) ;				// 同じschemaを読む専用移送。
		CollectorProjectedResponseBytes candidate ;			// 全照合後だけ所有値を公開。
		std::string						io ;				// 旧objectの元byte。
		responseFields( fields, candidate.value, io, candidate.metadata) ;
		reader.finish() ;
		require( canonical.view() == outer.response) ;
		checked( decodeCollectorMetadata( job, candidate.metadata, candidate.value.metadata),
				Limit::METADATA_BYTES) ;
		require( decodeCollectorHttpObservation(
			io, operation( candidate.value.generation, candidate.value.job), candidate.value.io)) ;
		auto &observed			   = candidate.value.io ;	// 旧v1 objectに外側fieldを再結合します。
		observed.sends			   = candidate.value.sends ;
		observed.bytesKnown		   = candidate.value.bytes.has_value() ;
		observed.finishedUtcMillis = candidate.value.finished ;
		observed.error = {candidate.value.errorDomain, candidate.value.error, observed.stage} ;
		validate( job, candidate.value) ;
		// 特殊hash故障の最小形だけは空projectionを維持します。
		if( candidate.value.metadata.reason != Reason::METADATA_HASH) {
			require( isHash( candidate.value.projection)) ;
			const auto digest = hashBytes( candidate.metadata, probe, HashStage::READ_METADATA,
										  Limit::METADATA_BYTES) ;	// 独立実計算。
			require( digest == candidate.value.projection) ;
		}

		require( ioBytes( candidate.value) == io) ;
		candidate.response		 = std::move( outer.response) ;
		candidate.responseSha256 = std::move( outer.responseSha256) ;
		candidate.envelope.assign( envelope) ;
		decoded = std::move( candidate) ;
		return {{Status::OK, 0}, Limit::NONE} ;
	} catch( ...) {
		return failure() ;
	}
}

/**
 * @copydoc drivercrate::encodeCollectorProjectedResponseWithFallback(const CollectorProjectedJobInput &, const CollectorProjectedResponse &, CollectorProjectedResponseBytes &, const CollectorProjectedHashProbe &)
 */
CollectorProjectedResponseResult encodeCollectorProjectedResponseWithFallback(
	const CollectorProjectedJobInput &job, const Response &response,
	CollectorProjectedResponseBytes &encoded, const CollectorProjectedHashProbe &probe) noexcept
{
	encoded = {} ;
	const auto initial =
		// 通常候補の一回符号化。
		encodeCollectorProjectedResponse( job, response, encoded, probe) ;
	// 成功と、縮退してはならない第一失敗をそのまま返します。
	if( initial.result.status == Status::OK || response.metadata.reason == Reason::WORKER_FAILURE ||
	   response.metadata.reason == Reason::METADATA_HASH ||
	   (initial.result.status != Status::SIZE_LIMIT &&
		!(initial.result.status == Status::HASH_FAILURE &&
		  initial.stage == Limit::METADATA_BYTES))) {
		return initial ;
	}

	try {
		require( response.io.cause == CollectorIoCause::COMPLETE ||
				response.metadata.diagnostics.workerReason ==
					CollectorProjectedWorkerReason::PROJECTION_LIMIT) ;
		Response fallback = response ;			// 元I/Oや元所有値を変更しない一回の縮退候補。
		auto	&metadata = fallback.metadata ;	// 成功配列を持ち出さない最小形。
		metadata.records.clear() ;
		metadata.slices.clear() ;
		metadata.edges.clear() ;
		metadata.complete = false ;
		fallback.projection.clear() ;
		// Hash故障は元HRESULTを保持し、そのmetadataを再hashしません。
		if( initial.result.status == Status::HASH_FAILURE) {
			metadata.form					= CollectorMetadataForm::MINIMAL_FAILURE ;
			metadata.outcome				= Outcome::FAILED ;
			metadata.reason					= Reason::METADATA_HASH ;
			metadata.diagnostics.limitStage = Limit::NONE ;
			metadata.error					= CollectorMetadataError{
				 CollectorMetadataErrorPhase::METADATA_HASH, Domain::HRESULT_ERROR,
				 static_cast<std::uint32_t>( initial.result.error)} ;
		} else {
			metadata.form					= CollectorMetadataForm::FULL ;
			metadata.outcome				= Outcome::HELD ;
			metadata.reason					= Reason::PROJECTION_LIMIT ;
			metadata.diagnostics.limitStage = initial.stage ;
			metadata.error.reset() ;
		}

		fallback.state		   = metadata.outcome ;
		fallback.cacheDecision = collectorProjectedCacheDecision( fallback) ;
		return encodeCollectorProjectedResponse( job, fallback, encoded, probe) ;
	} catch( ...) {
		return failure() ;
	}
}
} // namespace drivercrate
