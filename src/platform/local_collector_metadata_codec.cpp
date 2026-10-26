//------------------------------------------------------------------------------
/**
 * @file local_collector_metadata_codec.cpp
 * @brief 収集metadataの有限往復と元scope関係を検査します。
 * @version 01.00.03
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  固定fieldと全対象関係のcodecを追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.00.02   Shunji Ogawa  2026/10/16 codec引数の読書き状態と例外変換の戻り値を明記。
 * Ver.01.00.03 Shunji Ogawa  2026/10/26  IntelのSHA-512単独射影を算法別に検証。
 * </pre>
 *
 * @note Hash生成、予約受入、永続保存は行いません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_metadata_codec.h"
#include "platform/official_collector_public_text.h"
#include "platform/asus_catalog_parser.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "core/official_source_policy.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>

namespace drivercrate {
namespace {
using namespace collector_projected_json ;
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using Object = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using Value = winrt::Windows::Data::Json::IJsonValue ;
/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using Array = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON値の実種別を表し、schemaで要求する型との一致を検査する。
 */
using Type = winrt::Windows::Data::Json::JsonValueType ;
/**
 * @brief 収集metadataの不成立理由をschemaの列挙値で保持し、成功結果と区別する。
 */
using Reason = CollectorMetadataReason ;
/**
 * @brief 収集metadataの終端区分を保持し、本文取得成功と候補適合を混同しない。
 */
using Outcome = CollectorMetadataOutcome ;
/**
 * @brief Metadata解析に使用する登録済み形式を保持する。
 */
using Form = CollectorMetadataForm ;
/**
 * @brief Metadata取得後の採用・拒否区分を保持する。
 */
using Disposition = CollectorMetadataDisposition ;
/**
 * @brief 有限予算の到達段階を保持し、正常完了と区別する。
 */
using Limit = CollectorMetadataLimitStage ;
/**
 * @brief 元診断が発生した処理段階を保持する。
 */
using Phase = CollectorMetadataErrorPhase ;
/**
 * @brief 投影対象ごとの現在の進行状態を保持する。
 */
using State = CollectorProjectedTargetState ;

/**
 * @brief 型・関係違反を数値だけで伝えます。
 * @param[in] condition 成立を必須とする型・関係条件。
 * @throws Failure conditionがfalseの場合。Status::INVALIDを保持する。
 */
void require( bool condition)
{
	// 欠測や矛盾を補正して成功へ変更しません。
	if( !condition) {
		throw Failure{Status::INVALID} ;
	}
}

/**
 * @brief 元例外をOOMと構造拒否へ区別します。呼出しはcatch内限定です。
 * @return Failureの元分類、確保失敗のOUT_OF_MEMORYとE_OUTOFMEMORY、またはINVALIDと0です。
 * @pre 現在の例外を処理するcatch節内から呼び出すこと。
 * @note 例外を外へ渡さず、戻り値は参照や新しい資源の所有権を保持しません。
 */
Result currentFailure() noexcept
{
	try {
		throw ;
	} catch( const Failure &failure) {
		return {failure.status, 0} ;
	} catch( const std::bad_alloc &) {
		return {Status::OUT_OF_MEMORY, E_OUTOFMEMORY} ;
	} catch( const winrt::hresult_error &failure) {
		// WinRTの確保失敗を不正JSONへ読み替えません。
		if( failure.code() == E_OUTOFMEMORY) {
			return {Status::OUT_OF_MEMORY, E_OUTOFMEMORY} ;
		}

		return {Status::INVALID, 0} ;
	} catch( ...) {
		return {Status::INVALID, 0} ;
	}
}

/**
 * @brief 同じ固定field順で書込みと読込み後の再符号化を行います。
 * @note 例外で中断した場合、sinkと移送先には途中状態が残る。完成値の公開は外側codecが判断する。
 */
class Fields final {
public:
	/**
	 * @brief 所有sinkと任意の有限parse済みobjectを借用します。
	 * @param[in,out] writer このFieldsより長生きする有限sink。構築時に開始braceを出力する。
	 * @param[in] input 読込み元JSONの共有参照。nullは書込み専用を表す。
	 */
	Fields( Writer &writer, Object input = nullptr) : writer_( writer), input_( input)
	{
		writer_.append( "{") ;
	}
	/** @brief 明示したfieldを終えます。Destructorからは出力しません。 */
	void end()
	{
		writer_.append( "}") ;
	}
	/**
	 * @brief 現在の処理が読込みも伴うか返します。
	 * @return 読込み元objectを保持する場合true。書込み専用の場合false。
	 */
	bool reading() const noexcept
	{
		return input_ != nullptr ;
	}
	/**
	 * @brief 一つの固定名を出力し、読込み時は元型を取得します。
	 * @param[in] name 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @return 読込み時は指定fieldのJSON共有参照、書込み専用時はnull。欠損や型取得失敗は例外。
	 */
	Value field( std::string_view name)
	{
		// 区切りを元field順で一度だけ出力します。
		if( !first_) {
			writer_.append( ",") ;
		}

		first_ = false ;
		writer_.text( name) ;
		writer_.append( ":") ;
		return input_ ? input_.GetNamedValue( winrt::to_hstring( name)) : nullptr ;
	}
	/**
	 * @brief 有限公開文字列を型付きで移送します。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] textValue 書込み元または読込み先の所有文字列。検査失敗時は途中状態を保持する。
	 * @param[in] limit 許可するUTF-16 code unit数の上限。
	 */
	void text( std::string_view key, std::wstring &textValue, std::size_t limit = 1024U)
	{
		const auto raw = field( key) ;	// 元fieldの型付き値。
		// 保存文字列だけを受理します。
		if( raw) {
			require( raw.ValueType() == Type::String) ;
			textValue = raw.GetString() ;
		}

		require( textValue.size() <= limit) ;
		writer_.wideText( textValue) ;
	}
	/**
	 * @brief 定数schemaやprofileを明示検査します。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in] expected 一致を必須とする固定文字列。同期中だけ借用する。
	 */
	void constant( std::string_view key, std::wstring_view expected)
	{
		std::wstring actual( expected) ;	// 読込み前の定数。
		text( key, actual, 128U) ;
		require( actual == expected) ;
	}
	/**
	 * @brief Bool以外への型変換を行いません。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void boolean( std::string_view key, bool &value)
	{
		const auto raw = field( key) ;	// 元field。
		// 数値や文字列の代用を拒否します。
		if( raw) {
			require( raw.ValueType() == Type::Boolean) ;
			value = raw.GetBoolean() ;
		}

		writer_.append( value ? "true" : "false") ;
	}
	/**
	 * @brief 非負整数を元格納型とJSONの共通範囲へ制限します。
	 * @tparam T 非負整数を保持する格納型。JSONの正確な整数範囲内に制限する。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	template <class T> void number( std::string_view key, T &value)
	{
		const auto raw = field( key) ;	// 元field。
		// 字句事前検査後でも対象型の範囲を再確認します。
		if( raw) {
			require( raw.ValueType() == Type::Number) ;
			const double numeric = raw.GetNumber() ;	// 2^53未満の正確な整数。
			require( numeric >= 0 && numeric <= static_cast<double>( MAX_INTEGER) &&
					numeric <= static_cast<double>( (std::numeric_limits<T>::max)())) ;
			value = static_cast<T>( numeric) ;
			require( static_cast<double>( value) == numeric) ;
		}

		writer_.number( value) ;
	}
	/**
	 * @brief Optional整数の欠測をnullとして保持します。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void optionalNumber( std::string_view key, std::optional<std::uint64_t> &value)
	{
		const auto raw = field( key) ;	// 元field。
		// 欠測を実測0へ補いません。
		if( raw) {
			value.reset() ;
			// Numberだけを範囲検査して所有します。
			if( raw.ValueType() != Type::Null) {
				require( raw.ValueType() == Type::Number) ;
				const double numeric = raw.GetNumber() ;	// 正確な非負整数。
				require( numeric >= 0 && numeric <= static_cast<double>( MAX_INTEGER)) ;
				value = static_cast<std::uint64_t>( numeric) ;
				require( static_cast<double>( *value) == numeric) ;
			}
		}

		// nullと実値の出力を分離します。
		if( value) {
			writer_.number( *value) ;
		} else {
			writer_.append( "null") ;
		}
	}
	/**
	 * @brief Optional公開文字列の空とnullを区別します。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 */
	void optionalText( std::string_view key, std::optional<std::wstring> &value)
	{
		const auto raw = field( key) ;	// 元field。
		// 元のnullを保持します。
		if( raw) {
			value.reset() ;
			// 存在する文字列だけを所有します。
			if( raw.ValueType() != Type::Null) {
				require( raw.ValueType() == Type::String) ;
				value = raw.GetString() ;
			}
		}

		// 公開表示の上限を出力より前に検査します。
		if( value) {
			require( value->size() <= 1024U) ;
			writer_.wideText( *value) ;
		} else {
			writer_.append( "null") ;
		}
	}
	/**
	 * @brief 明示対応表だけでenumを変換します。未知値のcastは行いません。
	 * @tparam E 対応表で明示した列挙型。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 * @param[in] values 許可するenumと保存名の有限対応表。同期中だけ借用する。
	 */
	template <class E>
	void enumeration( std::string_view key, E &value,
					 std::initializer_list<std::pair<E, std::wstring_view>> values)
	{
		const auto raw = field( key) ;	// 元field。
		require( !raw || raw.ValueType() == Type::String) ;
		// 有限集合内の名前・値だけを照合します。
		for( const auto &entry : values) {
			// 保存値は名前、出力値はenumへ完全一致させます。
			if( raw ? raw.GetString() == entry.second : value == entry.first) {
				value = entry.first ;
				writer_.wideText( entry.second) ;
				return ;
			}
		}

		throw Failure{Status::INVALID} ;
	}
	/**
	 * @brief 一つの固定objectを同じsinkへ再帰出力します。
	 * @tparam T 子objectの所有値型。
	 * @tparam F 同期の子object移送callback型。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 * @param[in] transfer 子値を同じsinkへ移送する同期callback。引数の参照を呼出し後まで保持しない。
	 */
	template <class T, class F> void object( std::string_view key, T &value, F transfer)
	{
		const auto raw = field( key) ;	// 子objectの元値。
		require( !raw || raw.ValueType() == Type::Object) ;
		Fields child( writer_, raw ? raw.GetObject() : Object{nullptr}) ;	// 同じ有限sink。
		transfer( child, value) ;
		child.end() ;
	}
	/**
	 * @brief Optional objectの欠測を保持します。
	 * @tparam T 存在時に保持する子objectの値型。
	 * @tparam F 同期の子object移送callback型。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
	 * @param[in] transfer 子値を同じsinkへ移送する同期callback。引数の参照を呼出し後まで保持しない。
	 */
	template <class T, class F>
	void optional( std::string_view key, std::optional<T> &value, F transfer)
	{
		const auto raw = field( key) ;	// 子objectまたはnull。
		// 元の有無を型検査して所有します。
		if( raw) {
			require( raw.ValueType() == Type::Null || raw.ValueType() == Type::Object) ;
			value.reset() ;
			// 存在時だけ初期値を確保します。
			if( raw.ValueType() == Type::Object) {
				value.emplace() ;
			}
		}

		// 明示nullを欠損fieldとして扱いません。
		if( !value) {
			writer_.append( "null") ;
			return ;
		}

		Fields child( writer_, raw ? raw.GetObject() : Object{nullptr}) ;	// 同じ有限sink。
		transfer( child, *value) ;
		child.end() ;
	}
	/**
	 * @brief 配列を確保前に件数制限し、元順序で移送します。
	 * @tparam T 配列の所有要素型。
	 * @tparam F 各要素を同期移送するcallback型。
	 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
	 * @param[in,out] values 書込み元または読込み先の配列。読込み時にresizeし、例外時は途中状態を保持する。
	 * @param[in] maximum 確保・出力前に照合する最大要素数。
	 * @param[in] transfer 子値を同じsinkへ移送する同期callback。引数の参照を呼出し後まで保持しない。
	 */
	template <class T, class F>
	void list( std::string_view key, std::vector<T> &values, std::size_t maximum, F transfer)
	{
		const auto raw = field( key) ;	// 子配列の元値。
		Array	   array{nullptr} ;		// 読込み時だけ元配列を借用。
		// 確保前に型と件数を確認します。
		if( raw) {
			require( raw.ValueType() == Type::Array) ;
			array = raw.GetArray() ;
			require( array.Size() <= maximum) ;
			values.resize( array.Size()) ;
		}

		require( values.size() <= maximum) ;
		writer_.append( "[") ;
		// 全要素を元順序で出力します。
		for( std::size_t index = 0; index < values.size(); ++index) {
			// 元順序のdelimiterだけを追加します。
			if( index) {
				writer_.append( ",") ;
			}

			transfer( writer_,
					 array ? array.GetAt( static_cast<std::uint32_t>( index)) : Value{nullptr},
					 values[index]) ;
		}

		writer_.append( "]") ;
	}

private:
	/// 全層で共有する有限sink。
	Writer &writer_ ;
	/// 読込み時だけ存在する有限object。
	Object	input_ ;
	/// 最初のfieldかどうか。
	bool	first_{true} ;
} ;

/**
 * @brief 固定理由の名前を明示移送します。
 * @param[in,out] fields 同じ有限sinkと読込みobjectを扱う移送context。
 * @param[in] key 固定schemaのASCII field名。同期呼出し中だけ借用する。
 * @param[in,out] reason 書込み元または保存理由の読込み先。未知名は拒否する。
 */
void reasonField( Fields &fields, std::string_view key, Reason &reason)
{
	fields.enumeration( key, reason,
					   {{Reason::NONE, L"NONE"},
						{Reason::SOURCE_INCOMPLETE, L"SOURCE_INCOMPLETE"},
						{Reason::NO_ELIGIBLE_RECORD, L"NO_ELIGIBLE_RECORD"},
						{Reason::NO_MATCHING_TARGET, L"NO_MATCHING_TARGET"},
						{Reason::DECREASED, L"DECREASED"},
						{Reason::PROJECTION_LIMIT, L"PROJECTION_LIMIT"},
						{Reason::WORKER_FAILURE, L"WORKER_FAILURE"},
						{Reason::CACHE_BASIS_INVALID, L"CACHE_BASIS_INVALID"},
						{Reason::METADATA_HASH, L"METADATA_HASH"}}) ;
}
/**
 * @brief Error domainを既存列挙名に結合します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] domain 書込み時の元分類。読込み時は検証した保存値へ更新します。
 */
void domainField( Fields &fields, CollectorIoErrorDomain &domain)
{
	using D = CollectorIoErrorDomain ;
	fields.enumeration( "domain", domain,
					   {{D::NONE, L"NONE"},
						{D::WIN32_ERROR, L"WIN32_ERROR"},
						{D::WINSOCK_ERROR, L"WINSOCK_ERROR"},
						{D::HRESULT_ERROR, L"HRESULT_ERROR"},
						{D::HTTP, L"HTTP"},
						{D::PARSER, L"PARSER"}}) ;
}
/**
 * @brief Array内objectを同じ有限sinkへ移送します。
 * @tparam T 子objectの所有値型。
 * @tparam F 同じsinkへの同期移送callback型。
 * @param[in,out] writer 呼出し中だけ借用する有限sink。例外時は途中までの出力を保持する。
 * @param[in] raw 読込み時の元JSON値の共有参照。nullは書込みだけを行う。
 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
 * @param[in] transfer 子値を同じsinkへ移送する同期callback。引数の参照を呼出し後まで保持しない。
 */
template <class T, class F> void element( Writer &writer, Value raw, T &value, F transfer)
{
	require( !raw || raw.ValueType() == Type::Object) ;
	Fields child( writer, raw ? raw.GetObject() : Object{nullptr}) ;	// 同じsink上の子object。
	transfer( child, value) ;
	child.end() ;
}
/**
 * @brief Fingerprintの元32 byteを小文字hexとして保持します。
 * @param[in] fingerprint 全32 byteを保持する元指紋。同期中だけ借用する。
 * @return 元byteと同順の64桁小文字hexを所有して返す。
 */
std::wstring fingerprintText( const OfficialStableRecordFingerprint &fingerprint)
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 内部指紋の固定表記。
	std::wstring				value ;						// 有限64文字の出力。
	value.reserve( 64U) ;
	// 元byteを変更せず二桁ずつ出力します。
	for( const auto byte : fingerprint.bytes) {
		value.push_back( HEX[std::to_integer<unsigned>( byte) >> 4U]) ;
		value.push_back( HEX[std::to_integer<unsigned>( byte) & 15U]) ;
	}

	return value ;
}
/**
 * @brief 小文字hexからだけ元指紋を復元します。
 * @param[in] value 64桁小文字hexの借用view。入力形式を検査してから復元する。
 * @param[out] fingerprint 形式検査成功後に全32 byteを設定する。形式拒否時は変更しない。
 * @throws Failure 入力が固定hash表記ではない場合。
 */
void parseFingerprint( std::wstring_view value, OfficialStableRecordFingerprint &fingerprint)
{
	require( isHash( value)) ;
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 有限変換表。
	// 全32 byteの各二桁を消費します。
	for( std::size_t index = 0; index < fingerprint.bytes.size(); ++index) {
		fingerprint.bytes[index] = static_cast<std::byte>( HEX.find( value[index * 2U]) * 16U +
														  HEX.find( value[index * 2U + 1U])) ;
	}
}
/**
 * @brief 配列の公開文字列要素を有限移送します。
 * @param[in,out] writer 呼出し中だけ借用する有限sink。例外時は途中までの出力を保持する。
 * @param[in] raw 読込み時の元JSON値の共有参照。nullは書込みだけを行う。
 * @param[in,out] value 書込み時の元値。読込み時は保存値へ更新する。例外時は途中の値を保持する。
 */
void textElement( Writer &writer, Value raw, std::wstring &value)
{
	// 保存要素を文字列に限定します。
	if( raw) {
		require( raw.ValueType() == Type::String) ;
		value = raw.GetString() ;
	}

	require( value.size() <= 256U) ;
	writer.wideText( value) ;
}
/**
 * @brief Payloadの九公開値と検証観測を固定順に移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] payload 書込み時の元payload。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void payloadFields( Fields &fields, CollectorProjectedPayload &payload)
{
	auto &value = payload.value ;	// 検査済み公開fieldの所有値。
	fields.text( "resourceId", value.resourceId, 64U) ;
	fields.number( "payloadOrdinal", value.payloadOrdinal) ;
	fields.enumeration(
		"kind", value.kind,
		{{OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE, L"STANDARD_INF_PACKAGE"}}) ;
	fields.text( "fileDisplayName", value.fileDisplayName, 260U) ;
	fields.optionalNumber( "publishedSizeBytes", value.publishedSizeBytes) ;
	fields.text( "publishedSha256", value.publishedSha256, 64U) ;
	fields.text( "publishedSha512", value.publishedSha512, 128U) ;
	fields.text( "publisher", value.publisher, 512U) ;
	fields.text( "expectedContentType", value.expectedContentType, 128U) ;
	fields.boolean( "payloadLinkValidated", payload.payloadLinkValidated) ;
}
/**
 * @brief Recordを一payload配列に限定して移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] record 書込み時の元record。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void recordFields( Fields &fields, CollectorProjectedRecord &record)
{
	auto		&value		 = record.value ;								// 元の公開record。
	std::wstring fingerprint = fingerprintText( value.stableFingerprint) ;	// 元指紋の表記。
	fields.text( "slice", record.sliceKey, 256U) ;
	fields.text( "fingerprint", fingerprint, 64U) ;
	parseFingerprint( fingerprint, value.stableFingerprint) ;
	fields.text( "parserId", value.parserId, 64U) ;
	fields.number( "parserRevision", value.parserRevision) ;
	fields.text( "recordRoute", value.recordRoute, 256U) ;
	fields.text( "recordKey", value.recordKey, 256U) ;
	fields.text( "productFamily", value.productFamily) ;
	fields.text( "driverCategory", value.driverCategory) ;
	fields.text( "operatingSystem", value.operatingSystem) ;
	fields.enumeration( "architecture", value.architecture,
					   {{OfficialDistributionArchitecture::WINDOWS_X64, L"WINDOWS_X64"}}) ;
	fields.text( "packageVersion", value.packageVersion) ;
	fields.text( "publishedDate", value.publishedDate) ;
	fields.enumeration( "terms", value.terms,
					   {{OfficialDistributionTerms::CONFIRMED_NO_CONSENT, L"CONFIRMED_NO_CONSENT"},
						{OfficialDistributionTerms::ACCEPTANCE_REQUIRED, L"ACCEPTANCE_REQUIRED"}}) ;
	fields.text( "eulaRevision", value.eulaRevision, 256U) ;
	fields.list( "dependencies", value.dependencies, 32U, textElement) ;
	fields.list( "payloads", record.payloads, 1U,
				[]( Writer &writer, Value raw, CollectorProjectedPayload &payload) {
					element( writer, raw, payload, payloadFields) ;
				}) ;
	// 保存上の一配列からだけ二つ目を構成します。書込み前の差は別validatorで拒否します。
	if( fields.reading()) {
		value.payloads.clear() ;
		// 元順序と九fieldを同じ所有値から構成します。
		for( const auto &payload : record.payloads) {
			value.payloads.push_back( payload.value) ;
		}
	}
}
/**
 * @brief Sliceと最終採否を固定順に移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] slice 書込み時の元slice。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void sliceFields( Fields &fields, CollectorMetadataSlice &slice)
{
	fields.text( "key", slice.scope.key, 256U) ;
	fields.text( "category", slice.scope.category) ;
	fields.text( "purpose", slice.scope.purpose) ;
	fields.text( "operatingSystem", slice.scope.operatingSystem) ;
	fields.text( "architecture", slice.scope.architecture) ;
	fields.enumeration( "disposition", slice.disposition,
					   {{Disposition::ACCEPTED, L"ACCEPTED"}, {Disposition::HELD, L"HELD"}}) ;
	reasonField( fields, "reason", slice.reason) ;
	fields.boolean( "complete", slice.complete) ;
}
/**
 * @brief 元targetの全fieldを省略せず移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] target 書込み時の元target。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void targetFields( Fields &fields, CollectorProjectedTargetScope &target)
{
	fields.number( "index", target.index) ;
	fields.text( "id", target.target.id, 256U) ;
	fields.text( "maker", target.target.maker) ;
	fields.text( "model", target.target.model) ;
	fields.text( "kind", target.target.kind) ;
	fields.text( "purpose", target.target.purpose) ;
	fields.text( "operatingSystem", target.operatingSystem) ;
	fields.text( "architecture", target.architecture) ;
	fields.text( "chip", target.chip) ;
}
/**
 * @brief 全対象edgeと順序固定参照を移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] edge 書込み時の元edge。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void edgeFields( Fields &fields, CollectorProjectedEdge &edge)
{
	fields.object( "target", edge.target, targetFields) ;
	fields.text( "slice", edge.sliceKey, 256U) ;
	fields.text( "body", edge.bodySha256, 64U) ;
	fields.text( "recordParser", edge.recordParser, 256U) ;
	fields.text( "identityParser", edge.identityParser, 256U) ;
	fields.text( "matchingRule", edge.matchingRule, 256U) ;
	fields.enumeration(
		"state", edge.state,
		{{State::MATCH, L"MATCH"}, {State::NO_MATCH, L"NO_MATCH"}, {State::UNKNOWN, L"UNKNOWN"}}) ;
	fields.number( "reasonCode", edge.reasonCode) ;
	fields.optionalText( "sourceProductId", edge.sourceProductId) ;
	fields.optionalText( "sourceDisplayName", edge.sourceDisplayName) ;
	fields.optionalText( "sourceComparisonName", edge.sourceComparisonName) ;
	fields.list( "recordFingerprints", edge.recordFingerprints, 16U,
				[]( Writer &writer, Value raw, OfficialStableRecordFingerprint &fingerprint) {
					std::wstring value = fingerprintText( fingerprint) ;	// 元32 byteの表記。
					textElement( writer, raw, value) ;
					parseFingerprint( value, fingerprint) ;
				}) ;
}
/**
 * @brief Parserの元状態とerrorを移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] parser 書込み時の元診断。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void parserFields( Fields &fields, CollectorParserResult &parser)
{
	using P = CollectorParserStatus ;
	fields.enumeration( "status", parser.status,
					   {{P::COMPLETED, L"COMPLETED"},
						{P::REJECTED, L"REJECTED"},
						{P::LIMIT_EXCEEDED, L"LIMIT_EXCEEDED"},
						{P::STOPPED, L"STOPPED"},
						{P::FAILED, L"FAILED"}}) ;
	fields.object( "error", parser.error, []( Fields &child, CollectorIoError &error) {
		using S = CollectorIoStage ;
		domainField( child, error.domain) ;
		child.number( "code", error.code) ;
		child.enumeration( "stage", error.stage,
						  {{S::RESERVATION, L"RESERVATION"},
						   {S::SETUP, L"SETUP"},
						   {S::DNS, L"DNS"},
						   {S::OPEN, L"OPEN"},
						   {S::SEND, L"SEND"},
						   {S::RECEIVE, L"RECEIVE"},
						   {S::HEADERS, L"HEADERS"},
						   {S::QUERY, L"QUERY"},
						   {S::READ, L"READ"},
						   {S::DECODE, L"DECODE"},
						   {S::HASH, L"HASH"},
						   {S::PARSE, L"PARSE"},
						   {S::PROJECT, L"PROJECT"},
						   {S::CLEANUP, L"CLEANUP"},
						   {S::COMPLETE, L"COMPLETE"}}) ;
	}) ;
}
/**
 * @brief Source別数値診断を固定順で移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] source 書込み時の元診断。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void sourceFields( Fields &fields, CollectorMetadataSource &source)
{
	fields.number( "status", source.status) ;
	fields.number( "seen", source.seen) ;
	std::vector<std::uint32_t> counts( source.reasonCounts.begin(),
									  // 固定六要素。
									  source.reasonCounts.end()) ;
	fields.list( "reasonCounts", counts, 6U, []( Writer &writer, Value raw, std::uint32_t &value) {
		// 元数値の範囲と整数性を確認します。
		if( raw) {
			require( raw.ValueType() == Type::Number) ;
			const double numeric = raw.GetNumber() ;	// 元数値。
			require( numeric >= 0 && numeric <= UINT32_MAX) ;
			value = static_cast<std::uint32_t>( numeric) ;
			require( numeric == value) ;
		}

		writer.number( value) ;
	}) ;
	require( counts.size() == source.reasonCounts.size()) ;
	std::copy( counts.begin(), counts.end(), source.reasonCounts.begin()) ;
	fields.number( "duplicates", source.duplicates) ;
	fields.number( "rejected", source.rejected) ;
	fields.number( "collisions", source.collisions) ;
}

/**
 * @brief 全schema fieldを一つの固定順で移送します。
 * @param[in,out] fields 同期中だけ借用する読込み・書込み状態。例外時は途中の状態を保持します。
 * @param[in,out] document 書込み時の元全体値。読込み時は保存値へ更新し、例外時は途中の値を保持します。
 */
void documentFields( Fields &fields, CollectorMetadataDocument &document)
{
	fields.constant( "schema", L"collector-metadata-projection-v1") ;
	fields.constant( "profile", L"METADATA_PROJECTION_V1") ;
	fields.enumeration( "form", document.form,
					   {{Form::FULL, L"FULL"}, {Form::MINIMAL_FAILURE, L"MINIMAL_FAILURE"}}) ;
	fields.enumeration( "outcome", document.outcome,
					   {{Outcome::FETCHED, L"FETCHED"},
						{Outcome::HELD, L"HELD"},
						{Outcome::FAILED, L"FAILED"},
						{Outcome::REVALIDATED, L"REVALIDATED"}}) ;
	reasonField( fields, "reason", document.reason) ;
	fields.boolean( "complete", document.complete) ;
	fields.boolean( "researchOnly", document.researchOnly) ;
	fields.boolean( "publishable", document.publishable) ;
	fields.boolean( "downloadEligible", document.downloadEligible) ;
	fields.object( "binding", document.binding,
				  []( Fields &child, CollectorMetadataBinding &binding) {
					  child.text( "source", binding.source, 256U) ;
					  child.text( "provider", binding.provider, 256U) ;
					  child.text( "policy", binding.policy, 256U) ;
					  child.text( "resource", binding.resource, 256U) ;
					  child.text( "scope", binding.scope, 64U) ;
					  child.text( "cache", binding.cache, 64U) ;
					  child.text( "body", binding.body, 64U) ;
					  child.optionalNumber( "validatedUtc", binding.validatedUtc) ;
				  }) ;
	fields.list( "records", document.records, 16U,
				[]( Writer &writer, Value raw, CollectorProjectedRecord &record) {
					element( writer, raw, record, recordFields) ;
				}) ;
	fields.list( "slices", document.slices, 16U,
				[]( Writer &writer, Value raw, CollectorMetadataSlice &slice) {
					element( writer, raw, slice, sliceFields) ;
				}) ;
	fields.list( "edges", document.edges, 3000U,
				[]( Writer &writer, Value raw, CollectorProjectedEdge &edge) {
					element( writer, raw, edge, edgeFields) ;
				}) ;
	fields.object( "diagnostics", document.diagnostics,
				  []( Fields &child, CollectorMetadataDiagnostics &diagnostics) {
					  using W = CollectorProjectedWorkerReason ;
					  child.enumeration( "workerReason", diagnostics.workerReason,
										{{W::NONE, L"NONE"},
										 {W::PROJECTION_LIMIT, L"PROJECTION_LIMIT"},
										 {W::IO_FAILURE, L"IO_FAILURE"}}) ;
					  child.optional( "parser", diagnostics.parser, parserFields) ;
					  child.optional( "source", diagnostics.source, sourceFields) ;
					  child.optional( "counts", diagnostics.counts,
									 []( Fields &values, CollectorMetadataCounts &counts) {
										 values.number( "records", counts.records) ;
										 values.number( "payloads", counts.payloads) ;
										 values.number( "slices", counts.slices) ;
										 values.number( "edges", counts.edges) ;
										 values.number( "maximumReferences",
													   counts.maximumReferences) ;
									 }) ;
					  child.enumeration( "limitStage", diagnostics.limitStage,
										{{Limit::NONE, L"NONE"},
										 {Limit::WORKER, L"WORKER"},
										 {Limit::COUNTS, L"COUNTS"},
										 {Limit::METADATA_BYTES, L"METADATA_BYTES"},
										 {Limit::RESPONSE_BYTES, L"RESPONSE_BYTES"},
										 {Limit::ENVELOPE_BYTES, L"ENVELOPE_BYTES"}}) ;
				  }) ;
	fields.optional( "error", document.error, []( Fields &child, CollectorMetadataError &error) {
		child.enumeration( "phase", error.phase,
						  {{Phase::WORKER, L"WORKER"},
						   {Phase::CACHE_BASIS, L"CACHE_BASIS"},
						   {Phase::METADATA_HASH, L"METADATA_HASH"}}) ;
		domainField( child, error.domain) ;
		child.number( "code", error.code) ;
	}) ;
}

/**
 * @brief 公開fieldを旧短文字数と新byte予算の両方へ照合します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @param[in] bytes UTF-8へ変換した後の最大byte数。
 * @param[in] characters 変換前に確認する最大UTF-16 code unit数。
 * @param[in] kind 共通公開文字列policyで使用するfieldの用途。
 */
void publicText( std::wstring_view value, std::size_t bytes = 1024U, std::size_t characters = 4096U,
				OfficialCollectorPublicTextKind kind = OfficialCollectorPublicTextKind::TEXT)
{
	require( value.size() <= characters && isOfficialCollectorPublicText( value, bytes, kind)) ;
}
/**
 * @brief 元公開digestの大小文字を保持してhex桁数だけを検査します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @param[in] length 許可するhex文字数。大文字と小文字は変更しない。
 * @return 指定桁数のASCII hexだけならtrue。それ以外はfalse。
 */
bool publicHash( std::wstring_view value, std::size_t length)
{
	return value.size() == length && std::all_of( value.begin(), value.end(), []( wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'a' && character <= L'f') ||
					  (character >= L'A' && character <= L'F') ;
		   }) ;
}
/**
 * @brief Payloadの全九fieldが元順序で同値か検査します。
 * @param[in] left 比較する先行の公開値。同期中だけ借用する。
 * @param[in] right 比較する後続の公開値。同期中だけ借用する。
 * @return 対象の全公開fieldと要素順序が一致する場合true。差がある場合false。
 */
bool samePayload( const OfficialCollectorPayloadProjection &left,
				 const OfficialCollectorPayloadProjection &right)
{
	return left.resourceId == right.resourceId && left.payloadOrdinal == right.payloadOrdinal &&
		   left.kind == right.kind && left.fileDisplayName == right.fileDisplayName &&
		   left.publishedSizeBytes == right.publishedSizeBytes &&
		   left.publishedSha256 == right.publishedSha256 &&
		   left.publishedSha512 == right.publishedSha512 && left.publisher == right.publisher &&
		   left.expectedContentType == right.expectedContentType ;
}
/**
 * @brief 元sliceの全公開fieldとkeyを比較します。
 * @param[in] left 比較する先行の公開値。同期中だけ借用する。
 * @param[in] right 比較する後続の公開値。同期中だけ借用する。
 * @return 対象の全公開fieldと要素順序が一致する場合true。差がある場合false。
 */
bool sameSlice( const CollectorProjectedSliceScope &left, const CollectorProjectedSliceScope &right)
{
	return left.key == right.key && left.category == right.category &&
		   left.purpose == right.purpose && left.operatingSystem == right.operatingSystem &&
		   left.architecture == right.architecture ;
}
/**
 * @brief 元対象のindexを含む全fieldを比較します。
 * @param[in] left 比較する先行の公開値。同期中だけ借用する。
 * @param[in] right 比較する後続の公開値。同期中だけ借用する。
 * @return 対象の全公開fieldと要素順序が一致する場合true。差がある場合false。
 */
bool sameTarget( const CollectorProjectedTargetScope &left,
				const CollectorProjectedTargetScope &right)
{
	return left.index == right.index && left.target.id == right.target.id &&
		   left.target.maker == right.target.maker && left.target.model == right.target.model &&
		   left.target.kind == right.target.kind && left.target.purpose == right.target.purpose &&
		   left.operatingSystem == right.operatingSystem &&
		   left.architecture == right.architecture && left.chip == right.chip ;
}
/**
 * @brief Recordと一payloadを初期source契約へ照合します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] record Scopeとpayload条件を検査する元record。
 * @param[in] asus ASUS固有のschema・理由対応を選ぶ場合true。falseはIntelの対応を使う。
 */
void validateRecord( const CollectorProjectedJobInput &job, const CollectorProjectedRecord &record,
					bool asus)
{
	require( job.publicLocator.size() <= 256U) ;
	const auto &value = record.value ;	// 元公開record。
	require( record.sliceKey == job.slices.front().key && value.payloads.size() == 1U &&
			record.payloads.size() == 1U) ;
	publicText( value.parserId, 256U, 64U) ;
	publicText( value.recordRoute, 256U, 256U) ;
	publicText( value.recordKey, 256U, 512U) ;
	publicText( value.productFamily) ;
	publicText( value.driverCategory) ;
	publicText( value.operatingSystem) ;
	publicText( value.packageVersion) ;
	publicText( value.publishedDate, 1024U, 4096U, OfficialCollectorPublicTextKind::DATE) ;
	publicText( value.eulaRevision, 256U, 4096U) ;
	require( value.architecture == OfficialDistributionArchitecture::WINDOWS_X64 &&
			value.dependencies.size() <= 32U) ;
	// 全依存keyを元順序のまま検査します。
	for( const auto &dependency : value.dependencies) {
		publicText( dependency, 256U, 512U) ;
	}

	const auto &payload = value.payloads.front() ;	// 二配列を比較する元公開payload。
	require( samePayload( payload, record.payloads.front().value) &&
			record.payloads.front().payloadLinkValidated) ;
	publicText( payload.resourceId, 256U, 64U) ;
	publicText( payload.fileDisplayName, 1024U, 260U) ;
	publicText( payload.publisher, 1024U, 512U) ;
	publicText( payload.expectedContentType, 1024U, 128U,
			   OfficialCollectorPublicTextKind::CONTENT_TYPE) ;
	require( payload.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID && payload.payloadOrdinal == 0U &&
			payload.kind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE &&
			payload.fileDisplayName.size() > 4U && payload.fileDisplayName.ends_with( L".zip") &&
			payload.expectedContentType == L"application/zip" &&
			(asus ? publicHash( payload.publishedSha256, 64U)
				  : (!payload.publishedSha256.empty() || !payload.publishedSha512.empty()) &&
						(payload.publishedSha256.empty() ||
						 publicHash( payload.publishedSha256, 64U))) &&
			(payload.publishedSha512.empty() || publicHash( payload.publishedSha512, 128U)) &&
			(!payload.publishedSizeBytes ||
			 (*payload.publishedSizeBytes > 0U &&
			  *payload.publishedSizeBytes <= 128ULL * 1024ULL * 1024ULL))) ;
	// Sourceごとの固定公開fieldを元adapter契約に結合します。
	if( asus) {
		require( !value.productFamily.empty() && value.productFamily.size() <= 512U &&
				!value.packageVersion.empty() && value.packageVersion.size() <= 512U) ;
		const std::wstring prefix =
			job.publicLocator + L"|" ;	// 元modelを省略しないrecord key prefix。
		require( value.parserId == L"asus-catalog-record-v1" && value.parserRevision == 1U &&
				value.recordRoute == L"asus-support-catalog-zip" &&
				value.recordKey.starts_with( prefix) && value.recordKey.size() > prefix.size() &&
				value.driverCategory == L"LAN" && value.operatingSystem == L"Windows 11 64-bit" &&
				value.terms == OfficialDistributionTerms::CONFIRMED_NO_CONSENT &&
				value.eulaRevision.empty()) ;
	} else {
		require( value.parserId == INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_ID &&
				value.parserRevision == INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION &&
				value.recordRoute == L"intel-download-record" && value.recordKey == L"727998" &&
				value.productFamily == L"Intel Ethernet Network Adapters" &&
				value.driverCategory.empty() && value.operatingSystem == L"Microsoft Windows 11" &&
				value.terms == OfficialDistributionTerms::ACCEPTANCE_REQUIRED &&
				!value.eulaRevision.empty() && !value.packageVersion.empty() &&
				value.packageVersion.size() <= 64U && value.publishedDate.size() <= 128U &&
				payload.fileDisplayName == L"Wired_driver_" + value.packageVersion + L"_x64.zip") ;
	}
}
/**
 * @brief Source診断の元enum集合と件数関係を検査します。
 * @param[in] source 元enum、件数、HTTP診断の関係を検査するsource値。
 * @param[in] asus ASUS固有のschema・理由対応を選ぶ場合true。falseはIntelの対応を使う。
 */
void validateSource( const CollectorMetadataSource &source, bool asus)
{
	// 初期ASUS正常配列にschema拒否・limitを許しません。
	if( asus) {
		require( source.status <= 7U && source.status != 5U && source.status != 6U &&
				source.duplicates == 0U && source.rejected == 0U && source.collisions == 0U) ;
		return ;
	}

	require( source.status <= 3U && source.seen <= 1024U && source.duplicates <= source.seen &&
			source.rejected <= source.seen && source.collisions <= source.seen &&
			static_cast<std::uint64_t>( source.duplicates) + source.rejected + source.collisions <=
				source.seen &&
			std::all_of( source.reasonCounts.begin(), source.reasonCounts.end(),
						[]( auto count) { return count == 0U ; })) ;
}
/**
 * @brief 数値理由をsource別三状態へ明示対応します。
 * @param[in] reason 元sourceが返した数値理由。未知値は検査例外で拒否する。
 * @param[in] asus ASUS固有のschema・理由対応を選ぶ場合true。falseはIntelの対応を使う。
 * @return 許可した理由へ明示対応する対象状態。
 */
State expectedState( std::uint32_t reason, bool asus)
{
	require( reason <= (asus ? 11U : 13U)) ;
	// 両sourceともMATCHEDだけが一致です。
	if( reason == 0U) {
		return State::MATCH ;
	}

	// 既知の矛盾だけをNO_MATCHにします。
	if( asus ? (reason == 3U || reason == 4U || reason == 6U || reason == 8U)
			: (reason == 4U || reason == 7U || reason == 9U || reason == 11U)) {
		return State::NO_MATCH ;
	}

	return State::UNKNOWN ;
}
/**
 * @brief Source identityの三optionalと元比較規則を照合します。
 * @param[in] edge 公開identityと元比較規則を検査する参照edge。
 * @param[in] asus ASUS固有のschema・理由対応を選ぶ場合true。falseはIntelの対応を使う。
 */
void validateIdentity( const CollectorProjectedEdge &edge, bool asus)
{
	require( edge.sourceProductId.has_value() == edge.sourceDisplayName.has_value() &&
			edge.sourceProductId.has_value() == edge.sourceComparisonName.has_value()) ;
	// 同時欠測はUNKNOWN等の元観測として保持します。
	if( !edge.sourceProductId) {
		require( edge.state != State::MATCH) ;
		return ;
	}

	publicText( *edge.sourceProductId, 256U, 256U) ;
	publicText( *edge.sourceDisplayName) ;
	publicText( *edge.sourceComparisonName) ;
	require( !edge.sourceProductId->empty() && !edge.sourceDisplayName->empty() &&
			!edge.sourceComparisonName->empty()) ;
	require( edge.sourceProductId->size() <= (asus ? 16U : 10U) &&
			edge.sourceProductId->front() != L'0') ;
	std::uint64_t productNumber = 0U ;	// 元sourceのcanonical十進ID。
	// 16桁以下の値をJSON整数上限内で照合します。
	for( const wchar_t digit : *edge.sourceProductId) {
		require( digit >= L'0' && digit <= L'9') ;
		productNumber = productNumber * 10U + static_cast<std::uint64_t>( digit - L'0') ;
		require( productNumber <= MAX_INTEGER) ;
	}

	// ASUSは公開された元の空白比較関数を使用します。
	if( asus) {
		require( edge.sourceDisplayName->size() <= 128U &&
				edge.sourceComparisonName->size() <= 128U) ;
		require( asusCollectorModelComparisonKey( *edge.sourceDisplayName) ==
				*edge.sourceComparisonName) ;
	} else {
		require( edge.sourceDisplayName->size() <= 256U &&
				edge.sourceComparisonName->size() <= 256U && edge.sourceProductId->size() <= 10U &&
				edge.sourceProductId->front() != L'0' &&
				std::all_of( edge.sourceProductId->begin(), edge.sourceProductId->end(),
							[]( wchar_t value) { return value >= L'0' && value <= L'9' ; })) ;
		wchar_t	  normalized[512]{} ;	// 元Intel比較と同じ有限NFC出力。
		const int length = NormalizeString( NormalizationC, edge.sourceDisplayName->data(),
										   static_cast<int>( edge.sourceDisplayName->size()),
										   normalized, 512) ;	// OSの正規化結果。
		// OSの確保失敗を不正保存値へ読み替えません。
		if( length <= 0) {
			const DWORD error = GetLastError() ;	// 元正規化APIの数値。
			// 固定bufferの検査でもlibrary側OOMは独立に伝播します。
			if( error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY) {
				throw std::bad_alloc{} ;
			}
		}

		require( length > 0 && length <= 256 &&
				std::wstring_view( normalized, static_cast<std::size_t>( length)) ==
					*edge.sourceComparisonName) ;
	}
}
/**
 * @brief Scope全体と全record参照を一行も省略せず検査します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] document 全record、slice、edgeの所属を検査する所有値。
 * @param[in] asus ASUS固有のschema・理由対応を選ぶ場合true。falseはIntelの対応を使う。
 */
void validateArrays( const CollectorProjectedJobInput &job,
					const CollectorMetadataDocument &document, bool asus)
{
	require( document.records.size() <= (asus ? 16U : 1U) && document.slices.size() == 1U &&
			sameSlice( document.slices.front().scope, job.slices.front()) &&
			document.edges.size() == job.targets.size()) ;
	// 重複指紋を同内容でも拒否します。
	for( std::size_t index = 0; index < document.records.size(); ++index) {
		validateRecord( job, document.records[index], asus) ;
		// 一つの指紋が複数の行を指すことを許しません。
		for( std::size_t prior = 0; prior < index; ++prior) {
			require( document.records[index].value.stableFingerprint.bytes !=
					document.records[prior].value.stableFingerprint.bytes) ;
		}
	}

	// 元対象順×初期一sliceの全edgeを検査します。
	for( std::size_t index = 0; index < document.edges.size(); ++index) {
		const auto &edge = document.edges[index] ;	// 元対象と同じ位置のedge。
		require( sameTarget( edge.target, job.targets[index]) &&
				edge.sliceKey == job.slices.front().key &&
				edge.bodySha256 == document.binding.body && edge.recordParser == job.recordParser &&
				edge.identityParser == job.identityParser &&
				edge.matchingRule == job.matchingRule &&
				edge.state == expectedState( edge.reasonCode, asus)) ;
		publicText( edge.target.target.id, 256U) ;
		publicText( edge.target.target.maker) ;
		publicText( edge.target.target.model) ;
		publicText( edge.target.target.kind) ;
		publicText( edge.target.target.purpose) ;
		publicText( edge.target.operatingSystem) ;
		publicText( edge.target.architecture) ;
		publicText( edge.target.chip) ;
		validateIdentity( edge, asus) ;
		const bool missingSource =
			asus && (edge.reasonCode == 1U || edge.reasonCode == 2U) ;	// 元ASUSの空参照分岐。
		require( edge.recordFingerprints.size() == (missingSource ? 0U : document.records.size())) ;
		// 元source欠測の分岐ではidentityも保持しません。
		if( missingSource) {
			require( !edge.sourceProductId) ;
		}

		// UNKNOWNを理由に参照の欠落や並べ替えを許しません。
		for( std::size_t ordinal = 0; ordinal < edge.recordFingerprints.size(); ++ordinal) {
			require( edge.recordFingerprints[ordinal].bytes ==
					document.records[ordinal].value.stableFingerprint.bytes) ;
		}

		require( edge.state != State::MATCH || !edge.recordFingerprints.empty()) ;
	}
}
/**
 * @brief 現配列からだけ診断件数を導きます。呼出し前に件数上限が必要です。
 * @param[in] document 配列上限を検査済みのmetadata。同期中だけ借用する。
 * @return 現在の配列とsource診断から計数した値。元入力は変更しない。
 */
CollectorMetadataCounts measuredCounts( const CollectorMetadataDocument &document)
{
	CollectorMetadataCounts counts ;	// 測定済みの0を含む実件数。
	counts.records = static_cast<std::uint32_t>( document.records.size()) ;
	counts.slices  = static_cast<std::uint32_t>( document.slices.size()) ;
	counts.edges   = static_cast<std::uint32_t>( document.edges.size()) ;
	// 全payloadをchecked上限内で合算します。
	for( const auto &record : document.records) {
		counts.payloads += static_cast<std::uint32_t>( record.payloads.size()) ;
	}

	// 最大値は全edgeの実参照から算出します。
	for( const auto &edge : document.edges) {
		counts.maximumReferences = (std::max)(
			counts.maximumReferences, static_cast<std::uint32_t>( edge.recordFingerprints.size())) ;
	}

	return counts ;
}
/**
 * @brief 正常200の固定理由を、親の減少判定以外から導きます。
 * @param[in] document 正常200の元source診断と候補配列。
 * @param[in] rawComplete 元sourceの完全性を確認できた場合true。
 * @return 完全性・適格record・照合対象の有無に対応する理由。
 */
Reason normalReason( const CollectorMetadataDocument &document, bool rawComplete)
{
	// 候補欠測を最優先に残します。
	if( document.records.empty()) {
		return Reason::NO_ELIGIBLE_RECORD ;
	}

	// 全対象に一致がない場合だけ対象欠測です。
	if( std::none_of( document.edges.begin(), document.edges.end(),
					[]( const auto &edge) { return edge.state == State::MATCH ; })) {
		return Reason::NO_MATCHING_TARGET ;
	}

	return rawComplete ? Reason::NONE : Reason::SOURCE_INCOMPLETE ;
}
/**
 * @brief 正常200の完全性を元source診断から導きます。
 * @param[in] document 元sourceの完了と件数診断。
 * @param[in] asus ASUS固有のschema・理由対応を選ぶ場合true。falseはIntelの対応を使う。
 * @return 当該sourceの全完全性条件を満たす場合true。不完全または矛盾時はfalse。
 */
bool rawComplete( const CollectorMetadataDocument &document, bool asus)
{
	return asus ? document.diagnostics.source->status == 7U
				: document.diagnostics.source->status == 0U && !document.records.empty() ;
}
/**
 * @brief 全fieldの意味関係を検査します。元HTTPや以前の成功は検査しません。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] document 全fieldの意味関係を検査するmetadata。元HTTPの実在を証明する値ではない。
 */
void validate( const CollectorProjectedJobInput &job, const CollectorMetadataDocument &document)
{
	const bool asus = job.source.sourceId == L"ASUS_CATALOG" ;	// 初期source分岐。
	require( asus || job.source.sourceId == L"INTEL_ETHERNET_WINDOWS11") ;
	require( job.slices.size() == 1U && !job.targets.empty() && job.targets.size() <= 3000U &&
			isHash( job.scopeSha256) && isHash( job.cacheBinding) && document.researchOnly &&
			!document.publishable && !document.downloadEligible) ;
	const auto &binding = document.binding ;	// 同じ元jobの全公開結合。
	require( binding.source == job.source.sourceId && binding.provider == job.providerId &&
			binding.policy == job.policyId && binding.resource == job.source.resourceId &&
			binding.scope == job.scopeSha256 && binding.cache == job.cacheBinding &&
			(binding.body.empty() || isHash( binding.body)) &&
			(!binding.validatedUtc ||
			 (*binding.validatedUtc > 0U && *binding.validatedUtc <= 253402300799999ULL))) ;
	publicText( binding.source, 256U) ;
	publicText( binding.provider, 256U) ;
	publicText( binding.policy, 256U) ;
	publicText( binding.resource, 256U) ;
	require( document.records.size() <= 16U && document.slices.size() <= 16U &&
			document.edges.size() <= 3000U) ;
	const auto &diagnostics = document.diagnostics ;	// 欠測を保持する元数値診断。
	// 正常source値が存在する場合は独立に有限集合を検査します。
	if( diagnostics.source) {
		validateSource( *diagnostics.source, asus) ;
	}

	// 実件数診断は汎用予算内でのみ保持します。
	if( diagnostics.counts) {
		const auto &counts = *diagnostics.counts ;	// 元測定件数。
		require( collector_projection_detail::withinCountLimits( counts.records, counts.payloads,
															   counts.slices, counts.edges,
															   counts.maximumReferences)) ;
	}

	// 元parserの成功・失敗と数値domainを独立照合します。
	if( diagnostics.parser) {
		const auto &parser = *diagnostics.parser ;	// 元parser観測。
		require( (parser.error.domain == CollectorIoErrorDomain::NONE) == (parser.error.code == 0U)) ;
		require( parser.status != CollectorParserStatus::COMPLETED || parser.error.code == 0U) ;
	}

	const bool empty = document.records.empty() && document.slices.empty() &&
					   // 消去形の共通条件。
					   document.edges.empty() ;
	// 失敗形は正常配列を持ちません。原I/Oとの一致は親入口の責任です。
	if( document.form == Form::MINIMAL_FAILURE) {
		require( document.outcome == Outcome::FAILED && !document.complete && empty &&
				document.error && diagnostics.limitStage == Limit::NONE) ;
		const auto &error = *document.error ;	// 元の固定失敗数値。
		require( error.domain != CollectorIoErrorDomain::NONE && error.code != 0U) ;
		// Worker失敗では消去済み診断を補いません。
		if( document.reason == Reason::WORKER_FAILURE) {
			require( error.phase == Phase::WORKER &&
					diagnostics.workerReason == CollectorProjectedWorkerReason::IO_FAILURE &&
					!binding.validatedUtc && !diagnostics.source && !diagnostics.counts) ;
		}
		// 元200の親検査拒否には固定数値だけを用います。
		else if( document.reason == Reason::CACHE_BASIS_INVALID) {
			require( error.phase == Phase::CACHE_BASIS &&
					error.domain == CollectorIoErrorDomain::PARSER && error.code == 1U &&
					diagnostics.workerReason == CollectorProjectedWorkerReason::NONE &&
					binding.body.empty() && !binding.validatedUtc && !diagnostics.source &&
					!diagnostics.counts) ;
		}
		// Hash障害は元HRESULTの失敗bitを保持します。
		else {
			require( document.reason == Reason::METADATA_HASH &&
					error.phase == Phase::METADATA_HASH &&
					error.domain == CollectorIoErrorDomain::HRESULT_ERROR &&
					(error.code & 0x80000000U) != 0U &&
					diagnostics.workerReason != CollectorProjectedWorkerReason::IO_FAILURE) ;
		}

		return ;
	}

	require( document.form == Form::FULL && !document.error) ;
	// 304形は元200根拠なしでは親受入できません。このcodecは形だけを検査します。
	if( document.outcome == Outcome::REVALIDATED) {
		require( document.reason == Reason::NONE && document.complete && empty &&
				binding.body.empty() && !binding.validatedUtc &&
				diagnostics.workerReason == CollectorProjectedWorkerReason::NONE &&
				!diagnostics.parser && !diagnostics.source && !diagnostics.counts &&
				diagnostics.limitStage == Limit::NONE) ;
		return ;
	}

	// 上限形を正常な空成功へ読み替えません。
	if( document.reason == Reason::PROJECTION_LIMIT) {
		require( document.outcome == Outcome::HELD && !document.complete && empty &&
				diagnostics.limitStage != Limit::NONE) ;
		// Worker消去済みならdiagnosticsを復元しません。
		if( diagnostics.limitStage == Limit::WORKER) {
			require( diagnostics.workerReason == CollectorProjectedWorkerReason::PROJECTION_LIMIT &&
					!binding.validatedUtc && !diagnostics.source && !diagnostics.counts &&
					diagnostics.parser &&
					diagnostics.parser->status == CollectorParserStatus::LIMIT_EXCEEDED) ;
		} else {
			require( diagnostics.workerReason == CollectorProjectedWorkerReason::NONE) ;
		}

		return ;
	}

	require( isHash( binding.body) && binding.validatedUtc && diagnostics.source &&
			diagnostics.counts && diagnostics.parser &&
			diagnostics.parser->status == CollectorParserStatus::COMPLETED &&
			diagnostics.workerReason == CollectorProjectedWorkerReason::NONE &&
			diagnostics.limitStage == Limit::NONE) ;
	validateArrays( job, document, asus) ;
	const auto	measured = measuredCounts( document) ;	// 元配列から独立算出。
	const auto &stored	 = *diagnostics.counts ;		// 保存された件数。
	require( measured.records == stored.records && measured.payloads == stored.payloads &&
			measured.slices == stored.slices && measured.edges == stored.edges &&
			measured.maximumReferences == stored.maximumReferences) ;
	const auto expectedReason =
		// 減少なしの元200理由。
		normalReason( document, rawComplete( document, asus)) ;
	const auto &slice	 = document.slices.front() ;	// 初期一slice。
	const bool	accepted = expectedReason == Reason::NONE ||
						  // 正常採用可否。
						  expectedReason == Reason::SOURCE_INCOMPLETE ;
	// 減少の根拠自体は以前の成功を持つ親だけが検証します。
	if( document.reason == Reason::DECREASED) {
		require( document.outcome == Outcome::HELD && !document.complete &&
				slice.disposition == Disposition::HELD && slice.reason == Reason::DECREASED &&
				!slice.complete) ;
	} else {
		require( document.reason == expectedReason &&
				document.outcome == (accepted ? Outcome::FETCHED : Outcome::HELD) &&
				document.complete == (accepted && rawComplete( document, asus)) &&
				slice.disposition == (accepted ? Disposition::ACCEPTED : Disposition::HELD) &&
				slice.reason == expectedReason && slice.complete == document.complete) ;
	}
}

/**
 * @brief Draftの文字列を複写する前に有限長へ制限します。意味検査は後続です。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] draft 複写前の公開draft。全対象の上限と各文字列長を検査する。
 */
void boundDraftBeforeCopy( const CollectorProjectedJobInput		 &job,
						  const CollectorMetadataProjectionDraft &draft)
{
	require( job.slices.size() == 1U && draft.slices.size() == 1U &&
			sameSlice( job.slices.front(), draft.slices.front())) ;
	// Bindingとsliceの元値に文字数上限を適用します。
	for( const std::wstring_view value :
		{std::wstring_view( draft.sourceId), std::wstring_view( draft.providerId),
		 std::wstring_view( draft.policyId), std::wstring_view( draft.resourceId),
		 std::wstring_view( draft.scopeSha256), std::wstring_view( draft.cacheBinding),
		 std::wstring_view( draft.bodySha256), std::wstring_view( draft.slices.front().key),
		 std::wstring_view( draft.slices.front().category),
		 std::wstring_view( draft.slices.front().purpose),
		 std::wstring_view( draft.slices.front().operatingSystem),
		 std::wstring_view( draft.slices.front().architecture)}) {
		require( value.size() <= 1024U) ;
	}

	// 九field照合と公開値検査は所有複写より先にも実施します。
	for( const auto &record : draft.records) {
		validateRecord( job, record, job.source.sourceId == L"ASUS_CATALOG") ;
	}

	// 全edgeの各文字列を複写前に制限します。
	for( const auto &edge : draft.edges) {
		// 元公開値の全fieldを有限長へ確認します。
		for( const std::wstring_view value :
			{std::wstring_view( edge.sliceKey), std::wstring_view( edge.bodySha256),
			 std::wstring_view( edge.recordParser), std::wstring_view( edge.identityParser),
			 std::wstring_view( edge.matchingRule), std::wstring_view( edge.target.target.id),
			 std::wstring_view( edge.target.target.maker),
			 std::wstring_view( edge.target.target.model),
			 std::wstring_view( edge.target.target.kind),
			 std::wstring_view( edge.target.target.purpose),
			 std::wstring_view( edge.target.operatingSystem),
			 std::wstring_view( edge.target.architecture), std::wstring_view( edge.target.chip)}) {
			require( value.size() <= 1024U) ;
		}

		require( (!edge.sourceProductId || edge.sourceProductId->size() <= 256U) &&
				(!edge.sourceDisplayName || edge.sourceDisplayName->size() <= 1024U) &&
				(!edge.sourceComparisonName || edge.sourceComparisonName->size() <= 1024U)) ;
	}
}

} // namespace

/** @see local_collector_metadata_codec.h */
Result makeCollectorMetadataDocument( const CollectorProjectedJobInput		&job,
									 const CollectorMetadataProjectionDraft &draft,
									 const CollectorParserResult			&parser,
									 CollectorMetadataDocument				&document) noexcept
{
	document = {} ;
	try {
		require(
			collector_projection_detail::checkCounts( draft.records, draft.slices, draft.edges) ==
				collector_projection_detail::CountResult::WITHIN_LIMIT &&
			draft.slices.size() == 1U &&
			draft.status != CollectorProjectionDraftStatus::MINIMAL_FAILURE &&
			parser.status == CollectorParserStatus::COMPLETED) ;
		boundDraftBeforeCopy( job, draft) ;
		CollectorMetadataDocument candidate ;	// 一度も保存されない検査候補。
		candidate.binding = {draft.sourceId,   draft.providerId,		draft.policyId,
							 draft.resourceId, draft.scopeSha256,		draft.cacheBinding,
							 draft.bodySha256, draft.validatedUtcMillis} ;
		candidate.records = draft.records ;
		candidate.edges	  = draft.edges ;
		candidate.slices.push_back( {draft.slices.front()}) ;
		candidate.diagnostics.parser = parser ;
		candidate.diagnostics.source = CollectorMetadataSource{
			draft.sourceStatus,		draft.sourceSeen,	  draft.sourceReasonCounts,
			draft.sourceDuplicates, draft.sourceRejected, draft.sourceCollisions} ;
		candidate.diagnostics.counts = measuredCounts( candidate) ;
		require( draft.complete == rawComplete( candidate, job.source.sourceId == L"ASUS_CATALOG")) ;
		candidate.reason	= normalReason( candidate, draft.complete) ;
		const bool accepted = candidate.reason == Reason::NONE ||
							  // 暫定採用。
							  candidate.reason == Reason::SOURCE_INCOMPLETE ;
		require( draft.status == (accepted ? CollectorProjectionDraftStatus::FETCHED
										  : CollectorProjectionDraftStatus::HELD)) ;
		candidate.outcome					 = accepted ? Outcome::FETCHED : Outcome::HELD ;
		candidate.complete					 = accepted && draft.complete ;
		candidate.slices.front().disposition = accepted ? Disposition::ACCEPTED : Disposition::HELD ;
		candidate.slices.front().reason		 = candidate.reason ;
		candidate.slices.front().complete	 = candidate.complete ;
		validate( job, candidate) ;
		document = std::move( candidate) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return currentFailure() ;
	}
}

/** @see local_collector_metadata_codec.h */
Result encodeCollectorMetadata( const CollectorProjectedJobInput &job,
							   const CollectorMetadataDocument	&document,
							   std::string						&bytes) noexcept
{
	bytes.clear() ;
	try {
		validate( job, document) ;
		CollectorMetadataDocument candidate =
			document ;						// 検査済み有限所有値。元入力を変更しません。
		Writer writer( METADATA_LIMIT) ;	// 追加前に検査する独立sink。
		Fields fields( writer) ;			// 固定schemaの出力。
		documentFields( fields, candidate) ;
		fields.end() ;
		bytes = writer.take() ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return currentFailure() ;
	}
}

/** @see local_collector_metadata_codec.h */
Result decodeCollectorMetadata( const CollectorProjectedJobInput &job, std::string_view bytes,
							   CollectorMetadataDocument &document) noexcept
{
	document = {} ;
	try {
		Reader preflight( bytes, METADATA_LIMIT) ;	// 確保なしのUTF-8／構文／深さ事前検査。
		static_cast<void>( preflight) ;
		const auto input =
			// 有限事前検査後だけtyped parse。
			Object::Parse( winrt::to_hstring( bytes)) ;
		CollectorMetadataDocument candidate ;				// 成功まで外部へ出さない値。
		Writer					  writer( METADATA_LIMIT) ;	// 元順序・表記の独立再符号化。
		Fields					  fields( writer, input) ;	// 同じschema writerを兼用する読込み。
		documentFields( fields, candidate) ;
		fields.end() ;
		validate( job, candidate) ;
		require( writer.view() == bytes) ;
		document = std::move( candidate) ;
		return {Status::OK, 0} ;
	} catch( ...) {
		return currentFailure() ;
	}
}

} // namespace drivercrate
