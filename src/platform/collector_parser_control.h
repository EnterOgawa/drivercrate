//------------------------------------------------------------------------------
/**
 * @file collector_parser_control.h
 * @brief 収集parserの明示制御と型付き終了の共通境界。
 * @version 01.00.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  解析内部の停止確認と失敗分類を追加。
 * </pre>
 *
 * @note 実装や台帳を保持せず、呼出し中だけworker所有の制御を借用します。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/official_collector_http_control.h"

#include <algorithm>
#include <cstddef>
#include <new>
#include <string_view>
#include <windows.h>
#include <winrt/base.h>

namespace drivercrate {

/** @brief 候補の適合性とは独立した解析手順の終了分類です。 */
enum class CollectorParserStatus {
	/// 全手順が完了しました。候補の存在やMATCHを保証しません。
	COMPLETED,
	/// 入力契約または全体構造を拒否しました。
	REJECTED,
	/// 明示された有限上限を超えました。
	LIMIT_EXCEEDED,
	/// 同じcontrolの停止を観測しました。
	STOPPED,
	/// OOMまたはlibrary/API障害です。
	FAILED
} ;

/** @brief URLや自由文を含まない終了値です。 */
struct CollectorParserResult {
	/// 解析手順の状態。
	CollectorParserStatus status{CollectorParserStatus::COMPLETED} ;
	/// 失敗の元数値。成功時はNONEです。
	CollectorIoError	  error ;
} ;

/** @brief 内部coreをunwindする固定値です。旧無制御経路へは投げません。 */
struct CollectorParserFailure {
	/// 原終了値。
	CollectorParserResult result ;
} ;

/** @brief Workerが所有する同じHTTP制御を同期呼出し中だけ借用します。 */
class CollectorParserContext {
public:
	/** @brief 必須参照と現在の段階を固定します。
	 * @param[in,out] control 元GETの制御。
	 * @param[in] stage PARSEまたはPROJECT。
	 */
	explicit CollectorParserContext( OfficialCollectorHttpControl &control,
									CollectorIoStage			  stage = CollectorIoStage::PARSE)
		: control_( control), stage_( stage)
	{
	}

	/** @brief 元期限と停止を確認し、中止時は所有値の公開前にunwindします。 */
	void checkpoint()
	{
		// Phaseの設定は元予約期限を更新しません。
		if( control_.begin( stage_, 60'000U) == 0U) {
			throw CollectorParserFailure{
				{CollectorParserStatus::STOPPED, control_.snapshot().error}} ;
		}

		work_ = 0U ;
	}

	/** @brief 内側走査の作業量を最大256単位で確認します。
	 * @param[in] units 文字数または比較数。飛び越える前の作業量。
	 */
	void step( std::size_t units = 1U)
	{
		// 巨大な単位指定も加算overflowを起こさず確認します。
		if( units >= 256U || work_ >= 256U - units) {
			checkpoint() ;
		} else {
			work_ += units ;
		}
	}

	/** @brief 原API失敗を保持した固定例外を発生させます。
	 * @param[in] domain 元数値のdomain。
	 * @param[in] code 元数値。
	 */
	[[noreturn]] void failed( CollectorIoErrorDomain domain, std::uint32_t code) const
	{
		throw CollectorParserFailure{{CollectorParserStatus::FAILED, {domain, code, stage_}}} ;
	}

	/** @brief 型付き終了を第一原因へ結合します。結果のsealは行いません。
	 * @param[in] result 解析手順の終了値。
	 * @return 先着停止を保った終了値。
	 */
	[[nodiscard]] CollectorParserResult finishStep( CollectorParserResult result)
	{
		// 中止以外の失敗だけを登録し、既存の第一原因を置換しません。
		if( result.status != CollectorParserStatus::COMPLETED &&
		   result.status != CollectorParserStatus::STOPPED) {
			control_.fail( CollectorIoCause::PARSER, result.error, false) ;
		}

		const auto snapshot = control_.snapshot() ;	// 第一原因の固定観測。
		// 他段階で確定済みの停止が解析結果より先ならそれを維持します。
		if( snapshot.cause != CollectorIoCause::NONE && snapshot.cause != CollectorIoCause::PARSER) {
			return {CollectorParserStatus::STOPPED, snapshot.error} ;
		}

		return result ;
	}

	/** @brief 現在の段階を返します。
	 * @return 初期化時の段階。
	 */
	[[nodiscard]] CollectorIoStage stage() const noexcept
	{
		return stage_ ;
	}

	/** @brief 下位の型付き入口へ同じ制御を借用させます。
	 * @return この同期呼出し中だけ有効な元HTTP制御。
	 */
	[[nodiscard]] OfficialCollectorHttpControl &httpControl() const noexcept
	{
		return control_ ;
	}

private:
	/// 呼出し元が寿命を保証する同一control。
	OfficialCollectorHttpControl &control_ ;
	/// このcoreの段階。
	CollectorIoStage			  stage_ ;
	/// 直前checkpointからの所有走査単位数。
	std::size_t					  work_{} ;
} ;

/** @brief 旧coreでは無操作、新coreでは明示制御を確認します。
 * @param[in,out] control 新経路のcontext。旧経路だけnull。
 */
inline void collectorParserCheckpoint( CollectorParserContext *control)
{
	// 旧public wrapperの動作を変更しません。
	if( control != nullptr) {
		control->checkpoint() ;
	}
}

/** @brief 内側の文字・比較走査を計数します。
 * @param[in,out] control 新経路のcontext。旧経路だけnull。
 * @param[in] units 今回進める有限単位数。
 */
inline void collectorParserStep( CollectorParserContext *control, std::size_t units = 1U)
{
	// 暗黙のglobal／thread-local制御を使いません。
	if( control != nullptr) {
		control->step( units) ;
	}
}

/** @brief 長い検索も256文字以下ごとの停止確認へ分割します。
 * @param[in,out] control 新経路のcontext。旧経路だけnull。
 * @param[in] text 有限本文。
 * @param[in] needle 固定検索文字列。
 * @param[in] start 検索開始。
 * @return 最初の位置。未検出はnpos。
 */
[[nodiscard]] inline std::size_t collectorParserFind( CollectorParserContext *control,
													 std::wstring_view		 text,
													 std::wstring_view		 needle,
													 std::size_t			 start = 0U)
{
	// 旧経路の標準検索と例外契約を維持します。
	if( control == nullptr) {
		return text.find( needle, start) ;
	}

	collectorParserCheckpoint( control) ;
	// 空needleと範囲外を標準検索と同じ意味にします。
	if( start > text.size() || needle.size() > text.size() - start) {
		return text.npos ;
	}

	// 所有scanは一文字ずつ進め、終端にも確認を置きます。
	for( std::size_t index = start; index <= text.size() - needle.size(); ++index) {
		collectorParserStep( control) ;
		// Needleは呼出し側の固定短文に限定します。
		if( text.substr( index, needle.size()) == needle) {
			collectorParserCheckpoint( control) ;
			return index ;
		}
	}

	collectorParserCheckpoint( control) ;
	return text.npos ;
}

/** @brief 一文字検索を同じ有限scanへ接続します。
 * @param[in,out] control 新経路のcontext。
 * @param[in] text 有限本文。
 * @param[in] needle 検索文字。
 * @param[in] start 検索開始。
 * @return 最初の位置またはnpos。
 */
[[nodiscard]] inline std::size_t collectorParserFind( CollectorParserContext *control,
													 std::wstring_view text, wchar_t needle,
													 std::size_t start = 0U)
{
	return collectorParserFind( control, text, std::wstring_view( &needle, 1U), start) ;
}

/** @brief 逆方向の固定marker検索を有限checkpointへ接続します。
 * @param[in,out] control 新経路のcontext。
 * @param[in] text 有限本文。
 * @param[in] needle 固定短文marker。
 * @param[in] start 最後に検索する位置。
 * @return 最後の一致位置またはnpos。
 */
[[nodiscard]] inline std::size_t collectorParserRfind( CollectorParserContext *control,
													  std::wstring_view		  text,
													  std::wstring_view		  needle,
													  std::size_t start = std::wstring_view::npos)
{
	// 旧経路は標準検索を維持します。
	if( control == nullptr) {
		return text.rfind( needle, start) ;
	}

	collectorParserCheckpoint( control) ;
	// 減算の範囲外を防ぎます。
	if( needle.size() > text.size()) {
		return text.npos ;
	}

	std::size_t index = (std::min)( start, text.size() - needle.size()) ;	// 最後の候補位置。
	// 0位置を一度だけ評価し、unsignedのunderflowを防ぎます。
	for( ;;) {
		collectorParserStep( control) ;
		// 固定markerの完全一致だけを返します。
		if( text.substr( index, needle.size()) == needle) {
			collectorParserCheckpoint( control) ;
			return index ;
		}

		// 先頭まで検査したら終了します。
		if( index == 0U) {
			break ;
		}

		--index ;
	}

	collectorParserCheckpoint( control) ;
	return text.npos ;
}

/** @brief 文字集合検索を内側の有限走査へ接続します。
 * @param[in,out] control 新経路のcontext。
 * @param[in] text 有限本文。
 * @param[in] characters 固定の短い文字集合。
 * @param[in] invert 集合外の文字を選ぶ場合true。
 * @param[in] reverse 末尾から探す場合true。
 * @param[in] start 開始位置。省略は方向に対応する端。
 * @return 最初の対象位置またはnpos。
 */
[[nodiscard]] inline std::size_t collectorParserFindSet( CollectorParserContext *control,
														std::wstring_view		text,
														std::wstring_view characters, bool invert,
														bool		reverse,
														std::size_t start = std::wstring_view::npos)
{
	collectorParserCheckpoint( control) ;
	// 空本文では減算を行いません。
	if( text.empty()) {
		return text.npos ;
	}

	std::size_t index = reverse ? (std::min)( start, text.size() - 1U)
								: (start == text.npos ? 0U : start) ;	// 方向に対応する有限cursor。
	// 自前の長い走査は256文字ごとに中断可能とします。
	while( index < text.size()) {
		collectorParserStep( control) ;
		const bool member = characters.find( text[index]) != characters.npos ;	// 短い固定集合。
		// 要求された内外一致だけを返します。
		if( member != invert) {
			collectorParserCheckpoint( control) ;
			return index ;
		}

		// 逆走査のunsigned underflowを防ぎます。
		if( reverse && index == 0U) {
			break ;
		}

		index = reverse ? index - 1U : index + 1U ;
	}

	collectorParserCheckpoint( control) ;
	return text.npos ;
}

/** @brief 解析の内部例外を型付き終了へ変換します。
 * @tparam Function 同じcontextを使用し、出力は成功後だけ公開するcore。
 * @param[in,out] control 元GETの必須制御参照。
 * @param[in] function 同期core。falseは構造拒否。
 * @param[in] stage 原失敗に保持する段階。
 * @return 固定終了値。HTTPのseal・cleanup・再送は行いません。
 */
template <class Function>
[[nodiscard]] CollectorParserResult runCollectorParser(
	OfficialCollectorHttpControl &control, Function function,
	CollectorIoStage stage = CollectorIoStage::PARSE)
{
	CollectorParserContext context( control, stage) ;	// 同じ期限の借用context。
	CollectorParserResult  result ;						// 例外本文は結果に保持しません。
	try {
		context.checkpoint() ;
		const bool accepted = function( context) ;	// 所有値の公開前にcore自身が確認します。
		context.checkpoint() ;
		// 候補なしと構造拒否はcoreの契約で区別します。
		if( !accepted) {
			result = {CollectorParserStatus::REJECTED, {CollectorIoErrorDomain::PARSER, 1U, stage}} ;
		}
	} catch( const CollectorParserFailure &failure) {
		result = failure.result ;
	} catch( const std::bad_alloc &) {
		result = {CollectorParserStatus::FAILED,
				  {CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( E_OUTOFMEMORY),
				   stage}} ;
	} catch( const winrt::hresult_error &failure) {
		result = {CollectorParserStatus::FAILED,
				  {CollectorIoErrorDomain::HRESULT_ERROR,
				   static_cast<std::uint32_t>( failure.code().value), stage}} ;
	} catch( ...) {
		result = {
			CollectorParserStatus::FAILED,
			{CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( E_FAIL), stage}} ;
	}

	return context.finishStep( result) ;
}

/** @brief 明示予算超過だけを型付きで中止します。
 * @param[in,out] control 新coreのcontext。旧coreでは無操作。
 */
inline void collectorParserLimit( CollectorParserContext *control)
{
	// 旧APIのfalse／source statusを維持するため新経路だけunwindします。
	if( control != nullptr) {
		throw CollectorParserFailure{{CollectorParserStatus::LIMIT_EXCEEDED,
									  {CollectorIoErrorDomain::PARSER, 2U, control->stage()}}} ;
	}
}
} // namespace drivercrate
