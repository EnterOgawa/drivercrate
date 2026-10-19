//------------------------------------------------------------------------------
/**
 * @file collector_parser_test_control.h
 * @brief 解析内checkpointごとの決定的停止・例外注入fixture。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  制御付きparserの障害fixtureを追加。
 * </pre>
 *
 * @note 実装や台帳を保持せず、呼出し中だけworker所有の制御を借用します。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/collector_parser_control.h"
#include "test_framework.h"

namespace drivercrate::test {

/** @brief Checkpointでだけ発生させる決定的な試験条件です。 */
enum class ParserTestFault {
	/// 障害なし。
	NONE,
	/// 取消し。
	CANCEL,
	/// 期限切れ。
	DEADLINE,
	/// C++の割当て例外。
	OOM,
	/// WinRTのOOM。
	HRESULT_OOM,
	/// WinRTの別原値。
	HRESULT_OTHER,
	/// 非標準例外。
	UNKNOWN
} ;

/** @brief 実通信・時計・global hookなしで同じ下位coreを検査します。 */
class ParserTestControl final : public OfficialCollectorHttpControl {
public:
	/// 注入するcheckpoint番号。0は注入なし。
	std::size_t			trigger{} ;
	/// 注入する事象。
	ParserTestFault		fault{ParserTestFault::NONE} ;
	/// 観測したcheckpoint数。
	std::size_t			calls{} ;
	/// 固定観測値。
	CollectorIoSnapshot observed{} ;

	/** @brief 指定した一回だけ停止または例外を発生させます。
	 * @param[in] stage 本番coreが指定した段階。
	 * @param[in] limit 正数のphase予算。
	 * @return 継続なら予算、中止なら0。
	 */
	std::uint32_t		begin( CollectorIoStage stage, std::uint32_t limit) override
	{
		++calls ;
		observed.stage = stage ;
		// 先着原因が確定した後は再開しません。
		if( observed.cause != CollectorIoCause::NONE) {
			return 0U ;
		}

		// 無障害の計測と、指定したcheckpoint以外は継続します。
		if( calls != trigger) {
			return limit ;
		}

		// OOMをlibrary失敗や有限上限と取り違えないことを検査します。
		if( fault == ParserTestFault::OOM) {
			throw std::bad_alloc{} ;
		}

		// WinRTの原HRESULTもそのまま維持されなければなりません。
		if( fault == ParserTestFault::HRESULT_OOM) {
			throw winrt::hresult_error( E_OUTOFMEMORY) ;
		}

		// OOM以外の原値が上書きされないことも確認します。
		if( fault == ParserTestFault::HRESULT_OTHER) {
			throw winrt::hresult_error( E_ACCESSDENIED) ;
		}

		// 未知例外の自由文を出力せずE_FAILに固定します。
		if( fault == ParserTestFault::UNKNOWN) {
			throw 7U ;
		}

		// 外部停止は解析拒否として登録しません。
		if( fault == ParserTestFault::CANCEL || fault == ParserTestFault::DEADLINE) {
			observed.cause		 = fault == ParserTestFault::CANCEL ? CollectorIoCause::CANCELLED
																	: CollectorIoCause::DEADLINE ;
			observed.error.stage = stage ;
			return 0U ;
		}

		return limit ;
	}
	/** @brief 実送信は行いません。 @return 常にtrue。 */
	bool noteSendCall() override
	{
		return true ;
	}
	/** @brief 実読取りは行いません。
	 * @param[in] requested 未使用要求量。
	 * @param[in] received 未使用取得量。
	 * @return 常にtrue。
	 */
	bool noteRead( std::uint32_t requested, std::uint32_t received) override
	{
		(void)requested ;
		(void)received ;
		return true ;
	}
	/** @brief 実headerはありません。 @return 常にtrue。 */
	bool noteHeaders() override
	{
		return true ;
	}
	/** @brief 第一原因を保持します。
	 * @param[in] cause 終了原因。
	 * @param[in] error 原数値。
	 * @param[in] bytesUnknown 未使用の本文欠測。
	 */
	void fail( CollectorIoCause cause, CollectorIoError error, bool bytesUnknown) override
	{
		(void)bytesUnknown ;
		// 同じcontrolの先着原因を置換しません。
		if( observed.cause == CollectorIoCause::NONE) {
			observed.cause = cause ;
			observed.error = error ;
		}
	}
	/** @brief 解放観測を更新します。 @param[in] released 解放状態。 */
	void setNativeReleased( bool released) override
	{
		observed.nativeReleased = released ;
	}
	/** @brief 固定観測を返します。 @return 整合した値。 */
	CollectorIoSnapshot snapshot() const override
	{
		return observed ;
	}
} ;

/** @brief 正常経路の全checkpointに取消し・例外を一回ずつ注入します。
 * @tparam Call 実coreを呼ぶ関数型。
 * @tparam Empty 出力が空であることの検査型。
 * @param[in,out] context Assertion集計。
 * @param[in] call 必須制御を受ける本番入口。
 * @param[in] empty 部分結果の持出しがないことの検査。
 * @param[in] stage 期待段階。
 */
template <class Call, class Empty>
void testParserCheckpoints( TestContext &context, Call call, Empty empty,
						   CollectorIoStage stage = CollectorIoStage::PARSE)
{
	ParserTestControl baseline ;	// 正常経路の到達checkpointを測ります。
	DRIVERCRATE_EXPECT( context, call( baseline).status == CollectorParserStatus::COMPLETED) ;
	DRIVERCRATE_EXPECT( context,
					   baseline.calls >= 3U && baseline.observed.cause == CollectorIoCause::NONE) ;
	// 途中の到達点を分母から省略しません。
	for( std::size_t point = 1U; point <= baseline.calls; ++point) {
		// C++ OOMとWinRT OOMを各下位catchに通して検査します。
		for( const auto fault : {ParserTestFault::CANCEL, ParserTestFault::DEADLINE,
								ParserTestFault::OOM, ParserTestFault::HRESULT_OOM,
								ParserTestFault::HRESULT_OTHER, ParserTestFault::UNKNOWN}) {
			ParserTestControl injected ;	// 一試行ごとに独立した第一原因。
			injected.trigger   = point ;
			injected.fault	   = fault ;
			const auto result  = call( injected) ;	// 実parserの型付き終了。
			const bool stopped = fault == ParserTestFault::CANCEL ||
								 // 外部停止の期待値。
								 fault == ParserTestFault::DEADLINE ;
			DRIVERCRATE_EXPECT( context, result.status == (stopped ? CollectorParserStatus::STOPPED
																  : CollectorParserStatus::FAILED)) ;
			DRIVERCRATE_EXPECT( context, empty() && !injected.observed.sealed) ;
			DRIVERCRATE_EXPECT( context, result.error.stage == stage) ;
			// 非停止の例外は原HRESULTとして保持します。
			if( !stopped) {
				const auto expected =
					fault == ParserTestFault::HRESULT_OTHER
						? E_ACCESSDENIED
						: (fault == ParserTestFault::UNKNOWN ? E_FAIL
															 : E_OUTOFMEMORY) ;	// 期待原値。
				DRIVERCRATE_EXPECT( context,
								   result.error.domain == CollectorIoErrorDomain::HRESULT_ERROR &&
									   result.error.code == static_cast<std::uint32_t>( expected)) ;
				DRIVERCRATE_EXPECT( context, injected.observed.cause == CollectorIoCause::PARSER) ;
			}
		}
	}
}
} // namespace drivercrate::test
