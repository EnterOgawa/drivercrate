//------------------------------------------------------------------------------
/**
 * @file test_framework.h
 * @brief 単体試験framework定義。
 * @version 01.00.00
 * @date 2026/09/01
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 外部test frameworkに依存しない最小のassertion helperを定義します。
 */
//------------------------------------------------------------------------------

#pragma once

#include <iostream>
#include <string_view>

namespace drivercrate::test {

//------------------------------------------------------------------------------
// Assertion集計型定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つの test process 内の assertion 件数と失敗件数を集計する。
 */
class TestContext final {
public:
	/**
     * @brief 条件を検証し、失敗時に source 位置を表示する。
     * @param[in] condition 成功と期待する条件。
     * @param[in] expression 呼出し側の条件式文字列。
     * @param[in] file 条件式の source file。
     * @param[in] line 条件式の source line。
     */
	//------------------------------------------------------------------------------
	void expect( const bool condition, const std::string_view expression, const char *file,
				const int line)
	{
		++assertionCount_ ;
		// 期待条件の失敗だけを集計し、原因を特定できるsource位置と式を出力する。
		if( !condition) {
			++failureCount_ ;
			std::cerr << file << ':' << line << ": expectation failed: " << expression << '\n' ;
		}
	}

	/**
     * @brief 実行済み assertion 件数を返す。
     * @return assertion 件数。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] int assertionCount() const noexcept
	{
		return assertionCount_ ;
	}

	/**
     * @brief 失敗 assertion 件数を返す。
     * @return failure 件数。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] int failureCount() const noexcept
	{
		return failureCount_ ;
	}

private:
	/// 実行済みexpect呼出し数。
	int assertionCount_{} ;
	/// 条件がfalseだったexpect呼出し数。
	int failureCount_{} ;
} ;

} // namespace drivercrate::test

// 呼出し位置と条件式をTestContextへ渡すassertion macro。
#define DRIVERCRATE_EXPECT( context, expression)                                                    \
	( context).expect( static_cast<bool>( expression), #expression, __FILE__, __LINE__)
