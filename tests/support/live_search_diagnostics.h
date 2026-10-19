//------------------------------------------------------------------------------
/**
 * @file live_search_diagnostics.h
 * @brief Live検索の非機密ASCII診断契約。
 * @version 01.00.00
 * @date 2026/09/08
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 数値とboolだけを受け取り、test専用streamへ診断を出力します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <iosfwd>

namespace drivercrate::test {

/**
 * @brief Live検索の終了時点を表す、秘密情報を含まない所有値。
 */
struct LiveSearchDiagnostics {
	/// 検索が返した32-bit値。0でも取得成功を保証しない。
	NativeError error{} ;
	/// 今回のmetadata reader呼出し回数。
	std::size_t metadataReads{} ;
	/// trueの場合はmetadataまたは取得根拠の検証で拒否。
	bool		metadataRejected{} ;
	/// 検索結果として保持された候補数。
	std::size_t candidates{} ;
	/// trueの場合は同一scanのlanding取得根拠が存在する。
	bool		landingEvidence{} ;
	/// trueの場合はread-only検索の非取得境界に反する。
	bool		payloadEvidence{} ;
} ;

/**
 * @brief 診断値を固定ASCIIとして一回書込み、明示flushの結果を返す。
 * @details Locale、format flag、exception maskを変更しない。部分出力を再試行しない。検索の成否は変更せず、出力失敗時は呼出し側でも成功表示を抑止する。
 * 非機密の検索診断を固定ASCIIで出力する。
 * 構築失敗では書き込まず、I/O失敗では部分出力を再試行しない。出力先が故障した場合の診断値保存を保証しない。
 * @param[in,out] output 呼出し中だけ借用するnarrow stream。失敗状態は解除しない。 借用stream。失敗状態・format設定を解除しない。
 * @param[in] diagnostics 32-bit error、件数、取得根拠flagのsnapshot。 検索結果の数値とboolだけを保持する値。
 * @return 全recordの書込みとflush成功時true。構築・I/O失敗と例外はfalse。 Record書込みとflush成功時true。例外と全失敗時false。
 */
[[nodiscard]] bool writeLiveSearchDiagnostics( std::ostream				  &output,
											  const LiveSearchDiagnostics &diagnostics) noexcept ;

} // namespace drivercrate::test
