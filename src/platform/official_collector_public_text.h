//------------------------------------------------------------------------------
/**
 * @file official_collector_public_text.h
 * @brief 収集専用の公開文字列形状とUTF-8上限を検証します。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  metadata専用公開値境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  必須制御付き公開値検証を追加。
 * </pre>
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/collector_parser_control.h"

#include <cstddef>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公開field種別定義。
//------------------------------------------------------------------------------

/** @brief Slashを認める有限field文法です。 */
enum class OfficialCollectorPublicTextKind {
	/// 表示名・key。Slashを認めません。
	TEXT,
	/// YYYY/MM/DD形式だけslashを認めます。
	DATE,
	/// ASCII MIME tokenの区切り一つだけを認めます。
	CONTENT_TYPE,
} ;

//------------------------------------------------------------------------------
// 公開関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 収集metadataの公開形状、Unicode、実UTF-8 byte数を検証します。
 * @param[in] value Sourceが選んだ公開field。空値の必須性はcallerが検証します。
 * @param[in] maximumBytes UTF-8変換後の有限上限。最大1,024 byte。
 * @param[in] kind Slashのfield別文法。
 * @return 不可視制御、path／query／端末ID形状がなく上限内ならtrue。
 * @note 通常record契約には適用せず、公式性や任意値の非秘密性を証明しません。
 */
[[nodiscard]] bool isOfficialCollectorPublicText(
	std::wstring_view value, std::size_t maximumBytes,
	OfficialCollectorPublicTextKind kind = OfficialCollectorPublicTextKind::TEXT) noexcept ;

/**
 * @brief 公開値の形状・Unicode走査を元control付きで検証します。
 * @param[in] value 有限公開値。
 * @param[in] maximumBytes 最大UTF-8 byte数。
 * @param[in] kind Slash文法。
 * @param[in,out] context 必須の元制御。
 * @return 文字検証の成立。停止・例外は上位境界へ伝播します。
 */
[[nodiscard]] bool isOfficialCollectorPublicTextForCollector( std::wstring_view value,
															 std::size_t	   maximumBytes,
															 OfficialCollectorPublicTextKind kind,
															 CollectorParserContext &context) ;
} // namespace drivercrate
