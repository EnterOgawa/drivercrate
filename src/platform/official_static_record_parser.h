//------------------------------------------------------------------------------
/**
 * @file official_static_record_parser.h
 * @brief 公式配布record用の静的HTML／JSON抽出境界定義。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  有限HTML属性とJSON object path抽出境界を追加。
 * </pre>
 *
 * @note Provider parserだけが対象区画とfieldの意味を決めます。本境界はscriptを実行せず、URL、
 *       host、driver方式、適用性または取得許可を推測しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/**
 * @brief 一意なProvider markerと同じHTML開始tagにある指定属性値を取得します。
 * @param[in] html 4 Mi UTF-16 code unit以下の静的公式HTML。
 * @param[in] uniqueMarker Provider parserが一件だけ存在すると定めたtag内marker。
 * @param[in] attributeName 同じ開始tagから読むASCII属性名。
 * @param[in] maximumValueCharacters 属性値へ許可する1以上8,192以下のUTF-16 code unit数。
 * @param[out] value 成功時だけ設定する未解釈属性値。失敗時は空です。
 * @return Marker、開始tag、属性と有限値が一意で安全な場合は`true`。
 * @note `script`／`style`、HTML entity、単引用符、別tag、重複属性を解釈または補完しません。
 */
[[nodiscard]] bool extractUniqueOfficialHtmlAttribute( std::wstring_view html,
													  std::wstring_view uniqueMarker,
													  std::wstring_view attributeName,
													  std::size_t		maximumValueCharacters,
													  std::wstring	   &value) ;

/**
 * @brief Provider指定のJSON object pathにある文字列propertyを型付きで取得します。
 * @param[in] json 4 Mi UTF-16 code unit以下の静的公式JSON object本文。
 * @param[in] objectPath Rootから順に辿る0件以上8件以下のobject property名。
 * @param[in] propertyName 最終objectから読む文字列property名。
 * @param[in] maximumValueCharacters 値へ許可する1以上8,192以下のUTF-16 code unit数。
 * @param[out] value 成功時だけ設定するdecoded文字列。失敗時は空です。
 * @return Root、全path要素、最終propertyの型と有限値が有効な場合は`true`。
 * @note Array検索、field名推測、数値から文字列への変換、script実行を行いません。
 */
[[nodiscard]] bool extractOfficialJsonStringAtObjectPath(
	std::wstring_view json, std::span<const std::wstring_view> objectPath,
	std::wstring_view propertyName, std::size_t maximumValueCharacters, std::wstring &value) ;

} // namespace drivercrate
