//------------------------------------------------------------------------------
/**
 * @file nvidia_catalog_parser.h
 * @brief NVIDIA公式catalog応答parser定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通XML検証契約を追記。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note NVIDIA公式lookup XMLとdriver検索JSONを上限付きの内部値へ変換します。応答schema不一致時は候補を推測せず失敗します。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// NVIDIA catalog値型定義。
//------------------------------------------------------------------------------

/**
 * @brief NVIDIA lookup APIが返す表示名と数値IDの組である。
 */
struct NvidiaLookupValue {
	/// Product type、series、productの公式表示名。
	std::wstring name ;
	/// 後続APIへ渡す数字だけのopaque ID。
	std::wstring value ;
} ;

/**
 * @brief NVIDIA driver検索APIが返す一つの公式driver releaseである。
 */
struct NvidiaDriverEntry {
	/// NVIDIAが発行したdownload ID。
	std::wstring id ;
	/// Game ReadyまたはStudio等のrelease名称。
	std::wstring name ;
	/// NVIDIA形式のdriver version。
	std::wstring version ;
	/// NVIDIAが返す英語release日付。
	std::wstring releaseDate ;
	/// NVIDIA公式詳細page URL。
	std::wstring detailsUrl ;
	/// NVIDIA公式installer URL。
	std::wstring downloadUrl ;
	/// NVIDIAが返す表示用file size。
	std::wstring downloadSize ;
	/// trueの場合はNVIDIA応答がWHQLと示したrelease。
	bool		 whql{} ;
	/// trueの場合はStudio/Creator driver channel。
	bool		 studio{} ;
	/// trueの場合はNVIDIA応答が有効と示したrelease。
	bool		 active{} ;
	/// trueの場合は64-bit Windows package。
	bool		 x64{} ;
} ;

//------------------------------------------------------------------------------
// NVIDIA catalog parser定義。
//------------------------------------------------------------------------------

/**
 * @brief NVIDIA lookup APIのXMLからbounded lookup value群を取得する。
 * NVIDIA lookup XMLをbounded lookup value群へ変換する。
 * LookupValueSearch container内のName/Value組だけを受理する。
 * @param[in] xml NVIDIA公式APIから取得したUTF-16 XML text。 NVIDIA公式APIのUTF-16 XML。
 * @param[out] values 成功時のlookup value群。失敗時は空にする。
 * @return schemaと上限を満たす場合は`true`。 一件以上のschema準拠要素を取得できた場合は`true`。
 * @pre 呼出しthreadでCOM apartmentが初期化されていること。
 */
[[nodiscard]] bool parseNvidiaLookupXml( std::wstring_view				xml,
										std::vector<NvidiaLookupValue> &values) ;

/**
 * @brief NVIDIA driver検索APIのJSONからbounded release群を取得する。
 * NVIDIA driver JSONをbounded release群へ変換する。
 * 必須fieldを上限付きで取得し、不完全entryを推測で補完しない。
 * @param[in] json NVIDIA公式APIから取得したUTF-16 JSON text。 NVIDIA公式APIのUTF-16 JSON。
 * @param[out] entries 成功時のdriver release群。失敗時は空にする。
 * @return schemaと上限を満たす場合は`true`。 Schema準拠応答を解析できた場合は`true`。候補0件も成功。
 */
[[nodiscard]] bool parseNvidiaDriverJson( std::wstring_view				 json,
										 std::vector<NvidiaDriverEntry> &entries) ;

} // namespace drivercrate
