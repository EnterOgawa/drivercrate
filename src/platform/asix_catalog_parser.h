//------------------------------------------------------------------------------
/**
 * @file asix_catalog_parser.h
 * @brief ASIX AX88179A公式製品page・Terms parser定義。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Terms本文と取得前配布recordの結合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  数値配布IDの観測境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note AX88179A製品pageとTermsの既知構造を非実行で解析し、worker専用recordへ結合します。Payload取得、PnP適用性、署名監査および導入許可は扱いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_release_metadata.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {

/** @brief ASIX製品pageが区別するWindows client x64系列。 */
enum class AsixWindowsClientFamily {
	/// Windows 10 x64向けdriver-only行。
	WINDOWS10_X64,
	/// Windows 11 x64向けdriver-only行。
	WINDOWS11_X64,
} ;

/** @brief 一つのASIX Windows x64 driver行から得た表示専用metadata。 */
struct AsixDriverPageEntry {
	/// Page上で明示されたWindows client系列。
	AsixWindowsClientFamily family{} ;
	/// 公式endpointが明示した数値download ID。
	std::wstring			releaseKey ;
	/// Setup programと区別したdriver行の正式表示名。
	std::wstring			title ;
	/// PageがVersionとして明示したpackage版。
	std::wstring			version ;
	/// Pageが表示したYYYY-MM-DD形式の日付。
	std::wstring			releaseDate ;
	/// Pageの概算size。取得上限には使用しない。
	std::wstring			displaySize ;
	/// ASIX公式endpoint。取得許可ではない。
	std::wstring			downloadUrl ;
} ;

/** @brief AX88179AのWindows 10／11 x64 driver行を保持する解析結果。 */
struct AsixAx88179aCatalog {
	/// Windows 10 x64の表示情報。
	AsixDriverPageEntry windows10 ;
	/// Windows 11 x64の表示情報。
	AsixDriverPageEntry windows11 ;
} ;

/** @brief ASIX公式Terms pageから省略せず抽出した同意対象snapshot。 */
struct AsixTermsSnapshot {
	/// 表示用に空白と改行だけを正規化したTerms全文。
	std::wstring text ;
	/// DriverCrate算出と明示したUTF-8本文SHA-256識別子。
	std::wstring revision ;
} ;

/**
 * @brief ASIX AX88179A公式製品pageを有限規則で解析する。
 * 公開page情報だけを返し、hash、INF内容、PnP適用性、導入可否を補完しない。
 * @param[in] html ASIX公式hostから取得したUTF-16 HTML。
 * @param[out] catalog 成功時のWindows 10／11 x64表示情報。失敗時は初期値。 成功時のWindows 10／11 x64情報。失敗時は初期値。
 * @return 製品名、二つのdriver行、版、日付、size、公式endpointが整合する場合true。 固定製品と二つの対象driver行が整合する場合true。
 * @note 公開SHA-256がないため、本結果だけではpayload取得またはinstallを許可しない。
 */
[[nodiscard]] bool parseAsixAx88179aProductPage( std::wstring_view	 html,
												AsixAx88179aCatalog &catalog) ;

/**
 * @brief ASIX公式Terms pageの単一mainを有限規則でplain textへ変換する。
 * Main外のnavigationとfooterを混ぜず、本文hashだけで完全一致確認を代替しない。
 * @param[in] html 固定Terms起点から取得した最大256 Ki UTF-16単位のHTML。 ASIX固定Terms起点から取得したUTF-16 HTML。
 * @param[out] snapshot 成功時の全文と算出識別子。失敗時は初期値。 成功時の正規化全文と算出識別子。
 * @return 既知container、見出し、tag、entityを省略なく変換できた場合true。 単一mainの全文を既知構造から省略なく変換できた場合true。
 * @note Navigationやfooterを同意対象へ混ぜず、未知構造を黙って除去しない。
 */
[[nodiscard]] bool parseAsixTermsPage( std::wstring_view html, AsixTermsSnapshot &snapshot) ;

/**
 * @brief 実Windows client buildに対応するASIX表示情報を選ぶ。
 * Serverとbuild不明をfail-closedにし、別OS向け行をfallbackに使用しない。
 * @param[in] catalog 検証済み製品pageの所有値。
 * @param[in] windowsServer 実OSがWindows Serverの場合true。 実OSがServerの場合true。
 * @param[in] windowsBuild 実OSのmajor build番号。0は判定不能。 実OSのmajor build。0は不明。
 * @param[out] entry 成功時に選択した表示情報の複製。失敗時は初期値。
 * @return 対応するWindows 10／11 x64 client系列を選択できた場合true。 対応するWindows client系列を選べた場合true。
 */
[[nodiscard]] bool selectAsixAx88179aWindowsEntry( const AsixAx88179aCatalog &catalog,
												  bool windowsServer, std::uint32_t windowsBuild,
												  AsixDriverPageEntry &entry) ;

/**
 * @brief 同じsource sessionの製品pageとTerms pageをOS別の取得前recordへ結合する。
 * 呼出側が同一source sessionを保証する。未公開値を補完せず導入許可しない。
 * @param[in] productHtml 固定AX88179A製品pageのHTML。
 * @param[in] termsHtml 製品pageが一意に参照する固定Terms pageのHTML。 同じsource sessionの固定Terms page HTML。
 * @param[in] windowsServer 実OSがWindows Serverの場合true。
 * @param[in] windowsBuild 実OSのmajor build番号。0は判定不能。
 * @param[out] record 成功時のworker専用配布snapshot。失敗時は初期値。 成功時の取得前配布snapshot。
 * @return 両pageの解析、client OS選択、本文識別、配布identityが全て成立した場合true。 二page、OS選択、本文識別、配布identityが全て成立した場合
 *         true。
 * @note 呼出側が両pageの同一公式source session証拠を保証する。本関数は取得・導入を許可しない。
 */
[[nodiscard]] bool makeAsixAx88179aPreparedRelease( std::wstring_view productHtml,
												   std::wstring_view termsHtml, bool windowsServer,
												   std::uint32_t		  windowsBuild,
												   OfficialReleaseRecord &record) ;

} // namespace drivercrate
