//------------------------------------------------------------------------------
/**
 * @file broadcom_catalog_parser.h
 * @brief Broadcom NetXtreme-E公開配布情報の解析契約。
 * @version 01.00.00
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 表示用解析と取得対象用解析を区別し、取得元検証・同意・導入を呼出し側へ委譲します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_release_metadata.h"

#include <optional>
#include <string>
#include <string_view>

namespace drivercrate {

// N210TP公開pageの固定path。端末の製品名から動的に組み立てない。
inline constexpr std::wstring_view BROADCOM_PRODUCT_PATH =
	L"/products/ethernet-connectivity/network-adapters/n210tp" ;
// 固定localeの公開Web JSON。端末情報をqueryへ含めない。
inline constexpr std::wstring_view BROADCOM_CATALOG_URL =
	L"https://www.broadcom.com/api/getjson?url=%2Fproducts%2Fethernet-connectivity"
	L"%2Fnetwork-adapters%2Fn210tp&locale=en-us" ;
// 配布分類に利用する正確な公式title。INFの適用性を保証しない。
inline constexpr std::wstring_view BROADCOM_WINDOWS_DRIVER_TITLE =
	L"Broadcom NetXtreme-E Windows Drivers" ;

/**
 * @brief 公式公開recordをdocument情報へ結合する、worker内だけの表示metadataである。
 * @note Asset版をINF版として扱わず、payload URLとEULA本文は保持しない。
 */
struct BroadcomDriverRelease {
	/// 製品recordとdocumentの一致確認専用ID。
	std::wstring contentId ;
	/// 4個の数値要素からなる配布表示版。
	std::wstring assetVersion ;
	/// 検証済み識別子を固定公式APIへ結合したURL。
	std::wstring documentApiUrl ;
} ;

/**
 * @brief 固定製品JSONから唯一の現行Windows driver recordを解析する。
 * 有限な固定製品JSONを解析し、成功した現行配布情報だけを返す。失敗時は出力を初期化する。
 * @param[in] json 2 Mi文字以内のJSON。ネットワーク取得元は呼出し側が検証する。 上限付きの公式JSON本文。
 * @param[out] release 成功時の配布情報。現行recordなしまたは失敗時は空。 製品record。出力時の部分値は呼出し側が失敗時に破棄する。
 * @return 構造が有効ならtrue。曖昧な現行recordまたはmetadata不正はfalse。 定義した検査に適合する場合true。不一致はfalse。
 */
[[nodiscard]] bool parseBroadcomCatalog( std::wstring_view					  json,
										std::optional<BroadcomDriverRelease> &release) ;

/**
 * @brief 公式document情報と製品recordを結合し、公開EULA／ZIP形式を検査する。
 * 既存の製品・document・ZIP URLを照合する。取得用の本文変換と同意は別処理で行う。
 * @param[in] json 256 Ki文字以内の公開document JSON。 上限付きの公式JSON本文。
 * @param[in] release 同一scanの製品parserが返したrecord。 製品record。出力時の部分値は呼出し側が失敗時に破棄する。
 * @return 既知の公開EULA形式と同一配布recordならtrue。不明または不一致はfalse。 定義した検査に適合する場合true。不一致はfalse。
 * @note 同意・payload取得・署名確認・OS／PnP判定は実施しない。
 */
[[nodiscard]] bool validateBroadcomDocument( std::wstring_view			 json,
											const BroadcomDriverRelease &release) ;

/**
 * @brief 配布物と二つの公開license本文を取得承認用recordへ結合する。
 * 既存の製品・ZIP検証を再利用し、公開されていないhash・exact sizeは補完しない。
 * @param[in] json 同一scanの公式document JSON。
 * @param[in] release 製品JSONで選択した現行record。
 * @param[out] record 成功時のworker専用情報。失敗時は空。 成功時の配布物と同意本文。失敗時は空。
 * @return URL結合と省略しない本文変換に成功した場合true。 公式recordと表示可能な本文が結合できればtrue。
 * @note 取得元の照合・明示同意・取得は呼出し側で行う。
 */
[[nodiscard]] bool parseBroadcomPreparedRelease( std::wstring_view			 json,
												const BroadcomDriverRelease &release,
												OfficialReleaseRecord		&record) ;

} // namespace drivercrate
