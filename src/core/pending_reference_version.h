//------------------------------------------------------------------------------
/**
 * @file pending_reference_version.h
 * @brief 同scanの取得前参照版を更新確認用に分類します。
 * @version 01.00.01
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  版不明/同版/旧版と新版の取得前確認を分離。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 候補の由来を認証せず、適合/rank/導入許可も発行しません。元計画の選択検査は別途必要です。
 * @see docs/adr/0428-newer-index-reference-confirmation.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace drivercrate {
/** @brief 適用性と独立した取得前版の比較結果。 */
enum class PendingReferenceVersion {
	/// 版/現在観測/関係の比較条件が不足しています。
	UNKNOWN,
	/// 比較可能な収集者申告版が現在版より新しいです。
	NEWER,
	/// 数値版が同じです。未取得/未検査です。
	SAME,
	/// 数値版が古いです。未取得/未検査です。
	OLDER,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 明示4個の16bit十進数だけをWindows版比較へ変換します。
 * @param[in] version 元の版文字列。欠損/省略/任意suffixを補完しません。
 * @return 四要素のpacked値。不正/不足はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseFourPartDriverVersion(
	std::wstring_view version) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 同scanの一意な登録済み現在観測との取得前比較を行います。
 * @param[in] candidate 記述済みの署名索引参照。producerが原metadataだけを投影します。
 * @param[in] candidates 同じsnapshotの現在行と候補。
 * @param[in] scanSessionId 現在有効な同scan。
 * @return 比較条件が全て成立した場合だけNEWER/SAME/OLDER。導入actionは変更しません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] PendingReferenceVersion classifyPendingReferenceVersion(
	const UpdateCandidate &candidate, std::span<const UpdateCandidate> candidates,
	ScanSessionId scanSessionId) noexcept ;
}
