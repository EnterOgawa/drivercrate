//------------------------------------------------------------------------------
/**
 * @file intel_collector_identity_parser.h
 * @brief Intel配布pageの公開製品identity純粋解析API。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  有限Intel製品identity解析を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  同じhero内の配布button拘束を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  必須制御付きの型付き入口を追加。
 * </pre>
 *
 * @note 通信・record生成・出典証明・driver適用性判定は行いません。
 * @see docs/adr/0221-collector-official-product-identity.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/collector_parser_control.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

// Record parser revisionと独立した製品一覧契約のrevision。
inline constexpr std::uint32_t INTEL_COLLECTOR_IDENTITY_PARSER_REVISION = 1U ;

/**
 * @brief 配布情報や取得許可とは独立した本文内identityの結果です。
 */
enum class IntelCollectorIdentityStatus {
	/// 一意な所属と全行を確認した。正常な同値重複は許す。
	ACCEPTED,
	/// 不正または衝突する行を全て除いた部分結果。
	PARTIAL_REJECTED,
	/// 専用一覧または必要な所属根拠が未掲載。
	IDENTITY_UNKNOWN,
	/// 一覧内に未評価の追加要素があるため全結果を保留。
	PAGINATION_INCOMPLETE,
	/// 属性・階層・閉鎖等の構造違反。
	SCHEMA_REJECTED,
	/// 本文・token・属性・階層・行数の有限上限超過。
	LIMIT_EXCEEDED
} ;

/**
 * @brief URLを保持しない公開製品identityの所有値です。
 */
struct IntelCollectorProductIdentity {
	/// 公式製品path由来の先頭0なし1～10桁十進SKU。
	std::wstring sku ;
	/// Entityと空白を整形した256 UTF-16以内の表示名。
	std::wstring displayName ;
	/// 表示名をNFCへ変換した完全一致比較名。
	std::wstring comparisonName ;
} ;

/**
 * @brief 純粋本文解析の所有結果です。GET成功やrecordの存在は表しません。
 */
struct IntelCollectorIdentityResult {
	/// ACCEPTEDだけが全一覧の構造と行の検査完了を示す。
	IntelCollectorIdentityStatus status{IntelCollectorIdentityStatus::IDENTITY_UNKNOWN} ;
	/// 重複除去前の行数。構造拒否時は0。
	std::size_t					 seen{} ;
	/// 有効な同key同名の折畳み行数。衝突群はここへ数えない。
	std::size_t					 duplicates{} ;
	/// 内容またはSKUが不正な行数。
	std::size_t					 rejected{} ;
	/// keyまたは比較名が衝突した全原行数。
	std::size_t					 collisions{} ;
	/// 元順序を維持した非衝突の一意identity。全体拒否時は空。
	std::vector<IntelCollectorProductIdentity> products ;
} ;

/**
 * @brief 727998配布pageの専用対応製品一覧を通信なしで解析します。
 * @param[in] html 呼出し中だけ借用する最大4 Mi UTF-16本文。
 * @return 所有identityと診断。構造拒否時は部分identityを返さない。
 * @note 純粋関数であり、公式性・record・適用性・取得許可を発行しません。
 *       配布parserとの同一本文結合とGET所有型は後段の責務です。
 */
[[nodiscard]] IntelCollectorIdentityResult parseIntelCollectorProductIdentity(
	std::wstring_view html) ;

/**
 * @brief 製品一覧と、同じ左panelの配布heroにある正確な一buttonを解析します。
 * @param[in] html 配布parserへも渡した同一UTF-16本文。
 * @param[in] expectedDownloadUrl 配布parserが確定したworker内秘密URL。空は禁止です。
 * @return URLを保持しないidentity結果。HeroでURLが一意に結べなければ全体拒否です。
 * @note URLと本文の公式GET出典・payload取得権限は検証しません。
 */
[[nodiscard]] IntelCollectorIdentityResult parseIntelCollectorProductIdentityForPayload(
	std::wstring_view html, std::wstring_view expectedDownloadUrl) ;

/**
 * @brief 同じ内部coreで停止・上限・構造・例外を区別する収集専用入口です。
 * @param[in] html 最大4 Mi UTF-16の有限本文。
 * @param[in] expectedDownloadUrl 空ならidentityのみ、非空なら同じheroへ拘束します。
 * @param[in,out] control 元GETと同じ必須制御。sealはしません。
 * @param[out] result COMPLETED時だけ公開する所有値。未掲載は正常終了のsource状態です。
 * @return 候補適合性とは独立した解析終了値。
 */
[[nodiscard]] CollectorParserResult parseIntelCollectorProductIdentityControlled(
	std::wstring_view html, std::wstring_view expectedDownloadUrl,
	OfficialCollectorHttpControl &control, IntelCollectorIdentityResult &result) ;

} // namespace drivercrate
