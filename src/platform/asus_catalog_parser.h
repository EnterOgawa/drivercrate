//------------------------------------------------------------------------------
/**
 * @file asus_catalog_parser.h
 * @brief ASUS公式support page parser定義。
 * @version 01.05.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  LAN／Wireless限定解析を明示引数として追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/20  汎用categoryと個別拒否の観測modeを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  収集専用の同一store製品識別と行診断を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  収集専用model比較keyを公開target照合へ共有。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  収集専用の必須制御付き入口を追加。
 * </pre>
 *
 * @note ASUS公式製品pageのserver-side HTMLに埋め込まれたNuxt JSONだけを有限に解析します。本結果だけでPnP適用性またはinstall可否を決定しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/collector_parser_control.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 明示catalog modeの対象行と個別拒否を区別する集計です。 */
struct AsusDriverCatalogObservation {
	/// 全体構造・model・OSと対象category走査が成立した場合true。
	bool		structurallyValid{} ;
	/// 対象categoryで本文を検査した行数。
	std::size_t seen{} ;
	/// Metadata検証に合格しentriesへ返した行数。
	std::size_t accepted{} ;
	/// Hash欠落・別OS・対象外形式等で候補にしない行数。
	std::size_t ignored{} ;
	/// 本文schema・hash・path・size等の不正を隔離した行数。
	std::size_t rejected{} ;
} ;

/**
 * @brief 既存の非boot-critical driver分類か判定します。
 * @param[in] category 公式pageが表示する分類名。
 * @return Driver分類の場合true。BIOS・firmware・utility・SATA等はfalse。
 */
[[nodiscard]] bool isAsusDriverCatalogCategory( std::wstring_view category) noexcept ;

//------------------------------------------------------------------------------
// ASUS公式page値型定義。
//------------------------------------------------------------------------------

/**
 * @brief ASUS製品別support pageに含まれる一つの検査可能なdriver archiveである。
 *
 * @note `downloadUrl`はG11取得前の公式metadataであり、候補、適用可能またはinstall可能を
 * 意味しない。
 */
struct AsusDriverPageEntry {
	/// ASUS page上のdriver分類。
	std::wstring  category ;
	/// Page schemaとOSを照合するASUS内部ID。
	std::wstring  opaqueId ;
	/// ASUSが表示するdriver package名称。
	std::wstring  title ;
	/// ASUSが表示するpackage version。
	std::wstring  version ;
	/// `YYYY/MM/DD`形式の公開日。
	std::wstring  releaseDate ;
	/// `dlcdnets.asus.com`上のZIPまたはCAB URL。
	std::wstring  downloadUrl ;
	/// ASUS pageが公開する小文字64桁SHA-256。
	std::wstring  sha256 ;
	/// 丸められた表示sizeへ余裕を加えた、検査用downloadの上限byte数。
	std::uint64_t maximumDownloadBytes{} ;
} ;

/** @brief 収集専用の一行が最初に確定した分類です。 */
enum class AsusCollectorRowReason {
	/// 公式recordとして採用した行です。
	ACCEPTED,
	/// 同じ公式page内の別OSに対応する行です。
	OTHER_OS,
	/// 初期収集profileが扱わない配布形式です。
	UNSUPPORTED_FORMAT,
	/// 公開SHA-256の掲載がありません。
	HASH_NOT_PUBLISHED,
	/// 検証済み取得上限が明示予算を超えました。
	BUDGET_EXCEEDED,
	/// 行のschema、参照、pathまたは公開値が不正です。
	REJECTED_ROW,
} ;

/** @brief 収集専用sliceのparser時点の状態です。減少判定は親が行います。 */
enum class AsusCollectorSliceStatus {
	/// 同一storeの対象分類が掲載されていません。
	NOT_LISTED,
	/// 対象分類が掲載され、行数が0です。
	EMPTY,
	/// 同一storeの要求OS選択肢がありません。
	OS_NOT_LISTED,
	/// 対象行はありますが採用できる行はありません。
	NO_ELIGIBLE_RECORD,
	/// 有効行と個別不採用行が混在します。
	PARTIAL_REJECTED,
	/// 必須の所属または一覧schemaが不正です。
	SCHEMA_REJECTED,
	/// 17件目の有効recordを検出しました。
	RECORD_LIMIT,
	/// 対象分類の全行を採用しました。
	ACCEPTED,
} ;

/** @brief 同一storeの公開identityと行別診断を所有するworker内の結果です。 */
struct AsusCollectorPageResult {
	/// Nuxt routeと同一storeの基本構造が有効な場合trueです。
	bool							 structurallyValid{} ;
	/// 要求modelとpage／driverの公開modelが一致した場合trueです。
	bool							 targetModelMatches{} ;
	/// 公式pageの元model名です。
	std::wstring					 pageModel ;
	/// ASUS_ASCII_SPACE_V1による比較keyです。
	std::wstring					 modelComparisonKey ;
	/// 同一storeの公開数値productIdを十進表記した値です。
	std::wstring					 productId ;
	/// 対象OSの元表示名です。
	std::wstring					 osName ;
	/// 同一storeから確認したOS ID。未掲載時は空です。
	std::wstring					 osId ;
	/// 明示した対象分類です。
	std::wstring					 category ;
	/// 同一storeから確認した分類のparser時点状態です。
	AsusCollectorSliceStatus		 sliceStatus{AsusCollectorSliceStatus::SCHEMA_REJECTED} ;
	/// 対象分類で検査した行数です。
	std::size_t						 seen{} ;
	/// 行別の第一理由だけを数えます。enumの順序と同じ添字です。
	std::size_t						 reasonCounts[6]{} ;
	/// URLを含むためworker外へ渡さない採用済み行です。
	std::vector<AsusDriverPageEntry> entries ;
} ;

/**
 * @brief 収集専用parserと同じASUS_ASCII_SPACE_V1比較keyを構築します。
 * @param[in] publicModel 公式pageまたは公開targetの有限製品名。
 * @return 有効な公開製品名なら所有key、不正または空なら空文字列。
 * @note 公式出典や端末の適合性は証明しません。
 */
[[nodiscard]] std::wstring asusCollectorModelComparisonKey( std::wstring_view publicModel) ;

/**
 * @brief 同じNuxt本文内のASUS公開identity・対象分類・行理由を収集専用に解析します。
 * @param[in] html 制御付きGETから借用した公式HTML。本文の出典はcallerが別に確認します。
 * @param[in] expectedModel 固定planで要求した公開製品名。
 * @param[in] expectedOsName 初期scopeのWindows 11 64-bit表記。
 * @param[in] expectedCategory 初期scopeのLAN分類。
 * @param[in] maximumBytes 一配布物の明示受信予算。
 * @param[out] result 成功時だけ同一storeの所有値を返します。失敗時は既定値です。
 * @return Nuxtと同一storeの構造が成立した場合true。対象model違いと空sliceは結果の状態で区別します。
 * @pre 呼出しthreadでCOM apartmentが初期化されていること。
 * @note 出典・公式URL・取得許可を発行しません。通常のparseAsusDriverPageHtmlの受理条件は変更しません。
 */
[[nodiscard]] bool		   parseAsusCollectorDriverPageHtml( std::wstring_view		 html,
															std::wstring_view		 expectedModel,
															std::wstring_view		 expectedOsName,
															std::wstring_view		 expectedCategory,
															std::uint64_t			 maximumBytes,
															AsusCollectorPageResult &result) ;

//------------------------------------------------------------------------------
// ASUS公式page parser定義。
//------------------------------------------------------------------------------

/**
 * @brief ASUS製品別support pageから公式driver archive metadataを取得する。
 * Nuxt flattened参照を有限に解決し、公式CDNのSHA-256付きZIP／CABだけをG11取得前metadataとして返す。
 * @param[in] html ASUS公式起点から取得したUTF-16 HTML。 ASUS公式起点pageのUTF-16 HTML。
 * @param[in] expectedModel 端末内SMBIOSから得たsystemまたはbaseboard product名。 Local SMBIOSのsystem／board
 *                   model。
 * @param[in] expectedOsName ASUS page上の対象OS名。例は`Windows 11 64-bit`。
 * @param[out] entries 成功時のSHA-256付きZIP／CAB一覧。該当なしの場合は空にする。 全検証成功時の検査可能archive一覧。
 * @param[in] expectedCategory 空の場合は従来の全record、LANまたはWirelessの場合は当該category本文だけを検証する。
 * @param[out] catalogObservation 非nullなら明示catalog mode。既存driver分類一つを要求し、個別不正は拒否件数として隔離する。
 * @return 全体構造・model・OSの検証成功時true。従来modeでは対象内の個別不正もfalse。
 * @pre 呼出しthreadでCOM apartmentが初期化されていること。
 * @note Category限定時も全categoryの型・Count・Files参照と全体model／OSを検証する。
 * 対象外本文の有効性は保証せず、未知category引数は拒否する。
 */
[[nodiscard]] bool		   parseAsusDriverPageHtml(
			std::wstring_view html, std::wstring_view expectedModel, std::wstring_view expectedOsName,
			std::vector<AsusDriverPageEntry> &entries, std::wstring_view expectedCategory = {},
			AsusDriverCatalogObservation *catalogObservation = nullptr) ;

/**
 * @brief 同一Nuxt coreの構造・上限・停止・障害を分離します。
 * @param[in] html 同一GET本文。
 * @param[in] expectedModel 固定planの公開model。
 * @param[in] expectedOsName 固定OS表示。
 * @param[in] expectedCategory 固定LAN分類。
 * @param[in] maximumBytes 明示配布予算。
 * @param[in,out] control 元GETの必須制御。
 * @param[out] result 完了時だけ公開する所有結果。
 * @return 候補採用とは独立した型付き終了。
 */
[[nodiscard]] CollectorParserResult parseAsusCollectorDriverPageHtmlControlled(
	std::wstring_view html, std::wstring_view expectedModel, std::wstring_view expectedOsName,
	std::wstring_view expectedCategory, std::uint64_t maximumBytes,
	OfficialCollectorHttpControl &control, AsusCollectorPageResult &result) ;
} // namespace drivercrate
