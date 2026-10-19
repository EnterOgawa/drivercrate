//------------------------------------------------------------------------------
/**
 * @file asus_collector_target_assessment.h
 * @brief 同一ASUS本文の一時候補と公開対象を三状態で照合します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  公開target三状態と複数候補番号の純粋照合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  必須制御付き候補／対象照合入口を追加。
 * </pre>
 *
 * @note 公開値だけを結果へ保持します。HTTP・取得・端末PnP照合は行いません。
 * @see docs/adr/0221-collector-official-product-identity.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/asus_catalog_parser.h"
#include "platform/official_download_grant.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 収集専用ASUS対象照合型定義。
//------------------------------------------------------------------------------

/** @brief 一つの公開対象に明示された照合条件です。すべて借用値です。 */
struct AsusCollectorTargetQuery {
	/// 現campaign内の公開対象key。重複を認めません。
	std::wstring_view targetKey ;
	/// Boardのメーカー。Componentのメーカーではありません。
	std::wstring_view maker ;
	/// 公式pageと完全比較する公開model。
	std::wstring_view model ;
	/// MAINBOARD等の公開機器種別。
	std::wstring_view kind ;
	/// LAN等の明示用途。
	std::wstring_view purpose ;
	/// Windows 11 64-bit等の明示OS。
	std::wstring_view operatingSystem ;
	/// x64等の明示architecture。
	std::wstring_view architecture ;
	/// 任意のchip条件。空ならchip条件を課しません。
	std::wstring_view chip ;
} ;

/** @brief 同一本文と候補集合から得た一時照合状態です。 */
enum class AsusCollectorTargetState {
	/// 全条件と一件以上の候補が揃いました。
	MATCH,
	/// 検証済みの公開fieldに明示矛盾があります。
	NO_MATCH,
	/// 出典構造、公開値、必要な条件または候補が欠けています。
	UNKNOWN,
} ;

/** @brief 明示矛盾を未知より優先し、同状態内は製品、目的、OS、architecture、chipの順です。 */
enum class AsusCollectorTargetReason {
	/// 全軸が成立しました。
	MATCHED,
	/// 公開対象のfieldが有限契約を満たしません。
	INVALID_QUERY,
	/// 同一storeの公開製品構造を検証できません。
	SOURCE_UNKNOWN,
	/// メーカー、機器種別または製品modelが公式pageと矛盾します。
	PRODUCT_CONFLICT,
	/// 明示された別の既知用途です。
	PURPOSE_CONFLICT,
	/// 用途の意味を公式LAN分類と比較できません。
	PURPOSE_UNKNOWN,
	/// 解決済みOS IDの公開名と既知別OSが矛盾します。
	OS_CONFLICT,
	/// OS ID未解決または意味が比較できません。
	OS_UNKNOWN,
	/// 明示された別の既知architectureです。
	ARCHITECTURE_CONFLICT,
	/// Architectureの意味を比較できません。
	ARCHITECTURE_UNKNOWN,
	/// Chipの構造化根拠がありません。
	CHIP_UNKNOWN,
	/// 配布候補がありません。
	RECORD_UNKNOWN,
} ;

/** @brief GET証拠や取得許可を含まない一対象の所有結果です。 */
struct AsusCollectorTargetAssessment {
	/// 元入力の公開key。
	std::wstring			   targetKey ;
	/// 明示矛盾・未知を含む三状態。
	AsusCollectorTargetState   state{AsusCollectorTargetState::UNKNOWN} ;
	/// 同状態内で優先された第一理由。
	AsusCollectorTargetReason  reason{AsusCollectorTargetReason::SOURCE_UNKNOWN} ;
	/// 同一storeから確認した数値productId。source不成立時は空です。
	std::wstring			   productId ;
	/// 同一storeから確認した元model。source不成立時は空です。
	std::wstring			   displayModel ;
	/// ASUS_ASCII_SPACE_V1比較key。source不成立時は空です。
	std::wstring			   comparisonModel ;
	/// 同じ本文の候補配列index。候補欠測時は空、取得権限ではありません。
	std::vector<std::uint32_t> candidateOrdinals ;
} ;

//------------------------------------------------------------------------------
// 公開関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 同じ解析済みpageと一時候補を最大300公開対象に照合します。
 * @param[in] page 同一storeから得た所有解析結果。公式GET証拠は含みません。
 * @param[in] candidates 同じpageから作った最大16候補。空なら全対象に候補なしを記録します。
 * @param[in] targets 重複しない公開keyを持つ最大300件の対象。
 * @param[out] assessments 入力順の一時判定。集合拒否時は空です。
 * @return 集合境界と候補の同一page結合が成立した場合true。
 * @note 本関数はURL、EULA本文、fingerprint、GET出典、取得許可を結果に含めません。
 */
[[nodiscard]] bool inspectAsusCollectorTargets(
	const AsusCollectorPageResult					 &page,
	std::span<const OfficialCollectorRecordCandidate> candidates,
	std::span<const AsusCollectorTargetQuery>		  targets,
	std::vector<AsusCollectorTargetAssessment>		 &assessments) ;

/**
 * @brief 同じcoreで停止・失敗と候補／対象の照合結果を分けます。
 * @param[in] page 同じ本文のpage。
 * @param[in] candidates 同じpageの候補。
 * @param[in] targets 全公開対象。
 * @param[in,out] control 元GETの必須制御。
 * @param[out] assessments 完了時のみ公開する所有値。
 * @return 解析／照合の型付き終了。
 */
[[nodiscard]] CollectorParserResult inspectAsusCollectorTargetsControlled(
	const AsusCollectorPageResult					 &page,
	std::span<const OfficialCollectorRecordCandidate> candidates,
	std::span<const AsusCollectorTargetQuery> targets, OfficialCollectorHttpControl &control,
	std::vector<AsusCollectorTargetAssessment> &assessments) ;
} // namespace drivercrate
