//------------------------------------------------------------------------------
/**
 * @file candidate_selection.h
 * @brief Driver候補の既定選択定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  探索経路境界検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Providerが明示した検証根拠から一device一候補の初期選択を作成します。Version、日付、titleを取得元間の優先順位へ使用しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <optional>
#include <span>
#include <vector>

namespace drivercrate {

/**
 * @brief Candidateの探索経路がProvider registryの信頼境界と一致するか検証する。
 * Candidate探索経路とProvider境界の整合性を検証する。
 * 区分A／Bは公式network、区分Cは利用者指定fileだけへ限定し、未定義または昇格した区分をfail-closedで拒否する。
 * @param[in] candidate 検証する一件の候補。 検証する候補。
 * @param[in] provider `candidate.providerId`に対応するProvider定義。 候補のProvider定義。
 * @return 探索経路、capability、および取得元tierが矛盾しない場合は`true`。 探索経路とregistry境界が一致する場合は`true`。
 */
[[nodiscard]] bool isCandidateDiscoveryBasisValid( const UpdateCandidate	   &candidate,
												  const ProviderDescriptor &provider) noexcept ;

/**
 * @brief 一方の候補別既定選択根拠を他方より先に扱うか判定する。
 * 候補別既定選択根拠の優先順を比較する。
 * OEM、reference component、managed、generic、noneの順にする。
 * @param[in] left 比較する一方の既定選択根拠。 比較する一方の根拠。
 * @param[in] right 比較する他方の既定選択根拠。 比較する他方の根拠。
 * @return `left`を初期選択で優先する場合は`true`。 leftを先に扱う場合は`true`。同順位または定義外値は`false`。
 * @note 同順位または定義外値の場合は`false`とし、scan結果内の順序を維持する。
 */
[[nodiscard]] bool candidateDefaultPreferencePrecedes( CandidateDefaultPreference left,
													  CandidateDefaultPreference right) noexcept ;

/**
 * @brief 候補別既定選択根拠が候補状態とProviderの信頼境界に一致するか検証する。
 * 候補別既定選択根拠の整合性を検証する。
 * 根拠の昇格をProvider種別と推奨通常更新条件でfail-closedに制限する。
 * @param[in] candidate 検証する一件の候補。 検証する候補。
 * @param[in] provider `candidate.providerId`に対応するProvider定義。 候補のProvider定義。
 * @return 根拠、候補状態、およびProvider種別が矛盾しない場合は`true`。 候補状態とProvider境界が矛盾しない場合は`true`。
 */
[[nodiscard]] bool isCandidateDefaultPreferenceValid( const UpdateCandidate	  &candidate,
													 const ProviderDescriptor &provider) noexcept ;

/**
 * @brief 推奨通常更新から一device一候補の初期選択状態を作成する。
 * 検証根拠だけを比較し、同順位では先に確定した候補を維持する。
 * @param[in] candidates 集約済みscan候補。入力順はProvider workerが確定した順序である。
 * @param[in] providers Stable ID、capability、および取得元tierを持つProvider registry。
 * @return 正常時は候補と同じ要素数の選択状態。不正入力時は`std::nullopt`。 正常時は候補別選択状態。不正入力時は`std::nullopt`。
 * @note 区分B／Cは初期選択せず、同じ根拠では入力順を維持し、version、日付、titleを比較しない。
 */
[[nodiscard]] std::optional<std::vector<bool>> buildDefaultCandidateSelection(
	std::span<const UpdateCandidate> candidates, std::span<const ProviderDescriptor> providers) ;

} // namespace drivercrate
