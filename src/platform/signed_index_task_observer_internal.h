//------------------------------------------------------------------------------
/**
 * @file signed_index_task_observer_internal.h
 * @brief 内部UI targetだけの承認済みtask同期観測を宣言します。
 * @version 01.00.00
 * @date 2026/10/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/15  同workerの実claim済みtaskへnoexcept観測を限定。
 * </pre>
 *
 * @note 通常platformでは型と登録関数を生成しません。借用は同期callback中だけです。
 * @see docs/adr/0342-approved-index-task-observation.md
 */
//------------------------------------------------------------------------------
#pragma once

// UI専用objectと同targetの試験だけへ宣言し、通常製品の登録能力を増やしません。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER) && defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_scan.h"
#include <cstdint>

namespace drivercrate::signed_index_task_observer_detail {
/** @brief 同workerがclaimしたtaskへ同期中だけ借用する非throwing観測関数型です。
 * @note stateはworkerのstop/joinまで試験が所有します。残る全参照はcallback中だけ有効です。
 * 元taskの所有copyだけを変更し、元session/adapterの拒否と元scan summaryを読み取ります。
 * UI assertionや別threadへの参照移転を行わず、元task/grant/結果を置き換えません。
 */
using ApprovedTaskObserver = void ( *)( void *state, OfficialPreparationSession &preparation,
									  const OfficialPreparationTask &task,
									  SignedIndexAcquisitionAdapter &adapter,
									  IndexLookupContext context, std::uint64_t nowUtcSeconds,
									  const SignedIndexScanSession &scan) noexcept ;

/** @brief 同worker threadへ一組の観測pointerを登録し、null対で解除します。
 * @param[in] observer 非nullはstateと対で登録します。nullはstateもnullの場合だけ解除します。
 * @param[in] state Workerのstop/joinまで有効な非所有pointerです。関数と対でnullを受理します。
 * @return 空slotへの登録またはnull対の解除はtrue、不整合または重複登録はfalseです。
 * @note 同workerだけから呼びます。例外・blocking・製品への登録fallbackはありません。
 */
[[nodiscard]] bool registerApprovedIndexTaskObserver( ApprovedTaskObserver observer,
													 void				 *state) noexcept ;
} // namespace drivercrate::signed_index_task_observer_detail
#endif
