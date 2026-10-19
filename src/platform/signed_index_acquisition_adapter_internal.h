//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_adapter_internal.h
 * @brief 製品設定へ注入できない固定RAM fixture取得policyを宣言します。
 * @version 01.01.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  署名snapshotと同grant・共通取得の有限接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  私有構築済みbatchの同snapshot集約fixtureを追加。
 * </pre>
 *
 * @note 固定fixture-mainの隔離署名snapshotだけを扱います。任意鍵・host・bool設定を受けません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/signed_index_acquisition_adapter.h"
#include <span>
#include <utility>
namespace drivercrate::signed_index_acquisition_detail {
/** @brief 固定RAM fixture policyだけを有効にする内部friendです。 */
struct Access {
	/** @brief 同じ実開始検査へ固定fixture-main／revision1だけを渡します。
	 * @param[in,out] adapter 未開始adapter。
	 * @param[in] lookup 真署名・隔離commit／reload済みlookup。
	 * @param[in] current 同worker context。
	 * @param[in] targetOs 既知OS分類。
	 * @param[in] nowUtc 信頼UTC。
	 * @return 全開始検査成功0、それ以外は元拒否HRESULT。
	 */
	[[nodiscard]] static NativeError beginFixture(
		SignedIndexAcquisitionAdapter				  &adapter,
		std::shared_ptr<const SignedIndexRecordLookup> lookup, IndexLookupContext current,
		IndexTargetOs targetOs, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/** @brief 公開relationでなく実lookupだけを私有集約入口へ渡します。
	 * @param[in] snapshot 真署名・隔離保存の同じ原snapshot。
	 * @param[in] context 元scanの全context。
	 * @param[in] batches 正規lookupが私有構築したbatch。
	 * @param[in] nowUtc 信頼UTC。
	 * @return 同snapshot・全context成立時だけ不変集約。異なる原byte／世代を拒否します。
	 */
	[[nodiscard]] static IndexRecordLookupResult freezeFixture(
		std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, IndexLookupContext context,
		std::span<const SignedIndexRecordLookup> batches,
		std::optional<std::chrono::sys_seconds>	 nowUtc) noexcept
	{
		return SignedIndexRecordLookup::freezeOwnedBatches( std::move( snapshot), context, batches,
														   nowUtc) ;
	}
} ;
} // namespace drivercrate::signed_index_acquisition_detail
