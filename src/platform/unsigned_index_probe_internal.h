//------------------------------------------------------------------------------
/**
 * @file unsigned_index_probe_internal.h
 * @brief 未署名CLI診断だけの有限な匿名照合件数を集計します。
 * @version 01.00.00
 * @date 2026/11/07
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/07  CLI診断の既loopを非権限の共通値へ抽出。
 * </pre>
 * @note 認証receipt/lookup/proof/planを発行しません。callerの同期callbackを借用するだけです。
 * @see docs/adr/0458-bounded-index-capacity-and-owned-state-maps.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/index_capacity_limits.h"
#include "platform/signed_index_record_lookup.h"
#include <cstddef>
#include <span>
#include <vector>

namespace drivercrate::unsigned_index_probe_detail {
/** @brief 一原recordに対する非機密診断件数です。 */
struct Row {
	/// 元recordの順序です。IDやhashを保持しません。
	std::size_t recordOrdinal{} ;
	/// 元callbackが返したopaque関係件数だけです。
	std::size_t positiveRelations{} ;
	/// 元未完了又はerror付きcallback件数です。
	std::size_t unknownIds{} ;
} ;
/** @brief 全recordの診断進行だけを所有する未認証結果です。 */
struct Result {
	/// 全recordの全IDが有限枠内で終了した場合だけtrueです。
	bool			 completed{} ;
	/// 実callback件数です。
	std::size_t		 calls{} ;
	/// 一関係以上を持つrecord件数です。適合/導入成功ではありません。
	std::size_t		 matchedRecords{} ;
	/// 原record順の完全行だけです。途中容量拒否は成功reportへ出しません。
	std::vector<Row> rows ;
} ;
/** @brief 既CLIの件数loopを未認証値だけで同期実行します。
 * @param[in] records callerが同じ値codecで全hash/schema/期限を確認した原recordです。
 * @param[in] context 同native factoryの元contextです。
 * @param[in] present 同factoryの全opaque集合です。resolverが毎query再照合します。
 * @param[in] resolver 同一threadで借用する現在属性callbackです。
 * @return 完全終了又は次record容量拒否と匿名件数です。認証や実適合を証明しません。
 * @throws 同期callback又は確保の例外をcallerへそのまま返します。
 * @note 全体枠は固定で、一recordの途中から後続へ飛びません。秘密値を保存しません。
 */
[[nodiscard]] inline Result probe( std::span<const IndexDistributionRecord> records,
								  IndexLookupContext context, std::span<const std::wstring> present,
								  const IndexPublicIdResolver &resolver)
{
	Result result ;	// 不完全を完了へ補完しない初期状態です。
	// 元record順に全IDを照合し、次recordが残枠へ収まらなければ停止します。
	for( const auto &record : records) {
		// 次record全体が収まらない場合は、部分行や成功reportを発行しません。
		if( record.publishedIdentityEvidence.pnpIds.size() >
		   index_capacity::WHOLE_PUBLIC_IDS - result.calls) {
			return result ;
		}

		Row row{result.rows.size(), 0U, 0U} ;	// 同recordだけの匿名行です。
		// PUBLISHED側の役割をnative属性指定へ転用せず、元classと全opaqueを渡します。
		for( const auto &id : record.publishedIdentityEvidence.pnpIds) {
			++result.calls ;
			const auto resolution =
				resolver.resolve( id.kind, id.value, record.publishedIdentityEvidence.classGuid,
								 context, present) ;	// 同期借用だけです。
			row.positiveRelations += resolution.devices.size() ;
			row.unknownIds += !resolution.completed || resolution.error != 0U ? 1U : 0U ;
		}

		result.matchedRecords += row.positiveRelations != 0U ? 1U : 0U ;
		result.rows.push_back( row) ;
	}

	result.completed = true ;
	return result ;
}
} // namespace drivercrate::unsigned_index_probe_detail
