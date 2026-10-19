//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_ledger.h
 * @brief 区間に依存しない共有制御・予算の有限byte契約を定義します。
 * @version 01.00.00
 * @date 2026/10/01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/01  共有台帳の専用型・codec・非変更carryを追加。
 * </pre>
 *
 * @note 保存・通信・取得許可を発行しない開発用coreです。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "local_collector_campaign.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace drivercrate {

/** @brief 旧CACHEの個別検査に渡すhash参照です。検証済み証明ではありません。 */
struct CollectorSharedCacheReference {
	/// 元CACHEを保持する区間の小文字SHA-256。
	std::wstring segment ;
	/// 登録CACHE本文の小文字SHA-256。
	std::wstring cacheSha256 ;
	/// 元artifact／parser／policy／scopeのbinding hash。
	std::wstring binding ;
} ;

/** @brief 恒久requestの現在制御と旧CACHEへの直接参照です。 */
struct CollectorSharedRequestState {
	/// 元観測・待機・review・開始intentを保持する制御値。
	CollectorWaitControl						 control ;
	/// 根拠未保持はnullopt。存在だけで再利用を許しません。
	std::optional<CollectorSharedCacheReference> cache ;
} ;

/** @brief 最大4096 requestの現在値です。保存元の公式性を証明しません。 */
struct CollectorSharedLedgerSnapshot {
	/// Manifest・artifact・区間から独立したcollectionの完全hash。
	std::wstring										collection ;
	/// 保存観測UTCの最高millisecond。時計後退を許しません。
	std::uint64_t										lastUtcMillis{} ;
	/// 既存意味を維持する元JST日の最大1200予約。
	CollectorBudgetSnapshot								budget ;
	/// 生group key昇順の最大20行。g-接頭辞は付けません。
	std::map<std::wstring, CollectorWaitControl>		groups ;
	/// 完全request hash昇順の最大4096行。r-接頭辞は付けません。
	std::map<std::wstring, CollectorSharedRequestState> requests ;
} ;

/** @brief Hash envelopeをまだ付けていない固定66 canonical本文です。 */
struct CollectorSharedLedgerBytes {
	/// Collectionに結合した元予算object。最大768 KiB。
	std::string					 budget ;
	/// Group現在値の固定順本文。最大768 KiB。
	std::string					 groups ;
	/// 00～3fのordinal順。空shardも省略しません。
	std::array<std::string, 64U> requests ;
} ;

/**
 * @brief 関係・上限を検査して固定66本文を作ります。
 * @param[in] snapshot Caller所有の状態。関数中は変更しません。
 * @param[out] bytes 成功時だけの本文。失敗時は空です。
 * @return 成功0、不正13、容量68、確保失敗8。保存・予約は行いません。
 * @note 入出力のaliasを禁止します。保護store・seal・公式性は未検査です。
 */
[[nodiscard]] DWORD encodeCollectorSharedLedger( const CollectorSharedLedgerSnapshot &snapshot,
												CollectorSharedLedgerBytes &bytes) noexcept ;

/**
 * @brief 全shardと元予算を完全再結合し、途中の状態を公開しません。
 * @param[in] bytes 所有66本文。全byteをこの呼出し中保持してください。
 * @param[out] snapshot 全成立時だけの値。失敗時は空です。aliasは禁止です。
 * @return 成功0、不正13、容量68、確保失敗8。保存や通信を行いません。
 */
[[nodiscard]] DWORD decodeCollectorSharedLedger( const CollectorSharedLedgerBytes &bytes,
												CollectorSharedLedgerSnapshot &snapshot) noexcept ;

/**
 * @brief 閉鎖済み同一台帳の値を変えないcarry条件だけを判定します。
 * @param[in] before 切替前のcaller snapshot。検証済みsealとは扱いません。
 * @param[in] after 切替後のcaller snapshot。全66本文の完全一致を要求します。
 * @param[in] utcMillis 今回検査UTC。最高値以上かつ許可時刻範囲です。
 * @return 非変更・未精算なし0、不成立13、容量68、確保失敗8。
 * @note 判定0でもwriter能力・切替許可・HTTP許可は発行しません。
 */
[[nodiscard]] DWORD checkCollectorSharedLedgerCarry( const CollectorSharedLedgerSnapshot &before,
													const CollectorSharedLedgerSnapshot &after,
													std::uint64_t utcMillis) noexcept ;

} // namespace drivercrate
