//------------------------------------------------------------------------------
/**
 * @file index_capacity_limits.h
 * @brief 索引全体・一batch・保持・native JSONの有限容量を用途別に定義します。
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
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/07  全索引入力とbatch・保持・purpose別byte枠を分離。
 * </pre>
 *
 * @note 件数とbyte・時間は独立に検査します。権限や原期限を追加・延長しません。
 * @see docs/adr/0458-bounded-index-capacity-and-owned-state-maps.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <cstddef>

namespace drivercrate::index_capacity {

// 一索引の公開ID入力総数。保持tuple数とは別です。
inline constexpr std::size_t WHOLE_PUBLIC_IDS = 1048576U ;
// 一索引の全record数です。
inline constexpr std::size_t RECORDS = 65536U ;
// 一索引の公開source数です。
inline constexpr std::size_t SOURCES = 4096U ;
// 一同期batchのrecord数です。
inline constexpr std::size_t BATCH_RECORDS = 256U ;
// 一同期batchのresolver呼出数です。
inline constexpr std::size_t BATCH_PUBLIC_IDS = 32768U ;
// 同scanが保持する関係tuple数です。全入力総数ではありません。
inline constexpr std::size_t RETAINED_RELATIONS = 32768U ;
// 全関係と個別投影が保持するopaque総数です。
inline constexpr std::size_t RETAINED_OPAQUE_IDENTITIES = 32768U ;
// 同native inventoryがcaptureする秘密IDの総数です。
inline constexpr std::size_t NATIVE_INVENTORY_IDS = 32768U ;
// 同scanの全present集合の件数です。
inline constexpr std::size_t PRESENT = 4096U ;
// stateのtargetsとhostsそれぞれの歴史entry枠です。
inline constexpr std::size_t STATE_MAP_ENTRIES = 8192U ;
// 同時に読み込む外部定義の個数です。
inline constexpr std::size_t DEFINITIONS = 1024U ;
// 定義と原bootstrapからなる閉JSON集合です。
inline constexpr std::size_t DEFINITION_JSON_FILES = DEFINITIONS + 1U ;
// JSON集合とManager・LICENSE・NOTICE・manifestからなる閉program集合です。
inline constexpr std::size_t PROGRAM_FILES = DEFINITION_JSON_FILES + 4U ;
// 一recordの公表側ID数です。
inline constexpr std::size_t RECORD_IDS = 4096U ;
// 一recordのbase64解除後の原byte枠です。
inline constexpr std::size_t RECORD_BYTES = 512U * 1024U ;
// 全record原byteの合計枠です。
inline constexpr std::size_t TOTAL_RECORD_BYTES = 64U * 1024U * 1024U ;
// header/footerを含む原gzipの枠です。
inline constexpr std::size_t GZIP_BYTES = 32U * 1024U * 1024U ;
// 共通codecの展開byteと同purposeのindex JSON枠です。
inline constexpr std::size_t EXPANDED_BYTES = 128U * 1024U * 1024U ;
// 元gzip全containerに対する最大展開倍率です。
inline constexpr std::size_t COMPRESSION_RATIO = 128U ;
// generic state/config及び定義集合の原byte枠です。
inline constexpr std::size_t LOCAL_BYTES = 64U * 1024U * 1024U ;
// 全scanの協調期限です。同期処理の強制終了を保証しません。
inline constexpr std::size_t SCAN_MILLISECONDS = 30000U ;
// 一batchの協調期限です。
inline constexpr std::size_t BATCH_MILLISECONDS = 5000U ;

} // namespace drivercrate::index_capacity
