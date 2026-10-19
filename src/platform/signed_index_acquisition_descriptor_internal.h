//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_descriptor_internal.h
 * @brief 署名索引の取得descriptorに限定した共通型読取りと整合検査を宣言します。
 * @version 01.00.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  v2 descriptorの有限文法・元申告整合検査を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Network、DNS、grant、同意、候補や導入許可は発行しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_records.h"
#include <string>
#include <string_view>

namespace drivercrate::signed_index_acquisition {

/**
 * @brief Record層と同じstrict readerだけを借用します。
 */
using DescriptorReader = signed_index_json::Reader<IndexRecordsStatus> ;
/**
 * @brief 既存Known text文法へ委譲する同期reader。所有値だけを返し参照を保持しません。
 */
using TextValueReader = IndexObservedValue<std::string> (*)( DescriptorReader &) ;

/** @brief 原HTTPS URLを共通URL parserと用途限定PAGE文法へ照合します。
 * @param[in] value 2048byte以内の原ASCII URL。値を書き換えません。
 * @param[in] pageQuery PAGEの閉じた公開数値selectorだけを認める指定。
 * @note DNS・実宛先・公式性・到達性を確認しません。不成立はcodecの固定拒否へ中断します。
 */
void									 requireUrl( std::string_view value, bool pageQuery) ;

/** @brief Descriptorの全13fieldと全入れ子をstrict readerで読みます。
 * @param[in,out] reader 原recordの有限reader。呼出し中だけ借用します。
 * @param[in] readText 既存Known textの同期parser。Null不可、参照を保持しません。
 * @return 全構造検査を成功した元申告。取得能力はありません。
 * @note Source・manifest・record方式への結合はvalidateBindingで別に検査します。
 */
[[nodiscard]] IndexAcquisitionDescriptor readDescriptor( DescriptorReader &reader,
														TextValueReader	  readText) ;

/** @brief 元recordとsource・manifestへの取得情報の結合だけを検査します。
 * @param[in] record 原byteへ結合した読取り済みrecord。値を補完しません。
 * @param[in] source 一意に解決した同indexのsource。
 * @param[in] manifest 原byte認証済みmanifest。確認時刻を更新しません。
 * @note Size上限超過の元申告recordは保持します。後段の容量保留とgrant判断は別です。
 */
void validateBinding( const IndexDistributionRecord &record, const IndexRecordSource &source,
					 const IndexManifestData &manifest) ;

} // namespace drivercrate::signed_index_acquisition
