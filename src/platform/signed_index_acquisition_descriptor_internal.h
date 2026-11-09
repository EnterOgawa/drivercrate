//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_descriptor_internal.h
 * @brief 署名索引の取得descriptorに限定した共通型読取りと整合検査を宣言します。
 * @version 01.04.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  PAGEとpayload由来証拠のquery用途を明示分離。
 * Ver.01.02.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続。
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
void									  requireUrl( std::string_view value, bool pageQuery) ;

/** @brief 原payload URLだけに単一公開cache版queryを認めます。
 * @param[in] value 原ASCII URLです。認証queryや複合値は拒否します。
 * @note PAGEの数値selectorをpayload用途へ追加しません。
 */
void									  requirePayloadUrl( std::string_view value) ;

/** @brief PAGEまたはpayloadを出典にできる証拠URLの既存数値/公開cache版を検査します。
 * @param[in] value 根拠の原ASCII URLです。通信値を書き換えません。
 * @note sourceのdistributionPageと公式性attestationはrequireUrlでPAGEとして別検査します。
 */
void									  requireEvidenceUrl( std::string_view value) ;

/** @brief v2の閉じた取得方法と三段resource計画をstrict readerで読む。
 * @param[in,out] reader 元recordを借用するstrict reader。
 * @param[out] anonymousCdn 明示された匿名解決の公開値。STATIC_URL時は空。
 * @return 全静的結合を成功した計画。取得/導入能力はない。
 */
[[nodiscard]] OfficialResourceContentPlan readResourcePayloadPlan(
	DescriptorReader &reader, std::optional<OfficialAnonymousCdnPlan> &anonymousCdn) ;

/** @brief Descriptorのv1全13fieldまたはv2全14fieldと全入れ子をstrict readerで読みます。
 * @param[in,out] reader 原recordの有限reader。呼出し中だけ借用します。
 * @param[in] readText 既存Known textの同期parser。Null不可、参照を保持しません。
 * @return 全構造検査を成功した元申告。取得能力はありません。
 * @note Source・manifest・record方式への結合はvalidateBindingで別に検査します。
 */
[[nodiscard]] IndexAcquisitionDescriptor readDescriptor( DescriptorReader &reader,
														TextValueReader	  readText) ;

/** @brief 既存strict readerで一つの規約宣言を閉検証します。
 * @param[in] raw 最大512KiBの原JSONです。本文ではなく固定文書情報だけです。
 * @return 観測や同意を発行しない型付き規約です。
 */
[[nodiscard]] IndexAcquisitionTerms		 readTermsValue( std::string_view raw) ;

/** @brief 元recordとsource・manifestへの取得情報の結合だけを検査します。
 * @param[in] record 原byteへ結合した読取り済みrecord。値を補完しません。
 * @param[in] source 一意に解決した同indexのsource。
 * @param[in] manifest 原byte認証済みmanifest。確認時刻を更新しません。
 * @note Size上限超過の元申告recordは保持します。後段の容量保留とgrant判断は別です。
 */
void validateBinding( const IndexDistributionRecord &record, const IndexRecordSource &source,
					 const IndexManifestData &manifest) ;

} // namespace drivercrate::signed_index_acquisition
