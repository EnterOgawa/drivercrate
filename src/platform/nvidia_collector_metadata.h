//------------------------------------------------------------------------------
/**
 * @file nvidia_collector_metadata.h
 * @brief NVIDIA公開queryとcollectorの同release再確認を定義します。
 * @version 01.01.00
 * @date 2026/11/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/05  登録公開queryと原API応答の同一性検査を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/11/05  不正応答と既知の非対象releaseを分離する契約を追記。
 * </pre>
 * @note metadata成功はpayload取得・内容検査・同意・導入の成功を意味しません。
 * @see docs/adr/0447-nvidia-collector-json-metadata.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/nvidia_catalog_parser.h"
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief 手動登録された公開catalog IDだけを持つ閉queryです。 */
struct NvidiaCollectorLookup {
	/// NVIDIA公開series IDです。端末inventoryではありません。
	std::wstring seriesId ;
	/// NVIDIA公開product IDです。端末inventoryではありません。
	std::wstring productId ;
	/// APIが定義するWindows x64 OS IDの57/135です。
	std::wstring osId ;
	/// trueはStudio、falseはGame Ready/securityの公開channelです。
	bool		 studio{} ;
} ;
/** @brief 解析拒否と公式空結果を分けるmetadata結果です。 */
enum class NvidiaCollectorMetadataStatus {
	/// Schema・query・flag字句・有効候補の一意性が不成立です。
	INVALID,
	/// 原API空結果または全行非対象です。成功driverではありません。
	NO_RESULT,
	/// 同じ公開query内で有効な非beta候補の一意な最大marketing版を選択しました。
	SELECTED,
} ;
/** @brief 任意queryを許さずcanonical公開lookupを読みます。
 * @param[in] url 定義内の未認証URLです。
 * @param[out] lookup 成功時の公開条件です。拒否時は初期値です。
 * @return 固定query条件に一致する場合trueです。
 */
[[nodiscard]] bool							parseNvidiaCollectorLookupUrl( std::wstring_view		 url,
																		  NvidiaCollectorLookup &lookup) ;
/** @brief 既存parserの公式host/ID検査と原Request echoを一致確認します。
 * @param[in] json 同APIの有限原JSON本文です。
 * @param[in] lookupUrl 登録したcanonical公開queryです。
 * @param[out] selected SELECTEDのときだけ一意な原releaseを返します。
 * @return 原metadataの不正・空結果または全行非対象・有効候補選択を区別します。
 * @note marketing版をINF四要素版へ変換しません。呼出し中はCOM apartmentが必要です。
 */
[[nodiscard]] NvidiaCollectorMetadataStatus selectNvidiaCollectorRelease(
	std::wstring_view json, std::wstring_view lookupUrl, NvidiaDriverEntry &selected) ;
} // namespace drivercrate
