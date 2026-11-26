//------------------------------------------------------------------------------
/**
 * @file collector_property_page_export_internal.h
 * @brief 収集用の元PEとインポート・エクスポートを非実行で検査します
 * @version 01.01.00
 * @date 2026/11/19
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/19  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/24  USB無線の元EXEと同梱DLLの直接依存検査を追加
 * </pre>
 *
 * @note 呼出し中の原byteだけを借用し、信頼・実行・導入の権限を生成しません
 * @see docs/adr/0515-collector-device-property-page-validation.md
 * @see docs/adr/0582-catalog-usb-wireless-quoted-service.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include <cstddef>
#include <span>
#include <string_view>

namespace drivercrate {
// ローダーを使わずに固定する単一の元DLLのbyte上限です
inline constexpr std::size_t MAXIMUM_PROPERTY_PAGE_DLL_BYTES = 64U * 1024U * 1024U ;

//------------------------------------------------------------------------------
/**
 * @brief 元AMD64 DLLのexport表と宣言された一意なcallbackを静的に照合します
 * @param[in] bytes 呼出し中固定した原file全体の読取り専用byte列です
 * @param[in] callback 元INFの大小文字を保持したASCII名です
 * @return 実行可能節の原byteへ一意に到達すれば0、不正形式はHRESULTです
 * @note DLLをロードせず、内容の一致だけを扱います。CAT照合と導入判定は呼出し元の別工程です
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError	 inspectCollectorPropertyPageExport( std::span<const std::byte> bytes,
																std::wstring_view		   callback) ;

/** @brief 収集側で同じ配置と照合した一つの元PEです */
struct CollectorPeFile {
	/// 同じディレクトリーへのコピーを検査した元のファイル名です
	std::wstring_view		   name ;
	/// 全バイトのハッシュを照合して同期中だけ固定した読取り範囲です
	std::span<const std::byte> bytes ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元USB無線の補助EXEと三つの同梱DLLの直接インポートを静的に照合します
 * @param[in] files 同じ元CATと選択コピーへ結んだ補助EXEと三つのDLLです。並びは任意です
 * @return 元配置、既知Windows側の名前、同梱関数の非転送exportを照合できれば0です
 * @note 実行時に選ぶ追加モジュールや端末の状態は検査しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectScopedUsbWirelessPeImports(
	std::span<const CollectorPeFile, 4U> files) ;
} // namespace drivercrate
