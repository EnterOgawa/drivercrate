//------------------------------------------------------------------------------
/**
 * @file official_rtf_terms.h
 * @brief 公式配布に埋め込まれたRTFを表示用本文へ変換します
 * @version 01.00.00
 * @date 2026/11/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * </pre>
 *
 * @note 原バイトの出所とハッシュの検証は呼出し側が担当します
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <span>
#include <string>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief 有限なRTFの本文をUnicodeのプレーンテキストへ変換します
 *
 * 本文の文字と順序を保持し、段落と明示改行をCRLFへ変換します
 *
 * @param[in] source 呼出し中だけ借用する原RTF全体です
 * @param[out] body 成功した場合は全文、失敗した場合は空文字列です。sourceと記憶領域を共有できません
 * @return 対応形式で全文を表示できる場合true、形式・文字・上限の拒否時はfalseです
 * @throws std::bad_alloc 本文または解析状態に必要な記憶を確保できない場合です
 * @note 埋込みコードや外部参照を処理する機能は持ちません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeOfficialRtfTerms( std::span<const std::byte> source, std::wstring &body) ;

} // namespace drivercrate
