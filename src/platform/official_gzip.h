//------------------------------------------------------------------------------
/**
 * @file official_gzip.h
 * @brief 公式GZip catalog展開定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 署名検証済みGZipを固定上限内で展開し、header、CRC32、ISIZEを検証します。Deflate処理は静的linkしたminizを使用し、外部runtimeを要求しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief 一つのGZip memberをmemory上で上限付き展開する。
 * Header、optional field、単一Deflate stream、CRC32、ISIZEを完全検証し、成功時だけ出力を更新する。
 * @param[in] compressed GZip container全体。有効期間は本呼出し中に限る。
 * @param[in] maximumExpandedBytes 展開を許可する最大byte数。
 * @param[out] expanded 成功時の展開済みbyte列。失敗時は空にする。 成功時の展開結果。失敗時は空。
 * @return 成功時は0、形式不正、上限超過、展開失敗時はHRESULT bit pattern。
 * @note Concatenated member、予約flag、壊れたCRC32またはISIZEを拒否する。
 */
[[nodiscard]] NativeError decompressOfficialGzip( std::span<const std::byte> compressed,
												 std::uint64_t				maximumExpandedBytes,
												 std::vector<std::byte>	   &expanded) ;

/**
 * @brief Local GZip fileを読み、呼出し側が所有する新規file handleへ展開する。
 * Local GZip fileを新規file handleへ上限付き展開する。
 * 入出力pathをcontainer metadataから構成せず、署名済みbyte列全体を検証した後だけ保護workspaceへ書き込む。
 * @param[in] inputPath 署名検証済みGZipのlocal絶対path。 署名検証済みGZip絶対path。
 * @param[in] maximumCompressedBytes 入力fileの最大byte数。 入力file上限byte数。
 * @param[in] maximumExpandedBytes 展開後の最大byte数。 展開後上限byte数。
 * @param[in] outputFile 書込み可能で現在位置が先頭の所有外file handle。 呼出し側所有の新規file handle。
 * @return 成功時は0、file検証、展開、書込み失敗時はHRESULT bit pattern。 成功時は0、file、展開、書込み失敗時はHRESULT。
 * @pre `outputFile`は保護workspace内へCREATE_NEWした通常fileであること。
 */
[[nodiscard]] NativeError decompressOfficialGzipFile( std::wstring_view inputPath,
													 std::uint64_t	   maximumCompressedBytes,
													 std::uint64_t	   maximumExpandedBytes,
													 HANDLE			   outputFile) ;

} // namespace drivercrate
