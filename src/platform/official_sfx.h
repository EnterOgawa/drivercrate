//------------------------------------------------------------------------------
/**
 * @file official_sfx.h
 * @brief 公式自己解凍形式の静的識別定義。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z形式の静的識別を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate直前zero paddingへ対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式EXEを実行せず、PE image後方に付加された単一7z streamの境界とCRCを検証します。Certificate直前はPE仕様に必要なzero paddingだけを受理
 *       します。本fileの契約は展開、真正性、driver適用性を保証しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace drivercrate {

/**
 * @brief PE末尾7z自己解凍形式を識別するときの有限上限を表す。
 */
struct OfficialSfxInspectionPolicy {
	/// 入力EXE全体の最大byte数。
	std::uint64_t maximumExecutableBytes ;
	/// PE image末尾から7z開始までの最大byte数。
	std::uint64_t maximumStubBytes ;
	/// Certificateを除く7z streamの最大byte数。
	std::uint64_t maximumArchiveBytes ;
} ;

/**
 * @brief 構造とCRCを検証したPE末尾7z streamのfile内範囲を表す。
 */
struct OfficialSfxLayout {
	/// 7z signature先頭のfile offset。
	std::uint64_t archiveOffset{} ;
	/// Paddingを含まない7z streamのbyte数。
	std::uint64_t archiveSize{} ;
	/// Certificate直前の検証済みzero byte数。
	std::uint64_t certificatePaddingSize{} ;
	/// 7z Next Header先頭のfile offset。
	std::uint64_t nextHeaderOffset{} ;
	/// CRC検証済みNext Headerのbyte数。
	std::uint64_t nextHeaderSize{} ;
	/// PE certificate table先頭。未存在時は0。
	std::uint64_t certificateOffset{} ;
	/// PE certificate table長。未存在時は0。
	std::uint64_t certificateSize{} ;
} ;

/**
 * @brief PE image後方の単一7z streamを、実行も展開もせず識別する。
 * PE image後方の単一7z streamを識別する。
 * EXEを実行・展開せず、全検査成功後だけ出力範囲を確定する。
 * @param[in] executable 公式取得後のEXE全体。有効期間は本呼出し中に限る。
 * @param[in] policy 入力、stub走査、7z streamへ適用する有限上限。 入力、stub走査、7z streamの有限上限。
 * @param[out] layout 成功時の7z、zero padding、certificate table範囲。失敗時は既定値。 成功時の7zおよびcertificate範囲。
 * @return 成功時は0、引数、上限、PE／7z構造またはCRC不正時はHRESULT bit pattern。 成功時は0、引数、上限、PE／7z構造、CRC不正時はHRESULT。
 * @note 本関数はfileを実行・展開せず、署名、publisher、driver適用性も判定しない。
 */
[[nodiscard]] NativeError inspectOfficialSevenZipSfx( std::span<const std::byte>			executable,
													 const OfficialSfxInspectionPolicy &policy,
													 OfficialSfxLayout &layout) noexcept ;

} // namespace drivercrate
