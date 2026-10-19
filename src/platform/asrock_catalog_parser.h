//------------------------------------------------------------------------------
/**
 * @file asrock_catalog_parser.h
 * @brief ASRock公式最新driver一覧parser定義。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定ASRock公式pageの表示情報を有限に解析します。製品名、driver種別、OS以外からPnP適用性を推測せず、payload URLを返しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_catalog_device.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// ASRock公式page値型定義。
//------------------------------------------------------------------------------

/**
 * @brief ASRock公式page上のdriver区分を表す。
 */
enum class AsrockDriverKind {
	/// 個別PnP deviceへ安全に関連付けられない区分。
	UNSUPPORTED,
	/// Ethernet LAN driver区分。
	NETWORK,
	/// Wireless LAN driver区分。
	WIRELESS,
	/// Bluetooth driver区分。
	BLUETOOTH,
	/// Audio driver区分。
	AUDIO,
	/// Display driver区分。
	DISPLAY,
} ;

/**
 * @brief ASRock公式最新driver一覧の一行から得た表示専用情報である。
 */
struct AsrockDriverPageEntry {
	/// ASRockが表示するdriver名称。
	std::wstring	 title ;
	/// `ver:`の後に表示されたpackage revision。
	std::wstring	 version ;
	/// `M/D/YYYY`形式の公式掲載日。
	std::wstring	 releaseDate ;
	/// ASRockが表示する概算download size。
	std::wstring	 sizeText ;
	/// Local表示名との照合に使用するmaker key。
	std::wstring	 vendorKey ;
	/// Driver種別。
	AsrockDriverKind kind{AsrockDriverKind::UNSUPPORTED} ;
} ;

//------------------------------------------------------------------------------
// ASRock公式page parser定義。
//------------------------------------------------------------------------------

/**
 * @brief 固定ASRock公式pageからlocal boardとOSに一致するdriver表示情報を取得する。
 * ASRock公式最新driver一覧を解析する。
 * ModelとOSが一致し、PnP classとmakerを限定できる行だけを返す。不正な一行があれば部分結果を公開しない。
 * @param[in] html ASRock公式Latest Drivers Update pageのUTF-16 HTML。 固定公式pageのUTF-16 HTML。
 * @param[in] boardModel SMBIOSから得たASRock baseboard model表示値。 Local ASRock boardの完全一致model。
 * @param[in] osName `Windows 10 64bit`または`Windows 11 64bit`。 Local Windows x64区分。
 * @param[out] entries 成功時の対応driver表示情報。該当なしの場合は空にする。 成功時の表示専用driver情報。
 * @return Table schemaと全採用行の必須metadataが有効な場合は`true`。 公式table schemaと全採用行が有効な場合は`true`。
 */
[[nodiscard]] bool parseAsrockLatestDriverHtml( std::wstring_view html, std::wstring_view boardModel,
											   std::wstring_view				   osName,
											   std::vector<AsrockDriverPageEntry> &entries) ;

/**
 * @brief ASRock表示情報を一つのlocal PnP deviceへ関連付けられるか判定する。
 * ASRock表示情報をlocal PnP deviceへ関連付ける。
 * Versionまたは日付を使わず、表示専用の関連付けだけを行う。
 * @param[in] entry 検証済みASRock表示情報。
 * @param[in] device Driver Store列挙から得た非機密device snapshot。 非機密local device snapshot。
 * @return Driver classとmaker表示が両方一致する場合は`true`。 Setup classとmaker表示が両方一致する場合は`true`。
 * @note 本判定は表示用の関連付けだけであり、PnP適用性またはinstall許可を意味しない。
 */
[[nodiscard]] bool asrockEntryMatchesDevice( const AsrockDriverPageEntry &entry,
											const OfficialCatalogDevice &device) ;

} // namespace drivercrate
