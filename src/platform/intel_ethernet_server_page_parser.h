//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_server_page_parser.h
 * @brief Intel Ethernet Server／Windows 11公式download page parser定義。
 * @version 01.03.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  同一pageの許諾snapshotを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows 11 record専用profileを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  制御付きWindows 11 core入口を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/26  公開SHA-512をSHA-256と分けて保持。
 * </pre>
 *
 * @note Intel EthernetのServer 2025とWindows 11を別profileで解析します。取得元の確認と
 *       record生成に限定し、INF適用性、OEM互換性、導入許可を発行しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/collector_parser_control.h"

#include <string>
#include <string_view>

namespace drivercrate {

/**
 * @brief Intel Ethernet公式pageから取得したprofile別metadataです。
 * @note 対象OSと製品markerは呼出した専用parserが固定し、本型だけではprofileを表しません。
 */
struct IntelEthernetDownloadPageMetadata {
	/// ZIP名とdriver package表示が一致した配布版。
	std::wstring version ;
	/// 対象profile向けx64 ZIPのbasename。
	std::wstring fileName ;
	/// Intel公式mirror上のHTTPS URL。取得許可ではない。
	std::wstring downloadUrl ;
	/// 公式pageの概算size。完全性検証には使用しない。
	std::wstring displaySize ;
	/// 公式pageが表示した64桁uppercase SHA-256。
	std::wstring sha256 ;
	/// 公式pageが表示した128桁ASCII hexのSHA-512。未掲載は空。
	std::wstring sha512 ;
	/// trueの場合は取得前の利用許諾同意が必要。
	bool		 requiresEula{} ;
	/// 同一pageの明示許諾名と版。許諾欄がない場合は空。
	std::wstring eulaRevision ;
	/// Title付きの完全plain text。取得同意や法的判断ではない。
	std::wstring eulaText ;
} ;

/**
 * @brief 既存Server 2025 parser APIが使用するmetadata型です。
 */
using IntelEthernetServerPageMetadata = IntelEthernetDownloadPageMetadata ;

/**
 * @brief Intel Ethernet Windows Server 2025向けdownload pageを有限規則で解析する。
 * 公式page情報だけを返す。INF／CAT、現在PnP ID、OEM差分、導入可否は後段で判定する。
 * @param[in] html Intel公式hostから取得したUTF-16 HTML。
 * @param[out] metadata 成功時の表示専用metadata。失敗時は初期値。
 * @return 対象OS、x64 ZIP、公式URL、版、size、少なくとも一方の公開SHA-256／SHA-512、EULA表示が整合する場合true。
 * @note 本結果は公式配布情報であり、現在deviceへの適用性やOEM推奨を保証しない。
 * @note 許諾欄がある場合は完全なsnapshotを要求する。不正欄を空として受理しない。
 */
[[nodiscard]] bool parseIntelEthernetServerDownloadPage( std::wstring_view				 html,
														IntelEthernetServerPageMetadata &metadata) ;

/**
 * @brief Intel record 727998のWindows 11 x64 download pageを有限規則で解析します。
 * @param[in] html Intel公式hostの固定recordから取得したUTF-16 HTML。
 * @param[out] metadata 成功時のWindows 11配布metadata。失敗時は初期値。
 * @return Windows 11、E610-XT2掲載、x64 ZIP、公式URL、版、size表示、公開SHA-256／SHA-512、
 *         EULA表示が整合する場合は`true`。
 * @note Exact byte数を概算sizeから推測せず、取得、同意、適用性または導入を行いません。
 */
[[nodiscard]] bool parseIntelEthernetWindows11DownloadPage(
	std::wstring_view html, IntelEthernetDownloadPageMetadata &metadata) ;

/**
 * @brief 同じWindows 11配布coreへ必須制御を伝播します。
 * @param[in] html 同じ公式本文。
 * @param[out] metadata 非採用時は初期値。
 * @param[in,out] context 元GETの制御。
 * @return 配布非採用はfalse。停止・障害は上位境界へ伝播します。
 */
[[nodiscard]] bool parseIntelEthernetWindows11DownloadPageForCollector(
	std::wstring_view html, IntelEthernetDownloadPageMetadata &metadata,
	CollectorParserContext &context) ;
} // namespace drivercrate
