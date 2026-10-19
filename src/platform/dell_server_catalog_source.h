//------------------------------------------------------------------------------
/**
 * @file dell_server_catalog_source.h
 * @brief Dell PowerEdge署名済みcatalog取得定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得根拠記録追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Dell Enterprise Catalogとdetached signatureを同じ保護workspaceへ取得し、固定公開鍵、GZip、UTF-16上限を検証してからXMLを
 *       返します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_provider.h"
#include "platform/official_http_client.h"

#include <string>

namespace drivercrate {

/**
 * @brief Dell Enterprise catalog取得とmetadata検証の結果である。
 */
struct DellServerCatalogLoadResult {
	/// 失敗時のHRESULT bit pattern。
	NativeError	 error{} ;
	/// 署名、GZip、encoding拒否ならtrue。
	bool		 metadataRejected{} ;
	/// 成功時のUTF-16 Enterprise catalog XML。
	std::wstring xml ;
} ;

/**
 * @brief Dell公式Enterprise catalogを取得してOpenPGP検証後に展開する。
 * Dell公式Enterprise catalogを署名検証して展開する。
 * Download失敗とmetadata拒否を分離し、署名成功前にGZipを展開しない。
 * @param[in] client 公式host allowlistとsystem proxyを使用するHTTP client。 公式HTTP client。
 * @param[in] scanSessionId 0ではないscan session ID。
 * @param[in] progressCallback 取得、署名検証、展開の確定進捗通知先。 確定段階の進捗通知先。
 * @return 成功時はXML、失敗時は分類とHRESULTを保持する結果。 成功時のUTF-16 XML、または失敗分類とHRESULT。
 * @note Provider固定のDell公開鍵だけを信頼し、networkから鍵を取得しない。
 */
[[nodiscard]] DellServerCatalogLoadResult loadDellServerCatalog(
	OfficialHttpClient &client, ScanSessionId scanSessionId,
	const ProviderProgressCallback &progressCallback) ;

} // namespace drivercrate
