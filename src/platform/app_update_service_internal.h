//------------------------------------------------------------------------------
/**
 * @file app_update_service_internal.h
 * @brief App更新の完全な非通信I/O注入だけを定義します。
 * @version 01.00.01
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 通常UIや設定から試験backendを指定する入口はありません。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/app_update_service.h"
#include "platform/official_http_client.h"
#include "platform/official_http_transport.h"
#include <filesystem>

namespace drivercrate::app_update_detail {
/** @brief 共通HTTPから返す最小の数値と確認本文です。 */
struct HttpResult {
	/// 実観測HTTP statusです。
	std::uint32_t status{} ;
	/// 配布元が要求した待機秒数です。
	std::uint64_t retryAfterSeconds{} ;
	/// metadata応答JSONを一時所有します。URLも含みますが永続化・log・実行権限へ保存しません。
	std::string	  metadata ;
} ;
/** @brief 完全fixtureだけが所有する署名/Explorer境界です。 */
struct Fixture {
	/// 架空の配置にあるApp fileの絶対pathです。
	std::filesystem::path appPath ;
	/// 全て非通信に置き換えたWinHTTP I/Oです。
	OfficialHttpTransport transport ;
	/// fixtureの元App版です。
	AppVersion			  current ;
	/// 署名・size・版の検証を完全に差し替えます。
	std::function<AppUpdateFailure( const std::filesystem::path &, const AppUpdateRelease &)> verify ;
	/// 通常userへの起動を完全に差し替えます。
	std::function<AppUpdateFailure( const std::filesystem::path &, const std::filesystem::path &)>
		launch ;
} ;
/** @brief 閉じたApp用途の共通HTTPと完全fixtureを接続します。 */
struct Access {
	/**
	 * @brief 任意URLを受け取らず固定用途だけを要求します。
	 * @param[in,out] client cacheなしの専用clientです。
	 * @param[in] release nullは固定latest、非nullは固定Setupです。
	 * @param[in] output Setup時だけの書込みfileです。
	 * @param[in,out] control この一回だけの期限/取消しです。
	 * @param[out] result status/待機と成功metadataです。
	 * @return 共通HTTPの元診断値です。
	 */
	[[nodiscard]] static NativeError					   http( OfficialHttpClient	   &client,
																const AppUpdateRelease *release, HANDLE output,
																SignedIndexHttpControl &control, HttpResult &result) ;
	/**
	 * @brief 全てをfakeへ置換したbackendを構築します。
	 * @param[in] fixture 完全なI/Oと所有配置です。
	 * @return 完全backend。欠損は例外で拒否します。
	 * @throws std::invalid_argument 配置が不正、必須seam欠損、または実通信APIが残る場合です。
	 * @throws std::bad_alloc 完全fixture backendの確保に失敗した場合です。
	 */
	[[nodiscard]] static std::unique_ptr<AppUpdateBackend> fixtureBackend( Fixture fixture) ;
} ;
}
