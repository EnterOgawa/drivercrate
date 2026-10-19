//------------------------------------------------------------------------------
/**
 * @file official_catalog_cache.h
 * @brief 公式catalog cache定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Cache検証UTCの読取り値を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式catalog本文だけを管理者保護directoryへ保存し、URL key、size、SHA-256、検証時刻、ETagを再検証します。破損entryは利用しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式catalog cache型定義。
//------------------------------------------------------------------------------

/**
 * @brief 検証済みcache entryの期限状態である。
 */
enum class CatalogCacheState {
	/// Entryが存在しない状態。
	MISSING,
	/// 指定期限内でnetwork再検証を省略できる状態。
	FRESH,
	/// 本文は正常だがnetwork再検証が必要な状態。
	STALE,
	/// 破損または不整合を検出して破棄した状態。
	INVALIDATED,
} ;

/**
 * @brief 検証済みcache本文と条件付きrequest情報である。
 */
struct CatalogCacheEntry {
	/// Entryの期限または破棄状態。
	CatalogCacheState			 state{CatalogCacheState::MISSING} ;
	/// SHA-256検証済みcatalog本文。
	std::vector<std::byte>		 content ;
	/// 検証済みの任意ETag。
	std::wstring				 etag ;
	/// Sidecarのorigin検証UTC。変換不能時は空。
	std::optional<std::uint64_t> validatedUtcSeconds ;
} ;

/**
 * @brief 公式catalogだけを永続化するfail-closed cacheである。
 *
 * @note 既定rootはProgramData配下へSYSTEM／Administrators限定ACLで作成する。
 *       明示root constructorはnetworkを使用しない単体試験専用である。
 */
class OfficialCatalogCache final {
public:
	/**
     * @brief 管理者保護された既定cache rootを使用するobjectを作成する。
     */
	OfficialCatalogCache() = default ;

	/**
	 * @brief 単体試験が所有する既存親directory内のcache rootを使用する。
	 * 試験用cache rootを使用するobjectを作成する。
	 * Rootのlifetimeと削除は呼出し側が管理する。
	 * @param[in] rootOverride 試験終了時に呼出し側が削除する絶対path。 試験が所有する絶対directory path。
	 */
	explicit OfficialCatalogCache( std::wstring rootOverride) ;

	/**
	 * @brief URLに対応するcache本文をsize、SHA-256、期限付きで読み取る。
	 * URLに対応するcache本文を検証付きで読み取る。
	 * 不正metadata、size、hash、reparseを検出したentryは破棄する。
	 * @param[in] url 公式HTTPS resourceの完全なURL。 Cache keyの公式HTTPS URL。
	 * @param[in] maximumBytes 読取りを許可する本文上限byte数。
	 * @param[in] maximumAgeSeconds Freshとみなす最大経過秒数。0は常にStaleとする。 Fresh期限秒数。
	 * @param[out] entry 成功時のcache状態と検証済み本文。Missing時は本文なし。 検証済みcache状態と本文。
	 * @return Cache処理成功時は0、初期化またはI/O失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError load( std::wstring_view url, std::uint64_t maximumBytes,
								   std::uint64_t maximumAgeSeconds, CatalogCacheEntry &entry) const ;

	/**
	 * @brief Networkで再検証したcatalog本文をatomicに保存する。
	 * Bodyを先に置換しmetadataを最後に置換してcommit pointとする。
	 * @param[in] url 公式HTTPS resourceの完全なURL。 Cache keyの公式HTTPS URL。
	 * @param[in] content 空ではない検証対象本文。 空ではないcatalog本文。
	 * @param[in] etag Responseが返した任意ETag。不正値は保存せず本文だけを保存する。 任意のresponse ETag。
	 * @return 保存成功時は0、初期化またはI/O失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError store( std::wstring_view url, std::span<const std::byte> content,
									std::wstring_view etag) const ;

	/**
	 * @brief URLに対応する本文とmetadataをbest-effortで破棄する。
	 * URLに対応する本文とmetadataを破棄する。
	 * 例外とI/O errorを呼出し側へ伝播せず、cacheを正本にしない。
	 * @param[in] url 破棄対象resourceの完全なURL。 破棄対象resource URL。
	 */
	void					  discard( std::wstring_view url) const noexcept ;

private:
	/// 空でない場合だけ試験用cache rootとして使用する絶対path。
	std::wstring rootOverride_ ;
} ;

} // namespace drivercrate
