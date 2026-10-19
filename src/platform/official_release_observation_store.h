//------------------------------------------------------------------------------
/**
 * @file official_release_observation_store.h
 * @brief 公式release観測と自動探索cacheの端末内永続化定義。
 * @version 01.01.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末固有binding key管理追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  URL非保持の公式自動探索cache永続化を追加。
 * </pre>
 *
 * @note 端末固有binding key、検証済みrelease観測とURL非保持の探索cacheをProgramDataへ保存します。
 *       本classは過去の保存値からdownloadまたはinstallを許可しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_release_observation.h"
#include "core/update_types.h"
#include "platform/official_discovery_cache.h"

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式release観測永続化型定義。
//------------------------------------------------------------------------------

/**
 * @brief 端末内release観測fileの読取り状態である。
 */
enum class ReleaseObservationStoreState {
	/// 保存fileが存在しない。
	MISSING,
	/// 全recordとSHA-256の検証に成功した。
	LOADED,
	/// 破損、不正形式、重複recordを検出して破棄した。
	INVALIDATED,
} ;

/**
 * @brief 端末内release観測fileの検証済み読取り結果である。
 */
struct ReleaseObservationStoreResult {
	/// File不在、全検証成功、破損破棄を区別する状態。
	ReleaseObservationStoreState				 state{ReleaseObservationStoreState::MISSING} ;
	/// 検証済み観測集合。
	std::vector<LocalOfficialReleaseObservation> observations ;
} ;

/**
 * @brief 端末内公式自動探索cache fileの読取り状態です。
 */
enum class DiscoveryCacheStoreState {
	/// 保存fileが存在しません。
	MISSING,
	/// 全entryとSHA-256の検証に成功しました。
	LOADED,
	/// 破損、不正形式または重複entryを検出して破棄しました。
	INVALIDATED,
} ;

/**
 * @brief 端末内公式自動探索cache fileの検証済み読取り結果です。
 */
struct DiscoveryCacheStoreResult {
	/// File不在、全検証成功または破損破棄を区別する状態です。
	DiscoveryCacheStoreState				 state{DiscoveryCacheStoreState::MISSING} ;
	/// URL、grant、PnP IDまたはlocal pathを含まない検証済みentry集合です。
	std::vector<OfficialDiscoveryCacheEntry> entries ;
} ;

/**
 * @brief 端末内release観測を有限・atomicに永続化するstoreである。
 *
 * @note 既定rootはProgramData配下へSYSTEM／Administrators限定DACLで作成する。
 *       明示root constructorはnetworkを使用しない単体試験専用である。
 */
class OfficialReleaseObservationStore final {
public:
	/**
     * @brief 管理者保護された既定state rootを使用するobjectを作成する。
     */
	OfficialReleaseObservationStore() = default ;

	/**
	 * @brief 単体試験が所有する既存親directory内のstate rootを使用する。
	 * 試験用state rootを使用するobjectを作成する。
	 * ProductionのProgramDataとDACLを使用せずfile境界を試験する。
	 * @param[in] rootOverride 試験終了時に呼出し側が削除する絶対path。 試験が所有する絶対directory path。
	 */
	explicit OfficialReleaseObservationStore( std::wstring rootOverride) ;

	/**
	 * @brief 端末内release観測fileを整合性検証付きで読み取る。
	 * 不在を正常状態として返し、破損fileはInvalidatedとして破棄する。
	 * @param[out] result 成功時のfile状態と検証済み観測。Missing時は空集合。
	 * @return 処理成功時は0、root初期化またはI/O失敗時はHRESULT bit pattern。
	 * @note 破損fileはbest-effortで破棄し、Invalidatedを返す。
	 */
	[[nodiscard]] NativeError load( ReleaseObservationStoreResult &result) const ;

	/**
	 * @brief 現在の全release観測を一つのatomic snapshotとして保存する。
	 * 全内容を先にencodeし、一時fileをflushしてからatomic置換する。失敗時は既存snapshotを維持する。
	 * @param[in] observations 保存する検証済み観測。空集合も有効なsnapshotである。
	 * @return 保存成功時は0、不正入力、上限、初期化、I/O失敗時はHRESULT bit pattern。
	 * @note 保存失敗時は既存snapshotを変更しない。
	 */
	[[nodiscard]] NativeError store(
		std::span<const LocalOfficialReleaseObservation> observations) const ;

	/**
	 * @brief URL非保持の公式自動探索cache fileを整合性検証付きで読み取ります。
	 * 不在を正常状態として返し、破損fileはInvalidatedとして破棄します。
	 * @param[out] result 成功時のfile状態と検証済みentryです。Missing時は空集合です。
	 * @return 処理成功時は0、root初期化またはI/O失敗時はHRESULT bit patternです。
	 * @note 読取り結果はfreshness判定前であり、取得または導入権限を持ちません。
	 */
	[[nodiscard]] NativeError loadDiscoveryCache( DiscoveryCacheStoreResult &result) const ;

	/**
	 * @brief URL非保持の公式自動探索cacheを一つのatomic snapshotとして保存します。
	 * 全entryを先に検証して一時fileをflushし、成功した場合だけ既存snapshotを置換します。
	 * @param[in] entries 保存する検証済みentryです。空集合も有効なsnapshotです。
	 * @return 保存成功時は0、不正入力、上限、初期化またはI/O失敗時はHRESULT bit patternです。
	 * @note URL、token、EULA本文、grant、PnP IDまたはlocal pathを受理するfieldはありません。
	 */
	[[nodiscard]] NativeError storeDiscoveryCache(
		std::span<const OfficialDiscoveryCacheEntry> entries) const ;

	/**
	 * @brief 端末固有binding keyを保護stateから読み、未作成時は生成する。
	 * 既存keyを優先し、通常fileの不正sizeまたは全0だけを破棄してCNGで再生成する。ReparseやACL失敗では置換しない。
	 * @param[out] secret 成功時の32 byte HMAC key。失敗時は全byte 0。
	 * @param[out] regenerated 新規作成または破損file再生成時はtrue。
	 * @return 成功時は0、root、reparse、ACL、I/O、CNG失敗時はHRESULT bit pattern。
	 * @note KeyをUI、log、network、診断出力へ渡してはならない。
	 */
	[[nodiscard]] NativeError loadOrCreateBindingSecret( LocalOfficialBindingSecret &secret,
														bool &regenerated) const ;

	/**
	 * @brief 保存済み観測fileをbest-effortで破棄する。
	 * 保存済みrelease観測fileを破棄する。
	 * Shutdownや明示失効時に使用し、I/O errorを外へ漏らさない。
	 */
	void					  discard() const noexcept ;

	/**
	 * @brief 保存済み公式自動探索cache fileをbest-effortで破棄します。
	 * 明示失効時に使用し、I/O errorを外へ漏らしません。
	 */
	void					  discardDiscoveryCache() const noexcept ;

private:
	/// 空でない場合だけ試験用rootとして使用する絶対path。
	std::wstring rootOverride_ ;
} ;

} // namespace drivercrate
