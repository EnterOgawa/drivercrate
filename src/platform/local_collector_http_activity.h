//------------------------------------------------------------------------------
/**
 * @file local_collector_http_activity.h
 * @brief 私有HTTP所有ticketと排他的な再発行停止の寿命を定義します。
 * @version 01.00.01
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  実所有の閉鎖と再発行停止を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 構築keyはstoreだけが所有します。保存許可や任意threadの停止証明ではありません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <memory>
#include <utility>

namespace drivercrate {
class LocalCollectorStateStore ;
struct CollectorStoreHttpActivity ;
/** @brief Poolと全controlが共有する、一つの実HTTP所有登録です。 */
class CollectorStoreHttpLease final {
public:
	/** @brief Storeの私有発行だけに使用する構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorStateStore ;
		/** @brief Callerによる登録数の操作を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 発行前に登録の所有領域を確保します。
	 * @param[in] key Storeだけの構築key。
	 * @param[in] activity 実storeと同じprocess内所有状態。
	 */
	CollectorStoreHttpLease( ConstructionKey								key,
							std::shared_ptr<CollectorStoreHttpActivity> activity)
		: activity_( std::move( activity))
	{
		(void)key ;
	}
	/** @brief 最後の実所有者が返す登録をatomicに減らします。 */
	~CollectorStoreHttpLease() ;
	/**
	 * @brief HTTP登録数の返却責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorStoreHttpLease( const CollectorStoreHttpLease &) = delete ;
	/**
	 * @brief HTTP登録数の返却責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorStoreHttpLease &operator=( const CollectorStoreHttpLease &) = delete ;

private:
	friend class LocalCollectorStateStore ;
	/// Storeを参照せず、最後のworker所有解放まで存続する登録状態。
	std::shared_ptr<CollectorStoreHttpActivity> activity_ ;
	/// Atomic登録が成功した後だけtrue。未発行の確保失敗では減算しません。
	bool										armed_{} ;
} ;
/** @brief HTTP所有0から取得し、最後の参照まで新しい発行を止めます。 */
class CollectorStoreHttpFreeze final {
public:
	/** @brief 実storeの私有閉鎖だけに使用する構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorStateStore ;
		/** @brief Callerの真偽値からの停止認定を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 閉鎖前に所有領域を確保します。
	 * @param[in] key Storeだけの構築key。
	 * @param[in] activity 同じ実writerのprocess内登録状態。
	 */
	CollectorStoreHttpFreeze( ConstructionKey							 key,
							 std::shared_ptr<CollectorStoreHttpActivity> activity)
		: activity_( std::move( activity))
	{
		(void)key ;
	}
	/** @brief 最後の参照が再発行停止をatomicに返します。 */
	~CollectorStoreHttpFreeze() ;
	/**
	 * @brief HTTP再発行停止の返却責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorStoreHttpFreeze( const CollectorStoreHttpFreeze &) = delete ;
	/**
	 * @brief HTTP再発行停止の返却責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorStoreHttpFreeze &operator=( const CollectorStoreHttpFreeze &) = delete ;

private:
	friend class LocalCollectorStateStore ;
	/// 実storeと同じ所有登録です。Windows handleや保存権限は持ちません。
	std::shared_ptr<CollectorStoreHttpActivity> activity_ ;
	/// 所有0からの閉鎖取得が成立した後だけtrueです。
	bool										armed_{} ;
} ;
} // namespace drivercrate
