//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_inventory.h
 * @brief 同親leaseの共有履歴から導出する読取り根拠を定義します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  同親の実共有raw根拠を追加。
 * </pre>
 *
 * @note ROOT／CACHE内容・live lease・switch／取得許可ではありません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_shared_ledger.h"
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
/** @brief 共有semantic検査に使用した一保護fileです。 */
struct CollectorSharedInventoryFile {
	/// 親の場合true、選択区間の場合false。
	bool		  parent{} ;
	/// 固定current／runs相対名。任意pathではありません。
	std::wstring  name ;
	/// 元envelopeも含むraw SHA-256。
	std::wstring  sha256 ;
	/// 元handleで確認したraw byte数。
	std::uint64_t bytes{} ;
} ;
/** @brief 同親の全検査から作る値です。単体DTOは証明ではありません。 */
struct CollectorSharedRootEvidence {
	/// 元値を全操作から再導出した共有snapshot。CACHEは未検証参照です。
	CollectorSharedLedgerSnapshot			  snapshot ;
	/// 実子leaseのsegment key。
	std::wstring							  segment ;
	/// 元head本文のSHA-256。raw hashとは区別します。
	std::wstring							  headSha256 ;
	/// 元全66本文に結合した台帳digest。
	std::wstring							  ledger ;
	/// 検査UTC。元最高時計を更新しません。
	std::uint64_t							  inspectedUtcMillis{} ;
	/// 元区間の完了共有操作数。ROOT世代数ではありません。
	std::size_t								  operations{} ;
	/// 親と選択区間の重複なしraw合計。
	std::uint64_t							  fileBytes{} ;
	/// 親current／runs、子current／runsの各列挙順。
	std::vector<CollectorSharedInventoryFile> files ;
	/// 最大256 KiBのcanonical本文。
	std::string								  inventory ;
	/// inventory本文のSHA-256。
	std::wstring							  inventorySha256 ;
	/// 最大16 KiBの共有根拠封印本文。区間sealではありません。
	std::string								  seal ;
	/// seal本文のSHA-256。配布署名ではありません。
	std::wstring							  sealSha256 ;
} ;
class LocalCollectorSharedStore ;
/** @brief 同親leaseの最終全raw／全名再照合後だけ発行するimmutable根拠です。 */
class CollectorSharedRootInventory final {
public:
	/** @brief 共有保護readerだけが持つ構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorSharedStore ;
		/** @brief Caller DTO／hashからの発行を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 全再照合済みの元根拠を所有します。
	 * @param[in] key 共有readerだけのkey。
	 * @param[in] evidence 同じ呼出しで検査した所有値。
	 */
	CollectorSharedRootInventory( ConstructionKey key, CollectorSharedRootEvidence evidence)
		: evidence_( std::move( evidence))
	{
		(void)key ;
	}
	/** @brief 検査時点の共有根拠を借用します。
	 * @return Contextと同寿命のconst参照。後続のfresh検査を代行しません。
	 */
	[[nodiscard]] const CollectorSharedRootEvidence &evidence() const noexcept
	{
		return evidence_ ;
	}

private:
	/// 読取り検査時点の所有値。live leaseや更新能力は保持しません。
	CollectorSharedRootEvidence evidence_ ;
} ;
} // namespace drivercrate
