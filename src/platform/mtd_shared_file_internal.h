//------------------------------------------------------------------------------
/**
 * @file mtd_shared_file_internal.h
 * @brief MTD原コピーの共有DLLを非置換で成立させる内部操作です
 * @version 01.00.00
 * @date 2026/11/16
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/16  新規作成
 * </pre>
 *
 * @note 同意/復旧、原queueの照合と指定device導入は呼出し側の責務です
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/official_driver_package.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <span>

namespace drivercrate {
class OfficialDownloadWorkspace ;
class MtdQualifiedQueue ;
namespace test {
struct MtdSharedFileFixtureAccess ;
}

/** @brief 一操作が実際に満たした共有copyの部分結果です */
struct MtdSharedFileResult {
	/// renameが成功を返した件数です。正規先確認とは別です
	std::uint32_t renameSucceeded{} ;
	/// 新規正規配置を確認した件数です
	std::uint32_t created{} ;
	/// 保護された同byte既存fileを再利用した件数です
	std::uint32_t reused{} ;
	/// 所有tempの後片付けが確認できなかった場合trueです
	bool		  cleanupUncertain{} ;
	/// 不成立時の固定操作段階です。全成功時は0です
	std::uint32_t failureStage{} ;
} ;

/** @brief 同一operation中だけ原共有DLLと親directoryを固定します */
class MtdSharedFileOperation final {
public:
	/**
	 * @brief 同操作が所有するhandleと未配置tempだけを解放します
	 */
	~MtdSharedFileOperation() noexcept ;
	/**
	 * @brief 操作の複製を禁止します
	 * @param[in] other 複製できない同operationです
	 */
	MtdSharedFileOperation( const MtdSharedFileOperation &other) = delete ;
	/**
	 * @brief 操作の複製代入を禁止します
	 * @param[in] other 複製できない同operationです
	 */
	MtdSharedFileOperation			&operator=( const MtdSharedFileOperation &other) = delete ;

	/**
	 * @brief 同意と復旧の後に元COPY/CATと既存targetを変更せず固定します
	 * @param[in,out] workspace 同原ADMIN保護sourceとoperation記録を所有します
	 * @param[in] facts 同原選択から固定した全COPY行とassociated SYSです
	 * @param[out] operation 全preflight成立時だけの単独所有です
	 * @return 全sourceと既存target成立0、不正/未知/異byteは元HRESULTです
	 * @note INF登録、共有fileの新規配置、queue commitを行いません
	 */
	[[nodiscard]] static NativeError prepare( OfficialDownloadWorkspace				 &workspace,
											 const SelectedStorageServiceFacts		 &facts,
											 std::unique_ptr<MtdSharedFileOperation> &operation) ;

	/**
	 * @brief 同一handle/file IDと全byteを共有DLLごとに再照合します
	 * @return 全target固定0、不在/差替え/byte変更はHRESULTです
	 */
	[[nodiscard]] NativeError		 verify() const ;

private:
	friend class MtdQualifiedQueue ;
	friend struct test::MtdSharedFileFixtureAccess ;
	/**
	 * @brief 元queueの各sourceを同原workspace又は同登録INFの保護Store memberへ結びます
	 * @param[in] registeredInf 同原byteとして保持中の登録INFです
	 * @param[in] sources 原COPY行と同じ順序のqueue source完全pathです
	 * @return 全sourceの位置、親、所有、file IDとCAT hash成立0、それ以外はHRESULTです
	 * @note 他packageや任意の同hash pathを採用せず、全handleを操作終端まで保持します
	 */
	[[nodiscard]] NativeError bindQueueSources( std::wstring_view			 registeredInf,
											   std::span<const std::wstring> sources) ;

	/**
	 * @brief 原queue照合後に共有DLLを同byte再利用又は非置換配置します
	 * @param[in] cancelled 操作中の取消し照会です。空は取消しなしです
	 * @param[in] authorization 同原record/UTCを作用直前に再確認します
	 * @param[out] result 部分配置とcleanup不確定も含む原結果です
	 * @return 全共有DLL充足0、取消し又は最初の原HRESULTです
	 * @pre 呼出し側は同意/復旧と同選択の原queue全照合を確認済みです
	 * @note SYSのcopy、queue commit、DIFを行いません
	 */
	[[nodiscard]] NativeError satisfy( const std::function<bool()>		 &cancelled,
									  const std::function<NativeError()> &authorization,
									  MtdSharedFileResult				 &result) ;

	struct State ;
	/**
	 * @brief 完全preflight前の所有状態を作ります
	 * @param[in] workspace 同原ADMIN保護領域です
	 */
	explicit MtdSharedFileOperation( OfficialDownloadWorkspace &workspace) ;
	/// 全操作終端まで維持する非公開状態です
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
