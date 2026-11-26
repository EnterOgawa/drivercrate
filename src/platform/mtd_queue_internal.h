//------------------------------------------------------------------------------
/**
 * @file mtd_queue_internal.h
 * @brief MTDの原queueを同原COPYへ照合し制御queueを所有します
 * @version 01.00.00
 * @date 2026/11/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/17  新規作成
 * </pre>
 *
 * @note 選択deviceと同意/復旧の成立は呼出し側で別に確認します
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/mtd_shared_file_internal.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <functional>
#include <memory>

namespace drivercrate {
class DriverStoreProvider ;
namespace test {
struct MtdQueueFixtureAccess ;
}
/** @brief 照合済みqueueが報告した実作用を区別します */
struct MtdQueueResult {
	/// 元queueの照合を開始した場合trueです
	bool				preparationStarted{} ;
	/// 同原queueと制御queueの照合が成立した場合trueです
	bool				prepared{} ;
	/// queue/copy自体の最初の元HRESULTです
	NativeError			copyError{} ;
	/// 所有device setの一時parameterを戻せなかった場合の元HRESULTです
	NativeError			parameterCleanupError{} ;
	/// 指定DIFの呼出し・Windows応答・原失敗をcopyとは別に保持します
	bool				deviceInstallStarted{} ;
	/// 指定DIFが成功した場合trueです
	bool				deviceInstallSucceeded{} ;
	/// 指定DIFが返した元HRESULTです
	NativeError			deviceInstallError{} ;
	/// DIF後の保持再照合が失敗した場合の元HRESULTです
	NativeError			postVerifyError{} ;
	/// DLLのrename成功、確認済み配置、同byte再利用と途中失敗です
	MtdSharedFileResult shared ;
	/// WindowsがSYSの遅延操作を通知した場合trueです
	bool				systemDelayed{} ;
	/// queue commitが開始された場合trueです。成功を意味しません
	bool				commitStarted{} ;
	/// queue commitが正常終了した場合trueです
	bool				commitCompleted{} ;
} ;

/** @brief 元queueと同原INFから構成した単独制御queueです */
class MtdQualifiedQueue final {
public:
	/**
	 * @brief 自分が開いたINFと制御queueだけを閉じます
	 */
	~MtdQualifiedQueue() noexcept ;
	/**
	 * @brief 所有queueの複写を禁止します
	 * @note 同operationの所有は共有しません
	 */
	MtdQualifiedQueue( const MtdQualifiedQueue &) = delete ;
	/**
	 * @brief 所有queueの複写代入を禁止します
	 * @note 同operationの所有は共有しません
	 */
	MtdQualifiedQueue &operator=( const MtdQualifiedQueue &) = delete ;

private:
	friend class DriverStoreProvider ;
	friend struct test::MtdQueueFixtureAccess ;
	/**
	 * @brief 元と制御queueの全copyを一対一に照合しsourceを固定します
	 * @param[in] original 同選択DIF_INSTALLDEVICEFILESが構築した未commit queueです
	 * @param[in] registeredInf 同原byteとして保持中の登録INFです
	 * @param[in] workspace 同原ADMIN所有領域です
	 * @param[in] facts 全原COPY行とCAT memberです
	 * @param[in,out] files 同operationの共有先とsource保持です
	 * @param[out] qualified 全照合時だけの所有queueです
	 * @return 全tuple成立0、元API/未知作用/不一致はHRESULTです
	 * @note この関数は原queueをcommitせず、共有先も変更しません
	 */
	[[nodiscard]] static NativeError prepare( HSPFILEQ original, std::wstring_view registeredInf,
											 OfficialDownloadWorkspace			&workspace,
											 const SelectedStorageServiceFacts	&facts,
											 MtdSharedFileOperation				&files,
											 std::unique_ptr<MtdQualifiedQueue> &qualified) ;

	/**
	 * @brief 共有DLLを充足した後だけ同制御queueのSYS更新をcommitします
	 * @param[in] parent 同明示操作の親windowです
	 * @param[in] cancelled 同operationの取消し照会です
	 * @param[in] authorization 同原record/UTCの作用直前再検証です
	 * @param[out] result 部分配置、commit状態とSYS遅延を保持します
	 * @return 全元作用の有限copy成立0、失敗又は取消しは元HRESULTです
	 * @note 原queueはcommitせず、DLLの遅延通知は失敗と部分作用として扱います
	 */
	[[nodiscard]] NativeError		 commit( HWND parent, const std::function<bool()> &cancelled,
											const std::function<NativeError()> &authorization,
											MtdQueueResult					   &result) ;

	struct State ;
	/**
	 * @brief 保持した同operationの未公開queue状態を作ります
	 * @param[in,out] files 同operation終端まで有効な保持です
	 */
	explicit MtdQualifiedQueue( MtdSharedFileOperation &files) ;
	/// 同operationの未公開所有状態です
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
