//------------------------------------------------------------------------------
/**
 * @file common_inf_plan.h
 * @brief 封印取得と通常単一INFの準備計画および内部選択adapterを定義する。
 * @version 01.01.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  共通単一INFの非実行計画と発行所有境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  内部選択一括adapterと個別実行観測を追加。
 * </pre>
 *
 * @note 同期worker専用。準備計画は導入許可ではなく、installerや公開候補を生成しない。
 * @see docs/adr/0285-common-inf-plan-factory.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/common_driver_package.h"
#include "platform/official_acquisition.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_inf_install_binding.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class CommonInfInstallPlan ;
class CommonInfPlanExecutor ;

/** @brief 一つの候補を同じscanの一基本INFと現在deviceへ結ぶworker限定要求。 */
struct CommonInfPlanRequest {
	/// 元取得と同じ非零session。
	ScanSessionId scanSessionId{} ;
	/// 全通常検査結果内の0起点INF位置。
	std::size_t	  infIndex{} ;
	/// Workerが当該scanに割り当てた非空opaque候補ID。
	std::wstring  candidateIdentity ;
	/// Driver Storeの当該scan内だけで意味を持つopaque device ID。
	std::wstring  deviceIdentity ;
	/// 現在driverのProvider snapshot。空を拒否する。
	std::wstring  currentProvider ;
	/// 現在driverの原文版。初回導入の架空値を渡さない。
	std::wstring  currentVersion ;
	/// 現在driverの日付。空を拒否する。
	std::wstring  currentDate ;
} ;

/**
 * @brief 生存取得と通常検査を所有して非公開のbinding準備計画だけを発行する。
 * @note 取得sessionを共有所有し、元workspaceは単独所有する。破棄・全操作は初期化threadに限定する。
 * callbackは同期workerが固定する信頼境界で、UIや永続JSONから構成しない。
 */
class CommonInfPlanFactory final {
public:
	/** @brief 取得物を持たない空factoryを作る。 */
	CommonInfPlanFactory() ;
	/** @brief 自身の計画を失効させ、所有物とtokenをbest-effortで回収する。 */
	~CommonInfPlanFactory() ;
	/** @brief 取得物の複写を禁止する。
	 * @param[in] other 複写不能な元factory。
	 */
	CommonInfPlanFactory( const CommonInfPlanFactory &other) = delete ;
	/** @brief 複写代入を禁止する。
	 * @param[in] other 複写不能な元factory。
	 * @return 呼出し不能であり値を返さない。
	 */
	CommonInfPlanFactory &operator=( const CommonInfPlanFactory &other) = delete ;
	/** @brief Borrowとthread固定のため移動を禁止する。
	 * @param[in] other 移動不能な元factory。
	 */
	CommonInfPlanFactory( CommonInfPlanFactory &&other) = delete ;
	/** @brief 移動代入を禁止する。
	 * @param[in] other 移動不能な元factory。
	 * @return 呼出し不能であり値を返さない。
	 */
	CommonInfPlanFactory	 &operator=( CommonInfPlanFactory &&other) = delete ;
	/**
	 * @brief 封印元archiveから通常検査を行い、所有を全成功後にcommitする。
	 * @param[in] session 生存取得issuerの共有所有。Nullを拒否する。
	 * @param[in,out] archive 元取得workspace。成功時だけ所有を移し、失敗時は不変。
	 * @param[in,out] evidence 当該sessionが発行した封印。成功時だけ所有を移す。
	 * @param[in] format 実行しないZIPまたはCAB。
	 * @param[in] rankAuditor Driver Storeへ固定する完全rank照合。
	 * @param[in] binder Driver Storeへ固定するbinding発行。
	 * @param[in] releaser 本factoryのtokenだけを解放する境界。
	 * @param[in] cancellation 空または非blocking取消し照会。
	 * @return 成功0、由来・位置・内容・容量・取消し・例外のHRESULT。
	 * @note 全体検査完了は個別INF合格を意味しない。通信・staging・導入を行わない。
	 */
	[[nodiscard]] NativeError initialize( std::shared_ptr<const OfficialAcquisitionSession> session,
										 std::unique_ptr<OfficialDownloadWorkspace>		  &archive,
										 OfficialAcquiredFileEvidence					  &evidence,
										 OfficialDriverArchiveFormat					   format,
										 const OfficialInfRankAuditor			 &rankAuditor,
										 const OfficialInfInstallBinder			 &binder,
										 const OfficialInfInstallBindingReleaser &releaser,
										 const OfficialAuditCancellation &cancellation = {}) ;
	/**
	 * @brief 通常基本INFと完全rankから一deviceのbinding準備計画を発行する。
	 * @param[in] request 同じscanのopaque identityと現在driver snapshot。
	 * @param[out] plan 初期状態が空の出力。成功時だけ内部状態を保持する。
	 * @return 成功0、未対応・入力・再検証・rank・binding・rollback失敗のHRESULT。
	 * @pre 初期化workerで直列に呼び、callbackから再入しない。
	 * @note 公開candidateを発行せず、methodや同意を合格へ変更しない。
	 */
	[[nodiscard]] NativeError prepare( const CommonInfPlanRequest &request,
									  CommonInfInstallPlan		 &plan) ;
	/**
	 * @brief 本factoryの全計画を失効させ、発行tokenだけを解放する。
	 * @return 全解放成功0、別thread・再入または最初の解放失敗のHRESULT。
	 * @note 失敗時も同threadの計画は失効する。Windowsの導入済みINFを削除しない。
	 */
	[[nodiscard]] NativeError invalidate() noexcept ;
	/** @brief 通常検査の成功・拒否を含む全INF件数を返す。
	 * @return 非初期化・失効・別threadでは0。
	 */
	[[nodiscard]] std::size_t infCount() const noexcept ;
	/** @brief 最後のrollback解放失敗を元処理のHRESULTと独立に返す。
	 * @return 同workerの保持診断。未初期化・別threadでは0。
	 * @note 0はWindows状態の包括的な復旧保証ではない。
	 */
	[[nodiscard]] NativeError lastCleanupError() const noexcept ;

private:
	friend class CommonInfInstallPlan ;
	friend class CommonInfPlanExecutor ;
	/** @brief 元取得と通常閉包・発行tokenを所有するworker限定状態。 */
	struct State ;
	/// 計画と共有する私有所有状態。外部へmutable参照を返さない。
	std::shared_ptr<State> state_ ;
	/// 初期化callbackからの再入を拒否する当該worker限定flag。
	bool				   initializing_{} ;
} ;

/**
 * @brief Factoryだけが有効なbindingを結合できる非複写の準備計画。
 * @note 由来や内容の公開DTOから復元できず、実行APIを持たない。移動・破棄は所有workerだけで行う。
 */
class CommonInfInstallPlan final {
public:
	/** @brief bindingのない空計画を作る。 */
	CommonInfInstallPlan() ;
	/** @brief 自分の未使用tokenをbest-effortで解放する。 */
	~CommonInfInstallPlan() ;
	/** @brief tokenと取得物所有の複写を禁止する。
	 * @param[in] other 複写不能な元計画。
	 */
	CommonInfInstallPlan( const CommonInfInstallPlan &other) = delete ;
	/** @brief 複写代入を禁止する。
	 * @param[in] other 複写不能な元計画。
	 * @return 呼出し不能であり値を返さない。
	 */
	CommonInfInstallPlan &operator=( const CommonInfInstallPlan &other) = delete ;
	/** @brief 所有を移し、移動元を空にする。
	 * @param[in,out] other 同じworkerで使用中でない元計画。
	 */
	CommonInfInstallPlan( CommonInfInstallPlan &&other) noexcept ;
	/** @brief 移動代入を禁止し、未解放tokenの暗黙破棄を避ける。
	 * @param[in] other 移動代入不能な元計画。
	 * @return 呼出し不能であり値を返さない。
	 */
	CommonInfInstallPlan	 &operator=( CommonInfInstallPlan &&other) = delete ;
	/** @brief 準備bindingの存在だけを観測する。導入可能を意味しない。
	 * @return 同じworker・生存所有者・未失効tokenの場合true。それ以外false。
	 */
	[[nodiscard]] bool		  isBound() const noexcept ;
	/** @brief 本計画だけを失効させ、私有tokenを解放する。
	 * @return 解放成功または空0、別thread・再入・解放失敗のHRESULT。
	 */
	[[nodiscard]] NativeError invalidate() noexcept ;

private:
	friend class CommonInfPlanFactory ;
	friend class CommonInfPlanExecutor ;
	/** @brief 一候補のrequest・完全rank・bindingと元取得共有所有を保持する。 */
	struct State ;
	/// Factoryだけが設定できる非複写状態。既定とmove元ではnull。
	std::unique_ptr<State> state_ ;
} ;

/** @brief 当該scanの表示選択と私有計画を照合するworker限定借用。 */
struct CommonInfPlanSelection {
	/// 呼出し終了まで生存し、使用中move・破棄しない計画。Nullを拒否する。
	CommonInfInstallPlan *plan{} ;
	/// 最終選択されたopaque候補ID。発行時と完全一致させる。
	std::wstring		  candidateIdentity ;
	/// 最終選択されたopaque device ID。発行時と完全一致させる。
	std::wstring		  deviceIdentity ;
} ;

/**
 * @brief 指定導入と同じWindows bindingを変更なしで再検証する内部境界。
 * @note 引数はscan、opaque device、所有workspace、単一INF、私有bindingの順である。
 * すべて呼出し中だけ借用し、成功0または元HRESULTを返す。UI入力から構成しない。
 */
using CommonInfBindingRevalidator =
	std::function<NativeError( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							  const OfficialInfPackage &, const OfficialInfInstallBinding &)> ;

/** @brief 既存個別結果とWindows変更可能性・token解放診断を分離する内部結果。 */
struct CommonInfPlanExecutionResult {
	/// 既存保護callerが復元結果を付加する候補順の結果。Adapterは復元を行わない。
	InstallResult	  result ;
	/// 個別結果と同じ順。Trueはcallback呼出し済みで、失敗時も変更なしとは限らない。
	std::vector<bool> installerInvoked ;
	/// 所有者全失効時の最初の解放失敗。元の導入HRESULTを上書きしない。
	NativeError		  cleanupError{} ;
} ;

/**
 * @brief 私有計画を全件preflightして既存指定導入だけへ渡す内部adapter。
 * @note 製品Provider／workerには未接続。公開内容DTO・boolから計画を再構成しない。
 */
class CommonInfPlanExecutor final {
public:
	/**
	 * @brief 全選択の再検証後、直前再検証と指定導入を候補順に行う。
	 * @param[in] scanSessionId 現在workerで最終選択された非零scan。
	 * @param[in] selections 使用中変更しない有限選択集合。空・重複・一device複数を拒否する。
	 * @param[in] revalidator Driver Storeの既存binding再検証へ固定した同期境界。
	 * @param[in] installer Driver Storeの既存指定導入へ固定した同期境界。
	 * @param[in] parentWindowNative 既存workerが確認した親Window値。
	 * @param[in] progressCallback 空または確定済み項目数だけの同期通知先。
	 * @return 個別結果と呼出し観測、独立した全失効診断。
	 * @pre 既存Provider install内で、workerの実OS・最終同意・EULA・必須条件確認と
	 * client復元開始成功またはServer専用backup確認を満たして呼ぶ。取得同意で代替しない。
	 * @post 同workerで受理した参加factoryの全計画を失効する。別thread／再入は変更しない。
	 * @note 元取得・全memberと祖先を全callback終了まで固定する。GET・自動retry・INF削除をしない。
	 * Callback例外は結果へ変換する。結果のallocation失敗では候補列が空の場合もある。
	 */
	[[nodiscard]] static CommonInfPlanExecutionResult execute(
		ScanSessionId scanSessionId, std::span<const CommonInfPlanSelection> selections,
		const CommonInfBindingRevalidator &revalidator, const OfficialBoundInfInstaller &installer,
		std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback = {}) ;

private:
	/** @brief 参加所有者と使用中file固定を全終了経路で回収する内部scope。 */
	struct Scope ;
} ;

} // namespace drivercrate
