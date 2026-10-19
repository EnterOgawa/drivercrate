//------------------------------------------------------------------------------
/**
 * @file common_inf_plan.cpp
 * @brief 共通単一INFの元取得所有・binding準備と内部選択adapterを実装する。
 * @version 01.01.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  生存取得から単一INFの準備計画を発行する。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  全件preflightと直前照合の指定導入adapterを追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 呼出しworkerに限定する。準備のfile固定は返却時、一括実行の固定は全callback終了時まで保持する。
 * @see docs/adr/0285-common-inf-plan-factory.md
 */
//------------------------------------------------------------------------------
#include "platform/common_inf_plan.h"
#include "platform/inf_dependency_native.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <new>
#include <set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

constexpr std::size_t	MAXIMUM_PLANS = 4096U ;									// 一回の同時保持上限。全体の対応件数ではない。
constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES = 128ULL * 1024ULL * 1024ULL ;	// 従来の入力上限。

/** @brief 検査scope中のfile・祖先handleを単独所有する。 */
struct PlanHandleCloser {
	/** @brief 取得済みhandleだけを閉じる。
	 * @param[in] value 所有handle。無効値は閉じない。
	 */
	void operator()( void *value) const noexcept
	{
		// 未取得値をOSへ渡さない。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief 返却までの使用中固定。
 */
using PlanHandle = std::unique_ptr<void, PlanHandleCloser> ;

/** @brief 再入拒否flagをすべての終了経路で戻す。 */
struct PlanBusyScope {
	/// 当該workerだけが更新する借用flag。
	bool &busy ;
	/** @brief 操作中状態を開始する。
	 * @param[in,out] value 事前にfalseを確認した所有者flag。
	 */
	explicit PlanBusyScope( bool &value) noexcept : busy( value)
	{
		busy = true ;
	}
	/** @brief 成功・失敗・例外のいずれでも操作中状態を解除する。 */
	~PlanBusyScope()
	{
		busy = false ;
	}
} ;

/**
 * @brief 通常位置を実handleで確認し、祖先renameとleaf書換えをscope中拒否する。
 * @param[in] path 元workspace内の有限通常DOS path。
 * @param[in,out] pins 成功handleを保持する当該操作の所有列。
 * @return 全位置確認0、入力・reparse・別最終位置・競合のHRESULT。
 * @note Hash・署名は共通検証へ委譲する。この関数は内容を認証しない。
 */
NativeError pinPlanFile( const std::wstring &path, std::vector<PlanHandle> &pins)
{
	// 取得由来のpathでも曖昧なDOS位置を受け取らない。
	if( !validInfDependencyPath( path, true)) {
		return E_INVALIDARG ;
	}

	// Rootからleafまで一回ずつ固定し、全handleを呼出しscopeへ保持する。
	for( std::size_t end = 3U; end <= path.size(); ++end) {
		// Component境界以外は開かない。
		if( end != 3U && end != path.size() && path[end] != L'\\') {
			continue ;
		}

		const bool		   directory = end != path.size() ;		// 最後だけleaf fileを期待する。
		const std::wstring part		 = path.substr( 0U, end) ;	// Win32向け終端付き原位置。
		// 祖先のrenameとleafのwriterをこの操作終了まで共有しない所有handle。
		PlanHandle		   handle( CreateFileW(
			part.c_str(), directory ? FILE_READ_ATTRIBUTES : GENERIC_READ,
			directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ, nullptr,
			OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U), nullptr)) ;
		// Writer競合・open失敗を成功履歴で補完しない。
		if( handle.get() == INVALID_HANDLE_VALUE) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// 実handleの属性とtag。
		// Reparse・種別・disk以外のfileを拒否する。
		if( !GetFileInformationByHandleEx( handle.get(), FileAttributeTagInfo, &attributes,
										 sizeof( attributes))) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// 同じ名前でも期待する通常objectでなければ固定へ含めない。
		if( GetFileType( handle.get()) != FILE_TYPE_DISK ||
		   (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
		   ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		std::array<wchar_t, MAX_PATH + 4U> finalName{} ;	// 接頭辞を含む有限最終位置。
		const DWORD						   count = GetFinalPathNameByHandleW(
			   handle.get(), finalName.data(), static_cast<DWORD>( finalName.size()),
			   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 実最終位置。
		// 切詰めとAPI失敗を一致と扱わない。
		if( count == 0U || count >= finalName.size()) {
			return count == 0U ? HRESULT_FROM_WIN32( GetLastError())
							   : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		const std::wstring_view actual( finalName.data(), count) ;	// 終端を除く借用。
		// Junctionや別名経由の成功を原位置への固定へ流用しない。
		if( !actual.starts_with( L"\\\\?\\") ||
		   CompareStringOrdinal( actual.data() + 4U, static_cast<int>( actual.size() - 4U),
								part.data(), static_cast<int>( part.size()), TRUE) != CSTR_EQUAL) {
			return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
		}

		pins.push_back( std::move( handle)) ;
	}

	return 0 ;
}

/** @brief 版ではなく完全rank監査の全fieldを一致させる。
 * @param[in] left 再監査値。
 * @param[in] right binding返却値。
 * @return 全fieldが一致する場合true。
 */
bool equalPlanRank( const OfficialDriverRankAudit &left,
				   const OfficialDriverRankAudit &right) noexcept
{
	return left.decision == right.decision &&
		   left.currentPosition.kind == right.currentPosition.kind &&
		   left.currentPosition.index == right.currentPosition.index &&
		   left.candidatePosition.kind == right.candidatePosition.kind &&
		   left.candidatePosition.index == right.candidatePosition.index &&
		   left.currentRank == right.currentRank && left.candidateRank == right.candidateRank &&
		   left.currentIdentifierScore == right.currentIdentifierScore &&
		   left.candidateIdentifierScore == right.candidateIdentifierScore ;
}
} // namespace

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
struct CommonInfPlanFactory::State {
	/// 取得issuerを元取得物より長く所有する。
	std::shared_ptr<const OfficialAcquisitionSession> session ;
	/// 元取得fileの単独所有。
	std::unique_ptr<OfficialDownloadWorkspace>		  archive ;
	/// このsessionと元workspaceだけへ再照合できる封印。
	OfficialAcquiredFileEvidence					  evidence ;
	/// 内部で検査した全通常INFの所有閉包。
	CommonDriverPackageInspection					  inspected ;
	/// 当該workerだけで使用する完全rank境界。
	OfficialInfRankAuditor							  rankAuditor ;
	/// 当該workerだけで使用するbinding発行境界。
	OfficialInfInstallBinder						  binder ;
	/// 本factoryのtokenだけを解放する境界。
	OfficialInfInstallBindingReleaser				  releaser ;
	/// Tokenから発行済みopaque候補IDへの私有集合。
	std::map<std::uint64_t, std::wstring>			  tokens ;
	/// 初期化時のworker thread ID。
	DWORD											  thread{} ;
	/// このfactoryが有効であればtrue。再scan・終了でfalseにする。
	bool											  active{} ;
	/// Callback再入を拒否する当該worker限定flag。
	bool											  busy{} ;
	/// 元HRESULTと別に保持する最後のrollback解放失敗。
	NativeError										  cleanupError{} ;
	/** @brief 既存tokenを除く本操作の解放を診断付きで呼ぶ。
	 * @param[in] token 本factoryの新規または保持token。
	 * @return 解放0、失効またはcallback例外のHRESULT。
	 */
	NativeError										  release( std::uint64_t token) noexcept
	{
		try {
			return releaser( inspected.scanSessionId, token)
					   ? 0
					   : HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE) ;
		} catch( ...) {
			// Windows側の完了を推測せず、呼出し側へ元計画の解放失敗を残す。
			return E_UNEXPECTED ;
		}
	}
	/** @brief 途中例外でも既存計画のtokenをrollbackで解放しない。
	 * @param[in] token 本操作が返却した未commit token。0と既存tokenは解放しない。
	 * @return 解放成功または解放不要0、解放失敗のHRESULT。
	 */
	NativeError rollbackUncommitted( std::uint64_t token) noexcept
	{
		return token == 0U || tokens.contains( token) ? 0 : release( token) ;
	}
} ;

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
struct CommonInfInstallPlan::State {
	/// 元取得と閉包・issuerを同じfactory状態へ結合する所有。
	std::shared_ptr<CommonInfPlanFactory::State> owner ;
	/// 当該scanの一候補・一device・一INFと現在状態。
	CommonInfPlanRequest						 request ;
	/// 完全rankと現在driverへ結合した非公開token。
	OfficialInfInstallBinding					 binding ;
} ;

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
struct CommonInfPlanExecutor::Scope {
	/// 終了まで元取得・閉包とcallbackを共有所有する有限集合。
	std::vector<std::shared_ptr<CommonInfPlanFactory::State>> owners ;
	/// 全callback終了まで保持する元archive・member・祖先の固定。
	std::vector<PlanHandle>									  pins ;
	/// 同じ所有位置を一度だけ固定する内部集合。外部へ出さない。
	std::set<std::wstring>									  paths ;
	/// 全所有者を同workerで受理した場合だけtrue。
	bool													  locked{} ;
	/** @brief 例外を含む終了で全私有計画を失効する。 */
	~Scope()
	{
		static_cast<void>( finish()) ;
	}
	/** @brief 一度だけ全所有者のtokenを解放し、元診断とは別に返す。
	 * @return 最初の解放失敗。未受理・完了済みでは0。
	 */
	NativeError finish() noexcept
	{
		// 別threadと再入の拒否では既存実行の状態に触れない。
		if( !locked) {
			return 0 ;
		}

		NativeError first{} ;	// 参加所有者の最初の解放失敗。
		// 全所有者のbusyを保ったまま解放し、解放callbackの再入も拒否する。
		for( const auto &owner : owners) {
			owner->active = false ;
			NativeError cleanup{} ;	// 当該所有者だけの解放結果。
			// 参加factoryの未選択draftも終了scanの計画として失効する。
			for( const auto &entry : owner->tokens) {
				const NativeError error = owner->release( entry.first) ;	// 個別解放結果。
				// 先行失敗を後続成功で消さない。
				if( cleanup == 0 && error != 0) {
					cleanup = error ;
				}
			}

			owner->tokens.clear() ;
			owner->cleanupError = cleanup ;
			// 全体にも最初の解放失敗だけを保持する。
			if( first == 0 && cleanup != 0) {
				first = cleanup ;
			}
		}

		// 解放callbackがすべて終わった後で再入拒否を解除する。
		for( const auto &owner : owners) {
			owner->busy = false ;
		}

		locked = false ;
		return first ;
	}
	/** @brief 同じ所有pathは重複openせず、実handle固定を継続する。
	 * @param[in] path 所有者内の通常file位置。
	 * @return 固定成功0、元の位置・競合HRESULT。
	 */
	NativeError pin( const std::wstring &path)
	{
		// 一度固定したleafは共有memberとして扱い、hash検証は省略しない。
		if( paths.contains( path)) {
			return 0 ;
		}

		const NativeError error = pinPlanFile( path, pins) ;	// 実位置確認。
		// Open成功後だけ重複集合へ登録する。
		if( error == 0) {
			paths.insert( path) ;
		}

		return error ;
	}
	/** @brief 同じ計画の生存元取得・通常内容・完全rank・私有bindingを再検証する。
	 * @param[in] plan Factoryだけが発行した内部状態。
	 * @param[in] revalidator Windows bindingの既存再検証境界。
	 * @return 全検証成功0、元のHRESULTまたは完全rank変化のERROR_RETRY。
	 */
	NativeError verify( const CommonInfInstallPlan::State &plan,
					   const CommonInfBindingRevalidator &revalidator)
	{
		const auto &owner = *plan.owner ;									// Scopeが所有とbusyを維持する元取得。
		const auto &inf	  = owner.inspected.infs[plan.request.infIndex] ;	// 内部検査済み単一INF。
		NativeError error = owner.session->verifyAcquiredFile(
			owner.evidence, *owner.archive) ;	// 元封印の再照合結果。
		// 前の検証失敗を通常内容合格で補完しない。
		if( error == 0) {
			error = reverifyCommonDriverInf( inf) ;
		}

		// 元取得と内容の失敗ではWindows照合へ進まない。
		if( error != 0) {
			return error ;
		}

		OfficialDriverRankAudit rank ;										// 導入直前の完全rank観測。
		const auto			   &package = inf.closure.packages.front() ;	// 私有所有の一基本INF。
		error = owner.rankAuditor( plan.request.scanSessionId, plan.request.deviceIdentity,
								  *inf.workspace, package, rank) ;
		// 版や決定値だけで発行時の完全rank一致を補わない。
		if( error != 0 || rank.decision != OfficialDriverRankDecision::APPLICABLE ||
		   !equalPlanRank( rank, plan.binding.rankAudit)) {
			return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}

		return revalidator( plan.request.scanSessionId, plan.request.deviceIdentity, *inf.workspace,
						   package, plan.binding) ;
	}
} ;

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
CommonInfPlanExecutionResult CommonInfPlanExecutor::execute(
	ScanSessionId scanSessionId, std::span<const CommonInfPlanSelection> selections,
	const CommonInfBindingRevalidator &revalidator, const OfficialBoundInfInstaller &installer,
	std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback)
{
	CommonInfPlanExecutionResult report ;		// 元結果と失効結果を別々に保持する。
	Scope						 scope ;		// Return・例外にかかわらず受理済み所有者を回収する。
	NativeError					 error{} ;		// 全件停止または最初の個別失敗。
	std::size_t					 completed{} ;	// 実際にcallbackが完了した件数だけを数える。
	try {
		// 空・予算超過では私有所有者へ触れない。
		if( selections.empty() || selections.size() > MAXIMUM_PLANS) {
			report.result.installOutcome = OutcomeCode::FAILURE ;
			report.result.installError	 = E_INVALIDARG ;
			return report ;
		}

		// Identityを結果へ複写する前に有限長を確認し、入力から無制限allocationを要求させない。
		for( const auto &selection : selections) {
			// 不正な過大入力は私有所有者の操作へ進めない。
			if( selection.candidateIdentity.size() > 256U ||
			   selection.deviceIdentity.size() > 256U) {
				report.result.installOutcome = OutcomeCode::FAILURE ;
				report.result.installError	 = E_INVALIDARG ;
				return report ;
			}
		}

		report.result.updates.reserve( selections.size()) ;
		report.installerInvoked.resize( selections.size(), false) ;
		// 拒否で途中終了しても選択全件の個別結果を保持する。
		for( const auto &selection : selections) {
			report.result.updates.push_back( {.identity = selection.candidateIdentity}) ;
		}

		// 私有状態の所有者を先に確認し、別thread／再入を全件で拒否する。
		for( const auto &selection : selections) {
			// 空計画は後の入力照合で拒否するが、既存所有者の生存を確保する。
			if( selection.plan == nullptr || !selection.plan->state_) {
				continue ;
			}

			const auto owner = selection.plan->state_->owner ;	// 実行終了まで保持する私有元取得。
			// 既存の別操作を失効させないよう、lock前に全件確認する。
			if( owner->thread != GetCurrentThreadId() || owner->busy) {
				error = RPC_E_WRONG_THREAD ;
				break ;
			}

			// 同じfactoryは一度だけ参加集合へ加える。
			if( std::find( scope.owners.begin(), scope.owners.end(), owner) == scope.owners.end()) {
				scope.owners.push_back( owner) ;
			}
		}

		// 同workerで受理した集合だけを排他・終了失効の対象にする。
		if( error == 0) {
			// 全参加所有者を一括で再入拒否にしてからcallbackへ進む。
			for( const auto &owner : scope.owners) {
				owner->busy			= true ;
				owner->cleanupError = 0 ;
			}

			scope.locked = true ;
			// Callback不足やscan欠損も受理後は計画を再利用させない。
			if( scanSessionId == 0U || !revalidator || !installer) {
				error = E_INVALIDARG ;
			}
		}

		std::set<std::wstring> candidates ;	// 全選択のopaque候補重複を拒否する。
		std::set<std::wstring> devices ;	// 一device一基本計画を維持する。
		// 全identity・token・通常単一INFを最初のWindows導入より前に確認する。
		for( std::size_t index = 0U; error == 0 && index < selections.size(); ++index) {
			const auto &selection = selections[index] ;	// 使用中変更しない借用選択。
			// Public identityや空計画から実行許可を作らない。
			if( selection.plan == nullptr || !selection.plan->state_) {
				error = E_INVALIDARG ;
				break ;
			}

			const auto &plan  = *selection.plan->state_ ;					// Factory発行の非公開結合。
			const auto &owner = *plan.owner ;								// 同workerで固定された所有者。
			const auto	token = owner.tokens.find( plan.binding.token) ;	// 私有発行集合の照合。
			// scan・両identity・token・一device一候補を完全一致させる。
			if( !owner.active || plan.request.scanSessionId != scanSessionId ||
			   owner.inspected.scanSessionId != scanSessionId || token == owner.tokens.end() ||
			   token->second != selection.candidateIdentity ||
			   plan.request.candidateIdentity != selection.candidateIdentity ||
			   plan.request.deviceIdentity != selection.deviceIdentity ||
			   !candidates.insert( selection.candidateIdentity).second ||
			   !devices.insert( selection.deviceIdentity).second ||
			   plan.request.infIndex >= owner.inspected.infs.size()) {
				error = E_INVALIDARG ;
				break ;
			}

			report.result.updates[index].downloadOutcome = OutcomeCode::SUCCESS ;
			const auto &inf =
				owner.inspected.infs[plan.request.infIndex] ;	// 所有閉包だけを使用する。
			// 準備済みでも依存／拒否を公開boolで解除しない。
			if( inf.state != CommonInfInspectionState::VERIFIED || inf.error != 0 ||
			   !inf.workspace || inf.scanSessionId != scanSessionId ||
			   inf.closure.packages.size() != 1U || inf.closure.entries.empty() ||
			   inf.closure.packages.front().hasExternalDependencies) {
				error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				break ;
			}

			error = scope.pin( owner.evidence.observation().inspectionPath) ;
			// 全閉包を一括で固定し、共有fileの固定をcallback終了まで保持する。
			for( const auto &entry : inf.closure.entries) {
				// 最初の固定失敗を別memberの成功で隠さない。
				if( error != 0) {
					break ;
				}

				error = scope.pin( inf.workspace->path( entry.relativePath)) ;
			}
		}

		// 全件preflight。後続の一件が失敗しても導入は一件も開始しない。
		for( std::size_t index = 0U; error == 0 && index < selections.size(); ++index) {
			error = scope.verify( *selections[index].plan->state_, revalidator) ;
		}

		// 確定進捗0だけを通知し、待ち時間で加算しない。
		if( error == 0 && progressCallback) {
			progressCallback( {.stage	  = ProviderStage::INSTALLING,
							  .totalItems = static_cast<std::uint32_t>( selections.size())}) ;
		}

		// 全件検証後だけ個別の直前照合と既存指定導入へ進む。
		for( std::size_t index = 0U; error == 0 && index < selections.size(); ++index) {
			const auto &plan = *selections[index].plan->state_ ;	// Busy中のprivate結合。
			error			 = scope.verify( plan, revalidator) ;
			// 先の導入で別device状態が変わった場合も残りを自動導入しない。
			if( error != 0) {
				report.result.updates[index].installError = error ;
				break ;
			}

			auto	   &item = report.result.updates[index] ;						// 呼出し済み項目の個別結果。
			const auto &inf	 = plan.owner->inspected.infs[plan.request.infIndex] ;	// 私有閉包。
			report.installerInvoked[index] = true ;
			try {
				error = installer( scanSessionId, plan.request.deviceIdentity, *inf.workspace,
								  inf.closure.packages.front(), plan.binding, parentWindowNative,
								  item.rebootRequired) ;
			} catch( const std::bad_alloc &) {
				error = E_OUTOFMEMORY ;
			} catch( ...) {
				// Windows変更が未確定の例外を変更なし・自動retryへ変換しない。
				error = E_UNEXPECTED ;
			}

			item.installError			 = error ;
			item.installOutcome			 = error == 0 ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
			report.result.rebootRequired = report.result.rebootRequired || item.rebootRequired ;
			++completed ;
			// Callback完了済み件数だけを全体の進捗へ反映する。
			if( progressCallback) {
				progressCallback( {.stage		   = ProviderStage::INSTALLING,
								  .percentComplete = static_cast<std::uint32_t>( completed * 100U /
																				selections.size()),
								  .completedItems  = static_cast<std::uint32_t>( completed),
								  .totalItems = static_cast<std::uint32_t>( selections.size())}) ;
			}
		}
	} catch( const std::bad_alloc &) {
		// 通知例外で既に記録した導入失敗を上書きしない。
		if( error == 0) {
			error = E_OUTOFMEMORY ;
		}
	} catch( ...) {
		// 検査／通知callback例外でも完了済み結果を保持し、未開始を成功にしない。
		if( error == 0) {
			error = E_UNEXPECTED ;
		}
	}

	// 未開始項目にも停止診断を残し、完了済みの元HRESULTは変更しない。
	for( auto &item : report.result.updates) {
		// 実行済み結果を変更せず、未開始に停止理由だけを付ける。
		if( item.installOutcome == OutcomeCode::NOT_STARTED) {
			item.installError = error ;
		}
	}

	report.cleanupError = scope.finish() ;
	report.result.downloadOutcome =
		report.result.updates.size() == selections.size() &&
				std::all_of(
					report.result.updates.begin(), report.result.updates.end(),
					// 選択順に保持した実取得事実だけを集約する。
					[]( const auto &item) { return item.downloadOutcome == OutcomeCode::SUCCESS ; })
			? OutcomeCode::SUCCESS
			: OutcomeCode::NOT_STARTED ;
	report.result.installError = error ;
	const bool anySucceeded =
		std::any_of( report.result.updates.begin(), report.result.updates.end(),
					// 全callback失敗を一部成功と呼ばない。
					[]( const auto &item) { return item.installOutcome == OutcomeCode::SUCCESS ; }) ;
	report.result.installOutcome = error == 0	  ? OutcomeCode::SUCCESS
								   : anySucceeded ? OutcomeCode::SUCCEEDED_WITH_ERRORS
												  : OutcomeCode::FAILURE ;
	report.result.succeeded =
		error == 0 && completed == selections.size() && report.cleanupError == 0 ;
	return report ;
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
CommonInfPlanFactory::CommonInfPlanFactory() = default ;
/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
CommonInfPlanFactory::~CommonInfPlanFactory()
{
	static_cast<void>( invalidate()) ;
}
/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
CommonInfInstallPlan::CommonInfInstallPlan() = default ;
/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
CommonInfInstallPlan::~CommonInfInstallPlan()
{
	static_cast<void>( invalidate()) ;
}
/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
CommonInfInstallPlan::CommonInfInstallPlan( CommonInfInstallPlan &&other) noexcept = default ;

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
NativeError CommonInfPlanFactory::initialize(
	std::shared_ptr<const OfficialAcquisitionSession> session,
	std::unique_ptr<OfficialDownloadWorkspace> &archive, OfficialAcquiredFileEvidence &evidence,
	OfficialDriverArchiveFormat format, const OfficialInfRankAuditor &rankAuditor,
	const OfficialInfInstallBinder &binder, const OfficialInfInstallBindingReleaser &releaser,
	const OfficialAuditCancellation &cancellation)
{
	// 公開DTOからの再構成・再初期化・不完全callbackを検査開始前に拒否する。
	if( state_ || initializing_ || !session || !archive || !rankAuditor || !binder || !releaser ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET)) {
		return E_INVALIDARG ;
	}

	PlanBusyScope initializing( initializing_) ;	// 初期化中もcallbackからの所有上書きを拒否する。
	try {
		const auto &observed = evidence.observation() ;	// 封印証拠内部の固定metadata。
		// 通常検査上限を取得層の大容量許可で緩和しない。
		if( observed.byteCount == 0U || observed.byteCount > MAXIMUM_ARCHIVE_BYTES) {
			return E_INVALIDARG ;
		}

		std::vector<PlanHandle> pins ;										// 元fileと全祖先を検査・commit終了まで固定する。
		NativeError error = pinPlanFile( observed.inspectionPath, pins) ;	// 元位置を先に固定する。
		// 元位置の固定失敗では内容解析へ進まない。
		if( error != 0) {
			return error ;
		}

		error = session->verifyAcquiredFile( evidence, *archive) ;
		// 別issuerや別workspaceの同byteを受理しない。
		if( error != 0) {
			return error ;
		}

		auto pending = std::make_shared<State>() ;	// すべての検査後だけ公開する一時所有。
		const DriverArchiveInput input{observed.scanSessionId, observed.inspectionPath,
									   observed.byteCount,
									   observed.sha256} ;	// 認証済み元fileからのみ構築する。
		error = inspectCommonDriverPackage( input, format, pending->inspected, cancellation) ;
		// 全体失敗・改変された検査結合を部分合格へ変換しない。
		if( error != 0) {
			return error ;
		}

		// 通常検査の元session・hash・size・全INF上限を固定する。
		if( pending->inspected.error != 0 ||
		   pending->inspected.scanSessionId != observed.scanSessionId ||
		   pending->inspected.archiveSha256 != observed.sha256 ||
		   pending->inspected.archiveBytes != observed.byteCount ||
		   pending->inspected.infs.size() > 128U) {
			return E_INVALIDARG ;
		}

		error = session->verifyAcquiredFile( evidence, *archive) ;
		// 全同期検査中の失効・変更も所有commit前に拒否する。
		if( error != 0) {
			return error ;
		}

		pending->rankAuditor = rankAuditor ;
		pending->binder		 = binder ;
		pending->releaser	 = releaser ;
		pending->session	 = std::move( session) ;
		pending->thread		 = GetCurrentThreadId() ;
		pending->active		 = true ;
		pending->archive	 = std::move( archive) ;
		pending->evidence	 = std::move( evidence) ;
		state_				 = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
NativeError CommonInfPlanFactory::prepare( const CommonInfPlanRequest &request,
										  CommonInfInstallPlan		 &plan)
{
	// 空・失効・別thread・再入・出力上書きをbinding開始前に拒否する。
	if( !state_ || !state_->active || state_->thread != GetCurrentThreadId() || state_->busy ||
	   plan.state_) {
		return E_INVALIDARG ;
	}

	PlanBusyScope busy( state_->busy) ;	// Callbackからの再入を全returnで拒否する。
	state_->cleanupError = 0 ;
	OfficialInfInstallBinding issued ;	// 発行後にcommitできないtokenを解放するための一時値。
	try {
		// 入力identityと現在driverを有限にし、初回導入を架空版で通さない。
		if( request.scanSessionId != state_->inspected.scanSessionId ||
		   request.infIndex >= state_->inspected.infs.size() || request.candidateIdentity.empty() ||
		   request.candidateIdentity.size() > 256U || request.deviceIdentity.empty() ||
		   request.deviceIdentity.size() > 256U || request.currentProvider.empty() ||
		   request.currentProvider.size() > 256U || request.currentVersion.empty() ||
		   request.currentVersion.size() > 128U || request.currentDate.empty() ||
		   request.currentDate.size() > 32U) {
			return E_INVALIDARG ;
		}

		// この操作の同時保持件数だけを制限する。
		if( state_->tokens.size() >= MAXIMUM_PLANS) {
			return HRESULT_FROM_WIN32( ERROR_TOO_MANY_NAMES) ;
		}

		// 同じ候補IDへ二つの秘密routingを発行しない。
		for( const auto &entry : state_->tokens) {
			// 保持済み候補の上書きを拒否する。
			if( entry.second == request.candidateIdentity) {
				return E_INVALIDARG ;
			}
		}

		const CommonInfInspection &inf =
			state_->inspected.infs[request.infIndex] ;	// 内部で検査した閉包。
		// 通常内容合格かつ明示依存なしの一基本INFだけを接続する。
		if( inf.state != CommonInfInspectionState::VERIFIED || inf.error != 0 || !inf.workspace ||
		   inf.scanSessionId != request.scanSessionId || inf.closure.packages.size() != 1U ||
		   inf.closure.entries.empty() || inf.closure.packages.front().hasExternalDependencies) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		std::vector<PlanHandle> pins ;	// 元archiveと全閉包fileを発行返却まで固定する。
		NativeError				error =
			// 元位置の再固定。
			pinPlanFile( state_->evidence.observation().inspectionPath, pins) ;
		// 元取得の変更や失効を検査済みboolで補わない。
		if( error == 0) {
			error = state_->session->verifyAcquiredFile( state_->evidence, *state_->archive) ;
		}

		// 全memberを固定し、一つでも競合があればbindingしない。
		for( const auto &entry : inf.closure.entries) {
			// 前の固定失敗を後の成功で上書きしない。
			if( error != 0) {
				return error ;
			}

			error = pinPlanFile( inf.workspace->path( entry.relativePath), pins) ;
		}

		// 全fileの署名・内容再検証を既存通常処理へ委譲する。
		if( error == 0) {
			error = reverifyCommonDriverInf( inf) ;
		}

		// 内容失敗ではWindows rankへ進まない。
		if( error != 0) {
			return error ;
		}

		auto pending =
			std::make_unique<CommonInfInstallPlan::State>() ;	// Binding前に確保する未commit計画。
		pending->owner	 = state_ ;
		pending->request = request ;
		OfficialDriverRankAudit	  rank ;									// 現在deviceと全rankの新規観測。
		const OfficialInfPackage &package = inf.closure.packages.front() ;	// 正常な単一基本INF。
		error = state_->rankAuditor( request.scanSessionId, request.deviceIdentity, *inf.workspace,
									package, rank) ;
		// Rankを独自の版比較で置換しない。
		if( error != 0) {
			return error ;
		}

		// 完全監査が適用可能でない場合はbindingを発行しない。
		if( rank.decision != OfficialDriverRankDecision::APPLICABLE) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		error = state_->binder( request.scanSessionId, request.deviceIdentity, *inf.workspace,
							   package, request.currentProvider, request.currentVersion,
							   request.currentDate, rank, issued) ;
		// 別計画の既存tokenを重複返却しても解放しない。
		if( issued.token != 0U && state_->tokens.contains( issued.token)) {
			issued.token = 0U ;
			return E_INVALIDARG ;
		}

		// 発行後のmetadata不一致は本操作の新規tokenだけを解放する。
		if( error != 0 || issued.token == 0U || issued.currentProvider != request.currentProvider ||
		   issued.currentVersion != request.currentVersion ||
		   issued.currentDate != request.currentDate ||
		   issued.candidateProvider != package.providerName ||
		   issued.candidateVersion != package.driverVersion ||
		   issued.candidateDate != package.driverDate || !equalPlanRank( issued.rankAudit, rank)) {
			const NativeError primary =
				error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;	// 元発行診断。
			const NativeError cleanup =
				// 本操作だけのrollback。
				issued.token == 0U ? 0 : state_->release( issued.token) ;
			issued.token		 = 0U ;
			state_->cleanupError = cleanup ;
			return primary ;
		}

		state_->tokens.emplace( issued.token, request.candidateIdentity) ;
		pending->binding = std::move( issued) ;
		plan.state_		 = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		state_->cleanupError = state_->rollbackUncommitted( issued.token) ;
		return E_OUTOFMEMORY ;
	} catch( ...) {
		const NativeError cleanup =
			// 途中発行のrollback。
			state_->rollbackUncommitted( issued.token) ;
		state_->cleanupError = cleanup ;
		return E_UNEXPECTED ;
	}
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
std::size_t CommonInfPlanFactory::infCount() const noexcept
{
	return state_ && state_->active && state_->thread == GetCurrentThreadId()
			   ? state_->inspected.infs.size()
			   : 0U ;
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
NativeError CommonInfPlanFactory::lastCleanupError() const noexcept
{
	return state_ && state_->thread == GetCurrentThreadId() ? state_->cleanupError : 0 ;
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
NativeError CommonInfPlanFactory::invalidate() noexcept
{
	// 初期化callback内の失効要求を完了やcancelとして処理しない。
	if( initializing_) {
		return RPC_E_CALL_REJECTED ;
	}

	// 空のfactoryは変更不要とする。
	if( !state_) {
		return 0 ;
	}

	// 別threadとcallback再入ではWindows側のtokenを変更しない。
	if( state_->thread != GetCurrentThreadId() || state_->busy) {
		return RPC_E_WRONG_THREAD ;
	}

	PlanBusyScope busy( state_->busy) ;	// 失効中のcallback再入を拒否する。
	state_->active = false ;
	NativeError first{} ;	// 最初の解放失敗を保持する。
	// 本factoryで発行したtokenだけを解放する。
	for( const auto &entry : state_->tokens) {
		const NativeError error = state_->release( entry.first) ;	// 当該tokenの解放結果。
		// 個別成功で既存失敗を消さない。
		if( first == 0 && error != 0) {
			first = error ;
		}
	}

	state_->tokens.clear() ;
	state_->cleanupError = first ;
	return first ;
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
bool CommonInfInstallPlan::isBound() const noexcept
{
	return state_ && state_->owner->active && state_->owner->thread == GetCurrentThreadId() &&
		   state_->owner->tokens.contains( state_->binding.token) ;
}

/** @see src/platform/common_inf_plan.h 宣言側の契約を正本とする。 */
NativeError CommonInfInstallPlan::invalidate() noexcept
{
	// 空やmove元はtokenを持たない。
	if( !state_) {
		return 0 ;
	}

	const auto owner = state_->owner ;	// 解放callback終了まで元取得の所有者を保持する。
	// 別threadとcallback再入では状態とWindows側を変更しない。
	if( owner->thread != GetCurrentThreadId() || owner->busy) {
		return RPC_E_WRONG_THREAD ;
	}

	PlanBusyScope		busy( owner->busy) ;				// 個別解放の再入を拒否する。
	const std::uint64_t token = state_->binding.token ;		// 外部へ返さない対象token。
	const bool owned = owner->tokens.erase( token) != 0U ;	// Factory全失効済みでは二重解放しない。
	state_.reset() ;
	const NativeError cleanup = owned ? owner->release( token) : 0 ;	// 独立した解放診断。
	owner->cleanupError		  = cleanup ;
	return cleanup ;
}
} // namespace drivercrate
