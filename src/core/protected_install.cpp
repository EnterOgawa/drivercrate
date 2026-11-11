//------------------------------------------------------------------------------
/**
 * @file protected_install.cpp
 * @brief OS別回復保護付きinstall処理実装。
 * @version 01.01.01
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元処理進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server専用経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.01.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note Clientの復元ポイント保護とServerの明示同意済み経路を実装します。Server専用経路の利用可否はworkerが実OSを再検証します。
 */
//------------------------------------------------------------------------------

#include "core/protected_install.h"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 開始済み復元ポイントへの終了通知をscopeで保証する。
 */
class RestorePointScope final {
public:
	/**
     * @brief 終了通知対象のサービスとsequence numberを保持する。
     * @param[in,out] service 復元ポイントサービス。
     * @param[in] sequenceNumber 開始済み復元ポイントの識別番号。
     */
	RestorePointScope( IRestorePointService &service, std::int64_t sequenceNumber) noexcept ;

	/**
	 * @brief 明示終了されていない復元ポイントへ終了通知を行う。
	 */
	~RestorePointScope() ;

	// 同じ復元ポイントへ複数回終了通知しないようcopy/moveを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	RestorePointScope( const RestorePointScope &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	RestorePointScope &operator=( const RestorePointScope &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	RestorePointScope( RestorePointScope &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	RestorePointScope						 &operator=( RestorePointScope &&) = delete ;

	/**
	 * @brief 復元ポイントへ終了通知し、結果を返す。
	 * @return Windows復元ポイントAPIの終了結果。
	 */
	[[nodiscard]] RestorePointOperationResult complete() noexcept ;

private:
	/// 終了通知先。scopeより長く生存する非所有参照。
	IRestorePointService &service_ ;
	/// 開始済み復元ポイントの識別番号。
	std::int64_t		  sequenceNumber_{} ;
	/// trueの場合は終了通知を再実行しない。
	bool				  completed_{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Providerを実行しなかった候補別結果を作成する。
 *
 * @param[in] identities UIが選択したopaque identity群。
 * @return 全候補を未開始として保持する失敗結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult makeUnstartedInstallResult(
	const std::span<const std::wstring> identities)
{
	InstallResult result{} ;	// 選択identityとの対応だけを保持する未開始結果。
	result.updates.reserve( identities.size()) ;

	// UIが全選択候補を未インストールとして表示できるようidentityを保持する。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider例外を候補別の失敗結果へ変換する。
 *
 * @param[in] identities UIが選択したopaque identity群。
 * @return E_UNEXPECTEDを保持する候補別失敗結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult makeExceptionInstallResult(
	const std::span<const std::wstring> identities)
{
	// 型不明のProvider例外を、候補別結果へ記録するE_UNEXPECTEDのbit pattern。
	constexpr NativeError UNEXPECTED_ERROR = static_cast<NativeError>( 0x8000FFFFU) ;
	InstallResult		  result{} ;	// Provider境界の型不明例外を示すsynthetic結果。
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = UNEXPECTED_ERROR ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = UNEXPECTED_ERROR ;
	result.updates.reserve( identities.size()) ;

	// 全選択候補を同じProvider境界エラーへ対応付ける。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::FAILURE,
								  .downloadError   = UNEXPECTED_ERROR,
								  .installOutcome  = OutcomeCode::FAILURE,
								  .installError	   = UNEXPECTED_ERROR}) ;
	}

	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 終了通知対象のサービスとsequence numberを保持する。
 * @param[in,out] service 復元ポイントサービス。
 * @param[in] sequenceNumber 開始済み復元ポイントの識別番号。
 */
//------------------------------------------------------------------------------
RestorePointScope::RestorePointScope( IRestorePointService &service,
									 const std::int64_t	   sequenceNumber) noexcept
	: service_( service), sequenceNumber_( sequenceNumber)
{
}

//------------------------------------------------------------------------------
/**
 * @brief 明示終了されていない復元ポイントへ終了通知を行う。
 */
//------------------------------------------------------------------------------
RestorePointScope::~RestorePointScope()
{
	// 例外などで明示終了に到達しなかった復元ポイントにも、scope終了時に終了通知を行う。
	if( !completed_) {
		static_cast<void>( service_.complete( sequenceNumber_)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイントへ終了通知し、結果を返す。
 * @return Windows復元ポイントAPIの終了結果。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult RestorePointScope::complete() noexcept
{
	completed_ = true ;
	return service_.complete( sequenceNumber_) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイントで保護したdriver download/installを同期実行する。実在保護未成立時はProviderを呼ばない。native BEGIN所有時は正常・失敗・例外で
 *        もEND一回を試行する。同日再利用は両native操作を呼ばない。
 * @param[in,out] provider 選択候補を処理するProvider。worker thread専用である。
 * @param[in,out] restorePointService 復元ポイントを開始・終了するサービス。 復元ポイントサービス。
 * @param[in] scanSessionId 選択元のscan session ID。
 * @param[in] identities UIが明示選択したopaque identity群。
 * @param[in] parentWindowNative Windows dialogの親HWNDを整数表現で渡す値。
 * @param[in] progressCallback 復元、download、installの全体進捗通知先。
 * @param[in] restorePointDescription Windowsの復元UIへ表示する説明。 復元UIに表示する説明。
 * @return 復元ポイントと候補ごとの実行結果。
 * @note 保護scopeは必ず閉じる。再利用の実在とnative呼出し事実を分け、メモ失敗だけで実導入成否を変更しない。
 */
//------------------------------------------------------------------------------
InstallResult installWithRestorePoint( IUpdateProvider					 &provider,
									  IRestorePointService				 &restorePointService,
									  const ScanSessionId				  scanSessionId,
									  const std::span<const std::wstring> identities,
									  const std::uintptr_t				  parentWindowNative,
									  const ProviderProgressCallback	 &progressCallback,
									  const std::wstring_view			  restorePointDescription)
{
	progressCallback( {.stage = ProviderStage::VERIFYING_RESTORE_POINT}) ;
	// Driver変更前にWindowsへ復元ポイント開始を要求する。
	const RestorePointOperationResult creation = restorePointService.begin( restorePointDescription) ;
	const auto protection = restorePointService.protection() ;	// native結果と実在確認を分けます。
	const bool legacy	  = protection.disposition ==
						RestorePointDisposition::NATIVE_TRANSACTION ;	// 旧serviceのnative契約です。
	const bool daily = protection.disposition ==
					   RestorePointDisposition::SAME_DAY_REUSED ;	// native未実行の再利用です。
	const bool knownDisposition =
		daily || protection.disposition == RestorePointDisposition::NEW_POINT_VERIFIED ||
		protection.disposition ==
			RestorePointDisposition::WINDOWS_SELECTED_POINT ;	// 実在保護を許す閉集合です。
	// 復元ポイントの開始成功と有効な番号がそろわなければ、Providerを呼ばず中止する。
	const bool prepared =
		knownDisposition && protection.verifiedBefore &&
		protection.verification == OutcomeCode::SUCCESS && protection.error == 0 &&
		protection.sequenceNumber > 0 && creation.error == 0 && protection.createdUtc > 0 &&
		protection.localDay != 0 && !protection.nativeEndCalled &&
		(daily ? creation.outcome == OutcomeCode::NOT_STARTED && !protection.nativeBeginCalled &&
					 creation.sequenceNumber == protection.sequenceNumber
			   : creation.outcome == OutcomeCode::SUCCESS && protection.nativeBeginCalled &&
					 creation.sequenceNumber == protection.sequenceNumber) ;
	// 実在保護が成立しなければProviderを実行しません。
	if( !prepared) {
		InstallResult result  = makeUnstartedInstallResult( identities) ;	// Fail-closed結果。
		result.protectionMode = InstallProtectionMode::WINDOWS_RESTORE_POINT ;
		result.restorePointCreation =
			legacy || protection.nativeBeginCalled ? creation : RestorePointOperationResult{} ;
		// BEGIN成功後に実在確認だけが失敗したscopeも、元sequenceへENDを一回通知します。
		if( creation.outcome == OutcomeCode::SUCCESS && creation.sequenceNumber > 0) {
			result.restorePointCompletion = restorePointService.complete( creation.sequenceNumber) ;
		}

		result.restorePointProtection = restorePointService.protection() ;
		// 不正な区分/結合を実在保護成功へ表示せず、元native結果は保持します。
		result.restorePointProtection.verification = OutcomeCode::FAILURE ;
		// 元診断が欠けた場合だけ未成立のcodeを補います。
		if( result.restorePointProtection.error == 0) {
			result.restorePointProtection.error =
				creation.error ? creation.error : static_cast<NativeError>( 0x8000FFFFU) ;
		}

		progressCallback( {.stage = ProviderStage::VERIFYING_RESTORE_POINT, .percentComplete = 100}) ;
		return result ;
	}

	progressCallback( {.stage = protection.disposition == RestorePointDisposition::NEW_POINT_VERIFIED
								   ? ProviderStage::CREATING_RESTORE_POINT
								   : ProviderStage::REUSING_RESTORE_POINT,
					  .percentComplete = 10}) ;

	RestorePointScope			   restorePointScope( restorePointService,
													 creation.sequenceNumber) ;	// 終了通知guard。
	InstallResult				   result{} ;									// Provider結果へ復元ポイント結果を付加する最終結果。
	// Provider内部の0～100%を保護付きoperation全体の10～90%へ変換する通知関数。
	const ProviderProgressCallback providerProgressCallback =
		[&progressCallback]( const ProviderProgress &progress) {
			ProviderProgress protectedProgress = progress ;	// 復元処理を含む全体進捗値。
			protectedProgress.percentComplete =
				10 + std::min<std::uint32_t>( progress.percentComplete, 100) * 80 / 100 ;
			progressCallback( protectedProgress) ;
		} ;
	try {
		result = provider.install( scanSessionId, identities, parentWindowNative,
								  providerProgressCallback) ;
	} catch( ...) {
		// Provider例外をthread境界へ漏らさず、復元ポイントを終了して失敗結果を返す。
		result = makeExceptionInstallResult( identities) ;
	}

	result.restorePointCreation = creation ;
	result.protectionMode		= InstallProtectionMode::WINDOWS_RESTORE_POINT ;
	progressCallback( {.stage		   = daily ? ProviderStage::VERIFYING_RESTORE_POINT
											   : ProviderStage::FINALIZING_RESTORE_POINT,
					  .percentComplete = 90}) ;
	result.restorePointCompletion = restorePointScope.complete() ;
	result.restorePointProtection = restorePointService.protection() ;
	// 終了通知の失敗は全体成功へ含めず、実際の個別導入結果を保持したまま報告する。
	if( !isRestorePointProtectionValid( result)) {
		// 終了通知失敗を全体成功として表示しないが、実際の候補別結果は保持する。
		result.succeeded = false ;
	}

	progressCallback( {.stage		   = daily ? ProviderStage::VERIFYING_RESTORE_POINT
											   : ProviderStage::FINALIZING_RESTORE_POINT,
					  .percentComplete = 100}) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Serverで復元ポイントを呼ばずdriver download/installを同期実行する。Windows Serverで復元ポイントなしのinstallを実行
 *        する。SRSetRestorePointWを呼ばずProviderを実行する。呼出側でOSと管理者同意を検証し、Provider例外は失敗結果へ変換する。
 * @param[in,out] provider 選択候補を処理するProvider。worker thread専用である。
 * @param[in] scanSessionId 選択元のscan session ID。
 * @param[in] identities UIが明示選択したopaque identity群。 UIが選択したopaque identity群。
 * @param[in] parentWindowNative Windows dialogの親HWNDを整数表現で渡す値。
 * @param[in] progressCallback download、installの進捗通知先。
 * @return Server専用modeと候補ごとの実行結果。復元ポイント結果は`NOT_STARTED`である。
 * @note 呼出側は実OSがWindows Serverであり、利用者が復元ポイントなしの実行へ明示同意したことをworker境界で検証しなければならない。Provider例外は失敗結果へ変換する。
 */
//------------------------------------------------------------------------------
InstallResult installWithoutRestorePointOnServer( IUpdateProvider					&provider,
												 const ScanSessionId				 scanSessionId,
												 const std::span<const std::wstring> identities,
												 const std::uintptr_t			 parentWindowNative,
												 const ProviderProgressCallback &progressCallback)
{
	InstallResult result{} ;	// Provider結果へServer専用保護modeを付加する最終結果。
	try {
		result = provider.install( scanSessionId, identities, parentWindowNative, progressCallback) ;
	} catch( ...) {
		// Provider例外をworker境界へ漏らさず、全選択候補の失敗結果へ変換する。
		result = makeExceptionInstallResult( identities) ;
	}

	result.protectionMode		  = InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT ;
	result.restorePointCreation	  = {} ;
	result.restorePointCompletion = {} ;
	result.restorePointProtection = {} ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定したOS種別とinstall保護方針の組合せを検証する。Clientで復元ポイント回避、Serverで非support API使用を許可しないfail-closed判定を行う。
 * @param[in] windowsServer 実OSがWindows Serverの場合は`true`。 Windows Serverの場合はtrue。
 * @param[in] protectionMode 利用者確認時に固定した保護方針。
 * @return ServerだけがServer専用mode、clientだけが復元ポイントmodeの場合は`true`。 OSに対応する唯一の保護方針の場合は`true`。
 */
//------------------------------------------------------------------------------
bool isInstallProtectionModeAllowed( const bool					windowsServer,
									const InstallProtectionMode protectionMode) noexcept
{
	// Serverでは専用確認modeだけを許可し、非対応のSystem Restore経路へ進めない。
	if( windowsServer) {
		return protectionMode == InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT ;
	}

	return protectionMode == InstallProtectionMode::WINDOWS_RESTORE_POINT ;
}

//------------------------------------------------------------------------------
/**
 * @brief Native呼出し事実とOS別実在保護の整合性を検査します。
 * @param[in] result 受理するInstall結果です。
 * @return 指定保護契約に一致する場合trueです。memo保存失敗は実導入成否を変更しません。
 */
//------------------------------------------------------------------------------
bool isRestorePointProtectionValid( const InstallResult &result) noexcept
{
	const auto &begin = result.restorePointCreation ;	// 実native開始です。
	const auto &end	  = result.restorePointCompletion ;	// 実native終了です。
	const auto &p	  = result.restorePointProtection ;	// 実在確認です。
	// Serverでは実在確認と両native操作が未実行であることを要求します。
	if( result.protectionMode == InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) {
		return begin.outcome == OutcomeCode::NOT_STARTED &&
			   end.outcome == OutcomeCode::NOT_STARTED &&
			   p.verification == OutcomeCode::NOT_STARTED && !p.nativeBeginCalled &&
			   !p.nativeEndCalled ;
	}

	// 定義外の保護modeを受理しません。
	if( result.protectionMode != InstallProtectionMode::WINDOWS_RESTORE_POINT) {
		return false ;
	}

	// bare native成功はClientの実在保護に使いません。
	if( p.disposition == RestorePointDisposition::NATIVE_TRANSACTION) {
		// Bare API成功だけでは現在の実在保護を証明しません。
		return false ;
	}

	// 同じscopeの開始前後の実在と原番号を要求します。
	if( !p.verifiedBefore || !p.verifiedAfter || p.verification != OutcomeCode::SUCCESS ||
	   p.error != 0 || p.sequenceNumber <= 0 || p.createdUtc <= 0 || p.localDay == 0) {
		return false ;
	}

	// 日内再利用ではnative操作の未実行を要求します。
	if( p.disposition == RestorePointDisposition::SAME_DAY_REUSED) {
		return !p.nativeBeginCalled && !p.nativeEndCalled &&
			   begin.outcome == OutcomeCode::NOT_STARTED &&
			   end.outcome == OutcomeCode::NOT_STARTED && begin.error == 0 && end.error == 0 ;
	}

	// 新規またはWindows選択の区分以外を拒否します。
	if( p.disposition != RestorePointDisposition::NEW_POINT_VERIFIED &&
	   p.disposition != RestorePointDisposition::WINDOWS_SELECTED_POINT) {
		return false ;
	}

	return p.nativeBeginCalled && p.nativeEndCalled && begin.outcome == OutcomeCode::SUCCESS &&
		   end.outcome == OutcomeCode::SUCCESS && begin.error == 0 && end.error == 0 &&
		   begin.sequenceNumber == p.sequenceNumber && end.sequenceNumber == p.sequenceNumber ;
}

} // namespace drivercrate
