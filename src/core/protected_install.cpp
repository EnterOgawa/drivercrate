//------------------------------------------------------------------------------
/**
 * @file protected_install.cpp
 * @brief OS別回復保護付きinstall処理実装。
 * @version 01.00.01
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
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
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
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
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
 * @see src/core/protected_install.cpp RestorePointScope宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointScope::RestorePointScope( IRestorePointService &service,
									 const std::int64_t	   sequenceNumber) noexcept
	: service_( service), sequenceNumber_( sequenceNumber)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/core/protected_install.cpp 宣言側の契約を正本とする。
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
 * @see src/core/protected_install.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult RestorePointScope::complete() noexcept
{
	completed_ = true ;
	return service_.complete( sequenceNumber_) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/protected_install.h 宣言側の契約を正本とする。
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
	progressCallback( {.stage = ProviderStage::CREATING_RESTORE_POINT}) ;
	// Driver変更前にWindowsへ復元ポイント開始を要求する。
	const RestorePointOperationResult creation = restorePointService.begin( restorePointDescription) ;
	// 復元ポイントの開始成功と有効な番号がそろわなければ、Providerを呼ばず中止する。
	if( creation.outcome != OutcomeCode::SUCCESS || creation.sequenceNumber <= 0) {
		InstallResult result		= makeUnstartedInstallResult( identities) ;	// Fail-closed結果。
		result.protectionMode		= InstallProtectionMode::WINDOWS_RESTORE_POINT ;
		result.restorePointCreation = creation ;
		// 成功通知でも復元ポイント番号が無効なら、保護開始失敗として結果を補正する。
		if( creation.outcome == OutcomeCode::SUCCESS) {
			result.restorePointCreation.outcome = OutcomeCode::FAILURE ;
			result.restorePointCreation.error	= static_cast<NativeError>( 0x8000FFFFU) ;
		}

		progressCallback( {.stage = ProviderStage::CREATING_RESTORE_POINT, .percentComplete = 100}) ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::CREATING_RESTORE_POINT, .percentComplete = 10}) ;

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
	progressCallback( {.stage = ProviderStage::FINALIZING_RESTORE_POINT, .percentComplete = 90}) ;
	result.restorePointCompletion = restorePointScope.complete() ;
	// 終了通知の失敗は全体成功へ含めず、実際の個別導入結果を保持したまま報告する。
	if( result.restorePointCompletion.outcome != OutcomeCode::SUCCESS) {
		// 終了通知失敗を全体成功として表示しないが、実際の候補別結果は保持する。
		result.succeeded = false ;
	}

	progressCallback( {.stage = ProviderStage::FINALIZING_RESTORE_POINT, .percentComplete = 100}) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/protected_install.h 宣言側の契約を正本とする。
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
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/protected_install.h 宣言側の契約を正本とする。
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

} // namespace drivercrate
