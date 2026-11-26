//------------------------------------------------------------------------------
/**
 * @file protected_install.cpp
 * @brief OS別回復保護付きinstall処理実装
 * @version 01.02.00
 * @date 2026/09/01
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元処理進捗通知追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server専用経路追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足
 * Ver.01.01.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.01.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.03 Shunji Ogawa  2026/11/12  取得APIと復元最終判定の匿名診断を補完
 * Ver.01.01.04 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * </pre>
 *
 * @note Clientの復元ポイント保護とServerの明示同意済み経路を実装します。Server専用経路の利用可否はworkerが実OSを再検証します
 */
//------------------------------------------------------------------------------

#include "core/protected_install.h"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部型定義
//------------------------------------------------------------------------------

/**
 * @brief 開始済み復元ポイントへの終了通知をscopeで保証する
 */
class RestorePointScope final {
public:
	/**
     * @brief 終了通知対象のサービスとsequence numberを保持する
     * @param[in,out] service 復元ポイントサービス
     * @param[in] sequenceNumber 開始済み復元ポイントの識別番号
     */
	RestorePointScope( IRestorePointService &service, std::int64_t sequenceNumber) noexcept ;

	/**
	 * @brief 明示終了されていない復元ポイントへ終了通知を行う
	 */
	~RestorePointScope() ;

	// 同じ復元ポイントへ複数回終了通知しないようcopy/moveを禁止する
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	RestorePointScope( const RestorePointScope &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	RestorePointScope &operator=( const RestorePointScope &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	RestorePointScope( RestorePointScope &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	RestorePointScope						 &operator=( RestorePointScope &&) = delete ;

	/**
	 * @brief 復元ポイントへ終了通知し、結果を返す
	 * @return Windows復元ポイントAPIの終了結果
	 */
	[[nodiscard]] RestorePointOperationResult complete() noexcept ;

private:
	/// 終了通知先。scopeより長く生存する非所有参照
	IRestorePointService &service_ ;
	/// 開始済み復元ポイントの識別番号
	std::int64_t		  sequenceNumber_{} ;
	/// trueの場合は終了通知を再実行しない
	bool				  completed_{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Providerを実行しなかった候補別結果を作成する
 *
 * @param[in] identities UIが選択したopaque identity群
 * @return 全候補を未開始として保持する失敗結果
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult makeUnstartedInstallResult(
	const std::span<const std::wstring> identities)
{
	InstallResult result{} ;	// 選択identityとの対応だけを保持する未開始結果
	result.updates.reserve( identities.size()) ;

	// UIが全選択候補を未インストールとして表示できるようidentityを保持する
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider例外を候補別の失敗結果へ変換する
 *
 * @param[in] identities UIが選択したopaque identity群
 * @return E_UNEXPECTEDを保持する候補別失敗結果
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult makeExceptionInstallResult(
	const std::span<const std::wstring> identities)
{
	// 型不明のProvider例外を、候補別結果へ記録するE_UNEXPECTEDのbit pattern
	constexpr NativeError UNEXPECTED_ERROR = static_cast<NativeError>( 0x8000FFFFU) ;
	InstallResult		  result{} ;	// Provider境界の型不明例外を示すsynthetic結果
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = UNEXPECTED_ERROR ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = UNEXPECTED_ERROR ;
	result.updates.reserve( identities.size()) ;

	// 全選択候補を同じProvider境界エラーへ対応付ける
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
 * @brief 終了通知対象のサービスとsequence numberを保持する
 * @param[in,out] service 復元ポイントサービス
 * @param[in] sequenceNumber 開始済み復元ポイントの識別番号
 */
//------------------------------------------------------------------------------
RestorePointScope::RestorePointScope( IRestorePointService &service,
									 const std::int64_t	   sequenceNumber) noexcept
	: service_( service), sequenceNumber_( sequenceNumber)
{
}

//------------------------------------------------------------------------------
/**
 * @brief 明示終了されていない復元ポイントへ終了通知を行う
 */
//------------------------------------------------------------------------------
RestorePointScope::~RestorePointScope()
{
	// 例外などで明示終了に到達しなかった復元ポイントにも、scope終了時に終了通知を行う
	if( !completed_) {
		static_cast<void>( service_.complete( sequenceNumber_)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイントへ終了通知し、結果を返す
 * @return Windows復元ポイントAPIの終了結果
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
 *        もEND一回を試行する。同日再利用は両native操作を呼ばない
 * @param[in,out] provider 選択候補を処理するProvider。worker thread専用である
 * @param[in,out] restorePointService 復元ポイントを開始・終了するサービス。 復元ポイントサービス
 * @param[in] scanSessionId 選択元のscan session ID
 * @param[in] identities UIが明示選択したopaque identity群
 * @param[in] parentWindowNative Windows dialogの親HWNDを整数表現で渡す値
 * @param[in] progressCallback 復元、download、installの全体進捗通知先
 * @param[in] restorePointDescription Windowsの復元UIへ表示する説明。 復元UIに表示する説明
 * @return 復元ポイントと候補ごとの実行結果
 * @note 保護scopeは必ず閉じる。再利用の実在とnative呼出し事実を分け、メモ失敗だけで実導入成否を変更しない
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
	// Driver変更前にWindowsへ復元ポイント開始を要求する
	const RestorePointOperationResult creation = restorePointService.begin( restorePointDescription) ;
	const auto protection = restorePointService.protection() ;	// native結果と実在確認を分けます
	const bool legacy	  = protection.disposition ==
						RestorePointDisposition::NATIVE_TRANSACTION ;	// 旧serviceのnative契約です
	const bool daily = protection.disposition ==
					   RestorePointDisposition::SAME_DAY_REUSED ;	// native未実行の再利用です
	const bool knownDisposition =
		daily || protection.disposition == RestorePointDisposition::NEW_POINT_VERIFIED ||
		protection.disposition ==
			RestorePointDisposition::WINDOWS_SELECTED_POINT ;	// 実在保護を許す閉集合です
	// 復元ポイントの開始成功と有効な番号がそろわなければ、Providerを呼ばず中止する
	const bool prepared =
		knownDisposition && protection.verifiedBefore &&
		protection.verification == OutcomeCode::SUCCESS && protection.error == 0 &&
		protection.sequenceNumber > 0 && creation.error == 0 && protection.createdUtc > 0 &&
		protection.localDay != 0 && !protection.nativeEndCalled &&
		(daily ? creation.outcome == OutcomeCode::NOT_STARTED && !protection.nativeBeginCalled &&
					 creation.sequenceNumber == protection.sequenceNumber
			   : creation.outcome == OutcomeCode::SUCCESS && protection.nativeBeginCalled &&
					 creation.sequenceNumber == protection.sequenceNumber) ;
	// 実在保護が成立しなければProviderを実行しません
	if( !prepared) {
		InstallResult result  = makeUnstartedInstallResult( identities) ;	// Fail-closed結果
		result.protectionMode = InstallProtectionMode::WINDOWS_RESTORE_POINT ;
		result.restoreStoppedBeforeProvider = true ;
		result.restorePointCreation =
			legacy || protection.nativeBeginCalled ? creation : RestorePointOperationResult{} ;
		// BEGIN成功後に実在確認だけが失敗したscopeも、元sequenceへENDを一回通知します
		if( creation.outcome == OutcomeCode::SUCCESS && creation.sequenceNumber > 0) {
			result.restorePointCompletion = restorePointService.complete( creation.sequenceNumber) ;
		}

		result.restorePointProtection = restorePointService.protection() ;
		// 不正な区分/結合を実在保護成功へ表示せず、元native結果は保持します
		result.restorePointProtection.verification = OutcomeCode::FAILURE ;
		// 元診断が欠けた場合だけ未成立のcodeを補います
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
													 creation.sequenceNumber) ;	// 終了通知guard
	InstallResult				   result{} ;									// Provider結果へ復元ポイント結果を付加する最終結果
	// Provider内部の0～100%を保護付きoperation全体の10～90%へ変換する通知関数
	const ProviderProgressCallback providerProgressCallback =
		[&progressCallback]( const ProviderProgress &progress) {
			ProviderProgress protectedProgress = progress ;	// 復元処理を含む全体進捗値
			protectedProgress.percentComplete =
				10 + std::min<std::uint32_t>( progress.percentComplete, 100) * 80 / 100 ;
			progressCallback( protectedProgress) ;
		} ;
	try {
		result = provider.install( scanSessionId, identities, parentWindowNative,
								  providerProgressCallback) ;
	} catch( ...) {
		// Provider例外をthread境界へ漏らさず、復元ポイントを終了して失敗結果を返す
		result = makeExceptionInstallResult( identities) ;
	}

	// Provider返却DTOの自己申告で導入前停止を成立させません
	result.restoreStoppedBeforeProvider = false ;
	result.restoreFailureOperationId	= 0U ;
	result.restoreFailureError			= 0U ;
	result.restorePointCreation			= creation ;
	result.protectionMode				= InstallProtectionMode::WINDOWS_RESTORE_POINT ;
	progressCallback( {.stage		   = daily ? ProviderStage::VERIFYING_RESTORE_POINT
											   : ProviderStage::FINALIZING_RESTORE_POINT,
					  .percentComplete = 90}) ;
	result.restorePointCompletion = restorePointScope.complete() ;
	result.restorePointProtection = restorePointService.protection() ;
	// 終了通知の失敗は全体成功へ含めず、実際の個別導入結果を保持したまま報告する
	if( !isRestorePointProtectionValid( result)) {
		// 終了通知失敗を全体成功として表示しないが、実際の候補別結果は保持する
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
 *        する。SRSetRestorePointWを呼ばずProviderを実行する。呼出側でOSと管理者同意を検証し、Provider例外は失敗結果へ変換する
 * @param[in,out] provider 選択候補を処理するProvider。worker thread専用である
 * @param[in] scanSessionId 選択元のscan session ID
 * @param[in] identities UIが明示選択したopaque identity群。 UIが選択したopaque identity群
 * @param[in] parentWindowNative Windows dialogの親HWNDを整数表現で渡す値
 * @param[in] progressCallback download、installの進捗通知先
 * @return Server専用modeと候補ごとの実行結果。復元ポイント結果は`NOT_STARTED`である
 * @note 呼出側は実OSがWindows Serverであり、利用者が復元ポイントなしの実行へ明示同意したことをworker境界で検証しなければならない。Provider例外は失敗結果へ変換する
 */
//------------------------------------------------------------------------------
InstallResult installWithoutRestorePointOnServer( IUpdateProvider					&provider,
												 const ScanSessionId				 scanSessionId,
												 const std::span<const std::wstring> identities,
												 const std::uintptr_t			 parentWindowNative,
												 const ProviderProgressCallback &progressCallback)
{
	InstallResult result{} ;	// Provider結果へServer専用保護modeを付加する最終結果
	try {
		result = provider.install( scanSessionId, identities, parentWindowNative, progressCallback) ;
	} catch( ...) {
		// Provider例外をworker境界へ漏らさず、全選択候補の失敗結果へ変換する
		result = makeExceptionInstallResult( identities) ;
	}

	result.restoreStoppedBeforeProvider = false ;
	result.restoreFailureOperationId	= 0U ;
	result.restoreFailureError			= 0U ;
	result.protectionMode				= InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT ;
	result.restorePointCreation			= {} ;
	result.restorePointCompletion		= {} ;
	result.restorePointProtection		= {} ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定したOS種別とinstall保護方針の組合せを検証する。Client専用例外modeとServerを分離し、復元なしの一回保持はworkerで別検証する
 * @param[in] windowsServer 実OSがWindows Serverの場合は`true`。 Windows Serverの場合はtrue
 * @param[in] protectionMode 利用者確認時に固定した保護方針
 * @return OSに対応する保護方針の場合trueです。Client例外の本人判断はこの関数だけでは成立しません
 */
//------------------------------------------------------------------------------
bool isInstallProtectionModeAllowed( const bool					windowsServer,
									const InstallProtectionMode protectionMode) noexcept
{
	// Serverでは専用確認modeだけを許可し、非対応のSystem Restore経路へ進めない
	if( windowsServer) {
		return protectionMode == InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT ;
	}

	return protectionMode == InstallProtectionMode::WINDOWS_RESTORE_POINT ||
		   protectionMode == InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元bool保護契約と同じ条件を固定拒否理由として返します
 * @param[in] result 変更しない元Install結果です
 * @return 元契約成立はNONE、それ以外は最初の固定拒否理由です
 * @note 原番号/時刻/文字列を返さず、memo errorは元契約どおり成否に含めません
 */
//------------------------------------------------------------------------------
RestorePointProtectionIssue restorePointProtectionIssue( const InstallResult &result) noexcept
{
	const auto &begin = result.restorePointCreation ;	// 元native開始です
	const auto &end	  = result.restorePointCompletion ;	// 元native終了です
	const auto &p	  = result.restorePointProtection ;	// 原実在確認です
	using Issue		  = RestorePointProtectionIssue ;
	// 元Server契約は未実行だけを要求します
	if( result.protectionMode == InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) {
		return begin.outcome == OutcomeCode::NOT_STARTED &&
					   end.outcome == OutcomeCode::NOT_STARTED &&
					   p.verification == OutcomeCode::NOT_STARTED && !p.nativeBeginCalled &&
					   !p.nativeEndCalled
				   ? Issue::NONE
				   : Issue::SERVER_NATIVE_STATE ;
	}

	// 定義外modeを受理しません
	if( result.protectionMode != InstallProtectionMode::WINDOWS_RESTORE_POINT) {
		return Issue::MODE ;
	}

	// bare native成功を実在保護へ使いません
	if( p.disposition == RestorePointDisposition::NATIVE_TRANSACTION) {
		return Issue::UNCLASSIFIED ;
	}

	// Provider前の原実在を要求します
	if( !p.verifiedBefore) {
		return Issue::BEFORE_NOT_VERIFIED ;
	}

	// scope後の原実在を要求します
	if( !p.verifiedAfter) {
		return Issue::AFTER_NOT_VERIFIED ;
	}

	// 元verificationを成功へ補完しません
	if( p.verification != OutcomeCode::SUCCESS) {
		return Issue::VERIFICATION ;
	}

	// 原errorは成功値へ変換しません
	if( p.error != 0) {
		return Issue::PROTECTION_ERROR ;
	}

	// 有効な元番号を要求します
	if( p.sequenceNumber <= 0) {
		return Issue::SEQUENCE ;
	}

	// 元作成時刻を要求します
	if( p.createdUtc <= 0) {
		return Issue::CREATION_TIME ;
	}

	// 原local日付を要求します
	if( p.localDay == 0) {
		return Issue::LOCAL_DAY ;
	}

	// 元reuse契約ではnative両操作とerrorがないことを要求します
	if( p.disposition == RestorePointDisposition::SAME_DAY_REUSED) {
		return !p.nativeBeginCalled && !p.nativeEndCalled &&
					   begin.outcome == OutcomeCode::NOT_STARTED &&
					   end.outcome == OutcomeCode::NOT_STARTED && begin.error == 0 && end.error == 0
				   ? Issue::NONE
				   : Issue::REUSE_NATIVE_STATE ;
	}

	// 元新規/OS選択だけを受理します
	if( p.disposition != RestorePointDisposition::NEW_POINT_VERIFIED &&
	   p.disposition != RestorePointDisposition::WINDOWS_SELECTED_POINT) {
		return Issue::DISPOSITION ;
	}

	// 実BEGIN/ENDの元呼出しと成功を要求します
	if( !p.nativeBeginCalled || !p.nativeEndCalled || begin.outcome != OutcomeCode::SUCCESS ||
	   end.outcome != OutcomeCode::SUCCESS) {
		return Issue::NATIVE_STATE ;
	}

	// 両native操作の元errorを保持します
	if( begin.error != 0 || end.error != 0) {
		return Issue::NATIVE_ERROR ;
	}

	// 元番号が一致した同scopeだけを受理します
	if( begin.sequenceNumber != p.sequenceNumber || end.sequenceNumber != p.sequenceNumber) {
		return Issue::SEQUENCE_BINDING ;
	}

	return Issue::NONE ;
}
//------------------------------------------------------------------------------
/**
 * @brief Native呼出し事実とOS別実在保護の整合性を検査します
 * @param[in] result 受理するInstall結果です
 * @return 指定保護契約に一致する場合trueです。memo保存失敗は実導入成否を変更しません
 */
//------------------------------------------------------------------------------
bool isRestorePointProtectionValid( const InstallResult &result) noexcept
{
	return restorePointProtectionIssue( result) == RestorePointProtectionIssue::NONE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元保護失敗と全選択の未消費所有を照合して提示を保持します
 * @param[in] operationId 元の失敗操作です
 * @param[in] scanSessionId 元scanです
 * @param[in] identities 元選択全件です。重複を拒否します
 * @param[in] result 共通保護処理の元失敗です
 * @param[in] retention 実ownerの保持証明です。nullは拒否します
 * @return Provider未実行と全元選択の保持を証明した場合trueです
 */
//------------------------------------------------------------------------------
bool RestoreContinuation::offer( const OperationId operationId, const ScanSessionId scanSessionId,
								const std::span<const std::wstring>	 identities,
								const InstallResult					&result,
								const InstallRetentionSummary *const retention)
{
	reset() ;
	const auto		 &creation	 = result.restorePointCreation ;	// 元BEGIN結果です
	const auto		 &completion = result.restorePointCompletion ;	// 元END結果です
	const auto		 &protection = result.restorePointProtection ;	// 保護成功へ変換しません
	// 元保護失敗のHRESULTを符号付きのまま保持します
	const NativeError error = creation.error != 0U ? creation.error : protection.error ;
	// 共通停止事実/実所有のどちらかが欠ける場合は提示しません
	if( operationId == 0U || scanSessionId == 0U || identities.empty() || !retention ||
	   retention->operationId != operationId || retention->scanSessionId != scanSessionId ||
	   retention->providerEntered || !result.restoreStoppedBeforeProvider || result.succeeded ||
	   result.protectionMode != InstallProtectionMode::WINDOWS_RESTORE_POINT ||
	   result.downloadOutcome != OutcomeCode::NOT_STARTED || result.downloadError != 0U ||
	   result.installOutcome != OutcomeCode::NOT_STARTED || result.installError != 0U ||
	   result.updates.size() != identities.size() || error == 0U ||
	   (protection.disposition != RestorePointDisposition::UNAVAILABLE &&
		protection.disposition != RestorePointDisposition::NEW_POINT_VERIFIED &&
		protection.disposition != RestorePointDisposition::WINDOWS_SELECTED_POINT &&
		protection.disposition != RestorePointDisposition::SAME_DAY_REUSED) ||
	   protection.verification != OutcomeCode::FAILURE) {
		return false ;
	}

	// 取消し/時計/排他/未分類例外/不正契約を復元設定の失敗として迂回しません
	if( error == static_cast<NativeError>( 0x800704C7U) ||
	   error == static_cast<NativeError>( 0x80004004U) ||
	   error == static_cast<NativeError>( 0x800705B4U) ||
	   error == static_cast<NativeError>( 0x800700AAU) ||
	   error == static_cast<NativeError>( 0x80070020U) ||
	   error == static_cast<NativeError>( 0x80070021U) ||
	   error == static_cast<NativeError>( 0x80070576U) ||
	   error == static_cast<NativeError>( 0x8000FFFFU) ||
	   error == static_cast<NativeError>( 0x80070057U) ||
	   error == static_cast<NativeError>( 0x8007000EU) ||
	   error == static_cast<NativeError>( 0x80004001U)) {
		return false ;
	}

	const bool owned = creation.outcome == OutcomeCode::SUCCESS ;	// 元BEGIN所有だけです
	// 所有済みscopeは同番号のEND成功後だけ、失敗BEGINはEND0だけを許します
	if( owned ? creation.error != 0U || creation.sequenceNumber <= 0 ||
				   !protection.nativeBeginCalled || !protection.nativeEndCalled ||
				   completion.outcome != OutcomeCode::SUCCESS || completion.error != 0U ||
				   completion.sequenceNumber != creation.sequenceNumber
			 : (creation.outcome != OutcomeCode::FAILURE &&
				creation.outcome != OutcomeCode::NOT_STARTED) ||
				   creation.sequenceNumber != 0 || protection.nativeEndCalled ||
				   (creation.outcome == OutcomeCode::NOT_STARTED && protection.nativeBeginCalled) ||
				   completion.outcome != OutcomeCode::NOT_STARTED || completion.error != 0U ||
				   completion.sequenceNumber != 0) {
		return false ;
	}

	// 元選択全件を重複なしの結果と未消費ownerへ一対一に結びます
	for( std::size_t index{}; index < identities.size(); ++index) {
		const auto &identity = identities[index] ;	// 元opaque値は永続化しません
		// 重複/空選択とowner喪失を提示へ採用しません
		if( identity.empty() || std::ranges::count( identities, identity) != 1 ||
		   std::ranges::count( retention->candidates, identity,
							  &RetainedInstallCandidate::identity) != 1 ||
		   std::ranges::count( result.updates, identity, &UpdateExecutionResult::identity) != 1) {
			return false ;
		}
	}

	// 個別native作用/handoff/役割の開始が一件でもあれば再導入を提示しません
	for( const auto &update : result.updates) {
		// 今回の固定条件だけを変更し、元保持と他の拒否境界を維持します
		if( update.downloadOutcome != OutcomeCode::NOT_STARTED || update.downloadError != 0U ||
		   update.installOutcome != OutcomeCode::NOT_STARTED || update.installError != 0U ||
		   update.installerHandoff || update.handoffOutcome != OutcomeCode::NOT_STARTED ||
		   update.handoffError != 0U || update.installerExitCode || !update.requiredRoles.empty() ||
		   !update.requiredImports.empty()) {
			return false ;
		}
	}

	failedOperationId_ = operationId ;
	scanSessionId_	   = scanSessionId ;
	identities_.assign( identities.begin(), identities.end()) ;
	error_ = error ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scan/完全元選択への未使用提示を確認します
 * @param[in] failedOperationId 元の失敗操作です
 * @param[in] scanSessionId 現scanです
 * @param[in] identities 現選択全件です
 * @return 同じ未使用提示だけtrueです
 */
//------------------------------------------------------------------------------
bool RestoreContinuation::matches( const OperationId					  failedOperationId,
								  const ScanSessionId				  scanSessionId,
								  const std::span<const std::wstring> identities) const noexcept
{
	return failedOperationId_ != 0U && failedOperationId == failedOperationId_ &&
		   scanSessionId == scanSessionId_ && identities.size() == identities_.size() &&
		   std::ranges::all_of( identities_, [&]( const auto &identity) {
			   return std::ranges::count( identities, identity) == 1 ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 照合の成否にかかわらず提示を一回消費します
 * @param[in] failedOperationId 元の失敗操作です
 * @param[in] scanSessionId 現scanです
 * @param[in] identities 現選択全件です
 * @return 一致時だけ原保護errorです。拒否はnulloptです
 */
//------------------------------------------------------------------------------
std::optional<NativeError> RestoreContinuation::consume(
	const OperationId failedOperationId, const ScanSessionId scanSessionId,
	const std::span<const std::wstring> identities) noexcept
{
	const auto result = matches( failedOperationId, scanSessionId, identities)
							? std::optional<NativeError>{error_}
							: std::nullopt ;	// 今回だけの原errorです
	reset() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取消し/別操作/終了で未使用提示を破棄します
 */
//------------------------------------------------------------------------------
void RestoreContinuation::reset() noexcept
{
	failedOperationId_ = 0U ;
	scanSessionId_	   = 0U ;
	identities_.clear() ;
	error_ = 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本人選択とworkerの短命保持照合後にclient導入を一回実行します
 * @param[in,out] provider 元所有と対象限定preflightを通ったProviderです
 * @param[in] scanSessionId 元scanです
 * @param[in] identities 元の完全選択です
 * @param[in] parentWindowNative 既installer UIの親です
 * @param[in] progressCallback 元操作へ結合する進捗です
 * @param[in] failedOperationId 一回消費した原失敗操作です
 * @param[in] failureError 原保護errorです
 * @return 個別実結果と明示復元なし事実です。native BEGIN/END/pointは未実行です
 * @note 呼出側は実client OS/原所有/短命提示消費を独立検証します
 */
//------------------------------------------------------------------------------
InstallResult installExplicitlyWithoutRestorePoint( IUpdateProvider	  &provider,
												   const ScanSessionId scanSessionId,
												   const std::span<const std::wstring> identities,
												   const std::uintptr_t parentWindowNative,
												   const ProviderProgressCallback &progressCallback,
												   const OperationId failedOperationId,
												   const NativeError failureError)
{
	InstallResult result{} ;	// 個別native結果はそのまま保持します
	try {
		result = provider.install( scanSessionId, identities, parentWindowNative, progressCallback) ;
	} catch( ...) {
		result = makeExceptionInstallResult( identities) ;
	}

	result.protectionMode		  = InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT ;
	result.restorePointCreation	  = {} ;
	result.restorePointCompletion = {} ;
	result.restorePointProtection = {.disposition = RestorePointDisposition::UNAVAILABLE} ;
	result.restoreStoppedBeforeProvider = false ;
	result.restoreFailureOperationId	= failedOperationId ;
	result.restoreFailureError			= failureError ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示復元なし結果にnative保護成功や架空pointが混在していないか確認します
 * @param[in] result 変更しない今回の結果です
 * @param[in] failedOperationId controllerが消費した原失敗操作です
 * @param[in] failureError 消費時の原保護errorです
 * @return 原判断と一致し復元操作が未実行の場合trueです
 */
//------------------------------------------------------------------------------
bool isExplicitNoRestoreResultValid( const InstallResult &result,
									const OperationId	 failedOperationId,
									const NativeError	 failureError) noexcept
{
	const auto &p = result.restorePointProtection ;	// 実在保護なしの閉状態です
	return result.protectionMode == InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT &&
		   failedOperationId != 0U && failureError != 0U &&
		   result.restoreFailureOperationId == failedOperationId &&
		   result.restoreFailureError == failureError && !result.restoreStoppedBeforeProvider &&
		   result.restorePointCreation.outcome == OutcomeCode::NOT_STARTED &&
		   result.restorePointCreation.error == 0U &&
		   result.restorePointCreation.sequenceNumber == 0 &&
		   result.restorePointCompletion.outcome == OutcomeCode::NOT_STARTED &&
		   result.restorePointCompletion.error == 0U &&
		   result.restorePointCompletion.sequenceNumber == 0 &&
		   p.disposition == RestorePointDisposition::UNAVAILABLE &&
		   p.verification == OutcomeCode::NOT_STARTED && p.error == 0U && p.sequenceNumber == 0 &&
		   p.createdUtc == 0 && p.localDay == 0U && !p.verifiedBefore && !p.verifiedAfter &&
		   !p.nativeBeginCalled && !p.nativeEndCalled ;
}

//------------------------------------------------------------------------------
/**
 * @brief 成功したdialogの明示続行buttonだけを本人判断として受理します
 * @param[in] dialogResult TaskDialogの元HRESULT bit patternです
 * @param[in] selectedButton 選択buttonです。既定/closeは中止です
 * @return S_OKかつ続行buttonだけtrueです。表示失敗から代替実行しません
 */
//------------------------------------------------------------------------------
bool isRestoreContinuationChoiceConfirmed( const NativeError dialogResult,
										  const int			selectedButton) noexcept
{
	return dialogResult == 0U && selectedButton == RESTORE_CONTINUATION_BUTTON_ID ;
}

} // namespace drivercrate
