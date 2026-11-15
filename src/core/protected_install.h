//------------------------------------------------------------------------------
/**
 * @file protected_install.h
 * @brief OS別回復保護付きinstall処理定義
 * @version 01.01.04
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
 * Ver.01.01.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.01.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.03 Shunji Ogawa  2026/11/12  取得APIと復元最終判定の匿名診断を補完
 * Ver.01.01.04 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * </pre>
 *
 * @note Clientは通常復元保護を準備し、導入前失敗の元保持へ結合した一回の本人選択だけ例外を許します。Serverの同意は別です
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/restore_point_service.h"
#include "core/update_provider.h"

#include <cstdint>
#include <optional>
#include <vector>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 保護付きinstall関数定義
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
[[nodiscard]] InstallResult installWithRestorePoint(
	IUpdateProvider &provider, IRestorePointService &restorePointService,
	ScanSessionId scanSessionId, std::span<const std::wstring> identities,
	std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback,
	std::wstring_view restorePointDescription) ;

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
 * @note 呼出側は実OSがWindows Serverであり、利用者が復元ポイントなしの実行へ明示同意したことをworker境界で検証しなければならない。Provider例外は失敗結果へ変換す
 *       る
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult installWithoutRestorePointOnServer(
	IUpdateProvider &provider, ScanSessionId scanSessionId,
	std::span<const std::wstring> identities, std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progressCallback) ;

//------------------------------------------------------------------------------
/**
 * @brief 指定したOS種別とinstall保護方針の組合せを検証する。Client専用例外modeとServerを分離し、復元なしの一回保持はworkerで別検証する
 * @param[in] windowsServer 実OSがWindows Serverの場合は`true`。 Windows Serverの場合はtrue
 * @param[in] protectionMode 利用者確認時に固定した保護方針
 * @return OSに対応する保護方針の場合trueです。Client例外の本人判断はこの関数だけでは成立しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isInstallProtectionModeAllowed( bool					windowsServer,
												  InstallProtectionMode protectionMode) noexcept ;

/** @brief OS別の最終保護guardが拒否した固定理由です */
enum class RestorePointProtectionIssue {
	/// 元保護契約が成立した状態
	NONE,
	/// Serverに未実行以外の復元状態がある状態
	SERVER_NATIVE_STATE,
	/// 定義外の保護mode
	MODE,
	/// 実在未分類のnative結果
	UNCLASSIFIED,
	/// Provider前の実在確認がない状態
	BEFORE_NOT_VERIFIED,
	/// scope後の実在確認がない状態
	AFTER_NOT_VERIFIED,
	/// 最終実在確認が成功以外の状態
	VERIFICATION,
	/// 元実在確認errorがある状態
	PROTECTION_ERROR,
	/// 元保護番号が成立していない状態
	SEQUENCE,
	/// 元作成時刻が成立していない状態
	CREATION_TIME,
	/// 元local日付がない状態
	LOCAL_DAY,
	/// 日内再利用にnative呼出し又はnative結果がある状態
	REUSE_NATIVE_STATE,
	/// 未許可の実在区分
	DISPOSITION,
	/// 実BEGIN/ENDの呼出し又は成功が欠ける状態
	NATIVE_STATE,
	/// 元BEGIN/END errorがある状態
	NATIVE_ERROR,
	/// 元保護番号とBEGIN/END番号が一致しない状態
	SEQUENCE_BINDING,
} ;
//------------------------------------------------------------------------------
/**
 * @brief 元bool保護契約と同じ条件を固定拒否理由として返します
 * @param[in] result 変更しない元Install結果です
 * @return 元契約成立はNONE、それ以外は最初の固定拒否理由です
 * @note 原番号/時刻/文字列を返さず、memo errorは元契約どおり成否に含めません
 */
//------------------------------------------------------------------------------
[[nodiscard]] RestorePointProtectionIssue restorePointProtectionIssue(
	const InstallResult &result) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief Native呼出し事実とOS別実在保護の整合性を検査します
 * @param[in] result 受理するInstall結果です
 * @return 指定保護契約に一致する場合trueです。memo保存失敗は実導入成否を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		  isRestorePointProtectionValid( const InstallResult &result) noexcept ;

// 今回だけの明示続行buttonです。既定/close/EscはIDCANCELです
inline constexpr int	  RESTORE_CONTINUATION_BUTTON_ID = 1001 ;
//------------------------------------------------------------------------------
/**
 * @brief 成功したdialogの明示続行buttonだけを本人判断として受理します
 * @param[in] dialogResult TaskDialogの元HRESULT bit patternです
 * @param[in] selectedButton 選択buttonです。既定/closeは中止です
 * @return S_OKかつ続行buttonだけtrueです。表示失敗から代替実行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		  isRestoreContinuationChoiceConfirmed( NativeError dialogResult,
															   int		   selectedButton) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief Provider前の保護失敗だけへ一回の続行を拘束する短命状態です
 * @note Controllerとworkerが各所有し、公開DTOだけから実行権限を作りません
 */
//------------------------------------------------------------------------------
class RestoreContinuation final {
public:
	/**
	 * @brief 元保護失敗と全選択の未消費所有を照合して提示を保持します
	 * @param[in] operationId 元の失敗操作です
	 * @param[in] scanSessionId 元scanです
	 * @param[in] identities 元選択全件です。重複を拒否します
	 * @param[in] result 共通保護処理の元失敗です
	 * @param[in] retention 実ownerの保持証明です。nullは拒否します
	 * @return Provider未実行と全元選択の保持を証明した場合trueです
	 */
	[[nodiscard]] bool offer( OperationId operationId, ScanSessionId scanSessionId,
							 std::span<const std::wstring> identities, const InstallResult &result,
							 const InstallRetentionSummary *retention) ;
	/**
	 * @brief 同scan/完全元選択への未使用提示を確認します
	 * @param[in] failedOperationId 元の失敗操作です
	 * @param[in] scanSessionId 現scanです
	 * @param[in] identities 現選択全件です
	 * @return 同じ未使用提示だけtrueです
	 */
	[[nodiscard]] bool matches( OperationId failedOperationId, ScanSessionId scanSessionId,
							   std::span<const std::wstring> identities) const noexcept ;
	/**
	 * @brief 照合の成否にかかわらず提示を一回消費します
	 * @param[in] failedOperationId 元の失敗操作です
	 * @param[in] scanSessionId 現scanです
	 * @param[in] identities 現選択全件です
	 * @return 一致時だけ原保護errorです。拒否はnulloptです
	 */
	[[nodiscard]] std::optional<NativeError> consume(
		OperationId failedOperationId, ScanSessionId scanSessionId,
		std::span<const std::wstring> identities) noexcept ;
	/**
	 * @brief 取消し/別操作/終了で未使用提示を破棄します
	 */
	void reset() noexcept ;

private:
	/// 元失敗操作です。0は未保持です
	OperationId				  failedOperationId_{} ;
	/// 保持された元scanです
	ScanSessionId			  scanSessionId_{} ;
	/// 元の完全選択です。worker/UIそれぞれが所有します
	std::vector<std::wstring> identities_ ;
	/// 元の保護errorです。現在のAPI結果を代替しません
	NativeError				  error_{} ;
} ;

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
[[nodiscard]] InstallResult installExplicitlyWithoutRestorePoint(
	IUpdateProvider &provider, ScanSessionId scanSessionId,
	std::span<const std::wstring> identities, std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progressCallback, OperationId failedOperationId,
	NativeError failureError) ;

//------------------------------------------------------------------------------
/**
 * @brief 明示復元なし結果にnative保護成功や架空pointが混在していないか確認します
 * @param[in] result 変更しない今回の結果です
 * @param[in] failedOperationId controllerが消費した原失敗操作です
 * @param[in] failureError 消費時の原保護errorです
 * @return 原判断と一致し復元操作が未実行の場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isExplicitNoRestoreResultValid( const InstallResult &result,
												  OperationId		   failedOperationId,
												  NativeError		   failureError) noexcept ;

} // namespace drivercrate
