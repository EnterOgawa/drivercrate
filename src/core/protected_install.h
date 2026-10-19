//------------------------------------------------------------------------------
/**
 * @file protected_install.h
 * @brief OS別回復保護付きinstall処理定義。
 * @version 01.00.00
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
 * </pre>
 *
 * @note Clientでは復元ポイント成功後だけProvider installを実行します。Serverでは呼出側のOS判定と明示同意を前提に復元ポイントを使用しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/restore_point_service.h"
#include "core/update_provider.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 保護付きinstall関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 復元ポイントで保護したdriver download/installを同期実行する。
 * 復元ポイント開始失敗時はProviderを呼ばない。開始成功後はProviderの正常・失敗・例外にかかわらず終了通知を試行する。
 * @param[in,out] provider 選択候補を処理するProvider。worker thread専用である。
 * @param[in,out] restorePointService 復元ポイントを開始・終了するサービス。 復元ポイントサービス。
 * @param[in] scanSessionId 選択元のscan session ID。
 * @param[in] identities UIが明示選択したopaque identity群。
 * @param[in] parentWindowNative Windows dialogの親HWNDを整数表現で渡す値。
 * @param[in] progressCallback 復元、download、installの全体進捗通知先。
 * @param[in] restorePointDescription Windowsの復元UIへ表示する説明。 復元UIに表示する説明。
 * @return 復元ポイントと候補ごとの実行結果。
 * @note 復元ポイント開始失敗時はProviderを呼ばない。開始成功後はProviderが例外を送出しても終了通知を試行し、例外をInstallResultの失敗へ変換する。
 */
[[nodiscard]] InstallResult installWithRestorePoint(
	IUpdateProvider &provider, IRestorePointService &restorePointService,
	ScanSessionId scanSessionId, std::span<const std::wstring> identities,
	std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback,
	std::wstring_view restorePointDescription) ;

/**
 * @brief Windows Serverで復元ポイントを呼ばずdriver download/installを同期実行する。
 * Windows Serverで復元ポイントなしのinstallを実行する。
 * SRSetRestorePointWを呼ばずProviderを実行する。呼出側でOSと管理者同意を検証し、Provider例外は失敗結果へ変換する。
 * @param[in,out] provider 選択候補を処理するProvider。worker thread専用である。
 * @param[in] scanSessionId 選択元のscan session ID。
 * @param[in] identities UIが明示選択したopaque identity群。 UIが選択したopaque identity群。
 * @param[in] parentWindowNative Windows dialogの親HWNDを整数表現で渡す値。
 * @param[in] progressCallback download、installの進捗通知先。
 * @return Server専用modeと候補ごとの実行結果。復元ポイント結果は`NOT_STARTED`である。
 * @note 呼出側は実OSがWindows Serverであり、利用者が復元ポイントなしの実行へ明示同意したことをworker境界で検証しなければならない。Provider例外は失敗結果へ変換す
 *       る。
 */
[[nodiscard]] InstallResult installWithoutRestorePointOnServer(
	IUpdateProvider &provider, ScanSessionId scanSessionId,
	std::span<const std::wstring> identities, std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progressCallback) ;

/**
 * @brief 指定したOS種別とinstall保護方針の組合せを検証する。
 * Clientで復元ポイント回避、Serverで非support API使用を許可しないfail-closed判定を行う。
 * @param[in] windowsServer 実OSがWindows Serverの場合は`true`。 Windows Serverの場合はtrue。
 * @param[in] protectionMode 利用者確認時に固定した保護方針。
 * @return ServerだけがServer専用mode、clientだけが復元ポイントmodeの場合は`true`。 OSに対応する唯一の保護方針の場合は`true`。
 */
[[nodiscard]] bool isInstallProtectionModeAllowed( bool					windowsServer,
												  InstallProtectionMode protectionMode) noexcept ;

} // namespace drivercrate
