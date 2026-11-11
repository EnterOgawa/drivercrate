//------------------------------------------------------------------------------
/**
 * @file app_update_service.h
 * @brief App更新workerと公式Setup backendの境界を定義します。
 * @version 01.00.00
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * </pre>
 * @note 一要求・一結果を所有し、ドライバーworkerのsessionを共有しません。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/app_update.h"
#include <Windows.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

namespace drivercrate {
/** @brief App更新だけのworker段階です。 */
enum class AppUpdateStage {
	/// 要求を待っています。
	IDLE,
	/// 小さい正式Release情報だけを確認中です。
	CHECKING,
	/// 明示同意待ちです。
	OFFERED,
	/// 同意したSetupを取得・検査中です。
	DOWNLOADING,
	/// 検査済みSetupの引継ぎ待ちです。
	READY,
	/// 通常userへSetupを引継ぎ中です。
	HANDING_OFF,
} ;
/** @brief 一回の確定結果をUIへ所有移転します。 */
struct AppUpdateEvent {
	/// この終端に到達した操作です。
	AppUpdateStage					operation{AppUpdateStage::IDLE} ;
	/// 固定の失敗と元数値です。
	AppUpdateFailure				failure ;
	/// 確認成功で見つかった新版です。同意の代わりにはなりません。
	std::optional<AppUpdateRelease> release ;
	/// 明示的な確認または同意後の操作です。
	bool							manual{} ;
} ;
/** @brief 公式JSONから必要な宣言だけを検査します。
 * @param[in] raw 256KiB以内の原UTF-8です。
 * @param[in] current 実行中Appの数値版です。
 * @param[out] release 新版の正しい宣言だけを返します。失敗/同版以下では空です。
 * @return 失敗分類と元数値。正しい同版以下も成功です。
 */
[[nodiscard]] AppUpdateFailure parseAppUpdateReleaseJson(
	std::string_view raw, const AppVersion &current,
	std::optional<AppUpdateRelease> &release) noexcept ;
/** @brief 更新専用の非blocking取消し照会です。 */
using AppUpdateCancellation = std::function<bool()> ;
/** @brief 一つのworker内だけで公式I/Oを所有するbackendです。 */
class AppUpdateBackend {
public:
	/** @brief worker停止後に所有resourceを解放します。 */
	virtual ~AppUpdateBackend() = default ;
	/** @brief 正式Releaseだけを確認し、実行物は取得しません。
	 * @param[in] cancellation 同じ操作の取消し照会です。
	 * @return 確認結果。ドライバーへの作用を持ちません。
	 */
	[[nodiscard]] virtual AppUpdateEvent check(
		const AppUpdateCancellation &cancellation) noexcept = 0 ;
	/** @brief 明示同意した一件だけを取得・検査します。
	 * @param[in] release 元確認の完全宣言です。
	 * @param[in] cancellation 同じ操作の取消し照会です。
	 * @return 取得・検査結果。成功時だけ保護したfileを保持します。
	 */
	[[nodiscard]] virtual AppUpdateFailure download(
		const AppUpdateRelease &release, const AppUpdateCancellation &cancellation) noexcept = 0 ;
	/** @brief 保護したfileを再検査して通常userへ渡します。
	 * @param[in] release 元同意と取得に一致する宣言です。
	 * @param[in] cancellation 引継ぎ前の取消し照会です。
	 * @return 引継ぎ要求の結果。Setup完了結果ではありません。
	 */
	[[nodiscard]] virtual AppUpdateFailure launch(
		const AppUpdateRelease &release, const AppUpdateCancellation &cancellation) noexcept = 0 ;
} ;
/** @brief 既Windows APIを使う公式backendを生成します。
 * @return 所有backend。確保失敗は例外です。
 */
[[nodiscard]] std::unique_ptr<AppUpdateBackend> makeAppUpdateBackend() ;
/** @brief 任意boolだけの現在配置設定を読みます。
 * @param[out] enabled 不在はtrue。不正/失敗はfalseです。
 * @return 成功0、設定fileを扱えない場合は元数値です。
 */
[[nodiscard]] NativeError						loadAppUpdatePreference( bool &enabled) noexcept ;
/** @brief 自動確認boolを現在配置に保存します。
 * @param[in] enabled 保存する設定です。URL等は保存しません。
 * @return 保存成功0、失敗時は元数値です。
 */
[[nodiscard]] NativeError						saveAppUpdatePreference( bool enabled) noexcept ;

/** @brief 一つの専用threadでApp更新要求を直列処理します。 */
class AppUpdateService							final {
public:
	 /** @brief 完全backendとWindow通知先を所有します。
	 * @param[in] window 非所有通知先です。停止前に破棄しません。
	 * @param[in] message WM_APP範囲の通知です。
	 * @param[in] backend worker専用backendです。nullは拒否します。
	 */
	 AppUpdateService( HWND window, UINT message, std::unique_ptr<AppUpdateBackend> backend) ;
	 /** @brief 取消しを通知し、worker終了を待って解放します。 */
	 ~AppUpdateService() ;
	 /** @brief thread所有権の複製を禁止します。
	 * @param[in] other 未使用の自己型です。
	 */
	 AppUpdateService( const AppUpdateService &other) = delete ;
	 /** @brief thread所有権の代入を禁止します。
	 * @param[in] other 未使用の自己型です。
	 * @return 削除宣言のため呼出せません。
	 */
	 AppUpdateService							&operator=( const AppUpdateService &other) = delete ;
	 /** @brief 実行物を取らない一回の確認を受理します。
	 * @param[in] manual 手動確認ならtrueです。
	 * @return idle/offeredかつ未受領結果がない場合だけtrueです。
	 */
	 [[nodiscard]] bool							 requestCheck( bool manual) ;
	 /** @brief 元の提示に対する明示同意を受理します。
	 * @return offeredかつ元の提示がある場合だけtrueです。
	 */
	 [[nodiscard]] bool							 requestDownload() ;
	 /** @brief UIがidleを再確認した引継ぎ要求を受理します。
	 * @return 元取得のreadyである場合だけtrueです。
	 */
	 [[nodiscard]] bool							 requestLaunch() ;
	 /** @brief 現在提示の再通知を見送ります。取得は行いません。 */
	 void										 dismiss() noexcept ;
	 /** @brief 実行中のApp更新だけを協調取消しします。 */
	 void										 cancel() noexcept ;
	 /** @brief 新規要求を閉じ、所有threadをjoinします。 */
	 void										 stop() noexcept ;
	 /** @brief 所有された確定結果一件を取り出します。
	 * @return 結果なしはnulloptです。
	 */
	 [[nodiscard]] std::optional<AppUpdateEvent> takeEvent() ;
	 /** @brief 現段階のsnapshotを返します。
	 * @return mutexで保護した現在段階です。
	 */
	 [[nodiscard]] AppUpdateStage				 stage() const noexcept ;

private:
	 /** @brief 固定の段階を一件だけ予約します。
	 * @param[in] operation 受理する操作です。
	 * @param[in] manual 明示操作かどうかです。
	 * @return 同時要求/停止/未受領結果を拒否した場合はfalseです。
	 */
	 [[nodiscard]] bool				   enqueue( AppUpdateStage operation, bool manual) ;
	 /** @brief 例外をthread境界から漏らさず直列処理します。 */
	 void							   run() noexcept ;
	 /// 非所有通知先です。
	 HWND							   window_{} ;
	 /// 通知用messageです。
	 UINT							   message_{} ;
	 /// このthread専用の完全backendです。
	 std::unique_ptr<AppUpdateBackend> backend_ ;
	 /// 要求と結果の所有権を保護します。
	 mutable std::mutex				   mutex_ ;
	 /// 一要求または終了だけを通知します。
	 std::condition_variable		   ready_ ;
	 /// 未処理は一要求に限定します。
	 std::optional<AppUpdateStage>	   request_ ;
	 /// UI未受領の確定結果です。
	 std::optional<AppUpdateEvent>	   event_ ;
	 /// 確認した元宣言です。
	 std::optional<AppUpdateRelease>   offered_ ;
	 /// 同process中に見送った同版です。
	 std::optional<AppVersion>		   dismissed_ ;
	 /// 現在の段階です。
	 AppUpdateStage					   stage_{AppUpdateStage::IDLE} ;
	 /// 現要求が手動かどうかです。
	 bool							   manual_{} ;
	 /// 終了開始後は送信・引継ぎを許可しません。
	 std::atomic_bool				   stopping_{} ;
	 /// 同じApp操作だけの取消しです。
	 std::atomic_bool				   cancelled_{} ;
	 /// 有限の直列処理を所有します。
	 std::thread					   thread_ ;
} ;
}
