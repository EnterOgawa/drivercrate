//------------------------------------------------------------------------------
/**
 * @file official_inf_models_native_internal.h
 * @brief currentOS Models一SDKの非公開同thread観測境界です
 * @version 01.08.00
 * @date 2026/11/18
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/18  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/22  未参照登録の全元構造検査を内部対照から呼び出す
 * Ver.01.02.00 Shunji Ogawa  2026/11/22  公式無線LANのコピーと削除の対照を追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/24  不在の無線LAN媒体に対する元INFの逆参照を試験から確認
 * Ver.01.04.00 Shunji Ogawa  2026/11/24  同じ内部試験でx86専用媒体の逆参照を確認
 * Ver.01.05.00 Shunji Ogawa  2026/11/24  USB無線の選択コピーを同じ読取入口で対照
 * Ver.01.06.00 Shunji Ogawa  2026/11/24  USB無線の選択サービスを同じ元コピーで対照
 * Ver.01.07.00 Shunji Ogawa  2026/11/24  USB無線の表示用途を元の登録形式で対照
 * Ver.01.08.00 Shunji Ogawa  2026/11/24  USB無線の元登録と同梱効果を同じ選択で対照
 * </pre>
 *
 * @note 同threadで単独所有し、public DTO/取得/導入権限を発行しません
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {
class OfficialDownloadWorkspace ;
struct OfficialZipEntry ;
} // namespace drivercrate

namespace drivercrate::official_inf_models_native_detail {
/** @brief SDKと同じ一関数だけの完全な低位呼出し表です */
struct Calls {
	/// HINF/context/NULL platform/buffer/required-size/LastErrorを元SDK署名で扱います
	decltype( &::SetupDiGetActualModelsSectionW) getActualModelsSection{} ;
} ;
class Access ;
/** @brief 同threadで生成/破棄する移動不可の一owner scopeです */
class ScopedFixture final {
public:
	/**
	 * @brief 同owner threadの低位表だけを解除します
	 * @note 別thread破棄は契約違反として終端し、dangling表を使用しません
	 */
	~ScopedFixture() noexcept ;
	/**
	 * @brief 同threadの所有scopeを複製しません
	 * @param[in] other 複製を禁止する元scopeです
	 */
	ScopedFixture( const ScopedFixture &other) = delete ;
	/**
	 * @brief 同threadの所有scopeを代入しません
	 * @param[in] other 代入を禁止する元scopeです
	 */
	ScopedFixture			  &operator=( const ScopedFixture &other) = delete ;
	/**
	 * @brief 元scopeの完全表を同期借用します
	 * @return 本scope生存中の不変表です
	 */
	[[nodiscard]] const Calls &calls() const noexcept ;

private:
	friend class Access ;
	/**
	 * @brief 検証済み一APIを同threadへ排他的に固定します
	 * @param[in] calls 完全な低位表です
	 */
	explicit ScopedFixture( Calls calls) noexcept ;
	/// 同owner threadです。別threadでの破棄/借用を許可しません
	DWORD ownerThread_{} ;
	/// scopeの原関数を終端まで所有します
	Calls calls_ ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 同threadの低位表を非権限で観測します
 * @return scopeがある場合だけその不変表、通常製品ではnullptrです
 */
//------------------------------------------------------------------------------
[[nodiscard]] const Calls *activeCalls() noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 原SDK又は明示scopeの同署名APIを同期呼出しします
 * @param[in] context 原HINFのManufacturer contextです
 * @param[in] platform 原alternate-platformです。NULLの意味を変更しません
 * @param[out] buffer 元SDKの有界受信先です。size queryではnullptrです
 * @param[in] capacity 元bufferの文字数です
 * @param[out] required 元SDKの必要文字数です。null可です
 * @param[in] reserved 元SDKの予約引数です
 * @return 元BOOLです。LastErrorを変換せず、FALSE直後の原値をcallerが保持します
 */
//------------------------------------------------------------------------------
BOOL WINAPI actualModelsSection( PINFCONTEXT context, PSP_ALTPLATFORM_INFO platform, PWSTR buffer,
								DWORD capacity, PDWORD required, PVOID reserved) ;
#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
/** @brief 同じ元INFの内部試験で確認する範囲です */
enum class ScopedUsbWirelessCheck {
	/// 元コピーと配置先を照合します
	COPIES,
	/// 元コピーに二サービスを結びます
	SERVICES,
	/// 同梱依存のない元選択の登録・イベント・参照を含めます
	EFFECTS,
	/// 同梱依存確認済み状態を与え、同じ元選択の登録・イベント・参照を含めます
	EFFECTS_WITH_INBOX,
} ;

/** @brief unit targetだけが完全表の所有scopeを作れます */
class Access final {
public:
	/**
	 * @brief 欠落/本SDK混入/同thread入れ子を拒否します
	 * @param[in] calls 欠落しないfake一関数の表です
	 * @return 一owner scope、拒否又は確保不能ではnullptrです
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( Calls calls) noexcept ;

	/**
	 * @brief 架空INFで未参照登録の原構造と従来拒否を確認します
	 * @param[in] path 所有テスト領域の有限元INF絶対パスです
	 * @return 全元構造と限定再検査に合格し、従来経路で拒否された場合だけtrueです
	 * @note 署名・媒体・収集資格を発行しない内部の非実行検査です
	 */
	[[nodiscard]] static bool		 inspectInactiveRegistration( std::wstring_view path) ;

	/**
	 * @brief 架空INF全体で指定した媒体への逆参照を調べます
	 * @param[in] path 所有試験領域の元INF絶対パスです
	 * @param[in] leaf 試験対象の不在DLLまたはx86のSYS名です。パスを含みません
	 * @return 元INF内の限定構造と全値が成立し、外部依存がなければtrueです
	 * @note 元署名・媒体・収集資格を発行しない内部試験です
	 */
	[[nodiscard]] static bool		 inspectScopedMediaIsolation( std::wstring_view path,
																 std::wstring_view leaf) ;

	/**
	 * @brief 架空INFで既存の作用棚卸しと無線LANの媒体検査を行います
	 * @param[in] workspace 架空の元INFと媒体位置を所有する試験領域です
	 * @param[in] entries 架空の同梱元媒体一覧です。実ファイル検査を行いません
	 * @param[in] inboxVerified 試験で同梱依存を確認した状態を指定します
	 * @param[out] complete 元の全用途を照合した場合trueです。失敗時はfalseです
	 * @return 作用とコピー構成が成立した場合0、最初の診断はHRESULTです
	 * @note 署名、Windows側の同梱依存、端末適用、導入資格を返さない内部試験です
	 */
	[[nodiscard]] static NativeError inspectScopedWirelessProfile(
		const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
		bool inboxVerified, bool &complete) ;
	/**
	 * @brief 架空USB無線INFの同じ選択のコピー、サービスと作用を指定範囲で対照します
	 * @param[in] workspace 架空fixture.infと媒体名を保持する試験領域です
	 * @param[in] entries 元CABの媒体に相当する架空の元名です
	 * @param[in] selection 確認する範囲と架空の同梱依存状態です
	 * @return 指定した照合の全成功は0、それ以外は元HRESULTです
	 * @note 実署名、導入許可、公開候補を発行しない内部試験です
	 */
	[[nodiscard]] static NativeError inspectScopedUsbWirelessProfile(
		const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
		ScopedUsbWirelessCheck selection) ;

	/**
	 * @brief 架空の登録行を共通の表示用途判定に通します
	 * @param[in] values SetupAPI展開後を模した登録行の全欄です
	 * @param[in] usbWireless trueは公式USB無線と照合できた選択を模します
	 * @return 元の表示形式と一致した場合trueです
	 * @note 実ファイルや登録内容に変更を加えない内部試験です
	 */
	[[nodiscard]] static bool inspectScopedWirelessLabel( std::span<const std::wstring> values,
														 bool						   usbWireless) ;
} ;
#endif
} // namespace drivercrate::official_inf_models_native_detail
