//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native_internal.h
 * @brief 同worker内の完全な低位依存API表を隔離して所有します。
 * @version 01.00.01
 * @date 2026/10/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  完全五APIの内部所有scopeを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/13  完全五API所有scopeの前置契約と採用書式を整合。
 * </pre>
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <functional>
#include <memory>
#include <span>
#include <string>
namespace drivercrate::inf_dependency_native_detail {
/** @brief 署名・OS・対応Storeを一括で置換する完全な同期表です。 */
struct Api {
	/// 同一観測のOS versionとnative architectureです。
	std::function<NativeError( OSVERSIONINFOEXW &, SYSTEM_INFO &)>			 version ;
	/// fixture所有のWindows起点です。
	std::function<NativeError( std::wstring &)>								 windowsDirectory ;
	/// 同byteへ結合するINF署名応答です。
	std::function<NativeError( const std::wstring &, SP_INF_SIGNER_INFO_W &)> infSignature ;
	/// 同CATと全実memberの検査です。
	std::function<NativeError( const std::wstring &, std::span<const std::wstring>)>
																	 catalogSignature ;
	/// 同INFの対応Driver Store位置です。
	std::function<NativeError( const std::wstring &, std::wstring &)> driverStore ;
} ;
class Access ;
/** @brief 同一threadだけで完全表を所有する非公開構築scopeです。 */
class ScopedFixture final {
public:
	/** @brief 所有表を解除します。作成threadで破棄します。 */
	~ScopedFixture() ;
	/** @brief 同threadの所有表を複製しないためコピー構築を禁止します。 */
	ScopedFixture( const ScopedFixture &) = delete ;
	/** @brief 同threadの所有表を複製しないためコピー代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	ScopedFixture &operator=( const ScopedFixture &) = delete ;

private:
	friend class Access ;
	/** @brief 検証済み完全表を同threadへ固定します。
	 * @param[in] api 所有権を移す完全表です。
	 */
	explicit ScopedFixture( Api api) ;
	/// scopeと同じ寿命の所有表です。
	Api api_ ;
} ;
/** @brief 固定native処理または完全内部表へ同期分岐します。
 * @return 内部scopeがある場合だけ非所有表、製品ではnullptrです。
 */
[[nodiscard]] const Api *activeApi() noexcept ;
#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
/** @brief 内部検証targetだけが完全表を作れます。 */
class Access final {
public:
	/** @brief 欠落表と再入を拒否して所有scopeを作ります。
	 * @param[in] api 全五APIを持つ表です。
	 * @return 正常時のscope、不完全または再入時nullptrです。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( Api api) ;
} ;
#endif
} // namespace drivercrate::inf_dependency_native_detail
