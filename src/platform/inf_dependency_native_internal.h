//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native_internal.h
 * @brief 同worker内の完全な低位依存API表を隔離して所有します
 * @version 01.04.00
 * @date 2026/10/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/10/13  完全五API所有scopeの前置契約と採用書式を整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.03 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.00.04 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.00.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.01.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/21  起動グループ順序の読み取りを完全APIへ追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/22  保護された仮想Wi-Fi INFの同期読取りを接続
 * Ver.01.04.00 Shunji Ogawa  2026/11/23  イベント資源の明示コピー先を両方のINF読取りで共有
 * </pre>
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include "platform/official_file_verifier.h"
#include "platform/system_inf_effects_internal.h"
#include "platform/official_download_workspace.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
namespace drivercrate {
struct InfDependencyNativeResult ;
struct StorageLoadOrder ;

//------------------------------------------------------------------------------
/**
 * @brief イベント用DLLの元コピーリストが明示的にSystem32直下を指定することを確認する
 * @param[in] inf 元署名文書のHINFを同期借用する
 * @param[in] list 元の名前付きコピー節。空は受理しない
 * @return 元DestinationDirsに重複のない単一DIRID 11があればtrue
 * @note 既定宛先とサブディレクトリは認めない。実配置やシステムの変更は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasExplicitStorageEventCopyDestination( HINF inf, const std::wstring &list) ;
}
namespace drivercrate::inf_dependency_native_detail {
/** @brief 署名・OS・対応Storeを一括で置換する完全な同期表です */
struct Api {
	/// 同一観測のOS versionとnative architectureです
	std::function<NativeError( OSVERSIONINFOEXW &, SYSTEM_INFO &)>			 version ;
	/// fixture所有のWindows起点です
	std::function<NativeError( std::wstring &)>								 windowsDirectory ;
	/// 同byteへ結合するINF署名応答です
	std::function<NativeError( const std::wstring &, SP_INF_SIGNER_INFO_W &)> infSignature ;
	/// 同CATと全実memberの検査です
	std::function<NativeError( const std::wstring &, std::span<const std::wstring>)>
																			   catalogSignature ;
	/// 同INFの対応Driver Store位置です
	std::function<NativeError( const std::wstring &, std::wstring &)>		   driverStore ;
	/// 新SYSTEM登録だけの実file trustです。空ならその作用を拒否しnativeへ補完しません
	std::function<NativeError( const std::wstring &, WindowsSystemFileTrust &)> systemFileTrust ;
	/// 必要な同原serviceだけを読む完全な代替です。欠落時nativeへ補完しません
	std::function<NativeError( std::wstring_view, SystemServiceEvidence &)>	   systemService ;
	/// storageだけのexact現kernel観測です。欠落表を実SCMへ補完しません
	std::function<NativeError( std::wstring_view, SystemServiceEvidence &)>	   storageService ;
	/// 正式メディアチェンジャー用のWindows起動グループの読み取り結果です
	std::function<NativeError( StorageLoadOrder &)>							   storageLoadOrder ;
	/// 原byteを所有する試験専用Store投影です。製品の完全表は存在せずnull固定です
	const OfficialDownloadWorkspace											  *projectedStore{} ;
	/// 所有fixtureだけのcanonical→physical全対応です。空の製品経路はidentityです
	std::function<NativeError( std::wstring_view, std::wstring &)>			   readPath ;
	/// 内部資格だけが同parserの原file/節消費を観測します。製品は空固定です
	std::function<void( std::wstring_view, std::wstring_view)>				   observedSection ;
	/// 内部資格だけへ全終了再確認済み結果を同期借用します。製品は空固定です
	std::function<void( const InfDependencyNativeResult &)>					   observedResult ;
} ;
class Access ;
/** @brief 同一threadだけで完全表を所有する非公開構築scopeです */
class ScopedFixture final {
public:
	/**
	 * @brief 所有表を解除します。作成threadで破棄します
	 */
	~ScopedFixture() ;
	/**
	 * @brief 同threadの所有表を複製しないためコピー構築を禁止します
	 */
	ScopedFixture( const ScopedFixture &) = delete ;
	/**
	 * @brief 同threadの所有表を複製しないためコピー代入を禁止します
	 */
	ScopedFixture &operator=( const ScopedFixture &) = delete ;

private:
	friend class Access ;
	/**
	 * @brief 検証済み完全表を同threadへ固定します
	 * @param[in] api 所有権を移す完全表です
	 */
	explicit ScopedFixture( Api api) ;
	/// scopeと同じ寿命の所有表です
	Api api_ ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 固定native処理または完全内部表へ同期分岐します
 * @return 内部scopeがある場合だけ非所有表、製品ではnullptrです
 */
//------------------------------------------------------------------------------
[[nodiscard]] const Api	 *activeApi() noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 原Windows仮想無線バスINFの署名・Store・バイトを同期で固定して読み取ります
 * @param[in] workspace 元の署名付き収集workspaceを同期中だけ借用します
 * @param[in] inspect 同梱INFと対応Storeの絶対パス及び署名時と一致する全バイトを同期で借用します
 * @return 元Windows由来と読取りの前後確認が成立した場合0です。拒否は元HRESULTです
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectProtectedWifiBusInf(
	const OfficialDownloadWorkspace								 &workspace,
	const std::function<NativeError( const std::wstring &, std::wstring_view,
									std::span<const std::byte>)> &inspect) ;
#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
/** @brief 内部検証targetだけが完全表を作れます */
class Access final {
public:
	/**
	 * @brief 欠落表と再入を拒否して所有scopeを作ります
	 * @param[in] api 元五APIと、Store投影時は完全readPathを持つ表です
	 * @return 正常時のscope、不完全または再入時nullptrです
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( Api api) ;
} ;
#endif
} // namespace drivercrate::inf_dependency_native_detail
