//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding_internal.h
 * @brief 私有索引候補sessionの内部固定fixture接続を定義します。
 * @version 01.02.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  同workerの索引候補と指定導入の内部境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/15  発行前条件の非機密な内部同期観測を追加。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/composite_update_provider.h"
#include <Windows.h>
#include <cstddef>
#include <memory>
#include <utility>
namespace drivercrate::provider_worker_index_detail {
struct Services ;
}
namespace drivercrate::signed_index_candidate_binding_detail {
/** @brief 公式installer引継ぎの完全な低位Windows呼出し表です。 */
struct InstallerNativeCalls {
	/// 指定applicationと変更可能command bufferだけを実行します。
	decltype( &CreateProcessW)	   createProcess{} ;
	/// 起動したprocessの終端を待ちます。
	decltype( &WaitForSingleObject) waitProcess{} ;
	/// 終端済みprocessの原exit codeを取得します。
	decltype( &GetExitCodeProcess)  exitCode{} ;
	/// 同じ呼出し表が発行したhandleを閉じます。
	decltype( &CloseHandle)		   closeHandle{} ;
	/// MSIの固定Windows標準起動元を取得します。
	decltype( &GetSystemDirectoryW) systemDirectory{} ;
} ;
/** @brief 同worker threadだけへ完全なlaunch fixtureを固定する単独所有scopeです。 */
class ScopedInstallerFixture final {
public:
	/** @brief 当該scopeの低位表だけを解除します。 */
	~ScopedInstallerFixture() noexcept ;
	/** @brief 固定表のscope複製を禁止します。
	 * @param[in] other 借用scopeです。本constructorは呼出し禁止です。
	 */
	ScopedInstallerFixture( const ScopedInstallerFixture &other) = delete ;
	/** @brief 固定表のscope代入を禁止します。
	 * @param[in] other 借用scopeです。本演算子は呼出し禁止です。
	 * @return 本演算子は呼出し禁止です。
	 */
	ScopedInstallerFixture &operator=( const ScopedInstallerFixture &other) = delete ;
	/** @brief 同scopeで固定した全低位表を借用します。
	 * @return 本scopeが生存する間だけ有効な完全表です。
	 */
	[[nodiscard]] const InstallerNativeCalls &calls() const noexcept ;

private:
	friend struct Access ;
	/** @brief 完全表を同threadへ固定します。
	 * @param[in] calls 欠損のないWindows ABI表です。
	 */
	explicit ScopedInstallerFixture( InstallerNativeCalls calls) noexcept ;
	/// 同thread lifetime中に変更しない完全呼出し表です。
	InstallerNativeCalls calls_ ;
} ;
// 私有本体接続は内部macroの有限fixtureにだけ公開します。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @brief 内容評価直前の非機密な一致条件だけを保持します。 */
struct PublicationDiagnostic {
	/// 同record内の元INF順序です。
	std::size_t infOrdinal{} ;
	/// 内容評価前1、READY検証前3です。
	unsigned	stage{} ;
	/// 現在行を候補へ流用した場合trueです。
	bool		candidateCurrent{} ;
	/// 同INFの明示providerとの完全一致です。
	bool		providerMatches{} ;
	/// 同INFの明示versionとの完全一致です。
	bool		versionMatches{} ;
	/// 同scan・成功内容・単一閉包・workspace・正証拠の成立です。
	bool		contentContextValid{} ;
	/// 同取得由来findingがORIGIN軸に有効です。
	bool		originValid{} ;
	/// Windows観測の元errorとrankの組合せが有効です。
	bool		observationValid{} ;
	/// 八軸評価がREADYを満たす場合trueです。
	bool		assessmentReady{} ;
	/// 必須条件に含まれる基本driver役割の数です。
	std::size_t baseRequirements{} ;
	/// 必須条件に含まれるExtension役割の数です。
	std::size_t extensionRequirements{} ;
	/// 必須条件に含まれるcomponent役割の数です。
	std::size_t componentRequirements{} ;
	/// 実選択graphで検証されたNeeds辺数です。追加導入INF数ではありません。
	std::size_t verifiedNeedsEdges{} ;
	/// 元私有計画の追加INF member数です。基本INFを含みません。
	std::size_t additionalMembers{} ;
} ;
/** @brief 同期private観測だけを受けるnoexcept callback型です。 */
using PublicationObserver = void ( *)( const PublicationDiagnostic &, void *) noexcept ;
/** @brief 通常workerと同じprivate本体接続の内部試験入口です。 */
struct Access {
	/** @brief 同threadだけの同期非機密観測を登録または解除します。
	 * @param[in] observer 解除時はnullです。元処理の結果を変更できません。
	 * @param[in,out] state 同期呼出し中だけ借用する観測所有者です。
	 */
	static void observePublication( PublicationObserver observer, void *state) noexcept ;
	/** @brief 完全なlaunch表だけを同worker threadへ結合します。
	 * @param[in] calls 全五関数のWindows ABI fixtureです。
	 * @return 欠損または同threadの重複scopeでは空、それ以外は単独所有scopeです。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedInstallerFixture> createInstaller(
		InstallerNativeCalls calls) ;
	/** @brief 同worker所有者と完全固定依存を借用結合します。
	 * @param[in,out] provider 本体Compositeです。
	 * @param[in,out] session 終端まで生存する同scan ownerです。
	 * @param[in] services 開始前固定の非通信fixture依存です。
	 * @param[in] operationId 正の通常scan操作IDです。
	 */
	static void bind( CompositeUpdateProvider &provider, SignedIndexScanSession &session,
					 const provider_worker_index_detail::Services &services,
					 OperationId								   operationId)
	{
		provider.bindSignedIndexSession( session, services, operationId, {}) ;
	}
	/** @brief 同原lookupの参照を通常scanへ公開します。
	 * @param[in,out] provider 同本体Compositeです。
	 * @param[in] plan 実adapter生成の同scan計画です。
	 * @param[in,out] result 元通常scanの所有結果です。
	 */
	static void publishReferences( CompositeUpdateProvider		&provider,
								  const OfficialPreparationPlan &plan, ScanResult &result)
	{
		provider.finishSignedIndexScanPublication( plan, result) ;
	}
} ;
#endif
} // namespace drivercrate::signed_index_candidate_binding_detail
