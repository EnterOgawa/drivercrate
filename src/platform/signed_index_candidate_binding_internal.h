//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding_internal.h
 * @brief 私有索引候補sessionの内部固定fixture接続を定義します
 * @version 01.07.01
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.02.00 Shunji Ogawa  2026/10/15  発行前条件の非機密な内部同期観測を追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/28  既検証WUA候補と未取得索引の明示混在fixtureを追加
 * Ver.01.03.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.03.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.03.03 Shunji Ogawa  2026/11/12  WUA検索終端の状態契約と診断改訂値を整合
 * Ver.01.03.04 Shunji Ogawa  2026/11/17  内部試験だけに必要子の限定観測を接続
 * Ver.01.04.00 Shunji Ogawa  2026/11/18  同所有targetの既入力だけを読むunit getterを追加
 * Ver.01.04.01 Shunji Ogawa  2026/11/18  元参照factory転送と同owner cached summary読取りを追加
 * Ver.01.05.00 Shunji Ogawa  2026/11/23  WiX表示行から保持した元照合数の読み取りを追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/23  元規約への同意だけを照合する隔離試験入口を追加
 * Ver.01.07.00 Shunji Ogawa  2026/11/27  同一の署名配布形式で再照合する試験入口を追加
 * Ver.01.07.01 Shunji Ogawa  2026/11/28  取得前参照に同scanの表示時刻を渡す
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/composite_update_provider.h"
#include "core/provider_registry.h"
#include "platform/common_driver_package.h"
#include "platform/official_driver_closure.h"
#include <Windows.h>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
namespace drivercrate::provider_worker_index_detail {
struct Services ;
}
namespace drivercrate::signed_index_candidate_binding_detail {
/** @brief 公式installer引継ぎの完全な低位Windows呼出し表です */
struct InstallerNativeCalls {
	/// 指定applicationと変更可能command bufferだけを実行します
	decltype( &CreateProcessW)	   createProcess{} ;
	/// 起動したprocessの終端を待ちます
	decltype( &WaitForSingleObject) waitProcess{} ;
	/// 終端済みprocessの原exit codeを取得します
	decltype( &GetExitCodeProcess)  exitCode{} ;
	/// 同じ呼出し表が発行したhandleを閉じます
	decltype( &CloseHandle)		   closeHandle{} ;
	/// MSIの固定Windows標準起動元を取得します
	decltype( &GetSystemDirectoryW) systemDirectory{} ;
} ;
/** @brief 同worker threadだけへ完全なlaunch fixtureを固定する単独所有scopeです */
class ScopedInstallerFixture final {
public:
	/**
	 * @brief 当該scopeの低位表だけを解除します
	 */
	~ScopedInstallerFixture() noexcept ;
	/**
	 * @brief 固定表のscope複製を禁止します
	 * @param[in] other 借用scopeです。本constructorは呼出し禁止です
	 */
	ScopedInstallerFixture( const ScopedInstallerFixture &other) = delete ;
	/**
	 * @brief 固定表のscope代入を禁止します
	 * @param[in] other 借用scopeです。本演算子は呼出し禁止です
	 */
	ScopedInstallerFixture &operator=( const ScopedInstallerFixture &other) = delete ;
	/**
	 * @brief 同scopeで固定した全低位表を借用します
	 * @return 本scopeが生存する間だけ有効な完全表です
	 */
	[[nodiscard]] const InstallerNativeCalls &calls() const noexcept ;

private:
	friend struct Access ;
	/**
	 * @brief 完全表を同threadへ固定します
	 * @param[in] calls 欠損のないWindows ABI表です
	 */
	explicit ScopedInstallerFixture( InstallerNativeCalls calls) noexcept ;
	/// 同thread lifetime中に変更しない完全呼出し表です
	InstallerNativeCalls calls_ ;
} ;
// 私有本体接続は内部macroの有限fixtureにだけ公開します
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @brief 内容評価直前の非機密な一致条件だけを保持します */
struct PublicationDiagnostic {
	/// 同record内の元INF順序です
	std::size_t infOrdinal{} ;
	/// 内容評価前1、READY検証前3です
	unsigned	stage{} ;
	/// 現在行を候補へ流用した場合trueです
	bool		candidateCurrent{} ;
	/// 同INFの明示providerとの完全一致です
	bool		providerMatches{} ;
	/// 同INFの明示versionとの完全一致です
	bool		versionMatches{} ;
	/// 同scan・成功内容・単一閉包・workspace・正証拠の成立です
	bool		contentContextValid{} ;
	/// 同取得由来findingがORIGIN軸に有効です
	bool		originValid{} ;
	/// Windows観測の元errorとrankの組合せが有効です
	bool		observationValid{} ;
	/// 八軸評価がREADYを満たす場合trueです
	bool		assessmentReady{} ;
	/// 必須条件に含まれる基本driver役割の数です
	std::size_t baseRequirements{} ;
	/// 必須条件に含まれるExtension役割の数です
	std::size_t extensionRequirements{} ;
	/// 必須条件に含まれるcomponent役割の数です
	std::size_t componentRequirements{} ;
	/// 実選択graphで検証されたNeeds辺数です。追加導入INF数ではありません
	std::size_t verifiedNeedsEdges{} ;
	/// 元私有計画の追加INF member数です。基本INFを含みません
	std::size_t additionalMembers{} ;
} ;
/** @brief 同期private観測だけを受けるnoexcept callback型です */
using PublicationObserver = void ( *)( const PublicationDiagnostic &, void *) noexcept ;
/** @brief 通常workerと同じprivate本体接続の内部試験入口です */
struct Access {
	/**
	 * @brief 隔離試験の消費済み取得を本体と同じ形式選択へ渡す
	 * @param[in] acquisition 架空だが元ledgerへ結んだ実取得結果
	 * @param[in] grant 同じ操作の消費済み権限
	 * @param[in] hint 封印に結ぶ元署名とバイトの照合値
	 * @param[in] format 試験の署名済み配布形式
	 * @param[out] input 検査入力。拒否時は空
	 * @return 検査入力の照合が成立した場合0
	 * @note 定義は試験targetのみ。取得権限を発行しない
	 */
	[[nodiscard]] static NativeError bindDelegatedInputForFixture(
		const OfficialAcquisitionResult &acquisition, const RecordScopedDownloadGrant &grant,
		const IndexedDriverArchiveHint &hint, IndexPayloadFormat format,
		DelegatedOfficialPackageInput &input) noexcept ;

	/**
	 * @brief 固定した一件の候補の同意照合だけを、実機や取得内容なしで試験します
	 * @param[in] originalTerms 同スキャン83の候補wix-consent-fixtureが保持する元表示です
	 * @param[in] session 選択に指定するスキャンです
	 * @param[in] identities 今回の選択です
	 * @param[in] consents 選択に渡す試験用の同意です
	 * @return 元表示の純粋な照合結果です
	 * @note 導入トークン、取得証拠、復元操作は作りません
	 */
	[[nodiscard]] static bool validateWixConsentsForFixture(
		const std::shared_ptr<const WixTermsPresentation> &originalTerms,
		const ScanSessionId session, std::span<const std::wstring> identities,
		std::span<const WixInstallConsent> consents)
	{
		SignedIndexCandidateBindingSession binding ;		// 読取り専用の照合だけを呼びます
		auto &record = binding.records_.emplace_back() ;	// 取得操作から発行された表示を模します
		record.task.scanSessionId = 83U ;
		record.task.target.terms  = OfficialPreparationTerms::INSPECTION_ONLY ;
		record.wixTerms			  = originalTerms ;
		auto &route		  = binding.routes_.emplace_back() ;	// 同じ候補と規約の結合を固定します
		route.recordIndex = 0U ;
		route.candidate.identity					= L"wix-consent-fixture" ;
		route.candidate.wixInspectionSourceIdentity = L"wix-inspected-fixture" ;
		route.candidate.storageChange.emplace().singleBoot.emplace() ;
		route.requiredPlan = std::make_shared<const RequiredDriverComponentPlan>() ;
		return binding.validateWixInstallConsents( session, identities, consents) ;
	}
	/**
	 * @brief 同sessionの元lookupとissuerから既参照factoryだけを呼びます
	 * @param[in,out] session 同threadの原scan ownerです
	 * @param[in] plan 同ownerの元未検査取得計画です
	 * @param[in] candidates 同captureの実現在行です
	 * @param[in] hints 同現在行から正規factoryで作ったhintです
	 * @param[in] nowUtc 同scanの表示に使う固定試験時刻です
	 * @return 元factoryが検証して発行した非導入参照行です
	 * @note claim/grant/token/recordを新しく作らず、元guardとordinal検査を維持します
	 */
	[[nodiscard]] static std::vector<UpdateCandidate> makeReferencesForFixture(
		SignedIndexScanSession &session, const OfficialPreparationPlan &plan,
		std::span<const UpdateCandidate>			 candidates,
		std::span<const OfficialDiscoveryDeviceHint> hints, std::chrono::sys_seconds nowUtc)
	{
		return session.binding_.makeReferences( session.acquisitionLookup_, session.adapter_, plan,
											   candidates, hints, nowUtc) ;
	}
	/**
	 * @brief Composite registryが一度実行した元索引summaryを読取りcopyします
	 * @param[in] provider 同threadの元Composite ownerです
	 * @return 元cached statusと非機密counterだけのcopyです
	 * @note scan/resolver発行/lookupの失効やownerの変更を行いません
	 */
	[[nodiscard]] static IndexScanSummary cachedSummaryForFixture(
		const CompositeUpdateProvider &provider)
	{
		return provider.signedIndexSummary_ ;
	}
	/**
	 * @brief 試験用の同じWiX対象と表示行が保持した元照合数を返します
	 * @param[in] session 同じスキャンと署名索引を保持する所有者です
	 * @param[in] target 取得用の元対象です
	 * @param[in] candidate 同スキャンの閲覧専用行です
	 * @return 保存した照合数です。完全一致がなければ0です
	 * @note 参照、取得票、追加の導入許可は発行しません
	 */
	[[nodiscard]] static std::size_t wixReferenceRelationCountForFixture(
		const SignedIndexScanSession &session, const OfficialPreparationTarget &target,
		const UpdateCandidate &candidate) ;
	/**
	 * @brief 同所有targetの既検査入力だけをunitへ読取りcopyします
	 * @param[in] session 同threadの原scan ownerです
	 * @param[in] target 元target identityです
	 * @return 唯一の正常所有入力、欠損/別target/不正ordinalでは空です
	 * @note 原const object/claim/grant/token/observerを変更しません
	 */
	[[nodiscard]] static std::optional<DriverArchiveInput> inspectionInputForFixture(
		const SignedIndexScanSession &session, std::wstring_view target) ;
	/**
	 * @brief 完全fake操作中に限り既存Driver Store ownerを試験へ借用します
	 * @param[in,out] provider 同workerが所有する通常Compositeです
	 * @return 同Compositeの非所有参照です。scanや導入権限を発行しません
	 */
	[[nodiscard]] static DriverStoreProvider &driverStoreFixture( CompositeUpdateProvider &provider)
	{
		return provider.driverStoreProvider_ ;
	}
	/**
	 * @brief 非通信の検索終端試験へ既inventory slotのscanだけを接続します
	 * @param[in,out] provider 同threadが所有する本物Compositeです
	 * @param[in] fake 現在行/実APIを持たず、保護stateを生成しない完全な試験用Providerです
	 * @return 元inventory slotを差し替えた場合trueです。空fakeやslot欠損は拒否します
	 * @note installやProvider追加を行いません。空の公式device snapshotだけを使います
	 */
	[[nodiscard]] static bool setInventoryScanFixture( CompositeUpdateProvider		  &provider,
													  std::shared_ptr<IUpdateProvider> fake)
	{
		// 不完全なfakeを実device列挙へfallbackさせません
		if( !fake) {
			return false ;
		}

		// 既registryのinventory一slotだけを同scopeのfakeへ接続します
		for( auto &entry : provider.providerRegistry_) {
			// WUAや公式Providerのslotとroutingは変更しません
			if( entry.descriptor.id != DRIVER_STORE_PROVIDER_ID) {
				continue ;
			}

			entry.scan = [fake]( const auto session, const auto &options, const auto, const auto &,
								const auto &progress) {
				return fake->scan( session, options, progress) ;
			} ; // 同scopeの明示fakeを共有所有します
			entry.measurementEvidence = {} ;
			return true ;
		}

		return false ;
	}
	/**
	 * @brief 混在試験だけの明示fakeを既存WUA registryへ接続します
	 * @param[in,out] provider 同workerだけが所有する本物Compositeです
	 * @param[in] fake 実WUA APIを持たない完全な試験用Providerです
	 * @return 既存WUA slotをscan/installとも置換できた場合trueです
	 * @note 製品入口から呼べず、空fakeやslot欠損をnativeへ補完しません
	 */
	[[nodiscard]] static bool setManagedFixture( CompositeUpdateProvider			&provider,
												std::shared_ptr<IUpdateProvider> fake)
	{
		// 不完全なfixtureを製品WUAへfallbackさせません
		if( !fake) {
			return false ;
		}

		// Canonical registryの既存slot一つだけを置換し、Providerを追加しません
		for( auto &entry : provider.providerRegistry_) {
			// WUA以外の元inventory・索引・公式境界を変更しません
			if( entry.descriptor.id != WINDOWS_UPDATE_PROVIDER_ID) {
				continue ;
			}

			entry.scan = [fake]( const auto session, const auto &options, const auto, const auto &,
								const auto &progress) {
				return fake->scan( session, options, progress) ;
			} ; // 同workerの明示fakeだけを共有所有します
			entry.install = [fake]( const auto session, const auto ids, const auto parent,
								   const auto &progress) {
				return fake->install( session, ids, parent, progress) ;
			} ; // 同じfakeが元scanと元選択を照合します
			entry.invalidatePreparation = [fake]() { fake->invalidatePreparation() ; } ;
			entry.measurementEvidence	= {} ;
			entry.metadataScan			= {} ;
			return true ;
		}

		return false ;
	}
	/**
	 * @brief 同threadだけの同期非機密観測を登録または解除します
	 * @param[in] observer 解除時はnullです。元処理の結果を変更できません
	 * @param[in,out] state 同期呼出し中だけ借用する観測所有者です
	 */
	static void observePublication( PublicationObserver observer, void *state) noexcept ;
	/**
	 * @brief 完全なlaunch表だけを同worker threadへ結合します
	 * @param[in] calls 全五関数のWindows ABI fixtureです
	 * @return 欠損または同threadの重複scopeでは空、それ以外は単独所有scopeです
	 */
	[[nodiscard]] static std::unique_ptr<ScopedInstallerFixture> createInstaller(
		InstallerNativeCalls calls) ;
	/**
	 * @brief 同worker所有者と完全固定依存を借用結合します
	 * @param[in,out] provider 本体Compositeです
	 * @param[in,out] session 終端まで生存する同scan ownerです
	 * @param[in] services 開始前固定の非通信fixture依存です
	 * @param[in] operationId 正の通常scan操作IDです
	 */
	static void bind( CompositeUpdateProvider &provider, SignedIndexScanSession &session,
					 const provider_worker_index_detail::Services &services,
					 OperationId								   operationId)
	{
		provider.bindSignedIndexSession( session, services, operationId, {}) ;
	}
	/**
	 * @brief 同原lookupの参照を通常scanへ公開します
	 * @param[in,out] provider 同本体Compositeです
	 * @param[in] plan 実adapter生成の同scan計画です
	 * @param[in,out] result 元通常scanの所有結果です
	 */
	static void publishReferences( CompositeUpdateProvider		&provider,
								  const OfficialPreparationPlan &plan, ScanResult &result)
	{
		provider.finishSignedIndexScanPublication( plan, result) ;
	}
} ;
#endif
} // namespace drivercrate::signed_index_candidate_binding_detail
