//------------------------------------------------------------------------------
/**
 * @file signed_index_scan.cpp
 * @brief 通常worker scanの全batchと協調期限を管理します
 * @version 01.34.01
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/10/11  停止と保持枠拒否で最初の元照合診断を保持
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  全batch凍結から同active taskの共通取得・内容検査へ接続
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  同認証payloadと取得policyの同一targetを一枠へ予約
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  私有証拠付き部分positiveを元未判定件数へ分離保持
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  UI専用objectで実claim済みtaskを同期観測
 * Ver.01.07.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続
 * Ver.01.08.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.09.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続
 * Ver.01.11.00 Shunji Ogawa  2026/11/03  拡大recordと有限保持quotaを通常経路へ整合
 * Ver.01.12.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合
 * Ver.01.13.00 Shunji Ogawa  2026/11/08  同一署名索引の本体再利用から通常loadと照合を継続
 * Ver.01.14.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.14.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.14.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.15.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * Ver.01.16.00 Shunji Ogawa  2026/11/18  retained全A/Bの純粋照合後だけLOCALとhost観測を接続
 * Ver.01.17.00 Shunji Ogawa  2026/11/19  正規client最低buildのretained入力も同scan hostへ結合
 * Ver.01.18.00 Shunji Ogawa  2026/11/20  HardwareIds限定の照合を同じ上限と取消しへ接続
 * Ver.01.19.00 Shunji Ogawa  2026/11/20  認証済み追加欄から端末用の元領域を保持
 * Ver.01.20.00 Shunji Ogawa  2026/11/20  機種条件付きの追加行と同スキャンの端末型番を接続
 * Ver.01.21.00 Shunji Ogawa  2026/11/20  同workerの型番観測と保持fileの新使用前確認を接続
 * Ver.01.22.00 Shunji Ogawa  2026/11/20  内容検査の通常入口で元配布物と現在の型番を確認
 * Ver.01.23.00 Shunji Ogawa  2026/11/20  公式の必須条件を現在デバイス名と同じ取得対象へ結合
 * Ver.01.24.00 Shunji Ogawa  2026/11/20  内容検査と取得済み本文の再利用で現在の端末群を再確認
 * Ver.01.25.00 Shunji Ogawa  2026/11/22  同じ走査の署名済み専用欄を照合と非導入内容検査へ接続
 * Ver.01.25.01 Shunji Ogawa  2026/11/22  公式Modelsの検査後の保持失敗を内容エラーへ結合
 * Ver.01.26.00 Shunji Ogawa  2026/11/22  私有ZIP規約を明示同意と新規・再利用の保護ファイルへ接続
 * Ver.01.27.00 Shunji Ogawa  2026/11/22  完全Hardware ID付きベンダー配布を署名済み補足から照合へ接続
 * Ver.01.28.00 Shunji Ogawa  2026/11/23  私有WiX行を同スキャンのWindows観測と完全IDの照合へ接続
 * Ver.01.29.00 Shunji Ogawa  2026/11/23  検査専用の元リンク照合と両配布元の待機を取得へ接続
 * Ver.01.29.01 Shunji Ogawa  2026/11/23  保護取得物の照合後に元期限を確認し内容状態を分離
 * Ver.01.30.00 Shunji Ogawa  2026/11/23  封印したWiXの署名・元規約・全ドライバー閉包を検査
 * Ver.01.31.00 Shunji Ogawa  2026/11/23  同じ検査用取得から期限付きの閲覧用規約全文を返す
 * Ver.01.32.00 Shunji Ogawa  2026/11/23  検査済みWiXの同じ保護領域を端末用に再検査
 * Ver.01.33.00 Shunji Ogawa  2026/11/23  検査で発行した同じ規約表示を取得の元証拠に保持
 * Ver.01.33.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.01.34.00 Shunji Ogawa  2026/11/27  二段の公式規約を取得・再検査前の同一操作へ結合
 * Ver.01.34.01 Shunji Ogawa  2026/11/27  取得直後と再照合で同じ元配布形式を使用
 * </pre>
 *
 * @note Crypto・schema・端末照合は既存の共通実装へ委譲します
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_scan.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/signed_index_wix_content.h"
#include "platform/client_min_build_scope.h"
#include "core/provider_registry.h"
#include "platform/official_download_grant.h"
#include "platform/official_download_workspace.h"
#include "platform/common_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_inf_metadata_extraction.h"
#include "platform/official_mapped_file.h"
#include "platform/official_zip.h"
#include "platform/signed_index_task_observer_internal.h"
#include <array>
#include <memory>
#include <new>
#include <set>
#include <utility>
#include <algorithm>
#include <windows.h>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief Windowsが保持するSMBIOS由来の製造元と製品名から機種型番を確認します
 * @return 確認済みの製造元と型番です。元の値を外部へ返しません
 */
//------------------------------------------------------------------------------
IndexPlatformMachineIdentity provider_worker_index_detail::observeIndexPlatformMachine()
{
	// 固定した二つのWMI相当属性だけを分離したバッファへ読み取ります
	const auto read = []( const wchar_t			   *name,
						 std::array<wchar_t, 129U> &buffer) -> std::wstring_view {
		constexpr auto BIOS	  = L"HARDWARE\\DESCRIPTION\\System\\BIOS" ;	// SMBIOSの読取り専用値です
		DWORD		   bytes  = static_cast<DWORD>( sizeof( buffer)) ;		// バッファ全量です
		const auto	   status = RegGetValueW( HKEY_LOCAL_MACHINE, BIOS, name, RRF_RT_REG_SZ, nullptr,
											 // 指定した単一の通常文字列です
											 buffer.data(), &bytes) ;
		// 切り詰め、ゼロ長、埋込みNULを別の有効値へ変換しません
		if( status != ERROR_SUCCESS || bytes < sizeof( wchar_t) || bytes > sizeof( buffer) ||
		   bytes % sizeof( wchar_t) != 0U) {
			return {} ;
		}

		const auto				length = bytes / sizeof( wchar_t) - 1U ;	// 終端を除く実文字数です
		const std::wstring_view value{buffer.data(), length} ;				// 同呼出中だけ借用します
		return buffer[length] == L'\0' && value.find( L'\0') == value.npos ? value
																		  : std::wstring_view{} ;
	} ;
	std::array<wchar_t, 129U> manufacturer{} ;	// 端末のSystemManufacturerだけです
	std::array<wchar_t, 129U> product{} ;		// 端末のSystemProductNameだけです
	return parseIndexPlatformMachine( read( L"SystemManufacturer", manufacturer),
									 read( L"SystemProductName", product)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの保持量を有限枠内だけで加算する
 * @param[in] additional 今回検査が実保持したbyte数
 * @param[in,out] total 元累計。失敗時は変更しない
 * @return overflowせず3GiB以内へ加算できた場合true
 */
//------------------------------------------------------------------------------
bool tryRetainIndexedInspectionBytes( const std::uint64_t additional, std::uint64_t &total) noexcept
{
	// 既に不正な累計も、加算overflowも小さい正常値へ戻さない
	if( total > INDEX_SCAN_RETAINED_MAX_BYTES ||
	   additional > INDEX_SCAN_RETAINED_MAX_BYTES - total) {
		return false ;
	}

	total += additional ;
	return true ;
}
// 通常platformと製品EXEへ観測登録・呼出の定義を生成しません
#if defined( DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER) && defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
namespace {
/** @brief 同workerの同期観測関数です */
// 同worker threadだけで使用する非所有noexcept関数pointerです
thread_local signed_index_task_observer_detail::ApprovedTaskObserver approvedIndexTaskObserver =
	nullptr ;
/** @brief 同workerの同期観測stateです */
// 試験がworkerのstop/joinまで共有所有する非所有stateです
thread_local void *approvedIndexTaskObserverState = nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同worker threadへ一組の観測pointerを登録し、null対で解除します
 * @param[in] observer 非nullはstateと対で登録します。nullはstateもnullの場合だけ解除します
 * @param[in] state Workerのstop/joinまで有効な非所有pointerです。関数と対でnullを受理します
 * @return 空slotへの登録またはnull対の解除はtrue、不整合または重複登録はfalseです
 * @note 同workerだけから呼びます。例外・blocking・製品への登録fallbackはありません
 */
//------------------------------------------------------------------------------
bool signed_index_task_observer_detail::registerApprovedIndexTaskObserver(
	ApprovedTaskObserver observer, void *state) noexcept
{
	// 片方だけのnullと重複登録から未所有stateを呼び出しません
	if( (observer == nullptr) != (state == nullptr) ||
	   (observer != nullptr && approvedIndexTaskObserver != nullptr)) {
		return false ;
	}

	approvedIndexTaskObserver	   = observer ;
	approvedIndexTaskObserverState = state ;
	return true ;
}
#endif
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 認証済みHTTPS URLから待機照合用の小文字DNS名を借用します
 * @param[in] url 索引のURL文法を検証済みの元リンク又は転送先です
 * @return DNS名です。ポート表記の違いを同じ配布元として扱います
 * @note 取得先の検証や権限の発行には使用しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string_view wixPayloadHost( std::string_view url) noexcept
{
	constexpr std::string_view HTTPS = "https://" ;	// 検証済みのHTTPSスキームです
	// 認証済みのHTTPS以外から待機のキーを作りません
	if( !url.starts_with( HTTPS)) {
		return {} ;
	}

	url.remove_prefix( HTTPS.size()) ;
	return url.substr( 0U, url.find_first_of( ":/?")) ;
}

/** @brief Callback回数と時計・取消しを全batch共通で制限します */
class LimitedResolver final : public IndexPublicIdResolver {
public:
	/**
	 * @brief 同期scan期間だけ全参照を借用します
	 * @param[in] inner 元の同scan callback
	 * @param[in] services 固定service
	 * @param[in] cancellation 操作限定取消し
	 * @param[in] deadline 全operation期限
	 * @param[in,out] summary 全operation件数
	 */
	LimitedResolver( const IndexPublicIdResolver					 &inner,
					const provider_worker_index_detail::Services &services,
					const ProviderScanCancellation				 &cancellation,
					std::chrono::steady_clock::time_point deadline, IndexScanSummary &summary)
		: inner_( inner), services_( services), cancellation_( cancellation), deadline_( deadline),
		  summary_( summary), batchDeadline_( deadline)
	{
	}
	/**
	 * @brief 種別・contextを保ったまま予算内のcallbackだけを呼びます
	 * @param[in] kind 元公開ID種別
	 * @param[in] publishedId 元公開ID
	 * @param[in] classGuid 元class
	 * @param[in] context 同scan context
	 * @param[in] present 全present opaque
	 * @return 停止・超過では未完了。実callback診断を保持します
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present) const override
	{
		return resolveWithinBudget( kind, publishedId, classGuid, context, present, false) ;
	}

	/**
	 * @brief HardwareIds限定の照合を同じ上限で呼び出す
	 * @param[in] publishedId 元の公表Hardware ID
	 * @param[in] classGuid 元レコードのClassGUID
	 * @param[in] context 同scan context
	 * @param[in] present 全present opaque。同期中だけ借用する
	 * @return 停止・超過では未完了。実callbackの診断とHardwareIds限定証拠を保持する
	 */
	[[nodiscard]] IndexPublicIdResolution resolveHardwareId(
		std::string_view publishedId, std::string_view classGuid, IndexLookupContext context,
		std::span<const std::wstring> present) const override
	{
		return resolveWithinBudget( IndexPnpIdKind::HARDWARE, publishedId, classGuid, context,
								   present, true) ;
	}

private:
	/**
	 * @brief 各照合を同じ呼出し予算・期限・取消しへ結ぶ
	 * @param[in] kind 元公開IDの種別
	 * @param[in] publishedId 元公開ID
	 * @param[in] classGuid 元レコードのClassGUID
	 * @param[in] context 同scan context
	 * @param[in] present 同scanの完全なpresent opaque
	 * @param[in] hardwareOnly HardwareIdsだけを使う照合のときtrue
	 * @return 元callbackの同期結果。期限または取消し到達時は証拠を破棄した未完了結果
	 */
	[[nodiscard]] IndexPublicIdResolution resolveWithinBudget(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present, bool hardwareOnly) const
	{
		// 取消し・期限・全operation callback上限後に秘密照合を開始しません
		if( stopped() || summary_.resolverCalls >= services_.maximumCalls) {
			return {.context = context,
					.error	 = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))} ;
		}

		++summary_.resolverCalls ;
		auto result =
			// 指定された照合区分を内側の同じ入口へ渡す
			hardwareOnly ? inner_.resolveHardwareId( publishedId, classGuid, context, present)
						 : inner_.resolve( kind, publishedId, classGuid, context, present) ;
		// 同期callback中の取消しや期限到達を正の関係へ昇格しません
		if( stopped()) {
			result.completed = false ;
			result.devices.clear() ;
			result.positiveProof.reset() ;
			result.deviceProofs.clear() ;
			// 元callback診断がない場合だけ協調停止の診断を補います
			if( result.error == 0U) {
				result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
			}
		}

		return result ;
	}

public:
	/**
	 * @brief Nativeだけが元inventoryの私有leaseを共有します
	 * @return 元factory発行の不変証拠の共有所有です。generic callbackでは空です。証拠objectは共有しても元inventory/contextの有効性や権限を
	 *         延長しません
	 * @note 内側resolverのleaseProofを一回呼び、そのshared_ptrを返します。このwrapper自身はleaseを新発行しません
	 */
	[[nodiscard]] std::shared_ptr<const NativeIndexLookupLease> leaseProof() const noexcept override
	{
		return inner_.leaseProof() ;
	}
	/**
	 * @brief 元全体期限以内の一batch協調期限を開始します
	 */
	void startBatch()
	{
		batchDeadline_ =
			std::min( deadline_, services_.monotonic() +
									std::chrono::milliseconds{index_capacity::BATCH_MILLISECONDS}) ;
	}
	/**
	 * @brief 現在の協調停止条件を確認します
	 * @return 取消しまたは期限以上ならtrue
	 */
	[[nodiscard]] bool stopped() const
	{
		return (cancellation_ && cancellation_()) ||
			   services_.monotonic() >= std::min( deadline_, batchDeadline_) ;
	}

private:
	/// 同scan秘密callbackの借用
	const IndexPublicIdResolver					 &inner_ ;
	/// Worker固定serviceの借用
	const provider_worker_index_detail::Services &services_ ;
	/// 同operation取消しの借用
	const ProviderScanCancellation				 &cancellation_ ;
	/// 全operationの単調期限
	std::chrono::steady_clock::time_point		  deadline_ ;
	/// 同workerだけが更新する非機密件数
	IndexScanSummary							 &summary_ ;
	/// 同全体期限以内に固定した一batchの協調期限です
	std::chrono::steady_clock::time_point		  batchDeadline_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Store／lookupの期限拒否を索引専用区分へ保ちます
 * @param[in] status Storeの元区分
 * @return 読取り成立以外の明示区分
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexScanStatus loadStatus( const IndexStoreStatus status) noexcept
{
	// 元拒否分類だけを映し、空・未配備を成功へまとめません
	if( status == IndexStoreStatus::TRUST_UNAVAILABLE) {
		return IndexScanStatus::TRUST_UNAVAILABLE ;
	}

	// Genesisは有効な索引世代がない状態です
	if( status == IndexStoreStatus::EMPTY_STORE) {
		return IndexScanStatus::EMPTY_STORE ;
	}

	// 現在時刻不明は期限内と推測しません
	if( status == IndexStoreStatus::TIME_UNAVAILABLE) {
		return IndexScanStatus::TIME_UNAVAILABLE ;
	}

	// 発行前の索引を使用しません
	if( status == IndexStoreStatus::NOT_YET_VALID) {
		return IndexScanStatus::NOT_YET_VALID ;
	}

	// 期限以上の索引を使用しません
	if( status == IndexStoreStatus::EXPIRED) {
		return IndexScanStatus::EXPIRED ;
	}

	return IndexScanStatus::LOAD_REJECTED ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 秘密snapshot・callback・関係を全て解放します
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::invalidate() noexcept
{
	nextOwnedPayloadOrdinal_ = 1U ;
	adapter_.invalidate() ;
	binding_.invalidate( bindingStore_) ;
	acquisition_.reset() ;
	workspace_.reset() ;
	acquisitionLookup_.reset() ;
	context_ = {} ;
	host_.reset() ;
	limits_				= {} ;
	preparationSummary_ = {} ;
	batches_.clear() ;
	resolver_.reset() ;
	snapshot_.reset() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常workerの同scan完了後に全operation予算内で読取ります
 * @param[in,out] provider 実scanを終えた同worker Provider
 * @param[in] operationId 正のworker operation
 * @param[in] sessionId 実scan結果と一致する正のsession
 * @param[in] services 固定製品入口または内部fixture能力
 * @param[in] cancellation 同operation限定の協調取消し
 * @param[in] progress 確定record数だけの同期通知。空では通知しません
 * @return 非機密件数と独立status。元scanの成否を変更しません
 * @note 例外は秘密所有を破棄して診断へ変換します
 */
//------------------------------------------------------------------------------
IndexScanSummary SignedIndexScanSession::scan(
	IUpdateProvider &provider, const OperationId operationId, const ScanSessionId sessionId,
	const provider_worker_index_detail::Services		&services,
	const ProviderScanCancellation						&cancellation,
	const std::function<void( const IndexScanSummary &)> &progress) noexcept
{
	invalidate() ;
	IndexScanSummary summary ;	// 終端でも秘密文字列を持たない件数です
	try {
		// 内部fixtureでも固定製品上限を広げることを認めません
		if( !services.load || !services.utc || !services.monotonic ||
		   services.maximumRecords > index_capacity::RECORDS ||
		   services.maximumCalls > index_capacity::WHOLE_PUBLIC_IDS ||
		   services.maximumRelations > index_capacity::RETAINED_RELATIONS ||
		   services.duration.count() < 0 ||
		   services.duration > std::chrono::milliseconds{index_capacity::SCAN_MILLISECONDS}) {
			summary.status = IndexScanStatus::INTERNAL_FAILURE ;
			return summary ;
		}

		auto *const inventory =
			dynamic_cast<IIndexScanInventory *>( &provider) ;	// 同scanの秘密seamだけです
		// SeamのないProviderから製品network/storeや別inventoryを起動しません
		if( inventory == nullptr) {
			summary.status = IndexScanStatus::INVENTORY_UNAVAILABLE ;
			return summary ;
		}

		// 取消済みcommandはstoreを読みません
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			return summary ;
		}

		// 明示されたrefreshだけを一回実行し、空のlocal fixtureを製品依存へ補完しません
		if( services.refresh) {
			summary.refresh = services.refresh( cancellation) ;
			// Commit後でも取消しからlocal候補や未使用grantを発行しません
			if( (cancellation && cancellation()) ||
			   summary.refresh->status == IndexRefreshStatus::CANCELLED) {
				summary.status = IndexScanStatus::CANCELLED ;
				return summary ;
			}

			// 暗号・rollback・不確定commit等の元失敗を旧cacheの再読取りで隠しません
			if( summary.refresh->status != IndexRefreshStatus::REFRESHED &&
			   summary.refresh->status != IndexRefreshStatus::AUTHENTICATED_CACHE &&
			   summary.refresh->status != IndexRefreshStatus::UNCHANGED) {
				summary.status = summary.refresh->status == IndexRefreshStatus::TIME_UNAVAILABLE
									 ? IndexScanStatus::TIME_UNAVAILABLE
									 : IndexScanStatus::LOAD_REJECTED ;
				summary.error  = summary.refresh->error ;
				return summary ;
			}
		}

		const auto deadline =
			// Refresh後の独立した全scan期限です
			services.monotonic() + services.duration ;
		const auto now = services.utc() ;	// 信頼UTCを一度確認します
		// 時刻不明ではloadを開始しません
		if( !now) {
			summary.status = IndexScanStatus::TIME_UNAVAILABLE ;
			return summary ;
		}

		// 期限到達後は追加I/Oを開始しません
		if( services.monotonic() >= deadline) {
			summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
			return summary ;
		}

		auto loaded			= services.load( now) ;	// 同じ実保存原byteの全再認証です
		summary.storeStatus = loaded.status ;
		summary.error		= loaded.error ;
		// Load中の取消しはsnapshotを所有しません
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			return summary ;
		}

		// 未配備・破損・期限切れを候補なし成功へ変換しません
		if( loaded.status != IndexStoreStatus::SNAPSHOT_READY || !loaded.snapshot) {
			summary.status = loadStatus( loaded.status) ;
			return summary ;
		}

		// 同じ保護ストアから再読した原assetの、先頭識別子に対応する一領域を検査します
		const auto &base = loaded.snapshot->schemaReceipt() ;
		// GZipの追加欄が専用の公式Models形式かを保持します
		const bool	scopedModels = base.assetBytes().hasScopedModelsFrame() ;
		// 追加欄の識別子に対応する読み取りの結果と候補レコード
		auto		supplemental = scopedModels ? readSignedIndexScopedModels( base, now)
												: readSignedIndexConsumerSupplement( base, now) ;
		summary.supplementStatus = supplemental.contents.transportStatus ;
		// 追加欄の展開前の失敗と元recordの構造拒否を区別します
		if( supplemental.contents.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED) {
			summary.supplementRecordsStatus = supplemental.contents.status ;
		}

		// 解析中の取消し後に端末の照合や取得を許可しません
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			return summary ;
		}

		// 追加欄を検査している間に時間枠へ到達した場合は端末照合を行いません
		if( services.monotonic() >= deadline) {
			summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
			return summary ;
		}

		// 追加欄の認証と全検査が通った場合だけ、端末が扱える証拠付きの候補を使用します
		if( supplemental.contents.status == IndexRecordsStatus::SCHEMA_VALIDATED) {
			// 元の規約を再確認できる行と完全ID照合の行を通常の候補へ渡します
			std::erase_if( supplemental.contents.records, []( const IndexDistributionRecord &record) {
				return !requiresExactIndexHardwareMatch( record) &&
					   (!record.acquisitionDescriptor ||
						!SignedIndexAcquisitionAdapter::requiresApprovedTermsRecheck(
							record.acquisitionDescriptor->terms)) ;
			}) ;
			loaded.snapshot->consumerSupplement_ = std::move( supplemental) ;
		}
		// DMの期限や構造の拒否とDCの既存処理を分け、認証済み本文の照合を継続します
		else if( !scopedModels &&
				supplemental.contents.transportStatus != IndexAssetSupplementStatus::ABSENT &&
				supplemental.contents.transportStatus != IndexAssetSupplementStatus::EXPIRED) {
			summary.status = IndexScanStatus::LOAD_REJECTED ;
			summary.error  = supplemental.contents.error ;
			return summary ;
		}

		const auto records =
			// 同じ認証済み索引の端末用元recordです
			loaded.snapshot->consumerRecords() ;
		summary.totalRecords	 = records.size() ;
		summary.remainingRecords = summary.totalRecords ;
		bool needsPlatformMachine{} ;	// 公式型番を確認できる機種別レコードがある場合だけ観測します
		// 全codec検査済みrecordの公開入力数を別分母として保持します
		for( std::size_t recordIndex = 0U; recordIndex < records.size(); ++recordIndex) {
			const auto &record = records[recordIndex] ;	// 元の全IDと配布条件を併せて確認します
			summary.totalPublicIds += record.publishedIdentityEvidence.pnpIds.size() ;
			needsPlatformMachine =
				needsPlatformMachine ||
				(record.platformDeviceScope &&
				 record.platformDeviceScope->machineVendor != IndexPlatformMachineVendor::UNKNOWN) ;
		}

		IndexLookupContext		  context ;	// 実Driver Store発行contextです
		std::vector<std::wstring> present ;	// 同scanの全opaqueです
		resolver_ = inventory->indexScanInventory( operationId, context, present) ;
		// 別scan／0／不正inventory contextではbatchを開始しません
		if( !resolver_ || operationId == 0U || sessionId == 0U ||
		   context.operationId != operationId || context.scanSessionId != sessionId ||
		   context.inventoryGeneration == 0U) {
			summary.status = IndexScanStatus::STALE_CONTEXT ;
			invalidate() ;
			return summary ;
		}

		context_ = context ;
		// 確定した同スキャンの端末で機種条件付き行の照合に必要な値だけを取得します
		if( needsPlatformMachine && services.platformMachine) {
			try {
				loaded.snapshot->platformMachine_		 = services.platformMachine() ;
				loaded.snapshot->platformMachineContext_ = context ;
			} catch( ...) {
				loaded.snapshot->platformMachine_ = {} ;
			}
		}

		// 確定した同scan contextへ一度だけ原host観測を結びます
		if( services.hostPlatform) {
			WindowsHostPlatformObservation observation ;	// 依存例外を原native errorへ捏造しません
			try {
				observation = services.hostPlatform() ;
			} catch( ...) {
				observation = {} ;
			}

			host_								 = IndexScanHostSnapshot{context_, observation} ;
			loaded.snapshot->windowsHost_		 = observation ;
			loaded.snapshot->windowsHostContext_ = context_ ;
		}

		snapshot_ = std::make_shared<const AuthenticatedIndexSnapshot>( std::move( *loaded.snapshot)) ;
		LimitedResolver limited{*resolver_, services, cancellation, deadline,
								summary} ;	// 全batchで同じ予算です
		// 全recordを処理するか有限operation予算／協調停止まで進めます
		while( summary.processedRecords < summary.totalRecords) {
			// 中断後の関係は秘密所有も含めて失効します
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			// 全operation上限を超える残recordを成功へ数えません
			if( limited.stopped() || summary.processedRecords >= services.maximumRecords) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}

			const auto count =
				std::min( {INDEX_LOOKUP_RECORD_BATCH_MAX, summary.remainingRecords,
						  services.maximumRecords -
							  summary.processedRecords}) ;	// 全operation残枠内のbatchです
			limited.startBatch() ;
			const auto batchStart  = services.monotonic() ;		// 同じ単調時計のbatch開始値です
			const auto callsBefore = summary.resolverCalls ;	// 元inner resolverの実呼出数です
			// 同batchの所有結果と停止理由です
			auto	   result = lookupSignedIndexRecords(
				  snapshot_, context, context, present,
				  {summary.processedRecords, count,
					   std::min( INDEX_LOOKUP_RESOLVER_CALL_MAX,
								services.maximumCalls - summary.resolverCalls),
					   services.maximumRelations - summary.relationCount,
					   index_capacity::RETAINED_OPAQUE_IDENTITIES - summary.relatedDeviceCount, true,
					   [&limited] { return limited.stopped() ; }},
				  services.utc(), &limited) ;
			summary.maximumBatchResolverCalls =
				std::max( summary.maximumBatchResolverCalls, summary.resolverCalls - callsBefore) ;
			const auto batchElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
										  services.monotonic() - batchStart)
										  .count() ;	// 観測時間です
			summary.maximumBatchMilliseconds = std::max(
				summary.maximumBatchMilliseconds,
				static_cast<std::size_t>( std::max<decltype( batchElapsed)>( 0, batchElapsed))) ;
			summary.lookupStatus = result.status ;
			// Lookup入力拒否では保存物を後続に保持しません
			if( !result.lookup) {
				// 後続batchの入力拒否で先行した元callback診断を上書きしません
				if( summary.error == 0U) {
					summary.error = result.error ;
				}

				summary.status = result.status == IndexRecordLookupStatus::EXPIRED
									 ? IndexScanStatus::EXPIRED
								 : result.status == IndexRecordLookupStatus::TIME_UNAVAILABLE
									 ? IndexScanStatus::TIME_UNAVAILABLE
								 : result.status == IndexRecordLookupStatus::NOT_YET_VALID
									 ? IndexScanStatus::NOT_YET_VALID
									 : IndexScanStatus::STALE_CONTEXT ;
				invalidate() ;
				return summary ;
			}

			// 未commit recordの元診断も先行する失敗を上書きせず保持します
			if( summary.error == 0U) {
				summary.error = result.error ;
			}

			// 取消し後のpartial positivesから権限を発行しません
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			const auto coverage =
				// 同lookupだけがcommitした全record prefixです
				result.lookup->progress() ;
			// 完全recordに属する保持tupleと元不足だけを計数します
			for( const auto &relation : result.lookup->relations()) {
				summary.relatedDeviceCount += relation.relatedDevices.size() ;
				++summary.relationCount ;
				summary.matchedRelations +=
					relation.state == IndexRecordMatchState::MATCHED ? 1U : 0U ;
				summary.nonUniqueRelations +=
					relation.reason == IndexRecordMatchReason::NON_UNIQUE_RELATION ? 1U : 0U ;
				summary.undeterminedRelations +=
					relation.state == IndexRecordMatchState::UNDETERMINED ||
							relation.state == IndexRecordMatchState::VERIFIED_PARTIAL ||
							relation.error != 0U
						? 1U
						: 0U ;
				summary.verifiedPartialRelations +=
					relation.state == IndexRecordMatchState::VERIFIED_PARTIAL ? 1U : 0U ;
				// 原callback診断は後続成功で消しません
				if( summary.error == 0U) {
					summary.error = relation.error ;
				}
			}

			summary.processedRecords += coverage.completedRecords ;
			summary.remainingRecords = summary.totalRecords - summary.processedRecords ;
			summary.processedPublicIds += coverage.processedPublicIds ;
			summary.definitiveNoRelationIds += coverage.definitiveNoRelationIds ;
			// 空の途中recordを完了batchとして保存しません
			if( coverage.completedRecords != 0U) {
				batches_.push_back( std::move( *result.lookup)) ;
			}

			// 表示の進行は要求countでなく完全record prefixだけです
			if( progress) {
				progress( summary) ;
			}

			// 最終progress callbackからの取消しも残件なし成功へ通しません
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			// 取消し/時刻/保持不足や進行不能を残件ありのまま返します
			if( coverage.stopReason == IndexLookupStopReason::STOP_REQUESTED ||
			   coverage.stopReason == IndexLookupStopReason::RETAINED_CAPACITY ||
			   coverage.completedRecords == 0U || limited.stopped()) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}
			// CALL_BUDGETは完全record境界で次の有限batchへ進み、元IDを飛ばしません
		}

		// 最終progress callbackからの取消しも残件なし成功へ通しません
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			invalidate() ;
			return summary ;
		}

		summary.status = summary.undeterminedRelations == 0U && summary.error == 0U &&
								 summary.processedPublicIds == summary.totalPublicIds
							 ? IndexScanStatus::COMPLETED
							 : IndexScanStatus::PARTIAL ;
		return summary ;
	} catch( const std::bad_alloc &) {
		invalidate() ;
		summary.status = IndexScanStatus::INTERNAL_FAILURE ;
		summary.error  = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		invalidate() ;
		summary.status = IndexScanStatus::INTERNAL_FAILURE ;
		summary.error  = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return summary ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの全私有batchから既存計画へ取得対象だけを結合します
 * @param[in,out] plan Providerの元計画または同じ有限上限の空計画
 * @param[in] services Worker開始前に固定した依存。任意公開鍵を受けません
 * @param[out] summary 非機密の件数と未接続診断。原UNKNOWNは元snapshotへ保持します
 * @param[in] currentCandidates 同じスキャンの元デバイス名を借用する候補一覧です
 * @return 計画の結合成立0。取得能力不足はsummaryへ独立保持して元Provider計画を維持します
 */
//------------------------------------------------------------------------------
NativeError SignedIndexScanSession::augmentPreparationPlan(
	OfficialPreparationPlan &plan, const provider_worker_index_detail::Services &services,
	IndexPreparationSummary &summary, const std::span<const UpdateCandidate> currentCandidates)
{
	preparationSummary_ = {.scanSessionId = plan.scanSessionId, .planId = plan.planId} ;
	// 索引読取り不成立では元Provider計画だけを維持します
	if( !snapshot_ || !resolver_ || context_.scanSessionId != plan.scanSessionId) {
		summary = preparationSummary_ ;
		return 0U ;
	}

	// 同scanの元計画上限と一意IDを、索引追加で回避しません
	if( plan.targets.size() > 256U || plan.scanSessionId == 0U || plan.planId == 0U ||
	   acquisitionLookup_) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto frozen = SignedIndexRecordLookup::freezeOwnedBatches( snapshot_, context_, batches_,
															  // 原byte／世代／全contextの再照合
															  services.utc()) ;
	// 全batchが凍結できなければ一部lookupから権限を作りません
	if( !frozen.lookup) {
		preparationSummary_.authorityError =
			frozen.error != 0U ? frozen.error : static_cast<NativeError>( E_ACCESSDENIED) ;
		summary = preparationSummary_ ;
		return 0U ;
	}

	acquisitionLookup_ = std::make_shared<const SignedIndexRecordLookup>( std::move( *frozen.lookup)) ;
	limits_			   = plan.limits ;
	// fullhost失敗をlegacy bool/build/SKUから補完しません
	if( host_) {
		preparationSummary_.authorityError =
			services.beginHostAcquisition
				? services.beginHostAcquisition( adapter_, acquisitionLookup_, context_, *host_,
												services.hostPlatform, services.utc())
				: adapter_.beginHost( acquisitionLookup_, context_, *host_, services.hostPlatform,
									 services.utc()) ;
	} else {
		const auto os =
			services.targetOs ? services.targetOs() : std::nullopt ;	// WorkerのOS観測だけです
		// OS不明をrecordの公開条件から補完しません
		if( !os) {
			preparationSummary_.authorityError = static_cast<NativeError>( E_NOTIMPL) ;
		} else {
			preparationSummary_.authorityError =
				services.beginAcquisition
					? services.beginAcquisition( adapter_, acquisitionLookup_, context_, *os,
												services.utc())
					: adapter_.begin( acquisitionLookup_, context_, *os, services.utc()) ;
		}
	}

	// 製品取得policy未配備では元Provider計画を残し、索引不足件数だけを返します
	if( preparationSummary_.authorityError != 0U) {
		preparationSummary_.unavailableRelations = acquisitionLookup_->relations().size() ;
		summary									 = preparationSummary_ ;
		return 0U ;
	}

	adapter_.platformMachineObserver_ = services.platformMachine ;
	adapter_.platformDeviceStore_	  = bindingStore_ ;
	std::unique_ptr<OfficialHttpClient> termsClient ;	// 本文が必要な元recordでだけ生成します
	// 全batchのglobal関係位置だけを使用し、計画全体256対象を越えません
	for( std::size_t relationIndex = 0U; relationIndex < acquisitionLookup_->relations().size();
		++relationIndex) {
		// 枠超過分を候補なし成功へ数えず元recordは不変に保持します
		if( plan.targets.size() >= 256U) {
			++preparationSummary_.capacityRejectedRelations ;
			continue ;
		}

		SignedIndexPreparationDescription description ;							// 同原関係だけの非機密対象と私有理由
		NativeError						  error{} ;								// 同意不要からnetwork clientを生成しません
		const auto &relation = acquisitionLookup_->relations()[relationIndex] ;	// 同原関係です
		const auto &original =
			// 原recordです
			acquisitionLookup_->snapshot().consumerRecords()[relation.recordIndex] ;
		std::wstring_view firmwareDeviceName ;	// 通常画面と同じ端末の名前です
		// 機器別条件の表示は同じ元端末の現在行だけから取得します
		if( !original.platformFirmwareGroups.empty() && relation.deviceIdentity) {
			const auto device =
				std::ranges::find_if( currentCandidates, [&relation]( const auto &entry) {
					return entry.current && entry.deviceIdentity == *relation.deviceIdentity ;
				}) ; // 同じ元スキャンの一台です
			// 元端末が表示されない場合は規約通信も確認計画も追加しません
			if( device == currentCandidates.end() ||
			   (device->model.empty() && device->title.empty())) {
				++preparationSummary_.unavailableRelations ;
				continue ;
			}

			firmwareDeviceName = device->model.empty() ? device->title : device->model ;
		}

		// 埋込み規約は明示した検査用取得の後に扱い、通常検索で配布物を読みません
		if( !original.wixContentEvidence && original.acquisitionDescriptor &&
		   original.acquisitionDescriptor->terms.state == IndexTermsState::ACCEPTANCE_REQUIRED) {
			// ZIP規約と二段リンクの追加通信は、同意前に通常回線と確認できた場合だけ行います
			if( SignedIndexAcquisitionAdapter::requiresApprovedTermsRecheck(
				   original.acquisitionDescriptor->terms)) {
				auto cost =
					services.costReader
						? services.costReader()
						: std::make_unique<
							  WindowsOfficialNetworkCostReader>() ;	// 同じworkerの回線照会です
				OfficialNetworkCostKind kind{} ;					// 判定不能時は通信を開始しません
				// 同意前の規約通信を通常回線に限り、判定できない候補は提示しません
				if( !cost || cost->read( kind) != 0U ||
				   kind != OfficialNetworkCostKind::UNRESTRICTED) {
					++preparationSummary_.unavailableRelations ;
					continue ;
				}
			}

			// 完全HTTP表を一度だけ同workerへ固定します
			if( !termsClient) {
				termsClient = services.httpTransport
								  ? std::make_unique<OfficialHttpClient>( services.httpTransport())
								  : std::make_unique<OfficialHttpClient>( false) ;
			}

			error = adapter_.readTermsText( relationIndex, context_, services.utc, *termsClient, {}) ;
		}

		// 全文不成立の対象はpayloadの取得同意計画へ入れません
		if( error == 0U) {
			error = adapter_.describe( relationIndex, context_, services.utc(), limits_, description,
									  firmwareDeviceName) ;	// 同scan予約上限を維持します
		}

		// UNKNOWN・未対応・非一意は取得対象を発行せず元理由をsnapshotへ残します
		if( error != 0U || !description.target) {
			++preparationSummary_.unavailableRelations ;
			continue ;
		}

		const auto existingTarget = std::ranges::find_if( plan.targets, [&]( const auto &target) {
			return target.identity == description.target->identity ;
		}) ; // 同issuerが全元関係へ結合した共有targetだけを一回予約します
		// 同じ共有targetの完全一致は別payload予約や取得件数へ重複追加しません
		if( existingTarget != plan.targets.end() && *existingTarget == *description.target &&
		   existingTarget->providerId == SIGNED_INDEX_PROVIDER_ID) {
			continue ;
		}

		// 同じIDでも値やProviderが異なる対象は黙って削除しません
		if( existingTarget != plan.targets.end()) {
			adapter_.invalidate() ;
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		plan.targets.push_back( std::move( *description.target)) ;
		++preparationSummary_.plannedTargets ;
	}

	summary = preparationSummary_ ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ公式配布の二つの通信先について送信前に原待機を確認します
 * @param[in] hosts 認証済み元アンカーと転送先の小文字DNSホストです
 * @param[in] now 同workerが送信チェック時に観測したUTCです
 * @return 送信可能なら0、時刻不明・逆行・要確認・待機中なら元の拒否HRESULTです
 * @note UTC確認は同workerの有効な最大値を保持します。再走査で原待機を解放しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexScanSession::checkWixPayloadWait(
	const std::array<std::string_view, 2U>		 &hosts,
	const std::optional<std::chrono::sys_seconds> now) noexcept
{
	// 妥当な現在時刻と保存を保証できない状態では通信を開始しません
	if( wixWaitCapacityClosed_ || !now || now->time_since_epoch().count() <= 0 || hosts[0].empty() ||
	   hosts[1].empty()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto seconds =
		// 正のUTC Unix秒です
		static_cast<std::uint64_t>( now->time_since_epoch().count()) ;
	// UTC逆行で新たな応答時刻や送信許可を算出しません
	if( seconds < wixLatestUtcSeconds_) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	wixLatestUtcSeconds_ = seconds ;
	// 元アンカーと転送先の両方を調べ、どちらかに有効な待機があれば通信を止めます
	for( const auto host : hosts) {
		const auto wait = wixPayloadWaits_.find( host) ;	// 同じホストの原HTTP応答です
		// 時刻不明の応答は自動解除せず、有効な時刻指定は元UTCまで保持します
		if( wait != wixPayloadWaits_.end() &&
		   (wait->second.needsReview || wait->second.notBeforeUtcSeconds > seconds)) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ配布の原HTTP応答から両ホストの待機下限と要確認状態を保持します
 * @param[in] hosts 認証済み元アンカーと転送先の小文字DNSホストです
 * @param[in] observation 共通HTTPの数値・UTC・要確認だけを持つ応答観測です
 * @note 同workerで元下限を短縮しません。保持枠又は割当の失敗後は新しいWiX送信を拒否します
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::rememberWixPayloadWait(
	const std::array<std::string_view, 2U> &hosts,
	const OfficialPayloadRetryObservation  &observation)
{
	// 待機を指定していない応答では既に保持する制約を変更しません
	if( !observation.needsReview && observation.notBeforeUtcSeconds == 0U) {
		return ;
	}

	// 両方を記録できると確認するまで次の通信許可を閉じ、例外時も閉じたままにします
	wixWaitCapacityClosed_ = true ;
	// 共通HTTPの同一配布経路に含まれる両配布元へ原応答を結びます
	for( const auto host : hosts) {
		auto wait = wixPayloadWaits_.find( host) ;	// 以前の原時刻と要確認状態を保持する行です
		// 以前に待機がないホストだけを有限の保持枠へ追加します
		if( wait == wixPayloadWaits_.end()) {
			// 上限到達後に以前の待機を削除して繰り返し送信しません
			if( wixPayloadWaits_.size() >= index_capacity::RETAINED_RELATIONS) {
				return ;
			}

			wait = wixPayloadWaits_.emplace( std::string{host}, observation).first ;
		}

		wait->second.notBeforeUtcSeconds =
			std::max( wait->second.notBeforeUtcSeconds, observation.notBeforeUtcSeconds) ;
		wait->second.needsReview = wait->second.needsReview || observation.needsReview ;
		wait->second.httpStatus	 = observation.httpStatus ;
	}

	wixWaitCapacityClosed_ = false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同active taskだけを共通grant・取得seal・通常内容検査へ接続します
 * @param[in,out] preparation 実approve／claimNextしたworker session
 * @param[in] task 同計画の未変更active task。元scan操作とは別です
 * @param[in] services Worker固定のHTTP・時計・回線依存
 * @param[in] cancellation 同取得操作の協調停止
 * @return 取得の確定結果。内容失敗は独立summaryへ残します
 * @throws std::bad_alloc 内部allocationに失敗した場合
 * @throws ... 内部serviceが送出した元例外
 * @note Workerの取得callbackは例外を再throwする前にinvalidateAcquisitionを呼びます
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult SignedIndexScanSession::acquireForInspection(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const provider_worker_index_detail::Services &services,
	const PreparationCancellation				 &cancellation)
{
	IndexPreparationItemSummary item{.targetIdentity =
										 task.target.identity} ;	// URL・hash・pathを含みません
	// 実active taskと元planが一致しない要求は共通取得より前に拒否します
	if( !acquisitionLookup_ || task.scanSessionId != context_.scanSessionId ||
	   task.planId != preparationSummary_.planId || !preparation.ownsActiveTask( task) ||
	   preparationSummary_.items.size() >= 256U) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_ACCESSDENIED),
				0U} ;
	}

	const auto approved = std::ranges::find(
		adapter_.bindings_, task.target,
		&SignedIndexAcquisitionAdapter::PreparedBinding::target) ;	// 元の取得計画に結ぶ私有行です
	const bool inspectWix =
		// 規約確認前の取得だけです
		task.target.terms == OfficialPreparationTerms::INSPECTION_ONLY ;
	std::array<std::string_view, 2U> wixHosts{} ;	// 元配布のアンカーと転送先の借用ホストです
	// 検査専用の元関係と同じ配布を確認し、両配布元の待機に結びます
	if( inspectWix && approved != adapter_.bindings_.end() &&
	   approved->relationIndex < acquisitionLookup_->relations().size()) {
		const auto index = acquisitionLookup_->relations()[approved->relationIndex]
							   .recordIndex ;	// 元関係の配布位置です
		const auto records =
			// 同署名索引からだけ借用します
			acquisitionLookup_->snapshot().consumerRecords() ;
		// 完全な元配布を持つ対象だけに待機キーを設定します
		if( index < records.size() && records[index].wixContentEvidence &&
		   records[index].acquisitionDescriptor) {
			wixHosts = {wixPayloadHost( records[index].acquisitionDescriptor->payloadUrl),
						wixPayloadHost( records[index].wixContentEvidence->downloadUrl)} ;
		}
	}

	NativeError wixWaitError{} ;	// 送信を止めた原待機診断を協調取消しから区別します
	const PreparationCancellation guardedCancellation = [&] {
		// 利用者の取消しは時計や通信を照会せず終端へ返します
		if( cancellation && cancellation()) {
			return true ;
		}

		wixWaitError = checkWixPayloadWait( wixHosts, services.utc()) ;
		return wixWaitError != 0U ;
	} ; // 同期取得中の元状態と時計だけを借用します
	const auto &transferCancellation =
		inspectWix ? guardedCancellation : cancellation ;	// 旧経路の取消し契約は維持します
	const auto makeClient = [&services] {
		return services.httpTransport
				   ? std::make_unique<OfficialHttpClient>( services.httpTransport())
				   : std::make_unique<OfficialHttpClient>( false) ;
	} ; // 同workerの固定HTTP factoryを同期中だけ借用します
	const auto readCost = [&services] {
		return services.costReader ? services.costReader()
								   : std::make_unique<WindowsOfficialNetworkCostReader>() ;
	} ; // 試験又は実回線の固定factoryを同期中だけ借用します
	std::unique_ptr<OfficialHttpClient> client ;		// WiXのページと配布取得では同じHTTP依存を使用します
	std::unique_ptr<IOfficialNetworkCostReader> cost ;	// 明示的な回線同意と共通取得で再照会します
	// 検査専用の元ページは、選択・回線・待機が成立した場合だけ送信します
	if( inspectWix) {
		cost = readCost() ;
		OfficialNetworkCostKind kind{} ;								// 許可のない従量制又は不明の回線を拒否します
		auto state = OfficialPreparationItemState::REJECTED ;			// 原待機又は原リンクの不一致です
		auto acquisitionState = OfficialAcquisitionState::REJECTED ;	// 内容検査とは別に保持します
		NativeError error	  = 0U ;									// HTTP前の拒否又は同じ公式ページの照合結果です
		// 回線照会が準備できない場合は、公式ページも送信しません
		if( !cost) {
			state			 = OfficialPreparationItemState::FAILURE ;
			acquisitionState = OfficialAcquisitionState::FAILURE ;
			error			 = static_cast<NativeError>( E_UNEXPECTED) ;
		}
		// 通常回線と確認できない場合は、この操作に結ぶ回線同意が必要です
		else if( (cost->read( kind) != 0U || kind != OfficialNetworkCostKind::UNRESTRICTED) &&
				!task.restrictedNetworkApproved) {
			state			 = OfficialPreparationItemState::AWAITING_NETWORK_CONSENT ;
			acquisitionState = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
			error			 = static_cast<NativeError>( E_ACCESSDENIED) ;
		}
		// 両配布元の原待機があるか、利用者が取り消した場合はページを要求しません
		else if( transferCancellation()) {
			error = wixWaitError != 0U
						? wixWaitError
						: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
		} else {
			client = makeClient() ;
			error  = adapter_.verifyWixInspectionPage( preparation, task, context_, services.utc,
													  *client, transferCancellation) ;
		}

		// 利用者の取消しを配布元の待機や証拠不一致として表示しません
		if( error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) {
			state			 = OfficialPreparationItemState::CANCELLED ;
			acquisitionState = OfficialAcquisitionState::CANCELLED ;
		}

		// 元ページ未成立から取得grantやローカル本体に分岐しません
		if( error != 0U) {
			item.acquisition =
				wixWaitError != 0U ? OfficialAcquisitionState::REJECTED : acquisitionState ;
			item.acquisitionError = wixWaitError != 0U ? wixWaitError : error ;
			preparationSummary_.items.push_back( item) ;
			return {wixWaitError != 0U ? OfficialPreparationItemState::REJECTED : state,
					item.acquisitionError, 0U} ;
		}
	}

	// 再確認が必要な規約を新規転送とローカル検査へ分ける前に確認する
	if( !inspectWix && approved != adapter_.bindings_.end() &&
	   approved->relationIndex < acquisitionLookup_->relations().size()) {
		const auto index =
			// 元候補位置です
			acquisitionLookup_->relations()[approved->relationIndex].recordIndex ;
		const auto records =
			// 署名済みの元候補だけです
			acquisitionLookup_->snapshot().consumerRecords() ;
		// ZIP内と二段リンク用の元レコードだけを承認済みの再照合へ進める
		if( index < records.size() && records[index].acquisitionDescriptor &&
		   SignedIndexAcquisitionAdapter::requiresApprovedTermsRecheck(
			   records[index].acquisitionDescriptor->terms)) {
			auto termsCost =
				services.costReader
					? services.costReader()
					: std::make_unique<WindowsOfficialNetworkCostReader>() ;	// この操作の実回線です
			OfficialNetworkCostKind kind{} ;									// 不明は従量制と同じ元同意境界に残します
			NativeError termsError = E_ACCESSDENIED ;							// 回線同意が成立しなければ送信しません
			// 通常回線か、この操作で別途許可された回線からだけ公式規約を再確認します
			if( termsCost &&
			   ((termsCost->read( kind) == 0U && kind == OfficialNetworkCostKind::UNRESTRICTED) ||
				task.restrictedNetworkApproved)) {
				auto termsClient =
					services.httpTransport
						? std::make_unique<OfficialHttpClient>( services.httpTransport())
						: std::make_unique<OfficialHttpClient>( false) ;	// 公式規約だけの低位HTTPです
				termsError = adapter_.recheckApprovedTerms(
					preparation, task, context_, services.utc, *termsClient, cancellation) ;
			}

			// 別の規約・期限や回線を拒否し、ローカル検査や転送へ分岐しません
			if( termsError != 0U) {
				item.acquisition	  = OfficialAcquisitionState::REJECTED ;
				item.acquisitionError = termsError ;
				preparationSummary_.items.push_back( item) ;
				return {OfficialPreparationItemState::REJECTED, termsError, 0U} ;
			}
		}
	}

	// 原TRANSFERのowned fileだけを直接参照します。local→localの連鎖を作りません
	for( std::size_t sourceIndex = 0U; !inspectWix && sourceIndex < binding_.records_.size();
		++sourceIndex) {
		const auto &source = binding_.records_[sourceIndex] ;	// 原owned recordです
		// 同配布tupleの原所有があれば通信へfallbackせず、新承認の独立検査へ進みます
		if( !source.ownedBodyRecordIndex && adapter_.matchesRetainedBody( task, source.task)) {
			return inspectRetainedBody( preparation, task, sourceIndex, services, cancellation) ;
		}
	}

	const auto utcClock = [&services]() -> std::uint64_t {
		const auto now = services.utc() ;	// 信頼時計の再照会。失敗では0です
		return now && now->time_since_epoch().count() > 0
				   ? static_cast<std::uint64_t>( now->time_since_epoch().count())
				   : 0U ;
	} ; // 同期呼出し中だけworker固定serviceを借用します
	SignedIndexCandidateBindingSession::PreparedRecord record ;	// 元権限と閉包をmove所有します
	record.lookup		 = acquisitionLookup_ ;
	record.context		 = context_ ;
	record.task			 = task ;
	const auto reference = std::find_if( binding_.references_.begin(), binding_.references_.end(),
										[&task]( const auto &value) {
											return value.target == task.target ;
										}) ; // 元同targetへの私有対応
	// 取得検査専用の既存fixtureから参照なしの候補を発行しません
	record.referenceIndex =
		reference == binding_.references_.end()
			? binding_.references_.size()
			: static_cast<std::size_t>( reference - binding_.references_.begin()) ;
	auto &grant = record.grant ;	// 同active taskから一回だけ発行する既存grant
								// UI専用objectだけで元claim後・grant発行前の同期観測を行います
#if defined( DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER) && defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
	// 同workerが登録したnoexcept観測だけへ同期中の実所有者を貸します
	if( approvedIndexTaskObserver != nullptr) {
		approvedIndexTaskObserver( approvedIndexTaskObserverState, preparation, task, adapter_,
								  context_, utcClock(), *this) ;
	}
#endif
	const auto grantError =
		// 一回grant
		adapter_.claimApprovedRecord( preparation, task, context_, utcClock(), grant) ;
	// 改変・再使用・期限切れ・別issuerでは取得を開始しません
	if( grantError != 0U) {
		// 拒否した当該taskの結果だけを残し、未処理owner/issuerを失効させません
		item.acquisition	  = OfficialAcquisitionState::REJECTED ;
		item.acquisitionError = grantError ;
		preparationSummary_.items.push_back( item) ;
		return {OfficialPreparationItemState::REJECTED, grantError, 0U} ;
	}

	// 同scanだけの保護領域と成功byte累積ledgerを最初の選択時に一度作ります
	if( !workspace_ || !acquisition_) {
		auto workspace	 = std::make_unique<OfficialDownloadWorkspace>() ;	// 初期化失敗時の自動回収
		auto acquisition = std::make_unique<OfficialAcquisitionSession>() ;	// 同scanの累積ledger
		NativeError error =
			// 保護領域のみ
			workspace->initialize( L"signed-index", task.scanSessionId) ;
		// 元計画と同じ上限で取得ledgerを開始し、Provider別と全scan枠を維持します
		if( error == 0U) {
			error = acquisition->initialize(
				task.scanSessionId, {limits_.maximumFileBytes, limits_.maximumProviderBytes,
									 limits_.maximumSessionBytes, 256ULL * 1024ULL * 1024ULL,
									 limits_.maximumProviderFiles, limits_.maximumSessionFiles}) ;
		}

		// 保護領域不成立を一般Tempや未保護fileへfallbackしません
		if( error != 0U) {
			item.acquisition	  = OfficialAcquisitionState::FAILURE ;
			item.acquisitionError = error ;
			preparationSummary_.items.push_back( item) ;
			return {OfficialPreparationItemState::FAILURE, error, 0U} ;
		}

		workspace_	 = std::move( workspace) ;
		acquisition_ = std::move( acquisition) ;
	}

	// 元ページのない取得は従来どおり同taskからgrantを発行した後で依存を準備します
	if( !inspectWix) {
		client = makeClient() ;
		cost   = readCost() ;
	}

	OfficialHttpAcquisitionTransport transport{*client} ;	// 同grantの共通HTTP validatorを通ります
	// 不完全な内部依存から製品回線境界へ縮退しません
	if( !cost) {
		item.acquisition	  = OfficialAcquisitionState::FAILURE ;
		item.acquisitionError = static_cast<NativeError>( E_UNEXPECTED) ;
		preparationSummary_.items.push_back( item) ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_UNEXPECTED), 0U} ;
	}

	const auto relationIndex =
		// 私有grantが封印した元関係です
		grant.metadata().recordEvidenceId - 1U ;
	// 表示IDや外部tupleから形式や保存pathを組み立てません
	if( relationIndex >= acquisitionLookup_->relations().size()) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_ACCESSDENIED),
				0U} ;
	}

	const auto &snapshot = acquisitionLookup_->snapshot() ;	// 同元認証索引です
	const auto	distributionIndex =
		// 元配布の位置です
		acquisitionLookup_->relations()[relationIndex].recordIndex ;
	const auto &distribution =
		// 同じ署名済み元配布です
		snapshot.consumerRecords()[distributionIndex] ;
	const auto payloadFormat =
		distribution.acquisitionDescriptor->format ;	// 元方式へcodec結合済みです
	const auto extension = payloadFormat == IndexPayloadFormat::CABINET ? L".cab"
						   : (payloadFormat == IndexPayloadFormat::WINDOWS_EXE ||
							  payloadFormat == IndexPayloadFormat::WIX_BURN_V3 ||
							  payloadFormat == IndexPayloadFormat::SEVEN_ZIP_SFX ||
							  payloadFormat == IndexPayloadFormat::PE_RESOURCE_CONTAINER)
							   ? L".exe"
						   : payloadFormat == IndexPayloadFormat::WINDOWS_MSI
							   ? L".msi"
							   : L".zip" ;	// 固定四形式だけです
	const auto fileName	 = L"index-payload-" + std::to_wstring( nextOwnedPayloadOrdinal_++) +
						  extension ;	// 元wireのfilenameではなく保護所有者の不透明名です
	// 同一保護領域の各対象でCREATE_NEW用相対名を一意にします
	const OfficialAcquisitionRequest request{.workspaceFileName = fileName,
											 .restrictedNetworkApproved =
												 task.restrictedNetworkApproved,
											 .delegatedGrant   = &grant,
											 .delegatedGrantId = grant.metadata().grantId,
											 .delegatedUtcNow  = utcClock} ;
	auto	  &acquired		 = record.acquisition ;	// 実path/hashを元私有recordへ保持します
	const auto dispatchError = adapter_.revalidateHostForAcquisition(
		task, context_, services.utc()) ;	// 実通信へ渡す最後の原host確認です
	// claim後の変化/観測失敗はpayloadを呼ばず新scanへ送ります
	if( dispatchError != 0) {
		item.acquisition	  = OfficialAcquisitionState::REJECTED ;
		item.acquisitionError = dispatchError ;
		preparationSummary_.items.push_back( item) ;
		return {OfficialPreparationItemState::REJECTED, dispatchError, 0U} ;
	}

	const auto acquireError = acquisition_->acquire(
		request, *workspace_, transport, *cost, []( std::uint64_t, std::uint64_t) {},
		transferCancellation,
		acquired) ;	// 同期転送中は確定件数を増やしません
	item.acquisition	  = acquired.state ;
	item.acquisitionError = acquireError ;
	item.auxiliaryHttp	  = acquired.auxiliaryHttp ;
	// 元応答が指定した待機は転送成否と独立に同workerで保持します
	if( inspectWix) {
		rememberWixPayloadWait( wixHosts, acquired.payloadRetry) ;
		// 次の送信前に原待機で中断した場合は指定された元理由を返します
		if( wixWaitError != 0U) {
			item.acquisition	  = OfficialAcquisitionState::REJECTED ;
			item.acquisitionError = wixWaitError ;
			preparationSummary_.items.push_back( item) ;
			return {OfficialPreparationItemState::REJECTED, wixWaitError, 0U} ;
		}

		// ページ照合の後に回線状態が変わればその操作の回線同意へ戻します
		if( acquired.state == OfficialAcquisitionState::AWAITING_NETWORK_CONSENT) {
			preparationSummary_.items.push_back( item) ;
			return {OfficialPreparationItemState::AWAITING_NETWORK_CONSENT, acquireError, 0U} ;
		}
	}

	// 成功取得だけを元sealと実byte内容検査へ進めます
	if( acquireError == 0U) {
		auto &evidence = record.seal ;	// 公開取得DTOから作れない実seal
		item.contentError =
			acquisition_->bindAcquiredFile( *workspace_, acquired.acquisitionId, evidence) ;
		auto &hint	= record.hint ;		// 原record/descriptorへ結合する実byte期待値
		auto &input = record.input ;	// 元保護archiveを所有者の寿命に結合します
		// 取得seal成立時だけ同task／同issuerの元recordへ再照合します
		if( item.contentError == 0U) {
			item.contentError = adapter_.bindInspectionInput(
				task, context_, utcClock(), *acquisition_, *workspace_, evidence, hint, input) ;
		}

		// 旧境界でも取得中に端末条件が変わった元バイトを検査入力へ進めません
		if( !inspectWix && item.contentError == 0U) {
			item.contentError =
				adapter_.reobservePreparedDevice( distribution, task.target, context_) ;
		}

		auto &inspected = record.inspection ;	// 内容・CATの個別拒否と保護閉包を所有します
		// WiXは元封印を同梱規約とドライバーの専用内容検査へ渡します
		if( inspectWix) {
			const auto byteCount =
				acquired.byteCount ;	// 転送の成功と実byte数は内容診断から分離します
			// ファイル照合中に時計が逆行するか元期限に達した場合は検査入力として保持しません
			if( item.contentError == 0U) {
				const auto now = services.utc() ;	// 原ファイルと現在の機器を照合した後の信頼時計です
				std::string reason ;				// 署名索引の原拒否理由は外部の結果に載せません
				item.contentError = checkWixPayloadWait( wixHosts, now) ;
				// 同じ配布の待機と時計が成立した場合だけ元期限と承認を再確認します
				if( item.contentError == 0U) {
					item.contentError = adapter_.validateBinding( *approved, context_, now, reason) ;
				}
			}

			// 元ファイル・機器・期限がそろう場合だけ内容を検査します
			if( item.contentError == 0U) {
				const auto termsExpiry = std::min(
					{snapshot.schemaReceipt().assetBytes().manifest().data().expiresAtUtc,
					 snapshot.consumerRecordRegion( distributionIndex).expiresAtUtc,
					 distribution.acquisitionDescriptor->attestation
						 ->validUntilUtc}) ;	// 同じ元manifest、領域、元取得確認の最短期限です
				inspectBoundWix( distribution, termsExpiry, record, item, services,
								transferCancellation) ;
				// 時計逆行や配布元の待機による停止は、利用者の取消しと区別します
				if( wixWaitError != 0U && item.content == IndexedDriverInspectionState::CANCELLED) {
					item.contentError = wixWaitError ;
					item.content	  = IndexedDriverInspectionState::INSPECTION_FAILED ;
				}
			} else {
				item.content = IndexedDriverInspectionState::INPUT_REJECTED ;
			}

			preparationSummary_.items.push_back( item) ;
			return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0U, byteCount} ;
		}

		// 同消費済みgrantと実ledgerを結合し、DTOから権限を生成しません
		if( item.contentError == 0U &&
		   *distribution.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			item.contentError = SignedIndexCandidateBindingSession::bindDelegatedInput(
				acquired, grant, hint, payloadFormat, record.delegated) ;
		}

		// 実byteと元record結合が成立した対象だけ通常policyで内容検査します
		if( item.contentError == 0U &&
		   *distribution.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			item.contentError = inspectBoundArchive(
				distribution,
				payloadFormat == IndexPayloadFormat::CABINET ? OfficialDriverArchiveFormat::CABINET
				: payloadFormat == IndexPayloadFormat::PE_RESOURCE_CONTAINER
					? OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER
				: payloadFormat == IndexPayloadFormat::SEVEN_ZIP_SFX
					? OfficialDriverArchiveFormat::SEVEN_ZIP_SFX
					: OfficialDriverArchiveFormat::ZIP,
				record, cancellation) ;
		} else {
			inspected.state = IndexedDriverInspectionState::INPUT_REJECTED ;
			inspected.error = item.contentError ;
		}

		// EXE/MSIは展開せず、同seal/原hash/publisherを専用署名境界へ結びます
		if( *distribution.acquisition.value == IndexAcquisitionKind::OFFICIAL_INSTALLER) {
			record.installerHandoff = true ;
			record.msi				= payloadFormat == IndexPayloadFormat::WINDOWS_MSI ;
			record.publisher =
				// 元grantの厳密UTF-8変換済み期待値です
				grant.payloadView().publisher ;
			// 原byteと同recordの結合前に署名処理を実行しません
			if( item.contentError == 0U) {
				const std::array<std::wstring_view, 1U> publishers{
					record.publisher} ;	// 元exact publisherだけです
				item.contentError = verifyAuthenticodePublisher( input.inspectionPath, publishers) ;
			}

			record.installerError = item.contentError ;
			inspected.state		  = item.contentError == 0U
										? IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED
										: IndexedDriverInspectionState::INSPECTION_FAILED ;
			inspected.error		  = item.contentError ;
			inspected.inputBound  = item.contentError == 0U ;
		}

		// 検査済み閉包を次の候補処理まで保持する操作の診断値
		const auto retainError = retainInspection( record, item) ;
		// 閉包を保持できないときは候補を導入へ引き継がず、個別の理由を残します
		if( retainError != 0U) {
			item.contentError = retainError ;
		}

		binding_.records_.push_back( std::move( record)) ;
	}

	preparationSummary_.items.push_back( std::move( item)) ;
	// 内容失敗後も取得成功は取得成功のまま保持し、UIで独立した失敗を表示します
	return {acquireError == 0U ? OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION
			: acquired.state == OfficialAcquisitionState::CANCELLED
				? OfficialPreparationItemState::CANCELLED
			: acquired.state == OfficialAcquisitionState::REJECTED
				? OfficialPreparationItemState::REJECTED
				: OfficialPreparationItemState::FAILURE,
			acquireError, acquired.byteCount} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元WiXの内容を検査し、規約とドライバー閉包を同じprivate recordにだけ保持します
 * @param[in] original 同じ元取得に結んだ認証済みv8レコードです
 * @param[in] termsExpiry 同じ元索引と取得証拠から決まる最短の規約閲覧期限です
 * @param[in,out] record 元sealと入力を所有します。成功時は保持枠と共にworkerへ所有を移します
 * @param[in,out] item 元取得とは独立した検査結果です。内容が成立した場合だけ件数を設定します
 * @param[in] services 元期限を最後に照合するworkerの依存です
 * @param[in] cancellation 同取得の停止・時刻再照会です
 * @pre 入力sealと元機器を同操作で再照合済みです
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::inspectBoundWix(
	const IndexDistributionRecord &original, const std::chrono::sys_seconds termsExpiry,
	SignedIndexCandidateBindingSession::PreparedRecord &record, IndexPreparationItemSummary &item,
	const provider_worker_index_detail::Services &services,
	const PreparationCancellation				 &cancellation)
{
	constexpr auto CANCELLED_ERROR =
		// 同操作の明示中止です
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	item.inputBound	  = true ;
	item.content	  = IndexedDriverInspectionState::INSPECTION_FAILED ;
	item.contentError = static_cast<NativeError>( E_ACCESSDENIED) ;
	// 元Windowsの観測が無い場合、別の機器やOSに向けた内容を保持しません
	if( !host_ || !host_->observation.value) {
		return ;
	}

	auto verified = std::make_shared<
		OfficialWixDriverContent>() ;	// 同じ保護領域を端末内容と共有できる所有者です
	std::uint64_t retainedBytes{} ;		// 署名照合済みの規約・MSI・閉包に実際に保持する容量です
	item.contentError = inspectSignedIndexWixContent(
		original, record.input, *host_->observation.value, cancellation, *verified, retainedBytes) ;
	// 内容検査で一つでも不一致があれば、元規約や部分照合を保持しません
	if( item.contentError != 0U) {
		// 取消しによる停止を内容不正と区別します
		if( item.contentError == CANCELLED_ERROR) {
			item.content = IndexedDriverInspectionState::CANCELLED ;
		}

		return ;
	}

	std::vector<WixTermsDocument> documents ;	// 解釈できた全言語だけを画面へ渡します
	const auto termsError = readSignedIndexWixTerms( original, *verified, cancellation,
													documents) ;	// 内容検査と独立した表示可否です

	// 同じ元機器と全規約に結びつく場合、保持中のINFを別の端末ポリシーで検査します
	if( termsError == 0U && record.referenceIndex < binding_.references_.size() &&
	   (!cancellation || !cancellation())) {
		const std::shared_ptr<OfficialDownloadWorkspace> driverWorkspace{
			verified, verified->driverWorkspace.get()} ;	// 元保護領域を別領域へ複写しません
		CommonInfInspection storage ;						// 端末用の再検査を通った同じINFとCATです
		record.inspection.error = inspectRetainedStorageInf(
			record.task.scanSessionId, driverWorkspace, verified->closure, storage) ;
		// 端末用ポリシーに通った場合だけ元取得と同じ閉包の検査結果を保持します
		if( record.inspection.error == 0U) {
			auto &inspection =
				record.inspection.inspection ;	// 後続のWindows適合性が参照する私有内容です
			inspection.scanSessionId	  = record.task.scanSessionId ;
			inspection.archiveSha256	  = record.input.sha256 ;
			inspection.archiveBytes		  = record.input.byteCount ;
			inspection.inventoryFileCount = storage.closure.entries.size() ;
			inspection.retainedBytes	  = storage.closure.expandedBytes ;
			inspection.infs.push_back( std::move( storage)) ;
		}
	}

	// 規約を開ける証拠を保持する直前に、同じ元期限と実機器を再照合します
	const auto now	  = services.utc() ;	// 規約と端末用の読み取り後の同じ信頼UTCです
	item.contentError = adapter_.revalidateHostForAcquisition( record.task, context_, now) ;
	// 元端末・期限が変わった場合は保持容量にも加算しません
	if( item.contentError != 0U) {
		return ;
	}

	// 内容検査中に取消しが届いた場合、合格済みの規約と閉包も保持しません
	if( cancellation && cancellation()) {
		item.contentError = CANCELLED_ERROR ;
		item.content	  = IndexedDriverInspectionState::CANCELLED ;
		return ;
	}

	auto nextRetainedBytes = binding_.retainedBytes_ ;	// 所有権の確定までは旧使用量を変更しません
	// 既存の同scan保持上限を使い、超過した場合は一時領域を破棄します
	if( !tryRetainIndexedInspectionBytes( retainedBytes, nextRetainedBytes)) {
		item.contentError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		return ;
	}

	const auto fileCount =
		// 合格したINFと全参照の実ファイル数です
		verified->closure.entries.size() ;
	const auto infCount =
		// 共通署名と元レコードに一致したINFだけです
		verified->closure.packages.size() ;
	// 期限内に全言語を確認した場合だけ本文を一つの閲覧用通知へ結びます
	if( termsError == 0U && now && *now < termsExpiry) {
		item.wixTerms = std::make_shared<const WixTermsPresentation>(
			WixTermsPresentation{*now, termsExpiry, std::move( documents)}) ;
		record.wixTerms = item.wixTerms ;
	}

	record.wixInspection		 = std::move( verified) ;
	record.inspection.state		 = IndexedDriverInspectionState::INSPECTION_COMPLETED ;
	record.inspection.inputBound = true ;
	binding_.records_.push_back( std::move( record)) ;
	binding_.retainedBytes_ = nextRetainedBytes ;
	item.content			= IndexedDriverInspectionState::INSPECTION_COMPLETED ;
	item.inventoryFileCount = fileCount ;
	item.infCount			= infCount ;
	item.parsedInfCount		= infCount ;
	item.acceptedInfCount	= infCount ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元承認に結んだファイルを、選択したレコードの内容契約で検査します
 * @param[in] original 同スキャンで認証した元レコードです
 * @param[in] format 同取得物の元archive形式です
 * @param[in,out] record ファイルsealと同じ元入力および出力の所有者です
 * @param[in] cancellation 同操作の取消しです
 * @return 内容を保持できた場合0、拒否又は取消しで元HRESULT、保持領域の確保失敗はE_OUTOFMEMORYです
 * @note DMの結果は導入用の通常閉包へ変換しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexScanSession::inspectBoundArchive(
	const IndexDistributionRecord &original, const OfficialDriverArchiveFormat format,
	SignedIndexCandidateBindingSession::PreparedRecord &record,
	const PreparationCancellation					   &cancellation)
{
	OfficialMappedFile archive ;	// 規約検査からINF検査の終了まで同じZIPの差し替えを防ぎます
	// ZIP規約を要求する元行だけに、同じ保護ファイルで原規約を検査します
	if( original.acquisitionDescriptor && original.acquisitionDescriptor->terms.archiveNotice) {
		const auto &notice =
			*original.acquisitionDescriptor->terms.archiveNotice ;	// 署名済みの元ZIPと規約指定です
		NativeError noticeError = E_ACCESSDENIED ;					// 別形式や別サイズに規約検査を流用しません
		// 封印済みZIPのサイズが元証拠と一致する場合だけ、ファイルを固定します
		if( format == OfficialDriverArchiveFormat::ZIP &&
		   record.hint.archiveBytes == notice.archiveSizeBytes) {
			noticeError = cancellation && cancellation()
							  ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
							  : archive.open( record.input.inspectionPath, notice.archiveSizeBytes) ;
		}

		// ファイルを固定してから、取得sealに結んだ元SHA-256とサイズを照合します
		if( noticeError == 0U) {
			noticeError = verifyOfficialFileMetadata(
				record.input.inspectionPath, {notice.archiveSizeBytes, record.hint.archiveSha256}) ;
		}

		// 同じ固定ファイルの規約メンバーの原バイトと指定文を検査します
		if( noticeError == 0U) {
			constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// SHA-256の小文字16進表記です
			std::wstring				memberHash ;				// 固定長の規約メンバーの元SHA-256です
			memberHash.reserve( notice.memberSha256.size() * 2U) ;
			// 署名済みの各ハッシュバイトを二桁の小文字16進へ写します
			for( const auto byte : notice.memberSha256) {
				memberHash.push_back( HEX[byte >> 4U]) ;
				memberHash.push_back( HEX[byte & 15U]) ;
			}

			const std::wstring relativePath{notice.memberPath.begin(),
											// codecが検査済みのASCII相対名です
											notice.memberPath.end()} ;
			noticeError = verifyOfficialZipNotice( archive.bytes(), OFFICIAL_INF_ARCHIVE_POLICY,
												  {relativePath, notice.memberSizeBytes, memberHash,
												   notice.statementOffset, notice.statement}) ;
		}

		// 規約不一致を署名付きINFの検査成功へ読み替えません
		if( noticeError != 0U) {
			record.inspection.state =
				noticeError == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
					? IndexedDriverInspectionState::CANCELLED
					: IndexedDriverInspectionState::INPUT_REJECTED ;
			record.inspection.error = noticeError ;
			return noticeError ;
		}
	}

	// 従来のレコードは通常の導入用閉包を返します
	if( original.recordSchemaVersion != 6U) {
		return inspectIndexedDriverPackage( record.task.scanSessionId, record.hint, record.input,
										   format, record.inspection, cancellation) ;
	}

	CollectorDriverPackageContent scoped ;	// 選択元に結ぶ非導入内容だけです
	// 元の公式Models証拠があるCABには専用照合を使い、選択した配布物の内容検査の診断を保持します
	auto error = original.scopedModelsEvidence && format == OfficialDriverArchiveFormat::CABINET
					 ? inspectIndexedScopedDriverPackage(
						   record.task.scanSessionId, record.hint, record.input,
						   *original.scopedModelsEvidence, scoped, cancellation)
					 : static_cast<NativeError>( E_ACCESSDENIED) ;
	// 元検査の成功時だけ読み取り専用で保持し、確保失敗を内容完了にしません
	if( error == 0U) {
		try {
			record.scopedInspection =
				std::make_shared<const CollectorDriverPackageContent>( std::move( scoped)) ;
		} catch( const std::bad_alloc &) {
			error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		}
	}

	record.inspection.error		 = error ;
	record.inspection.inputBound = error == 0U ;
	record.inspection.state =
		error == 0U ? IndexedDriverInspectionState::INSPECTION_COMPLETED
		: error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
			? IndexedDriverInspectionState::CANCELLED
			: IndexedDriverInspectionState::INSPECTION_FAILED ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 棚卸しと元の個別拒否を表示用に数え、閉包の保持枠を適用します
 * @param[in,out] record 同承認taskの検査所有者です。保持枠失敗では閉包を解放します
 * @param[in,out] item このtaskに返す内容の集計です
 * @return 枠内なら0、超過ならERROR_FILE_TOO_LARGEのHRESULTです
 */
//------------------------------------------------------------------------------
NativeError SignedIndexScanSession::retainInspection(
	SignedIndexCandidateBindingSession::PreparedRecord &record, IndexPreparationItemSummary &item)
{
	// 選択した検査経路が保持する閉包のバイト数
	const auto retained = record.scopedInspection ? record.scopedInspection->retainedBytes
												  : record.inspection.inspection.retainedBytes ;
	// 閉包を保持するための同一操作の容量枠を超えた候補は受け付けません
	if( !tryRetainIndexedInspectionBytes( retained, binding_.retainedBytes_)) {
		// 表示と取得結果の両方に残す元の容量拒否
		const auto error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		record.scopedInspection.reset() ;
		record.inspection.inspection = {} ;
		record.inspection.state		 = IndexedDriverInspectionState::INSPECTION_FAILED ;
		record.inspection.error		 = error ;
		item.content				 = record.inspection.state ;
		item.inputBound				 = record.inspection.inputBound ;
		return error ;
	}

	item.content	 = record.inspection.state ;
	item.inputBound	 = record.inspection.inputBound ;
	const auto count = [&]( const auto &content) {
		item.inventoryFileCount = content.inventoryFileCount ;
		item.infCount			= content.infs.size() ;
		// 閉包の全INFを数え、検証を通過したINFだけを合格件数へ加えます
		for( const auto &inf : content.infs) {
			item.acceptedInfCount += inf.state == CommonInfInspectionState::VERIFIED ? 1U : 0U ;
			item.signatureRejectedInfCount +=
				inf.state == CommonInfInspectionState::SIGNATURE_REJECTED ? 1U : 0U ;
			item.parsedInfCount += inf.state == CommonInfInspectionState::SIGNATURE_REJECTED ||
										   inf.state == CommonInfInspectionState::VERIFIED
									   ? 1U
									   : 0U ;
			// 元の最初の拒否だけを保持します
			if( item.firstInfRejection == 0U && inf.error != 0U) {
				item.firstInfRejection = inf.error ;
			}
		}
	} ;
	// 実際に選んだ公式Models経路の検査結果を通常経路と重複させず集計します
	if( record.scopedInspection) {
		count( *record.scopedInspection) ;
	} else {
		count( record.inspection.inspection) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元owned bodyを新active taskで非通信再検査します
 * @param[in,out] preparation 当該active taskの所有者です
 * @param[in] task 新しい明示承認taskです
 * @param[in] sourceIndex 元TRANSFER recordの安定indexです
 * @param[in] services 元時計です。通信は呼びません
 * @param[in] cancellation 同検査の取消しです
 * @return 実検査の終端と当該local照合票です。取得成功は再発行しません
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult SignedIndexScanSession::inspectRetainedBody(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const std::size_t sourceIndex, const provider_worker_index_detail::Services &services,
	const PreparationCancellation &cancellation)
{
	IndexPreparationItemSummary item{.targetIdentity =
										 task.target.identity} ;		// 取得を再発行しません
	NativeError error	= static_cast<NativeError>( E_ACCESSDENIED) ;	// 原拒否を保持します
	const auto	binding = std::ranges::find(
		 adapter_.bindings_, task.target,
		 &SignedIndexAcquisitionAdapter::PreparedBinding::target) ;	// 新Bの元targetです
	const auto reference = std::ranges::find(
		binding_.references_, task.target,
		&SignedIndexCandidateBindingSession::Reference::target) ;		// Bの元参照をclaim前に確認します
	const auto now	   = services.utc ? services.utc() : std::nullopt ;	// A/B共通の原時計です
	const auto seconds = now && now->time_since_epoch().count() > 0
							 ? static_cast<std::uint64_t>( now->time_since_epoch().count())
							 : 0U ;	// 信頼UTC秒です
	// 現在承認と原ownerがなければhash/pathだけで許可しません
	if( preparation.ownsActiveTask( task) && sourceIndex < binding_.records_.size() &&
	   binding != adapter_.bindings_.end() && !binding->claimedTask &&
	   reference != binding_.references_.end() &&
	   !binding_.records_[sourceIndex].ownedBodyRecordIndex && acquisition_ && workspace_ &&
	   adapter_.matchesRetainedBody( task, binding_.records_[sourceIndex].task)) {
		error = binding_.reverifyRecordBinding( *this, binding_.records_[sourceIndex], services) ;
		// A成功でBの全共有record/期限/ownerを省略せず、observer/LOCALより先に確認します
		if( error == 0U) {
			std::string reason ;	// 原Bの純粋binding診断です
			error = adapter_.validateBinding( *binding, context_, now, reason) ;
		}

		// 新LOCAL claimでも指定された元規約を同じ実行計画で再確認する
		if( error == 0U) {
			const auto &original =
				acquisitionLookup_->snapshot()
					.consumerRecords()[acquisitionLookup_->relations()[binding->relationIndex]
										   .recordIndex] ;	// 新Bの認証済み元行です
			// 別操作又は旧計画の規約照合で、再利用に対する同意を代用しません
			if( SignedIndexAcquisitionAdapter::requiresApprovedTermsRecheck(
				   original.acquisitionDescriptor->terms) &&
			   (binding->recheckedTermsOperation != task.operationId ||
				binding->recheckedTermsPlan != task.planId ||
				binding->recheckedTermsOperation == 0U)) {
				error = E_ACCESSDENIED ;
			}
		}

		// Bの全参照ordinalもclaim前に検証します
		if( error == 0U) {
			const auto &relations = acquisitionLookup_->relations() ;	// 同元lookupだけです
			const auto &originals =
				// 原署名です
				acquisitionLookup_->snapshot().consumerRecords() ;
			std::set<std::wstring> devices ;	// 当該target全deviceです
			// 新Bの全参照をLOCAL claim前に確認します
			for( const auto &value : binding_.references_) {
				// 別targetの関係をBの確認へ混ぜません
				if( value.target != task.target) {
					continue ;
				}

				// 代表/有限集合/deviceの不足を新claim前に拒否します
				if( value.relationIndices.empty() ||
				   value.relationIndices.front() != value.relationIndex ||
				   value.relationIndices.size() > originals.size() ||
				   value.hint.deviceIdentity != value.candidate.deviceIdentity) {
					error = static_cast<NativeError>( E_ACCESSDENIED) ;
					break ;
				}

				std::set<std::size_t> ordinals ;	// 同relationの重複を拒否します
				// Bの全元ordinalを独立に照合します
				for( const auto ordinal : value.relationIndices) {
					// 同位置の重複又は範囲外を先に拒否します
					if( ordinal >= relations.size() || !ordinals.insert( ordinal).second) {
						error = static_cast<NativeError>( E_ACCESSDENIED) ;
						break ;
					}

					const auto &relation = relations[ordinal] ;	// 範囲照合後の元位置です
					// 元scan/record/source/hash/device以外をBへ補完しません
					if( relation.recordIndex >= originals.size() || relation.context != context_ ||
					   !relation.deviceIdentity ||
					   *relation.deviceIdentity != value.hint.deviceIdentity ||
					   relation.recordId != originals[relation.recordIndex].recordId ||
					   relation.sourceId != originals[relation.recordIndex].sourceId ||
					   relation.recordSha256 != originals[relation.recordIndex].recordSha256) {
						error = static_cast<NativeError>( E_ACCESSDENIED) ;
						break ;
					}
				}

				devices.insert( value.hint.deviceIdentity) ;
			}

			// 原承認のdevice数が不足又は過大なら止めます
			if( devices.empty() || devices.size() > 32U ||
			   devices.size() != task.target.deviceCount) {
				error = static_cast<NativeError>( E_ACCESSDENIED) ;
			}
		}
	}

	// Bの型番と現在の群をAの取得結果から補完せず、LOCALのclaim前に再観測します
	if( error == 0U) {
		const auto &record =
			acquisitionLookup_->snapshot()
				.consumerRecords()[acquisitionLookup_->relations()[binding->relationIndex]
									   .recordIndex] ;	// 新対象Bの元行です
		error = adapter_.reobservePreparedDevice( record, task.target, context_) ;
	}

	SignedIndexCandidateBindingSession::PreparedRecord
		record ;	// Bの新しい実検査結果だけを所有します
	// 原TRANSFERの期限/所有/実byte成立後だけ、新しいLOCAL taskを一回claimします
	if( error == 0U) {
		// 失敗後も原Bへ結ぶ完全な記録だけを保持し、空PreparedRecordをappendしません
		record.lookup				= acquisitionLookup_ ;
		record.context				= context_ ;
		record.task					= task ;
		record.ownedBodyRecordIndex = sourceIndex ;
		record.referenceIndex  = static_cast<std::size_t>( reference - binding_.references_.begin()) ;
		record.localInspection = preparation.claimIndexLocalInspection( task) ;
		// 他用途の既claimや別active taskを拒否します
		if( !record.localInspection) {
			error = static_cast<NativeError>( E_ACCESSDENIED) ;
		}
	}

	// 元grant/report/token/sealをBへ複写しません
	if( error == 0U) {
		record.lookup					= acquisitionLookup_ ;
		record.context					= context_ ;
		record.task						= task ;
		record.ownedBodyRecordIndex		= sourceIndex ;
		binding->claimedTask			= task ;
		binding->localInspectionClaimed = true ;
		const auto &source = binding_.records_[sourceIndex] ;	// 原ownerを借用し移動しません
		const auto &original =
			acquisitionLookup_->snapshot()
				.consumerRecords()[acquisitionLookup_->relations()[binding->relationIndex]
									   .recordIndex] ;	// 全B境界検証済みです
		// DMは後続の再利用入力確定でBの同原hostを再確認します
		if( original.recordSchemaVersion != 6U && requiresBoundIndexHost( original)) {
			error = adapter_.reobserveHost( context_) ;
		}

		// host拒否から新しいB hint/inputを発行しません
		if( error == 0U) {
			error = adapter_.bindRetainedInspectionInput(
				task, source.task, context_, seconds, *acquisition_, *workspace_, source.seal,
				*record.localInspection, record.hint, record.input) ;
		}

		// bind後の元期限/全参照/実byteも純粋に再確認し、観測を重複消費しません
		if( error == 0U) {
			error = binding_.reverifyRecordBinding( *this, record, services) ;
		}

		// 配布物を再利用するBの元承認と実バイトに結び、現在の機種と群を確認します
		if( error == 0U) {
			error = adapter_.reobservePreparedDevice( original, task.target, context_) ;
		}

		// 新対象の原selectorへ実INF/CATを独立検査します。Aの合格を流用しません
		if( error == 0U) {
			error = inspectBoundArchive( original, source.delegated.format, record, cancellation) ;
		} else {
			record.inspection.state = IndexedDriverInspectionState::INPUT_REJECTED ;
			record.inspection.error = error ;
		}

		item.reusedOwnedBody = true ;
		// 再検査した閉包の同一操作での保持結果
		const auto retainError = retainInspection( record, item) ;
		// 再検査に成功していても保持枠を確保できない場合は導入可能として扱いません
		if( retainError != 0U) {
			error = retainError ;
		}
	}

	item.contentError = error ;
	// 入力未成立を未開始成功や再取得成功へ変えません
	if( !item.reusedOwnedBody) {
		item.acquisition	  = OfficialAcquisitionState::REJECTED ;
		item.acquisitionError = error ;
		item.contentError	  = 0U ;
	}

	const auto local = record.localInspection ;	// 同active claimの照合票だけを結果へ結びます
	// 原recordは安定indexで保持し、原Aのownerを消費routeと一緒に消しません
	if( record.localInspection && record.lookup && record.ownedBodyRecordIndex &&
	   record.referenceIndex < binding_.references_.size()) {
		binding_.records_.push_back( std::move( record)) ;
	}

	preparationSummary_.items.push_back( std::move( item)) ;
	return error == 0U ? OfficialPreparationTransferResult{OfficialPreparationItemState::
															   LOCAL_INSPECTION_COMPLETED,
														   0U, 0U, local}
					   : OfficialPreparationTransferResult{OfficialPreparationItemState::REJECTED,
														   error, 0U} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元計画と今回の操作へ非機密結果だけを複写します
 * @param[in] operationId 実取得operation。0では計画summaryです
 * @return 同scan／planと有限個別結果。秘密所有を含みません
 */
//------------------------------------------------------------------------------
IndexPreparationSummary SignedIndexScanSession::preparationSummary(
	const OperationId operationId) const
{
	auto summary		= preparationSummary_ ;	// 非機密の確定snapshotだけを複写します
	summary.operationId = operationId ;
	return summary ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原metadataだけで残planを検証し当該summaryを開始します
 * @param[in,out] plan 原tuple/予算のsubsetです。失効対象だけを除きます
 * @param[in] services 元信頼時計です。HTTPは呼びません
 * @return 原context/新ID/予算が整合した場合trueです
 */
//------------------------------------------------------------------------------
bool SignedIndexScanSession::retainPreparationPlan(
	OfficialPreparationPlan &plan, const provider_worker_index_detail::Services &services)
{
	// 原索引ownerなしで索引targetを新たに追加しません
	if( !acquisitionLookup_) {
		return std::ranges::none_of( plan.targets, []( const auto &target) {
			return target.providerId == SIGNED_INDEX_PROVIDER_ID ;
		}) ;
	}

	// 原予算/scanと新しいplan IDだけを使います
	if( plan.scanSessionId != context_.scanSessionId || plan.planId <= preparationSummary_.planId ||
	   plan.limits != limits_) {
		return false ;
	}

	const auto now = services.utc ? services.utc() : std::nullopt ;	// 原時計です
	std::erase_if( plan.targets, [&]( const auto &target) {
		// 他Providerの原記述はこのadapterで変更しません
		if( target.providerId != SIGNED_INDEX_PROVIDER_ID) {
			return false ;
		}

		const auto	binding = std::ranges::find_if( adapter_.bindings_, [&]( const auto &entry) {
			 return entry.target == target ;
		 }) ;				// 元targetです
		std::string reason ;	// 非公開診断です
		return binding == adapter_.bindings_.end() || binding->claimedTask ||
			   adapter_.validateBinding( *binding, context_, now, reason) != 0U ;
	}) ;
	preparationSummary_.planId = plan.planId ;
	preparationSummary_.items.clear() ;
	preparationSummary_.plannedTargets = static_cast<std::uint64_t>(
		std::ranges::count( plan.targets, std::wstring{SIGNED_INDEX_PROVIDER_ID},
						   &OfficialPreparationTarget::providerId)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Adapterの取得能力とissuer leaseを失効し、確定結果と内容所有を保持します
 * @note 新しいgrantと未使用grantの使用を拒否し、snapshot、lookup、取得ledger、workspace、summary、検査閉包は解放しません。同期callbackの
 *       借用を破壊しません
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::invalidateAcquisition() noexcept
{
	adapter_.invalidate() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新取得だけを閉鎖し、同期限内の消費済み元根拠を導入終端まで保持します
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::closeAcquisitionForInstall() noexcept
{
	adapter_.closeAcquisitionForInstall() ;
}
} // namespace drivercrate
