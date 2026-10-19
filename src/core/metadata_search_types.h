//------------------------------------------------------------------------------
/**
 * @file metadata_search_types.h
 * @brief 情報検索専用requestと非機密の実行結果。
 * @version 01.00.01
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  Metadata専用検索の契約を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  既定比較の引数と一致条件の契約を明記。
 * </pre>
 *
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

// 製品から選べる唯一のmetadata検索予算policy。
inline constexpr std::wstring_view METADATA_SEARCH_POLICY_ID = L"metadata-only-initial-20260911-v1" ;
// 固定policyの解釈を変える場合に更新するrevision。
inline constexpr std::uint32_t	   METADATA_SEARCH_POLICY_REVISION = 1U ;
// UIとworker間で保持できるregistry entryの安全上限。
inline constexpr std::size_t	   METADATA_SEARCH_PROVIDER_LIMIT = 64U ;

/** @brief 検索結果に付随する権限の種類。未知値は拒否する。 */
enum class ScanPurpose {
	/// 従来の候補検索。個別の監査・同意は別途必須。
	STANDARD,
	/// 配布情報の表示のみ。取得準備・導入を許可しない。
	METADATA_ONLY,
} ;

/** @brief 通常scanの取得同意を含まない、明示的な情報検索要求。 */
struct MetadataSearchRequest {
	/// 明示選択した重複なしのstable Provider ID。空集合は拒否。
	std::vector<std::wstring> enabledProviderIds ;
	/// 製品で固定した予算policyのID。
	std::wstring			  policyId{METADATA_SEARCH_POLICY_ID} ;
	/// Policy解釈のrevision。未知値を拒否。
	std::uint32_t			  policyRevision{METADATA_SEARCH_POLICY_REVISION} ;
	/// trueなら今回だけ制限・未知回線のmetadata通信を許可。
	bool					  restrictedNetworkApproved{} ;

	/**
	 * @brief 取得許可へ拡張せず要求snapshotを完全一致で比較する。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	bool					  operator==( const MetadataSearchRequest &other) const = default ;
} ;

/** @brief 未同意のまま表示する、別操作に必要な許諾条件。 */
enum class MetadataLicenseStatus {
	/// 条件を未確認であり、同意済みではない。
	UNRESOLVED,
	/// 別の取得操作で許諾全文の明示確認が必要。
	ACCEPTANCE_BEFORE_DOWNLOAD,
	/// Metadata上は取得前の同意不要。取得・導入の許可ではない。
	CONFIRMED_NO_CONSENT,
} ;

/** @brief 取得URLやpayload identityを含まない情報検索だけの表示値。 */
struct MetadataDistributionDetails {
	/// 明示配布版。現在INF版と比較せず、空は未知。
	std::wstring		  version ;
	/// Metadataが示す別操作の許諾条件。今回の同意を表さない。
	MetadataLicenseStatus license{MetadataLicenseStatus::UNRESOLVED} ;
} ;

/** @brief 検索と非実行の理由。成功件数と区別して報告する。 */
enum class MetadataSearchReason {
	/// 正常終端。候補なしも含む。
	COMPLETED,
	/// 利用者または終了要求による協調取消し。
	CANCELLED,
	/// 固定の本文またはrequest数予算を超過。
	BUDGET_EXCEEDED,
	/// Monotonic deadlineへ到達。
	DEADLINE_EXCEEDED,
	/// API、metadata、内部契約の失敗。
	FAILED,
	/// 今回のrequestで未選択。
	NOT_SELECTED,
	/// 実OSまたはlocal表示属性条件に対象なし。
	NOT_APPLICABLE,
	/// 制限・未知回線への今回の同意なし。
	NETWORK_NOT_APPROVED,
	/// 全体停止後のため未実施。
	NOT_RUN_AFTER_STOP,
} ;

/** @brief 成功resource数とは独立した、返却しない実消費量。 */
struct MetadataSearchUsage {
	/// 読み取った本文byte。失敗分とcache本文も含む。
	std::uint64_t bodyBytes{} ;
	/// 上限を判定するためだけに読み捨てた最大一byteのprobe累計。
	std::uint64_t probeBytes{} ;
	/// Cache利用を含む開始済みlogical resource数。
	std::uint32_t logicalResources{} ;
	/// Redirectを含むアプリによる明示HTTP送信試行数。
	std::uint32_t httpAttempts{} ;

	/**
	 * @brief 消費量のsnapshotを完全一致で比較する。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	bool		  operator==( const MetadataSearchUsage &other) const = default ;
} ;

/** @brief 一つのregistry entryの非機密な終了理由と消費量。 */
struct MetadataProviderSummary {
	/// Registryのstable ID。URLや端末識別子ではない。
	std::wstring		 providerId ;
	/// 当該Providerの終端または非実行の理由。
	MetadataSearchReason reason{MetadataSearchReason::NOT_SELECTED} ;
	/// 最初のnative診断値。成功時は0。
	std::int32_t		 error{} ;
	/// 当該Providerの実消費量。
	MetadataSearchUsage	 usage ;
} ;

/** @brief Metadata検索結果をoperation・requestへ拘束する非機密snapshot。 */
struct MetadataSearchSummary {
	/// UIが発行した非ゼロoperation ID。Worker公開直前に拘束。
	std::uint64_t						 operationId{} ;
	/// Workerが発行した非ゼロsession ID。
	std::uint64_t						 scanSessionId{} ;
	/// 実行した要求の所有copy。次runへ同意を継承しない。
	MetadataSearchRequest				 request ;
	/// 全体の主停止理由。最初の観測原因を維持。
	MetadataSearchReason				 reason{MetadataSearchReason::FAILED} ;
	/// Inventoryが全present nodeを表現できた場合true。
	bool								 inventoryComplete{} ;
	/// Inventoryを含むworker処理の経過millisecond。
	std::uint64_t						 elapsedMilliseconds{} ;
	/// 全Providerの累積消費量。
	MetadataSearchUsage					 usage ;
	/// 全registry entryの結果。未選択も省略しない。
	std::vector<MetadataProviderSummary> providers ;
} ;

} // namespace drivercrate
