//------------------------------------------------------------------------------
/**
 * @file candidate_source_group.cpp
 * @brief 同一版取得元候補group実装。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Versionやtitleを推測せず、Providerが返した明示版の完全一致だけを扱います。同一版でもpayloadとinstall routingは取得元ごとに分離します。
 */
//------------------------------------------------------------------------------

#include "core/candidate_source_group.h"

#include "core/candidate_selection.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 出力可否を確定する前の同一版候補群を表す。
 */
struct WorkingGroup {
	/// 完全一致するdevice opaque ID。
	std::wstring					 deviceIdentity ;
	/// Providerが明示した完全一致版。
	std::wstring					 version ;
	/// 全候補で一致する操作分類。
	DriverAction					 action{DriverAction::NONE} ;
	/// 元candidate vector内index群。
	std::vector<std::size_t>		 candidateIndexes ;
	/// 異なる取得元の検出集合。
	std::unordered_set<std::wstring> providerIds ;
	/// 同じProviderが同一keyを複数提示した場合true。
	bool							 ambiguousProvider{} ;
} ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_source_group.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::vector<CandidateSourceGroup>> groupEquivalentCandidateSources(
	const std::span<const UpdateCandidate>	  candidates,
	const std::span<const ProviderDescriptor> providers)
{
	// 取得元を照合できない構成では同一版groupを推測で生成しない。
	if( providers.empty()) {
		return std::nullopt ;
	}

	// Spanの有効期間内だけ参照するstable ID別Provider定義。
	std::unordered_map<std::wstring, const ProviderDescriptor *> providersById ;
	providersById.reserve( providers.size()) ;
	// 空または重複したProvider IDをgroup判定前に拒否する。
	for( const ProviderDescriptor &provider : providers) {
		// 空IDまたは重複したProvider定義により、取得元の区別が曖昧になる構成を拒否する。
		if( provider.id.empty() || !providersById.emplace( provider.id, &provider).second) {
			return std::nullopt ;
		}
	}

	std::unordered_set<std::wstring> candidateIdentities ;	// Candidate identity重複検出集合。
	candidateIdentities.reserve( candidates.size()) ;
	std::vector<WorkingGroup> workingGroups ;	// Key初出順を維持する一時group群。
	// 候補を先頭から全件照合し、device・操作・明示版が一致する集合へ一度ずつ登録する。
	for( std::size_t index = 0; index < candidates.size(); ++index) {
		const UpdateCandidate &candidate = candidates[index] ;				// 現在検証する候補。
		const auto provider = providersById.find( candidate.providerId) ;	// Provider照合結果。
		// 候補IDや取得元が不正なら、同一版groupを部分的に生成せず全体を拒否する。
		if( candidate.identity.empty() || candidate.deviceIdentity.empty() ||
		   candidate.providerId.empty() || !candidateIdentities.insert( candidate.identity).second ||
		   provider == providersById.end() ||
		   !isCandidateDefaultPreferenceValid( candidate, *provider->second)) {
			return std::nullopt ;
		}

		// 現在版や非導入候補、明示版のない候補を同一版の取得元比較へ混ぜない。
		if( candidate.current || !candidate.installable || candidate.version.empty() ||
		   candidate.action == DriverAction::NONE) {
			continue ;
		}

		const auto group = std::find_if(
			workingGroups.begin(), workingGroups.end(), [&candidate]( const WorkingGroup &value) {
				return value.deviceIdentity == candidate.deviceIdentity &&
					   value.version == candidate.version && value.action == candidate.action ;
			}) ; // 同一device、明示版、操作分類の既存group。
		// 同じdevice・操作・明示版の初出候補でgroupを作り、異なる版を混ぜない。
		if( group == workingGroups.end()) {
			WorkingGroup created{.deviceIdentity   = candidate.deviceIdentity,
								 .version		   = candidate.version,
								 .action		   = candidate.action,
								 .candidateIndexes = {index}} ;	// 初出候補group。
			created.providerIds.insert( candidate.providerId) ;
			workingGroups.push_back( std::move( created)) ;
			continue ;
		}

		group->candidateIndexes.push_back( index) ;
		// 同じProviderから複数候補が入るgroupは曖昧と記録し、任意の一件へ絞らない。
		if( !group->providerIds.insert( candidate.providerId).second) {
			group->ambiguousProvider = true ;
		}
	}

	std::vector<CandidateSourceGroup> result ;	// 利用者へ取得元選択を提示できる確定group群。
	// 初出順の一時groupから曖昧でない複数Provider groupだけを確定する。
	for( const WorkingGroup &group : workingGroups) {
		// 比較対象が一件だけ、またはProviderが一意でない集合には同一版groupを付けない。
		if( group.candidateIndexes.size() < 2 || group.ambiguousProvider) {
			continue ;
		}

		std::size_t preferred = group.candidateIndexes.front() ;	// 現在の既定取得元index。
		// Candidate別検証根拠が強い取得元を選び、同順位では初出順を維持する。
		for( const std::size_t candidateIndex : group.candidateIndexes) {
			const UpdateCandidate &candidate = candidates[candidateIndex] ;		// 比較対象候補。
			const UpdateCandidate &preferredCandidate = candidates[preferred] ;	// 現在の既定候補。
			// 同一版group内の初期取得元だけを根拠の優先順で更新し、他の候補行は残す。
			if( candidateDefaultPreferencePrecedes( candidate.defaultPreference,
												  preferredCandidate.defaultPreference)) {
				preferred = candidateIndex ;
			}
		}

		result.push_back(
			{.candidateIndexes = group.candidateIndexes, .preferredCandidateIndex = preferred}) ;
	}

	return result ;
}

} // namespace drivercrate
