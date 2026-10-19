//------------------------------------------------------------------------------
/**
 * @file inf_dependency_plan.cpp
 * @brief 同節Include／Needsの有限解決核と確認計画の実装。
 * @version 01.00.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  有限依存核・曖昧／循環・snapshot再確認を追加。
 * </pre>
 *
 * @note loaderの証拠を独立に保持し、実byte取得・署名・実device導入を直接行わない。
 * @see docs/adr/0269-bounded-inf-dependency-core-and-review-plan.md
 */
//------------------------------------------------------------------------------

#include "inf_dependency_plan.h"

#include <Windows.h>

#include <algorithm>
#include <new>
#include <utility>

namespace drivercrate {
namespace {

constexpr std::size_t MAX_DOCUMENTS	 = 64U ;	// 一runのINF snapshot数上限。
constexpr std::size_t MAX_SECTIONS	 = 1024U ;	// 未発見を含む節照会上限。
constexpr std::size_t MAX_REFERENCES = 4096U ;	// 全節の累積参照数と出力辺数上限。
constexpr std::size_t MAX_DEPTH		 = 32U ;	// C++再帰の最大段数。
constexpr std::size_t MAX_NAME		 = 254U ;	// 明示名の最大文字数。

/** @brief Windows ordinal規則で有限節名を比較する。
 * @param[in] left 有限な一名称。
 * @param[in] right 有限な一名称。
 * @return 大小文字を除いて一致する場合true。
 */
bool				  sameName( std::wstring_view left, std::wstring_view right)
{
	return left.size() <= MAX_NAME && right.size() <= MAX_NAME &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 証拠enumの未知値を拒否する。
 * @param[in] value 調べる証拠軸。
 * @return 三既知値のいずれかならtrue。
 */
bool validEvidence( InfDependencyEvidence value)
{
	return value == InfDependencyEvidence::NOT_CHECKED ||
		   value == InfDependencyEvidence::VERIFIED || value == InfDependencyEvidence::FAILED ;
}

/** @brief OSと観測世代を完全一致させる。
 * @param[in] left 開始文脈。
 * @param[in] right 候補文脈。
 * @return 全field一致ならtrue。
 */
bool sameContext( const InfDependencyContext &left, const InfDependencyContext &right)
{
	return left.major == right.major && left.minor == right.minor && left.build == right.build &&
		   left.machine == right.machine && left.windowsServer == right.windowsServer &&
		   left.observationId == right.observationId ;
}

/** @brief 一documentの形を検査する。検査済み状態へ昇格しない。
 * @param[in] document 有限なsnapshot。
 * @return 全必須fieldが有効ならtrue。
 */
bool validDocument( const InfDependencyDocument &document)
{
	return document.identity != 0U && document.byteCount > 0U &&
		   document.byteCount <= 4U * 1024U * 1024U && document.sha256.size() == 64U &&
		   std::ranges::all_of( document.sha256,
							   []( wchar_t value) {
								   // 小文字hexだけを原hashの表現として受理する。
								   return (value >= L'0' && value <= L'9') ||
										  (value >= L'a' && value <= L'f') ;
							   }) &&
		   (document.origin == InfDependencyOrigin::PACKAGE ||
			document.origin == InfDependencyOrigin::SYSTEM) &&
		   validEvidence( document.byteBinding) && validEvidence( document.provenance) &&
		   validEvidence( document.signature) ;
}

/** @brief 同identityの証拠差替えを検出する。
 * @param[in] left 保存済みsnapshot。
 * @param[in] right 再取得snapshot。
 * @return 全byte／証拠／文脈が一致ならtrue。
 */
bool sameDocument( const InfDependencyDocument &left, const InfDependencyDocument &right)
{
	return left.identity == right.identity && left.sha256 == right.sha256 &&
		   left.byteCount == right.byteCount && left.origin == right.origin &&
		   left.byteBinding == right.byteBinding && left.provenance == right.provenance &&
		   left.signature == right.signature && sameContext( left.context, right.context) ;
}

/** @brief 一明示名の長さと制御文字等を検査する。
 * @param[in] name worker内だけの一名称。
 * @return 境界に適合する場合true。
 */
bool validSectionName( std::wstring_view name)
{
	return !name.empty() && name.size() <= MAX_NAME && name.front() != L' ' &&
		   name.back() != L' ' && std::ranges::none_of( name, []( wchar_t value) {
			   // section名からpath・多値・制御文字への切替えを許可しない。
			   return value < L' ' || value == 0x7f ||
					  std::wstring_view( L"[]\\/,:\"").find( value) != std::wstring_view::npos ;
		   }) ;
}

/** @brief Includeの安全な相対INF名だけを受理する。
 * @param[in] name 原相対名称。
 * @return 親移動・絶対path・予約文字を含まないINF名ならtrue。
 */
bool validIncludeName( std::wstring_view name)
{
	// 長さと拡張子の不正からpath検索へ進ませない。
	if( name.size() < 5U || name.size() > MAX_NAME ||
	   !sameName( name.substr( name.size() - 4U), L".inf")) {
		return false ;
	}

	std::size_t begin{} ;	// 各相対componentの開始位置。
	// 有限な全componentを確認し、途中の親移動も拒否する。
	while( begin < name.size()) {
		const std::size_t		end	 = name.find_first_of( L"\\/", begin) ;	// 次の相対component境界。
		const std::wstring_view part = name.substr(
			begin, end == std::wstring_view::npos ? end : end - begin) ;	// 借用component。
		// 空component、親移動、末尾正規化、任意検索文字を許可しない。
		if( part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
		   part.back() == L' ' || std::ranges::any_of( part, []( wchar_t value) {
			   // loaderのpath解決前に制御・予約・環境展開文字を拒否する。
			   return value < L' ' || value == 0x7f ||
					  std::wstring_view( L":<>|\"?*%").find( value) != std::wstring_view::npos ;
		   })) {
			return false ;
		}

		// 最後のcomponentを検証した時点で完了する。
		if( end == std::wstring_view::npos) {
			return true ;
		}

		begin = end + 1U ;
	}

	return false ;
}

/** @brief 三証拠が全て確認済みかを調べる。
 * @param[in] document 独立証拠を持つsnapshot。
 * @return 全軸VERIFIEDならtrue。device適用性は表さない。
 */
bool verifiedDocument( const InfDependencyDocument &document)
{
	return document.byteBinding == InfDependencyEvidence::VERIFIED &&
		   document.provenance == InfDependencyEvidence::VERIFIED &&
		   document.signature == InfDependencyEvidence::VERIFIED ;
}

/** @brief 同期runの有限cacheと非実行結果を所有する。 */
class DependencyResolver {
public:
	/** @brief loaderと開始文脈を同期借用する。
	 * @param[in] operations 呼出し完了まで有効なloader。
	 * @param[in] context rootと全候補を結合する文脈。
	 */
	DependencyResolver( const InfDependencyOperations &operations,
					   const InfDependencyContext	 &context)
		: operations_( operations)
	{
		result_.context = context ;
	}

	/** @brief seedを観測し全snapshot再確認後にだけ結果を移す。
	 * @param[in] root 開始snapshot。
	 * @param[in] seeds 明示開始節。
	 * @param[out] result 全成功後だけ保持する結果。
	 * @return 成功0、最初の拒否HRESULT。
	 */
	NativeError run( const InfDependencyDocument &root, std::span<const std::wstring> seeds,
					InfDependencyResult &result)
	{
		std::size_t rootIndex{} ;							// 一意rootの保存位置。
		NativeError error = addDocument( root, rootIndex) ;	// rootも同じsnapshot規則へ結合する。
		// 全seedを順に確認し、重複・共有はcacheで再走査を止める。
		for( const auto &seed : seeds) {
			// 先行する失敗の部分値を結果へ移さない。
			if( error != 0) {
				return error ;
			}

			bool cycle{} ;	// seedでは通常falseで、再帰辺だけが循環を注釈する。
			error = walk( rootIndex, seed, 1U, cycle) ;
		}

		// 全発見snapshotを再確認し、照会後の改変・OS差を止める。
		for( const auto &document : result_.documents) {
			// 観測失敗または一つの再確認失敗でも全体を破棄する。
			if( error != 0) {
				return error ;
			}

			error = operations_.recheck( document) ;
		}

		// 最後のcallbackの失敗も成功結果へ変換しない。
		if( error != 0) {
			return error ;
		}

		result_.plan.referencesResolved =
			sourcesPresent_ && std::ranges::all_of( result_.edges, []( const auto &edge) {
				// 明示辺の解決だけを集計し、存在・未検査を含めない。
				return edge.state == InfDependencyState::RESOLVED_PACKAGE ||
					   edge.state == InfDependencyState::RESOLVED_SYSTEM ;
			}) ;
		result_.plan.rootEvidenceVerified = verifiedDocument( result_.documents[rootIndex]) ;
		// rootと参照資料の役割だけを保存し、追加導入や実行順序を作らない。
		for( const auto &document : result_.documents) {
			result_.plan.entries.push_back(
				{document.identity, document.identity == result_.documents[rootIndex].identity}) ;
		}

		result = std::move( result_) ;
		return 0 ;
	}

private:
	/** @brief 一照会節と再帰状態のcache。 */
	struct CachedSection {
		/// result.sectionsと同じ位置のdocument保存index。
		std::size_t			 documentIndex{} ;
		/// 原名の有限snapshot。read callbackの再呼出しを防ぐ。
		InfDependencySection snapshot ;
		/// 0は照会のみ、1は再帰中、2は走査完了。
		unsigned int		 phase{} ;
	} ;
	/// 呼出し中だけ有効な同期loader。
	const InfDependencyOperations &operations_ ;
	/// 全成功前の非公開結果。
	InfDependencyResult			   result_ ;
	/// result.sectionsに一対一対応する有限cache。
	std::vector<CachedSection>	   cache_ ;
	/// 全snapshotで累積した参照数。最大4,096。
	std::size_t					   observedReferences_{} ;
	/// 走査すべきseed／再帰元が全てPRESENTの場合true。
	bool						   sourcesPresent_{true} ;

	/** @brief candidateを一意identityとOS文脈へ結合する。
	 * @param[in] document 観測snapshot。
	 * @param[out] index 成功時の保存位置。
	 * @return 成功0、不正・OS差・差替え・容量のHRESULT。
	 */
	NativeError addDocument( const InfDependencyDocument &document, std::size_t &index)
	{
		// 不正hash・証拠・由来を単なる未検査へ弱めない。
		if( !validDocument( document)) {
			return E_INVALIDARG ;
		}

		// 他OSや別観測世代のsystem充足を持ち込ませない。
		if( !sameContext( result_.context, document.context)) {
			return HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		// 同identityの再発見を保存済みの全証拠へ結合する。
		for( std::size_t position = 0U; position < result_.documents.size(); ++position) {
			// 名称や同hashだけで別documentを同一化しない。
			if( result_.documents[position].identity == document.identity) {
				// 同identityの内容・証拠変更は全体拒否する。
				if( !sameDocument( result_.documents[position], document)) {
					return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
				}

				index = position ;
				return 0 ;
			}
		}

		// 一runのINF数を無制限に広げない。
		if( result_.documents.size() >= MAX_DOCUMENTS) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		index = result_.documents.size() ;
		result_.documents.push_back( document) ;
		return 0 ;
	}

	/** @brief 明示節を一度だけ照会し有限snapshotへ固定する。
	 * @param[in] documentIndex 保存済みdocument位置。
	 * @param[in] section 安全な明示節。
	 * @param[out] index 成功時のcache位置。
	 * @return 成功0、callback・容量・応答不正のHRESULT。
	 */
	NativeError read( std::size_t documentIndex, std::wstring_view section, std::size_t &index)
	{
		// 同document／節の共有照会をcacheへ戻す。
		for( std::size_t position = 0U; position < cache_.size(); ++position) {
			// Windows ordinalの大小文字だけを同一節として扱う。
			if( cache_[position].documentIndex == documentIndex &&
			   sameName( result_.sections[position].section, section)) {
				index = position ;
				return 0 ;
			}
		}

		// 候補の未発見も有限節予算へ含める。
		if( cache_.size() >= MAX_SECTIONS) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		InfDependencySection snapshot ;	// 一callbackの局所結果。
		const NativeError error = operations_.readSection( result_.documents[documentIndex], section,
														  snapshot) ;	// 明示名だけ。
		// callback失敗の部分snapshotを保持しない。
		if( error != 0) {
			return error ;
		}

		// 未知段階と未検査／未発見に付いた参照集合は不正応答とする。
		if( (snapshot.state != InfDependencyReadState::NOT_CHECKED &&
			snapshot.state != InfDependencyReadState::MISSING &&
			snapshot.state != InfDependencyReadState::PRESENT) ||
		   (snapshot.state != InfDependencyReadState::PRESENT && !snapshot.references.empty())) {
			return E_INVALIDARG ;
		}

		// 個別と累積の両参照予算を超えた結果を切り捨てない。
		if( snapshot.references.size() > MAX_REFERENCES - observedReferences_) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 既知参照enumだけを受理し、過長名称の複製を止める。
		for( auto &reference : snapshot.references) {
			// 未知directiveをNeedsとして解釈しない。
			if( reference.directive != InfDependencyDirective::INCLUDE &&
			   reference.directive != InfDependencyDirective::NEEDS) {
				return E_INVALIDARG ;
			}

			// 過長名は空のINVALID_REFERENCE辺に残し、本文を複製しない。
			if( reference.target.size() > MAX_NAME) {
				reference.target.clear() ;
			}
		}

		observedReferences_ += snapshot.references.size() ;
		index = cache_.size() ;
		result_.sections.push_back(
			{result_.documents[documentIndex].identity, std::wstring( section), snapshot.state}) ;
		cache_.push_back( {documentIndex, std::move( snapshot), 0U}) ;
		return 0 ;
	}

	/** @brief 一意候補の独立証拠を辺へ注釈する。
	 * @param[in,out] edge 元参照の結果。
	 * @param[in] document 対象snapshot。
	 */
	void bindEdge( InfDependencyEdge &edge, const InfDependencyDocument &document)
	{
		edge.targetIdentity = document.identity ;
		// 存在だけでは署名・由来未確認を解決済みへ昇格しない。
		if( !verifiedDocument( document)) {
			edge.state	= InfDependencyState::OBSERVED ;
			edge.reason = InfDependencyReason::EVIDENCE_INCOMPLETE ;
			return ;
		}

		edge.state	= document.origin == InfDependencyOrigin::PACKAGE
						  ? InfDependencyState::RESOLVED_PACKAGE
						  : InfDependencyState::RESOLVED_SYSTEM ;
		edge.reason = InfDependencyReason::NONE ;
	}

	/** @brief 同節Includeを全照会して一意性と証拠を保持する。
	 * @param[in] source 元snapshot。
	 * @param[in,out] edge 原Include辺。
	 * @param[out] indexes 発見候補のdocument位置。
	 * @param[out] checked 照会済みならtrue。
	 * @return 成功0、callback・応答・容量のHRESULT。
	 */
	NativeError include( const InfDependencyDocument &source, InfDependencyEdge &edge,
						std::vector<std::size_t> &indexes, bool &checked)
	{
		InfDependencyLookup lookup ;	// このIncludeだけの有限照会結果。
		const NativeError	error =
			// 表示名からpathを合成しない。
			operations_.lookup( source, edge.target, lookup) ;
		// callback拒否を未発見へ変換しない。
		if( error != 0) {
			return error ;
		}

		// 未検査の部分候補と一照会の過大集合を拒否する。
		if( (!lookup.checked && !lookup.documents.empty()) ||
		   lookup.documents.size() > MAX_DOCUMENTS) {
			return E_INVALIDARG ;
		}

		checked = lookup.checked ;
		// 一照会の候補重複をloader不正として拒否する。
		for( const auto &document : lookup.documents) {
			std::size_t		  index{} ;	// 全結果内の保存位置。
			const NativeError added =
				// 同identityの差替えも検査する。
				addDocument( document, index) ;
			// 一候補だけの失敗でも部分graphを返さない。
			if( added != 0) {
				return added ;
			}

			// 同じ実documentを別候補として水増ししない。
			if( std::ranges::find( indexes, index) != indexes.end()) {
				return E_INVALIDARG ;
			}

			indexes.push_back( index) ;
		}

		edge.candidateCount = indexes.size() ;
		// 一意であっても三証拠を独立に確認する。
		if( indexes.size() == 1U) {
			bindEdge( edge, result_.documents[indexes.front()]) ;
		} else {
			edge.state = checked ? InfDependencyState::UNRESOLVED : InfDependencyState::NOT_CHECKED ;
			edge.reason = !checked ? InfDependencyReason::NOT_CHECKED
								   : (indexes.empty() ? InfDependencyReason::MISSING
													  : InfDependencyReason::AMBIGUOUS) ;
		}

		return 0 ;
	}

	/** @brief 明示節を有限再帰で走査し、共有と循環を分離する。
	 * @param[in] documentIndex 保存document位置。
	 * @param[in] section 明示節。
	 * @param[in] depth 1～32の再帰段数。
	 * @param[out] cycle 再帰中の同じ節ならtrue。
	 * @return 成功0、callback・容量のHRESULT。
	 */
	NativeError walk( std::size_t documentIndex, std::wstring_view section, std::size_t depth,
					 bool &cycle)
	{
		cycle = false ;
		// 有限再帰を超えた観測を部分成功にしない。
		if( depth > MAX_DEPTH) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::size_t position{} ;										// 元節cacheの安定した位置。
		NativeError error = read( documentIndex, section, position) ;	// 一度だけの明示照会。
		// 読取失敗のgraphを処理しない。
		if( error != 0) {
			return error ;
		}

		// 再帰中と走査完了を区別して循環辺を保持する。
		if( cache_[position].phase != 0U) {
			cycle = cache_[position].phase == 1U ;
			return 0 ;
		}

		cache_[position].phase = 1U ;
		// 未検査／未発見のseedを空の完全graphへ昇格しない。
		if( cache_[position].snapshot.state != InfDependencyReadState::PRESENT) {
			sourcesPresent_		   = false ;
			cache_[position].phase = 2U ;
			return 0 ;
		}

		const InfDependencyDocument source =
			result_.documents[documentIndex] ;							// vector拡張から独立した同期借用元。
		const std::wstring sourceSection( section) ;					// 再帰によるvector再配置から独立した原節。
		const auto references = cache_[position].snapshot.references ;	// 最大4,096の局所所有参照。
		std::vector<std::vector<std::size_t>> included(
			// 各Includeの候補を同じ元節だけで保持する。
			references.size()) ;
		std::vector<bool> checked( references.size(), false) ;	// 各Include照会の完了状態。
		std::vector<InfDependencyEdge> edges ;					// 元順序を維持する局所辺。
		// 同節の全Includeを先に照会し、Needsの前後順に依存させない。
		for( std::size_t ordinal = 0U; ordinal < references.size(); ++ordinal) {
			const auto		 &reference = references[ordinal] ;	// 一明示参照の同期借用。
			InfDependencyEdge edge{source.identity, sourceSection, reference.target,
								   reference.directive} ;	// 初期未検査辺。
			const bool		  valid = reference.directive == InfDependencyDirective::INCLUDE
										  ? validIncludeName( reference.target)
										  : validSectionName( reference.target) ;	// 原名の境界。
			// 不正名は辺へ残すが、loaderのpath／節探索へ渡さない。
			if( !valid) {
				edge.state	= InfDependencyState::INVALID_REFERENCE ;
				edge.reason = InfDependencyReason::INVALID_NAME ;
			}
			// 正当なIncludeだけを同節の候補照会へ進める。
			else if( reference.directive == InfDependencyDirective::INCLUDE) {
				bool done{} ;	// vector<bool>のproxyをcallbackへ渡さない。
				error			 = include( source, edge, included[ordinal], done) ;
				checked[ordinal] = done ;
				// 一つの照会不正でも部分結果を破棄する。
				if( error != 0) {
					return error ;
				}
			}

			edges.push_back( std::move( edge)) ;
		}

		// 全原辺を順序通り保存し、Needsだけを一意候補へ再帰する。
		for( std::size_t ordinal = 0U; ordinal < edges.size(); ++ordinal) {
			InfDependencyEdge		 edge = edges[ordinal] ;	// 再帰の出力vectorから独立する辺。
			std::vector<std::size_t> matches ;					// 明示Needsを含む異なるdocument候補。
			bool					 unknown{} ;				// 未照会またはbyte未結合候補を隠さない。
			// Includeと不正名はNeeds節として再解釈しない。
			if( edge.directive == InfDependencyDirective::NEEDS &&
			   edge.state != InfDependencyState::INVALID_REFERENCE) {
				std::vector<std::size_t> candidates{documentIndex} ;	// 同INFの明示節も独立に調べる。
				// 同じ元節のIncludeだけから候補を集める。
				for( std::size_t item = 0U; item < references.size(); ++item) {
					// 他のNeedsをIncludeへ読み替えない。
					if( references[item].directive != InfDependencyDirective::INCLUDE) {
						continue ;
					}

					unknown = unknown || !checked[item] ||
							  edges[item].state == InfDependencyState::INVALID_REFERENCE ;
					// 共有Include先は同じ一候補として節を調べる。
					for( const auto candidate : included[item]) {
						// 異なるidentityを同hashだけで合併しない。
						if( std::ranges::find( candidates, candidate) == candidates.end()) {
							candidates.push_back( candidate) ;
						}
					}
				}

				// byte結合した明示節だけを一度ずつ照会する。
				for( const auto candidate : candidates) {
					// byte未確認の候補を実存在や充足へ昇格しない。
					if( result_.documents[candidate].byteBinding !=
					   InfDependencyEvidence::VERIFIED) {
						unknown = true ;
						continue ;
					}

					std::size_t target{} ;	// 明示対象のcache位置。
					error = read( candidate, edge.target, target) ;
					// 一つの照会エラーを未発見で隠さない。
					if( error != 0) {
						return error ;
					}

					unknown = unknown ||
							  cache_[target].snapshot.state == InfDependencyReadState::NOT_CHECKED ;
					// PRESENTだけを節候補へ加え、MISSINGは別候補の一意性を妨げない。
					if( cache_[target].snapshot.state == InfDependencyReadState::PRESENT) {
						matches.push_back( candidate) ;
					}
				}

				edge.candidateCount = matches.size() ;
				// 複数の実在節から勝手に最初を選ばない。
				if( matches.size() > 1U) {
					edge.state	= InfDependencyState::UNRESOLVED ;
					edge.reason = InfDependencyReason::AMBIGUOUS ;
				}
				// 未照会候補が残る間は一意性を認定しない。
				else if( unknown) {
					edge.state	= InfDependencyState::NOT_CHECKED ;
					edge.reason = InfDependencyReason::NOT_CHECKED ;
				}
				// 全候補を照会した未発見と未検査を区別する。
				else if( matches.empty()) {
					edge.state	= InfDependencyState::UNRESOLVED ;
					edge.reason = InfDependencyReason::MISSING ;
				} else {
					bindEdge( edge, result_.documents[matches.front()]) ;
					bool recursiveCycle{} ;	// 共有はfalse、active節へ戻る辺だけtrue。
					error = walk( matches.front(), edge.target, depth + 1U, recursiveCycle) ;
					// 再帰容量・callback失敗の部分辺を返さない。
					if( error != 0) {
						return error ;
					}

					// 存在・署名が正当でも循環を全充足としない。
					if( recursiveCycle) {
						edge.state	= InfDependencyState::UNRESOLVED ;
						edge.reason = InfDependencyReason::CYCLE ;
					}
				}
			}

			// 重複辺を維持しつつ出力集合にも有限境界を適用する。
			if( result_.edges.size() >= MAX_REFERENCES) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			result_.edges.push_back( std::move( edge)) ;
		}

		cache_[position].phase = 2U ;
		return 0 ;
	}
} ;

} // namespace

/** @see src/platform/inf_dependency_plan.h 宣言側の契約を正本とする。 */
NativeError resolveInfDependencies( const InfDependencyDocument	 &root,
								   std::span<const std::wstring>  seeds,
								   const InfDependencyOperations &operations,
								   InfDependencyResult			 &result)
{
	result = {} ;
	try {
		// 実loaderの欠落、他architecture、観測世代未指定から解決済みを作らない。
		if( !operations.lookup || !operations.readSection || !operations.recheck ||
		   !validDocument( root) || root.context.major == 0U || root.context.build == 0U ||
		   root.context.machine != 0x8664U || root.context.observationId == 0U ||
		   root.byteBinding != InfDependencyEvidence::VERIFIED || seeds.empty() ||
		   seeds.size() > MAX_SECTIONS || std::ranges::any_of( seeds, []( const auto &seed) {
			   // loaderへ渡す開始節は事前に明示名境界へ結合する。
			   return !validSectionName( seed) ;
		   })) {
			return E_INVALIDARG ;
		}

		DependencyResolver resolver( operations, root.context) ;	// この同期runだけの有限所有者。
		return resolver.run( root, seeds, result) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

} // namespace drivercrate
