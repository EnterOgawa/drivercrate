//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_storage.cpp
 * @brief Fresh根拠と同親handleへ切替準備の固定順保存を結合します。
 * @version 01.06.00
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  同親保持と固定保存roleの容量先払いを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  全raw再検査と固定準備prefix保存を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/02  新子69roleの全名検査と不足分実保存を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/02  実保存66像のcarryと専用初期ROOT保存を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/02  元head保持記録と二段親head保存を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * </pre>
 *
 * @note 初回ROOT有無ごとの実回復と不足保存を扱います。通常収集は未接続です。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_segment_storage.h"
#include "local_collector_segment_recovery.h"
#include "local_collector_projected_json.h"
#include "local_collector_shared_ledger.h"
#include "official_file_verifier.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <new>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
namespace drivercrate {
namespace {
using collector_projected_json::Reader ;	// 新子から読む全有限envelopeの字句検査です。
constexpr std::wstring_view INITIAL_ROOT_NAME =
	L"current/segment-history-root-v1.json" ;							// 専用history固定名です。
using collector_projected_json::Writer ;								// 元の有限UTF-8 canonical sinkです。
using collector_projected_json::Failure ;								// 字句とbyte上限を区別します。
using collector_projected_json::Status ;								// 第一数値へ固定変換します。
constexpr std::uint64_t STORE_LIMIT = 5ULL * 1024U * 1024U * 1024U ;	// 各storeの既存上限です。
constexpr std::size_t	ENTRY_LIMIT = 4096U ;							// Directoryごとの既存上限です。
constexpr std::size_t	RAW_LIMIT	= 2U * 1024U * 1024U ;				// 一保存の既存上限です。
/** @brief APIの第一数値を保持して内部unwindします。
 * @param[in] code 元API結果です。
 * @throws DWORD 成功以外の元codeです。
 */
void					io( const DWORD code)
{
	// 第一失敗を容量や形式へ変えません。
	if( code != ERROR_SUCCESS) {
		throw code ;
	}
}
/** @brief 必須関係を容量拒否と区別します。
 * @param[in] condition 必須関係です。
 * @throws DWORD 不成立の場合13です。
 */
void require( const bool condition)
{
	// 未検査値を保存予定の成功へ補完しません。
	if( !condition) {
		throw static_cast<DWORD>( ERROR_INVALID_DATA) ;
	}
}
/** @brief 元byteの実CNG指紋を作ります。
 * @param[in] body 保持しているcanonical本文です。
 * @return 元本文の完全小文字SHA-256です。
 * @throws DWORD 第一CNG codeです。
 */
std::wstring digest( const std::string_view body)
{
	std::wstring value ;	// 成功時だけの元指紋です。
	io( static_cast<DWORD>( computeCollectorMetadataSha256( body, value))) ;
	return value ;
}
/** @brief 既存shared envelopeと同じ固定byteへ包みます。
 * @param[in] body 型付きcodecで検査した本文です。
 * @return 最大2 MiBの保存予定rawです。
 * @throws Failure 字句／byte上限拒否です。
 * @throws DWORD 第一CNG codeです。
 */
std::string pack( const std::string_view body)
{
	Writer writer( RAW_LIMIT) ;	// 一保存の独立上限です。
	writer.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	writer.text( body) ;
	writer.append( ",\"sha256\":") ;
	writer.wideText( digest( body)) ;
	writer.append( "}") ;
	return writer.take() ;
}
/** @brief 実rawの固定envelopeとCNGを検査して本文を復号します。
 * @param[in] raw 保護handleから読んだ有限rawです。
 * @param[in] bodyLimit 用途固有の独立本文上限です。
 * @return 完全canonical一致した元本文です。
 * @throws Failure 字句／byte上限拒否です。
 * @throws DWORD 第一CNG codeまたは内容13です。
 */
std::string unpack( const std::string_view raw, const std::size_t bodyLimit)
{
	Reader reader( raw, RAW_LIMIT) ;	// 外側の固定順と型を検査します。
	reader.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	auto body = reader.text( bodyLimit) ;	// 用途の有限本文だけを所有します。
	reader.literal( ",\"sha256\":") ;
	const auto encodedHash = reader.text( 64U) ;	// 余分なhash文字を受理しません。
	reader.literal( "}") ;
	reader.finish() ;
	const auto hash = digest( body) ;	// 同じ実本文のCNGです。
	require( encodedHash.size() == 64U &&
			std::wstring( encodedHash.begin(), encodedHash.end()) == hash && pack( body) == raw) ;
	return body ;
}
/** @brief 固定ordinalだけを二桁小文字hexへ変換します。
 * @param[in] ordinal 0～65の検査済みordinalです。
 * @return 固定名の二文字断片です。
 */
std::wstring ordinalKey( const std::size_t ordinal)
{
	constexpr std::wstring_view digits = L"0123456789abcdef" ;	// 固定ASCII名です。
	return std::wstring{digits[ordinal / 16U], digits[ordinal % 16U]} ;
}
/** @brief 同じfresh検査の全元像から固定順roleを導出します。
 * @param[in] draft 同じ実検査から再導出した元draftです。
 * @param[in] evidence 同じ親／旧子／historyの元根拠です。
 * @return 最大90の非保存roleです。
 * @throws DWORD 第一codec／CNG結果や結合不成立です。
 * @throws Failure 字句／byte上限拒否です。
 */
std::vector<CollectorSegmentStorageRole> fixedRoles( const CollectorSegmentSwitchDraft  &draft,
													const CollectorSegmentRootEvidence &evidence)
{
	require( evidence.shards.size() == draft.intent.inventory.size() && !evidence.shards.empty() &&
			evidence.shards.size() <= 16U) ;
	CollectorSharedLedgerBytes bodies ;	// 元値を変更せず全66本文を再導出します。
	io( encodeCollectorSharedLedger( evidence.shared->evidence().snapshot, bodies)) ;
	std::vector<CollectorSegmentStorageRole> roles ;	// 保存順序の固定最大90件です。
	roles.reserve( 90U) ;
	roles.push_back( {CollectorSegmentStorageScope::PARENT,
					 L"runs/segment-switch-intent-" + draft.intentHash + L".json",
					 pack( draft.intentBytes)}) ;
	// 元ordinal順の全inventoryを旧子へ限定します。
	for( std::size_t i = 0U; i < evidence.shards.size(); ++i) {
		const auto &shard = evidence.shards[i] ;	// 同じsealへ結合する元本文です。
		require( digest( shard.body) == draft.intent.inventory[i]) ;
		roles.push_back(
			{CollectorSegmentStorageScope::OLD_SEGMENT,
			 L"runs/segment-inventory-" + draft.intentHash + L"-" + ordinalKey( i) + L".json",
			 pack( shard.body)}) ;
	}

	roles.push_back( {CollectorSegmentStorageScope::OLD_SEGMENT, L"current/segment-seal-v1.json",
					 pack( evidence.seal)}) ;
	Writer marker( 4096U) ;	// 元専用子markerと同じfield順です。
	marker.append( "{\"schema\":\"collector-segment-history-store-v1\",\"collection\":") ;
	marker.wideText( draft.intent.collection) ;
	marker.append( ",\"segment\":") ;
	marker.wideText( draft.intent.newSegment) ;
	marker.append( ",\"history\":\"history\"}") ;
	roles.push_back( {CollectorSegmentStorageScope::NEW_SEGMENT,
					 L"current/collector-campaign-mode-v1.json", marker.take()}) ;
	// 予算・group・全64 requestを省略せず元hashへ再結合します。
	for( std::size_t i = 0U; i < draft.images.size(); ++i) {
		const std::string_view body = i == 0U ? bodies.budget
									  : i == 1U
										  ? bodies.groups
										  : bodies.requests[i - 2U] ;	// 値や最高UTCを変えません。
		require( digest( body) == draft.images[i]) ;
		roles.push_back(
			{CollectorSegmentStorageScope::NEW_SEGMENT,
			 L"runs/segment-switch-image-" + draft.intentHash + L"-" + ordinalKey( i) + L".json",
			 pack( body)}) ;
	}

	roles.push_back( {CollectorSegmentStorageScope::NEW_SEGMENT,
					 L"current/segment-shared-base-v1.json", pack( draft.base)}) ;
	roles.push_back( {CollectorSegmentStorageScope::NEW_SEGMENT,
					 L"runs/segment-switch-bootstrap-" + draft.intentHash + L".json",
					 pack( draft.bootstrap)}) ;
	Writer registered( 16U * 1024U) ;	// 旧headと次headを元intentへ一方向に結合します。
	registered.append( "{\"schema\":\"collector-segment-switch-registered-v1\",\"collection\":") ;
	registered.wideText( draft.intent.collection) ;
	registered.append( ",\"oldHead\":") ;
	registered.wideText( draft.intent.oldHead) ;
	registered.append( ",\"intent\":") ;
	registered.wideText( draft.intentHash) ;
	registered.append( ",\"nextHead\":") ;
	registered.wideText( draft.intent.nextHead) ;
	registered.append( "}") ;
	roles.push_back( {CollectorSegmentStorageScope::PARENT, L"current/collection-head-v1.json",
					 pack( registered.take())}) ;
	roles.push_back( {CollectorSegmentStorageScope::PARENT, L"current/collection-head-v1.json",
					 pack( draft.nextHead)}) ;
	return roles ;
}
/** @brief 実usageをfresh全raw集合へ再結合します。
 * @param[in] evidence 同じ呼出しの全名・全raw集合です。
 * @param[in] usage 親／旧子の同handle実usageです。
 * @throws DWORD 件数・byte／scopeの不一致13です。
 */
void checkUsage( const CollectorSegmentRootEvidence		  &evidence,
				const std::array<CollectorStoreUsage, 2U> &usage)
{
	std::array<CollectorStoreUsage, 2U> expected{} ;	// Historyは保存対象に含めません。
	// Fresh読取りで確定した親／旧子の全fileだけを数えます。
	for( const auto &file : evidence.files) {
		// Historyは非変更であり別storeへ容量を流用しません。
		if( file.scope == L"history") {
			continue ;
		}

		require( file.scope == L"parent" || file.scope == L"segment") ;
		auto &target = expected[file.scope == L"parent" ? 0U : 1U] ;	// 元scopeの独立実量です。
		require( file.name.starts_with( L"current/") || file.name.starts_with( L"runs/")) ;
		target.bytes += file.bytes ;
		target.currentEntries += file.name.starts_with( L"current/") ? 1U : 0U ;
		target.runEntries += file.name.starts_with( L"runs/") ? 1U : 0U ;
	}

	// Stagingや余分な名をfresh元集合の保存量として見逃しません。
	for( std::size_t i = 0U; i < usage.size(); ++i) {
		require( expected[i].bytes == usage[i].bytes &&
				expected[i].currentEntries == usage[i].currentEntries &&
				expected[i].runEntries == usage[i].runEntries) ;
	}
}
/** @brief 新子作成前までの固定準備role数を確認します。
 * @param[in] roles 元予約が所有する固定順roleです。
 * @param[in] draft 同じ元予約の非循環draftです。
 * @return Intent、全inventory、seal準備の件数です。
 * @throws DWORD 元固定関係の不一致13です。
 */
std::size_t preparationCount( const std::span<const CollectorSegmentStorageRole> roles,
							 const CollectorSegmentSwitchDraft				   &draft)
{
	const auto count = draft.intent.inventory.size() + 2U ;	// 最大18保存だけを認めます。
	require( count >= 3U && count <= 18U && roles.size() > count &&
			roles[0].scope == CollectorSegmentStorageScope::PARENT &&
			roles[count].scope == CollectorSegmentStorageScope::NEW_SEGMENT) ;
	// 親intentの後は旧子準備だけで、新子や親headへ書き込みません。
	for( std::size_t i = 1U; i < count; ++i) {
		require( roles[i].scope == CollectorSegmentStorageScope::OLD_SEGMENT) ;
	}

	return count ;
}
/** @brief 元全rawと保存済みの連続準備prefixを同じ保護handleで再照合します。
 * @param[in] evidence 元fresh readerの全名／実size／raw hashです。
 * @param[in] roles 元予約の全固定roleです。
 * @param[in] count 新子作成前の最大18role数です。
 * @param[in,out] stores 私有保存借用中の親／旧子／historyです。
 * @param[in] activation 指定時だけ許す元head保持記録です。通常はnullです。
 * @param[in] alternateHead 指定時だけ許す元／登録／最終headの検査済みrawです。
 * @param[in] headPrefix 元二headの保存済み件数0～2です。activation指定時だけ使います。
 * @return 全検査できた連続物理prefix件数です。
 * @throws DWORD 第一I/O／CNG、容量68、集合／byte矛盾13です。
 */
std::size_t verifyPreparation( const CollectorSegmentRootEvidence				&evidence,
							  const std::span<const CollectorSegmentStorageRole> roles,
							  const std::size_t									 count,
							  const std::array<LocalCollectorStateStore *, 3U>	&stores,
							  const CollectorSegmentStorageRole *activation	   = nullptr,
							  const std::string_view			 alternateHead = {},
							  const std::size_t					 headPrefix	   = 0U)
{
	require( headPrefix <= 2U && (!activation || !alternateHead.empty())) ;
	std::array<std::set<std::wstring>, 3U> names ;			// 三scopeを混ぜず全固定相対名を保持します。
	std::array<CollectorStoreUsage, 3U>	   expected{} ;		// 元fileと準備prefixだけの実量です。
	std::uint64_t sharedRemaining  = 16U * 1024U * 1024U ;	// 親／旧子共有の既存raw枠です。
	std::uint64_t historyRemaining = 64U * 1024U * 1024U ;	// Historyの既存raw枠です。
	// 元全fileをfreshに再読し、欠損や未知scopeを保存予定で補完しません。
	for( const auto &file : evidence.files) {
		require( file.scope == L"parent" || file.scope == L"segment" || file.scope == L"history") ;
		const std::size_t scope = file.scope == L"parent"	 ? 0U
								  : file.scope == L"segment" ? 1U
															 : 2U ;	// 固定三scopeです。
		require( names[scope].insert( file.name).second) ;
		std::string raw ;		// 同じ保護handleから読む現在byteです。
		bool		found{} ;	// 元fileの欠損は拒否します。
		auto	   &remaining =
			// 元由来の独立読取り枠です。
			scope == 2U ? historyRemaining : sharedRemaining ;
		io( stores[scope]->read( file.name, raw, found, remaining)) ;
		// 親head専用入口で事前検査した置換だけを許し、他の元rawは変更しません。
		if( activation && scope == 0U && file.name == L"current/collection-head-v1.json") {
			require( found && raw == alternateHead) ;
		} else {
			require( found && raw.size() == file.bytes && digest( raw) == file.sha256) ;
		}

		expected[scope].bytes += raw.size() ;
		expected[scope].currentEntries += file.name.starts_with( L"current/") ? 1U : 0U ;
		expected[scope].runEntries += file.name.starts_with( L"runs/") ? 1U : 0U ;
	}

	std::uint64_t preparedRemaining = 18U * RAW_LIMIT ;	// 準備roleだけの別有限raw枠です。
	std::size_t	  prefix{} ;							// 穴の後の存在を連続prefixへ数えません。
	bool		  missing{} ;							// 最初の欠損以降は全role欠損だけを認めます。
	// 親intentからseal準備までの元raw完全一致だけを再利用します。
	for( std::size_t i = 0U; i < count; ++i) {
		const auto &role  = roles[i] ;								// 元予約だけが所有する固定名と本文です。
		const auto	scope = static_cast<std::size_t>( role.scope) ;	// count内は親／旧子だけです。
		std::string raw ;											// 保存済み準備byteです。
		bool		found{} ;										// 欠損roleを新しいsuffixとして扱います。
		io( stores[scope]->read( role.name, raw, found, preparedRemaining)) ;
		// 穴の後の存在と同名の別byteは修復せず拒否します。
		if( found) {
			require( !missing && raw == role.raw && names[scope].insert( role.name).second) ;
			++prefix ;
			expected[scope].bytes += raw.size() ;
			expected[scope].currentEntries += role.name.starts_with( L"current/") ? 1U : 0U ;
			expected[scope].runEntries += role.name.starts_with( L"runs/") ? 1U : 0U ;
		} else {
			missing = true ;
		}
	}

	bool activationFound{} ;	// 記録なしでは変更済みheadを受理しません。
	// 親head専用入口だけで元固定記録を追加名へ認めます。
	if( activation) {
		std::string	  raw ;						// 独立枠で読む一記録です。
		std::uint64_t remaining = RAW_LIMIT ;	// 旧共有読取り枠へ混ぜません。
		io( stores[0]->read( activation->name, raw, activationFound, remaining)) ;
		require( headPrefix == 0U || activationFound) ;
		// 同名別記録を完全一致の保存済みprefixと扱いません。
		if( activationFound) {
			require( raw == activation->raw && names[0].insert( activation->name).second) ;
			expected[0].bytes += raw.size() ;
			++expected[0].runEntries ;
		}
	}

	std::array<CollectorStoreUsage, 3U> actual{} ;	// Staging込み実量を最後に照合します。
	// 全三scopeの二directoryを検査し、未登録名と残留stagingを見逃しません。
	for( std::size_t scope = 0U; scope < stores.size(); ++scope) {
		std::vector<std::wstring> current ;	// 同じ検証済みdirectoryの固定順名です。
		std::vector<std::wstring> runs ;	// runsの未知準備名も拒否します。
		io( stores[scope]->listCurrentNames( current)) ;
		io( stores[scope]->listRunNames( runs)) ;
		require( current.size() == expected[scope].currentEntries &&
				runs.size() == expected[scope].runEntries) ;
		// 列挙された全名が元fileまたは完全一致した準備prefixに限られるか確認します。
		for( const auto &name : current) {
			require( names[scope].contains( L"current/" + name)) ;
		}

		// 名前だけが違う同size fileを容量一致で受理しません。
		for( const auto &name : runs) {
			require( names[scope].contains( L"runs/" + name)) ;
		}

		io( stores[scope]->inspectUsage( actual[scope])) ;
		require( actual[scope].bytes == expected[scope].bytes &&
				actual[scope].currentEntries == expected[scope].currentEntries &&
				actual[scope].runEntries == expected[scope].runEntries) ;
	}

	// 旧準備入口では新子全予定を空usageへ先払いし、新子実量は別検査します。
	const std::array<CollectorStoreUsage, 3U> usage{actual[0], actual[1], {}} ;
	std::array<CollectorSegmentStorageCost, 3U>
		cost ;	// 既存prefixは不足分の追加量へ重複計上しません。
	// 完了した新子・headと既存記録を追加量に重複計上しません。
	if( activation) {
		std::vector<CollectorSegmentStorageRole> missingRoles ;				// 元二headの不足suffixだけです。
		const auto heads = roles.subspan( roles.size() - 2U + headPrefix) ;	// 検査済み固定末尾です。
		missingRoles.assign( heads.begin(), heads.end()) ;
		// 未保存の記録だけを親の同じ追加量へ先払いします。
		if( !activationFound) {
			missingRoles.push_back( *activation) ;
		}

		io( checkCollectorSegmentStorageCapacity( usage, missingRoles, cost)) ;
	} else {
		io( checkCollectorSegmentStorageCapacity( usage, roles.subspan( prefix), cost)) ;
	}

	return prefix ;
}
/** @brief 元新子準備だけの完全一致prefixと空historyを検査します。
 * @param[in] roles 元予約の全固定roleです。
 * @param[in] begin 新子markerの固定開始添字です。
 * @param[in,out] stores 元同親保存借用中の親／旧子／旧historyです。
 * @param[in,out] next 元固定新子／新historyの実handleです。
 * @param[in] initialRaw 空なら空history限定、非空なら元導出ROOTだけを認めます。
 * @param[out] initialFound 指定時は全検査後だけのROOT存在です。
 * @param[in] headPrefix 親head専用入口の保存済み二head件数です。既定0です。
 * @return 全検査した新子側prefix件数です。
 * @throws DWORD 第一I/O、容量68、byte／集合矛盾13です。
 */
std::size_t verifyNewPreparation( const std::span<const CollectorSegmentStorageRole> roles,
								 const std::size_t									begin,
								 const std::array<LocalCollectorStateStore *, 3U>  &stores,
								 const std::array<LocalCollectorStateStore *, 2U>  &next,
								 const std::string_view								initialRaw = {},
								 bool *initialFound = nullptr, const std::size_t headPrefix = 0U)
{
	require( headPrefix <= 2U && next[0] && next[1] && roles.size() == begin + 71U &&
			roles[begin + 69U].scope == CollectorSegmentStorageScope::PARENT &&
			roles[begin + 70U].scope == CollectorSegmentStorageScope::PARENT) ;
	std::set<std::wstring> names ;							// 固定69roleの存在済み名だけです。
	CollectorStoreUsage	   expected{} ;						// 準備prefixだけの新子実量です。
	std::uint64_t		   remaining = 69U * RAW_LIMIT ;	// 新子準備専用の有限raw上限です。
	std::size_t			   prefix{} ;						// Markerから順に連続した保存数です。
	bool				   missing{} ;						// 穴の後の存在は不足suffixへ格下げしません。
	// 新子marker・全66像・base・bootstrapの元rawだけを再利用します。
	for( std::size_t i = 0U; i < 69U; ++i) {
		const auto &role = roles[begin + i] ;	// 元予約だけの固定保存roleです。
		require( role.scope == CollectorSegmentStorageScope::NEW_SEGMENT) ;
		std::string raw ;		// 同じ保護handleで読む保存済み原byteです。
		bool		found{} ;	// 初回不足suffixと元prefixを区別します。
		io( next[0]->read( role.name, raw, found, remaining)) ;
		// 同名別byteと非prefixは非変更で拒否します。
		if( found) {
			require( !missing && raw == role.raw && names.insert( role.name).second) ;
			++prefix ;
			expected.bytes += raw.size() ;
			expected.currentEntries += role.name.starts_with( L"current/") ? 1U : 0U ;
			expected.runEntries += role.name.starts_with( L"runs/") ? 1U : 0U ;
		} else {
			missing = true ;
		}
	}

	require( prefix != 0U) ;
	std::vector<std::wstring> current ;	// 固定currentの全名です。
	std::vector<std::wstring> runs ;	// 未登録準備も含む実runs全名です。
	io( next[0]->listCurrentNames( current)) ;
	io( next[0]->listRunNames( runs)) ;
	require( current.size() == expected.currentEntries && runs.size() == expected.runEntries) ;
	// New currentの全名が完全一致したprefixに含まれるか照合します。
	for( const auto &name : current) {
		require( names.contains( L"current/" + name)) ;
	}

	// 同じsizeの別名を実usageだけで受理しません。
	for( const auto &name : runs) {
		require( names.contains( L"runs/" + name)) ;
	}

	io( next[1]->listCurrentNames( current)) ;
	io( next[1]->listRunNames( runs)) ;
	bool		  rootFound{} ;					// 専用ROOT以外の新履歴は許可しません。
	std::string	  rootRaw ;						// 同じ保護historyの現在byteです。
	std::uint64_t rootRemaining = RAW_LIMIT ;	// 一ROOTの独立読取り上限です。
	io( next[1]->read( INITIAL_ROOT_NAME, rootRaw, rootFound, rootRemaining)) ;
	require( runs.empty() &&
			(rootFound ? !initialRaw.empty() && prefix == 69U && rootRaw == initialRaw &&
							 current == std::vector<std::wstring>{L"segment-history-root-v1.json"}
					   : current.empty())) ;
	CollectorStoreUsage history ;	// 全payload／stagingを空または元ROOT一件へ限定します。
	io( next[1]->inspectUsage( history)) ;
	require( history.bytes == (rootFound ? initialRaw.size() : 0U) &&
			history.currentEntries == (rootFound ? 1U : 0U) && history.runEntries == 0U) ;
	// 専用ROOTだけを別storeの既存容量へ独立先払いします。
	if( !initialRaw.empty()) {
		const std::array<CollectorStoreUsage, 3U> rootUsage{
			history, {}, {}} ;	// 他storeの余量を流用しません。
		const std::array<CollectorSegmentStorageRole, 1U> rootRole{
			{{CollectorSegmentStorageScope::PARENT, std::wstring( INITIAL_ROOT_NAME),
			  // 容量判定だけの一store roleです。
			  std::string( initialRaw)}}} ;
		std::array<CollectorSegmentStorageCost, 3U> rootCost ;	// ROOT不足分と最大一stagingです。
		io( checkCollectorSegmentStorageCapacity(
			rootUsage,
			std::span<const CollectorSegmentStorageRole>( rootRole).subspan( rootFound ? 1U : 0U),
			rootCost)) ;
	}

	std::array<CollectorStoreUsage, 3U> actual{} ;	// 親／旧子／新子を独立先払いします。
	io( stores[0]->inspectUsage( actual[0])) ;
	io( stores[1]->inspectUsage( actual[1])) ;
	io( next[0]->inspectUsage( actual[2])) ;
	require( actual[2].bytes == expected.bytes &&
			actual[2].currentEntries == expected.currentEntries &&
			actual[2].runEntries == expected.runEntries) ;
	std::array<CollectorSegmentStorageCost, 3U> cost ;	// 保存済みprefixは追加量へ二重計上しません。
	require( headPrefix == 0U || prefix == 69U) ;
	io( checkCollectorSegmentStorageCapacity( actual, roles.subspan( begin + prefix + headPrefix),
											cost)) ;
	// 失敗途中のROOT観測を成功出力へ公開しません。
	if( initialFound) {
		*initialFound = rootFound ;
	}

	return prefix ;
}
/** @brief 実新子の66像から元carryを復号し専用ROOTを導出します。
 * @param[in] roles 元予約の固定名と本文です。
 * @param[in] begin 元新子markerの添字です。
 * @param[in] draft 元intent／base／bootstrapの全結合です。
 * @param[in] before 元fresh readerの変更しない共有snapshotです。
 * @param[in,out] child 同じ私有新子handleです。
 * @return 専用初期ROOTの固定envelope rawです。
 * @throws DWORD 第一I/O／CNG／codec・形式13です。
 * @throws Failure 独立字句／byte上限拒否です。
 */
std::string initialRoot( const std::span<const CollectorSegmentStorageRole> roles,
						const std::size_t begin, const CollectorSegmentSwitchDraft &draft,
						const CollectorSharedLedgerSnapshot &before,
						LocalCollectorStateStore			&child)
{
	require( roles.size() == begin + 71U) ;
	CollectorSharedLedgerBytes bodies ;							// 実読取りから再結合する元66本文です。
	std::uint64_t			   remaining = 66U * RAW_LIMIT ;	// 実像専用の有限raw枠です。
	// 空shardを省略せず全66実像を元ordinalへ結合します。
	for( std::size_t i = 0U; i < 66U; ++i) {
		const auto &role = roles[begin + 1U + i] ;	// 元body hashに対応する固定保存名です。
		std::string raw ;							// 同じ保護handleで読む現在byteです。
		bool		found{} ;						// 欠損像を元snapshotから補完しません。
		io( child.read( role.name, raw, found, remaining)) ;
		require( found && raw == role.raw) ;
		Reader reader( raw, RAW_LIMIT) ;	// 外側field順・型・末尾を有限検査します。
		reader.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
		auto body = reader.text( 768U * 1024U) ;	// JSON文字列を元UTF-8本文へ復号します。
		reader.literal( ",\"sha256\":") ;
		const auto encodedHash = reader.text( 64U) ;	// 元内部hashを無制限に読みません。
		reader.literal( "}") ;
		reader.finish() ;
		const auto hash = digest( body) ;	// 同じ実本文のCNG指紋です。
		require( hash == draft.images[i] && encodedHash.size() == 64U &&
				std::wstring( encodedHash.begin(), encodedHash.end()) == hash && pack( body) == raw) ;
		// 二先頭roleをrequestへ取り違えません。
		if( i < 2U) {
			(i == 0U ? bodies.budget : bodies.groups) = std::move( body) ;
		} else {
			bodies.requests[i - 2U] = std::move( body) ;
		}
	}

	CollectorSharedLedgerSnapshot carried ;	// 全型・関係・上限を検査した実保存値です。
	io( decodeCollectorSharedLedger( bodies, carried)) ;
	io( checkCollectorSharedLedgerCarry( before, carried, draft.intent.accepted)) ;
	const auto &i = draft.intent ;	// 元acceptedと最高UTCを取り違えません。
	require( carried.collection == i.collection && i.ledger.size() == 64U) ;
	Writer root( 16U * 1024U) ;	// 専用ROOTの独立body上限です。
	root.append( "{\"schema\":\"collector-segment-history-root-v1\",\"collection\":") ;
	root.wideText( i.collection) ;
	root.append( ",\"segment\":") ;
	root.wideText( i.newSegment) ;
	root.append( ",\"ordinal\":") ;
	root.number( i.ordinal) ;
	root.append( ",\"accepted\":") ;
	root.number( i.accepted) ;
	root.append( ",\"lastUtc\":") ;
	root.number( carried.lastUtcMillis) ;
	root.append( ",\"oldSegment\":") ;
	root.wideText( i.oldSegment) ;
	root.append( ",\"oldRoot\":") ;
	root.wideText( i.oldRoot) ;
	root.append( ",\"seal\":") ;
	root.wideText( i.seal) ;
	root.append( ",\"ledger\":") ;
	root.wideText( i.ledger) ;
	root.append( ",\"base\":") ;
	root.wideText( i.base) ;
	root.append( ",\"bootstrap\":") ;
	root.wideText( i.bootstrap) ;
	root.append( ",\"switchIntent\":") ;
	root.wideText( draft.intentHash) ;
	root.append( ",\"images\":[") ;
	// 元body hashを固定順で全件登録し、許可や新操作を生成しません。
	for( std::size_t n = 0U; n < draft.images.size(); ++n) {
		// 先頭以外だけ固定delimiterを置きます。
		if( n != 0U) {
			root.append( ",") ;
		}

		root.wideText( draft.images[n]) ;
	}

	root.append( "],\"generations\":[],\"operations\":[],\"active\":null}") ;
	return pack( root.take()) ;
}
} // namespace
/** @see local_collector_segment_storage.h */
DWORD checkCollectorSegmentStorageCapacity(
	const std::array<CollectorStoreUsage, 3U>		  &usage,
	const std::span<const CollectorSegmentStorageRole> roles,
	std::array<CollectorSegmentStorageCost, 3U>		  &cost) noexcept
{
	cost = {} ;
	try {
		// 予定名を無制限に確保せず固定role上限で止めます。
		if( roles.size() > 90U) {
			return ERROR_TOO_MANY_NAMES ;
		}

		std::array<CollectorSegmentStorageCost, 3U> next{} ;	// 全成功後だけの独立容量です。
		std::array<std::set<std::wstring>, 3U>		current ;	// 二回head保存のentryは一つです。
		std::array<std::set<std::wstring>, 3U>		runs ;		// scopeごとに重複を除きます。
		// 最大90の各rawを追加前に検査して加算します。
		for( const auto &role : roles) {
			const auto index = static_cast<std::size_t>( role.scope) ;	// 無効enumを添字にしません。
			// DTO単体でも任意scopeと不正相対名を成功容量にしません。
			if( index >= next.size() ||
			   !(role.name.starts_with( L"current/") || role.name.starts_with( L"runs/")) ||
			   !role.name.ends_with( L".json") ||
			   role.name.find_first_of( L"/\\", role.name.find( L'/') + 1U) != std::wstring::npos ||
			   role.name.find( L"..") != std::wstring::npos ||
			   role.name.find( L':') != std::wstring::npos) {
				return ERROR_INVALID_DATA ;
			}

			// 一rawと追加量の既存上限を加算前に保持します。
			if( role.raw.size() > RAW_LIMIT || role.raw.size() > STORE_LIMIT - next[index].bytes) {
				return ERROR_TOO_MANY_NAMES ;
			}

			next[index].bytes += role.raw.size() ;
			next[index].stagingBytes =
				std::max( next[index].stagingBytes, static_cast<std::uint64_t>( role.raw.size())) ;
			(role.name.starts_with( L"current/") ? current[index] : runs[index]).insert( role.name) ;
		}

		// 親／旧子／新子の量を合算せず各storeで独立先払いします。
		for( std::size_t i = 0U; i < next.size(); ++i) {
			next[i].currentNames = current[i].size() ;
			next[i].runNames	 = runs[i].size() ;
			// 減算形でoverflowなく、全保存と最大一stagingを事前拒否します。
			if( usage[i].bytes > STORE_LIMIT || next[i].bytes > STORE_LIMIT - usage[i].bytes ||
			   next[i].stagingBytes > STORE_LIMIT - usage[i].bytes - next[i].bytes ||
			   usage[i].currentEntries >= ENTRY_LIMIT || usage[i].runEntries >= ENTRY_LIMIT ||
			   next[i].currentNames > ENTRY_LIMIT - usage[i].currentEntries - 1U ||
			   next[i].runNames > ENTRY_LIMIT - usage[i].runEntries - 1U) {
				return ERROR_TOO_MANY_NAMES ;
			}
		}

		cost = next ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::prepare(
	LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
	const std::span<const CollectorCampaignSource> sources, const std::wstring_view newSegment,
	const std::uint64_t										   acceptedUtcMillis,
	std::shared_ptr<const CollectorSegmentStorageReservation> &reservation) noexcept
{
	auto previous = std::move( reservation) ;	// Aliasと旧holdを同期呼出し中だけ保持します。
	(void)previous ;
	try {
		std::shared_ptr<const CollectorSegmentQuiescentSwitch>
			fresh ;	// 古いcontextを受け取りません。
		io( LocalCollectorSegmentPreparation::prepareQuiescent(
			collection, segment, sources, newSegment, acceptedUtcMillis, fresh)) ;
		auto												 roles = fixedRoles( fresh->draft(),
																				// 全元body hashへ結合した保存予定です。
																				fresh->root().evidence()) ;
		std::shared_ptr<const CollectorCollectionSwitchHold> hold ;	// 非変更の同親handle保持です。
		std::array<CollectorStoreUsage, 2U> actual ;				// 同じ親／旧子の独立実容量です。
		io( collection.reserveSwitch( segment, fresh->draft().intent.newSegment, hold, actual)) ;
		checkUsage( fresh->root().evidence(), actual) ;
		const std::array<CollectorStoreUsage, 3U> usage{
			actual[0], actual[1], {}} ;						// 新子は未作成です。
		std::array<CollectorSegmentStorageCost, 3U> cost ;	// 全三scopeの先払い結果です。
		io( checkCollectorSegmentStorageCapacity( usage, roles, cost)) ;
		reservation = std::make_shared<const CollectorSegmentStorageReservation>(
			CollectorSegmentStorageReservation::ConstructionKey{}, std::move( hold),
			std::move( fresh), std::move( roles), cost) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure &failure) {
		return failure.status == Status::SIZE_LIMIT ? ERROR_TOO_MANY_NAMES : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::savePreparation(
	std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
	const std::function<DWORD( std::size_t)> &afterSave) noexcept
{
	saved = 0U ;
	std::size_t verified{} ;	// Callerや診断callbackが変更できない内部prefixです。
	// Caller DTOや欠損能力から保存を発行しません。
	if( !reservation || (reservation->recoveredRoot_ && !reservation->recoveryPreparation_)) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		std::array<LocalCollectorStateStore *, 3U> stores{} ;	// 同じhold内の三実handleだけです。
		io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, true, stores)) ;
		const auto returnBorrow = [&reservation]( const CollectorCollectionSwitchHold *) {
			LocalCollectorCollectionStore::releaseSwitchStorage( reservation->hold_) ;
		} ; // 同期呼出しの強所有予約はguardより長く存続します。
		std::unique_ptr<const CollectorCollectionSwitchHold, decltype( returnBorrow)> borrowed(
			// 全終了経路で返す私有借用です。
			reservation->hold_.get(), returnBorrow) ;
		const auto	roles = reservation->roles() ;								// 任意のrole入力は受け取りません。
		const auto	count = preparationCount( roles, reservation->draft()) ;	// 最大18保存です。
		const auto &evidence =
			// 同じ元検査の全raw集合です。
			reservation->evidence() ;
		const auto verify = [&] {
			std::array<LocalCollectorStateStore *, 2U> next{} ;	// 実保存済み新側だけを再照合します。
			io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, false, stores,
																  &next)) ;
			const auto prefix =
				// 元旧準備の実prefixです。
				verifyPreparation( evidence, roles, count, stores) ;
			// 新子作成済み準備回復では旧準備の欠損を補完せず、新側改変も毎pass拒否します。
			if( reservation->recoveryPreparation_ && next[0]) {
				require( prefix == count && next[1]) ;
				(void)verifyNewPreparation( roles, count, stores, next) ;
			}

			return prefix ;
		} ; // 元予約と借用を同期呼出し中だけ参照し、全名／全rawをfresh検査します。
		verified = verify() ;
		saved	 = verified ;
		// 最大18roleの欠けたsuffixだけを元順序で保存し、完了prefixは置換しません。
		while( verified < count) {
			const auto before = verify() ;	// 保存前の元全raw／全名と現在prefixです。
			require( before == verified) ;
			const auto &role = roles[verified] ;	// 同じ元intentから導出した次の一roleです。
			io( stores[static_cast<std::size_t>( role.scope)]->write( role.name, role.raw)) ;
			const auto after = verify() ;	// Atomic保存後も元payloadと全固定prefixを再照合します。
			require( after == verified + 1U) ;
			verified = after ;
			saved	 = verified ;
			// 数値停止は第一codeを維持し、callback後の再入で保存を重複させません。
			if( afterSave) {
				const auto code = afterSave( verified) ;	// 外部出力改変を次の添字へ流用しません。
				saved			= verified ;
				io( code) ;
			}
		}

		require( verify() == count) ;
		saved = verified ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		saved = verified ;
		return code ;
	} catch( const std::bad_alloc &) {
		saved = verified ;
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		saved = verified ;
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::saveNewSegmentPreparation(
	std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
	const std::function<DWORD( std::size_t)> &afterSave) noexcept
{
	saved = 0U ;
	std::size_t verified{} ;	// Callbackが変更できない新子側prefixです。
	// 欠損能力から新子を作成しません。
	if( !reservation || (reservation->recoveredRoot_ && !reservation->recoveryPreparation_)) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		std::array<LocalCollectorStateStore *, 3U> stores{} ;	// 元親／旧子／historyです。
		std::array<LocalCollectorStateStore *, 2U> next{} ;		// 私有新子だけの実handleです。
		io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, true, stores,
															  &next)) ;
		const auto returnBorrow = [&reservation]( const CollectorCollectionSwitchHold *) {
			LocalCollectorCollectionStore::releaseSwitchStorage( reservation->hold_) ;
		} ; // 強所有予約は同期guardより長く存続し、全終了経路で保存借用を返します。
		std::unique_ptr<const CollectorCollectionSwitchHold, decltype( returnBorrow)> borrowed(
			// 公開leaseへ二子借用を拡張しません。
			reservation->hold_.get(), returnBorrow) ;
		const auto	roles	  = reservation->roles() ;								// Caller roleは受け取りません。
		const auto	begin	  = preparationCount( roles, reservation->draft()) ;	// 新子開始添字です。
		const auto &evidence  = reservation->evidence() ;							// 同じ元全rawです。
		const auto	verifyOld = [&] {
			 io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, false, stores,
																   &next)) ;
			 require( verifyPreparation( evidence, roles, begin, stores) == begin) ;
		} ; // 旧準備と元全rawを保存前後にfresh検査します。
		verifyOld() ;
		const bool opening = next[0] == nullptr ;	// 未発行新子だけmarker地点を通知します。
		// 既存新子の破損をhandle再利用で見逃しません。
		if( !opening) {
			(void)verifyNewPreparation( roles, begin, stores, next) ;
		}

		io( LocalCollectorCollectionStore::createSwitchStorage( reservation->hold_, roles[0].name,
															  roles[0].raw, next)) ;
		const auto verify = [&] {
			verifyOld() ;
			return verifyNewPreparation( roles, begin, stores, next) ;
		} ; // 同じholdの全旧raw／新準備／空historyを検査します。
		verified = verify() ;
		saved	 = verified ;
		// 新markerと空historyの発行後だけ最初の停止地点を通知します。
		if( opening && afterSave) {
			const auto code = afterSave( verified) ;	// 元数値停止を保存成功へ変換しません。
			saved			= verified ;
			io( code) ;
		}

		// 固定69roleの不足suffixだけを順番に保存し、親headへは進みません。
		while( verified < 69U) {
			require( verify() == verified) ;
			const auto &role = roles[begin + verified] ;	// 次の固定新子roleです。
			io( next[0]->write( role.name, role.raw)) ;
			const auto after = verify() ;	// 元byteと全準備を実保存後にも再照合します。
			require( after == verified + 1U) ;
			verified = after ;
			saved	 = verified ;
			// 診断再入とcaller出力改変を内部添字から隔離します。
			if( afterSave) {
				const auto code = afterSave( verified) ;	// 第一診断codeです。
				saved			= verified ;
				io( code) ;
			}
		}

		require( verify() == 69U) ;
		saved = verified ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		saved = verified ;
		return code ;
	} catch( const std::bad_alloc &) {
		saved = verified ;
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		saved = verified ;
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::saveInitialHistoryRoot(
	std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
	const std::function<DWORD( std::size_t)> &afterSave) noexcept
{
	saved = 0U ;
	std::size_t verified{} ;	// Callerが変更できない最後のROOT検査件数です。
	// 元生存能力なしでROOTを生成しません。
	if( !reservation || (reservation->recoveredRoot_ && !reservation->recoveryPreparation_)) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		std::array<LocalCollectorStateStore *, 3U> stores{} ;	// 元親／旧子／旧historyです。
		std::array<LocalCollectorStateStore *, 2U> next{} ;		// 元私有新子／新historyです。
		io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, true, stores,
															  &next)) ;
		const auto returnBorrow = [&reservation]( const CollectorCollectionSwitchHold *) {
			LocalCollectorCollectionStore::releaseSwitchStorage( reservation->hold_) ;
		} ; // 強所有予約は同期guardより長く存続し、全終了経路で保存借用だけを返します。
		std::unique_ptr<const CollectorCollectionSwitchHold, decltype( returnBorrow)> borrowed(
			// 公開の二子借用を発行しません。
			reservation->hold_.get(), returnBorrow) ;
		const auto	roles = reservation->roles() ;								// 元予約だけの固定name／bodyです。
		const auto	begin = preparationCount( roles, reservation->draft()) ;	// 新子開始添字です。
		const auto &evidence =
			// 元fresh全rawと共有根拠です。
			reservation->evidence() ;
		std::string rootRaw ;	// 全fresh検査後だけ保持する専用ROOT rawです。
		const auto	verify = [&] {
			 io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, false, stores,
																   &next)) ;
			 require( next[0] && next[1] &&
					 verifyPreparation( evidence, roles, begin, stores) == begin) ;
			 auto candidate = initialRoot( roles, begin, reservation->draft(),
										  evidence.shared->evidence().snapshot,
										  *next[0]) ;	// 実66像のcarryから再導出します。
			 bool found{} ;								// 全名と容量の検査後だけのROOT存在です。
			 require( verifyNewPreparation( roles, begin, stores, next, candidate, &found) == 69U) ;
			 rootRaw = std::move( candidate) ;
			 return found ;
		} ; // 同期借用中だけ元全raw・全準備・同じROOTをfresh検査します。
		verified = verify() ? 1U : 0U ;
		saved	 = verified ;
		// 未保存の一ROOTだけを元固定名へ保存し、既存完全一致ROOTは置換しません。
		if( verified == 0U) {
			require( !verify()) ;
			io( next[1]->write( INITIAL_ROOT_NAME, rootRaw)) ;
			require( verify()) ;
			verified = 1U ;
			saved	 = verified ;
			// 実保存と全再照合の後だけ数値診断を通知します。
			if( afterSave) {
				const auto code = afterSave( verified) ;	// 内部件数は外部出力改変に依存しません。
				saved			= verified ;
				io( code) ;
			}
		}

		require( verify()) ;
		saved = verified ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		saved = verified ;
		return code ;
	} catch( const Failure &failure) {
		saved = verified ;
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		saved = verified ;
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		saved = verified ;
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::parentHeads(
	std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
	const std::function<DWORD( std::size_t)> &afterSave, const bool validateOnly) noexcept
{
	saved = 0U ;
	std::size_t verified{} ;	// Callerが変更できない最後の三地点検査件数です。
	// 元予約なしで任意headを保存しません。
	if( !reservation) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		std::array<LocalCollectorStateStore *, 3U> stores{} ;	// 元親／旧子／旧historyです。
		std::array<LocalCollectorStateStore *, 2U> next{} ;		// 元固定新子／新historyです。
		io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, true, stores,
															  &next)) ;
		const auto returnBorrow = [&reservation]( const CollectorCollectionSwitchHold *) {
			LocalCollectorCollectionStore::releaseSwitchStorage( reservation->hold_) ;
		} ; // 同期入口の強所有はguardより長く存続し、全終了経路で私有借用を返します。
		std::unique_ptr<const CollectorCollectionSwitchHold, decltype( returnBorrow)> borrowed(
			// 元HTTP閉鎖と単一writerは返しません。
			reservation->hold_.get(), returnBorrow) ;
		const auto	roles = reservation->roles() ;								// 元固定保存順だけです。
		const auto	begin = preparationCount( roles, reservation->draft()) ;	// 旧準備の開始境界です。
		const auto &draft = reservation->draft() ;								// 元非循環結合です。
		const auto &evidence = reservation->evidence() ;						// 元全rawを保持します。
		CollectorSegmentStorageRole activation{CollectorSegmentStorageScope::PARENT,
											   L"runs/segment-switch-activation-" +
												   draft.intentHash + L".json",
											   {}} ;	// 固定記録だけです。
		const auto					verify = [&] {
			 io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, false, stores,
																				   &next)) ;
			 require( next[0] && next[1] && roles.size() == begin + 71U) ;
			 const auto rootRaw =
				 initialRoot( roles, begin, draft, evidence.shared->evidence().snapshot,
											 *next[0]) ;						// 保存済み実66像から再導出します。
			 const auto	   rootHash = digest( unpack( rootRaw, 16U * 1024U)) ;	// 専用ROOT本文hashです。
			 std::string   headRaw ;											// 同じ保護親の現在headです。
			 bool		   headFound{} ;										// 欠損headを保存で補完しません。
			 std::uint64_t headRemaining = RAW_LIMIT ;							// 現在headの独立読取り枠です。
			 io( stores[0]->read( L"current/collection-head-v1.json", headRaw, headFound,
												headRemaining)) ;
			 require( headFound) ;
			 std::string   actual ;					// 元保持記録の現在rawです。
			 bool		   found{} ;				// 最初の不足記録だけを保存対象にします。
			 std::uint64_t remaining = RAW_LIMIT ;	// 記録の独立有限raw枠です。
			 io( stores[0]->read( activation.name, actual, found, remaining)) ;
			 Writer record( 256U * 1024U) ;	// 元headを含む有限本文です。
			 record.append( "{\"schema\":\"collector-segment-switch-activation-v1\",\"collection\":") ;
			 record.wideText( draft.intent.collection) ;
			 record.append( ",\"intent\":") ;
			 record.wideText( draft.intentHash) ;
			 record.append( ",\"oldHead\":") ;
			 record.wideText( draft.intent.oldHead) ;
			 record.append( ",\"oldHeadRaw\":") ;
			 std::string oldRaw = headRaw ;	// 記録なしでは現在headを元rawとして実検査します。
			 // 記録ありでも元全rawのhash検査へ戻し、本文を無条件に信用しません。
			 if( found) {
				 const auto body =
					 // 外側CNGとcanonical順を検査します。
					 unpack( actual, 256U * 1024U) ;
				 Reader reader( body, 256U * 1024U) ;	// 固定identityと元head文字列だけです。
				 reader.literal( record.view()) ;
				 oldRaw = reader.text( 128U * 1024U) ;
				 Writer tail( 4096U) ;	// 既存ROOTと次headへの元結合だけです。
				 tail.append( ",\"initialRoot\":") ;
				 tail.wideText( rootHash) ;
				 tail.append( ",\"nextHead\":") ;
				 tail.wideText( draft.intent.nextHead) ;
				 tail.append( "}") ;
				 reader.literal( tail.view()) ;
				 reader.finish() ;
			 }

			 require( oldRaw.size() <= 128U * 1024U &&
									 digest( unpack( oldRaw, 128U * 1024U)) == draft.intent.oldHead) ;
			 std::size_t originalHeads{} ;	// 元inventoryに唯一headが登録されていることを要求します。
			 // 元scope付きinventoryのheadだけを固定記録へ完全結合します。
			 for( const auto &file : evidence.files) {
				 // 他scopeの同名を元親headとして使いません。
				 if( file.scope == L"parent" && file.name == L"current/collection-head-v1.json") {
					 require( oldRaw.size() == file.bytes && digest( oldRaw) == file.sha256) ;
					 ++originalHeads ;
				 }
			 }

			 require( originalHeads == 1U) ;
			 record.text( oldRaw) ;
			 record.append( ",\"initialRoot\":") ;
			 record.wideText( rootHash) ;
			 record.append( ",\"nextHead\":") ;
			 record.wideText( draft.intent.nextHead) ;
			 record.append( "}") ;
			 activation.raw = pack( record.take()) ;
			 require( !found || actual == activation.raw) ;
			 std::size_t prefix{} ;	// 記録なし／元head／登録／最終の四状態だけです。
			 // 変更済みheadは元記録が完全に成立した後だけを認めます。
			 if( found) {
				 prefix = headRaw == oldRaw					  ? 1U
										  : headRaw == roles[begin + 69U].raw ? 2U
										  : headRaw == roles[begin + 70U].raw ? 3U
																			  : 0U ;
				 require( prefix != 0U) ;
			 } else {
				 require( headRaw == oldRaw) ;
			 }

			 const auto heads = prefix == 0U ? 0U : prefix - 1U ;	// 完了headを不足量へ数えません。
			 require( verifyPreparation( evidence, roles, begin, stores, &activation, headRaw,
													   heads) == begin) ;
			 bool rootFound{} ;	// 保存済みROOTの完全一致を必須とします。
			 require( verifyNewPreparation( roles, begin, stores, next, rootRaw, &rootFound, heads) ==
										 69U &&
									 rootFound) ;
			 return prefix ;
		} ; // 同期借用内の全旧raw・新準備・ROOT・元保持記録を毎pass再検査します。
		verified = verify() ;
		saved	 = verified ;
		// 回復能力発行前は全検査だけを行い、既存byteを変更しません。
		if( validateOnly) {
			return ERROR_SUCCESS ;
		}

		// 記録、登録head、最終headの不足suffixだけを元固定順で保存します。
		while( verified < 3U) {
			require( verify() == verified) ;
			const auto &role =
				// 元予定の一保存です。
				verified == 0U ? activation : roles[begin + 68U + verified] ;
			io( stores[0]->write( role.name, role.raw)) ;
			require( verify() == verified + 1U) ;
			++verified ;
			saved = verified ;
			// 物理保存と全再照合の後だけ数値診断を呼び、第一codeを保持します。
			if( afterSave) {
				const auto code = afterSave( verified) ;	// 外部件数改変を次のroleへ流用しません。
				saved			= verified ;
				io( code) ;
			}
		}

		require( verify() == 3U) ;
		saved = verified ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		saved = verified ;
		return code ;
	} catch( const Failure &failure) {
		saved = verified ;
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		saved = verified ;
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		saved = verified ;
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::recover(
	LocalCollectorCollectionStore &collection, const std::wstring_view intentKey,
	const std::span<const CollectorCampaignSource>			   sources,
	std::shared_ptr<const CollectorSegmentStorageReservation> &reservation,
	const std::function<DWORD()>							  &beforeFinalRecheck) noexcept
{
	return recoverInternal( collection, intentKey, sources, reservation, beforeFinalRecheck, false) ;
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::recoverPreparation(
	LocalCollectorCollectionStore &collection, const std::wstring_view intentKey,
	const std::span<const CollectorCampaignSource>			   sources,
	std::shared_ptr<const CollectorSegmentStorageReservation> &reservation,
	const std::function<DWORD()>							  &beforeFinalRecheck) noexcept
{
	return recoverInternal( collection, intentKey, sources, reservation, beforeFinalRecheck, true) ;
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::verifyPreparationRecovery(
	const std::shared_ptr<const CollectorSegmentStorageReservation> &reservation)
{
	// ROOT保存済み回復能力を準備保存へ転用しません。
	if( !reservation || !reservation->recoveredRoot_ || !reservation->recoveryPreparation_) {
		return ERROR_INVALID_PARAMETER ;
	}

	std::array<LocalCollectorStateStore *, 3U> stores{} ;	// 元三handleです。
	std::array<LocalCollectorStateStore *, 2U> next{} ;		// 存在する新二handleだけです。
	io( LocalCollectorCollectionStore::borrowSwitchStorage( reservation->hold_, true, stores, &next)) ;
	const auto release = [&reservation]( const CollectorCollectionSwitchHold *) {
		LocalCollectorCollectionStore::releaseSwitchStorage( reservation->hold_) ;
	} ; // 予約の強所有は同期借用guardより長く生存します。
	std::unique_ptr<const CollectorCollectionSwitchHold, decltype( release)> borrowed(
		// 全終端で私有借用だけを返します。
		reservation->hold_.get(), release) ;
	const auto roles = reservation->roles() ;							// 同じ再導出からの固定roleです。
	const auto count = preparationCount( roles, reservation->draft()) ;	// 新子以前の全旧準備です。
	// 固定intentから元旧準備の実連続部分だけを検査します。
	const auto prefix = verifyPreparation( reservation->evidence(), roles, count, stores) ;
	// 固定intentのない状態から回復予約を新規発行しません。
	require( prefix > 0U && static_cast<bool>( next[0]) == static_cast<bool>( next[1])) ;
	// 新子作成済みの場合は全旧準備と連続新準備・空historyを追加で要求します。
	if( next[0]) {
		require( prefix == count) ;
		(void)verifyNewPreparation( roles, count, stores, next) ;
	}

	return ERROR_SUCCESS ;
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::recoverInternal(
	LocalCollectorCollectionStore &collection, const std::wstring_view intentKey,
	const std::span<const CollectorCampaignSource>			   sources,
	std::shared_ptr<const CollectorSegmentStorageReservation> &reservation,
	const std::function<DWORD()> &beforeFinalRecheck, const bool preparation) noexcept
{
	auto previous = std::move( reservation) ;	// Aliasと旧所有は同期入口中だけ保持します。
	(void)previous ;
	try {
		// 任意名を親のreadへ渡しません。
		if( !collector_projected_json::isHash( intentKey)) {
			return ERROR_INVALID_PARAMETER ;
		}

		const std::wstring		  key( intentKey) ;	// Caller参照の変更から元identityを分離します。
		LocalCollectorStateStore *parent{} ;		// 私有同親storeだけです。
		io( collection.recoveryParent( parent)) ;
		std::uint64_t remaining = 144U * 1024U * 1024U ;	// 固定66像と四制御rawの独立枠です。
		const auto	  read = [&remaining]( LocalCollectorStateStore &store, const std::wstring &name,
										  const bool optional = false) {
			   std::string raw ;		// 同じ保護fileからの所有byteです。
			   bool		   found{} ;	// Activation未保存以外は欠損を拒否します。
			   io( store.read( name, raw, found, remaining)) ;
			   require( found || optional) ;
			   return raw ;
		} ; // 残予算はこの同期検査より長く生存します。
		const auto intentRaw =
			// 固定起点です。
			read( *parent, L"runs/segment-switch-intent-" + key + L".json") ;
		const auto intentBody = unpack( intentRaw, 16U * 1024U) ;	// CNGとcanonicalを検査します。
		require( digest( intentBody) == key) ;
		CollectorSegmentSwitchIntent intent ;	// 実本文由来だけの固定二子です。
		io( decodeCollectorSegmentSwitchIntent( intentBody, intent)) ;
		require( intent.collection == parent->root().filename().native()) ;
		// 初回専用の意味readerで後続区間を成功扱いにしません。
		if( intent.ordinal != 1U) {
			return ERROR_NOT_SUPPORTED ;
		}

		std::shared_ptr<const CollectorCollectionSwitchHold> hold ;	// 再取得した実handle所有です。
		io( collection.openRecoverySwitch( intent.oldSegment, intent.newSegment, hold, preparation)) ;
		std::array<LocalCollectorStateStore *, 3U> stores{} ;	// 親／旧子／旧historyです。
		std::array<LocalCollectorStateStore *, 2U> next{} ;		// 新子／新historyです。
		io( LocalCollectorCollectionStore::borrowSwitchStorage( hold, true, stores, &next)) ;
		const auto release = [&hold]( const CollectorCollectionSwitchHold *) {
			LocalCollectorCollectionStore::releaseSwitchStorage( hold) ;
		} ; // 全終了経路で保存借用を返し、所有自体は予約まで保持します。
		// 元holdはこの非所有guardより長く生存し、借用だけを全終端で返します。
		std::unique_ptr<const CollectorCollectionSwitchHold, decltype( release)> borrowed( hold.get(),
																						 release) ;
		require( static_cast<bool>( next[0]) == static_cast<bool>( next[1])) ;
		std::shared_ptr<const CollectorStoreHttpFreeze> freeze ;	// 実旧history所有0から取得します。
		io( stores[2]->freezeHttpActivity( freeze)) ;
		const auto head =
			// 現在物理headです。
			read( *stores[0], L"current/collection-head-v1.json") ;
		const auto activation =
			read( *stores[0], L"runs/segment-switch-activation-" + key + L".json",
				 true) ;						// 元head記録です。
		CollectorSegmentRecoveryState decoded ;	// 成功DTO単体は予約の根拠にしません。
		// ROOT未保存では実intentと実headだけを旧意味readerへ投影します。
		if( preparation) {
			require( activation.empty()) ;
			// 空historyだけを準備回復で許可し、保存済みROOTは別の厳格入口へ分離します。
			if( next[1]) {
				std::string rootRaw ;	// 実固定ROOTの存在を読みます。
				bool		found{} ;	// 空本文でも存在を拒否します。
				io( next[1]->read( std::wstring( INITIAL_ROOT_NAME), rootRaw, found, remaining)) ;
				require( !found) ;
			}

			decoded.draft.intent	 = intent ;
			decoded.draft.intentHash = key ;
			decoded.oldHeadRaw		 = head ;
		} else {
			require( next[0] && next[1]) ;
			const auto root = read( *next[1], std::wstring( INITIAL_ROOT_NAME)) ;	// 実専用ROOTです。
			std::array<std::string, 66U>  images ;									// 全実像を内部decode終了まで保持します。
			CollectorSegmentRecoveryBytes bytes ;									// 外部DTOではなく実handle由来の借用です。
			bytes.intent	 = intentRaw ;
			bytes.root		 = root ;
			bytes.head		 = head ;
			bytes.activation = activation ;
			// 固定ordinal順の全66像を非変更で検査します。
			for( std::size_t n = 0U; n < images.size(); ++n) {
				images[n]		= read( *next[0], L"runs/segment-switch-image-" + key + L"-" +
													 ordinalKey( n) + L".json") ;
				bytes.images[n] = images[n] ;
			}

			io( decodeCollectorSegmentRecovery( bytes, decoded)) ;
		}

		std::shared_ptr<const CollectorSegmentRootInventory>
			recovered ;	// 全旧意味readerの実根拠です。
		io( LocalCollectorSegmentInventory::inspectRecovery( stores, decoded, sources, recovered,
														   beforeFinalRecheck)) ;
		const auto &evidence = recovered->evidence() ;		// 全履歴と元head投影のseal一致済みです。
		const auto &shared = evidence.shared->evidence() ;	// 実bootstrapと全操作から再導出済みです。
		// ROOT保存済みでは全保存像を元全台帳と比較し、未保存では元台帳から全予定を再導出します。
		if( !preparation) {
			CollectorSharedLedgerBytes oldBodies ;	// 実元全66現在値です。
			CollectorSharedLedgerBytes newBodies ;	// 新子の全66保存像です。
			io( encodeCollectorSharedLedger( shared.snapshot, oldBodies)) ;
			io( encodeCollectorSharedLedger( decoded.carried, newBodies)) ;
			require( oldBodies.budget == newBodies.budget && oldBodies.groups == newBodies.groups &&
					oldBodies.requests == newBodies.requests) ;
		}

		CollectorSegmentSwitchRequest request ;	// 全hashは同じ実readerから再導出します。
		request.oldSegment = shared.segment ;
		request.newSegment = intent.newSegment ;
		request.oldHead	   = shared.headSha256 ;
		request.oldRoot	   = evidence.history->evidence().rootSha256 ;
		request.seal	   = evidence.sealSha256 ;
		request.accepted   = intent.accepted ;
		// 実閉鎖と両readerの完了条件です。
		request.observation = {true, true, true, 0U, 0U, false} ;
		// 全元shardを同じ非循環intentへ再結合します。
		for( const auto &shard : evidence.shards) {
			request.inventory.push_back( shard.sha256) ;
		}

		CollectorSegmentSwitchDraft draft ;	// Fresh prepared能力を偽造しない回復由来の値です。
		const auto				   &carried =
			preparation ? shared.snapshot : decoded.carried ;	// 実reader由来の全像です。
		io( prepareCollectorSegmentSwitchDraft( shared.snapshot, carried, request, draft)) ;
		require( draft.intentBytes == intentBody && draft.intentHash == key) ;
		auto roles	   = fixedRoles( draft, evidence) ;	// 元全rawと全固定準備byteへ結合します。
		auto candidate = std::make_shared<const CollectorSegmentStorageReservation>(
			CollectorSegmentStorageReservation::ConstructionKey{}, hold, std::move( freeze),
			// まだ公開しません。
			std::move( recovered), std::move( draft), std::move( roles), preparation) ;
		borrowed.reset() ;
		// ROOTの有無ごとに異なる保存能力を全実raw／全名／容量の最終検査へ結合します。
		if( preparation) {
			io( verifyPreparationRecovery( candidate)) ;
		} else {
			std::size_t checked{} ;	// ROOT保存済みの全head suffix再検査です。
			io( parentHeads( candidate, checked, {}, true)) ;
			require( checked == decoded.saved) ;
		}

		reservation = std::move( candidate) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure &failure) {
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_storage.h */
DWORD LocalCollectorSegmentStorage::saveParentHeads(
	std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
	const std::function<DWORD( std::size_t)> &afterSave) noexcept
{
	return parentHeads( std::move( reservation), saved, afterSave, false) ;
}
} // namespace drivercrate
